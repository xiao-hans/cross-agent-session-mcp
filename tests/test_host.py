"""生产宿主 `cross_agent_session_mcp/host.py` 的合成用例（H-01..H-20）。

纪律：只用临时目录里现场新建的合成夹具；不读取任何真实会话、不打开任何真实存储、不访问
用户配置或其它 Agent 的配置、不联网（DSH 解码走 3.14 进程内后端）。绑定与查询多数在本
进程内直接调用；最后一组用 `mcp` 客户端连生产宿主的 stdio 子进程，前提与既有
`tests/test_stdio.py` / `tests/test_stdio_bound.py` 相同，不新增依赖。

口径关注点：
- 配置形状与版本不合一律拒（`ConfigError` 只带位置与固定原因码，绝不带路径值）。
- 显式项目映射 + 显式逐源存储根缺一即不绑定；未配置 / 已关闭 / 缺根 / 被拒都如实报
  `disabled` 或 `unavailable`，绝不退化成「先扫一遍看看」，也不把「读不下去」说成「没有会话」。
- 绑定集合只交付逐条 `authorize_store` 通过的条目；被拒条目只进计数。
- 正文只有在记录可按可信项目元数据归属到已批准项目根时才发布；宿主不代替策略放行。
- 行族的上下文槽位按来源只有一条（`server._line_context_slots`）：宿主绑集合首条，
  其余文件的 ctxref 走既有 `binding_mismatch` 口径，不是本层新造的拒绝理由。

运行（由 DSH 执行；本轮按调度约束未实跑）：python -m unittest tests.test_host -v
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
for _entry in (str(REPO_ROOT), str(REPO_ROOT / "tests")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import hermes_synthetic as hfx  # noqa: E402
import workbuddy_synthetic as wfx  # noqa: E402

from cross_agent_session_mcp import host, server  # noqa: E402
from cross_agent_session_mcp.policy import PolicyDenied, RefusalCode  # noqa: E402
from cross_agent_session_mcp.server import ToolError, reset_bound_services  # noqa: E402
from cross_agent_session_mcp.session_discovery import MAX_FILES_PER_QUERY  # noqa: E402
from cross_agent_session_mcp.sources import dsh as dsh_source  # noqa: E402

SCOPE = "host-scope"
PROJECT = "host-project"
NEEDLE = "host needle"


def run(tool: Any, **kwargs: Any) -> Any:
    return asyncio.run(tool(**kwargs))


def rows_of(payload: Any) -> dict[str, dict[str, Any]]:
    return {row["source"]: row for row in payload["sources"]}


def write_session(path: Path, cwd: Path, session_id: str, texts: list[str]) -> Path:
    """pi / codex 同形的 stream-json 会话文件（正文一律无意义合成文本）。"""
    rows: list[dict[str, Any]] = [
        {"type": "session", "version": "1", "cwd": str(cwd), "id": session_id}
    ]
    for index, text in enumerate(texts):
        rows.append(
            {
                "type": "message",
                "message": {
                    "role": "user",
                    "timestamp": f"2026-03-01T10:{index:02d}:00Z",
                    "content": [{"type": "input_text", "text": text}],
                },
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    return path


class HostCase(unittest.TestCase):
    """公共骨架：临时目录 + 每用例前后 reset（宿主绑的全是进程内槽位）。"""

    def setUp(self) -> None:
        reset_bound_services()
        self.temp = Path(tempfile.mkdtemp(prefix="cas-host-"))
        self.proj = self.temp / "proj"
        self.proj.mkdir()
        self.other = self.temp / "other"
        self.other.mkdir()
        self.store = self.temp / "store"
        self.store.mkdir()

    def tearDown(self) -> None:
        reset_bound_services()
        shutil.rmtree(self.temp, ignore_errors=True)

    # -- 配置与绑定的便捷入口 ------------------------------------------------
    def write_config(self, payload: Any, *, name: str = "host.json") -> Path:
        path = self.temp / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def config(self, sources: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        """形状合法的最小授权配置：项目映射默认指向 `self.proj`。"""
        config: dict[str, Any] = {
            "schema_version": host.CONFIG_SCHEMA_VERSION,
            "scope": SCOPE,
            "projects": [{"name": PROJECT, "cwd_roots": [str(self.proj)]}],
            "sources": sources,
        }
        config.update(overrides)
        return config

    def loaded(self, sources: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        return host.load_config(self.write_config(self.config(sources, **overrides)))

    def bind(self, sources: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        return host.bind(self.config(sources, **overrides))

    def bind_loaded(self, sources: dict[str, Any], **overrides: Any) -> dict[str, Any]:
        return host.bind(self.loaded(sources, **overrides))

    def rows(self, report: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {row["source"]: row for row in report["sources"]}

    def assert_no_paths(self, text: str, *extra: str) -> None:
        """报告面/结果面不得外出任何路径值（含临时根、存储根、项目根）。"""
        flat = text.replace("\\\\", "\\")
        for forbidden in (str(self.temp), str(self.proj), str(self.other), str(self.store), *extra):
            self.assertNotIn(str(forbidden), flat)

    def pi_files(self, *items: tuple[str, str]) -> list[dict[str, str]]:
        """在已批准的存储根内新建合成会话：`(会话标识, 正文)`。"""
        files = []
        for session_id, text in items:
            path = write_session(self.store / f"{session_id}.jsonl", self.proj, session_id, [text])
            files.append({"path": str(path), "session_id": session_id})
        return files


class TestConfigShape(HostCase):
    """H-01 配置形状门：不合即拒，且拒话里绝不含路径值。"""

    def test_relative_config_path_is_refused(self) -> None:
        # 相对路径会让进程 cwd 参与决定「读哪份授权」：同一串在两个 cwd 下指向两份配置。
        with self.assertRaises(host.ConfigError) as caught:
            host.load_config("host.json")
        self.assertEqual(caught.exception.location, "--config")
        self.assertEqual(caught.exception.reason, "config_path_unsafe")

    def test_parent_traversal_config_path_is_refused(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            host.load_config(str(self.temp / ".." / "evil.json"))
        self.assertEqual(caught.exception.reason, "config_path_unsafe")

    def test_unknown_top_level_key_is_refused(self) -> None:
        # 未知键＝配置与实现不同版：宁可拒启动，也不忽略一个可能被误写的授权项。
        with self.assertRaises(host.ConfigError) as caught:
            host.load_config(
                self.write_config(self.config({"pi": {}}, scan_all=True))
            )
        self.assertEqual(caught.exception.reason, "unknown_key:scan_all")

    def test_unknown_schema_version_is_refused(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            host.load_config(
                self.write_config(self.config({"pi": {}}, schema_version=99))
            )
        self.assertEqual(caught.exception.location, "schema_version")
        self.assertEqual(caught.exception.reason, "unsupported_schema_version")

    def test_unknown_source_and_typo_key_are_refused(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            self.loaded({"ghost_cli": {}})
        self.assertEqual(caught.exception.reason, "unknown_source")
        with self.assertRaises(host.ConfigError) as second:
            self.loaded({"pi": {"store_root": str(self.store)}})
        self.assertEqual(second.exception.reason, "unknown_key:store_root")

    def test_empty_projects_and_empty_sources_are_refused(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            self.loaded({"pi": {}}, projects=[])
        self.assertEqual(caught.exception.location, "projects")
        self.assertEqual(caught.exception.reason, "empty_projects")
        with self.assertRaises(host.ConfigError) as second:
            self.loaded({})
        self.assertEqual(second.exception.reason, "empty_sources")

    def test_missing_or_blank_scope_is_refused(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            host.load_config(self.write_config(self.config({"pi": {}}, scope="  ")))
        self.assertEqual(caught.exception.reason, "scope_not_string")

    def test_scalar_gates_on_a_source_block(self) -> None:
        cases = (
            ("pi", {"mode": "scan"}, "sources.pi.mode", "mode_invalid"),
            ("pi", {"enabled": "false"}, "sources.pi.enabled", "enabled_not_bool"),
            ("pi", {"context_index": -1}, "sources.pi.context_index", "context_index_invalid"),
            ("pi", {"context_index": True}, "sources.pi.context_index", "context_index_invalid"),
            ("dsh", {"decoder_python": "  "}, "sources.dsh.decoder_python", "decoder_python_invalid"),
            ("dsh", {"attribution_project": 7}, "sources.dsh.attribution_project", "attribution_project_not_string"),
        )
        for source, block, location, reason in cases:
            with self.subTest(block=block):
                merged: dict[str, Any] = {"store_roots": [str(self.store)]}
                for key, value in block.items():
                    merged[key] = value
                with self.assertRaises(host.ConfigError) as caught:
                    self.loaded({source: merged})
                self.assertEqual(caught.exception.location, location)
                self.assertEqual(caught.exception.reason, reason)

    def test_binding_entry_shape_is_refused(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            self.loaded(
                {"pi": {"store_roots": [str(self.store)], "files": [{"path": "C:/x.jsonl"}]}}
            )
        # 缺 `session_id` 不是未知键：逐字段核对会把它当空白值拒掉，位点写到字段名。
        self.assertEqual(caught.exception.location, "sources.pi.files[0].session_id")
        self.assertEqual(caught.exception.reason, "value_not_string")
        with self.assertRaises(host.ConfigError) as extra:
            self.loaded(
                {
                    "pi": {
                        "store_roots": [str(self.store)],
                        "files": [{"path": "C:/x.jsonl", "session_id": "s", "cwd": "C:/p"}],
                    }
                }
            )
        self.assertEqual(extra.exception.reason, "unknown_key:cwd")
        with self.assertRaises(host.ConfigError) as second:
            self.loaded(
                {
                    "hermes": {
                        "store_roots": [str(self.store)],
                        "stores": [{"path": "C:/db.sqlite", "session_id": "  "}],
                    }
                }
            )
        self.assertEqual(second.exception.reason, "value_not_string")

    def test_roots_gates(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            self.loaded({"pi": {"store_roots": []}})
        self.assertEqual(caught.exception.reason, "empty_roots")
        with self.assertRaises(host.ConfigError) as second:
            self.loaded({"pi": {"store_roots": [f"C:/r{i}" for i in range(17)]}})
        self.assertEqual(second.exception.reason, "too_many_roots")
        with self.assertRaises(host.ConfigError) as third:
            self.loaded({"pi": {"store_roots": [{"path": "C:/r", "allow_links": "yes"}]}})
        self.assertEqual(third.exception.reason, "allow_links_not_bool")
        with self.assertRaises(host.ConfigError) as fourth:
            self.loaded({"pi": {"store_roots": [{"path": "  "}]}})
        self.assertEqual(fourth.exception.reason, "path_not_string")

    def test_project_name_gate(self) -> None:
        with self.assertRaises(host.ConfigError) as caught:
            self.loaded({"pi": {}}, projects=[{"name": " padded ", "cwd_roots": [str(self.proj)]}])
        self.assertEqual(caught.exception.reason, "project_name_invalid")

    def test_broken_and_missing_config_files(self) -> None:
        bad = self.temp / "broken.json"
        bad.write_text("{not json", encoding="utf-8")
        with self.assertRaises(host.ConfigError) as caught:
            host.load_config(bad)
        self.assertEqual(caught.exception.reason, "config_not_json")
        with self.assertRaises(OSError):
            host.load_config(self.temp / "missing.json")

    def test_bom_prefixed_config_is_read(self) -> None:
        # Windows 记事本存的 UTF-8 BOM 不能把宿主挡在门外。
        path = self.temp / "bom.json"
        path.write_text(
            json.dumps(self.config({"pi": {"store_roots": [str(self.store)]}})),
            encoding="utf-8-sig",
        )
        self.assertEqual(host.load_config(path)["scope"], SCOPE)

    def test_error_objects_never_carry_path_values(self) -> None:
        for block in ({"store_root": str(self.store)}, {"store_roots": []}, {"files": [{}]}):
            with self.assertRaises(host.ConfigError) as caught:
                self.loaded({"pi": block})
            self.assert_no_paths(str(caught.exception.__dict__))


class TestPolicyBuild(HostCase):
    """H-02 配置 → `SessionPolicy`：授权面逐字来自配置，不碰文件系统。"""

    def test_policy_carries_scope_projects_and_source_roots(self) -> None:
        config = self.loaded(
            {
                "pi": {"store_roots": [str(self.store)]},
                "hermes": {"store_roots": [str(self.store)]},
            }
        )
        policy = host.build_policy(config)
        self.assertEqual(policy.scope_names(), (SCOPE,))
        self.assertEqual(policy.project_names(SCOPE), (PROJECT,))
        self.assertEqual(policy.authorized_sources(SCOPE), ("hermes", "pi"))
        self.assertEqual(policy.authorize_query(SCOPE, sources=("pi",)).scope, SCOPE)
        with self.assertRaises(PolicyDenied) as caught:
            policy.authorize_query(SCOPE, sources=("codex",))
        self.assertIs(caught.exception.code, RefusalCode.SOURCE_NOT_AUTHORIZED)

    def test_policy_construction_does_not_touch_the_filesystem(self) -> None:
        # 根不存在也要能构造出策略：策略只做形状自检，存在性判定留给 authorize_*。
        config = self.loaded({"pi": {"store_roots": [str(self.temp / "ghost" / "store")]}})
        policy = host.build_policy(config)
        self.assertEqual(policy.scope_names(), (SCOPE,))

    def test_extension_source_grants_no_store_root(self) -> None:
        config = self.loaded({"claude_code_cli": {"store_roots": [str(self.store)]}})
        policy = host.build_policy(config)
        # 扩展来源不进授权面：不给它读轴，也就无从被「顺手绑上」。
        self.assertEqual(policy.authorized_sources(SCOPE), ())

    def test_undecodable_policy_shape_becomes_one_error_row(self) -> None:
        # 策略建不起来时报告只有一行 error，不逐族试绑（此处直接喂 bind，绕过 load_config）。
        report = host.bind(
            {
                "schema_version": host.CONFIG_SCHEMA_VERSION,
                "scope": SCOPE,
                "projects": [{"name": PROJECT, "cwd_roots": [str(self.proj)]}],
                "sources": {"pi": {"store_roots": [str(self.proj), 7]}},
            }
        )
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["sources"], [])


class TestBindFailClosed(HostCase):
    """H-03..H-06：缺根 / 缺映射 / 被拒 / 越界一律如实报，不猜、不扫。"""

    def test_unconfigured_families_are_disabled_and_tools_still_refuse(self) -> None:
        report = self.bind({"pi": {"enabled": False}})
        rows = self.rows(report)
        self.assertEqual(rows["pi"]["reason"], "explicitly_disabled")
        for name in ("hermes", "dsh", "workbuddy", "cursor_agent_cli", "codex"):
            self.assertEqual(rows[name]["status"], "disabled", name)
            self.assertEqual(rows[name]["reason"], "not_configured", name)
        self.assertEqual(report["status"], "unavailable")
        with self.assertRaises(ToolError) as caught:
            run(server.search_sessions, query=NEEDLE, scope=SCOPE)
        self.assertIn("未绑定", str(caught.exception))

    def test_source_without_store_roots_is_unavailable_not_scanned(self) -> None:
        # 没有根就没有任何位置被批准：报 unavailable，绝不退化成「先扫一遍看看」。
        report = self.bind({"pi": {"files": []}})
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "unavailable")
        self.assertEqual(row["reason"], "no_store_roots")
        self.assertNotIn("files_bound", row)

    def test_files_outside_approved_roots_are_denied_and_counted(self) -> None:
        rogue = write_session(self.other / "rogue.jsonl", self.other, "rogue", [f"{NEEDLE} one"])
        report = self.bind(
            {"pi": {"store_roots": [str(self.store)], "files": [{"path": str(rogue), "session_id": "rogue"}]}}
        )
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "unavailable")
        self.assertEqual(row["reason"], "no_bound_files")
        self.assertEqual(row["bindings_denied"], 1)
        self.assertEqual(report["status"], "unavailable")

    def test_missing_binding_list_surfaces_as_error_row(self) -> None:
        # 配了根却没配集合：宿主不把它当「集合为空」的合法结论（那是发现层才允许的）。
        report = self.bind({"pi": {"store_roots": [str(self.store)]}})
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["reason"], "files_not_configured")
        self.assertEqual(row["location"], "sources.pi.files")

    def test_discovery_without_a_discovery_layer_is_refused(self) -> None:
        # hermes/workbuddy/codex 没有发现层：只能显式列举，不给「先扫库文件」的兼容处理。
        report = self.bind({"hermes": {"store_roots": [str(self.store)], "mode": "discover"}})
        row = self.rows(report)["hermes"]
        self.assertEqual(row["status"], "unavailable")
        self.assertEqual(row["reason"], "discovery_not_supported")

    def test_over_limit_bindings_are_error_not_truncation(self) -> None:
        entries = [
            {"path": str(write_session(self.store / f"s{i}.jsonl", self.proj, f"s{i}", ["x"])), "session_id": f"s{i}"}
            for i in range(MAX_FILES_PER_QUERY + 1)
        ]
        report = self.bind({"pi": {"store_roots": [str(self.store)], "files": entries}})
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["reason"], f"too_many_bindings:{MAX_FILES_PER_QUERY}")

    def test_line_context_index_out_of_range_is_error(self) -> None:
        path = write_session(self.store / "codex-s1.jsonl", self.proj, "codex-s1", ["x"])
        report = self.bind(
            {
                "codex": {
                    "store_roots": [str(self.store)],
                    "files": [{"path": str(path), "session_id": "codex-s1"}],
                    "context_index": 3,
                }
            }
        )
        row = self.rows(report)["codex"]
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["reason"], "context_index_out_of_range")

    def test_extension_source_is_never_bound(self) -> None:
        config = self.loaded({"claude_code_cli": {"store_roots": [str(self.store)], "files": []}})
        report = host.bind(config)
        row = self.rows(report)["claude_code_cli"]
        # 扩展来源一律不绑：避免给出「检索有结果但读不到上下文」的半截能力。
        self.assertEqual(row["status"], "disabled")
        self.assertEqual(row["reason"], "extension_source_not_enabled")
        self.assertNotIn("claude_code_cli", [row["source"] for row in report["sources"] if row["status"] == "ready"])
        with self.assertRaises(ToolError) as caught:
            run(
                server.read_session_context,
                source="claude_code_cli",
                session_id="x",
                location="ctxref:1",
                scope=SCOPE,
            )
        self.assertIn("扩展来源且默认未启用", str(caught.exception))

    def test_report_and_stderr_never_carry_path_values(self) -> None:
        report = self.bind_loaded({"pi": {"store_roots": [str(self.store)], "files": []}})
        self.assert_no_paths(json.dumps(report, ensure_ascii=False))
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            host._print_report(report, json_mode=False)
        self.assert_no_paths(buffer.getvalue())

    def test_rebind_resets_previous_family_slots(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        self.bind_loaded({"pi": {"store_roots": [str(self.store)], "files": files}})
        self.assertEqual(rows_of(run(server.list_sources))["pi"]["status"], "ready")
        # 第二轮配置里 pi 已关闭：reset 必须清掉上一轮槽位，不留半对绑定。
        self.bind_loaded({"pi": {"enabled": False}})
        self.assertEqual(rows_of(run(server.list_sources))["pi"]["status"], "unavailable")
        with self.assertRaises(ToolError):
            run(server.search_sessions, query=NEEDLE, scope=SCOPE)

    def test_bind_uses_one_shared_ledger_across_families(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        self.bind_loaded(
            {
                "pi": {"store_roots": [str(self.store)], "files": files},
                "codex": {"store_roots": [str(self.store)], "files": files},
            }
        )
        # 跨族共用一个引用账本：ctxref 的族内路由仍由 service_key 判定，不会串族发布。
        self.assertIsNotNone(server._pi_search)
        self.assertIsNotNone(server._line_search_slots.get("codex"))


class TestBoundQueryClosure(HostCase):
    """H-07..H-12：绑定后的真实查询口径（含逐条归属核对先于正文发布）。"""

    def test_pi_explicit_binding_closes_over_two_files(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"), ("sB", f"{NEEDLE} two"))
        report = self.bind_loaded({"pi": {"store_roots": [str(self.store)], "files": files}})
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "ready")
        self.assertEqual(row["files_bound"], 2)
        self.assertEqual(row["bindings_denied"], 0)
        self.assertIs(row["coverage_incomplete"], False)
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["projects_authorized"], [PROJECT])
        self.assertEqual(rows_of(run(server.list_sources))["pi"]["status"], "ready")

        payload = run(server.search_sessions, query=NEEDLE, scope=SCOPE)
        self.assertEqual(sorted({r["session_id"] for r in payload["results"]}), ["sA", "sB"])
        self.assertEqual(payload["coverage_scope"], "bounded_pi_file_set")
        self.assertTrue(payload["complete"], payload)
        for result in payload["results"]:
            token = result["location"]
            self.assertTrue(str(token).startswith("ctxref:"), token)
            context = run(
                server.read_session_context,
                source="pi",
                session_id=result["session_id"],
                location=token,
                scope=SCOPE,
                before=1,
                after=1,
            )
            self.assertEqual(context["stage_reached"], "published", context)
            self.assertIs(context["complete"], True)
            self.assertEqual({r["session_id"] for r in context["results"]}, {result["session_id"]})
            self.assert_no_paths(json.dumps(context, ensure_ascii=False), "sA.jsonl")

    def test_pi_discover_mode_binds_the_found_set(self) -> None:
        self.pi_files(("sA", f"{NEEDLE} one"))
        report = self.bind_loaded(
            {"pi": {"store_roots": [str(self.store)], "mode": "discover"}}
        )
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "ready", row)
        self.assertEqual(row["files_bound"], 1)
        self.assertEqual(row["bindings_denied"], 0)
        payload = run(server.search_sessions, query=NEEDLE, sources=["pi"], scope=SCOPE)
        self.assertEqual({r["session_id"] for r in payload["results"]}, {"sA"})

    def test_pi_discover_mode_on_missing_root_is_unavailable_not_empty(self) -> None:
        # 「读不下去」≠「没有会话」：根不存在时不得宣称已扫完。
        report = self.bind_loaded(
            {
                "pi": {
                    "store_roots": [str(self.temp / "ghost" / "store")],
                    "mode": "discover",
                }
            }
        )
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "unavailable")
        self.assertEqual(row["reason"], "no_bound_files")
        self.assertGreaterEqual(row["bindings_denied"], 1)

    def test_bodies_not_attributable_to_the_approved_project_are_not_published(self) -> None:
        # 读取轴批准（根内）≠归属轴批准：会话头 cwd 落在未批准目录 ⇒ 逐条归属核对不过 ⇒ 零发布。
        path = write_session(self.store / "sX.jsonl", self.other, "sX", [f"{NEEDLE} secret"])
        good = self.pi_files(("sA", f"{NEEDLE} visible"))
        report = self.bind_loaded(
            {
                "pi": {
                    "store_roots": [str(self.store)],
                    "files": [{"path": str(path), "session_id": "sX"}] + good,
                }
            }
        )
        row = self.rows(report)["pi"]
        self.assertEqual(row["status"], "ready", "读取轴批准≠归属轴批准")
        self.assertEqual(row["files_bound"], 2)
        payload = run(server.search_sessions, query=NEEDLE, sources=["pi"], scope=SCOPE)
        # 同一集合里只发布可归属记录：归属不明的那一份被逐条剔除，且不外流正文。
        self.assertEqual({r["session_id"] for r in payload["results"]}, {"sA"}, payload)
        self.assertIs(payload["complete"], False)
        self.assertIs(payload["partial"], True)
        dumped = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn("secret", dumped, "归属不明的正文不得外流")
        self.assert_no_paths(dumped)

    def test_project_filter_is_a_policy_name_not_a_path(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        self.bind_loaded({"pi": {"store_roots": [str(self.store)], "files": files}})
        payload = run(server.search_sessions, query=NEEDLE, scope=SCOPE, project=PROJECT)
        self.assertEqual({r["session_id"] for r in payload["results"]}, {"sA"}, payload)
        # 项目过滤位只认已批准项目名：未知名与路径串都在策略层落空，结果为零且不回显输入。
        for name in ("not-a-project", str(self.proj)):
            with self.subTest(project=name):
                miss = run(server.search_sessions, query=NEEDLE, scope=SCOPE, project=name)
                self.assertEqual(miss["results"], [], miss)
                self.assert_no_paths(json.dumps(miss, ensure_ascii=False))
        # 空白项目名属形状问题：由服务端固定文案拒绝。
        with self.assertRaises(ToolError) as caught:
            run(server.search_sessions, query=NEEDLE, scope=SCOPE, project="  ")
        self.assertNotIn(str(self.store), str(caught.exception))

    def test_line_family_binds_one_context_slot_and_keeps_the_search_set(self) -> None:
        """行族上下文槽位按来源只有一条：绑的是 `context_index` 指的那条，其余文件无上下文轴。"""
        filler = write_session(self.store / "codex-s1.jsonl", self.proj, "codex-s1", ["filler only"])
        hit = write_session(self.store / "codex-s2.jsonl", self.proj, "codex-s2", [f"{NEEDLE} hit"])
        report = self.bind_loaded(
            {
                "codex": {
                    "store_roots": [str(self.store)],
                    "files": [
                        {"path": str(filler), "session_id": "codex-s1"},
                        {"path": str(hit), "session_id": "codex-s2"},
                    ],
                }
            }
        )
        row = self.rows(report)["codex"]
        self.assertEqual(row["status"], "ready")
        self.assertEqual(row["files_bound"], 2)
        self.assertIs(row["context_bound"], True)
        self.assertEqual(row["context_index"], 0)
        self.assertEqual(rows_of(run(server.list_sources))["codex"]["status"], "ready")

        search = server._line_search_slots["codex"]
        context = server._line_context_slots["codex"]
        # 检索轴覆盖整个有界集合，上下文轴只对得上首条：两个绑定键不同，不是同一位置。
        self.assertNotEqual(search.binding_key(0), search.binding_key(1))
        self.assertEqual(context.binding_key(), search.binding_key(0))
        payload = run(server.search_sessions, query=NEEDLE, sources=["codex"], scope=SCOPE)
        self.assertEqual(payload["coverage_scope"], "bounded_line_file_set:codex")
        # Codex 头部未获格式契约认可 ⇒ 归属不可信：本层不得发布任何正文。
        self.assertEqual(payload["results"], [], payload)
        self.assert_no_paths(json.dumps(payload, ensure_ascii=False))

    def test_line_family_context_follows_context_index(self) -> None:
        filler = write_session(self.store / "codex-s1.jsonl", self.proj, "codex-s1", ["filler only"])
        hit = write_session(self.store / "codex-s2.jsonl", self.proj, "codex-s2", [f"{NEEDLE} hit"])
        files = [
            {"path": str(filler), "session_id": "codex-s1"},
            {"path": str(hit), "session_id": "codex-s2"},
        ]
        report = self.bind_loaded(
            {"codex": {"store_roots": [str(self.store)], "files": files, "context_index": 1}}
        )
        self.assertEqual(self.rows(report)["codex"]["context_index"], 1)
        # 宿主只把 `context_index` 交给既有的 `context_service(index)`，不自定路由：
        # 上下文槽位必须与检索集合的指定位共享同一绑定键。
        search = server._line_search_slots["codex"]
        context = server._line_context_slots["codex"]
        self.assertEqual(context.binding_key(), search.binding_key(1))
        self.assertNotEqual(context.binding_key(), search.binding_key(0))

    def test_store_family_needs_explicit_stores_and_counts_denials(self) -> None:
        path = self.store / wfx.STORE_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = wfx.build_store(path)
        wfx.add_session(conn, session_id=wfx.SESSION, project_path=str(self.proj))
        wfx.add_message(conn, session_id=wfx.SESSION, content=f"{NEEDLE} indexed")
        conn.close()
        rogue = self.other / "index.db"
        shutil.copyfile(path, rogue)
        report = self.bind_loaded(
            {
                "workbuddy": {
                    "store_roots": [str(self.store)],
                    "stores": [
                        {"path": str(path), "session_id": wfx.SESSION},
                        {"path": str(rogue), "session_id": "ghost-session"},
                    ],
                }
            }
        )
        row = self.rows(report)["workbuddy"]
        self.assertEqual(row["status"], "ready")
        self.assertEqual(row["stores_bound"], 1)
        self.assertEqual(row["bindings_denied"], 1)
        self.assertEqual(row["body_publication"], "source_layer_decides")

    def test_hermes_binding_is_ready_only_for_explicit_stores(self) -> None:
        path = self.store / "state.db"
        conn = hfx.create_store(path)
        hfx.add_session(conn, "h1", cwd=str(self.proj))
        hfx.add_message(conn, "h1", "user", f"{NEEDLE} hermes")
        conn.close()
        report = self.bind_loaded(
            {"hermes": {"store_roots": [str(self.store)], "stores": [{"path": str(path), "session_id": "h1"}]}}
        )
        row = self.rows(report)["hermes"]
        self.assertEqual(row["status"], "ready", row)
        self.assertEqual(row["stores_bound"], 1)
        self.assertEqual(rows_of(run(server.list_sources))["hermes"]["status"], "ready")

    def test_dsh_row_never_claims_ready_without_a_decoder_runtime(self) -> None:
        """宿主报告的 dsh 行与 `list_sources` 同源：运行时不可用就报 error。"""
        path = write_session(self.store / "dsh-s1.jsonl", self.proj, "dsh-s1", [f"{NEEDLE} d"])
        missing = dsh_source.DshDecoderRuntime(mode=dsh_source.DshDecoderMode.MISSING)
        # 绑定时服务器会重新探测运行时，因此只能桩在探测函数上，不能桩在缓存字段上。
        with mock.patch.object(server, "_probe_dsh_runtime", return_value=missing):
            report = self.bind_loaded(
                {
                    "dsh": {
                        "store_roots": [str(self.store)],
                        "files": [{"path": str(path), "session_id": "dsh-s1"}],
                    }
                }
            )
        row = self.rows(report)["dsh"]
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["reason"], "decoder_runtime_unusable")
        self.assertEqual(rows_of(run(server.list_sources))["dsh"]["status"], "error")
        # 运行时缺失也不谎报 ready，结果面同样不得发布正文（拒绝形状由服务层定）。
        try:
            payload = run(server.search_sessions, query=NEEDLE, sources=["dsh"], scope=SCOPE)
        except ToolError:
            payload = None
        if payload is not None:
            self.assertEqual(payload["results"], [], payload)


class TestMainCli(HostCase):
    """H-13..H-16：`main()` 的退出码与「不启动服务」分支（不起子进程、不跑 stdio）。"""

    def capture_main(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = host.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_check_mode_prints_json_without_running_the_server(self) -> None:
        path = self.write_config(self.config({"pi": {"store_roots": [str(self.store)], "files": []}}))
        with mock.patch.object(server.app, "run") as run_spy:
            code, out, _err = self.capture_main(["--config", str(path), "--check"])
        self.assertEqual(code, 0, "空集合只是 unavailable，不是配置非法")
        self.assertEqual(json.loads(out)["status"], "unavailable")
        self.assertEqual(run_spy.call_count, 0, "--check 不得启动服务")
        report = json.loads(out)
        self.assertEqual(
            {row["source"] for row in report["sources"]},
            {"hermes", "dsh", "workbuddy", "pi", "cursor_agent_cli", "codex"},
        )

    def test_default_mode_runs_stdio_transport_once(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        path = self.write_config(
            self.config({"pi": {"store_roots": [str(self.store)], "files": files}})
        )
        with mock.patch.object(server.app, "run") as run_spy:
            code, _out, err = self.capture_main(["--config", str(path)])
        self.assertEqual(code, 0)
        run_spy.assert_called_once_with(transport="stdio")
        self.assertIn("[host]", err)
        self.assertIn("pi: ready", err)

    def test_broken_config_exits_two_and_never_starts(self) -> None:
        path = self.write_config(self.config({"pi": {}}, projects=[]))
        with mock.patch.object(server.app, "run") as run_spy:
            code, _out, err = self.capture_main(["--config", str(path)])
        self.assertEqual(code, 2)
        self.assertEqual(run_spy.call_count, 0)
        self.assertIn("配置非法", err)

    def test_unreadable_config_exits_two_without_echoing_the_path(self) -> None:
        missing = self.temp / "missing.json"
        with mock.patch.object(server.app, "run") as run_spy:
            code, _out, err = self.capture_main(["--config", str(missing)])
        self.assertEqual(code, 2)
        self.assertEqual(run_spy.call_count, 0)
        self.assertIn("config_unreadable", err)
        self.assertNotIn(str(missing), err, "配置路径本身含用户目录信息，不回显")

    def test_unsafe_config_path_exits_two(self) -> None:
        with mock.patch.object(server.app, "run") as run_spy:
            code, _out, err = self.capture_main(["--config", "relative.json"])
        self.assertEqual(code, 2)
        self.assertEqual(run_spy.call_count, 0)
        self.assertIn("config_path_unsafe", err)

    def test_strict_mode_refuses_to_start_when_a_family_failed(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        path = self.write_config(
            self.config(
                {
                    "pi": {"store_roots": [str(self.store)], "files": files},
                    "codex": {"store_roots": [str(self.store)], "files": files, "context_index": 5},
                }
            )
        )
        with mock.patch.object(server.app, "run") as run_spy:
            code, _out, err = self.capture_main(["--config", str(path), "--strict"])
        self.assertEqual(code, 2)
        self.assertEqual(run_spy.call_count, 0, "--strict 下有族失败就不拉起服务")
        self.assertIn("--strict", err)

    def test_non_strict_mode_starts_even_when_one_family_failed(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        path = self.write_config(
            self.config(
                {
                    "pi": {"store_roots": [str(self.store)], "files": files},
                    "codex": {"store_roots": [str(self.store)], "files": files, "context_index": 5},
                }
            )
        )
        with mock.patch.object(server.app, "run") as run_spy:
            code, _out, _err = self.capture_main(["--config", str(path)])
        self.assertEqual(code, 0)
        run_spy.assert_called_once_with(transport="stdio")

    def test_host_reads_no_environment_and_no_default_roots(self) -> None:
        # 宿主只吃 --config 那一份文件：测试宿主的环境变量在生产宿主里必须无效。
        path = self.write_config(
            self.config({"pi": {"store_roots": [str(self.store)], "files": []}})
        )
        with (
            mock.patch.dict(
                "os.environ",
                {"CROSS_AGENT_TEST_STORE_ROOTS": str(self.proj), "CROSS_AGENT_TEST_SCOPE": "env-scope"},
                clear=False,
            ),
            mock.patch.object(server.app, "run") as run_spy,
        ):
            code, out, _err = self.capture_main(["--config", str(path), "--check"])
        self.assertEqual(code, 0)
        self.assertEqual(run_spy.call_count, 0)
        report = json.loads(out)
        self.assertEqual(report["scope"], SCOPE, "环境变量不得改变 scope")
        self.assertEqual(report["projects_authorized"], [PROJECT])


class TestProductionStdio(HostCase):
    """H-17..H-20：真 stdio 传输上跑生产宿主（子进程只做协议握手，夹具仍是合成临时目录）。

    这一组用 `mcp` 客户端库连宿主，因此需要 mcp 依赖；本仓库测试环境的既有 stdio 用例
    （`tests/test_stdio.py` / `tests/test_stdio_bound.py`）同前提，不新增依赖。
    """

    def host_env(self) -> dict[str, str]:
        """子进程环境只给解释器必需的三项：生产宿主不读任何授权类环境变量。"""
        env = {
            "PYTHONPATH": str(REPO_ROOT),
            "PYTHONIOENCODING": "utf-8",
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
        }
        return env

    def server_params(self, config_path: Path):
        from mcp import StdioServerParameters

        return StdioServerParameters(
            command=sys.executable,
            args=["-m", "cross_agent_session_mcp.host", "--config", str(config_path)],
            env=self.host_env(),
            cwd=str(REPO_ROOT),
        )

    async def with_client(self, config_path: Path, body) -> Any:
        from mcp import ClientSession
        from mcp.client.stdio import stdio_client

        async with (
            asyncio.timeout(60),
            stdio_client(self.server_params(config_path)) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            return await body(session)

    def drive(self, config_path: Path, body) -> Any:
        return asyncio.run(self.with_client(config_path, body))

    def payload_of(self, result: Any) -> dict[str, Any]:
        structured = getattr(result, "structured_content", None)
        if isinstance(structured, dict):
            return structured
        for item in result.content:
            text = getattr(item, "text", None)
            if isinstance(text, str):
                return json.loads(text)
        self.fail("工具返回里没有可解析载荷")
        return {}

    def error_text_of(self, result: Any) -> str:
        return " ".join(
            str(getattr(item, "text", ""))
            for item in result.content
            if getattr(item, "type", None) == "text"
        )

    def test_stdio_handshake_lists_only_the_three_tools(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        path = self.write_config(
            self.config({"pi": {"store_roots": [str(self.store)], "files": files}})
        )

        async def body(session):
            return {tool.name for tool in (await session.list_tools()).tools}

        names = self.drive(path, body)
        self.assertEqual(
            names, {"list_sources", "search_sessions", "read_session_context"}
        )

    def test_stdio_search_and_context_over_production_host(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        path = self.write_config(
            self.config({"pi": {"store_roots": [str(self.store)], "files": files}})
        )

        async def body(session):
            rows = self.payload_of(await session.call_tool("list_sources", {}))
            bound = rows_of(rows).get("pi", {})
            search = self.payload_of(
                await session.call_tool("search_sessions", {"query": NEEDLE, "scope": SCOPE})
            )
            token = ""
            if search["results"]:
                first = search["results"][0]
                read = self.payload_of(
                    await session.call_tool(
                        "read_session_context",
                        {
                            "source": first["source"],
                            "session_id": first["session_id"],
                            "location": first["location"],
                            "scope": SCOPE,
                        },
                    )
                )
                token = str(read.get("stage_reached"))
            return {"pi": bound, "search": search, "stage": token}

        result = self.drive(path, body)
        self.assertEqual(result["pi"].get("status"), "ready", result["pi"])
        self.assertEqual(
            {r["session_id"] for r in result["search"]["results"]}, {"sA"}, result["search"]
        )
        self.assertEqual(result["stage"], "published", "生产宿主上要能走完 ctxref 闭环")

    def test_stdio_refuses_when_nothing_is_bound(self) -> None:
        path = self.write_config(self.config({"pi": {"enabled": False}}))

        async def body(session):
            res = await session.call_tool("search_sessions", {"query": NEEDLE, "scope": SCOPE})
            return self.error_text_of(res)

        self.assertIn("未绑定", self.drive(path, body))

    def test_stdio_client_cannot_supply_paths(self) -> None:
        files = self.pi_files(("sA", f"{NEEDLE} one"))
        path = self.write_config(
            self.config({"pi": {"store_roots": [str(self.store)], "files": files}})
        )

        async def body(session):
            # 三个工具的入参面没有任何路径位：客户端能传的只有 scope/来源名/会话标识。
            schema = {
                tool.name: set((tool.input_schema or {}).get("properties", {}))
                for tool in (await session.list_tools()).tools
            }
            res = await session.call_tool(
                "search_sessions", {"query": NEEDLE, "scope": str(self.store)}
            )
            return schema, self.error_text_of(res), bool(res.is_error)

        schema, text, is_error = self.drive(path, body)
        forbidden = {"path", "paths", "cwd", "root", "roots", "file", "dir", "directory"}
        for name, props in schema.items():
            self.assertFalse(props & forbidden, f"{name} 暴露了路径位 {props & forbidden}")
        self.assertTrue({"query", "sources", "scope"}.issubset(schema["search_sessions"]))
        self.assertTrue(
            {"source", "session_id", "location", "scope"}.issubset(schema["read_session_context"])
        )
        # scope 被当作路径使用时按参数错误拒绝，且不回显调用方给的那串路径。
        self.assertTrue(is_error, text)
        self.assertNotIn(str(self.store), text)


if __name__ == "__main__":
    unittest.main()
