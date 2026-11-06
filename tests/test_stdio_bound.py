"""TC-MCP-01 已绑定侧（合成）：真实 stdio `tools/call` 走完多文件查询 → ctxref → 上下文读取。

与 `tests/test_stdio.py`（默认未绑定）互补：这里用**测试专用宿主** `tests/_bound_stdio_host.py`
把临时目录里的合成会话发现成有界文件集合并显式绑定，再通过真实的 MCP stdio 传输调用工具。
`TestBoundHermesStdio` 走宿主的 `CROSS_AGENT_TEST_HERMES_DB` 分支：同一套真实 stdio 上完成
Hermes 合成单库双会话的检索 → ctxref → 上下文读取闭环、拒绝与路径不外泄断言。
生产入口 `server.main()` 依旧不绑定、不读配置，本测试不改变这一点。

只用合成数据：不读取任何真实会话、不访问用户配置目录、不联网、不启常驻服务（宿主子进程随
每个用例的 `async with` 退出即终止）。运行：python -m unittest tests.test_stdio_bound -v
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hermes_synthetic import add_message, add_session, create_store

REPO_ROOT = Path(__file__).resolve().parent.parent
HOST_SCRIPT = REPO_ROOT / "tests" / "_bound_stdio_host.py"
TIMEOUT_SECONDS = 60.0
SCOPE = "synthetic-scope"


def _write_session(path: Path, cwd: Path, sid: str, texts: list[str]) -> None:
    rows: list[dict[str, Any]] = [
        {"type": "session", "version": "1", "cwd": str(cwd), "id": sid}
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


def _payload(res: Any) -> dict[str, Any]:
    structured = getattr(res, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    text = _error_text(res)
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"_text": text}
    return parsed if isinstance(parsed, dict) else {"_text": text}


def _error_text(res: Any) -> str:
    return "\n".join(c.text for c in res.content if getattr(c, "type", None) == "text")


class _BoundHost(unittest.IsolatedAsyncioTestCase):
    """基类：搭合成目录 → 每个用例起一次绑定宿主的 stdio 会话，用完即关。"""

    async def asyncSetUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="cas-mcp-bound-"))
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        self.repo_a = self.temp / "repo-a"
        self.repo_b = self.temp / "repo-b"
        self.store = self.temp / "store"
        for repo in (self.repo_a, self.repo_b):
            repo.mkdir(parents=True)
        # 两个项目、两条绑定：命中分布在两条文件上，才能验证 ctxref 回到发放它的那一条。
        _write_session(
            self.store / "sA.jsonl",
            self.repo_a,
            "sA",
            ["alpha needle one", "alpha filler two", "alpha needle three"],
        )
        _write_session(
            self.store / "nested" / "sB.jsonl",
            self.repo_b,
            "sB",
            ["beta filler", "beta needle here"],
        )
        env = {
            "PYTHONPATH": str(REPO_ROOT),
            "PYTHONIOENCODING": "utf-8",
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
            "CROSS_AGENT_TEST_SCOPE": SCOPE,
            "CROSS_AGENT_TEST_PROJECT_DIRS": ",".join(
                [str(self.repo_a), str(self.repo_b)]
            ),
            "CROSS_AGENT_TEST_STORE_ROOTS": str(self.store),
        }
        self.params = StdioServerParameters(
            command=sys.executable,
            args=[str(HOST_SCRIPT)],
            env=env,
            cwd=str(REPO_ROOT),
        )

    async def _call(self, session: ClientSession, tool: str, args: dict[str, Any]):
        return await asyncio.wait_for(
            session.call_tool(tool, args), timeout=TIMEOUT_SECONDS
        )

    async def _case(self, body: Callable[[ClientSession], Awaitable[None]]) -> None:
        async with (
            asyncio.timeout(TIMEOUT_SECONDS),
            stdio_client(self.params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            await body(session)


class TestBoundStdioClosure(_BoundHost):
    async def test_list_sources_reports_binding_without_claiming_full_scan(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(session, "list_sources", {})
            self.assertFalse(res.is_error)
            payload = _payload(res)
            rows = {row["source"]: row for row in payload["sources"]}
            self.assertEqual(len(rows), 6, "六类必备来源都要有行")
            pi = rows["pi"]
            self.assertEqual(pi["status"], "ready", "宿主已注入聚合服务：pi 报 ready")
            self.assertIs(pi["enabled"], True)
            self.assertEqual(payload["implementation_status"], "partial")
            self.assertIs(payload["config_checked"], False, "ready 不来自配置读取")
            self.assertIs(payload["verified"], False, "ready 不来自磁盘探测")
            self.assertIn("不表示整个 pi 来源已扫完", pi["reason"])
            # Hermes 适配器已编写：本宿主只绑了 pi 一族，hermes 行必须是「未绑定」而非「未实现」。
            hermes = rows["hermes"]
            self.assertEqual(hermes["status"], "unavailable", "未绑定 ≠ 未实现")
            self.assertIs(hermes["enabled"], False)
            self.assertIsNone(hermes["project_config"])
            self.assertIn("宿主未在本进程注入", hermes["reason"])
            self.assertNotIn("未实现", hermes["reason"], "适配器已编写，不得误标未实现")
            for name in ("dsh", "workbuddy", "cursor_agent_cli", "codex"):
                row = rows[name]
                # P1-7/P1-8 统一口径：四族适配器均已编写，未绑定即 unavailable +
                # enabled False + project_config null（不再有「未实现」分支）。
                self.assertEqual(row["status"], "unavailable", name)
                self.assertIs(row["enabled"], False, name)
                self.assertIsNone(row["project_config"], name)
                self.assertIn("宿主未在本进程注入", row["reason"], name)
                self.assertNotIn("未实现", row["reason"], name)
            dump = json.dumps(payload).replace("\\\\", "\\")
            for forbidden in (str(self.store), str(self.repo_a), str(self.repo_b)):
                self.assertNotIn(forbidden, dump, "状态面不得外出任何路径")

        await self._case(body)

    async def test_multi_file_search_and_ctxref_read_closure(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(
                session, "search_sessions", {"query": "needle", "scope": SCOPE}
            )
            self.assertFalse(res.is_error, _error_text(res))
            payload = _payload(res)
            # 两条绑定的命中都要出现：这正是因为接线的是聚合服务而不是单文件服务。
            self.assertEqual(
                sorted({row["session_id"] for row in payload["results"]}),
                ["sA", "sB"],
                payload,
            )
            # 诚实口径：complete 只指本次有界集合扫完；coverage_scope 明说它不是整个来源。
            self.assertTrue(payload["complete"])
            self.assertFalse(payload["partial"])
            self.assertEqual(payload["coverage_scope"], "bounded_pi_file_set")
            self.assertEqual(
                [row["status"] for row in payload["files"]], ["searched", "searched"]
            )
            by_session = {
                row["session_id"]: row["location"] for row in payload["results"]
            }
            for sid, token in by_session.items():
                self.assertTrue(token.startswith("ctxref:"), token)
                read = await self._call(
                    session,
                    "read_session_context",
                    {
                        "source": "pi",
                        "session_id": sid,
                        "location": token,
                        "scope": SCOPE,
                        "before": 1,
                        "after": 1,
                    },
                )
                self.assertFalse(read.is_error, _error_text(read))
                ctx = _payload(read)
                self.assertTrue(ctx["complete"] or ctx["partial"], ctx)
                self.assertGreaterEqual(len(ctx["results"]), 1)
                self.assertEqual({r["session_id"] for r in ctx["results"]}, {sid})
                # 覆盖层级仍是单条绑定口径：一次上下文只证明那一条文件。
                self.assertEqual(ctx["coverage_scope"], "single_approved_file")
                dump = json.dumps(ctx).replace("\\\\", "\\")
                for forbidden in (
                    str(self.store),
                    "nested",
                    str(self.repo_a),
                    str(self.repo_b),
                ):
                    self.assertNotIn(forbidden, dump, "上下文面不得外出路径")

        await self._case(body)

    async def test_project_filter_narrows_across_bound_files(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(
                session,
                "search_sessions",
                {"query": "needle", "scope": SCOPE, "project": "test-proj-1"},
            )
            self.assertFalse(res.is_error, _error_text(res))
            payload = _payload(res)
            self.assertEqual(
                {row["session_id"] for row in payload["results"]},
                {"sB"},
                "项目收窄应只留 repo-b 那条绑定",
            )

        await self._case(body)

    async def test_named_non_pi_source_is_reported_unsupported_not_rejected(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(
                session,
                "search_sessions",
                {"query": "needle", "scope": SCOPE, "sources": ["codex"]},
            )
            self.assertFalse(res.is_error, "未绑定来源是状态报告，不是参数错误")
            payload = _payload(res)
            # P1-7/P1-8 后：点名未绑定来源给 service_unbound（适配器已编写，只是未注入），
            # 覆盖行状态同 list_sources 的 unavailable 口径。
            self.assertEqual(payload["failure_category"], "service_unbound")
            self.assertEqual(payload["returned_count"], 0)
            self.assertEqual(payload["coverage"][0]["status"], "unavailable")

        await self._case(body)


class TestBoundStdioRefusals(_BoundHost):
    async def _first_token(self, session: ClientSession) -> tuple[str, str]:
        res = await self._call(
            session, "search_sessions", {"query": "needle", "scope": SCOPE}
        )
        payload = _payload(res)
        row = payload["results"][0]
        return row["session_id"], row["location"]

    async def test_scope_mismatch_refuses_without_opening_files(self) -> None:
        async def body(session: ClientSession) -> None:
            sid, token = await self._first_token(session)
            res = await self._call(
                session,
                "read_session_context",
                {
                    "source": "pi",
                    "session_id": sid,
                    "location": token,
                    "scope": "other-scope",
                },
            )
            self.assertTrue(res.is_error)
            text = _error_text(res)
            self.assertIn("scope", text)
            self.assertIn("未打开任何文件", text)
            self.assertNotIn(str(self.store), text, "拒绝文案不得外出路径")

        await self._case(body)

    async def test_search_scope_mismatch_refuses(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(
                session, "search_sessions", {"query": "needle", "scope": "nope"}
            )
            self.assertTrue(res.is_error)
            self.assertIn("scope", _error_text(res))

        await self._case(body)

    async def test_unknown_token_is_ref_expired_with_zero_results(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(
                session,
                "read_session_context",
                {
                    "source": "pi",
                    "session_id": "sA",
                    "location": "ctxref:" + "z" * 40,
                    "scope": SCOPE,
                },
            )
            self.assertFalse(res.is_error, "读不到是零结果结论，不是协议错误")
            payload = _payload(res)
            self.assertEqual(payload["reason"], "ref_expired")
            self.assertEqual(payload["results"], [])
            self.assertFalse(payload["complete"])

        await self._case(body)

    async def test_malformed_location_is_invalid_argument(self) -> None:
        async def body(session: ClientSession) -> None:
            for location in ("12", f"{self.store}{os.sep}sA.jsonl", "ctxref:"):
                res = await self._call(
                    session,
                    "read_session_context",
                    {
                        "source": "pi",
                        "session_id": "sA",
                        "location": location,
                        "scope": SCOPE,
                    },
                )
                self.assertFalse(res.is_error, location)
                payload = _payload(res)
                self.assertEqual(payload["reason"], "invalid_argument", location)
                self.assertEqual(payload["results"], [])
                self.assertNotIn(
                    str(self.store), json.dumps(payload).replace("\\\\", "\\")
                )

        await self._case(body)

    async def test_cross_file_token_usage_refuses_as_binding_mismatch(self) -> None:
        """把 B 文件的引用配 A 文件的会话标识来读：绑定核对必须拒掉（两条轴都指错）。"""

        async def body(session: ClientSession) -> None:
            res = await self._call(
                session, "search_sessions", {"query": "needle", "scope": SCOPE}
            )
            rows = _payload(res)["results"]
            by_session = {row["session_id"]: row["location"] for row in rows}
            self.assertEqual(len(by_session), 2, "需要两条不同绑定的引用")
            wrong = await self._call(
                session,
                "read_session_context",
                {
                    "source": "pi",
                    "session_id": "sA",
                    "location": by_session["sB"],
                    "scope": SCOPE,
                },
            )
            self.assertFalse(wrong.is_error)
            payload = _payload(wrong)
            self.assertEqual(payload["reason"], "binding_mismatch", payload)
            self.assertEqual(payload["results"], [])

        await self._case(body)

    async def test_path_like_scope_still_refused_when_bound(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(
                session,
                "search_sessions",
                {"query": "needle", "scope": str(self.store)},
            )
            self.assertTrue(res.is_error)
            self.assertIn("scope", _error_text(res))
            self.assertNotIn(str(self.store), _error_text(res), "不回显调用方输入")

        await self._case(body)

    async def test_window_bounds_and_limit_rejected(self) -> None:
        async def body(session: ClientSession) -> None:
            sid, token = await self._first_token(session)
            for before, after in ((11, 0), (0, -1)):
                res = await self._call(
                    session,
                    "read_session_context",
                    {
                        "source": "pi",
                        "session_id": sid,
                        "location": token,
                        "scope": SCOPE,
                        "before": before,
                        "after": after,
                    },
                )
                self.assertTrue(res.is_error, (before, after))
            res = await self._call(
                session,
                "search_sessions",
                {"query": "needle", "scope": SCOPE, "limit": 101},
            )
            self.assertTrue(res.is_error)
            self.assertIn("limit", _error_text(res))
            # 会话仍然可用：拒绝不破坏连接。
            alive = await self._call(session, "list_sources", {})
            self.assertFalse(alive.is_error)

        await self._case(body)

    async def test_no_resources_or_prompts_when_bound(self) -> None:
        """绑定后也不得凭 `resources/*` 读到任意本地文件（与未绑定侧同口径）。"""

        async def body(session: ClientSession) -> None:
            self.assertEqual((await session.list_resources()).resources, [])
            self.assertEqual((await session.list_prompts()).prompts, [])
            probe = self.store / "sA.jsonl"
            try:
                await session.read_resource(probe.as_uri())
            except MCPError as exc:
                self.assertIn(exc.code, (-32602, -32601))
            else:
                self.fail("resources/read 不得返回会话文件内容")

        await self._case(body)


class TestBoundHermesStdio(_BoundHost):
    """宿主走 `_bound_stdio_host.py` 的 Hermes 分支：单库双会话的有界绑定闭环。

    库与会话全部由 tests/hermes_synthetic.py 现场新建在临时目录；绑定集合是宿主配置的
    `(库, 会话)` 二元组（客户端在协议面上永远无法提供库路径），因此本类验证的是真实
    stdio 上的 Hermes 检索 → ctxref → 上下文读取闭环、拒绝口径与路径不外泄。
    """

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.hermes_dir = self.temp / "hermes"
        self.hermes_db = self.hermes_dir / "state.db"
        conn = create_store(self.hermes_db)
        add_session(
            conn,
            "sA",
            cwd=str(self.repo_a),
            git_repo_root=str(self.repo_a),
        )
        add_message(conn, "sA", "user", "hermes needle alpha one")
        add_message(conn, "sA", "assistant", "hermes filler alpha two")
        add_message(conn, "sA", "user", "hermes needle alpha three")
        add_session(
            conn,
            "sB",
            cwd=str(self.repo_b),
            git_repo_root=str(self.repo_b),
        )
        add_message(conn, "sB", "user", "hermes needle beta one")
        add_message(conn, "sB", "assistant", "hermes filler beta two")
        conn.close()
        env = dict(self.params.env or {})
        env["CROSS_AGENT_TEST_HERMES_DB"] = str(self.hermes_db)
        env["CROSS_AGENT_TEST_HERMES_REPO"] = str(self.repo_a)
        self.params = StdioServerParameters(
            command=self.params.command,
            args=list(self.params.args or []),
            env=env,
            cwd=self.params.cwd,
        )

    async def _search(self, session: ClientSession, args: dict[str, Any]) -> Any:
        base: dict[str, Any] = {"query": "needle", "scope": SCOPE}
        base.update(args)
        return await self._call(session, "search_sessions", base)

    async def _first_token(self, session: ClientSession) -> tuple[str, str]:
        res = await self._search(session, {})
        self.assertFalse(res.is_error, _error_text(res))
        rows = _payload(res)["results"]
        self.assertGreater(len(rows), 0)
        return rows[0]["session_id"], rows[0]["location"]

    def _assert_no_path_leak(self, payload: Any) -> None:
        dump = json.dumps(payload).replace("\\\\", "\\")
        for forbidden in (
            str(self.hermes_db),
            "state.db",
            str(self.hermes_dir),
            str(self.repo_a),
            str(self.repo_b),
        ):
            self.assertNotIn(forbidden, dump, "Hermes 面不得外出任何本地路径")

    async def test_list_sources_hermes_ready_pi_stays_unavailable(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._call(session, "list_sources", {})
            self.assertFalse(res.is_error)
            payload = _payload(res)
            rows = {row["source"]: row for row in payload["sources"]}
            self.assertEqual(len(rows), 6, "六类必备来源都要有行")
            hermes = rows["hermes"]
            self.assertEqual(hermes["status"], "ready", "宿主已注入 Hermes 聚合服务")
            self.assertIs(hermes["enabled"], True)
            self.assertIn("宿主已显式绑定", hermes["reason"])
            # pi 侧本宿主故意不绑：绑定槽位只容一族，pi 行必须是未绑定口径。
            pi = rows["pi"]
            self.assertEqual(pi["status"], "unavailable")
            self.assertIs(pi["enabled"], False)
            self.assertIn("宿主未在本进程注入", pi["reason"])
            self.assertNotIn("未实现", pi["reason"], "pi 适配器已编写，不得误标未实现")
            self.assertEqual(payload["implementation_status"], "partial")
            self.assertIs(payload["config_checked"], False, "ready 不来自配置读取")
            self.assertIs(payload["verified"], False, "ready 不来自磁盘探测")
            for name in ("dsh", "workbuddy", "cursor_agent_cli", "codex"):
                row = rows[name]
                self.assertEqual(row["status"], "unavailable", name)
                self.assertIs(row["enabled"], False, name)
                self.assertIsNone(row["project_config"], name)
                self.assertIn("宿主未在本进程注入", row["reason"], name)
                self.assertNotIn("未实现", row["reason"], name)
            self._assert_no_path_leak(payload)

        await self._case(body)

    async def test_hermes_search_and_ctxref_read_closure(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._search(session, {})
            self.assertFalse(res.is_error, _error_text(res))
            payload = _payload(res)
            # 两条绑定会话的命中都要出现：接线的是聚合服务，路由靠 (库, 会话) 二元组。
            self.assertEqual(
                sorted({row["session_id"] for row in payload["results"]}),
                ["sA", "sB"],
                payload,
            )
            self.assertTrue(payload["complete"])
            self.assertFalse(payload["partial"])
            self.assertEqual(payload["coverage_scope"], "bounded_hermes_store_set")
            self.assertEqual(
                [row["status"] for row in payload["stores"]], ["read", "read"]
            )
            self.assertEqual(payload["coverage"][0]["status"], "searched")
            by_session = {
                row["session_id"]: row["location"] for row in payload["results"]
            }
            self._assert_no_path_leak(payload)
            for sid, token in by_session.items():
                self.assertTrue(token.startswith("ctxref:"), token)
                read = await self._call(
                    session,
                    "read_session_context",
                    {
                        "source": "hermes",
                        "session_id": sid,
                        "location": token,
                        "scope": SCOPE,
                        "before": 1,
                        "after": 1,
                    },
                )
                self.assertFalse(read.is_error, _error_text(read))
                ctx = _payload(read)
                self.assertTrue(ctx["complete"], ctx)
                self.assertGreaterEqual(len(ctx["results"]), 1)
                self.assertEqual({r["session_id"] for r in ctx["results"]}, {sid})
                # 窗口按行序交出（before=1 时首行可能是锚的前一行）：锚正文必须在窗口里。
                self.assertTrue(
                    any("needle" in r["snippet"].lower() for r in ctx["results"]),
                    ctx,
                )
                # 一次上下文只证明那一个 (库, 会话) 绑定。
                self.assertEqual(
                    ctx["coverage_scope"], "single_bound_hermes_store"
                )
                self.assertEqual(ctx["stage_reached"], "published")
                self.assertIs(ctx["version_confirmed"], True)
                self._assert_no_path_leak(ctx)

        await self._case(body)

    async def test_project_filter_narrows_hermes_bindings(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._search(session, {"project": "test-proj-0"})
            self.assertFalse(res.is_error, _error_text(res))
            payload = _payload(res)
            self.assertEqual(
                {row["session_id"] for row in payload["results"]},
                {"sA"},
                "项目收窄应只留 repo-a 那条绑定",
            )
            self._assert_no_path_leak(payload)

        await self._case(body)

    async def test_pi_named_against_hermes_host_is_unsupported_not_rejected(self) -> None:
        async def body(session: ClientSession) -> None:
            res = await self._search(session, {"sources": ["pi"]})
            self.assertFalse(res.is_error, "本宿主未绑 pi：是状态报告，不是参数错误")
            payload = _payload(res)
            # P1-7/P1-8 后：点名未绑定的已编写来源报 service_unbound（不是 source_unsupported）。
            self.assertEqual(payload["failure_category"], "service_unbound")
            self.assertEqual(payload["returned_count"], 0)
            self.assertEqual(payload["results"], [])
            self._assert_no_path_leak(payload)

        await self._case(body)

    async def test_hermes_read_scope_mismatch_refuses_without_opening_store(self) -> None:
        async def body(session: ClientSession) -> None:
            sid, token = await self._first_token(session)
            res = await self._call(
                session,
                "read_session_context",
                {
                    "source": "hermes",
                    "session_id": sid,
                    "location": token,
                    "scope": "other-scope",
                },
            )
            self.assertTrue(res.is_error)
            text = _error_text(res)
            self.assertIn("scope", text)
            self.assertIn("未打开任何文件", text)
            self.assertNotIn(str(self.hermes_db), text, "拒绝文案不得外出路径")

        await self._case(body)

    async def test_hermes_ref_expired_and_invalid_location_payloads(self) -> None:
        async def body(session: ClientSession) -> None:
            unknown = await self._call(
                session,
                "read_session_context",
                {
                    "source": "hermes",
                    "session_id": "sA",
                    "location": "ctxref:" + "z" * 40,
                    "scope": SCOPE,
                },
            )
            self.assertFalse(unknown.is_error, "读不到是零结果结论，不是协议错误")
            payload = _payload(unknown)
            self.assertEqual(payload["reason"], "ref_expired")
            self.assertEqual(payload["results"], [])
            self.assertFalse(payload["complete"])
            self._assert_no_path_leak(payload)
            for location in ("ctxref:", "line:3", str(self.hermes_db)):
                res = await self._call(
                    session,
                    "read_session_context",
                    {
                        "source": "hermes",
                        "session_id": "sA",
                        "location": location,
                        "scope": SCOPE,
                    },
                )
                self.assertFalse(res.is_error, location)
                bad = _payload(res)
                self.assertEqual(bad["reason"], "invalid_argument", location)
                self.assertEqual(bad["results"], [])
                self._assert_no_path_leak(bad)

        await self._case(body)

    async def test_hermes_cross_binding_token_refused_as_binding_mismatch(self) -> None:
        """把 sA 发的引用配 sB 的会话标识来读：绑定核对必须拒掉。"""

        async def body(session: ClientSession) -> None:
            res = await self._search(session, {})
            rows = _payload(res)["results"]
            by_session = {row["session_id"]: row["location"] for row in rows}
            self.assertEqual(len(by_session), 2, "需要两条不同绑定的引用")
            wrong = await self._call(
                session,
                "read_session_context",
                {
                    "source": "hermes",
                    "session_id": "sA",
                    "location": by_session["sB"],
                    "scope": SCOPE,
                },
            )
            self.assertFalse(wrong.is_error)
            payload = _payload(wrong)
            self.assertEqual(payload["reason"], "binding_mismatch", payload)
            self.assertEqual(payload["results"], [])
            self._assert_no_path_leak(payload)

        await self._case(body)

    async def test_hermes_window_and_limit_rejected_before_service(self) -> None:
        async def body(session: ClientSession) -> None:
            sid, token = await self._first_token(session)
            for before, after in ((11, 0), (0, -1)):
                res = await self._call(
                    session,
                    "read_session_context",
                    {
                        "source": "hermes",
                        "session_id": sid,
                        "location": token,
                        "scope": SCOPE,
                        "before": before,
                        "after": after,
                    },
                )
                self.assertTrue(res.is_error, (before, after))
            over = await self._search(session, {"limit": 101})
            self.assertTrue(over.is_error)
            self.assertIn("limit", _error_text(over))
            # 拒绝不破坏连接：会话仍可用。
            alive = await self._call(session, "list_sources", {})
            self.assertFalse(alive.is_error)

        await self._case(body)


if __name__ == "__main__":
    unittest.main()
