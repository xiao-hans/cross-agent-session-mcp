"""§7 接线侧的合成验证（W-01..W-09）：七族绑定门、逐族分发、跨族合并与固定拒绝口径。

只用临时目录里的合成夹具；不读取任何真实会话、不访问用户配置目录、不联网、不起子进程
（进程内直接调用三个工具 handler，与 `tests/test_session_context.py` 同一手法）。
W-10（既有 stdio 绑定用例在注册表改造后全绿）属于统一测试轮检查点，见
`tmp/pi-all-sources-implementation-result.md`，本文件不重复跑真实 stdio。

覆盖计划条目：W-01 全未绑定文案矩阵快照 | W-02 单族绑定不串味 | W-03 扩展来源
claude_code_cli 的 disabled 覆盖行与零磁盘触达 | W-04 DSH 解码未就绪永远不 ready |
W-05 多族同绑的合并与全局 limit | W-06 合并 flags 传播与 scope_mismatch ToolError |
W-07 上下文路由：跨族坐标 binding_mismatch、未绑定族固定拒绝 | W-08 reset 清全表与账本 |
W-09 参数门回归与别名归一。

运行：python -m unittest tests.test_wiring_all_sources -v
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import cursor_synthetic as cfx  # noqa: E402
import dsh_synthetic as dfx  # noqa: E402
import workbuddy_synthetic as wfx  # noqa: E402

from cross_agent_session_mcp import server  # noqa: E402
from cross_agent_session_mcp.line_search import (  # noqa: E402
    CODEX_SPEC,
    CURSOR_SPEC,
    LineAggregateContextService,
    LineAggregateSearchService,
    make_dsh_spec,
)
from cross_agent_session_mcp.multi_source import (  # noqa: E402
    FamilyContextEntry,
    FamilySearchEntry,
    ServiceRegistry,
)
from cross_agent_session_mcp.policy import (  # noqa: E402
    CwdRootGrant,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.references import (  # noqa: E402
    ReferenceLedger,
    lookup_reference,
    parse_reference_token,
)
from cross_agent_session_mcp.server import (  # noqa: E402
    ToolError,
    bind_codex_file_context_service,
    bind_codex_file_search_service,
    bind_cursor_file_context_service,
    bind_cursor_file_search_service,
    bind_dsh_context_service,
    bind_dsh_search_service,
    bind_pi_multi_file_context_service,
    bind_pi_multi_file_search_service,
    bind_workbuddy_store_context_service,
    bind_workbuddy_store_search_service,
    reset_bound_services,
)
from cross_agent_session_mcp.session_discovery import (  # noqa: E402
    PiMultiFileContextService,
    PiMultiFileSearchService,
    SessionFileRef,
)
from cross_agent_session_mcp.sources import dsh as dsh_source  # noqa: E402
from cross_agent_session_mcp.sources import workbuddy as workbuddy_source  # noqa: E402
from cross_agent_session_mcp.sources.cursor import CursorAgentTranscriptLineParser  # noqa: E402
from cross_agent_session_mcp.sources.dsh import (  # noqa: E402
    DshDecoderMode,
    DshDecoderRuntime,
)
from cross_agent_session_mcp.sources.workbuddy import (  # noqa: E402
    WORKBUDDY_BODY_LAYOUT_REASON,
    WorkBuddyAggregateContextService,
    WorkBuddyAggregateSearchService,
    WorkBuddyStoreRef,
)

SCOPE = "wiring-scope"
PROJECT = "wiring-project"
RT = DshDecoderRuntime.probe()


def rows_of(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["source"]: row for row in payload["sources"]}


def coverage_of(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["source"]: row for row in payload.get("coverage") or []}


def run(tool: Any, **kwargs: Any) -> Any:
    return asyncio.run(tool(**kwargs))


class WiringCase(unittest.TestCase):
    """每个用例独立的临时目录 + 独立授权范围；结束一律 reset，槽位不跨用例残留。"""

    def setUp(self) -> None:
        reset_bound_services()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.proj = self.root / "proj"
        self.proj.mkdir()
        self.store = self.root / "store"
        self.store.mkdir()

    def tearDown(self) -> None:
        reset_bound_services()
        self._tmp.cleanup()

    def policy(self) -> SessionPolicy:
        grants = (
            StoreRootGrant("pi", str(self.store)),
            StoreRootGrant("codex", str(self.store)),
            StoreRootGrant("claude_code_cli", str(self.store)),
            StoreRootGrant(cfx.SOURCE, str(self.store)),
            StoreRootGrant(dfx.SOURCE, str(self.store)),
            StoreRootGrant(wfx.SOURCE, str(self.root)),
        )
        return SessionPolicy(
            (
                ScopeGrant(
                    SCOPE,
                    (ProjectGrant(PROJECT, (CwdRootGrant(str(self.proj), allow_links=True),)),),
                    grants,
                ),
            )
        )

    # -- 夹具写入 ---------------------------------------------------------
    def write_pi(self, name: str = "pi-s1.jsonl", *, needle: str = "wiring needle", count: int = 1) -> Path:
        rows: list[dict[str, Any]] = [
            {"type": "session", "version": "1", "cwd": str(self.proj), "id": "pi-s1"},
        ]
        for index in range(count):
            rows.append(
                {
                    "type": "message",
                    "message": {
                        "role": "user",
                        "timestamp": f"2026-03-01T10:0{index}:00Z",
                        "content": [{"type": "text", "text": f"{needle} {index}"}],
                    },
                }
            )
        path = self.store / name
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def bind_pi_pair(
        self, files: tuple[Path, ...]
    ) -> PiMultiFileSearchService:
        """pi 聚合族成对绑定：同一组批准文件、共用默认账本（两侧 ledger=None）。"""
        refs = tuple(
            SessionFileRef(path=str(path), session_id="pi-s1") for path in files
        )
        policy = self.policy()
        search = PiMultiFileSearchService(policy=policy, scope=SCOPE, files=refs)
        context = PiMultiFileContextService(policy=policy, scope=SCOPE, files=refs)
        bind_pi_multi_file_search_service(search)
        bind_pi_multi_file_context_service(context, search_service=search)
        return search

    def write_cursor(self, name: str = "cursor-s1.jsonl") -> Path:
        directory = self.store / "agent-transcripts"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        lines = cfx.normal_stream(query="wiring needle", reply="wiring needle reply")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def write_dsh(self, name: str = "session.v4.jsonl.zstd") -> Path:
        frames = [
            dfx.header_frame(),
            dfx.message_frame("wiring needle"),
            dfx.user_frame("wiring needle reply"),
        ]
        path = self.store / name
        path.write_bytes(b"".join(frames))
        return path

    def write_codex(self, name: str = "codex-s1.jsonl") -> Path:
        rows: list[dict[str, Any]] = [
            {"type": "session", "version": "1", "id": "codex-s1", "cwd": str(self.proj)},
        ]
        for index, text in enumerate(("wiring needle one", "wiring needle two")):
            rows.append(
                {
                    "type": "message",
                    "message": {
                        "role": "user",
                        "timestamp": f"2026-03-01T10:0{index}:00Z",
                        "content": [{"type": "input_text", "text": text}],
                    },
                }
            )
        path = self.store / name
        path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        return path

    def write_workbuddy(self, name: str = "index.db") -> Path:
        path = self.root / name
        conn = wfx.build_store(path)
        wfx.add_session(conn, project_path=str(self.proj))
        conn.close()
        return path

    # -- 服务成对构造 -----------------------------------------------------
    def line_pair(
        self,
        spec: Any,
        refs: tuple[SessionFileRef, ...],
        *,
        ledger: ReferenceLedger | None = None,
    ) -> tuple[LineAggregateSearchService, LineAggregateContextService, ReferenceLedger]:
        policy = self.policy()
        use = ReferenceLedger() if ledger is None else ledger
        search = LineAggregateSearchService(
            policy=policy, scope=SCOPE, spec=spec, files=refs, ledger=use
        )
        context = LineAggregateContextService(
            policy=policy,
            scope=SCOPE,
            spec=spec,
            path=refs[0].path,
            session_id=refs[0].session_id,
            ledger=use,
        )
        return search, context, use

    def bind_cursor(self) -> tuple[LineAggregateSearchService, Path]:
        path = self.write_cursor()
        refs = (SessionFileRef(path=str(path), session_id=cfx.SESSION),)
        search, context, _ = self.line_pair(CURSOR_SPEC, refs)
        bind_cursor_file_search_service(search)
        bind_cursor_file_context_service(context, search_service=search)
        return search, path

    def bind_workbuddy(self) -> Path:
        path = self.write_workbuddy()
        policy = self.policy()
        ledger = ReferenceLedger()
        refs = (WorkBuddyStoreRef(store_path=str(path), session_id=wfx.SESSION),)
        search = WorkBuddyAggregateSearchService(
            policy=policy, scope=SCOPE, stores=refs, ledger=ledger
        )
        context = WorkBuddyAggregateContextService(
            policy=policy, scope=SCOPE, stores=refs, ledger=ledger
        )
        bind_workbuddy_store_search_service(search)
        bind_workbuddy_store_context_service(context, search_service=search)
        return path


class TestUnboundMatrix(WiringCase):
    """W-01：七族全未绑定的口径快照——接线完成后不再有「未编写适配器」的说法。"""

    REQUIRED_ROWS = ("hermes", "dsh", "workbuddy", "pi", "cursor_agent_cli", "codex")

    def test_all_six_rows_unavailable_and_enabled_false(self) -> None:
        payload = run(server.list_sources)
        # P1-8：七族注册表非空 ⇒ 本构建已接线，顶层恒报 partial（not_implemented
        # 只留给注册表为空的构建）；宿主未注入只影响逐源 enabled/status，不改顶层。
        self.assertEqual(payload["implementation_status"], "partial")
        self.assertIs(payload["verified"], False)
        self.assertIs(payload["config_checked"], False)
        rows = rows_of(payload)
        self.assertEqual(sorted(rows), sorted(self.REQUIRED_ROWS))
        for name, row in rows.items():
            self.assertEqual(row["status"], "unavailable", name)
            self.assertIs(row["enabled"], False, name)
            self.assertIsNone(row["project_config"], name)
            self.assertTrue(row["reason"], name)

    def test_reasons_never_claim_unimplemented_adapter(self) -> None:
        rows = rows_of(run(server.list_sources))
        for name, row in rows.items():
            reason = row["reason"]
            self.assertNotIn("未编写", reason, name)
            self.assertNotIn("未实现", reason, name)
            self.assertNotIn("unsupported", reason, name)
            self.assertIn("宿主未在本进程注入", reason, name)
            self.assertIn("project_config 为 null", reason, name)

    def test_workbuddy_unbound_states_body_layout_unverified(self) -> None:
        rows = rows_of(run(server.list_sources))
        self.assertIn("正文文件布局未逐字核实", rows["workbuddy"]["reason"])

    def test_tools_refuse_without_touching_disk(self) -> None:
        with mock.patch.object(
            server, "_registry", wraps=server._registry
        ) as spy:  # 分发层不得被调用
            with self.assertRaises(Exception) as search_error:
                run(server.search_sessions, query="needle", scope=SCOPE)
            with self.assertRaises(Exception) as read_error:
                run(
                    server.read_session_context,
                    source="codex",
                    session_id="s1",
                    location="ctxref:" + "a" * 40,
                    scope=SCOPE,
                )
        self.assertEqual(spy.search.call_count, 0)
        self.assertEqual(spy.read_context.call_count, 0)
        self.assertIn("未绑定", str(search_error.exception))
        self.assertIn("未绑定", str(read_error.exception))
        self.assertNotIn("未实现", str(search_error.exception))

    def test_unknown_source_still_rejected_and_alias_normalized(self) -> None:
        # W-09 参数门：未知来源仍是参数错误，不因新族放行。
        bind = self.bind_cursor()  # noqa: F841 —— 需要至少一个族在场
        with self.assertRaises(Exception) as unknown:
            run(server.search_sessions, query="needle", sources=["nosuch"], scope=SCOPE)
        self.assertIn("sources 含未支持的来源", str(unknown.exception))
        with self.assertRaises(Exception) as bad_source:
            run(
                server.read_session_context,
                source="nosuch",
                session_id=cfx.SESSION,
                location="1:1",
                scope=SCOPE,
            )
        self.assertIn("source 为未支持的来源", str(bad_source.exception))
        # `claude_code` 简称归一为规范 ID：放行到分发层，报 disabled 覆盖行而非参数错误。
        payload = run(
            server.search_sessions, query="needle", sources=["claude_code"], scope=SCOPE
        )
        self.assertIn("claude_code_cli", coverage_of(payload))
        self.assertEqual(coverage_of(payload)["claude_code_cli"]["status"], "disabled")


class TestSingleFamilyBinding(WiringCase):
    """W-02/W-04：单族绑定只改自己那一行；DSH 未就绪永远不 ready。"""

    def test_cursor_binding_flips_only_its_row(self) -> None:
        before = rows_of(run(server.list_sources))
        self.assertEqual(before["cursor_agent_cli"]["status"], "unavailable")
        self.bind_cursor()
        after = rows_of(run(server.list_sources))
        self.assertEqual(after["cursor_agent_cli"]["status"], "ready")
        self.assertIs(after["cursor_agent_cli"]["enabled"], True)
        self.assertIn("不表示整个来源已扫完", after["cursor_agent_cli"]["reason"])
        for name in ("hermes", "dsh", "workbuddy", "pi", "codex"):
            self.assertEqual(after[name]["status"], "unavailable", name)
            self.assertIs(after[name]["enabled"], False, name)

    def test_context_only_binding_does_not_claim_search_ready(self) -> None:
        path = self.write_cursor()
        search, context, _ = self.line_pair(
            CURSOR_SPEC, (SessionFileRef(path=str(path), session_id=cfx.SESSION),)
        )
        bind_cursor_file_context_service(context)
        rows = rows_of(run(server.list_sources))
        self.assertEqual(rows["cursor_agent_cli"]["status"], "unavailable")
        bind_cursor_file_search_service(search)
        rows = rows_of(run(server.list_sources))
        self.assertEqual(rows["cursor_agent_cli"]["status"], "ready")

    def test_bound_payload_never_leaks_absolute_paths(self) -> None:
        self.bind_cursor()
        self.bind_workbuddy()
        dump = json.dumps(run(server.list_sources), ensure_ascii=False)
        self.assertNotIn(str(self.root), dump)
        self.assertNotIn("agent-transcripts", dump)

    def test_wrong_family_service_is_rejected_at_bind_time(self) -> None:
        codex = self.write_codex()
        codex_search, _, _ = self.line_pair(
            CODEX_SPEC, (SessionFileRef(path=str(codex), session_id="codex-s1"),)
        )
        cursor_path = self.write_cursor()
        _, cursor_context, _ = self.line_pair(
            CURSOR_SPEC, (SessionFileRef(path=str(cursor_path), session_id=cfx.SESSION),)
        )
        with self.assertRaises(TypeError):
            bind_cursor_file_search_service("not-a-service")  # type: ignore[arg-type]
        # 装错槽：codex 检索服务配进 cursor 上下文槽，必须在成对形状核对处被拒
        # （两侧账本不是同一个实例——绑定错误，不得伪装成运行时的引用问题）。
        bind_codex_file_search_service(codex_search)
        with self.assertRaises(ValueError):
            bind_cursor_file_context_service(cursor_context, search_service=codex_search)

    def test_ledger_less_line_service_is_rejected(self) -> None:
        path = self.write_cursor()
        policy = self.policy()
        bare = LineAggregateSearchService(
            policy=policy,
            scope=SCOPE,
            spec=CURSOR_SPEC,
            files=(SessionFileRef(path=str(path), session_id=cfx.SESSION),),
        )
        with self.assertRaises(TypeError):
            bind_cursor_file_search_service(bare)

    def test_dsh_bound_without_runtime_is_error_never_ready(self) -> None:
        if not dfx.frames_available():
            self.skipTest("本机无 zstd 后端，DSH 帧夹具不可构造（P1-9）")
        path = self.write_dsh()
        search, context, _ = self.line_pair(
            make_dsh_spec(RT), (SessionFileRef(path=str(path), session_id=dfx.SESSION),)
        )
        missing = DshDecoderRuntime(mode=DshDecoderMode.MISSING, python_path=None)
        bind_dsh_search_service(search, decoder_python="C:/synthetic/missing-python")
        bind_dsh_context_service(
            context, search_service=search, decoder_python="C:/synthetic/missing-python"
        )
        with mock.patch.object(server, "_dsh_runtime", missing):
            rows = rows_of(run(server.list_sources))
            self.assertEqual(rows["dsh"]["status"], "error")
            self.assertIs(rows["dsh"]["enabled"], False)
            self.assertIn(dsh_source.DSH_DECODER_MISSING_REASON, rows["dsh"]["reason"])
            self.assertNotEqual(rows["dsh"]["status"], "ready")
            payload = run(
                server.search_sessions, query="needle", sources=["dsh"], scope=SCOPE
            )
            dsh_row = coverage_of(payload)["dsh"]
            # _dsh_search_factory 对未就绪运行时返回 None：覆盖行按未绑槽位诚实标注。
            self.assertIn(dsh_row["status"], ("error", "unavailable", "disabled"))
            self.assertNotEqual(dsh_row["status"], "searched")
            self.assertNotEqual(dsh_row["status"], "ready")
            self.assertIn(payload.get("failure_category"), (None, "service_unbound"))
            self.assertEqual(payload["results"], [])
        self.assertEqual(server._line_search_slots.get("dsh"), search)

    def test_dsh_ready_requires_usable_runtime(self) -> None:
        if not RT.usable:
            self.skipTest("本机无可用 zstd 解码入口，DSH ready 由 error 侧用例覆盖")
        path = self.write_dsh()
        search, context, _ = self.line_pair(
            make_dsh_spec(RT), (SessionFileRef(path=str(path), session_id=dfx.SESSION),)
        )
        bind_dsh_search_service(search)
        bind_dsh_context_service(context, search_service=search)
        rows = rows_of(run(server.list_sources))
        self.assertEqual(rows["dsh"]["status"], "ready")
        self.assertIs(rows["dsh"]["enabled"], True)
        self.assertIn("解码运行时可用", rows["dsh"]["reason"])
        bind_dsh_search_service(None)
        rows = rows_of(run(server.list_sources))
        self.assertEqual(rows["dsh"]["status"], "unavailable")
        self.assertIsNone(server._dsh_runtime, "解绑必须同时清掉解码运行时")

    def test_decoder_python_argument_gate(self) -> None:
        if not dfx.frames_available():
            self.skipTest("本机无 zstd 后端，DSH 帧夹具不可构造（P1-9）")
        path = self.write_dsh()
        search, _, _ = self.line_pair(
            make_dsh_spec(RT), (SessionFileRef(path=str(path), session_id=dfx.SESSION),)
        )
        for bad in ("", "   ", 7, Path("C:/x")):
            with self.assertRaises(TypeError):
                bind_dsh_search_service(search, decoder_python=bad)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            bind_dsh_search_service(None, decoder_python="C:/synthetic/python")


class TestExtendedClaudeFamily(WiringCase):
    """W-03：扩展来源 claude_code_cli 未绑定时 disabled 覆盖行 + 零磁盘触达。"""

    def test_named_unbound_produces_disabled_row_and_zero_reads(self) -> None:
        self.bind_cursor()
        opened: list[Any] = []
        real_open = Path.open

        def spy(self_path: Path, *args: Any, **kwargs: Any) -> Any:
            opened.append(str(self_path))
            return real_open(self_path, *args, **kwargs)

        with mock.patch.object(Path, "open", spy):
            payload = run(
                server.search_sessions, query="needle", sources=["claude_code_cli"], scope=SCOPE
            )
        self.assertEqual(opened, [], "disabled 覆盖行不得打开任何文件")
        row = coverage_of(payload)["claude_code_cli"]
        self.assertEqual(row["status"], "disabled")
        self.assertIs(row["enabled"], False)
        self.assertIn("扩展来源", row["reason"])
        self.assertEqual(payload["results"], [])

    def test_all_disabled_rows_leave_top_level_reason_empty(self) -> None:
        self.bind_cursor()
        payload = run(
            server.search_sessions, query="needle", sources=["claude_code_cli"], scope=SCOPE
        )
        self.assertIs(payload["complete"], False)
        self.assertIs(payload["partial"], True)
        self.assertIsNone(payload.get("failure_category"), payload)
        self.assertEqual(payload.get("reason") or "", "")

    def test_bound_claude_family_is_routed(self) -> None:
        codex = self.write_codex()
        search, context, _ = self.line_pair(
            CODEX_SPEC, (SessionFileRef(path=str(codex), session_id="codex-s1"),)
        )
        bind_codex_file_search_service(search)
        bind_codex_file_context_service(context, search_service=search)
        payload = run(
            server.search_sessions, query="wiring needle", sources=["codex"], scope=SCOPE
        )
        row = coverage_of(payload)["codex"]
        self.assertEqual(row["coverage_scope"], "bounded_line_file_set:codex")
        self.assertIn(row["status"], ("no_match", "searched", "incomplete"), row["status"])


class TestMultiFamilyMerge(WiringCase):
    """W-05/W-06：多族同绑（跨族共存）→ 逐族分发、跨族合并、全局 limit。"""

    def test_three_families_coexist_and_merge(self) -> None:
        self.bind_cursor()
        self.bind_workbuddy()
        codex = self.write_codex()
        search, context, _ = self.line_pair(
            CODEX_SPEC, (SessionFileRef(path=str(codex), session_id="codex-s1"),)
        )
        bind_codex_file_search_service(search)
        bind_codex_file_context_service(context, search_service=search)

        rows = rows_of(run(server.list_sources))
        for name in ("codex", "cursor_agent_cli", "workbuddy"):
            self.assertEqual(rows[name]["status"], "ready", name)

        payload = run(
            server.search_sessions,
            query="wiring needle",
            sources=["codex", "cursor_agent_cli", "workbuddy"],
            scope=SCOPE,
        )
        self.assertEqual(len(payload["coverage"]), 3)
        self.assertEqual(payload["coverage_scope"], "bounded_service_sets")
        self.assertIs(payload["partial"], True)
        self.assertIs(payload["complete"], False)
        self.assertEqual(payload["returned_count"], len(payload["results"]))
        # 行族合成夹具的归属核对不放行、WorkBuddy 正文布局未核实 ⇒ 本次合并零命中，
        # 但三行有界覆盖与半覆盖旗标必须齐备——这正是接线要证明的诚实口径。
        self.assertEqual(payload["results"], [])
        self.assertIn(
            coverage_of(payload)["cursor_agent_cli"]["status"],
            ("incomplete", "no_match", "searched"),
        )
        self.assertEqual(coverage_of(payload)["workbuddy"]["status"], "incomplete")
        self.assertEqual(
            coverage_of(payload)["workbuddy"]["reason"], WORKBUDDY_BODY_LAYOUT_REASON
        )

    def test_global_limit_truncates_across_sources(self) -> None:
        # 行族合成夹具的归属核对不放行（cursor 头域 cwd 落在授权外），跨源截断改用
        # 可发布的 pi 聚合族验证：一个批准文件三条命中，全局 limit 截到两条。
        three = self.write_pi("pi-limit.jsonl", needle="limit needle", count=3)
        self.bind_pi_pair((three,))

        payload = run(
            server.search_sessions,
            query="limit needle",
            sources=["pi"],
            scope=SCOPE,
            limit=2,
        )
        self.assertEqual(len(payload["results"]), 2)
        self.assertIs(payload["truncated"], True)
        self.assertIs(payload["partial"], True)
        counts = {row["source"]: row["returned_count"] for row in payload["coverage"]}
        self.assertEqual(sum(counts.values()), 2)
        self.assertEqual(payload["returned_count"], 2)

    def test_scope_mismatch_is_a_fixed_refusal(self) -> None:
        self.bind_cursor()
        with self.assertRaises(Exception) as caught:
            run(server.search_sessions, query="needle", scope="D:/somewhere/else")
        self.assertIn("scope 必须是授权范围标识，不得为路径形态", str(caught.exception))
        with self.assertRaises(Exception) as other:
            run(server.search_sessions, query="needle", scope="other-scope")
        self.assertIn("scope 与已绑定授权范围不匹配", str(other.exception))

    def test_rejected_filter_is_a_fixed_refusal(self) -> None:
        self.bind_cursor()
        # ServiceRegistry 是 __slots__ 实例：属性只能打在类上，打在实例上会 AttributeError。
        with mock.patch.object(
            type(server._registry), "search", return_value={"rejected": True, "results": []}
        ), self.assertRaises(ToolError) as caught:
            run(server.search_sessions, query="needle", scope=SCOPE)
        self.assertIn("查询过滤条件不合法", str(caught.exception))

    def test_param_gate_regressions(self) -> None:
        self.bind_cursor()
        for bad_limit in (0, 101, "20", True):
            with self.assertRaises(ToolError):
                run(server.search_sessions, query="needle", scope=SCOPE, limit=bad_limit)
        with self.assertRaises(ToolError):
            run(server.search_sessions, scope=SCOPE)
        with self.assertRaises(ToolError):
            run(server.search_sessions, query="   ", scope=SCOPE)
        with self.assertRaises(ToolError):
            run(server.search_sessions, query="needle", sources="pi", scope=SCOPE)
        with self.assertRaises(ToolError):
            run(server.search_sessions, query="needle", scope="/abs/path")


class TestContextRouting(WiringCase):
    """W-07：上下文按族路由 —— 跨族坐标 binding_mismatch，未绑定族固定拒绝。"""

    def token_for(self, source: str, query: str = "wiring needle") -> str:
        payload = run(
            server.search_sessions, query=query, sources=[source], scope=SCOPE
        )
        self.assertTrue(payload["results"], payload.get("reason"))
        row = payload["results"][0]
        token = row["location"]
        self.assertTrue(str(token).startswith("ctxref:"), token)
        self.assertEqual(row["source"], source)
        return token

    def test_round_trip_reads_back_the_hit(self) -> None:
        # 正向发放-核对回路用可发布的 pi 聚合族：行族合成夹具的归属核对一律不放行。
        self.bind_pi_pair((self.write_pi(),))
        token = self.token_for("pi")
        payload = run(
            server.read_session_context,
            source="pi",
            session_id="pi-s1",
            location=token,
            scope=SCOPE,
        )
        self.assertIsInstance(payload, dict)
        self.assertIn("results", payload)
        self.assertNotIn("coverage_scope", payload.get("reason") or "")
        dump = json.dumps(payload, ensure_ascii=False)
        self.assertNotIn(str(self.store), dump, "上下文结果不得外出磁盘路径")

    def test_cross_family_token_is_binding_mismatch_not_another_family(self) -> None:
        self.bind_cursor()
        self.bind_pi_pair((self.write_pi(),))
        token = self.token_for("pi")
        with mock.patch.object(
            CursorAgentTranscriptLineParser, "feed_line", side_effect=AssertionError("不该重开原文")
        ):
            payload = run(
                server.read_session_context,
                source="cursor_agent_cli",
                session_id=cfx.SESSION,
                location=token,
                scope=SCOPE,
            )
        # pi 账本发的 ctxref 在 cursor 族自己的账本里必然查不到：只出引用类拒绝，
        # 绝不改派别的族、也绝不重开原始文件核对。
        self.assertIn(payload["reason"], ("ref_expired", "source_mismatch", "binding_mismatch"))
        self.assertEqual(payload["results"], [])

    def test_unbound_family_refusals_are_fixed_wording(self) -> None:
        # 只绑 cursor 一族，其余族的上下文请求一律固定拒绝且不触碰磁盘。
        self.bind_cursor()
        with mock.patch.object(dsh_source, "run_dsh_frame_file") as dsh_run, mock.patch.object(
            workbuddy_source, "run_workbuddy_session"
        ) as wb_run:
            with self.assertRaises(Exception) as dsh_error:
                run(
                    server.read_session_context,
                    source="dsh",
                    session_id=dfx.SESSION,
                    location="ctxref:" + "b" * 40,
                    scope=SCOPE,
                )
            with self.assertRaises(Exception) as wb_error:
                run(
                    server.read_session_context,
                    source="workbuddy",
                    session_id=wfx.SESSION,
                    location="ctxref:" + "c" * 40,
                    scope=SCOPE,
                )
            with self.assertRaises(Exception) as claude_error:
                run(
                    server.read_session_context,
                    source="claude_code_cli",
                    session_id="s",
                    location="ctxref:" + "d" * 40,
                    scope=SCOPE,
                )
        self.assertEqual(dsh_run.call_count, 0)
        self.assertEqual(wb_run.call_count, 0)
        self.assertIn(dsh_source.DSH_DECODER_MISSING_REASON, str(dsh_error.exception))
        self.assertIn(WORKBUDDY_BODY_LAYOUT_REASON, str(wb_error.exception))
        self.assertIn("扩展来源且默认未启用", str(claude_error.exception))

    def test_workbuddy_body_read_refuses_by_design(self) -> None:
        path = self.bind_workbuddy()
        payload = run(
            server.search_sessions, query="needle", sources=["workbuddy"], scope=SCOPE
        )
        self.assertEqual(payload["results"], [])
        with mock.patch.object(
            workbuddy_source, "run_workbuddy_session", side_effect=AssertionError("不该读正文")
        ):
            refusal = WorkBuddyAggregateContextService(
                policy=self.policy(),
                scope=SCOPE,
                stores=(WorkBuddyStoreRef(store_path=str(path), session_id=wfx.SESSION),),
                ledger=ReferenceLedger(),
            ).read(
                scope=SCOPE,
                source="workbuddy",
                session_id=wfx.SESSION,
                location="ctxref:" + "e" * 40,
            )
        self.assertEqual(refusal.reason, WORKBUDDY_BODY_LAYOUT_REASON)

    def test_bad_coordinates_are_invalid_argument_not_an_error(self) -> None:
        self.bind_cursor()
        # 空 location 在参数门就被拒：ToolError，且不触碰任何文件。
        with self.assertRaises(ToolError) as empty_error:
            run(
                server.read_session_context,
                source="cursor_agent_cli",
                session_id=cfx.SESSION,
                location="",
                scope=SCOPE,
            )
        self.assertIn("session_id/location 必须为非空字符串", str(empty_error.exception))
        for location in ("12", "line:3", str(self.store / "x.jsonl")):
            payload = run(
                server.read_session_context,
                source="cursor_agent_cli",
                session_id=cfx.SESSION,
                location=location,
                scope=SCOPE,
            )
            self.assertEqual(payload["reason"], "invalid_argument", location)
            self.assertEqual(payload["results"], [])
        self.assertIs(server._registry.supports_context("codex"), True)


class TestResetBoundServices(WiringCase):
    """W-08：reset 清全表 + 账本；解绑单族不影响其它族。"""

    def test_reset_clears_every_slot_and_ledger(self) -> None:
        if not dfx.frames_available():
            self.skipTest("本机无 zstd 后端，DSH 帧夹具不可构造（P1-9）")
        cursor = self.write_cursor()
        dsh = self.write_dsh()
        cursor_refs = (SessionFileRef(path=str(cursor), session_id=cfx.SESSION),)
        dsh_refs = (SessionFileRef(path=str(dsh), session_id=dfx.SESSION),)
        c_search, c_context, c_ledger = self.line_pair(CURSOR_SPEC, cursor_refs)
        d_search, d_context, d_ledger = self.line_pair(make_dsh_spec(RT), dsh_refs)
        bind_cursor_file_search_service(c_search)
        bind_cursor_file_context_service(c_context, search_service=c_search)
        bind_dsh_search_service(d_search)
        bind_dsh_context_service(d_context, search_service=d_search)
        self.bind_workbuddy()
        self.assertEqual(len(c_ledger) + len(d_ledger), 0)

        # 令牌发放用可发布的 pi 聚合族（两侧 ledger=None 共用默认账本）：reset 清默认账本后
        # 旧引用必须核对失败；行族自己的账本实例只验零发放。
        self.bind_pi_pair((self.write_pi(),))
        payload = run(
            server.search_sessions, query="wiring needle", sources=["pi"], scope=SCOPE
        )
        token = payload["results"][0]["location"]
        self.assertIsNotNone(lookup_reference(parse_reference_token(token) or ""))

        reset_bound_services()
        rows = rows_of(run(server.list_sources))
        self.assertEqual({row["status"] for row in rows.values()}, {"unavailable"})
        self.assertEqual(server._line_search_slots, {})
        self.assertEqual(server._line_context_slots, {})
        self.assertIsNone(server._workbuddy_search)
        self.assertIsNone(server._workbuddy_context)
        self.assertIsNone(server._dsh_runtime)
        self.assertIsNone(server._search_service)
        self.assertIsNone(server._context_service)
        self.assertIn("pi-files", server._registry.families(), "reset 必须重装七族登记")
        self.assertIn("workbuddy-store-set", server._registry.families())
        self.assertIsNone(
            lookup_reference(parse_reference_token(token) or ""), "reset 后旧引用不得仍可核对"
        )

    def test_unbinding_one_family_leaves_others_bound(self) -> None:
        self.bind_cursor()
        self.bind_workbuddy()
        bind_cursor_file_search_service(None)
        bind_cursor_file_context_service(None)
        rows = rows_of(run(server.list_sources))
        self.assertEqual(rows["cursor_agent_cli"]["status"], "unavailable")
        self.assertEqual(rows["workbuddy"]["status"], "ready")
        with self.assertRaises(ToolError) as unbound_error:
            run(
                server.read_session_context,
                source="cursor_agent_cli",
                session_id=cfx.SESSION,
                location="ctxref:" + "f" * 40,
                scope=SCOPE,
            )
        self.assertIn("未绑定", str(unbound_error.exception))

    def test_registry_routes_unbound_source_without_touching_disk(self) -> None:
        registry = ServiceRegistry()
        calls: list[str] = []

        def make_service(*, scope: str) -> Any:
            del scope
            calls.append("factory")
            return None

        registry.register_search(
            FamilySearchEntry(family="line:test", sources=("codex",), make_service=make_service)
        )
        registry.register_context(
            FamilyContextEntry(family="line:test", sources=("codex",), make_service=make_service)
        )
        payload = registry.search(scope=SCOPE, requested_sources=["codex"], query="q", limit=5)
        self.assertEqual(payload["coverage"][0]["status"], "disabled")
        self.assertEqual(payload["coverage"][0]["reason"], "service_unbound")
        self.assertEqual(calls, ["factory"])
        self.assertEqual(payload["results"], [])


if __name__ == "__main__":
    unittest.main()
