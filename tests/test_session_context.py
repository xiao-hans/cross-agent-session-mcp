"""受限上下文闭环的合成验证：引用发放 → 绑定核对 → 同趟版本 → 有限窗口（DES-API-01）。

只用临时目录里的合成 JSONL 记录；不读取任何真实会话数据、不加载用户配置、不启动服务。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from cross_agent_session_mcp import server
from cross_agent_session_mcp.file_search import PiFileSearchService
from cross_agent_session_mcp.policy import (
    CwdRootGrant,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.references import (
    MAX_ACTIVE_REFERENCES,
    ReferenceLedger,
    lookup_reference,
    parse_reference_token,
    service_binding_key,
)
from cross_agent_session_mcp.server import (
    bind_pi_file_context_service,
    bind_pi_file_search_service,
    bind_pi_multi_file_context_service,
    bind_pi_multi_file_search_service,
    reset_bound_services,
)
from cross_agent_session_mcp.session_context import (
    MAX_WINDOW_RECORDS,
    ContextFailureCategory,
    PiFileContextService,
)
from cross_agent_session_mcp.session_discovery import (
    PiMultiFileContextService,
    PiMultiFileSearchService,
    SessionFileRef,
)

SCOPE = "synthetic-scope"
SESSION_ID = "synthetic-session"
PROJECT = "synthetic-project"


def _rows(count: int, repo: Path, *, session_id: str = SESSION_ID) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {"type": "session", "version": "1", "cwd": str(repo), "id": session_id}
    ]
    for index in range(count):
        rows.append(
            {
                "type": "message",
                "message": {
                    "role": "user",
                    "timestamp": f"2026-03-01T10:{index:02d}:00Z",
                    "content": [{"type": "input_text", "text": f"needle {index} body"}],
                },
            }
        )
    return rows


def _write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )


class _Fixture(unittest.TestCase):
    """共享的一次性合成夹具：一个策略、一个已批准文件、一对共用账本的服务。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="ctx-ledger-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.store = self.root / "store"
        self.repo.mkdir()
        self.store.mkdir()
        self.policy = SessionPolicy(
            scopes=(
                ScopeGrant(
                    scope_id=SCOPE,
                    projects=(ProjectGrant(PROJECT, (CwdRootGrant(str(self.repo)),)),),
                    store_roots=(StoreRootGrant("pi", str(self.store)),),
                ),
            )
        )
        self.path = self.store / "session.jsonl"
        _write(self.path, _rows(9, self.repo))
        self.ledger = ReferenceLedger()
        self.search = PiFileSearchService(
            policy=self.policy,
            scope=SCOPE,
            path=str(self.path),
            session_id=SESSION_ID,
            ledger=self.ledger,
        )
        self.context = PiFileContextService(
            policy=self.policy,
            scope=SCOPE,
            path=str(self.path),
            session_id=SESSION_ID,
            ledger=self.ledger,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _token(self, index: int = 0) -> str:
        result = self.search.search(scope=SCOPE, query="needle", sources=["pi"], limit=10)
        self.assertTrue(result["complete"], result["failure_category"])
        return str(result["results"][index]["location"])


class TestReferenceLedger(unittest.TestCase):
    """账本自身的容量/期限/绑定语义（不触磁盘）。"""

    def test_token_shape_carries_no_address(self) -> None:
        ledger = ReferenceLedger()
        token = ledger.issue(
            service_key="k",
            path="/approved/only",
            scope="s",
            source="pi",
            session_id="sid",
            project=None,
            line_no=7,
            ordinal=2,
            stream_label=None,
            volume=1,
            file_id=2,
            size_bytes=3,
            content_sha256="a" * 64,
        )
        self.assertTrue(token.startswith("ctxref:"))
        self.assertEqual(parse_reference_token(token), token)
        # 引用串除固定前缀外只有随机段：不含路径/位置记号，客户端无法从中读出地址。
        remainder = token[len("ctxref:"):]
        self.assertNotIn("#", remainder)
        self.assertNotIn("/", remainder)
        self.assertNotIn("\\", remainder)
        self.assertNotIn(":", remainder)
        entry = lookup_reference(token, ledger=ledger)
        assert entry is not None
        self.assertEqual((entry.line_no, entry.ordinal, entry.size_bytes), (7, 2, 3))

    def test_forged_and_nonliteral_tokens_are_unparsable(self) -> None:
        for candidate in (
            "jsonl:unknown-stream#L2",
            "ctxref:",
            "ctxref:with space",
            "ctxref:path/like",
            "ctxref:a" * 2,
            12,
            None,
            "CTXREF:abc",
        ):
            with self.subTest(candidate=candidate):
                self.assertIsNone(parse_reference_token(candidate))

    def test_capacity_evicts_oldest_and_expired_lookup_is_none(self) -> None:
        ledger = ReferenceLedger(capacity=2, ttl_seconds=60.0)
        first = ledger.issue(
            service_key="k",
            path="p",
            scope="s",
            source="pi",
            session_id="sid",
            project=None,
            line_no=1,
            ordinal=0,
            stream_label=None,
            volume=1,
            file_id=1,
            size_bytes=1,
            content_sha256="b" * 64,
        )
        for line in (2, 3):
            ledger.issue(
                service_key="k",
                path="p",
                scope="s",
                source="pi",
                session_id="sid",
                project=None,
                line_no=line,
                ordinal=0,
                stream_label=None,
                volume=1,
                file_id=1,
                size_bytes=1,
                content_sha256="b" * 64,
            )
        self.assertEqual(len(ledger), 2)
        self.assertIsNone(lookup_reference(first, ledger=ledger), "满员按发放顺序淘汰最旧")

    def test_expiry_is_the_same_refusal_as_absence(self) -> None:
        clock = {"now": 100.0}
        ledger = ReferenceLedger(ttl_seconds=60.0, clock=lambda: clock["now"])
        token = ledger.issue(
            service_key="k",
            path="p",
            scope="s",
            source="pi",
            session_id="sid",
            project=None,
            line_no=1,
            ordinal=0,
            stream_label=None,
            volume=1,
            file_id=1,
            size_bytes=1,
            content_sha256="c" * 64,
        )
        self.assertIsNotNone(lookup_reference(token, ledger=ledger))
        clock["now"] += 61.0
        self.assertIsNone(lookup_reference(token, ledger=ledger))
        self.assertEqual(len(ledger), 0, "过期条目在查询时即删除")

    def test_release_only_withholds_named_tokens(self) -> None:
        ledger = ReferenceLedger()
        keep = ledger.issue(
            service_key="k",
            path="p",
            scope="s",
            source="pi",
            session_id="sid",
            project=None,
            line_no=1,
            ordinal=0,
            stream_label=None,
            volume=1,
            file_id=1,
            size_bytes=1,
            content_sha256="d" * 64,
        )
        drop = ledger.issue(
            service_key="k",
            path="p",
            scope="s",
            source="pi",
            session_id="sid",
            project=None,
            line_no=2,
            ordinal=0,
            stream_label=None,
            volume=1,
            file_id=1,
            size_bytes=1,
            content_sha256="d" * 64,
        )
        ledger.release([drop])
        self.assertIsNotNone(lookup_reference(keep, ledger=ledger))
        self.assertIsNone(lookup_reference(drop, ledger=ledger))

    def test_binding_key_is_length_prefixed_and_order_sensitive(self) -> None:
        left = service_binding_key(scope="ab", source="pi", path="c", session_id="d")
        right = service_binding_key(scope="a", source="pi", path="bc", session_id="d")
        self.assertNotEqual(left, right, "拼接歧义必须被长度前缀挡住")

    def test_issue_rejects_programming_side_inputs(self) -> None:
        ledger = ReferenceLedger()
        base: dict[str, Any] = {
            "service_key": "k",
            "path": "p",
            "scope": "s",
            "source": "pi",
            "session_id": "sid",
            "project": None,
            "ordinal": 0,
            "stream_label": None,
            "volume": 1,
            "file_id": 1,
            "size_bytes": 1,
            "content_sha256": "e" * 64,
        }
        for field, bad in (
            ("line_no", 0),
            ("line_no", -1),
            ("line_no", True),
            ("volume", -1),
            ("content_sha256", "zz" * 32),
            ("session_id", ""),
            ("stream_label", 3),
        ):
            with self.subTest(field=field, bad=bad):
                payload = dict(base)
                payload["line_no"] = 1
                payload[field] = bad
                with self.assertRaises(ValueError):
                    ledger.issue(**payload)
        with self.assertRaises(ValueError):
            ReferenceLedger(capacity=MAX_ACTIVE_REFERENCES + 1)
        with self.assertRaises(ValueError):
            ReferenceLedger(ttl_seconds=0.0)


class TestContextWindow(_Fixture):
    """引用驱动的有限窗口：两侧独立、条数封顶、定位符只发放不寻址。"""

    def test_window_is_bounded_on_both_sides_in_stream_order(self) -> None:
        token = self._token(4)
        outcome = self.context.read(
            scope=SCOPE, source="pi", session_id=SESSION_ID, location=token, before=2, after=1
        ).as_public_dict()
        self.assertTrue(outcome["complete"])
        self.assertEqual(outcome["status"], "searched")
        self.assertEqual(outcome["window_size"], 4)
        self.assertEqual(outcome["returned_count"], 4)
        # 窗口行按行流顺序交出，不外出行号/序号/相对距离：客户端只能靠内容顺序定位。
        self.assertEqual(
            [row["snippet"] for row in outcome["results"]],
            ["needle 2 body", "needle 3 body", "needle 4 body", "needle 5 body"],
        )
        for row in outcome["results"]:
            self.assertNotIn("line_no", row)
            self.assertNotIn("ordinal", row)
            self.assertNotIn("distance", row)
        self.assertEqual(outcome["version_confirmed"], True)
        # 窗口内每条记录都拿到**新发放**的引用，可继续相邻扩读。
        for row in outcome["results"]:
            self.assertTrue(row["location"].startswith("ctxref:"))
        self.assertNotEqual(outcome["results"][0]["location"], token)

    def test_asymmetric_zero_sides(self) -> None:
        token = self._token(0)
        forward = self.context.read(location=token, before=0, after=3).as_public_dict()
        self.assertEqual(
            [row["snippet"] for row in forward["results"]],
            ["needle 0 body", "needle 1 body", "needle 2 body", "needle 3 body"],
        )
        backward = self.context.read(location=token, before=3, after=0).as_public_dict()
        self.assertEqual(
            [row["snippet"] for row in backward["results"]], ["needle 0 body"]
        )

    def test_window_caps_at_max_records(self) -> None:
        token = self._token(4)
        outcome = self.context.read(location=token, before=10, after=10).as_public_dict()
        self.assertLessEqual(outcome["returned_count"], MAX_WINDOW_RECORDS)
        self.assertEqual(outcome["returned_count"], 9, "本夹具只有 9 条记录，全部可交")

    def test_out_of_range_sides_are_rejected_before_any_read(self) -> None:
        token = self._token(0)
        bad_sides: list[tuple[str, Any]] = [
            ("before", 11),
            ("after", -1),
            ("before", "2"),
            ("after", True),
        ]
        for field, bad in bad_sides:
            with self.subTest(field=field, bad=bad):
                outcome = self.context.read(location=token, **{field: bad}).as_public_dict()
                self.assertEqual(
                    outcome["failure_category"],
                    ContextFailureCategory.INVALID_ARGUMENT.value,
                )
                self.assertEqual(outcome["returned_count"], 0)
                self.assertEqual(outcome["coverage_scope"], "none")

    def test_no_body_or_identity_leaks_in_published_output(self) -> None:
        token = self._token(3)
        payload = json.dumps(
            self.context.read(location=token, before=2, after=2).as_public_dict()
        )
        for forbidden in ("volume", "file_id", "sha", "content_sha256", str(self.root), "jsonl:"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, payload)


class TestContextRefusals(_Fixture):
    """四类拒绝都必须是零正文，且类别精确不混报。"""

    def test_unknown_token_is_expired_not_not_found(self) -> None:
        outcome = self.context.read(location="ctxref:" + "z" * 40).as_public_dict()
        self.assertEqual(
            outcome["failure_category"], ContextFailureCategory.REF_EXPIRED.value
        )
        self.assertEqual(outcome["results"], [])
        self.assertEqual(outcome["coverage_scope"], "none")
        self.assertTrue(outcome["partial"])

    def test_forged_jsonl_reference_is_invalid_argument(self) -> None:
        outcome = self.context.read(location="jsonl:unknown-stream#L3").as_public_dict()
        self.assertEqual(
            outcome["failure_category"], ContextFailureCategory.INVALID_ARGUMENT.value
        )
        self.assertEqual(outcome["results"], [])

    def test_binding_mismatch_per_declared_axis(self) -> None:
        token = self._token(2)
        cases: list[tuple[dict[str, Any], str]] = [
            ({"scope": "other-scope"}, "scope_mismatch"),
            ({"source": "hermes"}, "source_mismatch"),
            ({"session_id": "other-session"}, "session_decl_mismatch"),
            ({"project": "other-project"}, "project_binding"),
        ]
        for kwargs, code in cases:
            with self.subTest(**kwargs):
                outcome = self.context.read(location=token, **kwargs).as_public_dict()
                self.assertEqual(
                    outcome["failure_category"],
                    ContextFailureCategory.BINDING_MISMATCH.value,
                )
                self.assertIn(code, outcome["filter_errors"])
                self.assertEqual(outcome["results"], [])

    def test_context_service_from_another_binding_is_refused(self) -> None:
        """换一个绑定服务实例（同文件同会话也算）：服务指纹失配即整批拒。"""
        token = self._token(1)
        other = PiFileContextService(
            policy=self.policy,
            scope=SCOPE,
            path=str(self.path),
            session_id=SESSION_ID,
            ledger=ReferenceLedger(capacity=8),  # 另一本账：引用必然缺失
        )
        outcome = other.read(location=token).as_public_dict()
        self.assertEqual(
            outcome["failure_category"], ContextFailureCategory.REF_EXPIRED.value
        )
        self.assertEqual(outcome["results"], [])

    def test_same_size_rewrite_is_file_replaced(self) -> None:
        """同体积改写：摘要轴单独就能识破，不靠体积、不靠按路径 stat 冒充句柄证据。"""
        token = self._token(5)
        original = self.path.read_bytes()
        rewritten = original.replace(b"needle 5", b"NEEDLE 5")
        self.assertEqual(len(rewritten), len(original), "必须是同大小改写")
        self.path.write_bytes(rewritten)
        outcome = self.context.read(location=token).as_public_dict()
        self.assertEqual(
            outcome["failure_category"], ContextFailureCategory.FILE_REPLACED.value
        )
        self.assertFalse(outcome["version_confirmed"])
        self.assertEqual(outcome["results"], [])
        self.assertEqual(outcome["reason"], ContextFailureCategory.FILE_REPLACED.value)

    def test_appending_file_is_also_file_replaced(self) -> None:
        token = self._token(0)
        _write(
            self.path,
            _rows(9, self.repo)
            + [
                {
                    "type": "message",
                    "message": {
                        "role": "user",
                        "timestamp": "2026-03-01T11:00:00Z",
                        "content": [{"type": "input_text", "text": "appended needle"}],
                    },
                }
            ],
        )
        outcome = self.context.read(location=token).as_public_dict()
        self.assertEqual(
            outcome["failure_category"], ContextFailureCategory.FILE_REPLACED.value
        )

    def test_incomplete_file_publishes_zero_context(self) -> None:
        """未过完整核对的文件不发引用，也就不可能有可核对的上下文。"""
        _write(self.path, _rows(3, self.repo, session_id="C:/Users/BOB/private/id"))
        result = self.search.search(scope=SCOPE, query="needle", sources=["pi"])
        for row in result["results"]:
            self.assertFalse(row["location"].startswith("ctxref:"), "标识形态不合不发放引用")
        self.assertTrue(result["partial"])


class TestServerBinding(unittest.TestCase):
    """协议层绑定门：两把服务必须共用同一账本，否则发放与核对落在两本账上。"""

    def tearDown(self) -> None:
        reset_bound_services()

    def test_mismatched_ledgers_are_rejected_at_bind_time(self) -> None:
        policy = SessionPolicy(
            scopes=(
                ScopeGrant(
                    scope_id=SCOPE,
                    projects=(ProjectGrant(PROJECT, (CwdRootGrant("D:/synthetic/repo"),)),),
                    store_roots=(StoreRootGrant("pi", "D:/synthetic/store"),),
                ),
            )
        )
        search = PiFileSearchService(
            policy=policy, scope=SCOPE, path="D:/synthetic/store/s.jsonl",
            session_id=SESSION_ID, ledger=ReferenceLedger(),
        )
        context = PiFileContextService(
            policy=policy, scope=SCOPE, path="D:/synthetic/store/s.jsonl",
            session_id=SESSION_ID, ledger=ReferenceLedger(),
        )
        bind_pi_file_search_service(search)
        with self.assertRaises(ValueError):
            bind_pi_file_context_service(context)
        # 同一本账即放行。
        shared = PiFileContextService(
            policy=policy, scope=SCOPE, path="D:/synthetic/store/s.jsonl",
            session_id=SESSION_ID, ledger=search.ledger,
        )
        bind_pi_file_context_service(shared)

    def test_unbound_context_tool_reports_unbound_not_unimplemented(self) -> None:
        import asyncio

        from cross_agent_session_mcp import server

        reset_bound_services()
        with self.assertRaises(Exception) as caught:
            asyncio.run(
                server.read_session_context(
                    source="pi",
                    session_id=SESSION_ID,
                    location="ctxref:" + "a" * 40,
                    scope=SCOPE,
                )
            )
        text = str(caught.exception)
        self.assertIn("未绑定", text)
        self.assertNotIn("未实现", text, "已实现但未绑定的工具不得自称未实现")


class TestServerMultiFileBinding(unittest.TestCase):
    """聚合服务绑定门：账本共用的同旧口径，新增「两侧同形」与类型门、绑定后的 list_sources 口径。

    本类只跑进程内 handler（不起子进程），绑定对象用合成路径：验证的是绑定门的判定，
    不是读取能力（读取能力已由 `tests/test_stdio_bound.py` 的真实 stdio 用例覆盖）。
    """

    def tearDown(self) -> None:
        reset_bound_services()

    @staticmethod
    def _policy() -> SessionPolicy:
        return SessionPolicy(
            scopes=(
                ScopeGrant(
                    scope_id=SCOPE,
                    projects=(ProjectGrant(PROJECT, (CwdRootGrant("D:/synthetic/repo"),)),),
                    store_roots=(StoreRootGrant("pi", "D:/synthetic/store"),),
                ),
            )
        )

    def _pair(self, *, ledger: ReferenceLedger | None = None):
        refs = (
            SessionFileRef(path="D:/synthetic/store/s1.jsonl", session_id="s1"),
            SessionFileRef(path="D:/synthetic/store/s2.jsonl", session_id="s2"),
        )
        policy = self._policy()
        search = PiMultiFileSearchService(policy, SCOPE, refs, ledger=ledger)
        context = PiMultiFileContextService(policy, SCOPE, refs, ledger=ledger)
        return search, context

    def test_multi_file_slots_reject_wrong_types(self) -> None:
        policy = self._policy()
        single = PiFileSearchService(
            policy=policy,
            scope=SCOPE,
            path="D:/synthetic/store/s.jsonl",
            session_id=SESSION_ID,
        )
        with self.assertRaises(TypeError):
            bind_pi_multi_file_search_service(single)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            bind_pi_multi_file_context_service(single)  # type: ignore[arg-type]
        # 通用入口仍允许 None（解绑）与两种已实现类型。
        bind_pi_file_search_service(None)
        bind_pi_file_search_service(single)
        with self.assertRaises(TypeError):
            bind_pi_file_search_service("not-a-service")  # type: ignore[arg-type]

    def test_shape_mismatch_is_rejected_at_bind_time(self) -> None:
        """聚合与单文件混搭：不论哪侧后绑都在绑时被拒，且失败的绑定不改槽位（全有或全无）。"""
        ledger = ReferenceLedger()
        search, context = self._pair(ledger=ledger)
        policy = self._policy()
        single_context = PiFileContextService(
            policy=policy,
            scope=SCOPE,
            path="D:/synthetic/store/s1.jsonl",
            session_id="s1",
            ledger=ledger,
        )
        single_search = PiFileSearchService(
            policy=policy,
            scope=SCOPE,
            path="D:/synthetic/store/s1.jsonl",
            session_id="s1",
            ledger=ledger,
        )
        # 先绑聚合查询，再绑单文件上下文：后绑侧拒。
        bind_pi_multi_file_search_service(search)
        with self.assertRaises(ValueError):
            bind_pi_file_context_service(single_context)
        self.assertIsNone(server._context_service)
        # 换成聚合上下文则成（同形同账本）。
        bind_pi_multi_file_context_service(context)
        # 反向：已绑聚合上下文后，把查询槽换成单文件也拒（旧对称门）。
        with self.assertRaises(ValueError):
            bind_pi_file_search_service(single_search)
        self.assertIs(server._search_service, search)
        # 失败的绑定不影响兼容配置：聚合查询仍可重绑。
        bind_pi_multi_file_search_service(search)

    def test_multi_file_ledger_mismatch_is_rejected_at_bind_time(self) -> None:
        search, _ = self._pair(ledger=ReferenceLedger())
        _, context = self._pair(ledger=ReferenceLedger())
        bind_pi_multi_file_search_service(search)
        with self.assertRaises(ValueError):
            bind_pi_multi_file_context_service(context)
        self.assertIsNone(server._context_service)
        # 反向：同形同账本可用后，把查询槽换成另一本账上的服务也拒。
        reset_bound_services()
        shared_search, shared_context = self._pair(ledger=context.ledger)
        bind_pi_multi_file_search_service(shared_search)
        bind_pi_multi_file_context_service(shared_context)
        with self.assertRaises(ValueError):
            bind_pi_multi_file_search_service(search)
        self.assertIs(server._search_service, shared_search)

    def test_list_sources_reports_unbound_pi_as_unavailable(self) -> None:
        import asyncio

        from cross_agent_session_mcp import server

        reset_bound_services()
        payload = asyncio.run(server.list_sources())
        # P1-8：七族注册表非空 ⇒ 顶层恒报 partial；未绑定只体现为逐源字段。
        self.assertEqual(payload["implementation_status"], "partial")
        rows = {row["source"]: row for row in payload["sources"]}
        self.assertEqual(rows["pi"]["status"], "unavailable", "未绑定不得报 ready")
        self.assertIs(rows["pi"]["enabled"], False)
        self.assertIsNone(rows["pi"]["project_config"])
        self.assertIn("不代表 pi 未安装或未启用", rows["pi"]["reason"])
        # 固定文案与字段一致：未绑定时 enabled 就是 false，reason 不得称其为 null。
        self.assertIn("enabled 为 false", rows["pi"]["reason"])
        self.assertNotIn("enabled 与", rows["pi"]["reason"])
        # hermes 与本仓同形：适配器已编写，未绑定时报 unavailable（已实现但未注入），
        # 不得与四个「未编写适配器」的来源一起归入 unsupported。
        self.assertEqual(rows["hermes"]["status"], "unavailable")
        self.assertIs(rows["hermes"]["enabled"], False)
        self.assertIsNone(rows["hermes"]["project_config"])
        # 其余四个来源同样已编写（dsh/workbuddy/cursor/codex 适配器在本构建内）：
        # P1-7/P1-8 统一口径后未绑定一律 unavailable + enabled False + project_config null，
        # 不再区分「适配器未编写」的 unsupported 分支。
        for name in ("dsh", "workbuddy", "cursor_agent_cli", "codex"):
            self.assertEqual(rows[name]["status"], "unavailable", name)
            self.assertIs(rows[name]["enabled"], False, name)
            self.assertIsNone(rows[name]["project_config"], name)

    def test_list_sources_bound_ready_still_denies_full_scan(self) -> None:
        import asyncio

        from cross_agent_session_mcp import server

        search, context = self._pair(ledger=ReferenceLedger())
        bind_pi_multi_file_search_service(search)
        bind_pi_multi_file_context_service(context)
        payload = asyncio.run(server.list_sources())
        self.assertEqual(payload["implementation_status"], "partial")
        rows = {row["source"]: row for row in payload["sources"]}
        self.assertEqual(rows["pi"]["status"], "ready")
        self.assertIs(rows["pi"]["enabled"], True)
        self.assertIs(payload["config_checked"], False)
        self.assertIs(payload["verified"], False)
        self.assertIn("不表示整个 pi 来源已扫完", rows["pi"]["reason"])
        dump = json.dumps(payload)
        self.assertNotIn("D:/synthetic", dump, "状态面不得外出绑定里的路径")
        # 只绑查询服务（检索能力已注入）仍报 ready；只绑上下文服务不算 ready：
        # 本工具报告的是检索能力，只以查询服务为准。
        reset_bound_services()
        bind_pi_file_search_service(search)
        rows = {row["source"]: row for row in asyncio.run(server.list_sources())["sources"]}
        self.assertEqual(rows["pi"]["status"], "ready")
        reset_bound_services()
        bind_pi_file_context_service(context)
        rows = {row["source"]: row for row in asyncio.run(server.list_sources())["sources"]}
        self.assertEqual(rows["pi"]["status"], "unavailable", "上下文单独绑定不得谎报检索能力")
        self.assertIs(rows["pi"]["enabled"], False)


if __name__ == "__main__":
    unittest.main()
