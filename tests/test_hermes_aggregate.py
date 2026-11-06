"""TC-MCP-09/10 合成侧：Hermes 有界库集合聚合检索与 ctxref 引用回读闭环（进程内）。

对应 SRS-SEARCH-01..11、DES-ADAPTER-01/DES-SEC-01（05 §6.4）与 06「已绑定 stdio 闭环」的
Hermes 半边。本文件只覆盖**进程内宿主注入**：合成库与合成项目根全部由临时目录提供，
不读取真实会话、真实数据库、用户配置，也不联网。stdio 那一段在
`tests/test_stdio_bound.py` 的 `HermesBoundHostTests` 里走真实协议面。

断言口径跟着 05 的确认约束走：

- 存储授权与项目归属分离：库根只决定「可读」，项目名只来自归属轴授权；
- 完整性/版本核验：同趟句柄指纹（卷号/文件标识/体积/一趟 SHA-256）不一致即不完整；
- 输出遮蔽：遮蔽结论进内部计数与覆盖注记，不外发命中数、不外发原文；
- 资源上限：指纹字节预算、候选条数、每库片段条数与总字符数，越界整批不发布；
- 整批拒绝不发布前缀：任一片段被拒 => 本次零结果，已发令牌回收；
- ctxref 不编码路径/坐标/版本：对外行只有 `ctxref:<opaque>`，令牌里找不到路径与行号；
- 失败覆盖不得伪报完整：任一库被拒/跳过/裁尾 => 整体 `complete=false`。
"""

from __future__ import annotations

import contextlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hermes_synthetic import add_message, add_session, create_store

from cross_agent_session_mcp import hermes_aggregate as HA
from cross_agent_session_mcp import hermes_aggregate_context as HC
from cross_agent_session_mcp import server
from cross_agent_session_mcp.file_search import PiFileSearchService
from cross_agent_session_mcp.hermes_aggregate import (
    COVERAGE_SCOPE_MULTI_HERMES,
    HermesAggregateSearchService,
    HermesStoreRef,
)
from cross_agent_session_mcp.hermes_aggregate_context import (
    HermesAggregateContextService,
)
from cross_agent_session_mcp.policy import (
    CwdRootGrant,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.publication import (
    MAX_SNIPPETS_PER_FILE,
    SnippetCollector,
)
from cross_agent_session_mcp.query import MAX_SESSION_ID_CHARS
from cross_agent_session_mcp.references import (
    REFERENCE_PREFIX,
    ReferenceLedger,
    parse_reference_token,
    service_binding_key,
)
from cross_agent_session_mcp.safe_reader import FileVersion
from cross_agent_session_mcp.session_context import MAX_WINDOW_RECORDS

SCOPE = "synthetic-scope"
PROJECT = "synthetic-project"
OTHER_PROJECT = "synthetic-project-b"
STORE_A = "session-a"
STORE_B = "session-b"


def _policy_for(db: Path, repo: Path, *, second: Path | None = None) -> SessionPolicy:
    """一 scope、两归属项目（可选第二根）、一 Hermes 库根：SQLite 根必须逐根显式配置。"""
    projects = [ProjectGrant(PROJECT, (CwdRootGrant(str(repo)),))]
    if second is not None:
        projects.append(ProjectGrant(OTHER_PROJECT, (CwdRootGrant(str(second)),)))
    return SessionPolicy(
        scopes=(
            ScopeGrant(
                scope_id=SCOPE,
                projects=tuple(projects),
                store_roots=(StoreRootGrant("hermes", str(db)),),
            ),
        )
    )


class _Fixture(unittest.TestCase):
    """每测试一个 temp 目录；写连接先关再删（Windows 上未关连接会卡住删除）。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="xagent-hermes-agg-"))
        self._writers: list[sqlite3.Connection] = []
        self.addCleanup(self._cleanup)
        self.addCleanup(server.reset_bound_services)

    def _cleanup(self) -> None:
        for conn in self._writers:
            with contextlib.suppress(sqlite3.Error):
                conn.close()
        self._writers.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def writer(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        self._writers.append(conn)
        return conn

    def store(
        self,
        *,
        name: str = "state.db",
        session_id: str = STORE_A,
        rows: int = 3,
        cwd: str | None = "USE_REPO",
        repo: Path | None = None,
        **store_kwargs: Any,
    ) -> tuple[Path, Path, sqlite3.Connection]:
        """一个合成会话：`rows` 条交替 user/assistant 正文，归属指向 `repo`。"""
        repo = self.tmp / "repo" if repo is None else repo
        repo.mkdir(parents=True, exist_ok=True)
        db = self.tmp / name
        conn = self.writer(create_store(db, **store_kwargs))
        add_session(
            conn,
            session_id,
            cwd=(str(repo) if cwd == "USE_REPO" else cwd),
            git_repo_root=(str(repo) if cwd == "USE_REPO" else cwd),
        )
        for index in range(rows):
            add_message(
                conn,
                session_id,
                "user" if index % 2 == 0 else "assistant",
                f"synthetic message {index} needle-alpha body",
            )
        return db, repo, conn

    def add_session_rows(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        *,
        repo: Path,
        rows: int = 3,
        word: str = "needle-alpha",
    ) -> None:
        add_session(
            conn, session_id, cwd=str(repo), git_repo_root=str(repo)
        )
        for index in range(rows):
            add_message(
                conn,
                session_id,
                "user" if index % 2 == 0 else "assistant",
                f"synthetic message {index} {word} body",
            )

    def services(
        self,
        policy: SessionPolicy,
        stores: tuple[HermesStoreRef, ...],
        *,
        ledger: ReferenceLedger | None = None,
    ) -> tuple[HermesAggregateSearchService, HermesAggregateContextService, ReferenceLedger]:
        """配对构造：上下文服务由发放方交出，两侧共用同一本引用账。"""
        book = ledger if ledger is not None else ReferenceLedger()
        search = HermesAggregateSearchService(
            policy=policy, scope=SCOPE, stores=stores, ledger=book
        )
        return search, search.context_service(), book

    def search_one(
        self,
        db: Path,
        repo: Path,
        *,
        session_id: str = STORE_A,
        query: str | None = "needle-alpha",
        project: str | None = PROJECT,
        limit: int = 20,
        sources: tuple[str, ...] | None = None,
        ledger: ReferenceLedger | None = None,
    ) -> tuple[dict[str, Any], ReferenceLedger]:
        policy = _policy_for(db, repo)
        search, _context, book = self.services(
            policy, (HermesStoreRef(str(db), session_id),), ledger=ledger
        )
        kwargs: dict[str, Any] = {
            "query": query,
            "project": project,
            "limit": limit,
            "sources": ("hermes",) if sources is None else sources,
        }
        return search.search(**kwargs), book


class ShapeTests(_Fixture):
    """绑定形态门：越界一律抛，不静默截断（05 §6.4 资源上限）。"""

    def test_store_ref_rejects_unusable_identity(self) -> None:
        # 判形在构造当场生效：路径形态不合一律 ValueError。契约（06 TC-MCP-12）只要求
        # 「非空 str」：不 strip，纯空白路径是合法构造入参（待授权写法），其可读性由策略层
        # authorize_store 当场判定；05 §标识形白名单门只管 session_id 等结果字段，不管 store_path。
        for bad in ("", Path("x.db"), 1):
            with self.subTest(store_path=bad), self.assertRaises(ValueError):
                HermesStoreRef(bad, "sA")  # type: ignore[arg-type]
        for bad in ("", "a" * (MAX_SESSION_ID_CHARS + 1), "带空格 id", None):
            with self.subTest(session_id=bad), self.assertRaises(ValueError):
                HermesStoreRef("D:/synthetic/state.db", bad)  # type: ignore[arg-type]

    def test_binding_requires_policy_scope_and_non_empty_store_sequence(self) -> None:
        policy = _policy_for(Path("D:/synthetic/state.db"), Path("D:/synthetic/repo"))
        with self.assertRaises(TypeError):
            HermesAggregateSearchService(
                policy="nope",  # type: ignore[arg-type]
                scope=SCOPE,
                stores=(HermesStoreRef("D:/synthetic/state.db", "sA"),),
            )
        for bad_scope in ("", "  ", None):
            with self.subTest(scope=bad_scope), self.assertRaises(ValueError):
                HermesAggregateSearchService(
                    policy=policy, scope=bad_scope, stores=()  # type: ignore[arg-type]
                )
        with self.assertRaises(TypeError):
            HermesAggregateSearchService(
                policy=policy,
                scope=SCOPE,
                stores="D:/synthetic/state.db",  # type: ignore[arg-type]
            )

    def test_binding_rejects_over_bound_store_set(self) -> None:
        policy = _policy_for(Path("D:/synthetic/state.db"), Path("D:/synthetic/repo"))
        stores = tuple(
            HermesStoreRef(f"D:/synthetic/s{index}.db", "sA")
            for index in range(HA.MAX_STORES_PER_QUERY + 1)
        )
        with self.assertRaises(ValueError):
            HermesAggregateSearchService(policy=policy, scope=SCOPE, stores=stores)

    def test_binding_key_rejects_out_of_range_index(self) -> None:
        ref = HermesStoreRef("D:/synthetic/state.db", "sA")
        policy = _policy_for(Path("D:/synthetic/state.db"), Path("D:/synthetic/repo"))
        search = HermesAggregateSearchService(
            policy=policy, scope=SCOPE, stores=(ref,)
        )
        self.assertEqual(search.binding_key(0), HA._hermes_service_key(scope=SCOPE, ref=ref))
        for bad in (-1, 1, True, "0", None):
            with self.subTest(index=bad), self.assertRaises(ValueError):
                search.binding_key(bad)  # type: ignore[arg-type]

    def test_pairing_requires_one_ledger_one_scope_one_ordered_store_set(self) -> None:
        db = self.tmp / "state.db"
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        policy = _policy_for(db, repo)
        ref = HermesStoreRef(str(db), STORE_A)
        first = ReferenceLedger()
        search = HermesAggregateSearchService(
            policy=policy, scope=SCOPE, stores=(ref,), ledger=first
        )
        # 配对核对只在两侧都在场时生效：先绑发放方，再拿错配的核对方过绑定入口。
        server.bind_hermes_aggregate_search_service(search)
        with self.assertRaises(ValueError):
            server.bind_hermes_aggregate_context_service(
                HermesAggregateContextService(
                    policy=policy,
                    scope=SCOPE,
                    stores=(ref,),
                    ledger=ReferenceLedger(),
                    binding_key=search.binding_key,
                )
            )
        server.reset_bound_services()
        server.bind_hermes_aggregate_search_service(search)
        with self.assertRaises(ValueError):
            server.bind_hermes_aggregate_context_service(
                HermesAggregateContextService(
                    policy=policy,
                    scope="other-scope",
                    stores=(ref,),
                    ledger=first,
                    binding_key=search.binding_key,
                )
            )
        server.reset_bound_services()
        server.bind_hermes_aggregate_search_service(search)
        with self.assertRaises(ValueError):
            server.bind_hermes_aggregate_context_service(
                HermesAggregateContextService(
                    policy=policy,
                    scope=SCOPE,
                    stores=(ref, HermesStoreRef(str(db), STORE_B)),
                    ledger=first,
                    binding_key=search.binding_key,
                )
            )
        server.reset_bound_services()
        # 同族识别：发放与核对都落在 hermes-aggregate 一族。
        paired = search.context_service()
        server.bind_hermes_aggregate_search_service(search)
        server.bind_hermes_aggregate_context_service(paired)
        # 值比较不用 assertIs：字符串不保证驻留，同族判定看值不看对象身份。
        self.assertEqual(server._family(search), "hermes-aggregate")
        self.assertEqual(server._family(paired), "hermes-aggregate")

    def test_reset_leaves_production_unbound(self) -> None:
        server.reset_bound_services()
        self.assertIsNone(server._search_service)
        self.assertIsNone(server._context_service)


class AggregateClosureTests(_Fixture):
    """闭环正向：聚合检索发令牌，上下文按令牌回读同一记录。"""

    def test_search_publishes_ctxref_rows_with_bounded_coverage(self) -> None:
        db, repo, _conn = self.store(rows=3)
        out, book = self.search_one(db, repo)
        self.assertFalse(out["rejected"])
        self.assertTrue(out["complete"], out["reason"])
        self.assertFalse(out["partial"])
        self.assertEqual(out["coverage_scope"], COVERAGE_SCOPE_MULTI_HERMES)
        self.assertEqual(out["stage_reached"], "published")
        self.assertIsNone(out["failure_category"])
        self.assertGreater(out["total_matched"], 0)
        self.assertEqual(out["returned_count"], len(out["results"]))
        # 覆盖行报的是过滤层实际匹配数（有界集合内），不报「整个来源扫完了」。
        row = out["coverage"][0]
        self.assertEqual(row["source"], "hermes")
        self.assertEqual(row["matched_count"], out["total_matched"])
        self.assertGreater(row["matched_count"], 0)
        self.assertEqual(row["status"], "searched")
        self.assertFalse(row["partial"])
        self.assertEqual(row["filter_errors"], [])
        # 库诊断行只给状态与计数，不给路径与会话。
        self.assertEqual(len(out["stores"]), 1)
        store_row = out["stores"][0]
        self.assertEqual(store_row["index"], 0)
        self.assertEqual(store_row["status"], "read")
        self.assertEqual(store_row["records_captured"], 3)
        store_blob = repr(out["stores"]).lower()
        for token in (str(db).lower(), STORE_A, PROJECT, "state.db"):
            self.assertNotIn(token, store_blob, "逐库诊断行不得外出路径/会话/项目")
        # 对外行允许携带会话与项目（它们经公钥判形）；路径仍一律不出。
        blob = repr(out).lower()
        for token in (str(db).lower(), "state.db"):
            self.assertNotIn(token, blob)
        # 每条结果的位置都是新发的不透明令牌，且已进同一本账。
        self.assertEqual(len(out["results"]), out["returned_count"])
        for item in out["results"]:
            self.assertEqual(item["source"], "hermes")
            self.assertTrue(item["location"].startswith(f"{REFERENCE_PREFIX}:"))
            self.assertIsNotNone(parse_reference_token(item["location"]))
            record = book.lookup(item["location"])
            self.assertIsNotNone(record, "显式账本里必有刚发放的令牌")
            assert record is not None
            self.assertEqual(record.session_id, STORE_A)
        self.assertEqual(book.__len__(), out["returned_count"])

    def test_ctxref_round_trip_returns_window_without_coordinates(self) -> None:
        db, repo, _conn = self.store(rows=5)
        out, book = self.search_one(db, repo)
        location = out["results"][0]["location"]
        policy = _policy_for(db, repo)
        search, context, _book = self.services(
            policy, (HermesStoreRef(str(db), STORE_A),), ledger=book
        )
        self.assertIs(context.ledger, book)
        read = context.read(location=location, session_id=STORE_A, project=PROJECT)
        pub = read.as_public_dict()
        self.assertTrue(pub["complete"], pub["reason"])
        self.assertEqual(pub["status"], "searched")
        self.assertEqual(pub["stage_reached"], "published")
        self.assertTrue(pub["version_confirmed"])
        self.assertEqual(pub["coverage_scope"], HC.COVERAGE_SCOPE_HERMES_STORE)
        self.assertGreaterEqual(pub["window_size"], 3)
        self.assertLessEqual(pub["window_size"], MAX_WINDOW_RECORDS)
        self.assertEqual(pub["returned_count"], len(pub["results"]))
        body = pub["results"][0]["snippet"]
        self.assertIn("needle-alpha", body)
        self.assertEqual(pub["results"][0]["source"], "hermes")
        # 窗口行只带 ctxref：没有 line_no / ordinal / volume / 路径。
        blob = repr(pub).lower()
        for forbidden in ("line_no", "ordinal", "volume", "file_id", str(db).lower(), "state.db"):
            self.assertNotIn(forbidden, blob)
        for item in pub["results"]:
            self.assertTrue(item["location"].startswith(f"{REFERENCE_PREFIX}:"))
            self.assertNotEqual(item["location"], location)
        # 窗口回发的是新令牌：旧令牌仍可用，二者互不替换。
        self.assertIsNotNone(book.lookup(location))
        self.assertEqual(book.__len__(), out["returned_count"] + pub["window_size"])

    def test_search_ignores_client_supplied_path_and_coordinates(self) -> None:
        db, repo, _conn = self.store(rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        with self.assertRaises(TypeError):
            search.search(path=str(db), query="needle-alpha")  # type: ignore[call-keyword]
        with self.assertRaises(TypeError):
            search.search(query="needle-alpha", line_no=3)  # type: ignore[call-keyword]

    def test_source_axis_narrows_only_hermes(self) -> None:
        db, repo, _conn = self.store(rows=2)
        out, _book = self.search_one(db, repo, sources=("pi",))
        self.assertEqual(out["failure_category"], "source_unsupported")
        self.assertEqual(out["reason"], "source_unsupported")
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertEqual(out["coverage_scope"], "none")
        self.assertEqual(out["stores"], [])
        # 点名的陌生来源各有自己的覆盖行：不把未扫写成扫过。
        self.assertEqual({row["source"] for row in out["coverage"]}, {"pi", "hermes"})
        for row in out["coverage"]:
            self.assertTrue(row["partial"])

    def test_scope_mismatch_opens_no_store(self) -> None:
        db, repo, _conn = self.store(rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        with mock.patch.object(
            HA, "run_hermes_session", side_effect=AssertionError("store opened")
        ) as run, mock.patch.object(HA, "_digest_store", side_effect=AssertionError("digest")):
            out = search.search(scope="other-scope", query="needle-alpha")
        self.assertEqual(out["failure_category"], "scope_mismatch")
        self.assertEqual(out["coverage_scope"], "none")
        self.assertEqual(out["coverage"], [])
        self.assertEqual(out["stores"], [])
        self.assertEqual(out["stage_reached"], "coordinator")
        run.assert_not_called()

    def test_filter_rejection_returns_zero_results_and_zero_stores(self) -> None:
        db, repo, _conn = self.store(rows=2)
        # 只给非法关键词（时间界省略）=> 过滤层整批评拒 filter_keyword_invalid，且不得先读库。
        # 判序（query.py `_build_filter`）先关键词后时间：入参不带非法 time，拒绝码才确定落在关键词。
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        with mock.patch.object(
            HA, "run_hermes_session", side_effect=AssertionError("store opened")
        ):
            out = search.search(query="  ")
        self.assertTrue(out["rejected"])
        self.assertEqual(out["reason"], "filter_keyword_invalid")
        self.assertEqual(out["failure_category"], "filter_keyword_invalid")
        self.assertEqual(out["results"], [])
        self.assertEqual(out["coverage"], [])
        self.assertEqual(out["stores"], [])
        self.assertEqual(out["stage_reached"], "coordinator")
        # 协议额度门在协调器层先于过滤预检：非 1-100 的整数一律 invalid_request。
        for bad_limit in (True, 0, HA.MAX_PROTOCOL_LIMIT + 1, "10"):
            with self.subTest(limit=bad_limit):
                out = search.search(query="needle-alpha", limit=bad_limit)  # type: ignore[arg-type]
                self.assertEqual(out["reason"], "invalid_request")

    def test_project_filter_out_of_attribution_is_filter_layer_only(self) -> None:
        db, repo, _conn = self.store(rows=2)
        out, _book = self.search_one(db, repo, project="unmatched-project")
        # 09 裁决 P2-2：项目收窄属过滤层语义，不参与覆盖判定。库根已批准 => 整库可读、
        # 记录按真实归属发布名入过滤层，未命中只是零结果，不得把该库降级成不可用（旧断言
        # `stores_unusable` + `incomplete` 正是「归属轴逐条拒」缺陷被固化成预期的形态）。
        self.assertEqual(out["stores"][0]["status"], "read")
        self.assertIsNone(out["stores"][0]["reason"])
        self.assertEqual(out["stores"][0]["records_captured"], 2)
        self.assertIsNone(out["failure_category"])
        self.assertIsNone(out["reason"])
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertEqual(out["total_scanned"], 2)
        self.assertEqual(out["total_matched"], 0)
        self.assertTrue(out["complete"], out["reason"])
        self.assertFalse(out["partial"])
        self.assertEqual(out["coverage_scope"], "bounded_hermes_store_set")


class CoverageHonestyTests(_Fixture):
    """失败覆盖不伪报完整：任何一库未读完，整体不得是 complete 或「无匹配」。

    口径钉死（06 TC-MCP-AGG-09「契约裁决」）：digest 预算穷尽只以逐库
    `skipped_budget` reason 呈现；存在任一可用记录时顶层 `failure_category` 为
    `null`，仅整集合零可用记录时才是 `stores_unusable`（预算穷尽码只进
    `stores[].reason`，不进顶层）。
    """

    def test_unapproved_store_is_refused_and_never_claims_no_match(self) -> None:
        db, repo, _conn = self.store(name="state.db")
        outside = self.tmp / "outside.db"
        conn = self.writer(create_store(outside))
        add_session(conn, STORE_B, cwd=str(repo), git_repo_root=str(repo))
        add_message(conn, STORE_B, "user", "synthetic message 0 needle-alpha body")
        search, _context, _book = self.services(
            _policy_for(db, repo),
            (HermesStoreRef(str(db), STORE_A), HermesStoreRef(str(outside), STORE_B)),
        )
        out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])
        self.assertEqual(out["coverage_scope"], COVERAGE_SCOPE_MULTI_HERMES)
        statuses = [row["status"] for row in out["stores"]]
        self.assertEqual(statuses, ["read", "refused"])
        row = out["coverage"]
        self.assertIn(row[0]["status"], ("searched", "incomplete"))
        self.assertNotIn("no_match", {item["status"] for item in out["coverage"]})
        # 授权外的库不会泄露它自己的计数结论：只保留可读那一库的候选。
        self.assertGreater(out["total_scanned"], 0)

    def test_missing_store_degrades_coverage_without_crashing(self) -> None:
        db, repo, _conn = self.store()
        ghost = self.tmp / "ghost.db"
        search, _context, _book = self.services(
            _policy_for(db, repo),
            (HermesStoreRef(str(db), STORE_A), HermesStoreRef(str(ghost), STORE_B)),
        )
        out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertEqual([r["status"] for r in out["stores"]], ["read", "refused"])
        self.assertIsNone(out["failure_category"])
        self.assertGreater(out["returned_count"], 0)

    def test_digest_budget_exhaustion_skips_stores_not_truncates_results(self) -> None:
        # 指纹预算只能整库跳过（skipped_budget），不得把已读到的结果裁掉冒充读完。
        db, repo, _conn = self.store(name="s1.db", session_id=STORE_A)
        refs = (
            HermesStoreRef(str(db), STORE_A),
            HermesStoreRef(str(db), STORE_A),
            HermesStoreRef(str(db), STORE_A),
        )
        search, _context, _book = self.services(_policy_for(db, repo), refs)
        # 额度小于单库最小指纹预算：逐库都是 skipped_budget，整体没有可用候选。
        # 反证档：本档集合零可用记录，顶层 stores_unusable 合法（hermes_aggregate.py:990
        # 只在 usable_records == 0 时给出该类别）；下一档（首库已发布命中）则必须为 null。
        with mock.patch.object(HA, "MAX_HERMES_AGGREGATE_DIGEST_BYTES", 15):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])
        self.assertEqual(out["failure_category"], "stores_unusable")
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertEqual(out["stage_reached"], "store_read")
        self.assertEqual(
            [row["status"] for row in out["stores"]], ["skipped_budget"] * 3
        )
        self.assertEqual(out["coverage"][0]["status"], "incomplete")
        # 双趟指纹要读两遍，并在第二趟拿到一次「返回 0 字节」的读取才确立 EOF：整库需要
        # 2*S+1 字节的额度（记账只有 2*S），所以只给一趟额度时第一库自己就判不完整。
        # 余量取 10 < _MIN_DIGEST_BUDGET=16：第一库读成并发布，后面的库整库 skipped_budget，
        # 而不是把已读到的结果裁半。
        once = 2 * db.stat().st_size + 10
        with mock.patch.object(HA, "MAX_HERMES_AGGREGATE_DIGEST_BYTES", once):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])
        # 契约（06 TC-MCP-AGG-09「契约裁决」）：预算穷尽只作逐库 skipped_budget reason；
        # 顶层 failure_category 在存在可用记录时为 null（零可用记录时才是 stores_unusable）。
        # read_budget_exhausted 只进 stores[].reason，不进顶层（顶层 reason 本档实测为 null）。
        self.assertIsNone(out["failure_category"])
        self.assertGreater(out["returned_count"], 0)
        self.assertEqual(
            [row["status"] for row in out["stores"]],
            ["read", "skipped_budget", "skipped_budget"],
        )
        self.assertEqual(out["stores"][1]["reason"], "read_budget_exhausted")

    def test_session_identity_drift_drops_whole_store(self) -> None:
        db, repo, _conn = self.store(rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), "wrong-session"),)
        )
        out = search.search(query="needle-alpha", project=PROJECT)
        self.assertEqual(out["failure_category"], "stores_unusable")
        self.assertEqual(out["stores"][0]["status"], "incomplete")
        self.assertEqual(out["stores"][0]["reason"], "session_not_found")

    def test_store_identity_conflict_is_reported_not_silently_dropped(self) -> None:
        db, repo, _conn = self.store(rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        original = HA._read_one_store

        def drift(**kwargs: Any) -> HA._StoreSegment:
            segment = original(**kwargs)
            if segment.records:
                record = segment.records[0]
                segment.records[0] = record.__class__(
                    source=record.source,
                    session_id="other-session",
                    role=record.role,
                    text=record.text,
                    timestamp=record.timestamp,
                    project=record.project,
                    location=record.location,
                )
            return segment

        with mock.patch.object(HA, "_read_one_store", side_effect=drift):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertEqual(out["stores"][0]["reason"], "session_identity_conflict")
        self.assertEqual(out["results"], [])
        # 无孤儿（06 TC-MCP-AGG-13）：被拒库的一条记录也不得进过滤层与计数。
        self.assertEqual(out["total_scanned"], 0)
        self.assertEqual(out["skipped_records"], 0)

    def _poison_segment_record(self, *, session_id: str, index: int) -> Any:
        """把 `session_id` 那一库的第 `index` 条候选换成别人的会话身份（模拟适配器漂移）。

        污染后的文本不含关键词：被污染记本身在旧法下也从不入列（循环在它这里 break），
        因此旧法一旦出现在扫描/命中，只能来自它**之前**的孤儿前缀，场景不混淆（06 TC-MCP-AGG-13）。
        """
        original = HA._read_one_store

        def drift(**kwargs: Any) -> HA._StoreSegment:
            segment = original(**kwargs)
            if getattr(kwargs.get("ref"), "session_id", None) != session_id:
                return segment
            if len(segment.records) > index:
                record = segment.records[index]
                segment.records[index] = record.__class__(
                    source=record.source,
                    session_id="other-session",
                    role=record.role,
                    text="unrelated body without keyword",
                    timestamp=record.timestamp,
                    project=record.project,
                    location=record.location,
                )
            return segment

        return mock.patch.object(HA, "_read_one_store", side_effect=drift)

    def test_identity_conflict_on_later_record_leaves_no_orphan(self) -> None:
        # 06 TC-MCP-AGG-13：冲突在 records[1] 时，前 1 条已入列的孤儿必须不存在。
        db, repo, _conn = self.store(name="s1.db", session_id=STORE_A, rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        with self._poison_segment_record(session_id=STORE_A, index=1):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertEqual(out["stores"][0]["reason"], "session_identity_conflict")
        self.assertEqual(out["stores"][0]["status"], "incomplete")
        # 旧法：冲突前的孤儿进了过滤层 => total_scanned=1，并因命中而整批塔成 match_join_failed
        # （实测：complete=False/partial=True/total_scanned=1/total_matched=1/
        #  failure_category='match_join_failed'/reason='publication_failed'）。
        self.assertEqual(out["total_scanned"], 0)
        self.assertEqual(out["total_matched"], 0)
        self.assertEqual(out["skipped_records"], 0)
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertEqual(out["failure_category"], "stores_unusable")
        self.assertNotEqual(out["failure_category"], "match_join_failed")

    def test_identity_conflict_does_not_taint_healthy_store(self) -> None:
        # 06 TC-MCP-AGG-13 姊妹断言：被污染库不得牵连健康库（旧法整批零结果）。
        db, repo, conn = self.store(name="s1.db", session_id=STORE_A, rows=2)
        self.add_session_rows(conn, STORE_B, repo=repo, rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo),
            (HermesStoreRef(str(db), STORE_A), HermesStoreRef(str(db), STORE_B)),
        )
        with self._poison_segment_record(session_id=STORE_A, index=1):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertEqual(out["stores"][0]["reason"], "session_identity_conflict")
        self.assertEqual(out["stores"][1]["status"], "read")
        self.assertGreater(out["returned_count"], 0)
        self.assertIsNone(out["failure_category"])
        self.assertNotEqual(out["reason"], "match_join_failed")
        # 06 TC-MCP-AGG-13 (d)：返回结果每条都必须归属健库，孤儿不得当成结果回流
        # （旧法双库实测 total_scanned=3 且 results 里混进 session-a，而 stores[0] 自报
        #  records_captured=0/filter_scanned=0/returned_count=0 ——自相矛盾）。
        self.assertTrue(out["results"])
        self.assertEqual({str(r["session_id"]) for r in out["results"]}, {STORE_B})
        # 旧法：孤儿进了合并缓冲 => 全查询扫描总量虚增为 3，与 stores 自报总和不一致。
        self.assertEqual(out["total_scanned"], 2)
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])

    def test_version_instability_between_passes_degrades_store(self) -> None:
        db, repo, _conn = self.store(rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        original = HA._digest_store
        calls = {"n": 0}

        def unstable(*args: Any, **kwargs: Any) -> FileVersion:
            calls["n"] += 1
            version = original(*args, **kwargs)
            if calls["n"] == 2:
                return FileVersion(
                    volume=version.volume,
                    file_id=version.file_id,
                    size_bytes=version.size_bytes + 1,
                    content_sha256=version.content_sha256,
                    complete=True,
                )
            return version

        with mock.patch.object(HA, "_digest_store", side_effect=unstable):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertEqual(out["stores"][0]["reason"], "version_unstable")
        self.assertEqual(out["results"], [])

    def test_incomplete_digest_of_large_store_marks_store_incomplete(self) -> None:
        """指纹被预算截断 = 超大库（`over_size`），不得误报成并发修改（09 裁决 P3）。

        旧预期 `version_unstable` 正是被本裁决作废的契约：半程指纹不等只是「这库超出可核对
        上限」的表现，写成「这库在变」会把运维引向错误的结论；且旧法在定性之后仍跑整库 SQL。
        """
        db, repo, _conn = self.store(rows=2)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        original = HA._digest_store

        def partial(*args: Any, **kwargs: Any) -> FileVersion:
            version = original(*args, **kwargs)
            return version.__class__(
                volume=version.volume,
                file_id=version.file_id,
                size_bytes=version.size_bytes,
                content_sha256=version.content_sha256,
                complete=False,
            )

        with mock.patch.object(HA, "_digest_store", side_effect=partial), mock.patch.object(
            HA, "run_hermes_session", wraps=HA.run_hermes_session
        ) as SQL:
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertEqual(out["stores"][0]["reason"], "over_size")
        self.assertNotEqual(out["stores"][0]["reason"], "version_unstable")
        self.assertGreater(out["stores"][0]["digest_bytes"], 0)
        # 早退在整库 SQL 之前：一趟查询也不跑（旧法在这里把 SQL 与第二趟指纹全费完）。
        self.assertEqual(SQL.call_count, 0)
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)

    def test_store_over_row_cap_is_over_size_not_version_unstable(self) -> None:
        """TC-MCP-AGG-09a（09 裁决 P3）：单库行数超 `MAX_HERMES_STORE_ROWS` 记 `over_size`。

        该库只跑一趟 SQL：行级上限检查在第二趟指纹之前，超限已定性，再读整库只浪费预算。
        默认上限（2 000 行，待真实库校准）在测试里不现实，因此按现有形状用 patch 收紧，
        不改动生产默认值。
        """
        db, repo, _conn = self.store(rows=5)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        with mock.patch.object(HA, "MAX_HERMES_STORE_ROWS", 3), mock.patch.object(
            HA, "run_hermes_session", wraps=HA.run_hermes_session
        ) as SQL:
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertEqual(out["stores"][0]["reason"], "over_size")
        self.assertNotEqual(out["stores"][0]["reason"], "version_unstable")
        self.assertEqual(out["stores"][0]["status"], "incomplete")
        # 整库 SQL 只跑一趟：超限检查落在第二趟指纹之前。
        self.assertEqual(SQL.call_count, 1)
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])
        # 零可用记录：顶层按 stores_unusable 收，不把「没读到」写成「没有匹配」。
        self.assertEqual(out["failure_category"], "stores_unusable")

    def test_store_within_row_cap_still_reads(self) -> None:
        """行级上限不得误伤正常库：同库只放宽阈值边界即可读成 `read`。"""
        db, repo, _conn = self.store(rows=5)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        with mock.patch.object(HA, "MAX_HERMES_STORE_ROWS", 5):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertEqual(out["stores"][0]["status"], "read")
        self.assertNotEqual(out["stores"][0]["reason"], "over_size")
        self.assertTrue(out["complete"], out["reason"])
        self.assertGreater(out["returned_count"], 0)

    def test_internal_failure_releases_tokens_and_keeps_zero_results(self) -> None:
        db, repo, _conn = self.store(rows=2)
        book = ReferenceLedger()
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),), ledger=book
        )
        with mock.patch.object(
            HA, "_issue_hermes_references", side_effect=RuntimeError("boom")
        ):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertFalse(out["complete"])
        self.assertEqual(out["failure_category"], "internal_failure")
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertGreater(out["records_withheld"], 0)
        self.assertGreater(out["skipped_records"], 0)
        self.assertEqual(out["coverage"][0]["status"], "searched")
        # 失败覆盖不伪报「无匹配」：状态来自过滤层，并带 internal_failure 标签。
        self.assertIn("internal_failure", out["coverage"][0]["filter_errors"])
        self.assertEqual(book.__len__(), 0)


class WholeBatchRejectionTests(_Fixture):
    """整批拒绝不发布前缀：任一片段不可发布 => 本次零结果且已发令牌回收。"""

    def _search_with_tiny_output_cap(self, db: Path, repo: Path, cap: int) -> dict[str, Any]:
        search, _context, book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),), ledger=ReferenceLedger()
        )
        with mock.patch.object(HA, "MAX_SNIPPET_TOTAL_CHARS", cap), mock.patch.object(
            HA, "SnippetCollector", wraps=SnippetCollector
        ) as wrapped:
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertTrue(wrapped.called)
        self.assertEqual(book.__len__(), 0)
        return out

    def test_total_chars_over_budget_drops_entire_batch(self) -> None:
        db, repo, _conn = self.store(rows=4)
        out = self._search_with_tiny_output_cap(db, repo, 12)
        self.assertFalse(out["complete"])
        self.assertEqual(out["reason"], "publication_failed")
        self.assertEqual(out["failure_category"], "snippet_total_chars_limit")
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertEqual(out["stage_reached"], "publication")
        self.assertGreater(out["total_matched"], 0)
        # 诊断量保留（records_withheld/total_matched），但对外零发布：没有前缀存活。
        self.assertGreater(out["records_withheld"], 0)

    def test_redaction_rejection_drops_entire_batch(self) -> None:
        db, repo, _conn = self.store(rows=3)
        search, _context, book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),), ledger=ReferenceLedger()
        )
        with mock.patch(
            "cross_agent_session_mcp.publication.redact_text",
            side_effect=lambda text: _UnusableRedaction(),
        ):
            out = search.search(query="needle-alpha", project=PROJECT)
        self.assertEqual(out["failure_category"], "redaction_rejected")
        self.assertEqual(out["results"], [])
        self.assertEqual(out["returned_count"], 0)
        self.assertGreater(out["total_matched"], 0)
        self.assertGreater(out["records_withheld"], 0)
        self.assertEqual(book.__len__(), 0)
        self.assertEqual(out["coverage"][0]["status"], "error")

    def test_per_store_cap_over_flow_marks_partial_not_complete(self) -> None:
        # 单库候选超过每库片段额度：结果裁到额度并标 partial，不静默丢尾。
        db, repo, conn = self.store(name="s1.db", session_id=STORE_A, rows=MAX_SNIPPETS_PER_FILE + 4)
        search, _context, _book = self.services(
            _policy_for(db, repo), (HermesStoreRef(str(db), STORE_A),)
        )
        out = search.search(query="needle-alpha", project=PROJECT, limit=HA.MAX_HERMES_AGGREGATE_SNIPPETS)
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])
        self.assertLessEqual(out["returned_count"], MAX_SNIPPETS_PER_FILE)
        self.assertGreater(out["total_matched"], out["returned_count"])
        self.assertEqual(out["coverage"][0]["status"], "searched")
        self.assertTrue(out["truncated"])

    def test_multi_store_cap_cut_reports_partial(self) -> None:
        db, repo, conn = self.store(name="s1.db", session_id=STORE_A, rows=MAX_SNIPPETS_PER_FILE + 2)
        self.add_session_rows(conn, STORE_B, repo=repo, rows=MAX_SNIPPETS_PER_FILE + 2)
        search, _context, _book = self.services(
            _policy_for(db, repo),
            (HermesStoreRef(str(db), STORE_A), HermesStoreRef(str(db), STORE_B)),
        )
        out = search.search(
            query="needle-alpha", project=PROJECT, limit=HA.MAX_HERMES_AGGREGATE_SNIPPETS
        )
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])
        self.assertLessEqual(out["returned_count"], HA.MAX_HERMES_AGGREGATE_SNIPPETS)
        self.assertGreater(out["total_matched"], out["returned_count"])
        self.assertEqual(len(out["stores"]), 2)


class _UnusableRedaction:
    """遮蔽层拒绝形态：`usable=False` 且无派生文本。"""

    usable = False
    text = None
    redacted_count = 0
    truncated = False
    input_over_limit = False
    reason = "input_over_limit"


class AttributionTests(_Fixture):
    """存储授权与项目归属分离：库可读不等于项目可发布。"""

    def test_multi_store_project_narrow_keeps_other_project_store_readable(self) -> None:
        """TC-MCP-AGG-14（09 裁决 P2-2）：多项目库集合按项目 A 收窄时，项目 B 的库仍可读。

        旧缺陷：`_store_projects` 把用户收窄下进归属轴，B 库每条记录都 `PolicyDenied` =>
        整库 `attribution_denied` + `incomplete`，并牵连整体 `complete=false`。修后收窄只作
        过滤谓词：B 库贡献扫描量但不贡献结果。
        """
        second = self.tmp / "repo-b"
        second.mkdir(parents=True, exist_ok=True)
        db, repo, conn = self.store(rows=2, session_id=STORE_A)
        # 同一库文件、两个会话分属两个已批准项目根：两库都命中词，只有 A 命中项目收窄。
        self.add_session_rows(conn, STORE_B, repo=second, rows=2)
        policy = _policy_for(db, repo, second=second)
        search, _context, _book = self.services(
            policy,
            (HermesStoreRef(str(db), STORE_A), HermesStoreRef(str(db), STORE_B)),
        )
        out = search.search(query="needle-alpha", project=PROJECT, limit=20)
        reasons = [row["reason"] for row in out["stores"]]
        self.assertEqual([row["status"] for row in out["stores"]], ["read", "read"])
        self.assertEqual(reasons, [None, None])
        self.assertNotIn("attribution_denied", reasons)
        self.assertIsNone(out["failure_category"])
        self.assertTrue(out["complete"], out["reason"])
        self.assertEqual(out["coverage_scope"], "bounded_hermes_store_set")
        # B 库确实被扫过（不是被跳过），只是不发布：扫描量含两库四条。
        self.assertEqual(out["total_scanned"], 4)
        self.assertEqual(out["skipped_records"], 0)
        self.assertEqual({row["session_id"] for row in out["results"]}, {STORE_A})
        self.assertEqual({row["project"] for row in out["results"]}, {PROJECT})

    def test_store_outside_approved_project_is_not_published(self) -> None:
        other_repo = self.tmp / "other-repo"
        db, _repo, _conn = self.store(name="state.db", repo=other_repo)
        # 库根被批准（可读），但会话归属的 cwd 不在任何授权项目根下：策略根只给 tmp/repo。
        search, _context, _book = self.services(
            _policy_for(db, self.tmp / "repo"), (HermesStoreRef(str(db), STORE_A),)
        )
        out = search.search(query="needle-alpha", project=PROJECT)
        self.assertEqual(out["failure_category"], "stores_unusable")
        self.assertEqual(out["results"], [])
        self.assertFalse(out["complete"])

    def test_second_project_grant_publishes_under_its_own_name(self) -> None:
        second = self.tmp / "repo-b"
        second.mkdir(parents=True, exist_ok=True)
        db = self.tmp / "state.db"
        conn = self.writer(create_store(db))
        add_session(conn, STORE_A, cwd=str(second), git_repo_root=str(second))
        add_message(conn, STORE_A, "user", "synthetic message 0 needle-alpha body")
        policy = _policy_for(db, self.tmp / "repo", second=second)
        search, _context, _book = self.services(
            policy, (HermesStoreRef(str(db), STORE_A),)
        )
        out = search.search(query="needle-alpha", project=OTHER_PROJECT)
        self.assertTrue(out["complete"], out["reason"])
        self.assertEqual(out["returned_count"], 1)
        self.assertEqual(out["results"][0]["project"], OTHER_PROJECT)


class ContextRefusalTests(_Fixture):
    """回读侧的每一道拒绝都必须零正文，且区分「过期」与「绑定不合」。"""

    def _issued(self, rows: int = 4) -> tuple[HermesStoreRef, dict[str, Any], ReferenceLedger]:
        db, repo, _conn = self.store(rows=rows)
        out, book = self.search_one(db, repo)
        self.assertGreater(out["returned_count"], 0)
        return HermesStoreRef(str(db), STORE_A), out, book

    def _context(self, ref: HermesStoreRef, book: ReferenceLedger) -> HermesAggregateContextService:
        policy = _policy_for(Path(ref.store_path), self.tmp / "repo")
        _search, context, _book = self.services(policy, (ref,), ledger=book)
        return context

    def test_garbage_and_foreign_tokens_are_rejected(self) -> None:
        ref, out, book = self._issued()
        context = self._context(ref, book)
        for bad in ("", "   ", "line:3", "ctxref:", "ctxref:" + "ü" * 8, 7, None):
            with self.subTest(location=bad):
                pub = context.read(location=bad).as_public_dict()
                self.assertEqual(pub["failure_category"], "invalid_argument")
                self.assertEqual(pub["results"], [])
                self.assertEqual(pub["coverage_scope"], "none")
                self.assertEqual(pub["stage_reached"], "coordinator")
                self.assertFalse(pub["version_confirmed"])

    def test_expired_or_evicted_reference_reports_ref_expired(self) -> None:
        ref, out, book = self._issued()
        context = self._context(ref, book)
        location = out["results"][0]["location"]
        book.release((location,))
        pub = context.read(location=location).as_public_dict()
        self.assertEqual(pub["failure_category"], "ref_expired")
        self.assertEqual(pub["results"], [])
        self.assertEqual(pub["coverage_scope"], "none")
        self.assertFalse(pub["version_confirmed"])

    def test_cross_binding_is_rejected_before_any_read(self) -> None:
        ref, out, book = self._issued()
        context = self._context(ref, book)
        location = out["results"][0]["location"]
        with mock.patch.object(
            HA, "run_hermes_session", side_effect=AssertionError("store opened")
        ) as run:
            wrong_scope = context.read(scope="other-scope", location=location).as_public_dict()
            wrong_source = context.read(
                source="pi", location=location, session_id=STORE_A
            ).as_public_dict()
            wrong_session = context.read(
                location=location, session_id="other-session"
            ).as_public_dict()
            unbound = HermesAggregateContextService(
                policy=context.policy,
                scope=SCOPE,
                stores=(HermesStoreRef(str(self.tmp / "elsewhere.db"), "sX"),),
                ledger=book,
            ).read(location=location).as_public_dict()
        run.assert_not_called()
        for pub, code in (
            (wrong_scope, "scope_mismatch"),
            (wrong_source, "source_mismatch"),
            (wrong_session, "session_binding"),
            (unbound, "service_binding"),
        ):
            self.assertEqual(pub["failure_category"], "binding_mismatch", code)
            self.assertEqual(pub["reason"], "binding_mismatch")
            self.assertIn(code, pub["filter_errors"])
            self.assertEqual(pub["results"], [])
            self.assertEqual(pub["window_size"], 0)
            self.assertFalse(pub["version_confirmed"])

    def test_declared_session_illegal_shape_is_refused_not_silently_replaced(self) -> None:
        """09 裁决 P3-5.2：非法会话声明严格拒，不再静默换成绑定值。

        旧写法 `session_id if isinstance(...) and _comparable_key(...) is not None else ref.session_id`
        把客户端递不进的声明换成绑定值，「声明与绑定不合」恒不成立 -> 非法声明反而变成合法请求。
        「省略声明」（None）是另一回事：它保留回退，由 `test_declared_session_omitted_still_reads` 守住。
        """
        ref, out, book = self._issued()
        context = self._context(ref, book)
        location = out["results"][0]["location"]
        for bad in (7, 3.0, True, b"x", "", "   ", "ü" * 400):
            with self.subTest(session_id=bad):
                with mock.patch.object(
                    HA, "run_hermes_session", side_effect=AssertionError("store opened")
                ):
                    pub = context.read(
                        location=location, session_id=bad
                    ).as_public_dict()
                self.assertEqual(pub["failure_category"], "binding_mismatch")
                self.assertIn("session_binding", pub["filter_errors"])
                self.assertEqual(pub["results"], [])
                self.assertEqual(pub["window_size"], 0)
                self.assertFalse(pub["version_confirmed"])

    def test_declared_session_omitted_still_reads(self) -> None:
        """省略声明不是非法声明：仍回退成绑定值并读到正文（改严格拒后的回归护栏）。"""

        ref, out, book = self._issued()
        context = self._context(ref, book)
        location = out["results"][0]["location"]
        omitted = context.read(location=location).as_public_dict()
        declared = context.read(location=location, session_id=STORE_A).as_public_dict()
        self.assertTrue(omitted["complete"], omitted["reason"])
        self.assertTrue(declared["complete"], declared["reason"])
        # 两次读取各自发出新 ctxref，`location` 必不同；上下文行也不外出坐标（`_row_for` 有意
        # 不给行号/序号），只能比正文形状。
        self.assertEqual(
            [(r["session_id"], r["role"], r["snippet"]) for r in omitted["results"]],
            [(r["session_id"], r["role"], r["snippet"]) for r in declared["results"]],
        )

    def test_declared_project_drift_is_rejected(self) -> None:
        ref, out, book = self._issued()
        context = self._context(ref, book)
        location = out["results"][0]["location"]
        pub = context.read(location=location, project=OTHER_PROJECT).as_public_dict()
        self.assertEqual(pub["failure_category"], "binding_mismatch")
        self.assertEqual(pub["reason"], "binding_mismatch")
        self.assertIn("project_binding", pub["filter_errors"])
        self.assertEqual(pub["results"], [])

    def test_replaced_store_reports_file_replaced_with_zero_body(self) -> None:
        db, repo, _conn = self.store(rows=3)
        out, book = self.search_one(db, repo)
        location = out["results"][0]["location"]
        ref = HermesStoreRef(str(db), STORE_A)
        context = self._context(ref, book)
        original = HA._hermes_read_store

        def replaced(*args: Any, **kwargs: Any):
            records, projects, version, reason = original(*args, **kwargs)
            assert version is not None
            forged = FileVersion(
                volume=version.volume,
                file_id=version.file_id,
                size_bytes=version.size_bytes + 7,
                content_sha256="f" * 64,
                complete=True,
            )
            return records, projects, forged, reason

        with mock.patch.object(HC, "_hermes_read_store", side_effect=replaced):
            pub = context.read(location=location).as_public_dict()
        self.assertEqual(pub["failure_category"], "file_replaced")
        self.assertEqual(pub["results"], [])
        self.assertFalse(pub["version_confirmed"])
        self.assertGreaterEqual(pub["records_withheld"], 1)
        self.assertEqual(pub["coverage_scope"], HC.COVERAGE_SCOPE_FILE)

    def test_unreadable_store_degrades_to_incomplete_not_no_match(self) -> None:
        db, repo, _conn = self.store(rows=2)
        out, book = self.search_one(db, repo)
        location = out["results"][0]["location"]
        context = self._context(HermesStoreRef(str(db), STORE_A), book)
        with mock.patch.object(
            HC, "_hermes_read_store", return_value=([], [], None, "denied")
        ):
            pub = context.read(location=location).as_public_dict()
        self.assertEqual(pub["failure_category"], "incomplete")
        self.assertEqual(pub["status"], "incomplete")
        self.assertNotEqual(pub["status"], "no_match")
        self.assertEqual(pub["results"], [])
        self.assertFalse(pub["version_confirmed"])

    def test_window_identity_conflict_refuses_whole_window(self) -> None:
        db, repo, _conn = self.store(rows=4)
        out, book = self.search_one(db, repo)
        location = out["results"][0]["location"]
        context = self._context(HermesStoreRef(str(db), STORE_A), book)
        original = HA._hermes_read_store

        def drift(*args: Any, **kwargs: Any):
            records, projects, version, reason = original(*args, **kwargs)
            if len(records) > 1:
                record = records[1]
                records = [
                    *records[:1],
                    record.__class__(
                        source=record.source,
                        session_id="other-session",
                        role=record.role,
                        text=record.text,
                        timestamp=record.timestamp,
                        project=record.project,
                        location=record.location,
                    ),
                    *records[2:],
                ]
            return records, projects, version, reason

        with mock.patch.object(HC, "_hermes_read_store", side_effect=drift):
            pub = context.read(location=location).as_public_dict()
        self.assertEqual(pub["failure_category"], "window_unresolved")
        self.assertIn("window_identity_conflict", pub["filter_errors"])
        self.assertEqual(pub["results"], [])

    def test_window_bounds_are_clamped_and_never_open_a_file_on_bad_input(self) -> None:
        db, repo, _conn = self.store(rows=3)
        out, book = self.search_one(db, repo)
        location = out["results"][0]["location"]
        context = self._context(HermesStoreRef(str(db), STORE_A), book)
        for bad in (True, -1, 11, "2", 2.0, None):
            with self.subTest(before=bad):
                with mock.patch.object(
                    HA, "run_hermes_session", side_effect=AssertionError("store opened")
                ):
                    pub = context.read(location=location, before=bad).as_public_dict()
                self.assertEqual(pub["failure_category"], "invalid_argument")
                self.assertEqual(pub["results"], [])
                self.assertEqual(pub["stage_reached"], "coordinator")

    def test_store_read_failure_codes_are_carried_into_the_reason_code(self) -> None:
        db, repo, _conn = self.store(rows=3)
        out, book = self.search_one(db, repo)
        location = out["results"][0]["location"]
        context = self._context(HermesStoreRef(str(db), STORE_A), book)
        original = HC._hermes_read_store

        def unstable(*args: Any, **kwargs: Any):
            records, projects, version, reason = original(*args, **kwargs)
            return records, projects, version, "version_unstable"

        with mock.patch.object(HC, "_hermes_read_store", side_effect=unstable):
            pub = context.read(location=location).as_public_dict()
        self.assertEqual(pub["failure_category"], "version_unstable")
        self.assertIn("version_unstable", pub["filter_errors"])
        self.assertEqual(pub["results"], [])


class RoutingTests(_Fixture):
    """路由靠绑定键：同库不同会话是两个独立绑定，互不借位。"""

    def test_same_store_two_sessions_route_by_pair(self) -> None:
        db, repo, conn = self.store(name="state.db", session_id=STORE_A, rows=3)
        self.add_session_rows(conn, STORE_B, repo=repo, rows=3, word="needle-beta")
        policy = _policy_for(db, repo)
        refs = (HermesStoreRef(str(db), STORE_A), HermesStoreRef(str(db), STORE_B))
        search, context, book = self.services(policy, refs)
        out_a = search.search(query="needle-alpha", project=PROJECT)
        out_b = search.search(query="needle-beta", project=PROJECT)
        self.assertIsNone(out_a["failure_category"])
        self.assertIsNone(out_b["failure_category"])
        self.assertEqual([r["session_id"] for r in out_a["results"]], [STORE_A] * out_a["returned_count"])
        self.assertEqual([r["session_id"] for r in out_b["results"]], [STORE_B] * out_b["returned_count"])
        # A 的令牌只能回 A；声明成 B 就是 session_binding，且一库不读。
        token_a = out_a["results"][0]["location"]
        with mock.patch.object(
            HA, "run_hermes_session", side_effect=AssertionError("store opened")
        ):
            pub = context.read(location=token_a, session_id=STORE_B).as_public_dict()
        self.assertEqual(pub["failure_category"], "binding_mismatch")
        self.assertIn("session_binding", pub["filter_errors"])
        # 正常回读：只开被路由的那一库（另一库字节预算未被消耗由单测外的 stdio 侧观察）。
        ok = context.read(location=token_a, session_id=STORE_A).as_public_dict()
        self.assertTrue(ok["complete"], ok["reason"])
        self.assertIn("needle-alpha", ok["results"][0]["snippet"])

    def test_service_without_binding_key_falls_back_to_local_algorithm(self) -> None:
        db, repo, _conn = self.store(rows=2)
        ref = HermesStoreRef(str(db), STORE_A)
        policy = _policy_for(db, repo)
        context = HermesAggregateContextService(
            policy=policy, scope=SCOPE, stores=(ref,), ledger=ReferenceLedger()
        )
        self.assertEqual(
            context._service_key(0, ref), service_binding_key(scope=SCOPE, source="hermes", path=str(db), session_id=STORE_A)
        )
        self.assertTrue(
            isinstance(
                context._route_ref(service_binding_key(scope=SCOPE, source="hermes", path=str(db), session_id=STORE_A)),
                HermesStoreRef,
            )
        )
        self.assertIsNone(context._route_ref("0" * 64))

    def test_search_service_without_ledger_uses_process_default(self) -> None:
        db, repo, _conn = self.store(rows=2)
        search = HermesAggregateSearchService(
            policy=_policy_for(db, repo), scope=SCOPE, stores=(HermesStoreRef(str(db), STORE_A),)
        )
        self.assertIsNone(search.ledger)
        out = search.search(query="needle-alpha", project=PROJECT)
        self.assertGreater(out["returned_count"], 0)
        location = out["results"][0]["location"]
        context = search.context_service()
        self.assertIsNone(context.ledger)
        pub = context.read(location=location).as_public_dict()
        self.assertTrue(pub["complete"], pub["reason"])


class UnboundServerTests(unittest.IsolatedAsyncioTestCase):
    """生产默认口径：未注入时 hermes 行是 unavailable，绝不声称适配器未编写。"""

    def setUp(self) -> None:
        self.addCleanup(server.reset_bound_services)
        server.reset_bound_services()

    async def test_hermes_row_is_unavailable_when_unbound(self) -> None:
        payload = await server.list_sources()
        row = next(item for item in payload["sources"] if item["source"] == "hermes")
        self.assertEqual(row["status"], "unavailable")
        self.assertFalse(row["enabled"])
        self.assertIsNone(row["project_config"])
        self.assertIn("宿主未在本进程注入", row["reason"])
        self.assertNotIn("未实现", row["reason"])

    async def test_other_adapters_stay_unsupported(self) -> None:
        """P1-8 后的诚实口径：未绑定行族报 unavailable，不再谎称「未实现适配器」。"""
        payload = await server.list_sources()
        for source in ("dsh", "workbuddy", "cursor_agent_cli", "codex"):
            with self.subTest(source=source):
                row = next(
                    item for item in payload["sources"] if item["source"] == source
                )
                self.assertEqual(row["status"], "unavailable")
                self.assertIs(row["enabled"], False)
                self.assertIsNone(row["project_config"])
                self.assertIn("宿主未在本进程注入", row["reason"])
                self.assertNotIn("未实现", row["reason"])
        pi_row = next(item for item in payload["sources"] if item["source"] == "pi")
        self.assertEqual(pi_row["status"], "unavailable")

    async def test_pi_binding_does_not_make_hermes_ready(self) -> None:
        db, repo = Path("D:/synthetic/state.db"), Path("D:/synthetic/repo")
        policy = _policy_for(db, repo)
        ledger = ReferenceLedger()
        pi_search = PiFileSearchService(
            policy=policy,
            scope=SCOPE,
            path=str(db),
            session_id=STORE_A,
            ledger=ledger,
        )
        server.bind_pi_file_search_service(pi_search)
        payload = await server.list_sources()
        row = next(item for item in payload["sources"] if item["source"] == "hermes")
        self.assertEqual(row["status"], "unavailable")
        self.assertIn("宿主未在本进程注入", row["reason"])
        pi_row = next(item for item in payload["sources"] if item["source"] == "pi")
        self.assertEqual(pi_row["status"], "ready")


class ServerSourceHonestyTests(unittest.IsolatedAsyncioTestCase):
    """09 裁决 P2-3/P3（plan §6）：`server.py` 状态口径与来源 ID 归一。

    两条口径各自对应一个复审缺陷：

    1. **codex 不得被说成「未编写」**（§6.2）：`sources/codex.py` 已实现，只是未接线到
       本服务的查询绑定。`status` 仍为 unsupported（不扩枚举），但 reason 必须区分
       「已编写但未接线」与「未编写」，否则 `list_sources` 重新落入同一不诚实口径。
    2. **扩展来源按绑定事实处置**（计划 D-4 改口）：`claude_code_cli` 归一后不得降级成
       `source_unsupported` 结果；本构建已接线时：有其它绑定在场则 `search_sessions` 返回
       `status=disabled` 覆盖行（不触磁盘），全未绑定则走统一未绑定拒绝；
       `read_session_context` 保持固定拒绝。未启用与未探测的语义分别由覆盖行状态承载，
       不再混进参数错误。
    """

    def setUp(self) -> None:
        self.addCleanup(server.reset_bound_services)
        server.reset_bound_services()

    async def test_codex_row_says_wired_not_written(self) -> None:
        """P1-8 统一口径后：codex 未绑定时也是 unavailable+诚实 reason，不分裂文案。"""
        payload = await server.list_sources()
        row = next(item for item in payload["sources"] if item["source"] == "codex")
        self.assertEqual(row["status"], "unavailable")
        self.assertIs(row["enabled"], False)
        self.assertIsNone(row["project_config"])
        self.assertIn("宿主未在本进程注入", row["reason"])
        self.assertNotIn("未编写该来源", row["reason"], "codex 适配器已存在，不得谎称未编写")
        self.assertNotIn("未实现", row["reason"])

    async def test_unwritten_adapters_stay_worded_as_unwritten(self) -> None:
        """P1-8 后：dsh/workbuddy/cursor 三族适配器均已编写，未绑定即 unavailable，
        reason 沿用诚实人话；不得再用「未编写该来源的读取适配器」误伤已实现适配器。"""
        payload = await server.list_sources()
        rows = {item["source"]: item for item in payload["sources"]}
        for name in ("dsh", "workbuddy", "cursor_agent_cli"):
            with self.subTest(source=name):
                self.assertEqual(rows[name]["status"], "unavailable")
                self.assertIs(rows[name]["enabled"], False)
                self.assertIn("宿主未在本进程注入", rows[name]["reason"])
                self.assertNotIn("未编写", rows[name]["reason"])
                self.assertNotIn("未实现", rows[name]["reason"])
        for name in ("pi", "hermes"):
            with self.subTest(bound=name):
                self.assertEqual(rows[name]["status"], "unavailable")
                self.assertIs(rows[name]["enabled"], False)
                self.assertNotIn("未实现", rows[name]["reason"])

    async def test_extended_source_alias_normalized_and_zero_disk(self) -> None:
        """D-4：全未绑定时扩展来源走统一未绑定拒绝；归一不当场报错，也不开磁盘。"""
        with self.assertRaises(server.ToolError) as caught:
            await server.search_sessions(query="needle", sources=["claude_code_cli"], scope=SCOPE)
        text = str(caught.exception)
        self.assertIn("未绑定", text, "全未绑定时按绑定事实给未绑定人话（D-4）")
        self.assertNotIn("未支持的来源", text, "归一后的合法 ID 不得降级成未知来源")
        # 归一不得把合法全称变成无效：cursor_agent_cli 仍是可接受 ID。
        with self.assertRaises(server.ToolError) as other:
            await server.search_sessions(
                query="needle", sources=["cursor_agent_cli"], scope=SCOPE
            )
        self.assertIn("未绑定", str(other.exception))
        # 未知 ID 仍报“未支持的来源”，不降级成 source_unsupported 结果。
        with self.assertRaises(server.ToolError) as unknown:
            await server.search_sessions(query="needle", sources=["nosuch_source"], scope=SCOPE)
        self.assertIn("未支持的来源", str(unknown.exception))

    async def test_read_session_context_shares_the_same_source_gate(self) -> None:
        with self.assertRaises(server.ToolError) as caught:
            await server.read_session_context(
                source="claude_code_cli",
                session_id=STORE_A,
                location=REFERENCE_PREFIX + "0" * 40,
                scope=SCOPE,
            )
        self.assertIn("扩展来源", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
