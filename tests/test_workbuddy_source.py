"""WorkBuddy 来源适配器合成单测（计划 §8.3，映射 TC-MCP-PLN-WB-01/02）。

只用临时目录里的合成 SQLite 索引库与注入的合成正文行，绝不触碰真实 ``~/.workbuddy``。
按「仅静态自检」要求编写：所有断言取自一次性探针脚本对实现的实测值，本会话未运行测试套件。

两条固定口径（测试不放宽）：
- 正文文件布局未逐字核实 ⇒ 本增量没有发布通道，``publication_allowed`` 恒 False，
  聚合结果恒零命中且 ``partial`` 为真（绝不把「没查正文」写成「查过且没有」）。
- 存储轴与归属轴互不蕴含：两个门禁码（``storage_denied`` / ``attribution_denied``）分别断言。
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS_DIR = str(ROOT / "tests")
if TESTS_DIR not in sys.path:
    sys.path.insert(3, TESTS_DIR)

import workbuddy_synthetic as fx  # noqa: E402  pi-lens-ignore: reportMissingImports
from cross_agent_session_mcp.models import IssueCode, ProjectQuality  # noqa: E402
from cross_agent_session_mcp.policy import (  # noqa: E402  # noqa: E402
    CwdRootGrant,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.references import ReferenceLedger  # noqa: E402
from cross_agent_session_mcp.sources import workbuddy as wb  # noqa: E402

GATE = wb.WorkBuddyGateCode
ACCESS = wb.WorkBuddyAccessCode
LAYOUT_REASON = wb.WORKBUDDY_BODY_LAYOUT_REASON


def stage_reason(outcome: wb.WorkBuddySessionOutcome) -> str:
    """阶段口径取值（阶段缺失即测试失败，而不是 Optional 属性猜测）。"""
    stage = outcome.stage
    if stage is None or stage.reason is None:
        raise AssertionError("expected a staged outcome")
    return str(stage.reason.value)


def plan_of(path: Path | str, session_id: str = fx.SESSION, **kwargs: Any) -> wb.WorkBuddySessionPlan:
    """索引侧计划（不含授权），WB 全部列集/状态门禁的观测入口。"""
    return wb.plan_workbuddy_session(path=str(path), session_id=session_id, **kwargs)


class WorkBuddyFixtureCase(unittest.TestCase):
    """每个用例一套临时目录，teardown 清理。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="wb-src-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def store(self, name: str = "index.db", **kwargs: Any) -> Path:
        return fx.create_store(self.tmp / name, **kwargs)


class TestSchemaGate(WorkBuddyFixtureCase):
    """WB-01：列集/表集不认识 ⇒ 门禁码，不猜语义。"""

    def test_wb01_full_store_is_known_and_layout_gated(self) -> None:
        plan = plan_of(self.store())
        self.assertTrue(plan.available)
        self.assertIs(plan.access, ACCESS.OK)
        self.assertTrue(plan.schema_known)
        self.assertEqual(plan.schema_version, 22)
        self.assertTrue(plan.integrity_ok)
        self.assertTrue(plan.session_exists)
        self.assertIs(plan.gate, GATE.BODY_LAYOUT_UNKNOWN)
        self.assertEqual(plan.row_count, 1)
        self.assertFalse(plan.body_available)
        self.assertEqual(plan.body_missing_reason, LAYOUT_REASON)

    def test_wb01_missing_sessions_table_is_schema_unknown_tables(self) -> None:
        path = self.tmp / "no-sessions.db"
        conn = fx.build_store(path, with_messages_table=False, with_aux_tables=False)
        conn.execute('DROP TABLE "sessions"')
        conn.commit()
        conn.close()
        plan = plan_of(path)
        self.assertFalse(plan.available)
        self.assertIs(plan.access, ACCESS.FAULT)
        self.assertIs(plan.gate, GATE.SCHEMA_UNKNOWN_TABLES)

    def test_wb01_missing_aux_table_is_also_unknown_tables(self) -> None:
        path = self.tmp / "no-aux.db"
        fx.build_store(path, with_aux_tables=False).close()
        plan = plan_of(path)
        self.assertFalse(plan.available)
        self.assertIs(plan.gate, GATE.SCHEMA_UNKNOWN_TABLES)

    def test_wb01_missing_required_column_is_schema_unknown_columns(self) -> None:
        path = self.tmp / "missing-status.db"
        conn = fx.build_store(path, with_messages_table=False)
        names = [name for name in fx.SESSION_COLUMNS if name != "status"]
        columns = ", ".join(fx._quote_ident(name) for name in names)  # noqa: SLF001
        conn.execute('DROP TABLE "sessions"')
        conn.execute(f"CREATE TABLE sessions ({columns})")  # pi-lens-ignore: python-sql-injection
        conn.commit()
        conn.close()
        plan = plan_of(path)
        self.assertFalse(plan.available)
        self.assertIs(plan.gate, GATE.SCHEMA_UNKNOWN_COLUMNS)
        self.assertFalse(plan.schema_known)

    def test_wb01_extra_column_and_extra_table_are_reported_not_fatal(self) -> None:
        path = fx.unknown_column_store(self.store("mystery.db"))
        plan = plan_of(path)
        self.assertTrue(plan.available)
        self.assertIn("mystery_column", plan.unknown_columns)
        other = self.store("extra-table.db")
        conn = sqlite3.connect(str(other))
        conn.execute('CREATE TABLE "mystery_table" ("a" TEXT)')  # pi-lens-ignore: python-sql-injection
        conn.commit()
        conn.close()
        plan2 = plan_of(other)
        self.assertTrue(plan2.available)
        self.assertIs(plan2.gate, GATE.BODY_LAYOUT_UNKNOWN)

    def test_wb01_statement_whitelist_shape_is_clean(self) -> None:
        self.assertEqual(wb.whitelist_shape_problems(), ())

    def test_wb01_public_plan_carries_no_sql_or_path(self) -> None:
        path = self.store()
        dumped = json.dumps(plan_of(path).as_public_dict(), ensure_ascii=False)
        self.assertNotIn(str(path), dumped)
        for token in ("SELECT", "PRAGMA", "INSERT", "ATTACH"):
            self.assertNotIn(token, dumped)


class TestSessionSetGates(WorkBuddyFixtureCase):
    """WB-02/03/04/05/06：删除位、状态白名单、后台自动化、playground 一律保守。"""

    def test_wb02_deleted_at_marks_inactive_but_keeps_index_facts(self) -> None:
        path = self.tmp / "deleted.db"
        conn = fx.build_store(path)
        fx.add_session(conn, deleted_at="2026-04-01T00:00:00.000Z")
        conn.close()
        plan = plan_of(path)
        self.assertTrue(plan.session_exists)
        self.assertEqual(plan.inactive_count, 1)
        outcome = wb.run_workbuddy_session(path=str(path), session_id=fx.SESSION)
        self.assertFalse(outcome.complete)
        self.assertFalse(outcome.publication_allowed)
        self.assertEqual(outcome.records_emitted, 0)
        self.assertEqual(outcome.rows_read, 1)  # 索引行确实存在：绝不写成 0 消息会话

    def test_wb06_unknown_status_is_status_unknown(self) -> None:
        path = self.tmp / "archived.db"
        conn = fx.build_store(path)
        fx.add_session(conn, status="archived")
        conn.close()
        plan = plan_of(path)
        self.assertIs(plan.gate, GATE.STATUS_UNKNOWN)
        self.assertEqual(plan.inactive_count, 1)
        self.assertEqual(plan.unavailable_reasons.get("status_unknown"), 1)

    def test_wb06_status_whitelist_is_closed_set(self) -> None:
        self.assertEqual(
            wb.WORKBUDDY_ACTIVE_STATUSES, frozenset({"active", "open", "ready"})
        )

    def test_wb03_automation_and_usage_rows_count_but_never_impersonate_hits(self) -> None:
        path = self.store("automation.db")
        conn = sqlite3.connect(str(path))
        conn.execute(
            "INSERT INTO session_usage (session_id, used, size, updated_at, credit_json)"
            " VALUES (?, ?, ?, ?, ?)",
            (fx.SESSION, "10", "20", None, None),
        )
        conn.execute(
            "INSERT INTO automation_runs (thread_id, automation_id, status, source_cwd)"
            " VALUES (?, ?, ?, ?)",
            ("t-1", "auto-1", "running", fx.PROJECT),
        )
        conn.commit()
        conn.close()
        plan = plan_of(path)
        self.assertTrue(plan.available)
        self.assertGreaterEqual(plan.candidate_count, 2)  # 1 会话行 + 辅助候选行
        self.assertEqual(plan.row_count, 2)
        outcome = wb.run_workbuddy_session(
            path=str(path),
            session_id=fx.SESSION,
            project_filter=fx.PROJECT,
            body_lines=fx.flat_body_lines(["needle in the transcript"]),
        )
        self.assertEqual(outcome.records_emitted, 1)  # 只来自注入正文，与索引候选行无关
        self.assertFalse(outcome.publication_allowed)

    def test_wb04_is_playground_value_is_never_published(self) -> None:
        path = self.store("playground.db")
        conn = sqlite3.connect(str(path))
        conn.execute("UPDATE sessions SET is_playground = 1")  # pi-lens-ignore: python-sql-injection
        conn.commit()
        conn.close()
        payload = plan_of(path).as_public_dict()
        self.assertTrue(payload["available"])
        self.assertNotIn("is_playground", payload)  # 只可能作为未知列名出现，取值不外泄
        for row in payload["unavailable_reasons"]:
            self.assertNotIn("playground", row)

    def test_wb05_unknown_source_mode_does_not_infer_executor(self) -> None:
        path = self.tmp / "odd-mode.db"
        conn = fx.build_store(path)
        fx.add_session(conn, source_mode="quantum", executor_id="exec-9")
        conn.close()
        plan = plan_of(path)
        self.assertTrue(plan.available)
        self.assertNotIn("executor", plan.as_public_dict())
        records = wb.WorkBuddyBodyLineParser(
            session_id=fx.SESSION, project=fx.PROJECT
        ).feed(fx.flat_body_lines(["needle"]))
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].executor)


class TestAccessStates(WorkBuddyFixtureCase):
    """WB-07：锁 / 缺席 / 故障三态分开，不合并成「库不可用」。"""

    def test_wb07_missing_file_is_not_found(self) -> None:
        plan = plan_of(self.tmp / "does-not-exist.db")
        self.assertFalse(plan.available)
        self.assertIs(plan.access, ACCESS.NOT_FOUND)
        self.assertIs(plan.gate, GATE.SESSION_ABSENT)

    def test_wb07_absent_session_in_present_store_is_a_different_state(self) -> None:
        plan = plan_of(self.store(), session_id="absent-session")
        self.assertTrue(plan.available)
        self.assertFalse(plan.session_exists)
        self.assertIs(plan.gate, GATE.SESSION_ABSENT)
        outcome = wb.run_workbuddy_session(
            path=str(self.tmp / "index.db"), session_id="absent-session"
        )
        self.assertIs(outcome.access, ACCESS.OK)
        self.assertIs(outcome.gate, GATE.SESSION_ABSENT)
        self.assertFalse(outcome.complete)

    def test_wb07_corrupt_file_is_fault_integrity(self) -> None:
        path = fx.corrupt_store(self.store("corrupt.db"))
        plan = plan_of(path)
        self.assertFalse(plan.available)
        self.assertIs(plan.access, ACCESS.FAULT)
        self.assertIs(plan.gate, GATE.INTEGRITY)

    def test_wb07_lock_is_a_separate_state(self) -> None:
        path = self.store("locked.db")

        class _LockedConnection:
            """只回答「锁住」的伪连接：不执行任何真实语句。"""

            def execute(self, statement: str, parameters: Any = ()) -> Any:
                error = sqlite3.OperationalError("database is locked")
                error.sqlite_errorcode = 5
                raise error

            def close(self) -> None:
                return None

            def commit(self) -> None:
                return None

            def rollback(self) -> None:
                return None

        def fake_connect(*args: Any, **kwargs: Any) -> Any:
            return _LockedConnection()

        with mock.patch.object(sqlite3, "connect", fake_connect):
            plan = plan_of(path)
        self.assertFalse(plan.available)
        self.assertIs(plan.access, ACCESS.LOCKED)
        self.assertIs(plan.gate, GATE.LOCK_TIMEOUT)
        self.assertIsNone(plan.integrity_ok)

    def test_wb07_classification_table_is_explicit(self) -> None:
        path = str(self.store())
        for code in (5, 6):
            error = sqlite3.OperationalError("database is locked")
            error.sqlite_errorcode = code
            self.assertIs(wb._classify_exception(error, path), ACCESS.LOCKED)  # noqa: SLF001
        missing = sqlite3.OperationalError("unable to open database file")
        missing.sqlite_errorcode = 14
        self.assertIs(wb._classify_exception(missing, path), ACCESS.FAULT)  # noqa: SLF001
        self.assertIs(
            wb._ACCESS_GATE_DEFAULT[ACCESS.LOCKED], GATE.LOCK_TIMEOUT  # noqa: SLF001
        )
        self.assertIs(
            wb._ACCESS_GATE_DEFAULT[ACCESS.NOT_FOUND], GATE.SESSION_ABSENT  # noqa: SLF001
        )

    def test_wb07_argument_shape_is_invalid_argument(self) -> None:
        path = self.store()
        bad_path: Any = path
        self.assertIs(
            wb.run_workbuddy_session(path=bad_path, session_id=fx.SESSION).gate,
            GATE.INVALID_ARGUMENT,
        )  # Path 不是 str
        self.assertIs(
            wb.run_workbuddy_session(path=str(path), session_id="").gate,
            GATE.INVALID_ARGUMENT,
        )
        relative = wb.run_workbuddy_session(path="index.db", session_id=fx.SESSION)
        self.assertIs(relative.gate, GATE.STORAGE_DENIED)
        self.assertEqual(relative.denial_code, "path_unsafe")


class TestIdShapeGate(WorkBuddyFixtureCase):
    """WB-12：会话 id 形态门 + 重复行拒选一个。"""

    def test_wb12_path_like_session_id_never_produces_records(self) -> None:
        path = self.store()
        for bad in ("..\\evil", "../../etc/passwd", "a/b", "C:\\x"):
            outcome = wb.run_workbuddy_session(path=str(path), session_id=bad)
            self.assertEqual(outcome.records_emitted, 0, bad)
            self.assertNotIn(
                outcome.gate,
                (GATE.BODY_LAYOUT_UNKNOWN, GATE.BODY_MISSING),
                bad,
            )

    def test_wb12_storing_a_path_like_id_is_id_shape_rejected(self) -> None:
        path = self.tmp / "bad-id.db"
        conn = fx.build_store(path)
        fx.add_session(conn, session_id="..\\evil")
        conn.close()
        plan = plan_of(path, session_id="..\\evil")
        self.assertFalse(plan.available)
        self.assertIs(plan.gate, GATE.ID_SHAPE_REJECTED)
        self.assertIs(plan.access, ACCESS.FAULT)

    def test_wb12_duplicate_rows_never_pick_one(self) -> None:
        path = self.tmp / "dup.db"
        conn = fx.build_store(path)
        fx.add_session(conn)
        fx.add_session(conn, title="second row same id")
        conn.close()
        plan = plan_of(path)
        self.assertFalse(plan.available)
        self.assertIs(plan.gate, GATE.CANDIDATE_LIMIT)


class TestBodyShapes(WorkBuddyFixtureCase):
    """WB-08/09/10：正文三形态、双限截断、withhold 双记。"""

    def setUp(self) -> None:
        super().setUp()
        self.path = self.store()

    def run_body(
        self, lines: list[str] | None, **kwargs: Any
    ) -> wb.WorkBuddySessionOutcome:
        return wb.run_workbuddy_session(
            path=str(self.path),
            session_id=fx.SESSION,
            project_filter=fx.PROJECT,
            body_lines=lines,
            **kwargs,
        )

    def test_wb08_missing_body_is_body_missing_not_zero_messages(self) -> None:
        outcome = self.run_body(None)
        self.assertIs(outcome.gate, GATE.BODY_MISSING)
        self.assertFalse(outcome.complete)
        self.assertFalse(outcome.publication_allowed)
        self.assertEqual(outcome.records_emitted, 0)
        self.assertEqual(outcome.rows_read, 1)  # 索引侧确实有会话行
        self.assertEqual(outcome.withheld_reasons["body_missing"], 1)
        self.assertFalse(outcome.plan.body_available)
        self.assertEqual(outcome.plan.body_missing_reason, LAYOUT_REASON)

    def test_wb08_flat_body_lines_produce_records_yet_stay_incomplete(self) -> None:
        outcome = self.run_body(fx.flat_body_lines(["needle one", "needle two"]))
        self.assertEqual(outcome.records_emitted, 2)
        self.assertEqual(outcome.parse.records_emitted, 2)
        self.assertIs(outcome.gate, GATE.BODY_LAYOUT_UNKNOWN)
        self.assertFalse(outcome.complete)
        self.assertFalse(outcome.publication_allowed)
        # 扇平行补了 created_at 后 MISSING_TIMESTAMP 不再触发，parse.stats 干净 ⇒
        # stream_complete=True；但扁平形态无头部行，正文侧不存在头部级归属证据 ⇒
        # 核对点按管道契约报 project_unattributed（比旧断言 stream_incomplete 更精确：
        # 旧码是 MISSING_TIMESTAMP 把 partial 拉高后的连锁结果，不是本形态的固有结论）。
        self.assertEqual(stage_reason(outcome), "project_unattributed")

    def test_wb08_nested_body_shape_is_counted_not_silently_accepted(self) -> None:
        outcome = self.run_body(fx.nested_body_lines([("user", "needle one")]))
        self.assertEqual(outcome.records_emitted, 0)
        self.assertEqual(outcome.withheld_reasons["role_unusable"], 1)
        self.assertEqual(outcome.parse.issue_counts[IssueCode.MISSING_ROLE], 1)

    def test_wb09_empty_injection_is_not_body_missing(self) -> None:
        outcome = self.run_body([])
        self.assertIs(outcome.gate, GATE.BODY_LAYOUT_UNKNOWN)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.withheld_reasons["body_missing"], 0)

    def test_wb09_text_char_cap_truncates_and_reports(self) -> None:
        outcome = self.run_body(fx.flat_body_lines(["x" * 40_000]))
        self.assertEqual(outcome.records_emitted, 1)
        self.assertEqual(outcome.withheld_reasons["content_overlong"], 1)
        self.assertEqual(
            outcome.parse.issue_counts[IssueCode.TEXT_BLOCK_TRUNCATED], 1
        )
        self.assertTrue(outcome.parse.partial)

    def test_wb09_block_list_is_joined_into_one_record(self) -> None:
        blocks = [{"text": f"b{index}"} for index in range(40)]
        outcome = self.run_body(fx.body_lines([{"role": "user", "content": blocks}]))
        self.assertEqual(outcome.records_emitted, 1)

    def test_wb09_row_cap_marks_parser_partial(self) -> None:
        parser = wb.WorkBuddyBodyLineParser(session_id=fx.SESSION, project=fx.PROJECT)
        records = parser.feed(fx.flat_body_lines([f"line {i}" for i in range(70)]))
        stats = parser.finish()
        self.assertEqual(len(records), wb.MAX_ROWS_PER_SESSION)
        self.assertEqual(
            stats.issue_counts[IssueCode.MAX_STREAM_LINES_EXCEEDED], 1
        )
        self.assertTrue(stats.partial)

    def test_wb10_withhold_is_double_recorded(self) -> None:
        outcome = self.run_body(
            fx.flat_body_lines(["tool noise"], role="tool")
            + fx.flat_body_lines(["kept"])
        )
        self.assertEqual(outcome.withheld_reasons["content_shape"], 1)
        self.assertEqual(outcome.parse.issue_counts[IssueCode.SKIPPED_ROLE], 1)
        self.assertEqual(outcome.records_emitted, 1)

    def test_wb10_identity_conflict_withholds_foreign_row(self) -> None:
        lines = [
            json.dumps({"role": "user", "content": "foreign", "session_id": "other"}),
            *fx.flat_body_lines(["kept"]),
        ]
        outcome = self.run_body(lines)
        self.assertEqual(outcome.withheld_reasons["identity_unusable"], 1)
        self.assertEqual(outcome.parse.issue_counts[IssueCode.SESSION_ID_MISMATCH], 1)
        self.assertEqual(outcome.records_emitted, 1)

    def test_wb10_junk_rows_are_all_counted(self) -> None:
        outcome = self.run_body(
            [
                "@@@not json",
                "[1,2]",
                "   ",
                '{"content":"no role"}',
                '{"role":"user","content":"  "}',
            ]
        )
        self.assertEqual(outcome.records_emitted, 0)
        self.assertTrue(outcome.parse.partial)
        for issue in (
            IssueCode.CORRUPT_LINE,
            IssueCode.LINE_NOT_OBJECT,
            IssueCode.BLANK_LINE,
            IssueCode.MISSING_ROLE,
            IssueCode.NO_TEXT_CONTENT,
        ):
            self.assertEqual(outcome.parse.issue_counts[issue], 1, issue.value)

    def test_attribution_is_required_for_any_record(self) -> None:
        outcome = wb.run_workbuddy_session(
            path=str(self.path), session_id=fx.SESSION, body_lines=fx.flat_body_lines(["needle"])
        )
        self.assertEqual(outcome.records_emitted, 0)
        self.assertEqual(stage_reason(outcome), "project_unattributed")
        if outcome.stage is None:
            raise AssertionError("expected a staged outcome")
        self.assertEqual(outcome.stage.dropped_count, 1)

    def test_cancel_stops_body_stage(self) -> None:
        outcome = self.run_body(
            fx.flat_body_lines(["one", "two"]), should_stop=lambda: True
        )
        self.assertIs(outcome.gate, GATE.BODY_MISSING)
        self.assertEqual(stage_reason(outcome), "cancelled")
        self.assertEqual(outcome.records_emitted, 0)


class TestBodyLineParserContract(WorkBuddyFixtureCase):
    """WB-09 + 共性矩阵⑥⑦：解析器 API 契约与记录形状。"""

    def test_whole_payload_feed_raises_type_error(self) -> None:
        parser = wb.WorkBuddyBodyLineParser(session_id=fx.SESSION)
        whole: Any = '{"role":"user","content":"x"}'
        with self.assertRaises(TypeError):
            parser.feed(whole)
        whole_bytes: Any = b'{"role":"user","content":"x"}'
        with self.assertRaises(TypeError):
            parser.feed(whole_bytes)

    def test_feed_after_finish_raises_runtime_error(self) -> None:
        parser = wb.WorkBuddyBodyLineParser(session_id=fx.SESSION)
        parser.finish()
        with self.assertRaises(RuntimeError):
            parser.feed_line('{"role":"user","content":"x"}')

    def test_finish_is_idempotent(self) -> None:
        parser = wb.WorkBuddyBodyLineParser(session_id=fx.SESSION, project=fx.PROJECT)
        self.assertIs(parser.finish(), parser.finish())

    def test_record_shape_is_the_common_contracts_shape(self) -> None:
        parser = wb.WorkBuddyBodyLineParser(
            session_id=fx.SESSION, project=fx.PROJECT, stream_label="store-index"
        )
        records = parser.feed(
            [
                json.dumps(
                    {
                        "role": "user",
                        "content": {"text": "dict body"},
                        "timestamp": "2026-03-01T10:00:00.000Z",
                    }
                )
            ]
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.source, fx.SOURCE)
        self.assertEqual(record.session_id, fx.SESSION)
        self.assertEqual(record.text, "dict body")
        self.assertIsNone(record.executor)
        self.assertEqual(record.location.stream_label, "store-index")
        self.assertEqual(record.location.line_no, 1)
        self.assertEqual(record.project, fx.PROJECT)
        self.assertIs(record.project_quality, ProjectQuality.CALLER_ASSERTED)
        self.assertEqual(record.issues, ())

    def test_missing_project_assert_marks_every_record_and_stats(self) -> None:
        parser = wb.WorkBuddyBodyLineParser(session_id=fx.SESSION)
        self.assertIs(parser.project_quality, ProjectQuality.UNKNOWN)
        # feed() 是惰性的：必须先消费完记录，`finish()` 才能报出收尾的
        # unknown_project / partial——消费前调用等于对未扫完的流下结论。
        records = list(parser.feed(fx.flat_body_lines(["needle"])))
        stats = parser.finish()
        self.assertEqual(
            [record.issues for record in records], [(IssueCode.PROJECT_UNVERIFIED,)]
        )
        self.assertEqual(stats.issue_counts[IssueCode.UNKNOWN_PROJECT], 1)
        self.assertTrue(stats.partial)

    def test_oversized_bytes_line_is_rejected_before_decode(self) -> None:
        parser = wb.WorkBuddyBodyLineParser(session_id=fx.SESSION, project=fx.PROJECT)
        huge: Any = b"x" * (wb.MAX_LINE_BYTES + 1)
        self.assertEqual(parser.feed_line(huge), [])
        self.assertEqual(parser.stats.issue_counts[IssueCode.LINE_TOO_LARGE], 1)


class TestPolicyAxes(WorkBuddyFixtureCase):
    """WB-11 前半：存储轴与归属轴互不蕴含。"""

    def setUp(self) -> None:
        super().setUp()
        self.project_root = self.tmp / "project"
        self.project_root.mkdir()
        self.store_root = self.tmp / "stores"
        self.store_root.mkdir()
        self.path = fx.create_store(self.store_root / "inside.db")
        self.policy = SessionPolicy(
            (
                ScopeGrant(
                    "s",
                    (ProjectGrant("p", (CwdRootGrant(str(self.project_root)),)),),
                    (StoreRootGrant(fx.SOURCE, str(self.store_root)),),
                ),
            )
        )

    def run_authorized(self, **kwargs: Any) -> wb.WorkBuddySessionOutcome:
        return wb.run_workbuddy_session(
            path=str(self.path),
            session_id=fx.SESSION,
            policy=self.policy,
            scope="s",
            **kwargs,
        )

    def test_storage_axis_denies_unapproved_root(self) -> None:
        outside = fx.create_store(self.tmp / "outside.db")
        outcome = wb.run_workbuddy_session(
            path=str(outside), session_id=fx.SESSION, policy=self.policy, scope="s"
        )
        self.assertIs(outcome.gate, GATE.STORAGE_DENIED)
        self.assertIs(outcome.access, ACCESS.DENIED)
        self.assertEqual(outcome.denial_code, "path_out_of_scope")
        self.assertEqual(outcome.records_emitted, 0)

    def test_storage_axis_denies_unknown_scope(self) -> None:
        outcome = wb.run_workbuddy_session(
            path=str(self.path), session_id=fx.SESSION, policy=self.policy, scope="zz"
        )
        self.assertIs(outcome.gate, GATE.STORAGE_DENIED)
        self.assertEqual(outcome.denial_code, "scope_unknown")

    def test_pairing_is_required_before_any_open(self) -> None:
        policy_only = wb.run_workbuddy_session(
            path=str(self.path), session_id=fx.SESSION, policy=self.policy
        )
        self.assertIs(policy_only.gate, GATE.INVALID_ARGUMENT)
        scope_only = wb.run_workbuddy_session(
            path=str(self.path), session_id=fx.SESSION, scope="s"
        )
        self.assertIs(scope_only.gate, GATE.INVALID_ARGUMENT)

    def test_attribution_axis_denies_without_touching_storage_axis(self) -> None:
        outcome = self.run_authorized()
        self.assertIs(outcome.gate, GATE.ATTRIBUTION_DENIED)
        self.assertEqual(outcome.denial_code, "attribution_unmatched")
        named = self.run_authorized(project_filter="p")
        self.assertIs(named.gate, GATE.ATTRIBUTION_DENIED)
        self.assertEqual(named.denial_code, "attribution_unmatched")
        path_as_filter = self.run_authorized(project_filter=fx.PROJECT)
        self.assertIs(path_as_filter.gate, GATE.ATTRIBUTION_DENIED)
        self.assertEqual(path_as_filter.denial_code, "project_unknown")

    def test_denial_payload_has_no_path_or_query(self) -> None:
        outcome = self.run_authorized()
        dumped = json.dumps(outcome.as_public_dict(), ensure_ascii=False)
        self.assertNotIn(str(self.path), dumped)
        self.assertNotIn(str(self.store_root), dumped)
        self.assertFalse(outcome.publication_allowed)


class TestAggregateService(WorkBuddyFixtureCase):
    """WB-11 后半：聚合服务门禁、逐库行、零结果口径。"""

    def setUp(self) -> None:
        super().setUp()
        self.project_root = self.tmp / "project"
        self.project_root.mkdir()
        self.store_root = self.tmp / "stores"
        self.store_root.mkdir()
        self.good = fx.create_store(self.store_root / "inside.db")
        self.policy = SessionPolicy(
            (
                ScopeGrant(
                    "s",
                    (ProjectGrant("p", (CwdRootGrant(str(self.project_root)),)),),
                    (StoreRootGrant(fx.SOURCE, str(self.store_root)),),
                ),
            )
        )
        self.refs = (
            wb.WorkBuddyStoreRef(store_path=str(self.good), session_id=fx.SESSION),
            wb.WorkBuddyStoreRef(
                store_path=str(self.store_root / "gone.db"), session_id="absent-sess"
            ),
        )
        self.service = wb.WorkBuddyAggregateSearchService(
            policy=self.policy,
            scope="s",
            stores=self.refs,
            ledger=ReferenceLedger(),
        )

    def test_service_shape_and_binding_keys(self) -> None:
        self.assertEqual(self.service.source, fx.SOURCE)
        self.assertEqual(self.service.store_refs(), self.refs)
        key = self.service.binding_key(0)
        self.assertEqual(len(key), 64)
        self.assertEqual(key, self.service.binding_key(0))
        self.assertNotEqual(key, self.service.binding_key(1))
        for bad in (2, -1, True):
            bad_index: Any = bad
            with self.assertRaises(ValueError):
                self.service.binding_key(bad_index)

    def test_construction_gates(self) -> None:
        bad_policy: Any = "x"
        bad_stores: Any = (fx.SOURCE,)
        bad_ledger: Any = "not-a-ledger"
        bad_scope: Any = ""
        with self.assertRaises(TypeError):
            wb.WorkBuddyAggregateSearchService(
                policy=bad_policy, scope="s", stores=self.refs, ledger=ReferenceLedger()
            )
        with self.assertRaises(ValueError):
            wb.WorkBuddyAggregateSearchService(
                policy=self.policy,
                scope=bad_scope,
                stores=self.refs,
                ledger=ReferenceLedger(),
            )
        with self.assertRaises(TypeError):
            wb.WorkBuddyAggregateSearchService(
                policy=self.policy,
                scope="s",
                stores=bad_stores,
                ledger=ReferenceLedger(),
            )
        with self.assertRaises(TypeError):
            wb.WorkBuddyAggregateSearchService(
                policy=self.policy,
                scope="s",
                stores=self.refs,
                ledger=bad_ledger,
            )
        too_many = tuple(
            wb.WorkBuddyStoreRef(store_path=str(self.good), session_id=f"s-{i}")
            for i in range(wb.MAX_STORES_PER_QUERY + 1)
        )
        with self.assertRaises(ValueError):
            wb.WorkBuddyAggregateSearchService(
                policy=self.policy, scope="s", stores=too_many, ledger=ReferenceLedger()
            )

    def test_store_ref_shape_gates(self) -> None:
        # 非字符串与空白都判 ValueError（与 HermesStoreRef / SessionFileRef 同口径：
        # StoreRef 的 __post_init__ 判形是「不可用值」语义，不是类型错误）。
        for bad in ("", "  ", 3):
            bad_ref: Any = bad
            with self.assertRaises(ValueError):
                wb.WorkBuddyStoreRef(store_path=bad_ref, session_id=fx.SESSION)

    def test_scope_mismatch_short_circuits_before_any_open(self) -> None:
        with mock.patch.object(
            wb.sqlite3, "connect", side_effect=AssertionError("opened a store")
        ):
            payload = self.service.search(scope="other", query="needle")
        self.assertEqual(payload["reason"], "scope_mismatch")
        self.assertEqual(payload["failure_category"], "scope_mismatch")
        self.assertEqual(payload["stage_reached"], "coordinator")
        self.assertEqual(payload["coverage_scope"], "none")
        self.assertEqual(payload["stores"], [])
        self.assertFalse(payload["partial"])

    def test_source_and_limit_gates(self) -> None:
        wrong = self.service.search(scope="s", query="needle", sources=("codex",))
        self.assertEqual(wrong["reason"], "source_unsupported")
        self.assertEqual(wrong["stage_reached"], "coordinator")
        self.assertEqual(wrong["results"], [])
        for bad in (0, 101, "10"):
            bad_limit: Any = bad
            self.assertEqual(
                self.service.search(scope="s", query="needle", limit=bad_limit)["reason"],
                "invalid_request",
                bad,
            )

    def test_search_payload_is_honest_incomplete_zero_results(self) -> None:
        payload = self.service.search(
            scope="s", query="needle", sources=("workbuddy",)
        )
        self.assertFalse(payload["complete"])
        self.assertTrue(payload["partial"])
        self.assertEqual(payload["results"], [])
        self.assertEqual(payload["total_matched"], 0)
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["failure_category"], "body_unverified")
        self.assertEqual(payload["stage_reached"], "store_plan")
        self.assertEqual(
            payload["coverage_scope"], wb.COVERAGE_SCOPE_MULTI_WORKBUDDY
        )
        self.assertEqual(payload["reason"], LAYOUT_REASON)
        row = payload["coverage"][0]
        self.assertEqual(row["source"], fx.SOURCE)
        self.assertEqual(row["status"], "incomplete")
        self.assertTrue(row["partial"])
        self.assertEqual(row["matched_count"], 0)
        self.assertEqual(row["reason"], LAYOUT_REASON)

    def test_per_store_rows_disclose_gates_not_paths(self) -> None:
        payload = self.service.search(scope="s", query="needle")
        rows = payload["stores"]
        self.assertEqual([row["index"] for row in rows], [0, 1])
        self.assertEqual(rows[0]["session_id"], fx.SESSION)
        self.assertEqual(rows[0]["gate"], "attribution_denied")
        self.assertEqual(rows[1]["gate"], "storage_denied")
        for row in rows:
            self.assertEqual(row["records_captured"], 0)
            self.assertEqual(row["returned_count"], 0)
            self.assertEqual(row["status"], "incomplete")
        dumped = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn(str(self.good), dumped)

    def test_context_service_is_a_pure_refusal(self) -> None:
        context = self.service.context_service()
        self.assertIsInstance(
            context, wb.WorkBuddyAggregateContextService
        )
        self.assertEqual(context.store_refs(), self.refs)
        with mock.patch.object(
            wb.sqlite3, "connect", side_effect=AssertionError("opened a store")
        ):
            outcome = context.read(
                scope="s",
                source=fx.SOURCE,
                session_id=fx.SESSION,
                location="store-index:1:0",
            )
        payload = outcome.as_public_dict()
        self.assertEqual(outcome.reason, LAYOUT_REASON)
        self.assertFalse(outcome.complete)
        self.assertEqual(payload["status"], "incomplete")
        self.assertTrue(payload["partial"])
        self.assertEqual(payload["results"], [])
        self.assertEqual(payload["returned_count"], 0)
        self.assertEqual(
            payload["coverage_scope"], wb.COVERAGE_SCOPE_MULTI_WORKBUDDY
        )

    def test_context_gates_precede_the_layout_refusal(self) -> None:
        context = self.service.context_service()
        mismatch = context.read(scope="other").as_public_dict()
        self.assertEqual(mismatch["reason"], "scope_mismatch")
        self.assertEqual(mismatch["coverage_scope"], "none")
        self.assertFalse(mismatch["partial"])
        wrong = context.read(source="codex").as_public_dict()
        self.assertEqual(wrong["reason"], "source_unsupported")
        self.assertEqual(wrong["coverage_scope"], "none")


class TestHonestZeroResults(WorkBuddyFixtureCase):
    """WB-12 尾 + 共性矩阵②：GUI/CLI 形态互不推断，空结果不写成「查过且没有」。"""

    def test_empty_store_is_never_reported_complete(self) -> None:
        path = fx.write_store(self.tmp, store_name="empty.db")
        outcome = wb.run_workbuddy_session(path=str(path), session_id="absent-session")
        self.assertFalse(outcome.complete)
        self.assertFalse(outcome.publication_allowed)
        self.assertEqual(outcome.records_emitted, 0)
        self.assertIs(outcome.gate, GATE.SESSION_ABSENT)
        self.assertTrue(outcome.plan.schema_known)

    def test_extra_gui_shaped_table_does_not_prove_cli_inactivity(self) -> None:
        path = self.store("gui.db")
        conn = sqlite3.connect(str(path))
        conn.execute('CREATE TABLE "chat_threads" ("a" TEXT)')  # pi-lens-ignore: python-sql-injection
        conn.commit()
        conn.close()
        plan = plan_of(path)
        self.assertTrue(plan.available)
        self.assertFalse(plan.body_available)
        self.assertEqual(plan.gate, GATE.BODY_LAYOUT_UNKNOWN)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
