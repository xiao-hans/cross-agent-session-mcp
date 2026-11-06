"""Synthetic verification for the read-only Hermes SQLite session adapter.

本套件只新建合成 sqlite 文件（temp 目录内），**从不**打开、复制或读取任何真实
Hermes 状态库、日志或用户配置。断言面：

* 白名单形状自检（语句文本 / 绑定个数 / 角色谓词形状）。
* 存储轴与归属轴相互独立，且都在 `run_hermes_session` 内强制（缺任一即拒，绝不默认放行）。
* 只读打开（`mode=ro`）在 锁 / 损坏 / 空文件 / 未知 schema / 低版本 下的固定类别。
* 判限发生在取正文**之前**；任何非完整路径整批丢弃，公开结果只有整数与固定类别。
* 逐行降级（坏角色 / 坏时间戳 / 非文本正文 / 超长 / 不活跃 / active 未识别）如实计数并
  使覆盖不完整（`parse_incomplete`），不静默跳过。
* 统计与取数之间的行数漂移由假游标直接驱动单测（真实只读连接拿语句级快照，无法在
  同连接内制造「统计后追加行再取数」的可见变化，所以那条路径用单元级替身验证）。
"""

from __future__ import annotations

import contextlib
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hermes_synthetic import add_message, add_session, create_store

from cross_agent_session_mcp.policy import (
    CwdRootGrant,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.publication import PublicationRefusal, SnippetCollector
from cross_agent_session_mcp.session_stage import (
    PER_RECORD_FIXED_OVERHEAD_BYTES,
    StageDiscardReason,
)
from cross_agent_session_mcp.sources import hermes as H

SCOPE = "synthetic-scope"
SESSION_ID = "synthetic-session"
PROJECT = "synthetic-project"
OTHER_PROJECT = "synthetic-project-b"


def _policy_for(db: Path, repo: Path, *, second: Path | None = None) -> SessionPolicy:
    roots = [StoreRootGrant("hermes", str(db))]
    projects = [ProjectGrant(PROJECT, (CwdRootGrant(str(repo)),))]
    if second is not None:
        projects.append(ProjectGrant(OTHER_PROJECT, (CwdRootGrant(str(second)),)))
    return SessionPolicy(
        scopes=(
            ScopeGrant(
                scope_id=SCOPE,
                projects=tuple(projects),
                store_roots=tuple(roots),
            ),
        )
    )


class _Fixture(unittest.TestCase):
    """每个测试一个独立 temp 目录；连接与目录都显式清理（Windows 上未关连接会卡删除）。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="xagent-hermes-"))
        self._writers: list[sqlite3.Connection] = []
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        for conn in self._writers:
            with contextlib.suppress(sqlite3.Error):
                conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def writer(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        self._writers.append(conn)
        return conn

    def store(
        self,
        *,
        session_id: str = SESSION_ID,
        rows: int = 2,
        name: str = "state.db",
        cwd: str | None = "USE_REPO",
        repo: Path | None = None,
        **store_kwargs: Any,
    ) -> tuple[Path, Path, sqlite3.Connection]:
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
            add_message(conn, session_id, "user" if index % 2 == 0 else "assistant", f"synthetic message {index} body")
        return db, repo, conn

    def read(self, db: Path, repo: Path, **kwargs: Any) -> H.HermesSessionOutcome:
        options: dict[str, Any] = {
            "path": str(db),
            "session_id": SESSION_ID,
            "scope": SCOPE,
            "policy": _policy_for(db, repo),
            "project_filter": PROJECT,
        }
        options.update(kwargs)
        return H.run_hermes_session(**options)


class WhitelistShapeTests(unittest.TestCase):
    def test_whitelist_shape_is_clean(self) -> None:
        self.assertEqual(H.whitelist_shape_problems(), ())

    def test_execute_refuses_arity_mismatch_without_running_sql(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            with self.assertRaises(TypeError):
                H._execute(conn, H._Op.SESSION_FACTS, ())
            with self.assertRaises(TypeError):
                H._execute(conn, H._Op.SESSION_FACTS, ("a", "b"))
        finally:
            conn.close()

    def test_execute_refuses_unexplainable_bound_shapes(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            with self.assertRaises(TypeError):
                H._execute(conn, H._Op.SESSION_FACTS, (["x"],))
            with self.assertRaises(TypeError):
                H._execute(conn, H._Op.SESSION_FACTS, (True,))
            with self.assertRaises(TypeError):
                H._execute(conn, H._Op.SESSION_FACTS, (("ok", ["nested"]),))
        finally:
            conn.close()

    def test_read_only_uri_guard_rejects_non_mode_ro(self) -> None:
        with self.assertRaises(sqlite3.ProgrammingError):
            H._connect_read_only("file:C:/x/y.db", 100)
        with self.assertRaises(sqlite3.ProgrammingError):
            H._connect_read_only("C:/x/y.db?mode=ro", 100)


class HappyPathTests(_Fixture):
    def test_complete_run_stages_verified_candidates(self) -> None:
        db, repo, _ = self.store(rows=4)
        outcome = self.read(db, repo)
        self.assertTrue(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.OK)
        self.assertIs(outcome.access, H.HermesAccessCode.OK)
        self.assertFalse(outcome.publication_allowed)
        self.assertEqual(outcome.records_emitted, 4)
        self.assertEqual(outcome.rows_read, 4)
        stage = outcome.stage
        assert stage is not None
        self.assertTrue(stage.complete)
        self.assertEqual(stage.candidate_count, 4)
        self.assertFalse(outcome.parse.partial)
        self.assertIsNone(stage.reason)

    def test_public_dicts_carry_no_bodies_no_paths(self) -> None:
        db, repo, _ = self.store(rows=2)
        outcome = self.read(db, repo)
        dumped = json.dumps(outcome.as_public_dict(), ensure_ascii=False)
        for needle in ("synthetic message 0", str(db), str(repo), SESSION_ID):
            self.assertNotIn(needle, dumped)
        self.assertEqual(json.loads(dumped)["source"], "hermes")
        plan_dumped = json.dumps(outcome.plan.as_public_dict())
        for needle in (str(db), str(repo), SESSION_ID):
            self.assertNotIn(needle, plan_dumped)

    def test_plan_probe_reports_counts_without_bodies(self) -> None:
        db, _repo, _conn = self.store(rows=3)
        plan = H.plan_hermes_session(path=str(db), session_id=SESSION_ID)
        self.assertTrue(plan.available)
        self.assertIs(plan.access, H.HermesAccessCode.OK)
        self.assertTrue(plan.session_exists)
        self.assertEqual(plan.row_count, 3)
        self.assertEqual(plan.candidate_count, 3)
        self.assertEqual(plan.inactive_count, 0)
        self.assertEqual(plan.unknown_columns, 0)
        self.assertEqual(plan.text_chars, 3 * len("synthetic message 0 body"))
        self.assertTrue(plan.schema_known)
        self.assertEqual(plan.schema_version, H.HERMES_SCHEMA_VERSION)
        self.assertTrue(plan.integrity_ok)

    def test_missing_session_is_a_confirmed_absence(self) -> None:
        db, repo, _ = self.store(rows=1)
        outcome = self.read(db, repo, session_id="synthetic-other")
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.SESSION_NOT_FOUND)
        self.assertIs(outcome.access, H.HermesAccessCode.OK)
        self.assertTrue(outcome.plan.available)
        self.assertFalse(outcome.plan.session_exists)
        self.assertEqual(outcome.records_emitted, 0)
        stage = outcome.stage
        assert stage is not None
        self.assertIs(stage.reason, StageDiscardReason.STREAM_INCOMPLETE)
        self.assertEqual(stage.candidate_count, 0)

    def test_empty_session_cannot_verify_identity_and_stays_unconfirmed(self) -> None:
        db, repo, _ = self.store(rows=0)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        # 零候选无法建立记录侧身份：这是「未确认」，不是「无匹配」。
        self.assertIs(outcome.gate, H.HermesGateCode.STAGE_INCOMPLETE)
        self.assertEqual(outcome.records_emitted, 0)


class AuthorizationAxisTests(_Fixture):
    def test_storage_denied_before_any_open(self) -> None:
        db, repo, _ = self.store(rows=2)
        outsider = self.tmp / "outsider.db"
        shutil.copyfile(db, outsider)
        outcome = self.read(db, repo, path=str(outsider))
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.STORAGE_DENIED)
        self.assertIsNone(outcome.stage)
        self.assertFalse(outcome.plan.available)

    def test_wrong_scope_denies_storage_axis(self) -> None:
        db, repo, _ = self.store(rows=2)
        outcome = self.read(db, repo, scope="synthetic-other-scope")
        self.assertIs(outcome.gate, H.HermesGateCode.STORAGE_DENIED)
        self.assertIsNone(outcome.stage)

    def test_directory_instead_of_file_denies_storage_axis(self) -> None:
        db, repo, _ = self.store(rows=2)
        outcome = self.read(db, repo, path=str(repo))
        self.assertIs(outcome.gate, H.HermesGateCode.STORAGE_DENIED)
        self.assertIsNone(outcome.stage)

    def test_no_policy_means_no_candidates(self) -> None:
        db, _repo, _conn = self.store(rows=2)
        outcome = H.run_hermes_session(path=str(db), session_id=SESSION_ID)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.STORAGE_DENIED)
        self.assertIsNone(outcome.stage)

    def test_policy_and_scope_must_be_paired(self) -> None:
        db, repo, _ = self.store(rows=2)
        outcome = H.run_hermes_session(
            path=str(db), session_id=SESSION_ID, policy=_policy_for(db, repo)
        )
        self.assertIs(outcome.gate, H.HermesGateCode.INVALID_ARGUMENT)
        outcome = H.run_hermes_session(
            path=str(db), session_id=SESSION_ID, scope=SCOPE
        )
        self.assertIs(outcome.gate, H.HermesGateCode.INVALID_ARGUMENT)

    def test_attribution_denied_without_any_trusted_evidence(self) -> None:
        db, repo, _conn = self.store(rows=2, cwd=None)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.ATTRIBUTION_DENIED)
        self.assertEqual(outcome.withheld_reasons["project_unusable"], 1)
        self.assertEqual(outcome.withheld_reasons["admit_denied"], 1)
        self.assertEqual(outcome.withheld_reasons["attribution_denied"], 1)
        self.assertEqual(outcome.records_emitted, 0)

    def test_attribution_unmatched_is_a_layer_above_denial(self) -> None:
        second = self.tmp / "repo-b"
        second.mkdir()
        db, repo, _ = self.store(rows=2)
        outcome = self.read(db, repo, policy=_policy_for(db, repo, second=second),
                           project_filter=OTHER_PROJECT)
        self.assertFalse(outcome.complete)
        # 已核对且确定属于另一个项目：零命中层结论，不是「核对失败」。
        self.assertIs(outcome.gate, H.HermesGateCode.ATTRIBUTION_UNMATCHED)
        self.assertEqual(outcome.withheld_reasons["attribution_unmatched"], 0)
        self.assertEqual(outcome.withheld_reasons["project_mismatch"], 1)
        self.assertEqual(outcome.withheld_reasons["admit_denied"], 1)

    def test_attribution_unmatched_for_path_outside_any_root(self) -> None:
        nowhere = str(self.tmp / "not-a-granted-root")
        db, repo, _ = self.store(rows=2, cwd=nowhere)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.ATTRIBUTION_UNMATCHED)
        self.assertEqual(outcome.withheld_reasons["attribution_unmatched"], 1)

    def test_ambiguous_attribution_denies(self) -> None:
        outer = self.tmp / "outer"
        inner = outer / "inner-repo"
        inner.mkdir(parents=True)
        db = self.tmp / "state.db"
        conn = self.writer(create_store(db))
        add_session(conn, SESSION_ID, cwd=str(inner), git_repo_root=str(inner))
        add_message(conn, SESSION_ID, "user", "ambiguous body")
        policy = SessionPolicy(
            scopes=(
                ScopeGrant(
                    scope_id=SCOPE,
                    projects=(
                        ProjectGrant(PROJECT, (CwdRootGrant(str(inner)),)),
                        ProjectGrant(OTHER_PROJECT, (CwdRootGrant(str(outer)),)),
                    ),
                    store_roots=(StoreRootGrant("hermes", str(db)),),
                ),
            )
        )
        outcome = H.run_hermes_session(
            path=str(db),
            session_id=SESSION_ID,
            scope=SCOPE,
            policy=policy,
        )
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.ATTRIBUTION_DENIED)
        self.assertEqual(outcome.withheld_reasons["attribution_ambiguous"], 1)

    def test_caller_admit_can_only_be_stricter(self) -> None:
        db, repo, _ = self.store(rows=2)
        seen: list[str] = []

        def admit(record) -> str:
            seen.append(record.text)
            return "caller refuses"

        outcome = self.read(db, repo, admit=admit)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.ATTRIBUTION_DENIED)
        self.assertEqual(outcome.withheld_reasons["admit_denied"], 1)
        self.assertEqual(seen, ["synthetic message 0 body"])
        self.assertEqual(outcome.records_emitted, 0)

    def test_admit_hook_exception_is_internal_failure(self) -> None:
        db, repo, _ = self.store(rows=2)

        def admit(record):
            raise RuntimeError("path/to/secret leaked in message")

        outcome = self.read(db, repo, admit=admit)
        self.assertIs(outcome.gate, H.HermesGateCode.INTERNAL_FAILURE)
        dumped = json.dumps(outcome.as_public_dict(), ensure_ascii=False)
        self.assertNotIn("secret leaked", dumped)


class LockCorruptionAndSchemaTests(_Fixture):
    def _delete_mode_store(self, name: str = "legacy.db") -> tuple[Path, Path, sqlite3.Connection]:
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        db = self.tmp / name
        conn = self.writer(sqlite3.connect(str(db)))
        conn.execute("PRAGMA journal_mode = delete")
        conn.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        conn.execute("INSERT INTO schema_version VALUES (32)")
        conn.execute(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT NOT NULL,"
            " started_at REAL NOT NULL, ended_at REAL, end_reason TEXT, cwd TEXT,"
            " git_repo_root TEXT, profile_name TEXT, archived INTEGER, hidden INTEGER,"
            " title TEXT, message_count INTEGER)"
        )
        conn.execute(
            "CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT,"
            " tool_call_id TEXT, tool_name TEXT, timestamp REAL NOT NULL,"
            " active INTEGER NOT NULL DEFAULT 1)"
        )
        add_session(conn, SESSION_ID, cwd=str(repo), git_repo_root=str(repo))
        add_message(conn, SESSION_ID, "user", "legacy body")
        return db, repo, conn

    def test_exclusive_writer_lock_reports_locked(self) -> None:
        db, _repo, conn = self._delete_mode_store()
        conn.execute("BEGIN EXCLUSIVE")
        try:
            plan = H.plan_hermes_session(
                path=str(db), session_id=SESSION_ID, busy_timeout_ms=150
            )
        finally:
            conn.rollback()
        self.assertFalse(plan.available)
        self.assertIs(plan.access, H.HermesAccessCode.BUSY)
        self.assertIs(plan.gate, H.HermesGateCode.SOURCE_UNAVAILABLE)
        self.assertEqual(plan.unusable_count, 0)

    def test_locked_run_fails_without_touching_candidates(self) -> None:
        db, repo, conn = self._delete_mode_store()
        conn.execute("BEGIN EXCLUSIVE")
        try:
            outcome = self.read(db, repo, busy_timeout_ms=150)
        finally:
            conn.rollback()
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.access, H.HermesAccessCode.BUSY)
        self.assertIs(outcome.gate, H.HermesGateCode.SOURCE_UNAVAILABLE)
        self.assertEqual(outcome.records_emitted, 0)

    def test_missing_db_file_reports_deleted_during_read(self) -> None:
        repo = self.tmp / "repo"
        repo.mkdir()
        plan = H.plan_hermes_session(path=str(self.tmp / "absent.db"), session_id=SESSION_ID)
        self.assertFalse(plan.available)
        self.assertIs(plan.access, H.HermesAccessCode.DELETED_DURING_READ)

    def test_zero_byte_file_is_unknown_schema(self) -> None:
        empty = self.tmp / "empty.db"
        empty.write_bytes(b"")
        plan = H.plan_hermes_session(path=str(empty), session_id=SESSION_ID)
        self.assertFalse(plan.available)
        self.assertIs(plan.access, H.HermesAccessCode.UNKNOWN_SCHEMA)
        self.assertIsNone(plan.integrity_ok)

    def test_nul_padding_and_mangled_header_are_corrupt(self) -> None:
        nul = self.tmp / "nul.db"
        nul.write_bytes(b"\x00" * 8192)
        plan = H.plan_hermes_session(path=str(nul), session_id=SESSION_ID)
        self.assertIs(plan.access, H.HermesAccessCode.CORRUPT)
        db, _repo, conn = self.store(rows=1)
        conn.close()
        raw = bytearray(db.read_bytes())
        raw[0:16] = b"XXXXXX" + bytes(10)
        db.write_bytes(bytes(raw))
        plan = H.plan_hermes_session(path=str(db), session_id=SESSION_ID)
        self.assertIs(plan.access, H.HermesAccessCode.CORRUPT)
        self.assertIs(plan.gate, H.HermesGateCode.SOURCE_UNAVAILABLE)

    def test_missing_required_column_is_unknown_schema(self) -> None:
        db = self.tmp / "noact.db"
        conn = self.writer(create_store(db, messages_sql=(
            "id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,"
            " role TEXT NOT NULL, content TEXT, tool_call_id TEXT, tool_name TEXT,"
            " timestamp REAL NOT NULL"
        )))
        add_session(conn, SESSION_ID)
        # 本库的 messages 没有 `active` 列：按实际列插入，不借用默认夹具的列形状。
        conn.execute(
            "INSERT INTO messages (session_id, role, content, timestamp)"
            " VALUES (?, 'user', 'body', 1770000000.0)",
            (SESSION_ID,),
        )
        conn.commit()
        plan = H.plan_hermes_session(path=str(db), session_id=SESSION_ID)
        self.assertFalse(plan.available)
        self.assertIs(plan.access, H.HermesAccessCode.UNKNOWN_SCHEMA)

    def test_multiple_or_absent_version_markers_are_unknown_schema(self) -> None:
        db = self.tmp / "two.db"
        conn = self.writer(create_store(db))
        conn.execute("INSERT INTO schema_version VALUES (33)")
        # 只读连接看不到未提交行：必须提交，否则测的是「不可见」而不是「多标记」。
        conn.commit()
        plan = H.plan_hermes_session(path=str(db), session_id=SESSION_ID)
        self.assertIs(plan.access, H.HermesAccessCode.UNKNOWN_SCHEMA)
        self.assertFalse(plan.available)
        other = self.tmp / "nosess.db"
        conn2 = self.writer(create_store(other))
        conn2.execute("DROP TABLE sessions")
        conn2.commit()
        plan = H.plan_hermes_session(path=str(other), session_id=SESSION_ID)
        self.assertIs(plan.access, H.HermesAccessCode.UNKNOWN_SCHEMA)

    def test_old_schema_version_is_unsupported_not_guessed(self) -> None:
        db = self.tmp / "v24.db"
        conn = self.writer(create_store(db, schema_version=24))
        add_session(conn, SESSION_ID)
        plan = H.plan_hermes_session(path=str(db), session_id=SESSION_ID)
        self.assertFalse(plan.available)
        self.assertIs(plan.access, H.HermesAccessCode.SCHEMA_VERSION_UNSUPPORTED)
        self.assertEqual(plan.schema_version, 24)

    def test_extra_columns_are_counted_not_selected(self) -> None:
        db = self.tmp / "extra.db"
        conn = self.writer(
            create_store(
                db,
                extra_session_columns=("mystery_a TEXT",),
                extra_message_columns=("mystery_b INTEGER", "mystery_c TEXT"),
            )
        )
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        add_session(conn, SESSION_ID, cwd=str(repo), git_repo_root=str(repo))
        add_message(conn, SESSION_ID, "user", "known body")
        outcome = self.read(db, repo)
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.plan.unknown_columns, 3)
        self.assertTrue(outcome.plan.schema_known)
        self.assertEqual(outcome.withheld_reasons["unknown_columns"], 3)
        dumped = json.dumps(outcome.as_public_dict(), ensure_ascii=False)
        self.assertNotIn("mystery", dumped)


class RowDegradationTests(_Fixture):
    def _db_with(self, mutate) -> tuple[Path, Path]:
        db = self.tmp / "state.db"
        conn = self.writer(create_store(db))
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        add_session(conn, SESSION_ID, cwd=str(repo), git_repo_root=str(repo))
        mutate(conn)
        # mutate 里的裸 `conn.execute` 不会自动提交；只读连接看不到未提交行，
        # 所以这里统一提交（add_message 自己提交，重复提交无害）。
        conn.commit()
        return db, repo

    def test_tool_rows_skipped_without_breaking_coverage(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", "user body")
            add_message(conn, SESSION_ID, "tool", "tool output body", tool_name="bash")

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.records_emitted, 1)
        self.assertEqual(outcome.withheld_reasons["role_skipped"], 1)
        self.assertFalse(outcome.parse.partial)

    def test_inactive_rows_counted_without_parse_degradation(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", "live body")
            add_message(conn, SESSION_ID, "user", "archived body", active=0)

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.withheld_reasons["inactive_rows"], 1)
        self.assertEqual(outcome.plan.inactive_count, 1)
        self.assertEqual(outcome.records_emitted, 1)

    def test_unrecognized_active_marks_parse_incomplete(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", "live body")
            add_message(conn, SESSION_ID, "user", "weird body", active=2)

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.PARSE_INCOMPLETE)
        self.assertEqual(outcome.withheld_reasons["active_unrecognized"], 1)
        self.assertTrue(outcome.parse.partial)
        self.assertEqual(outcome.records_emitted, 1)

    def test_unknown_role_marks_parse_incomplete(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", "live body")
            add_message(conn, SESSION_ID, "system", "system prompt body")

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.PARSE_INCOMPLETE)
        self.assertEqual(outcome.withheld_reasons["role_unusable"], 1)

    def test_unusable_timestamp_row_is_dropped_and_counted(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", "live body")
            # REAL 亲和列把 '2026-01-01' 折成 2026.0：来源侧存的是**文本时间**，
            # 本模块只认纪元秒区间，因此整行不产出并计数（不回填 1970 冒充事件时间）。
            conn.execute(
                "INSERT INTO messages (session_id, role, content, timestamp, active)"
                " VALUES (?, 'user', 'text stamp body', '2026-01-01', 1)",
                (SESSION_ID,),
            )

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.PARSE_INCOMPLETE)
        self.assertEqual(outcome.withheld_reasons["timestamp_unusable"], 1)
        self.assertEqual(outcome.records_emitted, 1)

    def test_bytes_content_is_unexplainable_shape(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", b"\x00\x01 binary body")
            add_message(conn, SESSION_ID, "user", "live body")

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.withheld_reasons["content_shape"], 1)
        self.assertEqual(outcome.records_emitted, 1)

    def test_empty_content_counted_separately(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", "")
            add_message(conn, SESSION_ID, "assistant", "real body")

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        # 契约（models.NON_PARTIAL_ISSUES 含 NO_TEXT_CONTENT，与 pi 路径的
        # KNOWN_NON_TEXT_BLOCK 同取向）：来源侧已知的空正文是**已知非正文**，
        # 只计数、不使覆盖不完整。因此本次流可以完成。
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.withheld_reasons["content_empty"], 1)
        self.assertEqual(outcome.plan.unusable_count, 1)
        self.assertFalse(outcome.parse.partial)
        self.assertEqual(outcome.records_emitted, 1)

    def test_overlong_content_never_truncated_kept(self) -> None:
        giant = "g" * (H.MAX_ROW_TEXT_CHARS + 1)

        def mutate(conn):
            add_message(conn, SESSION_ID, "user", giant)
            add_message(conn, SESSION_ID, "user", "live body")

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.withheld_reasons["content_overlong"], 1)
        dumped = json.dumps(outcome.as_public_dict(), ensure_ascii=False)
        self.assertNotIn("gggg", dumped)

    def test_unusable_tool_name_is_counted_not_passed(self) -> None:
        def mutate(conn):
            add_message(conn, SESSION_ID, "user", "live body", tool_name=" padded ")

        db, repo = self._db_with(mutate)
        outcome = self.read(db, repo)
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.withheld_reasons["tool_name_unusable"], 1)

    def test_odd_source_value_is_observed_not_filtered(self) -> None:
        db = self.tmp / "state.db"
        conn = self.writer(create_store(db))
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        add_session(conn, SESSION_ID, source="other-runtime", cwd=str(repo),
                    git_repo_root=str(repo))
        add_message(conn, SESSION_ID, "user", "body")
        outcome = self.read(db, repo)
        self.assertEqual(outcome.withheld_reasons["source_hermes_mismatch"], 1)


class LimitTests(_Fixture):
    def test_row_limit_aborts_before_any_body(self) -> None:
        db, repo, conn = self.store(rows=0)
        for index in range(30):
            add_message(conn, SESSION_ID, "user", f"bulk {index}")
        outcome = self.read(db, repo)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.MESSAGE_LIMIT_EXCEEDED)
        self.assertEqual(outcome.rows_read, 0)
        self.assertEqual(outcome.records_emitted, 0)
        self.assertEqual(outcome.withheld_reasons["trailing_rows"], 9)
        self.assertTrue(outcome.plan.available)
        stage = outcome.stage
        assert stage is not None
        self.assertEqual(stage.candidate_count, 0)

    def test_byte_limit_aborts_before_any_body(self) -> None:
        db = self.tmp / "state.db"
        conn = self.writer(create_store(db))
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        add_session(conn, SESSION_ID, cwd=str(repo), git_repo_root=str(repo))
        for index in range(2):
            add_message(conn, SESSION_ID, "user", "x" * 9_000 + f" {index}")
        outcome = self.read(db, repo, max_bytes=30_000)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.BYTE_LIMIT_EXCEEDED)
        self.assertEqual(outcome.rows_read, 0)
        self.assertEqual(outcome.records_emitted, 0)

    def test_stage_byte_rejection_discards_whole_batch(self) -> None:
        db = self.tmp / "state.db"
        conn = self.writer(create_store(db))
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        add_session(conn, SESSION_ID, cwd=str(repo), git_repo_root=str(repo))
        for index in range(2):
            add_message(conn, SESSION_ID, "user", "y" * 600 + f" {index}")
        # 默认按最坏 4 字节/字符折算通过，但真实 utf-8 只有 1 字节/字符：这里用极小
        # max_bytes 让折算也通过是不可能的，因此直接构造预算内候选 > 暂存硬账的场景：
        # 用 rows=2、bytes 恰好容 2 条固定开销但正文预算为 1 字符。
        outcome = self.read(db, repo, max_bytes=24_576 + 8)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.BYTE_LIMIT_EXCEEDED)

    def test_should_stop_is_cancelled_not_unavailable(self) -> None:
        db, repo, _ = self.store(rows=2)
        outcome = self.read(db, repo, should_stop=lambda: True)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.CANCELLED)
        self.assertIs(outcome.access, H.HermesAccessCode.OK)
        self.assertEqual(outcome.records_emitted, 0)

    def test_max_candidates_clamps_rows_and_budget(self) -> None:
        db, repo, _ = self.store(rows=3)
        outcome = self.read(db, repo, max_candidates=2, max_rows=2)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.MESSAGE_LIMIT_EXCEEDED)
        self.assertEqual(outcome.withheld_reasons["trailing_rows"], 1)


class AccountDriftUnitTests(_Fixture):
    """用替身游标直接驱动 `emit` 的行数对账分支。

    真实只读连接里「统计语句」与「取数语句」共享同一语句级快照，并发写不改变游标可见行，
    因此漂移分支无法在合成库里自然复现；这里只替换游标，其余（连接、事实、归属核对）
    都走真实路径——否则第一条记录就会在归属轴被拒（无策略=不放行），根本走不到行数对账。
    """

    class _FakeCursor:
        def __init__(self, rows, error: Exception | None = None) -> None:
            self._rows = list(rows)
            self._error = error

        def fetchmany(self, size: int = -1):
            if self._error is not None:
                raise self._error
            if size < 0:
                size = len(self._rows)
            batch, self._rows = self._rows[:size], self._rows[size:]
            return batch

    def _run(self, db: Path, repo: Path, **overrides: Any) -> H._SessionRun:
        options: dict[str, Any] = {
            "session_id": SESSION_ID,
            "store_path": str(db),
            "scope": SCOPE,
            "policy": _policy_for(db, repo),
            "project_filter": PROJECT,
            "label": "state.db",
            "max_candidates": 8,
            "max_rows": 8,
            "max_bytes": 655_360,
            "max_text_chars": 32_768,
        }
        options.update(overrides)
        run = H._SessionRun(**options)
        run.open(1_000)
        run.probe()
        run.load_facts()
        return run

    def _row(self, row_id: int, text: str) -> tuple:
        return (row_id, SESSION_ID, "user", text, None, None, 1_770_000_000.0)

    def _cursor(self, rows, error: Exception | None = None):
        # cast 只声明本替身满足 emit 依赖的最小游标形状（fetchmany）。
        return cast(H._RowCursor, self._FakeCursor(rows, error=error))

    def test_more_rows_than_stats_reports_unbounded(self) -> None:
        db, repo, _ = self.store(rows=2)
        run = self._run(db, repo)
        gate = run.emit(
            self._cursor([self._row(1, "a"), self._row(2, "b"), self._row(3, "c")]),
            2,
            should_stop=None,
        )
        self.assertIs(gate, H.HermesGateCode.MESSAGE_ROWS_UNBOUNDED)
        self.assertEqual(run._withheld["trailing_rows"], 1)
        run.close()

    def test_fewer_rows_than_stats_reports_short(self) -> None:
        db, repo, _ = self.store(rows=2)
        run = self._run(db, repo)
        gate = run.emit(self._cursor([self._row(1, "a")]), 3, should_stop=None)
        self.assertIs(gate, H.HermesGateCode.MESSAGE_ROWS_SHORT)
        run.close()

    def test_cancel_wins_over_drift_comparison(self) -> None:
        db, repo, _ = self.store(rows=2)
        run = self._run(db, repo)
        gate = run.emit(
            self._cursor([self._row(1, "a"), self._row(2, "b")]),
            9,
            should_stop=lambda: True,
        )
        self.assertIs(gate, H.HermesGateCode.CANCELLED)
        self.assertTrue(run._cancelled)
        run.close()

    def test_fetch_error_classifies_to_source_codes(self) -> None:
        db, repo, _ = self.store(rows=2)
        exc = sqlite3.OperationalError("no such column: fake")
        exc.sqlite_errorcode = 0x01
        run = self._run(db, repo)
        gate = run.emit(self._cursor([], error=exc), 1, should_stop=None)
        self.assertIs(gate, H.HermesGateCode.SOURCE_UNAVAILABLE)
        self.assertIs(run._access, H.HermesAccessCode.UNKNOWN_SCHEMA)
        run.close()

        busy = sqlite3.OperationalError("database is locked")
        busy.sqlite_errorcode = 0x05
        run2 = self._run(db, repo)
        gate2 = run2.emit(self._cursor([], error=busy), 1, should_stop=None)
        self.assertIs(gate2, H.HermesGateCode.SOURCE_UNAVAILABLE)
        self.assertIs(run2._access, H.HermesAccessCode.BUSY)
        run2.close()

    def test_stage_rejection_propagates_gate(self) -> None:
        db, repo, _ = self.store(rows=2)
        run = self._run(db, repo, max_candidates=1)
        # 两条可用行 + 候选上限 1：第二条由暂存层整批拒绝（归属核对通过，所以拒因落在
        # 暂存层而不是准入轴上）。
        gate = run.emit(
            self._cursor([self._row(1, "a"), self._row(2, "b")]),
            2,
            should_stop=None,
        )
        self.assertIs(gate, H.HermesGateCode.STAGE_REJECTED)
        run.close()


class PublicationBoundaryTests(_Fixture):
    def test_capture_refusal_discards_batch_as_stage_rejected(self) -> None:
        # 核验通过后的**外递**首拒：这翻的是发布/外递终态（`complete=False`、
        # `gate=stage_rejected`），**不反向改写**暂存核对快照——那批候选当时确实通过了核对。
        # 依据 05 DES-API-01「发布失败时诊断量可非零而 `returned_count`、`results` 必须为零
        # （整批拒绝，不发布前缀）」——公开结果/分层计数侧；09:281 同势参照，两者均不证明回调前缀可回滚。
        # 「整批丢弃」指的是缓冲里未递出的正文整批清空、公开结果不含任何正文，不是把快照归零。
        db, repo, _ = self.store(rows=2)
        calls: list[str] = []

        def capture(record):
            calls.append(record.text)
            return "output side refuses"

        outcome = self.read(db, repo, capture=capture)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.STAGE_REJECTED)
        # 首拒即停：只递到第一条，第二条随缓冲一起丢弃、不再外递。
        self.assertEqual(calls, ["synthetic message 0 body"])
        stage = outcome.stage
        assert stage is not None
        # 核对快照保留（两条都已核验），核对通过后的清空不计入 dropped_count。
        self.assertTrue(stage.complete)
        self.assertEqual(stage.candidate_count, 2)
        self.assertEqual(stage.dropped_count, 0)
        # 发布可见结果不含任何候选正文（整棵公开字典做 JSON 全文扫描）。
        dumped = json.dumps(outcome.as_public_dict())
        for index in range(2):
            self.assertNotIn(f"synthetic message {index} body", dumped)

    def test_capture_refusal_after_accepted_prefix_keeps_clean_hermes_outcome(self) -> None:
        # 首拒即停，断言的是 **Hermes 自身终态干净**，不是外部收集器被回滚：
        #   1. 外递循环在首拒处停下，被拒记录之后的候选正文一律不再外递，未递出的剩余候选
        #      随缓冲整批清空（本模块终态零正文）；
        #   2. stage 快照按核对点冻结，事后外递失败不回改 candidate_count/staged_bytes/dropped_count。
        # 首条被拒前 capture 已逐条收到过的那些正文（calls 里的前缀）属于调用方一侧已发生的
        # 事实，本模块无法撤销——所以 calls 断言照旧记录已发生的调用，不声称它被回滚；
        # 「整批或零条」需收集器自己保证（另见 test_snippet_collector_clears_accepted_prefix_on_refusal）。
        db, repo, _ = self.store(rows=3)
        calls: list[str] = []

        def capture(record):
            calls.append(record.text)
            if record.text == "synthetic message 1 body":
                return "output side refuses"
            return None

        outcome = self.read(db, repo, capture=capture)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.STAGE_REJECTED)
        # 停在首拒：第三条正文从未递出（缓冲被清空），前两条各递一次。
        self.assertEqual(calls, ["synthetic message 0 body", "synthetic message 1 body"])
        self.assertNotIn("synthetic message 2 body", calls)
        stage = outcome.stage
        assert stage is not None
        # 三条都在核验阶段通过，快照按核对点保留；事后清空不记入 dropped_count。
        self.assertTrue(stage.complete)
        self.assertEqual(stage.candidate_count, 3)
        self.assertEqual(stage.dropped_count, 0)
        # 快照冻结的另一半证据：`staged_bytes` 与同一会话**不带 capture** 的那一趟逐字相同，
        # 说明事后外拒没有重算冻结快照（核对点已定的量不被改写；下界=每条固定扣账额度）。
        baseline = self.read(db, repo)
        # 基准趟必须自己就是完整的，否则「两趟相等」会退化成「两边都是 0」。
        self.assertTrue(baseline.complete)
        assert baseline.stage is not None
        self.assertEqual(
            stage.staged_bytes,
            baseline.stage.staged_bytes,
        )
        self.assertGreaterEqual(
            stage.staged_bytes, 3 * PER_RECORD_FIXED_OVERHEAD_BYTES
        )
        dumped = json.dumps(outcome.as_public_dict())
        for index in range(3):
            self.assertNotIn(f"synthetic message {index} body", dumped)

    def test_capture_exception_after_accepted_prefix_is_internal_failure(self) -> None:
        # 已接受前缀之后钩子抛异常：终态固定为 `internal_failure`，异常文本绝不外传，
        # 被抛记录之后的候选正文一律不再外递（与拒绝路径同一「首错即停、缓冲清空」方向）。
        db, repo, _ = self.store(rows=3)
        calls: list[str] = []

        def capture(record):
            calls.append(record.text)
            if record.text == "synthetic message 1 body":
                raise ValueError("/private/path leaked into exception")
            return None

        outcome = self.read(db, repo, capture=capture)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.INTERNAL_FAILURE)
        self.assertEqual(calls, ["synthetic message 0 body", "synthetic message 1 body"])
        self.assertNotIn("synthetic message 2 body", calls)
        dumped = json.dumps(outcome.as_public_dict())
        self.assertNotIn("/private/path", dumped)
        for index in range(3):
            self.assertNotIn(f"synthetic message {index} body", dumped)

    def test_snippet_collector_clears_accepted_prefix_on_refusal(self) -> None:
        # 采集器（`capture=collector.collect`）在条数上限处首拒：`_fail` 会连同**已接受的前缀**
        # 一起清空内部候选，所以发布出口既拿不到被拒记录、也拿不到此前那一条——无任何前缀泄漏。
        # 暂存核对快照仍保留三条（核对发生在外递之前，采集器拒绝属事后失败，不回改核对结论）。
        db, repo, _ = self.store(rows=3)
        collector = SnippetCollector(source="hermes", max_snippets=1)
        outcome = self.read(db, repo, capture=collector.collect)
        self.assertFalse(outcome.complete)
        self.assertIs(outcome.gate, H.HermesGateCode.STAGE_REJECTED)
        self.assertEqual(collector.count, 0)
        self.assertEqual(collector.total_chars, 0)
        self.assertIs(collector.refusal, PublicationRefusal.SNIPPET_LIMIT_EXCEEDED)
        self.assertEqual(collector.release(confirmed=True), ())
        stage = outcome.stage
        assert stage is not None
        self.assertTrue(stage.complete)
        self.assertEqual(stage.candidate_count, 3)
        self.assertEqual(stage.dropped_count, 0)
        dumped = json.dumps(outcome.as_public_dict())
        for index in range(3):
            self.assertNotIn(f"synthetic message {index} body", dumped)

    def test_capture_exception_is_internal_failure(self) -> None:
        db, repo, _ = self.store(rows=2)

        def capture(record):
            raise ValueError("/private/path in message")

        outcome = self.read(db, repo, capture=capture)
        self.assertIs(outcome.gate, H.HermesGateCode.INTERNAL_FAILURE)
        self.assertNotIn("/private/path", json.dumps(outcome.as_public_dict()))

    def test_snippet_collector_sees_redacted_bodies_only(self) -> None:
        db = self.tmp / "state.db"
        conn = self.writer(create_store(db))
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        add_session(conn, SESSION_ID, cwd=str(repo), git_repo_root=str(repo))
        add_message(conn, SESSION_ID, "user", "please use api_key sk-abcdefghijklmnopqrstuvwxyz012345")
        add_message(conn, SESSION_ID, "assistant", "nothing sensitive here")
        collector = SnippetCollector(source="hermes")
        outcome = self.read(db, repo, capture=collector.collect)
        self.assertTrue(outcome.complete)
        self.assertFalse(outcome.publication_allowed)
        # collector 是**一次性生命周期**：未确证即终局拒绝，后续任何 release 都返回空。
        # 因此「未确证」另开一个 collector 断言，不在同一个上先拒再取。
        denied = SnippetCollector(source="hermes")
        self.assertEqual(self.read(db, repo, capture=denied.collect).gate, H.HermesGateCode.OK)
        self.assertEqual(denied.release(confirmed=False), ())
        self.assertEqual(denied.release(confirmed=True), ())

        snippets = collector.release(confirmed=True)
        self.assertEqual(len(snippets), 2)
        joined = " ".join(snippet.snippet for snippet in snippets)
        self.assertIn("[redacted]", joined)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", joined)
        self.assertEqual({snippet.line_no for snippet in snippets}, {1, 2})
        self.assertEqual({snippet.source for snippet in snippets}, {"hermes"})

    def test_closed_collector_refuses_after_release(self) -> None:
        db, repo, _ = self.store(rows=2)
        collector = SnippetCollector(source="hermes")
        outcome = self.read(db, repo, capture=collector.collect)
        self.assertTrue(outcome.complete)
        collector.release(confirmed=True)
        second = self.read(db, repo, capture=collector.collect)
        self.assertFalse(second.complete)
        self.assertIs(second.gate, H.HermesGateCode.STAGE_REJECTED)

    def test_discarded_collector_refuses_capture(self) -> None:
        db, repo, _ = self.store(rows=2)
        collector = SnippetCollector(source="hermes")
        collector.discard(PublicationRefusal.RECORD_UNUSABLE)
        outcome = self.read(db, repo, capture=collector.collect)
        self.assertIs(outcome.gate, H.HermesGateCode.STAGE_REJECTED)
        self.assertEqual(collector.count, 0)


class ArgumentShapeTests(_Fixture):
    def test_bad_shapes_are_invalid_argument_without_opening(self) -> None:
        db, repo, _ = self.store(rows=1)
        for bad in (None, "", " ", "x" * (H.MAX_ID_CHARS + 1), 5, SESSION_ID + " "):
            outcome = self.read(db, repo, session_id=bad)
            self.assertIs(outcome.gate, H.HermesGateCode.INVALID_ARGUMENT, bad)
            self.assertIsNone(outcome.stage)
        for bad_path in (None, "", "q?x.db", "frag#1.db", "nul\x00.db", 42):
            outcome = self.read(db, repo, path=bad_path)
            self.assertIs(outcome.gate, H.HermesGateCode.INVALID_ARGUMENT, bad_path)
        outcome = self.read(db, repo, busy_timeout_ms=50)
        self.assertIs(outcome.gate, H.HermesGateCode.INVALID_ARGUMENT)
        outcome = self.read(db, repo, max_bytes=True)
        self.assertIs(outcome.gate, H.HermesGateCode.INVALID_ARGUMENT)
        outcome = self.read(db, repo, max_rows=0)
        self.assertIs(outcome.gate, H.HermesGateCode.INVALID_ARGUMENT)

    def test_plan_entry_also_refuses_bad_shapes(self) -> None:
        plan = H.plan_hermes_session(path=None, session_id=SESSION_ID)
        self.assertIs(plan.gate, H.HermesGateCode.INVALID_ARGUMENT)
        plan = H.plan_hermes_session(path="a?b.db", session_id=SESSION_ID)
        self.assertIs(plan.gate, H.HermesGateCode.INVALID_ARGUMENT)


class LabelTests(_Fixture):
    def test_untrusted_db_name_degrades_to_fixed_label(self) -> None:
        label, degraded = H._db_stream_label("bad name\u00e9.db")
        self.assertEqual(label, "redacted-stream")
        self.assertTrue(degraded)
        label, degraded = H._db_stream_label("state.db")
        self.assertEqual(label, "state.db")
        self.assertFalse(degraded)

    def test_run_with_odd_name_counts_label_unusable(self) -> None:
        repo = self.tmp / "repo"
        repo.mkdir(parents=True, exist_ok=True)
        db = self.tmp / "state odd!.db"
        conn = self.writer(create_store(db))
        add_session(conn, SESSION_ID, cwd=str(repo), git_repo_root=str(repo))
        add_message(conn, SESSION_ID, "user", "body")
        outcome = self.read(db, repo)
        self.assertTrue(outcome.complete)
        self.assertEqual(outcome.withheld_reasons["label_unusable"], 1)


if __name__ == "__main__":
    unittest.main()
