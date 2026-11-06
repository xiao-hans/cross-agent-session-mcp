"""Synthetic end-to-end checks for the fixed-path Pi query coordinator.

These tests create temporary, synthetic JSONL records only; they never inspect real session data
or load user configuration.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from mcp.server.mcpserver.exceptions import ToolError

from cross_agent_session_mcp.file_search import (
    COVERAGE_SCOPE_FILE,
    COVERAGE_SCOPE_NONE,
    PiFileFailureCategory,
    PiFileSearchService,
    PiFileStageReached,
)
from cross_agent_session_mcp.policy import (
    CwdRootGrant,
    PolicyDenied,
    ProjectGrant,
    RefusalCode,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.publication import PublicationRefusal
from cross_agent_session_mcp.query import (
    FilterErrorCode,
    QueryRejectionReason,
    scan_filter,
)
from cross_agent_session_mcp.redaction import MAX_OUTPUT_CHARS
from cross_agent_session_mcp.safe_reader import ReadStop, SafeReadDenied
from cross_agent_session_mcp.server import bind_pi_file_search_service
from cross_agent_session_mcp.session_pipeline import StageDiscardReason

SCOPE = "synthetic-scope"
SESSION_ID = "synthetic-session"
PROJECT = "synthetic-project"
TIMESTAMP = "2026-03-01T10:30:00Z"


def _write_session(
    path: Path, cwd: Path, *, text: str, session_id: str = SESSION_ID
) -> None:
    header = {
        "type": "session",
        "version": "1",
        "cwd": str(cwd),
        "id": session_id,
    }
    message = {
        "type": "message",
        "message": {
            "role": "user",
            "timestamp": TIMESTAMP,
            "content": [{"type": "input_text", "text": text}],
        },
    }
    path.write_text(
        "\n".join((json.dumps(header), json.dumps(message))) + "\n",
        encoding="utf-8",
    )


def _write_multi(
    path: Path,
    cwd: Path,
    *,
    text: str,
    count: int,
    session_id: str = SESSION_ID,
    role: str = "user",
) -> None:
    """Write one header plus `count` distinct-timestamp messages to the same session."""
    rows: list[dict[str, Any]] = [
        {"type": "session", "version": "1", "cwd": str(cwd), "id": session_id},
    ]
    for index in range(count):
        rows.append(
            {
                "type": "message",
                "message": {
                    "role": role,
                    "timestamp": f"2026-03-01T10:{index:02d}:00Z",
                    "content": [{"type": "input_text", "text": text}],
                },
            }
        )
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )


def _policy(repo: Path, store: Path) -> SessionPolicy:
    return SessionPolicy(
        scopes=(
            ScopeGrant(
                scope_id=SCOPE,
                projects=(ProjectGrant(PROJECT, (CwdRootGrant(str(repo)),)),),
                store_roots=(StoreRootGrant("pi", str(store)),),
            ),
        )
    )


class TestResultBoundaryVocabulary(unittest.TestCase):
    """① Only closed-form identifiers and sanitizer-backed locations may leave the file."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pi-file-boundary-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.store = self.root / "store"
        self.repo.mkdir()
        self.store.mkdir()
        self.policy = _policy(self.repo, self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _service(self, name: str, *, header_id: str, asserted_id: str | None = None):
        path = self.store / name
        _write_session(path, self.repo, text="a synthetic needle", session_id=header_id)
        return PiFileSearchService(
            policy=self.policy,
            scope=SCOPE,
            path=str(path),
            session_id=asserted_id if asserted_id is not None else header_id,
        )

    def test_path_shaped_session_id_is_withheld_not_published(self) -> None:
        """A session that stores a path where an ID belongs publishes null, never the path."""
        leaky_id = "C:/Users/BOB/private/dir"
        service = self._service("leaky.jsonl", header_id=leaky_id)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        self.assertEqual(result["results"][0]["session_id"], None)
        self.assertNotIn(leaky_id, json.dumps(result))
        self.assertNotIn("BOB", json.dumps(result))
        self.assertTrue(result["partial"])
        self.assertFalse(result["complete"])
        row = result["coverage"][0]
        self.assertIn("metadata_withheld", row["filter_errors"])
        self.assertTrue(row["partial"])
        # The snippet itself is still a redacted, complete row: only the identifier is withheld.
        self.assertEqual(result["returned_count"], 1)
        self.assertEqual(row["status"], "searched")

    def test_free_text_role_is_withheld(self) -> None:
        """Whitespace- or separator-bearing identifier values cannot cross as identifiers."""
        for index, candidate in enumerate(("user /srv/data", "user:admin", "\\\\srv\\share", "a b")):
            with self.subTest(candidate=candidate):
                path = self.store / f"role-{index}.jsonl"
                _write_session(
                    path, self.repo, text="a synthetic needle", session_id=candidate
                )
                service = PiFileSearchService(
                    policy=self.policy,
                    scope=SCOPE,
                    path=str(path),
                    session_id=candidate,
                )
                result = service.search(scope=SCOPE, query="needle", sources=["pi"])
                self.assertEqual(result["results"][0]["session_id"], None)
                self.assertNotIn(candidate, json.dumps(result))
                self.assertIn("metadata_withheld", result["coverage"][0]["filter_errors"])

    def test_location_is_always_a_sanitize_backed_reference(self) -> None:
        """已发布行的 `location` 只能是账本发放的不透明引用：行号/流标签/路径不外出。"""
        service = self._service("loc.jsonl", header_id=SESSION_ID)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        location = result["results"][0]["location"]
        self.assertRegex(location, r"\Actxref:[A-Za-z0-9_-]{1,120}\Z")
        self.assertNotIn("jsonl:", json.dumps(result))
        self.assertNotIn("#L", json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_all_published_fields_are_closed_vocabulary(self) -> None:
        """Every non-snippet string in a row comes from a fixed set or a policy/identifier gate."""
        service = self._service("vocab.jsonl", header_id=SESSION_ID)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        row = result["results"][0]
        self.assertEqual(row["source"], "pi")
        self.assertEqual(row["role"], "user")
        self.assertIsNone(row["executor"])
        self.assertEqual(row["project"], PROJECT)
        self.assertEqual(row["time_quality"], "exact")
        self.assertEqual(row["project_quality"], "trusted_header_cwd")
        self.assertNotIn("line_no", row)
        self.assertNotIn("ordinal", row)
        self.assertIsInstance(row["redacted_count"], int)
        self.assertIsInstance(row["redacted_count"], int)
        self.assertIsInstance(row["snippet_truncated"], bool)
        self.assertEqual(set(row), set(_ROW_KEYS))


class TestFileLevelCoverageScope(unittest.TestCase):
    """② A complete scan proves this one approved file, never the whole `pi` source."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pi-file-scope-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.store = self.root / "store"
        self.repo.mkdir()
        self.store.mkdir()
        self.session_file = self.store / "session.jsonl"
        _write_session(self.session_file, self.repo, text="a synthetic needle")
        self.service = PiFileSearchService(
            policy=_policy(self.repo, self.store),
            scope=SCOPE,
            path=str(self.session_file),
            session_id=SESSION_ID,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _assert_file_scope(self, result: dict[str, Any]) -> None:
        self.assertEqual(result["coverage_scope"], "single_approved_file")
        for row in result["coverage"]:
            self.assertEqual(row["coverage_scope"], "single_approved_file")
            self.assertIn("单个已批准文件", row["reason"])

    def test_every_row_declares_file_scope(self) -> None:
        with self.subTest(case="matched"):
            self._assert_file_scope(
                self.service.search(scope=SCOPE, query="needle", sources=["pi"])
            )
        with self.subTest(case="empty"):
            self._assert_file_scope(
                self.service.search(
                    scope=SCOPE,
                    start="2026-03-02T00:00:00Z",
                    end="2026-03-03T00:00:00Z",
                )
            )
        with self.subTest(case="gate-failure"):
            with self.session_file.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "type": "session",
                            "version": "1",
                            "cwd": str(self.repo),
                            "id": "different-synthetic-session",
                        }
                    )
                    + "\n"
                )
            self._assert_file_scope(
                self.service.search(scope=SCOPE, query="needle", sources=["pi"])
            )

    def test_no_match_never_claims_source_level_completion(self) -> None:
        result = self.service.search(
            scope=SCOPE,
            start="2026-03-02T00:00:00Z",
            end="2026-03-03T00:00:00Z",
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["coverage"][0]["status"], "no_match")
        # File-level proof, stated as such: the reason must not read as "pi source has no match".
        reason = result["coverage"][0]["reason"]
        self.assertNotIn("整个 pi 来源", reason.replace("不声明整个 pi 来源已扫完", ""))
        self.assertIn("不声明整个 pi 来源已扫完", reason)
        # The outcome vocabulary never offers a source-level completion claim.
        self.assertNotIn("source_complete", result)

    def test_named_but_unserved_sources_are_none_scope_unsupported(self) -> None:
        result = self.service.search(scope=SCOPE, query="needle", sources=["hermes", "pi"])
        rows = {row["source"]: row for row in result["coverage"]}
        self.assertEqual(rows["hermes"]["status"], "unsupported")
        self.assertEqual(rows["hermes"]["coverage_scope"], "none")
        self.assertTrue(rows["hermes"]["partial"])
        self.assertEqual(rows["pi"]["coverage_scope"], "single_approved_file")
        # An unserved source named alongside pi keeps the whole outcome partial: the request was
        # never satisfied at source level.
        self.assertTrue(result["partial"])
        self.assertFalse(result["complete"])

    def test_requests_without_pi_have_no_file_scope_at_all(self) -> None:
        result = self.service.search(scope=SCOPE, query="needle", sources=["codex"])
        self.assertEqual(result["coverage_scope"], "none")
        self.assertEqual(result["stage_reached"], "coordinator")
        self.assertEqual(result["reason"], "source_unsupported")
        self.assertTrue(all(row["coverage_scope"] == "none" for row in result["coverage"]))

    def test_scope_mismatch_is_none_scope_and_rejected(self) -> None:
        result = self.service.search(scope="other-scope", query="needle")
        self.assertTrue(result["rejected"])
        self.assertEqual(result["coverage_scope"], "none")
        self.assertEqual(result["reason"], "scope_mismatch")
        self.assertEqual(result["coverage"], [])


class TestLayeredCounters(unittest.TestCase):
    """③ Read/parse/stage/filter progress stays distinguishable when a gate fails."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pi-file-layers-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.store = self.root / "store"
        self.repo.mkdir()
        self.store.mkdir()
        self.session_file = self.store / "conflict.jsonl"
        _write_session(self.session_file, self.repo, text="a synthetic needle")
        with self.session_file.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "type": "session",
                        "version": "1",
                        "cwd": str(self.repo),
                        "id": "different-synthetic-session",
                    }
                )
                + "\n"
            )
        self.service = PiFileSearchService(
            policy=_policy(self.repo, self.store),
            scope=SCOPE,
            path=str(self.session_file),
            session_id=SESSION_ID,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_gate_failure_still_reports_lines_read_and_records_parsed(self) -> None:
        result = self.service.search(scope=SCOPE, query="needle", sources=["pi"])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["stage_reached"], "file_pipeline")
        self.assertEqual(result["reason"], "file_incomplete")
        self.assertEqual(result["failure_category"], "file_incomplete")
        self.assertEqual(result["records_withheld"], 1)
        row = result["coverage"][0]
        self.assertEqual(row["status"], "incomplete")
        # Filter layer: judged nothing, so its counters are zero.
        self.assertEqual(row["records_scanned"], 0)
        self.assertEqual(row["scan_chars"], 0)
        self.assertEqual(row["matched_count"], 0)
        self.assertEqual(row["skipped_count"], result["skipped_records"])
        # File layer: the run really read the file and really parsed one record.
        read = result["file"]["read"]
        self.assertEqual(read["lines_read"], 3)
        self.assertTrue(read["eof_reached"])
        self.assertEqual(result["file"]["pipeline"]["parse"]["records_emitted"], 1)
        self.assertEqual(result["file"]["pipeline"]["stage"]["dropped_count"], 1)
        # The reason text distinguishes the two layers instead of claiming "nothing scanned".
        self.assertIn("查询过滤层未判定", row["reason"])
        self.assertIn("不表示文件未被读取", row["reason"])

    def test_gate_failure_filter_errors_stay_closed_enums(self) -> None:
        result = self.service.search(scope=SCOPE, query="needle", sources=["pi"])
        row = result["coverage"][0]
        self.assertEqual(row["filter_errors"][0], "file_incomplete")
        self.assertIn("stream_incomplete", row["filter_errors"])
        serialized = json.dumps(result)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("synthetic needle", serialized)
        self.assertNotIn(SESSION_ID, serialized)

    def test_internal_failure_keeps_file_snapshot_and_stage(self) -> None:
        """An unexpected failure must not erase the layered counters or leak details."""
        import cross_agent_session_mcp.file_search as module

        # A file that passes every gate: the crash is injected after the pipeline returned a
        # complete conclusion, so the layered `file` snapshot must survive into the outcome.
        clean_file = self.store / "clean.jsonl"
        _write_session(clean_file, self.repo, text="a synthetic needle")
        service = PiFileSearchService(
            policy=_policy(self.repo, self.store),
            scope=SCOPE,
            path=str(clean_file),
            session_id=SESSION_ID,
        )
        original = module.scan_filter

        def explode_after_preflight(*args: Any, **kwargs: Any) -> Any:
            """Fail only the real scan over captured candidates, not the empty preflight."""
            if args and isinstance(args[0], (list, tuple)) and args[0]:
                raise RuntimeError("detail /secret/path")
            return original(*args, **kwargs)

        module.scan_filter = explode_after_preflight  # type: ignore[assignment]
        try:
            result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        finally:
            module.scan_filter = original
        self.assertEqual(result["reason"], "internal_failure")
        self.assertEqual(result["failure_category"], "internal_failure")
        # The file pipeline really completed and reported its own counts before the crash.
        self.assertEqual(result["stage_reached"], "filter")
        self.assertEqual(result["coverage_scope"], "single_approved_file")
        self.assertTrue(result["partial"])
        self.assertEqual(result["results"], [])
        self.assertIsNotNone(result["file"])
        # The file layer really finished: its own counters stay readable, so this is not
        # reportable as "nothing was scanned".
        self.assertTrue(result["file"]["complete"])
        self.assertEqual(result["file"]["read"]["lines_read"], 2)
        self.assertEqual(result["records_withheld"], 1)
        self.assertEqual(result["coverage"][0]["filter_errors"][0], "internal_failure")
        self.assertNotIn("/secret/path", json.dumps(result))
        self.assertNotIn("RuntimeError", json.dumps(result))

    def test_failure_before_the_file_pipeline_reports_none_scope(self) -> None:
        """A crash in filter pre-validation never reads as "the file was scanned"."""
        import cross_agent_session_mcp.file_search as module

        def explode(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("detail /secret/path")

        original = module.scan_filter
        module.scan_filter = explode  # type: ignore[assignment]
        try:
            result = self.service.search(scope=SCOPE, query="needle", sources=["pi"])
        finally:
            module.scan_filter = original
        self.assertEqual(result["reason"], "internal_failure")
        self.assertEqual(result["stage_reached"], "coordinator")
        self.assertEqual(result["coverage_scope"], "none")
        self.assertIsNone(result["file"])
        self.assertEqual(result["records_withheld"], 0)
        self.assertEqual(result["coverage"][0]["coverage_scope"], "none")
        self.assertNotIn("/secret/path", json.dumps(result))


class TestBudgetAndMatchVsReturn(unittest.TestCase):
    """④⑤ Output-budget refusal is whole-batch, and matching is never publishing."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pi-file-budget-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.store = self.root / "store"
        self.repo.mkdir()
        self.store.mkdir()
        self.policy = _policy(self.repo, self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _service(self, name: str, *, text: str, count: int) -> PiFileSearchService:
        path = self.store / name
        _write_multi(path, self.repo, text=text, count=count)
        return PiFileSearchService(
            policy=self.policy, scope=SCOPE, path=str(path), session_id=SESSION_ID
        )

    def test_total_char_budget_refuses_the_whole_batch_with_exact_reason(self) -> None:
        service = self._service("chars.jsonl", text="needle " + ("z" * 5000), count=12)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["returned_count"], 0)
        self.assertEqual(result["reason"], "publication_failed")
        self.assertEqual(result["failure_category"], "snippet_total_chars_limit")
        self.assertEqual(result["stage_reached"], "publication")
        row = result["coverage"][0]
        self.assertEqual(row["status"], "error")
        self.assertIn("snippet_total_chars_limit", row["filter_errors"])
        self.assertIn("总字符数", row["reason"])
        # Budget refusal is not truncation: nothing was emitted, so no prefix exists.
        self.assertFalse(result["truncated"])
        self.assertEqual(result["records_withheld"], 12)

    def test_matched_count_stays_visible_while_returned_count_is_zero(self) -> None:
        service = self._service("diag.jsonl", text="needle " + ("z" * 5000), count=12)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        self.assertEqual(result["total_matched"], 12)
        self.assertEqual(result["coverage"][0]["matched_count"], 12)
        self.assertEqual(result["coverage"][0]["returned_count"], 0)
        self.assertEqual(result["returned_count"], 0)
        self.assertTrue(result["partial"])
        self.assertFalse(result["complete"])
        # The refusal vocabulary is closed: a data-side string can never become a reason code.
        self.assertIn(result["reason"], _REASON_VOCABULARY)
        self.assertIn(result["failure_category"], _REFUSAL_VOCABULARY)

    def test_result_limit_reports_matched_more_than_returned(self) -> None:
        service = self._service("limit.jsonl", text="needle body", count=3)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"], limit=1)
        self.assertEqual(result["total_matched"], 3)
        self.assertEqual(result["returned_count"], 1)
        self.assertTrue(result["truncated"])
        self.assertTrue(result["partial"])
        row = result["coverage"][0]
        self.assertEqual(row["matched_count"], 3)
        self.assertEqual(row["returned_count"], 1)
        self.assertIn("result_truncated", row["filter_errors"])

    def test_per_file_snippet_cap_is_reported_not_silently_dropped(self) -> None:
        service = self._service("cap.jsonl", text="needle body", count=20)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"], limit=20)
        self.assertLessEqual(result["returned_count"], 16)
        self.assertEqual(result["total_matched"], 20)
        self.assertTrue(result["truncated"])

    def test_redaction_output_truncation_is_its_own_channel(self) -> None:
        """遮蔽层按输出上限截片不等于预算整批拒绝：一条外出、不触限、但记不完整。"""
        service = self._service(
            "trunc.jsonl", text="needle " + ("y" * (MAX_OUTPUT_CHARS + 300)), count=1
        )
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        self.assertEqual(result["returned_count"], 1)
        self.assertEqual(result["failure_category"], None)
        self.assertNotEqual(result["reason"], "publication_failed")
        row = result["results"][0]
        self.assertEqual(len(row["snippet"]), MAX_OUTPUT_CHARS)
        self.assertTrue(row["snippet_truncated"])
        # 片段侧截断会同时抬升 outcome.truncated（结果侧截断与预算拒绝是两个通道）。
        self.assertTrue(result["truncated"])
        self.assertTrue(result["partial"])
        self.assertFalse(result["complete"])
        cover = result["coverage"][0]
        self.assertIn("snippet_output_truncated", cover["filter_errors"])
        self.assertNotIn("snippet_total_chars_limit", cover["filter_errors"])
        self.assertIn("按输出上限截断", cover["reason"])

    def test_metadata_gate_does_not_disturb_the_normal_row(self) -> None:
        """The ordinary path keeps real identifier/role values and adds no withheld marker."""
        service = self._service("normal.jsonl", text="needle body", count=1)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        row = result["results"][0]
        self.assertEqual(row["session_id"], SESSION_ID)
        self.assertEqual(row["role"], "user")
        self.assertRegex(row["location"], r"\Actxref:[A-Za-z0-9_-]{1,120}\Z")
        self.assertFalse(result["partial"])
        self.assertEqual(result["coverage"][0]["filter_errors"], [])

    def test_closed_join_failures_keep_their_exact_category(self) -> None:
        """Wiring mismatches are distinct categories, not a generic publication failure."""
        import dataclasses

        import cross_agent_session_mcp.file_search as module

        service = self._service("join.jsonl", text="needle body", count=2)

        def search_with_double() -> dict[str, Any]:
            return service.search(scope=SCOPE, query="needle", sources=["pi"])

        with self.subTest(case="match_join"):
            original_scan = module.scan_filter

            def out_of_range(*args: Any, **kwargs: Any) -> Any:
                outcome = original_scan(*args, **kwargs)
                candidates = args[0] if args else kwargs.get("records")
                if outcome.rejected or not outcome.matches or not candidates:
                    return outcome
                first = dataclasses.replace(
                    outcome.matches[0], record_index=len(candidates) + 5
                )
                return dataclasses.replace(
                    outcome, matches=(first,) + outcome.matches[1:]
                )

            module.scan_filter = out_of_range  # type: ignore[assignment]
            try:
                result = search_with_double()
            finally:
                module.scan_filter = original_scan  # type: ignore[assignment]
            self.assertEqual(result["results"], [])
            self.assertEqual(result["failure_category"], "match_join_failed")
            self.assertIn("match_join_failed", result["coverage"][0]["filter_errors"])

        with self.subTest(case="snippet_join"):
            original_collector = module.SnippetCollector

            class ShortCollector:
                """Collector stand-in that releases fewer snippets than matched."""

                def __init__(self, **_kwargs: Any) -> None:
                    self._rows: list[Any] = []

                def collect(self, record: Any) -> Any:
                    self._rows.append(record)
                    return None

                def release(self, *, confirmed: bool) -> tuple[Any, ...]:
                    if not confirmed:
                        return ()
                    return tuple(self._rows[:1])

                def discard(self, _reason: Any) -> None:
                    self._rows = []

            module.SnippetCollector = ShortCollector  # type: ignore[assignment]
            try:
                result = search_with_double()
            finally:
                module.SnippetCollector = original_collector  # type: ignore[assignment]
            self.assertEqual(result["results"], [])
            self.assertEqual(result["returned_count"], 0)
            self.assertEqual(result["reason"], "publication_failed")
            self.assertEqual(result["failure_category"], "snippet_join_failed")
            self.assertIn(result["failure_category"], _REFUSAL_VOCABULARY)
            self.assertEqual(result["stage_reached"], "publication")
            self.assertIn(
                result["failure_category"], result["coverage"][0]["filter_errors"]
            )

    def test_publication_diagnostics_do_not_imply_publication(self) -> None:
        """A non-zero match count alone must never be readable as "results were returned"."""
        service = self._service("wording.jsonl", text="needle " + ("z" * 5000), count=12)
        result = service.search(scope=SCOPE, query="needle", sources=["pi"])
        self.assertTrue(result["complete"] is False)
        self.assertNotIn("已发布", json.dumps(result["coverage"], ensure_ascii=False))
        self.assertIn("整批未发布", result["coverage"][0]["reason"])

    def test_reason_refusal_and_scope_vocabularies_are_exactly_the_closed_enums(self) -> None:
        """Guard the derived sets above against drift from the enums they come from."""
        self.assertEqual(
            _REASON_VOCABULARY,
            {reason.value for reason in QueryRejectionReason}
            | {category.value for category in PiFileFailureCategory},
        )
        self.assertTrue(
            {
                "scope_mismatch",
                "source_unsupported",
                "file_incomplete",
                "publication_failed",
            }
            <= _REASON_VOCABULARY
        )
        self.assertTrue(
            {"records_unbounded", "filter_sources_invalid", "record_type_invalid"}
            <= _REASON_VOCABULARY
        )
        self.assertTrue(
            {"result_truncated", "parse_incomplete", "scan_resource_limit"}
            <= _FILTER_ERROR_VOCABULARY
        )
        self.assertTrue(
            {"stream_incomplete", "session_identity_conflict", "byte_limit_exceeded"}
            <= _PIPELINE_CODE_VOCABULARY
        )
        self.assertEqual(
            _REFUSAL_VOCABULARY,
            {refusal.value for refusal in PublicationRefusal}
            | {"match_join_failed", "snippet_join_failed"},
        )
        self.assertNotIn("invalid_filter", _REASON_VOCABULARY)
        self.assertNotIn("metadata_withheld", _REFUSAL_VOCABULARY)
        self.assertEqual(_SCOPE_VOCABULARY, {"single_approved_file", "none"})

    def test_every_outcome_field_uses_only_closed_vocabulary(self) -> None:
        """No gate path may hand out a reason/stage/scope/category string outside its enum."""
        service = self._service("closed.jsonl", text="needle body", count=2)
        conflict = self.store / "closed-conflict.jsonl"
        _write_multi(conflict, self.repo, text="needle body", count=1)
        with conflict.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "type": "session",
                        "version": "1",
                        "cwd": str(self.repo),
                        "id": "different-synthetic-session",
                    }
                )
                + "\n"
            )
        conflicting = PiFileSearchService(
            policy=self.policy, scope=SCOPE, path=str(conflict), session_id=SESSION_ID
        )
        for label, outcome in (
            ("published", service.search(scope=SCOPE, query="needle", sources=["pi"])),
            ("gate", conflicting.search(scope=SCOPE, query="needle", sources=["pi"])),
            (
                "empty",
                service.search(
                    scope=SCOPE, start="2026-03-02T00:00:00Z", end="2026-03-03T00:00:00Z"
                ),
            ),
        ):
            with self.subTest(case=label):
                if outcome["reason"] is not None:
                    self.assertIn(outcome["reason"], _REASON_VOCABULARY)
                if outcome["failure_category"] is not None:
                    self.assertIn(
                        outcome["failure_category"],
                        _REASON_VOCABULARY | _REFUSAL_VOCABULARY,
                    )
                self.assertIn(outcome["stage_reached"], _STAGE_VOCABULARY)
                self.assertIn(outcome["coverage_scope"], _SCOPE_VOCABULARY)
                for row in outcome["coverage"]:
                    self.assertIn(row["coverage_scope"], _SCOPE_VOCABULARY)
                    for code in row["filter_errors"]:
                        self.assertIn(
                            code,
                            _REASON_VOCABULARY
                            | _REFUSAL_VOCABULARY
                            | _FILTER_ERROR_VOCABULARY
                            | _PIPELINE_CODE_VOCABULARY,
                        )


_ROW_KEYS = (
    "source",
    "session_id",
    "role",
    "executor",
    "timestamp",
    "time_quality",
    "project",
    "project_quality",
    "location",
    "snippet",
    "redacted_count",
    "snippet_truncated",
)
_REASON_VOCABULARY = (
    {reason.value for reason in QueryRejectionReason}
    | {category.value for category in PiFileFailureCategory}
)
_REFUSAL_VOCABULARY = {refusal.value for refusal in PublicationRefusal} | {
    PiFileFailureCategory.MATCH_JOIN_FAILED.value,
    PiFileFailureCategory.SNIPPET_JOIN_FAILED.value,
}
_STAGE_VOCABULARY = {stage.value for stage in PiFileStageReached}
_SCOPE_VOCABULARY = {COVERAGE_SCOPE_FILE, COVERAGE_SCOPE_NONE}
# Diagnostic codes the query layer itself may put on a row, plus the fixed pipeline-layer codes
# this coordinator copies into `filter_errors` when a gate fails (ReadStop/StageDiscardReason /
# RefusalCode). All four are closed enums; no data-side string may appear in `filter_errors`.
_FILTER_ERROR_VOCABULARY = {code.value for code in FilterErrorCode}
_PIPELINE_CODE_VOCABULARY = (
    {stop.value for stop in ReadStop}
    | {reason.value for reason in StageDiscardReason}
    | {code.value for code in RefusalCode}
)


class TestCompletedEmptyCoverage(unittest.TestCase):
    def test_only_explicitly_completed_empty_source_can_be_no_match(self) -> None:
        complete = scan_filter(
            [], query="needle", sources=["pi"], completed_sources=["pi"]
        )
        self.assertFalse(complete.rejected)
        self.assertTrue(complete.complete)
        self.assertEqual(complete.coverage[0].status.value, "no_match")
        self.assertEqual(complete.unscanned_sources, ())

        conservative = scan_filter([], query="needle", sources=["pi"])
        self.assertFalse(conservative.complete)
        self.assertEqual(conservative.coverage[0].status.value, "incomplete")
        self.assertEqual(conservative.unscanned_sources, ("pi",))

        partial = scan_filter(
            [],
            query="needle",
            sources=["pi"],
            completed_sources=["pi"],
            stream_partial=True,
        )
        self.assertFalse(partial.complete)
        self.assertEqual(partial.coverage[0].status.value, "incomplete")


class TestPiFileSearch(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pi-file-search-synthetic-")
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.store = self.root / "store"
        self.repo.mkdir()
        self.store.mkdir()
        self.session_file = self.store / "session.jsonl"
        self.policy = _policy(self.repo, self.store)
        _write_session(
            self.session_file,
            self.repo,
            text="A synthetic needle. password=synthetic-secret-not-real",
        )
        self.service = PiFileSearchService(
            policy=self.policy,
            scope=SCOPE,
            path=str(self.session_file),
            session_id=SESSION_ID,
        )

    def tearDown(self) -> None:
        bind_pi_file_search_service(None)
        self.temp.cleanup()

    def test_keyword_time_project_filter_and_redacted_result(self) -> None:
        result = self.service.search(
            scope=SCOPE,
            query="NEEDLE",
            sources=["pi"],
            start="2026-03-01T10:00:00+00:00",
            end="2026-03-01T11:00:00+00:00",
            project=PROJECT,
            limit=20,
        )
        self.assertTrue(result["complete"])
        self.assertFalse(result["partial"])
        self.assertEqual(result["returned_count"], 1)
        hit = result["results"][0]
        self.assertEqual(hit["source"], "pi")
        self.assertEqual(hit["session_id"], SESSION_ID)
        self.assertEqual(hit["project"], PROJECT)
        self.assertEqual(hit["role"], "user")
        self.assertIn("[redacted]", hit["snippet"])
        self.assertNotIn("synthetic-secret-not-real", hit["snippet"])
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertEqual(result["coverage"][0]["status"], "searched")

    def test_time_filter_can_prove_no_match_after_complete_scan(self) -> None:
        result = self.service.search(
            scope=SCOPE,
            start="2026-03-02T00:00:00Z",
            end="2026-03-03T00:00:00Z",
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["coverage"][0]["status"], "no_match")
        self.assertEqual(result["coverage"][0]["records_scanned"], 1)
        self.assertEqual([row["source"] for row in result["coverage"]], ["pi"])

    def test_late_session_identity_conflict_discards_all_prefix_results(self) -> None:
        conflicting_header = {
            "type": "session",
            "version": "1",
            "cwd": str(self.repo),
            "id": "different-synthetic-session",
        }
        with self.session_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(conflicting_header) + "\n")

        result = self.service.search(scope=SCOPE, query="needle", sources=["pi"])
        self.assertFalse(result["complete"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["coverage"][0]["status"], "incomplete")
        self.assertNotIn("synthetic-secret-not-real", json.dumps(result))

    def test_unapproved_store_path_is_denied_before_results(self) -> None:
        outside = self.root / "not-approved.jsonl"
        _write_session(outside, self.repo, text="synthetic needle")
        outside_service = PiFileSearchService(
            policy=self.policy,
            scope=SCOPE,
            path=str(outside),
            session_id=SESSION_ID,
        )
        with self.assertRaises((PolicyDenied, SafeReadDenied)):
            outside_service.search(query="needle", sources=["pi"])

    def test_unapproved_project_filter_is_denied(self) -> None:
        with self.assertRaises(PolicyDenied):
            self.service.search(
                scope=SCOPE, query="needle", sources=["pi"], project="not-approved"
            )

    def test_mcp_handler_delegates_only_after_explicit_binding(self) -> None:
        from cross_agent_session_mcp.server import search_sessions

        async def invoke() -> tuple[dict[str, Any], bool, bool]:
            bind_pi_file_search_service(self.service)
            try:
                result = await search_sessions(
                    query="needle",
                    sources=["pi"],
                    scope=SCOPE,
                    project=PROJECT,
                )
                try:
                    await search_sessions(
                        query="needle", sources=["pi"], scope="different-scope"
                    )
                except ToolError:
                    mismatched_scope_rejected = True
                else:
                    mismatched_scope_rejected = False
                try:
                    await search_sessions(
                        query="needle", sources=["pi"] * 33, scope=SCOPE
                    )
                except ToolError:
                    too_many_sources_rejected = True
                else:
                    too_many_sources_rejected = False
                return result, mismatched_scope_rejected, too_many_sources_rejected
            finally:
                bind_pi_file_search_service(None)

        result, mismatched_scope_rejected, too_many_sources_rejected = asyncio.run(
            invoke()
        )
        self.assertEqual(result["returned_count"], 1)
        self.assertNotIn("path", result)
        self.assertTrue(mismatched_scope_rejected)
        self.assertTrue(too_many_sources_rejected)


if __name__ == "__main__":
    unittest.main()
