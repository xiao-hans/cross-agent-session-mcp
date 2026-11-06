"""Synthetic checks for bounded Pi discovery and multi-file aggregate search.

These tests create temporary, synthetic JSONL records only; they never inspect real
session data or load user configuration.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from cross_agent_session_mcp import session_discovery as discovery_module
from cross_agent_session_mcp.file_search import PiFileSearchService
from cross_agent_session_mcp.policy import (
    CwdRootGrant,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.publication import MAX_SNIPPET_TOTAL_CHARS
from cross_agent_session_mcp.references import ReferenceLedger
from cross_agent_session_mcp.session_discovery import (
    COVERAGE_SCOPE_MULTI,
    MAX_DISCOVERY_FILES,
    MAX_DISCOVERY_ROOTS,
    MAX_FILES_PER_QUERY,
    PiMultiFileContextService,
    PiMultiFileSearchService,
    SessionDiscoveryOutcome,
    SessionFileRef,
    discover_pi_session_files,
)

SCOPE = "synthetic-scope"
PROJECT_A = "proj-a"
PROJECT_B = "proj-b"


class _ScanIterable:
    """Stand-in for `os.scandir`'s return: the walker uses it as both an
    iterable and a context manager, so plain list iterators are not enough."""

    def __init__(self, entries: list[Any]) -> None:
        self._entries = tuple(entries)

    def __iter__(self):
        return iter(self._entries)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        return False


def _write_session(
    path: Path, cwd: Path, sid: str, texts: list[str], *, role: str = "user"
) -> None:
    rows: list[dict[str, Any]] = [
        {"type": "session", "version": "1", "cwd": str(cwd), "id": sid}
    ]
    for index, text in enumerate(texts):
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


def _policy(repo_a: Path, repo_b: Path, store: Path) -> SessionPolicy:
    return SessionPolicy(
        scopes=(
            ScopeGrant(
                scope_id=SCOPE,
                projects=(
                    ProjectGrant(PROJECT_A, (CwdRootGrant(str(repo_a)),)),
                    ProjectGrant(PROJECT_B, (CwdRootGrant(str(repo_b)),)),
                ),
                store_roots=(StoreRootGrant("pi", str(store)),),
            ),
        )
    )


class _Fixture(unittest.TestCase):
    """Shared synthetic store: two projects, two sessions in nested dirs."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="pi-discovery-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "store"
        self.repo_a = self.root / "repo-a"
        self.repo_b = self.root / "repo-b"
        (self.store / "nested").mkdir(parents=True)
        self.repo_a.mkdir()
        self.repo_b.mkdir()
        self.policy = _policy(self.repo_a, self.repo_b, self.store)

    def _make_pair(self) -> tuple[SessionFileRef, ...]:
        _write_session(
            self.store / "sA.jsonl", self.repo_a, "sA", ["alpha needle", "quiet line"]
        )
        _write_session(
            self.store / "nested" / "sB.jsonl", self.repo_b, "sB", ["beta needle"]
        )
        discovery = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        self.assertTrue(discovery.complete, discovery.as_public_dict())
        return discovery.files


class TestBoundedDiscovery(_Fixture):
    def test_discovers_across_nested_dirs_without_reading_content(self) -> None:
        files = self._make_pair()
        self.assertEqual({ref.session_id for ref in files}, {"sA", "sB"})
        # delivery order is the sorted real path, deterministic across runs
        paths = [ref.path for ref in files]
        self.assertEqual(paths, sorted(paths))

    def test_outside_root_is_refused_and_breaks_completeness(self) -> None:
        files = self._make_pair()
        outcome = discover_pi_session_files(
            self.policy, SCOPE, [str(self.store), str(self.root / "elsewhere")]
        )
        self.assertEqual(outcome.roots_total, 2)
        self.assertEqual(
            [row["reason"] for row in outcome.roots_refused], ["path_out_of_scope"]
        )
        self.assertFalse(outcome.complete)
        self.assertEqual(len(outcome.files), len(files))
        self.assertEqual(outcome.as_public_dict()["files_found"], len(files))

    def test_session_assertion_shape_rejects_path_like_file_names(self) -> None:
        _write_session(
            self.store / "bad name.jsonl", self.repo_a, "bad", ["needle"]
        )
        outcome = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        self.assertEqual(outcome.session_assertions_rejected, 1)
        self.assertFalse(outcome.complete)
        self.assertNotIn("bad name", {ref.session_id for ref in outcome.files})

    def test_file_budget_trips_limit_hit(self) -> None:
        self._make_pair()
        outcome = discover_pi_session_files(
            self.policy, SCOPE, [str(self.store)], max_files=1
        )
        self.assertTrue(outcome.limit_hit)
        self.assertFalse(outcome.complete)
        self.assertEqual(len(outcome.files), 1)

    def test_entry_budget_trips_limit_hit(self) -> None:
        self._make_pair()
        outcome = discover_pi_session_files(
            self.policy, SCOPE, [str(self.store)], max_entries=1
        )
        self.assertTrue(outcome.limit_hit)
        self.assertFalse(outcome.complete)

    def test_depth_budget_counts_unentered_dirs(self) -> None:
        self._make_pair()
        # one level deeper than the pair: depth=1 may not enter it
        (self.store / "nested" / "deep").mkdir()
        _write_session(
            self.store / "nested" / "deep" / "sC.jsonl", self.repo_a, "sC", ["gamma"]
        )
        outcome = discover_pi_session_files(
            self.policy, SCOPE, [str(self.store)], max_depth=1
        )
        self.assertEqual(outcome.dirs_not_entered, 1)
        self.assertFalse(outcome.complete)
        self.assertEqual({ref.session_id for ref in outcome.files}, {"sA", "sB"})

    def test_duplicate_roots_do_not_duplicate_files(self) -> None:
        files = self._make_pair()
        outcome = discover_pi_session_files(
            self.policy, SCOPE, [str(self.store), str(self.store)]
        )
        self.assertEqual(len(outcome.files), len(files))

    def test_exact_cap_with_nothing_left_over_is_not_limit_hit(self) -> None:
        # P2-2: hitting the file budget on the very last visible entry must not
        # be reported as a truncation; only unseen leftovers make it partial.
        self._make_pair()  # exactly two session files, no more entries
        outcome = discover_pi_session_files(
            self.policy, SCOPE, [str(self.store)], max_files=2
        )
        self.assertFalse(outcome.limit_hit)
        self.assertTrue(outcome.complete)
        self.assertEqual(len(outcome.files), 2)

    def test_root_count_above_hard_cap_is_rejected(self) -> None:
        # P2-3: the caller cannot stream an unbounded root list into the walker.
        roots = [str(self.store)] * (MAX_DISCOVERY_ROOTS + 1)
        with self.assertRaises(ValueError):
            discover_pi_session_files(self.policy, SCOPE, roots)

    def test_symlinks_are_skipped_when_the_platform_allows_them(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        _write_session(outside / "sX.jsonl", self.repo_a, "sX", ["needle outside"])
        link = self.store / "linkdir"
        try:
            os.symlink(str(outside), str(link), target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("platform does not allow creating directory symlinks")
        outcome = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        self.assertGreaterEqual(outcome.symlink_dirs_skipped, 1)
        self.assertNotIn("sX", {ref.session_id for ref in outcome.files})

    def test_file_symlinks_are_counted_by_target_type(self) -> None:
        # P2-1: with follow_symlinks=False a link is neither file nor dir; the
        # skip counter must classify by the target, not stay forever at zero.
        outside = self.root / "outside"
        outside.mkdir()
        _write_session(outside / "sX.jsonl", self.repo_a, "sX", ["needle outside"])
        link = self.store / "link.jsonl"
        try:
            os.symlink(str(outside / "sX.jsonl"), str(link))
        except (OSError, NotImplementedError):
            self.skipTest("platform does not allow creating file symlinks")
        outcome = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        self.assertGreaterEqual(outcome.symlink_files_skipped, 1)
        self.assertNotIn("sX", {ref.session_id for ref in outcome.files})

    def test_reparse_point_without_symlink_flag_is_not_entered(self) -> None:
        # P1-1 regression: a Windows junction reports is_symlink() == False and
        # is_dir(follow_symlinks=False) == True; only the shared reparse-attribute
        # check keeps discovery out of it. Platforms without `cmd` (or without
        # junction permission) must skip cleanly, never error out.
        try:
            side = subprocess.run(
                [
                    "cmd",
                    "/c",
                    "mklink",
                    "/J",
                    str(self.store / "jtest"),
                    str(self.store / "nested"),
                ],
                check=False,
                capture_output=True,
            )
        except OSError:
            self.skipTest("platform cannot invoke `cmd` to create a junction")
        junction = self.store / "jtest"
        if side.returncode != 0 or not junction.is_dir():
            self.skipTest("platform does not allow creating directory junctions")
        # real payloads behind BOTH paths: nested/ holds sB, so entering the
        # junction would surface a second collectible session file.
        self._make_pair()
        try:
            outcome = discover_pi_session_files(
                self.policy, SCOPE, [str(self.store)]
            )
            # exactly one sA + one sB, both via their real paths; the junction
            # is refused as a link and never entered.
            self.assertEqual(
                {ref.session_id for ref in outcome.files}, {"sA", "sB"}
            )
            self.assertEqual(len(outcome.files), 2)
            self.assertNotIn(
                str(junction), {ref.path for ref in outcome.files}
            )
            self.assertEqual(outcome.symlink_dirs_skipped, 1)
        finally:
            junction.rmdir()

    def test_windows_reparse_branch_refuses_a_non_symlink_link_entry(self) -> None:
        # Same P1-1 logic exercised deterministically on every platform: the
        # walker's reparse probe (policy._is_link) is the gate for entries that
        # report is_symlink() == False. Patch only the OS-quirk predicate; the
        # refusing branch itself is the real discovery code.
        class _FakeEntry:
            name = "weirddir"

            def __init__(self, path: str) -> None:
                self.path = path

            def is_symlink(self) -> bool:
                return False

            def is_dir(self, *, follow_symlinks: bool) -> bool:
                return True

            def is_file(self, *, follow_symlinks: bool) -> bool:
                return False

        self._make_pair()
        fake = _FakeEntry(str(self.store / "weirddir"))
        real_scandir = os.scandir

        def fake_scandir(path: str):
            if str(path) == str(self.store):
                return _ScanIterable([fake])
            return real_scandir(path)

        with mock.patch.object(
            discovery_module, "_is_link", return_value=True
        ), mock.patch.object(
            discovery_module.os, "scandir", side_effect=fake_scandir
        ), mock.patch.object(
            discovery_module, "_IS_WINDOWS", True
        ):
            outcome = discover_pi_session_files(
                self.policy, SCOPE, [str(self.store)]
            )
        # the reparse point was refused, never entered, and counted as skipped;
        # the walk itself saw every in-scope entry, so it may claim completeness
        self.assertEqual(outcome.symlink_dirs_skipped, 1)
        self.assertEqual(outcome.files, ())
        self.assertTrue(outcome.complete)

    def test_unstatable_entry_breaks_completeness(self) -> None:
        # P1-2 regression: an entry whose type cannot be read must count as a
        # walk error, flip entry_unavailable, and forbid complete == True.
        class _BrokenEntry:
            name = "broken.jsonl"
            path = "broken"

            def is_symlink(self) -> bool:
                raise OSError("stat failed")

            def is_dir(self, *, follow_symlinks: bool) -> bool:  # pragma: no cover
                raise AssertionError("unreachable")

            def is_file(self, *, follow_symlinks: bool) -> bool:  # pragma: no cover
                raise AssertionError("unreachable")

        real_scandir = os.scandir

        def fake_scandir(path: str):
            if str(path) == str(self.store):
                return _ScanIterable([_BrokenEntry()])
            return real_scandir(path)

        with mock.patch.object(
            discovery_module.os, "scandir", side_effect=fake_scandir
        ):
            outcome = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        self.assertEqual(outcome.walk_errors, 1)
        self.assertTrue(outcome.entry_unavailable)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.files, ())

    def test_unlistable_directory_counts_as_walk_error(self) -> None:
        # P1-2 regression, directory-open branch: a granted root that cannot be
        # listed is an honest coverage hole, never a silent "we finished".
        real_scandir = os.scandir

        def fake_scandir(path: str):
            if str(path) == str(self.store):
                raise OSError("permission denied")
            return real_scandir(path)

        with mock.patch.object(
            discovery_module.os, "scandir", side_effect=fake_scandir
        ):
            outcome = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        self.assertEqual(outcome.walk_errors, 1)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.dirs_scanned, 0)


class TestSessionFileRef(unittest.TestCase):
    def test_shape_gate_rejects_path_like_or_empty_identifiers(self) -> None:
        with self.assertRaises(ValueError):
            SessionFileRef(path="X", session_id="")
        with self.assertRaises(ValueError):
            SessionFileRef(path="X", session_id="C:/Users/private")
        with self.assertRaises(ValueError):
            SessionFileRef(path="", session_id="ok-id")

    def test_publishable_identifier_survives(self) -> None:
        ref = SessionFileRef(path="X", session_id="run-01_A")
        self.assertEqual(ref.session_id, "run-01_A")


class TestServiceConstruction(_Fixture):
    def test_empty_file_set_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PiMultiFileSearchService(self.policy, SCOPE, ())

    def test_too_many_files_is_rejected(self) -> None:
        refs = tuple(
            SessionFileRef(path=f"X{i}", session_id=f"s{i}")
            for i in range(MAX_FILES_PER_QUERY + 1)
        )
        with self.assertRaises(ValueError):
            PiMultiFileSearchService(self.policy, SCOPE, refs)

    def test_non_ref_entries_and_bad_ledger_are_rejected(self) -> None:
        bad_files: Any = ("not-a-ref",)
        with self.assertRaises(TypeError):
            PiMultiFileSearchService(self.policy, SCOPE, bad_files)
        bad_ledger: Any = "x"
        with self.assertRaises(TypeError):
            PiMultiFileSearchService(
                self.policy, SCOPE, (SessionFileRef(path="X", session_id="s"),), ledger=bad_ledger
            )

    def test_context_service_index_bounds(self) -> None:
        service = PiMultiFileSearchService(
            self.policy, SCOPE, (SessionFileRef(path="X", session_id="s"),)
        )
        with self.assertRaises(ValueError):
            service.context_service(1)
        with self.assertRaises(ValueError):
            service.context_service(True)

    def test_overrides_above_hard_caps_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            discover_pi_session_files(
                self.policy, SCOPE, [str(self.store)], max_files=MAX_DISCOVERY_FILES + 1
            )
        with self.assertRaises(ValueError):
            discover_pi_session_files(self.policy, SCOPE, [str(self.store)], max_files=0)


class TestAggregateSearch(_Fixture):
    def _service(self, **kwargs: Any) -> PiMultiFileSearchService:
        return PiMultiFileSearchService(
            self.policy, SCOPE, self._make_pair(), **kwargs
        )

    def test_aggregates_matches_across_files(self) -> None:
        out = self._service().search(query="needle")
        self.assertTrue(out["complete"], out)
        self.assertFalse(out["partial"])
        self.assertEqual(out["total_matched"], 2)
        self.assertEqual(out["returned_count"], 2)
        self.assertEqual(
            [row["session_id"] for row in out["results"]], ["sB", "sA"]
        )  # sorted-path segment order
        projects = {row["project"] for row in out["results"]}
        self.assertEqual(projects, {PROJECT_A, PROJECT_B})
        self.assertEqual(out["coverage_scope"], COVERAGE_SCOPE_MULTI)
        self.assertEqual(out["stage_reached"], "published")

    def test_global_limit_is_not_reset_per_file(self) -> None:
        out = self._service().search(query="needle", limit=1)
        self.assertEqual(out["returned_count"], 1)
        self.assertTrue(out["truncated"])
        self.assertEqual(out["total_matched"], 2)
        self.assertFalse(out["complete"])

    def test_per_file_snippet_quota_marks_partial_and_truncated(self) -> None:
        base = self._make_pair()  # two needles live in the small sessions
        texts = [f"needle {index}" for index in range(20)]
        _write_session(self.store / "big.jsonl", self.repo_a, "big", texts)
        discovery = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        service = PiMultiFileSearchService(self.policy, SCOPE, discovery.files)
        out = service.search(query="needle", limit=32)
        self.assertEqual(out["total_matched"], 22)
        # 16 (per-file cap) from big + one from each small session
        self.assertEqual(out["returned_count"], 18)
        self.assertTrue(out["truncated"])
        self.assertTrue(out["partial"])
        self.assertFalse(out["complete"])
        self.assertEqual(out["coverage"][0]["status"], "searched")
        # P2-4: the pi coverage row must report the rows actually published,
        # stay partial, and carry the truncation error code after the quota cut.
        pi_row = out["coverage"][0]
        self.assertEqual(pi_row["returned_count"], 18)
        self.assertTrue(pi_row["partial"])
        self.assertIn("result_truncated", pi_row["filter_errors"])
        del base

    def test_snippet_char_budget_is_shared_across_files(self) -> None:
        # P2-5: each file may stay under MAX_SNIPPET_TOTAL_CHARS on its own,
        # but the published total across files must not exceed it. The gate
        # fires before the first token leaves the ledger: zero results,
        # no prefix.
        half = MAX_SNIPPET_TOTAL_CHARS // 2
        ledger = ReferenceLedger()
        _write_session(
            self.store / "big-a.jsonl",
            self.repo_a,
            "bigA",
            ["needle " + "a" * (half // 3) for _ in range(3)],
        )
        _write_session(
            self.store / "big-b.jsonl",
            self.repo_b,
            "bigB",
            ["needle " + "b" * (half // 3 + 8) for _ in range(4)],
        )
        service = PiMultiFileSearchService(
            self.policy,
            SCOPE,
            (
                SessionFileRef(str(self.store / "big-a.jsonl"), "bigA"),
                SessionFileRef(str(self.store / "big-b.jsonl"), "bigB"),
            ),
            ledger=ledger,
        )
        out = service.search(query="needle", limit=32)
        self.assertEqual(out["returned_count"], 0)
        self.assertEqual(out["reason"], "publication_failed")
        self.assertEqual(out["failure_category"], "snippet_total_chars_limit")
        self.assertEqual(out["stage_reached"], "publication")
        self.assertEqual(out["coverage"][0]["status"], "error")
        # the filter layer saw all seven matches; nothing was published
        self.assertEqual(out["total_matched"], 7)
        self.assertEqual(out["coverage"][0]["matched_count"], 7)
        # the char gate fired before any token left the shared ledger:
        # a zero-result failure must not leave resolvable references behind
        self.assertEqual(len(ledger), 0)

    def test_no_match_still_claims_only_the_bounded_set(self) -> None:
        out = self._service().search(query="zzz-not-present")
        self.assertTrue(out["complete"], out)
        self.assertEqual(out["returned_count"], 0)
        row = out["coverage"][0]
        self.assertEqual(row["status"], "no_match")
        self.assertEqual(row["coverage_scope"], COVERAGE_SCOPE_MULTI)
        self.assertIn("不声明整个 pi 来源已扫完", row["reason"])

    def test_project_filter_narrows_without_marking_other_files_broken(self) -> None:
        out = self._service().search(query="needle", project=PROJECT_A)
        self.assertTrue(out["complete"], out)
        self.assertFalse(out["partial"])
        self.assertEqual(out["total_matched"], 1)
        self.assertEqual([r["session_id"] for r in out["results"]], ["sA"])
        # the unfiltered file stays fully covered: it was searched, just not matched
        self.assertEqual({f["status"] for f in out["files"]}, {"searched"})

    def test_refused_file_only_marks_its_own_row(self) -> None:
        outside = self.root / "outside.jsonl"
        _write_session(outside, self.repo_a, "outside", ["needle outside"])
        files = (*self._make_pair(), SessionFileRef(path=str(outside), session_id="outside"))
        service = PiMultiFileSearchService(self.policy, SCOPE, files)
        out = service.search(query="needle")
        statuses = {f["index"]: f["status"] for f in out["files"]}
        self.assertEqual(list(statuses.values())[-1], "refused")
        self.assertEqual(out["files"][-1]["reason"], "path_out_of_scope")
        self.assertEqual(out["returned_count"], 2)
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])

    def test_incomplete_file_does_not_block_other_files(self) -> None:
        self._make_pair()
        _write_session(self.store / "good.jsonl", self.repo_a, "good", ["needle here"])
        bad = self.store / "abad.jsonl"
        bad.write_bytes(b"\x00garbage\n")  # binary: refused before any content is staged
        discovery = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        service = PiMultiFileSearchService(self.policy, SCOPE, discovery.files)
        out = service.search(query="needle")
        self.assertFalse(out["complete"])
        self.assertTrue(out["partial"])
        self.assertEqual(out["returned_count"], 3)
        statuses = [f["status"] for f in out["files"]]
        self.assertIn("refused", statuses)
        self.assertEqual(statuses.count("searched"), 3)
        self.assertNotIn("garbage", json.dumps(out["results"]))

    def test_publication_budget_failure_is_zero_result_without_prefix(self) -> None:
        long_text = "needle " + "x" * 7000
        texts = [long_text for _ in range(6)]
        _write_session(self.store / "big.jsonl", self.repo_a, "big", texts)
        discovery = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        service = PiMultiFileSearchService(self.policy, SCOPE, discovery.files)
        out = service.search(query="needle")
        self.assertEqual(out["returned_count"], 0)
        self.assertEqual(out["failure_category"], "snippet_total_chars_limit")
        self.assertEqual(out["reason"], "publication_failed")
        self.assertEqual(out["stage_reached"], "publication")
        self.assertEqual(out["coverage"][0]["status"], "error")
        self.assertEqual(out["total_matched"], 6)  # only big.jsonl exists in this fixture
        self.assertEqual(out["results"], [])

    def test_no_usable_files_is_files_unusable_not_no_match(self) -> None:
        bad = self.store / "only.jsonl"
        bad.write_bytes(b"\x00\x00binary\x00")
        discovery = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        service = PiMultiFileSearchService(self.policy, SCOPE, discovery.files)
        out = service.search(query="needle")
        self.assertTrue(out["rejected"] is False)
        self.assertEqual(out["reason"], "files_unusable")
        self.assertEqual(out["stage_reached"], "file_pipeline")
        self.assertEqual(out["returned_count"], 0)
        self.assertIn("files_unusable", out["coverage"][0]["filter_errors"])

    def test_read_budget_exhaustion_skips_later_files_honestly(self) -> None:
        self._make_pair()
        _write_session(self.store / "third.jsonl", self.repo_a, "third", ["needle three"])
        discovery = discover_pi_session_files(self.policy, SCOPE, [str(self.store)])
        self.assertEqual(len(discovery.files), 3)
        service = PiMultiFileSearchService(self.policy, SCOPE, discovery.files)
        # A patched aggregate budget that the first (smallest) file drains: the tail
        # files never open and must be reported as skipped_budget, not as searched.
        with mock.patch(
            "cross_agent_session_mcp.session_discovery.MAX_AGGREGATE_TOTAL_READ_BYTES",
            300,
        ):
            out = service.search(query="needle")
        statuses = [f["status"] for f in out["files"]]
        self.assertEqual(statuses[0], "searched")
        self.assertIn("skipped_budget", statuses)
        skipped_row = out["files"][statuses.index("skipped_budget")]
        self.assertEqual(skipped_row["reason"], "read_budget_exhausted")
        self.assertEqual(skipped_row["records_captured"], 0)
        self.assertTrue(out["partial"])
        self.assertFalse(out["complete"])
        self.assertGreaterEqual(out["returned_count"], 1)

    def test_unsupported_source_and_scope_gates(self) -> None:
        service = self._service()
        out = service.search(query="needle", sources=["codex"])
        self.assertEqual(out["failure_category"], "source_unsupported")
        self.assertEqual(out["coverage"][0]["status"], "unsupported")
        self.assertEqual(out["returned_count"], 0)
        mismatch = service.search(scope="other-scope")
        self.assertTrue(mismatch["rejected"])
        self.assertEqual(mismatch["reason"], "scope_mismatch")
        for bad_limit_value in (0, 101, True, "20"):
            bad_limit: Any = bad_limit_value
            rejected = service.search(query="needle", limit=bad_limit)
            self.assertTrue(rejected["rejected"], bad_limit)
            self.assertEqual(rejected["reason"], "invalid_request")

    def test_results_carry_no_paths_or_raw_locations(self) -> None:
        out = self._service().search(query="needle")
        dump = json.dumps(out)
        for forbidden in (str(self.store), str(self.repo_a), str(self.repo_b), "nested"):
            self.assertNotIn(forbidden, dump)
        for row in out["results"]:
            self.assertTrue(row["location"].startswith("ctxref:"))
            self.assertNotIn("line_no", row)
            self.assertNotIn("ordinal", row)


class TestReferenceRouting(_Fixture):
    def test_token_reads_back_only_through_its_own_file_binding(self) -> None:
        files = self._make_pair()
        ledger = ReferenceLedger()
        service = PiMultiFileSearchService(self.policy, SCOPE, files, ledger=ledger)
        out = service.search(query="needle")
        rows = out["results"]
        by_session = {row["session_id"]: row["location"] for row in rows}
        index_a = next(i for i, ref in enumerate(files) if ref.session_id == "sA")
        index_b = next(i for i, ref in enumerate(files) if ref.session_id == "sB")
        ctx_a = service.context_service(index_a)
        ctx_b = service.context_service(index_b)
        self.assertIs(ctx_a.ledger, ledger)
        ok = ctx_a.read(
            scope=SCOPE, source="pi", session_id="sA", location=by_session["sA"],
            project=None, before=1, after=1,
        ).as_public_dict()
        self.assertTrue(ok["complete"] or ok["partial"], ok)
        self.assertGreaterEqual(len(ok["results"]), 1)
        wrong = ctx_b.read(
            scope=SCOPE, source="pi", session_id="sB", location=by_session["sA"],
            project=None,
        ).as_public_dict()
        self.assertFalse(wrong["complete"])
        self.assertEqual(wrong["reason"], "binding_mismatch")

    def test_ledger_separation_isolates_tokens(self) -> None:
        files = self._make_pair()
        service = PiMultiFileSearchService(self.policy, SCOPE, files)
        out = service.search(query="needle")
        token = out["results"][0]["location"]
        other = PiMultiFileSearchService(
            self.policy, SCOPE, files, ledger=ReferenceLedger()
        )
        index = next(
            i for i, ref in enumerate(files)
            if ref.session_id == out["results"][0]["session_id"]
        )
        miss = other.context_service(index).read(
            scope=SCOPE, source="pi", session_id=files[index].session_id,
            location=token, project=None,
        ).as_public_dict()
        self.assertFalse(miss["complete"])
        self.assertIn(miss["reason"], {"ref_expired", "invalid_argument"})

    def test_single_file_service_tokens_route_into_aggregate_context(self) -> None:
        """The shared ledger keeps old single-file locations valid under the new service."""
        files = self._make_pair()
        ledger = ReferenceLedger()
        index_a = next(i for i, ref in enumerate(files) if ref.session_id == "sA")
        ref_a = files[index_a]
        single = PiFileSearchService(
            policy=self.policy,
            scope=SCOPE,
            path=ref_a.path,
            session_id=ref_a.session_id,
            ledger=ledger,
        )
        out = single.search(scope=SCOPE, query="needle")
        self.assertTrue(out["complete"], out)
        token = out["results"][0]["location"]
        aggregate = PiMultiFileSearchService(self.policy, SCOPE, files, ledger=ledger)
        ctx = aggregate.context_service(index_a).read(
            scope=SCOPE, source="pi", session_id="sA", location=token, project=None
        ).as_public_dict()
        self.assertTrue(ctx["complete"] or ctx["partial"], ctx)
        self.assertGreaterEqual(len(ctx["results"]), 1)


class TestAggregateContextRouter(_Fixture):
    """`PiMultiFileContextService.read` 的路由口径：只回到发放它的那条绑定，且不开多余文件。"""

    def _tokens(self, files, ledger):
        service = PiMultiFileSearchService(self.policy, SCOPE, files, ledger=ledger)
        out = service.search(query="needle")
        return {row["session_id"]: row["location"] for row in out["results"]}

    def test_routes_each_token_back_to_its_own_file(self) -> None:
        files = self._make_pair()
        ledger = ReferenceLedger()
        tokens = self._tokens(files, ledger)
        router = PiMultiFileContextService(self.policy, SCOPE, files, ledger=ledger)
        for session_id in ("sA", "sB"):
            outcome = router.read(
                scope=SCOPE,
                source="pi",
                session_id=session_id,
                location=tokens[session_id],
                project=None,
                before=1,
                after=1,
            ).as_public_dict()
            self.assertTrue(outcome["complete"] or outcome["partial"], outcome)
            self.assertGreaterEqual(len(outcome["results"]), 1)
            # 路由后的覆盖结论仍只声明本次那一个已批准文件
            self.assertEqual(outcome["coverage_scope"], "single_approved_file")
            self.assertEqual(
                {row["session_id"] for row in outcome["results"]}, {session_id}
            )

    def test_client_scope_and_source_contradictions_refuse_before_any_lookup(self) -> None:
        files = self._make_pair()
        ledger = ReferenceLedger()
        tokens = self._tokens(files, ledger)
        router = PiMultiFileContextService(self.policy, SCOPE, files, ledger=ledger)
        wrong_scope = router.read(
            scope="other-scope", source="pi", session_id="sA",
            location=tokens["sA"], project=None,
        ).as_public_dict()
        self.assertEqual(wrong_scope["reason"], "binding_mismatch")
        self.assertIn("scope_mismatch", wrong_scope["filter_errors"])
        self.assertEqual(wrong_scope["coverage_scope"], "none")
        self.assertEqual(wrong_scope["results"], [])
        wrong_source = router.read(
            scope=SCOPE, source="codex", session_id="sA",
            location=tokens["sA"], project=None,
        ).as_public_dict()
        self.assertIn("source_mismatch", wrong_source["filter_errors"])
        # source 轴与 scope 轴同口径：在任何查账/路由前拒，零结果、none 覆盖。
        self.assertEqual(wrong_source["reason"], "binding_mismatch")
        self.assertEqual(wrong_source["coverage_scope"], "none")
        self.assertEqual(wrong_source["results"], [])

    def test_session_decl_mismatch_survives_routing(self) -> None:
        """路由只定位文件；声明矛盾仍由单文件路径拒掉——A 的令牌问 B 在协议上不存在。"""
        files = self._make_pair()
        ledger = ReferenceLedger()
        tokens = self._tokens(files, ledger)
        router = PiMultiFileContextService(self.policy, SCOPE, files, ledger=ledger)
        cross = router.read(
            scope=SCOPE, source="pi", session_id="sB",
            location=tokens["sA"], project=None,
        ).as_public_dict()
        self.assertFalse(cross["complete"])
        self.assertEqual(cross["reason"], "binding_mismatch")
        self.assertIn("session_decl_mismatch", cross["filter_errors"])
        self.assertEqual(cross["results"], [])

    def test_project_axis_passes_through_to_delegate(self) -> None:
        """project 声明不在路由层消化：原样透传后由单文件层的绑定核对拒掉。"""
        files = self._make_pair()
        ledger = ReferenceLedger()
        tokens = self._tokens(files, ledger)
        router = PiMultiFileContextService(self.policy, SCOPE, files, ledger=ledger)
        wrong_project = router.read(
            scope=SCOPE, source="pi", session_id="sA",
            location=tokens["sA"], project="no-such-project",
        ).as_public_dict()
        self.assertEqual(wrong_project["reason"], "binding_mismatch")
        self.assertIn("project_binding", wrong_project["filter_errors"])
        self.assertEqual(wrong_project["results"], [])

    def test_unknown_or_malformed_location_refuses_without_opening_files(self) -> None:
        files = self._make_pair()
        ledger = ReferenceLedger()
        self._tokens(files, ledger)
        router = PiMultiFileContextService(self.policy, SCOPE, files, ledger=ledger)
        bogus = "ctxref:" + "z" * 40
        for location, expected in ((bogus, "ref_expired"), ("12", "invalid_argument")):
            outcome = router.read(
                scope=SCOPE, source="pi", session_id="sA",
                location=location, project=None,
            ).as_public_dict()
            self.assertEqual(outcome["reason"], expected, (location, outcome))
            self.assertEqual(outcome["results"], [])

    def test_token_from_another_ledger_or_binding_is_refused(self) -> None:
        files = self._make_pair()
        ledger = ReferenceLedger()
        tokens = self._tokens(files, ledger)
        # 另一本账上的路由（同文件集）：查不到 -> ref_expired
        stranger = PiMultiFileContextService(
            self.policy, SCOPE, files, ledger=ReferenceLedger()
        )
        miss = stranger.read(
            scope=SCOPE, source="pi", session_id="sA",
            location=tokens["sA"], project=None,
        ).as_public_dict()
        self.assertEqual(miss["reason"], "ref_expired")
        # 同账本、但绑定集合不含该文件的另一服务：指纹路由不回任何文件
        other_files = (next(ref for ref in files if ref.session_id == "sB"),)
        orphan = PiMultiFileContextService(
            self.policy, SCOPE, other_files, ledger=ledger
        )
        refused = orphan.read(
            scope=SCOPE, source="pi", session_id="sA",
            location=tokens["sA"], project=None,
        ).as_public_dict()
        self.assertEqual(refused["reason"], "binding_mismatch")
        self.assertIn("service_binding", refused["filter_errors"])
        self.assertEqual(refused["coverage_scope"], "none")

    def test_construction_gates_and_index_bounds(self) -> None:
        files = self._make_pair()
        policy = self.policy
        with self.assertRaises(ValueError):
            PiMultiFileContextService(policy, SCOPE, ())
        bad_ledger: Any = "not-a-ledger"
        bad_policy: Any = "not-a-policy"
        with self.assertRaises(TypeError):
            PiMultiFileContextService(policy, SCOPE, files, ledger=bad_ledger)
        with self.assertRaises(TypeError):
            PiMultiFileContextService(bad_policy, SCOPE, files)
        router = PiMultiFileContextService(policy, SCOPE, files)
        for bad in (-1, len(files), True, "0"):
            with self.assertRaises(ValueError):
                router.context_service(bad)  # type: ignore[arg-type]


class TestDiscoveryOutcomeShape(unittest.TestCase):
    def test_public_dict_keys_are_closed_and_path_free(self) -> None:
        outcome = SessionDiscoveryOutcome(
            files=(),
            complete=False,
            roots_total=1,
            roots_refused=({"index": 0, "reason": "path_out_of_scope"},),
            dirs_scanned=0,
            dirs_not_entered=0,
            entries_scanned=0,
            files_denied=(),
            symlink_files_skipped=0,
            symlink_dirs_skipped=0,
            symlink_generic_skipped=0,
            entry_unavailable=False,
            session_assertions_rejected=0,
            walk_errors=0,
            limit_hit=False,
        )
        public = outcome.as_public_dict()
        self.assertEqual(public["coverage_scope"], COVERAGE_SCOPE_MULTI)
        self.assertEqual(public["files_found"], 0)
        self.assertNotIn("files", public)  # deliveries stay host-side only


if __name__ == "__main__":
    unittest.main()
