"""DSH 帧式来源适配器的合成回归测试（计划 §8.2 DSH-01…14）。

所有断言都对照本仓库 2026-11-04 的探针实测矩阵编写；不运行真实存储，不读取用户目录。
发布链路（`run_dsh_frame_file` 起）在身份未核实（`DSH_HEADER_CWD_TRUSTED=False`）时
只产出不完整行与归属拒绝，绝不伪造 `complete` 或归属。
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dsh_synthetic as fx  # noqa: E402  (tests/ 内的合成夹具)

from cross_agent_session_mcp import redaction  # noqa: E402
from cross_agent_session_mcp.line_search import (  # noqa: E402
    DSH_SPEC,
    LineAggregateContextService,
    LineAggregateSearchService,
    SessionFileRef,
    make_dsh_spec,
    spec_for_source,
)
from cross_agent_session_mcp.policy import (  # noqa: E402
    CwdRootGrant,
    PolicyDenied,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.references import ReferenceLedger  # noqa: E402
from cross_agent_session_mcp.sources import dsh as dsh_source  # noqa: E402
from cross_agent_session_mcp.sources.dsh import (  # noqa: E402
    DSH_COVERAGE_SCOPE,
    DSH_SESSION_FILE_NAME,
    MAX_DSH_DECOMPRESSED_BYTES_PER_SESSION,
    MAX_DSH_FRAMES_PER_SESSION,
    MAX_DSH_LINE_BYTES,
    SOURCE_DSH,
    DshDecoderMode,
    DshDecoderRuntime,
    DshDiscoveryStatus,
    DshFrameReader,
    DshLineParser,
    DshStreamError,
    DshStreamStop,
    discover_dsh_sessions,
    run_dsh_frame_file,
)
from cross_agent_session_mcp.models import IssueCode, ProjectQuality  # noqa: E402

RT = DshDecoderRuntime.probe()


def issue_map(stats):
    return {code.value: count for code, count in stats.issue_counts.items()}


def parse_frames(frames, **kwargs):
    """把帧序列解成一趟行流并解析；返回 (记录列表, 解析器)。"""
    raw = b"".join(frames)
    reader = DshFrameReader(raw, RT)
    parser = DshLineParser(
        stream_label=fx.LABEL,
        project=kwargs.pop("project", fx.PROJECT),
        session_id=kwargs.pop("session_id", fx.SESSION),
        **kwargs,
    )
    records = []
    try:
        for _, line in reader.iter_lines():
            records.extend(parser.feed_line(bytes(line).decode("utf-8")))
    finally:
        parser.finish()
    return records, parser


def parse_lines(lines, **kwargs):
    parser = DshLineParser(
        stream_label=fx.LABEL,
        project=kwargs.pop("project", fx.PROJECT),
        session_id=kwargs.pop("session_id", fx.SESSION),
        **kwargs,
    )
    records = []
    try:
        for line in lines:
            records.extend(parser.feed_line(line))
    finally:
        parser.finish()
    return records, parser


def build_policy(store_roots=(), project_path=None):
    grants = tuple(StoreRootGrant(SOURCE_DSH, str(root)) for root in store_roots)
    cwd = str(project_path) if project_path is not None else fx.PROJECT
    return SessionPolicy(
        (
            ScopeGrant(
                "s",
                (ProjectGrant("p", (CwdRootGrant(cwd, allow_links=True),)),),
                grants,
            ),
        )
    )


class DshFixtureCase(unittest.TestCase):
    """带 tmp 存储的公共底座：policy / 文件路径 / 聚合服务。"""

    @classmethod
    def setUpClass(cls):
        # P1-9：本底座下所有用例都要真帧夹具（压缩/解压缩需 zstd 后端）；
        # 无后端环境诚实跳过，不得算作实现缺陷红。
        if not fx.frames_available():
            raise unittest.SkipTest("本机无 zstd 后端（compression.zstd / zstandard），DSH 帧用例跳过")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.proj = cls.root / "proj"
        cls.proj.mkdir()
        cls.store = cls.root / "store"
        cls.sessions = cls.store / fx.SESSION
        cls.sessions.mkdir(parents=True)
        cls.policy = build_policy((cls.store,), project_path=cls.proj)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def write_session(self, name, raw, *, subdir=None):
        base = self.sessions if subdir is None else self.store / subdir
        base.mkdir(parents=True, exist_ok=True)
        path = base / name
        path.write_bytes(raw)
        return path

    def run_file(self, path, session_id=fx.SESSION, **kwargs):
        kwargs.setdefault("cwd", fx.PROJECT)
        kwargs.setdefault("runtime", RT)
        return run_dsh_frame_file(self.policy, "s", str(path), session_id, **kwargs)

    def services(self, path, session_id=fx.SESSION, *, runtime=None):
        spec = make_dsh_spec(RT if runtime is None else runtime)
        ledger = ReferenceLedger()
        search = LineAggregateSearchService(
            policy=self.policy,
            scope="s",
            spec=spec,
            files=(SessionFileRef(path=str(path), session_id=session_id),),
            ledger=ledger,
        )
        context = LineAggregateContextService(
            policy=self.policy,
            scope="s",
            spec=spec,
            path=str(path),
            session_id=session_id,
            ledger=ledger,
        )
        return search, context


class TestDshFrameReader(DshFixtureCase):
    """DSH-01：帧流reader的边界语义（跨帧行、skippable、上限、坏帧）。"""

    def test_json_fragment_spanning_frames_yields_one_line(self):
        parts = json.dumps(
            {"type": "session_header", "version": "v4", "sessionId": fx.SESSION,
             "cwd": fx.PROJECT},
            ensure_ascii=False,
        ).encode("utf-8")
        raw = fx.compress_frame(parts[:20]) + fx.compress_frame(parts[20:] + b"\n")
        reader = DshFrameReader(raw, RT)
        lines = [(number, bytes(line)) for number, line in reader.iter_lines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0][0], 1)
        self.assertEqual(json.loads(lines[0][1].decode("utf-8"))["version"], "v4")
        self.assertTrue(reader.clean_eof)
        self.assertEqual(reader.frames, 2)
        self.assertIsNone(reader.stop_reason)

    def test_frame_limit_stops_without_claiming_eof(self):
        raw = fx.header_frame() + fx.message_frame("a", seq=1) + fx.message_frame("b", seq=2)
        reader = DshFrameReader(raw, RT, max_frames=2)
        lines = list(reader.iter_lines())
        self.assertEqual(len(lines), 2)
        self.assertEqual(reader.stop_reason, DshStreamStop.FRAME_LIMIT.value)
        self.assertFalse(reader.clean_eof)

    def test_skippable_frame_is_counted_not_parsed(self):
        raw = fx.skippable_frame() + fx.header_frame() + fx.message_frame("x", seq=1)
        reader = DshFrameReader(raw, RT)
        lines = list(reader.iter_lines())
        self.assertEqual(len(lines), 2)
        self.assertEqual(reader.frames, 3)
        self.assertTrue(reader.clean_eof)

    def test_truncated_last_frame_raises_frame_error(self):
        reader = DshFrameReader(fx.truncated_frame("tail"), RT)
        with self.assertRaises(DshStreamError) as caught:
            list(reader.iter_lines())
        self.assertEqual(caught.exception.category, DshStreamStop.TRUNCATED_FRAME.value)
        self.assertEqual(reader.stop_reason, DshStreamStop.TRUNCATED_FRAME.value)

    def test_truncation_after_kept_lines_reports_partial(self):
        raw = fx.header_frame() + fx.message_frame("kept", seq=1) + fx.truncated_frame("late")
        reader = DshFrameReader(raw, RT)
        got = []
        with self.assertRaises(DshStreamError) as caught:
            for item in reader.iter_lines():
                got.append(item)
        self.assertEqual(caught.exception.category, DshStreamStop.TRUNCATED_FRAME.value)
        self.assertEqual(len(got), 2)
        self.assertEqual(reader.frames, 2)

    def test_bad_magic_is_frame_error(self):
        reader = DshFrameReader(fx.bad_magic_bytes(), RT)
        with self.assertRaises(DshStreamError) as caught:
            list(reader.iter_lines())
        self.assertEqual(caught.exception.category, DshStreamStop.BAD_MAGIC.value)

    def test_decompressed_bomb_stops_at_budget(self):
        raw = fx.header_frame() + fx.bomb_frames(line_bytes=4096, frames=4)
        reader = DshFrameReader(raw, RT, max_decompressed_bytes=1)
        lines = list(reader.iter_lines())
        self.assertEqual(lines, [])
        self.assertEqual(reader.stop_reason, DshStreamStop.DECOMPRESSED_LIMIT.value)
        self.assertLessEqual(reader.decompressed_bytes, 4096)

    def test_oversized_line_is_cut_and_counted(self):
        reader = DshFrameReader(fx.compress_frame(b"x" * 5000 + b"y" * 5000),
                                RT, max_line_bytes=1000)
        lines = [(number, len(bytes(line))) for number, line in reader.iter_lines()]
        self.assertEqual(lines[0], (1, 1000))
        self.assertEqual(reader.oversized_lines, 1)

    def test_trailing_newline_is_line_terminator_not_extra_fragment(self):
        reader = DshFrameReader(
            fx.compress_frame(b"one\n") + fx.compress_frame(b"two\n"), RT)
        self.assertEqual([bytes(line) for _, line in reader.iter_lines()],
                         [b"one", b"two"])

    def test_missing_runtime_raises_before_any_line(self):
        reader = DshFrameReader(fx.TINY_HEADER_FRAME,
                                DshDecoderRuntime(mode=DshDecoderMode.MISSING))
        with self.assertRaises(DshStreamError) as caught:
            list(reader.iter_lines())
        self.assertEqual(caught.exception.category,
                         DshDecoderRuntime.__dict__ and DshStreamStop.DECODER_MISSING.value)
        self.assertEqual(reader.frames, 0)
        self.assertFalse(reader.clean_eof)

    def test_budget_arguments_are_validated(self):
        for kwargs in ({"max_line_bytes": 0}, {"max_decompressed_bytes": -1},
                       {"max_frames": -2}, {"timeout_seconds": 0}):
            with self.assertRaises(ValueError):
                DshFrameReader(b"", RT, **kwargs)
        with self.assertRaises(TypeError):
            DshFrameReader(b"", object())  # type: ignore[arg-type]

    def test_module_limits_are_the_hard_caps(self):
        self.assertEqual(MAX_DSH_LINE_BYTES, 1_048_576)
        self.assertEqual(MAX_DSH_FRAMES_PER_SESSION, 50_000)
        self.assertEqual(MAX_DSH_DECOMPRESSED_BYTES_PER_SESSION, 268_435_456)
        self.assertEqual(RT.mode, DshDecoderMode.IN_PROCESS)
        self.assertTrue(RT.usable)


class TestSubprocessDecoder(DshFixtureCase):
    """DSH-09/DSH-13：子进程解码通道的 argv 泄漏与退出码分类。"""

    def _capture(self, fake_run, raw, runtime=None):
        real = subprocess.run
        subprocess.run = fake_run
        try:
            reader = DshFrameReader(
                raw,
                runtime
                or DshDecoderRuntime(mode=DshDecoderMode.SUBPROCESS,
                                     python_path="C:/synthetic/python.exe"),
            )
            lines = list(reader.iter_lines())
            return reader, lines
        finally:
            subprocess.run = real
        raise AssertionError("unreachable")

    def test_subprocess_argv_carries_no_real_paths_or_ids(self):
        calls = {}

        def fake_run(argv, **kwargs):
            calls["argv"] = list(argv)
            calls["kwargs"] = kwargs
            # 子进程 stdout 是解压后的明文 JSONL 行流（不是压缩帧字节）。
            return SimpleNamespace(
                returncode=0,
                stdout=(fx.plain_header_line() + fx.plain_message_line("z", seq=1)).encode(
                    "utf-8"
                ),
                stderr=b"",
            )

        reader, lines = self._capture(fake_run,
                                      fx.header_frame() + fx.message_frame("z", seq=1))
        argv = calls["argv"]
        self.assertEqual(argv[0], "C:/synthetic/python.exe")
        self.assertEqual(argv[1], "-c")
        self.assertEqual(len(argv), 4)
        joined = json.dumps(argv, ensure_ascii=False)
        for secret in (fx.SESSION, fx.PROJECT, str(self.store), str(self.root)):
            self.assertNotIn(secret, joined)
        self.assertEqual(calls["kwargs"]["input"],
                         fx.header_frame() + fx.message_frame("z", seq=1))
        self.assertEqual(len(lines), 2)
        # 帧界在对端：子进程模式不猜帧数，`frames` 恒为 None（不拿行数顶替）。
        self.assertIsNone(reader.frames)
        self.assertTrue(reader.clean_eof)

    def test_exit_codes_map_to_closed_stop_reasons(self):
        expectations = {
            4: DshStreamStop.DECODER_MISSING.value,
            5: DshStreamStop.DECOMPRESSED_LIMIT.value,
            7: DshStreamStop.DECODER_FAULT.value,
        }

        def make_run(_code):
            def fake_run(argv, **kwargs):
                return SimpleNamespace(returncode=_code, stdout=b"", stderr=b"secret-ish")

            return fake_run

        for code, category in expectations.items():
            with self.assertRaises(DshStreamError) as caught:
                self._capture(make_run(code), fx.header_frame())
            self.assertEqual(caught.exception.category, category)
            self.assertNotIn("secret-ish", str(caught.exception))

    def test_timeout_is_decoder_fault(self):
        def fake_run(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd="decoder", timeout=1)

        with self.assertRaises(DshStreamError) as caught:
            self._capture(fake_run, fx.header_frame())
        self.assertEqual(caught.exception.category, DshStreamStop.DECODER_FAULT.value)


class TestDshLineParser(DshFixtureCase):
    """DSH-02/03/06/07/08 + 通用矩阵⑥⑦：解析器的诚实性。"""

    def test_clean_stream_basics(self):
        records, parser = parse_frames(
            [fx.header_frame(), fx.message_frame(fx.NEEDLE, seq=3),
             fx.user_frame("reply", seq=4)])
        self.assertEqual([record.text for record in records], [fx.NEEDLE, "reply"])
        self.assertEqual([record.source for record in records], [SOURCE_DSH, SOURCE_DSH])
        self.assertEqual([record.location.line_no for record in records], [2, 3])
        self.assertEqual([record.location.ordinal for record in records], [3, 4])
        self.assertEqual([record.location.stream_label for record in records],
                         [fx.LABEL, fx.LABEL])
        self.assertEqual([record.role for record in records], ["assistant", "user"])
        self.assertEqual([record.executor for record in records], [None, None])
        self.assertEqual(issue_map(parser.stats), {IssueCode.KNOWN_NON_TEXT_BLOCK.value: 1})
        self.assertFalse(parser.stats.partial)
        self.assertEqual(parser.header.session_id, fx.SESSION)
        self.assertFalse(parser.header.trusted)
        self.assertTrue(parser.header.seen)

    def test_ordinal_prefers_seq_then_frame_index(self):
        records, _ = parse_frames([fx.message_frame("a", seq=7), fx.message_frame("b", seq=8)])
        self.assertEqual([record.location.ordinal for record in records], [7, 8])
        frame = {"type": "assistant", "time": 1_770_000_000,
                 "data": {"role": "assistant", "content": [{"type": "text", "text": "n"}]}}
        records, parser = parse_lines([json.dumps(frame, ensure_ascii=False)])
        self.assertEqual(records[0].location.ordinal, 0)
        self.assertEqual(records[0].location.line_no, 1)

    def test_content_blocks_join_and_dataless_variants(self):
        frame = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                 "data": {"role": "assistant",
                          "content": [{"type": "text", "text": "one"},
                                      {"type": "text", "text": "two"}]}}
        records, _ = parse_lines([json.dumps(frame, ensure_ascii=False)])
        self.assertEqual([record.text for record in records], ["one\ntwo"])
        content_only = {"type": "assistant", "seq": 2, "time": 1_770_000_000,
                        "content": fx.NEEDLE}
        records, parser = parse_lines([json.dumps(content_only, ensure_ascii=False)])
        self.assertEqual(records, [])
        self.assertEqual(issue_map(parser.stats)[IssueCode.MISSING_MESSAGE_ENVELOPE.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_malformed_lines_closed_codes(self):
        records, parser = parse_lines(
            ['{"nope"', "[1,2]", "  ",
             json.dumps({"type": "assistant", "seq": 9, "time": 1_770_000_000,
                         "data": {"role": "assistant",
                                  "content": [{"type": "text", "text": "n"}]}},
                        ensure_ascii=False)])
        counts = issue_map(parser.stats)
        self.assertEqual(counts[IssueCode.CORRUPT_LINE.value], 1)
        self.assertEqual(counts[IssueCode.LINE_NOT_OBJECT.value], 1)
        self.assertEqual(counts[IssueCode.BLANK_LINE.value], 1)
        self.assertEqual(len(records), 1)
        self.assertTrue(parser.stats.partial)

    def test_time_matrix(self):
        expectations = {
            1_770_000_000: ("exact", "2026-02-02 02:40:00+00:00"),
            1_770_000_000_000: ("exact", "2026-02-02 02:40:00+00:00"),
            "2026-03-01T10:00:00+08:00": ("exact", "2026-03-01 10:00:00+08:00"),
            "2026-03-01T10:00:00Z": ("exact", "2026-03-01 10:00:00+00:00"),
            "2026-03-01T10:00:00": ("no_timezone", None),
            -5: ("invalid", None),
            1: ("invalid", None),
            "1770000000": ("invalid", None),
            None: ("missing", None),
        }
        for value, (quality, stamp) in expectations.items():
            frame = {"type": "assistant", "seq": 1, "time": value,
                     "data": {"role": "assistant",
                              "content": [{"type": "text", "text": "t"}]}}
            records, _ = parse_lines([json.dumps(frame, ensure_ascii=False)])
            self.assertEqual(len(records), 1, value)
            self.assertEqual(records[0].time_quality.value, quality, value)
            rendered = str(records[0].timestamp) if records[0].timestamp else None
            self.assertEqual(rendered, stamp, value)

    def test_role_and_content_gates(self):
        def counts_for(**overrides):
            frame = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                     "data": {"role": "assistant",
                              "content": [{"type": "text", "text": "t"}]}}
            frame.update(overrides)
            records, parser = parse_lines([json.dumps(frame, ensure_ascii=False)])
            return records, issue_map(parser.stats)

        no_role = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                   "data": {"content": [{"type": "text", "text": "t"}]}}
        records, _ = parse_lines([json.dumps(no_role, ensure_ascii=False)])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].role, "assistant")
        records, counts = counts_for(data={"role": "tool_result", "content": []})
        self.assertEqual(records, [])
        self.assertEqual(counts[IssueCode.UNKNOWN_ROLE.value], 1)
        records, counts = counts_for(data={"role": "developer", "content": []})
        self.assertEqual(records, [])
        self.assertEqual(counts[IssueCode.SKIPPED_ROLE.value], 1)
        for content, code in (
            ([{"type": "text"}], IssueCode.INVALID_CONTENT_SHAPE),
            ([{"type": "text", "text": 5}], IssueCode.NON_STRING_TEXT_BLOCK),
        ):
            records, counts = counts_for(data={"role": "assistant", "content": content})
            self.assertEqual(records, [])
            self.assertEqual(counts[code.value], 1)
        bare = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                "data": {"role": "assistant", "content": "bare text"}}
        records, _ = parse_lines([json.dumps(bare, ensure_ascii=False)])
        self.assertEqual([record.text for record in records], ["bare text"])
        thinking = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                    "data": {"role": "assistant",
                             "content": [{"type": "thinking", "thinking": "d"}]}}
        records, parser = parse_lines([json.dumps(thinking, ensure_ascii=False)])
        self.assertEqual(records, [])
        frame_no_data = {"type": "assistant", "seq": 1, "time": 1_770_000_000}
        records, parser = parse_lines([json.dumps(frame_no_data, ensure_ascii=False)])
        self.assertEqual(records, [])

    def test_version_and_header_placement(self):
        records, parser = parse_frames([fx.header_frame(version="v9"),
                                        fx.message_frame("after", seq=2)])
        self.assertTrue(parser.unsupported_version)
        counts = issue_map(parser.stats)
        self.assertEqual(counts[IssueCode.UNSUPPORTED_HEADER_VERSION.value], 1)
        self.assertTrue(parser.stats.partial)
        records, parser = parse_frames([fx.message_frame("t", seq=1),
                                        fx.header_frame()])
        counts = issue_map(parser.stats)
        self.assertFalse(parser.unsupported_version)
        self.assertEqual(counts.get(IssueCode.LATE_SESSION_HEADER.value), 1)
        self.assertEqual(len(records), 1)

    def test_project_quality_and_conflict(self):
        records, parser = parse_frames([fx.header_frame(), fx.message_frame("t", seq=1)])
        self.assertEqual(parser.project_quality, ProjectQuality.UNVERIFIED_HEADER_CWD)
        self.assertEqual(records[0].project_quality, ProjectQuality.UNVERIFIED_HEADER_CWD)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        self.assertFalse(parser.project_conflict)
        records, parser = parse_frames([fx.header_frame(), fx.message_frame("t", seq=1)],
                                       project=fx.OTHER_PROJECT)
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        counts = issue_map(parser.stats)
        self.assertEqual(counts[IssueCode.CONFLICTING_HEADER_CWD.value], 1)
        self.assertEqual(counts[IssueCode.UNKNOWN_PROJECT.value], 1)

    def test_session_identity_conflicts_never_publish_mismatched_rows(self):
        records, parser = parse_frames([fx.header_frame(sessionId="wrong"),
                                        fx.message_frame("t", seq=1)])
        self.assertEqual(records, [])
        self.assertIsNone(parser.session_id)
        counts = issue_map(parser.stats)
        self.assertEqual(counts[IssueCode.HEADER_SESSION_ID_MISMATCH.value], 1)
        self.assertEqual(counts[IssueCode.SESSION_ID_MISMATCH.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_gate_off_keys_land_in_unknown_event(self):
        self.assertFalse(dsh_source.DSH_KNOWN_SURFACE_OP)
        self.assertFalse(dsh_source.DSH_KNOWN_SOURCE_EVENT_SEQS)
        records, parser = parse_frames([fx.header_frame(),
                                        fx.frame({"type": "surfaceOp", "seq": 2,
                                                  "data": {"op": "x"}})])
        self.assertEqual(records, [])
        self.assertEqual(issue_map(parser.stats)[IssueCode.UNKNOWN_EVENT.value], 1)
        self.assertTrue(parser.stats.partial)
        records, parser = parse_frames([fx.header_frame(),
                                        fx.message_frame("t", seq=2, sourceEventSeqs=[3])])
        self.assertEqual(issue_map(parser.stats)[IssueCode.UNKNOWN_EVENT.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_known_non_text_types_do_not_break_completeness(self):
        records, parser = parse_frames([fx.header_frame(),
                                        fx.frame({"type": "usage", "seq": 2,
                                                  "data": {"in": 1}})])
        self.assertEqual(records, [])
        self.assertFalse(parser.stats.partial)
        self.assertEqual(
            issue_map(parser.stats)[IssueCode.KNOWN_NON_TEXT_BLOCK.value], 2)

    def test_text_and_block_caps(self):
        long_frame = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                      "data": {"role": "assistant",
                               "content": [{"type": "text", "text": "x" * 40_000}]}}
        records, parser = parse_lines([json.dumps(long_frame, ensure_ascii=False)])
        self.assertEqual(len(records[0].text), dsh_source.MAX_TEXT_BLOCK_CHARS)
        self.assertEqual(
            issue_map(parser.stats)[IssueCode.TEXT_BLOCK_TRUNCATED.value], 1)
        self.assertIn(IssueCode.TEXT_BLOCK_TRUNCATED, records[0].issues)
        many = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                "data": {"role": "assistant",
                         "content": [{"type": "text", "text": f"b{i}"} for i in range(40)]}}
        records, parser = parse_lines([json.dumps(many, ensure_ascii=False)])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].text.split("\n")[:2], ["b0", "b1"])
        self.assertNotIn("b32", records[0].text.split("\n"))
        self.assertEqual(
            issue_map(parser.stats)[IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED.value], 1)
        big = json.dumps(
            {"type": "assistant", "seq": 1, "time": 1_770_000_000,
             "data": {"role": "assistant",
                      "content": [{"type": "text", "text": "y" * 300_000}]}},
            ensure_ascii=False)
        records, parser = parse_lines([big])
        self.assertEqual(records, [])
        self.assertEqual(issue_map(parser.stats)[IssueCode.LINE_TOO_LARGE.value], 1)

    def test_feed_and_finish_contracts(self):
        parser = DshLineParser(stream_label=fx.LABEL, project=fx.PROJECT,
                               session_id=fx.SESSION)
        # 整个 str/bytes payload 直接 TypeError（不是迭代行序列）；此处用明文行，
        # 不拿压缩帧字节去 decode（那会先炸 UnicodeDecodeError，测不到 feed 的契约）。
        with self.assertRaises(TypeError):
            parser.feed(fx.plain_header_line())
        with self.assertRaises(TypeError):
            parser.feed(fx.plain_header_line().encode("utf-8"))  # type: ignore[arg-type]
        # 行序列可正常 feed：头部行被吸收（0 记录），正文行产 1 条记录。
        self.assertEqual(
            len(list(parser.feed([fx.plain_message_line("z")]))), 1)
        parser.finish()
        parser.finish()
        with self.assertRaises(RuntimeError):
            parser.feed_line(fx.plain_header_line())
        with self.assertRaises(ValueError):
            DshLineParser(source=SOURCE_DSH + "-x")
        # 非字符串 project 不炸构造器：按「未知项目」处理（规范为 None，质量=unknown）。
        lenient = DshLineParser(project=3)  # type: ignore[arg-type]
        self.assertIsNone(lenient._asserted_project)
        # 超长/不合规 stream_label 不截断：整体替换为固定脱敏标签，不外泄原值片段。
        sanitized = DshLineParser(stream_label=fx.LABEL * 100)
        self.assertEqual(sanitized._stream_label, "redacted-stream")

    def test_record_text_is_raw_and_redaction_is_downstream(self):
        sample_text = "sk-abcdefghijklmnop0123456789ABCD"  # synthetic key-shaped fixture
        frame = {"type": "assistant", "seq": 1, "time": 1_770_000_000,
                 "data": {"role": "assistant",
                          "content": [{"type": "text", "text": f"key {sample_text} end"}]}}
        records, _ = parse_lines([json.dumps(frame, ensure_ascii=False)])
        self.assertIn(sample_text, records[0].text)
        masked = getattr(redaction.redact_text(records[0].text), "text", "") or ""
        self.assertNotIn(sample_text, masked)


class TestRunDshFrameFile(DshFixtureCase):
    """DSH-04/05/10/12/13/14：文件级结论、归属诚实、读取拒绝。"""

    def test_clean_file_stays_incomplete_until_attribution_trusts_cwd(self):
        path = self.write_session(
            "clean.zstd",
            fx.header_frame() + fx.message_frame(fx.NEEDLE, seq=3)
            + fx.user_frame("needle two", seq=4))
        outcome = self.run_file(path)
        self.assertFalse(outcome.complete)
        self.assertFalse(outcome.publication_allowed)
        self.assertEqual(outcome.attribution_refusal, "attribution_unknown")
        self.assertEqual(outcome.reason, "stream_incomplete")
        self.assertEqual(outcome.read.lines_read, 2)
        self.assertEqual(outcome.decoder_mode, DshDecoderMode.IN_PROCESS)
        self.assertIsNone(outcome.stream_error)
        self.assertFalse(outcome.unsupported_version)
        public = json.dumps(outcome.as_public_dict(), ensure_ascii=False)
        for secret in (fx.NEEDLE, str(self.store), str(self.proj)):
            self.assertNotIn(secret, public)
        self.assertEqual(
            sorted(outcome.as_public_dict().keys()),
            ["attribution_refusal", "complete", "dsh", "pipeline", "publication_allowed",
             "read", "reason"])

    def test_truncation_after_a_kept_line_is_error_not_clean_end(self):
        path = self.write_session(
            "t.zstd",
            fx.header_frame() + fx.message_frame("needle kept", seq=1)
            + fx.truncated_frame("late"))
        outcome = self.run_file(path)
        self.assertFalse(outcome.complete)
        self.assertEqual(outcome.stream_stop, DshStreamStop.TRUNCATED_FRAME.value)
        self.assertGreaterEqual(outcome.read.lines_read, 1)
        self.assertFalse(outcome.read.complete)

    def test_truncated_only_and_bad_magic_are_file_level_errors(self):
        only = self.run_file(self.write_session("only.zstd", fx.truncated_frame("x")),
                             "only-sess")
        self.assertEqual(only.stream_error, DshStreamStop.TRUNCATED_FRAME.value)
        self.assertEqual(only.read.lines_read, 0)
        self.assertFalse(only.complete)
        bad = self.run_file(self.write_session("bad.zstd", fx.bad_magic_bytes()),
                            "bad-sess")
        self.assertEqual(bad.stream_error, DshStreamStop.BAD_MAGIC.value)
        self.assertEqual(bad.read.lines_read, 0)

    def test_missing_decoder_runtime_is_file_level_error(self):
        path = self.write_session(
            "m.zstd", fx.header_frame() + fx.message_frame("needle", seq=3))
        outcome = self.run_file(path, runtime=DshDecoderRuntime(
            mode=DshDecoderMode.MISSING))
        self.assertEqual(outcome.stream_error, DshStreamStop.DECODER_MISSING.value)
        self.assertEqual(outcome.decoder_mode, DshDecoderMode.MISSING)
        self.assertEqual(outcome.frames, 0)
        self.assertFalse(outcome.publication_allowed)

    def test_relative_path_is_refused_before_open(self):
        outcome = run_dsh_frame_file(self.policy, "s", f"{fx.SESSION}", fx.SESSION,
                                     cwd=fx.PROJECT)
        self.assertEqual(outcome.read_refusal, "path_unsafe")
        self.assertIsNone(outcome.frames)

    def test_path_outside_approved_root_refuses_without_raising(self):
        outside = self.proj / "nope.zstd"
        outside.write_bytes(fx.header_frame())
        outcome = self.run_file(outside, "x")
        self.assertEqual(outcome.read_refusal, "path_out_of_scope")
        self.assertFalse(outcome.complete)

    def test_unapproved_root_denies_at_authorization(self):
        rogue = self.root / "rogue"
        rogue.mkdir(exist_ok=True)
        foreign = rogue / DSH_SESSION_FILE_NAME
        foreign.write_bytes(fx.header_frame())
        with self.assertRaises(PolicyDenied):
            run_dsh_frame_file(build_policy(), "s", str(foreign), fx.SESSION,
                               cwd=fx.PROJECT)

    def test_header_only_file_is_partial_never_complete(self):
        path = self.write_session("hdr.zstd", fx.header_frame(), subdir="h1")
        outcome = self.run_file(path, "h1")
        self.assertFalse(outcome.complete)
        self.assertTrue(outcome.pipeline.parse["partial"])
        self.assertEqual(outcome.read.lines_read, 1)


class TestDshAggregates(DshFixtureCase):
    """DSH-01/09/10 聚合层：固定 dsh 覆盖范围、诚实状态、上下文拒绝不抛不泄。"""

    def test_search_reports_fixed_coverage_and_incomplete_rows(self):
        path = self.write_session(
            "a1.zstd",
            fx.header_frame() + fx.message_frame(fx.NEEDLE, seq=3)
            + fx.user_frame("needle two", seq=4))
        search, _ = self.services(path)
        result = search.search(scope="s", query="needle", sources=("dsh",), limit=10)
        self.assertFalse(result["complete"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["results"], [])
        self.assertEqual(result["reason"], "files_unusable")
        row = result["coverage"][0]
        self.assertEqual(row["source"], SOURCE_DSH)
        self.assertEqual(row["coverage_scope"], DSH_COVERAGE_SCOPE)
        self.assertEqual(row["status"], "incomplete")
        self.assertTrue(row["partial"])
        self.assertEqual(result["coverage_scope"], DSH_COVERAGE_SCOPE)
        file_row = result["files"][0]
        self.assertEqual(file_row["status"], "incomplete")
        self.assertEqual(file_row["reason"], "stream_incomplete")
        self.assertEqual(file_row["file"]["attribution_refusal"], "attribution_unknown")
        self.assertEqual(file_row["file"]["dsh"]["decoder_mode"],
                         DshDecoderMode.IN_PROCESS.value)

    def test_missing_runtime_aggregates_as_error_row(self):
        path = self.write_session(
            "a2.zstd", fx.header_frame() + fx.message_frame("needle", seq=3))
        search, _ = self.services(path, runtime=DshDecoderRuntime(
            mode=DshDecoderMode.MISSING))
        result = search.search(scope="s", query="needle", sources=("dsh",), limit=10)
        file_row = result["files"][0]
        self.assertEqual(file_row["status"], "error")
        self.assertEqual(file_row["reason"], DshStreamStop.DECODER_MISSING.value)
        self.assertEqual(result["reason"], "files_unusable")
        self.assertTrue(result["partial"])
        self.assertFalse(result["complete"])

    def test_truncated_file_stays_incomplete_with_stop_reason(self):
        path = self.write_session(
            "a3.zstd",
            fx.header_frame() + fx.message_frame("needle kept", seq=1)
            + fx.truncated_frame("late"))
        search, _ = self.services(path)
        result = search.search(scope="s", query="needle", sources=("dsh",), limit=10)
        self.assertFalse(result["complete"])
        self.assertTrue(result["partial"])
        self.assertEqual(result["reason"], "files_unusable")
        row = result["coverage"][0]
        self.assertEqual(row["status"], "incomplete")
        self.assertEqual(row["filter_errors"], ["files_unusable", "files_unusable"])

    def test_context_read_refusals_never_raise_or_leak(self):
        path = self.write_session(
            "a4.zstd", fx.header_frame() + fx.message_frame(fx.NEEDLE, seq=1))
        _, context = self.services(path)
        for location in ("session-context:2:1", "ctxref_forged0000", "2",
                         {"line": 2}):
            outcome = context.read(scope="s", source=SOURCE_DSH,
                                   session_id=fx.SESSION, location=location)
            self.assertEqual(outcome.reason, "invalid_argument")
            self.assertEqual(outcome.results, ())
            self.assertEqual(outcome.coverage_scope, "single_approved_file")
            public = json.dumps(outcome.as_public_dict(), ensure_ascii=False)
            self.assertNotIn(fx.NEEDLE, public)
        wrong_source = context.read(scope="s", source="codex",
                                    session_id=fx.SESSION, location="ctxref_abc")
        self.assertEqual(wrong_source.reason, "binding_mismatch")
        self.assertIn("source_mismatch", wrong_source.filter_error_codes)
        wrong_scope = context.read(scope="other", source=SOURCE_DSH,
                                   session_id=fx.SESSION, location="ctxref_abc")
        self.assertEqual(wrong_scope.reason, "binding_mismatch")
        self.assertIn("scope_mismatch", wrong_scope.filter_error_codes)
        search, _ = self.services(path)
        named_other = search.search(scope="s", query="needle", sources=("codex",),
                                    limit=10)
        self.assertEqual(named_other["reason"], "source_unsupported")
        self.assertEqual(named_other["coverage"][0]["status"], "unsupported")

    def test_binding_gates_on_source_and_arguments(self):
        path = self.write_session(
            "a5.zstd", fx.header_frame() + fx.message_frame(fx.NEEDLE, seq=1))
        search, _ = self.services(path)
        bad_source = search.search(scope="s", query="needle",
                                   sources=("codex",), limit=10)
        self.assertEqual(bad_source["stage_reached"], "coordinator")
        self.assertEqual(bad_source["files"], [])
        # scope 不匹配是固定拒绝载荷（rejected=True, reason=scope_mismatch），不是异常：
        # 与 test_file_search.py / test_hermes_aggregate.py 的同契约断言对齐。
        ghost = search.search(scope="ghost", query="needle", sources=("dsh",), limit=10)
        self.assertTrue(ghost.get("rejected"))
        self.assertEqual(ghost.get("reason"), "scope_mismatch")
        self.assertEqual(ghost.get("coverage"), [])
        # 参数形状门：非 LineSourceSpec 的 spec 直接 TypeError（绑定层先判形，后授权）。
        with self.assertRaises(TypeError):
            LineAggregateSearchService(
                policy=self.policy, scope="s", spec=object(),  # type: ignore[arg-type]
                files=(SessionFileRef(path=str(path), session_id=fx.SESSION),))


class TestDshSpecAndDiscovery(DshFixtureCase):
    """§4/§7：spec 登记、make_dsh_spec 与五态发现（未批准根=拒绝，不是状态）。"""

    def test_spec_registration(self):
        self.assertIs(spec_for_source(SOURCE_DSH), DSH_SPEC)
        self.assertEqual(DSH_SPEC.source_id, SOURCE_DSH)
        self.assertEqual(DSH_SPEC.coverage_scope, DSH_COVERAGE_SCOPE)
        self.assertIs(DSH_SPEC.parser_factory, DshLineParser)
        missing = DshDecoderRuntime(mode=DshDecoderMode.MISSING)
        self.assertFalse(missing.usable)
        derived = make_dsh_spec(missing)
        self.assertIsNot(derived, DSH_SPEC)
        self.assertEqual(derived.source_id, SOURCE_DSH)
        self.assertEqual(derived.coverage_scope, DSH_COVERAGE_SCOPE)
        self.assertIs(spec_for_source(SOURCE_DSH), DSH_SPEC)
        self.assertEqual(
            sorted(DSH_SPEC.default_limits.keys()),  # type: ignore[union-attr]
            ["max_line_bytes", "max_lines", "max_total_bytes"])

    def test_discovery_disabled_and_available_and_no_candidates(self):
        self.write_session(
            DSH_SESSION_FILE_NAME, fx.header_frame() + fx.message_frame(fx.NEEDLE, seq=1))
        outcome = discover_dsh_sessions(self.policy, "s", store_root_path="")
        self.assertEqual(outcome.status, DshDiscoveryStatus.DISABLED)
        self.assertEqual(outcome.candidates, ())
        self.assertEqual(outcome.note, "该来源的会话存储根未配置")
        empty = self.root / "empty-disc"
        empty.mkdir(exist_ok=True)
        empty_policy = build_policy((empty,), project_path=self.proj)
        outcome = discover_dsh_sessions(empty_policy, "s", store_root_path=str(empty))
        self.assertEqual(outcome.status, DshDiscoveryStatus.NO_CANDIDATES)
        self.assertEqual(outcome.candidates, ())
        self.assertEqual(outcome.note, "该面无匹配")
        outcome = discover_dsh_sessions(self.policy, "s", store_root_path=str(self.store))
        self.assertEqual(outcome.status, DshDiscoveryStatus.AVAILABLE)
        pairs = [(session_id, name) for session_id, name in outcome.candidates]
        self.assertIn((fx.SESSION, f"{fx.SESSION}/{DSH_SESSION_FILE_NAME}"), pairs)

    def test_discovery_narrowing_on_attribution_miss(self):
        self.write_session(DSH_SESSION_FILE_NAME,
                           fx.header_frame() + fx.message_frame(fx.NEEDLE, seq=1),
                           subdir="n1")
        outcome = discover_dsh_sessions(self.policy, "s",
                                        store_root_path=str(self.store / "n1"),
                                        attribution_project="D:/nope")
        self.assertEqual(outcome.status, DshDiscoveryStatus.NO_CANDIDATES)
        self.assertEqual(outcome.candidates, ())

    def test_discovery_refuses_unapproved_roots(self):
        rogue = self.root / "rogue-disc"
        rogue.mkdir(exist_ok=True)
        with self.assertRaises(PolicyDenied):
            discover_dsh_sessions(build_policy(), "s", store_root_path=str(rogue))

    def test_discovery_note_carries_no_absolute_path_or_home(self):
        outcome = discover_dsh_sessions(self.policy, "s", store_root_path="")
        blob = f"{outcome.status}|{outcome.note}|{outcome.candidates}"
        self.assertNotIn(str(self.store), blob)
        self.assertNotIn(str(Path.home()), blob)


if __name__ == "__main__":
    unittest.main()
