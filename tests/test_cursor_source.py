"""Cursor Agent CLI 来源适配器的合成单测（plan §8.1 CUR-01~13）。

夹具全部来自 ``tests/cursor_synthetic.py``，只写临时目录，绝不触碰真实 ``~/.cursor``。
断言取值来自对解析器实际行为的探针核对（探针已删除），不是对来源格式的猜测：

* 正常流（带外部断言）两行正文、零逐条 issue、``partial`` 为假 —— CUR-01/03/05/06 的对照组。
* 行内归属证据只作候选：首版 ``trusted`` 恒 ``False``（CUR-04，P2-4）；无断言/断言冲突/
  行内 cwd 互相矛盾都不发布可归类记录，降级原因码闭合。
* 派生行按不可采信标记跳过并计数（CUR-07）；不可解释的派生声明另计 ``unknown_event``。
* 固定上限（字节/字符/块数/文本长度）触顶即截断并如实计数（CUR-12）；整行超限不解析。
* 发现四态+AVAILABLE 不合并、未批准根原样抛 PolicyDenied、归属未命中只收窄（CUR-08/09/10）；
  GUI 面零实现且发现不探测（CUR-10）。
* 计数器只含闭合类别与整数，无原文/凭据/绝对个人路径（CUR-13）。
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cursor_synthetic as fx  # noqa: E402

from cross_agent_session_mcp.models import (  # noqa: E402
    IssueCode,
    ProjectQuality,
    TimeQuality,
)
from cross_agent_session_mcp.policy import (  # noqa: E402
    CwdRootGrant,
    PolicyDenied,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.sources.cursor import (  # noqa: E402
    CURSOR_GUI_REASON,
    MAX_CONTENT_BLOCKS_PER_LINE,
    MAX_LINE_BYTES,
    MAX_LINE_CHARS,
    MAX_TEXT_BLOCK_CHARS,
    SOURCE_CURSOR,
    CursorAgentTranscriptLineParser,
    CursorDiscoveryStatus,
    discover_cursor_transcripts,
)


def parse(
    lines: list[str],
    *,
    project: str | None = fx.PROJECT,
    session_id: str | None = fx.SESSION,
    source: str = SOURCE_CURSOR,
    stream_label: str = "transcript.jsonl",
) -> tuple[CursorAgentTranscriptLineParser, list]:
    """静默跑一遍解析器，返回 (parser, 全部记录)。"""
    parser = CursorAgentTranscriptLineParser(
        source=source,
        stream_label=stream_label,
        project=project,
        session_id=session_id,
    )
    records: list = []
    for line in lines:
        records.extend(parser.feed_line(line))
    parser.finish()
    return parser, records


def counts(parser: CursorAgentTranscriptLineParser) -> dict[str, int]:
    return {str(code): count for code, count in parser.stats.issue_counts.items()}


class CursorIdentityTests(unittest.TestCase):
    """CUR-01/02/13：身份常量、逐行接口、来源参数门、超限与终态。"""

    def test_adapter_constants(self) -> None:
        self.assertEqual(SOURCE_CURSOR, "cursor_agent_cli")
        self.assertEqual(MAX_LINE_BYTES, 1_048_576)
        self.assertEqual(MAX_LINE_CHARS, 262_144)
        self.assertEqual(MAX_CONTENT_BLOCKS_PER_LINE, 32)
        self.assertEqual(MAX_TEXT_BLOCK_CHARS, 32_768)

    def test_feed_rejects_whole_payload(self) -> None:
        """CUR-02：把整个 str/bytes 当载荷喂进来一律 TypeError。"""
        parser = CursorAgentTranscriptLineParser(source=SOURCE_CURSOR, stream_label="s")
        with self.assertRaises(TypeError):
            parser.feed("\n".join(fx.normal_stream()))
        with self.assertRaises(TypeError):
            parser.feed(b'{"role":"user","content":"x"}\n')  # type: ignore[arg-type]

    def test_finish_is_idempotent_then_rejects(self) -> None:
        """CUR-02：``finally`` 收尾后不得再喂；finish 本身幂等。"""
        parser = CursorAgentTranscriptLineParser(source=SOURCE_CURSOR, stream_label="s")
        records = list(parser.feed([fx.header_line()]))
        self.assertEqual(records, [])
        parser.finish()
        parser.finish()
        with self.assertRaises(RuntimeError):
            parser.feed_line(fx.header_line())
        with self.assertRaises(RuntimeError):
            parser.feed([fx.header_line()])

    def test_source_argument_gate(self) -> None:
        """CUR-02：构造期 source 只放行 cursor_agent_cli 或省略。"""
        with self.assertRaises(ValueError):
            CursorAgentTranscriptLineParser(source="codex", stream_label="s")
        with self.assertRaises(ValueError):
            CursorAgentTranscriptLineParser(source="cursor", stream_label="s")
        parser = CursorAgentTranscriptLineParser(source=SOURCE_CURSOR, stream_label="s")
        self.assertEqual(parser.stats.lines_seen, 0)


class CursorHappyPathTests(unittest.TestCase):
    """CUR-01/03/05/06：正常流的记录形状、归属、时间与 ordinal。"""

    def setUp(self) -> None:
        self.parser, self.records = parse(fx.normal_stream())

    def test_clean_control_stream(self) -> None:
        self.assertEqual(len(self.records), 2)
        user, assistant = self.records
        self.assertEqual(
            [record.text for record in self.records],
            ["needle in the transcript", "needle reply"],
        )
        self.assertEqual([record.role for record in self.records], ["user", "assistant"])
        self.assertEqual(
            [record.source for record in self.records], [SOURCE_CURSOR, SOURCE_CURSOR]
        )
        self.assertEqual([record.location.line_no for record in self.records], [2, 3])
        self.assertEqual([record.location.ordinal for record in self.records], [0, 0])
        self.assertEqual([record.project for record in self.records], [fx.PROJECT, fx.PROJECT])
        self.assertEqual([record.session_id for record in self.records], [fx.SESSION, fx.SESSION])
        self.assertEqual([record.issues for record in self.records], [(), ()])
        self.assertFalse(self.parser.stats.partial)
        self.assertEqual(self.parser.project, fx.PROJECT)
        self.assertEqual(self.parser.session_id, fx.SESSION)
        self.assertEqual(self.parser.project_quality, ProjectQuality.CALLER_ASSERTED)

    def test_user_query_extraction_and_template_noise_excluded(self) -> None:
        """CUR-03：正文只取 ``<user_query>`` 标签内内容，标签外模板文字与时间外壳都不进。"""
        user = self.records[0]
        self.assertNotIn("<user_query>", user.text)
        self.assertNotIn("<timestamp>", user.text)
        self.assertNotIn("template instructions", user.text)
        self.assertEqual(user.time_quality, TimeQuality.EXACT)
        self.assertIsNotNone(user.timestamp)
        self.assertEqual(user.timestamp.isoformat(), "2026-03-01T10:00:00+00:00")

    def test_message_envelope_and_bare_string_content(self) -> None:
        """CUR-03：``message`` 信封与裸字符串 content 两种形态都能产正文。"""
        _, envelope = parse(
            [fx.message_line("assistant", [fx.text_block("envelope body")], timestamp=fx.TS)]
        )
        self.assertEqual([record.text for record in envelope], ["envelope body"])
        _, bare = parse([fx.assistant_line("plain body string", timestamp=fx.TS)])
        self.assertEqual([record.text for record in bare], ["plain body string"])

    def test_multi_block_ordinals(self) -> None:
        """CUR-03：单行多块各自成记录，ordinal 递增。"""
        _, records = parse(
            [
                fx.assistant_line(
                    [fx.text_block("first"), fx.text_block("second")],
                    timestamp=fx.TS,
                )
            ]
        )
        self.assertEqual([record.text for record in records], ["first", "second"])
        self.assertEqual([record.location.ordinal for record in records], [0, 1])

    def test_header_evidence_is_never_trusted(self) -> None:
        """CUR-04：行内归属快照 ``seen`` 为真但 ``trusted`` 恒 False。"""
        header = self.parser.header
        self.assertTrue(header.seen)
        self.assertFalse(header.trusted)
        self.assertEqual(header.cwd, fx.PROJECT)
        self.assertEqual(header.session_id, fx.SESSION)
        self.assertEqual(header.line_no, 1)


class CursorAttributionTests(unittest.TestCase):
    """CUR-04/08：归属证据等级、矛盾拒发布与粘性降级。"""

    def test_without_asserts_never_publishes_classifiable(self) -> None:
        """CUR-04：只有行内证据时记录逐条带 ``project_unverified``，质量不采信。"""
        parser, records = parse(fx.normal_stream(), project=None, session_id=None)
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertIsNone(record.project)
            self.assertIn(IssueCode.PROJECT_UNVERIFIED, record.issues)
        # 行内 cwd 只进冲突核对，绝不确立可信归属：project 保持 None。
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNVERIFIED_HEADER_CWD)
        self.assertTrue(parser.stats.partial)

    def test_project_assertion_conflict_is_sticky(self) -> None:
        """CUR-08：外部断言与行内 cwd 字面矛盾 ⇒ 粘性冲突，记录不得可归类。"""
        parser, records = parse(fx.normal_stream(), project=fx.OTHER_PROJECT)
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertTrue(records)
        for record in records:
            self.assertIsNone(record.project)
            self.assertIn(IssueCode.PROJECT_UNVERIFIED, record.issues)
        self.assertTrue(parser.stats.partial)

    def test_inline_cwd_conflict_between_lines(self) -> None:
        """两条头部行的 cwd 互斥：后读证据不得悄悄改写已采信归属。"""
        parser, records = parse(
            [
                fx.header_line(),
                fx.header_line(cwd=fx.OTHER_PROJECT),
                fx.assistant_line([fx.text_block("body")], timestamp=fx.TS),
            ]
        )
        self.assertIsNone(parser.project)
        self.assertTrue(parser.project_conflict)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertIn(IssueCode.UNKNOWN_PROJECT.value, counts(parser))
        self.assertTrue(parser.stats.partial)
        for record in records:
            self.assertIsNone(record.project)

    def test_session_id_conflict_rejects_records(self) -> None:
        """行内 sessionId 与断言冲突：记录按矛盾拒产，只留类别计数。"""
        parser, records = parse(
            [
                fx.header_line(),
                fx.assistant_line(
                    [fx.text_block("wrong session")],
                    sessionId="11111111-2222-3333-4444-555555555555",
                    timestamp=fx.TS,
                ),
            ]
        )
        self.assertEqual(records, [])
        self.assertEqual(counts(parser)[IssueCode.SESSION_ID_MISMATCH.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_missing_session_id_degrades(self) -> None:
        """三路证据全缺：记录仍产出但逐条带 ``missing_session_id``，覆盖不完整。"""
        parser, records = parse(
            [fx.assistant_line([fx.text_block("no session evidence")], timestamp=fx.TS)],
            project=None,
            session_id=None,
        )
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].session_id)
        self.assertIn(IssueCode.MISSING_SESSION_ID, records[0].issues)
        self.assertTrue(parser.stats.partial)


class CursorDegradeTests(unittest.TestCase):
    """CUR-06/07/11：未知事件、派生行、损坏行与不可解释形态。"""

    def test_unknown_event_publishes_nothing(self) -> None:
        parser, records = parse([fx.unknown_event_line()])
        self.assertEqual(records, [])
        self.assertEqual(counts(parser)[IssueCode.UNKNOWN_EVENT.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_known_meta_line_is_explained_skip(self) -> None:
        parser, records = parse([fx.meta_line()])
        self.assertEqual(records, [])
        self.assertEqual(counts(parser)[IssueCode.KNOWN_NON_TEXT_BLOCK.value], 1)
        self.assertFalse(parser.stats.partial)

    def test_missing_timestamp_degrades(self) -> None:
        # 用户行的时刻来自 `<timestamp>` 外壳；只有完全无时间证据的记录才计 missing。
        parser, records = parse([fx.header_line(), fx.assistant_line([fx.text_block("no ts")])])
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].timestamp)
        self.assertEqual(records[0].time_quality, TimeQuality.MISSING)
        self.assertIn(IssueCode.MISSING_TIMESTAMP, records[0].issues)
        self.assertTrue(parser.stats.partial)

    def test_timestamp_tag_is_enough_for_exact_time(self) -> None:
        """CUR-03：模板外壳内的时刻就是记录时间（无显式 `timestamp` 字段也算 exact）。"""
        parser, records = parse([fx.header_line(), fx.user_line("no ts here")])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].time_quality, TimeQuality.EXACT)
        self.assertFalse(parser.stats.partial)

    def test_non_string_text_block_downgrades(self) -> None:
        """声称 text 块但正文非字符串：``non_string_text_block``，不冒充空正文。"""
        parser, records = parse(
            [fx.assistant_line([{"type": "text", "text": 123}], timestamp=fx.TS)]
        )
        self.assertEqual(records, [])
        self.assertEqual(counts(parser)[IssueCode.NON_STRING_TEXT_BLOCK.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_sidechain_lines_skipped_and_counted(self) -> None:
        """CUR-07：可解释的派生声明按跳过计数；不可解释声明另计 unknown_event。"""
        parser = CursorAgentTranscriptLineParser(
            source=SOURCE_CURSOR, stream_label="s.jsonl", project=fx.PROJECT, session_id=fx.SESSION
        )
        records: list = []
        for line in [
            fx.header_line(),
            fx.sidechain_line(),
            fx.sidechain_line(isSidechain=False, parentToolUseId="toolu_1"),
            fx.sidechain_line(isSidechain=False, parentToolUseId="x" * 4096),
        ]:
            records.extend(parser.feed_line(line))
        parser.finish()
        self.assertEqual(records, [])
        self.assertEqual(parser.sidechain_skipped_lines, 3)
        # IssueCode 闭合集合无「派生跳过」类：跳过行计 unknown_event，覆盖不完整。
        self.assertEqual(counts(parser)[IssueCode.UNKNOWN_EVENT.value], 3)
        self.assertTrue(parser.stats.partial)

    def test_unexplainable_sidechain_claim_degrades(self) -> None:
        parser, records = parse([fx.sidechain_line(isSidechain=1)])
        self.assertEqual(records, [])
        self.assertEqual(parser.sidechain_skipped_lines, 0)
        self.assertEqual(counts(parser)[IssueCode.UNKNOWN_EVENT.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_blank_and_damaged_lines_are_classified_separately(self) -> None:
        """CUR-11：损坏/非对象/空行三类计数各归各位；空行单独不使覆盖不完整。"""
        parser, records = parse(
            [
                "not json at all",
                "[1, 2, 3]",
                "   ",
                fx.assistant_line([fx.text_block("fine")], timestamp=fx.TS),
            ]
        )
        tally = counts(parser)
        self.assertEqual(tally[IssueCode.CORRUPT_LINE.value], 1)
        self.assertEqual(tally[IssueCode.LINE_NOT_OBJECT.value], 1)
        self.assertEqual(tally[IssueCode.BLANK_LINE.value], 1)
        self.assertEqual(len(records), 1)
        self.assertTrue(parser.stats.partial)
        self.assertEqual(parser.stats.skipped_count, 3)

        blank_parser, blank_records = parse(["", "  "])
        self.assertEqual(blank_records, [])
        self.assertEqual(counts(blank_parser)[IssueCode.BLANK_LINE.value], 2)
        self.assertFalse(blank_parser.stats.partial)

    def test_issue_counts_stay_in_closed_set(self) -> None:
        parser, _ = parse(
            ["~~~", "[]", "", fx.unknown_event_line(), fx.header_line(), fx.user_line("body")]
        )
        for code in parser.stats.issue_counts:
            self.assertIsInstance(code, IssueCode)
        public = parser.stats.as_public_dict()
        self.assertTrue(all(isinstance(value, int) for value in public["issue_counts"].values()))


class CursorLimitTests(unittest.TestCase):
    """CUR-12：固定字节/长度/块数上限。"""

    def test_text_block_char_cap(self) -> None:
        parser, records = parse(
            [fx.assistant_line([fx.text_block("y" * 40_000)], timestamp=fx.TS)]
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0].text), MAX_TEXT_BLOCK_CHARS)
        self.assertIn(IssueCode.TEXT_BLOCK_TRUNCATED, records[0].issues)
        self.assertTrue(parser.stats.partial)

    def test_bare_string_content_same_cap(self) -> None:
        parser, records = parse([fx.assistant_line("z" * 40_000, timestamp=fx.TS)])
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0].text), MAX_TEXT_BLOCK_CHARS)
        self.assertEqual(counts(parser)[IssueCode.TEXT_BLOCK_TRUNCATED.value], 1)

    def test_content_block_cap(self) -> None:
        blocks = [fx.text_block(f"block-{index}") for index in range(MAX_CONTENT_BLOCKS_PER_LINE + 8)]
        parser, records = parse([fx.assistant_line(blocks, timestamp=fx.TS)])
        self.assertEqual(len(records), MAX_CONTENT_BLOCKS_PER_LINE)
        self.assertEqual(
            [record.location.ordinal for record in records],
            list(range(MAX_CONTENT_BLOCKS_PER_LINE)),
        )
        self.assertEqual(counts(parser)[IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED.value], 1)
        self.assertTrue(parser.stats.partial)

    def test_line_byte_and_char_caps_drop_the_line(self) -> None:
        parser, records = parse(
            ['{"type":"system","blob":"' + "x" * (MAX_LINE_BYTES + 64) + '"}']
        )
        self.assertEqual(records, [])
        self.assertEqual(counts(parser)[IssueCode.LINE_TOO_LARGE.value], 1)

        parser2, records2 = parse(
            ['{"role":"assistant","content":[{"type":"text","text":"' + "z" * (MAX_LINE_CHARS + 16) + '"}]}']
        )
        self.assertEqual(records2, [])
        self.assertEqual(counts(parser2)[IssueCode.LINE_TOO_LARGE.value], 1)

    def test_multibyte_cap_is_byte_safe(self) -> None:
        """CUR-13 面：多字节正文按字节判限，不得按字符数放行超限行。"""
        payload = (
            '{"role":"assistant","content":[{"type":"text","text":"'
            + "码" * (MAX_LINE_BYTES // 3 + 8)
            + '"}]}'
        )
        parser, records = parse([payload])
        self.assertEqual(records, [])
        self.assertEqual(counts(parser)[IssueCode.LINE_TOO_LARGE.value], 1)


class CursorDiscoveryTests(unittest.TestCase):
    """CUR-08/09/10：发现只收窄、不改写、读取轴拒绝原样抛出。"""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="cursor-disc-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / "store"
        self.transcripts = fx.write_store(self.store, fx.normal_stream())
        self.project_root = self.root / "project"
        self.project_root.mkdir()
        self.grant = StoreRootGrant(SOURCE_CURSOR, str(self.transcripts))
        # 「根不存在」与「根未批准」是两回事：CUR-08 的未批准根必须原样抛 PolicyDenied，
        # 而 missing-root 用例要拿到 UNAVAILABLE，所以 ghost 根得先授权（只是不落盘）。
        self.ghost_grant = StoreRootGrant(SOURCE_CURSOR, str(self.root / "ghost"))
        self.project_grant = ProjectGrant(
            "p", (CwdRootGrant(str(self.project_root)),)
        )
        self.policy = SessionPolicy(
            scopes=(
                ScopeGrant(
                    scope_id="s",
                    projects=(self.project_grant,),
                    store_roots=(self.grant, self.ghost_grant),
                ),
            )
        )

    def discover(self, path: object, attribution: object = None):
        return discover_cursor_transcripts(
            self.policy, "s", store_root_path=path, attribution_project=attribution
        )

    def test_unconfigured_root_is_disabled(self) -> None:
        for bad in ("", "   ", None, 7):
            result = self.discover(bad)
            self.assertEqual(result.status, CursorDiscoveryStatus.DISABLED)
            self.assertEqual(result.candidates, ())

    def test_missing_root_is_unavailable(self) -> None:
        result = self.discover(str(self.root / "ghost"))
        self.assertEqual(result.status, CursorDiscoveryStatus.UNAVAILABLE)
        self.assertEqual(result.candidates, ())

    def test_readable_root_without_face_is_no_candidates(self) -> None:
        empty_projects = self.root / "empty-store" / "projects"
        empty_projects.mkdir(parents=True)
        other_grant = StoreRootGrant(SOURCE_CURSOR, str(empty_projects))
        policy = SessionPolicy(
            scopes=(
                ScopeGrant(
                    scope_id="s",
                    projects=(self.project_grant,),
                    store_roots=(other_grant,),
                ),
            )
        )
        result = discover_cursor_transcripts(
            policy, "s", store_root_path=str(empty_projects), attribution_project=None
        )
        self.assertEqual(result.status, CursorDiscoveryStatus.NO_CANDIDATES)

    def test_available_candidates_are_relative(self) -> None:
        """CUR-09：候选 = (文件名基名, 相对存储根路径)；绝对个人路径不外发。"""
        result = self.discover(str(self.transcripts))
        self.assertEqual(result.status, CursorDiscoveryStatus.AVAILABLE)
        self.assertEqual(len(result.candidates), 1)
        session_id, relative = result.candidates[0]
        self.assertEqual(session_id, fx.SESSION)
        self.assertTrue(relative.endswith(f"{fx.SESSION}.jsonl"))
        self.assertNotIn(":", relative.replace(str(self.store.resolve()), ""))

    def test_unapproved_root_raises(self) -> None:
        """CUR-08：读取轴未批准 ⇒ 原样抛 PolicyDenied，不降级成空发现。"""
        elsewhere = self.root / "elsewhere" / "agent-transcripts"
        elsewhere.mkdir(parents=True)
        with self.assertRaises(PolicyDenied):
            self.discover(str(elsewhere))

    def test_attribution_miss_only_narrows(self) -> None:
        """CUR-10：归属未命中只收窄候选集，绝不改写发现状态或报读取拒绝。"""
        result = self.discover(str(self.transcripts), attribution="D:/definitely-not-this")
        self.assertEqual(result.status, CursorDiscoveryStatus.NO_CANDIDATES)
        self.assertNotIn("拒绝", result.note or "")

    def test_gui_shell_is_never_probed(self) -> None:
        """CUR-10：GUI 会话壳对发现不可见（零实现；不得被当成无消息会话）。"""
        self.assertEqual(CURSOR_GUI_REASON, "正文格式未核实")
        gui_store = self.root / "gui-store"
        fx.gui_meta_shell(gui_store)
        fx.write_store(gui_store, fx.normal_stream(), session_id="gui-adjacent")
        transcripts = gui_store / "projects" / fx.encode_workspace_dir(fx.PROJECT) / "agent-transcripts"
        gui_grant = StoreRootGrant(SOURCE_CURSOR, str(transcripts))
        policy = SessionPolicy(
            scopes=(
                ScopeGrant(
                    scope_id="s",
                    projects=(self.project_grant,),
                    store_roots=(self.grant, gui_grant),
                ),
            )
        )
        result = discover_cursor_transcripts(
            policy, "s", store_root_path=str(transcripts), attribution_project=None
        )
        self.assertEqual(result.status, CursorDiscoveryStatus.AVAILABLE)
        names = {Path(relative).name for _, relative in result.candidates}
        self.assertNotIn("meta.json", names)


class CursorSafetyTests(unittest.TestCase):
    """CUR-13：对外字典与计数不含原文/凭据/绝对个人路径。"""

    def test_public_stats_contains_no_content(self) -> None:
        parser, _ = parse(
            [
                fx.header_line(),
                fx.assistant_line(
                    [fx.text_block("sk-abcdefghijklmnopqrstuvwxyz012345")], timestamp=fx.TS
                ),
                fx.unknown_event_line(),
            ]
        )
        blob = str(parser.stats.as_public_dict())
        self.assertNotIn("sk-", blob)
        self.assertNotIn(fx.PROJECT, blob)
        self.assertNotIn(fx.SESSION, blob)
        self.assertNotIn("needle", blob)
        self.assertIsInstance(parser.stats.as_public_dict()["issue_counts"], dict)


if __name__ == "__main__":
    unittest.main()
