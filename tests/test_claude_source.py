"""Claude Code CLI 来源适配器的合成单测（TC-MCP-PLN-CLAUDE-01 / 02 / 03 + 共性安全用例）。

本套件**只**在 temp 目录里新建合成 JSONL 与合成目录名，从不打开、复制或读取任何真实
Claude Code 会话、`~/.claude` 目录、凭据或用户配置。断言面：

* **TC-MCP-PLN-CLAUDE-01（正常行与有界降级）**：`user`/`assistant` 正常行产正文，字符串形态的
  `message.content` 整串按单块正文取用（空/纯空白串是「已理解的无正文」）；单行块数上限与单块
  字符上限各自截断并如实计 `content_block_limit_exceeded` / `text_block_truncated`；凡不是显式
  `text` 的块（含 `tool_use`/`tool_result`/`thinking`/`image`）一律按未核实形态计
  `unknown_block_type` 并使覆盖不完整——「已理解的省略」豁免已废弃；缺 `cwd` 的行按
  `project_unverified`/`unknown_project` 交代；行内 `cwd` 与外部项目断言或已采信项目矛盾时粘性
  降级，声明了却给不出可用值（超长/非字符串/同层别名矛盾）计 `invalid_header_cwd`，且
  **已产出的记录不回改**。
* **TC-MCP-PLN-CLAUDE-02（角色、形态与标识）**：正文只在 `TEXT_ROLES` 上产出，`message.role`
  与行 `type` 冲突或角色未核实一律拒产；除已核实形态外的行类型（含无 `type` 的行）按不认识
  处理并计 partial，不套用宽识分支；会话标识三路核对（`<session-id>.jsonl` 文件名断言、
  `system` 头部、行内值），路径形态值过闭合形态门 → 整体判否 + 粘性拒产；标识字段被写入
  路径形态时构造期即 `ValueError`；同层别名键（`session_id`/`sessionId`、`cwd`/`working_directory`、
  `version`/`v`）取值互斥时不先到先得，按「有值但不可采信」降级。
* **TC-MCP-PLN-CLAUDE-03（派生/子代理会话）**：`isSidechain` 为真或带非空 `parent_tool_use_id`
  的行不产正文、不确立会话身份、不采信其头部字段，计数由 `sidechain_skipped_lines` 明示，
  并且**不**否定整条流的归属（与「矛盾行拒收」分列为两种结论）。父引用非字符串、超长或
  同层别名互斥时同样按派生行跳过：不可核实的派生标记不得当成「没有父引用」。
* **共性安全用例**：单行字节/字符超限整行丢弃记 `line_too_large`；非 UTF-8 与畸形 JSON 记
  `corrupt_line`；非对象行记 `line_not_object`；空行只记 `blank_line` 且不使覆盖不完整；
  整流行数上限粘性停止；`feed` 拒整块载荷、终态后拒再喂；对外字典只有整数与固定类别。
* **发现侧衔接**：temp 目录内合成 `<uuid>.jsonl`，断言取自文件名的会话标识能与头部核对；
  有损的编码目录名不是本层的入参（不能据此反推项目）。
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cross_agent_session_mcp.models import (
    NON_PARTIAL_ISSUES,
    IssueCode,
    ProjectQuality,
    TimeQuality,
)
from cross_agent_session_mcp.sources import claude as C

SESSION = "5f0d4c1e-2a3b-4c5d-8e9f-0a1b2c3d4e5f"
OTHER_SESSION = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
PROJECT = "D:/work/alpha"
OTHER_PROJECT = "D:/work/beta"
LABEL = "session-context"
TS = "2026-11-03T10:00:00.000Z"


def _init_line(**fields: object) -> str:
    """合成 `system`/`init` 会话起点行；`**fields` 覆盖或追加键（`None` 值表示显式声明空值）。"""
    payload: dict[str, object] = {
        "type": "system",
        "subtype": "init",
        "session_id": SESSION,
        "cwd": PROJECT,
        "version": "1.2.3",
    }
    payload.update(fields)
    return json.dumps(payload)


def _msg_line(
    role: str,
    content: object,
    **fields: object,
) -> str:
    """合成消息行：行 `type` 即角色，正文在 `message.content`。"""
    payload: dict[str, object] = {
        "type": role,
        "session_id": SESSION,
        "cwd": PROJECT,
        "timestamp": TS,
        "message": {"role": role, "content": content},
    }
    payload.update(fields)
    return json.dumps(payload)


def _text(text: str) -> dict[str, str]:
    return {"type": "text", "text": text}


def _drop(line: str, *keys: str) -> str:
    """删掉若干顶层键：用于区分「没声明该字段」与「声明了空值」两种降级。"""
    payload = json.loads(line)
    for key in keys:
        payload.pop(key, None)
    return json.dumps(payload)


def _parse(
    lines: Iterable[str | bytes],
    **kwargs: Any,
) -> tuple[C.ClaudeLineParser, tuple]:
    parser = C.ClaudeLineParser(stream_label=LABEL, **kwargs)
    return parser, tuple(parser.feed(lines))


def _count(parser: C.ClaudeLineParser, issue: IssueCode) -> int:
    return parser.stats.issue_counts.get(issue, 0)


class ShapeTests(unittest.TestCase):
    """构造与生命周期契约：来源钉死、断言门、终态不可复用。"""

    def test_records_carry_the_fixed_source_and_no_inferred_executor(self) -> None:
        parser, records = _parse(
            [_init_line(), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        for record in records:
            self.assertEqual(record.source, C.SOURCE_CLAUDE)
            self.assertEqual(record.source, "claude_code_cli")
            # 模型名/执行者证据未经核对：不得由角色或来源推断填充。
            self.assertIsNone(record.executor)
        self.assertNotIn("hello", json.dumps(parser.stats.as_public_dict()))

    def test_rejects_a_different_source_value(self) -> None:
        with self.assertRaises(ValueError) as caught:
            C.ClaudeLineParser(source="pi")
        self.assertIn("claude_code_cli", str(caught.exception))

    def test_source_argument_keeps_the_call_shape_only(self) -> None:
        # `source` 只为与其它适配器同形：`None` 与固定值都可，产出仍钉死为同一来源。
        parser = C.ClaudeLineParser(stream_label=LABEL, source=None)
        records = tuple(parser.feed([_init_line(), _msg_line("user", [_text("hi")])]))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source, C.SOURCE_CLAUDE)

    def test_source_constructor_rejects_non_string_and_invalid_values(self) -> None:
        # 旧门走 `_as_text`：非字符串与超长串都归一为 `None`，绕过等值检查而静默放行。
        for bad in (123, True, ["claude_code_cli"], "other", "   ", "x" * 100):
            with self.subTest(source=bad), self.assertRaises(ValueError):
                C.ClaudeLineParser(stream_label=LABEL, source=bad)  # type: ignore[arg-type]
        with self.assertRaises(ValueError) as caught:
            C.ClaudeLineParser(stream_label=LABEL, source="other")
        self.assertIn("claude_code_cli", str(caught.exception))

    def test_asserted_session_id_must_pass_the_closed_shape_gate(self) -> None:
        for bad in ("D:/work/sessions/abc", "C:\\Users\\x\\a.jsonl", "abc def", "abc/bcd"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                C.ClaudeLineParser(session_id=bad)

    def test_asserted_project_must_be_a_usable_string(self) -> None:
        with self.assertRaises(ValueError):
            C.ClaudeLineParser(project="   ")
        with self.assertRaises(ValueError):
            C.ClaudeLineParser(project="p" * (C.MAX_PROJECT_VALUE_CHARS + 1))

    def test_project_accepts_path_shape_that_the_session_gate_refuses(self) -> None:
        parser, _ = _parse([_init_line(cwd=PROJECT)], project=PROJECT)
        self.assertEqual(parser.asserted_project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.TRUSTED_HEADER_CWD)

    def test_feed_refuses_a_whole_payload(self) -> None:
        parser = C.ClaudeLineParser(stream_label=LABEL)
        with self.assertRaises(TypeError):
            parser.feed(_init_line() + "\n" + _msg_line("user", [_text("a")]))
        with self.assertRaises(TypeError):
            parser.feed(b'{"type":"user"}\n')  # type: ignore[arg-type]

    def test_finished_parser_refuses_more_lines(self) -> None:
        parser, _ = _parse([_init_line()])
        parser.finish()
        with self.assertRaises(RuntimeError):
            parser.feed([_msg_line("user", [_text("a")])])
        with self.assertRaises(RuntimeError):
            parser.feed_line(_msg_line("user", [_text("a")]))

    def test_finish_is_idempotent(self) -> None:
        parser = C.ClaudeLineParser(stream_label=LABEL)
        parser.finish()
        parser.finish()
        self.assertEqual(_count(parser, IssueCode.NO_SESSION_HEADER), 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)

    def test_the_lossy_encoded_directory_name_is_not_an_input(self) -> None:
        # 编码目录名有损（分隔符被替换），本层根本不接收它，因此无法据此反推项目。
        with self.assertRaises(TypeError):
            C.ClaudeLineParser(encoded_dir_name="D--work-alpha")  # type: ignore[call-arg]


class TC1NormalStreamTests(unittest.TestCase):
    """TC-MCP-PLN-CLAUDE-01：正常行、块/字符双限、非文本块计降级、字符串正文、cwd 缺失与矛盾。"""

    def test_clean_stream_is_complete_and_verified(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("hello")]),
                _msg_line("assistant", [_text("hi there")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual([r.role for r in records], ["user", "assistant"])
        self.assertEqual([r.text for r in records], ["hello", "hi there"])
        self.assertEqual(parser.session_id, SESSION)
        self.assertFalse(parser.session_id_conflict)
        self.assertEqual(parser.project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.TRUSTED_HEADER_CWD)
        for record in records:
            self.assertEqual(record.session_id, SESSION)
            self.assertEqual(record.project, PROJECT)
            self.assertEqual(record.project_quality, ProjectQuality.TRUSTED_HEADER_CWD)
            self.assertEqual(record.time_quality, TimeQuality.EXACT)
            self.assertEqual(record.issues, ())
            self.assertIsNotNone(record.timestamp)
            self.assertEqual(record.timestamp.year, 2026)
        self.assertEqual(parser.stats.lines_seen, 3)
        self.assertEqual(parser.stats.lines_with_records, 2)
        self.assertEqual(parser.stats.records_emitted, 2)
        self.assertEqual(parser.stats.issue_counts, {})
        self.assertFalse(parser.stats.partial)
        self.assertEqual(parser.header.line_no, 1)
        self.assertTrue(parser.header.trusted)

    def test_location_refs_carry_line_and_ordinal(self) -> None:
        _, records = _parse(
            [_init_line(), _msg_line("assistant", [_text("one"), _text("two")])],
            session_id=SESSION,
        )
        self.assertEqual(
            [r.location.to_ref() for r in records],
            [f"jsonl:{LABEL}#L2", f"jsonl:{LABEL}#L2+1"],
        )

    def test_block_count_limit_keeps_a_prefix_and_reports_the_loss(self) -> None:
        blocks = [_text(f"b{index}") for index in range(C.MAX_CONTENT_BLOCKS_PER_LINE + 6)]
        parser, records = _parse(
            [_init_line(), _msg_line("user", blocks)],
            session_id=SESSION,
        )
        self.assertEqual(len(records), C.MAX_CONTENT_BLOCKS_PER_LINE)
        self.assertEqual(_count(parser, IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED), 1)
        self.assertEqual(parser.stats.lines_with_records, 1)
        self.assertTrue(parser.stats.partial)
        self.assertIn(
            IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED,
            records[0].issues,
        )

    def test_long_block_is_truncated_without_ellipsis(self) -> None:
        long = "x" * (C.MAX_TEXT_BLOCK_CHARS + 500)
        parser, records = _parse(
            [_init_line(), _msg_line("assistant", [_text(long)])],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0].text), C.MAX_TEXT_BLOCK_CHARS)
        self.assertFalse(records[0].text.endswith("..."))
        self.assertEqual(_count(parser, IssueCode.TEXT_BLOCK_TRUNCATED), 1)
        self.assertTrue(parser.stats.partial)
        self.assertIn(IssueCode.TEXT_BLOCK_TRUNCATED, records[0].issues)

    def test_known_non_text_blocks_produce_partial_coverage(self) -> None:
        # 非文本块不再豁免：旧的 `known_non_text_block` 属 NON_PARTIAL_ISSUES，使纯工具/推理行
        # 被伪报成「完整扫描且无匹配」；未与真实数据核对的形态一律按不认识处理并计降级。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line(
                    "assistant",
                    [
                        {"type": "thinking", "thinking": "reasoning"},
                        {"type": "tool_use", "id": "toolu_1", "name": "Bash"},
                        {"type": "image", "source": {"data": "…"}},
                    ],
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_BLOCK_TYPE), 3)
        self.assertEqual(_count(parser, IssueCode.KNOWN_NON_TEXT_BLOCK), 0)
        # 内容确实被丢弃（lost_content）：不得记成「已理解的无正文」，也不得因
        # 首尾都是非文本块而双计。
        self.assertEqual(_count(parser, IssueCode.NO_TEXT_CONTENT), 0)
        self.assertTrue(parser.stats.partial)
        self.assertNotIn(IssueCode.UNKNOWN_BLOCK_TYPE, NON_PARTIAL_ISSUES)
        self.assertTrue(
            {IssueCode.NO_TEXT_CONTENT, IssueCode.BLANK_LINE} <= NON_PARTIAL_ISSUES
        )

    def test_tool_result_in_user_message_marks_the_coverage_incomplete(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line(
                    "user",
                    [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}],
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_BLOCK_TYPE), 1)
        self.assertEqual(_count(parser, IssueCode.KNOWN_NON_TEXT_BLOCK), 0)
        self.assertTrue(parser.stats.partial)

    def test_string_content_is_extracted_as_single_text_block(self) -> None:
        # 字符串形态 `content` 是 stream-json 的合法纯文本写法：整串按单块正文取用，
        # 不再当成不可解释形状被丢。
        parser, records = _parse(
            [_init_line(), _msg_line("user", "plain string content")],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].text, "plain string content")
        self.assertEqual(records[0].issues, ())
        self.assertEqual(_count(parser, IssueCode.INVALID_CONTENT_SHAPE), 0)
        self.assertEqual(parser.stats.records_emitted, 1)
        self.assertEqual(parser.stats.lines_with_records, 1)
        self.assertFalse(parser.stats.partial)

    def test_blank_string_content_is_understood_not_lossy(self) -> None:
        parser, records = _parse(
            [_init_line(), _msg_line("user", "   ")],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.NO_TEXT_CONTENT), 1)
        self.assertEqual(_count(parser, IssueCode.INVALID_CONTENT_SHAPE), 0)
        self.assertFalse(parser.stats.partial)

    def test_oversized_string_content_shares_the_block_char_cap(self) -> None:
        # 字符串形态走与数组内 `text` 块同一道 `MAX_TEXT_BLOCK_CHARS` 截断与原因码契约。
        long = "y" * (C.MAX_TEXT_BLOCK_CHARS + 400)
        parser, records = _parse(
            [_init_line(), _msg_line("assistant", long)],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0].text), C.MAX_TEXT_BLOCK_CHARS)
        self.assertFalse(records[0].text.endswith("..."))
        self.assertEqual(_count(parser, IssueCode.TEXT_BLOCK_TRUNCATED), 1)
        self.assertIn(IssueCode.TEXT_BLOCK_TRUNCATED, records[0].issues)
        self.assertTrue(parser.stats.partial)

    def test_unregistered_block_type_marks_the_coverage_incomplete(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line(
                    "assistant",
                    [_text("kept"), {"type": "redacted_thinking", "data": "…"}],
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_BLOCK_TYPE), 1)
        # 同批坏块不能只活在统计里：保留下来的记录必须自己说明内容丢过。
        self.assertIn(IssueCode.UNKNOWN_BLOCK_TYPE, records[0].issues)
        self.assertEqual(
            records[0].issues.count(IssueCode.UNKNOWN_BLOCK_TYPE), 1
        )
        self.assertTrue(parser.stats.partial)

    def test_bad_blocks_are_reported_on_every_record_of_the_same_message(self) -> None:
        # 一块坏块 + 多块合法正文：只产一条记录时，同批坏块不得在记录上隐身。
        line = _msg_line(
            "assistant",
            [
                _text("first"),
                _text("second"),
                {"type": "thinking", "thinking": "…"},
                {"type": "redacted_thinking", "data": "…"},
                "not-a-block",
                {"type": "text"},
                {"type": "text", "text": 42},
            ],
        )
        parser, records = _parse([_init_line(), line], session_id=SESSION)
        self.assertEqual(len(records), 2)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_BLOCK_TYPE), 2)
        self.assertEqual(_count(parser, IssueCode.INVALID_CONTENT_SHAPE), 2)
        self.assertEqual(_count(parser, IssueCode.NON_STRING_TEXT_BLOCK), 1)
        self.assertEqual(_count(parser, IssueCode.NO_TEXT_CONTENT), 0)
        self.assertEqual(parser.stats.records_emitted, 2)
        self.assertEqual(parser.stats.lines_with_records, 1)
        for record in records:
            for code in (
                IssueCode.UNKNOWN_BLOCK_TYPE,
                IssueCode.INVALID_CONTENT_SHAPE,
                IssueCode.NON_STRING_TEXT_BLOCK,
            ):
                self.assertIn(code, record.issues)
                # 统计按每次出现计，记录只按首次出现带一次，不按出现次数放大。
                self.assertEqual(record.issues.count(code), 1)
        # 干净头部与外部断言下没有其他降级码，因此记录码集合就是本行内容码的
        # 首次出现顺序。
        self.assertEqual(
            records[0].issues,
            (
                IssueCode.UNKNOWN_BLOCK_TYPE,
                IssueCode.INVALID_CONTENT_SHAPE,
                IssueCode.NON_STRING_TEXT_BLOCK,
            ),
        )
        self.assertEqual(records[0].issues, records[1].issues)
        self.assertTrue(parser.stats.partial)

    def test_a_line_of_only_bad_blocks_produces_no_records_and_no_empty_note(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("assistant", [{"type": "thinking"}, "nope"]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(parser.stats.records_emitted, 0)
        self.assertEqual(_count(parser, IssueCode.NO_TEXT_CONTENT), 0)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_BLOCK_TYPE), 1)
        self.assertEqual(_count(parser, IssueCode.INVALID_CONTENT_SHAPE), 1)
        self.assertTrue(parser.stats.partial)

    def test_two_truncated_blocks_count_twice_but_note_once_per_record(self) -> None:
        long = "z" * (C.MAX_TEXT_BLOCK_CHARS + 400)
        parser, records = _parse(
            [_init_line(), _msg_line("assistant", [_text(long), _text(long)])],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(_count(parser, IssueCode.TEXT_BLOCK_TRUNCATED), 2)
        for record in records:
            self.assertEqual(len(record.text), C.MAX_TEXT_BLOCK_CHARS)
            self.assertEqual(
                record.issues.count(IssueCode.TEXT_BLOCK_TRUNCATED), 1
            )

    def test_text_block_with_non_string_or_missing_body(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("assistant", [{"type": "text", "text": 42}]),
                _msg_line("assistant", [{"type": "text"}]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.NON_STRING_TEXT_BLOCK), 1)
        self.assertEqual(_count(parser, IssueCode.INVALID_CONTENT_SHAPE), 1)
        self.assertTrue(parser.stats.partial)
        self.assertEqual(parser.stats.records_emitted, 0)

    def test_unclaimed_content_shapes_are_not_read_as_empty(self) -> None:
        # 缺 `content` / 只有 `text` 别名键都是未核实的简写形态：记形状不可解释，不记「内容为空」。
        # （裸字符串不再是拒收形态：它是合法的纯文本写法，见
        # test_string_content_is_extracted_as_single_text_block。）
        parser, records = _parse(
            [
                _init_line(),
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "message": {"role": "user", "text": "alias form"},
                    }
                ),
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "message": {"role": "user"},
                    }
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.INVALID_CONTENT_SHAPE), 2)
        self.assertEqual(_count(parser, IssueCode.NO_TEXT_CONTENT), 0)
        self.assertTrue(parser.stats.partial)

    def test_empty_content_array_is_understood_not_lossy(self) -> None:
        parser, records = _parse(
            [_init_line(), _msg_line("assistant", [])],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.NO_TEXT_CONTENT), 1)
        self.assertFalse(parser.stats.partial)

    def test_line_without_cwd_and_without_any_project_evidence(self) -> None:
        parser, records = _parse(
            [
                _init_line(cwd=None),
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "timestamp": TS,
                        "message": {"role": "user", "content": [_text("no cwd here")]},
                    }
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].project)
        self.assertEqual(records[0].project_quality, ProjectQuality.UNKNOWN)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.INVALID_HEADER_CWD), 1)
        self.assertEqual(_count(parser, IssueCode.PROJECT_UNVERIFIED), 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)
        self.assertFalse(parser.project_conflict)
        self.assertTrue(parser.stats.partial)

    def test_message_cwd_never_becomes_an_unreviewed_project(self) -> None:
        parser, records = _parse(
            [
                _msg_line("user", [_text("hello")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNVERIFIED_HEADER_CWD)
        self.assertEqual(records[0].project_quality, ProjectQuality.UNVERIFIED_HEADER_CWD)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.NO_SESSION_HEADER), 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)

    def test_line_cwd_conflicting_with_trusted_header_project(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("first")]),
                _msg_line("assistant", [_text("second")], cwd=OTHER_PROJECT),
                _msg_line("user", [_text("third")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].project, PROJECT)
        self.assertEqual(records[0].issues, ())
        self.assertIsNone(records[1].project)
        self.assertEqual(records[1].project_quality, ProjectQuality.UNKNOWN)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[1].issues)
        self.assertIsNone(records[2].project)
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        self.assertTrue(parser.stats.partial)

    def test_line_cwd_oversized_and_invalid_notes_degradation(self) -> None:
        # 行内声明了 cwd 却给不出可用值（超 `MAX_PROJECT_VALUE_CHARS`、非字符串）时必留下
        # 降级计数，不得静默返回而让不可控输入在计数里零代价消失。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line(
                    "user",
                    [_text("first")],
                    cwd="p" * (C.MAX_PROJECT_VALUE_CHARS + 1),
                ),
                _msg_line("assistant", [_text("second")], cwd={"path": PROJECT}),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(_count(parser, IssueCode.INVALID_HEADER_CWD), 2)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 0)
        self.assertFalse(parser.project_conflict)
        self.assertEqual(parser.project, PROJECT)
        self.assertTrue(parser.stats.partial)

    def test_line_cwd_conflicts_with_asserted_project_and_multiple_lines(self) -> None:
        # 基准判定顺序 `_asserted_project` → `_project` → `_header.cwd` → `_observed_line_cwd`：
        # 外部项目断言排在最前，无头部时行内 cwd 仍与断言字面核对；两条消息行的 cwd 互斥（无
        # 任何头部证据）同样必判矛盾。两种情形都置位粘性 `project_conflict` 并降级归属。
        with self.subTest(baseline="caller assertion"):
            self._assert_conflicting_line_cwd_against_the_external_assertion()
        with self.subTest(baseline="observed line cwd"):
            self._assert_two_message_lines_with_conflicting_cwd_are_sticky()

    def _assert_conflicting_line_cwd_against_the_external_assertion(self) -> None:
        parser, records = _parse(
            [_msg_line("user", [_text("hello")], cwd=OTHER_PROJECT)],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].project)
        self.assertEqual(records[0].project_quality, ProjectQuality.UNKNOWN)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)
        self.assertTrue(parser.stats.partial)

    def _assert_two_message_lines_with_conflicting_cwd_are_sticky(self) -> None:
        # 首条记录先产且仍可按当时未确立的归属交代，第二条起逐条 `project_unverified`，
        # 整流 `finish()` 计 `unknown_project`；已产出的记录不回改。
        parser, records = _parse(
            [
                _msg_line("user", [_text("first")], cwd=PROJECT),
                _msg_line("assistant", [_text("second")], cwd=OTHER_PROJECT),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 2)
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        # 首条记录产出时也没得已采信项目（行内 cwd 不当头部用），因此两条都逐条交代。
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[1].issues)
        self.assertIn(IssueCode.NO_SESSION_HEADER, parser.stats.issue_counts)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)
        self.assertTrue(parser.stats.partial)

    def test_contradicting_cwd_aliases_in_the_header_are_not_adopted(self) -> None:
        # 同层 `cwd` 与每个别名（camel/snake）取值互斥时都不先到先得：按「有值但不可采信」
        # 降级，且这种形态矛盾不是「两个互斥的可用 cwd」，不置项目冲突。
        for alias in ("workingDirectory", "working_directory"):
            with self.subTest(alias=alias):
                parser, records = _parse(
                    [
                        _init_line(**{alias: OTHER_PROJECT}),
                        _msg_line("user", [_text("hello")]),
                    ],
                    session_id=SESSION,
                )
                self.assertFalse(parser.header.trusted)
                self.assertIsNone(parser.header.cwd)
                self.assertEqual(_count(parser, IssueCode.INVALID_HEADER_CWD), 1)
                self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 0)
                self.assertFalse(parser.project_conflict)
                self.assertEqual(len(records), 1)
                self.assertIsNone(parser.project)
                self.assertEqual(
                    records[0].project_quality,
                    ProjectQuality.UNVERIFIED_HEADER_CWD,
                )

    def test_contradicting_version_aliases_are_not_adopted(self) -> None:
        parser, _ = _parse(
            [_init_line(v="2.0.0")], session_id=SESSION, project=PROJECT
        )
        self.assertFalse(parser.header.trusted)
        self.assertEqual(_count(parser, IssueCode.UNSUPPORTED_HEADER_VERSION), 1)
        self.assertEqual(_count(parser, IssueCode.MISSING_HEADER_VERSION), 0)

    def test_header_cwd_conflicting_with_the_external_assertion(self) -> None:
        parser, records = _parse(
            [_init_line(), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
            project=OTHER_PROJECT,
        )
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].project)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        # 项目矛盾必须留下明确的原因码，只靠逐条 `project_unverified` 与收尾
        # `unknown_project` 交代不足以说明「发生过矛盾」。
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)

    def test_a_header_cwd_conflicts_with_a_line_cwd_seen_earlier(self) -> None:
        # 首个 init 晚于消息时，消息先声明的 cwd 仍是矛盾基准：不能因为「还没有头部」
        # 就把后来的 init cwd 直接采信而不计矛盾（判否通道与 `trusted` 无关）。
        for line_cwd, header_cwd in (
            (PROJECT, OTHER_PROJECT),
            (OTHER_PROJECT, PROJECT),
        ):
            with self.subTest(line_cwd=line_cwd):
                parser, records = _parse(
                    [
                        _msg_line("user", [_text("first")], cwd=line_cwd),
                        _init_line(cwd=header_cwd),
                        _drop(_msg_line("assistant", [_text("third")]), "cwd"),
                    ],
                    session_id=SESSION,
                )
                self.assertEqual(len(records), 2)
                self.assertTrue(parser.project_conflict)
                self.assertIsNone(parser.project)
                self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
                self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
                self.assertFalse(parser.session_id_conflict)
                # 已产出的首条记录不回改：它记的是当时尚未确立的归属。
                self.assertIsNone(records[0].project)
                self.assertEqual(
                    records[0].project_quality,
                    ProjectQuality.UNVERIFIED_HEADER_CWD,
                )
                self.assertNotIn(
                    IssueCode.CONFLICTING_HEADER_CWD, records[0].issues
                )
                self.assertIsNone(records[1].project)
                self.assertEqual(
                    records[1].project_quality, ProjectQuality.UNKNOWN
                )
                self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[1].issues)
                self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)

    def test_a_header_cwd_agreeing_with_an_earlier_line_cwd_is_not_a_conflict(self) -> None:
        # 对照：同一个 cwd 先出现在消息行、后出现在 init，是「对得上」而不是矛盾；
        # 此时头部才升格为可信项目，且不重复计任何矛盾码。
        parser, records = _parse(
            [
                _msg_line("user", [_text("first")]),
                _init_line(),
                _drop(_msg_line("assistant", [_text("third")]), "cwd"),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 2)
        self.assertFalse(parser.project_conflict)
        self.assertEqual(parser.project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.TRUSTED_HEADER_CWD)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 0)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 0)
        # 首条记录产出时项目尚未确立，因此逐条交代一次；后续记录已按可信头部交代。
        self.assertEqual(
            _count(parser, IssueCode.PROJECT_UNVERIFIED), 1
        )
        self.assertIsNone(records[0].project)
        self.assertEqual(records[1].project, PROJECT)
        self.assertEqual(records[1].issues, ())

    def test_an_untrusted_header_cwd_still_conflicts_with_the_external_assertion(self) -> None:
        # 缺版本的 init 只能降低采信度，不能把一份合法的 cwd 声明从矛盾核对里摸出去。
        parser, records = _parse(
            [
                _drop(_init_line(cwd=OTHER_PROJECT), "version"),
                _msg_line("user", [_text("hello")], cwd=PROJECT),
            ],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertEqual(_count(parser, IssueCode.MISSING_HEADER_VERSION), 1)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertFalse(parser.session_id_conflict)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].project)
        self.assertEqual(records[0].project_quality, ProjectQuality.UNKNOWN)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)

    def test_an_untrusted_header_cwd_agreeing_with_the_assertion_stays_caller_asserted(self) -> None:
        # 与断言一致的合法 `cwd` 只能确认「没矛盾」，不能给未信任的头声明抢下
        # `TRUSTED_HEADER_CWD`：项目归属仍是调用方断言提供的。
        parser, records = _parse(
            [
                _drop(_init_line(cwd=PROJECT), "version"),
                _msg_line("user", [_text("hello")]),
            ],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertEqual(_count(parser, IssueCode.MISSING_HEADER_VERSION), 1)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 0)
        self.assertEqual(_count(parser, IssueCode.INVALID_HEADER_CWD), 0)
        self.assertFalse(parser.project_conflict)
        self.assertFalse(parser.session_id_conflict)
        self.assertEqual(parser.project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.CALLER_ASSERTED)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].project, PROJECT)
        self.assertEqual(records[0].project_quality, ProjectQuality.CALLER_ASSERTED)
        self.assertNotIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        # 不信任的头 ID 不单独提供可信计数：三路证据（外部断言 + 行内 ID）仍然够。
        self.assertNotIn(IssueCode.SESSION_ID_UNVERIFIED, records[0].issues)

    def test_a_late_conflicting_header_cannot_reclaim_the_caller_assertion(self) -> None:
        # 重复 init 的项目矛盾不能靠外部断言或后续一致的消息行恢复到 `CALLER_ASSERTED`。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("first")]),
                _init_line(cwd=OTHER_PROJECT),
                _msg_line("assistant", [_text("second")], cwd=PROJECT),
            ],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertEqual(_count(parser, IssueCode.LATE_SESSION_HEADER), 1)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].project, PROJECT)
        self.assertEqual(records[0].issues, ())
        self.assertIsNone(records[1].project)
        self.assertEqual(records[1].project_quality, ProjectQuality.UNKNOWN)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[1].issues)

    def test_a_conflicting_header_cwd_degrades_before_any_record_exists(self) -> None:
        # 单独喂一条 init 就要能立刻看到矛盾码与不完整覆盖；后续与断言一致的消息行
        # 不能把项目「恢复」回来（粘性），收尾再计一次 `unknown_project`。
        parser = C.ClaudeLineParser(stream_label=LABEL, session_id=SESSION, project=PROJECT)
        self.assertEqual(parser.feed_line(_init_line(cwd=OTHER_PROJECT)), ())
        self.assertTrue(parser.project_conflict)
        self.assertTrue(parser.stats.partial)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        self.assertIsNone(parser.project)
        records = parser.feed_line(_msg_line("assistant", [_text("later")]))
        self.assertEqual(len(records), 1)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertEqual(records[0].project_quality, ProjectQuality.UNKNOWN)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        parser.finish()
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)

    def test_asserted_project_alone_is_attributable_without_a_header_cwd(self) -> None:
        parser, records = _parse(
            [_init_line(cwd=None), _msg_line("user", [_text("hello")], cwd=None)],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertEqual(parser.project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.CALLER_ASSERTED)
        self.assertEqual(records[0].project, PROJECT)
        self.assertNotIn(IssueCode.PROJECT_UNVERIFIED, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 0)


class TC2RoleAndIdentifierTests(unittest.TestCase):
    """TC-MCP-PLN-CLAUDE-02：角色映射、未核实行类型、会话标识三路核对。"""

    def test_only_text_roles_produce_body(self) -> None:
        for role in sorted(C.TEXT_ROLES):
            parser, records = _parse(
                [_init_line(), _msg_line(role, [_text("body")])],
                session_id=SESSION,
            )
            self.assertEqual(len(records), 1, role)
            self.assertEqual(records[0].role, role)
            self.assertFalse(parser.stats.partial)

    def test_conflicting_envelope_role_is_refused(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "message": {
                            "role": "assistant",
                            "content": [_text("who said this")],
                        },
                    }
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_ROLE), 1)
        self.assertTrue(parser.stats.partial)

    def test_envelope_role_case_folds_to_the_line_role(self) -> None:
        _, records = _parse(
            [
                _init_line(),
                json.dumps(
                    {
                        "type": "assistant",
                        "session_id": SESSION,
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "message": {"role": "Assistant", "content": [_text("ok")]},
                    }
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual([r.role for r in records], ["assistant"])

    def test_an_omitted_envelope_role_falls_back_to_the_row_type(self) -> None:
        # 字段真的缺席才回落 `event_type`：不记任何角色降级。
        line = json.dumps(
            {
                "type": "assistant",
                "session_id": SESSION,
                "cwd": PROJECT,
                "timestamp": TS,
                "message": {"content": [_text("ok")]},
            }
        )
        parser, records = _parse([_init_line(), line], session_id=SESSION)
        self.assertEqual([r.role for r in records], ["assistant"])
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_ROLE), 0)
        self.assertFalse(parser.stats.partial)

    def test_a_declared_but_unusable_role_is_refused_as_unknown_role(self) -> None:
        # 字段存在但给不出可用角色（显式 `null`、数字、布尔、容器、空白、超长串）：
        # 是「声明了本层解释不了的角色」，必须记 `unknown_role` 后拒产，不能拿行 type 冒充。
        unusable = (None, 7, 1.5, True, False, ["user"], {"role": "user"}, "", "   ", "r" * 200)
        for value in unusable:
            with self.subTest(value=repr(value)):
                parser, records = _parse(
                    [
                        _init_line(),
                        json.dumps(
                            {
                                "type": "user",
                                "session_id": SESSION,
                                "cwd": PROJECT,
                                "timestamp": TS,
                                "message": {"role": value, "content": [_text("x")]},
                            }
                        ),
                        _msg_line("assistant", [_text("next")]),
                    ],
                    session_id=SESSION,
                )
                self.assertEqual(_count(parser, IssueCode.UNKNOWN_ROLE), 1)
                # 本行拒产不置粘性冲突，也不影响后续合法行。
                self.assertEqual([r.text for r in records], ["next"])

    def test_a_declared_but_unusable_role_does_not_note_other_degradations(self) -> None:
        # 角色不可用时不进入正文/时间/归属核对：不产记录也不补其他原因码。
        parser, records = _parse(
            [
                _init_line(),
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "message": {"role": None, "content": [_text("x")]},
                    }
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(parser.stats.records_emitted, 0)
        self.assertEqual(parser.stats.lines_with_records, 0)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_ROLE), 1)
        self.assertEqual(_count(parser, IssueCode.NO_TEXT_CONTENT), 0)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_UNVERIFIED), 0)
        self.assertEqual(_count(parser, IssueCode.PROJECT_UNVERIFIED), 0)

    def test_roles_outside_the_text_set_are_refused_even_when_declared_validly(self) -> None:
        # 合法但不是正文角色（如 `tool`）：仍按 `unknown_role` 拒产，与「解释不了」区分开。
        for value in ("tool", "system", "TOOL"):
            with self.subTest(value=value):
                parser, records = _parse(
                    [
                        _init_line(),
                        json.dumps(
                            {
                                "type": "user",
                                "session_id": SESSION,
                                "cwd": PROJECT,
                                "timestamp": TS,
                                "message": {"role": value, "content": [_text("x")]},
                            }
                        ),
                    ],
                    session_id=SESSION,
                )
                self.assertEqual(records, ())
                self.assertEqual(_count(parser, IssueCode.UNKNOWN_ROLE), 1)

    def test_missing_message_envelope_is_refused(self) -> None:
        parser, records = _parse(
            [_init_line(), json.dumps({"type": "user", "content": [_text("flat")]})],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.MISSING_MESSAGE_ENVELOPE), 1)
        self.assertTrue(parser.stats.partial)

    def test_unverified_system_subtypes_are_not_adopted_as_headers(self) -> None:
        parser, _ = _parse(
            [
                _init_line(subtype="compact"),
                _init_line(subtype="compact_boundary", session_id=OTHER_SESSION, cwd=OTHER_PROJECT),
            ],
            session_id=SESSION,
        )
        self.assertEqual(_count(parser, IssueCode.SKIPPED_ROLE), 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)
        self.assertFalse(parser.header.seen)
        self.assertEqual(_count(parser, IssueCode.NO_SESSION_HEADER), 1)
        self.assertTrue(parser.stats.partial)

    def test_row_types_outside_the_verified_set_are_unknown_events(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                json.dumps({"type": "tool", "message": {"role": "tool", "content": [_text("x")]}}),
                json.dumps({"type": "result", "subtype": "success", "total_cost_usd": 0.1}),
                json.dumps({"role": "user", "content": [_text("no type at all")]}),
                json.dumps({"cwd": PROJECT, "session_id": SESSION}),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        # 无 `type` 的行不套用宽识分支：既不认成消息，也不认成头部。
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 4)
        self.assertEqual(_count(parser, IssueCode.MISSING_MESSAGE_ENVELOPE), 0)
        self.assertTrue(parser.stats.partial)

    def test_oversized_row_type_is_an_unknown_event(self) -> None:
        parser, _ = _parse([json.dumps({"type": "x" * 200})], session_id=SESSION)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)

    def test_path_shaped_session_id_in_the_header_is_refused_stickily(self) -> None:
        parser, records = _parse(
            [
                _init_line(session_id=f"D:/work/sessions/{SESSION}.jsonl"),
                _msg_line("user", [_text("hello")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertFalse(parser.header.trusted)
        self.assertTrue(parser.session_id_conflict)
        self.assertIsNone(parser.session_id)
        self.assertEqual(_count(parser, IssueCode.HEADER_SESSION_ID_MISMATCH), 1)
        self.assertGreaterEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 1)
        self.assertTrue(parser.stats.partial)

    def test_path_shaped_session_id_in_a_message_line_is_refused_stickily(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("first")], session_id="C:\\Users\\me\\x"),
                _msg_line("assistant", [_text("second")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.session_id_conflict)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 2)
        self.assertIsNone(parser.session_id)

    def test_inline_session_id_conflicting_with_the_assertion(self) -> None:
        parser, records = _parse(
            [
                _drop(_init_line(), "session_id"),
                _msg_line("user", [_text("hi")], session_id=OTHER_SESSION),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.session_id_conflict)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 1)

    def test_header_session_id_conflicting_with_the_assertion_stops_the_stream(self) -> None:
        # 两份可用标识互不相同（头部 vs 上层断言）：归属证据本身被污染 → 粘性拒产。
        parser, records = _parse(
            [_init_line(), _msg_line("user", [_text("hello")])],
            session_id=OTHER_SESSION,
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.session_id_conflict)
        self.assertFalse(parser.header.trusted)
        self.assertEqual(_count(parser, IssueCode.HEADER_SESSION_ID_MISMATCH), 1)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 1)

    def test_header_declaring_an_empty_session_id_is_not_adopted(self) -> None:
        # 头部声明 session_id 但给不出可用值：收回头部采信，但**不**否定整条流的归属。
        # 与「路径形态值」分列两种结论：后者是有值不可采信，才粘性拒产（见
        # test_path_shaped_session_id_in_the_header_is_refused_stickily）。
        parser, records = _parse(
            [_init_line(session_id=None), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertFalse(parser.header.trusted)
        self.assertIsNone(parser.header.session_id)
        self.assertIsNone(parser.session_id)
        self.assertEqual(_count(parser, IssueCode.HEADER_SESSION_ID_MISMATCH), 1)
        self.assertFalse(parser.session_id_conflict)
        # 消息行自带可用标识且与上层断言一致：两份独立证据 → 已核实，不降级为 unverified。
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].session_id, SESSION)
        self.assertNotIn(IssueCode.SESSION_ID_UNVERIFIED, records[0].issues)
        self.assertNotIn(IssueCode.SESSION_ID_MISMATCH, records[0].issues)

    def test_header_session_id_conflicts_with_inline_session_id(self) -> None:
        # 无外部断言时，已采信头部与行内标识两份证据仍无条件参与核对。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("hello")], session_id=OTHER_SESSION),
                _msg_line("assistant", [_text("second")]),
            ],
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.session_id_conflict)
        self.assertIsNone(parser.session_id)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 2)
        self.assertTrue(parser.stats.partial)

    def test_header_alias_contradiction_is_refused(self) -> None:
        # 头部行同时给 `session_id` 与 `sessionId` 且值不同：没有依据挑一个当权威，
        # 按「有值但不可采信」整体拒收，不先到先得。消息行本身干净。
        parser, records = _parse(
            [_init_line(sessionId=OTHER_SESSION), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.header.seen)
        self.assertFalse(parser.header.trusted)
        self.assertIsNone(parser.header.session_id)
        self.assertTrue(parser.session_id_conflict)
        self.assertFalse(parser.project_conflict)
        self.assertEqual(_count(parser, IssueCode.HEADER_SESSION_ID_MISMATCH), 1)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 1)
        self.assertIsNone(parser.session_id)
        self.assertTrue(parser.stats.partial)

    def test_message_alias_contradiction_is_refused(self) -> None:
        # 消息行内部别名矛盾（头部干净，所以真的走到消息层核对）：
        # 不记头部矛盾，粘性置位后当前与后续消息都零产出，共 2 次。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("hello")], sessionId=OTHER_SESSION),
                _msg_line("assistant", [_text("second")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.header.trusted)
        self.assertFalse(parser.project_conflict)
        self.assertEqual(_count(parser, IssueCode.HEADER_SESSION_ID_MISMATCH), 0)
        self.assertTrue(parser.session_id_conflict)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 2)
        self.assertIsNone(parser.session_id)
        self.assertTrue(parser.stats.partial)

    def test_alias_contradiction_in_both_layers_at_once_is_sticky(self) -> None:
        # 两层同时矛盾（原有覆盖）：头部先粘性置位，后续行只计一次，不补第二次。
        parser, records = _parse(
            [
                _init_line(sessionId=OTHER_SESSION),
                _msg_line("user", [_text("hello")], sessionId=OTHER_SESSION),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.header.seen)
        self.assertFalse(parser.header.trusted)
        self.assertTrue(parser.session_id_conflict)
        self.assertEqual(_count(parser, IssueCode.HEADER_SESSION_ID_MISMATCH), 1)
        # 粘性矛盾已置位：后续行一律整条拒产（每行计一次 mismatch，不补第二次）。
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 1)
        self.assertIsNone(parser.session_id)
        self.assertTrue(parser.stats.partial)

    def test_agreeing_alias_keys_are_adopted_normally(self) -> None:
        # 同层别名都存在但取值相同：不是矛盾，照常取用。
        parser, records = _parse(
            [
                _init_line(sessionId=SESSION),
                _msg_line("user", [_text("hello")], sessionId=SESSION),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertTrue(parser.header.trusted)
        self.assertFalse(parser.session_id_conflict)
        self.assertEqual(parser.session_id, SESSION)
        self.assertFalse(parser.stats.partial)

    def test_each_header_session_id_alias_alone_is_adopted(self) -> None:
        # 每个别名单独试一次：先删掉默认的正主键，确保测的是「只有别名」而不是「别名+正主」。
        for alias in ("sessionId", "session-id"):
            with self.subTest(alias=alias):
                header = _drop(_init_line(), "session_id")
                payload = json.loads(header)
                payload[alias] = SESSION
                parser, records = _parse(
                    [json.dumps(payload), _msg_line("user", [_text("hello")])],
                    session_id=SESSION,
                )
                self.assertTrue(parser.header.trusted)
                self.assertEqual(parser.header.session_id, SESSION)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].session_id, SESSION)
                self.assertFalse(parser.session_id_conflict)
                self.assertEqual(_count(parser, IssueCode.HEADER_SESSION_ID_MISMATCH), 0)
                self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 0)
                self.assertEqual(_count(parser, IssueCode.SESSION_ID_UNVERIFIED), 0)
                self.assertFalse(parser.stats.partial)

    def test_each_message_session_id_alias_alone_is_adopted(self) -> None:
        # 消息层只认 `session_id`/`sessionId`（`session-id` 属于头部键集）；
        # 同样先删默认键，只留别名一份声明。
        for alias in ("session_id", "sessionId"):
            with self.subTest(alias=alias):
                line = json.loads(_drop(_msg_line("user", [_text("hello")]), "session_id"))
                line[alias] = SESSION
                parser, records = _parse(
                    [_init_line(), json.dumps(line)],
                    session_id=SESSION,
                )
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].session_id, SESSION)
                self.assertFalse(parser.session_id_conflict)
                self.assertNotIn(IssueCode.SESSION_ID_UNVERIFIED, records[0].issues)
                self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 0)
                self.assertFalse(parser.stats.partial)

    def test_an_envelope_session_id_alone_is_read_as_inline_evidence(self) -> None:
        # 行层没声明时，`message` 内的标识仍是行内证据（两个键名都试）。
        for alias in ("session_id", "sessionId"):
            with self.subTest(alias=alias):
                line = json.loads(_drop(_msg_line("user", [_text("hello")]), "session_id"))
                line["message"][alias] = SESSION
                parser, records = _parse(
                    [_init_line(), json.dumps(line)],
                    session_id=SESSION,
                )
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].session_id, SESSION)
                self.assertFalse(parser.session_id_conflict)
                self.assertEqual(_count(parser, IssueCode.MISSING_SESSION_ID), 0)
                self.assertFalse(parser.stats.partial)

    def test_each_header_cwd_alias_alone_is_adopted(self) -> None:
        for alias in ("workingDirectory", "working_directory"):
            with self.subTest(alias=alias):
                payload = json.loads(_drop(_init_line(), "cwd"))
                payload[alias] = PROJECT
                parser, records = _parse(
                    [json.dumps(payload), _msg_line("user", [_text("hello")])],
                    session_id=SESSION,
                )
                self.assertTrue(parser.header.trusted)
                self.assertEqual(parser.header.cwd, PROJECT)
                self.assertEqual(parser.project, PROJECT)
                self.assertEqual(
                    parser.project_quality, ProjectQuality.TRUSTED_HEADER_CWD
                )
                self.assertFalse(parser.project_conflict)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].project, PROJECT)
                self.assertEqual(_count(parser, IssueCode.INVALID_HEADER_CWD), 0)
                self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 0)
                self.assertFalse(parser.stats.partial)

    def test_the_subtype_alias_alone_is_classified_as_a_header(self) -> None:
        payload = json.loads(_drop(_init_line(), "subtype"))
        payload["sub_type"] = "init"
        parser, records = _parse(
            [json.dumps(payload), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
        )
        self.assertTrue(parser.header.seen)
        self.assertTrue(parser.header.trusted)
        self.assertEqual(parser.header.subtype, "init")
        self.assertEqual(len(records), 1)
        self.assertEqual(_count(parser, IssueCode.NO_SESSION_HEADER), 0)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 0)
        self.assertFalse(parser.stats.partial)

    def test_contradicting_subtype_aliases_are_not_a_header(self) -> None:
        # 同层 subtype 别名矛盾：不能挑一个当「init」，也不得记成头部矛盾（它根本没被认作头部）。
        parser, records = _parse(
            [_init_line(sub_type="compact"), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertFalse(parser.header.seen)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)
        self.assertEqual(_count(parser, IssueCode.SKIPPED_ROLE), 0)
        self.assertEqual(_count(parser, IssueCode.NO_SESSION_HEADER), 1)
        self.assertFalse(parser.project_conflict)
        self.assertTrue(parser.stats.partial)

    def test_each_header_version_alias_alone_grants_trust(self) -> None:
        # 版本别名单独在场也算「声明了版本」：不记缺版本，也不降采信。
        for alias in ("v", "claude_code_version"):
            with self.subTest(alias=alias):
                payload = json.loads(_drop(_init_line(), "version"))
                payload[alias] = "1.2.3"
                parser, records = _parse(
                    [json.dumps(payload), _msg_line("user", [_text("hello")])],
                    session_id=SESSION,
                )
                self.assertTrue(parser.header.trusted)
                self.assertEqual(parser.header.version, "1.2.3")
                self.assertEqual(len(records), 1)
                self.assertEqual(_count(parser, IssueCode.MISSING_HEADER_VERSION), 0)
                self.assertEqual(_count(parser, IssueCode.UNSUPPORTED_HEADER_VERSION), 0)
                self.assertFalse(parser.stats.partial)

    def test_unverified_and_missing_session_identity_are_distinct(self) -> None:
        unverified_parser, unverified = _parse(
            [_msg_line("user", [_text("hello")])],
        )
        self.assertEqual(len(unverified), 1)
        self.assertEqual(unverified[0].session_id, SESSION)
        self.assertEqual(unverified[0].time_quality, TimeQuality.EXACT)
        self.assertIn(IssueCode.SESSION_ID_UNVERIFIED, unverified[0].issues)
        self.assertEqual(_count(unverified_parser, IssueCode.SESSION_ID_UNVERIFIED), 1)
        self.assertEqual(_count(unverified_parser, IssueCode.MISSING_SESSION_ID), 0)
        self.assertIsNone(unverified_parser.session_id)

        missing_parser, missing = _parse(
            [
                json.dumps(
                    {
                        "type": "user",
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "message": {"role": "user", "content": [_text("orphan")]},
                    }
                )
            ],
        )
        self.assertEqual(len(missing), 1)
        self.assertIsNone(missing[0].session_id)
        self.assertIn(IssueCode.MISSING_SESSION_ID, missing[0].issues)
        self.assertEqual(_count(missing_parser, IssueCode.MISSING_SESSION_ID), 1)

    def test_bare_id_is_not_a_session_identifier(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                json.dumps(
                    {
                        "type": "assistant",
                        "id": "msg_01ABC",
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "session_id": SESSION,
                        "message": {"id": "msg_01ABC", "role": "assistant", "content": [_text("ok")]},
                    }
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].session_id, SESSION)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 0)

    def test_late_conflicting_header_withdraws_attribution(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("first")]),
                _init_line(cwd=OTHER_PROJECT),
                _msg_line("assistant", [_text("second")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].project, PROJECT)
        # 头部本身未与别份头部矛盾；失去采信的是「头部支撑的归属」，不是会话身份。
        self.assertFalse(parser.header.trusted)
        self.assertFalse(parser.session_id_conflict)
        self.assertEqual(_count(parser, IssueCode.LATE_SESSION_HEADER), 1)
        self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 1)
        # 项目矛盾是粘性的：后续消息行 cwd 与旧头部一致也不恢复归属。
        self.assertTrue(parser.project_conflict)
        self.assertIsNone(parser.project)
        self.assertEqual(parser.project_quality, ProjectQuality.UNKNOWN)
        self.assertIsNone(records[1].project)
        self.assertEqual(records[1].project_quality, ProjectQuality.UNKNOWN)
        self.assertIn(IssueCode.PROJECT_UNVERIFIED, records[1].issues)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)

    def test_an_untrusted_header_id_still_participates_in_the_negative_check(self) -> None:
        # 缺版本只降低采信度，不能把合法的头部标识从矛盾核对里摸出去：
        # 头部 ID=S、消息 ID=T 必须拒产并粘性置位，两条消息各计一次，共 2。
        # 否定核对只用数据侧两份证据，不借外部 session 断言：那会让「头部被排除在核对之外」
        # 的旧实现也能通过。
        parser, records = _parse(
            [
                _drop(_init_line(), "version"),
                _msg_line("user", [_text("first")], session_id=OTHER_SESSION),
                _msg_line("assistant", [_text("second")]),
            ]
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.session_id_conflict)
        self.assertFalse(parser.project_conflict)
        self.assertIsNone(parser.session_id)
        self.assertEqual(_count(parser, IssueCode.MISSING_HEADER_VERSION), 1)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 2)
        self.assertEqual(parser.stats.records_emitted, 0)
        self.assertEqual(parser.stats.lines_with_records, 0)
        # 三行（init + 2 条消息）都未产出记录：skipped_count 按行计 = lines_seen - lines_with_records。
        self.assertEqual(parser.stats.skipped_count, 3)
        self.assertTrue(parser.stats.partial)

    def test_cross_layer_ids_disagreeing_are_refused_stickily(self) -> None:
        # 顶层 ID=S、`message` 内 ID=T，同一消息行的两层互相矛盾（同层别名本身无冲突）：
        # 不先到先得，当前与后续消息都零产出，粘性置位，共 2 次矛盾。
        clean = _init_line()
        crossed = json.loads(
            _msg_line(
                "user",
                [_text("first")],
                session_id=SESSION,
            )
        )
        crossed["message"]["session_id"] = OTHER_SESSION
        parser, records = _parse(
            [clean, json.dumps(crossed), _msg_line("assistant", [_text("second")])],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertTrue(parser.session_id_conflict)
        self.assertFalse(parser.project_conflict)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 2)
        self.assertEqual(_count(parser, IssueCode.INVALID_HEADER_CWD), 0)
        self.assertEqual(parser.stats.records_emitted, 0)

    def test_an_untrusted_header_id_still_grants_no_trusted_votes(self) -> None:
        parser, records = _parse(
            [_drop(_init_line(), "version"), _msg_line("user", [_text("first")])],
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].session_id, SESSION)
        self.assertIn(IssueCode.SESSION_ID_UNVERIFIED, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_UNVERIFIED), 1)
        self.assertFalse(parser.session_id_conflict)
        self.assertIsNone(parser.session_id)

    def test_an_untrusted_header_never_supplies_the_record_id_alone(self) -> None:
        # 头部合法但不可信，且消息行没自己的 ID、外部也没断言：不能拿头部 ID 冒充记录 ID。
        parser, records = _parse(
            [
                _drop(_init_line(), "version"),
                _drop(_msg_line("user", [_text("first")]), "session_id"),
            ],
        )
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].session_id)
        self.assertIn(IssueCode.MISSING_SESSION_ID, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.MISSING_SESSION_ID), 1)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 0)
        self.assertFalse(parser.session_id_conflict)

    def test_the_adopted_id_and_verified_votes_still_exclude_the_untrusted_header(self) -> None:
        # 不矛盾时，头部合法但不可信：既不单独供值，也不给「已核实」补票；
        # 有外部断言 + 行内一致的常规场景仍按已核实产出。
        parser, records = _parse(
            [
                _drop(_init_line(session_id=OTHER_SESSION), "version"),
                _msg_line("user", [_text("first")], session_id=OTHER_SESSION),
            ],
            session_id=OTHER_SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].session_id, OTHER_SESSION)
        self.assertNotIn(IssueCode.SESSION_ID_UNVERIFIED, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.SESSION_ID_MISMATCH), 0)
        self.assertFalse(parser.session_id_conflict)
        # 但「已核实的会话标识」仍只认可信头部与外部断言的一致：本例头部不可信，
        # 因此对外不暴露已核实标识。
        self.assertIsNone(parser.session_id)

    def test_header_without_version_is_not_adopted(self) -> None:
        parser, records = _parse(
            [_drop(_init_line(), "version"), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertFalse(parser.header.trusted)
        self.assertTrue(parser.header.seen)
        self.assertEqual(_count(parser, IssueCode.MISSING_HEADER_VERSION), 1)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].session_id, SESSION)
        self.assertNotIn(IssueCode.SESSION_ID_UNVERIFIED, records[0].issues)
        self.assertIsNone(parser.session_id)
        self.assertEqual(records[0].project, PROJECT)
        self.assertEqual(records[0].project_quality, ProjectQuality.CALLER_ASSERTED)

    def test_header_with_an_unusable_version_value_is_not_adopted(self) -> None:
        parser, _ = _parse(
            [_init_line(version=""), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertFalse(parser.header.trusted)
        self.assertEqual(_count(parser, IssueCode.UNSUPPORTED_HEADER_VERSION), 1)
        self.assertEqual(_count(parser, IssueCode.MISSING_HEADER_VERSION), 0)

    def test_timestamp_degradations(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("naive")], timestamp="2026-11-03T10:00:00"),
                _msg_line("assistant", [_text("junk")], timestamp="not-a-time"),
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "cwd": PROJECT,
                        "message": {"role": "user", "content": [_text("no stamp")]},
                    }
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0].time_quality, TimeQuality.NO_TIMEZONE)
        self.assertIsNone(records[1].timestamp)
        self.assertEqual(records[1].time_quality, TimeQuality.INVALID)
        self.assertEqual(records[2].time_quality, TimeQuality.MISSING)
        self.assertEqual(_count(parser, IssueCode.TIMESTAMP_NO_TIMEZONE), 1)
        self.assertEqual(_count(parser, IssueCode.TIMESTAMP_INVALID), 1)
        self.assertEqual(_count(parser, IssueCode.MISSING_TIMESTAMP), 1)
        self.assertTrue(parser.stats.partial)

    def test_each_row_timestamp_alias_alone_is_exact(self) -> None:
        # 行级三个时间别名各自单独在场都能用（先删默认键，确保只留别名）。
        for alias in ("timestamp", "createdAt", "created_at"):
            with self.subTest(alias=alias):
                line = json.loads(_drop(_msg_line("user", [_text("hi")]), "timestamp"))
                line[alias] = TS
                parser, records = _parse([_init_line(), json.dumps(line)], session_id=SESSION)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].time_quality, TimeQuality.EXACT)
                self.assertIsNotNone(records[0].timestamp)
                self.assertEqual(_count(parser, IssueCode.MISSING_TIMESTAMP), 0)
                self.assertEqual(_count(parser, IssueCode.TIMESTAMP_INVALID), 0)
                self.assertFalse(parser.stats.partial)

    def test_agreeing_row_timestamp_aliases_are_not_a_conflict(self) -> None:
        # 同层两个别名取值完全相同：不是矛盾，照常按 EXACT 采用。
        for alias in ("createdAt", "created_at"):
            with self.subTest(alias=alias):
                line = json.loads(_msg_line("user", [_text("hi")]))
                line[alias] = TS
                parser, records = _parse([_init_line(), json.dumps(line)], session_id=SESSION)
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].time_quality, TimeQuality.EXACT)
                self.assertEqual(_count(parser, IssueCode.TIMESTAMP_INVALID), 0)
                self.assertFalse(parser.stats.partial)

    def test_conflicting_row_timestamp_aliases_are_invalid(self) -> None:
        # 同层别名取值互异，或一份有效一份显式 `null`：不做跨格式等价推测，
        # 一律按 (None, INVALID) 保守处理，并带到保留记录上。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("a")], createdAt="2026-11-04T09:00:00.000Z"),
                _msg_line("assistant", [_text("b")], createdAt=None),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertIsNone(record.timestamp)
            self.assertEqual(record.time_quality, TimeQuality.INVALID)
            self.assertIn(IssueCode.TIMESTAMP_INVALID, record.issues)
        self.assertEqual(_count(parser, IssueCode.TIMESTAMP_INVALID), 2)
        self.assertEqual(_count(parser, IssueCode.MISSING_TIMESTAMP), 0)
        self.assertTrue(parser.stats.partial)

    def test_the_envelope_timestamp_is_never_a_row_time_fallback(self) -> None:
        # 行级缺席而 `message` 内有合法时间：仍记缺失，不把信封时间升格为 EXACT。
        line = json.loads(_drop(_msg_line("user", [_text("hi")]), "timestamp"))
        line["message"]["timestamp"] = TS
        parser, records = _parse([_init_line(), json.dumps(line)], session_id=SESSION)
        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].timestamp)
        self.assertEqual(records[0].time_quality, TimeQuality.MISSING)
        self.assertIn(IssueCode.MISSING_TIMESTAMP, records[0].issues)
        self.assertEqual(_count(parser, IssueCode.MISSING_TIMESTAMP), 1)
        self.assertEqual(_count(parser, IssueCode.TIMESTAMP_INVALID), 0)

    def test_a_lone_null_row_timestamp_is_missing_not_invalid(self) -> None:
        # 显式 `null` 而信封内有合法时间：单独一份 `null` 等于没声明到可用值，
        # 按缺失登记，不拿信封时间冒充。
        line = json.loads(_msg_line("user", [_text("hi")], timestamp=None))
        line["message"]["timestamp"] = TS
        parser, records = _parse([_init_line(), json.dumps(line)], session_id=SESSION)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].time_quality, TimeQuality.MISSING)
        self.assertIsNone(records[0].timestamp)
        self.assertEqual(_count(parser, IssueCode.MISSING_TIMESTAMP), 1)
        self.assertEqual(_count(parser, IssueCode.TIMESTAMP_INVALID), 0)

    def test_a_bad_row_timestamp_stays_invalid_despite_a_good_envelope_time(self) -> None:
        # 行级声明了但不能用（非时间串）：不被信封时间撕回「可用」。
        line = json.loads(_msg_line("user", [_text("hi")], timestamp="not-a-time"))
        line["message"]["timestamp"] = TS
        parser, records = _parse([_init_line(), json.dumps(line)], session_id=SESSION)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].time_quality, TimeQuality.INVALID)
        self.assertIsNone(records[0].timestamp)
        self.assertEqual(_count(parser, IssueCode.TIMESTAMP_INVALID), 1)
        self.assertEqual(_count(parser, IssueCode.MISSING_TIMESTAMP), 0)

    def test_a_good_row_timestamp_wins_over_a_different_envelope_time(self) -> None:
        # 行级可用而信封与它不同：信封从来不是候选，因此没有跨层否决。
        line = json.loads(_msg_line("user", [_text("hi")]))
        line["message"]["timestamp"] = "2020-01-01T00:00:00.000Z"
        parser, records = _parse([_init_line(), json.dumps(line)], session_id=SESSION)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].time_quality, TimeQuality.EXACT)
        self.assertIsNotNone(records[0].timestamp)
        self.assertEqual(records[0].issues, ())
        self.assertFalse(parser.stats.partial)

    def test_epoch_timestamp_is_accepted_as_exact(self) -> None:
        _, records = _parse(
            [_init_line(), _msg_line("user", [_text("hi")], timestamp=1_767_225_600)],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].time_quality, TimeQuality.EXACT)


class TC3SidechainTests(unittest.TestCase):
    """TC-MCP-PLN-CLAUDE-03：派生/子代理行不计为独立用户会话，且不否定主流归属。"""

    def test_sidechain_flag_lines_produce_no_body(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("main")]),
                _msg_line("assistant", [_text("subagent")], isSidechain=True),
                _msg_line("user", [_text("subagent")], is_sidechain="true"),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].text, "main")
        self.assertEqual(parser.sidechain_skipped_lines, 2)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 2)
        self.assertFalse(parser.project_conflict)
        self.assertFalse(parser.session_id_conflict)
        self.assertEqual(parser.project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.TRUSTED_HEADER_CWD)
        self.assertEqual(parser.session_id, SESSION)
        self.assertTrue(parser.stats.partial)

    def test_each_sidechain_alias_alone_is_read_as_a_derived_line(self) -> None:
        # 单独一个别名（布尔或等价字符串）就能确定派生：不要求两个别名都在场。
        for alias in ("isSidechain", "is_sidechain"):
            for value in (True, "true", "TRUE", " true ", "True"):
                with self.subTest(alias=alias, value=value):
                    parser, records = _parse(
                        [
                            _init_line(),
                            _msg_line("assistant", [_text("sub")], **{alias: value}),
                            _msg_line("user", [_text("main")]),
                        ],
                        session_id=SESSION,
                    )
                    self.assertEqual([r.text for r in records], ["main"])
                    self.assertEqual(parser.sidechain_skipped_lines, 1)
                    self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)
                    self.assertFalse(parser.project_conflict)
                    self.assertFalse(parser.session_id_conflict)

    def test_each_sidechain_alias_alone_declaring_false_stays_in_the_main_stream(self) -> None:
        # 假值同样只需一个别名就能确定，而且不得把主流行误跳。
        for alias in ("isSidechain", "is_sidechain"):
            for value in (False, "false", "FALSE", " false "):
                with self.subTest(alias=alias, value=value):
                    parser, records = _parse(
                        [_init_line(), _msg_line("user", [_text("main")], **{alias: value})],
                        session_id=SESSION,
                    )
                    self.assertEqual([r.text for r in records], ["main"])
                    self.assertEqual(parser.sidechain_skipped_lines, 0)
                    self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 0)
                    self.assertFalse(parser.stats.partial)

    def test_conflicting_sidechain_aliases_are_skipped_conservatively(self) -> None:
        # 两个别名都声明但结论相反：不先到先得，也不「当作没声明」，保守跳过。
        for first, second in ((False, True), (True, False)):
            with self.subTest(isSidechain=first, is_sidechain=second):
                parser, records = _parse(
                    [
                        _init_line(),
                        _msg_line(
                            "assistant",
                            [_text("sub")],
                            isSidechain=first,
                            is_sidechain=second,
                        ),
                        _msg_line("user", [_text("main")]),
                    ],
                    session_id=SESSION,
                )
                self.assertEqual([r.text for r in records], ["main"])
                self.assertEqual(parser.sidechain_skipped_lines, 1)
                self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)
                self.assertFalse(parser.project_conflict)
                self.assertFalse(parser.session_id_conflict)

    def test_a_boolean_and_an_equivalent_string_are_the_same_declaration(self) -> None:
        # `True` 与 `"true"` 是同一声明（不是矛盾）：仍按派生行跳过，只计一次。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line(
                    "assistant", [_text("sub")], isSidechain=True, is_sidechain="true"
                ),
                _msg_line("user", [_text("main")], isSidechain=False, is_sidechain="false"),
            ],
            session_id=SESSION,
        )
        self.assertEqual([r.text for r in records], ["main"])
        self.assertEqual(parser.sidechain_skipped_lines, 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)

    def test_illegal_sidechain_values_skip_the_line_and_never_claim_the_main_stream(self) -> None:
        # 数字（含 `0`：不得借 `False == 0` 洗白）、容器、空白、非法字符串、超长串：
        # 本层没有核对过的取值域，一律保守跳过该行，计一次 `unknown_event`。
        cases = (
            1,
            0,
            1.0,
            [True],
            {"v": True},
            "",
            "   ",
            "yes",
            "1",
            "truthy",
            "t" * 200,
        )
        for alias in ("isSidechain", "is_sidechain"):
            for value in cases:
                with self.subTest(alias=alias, value=repr(value)):
                    parser, records = _parse(
                        [
                            _init_line(),
                            _msg_line(
                                "user", [_text("suspect")], **{alias: value}
                            ),
                            _msg_line("assistant", [_text("main")]),
                        ],
                        session_id=SESSION,
                    )
                    self.assertEqual([r.text for r in records], ["main"])
                    self.assertEqual(parser.sidechain_skipped_lines, 1)
                    self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)
                    self.assertFalse(parser.project_conflict)
                    self.assertFalse(parser.session_id_conflict)
                    self.assertTrue(parser.stats.partial)

    def test_illegal_sidechain_values_on_an_init_line_keep_the_header_unadopted(self) -> None:
        # init 行同样走派生门：解释不了的标记不得确立主会话起点（也不反向记成头部矛盾）。
        for value in (1, "yes", {"v": True}):
            with self.subTest(value=repr(value)):
                parser, records = _parse(
                    [_init_line(isSidechain=value), _msg_line("user", [_text("main")])],
                    session_id=SESSION,
                    project=PROJECT,
                )
                self.assertEqual(len(records), 1)
                self.assertFalse(parser.header.seen)
                self.assertEqual(parser.sidechain_skipped_lines, 1)
                self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)
                self.assertEqual(_count(parser, IssueCode.NO_SESSION_HEADER), 1)
                self.assertEqual(_count(parser, IssueCode.INVALID_HEADER_CWD), 0)
                self.assertEqual(_count(parser, IssueCode.CONFLICTING_HEADER_CWD), 0)
                self.assertFalse(parser.project_conflict)
                self.assertFalse(parser.session_id_conflict)

    def test_a_bad_flag_and_a_bad_parent_reference_on_one_line_skip_once(self) -> None:
        # 同一行两个派生证据都坏：仍只跳一行、只计一次，不按证据个数放大。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line(
                    "assistant",
                    [_text("sub")],
                    isSidechain="yes",
                    parent_tool_use_id=7,
                ),
                _msg_line("user", [_text("main")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual([r.text for r in records], ["main"])
        self.assertEqual(parser.sidechain_skipped_lines, 1)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 1)
        self.assertEqual(parser.stats.skipped_count, 2)

    def test_a_lone_null_sidechain_declaration_is_not_a_flag(self) -> None:
        # 单独的 `null` 等于没声明：不降级、不跳过，主流行照常产出。
        for alias in ("isSidechain", "is_sidechain"):
            with self.subTest(alias=alias):
                parser, records = _parse(
                    [_init_line(), _msg_line("user", [_text("main")], **{alias: None})],
                    session_id=SESSION,
                )
                self.assertEqual([r.text for r in records], ["main"])
                self.assertEqual(parser.sidechain_skipped_lines, 0)
                self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 0)
                self.assertFalse(parser.stats.partial)
        # 两个别名都是 `null` 也是同一结论。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line(
                    "user", [_text("main")], isSidechain=None, is_sidechain=None
                ),
            ],
            session_id=SESSION,
        )
        self.assertEqual([r.text for r in records], ["main"])
        self.assertEqual(parser.sidechain_skipped_lines, 0)
        self.assertFalse(parser.stats.partial)

    def test_parent_reference_is_derived_evidence(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("assistant", [_text("child")], parent_tool_use_id="toolu_9"),
                _msg_line("assistant", [_text("child")], parentToolUseId="toolu_9"),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(parser.sidechain_skipped_lines, 2)

    def test_false_flags_and_empty_parent_references_stay_in_the_main_stream(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("one")], isSidechain=False),
                _msg_line("assistant", [_text("two")], parent_tool_use_id=None),
                _msg_line("user", [_text("three")], parent_tool_use_id="   "),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 3)
        self.assertEqual(parser.sidechain_skipped_lines, 0)
        self.assertFalse(parser.stats.partial)

    def test_derived_header_is_not_adopted(self) -> None:
        # 派生检查先于头部门：子代理流里的 `system/init` 不得确立主会话起点，
        # 否则派生会话会被冒充成独立用户会话（TC-MCP-PLN-CLAUDE-03）。
        parser, _ = _parse(
            [
                _init_line(
                    cwd=OTHER_PROJECT,
                    session_id=OTHER_SESSION,
                    isSidechain=True,
                ),
                _msg_line("user", [_text("main")], isSidechain=True),
            ],
            session_id=SESSION,
            project=PROJECT,
        )
        self.assertEqual(parser.sidechain_skipped_lines, 2)
        self.assertFalse(parser.session_id_conflict)
        self.assertFalse(parser.project_conflict)
        self.assertFalse(parser.header.seen)
        self.assertEqual(_count(parser, IssueCode.NO_SESSION_HEADER), 1)
        self.assertEqual(parser.project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.CALLER_ASSERTED)

    def test_derived_line_parent_tool_use_id_malformed_rejected(self) -> None:
        # 非字符串、超长、同层别名互斥的父引用都是**不可核实的派生标记**：担心子代理
        # 逃逸成主会话正文，一律按派生行跳过并计 `unknown_event`。
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("assistant", [_text("a")], parent_tool_use_id=7),
                _msg_line("assistant", [_text("b")], parent_tool_use_id="t" * 200),
                _msg_line(
                    "assistant",
                    [_text("c")],
                    parent_tool_use_id="toolu_1",
                    parentToolUseId="toolu_2",
                ),
                _msg_line("user", [_text("main")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual([r.text for r in records], ["main"])
        self.assertEqual(parser.sidechain_skipped_lines, 3)
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_EVENT), 3)
        self.assertFalse(parser.project_conflict)
        self.assertFalse(parser.session_id_conflict)
        self.assertEqual(parser.project_quality, ProjectQuality.TRUSTED_HEADER_CWD)

    def test_derived_skipping_is_not_reported_as_a_conflict(self) -> None:
        parser, records = _parse(
            [
                _init_line(),
                _msg_line("assistant", [_text("sub")], isSidechain=True),
                _msg_line("user", [_text("main")]),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(parser.project_conflict, False)
        self.assertEqual(parser.session_id_conflict, False)
        self.assertEqual(parser.stats.skipped_count, 2)


class DiscoveryBridgeTests(unittest.TestCase):
    """发现侧衔接：temp 目录内的合成 `<session-id>.jsonl` 能作为标识断言来源。"""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="claude-source-synthetic-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def _write_session_file(self, name: str, lines: list[str]) -> Path:
        directory = self.root / "projects" / "D--work-alpha"
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"{name}.jsonl"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return target

    def test_file_name_assertion_agrees_with_the_header(self) -> None:
        target = self._write_session_file(
            SESSION,
            [
                _init_line(),
                _msg_line("user", [_text("hello")]),
                _msg_line("assistant", [_text("hi")]),
            ],
        )
        found = sorted(path.name for path in target.parent.glob("*.jsonl"))
        self.assertEqual(found, [f"{SESSION}.jsonl"])
        asserted = found[0].removesuffix(".jsonl")
        lines = target.read_text(encoding="utf-8").splitlines()

        parser, records = _parse(lines, session_id=asserted)
        self.assertEqual(parser.session_id, SESSION)
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r.session_id == SESSION for r in records))
        self.assertEqual(parser.project, PROJECT)
        self.assertEqual(parser.project_quality, ProjectQuality.TRUSTED_HEADER_CWD)
        self.assertNotIn(IssueCode.SESSION_ID_UNVERIFIED, parser.stats.issue_counts)
        self.assertFalse(parser.stats.partial)

    def test_project_is_never_rebuilt_from_the_encoded_directory_name(self) -> None:
        target = self._write_session_file(
            SESSION,
            [
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "timestamp": TS,
                        "message": {"role": "user", "content": [_text("no cwd in line")]},
                    }
                )
            ],
        )
        parser, records = _parse(
            target.read_text(encoding="utf-8").splitlines(),
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertIsNone(parser.project)
        self.assertEqual(
            records[0].project_quality,
            ProjectQuality.UNKNOWN,
        )
        self.assertEqual(_count(parser, IssueCode.UNKNOWN_PROJECT), 1)

    def test_a_directory_name_that_fails_the_shape_gate_is_refused(self) -> None:
        target = self._write_session_file(
            "claude session copy",
            [_init_line(session_id="claude session copy")],
        )
        asserted = target.name.removesuffix(".jsonl")
        with self.assertRaises(ValueError):
            C.ClaudeLineParser(session_id=asserted)


class CommonSafetyTests(unittest.TestCase):
    """共性安全用例：字节/行数上限、损坏行、非对象行、空行、公开字典形状。"""

    def test_oversized_byte_line_is_dropped_whole(self) -> None:
        parser = C.ClaudeLineParser(stream_label=LABEL)
        huge = b'{"type":"user","pad":"' + b"x" * C.MAX_LINE_BYTES + b'"}'
        self.assertEqual(parser.feed_line(huge), ())
        self.assertEqual(_count(parser, IssueCode.LINE_TOO_LARGE), 1)
        self.assertEqual(parser.stats.lines_seen, 1)
        self.assertTrue(parser.stats.partial)

    def test_oversized_character_line_is_dropped_whole(self) -> None:
        parser = C.ClaudeLineParser(stream_label=LABEL)
        huge = "x" * (C.MAX_LINE_CHARS + 1)
        self.assertEqual(parser.feed_line(huge), ())
        self.assertEqual(_count(parser, IssueCode.LINE_TOO_LARGE), 1)

    def test_non_utf8_bytes_are_corrupt_not_guessed(self) -> None:
        parser = C.ClaudeLineParser(stream_label=LABEL)
        self.assertEqual(parser.feed_line(b'\xff\xfe{"type":"user"}'), ())
        self.assertEqual(_count(parser, IssueCode.CORRUPT_LINE), 1)

    def test_malformed_json_and_non_object_lines(self) -> None:
        parser, records = _parse(
            [
                '{"type": "user", ',
                json.dumps([1, 2, 3]),
                json.dumps("just a string"),
            ],
            session_id=SESSION,
        )
        self.assertEqual(records, ())
        self.assertEqual(_count(parser, IssueCode.CORRUPT_LINE), 1)
        self.assertEqual(_count(parser, IssueCode.LINE_NOT_OBJECT), 2)
        self.assertTrue(parser.stats.partial)

    def test_blank_lines_are_boundaries_not_incomplete_coverage(self) -> None:
        parser, records = _parse(
            ["", "   ", "\ufeff  ", _init_line(), _msg_line("user", [_text("hello")])],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(_count(parser, IssueCode.BLANK_LINE), 3)
        self.assertEqual(parser.stats.lines_seen, 5)
        self.assertFalse(parser.stats.partial)

    def test_byte_lines_decode_normally(self) -> None:
        parser, records = _parse(
            [
                _init_line().encode("utf-8"),
                json.dumps(
                    {
                        "type": "user",
                        "session_id": SESSION,
                        "cwd": PROJECT,
                        "timestamp": TS,
                        "message": {"role": "user", "content": [_text("带中文的正文")]},
                    }
                ).encode("utf-8"),
            ],
            session_id=SESSION,
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].text, "带中文的正文")
        self.assertFalse(parser.stats.partial)

    def test_stream_line_cap_stops_stickily(self) -> None:
        parser = C.ClaudeLineParser(stream_label=LABEL)
        for _ in range(C.MAX_LINES_PER_STREAM):
            parser.feed_line("")
        self.assertEqual(parser.stats.lines_seen, C.MAX_LINES_PER_STREAM)
        parser.feed_line(_init_line())
        self.assertEqual(_count(parser, IssueCode.MAX_STREAM_LINES_EXCEEDED), 1)
        self.assertEqual(parser.stats.lines_seen, C.MAX_LINES_PER_STREAM)
        self.assertFalse(parser.header.seen)
        parser.feed_line(_init_line())
        self.assertEqual(parser.stats.lines_seen, C.MAX_LINES_PER_STREAM)
        # 粘性：第二次被拒喂入不再计第二次超限，也不解析那一行。
        self.assertEqual(_count(parser, IssueCode.MAX_STREAM_LINES_EXCEEDED), 1)
        self.assertTrue(parser.stats.partial)

    def test_exceeding_the_line_cap_does_not_fetch_another_line(self) -> None:
        # 超限判定之后不得再拉下一行：最多 M 行入目，只有确实取得第 M+1 个元素时才
        # 计一次超限（该探测元素不计 lines_seen、不解码），第 M+2 个元素永不取。
        class _Counting:
            def __init__(self, items: list[str]) -> None:
                self.items = items
                self.fetched = 0

            def __iter__(self):
                return self

            def __next__(self) -> str:
                if self.fetched >= len(self.items):
                    raise AssertionError(
                        "parser fetched a line after the stream cap was hit"
                    )
                item = self.items[self.fetched]
                self.fetched += 1
                return item

        probe = _msg_line("user", [_text("the probe line")])
        source = _Counting([_init_line(), _msg_line("user", [_text("one")]), probe])
        with mock.patch.object(C, "MAX_LINES_PER_STREAM", 2):
            parser = C.ClaudeLineParser(stream_label=LABEL, session_id=SESSION)
            records = list(parser.feed(source))
        self.assertEqual(len(records), 1)
        self.assertEqual(source.fetched, 3)
        self.assertEqual(parser.stats.lines_seen, 2)
        self.assertEqual(_count(parser, IssueCode.MAX_STREAM_LINES_EXCEEDED), 1)
        self.assertTrue(parser.stats.partial)
        with self.assertRaises(RuntimeError):
            parser.feed_line(probe)

    def test_exactly_the_line_cap_is_not_reported_as_exceeding_it(self) -> None:
        # 恰好 M 行且自然结束：不报超限——「达到上限」不等于「存在未扫内容」。
        class _Counting:
            def __init__(self, items: list[str]) -> None:
                self.items = items
                self.fetched = 0

            def __iter__(self):
                return self

            def __next__(self) -> str:
                if self.fetched >= len(self.items):
                    raise StopIteration
                item = self.items[self.fetched]
                self.fetched += 1
                return item

        source = _Counting([_init_line(), _msg_line("user", [_text("one")])])
        with mock.patch.object(C, "MAX_LINES_PER_STREAM", 2):
            parser = C.ClaudeLineParser(stream_label=LABEL, session_id=SESSION)
            records = list(parser.feed(source))
        self.assertEqual(len(records), 1)
        self.assertEqual(parser.stats.lines_seen, 2)
        self.assertEqual(_count(parser, IssueCode.MAX_STREAM_LINES_EXCEEDED), 0)
        self.assertFalse(parser.stats.partial)

    def test_non_line_payload_is_corrupt_not_crashing(self) -> None:
        parser = C.ClaudeLineParser(stream_label=LABEL)
        self.assertEqual(parser.feed_line(None), ())  # type: ignore[arg-type]
        self.assertEqual(_count(parser, IssueCode.CORRUPT_LINE), 1)

    def test_public_stats_only_expose_integers_and_closed_categories(self) -> None:
        parser, _ = _parse(
            [
                _init_line(),
                _msg_line("user", [_text("hello")] ),
                _msg_line("assistant", [{"type": "mystery"}], timestamp="bad"),
                "{ broken",
            ],
            session_id=SESSION,
        )
        public = parser.stats.as_public_dict()
        self.assertEqual(
            set(public),
            {
                "lines_seen",
                "lines_with_records",
                "records_emitted",
                "skipped_count",
                "partial",
                "issue_counts",
            },
        )
        self.assertTrue(
            all(isinstance(value, int) for value in public["issue_counts"].values())
        )
        self.assertTrue(
            all(key in {code.value for code in IssueCode} for key in public["issue_counts"])
        )
        for code in parser.stats.reason_codes():
            self.assertIsInstance(code, IssueCode)
        serialized = json.dumps(public)
        self.assertNotIn(SESSION, serialized)
        self.assertNotIn(PROJECT, serialized)
        self.assertNotIn("hello", serialized)

    def test_unsafe_stream_label_is_replaced_as_a_whole(self) -> None:
        leaked = C.ClaudeLineParser(stream_label="D:/work/sessions/secret", session_id=SESSION)
        records = tuple(leaked.feed([_init_line(), _msg_line("user", [_text("hi")])]))
        self.assertEqual(len(records), 1)
        refs = [record.location.to_ref() for record in records]
        self.assertTrue(all("D:/work" not in ref for ref in refs), refs)
        self.assertIn("redacted-stream", refs[0])


if __name__ == "__main__":
    unittest.main()
