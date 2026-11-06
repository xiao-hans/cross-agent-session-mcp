"""合成 Cursor Agent CLI transcript 夹具（只写临时目录，绝不触碰真实 ``~/.cursor``）。

风格对齐 ``tests/hermes_synthetic.py``：模块级常量 + 纯构造函数 + 返回相对路径清单。
行形状按 04 取证登记的最小事实构造（``<timestamp>``/``<user_query>`` 标签、行内
``cwd``/``sessionId``/``version`` 字段、平铺与 ``message`` 信封双形态），标签与字段的
**语义** 未在真实存储上逐字核实 ⇒ 夹具只用于驱动解析分支，不用于证明来源格式。
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SOURCE = "cursor_agent_cli"

#: 合成工作区绝对路径：只作为行内 ``cwd`` 值与项目断言出现，夹具不据此创建目录。
PROJECT = "D:/synthetic/cursor-project"
OTHER_PROJECT = "D:/synthetic/other-project"
SESSION = "0f0f0f0f-1111-2222-3333-444444444444"
LABEL = "session-context"
TS = "2026-03-01T10:00:00.000Z"

TRANSCRIPT_DIR_MARKER = "agent-transcripts"
STORE_MARKER = "projects"


def line_text(**fields: Any) -> str:
    """把给定字段序列化为一行 JSONL（键顺序即入参顺序）。"""
    return json.dumps(fields, ensure_ascii=False)


def user_line(text: str, **fields: Any) -> str:
    """用户行：正文包在 ``<user_query>`` 标签里，时刻包在 ``<timestamp>`` 标签里。

    标签外的模板文字固定存在 —— 它正是「标签外内容不得进正文」这一判据的夹具。
    """
    body = (
        f"<timestamp>{TS}</timestamp>\n"
        "<user_query>" + text + "</user_query>\n"
        "[template instructions outside the query tag]"
    )
    payload: dict[str, Any] = {"role": "user", "content": body}
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False)


def assistant_line(blocks: Any, **fields: Any) -> str:
    """assistant 行：``content`` 可为裸字符串或块数组（调用方决定形状）。"""
    payload: dict[str, Any] = {"role": "assistant", "content": blocks}
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False)


def text_block(text: str, block_type: str = "text") -> dict[str, Any]:
    return {"type": block_type, "text": text}


def message_line(role: str, content: Any, **envelope: Any) -> str:
    """``message`` 信封形态：外层只带会话/归属字段，角色与正文在内层。"""
    inner: dict[str, Any] = {"role": role, "content": content}
    inner.update(envelope)
    return json.dumps({"message": inner}, ensure_ascii=False)


def header_line(**fields: Any) -> str:
    """带行内归属证据的首行（形态**未取证**：只用于驱动 ``_note_attribution`` 分支）。

    类型取已登记的元信息行 ``system``：归属证据本身不该顺带被计成 ``unknown_event``，否则
    「正常流不含未识别事件」这类断言会被夹具噪声污染。要断言未识别事件请另用
    :func:`unknown_event_line`。
    """
    payload: dict[str, Any] = {
        "type": "system",
        "version": "1",
        "sessionId": SESSION,
        "cwd": PROJECT,
    }
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False)


def meta_line(event_type: str = "queue-operation", **fields: Any) -> str:
    """已理解的元信息行（``KNOWN_NON_TEXT_BLOCK`` 分支）。"""
    payload: dict[str, Any] = {"type": event_type}
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False)


def unknown_event_line(**fields: Any) -> str:
    """未核实的事件类型行（须落 ``UNKNOWN_EVENT`` 并使覆盖不完整）。"""
    payload: dict[str, Any] = {"type": "model-switch", "detail": {"k": 1}}
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False)


def sidechain_line(**fields: Any) -> str:
    """派生/子代理标记行。默认布尔 ``True``；调用方可换 ``parentToolUseId`` 形态。"""
    payload: dict[str, Any] = {
        "role": "assistant",
        "content": "derived body",
        "isSidechain": True,
    }
    payload.update(fields)
    for key in ("role", "content", "isSidechain"):
        if key not in payload:
            continue
    return json.dumps(payload, ensure_ascii=False)


def normal_stream(
    *,
    query: str = "needle in the transcript",
    reply: str = "needle reply",
    session_id: str = SESSION,
) -> list[str]:
    """一条正常主会话流：归属证据首行 + 用户行 + 带时刻的 assistant 行。

    三行都带 ``sessionId``，assistant 行带显式 ``timestamp`` 字段 —— 配合外部项目断言即可
    跑出「零原因码、``partial`` 为假」的干净流，作为各降级用例的对照组。
    """
    return [
        header_line(),
        user_line(query, sessionId=session_id),
        assistant_line([text_block(reply)], sessionId=session_id, timestamp=TS),
    ]


def write_store(
    root: Path,
    lines: Sequence[str],
    *,
    session_id: str = SESSION,
    workspace_name: str | None = None,
    extra_files: Mapping[str, Sequence[str]] | None = None,
) -> Path:
    """在 ``root`` 下构造 ``<root>/projects/<workspace>/agent-transcripts/<id>.jsonl``。

    返回 transcript 目录（不是文件）：调用方要绝对路径必须自己拼接，本函数只写文件。
    ``workspace_name`` 默认用**有损编码**目录名（盘符/分隔符被替换）——CUR-05 的夹具：
    目录名不足以还原项目，归属只能来自行内证据或外部断言。
    """
    encoded = workspace_name or encode_workspace_dir(PROJECT)
    directory = root / STORE_MARKER / encoded / TRANSCRIPT_DIR_MARKER
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{session_id}.jsonl").write_text(
        "".join(line + "\n" for line in lines), encoding="utf-8"
    )
    for name, body in (extra_files or {}).items():
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(line + "\n" for line in body), encoding="utf-8")
    return directory


def encode_workspace_dir(path: str) -> str:
    """把项目路径压成目录名（**有损**：盘符与分隔符都换成 ``-``）。

    本函数是夹具侧的复刻，用于证明「解析层不据目录名反推项目」；它不是对真实
    Cursor 编码规则的主张（未取证）。
    """
    return path.replace(":", "-").replace(os.sep, "-").replace("/", "-").lstrip("-")


def gui_meta_shell(root: Path, *, workspace_name: str | None = None) -> Path:
    """CUR-10 夹具：GUI 侧 ``chat-files/meta.json`` 空壳（只证明条目存在）。

    读取适配器必须无视它 —— 把空壳当成「无消息会话」即为谎报。
    """
    encoded = workspace_name or encode_workspace_dir(PROJECT)
    directory = root / STORE_MARKER / encoded / "chat-files"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "meta.json").write_text(
        json.dumps({"sessions": [], "note": "synthetic gui shell"}), encoding="utf-8"
    )
    return directory
