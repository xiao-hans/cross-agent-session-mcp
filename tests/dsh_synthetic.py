"""合成 DSH 帧夹具：多帧 zstd JSONL（只写临时目录，绝不触碰真实 ``~/.dsh``）。

帧构造用**模块级** ``compression.zstd.compress``（一帧一条 JSONL 行）。3.14 起 stdlib
自带 ``compression.zstd``；运行环境无 zstd 后端时 :func:`frames_available` 返回 ``False``，
测试据此只跳过解压相关用例，解码入口契约用例（D-11）仍用固定字节夹具继续跑。
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

try:  # pragma: no cover - 取决于运行时
    from compression import zstd as _zstd
except Exception:  # noqa: BLE001 - 无后端时整套帧夹具不可用
    _zstd = None

SOURCE = "dsh"
SESSION = "dsh-session-0001"
PROJECT = "D:/synthetic/dsh-project"
OTHER_PROJECT = "D:/synthetic/other-project"
LABEL = "session-context"

SESSION_FILE_NAME = "session.v4.jsonl.zstd"
WORKSPACE_DIR = "workspace-a"

#: 聚合层搜索探针：正文里埋这个词，`search(query=NEEDLE)` 才可能命中；同一值也当
#: 「正文原文不得外泄」的哨兵（公开 dict 里不应出现它）。
NEEDLE = "needle"
NEEDLE_QUERY = NEEDLE
SECOND_NEEDLE = "needle two"

#: zstd 帧魔数与可跳过帧魔数（字节层夹具用得上，不依赖后端）。
FRAME_MAGIC = bytes.fromhex("28b52ffd")
SKIPPABLE_MAGIC = bytes.fromhex("502a4d18")

#: 无后端环境也能跑的极小固定帧夹具（D-11）：一帧，内容是头部行。
TINY_HEADER_FRAME = (
    b"\x28\xb5\x2f\xfd\x04\x00\x6e\x22\x2c\xce\x80\x7b\x22\x74\x79\x70\x65\x22\x3a"
    b"\x22\x73\x65\x73\x73\x69\x6f\x6e\x5f\x68\x65\x61\x64\x65\x72\x22\x2c\x22\x76"
    b"\x65\x72\x73\x69\x6f\x6e\x22\x3a\x22\x76\x34\x22\x7d\x0a"
)


def frames_available() -> bool:
    """本进程能否就地解帧（``compression.zstd`` 或 ``zstandard``）。"""
    return _zstd is not None


def compress_frame(payload: bytes) -> bytes:
    """一条完整帧：入参字节原样压缩（调用方自带行尾 ``\\n``）。"""
    if _zstd is None:
        raise RuntimeError("no zstd backend available for synthetic frame construction")
    return _zstd.compress(payload)


def frame(value: object) -> bytes:
    """一条 JSONL 帧：``json.dumps`` + ``\\n`` 后压缩。"""
    return compress_frame(json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n")


def header_frame(**fields: Any) -> bytes:
    """首帧（会话头）。默认 ``type=session_header``/``version=v4`` + 归属字段。"""
    payload: dict[str, Any] = {
        "type": "session_header",
        "version": "v4",
        "sessionId": SESSION,
        "cwd": PROJECT,
        "createdAt": "2026-03-01T10:00:00.000Z",
    }
    payload.update(fields)
    return frame(payload)


def plain_header_line(**fields: Any) -> str:
    """与 :func:`header_frame` 同载荷的**明文** JSONL 行（含行尾换行）。

    子进程解码通道的 stdout 是解压后的明文流，不是压缩帧；需要模拟它的夹具用本函数。
    """
    payload: dict[str, Any] = {
        "type": "session_header",
        "version": "v4",
        "sessionId": SESSION,
        "cwd": PROJECT,
        "createdAt": "2026-03-01T10:00:00.000Z",
    }
    payload.update(fields)
    return json.dumps(payload, ensure_ascii=False) + "\n"


def plain_message_line(text: str, *, seq: int = 1, **outer: Any) -> str:
    """与 :func:`message_frame` 同载荷的**明文** JSONL 行（含行尾换行）。"""
    payload: dict[str, Any] = {
        "type": "assistant",
        "seq": seq,
        "time": 1_770_000_000,
        "data": {
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
        },
    }
    payload.update(outer)
    return json.dumps(payload, ensure_ascii=False) + "\n"


def message_frame(text: str, *, seq: int = 1, **outer: Any) -> bytes:
    """一帧正文：帧顶层键 ``data/seq/time/type``（04 取证的键形态）。

    ``type`` 取角色值（``assistant``）：解析器只认这种形态，非角色的 ``type`` 一律按
    不认识的帧类型计 ``unknown_event``。载荷可用 ``data`` 覆盖。
    """
    payload: dict[str, Any] = {
        "type": "assistant",
        "seq": seq,
        "time": 1_770_000_000,
        "data": {
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
        },
    }
    payload.update(outer)
    return frame(payload)


def user_frame(text: str, *, seq: int = 1, **outer: Any) -> bytes:
    payload: dict[str, Any] = {
        "type": "user",
        "seq": seq,
        "time": 1_770_000_000,
        "data": {"role": "user", "content": [{"type": "text", "text": text}]},
    }
    payload.update(outer)
    return frame(payload)


def raw_line_frame(line: bytes) -> bytes:
    """任意字节一帧（损坏行/非 JSON 行夹具）。"""
    return compress_frame(line if line.endswith(b"\n") else line + b"\n")


def split_line_frames(parts: Sequence[bytes]) -> bytes:
    """把**一行**拆进多帧：跨帧边界行必须在合并流上拼接（DSH-01）。"""
    return b"".join(compress_frame(part) for part in parts)


def skippable_frame(payload_size: int = 8, filler: bytes = b"dshskiplst") -> bytes:
    """可跳过帧（魔数 ``50 2A 4D 18`` + 4 字节小端长度 + 载荷）。"""
    body = filler[:payload_size]
    return SKIPPABLE_MAGIC + len(body).to_bytes(4, "little") + body


def truncated_frame(text: str) -> bytes:
    """末帧截断：完整帧的前若干字节（DSH-02）。"""
    full = frame({"type": "assistant", "seq": 9, "data": {"role": "assistant", "content": [
        {"type": "text", "text": text}]}})
    return full[: max(1, len(full) // 2)]


def bad_magic_bytes() -> bytes:
    """魔数不符的字节流（DSH-03）：看着像数据，但不是 zstd 帧。"""
    return b"NOT-A-ZSTD-FRAME-PAYLOAD"


def bomb_frames(line_bytes: int = 65_536, frames: int = 8) -> bytes:
    """低压缩比多帧（DSH-09）：每帧解压后 ``line_bytes`` 字节的随机-ish 文本。

    内容用不可压缩的十六进制噪声，保证解压总量明显大于压缩总量，触顶判据才有效。
    """
    if _zstd is None:
        raise RuntimeError("no zstd backend available for synthetic frame construction")
    out: list[bytes] = []
    for _ in range(frames):
        body = os.urandom(line_bytes // 2).hex().encode("ascii")
        out.append(compress_frame(body + b"\n"))
    return b"".join(out)


def build_session_bytes(frames: Sequence[bytes]) -> bytes:
    """按序拼接帧 → 一个 ``session.v4.jsonl.zstd`` 的完整字节内容。"""
    return b"".join(frames)


def write_session(
    root: Path,
    frames: Sequence[bytes],
    *,
    session_id: str = SESSION,
    workspace: str = WORKSPACE_DIR,
    file_name: str = SESSION_FILE_NAME,
) -> Path:
    """写 ``<root>/sessions/<workspace>/<session-id>/session.v4.jsonl.zstd``，返回文件路径。

    目录名不参与项目还原（计划 §4.4）：本函数只是把字节放到磁盘上。
    """
    directory = root / "sessions" / workspace / session_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / file_name
    path.write_bytes(build_session_bytes(frames))
    return path


def write_raw_session(root: Path, raw: bytes, *, session_id: str = SESSION,
                      workspace: str = WORKSPACE_DIR, file_name: str = SESSION_FILE_NAME) -> Path:
    """直接写字节流（截断/坏魔数/固定字节夹具用）。"""
    directory = root / "sessions" / workspace / session_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / file_name
    path.write_bytes(raw)
    return path


def parse_frames(raw: bytes, *, runtime: Any = None, **reader_kwargs: Any):
    """便利入口：``DshFrameReader(raw, runtime).iter_lines()`` 的元组形式。"""
    from cross_agent_session_mcp.sources.dsh import DshDecoderRuntime, DshFrameReader

    active = runtime if runtime is not None else DshDecoderRuntime.probe()
    return DshFrameReader(raw, active, **reader_kwargs)
