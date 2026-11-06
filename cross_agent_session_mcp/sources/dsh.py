"""`dsh` 来源适配：压缩帧会话存储（`session.v4.jsonl.zstd`）的解码、行解析与有界执行。

本模块只做三件事，且都**不**跨层：

1. **解码运行时核定**（`DshDecoderRuntime.probe`）：当前进程能否就地解压（`in_process`）、
   只能借一个由调用方给定的解释器进程解压（`subprocess`）、或两条都不通（`missing`）。三态
   互不合并，`missing` 永不降级成「该面无会话」。
2. **帧流→行流**（`DshFrameReader`）：把 zstd 帧序列还原成**解压后的行流**，并交出解压侧的
   终态（帧数、字节量、是否走到真 EOF）。行号是**解压后事件序号**（1 起始），绝不冒充原始
   文件的字节偏移。
3. **逐行解析**（`DshLineParser`）：接口形态与 `PiLineParser` / `CursorAgentTranscriptLineParser`
   一致（`feed` / `feed_line` / `finish` + `stats` / `header` / `session_id` / `project` /
   `asserted_project` / `project_conflict` / `project_quality`），因此能直接作为
   `line_search.LineSourceSpec.parser_factory`；帧内 `seq` 是事件序号证据，用作
   `SourceLocation.ordinal`。

未核实的部分（本轮禁止读取 `~/.dsh`，因此全部按保守分支落地，并在代码里标出对应的「实测
后」开关）：

- 头部帧的 `cwd` 由谁写入、语义是否等于项目根 → `DSH_HEADER_CWD_TRUSTED = False`，头部
  `cwd` 一律 `unverified_header_cwd`，归属不成立 ⇒ 搜索 legitimately 零发布并保持 partial。
- `surfaceOp` / `sourceEventSeqs` 两类字段的语义 → `DSH_KNOWN_SURFACE_OP = False`，出现即计
  `unknown_event` 并令整流 `partial`（认识它的那条路径留在开关后面，取证后翻转即可）。
- 版本白名单 `DSH_SUPPORTED_VERSIONS` 只有 `"v4"`（文件名里的 `v4`）：白名单外一律
  `unsupported_header_version` + 整文件不支持，不去猜别的版本长什么样。

安全边界（DES-SEC-02）：压缩字节**不**走 `authorize_read` 的行读通道——该通道会对首 16 字节
做魔数检测，zstd 帧魔数（`0x28 0xB5 0x2F 0xFD`）在其拒绝清单内（`not_plain_text`）。本模块
因此只用 `safe_reader.authorize_raw_bytes`：与 `authorize_content_digest` 同一套原语（策略
类型门 → `authorize_store` → 打开前基线核对 → 句柄身份 → 最终路径再核对 → 有界顺序读 →
`finally` 关闭），差别只是把「只留摘要」换成「同时交出有界字节」。这条通道只用于本模块。

`subprocess` 模式只喂字节：argv 是本模块的固定常量（解释器路径 + `-c` + 固定脚本 + 数字
上限），**绝不**传会话文件路径（路径入参会绕过打开前的基线核对、句柄身份与最终路径复校，
让被改写路径顶替已核对的那个对象）；stderr 丢弃，输出按上限截断。
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from ..models import (
    TIMESTAMP_ISSUES,
    IssueCode,
    ParseStats,
    ProjectQuality,
    SourceLocation,
    StandardRecord,
    TimeQuality,
    normalize_timestamp,
    sanitize_stream_label,
)
from ..policy import (
    PolicyDenied,
    RefusalCode,
    SessionPolicy,
    TargetKind,
)
from ..safe_reader import (
    DEFAULT_MAX_TOTAL_BYTES,
    FileVersion,
    RawBytesResult,
    ReadOutcome,
    ReadStop,
    SafeReadDenied,
    authorize_raw_bytes,
)
from ..session_pipeline import (
    MAX_CANDIDATES_PER_SESSION,
    MAX_STAGE_BYTES_PER_SESSION,
    PiSessionPipeline,
)

__all__ = [
    "DSH_COVERAGE_SCOPE",
    "DSH_DECOMPRESS_TIMEOUT_SECONDS",
    "DSH_FILE_SUFFIX",
    "DSH_HEADER_CWD_TRUSTED",
    "DSH_HEADER_FRAME_INDEX",
    "DSH_KNOWN_SOURCE_EVENT_SEQS",
    "DSH_KNOWN_SURFACE_OP",
    "DSH_SESSION_FILE_NAME",
    "DSH_SUPPORTED_VERSIONS",
    "MAX_DSH_DECOMPRESSED_BYTES_PER_SESSION",
    "MAX_DSH_FRAME_BYTES_READ_CHUNK",
    "MAX_DSH_FRAMES_PER_SESSION",
    "MAX_DSH_LINE_BYTES",
    "MAX_LINES_PER_STREAM",
    "DshDecoderMode",
    "DshDecoderRuntime",
    "DshDiscoveryOutcome",
    "DshDiscoveryStatus",
    "DshFileOutcome",
    "DshFrameReader",
    "DshHeaderInfo",
    "DshLineParser",
    "DshStreamError",
    "DshStreamStop",
    "SOURCE_DSH",
    "discover_dsh_sessions",
    "run_dsh_frame_file",
]

#: 标准记录里的来源标识，与 `policy.KNOWN_SOURCES` / `server.REQUIRED_SOURCES` 一致。
SOURCE_DSH = "dsh"

# ---------- 存储形态（DES-INC-03 实测到的文件名/后缀；目录名不参与归属还原） ----------

DSH_SESSION_FILE_NAME = "session.v4.jsonl.zstd"
#: 压缩会话文件的后缀门：只有以此结尾的条目才进候选。
DSH_FILE_SUFFIX = ".jsonl.zstd"
DSH_DECODER_MISSING_REASON = "解码运行时缺失"

# ---------- 不可信输入的固定资源上限（DES-INC-01；解压侧另计） ----------

#: 逐块读取解压输出的粒度：与压缩侧读块同量级，避免一次性物化整段明文。
MAX_DSH_FRAME_BYTES_READ_CHUNK = 262_144
#: 单文件帧数上限：超出即判扫描不完整（帧数由调用方预算兜住，不靠信任文件）。
MAX_DSH_FRAMES_PER_SESSION = 50_000
#: 单行字节上限：与 `safe_reader.HARD_MAX_LINE_BYTES` 同值；超限行断在这里，交给解析器判形。
MAX_DSH_LINE_BYTES = 1_048_576
#: 单文件解压总量上限（防解压炸弹）：达到即停止解码并交代不完整，绝不继续喂解析器。
MAX_DSH_DECOMPRESSED_BYTES_PER_SESSION = 268_435_456
#: 帧头魔数（zstd regular frame）与可跳过帧魔数。
_FRAME_MAGIC = b"\x28\xb5\x2f\xfd"
_SKIPPABLE_MAGIC = b"\x50\x2a\x4d\x18"
#: `subprocess` 模式的等待上限：只约束等待，不约束路径。
DSH_DECOMPRESS_TIMEOUT_SECONDS = 30

#: 头部帧序号（0 起始）：第一帧即会话头部——按实测到的写入形态处理。
DSH_HEADER_FRAME_INDEX = 0
#: 头部 `cwd` 是否已核实为可信归属。**本轮未取证**，因此恒 `False`。
DSH_HEADER_CWD_TRUSTED = False
#: `surfaceOp` 是否已核实为非正文元信息。**本轮未取证**，因此恒 `False`
#: （出现即 `unknown_event` 并令整流 `partial`，不冒充「已理解并安全省略」）。
DSH_KNOWN_SURFACE_OP = False
#: `sourceEventSeqs` 是否已核实为非正文元信息。与 `surfaceOp` 是两类字段、两份取证：
#: 各自独立成门，才不会出现「核实了一项就顺带宣称另一项也认识」。
DSH_KNOWN_SOURCE_EVENT_SEQS = False
#: 已核实的头部版本白名单；白名单外一律整文件不支持。
DSH_SUPPORTED_VERSIONS: frozenset[str] = frozenset({"v4"})

#: 可产出检索正文的角色（当前任务边界，不是「其余角色可安全忽略」）。
TEXT_ROLES: frozenset[str] = frozenset({"assistant", "user"})
#: 已知但不是检索正文的角色：计 `skipped_role`（覆盖不完整），不上报角色名。
KNOWN_NON_TEXT_ROLES: frozenset[str] = frozenset(
    {"developer", "function", "system", "tool"}
)
#: 已知但不是检索正文的块类型：计 `known_non_text_block`（已理解的省略，不降级）。
KNOWN_NON_TEXT_BLOCKS: frozenset[str] = frozenset(
    {"audio", "image", "reasoning", "resource", "thinking", "toolcall", "tool_result", "tool_use"}
)
#: 被视为文本块的 `type` 值。
TEXT_BLOCK_TYPES: frozenset[str] = frozenset({"input_text", "output_text", "text"})

#: 单块正文上限（与行式族同值）。
MAX_TEXT_BLOCK_CHARS = 32_768
#: 单帧正文块数上限（嵌套双限的第一道）。
MAX_CONTENT_BLOCKS_PER_FRAME = 32
MAX_LINE_CHARS = 262_144
MAX_LINES_PER_STREAM = 200_000

#: DSH 聚合层的结论范围标签（计划 §2 D-3）：多帧压缩文件的集合完整性与行式来源不是同一
#: 种口径 —— 行式来源受「读到 EOF」约束，DSH 还多一层「解压到真 EOF」。因此单列一个标签，
#: 不复用 `bounded_line_file_set:dsh`，免得宿主把两种完整性承诺当成同一件事。
DSH_COVERAGE_SCOPE = "bounded_dsh_frame_set"
MAX_PROJECT_VALUE_CHARS = 512
MAX_SESSION_ID_CHARS = 256
MAX_MATCH_KEY_CHARS = 64
MAX_HEADER_VERSION_CHARS = 32
#: 会话序号的可外发上界（与 `query.MAX_MATCH_ORDINAL` 同一量级判断，本层只做形态门）。
_MAX_ORDINAL_VALUE = 65_535

# ---------- 候选键（按优先级；命名差异容错，但不猜语义） ----------

_FRAME_TYPE_KEYS: tuple[str, ...] = ("type",)
_FRAME_DATA_KEYS: tuple[str, ...] = ("data",)
_FRAME_SEQ_KEYS: tuple[str, ...] = ("seq",)
_FRAME_TIME_KEYS: tuple[str, ...] = ("time", "timestamp", "created_at", "createdAt")
_FRAME_CWD_KEYS: tuple[str, ...] = ("cwd", "workingDirectory", "working_directory")
_FRAME_SESSION_ID_KEYS: tuple[str, ...] = ("sessionId", "session_id", "id")
_FRAME_VERSION_KEYS: tuple[str, ...] = ("version", "v")
_FRAME_SURFACE_OP_KEYS: tuple[str, ...] = ("surfaceOp", "surface_op")
_FRAME_SOURCE_SEQS_KEYS: tuple[str, ...] = ("sourceEventSeqs", "source_event_seqs")
_ROLE_KEYS: tuple[str, ...] = ("role",)
_TEXT_KEYS: tuple[str, ...] = ("text", "content", "message")
#: 已知不产正文的帧类型（元信息/索引/遥测）。
_NON_TEXT_EVENT_TYPES: frozenset[str] = frozenset(
    {"session_header", "headers", "usage", "token_usage", "summary", "title", "meta"}
)
_FIELD_NOT_PRESENT = object()


# ---------------------------------------------------------------------------
# 形态门小工具（与行式族同一口径：判空、判型、判长；超长一律不截断使用）
# ---------------------------------------------------------------------------


def _first_present(mapping: dict[str, Any], keys: Sequence[str]) -> Any:
    """返回第一个存在且非 None 的键值；都不存在或都为 None 时返回 None。"""
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return None


def _has_field(mapping: dict[str, Any], keys: Sequence[str]) -> bool:
    """任一候选键是否存在（含值为 None）：区分「字段缺失」与「字段无效」。"""
    return any(key in mapping for key in keys)


def _as_text(value: Any, max_chars: int | None = None) -> str | None:
    """规范为非空字符串（保留原大小写）；非字符串、空白或**超长**返回 None。

    超长判不可用而不截断：截断后的标识/项目名是个不存在的值，拿它比对归属比「不知道」更糟。
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if max_chars is not None and len(stripped) > max_chars:
        return None
    return stripped


def _as_role(value: Any) -> str | None:
    """role/事件类型规范成小写比较键；非字符串、空白或超 `MAX_MATCH_KEY_CHARS` 返回 None。"""
    text = _as_text(value, MAX_MATCH_KEY_CHARS)
    return text.lower() if text is not None else None


def _is_oversized_text(value: Any) -> bool:
    """值是非空白字符串但超出 `MAX_MATCH_KEY_CHARS`（因此已归为 None）。"""
    return isinstance(value, str) and len(value.strip()) > MAX_MATCH_KEY_CHARS


def _bounded_text(value: str) -> tuple[str, bool]:
    """正文只保留前 `MAX_TEXT_BLOCK_CHARS` 个字符；返回 `(正文, 是否被截断)`。"""
    if len(value) <= MAX_TEXT_BLOCK_CHARS:
        return value, False
    return value[:MAX_TEXT_BLOCK_CHARS], True


def _version_text(value: Any) -> str | None:
    """版本字段规范成短字符串：接受 str 与整数（不含 bool），其它形状返回 None。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value.bit_length() > MAX_HEADER_VERSION_CHARS * 4:
            return None
        return str(value)
    return _as_text(value, MAX_HEADER_VERSION_CHARS)


def _frame_ordinal(payload: dict[str, Any]) -> tuple[int, bool]:
    """帧序号 `seq` → 位置序号；返回 `(ordinal, 是否来自 seq 字段)`。

    只接受字面 `int`（`bool` 不算）且 `0 <= seq <= _MAX_ORDINAL_VALUE`。seq 是本来源**事件
    序号证据**，因此优先作 `SourceLocation.ordinal`；不可用时退回 0（同一帧内正文合并成一条
    记录，(行号, 0) 仍逐帧唯一，不与其他帧撞坐标）。退回不新增原因码：它不声称任何语义，
    只是少了一路序号证据。
    """
    raw = _first_present(payload, _FRAME_SEQ_KEYS)
    if isinstance(raw, bool) or not isinstance(raw, int):
        return 0, False
    if raw < 0 or raw > _MAX_ORDINAL_VALUE:
        return 0, False
    return raw, True


# ---------------------------------------------------------------------------
# 解码运行时（三态不合并）
# ---------------------------------------------------------------------------


class DshDecoderMode(StrEnum):
    """解码能力三态：就地、借外部解释器、两者都不通。

    `MISSING` 是一条**独立终态**：既不是「该面无会话」（`no_match`），也不是「读到一半坏了」
    （`error`）。把它压成任何一种都会让人以为存储已被看过。
    """

    IN_PROCESS = "in_process"
    SUBPROCESS = "subprocess"
    MISSING = "missing"


#: 外部解释器的能力探测脚本（固定常量，不含任何路径参数）：只做一次自压缩自解压往返。
_DECODER_PROBE_SCRIPT = (
    "import sys\n"
    "mod = None\n"
    "for name in ('compression.zstd', 'zstandard'):\n"
    "    try:\n"
    "        mod = __import__(name, fromlist=[''])\n"
    "        break\n"
    "    except Exception:\n"
    "        mod = None\n"
    "if mod is None or not hasattr(mod, 'ZstdDecompressor'):\n"
    "    sys.exit(4)\n"
    "try:\n"
    "    blob = mod.compress(b'probe')\n"
    "    if mod.ZstdDecompressor().decompress(blob) != b'probe':\n"
    "        sys.exit(3)\n"
    "except Exception:\n"
    "    sys.exit(3)\n"
    "sys.exit(0)\n"
)

#: 外部解释器的解压脚本（固定常量）：stdin 收压缩字节，stdout 吐明文，超过 argv 上限即止。
_DECOMPRESS_SCRIPT = (
    "import sys\n"
    "mod = None\n"
    "for name in ('compression.zstd', 'zstandard'):\n"
    "    try:\n"
    "        mod = __import__(name, fromlist=[''])\n"
    "        break\n"
    "    except Exception:\n"
    "        mod = None\n"
    "if mod is None:\n"
    "    sys.exit(4)\n"
    "limit = int(sys.argv[1])\n"
    "total = 0\n"
    "try:\n"
    "    data = sys.stdin.buffer.read()\n"
    "    out = sys.stdout.buffer\n"
    "    offset = 0\n"
    "    size = mod.get_frame_size\n"
    "    while offset < len(data):\n"
    "        frame = size(data[offset:])\n"
    "        if frame <= 0:\n"
    "            sys.exit(3)\n"
    "        room = limit - total\n"
    "        chunk = mod.ZstdDecompressor().decompress(\n"
    "            data[offset:offset + frame], max_length=room + 1\n"
    "        )\n"
    "        total += len(chunk)\n"
    "        if total > limit:\n"
    "            sys.exit(5)\n"
    "        out.write(chunk)\n"
    "        offset += frame\n"
    "    out.flush()\n"
    "except Exception:\n"
    "    sys.exit(3)\n"
    "sys.exit(0)\n"
)


def _usable_backend(module: Any) -> bool:
    """形态要求：既能逐帧取帧长、又能构造解压器、还能自压缩（探测用）。

    只有 `get_frame_size` 在场，帧界才是确定的，截断与坏魔数才谈得上分类。缺任何一项都按
    「本进程不能就地解码」处理，不拿部分 API 猜行为。
    """
    return bool(
        hasattr(module, "ZstdDecompressor")
        and hasattr(module, "get_frame_size")
        and hasattr(module, "compress")
    )


def _load_backend() -> Any | None:
    """当前进程可用的 zstd 后端模块；两条**字面**导入路径都不合形态要求时返回 `None`。

    导入名写死为字面量（不用变量名动态导入）：本模块的候选后端是一个闭合集合，任何非字面
    导入都会把「后端探测」变成「按输入决定加载什么代码」，那不是本层该有的能力。
    """
    try:
        from compression import zstd as _compression_zstd
    except Exception:
        _compression_zstd = None
    if _usable_backend(_compression_zstd):
        return _compression_zstd
    try:
        # 候选后端名写死为字面量，缺失即回落 None；本仓不安装 zstandard，静态解析不到属预期。
        import zstandard as _zstandard  # pyright: ignore[reportMissingImports] # noqa: F401
    except Exception:
        _zstandard = None
    if _usable_backend(_zstandard):
        return _zstandard
    return None


def _backend_error_type(backend: Any) -> type[BaseException]:
    """后端异常类型（无 `ZstdError` 时退回 `Exception`）。"""
    return getattr(backend, "ZstdError", Exception)


@dataclass(frozen=True)
class DshDecoderRuntime:
    """解码运行时结论：模式 + 外部解释器路径（仅 `subprocess` 有意义）。

    `python_path` 只做「能不能借它解码」的探测，**从不**与会话文件路径一起进入 argv：路径
    入参会绕过打开前的基线核对、句柄身份与最终路径复校。因此本字段外发时只用于诊断行显示
    「用哪个解释器」，不参与任何读取决策。
    """

    mode: DshDecoderMode
    python_path: str | None = None

    #: 就地解码的后端模块（进程内缓存；`subprocess`/`missing` 下为 None）。
    _backend: Any = None

    @staticmethod
    def probe(python_path: object = None) -> DshDecoderRuntime:
        """核定解码运行时：① 就地 ② 外部解释器 ③ 都不通。

        本函数**不读任何配置文件**：`python_path` 只能由调用方（服务绑定处）给出；给的不是
        非空字符串就当没给。探测只跑固定脚本，不接触会话存储。
        """
        backend = _load_backend()
        if backend is not None:
            return DshDecoderRuntime(mode=DshDecoderMode.IN_PROCESS, _backend=backend)
        candidate = python_path if isinstance(python_path, str) else None
        if candidate is not None and candidate.strip():
            try:
                done = subprocess.run(  # noqa: S603 - argv 为本模块固定常量 + 调用方给出的解释器路径
                    [candidate, "-c", _DECODER_PROBE_SCRIPT],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError, ValueError):
                done = None
            if done is not None and done.returncode == 0:
                return DshDecoderRuntime(mode=DshDecoderMode.SUBPROCESS, python_path=candidate)
        return DshDecoderRuntime(mode=DshDecoderMode.MISSING)

    @property
    def usable(self) -> bool:
        return self.mode is not DshDecoderMode.MISSING


class DshStreamStop(StrEnum):
    """解压流的中止原因（只含闭合类别，不含任何原值）。"""

    EXHAUSTED = "exhausted"
    FRAME_LIMIT = "frame_limit"
    DECOMPRESSED_LIMIT = "decompressed_limit"
    TRUNCATED_FRAME = "truncated_frame"
    BAD_MAGIC = "bad_magic"
    DECODER_FAULT = "decoder_fault"
    DECODER_MISSING = "decoder_runtime_missing"


class DshStreamError(Exception):
    """解压在**产出任何行之前**失败：文件级错误，绝不降为「无匹配」。

    `category` 只取 `DshStreamStop` 的固定值；异常不携带路径、帧内容或后端原始消息。
    """

    def __init__(self, category: DshStreamStop) -> None:
        super().__init__(category.value)
        self.category = category

    def __repr__(self) -> str:  # pragma: no cover - 避免任何原值进日志
        return f"DshStreamError(category={self.category.value!r})"


# ---------------------------------------------------------------------------
# 帧读者：压缩字节 → 解压行流
# ---------------------------------------------------------------------------


class DshFrameReader:
    """把 zstd 帧序列还原成解压后的行流，并交出解压侧终态。

    行号是**解压后事件序号**（1 起始，含损坏行与空行，不含上限后的行）；跨帧的半行在合并
    字节流上拼接，因此一条 JSONL 记录被拆进多帧也只会是一行，不会被当成两行。

    三类终态严格分开（简报 §4.2）：

    - 产出任何行**之前**坏掉 → 抛 `DshStreamError`（文件级 `error`）。
    - 已产出行之后坏掉 → 收尾 + `FRAME_TRUNCATED` 记入解析计数（`partial`）。
    - 触到帧数/解压量上限 → 停止解码，`partial`，原因取上限本身，不谎称读到了 EOF。

    `in_process` 模式逐帧推进（帧界由 `get_frame_size` 确定，截断与坏魔数因此可分类）；
    `subprocess` 模式只能整段往返（帧界在对端），因此 `frames` 为 `None` 并如实标注「帧数
    不可计」，绝不拿行数冒充帧数。
    """

    __slots__ = (
        "_raw",
        "_runtime",
        "_max_line_bytes",
        "_max_decompressed",
        "_max_frames",
        "_timeout",
        "_frames",
        "_decompressed_bytes",
        "_oversized_lines",
        "_stop",
        "_consumed_prefix",
        "_exhausted",
    )

    def __init__(
        self,
        raw: bytes,
        runtime: DshDecoderRuntime,
        *,
        max_line_bytes: int = MAX_DSH_LINE_BYTES,
        max_decompressed_bytes: int = MAX_DSH_DECOMPRESSED_BYTES_PER_SESSION,
        max_frames: int = MAX_DSH_FRAMES_PER_SESSION,
        timeout_seconds: int = DSH_DECOMPRESS_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError("DshFrameReader expects the compressed bytes payload")
        if not isinstance(runtime, DshDecoderRuntime):
            raise TypeError("DshFrameReader expects a DshDecoderRuntime")
        for name, value in (
            ("max_line_bytes", max_line_bytes),
            ("max_decompressed_bytes", max_decompressed_bytes),
            ("max_frames", max_frames),
            ("timeout_seconds", timeout_seconds),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive int")
        # 只能收紧，不能放松：调用方给的超大值一律钳到本模块上限。
        self._raw = bytes(raw)
        self._runtime = runtime
        self._max_line_bytes = min(max_line_bytes, MAX_DSH_LINE_BYTES)
        self._max_decompressed = min(max_decompressed_bytes, MAX_DSH_DECOMPRESSED_BYTES_PER_SESSION)
        self._max_frames = min(max_frames, MAX_DSH_FRAMES_PER_SESSION)
        self._timeout = min(timeout_seconds, DSH_DECOMPRESS_TIMEOUT_SECONDS)
        self._frames: int | None = 0
        self._decompressed_bytes = 0
        self._oversized_lines = 0
        self._stop: DshStreamStop | None = None
        self._consumed_prefix = 0
        self._exhausted = False

    # -- 终态快照 ---------------------------------------------------------
    @property
    def frames(self) -> int | None:
        """已解码帧数（`subprocess` 模式为 `None`：帧界在对端，不可计）。"""
        return self._frames

    @property
    def decompressed_bytes(self) -> int:
        return self._decompressed_bytes

    @property
    def oversized_lines(self) -> int:
        """因超单行上限而被断开的行数（只计数，不回显内容）。"""
        return self._oversized_lines

    @property
    def stop_reason(self) -> DshStreamStop | None:
        return self._stop

    @property
    def clean_eof(self) -> bool:
        """是否走到**真** EOF：输入被完整消费到底，且没有中止原因悬在流上。

        只凭「无中止原因」会把惰性生成器**从未推进到末尾**（调用方提前中断、或根本还没开始
        消费）误读成干净收尾，所以下面还要有 `_exhausted`；帧数与总量触限同样不算 EOF。
        """
        return self._exhausted and self._stop in (None, DshStreamStop.EXHAUSTED)

    @property
    def consumed_prefix_bytes(self) -> int:
        """压缩侧被消费到的字节数（`in_process` 逐帧推进的真实进度；对端模式按全长）。"""
        return self._consumed_prefix

    @property
    def decoder_mode(self) -> DshDecoderMode:
        return self._runtime.mode

    # -- 主入口 -----------------------------------------------------------
    def iter_lines(self) -> Iterator[tuple[int, bytes]]:
        """产出 `(1 起始的解压后行序号, 行字节)`；行尾 `\\n` 已剥除。

        惰性推进：调用方提前中断时，本读者只会停在已经走过的帧界上，不预支后续帧。
        解压器不可用也走同一条惰性路径：在越过行流边界时才抛
        `DshStreamError(decoder_runtime_missing)`，本方法本身不同步抛错，
        否则 `run_dsh_frame_file` 的「任何行之前失败 = 文件级 error」收口会被绕过。
        """
        if not self._runtime.usable:
            return self._unusable()
        if self._runtime.mode is DshDecoderMode.IN_PROCESS:
            return self._iter_in_process()
        return self._iter_subprocess()

    def _unusable(self) -> Iterator[tuple[int, bytes]]:
        if self._stop is None:
            self._stop = DshStreamStop.DECODER_MISSING
        raise DshStreamError(DshStreamStop.DECODER_MISSING)
        yield  # pragma: no cover - 使其成为生成器

    def _assemble(self, chunks: Iterable[bytes]) -> Iterator[tuple[int, bytes]]:
        """在合并字节流上切行（跨帧拼接），并执行单行上限与解压总量上限。

        单行超上限时**先交出行首的上限长度**（解析器会把它判成损坏行并计入 `partial`），
        余下部分继续按行切：这不是「跳过一行」，而是把一个不可解释的巨大对象切成有界输入，
        行为与 `safe_reader` 的超限行同向。
        """
        index = 0
        buffer = bytearray()
        for chunk in chunks:
            if self._stop is not None:
                return
            self._decompressed_bytes += len(chunk)
            if self._decompressed_bytes > self._max_decompressed:
                # 防解压炸弹：达到上限立即停止，不再产出。已产出的行仍是真实内容，由调用方
                # 按 partial 处理；这里绝不静默截断后宣称完整。
                self._stop = DshStreamStop.DECOMPRESSED_LIMIT
                return
            start = 0
            span = len(chunk)
            while start < span:
                newline = chunk.find(b"\n", start)
                if newline < 0:
                    buffer.extend(chunk[start:])
                    break
                buffer.extend(chunk[start:newline])
                start = newline + 1
                index += 1
                yield from self._emit(bytes(buffer), index)
                buffer.clear()
                if self._stop is not None:
                    return
            if len(buffer) > self._max_line_bytes:
                index += 1
                oversized = bytes(buffer[: self._max_line_bytes])
                del buffer[: self._max_line_bytes]
                self._oversized_lines += 1
                yield from self._emit(oversized, index)
                if self._stop is not None:
                    return
        if buffer:
            # 末段无换行：仍然交出去（解析器会判形）；真 EOF 由调用方按 `_stop` 判。
            index += 1
            yield from self._emit(bytes(buffer), index)

    def _emit(self, line: bytes, index: int) -> Iterator[tuple[int, bytes]]:
        yield (index, line)

    # -- 就地逐帧 ---------------------------------------------------------
    def _iter_in_process(self) -> Iterator[tuple[int, bytes]]:
        backend = self._runtime._backend if self._runtime._backend is not None else _load_backend()
        if backend is None:
            self._stop = DshStreamStop.DECODER_MISSING
            raise DshStreamError(DshStreamStop.DECODER_MISSING)
        error_type = _backend_error_type(backend)

        def chunks() -> Iterator[bytes]:
            data = self._raw
            offset = 0
            total = len(data)
            frames = 0
            while offset < total:
                head = data[offset : offset + 4]
                if len(head) < 4:
                    # 残字节不足一个魔数：帧被截断。
                    self._stop = DshStreamStop.TRUNCATED_FRAME
                    return
                if head[:4] == _SKIPPABLE_MAGIC:
                    # 可跳过帧：按规范取 4 字节小端长度并跳过，不猜其内容。
                    if total - offset < 8:
                        self._stop = DshStreamStop.TRUNCATED_FRAME
                        return
                    extra = int.from_bytes(data[offset + 4 : offset + 8], "little")
                    if extra > self._max_decompressed:
                        self._stop = DshStreamStop.DECOMPRESSED_LIMIT
                        return
                    frames += 1
                    if frames > self._max_frames:
                        self._stop = DshStreamStop.FRAME_LIMIT
                        return
                    offset += 8 + extra
                    self._consumed_prefix = offset
                    continue
                if head != _FRAME_MAGIC:
                    self._stop = DshStreamStop.BAD_MAGIC
                    return
                try:
                    frame_size = backend.get_frame_size(data[offset:])
                except error_type:
                    # 帧头可读但长度不可确定：截断（尾部不完整）而非魔数错误。
                    self._stop = DshStreamStop.TRUNCATED_FRAME
                    return
                except Exception:
                    self._stop = DshStreamStop.DECODER_FAULT
                    return
                if frame_size <= 0 or offset + frame_size > total:
                    self._stop = DshStreamStop.TRUNCATED_FRAME
                    return
                try:
                    # 防解压炸弹：给对端的输出预算只剩 `remaining + 1` 字节。后端在 `max_length`
                    # 处**静默截断而不报错**，所以拿长度超限当作超预算的信号：整帧丢弃、不产出行，
                    # 绝不把半帧内容当真实正文交给调用方。
                    remaining = self._max_decompressed - self._decompressed_bytes
                    plain = backend.ZstdDecompressor().decompress(
                        data[offset : offset + frame_size],
                        max_length=remaining + 1,
                    )
                except error_type:
                    self._stop = DshStreamStop.DECODER_FAULT
                    return
                except Exception:
                    self._stop = DshStreamStop.DECODER_FAULT
                    return
                if len(plain) > remaining:
                    self._stop = DshStreamStop.DECOMPRESSED_LIMIT
                    return
                frames += 1
                yield plain
                offset += frame_size
                self._consumed_prefix = offset
                self._frames = frames
                if frames >= self._max_frames:
                    if offset < total:
                        self._stop = DshStreamStop.FRAME_LIMIT
                        return
                    self._exhausted = True
                    return
            # 走到这里才是把输入读到了底（真 EOF）；中途 return 或调用方提前中断都不会置位。
            self._exhausted = True

        # `yield from` 与逐条 yield 语义全等：`_assemble` 本身就是惰性生成器，触限/失败时
        # 提前结束，不预支后续行；下面的终态检查也只在生成器耗尽后才跑。
        yield from self._assemble(chunks())
        if self._stop is DshStreamStop.DECODER_FAULT:
            raise DshStreamError(DshStreamStop.DECODER_FAULT)
        if self._stop is DshStreamStop.BAD_MAGIC:
            raise DshStreamError(DshStreamStop.BAD_MAGIC)
        if self._stop is DshStreamStop.TRUNCATED_FRAME:
            raise DshStreamError(DshStreamStop.TRUNCATED_FRAME)

    # -- 外部解释器 -------------------------------------------------------
    def _iter_subprocess(self) -> Iterator[tuple[int, bytes]]:
        python_path = self._runtime.python_path
        if not python_path:
            self._stop = DshStreamStop.DECODER_MISSING
            raise DshStreamError(DshStreamStop.DECODER_MISSING)
        self._frames = None  # 帧界在对端：不猜、不拿行数顶替。
        argv = [python_path, "-c", _DECOMPRESS_SCRIPT, str(self._max_decompressed)]
        try:
            done = subprocess.run(  # noqa: S603 - argv 全为本模块固定常量与自身上限
                argv,
                input=self._raw,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._stop = DshStreamStop.DECODER_FAULT
            raise DshStreamError(DshStreamStop.DECODER_FAULT) from None
        except (OSError, ValueError, subprocess.SubprocessError):
            self._stop = DshStreamStop.DECODER_FAULT
            raise DshStreamError(DshStreamStop.DECODER_FAULT) from None
        if done.returncode == 5:
            self._stop = DshStreamStop.DECOMPRESSED_LIMIT
            raise DshStreamError(DshStreamStop.DECOMPRESSED_LIMIT)
        if done.returncode == 4:
            self._stop = DshStreamStop.DECODER_MISSING
            raise DshStreamError(DshStreamStop.DECODER_MISSING)
        if done.returncode != 0:
            # 对端只告诉我们「坏了」：坏在哪一帧、是截断还是魔数，无法在对端之外区分，因此
            # 报最保守的 decoder_fault（不假装知道是截断）。stderr 不回显、不落日志。
            self._stop = DshStreamStop.DECODER_FAULT
            raise DshStreamError(DshStreamStop.DECODER_FAULT)
        payload = done.stdout
        self._consumed_prefix = len(self._raw)
        step = MAX_DSH_FRAME_BYTES_READ_CHUNK
        yield from self._assemble(
            payload[start : start + step] for start in range(0, len(payload), step)
        )
        # `EXHAUSTED` 只能在流**真的走完**之后写：放在 `yield from` 之前会让 `_assemble` 的
        # 首个预算/行限检查看到已置位的停止原因，从而一行不产（子进程解码永远零输出）。
        # 已在流上置位的停止原因（解压炸弹、行限、帧数上限）一律不覆盖。
        if self._stop is None:
            self._exhausted = True
            self._stop = DshStreamStop.EXHAUSTED


# ---------------------------------------------------------------------------
# 行解析器
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DshHeaderInfo:
    """已读到的头部帧快照。

    `trusted` 只有在 `DSH_HEADER_CWD_TRUSTED` 为真（本轮未取证）时才可能为真；否则恒
    `False`，头部 `cwd` 只作为「有值但出处存疑」的证据留存，永不确立可信归属。
    """

    session_id: str | None = None
    cwd: str | None = None
    created_at: str | None = None
    version: str | None = None
    line_no: int | None = None
    seen: bool = False
    trusted: bool = False


class DshLineParser:
    """逐行解析 `dsh` 的解压后 JSONL 帧流，产出 `StandardRecord`。

    与 `PiLineParser` 同接口（`feed` / `feed_line` / `finish` + `stats` / `header` /
    `session_id` / `project` / `asserted_project` / `project_conflict` / `project_quality`），
    可直接作为 `LineSourceSpec.parser_factory`。本来源另暴露两个只读信号：

    - `unsupported_version`：头部版本落在白名单外。调用方（`run_dsh_frame_file`）据此把整
      个文件判为不支持——本层不在 `IssueCode` 里新增「不支持来源」这类语义，也不靠
      `partial` 让调用方猜。
    - `frame_no`：当前帧序号（0 起始），头部判定用。

    行号是**解压后事件序号**（1 起始），`seq` 字段作 `SourceLocation.ordinal`；单帧内的多个
    正文块**合并为一条记录**（换行拼接），因为 (帧号, seq) 才是本来源的事件坐标——把它们拆成
    同坐标的多条记录会让 ctxref 无法唯一回指。
    """

    def __init__(
        self,
        *,
        stream_label: str | None = None,
        session_id: str | None = None,
        project: str | None = None,
        source: str = SOURCE_DSH,
    ) -> None:
        """`session_id` 为会话归属校验断言，`project` 为上层给定的 **cwd 断言**。

        两者本层都**不验证**；`project` 传的是工作目录（与头部 `cwd` 同类值），不是策略里的
        项目名。`source` 不开放：记录来源固定 `dsh`。
        """
        self._stream_label = sanitize_stream_label(stream_label)
        self._asserted_project = _as_text(project, MAX_PROJECT_VALUE_CHARS)
        self._expected_session_id = _as_text(session_id, MAX_SESSION_ID_CHARS)
        normalized_source = _as_text(source, MAX_MATCH_KEY_CHARS)
        if normalized_source is not None and normalized_source != SOURCE_DSH:
            raise ValueError(
                "DshLineParser records always carry the fixed source 'dsh'"
            )
        self._source = SOURCE_DSH
        self._stats = ParseStats()
        self._header = DshHeaderInfo()
        self._line_no = 0
        self._frame_no = -1
        self._session_id: str | None = self._expected_session_id
        self._session_id_conflict = False
        self._project = self._asserted_project
        self._project_conflict = False
        if self._asserted_project is not None:
            self._project_quality = ProjectQuality.CALLER_ASSERTED
        else:
            self._project_quality = ProjectQuality.UNKNOWN
        self._line_limit_exceeded = False
        self._unsupported_version = False
        self._finished = False

    # -- 只读快照 ---------------------------------------------------------
    @property
    def stats(self) -> ParseStats:
        return self._stats

    @property
    def header(self) -> DshHeaderInfo:
        return self._header

    @property
    def session_id(self) -> str | None:
        """可核实的会话标识：需两个独立来源一致，否则 `None`。"""
        return self._session_id if self._verified_session_id() is not None else None

    @property
    def project(self) -> str | None:
        return self._project

    @property
    def asserted_project(self) -> str | None:
        return self._asserted_project

    @property
    def project_conflict(self) -> bool:
        return self._project_conflict

    @property
    def project_quality(self) -> ProjectQuality:
        return self._project_quality

    @property
    def unsupported_version(self) -> bool:
        """头部版本落在 `DSH_SUPPORTED_VERSIONS` 之外（整文件不支持的信号）。"""
        return self._unsupported_version

    @property
    def frame_no(self) -> int:
        return self._frame_no

    # -- 生命周期 ---------------------------------------------------------
    def finish(self) -> None:
        """收束整流：补齐归属结论。重复调用无副作用。"""
        if self._finished:
            return
        self._finished = True
        if not self._header.seen:
            # 头部帧缺失：版本与归属都无从判定，整流不得称完整。
            self._stats.note(IssueCode.NO_SESSION_HEADER)
        if self._project is None and self._project_quality is not ProjectQuality.TRUSTED_HEADER_CWD:
            self._stats.note(IssueCode.UNKNOWN_PROJECT)

    def feed(self, lines: Iterable[str | bytes]) -> Iterator[StandardRecord]:
        """按序消费行流，惰性产出记录；整个 `str`/`bytes` 直接 `TypeError`。"""
        if isinstance(lines, (str, bytes, bytearray)):
            raise TypeError("feed requires an iterable of lines, not a whole str/bytes payload")
        if self._finished:
            raise RuntimeError("parser is finished; create a new instance for a new stream")
        return self._iterate(lines)

    def _iterate(self, lines: Iterable[str | bytes]) -> Iterator[StandardRecord]:
        try:
            for line in lines:
                if self._line_limit_exceeded:
                    break
                yield from self.feed_line(line)
        finally:
            self.finish()

    def feed_line(self, line: str | bytes) -> list[StandardRecord]:
        """解析一行（一帧的 JSON），返回该行产出的记录（0 或 1 条正文记录）。"""
        if self._finished:
            raise RuntimeError("parser is finished; create a new instance for a new stream")
        if self._line_limit_exceeded:
            return []
        if self._line_no >= MAX_LINES_PER_STREAM:
            self._line_limit_exceeded = True
            self._stats.note(IssueCode.MAX_STREAM_LINES_EXCEEDED)
            return []
        self._line_no += 1
        self._frame_no = self._line_no - 1
        self._stats.lines_seen += 1
        text = self._decode(line)
        if text is None:
            return []
        stripped = text.lstrip("\ufeff").strip()
        if not stripped:
            self._stats.note(IssueCode.BLANK_LINE)
            return []
        try:
            payload = json.loads(stripped)
        except (ValueError, RecursionError):
            self._stats.note(IssueCode.CORRUPT_LINE)
            return []
        if not isinstance(payload, dict):
            self._stats.note(IssueCode.LINE_NOT_OBJECT)
            return []
        return self._dispatch(payload)

    # -- 行内分派 ---------------------------------------------------------
    def _dispatch(self, payload: dict[str, Any]) -> list[StandardRecord]:
        # 非正文元信息字段先判：语义未取证时宁可让整流不完整，也不把它当普通消息。两项门
        # 各自独立：只有对应字段已核实，才降级为「已理解的省略」。
        if _has_field(payload, _FRAME_SURFACE_OP_KEYS) and not DSH_KNOWN_SURFACE_OP:
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []
        if _has_field(payload, _FRAME_SOURCE_SEQS_KEYS) and not DSH_KNOWN_SOURCE_EVENT_SEQS:
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []
        if _has_field(payload, _FRAME_SURFACE_OP_KEYS) or _has_field(
            payload, _FRAME_SOURCE_SEQS_KEYS
        ):
            self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
            return []

        raw_type = _first_present(payload, _FRAME_TYPE_KEYS)
        if _is_oversized_text(raw_type):
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []
        event_type = _as_role(raw_type)

        if event_type == "session_header":
            # 头部帧只按**类型**吸收：首帧才采信，后出现的头部记 `late_session_header`，
            # 绝不覆盖首个头部的归属与会话标识。
            if self._frame_no == DSH_HEADER_FRAME_INDEX:
                self._adopt_header(payload, event_type=event_type)
                if not self._unsupported_version:
                    self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
            else:
                self._stats.note(IssueCode.LATE_SESSION_HEADER)
            return []

        if self._frame_no == DSH_HEADER_FRAME_INDEX:
            # 首帧不是头部：仍采集其字段作缺席证据（缺 `version` 即计 `missing_header_version`），
            # 但该帧照常解析，不因「占了头部位」而丢失正文。
            self._adopt_header(payload, event_type=event_type)
            if event_type is None:
                self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
                return []

        if event_type is not None and event_type not in TEXT_ROLES:
            if event_type in _NON_TEXT_EVENT_TYPES:
                # 头部之外的元信息帧同样不产正文。
                if not self._unsupported_version:
                    self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
            else:
                # 已识别但不是消息的事件：不声称认识其正文，按 unknown_event 令 partial。
                self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []

        data = payload.get("data", _FIELD_NOT_PRESENT)
        if data is _FIELD_NOT_PRESENT or data is None:
            self._stats.note(IssueCode.MISSING_MESSAGE_ENVELOPE)
            return []
        if not isinstance(data, dict):
            # 非对象 data（字符串/数组/数字）：不猜其语义。
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            return []
        return self._handle_frame(payload, data)

    def _adopt_header(self, payload: dict[str, Any], *, event_type: str | None) -> None:
        """头部帧吸收：版本白名单 → 会话标识 → `cwd`（按未取证分支处理）。

        版本判定**先于**其它一切：白名单外的帧集不是「另一种写法」，而是本层不认识的对象，
        继续解析只会拿猜测值产记录。`cwd` 是否可信由 `DSH_HEADER_CWD_TRUSTED` 决定；本轮为
        `False`，因此头部值一律只作冲突证据，项目质量为 `unverified_header_cwd`。
        """
        inline_version = _version_text(_first_present(payload, _FRAME_VERSION_KEYS))
        if inline_version is None and isinstance(payload.get("version"), str):
            inline_version = ""
        if inline_version is None:
            self._stats.note(IssueCode.MISSING_HEADER_VERSION)
        elif inline_version not in DSH_SUPPORTED_VERSIONS:
            self._stats.note(IssueCode.UNSUPPORTED_HEADER_VERSION)
            self._unsupported_version = True
        inline_cwd = _as_text(_first_present(payload, _FRAME_CWD_KEYS), MAX_PROJECT_VALUE_CHARS)
        inline_session = _as_text(
            _first_present(payload, _FRAME_SESSION_ID_KEYS), MAX_SESSION_ID_CHARS
        )
        created_at = _as_text(payload.get("createdAt") or payload.get("created_at"), 64)
        trusted = bool(DSH_HEADER_CWD_TRUSTED and inline_cwd is not None)
        self._header = DshHeaderInfo(
            session_id=inline_session,
            cwd=inline_cwd,
            created_at=created_at,
            version=inline_version,
            line_no=self._line_no,
            seen=True,
            trusted=trusted,
        )
        if inline_session is not None:
            if (
                self._expected_session_id is not None
                and self._expected_session_id != inline_session
            ):
                self._session_id_conflict = True
                self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
            else:
                self._session_id = inline_session
        if inline_cwd is None or self._project_conflict:
            return
        if self._asserted_project is not None and self._asserted_project != inline_cwd:
            # 字面不一致即歧义：两个值都不采信，粘性记下冲突。
            self._project_conflict = True
            self._project = None
            self._project_quality = ProjectQuality.UNKNOWN
            self._stats.note(IssueCode.CONFLICTING_HEADER_CWD)
            return
        if trusted:
            self._project = inline_cwd
            self._project_quality = ProjectQuality.TRUSTED_HEADER_CWD
            return
        self._project = inline_cwd
        self._project_quality = ProjectQuality.UNVERIFIED_HEADER_CWD
        if self._asserted_project is None:
            self._stats.note(IssueCode.PROJECT_UNVERIFIED)

    def _handle_frame(
        self, outer: dict[str, Any], data: dict[str, Any]
    ) -> list[StandardRecord]:
        """一帧 → 至多一条正文记录；坐标 `(帧号, seq)`。"""
        session_id, verified, rejected = self._resolve_session_id(outer, data)
        if rejected:
            return []
        if session_id is None:
            self._stats.note(IssueCode.MISSING_SESSION_ID)
            return []
        if not verified:
            self._stats.note(IssueCode.SESSION_ID_UNVERIFIED)

        raw_role = _first_present(data, _ROLE_KEYS)
        role = _as_role(raw_role)
        if role is None:
            role = _as_role(_first_present(outer, _FRAME_TYPE_KEYS))
        if role is None:
            self._stats.note(
                IssueCode.UNKNOWN_ROLE if _is_oversized_text(raw_role) else IssueCode.MISSING_ROLE
            )
            return []
        if role not in TEXT_ROLES:
            self._stats.note(
                IssueCode.SKIPPED_ROLE if role in KNOWN_NON_TEXT_ROLES else IssueCode.UNKNOWN_ROLE
            )
            return []

        moment, time_quality = self._resolve_time(outer, data)
        issues: list[IssueCode] = []
        if time_quality is not TimeQuality.EXACT:
            code = TIMESTAMP_ISSUES[time_quality]
            self._stats.note(code)
            issues.append(code)

        blocks, lost_content, limit_issues = self._content_blocks(data)
        issues.extend(limit_issues)
        if blocks is None:
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            return []
        if not blocks:
            if not lost_content:
                self._stats.note(IssueCode.NO_TEXT_CONTENT)
            return []
        if self._project_quality is not ProjectQuality.TRUSTED_HEADER_CWD and self._project is not None:
            # 未取证的可信度开关（DSH_HEADER_CWD_TRUSTED）：本轮一律报「归属未核实」。
            issues.append(IssueCode.PROJECT_UNVERIFIED)

        ordinal, _from_seq = _frame_ordinal(outer)
        text = "\n".join(blocks)
        record = StandardRecord(
            source=self._source,
            session_id=session_id,
            location=SourceLocation(self._stream_label, self._line_no, ordinal),
            text=text,
            role=role,
            executor=None,
            timestamp=moment,
            time_quality=time_quality,
            project=self._project,
            project_quality=self._project_quality,
            issues=tuple(issues),
        )
        self._stats.records_emitted += 1
        self._stats.lines_with_records += 1
        return [record]

    def _resolve_session_id(
        self, outer: dict[str, Any], data: dict[str, Any]
    ) -> tuple[str | None, bool, bool]:
        """返回 `(可用于记录的会话标识, 是否已核实, 是否拒绝本行)`。

        三份证据：调用方断言、头部帧快照、本帧帧内字段。任意两份不一致即计
        `session_id_mismatch` 并拒行；只有一份时可用但不算已核实。
        """
        inline = self._inline_session_id(outer, data)
        if self._session_id_conflict:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        header_id = self._header.session_id if self._header.seen else None
        candidates = [
            value
            for value in (self._expected_session_id, header_id, inline)
            if value is not None
        ]
        if len(set(candidates)) > 1:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        if not candidates:
            return None, False, False
        return candidates[0], len(candidates) >= 2, False

    def _inline_session_id(
        self, outer: dict[str, Any], data: dict[str, Any]
    ) -> str | None:
        """帧内会话标识：先外层再 data；裸 `id` 只在外层取（data 层的 `id` 常为对象 ID）。"""
        value = _as_text(_first_present(outer, _FRAME_SESSION_ID_KEYS), MAX_SESSION_ID_CHARS)
        if value is not None:
            return value
        for key in ("sessionId", "session_id"):
            value = _as_text(data.get(key), MAX_SESSION_ID_CHARS)
            if value is not None:
                return value
        return None

    def _verified_session_id(self) -> str | None:
        expected = self._expected_session_id
        inline = self._header.session_id if self._header.seen else None
        if self._session_id_conflict:
            return None
        if expected is not None and inline is not None:
            return expected if expected == inline else None
        return None

    def _resolve_time(
        self, outer: dict[str, Any], data: dict[str, Any]
    ) -> tuple[datetime | None, TimeQuality]:
        """只取帧内显式时间字段；单位由值量级判（`normalize_timestamp`），不硬编码毫秒。

        不回落到头部时间、更不回落到文件 mtime（AC-SEARCH-01）；帧里没有可用时间即
        `missing_timestamp`，整流 partial。
        """
        for holder in (outer, data):
            for key in _FRAME_TIME_KEYS:
                if key not in holder:
                    continue
                value = holder[key]
                if value is None:
                    continue
                return normalize_timestamp(value)
        return None, TimeQuality.MISSING

    def _content_blocks(
        self, data: dict[str, Any]
    ) -> tuple[tuple[str, ...], bool, tuple[IssueCode, ...]]:
        """帧内正文提取：字符串 / 块数组 / 块对象三形态，套同一组双限。

        返回 `(块元组, 是否有内容因不可解释而未产出, 本行命中的上限原因码)`。
        """
        content = _first_present(data, _TEXT_KEYS)
        if content is None and not _has_field(data, _TEXT_KEYS):
            return (), False, ()
        line_issues: list[IssueCode] = []

        if isinstance(content, str):
            if not content.strip():
                return (), False, ()
            bounded, truncated = _bounded_text(content)
            if truncated:
                self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
            return (bounded,), False, tuple(line_issues)

        if isinstance(content, dict):
            candidates: list[Any] = [content]
            dropped = 0
        elif isinstance(content, (list, tuple)):
            candidates = list(content[:MAX_CONTENT_BLOCKS_PER_FRAME])
            dropped = len(content) - len(candidates)
        else:
            return (), True, ()

        lost = bool(dropped)
        if dropped:
            self._stats.note(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
            line_issues.append(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)

        out: list[str] = []
        for item in candidates:
            if isinstance(item, str):
                if not item.strip():
                    continue
                bounded, truncated = _bounded_text(item)
                if truncated:
                    self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                    line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
                out.append(bounded)
                continue
            if not isinstance(item, dict):
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
                lost = True
                continue
            raw_block_type = _first_present(item, _FRAME_TYPE_KEYS)
            block_type = _as_role(raw_block_type)
            if block_type is None and _is_oversized_text(raw_block_type):
                self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
                lost = True
                continue
            if block_type is not None and block_type not in TEXT_BLOCK_TYPES:
                if block_type in KNOWN_NON_TEXT_BLOCKS:
                    self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
                else:
                    self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
                    lost = True
                continue
            body = _first_present(item, _TEXT_KEYS)
            if isinstance(body, str):
                if not body.strip():
                    continue
                bounded, truncated = _bounded_text(body)
                if truncated:
                    self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                    line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
                out.append(bounded)
                continue
            missing_body = body is None and not _has_field(item, _TEXT_KEYS)
            issue = (
                IssueCode.INVALID_CONTENT_SHAPE
                if missing_body
                else IssueCode.NON_STRING_TEXT_BLOCK
            )
            self._stats.note(issue)
            lost = True
        return tuple(out), lost, tuple(line_issues)

    def _decode(self, line: str | bytes) -> str | None:
        """先按固定上限判行大小，再按 UTF-8 解码；超限/解码失败均不保留原值。"""
        if isinstance(line, str):
            if len(line) > MAX_LINE_CHARS:
                self._stats.note(IssueCode.LINE_TOO_LARGE)
                return None
            return line
        if isinstance(line, (bytes, bytearray)):
            raw = bytes(line)
            if len(raw) > MAX_DSH_LINE_BYTES:
                self._stats.note(IssueCode.LINE_TOO_LARGE)
                return None
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                self._stats.note(IssueCode.CORRUPT_LINE)
                return None
            if len(decoded) > MAX_LINE_CHARS:
                self._stats.note(IssueCode.LINE_TOO_LARGE)
                return None
            return decoded
        self._stats.note(IssueCode.CORRUPT_LINE)
        return None


# ---------------------------------------------------------------------------
# 发现（两轴分离，与 cursor 同一判据）
# ---------------------------------------------------------------------------


class DshDiscoveryStatus(StrEnum):
    """发现结论状态；失败态**不得合并**（每态对外措辞与后续动作不同）。"""

    #: 候选已定位（只表示找到文件，不表示正文可读、更不表示归属成立）。
    AVAILABLE = "available"
    #: 未配置该来源的存储根：功能未启用，不是「没有会话」。
    DISABLED = "disabled"
    #: 存储根缺失/不可解析/不可读：该面**不可判定**，不得称无匹配。
    UNAVAILABLE = "unavailable"
    #: 存储根可读但本面没有候选条目：**该面无匹配**（禁称「完整无匹配」）。
    NO_CANDIDATES = "no_candidates_on_facet"
    #: 条目存在但形态超出已核实范围：本层不认识，不猜其内容。
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class DshDiscoveryOutcome:
    """发现结论：状态 + 候选 `(session_id, 相对存储根路径)` + 固定文案 note。

    候选里的目录名（`<workspace-dir>`）**不参与**项目还原：共享存储与有损编码都可能让目录名
    与项目无关，归属只从记录内的 `cwd` 证据走归属轴。
    """

    status: DshDiscoveryStatus
    candidates: tuple[tuple[str, str], ...] = ()
    note: str | None = None


def _relative_form(root: str, path: str) -> str:
    """存储根下的相对路径（posix 分隔，只用于外发，不用于再解析）。"""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        rel = os.path.basename(path)
    return rel.replace(os.sep, "/").replace("\\", "/")


_SAFE_SESSION_ID = re.compile(r"^[A-Za-z0-9._-]{1,256}$")


def _iter_session_files(store_root: str) -> tuple[list[tuple[str, str]], bool, bool]:
    """在有界两层里收集 `session.v4.jsonl.zstd` 候选。

    返回 `(候选, 是否见到不可解释条目, 是否因 I/O 读不下去)`：三种结局对应三个状态，不得
    互相顶替——「读不下去」不是「没有」，「条目形态不认识」也不是「没有」。
    """
    found: list[tuple[str, str]] = []
    unexplainable = False
    unreadable = False
    try:
        first = list(os.scandir(store_root))
    except OSError:
        return [], False, True
    for workspace in first:
        try:
            if not workspace.is_dir(follow_symlinks=False):
                continue
        except OSError:
            unreadable = True
            continue
        candidate = os.path.join(workspace.path, DSH_SESSION_FILE_NAME)
        if os.path.isfile(candidate):
            session_id = os.path.basename(workspace.path)
            if _SAFE_SESSION_ID.match(session_id):
                found.append((session_id, candidate))
            else:
                unexplainable = True
            continue
        # 再下一层：`<workspace>/<session-id>/session.v4.jsonl.zstd`（深度固定为 2）。
        try:
            second = list(os.scandir(workspace.path))
        except OSError:
            unreadable = True
            continue
        for entry in second:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                unreadable = True
                continue
            nested = os.path.join(entry.path, DSH_SESSION_FILE_NAME)
            if not os.path.isfile(nested):
                continue
            if _SAFE_SESSION_ID.match(entry.name):
                found.append((entry.name, nested))
            else:
                unexplainable = True
    return found, unexplainable, unreadable


def discover_dsh_sessions(
    policy: SessionPolicy,
    scope: object,
    *,
    store_root_path: object,
    attribution_project: object = None,
) -> DshDiscoveryOutcome:
    """在**已批准的存储根**内列举压缩会话候选（不读任何正文、不解压）。

    两轴严格分离：读取轴只认 `authorize_store(..., kind=DIRECTORY)`（拒绝原样抛
    `PolicyDenied`，不捕、不转译、不回退到项目树）；归属轴只做可选收窄，不参与读取判定。
    目录名不参与项目还原（见 `DshDiscoveryOutcome`）。
    """
    if not isinstance(store_root_path, str) or not store_root_path.strip():
        return DshDiscoveryOutcome(
            status=DshDiscoveryStatus.DISABLED, note="该来源的会话存储根未配置"
        )
    policy.authorize_store(
        scope, SOURCE_DSH, store_root_path, kind=TargetKind.DIRECTORY
    )
    if isinstance(attribution_project, str) and attribution_project.strip():
        try:
            policy.authorize_attribution(scope, store_root_path, project=attribution_project)
        except PolicyDenied:
            return DshDiscoveryOutcome(
                status=DshDiscoveryStatus.NO_CANDIDATES, note="该面无匹配"
            )
    if not os.path.isdir(store_root_path):
        return DshDiscoveryOutcome(
            status=DshDiscoveryStatus.UNAVAILABLE, note="存储根不可解析或不是目录"
        )
    found, unexplainable, unreadable = _iter_session_files(store_root_path)
    if unreadable and not found:
        return DshDiscoveryOutcome(status=DshDiscoveryStatus.UNAVAILABLE, note="存储根不可读")
    if unexplainable and not found:
        return DshDiscoveryOutcome(
            status=DshDiscoveryStatus.UNSUPPORTED, note="条目形态不可解释"
        )
    if not found:
        return DshDiscoveryOutcome(status=DshDiscoveryStatus.NO_CANDIDATES, note="该面无匹配")
    return DshDiscoveryOutcome(
        status=DshDiscoveryStatus.AVAILABLE,
        candidates=tuple(
            (session_id, _relative_form(store_root_path, path)) for session_id, path in found
        ),
        note=None,
    )


# ---------------------------------------------------------------------------
# 有界执行器（`line_search.LineSourceSpec.file_runner` 的 dsh 注入实现）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DshFileOutcome:
    """一帧文件的终态：与 `PiFileOutcome` 同一组必需字段 + 解压侧账目。

    `read_refusal` 只在**打开前**被策略/读取层拒绝时给出（固定码字符串）：聚合层把它折成
    `refused` 行，而不是让一次拒绝把整批降级成失败。`stream_stop` 是解压侧终态（含触限），
    `decoder_mode` 只说明用哪条解码路径，不参与任何结论判定。
    """

    complete: bool
    publication_allowed: bool
    reason: Any
    read: ReadOutcome
    pipeline: Any
    attribution_refusal: RefusalCode | None = None
    version: FileVersion | None = None
    read_refusal: str | None = None
    stream_error: DshStreamStop | None = None
    stream_stop: DshStreamStop | None = None
    decoder_mode: DshDecoderMode | None = None
    frames: int | None = None
    decompressed_bytes: int = 0
    unsupported_version: bool = False

    def as_public_dict(self) -> dict[str, object]:
        """固定键快照：整数/布尔/枚举字面量，无任何不受控原值（`version` 故意不进快照）。"""
        payload: dict[str, object] = {
            "complete": self.complete,
            "publication_allowed": self.publication_allowed,
            "reason": self.reason.value if self.reason is not None else None,
            "read": self.read.as_public_dict(),
            "pipeline": self.pipeline.as_public_dict(),
            "attribution_refusal": (
                self.attribution_refusal.value if self.attribution_refusal is not None else None
            ),
            "dsh": {
                "decoder_mode": (
                    self.decoder_mode.value if self.decoder_mode is not None else None
                ),
                "frames": self.frames,
                "decompressed_bytes": self.decompressed_bytes,
                "stream_stop": (
                    self.stream_stop.value if self.stream_stop is not None else None
                ),
                "unsupported_version": self.unsupported_version,
            },
        }
        if self.read_refusal is not None:
            payload["read_refusal"] = self.read_refusal
        if self.stream_error is not None:
            payload["stream_error"] = self.stream_error.value
        return payload


def _refusal_code_text(denial: BaseException) -> str:
    """拒绝对象 → 固定码字符串（不保留异常本身，不拼路径与系统原文）。"""
    code = getattr(denial, "code", None)
    value = getattr(code, "value", None)
    return value if isinstance(value, str) else "read_refused"


def run_dsh_frame_file(
    policy: SessionPolicy,
    scope: str,
    path: str,
    session_id: str,
    *,
    source: str = SOURCE_DSH,
    parser_factory: Callable[..., Any] | None = None,
    runtime: DshDecoderRuntime | None = None,
    cwd: str | None = None,
    project_filter: str | None = None,
    max_line_bytes: int = MAX_DSH_LINE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_lines: int = MAX_LINES_PER_STREAM,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
    should_stop: Callable[[], object] | None = None,
    _candidate_capture: Callable[[StandardRecord], object] | None = None,
    _project_grants: dict[int, str] | None = None,
) -> DshFileOutcome:
    """一个压缩会话文件的有界执行：授权 → 读压缩字节 → 解压成行流 → 解析 → 暂存核对 → 终态。

    与 `run_line_source_file` 同一条管线（`PiSessionPipeline._execute` + 同一 `admit` 判据），
    只把「`authorize_read` 的行通道」换成「`authorize_raw_bytes` + `DshFrameReader`」：行通道
    会对 zstd 帧魔数直接拒读（`not_plain_text`），因此压缩来源不能走它，这是本模块唯一的
    结构性差异，不新增任何核对项或拒绝码。

    `parser_factory` 缺省为 `DshLineParser`；传入的工厂必须按 `stream_label`/`session_id`/
    `project`/`source` 构造，且产出记录的 `record.source` 必须恰等于 `source`——不一致由暂存
    层按 `source_conflict` 整批丢弃。

    出口只有一类：`DshFileOutcome`，三种失败形态各归其位——打开前被拒折进 `read_refusal`
    （聚合层 `refused` 行）；解压在产出任何行**之前**失败折进 `stream_error`（聚合层 `error`
    行，绝不降为无匹配）；已产出行之后失败只记 `FRAME_TRUNCATED` + 终态不完整。
    """
    if source != SOURCE_DSH:
        raise ValueError("run_dsh_frame_file only runs the 'dsh' source")
    active_runtime = runtime if isinstance(runtime, DshDecoderRuntime) else DshDecoderRuntime.probe()

    policy.authorize_query(scope, sources=(source,), project=project_filter)

    def admit(record: StandardRecord) -> object:
        """逐记录归属准入：与 pi 内核同一判据，只把可信头部 cwd 的记录递交策略层。"""
        if record.project_quality is not ProjectQuality.TRUSTED_HEADER_CWD:
            return RefusalCode.ATTRIBUTION_UNKNOWN
        try:
            grant = policy.authorize_attribution(scope, record.project, project=project_filter)
        except PolicyDenied as denial:
            return denial.code
        if _project_grants is not None:
            _project_grants[id(record)] = grant.project
        return None

    try:
        payload: RawBytesResult = authorize_raw_bytes(
            policy, scope, source, path, max_total_bytes=max_total_bytes
        )
    except (PolicyDenied, SafeReadDenied) as denial:
        return DshFileOutcome(
            complete=False,
            publication_allowed=False,
            reason=None,
            read=ReadOutcome(
                complete=False,
                reason=ReadStop.CLOSED_BEFORE_EOF,
                lines_read=0,
                consumed_bytes=0,
                truncated_lines=0,
                bytes_discarded=0,
                eof_reached=False,
            ),
            pipeline=_EmptyPipeline(),
            read_refusal=_refusal_code_text(denial),
            decoder_mode=active_runtime.mode,
        )

    reader = DshFrameReader(payload.data, active_runtime, max_line_bytes=max_line_bytes)
    parser: DshLineParser = (DshLineParser if parser_factory is None else parser_factory)(
        stream_label=None, session_id=session_id, project=cwd, source=source
    )
    traced = _TracedLines(reader.iter_lines(), parser)

    def eof_confirmed() -> bool:
        """只有「解压走到真 EOF 且压缩侧读满」才算读完，两者任一不成立即不完整。"""
        return bool(reader.clean_eof and payload.version.complete and not parser.unsupported_version)

    try:
        pipeline = PiSessionPipeline(
            session_id=session_id,
            project=cwd,
            max_candidates=max_candidates,
            max_bytes=max_bytes,
            source=source,
            parser_factory=_bind_parser(parser),
        )
        outcome = pipeline._execute(
            traced,
            should_stop=should_stop,
            eof_confirmed=eof_confirmed,
            admit=admit,
            capture=_candidate_capture,
        )
    finally:
        # 管线提前停手（触限/取消/异常）时解析器可能还没收束：这里补一次，让
        # `NO_SESSION_HEADER`/`UNKNOWN_PROJECT` 与 `partial` 账目在任何出口都成立。
        parser.finish()

    if traced.failure is None and not reader.clean_eof:
        # 行流被调用方提前中断（准入短路/触限/取消）：读者还没走到真实终点，单看
        # `stop_reason=None` 无法说明流是**怎么**结束的。这里做一次有界探针把终态落定，
        # 对外的 `stream_stop`/`read.reason`/`eof_reached` 才有依据。行内容只被解压并丢弃：
        # 不解析、不产记录、不入任何账目，帧数/解压量/超时上限同样约束这一趟。
        traced.drain()

    if traced.failure is not None and traced.yielded == 0:
        # 产出任何行之前解压就坏掉：文件级错误，零候选、零归属映射，聚合层按 `error` 行处理。
        return DshFileOutcome(
            complete=False,
            publication_allowed=False,
            reason=None,
            read=ReadOutcome(
                complete=False,
                reason=ReadStop.CLOSED_BEFORE_EOF,
                lines_read=0,
                consumed_bytes=len(payload.data),
                truncated_lines=reader.oversized_lines,
                bytes_discarded=max(len(payload.data) - reader.consumed_prefix_bytes, 0),
                eof_reached=False,
            ),
            pipeline=outcome,
            attribution_refusal=pipeline._admission_refusal,
            read_refusal=None,
            stream_error=traced.failure,
            stream_stop=reader.stop_reason,
            decoder_mode=active_runtime.mode,
            frames=reader.frames,
            decompressed_bytes=reader.decompressed_bytes,
            unsupported_version=parser.unsupported_version,
        )

    parse = outcome.parse
    incomplete_stream = not reader.clean_eof
    if incomplete_stream and reader.stop_reason is not DshStreamStop.DECOMPRESSED_LIMIT:
        # 已产出行之后中断：整流不完整，原因由 FRAME_TRUNCATED 承担。
        parser.stats.note(IssueCode.FRAME_TRUNCATED)
    elif reader.stop_reason is DshStreamStop.DECOMPRESSED_LIMIT:
        parser.stats.note(IssueCode.FRAME_TRUNCATED)

    read_reason: ReadStop
    if reader.stop_reason is DshStreamStop.DECOMPRESSED_LIMIT:
        read_reason = ReadStop.TOTAL_BYTES_LIMIT
    elif reader.stop_reason is DshStreamStop.FRAME_LIMIT:
        read_reason = ReadStop.LINE_LIMIT
    elif reader.clean_eof and payload.version.complete:
        read_reason = ReadStop.EXHAUSTED
    else:
        read_reason = ReadStop.CLOSED_BEFORE_EOF

    read = ReadOutcome(
        complete=bool(reader.clean_eof and payload.version.complete and not parser.stats.partial),
        reason=read_reason,
        lines_read=outcome.parse.get("lines_seen", 0) if isinstance(parse, dict) else 0,
        consumed_bytes=len(payload.data),
        truncated_lines=reader.oversized_lines,
        bytes_discarded=max(len(payload.data) - reader.consumed_prefix_bytes, 0),
        eof_reached=bool(reader.clean_eof and payload.version.complete),
    )
    return DshFileOutcome(
        complete=bool(
            outcome.complete
            and read.complete
            and reader.clean_eof
            and payload.version.complete
            and not parser.unsupported_version
        ),
        publication_allowed=outcome.publication_allowed,
        reason=outcome.reason,
        read=read,
        pipeline=outcome,
        attribution_refusal=pipeline._admission_refusal,
        version=payload.version if payload.version.complete else None,
        stream_stop=reader.stop_reason,
        decoder_mode=active_runtime.mode,
        frames=reader.frames,
        decompressed_bytes=reader.decompressed_bytes,
        unsupported_version=parser.unsupported_version,
    )


class _EmptyPipeline:
    """打开前被拒时的管线替身：零记录、零解析账目，形态与 `PipelineOutcome` 一致。"""

    __slots__ = ()

    complete = False
    publication_allowed = False
    reason = None
    stream_exhausted = False
    records_seen = 0
    parse: dict[str, Any] = {"lines_seen": 0, "lines_with_records": 0, "records_emitted": 0,
                             "skipped_count": 0, "partial": True, "issue_counts": {}}

    def as_public_dict(self) -> dict[str, object]:
        return {
            "complete": self.complete,
            "publication_allowed": self.publication_allowed,
            "reason": None,
            "stream_exhausted": self.stream_exhausted,
            "records_seen": self.records_seen,
            "stage": {"complete": False, "publication_allowed": False, "reason": None,
                      "candidate_count": 0, "staged_bytes": 0, "dropped_count": 0},
            "parse": dict(self.parse),
        }


def _bind_parser(parser: DshLineParser) -> Callable[..., DshLineParser]:
    """把一个**已构造**的解析器绑定成工厂：管线构造时会调用它，返回同一实例。

    为什么需要：解压侧的行流与解析器共享一个对象，`eof_confirmed` / 终态判定要读同一个
    `parser` 的状态（`unsupported_version`、`stats`）。若让管线自造解析器，这些信号就会落在
    一个没人看的对象上，`partial` 与整文件不支持的判定都会失去依据。工厂仍按同一组关键字
    调用，只是拒绝在别处再构造第二个实例。
    """

    def factory(**kwargs: Any) -> DshLineParser:
        expected = {
            "stream_label": parser._stream_label,
            "session_id": parser._expected_session_id,
            "project": parser._asserted_project,
            "source": SOURCE_DSH,
        }
        for key, value in expected.items():
            if key in kwargs and kwargs[key] != value:
                raise ValueError(
                    "dsh parser is pre-bound; the pipeline must reuse the same instance"
                )
        return parser

    return factory


class _TracedLines:
    """行流包装：把解压侧的失败截住并记账，不让它被管线的通用异常吞掉。

    管线循环对 `next()` 逃出的普通异常一律降为「没读到结尾」，异常对象不留痕。压缩来源
    需要的正是这条区分：产出任何行**之前**失败是文件级错误（`error`），产出行**之后**失败
    只是整流不完整（`FRAME_TRUNCATED` + `partial`）。因此这里在异常越过行流边界之前把它
    收进 `failure`，并停止产出；调用方读这个字段，而不是接异常。

    同时记录已产出的行数 `yielded`：`failure` 是否发生在「第一行之前」只能由此判定。
    行序与解析器行号不同步（上游提前停手）同样按不完整收口：不产坐标错位的记录。
    """

    __slots__ = ("_iterator", "_parser", "failure", "yielded")

    def __init__(self, iterator: Iterator[tuple[int, bytes]], parser: DshLineParser) -> None:
        self._iterator = iterator
        self._parser = parser
        self.failure: DshStreamStop | None = None
        self.yielded = 0

    def __iter__(self) -> Iterator[bytes]:
        return self._lines()

    def _lines(self) -> Iterator[bytes]:
        try:
            for index, line in self._iterator:
                if index != self._parser._line_no + 1 and index > 1:
                    # 行序与解析器的行号不同步说明上游出错：停在这里，不产坐标错位的记录。
                    self._parser.stats.note(IssueCode.FRAME_TRUNCATED)
                    return
                self.yielded += 1
                yield line
        except DshStreamError as failure:
            self.failure = failure.category
            return

    def drain(self) -> None:
        """有界探针：推进行流直到终态落定或本探针出错，行内容丢弃不解析。

        调用方提前停手时，读取器尚未走到流的真实终点；不推进就只能给出
        `stream_stop=None`，而那不足以说明流是**怎么**结束的。字节只被解压并丢弃：
        不解析、不产记录、不入任何账目或对外字段，读取上限（帧数/解压字节/超时）
        同样约束这一趟。拿到第一个终态即停——此后 `stop_reason` 不会再变。"""
        try:
            for _ in self._iterator:
                pass
        except DshStreamError as failure:
            self.failure = failure.category
            return
