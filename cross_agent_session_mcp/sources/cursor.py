"""Cursor Agent CLI 会话 JSONL 逐行解析适配器（DES-ADAPTER-01「cursor_agent_cli」行）。

服务的需求条目：SRS-SEARCH-01、SRS-SEARCH-05、SRS-SEARCH-06、SRS-SEARCH-09；
`location` 与时间约定见 DES-DATA-01、DES-API-01。

本适配器**只覆盖 Agent CLI（agent-transcripts）分支**。Cursor 桌面 GUI 的
`~/.cursor/chats/**/meta.json` + `state.vscdb` 存储本轮零代码：不解析、不开库，由服务层
直接声明 `unsupported` + 固定 reason（DES-INC-03）。理由不是「不想做」，而是**正文格式未
核实**——按本包的纪律，未核实的字节不得声称已覆盖。

输入边界（与 `sources/pi.py` 同一条纪律，逐字不复用其结论）：

- 只解析**调用者提供的行流**（`Iterable[str | bytes]`，每元素一行）。整个 `str`/`bytes`
  直接 `TypeError`。不发现目录、不打开文件、不做路径授权；授权由 `policy.py` /
  `safe_reader.py` 在调用方侧完成（`discover_cursor_transcripts` 只做**发现**，且只接受
  调用方给定的已批准存储根）。
- 资源上限继承 codex/claude 同值（DES-INC-01）：`MAX_LINE_BYTES` / `MAX_LINE_CHARS` /
  `MAX_CONTENT_BLOCKS_PER_LINE` / `MAX_TEXT_BLOCK_CHARS` / `MAX_LINES_PER_STREAM`。超限行为
  照旧：该行或该流停止，只记固定 `IssueCode`，不保存被丢弃的输入值。
- 来源固定 `cursor_agent_cli`：构造参数 `source` 只接受空值或该 ID，其它非空值 `ValueError`。

与 pi 判据**不同的三处**（其余分支逐字复刻 pi，不另造语义）：

1. **归属只走保守轴**（P2-4）。行内 `cwd`/`workingDirectory` 在本轮**一律不确立可信归属**：
   已发布记录的项目质量恒为 `UNVERIFIED_HEADER_CWD`（无行内 cwd 时为 `UNKNOWN`），并把
   `PROJECT_UNVERIFIED` 逐条当场计数。原因不是「字段不存在」，而是**行内 cwd 的写入方与
   语义未取证**，不足以支撑「这条正文来自这个项目」——`CursorHeaderInfo.trusted` 首版恒
   `False` 就是这条判据的载体。归属最终由 `policy.authorize_attribution` 逐记录判定，
   本层只交证据、不裁决。
2. **正文以标签为发布边界**。CLI 把 `<timestamp>` / `<user_query>` 包在 user 消息正文里。
   本轮**只发布**：`<user_query>` 标签内的正文（剥掉标签）与 `<timestamp>` 标签内的时刻，
   以及已核实的纯文本形态（`content` 为裸字符串或 `text` 块）。标签外的其它角色文本在实测
   前**不发布**，按 `NO_TEXT_CONTENT`（已理解的无正文）或 `UNKNOWN_BLOCK_TYPE`（未核实的
   块形态，`partial`）记账——不把没读懂的模板文本当正文，也不把没读懂的正文当垃圾丢掉。
3. **子代理门先于角色门**（P2-4）。`_SUBAGENT_KEYS` 任一命中且值为真布尔或非空字符串 →
   该行进 `sidechain_skipped_lines` 计数、**不产记录**、不宣称独立会话。这与 claude 的派生行
   门同型：派生证据不否定整流归属，只是不能混进主会话正文。值为**不可解释形态**（超长串、
   数字、容器）时按 `UNKNOWN_EVENT` 降级——担心子代理正文逃逸成主会话内容，不得把无法核实
   的派生标记当成「没有派生」。

发现（DES-ARCH-04 两轴分离）：

- **读取轴**：`discover_cursor_transcripts` 只接受调用方给的 `store_root_path`，并先过
  `policy.authorize_store(scope, SOURCE_CURSOR, store_root_path, kind=TargetKind.DIRECTORY)`；
  未批即原样抛 `PolicyDenied`（对外映射 `storage_denied`），**绝不回退项目目录树，绝不做
  任何全盘扫描**。
- **归属轴**：`attribution_project` 只用于判定候选归属，**不授予任何读取能力**；批准归属根
  不会让项目树变成可读对象。归属轴未命中只影响候选是否被收窄，不影响读取轴结论。
- 四态严格不合并：存储根未配置 → `DISABLED`；根存在但 `<工作区编码>/agent-transcripts/`
  缺失 → `NO_CANDIDATES`（对外措辞「该面无匹配」，禁称「完整无匹配」）；目录存在但条目形态
  不可解释 → `UNSUPPORTED`；根缺失/无权 → `UNAVAILABLE`（或 `PolicyDenied`）。
- 候选返回 `(session_id, 相对存储根路径)` 二元组：绝对路径不外发，调用方要重建成绝对路径
  必须回到自己已批准的根上拼接，不能拿本层的返回值当授权凭据。

诚实边界（未核对项）：

- `<工作区编码>` 目录名 → 项目名的还原规则**未取证**，本层**不**从目录名反推项目（宁可不
  归类，也不错归类）。
- 会话头部形态未取证：`CursorHeaderInfo.seen` 只表示「读到过一条带行内归属字段的记录」，
  `trusted` 恒 `False`，因此 `NO_SESSION_HEADER` 不参与本来源的判定，整流 `partial` 由
  `PROJECT_UNVERIFIED` 承担（这是**有意的保守偏差**：健康会话也会报不完整）。
- 真实 CLI 存储的字段全集未核对（本轮禁止读取 `~/.cursor`）。行流解析与发布链由
  `tests/test_cursor_source.py` 驱动合成夹具验证，不代表真实存储兼容性。
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Iterator, Sequence
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

__all__ = [
    "CURSOR_GUI_REASON",
    "KNOWN_NON_TEXT_BLOCKS",
    "KNOWN_NON_TEXT_ROLES",
    "MAX_CONTENT_BLOCKS_PER_LINE",
    "MAX_HEADER_VERSION_CHARS",
    "MAX_LINE_BYTES",
    "MAX_LINE_CHARS",
    "MAX_LINES_PER_STREAM",
    "MAX_MATCH_KEY_CHARS",
    "MAX_PROJECT_VALUE_CHARS",
    "MAX_SESSION_ID_CHARS",
    "MAX_TEXT_BLOCK_CHARS",
    "CursorAgentTranscriptLineParser",
    "CursorDiscoveryOutcome",
    "CursorDiscoveryStatus",
    "CursorHeaderInfo",
    "SOURCE_CURSOR",
    "TRANSCRIPT_DIR_MARKER",
    "discover_cursor_transcripts",
]

#: 标准记录里的来源标识，与 `policy.KNOWN_SOURCES` / `server.REQUIRED_SOURCES` 一致。
SOURCE_CURSOR = "cursor_agent_cli"

#: 用户级存储根下的项目面标记（`~/.cursor/projects/<工作区编码>/agent-transcripts/`）。
STORE_ROOT_MARKER = "projects"
#: 会话正文所在目录名；只有该目录下的条目才被当作候选。
TRANSCRIPT_DIR_MARKER = "agent-transcripts"
#: GUI 分支的固定 reason（DES-INC-03）：只说未核实，不编造原因。
CURSOR_GUI_REASON = "正文格式未核实"

# ---------- 不可信输入的固定资源上限（与 pi/codex/claude 同值，DES-INC-01） ----------

MAX_LINE_BYTES = 1_048_576
MAX_LINE_CHARS = 262_144
MAX_CONTENT_BLOCKS_PER_LINE = 32
MAX_TEXT_BLOCK_CHARS = 32_768
MAX_LINES_PER_STREAM = 200_000
MAX_PROJECT_VALUE_CHARS = 512
MAX_SESSION_ID_CHARS = 256
MAX_MATCH_KEY_CHARS = 64
#: 头部版本字段长度上限：超限即判不可识别（不截断比较：前缀可能命中另一个合法版本号）。
MAX_HEADER_VERSION_CHARS = 32

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

# ---------- CLI 正文标签（本来源唯一的发布边界） ----------

_TIMESTAMP_TAG = re.compile(r"<timestamp>(.*?)</timestamp>", re.S)
_USER_QUERY_TAG = re.compile(r"<user_query>(.*?)</user_query>", re.S)
#: 标签内正文的字符上限：与单块上限同值，防止把整段模板当成一条正文。
_MAX_TAGGED_CHARS = MAX_TEXT_BLOCK_CHARS

# ---------- 候选键（按优先级；命名差异容错，但不猜语义） ----------

_ROLE_KEYS: tuple[str, ...] = ("role",)
_TYPE_KEYS: tuple[str, ...] = ("type",)
_CWD_KEYS: tuple[str, ...] = ("cwd", "workingDirectory", "working_directory")
_SESSION_ID_KEYS: tuple[str, ...] = ("sessionId", "session_id", "id")
_MESSAGE_SESSION_ID_KEYS: tuple[str, ...] = ("sessionId", "session_id")
_VERSION_KEYS: tuple[str, ...] = ("version", "v")
_TIMESTAMP_KEYS: tuple[str, ...] = ("timestamp", "createdAt", "created_at", "time")
_TEXT_KEYS: tuple[str, ...] = ("text", "content", "message")
#: 子代理/派生行标记（P2-4）：任一命中即整行跳过，不产正文、不宣称独立会话。
_SUBAGENT_KEYS: tuple[str, ...] = (
    "isSidechain",
    "is_sidechain",
    "parentToolUseId",
    "parent_tool_use_id",
    "subagent",
)
#: `id` 只当头部事件的会话标识候选：消息行的 `id` 常是单条消息 ID，拿它比对归属会误判串台。
_HEADER_ONLY_KEYS: frozenset[str] = frozenset({"id"})

#: 行内 `type` 的这些取值只携带元信息、不是正文事件（已理解，不使扫描降级）。
_NON_TEXT_EVENT_TYPES: frozenset[str] = frozenset(
    {"queue-operation", "last-prompt", "summary", "title", "system"}
)

_FIELD_NOT_PRESENT = object()


def _first_present(mapping: dict[str, Any], keys: Sequence[str]) -> Any:
    """返回第一个存在且非 None 的键值；都不存在或都为 None 时返回 None。"""
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return None


def _has_field(mapping: dict[str, Any], keys: Sequence[str]) -> bool:
    """任一候选键是否存在（含值为 None）；用于区分「字段缺失」与「字段无效」。"""
    return any(key in mapping for key in keys)


def _as_text(value: Any, max_chars: int | None = None) -> str | None:
    """规范为非空字符串（保留原大小写）；非字符串、空白或**超长**返回 None。

    超长判不可用而**不截断**：截断后的标识/项目名是个不存在的值，拿它比对归属比「不知道」
    更糟。
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
    """值是非空白字符串但超出 `MAX_MATCH_KEY_CHARS`（因此已归为 None）。

    用于区分「字段缺失」与「字段存在但不可能属于固定集合」：超长不能当缺失，否则带垃圾
    `type`/`role` 的行会走进更宽松的识别分支。
    """
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


def _subagent_claim(payload: dict[str, Any]) -> bool | None:
    """派生/子代理标记的取值判定：`True`=按派生跳过，`None`=没有声明，`False`=声明不可解释。

    只接受两类**可解释**的声明：布尔 `True`/`False`，以及父引用键（`parentToolUseId` /
    `parent_tool_use_id`）的非空字符串值。`False` 与缺席同类（主流行）。数字、容器、空白串、
    超 `MAX_MATCH_KEY_CHARS` 的串都返回 `False` 标记的「不可解释」——调用方据此降级，**不**
    把它们当成「没有父引用」。

    返回值语义刻意做成三态而不是布尔：`None`（无声明）与 `False`（不可解释）在调用侧走不同
    的计数分支，前者不计数，后者计 `UNKNOWN_EVENT` 使整流 `partial`。
    """
    explained_absent = True
    for key in _SUBAGENT_KEYS:
        if key not in payload:
            continue
        value = payload[key]
        if isinstance(value, bool):
            if value:
                return True
            continue
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                # 空白父引用等于没给出：与 null/缺席同类，不得据此把主流行判成派生行。
                continue
            if len(stripped) > MAX_MATCH_KEY_CHARS * 4:
                # 超长父引用：不可采信，但「不可采信的派生声明」仍按派生跳过（保守方向是
                # 少发布，不是多发布）。
                return True
            explained_absent = False
            return True
        # 数字/容器/显式 null 之外的异形值：声明存在但不可解释。
        explained_absent = False
        if value is None:
            continue
        return False
    return None if explained_absent else False


@dataclass(frozen=True)
class CursorHeaderInfo:
    """已读到的行内归属证据快照；**首版 `trusted` 恒为 `False`**。

    `seen` 只表示读到过一条带行内归属字段的记录，不表示该记录是「会话头部」——CLI 的头部
    形态未取证，本层不猜。`trusted` 恒 `False` 是 P2-4 判据的载体：行内 `cwd` 的写入方与
    语义未核实，因此**任何**行内值都不得充当可信归属，后续记录的项目质量也只能是
    `UNVERIFIED_HEADER_CWD` / `UNKNOWN`。
    """

    session_id: str | None = None
    cwd: str | None = None
    version: str | None = None
    line_no: int | None = None
    seen: bool = False
    trusted: bool = False


class CursorAgentTranscriptLineParser:
    """逐行解析 Cursor Agent CLI 的 transcript JSONL，产出 `StandardRecord`。

    接口形态与 `PiLineParser` 一致（`feed` / `feed_line` / `finish` + `stats` / `header` /
    `session_id` / `project` / `asserted_project` / `project_conflict` / `project_quality`），
    因此可直接作为 `line_search.LineSourceSpec.parser_factory` 的构造目标；额外暴露
    `sidechain_skipped_lines`（与 claude L497 同语义：**按不可采信派生标记跳过的行数**，
    不声称已核实为真实子代理）。

    行号是**行流中的 1 起始序号**（含损坏行与空行，不含行数上限后的行），保证定位连续可
    追踪；若上游是压缩流，它是解压后的事件序号，不伪装成原始文件字节偏移。

    计数器只累加**固定类别**（`IssueCode`）与整数，不含正文、路径、事件类型名、角色名，
    因此可安全用于日志与对外覆盖信息。
    """

    def __init__(
        self,
        *,
        stream_label: str | None = None,
        session_id: str | None = None,
        project: str | None = None,
        source: str = SOURCE_CURSOR,
    ) -> None:
        """`session_id` 为会话归属校验断言，`project` 为上层给定的 **cwd 断言**。

        两者本层都**不验证**：适配器不检查其与实际文件内容的关系，也不声明已获授权。
        `project` 传的是工作目录（与行内 `cwd` 同类值），**不是策略里的项目名**——项目名到
        归属根的映射属 `policy.py` 与协调层，本层拿到项目名只会让冲突判定比较两种语义不同的值。
        它是一条**独立于行内证据的断言通道**：不写回 `header`，也不充当行内 `cwd` 的替身。

        两个入参都是有界处理对象：`project` 超 `MAX_PROJECT_VALUE_CHARS`、`session_id` 超
        `MAX_SESSION_ID_CHARS` 均按未提供处理（不截断使用）；`stream_label` 走
        `sanitize_stream_label`。`source` 不开放：记录来源固定 `cursor_agent_cli`。
        """
        self._stream_label = sanitize_stream_label(stream_label)
        self._asserted_project = _as_text(project, MAX_PROJECT_VALUE_CHARS)
        self._expected_session_id = _as_text(session_id, MAX_SESSION_ID_CHARS)
        normalized_source = _as_text(source, MAX_MATCH_KEY_CHARS)
        if normalized_source is not None and normalized_source != SOURCE_CURSOR:
            raise ValueError(
                "CursorAgentTranscriptLineParser records always carry the fixed source "
                "'cursor_agent_cli'"
            )
        self._source = SOURCE_CURSOR
        self._stats = ParseStats()
        self._header = CursorHeaderInfo()
        self._line_no = 0
        self._project = self._asserted_project
        self._project_quality = (
            ProjectQuality.CALLER_ASSERTED if self._asserted_project else ProjectQuality.UNKNOWN
        )
        # 行内 cwd 与外部断言字面不一致：归属不唯一，粘住到流结束（不回抢）。
        self._project_conflict = False
        # 行内标识与断言一旦冲突，整流归属存疑，后续记录不再采信。
        self._session_id_conflict = False
        self._line_limit_exceeded = False
        self._finished = False
        self._sidechain_skipped_lines = 0

    # ---------- 对外状态 ----------

    @property
    def stats(self) -> ParseStats:
        """本次解析的类别计数（不含原文、路径与数据侧字符串）。"""
        return self._stats

    @property
    def header(self) -> CursorHeaderInfo:
        """已读到的行内归属证据；`trusted` 首版恒 `False`（P2-4）。"""
        return self._header

    @property
    def session_id(self) -> str | None:
        """已核实的会话标识（两个独立来源一致）；否则 `None`。"""
        return self._verified_session_id()

    @property
    def project(self) -> str | None:
        """可归类的项目值：本来源恒不采信行内 `cwd`，因此只有外部断言值（或冲突/无为 `None`）。"""
        return self._project

    @property
    def asserted_project(self) -> str | None:
        """外部断言通道原值（仅长度判限后的形式）：不被行内证据覆写或抹除。"""
        return self._asserted_project

    @property
    def project_conflict(self) -> bool:
        """行内 `cwd` 与外部断言是否已字面冲突；粘性为真。"""
        return self._project_conflict

    @property
    def project_quality(self) -> ProjectQuality:
        """项目归属质量；任何取值都不表示已获授权，只表示值的来源。"""
        return self._project_quality

    @property
    def sidechain_skipped_lines(self) -> int:
        """按**不可采信**派生标记跳过的行数；不声称已核实为真实子代理。"""
        return self._sidechain_skipped_lines

    def finish(self) -> None:
        """收尾：登记与单行无关的流级问题（项目无法确定）；幂等。

        与 pi 不同，本来源**不**计 `no_session_header`：头部形态未取证，缺席不构成「缺头部」
        这一具体判断。整流 `partial` 由逐条 `PROJECT_UNVERIFIED` 承担（P2-4：行内归属形态
        未核实 ⇒ 永不声称归属完整）。
        """
        if self._finished:
            return
        self._finished = True
        if not self._project_quality.sourced:
            # 无断言、断言被冲突抹掉、或只有不可采信的行内值：项目无法确定都须交代。
            self._stats.note(IssueCode.UNKNOWN_PROJECT)

    # ---------- 行入口 ----------

    def feed(self, lines: Iterable[str | bytes]) -> Iterator[StandardRecord]:
        """按序消费行流，惰性产出记录；整个 `str`/`bytes` 直接 `TypeError`。

        无论正常结束还是提前关闭，`finally` 都会 `finish()`，避免调用方漏掉流级问题；行数
        上限达到后不再从调用方迭代器取下一行。`finish()` 后复用抛 `RuntimeError`。
        """
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
        """解析一行，返回该行产出的记录（通常 0..若干个文本块）。

        终态与上限：`finish()` 后抛 `RuntimeError`；已因行数上限停机则直接返回空列表（该行
        不计 `lines_seen`、不解析）；单行超 `MAX_LINE_BYTES`/`MAX_LINE_CHARS` 时整行不交给
        `json.loads`，只计 `line_too_large`。
        """
        if self._finished:
            raise RuntimeError("parser is finished; create a new instance for a new stream")
        if self._line_limit_exceeded:
            return []
        if self._line_no >= MAX_LINES_PER_STREAM:
            # 整条流停止：上限后的行一概未读，因此必须向调用方交代扫描不完整。
            self._line_limit_exceeded = True
            self._stats.note(IssueCode.MAX_STREAM_LINES_EXCEEDED)
            return []
        self._line_no += 1
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

    # ---------- 行内分派 ----------

    def _dispatch(self, payload: dict[str, Any]) -> list[StandardRecord]:
        # 子代理门**先于**角色门（P2-4）：派生行的正文不得混进主会话结果，也不得被后面的
        # 角色/内容分支重新解释成主流记录。
        claim = _subagent_claim(payload)
        if claim is False:
            # 声明存在但形态不可解释：不猜其语义，计 unknown_event 使整流 partial。
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []
        if claim is True:
            self._sidechain_skipped_lines += 1
            # 与 claude 同型：IssueCode 是闭合枚举，无「派生跳过」类，因此计 unknown_event
            # 使覆盖不完整，真实构成由 sidechain_skipped_lines 明示。
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []

        self._note_attribution(payload)

        raw_type = payload.get("type")
        if _is_oversized_text(raw_type):
            # 超长 type 不可能命中任何固定集合，也不能当成「没有 type」走宽识分支。
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []
        event_type = _as_role(raw_type)
        if event_type in _NON_TEXT_EVENT_TYPES:
            # 已理解的元信息行：不产正文，也不使扫描降级。
            self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
            return []
        if event_type is not None and event_type not in TEXT_ROLES:
            # 已识别的「非消息事件」形态（模型切换、压缩、索引更新等）：按 unknown_event
            # 计数并令 partial 为真——不是「符合设计所以忽略」。
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return []
        return self._handle_message_line(payload)

    def _note_attribution(self, payload: dict[str, Any]) -> None:
        """吸收行内归属证据，但**只用于冲突核对**，绝不确立可信归属（P2-4）。

        行内 `cwd` 的写入方与语义未取证：因此 `header.trusted` 恒 `False`、项目质量不因行内值
        升级。仍保留读到的值（不假装什么都没看到），因为「有值但不可信」与「无值」对外是两件
        不同的事（前者 `unverified_header_cwd`，后者 `unknown`）。与外部断言字面不一致即归属
        不唯一：两个值都不采信，粘性记下冲突。
        """
        inline_cwd = _as_text(_first_present(payload, _CWD_KEYS), MAX_PROJECT_VALUE_CHARS)
        inline_version = _version_text(_first_present(payload, _VERSION_KEYS))
        if inline_cwd is not None and not self._header.seen:
            self._header = CursorHeaderInfo(
                session_id=_as_text(
                    _first_present(payload, _SESSION_ID_KEYS), MAX_SESSION_ID_CHARS
                ),
                cwd=inline_cwd,
                version=inline_version,
                line_no=self._line_no,
                seen=True,
                trusted=False,
            )
        if inline_cwd is None or self._project_conflict:
            return
        if self._asserted_project is not None and self._asserted_project != inline_cwd:
            # 字面不一致即歧义：本层无权裁决哪个是真的，也不拿其中一个冒充已核对的归属。
            self._project_conflict = True
            self._project = None
            self._project_quality = ProjectQuality.UNKNOWN
            return
        if self._asserted_project is None:
            # 只有不可采信的行内值：记下出处存疑，不猜测，也不拿它当项目值。
            self._project_quality = ProjectQuality.UNVERIFIED_HEADER_CWD

    def _handle_message_line(self, payload: dict[str, Any]) -> list[StandardRecord]:
        envelope = payload.get("message")
        if isinstance(envelope, dict):
            return self._handle_message(payload, envelope)
        if "role" in payload or _has_field(payload, _TEXT_KEYS):
            # CLI 把 role/content 平铺在本行；具备 role 或正文字段即按消息处理。
            return self._handle_message(payload, payload)
        self._stats.note(IssueCode.MISSING_MESSAGE_ENVELOPE)
        return []

    def _handle_message(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> list[StandardRecord]:
        """先定会话归属与角色，再取时间与正文；归属存疑的记录一律不产出。"""
        session_id, verified, rejected = self._resolve_session_id(outer, envelope)
        if rejected:
            return []
        record_issues: list[IssueCode] = []
        if session_id is None:
            self._stats.note(IssueCode.MISSING_SESSION_ID)
            record_issues.append(IssueCode.MISSING_SESSION_ID)
        elif not verified:
            # 只有一份证据（常为行内自报）：记录仍可用，但不得标为已核实的会话归属。
            self._stats.note(IssueCode.SESSION_ID_UNVERIFIED)
            record_issues.append(IssueCode.SESSION_ID_UNVERIFIED)

        role_value = envelope.get("role", outer.get("role"))
        role = _as_role(role_value)
        if role is None:
            self._stats.note(
                IssueCode.UNKNOWN_ROLE if _is_oversized_text(role_value) else IssueCode.MISSING_ROLE
            )
            return []
        if role not in TEXT_ROLES:
            # 非检索角色：不猜其内容是否可检索；角色名不进计数，只计固定类别并令覆盖不完整。
            if role in KNOWN_NON_TEXT_ROLES:
                self._stats.note(IssueCode.SKIPPED_ROLE)
            else:
                self._stats.note(IssueCode.UNKNOWN_ROLE)
            return []

        timestamp, time_quality = self._resolve_timestamp(outer, envelope)
        if time_quality is not TimeQuality.EXACT:
            self._stats.note(TIMESTAMP_ISSUES[time_quality])
            record_issues.append(TIMESTAMP_ISSUES[time_quality])

        blocks, lost_content, limit_issues = self._content_blocks(envelope, role=role)
        record_issues.extend(limit_issues)
        if blocks is None:
            # 形状不可解释：真实的信息损失，使扫描不完整。
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            return []
        if not blocks:
            if not lost_content:
                # 本身就没有任何文本块（如 `content: []`）：已理解的结构，不降级。
                self._stats.note(IssueCode.NO_TEXT_CONTENT)
            return []

        if not self._project_quality.sourced:
            # 已输出但无可靠项目归属：当场计入，后续出现行内 cwd 也不能挣销（记录不回改）。
            self._stats.note(IssueCode.PROJECT_UNVERIFIED)
            record_issues.append(IssueCode.PROJECT_UNVERIFIED)

        issues = tuple(record_issues)
        records = [
            StandardRecord(
                source=self._source,
                session_id=session_id,
                location=SourceLocation(self._stream_label, self._line_no, index),
                text=block,
                role=role,
                executor=None,
                timestamp=timestamp,
                time_quality=time_quality,
                project=self._project,
                project_quality=self._project_quality,
                issues=issues,
            )
            for index, block in enumerate(blocks)
        ]
        self._stats.records_emitted += len(records)
        self._stats.lines_with_records += 1
        return records

    # ---------- 字段解析辅助 ----------

    def _decode(self, line: str | bytes) -> str | None:
        """先按固定上限判行大小，再按 UTF-8 解码；超限/解码失败均不保留原值。"""
        if isinstance(line, str):
            if len(line) > MAX_LINE_CHARS:
                self._stats.note(IssueCode.LINE_TOO_LARGE)
                return None
            return line
        if isinstance(line, (bytes, bytearray)):
            raw = bytes(line)
            if len(raw) > MAX_LINE_BYTES:
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

    def _resolve_session_id(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> tuple[str | None, bool, bool]:
        """返回 `(可用于记录的会话标识, 是否已核实, 是否拒绝本行)`。

        三份证据：调用方断言、首次行内快照、本行行内字段。任意两份不一致 → 计
        `session_id_mismatch` 并拒行；只有一份证据时可用但**不算已核实**。
        """
        inline = self._inline_session_id(outer, envelope)
        if self._session_id_conflict:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        header_id = self._header.session_id if self._header.seen else None
        candidates = [v for v in (self._expected_session_id, header_id, inline) if v is not None]
        if len(set(candidates)) > 1:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        if not candidates:
            return None, False, False
        return candidates[0], len(candidates) >= 2, False

    def _inline_session_id(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> str | None:
        """行内会话标识：先看外层再看消息体；消息层不用裸 `id`（常为单条消息 ID）。"""
        for holder in (outer, envelope):
            for key in _MESSAGE_SESSION_ID_KEYS:
                value = _as_text(holder.get(key), MAX_SESSION_ID_CHARS)
                if value is not None:
                    return value
        return None

    def _verified_session_id(self) -> str | None:
        """可核实的会话标识：需两个独立来源一致；否则 `None`（不当可信归属用）。"""
        if self._session_id_conflict:
            return None
        expected = self._expected_session_id
        inline = self._header.session_id if self._header.seen else None
        if expected is not None and inline is not None:
            return expected if expected == inline else None
        return None

    def _resolve_timestamp(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> tuple[datetime | None, TimeQuality]:
        """只取本条记录内的**显式时间字段**或 `<timestamp>` 标签内容；不回落到头部/文件 mtime。

        标签内容优先（CLI 把用户消息的时刻写在正文标签里）；标签内值不合规则计
        `timestamp_invalid`（不回落猜测），标签缺失才看显式字段。
        """
        tagged = self._tagged_timestamp(outer, envelope)
        if tagged is not None:
            return tagged
        for holder in (envelope, outer):
            for key in _TIMESTAMP_KEYS:
                if key in _HEADER_ONLY_KEYS:
                    continue
                candidate = holder.get(key)
                if candidate is not None:
                    return normalize_timestamp(candidate)
        return None, TimeQuality.MISSING

    def _tagged_timestamp(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> tuple[datetime | None, TimeQuality] | None:
        """从正文里的 `<timestamp>` 标签取值并规范化；无标签返回 `None`（不计数）。"""
        for holder in (envelope, outer):
            for key in _TEXT_KEYS:
                value = holder.get(key)
                if not isinstance(value, str) or "<timestamp>" not in value:
                    continue
                found = _TIMESTAMP_TAG.search(value)
                if found is None:
                    continue
                raw = found.group(1).strip()
                if not raw:
                    return None, TimeQuality.INVALID
                if len(raw) > _MAX_TAGGED_CHARS:
                    return None, TimeQuality.INVALID
                moment, quality = normalize_timestamp(raw)
                if quality is TimeQuality.INVALID:
                    self._stats.note(IssueCode.TIMESTAMP_INVALID)
                    return None, TimeQuality.INVALID
                return moment, quality
        return None

    def _content_blocks(
        self, envelope: dict[str, Any], *, role: str
    ) -> tuple[tuple[str, ...] | None, bool, tuple[IssueCode, ...]]:
        """提取本行可发布的正文块（有界），并按标签边界收窄 user 正文。

        返回 `(块元组, 是否有内容因不可解释而未产出, 本行命中的上限原因码)`。块元组为 `None`
        表示 content 整体形状不可解释。

        与 pi 的关键差异（P2-4 发布边界）：**user 角色只发布 `<user_query>` 标签内的正文**。
        CLI 把用户输入包在该标签里，标签外是模板说明文本；未核实该模板的稳定性，因此标签外
        内容一概不进正文（`NO_TEXT_CONTENT` 表达「已理解且无标签内正文」，不降级；标签存在但
        为空亦同）。assistant 角色沿用块数组/裸字符串双限提取。
        """
        content = envelope.get("content", _FIELD_NOT_PRESENT)
        if content is _FIELD_NOT_PRESENT:
            content = envelope.get("text", _FIELD_NOT_PRESENT)
        if content is _FIELD_NOT_PRESENT or content is None:
            return None, True, ()
        line_issues: list[IssueCode] = []

        if isinstance(content, str):
            if not content.strip():
                return (), False, ()
            extracted, emitted, lost = self._extract_tagged(content, role=role)
            if emitted == 0 and not lost:
                self._stats.note(IssueCode.NO_TEXT_CONTENT)
            if extracted is None:
                return None, True, tuple(line_issues)
            texts, truncated = _bounded_text(extracted)
            if truncated:
                self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
            return (texts,), lost, tuple(line_issues)

        if isinstance(content, dict):
            candidates: list[Any] = [content]
            dropped_blocks = 0
        elif isinstance(content, (list, tuple)):
            candidates = list(content[:MAX_CONTENT_BLOCKS_PER_LINE])
            dropped_blocks = len(content) - len(candidates)
        else:
            # 数字/布尔等非集合形状：不猜其语义。
            return None, True, ()

        texts_out: list[str] = []
        lost = bool(dropped_blocks)
        if dropped_blocks:
            # 计数只记「发生了截断」一次，不记块数、类型名或原值。
            self._stats.note(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
            line_issues.append(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
        for item in candidates:
            if isinstance(item, str):
                if not item.strip():
                    continue
                extracted, emitted, block_lost = self._extract_tagged(item, role=role)
                lost = lost or block_lost
                if emitted == 0 and not block_lost:
                    self._stats.note(IssueCode.NO_TEXT_CONTENT)
                if extracted is None:
                    continue
                bounded, truncated = _bounded_text(extracted)
                if truncated:
                    self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                    line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
                texts_out.append(bounded)
                continue
            if not isinstance(item, dict):
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
                lost = True
                continue
            raw_block_type = _first_present(item, _TYPE_KEYS)
            block_type = _as_role(raw_block_type)
            if block_type is None and _is_oversized_text(raw_block_type):
                # 超长 type 不回落成「无 type 即文本块」：那会把未知块的 body 拉进正文。
                self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
                lost = True
                continue
            if block_type is not None and block_type not in TEXT_BLOCK_TYPES:
                if block_type in KNOWN_NON_TEXT_BLOCKS:
                    self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
                else:
                    # 未收录的类型：不声称认识它，也不猜块内有没有可检索文本。
                    self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
                    lost = True
                continue
            body = _first_present(item, _TEXT_KEYS)
            if isinstance(body, str):
                if not body.strip():
                    continue
                extracted, emitted, block_lost = self._extract_tagged(body, role=role)
                lost = lost or block_lost
                if emitted == 0 and not block_lost:
                    self._stats.note(IssueCode.NO_TEXT_CONTENT)
                if extracted is None:
                    continue
                bounded, truncated = _bounded_text(extracted)
                if truncated:
                    self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                    line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
                # 保留前缀逐字不动（不削内部空白），仅用 strip 判空。
                texts_out.append(bounded)
                continue
            if body is None and not _has_field(item, _TEXT_KEYS):
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            else:
                # 字段存在但形状不是字符串（列表/对象/数字/布尔/显式 null）：不猜语义。
                self._stats.note(IssueCode.NON_STRING_TEXT_BLOCK)
            lost = True
        return tuple(texts_out), lost, tuple(line_issues)

    def _extract_tagged(self, value: str, *, role: str) -> tuple[str | None, int, bool]:
        """按角色收窄正文：返回 `(可发布正文|None, 发布条数, 是否有内容未取全)`。

        - `user`：只取 `<user_query>` 标签内正文并剥标签。多段标签合并为一条（同一轮用户输入
          被拆成多段时，拆开检索会丢上下文；合并只保留顺序拼接，不改写内容）。标签缺失 →
          `(None, 0, False)`：模板外壳不是正文，本轮未核实其稳定性，宁可不发布。
        - 其它角色（本层只可能是 `assistant`）：原样发布，并去掉 `<timestamp>` 标签壳——时刻
          已由 `_resolve_timestamp` 单独承载，留在正文里会污染检索片段。
        """
        if role != "user":
            cleaned = _strip_timestamp_tag(value)
            if cleaned is None:
                return None, 0, True
            if not cleaned.strip():
                return None, 0, False
            return cleaned, 1, False
        found = _USER_QUERY_TAG.findall(value)
        if not found:
            return None, 0, False
        joined = "\n".join(part.strip() for part in found if part and part.strip())
        if not joined:
            return None, 0, False
        return joined, 1, False


def _strip_timestamp_tag(value: str) -> str | None:
    """移除正文中的 `<timestamp>` 外壳；标签不成对（形态不可解释）返回 `None`。

    不成对就整体不发布：半截标签说明该行的模板形态超出本层已核实的范围，把剩下的字节当正文
    会把没读懂的结构伪装成消息。
    """
    if "<timestamp>" not in value and "</timestamp>" not in value:
        return value
    if value.count("<timestamp>") != value.count("</timestamp>"):
        return None
    return _TIMESTAMP_TAG.sub("", value).strip()


# ---------- 发现（两轴分离，P1-2/P2-4） ----------


class CursorDiscoveryStatus(StrEnum):
    """发现结论的状态；四个失败态**不得合并**（每态对外措辞与后续动作不同）。

    `AVAILABLE` 是枚举必需的第五态（候选非空时的结论）：简报 §3.3 只列了四个失败态，而
    四态都表不了「已拿到候选」——`NO_CANDIDATES` 与非空 `candidates` 自相矛盾，`UNSUPPORTED`
    谎称不认识已认识的条目。本层宁可新增一个显式成功态，也不拿误称的失败态对外交代发现结果。
    """

    #: 候选已定位（只表示找到文件，不表示正文可读、更不表示归属成立）。
    AVAILABLE = "available"
    #: 调用方未配置该来源的存储根：功能未启用，不是「没有会话」。
    DISABLED = "disabled"
    #: 存储根缺失/不可解析/不可读：该面**不可判定**，不得称无匹配。
    UNAVAILABLE = "unavailable"
    #: 存储根可读但本面没有候选条目：**该面无匹配**（禁称「完整无匹配」）。
    NO_CANDIDATES = "no_candidates_on_facet"
    #: 条目存在但形态超出已核实范围：本层不认识，不猜其内容。
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class CursorDiscoveryOutcome:
    """发现结论：状态 + 候选 `(session_id, 相对存储根路径)` + 固定文案 note。

    `candidates` 里的路径是**相对存储根**的 posix 风格相对串，绝对路径不外发：调用方要重建
    绝对路径必须回到自己已批准的根上拼接，不能拿本字段当授权凭据。`session_id` 取自文件名
    基名（去掉 `.jsonl`）——它只是**候选断言**，与记录内字段的核对由解析层与策略层完成，
    本层不据此宣称归属成立。
    """

    status: CursorDiscoveryStatus
    candidates: tuple[tuple[str, str], ...] = ()
    note: str | None = None


def _relative_form(root: str, path: str) -> str:
    """存储根下的相对路径（posix 分隔，只用于外发，不用于再解析）。"""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        # 跨盘符（Windows）等不可比情形：退化成基名，绝不返回可能逃出根的路径串。
        rel = os.path.basename(path)
    return rel.replace(os.sep, "/").replace("\\", "/")


def _transcript_root(store_root: str) -> str:
    """已批准根之下的 `<工作区编码>/agent-transcripts/` 汇集面的定位。

    两种可解释形态：调用方给的根**就是** `agent-transcripts` 目录本身，或它是含该目录的工作区
    编码目录；其余形态只在其**直接子层**里找 `agent-transcripts`（有界一层，不做全盘递归）。
    """
    base = os.path.basename(store_root.rstrip("/\\"))
    if base.casefold() == TRANSCRIPT_DIR_MARKER:
        return store_root
    direct = os.path.join(store_root, TRANSCRIPT_DIR_MARKER)
    if os.path.isdir(direct):
        return direct
    return ""


def _iter_transcript_files(directories: Sequence[str]) -> list[tuple[str, str]] | None:
    """在给定目录里收集 `.jsonl` 候选；返回 `None` 表示存在**不可解释的条目形态**。

    不可解释 = 目录项里出现非文件非目录的其它形态（设备/FIFO/重解析目标不明）。符号链接指向
    文件仍算可解释（读取轴会另行按 `allow_links` 判定），本层只负责「条目是什么形态」。
    """
    found: list[tuple[str, str]] = []
    for directory in directories:
        try:
            entries = list(os.scandir(directory))
        except OSError:
            return None
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    nested = os.path.join(entry.path, TRANSCRIPT_DIR_MARKER)
                    if os.path.isdir(nested):
                        found.extend(_iter_transcript_files([nested]) or [])
                    continue
                if not entry.is_file(follow_symlinks=True):
                    return None
            except OSError:
                return None
            if not entry.name.lower().endswith(".jsonl"):
                continue
            session_id = entry.name[: -len(".jsonl")].strip()
            if not session_id:
                return None
            found.append((session_id, entry.path))
    return found


_MISSING_ROOT_CODES: frozenset[RefusalCode] = frozenset(
    {RefusalCode.PATH_MISSING, RefusalCode.PATH_UNRESOLVABLE}
)


def discover_cursor_transcripts(
    policy: SessionPolicy,
    scope: object,
    *,
    store_root_path: object,
    attribution_project: object = None,
) -> CursorDiscoveryOutcome:
    """在**已批准的存储根**内列举 Agent CLI transcript 候选（不读任何正文）。

    两轴严格分离（DES-ARCH-04）：

    - **读取轴**：`store_root_path` 必须先过 `authorize_store(scope, SOURCE_CURSOR, root,
      kind=DIRECTORY)`；未批即原样抛 `PolicyDenied`（对外固定 `storage_denied`），本层不捕、
      不转译、不回退。**绝不**因为归属轴批准了某个项目就去读项目目录树，也**绝不**全盘扫描。
    - **归属轴**：`attribution_project` 只判候选属于哪个已批准项目；批准归属根不使项目树可读。
      本参数为 `None` 时不做归属收窄（返回该面全部候选），给出时只用于收窄，不参与读取判定。

    四态判定（不合并）：

    - `store_root_path` 不是非空字符串 → `DISABLED`（未配置，不是「没有会话」）。
    - 授权通过但根不可解析/不是目录 → `UNAVAILABLE`（不可判定，禁称无匹配）。
    - 根可读但找不到 `agent-transcripts` 面或其下无 `.jsonl` → `NO_CANDIDATES`（该面无匹配）。
    - 条目形态不可解释（设备项、空基名等） → `UNSUPPORTED`（不认识，不猜）。
    - 候选已定位 → `AVAILABLE`（只表示找到文件，不表示正文可读、不表示归属成立）。

    候选数上限由调用方（服务层）负责，本函数只返回定位结论；返回的路径是相对存储根的串，
    绝对路径不外发。
    """
    if not isinstance(store_root_path, str) or not store_root_path.strip():
        return CursorDiscoveryOutcome(
            status=CursorDiscoveryStatus.DISABLED,
            note="该来源的会话存储根未配置",
        )
    # 读取轴：拒绝原样抛出（只带固定码），本层不捕、不转译、不拿它改任何结论。唯一例外是
    # 位置已在批准根内但取不到确定的真实位置（不存在/解析不出）：那是「根不可用」，不是
    # 「未批准」，按本层四态判给 UNAVAILABLE。先授权再判存在性，因此未批准（path_out_of_scope
    # 等）仍继续原样抛出，两种拒绝不得合并。
    try:
        policy.authorize_store(
            scope, SOURCE_CURSOR, store_root_path, kind=TargetKind.DIRECTORY
        )
    except PolicyDenied as denial:
        if denial.code not in _MISSING_ROOT_CODES:
            raise
        return CursorDiscoveryOutcome(
            status=CursorDiscoveryStatus.UNAVAILABLE,
            note="存储根不可解析或不是目录",
        )
    # 归属轴：只做一次可选核对，不影响上面的读取结论；未命中即收窄为空，但不改读取轴状态。
    if isinstance(attribution_project, str) and attribution_project.strip():
        try:
            policy.authorize_attribution(scope, store_root_path, project=attribution_project)
        except PolicyDenied:
            return CursorDiscoveryOutcome(
                status=CursorDiscoveryStatus.NO_CANDIDATES,
                note="该面无匹配",
            )

    if not os.path.isdir(store_root_path):
        return CursorDiscoveryOutcome(
            status=CursorDiscoveryStatus.UNAVAILABLE,
            note="存储根不可解析或不是目录",
        )
    direct = _transcript_root(store_root_path)
    if direct:
        directories = [direct]
    else:
        # 根是 `~/.cursor/projects` 这一层：只在其**直接子层**找 agent-transcripts（有界一层）。
        try:
            entries = list(os.scandir(store_root_path))
        except OSError:
            return CursorDiscoveryOutcome(
                status=CursorDiscoveryStatus.UNAVAILABLE,
                note="存储根不可读",
            )
        children: list[str] = []
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                return CursorDiscoveryOutcome(
                    status=CursorDiscoveryStatus.UNSUPPORTED,
                    note="条目形态不可解释",
                )
            nested = os.path.join(entry.path, TRANSCRIPT_DIR_MARKER)
            if os.path.isdir(nested):
                children.append(nested)
        if not children:
            return CursorDiscoveryOutcome(
                status=CursorDiscoveryStatus.NO_CANDIDATES,
                note="该面无匹配",
            )
        directories = children

    collected = _iter_transcript_files(directories)
    if collected is None:
        return CursorDiscoveryOutcome(
            status=CursorDiscoveryStatus.UNSUPPORTED,
            note="条目形态不可解释",
        )
    if not collected:
        return CursorDiscoveryOutcome(
            status=CursorDiscoveryStatus.NO_CANDIDATES,
            note="该面无匹配",
        )
    return CursorDiscoveryOutcome(
        status=CursorDiscoveryStatus.AVAILABLE,
        candidates=tuple(
            (session_id, _relative_form(store_root_path, path)) for session_id, path in collected
        ),
        note=None,
    )
