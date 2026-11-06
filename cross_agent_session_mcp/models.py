"""跨来源标准记录、位置与解析质量模型（DES-DATA-01）。

本模块是来源适配器和查询协调层之间的内部数据契约，服务的需求条目：
SRS-SEARCH-01、SRS-SEARCH-02、SRS-SEARCH-05、SRS-SEARCH-09。

可公开计数的硬约束：`ParseStats` 只接受**闭合枚举类别**（`IssueCode`）与整数计数，
不接受任何来自会话数据的字符串作为键。类型名、角色名、块类型、路径、正文都不得进入
计数结构，否则「可公开/可日志」的统计会被数据侧内容污染（DES-SEC-01）。

不可信输入的有界处理：会话行流是不可信数据。解析侧的资源上限（单行大小、单行块数、
文本块长度、单流行数）全部写成 `sources/pi.py` 里的固定常量，超限只记**固定原因码**
（`line_too_large` / `content_block_limit_exceeded` / `text_block_truncated` /
`max_stream_lines_exceeded`）并使 `partial` 为真，**不保存被丢弃或被截断的输入值**，
也不把上限值拼成数据侧的字符串键。时间字段同样有界：字符串先按
`MAX_TIMESTAMP_STRING_CHARS` 判长度再解析，超长字符串、NaN/Inf 与量级判不准单位的纪元数
（≥ 1e17 或 |值| < 1e9）一律 `invalid`，不猜单位、不回填时区。

位置标识的硬约束：`SourceLocation` 构造即经 `sanitize_stream_label` 规范标签，绝对路径、
带分隔符/空白/非 ASCII 的不受控原文、超长标签都整体替换为固定值 `redacted-stream`，
对外引用串里不会残留原值片段。

本增量状态（不得理解为功能已完成）：

- 已实现：标准记录 `StandardRecord`、可追踪位置 `SourceLocation`（含标签有界规范
  `sanitize_stream_label`）、时间与项目质量枚举、解析质量原因码 `IssueCode`（含上述四个
  资源上限原因码）、计数聚合 `ParseStats`，以及时间归一化 `normalize_timestamp`（带时区
  ISO 8601 / 秒 / 毫秒 / 微秒纪元数；长度与量级有界；无时区和非法值判为不可用，不回填
  本地时区、不使用文件 mtime）。
- 本层不含：授权范围与项目映射（`policy.py`）、`coverage` 汇总与结果分页截断
  （由协调层承担）、检索片段长度上限与常见凭据遮蔽（`publication.py`/`redaction.py`）、
  SQLite rowid 类位置形态、把 `IssueCode` 计数映射成对外 `coverage.status` 的规则
  （`partial` 只给出“是否不完整”的布尔判据，不含对外状态字符串）。本层也不验证项目值与会话标识，任何质量枚举都
  不表示「已授权」。

约束（DES-ARCH-02、DES-SEC-01）：本模块只依赖标准库；不导入 MCP SDK，不打开文件，
不发现任何来源，不写日志，不保存原始行文本。`text` 字段承载消息正文，属于返回给调用方
的数据，禁止由适配层写入日志或缓存。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

__all__ = [
    "IssueCode",
    "MAX_TIMESTAMP_STRING_CHARS",
    "NON_PARTIAL_ISSUES",
    "ParseStats",
    "ProjectQuality",
    "REDACTED_STREAM_LABEL",
    "SourceLocation",
    "StandardRecord",
    "STREAM_LABEL_MAX_CHARS",
    "TIMESTAMP_ISSUES",
    "TimeQuality",
    "normalize_timestamp",
    "sanitize_stream_label",
]

#: 时间字符串解析前的长度上限：带时区与微秒的 ISO 8601 约 32 字符，64 已留足余量。
#: 超长字符串**不做解析**直接判 `invalid`（避免把不受控的长文本喂给日期解析器）。
MAX_TIMESTAMP_STRING_CHARS = 64

#: 纪元数单位判据：绝对值小于该阈值按秒解释，再依次按毫秒、微秒解释。
_EPOCH_SECONDS_LIMIT = 1e11
_EPOCH_MILLISECONDS_LIMIT = 1e14
_EPOCH_MICROSECONDS_LIMIT = 1e17
#: 秒解释的下界（1e9 秒 ≈ 2001-09-09）。小于该量级的数字既可能是极早的秒值，也可能是
#: 毫秒时长、亚秒值或日期片段，单位无法可靠确定 → 判 `invalid`，不回填成 1970 年附近冒充时间。
_EPOCH_MIN_SECONDS = 1e9

#: 位置标签长度上限：超过即**整体**替换（不做前缀截断，前缀仍可能携带不受控原文）。
STREAM_LABEL_MAX_CHARS = 64
#: 不合规标签的统一替代值：固定字符串，不含原值任何片段，也不含路径分隔符。
REDACTED_STREAM_LABEL = "redacted-stream"
#: 标签字符白名单：ASCII 字母数字与 `._-`；不含 `/ \\ :`、盘符、空白与任何非 ASCII 文本。
_STREAM_LABEL_SAFE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)


class TimeQuality(StrEnum):
    """消息时间来源质量；只有 `EXACT` 可参与时间范围过滤（SRS-SEARCH-05）。"""

    EXACT = "exact"  # 记录内自带时间且带明确时区
    MISSING = "missing"  # 记录内没有时间字段
    NO_TIMEZONE = "no_timezone"  # 有时间但无时区，不猜测偏移
    INVALID = "invalid"  # 字段存在但形状/取值不可解释


class ProjectQuality(StrEnum):
    """项目归属质量。本层不验证任何取值，也不表达授权；只区分「值的来源」。

    只有 `TRUSTED_HEADER_CWD`（结构一致的头部 cwd）与 `CALLER_ASSERTED`（上层显式给定）
    算「有来源可信度的值」；其余记录不得宣称已按项目归类。两者都仍需后续授权层校验
    路径与项目映射，本枚举**不含**「已授权」含义。
    """

    TRUSTED_HEADER_CWD = "trusted_header_cwd"  # 取自结构可信头部（版本可识别、无冲突）的 cwd
    CALLER_ASSERTED = "caller_asserted"  # 由上层给定；本层未验证其真实性，也不表示已授权
    UNVERIFIED_HEADER_CWD = "unverified_header_cwd"  # 头部有 cwd，但头部本身不可采信（见下）
    UNKNOWN = "unknown"  # 无可信 cwd；不依据目录编码猜测

    @property
    def sourced(self) -> bool:
        """该质量的记录是否带有一个可解释的项目值（不含「已验证/已授权」）。"""
        return self in (ProjectQuality.TRUSTED_HEADER_CWD, ProjectQuality.CALLER_ASSERTED)


class IssueCode(StrEnum):
    """解析质量原因码：闭合集合，只含类别，不含原文、路径、凭据（DES-SEC-01）。

    新增类别只能改本枚举，不得由解析器用数据侧字符串临时造键：计数结果会进入
    对外覆盖信息与日志。
    """

    CORRUPT_LINE = "corrupt_line"  # JSON 解码或字节解码失败
    BLANK_LINE = "blank_line"  # 空行：跳过但不计为不完整
    LINE_NOT_OBJECT = "line_not_object"  # 合法 JSON 但不是对象
    LINE_TOO_LARGE = "line_too_large"  # 单行超出固定上限：整行不解析、不保存原值
    CONTENT_BLOCK_LIMIT_EXCEEDED = (
        "content_block_limit_exceeded"  # 单行块数超出上限：后面的块一概不看
    )
    TEXT_BLOCK_TRUNCATED = "text_block_truncated"  # 文本块超长度上限：只留固定长度前缀，不另存被削部分
    MAX_STREAM_LINES_EXCEEDED = (
        "max_stream_lines_exceeded"  # 单流扫描行数达上限：该行起停止整条流
    )
    NO_SESSION_HEADER = "no_session_header"  # 行流内未出现任何会话头部行
    LATE_SESSION_HEADER = "late_session_header"  # 重复的会话头部行：仅首个头部被采信
    CONFLICTING_HEADER_CWD = "conflicting_header_cwd"  # 多个头部 cwd 不一致
    CONFLICTING_HEADER_VERSION = "conflicting_header_version"  # 多个头部版本不一致，语义无法确定
    UNKNOWN_PROJECT = "unknown_project"  # 会话级项目无法确定
    PROJECT_UNVERIFIED = "project_unverified"  # 记录在无可靠项目归属下被产出（不因后续头部而撤销）
    MISSING_HEADER_VERSION = "missing_header_version"  # 头部没有可识别的版本字段
    UNSUPPORTED_HEADER_VERSION = (
        "unsupported_header_version"
    )  # 版本字段不可识别（含超 `MAX_HEADER_VERSION_CHARS` 的超长值）
    INVALID_HEADER_CWD = (
        "invalid_header_cwd"
    )  # 头部 cwd 字段存在但形状/取值不可用（含超 `MAX_PROJECT_VALUE_CHARS`）
    HEADER_SESSION_ID_MISMATCH = "header_session_id_mismatch"  # 头部会话标识与断言/其它头部冲突
    SESSION_ID_UNVERIFIED = "session_id_unverified"  # 该记录所属会话标识无法核实
    MISSING_SESSION_ID = "missing_session_id"  # 头部、调用方断言与行内字段都未给出会话标识
    SESSION_ID_MISMATCH = "session_id_mismatch"  # 会话标识证据冲突（记录被拒绝）
    MISSING_MESSAGE_ENVELOPE = "missing_message_envelope"  # 声称是消息却无消息体
    UNKNOWN_EVENT = "unknown_event"  # 未识别的事件类型（SRS-SEARCH-09）
    KNOWN_NON_TEXT_EVENT = "known_non_text_event"  # 已知的非正文/环境控制事件（模型变更、思考等级、自定义扩展等）
    MISSING_ROLE = "missing_role"  # 消息缺 role
    UNKNOWN_ROLE = "unknown_role"  # role 不在本适配器可产出正文的集合内
    SKIPPED_ROLE = "skipped_role"  # 已知但超出当前任务边界的角色：跳过即覆盖不完整
    NO_TEXT_CONTENT = "no_text_content"  # 消息可理解且未丢弃任何块，只是没有可检索文本
    INVALID_CONTENT_SHAPE = "invalid_content_shape"  # content/块形状不可解释
    UNKNOWN_BLOCK_TYPE = "unknown_block_type"  # 本适配器未收录的块类型（格式演进，覆盖不完整）
    KNOWN_NON_TEXT_BLOCK = "known_non_text_block"  # 已知的非检索正文块（图像/工具调用等）
    NON_STRING_TEXT_BLOCK = "non_string_text_block"  # 声称是文本块但正文字段不是非空字符串
    MISSING_TIMESTAMP = "missing_timestamp"  # 记录无时间
    TIMESTAMP_NO_TIMEZONE = "timestamp_no_timezone"  # 记录时间无时区
    TIMESTAMP_INVALID = "timestamp_invalid"  # 记录时间不可解析
    # 以下三类是新增来源（cursor/dsh/workbuddy）适配器的专属质量码：都属可解释降级，
    # 因此**不**加入 `NON_PARTIAL_ISSUES`——它们照常使 `ParseStats.partial` 为真。
    FRAME_TRUNCATED = "frame_truncated"  # 解压帧流在中途断掉（截断帧/超预算后停止）
    BODY_FILE_MISSING = "body_file_missing"  # 数据库行宣称的正文文件不存在或不可打开
    DECODER_RUNTIME_MISSING = "decoder_runtime_missing"  # 解压运行时缺失，帧流无法解码


#: 不计入“不完整”的原因码：这些行**已被完整理解且不隐藏任何内容**——
#: - `blank_line`：JSONL 的正常边界；
#: - `no_text_content`：消息结构合法，没有任何块被丢弃，只是本身不含文本（如 `content: []`）；
#: - `known_non_text_block`：块类型已被识别为非检索正文（图像、工具调用、思考块等），
#:   属于当前任务边界内的「已理解的省略」。
#: - `skipped_role`：已知非正文角色（如 system、tool、toolResult 等），已理解的过滤。
#: 其余原因码都是真实的信息损失或归属不可核实，必须使 `partial` 为真，包括：
#: 未知块类型、非字符串正文、形状不可解释、被跳过的其它角色、会话标识冲突/无法核实、
#: 无可靠项目归属的记录（SRS-SEARCH-09：不得把部分扫描说成完整无匹配）。
#: 资源上限类原因码（`line_too_large`、`content_block_limit_exceeded`、
#: `text_block_truncated`、`max_stream_lines_exceeded`）**同样使 `partial` 为真**：
#: 上限换的是「工作量与内存有界」，代价就是承认有内容没看全，不得粉饰为完整。
NON_PARTIAL_ISSUES: frozenset[IssueCode] = frozenset(
    {
        IssueCode.BLANK_LINE,
        IssueCode.NO_TEXT_CONTENT,
        IssueCode.KNOWN_NON_TEXT_BLOCK,
        IssueCode.KNOWN_NON_TEXT_EVENT,
        IssueCode.SKIPPED_ROLE,
    }
)

#: 时间质量到原因码的映射。
TIMESTAMP_ISSUES: dict[TimeQuality, IssueCode] = {
    TimeQuality.MISSING: IssueCode.MISSING_TIMESTAMP,
    TimeQuality.NO_TIMEZONE: IssueCode.TIMESTAMP_NO_TIMEZONE,
    TimeQuality.INVALID: IssueCode.TIMESTAMP_INVALID,
}


@dataclass(frozen=True)
class SourceLocation:
    """已授权来源内可追溯位置（DES-API-01）。

    `stream_label` 由调用者提供，但**不原样携带**：构造时即过 `sanitize_stream_label`，
    绝对路径、带分隔符/盘符/空白/非 ASCII 的不受控原文与超长值整体降为固定
    `redacted-stream`。适配器自身不发现、不打开、不校验文件，因此该标签只是调用方给出的
    行流短标识，不充当路径授权凭据；边界校验由 `policy.py` 与 `sanitize_stream_label` 共同承担。

    `line_no` 为 1 起始的行号，语义是**行流中的行序号**；若来源是压缩流，它是解压后
    事件序号，不伪装成原始文件字节偏移。`ordinal` 保留同一行内的第几个产出记录，
    用于一行含多条可产出记录时不丢位置。
    """

    stream_label: str | None
    line_no: int
    ordinal: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "stream_label", sanitize_stream_label(self.stream_label))

    def to_ref(self) -> str:
        """输出对外位置串；无标签时退化为纯行号并显式标出标签缺失。

        两个分支的输出都由固定字面量 + 规范后的短标签 + 整数组成，不得拼入原值。
        """
        if self.stream_label:
            base = f"jsonl:{self.stream_label}#L{self.line_no}"
        else:
            base = f"jsonl:unknown-stream#L{self.line_no}"
        return base if self.ordinal == 0 else f"{base}+{self.ordinal}"


def sanitize_stream_label(value: object) -> str | None:
    """把不受控的行流标签规范为短安全标识或 `None`（不可信值一律整体替代）。

    保留条件（全部满足）：是非空白字符串、`strip()` 后长度 ≤ `STREAM_LABEL_MAX_CHARS`、
    只含 `_STREAM_LABEL_SAFE_CHARS`（ASCII 字母数字与 `._-`）、且不以 `.` 起头（排除
    `..`、`.` 类相对跳转）。**不截断、不部分保留**：前缀截断仍会泄露原值片段，
    因此不合规时返回固定 `REDACTED_STREAM_LABEL`，绝对路径、Windows 盘符、反斜杠、
    非 ASCII 名称均无法透过位置串。空/非字符串返回 `None`（等价于「无标签」）。
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if len(candidate) > STREAM_LABEL_MAX_CHARS:
        return REDACTED_STREAM_LABEL
    if candidate.startswith("."):
        return REDACTED_STREAM_LABEL
    if not set(candidate) <= _STREAM_LABEL_SAFE_CHARS:
        return REDACTED_STREAM_LABEL
    return candidate


@dataclass(frozen=True)
class StandardRecord:
    """适配器产出的标准记录（DES-DATA-01）。

    可空字段为 `None` 表示“未知”，调用方必须在覆盖信息中说明，不得补默认值。
    `timestamp` 只接受带时区的 datetime；输出统一 ISO 8601 由查询层完成。
    `session_id` 只有在会话标识可核实时才有值；无法核实（头部冲突、头部缺标识且调用方
    未断言）时为 `None`，并由 `issues` 标出原因——不得把未核实的会话标成可信归属。
    """

    source: str
    session_id: str | None
    location: SourceLocation
    text: str
    role: str | None = None
    executor: str | None = None  # 实际执行者；元数据不能确认时为 None，不由模型名推断
    timestamp: datetime | None = None
    time_quality: TimeQuality = TimeQuality.MISSING
    project: str | None = None
    project_quality: ProjectQuality = ProjectQuality.UNKNOWN
    issues: tuple[IssueCode, ...] = ()


@dataclass
class ParseStats:
    """一次解析的计数聚合：只含**闭合类别**与整数，可安全用于日志与对外覆盖信息。

    不得出现来自会话数据的字符串（类型名、角色名、路径、正文）：所有质量信号先归入
    `IssueCode`，再由 `reason_codes()` / `as_public_dict()` 输出，键集合固定。"""

    lines_seen: int = 0
    lines_with_records: int = 0
    records_emitted: int = 0
    issue_counts: dict[IssueCode, int] = field(default_factory=dict)

    def note(self, issue: IssueCode) -> None:
        """累计一个原因码；只接受 `IssueCode` 闭合类别，不接受数据侧字符串。"""
        if not isinstance(issue, IssueCode):
            raise TypeError("issue counts only accept IssueCode categories")
        self.issue_counts[issue] = self.issue_counts.get(issue, 0) + 1

    @property
    def skipped_count(self) -> int:
        """未产出任何记录的行数（含空行、跳过事件与损坏行），供覆盖信息展示。

        按行计量而不是按记录计量：一行可能产出多个文本块，两者不能互推。
        """
        return max(self.lines_seen - self.lines_with_records, 0)

    @property
    def partial(self) -> bool:
        """是否存在使本次扫描不得称为“完整”的质量问题。"""
        return any(
            count > 0 for issue, count in self.issue_counts.items() if issue not in NON_PARTIAL_ISSUES
        )

    def reason_codes(self) -> tuple[IssueCode, ...]:
        """按出现次数降序返回原因码，供覆盖信息的 reason 组织（不含原文）。"""
        return tuple(sorted(self.issue_counts, key=lambda c: (-self.issue_counts[c], c.value)))

    def as_public_dict(self) -> dict[str, Any]:
        """计数快照；键为原因码字符串，值均为整数。

        `issue_counts` 的键是 `IssueCode` 闭合枚举，**不接受来自会话数据的字符串**；调用方
        按 `reason_codes()` 顺序输出（次数降序、同次数按码名字典序），固定键名与值类型，
        供覆盖信息的 reason 拼装使用。
        """
        counts = self.issue_counts
        return {
            "lines_seen": self.lines_seen,
            "lines_with_records": self.lines_with_records,
            "records_emitted": self.records_emitted,
            "skipped_count": self.skipped_count,
            "partial": self.partial,
            "issue_counts": {issue.value: counts[issue] for issue in self.reason_codes()},
        }


def _from_epoch(value: float) -> tuple[datetime | None, TimeQuality]:
    """按量级把纪元数解释为秒/毫秒/微秒；越界或无穷值判为不可用，不做时区回填。

    有界处理：绝对值 ≥ `_EPOCH_MICROSECONDS_LIMIT`（1e17）直接 `invalid`，不进入除法与
    `fromtimestamp`；绝对值 < `_EPOCH_MIN_SECONDS`（1e9）时单位无法可靠确定（可能是亚秒值、
    时长、日期片段或极早秒值）→ `invalid`，**不猜单位也不回填 1970 年附近冒充事件时间**。
    可解释的三个量级仍靠 `_EPOCH_*_LIMIT` 判单位，超出转换范围的由异常兼容为 `invalid`。
    """
    magnitude = abs(value)
    if magnitude >= _EPOCH_MICROSECONDS_LIMIT:
        return None, TimeQuality.INVALID
    if magnitude < _EPOCH_MIN_SECONDS:
        return None, TimeQuality.INVALID
    if magnitude >= _EPOCH_MILLISECONDS_LIMIT:
        seconds = value / 1_000_000
    elif magnitude >= _EPOCH_SECONDS_LIMIT:
        seconds = value / 1_000
    else:
        seconds = value
    try:
        return datetime.fromtimestamp(seconds, tz=UTC), TimeQuality.EXACT
    except (OverflowError, OSError, ValueError):
        return None, TimeQuality.INVALID


def normalize_timestamp(value: object) -> tuple[datetime | None, TimeQuality]:
    """把源内时间字段归一化为带时区 datetime 或“不可用 + 原因”。

    支持：带时区/`Z` 的 ISO 8601 字符串（长度 ≤ `MAX_TIMESTAMP_STRING_CHARS`）；秒、毫秒、
    微秒纪元数（量级在 `[1e9, 1e17)` 内且单位可判）。
    明确不支持（返回质量而非猜测）：超长字符串、无时区字符串、日期-only 字符串、布尔、
    NaN/Inf、单位判不准的过小/过大数字、其它类型。**不使用文件 mtime 兜底**
    （SRS-SEARCH-05、AC-SEARCH-01），也不从泛化 `time` 字段猜事件时间（由调用侧约束）。
    """
    if value is None:
        return None, TimeQuality.MISSING
    if isinstance(value, bool):
        return None, TimeQuality.INVALID
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except (OverflowError, ValueError):
            return None, TimeQuality.INVALID
        if not math.isfinite(number):
            return None, TimeQuality.INVALID
        return _from_epoch(number)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, TimeQuality.MISSING
        if len(text) > MAX_TIMESTAMP_STRING_CHARS:
            # 不受控的长文本不交给日期解析器，也不参入后续处理。
            return None, TimeQuality.INVALID
        if text[-1] in ("Z", "z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None, TimeQuality.INVALID
        if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
            return None, TimeQuality.NO_TIMEZONE
        return parsed, TimeQuality.EXACT
    return None, TimeQuality.INVALID
