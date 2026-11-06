"""pi 会话 JSONL 逐行解析适配器（DES-ADAPTER-01「pi」行）。

服务的需求条目：SRS-SEARCH-01、SRS-SEARCH-05、SRS-SEARCH-06、SRS-SEARCH-09；
`location` 与时间约定见 DES-DATA-01、DES-API-01。

输入边界（本增量的硬约束）：

- 只解析**调用者提供的行流**（`Iterable[str | bytes]`，每元素一行）。`feed` 对**整个
  `str`/`bytes` 直接拒绝**（`TypeError`）：把它们当行流会逐字符/逐字节迭代，等于把不受控
  正文拆成海量假行。不发现目录、不枚举会话、**不打开文件**、不读取用户或项目配置、不校验
  路径是否在授权范围内。路径授权与「谁可以读哪一条行流」由 `policy.py` 与 `safe_reader.py`
  在调用方侧完成。
- 资源上限（固定值，语义见下方常量注释）：解析 JSON **前**先限单行大小
  （`MAX_LINE_BYTES` / `MAX_LINE_CHARS`），每行内容块数上限 `MAX_CONTENT_BLOCKS_PER_LINE`，
  单文本块长度上限 `MAX_TEXT_BLOCK_CHARS`，单条流扫描行数上限 `MAX_LINES_PER_STREAM`。
  超限行为：**该行停止**（单行过大→整行不解析）或**该流停止**（行数达上限→不再消费调用方
  行流），只记固定原因码 `line_too_large` / `content_block_limit_exceeded` /
  `text_block_truncated` / `max_stream_lines_exceeded` 并使 `partial` 为真；**不保存被丢弃的
  输入值**（不缓存原行、不把上限数值或类型名拼进计数）。
- `finish()` 后的实例进入终态：`feed_line` 与新 `feed` 抛 `RuntimeError`（固定消息，不携带
  任何数据侧文本），需要重新解析就新建实例；不存在「收尾后继续喂行」的中间状态。
- 来源固定为 `pi`：构造参数 `source` 只接受空值或 `pi`，其它非空值直接 `ValueError`，
  本适配器不伪称自己解析的是别的来源。
- `stream_label` 经 `models.sanitize_stream_label` 规范后写入 `SourceLocation.stream_label`：
  绝对路径、带分隔符/盘符/空白/非 ASCII 的不受控原文与超长标签**整体**降为固定
  `redacted-stream`，对外位置串不残留原值片段。它不充当路径授权凭据，适配器也不解释其含义。
  行号是**行流中的 1 起始序号**；若上游是压缩流，它是解压后的事件序号，不伪装成原始文件
  字节偏移。
- 适配器不写日志、不缓存原文。`StandardRecord.text` 承载消息正文（已按
  `MAX_TEXT_BLOCK_CHARS` 截断），返回调用方后由调用方按数据权限处理；`ParseStats` 只含
  **闭合类别（`IssueCode`）与整数计数**，不含正文、路径，也不含任何来自会话数据的字符串
  （事件类型、role、块类型名一律归入固定类别），因此可安全用于日志与对外覆盖信息；
  数据侧的类型文本不得成为计数键。

项目与时间的判据（不猜测）：

- 项目有**两条互不合并的证据通道**：
  - **来源侧**只取**结构可信头部**的 `cwd`：头部需版本可识别（字段存在且落在
    `SUPPORTED_HEADER_VERSIONS`）、cwd 可用、与会话标识断言不冲突、后续头部不再矛盾。
    未知/缺失版本、冲突头部、无效 cwd 均不得标 `trusted_header_cwd`：此时即便头部里有 cwd，
    记录的 `project` 仍不取该头部值、质量标 `unverified_header_cwd`，宁可少归类不可错归类。
    头部缺失或无 `cwd` 时若也没有外部断言，项目为 `None`、质量标 `unknown` 并计入
    `unknown_project`，**不依据有损目录编码还原项目**。
  - **外部断言**（构造参数 `project`）是一条 **cwd 断言**通道（值为工作目录，与头部 `cwd` 同一种
    值；**不是**策略里的项目名——项目名到归属根的映射属 `policy.py` 与协调层，本层拿到项目名也
    无法核对，只会让冲突判定比较两种语义不同的值）。断言独立保存在 `asserted_project` 通道，
    **永不**写回头部字段、也**不**充当头部 `cwd` 的替身：把项目名当 cwd 就是用未经来源证据支持的
    字符串冒充归属。可信头部存在时头部值优先，断言只用于**冲突核对**：
    两者字面不一致即**归属不唯一**，项目降为 `None`/`unknown`（计 `unknown_project`，已产出的
    记录逐条计 `project_unverified`），既不采信头部值也不采信断言值；两者字面一致时**产出的项目值
    不变、质量由 `caller_asserted` 升为 `trusted_header_cwd`**（值的出处由断言换成头部证据），这仍
    **不**据此谎称「两路独立证据已印证」——发布的项目值始终是头部 `cwd` 那一路。无可信头部时断言值
    以 `caller_asserted` 产出（值有来源、归属未确立），**不**在本层确立归属。
  两个通道的取值都**需由后续授权层（`policy.py`）验证**：本层只记录值的来源，不声明已授权，
  也不宣称它已与配置里的项目映射核对过。
- 会话标识有三份证据：调用方断言、可信头部、行内字段。任意两份不一致→ 计 mismatch 并
  拒绝该行记录（不把可疑正文混入本会话结果）；只由行内字段自报的标识**不算核实**，
  计 `session_id_unverified` 且记录标为未核实，不得把未核实的会话标成可信归属。
- 已输出但无可靠项目归属的记录计 `project_unverified`，**即使后续出现头部也使整流
  `partial` 为真**：事后补上的头部不能追溯早期记录的可信度。同理，头部出现带来的质量升级
  （`caller_asserted` → `trusted_header_cwd`）只作用于其后产出的记录：`StandardRecord` 是冻结
  对象，已产出记录的 `project`/`project_quality`/`issues` 保持产出时刻的状态，**不追溯改写**。
- 消息时间只取该条记录内的**显式时间字段**（外层或消息体内）：泛化的 `time` 键不收录，
  它的单位与语义（时刻/时长/秒数）无法可靠确定，拿它猜事件时间会直接污染时间过滤。
  缺失/无时区/不可解析分别计为
  `missing_timestamp` / `timestamp_no_timezone` / `timestamp_invalid`；**不用文件 mtime
  代替，也不借用会话头部时间冒充消息时间**。带时区与长度/量级有界要求由
  `normalize_timestamp` 强制（超长字符串与单位判不准的数字一律 `invalid`）。
- 损坏行、非对象行、未知事件、缺 role、被跳过的其它角色、未知块类型、非字符串正文、
  content 形状不可解释、无可信头部、头部冲突、版本缺失/不认识、时间缺失/无时区/不可解析、
  会话标识冲突或无法核实、无可靠项目归属的记录一律计入 `ParseStats`，使 `partial`
  为真；调用方不得把这类扫描表述为「完整且无匹配」（SRS-SEARCH-09）。只有空行、
  本身无文本且不丢弃任何块的消息（`no_text_content`）、以及已识别的非检索正文块
  （`known_non_text_block`）不使扫描降级。
- 当前任务边界只产出 `user` / `assistant` 的文本块：其它角色（system/tool/…）或未收录的
  块类型虽能识别但不输出，这本身就是覆盖不完整，必须显式标出（`skipped_role` /
  `unknown_block_type`），不得因「符合设计」而报为完整。

字段形状依据 `docs/spec/05-详细设计说明.md`「pi：识别嵌套 `message`、带文本块的 content
和其本身的 cwd/timestamp」，并对同义键名（`sessionId`/`session_id`、
`timestamp`/`createdAt`、`cwd`/`workingDirectory`）做容错；不读取任何真实会话核对字段全集。
`time` 不作为时间候选键（单位无法可靠确定即不猜），字段集与阈值的收敛待后续授权核对。

已知保守偏差（待授权核对真实字段后收敛）：

- 会话行流常见的非消息事件（模型切换、压缩、索引更新等）按 `unknown_event` 计数并令
  `partial` 为真；非 `user`/`assistant` 角色与未收录块类型同样计入不完整。因此健康会话
  也可能报告为不完整——这是有意偏差：宁可多报不完整，不可把未读懂的字节说成已覆盖。
- 资源上限同样使扫描计为 `partial`：上限换来的是内存/CPU 有界，代价是必须承认上限后的
  内容未看全（不得把“因预算停止”说成“完整且无匹配”）。
- 头部没有版本字段按「格式未知」处理（`missing_header_version`），其 cwd 因此不标可信。
  若真实格式证实无版本头是正常形态，可在后续增量收敛为警告。
- 计数只向调用方交代不完整的**类别与数量**（`reason_codes()`），不交代具体类型名。

本模块自身的边界（接线现状另见协调层）：

- 本适配器只产出记录：它的输出不表示调用方已获得该会话的读取授权，也不表示字段集已与
  真实会话核对。行流现在由 `session_pipeline.py` 在 `authorize_read`（存储轴）与逐记录
  `authorize_attribution`（归属轴）全部通过后才喂入；授权判定仍在策略层，不在本层。
- `executor` 恒为 `None`：pi 记录中的 provider/model 名不等于实际执行者，不据此推断。
- 本层只做**解析侧资源上限**（行大小/块数/块长/行数）；结果数截断、检索片段长度上限、
  凭据遮蔽与 `partial` → 对外 `coverage.status` 映射由 `query.py`/`publication.py`/
  `file_search.py` 承担，不在本层。
- 只处理调用方交给的行流本身，不解压 `.zstd` 多帧流（DSH 专用要求，另增量）。
- 真实 pi 存储的字段集兼容性未核对（本任务不读真实会话）；合成行流的解析与发布链已由
  `tests/test_file_search.py` 与 `tests/test_session_context.py` 驱动。
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from datetime import datetime
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

__all__ = [
    "KNOWN_NON_TEXT_BLOCKS",
    "KNOWN_NON_TEXT_ROLES",
    "KNOWN_NON_TEXT_EVENTS",
    "MAX_CONTENT_BLOCKS_PER_LINE",
    "MAX_HEADER_VERSION_CHARS",
    "MAX_LINE_BYTES",
    "MAX_LINE_CHARS",
    "MAX_LINES_PER_STREAM",
    "MAX_MATCH_KEY_CHARS",
    "MAX_PROJECT_VALUE_CHARS",
    "MAX_SESSION_ID_CHARS",
    "MAX_TEXT_BLOCK_CHARS",
    "PiHeaderInfo",
    "PiLineParser",
    "SOURCE_PI",
]

#: 标准记录里的来源标识，与 `server.REQUIRED_SOURCES` 中的 `pi` 一致。
SOURCE_PI = "pi"

# ---------- 不可信输入的固定资源上限（含截断语义） ----------

#: 字节行**解码前**的硬上限：1 048 576 字节（1 MiB）。超过即不分配解码结果，整行计
#: `line_too_large` 并丢弃；解码后再按 `MAX_LINE_CHARS` 二次判限（防 UTF-8 膨胀）。
MAX_LINE_BYTES = 1_048_576
#: 单行字符上限：262 144 字符（256 KiB）。超限的整行**不交给 `json.loads`**（JSON 递归下降
#: 是真实的栈/CPU 风险），计 `line_too_large`，该行不产出记录，原行内容不作任何保存。
MAX_LINE_CHARS = 262_144
#: 一行 `content` 最多查看前 32 个块：第 33 个及以后**一概不查看、不解析**，计
#: `content_block_limit_exceeded` 一次并标记该行有内容未取全（`partial` 为真）；
#: 已取的前 32 个块不受影响（不因截断丢弃已理解的内容）。
MAX_CONTENT_BLOCKS_PER_LINE = 32
#: 单个文本块正文只保留前 32 768 字符，其余直接丢弃；丢弃时计 `text_block_truncated`（每块
#: 一次）并写入该记录的 `issues`。**不追加省略标记**（那会伪造正文），事实只由固定原因码表达。
MAX_TEXT_BLOCK_CHARS = 32_768
#: 一个解析器实例（= 一条会话行流）最多读取 200 000 行。到达上限：计
#: `max_stream_lines_exceeded` 一次，`feed` 不再从调用方迭代器取下一行，后续 `feed_line`
#: 直接返回空元组（不再计 `lines_seen`）。上限后的行全部未读，因此扫描必为 `partial`。
MAX_LINES_PER_STREAM = 200_000
#: 项目值（头部 cwd 与调用方断言 project）可用长度上限：512 字符。超长项不能当项目值
#: （不截断使用：截断会造出一个不存在的项目名），按不可用处理，头部计 `invalid_header_cwd`，
#: 断言值降为「未提供」。
MAX_PROJECT_VALUE_CHARS = 512
#: 会话标识字段可用长度上限：256 字符；超限的标识不参与比对也不写入记录（按未提供处理）。
MAX_SESSION_ID_CHARS = 256
#: 参与固定集合比较的短字段（事件类型/role/块类型/来源）长度上限：64 字符。
#: 超过该长度的值不可能命中本文件任何固定集合，因此**直接按不可识别处理**，
#: 不为它分配 `lower()` 副本（避免每行一次最长 256 KiB 的无意义拷贝）。
MAX_MATCH_KEY_CHARS = 64
#: 头部版本字段长度上限：32 字符。超限的版本无法属于任何已知格式（不截断比较，截断后的
#: 前缀可能恰好命中另一个合法版本号），按不可识别处理计 `unsupported_header_version`。
MAX_HEADER_VERSION_CHARS = 32

#: 可产出检索正文的角色（DES-ADAPTER-01「pi」：user/assistant 文本块）。
#: 这是**当前任务边界**，不是「其余角色可安全忽略」：被跳过的角色均计入 `skipped_role`
#: 并使扫描报为不完整。
TEXT_ROLES: frozenset[str] = frozenset({"assistant", "user"})

#: 已知但不是检索正文的角色：计入固定类别 `skipped_role`（覆盖不完整），不单独上报角色名。
KNOWN_NON_TEXT_ROLES: frozenset[str] = frozenset({"developer", "function", "system", "tool", "toolresult"})

#: 已知但不是会话检索正文的事件类型（环境/模型配置/自定义非正文事件等）
KNOWN_NON_TEXT_EVENTS: frozenset[str] = frozenset(
    {
        "custom",
        "model_change",
        "context_edit",
        "thinking_level_change",
    }
)

#: 已知但不是检索正文的块类型（已小写比较）：计入 `known_non_text_block`（已理解的省略）。
KNOWN_NON_TEXT_BLOCKS: frozenset[str] = frozenset(
    {"audio", "image", "reasoning", "resource", "thinking", "toolcall", "tool_result", "tool_use"}
)

#: 会话头部事件类型（`type` 值）；只在这些行读取 cwd / 会话标识 / 版本。
HEADER_EVENT_TYPES: frozenset[str] = frozenset({"session", "session-info", "session_info"})

#: 消息事件类型；除此之外的 `type` 一律计为未知事件。
MESSAGE_EVENT_TYPES: frozenset[str] = frozenset({"message", "messages"})

#: 被视为文本块的 `type` 值。
TEXT_BLOCK_TYPES: frozenset[str] = frozenset({"input_text", "output_text", "text"})

#: 本适配器可解释的头部版本；缺失或其它版本按未知格式计为不完整，头部不予采信。
#: 取值未与真实会话核对（本轮禁止读取），宁可误报不完整也不默认放行未知版本。
SUPPORTED_HEADER_VERSIONS: frozenset[str] = frozenset({"1", "2", "3"})

#: 头部与会话标识的候选键（按优先级）。命名差异容错，但不猜语义。
#: 裸 `id` 只当头部事件的标识：消息行的 `id` 常是单条消息 ID，拿它当会话标识会
#: 在调用方已断言 session_id 时误判串台并丢记录，所以消息层不用该键。
_SESSION_ID_KEYS: tuple[str, ...] = ("sessionId", "session_id", "id")
_MESSAGE_SESSION_ID_KEYS: tuple[str, ...] = ("sessionId", "session_id")
#: 时间候选键（按优先级）：只收**显式表示时刻**的字段名。`time` 这类泛化键不收录：
#: 其单位与语义（时刻/时长/亚秒计数）无法可靠确定，猜成事件时间会污染时间过滤。
_TIMESTAMP_KEYS: tuple[str, ...] = ("timestamp", "createdAt", "created_at")
_CWD_KEYS: tuple[str, ...] = ("cwd", "workingDirectory", "working_directory")
_VERSION_KEYS: tuple[str, ...] = ("version", "v")
_TEXT_KEYS: tuple[str, ...] = ("text", "content")
_TYPE_KEYS: tuple[str, ...] = ("type",)

_FIELD_NOT_PRESENT = object()


def _first_present(mapping: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """返回第一个存在且非 None 的键值；都不存在或都为 None 时返回 None。"""
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            return value
    return None


def _has_field(mapping: dict[str, Any], keys: tuple[str, ...]) -> bool:
    """任一候选键是否存在（含值为 None 的情况）；用于区分「字段缺失」与「字段无效」。"""
    return any(key in mapping for key in keys)


def _as_text(value: Any, max_chars: int | None = None) -> str | None:
    """规范为非空字符串（保留原大小写）；非字符串或空白返回 None。

    `max_chars` 不为 None 时：**超长直接判不可用（返回 `None`）而不截断**，因为截断后的
    标识/项目名是个不存在的值，拿它去比对会话归属或归类项目比“不知道”更糟。
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
    """role/事件类型规范成小写比较键；非字符串、空白或超 `MAX_MATCH_KEY_CHARS` 返回 None。

    超限值归为 None 后走已有的 `unknown_role` / `unknown_event` / `unknown_block_type` 固定
    类别，不另造原因码；不把长文本拷进小写副本，也不把类型原名写进计数。
    """
    text = _as_text(value, MAX_MATCH_KEY_CHARS)
    return text.lower() if text is not None else None


def _is_oversized_text(value: Any) -> bool:
    """值是非空白字符串但超出 `MAX_MATCH_KEY_CHARS`（因此已归为 None）。

    用于区分「字段缺失」与「字段存在但不可能属于固定集合」：超长不能当成缺失，否则
    一个带垃圾 `type`/`role` 的行会被当成「无该字段」走进更宽松的识别分支。
    """
    return isinstance(value, str) and len(value.strip()) > MAX_MATCH_KEY_CHARS


def _int_version_text(value: int) -> str | None:
    """整数版本字段转短十进制串；量级超上限直接判不可识别。

    先按 `bit_length()` 拦住天文数字再 `str()`：Python 3.11+ 对超长整数的 int→str 会抛
    `ValueError`（默认 4300 位限制），而一条未超 `MAX_LINE_CHARS` 的 JSON 里完全可以放下几万位的
    整数字面量，不做量级判限就会把异常泄到调用方。每十进制位 ≤ 4 bit，故 4 倍保守。
    """
    if value.bit_length() > MAX_HEADER_VERSION_CHARS * 4:
        return None
    return str(value)


def _version_text(value: Any) -> str | None:
    """版本字段规范成字符串：接受 str 与整数（不含 bool），其它形状返回 None（不可识别）。

    字符串按 `MAX_HEADER_VERSION_CHARS` 判长：**超长不截断而是判不可识别**，因为截断后的
    前缀可能恰好命中另一个合法版本号，那比「不认识」更危险。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        return _as_text(value, MAX_HEADER_VERSION_CHARS)
    if isinstance(value, int):
        return _int_version_text(value)
    if isinstance(value, float) and value.is_integer():
        number = int(value)
        # float 能表示的整数量级远小于 1e32（≈ 2**107），但仍走同一判限，不在此处开例外。
        return _int_version_text(number)
    return None


def _bounded_text(value: str) -> tuple[str, bool]:
    """正文按 `MAX_TEXT_BLOCK_CHARS` 取前缀；返回 `(保留文本, 是否发生截断)`。

    截断只保留固定长度前缀，**不追加省略号/标记文本**（那会把源数据变成伪造正文），
    被削掉的部分不保留也不另存；截断事实由固定原因码 `text_block_truncated` 表达。
    """
    if len(value) <= MAX_TEXT_BLOCK_CHARS:
        return value, False
    return value[:MAX_TEXT_BLOCK_CHARS], True


@dataclass(frozen=True)
class PiHeaderInfo:
    """从会话头部得到的元数据；缺失字段为 `None`（未知），不回填默认值。

    `seen=False` 表示行流内尚未出现头部行，因此 `line_no` 等字段全为初始值。
    `trusted` 表示该头部**结构可采信**：版本字段存在且可识别、与会话标识断言不冲突、
    cwd 有效且与后续头部不矛盾。出现任一问题即降为 `False`，其 cwd 不得标
    `trusted_header_cwd`；不信任头部不等于否认头部存在（`seen` 仍为 `True`）。
    """

    session_id: str | None = None
    cwd: str | None = None
    version: str | None = None
    line_no: int | None = None
    seen: bool = False
    trusted: bool = False


class PiLineParser:
    """pi JSONL 行流解析器：逐行喂入，产出 0..n 条标准记录并累计质量计数。

    典型用法（调用方已自行完成授权、打开与解压等前置动作）::

        parser = PiLineParser(stream_label=controlled_label, session_id=expected_id)
        for record in parser.feed(lines):
            ...        # 时间/项目/关键词过滤由 `query.py` 在协调层完成
        parser.finish()
        parser.stats   # 计数与原因码，供覆盖状态使用；不含原文

    一次实例对应一条会话行流且至多消费 `MAX_LINES_PER_STREAM` 行：头部行只解析一次，其
    会话标识与 cwd 沿用给后续记录；头部不再可信（版本不认识、与别的头部矛盾）时，由它
    推导的项目与会话归属同步降级。行号在 `feed_line` 每次调用时自增（含损坏行与空行，但
    不含行数上限后的行），保证定位连续可追踪；计数器只累加**固定类别**（`IssueCode`），
    不保留事件类型、角色名等数据侧文本，也不推断未出现事件的语义。
    """

    def __init__(
        self,
        *,
        stream_label: str | None = None,
        session_id: str | None = None,
        project: str | None = None,
        source: str = SOURCE_PI,
    ) -> None:
        """`session_id` 为会话归属的校验断言，`project` 为上层显式给定的 **cwd 断言**。

        两者本层都**不验证**：适配器不检查它们与实际文件内容的关系，也不据此还原项目，
        更不声明它们已获授权——路径与项目映射的合法性由后续授权层（`policy.py`）判定。
        `project` 传的是工作目录（与头部 `cwd` 同类值），**不是策略里的项目名**：项目名到归属根
        的映射属 `policy.py` 与协调层，本层拿到项目名也无法核对，只会让冲突判定比较两种语义的值。
        它是一条**独立于头部证据的断言通道**：不会被写回头部字段，也不充当头部
        `cwd` 的替身。未给 `project` 时项目完全依赖结构可信头部的 `cwd`；给了但头部尚未出现时以
        `caller_asserted` 产出，头部给出可信 `cwd` 后头部值接管——同一值时产出的项目值不变、质量
        升为 `trusted_header_cwd`，且升级只及于其后记录的产出状态；不一致则归属不唯一、降为未知。

        两个入参都是有界处理对象：`project` 超 `MAX_PROJECT_VALUE_CHARS`、`session_id` 超
        `MAX_SESSION_ID_CHARS` 均按未提供处理（不截断使用）；`stream_label` 走
        `sanitize_stream_label`，不可信值整体降为 `redacted-stream`。`source` 不开放：
        记录来源固定为 `pi`，与参数不一致的非空值拒接。
        """
        self._stream_label = sanitize_stream_label(stream_label)
        self._asserted_project = _as_text(project, MAX_PROJECT_VALUE_CHARS)
        self._expected_session_id = _as_text(session_id, MAX_SESSION_ID_CHARS)
        # 来源固定：本适配器只产出 `pi` 的记录。传入其它非空值直接拒接（不静默忽略，
        # 也不让记录声称来自它没解析过的来源），会话数据更不可能影响该字段。
        normalized_source = _as_text(source, MAX_MATCH_KEY_CHARS)
        if normalized_source is not None and normalized_source != SOURCE_PI:
            raise ValueError("PiLineParser records always carry the fixed source 'pi'")
        self._source = SOURCE_PI
        self._stats = ParseStats()
        self._header = PiHeaderInfo()
        self._line_no = 0
        self._project = self._asserted_project
        self._project_quality = (
            ProjectQuality.CALLER_ASSERTED if self._asserted_project else ProjectQuality.UNKNOWN
        )
        # 头部 cwd 与外部断言字面不一致：归属不唯一，粘住到流结束（不回抢）。
        self._project_conflict = False
        # 头部与会话标识断言一旦冲突，整条流的归属都存疑，后续记录不再采信。
        self._session_id_conflict = False
        # 扫描行数达 `MAX_LINES_PER_STREAM`：该行起整条流停止（不再计数、不再解析）。
        self._line_limit_exceeded = False
        self._finished = False

    # ---------- 对外状态 ----------

    @property
    def stats(self) -> ParseStats:
        """本次解析的类别计数（可安全用于日志：不含原文、路径与数据侧字符串）。"""
        return self._stats

    @property
    def header(self) -> PiHeaderInfo:
        """已解析到的会话头部（未出现时 `seen=False`、字段全 `None`）。"""
        return self._header

    @property
    def session_id(self) -> str | None:
        """已核实的会话标识；未核实或存疑时为 `None`，不拿未核实的值充当可信归属。"""
        return self._verified_session_id()

    @property
    def project(self) -> str | None:
        """可归类的项目值：可信头部 `cwd` 优先，无可信头部时为外部断言值，冲突或全无为 `None`。

        任何情况下都不会把断言值回填成头部 `cwd`（也不反向回填），因此调用方仍能区分两路证据。
        """
        return self._project

    @property
    def asserted_project(self) -> str | None:
        """外部断言通道原值（仅长度判限后的形式）：与头部证据独立保存，不被头部覆写或抹除。"""
        return self._asserted_project

    @property
    def project_conflict(self) -> bool:
        """头部 `cwd` 与外部断言是否已字面冲突（归属不唯一）；粘性为真，不因后续头部而抹去。"""
        return self._project_conflict

    @property
    def project_quality(self) -> ProjectQuality:
        """项目归属质量；任何取值都不表示已获授权，只表示值的来源。"""
        return self._project_quality

    def finish(self) -> None:
        """收尾：登记与单行无关的流级问题（没出现头部行、项目无法确定）；幂等。

        头部行存在但不可信时不再计 `no_session_header`（版本/冲突问题已在头部行记下）。
        头部 cwd 与外部断言冲突时项目为 `None`，此处按同一判据计 `unknown_project`：
        不拿任一侧的值冒充已确定归属。
        """
        if self._finished:
            return
        self._finished = True
        if not self._header.seen:
            self._stats.note(IssueCode.NO_SESSION_HEADER)
        if not self._project_quality.sourced:
            # 无论因为缺头部、头部不可信还是头部无 cwd：项目无法确定都须向调用方交代。
            self._stats.note(IssueCode.UNKNOWN_PROJECT)

    # ---------- 行入口 ----------

    def feed(self, lines: Iterable[str | bytes]) -> Iterator[StandardRecord]:
        """按序消费行流，惰性产出标准记录（调用方中断即停止扫描）。

        入口校验在迭代前完成（非生成器体，报错不拖到首次 `next()`）：

        - 整个 `str`/`bytes` 当行流传入直接 `TypeError`：逐字符迭代会把一行射成海量假行，
          行号与内容都不可信，调用方必须自己切行。
        - `finish()` 后复用实例抛 `RuntimeError`（固定消息，不携带数据侧文本）。

        无论正常结束还是提前关闭（生成器 `close()`/回收），`finally` 都会调用
        `finish()`，避免调用方忘记收尾时漏掉缺头部、项目未知这类流级问题；行数上限
        达到后不再从调用方迭代器取下一行。
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

    def feed_line(self, line: str | bytes) -> tuple[StandardRecord, ...]:
        """解析一行，返回该行产出的记录（通常为 0..若干个文本块）。

        终态与上限：`finish()` 后调用抛 `RuntimeError`；已因行数上限停机则直接返回空元组
        （该行不计入 `lines_seen`、不解析、不保存）；单行超出 `MAX_LINE_BYTES` /
        `MAX_LINE_CHARS` 时整行不交给 `json.loads`，只计 `line_too_large`。
        """
        if self._finished:
            raise RuntimeError("parser is finished; create a new instance for a new stream")
        if self._line_limit_exceeded:
            return ()
        if self._line_no >= MAX_LINES_PER_STREAM:
            # 整条流停止：上限后的行一概未读，因此必须向调用方交代扫描不完整。
            self._line_limit_exceeded = True
            self._stats.note(IssueCode.MAX_STREAM_LINES_EXCEEDED)
            return ()
        self._line_no += 1
        self._stats.lines_seen += 1
        text = self._decode(line)
        if text is None:
            return ()
        stripped = text.lstrip("\ufeff").strip()
        if not stripped:
            self._stats.note(IssueCode.BLANK_LINE)
            return ()
        try:
            payload = json.loads(stripped)
        except (ValueError, RecursionError):
            self._stats.note(IssueCode.CORRUPT_LINE)
            return ()
        if not isinstance(payload, dict):
            self._stats.note(IssueCode.LINE_NOT_OBJECT)
            return ()
        return self._dispatch(payload)

    # ---------- 行内部分派 ----------

    def _dispatch(self, payload: dict[str, Any]) -> tuple[StandardRecord, ...]:
        raw_type = payload.get("type")
        if _is_oversized_text(raw_type):
            # 超长的 type 不可能命中任何固定事件类型，也不能当成「没有 type」去走宽识分支。
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return ()
        event_type = _as_role(raw_type)
        if event_type in HEADER_EVENT_TYPES:
            return self._handle_header(payload)
        if event_type in MESSAGE_EVENT_TYPES:
            return self._handle_message_line(payload)
        if event_type in KNOWN_NON_TEXT_EVENTS:
            self._stats.note(IssueCode.KNOWN_NON_TEXT_EVENT)
            return ()
        if event_type is None:
            # 无 type 字段：只在具备可信特征时接受，避免把任意 JSON 对象当消息。
            if isinstance(payload.get("message"), dict) or "role" in payload:
                return self._handle_message_line(payload)
            if not self._header.seen and _first_present(payload, _CWD_KEYS) is not None:
                return self._handle_header(payload)
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return ()
        self._stats.note(IssueCode.UNKNOWN_EVENT)
        return ()

    def _handle_header(self, payload: dict[str, Any]) -> tuple[StandardRecord, ...]:
        """解析会话头部（取 cwd、会话标识、版本）；头部本身不产出检索记录。

        只有**结构可采信**的头部才能给后续记录提供项目与会话归属：版本字段存在且
        可识别、cwd 可用、与会话标识断言不冲突。不采信时仍保留读到的字段（不假装
        什么都没看到），但项目降为不归类、质量降为 `unverified_header_cwd`。

        后续头部行不覆盖首个头部的结论：一律计 `late_session_header`；字段与首个头部
        矛盾时额外计冲突码并将头部降为不可信（已有记录不回改，但流级不完整已经记下）。
        """
        cwd_present = _has_field(payload, _CWD_KEYS)
        new_cwd = _as_text(_first_present(payload, _CWD_KEYS), MAX_PROJECT_VALUE_CHARS)
        version_present = _has_field(payload, _VERSION_KEYS)
        new_version = _version_text(_first_present(payload, _VERSION_KEYS))
        new_session = _as_text(_first_present(payload, _SESSION_ID_KEYS), MAX_SESSION_ID_CHARS)
        if not self._header.seen:
            trusted = True
            if not version_present:
                self._stats.note(IssueCode.MISSING_HEADER_VERSION)
                trusted = False
            elif new_version is None or new_version not in SUPPORTED_HEADER_VERSIONS:
                # 版本字段存在但不可识别/不认识：字段语义无法保证，不拿它的 cwd 当可信项目。
                self._stats.note(IssueCode.UNSUPPORTED_HEADER_VERSION)
                trusted = False
            if cwd_present and new_cwd is None:
                # 写了 cwd 但不可用（非字符串/空白/超 `MAX_PROJECT_VALUE_CHARS`）：按无效值处理，
                # 不当作可信项目，也**不截断后使用**（截断会造出不存在的项目名）。
                self._stats.note(IssueCode.INVALID_HEADER_CWD)
                trusted = False
            if (
                new_session is not None
                and self._expected_session_id is not None
                and new_session != self._expected_session_id
            ):
                # 头部与会话标识断言不符：整条流的归属存疑，不产出正文。
                self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
                self._session_id_conflict = True
                trusted = False
            self._header = PiHeaderInfo(
                session_id=new_session,
                cwd=new_cwd,
                version=new_version,
                line_no=self._line_no,
                seen=True,
                trusted=trusted,
            )
            self._adopt_header_project()
            return ()
        self._stats.note(IssueCode.LATE_SESSION_HEADER)
        conflict = False
        if new_cwd is not None and self._header.cwd is not None and new_cwd != self._header.cwd:
            self._stats.note(IssueCode.CONFLICTING_HEADER_CWD)
            conflict = True
        if new_version is not None and self._header.version is not None and (
            new_version != self._header.version
        ):
            self._stats.note(IssueCode.CONFLICTING_HEADER_VERSION)
            conflict = True
        if new_session is not None and self._header.session_id is not None and (
            new_session != self._header.session_id
        ):
            self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
            self._session_id_conflict = True
            conflict = True
        if conflict and self._header.trusted:
            self._header = replace(self._header, trusted=False)
            self._adopt_header_project()
        return ()

    def _adopt_header_project(self) -> None:
        """按当前头部的可信状态重算项目值与质量（外部断言与头部 `cwd` 两条通道不合并）。

        可信头部的 `cwd` 是**归属证据**，因此它优先产出 `TRUSTED_HEADER_CWD`：不再被 `CALLER_ASSERTED`
        永久盖住。断言只作为**冲突核对**与无可信头部时的已声明值：

        - 可信头部 cwd 与断言字面不一致→ 归属不唯一：两个值**都不采信**（不拿头部值掩盖断言，
          也不拿断言值掩盖头部），项目降为 `None`/`unknown` 并粘性记下冲突。
        - 可信头部 cwd 与断言字面一致→ 项目值就是那个 cwd（取值不变），质量由 `CALLER_ASSERTED`
          升为 `TRUSTED_HEADER_CWD`：出处从「调用方说」变成「头部证据说」。升级只影响其后产出的
          记录，已产出的记录不回改（冻结 dataclass，产出时刻的状态即最终状态）。
        - 无可信头部 cwd（无头部/头部不可信/头部无可用 cwd）而只有断言→ 仍只给 `CALLER_ASSERTED`：
          值有来源，但归属不在本层确立（留给协调层与授权层）。
        - 只有不可信头部 cwd、无断言→ 仍不采信，`unverified_header_cwd`，不猜测。
        """
        if self._project_conflict:
            self._project = None
            self._project_quality = ProjectQuality.UNKNOWN
            return
        if self._header.trusted and self._header.cwd is not None:
            if self._asserted_project is not None and self._asserted_project != self._header.cwd:
                # 字面不一致即歧义：本层无权裁决哪个是真的，也不拿其中一个冒充已核对的归属。
                self._project_conflict = True
                self._project = None
                self._project_quality = ProjectQuality.UNKNOWN
                return
            self._project = self._header.cwd
            self._project_quality = ProjectQuality.TRUSTED_HEADER_CWD
            return
        if self._asserted_project is not None:
            self._project = self._asserted_project
            self._project_quality = ProjectQuality.CALLER_ASSERTED
            return
        # 无头部、头部不可信或头部没有可用 cwd：都不得称可信项目，也不猜测。
        self._project = None
        self._project_quality = (
            ProjectQuality.UNVERIFIED_HEADER_CWD
            if self._header.cwd is not None
            else ProjectQuality.UNKNOWN
        )

    def _handle_message_line(self, payload: dict[str, Any]) -> tuple[StandardRecord, ...]:
        envelope = payload.get("message")
        if isinstance(envelope, dict):
            return self._handle_message(payload, envelope)
        # 部分写出方把 role/content 平铺在本行；仅当具备 role 时接受，否则算缺消息体。
        if "role" in payload:
            return self._handle_message(payload, payload)
        self._stats.note(IssueCode.MISSING_MESSAGE_ENVELOPE)
        return ()

    def _handle_message(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> tuple[StandardRecord, ...]:
        """处理一条消息：先定会话归属与角色，再取时间与正文块。

        归属存疑（头部与断言冲突、行内标识与两者不符）的记录直接丢弃不产出正文，
        避免将未核实的会话内容混入本会话结果。
        """
        session_id, verified, rejected = self._resolve_session_id(outer, envelope)
        if rejected:
            return ()
        record_issues: list[IssueCode] = []
        if session_id is None:
            # 三份证据全部缺失：归属未知，不得当作可信会话输出。
            self._stats.note(IssueCode.MISSING_SESSION_ID)
            record_issues.append(IssueCode.MISSING_SESSION_ID)
        elif not verified:
            # 只有一份证据（常为行内自报）：记录仍可用，但不得标为已核实的会话归属。
            self._stats.note(IssueCode.SESSION_ID_UNVERIFIED)
            record_issues.append(IssueCode.SESSION_ID_UNVERIFIED)

        role_value = envelope.get("role", outer.get("role"))
        role = _as_role(role_value)
        if role is None:
            # 超长的 role 不是「缺 role」：按不可识别角色计数，不规归为缺失。
            self._stats.note(
                IssueCode.UNKNOWN_ROLE if _is_oversized_text(role_value) else IssueCode.MISSING_ROLE
            )
            return ()
        if role not in TEXT_ROLES:
            # 非检索角色：不猜其内容是否可检索，也不报为格式错误；但角色名不进入计数，
            # 只计固定类别，并使覆盖报为不完整（当前任务边界仅 user/assistant）。
            if role in KNOWN_NON_TEXT_ROLES:
                self._stats.note(IssueCode.SKIPPED_ROLE)
            else:
                self._stats.note(IssueCode.UNKNOWN_ROLE)
            return ()

        timestamp, time_quality = self._resolve_timestamp(outer, envelope)
        if time_quality is not TimeQuality.EXACT:
            self._stats.note(TIMESTAMP_ISSUES[time_quality])
            record_issues.append(TIMESTAMP_ISSUES[time_quality])

        blocks, lost_content, limit_issues = self._content_blocks(envelope)
        # 行级截断事实（块数上限/单块超长）已写入计数，同步标到本行产出的每条记录上，
        # 使调用方能从记录本身看出“这条正文来自被截断的行”。
        record_issues.extend(limit_issues)
        if blocks is None:
            # 形状不可解释：真实的信息损失，使扫描不完整。
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            return ()
        if not blocks:
            if not lost_content:
                # 本身就没有任何文本块（如 `content: []`）：已理解的结构，不降级。
                self._stats.note(IssueCode.NO_TEXT_CONTENT)
            return ()

        if not self._project_quality.sourced:
            # 已输出但无可靠项目归属：当场计入，后续出现头部也不能挣销（记录不回改）。
            self._stats.note(IssueCode.PROJECT_UNVERIFIED)
            record_issues.append(IssueCode.PROJECT_UNVERIFIED)

        issues = tuple(record_issues)
        records = tuple(
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
        )
        self._stats.records_emitted += len(records)
        self._stats.lines_with_records += 1
        return records

    # ---------- 字段解析辅助 ----------

    def _decode(self, line: str | bytes) -> str | None:
        """先按固定上限判行大小，再按 UTF-8 解码；超限/解码失败均不保留原值。

        - 字节行：解码前先判 `MAX_LINE_BYTES`（避免为超限行分配解码结果），解码后再判
          `MAX_LINE_CHARS`（UTF-8 多字节展开后的二次上限）；字符串行直接判 `MAX_LINE_CHARS`。
          超限计 `line_too_large` 并整行丢弃（**不截断后解析**：半截 JSON 会被当成损坏行，
          截断后的正文会被当成真正文）。
        - 非 `str`/`bytes` 元素与解码失败：计 `corrupt_line`，不做有损替换以免伪造正文。
        """
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

        三份证据：调用方断言、首个可信头部、行内字段。任意两份不一致→ 计
        `session_id_mismatch` 并拒行（可疑正文不得混入本会话结果）；只有一份证据
        时可以使用但**不算已核实**，由调用方计 `session_id_unverified`。
        """
        inline = self._inline_session_id(outer, envelope)
        if self._session_id_conflict:
            # 头部与断言已经对不上：后续记录的归属全部存疑，不再产出正文。
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        header_id = self._header.session_id if self._header.trusted else None
        candidates = [v for v in (self._expected_session_id, header_id, inline) if v is not None]
        if len(set(candidates)) > 1:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        if not candidates:
            return None, False, False
        # 两个独立来源（如头部 + 行内，或断言 + 头部）指向同一值才算交叉印证。
        return candidates[0], len(candidates) >= 2, False

    def _inline_session_id(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> str | None:
        """行内会话标识：先看外层再看消息体；消息层不用裸 `id`（常为单条消息 ID）。

        两处均按 `MAX_SESSION_ID_CHARS` 判长，超限的自报标识**不参与归属比对也不写入记录**，
        避免一个超长不受控字符串成为归属证据或流入对外字段。
        """
        inline = _as_text(_first_present(outer, _MESSAGE_SESSION_ID_KEYS), MAX_SESSION_ID_CHARS)
        if inline is None:
            inline = _as_text(
                _first_present(envelope, _MESSAGE_SESSION_ID_KEYS), MAX_SESSION_ID_CHARS
            )
        return inline

    def _verified_session_id(self) -> str | None:
        """可核实的会话标识：需两个独立来源一致；否则 `None`（不当可信归属用）。"""
        if self._session_id_conflict:
            return None
        header_id = self._header.session_id if self._header.trusted else None
        expected = self._expected_session_id
        if header_id is not None and expected is not None:
            return header_id if header_id == expected else None
        return None

    def _resolve_timestamp(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> tuple[datetime | None, TimeQuality]:
        """只取本条记录内的**显式时间字段**；不回落到头部时间，也不取文件 mtime。

        候选键不含泛化的 `time`：单位与语义无法可靠确定时不猜事件时间（长度/量级有界
        由 `normalize_timestamp` 保证，判不准一律 `invalid`）。
        """
        for holder in (envelope, outer):
            candidate = _first_present(holder, _TIMESTAMP_KEYS)
            if candidate is not None:
                return normalize_timestamp(candidate)
        return None, TimeQuality.MISSING

    def _content_blocks(
        self, envelope: dict[str, Any]
    ) -> tuple[tuple[str, ...] | None, bool, tuple[IssueCode, ...]]:
        """提取消息内的文本块（有界）。

        返回 `(块元组, 是否有内容因不可解释而未产出, 本行命中的上限原因码)`：

        - 块元组为 `None` 表示 content 整体形状不可解释。
        - 接受字符串 content、块列表与单个块对象；列表中的裸字符串按文本块处理。
        - 块数上限：只看前 `MAX_CONTENT_BLOCKS_PER_LINE` 个，**第 33 个及以后不查看不解析**，
          行计一次 `content_block_limit_exceeded`（不保存未看过的块）。
        - 单块长度上限：正文只保留前 `MAX_TEXT_BLOCK_CHARS` 个字符，每块计一次
          `text_block_truncated`，**不追加省略标记也不保存被削掉的部分**。
        - 本方法只计**固定类别**，不把数据侧的 type 文本写进计数（类型名会进入可公开/可日志
          的计数结构）。
        """
        content = envelope.get("content", _FIELD_NOT_PRESENT)
        if content is _FIELD_NOT_PRESENT:
            content = envelope.get("text", _FIELD_NOT_PRESENT)
        if content is _FIELD_NOT_PRESENT or content is None:
            return None, True, ()
        if isinstance(content, str):
            issues: list[IssueCode] = []
            if not content.strip():
                # 与块分支一致：先用 strip 判空，空白正文不产出记录也不计截断。
                return (), False, ()
            texts, truncated = _bounded_text(content)
            if truncated:
                self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
            return (texts,), False, tuple(issues)
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
        line_issues: list[IssueCode] = []
        lost = bool(dropped_blocks)
        if dropped_blocks:
            # 计数只记“发生了截断”一次，不记块数、类型名或原值。
            self._stats.note(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
            line_issues.append(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
        for item in candidates:
            if isinstance(item, str):
                if not item.strip():
                    continue
                bounded, truncated = _bounded_text(item)
                if truncated:
                    self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                    line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
                texts_out.append(bounded)
                continue
            if not isinstance(item, dict):
                # 块不是对象（数字/嵌套列表等）：形状不可解释，内容未能产出。
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
                lost = True
                continue
            raw_block_type = _first_present(item, _TYPE_KEYS)
            block_type = _as_role(raw_block_type)
            if block_type is None and _is_oversized_text(raw_block_type):
                # 超长 type 不回落成「无 type 则当作文本块」：那会把未知块的 body 拉进正文。
                self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
                lost = True
                continue
            if block_type is not None and block_type not in TEXT_BLOCK_TYPES:
                # 不猜块内是否有可检索文本：未收录的类型一律按格式演进计入不完整，
                # 已收录的非正文块计为「已理解的省略」（不使扫描降级）。
                if block_type in KNOWN_NON_TEXT_BLOCKS:
                    self._stats.note(IssueCode.KNOWN_NON_TEXT_BLOCK)
                else:
                    self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
                    lost = True
                continue
            body = _first_present(item, _TEXT_KEYS)
            if isinstance(body, str):
                if not body.strip():
                    # 空白正文：块已理解且本身不含文本，归外层 `no_text_content` 表达。
                    continue
                bounded, truncated = _bounded_text(body)
                if truncated:
                    self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                    line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
                # 保留前缀逐字不动（不削掉原文内部空白），仅用 strip 判空。
                texts_out.append(bounded)
                continue
            if body is None and not _has_field(item, _TEXT_KEYS):
                # 块里没有 text/content 字段：无法判断其形状与可检索性。
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            else:
                # 字段存在但形状不是字符串（列表/对象/数字/布尔/显式 null）：不猜其语义。
                self._stats.note(IssueCode.NON_STRING_TEXT_BLOCK)
            lost = True
        return tuple(texts_out), lost, tuple(line_issues)

