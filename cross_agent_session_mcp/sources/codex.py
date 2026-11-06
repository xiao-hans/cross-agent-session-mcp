"""Codex rollout JSONL 行流解析适配器（DES-ADAPTER-01「Codex」行）。

只解析**调用方提供的行流**（`Iterable[str | bytes]`，每元素一行）：不发现目录、不打开文件、
不读配置、不做授权（属 `policy.py`）、不接 `server.py`、不写日志。标准记录与质量枚举
来自 `models.py`（本轮时间语义未核实，因此**不调用其 `normalize_timestamp`**，只用自己的
缺失/不可用判定）；有界约束与 `sources/pi.py` 同口径但**不从 pi 导入**（DES-ARCH-02：来源之间不相互
依赖），本模块自带私有辅助与常量副本。

格式依据只有 `05` 的 Codex 行（识别 `session_meta` 中 cwd/originator 与消息 `payload`，处理
文本块并跳过提示词和工具数据；仅在元数据能确认时标注桌面或 CLI）与本轮用户指令（`session_meta`
的 id/cwd/originator、`response_item` 中 message/payload 文本块）。本轮禁止读取真实 rollout，
因此**只实现这两类行**，其余一律计为未理解并按不完整上报，见下方「未确认边界」。

这两条依据只是「哪些键名可能出现在哪里」，**不是格式契约**：字段层级、取值集合、时间语义、
版本含义、originator 取值都没有与真实 rollout 核对过，公开上游检索又被网络工具阻断，无法用
搜索标题补造格式。证据不足的后果是**收回可信资格**，不是补一套猜测：本轮任何 `session_meta`
都不得被采信（`CodexHeaderInfo.trusted` 恒为 `False`），因此既不产 `trusted_header_cwd`，也不产
「已核实的会话身份」；整流必须带固定原因码并被判为 `partial`，本层的输出**不可用于发布**，
只用于后续与真实格式核对。同样地，头部里存在版本类字段**不等于格式已识别**：没有已核实的
取值集合，本层不建白名单，只登记「格式标识不可核实」这一事实。

产出边界：只产 `user`/`assistant` 的可检索正文，且正文只来自 `response_item` 的
`payload.type == "message"`、`payload.role` 为非空字符串 `user`/`assistant`、`payload.content` 为
**数组**且每个块是声明了文本 `type` 与 `str` `text` 的对象。裸字符串 content、单个 dict content、
块内 `content` 别名、无 `type` 的块、行级 `role` 回落都不当正文（系统/开发者提示按角色跳过，计
`skipped_role`，仍属覆盖不完整）；工具参数与输出、推理文本不产正文。角色缺失或不可识别保守拒绝。
`executor` 恒为 `None`：originator 的取值集合无法从项目内证据确认，因此 05 要求的「桌面/CLI
标注」本轮**未实现**，原值只保存在 `header.originator` 供后续核对，不写进记录、不据模型名推断。

质量判据（只用现有固定枚举与原因码，不猜测；时间判据与 pi **不同**，见下方条目）：

- 会话标识只取 `session_meta` 的 id；消息行内的标识字段未经确认，本层不取，也不用裸 `id`
  （常是单条消息 ID）。头部本轮不可采信，所以**没有任何记录会被标成已核实身份**：只有断言一份
  证据时计 `session_id_unverified`。调用方断言与头部 id 不一致 → 整条流归属存疑，后续记录一律
  拒产正文。
- 项目有两条互不合并的通道：头部 `cwd`（结构可采信时）与构造参数 `project`（外部 **cwd 断言**，
  不是策略项目名）。断言永不写回头部字段、也不充当缺失 cwd 的替身；两份证据字面不一致 →
  归属不唯一，降为 `None`/`unknown`（粘性，且逐条已产出记录计 `project_unverified`、流级计
  `unknown_project`，这不是静默回落）；哪些头部参与该核对由下方「首发与迟到共用同一判据」条目
  定义，不只在首个头部。头部不可采信时断言值只以 `caller_asserted` 产出，本层不确立归属；
  `TRUSTED_HEADER_CWD` 分支保留给格式契约核实之后的复核，本轮不可达。
- 头部字段在**行级与其 `payload` 两处**都可能声明（层级未经确认，故两处都查）：同一字段在两处
  给出不同的可用值，或某处声明了该字段却给不出可用值（非字符串、空白、超长），一律**不采用
  「先到先得」的静默回落**——值取 `None` 并按固定已有码登记（cwd 矛盾 `conflicting_header_cwd`、
  cwd 不可用 `invalid_header_cwd`、id 矛盾 `header_session_id_mismatch`、id/originator 声明了却
  不可用 `invalid_content_shape`），**并置与跨头部核对同一套粘性失败状态**：cwd 矛盾或不可用
  → `_project_conflict`（项目降为 `None`/`unknown`），id 矛盾或不可用 → `_session_id_conflict`
  （其后记录一律拒产正文）。两个入口共用同一套失败状态：同行那条若只记码，归属仍会沿未经
  否证的断言通道输出。
- 头部证据核对**首发与迟到共用同一判据**（`_reconcile_header_evidence`）：每次读出的**可用** id
  都与外部会话标识断言、与首个头部 id **分别**比对，任一不一致 → 置 `_session_id_conflict` 粘性并
  记 `header_session_id_mismatch`（其后记录一律拒产正文）；每次读出的可用 cwd 都与外部 cwd 断言、
  与首个头部 cwd **分别**比对，任一不一致 → 置 `_project_conflict` 粘性并记
  `conflicting_header_cwd`（项目降为 `None`/`unknown`）。核对**不因首个头部缺该字段、也不因头部
  恒不可采信而跳过**：迟到头部给出的值同样能否证断言通道。同行两处层级互斥时该字段值取 `None`，
  没有可断言的头部值，本核对不参与，但失败状态不缺：那条路径既记矛盾/不可用码，也置同一个
  `_project_conflict`/`_session_id_conflict`（两个入口共用一套失败语义）。
- 已产出的记录不因后续头部而回改：早期无可靠归属的记录当场计 `project_unverified`。
- 时间：`timestamp`/`createdAt`/`created_at` 的层级、语义（消息时刻还是写入时刻）、单位与时区写法
  **全部未经核实**，因此任何候选来源都不发布时刻，本层也不解析其值：消息层与行级都没有给出候选
  值 → `None` + `missing`（计 `missing_timestamp`，确实缺失）；任一处给出了候选值（含显式 `null`）
  → `None` + `invalid`（计 `timestamp_invalid`，字段存在但语义未知）。**不用 `no_timezone` 档**：
  它宣称「已确认这是时间、只缺时区」，本层没有这个证据，拿它当降级就是伪装证据。既然没有 `EXACT`，
  本层记录一律不可参与时间过滤（查询层只让 `EXACT` 参与比较）。**不用文件 mtime、不用目录名
  （`sessions/YYYY/MM/DD`）猜时间**；消息层与行级给出不同值时结论同为 `invalid`，未核实的来源之间
  没有谁优先，矛盾只是「更不该发布」的旁证。
- `location` 为**解码后行号**（1 起始）与同行内序号 `ordinal`，不伪装成原始字节偏移。
- 资源硬限与 pi 同值（单行字节/字符、单消息块数、单块长度、单流行数、元数据长度）：超限只计
  固定原因码、不保存被丢弃的输入值，且一律使 `partial` 为真；长度超限的标识/项目值按未提供处理，
  **不截断使用**。超长的版本/格式标识同样不静默丢弃：按固定已有码 `unsupported_header_version`
  登记（超长值不可能属于任何已知格式，与「字段不存在」不是一回事，不能计成 `missing_*`）。
- 计数只用 `IssueCode` 闭合类别与整数（DES-SEC-01）：事件类型、role、块类型名、路径、正文
  一律不进入计数。

未确认边界（本轮无法证实，故不声称支持；均按不完整上报）：

- rollout 是否有版本字段、其取值集合为何，均未经确认：本层**不建版本白名单**，也**不把版本字段
  的存在当作格式已识别**。版本类字段（`version`/`v`）只用来选择登记哪个固定已有码：声明了但无法
  与任何已核实契约比对 → `unsupported_header_version`；完全没声明 → `missing_header_version`。
  两种情况头部都不可采信，区别只是向调用方说明「证据缺在哪」。
- 头部可信度本轮**不由 payload 形状、cwd 可用性与 id 一致性挣得**：那些判据只能说明「这份头部
  自洽」，不能说明「这确实是 Codex 的格式」。因此本轮 `trusted` 恒为 `False`，`_handle_header`
  里保留的可采信判据只在格式契约被核实之后才起作用。可信度为假**不免除独立证据核对**：
  `_reconcile_header_evidence` 对首发与迟到头部同一条路径运行，矛盾照常记固定码并粘性生效。
- 工具/推理事件的具体 payload 名称未经确认：本层不把它们标为「已理解的省略」
  （不使用 `known_non_text_block`），凡非 `message` 的 `response_item` 与消息内非文本块一律计
  `unknown_block_type`。代价是健康会话也会报为不完整——宁可多报，不假装已读懂。
- 除 `session_meta`/`response_item` 外的行类型（含无 `type` 的行、其它事件如压缩/中止/用量）
  一律计 `unknown_event`，不套用 pi 的无 type 宽识分支（那会把读不懂的行冒充成消息）。
- 头部字段究竟挂在行级还是其 `payload` 内未经确认：两处都查（先行级），两种形状均未核对。
- 时间候选键（含消息层的 `timestamp`/`createdAt`）是否表示消息时刻、单位与时区写法如何，均未经
  确认：本层因此**不解析也不发布**任何时刻，只在「确实缺失」与「存在但语义未知」之间二选一
  （见「质量判据」）。`timestamp_no_timezone` 这条码在本轮不可达，它属于格式核实之后的判定。
- 头部 originator 之间冲突（两处层级矛盾、或多个头部互不一致）无法用现有原因码表达（不扩大
  枚举）：本轮头部本就不可采信，所以冲突的后果是通过 `project_unverified`/`unknown_project`
  如实上报，同时由 `originator_conflict` 属性向调用方明示原因。originator 的取值集合与大小写规则
  均未经确认，因此比较按剥空白后的原值精确进行：任何不一致（包括仅大小写不同）都判为冲突，
  方向是少归类而不是放行。

调用方验收口径（本轮硬约束，不可提前挣免）：本层是**逐行惰性**产出，早期 yield 只反映流的前缀，
**不构成可验收的结论**。要判定一条会话行流，调用方必须：把整条流喂到耗尽（或明确记录被中断）→
调用/等待 `finish()` → 读**最终的** `stats.partial` 与 `reason_codes()` → 再做整流会话身份核对与
项目归属核对。本轮因头部一律不可采信，带头部的流必带 `missing_header_version` 或
`unsupported_header_version`，不带头部的流必带 `no_session_header`；每条产出的记录又必带
`timestamp_invalid` 或 `missing_timestamp`，因此 `partial` 恒为真且没有任何记录可按时间过滤；
因此**不存在「这条 Codex 会话验收通过」的中间态**，
只有等格式契约核实后才可能进入发布判断（还要叠加 05 的发布边界：存储授权 + 归属核对 + 整流身份
核对 + 脱敏，任一项不成立即丢弃并标不完整）。

本增量未实现：未接入协议层与查询层、未做来源绑定与授权核对、未做片段截断与凭据遮蔽、
未解压任何压缩流、未执行任何代码与测试；未核实任何 Codex 格式契约。输出不表示该会话已获读取
授权，也不表示其格式已被识别。"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
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
    sanitize_stream_label,
)

__all__ = [
    "CODEX_MESSAGE_TYPE",
    "HEADER_EVENT_TYPES",
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
    "MESSAGE_EVENT_TYPES",
    "SOURCE_CODEX",
    "TEXT_BLOCK_TYPES",
    "TEXT_ROLES",
    "CodexHeaderInfo",
    "CodexRolloutLineParser",
]

#: 标准记录里的来源标识，与 `server.REQUIRED_SOURCES` 中的 `codex` 一致。
SOURCE_CODEX = "codex"

# ---------- 不可信输入的固定资源上限（与 sources/pi.py 同值，语义相同） ----------

MAX_LINE_BYTES = 1_048_576
MAX_LINE_CHARS = 262_144
MAX_CONTENT_BLOCKS_PER_LINE = 32
MAX_TEXT_BLOCK_CHARS = 32_768
MAX_LINES_PER_STREAM = 200_000
MAX_PROJECT_VALUE_CHARS = 512
MAX_SESSION_ID_CHARS = 256
#: 头部版本/格式标识字段的长度上限（与 pi 同值）。超限值不可能属于任何已核实格式，按不可识别
#: 处理并计 `unsupported_header_version`；**不截断比较**（截断后的前缀可能恰好命中另一个版本号）。
MAX_HEADER_VERSION_CHARS = 32
#: 参与固定集合比较的短字段（行类型/payload 类型/role/块类型/originator）长度上限。
#: 超限值不可能命中本文件任何固定集合，直接按不可识别处理，不为它分配小写副本。
MAX_MATCH_KEY_CHARS = 64

#: 可产出检索正文的角色（05/本轮指令：仅用户与助手）。
TEXT_ROLES: frozenset[str] = frozenset({"assistant", "user"})

#: 已知但不是检索正文的角色（系统/开发者提示按 05 要求跳过，仍计覆盖不完整）。
KNOWN_NON_TEXT_ROLES: frozenset[str] = frozenset({"developer", "function", "system", "tool"})

#: 视为文本块的 `type` 值（沿用 `sources/pi.py` 已在项目内确立的同一名集）。
TEXT_BLOCK_TYPES: frozenset[str] = frozenset({"input_text", "output_text", "text"})

#: 会话头部行类型（05 确认的唯一头部形态）。
HEADER_EVENT_TYPES: frozenset[str] = frozenset({"session_meta"})

#: 可能携带消息正文的行类型（05/本轮指令确认的唯一正文通道；`event_msg` 等未收录）。
MESSAGE_EVENT_TYPES: frozenset[str] = frozenset({"response_item"})

#: `response_item` 的 payload 类型中唯一被确认为消息取值的取值。
CODEX_MESSAGE_TYPE = "message"

_SESSION_ID_KEYS: tuple[str, ...] = ("sessionId", "session_id", "id")
#: 时间候选键。**本轮不解析、不发布这些键的值**：它们在消息层与行级的层级、语义（消息时刻还是
#: 写入时刻）、单位与时区写法都未与真实 rollout 核对，因此只用来区分「确实缺失」与「字段存在但
#: 语义未知」（见「质量判据」与 `_resolve_timestamp`）。
_TIMESTAMP_KEYS: tuple[str, ...] = ("timestamp", "createdAt", "created_at")
_CWD_KEYS: tuple[str, ...] = ("cwd", "workingDirectory", "working_directory")
_ORIGINATOR_KEYS: tuple[str, ...] = ("originator",)
#: 头部格式/版本标识的候选键。**只用于判断「头部有没有给出可核实的格式标识」并选择登记哪个
#: 固定已有码**，不作放行名单：真实取值集合未经确认，字段存在也不等于格式已被识别。
_VERSION_KEYS: tuple[str, ...] = ("version", "v")
_ROLE_KEYS: tuple[str, ...] = ("role",)
#: 块正文只认显式 `text` 键；`content` 作为块内正文字段是未确认的别名，不取（外层唯一确认过的
#: 数组字段是 `response_item.payload.content`）。
_TEXT_KEYS: tuple[str, ...] = ("text",)
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
    """任一候选键是否存在（含值为 None）；用于区分「字段缺失」与「字段无效」。"""
    return any(key in mapping for key in keys)


def _as_text(value: Any, max_chars: int | None = None) -> str | None:
    """规范为非空字符串（保留原大小写）；非字符串、空白或超长返回 None。

    超长**判不可用而不截断**：截断后的标识/项目名是个不存在的值，拿它比对归属比不知道更糟。
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
    """行类型/role/块类型规范成小写比较键；非字符串、空白或超长返回 None。"""
    text = _as_text(value, MAX_MATCH_KEY_CHARS)
    return text.lower() if text is not None else None


def _is_oversized_text(value: Any) -> bool:
    """值是非空白字符串但超出 `MAX_MATCH_KEY_CHARS`（因此已归为 None）。

    用于区分「字段缺失」与「字段存在但不可能属于固定集合」：超长不能当成缺失，否则一个带
    垃圾 `type`/`role` 的行会走进更宽松的识别分支。
    """
    return isinstance(value, str) and len(value.strip()) > MAX_MATCH_KEY_CHARS


def _bounded_text(value: str) -> tuple[str, bool]:
    """正文按 `MAX_TEXT_BLOCK_CHARS` 取前缀；返回 `(保留文本, 是否截断)`。

    不追加省略标记（那会伪造正文），被削掉的部分不保留；事实由固定原因码表达。
    """
    if len(value) <= MAX_TEXT_BLOCK_CHARS:
        return value, False
    return value[:MAX_TEXT_BLOCK_CHARS], True


@dataclass(frozen=True)
class CodexHeaderInfo:
    """从 `session_meta` 得到的会话元数据；缺失字段为 `None`（未知），不回填默认值。

    `seen=False` 表示行流内尚未出现头部行。`trusted` 表示该头部**结构可采信**：格式契约已核实、
    payload 形状可解释、cwd 可用（若存在）、与会话标识断言及首个头部不矛盾。不采信不等于否认头部
    存在（`seen` 仍为 `True`）。

    **本轮 `trusted` 恒为 `False`**：结构自洽不等于格式已识别，而 Codex 的格式契约本轮没有任何
    已核实证据（见模块文档「未确认边界」）。因此头部既不授予 `trusted_header_cwd`，也不授予
    已核实的会话身份。**可信度为假不免除证据核对**：`_handle_header` 对首发与迟到头部一律调用
    `_reconcile_header_evidence`，可用 id/cwd 仍与外部断言、与首个头部值分别比对，矛盾照常登记固定
    码并粘性生效，供格式契约核实时的复核。
    """

    session_id: str | None = None
    cwd: str | None = None
    originator: str | None = None
    line_no: int | None = None
    seen: bool = False
    trusted: bool = False


class CodexRolloutLineParser:
    """Codex rollout JSONL 行流解析器：逐行喂入，产出 0..n 条标准记录并累计质量计数。

    一次实例对应一条会话行流，至多消费 `MAX_LINES_PER_STREAM` 行；只解析首个 `session_meta`
    为头部（后续头部只核对不覆盖），本轮头部**均不采信**，因此不给后续记录提供已核实的归属。
    `finish()` 后实例进入终态。计数器只累加固定类别，不保留行类型、role、块类型名等数据侧文本。
    """

    def __init__(
        self,
        *,
        stream_label: str | None = None,
        session_id: str | None = None,
        project: str | None = None,
        source: str = SOURCE_CODEX,
    ) -> None:
        """`session_id` 为会话归属的校验断言，`project` 为上层给定的 **cwd 断言**。

        两者本层都**不验证**，也不声明已授权；`project` 不是策略项目名（策略名到 cwd 的映射属
        `policy.py`/协调层），它独立保存、永不写回头部字段，也不充当缺失 cwd 的替身。超
        `MAX_PROJECT_VALUE_CHARS` / `MAX_SESSION_ID_CHARS` 的入参按未提供处理（不截断使用）；
        `stream_label` 走 `sanitize_stream_label`。`source` 不开放：与 `codex` 不一致的非空值拒接。
        """
        self._stream_label = sanitize_stream_label(stream_label)
        self._asserted_project = _as_text(project, MAX_PROJECT_VALUE_CHARS)
        self._expected_session_id = _as_text(session_id, MAX_SESSION_ID_CHARS)
        normalized_source = _as_text(source, MAX_MATCH_KEY_CHARS)
        if normalized_source is not None and normalized_source != SOURCE_CODEX:
            raise ValueError("CodexRolloutLineParser records always carry the fixed source 'codex'")
        self._source = SOURCE_CODEX
        self._stats = ParseStats()
        self._header = CodexHeaderInfo()
        self._line_no = 0
        self._project = self._asserted_project
        self._project_quality = (
            ProjectQuality.CALLER_ASSERTED if self._asserted_project else ProjectQuality.UNKNOWN
        )
        # 头部的 cwd 证据不可用于归属：与外部断言或首个头部字面互斥（跨头部入口），或同行两处互斥、
        # 声明了却给不出可用值（同行入口）。两个入口置同一个粘性标志，粘住到流结束（不回抢，也不因
        # 「头部反正不可采信」就把断言值继续当成归属证据用）。
        self._project_conflict = False
        # 头部的会话标识证据不可用：与断言或首个头部互斥（跨头部入口），或同行两处互斥、声明了却
        # 给不出可用值（同行入口）。一旦置位整条流归属存疑，后续记录不再采信。
        self._session_id_conflict = False
        # 头部 originator 冲突（行级与 payload 两处矛盾，或多个 session_meta 互不一致）：
        # 现有枚举无对应码，因此只由属性向调用方说明原因（详见模块文档）。
        self._originator_conflict = False
        self._line_limit_exceeded = False
        self._finished = False

    # ---------- 对外状态 ----------

    @property
    def stats(self) -> ParseStats:
        """类别计数（可安全用于日志：不含原文、路径与数据侧字符串）。"""
        return self._stats

    @property
    def header(self) -> CodexHeaderInfo:
        """已解析到的会话头部（未出现时 `seen=False`、字段全 `None`）。"""
        return self._header

    @property
    def session_id(self) -> str | None:
        """已核实的会话标识（需断言与**可信**头部一致）；否则 `None`。

        本轮头部恒不可采信，因此该属性恒为 `None`：没有任何记录能拿到已核实的身份。
        """
        if self._session_id_conflict:
            return None
        header_id = self._header.session_id if self._header.trusted else None
        expected = self._expected_session_id
        if header_id is not None and expected is not None:
            return header_id if header_id == expected else None
        return None

    @property
    def project(self) -> str | None:
        """可归类的项目值：可信头部 `cwd` 优先，无可信头部时为断言值，冲突或全无为 `None`。"""
        return self._project

    @property
    def asserted_project(self) -> str | None:
        """外部 cwd 断言原值（仅长度判限后的形式）：与头部证据独立保存，不被头部覆写或抹除。"""
        return self._asserted_project

    @property
    def project_conflict(self) -> bool:
        """头部 `cwd` 证据是否否证归属；粘性为真。

        两个入口都能置位：跨头部互斥（与外部 cwd 断言或首个头部不一致），以及同一行行级与
        `payload` 两处互斥、或声明了该键却给不出可用值。
        """
        return self._project_conflict

    @property
    def project_quality(self) -> ProjectQuality:
        """项目归属质量；任何取值都不表示已获授权，只表示值的来源。"""
        return self._project_quality

    @property
    def originator_conflict(self) -> bool:
        """头部 originator 是否矛盾（行级 vs payload，或多个头部之间）；现有枚举无对应码，故单独暴露。"""
        return self._originator_conflict

    def finish(self) -> None:
        """收尾：登记流级问题（未出现头部行、项目无法确定）；幂等。

        头部行存在但不可采信时不再计 `no_session_header`（形状/冲突问题已在头部行记下）。
        """
        if self._finished:
            return
        self._finished = True
        if not self._header.seen:
            self._stats.note(IssueCode.NO_SESSION_HEADER)
        if not self._project_quality.sourced:
            self._stats.note(IssueCode.UNKNOWN_PROJECT)

    # ---------- 行入口 ----------

    def feed(self, lines: Iterable[str | bytes]) -> Iterator[StandardRecord]:
        """按序消费行流，惰性产出标准记录。

        整个 `str`/`bytes` 当行流传入直接 `TypeError`（逐字符迭代会把一行射成海量假行）；
        `finish()` 后复用抛 `RuntimeError`（固定消息，不携带数据侧文本）。无论正常结束还是
        提前关闭，`finally` 都会调用 `finish()`；行数上限达到后不再从调用方迭代器取下一行。
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
        """解析一行，返回该行产出的记录（0..若干个文本块）。"""
        if self._finished:
            raise RuntimeError("parser is finished; create a new instance for a new stream")
        if self._line_limit_exceeded:
            return ()
        if self._line_no >= MAX_LINES_PER_STREAM:
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
        """只认 `session_meta` 与 `response_item` 两类行；其它（含无 `type`）计未知事件。

        这里不套用 pi 的「无 type 时按特征宽识」分支：Codex 的平铺写法未经确认，接受任意
        缺少 `type` 的 JSON 对象会把读不懂的行冒充成消息。
        """
        raw_type = payload.get("type")
        if _is_oversized_text(raw_type):
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return ()
        event_type = _as_role(raw_type)
        if event_type in HEADER_EVENT_TYPES:
            return self._handle_header(payload)
        if event_type in MESSAGE_EVENT_TYPES:
            return self._handle_response_item(payload)
        self._stats.note(IssueCode.UNKNOWN_EVENT)
        return ()

    def _meta_holders(self, payload: dict[str, Any]) -> tuple[dict[str, Any], ...]:
        """头部字段的查找顺序：行对象本身，再其 `payload` 子对象。

        05 只说「`session_meta` 中 cwd/originator」，未确认这些字段挂在行级还是 payload 内，
        因此两处都查（先行级）；两种形状都未经真实 rollout 核对。子对象存在但不是 dict 时
        由 `_handle_header` 记形状不可解释，本方法只返回可用的 dict。
        """
        holders: list[dict[str, Any]] = [payload]
        inner = payload.get("payload")
        if isinstance(inner, dict):
            holders.append(inner)
        return tuple(holders)

    def _handle_header(self, payload: dict[str, Any]) -> tuple[StandardRecord, ...]:
        """解析 `session_meta`（取 id、cwd、originator）；头部本身不产出检索记录。

        本轮没有已核实的格式契约，因此**任何头部都不可采信**（`trusted` 恒为 `False`）：它既不
        授予 `trusted_header_cwd`，也不授予已核实的会话身份。读到的字段仍如实保存（不假装什么都
        没看到），供格式契约核实后复核；证据不足只收回可信资格，不补猜测。

        同一字段在行级与其 `payload` 两处都声明时不做「先到先得」的静默回落：值矛盾或声明了却
        不可用都按固定已有码登记，**并置与跨头部核对同一套粘性失败状态**（见 `_holder_consensus`）：
        cwd 矛盾/不可用 → `_project_conflict`，id 矛盾/不可用 → `_session_id_conflict`。字段真正
        缺失（两处都没声明）不是矛盾，也不置任何粘性——那仍是未知。
        **首发与迟到头部都走 `_reconcile_header_evidence`**：可用 id/cwd 与外部断言、与首个头部值
        分别核对，矛盾即记固定码并置同一个粘性标志，不因「这是首个头部」或「头部不可采信」而跳过。
        后续头部行不覆盖首个头部：一律计 `late_session_header`，任何情况下都不升级可信度。
        """
        holders = self._meta_holders(payload)
        inner = payload.get("payload", _FIELD_NOT_PRESENT)
        shape_invalid = inner is not _FIELD_NOT_PRESENT and not isinstance(inner, dict)
        new_cwd, cwd_conflict, cwd_unusable = self._holder_consensus(
            holders, _CWD_KEYS, MAX_PROJECT_VALUE_CHARS
        )
        new_session, session_conflict, session_unusable = self._holder_consensus(
            holders, _SESSION_ID_KEYS, MAX_SESSION_ID_CHARS
        )
        new_originator, originator_conflict, originator_unusable = self._holder_consensus(
            holders, _ORIGINATOR_KEYS, MAX_MATCH_KEY_CHARS
        )
        if shape_invalid:
            # 头部 payload 形状不可解释：本层无法确认它描述的是哪个会话，其字段一概不予采信。
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
        if cwd_conflict:
            self._stats.note(IssueCode.CONFLICTING_HEADER_CWD)
            # 同行入口与跨头部入口共用失败状态：互斥的 cwd 同样否证归属，不能只记码不置状态。
            self._project_conflict = True
        if cwd_unusable:
            self._stats.note(IssueCode.INVALID_HEADER_CWD)
            # 已声明但给不出可用值的 cwd 同样否证归属（键真缺失时走不到这里，不新增假冲突）。
            self._project_conflict = True
        if session_conflict:
            self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
            self._session_id_conflict = True
        if session_unusable or originator_unusable:
            # 字段声明了却给不出可用值：这是形状问题，不是「没有该字段」。
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
        if session_unusable:
            # 会话标识的同行入口：与 `_reconcile_header_evidence` 那条跨头部入口同一失败语义，
            # 其后每条记录按流级冲突拒产正文。
            self._session_id_conflict = True
        if originator_conflict:
            # 两处 originator 不一致 → 「这条会话由哪个客户端产生」无法判定；`IssueCode` 内没有
            # 对应类别（本轮不扩大枚举），后果仍由 project_unverified / unknown_project 如实上报，
            # 另由 originator_conflict 属性向调用方说明原因。
            self._originator_conflict = True
        # 独立证据核对：首发与迟到走同一条路径，不因可信度为假而短路（细节见方法 docstring）。
        # 必须在把首发值写入 `self._header` **之前**调用，否则首个头部会与自己比对。
        self._reconcile_header_evidence(new_session, new_cwd)
        if not self._header.seen:
            # 格式标识证据登记：本轮无论走哪个分支，头部都不可采信；码只说明证据缺在哪。
            # 取值本身不参与任何判定（无已核实白名单），超长/非字符串/两处矛盾同样只登记码。
            _, version_conflict, _ = self._holder_consensus(
                holders, _VERSION_KEYS, MAX_HEADER_VERSION_CHARS
            )
            if any(_has_field(h, _VERSION_KEYS) for h in holders):
                # 声明了版本/格式标识只说明「有这个字段」，**不等于格式已识别**（无已核实白名单，
                # 取值一律不参与判定）；矛盾另计一码，形状问题不靠降级掩盖。
                self._stats.note(IssueCode.UNSUPPORTED_HEADER_VERSION)
                if version_conflict:
                    self._stats.note(IssueCode.CONFLICTING_HEADER_VERSION)
            else:
                self._stats.note(IssueCode.MISSING_HEADER_VERSION)
            self._header = CodexHeaderInfo(
                session_id=new_session,
                cwd=new_cwd,
                originator=new_originator,
                line_no=self._line_no,
                seen=True,
                trusted=False,
            )
            self._adopt_header_project()
            return ()
        self._stats.note(IssueCode.LATE_SESSION_HEADER)
        # 迟到头部只用于核对外部断言与首个头部，绝不升级：可信度本轮没有可升级的依据。
        # id/cwd 与外部断言、与首个头部的比对已由上方 `_reconcile_header_evidence` 统一完成
        # （首发与迟到同一条路径；此处 `self._header` 仍是首个头部，因此「与首个头部」那一路已生效）。
        # 本分支只剩 originator：现有枚举无对应码，只由属性向调用方明示。
        if new_originator is not None and self._header.originator is not None and (
            new_originator != self._header.originator
        ):
            # 多个 session_meta 的 originator 互不一致：与两处层级矛盾走同一路径（只记属性与后果码）。
            self._originator_conflict = True
        self._adopt_header_project()
        return ()

    def _reconcile_header_evidence(
        self, new_session: str | None, new_cwd: str | None
    ) -> None:
        """把这份头部给出的可用 id/cwd 与**外部断言**、与**首个头部**分别核对。

        首发与迟到头部共用本方法：可采信状态只决定这些值能不能被当归属证据用，**不决定矛盾
        能不能被登记**。不因「这是首个头部、没得比」而略过与外部断言的核对，也不因「头部本轮
        反正不可采信」而略过整条核对——后者会把外部断言通道未经否证的事实藏起来。

        比对只在**两侧都给出可用值**时进行：`None` 是「未知」，不是可断言的矛盾值（字段声明了
        却不可用、或同行两处互斥，由 `_holder_consensus` 那条路径按现有固定码登记，并置同样的
        `_project_conflict`/`_session_id_conflict` 粘性，本方法因此不必重复登记那份矛盾）。

        - id 与调用方断言不一致，或与首个头部 id 不一致 → 记 `header_session_id_mismatch` 并置
          粘性 `_session_id_conflict`：整条流归属存疑，其后记录一律拒产正文。
        - cwd 与外部 cwd 断言不一致，或与首个头部 cwd 不一致 → 记 `conflicting_header_cwd` 并置
          粘性 `_project_conflict`：两个值都不采信，项目由 `_adopt_header_project` 降为
          `None`/`unknown`（流级 `unknown_project`、已产出记录逐条 `project_unverified`）。

        首个头部时 `self._header` 仍是初始空值（`session_id`/`cwd` 为 `None`），因此与首个头部的
        那一路天然不参与；调用方必须在把首发值写入 `self._header` 之前调用本方法。
        """
        session_mismatch = new_session is not None and (
            (self._expected_session_id is not None and new_session != self._expected_session_id)
            or (
                self._header.session_id is not None
                and new_session != self._header.session_id
            )
        )
        if session_mismatch:
            self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
            self._session_id_conflict = True
        cwd_mismatch = new_cwd is not None and (
            (self._asserted_project is not None and new_cwd != self._asserted_project)
            or (self._header.cwd is not None and new_cwd != self._header.cwd)
        )
        if cwd_mismatch:
            self._stats.note(IssueCode.CONFLICTING_HEADER_CWD)
            self._project_conflict = True

    def _holder_consensus(
        self,
        holders: tuple[dict[str, Any], ...],
        keys: tuple[str, ...],
        max_chars: int,
    ) -> tuple[str | None, bool, bool]:
        """跨 holder（行级，再 `payload`）取一个头部字段，返回 `(值, 值矛盾, 声明了但不可用)`。

        字段在多处出现时**不按「先到先得」取值**：两份可用值互不相同就是归属不确定（值为
        `None`）；某处声明了该字段（键存在）却给不出可用值（非字符串、空白、超长）也令值失效。
        调用方必须据此登记固定码；对 cwd/id 还要置对应的粘性失败状态（originator 无粘性通道，
        只由属性向调用方说明）：不能因为另一处读到值就当矛盾不存在，也不能只记码而把归属继续
        按未否证的断言通道输出。
        """
        values: list[str] = []
        unusable = False
        declared = False
        for holder in holders:
            if not _has_field(holder, keys):
                continue
            declared = True
            text = _as_text(_first_present(holder, keys), max_chars)
            if text is None:
                unusable = True
            else:
                values.append(text)
        if len(set(values)) > 1:
            return None, True, unusable
        if unusable:
            return None, False, True
        return (values[0] if (values and declared) else None), False, False

    def _adopt_header_project(self) -> None:
        """按头部状态重算项目值与质量（外部断言与头部 `cwd` 两条通道不合并）。

        `_project_conflict` 由两个入口共同维护：跨头部的字面冲突由 `_reconcile_header_evidence`
        置位并登记 `conflicting_header_cwd`；同行两处互斥、或声明了却给不出可用值，由
        `_handle_header` 置位并登记 `conflicting_header_cwd`/`invalid_header_cwd`。本方法只按粘性
        结果重算值与质量：

        - 冲突已置 → 归属不唯一，两个值都不采信：粘性降为 `None`/`unknown`。这里**不因「头部本轮
          反正不可采信」就放过矛盾**：断言通道本身也被这份头部否证了，留着断言值继续归类就是
          静默回落。后果由固定码向调用方交代（流级 `unknown_project`、已产出记录逐条
          `project_unverified`），不另造新码。
        - 可信头部 cwd 且与断言不矛盾 → `TRUSTED_HEADER_CWD`：本轮不可达（头部恒不可采信），
          分支保留给格式契约核实之后的复核。
        - 无可信头部 cwd 而只有断言 → 仍只给 `CALLER_ASSERTED`：值有来源，归属不在本层确立。
        - 只有不可信头部 cwd、无断言 → 不采信，`UNVERIFIED_HEADER_CWD`，不猜目录名。
        """
        if self._project_conflict:
            self._project = None
            self._project_quality = ProjectQuality.UNKNOWN
            return
        if self._header.trusted and self._header.cwd is not None:
            self._project = self._header.cwd
            self._project_quality = ProjectQuality.TRUSTED_HEADER_CWD
            return
        if self._asserted_project is not None:
            self._project = self._asserted_project
            self._project_quality = ProjectQuality.CALLER_ASSERTED
            return
        self._project = None
        self._project_quality = (
            ProjectQuality.UNVERIFIED_HEADER_CWD
            if self._header.cwd is not None
            else ProjectQuality.UNKNOWN
        )

    def _handle_response_item(self, payload: dict[str, Any]) -> tuple[StandardRecord, ...]:
        """处理一行 `response_item`：只接受 `payload.type == "message"`，其它计未知块类型。

        工具调用/工具输出/推理等事件的名称本轮无法从项目内证据确认，因此不标为「已理解的省略」
        （不计 `known_non_text_block`，那会使扫描看起来完整），一律计 `unknown_block_type`
        并使 `partial` 为真；这既满足「跳过工具数据」的产出边界，也不假装读懂了它们。
        """
        envelope = payload.get("payload", _FIELD_NOT_PRESENT)
        if envelope is _FIELD_NOT_PRESENT or envelope is None:
            self._stats.note(IssueCode.MISSING_MESSAGE_ENVELOPE)
            return ()
        if not isinstance(envelope, dict):
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            return ()
        raw_item_type = _first_present(envelope, _TYPE_KEYS)
        if _is_oversized_text(raw_item_type):
            self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
            return ()
        if _as_role(raw_item_type) != CODEX_MESSAGE_TYPE:
            # 含缺失 `type` 的 payload：形状不足以判定它是不是消息，保守不产正文。
            self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
            return ()
        return self._handle_message(payload, envelope)

    def _handle_message(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> tuple[StandardRecord, ...]:
        """处理一条消息：先定会话归属与角色，再取时间与正文块。

        归属存疑（头部与断言冲突）的记录直接丢弃，避免把未核实的会话内容混入本会话结果。
        """
        session_id, verified, rejected = self._resolve_session_id()
        if rejected:
            return ()
        record_issues: list[IssueCode] = []
        if session_id is None:
            self._stats.note(IssueCode.MISSING_SESSION_ID)
            record_issues.append(IssueCode.MISSING_SESSION_ID)
        elif not verified:
            self._stats.note(IssueCode.SESSION_ID_UNVERIFIED)
            record_issues.append(IssueCode.SESSION_ID_UNVERIFIED)

        # 角色只取消息层 `payload.role`：行级 `role` 是否等价未经确认，**不做行级回落**
        # （回落等于把一份未确认的声明当成正文来源）。声明了但不可用按未知角色登记，不计缺失。
        role_value = envelope.get("role")
        role = _as_role(role_value)
        if role is None:
            self._stats.note(
                IssueCode.UNKNOWN_ROLE
                if _has_field(envelope, _ROLE_KEYS)
                else IssueCode.MISSING_ROLE
            )
            return ()
        if role not in TEXT_ROLES:
            # 系统/开发者提示等：按 05 要求跳过，但跳过本身就是覆盖不完整，必须显式标出。
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
        record_issues.extend(limit_issues)
        if blocks is None:
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            return ()
        if not blocks:
            if not lost_content:
                self._stats.note(IssueCode.NO_TEXT_CONTENT)
            return ()

        if not self._project_quality.sourced:
            # 已输出但无可靠项目归属：当场计入，后续头部不追溯挣销（记录不回改）。
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

        超限计 `line_too_large` 并整行丢弃（不截断后解析）；非 `str`/`bytes` 元素与解码失败
        计 `corrupt_line`，不做有损替换以免伪造正文。
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

    def _resolve_session_id(self) -> tuple[str | None, bool, bool]:
        """返回 `(可用于记录的会话标识, 是否已核实, 是否拒绝本行)`。

        证据只有两份：调用方断言与**可信**头部 id（消息行内标识未经确认，不取）。两者不一致已在
        头部处理时置为流级冲突 → 之后每行计 `session_id_mismatch` 并拒产正文；只有一份证据时
        可用但**不算已核实**。

        本轮头部恒不可采信（无已核实格式契约），所以 `header_id` 永远为 `None`：有断言也只到
        「可用但未核实」（计 `session_id_unverified`），`verified=True` 分支保留给格式契约核实
        之后的复核，本轮不可达。
        """
        if self._session_id_conflict:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        header_id = self._header.session_id if self._header.trusted else None
        candidates = [v for v in (self._expected_session_id, header_id) if v is not None]
        if len(set(candidates)) > 1:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        if not candidates:
            return None, False, False
        return candidates[0], len(candidates) >= 2, False

    def _resolve_timestamp(
        self, outer: dict[str, Any], envelope: dict[str, Any]
    ) -> tuple[datetime | None, TimeQuality]:
        """候选时间来源均未核实：不解析、不发布时刻，只区分「确实缺失」与「存在但语义未知」。

        `timestamp`/`createdAt`/`created_at` 在消息层与行级的层级、语义（消息时刻还是写入时刻）、
        单位与时区写法都没有与真实 rollout 核对过，因此本层不得从任何一路得到可过滤的时刻：

        - 消息层与行级都没有声明候选键 → `None` + `MISSING`（计 `missing_timestamp`）。
        - 任一处声明了候选键（含值为 `null`）→ `None` + `INVALID`（计 `timestamp_invalid`）：
          字段存在但无法确定它说什么，这**不是**「缺时区」。`NO_TIMEZONE` 会宣称「已确认这是
          时间、只缺时区」，本层没有这份证据，拿它当降级就是伪装证据。

        两条都不产生 `EXACT`，所以本层输出的记录全部不可参与时间范围过滤（查询层只让 `EXACT`
        参与比较）。候选键不含泛化 `time`；不回落头部时间，不用文件 mtime，不用目录名。
        消息层与行级同时给出不同值时结论同为 `INVALID`：未核实的来源之间没有谁优先，矛盾只是
        「更不该发布」的旁证，不再需要单独分支。
        """
        declared = _has_field(envelope, _TIMESTAMP_KEYS) or _has_field(outer, _TIMESTAMP_KEYS)
        if declared:
            return None, TimeQuality.INVALID
        return None, TimeQuality.MISSING

    def _content_blocks(
        self, envelope: dict[str, Any]
    ) -> tuple[tuple[str, ...] | None, bool, tuple[IssueCode, ...]]:
        """提取消息 `payload.content` 里的文本块（有界）：只接受**数组** content。

        每个块必须是对象，且**显式声明**一个命中 `TEXT_BLOCK_TYPES` 的 `type` 与非空 `str` 的
        `text`。以下形状本轮都未经确认，一律不当正文（猜出来的会是「正文」而不是「可能有正文」）：
        裸字符串 content、单个 dict 形式的 content、数组里的裸字符串元素、块内 `content` 别名、
        以及没有 `type` 的块（不回落成「无 type 即文本」）。

        返回 `(块元组, 是否有内容因不可解释而未产出, 本行命中的上限原因码)`；块元组为 `None`
        表示 content 整体形状不可解释。块数上限：只看前 `MAX_CONTENT_BLOCKS_PER_LINE` 个，其余
        不查看不解析，行计一次 `content_block_limit_exceeded`。单块超长只保留固定前缀并计
        `text_block_truncated`。非文本块类型一律计 `unknown_block_type`（本层不维护未经确认的
        Codex 工具/图像块名单，因此不使用 `known_non_text_block` 免降级通道）。
        """
        content = envelope.get("content", _FIELD_NOT_PRESENT)
        if content is _FIELD_NOT_PRESENT or content is None:
            return None, True, ()
        if not isinstance(content, (list, tuple)):
            # 字符串/对象/数字/布尔：数组以外的形状不猜语义，也不静默取用。
            return None, True, ()
        candidates: list[Any] = list(content[:MAX_CONTENT_BLOCKS_PER_LINE])
        dropped_blocks = len(content) - len(candidates)
        texts_out: list[str] = []
        line_issues: list[IssueCode] = []
        lost = bool(dropped_blocks)
        if dropped_blocks:
            self._stats.note(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
            line_issues.append(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
        for item in candidates:
            if not isinstance(item, dict):
                # 裸字符串块等未确认形状：不当正文，计形状不可解释（不是「已理解的省略」）。
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
                lost = True
                continue
            if _first_present(item, _TYPE_KEYS) is None:
                # 块没有声明 type：无法确认它是文本块，不回落。
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
                lost = True
                continue
            block_type = _as_role(_first_present(item, _TYPE_KEYS))
            if block_type is None or block_type not in TEXT_BLOCK_TYPES:
                # 含超长/非字符串/未收录的 type：都不当文本块。
                self._stats.note(IssueCode.UNKNOWN_BLOCK_TYPE)
                lost = True
                continue
            body = _first_present(item, _TEXT_KEYS)
            if not _has_field(item, _TEXT_KEYS):
                # 声明了文本 type 却没有 `text` 字段：块形状不完整，不取别名字段顶替。
                self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
                lost = True
                continue
            if not isinstance(body, str):
                self._stats.note(IssueCode.NON_STRING_TEXT_BLOCK)
                lost = True
                continue
            if not body.strip():
                continue  # 已理解的空文本块：没有内容被丢弃
            bounded, truncated = _bounded_text(body)
            if truncated:
                self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
            # 保留前缀逐字不动（不削掉原文内部空白），仅用 strip 判空。
            texts_out.append(bounded)
        return tuple(texts_out), lost, tuple(line_issues)
