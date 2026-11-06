"""Claude Code CLI stream-json 行流解析适配器（DES-INC-05 / DES-ADAPTER-05）。

只解析**调用方提供的行流**（`Iterable[str | bytes]`，每元素一行）：不发现目录、不打开文件、
不读配置、不做授权（属 `policy.py`）、不接 `server.py`、不写日志。标准记录与质量枚举来自
`models.py`；有界约束与 `sources/pi.py`、`sources/codex.py` 同口径但**不从它们导入**
（DES-ARCH-02：来源之间不相互依赖），本模块自带私有辅助与常量副本。

格式依据只有 `docs/spec/05` 的 Claude 行与本轮用户指令：`~/.claude/projects/<工作区编码目录>/
<session-id>.jsonl` 为逐行 JSON（stream-json），行内带 `type`/`message`/`timestamp`/`session_id`
一类键；取证更正——`assistant` 是 `type` 取值而不是顶层键。本轮禁止读取真实会话，键形态与取值
集合**未与真实数据核对**，因此未核实形态一律按不认识处理并计降级（沿用 codex 的未核实口径），
不补造契约。

产出边界（对齐 `PiLineParser` 的记录形态，但采信门槛更保守）：

- **正文**：只产 `user`/`assistant` 的可检索正文。行 `type` 即角色（`TEXT_ROLES`），正文来自
  `message.content`：数组形态里块必须是显式声明 `type == "text"` 且带 `str` `text` 的对象；
  字符串形态整串按**单块正文**取用，与数组内单个 `text` 块走同一道字符上限与
  `text_block_truncated` 契约。无 `type` 的块、`content`/`text` 别名都不当正文；
  `tool_use`/`tool_result`/`thinking`/`image` 等工具与推理内容一律按**未核实形态**计
  `unknown_block_type` 并使覆盖不完整（DES-INC-05：未与真实数据核对的形态不预设其为合法
  非文本，否则会把部分扫描说成完整无匹配）。
- **未核实的行类型**：除消息行与 `type == "system"` 之外一律 `unknown_event` 并计入覆盖不完整，
  不套用 pi 的「无 `type` 宽识」分支——没有与真实数据核对过的形态识别规则，就不认领任何形态。
- **会话标识**：外部断言（来自 `<session-id>` 目录文件名的上层断言）、`system` 头部行的
  `session_id`、消息行的 `session_id` 三路核对（与 `pi` 同型：任一不一致 → 整条流归属存疑，
  粘性拒产正文）。同层别名键（`session_id`/`sessionId`/`session-id`）取值互不相同时按
  「有值但不可采信」处理，**不先到先得**：在同一行里挑一个别名当权威没有依据。判否通道
  只看「有没有过形态门的可用标识」：**头部标识只要可用就参与矛盾核对**，不因头部未被采信
  （版本缺失等）而豁免——版本门控的是采信度，不是把一份合法标识声明从核对里摘出去的理由。
  选值与「已核实」的证据票数仍只用外部断言、**可信**头部与行内值三路：合法但不可信的头部
  既不能单独提供记录标识，也不给票数补票。只认 `id` 形态过**闭合字符集门**的值：含 `/`、`\\`、`:`、空白、盘符或非 ASCII 的路径
  形态值「有值但不能采信」→ 记 `header_session_id_mismatch` 并置粘性失败状态，**整体判否**、
  不做前缀保留（DES-API-01；本层自持该门，不依赖 `file_search` 的出口实现）。
- **项目归属**：行内 `cwd` 与外部 `project` 断言两路核对；编码目录名有损（分隔符替换），**不得**
  据其还原项目，本层根本不接收目录名入参。两路皆无 → 记录逐条 `project_unverified`、整流
  `unknown_project`。行内 `cwd` 超长、非字符串、同层别名矛盾都当场登记降级（`invalid_header_cwd`）
  并使覆盖不完整，不静默吞掉。**只有解析为可用短字符串的 cwd 参与值间比较**：空值/畸形值按
  形态降级处理，不与合法值并列成「两个互斥的 cwd 声明」。头部（首个与重复）的可用 cwd 与
  已有可用证据（外部断言、已采信项目、已见行内 cwd、已采信头部 cwd）跨行核对，矛盾即记一次
  `conflicting_header_cwd` 并**粘性**降级（`project_conflict`、清空项目、质量 `unknown`）；该判否
  **与 `header.trusted` 无关**，也不能靠后续一致的行内 cwd 或外部断言恢复。合法但不可信的头部
  cwd 与现有证据一致时，仍只按现有采信度归因，不升格为 `trusted_header_cwd`。
- **派生/子代理会话（sidechain）**：`isSidechain`/`is_sidechain` 为真、或 `parent_tool_use_id`
  给出非空父引用的行，**不得**计为独立用户会话：跳过、不产任何正文记录、不确立会话身份、
  不采信其头部字段，并计入覆盖不完整。父引用**有值但形态/长度不可采信**（非字符串、超长）
  的行同样按派生跳过：不可核实的派生标记不得逃逸成主会话正文。布尔标记只认明确取值域：
  `true`/`false` 布尔与折叠后等价的 `"true"`/`"false"` 字符串（原始长度 ≤ `MAX_MATCH_KEY_CHARS`）；
  缺席或单独的 `null` 是「没有声明」。数字、容器、空白与其它字符串都是**无法解释的声明**，
  两个别名互相矛盾也是——两种情况都保守跳过该行并按派生跳过计数，不默认放行成主流正文。`IssueCode` 是本包的闭合枚举（新增类别须改 `models.py`，
  不在本增量范围），所以这类行的原因码登记为 `unknown_event`，其真实构成由
  `sidechain_skipped_lines` 属性向调用方明示（与 `codex.originator_conflict` 同一先例）。
  「派生行跳过」与「矛盾行拒收」是两种结论：前者不否定整条流的归属，后者粘性否决。
- **时间**：**只取行顶层**的 `timestamp`/`createdAt`/`created_at`（ISO 字符串或纪元数值）交给
  `models.normalize_timestamp`；`message` 信封里的时间**不作为行级时间的回落**——把「顶层没有」
  读成「信封里有」会把另一个字段冒充成消息时刻。顶层同层别名取值互不相同（含一个 `null`
  加一个有效值）时按「有值但不可采信」处理，记 `timestamp_invalid`，不先到先得。带时区
  直接采用为精确时刻，无时区按 `TimeQuality` 降级（`timestamp_no_timezone`），不可解析/超长
  记 `timestamp_invalid`，顶层缺席记 `missing_timestamp`。`mtime` 不代消息时刻，本层也拿不到 `mtime`。
- **已产出的记录不因后续行而回改**；`session_id`/`project` 属性只读，整流归属按当前采信状态
  暴露（`project_conflict` 供调用方区分「冲突导致 null」与「本来就没有」）。
- **接线**：来源 ID 为 `claude_code_cli`（DES-CL-20261103-03），扩展来源、默认 disabled，门在
  `server.py`（`_SOURCE_ID_ALIASES` + `EXTENDED_SOURCE_IDS`），本模块不读策略、不判授权，产出
  记录的 `source` 恒为该固定值。

资源上限（超限的后果是覆盖不完整，不是静默丢弃）：单行字节/字符上限、整流行数上限、单行块数
上限与单块字符上限；正文截断只保留固定长度前缀，不追加省略号或标记文本，被削掉的部分不保留
也不另存，截断事实由 `text_block_truncated` 表达。

未核实边界（后续增量须与真实数据核对后才能收回）：头部采信规则、`cwd` 是否逐行出现、
`content` 为字符串的 user 行、块类型取值集合、`version`/`subtype` 集合、sidechain 标记的确切键名
与取值域。在这些收回之前，本层输出用于对照核对，不用于发布。
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
    "HEADER_EVENT_TYPES",
    "HEADER_SUBTYPES",
    "IDENTIFIER_SAFE_CHARS",
    "KNOWN_SYSTEM_SUBTYPES",
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
    "SOURCE_CLAUDE",
    "TEXT_BLOCK_TYPES",
    "TEXT_ROLES",
    "ClaudeHeaderInfo",
    "ClaudeLineParser",
]

#: 记录里的固定来源值：对外 ID 与内部键在本来源同一口径（`docs/spec/03` SRS-SEARCH-12），
#: 不接受调用方替换——来源标识由本模块钉死，否则 `source` 会成为可伪造的分组键。
SOURCE_CLAUDE = "claude_code_cli"

# --- 资源上限（与 pi/codex 同量级，取 `docs/spec/05` 为 Claude 记的更宽档位）---
#: 单行原始字节上限：超限整行丢弃并记 `line_too_large`（不解析半行）。
MAX_LINE_BYTES = 1_048_576
#: 解码后的单行字符上限：与字节门分列，因为多字节字符让两者不等价。
MAX_LINE_CHARS = 262_144
#: 单行文本块上限：超出的块不保留，整行计 `content_block_limit_exceeded`。
MAX_CONTENT_BLOCKS_PER_LINE = 64
#: 单块正文上限：超出只保留前缀并计 `text_block_truncated`。
MAX_TEXT_BLOCK_CHARS = 32_768
#: 整流行数上限：超出即停（粘性），后续行一律不再消费，整流计 partial。
MAX_LINES_PER_STREAM = 50_000
#: 项目值上限：Windows 长路径可超过 512（DES-INC-05 取证更正），故本来源放宽到 1024；
#: 它卡的是「一个可外出的短标识」，不是正文。
MAX_PROJECT_VALUE_CHARS = 1_024
#: 会话标识上限：Claude 的 session id 是 UUID（36 字符），128 已留足余量。
MAX_SESSION_ID_CHARS = 128
#: 头部版本值的长度上限。
MAX_HEADER_VERSION_CHARS = 32
#: 角色/类型等匹配键的统一长度上限：同时把匹配键的哈希成本钉住（与 pi/codex 同值）。
MAX_MATCH_KEY_CHARS = 64

#: 可产正文的角色：本层只把 `user`/`assistant` 当正文，其余角色一律不产正文并计降级。
TEXT_ROLES: frozenset[str] = frozenset({"assistant", "user"})

#: 已核实的文本块类型：只有显式 `text`。Claude 的 input_text/output_text 形态未经核对，
#: 不在认领范围（不预设任何块是合法非文本，故此处也不进 KNOWN 集合）。
TEXT_BLOCK_TYPES: frozenset[str] = frozenset({"text"})

#: 已核实的消息行类型：`user`/`assistant` 出现在行 `type`（取证更正：不是顶层键之外的东西）。
MESSAGE_EVENT_TYPES: frozenset[str] = frozenset({"user", "assistant"})

#: 已核实的头部行类型：`system` 事件行（其 `subtype` 决定是否可能为会话起点）。
HEADER_EVENT_TYPES: frozenset[str] = frozenset({"system"})

#: 可作为会话起点被采信的 subtype：只有 `init`。取值集合未与真实数据核对，因此其余 subtype
#: 一律不采信头部字段。
HEADER_SUBTYPES: frozenset[str] = frozenset({"init"})

#: 已知的 `system` subtype 中「不是会话起点」的那些：计 `skipped_role`（有交代的不处理）；
#: 未登记或缺失的 subtype 计 `unknown_event`（本层不认识），头部不采信。
KNOWN_SYSTEM_SUBTYPES: frozenset[str] = frozenset(
    {"compact", "hook_response", "mirror_error"}
)

#: 标识/角色的合法字符集（DES-API-01 闭合形态门）：ASCII 字母数字与 `-`、`_`、`.`。
#: 含 `/`、`\`、`:`、空白、盘符或非 ASCII 的值一律整体判否——不截断、不部分保留。
IDENTIFIER_SAFE_CHARS: frozenset[str] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)

_SESSION_ID_KEYS: tuple[str, ...] = ("session_id", "sessionId", "session-id")
#: 消息层的标识键：**不含**裸 `id`（常是单条消息/事件 ID，拿来当会话标识会把不同会话并成一条）。
_MESSAGE_SESSION_ID_KEYS: tuple[str, ...] = ("session_id", "sessionId")
_TIMESTAMP_KEYS: tuple[str, ...] = ("timestamp", "createdAt", "created_at")
_CWD_KEYS: tuple[str, ...] = ("cwd", "workingDirectory", "working_directory")
_SUBTYPE_KEYS: tuple[str, ...] = ("subtype", "sub_type")
_VERSION_KEYS: tuple[str, ...] = ("version", "v", "claude_code_version")
_ROLE_KEYS: tuple[str, ...] = ("role",)
_TYPE_KEYS: tuple[str, ...] = ("type",)
_TEXT_KEYS: tuple[str, ...] = ("text",)
#: 派生会话证据键：布尔标记与父引用各两种命名形态（驼峰/下划线），取值域见 `_is_derived_line`。
_SIDECHAIN_FLAG_KEYS: tuple[str, ...] = ("isSidechain", "is_sidechain")
_PARENT_REF_KEYS: tuple[str, ...] = ("parent_tool_use_id", "parentToolUseId")

_FIELD_NOT_PRESENT = object()
#: 「声明了该字段但形态不可采信」的哨兵：与「没有该字段」和「有可用值」三者互斥。
_SHAPE_REJECTED = object()


def _first_present(mapping: dict[str, Any], keys: tuple[str, ...]) -> Any:
    """按 `keys` 顺序返回第一个**存在**的字段的原始值，都没有时返回 `_FIELD_NOT_PRESENT`。

    用哨兵而非 `None`：字段存在但取值为 `null` 与字段缺席在降级登记上不同（前者是声明了却
    给不出可用值）。
    """
    for key in keys:
        if key in mapping:
            return mapping[key]
    return _FIELD_NOT_PRESENT


def _has_field(mapping: dict[str, Any], keys: tuple[str, ...]) -> bool:
    """`keys` 中任一字段存在（不论取值）——用于区分「没声明」与「声明了但不可用」。"""
    return any(key in mapping for key in keys)


def _reconcile_alias_values(
    mapping: dict[str, Any], keys: tuple[str, ...]
) -> tuple[Any, bool]:
    """同层别名键的**实质一致性**核对，返回 `(值, 是否矛盾)`。

    `_first_present` 先到先得会把「同时声明两个别名且取值不同」读成单一事实，掩盖数据自身的
    矛盾（`{"session_id": "a", "sessionId": "b"}` 里挑一个当权威没有依据）。因此多个别名都存在
    且原始值互不相同时返回 `(_FIELD_NOT_PRESENT, True)`：调用方按「有值但不可采信」降级。
    只有一个别名存在、或各别名取值相同，则照常给值（`conflict=False`）。
    """
    values = [mapping[key] for key in keys if key in mapping]
    if not values:
        return _FIELD_NOT_PRESENT, False
    distinct: list[Any] = []
    for value in values:
        if not any(value == seen for seen in distinct):
            distinct.append(value)
    if len(distinct) > 1:
        return _FIELD_NOT_PRESENT, True
    return values[0], False


def _as_text(value: Any, max_chars: int | None = None) -> str | None:
    """把可选值收成短文本：非字符串、空白、或超长都返回 `None`（不截断成可用前缀冒充）。"""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    if max_chars is not None and len(stripped) > max_chars:
        return None
    return stripped


def _as_identifier(
    value: Any,
    max_chars: int,
) -> tuple[str | None, object]:
    """闭合形态门：返回 `(可用值, 状态)`，状态是 `None`（缺席/空白/非字符串）、
    `_SHAPE_REJECTED`（有值但形态不可采信）或 `""`（可用）。

    长度超限按「有值但不可采信」处理：标识字段的路径形态往往就是超长串，把它当「没声明」会让
    调用方误以为归属证据完整。判否是**整体**的：不做前缀保留，因为前缀仍会泄露原值片段。
    """
    if value is _FIELD_NOT_PRESENT or value is None:
        return None, None
    if not isinstance(value, str):
        return None, _SHAPE_REJECTED
    stripped = value.strip()
    if not stripped:
        return None, None
    if len(stripped) > max_chars:
        return None, _SHAPE_REJECTED
    if stripped.startswith(".") or not set(stripped) <= IDENTIFIER_SAFE_CHARS:
        return None, _SHAPE_REJECTED
    return stripped, ""


def _as_role(value: Any) -> str | None:
    """角色/类型的小写归一：非字符串、空白、超长一律 `None`。

    折叠长度到 `MAX_MATCH_KEY_CHARS` 是为了让后续集合判定的哈希成本有界。
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if not candidate or len(candidate) > MAX_MATCH_KEY_CHARS:
        return None
    return candidate


def _is_oversized_text(value: Any) -> bool:
    """是否是「超长字符串」：用于把不可识别的取值与缺失/非字符串区分开登记。"""
    return isinstance(value, str) and len(value) > MAX_MATCH_KEY_CHARS


def _declared_but_unusable(status: object) -> bool:
    """形态门状态是否表示「声明了值但不能采信」。"""
    return status is _SHAPE_REJECTED


def _bounded_text(value: str) -> tuple[str, bool]:
    """正文按 `MAX_TEXT_BLOCK_CHARS` 取前缀；返回 `(保留文本, 是否发生截断)`。"""
    if len(value) <= MAX_TEXT_BLOCK_CHARS:
        return value, False
    return value[:MAX_TEXT_BLOCK_CHARS], True


def _flag_claim(value: Any) -> tuple[bool | None, bool]:
    """把派生标记的原始值收成 `(布尔结论, 是否无法解释)`。

    取值域是**明确列出**的：布尔 `True`/`False`，以及去空白、大小写折叠后等于 `"true"`/`"false"`
    的字符串（原始长度须 ≤ `MAX_MATCH_KEY_CHARS`，与角色/类型键同一长度门）。缺席与单独的
    `null` 返回 `(None, False)`——那是「没有声明」，不是「声明为假」。其余取值（数字、容器、
    空白串、`"yes"` 一类）返回 `(None, True)`：本层没有与之核对过的取值域，扩张解释会把
    不受控的行当成「已确认为主流」。

    布尔判定**不看 Python 相等**：`False == 0` 不能让数字 `0` 借道通过成合法假值。
    """
    if value is _FIELD_NOT_PRESENT or value is None:
        return None, False
    if isinstance(value, bool):
        return value, False
    if isinstance(value, str):
        if len(value) > MAX_MATCH_KEY_CHARS:
            return None, True
        folded = value.strip().casefold()
        if folded == "true":
            return True, False
        if folded == "false":
            return False, False
        return None, True
    return None, True


def _derived_flag_claim(payload: dict[str, Any]) -> bool:
    """sidechain 布尔别名的**存在、合法性与共识**判定：返回是否按派生行跳过。

    不直接依赖原始值的 Python 相等（`False == 0` 不能让非法数字借道通过），也不先到先得：
    先看每个别名的原始类型，再对合法语义求共识。任一别名无法解释（数字、容器、空白、
    非法字符串、超长串），或两个别名都声明且结论不同（`true`/`false` 矛盾、`null` 与明确
    布尔值不是同一声明），都保守当成派生行跳过。布尔 `True` 与字符串 `"true"` 是同一声明。
    只有单独一个 `null`（或两个别名都是 `null`）等于没声明，主流行不受影响。
    """
    declarations: list[bool | None] = []
    for key in _SIDECHAIN_FLAG_KEYS:
        if key not in payload:
            continue
        claim, unexplainable = _flag_claim(payload[key])
        if unexplainable:
            return True
        declarations.append(claim)
    if not declarations:
        return False
    distinct: list[bool | None] = []
    for claim in declarations:
        # `bool`/`None` 都是单例，用 `is` 比较避开 `False == 0` 一类的隐性相等。
        if not any(claim is seen for seen in distinct):
            distinct.append(claim)
    if len(distinct) > 1:
        return True
    return distinct[0] is True


@dataclass(frozen=True)
class ClaudeHeaderInfo:
    """`system` 头部行的解析结论（原值只作对照，不外出的字段一律不写进记录）。

    `cwd`/`version`/`subtype` 的取值集合未与真实数据核对；`trusted` 表示本次头部是否满足
    本层钉死的采信门槛（`subtype` 为 `init`、会话标识与 cwd 都可用、且不与任何外部断言矛盾）。
    """

    session_id: str | None = None
    cwd: str | None = None
    version: str | None = None
    subtype: str | None = None
    line_no: int | None = None
    seen: bool = False
    trusted: bool = False


class ClaudeLineParser:
    """Claude Code CLI JSONL 行流解析器：逐行喂入，产出 0..n 条标准记录并累计质量计数。

    典型用法（调用方已自行完成授权、发现、打开等前置动作；会话标识断言来自
    `<session-id>.jsonl` 目录文件名，项目断言来自外部 cwd 证据）::

        parser = ClaudeLineParser(
            stream_label=controlled_label,
            session_id=expected_id,   # 目录文件名里的 session id
            project=external_cwd,     # 行外来源的 cwd 断言
        )
        for record in parser.feed(lines):
            ...                       # 时间/项目/关键词过滤由 `query.py` 在协调层完成
        parser.finish()
        parser.stats                  # 计数与原因码，供覆盖状态使用；不含原文

    一次实例对应一条会话行流且至多消费 `MAX_LINES_PER_STREAM` 行：`system` 头部只解析一次，其
    会话标识沿用给后续记录；头部不再可信（subtype 不认识、与别的头部矛盾、标识形态不可采信）时，
    由它支撑的归属一并收回。编码目录名**不是**入参：有损编码不能反推项目（DES-INC-05）。
    参数 `source` 只为与其它适配器保持调用形状，实际值恒为 `SOURCE_CLAUDE`；传其它非空值
    `ValueError`。`session_id`/`project` 是外部断言：本层不把它们写回头部字段，也不在缺失头部时
    拿断言冒充头部证据。
    """

    def __init__(
        self,
        *,
        stream_label: str | None = None,
        session_id: str | None = None,
        project: str | None = None,
        source: str | None = SOURCE_CLAUDE,
    ) -> None:
        if source is not None:
            # 严格门控：非字符串、空白、超长一律 `ValueError`。早先只比对 `_as_text` 的
            # 归一结果，让 `source=123` 与超长串都得到 `None` 而绕过等值检查，把「伪造来源」
            # 变成静默放行。
            if not isinstance(source, str):
                raise ValueError(
                    f"source must be a string or None, got {type(source).__name__}"
                )
            stripped_source = source.strip()
            if (
                not stripped_source
                or len(stripped_source) > MAX_MATCH_KEY_CHARS
                or stripped_source != SOURCE_CLAUDE
            ):
                raise ValueError(
                    "ClaudeLineParser records always carry the fixed source "
                    f"'{SOURCE_CLAUDE}'"
                )
        self._source = SOURCE_CLAUDE
        self._stream_label = sanitize_stream_label(stream_label)
        # 外部断言只过长度/空白门（调用方是受控侧），但同样不能带路径分隔符外出：
        # 记录里的 session_id/project 必须与数据侧走同一道闭合字符集门。
        asserted_session, asserted_status = _as_identifier(
            session_id, MAX_SESSION_ID_CHARS
        )
        if _declared_but_unusable(asserted_status):
            raise ValueError(
                "the asserted session id must satisfy the closed identifier shape gate"
            )
        self._expected_session_id = asserted_session
        asserted_project = _as_text(project, MAX_PROJECT_VALUE_CHARS)
        if project is not None and asserted_project is None:
            raise ValueError(
                "the asserted project must be a non-blank string within "
                f"MAX_PROJECT_VALUE_CHARS ({MAX_PROJECT_VALUE_CHARS})"
            )
        self._asserted_project = asserted_project

        self._stats = ParseStats()
        self._header = ClaudeHeaderInfo()
        self._line_no = 0
        self._project = self._asserted_project
        self._project_quality = (
            ProjectQuality.CALLER_ASSERTED
            if self._asserted_project is not None
            else ProjectQuality.UNKNOWN
        )
        self._project_conflict = False
        self._observed_line_cwd: str | None = None
        self._session_id_conflict = False
        self._sidechain_skipped_lines = 0
        self._line_limit_exceeded = False
        self._finished = False

    # --- 只读暴露面 -------------------------------------------------------------

    @property
    def stats(self) -> ParseStats:
        """累计计数与原因码（不含原文）。"""
        return self._stats

    @property
    def header(self) -> ClaudeHeaderInfo:
        """最近一次采信的 `system` 头部结论；`seen=False` 表示整流没有可用头部。"""
        return self._header

    @property
    def session_id(self) -> str | None:
        """**已核实**的会话标识：头部与外部断言两份证据字面一致时才给值（`pi` 同型）。"""
        return self._verified_session_id()

    @property
    def project(self) -> str | None:
        """当前采信的项目归属；冲突或未确立时为 `None`。"""
        return self._project

    @property
    def asserted_project(self) -> str | None:
        """外部 cwd 断言原值（供调用方对照，不与采信值混用）。"""
        return self._asserted_project

    @property
    def project_conflict(self) -> bool:
        """是否发生过项目证据矛盾（区别于「本来就没有项目证据」）。"""
        return self._project_conflict

    @property
    def project_quality(self) -> ProjectQuality:
        """项目归属的证据等级。"""
        return self._project_quality

    @property
    def session_id_conflict(self) -> bool:
        """是否发生过会话标识矛盾（粘性；置位后整流不再产正文）。"""
        return self._session_id_conflict

    @property
    def sidechain_skipped_lines(self) -> int:
        """按派生会话证据跳过的行数：与「矛盾行拒收」分列，不并入会话身份结论。"""
        return self._sidechain_skipped_lines

    # --- 生命周期 ---------------------------------------------------------------

    def finish(self) -> None:
        """收尾：登记整流级缺失（无头部、项目未确立），幂等。"""
        if self._finished:
            return
        self._finished = True
        if not self._header.seen:
            self._stats.note(IssueCode.NO_SESSION_HEADER)
        if not self._project_quality.sourced:
            self._stats.note(IssueCode.UNKNOWN_PROJECT)

    def feed(self, lines: Iterable[str | bytes]) -> Iterator[StandardRecord]:
        """消费整条行流并逐条产出记录；迭代结束自动 `finish()`。

        传整块 `str`/`bytes` 会被拒：那会让本层按「一整行」解析一个多行载荷，行号与降级登记
        都失去意义。
        """
        if isinstance(lines, (str, bytes, bytearray)):
            raise TypeError(
                "feed requires an iterable of lines, not a whole str/bytes payload"
            )
        if self._finished:
            raise RuntimeError("parser is finished; create a new instance for a new stream")
        return self._iterate(lines)

    def feed_line(self, line: str | bytes) -> tuple[StandardRecord, ...]:
        """喂入一行，返回该行产出的记录（0..n）。"""
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

    def _iterate(self, lines: Iterable[str | bytes]) -> Iterator[StandardRecord]:
        """消费行流；超限判定之后**不再取下一个元素**。

        `for` 结构会先把下一行拉到手才检查停止标记：第 M+1 行置位超限之后还会再取第 M+2 行。
        这里把门放在 `next()` 之前（显式迭代器 + while），消费口径为：最多解析 M 行，只有
        确实取得第 M+1 个元素时才判有超限并计一次 `max_stream_lines_exceeded`（该探测元素不
        计 `lines_seen`、不解码），绝不再拉取第 M+2 行。恰好 M 行且自然结束不报超限——
        「达到上限」不等于「存在未扫内容」。
        """
        try:
            iterator = iter(lines)
            while not self._line_limit_exceeded:
                try:
                    line = next(iterator)
                except StopIteration:
                    break
                yield from self.feed_line(line)
        finally:
            self.finish()

    # --- 行分派 -----------------------------------------------------------------

    def _dispatch(self, payload: dict[str, Any]) -> tuple[StandardRecord, ...]:
        """按行 `type` 分派：消息行、`system` 头部行，其余一律「不认识」。

        没有 pi 的无 `type` 宽识分支：形态识别规则未经真实数据核对时，不认领任何形态。
        """
        raw_type = payload.get("type")
        if _is_oversized_text(raw_type):
            self._stats.note(IssueCode.UNKNOWN_EVENT)
            return ()
        event_type = _as_role(raw_type)
        if event_type in MESSAGE_EVENT_TYPES:
            return self._handle_message_line(payload, event_type)
        if event_type in HEADER_EVENT_TYPES:
            return self._handle_header(payload)
        self._stats.note(IssueCode.UNKNOWN_EVENT)
        return ()

    def _handle_header(self, payload: dict[str, Any]) -> tuple[StandardRecord, ...]:
        """`system` 行：按 `subtype` 分流，只有 `init` 可能被采信为会话起点。

        分类门先于头部门：`compact` 一类已知但不是起点的系统行不能算「迟到的头部」，
        缺失/未登记的 subtype 则按不认识处理——两种结论不混用。
        同层别名键（`subtype`/`sub_type`、`session_id`/`sessionId`/`session-id`、`cwd` 与
        `version` 的各形态）取值互相矛盾时，一律降为「有值但不可采信」，不先到先得。
        """
        if self._is_derived_line(payload):
            return ()
        subtype_value, subtype_conflicted = _reconcile_alias_values(
            payload, _SUBTYPE_KEYS
        )
        subtype = _as_role(_SHAPE_REJECTED if subtype_conflicted else subtype_value)
        if subtype not in HEADER_SUBTYPES:
            if subtype in KNOWN_SYSTEM_SUBTYPES:
                self._stats.note(IssueCode.SKIPPED_ROLE)
            else:
                self._stats.note(IssueCode.UNKNOWN_EVENT)
            return ()

        session_value, session_conflicted = _reconcile_alias_values(
            payload, _SESSION_ID_KEYS
        )
        session_id, session_status = _as_identifier(
            _SHAPE_REJECTED if session_conflicted else session_value,
            MAX_SESSION_ID_CHARS,
        )
        cwd_value, cwd_conflicted = _reconcile_alias_values(payload, _CWD_KEYS)
        cwd = _as_text(
            _SHAPE_REJECTED if cwd_conflicted else cwd_value,
            MAX_PROJECT_VALUE_CHARS,
        )
        cwd_present = _has_field(payload, _CWD_KEYS)
        version_value, version_conflicted = _reconcile_alias_values(
            payload, _VERSION_KEYS
        )
        version = _as_text(
            _SHAPE_REJECTED if version_conflicted else version_value,
            MAX_HEADER_VERSION_CHARS,
        )

        if not self._header.seen:
            trusted = True
            if not _has_field(payload, _VERSION_KEYS):
                self._stats.note(IssueCode.MISSING_HEADER_VERSION)
                trusted = False
            elif version is None:
                # 声明了版本但给不出可用值：形态未与真实数据核对，不据此采信。
                self._stats.note(IssueCode.UNSUPPORTED_HEADER_VERSION)
                trusted = False
            if _declared_but_unusable(session_status):
                # 标识字段是路径形态：有值但不能采信，整条流归属存疑（整体判否）。
                self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
                self._session_id_conflict = True
                trusted = False
            elif session_id is None and _has_field(payload, _SESSION_ID_KEYS):
                self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
                trusted = False
            if cwd_present and cwd is None:
                # 声明了 cwd 但给不出可用值（非字符串、空白、超长、同层别名矛盾）。
                self._stats.note(IssueCode.INVALID_HEADER_CWD)
                trusted = False
            if (
                session_id is not None
                and self._expected_session_id is not None
                and session_id != self._expected_session_id
            ):
                self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
                self._session_id_conflict = True
                trusted = False
            # 跨行 cwd 核对必须在**采用项目之前**完成：消息行先声明的 cwd、外部断言与已有
            # 头部 cwd 都是基准。判否通道与 `trusted` 无关——版本缺失只降低采信度，不能把
            # 一份合法的 cwd 声明从矛盾核对里摘出去。
            if cwd is not None:
                self._header_cwd_conflicts(cwd)
            self._header = ClaudeHeaderInfo(
                session_id=session_id,
                cwd=cwd,
                version=version,
                subtype=subtype,
                line_no=self._line_no,
                seen=True,
                trusted=trusted,
            )
            self._adopt_header_project()
            return ()

        self._stats.note(IssueCode.LATE_SESSION_HEADER)
        conflicting = False
        if _declared_but_unusable(session_status):
            # 后来的头部声明了标识却给不出可用值（路径形态、同层别名矛盾）：与首个头部同一道
            # 形态门。这类值不能参与值间比较（解析结果是 `None`），否则「首个头部没有
            # session_id、重复头部带路径形态 ID」会被读成两份缺席而不留任何代价。归属证据本身
            # 被污染 → 粘性判否，与值间矛盾同一出口，每个头部只计一次。
            self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
            self._session_id_conflict = True
            conflicting = True
        elif self._header.session_id != session_id:
            self._stats.note(IssueCode.HEADER_SESSION_ID_MISMATCH)
            self._session_id_conflict = True
            conflicting = True
        if cwd_present:
            if cwd is None:
                # 后来的头部声明了 cwd 却给不出可用值：与首行头部同一道形态降级。畸形值不是
                # 「另一个可用的 cwd 声明」，因此只收回头部采信，不记成值间矛盾。
                self._stats.note(IssueCode.INVALID_HEADER_CWD)
                conflicting = True
            elif self._header_cwd_conflicts(cwd):
                conflicting = True
        if (
            self._header.version is not None
            and version is not None
            and self._header.version != version
        ):
            self._stats.note(IssueCode.CONFLICTING_HEADER_VERSION)
            conflicting = True
        if conflicting and self._header.trusted:
            self._header = replace(self._header, trusted=False)
        self._adopt_header_project()
        return ()

    def _handle_message_line(
        self,
        payload: dict[str, Any],
        event_type: str,
    ) -> tuple[StandardRecord, ...]:
        """消息行：`type` 给出角色，正文只来自 `message` 信封。"""
        if self._is_derived_line(payload):
            return ()
        self._reconcile_line_cwd(payload)
        envelope = payload.get("message")
        if not isinstance(envelope, dict):
            self._stats.note(IssueCode.MISSING_MESSAGE_ENVELOPE)
            return ()
        return self._handle_message(payload, envelope, event_type)

    def _handle_message(
        self,
        outer: dict[str, Any],
        envelope: dict[str, Any],
        event_type: str,
    ) -> tuple[StandardRecord, ...]:
        """一行消息 → 0..n 条标准记录；任何归属或角色不确定都拒产并如实登记。"""
        record_issues: list[IssueCode] = []
        session_id, verified, rejected = self._resolve_session_id(outer, envelope)
        if rejected:
            return ()
        if session_id is None:
            self._stats.note(IssueCode.MISSING_SESSION_ID)
            record_issues.append(IssueCode.MISSING_SESSION_ID)
        elif not verified:
            self._stats.note(IssueCode.SESSION_ID_UNVERIFIED)
            record_issues.append(IssueCode.SESSION_ID_UNVERIFIED)

        role = self._resolve_role(envelope, event_type)
        if role is None:
            return ()

        timestamp, time_quality = self._resolve_timestamp(outer, envelope)
        if time_quality is not TimeQuality.EXACT:
            issue = TIMESTAMP_ISSUES[time_quality]
            self._stats.note(issue)
            record_issues.append(issue)

        blocks, lost_content, content_issues = self._content_blocks(envelope)
        record_issues.extend(content_issues)
        if blocks is None:
            self._stats.note(IssueCode.INVALID_CONTENT_SHAPE)
            return ()
        if not blocks:
            if not lost_content:
                self._stats.note(IssueCode.NO_TEXT_CONTENT)
            return ()

        if not self._project_quality.sourced:
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

    # --- 归属判定 ---------------------------------------------------------------

    def _resolve_role(self, envelope: dict[str, Any], event_type: str) -> str | None:
        """角色：行 `type` 是本来源的角色证据，`message.role` 若同时存在必须一致。

        **只有字段真的缺席**才回落到 `event_type`：字段存在但 `_as_role` 给不出可用值（显式
        `null`、数字、容器、空白、非法形态）是「声明了一个本层解释不了的角色」，必须记
        `unknown_role` 后拒产，不能当成「没声明」而拿行 type 冒充已理解的角色（只产正文的
        角色集合是闭合的）。这里不置项目/会话粘性冲突。
        两处都有可用值但不一致 → 归属不确定，同样按 `unknown_role` 拒产（不选一个「更可能」的）。
        """
        declared_raw = _first_present(envelope, _ROLE_KEYS)
        if declared_raw is _FIELD_NOT_PRESENT:
            role = event_type
        else:
            declared = _as_role(declared_raw)
            if declared is None:
                self._stats.note(IssueCode.UNKNOWN_ROLE)
                return None
            role = declared
            if role != event_type:
                self._stats.note(IssueCode.UNKNOWN_ROLE)
                return None
        if role not in TEXT_ROLES:
            # 本层只在 TEXT_ROLES 上产正文；其余角色（含 system/tool 一类）按未核实角色跳过。
            self._stats.note(IssueCode.UNKNOWN_ROLE)
            return None
        return role

    def _resolve_session_id(
        self,
        outer: dict[str, Any],
        envelope: dict[str, Any],
    ) -> tuple[str | None, bool, bool]:
        """三路核对会话标识，返回 `(值, 是否已核实, 是否整条拒产)`（`pi` 同型）。

        任一声明值为路径形态（有值但不能采信）→ 置粘性矛盾并整条拒产：那说明归属证据本身被
        污染，不能靠其余证据「补票」。
        """
        inline, inline_status = self._inline_session_id(outer, envelope)
        if self._session_id_conflict:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            return None, False, True
        if _declared_but_unusable(inline_status):
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            self._session_id_conflict = True
            return None, False, True
        # 判否通道：头部标识**只要过了形态门就无条件参与矛盾核对**，不以 `header.trusted`
        # 豁免——版本缺失只能降低采信度，不能把一份合法的标识声明从核对里摘出去（否则
        # 头部 ID=S、消息 ID=T 会被当作「只有一份证据」而照常产出 T）。
        claims = [
            value
            for value in (self._expected_session_id, self._header.session_id, inline)
            if value is not None
        ]
        if len(set(claims)) > 1:
            self._stats.note(IssueCode.SESSION_ID_MISMATCH)
            self._session_id_conflict = True
            return None, False, True
        # 选值与「已核实」票数仍只用可信证据：合法但不可信的头部既不能单独提供记录标识，
        # 也不给验证票数补票（`_verified_session_id` 的可信门同样不改）。
        candidates = [
            value
            for value in (
                self._expected_session_id,
                self._header.session_id if self._header.trusted else None,
                inline,
            )
            if value is not None
        ]
        if not candidates:
            return None, False, False
        return candidates[0], len(candidates) >= 2, False

    def _inline_session_id(
        self,
        outer: dict[str, Any],
        envelope: dict[str, Any],
    ) -> tuple[str | None, object]:
        """消息层的会话标识（行级优先，再 `message` 内），过闭合形态门。

        两处都声明但值不同 → 状态按不可采信处理（不先到先得）。
        """
        holders = (outer, envelope)
        values: list[tuple[str | None, object]] = []
        for holder in holders:
            raw, conflicted = _reconcile_alias_values(
                holder, _MESSAGE_SESSION_ID_KEYS
            )
            if raw is _FIELD_NOT_PRESENT and not conflicted:
                continue
            values.append(
                _as_identifier(
                    _SHAPE_REJECTED if conflicted else raw, MAX_SESSION_ID_CHARS
                )
            )
        usable = [
            value
            for value, status in values
            if status == "" and value is not None
        ]
        rejected = any(_declared_but_unusable(status) for _, status in values)
        if rejected or len(set(usable)) > 1:
            # 有值但形态不可采信、或多份可用值互不相同：都不先到先得，整条按不可采信处理。
            return None, _SHAPE_REJECTED
        if usable:
            return usable[0], ""
        return None, None

    def _verified_session_id(self) -> str | None:
        """只有可信头部与外部断言字面一致时才暴露「已核实的会话标识」。"""
        if self._session_id_conflict:
            return None
        header_id = self._header.session_id if self._header.trusted else None
        if header_id is not None and self._expected_session_id is not None:
            return header_id if header_id == self._expected_session_id else None
        return None

    def _adopt_header_project(self) -> None:
        """无项目矛盾时按当前可信度采用项目归属（`pi` 同型：断言不冒充头部证据、不写回头部）。

        矛盾判定统一走 `_header_cwd_conflicts`，本函数不再自行置冲突：同一矛盾因此只有
        一个登记位置。粘性冲突之下项目恒为 `None`、质量恒为 `UNKNOWN`，后续一致证据不恢复。
        合法但**不可信**的头部 cwd 不升格为 `TRUSTED_HEADER_CWD`（与外部断言一致只是「对得上」，
        不是头部被采信），也不把单独的消息 cwd 当可信项目。
        """
        if self._project_conflict:
            self._project = None
            self._project_quality = ProjectQuality.UNKNOWN
            return
        header_cwd = self._header.cwd if self._header.trusted else None
        if header_cwd is not None:
            self._project = header_cwd
            self._project_quality = ProjectQuality.TRUSTED_HEADER_CWD
            return
        if self._asserted_project is not None:
            self._project = self._asserted_project
            self._project_quality = ProjectQuality.CALLER_ASSERTED
            return
        self._project = None
        self._project_quality = (
            ProjectQuality.UNVERIFIED_HEADER_CWD
            if self._header.cwd is not None or self._observed_line_cwd is not None
            else ProjectQuality.UNKNOWN
        )

    def _header_cwd_conflicts(self, cwd: str) -> bool:
        """把新头部的可用 cwd 与已有可用项目证据逐项核对；矛盾时降级只记一次。

        基准集合是**可用值**：已采信头部 cwd、外部断言、已确立项目、已见的行内 cwd。只有双方
        都是可用短字符串才比较值，畸形/空值由 `invalid_header_cwd` 交代，不与合法值并列成
        「两个互斥的 cwd 声明」。判否**独立于 `header.trusted`**：不可采信头部照样能为「这个流
        里出现过另一个 cwd」作证（DES-INC-05 的跨行 cwd 矛盾粘性降级不以可信度为条件）。
        同一个 header 的同一矛盾即使命中多个基准也只计一次，不在本函数与
        `_adopt_header_project` 双计。
        """
        if self._project_conflict:
            # 粘性降级已经发生：项目已清空，重复证据不再计码。
            return False
        for baseline in (
            self._header.cwd,
            self._asserted_project,
            self._project,
            self._observed_line_cwd,
        ):
            if baseline is not None and baseline != cwd:
                self._degrade_project_conflict()
                return True
        return False

    def _degrade_project_conflict(self) -> None:
        """项目证据矛盾的**唯一**降级出口：记一次码、粘性置位、清空项目、质量降为未知。

        集中一处登记，避免同一矛盾在多个通道双计；矛盾只能让归属更不确定，不能被外部断言或
        后续一致消息恢复，也不能反过来置会话标识冲突。
        """
        self._stats.note(IssueCode.CONFLICTING_HEADER_CWD)
        self._project_conflict = True
        self._project = None
        self._project_quality = ProjectQuality.UNKNOWN

    def _reconcile_line_cwd(self, payload: dict[str, Any]) -> None:
        """行内 cwd 只作**核对**通道：与已采信的项目、外部断言或已见的 cwd 矛盾 → 粘性降级。

        消息行的 cwd 没得头部地位，因此本通道只会让归属更不确定，不会把一个未经核对的
        值升格成可归因的项目（DES-INC-05：行内 cwd 与外部断言两路核对，编码目录名不算证据）。
        已产出的记录不回改：矛盾只影响后续行的归属。
        声明了 cwd 但给不出可用值（非字符串、空白、超 `MAX_PROJECT_VALUE_CHARS`、同层别名
        矛盾）当场计 `invalid_header_cwd`：静默返回会让不可控输入在计数里零代价消失。
        """
        if self._project_conflict:
            return
        raw, conflicted = _reconcile_alias_values(payload, _CWD_KEYS)
        if raw is _FIELD_NOT_PRESENT:
            if conflicted:
                # 同层别名（`cwd`/`workingDirectory`/`working_directory`）互斥：字段本身矛盾，
                # 按「有值但形态不可采信」降级，不先到先得。
                self._stats.note(IssueCode.INVALID_HEADER_CWD)
            return
        if raw is None:
            # 取值为 null：调用方只是否认了这个字段有值，核对通道缺位，由记录逐条的
            # `project_unverified` 与整流 `unknown_project` 表达，不在本通道双计。
            return
        value = _as_text(raw, MAX_PROJECT_VALUE_CHARS)
        if value is None:
            # 非字符串或超 `MAX_PROJECT_VALUE_CHARS`：不可控输入必须留下代价，不得静默消失。
            self._stats.note(IssueCode.INVALID_HEADER_CWD)
            return
        if self._asserted_project is not None:
            baseline = self._asserted_project
        elif self._project is not None:
            baseline = self._project
        elif self._header.cwd is not None:
            baseline = self._header.cwd
        else:
            baseline = self._observed_line_cwd
        if baseline is None:
            self._observed_line_cwd = value
            self._project_quality = ProjectQuality.UNVERIFIED_HEADER_CWD
            return
        if value != baseline:
            self._degrade_project_conflict()

    def _is_derived_line(self, payload: dict[str, Any]) -> bool:
        """派生/子代理会话行的识别与处置：跳过、不产正文、不确立独立会话。

        证据是布尔标记为真、父引用非空、或**无法解释的派生声明**（布尔别名取值非法、两别名
        结论矛盾）。三类行都计 `unknown_event` 使整流覆盖不完整（原因码集合是本包的闭合枚举，
        `IssueCode` 无「派生跳过」类），真实构成由 `sidechain_skipped_lines` 明示：这是按
        不可采信派生标记跳过的计数，不声称已经核实为真实子代理。这与「矛盾行拒收」不同：
        派生证据不否定整条流的归属。
        父引用**有值但不可采信**（非字符串、空白外的超长串）同样按派生跳过：担心子代理逃逸成
        主会话正文，不得把不可核实的派生标记当成「没有父引用」。同一行同时有 flag 与父引用
        问题时仍只计一次跳过。
        """
        flag_derived = _derived_flag_claim(payload)
        parent, parent_conflicted = _reconcile_alias_values(payload, _PARENT_REF_KEYS)
        if parent is _FIELD_NOT_PRESENT or parent is None:
            has_parent_claim = False
        elif isinstance(parent, str) and not parent.strip():
            # 空白串等于没给出父引用：与 null/缺席同类，不得据此把主流行判成派生行。
            has_parent_claim = False
        else:
            # 非空父引用（可用值）与**形态/长度不可采信**的父引用（非字符串、超
            # `MAX_MATCH_KEY_CHARS`）在此同走一条结论：后者早先因 `_as_text` 返回 `None`
            # 而被当成「没有父引用」，让不受控的子代理行逃逸成主会话正文。
            has_parent_claim = True
        derived = flag_derived or has_parent_claim or parent_conflicted
        if not derived:
            return False
        self._sidechain_skipped_lines += 1
        self._stats.note(IssueCode.UNKNOWN_EVENT)
        return True

    # --- 内容/时间 --------------------------------------------------------------

    def _resolve_timestamp(
        self,
        outer: dict[str, Any],
        envelope: dict[str, Any],
    ) -> tuple[datetime | None, TimeQuality]:
        """时刻只取行顶层的 `timestamp`/`createdAt`/`created_at`；`message` 内不作为回落。

        信封里的时间字段属于另一个对象的元数据，把「顶层没有」读成「信封里有」是拿另一个
        值冒充消息时刻，因此 envelope 只作为接口参数保留（调用形状不变），不进入候选集合。
        顶层同层别名用 `_reconcile_alias_values` 核对：取值互不相同（含一个 `null` 加一个有效
        值）就是同层声明矛盾，直接返回 `(None, INVALID)`——最小保守口径只接受**原值相同**，
        不自创跨格式时间等价规则（同一时刻的不同编码是否等价需另待契约确认）。
        顶层真正缺席（或只有 `null`）→ `missing`，不回填解析时刻，那会把「没有这个值」
        变成伪造的时刻。长度、无时区与量级守卫仍由 `normalize_timestamp` 负责；原因码由
        `_handle_message` 统一登记一次，本函数不 `note`。
        """
        del envelope  # 保留私有调用接口；信封时间不作为行级时间的候选。
        raw, conflicted = _reconcile_alias_values(outer, _TIMESTAMP_KEYS)
        if conflicted:
            return None, TimeQuality.INVALID
        if raw is _FIELD_NOT_PRESENT:
            return None, TimeQuality.MISSING
        return normalize_timestamp(raw)

    def _content_blocks(
        self, envelope: dict[str, Any]
    ) -> tuple[tuple[str, ...] | None, bool, tuple[IssueCode, ...]]:
        """正文块提取：认 `content` 数组里的显式 `text` 块与**字符串形态整串**，
        返回 `(文本元组, 是否丢内容, 行级码)`。

        字符串形态（如 `{"role": "user", "content": "hello world"}`）是 stream-json 的合法纯文本
        写法，整串按单块正文取用，并走与数组内 `text` 块同一道 `MAX_TEXT_BLOCK_CHARS` 截断与
        `text_block_truncated` 登记；空/纯空白字符串是「已理解的无正文」（`no_text_content`）。
        单个对象一类不可解释的形态仍不认领：那会把「形态不认识」记成「内容为空」。

        第三个返回值是**本行的内容降级码集合**（按首次出现顺序、已去重）：除块数上限与截断之外，
        块级的 `invalid_content_shape`/`unknown_block_type`/`non_string_text_block` 也一并交出，
        由 `_handle_message` 附到该行**每条保留记录**的 `issues` 上——只产出一条记录的多块行不能
        把同批坏块丢在统计里、让单条记录看起来干净。统计仍按**每次出现**计，集合去重只作用于记录；
        形态整体不可解释的路径仍返回 `(None, True, ())`，由调用方记一次，不去双计。
        """
        content = envelope.get("content", _FIELD_NOT_PRESENT)
        if content is _FIELD_NOT_PRESENT or content is None:
            return None, True, ()
        if isinstance(content, str):
            if not content.strip():
                return (), False, ()
            bounded, truncated = _bounded_text(content)
            str_issues: list[IssueCode] = []
            if truncated:
                self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                str_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
            return (bounded,), False, tuple(str_issues)
        if not isinstance(content, (list, tuple)):
            # 形状不可解释的码由调用方统一记一次，避免同一行双计。
            return None, True, ()

        line_issues: list[IssueCode] = []

        def mark(issue: IssueCode) -> None:
            """登记一次内容降级：统计按出现次数计，记录级集合只留首次出现。"""
            self._stats.note(issue)
            if issue not in line_issues:
                line_issues.append(issue)

        candidates = list(content[:MAX_CONTENT_BLOCKS_PER_LINE])
        dropped = len(content) - len(candidates)
        lost_content = bool(dropped)
        if dropped:
            self._stats.note(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)
            line_issues.append(IssueCode.CONTENT_BLOCK_LIMIT_EXCEEDED)

        texts: list[str] = []
        for item in candidates:
            if not isinstance(item, dict):
                mark(IssueCode.INVALID_CONTENT_SHAPE)
                lost_content = True
                continue
            raw_block_type = _first_present(item, _TYPE_KEYS)
            block_type = _as_role(raw_block_type)
            if block_type is None:
                mark(IssueCode.UNKNOWN_BLOCK_TYPE)
                lost_content = True
                continue
            if block_type not in TEXT_BLOCK_TYPES:
                # DES-INC-05：未与真实数据核对的形态一律按不认识处理并计降级。
                # 曾先豁免 `tool_use`/`tool_result`/`thinking`/`image` 为「已理解的省略」（计入
                # NON_PARTIAL_ISSUES 的 known_non_text_block），使纯工具/推理行被伪报成
                # 「完整扫描且无匹配」；该豁免已废弃，改由未知块类型使覆盖不完整。
                mark(IssueCode.UNKNOWN_BLOCK_TYPE)
                lost_content = True
                continue
            body = _first_present(item, _TEXT_KEYS)
            if isinstance(body, str):
                if not body.strip():
                    continue
                bounded, truncated = _bounded_text(body)
                texts.append(bounded)
                if truncated:
                    self._stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
                    if IssueCode.TEXT_BLOCK_TRUNCATED not in line_issues:
                        line_issues.append(IssueCode.TEXT_BLOCK_TRUNCATED)
                continue
            if body is _FIELD_NOT_PRESENT or body is None:
                mark(IssueCode.INVALID_CONTENT_SHAPE)
                lost_content = True
                continue
            mark(IssueCode.NON_STRING_TEXT_BLOCK)
            lost_content = True

        return tuple(texts), lost_content, tuple(line_issues)

    def _decode(self, line: str | bytes) -> str | None:
        """字节/字符串行的有界解码：超限与非 UTF-8 都整行丢弃并登记固定码。"""
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
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                self._stats.note(IssueCode.CORRUPT_LINE)
                return None
            if len(text) > MAX_LINE_CHARS:
                self._stats.note(IssueCode.LINE_TOO_LARGE)
                return None
            return text
        self._stats.note(IssueCode.CORRUPT_LINE)
        return None
