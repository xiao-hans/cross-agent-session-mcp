"""跨 Agent 会话检索 MCP 服务（协议入口）。

按 `docs/spec/04-概要设计说明.md` 的文件映射，本模块承担协议入口：stdio 握手、能力声明、
`tools/list` 与三个只读工具的参数校验。`search_sessions` 与 `read_session_context` 各自可委托给
宿主显式绑定的服务：单个固定批准文件（`PiFileSearchService`/`PiFileContextService`）或有界文件
集合（`PiMultiFileSearchService`/`PiMultiFileContextService`）；默认 app 不绑定服务，也不读取用户
配置或自动发现文件。

当前能力边界：

- `list_sources` 只报告**绑定事实**，不检查用户或项目配置、不探测磁盘：六类必备来源（pi、hermes、
  codex、cursor_agent_cli、dsh、workbuddy）的读取适配器均已接入本服务的查询绑定，状态只随宿主
  绑定在 `ready`/`unavailable` 之间变（`unavailable` 表示本进程未注入该服务，`enabled` 为 false，
  二者都**不**表示未安装/未启用/适配器未编写）；`ready` 只表示已注入有界的批准文件集合或有界的
  批准库集合，不表示整个来源已扫完。dsh 已绑定但解码运行时不可用时报 `error`（绝不报告 ready）；
  cursor_agent_cli 的 GUI 存储读取轴被口径关闭，仍报 `unsupported`。`claude_code_cli` 属扩展
  来源（`docs/spec/03` 口径：默认 disabled、由策略配置启用），不在六类必备来源内，未启用时不接受
  其查询（被点名时只产 disabled 覆盖行，不打开任何文件）。
- `search_sessions` 执行宿主注入的有界服务集合内的查询：按点名来源逐族分发并跨族合并（命中行按
  时间倒序、`limit` 为跨来源总上限），覆盖口径逐族如实上报（pi 集合 `bounded_pi_file_set`、行族
  `bounded_line_file_set:<source>`、workbuddy `bounded_workbuddy_store_set`、多族合并
  `bounded_service_sets`）。客户端不能传路径或文件集合；默认未绑定时安全拒绝。
- `read_session_context` 只接受上一次授权查询发放的不透明引用（`ctxref:` 串）：客户端不能提供
  路径、行号或文件版本基准；它同样只有宿主显式绑定后才可用，默认未绑定时安全拒绝。聚合上下文服务
  按引用的绑定指纹（scope/source/path/session_id 的定长摘要）把它路由回**发放它的那个**文件，路由
  本身不打开任何文件；找不到对应绑定就是 `binding_mismatch`。查询与上下文两个服务必须共用同一个
  `ReferenceLedger` 实例（或由两者都省略的进程内默认账本）且绑定形状一致（同为单文件同为集合），
  `bind_pi_file_context_service`/`bind_pi_multi_file_context_service` 会校验这两点。

日志与本模块返回值都不包含会话原文、查询词、时间字符串或绝对个人路径（DES-SEC-01）。
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from .file_search import PiFileSearchService
from .hermes_aggregate import HermesAggregateSearchService
from .hermes_aggregate_context import HermesAggregateContextService
from .line_search import (
    DSH_SPEC,
    LineAggregateContextService,
    LineAggregateSearchService,
    make_dsh_spec,
)
from .multi_source import FamilyContextEntry, FamilySearchEntry, ServiceRegistry
from .policy import PolicyDenied
from .query import MAX_SOURCES_PER_QUERY
from .references import clear_reference_ledger
from .safe_reader import SafeReadDenied
from .session_context import PiFileContextService
from .session_discovery import PiMultiFileContextService, PiMultiFileSearchService
from .sources import dsh as dsh_source
from .sources import workbuddy as workbuddy_source
from .sources.cursor import SOURCE_CURSOR

SERVER_NAME = "cross-agent-session-mcp"
SERVER_VERSION = "0.0.1"

NOT_IMPLEMENTED_MARK = "未实现"
NOT_IMPLEMENTED_STATUS = "not_implemented"
_UNBOUND_SUFFIX = "：当前未绑定该服务，本构建不自动读取会话存储、用户配置或项目目录。"

# 参数错误信息为固定文案，不回显任何调用方输入（DES-SEC-01）。
_ERR_LIMIT = "参数错误：limit 必须为 1-100 之间的整数。"
_ERR_SOURCES_UNKNOWN = "参数错误：sources 含未支持的来源。"
_ERR_SOURCES_TYPE = "参数错误：sources 必须为来源 ID 字符串列表。"
_ERR_SOURCES_LIMIT = f"参数错误：sources 最多包含 {MAX_SOURCES_PER_QUERY} 项。"
_ERR_SOURCE_UNKNOWN = "参数错误：source 为未支持的来源。"
_ERR_QUERY_WITHOUT_RANGE = "参数错误：省略 query 时必须同时提供 start 与 end。"
_ERR_QUERY_TYPE = "参数错误：query 必须为字符串。"
_ERR_QUERY_BLANK = "参数错误：query 不得为空白字符串。"
_ERR_QUERY_FILTER = "参数错误：查询过滤条件不合法。"
_ERR_TIME_FORMAT = "参数错误：start/end 必须是带时区的 ISO 8601 时间字符串。"
_ERR_TIME_ORDER = "参数错误：start 不得晚于 end。"
_ERR_WINDOW = "参数错误：before/after 必须是 0-10 之间的整数。"
_ERR_SCOPE_EMPTY = "参数错误：scope 必填且不得为空白。"
_ERR_SCOPE_PATH = "参数错误：scope 必须是授权范围标识，不得为路径形态。"
_ERR_PROJECT = "参数错误：project 必须为非空字符串或省略。"
_ERR_REF = "参数错误：session_id/location 必须为非空字符串。"
_ERR_CONTEXT_DENIED = (
    "read_session_context 拒绝：授权或安全读取核对未通过，本次未返回结果。"
)

# 路径形态判据：`~` 或 Windows 盘符只认开头，分隔符认任意位置；
# `.` 与 `..` 是相对路径记号，同样拒绝（它们不构成授权范围标识）。
_PATH_LIKE = re.compile(r"(?:^(?:~|[A-Za-z]:)|[\\/])")
_RELATIVE_SCOPE_TOKENS = (".", "..")


def _check_text(value: Any, err: str) -> None:
    """必填文本参数必须为非空字符串；只报固定文案，不回显输入。"""
    if not isinstance(value, str) or not value.strip():
        raise ToolError(err)


#: 上下文读取窗口上限，同时写进工具说明，供调用方在提交前自我约束。
MAX_CONTEXT_WINDOW = 10


def _check_scope(scope: Any) -> None:
    """校验 scope 为非空、非路径形态的授权范围标识；只报固定错误文案。

    路径形态检查针对去除首尾空白后的值：`~` 与盘符只认开头，若对原值匹配，
    前导空白（如 ``" ~"``、``" C:"``）会使锚点失配而绕过判断。
    """
    if not isinstance(scope, str) or not scope.strip():
        raise ToolError(_ERR_SCOPE_EMPTY)
    stripped = scope.strip()
    if stripped in _RELATIVE_SCOPE_TOKENS or _PATH_LIKE.search(stripped):
        raise ToolError(_ERR_SCOPE_PATH)


def _parse_bound(value: str | None) -> datetime | None:
    """把可选时间边界解析为带时区的 datetime；不接受本地时间，不回填默认时区。"""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ToolError(_ERR_TIME_FORMAT)
    text = value.strip()
    if not text:
        raise ToolError(_ERR_TIME_FORMAT)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ToolError(_ERR_TIME_FORMAT) from None
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise ToolError(_ERR_TIME_FORMAT)
    return parsed


def _check_window(before: Any, after: Any) -> None:
    """校验上下文窗口条数为 0-10 的整数（bool 不算整数）。"""
    for value in (before, after):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolError(_ERR_WINDOW)
        if not 0 <= value <= MAX_CONTEXT_WINDOW:
            raise ToolError(_ERR_WINDOW)


#: 首版必须覆盖的六类来源（PRD 首版范围）。本增量不做任何探测。
REQUIRED_SOURCES = ("hermes", "dsh", "workbuddy", "pi", "cursor_agent_cli", "codex")

#: 对外简称 → 规范来源 ID 的别名表。规范 ID 与适配器产出的记录来源**同一口径**：
#: `sources/claude.py:100` 的 `SOURCE_CLAUDE = "claude_code_cli"` 就是内部键本身，因此
#: 旧简称 `claude_code` 归一为 `claude_code_cli`，而不是把已合法的对外全称映射成仓内
#: 不存在的键（旧方向会让参数校验放行一个 ID、记录产出另一个 ID，来源过滤与 coverage
#: 汇总当场对不上，即 P1-1 要消除的常量/内部键分叉）。
#: `cursor_agent_cli` 已是 `REQUIRED_SOURCES` 中的全称，因此本表不含它——把已合法的
#: 对外 ID 映射成不存在的键只会把有效输入变成校验失败。本表只登记真实需要的扩展来源别名。
_SOURCE_ID_ALIASES = {"claude_code": "claude_code_cli"}

#: 扩展来源（`docs/spec/03`：Claude Code CLI 属扩展来源，默认 disabled，由策略配置
#: 启用）。不在六类必备来源内，因此启用门在归一之后、必备集合判定之前。集合内登记的是
#: 归一后的规范 ID：与 `_SOURCE_ID_ALIASES` 的值、`sources/claude.py` 产出的记录来源
#: 三者同口径。
EXTENDED_SOURCE_IDS = ("claude_code_cli",)


def _normalize_source_id(value: str) -> str:
    """对外来源 ID 归一为内部来源键；未知键原样返回，由 `_check_source_allowed` 判未知。"""
    return _SOURCE_ID_ALIASES.get(value, value)


def _check_source_allowed(value: str, *, unknown_error: str) -> None:
    """来源 ID 校验（09 裁决 P2-3/P3）：归一 → 必备集合或扩展来源。

    扩展来源（`claude_code_cli`）在参数层**放行**（计划 D-4）：适配器与聚合服务已在本构建
    编写，参数门不再当场报「扩展来源未启用」，交由分发器按绑定事实处置——该族未绑定时
    `list_sources` 报 disabled、`search_sessions` 返回 `status=disabled` 覆盖行、
    `read_session_context` 固定拒绝，三者都不读任何配置、不打开任何文件。未启用与
    「已探测过且不支持」的语义分别由覆盖行状态与固定拒绝承载，不再混进参数错误。
    """
    if value in EXTENDED_SOURCE_IDS:
        return
    if value not in REQUIRED_SOURCES:
        raise ToolError(unknown_error)

_READ_ONLY_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

#: 绑定槽位接受的类型：精确类型门控，子类不算（宿主注入对象由本包构造）。
#: 每族各占自己的槽位：跨族共用槽会被类型门当场拒掉，pi 与 Hermes 可同时在场。
#: 行族（codex / claude_code_cli / cursor_agent_cli / dsh）都复用
#: `line_search.LineAggregate{Search,Context}Service`，按精确类型门控会被别的行族绕过，
#: 因此它们的类型门额外核对 `service.source` 恰等于本族来源 ID：
#: 一个 `spec=CURSOR_SPEC` 的服务只能进 cursor 槽，装错槽在绑定入口就被拒。
_PI_SEARCH_TYPES = (PiFileSearchService, PiMultiFileSearchService)
_PI_CONTEXT_TYPES = (PiFileContextService, PiMultiFileContextService)
_HERMES_SEARCH_TYPES = (HermesAggregateSearchService,)
_HERMES_CONTEXT_TYPES = (HermesAggregateContextService,)
_LINE_SEARCH_TYPE = LineAggregateSearchService
_LINE_CONTEXT_TYPE = LineAggregateContextService
_WORKBUDDY_SEARCH_TYPES = (workbuddy_source.WorkBuddyAggregateSearchService,)
_WORKBUDDY_CONTEXT_TYPES = (workbuddy_source.WorkBuddyAggregateContextService,)

_BIND_ERR_SEARCH = (
    "search service must be a PiFileSearchService, a PiMultiFileSearchService or None"
)
_BIND_ERR_CONTEXT = (
    "context service must be a PiFileContextService, a PiMultiFileContextService or None"
)
_BIND_ERR_HERMES_SEARCH = (
    "hermes search service must be a HermesAggregateSearchService or None"
)
_BIND_ERR_HERMES_CONTEXT = (
    "hermes context service must be a HermesAggregateContextService or None"
)
_BIND_ERR_WORKBUDDY_SEARCH = (
    "workbuddy search service must be a WorkBuddyAggregateSearchService or None"
)
_BIND_ERR_WORKBUDDY_CONTEXT = (
    "workbuddy context service must be a WorkBuddyAggregateContextService or None"
)


def _bind_err_line_search(source: str) -> str:
    return f"search service must be a LineAggregateSearchService for source {source!r} or None"


def _bind_err_line_context(source: str) -> str:
    return f"context service must be a LineAggregateContextService for source {source!r} or None"


def _check_line_binding(
    service: object,
    *,
    source: str,
    kind: str,
) -> None:
    """行族绑定的类型门：精确类型 + `spec.source_id` 等于本族来源。"""
    expected_type = _LINE_SEARCH_TYPE if kind == "search" else _LINE_CONTEXT_TYPE
    if type(service) is not expected_type or getattr(service, "source", None) != source:
        raise TypeError(
            _bind_err_line_search(source)
            if kind == "search"
            else _bind_err_line_context(source)
        )
    if service.policy is None or service.scope is None or service.ledger is None:
        raise TypeError(
            "a bound line-family service must carry its own policy, scope and ReferenceLedger"
        )


def _check_pairing_shape(
    search: Any,
    context: Any,
    *,
    family: str,
    label: str,
    binding_error: str,
) -> None:
    """按族做成对核对：账本同一、同族，形状不符当场 `ValueError`（赋值前）。

    `_validate_pairing` 是原三族（pi-single / pi-multi / hermes-aggregate）的既有规则，
    这里原样复用，不为新族改写；行族与 store 族另走形状核对：两侧的服务必须是配对
    构造出来的（`store_refs()` 与 `context_service()` 同源），否则宿主把 A 文件的发放
    配到 B 文件的核对，令牌能发出去却必然核对失败——那是配置错误，不该伪装成引用问题。
    """
    if search is None or context is None:
        return
    if search.ledger is not context.ledger:
        raise ValueError(
            "bound search and context services must share one ReferenceLedger"
        )
    if _family(search) != _family(context):
        raise ValueError(
            "bound search and context services must belong to the same source family"
        )
    if family in (_FAMILY_PI_FILES, "hermes-aggregate"):
        _validate_pairing(search, context)
        return
    if family.startswith("line:"):
        if search.spec.source_id != context.spec.source_id:
            raise ValueError(binding_error.format(label))
        if search.scope != context.scope:
            raise ValueError(binding_error.format(f"{label}（授权范围不一致）"))
        if search.policy is not context.policy:
            raise ValueError(binding_error.format(f"{label}（策略对象不是同一个）"))
        return
    if family == _FAMILY_WORKBUDDY:
        if search.store_refs() != context.store_refs():
            raise ValueError(binding_error.format(f"{label}（绑定库集合不一致）"))
        if search.scope != context.scope:
            raise ValueError(binding_error.format(f"{label}（授权范围不一致）"))
        if search.policy is not context.policy:
            raise ValueError(binding_error.format(f"{label}（策略对象不是同一个）"))
        return
    raise ValueError("bound services are not a recognized family")

_INSTRUCTIONS = (
    "本构建提供 MCP stdio 协议入口和三个只读工具。默认不绑定任何检索服务，search_sessions"
    "与 read_session_context 会安全拒绝；只有宿主在进程内显式注入持有策略与批准数据的服务"
    "时，才执行受限检索与上下文读取。可注入的族：pi（单个固定文件或宿主自持的有界批准文件"
    "集合）、hermes（宿主自持的有界已批准库集合）、codex / claude_code_cli / cursor_agent_cli"
    "（有界批准 JSONL 文件集合）、dsh（有界批准 zstd 帧流文件集合，解码运行时也由宿主注入）、"
    "workbuddy（宿主自持的有界 SQLite 库集合）。同一族的查询与上下文两侧必须共用同一个引用"
    "账本且绑定形状一致；客户端不能提供路径、库集合或文件集合。上下文只接受查询发放的 ctxref:"
    " 不透明引用（按族携带文件、帧位或库内行位坐标），行号与存储版本不由客户端携带。多来源"
    "查询跨族合并后统一按 limit 截断，各族只扫自己的集合，coverage 逐来源报告状态与原因；"
    "某族未绑定只会产出该族的未绑定覆盖行，绝不把他族命中冒充它已覆盖。list_sources 只报告"
    "绑定与探测事实，不检查用户或项目配置，ready 不表示整个来源已扫完；未核实正文形状的来源"
    "（cursor GUI、workbuddy 正文文件）只报状态与原因，不给出任何正文覆盖承诺。"
)

#: 绑定槽位的全体合法类型：pi 两族、Hermes 聚合族、四个行族与 workbuddy store 族。
_BoundSearch = (
    PiFileSearchService
    | PiMultiFileSearchService
    | HermesAggregateSearchService
    | LineAggregateSearchService
    | workbuddy_source.WorkBuddyAggregateSearchService
)
_BoundContext = (
    PiFileContextService
    | PiMultiFileContextService
    | HermesAggregateContextService
    | LineAggregateContextService
    | workbuddy_source.WorkBuddyAggregateContextService
)

#: 各族绑定槽位：每族独立，pi 与 Hermes 可同时在场（原先共用一个槽时互斥）。
#: 分发只读 `_registry`；`_search_service` / `_context_service` 仍是 pi / Hermes 槽位的
#: 镜像，供既有绑定测试与宿主读探针（`server._search_service`）使用，语义不变。
_pi_search: _BoundSearch | None = None
_pi_context: _BoundContext | None = None
_hermes_search: HermesAggregateSearchService | None = None
_hermes_context: HermesAggregateContextService | None = None
_line_search_slots: dict[str, LineAggregateSearchService] = {}
_line_context_slots: dict[str, LineAggregateContextService] = {}
_workbuddy_search: workbuddy_source.WorkBuddyAggregateSearchService | None = None
_workbuddy_context: workbuddy_source.WorkBuddyAggregateContextService | None = None
#: DSH 解码运行时：只从 `bind_dsh_*(decoder_python=…)` 进来，本构建从不读配置文件。
_dsh_runtime: dsh_source.DshDecoderRuntime | None = None

_search_service: _BoundSearch | None = None
_context_service: _BoundContext | None = None


def _family(
    service: Any,
) -> str | None:
    """服务族：`pi-single` / `pi-multi` / `hermes-aggregate` / 行族 / `workbuddy-store-set`；非本包类型算未知。

    发放与核对必须落在同一族里：跨族的令牌既发不出也对不上，只能在绑定时拒掉。
    行族四源共用 `LineAggregate*Service`，因此族名带上来源 ID（`line:codex` 等），
    与注册表里每源一条 `line:<source>` 登记项同名：跨行族的令牌不会静默落到另一族。
    """

    if type(service) is PiFileSearchService or type(service) is PiFileContextService:
        return "pi-single"
    if (
        type(service) is PiMultiFileSearchService
        or type(service) is PiMultiFileContextService
    ):
        return "pi-multi"
    if (
        type(service) is HermesAggregateSearchService
        or type(service) is HermesAggregateContextService
    ):
        return "hermes-aggregate"
    if type(service) is LineAggregateSearchService or type(service) is LineAggregateContextService:
        return f"line:{getattr(service, 'source', '')}"
    if (
        type(service) is workbuddy_source.WorkBuddyAggregateSearchService
        or type(service) is workbuddy_source.WorkBuddyAggregateContextService
    ):
        return "workbuddy-store-set"
    return None


def _validate_pairing(
    search: _BoundSearch | None,
    context: _BoundContext | None,
) -> None:
    """两侧都在场时的成对核对：同族、共用同一账本；从任一侧绑定都过这道门。

    配置错了在绑定入口就拒（`ValueError`），不留到运行时靠 `ref_expired` 拒绝默默解释：
    发放与核对落在两本账上、一族发放配另一族路由（或单文件发放配集合路由，反之亦然），
    都是宿主配置错误。
    """
    if search is None or context is None:
        return
    left, right = search.ledger, context.ledger
    # 两侧都省略账本即共用进程内默认账本（可用）；任一侧带了显式账本，
    # 另一侧必须是同一个实例，否则发放与核对落在两本账上。
    if not (left is right or (left is None and right is None)):
        raise ValueError(
            "bound search and context services must share one ReferenceLedger"
        )
    search_family = _family(search)
    context_family = _family(context)
    if search_family != context_family:
        raise ValueError(
            "bound search and context services must belong to the same source family"
        )
    if search_family == "pi-single":
        return
    if search_family == "pi-multi":
        return
    if search_family == "hermes-aggregate":
        # 同一族还须同范围：聚合上下文服务只在本 scope 下重算绑定键，
        # 两侧 scope 不同会让发放与核对的键分叉，表现为必然 binding_mismatch。
        if search.scope != context.scope:
            raise ValueError(
                "bound hermes aggregate services must share one authorization scope"
            )
        # 绑定集合也必须逐项同序相同：否则发放面向核对侧没有的库发令牌，或核对侧把已批准的库
        # 当成陌生绑定。路由失败本身会零正文拒绝，但那是宿主配置错误，不该伪装成令牌问题。
        if (
            isinstance(search, HermesAggregateSearchService)
            and isinstance(context, HermesAggregateContextService)
            and search.store_refs() != context.stores
        ):
            raise ValueError(
                "bound hermes aggregate services must share one ordered store set"
            )
        return
    raise ValueError("bound services are not a recognized family")


def bind_pi_file_search_service(
    service: PiFileSearchService | PiMultiFileSearchService | None,
) -> None:
    """绑定宿主显式构造的 pi 查询服务（单文件或聚合）；本模块与 ``main`` 从不读取配置或自动绑定。

    若上下文服务已在场，成对核对（账本与族）在赋值前执行：不过则整次绑定不生效。
    绑定成功后同步写入分发注册表（计划 D-1）：旧签名、旧报错文案、旧核对顺序均不变。
    """
    global _pi_search, _search_service
    if service is not None and type(service) not in _PI_SEARCH_TYPES:
        raise TypeError(_BIND_ERR_SEARCH)
    _validate_pairing(service, _pi_context)
    _pi_search = service
    if _pi_context is not None:
        _search_service = _pi_search
        _context_service = _pi_context
    elif _pi_context is None and _hermes_context is None and _hermes_search is None:
        # 单侧绑定时保持旧的全局镜像语义：失败配对不生效、成功配对可见。
        _search_service = service
        _context_service = _pi_context


def bind_pi_multi_file_search_service(service: PiMultiFileSearchService | None) -> None:
    """绑定聚合查询服务（宿主注入的有界批准文件集合）；只接受该类型，与单文件槽位互斥共用。"""
    if service is not None and type(service) is not PiMultiFileSearchService:
        raise TypeError("search service must be a PiMultiFileSearchService or None")
    bind_pi_file_search_service(service)


def bind_pi_file_context_service(
    service: PiFileContextService | PiMultiFileContextService | None,
    *,
    search_service: PiFileSearchService | PiMultiFileSearchService | None = None,
) -> None:
    """绑定宿主显式构造的上下文服务；可选地一并换绑查询服务（同一对参数成对生效）。

    引用必须跨两个服务可核对：两侧都省略账本时共用进程内默认账本；任一侧带了显式账本，
    另一侧必须带**同一个实例**，否则发放与读取落在两本账上，引用必然对不上——这里在绑定
    时就把这种配置拒掉（`TypeError`/`ValueError`），不留到运行时靠拒绝口径解释。

    两侧还必须**同为单文件或同为集合**：聚合上下文服务只把引用路由回自己绑定集合里的那条
    文件，配一个单文件查询服务会让发放与路由的口径错位（令牌能发出来却按集合语义被拒）。
    这道成对核对由 `_validate_pairing` 在**两侧绑定入口**都执行，任何一侧后绑也不能绕过。
    """
    global _pi_search, _pi_context, _search_service, _context_service
    if service is not None and type(service) not in _PI_CONTEXT_TYPES:
        raise TypeError(_BIND_ERR_CONTEXT)
    if search_service is not None and type(search_service) not in _PI_SEARCH_TYPES:
        raise TypeError(_BIND_ERR_SEARCH)
    partner = search_service if search_service is not None else _pi_search
    _validate_pairing(partner, service)
    if search_service is not None:
        _pi_search = search_service
    _pi_context = service
    if _pi_search is not None:
        _search_service = _pi_search
        _context_service = _pi_context


def bind_pi_multi_file_context_service(
    service: PiMultiFileContextService | None,
    *,
    search_service: PiMultiFileSearchService | None = None,
) -> None:
    """绑定聚合上下文服务；只接受该类型与聚合查询服务成对生效（口径见通用绑定函数）。"""
    if service is not None and type(service) is not PiMultiFileContextService:
        raise TypeError("context service must be a PiMultiFileContextService or None")
    if search_service is not None and type(search_service) is not PiMultiFileSearchService:
        raise TypeError("search service must be a PiMultiFileSearchService or None")
    bind_pi_file_context_service(service, search_service=search_service)


def bind_hermes_aggregate_search_service(
    service: HermesAggregateSearchService | None,
) -> None:
    """绑定宿主注入的 Hermes 聚合查询服务；只接受该类型，与 pi 槽位互斥共用。

    路径与会话断言只在宿主注入时进入本进程：客户端传不进库路径，也放宽不了任何上限。
    默认 ``main`` 从不调用本函数，因此生产入口仍保持未绑定。
    """
    global _hermes_search, _search_service, _context_service
    if service is not None and type(service) not in _HERMES_SEARCH_TYPES:
        raise TypeError(_BIND_ERR_HERMES_SEARCH)
    _validate_pairing(service, _hermes_context)
    _hermes_search = service
    if _hermes_context is not None:
        _search_service = _hermes_search
        _context_service = _hermes_context


def bind_hermes_aggregate_context_service(
    service: HermesAggregateContextService | None,
    *,
    search_service: HermesAggregateSearchService | None = None,
) -> None:
    """绑定宿主注入的 Hermes 聚合上下文服务；可与查询服务一并成对生效（同一对参数）。

    成对核对（账本、同族、同范围、同序库集合）在赋值前执行：不过则整次绑定不生效。
    推荐由发放方造配对：`HermesAggregateSearchService.context_service()` 把同一策略、
    同一 scope、同一库集合、同一账本与同一键算法一次带齐。
    """
    global _hermes_context, _hermes_search, _search_service, _context_service
    if service is not None and type(service) not in _HERMES_CONTEXT_TYPES:
        raise TypeError(_BIND_ERR_HERMES_CONTEXT)
    if search_service is not None and type(search_service) not in _HERMES_SEARCH_TYPES:
        raise TypeError(_BIND_ERR_HERMES_SEARCH)
    partner = search_service if search_service is not None else _hermes_search
    _validate_pairing(partner, service)
    if search_service is not None:
        _hermes_search = search_service
    _hermes_context = service
    if _hermes_search is not None:
        _search_service = _hermes_search
        _context_service = _hermes_context


#: 行族来源 ID 与注册表族名，与 `line_search` 里已登记的 spec 一一对应。
_SOURCE_CODEX = "codex"
_SOURCE_CLAUDE = "claude_code_cli"
_SOURCE_CURSOR = SOURCE_CURSOR
_SOURCE_DSH = dsh_source.SOURCE_DSH
_SOURCE_WORKBUDDY = workbuddy_source.SOURCE_WORKBUDDY
_FAMILY_PI_FILES = "pi-files"
_FAMILY_CODEX = f"line:{_SOURCE_CODEX}"
_FAMILY_CLAUDE = f"line:{_SOURCE_CLAUDE}"
_FAMILY_CURSOR = f"line:{_SOURCE_CURSOR}"
_FAMILY_DSH = f"line:{_SOURCE_DSH}"
_FAMILY_WORKBUDDY = "workbuddy-store-set"
#: 六类必列来源之外的扩展来源（有界集合已接线，默认未绑定，不占六行列表）。
_SOURCE_ORDER = ("pi", _SOURCE_CODEX, _SOURCE_CLAUDE, _SOURCE_CURSOR, _SOURCE_DSH, "hermes", _SOURCE_WORKBUDDY)
#: 行族各自的有界集合名称：写入 reason 与 coverage_scope，不混用“整个来源”。
_LINE_STAGES = {
    _SOURCE_CODEX: "有界 Codex 会话文件集合",
    _SOURCE_CLAUDE: "有界 Claude Code CLI 会话文件集合",
    _SOURCE_CURSOR: "有界 Cursor CLI 会话文件集合",
}
#: DSH 绑定时 `decoder_python` 的长度上限：宿主注入用的短字符串，不读配置、不校验路径。
_MAX_DECODER_PYTHON_CHARS = 4096


def _pi_search_factory(*, scope: str) -> Any:
    del scope
    return _pi_search


def _pi_context_factory(*, scope: str, source: str) -> Any:
    del scope, source
    return _pi_context


def _hermes_search_factory(*, scope: str) -> Any:
    del scope
    return _hermes_search


def _hermes_context_factory(*, scope: str, source: str) -> Any:
    del scope, source
    return _hermes_context


def _line_search_factory(slot: str) -> Callable[..., Any]:
    def make(*, scope: str) -> Any:
        del scope
        return _line_search_slots.get(slot)

    return make


def _line_context_factory(slot: str) -> Callable[..., Any]:
    def make(*, scope: str, source: str) -> Any:
        del scope, source
        return _line_context_slots.get(slot)

    return make


def _dsh_search_factory(*, scope: str) -> Any:
    """DSH 只有在解码运行时可用时才参与查询：未绑定或探测失败都返回 None。

    解码运行时缺失时服务本身仍可以绑定（宿主需要看到明确的未就绪状态），但分发
    不放它进磁盘路径，列表与覆盖行会由 `_coverage_rows_for` 标成 `error` 并写明
    「解码运行时缺失」，绝不报 ready。
    """
    del scope
    if _dsh_runtime is None or not _dsh_runtime.usable:
        return None
    return _line_search_slots.get(_SOURCE_DSH)


def _workbuddy_search_factory(*, scope: str) -> Any:
    del scope
    return _workbuddy_search


def _workbuddy_context_factory(*, scope: str, source: str) -> Any:
    del scope, source
    return _workbuddy_context


#: 来源族注册表：模块加载时登记一次，闭包读实时槽位；绑定与解绑都不重建它。
#: 绑定入口的配对与类型文案（新七族；旧三族仍用各自既有常量）。
_BIND_ERR_LINE = "bound {} services are not a matching pair"
_BIND_ERR_WORKBUDDY = "bound WorkBuddy store services are not a matching pair"
_BIND_ERR_DSH_DECODER = (
    "参数错误：decoder_python 必须是非空字符串且长度不超过 "
    f"{_MAX_DECODER_PYTHON_CHARS} 字符。"
)

#: 未绑定/禁用/解码缺失的诚实文案：七族接线完成后不再有「未编写适配器」的说法，
#: 接线完成后不再有「未编写适配器」的说法：退役为历史，只保留未绑定/禁用口径。
_UNBOUND_LINE_REASON = (
    "宿主未在本进程注入 {source} 的{stage}，故 status 为 unavailable；"
    "enabled 为 false 只表示本进程未注入，不代表该来源未安装或未启用；"
    "本构建不探测磁盘也不检查配置，故 project_config 为 null（未知）。"
)
_UNBOUND_DSH_REASON = (
    "宿主未在本进程注入 DSH 帧集合服务，故 status 为 unavailable；"
    "enabled 为 false 只表示本进程未注入，不代表 DSH 未安装或未启用；"
    "本构建不探测磁盘也不检查配置，故 project_config 为 null（未知）。"
)
_UNBOUND_WORKBUDDY_REASON = (
    "宿主未在本进程注入 WorkBuddy store 集合，故 status 为 unavailable；"
    "正文文件布局未逐字核实，索引侧结论不冒充正文覆盖；"
    "本构建不探测磁盘也不检查配置，故 project_config 为 null（未知）。"
)
_DISABLED_CLAUDE_REASON = (
    "claude_code_cli 属扩展来源：本构建已接线但默认未启用，故 status 为 disabled；"
    "未检查任何用户或项目配置，故 project_config 为 null（未知），本次未打开任何文件。"
)
_BIND_DSH_NOT_READY_REASON = (
    f"服务已绑定但{dsh_source.DSH_DECODER_MISSING_REASON}，故 status 为 error："
    "本构建不自动读取任何用户配置来寻找解释器，本次查询不打开任何文件，绝不报告 ready。"
)


#: 已绑定（ready）的诚实文案：ready 只代表本进程注入了宿主批准且有界的集合。
_BIND_LINE_REASON = (
    "宿主已显式绑定：status 为 ready 只表示本进程注入了宿主批准且有界的{stage}，"
    "不表示整个来源已扫完，也不表示完整性校验已通过或本次查询已有结果；本构建不"
    "检查用户或项目配置、不探测磁盘，故 config_checked 仍为 false、逐源 "
    "project_config 仍为 null。"
)
_BIND_DSH_REASON = (
    "宿主已显式绑定且解码运行时可用：status 为 ready 只表示本进程注入了宿主批准且"
    "有界的 DSH 帧集合，不表示整个 DSH 来源已扫完；解压预算与帧上限会使扫描部分完"
    "成，覆盖口径如实标注；本构建不检查用户或项目配置、不探测磁盘，故 config_checked"
    " 仍为 false、逐源 project_config 仍为 null。"
)
_BIND_WORKBUDDY_REASON = (
    "宿主已显式绑定：status 为 ready 只表示本进程注入了宿主批准且有界的 WorkBuddy "
    "store 集合（索引侧只读查询），不表示整个来源已扫完；正文文件路径与记录形状未逐字"
    "核实，正文读取一律按未核实口径拒绝，索引侧结论不冒充正文覆盖；本构建不检查用户或"
    "项目配置、不探测磁盘，故 config_checked 仍为 false、逐源 project_config 仍为 null。"
)


def _dsh_ready() -> bool:
    """DSH 可服务判据：已注入帧集合服务**且**绑定时探针确认解码运行时可用。"""

    return (
        _line_search_slots.get(_SOURCE_DSH) is not None
        and _dsh_runtime is not None
        and _dsh_runtime.usable
    )


def _mirror_pi_hermes_globals() -> None:
    """把 pi/hermes 的最新绑定镜像进遗留全局槽，其余族不动这两个槽。

    旧宿主与既有单测仍直接读 `_search_service`/`_context_service`；新族绑定成功时
    必须保持那对接旧槽继续指向同一个 pi/hermes 服务对，因此这里只刷新、不清空。
    """

    global _search_service, _context_service
    if _pi_search is not None or _pi_context is not None:
        _search_service = _pi_search
        _context_service = _pi_context
    elif _hermes_search is not None or _hermes_context is not None:
        _search_service = _hermes_search
        _context_service = _hermes_context


_registry = ServiceRegistry()


def _register_families() -> None:
    """登记全部七族的查询与坐标路由（供模块加载与 `reset_bound_services` 重装）。"""

    if "pi" not in _registry.families():
        _registry.register_search(
            FamilySearchEntry(
                family=_FAMILY_PI_FILES,
                sources=("pi",),
                make_service=_pi_search_factory,
            )
        )
        _registry.register_context(
            FamilyContextEntry(
                family=_FAMILY_PI_FILES,
                sources=("pi",),
                make_service=_pi_context_factory,
            )
        )
    if "hermes" not in _registry.families():
        _registry.register_search(
            FamilySearchEntry(
                family="hermes-aggregate",
                sources=("hermes",),
                make_service=_hermes_search_factory,
            )
        )
        _registry.register_context(
            FamilyContextEntry(
                family="hermes-aggregate",
                sources=("hermes",),
                make_service=_hermes_context_factory,
            )
        )
    for source, family in (
        (_SOURCE_CODEX, _FAMILY_CODEX),
        (_SOURCE_CLAUDE, _FAMILY_CLAUDE),
        (_SOURCE_CURSOR, _FAMILY_CURSOR),
        (_SOURCE_DSH, _FAMILY_DSH),
    ):
        if family in _registry.families():
            continue
        make_service = _dsh_search_factory if source == _SOURCE_DSH else _line_search_factory(source)
        _registry.register_search(
            FamilySearchEntry(family=family, sources=(source,), make_service=make_service)
        )
        _registry.register_context(
            FamilyContextEntry(
                family=family,
                sources=(source,),
                make_service=_line_context_factory(source),
            )
        )
    if _FAMILY_WORKBUDDY not in _registry.families():
        _registry.register_search(
            FamilySearchEntry(
                family=_FAMILY_WORKBUDDY,
                sources=(_SOURCE_WORKBUDDY,),
                make_service=_workbuddy_search_factory,
            )
        )
        _registry.register_context(
            FamilyContextEntry(
                family=_FAMILY_WORKBUDDY,
                sources=(_SOURCE_WORKBUDDY,),
                make_service=_workbuddy_context_factory,
            )
        )


# 模块加载即登记七族路由：注册表只登记族名与来源，不打开任何文件、不读任何配置；
# 具体服务是否存在由工厂闭包在每次调用时读实时槽位判定（计划 D-1）。
_register_families()


def _any_binding() -> bool:
    """任一族在场即算已接线：决定顶层 `implementation_status` 与未绑定拒答。"""

    return bool(
        _line_search_slots
        or _line_context_slots
        or _pi_search is not None
        or _pi_context is not None
        or _hermes_search is not None
        or _hermes_context is not None
        or _workbuddy_search is not None
        or _workbuddy_context is not None
    )


def _bound_search_sources() -> list[str]:
    """未点名来源时参与查询的来源：已绑定且可用的族，含 DSH 的解码可用性门。"""

    sources: list[str] = []
    for source in _SOURCE_ORDER:
        if source == _SOURCE_DSH:
            if _dsh_search_factory(scope="") is not None:
                sources.append(source)
            continue
        if _search_slot_for(source) is not None:
            sources.append(source)
    return sources


def _coverage_rows_for(
    requested: Sequence[str],
    *,
    unbound_status: str,
    unrouted_status: str,
) -> list[dict[str, Any]]:
    """为未点名查询的来源生成诚实的覆盖行：未绑定、禁用（扩展来源）与解码缺失。"""

    rows: list[dict[str, Any]] = []
    for name in requested:
        if name not in _SOURCE_ORDER:
            # 参数门本已拦下未知来源；走到这里只会是路由缺失，诚实记 unsupported。
            rows.append(
                _honest_coverage_row(
                    name,
                    unrouted_status,
                    _unbound_reason_for(name),
                    "source_unsupported",
                    None,
                )
            )
            continue
        if name == _SOURCE_CLAUDE and _line_search_slots.get(_SOURCE_CLAUDE) is None:
            # 扩展来源族已接线，但默认未绑定：未启用的语义写 disabled，不是未探测。
            rows.append(
                _honest_coverage_row(
                    name, "disabled", _DISABLED_CLAUDE_REASON, "service_unbound", False
                )
            )
            continue
        if _search_slot_for(name) is not None:
            continue
        status = unbound_status
        reason = _unbound_reason_for(name)
        if (
            name == _SOURCE_DSH
            and _line_search_slots.get(_SOURCE_DSH) is not None
            and (_dsh_runtime is None or not _dsh_runtime.usable)
        ):
            status = "error"
            reason = _BIND_DSH_NOT_READY_REASON
        rows.append(
            _honest_coverage_row(
                name, status, reason, "service_unbound", False
            )
        )
    return rows


def _honest_coverage_row(
    source: str,
    status: str,
    reason: str,
    category: str,
    enabled: bool | None,
) -> dict[str, Any]:
    """未执行来源的固定行：状态、reason 与机器可读类别同源（计划 §7.2）。"""

    return {
        "source": source,
        "status": status,
        "enabled": enabled,
        "project_config": None,
        "reason": reason,
        "filter_errors": [category],
    }


def _apply_unbound_coverage(
    result: dict[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """把未绑定来源的诚实覆盖行并进注册表合并结果，并同步诚实的状态标记。

    合并器对未路由来源给的是一行空计数加泛化原因；这里换成与 `list_sources`
    同源的同一条措辞，并按计划 §7.2 修正 complete/partial/failure_category：
    未绑定的来源不能把整体报成 complete，点名未支持来源仍归 `source_unsupported`。
    """

    by_source: dict[str, dict[str, Any]] = {}
    for row in result.get("coverage") or ():
        if isinstance(row, Mapping):
            name = row.get("source")
            if isinstance(name, str) and name:
                by_source.setdefault(name, dict(row))
    categories: set[str] = set()
    for row in rows:
        merged = by_source.setdefault(
            row["source"],
            {
                "source": row["source"],
                "scanned_count": 0,
                "matched_count": 0,
                "returned_count": 0,
                "skipped_count": 0,
            },
        )
        merged.update(
            {
                "source": row["source"],
                "status": row["status"],
                "partial": True,
                "reason": row["reason"],
                # 诚实行里的 enabled/project_config 必须随覆盖一起写入：合并器给的
                # 空计数行没有这两个键，缺了它们调用方无法区分「未启用」与「未注入」。
                "enabled": row["enabled"],
                "project_config": row["project_config"],
            }
        )
        merged.setdefault("scanned_count", 0)
        merged.setdefault("matched_count", 0)
        merged.setdefault("returned_count", 0)
        merged.setdefault("skipped_count", 0)
        codes = set(merged.get("filter_errors") or ()) | set(row["filter_errors"])
        merged["filter_errors"] = sorted(codes)
        categories.update(row["filter_errors"])
    result["coverage"] = sorted(
        by_source.values(),
        key=lambda row: (
            _SOURCE_ORDER.index(row["source"])
            if row["source"] in _SOURCE_ORDER
            else len(_SOURCE_ORDER)
        ),
    )
    result["complete"] = False
    result["partial"] = True
    if not result.get("reason") and not result.get("failure_category"):
        # 合并器只看载荷 reason；未执行来源必须自带机器可读类别，否则调用方只能从
        # coverage 行里反推。全部是 disabled（扩展来源未启用）时不报失败类别。
        if "source_unsupported" in categories:
            code = "source_unsupported"
        elif any(row["status"] != "disabled" for row in rows):
            code = "service_unbound"
        else:
            code = ""
        if code:
            result["reason"] = code
            result["failure_category"] = code
            result["stage_reached"] = "coordinator"
    return result


def _unbound_reason_for(source: str) -> str:
    if source == "pi":
        return _UNBOUND_PI_REASON
    if source == "hermes":
        return _UNBOUND_HERMES_REASON
    if source == _SOURCE_CODEX:
        return _UNBOUND_LINE_REASON.format(source=source, stage=_LINE_STAGES[source])
    if source == _SOURCE_CLAUDE:
        return _DISABLED_CLAUDE_REASON
    if source == _SOURCE_CURSOR:
        return _UNBOUND_LINE_REASON.format(source=source, stage=_LINE_STAGES[source])
    if source == _SOURCE_DSH:
        return _UNBOUND_DSH_REASON
    return _UNBOUND_WORKBUDDY_REASON


def _search_slot_for(source: str) -> Any:
    """按来源名取当前已绑定的查询服务（不碰注册表，只读槽位）。

    DSH 额外受解码运行时可用性约束：探针不可用时即使服务已绑也不参与查询，
    计划 §7.2 要求该情形永远不报 ready。
    """

    if source == "pi":
        return _pi_search
    if source == "hermes":
        return _hermes_search
    if source == _SOURCE_WORKBUDDY:
        return _workbuddy_search
    if source == _SOURCE_DSH:
        return _dsh_search_factory(scope="")
    return _line_search_slots.get(source)


def _read_denial_message(reason: Any) -> str:
    """按分发层的拒绝类别给固定拒答文案；全部不读盘，也不回显入参。"""

    if reason == "decoder_missing":
        return (
            "read_session_context 拒绝："
            f"{dsh_source.DSH_DECODER_MISSING_REASON}，本次未打开任何文件。"
        )
    if reason == "disabled":
        return (
            "read_session_context 拒绝：该来源属扩展来源且默认未启用，"
            "本构建未检查其配置，本次未打开任何文件。"
        )
    if reason == "body_layout_unverified":
        return (
            "read_session_context 拒绝："
            f"{workbuddy_source.WORKBUDDY_BODY_LAYOUT_REASON}"
        )
    return f"read_session_context 未绑定{_UNBOUND_SUFFIX}"


register_families = _register_families


def reset_bound_services() -> None:
    """解绑全部族的服务并清空默认账本：宿主轮换绑定或测试隔离用。

    接线前这里只清两个槽位；现在清空所有族的槽位与注册表登记项，再重建七族登记。
    `_search_service` / `_context_service` 两个镜像同步置 None，既有断言（绑定失败不
    留半对、reset 后两侧为 None）的口径不变。
    """
    global _pi_search, _pi_context, _hermes_search, _hermes_context
    global _workbuddy_search, _workbuddy_context, _dsh_runtime
    global _search_service, _context_service
    _pi_search = None
    _pi_context = None
    _hermes_search = None
    _hermes_context = None
    _workbuddy_search = None
    _workbuddy_context = None
    _dsh_runtime = None
    _line_search_slots.clear()
    _line_context_slots.clear()
    _search_service = None
    _context_service = None
    _registry.reset()
    _register_families()
    clear_reference_ledger()


def bind_codex_file_search_service(
    service: LineAggregateSearchService | None,
) -> None:
    """绑定有界 Codex 会话文件集合查询服务；None 只清这一族，其它族不动。

    宿主注入已核验的 `SessionFileRef` 集合与本 scope 下的授权，服务自带策略与账本；
    本服务不扫描目录，也不自动发现 Codex 根。ready 只表示这条有界集合可用。
    """

    if service is not None:
        _check_line_binding(service, source=_SOURCE_CODEX, kind="search")
        _check_pairing_shape(
            service,
            _line_context_slots.get(_SOURCE_CODEX),
            family=_FAMILY_CODEX,
            label="Codex 会话文件集合",
            binding_error=_BIND_ERR_LINE.format("Codex 会话文件集合"),
        )
    _replace_line_search_slot(_SOURCE_CODEX, service)


def bind_codex_file_context_service(
    service: LineAggregateContextService | None,
    *,
    search_service: LineAggregateSearchService | None = None,
) -> None:
    """绑定 Codex 坐标路由（含未绑定时清位）；发放与核对同集合、同 scope、同账本。"""

    if service is not None:
        _check_line_binding(service, source=_SOURCE_CODEX, kind="context")
        left = search_service if search_service is not None else _line_search_slots.get(_SOURCE_CODEX)
        _check_pairing_shape(
            left,
            service,
            family=_FAMILY_CODEX,
            label="Codex 会话文件集合",
            binding_error=_BIND_ERR_LINE.format("Codex 会话文件集合"),
        )
    _replace_line_context_slot(_SOURCE_CODEX, service)


def bind_claude_file_search_service(
    service: LineAggregateSearchService | None,
) -> None:
    """绑定有界 Claude Code CLI 会话文件集合查询服务；None 只清这一族。

    扩展来源：参数门放行到分发层，默认未绑定即出 `disabled` 覆盖行，绝不读盘。
    """

    if service is not None:
        _check_line_binding(service, source=_SOURCE_CLAUDE, kind="search")
        _check_pairing_shape(
            service,
            _line_context_slots.get(_SOURCE_CLAUDE),
            family=_FAMILY_CLAUDE,
            label="Claude Code CLI 会话文件集合",
            binding_error=_BIND_ERR_LINE.format("Claude Code CLI 会话文件集合"),
        )
    _replace_line_search_slot(_SOURCE_CLAUDE, service)


def bind_claude_file_context_service(
    service: LineAggregateContextService | None,
    *,
    search_service: LineAggregateSearchService | None = None,
) -> None:
    """绑定 Claude Code CLI 坐标路由；未点名查询里它仍以 `disabled` 行出现。"""

    if service is not None:
        _check_line_binding(service, source=_SOURCE_CLAUDE, kind="context")
        left = search_service if search_service is not None else _line_search_slots.get(_SOURCE_CLAUDE)
        _check_pairing_shape(
            left,
            service,
            family=_FAMILY_CLAUDE,
            label="Claude Code CLI 会话文件集合",
            binding_error=_BIND_ERR_LINE.format("Claude Code CLI 会话文件集合"),
        )
    _replace_line_context_slot(_SOURCE_CLAUDE, service)


def bind_cursor_file_search_service(
    service: LineAggregateSearchService | None,
) -> None:
    """绑定有界 Cursor CLI 会话文件集合查询服务；None 只清这一族。

    GUI 读取轴本构建恒不接线：无论是否绑定，`list_sources` 的 cursor_agent_cli
    行只在 CLI 集合上报 ready，GUI 侧由固定措辞说明「正文格式未核实」。
    """

    if service is not None:
        _check_line_binding(service, source=_SOURCE_CURSOR, kind="search")
        _check_pairing_shape(
            service,
            _line_context_slots.get(_SOURCE_CURSOR),
            family=_FAMILY_CURSOR,
            label="Cursor CLI 会话文件集合",
            binding_error=_BIND_ERR_LINE.format("Cursor CLI 会话文件集合"),
        )
    _replace_line_search_slot(_SOURCE_CURSOR, service)


def bind_cursor_file_context_service(
    service: LineAggregateContextService | None,
    *,
    search_service: LineAggregateSearchService | None = None,
) -> None:
    """绑定 Cursor CLI 坐标路由；与查询侧同集合、同 scope、同账本，否则拒绑。"""

    if service is not None:
        _check_line_binding(service, source=_SOURCE_CURSOR, kind="context")
        left = search_service if search_service is not None else _line_search_slots.get(_SOURCE_CURSOR)
        _check_pairing_shape(
            left,
            service,
            family=_FAMILY_CURSOR,
            label="Cursor CLI 会话文件集合",
            binding_error=_BIND_ERR_LINE.format("Cursor CLI 会话文件集合"),
        )
    _replace_line_context_slot(_SOURCE_CURSOR, service)


def bind_dsh_search_service(
    service: LineAggregateSearchService | None,
    *,
    decoder_python: str | None = None,
) -> None:
    """绑定有界 DSH 帧集合查询服务，并固化解码运行时；None 只清这一族。

    `decoder_python` 只在绑定这一层生效：非空字符串、长度上限 `_MAX_DECODER_PYTHON_CHARS`，
    由 `DshDecoderRuntime.probe` 现场探测；本构建从不读配置文件，也不接受客户端传值。
    探测失败只把这一族标成未就绪（`error`，解码运行时缺失），其它族不受影响。
    """

    global _dsh_runtime
    if service is not None:
        _check_line_binding(service, source=_SOURCE_DSH, kind="search")
        _check_pairing_shape(
            service,
            _line_context_slots.get(_SOURCE_DSH),
            family=_FAMILY_DSH,
            label="DSH 帧集合",
            binding_error=_BIND_ERR_LINE.format("DSH 帧集合"),
        )
        _dsh_runtime = _probe_dsh_runtime(decoder_python)
        # P1-2：探测成功即把运行时固化进服务 spec（含由本服务派生的上下文服务），
        # 搜索不再按文件重复探测，解码路径与绑定期核准的一致。
        if _dsh_runtime.usable:
            service = _pin_dsh_runtime_into_spec(service, _dsh_runtime)
    elif decoder_python is not None:
        raise TypeError(_BIND_ERR_DSH_DECODER)
    _replace_line_search_slot(_SOURCE_DSH, service)
    if service is None:
        _dsh_runtime = None


def bind_dsh_context_service(
    service: LineAggregateContextService | None,
    *,
    search_service: LineAggregateSearchService | None = None,
    decoder_python: str | None = None,
) -> None:
    """绑定 DSH 坐标路由（含未绑定时清位）；解码运行时同样只在绑定层固化。"""

    global _dsh_runtime
    if service is not None:
        _check_line_binding(service, source=_SOURCE_DSH, kind="context")
        left = search_service if search_service is not None else _line_search_slots.get(_SOURCE_DSH)
        _check_pairing_shape(
            left,
            service,
            family=_FAMILY_DSH,
            label="DSH 帧集合",
            binding_error=_BIND_ERR_LINE.format("DSH 帧集合"),
        )
        if decoder_python is not None:
            probed = _probe_dsh_runtime(decoder_python)
            if _dsh_runtime is not None and _dsh_runtime.python_path != probed.python_path:
                raise TypeError(_BIND_ERR_DSH_DECODER)
            _dsh_runtime = probed
        # P1-2：上下文服务的 spec 同样固化（绑定层已核准的运行时，不再逐文件探测）。
        if _dsh_runtime is not None and _dsh_runtime.usable:
            service = _pin_dsh_runtime_into_spec(service, _dsh_runtime)
    elif decoder_python is not None:
        raise TypeError(_BIND_ERR_DSH_DECODER)
    _replace_line_context_slot(_SOURCE_DSH, service)
    if service is None and _line_search_slots.get(_SOURCE_DSH) is None:
        _dsh_runtime = None


def bind_workbuddy_store_search_service(
    service: workbuddy_source.WorkBuddyAggregateSearchService | None,
) -> None:
    """绑定有界 WorkBuddy store 集合查询服务；None 只清这一族，其它族不动。

    服务只读 SQLite 索引与形状白名单；正文布局未核实时只出带原因的半覆盖行，
    不冒充「0 条消息的会话」。
    """

    global _workbuddy_search
    if service is not None:
        _check_workbuddy_binding(service, kind="search")
        _check_pairing_shape(
            service,
            _workbuddy_context,
            family=_FAMILY_WORKBUDDY,
            label="WorkBuddy store 集合",
            binding_error=_BIND_ERR_WORKBUDDY,
        )
    _workbuddy_search = service


def bind_workbuddy_store_context_service(
    service: workbuddy_source.WorkBuddyAggregateContextService | None,
    *,
    search_service: workbuddy_source.WorkBuddyAggregateSearchService | None = None,
) -> None:
    """绑定 WorkBuddy 坐标路由；成对核对同 scope 同序 stores，否则拒绑。"""

    global _workbuddy_context
    if service is not None:
        _check_workbuddy_binding(service, kind="context")
        left = search_service if search_service is not None else _workbuddy_search
        _check_pairing_shape(
            left,
            service,
            family=_FAMILY_WORKBUDDY,
            label="WorkBuddy store 集合",
            binding_error=_BIND_ERR_WORKBUDDY,
        )
    _workbuddy_context = service


def _check_workbuddy_binding(service: Any, *, kind: str) -> None:
    """WorkBuddy 服务类型门：只接受本包的 store 集合服务，且必须自带策略与账本。"""

    binding_error = _BIND_ERR_WORKBUDDY_SEARCH if kind == "search" else _BIND_ERR_WORKBUDDY_CONTEXT
    types = _WORKBUDDY_SEARCH_TYPES if kind == "search" else _WORKBUDDY_CONTEXT_TYPES
    if type(service) not in types:
        raise TypeError(binding_error)
    if getattr(service, "source", None) != _SOURCE_WORKBUDDY:
        raise ValueError(binding_error)
    if getattr(service, "policy", None) is None or getattr(service, "scope", None) is None:
        raise TypeError(
            "a bound WorkBuddy store service must carry its own policy and scope"
        )


def _probe_dsh_runtime(decoder_python: str | None) -> dsh_source.DshDecoderRuntime:
    """绑定层现场探测 DSH 解码运行时；非字符串或超长只算缺失，不抛路径。"""

    if decoder_python is None:
        return dsh_source.DshDecoderRuntime.probe()
    if (
        not isinstance(decoder_python, str)
        or not decoder_python.strip()
        or len(decoder_python) > _MAX_DECODER_PYTHON_CHARS
    ):
        raise TypeError(_BIND_ERR_DSH_DECODER)
    return dsh_source.DshDecoderRuntime.probe(decoder_python)


def _pin_dsh_runtime_into_spec(
    service: Any,
    runtime: dsh_source.DshDecoderRuntime,
) -> Any:
    """P1-2：把绑定层探测出的解码运行时固化进服务的 spec。

    宿主用注册表默认 `DSH_SPEC` 构造服务时，`file_runner` 是未固定 `runtime` 的
    `run_dsh_frame_file`，每次查询都会现场 `DshDecoderRuntime.probe()`（每文件一次），
    绑定层拿到的 `decoder_python` 不会生效——`list_sources` 报 ready 而搜索时按文件
    重新探测，解码路径可能与绑定期核准的不一致。这里用 `make_dsh_spec(runtime)` 派生
    一份 runner 已固定运行时的规格重建服务（同 policy/scope/绑定集合/账本，重建时
    重过同一批授权门，不会放宽任何边界）。spec 非注册表默认（宿主已自行固定）或探测
    结果不可用时保持原样：不可用的运行时不能伪装成可用。
    """
    if not runtime.usable or service is None:
        return service
    spec = getattr(service, "spec", None)
    if spec is not DSH_SPEC:
        return service
    if isinstance(service, LineAggregateSearchService):
        return LineAggregateSearchService(
            policy=service.policy,
            scope=service.scope,
            spec=make_dsh_spec(runtime),
            files=service.files,
            ledger=service.ledger,
        )
    if isinstance(service, LineAggregateContextService):
        return LineAggregateContextService(
            policy=service.policy,
            scope=service.scope,
            spec=make_dsh_spec(runtime),
            path=service.path,
            session_id=service.session_id,
            ledger=service.ledger,
        )
    return service


def _replace_line_search_slot(source: str, service: LineAggregateSearchService | None) -> None:
    if service is None:
        _line_search_slots.pop(source, None)
    else:
        _line_search_slots[source] = service


def _replace_line_context_slot(source: str, service: LineAggregateContextService | None) -> None:
    if service is None:
        _line_context_slots.pop(source, None)
    else:
        _line_context_slots[source] = service


app = MCPServer(
    name=SERVER_NAME,
    version=SERVER_VERSION,
    title="Cross Agent Session MCP",
    description="本地跨 Agent 会话检索 MCP 服务（默认未绑定检索服务）",
    instructions=_INSTRUCTIONS,
)


def _refusal(tool: str) -> ToolError:
    """已实现但未绑定时的人话：只说「未绑定」，不声称「未实现」（状态口径不得混淆）。"""
    return ToolError(f"{tool} 未绑定{_UNBOUND_SUFFIX}")


PI_BIND_STATUS_READY = "ready"
PI_BIND_STATUS_UNBOUND = "unavailable"

#: list_sources 逐源 reason 固定文案：适配器未编写与未绑定两种口径不得混淆（DES-SEC-01）。
_UNBOUND_PI_REASON = (
    "宿主未在本进程注入 pi 文件查询服务，故 status 为 unavailable；"
    "enabled 为 false 只表示本进程未注入，这不代表 pi 未安装或未启用；"
    "本构建不探测磁盘也不检查配置，故 project_config 为 null（未知）。"
)
_BIND_PI_REASON = (
    "宿主已显式绑定：status 为 ready 只表示本进程注入了宿主批准的 pi 文件（单个"
    "批准文件或一组有界的批准文件，以绑定形状为准），不表示整个 pi 来源已扫完，"
    "也不表示本次查询已有结果；本构建不检查用户或项目配置、不探测磁盘，故 "
    "config_checked 仍为 false、逐源 project_config 仍为 null。"
)
_UNBOUND_HERMES_REASON = (
    "宿主未在本进程注入 Hermes 聚合查询服务，故 status 为 unavailable；"
    "enabled 为 false 只表示本进程未注入，这不代表 Hermes 未安装或未启用，也不代表"
    "适配器代码缺失；本构建不探测磁盘、不枚举数据库、不检查配置，故 project_config "
    "为 null（未知）。"
)
_BIND_HERMES_REASON = (
    "宿主已显式绑定：status 为 ready 只表示本进程注入了宿主批准且有界的 Hermes 库集合，"
    "不表示整个 Hermes 来源已扫完（coverage_scope 为有界库集合），也不表示完整性校验已"
    "通过或本次查询已有结果；本构建不检查用户或项目配置、不探测磁盘，故 config_checked "
    "仍为 false、逐源 project_config 仍为 null。"
)
@app.tool(
    name="list_sources",
    title="来源可用性",
    description=(
        "只读：逐来源返回本地会话检索的可用性与绑定口径。六个必备来源为 hermes、dsh、"
        "workbuddy、pi、cursor_agent_cli、codex；claude_code_cli 属扩展来源，默认不在清单里"
        "单独成行（它只在被显式点名查询时以 disabled 覆盖行出现）。status 口径："
        "ready=宿主已在本进程注入该族的有界服务集合（不表示整个来源已扫完，也不表示已覆盖"
        "全部历史项目）；unavailable=适配器已编写但本进程未注入服务，或该读取轴被口径关闭"
        "（如 cursor_agent_cli 的 GUI 存储）；disabled=扩展来源未启用（未启用不等于已探测过"
        "且不支持）；error=已绑定但运行时前提不成立（如 dsh 解码运行时缺失，绝不报告 ready）；"
        "unsupported=本构建不读取该读取轴。enabled 只表达本进程绑定事实，不代表安装或用户启用；"
        "project_config 恒为 null（本构建不读取任何用户或项目配置）。顶层 verified=false 表示"
        "尚未在真实存储上做过验收，config_checked=false 表示未检查任何配置。"
        "本工具不读取会话存储，返回内容不含路径。"
    ),
    structured_output=False,
    annotations=_READ_ONLY_ANNOTATIONS,
)
async def list_sources() -> dict[str, Any]:
    """只读：逐来源报告可用性与诚实口径（不读取会话存储，不读取配置）。"""
    rows: list[dict[str, Any]] = []
    for name in REQUIRED_SOURCES:
        if name == "pi":
            # list_sources 报的是检索能力：只有查询服务在场才 ready；只绑上下文服务
            # 不得谎报检索已注入（enabled 与 status 均按查询服务为准）。
            bound = _pi_search is not None
            rows.append(
                {
                    "source": name,
                    "enabled": bool(bound),
                    "status": PI_BIND_STATUS_READY if bound else PI_BIND_STATUS_UNBOUND,
                    "project_config": None,
                    "reason": _BIND_PI_REASON if bound else _UNBOUND_PI_REASON,
                }
            )
            continue
        if name == "hermes":
            bound = _hermes_search is not None or _hermes_context is not None
            rows.append(
                {
                    "source": name,
                    "enabled": bool(bound),
                    "status": PI_BIND_STATUS_READY if bound else PI_BIND_STATUS_UNBOUND,
                    "project_config": None,
                    "reason": _BIND_HERMES_REASON if bound else _UNBOUND_HERMES_REASON,
                }
            )
            continue
        if name == _SOURCE_DSH:
            service = _line_search_slots.get(_SOURCE_DSH)
            if service is None:
                rows.append(
                    {
                        "source": name,
                        "enabled": False,
                        "status": PI_BIND_STATUS_UNBOUND,
                        "project_config": None,
                        "reason": _UNBOUND_DSH_REASON,
                    }
                )
                continue
            usable = _dsh_runtime is not None and _dsh_runtime.usable
            rows.append(
                {
                    "source": name,
                    "enabled": bool(usable),
                    "status": PI_BIND_STATUS_READY if usable else "error",
                    "project_config": None,
                    "reason": _BIND_DSH_REASON if usable else _BIND_DSH_NOT_READY_REASON,
                }
            )
            continue
        if name == _SOURCE_WORKBUDDY:
            bound = _workbuddy_search is not None or _workbuddy_context is not None
            rows.append(
                {
                    "source": name,
                    "enabled": bool(bound),
                    "status": PI_BIND_STATUS_READY if bound else PI_BIND_STATUS_UNBOUND,
                    "project_config": None,
                    "reason": _BIND_WORKBUDDY_REASON if bound else _UNBOUND_WORKBUDDY_REASON,
                }
            )
            continue
        # 行族（codex / cursor_agent_cli）：绑定即 ready，未绑定即 unavailable。
        service = _search_slot_for(name)
        bound = service is not None
        rows.append(
            {
                "source": name,
                "enabled": bool(bound),
                "status": PI_BIND_STATUS_READY if bound else PI_BIND_STATUS_UNBOUND,
                "project_config": None,
                "reason": _BIND_LINE_REASON.format(stage=_LINE_STAGES.get(name, "会话文件集合"))
                if bound
                else _unbound_reason_for(name),
            }
        )
    return {
        # 口径：本构建已完成七族接线，因此恒报 `partial`；`not_implemented` 只留给
        # 来源注册表为空（完全未接线）的构建。宿主未注入服务只影响逐源 `enabled`，
        # 不得把「已实现但未绑定」改判成「未实现」。
        "implementation_status": "partial"
        if rows
        else NOT_IMPLEMENTED_STATUS,
        "verified": False,
        "config_checked": False,
        "sources": rows,
    }


@app.tool(
    name="search_sessions",
    title="检索历史会话",
    description=(
        "只读：在宿主注入的有界服务集合内检索历史会话。scope 必填且为授权范围标识（不得为路径"
        "形态）；query 为关键词，省略 query 时必须同时给出 start 与 end（带时区的 ISO 8601）。"
        "sources 可点名来源（含 claude_code_cli 扩展来源：未注入时只返回 disabled 覆盖行，不读"
        "任何配置也不打开文件）；省略 sources 时只查询本进程**已绑定**的来源族，不把未绑定的族"
        "算进覆盖统计。多来源点名时逐族分发并跨族合并：命中行按时间倒序，limit 为跨来源总上限，"
        "被截断的族与整族失败的族都留在覆盖里。project 为项目过滤（宿主授权口径，非路径参数）。"
        "结果含片段与 ctxref 形态的坐标（各族坐标形态由该族决定，客户端不得按 pi 形态拼装），"
        "不含磁盘路径；时间不可靠的记录会被标注或排除，覆盖口径（coverage/complete/partial/"
        "skipped 等）如实反映扫描边界。未绑定任何族时返回固定拒绝文案，不自动读取任何存储。"
    ),
    structured_output=False,
    annotations=_READ_ONLY_ANNOTATIONS,
)
async def search_sessions(
    query: str | None = None,
    sources: list[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    project: str | None = None,
    limit: int = 20,
    *,
    scope: str,
) -> dict[str, Any]:
    """只读：逐族分发到有界服务并合并覆盖口径；本模块从不自动绑定或读取配置。"""
    _check_scope(scope)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ToolError(_ERR_LIMIT)
    if sources is not None:
        if not isinstance(sources, list):
            raise ToolError(_ERR_SOURCES_TYPE)
        if len(sources) > MAX_SOURCES_PER_QUERY:
            raise ToolError(_ERR_SOURCES_LIMIT)
        for item in sources:
            if not isinstance(item, str):
                raise ToolError(_ERR_SOURCES_TYPE)
        sources = [_normalize_source_id(item) for item in sources]
        for item in sources:
            _check_source_allowed(item, unknown_error=_ERR_SOURCES_UNKNOWN)
    if query is not None and not isinstance(query, str):
        raise ToolError(_ERR_QUERY_TYPE)
    if query is not None and not query.strip():
        raise ToolError(_ERR_QUERY_BLANK)
    if query is None and not (start and end):
        raise ToolError(_ERR_QUERY_WITHOUT_RANGE)
    if project is not None:
        _check_text(project, _ERR_PROJECT)
    start_dt = _parse_bound(start)
    end_dt = _parse_bound(end)
    if start_dt is not None and end_dt is not None and start_dt > end_dt:
        raise ToolError(_ERR_TIME_ORDER)

    wanted = list(sources) if sources is not None else _bound_search_sources()
    # 扩展来源（claude_code_cli）不在这里固定拒绝：`_check_source_allowed` 的契约（计划 D-4）
    # 要求未绑定时由注册表返回 `status=disabled` 覆盖行（`_coverage_rows_for` 的 claude 分支），
    # 固定拒绝只保留在 `read_session_context`；两条路径都不读配置、不开文件。
    if not _any_binding():
        raise _refusal("search_sessions")
    try:
        result = _registry.search(
            scope=scope,
            requested_sources=wanted,
            query=query,
            start=start_dt,
            end=end_dt,
            project=project,
            limit=limit,
            unrouted_status="unsupported",
            unbound_status="unavailable",
        )
    except (PolicyDenied, SafeReadDenied):
        raise ToolError("search_sessions 拒绝：授权或安全读取核对未通过，本次未返回结果。") from None
    if not isinstance(result, dict):
        result = dict(result)
    if result.get("reason") == "scope_mismatch":
        raise ToolError("search_sessions 拒绝：scope 与已绑定授权范围不匹配。")
    if result.get("rejected") is True:
        raise ToolError(_ERR_QUERY_FILTER)
    rows = _coverage_rows_for(
        wanted, unbound_status="unavailable", unrouted_status="unsupported"
    )
    if rows:
        result = _apply_unbound_coverage(result, rows)
    result.setdefault("returned_count", len(result.get("results") or []))
    return result


@app.tool(
    name="read_session_context",
    title="读取会话上下文",
    description=(
        "只读：按已发放的坐标读取某条命中记录的上下文窗口。source 为来源 ID（含 claude_code_cli"
        " 扩展来源：未注入时按固定拒绝文案返回，不读配置也不打开文件）；session_id 为该族的会话"
        "标识，location 为发放结果给出的坐标（行族给行锚、DSH 给帧/行锚、WorkBuddy 给记录锚，"
        "形态由发放侧决定，客户端原样回传即可，不得自行拼装）；scope 必须与检索时一致，否则固定"
        "拒绝且不打开任何文件。project 为宿主授权口径；before/after 为窗口两侧行数（0-10）。"
        "返回内容不含磁盘路径；引用未命中、授权不通过或该族未绑定时均为固定拒绝文案，不回显输入。"
        "WorkBuddy 的正文文件布局未逐字核实，因此其正文读取一律固定拒绝（索引侧结论不冒充正文"
        "覆盖）；DSH 在解码运行时缺失时同样固定拒绝。"
    ),
    structured_output=False,
    annotations=_READ_ONLY_ANNOTATIONS,
)
async def read_session_context(
    source: str,
    session_id: str,
    location: str,
    scope: str,
    project: str | None = None,
    before: int = 2,
    after: int = 2,
) -> dict[str, Any]:
    """只读：按族路由到已绑定的上下文服务；未绑定族一律固定拒绝，不触碰磁盘。"""
    _check_scope(scope)
    if not isinstance(source, str):
        raise ToolError(_ERR_SOURCE_UNKNOWN)
    source = _normalize_source_id(source)
    _check_source_allowed(source, unknown_error=_ERR_SOURCE_UNKNOWN)
    _check_text(session_id, _ERR_REF)
    _check_text(location, _ERR_REF)
    if project is not None:
        _check_text(project, _ERR_PROJECT)
    _check_window(before, after)

    # 扩展来源（claude_code_cli）的固定拒绝在绑定门之前：_check_source_allowed 的契约
    # 明确「未启用≠未绑定服务」，全未绑定时也要给扩展来源专属拒绝文案，而非笼统未绑定。
    if source == _SOURCE_CLAUDE:
        raise ToolError(
            "read_session_context 拒绝：该来源属扩展来源且默认未启用，"
            "本构建未检查其配置，本次未打开任何文件。"
        ) from None
    if not _any_binding():
        raise _refusal("read_session_context")
    try:
        result = _registry.read_context(
            scope=scope,
            source=source,
            session_id=session_id,
            location=location,
            project=project,
            before=before,
            after=after,
        )
    except (PolicyDenied, SafeReadDenied):
        raise ToolError(_ERR_CONTEXT_DENIED) from None
    if not isinstance(result, dict):
        result = dict(result)
    reason = result.get("reason")
    if reason in ("service_unbound", "source_unsupported", "invalid_request"):
        if source == _SOURCE_CLAUDE:
            raise ToolError(
                "read_session_context 拒绝：该来源属扩展来源且默认未启用，"
                "本构建未检查其配置，本次未打开任何文件。"
            ) from None
        if source == _SOURCE_DSH and not _dsh_ready():
            raise ToolError(
                f"read_session_context 拒绝：{dsh_source.DSH_DECODER_MISSING_REASON}，"
                "本次未打开任何文件。"
            ) from None
        if source == _SOURCE_WORKBUDDY:
            raise ToolError(
                f"read_session_context 拒绝：{workbuddy_source.WORKBUDDY_BODY_LAYOUT_REASON}"
            ) from None
        raise ToolError(_read_denial_message(reason)) from None
    if "scope_mismatch" in (result.get("filter_errors") or ()):
        raise ToolError(
            "read_session_context 拒绝：scope 与已绑定授权范围不匹配，本次未打开任何文件。"
        )
    return result


def main() -> None:
    """以 stdio 传输运行服务（DES-ARCH-03：仅本地 stdio，不启动远程监听）。"""
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
