"""最小生产 stdio 宿主：一份显式配置文件 → 策略 → 逐族绑定 → 真实 stdio 传输。

运行方式（本仓库没有打包元数据，因此只能以模块路径启动，仓库根需进 `PYTHONPATH`）::

    python -m cross_agent_session_mcp.host --config <配置绝对路径>
    python -m cross_agent_session_mcp.host --config <配置绝对路径> --check

口径（对齐 DES-ARCH-03 / DES-ARCH-05 / DES-SEC-01，以及 §09「验收边界与后续接入状态」）：

- **只读命令行指定的那一份配置文件**：不读环境变量、不展开 `~`、不做环境变量替换、不猜
  默认存储根，也不读取 Hermes 或其它 Agent 的任何自身配置。MCP 客户端在协议面上仍然
  永远传不进路径：路径的三个来源只有「宿主配置」这一条。
- **显式项目映射 + 显式逐源存储根**：两者缺一即该族不绑定。未配置 / 已关闭 / 根缺失 /
  授权被拒都如实报 `disabled` 或 `unavailable` 并带固定原因码，绝不退化成「先扫一遍看看」，
  也不把「读不下去」说成「没有会话」。
- **绑定顺序与判据全部走既有策略层**：本模块自身不打开任何会话文件，只做元数据级
  `authorize_store` 判定；正文能否发布仍由 `session_pipeline` 逐条核对可信归属（先按项目
  元数据过滤，再谈正文），宿主不代替策略放行任何一条记录。
- 配置错误只报**位置与固定原因码**，不回显路径值：路径本身是敏感信息（含用户目录）。
- `--check` 只做绑定判定并打印 JSON 报告（不启动服务）；默认模式绑定后以 stdio 运行
  `server.app`，与 `server.main()` 同一传输、同一工具面。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from . import server
from .hermes_aggregate import HermesAggregateSearchService, HermesStoreRef
from .line_search import LineAggregateSearchService, spec_for_source
from .policy import (
    CwdRootGrant,
    PolicyDenied,
    ProjectGrant,
    RefusalCode,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
    TargetKind,
    is_safe_literal_path,
)
from .references import ReferenceLedger
from .session_discovery import (
    MAX_DISCOVERY_ROOTS,
    MAX_FILES_PER_QUERY,
    PiMultiFileContextService,
    PiMultiFileSearchService,
    SessionFileRef,
    discover_pi_session_files,
)
from .sources.cursor import discover_cursor_transcripts
from .sources.dsh import discover_dsh_sessions
from .sources.workbuddy import (
    MAX_STORES_PER_QUERY,
    WorkBuddyAggregateSearchService,
    WorkBuddyStoreRef,
)

__all__ = ["ConfigError", "load_config", "build_policy", "bind", "main"]

#: 配置文件格式版本：只认这一版，未知版本一律拒（配置说不清边界时不降级成「部分允许」）。
CONFIG_SCHEMA_VERSION = 1

#: 本宿主可绑定的六个必备来源（与 `server.REQUIRED_SOURCES` 同集合）。
_BINDABLE_SOURCES = ("hermes", "dsh", "workbuddy", "pi", "cursor_agent_cli", "codex")
#: 扩展来源：本最小宿主一律不绑定（正文读取轴在 `server` 侧本就是固定拒绝，绑定只会给出
#: 「检索有结果但读不到上下文」的半截能力，因此按未启用交代，而不是假装可用）。
_EXTENSION_SOURCES = ("claude_code_cli",)
#: 有发现层的来源：无发现层的来源（hermes/workbuddy/codex）只能显式列举绑定集合。
_DISCOVERABLE_SOURCES = ("pi", "cursor_agent_cli", "dsh")
#: store 族（一个绑定项 = 一个库文件 + 库内断言的会话标识）。
_STORE_SOURCES = ("hermes", "workbuddy")


_TOP_KEYS = frozenset({"schema_version", "scope", "projects", "sources"})
_SOURCE_KEYS = frozenset(
    {
        "enabled",
        "store_roots",
        "mode",
        "files",
        "stores",
        "context_index",
        "attribution_project",
        "decoder_python",
    }
)
_PROJECT_KEYS = frozenset({"name", "cwd_roots", "allow_links"})
_MODE_EXPLICIT = "explicit"
_MODE_DISCOVER = "discover"

#: 报告状态（固定集合；与 `list_sources` 的 ready/unavailable/disabled/error 同一取向）。
_STATUS_READY = "ready"
_STATUS_DISABLED = "disabled"
_STATUS_UNAVAILABLE = "unavailable"
_STATUS_ERROR = "error"


class ConfigError(Exception):
    """配置不合法：只带位置与固定原因码，绝不带路径值。"""

    def __init__(self, location: str, reason: str) -> None:
        self.location = location
        self.reason = reason
        super().__init__(f"配置非法：{location} → {reason}")


def _expect_mapping(value: object, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(location, "not_an_object")
    return value


def _expect_list(value: object, location: str) -> list[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ConfigError(location, "not_a_list")
    return list(value)


def _check_keys(source: Mapping[str, Any], allowed: frozenset[str], location: str) -> None:
    unknown = sorted(set(source) - allowed)
    if unknown:
        # 未知键说明配置与实现不同版：宁可拒启动，也不忽略一个可能被误写的授权项。
        raise ConfigError(location, "unknown_key:" + ",".join(unknown))


def _binding_entries(
    block: Mapping[str, Any], key: str, location: str
) -> list[dict[str, str]]:
    """取一族的显式绑定列表（`files` / `stores`），并核对每条的 `path`/`session_id`。

    缺列表与列表形状不合都拒为 `ConfigError`：宿主不拿「配了根但没配集合」当「集合为空」，
    后者是发现层才允许的结论。返回的字典只含两个去空白后的字符串字段。
    """
    value = block.get(key)
    if value is None:
        raise ConfigError(location, f"{key}_not_configured")
    entries = _expect_list(value, location)
    out: list[dict[str, str]] = []
    for index, item in enumerate(entries):
        place = f"{location}[{index}]"
        ref = _expect_mapping(item, place)
        _check_keys(ref, frozenset({"path", "session_id"}), place)
        pair: dict[str, str] = {}
        for field in ("path", "session_id"):
            raw = ref.get(field)
            if not isinstance(raw, str) or not raw.strip():
                raise ConfigError(f"{place}.{field}", "value_not_string")
            pair[field] = raw.strip()
        out.append(pair)
    return out


def _root_entries(value: object, location: str) -> list[dict[str, Any]]:
    """把「字符串或 {path,allow_links}」的根列表规整成字典列表（形状不合即拒）。"""
    entries = _expect_list(value, location)
    if not entries:
        raise ConfigError(location, "empty_roots")
    if len(entries) > MAX_DISCOVERY_ROOTS:
        raise ConfigError(location, "too_many_roots")
    out: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        place = f"{location}[{index}]"
        if isinstance(entry, str):
            out.append({"path": entry, "allow_links": False})
            continue
        item = _expect_mapping(entry, place)
        _check_keys(item, frozenset({"path", "allow_links"}), place)
        path = item.get("path")
        if not isinstance(path, str) or not path.strip():
            raise ConfigError(place, "path_not_string")
        allow_links = item.get("allow_links", False)
        if not isinstance(allow_links, bool):
            raise ConfigError(place, "allow_links_not_bool")
        out.append({"path": path.strip(), "allow_links": allow_links})
    return out


def load_config(config_path: object) -> dict[str, Any]:
    """读取并校验配置形状（纯形状，不触文件系统，除配置本身）。

    路径必须是绝对的字面量：相对路径会让进程 cwd 参与决定「读哪份配置」，同一串在两个
    cwd 下指向两份授权，因此在这里就拒（与策略层的形状门同一判据）。
    """
    raw_path = str(config_path) if isinstance(config_path, (str, Path)) else config_path
    if not is_safe_literal_path(raw_path):
        raise ConfigError("--config", "config_path_unsafe")
    text = Path(raw_path).read_text(encoding="utf-8-sig")
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError as error:
        raise ConfigError("--config", "config_not_json") from error
    if not isinstance(loaded, dict):
        raise ConfigError("配置根", "not_an_object")
    config: dict[str, Any] = loaded
    _check_keys(config, _TOP_KEYS, "配置根")
    version = config.get("schema_version")
    if version is not None and version != CONFIG_SCHEMA_VERSION:
        raise ConfigError("schema_version", "unsupported_schema_version")

    scope = config.get("scope")
    if not isinstance(scope, str) or not scope.strip():
        raise ConfigError("scope", "scope_not_string")
    projects = _expect_list(config.get("projects"), "projects")
    if not projects:
        # 「已批准项目为空」等于没有任何可发布正文的范围：交给策略层同样是 config_invalid，
        # 在这里先拒是为了给出配置位置。
        raise ConfigError("projects", "empty_projects")
    for index, entry in enumerate(projects):
        place = f"projects[{index}]"
        project = _expect_mapping(entry, place)
        _check_keys(project, _PROJECT_KEYS, place)
        name = project.get("name")
        if not isinstance(name, str) or not name.strip() or name != name.strip():
            raise ConfigError(f"{place}.name", "project_name_invalid")
        _root_entries(project.get("cwd_roots"), f"{place}.cwd_roots")

    sources = _expect_mapping(config.get("sources"), "sources")
    if not sources:
        raise ConfigError("sources", "empty_sources")
    for name, entry in sources.items():
        place = f"sources.{name}"
        if name not in _BINDABLE_SOURCES and name not in _EXTENSION_SOURCES:
            raise ConfigError(place, "unknown_source")
        block = _expect_mapping(entry, place)
        _check_keys(block, _SOURCE_KEYS, place)
        enabled = block.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError(f"{place}.enabled", "enabled_not_bool")
        mode = block.get("mode")
        if mode is not None and mode not in (_MODE_EXPLICIT, _MODE_DISCOVER):
            raise ConfigError(f"{place}.mode", "mode_invalid")
        if name in _EXTENSION_SOURCES:
            continue
        if block.get("store_roots") is not None:
            _root_entries(block["store_roots"], f"{place}.store_roots")
        for key in ("files", "stores"):
            if block.get(key) is None:
                continue
            for index, item in enumerate(_expect_list(block[key], f"{place}.{key}")):
                ref = _expect_mapping(item, f"{place}.{key}[{index}]")
                _check_keys(ref, frozenset({"path", "session_id"}), f"{place}.{key}[{index}]")
                for field in ("path", "session_id"):
                    value = ref.get(field)
                    if not isinstance(value, str) or not value.strip():
                        raise ConfigError(f"{place}.{key}[{index}].{field}", "value_not_string")
        index_value = block.get("context_index")
        if index_value is not None and (
            isinstance(index_value, bool) or not isinstance(index_value, int) or index_value < 0
        ):
            raise ConfigError(f"{place}.context_index", "context_index_invalid")
        attribution = block.get("attribution_project")
        if attribution is not None and not isinstance(attribution, str):
            raise ConfigError(f"{place}.attribution_project", "attribution_project_not_string")
        decoder = block.get("decoder_python")
        if decoder is not None and (not isinstance(decoder, str) or not decoder.strip()):
            raise ConfigError(f"{place}.decoder_python", "decoder_python_invalid")
    return config


def build_policy(config: Mapping[str, Any]) -> SessionPolicy:
    """把配置里的显式授权变成 `SessionPolicy`（构造只做自检，不碰文件系统）。"""
    scope = str(config["scope"]).strip()
    projects: list[ProjectGrant] = []
    for entry in config["projects"]:
        roots = tuple(
            CwdRootGrant(item["path"], item["allow_links"])
            for item in _root_entries(entry["cwd_roots"], "cwd_roots")
        )
        projects.append(ProjectGrant(entry["name"].strip(), roots))
    store_roots: list[StoreRootGrant] = []
    for name, block in _expect_mapping(config.get("sources"), "sources").items():
        if name in _EXTENSION_SOURCES or not isinstance(block, Mapping):
            continue
        if block.get("store_roots") is None:
            continue
        for item in _root_entries(block["store_roots"], f"sources.{name}.store_roots"):
            store_roots.append(StoreRootGrant(name, item["path"], item["allow_links"]))
    return SessionPolicy(
        scopes=(ScopeGrant(scope_id=scope, projects=tuple(projects), store_roots=tuple(store_roots)),)
    )


#: 行族绑定入口表（与 `server` 的 bind_* 函数名逐条对应，不用动态拼名：拼错一个属性
#: 就会静默走 `getattr(..., None)` 分支，这里把对应关系写死可读）。
_LINE_BINDERS: dict[str, tuple[str, str]] = {
    "codex": ("bind_codex_file_search_service", "bind_codex_file_context_service"),
    "cursor_agent_cli": (
        "bind_cursor_file_search_service",
        "bind_cursor_file_context_service",
    ),
}

def _row(source: str, status: str, reason: str, **extra: Any) -> dict[str, Any]:
    """绑定报告行：只有状态、固定原因码与计数，不含任何路径或标识值。"""
    row: dict[str, Any] = {"source": source, "status": status, "reason": reason}
    row.update(extra)
    return row


def _refusal_reason(denial: PolicyDenied) -> str:
    return denial.code.value if isinstance(denial.code, RefusalCode) else "policy_denied"


def _project_names(policy: SessionPolicy, scope: str) -> tuple[str, ...]:
    try:
        return policy.project_names(scope)
    except PolicyDenied:
        return ()


def _collect_refs(
    policy: SessionPolicy,
    scope: str,
    source: str,
    candidates: Sequence[tuple[str, str]],
    *,
    limit: int,
) -> tuple[list[SessionFileRef], int, str | None]:
    """逐条授权候选绑定项，只交付通过的 `SessionFileRef`。

    返回 `(refs, 被拒条数, 错误行)`。被拒（形状/越界/链接/不存在）的条目不进绑定集合：
    宿主不拿「策略会拒绝的路径」冒充批准集合，也不整族降级——计数如实写进报告行。
    """
    refs: list[SessionFileRef] = []
    seen: set[str] = set()
    denied = 0
    for session_id, path in candidates:
        if path in seen:
            continue
        seen.add(path)
        try:
            policy.authorize_store(scope, source, path, kind=TargetKind.FILE)
        except PolicyDenied:
            denied += 1
            continue
        try:
            refs.append(SessionFileRef(path=path, session_id=session_id))
        except ValueError:
            # 会话标识形态不合：断言资格都没有，计数丢弃，不猜一个可用的 id。
            denied += 1
    if len(refs) > limit:
        return (refs, denied, f"too_many_bindings:{limit}")
    return (refs, denied, None)


def _discover_line_family(
    policy: SessionPolicy, scope: str, source: str, roots: Sequence[str], attribution: object
) -> tuple[list[tuple[str, str]], list[str]]:
    """游标/DSH 的有界发现：把「相对存储根」的候选拼回**已批准的根**上。

    返回 `(候选, 各根状态串)`。状态不合并：`disabled`（未配置）、`unavailable`（不可判定）
    与 `no_candidates_on_facet`（该面无匹配）是三种结论，宿主逐根如实带出。
    """
    discovered: list[tuple[str, str]] = []
    statuses: list[str] = []
    for root in roots:
        if source == "cursor_agent_cli":
            outcome = discover_cursor_transcripts(
                policy, scope, store_root_path=root, attribution_project=attribution
            )
            status, candidates = outcome.status.value, outcome.candidates
        else:
            outcome = discover_dsh_sessions(
                policy, scope, store_root_path=root, attribution_project=attribution
            )
            status, candidates = outcome.status.value, outcome.candidates
        statuses.append(status)
        for session_id, relative in candidates:
            absolute = str(Path(root, *relative.split("/")))
            discovered.append((session_id, absolute))
    return discovered, statuses


def _bind_pi(
    policy: SessionPolicy,
    scope: str,
    block: Mapping[str, Any],
    ledger: ReferenceLedger,
) -> dict[str, Any]:
    """pi：有发现层，且上下文槽位按集合路由（`PiMultiFileContextService`）。"""
    roots_cfg = block.get("store_roots")
    mode = block.get("mode") or _MODE_EXPLICIT
    if mode == _MODE_DISCOVER:
        if roots_cfg is None:
            return _row("pi", _STATUS_UNAVAILABLE, "no_store_roots")
        roots = [item["path"] for item in _root_entries(roots_cfg, "sources.pi.store_roots")]
        outcome = discover_pi_session_files(policy, scope, roots)
        refs = list(outcome.files)
        # 发现层自己只交过授权的引用，拒数取它自己的计数（根级逐条 + 文件级按原因汇总），
        # 不在此重新推断：`roots_refused` 一项即一次拒绝，`files_denied` 行带 `count`。
        denied = len(outcome.roots_refused) + sum(
            int(row.get("count", 0)) for row in outcome.files_denied
        )
        incomplete = not outcome.complete
    else:
        entries = _binding_entries(block, "files", "sources.pi.files")
        collected, denied, error = _collect_refs(
            policy,
            scope,
            "pi",
            [(item["session_id"], item["path"]) for item in entries],
            limit=MAX_FILES_PER_QUERY,
        )
        if error:
            return _row("pi", _STATUS_ERROR, error)
        refs = collected
        incomplete = False
    if not refs:
        # 空集合不绑定：构造门也会拒（「一个文件都没有时，无匹配是无根据的宣称」）。
        return _row("pi", _STATUS_UNAVAILABLE, "no_bound_files", bindings_denied=denied)
    search = PiMultiFileSearchService(policy=policy, scope=scope, files=refs, ledger=ledger)
    context = PiMultiFileContextService(policy=policy, scope=scope, files=refs, ledger=ledger)
    # 成对生效：同账本、同集合、同 scope 由服务自己带齐，宿主不手抄配对参数。
    server.bind_pi_multi_file_search_service(search)
    server.bind_pi_multi_file_context_service(context, search_service=search)
    return _row(
        "pi",
        _STATUS_READY,
        "bound",
        files_bound=len(refs),
        bindings_denied=denied,
        coverage_incomplete=incomplete,
    )


def _bind_line(
    policy: SessionPolicy,
    scope: str,
    source: str,
    block: Mapping[str, Any],
    ledger: ReferenceLedger,
) -> dict[str, Any]:
    """行族（codex / cursor_agent_cli / dsh）：有界文件集合 + 单文件上下文槽位。

    上下文槽位在 `server` 侧按来源只有一条（`_line_context_slots[source]`），因此本宿主每个
    行族只交付**一条**上下文绑定（默认集合首条，可用 `context_index` 指名）：其余文件的 ctxref
    会按既有口径得到 `binding_mismatch`，不是本层新造的拒绝理由。
    """
    mode = block.get("mode") or _MODE_EXPLICIT
    statuses: list[str] = []
    if mode == _MODE_DISCOVER:
        if source not in _DISCOVERABLE_SOURCES or block.get("store_roots") is None:
            return _row(source, _STATUS_UNAVAILABLE, "discovery_not_available")
        roots = [
            item["path"]
            for item in _root_entries(block["store_roots"], f"sources.{source}.store_roots")
        ]
        candidates, statuses = _discover_line_family(
            policy, scope, source, roots, block.get("attribution_project")
        )
    else:
        entries = _binding_entries(block, "files", f"sources.{source}.files")
        candidates = [(item["session_id"], item["path"]) for item in entries]
    refs, denied, error = _collect_refs(
        policy, scope, source, candidates, limit=MAX_FILES_PER_QUERY
    )
    if error:
        return _row(source, _STATUS_ERROR, error)
    if not refs:
        return _row(
            source,
            _STATUS_UNAVAILABLE,
            "no_bound_files" if not statuses else "no_candidates",
            discovery_status=",".join(statuses) if statuses else None,
            bindings_denied=denied,
        )
    spec = spec_for_source(source)
    if spec is None:  # pragma: no cover - 注册表在导入期即建好，缺项属实现缺陷
        return _row(source, _STATUS_ERROR, "spec_missing")
    index_value = block.get("context_index") or 0
    if index_value >= len(refs):
        # 下标越界是宿主配置错误：不拿「第一条正好能绑」当默认，也不静默改指另一个文件。
        return _row(source, _STATUS_ERROR, "context_index_out_of_range")
    search = LineAggregateSearchService(
        policy=policy, scope=scope, spec=spec, files=refs, ledger=ledger
    )
    context = search.context_service(index_value)
    if source == "dsh":
        # 解码运行时只在查询侧绑定入口注入：`bind_dsh_search_service` 会 probe 并把可用运行时
        # 固化进 spec（P1-2）。上下文侧因此**不再**回传未固化的 search 对象，也不第二次传
        # `decoder_python`（两遍路径不同会被绑定门拒为 TypeError），配对取槽位里的固化对象。
        server.bind_dsh_search_service(search, decoder_python=block.get("decoder_python"))
        server.bind_dsh_context_service(context)
        runtime = getattr(server, "_dsh_runtime", None)
        usable = runtime is not None and bool(getattr(runtime, "usable", False))
        return _row(
            source,
            _STATUS_READY if usable else _STATUS_ERROR,
            "bound" if usable else "decoder_runtime_unusable",
            files_bound=len(refs),
            bindings_denied=denied,
            context_bound=True,
            context_index=index_value,
            discovery_status=",".join(statuses) if statuses else None,
        )
    search_name, context_name = _LINE_BINDERS[source]
    getattr(server, search_name)(search)
    getattr(server, context_name)(context, search_service=search)
    return _row(
        source,
        _STATUS_READY,
        "bound",
        files_bound=len(refs),
        bindings_denied=denied,
        # 只报「上下文轴已绑」与下标，不回写会话标识（报告面不跟结果面混用同一标识）。
        context_bound=True,
        context_index=index_value,
        discovery_status=",".join(statuses) if statuses else None,
    )


def _bind_store_family(
    policy: SessionPolicy,
    scope: str,
    source: str,
    block: Mapping[str, Any],
    ledger: ReferenceLedger,
) -> dict[str, Any]:
    """store 族（hermes / workbuddy）：无发现层，绑定集合只能逐条显式给出。"""
    entries = _binding_entries(block, "stores", f"sources.{source}.stores")
    if len(entries) > MAX_STORES_PER_QUERY:
        return _row(source, _STATUS_ERROR, f"too_many_bindings:{MAX_STORES_PER_QUERY}")
    stores: list[Any] = []
    denied = 0
    seen: set[str] = set()
    ref_cls = HermesStoreRef if source == "hermes" else WorkBuddyStoreRef
    for item in entries:
        path = item["path"]
        session_id = item["session_id"]
        if path in seen:
            continue
        seen.add(path)
        try:
            policy.authorize_store(scope, source, path, kind=TargetKind.FILE)
        except PolicyDenied:
            # 未批准的库绝不进绑定集合：本族没有发现层，缺根就是缺根。
            denied += 1
            continue
        try:
            stores.append(ref_cls(store_path=path, session_id=session_id))
        except ValueError:
            # 库内断言的会话标识形态不合：不给它编一个可用的 id，计数丢弃。
            denied += 1
    if not stores:
        return _row(source, _STATUS_UNAVAILABLE, "no_bound_stores", bindings_denied=denied)
    if source == "hermes":
        search = HermesAggregateSearchService(
            policy=policy, scope=scope, stores=tuple(stores), ledger=ledger
        )
        server.bind_hermes_aggregate_search_service(search)
        server.bind_hermes_aggregate_context_service(
            search.context_service(), search_service=search
        )
    else:
        search = WorkBuddyAggregateSearchService(
            policy=policy, scope=scope, stores=tuple(stores), ledger=ledger
        )
        server.bind_workbuddy_store_search_service(search)
        server.bind_workbuddy_store_context_service(
            search.context_service(), search_service=search
        )
    return _row(
        source,
        _STATUS_READY,
        "bound",
        stores_bound=len(stores),
        bindings_denied=denied,
        # 正文口径由来源层自己交代（游标 GUI、workbuddy 正文布局未核实），宿主不额外承诺。
        body_publication="source_layer_decides",
    )


def bind(config: Mapping[str, Any], *, reset: bool = True) -> dict[str, Any]:
    """按配置绑定各族服务，返回只含状态与计数的宿主报告。

    单族失败只影响该族（其余族继续绑定），与 `list_sources` 的逐源口径一致；但绝不
    「降级猜测」：任何缺根、缺映射、被拒的条目都以固定原因码留在报告里，不静默通过。
    """
    scope = str(config["scope"]).strip()
    try:
        policy = build_policy(config)
    except PolicyDenied as denial:
        return {
            "scope": scope,
            "status": _STATUS_ERROR,
            "reason": _refusal_reason(denial),
            "sources": [],
        }
    except ConfigError as error:
        return {
            "scope": scope,
            "status": _STATUS_ERROR,
            "reason": error.reason,
            "location": error.location,
            "sources": [],
        }
    if reset:
        # 干净起点：不留半对绑定，也不沿用上一轮的引用账本。
        server.reset_bound_services()
    ledger = ReferenceLedger()
    rows: list[dict[str, Any]] = []
    sources = _expect_mapping(config.get("sources"), "sources")
    for name in _BINDABLE_SOURCES:
        block = sources.get(name)
        if not isinstance(block, Mapping) or not block.get("enabled", True):
            rows.append(
                _row(
                    name,
                    _STATUS_DISABLED,
                    "not_configured" if block is None else "explicitly_disabled",
                )
            )
            continue
        try:
            if block.get("store_roots") is None:
                # 无论显式列举还是发现：没有根就没有任何可读位置被批准，直接报不可用。
                rows.append(_row(name, _STATUS_UNAVAILABLE, "no_store_roots"))
                continue
            if (block.get("mode") or _MODE_EXPLICIT) == _MODE_DISCOVER and (
                name not in _DISCOVERABLE_SOURCES
            ):
                # 本族无发现层：只能显式列举，绝不得到「先扫库文件」的兼容处理。
                rows.append(_row(name, _STATUS_UNAVAILABLE, "discovery_not_supported"))
                continue
            if name == "pi":
                rows.append(_bind_pi(policy, scope, block, ledger))
            elif name in _STORE_SOURCES:
                rows.append(_bind_store_family(policy, scope, name, block, ledger))
            else:
                rows.append(_bind_line(policy, scope, name, block, ledger))
        except PolicyDenied as denial:
            rows.append(_row(name, _STATUS_UNAVAILABLE, _refusal_reason(denial)))
        except ConfigError as error:
            # 配置形状在本族才暴露：位点可写（只含配置键路径，不含文件路径）。
            rows.append(_row(name, _STATUS_ERROR, error.reason, location=error.location))
        except (TypeError, ValueError) as failure:
            # 绑定门的失败是宿主配置错误：留固定类名，不外抛原始消息（可能含值）。
            rows.append(_row(name, _STATUS_ERROR, type(failure).__name__))
    for name in _EXTENSION_SOURCES:
        if name in sources:
            rows.append(_row(name, _STATUS_DISABLED, "extension_source_not_enabled"))
    return {
        "scope": scope,
        "projects_authorized": list(_project_names(policy, scope)),
        "status": _STATUS_READY
        if any(row["status"] == _STATUS_READY for row in rows)
        else _STATUS_UNAVAILABLE,
        "sources": rows,
    }


def _print_report(report: Mapping[str, Any], *, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return
    # 人读一行一族：走 stderr，stdout 在默认模式下留给 stdio 协议的 stderr 诊断通道。
    print(
        f"[host] scope={report['scope']} status={report['status']} bound="
        f"{sum(1 for row in report['sources'] if row['status'] == _STATUS_READY)}",
        file=sys.stderr,
    )
    for row in report["sources"]:
        extra = "".join(
            f" {key}={row[key]}"
            for key in ("files_bound", "stores_bound", "bindings_denied", "context_bound")
            if row.get(key) is not None
        )
        print(f"[host]   {row['source']}: {row['status']} ({row['reason']}){extra}", file=sys.stderr)
    if report["status"] != _STATUS_READY:
        print(
            "[host] 本进程未绑定任何来源：search_sessions 与 read_session_context 一律安全拒绝。",
            file=sys.stderr,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cross_agent_session_mcp.host",
        description="最小生产 stdio 宿主：从一份显式配置绑定只读检索服务。",
    )
    parser.add_argument("--config", required=True, help="授权配置文件的绝对路径（JSON）")
    parser.add_argument(
        "--check",
        action="store_true",
        help="只做绑定判定并打印 JSON 报告，不启动 stdio 服务",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="任一已启用来源绑定失败即退出（默认：该族报 unavailable/error，其余族继续）",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        config = load_config(args.config)
    except ConfigError as error:
        print(f"[host] 配置非法：{error.location} → {error.reason}", file=sys.stderr)
        return 2
    except OSError:
        # 不回显路径：配置路径本身含用户目录信息。
        print("[host] 配置不可读：config_unreadable", file=sys.stderr)
        return 2

    report = bind(config)
    _print_report(report, json_mode=args.check)
    if args.check:
        return 0 if report["status"] in (_STATUS_READY, _STATUS_UNAVAILABLE) else 2
    if report["status"] == _STATUS_ERROR:
        # 策略本身建不起来（配置不合法）：不拉起一个只会逐条拒绝的服务，直接退。
        print(f"[host] 授权配置不可用：{report.get('reason')}，未启动服务。", file=sys.stderr)
        return 2
    failed = [row for row in report["sources"] if row["status"] == _STATUS_ERROR]
    if args.strict and failed:
        print("[host] --strict：存在绑定失败的已启用来源，不启动服务。", file=sys.stderr)
        return 2
    # 与 `server.main()` 同一传输：stdio，不监听端口，不接受客户端传路径。
    server.app.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
