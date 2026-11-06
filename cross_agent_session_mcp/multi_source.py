"""跨来源服务注册表与聚合合并。

本模块只做两件事：

1. ``ServiceRegistry``：按「服务族」登记各类检索/上下文服务，并把一次多来源请求
   路由到对应服务。路由失败必须显式化为 coverage 行，不得静默丢来源。
2. ``merge_search_outcomes``：把各来源服务返回的公开字典合并成一份对外结果。
   合并发生在脱敏之后——本模块只搬运已发布行，不接触任何原文。

合并规则（与实现方案 D-1/D-2 一致）：
- 结果行：稳定排序合并，排序键 ``(timestamp is None, timestamp or MIN, source,
  session_id, location)``，截到请求 limit；被丢弃行数记入 ``dropped_results``。
- coverage：按来源取并集，同来源多行取首行；未被路由的来源固定为
  ``disabled``/``unavailable`` 行。
- 顶层：``complete`` 要求所有被请求来源都被路由且 coverage 完整；任一来源拒绝
  即顶层 ``rejected``；任一来源 ``scope_mismatch`` 即顶层 ``scope_mismatch``。
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

__all__ = [
    "FamilyContextEntry",
    "FamilySearchEntry",
    "MAX_REQUESTED_SOURCES",
    "RegistryCodes",
    "ServiceRegistry",
    "merge_search_outcomes",
    "source_coverage_rows",
]

#: 单次请求允许点名的来源数上限（与 scan_filter 的来源列表上限同口径）。
MAX_REQUESTED_SOURCES = 32

#: 排序兜底用的最小时间戳（无时间戳的行一律排在有时间戳的行之后）。
_MIN_TIMESTAMP = datetime.min


class RegistryCodes:
    """注册表自身的失败码（闭合集合，值与既有 reason 词表同形）。"""

    INVALID_REQUEST = "invalid_request"
    SOURCE_UNSUPPORTED = "source_unsupported"
    SERVICE_UNBOUND = "service_unbound"
    INTERNAL_FAILURE = "internal_failure"


# ---------------------------------------------------------------------------
# 注册表条目
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FamilySearchEntry:
    """一个来源族的检索服务绑定。

    - ``family``：族标识（如 ``codex-line``）。
    - ``sources``：该族覆盖的来源 id。
    - ``make_service``：由调用方参数构造服务实例的工厂。
    - ``snapshot``：从已绑定服务读取公开快照的函数（未绑定服务时为 ``None``）。
    """

    family: str
    sources: tuple[str, ...]
    make_service: Callable[..., Any]
    snapshot: Callable[[Any], Mapping[str, Any]] | None = None
    clear: Callable[[], None] | None = field(default=None)


@dataclass(frozen=True)
class FamilyContextEntry:
    """一个来源族的上下文服务绑定；``make_service`` 返回 None 表示不可路由。"""

    family: str
    sources: tuple[str, ...]
    make_service: Callable[..., Any]


# ---------------------------------------------------------------------------
# 覆盖行辅助
# ---------------------------------------------------------------------------


def _clean_source_id(value: Any) -> str:
    """把来源 id 归一成可发布字符串；非字符串取 ``str`` 并限长。"""
    text = value if isinstance(value, str) else str(value)
    return text.strip()[:64]


def _normalize_sources(sources: Iterable[Any] | None) -> tuple[str, ...]:
    """来源列表去重保序；``None`` 表示未指名。"""
    if sources is None:
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for raw in sources:
        name = _clean_source_id(raw)
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return tuple(out)


def _default_coverage_row(source: str, status: str) -> dict[str, Any]:
    """未路由来源的固定 coverage 行；零计数、无错误标签。"""
    return {
        "source": source,
        "status": status,
        "scanned_count": 0,
        "matched_count": 0,
        "returned_count": 0,
        "skipped_count": 0,
        "partial": False,
        "filter_errors": [],
        "reason": "",
    }


def source_coverage_rows(
    payload: Any,
    source: str,
    *,
    unavailable_status: str = "unavailable",
) -> tuple[dict[str, Any], ...]:
    """从服务返回的公开字典里取某来源的 coverage 行；缺失时给固定兜底行。

    兜底行只在服务自身没有覆盖到该来源时使用（例如服务族被请求但内部来源列表
    不含它），保持 ``scanned_count`` 等计数与 ``status`` 的既有语义：未扫即 0。
    """
    rows = payload.get("coverage") if isinstance(payload, dict) else None
    if isinstance(rows, (list, tuple)):
        picked = [
            dict(row)
            for row in rows
            if isinstance(row, dict) and _clean_source_id(row.get("source")) == source
        ]
        if picked:
            return tuple(picked)
    status = unavailable_status if unavailable_status in ("disabled", "unavailable", "error") else "unavailable"
    return (_default_coverage_row(source, status),)


def _payload_reason(payload: Mapping[str, Any]) -> str:
    reason = payload.get("reason")
    return reason if isinstance(reason, str) else ""


# ---------------------------------------------------------------------------
# 注册表
# ---------------------------------------------------------------------------


class ServiceRegistry:
    """来源族 → 服务工厂的登记表。

    注册表不持有具体服务实例：实例由工厂在请求时构造或从 server 的绑定缓存取，
    这样 ``reset_bound_services()`` 只需清 server 侧缓存，注册表无需同步重建。
    """

    __slots__ = ("_search", "_context", "_known_sources")

    def __init__(self) -> None:
        self._search: dict[str, FamilySearchEntry] = {}
        self._context: dict[str, FamilyContextEntry] = {}
        self._known_sources: list[str] = []

    # ---- 登记 ----

    def register_search(self, entry: FamilySearchEntry) -> None:
        """登记一个检索族；同族重复登记视为配置错误。"""
        if not isinstance(entry, FamilySearchEntry):
            raise TypeError("entry must be FamilySearchEntry")
        if entry.family in self._search:
            raise ValueError(f"search family already registered: {entry.family}")
        self._search[entry.family] = entry
        for source in entry.sources:
            if source not in self._known_sources:
                self._known_sources.append(source)

    def register_context(self, entry: FamilyContextEntry) -> None:
        """登记一个上下文族（与检索族同名即可，二者分开存储）。"""
        if not isinstance(entry, FamilyContextEntry):
            raise TypeError("entry must be FamilyContextEntry")
        if entry.family in self._context:
            raise ValueError(f"context family already registered: {entry.family}")
        self._context[entry.family] = entry
        for source in entry.sources:
            if source not in self._known_sources:
                self._known_sources.append(source)

    def reset(self) -> None:
        """清空全部族绑定（先跑各族自带的解绑钩子）：`reset_bound_services` 的唯一入口。

        钩子按登记逆序执行，与绑定顺序对称；任一钩子报错就当场抛出，不留半清状态。
        """
        for entry in reversed(list(self._search.values())):
            if entry.clear is not None:
                entry.clear()
        self._search.clear()
        self._context.clear()
        self._known_sources.clear()

    def register(self, *, search: FamilySearchEntry, context: FamilyContextEntry | None = None) -> None:
        """便捷登记：一次把检索族与同名上下文族放进注册表。"""
        if search.family != (context.family if context is not None else search.family):
            raise ValueError("search and context families must share the family id")
        self.register_search(search)
        if context is not None:
            self.register_context(context)

    # ---- 查询 ----

    @property
    def known_sources(self) -> tuple[str, ...]:
        """已登记族覆盖的全部来源 id（注册顺序）。"""
        return tuple(self._known_sources)

    def families(self) -> tuple[str, ...]:
        """已登记的检索族 id。"""
        return tuple(self._search)

    def families_for(self, sources: Iterable[Any] | None) -> tuple[str, ...]:
        """按请求来源筛出需要路由的族 id（未指名 = 全部已登记族）。"""
        wanted = _normalize_sources(sources)
        if not wanted:
            return tuple(self._search)
        out: list[str] = []
        for family, entry in self._search.items():
            if any(source in wanted for source in entry.sources):
                out.append(family)
        return tuple(out)

    def route_sources(self, sources: Iterable[Any] | None) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """把请求来源拆成「已登记」与「未知」两组。"""
        wanted = _normalize_sources(sources)
        if not wanted:
            return self.known_sources, ()
        known = tuple(s for s in wanted if any(s in e.sources for e in self._search.values()))
        unknown = tuple(s for s in wanted if s not in known)
        return known, unknown

    def supports_context(self, source: Any) -> bool:
        """某来源是否有上下文族。"""
        name = _clean_source_id(source)
        return any(name in entry.sources for entry in self._context.values())

    # ---- 路由：检索 ----

    def search(
        self,
        *,
        scope: str,
        requested_sources: Iterable[Any] | None,
        query: str | None = None,
        start: Any = None,
        end: Any = None,
        project: Any = None,
        limit: int,
        unrouted_status: str = "error",
        unbound_status: str = "disabled",
    ) -> dict[str, Any]:
        """把一次检索请求路由到各族并合并结果。

        未登记的来源、无服务绑定的来源分别产出固定 coverage 行；两者的区别必须
        可由调用方读出（``source_unsupported`` vs ``service_unbound``）。

        两个状态词由调用方给定（默认 ``error`` / ``disabled``）：协议面要知道「本构建
        根本没有这一族」与「有这一族但宿主没绑定」的差别，而注册表本身只知道槽位空
        不空。reason 码不受此参数影响，状态词也不做白名单校验——写错的口径由调用方
        自己负责，注册表不猜。
        """
        wanted = _normalize_sources(requested_sources) or list(self.known_sources)
        if len(wanted) > MAX_REQUESTED_SOURCES:
            return _registry_rejection(RegistryCodes.INVALID_REQUEST, wanted)

        payloads: dict[str, Any] = {}
        unbound: list[dict[str, Any]] = []
        for source in wanted:
            entry = self._entry_for(source)
            if entry is None:
                unbound.append(
                    {
                        **_default_coverage_row(source, unrouted_status),
                        "partial": True,
                        "filter_errors": [RegistryCodes.SOURCE_UNSUPPORTED],
                        "reason": RegistryCodes.SOURCE_UNSUPPORTED,
                    }
                )
                continue
            service = _bound_service(entry, scope=scope)
            if service is None:
                unbound.append(
                    {
                        **_default_coverage_row(source, unbound_status),
                        "filter_errors": [RegistryCodes.SERVICE_UNBOUND],
                        "reason": RegistryCodes.SERVICE_UNBOUND,
                    }
                )
                continue
            payloads[source] = _call_search(
                service,
                scope=scope,
                sources=(source,),
                query=query,
                start=start,
                end=end,
                project=project,
                limit=limit,
            )
        return merge_search_outcomes(payloads, wanted, unbound_rows=unbound, limit=limit)

    def _entry_for(self, source: str) -> FamilySearchEntry | None:
        for entry in self._search.values():
            if source in entry.sources:
                return entry
        return None

    # ---- 路由：上下文 ----

    def read_context(
        self,
        *,
        scope: str,
        source: Any,
        session_id: Any = None,
        session_ref: Any = None,
        location: Any = None,
        around: Any = None,
        project: Any = None,
        before: int = 2,
        after: int = 2,
    ) -> dict[str, Any]:
        """把一次上下文请求路由到对应族。

        实参名与各族上下文服务的公开签名一致（`session_id`/`location`）；旧别名
        `session_ref`/`around` 仍接受，以免调用方改造期两头改。
        """
        name = _clean_source_id(source)
        if not name:
            return _context_refusal("invalid_request", "invalid_request")
        anchor = session_id if session_id is not None else session_ref
        coordinate = location if location is not None else around
        entry = None
        for candidate in self._context.values():
            if name in candidate.sources:
                entry = candidate
                break
        if entry is None:
            return _context_refusal("source_unsupported", "source_unsupported")
        service = entry.make_service(scope=scope, source=name)
        if service is None:
            return _context_refusal("service_unbound", "service_unbound")
        if not hasattr(service, "read"):
            return _context_refusal("service_unbound", "service_unbound")
        outcome = service.read(
            scope=scope,
            source=name,
            session_id=anchor,
            location=coordinate,
            project=project,
            before=before,
            after=after,
        )
        if isinstance(outcome, Mapping):
            return dict(outcome)
        as_public = getattr(outcome, "as_public_dict", None)
        if callable(as_public):
            public = as_public()
            if isinstance(public, Mapping):
                return dict(public)
        raise TypeError("context outcome must be a mapping or expose as_public_dict()")


def _bound_service(entry: FamilySearchEntry, *, scope: str) -> Any:
    """向族工厂取已绑定服务实例；未绑定返回 ``None``。

    工厂负责比对 scope：返回 ``False``/``None`` 表示该族在此 scope 无服务绑定。
    """
    return entry.make_service(scope=scope)


def _call_search(
    service: Any,
    *,
    scope: str,
    sources: tuple[str, ...],
    query: str | None,
    start: Any,
    end: Any,
    project: Any,
    limit: int,
) -> Any:
    """统一调用服务 ``search``：返回该来源的公开载荷（字典或 outcome 对象都可）。

    来源列表**显式带上这一条来源**而不传 None：各族对 None 的默认口径不同（有的当作
    「只查自己」，有的当作「不筛来源」），注册表按来源逐个路由时必须把口径钉死。
    """
    return service.search(
        scope=scope,
        query=query,
        sources=sources,
        start=start,
        end=end,
        project=project,
        limit=limit,
    )


def _registry_rejection(code: str, sources: Sequence[str]) -> dict[str, Any]:
    """注册表层的固定拒绝载荷（不触盘）。"""
    return {
        "results": [],
        "coverage": [
            {**_default_coverage_row(source, "error"), "partial": True, "reason": code}
            for source in sources
        ],
        "complete": False,
        "partial": False,
        "truncated": False,
        "total_matched": 0,
        "total_scanned": 0,
        "skipped_records": 0,
        "records_withheld": 0,
        "dropped_results": 0,
        "reason": code,
        "rejected": True,
        "failure_category": code,
        "stage_reached": "coordinator",
        "coverage_scope": "none",
        "files": [],
    }


def _context_refusal(category: str, reason: str) -> dict[str, Any]:
    """上下文层的固定拒绝载荷（与既有 refused 形态同形）。"""
    return {
        "records": [],
        "window": None,
        "coverage": None,
        "partial": False,
        "complete": False,
        "reason": reason,
        "failure_category": category,
        "stage_reached": "coordinator",
        "coverage_scope": "none",
        "records_withheld": 0,
        "redaction_withheld": 0,
    }


# ---------------------------------------------------------------------------
# 合并
# ---------------------------------------------------------------------------


def _as_public_dict(payload: Any) -> dict[str, Any]:
    """接受 outcome 对象或公开字典，统一成可合并的字典视图。"""
    if isinstance(payload, Mapping):
        return dict(payload)
    as_public = getattr(payload, "as_public_dict", None)
    if callable(as_public):
        out = as_public()
        if isinstance(out, Mapping):
            return dict(out)
    raise TypeError("payload must be a mapping or expose as_public_dict()")


def _rows(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("results")
    if not isinstance(raw, (list, tuple)):
        return []
    return [dict(row) for row in raw if isinstance(row, Mapping)]


def _coverage(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("coverage")
    if not isinstance(raw, (list, tuple)):
        return []
    return [dict(row) for row in raw if isinstance(row, Mapping)]


def _row_sort_key(row: Mapping[str, Any]) -> tuple[int, Any, str, str, str]:
    """稳定排序键：有时间戳优先、按时间升序、再按来源/会话/坐标。"""
    stamp = row.get("timestamp")
    has_stamp = 0 if isinstance(stamp, str) and stamp else 1
    order = stamp if has_stamp == 0 else _MIN_TIMESTAMP.isoformat()
    return (
        has_stamp,
        order,
        str(row.get("source") or ""),
        str(row.get("session_id") or ""),
        str(row.get("location") or ""),
    )


def _truthy(payload: Mapping[str, Any], key: str) -> bool:
    return payload.get(key) is True


def _count(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _status_rank(status: Any) -> int:
    """同来源多 coverage 行的合并优先级：error > incomplete > searched > no_match > 其余。"""
    order = {
        "error": 0,
        "incomplete": 1,
        "searched": 2,
        "no_match": 3,
        "disabled": 4,
        "unavailable": 5,
    }
    return order.get(status if isinstance(status, str) else "", 6)


def _merge_coverage_row(target: dict[str, Any], extra: Mapping[str, Any]) -> None:
    """把同一来源的第二行并入首行：计数相加、标签并集、状态取更差者。"""
    for key in ("scanned_count", "matched_count", "returned_count", "skipped_count"):
        target[key] = _count(target, key) + _count(extra, key)
    for key in ("total_bytes_read", "matched_files", "scanned_files", "searched_files"):
        if key in extra or key in target:
            target[key] = _count(target, key) + _count(extra, key)
    if isinstance(extra.get("window"), dict) and not isinstance(target.get("window"), dict):
        target["window"] = dict(extra["window"])
    tags = list(target.get("filter_errors") or [])
    for tag in list(extra.get("filter_errors") or []):
        if tag not in tags:
            tags.append(tag)
    target["filter_errors"] = tags
    notes = [text for text in (target.get("reason"), extra.get("reason")) if isinstance(text, str) and text]
    unique: list[str] = []
    for text in notes:
        if text not in unique:
            unique.append(text)
    target["reason"] = "；".join(unique)
    target["partial"] = bool(target.get("partial")) or bool(extra.get("partial"))
    if _status_rank(extra.get("status")) < _status_rank(target.get("status")):
        target["status"] = extra.get("status")


def merge_search_outcomes(
    payloads: Mapping[str, Any] | Iterable[tuple[str, Any]],
    requested_sources: Sequence[Any] | None,
    *,
    unbound_rows: Iterable[Mapping[str, Any]] = (),
    limit: int | None = None,
) -> dict[str, Any]:
    """合并多来源检索载荷为一份公开结果。

    ``payloads`` 的键只用于诊断，实际来源归属取行内 ``source`` 字段；
    ``unbound_rows`` 是未路由来源（未绑定/未支持）的固定 coverage 行。
    ``limit`` 为跨来源二次截断上限（各服务已按同一 limit 截过，此处收敛总量）。
    """
    items = list(payloads.items()) if isinstance(payloads, Mapping) else list(payloads)
    wanted = _normalize_sources(requested_sources)
    dicts = [(label, _as_public_dict(payload)) for label, payload in items]

    merged_rows: list[dict[str, Any]] = []
    coverage_by_source: dict[str, list[dict[str, Any]]] = {}
    files: list[dict[str, Any]] = []

    for _, payload in dicts:
        merged_rows.extend(_rows(payload))
        for row in _coverage(payload):
            name = _clean_source_id(row.get("source"))
            if not name:
                continue
            coverage_by_source.setdefault(name, []).append(row)
        raw_files = payload.get("files")
        if isinstance(raw_files, (list, tuple)):
            files.extend(dict(entry) for entry in raw_files if isinstance(entry, Mapping))

    for row in unbound_rows:
        name = _clean_source_id(row.get("source"))
        if not name:
            continue
        coverage_by_source.setdefault(name, []).append(dict(row))

    # 请求了但未出现在 coverage 里的来源：按最弱状态补一行，不得让 coverage 缺来源。
    for name in wanted:
        if name not in coverage_by_source:
            coverage_by_source[name] = [_default_coverage_row(name, "unavailable")]

    merged_coverage: list[dict[str, Any]] = []
    order = list(wanted) + [name for name in coverage_by_source if name not in set(wanted)]
    for name in order:
        rows = coverage_by_source.get(name) or []
        if not rows:
            continue
        head = dict(rows[0])
        for extra in rows[1:]:
            _merge_coverage_row(head, extra)
        merged_coverage.append(head)

    merged_rows.sort(key=_row_sort_key)

    # 跨来源二次截断：排序稳定，截断只丢尾部；丢掉的行如实计入 dropped_results，
    # 并按来源重算 returned_count，避免 coverage 与 results 自相矛盾。
    limited = merged_rows
    dropped = 0
    if isinstance(limit, int) and not isinstance(limit, bool) and 0 < limit < len(limited):
        dropped = len(limited) - limit
        kept = limited[:limit]
        returned_by_source: dict[str, int] = {}
        for row in kept:
            name = _clean_source_id(row.get("source"))
            if name:
                returned_by_source[name] = returned_by_source.get(name, 0) + 1
        for row in merged_coverage:
            name = _clean_source_id(row.get("source"))
            if name:
                row["returned_count"] = returned_by_source.get(name, 0)
        limited = kept

    any_rejected = any(_truthy(payload, "rejected") for _, payload in dicts)
    any_scope_mismatch = any(
        _payload_reason(payload) == "scope_mismatch" or _payload_reason(payload).startswith("scope_mismatch")
        for _, payload in dicts
    )
    any_unsupported = any(
        _payload_reason(payload).startswith("source_unsupported")
        or _payload_reason(payload).startswith(RegistryCodes.SOURCE_UNSUPPORTED)
        for _, payload in dicts
    )
    any_failure = any(
        _payload_reason(payload).startswith("internal_failure")
        or _payload_reason(payload).startswith("read_budget_exhausted")
        or _payload_reason(payload).startswith("publication_failed")
        for _, payload in dicts
    )
    any_partial = any(_truthy(payload, "partial") for _, payload in dicts)
    any_truncated = any(_truthy(payload, "truncated") for _, payload in dicts) or bool(dropped)
    any_unrouted = bool(list(unbound_rows)) or any_unsupported or any_failure
    all_complete = (
        bool(dicts)
        and not any_rejected
        and not any_partial
        and not any_unrouted
        and all(_truthy(payload, "complete") for _, payload in dicts)
    )

    withheld = sum(_count(payload, "records_withheld") for _, payload in dicts)
    dropped += sum(_count(payload, "dropped_results") for _, payload in dicts)
    redaction_withheld = sum(_count(payload, "redaction_withheld") for _, payload in dicts)

    reason = ""
    failure_category: str | None = None
    stage: str | None = None
    if any_rejected:
        for _, payload in dicts:
            if _truthy(payload, "rejected"):
                reason = _payload_reason(payload) or RegistryCodes.INVALID_REQUEST
                failure_category = payload.get("failure_category") if isinstance(payload.get("failure_category"), str) else reason
                stage = payload.get("stage_reached") if isinstance(payload.get("stage_reached"), str) else "coordinator"
                break
    elif any_scope_mismatch:
        reason = "scope_mismatch"
        failure_category = "scope_mismatch"
        stage = "coordinator"
    elif any_unsupported:
        reason = RegistryCodes.SOURCE_UNSUPPORTED
        failure_category = RegistryCodes.SOURCE_UNSUPPORTED
    elif any_failure:
        reason = RegistryCodes.INTERNAL_FAILURE
        failure_category = RegistryCodes.INTERNAL_FAILURE

    scope_parts = sorted(
        {
            payload["coverage_scope"]
            for _, payload in dicts
            if isinstance(payload.get("coverage_scope"), str) and payload.get("coverage_scope") not in ("", "none")
        }
    )
    # 单族检索保留该族自己的有界集合名（bounded_pi_file_set / bounded_hermes_store_set）：
    # 只路由到一个服务时，合并结果的覆盖口径就是那一个集合，换成泛名会丢精度；
    # 多族合并才用无交叠语义的 bounded_service_sets。
    if len(scope_parts) == 1:
        coverage_scope = scope_parts[0]
    elif scope_parts:
        coverage_scope = "bounded_service_sets"
    else:
        coverage_scope = "none"

    result: dict[str, Any] = {
        "results": limited,
        "coverage": merged_coverage,
        "complete": all_complete,
        "partial": bool(any_partial or any_unrouted or dropped) and not all_complete,
        "truncated": any_truncated,
        "total_matched": sum(_count(payload, "total_matched") for _, payload in dicts),
        "total_scanned": sum(_count(payload, "total_scanned") for _, payload in dicts),
        "skipped_records": sum(_count(payload, "skipped_records") for _, payload in dicts),
        "records_withheld": withheld,
        "dropped_results": dropped,
        "redaction_withheld": redaction_withheld,
        "reason": reason,
        "stage_reached": stage,
        "failure_category": failure_category,
        "coverage_scope": coverage_scope,
        "source_scopes": scope_parts,
    }
    if any(isinstance(payload.get("files"), (list, tuple)) and payload.get("files") for _, payload in dicts):
        result["files"] = files
    # Hermes 聚合载荷自带 stores 行（逐库读取状态）；单族路由时透传，多族合并则取并集。
    raw_stores: list[dict[str, Any]] = []
    for _, payload in dicts:
        payload_stores = payload.get("stores")
        if isinstance(payload_stores, (list, tuple)):
            raw_stores.extend(dict(entry) for entry in payload_stores if isinstance(entry, Mapping))
    if raw_stores:
        result["stores"] = raw_stores
    return result
