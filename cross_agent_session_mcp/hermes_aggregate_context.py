"""Hermes 来源的 ctxref 上下文读取（宿主进程内）。

本模块只服务一个已绑定的 Hermes 库：客户端交回的是不透明 `ctxref` 令牌，模块按固定顺序核对
「令牌可解析且未过期 → 服务绑定与声明相符 → 同一授权链重读且版本逐项相等 → 锚点记录在已核对
记录集里仍可定位」，任何一步不合就交出零正文。与 `session_context` 的 pi 路径同一判据，差别只有
三处，且这三处都是 Hermes 形态带来的：

1. **版本证据不是行读取的副产物**。`safe_reader.authorize_read` 的形态门会拒绝 SQLite 头，因此
   Hermes 的版本来自 `authorize_content_digest`：一次读取做两趟同授权指纹（SQL 快照前与快照后），
   两趟与账本里的指纹必须四项（卷号、文件标识、体积、同趟摘要）逐项相等；任何一趟不完整或被替换，
   该库即视为版本不可确立，零正文。这是本增量的妥协：它证明的是「两次指纹之间未变」，不是一趟读取
   的副产物，写进 09 供后续改造。
2. **坐标是 `messages.id` 与固定 ordinal 0**，`stream_label` 是该库的标签：只进账本与当场比较，
   不进对外行。窗口按本次重读的已核对记录顺序取相邻条，不承诺 id 连续。
3. **归属重判定**。令牌里记的 `project` 是发放时授权后的项目名；本次重读必须再走一次策略层归属轴，
   且与账本里的项目名相等，不等即绑定不合（不做「声明与实读不同也发布」）。

与检索侧一样：整批拒绝、不发布前缀；窗口行发放的是**新令牌**；失败只写进行状态，不写成「没有」。
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .file_search import (
    _LAYERED_COUNTER_NOTE,
    _METADATA_WITHHELD_NOTE,
    _SNIPPET_TRUNCATION_NOTE,
    COVERAGE_SCOPE_FILE,
    COVERAGE_SCOPE_NONE,
    _public_key,
)
from .hermes_aggregate import (
    HermesStoreRef,
    _entry_matches_version,
    _hermes_binding_problems,
    _hermes_read_store,
    _hermes_service_key,
    _issue_hermes_references,
)
from .models import StandardRecord
from .policy import PolicyDenied, SessionPolicy
from .publication import PublicationRefusal, SnippetCollector
from .query import MAX_SESSION_ID_CHARS
from .references import (
    ReferenceLedger,
    default_ledger,
    lookup_reference,
    parse_reference_token,
)
from .safe_reader import FileVersion, SafeReadDenied
from .session_context import (
    MAX_CONTEXT_SNIPPETS,
    MAX_CONTEXT_TOTAL_CHARS,
    MAX_WINDOW_RECORDS,
    _anchor_form,
    _labels_agree,
    _row_for,
    _validated_sides,
    _window_quality_issues,
)
from .session_stage import _comparable_key
from .sources.hermes import SOURCE_HERMES

# ---- 口径 ----

#: 上下文读取的覆盖声明：只覆盖该库本次重读并核对通过的记录集。
COVERAGE_SCOPE_HERMES_STORE = "single_bound_hermes_store"

_STORE_SCOPE_NOTE = (
    "覆盖范围仅限本次核对通过的单个已绑定 Hermes 库，不声明整个 hermes 来源已扫完。"
)

_INTERNAL_NOTE = "上下文读取内部失败；本次未发布任何正文（零结果，不是前缀）。"

_SNIPPET_JOIN_NOTE = "遮蔽片段与记录接线数量不符，整批未发布（零结果，不是前缀）。"

_ATTRIBUTION_NOTE = (
    "窗口的归属在发布层未通过当场再判定，整批未发布（零结果，不是前缀）。"
)

_WINDOW_NOTE = "窗口无法在已核对记录集里唯一确定，本次未发布任何正文（零结果，不是前缀）。"


class HermesContextFailureCategory(StrEnum):
    """上下文读取的闭合失败类别（与 pi 路径同名同值，便于协议层一致解释）。"""

    INVALID_ARGUMENT = "invalid_argument"
    REF_EXPIRED = "ref_expired"
    BINDING_MISMATCH = "binding_mismatch"
    FILE_REPLACED = "file_replaced"
    NOT_FOUND = "not_found"
    INCOMPLETE = "incomplete"
    VERSION_UNSTABLE = "version_unstable"
    WINDOW_UNRESOLVED = "window_unresolved"
    PUBLICATION_FAILED = "publication_failed"
    REFERENCE_ISSUE_FAILED = "reference_issue_failed"
    SNIPPET_OUTPUT_TRUNCATED = "snippet_output_truncated"
    METADATA_WITHHELD = "metadata_withheld"
    RECORD_FIELD_OUT_OF_BOUNDS = "record_field_out_of_bounds"
    INTERNAL_FAILURE = "internal_failure"


class HermesContextStageReached(StrEnum):
    """读到哪一步：与检索侧同一「阶段 + 快照」两层口径。"""

    COORDINATOR = "coordinator"
    STORE_READ = "store_read"
    WINDOW = "window"
    PUBLICATION = "publication"
    PUBLISHED = "published"


_CATEGORY_REASONS: dict[str, str] = {
    HermesContextFailureCategory.INVALID_ARGUMENT.value: (
        "参数形态不合：引用不可解析或窗口侧计数越界，本次未打开任何文件。"
    ),
    HermesContextFailureCategory.REF_EXPIRED.value: (
        "引用不可用：令牌不存在、已过期或已被回收，本次未打开任何文件；请重新查询后使用新引用。"
    ),
    HermesContextFailureCategory.BINDING_MISMATCH.value: (
        "引用绑定与本次声明不符（服务、来源、会话或项目），本次未打开任何文件。"
    ),
    HermesContextFailureCategory.FILE_REPLACED.value: (
        "拒绝：本次同授权指纹与发放引用时的指纹不一致（目标已被替换或改写，含同大小改写），"
        "整批未发布（零结果，不是前缀）；请重新查询后使用新引用。"
    ),
    HermesContextFailureCategory.NOT_FOUND.value: (
        "已核对记录集中定位不到该引用所指的记录，本次未发布任何正文。"
    ),
    HermesContextFailureCategory.INCOMPLETE.value: (
        "该库本次重读未达成完整核对，覆盖不完整，本次未发布任何正文。"
    ),
    HermesContextFailureCategory.VERSION_UNSTABLE.value: (
        "拒绝：读取前后两趟同授权指纹不一致或不完整，版本不可确立，整批未发布（零结果，不是前缀）。"
    ),
    HermesContextFailureCategory.WINDOW_UNRESOLVED.value: (
        "窗口无法在已核对记录集里唯一确定（身份漂移、超上限或接线不符），本次未发布任何正文。"
    ),
    HermesContextFailureCategory.PUBLICATION_FAILED.value: (
        "遮蔽、接线或发放环节失败，整批未发布（零结果，不是前缀）。"
    ),
    HermesContextFailureCategory.REFERENCE_ISSUE_FAILED.value: (
        "引用发放失败：窗口行未能全部拿到新引用，整批未发布（零结果，不是前缀）。"
    ),
    HermesContextFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value: (
        "一个或多个遮蔽片段按输出上限截断。"
    ),
    HermesContextFailureCategory.METADATA_WITHHELD.value: (
        "存在形态不可外的短元数据（路径形态、含分隔符/空白或超长），已降为 null 并记为覆盖不完整。"
    ),
    HermesContextFailureCategory.RECORD_FIELD_OUT_OF_BOUNDS.value: (
        "记录字段超出协议上限，已降为 null 并记为覆盖不完整。"
    ),
    HermesContextFailureCategory.INTERNAL_FAILURE.value: _INTERNAL_NOTE,
}

_PUBLICATION_REASONS: dict[str, str] = {
    PublicationRefusal.REDACTION_REJECTED.value: "遮蔽判定认为该记录不可外发，整批未发布。",
    PublicationRefusal.SNIPPET_LIMIT_EXCEEDED.value: "片段数量超出窗口配额，整批未发布。",
    PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED.value: "片段总字数超出上限，整批未发布。",
    PublicationRefusal.RECORD_UNUSABLE.value: "记录形态不合发布层要求，整批未发布。",
    PublicationRefusal.INTERNAL_FAILURE.value: "片段收集器内部失败，整批未发布。",
    PublicationRefusal.NOT_CONFIRMED.value: "未经完整核对即要求释放，整批未发布。",
}


@dataclass(frozen=True)
class HermesContextOutcome:
    """上下文读取的对外结论：闭合类别 + 整数 + 已遮蔽行，零正文即 `results=()`。"""

    complete: bool
    partial: bool
    truncated: bool
    status: str
    reason: str | None
    failure_category: str | None
    stage_reached: str
    coverage_scope: str
    window_size: int
    records_withheld: int
    version_confirmed: bool
    filter_error_codes: tuple[str, ...] = ()
    quality_issues: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    results: tuple[dict[str, object], ...] = ()

    @property
    def returned_count(self) -> int:
        return len(self.results)

    def as_public_dict(self) -> dict[str, Any]:
        coverage: dict[str, Any] = {
            "source": SOURCE_HERMES,
            "coverage_scope": self.coverage_scope,
            "status": self.status,
            "matched_count": self.window_size,
            "returned_count": self.returned_count,
            "records_scanned": self.window_size,
            "skipped_count": self.records_withheld,
            "partial": self.partial,
            "filter_errors": list(self.filter_error_codes),
            "quality_issues": list(self.quality_issues),
            "reason": "".join(self.notes),
        }
        return {
            "complete": self.complete,
            "partial": self.partial,
            "truncated": self.truncated,
            "status": self.status,
            "coverage_scope": self.coverage_scope,
            "stage_reached": self.stage_reached,
            "reason": self.reason,
            "failure_category": self.failure_category,
            "window_size": self.window_size,
            "returned_count": self.returned_count,
            "records_withheld": self.records_withheld,
            "version_confirmed": self.version_confirmed,
            "filter_errors": list(self.filter_error_codes),
            "quality_issues": list(self.quality_issues),
            "results": [dict(row) for row in self.results],
            "coverage": [coverage],
        }


def _refused(
    category: HermesContextFailureCategory | str,
    *,
    reason_code: str | None = None,
    coverage_scope: str = COVERAGE_SCOPE_FILE,
    stage: str,
    note: str | None = None,
    window: int = 0,
    records_withheld: int = 0,
    version_confirmed: bool = False,
) -> HermesContextOutcome:
    """零正文的拒绝结论：固定文案 + 分层计数注记 + 本库覆盖声明。"""

    value = category.value if isinstance(category, StrEnum) else str(category)
    text = note if note is not None else _CATEGORY_REASONS.get(
        value, _CATEGORY_REASONS[HermesContextFailureCategory.INTERNAL_FAILURE.value]
    )
    codes = [value]
    if reason_code is not None and reason_code != value:
        codes.append(reason_code)
    return HermesContextOutcome(
        complete=False,
        partial=True,
        truncated=False,
        status="incomplete",
        reason=value,
        failure_category=value,
        stage_reached=stage,
        coverage_scope=coverage_scope,
        window_size=window,
        records_withheld=records_withheld,
        version_confirmed=version_confirmed,
        filter_error_codes=tuple(codes),
        notes=(text, _LAYERED_COUNTER_NOTE, _STORE_SCOPE_NOTE),
    )


def _context_reason_text(
    *, window_size: int, anchor_index: int, candidate_count: int
) -> str:
    """一句固定说明：只由整数与固定片段拼成，不含正文、路径、引用原值、会话标识。"""

    if window_size <= 1:
        return (
            "锚点记录已通过两轴授权、身份核对与遮蔽，但它在本次已核对记录集里两侧都没有可交的"
            "相邻记录，因此上下文只含锚点本身；窗口外没有已核对的记录，其余候选不属于该窗口。"
            + _STORE_SCOPE_NOTE
        )
    return (
        f"上下文窗口交出 {window_size} 条已核对记录（锚点位于其中第 {anchor_index + 1} 条），"
        f"其余 {max(candidate_count - window_size, 0)} 条已核对候选不属于该窗口。"
        + _STORE_SCOPE_NOTE
    )


def _store_reason(denial: PolicyDenied | SafeReadDenied) -> str:
    code = getattr(denial, "code", None)
    value = getattr(code, "value", None)
    return value if isinstance(value, str) else "refused"


def _read_store(
    policy: SessionPolicy,
    scope: str,
    ref: HermesStoreRef,
    project_filter: str | None,
    stage: str,
) -> tuple[list[StandardRecord], list[str], FileVersion | None, HermesContextOutcome | None]:
    """一次上下文重读：与检索侧共用同一套核对，失败即返回零正文结论。

    候选、归属名、版本证据与失败结论都来自 `hermes_aggregate._hermes_read_store`：两条路径对
    「已核对」的定义必须同一定义，否则同一库在检索里可读、在上下文里被判不完整（或反之）。
    失败标签是来源侧的闭合值（适配器 gate、指纹类别、拒绝码），直接作为 `reason_code` 外显。
    """

    records, projects, version, reason = _hermes_read_store(
        policy, scope, ref, project_filter
    )
    if reason is not None:
        category: HermesContextFailureCategory | str
        if reason == HermesContextFailureCategory.VERSION_UNSTABLE.value:
            category = HermesContextFailureCategory.VERSION_UNSTABLE
        else:
            category = HermesContextFailureCategory.INCOMPLETE
        return [], [], None, _refused(
            category,
            reason_code=reason,
            stage=stage,
            records_withheld=len(records),
        )
    return records, projects, version, None


def read_hermes_store_context(
    policy: SessionPolicy,
    scope: str,
    ref: HermesStoreRef,
    *,
    location: str,
    project_filter: str | None = None,
    before: object = 2,
    after: object = 2,
    ledger: ReferenceLedger | None = None,
) -> HermesContextOutcome:
    """按 ctxref 读取单库上下文：核对顺序与 pi 路径一致，失败一律零正文。"""

    token = parse_reference_token(location)
    if token is None:
        return _refused(
            HermesContextFailureCategory.INVALID_ARGUMENT,
            coverage_scope=COVERAGE_SCOPE_NONE,
            stage=HermesContextStageReached.COORDINATOR.value,
        )
    sides = _validated_sides(before, after)
    if sides is None:
        return _refused(
            HermesContextFailureCategory.INVALID_ARGUMENT,
            coverage_scope=COVERAGE_SCOPE_NONE,
            stage=HermesContextStageReached.COORDINATOR.value,
        )
    before_size, after_size = sides

    ref_ledger = ledger if ledger is not None else default_ledger()
    entry = lookup_reference(token, ledger=ref_ledger)
    if entry is None:
        return _refused(
            HermesContextFailureCategory.REF_EXPIRED,
            coverage_scope=COVERAGE_SCOPE_NONE,
            stage=HermesContextStageReached.COORDINATOR.value,
        )

    service_key = _hermes_service_key(scope=scope, ref=ref)
    problem = _hermes_binding_problems(
        entry,
        service_key=service_key,
        session_id=ref.session_id,
        project_filter=project_filter,
    )
    if problem is not None:
        return _refused(
            HermesContextFailureCategory.BINDING_MISMATCH,
            reason_code=problem,
            coverage_scope=COVERAGE_SCOPE_NONE,
            stage=HermesContextStageReached.COORDINATOR.value,
        )

    records, projects, version, failure = _read_store(
        policy,
        scope,
        ref,
        project_filter,
        HermesContextStageReached.STORE_READ.value,
    )
    if failure is not None:
        return failure
    if version is None or not version.complete:
        return _refused(
            HermesContextFailureCategory.INCOMPLETE,
            reason_code="version_unavailable",
            stage=HermesContextStageReached.STORE_READ.value,
            records_withheld=len(records),
        )
    if not _entry_matches_version(entry, version):
        return _refused(
            HermesContextFailureCategory.FILE_REPLACED,
            stage=HermesContextStageReached.STORE_READ.value,
            records_withheld=len(records),
            version_confirmed=False,
        )

    stage = HermesContextStageReached.WINDOW.value
    for record in records:
        if _anchor_form(record) is None:
            return _refused(
                HermesContextFailureCategory.WINDOW_UNRESOLVED,
                reason_code="anchor_form_unusable",
                stage=stage,
                records_withheld=len(records),
                version_confirmed=True,
            )

    asserted = _comparable_key(ref.session_id)
    if asserted is None:
        return _refused(
            HermesContextFailureCategory.NOT_FOUND,
            stage=stage,
            records_withheld=len(records),
            version_confirmed=True,
        )

    anchor_index = -1
    for index, record in enumerate(records):
        form = _anchor_form(record)
        if form is None:
            continue
        if form[0] != entry.line_no or form[1] != entry.ordinal:
            continue
        if not _labels_agree(entry.stream_label, form[2]):
            continue
        if _comparable_key(record.session_id) != asserted:
            continue
        anchor_index = index
        break
    if anchor_index < 0:
        return _refused(
            HermesContextFailureCategory.REF_EXPIRED,
            reason_code="anchor_not_locatable",
            stage=stage,
            records_withheld=len(records),
            version_confirmed=True,
        )

    lower = max(0, anchor_index - before_size)
    upper = min(len(records), anchor_index + after_size + 1)
    selected = list(range(lower, upper))
    for index in selected:
        if _comparable_key(records[index].session_id) != asserted:
            return _refused(
                HermesContextFailureCategory.WINDOW_UNRESOLVED,
                reason_code="window_identity_conflict",
                stage=stage,
                records_withheld=len(records),
                version_confirmed=True,
            )
    if len(selected) > MAX_WINDOW_RECORDS:
        return _refused(
            HermesContextFailureCategory.WINDOW_UNRESOLVED,
            reason_code="window_limit_exceeded",
            stage=stage,
            records_withheld=len(records),
            version_confirmed=True,
        )

    window_records = [records[index] for index in selected]
    window_projects = [projects[index] for index in selected]
    for name in window_projects:
        usable, _held = _public_key(name, MAX_SESSION_ID_CHARS)
        if usable is None:
            return _refused(
                HermesContextFailureCategory.WINDOW_UNRESOLVED,
                reason_code="attribution_incomplete",
                stage=stage,
                records_withheld=len(window_records),
                version_confirmed=True,
            )
    # 令牌里记的项目必须与本次归属轴再判定的结果相等：不等即引用与当前归属不符。
    for name in window_projects:
        if name != entry.project:
            return _refused(
                HermesContextFailureCategory.BINDING_MISMATCH,
                reason_code="project_drift",
                stage=stage,
                records_withheld=len(window_records),
                version_confirmed=True,
            )

    stage = HermesContextStageReached.PUBLICATION.value
    effective_snippets = min(len(window_records), MAX_CONTEXT_SNIPPETS)
    collector = SnippetCollector(
        source=SOURCE_HERMES,
        max_snippets=effective_snippets,
        max_total_chars=MAX_CONTEXT_TOTAL_CHARS,
    )
    for record in window_records:
        refusal = collector.collect(record)
        if refusal is not None:
            collector.release(confirmed=False)
            return _refused(
                HermesContextFailureCategory.PUBLICATION_FAILED,
                reason_code=refusal.value,
                note=_PUBLICATION_REASONS.get(
                    refusal.value,
                    _PUBLICATION_REASONS[PublicationRefusal.NOT_CONFIRMED.value],
                ),
                stage=stage,
                window=len(window_records),
                records_withheld=len(window_records),
                version_confirmed=True,
            )
    snippets = collector.release(confirmed=True)
    if len(snippets) != len(window_records):
        return _refused(
            HermesContextFailureCategory.WINDOW_UNRESOLVED,
            reason_code="snippet_join_failed",
            note=_SNIPPET_JOIN_NOTE,
            stage=stage,
            window=len(window_records),
            records_withheld=len(window_records),
            version_confirmed=True,
        )

    try:
        issued = _issue_hermes_references(
            window_records,
            window_projects,
            version=version,
            service_key=service_key,
            scope=scope,
            path=ref.store_path,
            session_id=ref.session_id,
            ledger=ref_ledger,
        )
    except ValueError:
        return _refused(
            HermesContextFailureCategory.REFERENCE_ISSUE_FAILED,
            stage=stage,
            window=len(window_records),
            records_withheld=len(window_records),
            version_confirmed=True,
        )

    try:
        rows: list[dict[str, object]] = []
        metadata_withheld = False
        for record, project, reference, snippet in zip(
            window_records, window_projects, issued, snippets, strict=True
        ):
            row, withheld = _row_for(
                record,
                project,
                SOURCE_HERMES,
                reference,
                snippet.snippet,
                snippet.redacted_count,
                snippet.truncated,
            )
            metadata_withheld = metadata_withheld or withheld
            rows.append(row)
    except BaseException:
        ref_ledger.release(issued)
        raise

    quality_issues = _window_quality_issues(window_records)
    codes: list[str] = []
    notes = [
        _context_reason_text(
            window_size=len(window_records),
            anchor_index=anchor_index - lower,
            candidate_count=len(records),
        )
    ]
    truncated_output = any(snippet.truncated for snippet in snippets)
    if truncated_output:
        codes.append(HermesContextFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value)
        notes.append(_SNIPPET_TRUNCATION_NOTE)
    if metadata_withheld:
        codes.append(HermesContextFailureCategory.METADATA_WITHHELD.value)
        notes.append(_METADATA_WITHHELD_NOTE)
    if quality_issues:
        codes.append(HermesContextFailureCategory.RECORD_FIELD_OUT_OF_BOUNDS.value)

    partial = bool(metadata_withheld or truncated_output or quality_issues)
    published_stage = HermesContextStageReached.PUBLISHED.value
    outcome = HermesContextOutcome(
        complete=not partial,
        partial=partial,
        truncated=truncated_output,
        status="searched" if rows else "no_match",
        reason=None,
        failure_category=None,
        stage_reached=published_stage,
        coverage_scope=COVERAGE_SCOPE_HERMES_STORE,
        window_size=len(window_records),
        records_withheld=max(len(records) - len(window_records), 0),
        version_confirmed=True,
        filter_error_codes=tuple(codes),
        quality_issues=quality_issues,
        notes=tuple(notes),
        results=tuple(rows),
    )
    # 已发布行持有的令牌就是 outcome 里的 location，不回收（回收会让已外递的
    # ctxref 失效）；此处无局部引用需要清理。
    return outcome


class HermesAggregateContextService:
    """宿主进程内绑定的 Hermes 上下文服务：与检索服务共享同一引用账本与同一绑定集合。

    客户端只能交回令牌与声明（来源/会话/项目/窗口侧计数），传不进路径；路由靠账本里的服务绑定键
    在绑定集合内定位到具体库，定位不到即绑定不合，零正文。
    """

    def __init__(
        self,
        *,
        policy: SessionPolicy,
        scope: str,
        stores: Sequence[HermesStoreRef],
        ledger: ReferenceLedger | None = None,
        binding_key: Callable[[int], str] | None = None,
    ) -> None:
        from .hermes_aggregate import _validate_bound_stores

        _validate_bound_stores(
            label="HermesAggregateContextService",
            policy=policy,
            scope=scope,
            stores=stores,
            ledger=ledger,
        )
        if binding_key is not None and not callable(binding_key):
            raise TypeError("binding_key must be callable or None")
        self.policy = policy
        self.scope = scope
        self.stores: tuple[HermesStoreRef, ...] = tuple(stores)
        self.ledger = ledger
        # 绑定了发放方就只认它的键（单一事实源）；没绑定时自己按同一入构重建，
        # 供单库戒不依赖发放方的测试与宿主使用。
        self._binding_key: Callable[[int], str] | None = binding_key

    def _route_ref(self, service_key: str) -> HermesStoreRef | None:
        for index, ref in enumerate(self.stores):
            if self._service_key(index, ref) == service_key:
                return ref
        return None

    def _service_key(self, index: int, ref: HermesStoreRef) -> str:
        """该库的引用绑定键：优先用发放方提供的算法，否则按同一四元组现构。"""

        if self._binding_key is None:
            return _hermes_service_key(scope=self.scope, ref=ref)
        return self._binding_key(index)

    def read(
        self,
        *,
        scope: object = None,
        source: object = None,
        session_id: object = None,
        location: object = None,
        project: object = None,
        before: object = 2,
        after: object = 2,
    ) -> HermesContextOutcome:
        """上下文读取入口：核对顺序固定，任何一步不合都零正文。"""

        if scope is not None and scope != self.scope:
            return _refused(
                HermesContextFailureCategory.BINDING_MISMATCH,
                reason_code="scope_mismatch",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )
        if source is not None and source != SOURCE_HERMES:
            return _refused(
                HermesContextFailureCategory.BINDING_MISMATCH,
                reason_code="source_mismatch",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )
        if not isinstance(location, str):
            return _refused(
                HermesContextFailureCategory.INVALID_ARGUMENT,
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )
        token = parse_reference_token(location)
        if token is None:
            return _refused(
                HermesContextFailureCategory.INVALID_ARGUMENT,
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )

        from .references import default_ledger

        ref_ledger = self.ledger if self.ledger is not None else default_ledger()
        entry = lookup_reference(token, ledger=ref_ledger)
        if entry is None:
            return _refused(
                HermesContextFailureCategory.REF_EXPIRED,
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )
        ref = self._route_ref(entry.service_key)
        if ref is None:
            return _refused(
                HermesContextFailureCategory.BINDING_MISMATCH,
                reason_code="service_binding",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )
        declared_project = project if isinstance(project, str) else None
        # 「省略声明」与「非法声明」必须分开（09 裁决 P3-5.2）：
        # - 省略（None）：进程内服务的默认形状，保留回退成绑定值，语义与本裁决前一致；
        #   协议层 `server.read_session_context` 的 `session_id: str` 是必填且已过
        #   `_check_text(session_id, _ERR_REF)`，真实请求永远带显式声明，改必填只会把
        #   既有的「合法请求」用例一并打掉，属越出裁决范围。
        # - 非法声明（非字符串、空串、超长 —— `_comparable_key` 判不可用）：不得静默回退
        #   成绑定值。旧写法把非法声明换成 `ref.session_id` 后「声明与绑定不合」恒不成立，
        #   客户端递不进的会话 id 反而变成合法请求。
        # 严格拒的对外契约零变化：仍落 `binding_mismatch` + `reason_code="session_binding"`，
        # 只是覆盖面变宽，不新增拒绝码（`HermesContextFailureCategory` 是闭合类别集合）。
        if session_id is not None and (
            not isinstance(session_id, str) or _comparable_key(session_id) is None
        ):
            return _refused(
                HermesContextFailureCategory.BINDING_MISMATCH,
                reason_code="session_binding",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )
        declared_session = (
            session_id if isinstance(session_id, str) else ref.session_id
        )
        # 两侧统一走 `_comparable_key`：与 `hermes_aggregate._hermes_binding_problems` 同一口径
        # （它也用 `_comparable_key` 比对 `entry.session_id`），避开旧写法「合法性用键判、
        # 比较用原值直等」的两套口径（含首尾空格差异时旧法会多拒/漏拒）。
        if _comparable_key(declared_session) != _comparable_key(ref.session_id):
            return _refused(
                HermesContextFailureCategory.BINDING_MISMATCH,
                reason_code="session_binding",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=HermesContextStageReached.COORDINATOR.value,
            )
        return read_hermes_store_context(
            self.policy,
            self.scope,
            ref,
            location=location,
            project_filter=declared_project,
            before=before,
            after=after,
            ledger=ref_ledger,
        )


__all__ = [
    "COVERAGE_SCOPE_HERMES_STORE",
    "HermesAggregateContextService",
    "HermesContextFailureCategory",
    "HermesContextOutcome",
    "HermesContextStageReached",
    "read_hermes_store_context",
]
