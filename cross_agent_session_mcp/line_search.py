"""通用行式来源的聚合服务层（codex / claude / cursor 共用一套管线）。

对应实施计划 §2 D-2：pi/cursor/claude/codex 四个行式 JSONL 来源共用同一条「授权 →
有界候选 → 过滤 → 两段式发布 → ctxref」流程，只有 `source` 与解析器工厂不同；本模块把
`session_discovery._search_pi_files` 的聚合口径参数化，pi 与 hermes 的既有实现保持原样
不动（§7.5：不改 `session_discovery`/`session_pipeline` 对外行为，只复用其内核）。

口径要点（与 pi 多文件服务逐字同构，只换来源维度）：
- 服务只消费宿主注入的**有界文件集合**：不发现、不读配置、不接受客户端自由路径；
- 绑定即授权：构造期逐文件 `authorize_store`，运行期只跑 `authorize_query` 与逐记录
  `authorize_attribution`；
- scope 不符在协调器层短路：零文件打开、零候选、零发布；
- 归属证据只采解析器判定的 `TRUSTED_HEADER_CWD` 记录（D-6），逐条映射过策略层；不完整
  文件的候选绝不进发布批，其归属映射一并作废；
- 任一 partial / 预算触顶 ⇒ 集合自称不完整（禁「完整无匹配」口径）；
- 遮蔽或接线失败 ⇒ 整批零结果 + 回滚已签发令牌，绝不部分外发；
- 结果文本与定位符只来自遮蔽层/账本，本层不重建路径、不持有原文。

`coverage_scope` 取 `bounded_line_file_set:<source>`：它声明的是**绑定集合内**的完整性，
绝不表示整个来源已被扫完（同 pi 层的 `bounded_pi_file_set` 取向）。

与 pi 层的唯一实质差异是 ctxref 的签发：`file_search._issue_references` 把 `source` 钉死
为 `pi`（那是单文件层的私有口径），本层因此自带签发循环（`_issue_line_references`），逐字
沿用它的形态门与整批回滚，只把来源维度参数化。
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .file_search import (
    MAX_SNIPPET_TOTAL_CHARS,
    _join_result,
)
from .models import ProjectQuality, StandardRecord
from .policy import PolicyDenied, SessionPolicy
from .publication import (
    MAX_SNIPPETS_PER_FILE,
    PublicationRefusal,
    SnippetCollector,
)
from .multi_source import MAX_REQUESTED_SOURCES
from .query import (
    DEFAULT_LIMIT,
    FilterErrorCode,
    QueryRejectionReason,
    ScanFilterOutcome,
    SourceCoverage,
    scan_filter,
)
from .references import (
    MAX_ISSUE_PER_CALL,
    ReferenceLedger,
    default_ledger,
    lookup_reference,
    parse_reference_token,
    service_binding_key,
)
from .safe_reader import (
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_LINES,
    DEFAULT_MAX_TOTAL_BYTES,
    FileVersion,
    SafeReadDenied,
)
from .session_context import (
    MAX_CONTEXT_CANDIDATES,
    MAX_CONTEXT_SNIPPETS,
    MAX_CONTEXT_STAGE_BYTES,
    MAX_CONTEXT_TOTAL_CHARS,
    ContextFailureCategory,
    ContextOutcome,
    ContextStageReached,
    _anchor_form,
    _comparable_key,
    _row_for,
    _validated_sides,
    _window_quality_issues,
)
from .session_discovery import (
    AggregateFailureCategory,
    AggregateStageReached,
    COVERAGE_SCOPE_FILE,
    COVERAGE_SCOPE_MULTI,
    COVERAGE_SCOPE_NONE,
    MAX_AGGREGATE_SNIPPETS,
    MAX_AGGREGATE_TOTAL_READ_BYTES,
    MAX_AGGREGATE_TOTAL_SCAN_CHARS,
    MAX_FILES_PER_QUERY,
    MAX_PROTOCOL_LIMIT,
    PiFileFailureCategory,
    SessionFileRef,
    _FileRowStatus,
    FilterErrorTag,
    _LAYERED_COUNTER_NOTE,
    _MULTI_SCOPE_NOTE,
)
from .session_pipeline import (
    MAX_CANDIDATES_PER_SESSION,
    MAX_STAGE_BYTES_PER_SESSION,
    PiFileOutcome,
    run_line_source_file,
)
from .sources.claude import SOURCE_CLAUDE, ClaudeLineParser
from .sources.codex import SOURCE_CODEX, CodexRolloutLineParser
from .sources.cursor import SOURCE_CURSOR, CursorAgentTranscriptLineParser
from .sources.dsh import (
    DSH_COVERAGE_SCOPE,
    MAX_DSH_LINE_BYTES,
    MAX_LINES_PER_STREAM as MAX_DSH_LINES_PER_STREAM,
    SOURCE_DSH,
    DshLineParser,
    run_dsh_frame_file,
)
from .sources.pi import SOURCE_PI, PiLineParser

logger = logging.getLogger(__name__)

__all__ = [
    "CLAUDE_SPEC",
    "CODEX_SPEC",
    "CURSOR_SPEC",
    "DEFAULT_AGGREGATE_READ_BUDGET_BYTES",
    "LineAggregateContextService",
    "LineAggregateSearchService",
    "LineFileBindingError",
    "LineSourceSpec",
    "line_coverage_scope",
    "register_spec",
    "spec_for_source",
]

#: 单查询的读预算（字节）：与 pi 多文件服务同值，触顶即停止打开后续文件并自称不完整。
DEFAULT_AGGREGATE_READ_BUDGET_BYTES = MAX_AGGREGATE_TOTAL_READ_BYTES
#: 剩余预算低于此值就视为触顶：不足一次最小有界读取时再打开文件没有意义。
_MIN_READ_BUDGET = 16
#: 行式集合的片段总字符预算：与单文件遮蔽层同值（聚合层不放宽硬顶）。
_AGGREGATE_SNIPPET_TOTAL_CHARS = MAX_SNIPPET_TOTAL_CHARS
_FILES_UNUSABLE_NOTE = "绑定的文件集合中没有一份通过完整核对。"
_LINE_MULTI_SCOPE_NOTE = _MULTI_SCOPE_NOTE
#: 上下文窗口的记录硬上限：与单文件层同值（`MAX_WINDOW_RECORDS` 的聚合别名）。
MAX_CONTEXT_WINDOW_RECORDS = 21


def _join_reason(*parts: str | None) -> str:
    """把固定注记串成一句原因：空段丢弃，重复段只留一次。"""
    joined: list[str] = []
    for part in parts:
        if isinstance(part, str) and part and part not in joined:
            joined.append(part)
    return "；".join(joined)


def line_coverage_scope(source: str) -> str:
    """行式来源的覆盖声明：明确「绑定集合内完整」，不冒充全存储扫描。"""
    return f"bounded_line_file_set:{source}"


#: 打开前拒绝的异常族：策略层与读取层的固定码拒绝折成 `refused` 行，不升级为整批失败。
_REFUSAL_EXCEPTIONS: tuple[type[BaseException], ...] = (PolicyDenied, SafeReadDenied)

#: 结果配额裁剪的固定注记（覆盖行 reason 后缀；与 pi 聚合层同口径）。
_QUOTA_NOTE = "绑定集合内的匹配数超过本次配额，按文件段裁剪后返回。"


# ---------------------------------------------------------------------------
# 来源规格
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LineSourceSpec:
    """一个行式来源的服务侧规格：来源 ID、解析器工厂与可选默认限额。

    `default_limits` 只放 `session_pipeline` 内核已认识的键（`max_line_bytes`/
    `max_total_bytes`/`max_lines`），来源侧的块/字符上限留在解析器内部自管；本层不拿
    配置去覆盖任何硬顶。

    `file_runner` 为字节通道不同的来源留出注入口（计划 §2 D-3：DSH 的多帧 zstd 压缩文件
    无法走 `authorize_read` 的行通道，必须先按整文件字节授权再本地解压）。缺省 `None` 即
    用 `run_line_source_file`；注入的工厂必须产出同样带 `complete/reason/read/pipeline/
    version` 与 `as_public_dict()` 的文件终态，且**不得**引入计划外的新终止类别——读取被
    政策/安全层当场拒绝时把拒绝码记在 `read_refusal` 字段上并返回不完整终态，本层据此落
    `refused` 行。`coverage_scope` 同理：只允许改「集合形状」的标签，不允许放宽任何上限。
    """

    source_id: str
    parser_factory: Callable[..., Any]
    default_limits: dict[str, int] | None = None
    file_runner: Callable[..., Any] | None = None
    coverage_scope: str | None = None

    def limits(self) -> dict[str, int]:
        return dict(self.default_limits or {})

    def runner(self) -> Callable[..., Any]:
        return self.file_runner if self.file_runner is not None else run_line_source_file

    def scope_label(self) -> str:
        return (
            self.coverage_scope
            if self.coverage_scope is not None
            else line_coverage_scope(self.source_id)
        )


class LineFileBindingError(ValueError):
    """绑定参数形态不合（编程侧缺陷）：消息不含任何路径原值。"""


_SPECS: dict[str, LineSourceSpec] = {}


def register_spec(spec: LineSourceSpec) -> LineSourceSpec:
    """登记一个行式来源规格；同来源重复登记即失败（规格必须逐字一致才可共享）。"""
    existing = _SPECS.get(spec.source_id)
    if existing is not None and existing is not spec:
        raise LineFileBindingError(f"spec already registered for {spec.source_id}")
    _SPECS[spec.source_id] = spec
    return spec


def spec_for_source(source: object) -> LineSourceSpec | None:
    """按来源 ID 取规格；未登记返回 `None`（调用方按未绑定处理）。"""
    if not isinstance(source, str):
        return None
    return _SPECS.get(source)


# ---------------------------------------------------------------------------
# 绑定校验（与 `session_discovery._validate_bound_files` 同一组判据）
# ---------------------------------------------------------------------------


def _validate_bound_files(
    label: str,
    policy: object,
    scope: object,
    files: object,
    ledger: object,
) -> tuple[SessionFileRef, ...]:
    if not isinstance(policy, SessionPolicy):
        raise TypeError(f"{label} requires a SessionPolicy")
    if type(scope) is not str or not scope:
        raise ValueError(f"{label}.scope must be a non-empty string")
    if isinstance(files, (str, bytes)) or not isinstance(files, Sequence):
        raise TypeError(f"{label}.files must be a sequence of SessionFileRef")
    materialized = tuple(files)
    if not materialized:
        raise ValueError(f"{label} requires at least one bound file")
    if len(materialized) > MAX_FILES_PER_QUERY:
        raise ValueError(f"{label} exceeds MAX_FILES_PER_QUERY")
    if any(not isinstance(ref, SessionFileRef) for ref in materialized):
        raise TypeError("every bound entry must be a SessionFileRef")
    if ledger is not None and not isinstance(ledger, ReferenceLedger):
        raise TypeError(f"{label} accepts a ReferenceLedger only")
    return materialized


def _validate_bound_file(
    label: str, policy: object, scope: object, path: object, session_id: object
) -> None:
    """单文件绑定的判形：路径/会话标识必须是非空定长字面串。"""
    if not isinstance(policy, SessionPolicy):
        raise TypeError(f"{label} requires a SessionPolicy")
    if type(scope) is not str or not scope:
        raise ValueError(f"{label}.scope must be a non-empty string")
    if type(path) is not str or not path:
        raise ValueError(f"{label}.path must be a non-empty string")
    if type(session_id) is not str or not session_id:
        raise ValueError(f"{label}.session_id must be a non-empty string")


# ---------------------------------------------------------------------------
# 固定结论载荷（形态与 pi 聚合层的 `as_public_dict()` 一致：行是 dict，不是枚举对象）
# ---------------------------------------------------------------------------


def _coverage_row(
    source: str,
    coverage_scope: str,
    *,
    status: str,
    reason: str | None = None,
    filter_errors: Sequence[str] = (),
    quality_issues: Sequence[str] = (),
    partial: bool = True,
    matched: int = 0,
    returned: int = 0,
    scanned: int = 0,
    skipped: int = 0,
    scan_chars: int = 0,
) -> dict[str, Any]:
    """聚合层的覆盖行：固定键 + 整数/布尔 + 闭合枚举字符串，绝不含路径或原值。"""
    return {
        "source": source,
        "coverage_scope": coverage_scope,
        "status": status,
        "matched_count": matched,
        "returned_count": returned,
        "records_scanned": scanned,
        "skipped_count": skipped,
        "scan_chars": scan_chars,
        "partial": partial,
        "filter_errors": list(dict.fromkeys(filter_errors)),
        "quality_issues": list(dict.fromkeys(quality_issues)),
        "reason": reason or "",
    }


def _unsupported_row(source: str) -> dict[str, Any]:
    return _coverage_row(
        source,
        COVERAGE_SCOPE_NONE,
        status="unsupported",
        filter_errors=(AggregateFailureCategory.SOURCE_UNSUPPORTED.value,),
        reason=(
            f"聚合服务只查询本服务绑定的来源；点名它不等于批准它。{_LINE_MULTI_SCOPE_NOTE}"
        ),
    )


def _empty_payload(
    source: str,
    *,
    reason: str,
    stage: AggregateStageReached,
    category: AggregateFailureCategory | None,
    rejected: bool,
    coverage_scope: str | None = None,
    files: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """零结果载荷：只含闭合码与计数，`records_withheld` 由调用方按已捕获数如实填。"""
    scope = coverage_scope if coverage_scope is not None else line_coverage_scope(source)
    return {
        "results": [],
        "coverage": [
            _coverage_row(
                source,
                scope,
                status="incomplete",
                reason=reason,
                filter_errors=(reason,),
            )
        ],
        "complete": False,
        "partial": True,
        "truncated": False,
        "total_matched": 0,
        "total_scanned": 0,
        "skipped_records": 0,
        "records_withheld": 0,
        "rejected": rejected,
        "reason": reason,
        "stage_reached": stage.value,
        "failure_category": category.value if category is not None else reason,
        "coverage_scope": scope,
        "files": list(files),
    }


def _scope_rejection_payload(source: str) -> dict[str, Any]:
    """scope 不符：协调器层短路，零打开、零候选、零发布。"""
    return {
        "results": [],
        "coverage": [],
        "complete": False,
        "partial": False,
        "truncated": False,
        "total_matched": 0,
        "total_scanned": 0,
        "skipped_records": 0,
        "records_withheld": 0,
        "rejected": True,
        "reason": AggregateFailureCategory.SCOPE_MISMATCH.value,
        "stage_reached": AggregateStageReached.COORDINATOR.value,
        "failure_category": AggregateFailureCategory.SCOPE_MISMATCH.value,
        "coverage_scope": COVERAGE_SCOPE_NONE,
        "files": [],
    }


def _aggregate_row(scanned: ScanFilterOutcome | None, source: str, scope: str) -> dict[str, Any]:
    """从过滤层结论折算聚合层行（层级换成有界文件集合，计数器口径逐字沿用 pi 层）。"""
    row: SourceCoverage | None = None
    if scanned is not None:
        for candidate in scanned.coverage:
            if candidate.source == source:
                row = candidate
                break
    if row is None:
        return {
            "source": source,
            "coverage_scope": scope,
            "status": "incomplete",
            "matched_count": 0 if scanned is None else scanned.total_matched,
            "returned_count": 0,
            "records_scanned": 0 if scanned is None else scanned.total_scanned,
            "skipped_count": 0 if scanned is None else scanned.skipped_records,
            "scan_chars": 0 if scanned is None else scanned.scan_chars,
            "partial": True,
            "filter_errors": [FilterErrorTag.SOURCE_NOT_SCANNED.value],
            "quality_issues": [],
            "reason": (
                f"本次聚合没有可解释的过滤层逐来源行；{_LAYERED_COUNTER_NOTE}"
                f"{_LINE_MULTI_SCOPE_NOTE}"
            ),
        }
    public = row.as_public_dict()
    public["coverage_scope"] = scope
    public["reason"] = f"{public['reason']}{_LINE_MULTI_SCOPE_NOTE}"
    return public


# ---------------------------------------------------------------------------
# 文件循环：内核调用 + 归属映射
# ---------------------------------------------------------------------------


@dataclass
class _CaptureSink:
    """逐文件候选捕获器：返回值即遮蔽层的拒绝码，绝不吞记录。"""

    records: list[StandardRecord] = field(default_factory=list)
    failed: bool = False

    def __call__(self, record: StandardRecord) -> PublicationRefusal | None:
        self.records.append(record)
        return None


@dataclass
class _FileSegment:
    """一个已通过完整核对的文件段：记录 + 归属映射 + 版本快照。"""

    index: int
    ref: SessionFileRef
    outcome: PiFileOutcome
    records: list[StandardRecord]
    grants: dict[int, str]
    version: FileVersion | None
    positions: list[int] = field(default_factory=list)
    snippets: tuple[Any, ...] = ()
    tokens: list[str] = field(default_factory=list)
    consumed_bytes: int = 0


def _incomplete_reason(outcome: PiFileOutcome, sink: _CaptureSink) -> str:
    """不完整文件行的固定原因：捕获失败优先，其次管线原因码，最后兜底码。"""
    if sink.failed:
        return PiFileFailureCategory.CANDIDATE_CAPTURE_FAILED.value
    if outcome.reason is not None:
        return outcome.reason.value
    if outcome.attribution_refusal is not None:
        return outcome.attribution_refusal.value
    return PiFileFailureCategory.FILE_INCOMPLETE.value


def _collect_segments(
    policy: SessionPolicy,
    scope: str,
    spec: LineSourceSpec,
    files: Sequence[SessionFileRef],
    project: str | None,
) -> tuple[list[_FileSegment], list[dict[str, Any]], dict[int, str], bool, bool, int]:
    """授权循环：逐文件跑行式内核，产出可发布段 + 诊断行 + 归属映射。

    返回 `(segments, file_rows, mappings, any_incomplete, budget_hit, bytes_read)`。
    打开前的策略/读取拒绝折成 `refused` 行（不升级为整批失败）；未通过完整核对的文件其
    候选绝不进发布批，已建立的部分映射一并作废。
    """
    limits = spec.limits()
    runner = spec.runner()
    segments: list[_FileSegment] = []
    file_rows: list[dict[str, Any]] = []
    mappings: dict[int, str] = {}
    any_incomplete = False
    budget_hit = False
    bytes_read_total = 0
    budget_left = DEFAULT_AGGREGATE_READ_BUDGET_BYTES

    def _refused_row(index: int, reason: str) -> dict[str, Any]:
        return {
            "index": index,
            "status": _FileRowStatus.REFUSED.value,
            "coverage_scope": COVERAGE_SCOPE_FILE,
            "records_captured": 0,
            "reason": reason,
            "file": None,
        }

    for index, ref in enumerate(files):
        if budget_left < _MIN_READ_BUDGET:
            # 预算触顶：这份文件根本不打开，其候选绝不进发布批（先判后开，不做无用功）。
            budget_hit = True
            any_incomplete = True
            mappings = mappings  # 已建立的映射保持不动：本份文件从未被读过。
            file_rows.append(
                {
                    "index": index,
                    "status": _FileRowStatus.SKIPPED_BUDGET.value,
                    "coverage_scope": COVERAGE_SCOPE_FILE,
                    "records_captured": 0,
                    "reason": AggregateFailureCategory.READ_BUDGET_EXHAUSTED.value,
                    "file": None,
                }
            )
            continue
        sink = _CaptureSink()
        grants: dict[int, str] = {}
        try:
            outcome = runner(
                policy,
                scope,
                ref.path,
                ref.session_id,
                source=spec.source_id,
                parser_factory=spec.parser_factory,
                max_line_bytes=limits.get("max_line_bytes", DEFAULT_MAX_LINE_BYTES),
                max_total_bytes=min(
                    DEFAULT_MAX_TOTAL_BYTES,
                    limits.get("max_total_bytes", DEFAULT_MAX_TOTAL_BYTES),
                    max(budget_left, _MIN_READ_BUDGET),
                ),
                max_lines=limits.get("max_lines", DEFAULT_MAX_LINES),
                max_candidates=MAX_CANDIDATES_PER_SESSION,
                max_bytes=MAX_STAGE_BYTES_PER_SESSION,
                project_filter=project,
                _candidate_capture=sink,
                _project_grants=grants,
            )
        except _REFUSAL_EXCEPTIONS as denial:
            file_rows.append(
                _refused_row(
                    index,
                    getattr(getattr(denial, "code", None), "value", "read_refused"),
                )
            )
            any_incomplete = True
            continue
        read_refusal = getattr(outcome, "read_refusal", None)
        if read_refusal is not None:
            # 注入口内核把「打开前被拒」降为固定码终态：与异常路径同一行形态。
            file_rows.append(_refused_row(index, str(read_refusal)))
            any_incomplete = True
            grants.clear()
            continue
        budget_left -= max(outcome.read.consumed_bytes, 0)
        bytes_read_total += max(outcome.read.consumed_bytes, 0)
        stream_error = getattr(outcome, "stream_error", None)
        if stream_error is not None:
            # 文件存在但解不开（解压在产出任何行之前就失败）：这是文件级 `error` 行，
            # 绝不降为 `no_match`/`searched`，也不把它的候选或映射留下。
            any_incomplete = True
            grants.clear()
            for record in sink.records:
                mappings.pop(id(record), None)
            sink.records.clear()
            row = _refused_row(index, str(stream_error))
            row["status"] = "error"
            row["file"] = outcome.as_public_dict()
            file_rows.append(row)
            continue
        row: dict[str, Any] = {
            "index": index,
            "coverage_scope": COVERAGE_SCOPE_FILE,
            "records_captured": len(sink.records),
            "filter_scanned": 0,
            "filter_skipped": 0,
            "returned_count": 0,
            "reason": None,
            "file": outcome.as_public_dict(),
        }
        if outcome.read.reason is not None:
            row["read_stop"] = outcome.read.reason.value
        if outcome.pipeline.reason is not None:
            row["stage_stop"] = outcome.pipeline.reason.value
        if sink.failed or not outcome.complete:
            # 候选不完整或遮蔽捕获失败：整段作废，映射一并回收。
            any_incomplete = True
            for record in sink.records:
                mappings.pop(id(record), None)
            grants.clear()
            row["status"] = _FileRowStatus.INCOMPLETE.value
            row["reason"] = _incomplete_reason(outcome, sink)
            file_rows.append(row)
            continue
        segment = _FileSegment(
            index=index,
            ref=ref,
            outcome=outcome,
            records=list(sink.records),
            grants=dict(grants),
            version=outcome.version,
            consumed_bytes=max(outcome.read.consumed_bytes, 0),
        )
        segments.append(segment)
        row["status"] = _FileRowStatus.SEARCHED.value
        file_rows.append(row)
    return segments, file_rows, mappings, any_incomplete, budget_hit, bytes_read_total


# ---------------------------------------------------------------------------
# ctxref 签发（自带循环：`file_search._issue_references` 把 source 钉死为 pi）
# ---------------------------------------------------------------------------


def _issue_line_references(
    records: Sequence[StandardRecord],
    projects: Sequence[str | None],
    *,
    version: FileVersion,
    service_key: str,
    policy: SessionPolicy,
    scope: str,
    source: str,
    path: str,
    session_id: str,
    ledger: ReferenceLedger | None,
) -> tuple[str, ...]:
    """为一条文件段的候选签发定位令牌。

    与 `file_search._issue_references` 同一门禁：数量必须逐条对齐、超 `MAX_ISSUE_PER_CALL`
    即整段拒、版本不完整即拒、签发中途失败即整批回滚（一个字节都不外发）。
    """
    if len(records) != len(projects):
        raise ValueError("reference batch must carry one project per record")
    if len(records) > MAX_ISSUE_PER_CALL:
        raise ValueError("reference batch exceeds MAX_ISSUE_PER_CALL")
    if not version.complete:
        raise ValueError("reference issuance requires a complete file version")
    active = ledger if ledger is not None else default_ledger()
    tokens: list[str] = []
    try:
        for record, project in zip(records, projects, strict=True):
            location = record.location
            tokens.append(
                active.issue(
                    service_key=service_key,
                    path=path,
                    scope=scope,
                    source=source,
                    session_id=session_id,
                    project=project,
                    line_no=location.line_no,
                    ordinal=location.ordinal,
                    stream_label=location.stream_label,
                    volume=version.volume,
                    file_id=version.file_id,
                    size_bytes=version.size_bytes,
                    content_sha256=version.content_sha256,
                )
            )
    except BaseException:
        if tokens:
            active.release(tuple(tokens))
        raise
    return tuple(tokens)


# ---------------------------------------------------------------------------
# 搜索服务
# ---------------------------------------------------------------------------


class LineAggregateSearchService:
    """一个行式来源的有界文件集合搜索服务（codex / claude / cursor 共用）。"""

    __slots__ = ("policy", "scope", "spec", "files", "ledger")

    def __init__(
        self,
        *,
        policy: SessionPolicy,
        scope: str,
        spec: LineSourceSpec,
        files: Sequence[SessionFileRef],
        ledger: ReferenceLedger | None = None,
    ) -> None:
        if not isinstance(spec, LineSourceSpec):
            raise TypeError("LineAggregateSearchService requires a LineSourceSpec")
        materialized = _validate_bound_files(
            "LineAggregateSearchService", policy, scope, files, ledger
        )
        # 绑定即授权：每个文件都过一次 `authorize_store`，拒绝直接抛给宿主。
        for ref in materialized:
            policy.authorize_store(scope, spec.source_id, ref.path)
        self.policy = policy
        self.scope = scope
        self.spec = spec
        self.files = materialized
        self.ledger = ledger

    # -- 服务身份 ---------------------------------------------------------
    @property
    def source(self) -> str:
        return self.spec.source_id

    def store_refs(self) -> tuple[SessionFileRef, ...]:
        """绑定集合的只读快照（宿主诊断用；不含授权状态）。"""
        return self.files

    def binding_key(self, index: int) -> str:
        """第 `index` 个绑定文件的服务绑定指纹（四元组含来源）。"""
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.files):
            raise ValueError("binding_key index out of bounds")
        ref = self.files[index]
        return service_binding_key(
            scope=self.scope,
            source=self.spec.source_id,
            path=ref.path,
            session_id=ref.session_id,
        )

    def context_service(self, index: int) -> LineAggregateContextService:
        """派生绑定同一文件的上下文服务：同一策略、同一账本、同一 scope。"""
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.files):
            raise ValueError("context_service index out of bounds")
        ref = self.files[index]
        return LineAggregateContextService(
            policy=self.policy,
            scope=self.scope,
            spec=self.spec,
            path=ref.path,
            session_id=ref.session_id,
            ledger=self.ledger,
        )

    # -- 搜索入口 ---------------------------------------------------------
    def search(
        self,
        *,
        scope: str | None = None,
        query: str | None = None,
        sources: Sequence[str] | None = None,
        start: datetime | str | None = None,
        end: datetime | str | None = None,
        project: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        """在绑定的文件集合内执行一次有界搜索；返回可直接 JSON 化的脱敏载荷。"""
        source = self.spec.source_id
        if scope is not None and scope != self.scope:
            return _scope_rejection_payload(source)
        requested = tuple(sources) if sources else (source,)
        for item in requested:
            if not isinstance(item, str) or not item:
                return _empty_payload(
                    source,
                    reason=AggregateFailureCategory.INVALID_REQUEST.value,
                    stage=AggregateStageReached.COORDINATOR,
                    category=AggregateFailureCategory.INVALID_REQUEST,
                    rejected=True,
                    coverage_scope=COVERAGE_SCOPE_NONE,
                )
        if len(requested) > MAX_REQUESTED_SOURCES:
            return _empty_payload(
                source,
                reason=AggregateFailureCategory.INVALID_REQUEST.value,
                stage=AggregateStageReached.COORDINATOR,
                category=AggregateFailureCategory.INVALID_REQUEST,
                rejected=True,
                coverage_scope=COVERAGE_SCOPE_NONE,
            )
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PROTOCOL_LIMIT:
            return _empty_payload(
                source,
                reason=AggregateFailureCategory.INVALID_REQUEST.value,
                stage=AggregateStageReached.COORDINATOR,
                category=AggregateFailureCategory.INVALID_REQUEST,
                rejected=True,
                coverage_scope=COVERAGE_SCOPE_NONE,
            )
        if source not in requested:
            # 职责外点名：unsupported 行随行返回，不打开磁盘（多来源合并由注册表负责）。
            return {
                "results": [],
                "coverage": [_unsupported_row(item) for item in requested],
                "complete": False,
                "partial": True,
                "truncated": False,
                "total_matched": 0,
                "total_scanned": 0,
                "skipped_records": 0,
                "records_withheld": 0,
                "reason": AggregateFailureCategory.SOURCE_UNSUPPORTED.value,
                "stage_reached": AggregateStageReached.COORDINATOR.value,
                "failure_category": None,
                "coverage_scope": COVERAGE_SCOPE_NONE,
                "files": [],
            }
        return _search_line_files(
            self,
            query=query,
            start=start,
            end=end,
            project=project,
            limit=limit,
            unsupported=[item for item in requested if item != source],
            requested=requested,
        )


def _search_line_files(
    service: LineAggregateSearchService,
    *,
    query: str | None,
    start: datetime | str | None,
    end: datetime | str | None,
    project: str | None,
    limit: int,
    unsupported: Sequence[str],
    requested: Sequence[str],
) -> dict[str, Any]:
    """行式集合搜索内核：授权循环 → 全局过滤 → 两段式发布 → ctxref 签发。"""
    spec = service.spec
    source = spec.source_id
    scope_str = spec.scope_label()

    segments, file_rows, mappings, any_incomplete, budget_hit, _bytes_read = (
        _collect_segments(service.policy, service.scope, spec, service.files, project)
    )
    rows_by_index = {row["index"]: row for row in file_rows}

    if not segments:
        payload = _empty_payload(
            source,
            reason=AggregateFailureCategory.FILES_UNUSABLE.value,
            stage=AggregateStageReached.FILTER,
            category=AggregateFailureCategory.FILES_UNUSABLE,
            rejected=False,
            coverage_scope=scope_str,
            files=file_rows,
        )
        payload["coverage"][0]["filter_errors"] = [
            FilterErrorTag.FILES_UNUSABLE.value,
            AggregateFailureCategory.FILES_UNUSABLE.value,
        ]
        payload["coverage"][0]["reason"] = f"{_FILES_UNUSABLE_NOTE}{_LINE_MULTI_SCOPE_NOTE}"
        if unsupported:
            payload["coverage"].extend(_unsupported_row(item) for item in unsupported)
        return payload

    # 全局记录表：过滤层只看这一份列表，段内偏移用 positions 记账。
    all_records: list[StandardRecord] = []
    for seg in segments:
        for record in seg.records:
            seg.positions.append(len(all_records))
            all_records.append(record)
    full_set_scanned = not any_incomplete and not budget_hit

    scanned = scan_filter(
        all_records,
        query=query,
        start=start,
        end=end,
        project=project,
        project_mappings=mappings,
        sources=(source,),
        limit=min(limit, MAX_PROTOCOL_LIMIT),
        max_total_scan_chars=MAX_AGGREGATE_TOTAL_SCAN_CHARS,
        completed_sources=(source,) if full_set_scanned else (),
    )
    if scanned.rejected:
        reason = (
            scanned.reason.value
            if isinstance(scanned.reason, QueryRejectionReason)
            else AggregateFailureCategory.INVALID_REQUEST.value
        )
        payload = _empty_payload(
            source,
            reason=reason,
            stage=AggregateStageReached.FILTER,
            category=AggregateFailureCategory.INVALID_REQUEST,
            rejected=True,
            coverage_scope=scope_str,
            files=file_rows,
        )
        if unsupported:
            payload["coverage"].extend(_unsupported_row(item) for item in unsupported)
        return payload

    # 尾部跳过记账：过滤层没扫到的记录数写回文件行（只记账，不重扫）。
    for seg in segments:
        row = rows_by_index.get(seg.index)
        if row is None:
            continue
        row["filter_scanned"] = len(seg.positions)
        row["filter_skipped"] = scanned.skipped_records if seg is segments[-1] else 0

    # 逐文件片段配额：超出部分按文件段裁掉并声明结果截断。
    effective_limit = min(limit, MAX_AGGREGATE_SNIPPETS)
    per_file_cap = min(MAX_SNIPPETS_PER_FILE, effective_limit)
    kept_matches = []
    quota_cut = False
    used_per_segment: dict[int, int] = {}
    global_to_local: dict[int, int] = {}
    for offset, positions in enumerate([seg.positions for seg in segments]):
        for local, global_index in enumerate(positions):
            global_to_local[global_index] = offset
    for match in scanned.matches:
        segment_offset = global_to_local.get(match.record_index)
        if segment_offset is None:
            # 命中落在不可发布段：整批降级（与 pi 层同口径，绝不静默丢行）。
            return _aggregate_failure(
                service,
                segments,
                scanned,
                requested,
                category=AggregateFailureCategory.MATCH_JOIN_FAILED,
                stage=AggregateStageReached.FILTER,
                file_rows=file_rows,
            )
        used = used_per_segment.get(segment_offset, 0)
        if used >= per_file_cap:
            quota_cut = True
            continue
        used_per_segment[segment_offset] = used + 1
        kept_matches.append((match, segment_offset))

    ledger = service.ledger if service.ledger is not None else default_ledger()
    collectors: list[SnippetCollector | None] = [None] * len(segments)
    join_counters: dict[int, int] = {}
    returned_by_segment: dict[int, int] = {}
    issued_tokens: list[str] = []
    results: list[dict[str, Any]] = []
    metadata_withheld = False
    snippet_truncated = False

    try:
        # 遮蔽层第一段：逐段收集候选（拒绝即整批失败，绝不部分外发）。
        first_refusal: str | None = None
        for match, segment_offset in kept_matches:
            seg = segments[segment_offset]
            record = seg.records[seg.positions.index(match.record_index)]
            collector = collectors[segment_offset]
            if collector is None:
                collector = SnippetCollector(
                    source=source,
                    max_snippets=per_file_cap,
                    max_total_chars=_AGGREGATE_SNIPPET_TOTAL_CHARS,
                )
                collectors[segment_offset] = collector
            refusal = collector.collect(record)
            if refusal is not None:
                first_refusal = refusal.value
                break
        if first_refusal is not None:
            for collector in collectors:
                if collector is not None:
                    collector.discard(PublicationRefusal.NOT_CONFIRMED)
            return _aggregate_failure(
                service,
                segments,
                scanned,
                requested,
                category=AggregateFailureCategory.PUBLICATION_FAILED,
                stage=AggregateStageReached.PUBLICATION,
                file_rows=file_rows,
                reason=first_refusal,
            )

        # 遮蔽层第二段：逐段确认释放，并核对版本快照完整。
        published_total = 0
        published_chars = 0
        for offset, seg in enumerate(segments):
            collector = collectors[offset]
            if collector is None:
                continue
            if seg.version is None or not seg.version.complete:
                for other in collectors:
                    if other is not None:
                        other.discard(PublicationRefusal.NOT_CONFIRMED)
                return _aggregate_failure(
                    service,
                    segments,
                    scanned,
                    requested,
                    category=AggregateFailureCategory.FILE_INCOMPLETE,
                    stage=AggregateStageReached.PUBLICATION,
                    file_rows=file_rows,
                )
            snippets = collector.release(confirmed=True)
            seg.snippets = snippets
            published_total += len(snippets)
            published_chars += sum(len(snippet.snippet) for snippet in snippets)
        if published_chars > _AGGREGATE_SNIPPET_TOTAL_CHARS:
            return _aggregate_failure(
                service,
                segments,
                scanned,
                requested,
                category=AggregateFailureCategory.PUBLICATION_FAILED,
                stage=AggregateStageReached.PUBLICATION,
                file_rows=file_rows,
                reason=PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED.value,
            )
        if published_total != len(kept_matches):
            return _aggregate_failure(
                service,
                segments,
                scanned,
                requested,
                category=AggregateFailureCategory.SNIPPET_JOIN_FAILED,
                stage=AggregateStageReached.PUBLICATION,
                file_rows=file_rows,
            )

        # 逐段签发 ctxref：一段失败即整批回滚（已发令牌全部作废）。
        for match, segment_offset in kept_matches:
            seg = segments[segment_offset]
            local = seg.positions.index(match.record_index)
            if seg.outcome is None:
                return _aggregate_failure(
                    service,
                    segments,
                    scanned,
                    requested,
                    category=AggregateFailureCategory.MATCH_JOIN_FAILED,
                    stage=AggregateStageReached.PUBLICATION,
                    file_rows=file_rows,
                )
            if not seg.tokens:
                projects = [seg.grants.get(id(record)) for record in seg.records]
                seg.tokens = list(
                    _issue_line_references(
                        seg.records,
                        projects,
                        version=seg.version,
                        service_key=service.binding_key(seg.index),
                        policy=service.policy,
                        scope=service.scope,
                        source=source,
                        path=seg.ref.path,
                        session_id=seg.ref.session_id,
                        ledger=service.ledger,
                    )
                )
                issued_tokens.extend(seg.tokens)
            token = seg.tokens[local] if local < len(seg.tokens) else None
            if token is None:
                return _aggregate_failure(
                    service,
                    segments,
                    scanned,
                    requested,
                    category=AggregateFailureCategory.PUBLICATION_FAILED,
                    stage=AggregateStageReached.PUBLICATION,
                    file_rows=file_rows,
                    reason="reference_issue_failed",
                )
            # 片段与命中按「同段内收集顺序」一一对应：collect 在上一段循环里就是按
            # kept_matches 的顺序调用，release 保序返回，因此这里用段内计数器即可，
            # 绝不拿 line_no 猜匹配（同一行可产多个正文块，按行号对齐会串位）。
            join_offset = join_counters.get(segment_offset, 0)
            join_counters[segment_offset] = join_offset + 1
            snippet = seg.snippets[join_offset] if join_offset < len(seg.snippets) else None
            if snippet is None:
                return _aggregate_failure(
                    service,
                    segments,
                    scanned,
                    requested,
                    category=AggregateFailureCategory.SNIPPET_JOIN_FAILED,
                    stage=AggregateStageReached.PUBLICATION,
                    file_rows=file_rows,
                )
            row, withheld = _join_result(match, snippet)
            row["source"] = source
            row["location"] = token
            results.append(row)
            metadata_withheld = metadata_withheld or withheld
            snippet_truncated = snippet_truncated or bool(snippet.truncated)
            returned_by_segment[segment_offset] = returned_by_segment.get(segment_offset, 0) + 1
    except Exception:  # pragma: no cover - 意外失败必须整批作废
        logger.warning("line aggregate publication failed")
        if issued_tokens:
            ledger.release(tuple(issued_tokens))
        for collector in collectors:
            if collector is not None:
                collector.discard(PublicationRefusal.INTERNAL_FAILURE)
        return _aggregate_failure(
            service,
            segments,
            scanned,
            requested,
            category=AggregateFailureCategory.INTERNAL_FAILURE,
            stage=AggregateStageReached.PUBLICATION,
            file_rows=file_rows,
            records_withheld=len(all_records),
        )
    finally:
        for seg in segments:
            seg.records.clear()
            seg.grants.clear()
            seg.positions.clear()
            seg.snippets = ()

    coverage = [_aggregate_row(scanned, source, scope_str)]
    coverage.extend(_unsupported_row(item) for item in unsupported)
    for offset, count in returned_by_segment.items():
        srow = rows_by_index.get(segments[offset].index)
        if srow is not None and srow.get("status") == _FileRowStatus.SEARCHED.value:
            srow["returned_count"] = count
    if metadata_withheld:
        coverage = _annotate_dict_rows(
            coverage,
            AggregateFailureCategory.METADATA_WITHHELD.value,
            "短元数据形态不合，已降为 null。",
        )
    if snippet_truncated:
        coverage = _annotate_dict_rows(
            coverage,
            AggregateFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value,
            "遮蔽层按输出上限截过片段。",
        )
    if quota_cut:
        coverage[0]["returned_count"] = len(results)
        coverage[0]["partial"] = True
        coverage[0]["filter_errors"] = list(
            dict.fromkeys((*coverage[0]["filter_errors"], FilterErrorCode.RESULT_TRUNCATED.value))
        )
        coverage[0]["reason"] = _join_reason(coverage[0]["reason"], _QUOTA_NOTE)

    partial = (
        not scanned.complete
        or any_incomplete
        or budget_hit
        or quota_cut
        or metadata_withheld
        or snippet_truncated
        or any(row.get("partial") for row in coverage)
    )
    payload: dict[str, Any] = {
        "results": results,
        "coverage": coverage,
        "complete": bool(not partial and full_set_scanned),
        "partial": bool(partial),
        "truncated": bool(scanned.truncated or quota_cut),
        "total_matched": scanned.total_matched,
        "total_scanned": scanned.total_scanned,
        "skipped_records": scanned.skipped_records,
        "records_withheld": max(scanned.total_matched - len(results), 0) if quota_cut else 0,
        "rejected": False,
        "reason": scanned.reason.value if isinstance(scanned.reason, QueryRejectionReason) else None,
        "stage_reached": AggregateStageReached.PUBLISHED.value,
        "failure_category": None,
        "coverage_scope": scope_str,
        "files": file_rows,
        "source_scopes": [scope_str],
    }
    if quota_cut:
        payload["dropped_results"] = max(scanned.total_matched - len(results), 0)
    return payload


def _annotate_dict_rows(
    rows: Sequence[dict[str, Any]], category: str, note: str
) -> list[dict[str, Any]]:
    """dict 版覆盖行标注：`_annotate_rows` 只吃 SourceCoverage，聚合层行已是 dict。"""
    annotated: list[dict[str, Any]] = []
    for row in rows:
        updated = dict(row)
        errors = list(dict.fromkeys((*row.get("filter_errors", ()), category)))
        updated["filter_errors"] = errors
        updated["partial"] = True
        if updated.get("status") == "no_match":
            updated["status"] = "incomplete"
        updated["reason"] = _join_reason(updated.get("reason") or "", note)
        annotated.append(updated)
    return annotated


def _aggregate_failure(
    service: LineAggregateSearchService,
    segments: Sequence[_FileSegment],
    scanned: ScanFilterOutcome | None,
    requested: Sequence[str],
    *,
    category: AggregateFailureCategory,
    stage: AggregateStageReached,
    file_rows: list[dict[str, Any]],
    reason: str | None = None,
    records_withheld: int = 0,
) -> dict[str, Any]:
    """遮蔽/接线失败的整批结论：零结果 + error 行 + 逐文件行随行（不回滚由调用方负责）。"""
    source = service.spec.source_id
    scope_str = service.spec.scope_label()
    withheld = records_withheld
    if not withheld and scanned is not None:
        withheld = scanned.total_matched
    coverage_row = _aggregate_row(scanned, source, scope_str)
    coverage_row["status"] = "error"
    coverage_row["returned_count"] = 0
    coverage_row["partial"] = True
    coverage_row["filter_errors"] = list(
        dict.fromkeys(
            (*coverage_row["filter_errors"], FilterErrorTag.PUBLICATION_FAILED.value, category.value)
        )
    )
    coverage_row["reason"] = _join_reason(
        coverage_row["reason"], "遮蔽层或接线未发布本次结果。"
    )
    coverage = [coverage_row]
    coverage.extend(_unsupported_row(item) for item in requested if item != source)
    return {
        "results": [],
        "coverage": coverage,
        "complete": False,
        "partial": True,
        "truncated": False,
        "total_matched": scanned.total_matched if scanned is not None else 0,
        "total_scanned": scanned.total_scanned if scanned is not None else 0,
        "skipped_records": scanned.skipped_records if scanned is not None else 0,
        "records_withheld": withheld,
        "rejected": False,
        "reason": reason or category.value,
        "stage_reached": stage.value,
        "failure_category": category.value,
        "coverage_scope": scope_str,
        "files": file_rows,
        "source_scopes": [scope_str],
    }


# ---------------------------------------------------------------------------
# 上下文服务
# ---------------------------------------------------------------------------


class LineAggregateContextService:
    """一个绑定文件的上下文读取服务：ctxref → 重跑管线 → 定窗 → 遮蔽 → 重签。

    与 `session_context.PiFileContextService` 同一门禁链，只把来源与解析器参数化：scope /
    source / session / 绑定指纹四处核对、账本条目与文件版本快照必须逐字一致（改写即零结果
    拒绝），窗口两端只取已核实归属的记录。客户端全程无法提供路径。
    """

    __slots__ = ("policy", "scope", "spec", "path", "session_id", "ledger")

    def __init__(
        self,
        *,
        policy: SessionPolicy,
        scope: str,
        spec: LineSourceSpec,
        path: str,
        session_id: str,
        ledger: ReferenceLedger | None = None,
    ) -> None:
        if not isinstance(spec, LineSourceSpec):
            raise TypeError("LineAggregateContextService requires a LineSourceSpec")
        _validate_bound_file(
            "LineAggregateContextService", policy, scope, path, session_id
        )
        if ledger is not None and not isinstance(ledger, ReferenceLedger):
            raise TypeError("LineAggregateContextService accepts a ReferenceLedger only")
        policy.authorize_store(scope, spec.source_id, path)
        self.policy = policy
        self.scope = scope
        self.spec = spec
        self.path = path
        self.session_id = session_id
        self.ledger = ledger

    @property
    def source(self) -> str:
        return self.spec.source_id

    def binding_key(self) -> str:
        return service_binding_key(
            scope=self.scope,
            source=self.spec.source_id,
            path=self.path,
            session_id=self.session_id,
        )

    def read(
        self,
        *,
        scope: object = None,
        source: object = None,
        session_id: object = None,
        location: object = None,
        project: str | None = None,
        before: int = 2,
        after: int = 2,
    ) -> ContextOutcome:
        """读一段受限上下文；参数全为标量，客户端无法提供任何路径或版本基准。"""
        spec = self.spec
        source_id = spec.source_id
        if scope is not None and scope != self.scope:
            return _refused_line(
                ContextFailureCategory.BINDING_MISMATCH,
                reason_code="scope_mismatch",
                coverage_scope=COVERAGE_SCOPE_NONE,
            )
        if source is not None and source != source_id:
            return _refused_line(
                ContextFailureCategory.BINDING_MISMATCH,
                reason_code="source_mismatch",
                coverage_scope=COVERAGE_SCOPE_NONE,
            )
        token = parse_reference_token(location)
        if token is None:
            return _refused_line(ContextFailureCategory.INVALID_ARGUMENT)
        sides = _validated_sides(before, after)
        if sides is None:
            return _refused_line(
                ContextFailureCategory.INVALID_ARGUMENT, reason_code="window_out_of_range"
            )
        before_size, after_size = sides
        ledger = self.ledger if self.ledger is not None else default_ledger()
        entry = lookup_reference(token, ledger=ledger)
        if entry is None:
            return _refused_line(ContextFailureCategory.REF_EXPIRED)
        mismatch = _line_binding_matches(
            entry,
            service_key=self.binding_key(),
            session_id=session_id,
            project_filter=project,
            source=source_id,
        )
        if mismatch is not None:
            return _refused_line(
                ContextFailureCategory.BINDING_MISMATCH, reason_code=mismatch
            )

        candidates: list[StandardRecord] = []
        project_grants: dict[int, str] = {}
        capture_failed = False

        def _capture(record: StandardRecord) -> PublicationRefusal | None:
            nonlocal capture_failed
            try:
                candidates.append(record)
                return None
            except MemoryError:
                capture_failed = True
                return PublicationRefusal.INTERNAL_FAILURE

        limits = spec.limits()
        try:
            file_outcome = spec.runner()(
                self.policy,
                self.scope,
                self.path,
                self.session_id,
                source=source_id,
                parser_factory=spec.parser_factory,
                max_line_bytes=limits.get("max_line_bytes", DEFAULT_MAX_LINE_BYTES),
                max_total_bytes=limits.get(
                    "max_total_bytes", MAX_CONTEXT_STAGE_BYTES * 8
                ),
                max_lines=limits.get("max_lines", DEFAULT_MAX_LINES),
                max_candidates=MAX_CONTEXT_CANDIDATES,
                max_bytes=MAX_CONTEXT_STAGE_BYTES,
                project_filter=project,
                _candidate_capture=_capture,
                _project_grants=project_grants,
            )
        except _REFUSAL_EXCEPTIONS as denial:
            return _refused_line(
                ContextFailureCategory.NOT_FOUND,
                reason_code=getattr(getattr(denial, "code", None), "value", "read_refused"),
                file_outcome=None,
            )
        if getattr(file_outcome, "read_refusal", None) is not None:
            return _refused_line(
                ContextFailureCategory.NOT_FOUND,
                reason_code=str(file_outcome.read_refusal),
                file_outcome=None,
            )

        stage = ContextStageReached.FILE_PIPELINE
        if capture_failed:
            return _refused_line(
                ContextFailureCategory.CANDIDATE_CAPTURE_FAILED, file_outcome=file_outcome
            )
        if not file_outcome.complete:
            return _refused_line(
                ContextFailureCategory.INCOMPLETE,
                reason_code=(
                    file_outcome.reason.value if file_outcome.reason is not None else None
                ),
                file_outcome=file_outcome,
            )
        version = file_outcome.version
        if version is None or not version.complete:
            return _refused_line(
                ContextFailureCategory.INCOMPLETE,
                reason_code="version_unavailable",
                file_outcome=file_outcome,
            )
        if (
            version.volume != entry.volume
            or version.file_id != entry.file_id
            or version.size_bytes != entry.size_bytes
            or version.content_sha256 != entry.content_sha256
        ):
            return _refused_line(
                ContextFailureCategory.FILE_REPLACED, file_outcome=file_outcome
            )

        # 定窗：锚点必须落在本次重跑的同一条记录上（行号 + 序号 + 流标签三值同判）。
        forms = [_anchor_form(record) for record in candidates]
        anchor = None
        for index, form in enumerate(forms):
            if form is None:
                continue
            line_no, ordinal, label = form
            if (
                line_no == entry.line_no
                and ordinal == entry.ordinal
                and label == entry.stream_label
                and _comparable_key(candidates[index].session_id)
                == _comparable_key(self.session_id)
            ):
                anchor = index
                break
        if anchor is None:
            return _refused_line(
                ContextFailureCategory.NOT_FOUND,
                reason_code="anchor_not_found",
                file_outcome=file_outcome,
            )
        lower = max(0, anchor - before_size)
        upper = min(len(candidates), anchor + after_size + 1)
        window = candidates[lower:upper]
        if len(window) > MAX_CONTEXT_WINDOW_RECORDS:
            return _refused_line(
                ContextFailureCategory.WINDOW_UNRESOLVED,
                reason_code="window_limit_exceeded",
                file_outcome=file_outcome,
            )

        effective_snippets = min(len(window), MAX_CONTEXT_SNIPPETS)
        collector = SnippetCollector(
            source=source_id,
            max_snippets=effective_snippets,
            max_total_chars=MAX_CONTEXT_TOTAL_CHARS,
        )
        stage = ContextStageReached.WINDOW
        refusal = None
        for record in window:
            refusal = collector.collect(record)
            if refusal is not None:
                break
        if refusal is not None:
            collector.discard(PublicationRefusal.NOT_CONFIRMED)
            return _refused_line(
                ContextFailureCategory.PUBLICATION_FAILED,
                reason_code=refusal.value,
                file_outcome=file_outcome,
            )
        snippets = collector.release(confirmed=True)
        if len(snippets) != len(window):
            return _refused_line(
                ContextFailureCategory.WINDOW_UNRESOLVED,
                reason_code="snippet_join_failed",
                file_outcome=file_outcome,
            )

        stage = ContextStageReached.PUBLICATION
        window_projects: list[str | None] = []
        for record in window:
            granted = project_grants.get(id(record))
            if granted is None and record.project_quality is not ProjectQuality.TRUSTED_HEADER_CWD:
                window_projects.append(None)
                continue
            window_projects.append(granted)
        try:
            tokens = _issue_line_references(
                window,
                window_projects,
                version=version,
                service_key=self.binding_key(),
                policy=self.policy,
                scope=self.scope,
                source=source_id,
                path=self.path,
                session_id=self.session_id,
                ledger=self.ledger,
            )
        except ValueError:
            return _refused_line(
                ContextFailureCategory.REFERENCE_ISSUE_FAILED,
                file_outcome=file_outcome,
            )
        except Exception:
            return _refused_line(
                ContextFailureCategory.INTERNAL_FAILURE, file_outcome=file_outcome
            )

        rows: list[dict[str, Any]] = []
        withheld = False
        try:
            for record, snippet, reference in zip(window, snippets, tokens):
                row, held = _row_for(
                    record,
                    window_projects[len(rows)] if len(rows) < len(window_projects) else None,
                    source_id,
                    reference,
                    snippet.snippet,
                    snippet.redacted_count,
                    snippet.truncated,
                )
                rows.append(row)
                withheld = withheld or held
        except Exception:
            ledger.release(tokens)
            return _refused_line(
                ContextFailureCategory.INTERNAL_FAILURE, file_outcome=file_outcome
            )

        quality_issues = _window_quality_issues(window)
        codes: list[str] = []
        if any(snippet.truncated for snippet in snippets):
            codes.append(ContextFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value)
        if withheld:
            codes.append(ContextFailureCategory.METADATA_WITHHELD.value)
        outcome = ContextOutcome(
            complete=not codes,
            partial=bool(codes),
            truncated=withheld or any(snippet.truncated for snippet in snippets),
            status="searched" if rows else "no_match",
            reason=None,
            failure_category=None,
            stage_reached=ContextStageReached.PUBLISHED.value,
            coverage_scope=COVERAGE_SCOPE_FILE,
            window_size=len(rows),
            records_withheld=max(len(candidates) - len(window), 0),
            version_confirmed=True,
            filter_error_codes=tuple(codes),
            quality_issues=tuple(quality_issues),
            notes=(_FILE_SCOPE_NOTE,),
            results=tuple(rows),
            file=file_outcome,
        )
        return outcome


_FILE_SCOPE_NOTE = "结论范围限这一个已批准文件，不声明该来源的整体存储已扫完。"
MAX_CONTEXT_WINDOW_RECORDS = 21


def _refused_line(
    category: ContextFailureCategory,
    *,
    reason_code: str | None = None,
    coverage_scope: str = COVERAGE_SCOPE_FILE,
    stage: ContextStageReached = ContextStageReached.COORDINATOR,
    file_outcome: PiFileOutcome | None = None,
) -> ContextOutcome:
    """固定形状的拒绝结论：只含闭合码与计数，绝不含路径或正文。"""
    codes = [category.value]
    if reason_code:
        codes.append(reason_code)
    if file_outcome is not None:
        if file_outcome.read.reason is not None:
            codes.append(file_outcome.read.reason.value)
        if file_outcome.pipeline.reason is not None:
            codes.append(file_outcome.pipeline.reason.value)
        if file_outcome.attribution_refusal is not None:
            codes.append(file_outcome.attribution_refusal.value)
    return ContextOutcome(
        complete=False,
        partial=True,
        truncated=False,
        status="incomplete",
        reason=category.value,
        failure_category=category.value,
        stage_reached=stage.value,
        coverage_scope=coverage_scope,
        window_size=0,
        records_withheld=0,
        version_confirmed=False,
        filter_error_codes=tuple(dict.fromkeys(codes)),
        quality_issues=(),
        notes=(_FILE_SCOPE_NOTE, _LAYERED_COUNTER_NOTE),
        results=(),
        file=file_outcome,
    )


def _line_binding_matches(
    entry: Any,
    *,
    service_key: str,
    session_id: object,
    project_filter: str | None,
    source: str,
) -> str | None:
    """账本条目与本次请求的绑定核对：来源/服务/会话/归属四处任一不合即返回原因码。"""
    if entry.source != source:
        return "source_mismatch"
    if entry.service_key != service_key:
        return "service_binding"
    if session_id is not None and _comparable_key(session_id) != _comparable_key(
        entry.session_id
    ):
        return "session_binding"
    if project_filter is not None:
        claimed = _comparable_key(project_filter)
        if claimed is not None and claimed != _comparable_key(entry.project):
            return "project_binding"
    return None


# ---------------------------------------------------------------------------
# 规格实例（放在来源导入之后构造，避免循环导入：来源包不依赖本模块）
# ---------------------------------------------------------------------------

CODEX_SPEC = register_spec(
    LineSourceSpec(source_id=SOURCE_CODEX, parser_factory=CodexRolloutLineParser)
)
CLAUDE_SPEC = register_spec(
    LineSourceSpec(source_id=SOURCE_CLAUDE, parser_factory=ClaudeLineParser)
)
CURSOR_SPEC = register_spec(
    LineSourceSpec(
        source_id=SOURCE_CURSOR,
        parser_factory=CursorAgentTranscriptLineParser,
        default_limits={
            "max_line_bytes": 1_048_576,
            "max_total_bytes": 33_554_432,
            "max_lines": 200_000,
        },
    )
)
PI_SPEC = register_spec(
    LineSourceSpec(source_id=SOURCE_PI, parser_factory=PiLineParser)
)
DSH_SPEC = register_spec(
    LineSourceSpec(
        source_id=SOURCE_DSH,
        parser_factory=DshLineParser,
        coverage_scope=DSH_COVERAGE_SCOPE,
        default_limits={
            "max_line_bytes": MAX_DSH_LINE_BYTES,
            "max_total_bytes": 33_554_432,
            "max_lines": MAX_DSH_LINES_PER_STREAM,
        },
        file_runner=run_dsh_frame_file,
    )
)


def make_dsh_spec(runtime: object | None = None) -> LineSourceSpec:
    """按宿主给定的解码运行时派生一份 DSH 规格（运行时只从 `bind_dsh_*` 进来）。

    注册表里的 `DSH_SPEC` 缺省按当前进程探测；绑定期拿到显式解释器路径时，用本函数换掉
    runner 的 `runtime` 关键字（`functools.partial` 只固定这一个参数，其余调用形态不变），
    因此同一套聚合内核不必为 DSH 复制第二份。规格不同对象同来源不得混登，故不进注册表。
    """
    import functools

    runner = (
        run_dsh_frame_file
        if runtime is None
        else functools.partial(run_dsh_frame_file, runtime=runtime)  # type: ignore[call-arg]
    )
    return LineSourceSpec(
        source_id=DSH_SPEC.source_id,
        parser_factory=DSH_SPEC.parser_factory,
        coverage_scope=DSH_SPEC.coverage_scope,
        default_limits=dict(DSH_SPEC.default_limits or {}),
        file_runner=runner,
    )
