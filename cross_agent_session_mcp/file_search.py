"""Bounded keyword/time/project search over one explicitly approved Pi session file.

This coordinator never discovers files and has no client-supplied path parameter. A trusted
in-process host constructs ``PiFileSearchService`` with one fixed path, policy, scope, and
independently held session ID. Raw ``StandardRecord`` objects exist only in the bounded local
candidate list and are cleared before return; only policy-authorized metadata and redacted
snippets can cross the result boundary.

Result-boundary vocabulary
    Every string this module adds to a result or coverage row comes from a closed set defined
    here (``PiFileFailureCategory``, ``PiFileStageReached``), from a policy-supplied project
    name, or from the sanitizer-backed location reference. Session-side free text never crosses
    as an identifier: ``session_id``/``role``/``executor`` must pass ``_public_key`` (bounded
    length, fixed character class, no separators, drive letters, or whitespace) before
    publication, so a session that stores a filesystem path where an identifier belongs is
    withheld as ``null`` and its coverage row is marked ``metadata_withheld`` instead of
    publishing that path. That gate is not a duplicate of an internal check: those three values
    come from the untrusted session file, and upstream only judges blank/length, so a path-shaped
    identifier really does reach here. ``location`` is not a composed address at this boundary
    either: after whole-batch publication succeeds, each row's location is replaced by an opaque
    ``ctxref:<random>`` token from ``references.ReferenceLedger`` (metadata only, expiring, capped).
    The token carries no line number, label, path, or file version, so it cannot be guessed,
    forged, or steered: ``parse_reference_token`` rejects anything the ledger never issued, and
    ``session_context`` reads the binding from the ledger itself instead of from client fields.
    Rows whose publication or issuance failed keep zero output by the whole-batch rule. Snippet
    bodies are a different channel: the redaction layer only claims common credential shapes, so
    a body can still contain path-like text; that is the caller's data policy to handle, not
    something this module asserts away.

Coverage is file-level, never source-level
    Where this coordinator has file-level evidence, ``coverage_scope`` is ``single_approved_file``
    on the pi row. A ``no_match`` there proves only that *this* approved file was read to EOF,
    parsed, reconciled, and filtered; it never claims the whole ``pi`` source was scanned, which
    is all ``completed_sources=(SOURCE_PI,)`` can mean at this coordinator. Requests that never
    reached the file (scope mismatch, rejected filter, no approved pi file) and sources named but
    not served carry ``coverage_scope=none`` instead, so no row can be read as source-level
    completion.

Counters are layered, and matched is not published
    ``records_scanned``/``skipped_count``/``scan_chars`` describe the query-filter layer only, and
    a zero there is a statement about that layer.
    The file-layer snapshot nested under ``file`` answers how far the run actually got --
    ``read.lines_read``/``consumed_bytes``/``eof_reached``, ``pipeline.records_seen``,
    ``pipeline.parse.lines_seen``/``records_emitted``/``skipped_count``, and
    ``pipeline.stage.candidate_count``/``dropped_count`` -- together with ``stage_reached`` and
    ``records_withheld``. A failure before the filter layer therefore reads as "not judged by the
    filter layer", never as "nothing was scanned". ``matched_count``/``total_matched`` are filter
    diagnostics: a non-zero match count on a publication failure does **not** mean anything was
    returned. ``results``/``returned_count`` are the only publication channel, and publication
    failures zero them by design (whole-batch rejection, never a prefix).
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .models import StandardRecord
from .policy import PolicyDenied, SessionPolicy
from .publication import (
    MAX_SNIPPET_TOTAL_CHARS,
    MAX_SNIPPETS_HARD_LIMIT,
    MAX_SNIPPETS_PER_FILE,
    PublicationRefusal,
    PublishedSnippet,
    SnippetCollector,
)
from .query import (
    MAX_CALLER_KEY_CHARS,
    MAX_SESSION_ID_CHARS,
    SUPPORTED_SOURCES,
    MatchRef,
    ScanFilterOutcome,
    scan_filter,
)
from .references import (
    MAX_ISSUE_PER_CALL,
    ReferenceLedger,
    default_ledger,
    service_binding_key,
)
from .safe_reader import FileVersion, SafeReadDenied
from .session_pipeline import PiFileOutcome, _run_pi_file_pipeline

__all__ = [
    "COVERAGE_SCOPE_FILE",
    "PiFileFailureCategory",
    "PiFileSearchOutcome",
    "PiFileSearchService",
    "PiFileStageReached",
]

#: 已批准文件之外被点名的来源根本没有被扫：覆盖范围记为 `none`。
COVERAGE_SCOPE_NONE = "none"

#: 固定追加到每条 pi 覆盖行的范围声明（含前导空格，接在任意固定句后）。
_FILE_SCOPE_NOTE = "覆盖范围仅限本次绑定的单个已批准文件，不声明整个 pi 来源已扫完。"

SOURCE_PI = "pi"

#: 本协调器给出的覆盖结论只覆盖这一个已批准文件，不是整个 ``pi`` 来源。
COVERAGE_SCOPE_FILE = "single_approved_file"

#: 可外出短元数据的字符集：ASCII 字母数字与 ``-``、``_``、``.``。**不含** ``/``、``\\``、
#: ``:``、空白与非 ASCII，因此 ``C:/x``、``C:\\x``、``/a/b``、``\\\\srv\\share`` 这类路径形态、
#: 以及含空白的自由文本都无法作为标识外出。取向同 ``models.sanitize_stream_label``：整体判否，
#: 不做前缀截断（前缀仍会携带原值片段）。
_PUBLIC_KEY_SAFE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)


class PiFileFailureCategory(StrEnum):
    """本模块外出的失败类别：闭合集合，不接受数据侧字符串造键。

    这些值会进入 ``reason`` 与逐来源 ``filter_errors``，因此和 ``StageDiscardReason``、
    ``PublicationRefusal`` 一样必须是本模块定义的固定类别；新增类别只能改本枚举。
    ``read``/``pipeline`` 的分层类别（``ReadStop``/``StageDiscardReason``）也原样进
    ``filter_errors``——它们同样是闭合枚举成员，不含原值。
    """

    SCOPE_MISMATCH = "scope_mismatch"  # 请求 scope 与已绑定范围不符
    SOURCE_UNSUPPORTED = "source_unsupported"  # 点名的来源不由本文件服务提供
    FILE_INCOMPLETE = "file_incomplete"  # 读取/解析/身份/归属核对未通过
    CANDIDATE_CAPTURE_FAILED = "candidate_capture_failed"  # 捕获候选时失败
    ATTRIBUTION_INCOMPLETE = "attribution_incomplete"  # 缺可用的记录→项目映射
    INTERNAL_FAILURE = "internal_failure"  # 协调器内的意外失败
    PUBLICATION_FAILED = "publication_failed"  # 遮蔽或接线失败，整批未发布
    MATCH_JOIN_FAILED = "match_join_failed"  # 命中下标越界或重复
    SNIPPET_JOIN_FAILED = "snippet_join_failed"  # 片段数与命中数不等
    SNIPPET_OUTPUT_TRUNCATED = "snippet_output_truncated"  # 遮蔽层按输出上限截过片
    METADATA_WITHHELD = "metadata_withheld"  # 短元数据形态不合，已降为 null


class PiFileStageReached(StrEnum):
    """本次运行最远走到哪一层（闭合类别），供分层计数解读用。

    它只说明「走到哪」，不说明那一层是否通过；通过与否由 ``file`` 快照与各层整数回答。
    ``published`` 表示过滤、遮蔽、接线全部走通（片段是否真被外出仍看 ``returned_count``）。
    """

    COORDINATOR = "coordinator"  # 连文件管线结论都没拿到
    FILE_PIPELINE = "file_pipeline"  # 停在读/解析/暂存核对
    CANDIDATE_CAPTURE = "candidate_capture"  # 文件核对完成，捕获候选时失败
    ATTRIBUTION_JOIN = "attribution_join"  # 捕获完成，项目映射接线失败
    FILTER = "filter"  # 已交给过滤层，但过滤层未给出可用结论
    PUBLICATION = "publication"  # 走到遮蔽/接线，但未发布
    PUBLISHED = "published"  # 已发布（结果或可证明的空结果）


#: 每个类别对应一句固定人话：不拼接长度、条数、路径等派生值（同 ``query``/``publication``）。
#: 键取枚举成员：``StrEnum`` 成员与它的 ``.value`` 同哈希，所以按成员和按 ``str`` 都能查到。
_CATEGORY_REASONS: dict[str, str] = {
    PiFileFailureCategory.SOURCE_UNSUPPORTED: "本协调器仅查询一个已批准的 pi 文件。",
    PiFileFailureCategory.FILE_INCOMPLETE: (
        "文件未通过完整读取、身份或归属核对；本来源未发布结果。"
    ),
    PiFileFailureCategory.CANDIDATE_CAPTURE_FAILED: (
        "候选捕获失败，已核对的文件未交给查询过滤层；本来源未发布结果。"
    ),
    PiFileFailureCategory.ATTRIBUTION_INCOMPLETE: (
        "记录缺少可用的项目归属映射，未进入查询过滤层；本来源未发布结果。"
    ),
    PiFileFailureCategory.INTERNAL_FAILURE: (
        "协调器内部失败；本来源未发布结果，分层计数只在已取到的结论上给出。"
    ),
}

#: 类别表未命中时的兜底句（不拿另一个原因的文案顶替）。
_GENERIC_INCOMPLETE_NOTE = "本协调器未完成发布前置核对；本来源未发布结果。"

#: 遮蔽/接线失败时的固定说明：三条路径的可用性代价不同，不合并成一句。
_PUBLICATION_REASONS: dict[str, str] = {
    PublicationRefusal.REDACTION_REJECTED.value: (
        "至少一条候选未通过输出遮蔽，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.SNIPPET_LIMIT_EXCEEDED.value: (
        "遮蔽片段条数触本文件上限，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.NOT_CONFIRMED.value: (
        "本次运行未拿到完整确认，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED.value: (
        "遮蔽片段总字符数触本文件输出预算，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.RECORD_UNUSABLE.value: (
        "候选形态不可用于片段，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.INTERNAL_FAILURE.value: (
        "片段收集过程失败，整批未发布（零结果，不是前缀）。"
    ),
    PiFileFailureCategory.MATCH_JOIN_FAILED.value: (
        "命中引用的记录下标越界或重复，整批未发布（零结果，不是前缀）。"
    ),
    PiFileFailureCategory.SNIPPET_JOIN_FAILED.value: (
        "遮蔽片段数与命中数不等，无法一一对应，整批未发布（零结果，不是前缀）。"
    ),
}

_LAYERED_COUNTER_NOTE = (
    "计数按层给出：records_scanned=0 只表示查询过滤层未判定这些记录，不表示文件未被读取或解析。"
)
_SNIPPET_TRUNCATION_NOTE = "一个或多个遮蔽片段按输出上限截断。"
_METADATA_WITHHELD_NOTE = (
    "存在形态不可外的短元数据（路径形态、含分隔符/空白或超长），已降为 null 并记为覆盖不完整。"
)


@dataclass(frozen=True)
class PiFileSearchOutcome:
    """One query's safe, JSON-ready results and source coverage."""

    complete: bool
    partial: bool
    truncated: bool
    total_matched: int
    total_scanned: int
    skipped_records: int
    results: tuple[dict[str, Any], ...]
    coverage: tuple[dict[str, Any], ...]
    file: PiFileOutcome | None = None
    rejected: bool = False
    reason: str | None = None
    #: 本结论的覆盖层级：``single_approved_file`` 只指本次一个已批准文件；文件根本没被服
    #: 务的请求（scope 不配、预检被拒、只点名其他来源）记 ``none``。两者都不表示整个来源扫完。
    coverage_scope: str = COVERAGE_SCOPE_FILE
    #: 本次运行最远走到的层（``PiFileStageReached`` 值），用于正确解读分层计数。
    stage_reached: str = PiFileStageReached.COORDINATOR.value
    #: 因门禁未发布而收回的条数：过滤层之前失败记已捕获候选数；发布失败记本应发布的命中数。
    #: 它与过滤层的 ``skipped_records``（未进入过滤的记录数）不是同一口径。
    records_withheld: int = 0
    #: 失败时的精确类别（``PiFileFailureCategory`` 值或 ``PublicationRefusal`` 值）。
    failure_category: str | None = None

    @property
    def returned_count(self) -> int:
        """**已发布**的结果条数；``total_matched`` 非零不表示这里非零。"""
        return len(self.results)

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "partial": self.partial,
            "truncated": self.truncated,
            "total_matched": self.total_matched,
            "total_scanned": self.total_scanned,
            "skipped_records": self.skipped_records,
            "returned_count": self.returned_count,
            "rejected": self.rejected,
            "reason": self.reason,
            "coverage_scope": self.coverage_scope,
            "stage_reached": self.stage_reached,
            "records_withheld": self.records_withheld,
            "failure_category": self.failure_category,
            "results": list(self.results),
            "coverage": list(self.coverage),
            "file": self.file.as_public_dict() if self.file is not None else None,
        }


@dataclass(frozen=True)
class PiFileSearchService:
    """Server-side binding to one policy, scope, approved path, and independent session ID.

    Construction is explicit and performs no configuration lookup, filesystem read, or service
    startup. The path is never part of a search request.
    """

    policy: SessionPolicy
    scope: str
    path: str
    session_id: str
    ledger: ReferenceLedger | None = None

    def __post_init__(self) -> None:
        if self.ledger is not None and not isinstance(self.ledger, ReferenceLedger):
            raise TypeError("PiFileSearchService accepts a ReferenceLedger only")

    def search(
        self,
        *,
        scope: str | None = None,
        query: str | None = None,
        sources: Sequence[str] | None = None,
        start: datetime | str | None = None,
        end: datetime | str | None = None,
        project: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        if scope is not None and scope != self.scope:
            return PiFileSearchOutcome(
                complete=False,
                partial=False,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=0,
                results=(),
                coverage=(),
                rejected=True,
                reason=PiFileFailureCategory.SCOPE_MISMATCH.value,
                coverage_scope=COVERAGE_SCOPE_NONE,
                failure_category=PiFileFailureCategory.SCOPE_MISMATCH.value,
            ).as_public_dict()
        return _search_pi_file(
            self.policy,
            self.scope,
            self.path,
            self.session_id,
            query=query,
            sources=sources,
            start=start,
            end=end,
            project=project,
            limit=limit,
            ledger=self.ledger,
        ).as_public_dict()


def _search_pi_file(
    policy: SessionPolicy,
    scope: str,
    path: str,
    session_id: str,
    *,
    query: str | None = None,
    sources: Sequence[str] | None = None,
    start: datetime | str | None = None,
    end: datetime | str | None = None,
    project: str | None = None,
    limit: int = 20,
    ledger: ReferenceLedger | None = None,
) -> PiFileSearchOutcome:
    """Search one policy-approved Pi file without publishing a prefix on gate failure.

    Query filters are validated before opening the file. The file runner then performs store
    authorization, trusted-header attribution, session reconciliation, bounded parsing, and EOF
    confirmation. Only a complete file is passed to the query scanner. Matched records are
    redacted after filtering; any capture, scan, or publication failure yields no result snippets.
    """
    # Run the existing scanner on an empty bounded input as the query-validation boundary. This
    # prevents malformed filters from causing even the approved file to be opened. The actual
    # scan below reuses the same established scanner over the completed candidate batch.
    # `sources` is normalized once, up front: a generator/iterator argument must not be drained by
    # the preflight and then silently read as "pi was not requested" on the second pass.
    requested_sources = (SOURCE_PI,) if sources is None else tuple(sources)
    candidates: list[StandardRecord] = []
    project_grants: dict[int, str] = {}
    capture_failed = False
    collector: SnippetCollector | None = None
    file_outcome: PiFileOutcome | None = None
    scanned: ScanFilterOutcome | None = None
    issued_tokens: tuple[str, ...] = ()
    stage = PiFileStageReached.COORDINATOR
    try:
        preflight = scan_filter(
            [],
            query=query,
            start=start,
            end=end,
            project=project,
            sources=requested_sources,
            limit=limit,
        )
        if preflight.rejected:
            reason = (
                preflight.reason.value
                if preflight.reason
                else PiFileFailureCategory.INTERNAL_FAILURE.value
            )
            return PiFileSearchOutcome(
                complete=False,
                partial=False,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=0,
                results=(),
                coverage=(),
                rejected=True,
                reason=reason,
                coverage_scope=COVERAGE_SCOPE_NONE,
                failure_category=reason,
            )

        if SOURCE_PI not in requested_sources:
            rows = tuple(_unsupported_coverage(source) for source in requested_sources)
            return PiFileSearchOutcome(
                complete=False,
                partial=True,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=0,
                results=(),
                coverage=rows,
                reason=PiFileFailureCategory.SOURCE_UNSUPPORTED.value,
                coverage_scope=COVERAGE_SCOPE_NONE,
                failure_category=PiFileFailureCategory.SOURCE_UNSUPPORTED.value,
            )

        def capture_candidate(record: StandardRecord) -> object:
            nonlocal capture_failed
            try:
                candidates.append(record)
                return None
            except MemoryError:
                capture_failed = True
                return PublicationRefusal.INTERNAL_FAILURE

        file_outcome = _run_pi_file_pipeline(
            policy,
            scope,
            path,
            session_id,
            project_filter=project,
            _candidate_capture=capture_candidate,
            _project_grants=project_grants,
        )
        stage = PiFileStageReached.FILE_PIPELINE

        if not file_outcome.complete or capture_failed:
            # The file layers did report real progress (lines read, records parsed, candidates
            # staged or dropped): it lives in `file`, and `stage_reached` says which layer this
            # coordinator stopped at. `records_scanned=0` here means "the filter layer judged
            # nothing", never "nothing was read".
            category = (
                PiFileFailureCategory.CANDIDATE_CAPTURE_FAILED
                if capture_failed
                else PiFileFailureCategory.FILE_INCOMPLETE
            )
            if capture_failed:
                stage = PiFileStageReached.CANDIDATE_CAPTURE
            row = _incomplete_coverage(
                records_withheld=len(candidates),
                category=category.value,
                file_outcome=file_outcome,
            )
            return PiFileSearchOutcome(
                complete=False,
                partial=True,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=len(candidates),
                results=(),
                coverage=_merge_coverage((row,), requested_sources),
                file=file_outcome,
                reason=category.value,
                stage_reached=stage.value,
                records_withheld=len(candidates),
                failure_category=category.value,
            )

        stage = PiFileStageReached.CANDIDATE_CAPTURE
        mappings: dict[int, str] = {}
        for index, record in enumerate(candidates):
            project_name = project_grants.get(id(record))
            if not isinstance(project_name, str) or not project_name:
                category = PiFileFailureCategory.ATTRIBUTION_INCOMPLETE
                row = _incomplete_coverage(
                    records_withheld=len(candidates),
                    category=category.value,
                    file_outcome=file_outcome,
                )
                return PiFileSearchOutcome(
                    complete=False,
                    partial=True,
                    truncated=False,
                    total_matched=0,
                    total_scanned=0,
                    skipped_records=len(candidates),
                    results=(),
                    coverage=_merge_coverage((row,), requested_sources),
                    file=file_outcome,
                    reason=category.value,
                    stage_reached=PiFileStageReached.ATTRIBUTION_JOIN.value,
                    records_withheld=len(candidates),
                    failure_category=category.value,
                )
            mappings[index] = project_name

        # Attribution wiring is done; from here the run has reached the filter layer, so a
        # failure inside `scan_filter` reports `filter`, not an earlier stage.
        stage = PiFileStageReached.FILTER
        # Publication has a stricter per-file snippet cap than the API's 1..100 result limit.
        # Feeding that effective limit to scan_filter reports the cap honestly as truncation.
        effective_limit = min(limit, MAX_SNIPPETS_PER_FILE, MAX_SNIPPETS_HARD_LIMIT)
        scanned = scan_filter(
            candidates,
            query=query,
            start=start,
            end=end,
            project=project,
            project_mappings=mappings,
            sources=(SOURCE_PI,),
            limit=effective_limit,
            # File-level evidence only: this proves the approved file's own candidate bucket was
            # read to EOF, parsed, and reconciled before the scan. It never claims the whole
            # `pi` source was covered; `coverage_scope` on every row carries that boundary.
            completed_sources=(SOURCE_PI,),
        )
        if scanned.rejected:
            reason = (
                scanned.reason.value
                if scanned.reason
                else PiFileFailureCategory.INTERNAL_FAILURE.value
            )
            return PiFileSearchOutcome(
                complete=False,
                partial=True,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=len(candidates),
                results=(),
                coverage=(),
                file=file_outcome,
                rejected=True,
                reason=reason,
                stage_reached=stage.value,
                records_withheld=len(candidates),
                failure_category=reason,
            )

        indices: list[int] = []
        seen: set[int] = set()
        for match in scanned.matches:
            index = match.record_index
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or not 0 <= index < len(candidates)
                or index in seen
            ):
                return _publication_failure(
                    file_outcome,
                    scanned,
                    requested_sources,
                    PiFileFailureCategory.MATCH_JOIN_FAILED.value,
                    stage,
                )
            seen.add(index)
            indices.append(index)

        stage = PiFileStageReached.PUBLICATION
        collector = SnippetCollector(
            source=SOURCE_PI,
            max_snippets=effective_limit,
            max_total_chars=MAX_SNIPPET_TOTAL_CHARS,
        )
        for index in indices:
            refusal = collector.collect(candidates[index])
            if refusal is not None:
                # Refusal clears the entire candidate batch; never return a metadata-only prefix.
                # The exact budget/refusal stays visible as `failure_category` and in the row's
                # `filter_errors`, so "why zero" is distinguishable from "found nothing".
                collector.release(confirmed=False)
                return _publication_failure(
                    file_outcome,
                    scanned,
                    requested_sources,
                    refusal.value,
                    stage,
                )

        snippets = collector.release(confirmed=file_outcome.complete)
        if len(snippets) != len(scanned.matches):
            return _publication_failure(
                file_outcome,
                scanned,
                requested_sources,
                PiFileFailureCategory.SNIPPET_JOIN_FAILED.value,
                stage,
            )

        results: list[dict[str, Any]] = []
        metadata_withheld = False
        for match, snippet in zip(scanned.matches, snippets, strict=True):
            row, withheld = _join_result(match, snippet)
            results.append(row)
            metadata_withheld = metadata_withheld or withheld
        # 授权核对（两条策略轴 + EOF 确认 + 遮蔽）全部通过后才发放不透明引用：结果行的
        # `location` 一律换成 `ctxref:` 随机串，行号/流标签不外出；版本来自同趟授权读取，
        # 拿不到完整版本就不发引用（宁零不半）。发放失败整批改走发布失败出口，不留半成品。
        version = file_outcome.version
        if version is None or not version.complete:
            return _publication_failure(
                file_outcome,
                scanned,
                requested_sources,
                PiFileFailureCategory.FILE_INCOMPLETE.value,
                PiFileStageReached.PUBLICATION,
            )
        ref_ledger = ledger if ledger is not None else default_ledger()
        service_key = service_binding_key(
            scope=scope, source=SOURCE_PI, path=path, session_id=session_id
        )
        try:
            tokens = _issue_references(
                [candidates[index] for index in indices],
                [mappings[match.record_index] for match in scanned.matches],
                version=version,
                service_key=service_key,
                scope=scope,
                path=path,
                session_id=session_id,
                ledger=ref_ledger,
            )
        except Exception:
            # 发放入口已按点名收回本批条目：这里不再整表清空，否则会把同一宿主里其他
            # 会话仍在使用的有效引用一起抹掉（那是拒绝面扩大，不是安全收益）。
            return _publication_failure(
                file_outcome,
                scanned,
                requested_sources,
                PiFileFailureCategory.INTERNAL_FAILURE.value,
                PiFileStageReached.PUBLICATION,
            )
        issued_tokens = tokens
        for row, token in zip(results, tokens, strict=True):
            row["location"] = token
        coverage = tuple(_finalize_pi_row(row.as_public_dict()) for row in scanned.coverage)
        if any(snippet.truncated for snippet in snippets):
            coverage = _annotate_pi_rows(
                coverage,
                PiFileFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value,
                _SNIPPET_TRUNCATION_NOTE,
            )
        if metadata_withheld:
            coverage = _annotate_pi_rows(
                coverage,
                PiFileFailureCategory.METADATA_WITHHELD.value,
                _METADATA_WITHHELD_NOTE,
            )
        coverage = _merge_coverage(coverage, requested_sources)
        # `published` 阶段词只在结果对象真正成形后写下：行组装/覆盖收尾/对象构造任一步抛错，
        # 外层失败出口都落在 `publication`，不会出现「阶段词已发布而结果为空」的矛盾快照。
        partial = not scanned.complete or any(row["partial"] for row in coverage)
        outcome = PiFileSearchOutcome(
            complete=file_outcome.complete and scanned.complete and not partial,
            partial=partial,
            truncated=scanned.truncated
            or any(snippet.truncated for snippet in snippets),
            total_matched=scanned.total_matched,
            total_scanned=scanned.total_scanned,
            skipped_records=scanned.skipped_records,
            results=tuple(results),
            coverage=coverage,
            file=file_outcome,
            stage_reached=PiFileStageReached.PUBLISHED.value,
        )
        stage = PiFileStageReached.PUBLISHED
        return outcome
    except (PolicyDenied, SafeReadDenied):
        raise
    except Exception:  # noqa: BLE001 - prevent unexpected exception details from reaching the tool
        # Fixed category only; never allow an exception message to carry path, query, or body.
        # 本批已发放而未被结果交出的令牌按点名收回：失败出口不在账本里留只能活到 TTL 的
        # 孤儿引用（`issued_tokens` 未赋值时为空元组，收回是空操作）。整表清空仍是被禁止的。
        with contextlib.suppress(BaseException):
            (ledger if ledger is not None else default_ledger()).release(issued_tokens)
        # `stage_reached` plus the nested `file` snapshot keep the layered counters honest: a
        # failure before the filter layer is "not judged by the filter layer", never "nothing was
        # read". When the file pipeline never returned a conclusion, the scope is `none`.
        category = PiFileFailureCategory.INTERNAL_FAILURE.value
        scope = COVERAGE_SCOPE_NONE if file_outcome is None else COVERAGE_SCOPE_FILE
        # 走到这里说明结果对象没有交出：局部 `stage` 若已被写成 `published`，在这里
        # 收敛到 `publication`——宁报低一层，不报「已发布而结果为空」。
        fail_stage = (
            PiFileStageReached.PUBLICATION
            if stage is PiFileStageReached.PUBLISHED
            else stage
        )
        row = _incomplete_coverage(
            records_withheld=len(candidates),
            category=category,
            file_outcome=file_outcome,
            coverage_scope=scope,
        )
        return PiFileSearchOutcome(
            complete=False,
            partial=True,
            truncated=False if scanned is None else scanned.truncated,
            total_matched=0,
            total_scanned=0,
            skipped_records=len(candidates),
            results=(),
            coverage=_merge_coverage((row,), requested_sources),
            file=file_outcome,
            reason=category,
            coverage_scope=scope,
            stage_reached=fail_stage.value,
            records_withheld=len(candidates),
            failure_category=category,
        )
    finally:
        # These contain the only raw StandardRecord/text and policy project map in this coordinator.
        candidates.clear()
        project_grants.clear()
        if collector is not None:
            with contextlib.suppress(BaseException):
                collector.discard(PublicationRefusal.NOT_CONFIRMED)


def _issue_references(
    records: Sequence[StandardRecord],
    projects: Sequence[str],
    *,
    version: FileVersion,
    service_key: str,
    scope: str,
    path: str,
    session_id: str,
    ledger: ReferenceLedger,
) -> tuple[str, ...]:
    """为已发布行发放不透明引用（只存元数据，不存正文），返回与 `rows` 同序的引用串。

    发放发生在两条策略轴、EOF 确认与遮蔽全部通过之后，因此引用绑定的就是本次已核对的事实：
    服务绑定指纹、范围/来源/会话/项目、记录在行流中的 `(line_no, ordinal, stream_label)`
    与同一次授权读取确立的文件版本。引用串本身不含任何位置或版本信息。

    上限 `MAX_ISSUE_PER_CALL` 在这里硬拦：超限直接拒（由调用方折算发布失败），不发放一批
    只能部分回指的引用。任一条失败都在收回**本批已发放条目**之后再抛：整表清空会误伤别的
    活跃引用，因此这里只按点名收回，调用方拿到异常时账本已回到发放前的状态。
    """
    if len(records) != len(projects):
        raise ValueError("reference issuance shape mismatch")
    if len(records) > MAX_ISSUE_PER_CALL:
        raise ValueError("reference issuance over limit")
    if not version.complete:
        raise ValueError("reference version incomplete")
    tokens: list[str] = []
    try:
        for record, project in zip(records, projects, strict=True):
            location = record.location
            if location is None:
                raise ValueError("reference record location unusable")
            tokens.append(
                ledger.issue(
                    service_key=service_key,
                    path=path,
                    scope=scope,
                    source=SOURCE_PI,
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
        # 半途失败只收回本批已发放的条目，不整表清空（那会误伤别的活跃引用）。
        ledger.release(tokens)
        raise
    return tuple(tokens)


def _public_key(value: str | None, limit: int) -> tuple[str | None, bool]:
    r"""短元数据出结果前的最后一道形态门：返回 `(可外出的值, 是否被拦下)`。

    上游已经做过长度/空白判（`_short_text`），但那套判据不禁路径形态：会话头部把文件路径写进
    `id` 时，一个形似 ``C:/Users/x`` 或 ``/a/b`` 的字符串会作为「会话标识」原样外出。本门采用
    与 ``models.sanitize_stream_label`` 同一取向的**整体判否**：只允许固定字符集（ASCII 字母数字
    与 ``-_.``），不以 ``.`` 起头，不截断不部分保留；含 ``/ \ :``、空白、盘符或非 ASCII 的值一律
    降 `None` 并标记为拦下（调用方据此把本来源记为覆盖不完整，而不是默默出示一个不像标识的值）。
    本来就缺失的 `None` 不算拦下：那是「没有这个值」，不是「有值但不能外出」。

    长度上限在此保留是为了让出口门自带界限，不依赖上游常量是否一直如此；非字符串与超长都按
    「有值但不能外出」处理（fail closed），不给它们开路。与 `location` 不同：这三个值来自不受控
    的会话文件，本门是它们第一次被按字符集判，所以不是重复检查。
    """
    if value is None:
        return None, False
    if not isinstance(value, str) or len(value) > limit or value.startswith("."):
        return None, True
    if not value or not set(value) <= _PUBLIC_KEY_SAFE_CHARS:
        return None, True
    return value, False


def _join_result(match: MatchRef, snippet: PublishedSnippet) -> tuple[dict[str, Any], bool]:
    """Join scanner metadata to the correspondingly ordered redacted snippet only.

    Returns ``(row, metadata_withheld)``. The three data-side identifier fields must pass the
    closed-form gate before publication; a session that stores a path where an identifier belongs
    is published as ``null`` with a ``metadata_withheld`` coverage marker instead of leaking that
    path. The row carries no line number or ordinal: the caller replaces ``location`` with the
    freshly issued opaque reference after whole-batch publication succeeds, and the internal
    coordinates only ever live in the ledger entry. Snippet bodies are redaction's channel, not
    this gate's.
    """
    session_id, held_session = _public_key(match.session_id, MAX_SESSION_ID_CHARS)
    role, held_role = _public_key(match.role, MAX_CALLER_KEY_CHARS)
    executor, held_executor = _public_key(match.executor, MAX_CALLER_KEY_CHARS)
    withheld = held_session or held_role or held_executor
    return (
        {
            "source": match.source,
            "session_id": session_id,
            "role": role,
            "executor": executor,
            "timestamp": match.timestamp,
            "time_quality": match.time_quality.value,
            "project": match.project,
            "project_quality": match.project_quality.value,
            "location": match.location,
            "snippet": snippet.snippet,
            "redacted_count": snippet.redacted_count,
            "snippet_truncated": snippet.truncated,
        },
        withheld,
    )


def _incomplete_coverage(
    *,
    records_withheld: int,
    category: str,
    file_outcome: PiFileOutcome | None,
    coverage_scope: str = COVERAGE_SCOPE_FILE,
) -> dict[str, Any]:
    """Gate-failure row: filter-layer counters are honestly zero, file-layer codes are carried.

    `records_scanned=0`/`scan_chars=0` describe only the query-filter layer (it judged nothing);
    the pipeline's own fixed reason codes (`ReadStop`, `StageDiscardReason`, `RefusalCode`) ride
    in `filter_errors`, and the real read/parse/stage counts stay in the nested `file` snapshot.
    All three vocabularies are closed enums; no data-side string is composed here.
    `coverage_scope` is `none` when the file pipeline never returned a conclusion at all.
    """
    errors = [category]
    if file_outcome is not None:
        for code in (
            None
            if file_outcome.read.reason is None
            or file_outcome.read.reason.value == "exhausted"
            else file_outcome.read.reason.value,
            None if file_outcome.pipeline.reason is None else file_outcome.pipeline.reason.value,
            None
            if file_outcome.attribution_refusal is None
            else file_outcome.attribution_refusal.value,
        ):
            if code is not None and code not in errors:
                errors.append(code)
    note = _CATEGORY_REASONS.get(category, _GENERIC_INCOMPLETE_NOTE)
    return {
        "source": SOURCE_PI,
        "coverage_scope": coverage_scope,
        "status": "incomplete",
        "matched_count": 0,
        "returned_count": 0,
        "records_scanned": 0,
        "skipped_count": records_withheld,
        "scan_chars": 0,
        "partial": True,
        "filter_errors": errors,
        "quality_issues": [],
        "reason": f"{note}{_LAYERED_COUNTER_NOTE}{_FILE_SCOPE_NOTE}",
    }


def _unsupported_coverage(source: str) -> dict[str, Any]:
    return {
        "source": source,
        "coverage_scope": COVERAGE_SCOPE_NONE,
        "status": "unsupported",
        "matched_count": 0,
        "returned_count": 0,
        "records_scanned": 0,
        "skipped_count": 0,
        "scan_chars": 0,
        "partial": True,
        "filter_errors": [PiFileFailureCategory.SOURCE_UNSUPPORTED.value],
        "quality_issues": [],
        "reason": (
            _CATEGORY_REASONS[PiFileFailureCategory.SOURCE_UNSUPPORTED.value]
            + _FILE_SCOPE_NOTE
        ),
    }


def _merge_coverage(
    pi_rows: Sequence[dict[str, Any]], requested_sources: Sequence[str]
) -> tuple[dict[str, Any], ...]:
    by_source = {row["source"]: row for row in pi_rows}
    for source in requested_sources:
        if source != SOURCE_PI:
            by_source[source] = _unsupported_coverage(source)
    return tuple(
        by_source[source] for source in SUPPORTED_SOURCES if source in by_source
    )


def _finalize_pi_row(row: dict[str, Any]) -> dict[str, Any]:
    """Tag a scanner-produced pi row with its true (file-level) coverage scope.

    A `no_match` here proves only that this single approved file was read to EOF, parsed,
    reconciled, and fully filtered; it never claims the whole `pi` source was scanned, which is
    what `completed_sources=(SOURCE_PI,)` means at this coordinator.
    """
    copy = dict(row)
    copy["coverage_scope"] = COVERAGE_SCOPE_FILE
    copy["reason"] = f"{copy['reason']}{_FILE_SCOPE_NOTE}"
    return copy


def _annotate_pi_rows(
    coverage: Sequence[dict[str, Any]], category: str, note: str
) -> tuple[dict[str, Any], ...]:
    """Mark pi rows partial with one closed category and one fixed note (deduplicated)."""
    updated: list[dict[str, Any]] = []
    for row in coverage:
        copy = dict(row)
        if copy["source"] == SOURCE_PI:
            copy["partial"] = True
            if copy["status"] == "no_match":
                copy["status"] = "incomplete"
            errors = list(copy["filter_errors"])
            if category not in errors:
                errors.append(category)
            copy["filter_errors"] = errors
            copy["reason"] = f"{copy['reason']}{note}"
        updated.append(copy)
    return tuple(updated)


def _publication_failure(
    file_outcome: PiFileOutcome,
    scanned: ScanFilterOutcome,
    requested_sources: Sequence[str],
    category: str,
    stage: PiFileStageReached,
) -> PiFileSearchOutcome:
    """Replace any partial join/redaction result with a fixed all-or-nothing coverage failure.

    The exact first refusal category (`PublicationRefusal` value or a join-failure category)
    stays visible in `failure_category` and in the pi row's `filter_errors`, while
    `matched_count` keeps the filter-layer diagnostic count and `returned_count`/`results` stay
    zero: matching is not publishing, and a non-zero match count here must never read as
    "results were released". No prefix is ever released; the whole batch is withheld.
    """
    rows = [_finalize_pi_row(row.as_public_dict()) for row in scanned.coverage]
    for row in rows:
        if row["source"] == SOURCE_PI:
            row["status"] = "error"
            row["matched_count"] = scanned.total_matched
            row["returned_count"] = 0
            row["partial"] = True
            errors = list(row["filter_errors"])
            for code in (PiFileFailureCategory.PUBLICATION_FAILED.value, category):
                if code not in errors:
                    errors.append(code)
            row["filter_errors"] = errors
            note = _PUBLICATION_REASONS.get(
                category, _PUBLICATION_REASONS[PublicationRefusal.NOT_CONFIRMED.value]
            )
            row["reason"] = f"{note}{_FILE_SCOPE_NOTE}"
    return PiFileSearchOutcome(
        complete=False,
        partial=True,
        truncated=scanned.truncated,
        total_matched=scanned.total_matched,
        total_scanned=scanned.total_scanned,
        skipped_records=scanned.skipped_records,
        results=(),
        coverage=_merge_coverage(rows, requested_sources),
        file=file_outcome,
        reason=PiFileFailureCategory.PUBLICATION_FAILED.value,
        stage_reached=stage.value,
        records_withheld=scanned.returned_count,
        failure_category=category,
    )
