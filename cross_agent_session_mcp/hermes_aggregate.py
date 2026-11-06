"""Hermes 来源的有界库集合聚合检索与 ctxref 发放（DES-ADAPTER-01 的协议接线，上半：检索面）。

本模块把已存在的 Hermes 单会话适配器（`sources/hermes.py`，宿主进程内 API）接进聚合层，回答两个
问题：**一批宿主批准的 Hermes 库文件里有哪些记录命中**，以及**命中之后如何发放只能回到本次批准
绑定的不透明引用**。判据与 pi 聚合（`session_discovery.py`）一致，取值口径按数据库来源重列：

- 集合由宿主注入的 `HermesStoreRef(store_path, session_id)` 列表构成，客户端永远传不进路径。
  本增量**不做目录遍历发现**：Hermes 的取数白名单里没有任何「枚举会话 id」的语句，凭空加一条 SQL
  就是把未经审的语句形状带进适配器（`whitelist_shape_problems()` 只自检既有形状）。存储根候选
  发现登记在 `docs/spec/09` 的剩余项里。
- 逐库读取走 `run_hermes_session(policy=,scope=,capture=)`：存储轴授权、身份、归属、行数账目与
  遮蔽前完整核验全部由适配器内部完成；未核验终态一条正文也不外递（该模块 `emit`/`finish` 口径）。
  适配器自己的 gate/access/withheld 计数原样进逐库行，本层不改写、不补解释。
- **文件版本证据的取得方式与 pi 不同，必须写清楚**：pi 的 `FileVersion` 来自同一次授权行读取
  （句柄身份 + 逐块累加摘要）。数据库对象没有行语义可搭这条链，且 `authorize_read` 的固定形态
  确证会把 SQLite 魔数直接拒为 `not_plain_text`，因此本模块用 `safe_reader.authorize_content_digest`
  在**同一个库对象上取两次整趟指纹**：一次在只读 SQL 快照之前、一次之后。三者（指纹 A、SQL 结论、
  指纹 B）的卷号/文件标识/体积/摘要必须逐项相等，任何不等即该库记为不完整、其候选不进全局记录表。
  这只是「同一对象在我读它的那段时间里没被换过」的有界证据，**不是事务快照**，也不宣称拿到了一致
  时刻的视图——这个差别登记给 DSH 与真机验证。指纹超预算（库太大）同样记不完整：宁可不发布，
  不发布半个指纹。
- 发布是两阶段的：先逐库片段收集判过（任一拒绝即整批零结果、无前缀——`SnippetCollector` 首拒即清
  自身前缀，在这里就是「整批或零条」的保证），全部通过才逐库释放并按**该库自己的绑定**发放 ctxref
  （`service_key/scope/path/session_id/版本` 全取该库的授权事实）。`matched_count` 只是诊断值：
  发布失败时它可以非零，而 `returned_count` 与 `results` 必须为零。
- 覆盖口径固定 `bounded_hermes_store_set`：无匹配只声明「本次绑定的有界库集合」扫完；任何一库不
  完整、指纹预算触顶、候选未进过滤层，都只能在 `partial` 与逐库行状态里可见，绝不以
  `complete=True` 宣称集合之外的结论（SRS-SEARCH-09）。

本模块不读任何配置、不探测磁盘、不接真实会话；对外字典只含固定键、整数、布尔、闭合枚举值与遮蔽
后的片段（DES-SEC-01）。返回值与日志都不含会话原文、查询词、时间原值、绝对路径或行号坐标。
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # 只供注解：运行期反向导入在本模块尾部按需进行，避开循环
    from .hermes_aggregate_context import HermesAggregateContextService

from .file_search import (
    _LAYERED_COUNTER_NOTE,
    _METADATA_WITHHELD_NOTE,
    _SNIPPET_TRUNCATION_NOTE,
    COVERAGE_SCOPE_FILE,
    COVERAGE_SCOPE_NONE,
    _join_result,
    _public_key,
)
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
    LIMIT_MAX,
    MAX_SESSION_ID_CHARS,
    MAX_TOTAL_SCAN_CHARS,
    SUPPORTED_SOURCES,
    FilterErrorCode,
    MatchRef,
    ScanFilterOutcome,
    scan_filter,
)
from .references import (
    MAX_ISSUE_PER_CALL,
    ReferenceLedger,
    ReferenceRecord,
    default_ledger,
    service_binding_key,
)
from .safe_reader import FileVersion, SafeReadDenied, authorize_content_digest
from .session_stage import MAX_CANDIDATES_HARD_LIMIT, _comparable_key
from .sources.hermes import (
    DEFAULT_STAGE_BYTES,
    SOURCE_HERMES,
    HermesSessionOutcome,
    run_hermes_session,
)

# ---- 口径与上限 ----

#: Hermes 聚合的覆盖声明口径：只有本次绑定的有界库集合，永不升格为「hermes 来源已扫完」。
COVERAGE_SCOPE_MULTI_HERMES = "bounded_hermes_store_set"

#: 一次查询最多绑定的库数；超出即拒绝整次请求，不截断集合（截断会伪装成「扫完」）。
MAX_STORES_PER_QUERY = 16

#: 全查询片段硬上限（与 pi 聚合同一条 32 上限，按**全查询**计）。
MAX_HERMES_AGGREGATE_SNIPPETS = MAX_SNIPPETS_HARD_LIMIT

#: 全查询指纹预算：每库两次整趟摘要都算在这条额度上，触顶即后续库跳过并记不完整。
MAX_HERMES_AGGREGATE_DIGEST_BYTES = 32 * 1024 * 1024

#: 单库单趟指纹的字节上限：超出即 `complete=False`，该库永不发布（半程指纹不得当整流指纹用）。
MAX_HERMES_STORE_DIGEST_BYTES = 8 * 1024 * 1024

#: 预算低于这条值就不再尝试打开任何库（与 pi 聚合的 `_MIN_READ_BUDGET` 同一取向）。
_MIN_DIGEST_BUDGET = 16

#: 单库行数上限：活跃行超过这条值即判超大，该库不发布而记 `over_size`（09 裁决 P3）。
#: 判据取 `plan.row_count`（SQL 端活跃行总数）与实取候选条数的较大者，因此它不是「候选条数
#: 上限」——`MAX_CANDIDATES_HARD_LIMIT`（100）与来源侧 `MAX_ROWS_PER_SESSION`（21）管的是取数量，
#: 本条管的是一个库里到底堆了多少行：`row_count` 可以远大于两者而候选仍被截到 21 条。
#: **默认值待校准**：需要真实 Hermes state.db 的分库行数分布才能定得准，本轮受任务约束未访问
#: 真实库，因此这是一个保守上界（宁可少报超大，不可把正常库误判成超大）。校准时只应往下收紧，
#: 且必须同时确认它不与 `MAX_CANDIDATES_HARD_LIMIT` 冲突。
MAX_HERMES_STORE_ROWS = 2_000

#: 超大库的行级原因码。不进 `HermesAggregateFailureCategory`（那是闭合顶层类别集合，本增量
#: 不扩枚举）：`over_size` 只逐库外显在 `stores[].reason`，与同层的 `attribution_denied`、
#: `session_identity_conflict` 同一形状。它也不是 `read_budget_exhausted`：前者是「这库本身
#: 超出可核对上限」，后者是「本轮预算先花完了」，诊断上必须可区分。
_OVER_SIZE_REASON = "over_size"

#: 单库正文暂存预算：只收紧适配器默认值，不放宽。
HERMES_STORE_STAGE_BYTES = DEFAULT_STAGE_BYTES

#: 单库正文总字符预算：比适配器上限更紧——聚合是全查询口径，单库不得吃满。
HERMES_STORE_TEXT_CHARS = 16_384

#: 协议层 limit 上限（与 pi 聚合同一取值）。
MAX_PROTOCOL_LIMIT = LIMIT_MAX

#: 全查询扫描字符上限（过滤层）。
MAX_HERMES_AGGREGATE_SCAN_CHARS = MAX_TOTAL_SCAN_CHARS

_MULTI_HERMES_SCOPE_NOTE = (
    "覆盖范围仅限本次绑定的有界 Hermes 库集合，不声明 hermes 来源整体已扫完。"
)

_STORES_UNUSABLE_NOTE = (
    "绑定的库集合没有任何库通过完整核对与指纹一致性判定；聚合未发布结果，零结果不等于无匹配。"
)

_QUOTA_NOTE = "片段配额或全查询返回上限裁掉了部分命中；returned_count 是实际发布行数。"

_INTERNAL_NOTE = (
    "聚合协调器内部失败；本库集合未发布结果，分层计数只在已取到的结论上给出。"
)

_PUBLICATION_NOTE = "遮蔽、接线或发放环节失败，整批未发布（零结果，不是前缀）。"

_NO_FILTER_ROW_NOTE = (
    "本次聚合没有可解释的过滤层逐来源行；分层计数只在已取到的结论上给出。"
)

#: 发布失败细类各自的固定句子（按 `PublicationRefusal` 取，不拼接派生值）。
_PUBLICATION_CATEGORY_NOTES: dict[str, str] = {
    PublicationRefusal.REDACTION_REJECTED.value: (
        "遮蔽核对判定该片段不可外用，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.SNIPPET_LIMIT_EXCEEDED.value: (
        "片段数超上限，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED.value: (
        "片段总字符超上限，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.RECORD_UNUSABLE.value: (
        "命中记录形态不可外用，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.NOT_CONFIRMED.value: "发布未经确认，整批未发布（零结果，不是前缀）。",
    PublicationRefusal.INTERNAL_FAILURE.value: (
        "发布环节内部失败，整批未发布（零结果，不是前缀）。"
    ),
}


# ---- 闭合类别 ----


class HermesAggregateFailureCategory(StrEnum):
    """聚合检索的闭合失败类别（比 pi 聚合多一条数据库来源特有的指纹类别）。"""

    SCOPE_MISMATCH = "scope_mismatch"
    SOURCE_UNSUPPORTED = "source_unsupported"
    INVALID_REQUEST = "invalid_request"
    FILE_INCOMPLETE = "file_incomplete"
    READ_BUDGET_EXHAUSTED = "read_budget_exhausted"
    STORES_UNUSABLE = "stores_unusable"
    INTERNAL_FAILURE = "internal_failure"
    PUBLICATION_FAILED = "publication_failed"
    MATCH_JOIN_FAILED = "match_join_failed"
    SNIPPET_JOIN_FAILED = "snippet_join_failed"
    SNIPPET_OUTPUT_TRUNCATED = "snippet_output_truncated"
    METADATA_WITHHELD = "metadata_withheld"
    VERSION_UNSTABLE = "version_unstable"
    REFERENCE_ISSUE_FAILED = "reference_issue_failed"


class HermesAggregateStageReached(StrEnum):
    """本次聚合最远走到哪一层；只说明「走到哪」，不说明那一层是否通过。"""

    COORDINATOR = "coordinator"
    STORE_READ = "store_read"
    FILTER = "filter"
    PUBLICATION = "publication"
    PUBLISHED = "published"


class _StoreRowStatus(StrEnum):
    """逐库行的四种状态；`incomplete`/`skipped_budget` 都是「没读全」，不是「没有」。"""

    READ = "read"
    INCOMPLETE = "incomplete"
    REFUSED = "refused"
    SKIPPED_BUDGET = "skipped_budget"


class _FilterErrorTag(StrEnum):
    """聚合层自己追加的错误标签（过滤层细类由 `query` 行自带，本层不复制也不解释）。"""

    SOURCE_NOT_SCANNED = "source_not_scanned"
    READ_BUDGET_EXHAUSTED = "read_budget_exhausted"
    STORES_UNUSABLE = "stores_unusable"
    PUBLICATION_FAILED = "publication_failed"
    VERSION_UNSTABLE = "version_unstable"


_AGGREGATE_CATEGORY_REASONS: dict[str, str] = {
    HermesAggregateFailureCategory.SCOPE_MISMATCH: (
        "拒绝：请求的 scope 与已绑定的授权范围不一致，本次未打开任何库。"
    ),
    HermesAggregateFailureCategory.SOURCE_UNSUPPORTED: "拒绝：已绑定的聚合服务不查询该来源。",
    HermesAggregateFailureCategory.INVALID_REQUEST: (
        "拒绝：请求形态不合法，本次未打开任何库。"
    ),
    HermesAggregateFailureCategory.FILE_INCOMPLETE: (
        "覆盖不完整：至少一个库未通过完整核对，零结果不等于无匹配。"
    ),
    HermesAggregateFailureCategory.READ_BUDGET_EXHAUSTED: (
        "覆盖不完整：指纹或候选预算触顶，后续库未打开。"
    ),
    HermesAggregateFailureCategory.STORES_UNUSABLE: (
        "覆盖不完整：没有任何库通过完整核对与指纹一致性判定，整批未发布（零结果，不是前缀）。"
    ),
    HermesAggregateFailureCategory.INTERNAL_FAILURE: _INTERNAL_NOTE,
    HermesAggregateFailureCategory.PUBLICATION_FAILED: _PUBLICATION_NOTE,
    HermesAggregateFailureCategory.MATCH_JOIN_FAILED: (
        "拒绝：命中与记录、片段或项目映射的接线不一致，整批未发布（零结果，不是前缀）。"
    ),
    HermesAggregateFailureCategory.SNIPPET_JOIN_FAILED: (
        "拒绝：释放片段数与命中位置数不等，整批未发布（零结果，不是前缀）。"
    ),
    HermesAggregateFailureCategory.SNIPPET_OUTPUT_TRUNCATED: _SNIPPET_TRUNCATION_NOTE,
    HermesAggregateFailureCategory.METADATA_WITHHELD: _METADATA_WITHHELD_NOTE,
    HermesAggregateFailureCategory.VERSION_UNSTABLE: (
        "同一库在只读快照前后的内容指纹不一致或指纹不完整，无法确立版本；该库整批不发布。"
    ),
    HermesAggregateFailureCategory.REFERENCE_ISSUE_FAILED: (
        "拒绝：引用发放未完成，整批未发布（零结果，不是前缀）。"
    ),
}


# ---- 绑定形态 ----


@dataclass(frozen=True)
class HermesStoreRef:
    """宿主注入的一个绑定项：一个 Hermes 库文件 + 该库内断言的会话标识。

    `store_path` 是**待授权**的写法（绝对路径字符串），不是授权凭据：每一次指纹与每一次读取都由
    策略层当场判定。`session_id` 必须通过封闭白名单形态门（不含分隔符/空白/盘符/前导点），否则
    构造即拒绝——身份断言不可外用，聚合就没有可比对的锚，发放引用也就没有可核对的会话轴。
    """

    store_path: str
    session_id: str

    def __post_init__(self) -> None:
        if self.store_path.__class__ is not str or not self.store_path:
            raise ValueError("HermesStoreRef.store_path must be a non-empty str")
        if self.session_id.__class__ is not str or not self.session_id:
            raise ValueError("HermesStoreRef.session_id must be a non-empty str")
        if _public_key(self.session_id, MAX_SESSION_ID_CHARS)[0] is None:
            raise ValueError("HermesStoreRef.session_id is not a publishable identifier")


@dataclass
class _StoreSegment:
    """一个绑定库在本轮聚合内的中间事实：内部对象，绝不外递（路径只留在绑定与账本内部）。"""

    index: int
    ref: HermesStoreRef
    status: _StoreRowStatus
    outcome: HermesSessionOutcome | None = None
    reason: str | None = None
    version: FileVersion | None = None
    records: list[StandardRecord] = field(default_factory=list)
    projects: list[str] = field(default_factory=list)
    base: int = 0
    kept_local: list[int] = field(default_factory=list)
    skipped_tail: int = 0
    snippets: tuple[PublishedSnippet, ...] = ()
    tokens: list[str] = field(default_factory=list)
    digest_bytes: int = 0


# ---- 对外结果 ----


@dataclass(frozen=True)
class HermesAggregateSearchOutcome:
    """一次聚合检索的对外结果：固定键、整数、布尔、闭合枚举值与遮蔽后的片段，没有别的通道。

    分层计数是本类的核心口径：`total_matched`/行内 `matched_count` 是**过滤层判定**，发布失败时
    它们可以非零，而 `returned_count` 与 `results` 必须为零；`skipped_records`/`records_withheld`
    是「本层没扫到/被扣住」的量，不等于「没有」。
    """

    complete: bool
    partial: bool
    truncated: bool
    total_matched: int
    total_scanned: int
    skipped_records: int
    results: tuple[dict[str, object], ...]
    coverage: tuple[dict[str, object], ...]
    stores: tuple[dict[str, object], ...]
    rejected: bool = False
    reason: str | None = None
    coverage_scope: str = COVERAGE_SCOPE_MULTI_HERMES
    stage_reached: str = HermesAggregateStageReached.COORDINATOR.value
    records_withheld: int = 0
    failure_category: str | None = None

    @property
    def returned_count(self) -> int:
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
            "results": [dict(row) for row in self.results],
            "coverage": [dict(row) for row in self.coverage],
            "stores": [dict(row) for row in self.stores],
        }


# ---- 内部行装配 ----


def _rejected_outcome(reason: str, *, stage: str) -> HermesAggregateSearchOutcome:
    """拒绝态统一出口：整次请求零结果、零覆盖行，`rejected=True`（这不是「无匹配」）。"""

    return HermesAggregateSearchOutcome(
        complete=False,
        partial=True,
        truncated=False,
        total_matched=0,
        total_scanned=0,
        skipped_records=0,
        results=(),
        coverage=(),
        stores=(),
        rejected=True,
        reason=reason,
        coverage_scope=COVERAGE_SCOPE_NONE,
        stage_reached=stage,
        records_withheld=0,
        failure_category=reason,
    )


def _store_row(segment: _StoreSegment) -> dict[str, object]:
    """逐库行：只出序号、状态、整数与适配器自己的结论；路径与会话 id 永远不在这一行里。"""

    row: dict[str, object] = {
        "index": segment.index,
        "status": segment.status.value,
        "coverage_scope": COVERAGE_SCOPE_FILE,
        "records_captured": len(segment.records),
        "filter_scanned": 0,
        "filter_skipped": 0,
        "returned_count": 0,
        "digest_bytes": segment.digest_bytes,
        "reason": segment.reason,
        "store": segment.outcome.as_public_dict() if segment.outcome is not None else None,
    }
    return row


def _incomplete_hermes_row(reason_note: str, *, category: str) -> dict[str, object]:
    """没有过滤层结论时的诚实行：matched/returned/scanned 全零，缺口只走 partial 与标签。"""

    return {
        "source": SOURCE_HERMES,
        "coverage_scope": COVERAGE_SCOPE_MULTI_HERMES,
        "status": "incomplete",
        "matched_count": 0,
        "returned_count": 0,
        "records_scanned": 0,
        "skipped_count": 0,
        "scan_chars": 0,
        "partial": True,
        "filter_errors": [category],
        "quality_issues": [],
        "reason": f"{reason_note}{_LAYERED_COUNTER_NOTE}{_MULTI_HERMES_SCOPE_NOTE}",
    }


def _merge_filter_row(
    scanned: ScanFilterOutcome, *, partial_flags: bool, reason_note: str
) -> dict[str, object]:
    """取过滤层的 hermes 行并按聚合口径改注覆盖声明；没有该行时回落到诚实的 incomplete 行。"""

    for row in scanned.coverage:
        if row.source != SOURCE_HERMES:
            continue
        public = row.as_public_dict()
        public["coverage_scope"] = COVERAGE_SCOPE_MULTI_HERMES
        public["partial"] = bool(public["partial"]) or partial_flags
        if reason_note:
            public["reason"] = f"{public['reason']}{reason_note}"
        return public
    return _incomplete_hermes_row(
        _NO_FILTER_ROW_NOTE, category=_FilterErrorTag.SOURCE_NOT_SCANNED.value
    )


def _unsupported_row(source: str) -> dict[str, object]:
    """点名但未绑定的来源：诚实的 unsupported 行，零扫描零返回。"""

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
        "filter_errors": ["source_unsupported"],
        "quality_issues": [],
        "reason": (
            f"已绑定的聚合服务只查询有界 Hermes 库集合。{_MULTI_HERMES_SCOPE_NOTE}"
        ),
    }


def _merged_coverage(
    hermes_row: dict[str, object], requested_sources: Sequence[str]
) -> tuple[dict[str, object], ...]:
    """hermes 行 + 每个点名未支持来源各一行，按 `query.SUPPORTED_SOURCES` 的固定顺序排列。"""

    rows: dict[str, dict[str, object]] = {SOURCE_HERMES: dict(hermes_row)}
    for source in requested_sources:
        if source != SOURCE_HERMES and source not in rows:
            rows[source] = _unsupported_row(source)
    order = {name: position for position, name in enumerate(SUPPORTED_SOURCES)}
    return tuple(
        rows[name]
        for name in sorted(rows, key=lambda item: (order.get(item, len(order)), item))
    )


def _row_tags(row: dict[str, object], key: str) -> list[str]:
    """读回行内的标签列表：只承认字符串元素，其它形态一律丢弃（不猜、不回显）。"""

    value = row.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, str)]


def _annotate_hermes_rows(
    coverage: Sequence[dict[str, object]], category: str, note: str
) -> None:
    """就地给 hermes 行叠加类别与注记（其它来源的行不动）。"""

    for row in coverage:
        if row.get("source") != SOURCE_HERMES:
            continue
        row["partial"] = True
        if row["status"] == "no_match":
            row["status"] = "incomplete"
        errors = _row_tags(row, "filter_errors")
        if category not in errors:
            errors.append(category)
        row["filter_errors"] = errors
        row["reason"] = f"{row.get('reason', '')}{note}"


# ---- 版本与引用 ----


def _versions_agree(left: FileVersion | None, right: FileVersion | None) -> bool:
    """四项逐项相等：卷号、文件标识、体积、同趟摘要；任一方不完整即视为不等。"""

    if left is None or right is None:
        return False
    if not left.complete or not right.complete:
        return False
    return (
        left.volume == right.volume
        and left.file_id == right.file_id
        and left.size_bytes == right.size_bytes
        and left.content_sha256 == right.content_sha256
    )


def _entry_matches_version(
    entry: ReferenceRecord, version: FileVersion | None
) -> bool:
    """账本指纹与本次指纹逐项相等（上下文读取用）；缺指纹或不完整即不等。"""

    if version is None or not version.complete:
        return False
    return (
        entry.volume == version.volume
        and entry.file_id == version.file_id
        and entry.size_bytes == version.size_bytes
        and entry.content_sha256 == version.content_sha256
    )


def _hermes_service_key(
    *, scope: str, ref: HermesStoreRef
) -> str:
    """绑定键：scope + 来源 + 该库路径 + 该库内断言的会话 id，逐项长度前缀编码后取摘要。"""

    return service_binding_key(
        scope=scope,
        source=SOURCE_HERMES,
        path=ref.store_path,
        session_id=ref.session_id,
    )


def _hermes_binding_problems(
    entry: ReferenceRecord,
    *,
    service_key: str,
    session_id: str | None,
    project_filter: str | None,
) -> str | None:
    """引用绑定的三项当场核对：服务绑定、会话断言、项目声明；任一项不合即返回固定标签。"""

    if entry.service_key != service_key or entry.source != SOURCE_HERMES:
        return "service_binding"
    if session_id is not None and _comparable_key(session_id) != _comparable_key(
        entry.session_id
    ):
        return "session_binding"
    if project_filter is not None and project_filter != entry.project:
        return "project_binding"
    return None


def _issue_hermes_references(
    records: Sequence[StandardRecord],
    projects: Sequence[str | None],
    *,
    version: FileVersion,
    service_key: str,
    scope: str,
    path: str,
    session_id: str,
    ledger: ReferenceLedger,
) -> tuple[str, ...]:
    """为已确认发布的记录逐条发放 ctxref；任何一条发不出就回收已发的并整体失败。

    与 `file_search._issue_references` 同一判据（形状不符、超单次上限、版本不完整、位置不可用都
    先拒再发），差别只有 `source=SOURCE_HERMES`：坐标是 `messages.id` 与固定 ordinal 0，
    `stream_label` 是该库的标签，全部只进账本，不进对外行。
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
                    source=SOURCE_HERMES,
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
        ledger.release(tuple(tokens))
        raise
    return tuple(tokens)


# ---- 逐库读取 ----


class _CaptureSink:
    """适配器终态合格后才交出正文的接收器；返回拒绝码即让适配器停下（首拒即停）。"""

    __slots__ = ("failed", "records")

    def __init__(self) -> None:
        self.failed = False
        self.records: list[StandardRecord] = []

    def __call__(self, record: StandardRecord) -> str | None:
        try:
            self.records.append(record)
        except MemoryError:
            self.failed = True
            return PublicationRefusal.INTERNAL_FAILURE.value
        return None


def _digest_store(
    policy: SessionPolicy, scope: str, ref: HermesStoreRef, budget: int
) -> FileVersion:
    """单趟指纹：授权、打开前基准、句柄身份与落点再授权都在 `authorize_content_digest` 内。"""

    return authorize_content_digest(
        policy,
        scope,
        SOURCE_HERMES,
        ref.store_path,
        max_total_bytes=min(MAX_HERMES_STORE_DIGEST_BYTES, budget),
    )


def _refusal_code(denial: PolicyDenied | SafeReadDenied) -> str:
    """两类安全拒绝的固定码取值口（枚举本身是闭合的，不回显消息文本）。"""

    code = getattr(denial, "code", None)
    value = getattr(code, "value", None)
    return value if isinstance(value, str) else "refused"


def _store_projects(
    policy: SessionPolicy,
    scope: str,
    records: Sequence[StandardRecord],
    requested_project: str | None,
) -> list[str]:
    """发布层的归属映射：逐条重新走策略层**归属轴**，取授权后的项目名。

    适配器已经逐条核对过归属（`_policy_admit`），这里不是复用那个结论而是**再判定一次**：
    存储轴授权只说明这个库可读，项目名只能来自 `authorize_attribution` 的授权结果。任何一条
    在本层被拒或形态不合，调用方就把该库整体记为不完整——不做「丢掉几条继续」的部分发布。

    用户请求的收窄项目（`requested_project`）在这里**只用于记录可解析性**（能否归到某个已
    授权根），绝不作为过滤谓词下传：命中裁剪归 `scan_filter(project=...)` 承担（09 裁决
    P2-2，对齐 pi 侧 `_search_pi_files` 只在 preflight 用项目）。下传会把「本次查询不命中的
    合法项目库」误报成 `attribution_denied`/不完整——未批准的项目名会先在
    `authorize_attribution` 的 `_check_project` 抛 `PROJECT_UNKNOWN`，合法的另一项目名会抛
    `project_mismatch`，两条都塌成整库不可用：多项目库集合按任一项目收窄时永远拿不到
    `complete=true`。形参保留以维持调用点形状与审计痕迹。
    """

    del requested_project  # 语义已移交过滤层；此处刻意不读该值。
    projects: list[str] = []
    for record in records:
        claimed = record.project
        if claimed is None:
            return []
        try:
            grant = policy.authorize_attribution(scope, str(claimed), project=None)
        except PolicyDenied:
            return []
        name, _held = _public_key(grant.project, MAX_SESSION_ID_CHARS)
        if name is None:
            return []
        projects.append(name)
    return projects


def _read_one_store(
    *,
    policy: SessionPolicy,
    scope: str,
    ref: HermesStoreRef,
    requested_project: str | None,
    digest_bytes_left: int,
) -> _StoreSegment:
    """一个库的完整读取：指纹 A → 只读 SQL 快照 → 指纹 B，三者一致才给出版本证据。

    任何一步被策略层或安全读取拒绝、指纹不等或不完整，都只写成该库的行状态并把候选清空：本层不
    把单库失败解释成来源级结论，也不把「没读到」写成「没有」。
    """

    segment = _StoreSegment(index=0, ref=ref, status=_StoreRowStatus.INCOMPLETE)
    budget = min(digest_bytes_left, MAX_HERMES_STORE_DIGEST_BYTES)
    if budget < _MIN_DIGEST_BUDGET:
        segment.status = _StoreRowStatus.SKIPPED_BUDGET
        segment.reason = _FilterErrorTag.READ_BUDGET_EXHAUSTED.value
        return segment

    try:
        before = _digest_store(policy, scope, ref, budget)
    except (PolicyDenied, SafeReadDenied) as denial:
        segment.status = _StoreRowStatus.REFUSED
        segment.reason = _refusal_code(denial)
        return segment
    segment.digest_bytes += before.size_bytes

    # 单库体积超 digest 上限（非并发修改）：早退，省掉整库 SQL 与第二趟指纹，并把真实原因
    # 外显为 over_size，而不是误报 version_unstable（09 裁决 P3）。`authorize_content_digest`
    # 预算用尽而未确立 EOF 时只返回 `complete=False`（半程摘要不得当整流指纹用），永不抛异常，
    # 旧法会照旧跑完 SQL 再跑第二趟，最后因两趟截断指纹/体积不等报 `version_unstable`——那是
    # 「这库太大」被写成「这库在并发修改」，误导诊断且浪费一次整库 SQL + 一趟整库指纹。
    # 取「指纹不完整」而非「先 `os.fstat` 拿真实体积」作为判据（复审提到的替代方案，本层不采用，
    # 已登记取舍）：fstat 与后续指纹之间存在替换竞态窗口，且绕开 `safe_reader` 授权句柄身份链，
    # 与 DES-SEC-01 冲突。
    if not before.complete:
        segment.status = _StoreRowStatus.INCOMPLETE
        segment.reason = _OVER_SIZE_REASON
        return segment

    sink = _CaptureSink()
    # 项目收窄不下传来源适配器（09 裁决 P2-2）：来源侧只做存储轴 + 归属轴 + 会话身份，
    # 命中裁剪归过滤层。旧下传把合法的非命中项目记成归属拒绝。`run_hermes_session` 的
    # `project_filter` 形参保留不动（`sources/hermes.py` 自有测试仍按旧形状走）。
    outcome = run_hermes_session(
        path=ref.store_path,
        session_id=ref.session_id,
        scope=scope,
        policy=policy,
        capture=sink,
        max_bytes=HERMES_STORE_STAGE_BYTES,
        max_text_chars=HERMES_STORE_TEXT_CHARS,
    )
    segment.outcome = outcome

    # 行级硬上限（09 裁决 P3）：来源侧的 21 行上限只约束**取进内存的候选条数**，本层因此自持
    # `MAX_HERMES_STORE_ROWS` 作为单库体量上限——tool 行与不认形态的行不进候选，一个活跃行远超
    # 上限的库完全可能在候选侧一路绿灯，不检查就会把「只读到前 21 行」伪装成整库可读。
    # 判据取 SQL 端活跃行总数与实交条数的较大者，两者都不超即不判超大（`_empty_plan` 的
    # row_count=0 不会误伤：探测未得出结论时宁可落回原有 gate 原因）。
    # 超上限时整库候选清空而不发前缀：`sink.records` 最多是一条被截断的前缀，部分接收会伪装成
    # 完整覆盖（与本函数其余不完整分支同口径）；这里的「静默截断」因此只保留到原因外显。
    # 位置在第二趟指纹之前：超限已定性，再读一遍整库只浪费预算。
    if max(outcome.plan.row_count, len(sink.records)) > MAX_HERMES_STORE_ROWS:
        segment.status = _StoreRowStatus.INCOMPLETE
        segment.reason = _OVER_SIZE_REASON
        sink.records.clear()
        return segment

    after_budget = max(_MIN_DIGEST_BUDGET, budget - before.size_bytes)
    try:
        after = _digest_store(policy, scope, ref, after_budget)
    except (PolicyDenied, SafeReadDenied) as denial:
        segment.status = _StoreRowStatus.REFUSED
        segment.reason = _refusal_code(denial)
        sink.records.clear()
        return segment
    segment.digest_bytes += after.size_bytes

    if sink.failed:
        segment.status = _StoreRowStatus.INCOMPLETE
        segment.reason = HermesAggregateFailureCategory.INTERNAL_FAILURE.value
        sink.records.clear()
        return segment
    if not outcome.complete:
        # 适配器自己的终态不合：gate 是闭合类别，原样写进行原因，不改写成「无匹配」。
        segment.status = _StoreRowStatus.INCOMPLETE
        segment.reason = outcome.gate.value
        sink.records.clear()
        return segment
    if not _versions_agree(before, after):
        segment.status = _StoreRowStatus.INCOMPLETE
        segment.reason = HermesAggregateFailureCategory.VERSION_UNSTABLE.value
        sink.records.clear()
        return segment

    records = list(sink.records)
    sink.records.clear()
    projects = _store_projects(policy, scope, records, requested_project)
    if len(projects) != len(records):
        # 归属映射在本层被拒：该库整体不进过滤层（部分接收会伪装成完整覆盖）。
        segment.status = _StoreRowStatus.INCOMPLETE
        segment.reason = "attribution_denied"
        return segment

    segment.version = before
    segment.records = records
    segment.projects = projects
    segment.status = _StoreRowStatus.READ
    segment.reason = None
    return segment


def _hermes_read_store(
    policy: SessionPolicy,
    scope: str,
    ref: HermesStoreRef,
    requested_project: str | None,
) -> tuple[list[StandardRecord], list[str], FileVersion | None, str | None]:
    """上下文重读的共用口：一次完整读取的候选、归属、版本证据与固定失败标签。

    检索侧与上下文侧必须走同一套「指纹 A → 只读快照 → 指纹 B → 归属再判定」，否则两条路径对
    「已核对」的定义会分叉。失败时返回空集合与一个闭合标签（不携带路径、正文或原始错误）。
    """

    segment = _read_one_store(
        policy=policy,
        scope=scope,
        ref=ref,
        requested_project=requested_project,
        digest_bytes_left=MAX_HERMES_AGGREGATE_DIGEST_BYTES,
    )
    if segment.status is not _StoreRowStatus.READ:
        reason = segment.reason or segment.status.value
        segment.records = []
        segment.projects = []
        return [], [], None, reason
    version = segment.version
    records = list(segment.records)
    projects = list(segment.projects)
    segment.records = []
    segment.projects = []
    return records, projects, version, None


# ---- 聚合检索 ----


def _aggregate_failure(
    segments: Sequence[_StoreSegment],
    scanned: ScanFilterOutcome | None,
    requested_sources: Sequence[str],
    category: str,
    stage: str,
) -> HermesAggregateSearchOutcome:
    """发布/接线失败：整批零结果、零返回；`matched_count` 留在行里只作诊断。"""

    note = _AGGREGATE_CATEGORY_REASONS.get(category, _PUBLICATION_NOTE)
    if scanned is None:
        row = _incomplete_hermes_row(note, category=category)
    else:
        row = _merge_filter_row(scanned, partial_flags=True, reason_note="")
    row["status"] = "error"
    row["matched_count"] = scanned.total_matched if scanned is not None else 0
    row["returned_count"] = 0
    row["partial"] = True
    errors = _row_tags(row, "filter_errors")
    for tag in (_FilterErrorTag.PUBLICATION_FAILED.value, category):
        if tag not in errors:
            errors.append(tag)
    row["filter_errors"] = errors
    row["reason"] = (
        f"{_PUBLICATION_NOTE}{note}{_LAYERED_COUNTER_NOTE}{_MULTI_HERMES_SCOPE_NOTE}"
    )
    coverage = _merged_coverage(row, requested_sources)
    store_rows: list[dict[str, object]] = []
    for segment in segments:
        frow = _store_row(segment)
        frow["returned_count"] = 0
        if frow["status"] == _StoreRowStatus.READ.value and segment.kept_local:
            frow["reason"] = category
        store_rows.append(frow)
    return HermesAggregateSearchOutcome(
        complete=False,
        partial=True,
        truncated=False,
        total_matched=scanned.total_matched if scanned is not None else 0,
        total_scanned=scanned.total_scanned if scanned is not None else 0,
        skipped_records=scanned.skipped_records if scanned is not None else 0,
        results=(),
        coverage=coverage,
        stores=tuple(store_rows),
        coverage_scope=COVERAGE_SCOPE_MULTI_HERMES,
        stage_reached=(
            HermesAggregateStageReached.PUBLICATION.value
            if stage == HermesAggregateStageReached.PUBLISHED.value
            else stage
        ),
        records_withheld=scanned.returned_count if scanned is not None else 0,
        failure_category=category,
        reason=HermesAggregateFailureCategory.PUBLICATION_FAILED.value,
    )


def _search_hermes_stores(
    service: HermesAggregateSearchService,
    *,
    query: str | None,
    sources: Sequence[str] | None,
    start: datetime | None,
    end: datetime | None,
    project: str | None,
    limit: int,
) -> HermesAggregateSearchOutcome:
    """全量有界暂存 → 单次过滤 → 两阶段发布 → 逐库发放引用；任何一环失败即整批零结果。"""

    scope = service.scope
    policy = service.policy
    stores = service.stores
    requested_sources: tuple[str, ...] = (SOURCE_HERMES,) if sources is None else tuple(sources)

    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_PROTOCOL_LIMIT
    ):
        return _rejected_outcome(
            HermesAggregateFailureCategory.INVALID_REQUEST.value,
            stage=HermesAggregateStageReached.COORDINATOR.value,
        )

    preflight = scan_filter(
        (),
        query=query,
        start=start,
        end=end,
        project=project,
        sources=requested_sources,
        limit=min(limit, MAX_HERMES_AGGREGATE_SNIPPETS),
    )
    if preflight.rejected:
        return _rejected_outcome(
            preflight.reason.value
            if preflight.reason is not None
            else HermesAggregateFailureCategory.INVALID_REQUEST.value,
            stage=HermesAggregateStageReached.COORDINATOR.value,
        )
    if SOURCE_HERMES not in requested_sources:
        row = _incomplete_hermes_row(
            _AGGREGATE_CATEGORY_REASONS[
                HermesAggregateFailureCategory.SOURCE_UNSUPPORTED
            ],
            category=HermesAggregateFailureCategory.SOURCE_UNSUPPORTED.value,
        )
        return HermesAggregateSearchOutcome(
            complete=False,
            partial=True,
            truncated=False,
            total_matched=0,
            total_scanned=0,
            skipped_records=0,
            results=(),
            coverage=_merged_coverage(row, requested_sources),
            stores=(),
            reason=HermesAggregateFailureCategory.SOURCE_UNSUPPORTED.value,
            coverage_scope=COVERAGE_SCOPE_NONE,
            stage_reached=HermesAggregateStageReached.COORDINATOR.value,
            records_withheld=0,
            failure_category=HermesAggregateFailureCategory.SOURCE_UNSUPPORTED.value,
        )

    segments: list[_StoreSegment] = []
    all_records: list[StandardRecord] = []
    mappings: dict[int, str] = {}
    scanned: ScanFilterOutcome | None = None
    issued_tokens: list[str] = []
    open_collectors: dict[int, SnippetCollector] = {}
    ledger = service.ledger if service.ledger is not None else default_ledger()
    digest_left = MAX_HERMES_AGGREGATE_DIGEST_BYTES
    budget_hit = False
    any_incomplete = False
    stage = HermesAggregateStageReached.COORDINATOR.value

    try:
        stage = HermesAggregateStageReached.STORE_READ.value
        for position, ref in enumerate(stores):
            segment = _read_one_store(
                policy=policy,
                scope=scope,
                ref=ref,
                requested_project=project,
                digest_bytes_left=digest_left,
            )
            segment.index = position
            segments.append(segment)
            digest_left = max(0, digest_left - segment.digest_bytes)
            if segment.status is _StoreRowStatus.SKIPPED_BUDGET:
                budget_hit = True
                any_incomplete = True
                continue
            if segment.status is not _StoreRowStatus.READ:
                any_incomplete = True
                continue
            # 入列前置校验整库完成，才允许 append；校验期间 all_records/mappings 恒为
            # 该库之前的状态，因此中途任一校验失败时 base == len(all_records) 天然成立
            # ——不需要回滚，孤儿记录不可能产生（09 裁决 P2-1；旧法在校验循环内
            # 边校验边 append，冲突 break 后前缀成为孤儿并被下一库 base 续号吞掉）。
            segment.base = len(all_records)
            if len(all_records) + len(segment.records) > MAX_CANDIDATES_HARD_LIMIT:
                # 全查询候选预算装不下这一库的已核验候选：整库不进过滤层，不做部分接收。
                segment.status = _StoreRowStatus.INCOMPLETE
                segment.reason = _FilterErrorTag.READ_BUDGET_EXHAUSTED.value
                segment.records = []
                segment.projects = []
                any_incomplete = True
                continue
            asserted = _comparable_key(ref.session_id)
            conflict = next(
                (
                    local
                    for local, record in enumerate(segment.records)
                    if _comparable_key(record.session_id) != asserted
                ),
                None,
            )
            if conflict is not None:
                # 适配器内已按断言逐条拒过；真出现漂移就是身份不一致，整库不进过滤层。
                # 旧法会留下前 `conflict` 条孤儿：被下一库 base 续号吞掉、虚增 skipped、
                # 并进过滤层计入 total_scanned；孤儿命中时 global_to_local 查不到映射，
                # 整批塌成 match_join_failed 而牵连其它库（06 TC-MCP-AGG-13）。
                segment.status = _StoreRowStatus.INCOMPLETE
                segment.reason = "session_identity_conflict"
                segment.records = []
                segment.projects = []
                any_incomplete = True
                continue
            for local, record in enumerate(segment.records):
                all_records.append(record)
                mappings[segment.base + local] = segment.projects[local]
            if position + 1 < len(stores) and digest_left < _MIN_DIGEST_BUDGET:
                budget_hit = True
                any_incomplete = True

        usable_records = len(all_records)
        if usable_records == 0:
            row = _incomplete_hermes_row(
                _STORES_UNUSABLE_NOTE,
                category=_FilterErrorTag.STORES_UNUSABLE.value,
            )
            _annotate_hermes_rows(
                (row,),
                HermesAggregateFailureCategory.STORES_UNUSABLE.value,
                _LAYERED_COUNTER_NOTE + _MULTI_HERMES_SCOPE_NOTE,
            )
            return HermesAggregateSearchOutcome(
                complete=False,
                partial=True,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=0,
                results=(),
                coverage=_merged_coverage(row, requested_sources),
                stores=tuple(_store_row(segment) for segment in segments),
                reason=HermesAggregateFailureCategory.STORES_UNUSABLE.value,
                coverage_scope=COVERAGE_SCOPE_MULTI_HERMES,
                stage_reached=stage,
                records_withheld=0,
                failure_category=HermesAggregateFailureCategory.STORES_UNUSABLE.value,
            )

        stage = HermesAggregateStageReached.FILTER.value
        effective_limit = min(limit, MAX_HERMES_AGGREGATE_SNIPPETS)
        full_set_scanned = not any_incomplete and not budget_hit
        scanned = scan_filter(
            all_records,
            query=query,
            start=start,
            end=end,
            project=project,
            project_mappings=mappings,
            sources=(SOURCE_HERMES,),
            limit=effective_limit,
            max_total_scan_chars=MAX_HERMES_AGGREGATE_SCAN_CHARS,
            completed_sources=(SOURCE_HERMES,) if full_set_scanned else (),
        )
        if scanned.rejected:
            return _rejected_outcome(
                scanned.reason.value
                if scanned.reason is not None
                else HermesAggregateFailureCategory.INTERNAL_FAILURE.value,
                stage=stage,
            )

        hermes_row = _merge_filter_row(
            scanned, partial_flags=any_incomplete or budget_hit, reason_note=""
        )

        # 全查询上限裁掉的是记录表尾部的库：把「尾部没扫」回写到那些库的行并撤销无匹配声明。
        tail_skipped = int(scanned.skipped_records)
        if tail_skipped > 0:
            remaining = tail_skipped
            for segment in reversed(segments):
                if remaining <= 0:
                    break
                seg_total = len(segment.records)
                seg_skipped = min(seg_total, remaining)
                if seg_skipped <= 0:
                    continue
                remaining -= seg_skipped
                if segment.status is _StoreRowStatus.READ:
                    segment.status = _StoreRowStatus.INCOMPLETE
                    segment.reason = _FilterErrorTag.SOURCE_NOT_SCANNED.value
                    segment.skipped_tail = seg_skipped
                    any_incomplete = True

        global_to_local: dict[int, tuple[_StoreSegment, int]] = {}
        for segment in segments:
            for local in range(len(segment.records)):
                global_to_local[segment.base + local] = (segment, local)

        stage = HermesAggregateStageReached.PUBLICATION.value
        per_store_cap = min(MAX_SNIPPETS_PER_FILE, effective_limit)
        kept_matches: list[tuple[int, int]] = []  # (全局记录序号, 该库内局部序号)
        per_store_kept: dict[int, int] = {}
        quota_cut = False
        for match in scanned.matches:
            record_index = match.record_index
            pair = global_to_local.get(record_index) if isinstance(record_index, int) else None
            if pair is None:
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    HermesAggregateFailureCategory.MATCH_JOIN_FAILED.value,
                    stage,
                )
            segment, local = pair
            kept_so_far = per_store_kept.get(segment.index, 0)
            if kept_so_far >= per_store_cap:
                quota_cut = True
                continue
            per_store_kept[segment.index] = kept_so_far + 1
            kept_matches.append((record_index, local))

        first_refusal: str | None = None
        for record_index, _local in kept_matches:
            segment, local = global_to_local[record_index]
            collector = open_collectors.get(segment.index)
            if collector is None:
                collector = SnippetCollector(
                    source=SOURCE_HERMES,
                    max_snippets=per_store_cap,
                    max_total_chars=MAX_SNIPPET_TOTAL_CHARS,
                )
                open_collectors[segment.index] = collector
            refusal = collector.collect(all_records[record_index])
            if refusal is not None:
                first_refusal = refusal.value
                break
            segment.kept_local.append(local)
        if first_refusal is not None:
            for collector in open_collectors.values():
                collector.release(confirmed=False)
            open_collectors.clear()
            for segment in segments:
                segment.kept_local = []
            return _aggregate_failure(
                segments,
                scanned,
                requested_sources,
                first_refusal,
                stage,
            )

        # 片段全部判过，才逐库释放并按该库自己的绑定发放引用。
        published_chars = 0
        snippets_total = 0
        for segment in segments:
            if segment.index not in open_collectors:
                continue
            collector = open_collectors.pop(segment.index)
            seg_snippets = collector.release(confirmed=True)
            if len(seg_snippets) != len(segment.kept_local):
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    HermesAggregateFailureCategory.SNIPPET_JOIN_FAILED.value,
                    stage,
                )
            published_chars += sum(len(item.snippet) for item in seg_snippets)
            snippets_total += len(seg_snippets)
            segment.snippets = seg_snippets
        if published_chars > MAX_SNIPPET_TOTAL_CHARS:
            return _aggregate_failure(
                segments,
                scanned,
                requested_sources,
                PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED.value,
                stage,
            )
        if snippets_total != len(kept_matches):
            return _aggregate_failure(
                segments,
                scanned,
                requested_sources,
                HermesAggregateFailureCategory.SNIPPET_JOIN_FAILED.value,
                stage,
            )

        for segment in segments:
            if not segment.snippets:
                continue
            version = segment.version
            if version is None or not version.complete:
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    HermesAggregateFailureCategory.VERSION_UNSTABLE.value,
                    stage,
                )
            records = [all_records[segment.base + local] for local in segment.kept_local]
            projects = [segment.projects[local] for local in segment.kept_local]
            try:
                tokens = _issue_hermes_references(
                    records,
                    projects,
                    version=version,
                    service_key=_hermes_service_key(scope=scope, ref=segment.ref),
                    scope=scope,
                    path=segment.ref.store_path,
                    session_id=segment.ref.session_id,
                    ledger=ledger,
                )
            except ValueError:
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    HermesAggregateFailureCategory.REFERENCE_ISSUE_FAILED.value,
                    stage,
                )
            segment.tokens = list(tokens)
            issued_tokens.extend(tokens)

        results: list[dict[str, object]] = []
        metadata_withheld = False
        cursor: dict[int, int] = {}
        # 接线按 kept_matches 顺序：每条命中对应其库内下一个已释放片段与新引用。
        # 序号到命中的映射只从过滤层自己的 matches 建；重复序号即接线不一致，整批失败。
        match_by_index: dict[int, MatchRef] = {}
        for match in scanned.matches:
            if match.record_index in match_by_index:
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    HermesAggregateFailureCategory.MATCH_JOIN_FAILED.value,
                    stage,
                )
            match_by_index[match.record_index] = match
        for record_index, _local in kept_matches:
            segment, local = global_to_local[record_index]
            offset = cursor.get(segment.index, 0)
            cursor[segment.index] = offset + 1
            match = match_by_index.get(record_index)
            if (
                match is None
                or offset >= len(segment.snippets)
                or offset >= len(segment.tokens)
            ):
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    HermesAggregateFailureCategory.SNIPPET_JOIN_FAILED.value,
                    stage,
                )
            row, withheld = _join_result(match, segment.snippets[offset])
            row["location"] = segment.tokens[offset]
            metadata_withheld = metadata_withheld or withheld
            results.append(row)

        coverage_rows = list(_merged_coverage(hermes_row, requested_sources))
        if any(
            snippet.truncated for segment in segments for snippet in segment.snippets
        ):
            _annotate_hermes_rows(
                coverage_rows,
                HermesAggregateFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value,
                _SNIPPET_TRUNCATION_NOTE,
            )
        if metadata_withheld:
            _annotate_hermes_rows(
                coverage_rows,
                HermesAggregateFailureCategory.METADATA_WITHHELD.value,
                _METADATA_WITHHELD_NOTE,
            )
        if quota_cut:
            updated = dict(coverage_rows[0])
            updated["returned_count"] = len(results)
            updated["partial"] = True
            errors = _row_tags(updated, "filter_errors")
            if FilterErrorCode.RESULT_TRUNCATED.value not in errors:
                errors.append(FilterErrorCode.RESULT_TRUNCATED.value)
            updated["filter_errors"] = errors
            updated["reason"] = f"{updated.get('reason', '')}{_QUOTA_NOTE}"
            # 回写作用在已标注后的首行，不得替换回原行：否则抹掉上面叠上的类别注记。
            coverage_rows = [updated, *coverage_rows[1:]]

        store_rows: list[dict[str, object]] = []
        for segment in segments:
            frow = _store_row(segment)
            scanned_here = len(segment.records) - segment.skipped_tail
            frow["filter_scanned"] = max(0, scanned_here)
            frow["filter_skipped"] = segment.skipped_tail
            frow["returned_count"] = cursor.get(segment.index, 0)
            store_rows.append(frow)

        partial = (
            not scanned.complete
            or any_incomplete
            or budget_hit
            or quota_cut
            or any(bool(row.get("partial")) for row in coverage_rows)
        )
        truncated_output = scanned.truncated or quota_cut or any(
            snippet.truncated for segment in segments for snippet in segment.snippets
        )
        stage = HermesAggregateStageReached.PUBLISHED.value
        return HermesAggregateSearchOutcome(
            complete=not partial and full_set_scanned and scanned.complete,
            partial=partial,
            truncated=truncated_output,
            total_matched=scanned.total_matched,
            total_scanned=scanned.total_scanned,
            skipped_records=scanned.skipped_records,
            results=tuple(results),
            coverage=tuple(coverage_rows),
            stores=tuple(store_rows),
            reason=None,
            coverage_scope=COVERAGE_SCOPE_MULTI_HERMES,
            stage_reached=stage,
            records_withheld=scanned.skipped_records,
            failure_category=None,
        )
    except (PolicyDenied, SafeReadDenied):
        raise
    except Exception:  # noqa: BLE001 - 内部异常不回显，只折叠为固定类别
        with contextlib.suppress(BaseException):
            ledger.release(tuple(issued_tokens))
        for segment in segments:
            segment.tokens = []
        issued_tokens.clear()
        category = HermesAggregateFailureCategory.INTERNAL_FAILURE.value
        if scanned is None:
            row = _incomplete_hermes_row(_INTERNAL_NOTE, category=category)
        else:
            row = _merge_filter_row(scanned, partial_flags=True, reason_note="")
            errors = _row_tags(row, "filter_errors")
            if category not in errors:
                errors.append(category)
            row["filter_errors"] = errors
        row["reason"] = (
            f"{_INTERNAL_NOTE}{_LAYERED_COUNTER_NOTE}{_MULTI_HERMES_SCOPE_NOTE}"
        )
        fail_stage = (
            HermesAggregateStageReached.PUBLICATION.value
            if stage == HermesAggregateStageReached.PUBLISHED.value
            else stage
        )
        return HermesAggregateSearchOutcome(
            complete=False,
            partial=True,
            truncated=False,
            total_matched=0,
            total_scanned=0,
            skipped_records=len(all_records),
            results=(),
            coverage=_merged_coverage(row, requested_sources),
            stores=tuple(_store_row(segment) for segment in segments),
            coverage_scope=COVERAGE_SCOPE_MULTI_HERMES,
            stage_reached=fail_stage,
            records_withheld=len(all_records),
            failure_category=category,
            reason=category,
        )
    finally:
        for segment in segments:
            segment.records = []
            segment.projects = []
            segment.kept_local = []
            segment.snippets = ()
        for collector in open_collectors.values():
            with contextlib.suppress(BaseException):
                collector.discard(PublicationRefusal.NOT_CONFIRMED)
        open_collectors.clear()
        all_records.clear()
        mappings.clear()


# ---- 宿主进程内绑定服务 ----


def _validate_bound_stores(
    *,
    label: str,
    policy: object,
    scope: object,
    stores: object,
    ledger: object,
) -> None:
    """绑定时的形态与规模核对：全过才允许绑定，越界一律抛异常而不是截断。"""

    if not isinstance(policy, SessionPolicy):
        raise TypeError(f"{label} requires a SessionPolicy")
    if not isinstance(scope, str) or not scope or scope != scope.strip():
        raise ValueError(f"{label}.scope must be a non-empty string")
    if isinstance(stores, (str, bytes)) or not isinstance(stores, Sequence):
        raise TypeError(f"{label}.stores must be a sequence of HermesStoreRef")
    if len(stores) < 1:
        raise ValueError(f"{label}.stores must contain at least one HermesStoreRef")
    if len(stores) > MAX_STORES_PER_QUERY:
        raise ValueError(f"{label}.stores exceeds {MAX_STORES_PER_QUERY} bound stores")
    for entry in stores:
        if not isinstance(entry, HermesStoreRef):
            raise TypeError(f"{label} accepts HermesStoreRef entries only")
    if ledger is not None and not isinstance(ledger, ReferenceLedger):
        raise TypeError(f"{label} accepts a ReferenceLedger only")


@dataclass(frozen=True)
class HermesAggregateSearchService:
    """宿主注入的 Hermes 聚合检索服务：一策略、一范围、一有界库集合、一共用引用账本。

    与 `PiMultiFileSearchService` 同一绑定语义：路径与会话断言只在宿主注入时进入，客户端只能在
    已绑定的集合内收窄（时间、关键词、项目、limit），传不进路径，也放宽不了任何上限。
    """

    policy: SessionPolicy
    scope: str
    stores: tuple[HermesStoreRef, ...]
    ledger: ReferenceLedger | None = None

    def __post_init__(self) -> None:
        _validate_bound_stores(
            label="HermesAggregateSearchService",
            policy=self.policy,
            scope=self.scope,
            stores=self.stores,
            ledger=self.ledger,
        )
        object.__setattr__(self, "stores", tuple(self.stores))

    def store_refs(self) -> tuple[HermesStoreRef, ...]:
        """绑定集合的只读副本：宿主接线与测试用它确认集合未被改写。"""

        return tuple(self.stores)

    def binding_key(self, index: int) -> str:
        """绑定集合里第 `index` 个库在本 scope 下的引用绑定键。

        路由只能用发放方算出的键，不能由上下文侧重建：两边各自拼一遍 scope+来源+路径+会话
        四元组，日后任何一侧改了拼接口径都只会表现为 `binding_mismatch`——那种拒绝看起来像
        「令牌不对」，而真实原因在代码里。键算法只留一份，归本服务持有。
        """

        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.stores):
            raise ValueError("binding_key index out of bounds")
        return _hermes_service_key(scope=self.scope, ref=self.stores[index])

    def context_service(self) -> HermesAggregateContextService:
        """返回与本服务同范围、同绑定集合、**同引用账本**的上下文服务（配对绑定用）。

        键算法与路由表都经由 `binding_key` 仍留在发放方一侧，所以引用只能回到本次已批准绑定。
        上下文模块在运行期才导入：它依赖本模块的绑定键与读取口，顶层互相导入会成环。
        """

        from .hermes_aggregate_context import HermesAggregateContextService

        return HermesAggregateContextService(
            policy=self.policy,
            scope=self.scope,
            stores=self.stores,
            ledger=self.ledger,
            binding_key=self.binding_key,
        )

    def search(
        self,
        *,
        scope: str | None = None,
        query: str | None = None,
        sources: Sequence[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        project: str | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        """聚合检索入口：返回可直接 JSON 化的公开结论。

        `scope` 与绑定不符时在协调器层就拒：零结果、零覆盖行，`reason=scope_mismatch`，
        一个库都不打开；客户端传不进路径，也放宽不了任何上限。
        """

        if scope is not None and scope != self.scope:
            return HermesAggregateSearchOutcome(
                complete=False,
                partial=True,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=0,
                results=(),
                coverage=(),
                stores=(),
                rejected=False,
                reason=HermesAggregateFailureCategory.SCOPE_MISMATCH.value,
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage_reached=HermesAggregateStageReached.COORDINATOR.value,
                records_withheld=0,
                failure_category=HermesAggregateFailureCategory.SCOPE_MISMATCH.value,
            ).as_public_dict()
        return _search_hermes_stores(
            self,
            query=query,
            sources=sources,
            start=start,
            end=end,
            project=project,
            limit=limit,
        ).as_public_dict()


__all__ = [
    "COVERAGE_SCOPE_MULTI_HERMES",
    "HERMES_STORE_STAGE_BYTES",
    "HERMES_STORE_TEXT_CHARS",
    "MAX_HERMES_AGGREGATE_DIGEST_BYTES",
    "MAX_HERMES_STORE_DIGEST_BYTES",
    "MAX_HERMES_STORE_ROWS",
    "MAX_PROTOCOL_LIMIT",
    "MAX_STORES_PER_QUERY",
    "HermesAggregateFailureCategory",
    "HermesAggregateSearchOutcome",
    "HermesAggregateSearchService",
    "HermesAggregateStageReached",
    "HermesStoreRef",
]
