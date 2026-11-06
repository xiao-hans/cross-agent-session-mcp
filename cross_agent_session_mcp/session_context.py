"""单个已批准 Pi 文件的**受限上下文读取**协调器（DES-API-01「`read_session_context`」契约）。

定位：本模块回答一件事——**给定一条已授权查询发放的引用，能不能把它周围的有限上下文交出去**。
它不发现文件、不枚举目录、不读配置、不接客户端路径：可读对象只有一个由宿主在进程内显式绑定的
`PiFileContextService`（一个 `SessionPolicy`、一个 `scope`、**单个**已批准文件、**预先独立持有**的
`session_id`），与 `file_search.PiFileSearchService` 同一绑定形状。

引用只作核对，不作寻址
------------
`location` 是**上一次授权查询自己发放的随机不透明引用**（`ctxref:<随机串>`，见 `references.py`）。
引用串里没有任何位置信息：行号、同行序号、流标签、卷号、文件标识、体积都只能从账本条目里读出，
再由本模块拿去与**本次重新读取**的记录逐字段核对。因此
「客户端猜一个行号」「自带一个版本号来降级读取」这两条通道在协议上不存在。

绑定核对（全部在读取之前完成，且只比摘要/枚举，不回显原值）：
① 服务绑定指纹 `service_key`——`(scope, source, path, session_id)` 四元组的定长摘要：换一个绑定
服务实例即失配（`BINDING_MISMATCH`）；② 会话轴——账本条目的 `session_id` 与本次断言经
`session_stage._comparable_key` 归一后必须相等，重新读取出的锚点记录自身携带的会话标识也必须
与断言一致；③ 项目轴——客户端若带 `project` 收窄条件，必须与发放时策略给出的项目名逐字相等；
④ 位置轴——`(line_no, ordinal, stream_label)` 与重新核对记录集中某条记录逐字段一致，
两侧都有标签而不同即不属于同一行流（不拿「行号相同」放行）。

文件版本：同趟取证，不作预检
------------
版本基准**不由客户端携带**：发放引用时由 `safe_reader` 在同一次授权读取里确立（句柄身份 +
同趟累加的整文件 SHA-256）。本模块重新读取后，比较本次的同趟版本与账本记录的四项
（卷号、文件标识、体积、摘要）：任一不符即 `FILE_REPLACED`，整批零片段。同大小的改写会改变摘要，
所以「体积没变」不足以冒充未修改。这条比较与读取共用同一趟取证：本模块**不**做打开前的路径
`stat`，也**不**在读取之后再按路径 `stat` 冒充句柄证据；真实卷号/文件标识/摘要只参与内部比较，
永不进入任何对外结果（对外只给 `version_confirmed` 一个布尔）。

失败口径：零正文 + 分层计数
------------
任何拒绝/不完整都返回**零片段**，绝不给出上下文的前缀（与 `file_search` 同一口径）。缺失、过期、
被淘汰、与绑定矛盾、文件版本变化一律折算为固定类别（`ContextFailureCategory`）；结论里仍保留
分层计数（读侧 `read`、解析侧 `parse`、暂存侧 `stage`、本模块的 `records_withheld`/`window_size`），
以便调用方区分「被门禁拦下」与「文件里就没有这些记录」。引用对不上不报成「没找到」：那是拒绝，
把拒绝报成没找到会诱导调用方换个写法再试。

窗口与预算（有界性，全部只能收紧）
------------
- 窗口 `before`/`after` 各 0–10（协议层 `server.MAX_CONTEXT_WINDOW`），两侧条数各自独立；锚点本身
  恒占一条，因此一次运行最多交出 `MAX_WINDOW_RECORDS = 21` 条。越界在入口即 `INVALID_ARGUMENT`，
  不夹紧也不回显原值。
- 片段条数上限 `MAX_CONTEXT_SNIPPETS`（16）与总字符代理预算 `MAX_CONTEXT_TOTAL_CHARS`（32 768，
  遮蔽后字符数累加）与查询出口同一组常量；`SnippetCollector` 自身的两条硬顶仍在其上钳制。
- 候选驻留预算 `MAX_CONTEXT_CANDIDATES`（32）/`MAX_CONTEXT_STAGE_BYTES`（512 KiB）比查询路径默认
  更严：触限即整批丢弃并记 `INCOMPLETE`，不「跳过后面的记录继续找」。

发布边界（诚实的口径）
------------
`complete=True` 只说明：两条授权轴 + 逐记录归属准入 + 会话两路身份核对 + EOF 前置确认 + 解析侧无
`partial` + 引用绑定与本次读取逐字段一致 + 文件版本与账本一致 + 窗口内每条都过了完整遮蔽与两条
硬顶。它**不是**「整个来源已覆盖」：覆盖层级恒为 `single_approved_file`。它也不是发布许可的第二套
判据——`publication_allowed` 仍原样取自 `StageOutcome`（本增量恒 `False`）。窗口里的文字仍属不可信
历史内容（DES-SEC-01）。窗口内每条已发布记录同样获得**新发放**的 `ctxref:` 引用，客户端因此可以
沿相邻记录逐步扩读，而全程拿不到任何可直接寻址的坐标。

依赖限制（DES-ARCH-02）：只用标准库与本包模块；不导入协议层（`server.py`）与 MCP SDK，
不读文件/配置/环境变量，不写日志，不联网，不 `open`、不 `stat`（唯一读取通道仍是
`session_pipeline` 里的 `safe_reader.authorize_read`）。
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .file_search import (
    COVERAGE_SCOPE_FILE,
    COVERAGE_SCOPE_NONE,
    SOURCE_PI,
    _issue_references,
    _public_key,
)
from .models import (
    NON_PARTIAL_ISSUES,
    IssueCode,
    SourceLocation,
    StandardRecord,
    normalize_timestamp,
    sanitize_stream_label,
)
from .policy import PolicyDenied, SessionPolicy
from .publication import (
    MAX_SNIPPET_TOTAL_CHARS,
    MAX_SNIPPETS_HARD_LIMIT,
    MAX_SNIPPETS_PER_FILE,
    PublicationRefusal,
    SnippetCollector,
)
from .query import (
    MAX_CALLER_KEY_CHARS,
    MAX_LINE_NO,
    MAX_MATCH_ORDINAL,
    MAX_SESSION_ID_CHARS,
)
from .references import (
    ReferenceLedger,
    ReferenceRecord,
    default_ledger,
    lookup_reference,
    parse_reference_token,
    service_binding_key,
)
from .safe_reader import (
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_LINES,
    DEFAULT_MAX_TOTAL_BYTES,
    SafeReadDenied,
)
from .session_pipeline import PiFileOutcome, _run_pi_file_pipeline
from .session_stage import (
    MAX_CANDIDATES_HARD_LIMIT,
    MAX_STAGE_BYTES_HARD_LIMIT,
    _comparable_key,
)

__all__ = [
    "MAX_CONTEXT_CANDIDATES",
    "MAX_CONTEXT_SNIPPETS",
    "MAX_CONTEXT_STAGE_BYTES",
    "MAX_CONTEXT_TOTAL_CHARS",
    "MAX_WINDOW_RECORDS",
    "ContextFailureCategory",
    "ContextOutcome",
    "ContextStageReached",
    "PiFileContextService",
    "read_pi_file_context",
]

#: 上下文片段的条数上限：与查询出口的每文件默认条数同一常量，不另开一个更大的口子。
#: `SnippetCollector.MAX_SNIPPETS_HARD_LIMIT`（32）仍在上面钳制，调用方只能收紧。
MAX_CONTEXT_SNIPPETS = MAX_SNIPPETS_PER_FILE

#: 上下文片段的总字符代理预算（遮蔽后字符数累加，非 UTF-8 字节）：与查询出口同一常量。
MAX_CONTEXT_TOTAL_CHARS = MAX_SNIPPET_TOTAL_CHARS

#: 本模块的候选驻留上限（条数）：与查询路径同值不放宽，硬顶仍是 `MAX_CANDIDATES_HARD_LIMIT`。
MAX_CONTEXT_CANDIDATES = min(MAX_SNIPPETS_PER_FILE * 2, MAX_CANDIDATES_HARD_LIMIT)

#: 候选驻留的保留总量预算（字节）：查询路径默认 1 MiB 量级，上下文只取一条有限窗口，
#: 因此这里收紧到 512 KiB；`SessionCandidateStage` 自身的硬顶仍在上面钳制。
MAX_CONTEXT_STAGE_BYTES = min(512 * 1024, MAX_STAGE_BYTES_HARD_LIMIT)

#: 一次上下文运行最多交出的记录条数：两侧各 10（协议层 `server.MAX_CONTEXT_WINDOW`）加锚点本身。
#: 它不是「允许把 before/after 调到 10 以上」：两侧的合法域仍由协议层与 `_validated_sides` 判。
MAX_WINDOW_RECORDS = 21

#: 协议层窗口单侧上限：与 `server.MAX_CONTEXT_WINDOW` 同值，在此独立判一次是本模块自己的入口边界。
_MAX_WINDOW_SIDE = 10


class ContextFailureCategory(StrEnum):
    """上下文出口的外送失败类别：闭合集合，只含类别，不含正文、路径、会话标识、引用原值。

    这些值进入 `reason`/`failure_category` 与 `filter_errors`，因此与 `PiFileFailureCategory`、
    `PublicationRefusal` 一样必须是本模块定义的固定类别；新增类别只能改本枚举，不得由调用方用
    数据侧字符串临时造键。
    """

    INVALID_ARGUMENT = "invalid_argument"  # 参数形态不合（引用不可解析、窗口越界）
    REF_EXPIRED = "ref_expired"  # 引用缺失/过期/被淘汰，或锚点不属于本次已核对记录集
    BINDING_MISMATCH = "binding_mismatch"  # 引用绑定的服务/范围/来源/会话/项目与本次请求矛盾
    FILE_REPLACED = "file_replaced"  # 本次同趟版本与账本版本不符（含同大小改写）
    NOT_FOUND = "not_found"  # 会话标识在本次运行中根本不可用（无记录、身份不可核实）
    INCOMPLETE = "incomplete"  # 读/解析/暂存核对未通过（EOF 未确认、触限、坏行、归属/冲突）
    CANDIDATE_CAPTURE_FAILED = "candidate_capture_failed"  # 捕获候选环节失败
    WINDOW_UNRESOLVED = "window_unresolved"  # 窗口内某条记录不可用于片段（形态/位置越界）
    PUBLICATION_FAILED = "publication_failed"  # 遮蔽或预算未过，整批零片段（不是前缀）
    REFERENCE_ISSUE_FAILED = "reference_issue_failed"  # 相邻记录的发放入失败，整批改走发布失败
    SNIPPET_OUTPUT_TRUNCATED = "snippet_output_truncated"  # 遮蔽层按输出上限截过片
    METADATA_WITHHELD = "metadata_withheld"  # 短元数据形态不合，已降为 null
    RECORD_FIELD_OUT_OF_BOUNDS = "record_field_out_of_bounds"  # 候选存在越界质量码（相邻关系不可信）
    INTERNAL_FAILURE = "internal_failure"  # 协调器内的意外失败


class ContextStageReached(StrEnum):
    """本次运行最远走到哪一层（闭合类别），供分层计数解读与引用发放判据用。

    与 `file_search.PiFileStageReached` 同一取向：只说明「走到哪」，不说明那一层是否通过。
    """

    COORDINATOR = "coordinator"  # 连文件管线结论都没拿到（引用/窗口/绑定预检被拒）
    FILE_PIPELINE = "file_pipeline"  # 停在读/解析/暂存核对或版本、锚点、身份判定
    CANDIDATE_CAPTURE = "candidate_capture"  # 文件核对完成，捕获候选时失败
    WINDOW = "window"  # 已选出窗口记录，但窗口判定未通过
    PUBLICATION = "publication"  # 走到遮蔽/预算/发放，但未发布
    PUBLISHED = "published"  # 已发布（上下文或可证明的空窗口）


#: 每个类别一句固定人话：不拼接长度、条数、路径、引用串等派生值（同 `policy.REFUSAL_MESSAGES`）。
_CATEGORY_REASONS: dict[str, str] = {
    ContextFailureCategory.INVALID_ARGUMENT: (
        "拒绝：上下文请求的参数形态不合法；本次未返回任何正文。"
    ),
    ContextFailureCategory.REF_EXPIRED: (
        "拒绝：引用已缺失、过期、被淘汰，或所指位置不属于本次已核对的记录集，"
        "整批未发布（零结果，不是前缀）；请重新查询后使用新引用。"
    ),
    ContextFailureCategory.BINDING_MISMATCH: (
        "拒绝：引用绑定的授权服务/范围/来源/会话/项目与本次请求不一致，"
        "整批未发布（零结果，不是前缀）。"
    ),
    ContextFailureCategory.FILE_REPLACED: (
        "拒绝：本次同趟读取确立的文件版本与发放引用时的版本不一致（目标已被替换或改写，"
        "含同大小改写），整批未发布（零结果，不是前缀）；请重新查询后使用新引用。"
    ),
    ContextFailureCategory.NOT_FOUND: (
        "该会话在本次已批准文件中没有可用记录，未返回任何正文；"
        "这只对本文件成立，不表示整个来源没有该会话。"
    ),
    ContextFailureCategory.INCOMPLETE: (
        "文件未通过完整读取、身份或归属核对；本来源未发布结果。"
    ),
    ContextFailureCategory.CANDIDATE_CAPTURE_FAILED: (
        "候选捕获失败，已核对的文件未交给上下文窗口；本来源未发布结果。"
    ),
    ContextFailureCategory.WINDOW_UNRESOLVED: (
        "窗口内存在形态或位置不可用于片段的记录，整批未发布（零结果，不是前缀）。"
    ),
    ContextFailureCategory.PUBLICATION_FAILED: (
        "遮蔽未通过或片段预算触限，整批未发布（零结果，不是前缀）。"
    ),
    ContextFailureCategory.REFERENCE_ISSUE_FAILED: (
        "相邻记录的引用发放失败，整批未发布（零结果，不是前缀）。"
    ),
    ContextFailureCategory.SNIPPET_OUTPUT_TRUNCATED: (
        "一个或多个遮蔽片段按输出上限截断。"
    ),
    ContextFailureCategory.METADATA_WITHHELD: (
        "存在形态不可外的短元数据，已降为 null 并记为覆盖不完整。"
    ),
    ContextFailureCategory.RECORD_FIELD_OUT_OF_BOUNDS: (
        "候选存在越界质量码，相邻关系不再可信，本来源记为覆盖不完整。"
    ),
    ContextFailureCategory.INTERNAL_FAILURE: (
        "协调器内部失败；本来源未发布结果，分层计数只在已取到的结论上给出。"
    ),
}

#: 遮蔽侧的首拒类别（`PublicationRefusal`）→ 一句固定说明：各出口的代价不同，不合并。
_PUBLICATION_REASONS: dict[str, str] = {
    PublicationRefusal.REDACTION_REJECTED.value: (
        "至少一条候选未通过输出遮蔽，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.SNIPPET_LIMIT_EXCEEDED.value: (
        "遮蔽片段条数触本次上限，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED.value: (
        "遮蔽片段总字符数触本次输出预算，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.RECORD_UNUSABLE.value: (
        "候选形态不可用于片段，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.INTERNAL_FAILURE.value: (
        "片段收集过程失败，整批未发布（零结果，不是前缀）。"
    ),
    PublicationRefusal.NOT_CONFIRMED.value: (
        "本次运行未拿到完整确认，整批未发布（零结果，不是前缀）。"
    ),
}

#: 固定追加到覆盖行的范围声明：上下文结论只对本文件作证（同 `file_search._FILE_SCOPE_NOTE`）。
_FILE_SCOPE_NOTE = "覆盖范围仅限本次绑定的单个已批准文件，不声明整个 pi 来源已扫完。"

_LAYERED_COUNTER_NOTE = (
    "分层计数按层给出：records_scanned=0 只表示上下文窗口未判定这些记录，"
    "不表示文件未被读取或解析。"
)
_SNIPPET_TRUNCATION_NOTE = "一个或多个遮蔽片段按输出上限截断。"
_METADATA_WITHHELD_NOTE = (
    "存在形态不可外的短元数据（路径形态、含分隔符/空白或超长），已降为 null 并记为覆盖不完整。"
)
_QUALITY_ISSUE_NOTE = "窗口内存在越界解析质量码，相邻关系按覆盖不完整解读。"

#: 单侧窗口值的合法域：字面 `int`（`bool` 不算）且 0 ≤ 值 ≤ 10，否则 `None`（由调用方拒）。
_WINDOW_RANGE = range(_MAX_WINDOW_SIDE + 1)


@dataclass(frozen=True)
class ContextOutcome:
    """一次受限上下文运行的结论：可外出字段全部为固定键 + 整数/布尔/闭合枚举/脱敏片段。

    `status` 取 `query.CoverageStatus` 的三个可自证值（`searched`/`no_match`/`incomplete`）；
    `version_confirmed` 只回答「本次同趟版本是否与账本一致」这一个布尔——真实卷号、文件标识、
    体积与内容摘要永不外出，也不接受客户端提供的基准。任何路径都不含路径、scope、cwd、引用原值
    之外的寻址坐标（每行 `location` 是新发放的不透明引用）。
    """

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
    filter_error_codes: tuple[str, ...]
    quality_issues: tuple[str, ...]
    notes: tuple[str, ...]
    results: tuple[dict[str, Any], ...]
    file: PiFileOutcome | None

    @property
    def returned_count(self) -> int:
        """已发布的上下文条数；`window_size` 非零不表示这里非零。"""
        return len(self.results)

    def as_public_dict(self) -> dict[str, Any]:
        coverage = {
            "source": SOURCE_PI,
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
            "file": self.file.as_public_dict() if self.file is not None else None,
        }


def _refused(
    *,
    category: ContextFailureCategory,
    reason_code: str | None = None,
    coverage_scope: str = COVERAGE_SCOPE_FILE,
    stage: ContextStageReached = ContextStageReached.COORDINATOR,
    note: str | None = None,
    file_outcome: PiFileOutcome | None = None,
    window: int = 0,
    records_withheld: int = 0,
    version_confirmed: bool = False,
) -> ContextOutcome:
    """零结果出口的构造器：固定类别 + 分层计数 + 无片段，任何路径都不带正文前缀。"""
    codes = [category.value]
    if reason_code is not None and reason_code not in codes:
        codes.append(reason_code)
    if file_outcome is not None:
        for code in (
            None
            if file_outcome.read.reason is None
            or file_outcome.read.reason.value == "exhausted"
            else file_outcome.read.reason.value,
            None
            if file_outcome.pipeline.reason is None
            else file_outcome.pipeline.reason.value,
            None
            if file_outcome.attribution_refusal is None
            else file_outcome.attribution_refusal.value,
        ):
            if code is not None and code not in codes:
                codes.append(code)
    text = _CATEGORY_REASONS[category] if note is None else note
    return ContextOutcome(
        complete=False,
        partial=True,
        truncated=False,
        status="incomplete",
        reason=category.value,
        failure_category=category.value,
        stage_reached=stage.value,
        coverage_scope=coverage_scope,
        window_size=window,
        records_withheld=records_withheld,
        version_confirmed=version_confirmed,
        filter_error_codes=tuple(codes),
        quality_issues=(),
        notes=(text, _LAYERED_COUNTER_NOTE, _FILE_SCOPE_NOTE),
        results=(),
        file=file_outcome,
    )


def _validated_sides(before: object, after: object) -> tuple[int, int] | None:
    """两侧窗口各自判形：字面 `int`（排除 `bool`）且各自 0–10，否则 `None`（由调用方拒）。

    两侧是**两个独立参数**，不是一个 `window`：`before=0` 表示只要锚点与之后若干条，
    与 `after=0` 的语义不对称，因此不存在「合并成一个值」的合法化简。上界与协议层
    `server._check_window` 同值，这里独立判一次是本模块自己的入口边界：`read_pi_file_context`
    也可被包内其他调用方直接使用，不能假设上游已经夹紧过。
    """
    before_size = _window_side(before)
    after_size = _window_side(after)
    if before_size is None or after_size is None:
        return None
    return before_size, after_size


def _window_side(value: object) -> int | None:
    """单侧窗口取值判据：字面 `int`（`bool` 不算）且 0 ≤ 值 ≤ 10，否则 `None`。"""
    if not isinstance(value, int) or value.__class__ is not int:
        return None
    if not 0 <= value <= _MAX_WINDOW_SIDE:
        return None
    return value


def _anchor_form(record: StandardRecord) -> tuple[int, int, str | None] | None:
    """记录位置的可解释形态：`(line_no, ordinal, label)`；不可解释返回 `None`。

    与 `query._location_form` 同一值域判据（字面 `int`、`1..MAX_LINE_NO`、`0..MAX_MATCH_ORDINAL`），
    标签只接受 `None` 或 `models.sanitize_stream_label` 的产出形状。这里不新造判据：判不出位置的记录
    在查询路径同样拿不到引用，两条路径因此不会一个接受一个拒绝。
    """
    location = record.location
    if not isinstance(location, SourceLocation) or location.__class__ is not SourceLocation:
        return None
    line_no = location.line_no
    ordinal = location.ordinal
    if line_no.__class__ is not int or ordinal.__class__ is not int:
        return None
    if not 1 <= line_no <= MAX_LINE_NO or not 0 <= ordinal <= MAX_MATCH_ORDINAL:
        return None
    label = location.stream_label
    if label is None:
        return line_no, ordinal, None
    if label.__class__ is not str:
        return None
    if sanitize_stream_label(label) != label:
        return None
    return line_no, ordinal, label


def _labels_agree(entry_label: str | None, record_label: str | None) -> bool:
    """行流标签逐字段一致：`None` 也是一个确定值（本包不传标签，两侧都应为 `None`）。

    只比「两侧都有标签且不同」会漏掉一侧为 `None` 的情形：同一 `(line_no, ordinal)` 上，
    带标签与不带标签的记录不属于同一行流，拿「行号相同」放行等于把引用绑到另一条记录上。
    """
    if entry_label is None:
        return record_label is None
    return entry_label == record_label


def _binding_matches(
    entry: ReferenceRecord,
    *,
    service_key: str,
    session_id: str,
    project_filter: str | None,
) -> str | None:
    """引用绑定与本次请求的逐字段核对：返回固定失配码（`None` 即一致）。

    只比摘要与归一后的键，不回显任何原值：`service_key` 覆盖范围/来源/文件/会话四项，
    会话再单独过一次 `_comparable_key`（防归一口径漂移），项目只在客户端主动收窄时比。
    """
    if entry.service_key != service_key or entry.source != SOURCE_PI:
        return "service_binding"
    if _comparable_key(entry.session_id) != _comparable_key(session_id):
        return "session_binding"
    if project_filter is not None and project_filter != entry.project:
        return "project_binding"
    return None


def _row_for(
    record: StandardRecord,
    project: str | None,
    source: str,
    location: str,
    snippet: str,
    redacted_count: int,
    snippet_truncated: bool,
) -> tuple[dict[str, Any], bool]:
    """把一条窗口记录组成对外行：短元数据过闭集形态门，正文只接遮蔽出口。

    与 `file_search._join_result` 同一组判据（`_public_key` 整体判否、`project` 只取策略映射名、
    时间走 `models.normalize_timestamp` 的同一判据：`EXACT` 且能规范化才外出，否则 `null` +
    `time_quality` 说明原因，不猜、不回填时区、不用文件 mtime）。`location` 是**本次新发放**的
    不透明引用（由调用方在遮蔽与接线全部通过之后取得）：本模块不外出自拼的 `jsonl:` 坐标，也不外出
    行号/序号/相对距离——那些位置只作为账本条目的内部绑定存在，窗口行本身按行流顺序交出，
    客户端不需要也不应拿到坐标。返回 `(行, 是否拦下元数据)`。
    """
    session_id, held_session = _public_key(record.session_id, MAX_SESSION_ID_CHARS)
    role, held_role = _public_key(record.role, MAX_CALLER_KEY_CHARS)
    executor, held_executor = _public_key(record.executor, MAX_CALLER_KEY_CHARS)
    withheld = held_session or held_role or held_executor
    moment, quality = normalize_timestamp(record.timestamp)
    timestamp = None if moment is None else moment.isoformat()
    return (
        {
            "source": source,
            "session_id": session_id,
            "role": role,
            "executor": executor,
            "timestamp": timestamp,
            "time_quality": quality.value,
            "project": project,
            "project_quality": record.project_quality.value,
            "location": location,
            "snippet": snippet,
            "redacted_count": redacted_count,
            "snippet_truncated": snippet_truncated,
        },
        withheld,
    )


@dataclass(frozen=True)
class PiFileContextService:
    """宿主在进程内显式构造的上下文绑定：一个策略、一个范围、**单个**已批准文件、一个会话标识。

    与 `file_search.PiFileSearchService` 同一绑定形状：构造期不查配置、不探测磁盘、不读正文，
    路径永不进入任何请求参数。`session_id` 是**预先独立持有**的断言（与查询服务同源），本模块不
    从解析产物回填它。`ledger` 省略即用进程内默认账本：宿主想让引用只在一次查询的寿命内可用时，
    给查询服务与本服务传同一个 `ReferenceLedger` 实例即可（只能收紧，不能放宽）。
    """

    policy: SessionPolicy
    scope: str
    path: str
    session_id: str
    ledger: ReferenceLedger | None = None

    def __post_init__(self) -> None:
        if self.ledger is not None and type(self.ledger) is not ReferenceLedger:
            raise TypeError("context service ledger must be a ReferenceLedger or None")

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
        """读一段受限上下文；参数全部为标量，客户端无法提供任何路径或版本基准。

        `scope`/`source`/`session_id` 是**与引用绑定对照的客户端声明**：任一与发放时的绑定矛盾
        即整批零片段拒绝（`binding_mismatch`），本方法不拿「服务端已经绑好了」替它们放行。
        `None`（客户端省略）不算声明，只按服务绑定继续核对；协议层 `server.py` 要求这三项必填，
        因此经协议进来的请求一定带声明。
        """
        if scope is not None and scope != self.scope:
            return _refused(
                category=ContextFailureCategory.BINDING_MISMATCH,
                reason_code="scope_mismatch",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=ContextStageReached.COORDINATOR,
            )
        if source is not None and source != SOURCE_PI:
            return _refused(
                category=ContextFailureCategory.BINDING_MISMATCH,
                reason_code="source_mismatch",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=ContextStageReached.COORDINATOR,
            )
        if session_id is not None and session_id != self.session_id:
            return _refused(
                category=ContextFailureCategory.BINDING_MISMATCH,
                reason_code="session_decl_mismatch",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=ContextStageReached.COORDINATOR,
            )
        return read_pi_file_context(
            self.policy,
            self.scope,
            self.path,
            self.session_id,
            location=location,
            project_filter=project,
            before=before,
            after=after,
            ledger=self.ledger,
        )


def read_pi_file_context(
    policy: SessionPolicy,
    scope: str,
    path: str,
    session_id: str,
    *,
    location: object,
    project_filter: str | None = None,
    before: int = 2,
    after: int = 2,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_candidates: int = MAX_CONTEXT_CANDIDATES,
    max_bytes: int = MAX_CONTEXT_STAGE_BYTES,
    ledger: ReferenceLedger | None = None,
) -> ContextOutcome:
    """在一次授权读取里结算某条引用两侧的有限上下文。

    顺序即语义（任何一步不过都零片段）：① 入口判参（引用形态、两侧窗口值域）→ ② 账本精确取条目
    （缺失/过期/被淘汰同口径 `REF_EXPIRED`，**不打开任何文件**）→ ③ 绑定核对（服务指纹、来源、
    会话、项目收窄）→ ④ `_run_pi_file_pipeline` 重新读取（打开前 `authorize_query` + 打开后句柄
    最终路径再过 `authorize_store` + 文件身份核对 + 逐记录 `authorize_attribution` 只采信
    `TRUSTED_HEADER_CWD` + EOF 前置确认 + 暂存身份核对）→ ⑤ 本次同趟版本与账本版本逐项相等
    （卷号 + 文件标识 + 体积 + 整文件 SHA-256，任一不符即 `FILE_REPLACED`）→ ⑥ 锚点必须在已核对
    记录集中且与条目位置逐字段一致 → ⑦ 按行流位置取前 `before` 后 `after` 条（最多 21 条，
    条数按记录在行流中的位置结算，不按行号算术）→ ⑧ 逐条完整遮蔽 + 两条硬顶 →
    ⑨ `release(confirmed=True)` 一次性交出，并为每条已发布记录**新发放**引用。

    本函数不发现文件、不枚举目录、不读配置、不 `stat` 路径、不接受任何客户端提供的版本基准或行号：
    版本只能来自同趟授权读取，行号只能来自账本条目。授权被拒时 `PolicyDenied`/`SafeReadDenied`
    原样抛出（只带固定码），由协议层折算为明确错误；本模块不在结果里复制一份授权拒绝语义。
    """
    token = parse_reference_token(location)
    if token is None:
        return _refused(
            category=ContextFailureCategory.INVALID_ARGUMENT,
            coverage_scope=COVERAGE_SCOPE_NONE,
        )
    sides = _validated_sides(before, after)
    if sides is None:
        return _refused(
            category=ContextFailureCategory.INVALID_ARGUMENT,
            reason_code="window_out_of_range",
            coverage_scope=COVERAGE_SCOPE_NONE,
        )
    before_size, after_size = sides
    ref_ledger = ledger if ledger is not None else default_ledger()
    entry = lookup_reference(token, ledger=ref_ledger)
    if entry is None:
        # 缺失/过期/被淘汰三者不可分辨，也无需分辨：对外都是「这条引用不再可用」。
        return _refused(
            category=ContextFailureCategory.REF_EXPIRED,
            coverage_scope=COVERAGE_SCOPE_NONE,
        )
    service_key = service_binding_key(
        scope=scope, source=SOURCE_PI, path=path, session_id=session_id
    )
    mismatch = _binding_matches(
        entry, service_key=service_key, session_id=session_id, project_filter=project_filter
    )
    if mismatch is not None:
        return _refused(
            category=ContextFailureCategory.BINDING_MISMATCH,
            reason_code=mismatch,
            coverage_scope=COVERAGE_SCOPE_NONE,
        )

    candidates: list[StandardRecord] = []
    project_grants: dict[int, str] = {}
    capture_failed = False
    collector: SnippetCollector | None = None
    file_outcome: PiFileOutcome | None = None
    issued: tuple[str, ...] = ()
    stage = ContextStageReached.COORDINATOR

    def capture_candidate(record: StandardRecord) -> object:
        nonlocal capture_failed
        try:
            candidates.append(record)
            return None
        except MemoryError:
            capture_failed = True
            return PublicationRefusal.INTERNAL_FAILURE

    try:
        file_outcome = _run_pi_file_pipeline(
            policy,
            scope,
            path,
            session_id,
            project_filter=project_filter,
            max_line_bytes=max_line_bytes,
            max_total_bytes=max_total_bytes,
            max_lines=max_lines,
            max_candidates=max_candidates,
            max_bytes=max_bytes,
            _candidate_capture=capture_candidate,
            _project_grants=project_grants,
        )
        stage = ContextStageReached.FILE_PIPELINE

        if not file_outcome.complete or capture_failed:
            if capture_failed:
                stage = ContextStageReached.CANDIDATE_CAPTURE
            return _refused(
                category=(
                    ContextFailureCategory.CANDIDATE_CAPTURE_FAILED
                    if capture_failed
                    else ContextFailureCategory.INCOMPLETE
                ),
                stage=stage,
                file_outcome=file_outcome,
                window=0,
                records_withheld=len(candidates),
            )

        # 版本轴：本次同趟版本必须与账本逐项相等（卷号 + 文件标识 + 体积 + 整文件摘要）。
        # 这一步不做任何路径 stat：证据就是刚才那次授权读取自己的句柄身份与累加摘要，
        # 因此「引用发出后文件被换掉/改写过（含同大小改写）」只可能在这里被如实关掉。
        version = file_outcome.version
        if version is None or not version.complete:
            return _refused(
                category=ContextFailureCategory.INCOMPLETE,
                reason_code="version_unavailable",
                stage=stage,
                file_outcome=file_outcome,
                records_withheld=len(candidates),
            )
        if (
            version.volume != entry.volume
            or version.file_id != entry.file_id
            or version.size_bytes != entry.size_bytes
            or version.content_sha256 != entry.content_sha256
        ):
            return _refused(
                category=ContextFailureCategory.FILE_REPLACED,
                stage=stage,
                file_outcome=file_outcome,
                records_withheld=len(candidates),
                version_confirmed=False,
            )

        forms: list[tuple[int, int, str | None]] = []
        for record in candidates:
            form = _anchor_form(record)
            if form is None:
                return _refused(
                    category=ContextFailureCategory.WINDOW_UNRESOLVED,
                    stage=stage,
                    file_outcome=file_outcome,
                    records_withheld=len(candidates),
                    version_confirmed=True,
                )
            forms.append(form)

        # 会话轴：管线已核过两路证据（`file_outcome.complete` 蕴含暂存层身份已核对），这里只做
        # **逐条**的引用可用性判断：拿不出可比标识的记录无法证明属于这个会话，因此引用不能绑定
        # 到它（`REF_EXPIRED`），不拿「管线核过」替单条记录放行。
        asserted = _comparable_key(session_id)
        if asserted is None:
            return _refused(
                category=ContextFailureCategory.NOT_FOUND,
                stage=stage,
                file_outcome=file_outcome,
                records_withheld=len(candidates),
                version_confirmed=True,
            )

        anchor_index: int | None = None
        for index, (record, form) in enumerate(zip(candidates, forms, strict=True)):
            if form[0] != entry.line_no or form[1] != entry.ordinal:
                continue
            if not _labels_agree(entry.stream_label, form[2]):
                # 行流标签不逐字段一致：引用与记录不属于同一行流，不拿「行号相同」放行。
                continue
            if _comparable_key(record.session_id) != asserted:
                continue
            anchor_index = index
            break
        if anchor_index is None:
            return _refused(
                category=ContextFailureCategory.REF_EXPIRED,
                stage=stage,
                file_outcome=file_outcome,
                records_withheld=len(candidates),
                version_confirmed=True,
            )

        lower = max(0, anchor_index - before_size)
        upper = min(len(candidates), anchor_index + after_size + 1)
        selected = list(range(lower, upper))
        # 邻位身份轴（与锚点同一判据）：窗口是按记录在行流中的**位次**取的，邻记录不会因为
        # 「靠近锚点」就自动属于本会话。任何一条取不出可比标识、或取出的标识与断言不同，都是
        # 相邻关系不可证：零片段收尾，而不是把无法归属的正文交出去再给它发新引用。
        # 阶段词取 `window`：窗口已按位次选出，失败在窗口判定本身，不在文件管线。
        for index in selected:
            if _comparable_key(candidates[index].session_id) != asserted:
                return _refused(
                    category=ContextFailureCategory.WINDOW_UNRESOLVED,
                    reason_code="window_identity_conflict",
                    stage=ContextStageReached.WINDOW,
                    file_outcome=file_outcome,
                    window=len(selected),
                    records_withheld=len(candidates),
                    version_confirmed=True,
                )
        if len(selected) > MAX_WINDOW_RECORDS:
            # 不可达护栏：两侧各已限 0..10，加锚点至多 21 条。走到这里说明上游判据被改动，
            # 保守拒绝而不是把超出部分截下来交出去（截下来就是静默放宽窗口）。
            return _refused(
                category=ContextFailureCategory.WINDOW_UNRESOLVED,
                reason_code="window_limit_exceeded",
                stage=ContextStageReached.WINDOW,
                file_outcome=file_outcome,
                window=len(selected),
                records_withheld=len(candidates),
                version_confirmed=True,
            )

        stage = ContextStageReached.WINDOW
        effective_snippets = min(
            len(selected), MAX_CONTEXT_SNIPPETS, MAX_SNIPPETS_HARD_LIMIT
        )
        collector = SnippetCollector(
            source=SOURCE_PI,
            max_snippets=effective_snippets,
            max_total_chars=MAX_CONTEXT_TOTAL_CHARS,
        )
        for index in selected:
            refusal = collector.collect(candidates[index])
            if refusal is not None:
                # 遮蔽/预算首拒：收集器自己已整批清空，这里同样零片段收尾，不发布前缀。
                collector.release(confirmed=False)
                return _refused(
                    category=ContextFailureCategory.PUBLICATION_FAILED,
                    reason_code=refusal.value,
                    stage=ContextStageReached.PUBLICATION,
                    note=_PUBLICATION_REASONS.get(
                        refusal.value,
                        _PUBLICATION_REASONS[PublicationRefusal.NOT_CONFIRMED.value],
                    ),
                    file_outcome=file_outcome,
                    window=len(selected),
                    records_withheld=len(selected),
                    version_confirmed=True,
                )

        snippets = collector.release(confirmed=True)
        if len(snippets) != len(selected):
            return _refused(
                category=ContextFailureCategory.WINDOW_UNRESOLVED,
                reason_code="snippet_join_failed",
                stage=ContextStageReached.PUBLICATION,
                file_outcome=file_outcome,
                window=len(selected),
                records_withheld=len(selected),
                version_confirmed=True,
            )

        stage = ContextStageReached.PUBLICATION
        # 遮蔽与接线都过了才发放相邻记录的新引用：发放的是元数据绑定，正文不进账本。
        # 半途失败就整批改走发布失败出口——绝不出现「半数行已改写定位符」的半成品结果。
        window_records = [candidates[index] for index in selected]
        window_projects: list[str] = []
        for record in window_records:
            project_name = project_grants.get(id(record))
            if not isinstance(project_name, str) or not project_name:
                return _refused(
                    category=ContextFailureCategory.WINDOW_UNRESOLVED,
                    reason_code="attribution_incomplete",
                    stage=stage,
                    file_outcome=file_outcome,
                    window=len(selected),
                    records_withheld=len(selected),
                    version_confirmed=True,
                )
            window_projects.append(project_name)
        try:
            issued = _issue_references(
                window_records,
                window_projects,
                version=version,
                service_key=service_key,
                scope=scope,
                path=path,
                session_id=session_id,
                ledger=ref_ledger,
            )
        except ValueError:
            # 发放入口已把本批条目全部收回（不残留只能部分回指的引用）。
            return _refused(
                category=ContextFailureCategory.REFERENCE_ISSUE_FAILED,
                stage=stage,
                file_outcome=file_outcome,
                window=len(selected),
                records_withheld=len(selected),
                version_confirmed=True,
            )

        stage = ContextStageReached.PUBLICATION
        rows: list[dict[str, Any]] = []
        metadata_withheld = False
        truncated_output = False
        for offset, (index, snippet, reference) in enumerate(
            zip(selected, snippets, issued, strict=True)
        ):
            record = candidates[index]
            row, withheld = _row_for(
                record,
                window_projects[offset],
                SOURCE_PI,
                reference,
                snippet.snippet,
                snippet.redacted_count,
                snippet.truncated,
            )
            rows.append(row)
            metadata_withheld = metadata_withheld or withheld
            truncated_output = truncated_output or snippet.truncated

        quality_issues = _window_quality_issues(window_records)
        codes: list[str] = []
        notes: list[str] = [
            _context_reason_text(
                window_size=len(selected),
                anchor_index=anchor_index - lower,
                candidate_count=len(candidates),
            )
        ]
        if truncated_output:
            codes.append(ContextFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value)
            notes.append(_SNIPPET_TRUNCATION_NOTE)
        if metadata_withheld:
            codes.append(ContextFailureCategory.METADATA_WITHHELD.value)
            notes.append(_METADATA_WITHHELD_NOTE)
        if quality_issues:
            codes.append(ContextFailureCategory.RECORD_FIELD_OUT_OF_BOUNDS.value)
            notes.append(_QUALITY_ISSUE_NOTE)
        partial = bool(metadata_withheld or truncated_output or quality_issues)
        # 与 file_search 同构：先构造结果对象（`stage_reached` 内联取常量），构造成功后
        # 才把局部 `stage` 写成 `published`。构造期间抛错时局部仍停在 `publication`，
        # 外层失败出口不会报「已发布而结果为空」。
        outcome = ContextOutcome(
            complete=not partial,
            partial=partial,
            truncated=truncated_output,
            status="searched" if rows else "no_match",
            reason=codes[0] if codes else None,
            failure_category=codes[0] if codes else None,
            stage_reached=ContextStageReached.PUBLISHED.value,
            coverage_scope=COVERAGE_SCOPE_FILE,
            window_size=len(selected),
            records_withheld=len(candidates) - len(selected),
            version_confirmed=True,
            filter_error_codes=tuple(codes),
            quality_issues=quality_issues,
            notes=tuple(notes),
            results=tuple(rows),
            file=file_outcome,
        )
        stage = ContextStageReached.PUBLISHED
        return outcome
    except (PolicyDenied, SafeReadDenied):
        raise
    except Exception:  # noqa: BLE001 - 意外失败的原消息可能含路径/正文，不得进入结果
        # 本批已发放而未被任何结果行引用的令牌按点名收回：失败出口不给账本留下只能活到
        # TTL 的孤儿引用（`issued` 未赋值时为空元组，收回是空操作）。
        with contextlib.suppress(BaseException):
            ref_ledger.release(issued)
        # 走到异常出口就意味着结果对象没有交出：`published` 阶段词在这里不成立，
        # 收敛到 `publication`（宁报低一层，不报「已发布而结果为空」）。
        fail_stage = (
            ContextStageReached.PUBLICATION
            if stage is ContextStageReached.PUBLISHED
            else stage
        )
        return _refused(
            category=ContextFailureCategory.INTERNAL_FAILURE,
            coverage_scope=(
                COVERAGE_SCOPE_NONE if file_outcome is None else COVERAGE_SCOPE_FILE
            ),
            stage=fail_stage,
            file_outcome=file_outcome,
            records_withheld=len(candidates),
        )
    finally:
        # 候选正文与策略项目映射只存在于本函数栈内：任何出口（含中断）都在这里归还。
        candidates.clear()
        project_grants.clear()
        if collector is not None:
            with contextlib.suppress(BaseException):
                collector.discard(PublicationRefusal.NOT_CONFIRMED)


def _context_reason_text(
    *, window_size: int, anchor_index: int, candidate_count: int
) -> str:
    """一句固定说明：只由整数与固定片段拼成，不含正文、路径、引用原值、会话标识。"""
    if window_size <= 1:
        return (
            "锚点记录已通过两轴授权、身份核对与遮蔽，但它在本次已核对记录集中两侧都没有可交的"
            "相邻记录，因此上下文只含锚点本身；窗口外没有已核对的记录，其余候选不属于该窗口。"
            + _FILE_SCOPE_NOTE
        )
    return (
        f"上下文窗口交出 {window_size} 条已核对记录（锚点位于其中第 {anchor_index + 1} 条），"
        f"其余 {max(candidate_count - window_size, 0)} 条已核对候选不属于该窗口。"
        + _FILE_SCOPE_NOTE
    )


def _window_quality_issues(window: Sequence[StandardRecord]) -> tuple[str, ...]:
    """本次交出的窗口记录里的解析质量缺口：按固定 `IssueCode` 去重、保持首次出现顺序。

    `NON_PARTIAL_ISSUES` 三类（空行、无可检索文本、已知非文本块）不降级：它们是本模块已读懂的
    正常情况（`file_search` 与 `query` 同一口径）。其余任何质量码都使本行 `partial`，因为上下文
    是「逐条相邻」的输出，窗口内一条坏行会让相邻关系不再成立。口径只看已交出的记录：未入选的
    候选已经计入 `records_withheld`，拿它们降级对外行会把「没交出去的东西」算到结果头上。
    """
    seen: list[str] = []
    for record in window:
        for issue in record.issues:
            if issue in NON_PARTIAL_ISSUES:
                continue
            value = issue.value if isinstance(issue, IssueCode) else None
            if value is not None and value not in seen:
                seen.append(value)
    return tuple(seen)
