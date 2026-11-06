"""批准 pi 存储范围内的有界会话发现与多文件查询聚合（DES-API-01 增量九）。

本模块只回答两个问题：**哪些 pi 会话文件落在宿主批准的范围里**，以及**如何把这批文件的
查询结果聚合成一次有界、无回退的发布**。聚合服务与发现入口都是宿主进程内对象，路径与会话
标识断言由宿主显式持有，客户端永远传不进文件路径；协议层只按宿主绑定的实例数决定能否执行
（`PiMultiFileSearchService` 承接多文件 `search_sessions`，`PiMultiFileContextService` 按 ctxref
的绑定指纹把 `read_session_context` 路由回发放该引用的那个文件）。

有界发现（`discover_pi_session_files`）：
  存储根由宿主传入后逐条过 `authorize_store(kind=DIRECTORY)`，枚举只在授权通过的
  `readable_path` 下用 `os.scandir` 做元数据遍历——不打开任何文件、不读任何正文，
  因此不触碰真实会话凭据。文件级候选再逐条过 `authorize_store(kind=FILE)`：与打开
  （`authorize_read` 内部同一条轴）共用同一策略判定，链接/重解析逃逸在两条轴上都会
  被 `path_reparse`/`path_escape` 拒绝。会话标识断言取自授权后真实路径的文件名主干
  （pi 的存储布局约定），它**只是校验通道**：暂存层仍要求头部可信标识与断言两路一致
  才发布，形状不合的文件名直接拒为不可用断言。项目归属绝不从目录名猜测——归属只能
  来自可信头部 cwd 过 `authorize_attribution` 的映射。深度、条目数、文件数三个预算
  硬顶，任何一个触顶都会如实记入 `limit_hit` 并使 `complete` 为假。

多文件聚合（`PiMultiFileSearchService`）：
  逐文件跑既有的 `_run_pi_file_pipeline`（每文件独立会话断言与候选捕获），只有通过完整
  核对的文件才把候选拼进全局记录表；「记录序号 → 策略项目名」映射按全局偏移重建。
  过滤只调一次 `scan_filter`：`limit` 与扫描字符预算都是**全查询口径，不按文件重置**。
  未完整读取的文件其候选根本不进批；单文件授权/读取被拒只记该行状态，其余文件照常。
  发布是两阶段的：先逐文件片段收集判过（任一拒绝即整批零结果、无前缀），全部通过才
  逐文件释放并**按文件各自的绑定**发放 ctxref（service_key/scope/path/session_id/版本
  都取到该文件自己的授权事实），因此上下文令牌只能回到本次已批准的那条绑定。覆盖信息
  的层级口径固定为 `bounded_pi_file_set`：无匹配只声明「本次绑定的有界文件集合」扫完，
  绝不宣称整个 pi 来源。分层计数沿用既有约定：过滤层的 0 只表示过滤层未判定。

本模块不读取任何配置、环境变量或文件系统之外的数据；对外字典只含固定键、整数、布尔、
闭合枚举值与遮蔽后的片段（DES-SEC-01）。
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from .file_search import (
    COVERAGE_SCOPE_FILE,
    COVERAGE_SCOPE_NONE,
    SOURCE_PI,
    PiFileFailureCategory,
    _issue_references,
    _join_result,
    _public_key,
)
from .models import StandardRecord
from .policy import _IS_WINDOWS, PolicyDenied, SessionPolicy, TargetKind, _is_link
from .publication import (
    MAX_SNIPPET_TOTAL_CHARS,
    MAX_SNIPPETS_HARD_LIMIT,
    MAX_SNIPPETS_PER_FILE,
    PublicationRefusal,
    SnippetCollector,
)
from .query import (
    MAX_SESSION_ID_CHARS,
    MAX_TOTAL_SCAN_CHARS,
    SUPPORTED_SOURCES,
    FilterErrorCode,
    ScanFilterOutcome,
    SourceCoverage,
    scan_filter,
)
from .references import (
    ReferenceLedger,
    default_ledger,
    lookup_reference,
    parse_reference_token,
    service_binding_key,
)
from .safe_reader import (
    DEFAULT_MAX_TOTAL_BYTES,
    FileVersion,
    SafeReadDenied,
)
from .session_context import (
    ContextFailureCategory,
    ContextOutcome,
    ContextStageReached,
    PiFileContextService,
    _refused,
)
from .session_pipeline import PiFileOutcome, _run_pi_file_pipeline

__all__ = [
    "COVERAGE_SCOPE_MULTI",
    "MAX_AGGREGATE_SNIPPETS",
    "MAX_AGGREGATE_TOTAL_READ_BYTES",
    "MAX_AGGREGATE_TOTAL_SCAN_CHARS",
    "MAX_DISCOVERY_DEPTH",
    "MAX_DISCOVERY_ENTRIES",
    "MAX_DISCOVERY_FILES",
    "MAX_DISCOVERY_ROOTS",
    "MAX_FILES_PER_QUERY",
    "MAX_PROTOCOL_LIMIT",
    "AggregateFailureCategory",
    "AggregateStageReached",
    "PiAggregateSearchOutcome",
    "PiMultiFileContextService",
    "PiMultiFileSearchService",
    "SessionDiscoveryOutcome",
    "SessionFileRef",
    "discover_pi_session_files",
]

#: 聚合结论的覆盖层级：只声明本次绑定的有界文件集合，不声明整个 pi 来源扫完。
COVERAGE_SCOPE_MULTI = "bounded_pi_file_set"

#: 单文件发现/聚合共用的会话文件后缀（大小写不敏感）。
_SESSION_SUFFIX = ".jsonl"

#: 发现层一次最多交付的会话文件数（宿主预算可下调，不能上调过本硬顶）。
MAX_DISCOVERY_FILES = 64

#: 发现层自存储根向下的最大遍历深度（存储根本身记 0）。
MAX_DISCOVERY_DEPTH = 8

#: 发现层最多检视的目录条目数（含目录与非会话文件：预算为「看过多少」而设）。
MAX_DISCOVERY_ENTRIES = 20_000

#: 发现层一次接受的存储根条数硬顶：被拒根逐条进公开字典，根数不设顶就是无界的外泄面。
MAX_DISCOVERY_ROOTS = 16

#: 聚合查询一次接受的文件数硬顶：候选驻留内存由「文件数 × 每文件暂存预算」界定。
MAX_FILES_PER_QUERY = 64

#: 聚合发布的全局片段上限：等于单批发放硬顶，保证每文件的 ctxref 批次永不越界。
MAX_AGGREGATE_SNIPPETS = MAX_SNIPPETS_HARD_LIMIT

#: 聚合读取的总字节预算（所有文件共享；触顶后未跑的文件如实记 skipped_budget）。
MAX_AGGREGATE_TOTAL_READ_BYTES = 32 * 1024 * 1024

#: 聚合过滤的总扫描字符预算（全查询口径；等于 `scan_filter` 的默认总预算）。
MAX_AGGREGATE_TOTAL_SCAN_CHARS = MAX_TOTAL_SCAN_CHARS

#: 协议层 `search_sessions.limit` 的对外上界；聚合服务在宿主侧自行复核同一边界。
MAX_PROTOCOL_LIMIT = 100

#: 读取预算的最低可用值：与 `authorize_read` 的下界一致，剩余低于它就不再开新文件。
_MIN_READ_BUDGET = 16

_MULTI_SCOPE_NOTE = (
    "覆盖范围仅限本次绑定的有界文件集合，不声明整个 pi 来源已扫完。"
)
_LAYERED_COUNTER_NOTE = (
    "计数按层给出：records_scanned=0 只表示查询过滤层未判定这些记录，不表示文件未被读取或解析。"
)
_SNIPPET_TRUNCATION_NOTE = "一个或多个遮蔽片段按输出上限截断。"
_METADATA_WITHHELD_NOTE = (
    "存在形态不可外的短元数据（路径形态、含分隔符/空白或超长），已降为 null 并记为覆盖不完整。"
)
_FILES_UNUSABLE_NOTE = (
    "绑定的文件集合没有任何文件通过完整核对；聚合未发布结果，零结果不等于无匹配。"
)
_QUOTA_NOTE = (
    "单文件片段配额或全查询返回上限裁掉了部分命中；returned_count 是实际发布行数。"
)


class AggregateFailureCategory(StrEnum):
    """聚合结论外出的失败类别：闭合集合，不接受数据侧字符串造键。

    单文件层内的类别继续用 `PiFileFailureCategory` 与 `RefusalCode`/`ReadRefusalCode`
    （都是闭合枚举），本枚举只补聚合层独有的口径。
    """

    SCOPE_MISMATCH = "scope_mismatch"  # 请求 scope 与已绑定范围不符
    SOURCE_UNSUPPORTED = "source_unsupported"  # 点名的来源不在聚合服务职责内
    INVALID_REQUEST = "invalid_request"  # limit 形状/范围不合协议边界
    FILE_INCOMPLETE = "file_incomplete"  # 有绑定文件未通过单文件完整核对
    READ_BUDGET_EXHAUSTED = "read_budget_exhausted"  # 读预算触顶，其后的文件未打开
    FILES_UNUSABLE = "files_unusable"  # 没有任何文件通过完整核对
    INTERNAL_FAILURE = "internal_failure"  # 聚合协调器内的意外失败
    PUBLICATION_FAILED = "publication_failed"  # 遮蔽或接线失败，整批未发布
    MATCH_JOIN_FAILED = "match_join_failed"  # 命中下标越界、重复或落在未发布文件段
    SNIPPET_JOIN_FAILED = "snippet_join_failed"  # 片段数与命中数不等
    SNIPPET_OUTPUT_TRUNCATED = "snippet_output_truncated"  # 遮蔽层按输出上限截过片
    METADATA_WITHHELD = "metadata_withheld"  # 短元数据形态不合，已降为 null


class AggregateStageReached(StrEnum):
    """聚合运行最远走到哪一层（闭合类别）；通过与否由各层整数与行状态回答。"""

    COORDINATOR = "coordinator"  # 还在请求校验/文件循环
    FILE_PIPELINE = "file_pipeline"  # 文件循环走完，未交给过滤层（没有任何可用文件）
    FILTER = "filter"  # 已交给过滤层，但过滤层未给出可用结论
    PUBLICATION = "publication"  # 走到遮蔽/接线，但未发布
    PUBLISHED = "published"  # 已发布（结果或可证明的集合内空结果）


class _FileRowStatus(StrEnum):
    """一个绑定文件在聚合结论里的行状态：闭合集合，不含任何路径或原值。"""

    SEARCHED = "searched"  # 完整核对 + 候选全部进批且被过滤层扫完
    INCOMPLETE = "incomplete"  # 文件管线/身份/归属/捕获任一未通过
    REFUSED = "refused"  # 策略或安全读取在打开前拒绝了这个文件
    SKIPPED_BUDGET = "skipped_budget"  # 读预算触顶，这个文件根本没打开


class FilterErrorTag(StrEnum):
    """聚合 pi 行外出的补充错误码：只列过滤层闭合码之外聚合层独有的口径。"""

    SOURCE_NOT_SCANNED = "source_not_scanned"  # 沿用过滤层同名码的字面值
    READ_BUDGET_EXHAUSTED = "read_budget_exhausted"
    FILES_UNUSABLE = "files_unusable"
    PUBLICATION_FAILED = "publication_failed"


@dataclass(frozen=True)
class SessionFileRef:
    """宿主提供的一条会话文件绑定：授权后的文件路径 + 独立持有的会话标识断言。

    构造即校验（宿主边界一次判形，内部不再重复防御）：`path` 必须是非空字面字符串
    且形状过 `authorize_store` 的形状门（在发现流程里由策略再判，这里只判类型与非空）；
    `session_id` 必须过可外出的短标识形态门（ASCII 字母数字与 ``-_``、``.``，不含路径
    形态、空白与分隔符，≤`MAX_SESSION_ID_CHARS`）——它是校验通道里的**断言**，最终仍需
    可信头部两路一致才可发布，形状不合的标识连断言资格都没有。
    """

    path: str
    session_id: str

    def __post_init__(self) -> None:
        if self.path.__class__ is not str or not self.path:
            raise ValueError("SessionFileRef.path must be a non-empty string")
        if self.session_id.__class__ is not str or not self.session_id:
            raise ValueError("SessionFileRef.session_id must be a non-empty string")
        if _public_key(self.session_id, MAX_SESSION_ID_CHARS)[0] is None:
            raise ValueError("SessionFileRef.session_id is not a publishable identifier")


@dataclass(frozen=True)
class SessionDiscoveryOutcome:
    """一次有界发现的结论：交付的文件绑定 + 只含计数与闭合码的遍历账目。

    `complete` 只回答「遍历本身在预算内走完了所有授权根」；它**不**声明发现覆盖了整个
    pi 来源——预算、深度与文件数都限定的是宿主给出的根集合内的一个有限视野。被拒的根
    与文件都以固定原因码计数（不落任何路径）。`files` 是宿主侧对象列表，不进对外快照。
    """

    files: tuple[SessionFileRef, ...]
    complete: bool
    roots_total: int
    roots_refused: tuple[dict[str, Any], ...]
    dirs_scanned: int
    dirs_not_entered: int
    entries_scanned: int
    files_denied: tuple[dict[str, Any], ...]
    symlink_files_skipped: int
    symlink_dirs_skipped: int
    symlink_generic_skipped: int
    entry_unavailable: bool
    session_assertions_rejected: int
    walk_errors: int
    limit_hit: bool

    @property
    def files_found(self) -> int:
        """最终交付的会话文件数（与 `files` 等长；重复路径已合并）。"""
        return len(self.files)

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "coverage_scope": COVERAGE_SCOPE_MULTI,
            "roots_total": self.roots_total,
            "roots_refused": [dict(row) for row in self.roots_refused],
            "dirs_scanned": self.dirs_scanned,
            "dirs_not_entered": self.dirs_not_entered,
            "entries_scanned": self.entries_scanned,
            "files_found": self.files_found,
            "files_denied": [dict(row) for row in self.files_denied],
            "symlink_files_skipped": self.symlink_files_skipped,
            "symlink_dirs_skipped": self.symlink_dirs_skipped,
            "symlink_generic_skipped": self.symlink_generic_skipped,
            "entry_unavailable": self.entry_unavailable,
            "session_assertions_rejected": self.session_assertions_rejected,
            "walk_errors": self.walk_errors,
            "limit_hit": self.limit_hit,
        }


class _CaptureSink:
    """逐文件的候选捕获器：与单文件协调器同判据（只兜 `MemoryError`）。

    其余异常不吞——它们由外层统一收敛成 `internal_failure`，与既有单文件路径同构：
    捕获失败的文件其候选绝不进发布批。故意做成可调用对象而不是循环内闭包，
    避免回调绑定到随迭代重名的局部变量。
    """

    __slots__ = ("failed", "records")

    def __init__(self) -> None:
        self.records: list[StandardRecord] = []
        self.failed = False

    def __call__(self, record: StandardRecord) -> object:
        try:
            self.records.append(record)
            return None
        except MemoryError:
            self.failed = True
            return PublicationRefusal.INTERNAL_FAILURE


def _budget(value: object, hard_max: int, name: str) -> int:
    """发现预算参数一次判形：字面正 int、不越硬顶；越界即编程侧 ValueError。"""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive int")
    if value > hard_max:
        raise ValueError(f"{name} exceeds the hard cap {hard_max}")
    return value


def _has_more_entries(iterator: Any) -> bool:
    """配额触顶后向前探看是否还有未检视条目：真裁掉才算缺口，恰收满不算。

    探测本身失败（目录不可续读）保守判「还有」：宁可多记一次 limit_hit，
    也不让没看完的遍历自称完整。
    """
    try:
        return next(iterator, None) is not None
    except OSError:
        return True


def discover_pi_session_files(
    policy: SessionPolicy,
    scope: str,
    store_roots: Sequence[str],
    *,
    max_files: int = MAX_DISCOVERY_FILES,
    max_depth: int = MAX_DISCOVERY_DEPTH,
    max_entries: int = MAX_DISCOVERY_ENTRIES,
) -> SessionDiscoveryOutcome:
    """在宿主给出的 pi 存储根内做有界的会话文件发现，产出 `SessionFileRef` 绑定清单。

    发现与打开共用策略：每个根先过 `authorize_store(kind=DIRECTORY)`，每个 `.jsonl`
    候选文件再过 `authorize_store(kind=FILE)`；两者内部都会走字面包含、真实包含与
    链接链检查，因此指向范围外的符号链接/重解析点在这里就与打开时同样被拒。遍历只读
    目录元数据（`os.scandir` + `DirEntry` 的 `follow_symlinks=False` 判型），**不打开、
    不读取任何文件内容**，凭据不在本层的可见面上。文件名主干作为会话标识断言进绑定，
    形状不合者记数不交付（断言永远只是校验通道，发布仍要头部两路一致）。
    """
    if not isinstance(policy, SessionPolicy):
        raise TypeError("discover_pi_session_files requires a SessionPolicy")
    if scope.__class__ is not str or not scope:
        raise ValueError("scope must be a non-empty string")
    if not isinstance(store_roots, (list, tuple)) or not store_roots:
        raise ValueError("store_roots must be a non-empty list or tuple")
    if len(store_roots) > MAX_DISCOVERY_ROOTS:
        raise ValueError(
            f"store_roots must not exceed {MAX_DISCOVERY_ROOTS} entries"
        )
    for root in store_roots:
        if root.__class__ is not str or not root:
            raise ValueError("every store root must be a non-empty string")
    max_files = _budget(max_files, MAX_DISCOVERY_FILES, "max_files")
    max_depth = _budget(max_depth, MAX_DISCOVERY_DEPTH, "max_depth")
    max_entries = _budget(max_entries, MAX_DISCOVERY_ENTRIES, "max_entries")

    authorized: list[str] = []
    roots_refused: list[dict[str, Any]] = []
    for index, root in enumerate(store_roots):
        try:
            grant = policy.authorize_store(scope, SOURCE_PI, root, kind=TargetKind.DIRECTORY)
        except PolicyDenied as denial:
            roots_refused.append({"index": index, "reason": denial.code.value})
        else:
            authorized.append(grant.readable_path)

    collected: dict[str, SessionFileRef] = {}
    files_denied: dict[str, int] = {}
    dirs_scanned = 0
    dirs_not_entered = 0
    entries_scanned = 0
    symlink_files_skipped = 0
    symlink_dirs_skipped = 0
    session_rejected = 0
    walk_errors = 0
    entry_unavailable = False
    symlink_generic_skipped = 0
    limit_hit = False
    truncated_walk = False

    stack: list[tuple[str, int]] = [(root, 0) for root in reversed(authorized)]
    pending_visible = False
    while stack:
        directory, depth = stack.pop()
        try:
            it = os.scandir(directory)
        except OSError:
            # 根授权通过后目录却不可列（竞态删除/权限）：记一个固定类别，不猜内容。
            walk_errors += 1
            truncated_walk = True
            continue
        with it:
            dirs_scanned += 1
            for entry in it:
                entries_scanned += 1
                if entries_scanned > max_entries:
                    limit_hit = True
                    truncated_walk = True
                    pending_visible = False
                    break
                try:
                    is_link = entry.is_symlink()
                    # Windows 目录联接点在 Windows 上不是符号链接：与策略层同用
                    # `policy._is_link` 的重解析属性判据，发现与打开才同判。
                    if not is_link and _IS_WINDOWS:
                        is_link = _is_link(entry.path)
                    is_file = entry.is_file(follow_symlinks=False)
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    # 条目形态都拿不到：这一批目录项没检视成，整次发现不得自称完整。
                    walk_errors += 1
                    entry_unavailable = True
                    continue
                if is_link:
                    # 链接目录不进入遍历（发现与打开同拒链接逃逸）；链接文件也不作候选。
                    # 计数按链接**目标**判型：follow_symlinks=False 下链接本身既非文件
                    # 也非目录，直接复用上面的判型会让 dirs/files 两个计数恒零。目标不
                    # 可达或判型失败时记 generic，不猜测形态。
                    try:
                        target_is_dir = entry.is_dir(follow_symlinks=True)
                        target_is_file = (
                            not target_is_dir
                            and entry.is_file(follow_symlinks=True)
                        )
                    except OSError:
                        target_is_dir = False
                        target_is_file = False
                    if target_is_dir:
                        symlink_dirs_skipped += 1
                    elif target_is_file:
                        symlink_files_skipped += 1
                    else:
                        symlink_generic_skipped += 1
                    continue
                name = entry.name
                if is_dir:
                    if depth < max_depth:
                        stack.append((entry.path, depth + 1))
                        pending_visible = True
                    else:
                        # 触深未进入的目录是如实的覆盖缺口：不得计入「走完了根」。
                        dirs_not_entered += 1
                    continue
                if not is_file or not name.lower().endswith(_SESSION_SUFFIX):
                    continue
                try:
                    file_grant = policy.authorize_store(
                        scope, SOURCE_PI, entry.path, kind=TargetKind.FILE
                    )
                except PolicyDenied as denial:
                    files_denied[denial.code.value] = (
                        files_denied.get(denial.code.value, 0) + 1
                    )
                    continue
                stem = os.path.splitext(os.path.basename(file_grant.readable_path))[0]
                session_id = stem
                if "_" in stem:
                    # Pi 典型命名格式: <timestamp>_<uuid>
                    tail = stem.split("_", 1)[1]
                    if _public_key(tail, MAX_SESSION_ID_CHARS)[0] is not None:
                        session_id = tail
                if _public_key(session_id, MAX_SESSION_ID_CHARS)[0] is None:
                    session_rejected += 1
                    continue
                if file_grant.readable_path in collected:
                    continue
                collected[file_grant.readable_path] = SessionFileRef(
                    path=file_grant.readable_path, session_id=session_id
                )
                if len(collected) >= max_files:
                    # 文件数触顶：截断前先判「后面是否还有未看的条目」——最后一条恰好
                    # 收满不等于覆盖缺口；但栈里还排着未进入的子目录时，后面的候选
                    # 根本没机会被看，同样是真裁掉，必须记 limit_hit。
                    limit_hit = _has_more_entries(it) or bool(stack)
                    truncated_walk = truncated_walk or limit_hit
                    pending_visible = False
                    break
            else:
                # 本目录自然走完：栈里还有兄弟目录时保持「后面还有条目」的事实；
                # 目录打开失败/条目越限的 break 不走这里，保守为 False。
                pending_visible = bool(stack)
            if limit_hit:
                break

    denial_rows = tuple(
        {"reason": reason, "count": files_denied[reason]} for reason in sorted(files_denied)
    )
    files = tuple(collected[path] for path in sorted(collected))
    return SessionDiscoveryOutcome(
        files=files,
        complete=(
            not truncated_walk
            and not limit_hit
            and not roots_refused
            and not denial_rows
            and dirs_not_entered == 0
            and session_rejected == 0
            and walk_errors == 0
            # 栈非空即被 break 摘下的未完成遍历；末条恰触顶不记 limit_hit，由这里兜住。
            and not bool(stack)
            # 目录扫空不等于走完了它下面的层次：只有被裁掉的尾部条目才是缺口。
            and not (pending_visible and entries_scanned >= max_entries)
        ),
        roots_total=len(store_roots),
        roots_refused=tuple(roots_refused),
        dirs_scanned=dirs_scanned,
        dirs_not_entered=dirs_not_entered,
        entries_scanned=entries_scanned,
        files_denied=denial_rows,
        symlink_files_skipped=symlink_files_skipped,
        symlink_dirs_skipped=symlink_dirs_skipped,
        symlink_generic_skipped=symlink_generic_skipped,
        entry_unavailable=entry_unavailable,
        session_assertions_rejected=session_rejected,
        walk_errors=walk_errors,
        limit_hit=limit_hit,
    )


@dataclass(frozen=True)
class PiAggregateSearchOutcome:
    """一次多文件聚合查询的安全结论：已发布行 + 逐来源覆盖 + 逐文件账目。

    与单文件结论同一分层纪律：`total_matched` 是过滤层**已扫描**记录的匹配数，不是返回
    数；`returned_count` 才是已发布行数；发布失败记零而不留前缀。`files` 逐行只含序号、
    闭合状态码、该文件的 `file` 快照（无路径、无版本）与过滤层归属计数；`coverage` 的
    pi 行覆盖层级为 `bounded_pi_file_set`。`complete` 为真要求：集合内每个文件都完整核对、
    其候选全部被过滤层扫完、过滤层自身完整、且发布成功——任何一环缺失都只能在
    `partial`/行状态里可见，绝不以 `complete=True` 宣称集合无匹配之外的结论。
    """

    complete: bool
    partial: bool
    truncated: bool
    total_matched: int
    total_scanned: int
    skipped_records: int
    results: tuple[dict[str, Any], ...]
    coverage: tuple[dict[str, Any], ...]
    files: tuple[dict[str, Any], ...]
    rejected: bool = False
    reason: str | None = None
    coverage_scope: str = COVERAGE_SCOPE_MULTI
    stage_reached: str = AggregateStageReached.COORDINATOR.value
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
            "results": list(self.results),
            "coverage": list(self.coverage),
            "files": list(self.files),
        }


@dataclass
class _FileSegment:
    """聚合运行中一个绑定文件的内部账目：候选、映射、管线结论与发布中间态。"""

    index: int
    ref: SessionFileRef
    status: _FileRowStatus
    outcome: PiFileOutcome | None = None
    reason: str | None = None
    records: list[StandardRecord] = field(default_factory=list)
    projects: list[str | None] = field(default_factory=list)
    match_positions: list[int] = field(default_factory=list)
    skipped_tail: int = 0
    snippets: tuple[Any, ...] = ()
    tokens: list[str] = field(default_factory=list)


def _rejected_outcome(
    reason: str, *, stage: AggregateStageReached
) -> PiAggregateSearchOutcome:
    return PiAggregateSearchOutcome(
        complete=False,
        partial=False,
        truncated=False,
        total_matched=0,
        total_scanned=0,
        skipped_records=0,
        results=(),
        coverage=(),
        files=(),
        rejected=True,
        reason=reason,
        coverage_scope=COVERAGE_SCOPE_NONE,
        stage_reached=stage.value,
        failure_category=reason,
    )


def _file_row(segment: _FileSegment) -> dict[str, Any]:
    """一条对外文件行：固定键 + 整数/布尔 + 闭合枚举值；快照本身不含路径。"""
    row: dict[str, Any] = {
        "index": segment.index,
        "status": segment.status.value,
        "coverage_scope": COVERAGE_SCOPE_FILE,
        "records_captured": len(segment.records),
        "filter_scanned": 0,
        "filter_skipped": 0,
        "returned_count": 0,
        "reason": segment.reason,
        "file": segment.outcome.as_public_dict() if segment.outcome is not None else None,
    }
    if segment.outcome is not None and segment.outcome.read.reason is not None:
        row["read_stop"] = segment.outcome.read.reason.value
    return row


def _aggregate_pi_row(scanned: ScanFilterOutcome | None) -> dict[str, Any]:
    """从过滤层结论折算聚合层的 pi 覆盖行（层级换成有界文件集合）。"""
    source_row: SourceCoverage | None = None
    if scanned is not None:
        for row in scanned.coverage:
            if row.source == SOURCE_PI:
                source_row = row
                break
    if source_row is None:
        return {
            "source": SOURCE_PI,
            "coverage_scope": COVERAGE_SCOPE_MULTI,
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
                f"{_MULTI_SCOPE_NOTE}"
            ),
        }
    row = source_row.as_public_dict()
    row["coverage_scope"] = COVERAGE_SCOPE_MULTI
    row["reason"] = f"{row['reason']}{_MULTI_SCOPE_NOTE}"
    return row


def _validate_bound_files(
    *,
    label: str,
    policy: Any,
    scope: Any,
    files: Any,
    ledger: Any,
) -> None:
    """两个多文件服务共用的构造门禁（绑定错误在绑定时就报错，不留到运行时）。

    工具层只会跑宿主显式注入的对象，所以类型错就是接线错误：`files` 必须是已校验过的
    `SessionFileRef` 字面序列，字符串/字节这种「伪装成文件列表」的形状直接拒，不逐字符
    迭代；路径永不从客户端进入这条通道。
    """
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


@dataclass(frozen=True)
class PiMultiFileSearchService:
    """宿主侧多文件聚合查询绑定：一套策略/范围 + 一组已批准的会话文件引用 + 共享账本。

    构造完全显式：不做配置查询、不读文件系统、不启动服务；`files` 为空即拒（聚合查询
    一个文件都没有时，「无匹配」是无根据的宣称）。文件数超 `MAX_FILES_PER_QUERY` 即拒
    ——预算收缩比放宽更容易被误用，所以只设上界不放开口子。`ledger` 允许为 None（沿用
    宿主共享的默认账本），与单文件服务的语义一致。
    """

    policy: SessionPolicy
    scope: str
    files: Sequence[SessionFileRef]
    ledger: ReferenceLedger | None = None

    def __post_init__(self) -> None:
        _validate_bound_files(
            label="PiMultiFileSearchService",
            policy=self.policy,
            scope=self.scope,
            files=self.files,
            ledger=self.ledger,
        )
        # Materialize the sequence once: later host mutation of the list must
        # not silently change what a bound service considers approved.
        object.__setattr__(self, "files", tuple(self.files))

    def context_service(self, index: int) -> PiFileContextService:
        """为集合内第 `index` 个绑定文件构造同账本的上下文读取服务（宿主进程内对象）。

        ctxref 的绑定四元组（scope/source/path/session_id）逐文件独立发放，所以读取某条
        引用必须走**该文件**的上下文服务；用别的文件的绑定去读会撞上既有绑定核对而拒绝，
        这正是「令牌只能回到本次已批准绑定」的执行面。
        """
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.files):
            raise ValueError("context_service index out of bounds")
        ref = self.files[index]
        return PiFileContextService(
            policy=self.policy,
            scope=self.scope,
            path=ref.path,
            session_id=ref.session_id,
            ledger=self.ledger,
        )

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
        """聚合查询入口：返回可直接 JSON 化的公开结论（见 `as_public_dict`）。"""
        if scope is not None and scope != self.scope:
            zero = PiAggregateSearchOutcome(
                complete=False,
                partial=False,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=0,
                results=(),
                coverage=(),
                files=(),
                rejected=True,
                reason=AggregateFailureCategory.SCOPE_MISMATCH.value,
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage_reached=AggregateStageReached.COORDINATOR.value,
                failure_category=AggregateFailureCategory.SCOPE_MISMATCH.value,
            )
            return zero.as_public_dict()
        return _search_pi_files(
            self,
            query=query,
            sources=sources,
            start=start,
            end=end,
            project=project,
            limit=limit,
        ).as_public_dict()


@dataclass(frozen=True)
class PiMultiFileContextService:
    """多文件集合的上下文读取路由：按 ctxref 的绑定指纹回到**发放它的那个**文件。

    与 `PiMultiFileSearchService` 同一绑定形状（一套策略/范围 + 同一组
    `SessionFileRef` + 可选共享账本），因此宿主可以成对注入，引用才能跨服务核对。

    路由只做一件事：在**不打开任何文件**的前提下，把客户端传来的引用在本次绑定的
    ≤`MAX_FILES_PER_QUERY` 个文件里找回它属于哪一条（`service_binding_key` 是四元组
    (scope, source, path, session_id) 的定长摘要，逐文件 sha256 只用到宿主自持的路径）。
    找回后仍把**客户端声明逐字透传**给该文件的 `PiFileContextService.read`：scope/source/
    session 声明矛盾、版本重写、窗口未定、遮蔽失败那些核对完全沿用单文件路径，本类不拿
    「服务已经绑好了」替任何声明放行。找不到对应文件就是 `binding_mismatch`：引用只能回到
    本次已批准的那条绑定，把 A 文件的令牌拿去问 B 文件在协议上不存在。
    """

    policy: SessionPolicy
    scope: str
    files: Sequence[SessionFileRef]
    ledger: ReferenceLedger | None = None

    def __post_init__(self) -> None:
        _validate_bound_files(
            label="PiMultiFileContextService",
            policy=self.policy,
            scope=self.scope,
            files=self.files,
            ledger=self.ledger,
        )
        object.__setattr__(self, "files", tuple(self.files))

    def context_service(self, index: int) -> PiFileContextService:
        """为集合内第 `index` 个绑定文件构造同账本的单文件上下文服务（宿主进程内对象）。"""
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index < len(self.files)
        ):
            raise ValueError("context_service index out of bounds")
        ref = self.files[index]
        return PiFileContextService(
            policy=self.policy,
            scope=self.scope,
            path=ref.path,
            session_id=ref.session_id,
            ledger=self.ledger,
        )

    def _route_index(self, service_key: str) -> int | None:
        """在本次绑定集合里找出与账本指纹对应的文件下标（纯摘要比较，不开文件）。"""
        for index, ref in enumerate(self.files):
            candidate = service_binding_key(
                scope=self.scope,
                source=SOURCE_PI,
                path=ref.path,
                session_id=ref.session_id,
            )
            if candidate == service_key:
                return index
        return None

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
        """路由后读一段受限上下文；参数全为标量，客户端无法提供任何路径或版本基准。"""
        # 先查客户端自身的声明矛盾：这两项与单文件服务同口径，不需要账本也不需要文件。
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
        token = parse_reference_token(location)
        if token is None:
            return _refused(
                category=ContextFailureCategory.INVALID_ARGUMENT,
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=ContextStageReached.COORDINATOR,
            )
        ledger = self.ledger if self.ledger is not None else default_ledger()
        entry = lookup_reference(token, ledger=ledger)
        # 缺失/过期/被淘汰：不猜它是哪个文件，不开任何文件（与单文件路径同口径）。
        if entry is None:
            return _refused(
                category=ContextFailureCategory.REF_EXPIRED,
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=ContextStageReached.COORDINATOR,
            )
        index = self._route_index(entry.service_key)
        if index is None:
            return _refused(
                category=ContextFailureCategory.BINDING_MISMATCH,
                reason_code="service_binding",
                coverage_scope=COVERAGE_SCOPE_NONE,
                stage=ContextStageReached.COORDINATOR,
            )
        service = self.context_service(index)
        return service.read(
            scope=scope,
            source=source,
            session_id=session_id,
            location=location,
            project=project,
            before=before,
            after=after,
        )


def _unsupported_row(source: str) -> dict[str, Any]:
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
        "filter_errors": [AggregateFailureCategory.SOURCE_UNSUPPORTED.value],
        "quality_issues": [],
        "reason": f"聚合服务只查询已批准的 pi 文件集合。{_MULTI_SCOPE_NOTE}",
    }


def _merged_coverage(pi_rows: Sequence[dict[str, Any]], requested: Sequence[str]):
    by_source = {row["source"]: row for row in pi_rows}
    for source in requested:
        if source != SOURCE_PI:
            by_source[source] = _unsupported_row(source)
    return tuple(
        by_source[source] for source in SUPPORTED_SOURCES if source in by_source
    )


def _search_pi_files(
    service: PiMultiFileSearchService,
    *,
    query: str | None,
    sources: Sequence[str] | None,
    start: datetime | str | None,
    end: datetime | str | None,
    project: str | None,
    limit: int,
) -> PiAggregateSearchOutcome:
    """聚合主流程：请求校验 → 逐文件管线 → 一次全查询口径过滤 → 两阶段发布。"""
    requested_sources = (SOURCE_PI,) if sources is None else tuple(sources)
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_PROTOCOL_LIMIT
    ):
        return _rejected_outcome(
            AggregateFailureCategory.INVALID_REQUEST.value,
            stage=AggregateStageReached.COORDINATOR,
        )

    preflight = scan_filter(
        [],
        query=query,
        start=start,
        end=end,
        project=project,
        sources=requested_sources,
        limit=min(limit, MAX_AGGREGATE_SNIPPETS),
    )
    if preflight.rejected:
        reason = (
            preflight.reason.value
            if preflight.reason
            else AggregateFailureCategory.INTERNAL_FAILURE.value
        )
        return _rejected_outcome(reason, stage=AggregateStageReached.COORDINATOR)

    if SOURCE_PI not in requested_sources:
        rows = tuple(_unsupported_row(source) for source in requested_sources)
        return PiAggregateSearchOutcome(
            complete=False,
            partial=True,
            truncated=False,
            total_matched=0,
            total_scanned=0,
            skipped_records=0,
            results=(),
            coverage=rows,
            files=(),
            reason=AggregateFailureCategory.SOURCE_UNSUPPORTED.value,
            coverage_scope=COVERAGE_SCOPE_NONE,
            failure_category=AggregateFailureCategory.SOURCE_UNSUPPORTED.value,
        )

    policy = service.policy
    scope = service.scope
    segments: list[_FileSegment] = []
    all_records: list[StandardRecord] = []
    mappings: dict[int, str] = {}
    scanned: ScanFilterOutcome | None = None
    issued_tokens: list[str] = []
    open_collectors: dict[int, SnippetCollector] = {}
    read_budget_left = MAX_AGGREGATE_TOTAL_READ_BYTES
    read_budget_hit = False
    any_incomplete = False
    stage = AggregateStageReached.COORDINATOR

    try:
        # ---- 文件循环：每文件独立授权、独立断言、独立候选捕获 ----
        for index, ref in enumerate(service.files):
            sink = _CaptureSink()
            candidates = sink.records
            grants: dict[int, str] = {}

            if read_budget_left < _MIN_READ_BUDGET:
                # 预算触顶后的文件根本没打开：如实记 skipped_budget，不假装扫过。
                read_budget_hit = True
                any_incomplete = True
                segments.append(
                    _FileSegment(
                        index=index,
                        ref=ref,
                        status=_FileRowStatus.SKIPPED_BUDGET,
                        reason=AggregateFailureCategory.READ_BUDGET_EXHAUSTED.value,
                    )
                )
                continue
            per_file_bytes = min(DEFAULT_MAX_TOTAL_BYTES, read_budget_left)
            try:
                file_outcome = _run_pi_file_pipeline(
                    policy,
                    scope,
                    ref.path,
                    ref.session_id,
                    # 聚合路径不把 `project_filter` 下推进单文件管线：项目收窄是过滤层的
                    # 文档语义（`scan_filter` 用全局归属映射精确排除），若在此处下推，
                    # 其他项目的文件会被误标为读取不完整——那是收窄不是覆盖缺口。
                    # 归属轴的双重核对不因此减少：候选进批仍要求逐记录 authorize_attribution
                    # 通过（无 project 断言），发布行仍取该唯一命中项目名。
                    max_total_bytes=per_file_bytes,
                    _candidate_capture=sink,
                    _project_grants=grants,
                )
            except (PolicyDenied, SafeReadDenied) as denial:
                # 单文件被策略或安全读取拒绝：只记该行，其余文件照常（发现与打开同判）。
                # 两种拒绝都只携带闭合枚举码（PolicyDenied.code / SafeReadDenied.code），
                # 固定文案不含路径与调用方输入，直接取 `.code` 无需再判类型。
                segments.append(
                    _FileSegment(
                        index=index,
                        ref=ref,
                        status=_FileRowStatus.REFUSED,
                        reason=denial.code.value,
                    )
                )
                any_incomplete = True
                continue
            read_budget_left = max(0, read_budget_left - file_outcome.read.consumed_bytes)
            if sink.failed:
                any_incomplete = True
                segments.append(
                    _FileSegment(
                        index=index,
                        ref=ref,
                        status=_FileRowStatus.INCOMPLETE,
                        outcome=file_outcome,
                        reason=PiFileFailureCategory.CANDIDATE_CAPTURE_FAILED.value,
                    )
                )
                continue
            if not file_outcome.complete:
                any_incomplete = True
                segments.append(
                    _FileSegment(
                        index=index,
                        ref=ref,
                        status=_FileRowStatus.INCOMPLETE,
                        outcome=file_outcome,
                        reason=PiFileFailureCategory.FILE_INCOMPLETE.value,
                    )
                )
                continue
            # 归属接线：候选的项目名映射缺失即整文件剔除出批（宁缺不错），其余文件不受累。
            segment_projects: list[str | None] = []
            attribution_ok = True
            offset = len(all_records)
            for position, record in enumerate(candidates):
                project_name = grants.get(id(record))
                if not isinstance(project_name, str) or not project_name:
                    attribution_ok = False
                    break
                segment_projects.append(project_name)
                mappings[offset + position] = project_name
            if not attribution_ok:
                any_incomplete = True
                mappings = {key: value for key, value in mappings.items() if key < offset}
                segments.append(
                    _FileSegment(
                        index=index,
                        ref=ref,
                        status=_FileRowStatus.INCOMPLETE,
                        outcome=file_outcome,
                        reason=PiFileFailureCategory.ATTRIBUTION_INCOMPLETE.value,
                    )
                )
                candidates.clear()
                continue
            segment = _FileSegment(
                index=index,
                ref=ref,
                status=_FileRowStatus.SEARCHED,
                outcome=file_outcome,
            )
            segment.records = candidates
            segment.projects = segment_projects
            segments.append(segment)
            all_records.extend(candidates)

        stage = AggregateStageReached.FILE_PIPELINE
        usable = [seg for seg in segments if seg.status is _FileRowStatus.SEARCHED]
        if not usable:
            # 没有任何文件通过完整核对：零结果必须能区分于「扫完而无匹配」。绑定清单非空
            # 且每个文件都必有行，所以走到这里必然带着某种不完整；不再叠加条件判断。
            row = _aggregate_pi_row(None)
            row["filter_errors"] = [FilterErrorTag.FILES_UNUSABLE.value]
            row["reason"] = f"{_FILES_UNUSABLE_NOTE}{_LAYERED_COUNTER_NOTE}{_MULTI_SCOPE_NOTE}"
            unusable_rows = tuple(_file_row(seg) for seg in segments)
            return PiAggregateSearchOutcome(
                complete=False,
                partial=True,
                truncated=False,
                total_matched=0,
                total_scanned=0,
                skipped_records=0,
                results=(),
                coverage=_merged_coverage((row,), requested_sources),
                files=unusable_rows,
                reason=AggregateFailureCategory.FILES_UNUSABLE.value,
                stage_reached=stage.value,
                failure_category=AggregateFailureCategory.FILES_UNUSABLE.value,
            )

        # ---- 一次过滤：limit 与扫描字符预算都是全查询口径，不按文件重置 ----
        stage = AggregateStageReached.FILTER
        effective_limit = min(limit, MAX_AGGREGATE_SNIPPETS)
        full_set_scanned = not any_incomplete and not read_budget_hit
        scanned = scan_filter(
            all_records,
            query=query,
            start=start,
            end=end,
            project=project,
            project_mappings=mappings,
            sources=(SOURCE_PI,),
            limit=effective_limit,
            max_total_scan_chars=MAX_AGGREGATE_TOTAL_SCAN_CHARS,
            completed_sources=(SOURCE_PI,) if full_set_scanned else (),
        )
        if scanned.rejected:
            reason = (
                scanned.reason.value
                if scanned.reason
                else AggregateFailureCategory.INTERNAL_FAILURE.value
            )
            return _rejected_outcome(reason, stage=stage)

        # 过滤层跳过的是列表尾部的记录（桶内严格按输入顺序消费）：按段边界如实回写到文件行，
        # 保证「段没扫完的文件」不得宣称 searched。
        pi_row = _aggregate_pi_row(scanned)
        tail_skipped = pi_row["skipped_count"]
        for seg in reversed(segments):
            if tail_skipped <= 0:
                break
            seg_total = len(seg.records)
            if seg_total == 0:
                continue
            seg_skipped = min(tail_skipped, seg_total)
            tail_skipped -= seg_skipped
            if seg.status is _FileRowStatus.SEARCHED and seg_skipped > 0:
                seg.status = _FileRowStatus.INCOMPLETE
                seg.reason = FilterErrorTag.SOURCE_NOT_SCANNED.value
                seg.skipped_tail = seg_skipped
                any_incomplete = True

        offset = 0
        offsets: list[tuple[int, int]] = []  # (start, end) per usable segment
        for seg in segments:
            length = len(seg.records)
            offsets.append((offset, offset + length))
            offset += length
        global_to_local: dict[int, tuple[_FileSegment, int]] = {}
        for seg, (low, high) in zip(segments, offsets, strict=True):
            for global_index in range(low, high):
                global_to_local[global_index] = (seg, global_index - low)

        indices: list[int] = []
        seen: set[int] = set()
        for match in scanned.matches:
            record_index = match.record_index
            if (
                isinstance(record_index, bool)
                or not isinstance(record_index, int)
                or not 0 <= record_index < len(all_records)
                or record_index in seen
                or record_index not in global_to_local
            ):
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    AggregateFailureCategory.MATCH_JOIN_FAILED.value,
                    stage,
                )
            seen.add(record_index)
            indices.append(record_index)

        # ---- 两阶段发布：先逐文件收集判定，全部通过才释放并按文件绑定发放 ctxref ----
        # 单文件片段配额沿用 MAX_SNIPPETS_PER_FILE（全局预算不豁免文件级上限）：超限的
        # 命中只计 matched 不发布，记 result_truncated 使结论 partial——整源无匹配之类的
        # 断言仍由覆盖行与 completed_sources 回答，不由发布层回答。
        stage = AggregateStageReached.PUBLICATION
        per_file_cap = min(MAX_SNIPPETS_PER_FILE, effective_limit)
        kept_matches: list[Any] = []
        kept_indices: list[int] = []
        per_file_kept: dict[int, int] = {}
        quota_cut = False
        for match, record_index in zip(scanned.matches, indices, strict=True):
            seg, _local = global_to_local[record_index]
            used = per_file_kept.get(seg.index, 0)
            if used >= per_file_cap:
                quota_cut = True
                continue
            per_file_kept[seg.index] = used + 1
            kept_matches.append(match)
            kept_indices.append(record_index)

        first_refusal: str | None = None
        for record_index in kept_indices:
            seg, _local = global_to_local[record_index]
            collector = open_collectors.get(seg.index)
            if collector is None:
                collector = SnippetCollector(
                    source=SOURCE_PI,
                    max_snippets=per_file_cap,
                    max_total_chars=MAX_SNIPPET_TOTAL_CHARS,
                )
                open_collectors[seg.index] = collector
            refusal = collector.collect(all_records[record_index])
            if refusal is not None:
                first_refusal = refusal.value
                break
            seg.match_positions.append(record_index)
        if first_refusal is not None:
            # 首拒即整批零结果：未确认的收集器一律 release(confirmed=False) 关闭，
            # 「已收进去的前缀」绝不外递（与单文件协调器的 discard 路径同语义）。
            for collector in open_collectors.values():
                collector.release(confirmed=False)
            open_collectors.clear()
            return _aggregate_failure(
                segments,
                scanned,
                requested_sources,
                first_refusal,
                stage,
            )

        snippets_total = 0
        published_chars = 0
        metadata_withheld = False
        # 先全部释放并核完接线，再一次性按文件发放引用：任何「释放后才发现的失败」
        # 都发生在第一批 token 离开账本之前，零结果出口不会留下可解析的令牌。
        publishable: list[tuple[_FileSegment, FileVersion]] = []
        for seg in segments:
            if not seg.match_positions:
                continue
            collector = open_collectors.pop(seg.index)
            seg.snippets = collector.release(confirmed=True)
            if len(seg.snippets) != len(seg.match_positions):
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    AggregateFailureCategory.SNIPPET_JOIN_FAILED.value,
                    stage,
                )
            snippets_total += len(seg.snippets)
            # 字符预算是全查询口径：逐文件收集器各自只守单文件上限，跨文件累加必须
            # 在这里拦——发布行数不超 effective_limit，但遮蔽文本长度不随行数封顶；
            # 超限在第一批 token 离开账本前判出，整批零结果无前缀。
            published_chars += sum(
                len(snippet.snippet) for snippet in seg.snippets
            )
            if published_chars > MAX_SNIPPET_TOTAL_CHARS:
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED.value,
                    stage,
                )
            version = seg.outcome.version if seg.outcome is not None else None
            if version is None or not version.complete:
                return _aggregate_failure(
                    segments,
                    scanned,
                    requested_sources,
                    PiFileFailureCategory.FILE_INCOMPLETE.value,
                    stage,
                )
            publishable.append((seg, version))
        if snippets_total != len(kept_matches):
            return _aggregate_failure(
                segments,
                scanned,
                requested_sources,
                AggregateFailureCategory.SNIPPET_JOIN_FAILED.value,
                stage,
            )
        ref_ledger = service.ledger if service.ledger is not None else default_ledger()
        for seg, version in publishable:
            # ctxref 逐文件绑定发放：service_key/scope/path/session_id/版本都取该文件
            # 自己的授权事实，令牌只能回到这条已批准绑定（读取面由既有绑定核对执行）。
            service_key = service_binding_key(
                scope=scope,
                source=SOURCE_PI,
                path=seg.ref.path,
                session_id=seg.ref.session_id,
            )
            seg_records = [all_records[gi] for gi in seg.match_positions]
            seg_projects = [mappings[gi] for gi in seg.match_positions]
            seg.tokens = list(
                _issue_references(
                    seg_records,
                    seg_projects,
                    version=version,
                    service_key=service_key,
                    scope=scope,
                    path=seg.ref.path,
                    session_id=seg.ref.session_id,
                    ledger=ref_ledger,
                )
            )
            # 逐文件累计已发放 token：其后任何失败路径按批收回全部已发引用。
            issued_tokens.extend(seg.tokens)

        # 全局行序沿用过滤层的命中顺序；每行的元数据、遮蔽片段与该文件的 ctxref 三元对位。
        cursor: dict[int, int] = {}
        results: list[dict[str, Any]] = []
        for kept in kept_matches:
            seg, _local = global_to_local[kept.record_index]
            pos = cursor.get(seg.index, 0)
            cursor[seg.index] = pos + 1
            row, withheld = _join_result(kept, seg.snippets[pos])
            row["location"] = seg.tokens[pos]
            results.append(row)
            metadata_withheld = metadata_withheld or withheld
        returned_per_file: dict[int, int] = {}
        for seg in segments:
            returned_per_file[seg.index] = len(seg.match_positions)

        coverage_rows = [pi_row]
        if any(snippet.truncated for seg in segments for snippet in seg.snippets):
            coverage_rows = _annotate_rows(
                coverage_rows,
                AggregateFailureCategory.SNIPPET_OUTPUT_TRUNCATED.value,
                _SNIPPET_TRUNCATION_NOTE,
            )
        if metadata_withheld:
            coverage_rows = _annotate_rows(
                coverage_rows,
                AggregateFailureCategory.METADATA_WITHHELD.value,
                _METADATA_WITHHELD_NOTE,
            )
        file_rows: list[dict[str, Any]] = []
        for seg, (low, high) in zip(segments, offsets, strict=True):
            row = _file_row(seg)
            row["filter_scanned"] = (high - low) - seg.skipped_tail
            row["filter_skipped"] = seg.skipped_tail
            row["returned_count"] = returned_per_file[seg.index]
            file_rows.append(row)
        if quota_cut:
            # 配额裁掉过命中：pi 覆盖行的 returned_count 必须回写为实际发布行数，
            # 并带 result_truncated 标 partial——过滤层的原行是按「全部命中都发」口径
            # 计的，沿用它会宣称比真实发布更多的返回。回写作用在**已标注后的首行**上，
            # 不得把片段截断/元数据遮蔽的注记替换回过滤层原行。
            pi_row = dict(coverage_rows[0])
            pi_row["returned_count"] = len(results)
            pi_row["partial"] = True
            errors = list(pi_row["filter_errors"])
            if FilterErrorCode.RESULT_TRUNCATED.value not in errors:
                errors.append(FilterErrorCode.RESULT_TRUNCATED.value)
            pi_row["filter_errors"] = errors
            pi_row["reason"] = f"{pi_row['reason']}{_QUOTA_NOTE}"
            coverage_rows = [pi_row, *coverage_rows[1:]]
        coverage = _merged_coverage(coverage_rows, requested_sources)
        partial = (
            not scanned.complete
            or any_incomplete
            or read_budget_hit
            or quota_cut
            or any(row["partial"] for row in coverage)
        )
        # `published` 阶段词只在结果对象真正成形后写下（同单文件协调器的收敛纪律）。
        outcome = PiAggregateSearchOutcome(
            complete=(
                not partial
                and full_set_scanned
                and scanned.complete
            ),
            partial=partial,
            truncated=(
                scanned.truncated
                or quota_cut
                or any(
                    snippet.truncated for seg in segments for snippet in seg.snippets
                )
            ),
            total_matched=scanned.total_matched,
            total_scanned=scanned.total_scanned,
            skipped_records=scanned.skipped_records,
            results=tuple(results),
            coverage=coverage,
            files=tuple(file_rows),
            stage_reached=AggregateStageReached.PUBLISHED.value,
        )
        stage = AggregateStageReached.PUBLISHED
        return outcome
    except Exception:  # noqa: BLE001 - unexpected failures must not leak exception details
        # 策略/安全读取拒绝已在循环内逐文件消费并如实入账（refused 行）；走到这里的
        # 只可能是真正的内部异常，统一收敛为零结果，不再为无来源的逃逸保留 re-raise 分支。
        ref_ledger = service.ledger if service.ledger is not None else default_ledger()
        with contextlib.suppress(BaseException):
            ref_ledger.release(tuple(issued_tokens))
        if issued_tokens:
            # 已发放引用被整批收回：发布失败不留任何可解析令牌（同单文件协调器）。
            issued_tokens.clear()
        category = AggregateFailureCategory.INTERNAL_FAILURE.value
        row = _aggregate_pi_row(scanned)
        row["filter_errors"] = list(
            dict.fromkeys([*row["filter_errors"], category])
        )
        row["reason"] = (
            "聚合协调器内部失败；本文件集合未发布结果，分层计数只在已取到的结论上给出。"
            f"{_LAYERED_COUNTER_NOTE}{_MULTI_SCOPE_NOTE}"
        )
        fail_stage = (
            AggregateStageReached.PUBLICATION
            if stage is AggregateStageReached.PUBLISHED
            else stage
        )
        return PiAggregateSearchOutcome(
            complete=False,
            partial=True,
            truncated=False,
            total_matched=0,
            total_scanned=0,
            skipped_records=len(all_records),
            results=(),
            coverage=_merged_coverage((row,), requested_sources),
            files=tuple(_file_row(seg) for seg in segments),
            reason=category,
            stage_reached=fail_stage.value,
            records_withheld=len(all_records),
            failure_category=category,
        )
    finally:
        for seg in segments:
            seg.records.clear()
            seg.projects.clear()
            seg.match_positions.clear()
        for collector in open_collectors.values():
            # 仍未释放的收集器（异常/提前返回路径）：discard 只关闭不放行，已收前缀不外递。
            with contextlib.suppress(BaseException):
                collector.discard(PublicationRefusal.NOT_CONFIRMED)
        open_collectors.clear()
        all_records.clear()
        mappings.clear()


def _annotate_rows(
    rows: Sequence[dict[str, Any]], category: str, note: str
) -> list[dict[str, Any]]:
    updated: list[dict[str, Any]] = []
    for row in rows:
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
    return updated


def _aggregate_failure(
    segments: Sequence[_FileSegment],
    scanned: ScanFilterOutcome,
    requested_sources: Sequence[str],
    category: str,
    stage: AggregateStageReached,
) -> PiAggregateSearchOutcome:
    """聚合发布失败出口：整批零结果、无前缀；过滤层诊断计数保留。"""
    row = _aggregate_pi_row(scanned)
    row["status"] = "error"
    row["matched_count"] = scanned.total_matched
    row["returned_count"] = 0
    row["partial"] = True
    errors = list(row["filter_errors"])
    for code in (FilterErrorTag.PUBLICATION_FAILED.value, category):
        if code not in errors:
            errors.append(code)
    row["filter_errors"] = errors
    row["reason"] = (
        f"遮蔽、接线或发放环节失败，整批未发布（零结果，不是前缀）。"
        f"{_LAYERED_COUNTER_NOTE}{_MULTI_SCOPE_NOTE}"
    )
    file_rows: list[dict[str, Any]] = []
    for seg in segments:
        frow = _file_row(seg)
        frow["returned_count"] = 0
        if frow["status"] == _FileRowStatus.SEARCHED.value and seg.match_positions:
            frow["reason"] = category
        file_rows.append(frow)
    return PiAggregateSearchOutcome(
        complete=False,
        partial=True,
        truncated=scanned.truncated,
        total_matched=scanned.total_matched,
        total_scanned=scanned.total_scanned,
        skipped_records=scanned.skipped_records,
        results=(),
        coverage=_merged_coverage((row,), requested_sources),
        files=tuple(file_rows),
        reason=AggregateFailureCategory.PUBLICATION_FAILED.value,
        stage_reached=stage.value,
        records_withheld=scanned.returned_count,
        failure_category=category,
    )
