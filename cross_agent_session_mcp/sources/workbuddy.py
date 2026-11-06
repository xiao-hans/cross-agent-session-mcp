"""WorkBuddy 来源适配器：索引侧（SQLite）可用，正文侧未核实即不产出。

职责分三层，与 Hermes 适配器同一取向（`sources/hermes.py`）：

1. **白名单只读 SQL**。操作名是本模块自有枚举，语句是逐字面常量，参数一律走 sqlite3
   占位符绑定；连接固定 `file:` URI + `mode=ro`，事务固定 `BEGIN`/`ROLLBACK`；写关键字出现
   在任何 SELECT/PRAGMA 文本里都说明白名单被改动而未同步（`whitelist_shape_problems()`）。
2. **列集合即判据**。真实库 `~/.workbuddy/workbuddy.db`（323,584 B，另带 `-wal`/`-shm`）里
   逐字核对过的只有 `workspaces(path, last_opened_at)`、`session_usage(session_id, used, size,
   updated_at, credit_json)`、`automation_runs(thread_id, automation_id, status, read_at,
   thread_title, source_cwd, runs_json, result_success, metadata_json, created_at, updated_at,
   failure_code, reason_code)`、`automations`（空表）、`migration_meta(key, value)`。`sessions`
   的完整列集合与 `status`/`deleted_at`/`source_mode` 的取值域**来自简报候选名单，不是取证
   结果**，因此本模块对不认识的字面量零容忍：声明列缺失即 `SCHEMA_UNKNOWN_COLUMNS`，未声明
   的列一律计入 `unknown_columns`（存在但不解释），取值不认识即 `STATUS_UNKNOWN` 保守剔除并
   使覆盖不完整。
3. **正文未核实 ⇒ 默认不产记录**。`~/.workbuddy/sessions/` 目录确实存在，但正文文件的路径
   形状、单条记录形状与注入面均未核实，本增量也不得读取真实存储取证。因此
   `plan_workbuddy_session` 交出的计划恒为 `body_available=False` + 固定
   `body_missing_reason`；`run_workbuddy_session` 在没有宿主注入正文时**不产出任何记录**且整条
   会话判不完整（绝不冒充「0 条消息的会话」）。宿主注入正文时走 `WorkBuddyBodyLineParser`，
   形状不合的行逐条 withhold 并计数——这条路径是为「取证完成后接线」准备的，默认关闭。

安全边界：

- 两条授权轴各判一次且不可互替：`policy.authorize_store` 决定读不读，
  `policy.authorize_attribution` 决定认不认归属；本模块自己执行这两次判断，不依赖调用方已判。
- 锁与不可用严格分两态：`WorkBuddyAccessCode.LOCKED` 与 `NOT_FOUND` 是不同取值，聚合层因此
  不会把 `locked` 折成「无匹配」。
- 对外只给来源名、整数计数与封闭枚举值；路径只进绑定键与引用账本，不进结果。
"""

from __future__ import annotations

import contextlib
import json
import pathlib
import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
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
)
from ..policy import (
    PolicyDenied,
    RefusalCode,
    SessionPolicy,
    TargetKind,
    is_safe_literal_path,
)
from ..references import ReferenceLedger, service_binding_key
from ..session_discovery import COVERAGE_SCOPE_NONE
from ..session_stage import (
    MAX_CANDIDATES_PER_SESSION,
    MAX_STAGE_BYTES_PER_SESSION,
    SessionCandidateStage,
    StageDiscardReason,
    StageOutcome,
)

__all__ = [
    "COVERAGE_SCOPE_MULTI_WORKBUDDY",
    "SOURCE_WORKBUDDY",
    "WORKBUDDY_BODY_LAYOUT_REASON",
    "WORKBUDDY_SCHEMA_COLUMNS",
    "WORKBUDDY_SCHEMA_TABLES",
    "WORKBUDDY_SESSIONS_KNOWN",
    "WorkBuddyAccessCode",
    "WorkBuddyAggregateContextService",
    "WorkBuddyAggregateSearchService",
    "WorkBuddyBodyLineParser",
    "WorkBuddyContextOutcome",
    "WorkBuddyGateCode",
    "WorkBuddySessionOutcome",
    "WorkBuddySessionPlan",
    "WorkBuddyStoreRef",
    "plan_workbuddy_session",
    "run_workbuddy_session",
    "whitelist_shape_problems",
]

SOURCE_WORKBUDDY = "workbuddy"

#: 正文侧未核实的固定文案（计划、结果与聚合行共用，措辞不得飘）。
WORKBUDDY_BODY_LAYOUT_REASON = "正文文件路径与记录形状未逐字核实；索引侧结论不冒充正文覆盖。"

#: 聚合层的结论范围标签：这个有界库集合的完整性不声明全存储已扫完。
COVERAGE_SCOPE_MULTI_WORKBUDDY = "bounded_workbuddy_store_set"

#: 本模块逐字核对过的表与最小列集合（模块 docstring 第 2 条）。库里另有未声明的表不影响
#: 读取（只 SELECT 声明列）；这些表本身缺失即判 schema 不认识。
WORKBUDDY_SCHEMA_TABLES: tuple[str, ...] = (
    "workspaces",
    "session_usage",
    "automation_runs",
    "migration_meta",
)

WORKBUDDY_SCHEMA_COLUMNS: dict[str, frozenset[str]] = {
    "workspaces": frozenset({"path", "last_opened_at"}),
    "session_usage": frozenset({"session_id", "used", "size", "updated_at", "credit_json"}),
    "automation_runs": frozenset(
        {
            "thread_id",
            "automation_id",
            "status",
            "read_at",
            "thread_title",
            "source_cwd",
            "runs_json",
            "result_success",
            "metadata_json",
            "created_at",
            "updated_at",
            "failure_code",
            "reason_code",
        }
    ),
    "migration_meta": frozenset({"key", "value"}),
}

#: `sessions` 的已声明列集合 = 本模块愿意解释的上限。真实库列更多，未声明列只计入
#: `unknown_columns`（存在但不解释），本模块的 SELECT 面永不超过这个集合。
WORKBUDDY_SESSIONS_KNOWN: frozenset[str] = frozenset(
    {"id", "title", "created_at", "updated_at", "deleted_at", "status", "source_mode"}
)
#: 实际 SELECT 的列（顺序即行元组顺序）：身份 + 时间 + 生命周期三族，其余不取。
_SESSIONS_SELECT: tuple[str, ...] = (
    "id",
    "title",
    "created_at",
    "updated_at",
    "deleted_at",
    "status",
    "source_mode",
)
#: 必填列 = **实际 SELECT 的 7 列**：查询真的会引用它们，缺任何一列都是 schema 不匹配
#: （SCHEMA_UNKNOWN_COLUMNS），不是「少取一列」。曾经只声明 `{"id"}`，缺 `status` 的库会
#: 照常执行 SELECT，由 SQLite 抛 "no such column" 并伪装成一次普通的空结果。
#: 与 `_SESSIONS_SELECT` 同源，两者不会随重构各自漂移。
WORKBUDDY_SESSIONS_REQUIRED: frozenset[str] = frozenset(_SESSIONS_SELECT)

#: 会话 id 形态门（与引用账本的可发布标识符同向：ASCII 白名单，不含分隔符/盘符/前导点）。
MAX_ID_CHARS = 256
MAX_PROJECT_CHARS = 512
#: 单行原文字节上限与单条正文字符上限（字节上限服务解码前拦截，字符上限服务截断）。
MAX_LINE_BYTES = 1_048_576
MAX_ROW_TEXT_TOTAL_CHARS = 32_768
MAX_CONTENT_BLOCKS_PER_LINE = 32
#: 正文里愿意解释为可查询文本的角色；工具/系统/后台类一律不产记录。
_BODY_TEXT_ROLES = frozenset({"user", "assistant"})
_ID_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*")
_PATH_LIKE = re.compile(r"(?:^(?:~|[A-Za-z]:)|[\\/])")

#: 单次会话取数的硬上限（正文未核实，因此默认值只服务索引行；一律只收紧不放松）。
MAX_ROWS_PER_SESSION = 64
#: 暂存字节上限与候选数上限都直接沿用内核同名的最严值（`DEFAULT_STAGE_BYTES` 必须 ≤
#: `session_stage.MAX_STAGE_BYTES_PER_SESSION`，否则形态门会把自己默认的常量判成非法参数）。
DEFAULT_STAGE_BYTES = MAX_STAGE_BYTES_PER_SESSION
DEFAULT_BUSY_TIMEOUT_MS = 1_000
_BUSY_TIMEOUT_MIN_MS = 100
_BUSY_TIMEOUT_MAX_MS = 5_000
MAX_STORES_PER_QUERY = 16
MAX_PROTOCOL_LIMIT = 100
_DEFAULT_LIMIT = 20

#: 取值域**已按本模块解释力选定**的会话状态白名单：未在此列出的取值一律保守剔除并计入
#: `status_unknown`。真实取值域未逐字核实 ⇒ 这个白名单是本模块的产出选择，不是对来源的承诺。
WORKBUDDY_ACTIVE_STATUSES: frozenset[str] = frozenset({"active", "open", "ready"})

#: sqlite3 主结果码（Python 的 sqlite3 不导出这些常量，只能在模块内声明；
#: `exc.sqlite_errorcode` 是扩展码，`& 0xFF` 回到主码）。合成测试用真实写锁/损坏文件核验。
_SQLITE_ERROR = 0x01
_SQLITE_BUSY = 0x05
_SQLITE_LOCKED = 0x06
_SQLITE_READONLY = 0x08
_SQLITE_CORRUPT = 0x0B
_SQLITE_CANTOPEN = 0x0E
_SQLITE_NOTADB = 0x1A

_DB_NAME_MAX_CHARS = 64
_DB_NAME_ALLOWED = re.compile(r"[A-Za-z0-9._-]+")
_REDACTED_STREAM_LABEL = "redacted-stream"


class WorkBuddyAccessCode(StrEnum):
    """访问结果轴：只回答「这份存储够不够格被读」，不承担门语义原因。"""

    OK = "ok"
    DENIED = "denied"
    NOT_FOUND = "not_found"
    LOCKED = "locked"
    FAULT = "fault"


class WorkBuddyGateCode(StrEnum):
    """门语义轴：把「为什么只给这个结论」分成互斥的封闭取值。"""

    OK = "ok"
    SCHEMA_UNKNOWN_TABLES = "schema_unknown_tables"
    SCHEMA_UNKNOWN_COLUMNS = "schema_unknown_columns"
    SESSION_ABSENT = "session_absent"
    ROW_LIMIT = "row_limit"
    CANDIDATE_LIMIT = "candidate_limit"
    BYTE_LIMIT = "byte_limit"
    ID_SHAPE_REJECTED = "id_shape_rejected"
    STATUS_UNKNOWN = "status_unknown"
    BODY_LAYOUT_UNKNOWN = "body_layout_unknown"
    BODY_MISSING = "body_missing"
    LOCK_TIMEOUT = "lock_timeout"
    INTEGRITY = "integrity"
    STORAGE_DENIED = "storage_denied"
    ATTRIBUTION_DENIED = "attribution_denied"
    INVALID_ARGUMENT = "invalid_argument"
    INTERNAL_FAILURE = "internal_failure"


_WITHHELD_KEYS: tuple[str, ...] = (
    "identity_unusable",
    "timestamp_unusable",
    "content_empty",
    "content_shape",
    "content_overlong",
    "row_id_unusable",
    "status_unknown",
    "body_missing",
)

#: 访问码 → 默认门码。`locked` 单独成态（不得折成「库不可用」），`not_found` 折成会话缺席。
_ACCESS_GATE_DEFAULT: dict[WorkBuddyAccessCode, WorkBuddyGateCode] = {
    WorkBuddyAccessCode.OK: WorkBuddyGateCode.OK,
    WorkBuddyAccessCode.DENIED: WorkBuddyGateCode.STORAGE_DENIED,
    WorkBuddyAccessCode.NOT_FOUND: WorkBuddyGateCode.SESSION_ABSENT,
    WorkBuddyAccessCode.LOCKED: WorkBuddyGateCode.LOCK_TIMEOUT,
    WorkBuddyAccessCode.FAULT: WorkBuddyGateCode.INTEGRITY,
}


@dataclass(frozen=True)
class WorkBuddySessionPlan:
    """执行前计划：纯事实 + 封闭枚举。不含 SQL 文本、不含路径、不承诺授权。"""

    available: bool
    access: WorkBuddyAccessCode
    gate: WorkBuddyGateCode
    session_exists: bool
    row_count: int
    candidate_count: int
    inactive_count: int
    unknown_columns: tuple[str, ...]
    text_chars: int
    unusable_count: int
    unavailable_reasons: dict[str, int]
    integrity_ok: bool | None
    schema_version: int | None
    schema_known: bool
    body_available: bool
    body_missing_reason: str | None

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "access": self.access.value,
            "gate": self.gate.value,
            "session_exists": self.session_exists,
            "row_count": self.row_count,
            "candidate_count": self.candidate_count,
            "inactive_count": self.inactive_count,
            "unknown_columns": list(self.unknown_columns),
            "text_chars": self.text_chars,
            "unusable_count": self.unusable_count,
            "unavailable_reasons": dict(self.unavailable_reasons),
            "integrity_ok": self.integrity_ok,
            "schema_version": self.schema_version,
            "schema_known": self.schema_known,
            "body_available": self.body_available,
            "body_missing_reason": self.body_missing_reason,
        }


@dataclass(frozen=True)
class WorkBuddySessionOutcome:
    """执行后结果：完成性 + 封闭原因 + 自有计数（与计划分列，互不冒充）。"""

    complete: bool
    publication_allowed: bool
    gate: WorkBuddyGateCode
    access: WorkBuddyAccessCode
    stage: StageOutcome | None
    records_emitted: int
    rows_read: int
    withheld_reasons: dict[str, int]
    parse: ParseStats
    plan: WorkBuddySessionPlan
    denial_code: str | None = None

    def as_public_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "source": SOURCE_WORKBUDDY,
            "complete": self.complete,
            "publication_allowed": self.publication_allowed,
            "gate": self.gate.value,
            "access": self.access.value,
            "stage": self.stage.as_public_dict() if self.stage is not None else None,
            "records_emitted": self.records_emitted,
            "rows_read": self.rows_read,
            "withheld_reasons": dict(self.withheld_reasons),
            "parse": self.parse.as_public_dict(),
            "plan": self.plan.as_public_dict(),
        }
        if self.denial_code is not None:
            payload["denial_code"] = self.denial_code
        return payload


class _WbAbort(Exception):
    """内部提前停：只携带本模块自有枚举，不外传异常原文（消息里可能有路径或 SQL）。"""

    __slots__ = ("access", "gate")

    def __init__(self, gate: WorkBuddyGateCode, access: WorkBuddyAccessCode) -> None:
        super().__init__(gate.value)
        self.gate = gate
        self.access = access


def _empty_plan(
    access: WorkBuddyAccessCode,
    gate: WorkBuddyGateCode,
    *,
    unavailable_reasons: Mapping[str, int] | None = None,
) -> WorkBuddySessionPlan:
    reasons = dict.fromkeys(_WITHHELD_KEYS, 0)
    if unavailable_reasons:
        for key, value in unavailable_reasons.items():
            reasons[str(key)] = int(value)
    return WorkBuddySessionPlan(
        available=False,
        access=access,
        gate=gate,
        session_exists=False,
        row_count=0,
        candidate_count=0,
        inactive_count=0,
        unknown_columns=(),
        text_chars=0,
        unusable_count=0,
        unavailable_reasons=reasons,
        integrity_ok=None,
        schema_version=None,
        schema_known=False,
        body_available=False,
        body_missing_reason=WORKBUDDY_BODY_LAYOUT_REASON,
    )


def _gate_for_access(access: WorkBuddyAccessCode) -> WorkBuddyGateCode:
    return _ACCESS_GATE_DEFAULT.get(access, WorkBuddyGateCode.INTEGRITY)


def _classify_exception(exc: BaseException, path: str | None = None) -> WorkBuddyAccessCode:
    """异常 → 自有访问枚举（分派表来自 sqlite3 稳定类层次与主结果码）。

    `locked` 与「库不存在/不可读」是不同取值：前者说明存储**存在且持写锁**，后者说明没有
    可读对象。绝不回显异常消息。非 sqlite 异常原样上抛（不吞调用方中断）。
    """

    hresult = getattr(exc, "sqlite_errorcode", None)
    primary = None if hresult is None else hresult & 0xFF
    if primary in (_SQLITE_BUSY, _SQLITE_LOCKED):
        return WorkBuddyAccessCode.LOCKED
    if isinstance(exc, sqlite3.OperationalError):
        if primary == _SQLITE_ERROR:
            return WorkBuddyAccessCode.FAULT
        if primary in (_SQLITE_READONLY, _SQLITE_CANTOPEN) and not (
            primary == _SQLITE_CANTOPEN and path is not None and pathlib.Path(path).exists()
        ):
            if primary == _SQLITE_CANTOPEN:
                return WorkBuddyAccessCode.NOT_FOUND
            return WorkBuddyAccessCode.DENIED
        return WorkBuddyAccessCode.FAULT
    if isinstance(exc, sqlite3.Error):
        return WorkBuddyAccessCode.FAULT
    raise exc


class _Op(StrEnum):
    """取数意图。本模块自有枚举：调用方只能选这几种，无法注入语句。"""

    QUERY_ONLY = "query_only"
    BEGIN_READ = "begin_read"
    END_READ = "end_read"
    INTEGRITY = "integrity"
    USER_VERSION = "user_version"
    TABLE_NAMES = "table_names"
    TABLE_COLUMNS = "table_columns"
    SESSION_ROW_COUNT = "session_row_count"
    SESSION_FACTS = "session_facts"
    USAGE_ROWS = "usage_rows"


#: 语句是逐字面常量：字典下标取语句，绝不做字符串拼接或参数插值。
_QUERIES: dict[_Op, str] = {
    _Op.QUERY_ONLY: "PRAGMA query_only = ON",
    _Op.BEGIN_READ: "BEGIN",
    _Op.END_READ: "ROLLBACK",
    _Op.INTEGRITY: "PRAGMA integrity_check",
    _Op.USER_VERSION: "PRAGMA user_version",
    _Op.TABLE_NAMES: "SELECT name FROM sqlite_master WHERE type = 'table'",
    _Op.TABLE_COLUMNS: "SELECT name FROM pragma_table_info(?)",
    _Op.SESSION_ROW_COUNT: "SELECT COUNT(*) FROM sessions WHERE id = ?",
    _Op.SESSION_FACTS: (
        "SELECT id, title, created_at, updated_at, deleted_at, status, source_mode "
        "FROM sessions WHERE id = ? LIMIT 2"
    ),
    _Op.USAGE_ROWS: "SELECT used, size, updated_at FROM session_usage WHERE session_id = ? LIMIT ?",
}

_QUERY_ARITY: dict[_Op, int] = {
    _Op.QUERY_ONLY: 0,
    _Op.BEGIN_READ: 0,
    _Op.END_READ: 0,
    _Op.INTEGRITY: 0,
    _Op.USER_VERSION: 0,
    _Op.TABLE_NAMES: 0,
    _Op.TABLE_COLUMNS: 1,
    _Op.SESSION_ROW_COUNT: 1,
    _Op.SESSION_FACTS: 1,
    _Op.USAGE_ROWS: 2,
}

#: 事务语句的逐字面形态（合成测试直接比对，改写即视为白名单被动过）。
_TRANSACTION_STATEMENTS: dict[_Op, str] = {
    _Op.BEGIN_READ: "BEGIN",
    _Op.END_READ: "ROLLBACK",
}

#: 任何 SELECT 文本里作为**独立词**出现即说明白名单被改动而未同步自证（按词比对，不按子串：
#: `PRAGMA query_only` 里的 `query_only` 不是 `update`，裸子串会误报）。
_WRITE_KEYWORDS = frozenset(
    {"insert", "update", "delete", "attach", "detach", "drop", "alter"}
)

#: 允许的 PRAGMA 白名单（只读探针与只读开关；写型 PRAGMA 一律不接受）。
_ALLOWED_PRAGMAS = frozenset({"query_only", "integrity_check", "user_version", "table_info"})

#: 声明列集合按表分派；`sessions` 用本模块愿意解释的上限，其余是取证过的最小集合。
_DECLARED_COLUMNS: dict[str, frozenset[str]] = {
    **WORKBUDDY_SCHEMA_COLUMNS,
    "sessions": WORKBUDDY_SESSIONS_KNOWN,
}
_REQUIRED_TABLES: tuple[str, ...] = (*WORKBUDDY_SCHEMA_TABLES, "sessions")


def whitelist_shape_problems() -> tuple[str, ...]:
    """白名单自证：返回问题清单，空元组即通过（入口与合成测试共用）。"""

    problems: list[str] = []
    if set(_QUERIES) != set(_QUERY_ARITY):
        problems.append("query_key_mismatch")
    for op, statement in _QUERIES.items():
        arity = _QUERY_ARITY.get(op)
        if arity is None:
            continue
        if statement.count("?") != arity:
            problems.append(f"arity_mismatch:{op.value}")
        if op in _TRANSACTION_STATEMENTS:
            if statement != _TRANSACTION_STATEMENTS[op]:
                problems.append(f"transaction_text_changed:{op.value}")
            continue
        head = statement.split(" ", 1)[0].lower()
        if head not in {"select", "pragma"}:
            problems.append(f"not_read_only_shape:{op.value}")
        if head == "select":
            words = {token.strip("()") .lower() for token in statement.replace(",", " ").split()}
            if words & _WRITE_KEYWORDS:
                problems.append(f"write_keyword:{op.value}")
        if head == "pragma":
            pragma = statement[len("PRAGMA") :].strip().split(" ", 1)[0].split("=")[0].strip()
            if pragma.rstrip(";.") not in _ALLOWED_PRAGMAS:
                problems.append(f"pragma_not_allowed:{op.value}")
    return tuple(problems)


def _is_trusted_store(path: object) -> bool:
    """URI 形态守卫（不是授权）：含 `?`/`#` 的路径会被 sqlite3 URI 解析吃掉，直接拒。

    Windows 盘符路径本身合法，但 `file:` URI 由 `_read_only_uri` 用 `Path.resolve().as_uri()`
    生成，因此这里只保证传入字符串没有 URI 注入面。
    """

    if not isinstance(path, str) or not path or len(path) > 4096:
        return False
    if "\x00" in path or "?" in path or "#" in path:
        return False
    return not any(ord(char) < 32 for char in path)


def _read_only_uri(path: str) -> str:
    return pathlib.Path(path).resolve().as_uri() + "?mode=ro"


def _connect_read_only(uri: str, busy_timeout_ms: int) -> sqlite3.Connection:
    if not uri.startswith("file:") or not uri.endswith("?mode=ro"):
        raise sqlite3.ProgrammingError("workbuddy adapter requires a mode=ro file URI")
    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=busy_timeout_ms / 1000.0,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.text_factory = str
    return conn


def _db_stream_label(path: str) -> tuple[str, bool]:
    """存储标签只取 basename，且必须过封闭白名单；不合规则换成固定替身并回报被遮蔽。"""

    name = pathlib.Path(path).name
    if len(name) > _DB_NAME_MAX_CHARS or not _DB_NAME_ALLOWED.fullmatch(name):
        return _REDACTED_STREAM_LABEL, True
    return name, False


def _id_shape_ok(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_ID_CHARS:
        return False
    return bool(_ID_SHAPE.fullmatch(value))


def _as_project_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_PROJECT_CHARS:
        return None
    if "\x00" in text or text.startswith("<") or "|" in text:
        return None
    return text


def _clamp(value: int, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("limit must be an int")
    return max(lower, min(int(value), upper))


def _validate_args(
    path: object,
    session_id: object,
    busy_timeout_ms: object,
    max_rows: object,
    max_candidates: object,
    max_bytes: object,
) -> str | None:
    if not isinstance(path, str) or not path:
        return "path"
    if not isinstance(session_id, str) or not session_id:
        return "session_id"
    for name, value, lower, upper in (
        ("busy_timeout_ms", busy_timeout_ms, _BUSY_TIMEOUT_MIN_MS, _BUSY_TIMEOUT_MAX_MS),
        ("max_rows", max_rows, 1, MAX_ROWS_PER_SESSION),
        ("max_candidates", max_candidates, 1, MAX_CANDIDATES_PER_SESSION),
        ("max_bytes", max_bytes, 1, MAX_STAGE_BYTES_PER_SESSION),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
            return name
    return None


def _execute(
    conn: sqlite3.Connection, op: _Op, params: Sequence[Any] = ()
) -> sqlite3.Cursor:
    statement = _QUERIES[op]
    if not isinstance(statement, str):
        raise sqlite3.ProgrammingError("unknown workbuddy operation")
    if statement.count("?") != len(params):
        raise sqlite3.ProgrammingError("workbuddy statement arity changed")
    return conn.execute(statement, tuple(params))  # pi-lens-ignore: python-sql-injection


def _read_int(cursor: sqlite3.Cursor) -> int:
    row = cursor.fetchone()
    if row is None:
        return 0
    value = row[0]
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


class _Stats:
    """本模块自有计数：只记「为什么这一行没用上」，不记来源语义。"""

    __slots__ = (
        "rows_read",
        "text_chars",
        "unknown_columns",
        "identity_unusable",
        "timestamp_unusable",
        "content_empty",
        "content_shape",
        "content_overlong",
        "row_id_unusable",
        "status_unknown",
        "body_missing",
    )

    def __init__(self) -> None:
        self.rows_read = 0
        self.text_chars = 0
        self.unknown_columns: tuple[str, ...] = ()
        self.identity_unusable = 0
        self.timestamp_unusable = 0
        self.content_empty = 0
        self.content_shape = 0
        self.content_overlong = 0
        self.row_id_unusable = 0
        self.status_unknown = 0
        self.body_missing = 0

    def withhold(self, key: str) -> None:
        if key in _WITHHELD_KEYS:
            setattr(self, key, getattr(self, key) + 1)

    def accounted(self) -> dict[str, int]:
        return {
            "identity_unusable": self.identity_unusable,
            "timestamp_unusable": self.timestamp_unusable,
            "content_empty": self.content_empty,
            "content_shape": self.content_shape,
            "content_overlong": self.content_overlong,
            "row_id_unusable": self.row_id_unusable,
            "status_unknown": self.status_unknown,
            "body_missing": self.body_missing,
        }

    def unusable(self) -> int:
        return sum(self.accounted().values())


def _probe_schema(conn: sqlite3.Connection, stats: _Stats) -> tuple[int | None, bool]:
    """表与列集合就是判据；不认识的字面量零容忍。

    缺失声明表 → `SCHEMA_UNKNOWN_TABLES`；声明列缺失 → `SCHEMA_UNKNOWN_COLUMNS`；`sessions`
    里未声明的列只计入 `unknown_columns`（存在但不解释），因为本模块的 SELECT 面从不超过
    `WORKBUDDY_SESSIONS_KNOWN`。返回 (user_version, schema_known)。
    """

    names = {str(row[0]) for row in _execute(conn, _Op.TABLE_NAMES)}
    missing = [name for name in _REQUIRED_TABLES if name not in names]
    if missing:
        raise _WbAbort(WorkBuddyGateCode.SCHEMA_UNKNOWN_TABLES, WorkBuddyAccessCode.FAULT)
    for table, declared in _DECLARED_COLUMNS.items():
        columns = {str(row[0]) for row in _execute(conn, _Op.TABLE_COLUMNS, (table,))}
        required = WORKBUDDY_SESSIONS_REQUIRED if table == "sessions" else declared
        if not required.issubset(columns):
            raise _WbAbort(WorkBuddyGateCode.SCHEMA_UNKNOWN_COLUMNS, WorkBuddyAccessCode.FAULT)
        if table == "sessions":
            stats.unknown_columns = tuple(sorted(columns - declared))
    version_row = _execute(conn, _Op.USER_VERSION).fetchone()
    version = None if version_row is None else version_row[0]
    if isinstance(version, bool) or not isinstance(version, int):
        version = None
    return version, True


def _probe_integrity(conn: sqlite3.Connection) -> bool:
    row = _execute(conn, _Op.INTEGRITY).fetchone()
    if row is None:
        return False
    return isinstance(row[0], str) and row[0] == "ok"


#: 正文文件路径形状未逐字核实（`~/.workbuddy/sessions/` 存在，但记录形状、注入面与 id↔文件
#: 的对应关系都没有证据），因此索引侧从不自行打开任何正文文件。
_BODY_DIR_NAME = "sessions"


@dataclass(frozen=True)
class WorkBuddyStoreRef:
    """有界库集合的一项：存储路径 + 会话 id。构造即形状门，不含授权语义。"""

    store_path: str
    session_id: str

    def __post_init__(self) -> None:
        if type(self.store_path) is not str or not self.store_path.strip():
            raise ValueError("WorkBuddyStoreRef.store_path must be a non-empty str")
        if type(self.session_id) is not str or not self.session_id.strip():
            raise ValueError("WorkBuddyStoreRef.session_id must be a non-empty str")
        object.__setattr__(self, "store_path", self.store_path.strip())
        object.__setattr__(self, "session_id", self.session_id.strip())


def _workbuddy_service_key(*, scope: str, ref: WorkBuddyStoreRef) -> str:
    return service_binding_key(
        scope=scope, source=SOURCE_WORKBUDDY, path=ref.store_path, session_id=ref.session_id
    )


@dataclass(frozen=True)
class _SessionFacts:
    """索引侧从 `sessions` 单行取到的事实（原始值，未归一化，不外传）。"""

    row_id: str
    title: object
    created_at: object
    updated_at: object
    deleted: bool
    status: object
    status_known: bool
    status_active: bool


def _status_state(value: object, stats: _Stats) -> tuple[bool, bool]:
    """(取值域是否认识, 是否留在会话集)。未认识一律保守剔除并计数。"""

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in WORKBUDDY_ACTIVE_STATUSES:
            return True, True
    stats.withhold("status_unknown")
    return False, False


def _load_facts(conn: sqlite3.Connection, session_id: str, stats: _Stats) -> _SessionFacts | None:
    count = _read_int(_execute(conn, _Op.SESSION_ROW_COUNT, (session_id,)))
    if count == 0:
        return None
    if count > 1:
        # 同一 id 命中多行：取数上界拒，不挑一行冒充整个会话。
        raise _WbAbort(WorkBuddyGateCode.CANDIDATE_LIMIT, WorkBuddyAccessCode.FAULT)
    row = _execute(conn, _Op.SESSION_FACTS, (session_id,)).fetchone()
    if row is None or len(row) != len(_SESSIONS_SELECT):
        return None
    stats.rows_read += 1
    row_id, title, created_at, updated_at, deleted_at, status, _source_mode = row
    if not _id_shape_ok(row_id) or row_id != session_id:
        stats.withhold("identity_unusable")
        raise _WbAbort(WorkBuddyGateCode.ID_SHAPE_REJECTED, WorkBuddyAccessCode.FAULT)
    known, active = _status_state(status, stats)
    deleted = deleted_at is not None
    if isinstance(title, str):
        stats.text_chars += len(title)
    return _SessionFacts(
        row_id=str(row_id),
        title=title,
        created_at=created_at,
        updated_at=updated_at,
        deleted=deleted,
        status=status,
        status_known=known,
        status_active=active,
    )


def _load_usage(conn: sqlite3.Connection, session_id: str, stats: _Stats, max_rows: int) -> int:
    """`session_usage` 只提供体量事实（used/size），不推断正文，也不把 credit_json 展开。"""

    rows = 0
    try:
        for row in _execute(conn, _Op.USAGE_ROWS, (session_id, max_rows)):
            rows += 1
            stats.rows_read += 1
            for value in row[:2]:
                if isinstance(value, bool) or not isinstance(value, int):
                    stats.withhold("row_id_unusable")
    except sqlite3.Error as exc:  # 表存在但列形态不合：当作 schema 不认识处理
        access = _classify_exception(exc)
        raise _WbAbort(_gate_for_access(access), access) from None
    return rows


class _WorkBuddyRun:
    """单次索引读的连接生命周期：`mode=ro` 连接、显式只读事务、逐字面语句、必关。"""

    __slots__ = (
        "path",
        "session_id",
        "max_rows",
        "max_candidates",
        "max_bytes",
        "conn",
        "_tx",
        "_closed",
        "facts",
        "usage_rows",
        "stats",
        "schema_version",
        "schema_known",
        "integrity_ok",
    )

    def __init__(
        self,
        *,
        path: str,
        session_id: str,
        max_rows: int,
        max_candidates: int,
        max_bytes: int,
    ) -> None:
        self.path = path
        self.session_id = session_id
        self.max_rows = max_rows
        self.max_candidates = max_candidates
        self.max_bytes = max_bytes
        self.conn: sqlite3.Connection | None = None
        self._tx = False
        self._closed = False
        self.facts: _SessionFacts | None = None
        self.usage_rows = 0
        self.stats = _Stats()
        self.schema_version: int | None = None
        self.schema_known = False
        self.integrity_ok: bool | None = None

    def open(self, busy_timeout_ms: int) -> None:
        if not _is_trusted_store(self.path):
            raise _WbAbort(WorkBuddyGateCode.INVALID_ARGUMENT, WorkBuddyAccessCode.DENIED)
        # 绝对路径形态门先于任何文件系统探测：相对路径在这里就已经不可信，进程的当前目录
        # 不得参与位置判定（同一串相对路径在两个 cwd 下指向两个不同文件）。判据与策略层
        # `authorize_store` 的 `path_unsafe` 同源，因此不存在「适配器放行、策略层拒绝」两套门。
        if not is_safe_literal_path(self.path):
            raise _WbAbort(WorkBuddyGateCode.STORAGE_DENIED, WorkBuddyAccessCode.DENIED)
        target = pathlib.Path(self.path)
        if not target.exists():
            raise _WbAbort(WorkBuddyGateCode.SESSION_ABSENT, WorkBuddyAccessCode.NOT_FOUND)
        if not target.is_file():
            raise _WbAbort(WorkBuddyGateCode.STORAGE_DENIED, WorkBuddyAccessCode.DENIED)
        uri = _read_only_uri(self.path)
        try:
            conn = _connect_read_only(uri, busy_timeout_ms)
        except sqlite3.Error as exc:
            access = _classify_exception(exc, self.path)
            raise _WbAbort(_gate_for_access(access), access) from None
        self.conn = conn
        try:
            _execute(conn, _Op.QUERY_ONLY)
            _execute(conn, _Op.BEGIN_READ)
            self._tx = True
        except sqlite3.Error as exc:
            access = _classify_exception(exc, self.path)
            raise _WbAbort(_gate_for_access(access), access) from None

    def _require(self) -> sqlite3.Connection:
        if self.conn is None or self._closed:
            raise _WbAbort(WorkBuddyGateCode.STORAGE_DENIED, WorkBuddyAccessCode.DENIED)
        return self.conn

    def probe(self) -> None:
        conn = self._require()
        try:
            self.integrity_ok = _probe_integrity(conn)
            self.schema_version, self.schema_known = _probe_schema(conn, self.stats)
        except _WbAbort:
            raise
        except sqlite3.Error as exc:
            access = _classify_exception(exc, self.path)
            raise _WbAbort(_gate_for_access(access), access) from None
        if self.integrity_ok is not True:
            raise _WbAbort(WorkBuddyGateCode.INTEGRITY, WorkBuddyAccessCode.FAULT)

    def load(self) -> None:
        conn = self._require()
        try:
            self.facts = _load_facts(conn, self.session_id, self.stats)
            if self.facts is not None:
                self.usage_rows = _load_usage(conn, self.session_id, self.stats, self.max_rows)
        except _WbAbort:
            raise
        except sqlite3.Error as exc:
            access = _classify_exception(exc, self.path)
            raise _WbAbort(_gate_for_access(access), access) from None

    def build_plan(self) -> WorkBuddySessionPlan:
        facts = self.facts
        stats = self.stats
        reasons = stats.accounted()
        row_count = stats.rows_read
        if facts is None:
            return WorkBuddySessionPlan(
                available=True,
                access=WorkBuddyAccessCode.OK,
                gate=WorkBuddyGateCode.SESSION_ABSENT,
                session_exists=False,
                row_count=row_count,
                candidate_count=0,
                inactive_count=0,
                unknown_columns=stats.unknown_columns,
                text_chars=stats.text_chars,
                unusable_count=stats.unusable(),
                unavailable_reasons=reasons,
                integrity_ok=self.integrity_ok,
                schema_version=self.schema_version,
                schema_known=self.schema_known,
                body_available=False,
                body_missing_reason=WORKBUDDY_BODY_LAYOUT_REASON,
            )
        inactive = 1 if (facts.deleted or not facts.status_active) else 0
        gate = (
            WorkBuddyGateCode.BODY_LAYOUT_UNKNOWN
            if facts.status_known
            else WorkBuddyGateCode.STATUS_UNKNOWN
        )
        return WorkBuddySessionPlan(
            available=True,
            access=WorkBuddyAccessCode.OK,
            gate=gate,
            session_exists=True,
            row_count=row_count,
            candidate_count=1 + self.usage_rows,
            inactive_count=inactive,
            unknown_columns=stats.unknown_columns,
            text_chars=stats.text_chars,
            unusable_count=stats.unusable(),
            unavailable_reasons=reasons,
            integrity_ok=self.integrity_ok,
            schema_version=self.schema_version,
            schema_known=self.schema_known,
            body_available=False,
            body_missing_reason=WORKBUDDY_BODY_LAYOUT_REASON,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        conn = self.conn
        if conn is not None:
            if self._tx:
                self._tx = False
                with contextlib.suppress(sqlite3.Error):
                    _execute(conn, _Op.END_READ)
            with contextlib.suppress(sqlite3.Error):
                conn.close()
        self.conn = None


def _fallback_plan(access: WorkBuddyAccessCode, gate: WorkBuddyGateCode) -> WorkBuddySessionPlan:
    return _empty_plan(access, gate)


class WorkBuddyBodyLineParser:
    """正文行解析器（**平铺与嵌套两种形状都接，双限共用本模块常量**）。

    存在理由：取证完成后宿主直接注入正文行即可接线，不必改服务层。默认情况下
    `run_workbuddy_session` 拿不到注入 ⇒ 一行的正文也不读，因此本解析器在本增量里
    只由合成用例驱动。工具/系统注入/后台通知类角色一律不产记录；正文形状不合的行
    逐条 withhold 并计数（既进 `withheld_reasons` 也进 `ParseStats`）。
    """

    def __init__(
        self,
        *,
        session_id: str,
        project: str | None = None,
        stream_label: str | None = None,
        max_text_chars: int = MAX_ROW_TEXT_TOTAL_CHARS,
        max_lines: int = MAX_ROWS_PER_SESSION,
    ) -> None:
        self._session_id = session_id
        self._project = _as_project_text(project)
        self._stream_label = stream_label
        self._max_text_chars = max(1, min(int(max_text_chars), MAX_ROW_TEXT_TOTAL_CHARS))
        self._max_lines = max(1, min(int(max_lines), MAX_ROWS_PER_SESSION))
        self._line_no = 0
        self._line_limit_exceeded = False
        self._finished = False
        self.stats = ParseStats()
        self.withheld: dict[str, int] = dict.fromkeys(_WITHHELD_KEYS, 0)

    @property
    def project_quality(self) -> ProjectQuality:
        # 正文侧归属只能来自宿主注入的项目断言（索引侧的 workspaces.path 未与正文关联核实）。
        return ProjectQuality.CALLER_ASSERTED if self._project is not None else ProjectQuality.UNKNOWN

    def _withhold(self, key: str, issue: IssueCode) -> None:
        self.withheld[key] = self.withheld.get(key, 0) + 1
        self.stats.note(issue)

    def _decode(self, line: bytes | str) -> str | None:
        if isinstance(line, bytes):
            if len(line) > MAX_LINE_BYTES:
                self.stats.note(IssueCode.LINE_TOO_LARGE)
                return None
            try:
                return line.decode("utf-8")
            except UnicodeDecodeError:
                self._withhold("content_shape", IssueCode.CORRUPT_LINE)
                return None
        return line

    def feed_line(self, line: bytes | str) -> list[StandardRecord]:
        if self._finished:
            raise RuntimeError("parser is finished; create a new instance for a new stream")
        if self._line_limit_exceeded:
            return []
        if self._line_no >= self._max_lines:
            self._line_limit_exceeded = True
            self.stats.note(IssueCode.MAX_STREAM_LINES_EXCEEDED)
            return []
        self._line_no += 1
        self.stats.lines_seen += 1
        text = self._decode(line)
        if text is None:
            return []
        stripped = text.lstrip("\ufeff").strip()
        if not stripped:
            self.stats.note(IssueCode.BLANK_LINE)
            return []
        try:
            payload = json.loads(stripped)
        except (ValueError, RecursionError):
            self._withhold("content_shape", IssueCode.CORRUPT_LINE)
            return []
        if not isinstance(payload, dict):
            self._withhold("content_shape", IssueCode.LINE_NOT_OBJECT)
            return []
        row_session = payload.get("session_id", payload.get("sessionId"))
        if isinstance(row_session, str) and row_session and row_session != self._session_id:
            # 正文文件混入他会话行：不合并、不猜归属。
            self._withhold("identity_unusable", IssueCode.SESSION_ID_MISMATCH)
            return []
        role = payload.get("role")
        if not isinstance(role, str) or not role.strip():
            self._withhold("role_unusable", IssueCode.MISSING_ROLE)
            return []
        normalized = role.strip().lower()
        if normalized not in _BODY_TEXT_ROLES:
            # 工具结果/系统注入/后台通知类一律不产记录（计数但不谎称正文覆盖）。
            self.withheld["content_shape"] = self.withheld.get("content_shape", 0) + 1
            self.stats.note(IssueCode.SKIPPED_ROLE)
            return []
        content = payload.get("content", payload.get("text"))
        if isinstance(content, dict):
            content = content.get("text")
        if isinstance(content, list):
            parts: list[str] = []
            for item in content[:MAX_CONTENT_BLOCKS_PER_LINE]:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            content = "\n".join(parts)
        if not isinstance(content, str):
            self._withhold("content_shape", IssueCode.INVALID_CONTENT_SHAPE)
            return []
        body = content.strip()
        if not body:
            self._withhold("content_empty", IssueCode.NO_TEXT_CONTENT)
            return []
        truncated = len(body) > self._max_text_chars
        if truncated:
            body = body[: self._max_text_chars]
            self.withheld["content_overlong"] = self.withheld.get("content_overlong", 0) + 1
            self.stats.note(IssueCode.TEXT_BLOCK_TRUNCATED)
        timestamp, quality = normalize_timestamp(payload.get("timestamp", payload.get("created_at")))
        issues: list[IssueCode] = []
        if quality is not TimeQuality.EXACT:
            issue = TIMESTAMP_ISSUES.get(quality)
            if issue is not None:
                self.stats.note(issue)
                issues.append(issue)
        if self._project is None:
            issues.append(IssueCode.PROJECT_UNVERIFIED)
        record = StandardRecord(
            source=SOURCE_WORKBUDDY,
            session_id=self._session_id,
            location=SourceLocation(self._stream_label, self._line_no, 0),
            text=body,
            role=normalized,
            executor=None,
            timestamp=timestamp,
            time_quality=quality,
            project=self._project,
            project_quality=self.project_quality,
            issues=tuple(issues),
        )
        self.stats.records_emitted += 1
        self.stats.lines_with_records += 1
        return [record]

    def feed(self, lines: Iterable[bytes | str]) -> list[StandardRecord]:
        if isinstance(lines, (str, bytes, bytearray)):
            raise TypeError("feed requires an iterable of lines, not a whole str/bytes payload")
        out: list[StandardRecord] = []
        for line in lines:
            out.extend(self.feed_line(line))
        return out

    def finish(self) -> ParseStats:
        if self._finished:
            return self.stats
        self._finished = True
        if self._project is None:
            self.stats.note(IssueCode.UNKNOWN_PROJECT)
        return self.stats


def _outcome(
    *,
    complete: bool,
    gate: WorkBuddyGateCode,
    access: WorkBuddyAccessCode,
    stage: StageOutcome | None,
    records_emitted: int,
    rows_read: int,
    withheld: Mapping[str, int],
    parse: ParseStats,
    plan: WorkBuddySessionPlan,
    denial: PolicyDenied | None = None,
) -> WorkBuddySessionOutcome:
    return WorkBuddySessionOutcome(
        complete=complete,
        publication_allowed=False,
        gate=gate,
        access=access,
        stage=stage,
        records_emitted=records_emitted,
        rows_read=rows_read,
        withheld_reasons=dict(withheld),
        parse=parse,
        plan=plan,
        denial_code=None if denial is None else denial.code.value,
    )


def run_workbuddy_session(
    *,
    path: object,
    session_id: object,
    scope: str | None = None,
    policy: SessionPolicy | None = None,
    project_filter: str | None = None,
    body_lines: Iterable[bytes | str] | None = None,
    stream_label: str | None = None,
    should_stop: Callable[[], bool] | None = None,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    max_rows: int = MAX_ROWS_PER_SESSION,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = DEFAULT_STAGE_BYTES,
) -> WorkBuddySessionOutcome:
    """执行一次会话级读取：先过两条轴，再取索引事实，正文只在宿主注入时读。

    - `authorize_store(scope, SOURCE_WORKBUDDY, path, kind=FILE)` 未批 ⇒ `STORAGE_DENIED`，不开
      任何文件；`authorize_attribution` 未批 ⇒ `ATTRIBUTION_DENIED`（两条轴各判一次，互不替代）。
    - `body_lines is None` ⇒ `BODY_MISSING`：零记录、不完整，计划里 `body_available=False`。
      绝不冒充「这个会话没有消息」，也绝不自己猜正文路径。
    - 本增量没有发布通道，因此 `publication_allowed` 恒 False；`capture`/`admit` 钩子由服务层
      传入时也只影响暂存阶段，不改变结论口径。
    """

    invalid = _validate_args(path, session_id, busy_timeout_ms, max_rows, max_candidates, max_bytes)
    if invalid is not None:
        plan = _empty_plan(WorkBuddyAccessCode.DENIED, WorkBuddyGateCode.INVALID_ARGUMENT)
        return _outcome(
            complete=False,
            gate=WorkBuddyGateCode.INVALID_ARGUMENT,
            access=WorkBuddyAccessCode.DENIED,
            stage=None,
            records_emitted=0,
            rows_read=0,
            withheld=plan.unavailable_reasons,
            parse=ParseStats(),
            plan=plan,
        )
    if (policy is None) != (scope is None):
        plan = _empty_plan(WorkBuddyAccessCode.DENIED, WorkBuddyGateCode.INVALID_ARGUMENT)
        return _outcome(
            complete=False,
            gate=WorkBuddyGateCode.INVALID_ARGUMENT,
            access=WorkBuddyAccessCode.DENIED,
            stage=None,
            records_emitted=0,
            rows_read=0,
            withheld=plan.unavailable_reasons,
            parse=ParseStats(),
            plan=plan,
        )
    assert isinstance(path, str) and isinstance(session_id, str)

    # 存储轴之外的第二道位置门：没有策略也要拒相对路径。形状不合是「不可信参数」，与
    # 「库不存在」是两回事，因此门取 STORAGE_DENIED + denial_code=path_unsafe（策略层给出
    # 同一枚 `RefusalCode.PATH_UNSAFE`），并且一个文件也不碰。
    if not is_safe_literal_path(path):
        plan = _empty_plan(WorkBuddyAccessCode.DENIED, WorkBuddyGateCode.STORAGE_DENIED)
        return _outcome(
            complete=False,
            gate=WorkBuddyGateCode.STORAGE_DENIED,
            access=WorkBuddyAccessCode.DENIED,
            stage=None,
            records_emitted=0,
            rows_read=0,
            withheld=plan.unavailable_reasons,
            parse=ParseStats(),
            plan=plan,
            denial=PolicyDenied(RefusalCode.PATH_UNSAFE),
        )

    plan: WorkBuddySessionPlan
    if policy is not None and scope is not None:
        try:
            policy.authorize_store(scope, SOURCE_WORKBUDDY, path, kind=TargetKind.FILE)
        except PolicyDenied as denial:
            plan = _empty_plan(WorkBuddyAccessCode.DENIED, WorkBuddyGateCode.STORAGE_DENIED)
            return _outcome(
                complete=False,
                gate=WorkBuddyGateCode.STORAGE_DENIED,
                access=WorkBuddyAccessCode.DENIED,
                stage=None,
                records_emitted=0,
                rows_read=0,
                withheld=plan.unavailable_reasons,
                parse=ParseStats(),
                plan=plan,
                denial=denial,
            )
        try:
            policy.authorize_attribution(scope, path, project=project_filter)
        except PolicyDenied as denial:
            plan = _empty_plan(WorkBuddyAccessCode.DENIED, WorkBuddyGateCode.ATTRIBUTION_DENIED)
            return _outcome(
                complete=False,
                gate=WorkBuddyGateCode.ATTRIBUTION_DENIED,
                access=WorkBuddyAccessCode.DENIED,
                stage=None,
                records_emitted=0,
                rows_read=0,
                withheld=plan.unavailable_reasons,
                parse=ParseStats(),
                plan=plan,
                denial=denial,
            )

    plan = plan_workbuddy_session(
        path=path,
        session_id=session_id,
        busy_timeout_ms=busy_timeout_ms,
        max_rows=max_rows,
        max_candidates=max_candidates,
        max_bytes=max_bytes,
    )
    if not plan.available:
        return _outcome(
            complete=False,
            gate=plan.gate,
            access=plan.access,
            stage=None,
            records_emitted=0,
            rows_read=plan.row_count,
            withheld=plan.unavailable_reasons,
            parse=ParseStats(),
            plan=plan,
        )
    if not plan.session_exists:
        return _outcome(
            complete=False,
            gate=WorkBuddyGateCode.SESSION_ABSENT,
            access=WorkBuddyAccessCode.OK,
            stage=None,
            records_emitted=0,
            rows_read=plan.row_count,
            withheld=plan.unavailable_reasons,
            parse=ParseStats(),
            plan=plan,
        )
    if plan.inactive_count:
        return _outcome(
            complete=False,
            gate=plan.gate,
            access=WorkBuddyAccessCode.OK,
            stage=None,
            records_emitted=0,
            rows_read=plan.row_count,
            withheld=plan.unavailable_reasons,
            parse=ParseStats(),
            plan=plan,
        )

    label, _masked = _db_stream_label(path)
    if body_lines is None:
        stats = _Stats()
        stats.withhold("body_missing")
        return _outcome(
            complete=False,
            gate=WorkBuddyGateCode.BODY_MISSING,
            access=WorkBuddyAccessCode.OK,
            stage=None,
            records_emitted=0,
            rows_read=plan.row_count,
            withheld=stats.accounted(),
            parse=ParseStats(),
            plan=plan,
        )

    parser = WorkBuddyBodyLineParser(
        session_id=session_id, project=project_filter, stream_label=label or stream_label
    )
    stage = SessionCandidateStage(SOURCE_WORKBUDDY, session_id, max_candidates=max_candidates, max_bytes=max_bytes)
    emitted = 0
    for line in body_lines:
        if should_stop is not None and should_stop():
            stage.cancel(StageDiscardReason.CANCELLED)
            parse = parser.finish()
            return _outcome(
                complete=False,
                gate=WorkBuddyGateCode.BODY_MISSING,
                access=WorkBuddyAccessCode.OK,
                stage=stage.finish(stream_complete=False),
                records_emitted=emitted,
                rows_read=plan.row_count,
                withheld=parser.withheld,
                parse=parse,
                plan=plan,
            )
        for record in parser.feed_line(line):
            if stage.add(record):
                emitted += 1
        if stage.discarded:
            break
    parse = parser.finish()
    stream_complete = not stage.discarded and not parse.partial
    stage_outcome = stage.finish(stream_complete=stream_complete)
    complete = bool(stage_outcome.complete and stream_complete and not stage.discarded)
    gate = plan.gate if complete else WorkBuddyGateCode.BODY_LAYOUT_UNKNOWN
    return _outcome(
        complete=complete,
        gate=gate,
        access=WorkBuddyAccessCode.OK,
        stage=stage_outcome,
        records_emitted=emitted,
        rows_read=plan.row_count,
        withheld=parser.withheld,
        parse=parse,
        plan=plan,
    )


# ---------------------------------------------------------------------------
# 聚合服务层：有界库集合的索引侧结论（正文未核实 ⇒ 恒不完整、恒零结果）
# ---------------------------------------------------------------------------


class WorkBuddyAggregateFailureCategory(StrEnum):
    """聚合层的封闭失败类目（与 hermes 聚合层同一取向：状态与原因分轴）。"""

    SCOPE_MISMATCH = "scope_mismatch"
    SOURCE_UNSUPPORTED = "source_unsupported"
    INVALID_REQUEST = "invalid_request"
    STORES_UNUSABLE = "stores_unusable"
    BODY_UNVERIFIED = "body_unverified"
    INTERNAL_FAILURE = "internal_failure"


class WorkBuddyAggregateStageReached(StrEnum):
    COORDINATOR = "coordinator"
    STORE_PLAN = "store_plan"
    PUBLICATION = "publication"
    PUBLISHED = "published"


@dataclass(frozen=True)
class WorkBuddyContextOutcome:
    """正文侧上下文的诚实拒答：未核实 ⇒ 零窗口、零结果、固定原因。"""

    complete: bool
    partial: bool
    status: str
    reason: str
    coverage_scope: str
    results: tuple[dict[str, Any], ...] = ()

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "partial": self.partial,
            "status": self.status,
            "reason": self.reason,
            "coverage_scope": self.coverage_scope,
            "results": [dict(row) for row in self.results],
            "returned_count": len(self.results),
        }


def _denied_outcome(
    plan: WorkBuddySessionPlan, denial: PolicyDenied, gate: WorkBuddyGateCode
) -> WorkBuddySessionOutcome:
    """两条轴之一的拒绝：计划内只记封闭枚举，原文（可能含路径）不外传。"""

    return _outcome(
        complete=False,
        gate=gate,
        access=WorkBuddyAccessCode.DENIED,
        stage=None,
        records_emitted=0,
        rows_read=0,
        withheld=plan.unavailable_reasons,
        parse=ParseStats(),
        plan=replace(
            plan,
            unavailable_reasons={**plan.unavailable_reasons, "policy_denial": denial.code.value},
        ),
        denial=denial,
    )


def plan_workbuddy_session(
    *,
    path: object,
    session_id: object,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    max_rows: int = MAX_ROWS_PER_SESSION,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = DEFAULT_STAGE_BYTES,
) -> WorkBuddySessionPlan:
    """执行前计划：只做索引侧只读取数，不做任何授权判断（调用方先过 store/attribution 两轴）。

    白名单自证先跑一次：清单不过 ⇒ 整次拒绝，不开连接。正文侧恒 `body_available=False`，
    计划里绝不出现「0 条消息」这种把未核实冒充为完整结论的形状。
    """

    problems = whitelist_shape_problems()
    if problems:
        return _empty_plan(WorkBuddyAccessCode.FAULT, WorkBuddyGateCode.INTERNAL_FAILURE)
    invalid = _validate_args(path, session_id, busy_timeout_ms, max_rows, max_candidates, max_bytes)
    if invalid is not None:
        return _empty_plan(WorkBuddyAccessCode.DENIED, WorkBuddyGateCode.INVALID_ARGUMENT)
    assert isinstance(path, str) and isinstance(session_id, str)  # 形态门后不再信任早先判断
    run = _WorkBuddyRun(
        path=path,
        session_id=session_id,
        max_rows=max_rows,
        max_candidates=max_candidates,
        max_bytes=max_bytes,
    )
    try:
        run.open(int(busy_timeout_ms))
        run.probe()
        run.load()
        return run.build_plan()
    except _WbAbort as abort:
        return _empty_plan(abort.access, abort.gate)
    except Exception:
        return _empty_plan(WorkBuddyAccessCode.FAULT, WorkBuddyGateCode.INTERNAL_FAILURE)
    finally:
        run.close()


def _single_store_scope(index: int) -> str:
    return f"single_approved_store:{index}"


def _store_row(index: int, ref: WorkBuddyStoreRef, outcome: WorkBuddySessionOutcome) -> dict[str, Any]:
    """逐库诊断行：只披露封闭枚举与本模块计数，绝不回显路径或 SQL 原文。"""

    plan = outcome.plan
    return {
        "index": index,
        "coverage_scope": _single_store_scope(index),
        "session_id": ref.session_id,
        "store": _db_stream_label(ref.store_path)[0],
        "status": "error" if plan.access is WorkBuddyAccessCode.FAULT else "incomplete",
        "gate": plan.gate.value,
        "access": plan.access.value,
        "records_captured": outcome.records_emitted,
        "rows_read": outcome.rows_read,
        "returned_count": 0,
        "reason": plan.gate.value,
        "plan": plan.as_public_dict(),
    }


def _coverage_row(
    source: str,
    *,
    status: str,
    reason: str,
    partial: bool,
    filter_errors: Sequence[str] = (),
    scanned: int = 0,
    coverage_scope: str = COVERAGE_SCOPE_MULTI_WORKBUDDY,
) -> dict[str, Any]:
    return {
        "source": source,
        "coverage_scope": coverage_scope,
        "status": status,
        "matched_count": 0,
        "returned_count": 0,
        "records_scanned": scanned,
        "skipped_count": scanned,
        "scan_chars": 0,
        "partial": partial,
        "filter_errors": list(filter_errors),
        "quality_issues": [],
        "reason": reason,
    }


def _aggregate_payload(
    *,
    reason: str,
    category: WorkBuddyAggregateFailureCategory,
    stage: WorkBuddyAggregateStageReached,
    stores: Sequence[dict[str, Any]],
    coverage_status: str = "incomplete",
    partial: bool = True,
    coverage_scope: str = COVERAGE_SCOPE_MULTI_WORKBUDDY,
    scanned: int = 0,
) -> dict[str, Any]:
    return {
        "results": [],
        "coverage": [
            _coverage_row(
                SOURCE_WORKBUDDY,
                status=coverage_status,
                reason=reason,
                partial=partial,
                scanned=scanned,
                coverage_scope=coverage_scope,
            )
        ],
        "complete": False,
        "partial": partial,
        "truncated": False,
        "total_matched": 0,
        "total_scanned": scanned,
        "skipped_records": 0,
        "records_withheld": 0,
        "rejected": False,
        "reason": reason,
        "stage_reached": stage.value,
        "failure_category": category.value,
        "coverage_scope": coverage_scope,
        "source_scopes": sorted(_single_store_scope(index) for index in range(len(stores))),
        "stores": [dict(row) for row in stores],
    }


def _validate_bound_stores(
    *,
    label: str,
    policy: object,
    scope: object,
    stores: object,
    ledger: object,
) -> None:
    if not isinstance(policy, SessionPolicy):
        raise TypeError(f"{label} requires a SessionPolicy")
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError(f"{label} requires a non-empty scope")
    if isinstance(stores, (str, bytes)) or not isinstance(stores, Sequence) or not stores:
        raise TypeError(f"{label} requires a non-empty sequence of WorkBuddyStoreRef")
    if len(stores) > MAX_STORES_PER_QUERY:
        raise ValueError(f"{label} accepts at most {MAX_STORES_PER_QUERY} stores")
    for ref in stores:
        if not isinstance(ref, WorkBuddyStoreRef):
            raise TypeError(f"{label} entries must be WorkBuddyStoreRef")
    if ledger is not None and not isinstance(ledger, ReferenceLedger):
        raise TypeError(f"{label} ledger must be a ReferenceLedger or None")


@dataclass(frozen=True)
class WorkBuddyAggregateSearchService:
    """有界库集合的聚合入口：**本增量只出索引侧诚实结论，恒零结果、恒不完整**。

    存在理由：正文文件形状未逐字核实（DES §05 只钉住索引侧列集）。本服务因此不伪造正文覆盖，
    也不把「零结果」写成「查过且没有」——coverage 行 status 恒 incomplete，reason 恒为
    `WORKBUDDY_BODY_LAYOUT_REASON`，逐库行披露 plan 的门禁码。
    """

    policy: SessionPolicy
    scope: str
    stores: tuple[WorkBuddyStoreRef, ...]
    ledger: ReferenceLedger | None = None

    def __post_init__(self) -> None:
        _validate_bound_stores(
            label="WorkBuddyAggregateSearchService",
            policy=self.policy,
            scope=self.scope,
            stores=self.stores,
            ledger=self.ledger,
        )
        object.__setattr__(self, "stores", tuple(self.stores))

    @property
    def source(self) -> str:
        return SOURCE_WORKBUDDY

    def store_refs(self) -> tuple[WorkBuddyStoreRef, ...]:
        return tuple(self.stores)

    def binding_key(self, index: int) -> str:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.stores):
            raise ValueError("binding_key index out of bounds")
        return _workbuddy_service_key(scope=self.scope, ref=self.stores[index])

    def context_service(self) -> WorkBuddyAggregateContextService:
        return WorkBuddyAggregateContextService(
            policy=self.policy,
            scope=self.scope,
            stores=self.stores,
            ledger=self.ledger,
        )

    def _denied_row(self, index: int, ref: WorkBuddyStoreRef, denial: PolicyDenied) -> dict[str, Any]:
        gate = WorkBuddyGateCode.STORAGE_DENIED
        access = WorkBuddyAccessCode.DENIED
        plan = _empty_plan(access, gate)
        plan = replace(
            plan,
            unavailable_reasons={**plan.unavailable_reasons, "policy_denial": denial.code.value},
        )
        outcome = _outcome(
            complete=False,
            gate=gate,
            access=access,
            stage=None,
            records_emitted=0,
            rows_read=0,
            withheld=plan.unavailable_reasons,
            parse=ParseStats(),
            plan=plan,
            denial=denial,
        )
        return _store_row(index, ref, outcome)

    def search(
        self,
        *,
        scope: str | None = None,
        query: str | None = None,
        sources: Sequence[str] | None = None,
        start: object = None,
        end: object = None,
        project: str | None = None,
        limit: int = _DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        requested = tuple(sources) if isinstance(sources, (list, tuple)) else (SOURCE_WORKBUDDY,)
        none_scope = COVERAGE_SCOPE_NONE
        if scope is not None and scope != self.scope:
            category = WorkBuddyAggregateFailureCategory.SCOPE_MISMATCH
            return _aggregate_payload(
                reason=category.value,
                category=category,
                stage=WorkBuddyAggregateStageReached.COORDINATOR,
                stores=[],
                partial=False,
                coverage_scope=none_scope,
            )
        if any(not isinstance(item, str) for item in requested) or SOURCE_WORKBUDDY not in requested:
            category = WorkBuddyAggregateFailureCategory.SOURCE_UNSUPPORTED
            return _aggregate_payload(
                reason=category.value,
                category=category,
                stage=WorkBuddyAggregateStageReached.COORDINATOR,
                stores=[],
                coverage_scope=none_scope,
            )
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PROTOCOL_LIMIT:
            category = WorkBuddyAggregateFailureCategory.INVALID_REQUEST
            return _aggregate_payload(
                reason=category.value,
                category=category,
                stage=WorkBuddyAggregateStageReached.COORDINATOR,
                stores=[],
                coverage_scope=none_scope,
            )

        rows: list[dict[str, Any]] = []
        scanned = 0
        try:
            for index, ref in enumerate(self.stores):
                try:
                    grant = self.policy.authorize_store(
                        self.scope, SOURCE_WORKBUDDY, ref.store_path, kind=TargetKind.FILE
                    )
                except PolicyDenied as denial:
                    rows.append(self._denied_row(index, ref, denial))
                    continue
                outcome = run_workbuddy_session(
                    path=getattr(grant, "readable_path", ref.store_path),
                    session_id=ref.session_id,
                    scope=self.scope,
                    policy=self.policy,
                    project_filter=project,
                )
                scanned += max(outcome.rows_read, 0)
                rows.append(_store_row(index, ref, outcome))
        except Exception:
            category = WorkBuddyAggregateFailureCategory.INTERNAL_FAILURE
            return _aggregate_payload(
                reason=category.value,
                category=category,
                stage=WorkBuddyAggregateStageReached.STORE_PLAN,
                stores=rows,
                scanned=scanned,
            )
        return _aggregate_payload(
            reason=WORKBUDDY_BODY_LAYOUT_REASON,
            category=WorkBuddyAggregateFailureCategory.BODY_UNVERIFIED,
            stage=WorkBuddyAggregateStageReached.STORE_PLAN,
            stores=rows,
            scanned=scanned,
        )


@dataclass(frozen=True)
class WorkBuddyAggregateContextService:
    """正文侧上下文：形状未核实 ⇒ 恒拒答（零窗口、零结果、固定原因，不触正文磁盘）。"""

    policy: SessionPolicy
    scope: str
    stores: tuple[WorkBuddyStoreRef, ...]
    ledger: ReferenceLedger | None = None

    def __post_init__(self) -> None:
        _validate_bound_stores(
            label="WorkBuddyAggregateContextService",
            policy=self.policy,
            scope=self.scope,
            stores=self.stores,
            ledger=self.ledger,
        )
        object.__setattr__(self, "stores", tuple(self.stores))

    @property
    def source(self) -> str:
        return SOURCE_WORKBUDDY

    def store_refs(self) -> tuple[WorkBuddyStoreRef, ...]:
        return tuple(self.stores)

    def binding_key(self, index: int) -> str:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.stores):
            raise ValueError("binding_key index out of bounds")
        return _workbuddy_service_key(scope=self.scope, ref=self.stores[index])

    def read(
        self,
        *,
        scope: str | None = None,
        source: str | None = None,
        session_id: str | None = None,
        location: str | None = None,
        project: str | None = None,
        before: int = 2,
        after: int = 2,
    ) -> WorkBuddyContextOutcome:
        none_scope = COVERAGE_SCOPE_NONE
        if scope is not None and scope != self.scope:
            return WorkBuddyContextOutcome(
                complete=False,
                partial=False,
                status="incomplete",
                reason=WorkBuddyAggregateFailureCategory.SCOPE_MISMATCH.value,
                coverage_scope=none_scope,
            )
        if source is not None and source != SOURCE_WORKBUDDY:
            return WorkBuddyContextOutcome(
                complete=False,
                partial=True,
                status="incomplete",
                reason=WorkBuddyAggregateFailureCategory.SOURCE_UNSUPPORTED.value,
                coverage_scope=none_scope,
            )
        return WorkBuddyContextOutcome(
            complete=False,
            partial=True,
            status="incomplete",
            reason=WORKBUDDY_BODY_LAYOUT_REASON,
            coverage_scope=COVERAGE_SCOPE_MULTI_WORKBUDDY,
        )
