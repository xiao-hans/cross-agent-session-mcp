"""Hermes 来源：SQLite **只读**单会话适配器（DES-ADAPTER-01 的第一版可核验实现）。

本模块只做一件事：在调用方已经批准的数据库文件上，把一个 `session_id` 的会话读成
`models.StandardRecord` 流，并交给既有 `session_stage.SessionCandidateStage` 做身份/归属核对。
它**不做**跨来源聚合、不实现 MCP 工具、不接服务器、不发现文件、不读任何真实库（测试只用
本模块自己新建的合成库）。

架构决定（与 Pi 文本行流的差异，全部有源码证据，见 docs/spec/09 工程记录）：

- **来源事实不是行流头部**，因此身份/归属不能沿用「读流时从头部建立、`finish()` 再核对」那一套：
  `sessions` / `messages` 两个来源事实都在读取**之前**一次性取到（两条固定参数化 SELECT），
  本模块据此建立身份与归属，`finish()` 仍由暂存层用两路独立证据核对。
  `run_hermes_session` 的 `admit`/`capture` 因此默认由本模块自己实现；调用方钩子仍可在其前/后
  施加更严格的拒绝（钩子只能更严，不能替本模块放行）。`capture` 的外递点固定在 `finish()` 的
  **完整核验通过之后**：`parse.partial` 或其它未核验终态不向它递任何正文（缓冲整批清空）。
- **来源授权与项目归属仍是两道独立判据**：`sessions.cwd` 是来源内的归属**证据**，
  不是读取授权，也不是「已按项目归类」（`policy.authorize_attribution` 仍独立核对它落在哪个
  已批准项目内）。归属值取 `git_repo_root`，缺失时取 `cwd`
  （与 Hermes 自己的会话分组键同形：`hermes_state_sessions.py:33-35`）。
- **归属质量记 `TRUSTED_HEADER_CWD`**：`sessions` 行就是本来源的**结构头**——它在任何消息行
  之前一次性读到（授权库上的白名单参数化 SELECT，且经过 schema 探针逐字核对列形状），与
  `PiLineParser` 采信可信头部 `cwd` 同形；因此按来源内部结构证据记录质量（`session_stage.py`
  的项目归属只承认 `TRUSTED_HEADER_CWD`，`CALLER_ASSERTED` 只参与冲突核对、永不确立归属）。两个
  列都不可用时归属降为 `None`/`UNKNOWN` 并计数，归属不成立即整批不通过核对。
- **schema 判据以列形状为准**：表集合必须存在，必需列按**子集**核对（缺列即无法核对），多出的列
  计入 `unknown_columns`；`schema_version` 表的恰好一行才是版本标记（不是 `PRAGMA user_version`）。
- **有界性在取正文之前判**：候选行数与正文总字符数都由统计 SQL（与取数语句**同基准**的
  谓词，见下方 `_Op.MESSAGE_STATS` 注释）得出整数，因此不必把正文取进内存就能判限；取数语句另带 `LIMIT max_rows + 1`，
  多出来的那一行就是「统计基准与取数基准不一致」的直接证据。取数之后仍逐条交给
  `SessionCandidateStage.add()` 做同一套精确扣账与整批丢弃。
- **一次读取 = 一个只读快照**：探测、事实、统计、取数、逐行产出全部跑在 `open()` 建立的
  同一条只读事务里（见上方「读取快照一致性」）。只把统计与取数的**谓词写成同基准**不够——
  那只能发现行数变化，发现不了**同行数的内容替换**（改正文不改长度、改时间戳不改行数）：
  行数账目会对得上，而产出的正文与统计依据的正文已不是同一版本。因此快照不成立时本模块
  不拿行数账目当完整性的证据，而是直接拒发。
- **诚实覆盖**：表存在性与必需列形状在任何取数之前核对完（多出的未知列计入 `unknown_columns`）；
  时间戳/正文由 SQL 端判出「可用/不可用」的**计数**，
  避免为判限把整段正文读入；取数语句的正文列同样只在 SQL 端判为合法时才透出（非法形态与
  超长行的完整载荷由投影置为 NULL，从不进入 Python；合法正文逐字完整返回，不截断冒充）。锁、损坏、IOERR 只报固定类别（`sqlite_result_code`），
  不回显 sqlite 消息、路径或值。任何非「读完」的游标都判不完整并整批丢弃（候选正文随即清空）。
  外部 `capture` 不得先收片段：逐行阶段只缓冲，完整核验通过之后才逐条外递，未核验终态缓冲整批清空。

只读约束：连接串固定 `file:<path>?mode=ro`（`uri=True`、驱动层 autocommit 即
`isolation_level=None`、不建 schema、不写）。白名单里除 SELECT/PRAGMA 之外只有两条**事务控制**
语句（`BEGIN` / `ROLLBACK`，逐字常量由 `_Op` 令牌携带，见 `_TRANSACTION_STATEMENTS`）：它们不写库，
且 `PRAGMA query_only = ON` 对同一连接上的任何写语句仍然生效。执行顺序与参数形状由调用方给出，
不接受任何由数据侧拼出的 SQL 文本。

**读取快照一致性**：一次读取的所有阶段（schema 探测、`sessions` 事实、统计、取数、逐行产出）
必须落在**同一个只读快照**上，否则同行数的内容替换（改正文不改长度、改时间戳不改行数）在
统计与取数之间完全不可见，而产出层的行数账目又会把它读成「对得上」——这类漂移既不是取消也不是
判限，只会冒充一份自洽的会话。因此 `open()` 在 `query_only` 之后立刻执行 `_Op.BEGIN_READ`，并用
`conn.in_transaction` 证实快照已建立（记 `_snapshot`）；每个取数阶段前由 `_require_conn()` 复核，
每批取数前由 `emit()` 经 `_snapshot_held()` 复核（探测与取数之间的停止/复核检查点也在这里）。
任一环节无法建立或保持快照就按固定码 `snapshot_unavailable` 拒绝、整批不产出（候选由
`finish(False)` 清空），并在 `close()` 里用 `_Op.END_READ`（`ROLLBACK`）归还读锁——绝不静默降级成「逐语句各自快照」。
事务控制本身失败（含驱动不接受 `BEGIN`）由 sqlite 错误码分类承接，不假装成功。

安全限制：不导入 MCP SDK；不打开目录；不解析 `HERMES_HOME`；不读任何默认真实库；
不写日志、不持久化正文。`HermesSessionOutcome.as_public_dict()` 的键值全部是本模块自有
闭合类别与整数——不含正文、不含会话标识/项目/路径/标题原值、不含 sqlite 消息。
"""

from __future__ import annotations

import contextlib
import math
import pathlib
import re
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NamedTuple, Protocol

from ..models import (
    IssueCode,
    ParseStats,
    ProjectQuality,
    SourceLocation,
    StandardRecord,
    TimeQuality,
    normalize_timestamp,
)
from ..policy import PolicyDenied, RefusalCode, SessionPolicy, TargetKind
from ..session_stage import (
    MAX_CANDIDATES_HARD_LIMIT,
    MAX_CANDIDATES_PER_SESSION,
    MAX_SESSION_KEY_CHARS,
    MAX_STAGE_BYTES_HARD_LIMIT,
    PER_RECORD_FIXED_OVERHEAD_BYTES,
    SessionCandidateStage,
    StageOutcome,
)

__all__ = [
    "HERMES_ROLE_ALLOWLIST",
    "HERMES_SCHEMA_COLUMNS",
    "HERMES_SCHEMA_TABLES",
    "HERMES_SCHEMA_VERSION",
    "SOURCE_HERMES",
    "HermesAccessCode",
    "HermesGateCode",
    "HermesSessionOutcome",
    "HermesSessionPlan",
    "plan_hermes_session",
    "run_hermes_session",
]

SOURCE_HERMES = "hermes"

#: Hermes 侧权威 schema 版本（`hermes_state_common.py:289` `SCHEMA_VERSION = 32`）。
#: 本适配器只做**下界**判断：低于它说明列集合可能还没有本模块声明的最小列，判
#: `schema_too_old`；高于它说明 Hermes 自己也可能加过列（见下），本模块不猜新列语义，
#: 但仍只 SELECT 已逐字验证过的列，因此高版本可按「未知列存在」诚实降级而不是整库不可读。
#: 为什么不能拿版本号当列形状的硬判据——`hermes_state_common.py:286-289` 逐字：
#: "its catch-up is the declarative executescript(SCHEMA_SQL) + _reconcile_columns() every
#: writable open already runs (additive, idempotent). The bump only records that the declared
#: shape changed; a new table or column needs no bump." 即：**加列不升版本号**，所以真实库
#: 完全可能在 version=32 上带有多出的列。判据因此以列集合为准，版本号只当下界护栏。
HERMES_SCHEMA_VERSION = 32

#: 可解释的下界：**本模块自己设定的范围选择**，不对应 Hermes 源码里的任何兼容区间
#: （`hermes_cli/session_recovery.py` 里没有版本下界常量；它对**新建恢复库**要求
#: `version == SCHEMA_VERSION`，见 :820-823，那是「新鲜副本必须是当前版」的断言，不是旧库兼容承诺）。
#: 之所以取 25：本增量只在源码里逐字核对到当前声明形状（`hermes_state_schema.py:1102` 是低于当前版的
#: 最高一个数据迁移门，v25 之后本模块未再核对旧形状），低于它就声明「不认识」而不是猜。
#: 注意 Hermes 可写打开会 `_reconcile_columns()` 补齐缺列（`hermes_state_schema.py:772-778`），
#: 只读打开则跳过补齐（:170-172 注释），所以老库确实可能缺我们要求的列——这由列集合判据兜住，
#: 不由版本号兜住。高于 32 的库允许读取，但多出未声明的列一律计入 `unknown_columns`
#: 并使覆盖不完整（本模块不理解那些列，不冒充理解）。
HERMES_SCHEMA_MIN_VERSION = 25

#: 本增量声明所需的最小列集合：取自 `hermes_state_common.py:451` `SCHEMA_SQL` 的逐字面定义。
#: 判据是**包含关系**（required ⊆ 实际列）：缺列即无法核对，多列不阻断只 SELECT 声明列的读取，
#: 但必须计入 `unknown_columns`（不猜新列语义）。
#: 集合只包含**本模块真正 SELECT 的列**（外加身份列 `id`/`session_id`）：不用的列不要求存在，
#: 否则 `HERMES_SCHEMA_MIN_VERSION` 下界（25）附近缺 `message_uid`/`compacted` 的库会被误判不可读。
HERMES_SCHEMA_TABLES: tuple[str, ...] = ("schema_version", "sessions", "messages")

HERMES_SCHEMA_COLUMNS: dict[str, frozenset[str]] = {
    "schema_version": frozenset({"version"}),
    "sessions": frozenset(
        {
            "id",
            "source",
            "started_at",
            "ended_at",
            "end_reason",
            "cwd",
            "git_repo_root",
            "profile_name",
            "archived",
            "hidden",
            "title",
            "message_count",
        }
    ),
    "messages": frozenset(
        {
            "id",
            "session_id",
            "role",
            "content",
            "tool_call_id",
            "tool_name",
            "timestamp",
            "active",
        }
    ),
}

#: 行内角色白名单。Hermes 没有闭合的角色枚举：`hermes_state_messages.py` 的逐行分支里出现过
#: 'user'/'assistant'/'tool'（`role == "user"` :320/:1083/:1609、`role == "assistant"` :311/:371、
#: `role == "tool"` :322/:1612），另有被称作「transcript bookkeeping」的
#: 'session_meta'/'system'（:610-615 的 `role NOT IN ('session_meta', 'system')`、:1655-1659 的
#: `r["role"] != "session_meta"`），`schema_read_probe_statements`（`hermes_state_schema.py:169-183`）
#: 对 role 也无枚举约束。因此本白名单是**本模块的产出选择**，不是对来源的承诺：只有可解释为
#: 「消息正文」的 user/assistant 产出候选；`tool` 行计入 `role_skipped`（有意的来源侧降级，
#: 不使覆盖不完整）；`session_meta`/`system` 及任何其它取值计入 `role_unusable` 并使覆盖不完整
#: —— 本模块没有逐字核对过这些行的正文语义，不冒充「已知但不认识」，也不替来源解释它们。
#: `display_kind` 是真实列（`hermes_state_common.py:531` 建表块内；写入面
#: `hermes_state_messages.py:36`/`:401`，读取面 :365-366），但本增量未逐字核对它的取值集合，
#: 也不 SELECT 它，因此**不**对「按 display_kind 跳过某些行」作任何声明。
HERMES_ROLE_ALLOWLIST: frozenset[str] = frozenset({"user", "assistant"})


#: `'tool'` 是 Hermes 行角色中被本模块有意跳过的一类（工具结果不是消息正文）。
#: 两条带角色谓词的白名单语句里，本常量与 user/assistant 白名单**都只走占位符绑定**
#: （绑定顺序 `_ROLES_BOUND_ORDER`），SQL 文本里没有任何由数据侧拼出的片段，也没有
#: `'tool'` 字面量残留 —— 该形状由 `whitelist_shape_problems()` 按 `_ROLE_PREDICATE_SHAPE`
#: 核对（白名单或语句被改动而未同步时当场发现）。
TOOL_ROLE = "tool"

# 带角色谓词的两条语句里，角色白名单在 SQL 文本中只以字面占位符对（`?, ?`）出现，
# 因此 `占位符对个数 × 2 == len(_ROLES_BOUND_ORDER)`。这条不变量由
# `whitelist_shape_problems()` 核对；执行期另有 `_execute` 的整条语句形状护栏
# （`?` 总数必须等于绑定个数），不相等即抛错、绝不执行 —— 改白名单忘了改绑定序列会
# 当场失败，不会默默漏行或多绑参数。
_ROLES_BOUND_ORDER: tuple[str, ...] = tuple(sorted(HERMES_ROLE_ALLOWLIST))

#: 单会话取数的硬上限。预算推导（与暂存层逐字账目一致，见 `session_stage.py:790`：
#: 每条记录扣 `PER_RECORD_FIXED_OVERHEAD_BYTES` + 正文 utf-8 字节）：
#: 默认暂存预算 `MAX_STAGE_BYTES_PER_SESSION` = 262,144 B，每条固定开销 12,288 B ⇒
#: **任何行数上限都必须 ≤ 预算 // 12,288 = 21**，否则 22 条空正文也会整批丢弃。
#: 因此取 `MAX_ROWS_PER_SESSION = 21`，并同时受 `_clamp_limits` 按实际 `max_bytes` 再收。
#: 正文总字符预算按「utf-8 每字符至多 4 字节」的最坏形状折算：
#: 262,144 − 21 × 12,288 = 4,736 B ⇒ 1,184 字符；这是**默认预算下必然超限**的窗口。
#: 本模块因此声明 `DEFAULT_STAGE_BYTES`（384 KiB = 393,216 B，仍低于暂存层硬上限
#: 2 MiB）作为「默认参数下能完整读完一个有界小会话」的配套预算，并把 SQL 端正文总量
#: 判限抬到与之精确折算一致的 32,768 字符（超限即在 SQL 端判停，一条正文都不取进
#: 内存）。默认值组合是有意的：只读适配器的第一版优先保证「判限发生在取正文之前」，
#: 而不是优先保证大窗口能读完。
#: 正文总字符默认上限 = 折算后的精确余量（393,216 B − 21 × 12,288 B = 131,072 B ⇒
#: ÷ 4 = 32,768 字符）。`_clamp_limits` 会在调用方改小预算时同步收紧它，
#: 所以「SQL 端判限通过但取到一半才触限」这种中途丢弃在默认参数下不会发生。
MAX_ROW_TEXT_TOTAL_CHARS = 32_768
#: 单会话取数的行数上限（见下方预算推导；= 默认暂存预算 // 每条固定开销）。
MAX_ROWS_PER_SESSION = 21
#: SQL 端长度判据用的单条正文上限：`MAX_TEXT_BLOCK_CHARS` 量级（与 pi 单块上限同阶），
#: 超过即按不可用计数（不截断保留）。
MAX_ROW_TEXT_CHARS = 32_768
#: 默认暂存字节预算（> 固定开销 × 行数上限 + 正文预算的最坏形状折算）。
DEFAULT_STAGE_BYTES = 384 * 1024
#: 归属上限必须与暂存层的可比对键上限同值（`session_stage._comparable_key` 以
#: `MAX_SESSION_KEY_CHARS` 为界，超限即 `PROJECT_UNATTRIBUTED` 整批丢弃）：
#: 本模块先把超限值降为 null 并计数，丢弃原因因此落在计数里而不是落在意外上。
MAX_ID_CHARS = MAX_SESSION_KEY_CHARS
MAX_PROJECT_CHARS = MAX_SESSION_KEY_CHARS
MAX_TOOL_NAME_CHARS = 256
#: 可解释的纪元秒区间：与 Hermes 自己的 `hermes_cli/timefmt.py:18-19` EPOCH_MIN/MAX 同值，
#: 但下界抬到本包 `models._EPOCH_MIN_SECONDS`（1e9），因为低于它的值本包判 INVALID 是刻意的
#: （单位无法可靠确定，不回填 1970 年附近冒充事件时间）。区间外的行计 `timestamp_unusable`。
USABLE_EPOCH_MIN = 1_000_000_000.0
USABLE_EPOCH_MAX = 4_200_000_000.0
#: 有界等待：只读连接遇到写锁时由 sqlite 自行等待的上限（毫秒）。Hermes 自己的只读
#: 读预算是 `_READ_BUSY_TIMEOUT_S = 5.0`（`hermes_state.py:197`，作为连接 timeout 传入并在
#: :739/:884 的只读打开处使用；锁不在应用层重试，见 :758 注释），本适配器的上限
#: `_BUSY_TIMEOUT_MAX_MS = 5000` 与之同值；默认取更保守的 1000ms，超时即按 `locked` 报告，
#: 不重试、不排队、不启后台任务。
DEFAULT_BUSY_TIMEOUT_MS = 1_000
_BUSY_TIMEOUT_MIN_MS = 100
_BUSY_TIMEOUT_MAX_MS = 5_000
#: 游标取数的批大小：行以元组形式逐批进入本模块（正文已在 SQL 端按长度判限），
#: 批大小只影响调用次数，不影响峰值（峰值由 `MAX_ROWS_PER_SESSION` 与长度判限共同约束）。
_FETCH_BATCH_ROWS = 8

#: sqlite3 **主结果码**（`sqlite3.h`，自 3.0 起稳定：ERROR=1 / BUSY=5 / LOCKED=6 /
#: READONLY=8 / CORRUPT=11 / CANTOPEN=14 / NOTADB=26）。Python 的 `sqlite3` 模块**没有**把这些常量
#: 导出成模块属性（`getattr(sqlite3, 'SQLITE_BUSY', None)` 取到的是 `None`），所以只能在本
#: 模块内声明；`exc.sqlite_errorcode` 给的是**扩展结果码**，`& 0xFF` 才回到主码。
#: 合成测试里用真实写锁/损坏文件场景验证这些取值，而不是信任注释（tests/test_hermes_source.py）。
_SQLITE_ERROR = 0x01
_SQLITE_BUSY = 0x05
_SQLITE_LOCKED = 0x06
_SQLITE_READONLY = 0x08
_SQLITE_CORRUPT = 0x0B
_SQLITE_CANTOPEN = 0x0E
_SQLITE_NOTADB = 0x1A

_REDACTED_STREAM_LABEL = "redacted-stream"
_DB_NAME_MAX_CHARS = 64
_DB_NAME_ALLOWED = re.compile(r"[A-Za-z0-9._-]+")

#: 白名单 SQL：键是本模块自有固定操作名，值是逐字面只读语句。
#: **不接受任何由数据侧拼出的 SQL 文本**；参数一律走 sqlite3 占位符绑定。
#: 所有语句都用裸表名（不用 `ro.` / `main.` schema 前缀）：Hermes 的只读助手
#: （`hermes_state_holders.py:27` `read_only_db_uri`）不做 ATTACH，裸名与本包测试所用的连接形状一致。
#: `PRAGMA query_only` 与 `PRAGMA integrity_check` 是仅有的两条非 SELECT 语句，
#: 前者是防御性只读声明（mode=ro 已禁止写），后者是只读的完整性探测。
class _Op(StrEnum):
    QUERY_ONLY = "query_only"
    BEGIN_READ = "begin_read"
    END_READ = "end_read"
    INTEGRITY = "integrity"
    SCHEMA_MARKER_COUNT = "schema_marker_count"
    SCHEMA_MARKER = "schema_marker"
    TABLE_COUNT = "table_count"
    TABLE_COLUMNS = "table_columns"
    SESSION_FACTS = "session_facts"
    MESSAGE_STATS = "message_stats"
    MESSAGE_ROWS = "message_rows"
    SESSION_ROW_COUNT = "session_row_count"
    INACTIVE_COUNT = "inactive_count"
    ACTIVE_UNRECOGNIZED = "active_unrecognized"


_QUERIES: dict[_Op, str] = {
    _Op.QUERY_ONLY: "PRAGMA query_only = ON",
    # 两条事务控制语句：`BEGIN` 建立本次读取的快照，`ROLLBACK` 在收尾时归还读锁（只读事务
    # 没有可提交的内容，`ROLLBACK` 是唯一不写盘的结束方式；`COMMIT` 在只读事务上同样是
    # 「不写盘」，但本模块不用它，避免任何语句看起来像在结束一次可提交的事务）。
    # 形状由 `_TRANSACTION_STATEMENTS` 逐字核对；两者都在 `PRAGMA query_only = ON` 之后执行，
    # 该 PRAGMA 对同一连接持续生效，因此即使事务被外部提前结束，写语句也仍然会被拒绝。
    _Op.BEGIN_READ: "BEGIN",
    _Op.END_READ: "ROLLBACK",
    _Op.INTEGRITY: "PRAGMA integrity_check",
    # 取值形状与 Hermes 自己的读法同形：`SELECT version FROM schema_version LIMIT 1` 后
    # `int()` 或无结论（`hermes_cli/session_recovery.py:820-821`、`hermes_state_schema.py:1006`）。
    # 多出的「先数行」是本模块自加的确定性判据：Hermes 两处都不数行，而 >1 行时版本标记
    # 本身就是无结论形状（不知道哪一版），因此判 unknown schema 而不是任选一行（SCHEMA_MARKER_COUNT）。
    _Op.SCHEMA_MARKER_COUNT: "SELECT COUNT(*) FROM schema_version",
    _Op.SCHEMA_MARKER: "SELECT version FROM schema_version LIMIT 1",
    _Op.TABLE_COUNT: "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
    _Op.TABLE_COLUMNS: "SELECT name FROM pragma_table_info(?)",
    _Op.SESSION_FACTS: (
        "SELECT source, started_at, ended_at, end_reason, cwd, git_repo_root,"
        " profile_name, archived, hidden, title, message_count"
        " FROM sessions WHERE id = ?"
    ),
    # 统计谓词与 MESSAGE_ROWS 的取数谓词**同基准**（`session_id + active = 1 + 角色白名单`）：
    # 唯一的文本差异是候选判定多带了 `typeof(role) = 'text'` 守卫。它不改变行集 —— SQLite 里
    # BLOB/INTEGER/NULL 与文本 `'user'`/`'assistant'` 走 `IN` 也永不判等，两种写法对同一行给出
    # 相同结果；守卫只是让「候选」这一列的语义在 SQL 里自明。候选判定放在子查询里**只写一次**，
    # 其余列在同一行集上聚合，账目才能对上全表。
    #   c1 候选行数（与取数行数同基准）  c2 候选行可用正文总字符数
    #   c3 时间戳不可用（候选行内）        c4 身份不可用（候选行内）
    #   c5 正文非文本（候选行内）          c6 空正文（候选行内）
    #   c7 正文超长（候选行内）            c8 tool 行数（活跃行集内，含非候选？）——见下
    #   c9 非候选且非 tool 的行数（活跃行集内） c10 活跃行总数（= c1 + c8 + c9）
    # 绑定顺序（按 SQL 文本位置）：c2 正文上限；c3 两个纪元边界；c4 身份长度上限与查询值；
    # c7 正文上限；c8 的 tool；c9 的 tool + tool；内层角色白名单；内层 session_id；外层
    # session_id。共 13 个参数；改 SQL 必须同步改 `_stats_params`（`_execute` 逐条核对个数）。
    # 角色列表只以**字面占位符**出现在 SQL 里（无任何数据侧拼接）。
    _Op.MESSAGE_STATS: (
        "SELECT"
        " COALESCE(SUM(candidate), 0),"
        " COALESCE(SUM(CASE WHEN candidate = 1"
        "                    AND typeof(content) = 'text'"
        "                    AND LENGTH(content) BETWEEN 1 AND ?"
        "               THEN LENGTH(content) ELSE 0 END), 0),"
        " COALESCE(SUM(CASE WHEN candidate = 1"
        "                    AND (typeof(timestamp) NOT IN ('real', 'integer')"
        # SQLite 的 `<>` 对 NaN 恒为假，因此自比较只能识别真值；非有限值交给逐行复核。
        "                         OR CAST(timestamp AS REAL) <> CAST(timestamp AS REAL)"
        "                         OR CAST(timestamp AS REAL) NOT BETWEEN ? AND ?)"
        "               THEN 1 ELSE 0 END), 0),"
        " COALESCE(SUM(CASE WHEN candidate = 1"
        "                    AND (typeof(session_id) <> 'text'"
        # `LENGTH(NULL)` 为 NULL ⇒ CASE 走 ELSE，漏计 NULL 身份列，因此显式判空类型。
        "                         OR typeof(session_id) IS NULL"
        "                         OR LENGTH(session_id) > ?"
        "                         OR session_id <> ?)"
        "               THEN 1 ELSE 0 END), 0),"
        " COALESCE(SUM(CASE WHEN candidate = 1"
        "                    AND typeof(content) <> 'text'"
        "               THEN 1 ELSE 0 END), 0),"
        " COALESCE(SUM(CASE WHEN candidate = 1"
        "                    AND typeof(content) = 'text' AND LENGTH(content) = 0"
        "               THEN 1 ELSE 0 END), 0),"
        " COALESCE(SUM(CASE WHEN candidate = 1"
        "                    AND typeof(content) = 'text' AND LENGTH(content) > ?"
        "               THEN 1 ELSE 0 END), 0),"
        # c8：字面 tool 行（值绑定，不内联字面量）；在活跃行集上统计。
        " COALESCE(SUM(CASE WHEN role = ? THEN 1 ELSE 0 END), 0),"
        # c9：非候选且非字面 tool。`IS NOT` 对 NULL 也成立，所以 NULL 角色不会从账目里
        # 消失；`role = ?` 对 NULL 恒为假，因此 NULL 行必然计入本列。
        " COALESCE(SUM(CASE WHEN candidate = 0"
        "                    AND (role IS NOT ? OR role <> ?)"
        "               THEN 1 ELSE 0 END), 0),"
        # c10：活跃行总数（外层谓词与内层同形 ⇒ 账目可对：c1 + c8 + c9 = c10）。
        " COUNT(*)"
        # 内层只列出外层真正引用的列（含 candidate 的依赖列）：`SELECT *` 会让真实列遮蔽
        # 计算别名 `candidate`，聚合读到的就是数据而不是候选标记。
        " FROM (SELECT session_id, role, content, timestamp, active,"
        "                (typeof(role) = 'text' AND role IN (?, ?))"
        "       AS candidate FROM messages WHERE session_id = ? AND active = 1)"
        " WHERE session_id = ? AND active = 1"
    ),
    # 不活跃行（Hermes 的存活标记 `active = 0`）单独计数：本模块不取、不解释，只如实计数。
    # `active` 既非 1 亦非 0 的形态不属已知两种，另由 `_Op.ACTIVE_UNRECOGNIZED` 计数，
    # 否则这部分行会从账目里消失（诚实覆盖要求每一行都有归属）。
    _Op.INACTIVE_COUNT: (
        "SELECT COALESCE(COUNT(*), 0) FROM messages"
        " WHERE session_id = ? AND active = 0"
    ),
    _Op.ACTIVE_UNRECOGNIZED: (
        "SELECT COALESCE(COUNT(*), 0) FROM messages"
        " WHERE session_id = ? AND active IS NOT 1 AND active IS NOT 0"
    ),
    # LIMIT 取 max_rows+1：同一快照下取数行数本应等于统计行数，多出来的这一行因此是
    # 「统计与取数的判据不一致」的直接证据（而不是并发漂移），并保证工作量仍由上限封顶。
    # 谓词与 MESSAGE_STATS 的内层同基准（见该处注释对 `typeof` 守卫的说明）；`active = 1` 只取存活行。
    # **正文边界发生在投影处，不在 Python 里**：子查询先按与 MESSAGE_STATS c2/c7 同一组判据
    # 折出 `kind`（`'ok'` = 文本且长度 ∈ [1, MAX_ROW_TEXT_CHARS]；否则为来源原形态
    # `text`→'empty' / `integer`/`real`/`blob`/`null` = typeof 原值，外加 `'overlong'`），
    # 外层只在 `kind = 'ok'` 时把正文原样透出——合法正文逐字返回（不截断、不裁剪、不拿片段
    # 冒充完整），非法与超长行的正文列由 SQLite 投影为 NULL，**完整载荷从不进入 Python**
    # （这不是「先 fetch 再截断」）；分类与计数仍按原始形态/超长落在既有三个桶里。
    # ORDER BY/LIMIT 在子查询内封顶取数工作量，外层再按 id 定序（≤ max_rows+1 行，代价有界），
    # 顺序不依赖 SQLite 对派生表物化顺序的实现细节。
    _Op.MESSAGE_ROWS: (
        "SELECT id, session_id, role,"
        "       CASE WHEN kind = 'ok' THEN content ELSE NULL END,"
        "       tool_call_id, tool_name, timestamp, kind"
        " FROM (SELECT id, session_id, role, content, tool_call_id, tool_name, timestamp,"
        "              CASE WHEN typeof(content) <> 'text' THEN typeof(content)"
        "                   WHEN LENGTH(content) = 0 THEN 'empty'"
        "                   WHEN LENGTH(content) > ? THEN 'overlong'"
        "                   ELSE 'ok' END AS kind"
        "       FROM messages WHERE session_id = ? AND active = 1 AND role IN (?, ?)"
        "       ORDER BY id LIMIT ?)"
        " ORDER BY id"
    ),
    # 全表行数（不分 active/角色）：账目闭合的分母。`活跃行数 + inactive + 未识别形态`
    # 必须等于它；四条计数语句现在跑在同一只读快照上，所以不等只能说明来源形状与本模块
    # 声明的判据不符（或快照不成立），而不是「中间有人写了」。本模块据此拒绝核对不完整流。
    _Op.SESSION_ROW_COUNT: (
        "SELECT COALESCE(COUNT(*), 0) FROM messages WHERE session_id = ?"
    ),
}


#: 每条白名单语句**声明应受**的绑定个数。与 `_QUERIES` 里 `?` 的实际个数是否一致，由
#: `whitelist_shape_problems()` 核对（改语句或改这张表都会当场对上）；执行期另有
#: `_execute` 的实参个数护栏。两者都不依赖任何 sqlite 内部常量或版本行为。
_QUERY_ARITY: dict[_Op, int] = {
    _Op.QUERY_ONLY: 0,
    _Op.BEGIN_READ: 0,
    _Op.END_READ: 0,
    _Op.INTEGRITY: 0,
    _Op.SCHEMA_MARKER_COUNT: 0,
    _Op.SCHEMA_MARKER: 0,
    _Op.TABLE_COUNT: 1,
    _Op.TABLE_COLUMNS: 1,
    _Op.SESSION_FACTS: 1,
    _Op.MESSAGE_STATS: 13,
    _Op.MESSAGE_ROWS: 5,
    _Op.SESSION_ROW_COUNT: 1,
    _Op.INACTIVE_COUNT: 1,
    _Op.ACTIVE_UNRECOGNIZED: 1,
}

#: 带**角色**谓词的两条语句的形状：`(角色白名单占位符对个数, 工具角色字面量个数)`。
#: 两条语句都只有一个 `role IN (?, ?)`（= 1 对），工具角色也只以绑定值出现（= 0 处字面量）。
#: 白名单大小变化而未同步 SQL、或有人把绑定改回内联字面量，`whitelist_shape_problems()`
#: 都会报形状问题。
_ROLE_PREDICATE_SHAPE: dict[_Op, tuple[int, int]] = {
    _Op.MESSAGE_STATS: (1, 0),
    _Op.MESSAGE_ROWS: (1, 0),
}

#: 角色白名单在 SQL 文本里唯一可能的出现形式（字面占位符对，不含任何数据侧文本）。
_ROLE_BIND_PAIR = "?, ?"
#: 写操作关键字（按整词核对，作为 SELECT 文本的额外只读形状断言）。
_WRITE_KEYWORDS = ("insert", "update", "delete", "attach", "detach", "drop", "alter")

#: 允许的非 SELECT/PRAGMA 语句：**只有**这两条事务控制语句，且必须逐字相等。
#: 白名单里出现第三类语句即形状问题（`whitelist_shape_problems()` 当场报）；把 `BEGIN` 改成
#: `BEGIN IMMEDIATE`/`BEGIN EXCLUSIVE` 同样是问题——那是要写锁的意图，本模块只读，
#: 只需 `BEGIN` 让第一条读语句取到共享读锁并冻结快照。
_TRANSACTION_STATEMENTS: dict[_Op, str] = {
    _Op.BEGIN_READ: "BEGIN",
    _Op.END_READ: "ROLLBACK",
}


def whitelist_shape_problems() -> tuple[str, ...]:
    """白名单形状自检：返回问题列表（空即通过），供入口与合成测试断言。

    只读模块自己的常量，不碰任何数据库、不回显任何输入值。核对四件事：
    1. `_QUERIES` 与 `_QUERY_ARITY` 键集合一致，且每条语句的 `?` 个数等于声明个数；
    2. 每条语句只允许 `SELECT` 或 `PRAGMA` 形状（`_TRANSACTION_STATEMENTS` 里的两条逐字
       例外），且 `SELECT` 文本不含写操作关键字；
    3. 带角色谓词的语句里，角色白名单占位符对个数与声明一致，且工具角色字面量
       个数为声明值（当前应为 0：绑定值不出现在文本里）；
    4. `占位符对个数 × 2 == len(_ROLES_BOUND_ORDER)`，且绑定序列长度与白名单大小一致。
    """
    problems: list[str] = []
    if set(_QUERIES) != set(_QUERY_ARITY):
        problems.append("query/arity key sets differ")
    if set(_ROLE_PREDICATE_SHAPE) - set(_QUERIES):
        problems.append("role predicate table names unknown op")
    if len(_ROLES_BOUND_ORDER) != len(HERMES_ROLE_ALLOWLIST):
        problems.append("role bind order != allowlist size")
    for op, statement in _QUERIES.items():
        if type(statement) is not str:
            problems.append(f"{op}: statement is not a string")
            continue
        declared = _QUERY_ARITY.get(op)
        if declared is not None and statement.count("?") != declared:
            problems.append(f"{op}: placeholder count != declared arity")
        text = statement.lstrip()
        expected_tx = _TRANSACTION_STATEMENTS.get(op)
        if expected_tx is not None:
            # 事务控制语句按逐字常量核对：改一个字（含换成带写锁意图的变体）就是形状问题。
            if text != expected_tx:
                problems.append(f"{op}: transaction statement differs from declared literal")
            continue
        if not text.startswith(("SELECT", "PRAGMA")):
            problems.append(f"{op}: statement is not SELECT/PRAGMA shaped")
        if text.startswith("SELECT"):
            words = {tok.strip("()").lower() for tok in text.replace(",", " ").split()}
            if any(word in words for word in _WRITE_KEYWORDS):
                problems.append(f"{op}: SELECT text contains a write keyword")
    for op, (pairs, tool_literals) in _ROLE_PREDICATE_SHAPE.items():
        statement = _QUERIES.get(op)
        if not isinstance(statement, str):
            problems.append(f"{op}: role predicate statement missing")
            continue
        if statement.count(_ROLE_BIND_PAIR) != pairs:
            problems.append(f"{op}: role placeholder pair count != declared shape")
        if pairs * 2 != len(_ROLES_BOUND_ORDER):
            problems.append(f"{op}: role placeholder pairs != bind order length")
        if statement.count(f"'{TOOL_ROLE}'") != tool_literals:
            problems.append(f"{op}: tool literal count != declared shape")
    return tuple(problems)


class HermesAccessCode(StrEnum):
    """连接与 schema 层的固定结论（会外出，因此只含类别，不含 sqlite 消息/路径/值）。"""

    OK = "ok"
    UNAVAILABLE = "unavailable"  # 库不存在/无法按只读 URI 打开
    INVALID_ARGUMENT = "invalid_argument"  # 路径形状/参数不合法（本模块内已挡，不到 sqlite）
    INTERNAL_FAILURE = "internal_failure"  # 未预期的 sqlite 错误（含损坏之外的驱动错误）
    INTEGRITY_FAILED = "integrity_failed"  # integrity_check 未报 ok
    UNKNOWN_SCHEMA = "unknown_schema"  # 表/最小列集合不符，或 schema 读不出来
    BUSY = "locked"  # 写锁占用，超时有界等待后放弃
    CORRUPT = "corrupt"  # sqlite 报损坏类错误码
    SCHEMA_VERSION_UNSUPPORTED = "schema_version_unsupported"  # 版本低于可解释下界
    DELETED_DURING_READ = "deleted_during_read"  # 授权时存在、取数时不可打开（只读快照消失）
    SNAPSHOT_UNAVAILABLE = "snapshot_unavailable"  # 本次读取的只读快照建立不了或中途丢了


class HermesGateCode(StrEnum):
    """取数与产出层的固定结论：闭合集合，与 `StageDiscardReason` 不同层，互不顶替。"""

    OK = "ok"
    INVALID_ARGUMENT = "invalid_argument"  # 参数/路径形状在本模块内被挡（未到 sqlite）
    SESSION_NOT_FOUND = "session_not_found"
    MESSAGE_LIMIT_EXCEEDED = "message_limit_exceeded"  # SQL 端候选数判限，未取任何正文
    BYTE_LIMIT_EXCEEDED = "byte_limit_exceeded"  # SQL 端正文字符判限，未取任何正文
    MESSAGE_ROWS_UNBOUNDED = "message_rows_unbounded"  # 行数与统计不一致（快照内判据不合），不核对完整流
    MESSAGE_ROWS_SHORT = "message_rows_short"  # 取到的行数少于统计行数
    SOURCE_UNAVAILABLE = "source_unavailable"  # 来源侧不可读（锁/损坏/未知 schema/打不开/快照不成立）
    STAGE_REJECTED = (
        "stage_rejected"
        # 两个事务边界都用它，方向相同、快照不同：**核验前**暂存层自拒 → 整批丢弃、
        # `stage` 快照按不完整结算（计数归零、细分原因见 `stage.reason`）；**核验通过后的
        # 外递（`capture`）首拒** → 只翻外递终态，`stage` 快照仍是核验通过的那份（那批候选
        # 当时确实核验通过了），已核验条数作为分层诊断量保留，不代表还有正文可看。
    )
    STAGE_INCOMPLETE = "stage_incomplete"  # 核对未通过
    PARSE_INCOMPLETE = "parse_incomplete"  # 流读完了但有不可解释行（降级计数见 parse/withheld）
    CANCELLED = "cancelled"  # 调用方取消
    STORAGE_DENIED = "storage_denied"  # 策略层拒绝存储轴（本模块不解释拒绝原因）
    ATTRIBUTION_DENIED = "attribution_denied"  # 策略层拒绝归属轴（逐记录准入）
    ATTRIBUTION_UNMATCHED = (
        "attribution_unmatched"  # 已核对且确定不属于请求项目（零命中结论，非核对失败）
    )
    INTERNAL_FAILURE = "internal_failure"  # 逐行产出过程中的意外失败（不回显异常）


#: `HermesSessionPlan.unavailable_reasons` 与 `HermesSessionOutcome.withheld_reasons` 的
#: 计数键（SQL 端可解释性判据，全部是整数计数，不含原值）：
_WITHHELD_KEYS = {
    "identity_unusable": 0,  # session_id 非文本/超长/与查询值不符
    "timestamp_unusable": 0,  # 非 real / NaN / 区间外
    "content_empty": 0,  # 空正文或 NULL 正文（来源侧合法形态，不是消息正文）
    "content_shape": 0,  # 非文本形态（bytes/整数等）：本模块不认识，不猜
    "content_overlong": 0,  # 单条正文超过 MAX_ROW_TEXT_CHARS（不截断保留）
    "role_unusable": 0,  # 不认识的形态（非文本角色，或白名单外且非 tool）
    "role_skipped": 0,  # 已知来源侧跳过（tool 行不是消息正文，不使覆盖不完整）
    "row_id_unusable": 0,  # messages.id 非正整数或超出暂存层整数边界
    "project_unusable": 0,  # git_repo_root 与 cwd 都不可用
    "label_unusable": 0,  # 库名派生的 stream_label 不可信（已降为固定替身）
    "tool_name_unusable": 0,  # 工具名非文本/超长（降为 null）
    "facts_unusable": 0,  # sessions 行自身的列形态不可解释
    "source_hermes_mismatch": 0,  # sessions.source 不是 'hermes'（观测，不是过滤判据）
    "inactive_rows": 0,  # active = 0 的行（本模块不取、不解释，只计数）
    "active_unrecognized": 0,  # active 既非 1 亦非 0 的行（不猜含义，只计数）
    "unknown_columns": 0,  # schema 中本模块未声明的列数（不猜语义、绝不 SELECT）
    "trailing_rows": 0,  # 同快照下取数多于统计的行数（有界丢弃，不核对完整流）
    "account_mismatch": 0,  # 行数账目不闭合（同一快照内四条计数语句对不上）
    "admit_denied": 0,  # 归属轴逐记录准入被拒（不分细类，细类见下面四项）
    "attribution_denied": 0,  # 无可用归属证据 / 证据形态不合（ATTRIBUTION_UNKNOWN 取向）
    "attribution_unmatched": 0,  # 已核对且确定不在批准归属根内（零命中取向，非核对失败）
    "attribution_ambiguous": 0,  # 候选跨多个项目，不能单选一个（拒绝掩盖冲突）
    "project_mismatch": 0,  # 唯一归属项目与请求项目不符
}

#: 策略层归属轴的拒绝码 → 本模块的固定细类计数。映射是**显式列举**的：没列到的码
#: 不猜细类（只计入 `attribution_denied`），因为未知码的含义本模块并未核实。
_ATTRIBUTION_DENIAL_KEYS = {
    RefusalCode.ATTRIBUTION_UNKNOWN: "attribution_denied",
    RefusalCode.ATTRIBUTION_UNMATCHED: "attribution_unmatched",
    RefusalCode.ATTRIBUTION_AMBIGUOUS: "attribution_ambiguous",
    RefusalCode.PROJECT_MISMATCH: "project_mismatch",
}

#: 细类 → gate：「已核对且确定不属于请求项目」与「无法建立归属」是两个不同层的结论，
#: 不能共享一个 gate（前者可写成诚实的零命中覆盖，后者只能说未确认）。
#: 没有列进的码（含未知码）一律落回归属轴拒绝 gate：本模块不猜它们的含义，
#: 也不把它们冒充成零命中。
_ATTRIBUTION_UNMATCHED_GATES = {
    RefusalCode.ATTRIBUTION_UNMATCHED: HermesGateCode.ATTRIBUTION_UNMATCHED,
    RefusalCode.PROJECT_MISMATCH: HermesGateCode.ATTRIBUTION_UNMATCHED,
}

#: 「无归属证据」这个结论在来源侧就已得出（没有递交策略层），但细类与策略层的
#: `attribution_unknown` 同一含义，所以复用同一张映射表；这个键只带固定码
#: （消息取自策略层的固定文案），不调用策略层、不含任何输入值。
_ATTRIBUTION_UNKNOWN_DENIAL = PolicyDenied(RefusalCode.ATTRIBUTION_UNKNOWN)


@dataclass(frozen=True)
class HermesSessionPlan:
    """一次只读探测的结论：schema 是否可解释、会话是否存在、流是否有界。

    本模块**不提供任何返回正文的出口**（与 `session_stage` 同一取向）：正文只由
    `run_hermes_session` 交给暂存层，规划与暂存本身不发布；完整核验通过后，正文经
    `capture` 回调逐条外递（未核验终态一条也不递，见 `finish`）。
    """

    available: bool
    access: HermesAccessCode
    gate: HermesGateCode
    session_exists: bool
    #: 活跃行总数（SQL 端 `COUNT(*)`，含 tool 行与不认识形态的行）。
    row_count: int
    #: 候选行数（与取数语句谓词同形）——取数与账目核对的基准。
    candidate_count: int
    #: `active <> 1` 的行数（本模块不取、不解释）。
    inactive_count: int
    #: schema 中本模块未声明的列数（> 0 即不声明「完全理解该库」）。
    unknown_columns: int
    text_chars: int
    unusable_count: int
    #: 只读探测得到的计数型不可用原因（键取自 `_WITHHELD_KEYS`）。
    unavailable_reasons: dict[str, int]
    #: `PRAGMA integrity_check` 是否报 ok（None = 未探测到结论，保守按不可用）。
    integrity_ok: bool | None
    schema_version: int | None
    #: schema 结论的布尔化：表存在且**必需列子集**成立（多出的列计入 `unknown_columns`）。
    schema_known: bool

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "access": self.access.value,
            "gate": self.gate.value,
            "session_exists": self.session_exists,
            "row_count": self.row_count,
            "candidate_count": self.candidate_count,
            "inactive_count": self.inactive_count,
            "unknown_columns": self.unknown_columns,
            "text_chars": self.text_chars,
            "unusable_count": self.unusable_count,
            "unavailable_reasons": dict(self.unavailable_reasons),
            "integrity_ok": self.integrity_ok,
            "schema_version": self.schema_version,
            "schema_known": self.schema_known,
        }


@dataclass(frozen=True)
class HermesSessionOutcome:
    """一次单会话读取的最终结论：整数 + 本模块自有固定类别，绝不外出原值。"""

    complete: bool
    publication_allowed: bool  # 恒为 False：本增量无发布通道（发布由协调层决定）
    gate: HermesGateCode
    access: HermesAccessCode
    stage: StageOutcome | None
    records_emitted: int
    rows_read: int
    withheld_reasons: dict[str, int]
    parse: ParseStats
    plan: HermesSessionPlan

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "source": SOURCE_HERMES,
            "complete": self.complete,
            "publication_allowed": self.publication_allowed,
            "gate": self.gate.value,
            "access": self.access.value,
            "stage": self.stage.as_public_dict() if self.stage else None,
            "records_emitted": self.records_emitted,
            "rows_read": self.rows_read,
            "withheld_reasons": dict(self.withheld_reasons),
            "parse": self.parse.as_public_dict(),
            "plan": self.plan.as_public_dict(),
        }


class _Abort(Exception):
    """内部早停信号：只携带本模块自有类别。"""

    __slots__ = ("access", "gate")

    def __init__(self, gate: HermesGateCode, access: HermesAccessCode) -> None:
        super().__init__(gate.value)
        self.gate = gate
        self.access = access


def _empty_plan(access: HermesAccessCode, gate: HermesGateCode) -> HermesSessionPlan:
    return HermesSessionPlan(
        available=False,
        access=access,
        gate=gate,
        session_exists=False,
        row_count=0,
        candidate_count=0,
        inactive_count=0,
        unknown_columns=0,
        text_chars=0,
        unusable_count=0,
        unavailable_reasons=dict(_WITHHELD_KEYS),
        integrity_ok=None,
        schema_version=None,
        schema_known=False,
    )


def _gate_for_access(access: HermesAccessCode) -> HermesGateCode:
    """来源层结论到取数层结论的映射：本模块不复述 sqlite 原因，只区分「可读 / 来源不可读」。

    写锁占用、损坏、不可打开、未知 schema、版本不支持、只读快照建立不了或中途丢失
    都落在 `SOURCE_UNAVAILABLE`，
    具体类别由 `HermesSessionOutcome.access` 给出；`CANCELLED` 只表示**调用方**取消，
    不能拿来顶替来源侧失败（否则锁竞争会被读成「取消」）。
    """
    if access is HermesAccessCode.OK:
        return HermesGateCode.OK
    return HermesGateCode.SOURCE_UNAVAILABLE


def _classify_exception(exc: BaseException, path: str | None = None) -> HermesAccessCode:
    """把 sqlite 异常降为固定类别：只看错误码与异常类型，不回显消息（消息可能含路径/表名）。

    `SQLITE_ERROR`（miscellaneous）在本模块里只可能是探测语句本身报错——所有白名单语句都是
    常量文本、参数只走绑定，所以它的来源只有两种：表不存在（库形状问题）或本模块没预料到的
    用法错误。sqlite3 把这两者分属不同类型（`no such table` → `sqlite3.OperationalError`，
    其他 misc → `sqlite3.DatabaseError`），因此用类型分档，不拿消息文本当判据。锁类优先判，
    否则会和「来源不可用」混为一谈（写锁竞争不是取消，也不是库损坏）。

    `path` 仅用于把 `SQLITE_CANTOPEN` 分拆为「只读快照已消失」（授权时存在、现在不可打开）
    与其它不可用；这是一次**存在性观测**，不重新授权、不重新打开、消息仍不外传。
    """
    hresult = getattr(exc, "sqlite_errorcode", None)
    primary = None if hresult is None else hresult & 0xFF
    if primary in (_SQLITE_BUSY, _SQLITE_LOCKED):
        return HermesAccessCode.BUSY
    if isinstance(exc, sqlite3.OperationalError):
        if primary == _SQLITE_ERROR:
            # OperationalError + SQLITE_ERROR：sqlite3 用它承载「表/列不存在」一类运行时形状
            # 问题 ⇒ 未知 schema；本模块不因此声明任何完整覆盖。
            return HermesAccessCode.UNKNOWN_SCHEMA
        if primary in (_SQLITE_READONLY, _SQLITE_CANTOPEN):
            # `SQLITE_CANTOPEN` + 现在已不存在 = 授权时存在、取数时只读快照消失（一次存在性
            # 观测，不重新授权、不重新打开）；其余按不可用。
            if primary == _SQLITE_CANTOPEN and path is not None and not pathlib.Path(path).exists():
                return HermesAccessCode.DELETED_DURING_READ
            return HermesAccessCode.UNAVAILABLE
        return HermesAccessCode.INTERNAL_FAILURE
    if isinstance(exc, sqlite3.DatabaseError):
        if primary in (_SQLITE_CORRUPT, _SQLITE_NOTADB):
            return HermesAccessCode.CORRUPT
        return HermesAccessCode.INTERNAL_FAILURE
    if isinstance(exc, sqlite3.Error):
        return HermesAccessCode.INTERNAL_FAILURE
    raise exc


def _is_trusted_store(path: object) -> bool:
    """调用方给定的库路径是否可作为只读 URI 的目标（不做存在性/真实路径判定）。

    真正的授权由 `policy.authorize_store(scope, SOURCE_HERMES, path, kind=TargetKind.FILE)` 完成；
    本函数只挡住明显无法成为本地文件的取值（None、非字符串、空、含 NUL、控制字符），
    避免把不受控取值直接拼进 `file:` URI（`?`/`#` 会被 URI 截断，Hermes 助手已有同一坑）。
    """
    if not isinstance(path, str):
        return False
    if not path or len(path) > 4096:
        return False
    # `?`/`#` 会被 `file:` URI 解析为参数分隔/锚点（Hermes 助手已踩过同一坑），NUL/控制字符
    # 不可能是合法本地文件名。这里只把不可达 URI 的取值挡在前面，不构成授权判据。
    if "\x00" in path or "?" in path or "#" in path:
        return False
    return not any(ord(ch) < 32 for ch in path)


def _read_only_uri(path: str) -> str:
    """构造只读 URI：与 Hermes 自己的助手同形（`hermes_state_holders.py:27`）。

    Hermes 逐字：`Path(db_path).resolve().as_uri() + "?mode=ro"`。本模块不复用它的实现
    （引入 Hermes 包就不是只读适配器了），但采用同一形状：`as_uri()` 负责百分号转义，
    `?mode=ro` 只能拼在已转义的 URI 之后；路径中的 `?`/`#` 已由 `_is_trusted_store` 排除。
    `resolve()` 只服务于 URI 构造，**不充当授权判据**（授权在 `policy.authorize_store`）。
    """
    return pathlib.Path(path).resolve().as_uri() + "?mode=ro"


def _connect_read_only(uri: str, busy_timeout_ms: int) -> sqlite3.Connection:
    """只读连接的唯一进口：URI 必须是 `file:` 形态且带 `mode=ro`，否则不开。

    与 Hermes 的只读连接同形（`hermes_state.py:765 _connect_read_only`：`uri=True`、
    `check_same_thread=False`、有界 `timeout`、`isolation_level=None`）：本模块只读，
    因此不用驱动的隐式事务管理；本次读取的只读快照由 `open()` 显式 `BEGIN` 建立、
    `close()` 显式 `ROLLBACK` 释放（见 `_SessionRun.open`）。两道检查在**连接建立之前**：
    拿不到只读保证就不碰文件。
    `check_same_thread=False` 不是为了跨线程用连接（本模块单一所有者顺序驱动），而是
    与来源侧助手同形，避免本适配器在同一库上引入新的线程约束。
    """
    if not uri.startswith("file:") or not uri.endswith("?mode=ro"):
        raise sqlite3.ProgrammingError("hermes adapter requires a mode=ro file URI")
    conn = sqlite3.connect(
        uri,
        uri=True,
        timeout=busy_timeout_ms / 1000.0,
        isolation_level=None,
        check_same_thread=False,
    )
    conn.text_factory = str
    return conn


def _db_stream_label(path: str) -> tuple[str | None, bool]:
    """由库文件名派生短位置标签；不可信取值整体降为固定替身（不截断保留前缀）。

    返回 `(label, degraded)`。只取 basename（不含目录、不含盘符），且只接受
    ASCII 字母数字与 `._-`；其余一律 `redacted-stream`。
    """
    normalized = path.replace("\\", "/")
    name = normalized.rsplit("/", 1)[-1]
    if not name or len(name) > _DB_NAME_MAX_CHARS:
        return _REDACTED_STREAM_LABEL, True
    if not _DB_NAME_ALLOWED.fullmatch(name):
        return _REDACTED_STREAM_LABEL, True
    return name, False


def _execute(conn: sqlite3.Connection, op: _Op, params: tuple[object, ...] = ()) -> sqlite3.Cursor:
    """执行白名单语句：SQL 文本只能来自 `_QUERIES[op]`，参数只走绑定。

    语句文本只由**字典下标**（`_QUERIES[op]`）得出：不经拼接、不经格式化、不经数据侧；
    事务控制（`_Op.BEGIN_READ` / `_Op.END_READ`）也走同一条下标路径，同样是模块内逐字常量，
    不是调用方可传入的语句——调用方只能递进一个 `_Op` 枚举成员，永远递不进 SQL 文本；
    参数只走 sqlite 占位符绑定（`_bound_values` 逐项校形）。执行前三道检查都不依赖任何
    sqlite 内部常量（与驱动版本无关）：`op` 不在表里即 KeyError；取到的语句必须是 `str`；
    `?` 个数必须与绑定个数一致（文本里的 `?` 全是占位符，字面量中无 `?`）——不一致就是
    「改了 SQL 忘了改绑定」的形状错误，当场抛错、绝不执行，失败方向由调用方的内部失败路径承接。
    本包没有任何接受 SQL 文本的外部入口：调用方只能递进一个 `_Op` 枚举成员。静态安全规则仍会按
    形状（变量进 execute）在这一行失败关闭——它只认字面量与 SQLAlchemy/psycopg 的出处，证明不了
    字典白名单，因此这里用一行工具自带的行内豁免说明出处，而不是改设计去绕过它。
    """
    statement = _QUERIES[op]
    if type(statement) is not str:
        raise TypeError("hermes adapter whitelist entry is not a string")
    if statement.count("?") != len(params):
        raise TypeError("hermes adapter query/parameter arity mismatch")
    return conn.execute(statement, _bound_values(params))  # pi-lens-ignore: python-sql-injection


def _bound_values(params: tuple[object, ...]) -> tuple[object, ...]:
    """绑定参数只允许本模块能解释的形态（字符串/实数/整数/由标量组成的元组）。

    会话标识进入本模块前已由 `_validate_args` 定形，因此这里只校类型不校内容：不改写、
    不拿它拼 SQL（本包没有拼接出来的语句）。其余形态一律按形状错抛，不递给 sqlite。
    """
    for value in params:
        if isinstance(value, bool) or not isinstance(value, str | int | float | tuple):
            raise TypeError("hermes adapter binds only scalar or tuple parameters")
        if isinstance(value, tuple) and any(
            isinstance(item, bool) or not isinstance(item, str | int | float)
            for item in value
        ):
            raise TypeError("hermes adapter binds only scalar tuples")
    return params


def _read_int(cursor: sqlite3.Cursor) -> int | None:
    row = cursor.fetchone()
    if row is None:
        return None
    value = row[0]
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _probe_schema(
    conn: sqlite3.Connection,
) -> tuple[HermesAccessCode, int | None, bool, int]:
    """核对表存在性与必需列形状；返回 `(access, schema_version, schema_known, unknown_columns)`。

    版本标记的取值形状与 Hermes 自己的读法同形（`SELECT version ... LIMIT 1` 后 int 或无结论，
    `hermes_state_common.py:452` 建表 + `hermes_cli/session_recovery.py:820-821`、
    `hermes_state_schema.py:1006`）；`SCHEMA_MARKER_COUNT` 先数行是本模块自加的确定性判据
    （Hermes 不数行；>1 行即版本标记无结论），不是对 Hermes 行为的复刻。
    **不是 `PRAGMA user_version`**：那个整数在 Hermes 里只用于页头偏移解析
    （`hermes_state_dbfile.py:508`），不是 schema 标记。

    列判据是**子集**（required ⊆ 实际）而不是逐字相等：`hermes_state_common.py:286-289` 明确
    「加列不升版本号」，因此真实库可以在已知版本上带多出的列。多出的列一律计入
    `unknown_columns`（本模块不理解那些列，不猜语义，也绝不 SELECT 它们）。
    """
    try:
        marker_rows = _read_int(_execute(conn, _Op.SCHEMA_MARKER_COUNT))
    except sqlite3.Error as exc:
        return _classify_exception(exc), None, False, 0
    if marker_rows != 1:
        # 0 行 = 没有标记；多行 = 本模块无法判断哪一行是权威版本。
        return HermesAccessCode.UNKNOWN_SCHEMA, None, False, 0
    try:
        version = _read_int(_execute(conn, _Op.SCHEMA_MARKER))
    except sqlite3.Error as exc:
        return _classify_exception(exc), None, False, 0
    if version is None or version < 0:
        return HermesAccessCode.UNKNOWN_SCHEMA, None, False, 0
    if version < HERMES_SCHEMA_MIN_VERSION:
        # 低于可解释下界：最小列集合可能还不完整，不猜旧形状。
        return HermesAccessCode.SCHEMA_VERSION_UNSUPPORTED, version, False, 0
    unknown_columns = 0
    for table in HERMES_SCHEMA_TABLES:
        try:
            count = _read_int(_execute(conn, _Op.TABLE_COUNT, (table,)))
        except sqlite3.Error as exc:
            return _classify_exception(exc), version, False, unknown_columns
        if count != 1:
            return HermesAccessCode.UNKNOWN_SCHEMA, version, False, unknown_columns
    for table in HERMES_SCHEMA_TABLES:
        try:
            rows = _execute(conn, _Op.TABLE_COLUMNS, (table,)).fetchall()
        except sqlite3.Error as exc:
            return _classify_exception(exc), version, False, unknown_columns
        columns = frozenset(
            row[0] if isinstance(row[0], str) and row[0] == row[0].strip() else None
            for row in rows
        )
        if None in columns:
            # 有列名不可解释（非文本/带空白）：本模块无法声明「看到的都是认识的」。
            return HermesAccessCode.UNKNOWN_SCHEMA, version, False, unknown_columns
        required = HERMES_SCHEMA_COLUMNS[table]
        if not required.issubset(columns):
            return HermesAccessCode.UNKNOWN_SCHEMA, version, False, unknown_columns
        unknown_columns += len(columns - required)
    return HermesAccessCode.OK, version, True, unknown_columns


def _probe_integrity(conn: sqlite3.Connection) -> tuple[HermesAccessCode, bool | None]:
    """只读完整性探测：只看结论是否为 `ok`，不外传 sqlite 文本（文本可能含路径）。

    `integrity_check` 未报 ok 即按 `INTEGRITY_FAILED`（包括没有行、非字符串结论——本模块
    对这些取值不认识，不冒充「通过」）；`integrity_ok` 为 `None` 表示没有可用结论。
    """
    try:
        row = _execute(conn, _Op.INTEGRITY).fetchone()
    except sqlite3.Error as exc:
        return _classify_exception(exc), None
    if not row:
        return HermesAccessCode.INTEGRITY_FAILED, None
    verdict = row[0]
    if isinstance(verdict, str) and verdict.strip() == "ok":
        return HermesAccessCode.OK, True
    # 非字符串结论或别的结论：本模块不认识这些取值，不冒充「通过」。
    return HermesAccessCode.INTEGRITY_FAILED, None if not isinstance(verdict, str) else False


def _text_usable(value: object, limit: int) -> bool:
    return (
        isinstance(value, str)
        and value.__class__ is str
        and 0 < len(value) <= limit
        and value == value.strip()
    )


def _epoch_value(value: object) -> float | None:
    """把纪元秒降为可解释的 float，否则 None（bool/非实数/NaN/区间外都不认识）。

    不做 `float(str)` 式转换：只接受来源侧已经是实数/整数的取值（int 直接按 float 语义
    参与比较与返回），所以本函数不会抛，也就不需要拿异常当控制流。
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        number: float = value
    elif isinstance(value, int):
        number = value
    else:
        return None
    if not USABLE_EPOCH_MIN <= number < USABLE_EPOCH_MAX:
        return None
    return number


def _epoch_usable(value: object) -> bool:
    return _epoch_value(value) is not None


def _facts_from_row(row: tuple[Any, ...]) -> tuple[dict[str, Any], int]:
    """把 `sessions` 行折成本模块需要的少量事实，并返回不可用计数。

    任何一项取值不可解释都降为 `None` 并计数，不截断、不猜。
    """
    counts = 0
    facts: dict[str, Any] = {}
    source = row[0]
    if _text_usable(source, MAX_ID_CHARS) and source != "":
        facts["source"] = source
    else:
        facts["source"] = None
        counts += 1
    facts["started_at"] = _epoch_value(row[1])
    if row[1] is not None and facts["started_at"] is None:
        counts += 1
    facts["ended_at"] = _epoch_value(row[2])
    end_reason = row[3]
    facts["end_reason"] = end_reason if _text_usable(end_reason, MAX_ID_CHARS) else None
    cwd = row[4]
    facts["cwd"] = cwd if _text_usable(cwd, MAX_PROJECT_CHARS) else None
    if cwd is not None and facts["cwd"] is None:
        counts += 1
    repo_root = row[5]
    facts["git_repo_root"] = (
        repo_root if _text_usable(repo_root, MAX_PROJECT_CHARS) else None
    )
    if repo_root is not None and facts["git_repo_root"] is None:
        counts += 1
    profile = row[6]
    facts["profile_name"] = profile if _text_usable(profile, MAX_ID_CHARS) else None
    # archived / hidden 是来源侧的整数标记：只认识 0/1 之外的整数形态，不猜布尔。
    for name, value in (("archived", row[7]), ("hidden", row[8])):
        facts[name] = (
            value if isinstance(value, int) and not isinstance(value, bool) else None
        )
        if facts[name] is None and value is not None:
            counts += 1
    title = row[9]
    facts["title"] = title if _text_usable(title, MAX_PROJECT_CHARS) else None
    if title is not None and facts["title"] is None:
        counts += 1
    return facts, counts


def _project_from_facts(facts: dict[str, Any]) -> tuple[str | None, int]:
    """归属值：`git_repo_root` 优先，缺失退 `cwd`（与 Hermes 会话分组键同形）。

    这是**来源内结构证据**（sessions 行先于任何消息行读到，来自已授权 mode=ro 存储上的
    白名单 SELECT），所以质量记 `TRUSTED_HEADER_CWD`——与 `sources/pi.py` 采信文件头 cwd
    同一取向（pi.py:613-653 `_adopt_header_project`）。暂存层只从 `TRUSTED_HEADER_CWD` 建立
    会话级归属（session_stage.py:784-787 + `_project_attributed()`），记成 CALLER_ASSERTED
    将永远无法完成。存储授权与项目归属仍是两条**独立**轴：本质量不授权读盘，授权读盘也不
    等于归属成立。两者都不可用时返回 None 并计数。
    """
    for key in ("git_repo_root", "cwd"):
        value = facts.get(key)
        if isinstance(value, str) and value:
            return value, 0
    return None, 1


def _classify_row(
    row: tuple[Any, ...],
    *,
    session_id: str,
    label: str | None,
    project: str | None,
) -> tuple[StandardRecord | None, str | None, bool, bool]:
    """把一行 messages 变成 `StandardRecord`，返回 `(record, rejection, label_degraded, tool_degraded)`。

    `rejection` 是 `_REJECTION_KEY` 里的固定类别（None = 可用）。不可用的行**不产出**，只计数：
    身份不一致的行必须拒发，因为暂存层会把它判成冲突并整批作废，与其到核对点才发现，不如
    在产出时就按固定类别计数（两种做法结果都是整批不完整，后者的计数更可解释）。
    逐行判据必须与统计 SQL 的判据**同形**，否则账目对不上（对不上即 `message_rows_unbounded`）。

    超长/非法正文的**载荷边界在取数语句的投影处**（见 `_QUERIES[_Op.MESSAGE_ROWS]` 注释）：
    这类行到达本函数时正文列已是 NULL，判据来自同一条语句折出的 `kind`，因此不存在
    「先把完整载荷取进 Python 再拒」。合法（`kind='ok'`）的正文是完整原值，本函数不截断；
    长度上限仍逐列复核一次，是为了在 kind 缺失（替身游标）时保持同一判据，不是二次裁剪。
    """
    row_id, row_session, role, content, tool_call_id, tool_name, timestamp = row[:7]
    #: 第 8 列是 `MESSAGE_ROWS` 在 SQLite 投影端折出的 `kind`：`'ok'` 之外，正文已按原始形态
    #: /超长判停且从未进入 Python。无该列的旧形状（测试替身游标）为 None，走下方逐列复核。
    kind = row[7] if len(row) > 7 else None
    # 身份：行内 session_id 必须与查询值逐字相等且形态可用（取数谓词已过滤，此处再核一道）。
    if not _text_usable(row_session, MAX_ID_CHARS) or row_session != session_id:
        return None, "identity", False, False
    # 角色白名单（白名单外的文本角色在 SQL 端已计入 `role_unusable`，不会到这里）。
    if not _text_usable(role, MAX_ID_CHARS) or role not in HERMES_ROLE_ALLOWLIST:
        return None, "role", False, False
    # 正文：SQL 端 kind 已判定的行按**同一组固定桶**计数（原始形态与超长不混账），
    # 不在此处重取载荷；kind 缺失（替身游标）时才逐列复核。
    if isinstance(kind, str) and kind != "ok":
        if kind in ("empty", "null"):
            return None, "content_empty", False, False
        if kind == "overlong":
            return None, "content_overlong", False, False
        # 'blob' / 'integer' / 'real' 等 typeof 原值，以及任何本模块不认识的取值：
        # 形状不可解释，不猜。
        return None, "content_shape", False, False
    # 以下只对未被 SQL 端判停的行生效——合法正文到此已是完整载荷，绝不裁剪冒充。
    if content is None or (isinstance(content, str) and content == ""):
        return None, "content_empty", False, False
    if isinstance(content, bytes):
        return None, "content_shape", False, False
    if not isinstance(content, str):
        return None, "content_shape", False, False
    if len(content) > MAX_ROW_TEXT_CHARS:
        return None, "content_overlong", False, False
    # 时间：只接受可解释的纪元秒；区间外/NaN/非实数即整行不产出并计数。
    number = _epoch_value(timestamp)
    if number is None:
        return None, "timestamp", False, False
    stamp, quality = normalize_timestamp(number)
    if stamp is None or quality is not TimeQuality.EXACT:
        # 与统计谓词不一致的取值（本模块不认识这种形态）：不猜、不产出。
        return None, "timestamp", False, False
    line_no = _row_index(row_id)
    if line_no is None:
        return None, "row_id", False, False
    location = SourceLocation(stream_label=label, line_no=line_no, ordinal=0)
    label_degraded = location.stream_label != label
    executor = tool_name if _text_usable(tool_name, MAX_TOOL_NAME_CHARS) else None
    tool_degraded = tool_name is not None and executor is None
    # `tool_call_id` 只作观测：本增量不取它作为正文或身份的一部分。
    del tool_call_id
    return (
        StandardRecord(
            source=SOURCE_HERMES,
            session_id=session_id,
            location=location,
            text=content,
            role=role,
            executor=executor,
            timestamp=stamp,
            time_quality=quality,
            project=project,
            project_quality=(
                ProjectQuality.TRUSTED_HEADER_CWD
                if project is not None
                else ProjectQuality.UNKNOWN
            ),
            issues=(),
        ),
        None,
        label_degraded,
        tool_degraded,
    )


def _row_index(row_id: object) -> int | None:
    """行号语义：`messages.id`（INTEGER 主键，Hermes 自己的顺序读取就是 `ORDER BY id`）。

    上限与暂存层的整数边界兼容：绝对值必须 < 1e18（`session_stage.MAX_STAGED_INTEGER_MAGNITUDE`）；
    `id` 是 AUTOINCREMENT 主键，因此小于 1 的取值不是本模块认识的行号（不猜含义）。
    """
    if isinstance(row_id, bool) or not isinstance(row_id, int):
        return None
    if row_id < 1 or row_id >= 10**18:
        return None
    return row_id


class _Stats(NamedTuple):
    """一次统计阶段得出的整数集（全部来自白名单 SQL，不含任何行原值）。

    列语义与 `_QUERIES[_Op.MESSAGE_STATS]` 的注释逐字对应；后四项来自另外三条计数语句。
    """

    #: 候选行数（与取数语句谓词同形）。
    candidate: int
    #: 候选行可用正文总字符数。
    text_chars: int
    timestamp_unusable: int
    identity_unusable: int
    content_shape: int
    content_empty: int
    content_overlong: int
    #: 字面 `tool` 行数（本模块有意跳过，不使覆盖不完整）。
    tool_rows: int
    #: 非候选且非 tool 的活跃行数（不认识的角色形态，使覆盖不完整）。
    role_unusable: int
    #: 活跃行总数（由同一条 SQL 得出，用于账目核对）。
    active_rows: int
    #: `active = 0` 的行数。
    inactive_rows: int
    #: `active` 既非 1 亦非 0 的行数。
    active_unrecognized: int
    #: 该会话在全表中的行数（不分 active/角色，账目闭合的分母）。
    session_rows: int

    @property
    def unusable(self) -> int:
        """候选集内不可解释的行数合计（SQL 端结论，用于取正文前的判限与计划）。"""
        return (
            self.timestamp_unusable
            + self.identity_unusable
            + self.content_shape
            + self.content_empty
            + self.content_overlong
        )

    @property
    def accounted(self) -> bool:
        """行数账目是否闭合：活跃行 = 候选 + tool + 不认识角色，且活跃+不活跃+未识别 = 全表。"""
        if self.active_rows != self.candidate + self.tool_rows + self.role_unusable:
            return False
        return (
            self.active_rows + self.inactive_rows + self.active_unrecognized
            == self.session_rows
        )


class _RowCursor(Protocol):
    """`emit` 真正依赖的最小游标形状：只有 `fetchmany`。

    本模块不拿 `sqlite3.Cursor` 当类型前提：取数语句返回的就是它，但逐行阶段只调用
    `fetchmany`，因此这里声明真实依赖而不是具体类。这样单元测试能直接给出行数不一致的
    替身（真实只读连接在 `open()` 建立的只读事务里拿同一快照，同一连接内部制造不出
    「统计之后又多出/少掉行」），也不需要为了过类型检查而伪造游标。
    注意：替身游标不负责维护快照——`emit` 的快照复核看的是**连接**（`_snapshot_held`），
    因此测试仍须先 `open()` 一个真库再递入替身游标（现有测试即此形状）。
    """

    def fetchmany(self, size: int = ...) -> list[Any]: ...


class _SessionRun:
    """一次 `run_hermes_session` / `plan_hermes_session` 的内部状态机（单一所有者，顺序驱动）。

    授权不由本类判定：`store_path`/`scope`/`policy` 只是把调用方**已经**完成的存储轴结果带进来，
    供归属轴逐条核对。本类不打开目录、不解析 `HERMES_HOME`、不构造默认库路径。
    """

    __slots__ = (
        "_access",
        "_caller_admit",
        "_cancelled",
        "_capture",
        "_capture_pending",
        "_conn",
        "_facts",
        "_facts_loaded",
        "_gate",
        "_integrity_ok",
        "_label",
        "_label_degraded",
        "_max_bytes",
        "_max_candidates",
        "_max_rows",
        "_max_text_chars",
        "_parse",
        "_plan",
        "_policy",
        "_project",
        "_project_filter",
        "_rows_read",
        "_schema_known",
        "_schema_unknown_columns",
        "_schema_version",
        "_scope",
        "_session_id",
        "_snapshot",
        "_stage",
        "_stats",
        "_store_path",
        "_used",
        "_withheld",
    )

    def __init__(
        self,
        *,
        session_id: str,
        store_path: str | None = None,
        scope: str | None = None,
        policy: SessionPolicy | None = None,
        project_filter: str | None = None,
        label: str | None = None,
        label_degraded: bool = False,
        max_candidates: int,
        max_bytes: int,
        max_rows: int,
        max_text_chars: int,
        admit: Any = None,
        capture: Any = None,
    ) -> None:
        self._session_id = session_id
        self._store_path = store_path
        self._scope = scope
        self._policy = policy
        self._project_filter = project_filter
        self._label = label
        self._label_degraded = label_degraded
        self._max_candidates = max_candidates
        self._max_bytes = max_bytes
        self._max_rows = max_rows
        self._max_text_chars = max_text_chars
        self._caller_admit = admit
        self._capture = capture
        self._conn: sqlite3.Connection | None = None
        #: 本次读取是否已建立在同一个只读快照上（`open()` 建、各阶段复核、`close()` 释放）。
        self._snapshot = False
        self._used = False
        self._cancelled = False
        self._gate = HermesGateCode.OK
        self._access = HermesAccessCode.OK
        self._integrity_ok: bool | None = None
        self._schema_known = False
        self._schema_version: int | None = None
        self._schema_unknown_columns = 0
        self._facts_loaded = False
        self._facts: dict[str, Any] = {}
        self._project: str | None = None
        self._stats: _Stats | None = None
        self._rows_read = 0
        self._withheld: dict[str, int] = dict(_WITHHELD_KEYS)
        self._parse = ParseStats()
        self._plan: HermesSessionPlan | None = None
        self._stage = SessionCandidateStage(
            SOURCE_HERMES,
            session_id,
            max_candidates=max_candidates,
            max_bytes=max_bytes,
        )
        #: 核验前缓冲：`emit` 只把已入暂存层的候选记在这里（同一批对象的引用，条数与暂存层
        #: 同一上限），`finish()` 完整核验通过后才逐条交 `capture`；任何未核验终态整批清空。
        self._capture_pending: list[StandardRecord] = []

    # ---- 计数与准入 ----

    def _withhold(self, key: str, amount: int = 1) -> None:
        if amount <= 0:
            return
        self._withheld[key] = self._withheld.get(key, 0) + amount

    def _refusal_gate(self, failed: bool) -> HermesGateCode:
        """调用方准入钩子拒绝 → 归属轴拒绝；钩子自身抛异常 → 内部失败（都不回显内容）。"""
        if failed:
            return HermesGateCode.INTERNAL_FAILURE
        return HermesGateCode.ATTRIBUTION_DENIED

    def _admit_denial(self, denial: PolicyDenied) -> bool:
        """策略层拒绝的汇合入口：只留固定细类计数与**两个不同层**的 gate。

        `attribution_unmatched` / `project_mismatch` 是「已核对且确定不属于请求项目」——
        与「无法建立归属」(`attribution_denied`) 不同层，前者可写成诚实的零命中覆盖，
        后者只能说未确认。拒绝消息（可能含路径/项目名）不取。
        """
        self._withhold("admit_denied")
        key = _ATTRIBUTION_DENIAL_KEYS.get(denial.code)
        if key is None:
            # 本模块没预料到的拒绝码：不拿它猜细类，只计入总数（gate 仍为归属轴拒绝）。
            self._withhold("attribution_denied")
            self._gate = HermesGateCode.ATTRIBUTION_DENIED
            return True
        self._withhold(key)
        self._gate = _ATTRIBUTION_UNMATCHED_GATES.get(denial.code, HermesGateCode.ATTRIBUTION_DENIED)
        return True

    @staticmethod
    def _hook_refused(fn: Any, record: StandardRecord) -> tuple[bool, bool]:
        """调用一个钩子：返回 `(拒绝, 异常)`。异常一律按拒绝处理，绝不静默放行。"""
        try:
            refusal = fn(record)
        except Exception:  # noqa: BLE001 - 钩子异常一律折成「拒绝」，原始异常文本不得外传
            return True, True
        if refusal is None or refusal is False or refusal == "":
            return False, False
        return True, False

    def _policy_admit(self, record: StandardRecord) -> bool:
        """来源侧准入：策略层**归属轴**逐条核对（与存储轴相互独立）。

        归属证据是 `sessions.git_repo_root`/`cwd`：来源内的结构证据，不是读取授权，也不等于
        「已按项目归类」。因此每条候选都必须重新过 `policy.authorize_attribution`；通过也**不**
        授权发布（发布由调用方的输出侧准入决定）。策略拒绝在本模块只留下固定细类与计数，
        不回显项目名、路径或拒绝消息。「声称路径与请求项目不匹配」只能由策略层判定（路径→
        归属根→项目名映射）；本模块不拿记录路径与项目名做字面比较——那两者不是同一类对象。
        """
        policy = self._policy
        if policy is None:
            # 没有策略轴就没有归属判据：逐条核对无法进行，按拒绝收（不默认放行）。
            return self._admit_denial(_ATTRIBUTION_UNKNOWN_DENIAL)
        if record.project_quality is not ProjectQuality.TRUSTED_HEADER_CWD:
            # 无可用归属证据（sessions 行两个候选列都不可用）：不是越界，也不是形状错。
            return self._admit_denial(_ATTRIBUTION_UNKNOWN_DENIAL)
        try:
            policy.authorize_attribution(
                str(self._scope),
                str(record.project),
                project=self._project_filter,
            )
        except PolicyDenied as denial:
            # 不回显拒绝消息（可能含路径）：本模块只留固定细类与计数。
            return self._admit_denial(denial)
        return False

    def _admit(self, record: StandardRecord) -> bool:
        """两道准入串联：来源侧（策略归属轴）在前，调用方钩子在后；任一拒绝即整批不发布。

        调用方钩子只能更严（追加拒绝），不能替来源放行——它跑在来源侧之后，返回值只用于拒绝。
        """
        if self._policy_admit(record):
            return True
        caller = self._caller_admit
        if caller is None:
            return False
        refused, failed = self._hook_refused(caller, record)
        if refused:
            self._withhold("admit_denied")
            self._gate = self._refusal_gate(failed)
            return True
        return False

    # ---- 探测 ----

    def _require_conn(self) -> sqlite3.Connection:
        """连接与快照都由 `open()` 建立：本类的调用顺序由两个入口固定，缺任一个就是内部形状错。

        不用 `assert`：`python -O` 会把断言剔掉，而不是把失败方向保住。这里用显式检查
        + `_Abort`，所以下游拿到的连接永远是已建立的，而且**仍然在建立时那个只读事务里**：
        快照中途丢了就按 `snapshot_unavailable` 拒绝（不降级成逐语句各自快照继续读）。
        """
        conn = self._conn
        if conn is None:
            self._access = HermesAccessCode.INTERNAL_FAILURE
            raise _Abort(HermesGateCode.INTERNAL_FAILURE, self._access)
        if not self._snapshot_held():
            self._access = HermesAccessCode.SNAPSHOT_UNAVAILABLE
            raise _Abort(_gate_for_access(self._access), self._access)
        return conn

    @staticmethod
    def _tx_active(conn: sqlite3.Connection) -> bool:
        """驱动层唯一可核的快照证据：`in_transaction`。

        拿不到（连接已关、驱动报错）一律按「不在事务里」收——保守方向是拒发，不是继续读。
        """
        try:
            return bool(conn.in_transaction)
        except sqlite3.Error:  # 含 ProgrammingError（连接已关闭），它是 sqlite3.Error 的子类
            return False

    def _snapshot_held(self) -> bool:
        """本次读取的只读快照是否仍在（已声明建立 且 驱动仍报处于事务中）。"""
        conn = self._conn
        return bool(self._snapshot and conn is not None and self._tx_active(conn))

    def open(self, busy_timeout_ms: int) -> None:
        path = self._store_path
        if path is None:
            # 构造时没给库路径：内部调用形状错，按内部失败收（不猜默认路径、不碰任何文件）。
            self._access = HermesAccessCode.INTERNAL_FAILURE
            raise _Abort(HermesGateCode.INTERNAL_FAILURE, self._access)
        try:
            uri = _read_only_uri(path)
        except (OSError, ValueError):
            # URI 无法构造（路径无法 resolve/percent-encode）：形状不合，按不可用。
            self._access = HermesAccessCode.UNAVAILABLE
            raise _Abort(HermesGateCode.SOURCE_UNAVAILABLE, self._access) from None
        try:
            conn = _connect_read_only(uri, busy_timeout_ms)
        except sqlite3.Error as exc:
            self._access = _classify_exception(exc, path)
            raise _Abort(_gate_for_access(self._access), self._access) from None
        self._conn = conn
        try:
            # 防御性只读声明：mode=ro 已禁止写入，`query_only` 再兜一层（不是授权判据）。
            _execute(conn, _Op.QUERY_ONLY).fetchone()
        except sqlite3.Error as exc:
            self._access = _classify_exception(exc, path)
            gate = _gate_for_access(self._access)
            self.close()
            raise _Abort(gate, self._access) from None
        try:
            # 快照锚点：显式只读事务让第一条读语句取到共享读锁，并把本库版本冻结到本次读取
            # 结束（见模块头「读取快照一致性」）。`BEGIN` 是延迟的：锁在首条读语句上才拿，
            # 所以已持写锁的来源仍会在下游报 `locked`（有界等待），而不是在这里变成另一种结论。
            _execute(conn, _Op.BEGIN_READ).fetchone()
        except sqlite3.Error as exc:
            self._access = _classify_exception(exc, path)
            gate = _gate_for_access(self._access)
            self.close()
            raise _Abort(gate, self._access) from None
        if not self._tx_active(conn):
            # `BEGIN` 执行了但驱动不认为处于事务中：那拿不到同一快照，本模块不拿它冒充一致性。
            # 固定码拒收、候选尚未产生（因此无需清空），`close()` 不会留下未释放的事务。
            self._access = HermesAccessCode.SNAPSHOT_UNAVAILABLE
            self.close()
            raise _Abort(HermesGateCode.SOURCE_UNAVAILABLE, self._access) from None
        self._snapshot = True

    def probe(self) -> None:
        conn = self._require_conn()
        try:
            access, version, known, unknown_columns = _probe_schema(conn)
        except sqlite3.Error as exc:
            access, version, known, unknown_columns = (
                _classify_exception(exc, self._store_path),
                None,
                False,
                0,
            )
        self._access = access
        self._schema_version = version
        self._schema_known = known
        self._schema_unknown_columns = unknown_columns
        self._withhold("unknown_columns", unknown_columns)
        if access is not HermesAccessCode.OK:
            raise _Abort(_gate_for_access(access), access)
        try:
            access, integrity = _probe_integrity(conn)
        except sqlite3.Error as exc:
            access, integrity = _classify_exception(exc, self._store_path), None
        self._access = access
        self._integrity_ok = integrity
        if access is not HermesAccessCode.OK:
            raise _Abort(_gate_for_access(access), access)

    def load_facts(self) -> None:
        conn = self._require_conn()
        try:
            row = _execute(conn, _Op.SESSION_FACTS, (self._session_id,)).fetchone()
        except sqlite3.Error as exc:
            self._access = _classify_exception(exc, self._store_path)
            raise _Abort(_gate_for_access(self._access), self._access) from None
        if row is None:
            # 「会话不存在」是**确定的**来源结论（授权库上按主键查过），不是覆盖不完整。
            self._gate = HermesGateCode.SESSION_NOT_FOUND
            raise _Abort(self._gate, self._access)
        self._facts_loaded = True
        facts, counts = _facts_from_row(tuple(row))
        self._facts = facts
        self._withhold("facts_unusable", counts)
        if facts.get("source") != SOURCE_HERMES:
            # 观测：`sessions.source` 取值不是 'hermes'（含不可解释形态）。本增量不因此过滤
            # （产出判据是角色/正文形状），但如实计数，跨来源聚合不能假装没看见。
            self._withhold("source_hermes_mismatch")
        project, missing = _project_from_facts(facts)
        self._project = project
        self._withhold("project_unusable", missing)

    def _stats_params(self) -> tuple[object, ...]:
        """按 `_QUERIES[_Op.MESSAGE_STATS]` 的文本位置给出绑定序列。

        改这条 SQL 必须同步改这里；两处都只使用模块内常量与调用方给定的会话标识。
        """
        roles = _ROLES_BOUND_ORDER
        return (
            MAX_ROW_TEXT_CHARS,  # c2 正文长度上限
            USABLE_EPOCH_MIN,  # c3 下界
            USABLE_EPOCH_MAX,  # c3 上界
            MAX_ID_CHARS,  # c4 身份长度上限
            self._session_id,  # c4 身份逐字比对
            MAX_ROW_TEXT_CHARS,  # c7 超长上限
            TOOL_ROLE,  # c8 tool
            TOOL_ROLE,  # c9 IS NOT ?
            TOOL_ROLE,  # c9 <> ?
            *roles,  # 内层候选判定 role IN
            self._session_id,  # 内层 session_id
            self._session_id,  # 外层 session_id
        )

    def stats(self) -> _Stats:
        conn = self._require_conn()
        try:
            row = _execute(conn, _Op.MESSAGE_STATS, self._stats_params()).fetchone()
            inactive = _read_int(_execute(conn, _Op.INACTIVE_COUNT, (self._session_id,)))
            unrecognized = _read_int(
                _execute(conn, _Op.ACTIVE_UNRECOGNIZED, (self._session_id,))
            )
            session_rows = _read_int(
                _execute(conn, _Op.SESSION_ROW_COUNT, (self._session_id,))
            )
        except sqlite3.Error as exc:
            self._access = _classify_exception(exc, self._store_path)
            raise _Abort(_gate_for_access(self._access), self._access) from None
        if row is None or inactive is None or unrecognized is None or session_rows is None:
            self._gate = HermesGateCode.INTERNAL_FAILURE
            raise _Abort(self._gate, self._access)
        values = tuple(row)
        if len(values) != 10 or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ):
            # 统计列形态不认识：不猜、不产出，按内部失败收（覆盖必然不完整）。
            self._gate = HermesGateCode.INTERNAL_FAILURE
            raise _Abort(self._gate, self._access)
        stats = _Stats(
            candidate=values[0],
            text_chars=values[1],
            timestamp_unusable=values[2],
            identity_unusable=values[3],
            content_shape=values[4],
            content_empty=values[5],
            content_overlong=values[6],
            tool_rows=values[7],
            role_unusable=values[8],
            active_rows=values[9],
            inactive_rows=inactive,
            active_unrecognized=unrecognized,
            session_rows=session_rows,
        )
        self._stats = stats
        # 只统计**逐行取数看不到的类别**：tool 行、不认识角色、不活跃行、未识别 active
        # 都进不了 MESSAGE_ROWS 的谓词，因此由统计端计数；时间戳与正文形状留给逐行阶段，
        # 避免同一行被计两次。
        self._withhold("identity_unusable", stats.identity_unusable)
        self._withhold("role_skipped", stats.tool_rows)
        self._withhold("role_unusable", stats.role_unusable)
        self._withhold("inactive_rows", stats.inactive_rows)
        self._withhold("active_unrecognized", stats.active_unrecognized)
        # 本模块读到了但**无法解释**的行必须同时反映到 parse 降级（存在性记一次，真实
        # 条数在 withheld 计数里）：`ParseStats.partial` 是诚实覆盖的信号，协调层据此
        # 不得宣称「完整搜过」。不活跃行（active=0）不记降级：那是来源侧已知的合法形态，
        # 与 pi 路径的 KNOWN_NON_TEXT_BLOCK 同取向。
        if stats.identity_unusable:
            self._parse.note(IssueCode.MISSING_SESSION_ID)
        if stats.role_unusable:
            self._parse.note(IssueCode.UNKNOWN_ROLE)
        if stats.active_unrecognized:
            # `active` 既非 1 亦非 0：本模块不认识这种形态，不猜（行无法判定是否存活）。
            self._parse.note(IssueCode.CORRUPT_LINE)
        return stats

    def build_plan(self, stats: _Stats) -> HermesSessionPlan:
        """把探测/统计阶段的整数折成对外计划（不含正文、不含任何行原值）。"""
        reasons = dict(_WITHHELD_KEYS)
        reasons.update(self._withheld)
        return HermesSessionPlan(
            available=True,
            access=HermesAccessCode.OK,
            gate=HermesGateCode.OK,
            session_exists=True,
            row_count=stats.active_rows,
            candidate_count=stats.candidate,
            inactive_count=stats.inactive_rows,
            unknown_columns=self._schema_unknown_columns,
            text_chars=stats.text_chars,
            unusable_count=stats.unusable + stats.role_unusable,
            unavailable_reasons=reasons,
            integrity_ok=self._integrity_ok,
            schema_version=self._schema_version,
            schema_known=self._schema_known,
        )

    def check_bounds(self, stats: _Stats) -> None:
        """在取任何正文**之前**判限：账目闭合、行数、字节预算（最坏形状折算）。"""
        if not stats.accounted:
            # 四条计数语句处于同一只读快照，因此本应必然闭合；不闭合即来源形状与本模块声明的
            # 判据不符（或快照已不成立）：两种情况下都不核对可能不完整的流。
            self._withhold("account_mismatch")
            self._gate = HermesGateCode.MESSAGE_ROWS_UNBOUNDED
            raise _Abort(self._gate, self._access)
        if stats.candidate > self._max_rows:
            self._withhold("trailing_rows", stats.candidate - self._max_rows)
            self._gate = HermesGateCode.MESSAGE_LIMIT_EXCEEDED
            raise _Abort(self._gate, self._access)
        # 暂存层每条记录扣 `PER_RECORD_FIXED_OVERHEAD_BYTES` + 正文 utf-8 字节；这里按
        # 「每字符至多 4 字节」的最坏形状折算，精确扣账仍由暂存层负责（它触限时整批丢弃）。
        worst_bytes = stats.candidate * PER_RECORD_FIXED_OVERHEAD_BYTES + stats.text_chars * 4
        if stats.text_chars > self._max_text_chars or worst_bytes > self._max_bytes:
            self._gate = HermesGateCode.BYTE_LIMIT_EXCEEDED
            raise _Abort(self._gate, self._access)

    # ---- 取数与产出 ----

    def rows(self) -> sqlite3.Cursor:
        conn = self._require_conn()
        # 快照内取数：行集与统计阶段同一版本，因此这里的 `LIMIT max_rows + 1` 不再是「漂移
        # 上限」，而是行数判限的双保险（万一统计与取数的谓词基准不一致，多出的那一行仍会
        # 在 `rows_seen != expected_rows` 上当场发现）。游标本体的取数工作也因此在 SQL 端封顶。
        # 绑定顺序按 SQL 文本位置：kind 的正文上限 → 子查询 session_id → 角色白名单 → LIMIT。
        # kind 的上限与 MESSAGE_STATS c2/c7 绑定同一常量，投影端与统计端因此是同一判据。
        params = (
            MAX_ROW_TEXT_CHARS,
            self._session_id,
            *_ROLES_BOUND_ORDER,
            self._max_rows + 1,
        )
        try:
            return _execute(conn, _Op.MESSAGE_ROWS, params)
        except sqlite3.Error as exc:
            self._access = _classify_exception(exc, self._store_path)
            raise _Abort(_gate_for_access(self._access), self._access) from None

    def emit(
        self,
        cursor: _RowCursor,
        expected_rows: int,
        *,
        should_stop: Any,
    ) -> HermesGateCode:
        """逐行产出候选并交暂存层；任何中断都只留下固定类别与整数。

        `expected_rows` 是统计阶段的候选行数；两者现在处于同一只读快照，所以谓词同形的两条
        语句必须给出行数一致——不等即快照不成立（或基准不一致），仍按原有固定码报出。
        每批取数前复核一次快照（`_snapshot_held`）：事务在读取中被外部结束（如磁盘 IO 错误
        使 sqlite 自动回滚）时，下一批看到的就已是另一个版本，因此当场按
        `snapshot_unavailable` 停发（不拿已产出的半批冒充一份自洽的会话）。
        被拒的行**不产出**但计入 `lines_seen` 与降级类别，因此 skipped 计数与
        `ParseStats.partial` 都落在真实账目上。
        `capture` 不在本阶段执行：已暂存候选先进入 `_capture_pending`（与暂存层同一批对象，
        条数由 `max_candidates` 封顶），由 `finish()` 在完整核验通过之后逐条外递；取消、触限、
        锁、快照丢失、行数不一致、核对未通过、`parse.partial` 这些终态一条正文也不外递。
        """
        if self._label_degraded:
            self._withhold("label_unusable")
        stopped = False
        rows_seen = 0
        while True:
            if not self._snapshot_held():
                # 快照中途丢了：剩下的行属于另一个版本，不取、不产、不等。
                self._snapshot = False
                self._access = HermesAccessCode.SNAPSHOT_UNAVAILABLE
                self._gate = HermesGateCode.SOURCE_UNAVAILABLE
                return self._gate
            if should_stop is not None:
                try:
                    if should_stop():
                        stopped = True
                        break
                except Exception:  # noqa: BLE001 - 取消谓词抛错与返回真值同按取消处理
                    stopped = True
                    break
            try:
                batch = cursor.fetchmany(_FETCH_BATCH_ROWS)
            except sqlite3.Error as exc:
                self._access = _classify_exception(exc, self._store_path)
                self._gate = _gate_for_access(self._access)
                return self._gate
            if not batch:
                break
            for raw in batch:
                rows_seen += 1
                self._parse.lines_seen += 1
                record, rejection, label_degraded, tool_degraded = _classify_row(
                    tuple(raw),
                    session_id=self._session_id,
                    label=self._label,
                    project=self._project,
                )
                if label_degraded:
                    self._withhold("label_unusable")
                if tool_degraded:
                    self._withhold("tool_name_unusable")
                if rejection is not None:
                    self._withhold(_REJECTION_KEY[rejection])
                    self._parse.note(_REJECTION_ISSUE[rejection])
                    continue
                # `rejection is None` 与 `record is not None` 在 `_classify_row` 里同位给出，
                # 但本模块不把那个约定当成可依赖的前提：拿到预期外取值就按内部失败收。
                if record is None:
                    self._withhold("row_id_unusable")
                    self._gate = HermesGateCode.INTERNAL_FAILURE
                    return self._gate
                if self._admit(record):
                    return self._gate
                self._parse.lines_with_records += 1
                self._parse.records_emitted += 1
                if not self._stage.add(record):
                    self._gate = HermesGateCode.STAGE_REJECTED
                    return self._gate
                self._rows_read += 1
                if self._capture is not None:
                    # 逐行阶段**不**向外递正文：候选只进缓冲，`capture` 推迟到 `finish()`
                    # 完整核验通过之后。未核验终态（含 `parse.partial`）由 `finish()` 整批
                    # 清空缓冲且根本不调用 `capture`，外部收集器因此在**这些路径**上拿不到
                    # 任何片段；核验通过后的外递首拒可能已留下前缀（分层见 `finish`）。
                    self._capture_pending.append(record)
        if stopped:
            # `should_stop` 中断时游标上本来就还有未读行，那是取消的事实，不是行数不一致；
            # 两者不能同一类别。
            self._gate = HermesGateCode.CANCELLED
            self._cancelled = True
            return self._gate
        if rows_seen != expected_rows:
            # 同快照下两条语句的谓词同基准，行数必须相等：不等即快照不成立（或上游统计与
            # 取数的判据不一致），仍按固定码报告且不核对不完整流（候选由 `finish(False)` 清空）。
            # 取数语句带 `LIMIT max_rows + 1`：即使行集比预期大，游标也最多返回这些行，
            # 工作量由上限封顶；多出来的行计入 `trailing_rows`。
            if rows_seen > expected_rows:
                self._withhold("trailing_rows", rows_seen - expected_rows)
                self._gate = HermesGateCode.MESSAGE_ROWS_UNBOUNDED
            else:
                self._gate = HermesGateCode.MESSAGE_ROWS_SHORT
            return self._gate
        return HermesGateCode.OK

    # ---- 收尾 ----

    def finish(self, stream_complete: bool) -> HermesSessionOutcome:
        """核对并给出最终结论；**未核验终态一条也不外递**，缓冲在返回前整批清空；完整核验通过后才会逐条外递。

        暂存层在 `stream_complete=False` 或核对未通过时整批丢弃（候选正文清空、计数归零），
        所以取消、判限、锁、快照丢失、行数不一致、核对未通过这些路径都满足「失败不留正文」。
        注意：候选行为 0 的会话也无法建立记录侧身份（暂存层要求两路独立证据），因此
        `complete` 为 `False` 且 `gate=stage_incomplete`——这是「未确认」，不是「无匹配」。
        `capture` 只在本函数算出 `complete=True`（流读完、暂存层核对通过、`parse.partial` 为假）
        之后逐条外递缓冲；`parse.partial` 与其余未核验终态一条也不递，缓冲在返回前整批清空。
        外递阶段的拒绝/异常只翻掉 `complete` 与 `gate`（输出侧失败方向不变），不反向改写
        暂存层已定的核对结论：`stage` 快照仍是核对通过的那份（`candidate_count`/`staged_bytes`/
        `dropped_count` 都是验证时点的冻结值），候选正文不因此回流到本模块。
        口径分层（审查后澄清，2026-11-01）：「零正文」说的是**本模块的终态**——终态不含任何
        正文，缓冲也已整批清空；首条被拒之前，`capture` 已逐条收到过的那些正文属于**调用方
        一侧已经发生的事实**，本模块无法撤销，也不承诺调用方会把它们丢弃。要「整批或零条」
        语义需由收集器自己保证（内置 `SnippetCollector` 的首拒即清掉自身已收集前缀，含已接受
        部分；未来接线发布路径时须同样满足同等边界）。
        """
        admitted_stream = self._gate is HermesGateCode.OK and stream_complete
        stage_outcome = self._stage.finish(stream_complete=admitted_stream)
        complete = (
            admitted_stream
            and stage_outcome.complete
            and not self._parse.partial
        )
        if not complete and self._gate is HermesGateCode.OK:
            if admitted_stream and stage_outcome.complete and self._parse.partial:
                # 流读完了、核对过了，但存在不可解释的行：这不是「核对未通过」，
                # 也不能说完整，用独立类别区分。
                self._gate = HermesGateCode.PARSE_INCOMPLETE
            else:
                self._gate = HermesGateCode.STAGE_INCOMPLETE
        if complete and self._capture is not None:
            # 完整核验通过后才外递正文：逐条送 `capture`，任一拒绝即停（不再递后续候选），
            # 并把终态翻成未核验——失败方向与逐行阶段被拒时一致（拒绝→stage_rejected，
            # 钩子自身抛异常→internal_failure）。首拒之前通用逐条 callback 已收到过的前缀
            # 属于调用方一侧已发生的事实，本模块无法撤销；清空内部缓冲不能回滚外部 sink，
            # 「整批或零条」需由收集器自己保证（内置 `SnippetCollector` 首拒即清自身前缀）。
            complete = self._release_captured()
        else:
            # 未核验终态（含 `parse.partial`）：缓冲整批丢弃——正文既不外递也不留在实例上，
            # 与暂存层在同一判据上的丢弃保持同一方向。
            self._capture_pending.clear()
        plan = self._plan if self._plan is not None else self._fallback_plan()
        reasons = dict(plan.unavailable_reasons)
        reasons.update(self._withheld)
        plan = _replace_plan(plan, unavailable_reasons=reasons)
        return HermesSessionOutcome(
            complete=complete,
            publication_allowed=False,
            gate=self._gate,
            access=self._access,
            stage=stage_outcome,
            records_emitted=self._parse.records_emitted,
            rows_read=self._rows_read,
            withheld_reasons=reasons,
            parse=self._parse,
            plan=plan,
        )

    def _release_captured(self) -> bool:
        """把缓冲的已核验候选逐条交 `capture`；返回是否仍可称完整。缓冲**无论成败都清空**。

        首拒即停（不把后续正文继续外递），并按原有失败方向定 gate：钩子返回拒绝码 →
        `STAGE_REJECTED`；钩子自身抛异常 → `INTERNAL_FAILURE`（异常文本不回显）。
        未递出的剩余候选随缓冲一起丢弃：本模块不留「半个已核验集合」。
        """
        capture = self._capture
        pending = self._capture_pending
        self._capture_pending = []
        for record in pending:
            refused, failed = self._hook_refused(capture, record)
            if refused:
                self._gate = (
                    HermesGateCode.INTERNAL_FAILURE
                    if failed
                    else HermesGateCode.STAGE_REJECTED
                )
                pending.clear()
                return False
        return True

    def _fallback_plan(self) -> HermesSessionPlan:
        stats = self._stats
        if stats is None:
            return _empty_plan(self._access, self._gate)
        plan = self.build_plan(stats)
        return _replace_plan(
            plan,
            available=self._access is HermesAccessCode.OK,
            session_exists=self._facts_loaded,
            access=self._access,
            gate=self._gate,
        )

    def close(self) -> None:
        # 缓冲的最后一道清空：正常路径上 `finish()` 已处理，这里只兜住「未走到 finish」的
        # 出口（调用方拿到 `_Abort` 之前中断等），不把已读正文留在实例上。
        self._capture_pending.clear()
        conn = self._conn
        held = self._snapshot
        self._conn = None
        self._snapshot = False
        if conn is None:
            return
        if held:
            # 只读事务没有可提交的内容：`ROLLBACK` 是归还共享读锁的方式（它不写盘）。
            # 不能只 `close()` 就了事：否则本进程的残留读锁会让后续写入拿到 `locked`。
            # 失败不另判结论：快照已经作废，后面的 `close()` 才是本次读取的最后一步。
            with contextlib.suppress(sqlite3.Error):
                _execute(conn, _Op.END_READ).fetchone()
        with contextlib.suppress(sqlite3.Error):
            conn.close()


_REJECTION_KEY = {
    "identity": "identity_unusable",
    "role": "role_unusable",
    "content_empty": "content_empty",
    "content_shape": "content_shape",
    "content_overlong": "content_overlong",
    "timestamp": "timestamp_unusable",
    "row_id": "row_id_unusable",
}
_REJECTION_ISSUE = {
    "identity": IssueCode.MISSING_SESSION_ID,
    "role": IssueCode.UNKNOWN_ROLE,
    "content_empty": IssueCode.NO_TEXT_CONTENT,
    "content_shape": IssueCode.INVALID_CONTENT_SHAPE,
    "content_overlong": IssueCode.LINE_TOO_LARGE,
    "timestamp": IssueCode.TIMESTAMP_INVALID,
    "row_id": IssueCode.MISSING_MESSAGE_ENVELOPE,
}


def _replace_plan(plan: HermesSessionPlan, **changes: Any) -> HermesSessionPlan:
    """按给定字段重建冻结计划（只为合并计数，不引入任何新信息）。"""
    fields: dict[str, Any] = {
        "available": plan.available,
        "access": plan.access,
        "gate": plan.gate,
        "session_exists": plan.session_exists,
        "row_count": plan.row_count,
        "candidate_count": plan.candidate_count,
        "inactive_count": plan.inactive_count,
        "unknown_columns": plan.unknown_columns,
        "text_chars": plan.text_chars,
        "unusable_count": plan.unusable_count,
        "unavailable_reasons": plan.unavailable_reasons,
        "integrity_ok": plan.integrity_ok,
        "schema_version": plan.schema_version,
        "schema_known": plan.schema_known,
    }
    fields.update(changes)
    return HermesSessionPlan(**fields)  # type: ignore[arg-type]


def _abort_plan(run: _SessionRun, access: HermesAccessCode, gate: HermesGateCode) -> HermesSessionPlan:
    """中止路径上的计划：保留已经得到的整数结论，其余按「未知」如实留空。

    `available` 只表示**探测本身得出了可用结论且库可读写之外的只读访问正常**（access=OK）：
    会话不存在（session_not_found）与判限中止（limit/byte）都是「有结论」的中止，所以
    available 仍为 True；锁/损坏/未知 schema/内部失败才是 False。两种情况下本模块都**不**
    声明读完了正文。
    """
    stats = run._stats
    reasons = dict(_WITHHELD_KEYS)
    reasons.update(run._withheld)
    return HermesSessionPlan(
        available=access is HermesAccessCode.OK,
        access=access,
        gate=gate,
        session_exists=run._facts_loaded,
        row_count=stats.active_rows if stats is not None else 0,
        candidate_count=stats.candidate if stats is not None else 0,
        inactive_count=stats.inactive_rows if stats is not None else 0,
        unknown_columns=run._schema_unknown_columns,
        text_chars=stats.text_chars if stats is not None else 0,
        unusable_count=(stats.unusable + stats.role_unusable) if stats is not None else 0,
        unavailable_reasons=reasons,
        integrity_ok=run._integrity_ok,
        schema_version=run._schema_version,
        schema_known=run._schema_known,
    )


def _limits(
    *,
    max_candidates: int,
    max_rows: int,
    max_bytes: int,
    max_text_chars: int,
) -> tuple[int, int, int, int]:
    """折叠调用方上限，返回 `(max_candidates, max_rows, max_bytes, max_text_chars)`。"""
    candidates, rows, bytes_, chars = _clamp_limits(max_candidates, max_rows, max_bytes)
    chars = min(chars, max_text_chars)
    return candidates, rows, bytes_, chars


def plan_hermes_session(
    *,
    path: object,
    session_id: object,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    max_rows: int = MAX_ROWS_PER_SESSION,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = DEFAULT_STAGE_BYTES,
    max_text_chars: int = MAX_ROW_TEXT_TOTAL_CHARS,
) -> HermesSessionPlan:
    """只做只读探测与边界判定，不取任何正文，不返回任何原值。

    本函数**不做授权**：调用方必须先 `policy.authorize_store(scope, SOURCE_HERMES, path,
    kind=TargetKind.FILE)`，否则这里连路径形状都不检查（授权与探测是两件事，缺一不可）。
    结论只在 `available/access/gate` 三层与整数计数里出现；正文总字符的统计也在 SQL 端完成，
    所以「有界」的判定不消耗任何正文内存。
    """
    bad = _validate_args(
        session_id=session_id,
        busy_timeout_ms=busy_timeout_ms,
        max_rows=max_rows,
        max_candidates=max_candidates,
        max_bytes=max_bytes,
        max_text_chars=max_text_chars,
    )
    if bad is not None or not _is_trusted_store(path):
        return _empty_plan(HermesAccessCode.INVALID_ARGUMENT, HermesGateCode.INVALID_ARGUMENT)
    # `_validate_args`/`_is_trusted_store` 已把两者收敛为 str，但本模块不把那个约定
    # 当前提（`assert` 会被 `python -O` 剔掉，失败方向就丢了）：拿不到预期形状就
    # 按形状错收，不打开文件。
    if not isinstance(path, str) or not isinstance(session_id, str):
        return _empty_plan(
            HermesAccessCode.INVALID_ARGUMENT, HermesGateCode.INVALID_ARGUMENT
        )
    candidates, rows, bytes_, chars = _limits(
        max_candidates=max_candidates,
        max_rows=max_rows,
        max_bytes=max_bytes,
        max_text_chars=max_text_chars,
    )
    run = _SessionRun(
        session_id=session_id,
        store_path=path,
        max_candidates=candidates,
        max_bytes=bytes_,
        max_rows=rows,
        max_text_chars=chars,
    )
    try:
        run.open(busy_timeout_ms)
        run.probe()
        run.load_facts()
        stats = run.stats()
        plan = run.build_plan(stats)
        run._plan = plan
        run.check_bounds(stats)
        return plan
    except _Abort as abort:
        return _abort_plan(run, abort.access, abort.gate)
    except Exception:  # noqa: BLE001 - 未预期异常的原始消息可能含路径，不回显
        # 未预期的驱动/内部异常：不回显消息（可能含路径），只报内部失败。
        return _empty_plan(
            HermesAccessCode.INTERNAL_FAILURE, HermesGateCode.INTERNAL_FAILURE
        )
    finally:
        run.close()


def run_hermes_session(
    *,
    path: object,
    session_id: object,
    scope: str | None = None,
    policy: SessionPolicy | None = None,
    project_filter: str | None = None,
    should_stop: Any = None,
    capture: Any = None,
    admit: Any = None,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    max_rows: int = MAX_ROWS_PER_SESSION,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = DEFAULT_STAGE_BYTES,
    max_text_chars: int = MAX_ROW_TEXT_TOTAL_CHARS,
) -> HermesSessionOutcome:
    """把一个会话读成暂存候选并核对，返回**只有整数与固定类别**的结论。

    本增量不发布正文：`publication_allowed` 恒为 `False`，`StageOutcome` 也不带正文出口。
    调用方若要外出片段，必须另走 `publication.SnippetCollector` + `references` 台账
    （与 `file_search.py` 的 pi 路径同一形状），本模块只提供可信的「已核对候选流」。

    准入钩子是**串联**的：来源侧（策略归属轴）先跑，调用方 `admit` 后跑，任一拒绝即整批不
    发布；调用方钩子只能更严，不能替来源放行。`admit`/`capture` 自身抛异常一律按拒绝处理并
    归入 `internal_failure`（异常消息不回显）。

    `capture` 的**时点**：它不跑在逐行取数阶段。已暂存候选先进入内部缓冲（条数由 `max_candidates`
    封顶，不另开一条无界队列），只有 `finish()` 把整批核验通过（流读完 + 暂存层核对通过 +
    `parse.partial` 为假）后才逐条外递；`parse.partial` 与其余未核验终态一条也不递，缓冲整批
    丢弃。因此**本模块的终态**不含任何正文，未核验终态也不会外递片段。外递是逐条调用回调，
    首条被拒之前回调已经收到过的那些正文属于调用方一侧已经发生的事实，本模块无法撤销，因此
    **不承诺外部收集器「要么整批、要么什么都没有」**；要那种语义需由收集器自己保证（内置
    `SnippetCollector` 首拒即清掉自身已收集候选，含已接受部分；未来接线发布路径时须同样
    满足同等边界）。
    外递阶段首拒即停：拒绝码→ `gate=stage_rejected`，钩子异常→ `gate=internal_failure`，
    并把 `complete` 翻为假（不反向改写暂存层已定的核对结论——`stage` 快照是验证时点的冻结值，
    事后外递失败不回改 `stage.complete`/`candidate_count`/`staged_bytes`/`dropped_count`）。
    副作用：capture 存在时，行流会读到
    预期行数才开始外递（读取量仍由 `max_rows`/`max_candidates`/字节预算封顶，不增加可读上限）。

    两条授权轴在此**都由本函数强制**，不靠调用方自觉：
    1. 存储轴：`policy.authorize_store(scope, SOURCE_HERMES, path, kind=TargetKind.FILE)`，
       被拒即 `gate=storage_denied` 且不打开任何文件；通过后实际打开的是**授权凭证里的路径**
       （`grant.readable_path`），不是调用方原样传入的字符串。
    2. 归属轴：逐条 `authorize_attribution`（见 `_policy_admit`）。
    两轴相互独立，都通过也**不**等于可发布：发布由协调层决定，`publication_allowed` 恒为 False。
    """
    bad = _validate_args(
        session_id=session_id,
        busy_timeout_ms=busy_timeout_ms,
        max_rows=max_rows,
        max_candidates=max_candidates,
        max_bytes=max_bytes,
        max_text_chars=max_text_chars,
    )
    invalid = _empty_plan(
        HermesAccessCode.INVALID_ARGUMENT, HermesGateCode.INVALID_ARGUMENT
    )
    if bad is not None or not _is_trusted_store(path):
        return _failure_outcome(
            invalid, HermesGateCode.INVALID_ARGUMENT, HermesAccessCode.INVALID_ARGUMENT
        )
    # `_validate_args`/`_is_trusted_store` 已把两者收敛为 str，但本模块不把那个约定
    # 当前提（`assert` 会被 `python -O` 剔掉，失败方向就丢了）：拿不到预期形状就
    # 按形状错收，不打开文件。
    if not isinstance(path, str) or not isinstance(session_id, str):
        return _failure_outcome(
            invalid, HermesGateCode.INVALID_ARGUMENT, HermesAccessCode.INVALID_ARGUMENT
        )
    if (policy is None) != (scope is None):
        # `policy` 与 `scope` 必须成对：只给一个就是调用方形状错，不猜它想要哪个轴。
        return _failure_outcome(
            invalid, HermesGateCode.INVALID_ARGUMENT, HermesAccessCode.INVALID_ARGUMENT
        )
    if policy is None or scope is None:
        # 产出候选的路径必须有策略轴：没有授权对象可核对时按存储轴拒收，绝不默认放行。
        return _failure_outcome(
            _empty_plan(HermesAccessCode.UNAVAILABLE, HermesGateCode.STORAGE_DENIED),
            HermesGateCode.STORAGE_DENIED,
            HermesAccessCode.UNAVAILABLE,
        )
    if not isinstance(scope, str) or not scope:
        return _failure_outcome(
            invalid, HermesGateCode.INVALID_ARGUMENT, HermesAccessCode.INVALID_ARGUMENT
        )
    try:
        # 存储轴：先授权，后打开；实际打开的是凭证里的规范路径（宿主显式批准对象）。
        grant = policy.authorize_store(
            scope, SOURCE_HERMES, path, kind=TargetKind.FILE
        )
    except PolicyDenied:
        # 不回显拒绝消息（可能含路径），只留固定类别；本模块从未打开该库。
        return _failure_outcome(
            _empty_plan(HermesAccessCode.UNAVAILABLE, HermesGateCode.STORAGE_DENIED),
            HermesGateCode.STORAGE_DENIED,
            HermesAccessCode.UNAVAILABLE,
        )
    authorized_path = str(grant.readable_path)
    if not _is_trusted_store(authorized_path):
        # 凭证路径本身不合本模块的可信判据（含 URI 分隔符等）：不打开，按形状错收。
        return _failure_outcome(
            invalid, HermesGateCode.INVALID_ARGUMENT, HermesAccessCode.INVALID_ARGUMENT
        )
    candidates, rows, bytes_, chars = _limits(
        max_candidates=max_candidates,
        max_rows=max_rows,
        max_bytes=max_bytes,
        max_text_chars=max_text_chars,
    )
    label, degraded = _db_stream_label(authorized_path)
    run = _SessionRun(
        session_id=session_id,
        store_path=authorized_path,
        scope=scope,
        policy=policy,
        project_filter=project_filter,
        label=label,
        label_degraded=degraded,
        max_candidates=candidates,
        max_bytes=bytes_,
        max_rows=rows,
        max_text_chars=chars,
        admit=admit,
        capture=capture,
    )
    try:
        run.open(busy_timeout_ms)
        run.probe()
        run.load_facts()
        stats = run.stats()
        run._plan = run.build_plan(stats)
        run.check_bounds(stats)
        gate = run.emit(run.rows(), stats.candidate, should_stop=should_stop)
        return run.finish(gate is HermesGateCode.OK)
    except _Abort as abort:
        run._plan = _abort_plan(run, abort.access, abort.gate)
        run._gate = abort.gate
        run._access = abort.access
        return run.finish(False)
    except Exception:  # noqa: BLE001 - 不回显异常原文（可能含路径/正文），按内部失败收
        # 未预期异常：不回显，按内部失败收；候选正文整批丢弃（finish(False)）。
        run._gate = HermesGateCode.INTERNAL_FAILURE
        run._access = HermesAccessCode.INTERNAL_FAILURE
        return run.finish(False)
    finally:
        run.close()


def _failure_outcome(
    plan: HermesSessionPlan, gate: HermesGateCode, access: HermesAccessCode
) -> HermesSessionOutcome:
    return HermesSessionOutcome(
        complete=False,
        publication_allowed=False,
        gate=gate,
        access=access,
        stage=None,
        records_emitted=0,
        rows_read=0,
        withheld_reasons=dict(plan.unavailable_reasons),
        parse=ParseStats(),
        plan=plan,
    )


def _validate_args(**kwargs: Any) -> str | None:
    """参数形态校验：返回固定原因字符串（外出前会被降为 `invalid_argument` 类别）。"""
    session_id = kwargs.get("session_id")
    if not isinstance(session_id, str) or not session_id or len(session_id) > MAX_ID_CHARS:
        return "session_id"
    if session_id != session_id.strip():
        return "session_id"
    for name in ("max_rows", "max_candidates", "max_bytes", "max_text_chars"):
        value = kwargs.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return name
    busy = kwargs.get("busy_timeout_ms")
    if isinstance(busy, bool) or not isinstance(busy, int):
        return "busy_timeout_ms"
    if not _BUSY_TIMEOUT_MIN_MS <= busy <= _BUSY_TIMEOUT_MAX_MS:
        return "busy_timeout_ms"
    return None


def _clamp_limits(
    max_candidates: int, max_rows: int, max_bytes: int
) -> tuple[int, int, int, int]:
    """把行数、候选数、正文预算折叠到彼此兼容的取值。

    返回 `(max_candidates, max_rows, max_bytes, max_text_chars)`。行数上限受两个约束：
    调用方给的 `max_rows` 与暂存层硬上限，以及**每条记录 12,288 B 固定开销**
    （`session_stage.PER_RECORD_FIXED_OVERHEAD_BYTES`）——预算装不下那么多条时，行数必须先降，
    否则取到一半才在暂存层整批丢弃（`BYTE_LIMIT_EXCEEDED`），白读一遍。正文总字符上限同理
    按「utf-8 每字符至多 4 字节」折算：`(max_bytes − 行数 × 12,288) // 4`。
    """
    max_candidates = min(max_candidates, MAX_CANDIDATES_HARD_LIMIT)
    max_rows = min(max_rows, MAX_ROWS_PER_SESSION)
    max_bytes = min(max_bytes, MAX_STAGE_BYTES_HARD_LIMIT)
    max_rows = min(max_rows, max_candidates)
    # 预算能容纳的最大条数（含正文为 0 的极限形状）。
    affordable = max_bytes // PER_RECORD_FIXED_OVERHEAD_BYTES
    affordable = max(affordable, 1)
    max_rows = min(max_rows, affordable)
    max_candidates = max(max_candidates, max_rows)
    body = max_bytes - max_rows * PER_RECORD_FIXED_OVERHEAD_BYTES
    max_text_chars = max(1, body // 4)
    max_text_chars = min(max_text_chars, MAX_ROW_TEXT_TOTAL_CHARS)
    return max_candidates, max_rows, max_bytes, max_text_chars
