"""单会话候选结果的内存暂存边界（DES-API-01「会话结果发布边界」）。

依据 2026-10-28 经用户确认的那一条边界：按行流式读取单个会话时，只在内存中暂存**有数量
上限和体积总量上限**的候选结果，不提前向 MCP 客户端输出正文；该会话完整读取后，须核对
会话身份、项目归属与本地配置授权，再发布通过过滤和脱敏的结果。身份或项目冲突、归属无法
确认、流被提前中断或取消、候选缓冲触限导致无法完成核对时，丢弃该会话候选并标记不完整。
候选正文不写入日志、持久索引或临时文件；逐会话处理，避免累积无界内存。

本增量（仅暂存与核对判据）的实现取向：

- 逐会话一个实例：调用方为每个会话新建 `SessionCandidateStage`，`finish()` 后该实例关闭，
  不再接受候选。跨来源的 `coverage` 汇总与分页截断由协调层（`file_search.py` 及其后续多来源
  协调）负责，本层只交单流结论。
- **本模块不提供任何返回正文的出口**：既没有发布通道，也没有返回候选列表的
  `StageOutcome` 字段。这是刻意为之——正文发布必须另有遮蔽出口（`publication.py` 只交
  脱敏后的片段）与两道授权轴（`policy.py`），本层的核对通过只登记可自证的完整性事实，
  不构成本模块可直接发布正文的理由，因此不预留可被误用的接口。
- `finish()` 无论核对结果如何都清空候选，报错路径上也不留下候选。理由：既然本增量无人可
  发布正文，未脱敏的原文在核对完成后继续驻留内存只有坏处。日后实现脱敏层时，若需要跨
  `finish()` 保留候选，必须同时把保留期与脱敏产出绑定，并重新审视这里清空带来的安全收益。
- `finish()` 的结论是该会话的最终判定：核对点之后的提交只累计整数计数，不回写原因码，
  否则一次成功的核对会被后续误用改判成别的原因。
- **完整性参数缺失或类型错误按「不完整」收尾，不因报错而跳过清理**：`finish(stream_complete=...)`
  只接受真正的 `bool`。缺省值是一个「未表态」哨兵（区别于 `False`）：调用方未表态、或传非布尔
  真值（`1`、非空集合等）时，本模块先把该会话整体丢弃（清空候选、计入 `dropped_count`、抹去
  由记录建立的身份与归属证据、关闭并记下不完整结论），再抛 `TypeError`；若读流阶段已报出更具体
  的原因（触限、冲突、取消），收尾沿用那个原因码而不是拿 `stream_incomplete` 顶掉它。收尾在前、
  报错在后，两头都不让步：既不让不受控的表态替调用方拍成「完整」，也不让一次 API 误用把原文留在
  内存里并让实例停在「还能继续核对」的状态。误用抛错后 `summary()` 即为不完整状态；用合法参数再
  调一次返回同一个已记录的不完整结论，不得被改判。
- **证据独立性判据**（本增量可自证的最强口径）：会话身份只有在「调用方断言值」与「至少一条记录
  内可比对标识」同时存在且一致时才算核实；单独一句调用方断言不算核实，多条记录重复同一个标识
  也不算核实——它们同出一个来源，来源内自我重复不构成第二份证据。项目归属同理：只有
  `TRUSTED_HEADER_CWD` 记录可确立归属，`CALLER_ASSERTED` 只参与一致性比对（值不同即冲突丢弃），
  永不单独把归属标成已确立；且**整批每条**候选都必须带可比对的归属值，任何一条给不出即整批按
  项目无法归属处理，不用「其余候选可归属」冒充整批可归属。两者都仍不含授权语义。
- 授权判定属于策略层：本模块**不做授权决定**，`StageOutcome` 只报告「本模块可自证的核对
  项」与固定原因码，不输出也不暗示「已授权」。来源内元数据（头部 `cwd`、会话标识）在这里
  是**归属一致性证据**，不能替代授权判断。

安全限制（DES-SEC-01、DES-ARCH-02）：只依赖标准库与本包的 `models`；不导入 MCP SDK，不打开
文件，不做发现、不联网、不写日志、不持久化。丢弃与关闭立即清空对记录的引用。对外自省出口
只有 `summary()` 与 `StageOutcome.as_public_dict()`，其键与本模块自有取值全部是固定字面量与
整数：不含正文、不含会话标识/项目/来源原值、不含路径与位置串，可直接用于日志与不完整覆盖
信息的 reason 拼装（与 `ParseStats.as_public_dict()` 同一约束）。因此本模块不持有任何由正文
派生的数据（含归一化副本与散列）：重复正文按重复计字节。

计量口径：数量按**已接受的候选条数**计；体积按一条候选**将被整条保留的全部内容**计，不只是
`text`：正文按其 UTF-8 字节数精确计，其余保留字段（`source`/`session_id`/`role`/`executor`/
`project` 字符串、`location` 与其规范标签、`timestamp`、两个质量枚举、`issues` 容器及其元素）
按 `PER_RECORD_FIXED_OVERHEAD_BYTES` 的固定开销计——那是这些字段**通过形态校验后**按各自上限
推得的最坏量级扣账额度（每个被接受的候选都是「固定开销 + 正文 UTF-8 字节」，所以总量随
**保留条数**而非编码次数增长，不拿「整段正文实际字节 ÷ 条数」冒充字段开销），因此校验必须先于
计量。只统计被接受的候选。上限只约束**本模块自己保存**的内容：调用方若在暂存层之外另建候选
列表，那份内存不在本模块计量范围内，须由调用方自己的预算层约束（现有协调层用的是同口径的
候选数/字节上限，见 `session_stage` 模块文档与 `file_search.py`）。

这套字节数全是**预算扣账**（一条候选按口径该从 `max_bytes` 里扣多少），不是进程实际占用的上界：
扣账额度只在下列字段边界成立时才估得准，能拦住单条无界占用的是 `MAX_STAGED_*` 这些边界本身，
两者不能互相顶替；对象头、分配器对齐、`str` 内部表示与调用方另建的副本都不在这笔账的约束
范围内（口径详见该常量注释）。

保留字段的类型与长度边界（不把「非正文字段」当成天然有界）：`isinstance(record, StandardRecord)`
只保证字段集合存在，不保证字段形态——数据类不在运行时校验类型，`source`/`issues`/`project`
等可以是任意对象，`issues` 可以任意长，字符串字段可以携带整段正文。本模块**整条保留**记录
（日后脱敏层要拿它产出片段，不能凭一个被删改过的副本），因此一条记录的每个保留字段都必须在
类型与长度两项上通过固定边界（`MAX_STAGED_ID_STR_CHARS`、`MAX_STAGED_PROJECT_STR_CHARS`、
`MAX_STAGED_ISSUES`，以及 `location`/`timestamp`/质量枚举的具体类型要求）。`issues` 只接受**元素均为
`IssueCode` 成员的字面 `tuple`**（或 `None`）：本模块整条保留它，而 `list`/`set`/`frozenset` 入队后仍能被
`append`/`add` 变大，已按 64 个槽位扣下的预算就不再是预算；元素只收枚举成员（共享单例），容器
开销就是槽位数 × 指针宽。任一项不过即整条不接受，并**沿用同一套丢弃语义**：该会话已暂存的全部
候选一并丢弃、计 `dropped_count`、抹去记录侧身份与归属证据、记固定原因
`staged_record_unbounded`。三条红线：**不截断保留**（前缀仍可能是可辨认的原值片段）、
**不部分保留**（不从 `issues` 里删掉越界元素、不把 `location` 换成替身——那会让后续核对建立在
被本模块改写过、且与解析侧不再一致的证据上）、**不越界入队**。

单条正文不需要一个单独的长度常量：它的可保留上限由计量不等式 `text_utf8_bytes ≤ max_bytes -
staged_bytes - PER_RECORD_FIXED_OVERHEAD_BYTES` 决定（构造时 `max_bytes` 已按
`MAX_STAGE_BYTES_HARD_LIMIT` 钳制）：一条超预算的正文必在入队**之前**被体积上限挡在门外，
永远不会有「存下了一段超预算正文」的状态。预算不够时**连一次编码也不做**（见下方计量口径）。

UTF-8 计量的内存口径：纯 ASCII 用 `len()`（其 UTF-8 字节数等于码点数，无需编码）；其它正文
**分块编码累加**，每块最多 `UTF8_METER_CHUNK_ITEMS` 个码点（CPython 的 `str` 以码点为索引单位，
一个增补平面字符就是一个码点，不会在块边界被拆成孤立代理项）。一个码点最多占 4 字节（`str` 按
内容最大宽度取 1/2/4 字节每码点，UTF-8 对星面字符也产出 4 字节序列），所以一次只存在的「一块
码点切片 + 它的编码副本」两份临时对象各 ≤ `UTF8_METER_CHUNK_ITEMS × 4` = 4 KiB、计量瞬时峰值约
8 KiB，与正文总长无关；并在累计值越过**剩余预算**时立即停止，不再像 `len(text.encode("utf-8"))`
那样，为了回答一句「有没有超限」先完整复制一份与正文同量级的编码结果（一条 256 KiB 字符的
中文正文会被瞬时再造约 768 KiB）。代价是确实要入队的非 ASCII 正文多挨几次线性拷贝；分块**块数**
由剩余预算封顶（累计越过预算即停），因此临时分配与编码次数都不可出现正文量级的整段分配。计量
还有一道零成本前置短路：单个可编码码点最少占 1 字节，所以码点数是 UTF-8 字节数的下界，
`len(text)` 已超剩余预算的正文直接判触上限，不进入任何扫描/编码分支。

正文无法安全计量（`text` 非字面字符串，或分块编码抛 `UnicodeEncodeError`，如孤立代理项）时
按**整批丢弃**处理并记固定原因 `candidate_text_unmeterable`：编码异常的消息里带着该字符串的
片段，一律在本模块内吞掉，不向外传播、不回显；无法计量就意味着这条候选的真实体积未知，未知
体积的候选不得留在有界缓冲里。

一致性断言只由**真正进入缓冲的记录**建立：字段形态与来源检查之后先做条数与体积计量，再做身份
与项目比对，因此一条最终没能保存的记录（字段越界、触限、正文不可计量）不会留下会话身份或项目
归属断言，避免「凭一条已被丢弃的候选宣称身份可核实」。反向同样成立：**丢弃即清空由记录建立的证据**——
`_discard()` 除候选与字节数外，一并清掉记录侧身份键与两个项目归属键（头部级与调用方给定级），
因此任何一次整体丢弃之后，`summary()` 不可能再凭已消失的候选报出
`identity_established`/`project_established` 为真。构造时传入的会话标识断言是调用方自己的陈述，
不由候选派生，丢弃抹不掉它——但它永远只能算一路证据，单独存在时两项自省均为假。

触限与丢弃的语义：任一上限触达（字段形态越界、保留总量触 `max_bytes`、条数触
`max_candidates`）即丢弃**该会话已暂存的全部**候选（而非「装不下的那条丢掉、其余留下」）。
留下部分候选会让核对失去意义——会话不再完整，而规范只允许完整读取后核对发布。
同理，来源/身份/项目冲突一旦出现在冲突前的候选也不再可信，整体丢弃。被丢弃的条数作为整数
记在 `dropped_count`，供覆盖信息区分「该会话本无候选」与「候选已被丢弃」。
字段越界与触限同构，因为它同样是「这条候选本模块装不下也不改存」：不拿它入队、不拿它当证据，
也不拿部分保留的整批冒充完整会话。
`finish()` 判为不完整时同样按丢弃计数（含核对点前已暂存的全部候选）：不完整就没有「正常清空」
这回事，此时 `StageOutcome.candidate_count`/`staged_bytes` 为 0，数量只体现在 `dropped_count`。
只有核对通过后的清空不计入 `dropped_count`。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from .models import (
    STREAM_LABEL_MAX_CHARS,
    IssueCode,
    ProjectQuality,
    SourceLocation,
    StandardRecord,
    TimeQuality,
)

__all__ = [
    "MAX_CANDIDATES_HARD_LIMIT",
    "MAX_CANDIDATES_PER_SESSION",
    "MAX_SESSION_KEY_CHARS",
    "MAX_STAGE_BYTES_HARD_LIMIT",
    "MAX_STAGE_BYTES_PER_SESSION",
    "MAX_STAGED_ID_STR_CHARS",
    "MAX_STAGED_INTEGER_MAGNITUDE",
    "MAX_STAGED_ISSUES",
    "MAX_STAGED_PROJECT_STR_CHARS",
    "PER_RECORD_FIXED_OVERHEAD_BYTES",
    "SessionCandidateStage",
    "StageDiscardReason",
    "StageOutcome",
    "UTF8_METER_CHUNK_ITEMS",
]

#: 单会话候选条数默认上限。逐条读一整个会话时，几十条候选已够覆盖一次问答的上下文；上限
#: 的意义是让「单会话峰值内存」可预算，不是「够不够用」。
MAX_CANDIDATES_PER_SESSION = 32

#: 单会话保留总量默认上限（字节，**扣账口径**：每条固定字段扣账额度 + 正文 UTF-8 字节）。与条数
#: 上限同时生效：中文正文单条可达数千字节，只靠条数上限无法约束峰值。
MAX_STAGE_BYTES_PER_SESSION = 256 * 1024

#: 构造参数只能收紧、不能放松到的硬上限：防止调用方把上限当配置项放大成无界缓冲。
MAX_CANDIDATES_HARD_LIMIT = 100
MAX_STAGE_BYTES_HARD_LIMIT = 2 * 1024 * 1024

#: 会话标识/来源/项目等一致性比较键的长度上限：超长值一律不作为断言值保存（不截断保留
#: 前缀，前缀仍可能是可辨认的原值片段），改记为「断言不可用」。
MAX_SESSION_KEY_CHARS = 256

# ---------- 被整条保留的记录字段的类型与长度边界 ----------

#: `source`/`session_id`/`role`/`executor` 的可保留长度上限（字符）：与 `MAX_SESSION_KEY_CHARS`
#: 同值——超过它本来就不会被本模块当作可比对键（`_comparable_key` 判不可用），留着只会白占内存。
#: **解析侧产出的这些值都在此之内**（会话标识 256、角色/来源是短 ASCII 固定串），越界即说明
#: 这条记录没有经过解析侧的有界处理，按整条不可接受处理，不做前缀截断保留。
MAX_STAGED_ID_STR_CHARS = 256

#: `issues` 容器可保留的元素个数上限。容器形态只收**字面 `tuple`**（见
#: `_issues_within_stored_bounds`），因此这里卡的是元组长度：`list`/`set`/`frozenset` 在入队后仍能被
#: 调用方 `append`/`add` 变大，一旦接受它们，按长度扣下的预算就不再成立。取值口径是「解析侧单条
#: 记录能汇出的最坏元素数 + 余量」：`sources/pi.py` 一条记录最多带 1 个标识问题 + 1 个时间问题 +
#: 1 个归属问题 + 1 个 `content_block_limit_exceeded` + 每块一个 `text_block_truncated`（≤
#: `MAX_CONTENT_BLOCKS_PER_LINE` = 32），共 36 个；取 64 既能避开「全 32 块都被截断的正常记录被误判
#: 越界」，又不是无界。字面 `tuple` 的 64 个槽位约 568 字节（56 字节对象头 + 64 × 8 指针；枚举成员
#: 是共享单例，不按条计），已计入 `PER_RECORD_FIXED_OVERHEAD_BYTES` 的扣账口径。超过即该记录的
#: 质量集合异常，整条不接受（**不删掉多余元素后接受**）。
MAX_STAGED_ISSUES = 64

#: 项目值（`project`）的可保留长度上限：与解析侧对头部 cwd 与调用方断言值的上限**同值**
#: （`sources/pi.py:MAX_PROJECT_VALUE_CHARS` = 512）——本层不重做解析侧的字段校验（归属判据仍只看
#: 值的来源与一致性），两者同值使得「解析侧认为可用的项目值，本层都能整条保留」成立，而本层
#: 的扣账额度也只按这个上限估。
#: 与 `MAX_SESSION_KEY_CHARS`（256，`_comparable_key` 的比对键上限）的分工：长度落在 (256, 512]
#: 的项目值可以整条保留，但不能当可比对归属值，按 `project_unattributed` 整批处理。
MAX_STAGED_PROJECT_STR_CHARS = 512

#: 整数型保留字段（`location.line_no`/`location.ordinal`）的绝对值上限：Python 整数是变长的，
#: 一个 10^100000 量级的「行号」本身就是几十 KB 的内存，且不可能来自任何真实行流。取 10^18
#: （远超 `sources/pi.py:MAX_LINES_PER_STREAM` 与行内块序数的量级，不会误挡正常记录），既给整数
#: 一个真实的字节上界（≤ 8 字节量级），又不必对数据侧的合法大数造假阳性。
MAX_STAGED_INTEGER_MAGNITUDE = 10**18

#: 一条候选除正文之外的**预算扣账额度**（字节）：它回答的是「按本模块口径，一条候选该从
#: `max_bytes` 里扣多少」，不是「这条候选实际吃多少内存」——单条无界占用由 `MAX_STAGED_*` 各字段
#: 上限拦住，对象头、分配器对齐与调用方另建的副本都不在这笔扣账范围内。
#: 额度按字段上限的最坏量级推得：4 个短字符串字段（各 ≤256 码点）+ `project`（≤512 码点）+
#: `location.stream_label`（≤ 64 码点）共 1600 个码点，按 CPython 每码点最多 4 字节计为 6400 字节；
#: 再加 6 个 `str` 对象头、`StandardRecord`/`SourceLocation` 实例与属性字典、一个 64 槽 `issues`
#: 元组（约 568 字节）与一个 `datetime`（约 48 字节）约 1.5 KiB（两个质量枚举成员与 `UTC` 是共享
#: 单例，不按条计），最坏合计约 7.9 KiB；取 12 KiB 是给对齐与未逐项核算的字段留的保守余量。
#: 默认预算下的可容纳条数：256 KiB / 12 KiB ≈ 21 条，即一批**空正文**候选会在触到条数上限（32）
#: 之前先把字节预算扣完。这不改任何核对语义：条数与体积是两道独立约束（各自管「保留多少条」与
#: 「保留多少字节」），丢弃行为完全一致，原因码按先碰到的那道检查归因。硬上限组合（100 条 /
#: 2 MiB）下扣账合计 1.2 MiB < 2 MiB，不反客为主；12 KiB 也远小于默认预算，`max_bytes` 取默认
#: 值时单条候选总能装下。
PER_RECORD_FIXED_OVERHEAD_BYTES = 12 * 1024

#: UTF-8 分块计量的块大小（码点数）：一次只处理一块，块内同时存在两份临时对象——码点切片本身
#: 与它的编码副本。CPython 里一个码点最多占 4 字节（`str` 按内容最大宽度取 1/2/4 字节每码点，
#: UTF-8 编码对星面字符同样产出 4 字节序列），所以每份临时对象 ≤ `UTF8_METER_CHUNK_ITEMS × 4`
#: = 4 KiB、计量期间的瞬时峰值约 8 KiB，与正文总长无关。调大本常量只影响计量速度，不影响
#: 「临时分配有界」这条；这份峰值是计量开销，不代表正文本体的常驻占用。
UTF8_METER_CHUNK_ITEMS = 1024


class _Unstated:
    """`finish()` 完整性参数的「未表态」哨兵类型。

    必须是独立类型而不是 `None`/`False` 的复用：`False` 是调用方明确承认「没读完」，而
    「没表态」是一处 API 误用，需要先收尾（丢弃并关闭）再报错。做成默认值而不把参数写成必传，
    是为了让函数体能先跑起来完成清理：必传参数在 Python 里于进入函数体之前就抛错，清理根本
    无从执行，那正是「报错跳过清理」的成因。
    """

    __slots__ = ()


#: 完整性参数的默认值：只表示「调用方未表态」，不参与任何核对判定。
_NOT_STATED = _Unstated()

#: 记录内会话标识不可采信的标记（`issues` 中出现任一即该值只作参考，不作第二路身份证据）。
#: 用 `==` 逐个比对而非集合成员判定：`Enum.__hash__` 按成员**名**取哈希，数据侧纯字符串与
#: `StrEnum` 成员虽相等却不哈希相同，集合查法会漏掉不受控侧传来的字面值。
_IDENTITY_UNUSABLE_ISSUES: tuple[IssueCode, ...] = (
    IssueCode.SESSION_ID_UNVERIFIED,
    IssueCode.SESSION_ID_MISMATCH,
    IssueCode.HEADER_SESSION_ID_MISMATCH,
    IssueCode.MISSING_SESSION_ID,
)

#: 记录自身声明项目归属不可靠的标记（出现任一即该候选的归属不可确认，整批不得称已归属）。
_PROJECT_UNUSABLE_ISSUES: tuple[IssueCode, ...] = (
    IssueCode.UNKNOWN_PROJECT,
    IssueCode.PROJECT_UNVERIFIED,
    IssueCode.CONFLICTING_HEADER_CWD,
    IssueCode.INVALID_HEADER_CWD,
)


def _issues_flagged(record: StandardRecord, markers: tuple[IssueCode, ...]) -> bool:
    """记录的 `issues` 是否命中 `markers` 中任一项；形态不受控时一律按命中处理（保守）。

    `StandardRecord` 是数据类，不在运行时校验字段类型：`issues` 可能是列表、元组、字符串或
    任意对象，其元素也可能是数据侧字符串而非枚举成员。本函数不抛异常、不回显取值，只在
    「确认没命中」时返回 `False`；任何无法遍历/无法比对的形态都返回 `True`，即不采信该记录
    的对应证据。

    作为独立的语义门，它自身就具备兵不依赖形态门的作用：`add()` 里这道判据只跑在
    `_record_within_stored_bounds` 之后，能递到这里（即已通过形态门）的 `issues` 只会是 `None` 或
    元素均为 `IssueCode` 成员的字面 `tuple`（容器入队后不会再变大）。两道判据职责不同：形态门管
    「这条记录能不能整条保留」（预算），本函数管「它自报的质量标记是否让身份/归属证据不可采信」
    （语义），因此保留「标记不可读即不采信」的保守分支：形态门一旦放宽，不可采信的标记仍不会被
    误读成「无质量问题」。
    """
    issues = getattr(record, "issues", None)
    if not isinstance(issues, tuple):
        # None 即「无质量问题」；字符串/其它可迭代形态无法确定集合语义，不拿它当证据（保守）。
        return issues is not None
    for code in issues:
        try:
            matched = any(code == marker for marker in markers)
        except Exception:  # 元素自定义了 __eq__：不可信，按命中处理
            return True
        if matched:
            return True
    return False


class StageDiscardReason(StrEnum):
    """丢弃候选/判为不完整的固定原因：闭合集合，只含类别，不含原值、路径、正文。

    新增类别只能改本枚举，不得由调用方用数据侧字符串临时造键——这些值会进入对外覆盖信息
    的 reason 与日志。读流过程中判定的原因（字段越界、保留总量触限、正文不可计量、冲突、取消）
    与核对点判定的原因（流未完、身份不可核实、无项目归属）只是发现时点不同，结果一致：候选已
    丢弃且本增量不得发布。

    不拿一个原因码顶替另一个：`staged_record_unbounded`（保留字段本身不可预算）、
    `byte_limit_exceeded`（预算不够）、`candidate_text_unmeterable`（体积未知）是三种不同的失效，
    对调用方的诊断含义不同（前两者是“装不下”，最后一个是“这条候选的真实体积未知”），各自保留。
    """

    CANCELLED = "cancelled"  # 调用方取消该会话的读取
    STREAM_INCOMPLETE = "stream_incomplete"  # 流未读完即要求核对（提前中断）
    CANDIDATE_LIMIT_EXCEEDED = "candidate_limit_exceeded"  # 候选条数触上限
    BYTE_LIMIT_EXCEEDED = "byte_limit_exceeded"  # 保留总量（固定开销 + 正文 UTF-8）触上限
    SOURCE_CONFLICT = "source_conflict"  # 同一暂存内来源不一致，或来源值不可用
    SESSION_IDENTITY_CONFLICT = "session_identity_conflict"  # 会话标识证据冲突
    SESSION_ID_ASSERTION_INVALID = "session_id_assertion_invalid"  # 调用方断言的标识不可用（非字符串或超长）
    SESSION_ID_UNVERIFIED = "session_id_unverified"  # 未获得两路独立证据（调用方断言 + 记录内标识）并使其一致
    PROJECT_CONFLICT = "project_conflict"  # 可比对的项目归属值（头部或调用方给定）互相冲突
    PROJECT_UNATTRIBUTED = "project_unattributed"  # 有候选给不出可比对归属，或缺来源侧（头部）归属证据
    CANDIDATE_TEXT_UNMETERABLE = "candidate_text_unmeterable"  # 正文非字面字符串或无法按 UTF-8 计量
    STAGED_RECORD_UNBOUNDED = (
        "staged_record_unbounded"  # 保留字段/容器的类型或长度超出固定边界（整条不可接受）
    )


@dataclass(frozen=True)
class StageOutcome:
    """一次核对的结果：只含固定类别与整数，可安全进入日志与覆盖信息。

    `complete` 表示本模块可自证的核对项全部通过（流已读完、未触限、来源与会话身份一致且
    可自证、项目可归属）；它**不表示已授权**，也不表示可以发布正文。`publication_allowed`
    在本层恒为 `False`：阶段层不知道调用方事后是否还过了脱敏与硬顶，不替它们改判；保留这个
    字段是为了让调用方的「不可发布」判断
    显式化，而不是让它自行推断。`candidate_count` / `staged_bytes` 是核对点上的快照（`staged_bytes`
    是**保留字节**：每条固定字段扣账额度加正文 UTF-8 字节，与 `max_bytes` 同一口径）：**判为不完整
    时两者为 0**（那批候选已整体丢弃，报数会诱导出「还剩点东西可看」的联想），核对通过时才是
    核对前实际暂存的条数与字节数，此后候选已被清空；`dropped_count` 累计读流期间与核对点因丢弃
    而失去的候选，不完整那一整批全部记在这里。只有核对通过后的清空不计入 `dropped_count`。
    """

    complete: bool
    publication_allowed: bool
    reason: StageDiscardReason | None
    candidate_count: int
    staged_bytes: int
    dropped_count: int

    def as_public_dict(self) -> dict[str, object]:
        """整数与固定字符串的快照；键名固定，值不含任何会话侧原值。"""
        return {
            "complete": self.complete,
            "publication_allowed": self.publication_allowed,
            "reason": self.reason.value if self.reason else None,
            "candidate_count": self.candidate_count,
            "staged_bytes": self.staged_bytes,
            "dropped_count": self.dropped_count,
        }


def _utf8_size(text: str, *, ceiling: int | None = None) -> int:
    """正文的 UTF-8 字节数：纯 ASCII 走长度快路径，其它正文分块累加，不为计数复制整份编码结果。

    `ceiling` 是「调用方还剩多少预算」（已扣除本条固定字段开销）：累计字节一旦越过它就立即返回
    （返回值只用于判断 `size > room`，越限时精确值没有意义），于是超长正文的**扫描量与编码次数**由
    剩余预算封顶、不随正文长度增长；单次临时分配由块大小封顶（见 `UTF8_METER_CHUNK_ITEMS`）。预算
    已为负时调用方**不会进到这里**（一次编码也不做）。

    分块是按码点切的：CPython 的 `str` 以码点为索引单位，一个增补平面字符就是一个码点，不会在
    块边界被拆成孤立代理项，所以每块都能独立编码（一块最多 `UTF8_METER_CHUNK_ITEMS` 个码点、
    编码后 ≤ 4 KiB）。含孤立代理项等无法编码的字符时抛 `UnicodeEncodeError`（其消息含原文
    片段）。调用方必须捕获并转为固定原因，不得让异常或片段离开本模块。"""
    if text.isascii():
        # ASCII 的 UTF-8 编码逐码点一字节：长度即字节数，一次拷贝都不做。
        return len(text)
    total = 0
    length = len(text)
    for start in range(0, length, UTF8_METER_CHUNK_ITEMS):
        chunk = text[start : start + UTF8_METER_CHUNK_ITEMS]
        total += len(chunk.encode("utf-8"))
        if ceiling is not None and total > ceiling:
            return total
    return total


def _comparable_key(value: object) -> str | None:
    """把会话标识/来源/项目规范为可比较键；不可用取值一律降为 `None`（不保留前缀）。

    只接受非空字符串且长度 ≤ `MAX_SESSION_KEY_CHARS`。空串与超长值都判「不可用」：无法区分
    它是缺字段还是不受控输入，本模块不猜，只记 `*_invalid` / `*_unverified` / `*_conflict`。
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_SESSION_KEY_CHARS:
        return None
    return candidate


def _field_of(holder: object, name: str) -> object:
    """取对象字段，并故意降为 `object`：调用方的全部判据都是运行时形态判据。

    数据类不在运行时校验字段类型，调用方递进来的实例可以携带任何对象（类型注解只是注解）；
    先降级再逐项校验，避开“根据声明类型推断这些检查多余”的误判，也让校验顺序在本模块内可见。
    只读属性，不调用取值的任何方法。
    """
    return getattr(holder, name, None)


def _plain_str_within(value: object, limit: int) -> bool:
    """是否为**字面 `str`** 且长度 ≤ `limit`（排除带隐藏负载的 `str` 子类）。

    为什么不接受子类：本模块把整条记录留在手里，一个 `str` 子类实例可以随身带任意属性/占用（
    例如一个几 MB 的 `bytes` 字段），它的名字看上去只是个「短标识」，内存却不是。子类自己的
    `__len__`/`isascii()` 也可被覆写，长度判据会失去意义。解析侧产出的这些字段都是字面 `str`
    （`sources/pi.py` 的 `_as_text` 对取值做 `strip()`/切片，返回的就是字面串），因此这道约束
    不会误挡真实候选，只挡住绕过解析侧直接递进来的对象。
    """
    if not isinstance(value, str):
        return False
    if value.__class__ is not str:
        return False
    return len(value) <= limit


def _issues_within_stored_bounds(issues: object) -> bool:
    """`issues` 是否落在可保留的形态边界内：**只接受字面 `tuple`**（或 `None`），且元素
    均为 `IssueCode` 成员，个数 ≤ `MAX_STAGED_ISSUES`（不抛异常、不回显取值）。

    为什么只收字面 `tuple`（`issues.__class__ is tuple`）：本模块**整条保留**记录，`list`/`set`/
    `frozenset` 都是可变的——调用方入队后仍能 `append`/`add`，把已经按 64 个槽位扣下预算的容器
    变大，预算就不再是预算。`str` 被排除（会被逐字符遍历、集合语义无法确定）；`dict`/生成器/
    自定义迭代器同上（一次消费即变，留着等于留一个随时会变的证据）。`tuple` 子类同样排除：
    它可以覆写 `__len__`/`__iter__`/`__getitem__`，使长度判据与元素判据不成立，还能随身带属性。
    数据契约也是这么声明的：`StandardRecord.issues: tuple[IssueCode, ...] = ()`，`sources/pi.py`
    产出的就是字面 `tuple`（`tuple(record_issues)`），所以这道约束不会误挡真实候选。
    元素只收 `IssueCode` 成员：本模块对外只报固定类别（DES-SEC-01），一个长得像码的数据侧
    字符串既不可信也无法预算；枚举成员是共享单例，因此容器开销就是槽位数 × 指针宽，不随元素
    内容变化。超过即整条不接受（**不删元素后接受**）。
    """
    if issues is None:
        return True
    if not isinstance(issues, tuple) or issues.__class__ is not tuple:
        # `isinstance` 供类型窄化，`__class__` 真类判定排除可覆写 `__len__` 的 `tuple` 子类。
        return False
    if len(issues) > MAX_STAGED_ISSUES:
        return False
    return all(isinstance(code, IssueCode) for code in issues)


def _location_within_stored_bounds(location: object) -> bool:
    """`location` 是否是一个字段形态可预算的真 `SourceLocation`。

    必须是本包类而不是“长得像”的替身：`stream_label` 在构造时已过 `sanitize_stream_label`，
    因而只会是 `None` 或 ≤ `STREAM_LABEL_MAX_CHARS` 的字面 `str`（固定字符集）——本模块不重做
    一遍规范化，只校验这个不变量是否成立（不成立即说明对象是拼凑/事后改写的，不保留）。
    `line_no`/`ordinal` 要求字面 `int`（`bool` 排除）且绝对值 < `MAX_STAGED_INTEGER_MAGNITUDE`：
    Python 整数是变长的，不卡量级就等于开一个“用行号存大数”的无界口子。
    """
    if not isinstance(location, SourceLocation) or location.__class__ is not SourceLocation:
        return False
    if not _label_within_stored_bounds(_field_of(location, "stream_label")):
        return False
    return _bounded_index(_field_of(location, "line_no")) and _bounded_index(
        _field_of(location, "ordinal")
    )


def _label_within_stored_bounds(label: object) -> bool:
    """位置标签：`None` 或字面短 `str`（与 `sanitize_stream_label` 的产出一致）。"""
    if label is None:
        return True
    return _plain_str_within(label, STREAM_LABEL_MAX_CHARS)


def _bounded_index(value: object) -> bool:
    """行号/序数：字面 `int`（排除 `bool` 与带隐藏负载的 int 子类）且量级在固定界限内。"""
    if not isinstance(value, int) or value.__class__ is not int:
        return False
    return abs(value) < MAX_STAGED_INTEGER_MAGNITUDE


def _record_within_stored_bounds(record: StandardRecord) -> bool:
    """记录中**将被整条保留**的每个字段是否都有可预算的类型与长度（正文的可计量性另判）。

    判据是「形态」而不是「内容」：不比较值、不解释值、不规范化值，因此不会把一条真实候选因为
    本模块不认识的取值而误丢。任何一项不满足即整条不可接受——本模块不截断、不删元素、不替换
    字段，因为被改写过一条候选之后再拿它做身份/归属核对，核对的就不是解析侧产出的那条记录了。

    `text` 只在这里要求「是字面 `str`」：它的长度不靠另一个常量卡，而是由计量与体积预算共同决定
    ——可保留条件为 `正文 UTF-8 字节 ≤ max_bytes - 已占字节 - 本条固定扣账额度`，预算已被硬上限钳住，
    所以单条正文的可保留上限永远不超过 `MAX_STAGE_BYTES_HARD_LIMIT`。再叠一个常量只会变成一个
    永远顶不到的高水位。

    本函数不抛异常、不回显取值：任何“读不出来/比不了”的形态都当作越界处理（保守丢弃）。

    记录本身也要求字面 `StandardRecord`（不是它的子类）：子类可以加字段，而那些字段会随整条记录
    一起被保留，却不在上面任何一条预算之内（固定开销估的是本包声明的字段）。解析侧直接构造
    `StandardRecord`，`dataclasses.replace()` 也保持原类，所以这条不会误挡真实候选。非本包类型
    仍在 `add()` 里抛 `TypeError`（那是 API 误用，不是数据越界）。
    """
    if record.__class__ is not StandardRecord:
        return False
    if not _plain_str_within(_field_of(record, "source"), MAX_STAGED_ID_STR_CHARS):
        return False
    for name in ("session_id", "role", "executor"):
        value = _field_of(record, name)
        if value is None:
            continue
        if not _plain_str_within(value, MAX_STAGED_ID_STR_CHARS):
            return False
    project = _field_of(record, "project")
    if project is not None and not _plain_str_within(project, MAX_STAGED_PROJECT_STR_CHARS):
        return False
    # 正文必须是字面 `str`（长度不在此看：交给计量与预算）：计量信的是 `len`/`isascii`/`encode`
    # 的真实结果，一个带隐藏大附件或覆写了这些方法的 `str` 子类会让“按字节预算”变成一句空话。
    text = _field_of(record, "text")
    if not isinstance(text, str) or text.__class__ is not str:
        return False
    # 位置必须是真 `SourceLocation` 且字段形态可预算（标签与整数均有界）。
    if not _location_within_stored_bounds(_field_of(record, "location")):
        return False
    # 两个质量枚举必须是本包成员：数据侧字符串既无法预算它携带的内容，也会让 `sourced` 判据变成
    # “碰巧命中一个同名属性”，不拿它当证据。
    if not isinstance(_field_of(record, "project_quality"), ProjectQuality):
        return False
    if not isinstance(_field_of(record, "time_quality"), TimeQuality):
        return False
    # 时间同样要求字面 `datetime`（排除子类）：判据与上面的 `str` 子类一致——一个子类实例可以
    # 随身挂任意属性，固定开销就估不准。解析侧只产出字面 `datetime`（`normalize_timestamp` 走
    # `fromtimestamp`/`fromisoformat`，都是本类），所以这条不会误挡真实候选。`SourceLocation`/
    # `StandardRecord`/三个枚举同上：带成员的 `StrEnum` 在 Python 里不可被子类化，真类判定不花成本。
    timestamp = _field_of(record, "timestamp")
    if timestamp is None:
        pass
    elif not isinstance(timestamp, datetime) or timestamp.__class__ is not datetime:
        return False
    return _issues_within_stored_bounds(_field_of(record, "issues"))


class SessionCandidateStage:
    """单个会话的有限候选暂存：逐条 `add()`，读完后 `finish()` 核对并清空。

    用法（调用方为来源适配器或查询协调层）::

        stage = SessionCandidateStage(source="pi", session_id=header_session_id)
        for record in records:  # records 为来源侧逐行流
            stage.add(record)
        # read_reached_end：调用方自己持有的布尔量，只有读到流结尾才为 True，
        # 提前 break、抛异常或取消路径上保持 False（不传→先按不完整收尾再报错）。
        outcome = stage.finish(stream_complete=read_reached_end)

    `add()` 返回 `False` 表示该候选未被暂存（字段越界、上限触达、已丢弃或已关闭）；返回值不携带
    被拒记录的任何信息，需要原因时读 `summary()`。

    线程安全：不提供。一次流式读取应由单一所有者顺序驱动；跨线程共享实例需调用方自行
    串行化（与策略层/读取层的单一所有者所有权口径一致）。
    """

    __slots__ = (
        "_asserted_identity",
        "_candidates",
        "_closed",
        "_dropped_count",
        "_late_submission_count",
        "_max_bytes",
        "_max_candidates",
        "_outcome",
        "_project_asserted_key",
        "_project_header_key",
        "_reason",
        "_record_identity",
        "_session_id_invalid",
        "_source_key",
        "_staged_bytes",
    )

    def __init__(
        self,
        source: object,
        session_id: object = None,
        *,
        max_candidates: int = MAX_CANDIDATES_PER_SESSION,
        max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
    ) -> None:
        """`source`/`session_id` 由调用方给出（多为来源头部或已验证配置），只用于一致性比较。

        `session_id` 只是两路身份证据中的**一路**：单独一句断言不算核实（记录侧全程无可用标识时
        `finish()` 记 `SESSION_ID_UNVERIFIED`），它只能与记录内标识对拼才成立；不默认「同源即同一
        会话」，也不拿它给记录内标识兼底。传了但不可用（非字符串、空串、超长）时记
        `SESSION_ID_ASSERTION_INVALID`。

        `max_bytes` 是**保留总量**预算，不只是正文：每条被接受的候选按
        `PER_RECORD_FIXED_OVERHEAD_BYTES + 正文 UTF-8 字节` 扣账。因此单条正文实际可保留的上限是
        `max_bytes - 已占预算 - 本条固定开销`，预算越往后越窄（预算本身仍只能被收紧到
        `MAX_STAGE_BYTES_HARD_LIMIT` 以下，不得放松）。固定开销按字段上限的最坏量级核定（默认 12 KiB），
        默认预算下约可容 21 条空正文候选，即一批极短正文的候选会先碰体积上限、再碰条数上限。

        一个诚实的推论：`max_bytes` 小于 `PER_RECORD_FIXED_OVERHEAD_BYTES` 时本模块**一条候选也存不
        下**（连字段本身的扣账额度都不足），第一条就被整批丢弃并记 `byte_limit_exceeded`。这不是报错
        路径：预算就是保留总量的硬约束，不把“装不下”推平成“能装但正文为空”。调用方要存真实
        候选，至少得给出一条记录的开销。
        """
        if not isinstance(max_candidates, int) or isinstance(max_candidates, bool):
            raise TypeError("max_candidates must be an int")
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
            raise TypeError("max_bytes must be an int")
        if max_candidates < 1 or max_bytes < 1:
            raise ValueError("candidate and byte limits must be positive")
        # 只能收紧：超出硬上限直接钳制，不抛错，避免调用方用超大参数绕过有界性。
        self._max_candidates = min(max_candidates, MAX_CANDIDATES_HARD_LIMIT)
        self._max_bytes = min(max_bytes, MAX_STAGE_BYTES_HARD_LIMIT)
        self._source_key = _comparable_key(source)
        asserted = _comparable_key(session_id)
        self._session_id_invalid = session_id is not None and asserted is None
        # 两路身份证据分开保存：调用方断言与记录内标识，二者缺一即不算核实。
        self._asserted_identity = asserted
        self._record_identity: str | None = None
        # 项目归属分两路：头部 cwd 证据能确立归属；调用方给定的值（本层只能来自候选的
        # CALLER_ASSERTED）只作冲突比对证据，永不单独算已归属。
        self._project_header_key: str | None = None
        self._project_asserted_key: str | None = None
        self._candidates: list[StandardRecord] = []
        self._staged_bytes = 0
        self._dropped_count = 0
        self._late_submission_count = 0
        self._reason: StageDiscardReason | None = None
        self._outcome: StageOutcome | None = None
        self._closed = False

    @property
    def max_candidates(self) -> int:
        """实际生效的条数上限（已按硬上限钳制）。"""
        return self._max_candidates

    @property
    def max_bytes(self) -> int:
        """实际生效的保留总量上限（字节，按含每条固定字段扣账额度的同一口径，已按硬上限钳制）。"""
        return self._max_bytes

    @property
    def candidate_count(self) -> int:
        """当前已暂存的候选条数（丢弃或核对后为 0）。"""
        return len(self._candidates)

    @property
    def staged_bytes(self) -> int:
        """当前已暂存候选占用的保留字节数（正文 UTF-8 + 每条固定字段扣账额度），丢弃或核对后为 0。"""
        return self._staged_bytes

    @property
    def dropped_count(self) -> int:
        """因丢弃而失去的候选条数（含触发丢弃的那一条与不完整核对点上的全部暂存候选）。

        只有核对通过后的清空不属于「丢弃」，其数量见 `StageOutcome.candidate_count`。
        """
        return self._dropped_count

    @property
    def late_submission_count(self) -> int:
        """核对点之后被拒绝的提交次数；纯计数，不参与核对结论。"""
        return self._late_submission_count

    @property
    def discarded(self) -> bool:
        """候选是否已被整体丢弃或核对判为不完整（此后不再恢复暂存）。"""
        return self._reason is not None

    @property
    def discard_reason(self) -> StageDiscardReason | None:
        """当前固定原因码；未发生丢弃/拒绝时为 `None`。"""
        return self._reason

    @property
    def closed(self) -> bool:
        """是否已 `finish()`；关闭后 `add()` 一律拒绝。"""
        return self._closed

    def add(self, record: object) -> bool:
        """暂存一条候选，返回是否被保存。所有拒绝路径都不回显被拒记录的内容。

        检查顺序：类型 → 已关闭/已丢弃 → 字段形态与容器边界 → 来源一致性 → 条数上限
        → 剩余体积预算 → 正文计量 → 会话身份一致性 → 本条候选的项目可归属与冲突 → 入队。字段形态
        校验排在来源比对与一切计量之前（理由见下方），所以本函数对尚未通过形态校验的对象只读属性、
        不调用任何可被覆写的方法。身份与项目按「先出现的值为准，后续不同即冲突」判定；冲突时
        整体丢弃，因为部分候选已不可信，留着只会诱导出「按不完整结果回答」。字段越界、两条上限与
        不可计量同样整体丢弃，且一律排在一致性断言之前：
        一条最终没能保存的记录不得留下身份或归属断言，否则会出现「凭已丢弃的候选宣称身份可核实」。
        已关闭/已丢弃两道护栏仍在字段校验之前：越界记录在核对点之后只计入迟到提交次数，不得替
        已定的结论改判原因码。

        为什么条数上限在体积预算之前判（两道都是零成本整数比较，顺序只影响原因码的归谁）：
        当一条候选同时越过两条上限时（`max_candidates` 已到且扣完本条开销后剩余预算不足），先判
        条数才能报出可用诊断（“条数到了”）；反过来先报体积上限会把一次正常的条数触限说成“字节
        不够”，而调用方看到的 `staged_bytes` 并没多少正文。另一头也成立：因为体积口径含每条扣账
        开销，一批**零正文/极短正文**的候选会在触到条数上限之前先把字节预算扣完（默认 256 KiB /
        12 KiB ≈ 21 条），那一次报 `byte_limit_exceeded` 同样准确。两者的丢弃行为完全一致，且都在
        计量与任何编码之前。

        字段形态校验为什么在计量**之前**：`PER_RECORD_FIXED_OVERHEAD_BYTES` 是按「字段通过校验后的
        各自上限」推得的扣账额度，先校验再计量，这笔账才估得准；否则一个带几 MB 附件的 `str` 子类可以
        让名义上几十个字节的字段报出预算内的数字，预算就只是看上去存在。它还在来源比对**之前**：
        `_comparable_key` 会对取值调 `strip()`，未经验型的对象不能先跑它的方法（子类的 `strip()`
        可抛异常、可造出一个与原文同量级的副本）。形态门因此也在语义门（来源、标识、归属）之前：
        一条字段越界的候选即使同时「来源不对」「标识对不上」或「归属不明」，原因码仍取
        `staged_record_unbounded`（`_discard()` 只保留首个原因码）——丢弃行为与计数与那几道完全
        一致，只归给最靠前的检查，不拿两个原因码互相顶替。日后若要区分「形状不对」与「值不对」，
        应先调检查顺序，而不是在此多开一条汇报通道。

        越界记录的处理与触限/不可计量完全同构：整批丢弃、记 `dropped_count`、抹去记录侧证据；
        不截断、不删元素、不替身字段，也不为它单独开口“只存正文”。

        体积预算为什么先于编码判：剩余预算 `max_bytes - staged_bytes - 单条扣账额度` 一旦已经不够，
        这条候选无论正文多大都装不下——此时直接按触体积上限丢弃，**一个字节也不编码**（既不为
        注定失败的候选做编码拷贝，也不得把它的正文归入任何计数）。预算够才逐块计量，累计越过剩余
        预算就收工：单次临时分配由块大小封顶、编码次数由剩余预算封顶，都不可出现正文量级的整段
        分配。计量还先用「码点数是 UTF-8 字节数的下界」这一事实做一次零扫描短路：光靠 `len()`
        就能否定预算的正文，连一次 `isascii()` 全长度扫描也不做（见 `_text_size`）。

        项目归属是**逐条硬性要求**：本条候选给不出可比对的归属值（质量不具来源可信度、自报归属
        不可靠、或 `project` 值不可用）即整批丢弃并记 `project_unattributed`，不让它入队——因为一条
        无主候选留在手里，后面的记录就会拿整批去凑一个并不存在的归属；而它本身没进缓冲，也就没
        能为任何一个项目留下归属断言。
        """
        if not isinstance(record, StandardRecord):
            raise TypeError("staged candidates must be StandardRecord instances")
        if self._closed:
            # 只计数，不回写 `_reason`：finish() 的结论是该会话的最终判定，不得被改判。因此
            # 字段形态校验只能排在两道状态护栏之后：一个核对已通过的实例不能因为核对点之后
            # 递进来一条越界记录就重新制造丢弃、把 `dropped_count` 与原因码改写成别的样子。
            self._late_submission_count += 1
            return False
        if self._reason is not None:
            # 已丢弃：保持零候选，后续记录不再计量也不重复记账（丢弃已在上游报出）。
            return False
        # 字段形态先于一切计量：按固定扣账额度记账的前提是本条记录的保留字段已在类型与长度上可预算。
        if not _record_within_stored_bounds(record):
            self._discard(StageDiscardReason.STAGED_RECORD_UNBOUNDED, lost=1)
            return False

        record_source = _comparable_key(record.source)
        if record_source is None or record_source != self._source_key:
            self._discard(StageDiscardReason.SOURCE_CONFLICT, lost=1)
            return False

        # 两道零成本上限先过：越界的候选一律不进入计量，也就一个字节也不编码。
        if len(self._candidates) + 1 > self._max_candidates:
            self._discard(StageDiscardReason.CANDIDATE_LIMIT_EXCEEDED, lost=1)
            return False
        # 装不下就不看正文：`room < 0` 时连一次编码临时副本也不分配。
        room = self._max_bytes - self._staged_bytes - PER_RECORD_FIXED_OVERHEAD_BYTES
        if room < 0:
            self._discard(StageDiscardReason.BYTE_LIMIT_EXCEEDED, lost=1)
            return False
        size = self._text_size(record, ceiling=room)
        if size is None:
            # 正文不可计量：异常消息含原文片段，只降为固定原因码，整体丢弃。
            self._discard(StageDiscardReason.CANDIDATE_TEXT_UNMETERABLE, lost=1)
            return False
        if size > room:
            self._discard(StageDiscardReason.BYTE_LIMIT_EXCEEDED, lost=1)
            return False

        record_session = _comparable_key(record.session_id)
        # 记录内标识自报不可核实（带 `session_id_unverified` 等同类标记）时只作参考，
        # 不得升格为第二路身份证据；同批多条记录的重复值同出一个来源，也不算独立证据。
        if record_session is not None and not _issues_flagged(record, _IDENTITY_UNUSABLE_ISSUES):
            if self._record_identity is None:
                self._record_identity = record_session
            elif self._record_identity != record_session:
                self._discard(StageDiscardReason.SESSION_IDENTITY_CONFLICT, lost=1)
                return False
            if self._asserted_identity is not None and self._asserted_identity != record_session:
                self._discard(StageDiscardReason.SESSION_IDENTITY_CONFLICT, lost=1)
                return False
        # 记录内无可用标识：不丢弃既有候选，也不默认与断言值一致，可核实性交由 finish 判定。

        quality = record.project_quality
        attributable = (
            isinstance(quality, ProjectQuality)
            and quality.sourced
            and not _issues_flagged(record, _PROJECT_UNUSABLE_ISSUES)
        )
        record_project = _comparable_key(record.project) if attributable else None
        if record_project is None:
            # 整批每一条都必须能确认归属：只要有一条给不出可比对值，这堆候选就不是一批
            # 「同项目候选」，整体作废而不是留着让后续核对去凑多数。
            self._discard(StageDiscardReason.PROJECT_UNATTRIBUTED, lost=1)
            return False
        for known in (self._project_header_key, self._project_asserted_key):
            if known is not None and known != record_project:
                self._discard(StageDiscardReason.PROJECT_CONFLICT, lost=1)
                return False
        # 两路归属分开记录：CALLER_ASSERTED 存进不确立归属的那一路，但仍参与上面的冲突比对，
        # 不会因为「不确立归属」就连同它见过的项目值一起静默消失。
        if quality is ProjectQuality.TRUSTED_HEADER_CWD:
            self._project_header_key = record_project
        else:
            self._project_asserted_key = record_project

        self._candidates.append(record)
        self._staged_bytes += PER_RECORD_FIXED_OVERHEAD_BYTES + size
        return True

    def cancel(self, reason: StageDiscardReason = StageDiscardReason.CANCELLED) -> None:
        """调用方中断或取消该会话读取：清空候选并记录固定原因。

        `reason` 只接受 `StageDiscardReason` 闭合类别（同 `ParseStats.note()` 的约束），不
        接受数据侧字符串。核对点之后调用无效果：结论已定，原因码不覆盖，也不重新制造丢弃。
        """
        if not isinstance(reason, StageDiscardReason):
            raise TypeError("cancel reason must be a StageDiscardReason category")
        if self._closed:
            return
        self._discard(reason)

    def finish(self, *, stream_complete: bool | _Unstated = _NOT_STATED) -> StageOutcome:
        """核对会话身份与项目归属，关闭暂存并清空候选。

        `stream_complete` 只接受真正的 `bool`：本模块无法自证流是否读完，非布尔的真值（`1`、
        非空集合等）不得替调用方拍成一句断言。**未表态与传错值都不走“报错即结束”的捷径**：
        本函数先把该会话整体丢弃（候选清空、计入 `dropped_count`、记录侧身份与归属证据一并
        抹去）、记下不完整结论并关闭实例，然后才抛 `TypeError`——误用不得把未脱敏原文留在
        内存里，也不得把实例留在“还能继续核对”的状态；事后 `summary()` 即为不完整快照，用
        合法参数再调一次只会拿到同一个已记录结论。误用前已有丢弃原因（触限、取消、冲突等）
        时，收尾沿用那个更具体的原因码——参数误用只是表层症状，不拿它顶掉真实诊断；此前没有
        丢弃缘由则记 `STREAM_INCOMPLETE`，未表态本身就不能当作“读完了”。
        `stream_complete=False` 表示调用方承认流未读完（提前中断）或无法确认，同样直接判不完
        整；完整性与身份、项目一样都是核对项，不是可省略的修饰。本模块不做授权判定、不做脱敏，
        因此核对通过只说明「本模块可自证的一致性成立」。重复调用返回首次的同一快照：候选已
        清空，若每次现算，第二次会报成「完整且零候选」，把一次已判定过的会话冒充成成功的空扫描。
        """
        misuse: StageDiscardReason | None = None
        if not isinstance(stream_complete, bool):
            # 缺参数（哨兵）或非布尔真值：调用方没给出可用表态，按不完整收尾后再报错。
            misuse = self._reason or StageDiscardReason.STREAM_INCOMPLETE
        if misuse is not None and self._outcome is None:
            # 结论未定才收尾：已有结论（含核对通过）的实例不被一次误用改判，只报错。
            self._discard(misuse)
            self._close(StageOutcome(
                complete=False,
                publication_allowed=False,
                reason=misuse,
                candidate_count=0,
                staged_bytes=0,
                dropped_count=self._dropped_count,
            ))
        if misuse is not None:
            raise TypeError("stream_complete must be an explicit bool")
        if self._outcome is not None:
            return self._outcome
        if not isinstance(stream_complete, bool):
            # 上面的误用分支已报错过；保留这道窄化护栏，不拿非布尔值去跑核对。
            raise TypeError("stream_complete must be an explicit bool")
        reason = self._reason if self._reason is not None else self._verify(stream_complete)
        snapshot_candidates = len(self._candidates)
        snapshot_bytes = self._staged_bytes
        if reason is not None:
            # 不完整即丢弃：核对点上的暂存候选全部转入丢弃计数，不保留部分候选。
            self._discard(reason)
            snapshot_candidates = 0
            snapshot_bytes = 0
        outcome = StageOutcome(
            complete=reason is None,
            publication_allowed=False,
            reason=reason,
            candidate_count=snapshot_candidates,
            staged_bytes=snapshot_bytes,
            dropped_count=self._dropped_count,
        )
        # 本增量无人可发布正文：核对完成后不让未脱敏原文继续驻留内存。
        self._candidates.clear()
        self._staged_bytes = 0
        self._reason = reason
        self._close(outcome)
        return outcome

    def summary(self) -> dict[str, object]:
        """公开安全快照：整数 + 本模块自有固定字面量，不含正文与任何会话侧原值。"""
        return {
            "candidate_count": len(self._candidates),
            "staged_bytes": self._staged_bytes,
            "dropped_count": self._dropped_count,
            "late_submission_count": self._late_submission_count,
            "max_candidates": self._max_candidates,
            "max_bytes": self._max_bytes,
            "discarded": self._reason is not None,
            "reason": self._reason.value if self._reason else None,
            "closed": self._closed,
            "identity_established": self._identity_verified(),
            "project_established": self._project_attributed(),
            "publication_allowed": False,
        }

    def _identity_verified(self) -> bool:
        """两路独立证据齐备且一致：调用方断言 + 至少一条记录内可比对标识。

        单独一句断言（`_record_identity is None`）不算核实；多条记录重复同一标识也不算核实
        ——它们同出一个来源，来源内自我重复不是第二份证据。丢弃已抹去记录侧键，因此丢弃后
        本判据必为假。
        """
        if self._session_id_invalid:
            return False
        if self._asserted_identity is None or self._record_identity is None:
            return False
        return self._asserted_identity == self._record_identity

    def _project_attributed(self) -> bool:
        """归属已确立仅当存在头部级证据（调用方给定的值只参与冲突比对，不单独算已归属）。"""
        return self._project_header_key is not None

    def _verify(self, stream_complete: bool) -> StageDiscardReason | None:
        """核对点判据：返回固定原因码；`None` 表示本模块可自证的项全部通过。

        宁保守不误认：无法在本接口自证的（缺一路身份证据、无头部级归属证据）一律判不完整，
        绝不因「调用方断言了一个项目/标识」就当已核实，`CALLER_ASSERTED` 在本层也不带授权语义。
        """
        if not stream_complete:
            return StageDiscardReason.STREAM_INCOMPLETE
        if self._session_id_invalid:
            return StageDiscardReason.SESSION_ID_ASSERTION_INVALID
        if not self._identity_verified():
            return StageDiscardReason.SESSION_ID_UNVERIFIED
        if not self._project_attributed():
            return StageDiscardReason.PROJECT_UNATTRIBUTED
        return None

    def _text_size(self, record: StandardRecord, *, ceiling: int) -> int | None:
        """正文的 UTF-8 字节数；无法按 UTF-8 计量时返回 `None`（调用方据此整批丢弃）。

        `ceiling` 是调用方给出的**剩余预算**（已扣除本条的固定字段开销）：分块计量一旦越过它就
        提前返回，所以超长大正文不会为了一个「够不够装」的判定而被完整编码一遍（临时副本上限见
        `UTF8_METER_CHUNK_ITEMS`）。返回值只在「与 `ceiling` 比较」这一用途上可信，不做精确字节汇报。

        码点数是 UTF-8 字节数的下界（每个可编码码点至少 1 字节），所以 `len(text) > ceiling` 时
        这条候选**无论如何装不下**：直接拿码点数当结论返回，**一个码点也不扫、一次也不编码**（连
        `isascii()` 的全长扫描都省了）。此时调用方记的是 `byte_limit_exceeded`：预算否定得比
        计量更早，即使这条正文里还埋着孤立代理项也不影响结论——它要么装不下，要么因不可计量而
        装不下，丢弃与计数两条路径完全一致，只是原因码取那个已被确定证伪的门（预算）。这条短路对
        ASCII 正文不改变任何结果：ASCII 的字节数等于码点数。

        `UnicodeEncodeError`（如孤立代理项）的消息自带原文片段，在此就地吞掉：只降为 `None`
        交给调用方转为固定原因码，异常与片段都不得离开本模块。是否触体积上限不在此判定（上面的
        下界短路除外），两条丢弃原因（不可计量 / 触上限）因此不会互相顶替。
        """
        text = record.text
        if not isinstance(text, str):
            # 字段形态校验已在 `add()` 里把非字面 `str` 正文挡下；这道护栏保留，不拿它做计量。
            return None
        if len(text) > ceiling:
            return len(text)
        try:
            return _utf8_size(text, ceiling=ceiling)
        except UnicodeEncodeError:
            # 无法计量即未知体积：未知体积的候选不得留在一个自称有界的缓冲里，整批丢弃。
            return None

    def _discard(self, reason: StageDiscardReason, *, lost: int = 0) -> None:
        """整体丢弃：转入丢弃计数、清空引用与一致性证据，只保留首个原因码作为诊断依据。

        证据一同抹去是关键一步：候选都没了，凭它建立的身份与归属断言若还留着，`summary()`
        就会在丢弃之后继续报「身份/项目已建立」，那正是本模块要禁止的跳步。
        """
        self._dropped_count += len(self._candidates) + lost
        self._candidates.clear()
        self._staged_bytes = 0
        self._record_identity = None
        self._project_header_key = None
        self._project_asserted_key = None
        if self._reason is None:
            self._reason = reason

    def _close(self, outcome: StageOutcome) -> None:
        """关闭实例并留下最终结论：此后 `add()` 只计数，`finish()`/`cancel()` 不改变结论。"""
        self._closed = True
        self._outcome = outcome
