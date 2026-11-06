"""单会话「行流 → 解析 → 暂存核对」同步一次性管线（组合层，不新增判据）。

把 `sources/pi.py` 的 `PiLineParser` 与 `session_stage.py` 的 `SessionCandidateStage`
串成一条调用方直接可用的路径：喂进一个**调用方自己的行迭代器**，同步消费到底，产出
一份只含**固定类别与整数**的安全统计。本模块只做顺序编排与收尾时机控制，不重定义任何
核对判据：解析质量归 `ParseStats`，身份/归属核对归 `SessionCandidateStage`。
除统计入口外，本模块另提供一个**有界脱敏片段出口** `run_pi_file_snippets`（收集与预算本体在
`publication.py`）：它与统计入口共用同一条授权与核对路径，只在末端多一个逐记录遮蔽与
一次性释放；除它的 `snippets` 字段（只含遮蔽后正文）外，本模块的任何出口都不携带会话侧文本。

服务：DES-ADAPTER-01（pi 行）、DES-API-01（会话结果发布边界）、DES-SEC-01（打开后句柄复核，
经 `safe_reader.authorize_read` 承担）。单文件查询由 `file_search.py` 编排；`server.py.search_sessions`
只在宿主显式绑定固定文件服务后委托，`main()` 默认不绑定、不读配置。

授权文件入口 `run_pi_file`（「存储授权」+「逐记录归属准入」与「读整流」的联动）
------------------------------------

- 判据来源：调用方**显式**传入 `SessionPolicy` 实例、`scope`、**单个**存储文件路径、**预先独立
  持有**的 `session_id`、可选 `cwd` 断言与有界预算；`source` 固定为 `pi`（`SOURCE_PI`）。本层不发现
  文件、不枚举目录、不配置根、不读配置/环境变量，也**绝不**从解析产物（`parser.header` /
  `parser.project` / 记录字段）回填 `session_id` 或 `cwd`——断言只在构造期进入各自的通道，与
  `run(lines)` 的「断言独立性」同一约束。
- 读取只有一个入口：`with authorize_read(policy, scope, SOURCE_PI, path, ...) as reader:`（打开前授权 +
  打开后句柄复核）。返回的 `AuthorizedLineReader` 本身就是 `Iterable[bytes]`，被**原样**交给
  本模块私有的共用运行入口 `_execute(reader, ..., eof_confirmed=...)` 消费（公开的 `run(lines)` 就是
  它的一个无确认器调用）；本层不包壳、不另造读取器、不按偏移二次取字节、不缓存正文，
  也不在 reader 之外 `open`。运行结束后在 `with` 内显式 `reader.close()` 再取 `outcome()`（`close()`
  幂等，`__exit__` 再关一次不重复计丢弃量）：这样对外报出的 `read` 才是「缓冲已归还」之后的读侧终态。
- 完整性合并发生在**核对之前**，不是核对之后的追补：文件模式把「读侧终态确认器」交给私有共用
  运行入口 `_execute()`，它只在迭代器声明耗尽、其余收尾条件都成立、**准备向暂存层请求
  `stream_complete=True` 之前**被调用一次，取值只来自同一个 `reader.outcome().complete`。确认器
  返回假值或自身抛异常都算未确认，于是这次运行走的是失败路径：`cancel(STREAM_INCOMPLETE)` +
  `finish(stream_complete=False)`，整批候选丢弃、字节清零、条数如实进 `dropped_count`。因此
  `PipelineOutcome.complete`/`reason` 与 `PiFileOutcome.complete`/`reason` 说的是同一件事，不存在
  「嵌套层已判成功、顶层再单独否决」的两种结论。之后 `reader.close()`、`reader.outcome()` 取到的
  仍是「缓冲已归还」之后的读侧终态，`PiFileOutcome.complete = pipeline.complete and read.complete
  and not parse["partial"]`（后两项在当前判据下已被 `pipeline.complete` 蕴含，保留它们只是不让本层
  的结论依赖上游收尾顺序的不变式，不新增判据、不做事后改数）。
  否决项是并集不是重述：reader 触限（`line_bytes_limit`/`total_bytes_limit`/`line_limit`）、提前终止
  （`closed_before_eof`）或读取失败（`handle_read_failed` 等使 EOF 未确立的出口）、以及解析侧
  `stats.partial` 为真，任一个都使 `complete` 为假；安全统计不会因此把未读全报成 EOF，也不会把
  那批没能核对的候选报成「核对通过并已正常清空」。
  两层原因各自保留（`ReadStop` 与 `IssueCode`/`StageDiscardReason` 不互相顶替），本层不做二次解释。
- 不把读取器的 `StopIteration` 当文件 EOF：它触限或预算用尽后同样以 `StopIteration` 收束，因此
  「迭代器不再吐行」这句话本身不足以支撑一次完整核对——这正是确认器排在 `stage.finish` 之前的原因。
  `pipeline.stream_exhausted` 仍**只**记录迭代器是否耗尽（确认器不改写它），文件是否读完只由
  `ReadOutcome.eof_reached`/`complete` 回答；两个字段并列保留，供调用方区分「迭代器读完」与「文件读完」。
  `run(lines)` 这条公开路径不接确认器（它无从知道底层流是否走到结尾），语义与判据一字未改。
- 读侧失败的原因粒度只到「不完整」（本轮接受的代价）：读取器在 `read()` 失败时抛 `SafeReadDenied`，
  该异常被 `_execute()` 按既有口径吞掉（消息可能含路径，不外传），因此合并结果里只能看到
  `read.complete=False` + `read.reason=closed_before_eof`，**不能**区分「读取失败」与「提前收束」；
  否决方向仍正确（都不会报 EOF），只是诊断粒度较粗，本层不为此新开异常通道。
- 拒绝路径只带固定码：入口的 `PolicyDenied`（策略层）与 `SafeReadDenied`（读取层）原样向调用方
  抛出（两者只含 `RefusalCode`/`ReadRefusalCode` 与固定文案），本层不把异常对象、路径、scope、
  来源或系统错误原文放进任何结果；读取中途的失败已被 `_execute()` 降为固定原因码不外传。授权失败
  发生在 `with` 建立之前，此刻还没有管线与候选，无需也不做额外收尾。`BaseException` 中断沿用
  `_execute()` 的「取消收尾 → 关闭迭代器 → 原样重抛」，`__exit__` 再幂等关闭一次句柄；确认器自己
  挨到中断时同走这条取向：先取消收尾清空候选，再原样重抛，不把回调的中断当成正常完成。
- 本轮起，`run_pi_file` 在存储授权之外多接两道策略判定：打开前 `authorize_query(scope,
  sources=(SOURCE_PI,), project=project_filter)`（查询轴：来源与项目收窄；拒绝原样抛
  `PolicyDenied`，此时还没有管线与候选），以及**逐记录**的归属准入 `authorize_attribution(scope,
  record.project, project=project_filter)`。准入只采信 `TRUSTED_HEADER_CWD` 的记录项目值：其余质量
  （含 `CALLER_ASSERTED`）不递交策略层、不做任何路径探测，当场按固定码 `attribution_unknown` 拒绝。
  任何一条记录被拒即停止拉取后续行，并走与失败路径同一条整批丢弃收尾（`cancel` +
  `finish(stream_complete=False)`），本层不为准入新增 `StageDiscardReason`；真实拒绝的粒度只以固定
  `RefusalCode` 记在 `PiFileOutcome.attribution_refusal`。`project_filter` 是**策略项目名**，与 `cwd`
  那条 **cwd 断言**分属两个通道：前者只进策略层，后者只进解析器，本层不互相转换。
  查询/搜索接线由 `file_search.py` 与 `session_context.py` 承担（单批 pi 文件查询与引用发放
  后的上下文读取）；Codex 及其余来源仍未接；`publication_allowed` 仍取自 `StageOutcome`
  且恒为 `False`；`list_sources` 仍为骨架。

有界脱敏片段出口 `run_pi_file_snippets`（本增量新增，复用同一条管线）
------------------------------------

- 定位：它**不是**第二条管线。参数与 `run_pi_file` 同一组（同一个 `SessionPolicy`、`scope`、
  **单个**文件 `path`、预先独立持有的 `session_id`、可选 `cwd`/`project_filter`、同一组读/阶段预算），
  打开前 `authorize_query`、逐记录 `authorize_attribution`、EOF 前置确认、暂存核对与合并完整性
  **逐字同一条实现**（都走 `_execute`）。本层不发现文件、不新建宽松判定、不把 `stage.complete` 当授权。
- 只多一个钩子 `capture`：它跑在 `stage.add()` **返回真之后**，所以对外片段的集合是「已暂存集合」
  的子集——被暂存层拒掉/丢弃的记录不可能变片段。判定顺序固定为
  准入 → 暂存 → 脱敏收集；收集器（`publication.SnippetCollector`）逐条调用
  `redaction.redact_text`，遮蔽层在**完整输入**上做完识别才截片，本层不另实现规则、不预先切片。
- 释放时机：片段只能由 `run_pi_file_snippets` 在 `reader.close()`、`reader.outcome()` 与合并
  `complete` 全部结算**之后**，用 `release(confirmed=合并 complete)` 一次性交出。只认字面 `True`；
  `release` 只被调用一次、只在这一处。因此不存在「先拿到片段再在上层否决」的窗口，也没有任何
  逐条 yield / 用户回调通道（`should_stop` 仍是唯一钩子，语义与统计入口一致）。
- 零片段是默认的对外形态：遮蔽拒绝、条数/总字符两条硬顶任一触限、记录形态不可用、收集环节
  意外失败 → 收集器立即清空已收集片段并在 `release()` 处交出空元组（`snippet_refusal` 记住首拒）；
  逐记录准入被拒、暂存丢弃、EOF 未确认、解析侧 `partial`、合并 `complete` 为假，以及
  `BaseException` 中断（`finally` 里把收集器整批清空后原样重抛）→ 拿不到字面 `True`，同样零片段。
  **片段预算不反向改写核对结果**：收集首拒只停掉遮蔽工（`_note_capture` 短路），行流与暂存集合仍与
  `run_pi_file` 逐字一致，所触限不造成 `complete`/`dropped_count` 的任何变化——它的后果只能就是零片段。
  收集环节逃出的**任何普通异常**在被吞之前都会先把收集器已收集的那批整批清空（`INTERNAL_FAILURE`）：
  追加/计数中途失败（如 `MemoryError`）不会把「已经收进去的前缀」当成成功放出来，异常被吞之后对外仍是
  零片段、`released=False`、`snippet_refusal=internal_failure`（`release()` 对已拒绝实例只交出空元组）。
  释放处同时把「本次捕获到过收集拒绝」并入 `confirmed`，收集失败不可能绕过释放判定。
  首拒只以固定 `PublicationRefusal` 记在 `PiFileSnippets.snippet_refusal`，与
  `attribution_refusal`、`reason`（`StageDiscardReason`）各自保留、不互相顶替。
- 有界与外泄面：条数默认 16（硬顶 32，只可收紧）、总字符代理预算默认 32 768（硬顶
  `32 × redaction.MAX_OUTPUT_CHARS`，只可收紧），预算按**遮蔽后**的字符数累加；每条至多
  `redaction.MAX_OUTPUT_CHARS` 字符。`PublishedSnippet` 只含遮蔽后正文、调用方给定的固定来源 ID
  （`SOURCE_PI`，不是 `record.source` 原值）与两个整数位置（`line_no`/`ordinal`）及两个遮蔽元数据；
  不回传路径、scope、会话标识、cwd、项目值、`role`/`executor` 自由取值与时间戳原值（角色是数据侧
  自由串、本层无可闭合取值域，因此不回传）；原文不另建缓存、不按文件重读。
- 与发布许可的区分：`publication_allowed` 仍恒为 `False`（阶段层不知道脱敏发生过，本层不替它改判）；
  `PiFileSnippets.released=True` 只说明「两轴授权 + 完整性 + 脱敏 + 两条硬顶」同时成立过，
  仍不是「可以对外提供服务」——MCP 仅在宿主显式绑定固定文件服务后返回协调器结果，片段文字仍属不可信历史内容，遮蔽层不承诺检出率。

断言独立性（`run` / `run_pi_file` / `run_pi_file_snippets` 共用的硬约束）：

- 会话标识与项目断言**只来自构造参数**（外部预先给定）：会话标识同时交给解析器与暂存层各用
  一次；项目只交给解析器（外部断言通道 + 冲突核对），**不**交给暂存层充当第二份归属证据。
  本模块**绝不**把解析产物（`parser.header.session_id` / `parser.project` /
  `parser.asserted_project` / 记录字段）复制成
  第二份断言再喂回去——那会把「同一来源的自我陈述」伪装成两路独立证据，直接击穿暂存层的
  证据独立性判据。因此解析器的属性对本模块只读不取，也不对外暴露解析器/暂存层实例。
  逐记录准入读的是**记录自报的归属证据**（`record.project` 只作为待审对象送进策略层，不进任何
  断言通道、不回填给解析器或暂存层），因此它不构成第二份断言。
- 同一断言值在两侧各自判长：解析侧按 `MAX_SESSION_ID_CHARS`/`MAX_PROJECT_VALUE_CHARS` 把超限
  值降为「未提供」，暂存侧按 `MAX_SESSION_KEY_CHARS` 判 `session_id_assertion_invalid`。两侧口径
  不同是**有意的保守分歧**（本层不合并、不做归一化中转），不会出现「一侧放行、另一侧冒充核实」。

完成判据（顺序即语义）：只有 ①调用方迭代器真正耗尽（**只取 `next()` 抛出的 `StopIteration`**，
循环体内解析/暂存/回调逃出的 `StopIteration` 不算读完，非 break 即非耗尽）、
②`parser.finish()` 已执行、③收尾后的 `stats.partial` 为假、④暂存层未在任何一条记录上判丢弃，
⑤（仅文件模式）同一个读取器的 `outcome().complete` 给出真值，五条同时成立，才以
`stage.finish(stream_complete=True)` 请求核对；核对本身仍可能被暂存层判为
不完整（身份只有一路证据、无头部级归属证据等），本模块不替它改判。`partial` 的读取一律排在
`parser.finish()` 之后：缺头部、项目不可确定这类流级问题只在收尾时登记，提前读会漏。

失败路径（一律 `stage.cancel(reason)` 后再 `stage.finish(stream_complete=False)`）：

- 迟发头部冲突、任何使 `stats.partial` 为真的原因码 → `stream_incomplete`（精确类别留在
  `PipelineOutcome.parse` 的 `issue_counts` 里，本模块不拿一个原因码顶替另一个：暂存层若已因
  触限/冲突/字段越界记下更具体的原因，`cancel` 不会覆盖首个原因码）。
- 读取过程中抛异常（含调用方迭代器自身失败、`should_stop` 回调失败）→ `stream_incomplete`；
  异常对象与消息**一律不保留、不外传**（消息可能携带路径或正文片段），只降为固定原因码。
- 调用方提前停止（`should_stop` 返回真值）→ `cancelled`。判据排在 `next()` **之前**，
  因此被停止的那一行根本没有被读走。
- 读侧终态确认器返回假值，或确认器自身抛异常（文件模式独有）→ `stream_incomplete`：与「没读到
  结尾」同一条路径，整批丢弃、`candidate_count`/`staged_bytes` 归零、条数进 `dropped_count`。
  确认器异常的消息可能含路径，就地吞掉、不外传、不另造诊断码。
- 调用方中断（`KeyboardInterrupt`/`GeneratorExit`/`SystemExit` 等 `BaseException`）→ 先按
  `cancelled` 收尾、再关闭迭代器归还资源、最后**原样重抛**：清理路径上的任何失败都就地吞掉，
  不得把这次中断改写成另一个异常（原始异常与 traceback 完整保留）。
- 解析器行数触限（`max_stream_lines_exceeded`）或暂存层已整体丢弃 → 立即停止拉取调用方行流
  （不做无意义的后续读取），流按未读完处理。
- 契约误用（把整个 `str`/`bytes` 当行流递进来，或递进一个 `iter()` 就失败的非可迭代对象）→
  先按上面的失败路径收尾关闭，再抛固定消息的 `TypeError`：收尾在前、报错在后（与
  `SessionCandidateStage.finish` 同一取向），误用既不会把候选留在内存里，也不会把实例停在
  「还能继续核对」的状态。`__iter__` 自己抛出的非 `TypeError`（那是一次失败，不是一处误用）
  按普通迭代失败降为不完整；固定消息经 `from None` 切断链，不拿不受控的原消息顶替结论。

所有未读完的出口（提前停止、异常、中断、触限、读侧终态未确认）都在 `_conclude()` 清空候选**之后**关闭由
`iter(lines)` 得到的那个迭代器本身（而不是 `lines`：列表等可迭代对象没有 `close()`，能归还资源的
只有它的迭代器）。`getattr(obj, "close")` 与 `close()` 两步同受保护；中断路径上连清理自身的
`BaseException` 一并吞掉，避免费把用户的原中断顶掉。

所有出口都没有服务发布通道：`PipelineOutcome` 与 `PiFileOutcome` 只含整数、布尔、固定枚举与本模块自有键，
不含正文、会话标识、项目值、路径或位置串（继承 `StageOutcome.as_public_dict()`、
`ParseStats.as_public_dict()` 与 `ReadOutcome.as_public_dict()` 的同一约束）。本模块自身不 `open` 任何路径、不发现会话、不联网、不写日志；唯一的文件读取通道是
`safe_reader.authorize_read`（打开前授权 + 打开后句柄复核），且只被私有 `_run_pi_file_pipeline`
调用（公开 `run_pi_file`、`run_pi_file_snippets` 与包内 `file_search.py` 协调器复用该入口）；
`PiSessionPipeline.run(lines)` 路径本身不接触文件系统。唯一能携带会话侧文本的出口是
`PiFileSnippets.snippets`（只含遮蔽后正文），它只在上述两轴与完整性全部结算之后一次性返回。

已知保守限制（本增量明确不修）：

- **项目证据通道的分工**：解析侧已不再把外部 `project` 断言放在头部 `cwd` 之上（旧行为：
  `CALLER_ASSERTED` 永久盖住头部值，导致带项目断言的运行永远 `project_unattributed`）。
  现在可信头部 `cwd` 产 `TRUSTED_HEADER_CWD`（暂存层可据此确立归属），无可信头部时断言以
  `CALLER_ASSERTED` 产出（暂存层只当冲突比对证据），两者字面不一致则解析侧自行降为
  `unknown` 并由整流 `partial` 否决。本模块不因此改变任何取递方式：仍**不**把
  `parser.project` / `parser.asserted_project` / `parser.header` 回喂给暂存层，否则就把来源侧
  产物伪装成调用方断言。归属不唯一的字面比对只在解析侧完成（未做路径规范化）；真实路径
  与策略项目映射的核对已接入本层的**逐记录准入**（只有 `TRUSTED_HEADER_CWD` 的记录项目值送
  `policy.authorize_attribution`，见上）；`run(lines)` 这条公开路径仍不判任何授权。
- 授权与发布是两件事：`run_pi_file` 里的 `authorize_read` 完成**存储轴**授权（策略层两次
  `authorize_store` + 句柄侧复核），逐记录准入完成**归属轴**判定（`authorize_attribution`），
  `complete=True` 表示「两条授权轴 + 暂存层可自证的核对项 + 两侧完整性合并」全部通过，仍
  **不表示**可以对外提供服务（`publication_allowed` 恒为 `False`；MCP 仅在宿主显式绑定固定文件服务后返回脱敏查询结果）。
  `run_pi_file_snippets` 在此之上只多做了「逐条完整遮蔽 + 两条硬顶 + 一次性释放」：
  它交出的已是遮蔽后的片段，不是未脱敏正文的发布通道。
  准入拒绝只以固定 `RefusalCode` 外传，异常对象与原值不出本层。`run(lines)` 路径完全不判授权
  （`admit` 只由 `run_pi_file` 递进私有的 `_execute`，`capture` 只由 `run_pi_file_snippets` 递进）。
- 逐会话一个实例、一次性 `run()`：重复调用抛 `RuntimeError`；不提供跨线程共享（单一所有者
  顺序驱动），不做解压、多会话编排、结果分页与 `coverage.status` 映射。
- 单文件查询的过滤、覆盖与片段发布由 `file_search.py` 协调；上下文读取由 `session_context.py` 基于发放引用协调；`server.py` 仅接受宿主显式绑定的固定文件服务，默认 app 不绑定服务。`list_sources` 仍为骨架。
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .models import IssueCode, ProjectQuality, StandardRecord
from .policy import PolicyDenied, RefusalCode, SessionPolicy
from .publication import (
    MAX_SNIPPET_TOTAL_CHARS,
    MAX_SNIPPETS_PER_FILE,
    PublicationRefusal,
    PublishedSnippet,
    SnippetCollector,
)
from .safe_reader import (
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_LINES,
    DEFAULT_MAX_TOTAL_BYTES,
    FileVersion,
    ReadOutcome,
    ReadRefusalCode,
    SafeReadDenied,
    authorize_read,
)
from .session_stage import (
    MAX_CANDIDATES_PER_SESSION,
    MAX_STAGE_BYTES_PER_SESSION,
    SessionCandidateStage,
    StageDiscardReason,
    StageOutcome,
)
from .sources.pi import SOURCE_PI, PiLineParser

__all__ = [
    "PipelineOutcome",
    "PiFileOutcome",
    "PiFileSnippets",
    "PiSessionPipeline",
    "run_line_source_file",
    "run_pi_file",
    "run_pi_file_snippets",
    "run_pi_session",
]

#: 契约误用的固定消息：`run()` 与 iter() 失败两条路径共用同一个字面量，不含调用方任何原值。
_LINE_ITERABLE_MESSAGE = "run requires an iterable of lines, not a whole str/bytes payload"


@dataclass(frozen=True)
class PipelineOutcome:
    """一次管线运行的安全结论：只有固定键、整数、布尔与本包枚举，不含任何会话侧原值。

    `complete` 直接取暂存层核对结论（含其 `_verify` 的判定），本模块不做二次解释；文件模式下
    读侧终态确认已在请求核对**之前**参与否决（`_stream_was_complete`），因此这里不会出现
    「嵌套层先判成功、外层再单独改判」的两种结论。`publication_allowed` 取自 `StageOutcome`，
    在本增量恒为 `False`。`stream_exhausted` 记录
    调用方迭代器是否真正读到结尾（这是「未读完」与「读完了但质量不完整」唯一的区分依据），
    它只回答「迭代器不再吐行」，**不因**读侧确认结果而改写；文件是否真到 EOF 另由 `read` 回答。
    `records_seen` 是解析器产出并**递交**给暂存层的记录条数（不代表被暂存：被拒条数见
    `stage.dropped_count`）。`parse` 是 `parser.finish()` 之后的最终计数快照。
    """

    complete: bool
    publication_allowed: bool
    reason: StageDiscardReason | None
    stream_exhausted: bool
    records_seen: int
    stage: StageOutcome
    parse: dict[str, Any]

    def as_public_dict(self) -> dict[str, object]:
        """整数 + 固定字面量的嵌套快照，可直接用于日志与不完整覆盖信息的 reason 拼装。"""
        return {
            "complete": self.complete,
            "publication_allowed": self.publication_allowed,
            "reason": self.reason.value if self.reason else None,
            "stream_exhausted": self.stream_exhausted,
            "records_seen": self.records_seen,
            "stage": self.stage.as_public_dict(),
            "parse": self.parse,
        }


class PiSessionPipeline:
    """同步一次性消费调用方行迭代器：解析 → 暂存 → 核对，只返回安全统计。

    用法（调用方已完成授权、打开与解压等前置动作）::

        outcome = PiSessionPipeline(session_id=expected_id).run(lines)
        outcome.complete          # 暂存层可自证的核对项是否全部通过
        outcome.as_public_dict()  # 固定键 + 整数，无正文

    一次实例只能 `run()` 一次；需要重读同一会话就新建实例（与 `PiLineParser` 的终态一致）。

    文件模式（`run_pi_file` / `run_pi_file_snippets`）不走 `run()` 而是私有的
    `_execute(..., eof_confirmed=..., admit=..., capture=...)`：它多一个在核对之前参与否决的终态
    确认器、一个逐记录准入钩子，片段入口再多一个逐记录脱敏收集钩子（只收已被暂存层接受的记录，
    且不参与核对判据）。公开的 `run(lines)` 三者都不接，因此完成判据与语义一字未改。
    """

    __slots__ = (
        "_admission_refusal",
        "_capture_refusal",
        "_parser",
        "_records_seen",
        "_stage",
        "_used",
    )

    def __init__(
        self,
        *,
        session_id: str | None = None,
        project: str | None = None,
        stream_label: str | None = None,
        max_candidates: int = MAX_CANDIDATES_PER_SESSION,
        max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
        source: str = SOURCE_PI,
        parser_factory: Callable[..., Any] | None = None,
    ) -> None:
        """`session_id`/`project` 是**外部预先给定**的断言，本模块原样转交、绝不改写或回填。

        会话标识同时给解析器（归属校验断言）与 `SessionCandidateStage`（一路身份证据）；
        `project` 只给解析器作冲突核对与无可信头部时的已声明值，**不**给暂存层当第二份归属证据。
        本模块不读取解析结果（`parser.project`/`parser.header`）去补任何一个参数，也不在两处之间
        传值。上限由两侧各自判定（见模块文档的「同一断言值两侧各自判长」）。`max_candidates`/
        `max_bytes` 只透传给暂存层，越界仍由暂存层的硬上限钳制。

        `source`/`parser_factory` 是两个默认值不变的参数化出口（行式来源共用本管线）：
        省略即 `pi` + `PiLineParser`，与参数化前的构造一字不差。给定 `source` 时，解析器工厂
        按同一关键字形状（`stream_label`/`session_id`/`project`/`source`）构造，产出记录的
        `source` 必须与断言完全一致——不一致会被暂存层按 `source_conflict` 整批丢弃，本层
        不拿工厂的默认值去掩盖调用方声明的来源。本层不为参数化新增任何核对项。
        """
        self._parser = (PiLineParser if parser_factory is None else parser_factory)(
            stream_label=stream_label, session_id=session_id, project=project, source=source
        )
        self._stage = SessionCandidateStage(
            source, session_id, max_candidates=max_candidates, max_bytes=max_bytes
        )
        self._records_seen = 0
        self._used = False
        # 逐记录准入落下的固定拒绝码（`None` 即未接钩子或未拒）：只存枚举成员，不存原值/异常。
        self._admission_refusal: RefusalCode | None = None
        # 逐记录脱敏片段收集落下的固定拒绝码：同上，只存 `PublicationRefusal` 成员。
        self._capture_refusal: PublicationRefusal | None = None

    def run(
        self,
        lines: Iterable[str | bytes],
        *,
        should_stop: Callable[[], object] | None = None,
    ) -> PipelineOutcome:
        """按序消费行流，收尾核对并返回安全统计；任何路径都不产出正文。

        `should_stop` 在**取下一行之前**被调用（返回真值即停止，那一行不会被读）：它是单线程
        同步管线里调用方表达「取消/提前放弃」的唯一通道，必须廉价、不阻塞、不抛业务数据；
        它抛异常与迭代器本身抛异常同等处理（按未读完收尾）。回调的求值结果只按真值解释，
        不做任何记录、比较或回显（不受控返回值不得成为证据）。

        `exhausted` 只由 `next()` 抛出的 `StopIteration` 决定：`for` 循环会把循环体内逃出的
        `StopIteration` 也读成「正常结束」，因此这里显式取迭代器与 `next()`。`BaseException`
        （中断类）走「取消收尾 → 关闭迭代器 → 原样重抛」，既不丢候选也不吞掉用户的 Ctrl-C。
        误用（整个 `str`/`bytes` 或不可迭代对象）先收尾再抛固定 `TypeError`。

        本入口不接终态确认器：它无从知道底层流是否走到结尾，因此 `stream_exhausted` 只表达
        「迭代器不再吐行」这一件事。需要把真实 EOF 在核对之前参与否决的是文件入口
        `run_pi_file`（走 `_execute`）。
        """
        return self._execute(lines, should_stop=should_stop, eof_confirmed=None)

    def _execute(
        self,
        lines: Iterable[str | bytes],
        *,
        should_stop: Callable[[], object] | None,
        eof_confirmed: Callable[[], object] | None,
        admit: Callable[[StandardRecord], object] | None = None,
        capture: Callable[[StandardRecord], object] | None = None,
    ) -> PipelineOutcome:
        """私有共用运行入口：与 `run()` 同一条循环与收尾，只多三个可选钩子（确认器、准入、脱敏收集）。

        `eof_confirmed` 只在迭代器声明耗尽、解析侧无 `partial`、暂存层未丢弃、未被取消，即
        **即将**请求 `stage.finish(stream_complete=True)` 之前被调用一次；它不是第二份证据，
        只是一道前置否决：非 `True` 的返回值（含假值与任何不受控取值）与它抛出的 `Exception`
        都按「没读到结尾」处理，走与失败路径同一条收尾（`cancel(STREAM_INCOMPLETE)` +
        `finish(stream_complete=False)`），因此整批候选被丢弃、`candidate_count`/`staged_bytes`
        归零、条数如实进 `dropped_count`，不存在「先成功 finish、再在上层否决」的两种结论。
        中断类 `BaseException` 不吞：先清空候选再原样重抛。`stream_exhausted` 不由确认器改写。

        `admit`（只由 `run_pi_file` 递进来）是**逐记录归属准入**钩子：每条解析产物在递交暂存层
        **之前**过一次判定，被拒的那一条不入队、不计进 `records_seen`，随后停止拉取后续行。因为
        `exhausted` 仍为假，收尾自然落在既有的整批丢弃路径（`cancel` + `finish(stream_complete=False)`）
        上——本层不为准入新增 `StageDiscardReason`，也不在 `stage.finish` 之后再否决一次。
        拒绝只降为固定 `RefusalCode` 存在 `_admission_refusal`，钩子抛出的 `Exception` 与不受控
        返回值同方向（按 `ATTRIBUTION_UNKNOWN` 记），异常对象与原值不保留、不外传。

        `capture`（只由 `run_pi_file_snippets` 递进来）是**逐记录脱敏片段收集**钩子：它跑在
        `stage.add()` 返回真**之后**，因此只有已被暂存层接受的记录才可能变成片段（集合是已暂存
        集合的子集）。它不改变任何核对判据：只把固定 `PublicationRefusal` 存进 `_capture_refusal`。
        与 `admit` 不同的是：收集触限/被拒不中断行流拉取（首拒后 `_note_capture` 短路，不再跑遮蔽），
        因为片段预算是**输出侧**约束，拿它改写读侧/暂存侧的 `complete` 就是给统计入口变语义；
        后果由 `release()` 承担（拒绝状态下即使拿到 `confirmed=True` 也只交出空元组）。
        本层不拿它顶替准入码，也不为它新增 `StageDiscardReason`。

        收集环节逃出的普通异常（含 `MemoryError` 一类在**入队/计数之后**才失败的情况）由递进来的
        `capture` 闭包自己兜住：吞掉之前先对同一个收集器整批 `discard(INTERNAL_FAILURE)`，因此
        「已收进去的前缀」绝不会被当成成功结果放出；`_note_capture` 随后把同一个固定码存进
        `_capture_refusal`（`discard()` 幂等，不会覆盖已定的首拒码）。异常与只返拒绝码是两条不同的
        失效形态：后者由收集器自己的整批清空兑现，前者必须在被吞的这一刻补上同一次清空。
        """
        if self._used:
            raise RuntimeError("pipeline is one-shot; create a new instance for a new stream")
        self._used = True
        if isinstance(lines, (str, bytes, bytearray)):
            # 与 `PiLineParser.feed()` 同一护栏：逐字符迭代会把一行射成海量假行。
            # 这里还没有任何候选入队，收尾只负责把两个组件推进终态，然后才报错。
            self._conclude(exhausted=False, cancelled=False, eof_confirmed=None)
            raise TypeError(_LINE_ITERABLE_MESSAGE)
        try:
            iterator = iter(lines)
        except TypeError:
            # 「不可迭代」与「把整个 str 当行流」是同一类契约误用：先收尾（清空候选、推进终态），
            # 再抛固定消息。`from None` 切断链：`__iter__` 自报的消息可能带类名之外的原值内容。
            self._conclude(exhausted=False, cancelled=False, eof_confirmed=None)
            raise TypeError(_LINE_ITERABLE_MESSAGE) from None
        except Exception:
            # `__iter__` 抛非 TypeError：这是一次读取失败，不是一处误用，与取行失败同等处理——
            # 降为不完整、消息不外传。此处尚未建立迭代器，没有调用方资源要归还。
            return self._conclude(exhausted=False, cancelled=False, eof_confirmed=eof_confirmed)
        cancelled = False
        exhausted = False
        try:
            while True:
                # 判据排在 next() 之前：调用方决定停止时，那一行还没有被读走。
                if should_stop is not None and should_stop():
                    cancelled = True
                    break
                try:
                    line = next(iterator)
                except StopIteration:
                    # 只有这里（取下一行）抛出的 StopIteration 才表示流真正读到结尾。
                    exhausted = True
                    break
                for record in self._parser.feed_line(line):
                    # 准入排在递交之前：被拒的那一条不交暂存层，因此它既不为任何项目留下归属
                    # 断言，也不计进 `records_seen`（那一项只数递交给暂存层的记录）。
                    if admit is not None:
                        self._note_refusal(admit, record)
                        if self._admission_refusal is not None:
                            break
                    self._records_seen += 1
                    # 暂存层的返回值不回显被拒记录的信息；结论统一由收尾时的 `finish()` 给出。
                    staged = self._stage.add(record)
                    if capture is not None and staged:
                        # 脱敏收集只收「已被暂存层接受」的记录：对外片段的集合因此是已暂存集合的子集，
                        # 被暂存层拒掉的那一条（触限/越界/冲突）永远变不成片段。
                        # 收集首拒后 `_note_capture` 短路（不再跑遮蔽），但**不中断行流与本行剩余块**：
                        # 暂存集合必须与 `run_pi_file` 完全一致，否则片段预算就会改写核对结果。
                        self._note_capture(capture, record)
                if self._admission_refusal is not None:
                    # 准入被拒：不再拉取后续行（与触限/已丢弃同一取向）。`exhausted` 保持假，于是
                    # 收尾走的就是那条已有的整批丢弃路径，候选、字节与丢弃计数由暂存层自己结算。
                    break
                if self._stage.discarded:
                    # 该会话候选已整体丢弃（触限/冲突/字段越界）：继续读只会白做，且原因码
                    # 已由暂存层记下，本模块不再制造第二个诊断。
                    break
                if IssueCode.MAX_STREAM_LINES_EXCEEDED in self._parser.stats.issue_counts:
                    # 解析器已进入「不再读取」的终态，上限后的行一概未读。
                    break
        except StopIteration:
            # 循环体内（解析、暂存、`should_stop`）逃出的 StopIteration 不是「读到结尾」，
            # 按普通迭代失败降为不完整，不得冒充耗尽。
            exhausted = False
        except Exception:
            # 异常消息可能带路径或正文片段：就地吞掉，不保存、不外传，只降为固定原因码。
            exhausted = False
        except BaseException as exc:  # KeyboardInterrupt / GeneratorExit / SystemExit 等
            # 调用方中断：先按取消收尾清空候选，再关闭迭代器归还资源，最后原样重抛。
            # 清理一律不得顶替这次中断：连清理自身抛出的 BaseException 也吞掉，
            # 原始异常与 traceback 由末尾的 `raise exc` 完整保留。
            with contextlib.suppress(BaseException):
                self._conclude(exhausted=False, cancelled=True, eof_confirmed=None)
            with contextlib.suppress(BaseException):
                self._release(iterator)
            raise exc
        try:
            return self._conclude(
                exhausted=exhausted, cancelled=cancelled, eof_confirmed=eof_confirmed
            )
        finally:
            # 顺序固定：未读完的出口上，收尾清空候选在前，归还调用方迭代器在后（`_release` 自身不抛）。
            # 真正读到结尾时不再 close()：那批行已被完整消费，没有待归还的提前停止状态。
            if not exhausted:
                self._release(iterator)

    # ---------- 内部收尾 ----------

    def _conclude(
        self, *, exhausted: bool, cancelled: bool, eof_confirmed: Callable[[], object] | None
    ) -> PipelineOutcome:
        """按「先解析收尾、再暂存核对」的固定顺序产生唯一出口。

        文件模式下真实 EOF 的确认排在 `stage.finish()` **之前**（`_stream_was_complete`）：
        未确认就不请求完整核对，而是走下面那条已有的失败路径，候选、字节与丢弃计数由暂存层
        自己结算，本层不事后改数。
        """
        self._parser.finish()  # 幂等；流级问题只在这里登记
        partial = self._parser.stats.partial
        # 本方法不释放片段：片段只能由 `run_pi_file_snippets` 在合并终态之后一次性 `release()`。
        # 收集拒绝（`_capture_refusal`）不参与这里的任何判据：它是输出侧预算，不得改写核对结论。
        if self._stream_was_complete(
            exhausted=exhausted, cancelled=cancelled, partial=partial, eof_confirmed=eof_confirmed
        ):
            stage_outcome = self._stage.finish(stream_complete=True)
        else:
            # cancel 只写首个原因：暂存层已给出更具体诊断时本模块不顶替它。
            self._stage.cancel(
                StageDiscardReason.CANCELLED if cancelled else StageDiscardReason.STREAM_INCOMPLETE
            )
            stage_outcome = self._stage.finish(stream_complete=False)
        return PipelineOutcome(
            complete=stage_outcome.complete,
            publication_allowed=stage_outcome.publication_allowed,
            reason=stage_outcome.reason,
            stream_exhausted=exhausted,
            records_seen=self._records_seen,
            stage=stage_outcome,
            parse=self._parser.stats.as_public_dict(),
        )

    def _stream_was_complete(
        self,
        *,
        exhausted: bool,
        cancelled: bool,
        partial: bool,
        eof_confirmed: Callable[[], object] | None,
    ) -> bool:
        """是否可以向暂存层请求一次完整核对（`stream_complete=True`）。

        行流模式（`eof_confirmed is None`）只看已有的四项，因此 `run(lines)` 的判据不变。
        文件模式额外要求同一个读取器自报 `outcome().complete is True`：读取器触限、预算用尽、
        提前关闭时它仍以 `StopIteration` 收束迭代（`exhausted` 因此为真），但那不是文件 EOF。
        取值只认字面 `True`：确认器返回假值或非布尔值都不足以断言「读完了」。取证本身失败
        （`Exception`，包括句柄已关时读取器抛出的 `SafeReadDenied`）只能说明「确认不了」，与
        未读到结尾同路：消息不外传、不另造诊断码，也不拿它当已读完。
        中断类 `BaseException` 不改写为结论：按与循环内中断同一条收尾（取消 → `finish(False)`，
        候选清空）后原样重抛，不把回调逃出的中断当成一次正常完成。
        """
        if cancelled or partial or self._stage.discarded or not exhausted:
            return False
        if eof_confirmed is None:
            return True
        try:
            confirmed = eof_confirmed()
        except Exception:
            return False
        except BaseException:
            # 重入一次失败收尾：`parser.finish()` 与 `cancel`/`finish` 都幂等，`eof_confirmed=None`
            # 不会再触发确认；这里的结论不被任何出口使用，只负责不让候选驻留内存。
            with contextlib.suppress(BaseException):
                self._conclude(exhausted=False, cancelled=True, eof_confirmed=None)
            raise
        return confirmed is True

    def _note_refusal(
        self, admit: Callable[[StandardRecord], object], record: StandardRecord
    ) -> None:
        """跑一次逐记录准入：只保存固定 `RefusalCode`，异常对象、消息与原值一律不保留、不外传。

        钩子契约：返回 `None` 即放行；返回一个 `RefusalCode` 成员即按那个固定码拒绝；返回任何
        其它取值（真值、假值、不受控对象）都不足以表达「已准入」，按 `ATTRIBUTION_UNKNOWN` 记
        ——「准入判不出来」与「没有可核对的归属证据」在同一否决方向上。钩子自己逃出的 `Exception`
        （策略层 `PolicyDenied` 之外的意外失败）同样降为 `ATTRIBUTION_UNKNOWN`：它的消息可能含
        路径，就地吞掉，不另造诊断码。中断类 `BaseException` 不在这里吞：交给 `_execute()` 的
        既有中断收尾（先清空候选再原样重抛）。
        首个拒绝被粘住（与暂存层「只保留首个原因码」同一口径）：后续记录不再判定，结果里因此
        只有一个固定码，它也不拿暂存层的 `StageDiscardReason` 顶替任何一层的原因。
        """
        if self._admission_refusal is not None:
            return
        try:
            verdict = admit(record)
        except Exception:
            self._admission_refusal = RefusalCode.ATTRIBUTION_UNKNOWN
            return
        if verdict is None:
            return
        if isinstance(verdict, RefusalCode):
            self._admission_refusal = verdict
        else:
            # 不受控返回值不得成为放行依据：方向上保守拒绝，只存本包闭合枚举的成员。
            self._admission_refusal = RefusalCode.ATTRIBUTION_UNKNOWN

    def _note_capture(
        self, capture: Callable[[StandardRecord], object], record: StandardRecord
    ) -> None:
        """跑一次逐记录脱敏收集：只保存固定 `PublicationRefusal`，异常对象、消息与原值一律不外传。

        钩子契约：返回 `None` 即已收下；返回一个 `PublicationRefusal` 成员即按那个固定码拒绝；
        其它取值不足以表达「已收集」，按 `INTERNAL_FAILURE` 记。钩子自己逃出的 `Exception` 同方向
        降级（消息可能含正文）。中断类 `BaseException` 不吞：交给 `_execute()` 既有中断收尾，
        而候选在 `release()` 之前从未离开收集器。首拒粘住（同 `_note_refusal`）。
        """
        if self._capture_refusal is not None:
            return
        try:
            verdict = capture(record)
        except Exception:
            self._capture_refusal = PublicationRefusal.INTERNAL_FAILURE
            return
        if verdict is None:
            return
        if isinstance(verdict, PublicationRefusal):
            self._capture_refusal = verdict
        else:
            self._capture_refusal = PublicationRefusal.INTERNAL_FAILURE

    @staticmethod
    def _release(iterator: object) -> None:
        """未读完的出口上归还调用方资源：只在迭代器自带 `close()` 时调用一次，任何失败都不外传。

        两步同受保护：`close` 可能是个会抛异常的描述符，取属性本身就不是零成本操作。关闭失败
        既不改变已定的结论（原因码固定，不另造诊断），也不得在调用方中断路径上顶替原异常，
        因此这里不看异常类型，就地吞掉。
        """
        try:
            close = getattr(iterator, "close", None)
            if not callable(close):
                return
            close()
        except Exception:
            # 关闭失败不改变结论：流已是未读完状态，原因码固定，不拿它另造诊断（本模块不写日志）。
            # 中断路径上的 BaseException 由调用处的 suppress 托底。这里直接返回而不是记录异常。
            return


def run_pi_session(
    lines: Iterable[str | bytes],
    *,
    session_id: str | None = None,
    project: str | None = None,
    stream_label: str | None = None,
    should_stop: Callable[[], object] | None = None,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
) -> PipelineOutcome:
    """一次性便捷入口：等价于新建 `PiSessionPipeline` 后 `run(lines, should_stop=...)`。

    参数语义与构造期断言规则见 `PiSessionPipeline`；断言值同样只由调用方给定，本函数不接受
    任何来自解析结果的「回填断言」。
    """
    pipeline = PiSessionPipeline(
        session_id=session_id,
        project=project,
        stream_label=stream_label,
        max_candidates=max_candidates,
        max_bytes=max_bytes,
    )
    return pipeline.run(lines, should_stop=should_stop)


@dataclass(frozen=True)
class PiFileOutcome:
    """一次授权文件运行的合并终态：只含固定键、整数、布尔与本包闭合枚举，不含正文/路径/scope/会话标识。

    `complete` 是**两个终态的合并否决**（`pipeline.complete and read.complete and not parse["partial"]`）：
    读取侧触限、提前终止（`closed_before_eof`）、读取失败使 `read.complete` 为假，解析侧 `partial`
    为真，暂存层任何一条记录判丢弃使 `pipeline.complete` 为假——任一个都否决 `complete`，两层原因
    各自保留、不互相顶替。读侧的否决不排在这个合并式之后：文件模式把同一个读取器的
    `outcome().complete` 当作向暂存层请求完整核对的**前置条件**（见 `_stream_was_complete`），因此
    reader 触限/提前收束时那次「假耗尽」拿不到 `stream_complete=True` 的核对，嵌套的
    `pipeline.complete` 与外层 `complete`、`reason` 同向。`stream_exhausted`（在 `pipeline` 上）只说明
    调用方迭代器不再吐行，**不等于**文件读到 EOF：文件是否读完只由 `read.eof_reached`/`read.complete` 回答。
    `publication_allowed` 取自 `StageOutcome`，本增量恒为 `False`。
    `attribution_refusal` 是逐记录准入落下的**固定 `RefusalCode`（或 `None`）**：它只回答「哪一类
    归属判定没通过」，不含项目名、cwd、scope、异常对象或任何会话侧原值。非 `None` 时 `complete`
    必为假：拒绝已排在向暂存层请求完整核对**之前**（被拒后不再拉取行流，`stream_exhausted` 为假），
    因此本层不在合并式里再拿它否决一次；`reason`（暂存层的 `StageDiscardReason`）与它各自保留，
    不互相顶替。未接钩子或逐条全部准入通过时为 `None`。
    """

    complete: bool
    publication_allowed: bool
    reason: StageDiscardReason | None
    read: ReadOutcome
    pipeline: PipelineOutcome
    attribution_refusal: RefusalCode | None = None
    version: FileVersion | None = None

    def as_public_dict(self) -> dict[str, object]:
        """嵌套快照：固定键 + 整数/布尔/枚举字面量（含读侧计数），无任何不受控原值。

        `version` 故意**不**进快照：真实卷号/文件标识/内容摘要只供包内引用账本核对，
        不进入任何对外结果。
        """
        return {
            "complete": self.complete,
            "publication_allowed": self.publication_allowed,
            "reason": self.reason.value if self.reason else None,
            "read": self.read.as_public_dict(),
            "pipeline": self.pipeline.as_public_dict(),
            "attribution_refusal": (
                self.attribution_refusal.value if self.attribution_refusal else None
            ),
        }


def _run_pi_file_pipeline(
    policy: SessionPolicy,
    scope: str,
    path: str,
    session_id: str,
    *,
    cwd: str | None = None,
    project_filter: str | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
    should_stop: Callable[[], object] | None = None,
    _candidate_capture: Callable[[StandardRecord], object] | None = None,
    _project_grants: dict[int, str] | None = None,
    source: str = SOURCE_PI,
    parser_factory: Callable[..., Any] | None = None,
) -> PiFileOutcome:
    """一次性授权文件入口：存储授权 → 有界行读 → 读侧终态确认 → pi 解析 → 暂存核对 → 合并完整性。

    四个必需参数均为**调用方预先独立持有**的批准信息：`SessionPolicy` 实例、`scope` 标识、
    **单个**存储文件 `path`、会话标识断言 `session_id`；`source` 默认 `SOURCE_PI`（`"pi"`），
    参数化行式来源（codex/claude/cursor）由 `run_line_source_file` 传入各自固定 ID。
    `cwd` 是可选的 **cwd 断言**（走解析器的 `project` 通道，不是策略项目名），
    与 `session_id` 一样只在构造期进入各自的通道：本层**不发现文件、不配置根、不从解析结果回填身份**。
    `project_filter` 是另一个通道：**策略层已批准的项目名**，只交给策略层，不交给解析器与暂存层，
    本层不拿 `cwd` 充当它，也不拿它充当 `cwd` 断言。省略即「本范围内全部已批准项目」。

    两道策略判定（均在打开之前/逐记录）：① `authorize_query(scope, sources=(source,),
    project=project_filter)`——未知 scope、未批准的 pi 存储根、未知 project 都会原样抛
    `PolicyDenied`（只带固定码），此时 `with` 尚未建立，无候选、无句柄。② 逐记录归属准入：
    **只把 `project_quality is TRUSTED_HEADER_CWD` 的记录**的 `record.project` 送过一次
    `authorize_attribution(scope, record.project, project=project_filter)`；其余质量（含
    `CALLER_ASSERTED`）**不递交策略层**，当场按 `attribution_unknown` 拒——不让一个只来自断言通道
    的字符串去跑真实路径探测。结论只保留 `PolicyDenied.code`（`RefusalCode`）或 `None`：
    `AttributionGrant.project`、请求的项目名/cwd、异常对象一律不进结果、不回显、不写日志。
    被拒即停止拉取后续行，走与失败路径同一条整批丢弃收尾（候选、字节与 `dropped_count`
    仍由暂存层结算，本层不事后改数）；它排在 `stage.finish` **之前**，因此不存在
    「先核通过、再在上层补一票」的两种结论。本层不为准入新增 `StageDiscardReason`。
    三项字节/行预算只透传给 `authorize_read`，由其入口钳制（调用方只能收紧）。

    身份断言值不合时的归因不在本层：解析侧按 `MAX_SESSION_ID_CHARS`/`MAX_PROJECT_VALUE_CHARS`
    把超限值降为「未提供」，暂存侧按 `MAX_SESSION_KEY_CHARS` 记 `session_id_assertion_invalid`，
    两侧都只会使 `complete` 为假，本层不新增也不顶替任何拒绝码。本层不传 `stream_label`：
    读取器不提供一个不含路径的短标签，因此位置标签降为解析侧的固定 `unknown-stream`（行号仍真实），
    本层不拿 `path` 去充当标签。

    出口只有两类：① `PiFileOutcome`（含读侧与解析侧两份终态）；② 授权/打开被拒时原样抛出策略层
    `PolicyDenied` 或读取层 `SafeReadDenied`（两者只携带固定码与固定文案）——它们发生在 `with`
    建立之前，因此没有任何候选入队、也没有句柄遗留。读取中途的失败已被 `_execute()` 降为固定原因码，
    异常对象不外传；`BaseException` 中断由 `_execute()` 按「取消收尾 → 关闭迭代器 → 原样重抛」处理，
    `__exit__` 再幂等关闭一次句柄（关闭失败不顶替原中断）。另有一道不可达护栏：`with` 体无论
    如何都会 `return`，而 `__exit__` 的声明返回类型是 `bool`（源码恒 `False`），因此“走完 `with`
    仍无终态”这一路径在类型上存在：那里固定抛 `SafeReadDenied(handle_read_failed)`（只带固定码），
    不凭空的 `complete` 冒充读完了。本轮不改 `safe_reader.py` 的签名。

    完整核对的前置条件（本轮修正的根因）：本入口走私有的 `_execute(reader, ..., eof_confirmed=...)`
    而不是公开的 `run(lines)`，因为「读取器不再吐行」与「文件读到 EOF」不是同一句话：reader 触限与
    预算用尽后同样以 `StopIteration` 收束。确认器只在即将 `stage.finish(stream_complete=True)` 之前
    取一次同一个 `reader.outcome().complete`：假值与取证抛出的 `Exception` 都不得当「读完」，这次运行
    直接走失败收尾（整批丢弃、`candidate_count`/`staged_bytes` 归零、条数进 `dropped_count`）。确认器
    不参与、也不改写任何计数：丢弃与字节量仍由暂存层自己结算，本层不做事后统计补写。

    本执行器只负责固定 pi 文件的授权读取、整流核对与安全终态，不自行执行关键词/时间/项目过滤或返回查询结果；包内 `file_search.py` 通过私有有界候选钩子复用它，再调用 `query.py` 与 `publication.py` 完成筛选及一次性脱敏发布。`complete=True` 表示「存储授权 + 逐记录归属准入 + 读侧/解析侧/暂存层自证核对全部通过」，仍**不是**发布许可（`publication_allowed` 恒为 `False`，准入通过也只是路径→项目映射成立，不证明记录确实来自那个项目，也不构成发布授权）。

    参数化说明（行式来源共用本内核，不复制管线）：`source` 只流向两处——`authorize_query` 的
    sources 元组与 `PiSessionPipeline` 的 source/parser_factory 构造；默认 `SOURCE_PI` +
    `parser_factory=None`（= `PiLineParser`）时行为与参数化之前逐字节一致。`parser_factory`
    必须按 `stream_label`/`session_id`/`project`/`source` 这组关键字构造，且产出记录的
    `record.source` 必须恰等于 `source`：不一致由暂存层按 `source_conflict` 整批丢弃，本层不
    拿工厂默认值掩盖调用方声明的来源，也不为参数化新增任何核对项或拒绝码。
    """
    # 打开前的查询轴授权：拒绝原样抛出（只带固定码），本层不捕、不转译、不拿它改任何结论。
    policy.authorize_query(scope, sources=(source,), project=project_filter)

    def admit(record: StandardRecord) -> object:
        """逐记录归属准入：返回 `None` 放行，否则返回一个固定 `RefusalCode`。

        只读 `record.project_quality`/`record.project` 这两项**待审证据**：不回填任何断言通道，
        不把策略结论（项目名）交给解析器/暂存层，也不对外回显。除 `PolicyDenied` 外的任何
        意外失败由 `_note_refusal` 降为 `attribution_unknown`，异常消息（可能含路径）就地吞掉。
        """
        if record.project_quality is not ProjectQuality.TRUSTED_HEADER_CWD:
            # 断言级/未知级项目值不得充当归属证据：不探测、直接按「无可核对证据」拒。
            return RefusalCode.ATTRIBUTION_UNKNOWN
        try:
            grant = policy.authorize_attribution(scope, record.project, project=project_filter)
        except PolicyDenied as denial:
            # 只取枚举成员（固定码）；`denial` 对象本身不保留，它的文案已经是固定串。
            return denial.code
        if _project_grants is not None:
            # 仅供包内 file_search 按同一对象身份构建序号映射；不从 record.project 反推项目名。
            _project_grants[id(record)] = grant.project
        return None

    with authorize_read(
        policy,
        scope,
        source,
        path,
        max_line_bytes=max_line_bytes,
        max_total_bytes=max_total_bytes,
        max_lines=max_lines,
    ) as reader:
        pipeline = PiSessionPipeline(
            session_id=session_id,
            project=cwd,
            max_candidates=max_candidates,
            max_bytes=max_bytes,
            source=source,
            parser_factory=parser_factory,
        )
        # 直接消费读取器本身（它就是 Iterable[bytes]）：不包壳、不另造读取器、不按偏移二次取字节。
        # 确认器只从同一个 reader 取证（`outcome().complete`），它排在暂存层的完整核对之前；
        # 此处不调 `close()`：过早关闭会把缓冲字节计进丢弃量并翻成 `closed_before_eof`，把「真读完」
        # 误否；EOF 与否在缓冲仍自然为空时就能如实读出。
        outcome = pipeline._execute(
            reader,
            should_stop=should_stop,
            eof_confirmed=lambda: reader.outcome().complete,
            admit=admit,
            capture=_candidate_capture,
        )
        # 顺序固定：`_execute()` 内已完成 `parser.finish()` 与暂存核对；此处先取同趟版本
        #（句柄未关时从同一句柄取身份与摘要），再显式关句柄（`close()` 幂等，
        # `__exit__` 再关一次不重复计丢弃量），使未交出的缓冲字节先如实进丢弃量，再取读侧终态。
        version = reader.file_version()
        reader.close()
        read = reader.outcome()
        parse = outcome.parse
        # 两层终态的并集否决（否决已先在核对之前作用一次，这里是同一方向上的读侧终态快照）：
        # 任一否决项成立即 `complete=False`，本层不做二次解释也不事后改数。
        return PiFileOutcome(
            complete=bool(outcome.complete and read.complete and not parse["partial"]),
            publication_allowed=outcome.publication_allowed,
            reason=outcome.reason,
            read=read,
            pipeline=outcome,
            attribution_refusal=pipeline._admission_refusal,
            version=version if version.complete else None,
        )
    # 不可达出口：`AuthorizedLineReader.__exit__` 源码里恒 `return False`（不吞异常），`with` 体
    # 任一正常出口都已 `return`，因此本行实际不可达；它的存在只是因为 `__exit__` 的声明返回类型
    # 是 `bool`，类型检查器仍认为可能落入无终态的分支。那条分支上没有任何可报的结论，固定按
    # 「读取失败、句柄状态不可信」拒（只带固定码，不拼路径与系统原文），不凭空的 `complete`
    # 冒充读完了。本轮不改 `safe_reader.py` 的签名。
    raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED)


def run_line_source_file(
    policy: SessionPolicy,
    scope: str,
    path: str,
    session_id: str,
    *,
    source: str,
    parser_factory: Callable[..., Any],
    cwd: str | None = None,
    project_filter: str | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
    should_stop: Callable[[], object] | None = None,
    _candidate_capture: Callable[[StandardRecord], object] | None = None,
    _project_grants: dict[int, str] | None = None,
) -> PiFileOutcome:
    """通用行式来源的一次性授权文件入口（DES-ADAPTER-01 行式族共用内核的公开命名）。

    与 `run_pi_file` 完全同一条管线、同一组出口与同一份 `PiFileOutcome`，只多两个必给参数：
    `source`（策略层已批准的行式来源 ID，如 `codex`/`claude_code_cli`/`cursor_agent_cli`）与
    `parser_factory`（该来源的行解析器，按 `stream_label`/`session_id`/`project`/`source` 构造）。
    本入口不发现文件、不做关键词/时间/项目过滤、不发布片段：它只把「授权读 → 解析 → 暂存
    核对 → 终态合并」这条路换来源参数化地走一遍；拒绝出口仍只有固定码（`PolicyDenied` /
    `SafeReadDenied`）。pi 来源请继续用 `run_pi_file`（语义与历史行为逐字节不变）。
    """
    return _run_pi_file_pipeline(
        policy,
        scope,
        path,
        session_id,
        cwd=cwd,
        project_filter=project_filter,
        max_line_bytes=max_line_bytes,
        max_total_bytes=max_total_bytes,
        max_lines=max_lines,
        max_candidates=max_candidates,
        max_bytes=max_bytes,
        should_stop=should_stop,
        _candidate_capture=_candidate_capture,
        _project_grants=_project_grants,
        source=source,
        parser_factory=parser_factory,
    )


def run_pi_file(
    policy: SessionPolicy,
    scope: str,
    path: str,
    session_id: str,
    *,
    cwd: str | None = None,
    project_filter: str | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
    should_stop: Callable[[], object] | None = None,
) -> PiFileOutcome:
    """公开统计入口；包内查询协调器使用私有 runner 取得有界候选并在内部完成过滤与发布。"""
    outcome = _run_pi_file_pipeline(
        policy,
        scope,
        path,
        session_id,
        cwd=cwd,
        project_filter=project_filter,
        max_line_bytes=max_line_bytes,
        max_total_bytes=max_total_bytes,
        max_lines=max_lines,
        max_candidates=max_candidates,
        max_bytes=max_bytes,
        should_stop=should_stop,
    )
    return outcome


@dataclass(frozen=True)
class PiFileSnippets:
    """一次授权文件运行的**脱敏片段出口**结果：一次性片段元组 + 与统计入口同一份终态。

    `file` 就是 `run_pi_file` 返回的那个 `PiFileOutcome`（统计 API 不变、不另造一份结论）：
    `complete`/`publication_allowed`/`reason`/`attribution_refusal` 仍以它为准，
    `publication_allowed` 仍取自 `StageOutcome` 且恒为 `False`——本层不把「已释放片段」
    伪装成「阶段层已授权发布」。`released` 直读收集器的释放事实：
    本次是否拿到了字面 `True` 的终局确认并一次性交出过片段（零记录的成功运行也是
    `released=True` 且 `snippets` 为空）。
    `snippet_refusal` 是片段链上的**首个**固定 `PublicationRefusal`（或 `None`）：它只回答
    「哪一类片段环节没过」，不含正文、路径、scope、项目名与异常对象。两者不互相顶替。
    `snippets` 只在 `released=True` 时可能非空；任何未确认/拒绝/中断路径下它都是空元组。
    """

    complete: bool
    released: bool
    publication_allowed: bool
    reason: StageDiscardReason | None
    attribution_refusal: RefusalCode | None
    snippet_refusal: PublicationRefusal | None
    snippets: tuple[PublishedSnippet, ...]
    file: PiFileOutcome

    def as_public_dict(self) -> dict[str, object]:
        """嵌套快照：固定键 + 整数/布尔/枚举字面量 + 已遮蔽片段（不拼路径/scope/会话标识）。"""
        return {
            "complete": self.complete,
            "released": self.released,
            "publication_allowed": self.publication_allowed,
            "reason": self.reason.value if self.reason else None,
            "attribution_refusal": (
                self.attribution_refusal.value if self.attribution_refusal else None
            ),
            "snippet_refusal": self.snippet_refusal.value if self.snippet_refusal else None,
            "snippet_count": len(self.snippets),
            "snippets": [snippet.as_public_dict() for snippet in self.snippets],
            "file": self.file.as_public_dict(),
        }


def run_pi_file_snippets(
    policy: SessionPolicy,
    scope: str,
    path: str,
    session_id: str,
    *,
    cwd: str | None = None,
    project_filter: str | None = None,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
    max_candidates: int = MAX_CANDIDATES_PER_SESSION,
    max_bytes: int = MAX_STAGE_BYTES_PER_SESSION,
    max_snippets: int = MAX_SNIPPETS_PER_FILE,
    max_total_chars: int = MAX_SNIPPET_TOTAL_CHARS,
    should_stop: Callable[[], object] | None = None,
) -> PiFileSnippets:
    """单文件有界脱敏片段入口：**与 `run_pi_file` 同一条管线**，只在末端多一个脱敏出口。

    必需参数与 `run_pi_file` 完全同一组（同一个 `SessionPolicy` 实例、`scope`、**单个**文件 `path`、
    **预先独立持有**的 `session_id`，可选 `cwd` 断言与 `project_filter`）：本层不发现文件、不枚举
    目录、不配置根、不从解析产物回填身份，也不接受任何客户端自由路径。两条策略轴与
    `run_pi_file` 逐字同一条实现（打开前 `authorize_query`，逐记录 `authorize_attribution` 只采信
    `TRUSTED_HEADER_CWD`）：本层**不**新增宽松管线、**不**拿 `stage.complete` 当授权、
    **不**把 `publication_allowed` 当发布许可。

    片段只在记录**已被暂存层接受**后产生（`SnippetCollector.collect` 跑在 `stage.add` 返回真之后），
    因此对外片段的集合是已暂存集合的子集：被暂存层拒掉/丢弃的记录永远变不成片段。逐条先过
    `redaction.redact_text`（**完整遮蔽之后**才由遮蔽层自己截片），本层不另实现规则集、
    不缓存原文、不按文件重读、不按偏移二次取字节。两条硬顶只能收紧：条数 `MAX_SNIPPETS_HARD_LIMIT`、
    总字符代理预算 `MAX_SNIPPET_TOTAL_CHARS_HARD_LIMIT`（预算按遮蔽后的字符数累加）。

    任何一条拒绝路径都使对外**零片段**，但机制分两层：① 片段链自身拒绝（遮蔽拒绝、两条硬顶任一
    触限、记录形态不可用、收集意外失败）→ 收集器立即清空已收集片段，`release()` 即便拿到字面
    `True` 也只交出空元组；② 运行链拒绝（逐记录准入被拒、暂存层丢弃、EOF 未确认、解析侧 `partial`、
    合并完整性为假）→ `confirmed` 拿不到字面 `True`。**片段预算不反向改写核对**：收集首拒后只是
    不再跑遮蔽，行流、`records_seen` 与暂存集合仍与 `run_pi_file` 逐字一致（触限不会改变
    `complete`/`dropped_count`），它的后果只能就是零片段。完整确认前绝不 yield、绝不回调、
    绝不逐条外递：片段只能作为 `PiFileSnippets.snippets` 一次性返回，首拒的固定码只留在
    `snippet_refusal`。`should_stop` 是唯一的调用方钩子（与统计入口同一语义）；本层不接受任意用户回调。

    出口只有两类：① `PiFileSnippets`（`released` 取收集器自身的释放事实，不是 `complete` 的重述）；
    ② 授权/打开被拒时原样抛出 `PolicyDenied` 或
    `SafeReadDenied`（只带固定码与固定文案）——它们发生在 `with` 建立之前，无候选、无片段。
    读取中途失败仍由 `_execute()` 降为固定原因码不外传；`BaseException` 中断（Ctrl-C 等）由
    `_execute()` 按「取消收尾 → 关迭代器 → 原样重抛」处理，本层另在 `finally` 里把收集器的
    内部候选清空（清理自身的任何失败就地吞掉，不顶替原中断）；`__exit__` 再幂等关一次句柄。
    与 `run_pi_file` 同形的那道不可达护栏保留（固定抛 `SafeReadDenied(handle_read_failed)`）。

    `complete=True` 仍**不是**发布许可：它只说明两条授权轴、EOF 前置确认与暂存层可自证的
    核对全部通过；片段里的文字仍属不可信历史内容（DES-SEC-01），遮蔽层也不承诺任何检出率。
    """
    # 打开前的查询轴授权：与 `run_pi_file` 完全同一句，拒绝原样抛出（只带固定码）。
    policy.authorize_query(scope, sources=(SOURCE_PI,), project=project_filter)

    def admit(record: StandardRecord) -> object:
        """逐记录归属准入：与 `run_pi_file` 内的同一判据（不新建第二套宽松判定）。

        只读 `record.project_quality`/`record.project` 两项**待审证据**：不回填断言通道、
        不把策略结论交给解析器/暂存层、不对外回显。意外失败由 `_note_refusal` 降为
        `attribution_unknown`，异常消息（可能含路径）就地吞掉。
        """
        if record.project_quality is not ProjectQuality.TRUSTED_HEADER_CWD:
            return RefusalCode.ATTRIBUTION_UNKNOWN
        try:
            policy.authorize_attribution(scope, record.project, project=project_filter)
        except PolicyDenied as denial:
            return denial.code
        return None

    def capture(record: StandardRecord) -> object:
        """逐记录脱敏收集：把收集器的固定结论原样向上递（只返拒绝码的那条路径它自己已负责整批清空）。

        返回 `None` 即已收下；返回 `PublicationRefusal` 即首拒。循环只会递解析侧的产出（均为
        `StandardRecord`），因此收集器的契约 `TypeError` 在这里实际不可达；即使发生也被下面同一条
        异常出口折成 `internal_failure`（保守拒绝），异常对象与原值不外传。

        收集器**抛出**普通异常时（入队/计数中途失败，如 `MemoryError`：失败点可能排在已追加的片段
        **之后**，收集器自己那条清空来不及执行）：就地吞掉之前先对同一个收集器整批
        `discard(INTERNAL_FAILURE)`，把已经收进去的前缀一起清空；`_note_capture` 随后记下同一个固定码。
        清空与吞异常之间不留窗口：这条路径之后无论合并 `complete` 是什么，释放都拿不到字面 `True`。
        中断类 `BaseException` 不在这里兜：交给 `_execute()` 既有中断收尾与函数末尾的 `finally`。
        """
        try:
            return collector.collect(record)
        except Exception:
            collector.discard(PublicationRefusal.INTERNAL_FAILURE)
            return PublicationRefusal.INTERNAL_FAILURE

    collector = SnippetCollector(
        source=SOURCE_PI, max_snippets=max_snippets, max_total_chars=max_total_chars
    )
    try:
        with authorize_read(
            policy,
            scope,
            SOURCE_PI,
            path,
            max_line_bytes=max_line_bytes,
            max_total_bytes=max_total_bytes,
            max_lines=max_lines,
        ) as reader:
            pipeline = PiSessionPipeline(
                session_id=session_id,
                project=cwd,
                max_candidates=max_candidates,
                max_bytes=max_bytes,
            )
            # 同一个私有运行入口 `_execute`：确认器、准入钩子与 `run_pi_file` 一字不差，只是多递
            # 一个 `capture`。收集器不拿任何未确认的候选外递，因此本行不存在提前发布窗口。
            outcome = pipeline._execute(
                reader,
                should_stop=should_stop,
                eof_confirmed=lambda: reader.outcome().complete,
                admit=admit,
                capture=capture,
            )
            version = reader.file_version()
            reader.close()
            read = reader.outcome()
            version = reader.file_version()
            parse = outcome.parse
            file_outcome = PiFileOutcome(
                complete=bool(outcome.complete and read.complete and not parse["partial"]),
                publication_allowed=outcome.publication_allowed,
                reason=outcome.reason,
                read=read,
                pipeline=outcome,
                attribution_refusal=pipeline._admission_refusal,
                version=version if version.complete else None,
            )
            # 释放只发生在这里、只发生一次：`confirmed` 的取值就是上面那份合并终态的 `complete`，
            # 再与「本次没有收集拒绝」相与（两轴授权 + EOF 前置确认 + 暂存核对 + 解析侧无 `partial`，
            # 且片段收集环节没有落下过任何固定拒绝码）。假值→收集器清空并交出空元组；
            # 收集器已拒绝时即使拿到真值也只交出空元组（不拿不完整的脱敏集合对外）。
            # 收集拒绝并入 `confirmed` 不是新增判据，而是把「收集失败」固定在释放判定之前：
            # 它不参与 `file_outcome.complete`，核对与统计结论仍一字未改。
            snippets = collector.release(
                confirmed=file_outcome.complete and pipeline._capture_refusal is None
            )
            return PiFileSnippets(
                complete=file_outcome.complete,
                released=collector.released,
                publication_allowed=file_outcome.publication_allowed,
                reason=file_outcome.reason,
                attribution_refusal=file_outcome.attribution_refusal,
                snippet_refusal=collector.refusal,
                snippets=snippets,
                file=file_outcome,
            )
        # 不可达出口（与 `run_pi_file` 同理：`__exit__` 声明返回 `bool`）：那条分支上没有任何
        # 可报的结论，固定按「读取失败、句柄状态不可信」拒；`finally` 会把收集器清空。
        raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED)
    finally:
        # 未走到 `release()` 的全部出口（授权报错、读取失败、`BaseException` 中断）在这里兑现
        # 「内部候选清空」：已释放/已拒绝的实例 `discard()` 为空操作，不会改写已定的首拒码。
        # 清理自身的任何异常都就地吞掉，不得顶替调用方的原中断或原始报错。
        with contextlib.suppress(BaseException):
            collector.discard(PublicationRefusal.NOT_CONFIRMED)
