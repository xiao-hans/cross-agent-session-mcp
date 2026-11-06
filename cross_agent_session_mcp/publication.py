r"""单文件运行的**有界脱敏片段出口**（DES-API-01「会话结果发布边界」、DES-SEC-01「结果片段做常见凭据遮蔽」）。

定位：本模块只回答一件事——**一条已经走完授权的记录，能不能变成一个可外出的片段**。
它不做发现、不打开文件、不判授权、不接 `server.py`，也不产出任何「发布许可」结论：
授权判定仍只在 `policy.py`（存储轴 + 逐记录归属轴 + 查询轴），一致性核对仍只在
`session_stage.py`，本模块只是那条链末端**唯一**能携带会话侧文本的出口。

与 `session_stage.py` 的分工（为什么另开一个出口而不是改暂存层）：
暂存层刻意**没有任何返回正文的通道**，且它的 `StageOutcome.publication_allowed` 恒为 `False`
——它不知道脱敏发生过，也就不能声称可发布。本模块承担脱敏侧的那半边：逐条把正文交给
`redaction.redact_text`（**完整遮蔽之后**才允许截片，顺序由遮蔽层自己保证），把结果按**条数**与
**总字符代理预算**两条硬顶收进一个一次性收集器。两者都不放松对方：授权轴缺失、核对不过、
遮蔽拒绝、任一硬顶触限，收集器一律整体清空并返回零片段。

释放时机（顺序即语义）：本模块**不主动向任何人递交片段**。片段只有一个去处——
`SnippetCollector.release(confirmed=...)`，而 `confirmed` 只由调用方（`session_pipeline`）在
**同一次文件运行的两条授权轴与全部完整性判定都通过之后**给一次字面 `True`。非字面 `True`
（缺参数、`1`、`"y"` 等不受控真值）与已拒绝/已关闭状态都走同一条路：内部候选清空、返回空元组、
实例关闭。因此「先拿到片段、再在上层否决」在本模块里不可表达。

会话侧字符串字段的口径：`PublishedSnippet` 只携带
① 遮蔽后的正文 `snippet`、② **调用方给定的固定来源 ID**（`source`，不是 `record.source` 的原值）、
③ 两个整数位置（`line_no`/`ordinal`，解析侧的解码后行序号，非字节偏移）、④ 两个遮蔽元数据整数/布尔。
**不含**原始路径、scope、会话标识、cwd、项目值、`role`/`executor` 自由取值、时间戳原值——
`role` 是数据侧自由字符串（本模块没有可闭合的取值域），因此不回传；这是本轮接受的可用性代价。
位置串也不在这里拼（`SourceLocation.to_ref()` 会带 `stream_label`），只出整数。

有界性（不声称精确，只给可核对的上界）：
- 遮蔽**前**的长度上界不靠本模块：pi 侧单个文本块 `MAX_TEXT_BLOCK_CHARS = 32_768`，
  遮蔽层 `MAX_INPUT_CHARS = 65_536`，一条记录就是一个块，因此真实记录不会走进 `input_too_large`
  拒绝分支（走到也按拒绝整批清空，不做前缀处理）。
- 遮蔽**后**每条至多 `redaction.MAX_OUTPUT_CHARS = 8_192` 字符（遮蔽层截片并剥掉残缺占位）。
- 常驻片段字符总量 ≤ `min(条数生效上限, MAX_SNIPPETS_HARD_LIMIT) × 8_192`；
  总字符代理预算（按遮蔽后的**字符数**计，非 UTF-8 字节：一个码点最多 4 字节，
  所以字节量级由同一乘积再放大 4 倍封顶）在默认参数下为 32 768 字符。
- 两条上限都**只能被调用方收紧**：构造参数按 `MAX_SNIPPETS_HARD_LIMIT` /
  `MAX_SNIPPET_TOTAL_CHARS_HARD_LIMIT` 钳制，不抛错（与暂存层、读取层同一口径），
  避免用一个超大参数把「有界」读成「无界」。
- 计数口径：条数按**已接受的片段**计；字符数按遮蔽后的 `len(snippet)` 累加。触限的判据排在
  **追加之前**，所以不存在「装了一半」的状态；而任何一次失败（含遮蔽拒绝）都是整批清空，
  不留下「前几条安全、后面那条不安全」的误导。
- 遮蔽层是**纯函数**且整段调用一次：本模块不再自己实现规则集、不缓存原文、不重试、
  不拿占位串当内容判据。遮蔽结果仍属**不可信历史内容**（DES-SEC-01：形似指令的文字照样可能是），
  调用方不得把它当指令执行，也不得因「已过遮蔽层」而放宽客户端或模型的数据权限。
- 遮蔽层的已知漏检（无键名随机秘密、嵌套编码、值含空格的裸凭据等）在本模块外依然存在：
  这里做的是「外泄面收敛」，不是「敏感信息检测」。

失败与异常取向：`collect()` 对**数据侧**原因只返回闭合枚举（不抛、不回显任何原值），
对**非 `StandardRecord`** 的递入抛固定消息的 `TypeError`（那是 API 误用，与 `SessionCandidateStage.add`
同口径；抛出时尚未建立任何候选，因此没有需要清理的中间态）。
`Exception`（遮蔽层的意外失败等）→ 折成 `internal_failure` 并整批清空，异常对象与消息不外传。
本模块自己**不捕获中断类 `BaseException`**（它也不做捕获它的地方：一次 `collect()` 要么入队要么整批
清空）；中断的「先清空再原样重抛」由调用方（`session_pipeline.run_pi_file_snippets` 的 `finally`）
兑现，中断路径上清理自身的任何失败都就地吞掉，不得顶替用户的原中断。

预算只是输出侧约束：条数/总字符触限只使**片段出口**关成零片段（`release()` 即便拿到
`confirmed=True` 也只交出空元组），它不表示也不能用来改写读侧/解析侧/暂存侧的完整性结论；
本模块不做任何完整性或授权判定，也不报 `complete`。

依赖限制（DES-ARCH-02）：只用标准库与本包的 `models`/`redaction`；不导入 `policy.py`、
`session_stage.py`、来源适配器、`server.py` 或 MCP SDK；不读文件/配置/环境变量，不写日志，
不做缓存，不联网。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .models import SourceLocation, StandardRecord
from .redaction import MAX_OUTPUT_CHARS, redact_text

__all__ = [
    "MAX_SNIPPETS_HARD_LIMIT",
    "MAX_SNIPPETS_PER_FILE",
    "MAX_SNIPPET_TOTAL_CHARS",
    "MAX_SNIPPET_TOTAL_CHARS_HARD_LIMIT",
    "PUBLICATION_REFUSAL_MESSAGES",
    "PublishedSnippet",
    "PublicationRefusal",
    "SnippetCollector",
]

#: 单次文件运行可释放的片段条数默认上限。
MAX_SNIPPETS_PER_FILE = 16

#: 调用方可收紧、不可放松的**输出侧**条数硬顶：与暂存层默认条数上限
#: （`session_stage.MAX_CANDIDATES_PER_SESSION` = 32）同值。片段只能来自已被暂存层接受的候选，
#: 默认预算下抬高它永远碰不到；调用方把 `max_candidates` 放宽（暂存层硬顶为 100）时，
#: 本顶仍守住对外条数，不随阶段预算变大而多放正文。
MAX_SNIPPETS_HARD_LIMIT = 32

#: 片段正文的**总字符代理预算**默认值（遮蔽后字符数累加，非 UTF-8 字节）。
#: 它管的是「一次运行最多往外放多少文本」，与条数是两条独立约束：16 条极短正文不会触它，
#: 5 条各 8 192 字符的长正文会在第 5 条上触它（4 条刚好填满 32 768）。
#: 默认取 32 768 = 解析侧单块上限（`sources/pi.py` 的 `MAX_TEXT_BLOCK_CHARS`）× 4。
MAX_SNIPPET_TOTAL_CHARS = 32_768

#: 总字符预算的硬顶：`MAX_SNIPPETS_HARD_LIMIT × MAX_OUTPUT_CHARS`，即「每条都触到遮蔽层
#: 输出上限」时的最大可能总量——再大就不可能由这两个参数共同产生，放松它等于把条数上限当摆设。
MAX_SNIPPET_TOTAL_CHARS_HARD_LIMIT = MAX_SNIPPETS_HARD_LIMIT * MAX_OUTPUT_CHARS


class PublicationRefusal(StrEnum):
    """片段出口的固定拒绝原因：闭合集合，只含类别，不含正文、路径、会话标识、遮蔽掉的键名。

    新增类别只能改本枚举，不得由调用方用数据侧字符串临时造键（这些值会进入对外错误摘要与日志）。
    """

    REDACTION_REJECTED = "redaction_rejected"  # 遮蔽层拒绝该输入：不产出任何派生文本
    SNIPPET_LIMIT_EXCEEDED = "snippet_limit_exceeded"  # 条数触本模块上限
    TOTAL_CHARS_LIMIT_EXCEEDED = "snippet_total_chars_limit"  # 总字符代理预算触上限
    RECORD_UNUSABLE = "record_unusable"  # 记录/位置形态不可用于片段（不是可核对的真记录）
    INTERNAL_FAILURE = "internal_failure"  # 收集环节的意外失败或不受控返回值
    NOT_CONFIRMED = "not_confirmed"  # 释放请求未拿到完整确认（含误用表态）


#: 固定文案：不拼接输入内容、长度、位置等派生值（同 `policy.REFUSAL_MESSAGES` 的做法）。
PUBLICATION_REFUSAL_MESSAGES: dict[PublicationRefusal, str] = {
    PublicationRefusal.REDACTION_REJECTED: "拒绝：片段未通过输出遮蔽，不释放任何片段。",
    PublicationRefusal.SNIPPET_LIMIT_EXCEEDED: "拒绝：片段条数超出单次运行的上限。",
    PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED: "拒绝：片段总长度超出单次运行的预算。",
    PublicationRefusal.RECORD_UNUSABLE: "拒绝：记录形态不可用于片段生成。",
    PublicationRefusal.INTERNAL_FAILURE: "拒绝：片段收集过程失败。",
    PublicationRefusal.NOT_CONFIRMED: "拒绝：本次运行未取得完整确认，不释放片段。",
}


@dataclass(frozen=True)
class PublishedSnippet:
    """一个可外出的片段：遮蔽后的正文 + 固定来源 ID + 整数位置 + 有限遮蔽元数据。

    `source` 是**调用方给定的固定来源 ID**（本包内为 `sources.pi.SOURCE_PI`），不是记录自报的
    `record.source` 原值；`line_no`/`ordinal` 是解析侧的解码后行序号与同行内序号（不是文件字节
    偏移，压缩流下同样是事件序号）。`redacted_count` 是遮蔽层报出的**实际改写次数**，
    `truncated` 表示该片段被遮蔽层的输出长度上限截过片（`False` 不等于「未遮蔽」）。
    这里没有任何字段是会话侧自由文本的原件。
    """

    snippet: str
    source: str
    line_no: int
    ordinal: int
    redacted_count: int
    truncated: bool

    def as_public_dict(self) -> dict[str, object]:
        """固定键 + 字符串/整数/布尔：值域与本数据类一致，不新增任何派生串。"""
        return {
            "snippet": self.snippet,
            "source": self.source,
            "line_no": self.line_no,
            "ordinal": self.ordinal,
            "redacted_count": self.redacted_count,
            "truncated": self.truncated,
        }


class _Unstated:
    """`release()` 确认参数的「未表态」哨兵类型（与 `session_stage._Unstated` 同一取向）。

    必须是独立类型而不是 `None`/`False` 的复用：`False` 是调用方明确承认「没通过」，
    而「没表态」是一处 API 误用。做成默认值而不是必传参数，是为了让函数体先进入清理分支。
    """

    __slots__ = ()


_NOT_STATED = _Unstated()


def _plain_int(value: object) -> bool:
    """是否为字面 `int`（排除 `bool` 与带隐藏负载的 `int` 子类）。"""
    return isinstance(value, int) and value.__class__ is int


class SnippetCollector:
    """一次文件运行的内部片段收集器：逐条 `collect()`，完整确认之后才允许 `release()`。

    一次性、单一所有者顺序驱动（不提供线程安全，与 `SessionCandidateStage`/`PiLineParser` 一致）。
    生命周期：构造 → 若干次 `collect()` → **恰好一次** `release()`；任何拒绝都会立即清空内部候选
    并把实例推到终态（此后 `collect()` 一律拒绝、只保留首个拒绝码）。`release()` 之后实例关闭，
    返回的元组就是它交出过的全部内容——内部列表同时被清空，不留下跨运行的正文驻留。

    本收集器**不做任何授权判断**：它拿到一条记录时，那条记录的归属轴与核对已由调用方跑过；
    它只保证「过了遮蔽、在两条硬顶内、且在完整确认之后」这三件事。
    """

    __slots__ = (
        "_closed",
        "_max_snippets",
        "_max_total_chars",
        "_refusal",
        "_released",
        "_snippets",
        "_source",
        "_total_chars",
    )

    def __init__(
        self,
        *,
        source: str,
        max_snippets: int = MAX_SNIPPETS_PER_FILE,
        max_total_chars: int = MAX_SNIPPET_TOTAL_CHARS,
    ) -> None:
        """`source` 是对外片段的**固定来源 ID**（由调用方给，本模块不从记录取）。

        两条上限都只能收紧：超出硬顶直接钳制（不抛错，避免用超大参数绕过有界性）。
        `source` 必须是字面 `str` 且非空——它会出现在每个对外片段里，不接受数据侧原值。
        """
        if not isinstance(max_snippets, int) or max_snippets.__class__ is not int:
            raise TypeError("max_snippets must be an int")
        if not isinstance(max_total_chars, int) or max_total_chars.__class__ is not int:
            raise TypeError("max_total_chars must be an int")
        if max_snippets < 1 or max_total_chars < 1:
            raise ValueError("snippet budgets must be positive")
        if not isinstance(source, str) or source.__class__ is not str or not source:
            raise TypeError("snippet source must be a fixed non-empty str")
        self._source = source
        self._max_snippets = min(max_snippets, MAX_SNIPPETS_HARD_LIMIT)
        self._max_total_chars = min(max_total_chars, MAX_SNIPPET_TOTAL_CHARS_HARD_LIMIT)
        self._snippets: list[PublishedSnippet] = []
        self._total_chars = 0
        self._refusal: PublicationRefusal | None = None
        self._closed = False
        self._released = False

    @property
    def max_snippets(self) -> int:
        """实际生效的条数上限（已按硬顶钳制）。"""
        return self._max_snippets

    @property
    def max_total_chars(self) -> int:
        """实际生效的总字符代理预算（已按硬顶钳制）。"""
        return self._max_total_chars

    @property
    def count(self) -> int:
        """当前已收集的片段条数（拒绝或释放后为 0）。"""
        return len(self._snippets)

    @property
    def total_chars(self) -> int:
        """当前已收集片段的遮蔽后字符总数（拒绝或释放后为 0）。"""
        return self._total_chars

    @property
    def refusal(self) -> PublicationRefusal | None:
        """首个固定拒绝码；未拒为 `None`。"""
        return self._refusal

    @property
    def closed(self) -> bool:
        """是否已进入终态（释放过、或已拒绝、或已 `discard()`）。"""
        return self._closed

    @property
    def released(self) -> bool:
        """是否已一次性释放过片段（`True` 即确认曾拿到字面 `True`，与条数无关）。"""
        return self._released

    def _fail(self, reason: PublicationRefusal) -> PublicationRefusal:
        """记下**首个**固定拒绝码、清空内部候选并关闭实例，返回那个码给调用方就地 return。

        只保留首个原因（与暂存层 `_discard()`、`_note_refusal()` 同一口径）：一次清空真正的因由
        不能被后到的收尾动作改写。清空是「不留下前几条还能看」这种误导状态的唯一办法。
        """
        if self._refusal is None:
            self._refusal = reason
        self._snippets = []
        self._total_chars = 0
        self._closed = True
        return self._refusal

    def collect(self, record: object) -> PublicationRefusal | None:
        """把一条已过准入与核对的记录变成一个内部脱敏候选，返回当前固定拒绝码。

        返回值即结论：`None` 表示已收下；否则是**首个**拒绝码（粘性，后续记录不再判定）。
        任何拒绝路径都先清空内部候选——拒绝之后不存在「已收集的那几条还能不能看」这种状态。

        顺序（遮蔽在前、预算在后）：形态 → `redact_text` → 遮蔽结论可用 → 条数 → 总字符 → 入队。
        遮蔽排在预算之前，所以**被预算挡在门外的那条也已经遮蔽过了**：不存在「未遮蔽的文本
        因为装不下而被丢掉」这种遗留，也不存在「先切片再遮蔽」的漏检路径（遮蔽层自身的顺序保证）。
        """
        if self._closed:
            return self._refusal or PublicationRefusal.NOT_CONFIRMED
        if self._refusal is not None:
            return self._refusal
        if not isinstance(record, StandardRecord):
            # 契约误用（递进来的不是本包记录）：抛出前仍必须先清空并关闭——调用前可能已经收下过
            # 合规记录，误用不得把那些候选留在内存里，也不得把实例留在「还能再试一次」的状态。
            # 与 `release()` 未表态分支同一口径：先 `_fail` 再抛固定消息的 TypeError。
            self._fail(PublicationRefusal.RECORD_UNUSABLE)
            raise TypeError("snippet collection only accepts StandardRecord instances")
        location = record.location
        if not isinstance(location, SourceLocation) or location.__class__ is not SourceLocation:
            return self._fail(PublicationRefusal.RECORD_UNUSABLE)
        if not (_plain_int(location.line_no) and _plain_int(location.ordinal)):
            return self._fail(PublicationRefusal.RECORD_UNUSABLE)
        try:
            outcome = redact_text(record.text)
        except Exception:
            # 遮蔽层的意外失败：消息可能含正文片段，就地吞掉，只降为固定码。
            return self._fail(PublicationRefusal.INTERNAL_FAILURE)
        if not outcome.usable or outcome.text is None:
            # 遮蔽拒绝时它不产出任何派生文本；本模块不重试、不退化成前缀处理。
            # 入队记录的 `text` 已过暂存层的「字面 str」形态门，`redact_text` 的产出同样是字面 `str`，
            # 因此这里不再重做一次子类校验。
            return self._fail(PublicationRefusal.REDACTION_REJECTED)
        text = outcome.text
        size = len(text)
        if len(self._snippets) + 1 > self._max_snippets:
            return self._fail(PublicationRefusal.SNIPPET_LIMIT_EXCEEDED)
        if self._total_chars + size > self._max_total_chars:
            return self._fail(PublicationRefusal.TOTAL_CHARS_LIMIT_EXCEEDED)
        try:
            self._snippets.append(
                PublishedSnippet(
                    snippet=text,
                    source=self._source,
                    line_no=location.line_no,
                    ordinal=location.ordinal,
                    redacted_count=outcome.redacted_count,
                    truncated=outcome.truncated,
                )
            )
            self._total_chars += size
        except Exception:
            # 入队（构造/append/计数）的意外失败同样先清空再降为固定码。本分支是普通
            # `except Exception`：MemoryError/RecursionError 继承 Exception，一并接住；
            # GeneratorExit/KeyboardInterrupt/SystemExit 继承 BaseException，不吞——那是进程级
            # 信号，不该由暂存层拦截。入队失败时不预设「append 未生效」：构造可能已产出对象而
            # append 失败，也可能 append 成功而后续计数失败，两种半成品都靠 _fail 整表清空兜住。
            return self._fail(PublicationRefusal.INTERNAL_FAILURE)
        return None

    def discard(self, reason: PublicationRefusal) -> None:
        """调用方宣告这次运行不可发布片段：清空候选、记下固定码、关闭实例（幂等）。

        `reason` 只接受 `PublicationRefusal` 成员（同 `ParseStats.note()` 的约束），不接受数据侧
        字符串。已有拒绝码时不覆盖——首个原因是本次清空真正的因由，后到的只是收尾动作。
        """
        if not isinstance(reason, PublicationRefusal):
            raise TypeError("snippet discard reason must be a PublicationRefusal category")
        if self._closed:
            return
        self._fail(reason)

    def release(self, *, confirmed: object = _NOT_STATED) -> tuple[PublishedSnippet, ...]:
        """唯一的片段出口：**只接受字面 `True`**，一次性交出全部脱敏候选。

        `confirmed` 是调用方对本次运行的终局表态（两轴授权 + 完整性 + 核对全部通过）。
        非字面 `True` 一律不释放：未表态（哨兵）先清空、关闭，再抛固定消息的 `TypeError`（误用
        不得把已收集的片段留在内存里，也不得把实例留在「还能再试一次」的状态）；字面 `False` 与
        `1`/`"y"` 一类不受控真值同出口：清空、关闭、交出空元组（表态本身合法，不报错）。
        已拒绝的实例**保留首拒码**（`not_confirmed` 不顶替它）并交出空元组；已释放过的实例再调则记
        `not_confirmed` 并交出空元组——释放机会只有一次。

        本方法**不接受回调、不逐条外递**：结果只能作为返回值一次性交给调用方。
        """
        if confirmed is _NOT_STATED:
            # 未表态：先把内部候选清干净，再报错——误用不得把已收集的片段留在内存里。
            # `_fail` 不改写已定的首拒码，所以之前因遮蔽/预算被拒的实例仍报那个真正的原因。
            self._fail(PublicationRefusal.NOT_CONFIRMED)
            raise TypeError("snippet release requires an explicit confirmed bool")
        if confirmed is not True:
            # 只有字面 `False` 是明确表态「没通过」；`1`/`"y"` 这类不受控真值替不了调用方拍板，
            # 与字面 `False` 同方出口：清空、关闭、交出空元组（不报错，因为表态本身合法）。
            self._fail(PublicationRefusal.NOT_CONFIRMED)
            return ()
        if self._closed or self._refusal is not None or self._released:
            self._fail(PublicationRefusal.NOT_CONFIRMED)
            return ()
        # 冻结外递结果与内部清空是同一段收尾，必须整体成功：`tuple()` 一旦在列表实际变异时抛出，
        # 就地退回安全终态（清空候选、关闭实例），**不置 `_released`**——没成功外递过就不算释放过，
        # 但重试释放也拿不到东西（首拒前缀规则保证 `_fail` 只记 internal_failure，后续调用一律空元组）。
        try:
            released = tuple(self._snippets)
        except Exception:
            # 固定降级路径：不重抛、不重试、不回执原文。`_released` 保持 False，
            # `released` property 保持 False（_closed 已 True）——调用方只看返回值是不是空元组。
            self._fail(PublicationRefusal.INTERNAL_FAILURE)
            return ()
        # 交出即清空：内部不留第二份，同一批候选也不会被释放第二次。
        self._snippets = []
        self._closed = True
        self._released = True
        return released
