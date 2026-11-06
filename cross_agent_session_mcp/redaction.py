r"""输出遮蔽层：把不可信文本中常见凭据形态替换为固定占位（DES-SEC-01「结果片段做常见凭据遮蔽」）。

服务于 DES-API-01 的 `snippet` 与 `read_session_context` 输出、DES-ADAPTER-01 的「解析错误仅
输出经过脱敏的原因」，以及 DES-ARCH-05「识别并遮蔽常见凭据形态，但不宣称能检测所有敏感信息」。
本模块是**纯输出侧组件**：调用方（检索层、上下文层、错误摘要）把已经准备要发布的文本交给它，
拿回可安全外出的文本与有限元数据。它不判断能否读取，也不判断读多少。

遮蔽不是授权
- 本模块**不实现任何访问控制**：不知道 scope、项目、来源与路径，也不校验调用方是否有权拿到这段
  文本。`policy.py` 的存储授权与归属核对才是授权；本层只在授权之后减少外泄面。
- 覆盖范围是「常见凭据**形态**」，不是全部敏感信息：不含业务字段名的随机秘密、值中夹带空格的
  凭据、加密前的口令、图片/二进制内的密钥都无法保证识别。调用方不得因「已过本层」而放宽客户端
  或模型的数据权限（DES-SEC-01）。
- 输出仍是**不可信历史内容**：其中文字可能形似指令，调用方不得当作当前用户指令执行。

先遮蔽、后截片
------------

顺序是本模块的核心约束：任何截断都发生在**完整输入的识别与替换之后**。若在遮蔽前截片，
被切断的凭据只剩前缀，形态识别会漏检（`sk-` 前缀被切掉半截就不像密钥了），等于把漏检写进
正常流程。因此输入必须是**有界的完整**文本：超过 `MAX_INPUT_CHARS` 的输入整体拒绝，不退化成
「截个前缀假装处理过了」——前缀截断的输出会被调用方误认为可发布。同一道理适用于规则内部：
已识别的凭据**整体**替为占位，命中后不再按长度二次切段。长度阈值只用来决定一条规则**是否**
算这个形态（引号串长度、私钥块体长度、裸认证串长度），不决定遮多少：值段从开界符一直写到该
分支能确定的边界（闭合界符之后或行尾），因此不存在只遮前截的输出。

截片发生在替换之后，因此输出的任意前缀都不含原凭据字符：切点最坏落在固定占位串中间，留下
半个占位。这种情况在截断后剥掉残缺占位尾部（宁可少留几个普通字符，也不输出一个看着像被
截断的秘密的尾巴）。

硬限与固定拒绝
------------

- `MAX_INPUT_CHARS`：单次处理的输入字符上限，超限 → `input_too_large`。规则按固定顺序各扫一遍，
  单次调用的总工作量因此受“规则数 × 输入上限”约束（未实测，不作为严格的线性上界声明）；
  上限取值见常量注释。
- `MAX_OUTPUT_CHARS`：输出字符硬上限，超出即截片并置 `truncated=True`。
- 非 `str` 输入 → `input_not_text`；含 NUL 或无法编码为 UTF-8 的代理码点（异常编码的典型痕迹）
  → `input_encoding_invalid`。
- 三条拒绝路径都返回 `text=None`：拒绝时不产出任何派生文本，也不回显输入的任何片段。错误信息取自
  固定文案表（同 `policy.REFUSAL_MESSAGES` 的做法），不拼接长度以外的输入内容。

返回的元数据只有有限几项：状态、遮蔽次数、是否截片、输入字符数、拒绝码。全部是枚举或整数，
不含原敏感值、不含被遮蔽的键名，可安全进入日志与对外 `coverage`/错误摘要（DES-SEC-01）。

规则集合（闭合，不承诺通用 DLP）
------------

规则按固定顺序单次串联：每条规则读取上一条规则改写后的结果；不迭代至不动点。识别的形态：私钥块（PEM 与 PGP armor 头）、
`Authorization`/`Cookie` 等凭据头的行内值、
常见服务令牌字面形态（OpenAI/Anthropic、GitHub、Slack、AWS、Google、GitLab、Stripe、JWT）、带敏感键名的赋值
（JSON `"k": "v"`、嵌在字符串里的一层转义 JSON `\\\"k\\\": \\\"v\\\"`、YAML/INI/TOML `k: v`、shell/env `K=V`、HTML/XML 属性、`- k: v`）、
URL 的 `user:pass@` userinfo 整段（保守遮到最后一个可判界的 `@`，主机名保留）与敏感查询/片段参数（`?k=v`、`&k=v`、`#k=v`）、无键名的 `Bearer`/`Basic` 一类认证串。

赋值规则**先定键、后定值**：正则只匹配「键名 + 分隔符」，值边界由 `_value_span` 就地判定。非敏感键因此
天然停在键名处，既不消费自己的值，也不波及同级后续字段（引号、撇号、反引号都不能把兄弟字段划进值里）。
命中敏感键时保留键名、分隔符与闭合引号，只替值，因此 JSON/YAML 结构仍可辨认；其余规则整段替为占位。

值边界的取法（决定“整段”的范围，不存在部分遮蔽）：
- 以引号开头 → 只与**同一个**引号字符闭合（反斜杠转义跳过；相邻两个同引号按 YAML/C 风格的双写
  转义算值内文本并继续往后扫），闭合引号一并保留。
- 以 `\\\"` 开头（JSON 被再嵌一层时的转义引号）→ 闭合界符必须是**另一个单个反斜杠 + 引号**，
  两侧 `\\\"` 保留（反斜杠是结构不是凭据内容）；遇到裸引号、反斜杠连串、更深一层转义，或闭合处
  后面紧贴非结构字符（无法安全判定边界）则吞到行尾。只支持这一层常见转义，不解析转义文本（见“已知不足”）。
- 闭合界符**之后**必须是本行结尾或结构分隔符（空白与 `,;:)]}`）才算边界确定；紧贴其它字符
  （`PASSWORD=\\"abc\\"def`）说明这里不是干净的引号收尾，整个闭合判定作废，与不闭合同路。
- 引号在本行内不闭合、闭合边界判不定、或长于 `MAX_QUOTED_VALUE_CHARS` → 连同开引号吞到行尾
  （结构已坏，宁多遮蔽）。
- 无引号值（shell/env/YAML/日志/裸查询串）→ 取到行尾。`, ) '` 等都是普通口令字符，在那里停止就会把秘密
  的后半截留在输出里；宁可连带遮蔽同一行后续字段，不做部分遮蔽。
- 键名两侧允许出现连续转义反斜杠（`\\\"password\\\": \\\"v\\\"`、再深一层也认键名）：只放宽键名的匹配范围，
  值边界仍按上条就地判定——反斜杠多于一个时值判定不了界，走吞到行尾。两处反斜杠串的**封顶不同**：
  键名与分隔符之间的那一串封顶 `MAX_KEY_NAME_CHARS`（128）且占有一——那一串的起点被键名结尾钉住，
  只能一次吃完，超出 128 就认不出一条干净的「键 + 分隔符」；**键名前**的那一串靠正则引擎沿输入
  滑动起点识别，并没有同样封顶（一条更长的反斜杠连串会在靠后位置以 ≤128 的尾段起匹配，所以
  键名仍能被认出），它同样占有、不交还字符。本层不拿它们当严格的复杂度上界声明。
- 空白值（键后直接换行）→ 不产出占位，不计遮蔽次数。
- 无界符的值（已替为占位、或吞到行尾的形态）：占位守卫比较的是**剥掉开界符后的值内文本**，
  而不是“开界符 + 占位 + 开界符”拼出的整串：后者在转义形态下永远不相等，会重复计数。

一旦认定“这里是凭据”，就把**整个值**替为占位：长度阈值只用来判定“多长的连续串还算这个形态”
（以及区分凭据与整段正文），不用来限制遮蔽范围。已知的安全倒向：宁可多遮蔽（整行、整块、
该处之后的正文），不可只遮蔽前截。

键名判定用**分段比对**而不是子串匹配：先按 `_ - . ` 与驼峰边界切段，再要求某一段（或相邻两段
拼接）命中固定敏感词表。这样 `apiKey`、`X-Api-Key`、`AWS_SECRET_ACCESS_KEY_ID` 会命中，
`tokenizer`、`keyboard`、`monkey` 与单独的 `key: 值` 不会——避免把正常文本大面积遮蔽成噪声。
`key` 不单独入词表（含义过泛），复合形式靠相邻两段拼接命中。`Authorization`/`Cookie` 头部按
行尾为界整体遮蔽，单行 JSON 里这类字段之后的内容会被一并遮蔽：方向是宁多遮蔽不少遮蔽。

规则顺序不是实现细节而是正确性条件，因为每条规则都在前一条改写后的文本上跑：
1. 凭据头/令牌字面形态在前，避免其内部文本被后面的规则切成碎片。
2. 查询与片段参数在赋值后：真敏感参数的行内值已由赋值规则取到行尾，本规则只做兜底与结构保留（键名
   不在赋值字符集内的 `?k=v`、`#k=v` 变体），同一处不重复计数。
3. 赋值在认证串（`Bearer`/`Basic`）与 URL 用户信息前：`X-Auth: Bearer abc123`、`token: https://user:pass@host`
   这类先整段遮蔽，不会出现“先把凭据改写成占位、再让赋值与 URL 规则在占位后面失配”的漏检；
   无头部的裸 `Bearer xxx` 仍由认证串兜住。
4. “已遮蔽”的判据是**值内文本**（剥掉开界符与占位后为空）而不是整段字符串相等：占位只占值的一小段时
   不算已遮蔽，仍整段替换。反过来，前面规则留下的占位不会挡住后面的整值遮蔽——URL 用户信息把占位串的全部
   字符当作合法段内字符，`https://[redacted]:pw@host` 仍会把 `:pw` 一起遮掉；整段已是纯占位时按已遮蔽跳过，不改写不计次。`redacted_count` 只在文本真的
   被改写时增加；无键名的令牌字面形态不进入键名正则（键名字符类不含 `-` 且量词占有），`sk-…`/`ghp_…`
   不靠顺序也不会被部分改写。
占位守卫（“该处已遮蔽过”的判据）集中在 `_value_is_masked`、`_mask_keep_head` 与 `_mask_query_params`：
它们比较的都是**值内文本**（剥掉开界符、再剥掉占位与首尾空白后是否为空），不用固定的字符串相等
反比输出形式，因此既能认出“整值已是占位”而不重复计数，也不会因为占位只占值的一小段而放行。
`redacted_count` 因此等于文本**实际被改写的次数**，而不是命中次数。
规则顺序与阈值都是细节，对外契约只有 `redact_text` 与 `RedactionOutcome`。

依赖限制（DES-ARCH-02「范围保护」同源）：只用标准库 `re`/`dataclasses`/`enum`/`collections.abc`；
不导入 `policy.py`、`models.py`、`server.py` 或任何来源适配器；不读文件、不读配置与环境变量、
不写日志、不做缓存；无状态纯函数，同样的输入永远得到同样的输出。

本增量状态（不得理解为功能已完成）
------------

- 已实现：`redact_text`、`RedactionOutcome`、`RedactionStatus`、`RejectionCode`、固定文案表、
  上述规则集合与硬限常量。私钥块（PEM 与 PGP armor，含只有 BEGIN 头的不完整块）的吞并范围：有 END
  时按定界符，无 END 时到输入结尾（输入本身已封顶）。
- 接线：片段长度上限与遮蔽已经由 `publication.py`（`redact_text` 逐条完整遮蔽 + 两条硬顶）接入
  `file_search.py`/`session_context.py` 的发布路径；`server.py` 不直接调用本模块。
- 未验证：规则命中与漏检范围主要由静态推导确立。URL 整段遮蔽的回归见 `tests/test_redaction.py`（2026-11-01 已写入，本轮按用户指令未执行）；行为结论待后续运行与静态审查复核，不以文件存在声称已验证。
- 运行前提：Python 3.11+（`{m,n}+` 占有型量词、`StrEnum`）。本轮不改任何依赖/打包文件。
- 扫描结构（两阶段）：第一阶段按 `_RULES` 的固定顺序在整段输入上逐条改写；第二阶段只属于赋值规则——
  正则定「键名 + 分隔符」，`_value_span` 就地定值界。非敏感键停在键名处，空白值（键后直接换行）
  不遮蔽也不计次。占位去重靠比较**值内文本**（`_value_is_masked`/`_mask_keep_head`/`_mask_query_params`），
  不是幂等正则守卫；`redacted_count` 等于实际改写次数。
- 已知不足（真正未覆盖的形态）：值中含空格的裸凭据；无键名且不属于已知形态的随机秘密；嵌套编码
  （Base64/URL 编码后再放的口令）；JWT 的**声明内容**（要 Base64 解码才能判定，本层不解码）；形如
  `-----BEGIN PGP MESSAGE-----` 的加密消息块（不是私钥，不吞并）；弱方案词 `token` 后接空白加短英文词
  （如“token 数字”“token expires”）不识别——同位置的 `token: 值` 由赋值规则整行覆盖；**已遮蔽位置以外不再
  递归**——非敏感键（如 `note: "..."`）的整段值被当作普通文本，其内部不命中任何规则的嵌入凭据
  无法识别（键名形态的内嵌凭据已由赋值规则在转义形态下命中）；赋值规则认键名时，**键名与分隔符
  之间**的连续转义反斜杠封顶 `MAX_KEY_NAME_CHARS`（128）个（`_KEY_ASSIGN_RE` 的第二处
  `(?:\{1,128}+)?`，与键名长度同一个上限；超出就认不出这个键，退化为普通文本而不是报错），
  而**键名前**的那一串靠引擎滑动起点识别，**没有**同样的封顶（长连串的尾段仍可作为匹配起点），
  两者的量词都是占有型且不解析转义文本本身；只支持**一层**常见转义的值形式（`\\\"key\\\": \\\"value\\\"`）：再下一层
  （`\\\\\\\"k\\\\\\\"` 之类）不解析转义文本，值退化为吞到行尾的整段遮蔽，安全方向不变；引号串闭合处后面紧贴
  非结构字符、或同引号双写串在本行内不收尾时同样退化为吞到行尾（该行后续字段一并遮蔽：低优先的
  误遮代价，换来不留后半截秘密）；
  URL 的**非法 userinfo** 中含空段的罕见形态（`scheme://@host`、`a@@b@` 的前导空段）不扩展——合法 userinfo 内的 `,`/`;`/`'` sub-delims 与百分号编码内的 `:` 已由整段保守遮蔽覆盖；跳行赋值（YAML 块标量）
  与超长被截断的输入由调用方负责给全。
- 仍不在本层范围：OAuth 回调体的表单/HTML 解析（其中 `#access_token=` 片段参数与 `?k=v` 参数已按参数遮蔽）。
  遮蔽次数是**实际改写次数**，不是敏感度评估：本层不承诺任何检出率或准确率。
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "MAX_INPUT_CHARS",
    "MAX_KEY_NAME_CHARS",
    "MAX_OUTPUT_CHARS",
    "REDACTION_PLACEHOLDER",
    "REJECTION_MESSAGES",
    "RedactionOutcome",
    "RedactionStatus",
    "RejectionCode",
    "redact_text",
]

#: 遮蔽用的固定占位：不含任何原值字符，也不含敏感词根（不会被本模块的键名规则再次命中）。
REDACTION_PLACEHOLDER = "[redacted]"

#: 输入字符硬上限：65 536。解析侧单个文本块上限为 32 768（`sources/pi.py`），此值留出 2× 余量，
#: 允许调用方把相邻块或整条错误上下文一起送进来。超限**整体拒绝**，不做前缀处理。
MAX_INPUT_CHARS = 65_536
#: 输出字符硬上限：8 192。遮蔽完成后仍超此长度才截片；调用方若只需更短片段，自行在结果上再截。
MAX_OUTPUT_CHARS = 8_192
#: 参与键名判定的最大长度：更长的名字不属于任何已知配置风格，直接按不敏感处理（不遮蔽）。
MAX_KEY_NAME_CHARS = 128
#: 引号内值的最大匹配长度（`MAX_INPUT_CHARS` 的 1/16）：超过这个长度的引号串不像凭据而是整段
#: 正文，不再按闭合引号串处理；但同位置的无引号/不闭合分支仍会按行兜住（见 `_value_span`），
#: 所以命中的凭据值从来不会被部分遮蔽。
#: 未设上限的一类：查询参数值与令牌字面形态。它们的字符类本身会在空白/分隔符处自然
#: 停止，取整个连续串不会泛泛吞正文；反之若给它一个上限（曾为 512），超上限部分会原样
#: 留在输出里，那就是一个可预测的漏遮蔽缺口。
MAX_QUOTED_VALUE_CHARS = 4_096
#: 私钥块正文最大长度（含换行）：适用于**有 END 定界**的完整块。完整的 RSA/EC PEM 块体在
#: 数 KB 量级，8 KiB 留出余量；同时封顶一次匹配的长度。无 END 的情况不受此限（见规则注释）。
MAX_PRIVATE_KEY_BODY_CHARS = 8_192

_QUOTE = r"[\"'`]"
#: 判值边界时用的引号字符集（与 `_QUOTE` 同一套，只是改为成员测试）。
_QUOTE_CHARS = frozenset("\"'`")


class RedactionStatus(StrEnum):
    """处理结果的闭合状态；对外可直出，不含原文。"""

    CLEAN = "clean"  # 未发现本层已知的凭据形态（不等于无敏感信息）
    REDACTED = "redacted"  # 至少替换了一处
    REJECTED = "rejected"  # 输入不合法：text 为 None，没有任何可发布派生文本


class RejectionCode(StrEnum):
    """拒绝原因码：闭合集合，可安全用于日志与错误摘要（不含任何输入值）。"""

    INPUT_NOT_TEXT = "input_not_text"
    INPUT_TOO_LARGE = "input_too_large"
    INPUT_ENCODING_INVALID = "input_encoding_invalid"


#: 固定文案：不拼接输入内容，也不拼接长度、位置等派生值（DES-SEC-01）。
REJECTION_MESSAGES: dict[RejectionCode, str] = {
    RejectionCode.INPUT_NOT_TEXT: "拒绝：输入不是文本，不产出任何派生内容。",
    RejectionCode.INPUT_TOO_LARGE: "拒绝：输入超出单次可完整扫描的上限，不做前缀处理。",
    RejectionCode.INPUT_ENCODING_INVALID: "拒绝：输入含无法编码为 UTF-8 的字符。",
}


@dataclass(frozen=True)
class RedactionOutcome:
    """一次遮蔽的结果：文本 + 有限元数据。

    `text` 为 `None` 只在 `status is REJECTED` 时出现。`redacted_count` 与 `input_chars` 是整数，
    不揭示被遮蔽的是什么形态；`truncated` 表示输出因长度上限被截过片（与是否遮蔽过互不蕴含）。
    """

    text: str | None
    status: RedactionStatus
    redacted_count: int
    truncated: bool
    rejection: RejectionCode | None
    input_chars: int

    @property
    def usable(self) -> bool:
        """结果是否可作为输出依据（被拒时调用方必须改用自己的固定错误文案）。"""
        return self.status is not RedactionStatus.REJECTED

    @property
    def reason(self) -> str:
        """拒绝时的固定说明；其它状态为空串。"""
        return REJECTION_MESSAGES[self.rejection] if self.rejection else ""


def redact_text(text: str) -> RedactionOutcome:
    """遮蔽整段输入中的常见凭据形态，再按输出上限截片。

    参数是本层唯一的外部数据源：只接受 `str`，长度 ≤ `MAX_INPUT_CHARS`。返回的 `text` 不含任何
    已识别凭据的字符，也不含被切断的半个占位串。本函数不改变输入的其余文本（不重排空白、
    不改大小写、不解析 JSON、不把全角降为半角），因此可直接复用在片段、上下文窗口与错误摘要
    三种输出上；也正因为不改写编码形式，它不能处理藏在嵌套编码里的秘密（见模块文档）。
    """
    rejection = _input_rejection(text)
    if rejection is not None:
        return RedactionOutcome(
            text=None,
            status=RedactionStatus.REJECTED,
            redacted_count=0,
            truncated=False,
            rejection=rejection,
            input_chars=len(text) if isinstance(text, str) else 0,
        )

    redacted_count = 0
    result = text
    for apply_rule in _RULES:
        result, hits = apply_rule(result)
        redacted_count += hits

    truncated = len(result) > MAX_OUTPUT_CHARS
    if truncated:
        result = _drop_partial_placeholder(result[:MAX_OUTPUT_CHARS])

    status = RedactionStatus.REDACTED if redacted_count else RedactionStatus.CLEAN
    return RedactionOutcome(
        text=result,
        status=status,
        redacted_count=redacted_count,
        truncated=truncated,
        rejection=None,
        input_chars=len(text),
    )


def _input_rejection(text: object) -> RejectionCode | None:
    """输入边界检查：类型、有界性与编码。异常一律给固定原因码，不尝试修复输入。"""
    if not isinstance(text, str):
        return RejectionCode.INPUT_NOT_TEXT
    if len(text) > MAX_INPUT_CHARS:
        return RejectionCode.INPUT_TOO_LARGE
    if "\x00" in text:
        return RejectionCode.INPUT_ENCODING_INVALID
    if not text.isascii():
        # 孤立代理码点只能在这里被发现：它会在下游编码时抛错，或在替换后留下假字符。
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            return RejectionCode.INPUT_ENCODING_INVALID
    return None


def _drop_partial_placeholder(text: str) -> str:
    """剥掉结尾的残缺占位串：切点落在占位中间时，不留下半截冒充被截断的秘密。"""
    for size in range(len(REDACTION_PLACEHOLDER) - 1, 0, -1):
        if text.endswith(REDACTION_PLACEHOLDER[:size]):
            return text[:-size]
    return text


# ---------- 键名判定 ----------

#: 敏感词根（小写、整段比对）。不收录单独出现时含义过泛的 `key`（`tokenizer`/`keyboard`/
#: 普通映射的 `key` 都不该被遮蔽）；`api_key`、`access_token` 这类复合形式由相邻两段拼接命中，
#: 因此需同时列出其拼合后的完整形式。
_SENSITIVE_KEY_WORDS = frozenset(
    {
        "accesstoken",
        "apikey",
        "auth",
        "authkey",
        "authorization",
        "authtoken",
        "bearer",
        "bearertoken",
        "cert",
        "certificate",
        "clientsecret",
        "cookie",
        "credential",
        "idtoken",
        "pass",
        "passwd",
        "passphrase",
        "password",
        "privatekey",
        "pwd",
        "refreshtoken",
        "secret",
        "secretkey",
        "sessionkey",
        "sessiontoken",
        "signingkey",
        "signature",
        "token",
        "webhook",
    }
)
_KEY_SEPARATORS = re.compile(r"[_\-.:\s]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _in_sensitive_words(value: str) -> bool:
    """词表命中判定：接受规则内的复数形式（`tokens` → `token`），不做其它变形。"""
    if value in _SENSITIVE_KEY_WORDS:
        return True
    if len(value) > 3 and value.endswith("s"):
        return value[:-1] in _SENSITIVE_KEY_WORDS
    return False


def _is_sensitive_key(name: str) -> bool:
    """判断字段名是否指向凭据：按分隔符与驼峰切段，段或相邻两段拼接命中敏感词根即为是。

    宁可少认一个奇怪的拼法，也不把普通文本遮蔽成噪声：因此用整段比对。`apiKey`（切段 api+key
    拼成词表里的 `apikey`）与 `X-Api-Key` 都命中，`tokenizer`、`keyboard` 不命中。
    超长名字（> `MAX_KEY_NAME_CHARS`）不属于任何已知配置风格，按不敏感处理。
    """
    if not name or len(name) > MAX_KEY_NAME_CHARS:
        return False
    parts = [
        piece.lower()
        for chunk in _KEY_SEPARATORS.split(name)
        for piece in _CAMEL_BOUNDARY.split(chunk)
        if piece
    ]
    for index, part in enumerate(parts):
        if _in_sensitive_words(part):
            return True
        if index + 1 < len(parts) and _in_sensitive_words(part + parts[index + 1]):
            return True
    return False


# ---------- 规则 ----------

#: 私钥块分两步。第一条：按定界符取整块（惰量词，有 END 时只吃掉块本身，后面的正文不受影响）。
#: 第二条：只剩 BEGIN 没有 END（日志/片段里常被切断）时，从头部起吞到**输入结尾**：此时无法
#: 确定块体在哪里结束，给它一个小于输入上限的固定长度会把后半截 base64（即密钥本身）留下。
#: 输入已由 `MAX_INPUT_CHARS` 封顶，所以这一吞并不引入无界工作量，代价是调用方看到该处之后的
#: 正文丢失：宁可多吞一段正文，不可漏掉半截密钥。
#: PGP 的 armor 头在 `BEGIN` 与 `PRIVATE KEY` 之间多了 `PGP `，尾部多了 ` BLOCK`；PEM 没有。
#: 两类共用一个头部模式（结束行同样允许 ` BLOCK`），否则 PGP 私钥块整体失配、块体原样输出。
#: 只有头部没有结束行的情况由 `_PRIVATE_KEY_UNTERMINATED_RE` 兜住（同一条模式，END 缺失不影响）。
_PRIVATE_KEY_HEADER = r"-----BEGIN[A-Z ]{0,32}PRIVATE KEY(?: BLOCK)?-----"
_PRIVATE_KEY_FOOTER = r"-----END[A-Z ]{0,32}PRIVATE KEY(?: BLOCK)?-----"
_PRIVATE_KEY_BLOCK_RE = re.compile(
    _PRIVATE_KEY_HEADER
    + rf"[\s\S]{{0,{MAX_PRIVATE_KEY_BODY_CHARS}}}?"
    + _PRIVATE_KEY_FOOTER
)
_PRIVATE_KEY_UNTERMINATED_RE = re.compile(_PRIVATE_KEY_HEADER + r"[\s\S]*")

#: 凭据类头部字段：值取到行尾（整行，不截前缀），所以**不要求**同行有换行符：
#: 若写成行类加量词而无行尾锚定，单行长 JSON 失配后回溯会退到头部名中间再试下一个起点，
#: 代价随行高与头部出现次数相乘。行尾锚定消除这种“同一处反复交还字符”的尝试。值至少 1 个字符：
#: 避免对空值（`Authorization: `）凭空写一个占位串；占位守卫保证重复处理不二次计数。
_CREDENTIAL_HEADER_RE = re.compile(
    r"(?i)(?P<head>\b(?:proxy[-_]?authorization|authorization|cookie|set[-_]?cookie)\b[ \t]*[:=][ \t]*)"
    r"(?P<value>[^\r\n]{1,})"
)

#: `Bearer`/`Basic` 一类认证串（不带头部名时也要遮蔽，如 curl 参数与拼接出的调试串）。
#: 量词用占有型（`*+`）封顶：普通贪心量词在后继失配时会交还字符，使下一字符成为新起点，
#: 在长 base64 文本上形成二次方回溯。占有型消除这一类同处重试。
_CREDENTIAL_SCHEME_RE = re.compile(
    r"(?i)(?P<head>\b(?:bearer|basic|digest|ntlm|aws4-hmac-sha256|token)\b)"
    r"(?P<sep>[ \t]*+[:=][ \t]*+|[ \t]+)"
    r"(?P<cred>[A-Za-z0-9._~+/=%\-]{2,512})"
    r"[A-Za-z0-9._~+/=%\-]*+"
)
#: 无 `:`/`=` 分隔写法下认定“这是个令牌”的形状：长度下限（不要求含数字，
#: 十六进制与纯字母随机串同样常见）。短于下限的合法短令牌靠 `_is_bare_credential` 的形状判定兜住。
_SCHEME_BARE_MIN_CHARS = 16
#: 短于 `_SCHEME_BARE_MIN_CHARS` 时的下限：再短就不像完整凭据（像计数器、版本号）。
_SCHEME_BARE_SHORT_MIN_CHARS = 6
#: 非英文词的硬特征：数字或令牌分隔符。`Bearer abc123`、`Basic YWJjZA==` 这类短而合法的
#: 值不会因 16 的下限漏掉；正文里的 `bearer 某个东西` 仍不误伤（纯字母）。
_CREDENTIAL_SHAPE_RE = re.compile(r"[0-9_\-=+/\.]")


def _is_bare_credential(value: str) -> bool:
    """方案词后空白分隔的值是否像凭据（有 `:`/`=` 分隔时无需此判定）。"""
    if len(value) >= _SCHEME_BARE_MIN_CHARS:
        return True
    return (
        len(value) >= _SCHEME_BARE_SHORT_MIN_CHARS
        and _CREDENTIAL_SHAPE_RE.search(value) is not None
    )


#: 常见服务令牌的固定字面形态：与键名无关，出现在任何位置都遮蔽。量词只有下限、没有上限：
#: 字符类已限定在令牌字母表内，贪婪匹配必在下一个非令牌字符处自然结束；给了上限就会让
#: 比上限更长的真实密钥被切掉尾巴（前半被遮蔽、后半原样输出）。
_SERVICE_TOKEN_RE = re.compile(
    r"(?:"
    r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{16,}"
    r"|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{20,}"
    r"|\bxox[baprs]-[A-Za-z0-9\-]{6,}"
    r"|\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{12,}"
    r"|\bAIza[0-9A-Za-z_\-]{20,}"
    r"|\bglpat-[A-Za-z0-9_\-]{16,}"
    r"|\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{10,}"
    r"|\bya29\.[A-Za-z0-9_\-]{20,}"
    # JWT：三段 base64url。段内量词用占有型（`{8,}+`）：`.` 不在令牌字母表内，贪心必自然
    # 停在段分隔符处，占有型仅消除“交还字符后继续试”的回溯；起点前的环后断言把匹配锁在
    # 令牌边界上，`eyJ` 连续串（`eyJeyJeyJ…` 无分隔点）不会在每个内部 `eyJ` 处重跑一遍长串，
    # 从而避开这一处重跑（仅这一条模式的回溯开销，不构成本层的复杂度保证）。
    r"|(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}+\.eyJ[A-Za-z0-9_\-]{8,}+\.[A-Za-z0-9_\-]+"
    r")"
)

#: 键名/分隔符的匹配（**故意不含值分支**）：键名只用一个字符类、占有型量词（`{1,128}+`，Python 3.11+，
#: 与本项目已用的 `StrEnum`/`datetime.UTC` 同代）：键名字符与后面的引号/`:`/`=` 互斥，因此不存在
#: “先吞进敏感词根、再回推出长前缀”的多路径（否则超长令牌流上会退化成二次方扫描）。值边界交给 `_value_span` 就地判定，所以非敏感键只消费
#: 「键名 + 分隔符」，不吞值、不影响同级后续字段。键名是否真敏感由 `_is_sensitive_key` 判定。
#: 键名两侧允许出现连续转义反斜杠与引号（`\\\"password\\\": \\\"v\\\"`：嵌在 JSON 字符串里的 JSON）。
#: 反斜杠串只放宽**键名**匹配范围（多层转义的键名也能识别），不解析转义文本本身：开界符宽度 > 2
#: 的值一律回到 `_value_span` 的吞行分支（见该函数）。两处的封顶不等价：键与分隔符之间的那一串
#: 起点被键名结尾钉住，只能一次吃完，因此 `{1,128}+` 是真封顶（超出即失配这个键）；键名**前**的那
#: 一串由引擎沿输入滑动起点，长连串以尾段起匹配，所认键名并不受 128 封顶。两处都是占有型：
#: 一条反斜杠串只走一次，后继失配时不交还字符（扫描侧每步至少前进一个字符）。
_KEY_ASSIGN_RE = re.compile(
    rf"(?:\\{{1,{MAX_KEY_NAME_CHARS}}}+)?(?:{_QUOTE}?)(?P<key>[A-Za-z0-9_.\-]{{1,{MAX_KEY_NAME_CHARS}}}+)"
    rf"(?:\\{{1,{MAX_KEY_NAME_CHARS}}}+)?(?:{_QUOTE}?)[ \t]*+[:=][ \t]*+",
    re.IGNORECASE,
)

#: URL 用户信息：`scheme://user:pass@`。RFC 3986 的 userinfo 允许逗号、分号、撇号等 sub-delims，
#: 百分号编码内的 `:` 又无法在段内判界，所以本规则**不再按 `:` 切分用户名与口令**：把 `scheme://`
#: 到最后一个 `@` 之间的整段视为凭据段保守遮蔽。判界只靠能证明该处已不是 userinfo 的边界——空白
#: 与 `/`、`?`、`#`（authority 必在这三处终止）以及作分隔符的 `@`——因此不会遮进主机名，也不存在
#: “段内出现意外字符反而整条失配、连凭据一起放行”的漏检路径。段与段之间的量词占有（迭代段
#: `[^\s/?#@]*+`、收尾段 `[^\s/?#@]++`）：每个连续串只吃一次、不向后交还字符，无二次方回溯；
#: 迭代段**允许空段**（`*+` 而非 `++`），因此连续/重复 `@`（`u:p@@ss@`）仍能沿到最后一个结构性 `@`，
#: 空段之后的字符不会被留在输出里——每次迭代必消费一个 `@`，故不引入零长度循环，外层 `*` 仍可整体
#: 回退迭代数以让收尾段落在正确的 `@` 上；整段不封顶，超长用户名/口令仍整段遮掉。
#: 前面的规则把用户名或口令替为占位时，占位串的全部字符都在段内字符类里（`https://[redacted]:pw@host`
#: 仍会把 `:pw` 一起遮掉），“已插占位”不会阻断后续整值遮蔽。scheme 首字母后允许零长度（`x://…`）。
_URL_USERINFO_RE = re.compile(
    r"(?P<head>[A-Za-z][A-Za-z0-9+.\-]{0,31}://)"
    r"(?P<user>(?:[^\s/?#@]*+@)*[^\s/?#@]++)@"
)

#: 分隔符类含 `#`：片段参数与查询参数同形（`#access_token=…`），不在这里区分；值本身仍在
#: `&`/`#`/空白处自然停止，不吞同位置的后续正文。
_QUERY_PARAM_RE = re.compile(
    rf"[?&#](?P<key>[A-Za-z0-9_.\-]{{1,{MAX_KEY_NAME_CHARS}}})=(?P<value>[^&#\s]+)"
)


def _value_span(text: str, start: int) -> tuple[int, int, int, str]:
    """判定从 `start` 开始的值段边界，返回 `(值段结束, 内容结束, 开界符宽度, 闭合界符)`。

    值段是真正被替为占位的区间，内容结束是算作凭据内容的位置：两者仅在“引号在本行内不闭合
    或超长”时不同（此时连同开引号吞到行尾）。值的边界不在正则里，所以非敏感键不会走到这里。
    开界符宽度/闭合界符是**输出里该保留的界符**：`\\\"v\\\"` 形态下两侧各返回 2 个字符（`\\\"`）——
    反斜杠是转义结构而不是凭据内容，去掉会让下游 JSON 解析变难。落到“吞到行尾”分支时两者
    返回 `0`/`""`：结构已碎，开引号连同余下内容一起进占位段，不再保留界符。
    """
    line_end = text.find("\n", start)
    if line_end < 0:
        line_end = len(text)
    # CR 属于行尾，不属于凭据内容：把它留在输出里，空值也不会被当成有值。
    while line_end > start and text[line_end - 1] == "\r":
        line_end -= 1
    if start < line_end:
        open_quote, opener_width = _open_quote_at(text, start, line_end)
        if open_quote:
            close = _quote_close(text, start, line_end, open_quote, opener_width)
            if close >= 0:
                return close, close - opener_width, opener_width, text[close - opener_width : close]
    # 无引号值（shell/env/YAML/日志/被 `export` 前缀过的行）与不闭合、超长的引号值（含转义开界符
    # 在本行内找不到可安全判定的闭合、或遇到更深一层转义连串的情形）：取到行尾。`, ) ( '`
    # 都是普通口令字符，在那里停下就是把秘密后半截留在输出里。
    return line_end, line_end, 0, ""


def _open_quote_at(text: str, start: int, line_end: int) -> tuple[str, int]:
    """识别值段的开界符，返回 `(引号字符, 界符宽度)`；不是引号开头返回 `("", 0)`。

    宽度 >= 2 时是 JSON 被再嵌一层留下的转义引号（1 个反斜杠 = 一层，2 个 = 两层）：只把
    一层（宽度 2）当可判界的开界符；反斜杠多于一个（更深层）不解析，当无界符处理，由调用方
    吞到行尾。键名正则能吃掉任意长度的反斜杠串，因此深层转义也能进到本函数。
    """
    backslashes = 0
    index = start
    while index < line_end and text[index] == "\\":
        backslashes += 1
        index += 1
    if index >= line_end:
        return "", 0
    char = text[index]
    if char not in _QUOTE_CHARS:
        return "", 0
    # 反斜杠连串不设上限：更深层的转义形态不报错也不递归解码，由调用方（`_value_span`）吞到行尾。
    return char, backslashes + 1


#: 闭合引号**之后**允许出现的内容：结构分隔符（空白与收尾标点）。不在集内（字母、`-`、`/` 等）
#: 说明本行不是干净的引号收尾，值边界判不定 → 吞到行尾，不产出“只遮前截”的结果。
_VALUE_BOUNDARY_CHARS = frozenset(" \t,;:)]}")


def _boundary_after_close(text: str, index: int, line_end: int) -> bool:
    """闭合界符处是否正好落在本行结尾或结构分隔符上（两种类度的引号共用）。"""
    return index >= line_end or text[index] in _VALUE_BOUNDARY_CHARS


def _quote_close(
    text: str, start: int, line_end: int, open_quote: str, opener_width: int
) -> int:
    """返回闭合界符**之后**的位置；本行内找不到可安全判定的闭合界符时返回 `-1`。

    两种层度分开处理，不造转义解析器（宽度 > 2 的更深开界符进不了下面两支，直接判不定）：
    - 普通引号（宽度 1）：反斜杠跳过下一个字符，使 `"a\\\"b"` 在真正的闭合引号处结束；相邻两个
      同引号（YAML 单引号双写、C 风 `\"\"`）算值内文本继续往后扫，不在第一个处提前收尾。
    - 转义引号（宽度 2）：闭合界符必须是一个反斜杠 + 引号；转义的是其他字符（`\\n`）则跳两格，
      遇到裸引号、反斜杠连串 ≥2 的引号或更深的开界符（宽度 > 2）则返回 `-1` → 调用方吞到行尾（宁多遮不少遮）。
    两支都要求闭合处**后面**是本行结尾或结构分隔符（`_VALUE_BOUNDARY_CHARS`）：紧贴非结构字符
    （`PASSWORD=\"abc\"def`、`PASSWORD=\\\"abc\\\"def`）时整个闭合判定作废，回到吞行分支。
    超过 `MAX_QUOTED_VALUE_CHARS` 的引号串像整段正文而不是一条凭据，也返回 `-1`，但它仍会被
    行尾分支全覆盖，因此不存在部分遮蔽。
    """
    scan = start + opener_width
    if opener_width > 2:
        # 更深层的转义开界符（`\\\\\"v\\\\\"`）：不解析也不假定闭合位置，判不定 → 调用方吞到行尾。
        return -1
    if opener_width == 1:
        while scan < line_end:
            char = text[scan]
            if char == "\\":
                scan += 2
                continue
            if char == open_quote:
                if scan + 1 < line_end and text[scan + 1] == open_quote:
                    scan += 2
                    continue
                if scan - start - 1 > MAX_QUOTED_VALUE_CHARS:
                    return -1
                if not _boundary_after_close(text, scan + 1, line_end):
                    return -1
                return scan + 1
            scan += 1
        return -1
    while scan < line_end:
        char = text[scan]
        if char == "\\":
            if scan + 1 >= line_end or text[scan + 1] != open_quote:
                scan += 2
                continue
            if scan > start and text[scan - 1] == "\\":
                return -1
            if scan - start - opener_width > MAX_QUOTED_VALUE_CHARS:
                return -1
            if not _boundary_after_close(text, scan + 2, line_end):
                return -1
            return scan + 2
        if char == open_quote:
            return -1
        scan += 1
    return -1


def _value_is_masked(content: str, opener_width: int) -> bool:
    """值段内容是否已是一个完整占位（前面的规则在此处替过了）。

    `content` 含开界符而不含闭合界符（`_value_span` 的 `content_end` 已排除闭合界符），因此只剥
    开头 `opener_width` 个字符。比较的是**界符之间的文本**而不是整个值段：开界符宽度为 2
    （`\"v\"`）时“开界符 + 占位 + 开界符”拼出的串永远不等于居中的占位，拿输出形式去反比会
    错估成未遮蔽而重复计数；也不得反过来把占位只是一小部分的长值当成已遮蔽而直接放行。
    剥完后剩下空白或反斜杠（值形如 `\\`）仍视为未遮蔽：反斜杠可以是口令字符。
    剥完为空有两种来源（整值已是占位、本行就是一个空值），两者都没有需要遮蔽的内容，同一处理。
    """
    core = content[opener_width:]
    return not core.replace(REDACTION_PLACEHOLDER, "").strip()


def _mask_assignments(text: str) -> tuple[str, int]:
    """遮蔽带敏感键名的赋值：只替换值，保留键名与分隔符，使 JSON/YAML 结构仍可辨认。

    非敏感键（`text`/`content`/`command`）一律原样跳过，因此它们的值（包括带撇号、反引号、
    超长的值）不会把同级后续字段吞进遮蔽区间。`cursor` 与 `position` 分管两件事：`cursor` 是
    **输出侧**已落笔位置，只在文本真被改写时前移；`position` 是**扫描侧**位置，无论该处是否
    改写都前移；两者混淆会把同一段前缀重复输出。空白值（键后直接换行）不产出占位、不计数。
    """
    pieces: list[str] = []
    hits = 0
    cursor = 0
    position = 0
    while position < len(text):
        match = _KEY_ASSIGN_RE.match(text, position)
        if match is None:
            position += 1
            continue
        if not _is_sensitive_key(match["key"]):
            # 不敏感：从本次匹配起点往后推一个字符继续扫（正则无值分支，值与同级字段未被动过）。
            position = match.start() + 1
            continue
        value_start = match.end()
        value_end, content_end, opener_width, closer = _value_span(text, value_start)
        if content_end == value_start:
            # 空值（键后直接换行，含 CR 结尾的行）：没有可遮的东西，继续往后扫。
            position = value_start
            continue
        content = text[value_start:content_end]
        if _value_is_masked(content, opener_width):
            # 前面的规则已把该处替为完整占位：不重复计数、不嵌套替换，但只推扫描位置；
            # 输出侧的 `cursor` 不前移也不追这段文本，由后面的 `text[cursor:]` 一次性带出。
            position = value_end
            continue
        pieces.append(text[cursor:value_start])
        opener = text[value_start : value_start + opener_width]
        pieces.append(f"{opener}{REDACTION_PLACEHOLDER}{closer}")
        cursor = value_end
        hits += 1
        position = value_end
    if not hits:
        return text, 0
    pieces.append(text[cursor:])
    return "".join(pieces), hits


def _mask_scheme_credentials(text: str) -> tuple[str, int]:
    """遮蔽认证串的值，保留方案词（`Bearer`/`Basic`）以便定位是哪类头出了事。

    只有空白分隔（无 `:`/`=`）时额外校一次形状：方案词后的普通英文单词不是凭据。
    不用 `sub` + 回调：回调无权决定下一次扫描从哪里开始，一个被拒的候选会把紧跟其后的
    **方案词**一并吞掉（`bearer token abc123def` 中 `bearer token` 被拒后，`abc123def`
    就没有头部可遮，整串原样外出）。改成显式扫描：拒一个候选时只越过方案词本身，
    其后的分隔与值仍可作为 `token abc123def` 重判。
    重复处理不二次计数：占位串以 `[` 开头，不在令牌字符类内，因此已遮蔽处根本不产生匹配。
    """
    pieces: list[str] = []
    hits = 0
    cursor = 0
    position = 0
    length = len(text)
    while position < length:
        match = _CREDENTIAL_SCHEME_RE.match(text, position)
        if match is None:
            position += 1
            continue
        separator = match["sep"]
        credential = match["cred"]
        # 只有空白分隔（`Bearer abc...`）时额外校一次形状：长度够长，或短但带数字/令牌分隔符。
        # 方案词后的普通英文词不算凭据；但 `Bearer abc123` 这种短而合法的令牌不能漏。
        if ":" not in separator and "=" not in separator and not _is_bare_credential(credential):
            position = match.start() + len(match["head"])
            continue
        pieces.append(text[cursor : match.start()])
        pieces.append(f"{match['head']}{separator}{REDACTION_PLACEHOLDER}")
        cursor = match.end()
        hits += 1
        position = match.end()
    if not hits:
        return text, 0
    pieces.append(text[cursor:])
    return "".join(pieces), hits


def _mask_url_userinfo(text: str) -> tuple[str, int]:
    """保守遮蔽 `scheme://` 与最后一个可判界 `@` 之间的整个 userinfo 段，保留协议与 `@`。

    不再按 `:` 切分用户名与口令：合法 sub-delims（`,`/`;`/`'`）、百分号编码内的 `:` 等
    无法安全判界的形态统一由“整段遮蔽”覆盖；用户名本身也可能是标识（邮箱形式），因此不
    单独保留它；主机名在 `@` 后，不属于本规则。整段已是纯占位时不改写、不计次（幂等重扫
    不会虚增 `redacted_count`）。
    """
    hits = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal hits
        if match["user"] == REDACTION_PLACEHOLDER:
            return match.group(0)
        hits += 1
        return f"{match['head']}{REDACTION_PLACEHOLDER}@"

    return _URL_USERINFO_RE.sub(replace, text), hits


def _mask_query_params(text: str) -> tuple[str, int]:
    """遮蔽 URL 查询/片段中键名敏感的参数值；`?`/`&`/`#` 分隔符与键名保留。

    排在赋值之后：能当赋值处理的已经整行遮完了，本规则只兜住赋值键名正则够不到的形态，
    因此值已是占位时不计次数。
    """
    hits = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal hits
        if not _is_sensitive_key(match["key"]):
            return match.group(0)
        # 比较的是值内的文本（剥掉占位与首尾空白后为空），不是固定的字符串相等：
        # 占位只是值的一小段时仍整段重遮；已完全遮蔽的不重复计数。
        if not match["value"].replace(REDACTION_PLACEHOLDER, "").strip():
            return match.group(0)
        hits += 1
        return f"{match.group(0)[0]}{match['key']}={REDACTION_PLACEHOLDER}"

    return _QUERY_PARAM_RE.sub(replace, text), hits


def _mask_literal(text: str, pattern: re.Pattern[str]) -> tuple[str, int]:
    """整段匹配即遮蔽的通用规则（私钥块、令牌字面形态）。"""
    return pattern.subn(REDACTION_PLACEHOLDER, text)


def _mask_keep_head(text: str, pattern: re.Pattern[str]) -> tuple[str, int]:
    """保留头部（键名/认证方案词），只遮蔽其后的值。

    值已全是一个占位（同一输出重复过本层）时不写第二个占位、不计数；占位仅占值一小段时
    仍整段重遮。因此 `redacted_count` 只统计真实改写次数。
    """
    hits = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal hits
        if not match["value"].replace(REDACTION_PLACEHOLDER, "").strip():
            return match.group(0)
        hits += 1
        return f"{match['head']}{REDACTION_PLACEHOLDER}"

    return pattern.sub(replace, text), hits


#: 固定执行顺序：私钥块（整块→残留头部）→ 凭据头部 → 令牌字面形态 → 键名赋值
#: → URL 用户信息 → 查询/片段参数 → 认证串。私钥与头部在前，避免其内部文本被后面的规则切成碎片；
#: 赋值先于认证串与 URL 用户信息，使 `X-Auth: Bearer abc123`、`token: https://user:pass@host` 一次整段
#: 遮蔽（否则占位插入后后面的形态失配）。反过来，已插入的占位也不阻断后续整值遮蔽：占位守卫比较的是
#: 值内文本，只挡住“整值已是占位”这一种情形（见 `_value_is_masked`/`_mask_keep_head`/`_mask_query_params`），
#: URL 用户信息把占位串的字符当作合法段内字符（前面的规则留下的占位不阻断整段遮蔽）；整段已是纯占位时按已遮蔽跳过、不计次。
#: `sk-…`/`ghp_…` 这类无键名令牌不进入键名正则（字符类不含 `-` 且量词占有），所以不靠顺序也不会被部分改写。
_RULES: tuple[Callable[[str], tuple[str, int]], ...] = (
    lambda text: _mask_literal(text, _PRIVATE_KEY_BLOCK_RE),
    lambda text: _mask_literal(text, _PRIVATE_KEY_UNTERMINATED_RE),
    lambda text: _mask_keep_head(text, _CREDENTIAL_HEADER_RE),
    lambda text: _mask_literal(text, _SERVICE_TOKEN_RE),
    _mask_assignments,
    _mask_url_userinfo,
    _mask_query_params,
    _mask_scheme_credentials,
)
