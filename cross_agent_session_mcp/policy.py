r"""授权策略层：范围、项目、来源与路径边界（DES-SEC-01、DES-ARCH-05）。

服务的需求条目：SRS-SEARCH-07、SRS-SEARCH-10；合约见 DES-API-01 的 `scope`/`project`
说明与「会话结果发布边界」，边界规则见 DES-ARCH-05「规范化并处理 Windows 大小写、
symlink/junction 与路径逃逸。文件发现、上下文读取都执行同一边界」。本层把这个边界拆成两个
各自唯一的入口：会话对象（存储）路径的读取授权，与记录声称 cwd 的项目归属核对。

授权只来自调用方显式传入的配置
------------

- 本模块**不读取任何配置**：不打开文件、不读环境变量、不做 `expanduser`/`Path.home()`
  推断，也不导入协议层。批准范围（scope）、项目、来源、存储根目录与归属根目录全部由构造参数给出。
- 未配置即全拒：`SessionPolicy(())` 是合法构造，结果是任何查询与路径一律被拒
  （`scope_not_configured`）。空配置不等于「默认允许」。
- `scope` 只是配置里的**标识符**，本层对它唯一的操作是字典精确查表；绝不把 scope 值当
  路径拼接、解析或判绝对性。文件系统路径只来自配置里的 `StoreRootGrant.path`（来源级会话
  存储）与 `CwdRootGrant.path`（项目级归属），两套数据互不派生。
- 未知即拒：未知 scope、未知来源 ID、scope 内未批准的项目、没有可核对归属证据的记录，
  一律拒绝，不猜、不放宽、不退回全盘扫描。

不把解析结果当授权
------------

- 适配器（如 `sources/pi.py`）报出的 `cwd`、`project_quality` 与会话标识**不是授权**：
  它们只是「这条记录声称自己属于哪个目录」的证据。本层要求拿这个声称的目录再过一次
  `authorize_attribution()`，只有能唯一归到某个已批准项目的记录才可获得发布资格；声称
  缺失（`None`）即 `attribution_unknown`，不拿“没有证据”当成“已通过”（DES-API-01：来源内
  元数据可作为归属证据，但不能替代策略层的授权判断）。
- 两个结论各自独立、互不派生：`AttributionGrant` 没有 `readable_path`（归属成立不表示那个
  目录可读，批准一个项目的 cwd 绝不把整个项目树变成可读对象）；`StoreGrant` 没有
  `project`（共享存储里多个项目的会话共存，从路径推不出归属）。一条记录要发布，**两项检查
  都得通过**，再加整流身份核对与脱敏（DES-API-01 发布边界）。
- 处理器的进程 cwd 同样无关：输入路径必须是绝对路径，相对路径直接拒（`path_unsafe`），
  不给「用当前工作目录解释调用方给的相对路径」留空间。

存储授权与归属核对各有唯一入口
------------

`authorize_store(scope, source, path, kind=...)` 是唯一的**文件读授权**入口：来源发现阶段对
逐个候选路径调用它筛掉范围外对象，`read_session_context` 打开任何文件前也调用它。两条路径
共用同一实现，因此不存在「发现时宽松、读取时严格」或反向的差额。它只按 `source` 选根目录，
**不接受 `project`**：用项目收窄存储授权会造出「配了项目就能读该项目整个目录树」的误导语义。
返回的 `StoreGrant.readable_path` 是**检查时刻已通过全部校验的真实路径**，调用方只能打开这个
值，不得改用请求里原样的字符串（否则被拒绝的写法还会被拿去打开）。它是必要条件而非充分
保证：见「结论只到检查时刻为止」。

`authorize_attribution(scope, cwd, project=...)` 只做**项目判定**，不授予读取。判定顺序是
「先比字面归属根、后做真实解析」：字面轴在本范围**全部项目**的归属根上跑完，不命中即
`attribution_unmatched`，**在任何候选路径的文件系统探测之前**固定拒绝（不可信的 UNC 写法
因此不会触发 SMB 名解析）；字面命中后，真实轴只在这些候选根内复核并补查歧义（同项目
重叠根、字面未命中但真实命中的根），不可替代字面入口。合并命中的项目多于一个即
`attribution_ambiguous`——显式指定的
`project` 因此**不能掩盖冲突**（嵌套/重叠配置下它只会把记录归到错的项目）。project 合法但
与唯一判定结果不符 → `project_mismatch`；字面轴不命中任何项目 → `attribution_unmatched`（在任何
文件系统探测之前）。两项核对都通过仍不等于完整授权：本层只完成路径→项目与路径→存储的
映射判定，记录确实来自那个项目要靠来源可信格式字段、会话身份核对与整流一致性（DES-API-01）。

路径校验的顺序与判据（两套检查共用，先拒先返回）
------------

1. 形状：字符串、非空白、无 NUL/换行、原始分量不含 `..`，且是绝对路径 → 否则
   `path_unsafe`。Windows 上「绝对」取严格定义：完整盘符绝对（`D:\x`）或合法 UNC
   （`\\server\share`，可再带子路径）；其余形态一律拒——设备命名空间（`\\?\`、`\\.\`
   及 `/` 变体，它们绕过常规解析）、根相对（`\x`，隐含「当前盘符」）、盘相对（`D:x`，
   隐含该卷的当前目录）、裸盘符、盘符或共享名之后的 `:`（交替数据流写法）、通配符
   `*`/`?` 与非法字符、分量尾部的点或空格（Windows 解析会把它们剥掉，落点不是这个名字）、
   保留设备名（`CON`/`PRN`/`AUX`/`NUL`/`COM0-9`/`LPT0-9`，含 `CON.txt` 这类带扩展名写法）。
   所有判据作用于**原始串**，不先规范化再看。归属证据缺失（`None`）只在归属轴单独报
   `attribution_unknown`，与「形状坏掉」区分开；存储轴的 `None` 就是不可信参数 → `path_unsafe`。
2. 字面包含：调用方写法与配置写法各自折算成可比较形态（`normpath` + `normcase`，
   Windows 额外 `casefold`）后必须相等或位于某个已批准根目录之下 → 存储轴否则
   `path_out_of_scope`，归属轴把不命中记入 `attribution_unmatched` 与歧义判定。该形态**只是
   比较串**：绝不做 `realpath` 或链路探测的输入，也不参与第 3 步。它因折叠而多命中一个根
   目录也不会扩大授权：第 3 步按精确分量复核，落到不同目录即 `path_escape`，因折叠多出的
   命中至多把一次放行换成一次拒绝（归属轴上还可能换成一次歧义拒绝，方向同样是收紧）。
   归属轴上本步是**入口门**：不命中即 `attribution_unmatched`，且在**任何候选路径的文件系统
   探测之前**固定拒绝（不可信的 UNC 写法因此不会去触发 SMB 名解析）；第 3 步只用于复核
   已命中的候选与补查歧义，不能替代本步把字面不在已批准根下的路径判为归属。
3. 真实包含：对**调用方给出的原始路径**与其命中的根目录各做一次 `realpath`，再按
   `realpath` 返回的**精确分量**比较（不折叠大小写、只归一分隔符与冗余分量）→ 否则
   `path_escape`。字面通过、真实不通过（链接指到外部）即拒绝。Windows 可以按目录开启
   大小写敏感，折叠会把 `Work` 与 `work` 合并成同一个目录，因此真实比较宁可因大小写不同
   而拒绝，也不放过两个不同目录。
4. 链接与重解析点：自根向叶逐级探测**原始路径**的链路，出现 symlink/junction/其它
   reparse point 时保守拒绝（`path_reparse`），除非**每一条**已匹配根目录在配置里都显式
   `allow_links=True`（此时第 3 步的真实包含判断仍然生效）。探测本身失败（无法 `lstat`）按
   「不可信」处理，等同发现链接。理由：批准配置描述的是路径本身，未经描述的链接指向不该
   由本层推断其安全性。
5. 全部命中的根同时成立，不按配置顺序挑一个：候选必须落在**每一条**已匹配根（存储轴同来源
   的重叠根、归属轴同项目的重叠根）的字面与真实位置内，否则 `path_escape`——配置顺序不是
   变宽通道，多条重叠根只能保守地同时作约束。归属轴额外要求项目唯一：候选同时落入同范围内
   **多个项目**的归属根（嵌套配置）时报 `attribution_ambiguous` 而不是挑一个。
6. 存在性与类型：只做 `isdir`/`isfile` 元数据判断，不打开、不解码、不读正文
   → `path_missing` / `path_kind_mismatch`。`kind` 只接受 `TargetKind` 枚举成员，其它值
   （含看起来等价的 `"file"` 字符串）说明调用方参数不可信，固定 `path_kind_mismatch`，
   不降级成 `any` 放行；这一项在 `authorize_store` 入口处先验，非法即拒，不为一次不可信
   的调用做文件系统探测。归属轴要求候选解析后仍是目录（不存在 → `path_missing`，是文件
   → `path_kind_mismatch`）。作判定基准的已批准根无法解析、或候选解析不出确定位置时报
   `path_unresolvable`：不能拿位置不确定的目录当基准；归属轴上与本判定无关（未命中）的根
   不可达不改变结论。

不接受调用方声称的真实路径与链接事实
------------

本层只使用 `lexists` / `lstat` / `isdir` / `isfile` / `realpath` 这一组元数据调用，不调用
`open`、`read`、`listdir`、`scandir`，因此不发现任何真实会话内容，也不把正文引入策略判断。
边界判断的每一项事实都由本层**自己探测**：不接受调用方传入「已解析好的真实路径」或
「链路上没有链接」这类断言。调用方传来的字符串是本层要审查的对象，不是审查的证据——
一旦允许它替代探测，攻击者就能用一句假断言同时跳过 `realpath` 与重解析点检查；省一次探测
也不属于策略层的职责。因此本层不导出任何元数据旁路参数，调用方（含来源适配器）只能提交
待检路径并读取结论。

结论只到检查时刻为止，不代替打开后的复核
------------

第 3～6 步的探测与调用方后续 `open` 之间是两次系统调用：目标可能被替换成别处的同路径名
条目，本层不持有句柄，`readable_path` 只是**检查时刻成立**的结论。因此后续增量对来源层的要求是：
打开后把**句柄导出的最终路径**重新送过一次 `authorize_store`，并核验文件身份（如卷号 +
文件标识）与本层检查基准一致；只比对调用方自己传的路径字符串不算复核。最终路径无法从
已打开的句柄安全导出（平台/驱动不支持等）时，该结论不得发布。本层不持有也不导出句柄，
不声称覆盖上述复核，也不能靠返回一个字符串代替它；本轮未实现这部分。

配置只能是普通字面值
------------

策略层不接受调用方自定义类型、代理对象或可被 `__str__`/`__fspath__` 等协议接管的“伪字符串”：
`SessionPolicy` 的参数顶层只接受 `list`/`tuple`，`ScopeGrant.projects`/`store_roots` 必须是
`tuple`，`authorize_query` 的 `sources` 元素与 `source`/`path`/`scope_id`/项目名及各根目录路径
在各自入口就要求是普通 `str`，校验
后的值就是使用的值，不再做 `str()` 转换（否则可在验证之后换一个解析目标）。这里只求配置
形状与类型可预期，不为“恶意任意 Python 对象”做额外防御。

拒绝信息不含敏感值
------------

`PolicyDenied` 只携带 `RefusalCode` 闭合枚举，文案取自固定的 `REFUSAL_MESSAGES`，不拼接
scope 名、项目名、路径、来源或任何调用方输入（DES-SEC-01：错误与日志不写绝对个人路径、
查询词、凭据）。新增拒绝原因只能扩 `RefusalCode`，不得由实现临时造字符串。

本增量状态（不得理解为功能已完成）
------------

- 已实现：配置对象（`ScopeGrant`（含 `store_roots`）/`ProjectGrant`（含 `cwd_roots`）/
  `StoreRootGrant`/`CwdRootGrant`）与构造期自检（含上述普通字面值类型门）、查询授权
  `SessionPolicy.authorize_query`、
  存储授权 `SessionPolicy.authorize_store` 与归属核对 `SessionPolicy.authorize_attribution`
  （各自走上述六步中与其相关的判据）、Windows 严格绝对形状判据（盘符绝对/合法 UNC，拒
  设备前缀、根相对、盘相对、ADS、尾点尾空格、通配符、保留设备名）、真实包含的精确分量
  比较、元数据探针、结论对象 `QueryGrant`/`StoreGrant`/`AttributionGrant`、拒绝码与固定文案。
- 存储与归属分成两个入口，结论不交叉：`authorize_store` 只返回 `StoreGrant`（source +
  `readable_path`），`authorize_attribution` 只返回 `AttributionGrant`（project）。一个 API 只
  授权存储路径，另一个只核对 cwd 归属：其中一项结论成立不得当作另一项已成立，发布需要
  两次调用各自通过（共享存储可供多个已批准项目使用，cwd 命中也不产生读能力）。
- 接线现状：本模块经 `session_pipeline.py`（`authorize_query`/`authorize_attribution`/
  `authorize_store`）与 `safe_reader.py`（`authorize_store` 复核链）进入协议层；`server.py` 直接
  导入 `SessionPolicy`/`PolicyDenied` 作为绑定服务的类型与拒绝边界。仍未接：
  六来源的实际根目录配置、`coverage` 汇总、SQLite 只读 URI 及其
  `-wal`/`-shm` 侧边文件的授权与打开方式（属来源适配器）。`read_session_context` 的定位
  信息与会话身份交叉核对已由 `session_context.py` 的引用账本核对承担（绑定值来自发放时的
  授权结果，客户端不能再提供定位坐标）。
- 本层不判断「来源当前是否可用」（磁盘存在性、库是否被锁、格式是否支持）：那只影响
  `list_sources`/`coverage` 状态，不扩大也不缩小授权范围。
- Windows 8.3 短名**仍仅由第 2、3 步拦住**（短名字面量不等于已批准根目录下的长名 →
  `path_out_of_scope`），未做形状层拒绝；实际拦截效果待审查与测试确认。
- 检查与打开之间的替换窗口（DES-SEC-01 要求审核的竞态）不由本层消除：`readable_path` 只
  表达检查时刻结论；后续增量的要求是来源层打开后把句柄导出的最终路径重新经
  `authorize_store`，并核验文件身份与本层检查基准一致（见「结论只到检查时刻为止」），
  最终路径无法安全核验则不得发布；本轮未实现，`StoreGrant` 不新增句柄类字段。
- 本轮未运行任何代码与测试，未使用真实路径或真实会话核对判据；新增的拒绝码（归属歧义/
  不命中）与归属轴的多根约简行为同样只经过静态推导，待审查与测试确认。

依赖限制（DES-ARCH-02「范围保护：不依赖协议层」）：只用标准库；不导入 `mcp`、`server.py`、
`models.py` 或任何来源适配器；不打开文件、不写日志。
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePath

__all__ = [
    "KNOWN_SOURCES",
    "AttributionGrant",
    "CwdRootGrant",
    "PolicyDenied",
    "ProjectGrant",
    "QueryGrant",
    "RefusalCode",
    "SessionPolicy",
    "StoreGrant",
    "StoreRootGrant",
    "TargetKind",
    "is_safe_literal_path",
]

#: 首版固定来源集合；未列入的来源 ID 一律按未知来源拒绝（与协议层骨架一致）。
KNOWN_SOURCES: tuple[str, ...] = (
    "hermes",
    "dsh",
    "workbuddy",
    "pi",
    "cursor_agent_cli",
    "codex",
    "claude_code_cli",
)

_IS_WINDOWS = os.name == "nt"
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
_WINDOWS_DRIVE_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyz")
#: Windows 上不允许出现在受批准路径里的字符（`:` 单独判：盘符/交替数据流）。
_WINDOWS_FORBIDDEN_CHARS = frozenset('<>|"?*')
#: Win32 保留设备名：即使带扩展名（`CON.txt`）仍解析到设备，不是普通文件。
_WINDOWS_RESERVED_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(10)}
    | {f"LPT{index}" for index in range(10)}
)


class RefusalCode(StrEnum):
    """拒绝原因码：闭合集合，可安全用于日志与对外错误（不含任何输入值）。"""

    SCOPE_NOT_CONFIGURED = "scope_not_configured"
    SCOPE_UNKNOWN = "scope_unknown"
    SOURCE_UNKNOWN = "source_unknown"
    SOURCE_NOT_AUTHORIZED = "source_not_authorized"
    PROJECT_UNKNOWN = "project_unknown"
    PROJECT_MISMATCH = "project_mismatch"
    ATTRIBUTION_UNKNOWN = "attribution_unknown"
    ATTRIBUTION_AMBIGUOUS = "attribution_ambiguous"
    ATTRIBUTION_UNMATCHED = "attribution_unmatched"
    PATH_UNSAFE = "path_unsafe"
    PATH_OUT_OF_SCOPE = "path_out_of_scope"
    PATH_ESCAPE = "path_escape"
    PATH_REPARSE = "path_reparse"
    PATH_UNRESOLVABLE = "path_unresolvable"
    PATH_MISSING = "path_missing"
    PATH_KIND_MISMATCH = "path_kind_mismatch"
    CONFIG_INVALID = "config_invalid"


#: 每个原因码一句固定说明；不拼接 scope、项目、来源、路径或计数（DES-SEC-01）。
REFUSAL_MESSAGES: dict[RefusalCode, str] = {
    RefusalCode.SCOPE_NOT_CONFIGURED: "拒绝：本进程未配置任何授权范围，默认不查询任何来源。",
    RefusalCode.SCOPE_UNKNOWN: "拒绝：scope 不在已批准的授权范围标识内。",
    RefusalCode.SOURCE_UNKNOWN: "拒绝：source 不是受支持的来源标识。",
    RefusalCode.SOURCE_NOT_AUTHORIZED: "拒绝：该来源未在所选授权范围内批准，或该范围内它没有已批准的存储根目录。",
    RefusalCode.PROJECT_UNKNOWN: "拒绝：project 不在该授权范围已批准的项目内。",
    RefusalCode.PROJECT_MISMATCH: "拒绝：目标归属与显式指定的 project 不一致。",
    RefusalCode.ATTRIBUTION_UNKNOWN: "拒绝：缺少可核对的项目归属证据，不发布正文。",
    RefusalCode.ATTRIBUTION_AMBIGUOUS: "拒绝：归属证据在本范围内同时命中多个已批准项目，无法唯一确定。",
    RefusalCode.ATTRIBUTION_UNMATCHED: "拒绝：归属证据不在任何已批准项目的归属根目录内。",
    RefusalCode.PATH_UNSAFE: "拒绝：路径形状不安全（相对路径、跳转记号或受控形态之外的写法）。",
    RefusalCode.PATH_OUT_OF_SCOPE: "拒绝：路径不在该来源已批准的存储根目录内。",
    RefusalCode.PATH_ESCAPE: "拒绝：路径的真实位置超出已批准的根目录。",
    RefusalCode.PATH_REPARSE: "拒绝：路径链路上存在链接或重解析点，且该根目录未显式允许。",
    RefusalCode.PATH_UNRESOLVABLE: "拒绝：路径无法解析为确定的真实位置。",
    RefusalCode.PATH_MISSING: "拒绝：路径不存在，不作为可用目标。",
    RefusalCode.PATH_KIND_MISMATCH: "拒绝：路径类型与所需目标类型不符。",
    RefusalCode.CONFIG_INVALID: "拒绝：授权配置不合法，本进程不提供任何查询能力。",
}


class PolicyDenied(Exception):
    """授权被拒：只携带固定原因码，消息取固定文案，不含调用方输入。"""

    def __init__(self, code: RefusalCode) -> None:
        if not isinstance(code, RefusalCode):
            raise TypeError("PolicyDenied accepts a RefusalCode only")
        self.code = code
        super().__init__(REFUSAL_MESSAGES[code])


class TargetKind(StrEnum):
    """调用方对目标类型的要求；只依据元数据判断，不打开目标。

    `authorize_store` 只接受本枚举的成员：字符串 `"file"`、整数、`None` 或调用方自建的
    同值枚举都说明参数不可信，固定 `path_kind_mismatch` 拒绝，不退化成 `ANY` 放行。
    """

    FILE = "file"
    DIRECTORY = "directory"
    ANY = "any"


@dataclass(frozen=True)
class StoreRootGrant:
    """来源级会话存储根：某个来源的会话文件/数据库所在位置（DES-ARCH-04）。

    存储根**只绑定来源，不绑定项目**：一个来源的存储可以服务多个已批准项目（共享目录、
    同一 SQLite 库里的多项目会话），因此「存储在哪里」与「记录属于哪个项目」是两套独立
    配置，分别由 `authorize_store` 与 `authorize_attribution` 判定。

    `path` 必须是绝对路径（构造期校验；不做 `~`、环境变量或 cwd 展开）。它既可以是目录
    （逐源会话目录），也可以是单个文件（如 SQLite 库本身）：目录根的「其下」包含关系与
    文件根的「等于」包含关系由同一判据处理，调用方用 `kind` 表达期望类型。

    `allow_links` 默认关闭：链路上出现符号链接/junction/重解析点即保守拒绝；只有调用方在
    配置里显式声明「这个根本身经过链接」才放行，且放行后真实路径包含关系仍必须成立。

    写配置时盘符与目录名建议与文件系统实际大小写一致：字面包含比较做过大小写折叠，但真实
    包含比较用 `realpath` 返回的精确分量（不折叠），两者不一致时宁可拒绝也不合并目录。
    """

    source: str
    path: str
    allow_links: bool = False


@dataclass(frozen=True)
class CwdRootGrant:
    """项目级归属根：一个已批准项目的仓库/工作目录（记录声称的 `cwd` 应落在其内）。

    归属根**只用于判定记录属于哪个项目，不构成任何读取授权**：批准一个项目的 cwd 不会
    让它整个目录树变成可读对象（正文只来自经 `authorize_store` 批准的存储根）。`path`
    必须是绝对路径，`allow_links` 语义与 `StoreRootGrant` 相同。
    """

    path: str
    allow_links: bool = False


@dataclass(frozen=True)
class ProjectGrant:
    """一个已批准项目在本范围的归属根目录（至少一条，全部为 cwd 形态）。"""

    name: str
    cwd_roots: tuple[CwdRootGrant, ...]


@dataclass(frozen=True)
class ScopeGrant:
    """一个授权范围：标识符 + 逐源存储根 + 已批准项目的归属根（两套独立数据）。

    `store_roots` 可以为空：那表示本范围只承认项目归属、不授予任何文件读取，一律
    `source_not_authorized`（空集不表示「全部允许」）。`projects` 为空视为配置非法。
    """

    scope_id: str
    projects: tuple[ProjectGrant, ...]
    store_roots: tuple[StoreRootGrant, ...] = ()


@dataclass(frozen=True)
class QueryGrant:
    """查询授权结论：本次实际可选的来源与项目（均为已批准的有限集合）。"""

    scope: str
    sources: tuple[str, ...]
    projects: tuple[str, ...]


@dataclass(frozen=True)
class StoreGrant:
    """存储路径授权结论：**不含任何项目归属字段**。

    通过本结论只说明「这个存储对象在该范围内被该来源批准读取」，不说明它属于哪个项目；
    发布记录必须另过一次 `authorize_attribution`（DES-API-01 发布边界）。
    `readable_path` 是**检查时刻通过全部校验的真实路径**：调用方必须打开这个值，而不是
    请求里原样的字符串。它不构成 TOCTOU 保证：从本层探测到调用方 `open` 之间存在替换窗口，
    来源层的后续要求是打开后把句柄导出的最终路径重新送过一次 `authorize_store` 并核验文件
    身份与本层检查基准一致，无法安全核验则不得发布（见模块文档「结论只到检查时刻为止」）；
    本对象不持有句柄也不新增句柄类字段，该复核本轮未实现。
    """

    scope: str
    source: str
    readable_path: str
    is_directory: bool


@dataclass(frozen=True)
class AttributionGrant:
    """项目归属判定结论：**只回答属于哪个已批准项目，不授予任何读取能力**。

    没有 `readable_path` 字段是有意设计：归属成立不等于可以打开那个目录，正文读取只能来自
    `StoreGrant`。`project` 为本范围内唯一命中的已批准项目名（多个项目命中在返回前已被拒绝）。

    本结论也只证明“这个路径落在某已批准项目的归属根内”（一次路径→项目映射），**不证明这条
    记录确实来自那个项目**：记录与项目的实际绑定由来源可信格式内的字段、会话身份核对与
    整流一致性完成（DES-API-01 发布边界），不属本层能力。
    """

    scope: str
    project: str


# ---------- 路径比较原语（字面比较与真实比较各用一种形态） ----------


def _parts(form: str) -> tuple[str, ...]:
    r"""已规范化路径串的分量元组；首元素保留根（`C:\`、`\\server\share`、`/`）。"""
    return tuple(PurePath(form).parts)


def _literal_form(path: object) -> str | None:
    r"""第 2 步用的**字面比较形态**；无法比较时返回 `None`（调用方按不安全处理）。

    步骤：`normpath` 去冗余分隔符 → `normcase`（Windows 转小写并把 `/` 换成 `\`）→
    Windows 额外 `casefold`（覆盖 `normcase` 不处理的 Unicode 大小写）。POSIX 保留大小写
    （`normcase` 为恒等）。

    返回值只用来判断“像不像在批准根下”，**不是解析目标**：它做过了大小写折叠，不保证还能
    交给 `realpath`/`lstat` 解析到同一位置，因此第 3、4 步只用原始写法。设备命名空间等
    危险前缀已在形状阶段拒掉，这里不再为它们做等价归一。
    """
    if not isinstance(path, str) or not path.strip():
        return None
    try:
        text = os.path.normcase(os.path.normpath(path))
    except (TypeError, ValueError):
        return None
    if not text or text in (".", ".."):
        return None
    return text.casefold() if _IS_WINDOWS else text


def _exact_form(path: object) -> str | None:
    r"""第 3 步用的**真实比较形态**：只归一分隔符与冗余分量，不折叠大小写。

    Windows 可以按目录开启大小写敏感，且 `realpath` 已返回文件系统里的实际名字；在这里
    再 `casefold` 会把 `D:\Work` 与 `D:\work` 当成同一个目录。宁可因大小写不同而拒
    （`path_escape`），也不能把两个不同目录合并：配置时应写与文件系统一致的盘符大小。
    """
    if not isinstance(path, str) or not path.strip():
        return None
    try:
        text = os.path.normpath(path)
    except (TypeError, ValueError):
        return None
    if not text or text in (".", ".."):
        return None
    return text


def _is_within(child: str, parent: str) -> bool:
    r"""`child` 是否等于或位于 `parent` 之下（逐分量比较，绝不做字符串前缀匹配）。

    前缀比较会把 `C:\approval` 当成 `C:\approv` 的子路径，DES-SEC-01 明确它不构成隔离
    保证；分量比较下 `C:\approv\sub` 与根 `C:\approv` 只有真实相等才算同一目录。
    是否折叠大小写由传入的形态决定（字面比较用 `_literal_form`，真实比较用
    `_exact_form`），本函数自身不做任何归一。
    """
    left = _parts(child)
    right = _parts(parent)
    if not left or not right or len(left) < len(right):
        return False
    return left[: len(right)] == right


def _is_link(path: str) -> bool:
    """路径自身是否为链接/重解析点；探测失败按「不可信」返回 `True`（保守拒绝）。"""
    if os.path.islink(path):
        return True
    if not _IS_WINDOWS:
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    if _REPARSE_ATTRIBUTE and attributes & _REPARSE_ATTRIBUTE:
        return True
    return bool(getattr(info, "st_reparse_tag", 0))


def _chain_has_link(path: str) -> bool:
    r"""自根向叶探测**调用方原写法**链路上的链接；某一级尚不存在即停止。

    只用 `lexists` + `lstat`/`islink`，不跟随链接、不打开目标。提前停止不等于「无链接」：
    不存在的后续分量由真实包含与存在性检查拦住。输入必须是未规范化的原始路径：`normpath`
    会把 `\\server\share\x` 的分量拆坏，误判链路上哪些级存在。
    """
    parts = PurePath(path).parts
    for index in range(1, len(parts) + 1):
        prefix = str(PurePath(*parts[:index]))
        if not os.path.lexists(prefix):
            return False
        if _is_link(prefix):
            return True
    return False


def _real_form(path: str) -> str | None:
    r"""候选路径的真实比较形态；`realpath` 异常返回 `None`（调用方按 `path_unresolvable` 拒绝）。

    走 `_exact_form`：真实包含比较不折叠大小写，`D:\Work` 与 `D:\work` 不会因大小写差异
    被当成同一个目录（宁可多拒，不可合并不同目录）。
    """
    try:
        resolved = os.path.realpath(path)
    except (OSError, TypeError, ValueError):
        return None
    return _exact_form(resolved)


def _resolved_path(path: str) -> str | None:
    """候选路径的真实路径原值（供调用方打开）；异常时 `None`。"""
    try:
        return os.path.realpath(path)
    except (OSError, TypeError, ValueError):
        return None


def _is_windows_absolute(path: str) -> bool:
    r"""Windows 上的完整盘符绝对路径或合法 UNC（含共享名之后的子路径）。

    `os.path.isabs` 在 Windows 上会把 `\x`（根相对）、`D:x`（盘相对）与 `\\?\` 设备前缀
    当作绝对，它不足以表达本层要求的形状，故单独判：盘符必须双字符且后面紧跟分隔符，
    UNC 必须同时有非空且合法的服务器名与共享名。裸盘符（`D:`）不合法。
    """
    normalized = path.replace("/", "\\")
    drive, remainder = os.path.splitdrive(normalized)
    if len(drive) == 2 and drive[0].lower() in _WINDOWS_DRIVE_LETTERS and drive[1] == ":":
        return remainder.startswith("\\")
    if not normalized.startswith("\\\\"):
        return False
    # UNC：取前两个非空分量作服务器与共享，两者都不得含非法字符或点/空格尾。
    segments = [segment for segment in normalized[2:].split("\\") if segment]
    if len(segments) < 2:
        return False
    return all(not _windows_name_bad(segment) for segment in segments[:2])


def _windows_name_bad(name: str) -> bool:
    """单个分量在 Windows 上不可接受：非法字符、尾点/尾空格或命中保留设备名。

    `:` 在已确认绝对形状之后只能出现在盘符位，因此分量里出现 `:` 即交替数据流写法；
    尾部点与空格会被文件系统解析剥掉（`dir.` 与 `dir` 落同一处），保留设备名则直接
    指向设备而不是目录项，两者都不允许进入受批准路径。
    """
    if ":" in name or "*" in name or "?" in name:
        return True
    if _WINDOWS_FORBIDDEN_CHARS & set(name):
        return True
    if name.endswith((".", " ", ":")):
        return True
    stem = name.split(".", 1)[0].upper()
    return stem in _WINDOWS_RESERVED_STEMS


def _shape_ok(path: object) -> bool:
    r"""路径形状判据：绝对、无控制字符、原始分量不含 `..`，Windows 另拒受控形态之外的写法。

    对**原始**串判断，不做规范化后再看：`..` 一旦出现即拒（不依赖 `normpath` 的收敛
    语义），相对路径即拒（因此解析器或服务的 cwd 无法参与归属）。

    Windows 上 `os.path.isabs` 会把根相对（`\x`）、盘相对（`D:x`）与设备前缀当成绝对，
    因此另走 `_is_windows_absolute`：只认完整盘符绝对或合法 UNC。在此基础上再拒：
    设备命名空间前缀（`\\?\`、`\\.\` 与 `/` 变体，它们绕过常规解析与父目录语义）、
    任一分量含交替数据流的 `:`、通配符与非法字符、尾部点/空格（Windows 解析会剥掉它们，
    落点与字面名字不是同一个），以及保留设备名（`CON`、`NUL`、`COM1` 等，含 `CON.txt`）。
    """
    if not isinstance(path, str) or not path.strip():
        return False
    if path != path.strip():
        return False
    if any(char in path for char in ("\x00", "\n", "\r", "\x0b", "\x0c")):
        return False
    if ".." in PurePath(path).parts:
        return False
    if not os.path.isabs(path):
        return False
    if not _IS_WINDOWS:
        return True
    flattened = path.replace("/", "\\")
    if flattened.startswith(("\\\\?\\", "\\\\.\\")):
        return False
    if not _is_windows_absolute(path):
        return False
    # 交替数据流不依赖分量解析：盘符绝对只允许盘符那一个 `:`，UNC 一个也不允许。
    if flattened.count(":") > (1 if flattened[1:2] == ":" else 0):
        return False
    return not any(_windows_name_bad(name) for name in PurePath(path).parts[1:])


def is_safe_literal_path(path: object) -> bool:
    """`_shape_ok` 的公开别名：来源适配器在**碰任何文件系统之前**自测路径形状。

    判据与 `authorize_store` 完全同源（绝对、无控制字符、原始分量不含 `..`，Windows 上只认
    完整盘符绝对或合法 UNC），因此适配器提前拒掉的形状与策略层会拒的是同一个集合：不存在
    「适配器放行、策略层拒绝」两套判据。返回布尔而不抛，调用方自己决定拒绝码：形状不合是
    不可信参数（`path_unsafe`），不是「文件不存在」（`not_found`）。

    本函数不做解析、不 `lstat`、不读 cwd：相对路径在这里就已经被拒，因此进程的当前目录
    无法参与归属（同一串相对路径在两个 cwd 下指向两个不同文件）。
    """

    return _shape_ok(path)


# ---------- 配置内部索引 ----------


@dataclass(frozen=True)
class _StoreRoot:
    """校验后的存储根：预先算好字面比较形态，避免每次查询重复规范化。"""

    source: str
    path: str
    allow_links: bool
    literal: str

    def real_literal(self) -> str | None:
        """根目录自身的真实形态；无法解析时 `None`（拒绝，不拿不确定位置当授权基准）。"""
        return _real_form(self.path)


@dataclass(frozen=True)
class _CwdRoot:
    """校验后的项目归属根：只用于判定记录属于哪个项目，不作读取基准。"""

    project: str
    path: str
    allow_links: bool
    literal: str

    def real_literal(self) -> str | None:
        """归属根自身的真实形态；无法解析时 `None`（不作归属判定基准）。"""
        return _real_form(self.path)


@dataclass(frozen=True)
class _Scope:
    """校验后的范围：项目名有序列表 + 逐源存储根 + 逐项目归属根（两套独立数据）。"""

    scope_id: str
    projects: tuple[str, ...]
    store_roots: tuple[_StoreRoot, ...]
    cwd_roots: tuple[_CwdRoot, ...]

    def store_roots_for(self, source: str) -> tuple[_StoreRoot, ...]:
        """该来源在本范围内的存储根（与项目无关），按配置顺序。

        归属轴**没有对应的按项目取根方法**：多项目歧义必须在全部项目的归属根上先查一轮，
        按项目取根会把歧义提前掩盖掉。
        """
        return tuple(root for root in self.store_roots if root.source == source)


class SessionPolicy:
    r"""授权策略：把显式配置变成「查询可否 / 存储路径可否读 / 记录属于哪个项目」的判定。

    典型用法（调用方负责从受控配置构造 `scopes`；本层不接受任意路径输入）::

        policy = SessionPolicy(
            [ScopeGrant(
                "work",
                projects=(ProjectGrant("repo-a", (CwdRootGrant(r"D:\work\repo-a"),)),),
                store_roots=(StoreRootGrant("pi", r"D:\agents\pi\sessions"),),
            )]
        )
        grant = policy.authorize_query("work", project="repo-a")     # 查询前收窄
        target = policy.authorize_store("work", "pi", candidate)     # 发现与读取共用
        owner = policy.authorize_attribution("work", record_cwd)     # 只判项目归属
        with open(target.readable_path, "rb"):                       # 只打开已验证值
            ...

    存储根与归属根是分开的：上例里 `D:\agents\pi\sessions` 可服务多个已批准项目（共享存储），
    而 `D:\work\repo-a` 只用来判定记录声称的 cwd 属于哪个项目，**不会**让它下面的任何文件
    变成可读对象。一条记录可发布需要 `authorize_store` 与 `authorize_attribution` 两项都通过；
    两项通过仍不证明记录确实来自那个项目（那只是一次路径→项目映射），来源绑定属适配器。

    构造只做配置自检，不触碰文件系统：配置非法直接 `PolicyDenied(CONFIG_INVALID)`，因为
    一份说不清授权边界的配置不能降级成「部分允许」。构造后所有判定只读自身索引，唯一的
    对外副作用是元数据探测（`lexists`/`lstat`/`isdir`/`isfile`/`realpath`）。
    """

    def __init__(self, scopes: Sequence[ScopeGrant]) -> None:
        """接收调用方给出的批准配置；空配置合法，但意味着一切拒绝。

        顶层只接受 `list`/`tuple`：其它 iterable（生成器、自定义容器等）不能表达一份确定的
        授权配置，固定 `config_invalid`，不“边送边接受”。
        """
        if not isinstance(scopes, (list, tuple)):
            raise PolicyDenied(RefusalCode.CONFIG_INVALID)
        entries: list[_Scope] = []
        for grant in scopes:
            entry = _build_scope(grant)
            if entry.scope_id in {built.scope_id for built in entries}:
                raise PolicyDenied(RefusalCode.CONFIG_INVALID)
            entries.append(entry)
        self._scopes: dict[str, _Scope] = {entry.scope_id: entry for entry in entries}

    # ---------- 范围与项目查询 ----------

    def scope_names(self) -> tuple[str, ...]:
        """已批准的授权范围标识（空元组表示未配置，一切查询都会被拒）。"""
        return tuple(self._scopes)

    def project_names(self, scope: object) -> tuple[str, ...]:
        """某范围内已批准的项目名（配置顺序）；未知 scope 一律拒绝。"""
        return self._entry(scope).projects

    def authorized_sources(self, scope: object) -> tuple[str, ...]:
        """某范围内出现于已批准存储根的来源，按 `KNOWN_SOURCES` 顺序。

        只回答「配置批准过哪里的存储」，不表示这些来源当前可读或已启用——可用状态属于
        `list_sources`/`coverage` 的职责，不扩大授权范围。不按项目收窄：存储根是来源级的，
        一个存储根可以服务多个已批准项目，而项目归属不能反过来证明存储已获批准。
        """
        entry = self._entry(scope)
        return _ordered_sources({root.source for root in entry.store_roots})

    # ---------- 查询前授权 ----------

    def authorize_query(
        self,
        scope: object,
        *,
        sources: object = None,
        project: object = None,
    ) -> QueryGrant:
        """校验一次查询的范围、来源与项目收窄；全部通过才返回可选来源与项目。

        - `scope` 必须精确命中已批准标识；未配置任何范围 → `scope_not_configured`。
        - `sources` 省略即「该范围内全部已批准来源」；给出时必须逐个是已知来源 ID 且在
          范围内有已批准的存储根。
        - `project` 可选（DES-API-01：省略即搜该范围内全部已批准项目），给出时必须是该
          范围内已批准的项目名；本层不接受任何路径形态充当 project。项目只收窄**可发布的
          记录**（逐条走 `authorize_attribution`）：存储根是来源级的、与项目无关，因此来源候选
          始终按本范围的存储根判定，`project` 参不参与都不改变可选来源集合。
        """
        entry = self._entry(scope)
        if project is not None:
            self._check_project(entry, project)
        narrowed = project if isinstance(project, str) else None
        selected = self._select_sources(entry, sources)
        projects = entry.projects if narrowed is None else (narrowed,)
        return QueryGrant(scope=entry.scope_id, sources=selected, projects=projects)

    @staticmethod
    def _check_project(entry: _Scope, project: object) -> None:
        """project 必须是本范围已批准的项目名（精确匹配，不做路径或模糊比较）。"""
        if not isinstance(project, str) or project not in entry.projects:
            raise PolicyDenied(RefusalCode.PROJECT_UNKNOWN)

    @staticmethod
    def _select_sources(
        entry: _Scope, sources: object
    ) -> tuple[str, ...]:
        """解析来源选择：返回已批准来源元组，或给出精确的拒绝码。"""
        allowed = {root.source for root in entry.store_roots}
        if sources is None:
            if not allowed:
                raise PolicyDenied(RefusalCode.SOURCE_NOT_AUTHORIZED)
            return _ordered_sources(allowed)
        if not isinstance(sources, (list, tuple)) or not sources:
            raise PolicyDenied(RefusalCode.SOURCE_NOT_AUTHORIZED)
        for name in sources:
            if not isinstance(name, str) or name not in KNOWN_SOURCES:
                raise PolicyDenied(RefusalCode.SOURCE_UNKNOWN)
            if name not in allowed:
                raise PolicyDenied(RefusalCode.SOURCE_NOT_AUTHORIZED)
        return _ordered_sources(set(sources))

    def _entry(self, scope: object) -> _Scope:
        """scope 精确查表；这是本模块对 scope 值的唯一操作（绝不把它当路径使用）。"""
        if not self._scopes:
            raise PolicyDenied(RefusalCode.SCOPE_NOT_CONFIGURED)
        if not isinstance(scope, str) or scope not in self._scopes:
            raise PolicyDenied(RefusalCode.SCOPE_UNKNOWN)
        return self._scopes[scope]

    # ---------- 存储路径授权（只授予读取，不给出项目归属） ----------

    def authorize_store(
        self,
        scope: object,
        source: object,
        path: object,
        *,
        kind: TargetKind = TargetKind.FILE,
    ) -> StoreGrant:
        """判断 `path` 是否落在该来源已批准的**存储根**内，通过则只授予读取。

        来源发现（逐个候选路径）与 `read_session_context`（打开之前）都调用本方法，两侧
        共用同一判据。返回的 `StoreGrant` **不含 project 字段**：存储位置在哪与记录属于哪个
        项目是两套独立数据，共享存储（一个会话库服务多个项目）不能从路径反推归属，
        因此每条可发布的记录必须另过一次 `authorize_attribution`。

        本方法不接受 `project` 参数：用项目收窄存储授权会造出「配了项目就能读该项目整个目录树」
        的误导语义。`path` 为 `None` 或形状不合都是调用方给的对象不可信 → `path_unsafe`，
        不开任何元数据旁路。
        """
        entry = self._entry(scope)
        # kind 是调用方参数完整性的判据：先拒非法值，不为一次不可信的调用做文件系统探测。
        if not isinstance(kind, TargetKind):
            raise PolicyDenied(RefusalCode.PATH_KIND_MISMATCH)
        if not isinstance(source, str) or source not in KNOWN_SOURCES:
            raise PolicyDenied(RefusalCode.SOURCE_UNKNOWN)
        source_id = source
        candidates = entry.store_roots_for(source_id)
        if not candidates:
            raise PolicyDenied(RefusalCode.SOURCE_NOT_AUTHORIZED)
        if not _shape_ok(path) or not isinstance(path, str):
            # isinstance 只做类型收窄：校验后的普通 str 就是拿去解析与作为结论基准的值。
            raise PolicyDenied(RefusalCode.PATH_UNSAFE)
        literal = _literal_form(path)
        if literal is None:
            raise PolicyDenied(RefusalCode.PATH_UNSAFE)
        matched = tuple(root for root in candidates if _is_within(literal, root.literal))
        if not matched:
            raise PolicyDenied(RefusalCode.PATH_OUT_OF_SCOPE)
        requested = path
        resolved, real = _resolve_real(requested)
        _require_within_all_real(requested, real, matched)
        return _store_grant(resolved, kind, entry.scope_id, source_id)

    # ---------- 项目归属核对（只判项目，不授予任何读取） ----------

    def authorize_attribution(
        self,
        scope: object,
        path: object,
        *,
        project: object = None,
    ) -> AttributionGrant:
        """核对记录声称的 cwd（`path`）属于本范围内哪个已批准项目。

        返回的 `AttributionGrant` 只有项目名，**没有 `readable_path`**：归属成立不表示
        该目录可读，批准一个项目的 cwd 也绝不把整个项目树变成可读对象（正文只能来自
        `authorize_store`）。适配器声称的 `cwd`/`project_quality` 仍只是待核对证据。

        判定顺序是「字面入口先判，再进文件系统探测」：字面轴（`_literal_form` 形态）在本范围
        全部项目的归属根上一轮跑完，**不命中即固定 `attribution_unmatched`**，此时不解析、不
        探测、不 `lstat`，也就不会拿一个不可信的 UNC 写法去触发 SMB 名解析或挂载。字面命中后
        真实轴只在这些候选根内**复核与补查歧义**（同项目重叠根、字面未命中但真实命中的根），
        真实轴不能替代字面入口把一条完全不在批准根下的路径判为归属。
        合并后的候选项目多于一个即 `attribution_ambiguous`。因此显式指定的
        `project` **不能掩盖冲突**（嵌套/重叠配置下它只能选到错的项目）；project 合法但与
        唯一判定结果不符 → `project_mismatch`；字面轴不命中任何项目 → `attribution_unmatched`。
        同项目多条重叠归属根时，候选必须同时落在**每一条**已匹配根的字面与真实位置内，
        不因配置顺序而变宽（全部约束同时成立才通过）。
        """
        entry = self._entry(scope)
        if project is not None:
            self._check_project(entry, project)
        # 证据缺失单独报：没有归属证据不等于越界，也不是形状错误。
        if path is None:
            raise PolicyDenied(RefusalCode.ATTRIBUTION_UNKNOWN)
        if not _shape_ok(path) or not isinstance(path, str):
            # isinstance 只做类型收窄：校验通过后的普通 str 就是后续使用的值，不再 str() 转换。
            raise PolicyDenied(RefusalCode.PATH_UNSAFE)
        literal = _literal_form(path)
        if literal is None:
            raise PolicyDenied(RefusalCode.PATH_UNSAFE)
        requested = path
        literal_matched = tuple(
            root for root in entry.cwd_roots if _is_within(literal, root.literal)
        )
        if not literal_matched:
            # 字面入口不命中即固定拒绝：在碰任何候选路径的元数据之前返回，不可信的 UNC
            # 形状因此不会经 `realpath`/`lstat` 触发 SMB 名解析；真实轴只能在命中的候选内
            # 复核与补查歧义，不能替代这一步把范围外的路径判为归属。
            raise PolicyDenied(RefusalCode.ATTRIBUTION_UNMATCHED)
        literal_hits = frozenset(literal_matched)
        resolved, real = _resolve_real(requested)
        real_matched: list[_CwdRoot] = []
        for root in entry.cwd_roots:
            root_real = root.real_literal()
            if root_real is None:
                # 只有作为比较基准的根才要求可解析：无关项目的根不可达不能改变本判定。
                if root in literal_hits:
                    raise PolicyDenied(RefusalCode.PATH_UNRESOLVABLE)
                continue
            if _is_within(real, root_real):
                real_matched.append(root)
        owners = {root.project for root in literal_matched}
        owners.update(root.project for root in real_matched)
        if len(owners) > 1:
            raise PolicyDenied(RefusalCode.ATTRIBUTION_AMBIGUOUS)
        # 不在此处再判 owners 为空：字面入口已拦住不命中，走到这里 owners 至少含一个项目。
        owner = next(iter(owners))
        if project is not None and owner != project:
            raise PolicyDenied(RefusalCode.PROJECT_MISMATCH)
        # 同项目的重叠根：两轴命中合并去重后全部作为约束，不分先后。
        matched = tuple(dict.fromkeys([*literal_matched, *real_matched]))
        _require_within_all_real(requested, real, matched)
        if not os.path.isdir(resolved):
            raise PolicyDenied(
                RefusalCode.PATH_MISSING
                if not os.path.lexists(resolved)
                else RefusalCode.PATH_KIND_MISMATCH
            )
        return AttributionGrant(scope=entry.scope_id, project=owner)


def _resolve_real(requested: str) -> tuple[str, str]:
    """对调用方原写法做一次 `realpath`，返回（真实路径原值, 真实比较形态）。

    `requested` 是调用方原写法：它是 `realpath` 的解析目标，也是链路探测的输入。字面包含
    阶段算出的折叠形态只用于比较，绝不当解析目标；真实比较另走 `_exact_form`，不折叠大小写。
    解析不出确定位置 → `path_unresolvable`（不拿位置不确定的目录当基准）。
    """
    resolved = _resolved_path(requested)
    real = _exact_form(resolved) if resolved is not None else None
    if resolved is None or real is None:
        raise PolicyDenied(RefusalCode.PATH_UNRESOLVABLE)
    return resolved, real


def _require_within_all_real(
    requested: str,
    real: str,
    roots: Sequence[_StoreRoot] | Sequence[_CwdRoot],
) -> None:
    """第二道边界：必须同时落在**每一条**已匹配根目录的真实位置之内；链接按配置处理。

    不按顺序取第一条匹配根：同一项目内的重叠/嵌套根如果只比一条，配置顺序就成了变宽通道。
    这里要求全部约束同时成立，取不到同时成立的那一个就拒绝。`allow_links` 同样取保守集：
    只要有一条匹配根未显式允许链接，链路上出现链接即 `path_reparse`。两项事实都由本层
    自行探测，没有任何调用方可传入的旁路。
    """
    for root in roots:
        root_real = root.real_literal()
        if root_real is None:
            raise PolicyDenied(RefusalCode.PATH_UNRESOLVABLE)
        if not _is_within(real, root_real):
            raise PolicyDenied(RefusalCode.PATH_ESCAPE)
    if any(not root.allow_links for root in roots) and _chain_has_link(requested):
        raise PolicyDenied(RefusalCode.PATH_REPARSE)


def _store_grant(resolved: str, kind: TargetKind, scope_id: str, source: str) -> StoreGrant:
    """存储对象的存在性与类型核对：只用 `isdir`/`isfile` 元数据，不打开、不读正文。

    进入本函数前 `kind` 已由 `authorize_store` 验为 `TargetKind` 成员；`ANY` 不另做判据，
    目录与文件均视为命中。比较用 `is`（枚举成员）而非 `==`，避免字符串等价物被当作合法请求。
    `readable_path` 取 `realpath` 的**原值**（不取比较用的归一形态）：调用方要打开的就是
    本层刚刚复核过的那个位置。
    """
    is_directory = os.path.isdir(resolved)
    is_file = os.path.isfile(resolved)
    if not is_directory and not is_file:
        raise PolicyDenied(RefusalCode.PATH_MISSING)
    if kind is TargetKind.DIRECTORY and not is_directory:
        raise PolicyDenied(RefusalCode.PATH_KIND_MISMATCH)
    if kind is TargetKind.FILE and not is_file:
        raise PolicyDenied(RefusalCode.PATH_KIND_MISMATCH)
    return StoreGrant(
        scope=scope_id,
        source=source,
        readable_path=resolved,
        is_directory=is_directory,
    )


def _ordered_sources(names: Iterable[str]) -> tuple[str, ...]:
    """按 `KNOWN_SOURCES` 的固定顺序去重排序，保证对外输出稳定。"""
    wanted = set(names)
    return tuple(name for name in KNOWN_SOURCES if name in wanted)


def _build_scope(grant: object) -> _Scope:
    """校验单个范围配置：标识合法、项目唯一且非空、逐项目至少一条归属根、存储根来源已知。

    形状错误统一以 `config_invalid` 拒绝，不开旁路：一份说不清边界的配置不能降级成
    「部分允许」。存储根允许为空（那表示本范围不授予任何读取）。
    """
    if not isinstance(grant, ScopeGrant):
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    scope_id = grant.scope_id
    if (
        not isinstance(scope_id, str)
        or not scope_id.strip()
        or scope_id != scope_id.strip()
        or "/" in scope_id
        or "\\" in scope_id
    ):
        # scope 只是标识符：含分隔符的写法几乎一定是把路径误当范围传了进来。
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    if not isinstance(grant.store_roots, tuple):
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    store_roots = tuple(_build_store_root(root) for root in grant.store_roots)
    cwd_roots: list[_CwdRoot] = []
    projects: list[str] = []
    if not isinstance(grant.projects, tuple):
        # 与 store_roots 同规则：项目集合必须是普通 tuple，不接其它 iterable。
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    for project in grant.projects:
        if not isinstance(project, ProjectGrant) or not isinstance(project.cwd_roots, tuple):
            raise PolicyDenied(RefusalCode.CONFIG_INVALID)
        name = project.name
        if not isinstance(name, str) or not name.strip() or name in projects:
            raise PolicyDenied(RefusalCode.CONFIG_INVALID)
        if not project.cwd_roots:
            # 没有任何归属根的项目无法发布正文（所有记录都只能 unmatched）：视为配置错误。
            raise PolicyDenied(RefusalCode.CONFIG_INVALID)
        projects.append(name)
        for root in project.cwd_roots:
            cwd_roots.append(_build_cwd_root(name, root))
    if not projects:
        # 「已批准项目为空」等于该范围没有任何可查内容：视为配置错误，不静默通过。
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    return _Scope(
        scope_id=scope_id,
        projects=tuple(projects),
        store_roots=store_roots,
        cwd_roots=tuple(cwd_roots),
    )


def _root_literal(path: object) -> str:
    """根目录共有校验：形状合法且能算出字面比较形态，否则配置非法。"""
    if not _shape_ok(path):
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    literal = _literal_form(path)
    if literal is None:
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    return literal


def _build_store_root(root: object) -> _StoreRoot:
    """校验单条存储根：来源 ID 已知、绝对路径、比较形态可算出（不绑项目）。"""
    if not isinstance(root, StoreRootGrant) or not isinstance(root.allow_links, bool):
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    if not isinstance(root.source, str) or root.source not in KNOWN_SOURCES:
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    return _StoreRoot(
        source=root.source,
        path=root.path,
        allow_links=root.allow_links,
        literal=_root_literal(root.path),
    )


def _build_cwd_root(project: str, root: object) -> _CwdRoot:
    """校验单条归属根：绝对路径、比较形态可算出（不绑来源）。"""
    if not isinstance(root, CwdRootGrant) or not isinstance(root.allow_links, bool):
        raise PolicyDenied(RefusalCode.CONFIG_INVALID)
    return _CwdRoot(
        project=project,
        path=root.path,
        allow_links=root.allow_links,
        literal=_root_literal(root.path),
    )
