r"""已授权存储对象的只读有界行读取边界（DES-SEC-01「检查后打开竞态」、DES-API-01 发布边界）。

本模块只回答一件事：**已经过策略层授权的单个普通文件**能不能被安全地打开并按行有界读取。
它实现的是 05 里那条由来源层承担、`policy.py` 明确声明不实现的后续要求：

> 打开后把**句柄导出的最终路径**重新经一次同样的路径授权（策略层 `authorize_store`），并核验
> 文件身份（卷号 + 文件标识等）与打开前的检查基准一致；最终路径无法安全核验时结果不得发布。
> 不能把路径前缀比较当作强隔离保证。

定位与范围：

- 授权判定仍然**只在策略层**：调用方显式传入 `SessionPolicy` 实例、`scope`、`source` 与**单个
  存储路径**。本模块不发现目录、不枚举来源、不打开数据库（SQLite 属来源适配器）、不解压
  （DSH 多帧属来源适配器）、不接 `server.py`，也不接受客户端任意路径。
- 只读**普通文件**：授权用 `TargetKind.FILE`，并从**实际句柄**再确认一次「仍是普通文件」。
  目录、FIFO、socket、字符设备、块设备一律拒绝（`not_regular_file`）。正文之前还有一次固定
  形态核对：命中归档/数据库/可执行魔数 → `not_plain_text`，确认窗口内含 NUL →
  `binary_content`（本层不解压，见「未验证边界」）。
- 读取有界：单行字节、总字节、行数三项硬限在入口钳制（调用方只能收紧），读循环不会越过。
  任一触限都**如实标记不完整**（`ReadStop` + `complete=False`），不冒充读完。
- **对外就是行字节本身**：`AuthorizedLineReader` 直接是 `Iterable[bytes]`，每次 `__next__`
  交出「本次扫描当场收集到的那一整行」（含结尾的 `\n`；文件末尾无换行时那行为假）。
  本层只朝前顺序读一遍：行交出后其字节离开本层，不再向文件重复请求，调用方拿到的是行内容
  本身，不是可用于二次取数的定位值。
- 不缓存全文：内存里最多同时存在**一个尚未交出的行缓冲**，其长度受 `max_line_bytes` 硬限；
  一次底层请求最多 `_SCAN_WINDOW_BYTES` 字节（文件对象以 `buffering=0` 建立，无缓冲层预读）。
  对外出口只有逐行字节与整数计数，本层不提供
  整份文件的出口（没有 `read()`/`getvalue()`），无界读取在这里不可表达。

打开前授权 + 打开后复核（顺序即语义）
------------

1. `authorize_store(scope, source, path, kind=FILE)` 决定「这个存储对象可读吗」。未通过即按
   策略层的固定码拒绝，本模块不打开任何东西。
2. 用该结论返回的 `readable_path`（策略层自己 `realpath` 出来的值，不是调用方原写法）建立
   **打开前基准**：按下面第 3 步同一套标志安全打开该路径，从**那个句柄**取身份（卷号 +
   文件标识）并确认对象类型，然后立刻关闭它。拿不到基准 → `baseline_unavailable`；基准不是
   普通文件 → `not_regular_file`。**没有基准就不读**：复核必须有比对对象。
3. 只读打开该 `readable_path`（`O_RDONLY` + 平台可用的 `O_BINARY`/`O_NONBLOCK`/`O_NOCTTY`；
   不创建、不截断、不加锁、不写任何文件），得到**裸描述符**，此刻唯一关闭者是本函数。
4. 读取**任何正文之前**，用这个裸描述符完成两路复核（两者都由本模块自己从**已打开的句柄**
   导出，绝不另开第三个句柄来「代表」它）：
   - **文件身份**：`_probe_handle_identity(fd)` 从该句柄取 (卷号, 文件标识)，与第 2 步基准
     逐项比较，并确认句柄对象仍是普通文件。两侧走**同一个平台身份函数、同一组字段**：
     Windows 用 `GetFileInformationByHandleEx` 的 `FileIdInfo`（信息类 18）取 `VolumeSerialNumber`
     （64 位）+ `FileId`（16 字节 → 整数）；POSIX 用 `os.fstat` 的 (`st_dev`, `st_ino`)。
     **不假设 `os.stat` 与 `os.fstat` 在 Windows 上同源**，也不把 ctypes 直取的字段与 `os.stat`
     字段混比。任一项不相等 → `file_replaced`；平台无此能力、结构声明对不上或文件系统给出
     全零标识（`FileIdInfo` 得不到 128 位标识时的返回值）→ `file_identity_unsupported`，这
     **不是**放行，也不是「已核验」，也**不回退**到 32 位文件索引。
   - **最终路径**：从句柄导出实际落点（Windows `GetFinalPathNameByHandleW`，POSIX
     `/proc/self/fd/<fd>` 读链），剥掉设备命名空间前缀后**再走一次完全相同的
     `authorize_store`**（同一策略实例、同一 scope、同一 source、同一 kind，因此不存在
     「首次严格、复核宽松」的差额）。导不出来或形态无法安全解释（`\\?\Volume{...}`、命名管道
     等）→ `handle_path_unsupported`；读链带 ` (deleted)`（对象已被 unlink）→ `file_replaced`；
     策略层第二次拒绝 → 原样传播它的固定码；第二次结论的 `readable_path` 与句柄落点不是同一
     位置 → `handle_path_changed`。
5. 两路复核全过后，才把描述符交给 `os.fdopen(..., "rb", buffering=0, closefd=True)`——这是本模块
   里**唯一**改变关闭者的一步，无缓冲形态让本层的请求量就是底层请求量（见「计量口径」）。
   随后做一次固定窗口的形态确证（`not_plain_text` / `binary_content`），确证窗口那 16 字节
   留在行缓冲开头成为首行的开头。

调用方不能替本模块作证
------------

`authorize_read` **没有**任何「已解析真实路径」「无链接」「身份已核对」之类的旁路参数，也没有
布尔开关。所有复核输入都来自本模块自己发起的系统调用（句柄身份/句柄读链/
`GetFinalPathNameByHandleW`）。复核派生的原值（最终路径、卷号、文件标识）**不对外导出**：
`ReadOutcome` 只有整数、布尔与闭合枚举，绝对个人路径与系统错误原文不进结论、不进日志
（DES-SEC-01）。

调用方义务：不完整状态必须合并
------------

`reader.outcome().complete` 只说明**字节层面**读到了什么程度（EOF 是否确立、是否触限、是否
提前退出），它对「这个会话是否完整」一无所知；解析侧的最终状态（`parser.finish()` 之后的
`stats.partial` 等）也只说明它自己那一段。两者是**不同来源的两个缺口**，调用方必须同时合并
才得出一句话：任一为不完整就是不完整，并各自保留自己的原因（本层的 `ReadStop` 与解析层的
`IssueCode` 不互相顶替，也不得把 `complete=True` 单独当成「会话完整」或「可发布」）。
提前 `break`/抛异常退出行循环再读 `outcome()` 时，本层给 `closed_before_eof` + `complete=False`，
不会因为「没读到内容」而谎报读完。

本模块消除的是什么、不是什么
------------

- **是**：把「检查的路径」与「读的句柄」绑成同一个身份，绑定范围就是**实际核验的那个时间
  窗口**——核验通过的那一刻，这个句柄是普通文件、落点在授权范围内、身份与基准相同。名字在
  两次授权之间被换成另一个文件（同路径替换、换链接目标、unlink 后重建）会被第 4 步拦住。
- **不是**：快照。已核验的那个对象**仍可被其它写者原地改写内容**——只读打开不加锁，本模块
  不宣称拿到任何排他访问，也不提供任何一致性证明。「交出的字节」是「这个身份的对象在被读到
  那一刻的字节」，不是「授权那一刻的字节」；内容一致性归上层（解析与整流核对）。
- **不是**：覆盖硬链接。同一 inode 经另一个已批准名字（硬链接）打开，句柄身份与基准**完全
  相同**，本层判不出「换了名字」；这种情况只有策略层对那两个名字各自的授权判定有意义。
- **不是**：窗口消失。第 2 步基准句柄关闭与第 3 步打开之间仍是一次系统调用的间隔。本层只
  宣称**跨这个名字的替换会被检出并拒绝**。
- **不是**：「打开之前绝无副作用」。第 2 步本身就带标志打开了一次路径；若那个名字在判定之后、
  打开之前被换成设备节点，`open` 仍可能触发该设备自己的打开语义。`O_NONBLOCK`/`O_NOCTTY`
  只压制「打开即阻塞」和「成为控制终端」这两类，本层不宣称更多。
- **不是**：发布许可。发布仍需 05 的其余各项（`authorize_attribution` 归属核对、整流身份核对、
  脱敏）；本模块只回答「打开并读这个文件是否安全」，不判断内容能不能给别人看。

计量口径（三条上限各自约束什么）
------------

- `max_line_bytes` 约束**单行字节数**，也约束行缓冲长度：尚未见到换行的部分一旦达到该上限即
  判 `line_bytes_limit`，这一行不吐出（含行尾符正好等于上限的行仍能完整吐出）。形态确证窗口
  的字节会留在行缓冲里，所以入口还要求 `max_line_bytes >= _MAGIC_READ_BYTES`。
- `max_total_bytes` 约束**本层向文件请求并得到的字节总量**：每一次底层请求都扣账，包括正文
  之前的形态确证窗口；单趟顺序读使每个字节只计一次。文件对象由 `_transfer_fd` 以 `buffering=0`
  建立（无 `BufferedReader` 缓冲层），所以本层的请求量就是底层请求量：`consumed_bytes` 是
  **每次底层请求的预算**，一次请求至多 `min(_SCAN_WINDOW_BYTES, 单行剩余, 总预算剩余)` 字节，
  不因缓冲层预读而让未被本层计账的字节进过内核。预算恰好用到零剩余而未能确认 EOF 时，
  报 `total_bytes_limit` + 不完整（本层不会把「预算用尽」当成「文件读完」）。低于确证窗口的
  预算在任何文件系统探测之前按 `args_invalid` 拒绝——本层不在小预算上仍读固定 16 字节，
  也不假装「确证过但没读够」。
- `max_lines` 约束吐出的行数（EOF 后残留的无换行尾行同样受此约束，不会多开一行）。触限时若
  尚未确认 EOF，就报 `line_limit` + 不完整：本层不做额外的「再读一字节确认结尾」探测，因此
  恰好读满 `max_lines` 行的会话会被保守地报成未读全。
- 停止或提前退出时缓冲区里**未交出的字节**如实计入 `bytes_discarded`，其中的完整行数与残留
  一起计入 `truncated_lines`；不猜测未读部分还有多少。
- `eof_reached` 只由「某次读取返回 0 字节」确立；`complete` 要求 EOF 已确立、读取自然收束且
  未触任何上限。

生命周期（裸描述符唯一所有权）
------------

`os.open` 返回的裸描述符在整个复核期间**只有一个关闭者**（`authorize_read` 自己）：复核中的
任一步失败——包括 `PolicyDenied`、ctypes 抛出的非 `OSError`、`KeyboardInterrupt` 等
`BaseException`——都在归还那一个描述符后原样重抛，本层不把一次失败改写成另一个结论，也不在
移交失败处主动留下泄漏的描述符（`os.fdopen` 失败不关闭描述符，所以失败仍由本层关闭它）。
只有 `os.fdopen(..., "rb", buffering=0, closefd=True)` **成功**那一刻关闭者才换成文件对象；此后归还走
`AuthorizedLineReader.close()`。`with authorize_read(...) as reader:` 的 `__exit__` 保证任何出口
（读完、触限、调用方异常、中断）都关闭句柄；关闭后不可再读，重复 `close()` 幂等。

平台支持（本增量按「不支持即拒」实现）
------------

- Windows：身份来自 `ctypes` + `msvcrt.get_osfhandle` + `GetFileInformationByHandleEx`
  （`FileIdInfo` = 18：64 位 `VolumeSerialNumber` + 16 字节 `FileId`；基准句柄与读取句柄同一
  函数、同两组字段）；对象类型由同一句柄的两次独立查询判定——`GetFileType` 排除非磁盘对象
  （字符设备/管道/网络重定向），`FileAttributeTagInfo`（信息类 9）的 `FileAttributes` 排除目录；最终路径经
  `GetFinalPathNameByHandleW`。**本层未在任何机器上执行过这条 ctypes 路径**，只做静态核对与
  完整类型声明（`argtypes`/`restype`/`DWORD` 长度/结构体大小与字段偏移自检/两段式缓冲区），
  失败一律降为固定码。`GetFileType` 对网络重定向返回 `FILE_TYPE_REMOTE`，本层按非磁盘对象拒：
  这是保守方向，可能拒掉真机上仍可正常读取的 SMB 重定向。SMB 上 `FileIdInfo` 给出的 128 位
  标识是否稳定**未实测**；策略层对 UNC、设备命名空间与链接的形状限制不变，本层不据此放开
  任何路径形态。
- Linux：身份与类型来自同一句柄的 `os.fstat`（`S_ISREG` + `st_dev`/`st_ino`）；本层的类型判定
  在各平台都是身份函数内的独立查询，不与身份字段混比；最终路径来自
  `/proc/self/fd/<fd>` 读链。同样未实测。
- macOS/BSD 等没有 `/proc/self/fd` 的平台：本模块**没有**句柄侧最终路径导出通道，固定
  `handle_path_unsupported` 拒绝。`/dev/fd/<fd>` 的 `realpath` 不是句柄导出，不能拿来冒充。
- 因此「本模块能在真实会话文件上工作」这句话本轮不成立：见文末未验证清单。

依赖限制（DES-ARCH-02）：只用标准库与本包 `policy.py` 的公开名；不导入 `mcp`、`server.py`、
`models.py`、来源适配器、`sqlite3`、`gzip`/`zstd`；不写文件、不加锁、不建临时文件、不写日志。
运行前提：Python 3.11+（`StrEnum`）。
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat as stat_module
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum

from .policy import SessionPolicy, TargetKind

#: 本模块的公开出口。`READ_REFUSAL_MESSAGES` 与 `ReadRefusalCode` 一同维护：它把固定文案直接
#: 交给调用方组织对外 reason，避开 `policy.REFUSAL_MESSAGES` 需要额外入口的做法（本模块自己的
#: 表就是本层唯一的文案来源）。
__all__ = [
    "READ_REFUSAL_MESSAGES",
    "DEFAULT_MAX_LINE_BYTES",
    "DEFAULT_MAX_LINES",
    "DEFAULT_MAX_TOTAL_BYTES",
    "HARD_MAX_LINE_BYTES",
    "HARD_MAX_LINES",
    "HARD_MAX_TOTAL_BYTES",
    "AuthorizedLineReader",
    "FileVersion",
    "ReadOutcome",
    "ReadRefusalCode",
    "ReadStop",
    "SafeReadDenied",
    "authorize_read",
    "authorize_raw_bytes",
]

_IS_WINDOWS = os.name == "nt"

#: 单行字节上限默认值：与 `sources/pi.py` 的 `MAX_LINE_BYTES` 同值（人工核对，不导入来源模块）。
DEFAULT_MAX_LINE_BYTES = 1_048_576
#: 总读取字节上限默认值：与查询层每源预算同量级（人工核对）。
DEFAULT_MAX_TOTAL_BYTES = 8_388_608
#: 行数上限默认值：不高于解析侧 `MAX_LINES_PER_STREAM`，本层不放松任何更严的上限。
DEFAULT_MAX_LINES = 200_000

#: 三项硬钳制：调用方只能收紧，不能放宽，因此「给个大预算」不是绕过有界性的入口。
HARD_MAX_LINE_BYTES = 1_048_576
HARD_MAX_TOTAL_BYTES = 67_108_864
HARD_MAX_LINES = 200_000

#: 扫描窗口上限：一次底层请求最多取这么多字节，与单行预算解耦（长行按窗口推进）。
_SCAN_WINDOW_BYTES = 65_536
#: 句柄导出路径的最大长度（Win32 设备形式上限约 32767 个字符）；超过即拒，不猜截断点。
_MAX_HANDLE_PATH_CHARS = 32_768
#: 首次探测调用用的固定缓冲区字符数：返回值超过它才二次分配。
_PATH_PROBE_CHARS = 1024
#: 正文之前用于识别压缩流/二进制的固定窗口长度（只比长度与固定字节，不单独保留为诊断值）。
_MAGIC_READ_BYTES = 16

_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"\x1f\x9d",              # compress (LZW)
    b"BZh",                   # bzip2
    b"\x7fELF",               # 可执行对象，不是会话文本
    b"MZ",                   # PE
    b"SQLite format 3\x00",   # 数据库文件
    b"7z\xbc\xaf\x27\x1c",    # 7z
    b"PK\x03\x04",            # zip
    b"PK\x05\x06",
    b"%PDF-",
    b"\x00\x00\x01\x00",      # 图标/位图类
    b"\xfd\x37\x7a\x58\x5a",  # xz
    b"\x28\xb5\x2f\xfd",      # zstd 规范帧
)
_GZIP_MAGIC = b"\x1f\x8b"
_ZLIB_LEVEL_BYTES = frozenset((0x01, 0x5E, 0x9C, 0xDA))
_ZSTD_SKIPPABLE_FIRST_MIN = 0x50
_ZSTD_SKIPPABLE_FIRST_MAX = 0x5F
_ZSTD_SKIPPABLE_TAIL = b"\x2a\x4d\x18"

# Windows 句柄侧常量：两个结构体与两个信息类编号均取 winnt.h 的定义（本轮只静态核对，未真机执行）。
#: FILE_INFO_BY_HANDLE_CLASS（winnt.h）中本层只取两项：`FileAttributeTagInfo = 9`（两个 DWORD：
#: `FileAttributes` + `ReparseTag`）与 `FileIdInfo = 18`（`FILE_ID_INFO`：`ULONGLONG VolumeSerialNumber`
#: + `FILE_ID_128 FileId`，16 字节）。二者相邻关系：`MaximumFileInformationByHandleClass = 16`、
#: `FileIdHintInfo = 17`、`FileIdInfo = 18`。编号与结构布局本轮未真机核对，错只会让判据读不到位
#: （已列入文末未验证清单第 1 条），不拿它当已确认事实。
_FILE_ATTRIBUTE_TAG_INFO = 9
_FILE_ID_INFO = 18
_FILE_ATTRIBUTE_DIRECTORY = 0x0000_0010
_FILE_TYPE_DISK = 0x0000_0001
_FILE_TYPE_CHAR = 0x0000_0002
_FILE_TYPE_PIPE = 0x0000_0003
_FILE_TYPE_REMOTE = 0x0000_8000
_NON_DISK_FILE_TYPES = frozenset(
    (_FILE_TYPE_CHAR, _FILE_TYPE_PIPE, _FILE_TYPE_REMOTE)
)


class ReadRefusalCode(StrEnum):
    """读取被拒的固定原因码：闭合集合，可安全进日志；不含路径、句柄值或系统错误原文。"""

    ARGS_INVALID = "args_invalid"
    POLICY_NOT_SESSION = "policy_not_session"
    BASELINE_UNAVAILABLE = "baseline_unavailable"
    NOT_REGULAR_FILE = "not_regular_file"
    OPEN_FAILED = "open_failed"
    HANDLE_PATH_UNSUPPORTED = "handle_path_unsupported"
    HANDLE_PATH_CHANGED = "handle_path_changed"
    FILE_REPLACED = "file_replaced"
    HANDLE_IDENTITY_UNAVAILABLE = "handle_identity_unavailable"
    FILE_IDENTITY_UNSUPPORTED = "file_identity_unsupported"
    HANDLE_READ_FAILED = "handle_read_failed"
    HANDLE_CLOSED = "handle_closed"
    NOT_PLAIN_TEXT = "not_plain_text"
    BINARY_CONTENT = "binary_content"


#: 每个原因码一句固定说明；不拼接 scope、来源、路径、句柄值、errno 或异常消息。
READ_REFUSAL_MESSAGES: dict[ReadRefusalCode, str] = {
    ReadRefusalCode.ARGS_INVALID: "拒绝：调用参数不是本层接受的普通字面值、超出固定上限或容不下形态确证窗口。",
    ReadRefusalCode.POLICY_NOT_SESSION: "拒绝：授权入口不是本包的策略层实例。",
    ReadRefusalCode.BASELINE_UNAVAILABLE: "拒绝：无法建立打开前的文件身份基准，不读正文。",
    ReadRefusalCode.NOT_REGULAR_FILE: "拒绝：目标不是普通文件（目录、设备、管道或其它对象）。",
    ReadRefusalCode.OPEN_FAILED: "拒绝：只读打开失败。",
    ReadRefusalCode.HANDLE_PATH_UNSUPPORTED: "拒绝：无法从已打开的句柄导出最终路径，平台或对象形态不支持。",
    ReadRefusalCode.HANDLE_PATH_CHANGED: "拒绝：句柄最终路径与策略层复核时刻认定的位置不一致。",
    ReadRefusalCode.FILE_REPLACED: "拒绝：句柄身份或落点与打开前基准不一致，目标已被替换。",
    ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE: "拒绝：无法从已打开的句柄取得文件身份。",
    ReadRefusalCode.FILE_IDENTITY_UNSUPPORTED: "拒绝：本平台不能给出可比较的卷号与文件标识。",
    ReadRefusalCode.HANDLE_READ_FAILED: "拒绝：读取失败，句柄状态不可信。",
    ReadRefusalCode.HANDLE_CLOSED: "拒绝：读取器已关闭。",
    ReadRefusalCode.NOT_PLAIN_TEXT: "拒绝：命中归档、数据库或可执行对象的固定形态，本层不解压、不打开。",
    ReadRefusalCode.BINARY_CONTENT: "拒绝：确认窗口内含 NUL 的字节流不是本层可服务的文本存储对象。",
}


class ReadStop(StrEnum):
    """读取停止的固定类别：`complete` 为假时必有对应类别，不靠异常消息表达。"""

    EXHAUSTED = "exhausted"
    LINE_BYTES_LIMIT = "line_bytes_limit"
    TOTAL_BYTES_LIMIT = "total_bytes_limit"
    LINE_LIMIT = "line_limit"
    CLOSED_BEFORE_EOF = "closed_before_eof"


class SafeReadDenied(Exception):
    """读取被拒：只携带固定原因码，消息取固定文案，不含调用方输入与系统错误原文。"""

    def __init__(self, code: ReadRefusalCode) -> None:
        if not isinstance(code, ReadRefusalCode):
            raise TypeError("SafeReadDenied accepts a ReadRefusalCode only")
        self.code = code
        super().__init__(READ_REFUSAL_MESSAGES[code])


@dataclass(frozen=True)
class FileVersion:
    """同一授权读取句柄确立的文件版本：卷号、文件标识、体积与整文件 SHA-256 摘要。

    摘要在同趟 `AuthorizedLineReader` 的字节流上顺手算出（每个底层返回块进 `_read_chunk`
    即更新），**不二次读、不按路径 stat**；因此只有 `complete=True`（EOF 确立且未触限）时
    摘要才覆盖整个文件。同大小的改写会改变摘要，故体积相等不足以冒充未修改。

    本对象只供包内引用账本核对使用：真实卷号/文件标识不进入任何对外结果，本类不提供
    公开序列化通道（无 `as_public_dict`）。
    """

    volume: int
    file_id: int
    size_bytes: int
    content_sha256: str
    complete: bool


@dataclass(frozen=True)
class ReadOutcome:
    """一次读取的结论：整数 + 布尔 + 闭合枚举，可直接进日志与不完整覆盖信息。

    `complete` 只在 EOF 已确立、读取自然收束且未触任何上限时为真。`consumed_bytes` 是本层
    **发起的每次底层请求返回的字节总量**（含正文之前的形态确证窗口）：文件对象以 `buffering=0`
    建立，本层的每一次请求都至多 `min(_SCAN_WINDOW_BYTES, 单行剩余, 总预算剩余)` 字节，一次请求
    对应一次底层读，单趟顺序读使每字节只计一次。
    `truncated_lines`/`bytes_discarded` 只统计本层判定「不再交出」的行与字节（含停止
    时缓冲区里已扫到但未吐出的完整行），不猜测未读部分还有多少。本结论只描述字节层面读到
    什么程度，调用方必须与解析层的最终状态合并后再对外表述。
    """

    complete: bool
    reason: ReadStop | None
    lines_read: int
    consumed_bytes: int
    truncated_lines: int
    bytes_discarded: int
    eof_reached: bool

    def as_public_dict(self) -> dict[str, object]:
        """固定键快照；值为整数、布尔或闭合枚举字符串，不含路径与正文。"""
        return {
            "complete": self.complete,
            "reason": self.reason.value if self.reason is not None else None,
            "lines_read": self.lines_read,
            "consumed_bytes": self.consumed_bytes,
            "truncated_lines": self.truncated_lines,
            "bytes_discarded": self.bytes_discarded,
            "eof_reached": self.eof_reached,
        }


# ---------- 位置比较（与策略层同取向：规范化后逐分量相等，绝不做前缀匹配） ----------


def _compare_form(path: str) -> str:
    """同一 OS 内的可比较形态：`normpath` 归一冗余分量 + `normcase`。

    只用于判断「句柄导出的最终路径」与「策略层第二次授权的结论路径」是否**同一个位置**，
    不是解析目标、不参与任何授权决定（授权始终由策略层自己重新解析得出）。
    """
    try:
        return os.path.normcase(os.path.normpath(path))
    except (TypeError, ValueError):
        return ""


def _same_location(left: str, right: str) -> bool:
    """两个写法是否同一位置（规范化后完全相等；空形态永不相等）。"""
    a = _compare_form(left)
    b = _compare_form(right)
    return bool(a) and bool(b) and a == b


# ---------- 句柄身份（基准句柄与读取句柄共用同一函数、同一组字段） ----------


@dataclass(frozen=True)
class _Identity:
    """(卷号, 文件标识)：两侧都由**同一个平台身份函数**从**同一个句柄**填出。

    两个字段都是普通 `int`：Windows 的 `file_id` 是 16 字节 `FileId` 按小端解释成的整数
    （可到 2^128-1），POSIX 的 `file_id` 是 `st_ino`。这里只存值、不存字节序与字段边界，
    比较也只按整数相等（`same_as`），不再拆回高低字。
    不含权限位/模式：权限变动不是「同一个名字被换成另一个对象」的证据，把它算进身份
    只会造成误拒。对象类型由同一个句柄的独立查询单独核对（两侧都必须确认是普通文件）。
    """

    volume: int
    file_id: int

    def same_as(self, other: _Identity) -> bool:
        """两项**同时**相等才算同一对象；只比一项不足以排除替换。"""
        return self.volume == other.volume and self.file_id == other.file_id


def _identity_or_refuse(volume: int, file_id: int) -> _Identity:
    """把两个整数收成可比较身份；给不出可用标识就是拒绝，不是放行。

    文件标识为 0 不是「同一个文件」的证据，只是「这一层没给出可比较的标识」：Windows 上
    文件系统不支持 `FileIdInfo` 时返回的全零 128 位标识、POSIX 上的 0 号 inode 都落在这里。
    卷号为 0 同样丢掉了跨卷区分能力（Windows 网络对象可见到），两侧都不可信就整体不可信。
    """
    if file_id == 0 or volume == 0:
        raise SafeReadDenied(ReadRefusalCode.FILE_IDENTITY_UNSUPPORTED)
    return _Identity(volume=volume, file_id=file_id)


def _windows_handle_identity(fd: int) -> _Identity:
    """Windows：从**给定句柄**取 (64 位卷序列号, 128 位文件标识)，并确认它是磁盘上的普通文件。

    `os.open` 返回 C 运行库描述符，必须经 `msvcrt.get_osfhandle` 换成 Win32 HANDLE 再问内核。
    基准句柄与读取句柄都走这一个函数：`GetFileInformationByHandleEx` 的 `FileIdInfo`（信息类
    18），字段为 `VolumeSerialNumber`（64 位）与 `FileId`（16 字节，按固定小端解释成一个整数）——
    同一 API、同两组字段，不与任何 `os.stat` 字段混比。`FILE_ID_INFO` 声明为两个字段
    （`ULONGLONG VolumeSerialNumber` + 16 字节 `FileId`），并要求 `ctypes.sizeof` 为 24（偏移 0/8）；
    字节序只是本层的编码选择，不代表文件系统语义，两侧同函数同编码，相等才同对象。
    结构对不上说明这份声明不可信，固定按「平台不支持」拒，**不回退**到
    `GetFileInformationByHandle` 的 32 位文件索引（那对 ReFS 等 128 位标识的文件系统不足以区分对象）。
    类型判定是两次独立查询：`GetFileType` 判是否磁盘对象（字符设备/命名管道/网络重定向 →
    `not_regular_file`；返回 0 或未知取值 → `handle_identity_unavailable`）；目录判定用信息类 9
    （`FILE_ATTRIBUTE_TAG_INFO`：`DWORD FileAttributes` + `DWORD ReparseTag`，自检 8 字节）的
    `FileAttributes`（目录 → `not_regular_file`）；`ReparseTag` 本轮不据以改判（链接判定归策略层）。
    两个结构的声明归属（winnt.h）与布局本轮只经静态核对，已列入未验证清单。
    错误码固定：查询失败或返回值不可解释 → `handle_identity_unavailable`；平台无 ctypes、无
    `GetFileInformationByHandleEx` 入口、结构自检不合、或文件系统给出全零卷序列号/全零 128 位
    标识 → `file_identity_unsupported`。本函数不读 `GetLastError`、不外传系统错误原文。
    ctypes 约定按文档静态核对，**本层未执行**。
    """
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        class _FileIdInfo(ctypes.Structure):
            _fields_ = [
                ("VolumeSerialNumber", ctypes.c_ulonglong),
                ("FileId", ctypes.c_ubyte * 16),
            ]

        class _AttributeTagInfo(ctypes.Structure):
            _fields_ = [
                ("FileAttributes", wintypes.DWORD),
                ("ReparseTag", wintypes.DWORD),
            ]

        # 结构声明自检：与 winnt.h 的字段顺序和大小不一致就不再使用该声明，
        # 宁可报「平台不支持」，也不拿一份错位布局读出来的数去比身份。
        if ctypes.sizeof(_FileIdInfo) != 24 or ctypes.sizeof(_AttributeTagInfo) != 8:
            raise SafeReadDenied(ReadRefusalCode.FILE_IDENTITY_UNSUPPORTED) from None
    except SafeReadDenied:
        raise
    except Exception:
        # 拿不到 ctypes/msvcrt 就没法做同函数、同字段的核对：这是能力缺失，不是「已核验」。
        raise SafeReadDenied(ReadRefusalCode.FILE_IDENTITY_UNSUPPORTED) from None
    try:
        handle = msvcrt.get_osfhandle(fd)
        if isinstance(handle, bool) or not isinstance(handle, int) or handle in (0, -1):
            raise SafeReadDenied(ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE)
        kernel32 = ctypes.windll.kernel32
        exgetter = getattr(kernel32, "GetFileInformationByHandleEx", None)
        if exgetter is None:
            # 没有 Ex 入口：本层不拿只能给 64 位索引的旧 API 作替代判定。
            raise SafeReadDenied(ReadRefusalCode.FILE_IDENTITY_UNSUPPORTED)
        exgetter.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        exgetter.restype = wintypes.BOOL
        handle_arg = ctypes.c_void_p(handle)
        typer = kernel32.GetFileType
        typer.argtypes = [wintypes.HANDLE]
        typer.restype = wintypes.DWORD
        file_type = typer(handle_arg)
        tag = _AttributeTagInfo()
        # FileAttributeTagInfo（9）：只为取 FileAttributes（目录判定），不进身份；ReparseTag 本轮不据以改判。
        ok_tag = exgetter(
            handle_arg, _FILE_ATTRIBUTE_TAG_INFO, ctypes.byref(tag), ctypes.sizeof(tag)
        )
        info = _FileIdInfo()
        # FileIdInfo：本层唯一的身份来源。
        ok_id = exgetter(
            handle_arg, _FILE_ID_INFO, ctypes.byref(info), ctypes.sizeof(info)
        )
    except SafeReadDenied:
        raise
    except Exception:
        # 内核调用失败、句柄无效、类型不匹配：一律降为「取不到身份」，不外传原异常。
        raise SafeReadDenied(ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE) from None
    if file_type in _NON_DISK_FILE_TYPES:
        # 字符设备、命名管道、网络重定向：不是本层可服务的普通文件对象。
        raise SafeReadDenied(ReadRefusalCode.NOT_REGULAR_FILE)
    if file_type != _FILE_TYPE_DISK:
        # 0（FILE_TYPE_UNKNOWN：不是磁盘对象，或查询失败后未被清除的残值）与未知取值：
        # 连「是不是磁盘对象」都无法确认。
        raise SafeReadDenied(ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE)
    if not ok_tag or not ok_id:
        raise SafeReadDenied(ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE)
    if tag.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
        raise SafeReadDenied(ReadRefusalCode.NOT_REGULAR_FILE)
    # 链接数与文件大小都不进身份（不是「同名换成另一对象」的证据）；只取卷号 + 完整 128 位标识。
    # 全零卷序列号或全零 128 位标识（不支持 FileIdInfo 的对象返回全零）由 _identity_or_refuse
    # 固定判为 file_identity_unsupported：那是拒绝，不是「已核验」，也不退回 32 位文件索引去猜。
    return _identity_or_refuse(
        int(info.VolumeSerialNumber),
        int.from_bytes(bytes(info.FileId), "little"),
    )


def _posix_handle_identity(fd: int) -> _Identity:
    """Linux/POSIX：从**给定句柄** `os.fstat` 取 (st_dev, st_ino)，并确认它是普通文件。

    基准句柄与读取句柄走同一个函数、同一组字段；`st_mode` 只用于类型判定，不进身份。
    字段类型不合（不是普通 `int`）说明这个结果不可解释，按「取不到可比较身份」拒绝。
    """
    try:
        result = os.fstat(fd)
    except OSError:
        raise SafeReadDenied(ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE) from None
    if not stat_module.S_ISREG(result.st_mode):
        raise SafeReadDenied(ReadRefusalCode.NOT_REGULAR_FILE)
    volume = result.st_dev
    file_id = result.st_ino
    if isinstance(volume, bool) or isinstance(file_id, bool):
        raise SafeReadDenied(ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE)
    if not isinstance(volume, int) or not isinstance(file_id, int):
        raise SafeReadDenied(ReadRefusalCode.HANDLE_IDENTITY_UNAVAILABLE)
    return _identity_or_refuse(volume, file_id)


def _probe_handle_identity(fd: int) -> _Identity:
    """从一个已打开的句柄取身份（并按平台确认它是普通文件）。"""
    return _windows_handle_identity(fd) if _IS_WINDOWS else _posix_handle_identity(fd)


# ---------- 打开：裸描述符的唯一所有权 ----------


def _open_flags() -> int:
    """只读打开的标志：`O_RDONLY` + 平台可用的 `O_BINARY`/`O_NONBLOCK`/`O_NOCTTY`。

    后两项压制「打开即阻塞」（FIFO/设备节点）与「成为控制终端」两类后果；它们**不**代表
    设备节点在打开时绝无副作用——本层也不这样宣称（见模块文档）。不创建、不截断、不加锁。
    """
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOCTTY", 0)
    )


def _open_read_only(path: str) -> int:
    """只读打开并返回裸描述符；失败只降为固定码，不外传系统错误原文。"""
    try:
        return os.open(path, _open_flags())
    except OSError:
        raise SafeReadDenied(ReadRefusalCode.OPEN_FAILED) from None


def _close_fd(fd: int) -> None:
    """归还本层仍持有的那个裸描述符：只关一次，关闭失败不改变已定的拒绝结论。"""
    with contextlib.suppress(OSError):
        os.close(fd)


def _transfer_fd(fd: int) -> object:
    """把复核通过的裸描述符移交给只读二进制文件对象；这是**唯一**改变关闭者的一步。

    成功之后只有关闭这个文件对象才能归还描述符，不存在 `os.close` 与 `close()` 抢同一个编号
    的状态。`os.fdopen` 失败时对象并未建立（描述符仍归调用方），因此本函数就地归还它后再报错：
    移交失败不会主动留下泄漏的描述符，也不留下第二个关闭者。

    `buffering=0` 是本层兑现「每次底层请求预算」的方式：无缓冲的文件对象让 `read(n)` 直接落到
    `raw.read(n)`，本层的请求量即底层请求量（见模块文档「计量口径」）。它只使用 `open` 的原始
    形式 `buffering=0`，不叠加 `io.DEFAULT_BUFFER_SIZE` 一类常量；无缓冲形态不再有一层
    `BufferedReader` 替本层预读，但异常/中断时刻底层是否滞留字节仍属未实测边界（文末清单第 4 条），
    本层不宣称绝对零窗口。

    返回类型写成 `object` 是有意不在此多作一层断言：本层只用它的 `read`/`close`。
    """
    try:
        # 原始（无缓冲）二进制读：buffering=0 只在 "rb" 形态下被允许，本层正是该形态。
        return os.fdopen(fd, "rb", buffering=0, closefd=True)
    except OSError:
        _close_fd(fd)
        raise SafeReadDenied(ReadRefusalCode.OPEN_FAILED) from None


def _baseline_identity(path: str) -> _Identity:
    """建立打开前基准：按同一套标志安全打开一次，从**那个句柄**取身份，然后立刻关闭。

    基准必须来自句柄而不是路径的 `os.stat`：否则「基准用路径解析、读取用句柄」两套语义在
    Windows 上不同源，比较就失去意义。取不到基准就不读正文——复核必须有比对对象。
    打开失败按 `baseline_unavailable` 处理（这一步还没有读取句柄要归还，不涉及描述符归属）。
    """
    try:
        fd = os.open(path, _open_flags())
    except OSError:
        raise SafeReadDenied(ReadRefusalCode.BASELINE_UNAVAILABLE) from None
    try:
        return _probe_handle_identity(fd)
    finally:
        _close_fd(fd)


# ---------- 句柄侧最终路径导出 ----------


def _strip_device_prefix(value: str) -> str | None:
    r"""剥掉 Win32 设备命名空间前缀，还原可交给策略层复核的常规写法。

    `GetFinalPathNameByHandleW` 返回 `\\?\C:\dir\file` 或 `\\?\UNC\server\share\file`。
    其它形态（`\\?\Volume{guid}\`、命名管道、未知设备形式）返回 `None`：本层不去猜挂载点，
    猜出来的字符串不是复核证据。POSIX 路径原样返回。
    """
    if not isinstance(value, str) or not value:
        return None
    device = "\\\\?\\"
    unc_device = "\\\\?\\UNC\\"
    if value.startswith(unc_device):
        remainder = value[len(unc_device):]
        return ("\\\\" + remainder) if remainder else None
    if value.startswith(device):
        remainder = value[len(device):]
        if (
            len(remainder) >= 3
            and remainder[1] == ":"
            and remainder[2] in ("\\", "/")
            and remainder[0].isalpha()
        ):
            return remainder
        return None
    return value


def _windows_handle_path(fd: int) -> str | None:
    r"""Windows：从 CRT 描述符取 Win32 句柄，再向内核问最终路径。

    取不到 `ctypes`/`msvcrt`/`windll` 返回 `None`（调用方降为 `handle_path_unsupported`）。
    ctypes 约定按文档静态核对，**本轮未执行**：返回 0 表示失败；返回值不小于缓冲区长度
    表示「需要这么长（含终止符）」，此时重新分配再问一次；仍不合就放弃，不猜。
    """
    if not _IS_WINDOWS:
        return None
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
    except Exception:
        return None
    try:
        handle = msvcrt.get_osfhandle(fd)
        windll = ctypes.windll
        getter = windll.kernel32.GetFinalPathNameByHandleW
        getter.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_wchar),
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        getter.restype = wintypes.DWORD
        size = _PATH_PROBE_CHARS
        buffer = ctypes.create_unicode_buffer(size)
        # VOLUME_NAME_DOS = 0：需要盘符形式才能交给策略层复核。
        needed = getter(ctypes.c_void_p(handle), buffer, size, 0)
        if not isinstance(needed, int) or needed <= 0:
            return None
        if needed >= _MAX_HANDLE_PATH_CHARS:
            # 超出内核允许的长度：不截断、不猜，交给调用方拒绝。
            return None
        if needed >= size:
            size = needed
            buffer = ctypes.create_unicode_buffer(size)
            needed = getter(ctypes.c_void_p(handle), buffer, size, 0)
            if not isinstance(needed, int) or needed <= 0 or needed >= size:
                return None
        exported = buffer.value
    except Exception:
        # 内核调用失败、句柄无效、类型不匹配：一律降为「导不出来」，不外传原异常。
        return None
    return exported if exported else None


def _proc_handle_path(fd: int) -> str | None:
    """Linux：读 `/proc/self/fd/<fd>` 的符号链接得到句柄实际落点（句柄侧信息，非调用方字符串）。

    结尾 ` (deleted)` 表示对象已被 unlink：返回空串，由调用方按「与基准不一致」拒绝，
    不拿这个名字继续复核。`/dev/fd` 的 `realpath` 不是句柄导出，本函数不退化成它。
    """
    if _IS_WINDOWS:
        return None
    try:
        target = os.readlink(f"/proc/self/fd/{fd}")
    except OSError:
        return None
    if not isinstance(target, str) or not target:
        return None
    if target.endswith(" (deleted)"):
        return ""
    return target


def _export_handle_path(fd: int) -> str:
    """从已打开的句柄导出最终路径；任何不支持或失败都只降为固定码。"""
    exported = _windows_handle_path(fd) if _IS_WINDOWS else _proc_handle_path(fd)
    if exported is None:
        raise SafeReadDenied(ReadRefusalCode.HANDLE_PATH_UNSUPPORTED)
    if not exported:
        raise SafeReadDenied(ReadRefusalCode.FILE_REPLACED)
    normalized = _strip_device_prefix(exported)
    if normalized is None:
        raise SafeReadDenied(ReadRefusalCode.HANDLE_PATH_UNSUPPORTED)
    return normalized


def _reauthorize_final_path(
    policy: SessionPolicy, scope: str, source: str, final_path: str
) -> None:
    """把句柄导出的最终路径再送过一次**完全相同**的存储授权入口。

    第二次调用仍是 `authorize_store(scope, source, final_path, kind=FILE)`：同一个策略实例、
    同一个范围、同一个来源、同一个 kind，因此不存在首次严格、复核宽松的差额。策略层的拒绝
    原样传播（它的固定码本身不回显路径）。复核结论与句柄落点必须指向同一位置：策略层返回的是
    它自己 `realpath` 的值，若与内核给出的句柄落点不同，说明两次调用之间链路上的链接目标变了，
    本层拿不到「读的就是刚复核那个对象」的保证，固定拒绝。
    """
    recheck = policy.authorize_store(scope, source, final_path, kind=TargetKind.FILE)
    if not _same_location(final_path, recheck.readable_path):
        raise SafeReadDenied(ReadRefusalCode.HANDLE_PATH_CHANGED)


# ---------- 只读有界行扫描 ----------


def _is_known_archive_shape(data: bytes) -> bool:
    """固定形态比对：命中即认为不是本层可服务的普通文本存储对象。

    这是**名单比对不是完备判定**（名单外的压缩流仍会被按行读，已登记在文末未验证清单），
    它只拦住最常见的归档、可执行与数据库形态，把「本层会解压」这种误读挡在接口之外。
    比对只用 `startswith` 与固定字节，不保留、不回传读到的内容。
    反向的误拒（正文恰好以 `MZ`、`%PDF-` 这类字节开头）同样存在：方向是宁可不读也不误当
    会话文本，本层不为此另开旁路入口。
    """
    for magic in _MAGIC_PREFIXES:
        if data.startswith(magic):
            return True
    if data.startswith(_GZIP_MAGIC):
        return True
    if len(data) >= 2 and data[0] == 0x78 and data[1] in _ZLIB_LEVEL_BYTES:
        return True
    # zstd skippable 帧：小端 0x184D2A50..0x184D2A5F，即首字节 0x50..0x5F + 固定后三字节。
    return (
        len(data) >= 4
        and data[1:4] == _ZSTD_SKIPPABLE_TAIL
        and _ZSTD_SKIPPABLE_FIRST_MIN <= data[0] <= _ZSTD_SKIPPABLE_FIRST_MAX
    )


class AuthorizedLineReader:
    """已复核的只读行读取器：直接 `Iterable[bytes]`，每次交出一整行真实字节。

    实例只能由 `authorize_read()` 产生（构造函数不做授权，绕过工厂就绕过全部复核）。
    读取是**单趟向前**：`_buffer` 收集当前尚未交出的字节，长度永远不超过 `max_line_bytes`，
    一次底层请求不超过 `_SCAN_WINDOW_BYTES`。行交出后其字节离开本层；文件位置由已交出与
    已缓冲的字节数唯一决定，对外只给行内容与整数计数。

    同一趟读取顺手算出整文件 SHA-256（每个底层返回块只计入一次，含正文之前的形态确证窗口），
    因此 `file_version()` 不需要第二次读、也不需要按路径 stat 就能给出可识别同大小改写的版本；
    句柄身份 `identity` 来自复核通过的那个描述符，与正文同批确立。
    """

    __slots__ = (
        "_buffer",
        "_bytes_discarded",
        "_closed",
        "_consumed_bytes",
        "_digest",
        "_eof_reached",
        "_file",
        "_identity",
        "_lines_total",
        "_max_line_bytes",
        "_max_lines",
        "_max_total_bytes",
        "_stop",
        "_truncated_lines",
    )

    def __init__(
        self,
        file_obj: object,
        *,
        identity: _Identity,
        max_line_bytes: int,
        max_total_bytes: int,
        max_lines: int,
    ) -> None:
        """私有构造：`file_obj` 必须是复核通过、所有权**已移交**的只读二进制文件对象。"""
        self._file = file_obj
        self._identity = identity
        self._closed = file_obj is None
        self._max_line_bytes = max_line_bytes
        self._max_total_bytes = max_total_bytes
        self._max_lines = max_lines
        self._buffer = bytearray()
        self._consumed_bytes = 0
        self._lines_total = 0
        self._truncated_lines = 0
        self._bytes_discarded = 0
        self._eof_reached = False
        self._digest = hashlib.sha256()
        self._stop: ReadStop | None = None

    # ---------- 对外自省 ----------

    @property
    def closed(self) -> bool:
        """句柄是否已关闭（`with` 退出或 `close()` 之后为真）。"""
        return self._closed

    @property
    def lines_read(self) -> int:
        """已吐出的行数（不含被丢弃或未交出的行）。"""
        return self._lines_total

    def outcome(self) -> ReadOutcome:
        """当前结论（读完后再调用最有意义；中途或提前退出调用如实报「未完成」）。

        这里的不完整只描述字节层面；解析层是否读完、解析质量如何，仍要调用方合并解析侧最终
        状态后再说（见模块文档「调用方义务」）。
        """
        complete = self._eof_reached and self._stop is None and not self._buffer
        reason = self._stop
        if complete:
            reason = ReadStop.EXHAUSTED
        elif reason is None:
            reason = ReadStop.CLOSED_BEFORE_EOF
        return ReadOutcome(
            complete=complete,
            reason=reason,
            lines_read=self._lines_total,
            consumed_bytes=self._consumed_bytes,
            truncated_lines=self._truncated_lines,
            bytes_discarded=self._bytes_discarded,
            eof_reached=self._eof_reached,
        )

    def file_version(self) -> FileVersion:
        """本次读取已确立的文件版本（内部核对用；卷号/文件标识不对外）。

        三项证据全部来自**同一次授权读取**：句柄身份、已读字节量、同趟累加的 SHA-256。
        `size_bytes` 是本层实际读到的字节量，只有 `complete=True` 时才等于整文件长度，
        摘要也只在那个前提下覆盖全文；因此调用方必须先看 `complete`，不能拿部分摘要
        当「未修改」的证据。同摘要不要求同体积，同体积不同内容一定不同摘要。
        """
        return FileVersion(
            volume=self._identity.volume,
            file_id=self._identity.file_id,
            size_bytes=self._consumed_bytes,
            content_sha256=self._digest.hexdigest(),
            complete=self.outcome().complete,
        )

    # ---------- 生命周期 ----------

    def close(self) -> None:
        """关闭句柄；重复调用幂等，任何关闭失败都不外传（结论由统计给出）。"""
        file_obj, self._file = self._file, None
        self._closed = True
        buffer = self._buffer
        self._buffer = bytearray()
        if buffer and self._stop is None:
            # 提前关闭：缓冲区里未交出的字节如实计入丢弃量。
            self._truncated_lines += _pending_line_count(buffer)
            self._bytes_discarded += len(buffer)
        if file_obj is None:
            return
        # 关闭失败不改变已定结论，也不外传系统错误原文（消息里可能带路径）。
        with contextlib.suppress(OSError, ValueError):
            file_obj.close()  # type: ignore[union-attr]

    def __enter__(self) -> AuthorizedLineReader:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        # 任何出口（正常读完、触限、调用方异常、BaseException 中断）都走到这里关闭句柄。
        self.close()
        return False

    # ---------- 迭代 ----------

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        if self._closed:
            raise SafeReadDenied(ReadRefusalCode.HANDLE_CLOSED)
        if self._stop is not None:
            raise StopIteration
        return self._next_line()

    # ---------- 内部：单趟向前扫描 ----------

    def _read_chunk(self, count: int) -> bytes:
        """一次顺序读取：请求量受 `count` 封顶，返回的字节数计入总预算。

        文件对象无缓冲（`buffering=0`），因此这一次请求就是一次底层读；本层只顺序推进：
        文件位置由已读字节数唯一决定。系统错误消息可能含路径或描述符信息，
        一律降为固定码不外传；返回值必须是
        `bytes`/`bytearray`，否则这个句柄的形态不可信。返回 0 字节确立 EOF。
        """
        if self._closed or self._file is None:
            raise SafeReadDenied(ReadRefusalCode.HANDLE_CLOSED)
        try:
            data = self._file.read(count)  # type: ignore[union-attr]
        except (OSError, ValueError):
            raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED) from None
        if not isinstance(data, (bytes, bytearray)):
            raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED)
        chunk = bytes(data)
        self._consumed_bytes += len(chunk)
        # 同一趟读取顺手算版本：每个底层返回块只在这里计入一次，不二次读、不按路径 stat。
        self._digest.update(chunk)
        if not chunk:
            self._eof_reached = True
        return chunk

    def _terminate(self, stop: ReadStop) -> None:
        """触限/提前结束：未交出的缓冲如实计入丢弃量，置终态，`complete` 恒为假。"""
        self._stop = stop
        buffer = self._buffer
        if buffer:
            self._truncated_lines += _pending_line_count(buffer)
            self._bytes_discarded += len(buffer)
            self._buffer = bytearray()

    def _next_line(self) -> bytes:
        """推进到下一条完整行并交出它的字节；装不进预算时如实停住。"""
        while True:
            index = self._buffer.find(b"\n")
            if index >= 0:
                if self._lines_total >= self._max_lines:
                    # 行数硬限优先于缓冲里已扫到的行：不放松上限，未交出的部分如实计丢弃。
                    self._terminate(ReadStop.LINE_LIMIT)
                    raise StopIteration
                self._lines_total += 1
                line = bytes(self._buffer[: index + 1])
                del self._buffer[: index + 1]
                return line
            if self._eof_reached:
                return self._finish_tail()
            if self._lines_total >= self._max_lines:
                # 行数触限且 EOF 未确认：文件可能还有内容，本层不能说「已读完」。
                self._terminate(ReadStop.LINE_LIMIT)
                raise StopIteration
            if len(self._buffer) >= self._max_line_bytes:
                # 单行已长到装不进固定预算，且尚未见到换行：整行丢弃并标记不完整。
                self._terminate(ReadStop.LINE_BYTES_LIMIT)
                raise StopIteration
            remaining = self._max_total_bytes - self._consumed_bytes
            if remaining <= 0:
                self._terminate(ReadStop.TOTAL_BYTES_LIMIT)
                raise StopIteration
            chunk = self._read_chunk(
                min(_SCAN_WINDOW_BYTES, self._max_line_bytes - len(self._buffer), remaining)
            )
            if chunk:
                self._buffer += chunk

    def _finish_tail(self) -> bytes:
        """EOF 已确认后的出口：残留内容作为最后一行（无行尾符）交出，然后收束。

        行数触限时残留不开新行，报 `line_limit` + 不完整，避免「多吐一行」把硬上限抬到
        `max_lines + 1`；无残留（文件以行尾结束或空文件）直接抛 `StopIteration`：`_stop`
        保持未置位，`outcome()` 因此判为完整（自然结束不是一种触限）。
        """
        if self._buffer:
            if self._lines_total >= self._max_lines:
                self._terminate(ReadStop.LINE_LIMIT)
                raise StopIteration
            tail = bytes(self._buffer)
            self._buffer = bytearray()
            self._lines_total += 1
            return tail
        raise StopIteration

    def _check_plain_bytes(self) -> None:
        """正文之前的「普通文本字节流」确证：一个固定窗口，只比长度与固定字节。

        空文件视为合法普通文本文件（读循环自然给出 `complete=True`、0 行）。命中固定形态判
        `not_plain_text`，窗口内含 NUL 判 `binary_content`：本层**不解压**、不打开数据库，
        所以这两类是明确拒绝，不是「尽力读一段」。判据只覆盖这 `_MAGIC_READ_BYTES` 个字节：
        名单外的压缩流与窗口之后的 NUL **不在本层拦截范围内**（已登记文末未验证清单）。
        这次请求计入 `consumed_bytes`（入口已保证预算容得下这个窗口），取到的字节**留在行
        缓冲开头**作为首行的起点。
        """
        probe = self._read_chunk(_MAGIC_READ_BYTES)
        if not probe:
            return
        self._buffer += probe
        if _is_known_archive_shape(probe):
            raise SafeReadDenied(ReadRefusalCode.NOT_PLAIN_TEXT)
        if b"\x00" in probe:
            raise SafeReadDenied(ReadRefusalCode.BINARY_CONTENT)


def _pending_line_count(buffer: bytearray) -> int:
    """缓冲区里的行数：每个 `\n` 一行，末尾未换行的残留若非空再算一行。"""
    if not buffer:
        return 0
    return buffer.count(b"\n") + (1 if buffer[-1:] != b"\n" else 0)


# ---------- 唯一公开入口 ----------


def authorize_read(
    policy: object,
    scope: object,
    source: object,
    path: object,
    *,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_lines: int = DEFAULT_MAX_LINES,
) -> AuthorizedLineReader:
    """唯一公开入口：授权 → 句柄基准 → 只读打开 → 句柄复核 → 移交 → 有界行读取器。

    参数全部要求普通字面值：`policy` 必须是本包 `SessionPolicy` 实例（不接受子类或鸭子类型
    替身，否则被继承的 `authorize_store` 就不是策略层那一份判据），`scope`/`source`/`path`
    必须是普通 `str`；`max_lines` 必须是 `[1, HARD_MAX_LINES]` 内的 `int`（`bool` 不算），
    两个字节上限必须是 `[_MAGIC_READ_BYTES, HARD_*]` 内的 `int`——小于形态确证窗口的预算
    在这里就拒，本层不会在小预算上仍读固定 16 字节。调用方只能收紧，不能放宽。任一项不合 →
    `args_invalid`，且**不做任何文件系统探测**。

    返回值是**已完成全部复核、尚未吐出任何正文**的读取器，直接按 `Iterable[bytes]` 使用：

        with authorize_read(policy, scope, source, path) as reader:
            for line in reader:
                parser.feed_line(line)
            stats = parser.finish()

    调用方必须用 `with` 接住它，异常出口同样关闭句柄；并在结束后**同时**读
    `reader.outcome()` 与解析层最终状态，两者任一不完整就是不完整。拒绝路径只有固定码：
    本层 `SafeReadDenied` 与策略层原样传播的 `PolicyDenied`，两者都不含路径、来源、scope、
    errno 或异常原文。
    """
    if not isinstance(policy, SessionPolicy) or type(policy) is not SessionPolicy:
        raise SafeReadDenied(ReadRefusalCode.POLICY_NOT_SESSION)
    if not isinstance(scope, str) or not isinstance(source, str) or not isinstance(path, str):
        raise SafeReadDenied(ReadRefusalCode.ARGS_INVALID)
    for value, low, cap in zip(
        (max_line_bytes, max_total_bytes, max_lines),
        (_MAGIC_READ_BYTES, _MAGIC_READ_BYTES, 1),
        (HARD_MAX_LINE_BYTES, HARD_MAX_TOTAL_BYTES, HARD_MAX_LINES),
        strict=True,
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= cap:
            raise SafeReadDenied(ReadRefusalCode.ARGS_INVALID)

    # 1) 打开前授权：只接受策略层给出的真实路径，不拿调用方原写法去打开。
    grant = policy.authorize_store(scope, source, path, kind=TargetKind.FILE)
    verified = grant.readable_path
    # 2) 打开前基准：从「按同一套标志打开又关掉」的那个句柄取身份，拿不到就不读正文。
    baseline = _baseline_identity(verified)
    # 3) 只读打开：裸描述符的唯一关闭者此刻就是本函数。
    fd = _open_read_only(verified)
    try:
        # 4a) 句柄身份与基准逐项相等，并确认这个句柄指向普通文件（同一身份函数、同一组字段）。
        #     只比一项不足以排除替换：换卷、同卷换对象都会被拦住。
        identity = _probe_handle_identity(fd)
        if not identity.same_as(baseline):
            raise SafeReadDenied(ReadRefusalCode.FILE_REPLACED)
        # 4b) 句柄导出的最终路径再走一次同样的存储授权。
        final_path = _export_handle_path(fd)
        _reauthorize_final_path(policy, grant.scope, grant.source, final_path)
    except BaseException:
        # 本 try 内没有任何一步能把所有权交出去，因此这里的描述符一定仍属于本函数：
        # 精确关一次（含 `PolicyDenied`、非 `OSError`、中断路径），原样重抛。
        _close_fd(fd)
        raise
    # 5) 复核全过才移交：唯一能把所有权交给文件对象的一步；移交失败由它自己归还（不会泄漏）。
    #    无缓冲（buffering=0）形态：本层的请求量即底层请求量。
    file_obj = _transfer_fd(fd)
    reader = AuthorizedLineReader(
        file_obj,
        identity=identity,
        max_line_bytes=max_line_bytes,
        max_total_bytes=max_total_bytes,
        max_lines=max_lines,
    )
    # 6) 正文之前最后一步：确认它确实是本层可服务的普通字节流（不解压、不猜编码）。
    #    所有权已在读取器里，因此归还走它的 close()，不会再关那个描述符编号。
    try:
        reader._check_plain_bytes()
    except BaseException:
        reader.close()
        raise
    return reader


def authorize_content_digest(
    policy: object,
    scope: object,
    source: object,
    path: object,
    *,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> FileVersion:
    """存储对象的**内容指纹**通道：同一条授权/句柄复核链，逐块顺序读并算 SHA-256。

    为什么需要它：`authorize_read` 在第 6 步做固定形态确证，命中归档/数据库魔数即拒
    （`not_plain_text`），而 SQLite 库的头部魔数就在那份固定名单里。数据库来源需要文件版本
    作为引用发放与上下文读取的核对证据，但没有行语义（行由来源适配器经只读 SQL 取得）。
    本函数是那条缺口的**唯一**公开通道：它把形态确证换成「按字节顺序读一遍并累加摘要」，
    其余每一步与 `authorize_read` 共用同一批内部原语——同一策略层调用、同一打开前基准、
    同一组打开标志、同一句柄身份比较、同一次句柄最终路径再授权。

    与 `authorize_read` 相同的边界，逐条成立：
    - 判定只在策略层：`policy` 必须是本包 `SessionPolicy` 实例（不接受子类/鸭子替身），
      `scope`/`source`/`path` 必须是普通 `str`；预算必须是 `[_MAGIC_READ_BYTES,
      HARD_MAX_TOTAL_BYTES]` 内的 `int`（`bool` 不算），调用方只能收紧。任一项不合 →
      `args_invalid`，且**不做任何文件系统探测**。
    - 打开的是 `grant.readable_path`（策略层自己 `realpath` 出来的值），不是调用方原写法；
      句柄身份与基准逐项不等 → `file_replaced`；句柄落点再授权不过 → 策略层固定码原样传播；
      落点位置不一致 → `handle_path_changed`。裸描述符的唯一所有权交接与失败归还同
      `authorize_read` 第 3–5 步。
    - 有界：只朝前顺序读一遍，每次底层请求至多 `_SCAN_WINDOW_BYTES` 字节且逐次扣账；
      预算用尽而未确立 EOF → 返回 `complete=False`，此时 `size_bytes`/`content_sha256` 只
      覆盖已读部分，调用方必须以 `complete` 为准（与 `AuthorizedLineReader.file_version()`
      同一口径，半程摘要不得当整流指纹用）。本函数不把「预算用尽」当成「读完」。
    - 不宣称快照：只读打开不加锁，核验通过那一刻之后对象仍可被原地改写。数据库来源的
      一致性证据因此由调用方以「同一对象两次指纹相等」的方式取得，本层只保证指纹来自
      该身份的那个句柄、那一趟读取。

    返回 `FileVersion`：卷号、文件标识、读到的字节数、同趟 SHA-256 与 `complete`。这些值
    **不跨越协议边界**（本类无 `as_public_dict()`），只供包内引用账本与当场比对使用。
    """
    if not isinstance(policy, SessionPolicy) or type(policy) is not SessionPolicy:
        raise SafeReadDenied(ReadRefusalCode.POLICY_NOT_SESSION)
    if not isinstance(scope, str) or not isinstance(source, str) or not isinstance(path, str):
        raise SafeReadDenied(ReadRefusalCode.ARGS_INVALID)
    if (
        isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or not _MAGIC_READ_BYTES <= max_total_bytes <= HARD_MAX_TOTAL_BYTES
    ):
        raise SafeReadDenied(ReadRefusalCode.ARGS_INVALID)

    # 1) 打开前授权（与 authorize_read 第 1 步同一调用、同一 kind）。
    grant = policy.authorize_store(scope, source, path, kind=TargetKind.FILE)
    verified = grant.readable_path
    # 2) 打开前基准：同一套标志开一次取身份再关掉；拿不到基准就不读。
    baseline = _baseline_identity(verified)
    # 3) 只读打开：此刻裸描述符的唯一关闭者是本函数。
    fd = _open_read_only(verified)
    try:
        # 4a) 句柄身份与基准逐项相等（含「仍是普通文件」的判定在该身份函数内）。
        identity = _probe_handle_identity(fd)
        if not identity.same_as(baseline):
            raise SafeReadDenied(ReadRefusalCode.FILE_REPLACED)
        # 4b) 句柄导出的最终路径再走一次同样的存储授权。
        final_path = _export_handle_path(fd)
        _reauthorize_final_path(policy, grant.scope, grant.source, final_path)
    except BaseException:
        _close_fd(fd)
        raise
    # 5) 复核全过后移交所有权；无缓冲形态让本层的请求量就是底层请求量。
    file_obj = _transfer_fd(fd)
    digest = hashlib.sha256()
    consumed = 0
    eof_reached = False
    try:
        while True:
            remaining = max_total_bytes - consumed
            if remaining <= 0:
                # 预算用尽而 EOF 未确立：如实报不完整，不冒充读完整个对象。
                break
            try:
                data = file_obj.read(min(_SCAN_WINDOW_BYTES, remaining))  # type: ignore[union-attr]
            except (OSError, ValueError):
                raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED) from None
            if not isinstance(data, (bytes, bytearray)):
                raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED)
            chunk = bytes(data)
            if not chunk:
                # EOF 只由「某次读取返回 0 字节」确立（与行读取器同一判据）。
                eof_reached = True
                break
            consumed += len(chunk)
            digest.update(chunk)
    finally:
        # 任何出口都归还句柄；关闭失败不外传（结论由 complete 给出）。
        with contextlib.suppress(OSError, ValueError):
            file_obj.close()  # type: ignore[union-attr]
    return FileVersion(
        volume=identity.volume,
        file_id=identity.file_id,
        size_bytes=consumed,
        content_sha256=digest.hexdigest(),
        complete=eof_reached,
    )


@dataclass(frozen=True)
class RawBytesResult:
    """一次授权原始字节读取的结果：有界字节 + 同趟确立的文件版本。

    `data` 是本层实际读到的字节（至多 `max_total_bytes`）；`version.complete` 为真时才表示
    「读到 EOF、字节与摘要覆盖整个对象」。半程读取时两者都只覆盖已读部分，调用方必须以
    `complete` 为准（与 `AuthorizedLineReader.file_version()` 同一口径）。
    本对象不跨越协议边界：字节只在包内交给来源适配器，卷号/文件标识/摘要不进任何对外结果。
    """

    data: bytes
    version: FileVersion


def authorize_raw_bytes(
    policy: object,
    scope: object,
    source: object,
    path: object,
    *,
    max_total_bytes: int = HARD_MAX_TOTAL_BYTES,
) -> RawBytesResult:
    """已授权存储对象的**有界原始字节**通道：与 `authorize_read` 同一条复核链，不做文本形态确证。

    为什么需要它：`authorize_read` 的第 6 步 `_check_plain_bytes()` 命中固定归档魔数即拒
    （`not_plain_text`），而压缩帧（zstd `28 B5 2F FD` 等）正是会话存储的合法形态；行式读取器
    也不提供「按字节顺序交出全部原始内容」的语义。本函数是那条缺口的公开通道之一：它与
    `authorize_content_digest` 共享同一批内部原语——同一策略层调用（`kind=FILE`）、同一打开前
    基准、同一组打开标志、同一句柄身份比较、同一次句柄最终路径再授权——只是把「累加摘要后
    丢弃字节」换成「在固定预算内保留字节并同时累加摘要」。

    边界与另外两个入口逐条相同：
    - 判定只在策略层：`policy` 必须是本包 `SessionPolicy` 实例（不接受子类/鸭子替身），
      `scope`/`source`/`path` 必须是普通 `str`；预算必须是 `[_MAGIC_READ_BYTES,
      HARD_MAX_TOTAL_BYTES]` 内的 `int`（`bool` 不算），调用方只能收紧。任一项不合 →
      `args_invalid`，且**不做任何文件系统探测**。
    - 打开的是 `grant.readable_path`，不是调用方原写法；句柄身份与基准逐项不等 →
      `file_replaced`；句柄落点再授权不过 → 策略层固定码原样传播；落点位置不一致 →
      `handle_path_changed`。裸描述符所有权交接与归还同 `authorize_read` 第 3–5 步。
    - 有界：只朝前顺序读一遍，每次底层请求至多 `_SCAN_WINDOW_BYTES` 字节且逐次扣账；
      预算用尽而未确立 EOF → `complete=False`，`data` 只含已读前缀。本函数不把「预算用尽」
      当成「读完」，也不解压、不解释字节内容——解压与行语义归来源适配器（`sources/dsh.py`）。
    - 不宣称快照：只读打开不加锁，核验通过之后对象仍可被原地改写；`version` 是「该句柄那一趟
      读取」的证据，跨时刻比对由调用方负责。
    """
    if not isinstance(policy, SessionPolicy) or type(policy) is not SessionPolicy:
        raise SafeReadDenied(ReadRefusalCode.POLICY_NOT_SESSION)
    if not isinstance(scope, str) or not isinstance(source, str) or not isinstance(path, str):
        raise SafeReadDenied(ReadRefusalCode.ARGS_INVALID)
    if (
        isinstance(max_total_bytes, bool)
        or not isinstance(max_total_bytes, int)
        or not _MAGIC_READ_BYTES <= max_total_bytes <= HARD_MAX_TOTAL_BYTES
    ):
        raise SafeReadDenied(ReadRefusalCode.ARGS_INVALID)

    # 1) 打开前授权（与 authorize_read 第 1 步同一调用、同一 kind）。
    grant = policy.authorize_store(scope, source, path, kind=TargetKind.FILE)
    verified = grant.readable_path
    # 2) 打开前基准：同一套标志开一次取身份再关掉；拿不到基准就不读。
    baseline = _baseline_identity(verified)
    # 3) 只读打开：此刻裸描述符的唯一关闭者是本函数。
    fd = _open_read_only(verified)
    try:
        # 4a) 句柄身份与基准逐项相等（含「仍是普通文件」的判定在该身份函数内）。
        identity = _probe_handle_identity(fd)
        if not identity.same_as(baseline):
            raise SafeReadDenied(ReadRefusalCode.FILE_REPLACED)
        # 4b) 句柄导出的最终路径再走一次同样的存储授权。
        final_path = _export_handle_path(fd)
        _reauthorize_final_path(policy, grant.scope, grant.source, final_path)
    except BaseException:
        _close_fd(fd)
        raise
    # 5) 复核全过才移交所有权；无缓冲形态让本层的请求量就是底层请求量。
    file_obj = _transfer_fd(fd)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    collected = 0
    eof_reached = False
    try:
        while True:
            remaining = max_total_bytes - collected
            if remaining <= 0:
                # 预算用尽而 EOF 未确立：如实报不完整，不冒充读完整个对象。
                break
            try:
                data = file_obj.read(min(_SCAN_WINDOW_BYTES, remaining))  # type: ignore[union-attr]
            except (OSError, ValueError):
                raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED) from None
            if not isinstance(data, (bytes, bytearray)):
                raise SafeReadDenied(ReadRefusalCode.HANDLE_READ_FAILED)
            chunk = bytes(data)
            if not chunk:
                # EOF 只由「某次读取返回 0 字节」确立（与行读取器同一判据）。
                eof_reached = True
                break
            collected += len(chunk)
            chunks.append(chunk)
            digest.update(chunk)
    finally:
        # 任何出口都归还句柄；关闭失败不外传（结论由 complete 给出）。
        with contextlib.suppress(OSError, ValueError):
            file_obj.close()  # type: ignore[union-attr]
    return RawBytesResult(
        data=b"".join(chunks),
        version=FileVersion(
            volume=identity.volume,
            file_id=identity.file_id,
            size_bytes=collected,
            content_sha256=digest.hexdigest(),
            complete=eof_reached,
        ),
    )


# ---------- 接线状态与未验证边界 ----------
#
# 接线：`session_pipeline.authorize_read` 调用方链已接通——`session_pipeline.py`（唯一的
# `authorize_read` 调用点）、`file_search.py` 与 `session_context.py`（消费 `FileVersion`）、
# `server.py`（处理 `SafeReadDenied`）都导入本模块。本层仍不产出 `StandardRecord`、不做归属
# 核对（`authorize_attribution`）、不整流核对（`session_stage.py`）、不脱敏（`redaction.py`）、
# 不解析行内容；那些由上层负责。`authorize_store` 通过不等于可发布正文（DES-API-01 要求四项各自成立）。
#
# `FileVersion` 由同一次授权读取产生：句柄身份（`_probe_handle_identity` 的那份，与复核基准同一
# 来源）+ 逐块累计的 `consumed_bytes` + 同趟 `hashlib.sha256` 摘要。摘要在 `_read_chunk` 里对每块
# 更新，因此 `complete=False`（触限、提前关闭、非 EOF 停止）时 `content_sha256` 只覆盖已读部分，
# 调用方必须以 `complete` 为准，不能拿半程摘要当整流指纹。`as_public_dict()` 不存在，卷号、文件
# 标识、字节数与摘要都不跨越协议边界：它们只在 `references.ReferenceLedger` 内部与上下文读取
# 的当场比对中使用（`session_context` 比的是同一组四元字段，含同大小改写场景）。
#
# 未验证（交后续静态审查与真机功能测试）：
# 1. Windows ctypes 路径（`msvcrt.get_osfhandle` + `GetFileType` +
#    `GetFileInformationByHandleEx`(FileAttributeTagInfo=9 / FileIdInfo=18) +
#    `GetFinalPathNameByHandleW` 的结构体布局、两段式缓冲区、返回值语义与 `FILE_TYPE_*`
#    取值集合）未在真机执行；junction/符号链接目标下内核给出的
#    最终路径写法能否总被 `_strip_device_prefix` 还原成策略层接受的形态，未核实。
#    `FILE_ID_INFO` 与 `FILE_ATTRIBUTE_TAG_INFO` 的真实大小、字段偏移与名下归属（本层按 24/0+8
#    与 8 自检）未真机确认；自检不合即报 `file_identity_unsupported`，不拿错位布局比身份。
# 2. `FileIdInfo` 的 (VolumeSerialNumber 64 位, FileId 16 字节) 在真实会话
#    所在文件系统（网络盘/SMB、容器挂载、9P、ReFS、exFAT）上是否稳定唯一，完全未实测；
#    SMB 重定向对象的身份稳定性尤其未知（本层按 `FILE_TYPE_REMOTE` 归为非磁盘对象直接拒，
#    策略层的形状限制不变）。全零标识按 `file_identity_unsupported` 拒；给不出就被拒是安全
#    方向，代价是那些挂载上本层不可用。硬链接（同标识不同名字）本层判不出，不据此改判也不
#    宣称覆盖。
# 3. POSIX 侧 `st_dev`/`st_ino` 为 0 的判定与 `S_ISREG` 行为、Linux `/proc/self/fd` 在容器/
#    SELinux 下的可读性、` (deleted)` 后缀的确切形式未实测；macOS/BSD 固定
#    `handle_path_unsupported`（该平台上本层整体不可用）。
# 4. `buffering=0`（无缓冲文件对象）下的 `read(n)` 是否恰为一次底层读、异常或中断路径上底层
#    是否滞留未交出的字节，均未实测——本层因此只宣称「`consumed_bytes` 是每次底层请求的预算」，
#    不宣称异常时刻绝对零滞留、不扩展异步中断的窗口处理；`O_NONBLOCK`/`O_NOCTTY` 在目标 CRT 上
#    是否真的可用、以及单趟顺序读在真实大文件上的代价，同样未实测。
# 5. 行框架只用 `\n` 判行尾（`\r\n` 因 `\n` 前一字节是 `\r` 而自然被整行包含）：不处理孤立
#    `\r` 作为行尾的旧 Mac 写法，也不处理 `str.splitlines` 的其它边界（`\v`、`\f`、U+2028）。
#    这是有意的窄口径：行尾语义最终由来源解析器决定，本层只保证「按 `\n` 切分且交出整行字节」。
# 6. 魔数集合是固定名单（gzip/zlib/bzip2/xz/zstd/zip/7z/compress/PE/ELF/PDF/图标/SQLite），
#    只覆盖前 `_MAGIC_READ_BYTES`=16 个字节：名单外的压缩流仍会被按行读，窗口之后的 NUL 也不
#    拦，它不构成「已排除二进制/已排除数据库」的保证；反向误拒同样存在（会话正文恰好以 `MZ`、
#    `%PDF-` 开头时被当作归档拒掉）。名单本轮未扩展。
# 7. `_reauthorize_final_path` 要求策略层结论与句柄落点逐分量相等：存储根本身经过链接
#    （`allow_links=True`）时两者写法可能确实不同，此时本层拒绝而非放行——该保守方向
#    是否会在真实配置上造成不可用，未实测。
# 8. 合成验证状态（Windows 本机）：`tests/test_session_context.py` 以合成临时目录文件驱动
#    `file_replaced` 两条路径（同大小改写、追加改写）与 `file_version` 完整链；
#    `tests/test_file_search.py`/`tests/test_stdio.py` 驱动同一条授权读取链。
# 9. `authorize_content_digest`（2026-11-02 增量）同样只在合成临时目录上被驱动
#    （`tests/test_hermes_aggregate.py`：SQLite 头魔数对象可取指纹、预算小于对象即
#    `complete=False`、指纹随内容变化）；它不放宽上面任何一条边界，共享的是同一批原语，
#    因此 1–7 的未验证项对它同样成立。它同样不做解压、不打开数据库、不解释 SQL 结果。
#    未打开任何真实会话文件，未安装依赖，未联网。仍待真机覆盖的是下列 1–7 项各自的真实环境行为。
#    运行前提：Python 3.11+，不新增依赖。
