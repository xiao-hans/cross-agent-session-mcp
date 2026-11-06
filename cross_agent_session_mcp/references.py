"""进程内引用账本：授权核对完成后发放**不透明引用**，只存元数据、不存正文（DES-API-01/DES-SEC-01）。

定位：查询或上下文运行在两条授权轴与遮蔽全部通过后，为每条**已发布**记录发放一个随机不透明引用
（`ctxref:<随机串>`）。`read_session_context` 只认这个引用：客户端拿不到、也造不出可用的定位符——
行号、偏移、卷号、文件标识都不参与对外协议，猜行号或自带版本号来降级读取的通道不存在。

绑定了什么（全部为元数据，绝不含正文片段）：
- **服务绑定指纹**：`(scope, source, path, session_id)` 的定长摘要——换一个绑定服务实例即失配；
- **范围/来源/会话/项目**：与发放时的授权核对逐字段一致，上下文侧再与客户端参数比对；
- **消息位置**：记录在行流中的 `(line_no, ordinal, stream_label)`，只用于与重新读取的记录核对，
  永不从引用本身解出（引用串里没有任何位置信息）；
- **同一授权读取句柄确立的版本**：卷号、文件标识、体积与**整文件 SHA-256 摘要**（摘要在同趟
  `AuthorizedLineReader` 的字节流上顺手算出，不二次读、不按路径 stat），同大小改写也会变。
  真实卷号/文件标识只存内部、不外出。

容量与有效期（只能收紧）：
- 活跃引用硬顶 `MAX_ACTIVE_REFERENCES`（4096）：满员按发放顺序淘汰最旧条目，被淘汰的引用与
  过期同口径拒绝（缺失即拒，不静默续期）；
- 有效期 `REFERENCE_TTL_SECONDS`（900 秒，单调时钟）：到期即删；每次发放顺手清理过期项。

失败口径：缺失/过期/被淘汰/与绑定矛盾/文件版本变化，一律由调用方（`session_context`）折算为
固定类别的零结果拒绝；本模块只回答「这个引用在不在、绑定是什么、版本是什么」。

依赖限制（DES-ARCH-02）：只用标准库；不导入包内其他模块（版本三元组以显式标量入参传入），
不打开文件、不探测路径、不写日志、不联网。记录不实现任何携带正文的字段；`repr` 被刻意收窄为只含令牌前缀与绑定指纹（路径、卷号、文件标识、体积、摘要、行位都不出现），日志或异常里打印记录对象不构成外泄面。
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

__all__ = [
    "MAX_ACTIVE_REFERENCES",
    "MAX_ISSUE_PER_CALL",
    "MAX_REFERENCE_TOKEN_CHARS",
    "REFERENCE_PREFIX",
    "REFERENCE_TTL_SECONDS",
    "ReferenceLedger",
    "ReferenceRecord",
    "clear_reference_ledger",
    "default_ledger",
    "issue_reference",
    "lookup_reference",
    "parse_reference_token",
    "service_binding_key",
]

#: 引用前缀与整体形状：`ctxref:` + `secrets.token_urlsafe` 产出（URL-safe base64，不含 `+/=`，
#: 因此不可能携带路径分隔符、盘符或冒号之后的第二个可解析段）。
REFERENCE_PREFIX = "ctxref"

#: 随机字节数：34 字节 ≈ 45 个 base64url 字符，客户端无法枚举或猜测。
_REFERENCE_TOKEN_BYTES = 34

#: 引用串外出后的最大总长（前缀 + 冒号 + 随机段）；入口判形用，超长即拒，不截断使用。
MAX_REFERENCE_TOKEN_CHARS = 128

#: 活跃引用条数硬顶：满员按发放顺序淘汰最旧（淘汰即「缺失」，与过期同一拒绝口径）。
MAX_ACTIVE_REFERENCES = 4096

#: 单次调用可发放的引用条数上限（与上下文窗口 21、查询出口 32 的硬顶相容，只多不留余量）。
MAX_ISSUE_PER_CALL = 32

#: 引用有效期（秒，单调时钟）：过期即从账本删除，lookup 视同缺失。
REFERENCE_TTL_SECONDS = 900.0

#: 随机段允许的字符集：`secrets.token_urlsafe` 的产出字母表（A-Za-z0-9-_）。
_TOKEN_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


@dataclass(frozen=True, repr=False)
class ReferenceRecord:
    """一条已发放引用的内部绑定元数据：只含短标识与版本标量，绝不含正文、路径之外的原值回显。

    `path` 是发放时**已批准**的存储文件路径，仅用于与上下文服务的绑定比对（比对用完整字符串相等，
    本字段不进入任何对外结果）。`volume`/`file_id`/`size_bytes`/`content_sha256` 是同一授权读取
    句柄确立的版本，只在本模块与 `session_context` 内部使用，永不外出。
    """

    token: str
    service_key: str
    path: str
    scope: str
    source: str
    session_id: str
    project: str | None
    line_no: int
    ordinal: int
    stream_label: str | None
    volume: int
    file_id: int
    size_bytes: int
    content_sha256: str
    expires_at: float

    def __repr__(self) -> str:
        """只回显定位符前缀与绑定指纹：路径/卷号/文件标识/摘要/行位不进 repr。"""
        return (
            f"ReferenceRecord(token={self.token[:12]}… "
            f"service={self.service_key[:12]}…)"
        )


def service_binding_key(*, scope: str, source: str, path: str, session_id: str) -> str:
    """把服务绑定四元组折算为定长十六进制摘要：对外不出现在任何结果里，只做内部等值比对。

    用摘要而不是原值拼串，是为了让「比对绑定」这件事不依赖任何可回显的键形态；
    分隔符用长度前缀绑定，避免字段内容拼接歧义（`a|b` 与 `ab|` 之类的碰撞）。
    """
    digest = hashlib.sha256()
    for part in (scope, source, path, session_id):
        digest.update(str(len(part)).encode("ascii"))
        digest.update(b":")
        digest.update(part.encode("utf-8", "surrogatepass"))
    return digest.hexdigest()


def parse_reference_token(value: object) -> str | None:
    """入口判形：整体接受或整体拒绝，返回**字面 str** 引用串；不合形态返回 `None`。

    判据全部是形状判据：固定前缀、总长上限、随机段只允许 `token_urlsafe` 字母表。
    路径分隔符、盘符、空白、`#`/`L` 之类的位置记号都进不了这个字母表，
    因此「自造一个像行号的引用」在判形层就被拒。
    """
    if not isinstance(value, str) or value.__class__ is not str:
        return None
    if not 0 < len(value) <= MAX_REFERENCE_TOKEN_CHARS:
        return None
    prefix, sep, remainder = value.partition(":")
    if sep != ":" or prefix != REFERENCE_PREFIX or not remainder:
        return None
    if not all(char in _TOKEN_ALPHABET for char in remainder):
        return None
    return value


class ReferenceLedger:
    """进程内活跃引用表：发放、精确查询、按 TTL 与容量淘汰。无正文、无锁、单线程语义。

    与包内其他「有界驻留」结构同一取向：条目有硬顶、有寿命，满员淘汰最旧而不是拒绝发放新条目
    ——淘汰只会让旧引用变成「缺失即拒」，不会放宽任何核对。
    """

    __slots__ = ("_capacity", "_records", "_ttl", "clock")

    def __init__(
        self,
        *,
        capacity: int = MAX_ACTIVE_REFERENCES,
        ttl_seconds: float = REFERENCE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """容量与寿命只能收紧：非字面 int / 非正 TTL / 超硬顶的容量都当场 `ValueError`。"""
        if (
            isinstance(capacity, bool)
            or not isinstance(capacity, int)
            or capacity.__class__ is not int
            or not 1 <= capacity <= MAX_ACTIVE_REFERENCES
        ):
            raise ValueError("reference ledger capacity out of range")
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not 1.0 <= float(ttl_seconds) <= REFERENCE_TTL_SECONDS
        ):
            raise ValueError("reference ledger ttl out of range")
        self._capacity = capacity
        self._ttl = float(ttl_seconds)
        self.clock = clock
        # dict 保序：插入顺序即发放顺序，淘汰端取 `next(iter(...))`。
        self._records: dict[str, ReferenceRecord] = {}

    def __len__(self) -> int:
        return len(self._records)

    def issue(
        self,
        *,
        service_key: str,
        path: str,
        scope: str,
        source: str,
        session_id: str,
        project: str | None,
        line_no: int,
        ordinal: int,
        stream_label: str | None,
        volume: int,
        file_id: int,
        size_bytes: int,
        content_sha256: str,
    ) -> str:
        """发放一条新引用并返回随机引用串；同批调用方负责上限（见 `MAX_ISSUE_PER_CALL`）。

        入口一次校验（AGENTS.md：外部数据在边界校验一次）：位置与版本必须是字面非负 `int`、
        摘要必须是 64 位十六进制小写；绑定标识必须是非空字面 `str`。不合格直接 `ValueError`——
        那是编程侧错误，不是客户端可以触发的拒绝。
        """
        for text in (service_key, path, scope, source, session_id):
            if text.__class__ is not str or not text:
                raise ValueError("reference binding field invalid")
        if project is not None and (project.__class__ is not str or not project):
            raise ValueError("reference project field invalid")
        if stream_label is not None and stream_label.__class__ is not str:
            raise ValueError("reference stream label invalid")
        for value in (line_no, ordinal, volume, file_id, size_bytes):
            if value.__class__ is not int or value < 0:
                raise ValueError("reference integer field invalid")
        if line_no < 1:
            raise ValueError("reference line out of range")
        if (
            content_sha256.__class__ is not str
            or len(content_sha256) != 64
            or any(char not in "0123456789abcdef" for char in content_sha256)
        ):
            raise ValueError("reference digest invalid")
        now = self.clock()
        self._prune(now)
        if len(self._records) >= self._capacity:
            oldest = next(iter(self._records))
            del self._records[oldest]
        token = f"{REFERENCE_PREFIX}:{secrets.token_urlsafe(_REFERENCE_TOKEN_BYTES)}"
        self._records[token] = ReferenceRecord(
            token=token,
            service_key=service_key,
            path=path,
            scope=scope,
            source=source,
            session_id=session_id,
            project=project,
            line_no=line_no,
            ordinal=ordinal,
            stream_label=stream_label,
            volume=volume,
            file_id=file_id,
            size_bytes=size_bytes,
            content_sha256=content_sha256,
            expires_at=now + self._ttl,
        )
        return token

    def lookup(self, token: str) -> ReferenceRecord | None:
        """按**完整引用串**精确查询：缺失、过期、被淘汰都返回 `None`（同一拒绝口径）。

        不对未命中的串做任何解析或回退：引用串之外不存在任何定位通道，这是「不可猜」的另一半。
        """
        record = self._records.get(token)
        if record is None:
            return None
        if self.clock() >= record.expires_at:
            del self._records[token]
            return None
        return record

    def clear(self) -> None:
        """清空全部活跃引用（宿主轮换绑定时的显式动作；测试用它隔离状态）。"""
        self._records.clear()

    def release(self, tokens: Sequence[str]) -> None:
        """只收回点名给出的引用：半途失败的发放整批回滚用。

        调用方拿不到别人的引用串，因此本方法不可能越权收回：不认识的串直接不存在于表中，
        收回失败不抛异常也不返回计数（那只会多一个可被误用的观测面）。
        """
        for token in tokens:
            self._records.pop(token, None)

    def _prune(self, now: float) -> None:
        """清理已过期条目：发放路径顺手执行，读取路径靠 `lookup` 自身判过期。"""
        expired = [token for token, record in self._records.items() if now >= record.expires_at]
        for token in expired:
            del self._records[token]


_DEFAULT_LEDGER = ReferenceLedger()


def default_ledger() -> ReferenceLedger:
    """包内共享的默认账本实例：查询与上下文两条路径必须用同一个，引用才跨调用可核对。"""
    return _DEFAULT_LEDGER


def issue_reference(
    *,
    service_key: str,
    path: str,
    scope: str,
    source: str,
    session_id: str,
    project: str | None,
    line_no: int,
    ordinal: int,
    stream_label: str | None,
    volume: int,
    file_id: int,
    size_bytes: int,
    content_sha256: str,
    ledger: ReferenceLedger | None = None,
) -> str:
    """默认账本上的发放快捷入口（参数语义见 `ReferenceLedger.issue`）。"""
    return (ledger if ledger is not None else _DEFAULT_LEDGER).issue(
        service_key=service_key,
        path=path,
        scope=scope,
        source=source,
        session_id=session_id,
        project=project,
        line_no=line_no,
        ordinal=ordinal,
        stream_label=stream_label,
        volume=volume,
        file_id=file_id,
        size_bytes=size_bytes,
        content_sha256=content_sha256,
    )


def lookup_reference(token: str, *, ledger: ReferenceLedger | None = None) -> ReferenceRecord | None:
    """默认账本上的精确查询（语义见 `ReferenceLedger.lookup`）。"""
    return (ledger if ledger is not None else _DEFAULT_LEDGER).lookup(token)


def clear_reference_ledger(ledger: ReferenceLedger | None = None) -> None:
    """清空默认（或指定）账本：宿主轮换绑定或测试隔离用。"""
    (ledger if ledger is not None else _DEFAULT_LEDGER).clear()
