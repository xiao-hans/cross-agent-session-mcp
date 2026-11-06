"""测试专用宿主：把合成临时目录发现/显式列举成有界集合后绑定，再以 stdio 运行真实服务。

**这不是生产入口**：`cross_agent_session_mcp.server.main()` 依旧不绑定、不读配置。本脚本只服务
`tests/test_stdio_bound.py`——宿主从**环境变量**取得合成目录（客户端在协议面上永远无法提供路径）：
pi 侧用 `discover_pi_session_files` 得到 `SessionFileRef` 集合；hermes 侧用
`CROSS_AGENT_TEST_HERMES_DB` 显式列举 `(库路径, session_id)` 二元组（Hermes 没有发现层，绑定集合
只能来自宿主配置）。两侧都构造共账、同形的查询/上下文服务并显式绑定，然后走与生产完全相同的
stdio 传输。

不读取任何真实会话、不访问用户配置目录、不联网；所有目录与文件都由测试临时提供。

运行：python tests/_bound_stdio_host.py（需先把仓库根加入 PYTHONPATH；测试套件已经这么传）
环境变量：CROSS_AGENT_TEST_SCOPE / CROSS_AGENT_TEST_PROJECT_DIRS（逗号分隔项目根）/
CROSS_AGENT_TEST_STORE_ROOTS（逗号分隔 pi 存储根）
         CROSS_AGENT_TEST_HERMES_DB（合成 Hermes 库绝对路径）/ CROSS_AGENT_TEST_HERMES_REPO（归属项目根）
"""

from __future__ import annotations

import os
from pathlib import Path

from cross_agent_session_mcp import server
from cross_agent_session_mcp.hermes_aggregate import (
    HermesAggregateSearchService,
    HermesStoreRef,
)
from cross_agent_session_mcp.policy import (
    CwdRootGrant,
    ProjectGrant,
    ScopeGrant,
    SessionPolicy,
    StoreRootGrant,
)
from cross_agent_session_mcp.references import ReferenceLedger
from cross_agent_session_mcp.session_discovery import (
    PiMultiFileContextService,
    PiMultiFileSearchService,
    discover_pi_session_files,
)


def _dirs(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def build_policy(*, hermes_roots: tuple[str, ...] = ()) -> SessionPolicy:
    """按环境变量里的合成目录搭一套最小策略：一个 scope、若干项目、若干存储根。

    Hermes 侧另传被批准的库根：SQLite 不是可扫描文件，授权必须逐根显式配置，
    与 pi 的目录存储根分开登记，互不借位。
    """
    projects = tuple(
        ProjectGrant(f"test-proj-{index}", (CwdRootGrant(root),))
        for index, root in enumerate(_dirs("CROSS_AGENT_TEST_PROJECT_DIRS"))
    )
    store_roots = tuple(
        StoreRootGrant("pi", root) for root in _dirs("CROSS_AGENT_TEST_STORE_ROOTS")
    )
    store_roots += tuple(StoreRootGrant("hermes", root) for root in hermes_roots)
    if not projects or not store_roots:
        raise SystemExit("合成宿主缺少项目或存储根环境变量")
    return SessionPolicy(
        scopes=(
            ScopeGrant(
                scope_id=os.environ.get("CROSS_AGENT_TEST_SCOPE", "synthetic-scope"),
                projects=projects,
                store_roots=store_roots,
            ),
        )
    )


def _bind_hermes() -> None:
    """合成 Hermes 库 → 有界 `(库, 会话)` 集合绑定。Hermes 无发现层，集合只能显式给出。"""
    db = os.environ.get("CROSS_AGENT_TEST_HERMES_DB", "").strip()
    repo = os.environ.get("CROSS_AGENT_TEST_HERMES_REPO", "").strip()
    if not db or not repo:
        raise SystemExit("合成 Hermes 宿主缺少库路径或项目根")
    scope = os.environ.get("CROSS_AGENT_TEST_SCOPE", "synthetic-scope")
    policy = build_policy(hermes_roots=(str(Path(db).parent),))
    # 两个合成会话同库：路由靠的是 `(库, 会话)` 绑定，而不是库或会话单轴。
    stores = (HermesStoreRef(db, "sA"), HermesStoreRef(db, "sB"))
    ledger = ReferenceLedger()
    search = HermesAggregateSearchService(
        policy=policy, scope=scope, stores=stores, ledger=ledger
    )
    # 配对经 `context_service()` 交出：同账、同序集合与绑定键都由服务自己提供，宿主不手抄。
    server.bind_hermes_aggregate_search_service(search)
    server.bind_hermes_aggregate_context_service(search.context_service())


def main() -> None:
    scope = os.environ.get("CROSS_AGENT_TEST_SCOPE", "synthetic-scope")
    if os.environ.get("CROSS_AGENT_TEST_HERMES_DB", "").strip():
        # Hermes 用例只需要 hermes 一条链：pi 侧保持未绑定，避免两个来源同时 ready。
        _bind_hermes()
        server.app.run(transport="stdio")
        return
    policy = build_policy()
    roots = list(_dirs("CROSS_AGENT_TEST_STORE_ROOTS"))
    discovery = discover_pi_session_files(policy, scope, roots)
    # 直接沿用发现层交付的绑定（已过逐条授权、链接/逃逸拒绝与标识断言判形）：
    # 被拒/未授权的路径不会进绑定集合，而 `as_public_dict()` 本身也不外出任何路径。
    files = discovery.files
    if not files:
        raise SystemExit("合成宿主未发现任何会话文件")
    # 一本账、同形两侧：查询发放的 ctxref 才能被上下文服务核对。
    ledger = ReferenceLedger()
    search = PiMultiFileSearchService(
        policy=policy, scope=scope, files=files, ledger=ledger
    )
    context = PiMultiFileContextService(
        policy=policy, scope=scope, files=files, ledger=ledger
    )
    server.bind_pi_multi_file_search_service(search)
    server.bind_pi_multi_file_context_service(context)
    server.app.run(transport="stdio")


if __name__ == "__main__":
    main()
