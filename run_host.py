"""跨 Agent 会话检索 MCP stdio 独立启动脚本。

供 Hermes MCP stdio transport 直接运行，自动把仓库根加入 sys.path，
无需依赖外部 PYTHONPATH 环境变量。
"""

from __future__ import annotations

import sys
from pathlib import Path

# 把包含本脚本的仓库根目录加入 sys.path，确保能够导入 cross_agent_session_mcp 包
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cross_agent_session_mcp.host import main

if __name__ == "__main__":
    sys.exit(main())
