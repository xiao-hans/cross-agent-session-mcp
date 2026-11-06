"""来源适配层（DES-ARCH-02「来源适配」行）。

本包内每个模块对应一类来源，单向依赖 `cross_agent_session_mcp.models` 的标准记录契约；
来源之间不相互依赖，不导入 MCP SDK，不打开文件、不发现目录、不读取配置。

当前实现 `pi`（JSONL 逐行解析，已接入 server 工具面）、`codex`（rollout 行流解析，尚未接线）、
`claude`（Claude Code CLI stream-json 行流解析，来源 ID `claude_code_cli`，尚未接线；扩展来源默认
由 `server.py` 的门控制）与 `hermes`（SQLite 只读单会话适配：模块内建两轴授权与判限/降级契约，
但尚未接入 server 工具面与聚合检索，属于下一增量）。其余三类来源（dsh、workbuddy、
cursor_agent_cli）尚未编写。
"""

from __future__ import annotations

__all__: list[str] = []
