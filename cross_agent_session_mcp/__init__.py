"""跨 Agent 会话检索 MCP 服务包。

`server` 提供只读协议入口；宿主可显式绑定固定策略范围与单个批准 Pi 文件的查询与上下文服务
（两者必须共用同一个引用账本）。默认 MCP app 不绑定服务：未绑定时两个数据工具安全拒绝，
来源发现仍为骨架。
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.0.1"
