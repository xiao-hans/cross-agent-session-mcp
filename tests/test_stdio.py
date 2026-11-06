"""TC-MCP-01（合成）：stdio 握手 + tools/list + 未实现工具的安全拒绝。

只用合成数据：不读取任何真实会话、不访问用户配置目录、不联网。
运行：python -m unittest tests.test_stdio -v
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import unittest
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_MODULE = "cross_agent_session_mcp.server"
EXPECTED_TOOLS = {"list_sources", "search_sessions", "read_session_context"}
TIMEOUT_SECONDS = 60.0


def _server_params() -> StdioServerParameters:
    extra = os.environ.get("PYTHONPATH")
    search_path = str(REPO_ROOT) if not extra else os.pathsep.join([str(REPO_ROOT), extra])
    env = {
        "PYTHONPATH": search_path,
        "PYTHONIOENCODING": "utf-8",
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
    }
    return StdioServerParameters(command=sys.executable, args=["-m", SERVER_MODULE], env=env, cwd=str(REPO_ROOT))


async def _with_server(case: Callable[[ClientSession], Awaitable[Any]]) -> Any:
    async with (
        asyncio.timeout(TIMEOUT_SECONDS),
        stdio_client(_server_params()) as (read, write),
        ClientSession(read, write) as session,
    ):
        return await case(session)


def _run(case: Callable[[ClientSession], Awaitable[Any]]) -> Any:
    return asyncio.run(_with_server(case))


def _text_blocks(res: Any) -> str:
    return "\n".join(c.text for c in res.content if getattr(c, "type", None) == "text")


def _result_payload(res: Any) -> dict[str, Any]:
    """工具结果：优先 structuredContent，否则解析唯一 JSON 文本块。"""
    structured = getattr(res, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    text = _text_blocks(res)
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"_text": text}
    return parsed if isinstance(parsed, dict) else {"_text": text}


class TestStdioHandshake(unittest.TestCase):
    def test_initialize_returns_server_info(self) -> None:
        async def case(session: ClientSession) -> None:
            init = await session.initialize()
            self.assertTrue(init.protocol_version, "握手必须返回 protocolVersion")
            self.assertEqual(init.server_info.name, "cross-agent-session-mcp")
            self.assertIsNotNone(init.capabilities.tools, "必须声明 tools 能力")

        _run(case)

    def test_tools_list_exposes_exactly_three_read_only_tools(self) -> None:
        async def case(session: ClientSession) -> None:
            await session.initialize()
            listed = await session.list_tools()
            names = {t.name for t in listed.tools}
            self.assertEqual(names, EXPECTED_TOOLS, "本增量只注册三个工具")
            for tool in listed.tools:
                annotations = tool.annotations
                assert annotations is not None, f"{tool.name} 必须有 annotations"
                self.assertIs(annotations.read_only_hint, True, f"{tool.name} 必须标 readOnlyHint")
                self.assertIs(annotations.destructive_hint, False, f"{tool.name} 不得标破坏性")
                self.assertTrue(tool.description, f"{tool.name} 必须有说明")
                self.assertIsInstance(tool.input_schema, dict)
                self.assertEqual(tool.input_schema.get("type"), "object")

        _run(case)

    def test_input_schema_matches_des_api_01(self) -> None:
        async def case(session: ClientSession) -> None:
            await session.initialize()
            by_name = {t.name: t for t in (await session.list_tools()).tools}
            search_props = by_name["search_sessions"].input_schema.get("properties", {})
            for field in ("query", "sources", "start", "end", "scope", "project", "limit"):
                self.assertIn(field, search_props, f"search_sessions 缺少参数 {field}")
            read_props = by_name["read_session_context"].input_schema.get("properties", {})
            for field in (
                "source",
                "session_id",
                "location",
                "scope",
                "project",
                "before",
                "after",
            ):
                self.assertIn(field, read_props, f"read_session_context 缺少参数 {field}")
            # 版本/行号不由客户端携带：协议面不得出现这些参数（不可降级读取的另一半）。
            for forbidden in ("path", "line_no", "volume", "file_id", "size_bytes", "window"):
                self.assertNotIn(
                    forbidden, read_props, f"read_session_context 不得接受参数 {forbidden}"
                )

        _run(case)


class TestUnboundAndSkeletonRefusal(unittest.TestCase):
    """状态口径分开：`list_sources` 真未实现（骨架），两个读取工具是「已实现但未绑定」。

    误名修正：本类原名 `TestNotImplementedRefusal`，但它断言的两条读取拒绝来自**未绑定**
    （不是未实现）。把未绑定说成未实现会让调用方以为没有可用路径，从而不去绑定服务。
    """

    def test_list_sources_reports_no_ready_source(self) -> None:
        async def case(session: ClientSession) -> None:
            await session.initialize()
            res = await session.call_tool("list_sources", {})
            self.assertFalse(res.is_error, "骨架状态查询本身不应报错")
            payload = _result_payload(res)
            # P1-8 口径：本构建已完成七族接线，顶层恒报 `partial`；未绑定只体现为
            # 逐源 `enabled=false` + 非 ready，不得再冒充「未实现」。
            self.assertEqual(payload.get("implementation_status"), "partial", "接线完成后不得声称未实现")
            sources = payload.get("sources")
            assert isinstance(sources, list), "sources 必须是列表"
            self.assertTrue(sources, "必须逐源给出状态")
            for row in sources:
                self.assertIn(row.get("status"), {"disabled", "unavailable", "unsupported"})
                self.assertFalse(row.get("enabled"), "本增量不得报告任何来源已启用")
                self.assertTrue(row.get("reason"), f"每源必须给出简短原因：{row}")
                self.assertNotIn("path", row, "不得返回绝对个人路径")

        _run(case)

    def test_search_sessions_refuses_when_unbound(self) -> None:
        async def case(session: ClientSession) -> None:
            await session.initialize()
            res = await session.call_tool(
                "search_sessions",
                {
                    "query": "合成关键词",
                    "scope": "synthetic-scope",
                    "start": "2026-01-01T00:00:00+08:00",
                    "end": "2026-01-02T00:00:00+08:00",
                },
            )
            self.assertTrue(res.is_error, "未绑定服务的检索必须显式拒绝")
            text = _text_blocks(res)
            self.assertIn("未绑定", text, "已实现但未绑定的工具不得自称未实现")
            self.assertNotIn("未实现", text, "未绑定不是未实现")
            self.assertNotIn("合成关键词", text, "拒绝信息不得回显查询词")

        _run(case)

    def test_read_session_context_refuses_when_unbound(self) -> None:
        async def case(session: ClientSession) -> None:
            await session.initialize()
            res = await session.call_tool(
                "read_session_context",
                {
                    "source": "pi",
                    "session_id": "synthetic-session",
                    "location": "0",
                    "scope": "synthetic-scope",
                    "project": "synthetic-project",
                },
            )
            self.assertTrue(res.is_error, "未绑定服务的上下文读取必须显式拒绝")
            text = _text_blocks(res)
            self.assertIn("未绑定", text, "已实现但未绑定的工具不得自称未实现")
            self.assertNotIn("未实现", text, "未绑定不是未实现")

        _run(case)

    def test_read_session_context_window_bounds_and_out_of_range(self) -> None:
        """协议层先卡 before/after 各自 0-10，再判绑定：越界不回显原值也不打开任何文件。"""

        async def case(session: ClientSession) -> None:
            await session.initialize()
            base = {
                "source": "pi",
                "session_id": "synthetic-session",
                "location": "ctxref:synthetic",
                "scope": "synthetic-scope",
            }
            # 越界两侧均拒；`bool` 型越界在 SDK 的 JSON 校验层已被归一为整数，因此不在
            # stdio 测试面断言（协议层的 `bool` 拒只在本包 `_check_window`/`_window_side` 生效）。
            for field, bad in (("before", 11), ("after", -1)):
                payload: dict[str, Any] = dict(base)
                payload[field] = bad
                res = await session.call_tool("read_session_context", payload)
                self.assertTrue(res.is_error, f"{field}={bad!r} 必须被拒")
                text = _text_blocks(res)
                self.assertIn("before/after", text)
                self.assertNotIn("ctxref:synthetic", text, "拒绝信息不得回显定位符")

        _run(case)

    def test_unknown_tool_refused_and_session_survives(self) -> None:
        async def case(session: ClientSession) -> None:
            await session.initialize()
            res = await session.call_tool("write_session", {"session_id": "synthetic"})
            self.assertTrue(res.is_error, "未注册工具必须被拒绝")
            listed = await session.list_tools()
            self.assertEqual({t.name for t in listed.tools}, EXPECTED_TOOLS)

        _run(case)

    def test_no_resources_or_prompts_exposed_and_no_arbitrary_file_read(self) -> None:
        """本增量不开放资源/提示：不得凭 `resources/read` 读到任意本地文件。"""

        async def case(session: ClientSession) -> None:
            await session.initialize()
            self.assertEqual((await session.list_resources()).resources, [], "本增量不得暴露任何资源")
            self.assertEqual((await session.list_prompts()).prompts, [], "本增量不得暴露任何提示模板")
            probe = Path(sys.executable).as_uri()
            try:
                await session.read_resource(probe)
            except MCPError as exc:
                self.assertIn(exc.code, (-32602, -32601), f"预期拒绝读取任意路径，实际 code={exc.code}")
            else:
                self.fail(f"resources/read 不得返回任意本地文件内容：{probe}")

        _run(case)


if __name__ == "__main__":
    unittest.main()
