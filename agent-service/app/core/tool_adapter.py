"""
MCP 工具适配器

将 MCP 工具系统适配到现有的 agent 框架中
"""
from typing import Dict, Any, Optional, Callable, List
from loguru import logger

from app.core.mcp_tools import get_tool_registry, ToolResult

# 导入工具模块以触发自动注册
import app.core.tools

# 验证工具已注册
registry = get_tool_registry()
logger.info(f"[ToolAdapter] 已注册 {len(registry._tools)} 个 MCP 工具")


class MCPToolAdapter:
    """
    MCP工具适配器

    负责将MCP工具转换为现有的tool_handler格式
    """

    def __init__(self, context: Optional[Dict[str, Any]] = None):
        """
        初始化适配器

        Args:
            context: 执行上下文
        """
        self.registry = get_tool_registry()
        self.context = context or {}

    def get_tool_handlers(self) -> Dict[str, Callable]:
        """
        获取工具处理器字典（兼容现有格式）

        Returns:
            {tool_name: handler_function} 字典
        """
        handlers = {}
        for tool_def in self.registry.list_tools():
            tool_name = tool_def.name

            def make_handler(name: str):
                async def handler(**kwargs):
                    return await self._execute_tool(name, kwargs)
                return handler

            handlers[tool_name] = make_handler(tool_name)

        return handlers

    def get_llm_tools(self) -> List[Dict[str, Any]]:
        """
        获取LLM工具格式（OpenAI Function Calling兼容）

        Returns:
            LLM工具列表
        """
        tools = []
        for tool_def in self.registry.list_tools():
            # 转换为 OpenAI Function Calling 格式
            # Anthropic adapter 会提取 function 字段
            tools.append({
                "type": "function",
                "function": {
                    "name": tool_def.name,
                    "description": tool_def.description,
                    # 将 parameters 转换为 OpenAI 格式
                    "parameters": self._convert_parameters_to_openai(tool_def)
                }
            })
        return tools

    def _convert_parameters_to_openai(self, tool_def) -> Dict[str, Any]:
        """
        将 MCP 工具参数转换为 OpenAI Function Calling 格式

        Args:
            tool_def: MCP 工具定义

        Returns:
            OpenAI 格式的 parameters 字典
        """
        if tool_def.input_schema:
            # 如果有自定义的完整 schema，直接使用
            return tool_def.input_schema

        # 从参数列表构建 OpenAI 格式
        properties = {}
        required = []

        for param in tool_def.parameters:
            prop_def = {
                "type": param.type,
                "description": param.description
            }

            # 添加可选字段
            if param.enum:
                prop_def["enum"] = param.enum
            if param.format:
                prop_def["format"] = param.format
            if param.items:
                prop_def["items"] = param.items
            if param.properties:
                prop_def["properties"] = param.properties
            if param.default is not None:
                prop_def["default"] = param.default

            properties[param.name] = prop_def

            if param.required:
                required.append(param.name)

        return {
            "type": "object",
            "properties": properties,
            "required": required
        }

    async def _execute_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        """
        执行工具并返回字符串格式结果

        Args:
            name: 工具名称
            arguments: 工具参数

        Returns:
            字符串格式的结果
        """
        result: ToolResult = await self.registry.execute(
            name=name,
            arguments=arguments,
            context=self.context
        )

        # 转换 ToolResult 为字符串
        return self._format_result(result)

    def _format_result(self, result: ToolResult) -> str:
        """
        格式化工具结果为字符串

        Args:
            result: 工具执行结果

        Returns:
            格式化的字符串
        """
        if result.isError:
            # 错误结果
            for item in result.content:
                if item.get("type") == "error":
                    error_info = item.get("error", {})
                    return f"错误: {error_info.get('message', '未知错误')}"
            return "执行失败"

        # 成功结果
        output_parts = []
        for item in result.content:
            if item.get("type") == "text":
                output_parts.append(item.get("text", ""))
            elif item.get("type") == "json":
                # JSON类型不需要额外输出，已经包含在text中
                pass

        return "\n".join(output_parts) if output_parts else "执行成功"


def create_tool_bridge(context: Optional[Dict[str, Any]] = None) -> tuple:
    """
    创建工具桥接器

    Args:
        context: 执行上下文

    Returns:
        (tool_handlers, llm_tools) 元组
        - tool_handlers: 用于 ToolCallLoop 的处理器字典
        - llm_tools: 用于 LLM 的工具列表
    """
    adapter = MCPToolAdapter(context=context)

    return adapter.get_tool_handlers(), adapter.get_llm_tools()


def list_available_tools() -> List[Dict[str, Any]]:
    """
    列出所有可用工具

    Returns:
        工具定义列表
    """
    return get_tool_registry().list_tools()


def print_tools_summary():
    """打印工具摘要"""
    tools = list_available_tools()

    logger.info(f"\n{'='*60}")
    logger.info(f"已注册 {len(tools)} 个 MCP 工具:")
    logger.info(f"{'='*60}")

    for tool in tools:
        logger.info(f"\n📦 {tool.name}")
        logger.info(f"   {tool.description[:100]}...")

        if tool.parameters:
            required = [p.name for p in tool.parameters if p.required]
            optional = [p.name for p in tool.parameters if not p.required]

            if required:
                logger.info(f"   必需参数: {', '.join(required)}")
            if optional:
                logger.info(f"   可选参数: {', '.join(optional)}")

    logger.info(f"\n{'='*60}\n")


# 导出
__all__ = [
    "MCPToolAdapter",
    "create_tool_bridge",
    "list_available_tools",
    "print_tools_summary",
]
