"""
MCP 风格工具系统

提供符合 Model Context Protocol 标准的工具定义和执行框架
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Type
from dataclasses import dataclass, field
from enum import Enum
import json


class ToolErrorCode(Enum):
    """工具错误码"""
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    NOT_FOUND = "NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"


@dataclass
class ToolResult:
    """
    工具执行结果

    遵循 MCP 工具结果格式：
    - content: 结果内容列表
    - isError: 是否为错误
    - _meta: 元数据（可选）
    """
    content: List[Dict[str, Any]]
    isError: bool = False
    _meta: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式（MCP兼容）"""
        result = {
            "content": self.content,
            "isError": self.isError
        }
        if self._meta:
            result["_meta"] = self._meta
        return result

    @classmethod
    def success(cls, text: str, data: Optional[Dict[str, Any]] = None) -> "ToolResult":
        """创建成功结果"""
        content = [{"type": "text", "text": text}]
        if data:
            content.append({"type": "data", "data": data})
        return cls(content=content, isError=False)

    @classmethod
    def error(cls, message: str, code: ToolErrorCode = ToolErrorCode.INTERNAL_ERROR) -> "ToolResult":
        """创建错误结果"""
        return cls(
            content=[{
                "type": "error",
                "error": {
                    "code": code.value,
                    "message": message
                }
            }],
            isError=True
        )

    @classmethod
    def json(cls, data: Dict[str, Any], description: Optional[str] = None) -> "ToolResult":
        """创建JSON结果"""
        text = description or json.dumps(data, ensure_ascii=False, indent=2)
        return cls(
            content=[
                {"type": "text", "text": text},
                {"type": "json", "json": data}
            ],
            isError=False
        )


@dataclass
class ToolParameter:
    """
    工具参数定义

    遵循 JSON Schema 格式
    """
    name: str
    type: str  # string, number, integer, boolean, array, object
    description: str
    required: bool = False
    default: Any = None
    enum: Optional[List[Any]] = None
    format: Optional[str] = None  # 用于进一步限定类型，如 "uri", "email"
    items: Optional[Dict[str, Any]] = None  # 当type为array时，定义元素类型
    properties: Optional[Dict[str, Dict[str, Any]]] = None  # 当type为object时，定义属性

    def to_json_schema(self) -> Dict[str, Any]:
        """转换为JSON Schema格式"""
        schema: Dict[str, Any] = {
            "type": self.type,
            "description": self.description
        }

        if self.enum:
            schema["enum"] = self.enum
        if self.format:
            schema["format"] = self.format
        if self.default is not None:
            schema["default"] = self.default
        if self.items:
            schema["items"] = self.items
        if self.properties:
            schema["properties"] = self.properties

        return schema


@dataclass
class ToolDefinition:
    """
    工具定义

    遵循 MCP Tool 格式
    """
    name: str
    description: str
    parameters: List[ToolParameter] = field(default_factory=list)
    input_schema: Optional[Dict[str, Any]] = None  # 可选的完整JSON Schema

    def to_mcp_format(self) -> Dict[str, Any]:
        """转换为MCP工具格式"""
        if self.input_schema:
            # 使用自定义的完整schema
            properties = self.input_schema.get("properties", {})
            required = self.input_schema.get("required", [])
        else:
            # 从参数列表构建schema
            properties = {}
            required = []
            for param in self.parameters:
                properties[param.name] = param.to_json_schema()
                if param.required:
                    required.append(param.name)

        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required
            }
        }


class MCPTool(ABC):
    """
    MCP工具基类

    所有工具都应继承此类并实现 execute 方法
    """

    # 子类需要定义这些类属性
    name: str = ""
    description: str = ""
    parameters: List[ToolParameter] = []

    def __init__(self, context: Optional[Dict[str, Any]] = None):
        """
        初始化工具

        Args:
            context: 执行上下文，包含 audit_id, project_id 等
        """
        self.context = context or {}

    @classmethod
    def get_definition(cls) -> ToolDefinition:
        """获取工具定义"""
        return ToolDefinition(
            name=cls.name,
            description=cls.description,
            parameters=cls.parameters
        )

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        """
        执行工具

        Args:
            **kwargs: 工具参数

        Returns:
            ToolResult: 执行结果
        """
        pass

    async def validate_arguments(self, arguments: Dict[str, Any]) -> Optional[str]:
        """
        验证参数

        Returns:
            错误信息，如果验证通过则返回 None
        """
        for param in self.parameters:
            if param.required and param.name not in arguments:
                return f"缺少必需参数: {param.name}"

            # 类型验证
            if param.name in arguments:
                value = arguments[param.name]
                type_map = {
                    "string": str,
                    "number": (int, float),
                    "integer": int,
                    "boolean": bool,
                    "array": list,
                    "object": dict,
                }

                expected_type = type_map.get(param.type)
                if expected_type and not isinstance(value, expected_type):
                    return f"参数 {param.name} 类型错误，期望 {param.type}，实际 {type(value).__name__}"

                # enum 验证
                if param.enum and value not in param.enum:
                    return f"参数 {param.name} 值无效，允许的值: {param.enum}"

        return None

    def log(self, message: str) -> None:
        """记录日志（可通过 context 中的 logger 实现）"""
        from loguru import logger
        logger.debug(f"[{self.name}] {message}")

    def think(self, thought: str) -> None:
        """记录思考过程"""
        from loguru import logger
        logger.info(f"[{self.name}] 思考: {thought}")


class ToolRegistry:
    """
    工具注册表

    管理所有可用的MCP工具
    """

    def __init__(self):
        self._tools: Dict[str, Type[MCPTool]] = {}

    def register(self, tool_class: Type[MCPTool]) -> None:
        """注册工具"""
        if not tool_class.name:
            raise ValueError(f"工具类 {tool_class.__name__} 缺少 name 属性")

        self._tools[tool_class.name] = tool_class

    def get(self, name: str) -> Optional[Type[MCPTool]]:
        """获取工具类"""
        return self._tools.get(name)

    def list_tools(self) -> List[ToolDefinition]:
        """列出所有工具定义"""
        return [tool_class.get_definition() for tool_class in self._tools.values()]

    def to_mcp_tools_list(self) -> List[Dict[str, Any]]:
        """转换为MCP工具列表格式"""
        return [tool.to_mcp_format() for tool in self.list_tools()]

    async def execute(
        self,
        name: str,
        arguments: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """
        执行工具

        Args:
            name: 工具名称
            arguments: 工具参数
            context: 执行上下文

        Returns:
            ToolResult: 执行结果
        """
        tool_class = self._tools.get(name)
        if not tool_class:
            return ToolResult.error(f"工具不存在: {name}", ToolErrorCode.NOT_FOUND)

        tool = tool_class(context=context)

        # 验证参数
        error = await tool.validate_arguments(arguments)
        if error:
            return ToolResult.error(error, ToolErrorCode.INVALID_ARGUMENT)

        try:
            return await tool.execute(**arguments)
        except Exception as e:
            tool.log(f"执行失败: {str(e)}")
            return ToolResult.error(f"工具执行失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


# 全局工具注册表
_global_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """获取全局工具注册表"""
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry


def register_tool(tool_class: Type[MCPTool]) -> None:
    """注册工具到全局注册表"""
    get_tool_registry().register(tool_class)
