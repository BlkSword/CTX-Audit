"""
LLM 适配器基类

定义统一的 LLM 接口
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, AsyncIterator
from enum import Enum


class LLMProvider(Enum):
    """LLM 提供商"""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"
    QWEN = "qwen"
    ZHIPU = "zhipu"


@dataclass
class LLMResponse:
    """LLM 响应"""
    content: str
    model: str
    usage: Dict[str, int] = field(default_factory=dict)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    finish_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "content": self.content,
            "model": self.model,
            "usage": self.usage,
            "tool_calls": self.tool_calls,
            "finish_reason": self.finish_reason,
        }


@dataclass
class LLMStreamChunk:
    """LLM 流式响应块"""
    content: str
    is_complete: bool = False
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class LLMMessage:
    """LLM 消息"""
    role: str  # system | user | assistant
    content: str
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None


class BaseLLMAdapter(ABC):
    """LLM 适配器基类"""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    @abstractmethod
    async def generate(
        self,
        messages: List[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> LLMResponse:
        """生成文本"""
        pass

    @abstractmethod
    async def generate_stream(
        self,
        messages: List[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs
    ) -> AsyncIterator[LLMStreamChunk]:
        """流式生成文本"""
        pass

    def _convert_messages(self, messages: List[LLMMessage]) -> List[Dict[str, Any]]:
        """转换消息格式"""
        result = []
        for msg in messages:
            msg_dict = {"role": msg.role, "content": msg.content}
            if msg.tool_calls is not None:
                msg_dict["tool_calls"] = msg.tool_calls
            if msg.tool_call_id is not None:
                msg_dict["tool_call_id"] = msg.tool_call_id
            result.append(msg_dict)
        return result

    def _parse_tool_calls(self, raw_calls: List[Any]) -> List[Dict[str, Any]]:
        """解析工具调用"""
        if not raw_calls:
            return []

        result = []
        for call in raw_calls:
            result.append({
                "id": getattr(call, "id", ""),
                "type": "function",
                "function": {
                    "name": getattr(call.function, "name", ""),
                    "arguments": getattr(call.function, "arguments", "{}"),
                }
            })
        return result
