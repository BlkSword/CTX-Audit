"""
OpenAI 适配器

支持 OpenAI 和兼容 OpenAI API 的服务 (如 DeepSeek)
"""
import json
from typing import List, Dict, Any, Optional, AsyncIterator

try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from loguru import logger

from .base import BaseLLMAdapter, LLMResponse, LLMStreamChunk, LLMMessage


class OpenAIAdapter(BaseLLMAdapter):
    """OpenAI 适配器"""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: Optional[str] = None,
    ):
        super().__init__(api_key=api_key, model=model, base_url=base_url)

        if not OPENAI_AVAILABLE:
            raise ImportError("openai 包未安装，请运行: pip install openai")

        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
        )

    async def generate(
        self,
        messages: List[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> LLMResponse:
        """生成文本"""

        # 转换消息格式
        openai_messages = self._convert_messages(messages)

        # 构建请求参数
        request_params = {
            "model": self.model,
            "messages": openai_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        # 工具调用支持
        if tools:
            request_params["tools"] = tools

        try:
            response = await self.client.chat.completions.create(**request_params)

            choice = response.choices[0]
            message = choice.message

            # 解析工具调用
            tool_calls = None
            if message.tool_calls:
                tool_calls = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        }
                    }
                    for tc in message.tool_calls
                ]

            return LLMResponse(
                content=message.content or "",
                model=response.model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                },
                tool_calls=tool_calls or [],
                finish_reason=choice.finish_reason,
            )

        except Exception as e:
            logger.error(f"OpenAI API 调用失败: {e}")
            raise

    async def generate_stream(
        self,
        messages: List[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs
    ) -> AsyncIterator[LLMStreamChunk]:
        """流式生成文本"""

        openai_messages = self._convert_messages(messages)

        request_params = {
            "model": self.model,
            "messages": openai_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }

        try:
            stream = await self.client.chat.completions.create(**request_params)

            async for chunk in stream:
                delta = chunk.choices[0].delta

                # 提取内容
                if delta.content:
                    yield LLMStreamChunk(content=delta.content)

                # 检查是否完成
                if chunk.choices[0].finish_reason is not None:
                    yield LLMStreamChunk(content="", is_complete=True)
                    break

        except Exception as e:
            logger.error(f"OpenAI 流式 API 调用失败: {e}")
            raise
