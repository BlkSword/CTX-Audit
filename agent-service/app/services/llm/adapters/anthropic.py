"""
Anthropic Claude 适配器
"""
import asyncio
import json
from typing import List, Dict, Any, Optional, AsyncIterator

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from loguru import logger

from .base import BaseLLMAdapter, LLMResponse, LLMStreamChunk, LLMMessage


class AnthropicAdapter(BaseLLMAdapter):
    """Anthropic Claude 适配器"""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-5-sonnet-20241022",
        base_url: Optional[str] = None,
    ):
        super().__init__(api_key=api_key, model=model, base_url=base_url)

        if not ANTHROPIC_AVAILABLE:
            raise ImportError("anthropic 包未安装，请运行: pip install anthropic")

        self.client = anthropic.AsyncAnthropic(
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

        # 分离系统消息
        system_message = ""
        user_messages = []

        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                user_messages.append({
                    "role": msg.role,
                    "content": msg.content,
                })

        # 构建请求参数
        request_params = {
            "model": self.model,
            "messages": user_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if system_message:
            request_params["system"] = system_message

        # 工具调用支持
        if tools:
            request_params["tools"] = self._convert_tools(tools)

        try:
            response = await self.client.messages.create(**request_params)

            # 提取内容
            content = self._extract_content(response.content)

            # 解析工具调用
            tool_calls = self._extract_tool_calls(response.content)

            return LLMResponse(
                content=content,
                model=response.model,
                usage={
                    "prompt_tokens": response.usage.input_tokens,
                    "completion_tokens": response.usage.output_tokens,
                    "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
                },
                tool_calls=tool_calls,
                finish_reason=response.stop_reason,
            )

        except Exception as e:
            logger.error(f"Anthropic API 调用失败: {e}")
            raise

    async def generate_stream(
        self,
        messages: List[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs
    ) -> AsyncIterator[LLMStreamChunk]:
        """流式生成文本"""

        # 分离系统消息
        system_message = ""
        user_messages = []

        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                user_messages.append({
                    "role": msg.role,
                    "content": msg.content,
                })

        request_params = {
            "model": self.model,
            "messages": user_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if system_message:
            request_params["system"] = system_message

        try:
            async with self.client.messages.stream(**request_params) as stream:
                async for text in stream.text_stream:
                    yield LLMStreamChunk(content=text)

        except Exception as e:
            logger.error(f"Anthropic 流式 API 调用失败: {e}")
            raise

    async def generate_stream_with_tools(
        self,
        messages: List[LLMMessage],
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> AsyncIterator[LLMStreamChunk]:
        """
        流式生成文本（支持工具调用）

        返回包含 content 和累积的 tool_calls 的流式块
        当工具调用完成时，最终的块将包含完整的 tool_calls

        Yields:
            LLMStreamChunk: 每个 token 块，可能包含:
                - content: 文本内容
                - tool_calls: 累积的工具调用（如果有）
                - is_complete: 是否完成
        """
        # 分离系统消息
        system_message = ""
        user_messages = []

        for msg in messages:
            if msg.role == "system":
                system_message = msg.content
            else:
                user_messages.append({
                    "role": msg.role,
                    "content": msg.content,
                })

        request_params = {
            "model": self.model,
            "messages": user_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if system_message:
            request_params["system"] = system_message

        if tools:
            request_params["tools"] = self._convert_tools(tools)

        collected_tool_calls = []
        current_content = ""

        try:
            # 使用原始的 stream API 来获取事件流
            async with self.client.messages.stream(**request_params) as stream:
                async for event in stream:
                    if event.type == "content_block_start":
                        # 新的内容块开始
                        if event.content_block.type == "tool_use":
                            # 工具使用块开始
                            tool_call = {
                                "id": event.content_block.id,
                                "type": "function",
                                "function": {
                                    "name": event.content_block.name,
                                    "arguments": "",
                                }
                            }
                            collected_tool_calls.append(tool_call)

                    elif event.type == "content_block_delta":
                        # 内容增量
                        if event.delta.type == "text_delta":
                            # 文本增量
                            text = event.delta.text
                            current_content += text
                            yield LLMStreamChunk(
                                content=text,
                                tool_calls=None,
                                is_complete=False
                            )
                        elif event.delta.type == "input_json_delta":
                            # 工具参数增量
                            if collected_tool_calls:
                                # 更新最后一个工具调用的参数
                                last_tool = collected_tool_calls[-1]
                                last_tool["function"]["arguments"] += event.delta.partial_json

                    elif event.type == "message_stop":
                        # 消息完成
                        # 返回最终状态，包含所有工具调用
                        yield LLMStreamChunk(
                            content="",
                            tool_calls=collected_tool_calls if collected_tool_calls else None,
                            is_complete=True
                        )

        except Exception as e:
            logger.error(f"Anthropic 流式工具调用失败: {e}")
            raise

    def _convert_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """转换工具格式为 Anthropic 格式"""
        anthropic_tools = []

        for tool in tools:
            function = tool.get("function", {})
            # OpenAI 格式: function.parameters 包含 schema
            parameters = function.get("parameters", {})

            anthropic_tools.append({
                "name": function.get("name"),
                "description": function.get("description", ""),
                "input_schema": {
                    "type": "object",
                    "properties": parameters.get("properties", {}),
                    "required": parameters.get("required", []),
                }
            })

        return anthropic_tools

    def _extract_content(self, blocks: List[Any]) -> str:
        """从响应块中提取文本内容"""
        content_parts = []

        for block in blocks:
            if block.type == "text":
                content_parts.append(block.text)
            elif block.type == "tool_use":
                # 工具调用块，不提取文本
                pass

        return "".join(content_parts)

    def _extract_tool_calls(self, blocks: List[Any]) -> List[Dict[str, Any]]:
        """从响应块中提取工具调用"""
        tool_calls = []

        for block in blocks:
            if block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "type": "function",
                    "function": {
                        "name": block.name,
                        "arguments": json.dumps(block.input, ensure_ascii=False),
                    }
                })

        return tool_calls
