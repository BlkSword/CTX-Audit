"""
LLM 服务

统一的 LLM 服务接口
"""
from typing import List, Dict, Any, Optional, AsyncIterator
from loguru import logger

from .adapters.base import BaseLLMAdapter, LLMResponse, LLMStreamChunk, LLMMessage, LLMProvider
from .factory import LLMFactory, LLMAdapterError


class LLMService:
    """统一的 LLM 服务"""

    def __init__(
        self,
        provider: LLMProvider = LLMProvider.ANTHROPIC,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        初始化 LLM 服务

        Args:
            provider: LLM 提供商
            model: 模型名称
            api_key: API 密钥
            base_url: 自定义 API 基础 URL
            config: 额外配置
        """
        self.provider = provider
        self.model = model or LLMFactory.get_default_model(provider)
        self.adapter = LLMFactory.create_adapter(
            provider=provider,
            api_key=api_key,
            model=self.model,
            base_url=base_url,
            config=config,
        )

    async def generate(
        self,
        messages: List[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> LLMResponse:
        """
        生成文本

        Args:
            messages: 消息列表
            max_tokens: 最大生成 token 数
            temperature: 温度参数
            tools: 工具列表 (用于工具调用)

        Returns:
            LLM 响应
        """
        try:
            response = await self.adapter.generate(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                tools=tools,
            )

            logger.debug(
                f"LLM 生成完成: provider={self.provider.value}, "
                f"model={self.model}, "
                f"tokens={response.usage.get('total_tokens', 0)}"
            )

            return response

        except Exception as e:
            logger.error(f"LLM 生成失败: {e}")
            raise

    async def generate_stream(
        self,
        messages: List[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> AsyncIterator[LLMStreamChunk]:
        """
        流式生成文本

        Args:
            messages: 消息列表
            max_tokens: 最大生成 token 数
            temperature: 温度参数

        Yields:
            流式响应块
        """
        try:
            async for chunk in self.adapter.generate_stream(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            ):
                yield chunk

        except Exception as e:
            logger.error(f"LLM 流式生成失败: {e}")
            raise

    async def generate_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> Dict[str, Any]:
        """
        生成并调用工具

        Args:
            messages: 原始消息列表 (dict 格式)
            tools: 工具列表
            max_tokens: 最大生成 token 数
            temperature: 温度参数

        Returns:
            包含 content 和 tool_calls 的响应
        """
        # 转换消息格式
        llm_messages = [
            LLMMessage(
                role=msg["role"],
                content=msg["content"],
                tool_calls=msg.get("tool_calls"),
                tool_call_id=msg.get("tool_call_id"),
            )
            for msg in messages
        ]

        response = await self.generate(
            messages=llm_messages,
            max_tokens=max_tokens,
            temperature=temperature,
            tools=tools,
        )

        return {
            "content": response.content,
            "tool_calls": response.tool_calls,
            "usage": response.usage,
            "finish_reason": response.finish_reason,
        }

    async def generate_stream_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ):
        """
        流式生成文本（支持工具调用）

        Args:
            messages: 原始消息列表 (dict 格式)
            tools: 工具列表
            max_tokens: 最大生成 token 数
            temperature: 温度参数

        Yields:
            LLMStreamChunk: 流式响应块
        """
        # 转换消息格式
        llm_messages = [
            LLMMessage(
                role=msg["role"],
                content=msg["content"],
                tool_calls=msg.get("tool_calls"),
                tool_call_id=msg.get("tool_call_id"),
            )
            for msg in messages
        ]

        async for chunk in self.adapter.generate_stream_with_tools(
            messages=llm_messages,
            tools=tools,
            max_tokens=max_tokens,
            temperature=temperature,
        ):
            yield chunk

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "LLMService":
        """
        从配置创建 LLM 服务

        Args:
            config: 配置字典，包含:
                - provider: LLM 提供商（可选）
                - llm_provider: LLM 提供商（可选，优先级高于 provider）
                - model: 模型名称
                - api_key: API 密钥
                - base_url: API 端点（可选）

        Returns:
            LLM 服务实例
        """
        # 优先使用 llm_provider，然后使用 provider
        provider_str = config.get("llm_provider") or config.get("provider", "openai")

        # 如果没有有效的 base_url，无法继续
        if not config.get("api_key"):
            raise ValueError("api_key is required")

        # 尝试解析 provider，如果无效则使用 openai（最通用的格式）
        try:
            provider = LLMProvider(provider_str.lower())
        except ValueError:
            logger.warning(f"未知的 provider '{provider_str}'，使用 OpenAI 兼容模式")
            provider = LLMProvider.OPENAI

        return cls(
            provider=provider,
            model=config.get("model", "gpt-3.5-turbo"),
            api_key=config.get("api_key"),
            base_url=config.get("base_url"),
            config=config,
        )
