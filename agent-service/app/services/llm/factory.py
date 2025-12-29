"""
LLM 适配器工厂

根据配置创建相应的 LLM 适配器实例
"""
from typing import Optional, Dict, Any

from .adapters.base import BaseLLMAdapter, LLMProvider
from .adapters.anthropic import AnthropicAdapter
from .adapters.openai import OpenAIAdapter


class LLMAdapterError(Exception):
    """LLM 适配器错误"""
    pass


class LLMFactory:
    """LLM 适配器工厂"""

    # 默认模型映射
    DEFAULT_MODELS = {
        LLMProvider.ANTHROPIC: "claude-3-5-sonnet-20241022",
        LLMProvider.OPENAI: "gpt-4o",
        LLMProvider.DEEPSEEK: "deepseek-chat",
        LLMProvider.OLLAMA: "llama3",
        LLMProvider.QWEN: "qwen-turbo",
        LLMProvider.ZHIPU: "glm-4",
    }

    # API 密钥环境变量名
    API_KEY_ENV_VARS = {
        LLMProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
        LLMProvider.OPENAI: "OPENAI_API_KEY",
        LLMProvider.DEEPSEEK: "DEEPSEEK_API_KEY",
        LLMProvider.OLLAMA: "",  # Ollama 通常不需要 API 密钥
        LLMProvider.QWEN: "DASHSCOPE_API_KEY",
        LLMProvider.ZHIPU: "ZHIPU_API_KEY",
    }

    @classmethod
    def create_adapter(
        cls,
        provider: LLMProvider,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> BaseLLMAdapter:
        """
        创建 LLM 适配器

        Args:
            provider: LLM 提供商
            api_key: API 密钥 (如果为 None，从环境变量读取)
            model: 模型名称 (如果为 None，使用默认模型)
            base_url: 自定义 API 基础 URL
            config: 额外配置

        Returns:
            LLM 适配器实例
        """
        config = config or {}

        # 获取 API 密钥
        if api_key is None:
            import os
            env_var = cls.API_KEY_ENV_VARS.get(provider)
            if env_var:
                api_key = os.getenv(env_var)
                if not api_key:
                    raise LLMAdapterError(
                        f"未找到 API 密钥，请设置环境变量 {env_var} 或直接传入 api_key"
                    )
            else:
                api_key = ""

        # 获取模型名称
        if model is None:
            model = cls.DEFAULT_MODELS.get(provider)

        if not model:
            raise LLMAdapterError(f"未指定模型，且提供商 {provider.value} 没有默认模型")

        # 创建适配器
        if provider == LLMProvider.ANTHROPIC:
            return AnthropicAdapter(
                api_key=api_key,
                model=model,
                base_url=base_url,
            )

        elif provider == LLMProvider.OPENAI:
            # OpenAI 及其兼容 API (如 DeepSeek)
            if base_url is None and provider == LLMProvider.DEEPSEEK:
                base_url = "https://api.deepseek.com"

            return OpenAIAdapter(
                api_key=api_key,
                model=model,
                base_url=base_url,
            )

        else:
            # 其他使用 OpenAI 兼容 API 的提供商
            return OpenAIAdapter(
                api_key=api_key,
                model=model,
                base_url=base_url or config.get("base_url"),
            )

    @classmethod
    def create_from_config(cls, config: Dict[str, Any]) -> BaseLLMAdapter:
        """
        从配置字典创建适配器

        Args:
            config: 配置字典，包含 provider, api_key, model, base_url 等字段

        Returns:
            LLM 适配器实例
        """
        provider_str = config.get("provider", "anthropic")
        try:
            provider = LLMProvider(provider_str.lower())
        except ValueError:
            raise LLMAdapterError(f"不支持的 LLM 提供商: {provider_str}")

        return cls.create_adapter(
            provider=provider,
            api_key=config.get("api_key"),
            model=config.get("model"),
            base_url=config.get("base_url"),
            config=config,
        )

    @classmethod
    def get_default_model(cls, provider: LLMProvider) -> str:
        """获取提供商的默认模型"""
        return cls.DEFAULT_MODELS.get(provider, "")
