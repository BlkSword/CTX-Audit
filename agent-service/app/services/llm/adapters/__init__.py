"""
LLM 适配器

支持多种 LLM 平台的统一接口
"""
from .base import BaseLLMAdapter, LLMResponse, LLMStreamChunk
from .anthropic import AnthropicAdapter
from .openai import OpenAIAdapter

__all__ = [
    "BaseLLMAdapter",
    "LLMResponse",
    "LLMStreamChunk",
    "AnthropicAdapter",
    "OpenAIAdapter",
]
