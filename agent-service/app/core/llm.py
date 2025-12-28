"""
LLM 客户端

统一的 LLM 调用接口，支持多种提供商
"""
from typing import Optional, Dict, Any
from loguru import logger
import httpx

from app.config import settings


class LLMClient:
    """
    LLM 客户端

    支持：
    - Anthropic Claude
    - OpenAI GPT
    - 自定义端点（通过 HTTP）
    """

    def __init__(self):
        self.provider = settings.LLM_PROVIDER
        self.model = settings.LLM_MODEL
        self._client: Optional[httpx.AsyncClient] = None
        self.api_key = self._get_api_key()

    def _get_api_key(self) -> str:
        """获取 API Key"""
        if self.provider == "anthropic":
            return settings.ANTHROPIC_API_KEY
        elif self.provider == "openai":
            return settings.OPENAI_API_KEY
        return ""

    async def _get_client(self) -> httpx.AsyncClient:
        """获取 HTTP 客户端"""
        if self._client is None:
            timeout = httpx.Timeout(60.0, connect=10.0)
            self._client = httpx.AsyncClient(timeout=timeout)
        return self._client

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        **kwargs
    ) -> str:
        """
        生成文本

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            max_tokens: 最大 token 数
            temperature: 温度参数
            **kwargs: 其他参数

        Returns:
            生成的文本
        """
        if not self.api_key:
            logger.warning("未配置 LLM API Key，返回模拟响应")
            return self._mock_response(prompt)

        try:
            if self.provider == "anthropic":
                return await self._generate_anthropic(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            elif self.provider == "openai":
                return await self._generate_openai(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            else:
                logger.warning(f"不支持的 LLM 提供商: {self.provider}")
                return self._mock_response(prompt)

        except Exception as e:
            logger.error(f"LLM 调用失败: {e}")
            return self._mock_response(prompt)

    async def _generate_anthropic(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """调用 Anthropic Claude API"""
        client = await self._get_client()

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        messages = [{"role": "user", "content": prompt}]
        body = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }

        if system_prompt:
            body["system"] = system_prompt

        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=body,
        )

        response.raise_for_status()
        data = response.json()

        return data["content"][0]["text"]

    async def _generate_openai(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """调用 OpenAI GPT API"""
        client = await self._get_client()

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=body,
        )

        response.raise_for_status()
        data = response.json()

        return data["choices"][0]["message"]["content"]

    def _mock_response(self, prompt: str) -> str:
        """
        模拟响应（用于开发测试）

        Args:
            prompt: 原始提示词

        Returns:
            模拟响应
        """
        return """
这是一个模拟的 LLM 响应。

要启用真实的 LLM 功能，请在 .env 文件中配置：
- LLM_PROVIDER=anthropic 或 openai
- ANTHROPIC_API_KEY 或 OPENAI_API_KEY

在实际部署中，这里将返回 LLM 生成的真实分析结果。
""".strip()

    async def close(self):
        """关闭客户端连接"""
        if self._client:
            await self._client.aclose()
            self._client = None


# 全局 LLM 客户端实例
llm_client = LLMClient()
