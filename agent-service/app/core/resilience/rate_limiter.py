"""
速率限制器模块

基于令牌桶算法的速率限制实现
"""
import asyncio
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any
from loguru import logger


@dataclass
class RateLimiterConfig:
    """速率限制配置"""
    tokens_per_second: float = 10.0  # 每秒生成的令牌数
    max_tokens: int = 100             # 桶的最大容量
    initial_tokens: Optional[int] = None  # 初始令牌数（默认为 max_tokens）

    def __post_init__(self):
        if self.initial_tokens is None:
            self.initial_tokens = self.max_tokens


class RateLimiter:
    """
    速率限制器

    使用令牌桶算法：
    - 桶中有 max_tokens 个令牌
    - 每秒以 tokens_per_second 的速率添加令牌
    - 每次请求消耗一个令牌
    - 当没有令牌时，请求被阻塞或拒绝
    """

    def __init__(self, name: str, config: Optional[RateLimiterConfig] = None):
        self.name = name
        self.config = config or RateLimiterConfig()
        self._tokens = float(self.config.initial_tokens)
        self._last_refill = time.time()
        self._lock = asyncio.Lock()
        self._total_requests = 0
        self._total_rejected = 0
        self._total_wait_time = 0.0

    async def acquire(
        self,
        tokens: int = 1,
        block: bool = True,
        timeout: Optional[float] = None,
    ) -> bool:
        """
        获取令牌

        Args:
            tokens: 需要的令牌数
            block: 是否阻塞等待
            timeout: 最大等待时间（秒）

        Returns:
            是否成功获取令牌
        """
        self._total_requests += 1

        async with self._lock:
            # 补充令牌
            self._refill()

            # 检查是否有足够的令牌
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True

            # 不阻塞，直接返回失败
            if not block:
                self._total_rejected += 1
                return False

            # 计算需要等待的时间
            wait_time = self._calculate_wait_time(tokens)

            # 检查超时
            if timeout is not None and wait_time > timeout:
                self._total_rejected += 1
                return False

        # 等待令牌补充
        self._total_wait_time += wait_time
        await asyncio.sleep(wait_time)

        # 重新尝试获取
        return await self.acquire(tokens, block=False)

    def _refill(self) -> None:
        """补充令牌"""
        now = time.time()
        elapsed = now - self._last_refill

        # 计算应该补充的令牌数
        tokens_to_add = elapsed * self.config.tokens_per_second

        # 补充令牌，不超过最大容量
        self._tokens = min(
            self.config.max_tokens,
            self._tokens + tokens_to_add
        )

        self._last_refill = now

    def _calculate_wait_time(self, tokens: int) -> float:
        """计算等待时间"""
        deficit = tokens - self._tokens
        return deficit / self.config.tokens_per_second

    async def acquire_with_decorator(
        self,
        tokens: int = 1,
        block: bool = True,
        timeout: Optional[float] = None,
    ):
        """
        装饰器版本的令牌获取

        用法:
            @rate_limiter.acquire_with_decorator(tokens=2)
            async def some_function():
                pass
        """
        def decorator(func):
            async def wrapper(*args, **kwargs):
                await self.acquire(tokens, block, timeout)
                return await func(*args, **kwargs)
            return wrapper
        return decorator

    def get_status(self) -> Dict[str, Any]:
        """获取速率限制器状态"""
        self._refill()  # 确保获取最新状态
        return {
            "name": self.name,
            "available_tokens": int(self._tokens),
            "max_tokens": self.config.max_tokens,
            "tokens_per_second": self.config.tokens_per_second,
            "total_requests": self._total_requests,
            "total_rejected": self._total_rejected,
            "rejection_rate": (
                self._total_rejected / self._total_requests
                if self._total_requests > 0 else 0
            ),
            "total_wait_time": self._total_wait_time,
            "utilization": (
                1.0 - (self._tokens / self.config.max_tokens)
                if self.config.max_tokens > 0 else 0
            ),
        }

    def reset(self) -> None:
        """重置速率限制器"""
        self._tokens = float(self.config.initial_tokens)
        self._last_refill = time.time()
        self._total_requests = 0
        self._total_rejected = 0
        self._total_wait_time = 0.0


class RateLimiterRegistry:
    """速率限制器注册表"""

    def __init__(self):
        self._limiters: Dict[str, RateLimiter] = {}

    def get_or_create(
        self,
        name: str,
        config: Optional[RateLimiterConfig] = None,
    ) -> RateLimiter:
        """获取或创建速率限制器"""
        if name not in self._limiters:
            self._limiters[name] = RateLimiter(name, config)
        return self._limiters[name]

    def get(self, name: str) -> Optional[RateLimiter]:
        """获取速率限制器"""
        return self._limiters.get(name)

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """获取所有速率限制器的状态"""
        return {
            name: limiter.get_status()
            for name, limiter in self._limiters.items()
        }


# 全局注册表
_global_registry: Optional[RateLimiterRegistry] = None


def get_rate_limiter_registry() -> RateLimiterRegistry:
    """获取全局速率限制器注册表"""
    global _global_registry
    if _global_registry is None:
        _global_registry = RateLimiterRegistry()
    return _global_registry


def get_rate_limiter(
    name: str,
    config: Optional[RateLimiterConfig] = None,
) -> RateLimiter:
    """获取或创建速率限制器"""
    return get_rate_limiter_registry().get_or_create(name, config)


# 预定义的速率限制器配置

# LLM 调用限制（严格）
LLM_RATE_LIMITER = RateLimiterConfig(
    tokens_per_second=5.0,   # 每秒 5 次调用
    max_tokens=50,            # 桶容量 50
)

# 工具调用限制（宽松）
TOOL_RATE_LIMITER = RateLimiterConfig(
    tokens_per_second=20.0,  # 每秒 20 次调用
    max_tokens=200,           # 桶容量 200
)

# API 请求限制
API_RATE_LIMITER = RateLimiterConfig(
    tokens_per_second=10.0,
    max_tokens=100,
)


def get_llm_rate_limiter() -> RateLimiter:
    """获取 LLM 速率限制器"""
    return get_rate_limiter("llm", LLM_RATE_LIMITER)


def get_tool_rate_limiter(tool_name: str = "tool") -> RateLimiter:
    """获取工具速率限制器"""
    return get_rate_limiter(f"tool_{tool_name}", TOOL_RATE_LIMITER)


def get_api_rate_limiter() -> RateLimiter:
    """获取 API 速率限制器"""
    return get_rate_limiter("api", API_RATE_LIMITER)
