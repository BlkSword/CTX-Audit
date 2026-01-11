"""
Combined Resilience Module

结合重试和熔断器的综合容错能力
"""
from typing import Any, Awaitable, Callable, Optional, TypeVar
from loguru import logger

from .retry import RetryConfig, retry_with_backoff
from .circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitOpenError

T = TypeVar("T")


@dataclass
class ResilientConfig:
    """综合容错配置"""
    retry_config: RetryConfig = RetryConfig()
    circuit_config: Optional[CircuitBreakerConfig] = None
    enable_retry: bool = True
    enable_circuit_breaker: bool = True


async def resilient_call(
    func: Callable[[], Awaitable[T]],
    config: ResilientConfig = ResilientConfig(),
    operation_name: str = "operation",
) -> T:
    """
    综合容错调用 - 结合重试和熔断器

    Args:
        func: 要执行的异步函数
        config: 容错配置
        operation_name: 操作名称（用于日志）

    Returns:
        函数执行结果

    Raises:
        Exception: 所有重试和熔断都失败后抛出原始异常
    """
    circuit_breaker: Optional[CircuitBreaker] = None

    if config.enable_circuit_breaker and config.circuit_config:
        # 创建熔断器（如果启用）
        from .circuit_breaker import CircuitBreaker
        circuit_breaker = CircuitBreaker(
            name=operation_name,
            config=config.circuit_config
        )

    async def execute_with_circuit() -> T:
        if circuit_breaker:
            async with circuit_breaker:
                return await func()
        else:
            return await func()

    if config.enable_retry:
        # 使用重试机制包装
        return await retry_with_backoff(
            execute_with_circuit,
            config=config.retry_config,
            operation_name=operation_name,
        )
    else:
        return await execute_with_circuit()


def with_resilience(config: Optional[ResilientConfig] = None):
    """装饰器：为函数添加综合容错能力"""
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(*args, **kwargs) -> T:
            return await resilient_call(
                lambda: func(*args, **kwargs),
                config=config or ResilientConfig(),
                operation_name=func.__name__,
            )
        return wrapper
    return decorator


# 预定义的容错配置
LLM_RESILIENT_CONFIG = ResilientConfig(
    retry_config=RetryConfig(max_attempts=3, base_delay=1.0, max_delay=60.0),
    circuit_config=CircuitBreakerConfig(failure_threshold=5, recovery_timeout=30.0),
    enable_retry=True,
    enable_circuit_breaker=True,
)

TOOL_RESILIENT_CONFIG = ResilientConfig(
    retry_config=RetryConfig(max_attempts=2, base_delay=2.0, max_delay=30.0),
    circuit_config=CircuitBreakerConfig(failure_threshold=3, recovery_timeout=60.0),
    enable_retry=True,
    enable_circuit_breaker=True,
)


async def get_resilient_llm_call(llm_func: Callable[[], Awaitable[T]]) -> T:
    """
    带容错能力的LLM调用

    Args:
        llm_func: LLM调用函数

    Returns:
        LLM响应结果
    """
    return await resilient_call(
        llm_func,
        config=LLM_RESILIENT_CONFIG,
        operation_name="llm_call",
    )


async def get_resilient_tool_call(tool_func: Callable[[], Awaitable[T]], tool_name: str = "tool") -> T:
    """
    带容错能力的工具调用

    Args:
        tool_func: 工具调用函数
        tool_name: 工具名称

    Returns:
        工具执行结果
    """
    return await resilient_call(
        tool_func,
        config=TOOL_RESILIENT_CONFIG,
        operation_name=f"tool_{tool_name}",
    )


# 导入dataclass
from dataclasses import dataclass
