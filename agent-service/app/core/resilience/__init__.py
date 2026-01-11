"""
容错和弹性模块

提供重试、熔断器、速率限制等容错机制
"""
from .retry import (
    BackoffStrategy,
    RetryConfig,
    RetryResult,
    LLM_RETRY_CONFIG,
    TOOL_RETRY_CONFIG,
    NO_RETRY_CONFIG,
    retry_with_backoff,
    retry_with_result,
    with_retry,
    RetryContext,
)
from .circuit_breaker import (
    CircuitState,
    CircuitOpenError,
    CircuitBreakerConfig,
    CircuitStats,
    CircuitBreaker,
    CircuitBreakerRegistry,
    get_circuit_registry,
    get_circuit,
    get_llm_circuit,
    get_tool_circuit,
    with_circuit_breaker,
)
from .rate_limiter import (
    RateLimiterConfig,
    RateLimiter,
    RateLimiterRegistry,
    get_rate_limiter_registry,
    get_rate_limiter,
    get_llm_rate_limiter,
    get_tool_rate_limiter,
    get_api_rate_limiter,
    LLM_RATE_LIMITER,
    TOOL_RATE_LIMITER,
    API_RATE_LIMITER,
)

__all__ = [
    # Retry
    "BackoffStrategy",
    "RetryConfig",
    "RetryResult",
    "LLM_RETRY_CONFIG",
    "TOOL_RETRY_CONFIG",
    "NO_RETRY_CONFIG",
    "retry_with_backoff",
    "retry_with_result",
    "with_retry",
    "RetryContext",
    # Circuit Breaker
    "CircuitState",
    "CircuitOpenError",
    "CircuitBreakerConfig",
    "CircuitStats",
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "get_circuit_registry",
    "get_circuit",
    "get_llm_circuit",
    "get_tool_circuit",
    "with_circuit_breaker",
    # Rate Limiter
    "RateLimiterConfig",
    "RateLimiter",
    "RateLimiterRegistry",
    "get_rate_limiter_registry",
    "get_rate_limiter",
    "get_llm_rate_limiter",
    "get_tool_rate_limiter",
    "get_api_rate_limiter",
    "LLM_RATE_LIMITER",
    "TOOL_RATE_LIMITER",
    "API_RATE_LIMITER",
]
