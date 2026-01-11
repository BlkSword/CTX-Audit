"""
错误分类处理器

智能识别和处理不同类型的错误，提供针对性的恢复策略。
支持：
- API 错误分类（Rate limit, Quota exceeded, Connection error, Timeout 等）
- 自动重试策略（指数退避）
- 降级处理
- 错误上报和恢复建议

参考 DeepAudit-3.0.0 实现
"""
import asyncio
import re
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass
from loguru import logger


class ErrorCategory(str, Enum):
    """错误类别"""
    # API 错误
    RATE_LIMIT = "rate_limit"           # 速率限制
    QUOTA_EXCEEDED = "quota_exceeded"   # 配额用尽
    CONNECTION_ERROR = "connection"     # 连接错误
    TIMEOUT = "timeout"                 # 超时
    INVALID_REQUEST = "invalid_request" # 无效请求
    AUTH_ERROR = "auth"                 # 认证错误

    # LLM 错误
    LLM_OVERLOADED = "llm_overloaded"   # LLM 服务过载
    CONTENT_FILTERED = "content_filtered" # 内容被过滤

    # 工具错误
    TOOL_ERROR = "tool_error"           # 工具执行错误
    TOOL_TIMEOUT = "tool_timeout"       # 工具超时

    # 系统错误
    INSUFFICIENT_RESOURCES = "resources" # 资源不足
    DISK_SPACE = "disk_space"           # 磁盘空间不足

    # 未知错误
    UNKNOWN = "unknown"


class ErrorSeverity(str, Enum):
    """错误严重程度"""
    LOW = "low"         # 轻微，可以继续
    MEDIUM = "medium"   # 中等，需要重试
    HIGH = "high"       # 严重，需要干预
    CRITICAL = "critical" # 致命，必须停止


class RecoveryAction(str, Enum):
    """恢复动作"""
    RETRY = "retry"                     # 重试
    RETRY_WITH_BACKOFF = "backoff"      # 指数退避重试
    SKIP = "skip"                       # 跳过
    FALLBACK = "fallback"               # 降级处理
    ABORT = "abort"                     # 中止
    REPORT = "report"                   # 仅报告
    WAIT = "wait"                       # 等待后重试


@dataclass
class ErrorClassification:
    """错误分类结果"""
    category: ErrorCategory
    severity: ErrorSeverity
    action: RecoveryAction
    message: str
    retry_after: Optional[float] = None  # 秒
    max_retries: int = 3
    backoff_base: float = 2.0  # 指数退避基数


class ErrorClassifier:
    """
    错误分类器

    根据错误信息智能分类错误，并提供处理建议
    """

    # 错误模式匹配规则
    PATTERNS = {
        # Rate limit 错误
        ErrorCategory.RATE_LIMIT: [
            r"rate limit",
            r"rate_limit",
            r"too many requests",
            r"429",
            r"ratelimit",
            r"requests? exceeded",
        ],

        # Quota exceeded 错误
        ErrorCategory.QUOTA_EXCEEDED: [
            r"quota",
            r"credit",
            r"balance.*insufficient",
            r"billing",
            r"payment",
            r"usage.*limit",
        ],

        # Connection error
        ErrorCategory.CONNECTION_ERROR: [
            r"connection",
            r"network",
            r"dns.*fail",
            r"host.*unreachable",
            r"refused",
        ],

        # Timeout
        ErrorCategory.TIMEOUT: [
            r"timeout",
            r"timed out",
            r"deadline.*exceed",
        ],

        # Invalid request
        ErrorCategory.INVALID_REQUEST: [
            r"invalid",
            r"malformed",
            r"bad request",
            r"400",
            r"parameter",
        ],

        # Authentication error
        ErrorCategory.AUTH_ERROR: [
            r"unauthorized",
            r"authentication",
            r"forbidden",
            r"401",
            r"403",
            r"api key",
            r"token.*invalid",
        ],

        # LLM overloaded
        ErrorCategory.LLM_OVERLOADED: [
            r"overload",
            r"service.*unavailable",
            r"503",
            r"502",
            r"maintenance",
        ],

        # Content filtered
        ErrorCategory.CONTENT_FILTERED: [
            r"content.*filter",
            r"safety",
            r"policy.*violation",
            r"inappropriate",
        ],

        # Tool error
        ErrorCategory.TOOL_ERROR: [
            r"tool.*fail",
            r"execution.*error",
            r"command.*fail",
        ],

        # Insufficient resources
        ErrorCategory.INSUFFICIENT_RESOURCES: [
            r"memory",
            r"out of memory",
            r"oom",
            r"resource",
        ],

        # Disk space
        ErrorCategory.DISK_SPACE: [
            r"disk.*full",
            r"no space",
            r"storage.*full",
        ],
    }

    @classmethod
    def classify(cls, error: Any, context: Optional[Dict[str, Any]] = None) -> ErrorClassification:
        """
        分类错误

        Args:
            error: 错误对象（可以是 Exception、str 或 dict）
            context: 额外的上下文信息

        Returns:
            错误分类结果
        """
        # 提取错误消息
        error_message = cls._extract_error_message(error)
        error_message_lower = error_message.lower()

        # 尝试匹配错误类别
        category = ErrorCategory.UNKNOWN
        for cat, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_message_lower):
                    category = cat
                    break
            if category != ErrorCategory.UNKNOWN:
                break

        # 确定严重程度和恢复动作
        severity, action, retry_after = cls._determine_severity_and_action(
            category, error_message, context
        )

        # 生成消息
        message = cls._generate_message(category, error_message)

        return ErrorClassification(
            category=category,
            severity=severity,
            action=action,
            message=message,
            retry_after=retry_after,
            max_retries=cls._get_max_retries(category),
            backoff_base=cls._get_backoff_base(category),
        )

    @classmethod
    def _extract_error_message(cls, error: Any) -> str:
        """提取错误消息"""
        if isinstance(error, str):
            return error
        elif isinstance(error, Exception):
            return str(error)
        elif isinstance(error, dict):
            return error.get("message", "") or error.get("error", "") or str(error)
        else:
            return str(error)

    @classmethod
    def _determine_severity_and_action(
        cls,
        category: ErrorCategory,
        error_message: str,
        context: Optional[Dict[str, Any]],
    ) -> Tuple[ErrorSeverity, RecoveryAction, Optional[float]]:
        """确定严重程度和恢复动作"""
        # 默认值
        severity = ErrorSeverity.MEDIUM
        action = RecoveryAction.RETRY
        retry_after = None

        if category == ErrorCategory.RATE_LIMIT:
            severity = ErrorSeverity.MEDIUM
            action = RecoveryAction.RETRY_WITH_BACKOFF
            # 尝试提取重试时间
            match = re.search(r"retry.*?after\s*:?\s*(\d+)", error_message, re.IGNORECASE)
            if match:
                retry_after = float(match.group(1))

        elif category == ErrorCategory.QUOTA_EXCEEDED:
            severity = ErrorSeverity.CRITICAL
            action = RecoveryAction.ABORT

        elif category == ErrorCategory.CONNECTION_ERROR:
            severity = ErrorSeverity.MEDIUM
            action = RecoveryAction.RETRY_WITH_BACKOFF

        elif category == ErrorCategory.TIMEOUT:
            severity = ErrorSeverity.MEDIUM
            action = RecoveryAction.RETRY_WITH_BACKOFF

        elif category == ErrorCategory.INVALID_REQUEST:
            severity = ErrorSeverity.HIGH
            action = RecoveryAction.REPORT  # 不重试，报告即可

        elif category == ErrorCategory.AUTH_ERROR:
            severity = ErrorSeverity.CRITICAL
            action = RecoveryAction.ABORT

        elif category == ErrorCategory.LLM_OVERLOADED:
            severity = ErrorSeverity.MEDIUM
            action = RecoveryAction.RETRY_WITH_BACKOFF

        elif category == ErrorCategory.CONTENT_FILTERED:
            severity = ErrorSeverity.LOW
            action = RecoveryAction.SKIP

        elif category == ErrorCategory.TOOL_ERROR:
            severity = ErrorSeverity.MEDIUM
            action = RecoveryAction.RETRY

        elif category == ErrorCategory.INSUFFICIENT_RESOURCES:
            severity = ErrorSeverity.HIGH
            action = RecoveryAction.FALLBACK

        elif category == ErrorCategory.DISK_SPACE:
            severity = ErrorSeverity.CRITICAL
            action = RecoveryAction.ABORT

        return severity, action, retry_after

    @classmethod
    def _generate_message(cls, category: ErrorCategory, error_message: str) -> str:
        """生成人类可读的错误消息"""
        messages = {
            ErrorCategory.RATE_LIMIT: f"API 速率限制：{error_message}",
            ErrorCategory.QUOTA_EXCEEDED: f"API 配额已用尽：{error_message}",
            ErrorCategory.CONNECTION_ERROR: f"网络连接错误：{error_message}",
            ErrorCategory.TIMEOUT: f"请求超时：{error_message}",
            ErrorCategory.INVALID_REQUEST: f"无效请求：{error_message}",
            ErrorCategory.AUTH_ERROR: f"认证失败：{error_message}",
            ErrorCategory.LLM_OVERLOADED: f"LLM 服务过载：{error_message}",
            ErrorCategory.CONTENT_FILTERED: f"内容被过滤：{error_message}",
            ErrorCategory.TOOL_ERROR: f"工具执行错误：{error_message}",
            ErrorCategory.INSUFFICIENT_RESOURCES: f"资源不足：{error_message}",
            ErrorCategory.DISK_SPACE: f"磁盘空间不足：{error_message}",
        }
        return messages.get(category, f"未知错误：{error_message}")

    @classmethod
    def _get_max_retries(cls, category: ErrorCategory) -> int:
        """获取最大重试次数"""
        retries = {
            ErrorCategory.RATE_LIMIT: 5,
            ErrorCategory.CONNECTION_ERROR: 3,
            ErrorCategory.TIMEOUT: 3,
            ErrorCategory.LLM_OVERLOADED: 4,
            ErrorCategory.TOOL_ERROR: 2,
        }
        return retries.get(category, 1)

    @classmethod
    def _get_backoff_base(cls, category: ErrorCategory) -> float:
        """获取指数退避基数"""
        bases = {
            ErrorCategory.RATE_LIMIT: 2.0,   # 2, 4, 8, 16, 32 秒
            ErrorCategory.CONNECTION_ERROR: 1.5,
            ErrorCategory.TIMEOUT: 1.5,
            ErrorCategory.LLM_OVERLOADED: 2.0,
        }
        return bases.get(category, 2.0)


class ErrorHandler:
    """
    错误处理器

    根据错误分类执行相应的恢复策略
    """

    def __init__(self, classifier: Optional[ErrorClassifier] = None):
        self.classifier = classifier or ErrorClassifier()
        self.retry_count: Dict[str, int] = {}
        self.last_retry_time: Dict[str, float] = {}

    async def handle(
        self,
        error: Any,
        context: Optional[Dict[str, Any]] = None,
        operation_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        处理错误

        Args:
            error: 错误对象
            context: 上下文信息
            operation_id: 操作 ID（用于追踪重试）

        Returns:
            (是否应该重试, 等待时间（秒）)
        """
        classification = self.classifier.classify(error, context)

        # 记录错误
        logger.warning(f"[ErrorHandler] {classification.message} "
                      f"(类别: {classification.category}, 动作: {classification.action})")

        # 根据动作决定处理方式
        if classification.action == RecoveryAction.RETRY:
            return self._should_retry(operation_id, classification), None

        elif classification.action == RecoveryAction.RETRY_WITH_BACKOFF:
            return self._should_retry_with_backoff(operation_id, classification)

        elif classification.action == RecoveryAction.SKIP:
            return False, None

        elif classification.action == RecoveryAction.ABORT:
            return False, None

        elif classification.action == RecoveryAction.REPORT:
            return False, None

        elif classification.action == RecoveryAction.FALLBACK:
            return False, None

        elif classification.action == RecoveryAction.WAIT:
            wait_time = classification.retry_after or 5.0
            return True, wait_time

        return False, None

    def _should_retry(self, operation_id: Optional[str], classification: ErrorClassification) -> bool:
        """判断是否应该重试"""
        if operation_id is None:
            return True

        current_retries = self.retry_count.get(operation_id, 0)
        if current_retries < classification.max_retries:
            self.retry_count[operation_id] = current_retries + 1
            return True
        return False

    def _should_retry_with_backoff(
        self,
        operation_id: Optional[str],
        classification: ErrorClassification,
    ) -> Tuple[bool, Optional[float]]:
        """判断是否应该指数退避重试"""
        if operation_id is None:
            return True, 1.0

        current_retries = self.retry_count.get(operation_id, 0)

        if current_retries >= classification.max_retries:
            return False, None

        # 计算退避时间
        backoff_time = (classification.backoff_base ** current_retries)
        if classification.retry_after:
            backoff_time = max(backoff_time, classification.retry_after)

        # 限制最大退避时间
        backoff_time = min(backoff_time, 60.0)

        self.retry_count[operation_id] = current_retries + 1
        self.last_retry_time[operation_id] = time.time()

        logger.info(f"[ErrorHandler] 指数退避重试 {current_retries + 1}/{classification.max_retries}，"
                   f"等待 {backoff_time:.1f} 秒")

        return True, backoff_time

    def reset(self, operation_id: Optional[str] = None) -> None:
        """重置重试计数"""
        if operation_id:
            self.retry_count.pop(operation_id, None)
            self.last_retry_time.pop(operation_id, None)
        else:
            self.retry_count.clear()
            self.last_retry_time.clear()


def with_error_handling(
    error_handler: ErrorHandler,
    operation_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
):
    """
    错误处理装饰器

    用法：
        @with_error_handling(error_handler, operation_id="my_operation")
        async def my_function():
            ...
    """
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            retries = 0
            max_retries = 5

            while retries < max_retries:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    should_retry, wait_time = await error_handler.handle(
                        e, context=context, operation_id=operation_id
                    )

                    if not should_retry:
                        raise

                    if wait_time:
                        await asyncio.sleep(wait_time)

                    retries += 1

            raise Exception(f"操作 {operation_id} 在 {max_retries} 次重试后仍然失败")

        return wrapper
    return decorator


# 全局单例
_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """获取错误处理器单例"""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler()
    return _error_handler
