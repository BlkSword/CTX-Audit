"""
错误分类器单元测试
"""
import pytest
import asyncio

from app.core.error_classifier import (
    ErrorCategory,
    ErrorSeverity,
    RecoveryAction,
    ErrorClassification,
    ErrorClassifier,
    ErrorHandler,
    get_error_handler,
    with_error_handling,
)


class TestErrorClassifier:
    """ErrorClassifier 测试"""

    def test_classify_rate_limit(self):
        """测试速率限制错误分类"""
        errors = [
            "Rate limit exceeded",
            "Too many requests",
            "429 Too Many Requests",
            "rate_limit_exceeded",
        ]

        for error_msg in errors:
            classification = ErrorClassifier.classify(error_msg)
            assert classification.category == ErrorCategory.RATE_LIMIT
            assert classification.action in [RecoveryAction.RETRY_WITH_BACKOFF, RecoveryAction.WAIT]

    def test_classify_quota_exceeded(self):
        """测试配额用尽错误分类"""
        errors = [
            "API quota exceeded",
            "Insufficient credits",
            "Billing required",
            "Usage limit reached",
        ]

        for error_msg in errors:
            classification = ErrorClassifier.classify(error_msg)
            assert classification.category == ErrorCategory.QUOTA_EXCEEDED
            assert classification.action == RecoveryAction.ABORT
            assert classification.severity == ErrorSeverity.CRITICAL

    def test_classify_connection_error(self):
        """测试连接错误分类"""
        errors = [
            "Connection refused",
            "Network unreachable",
            "DNS resolution failed",
        ]

        for error_msg in errors:
            classification = ErrorClassifier.classify(error_msg)
            assert classification.category == ErrorCategory.CONNECTION_ERROR
            assert classification.action == RecoveryAction.RETRY_WITH_BACKOFF

    def test_classify_timeout(self):
        """测试超时错误分类"""
        errors = [
            "Request timeout",
            "Connection timed out",
            "Deadline exceeded",
        ]

        for error_msg in errors:
            classification = ErrorClassifier.classify(error_msg)
            assert classification.category == ErrorCategory.TIMEOUT

    def test_classify_auth_error(self):
        """测试认证错误分类"""
        errors = [
            "Unauthorized",
            "Invalid API key",
            "403 Forbidden",
            "Authentication failed",
        ]

        for error_msg in errors:
            classification = ErrorClassifier.classify(error_msg)
            assert classification.category == ErrorCategory.AUTH_ERROR
            assert classification.action == RecoveryAction.ABORT
            assert classification.severity == ErrorSeverity.CRITICAL

    def test_classify_unknown_error(self):
        """测试未知错误分类"""
        classification = ErrorClassifier.classify("Some unknown error")
        assert classification.category == ErrorCategory.UNKNOWN

    def test_max_retries(self):
        """测试最大重试次数"""
        # Rate limit 应该有更多重试
        classification = ErrorClassifier.classify("Rate limit exceeded")
        assert classification.max_retries == 5

        # Connection error 应该有较少重试
        classification = ErrorClassifier.classify("Connection failed")
        assert classification.max_retries == 3

    def test_backoff_base(self):
        """测试退避基数"""
        classification = ErrorClassifier.classify("Rate limit exceeded")
        assert classification.backoff_base == 2.0


class TestErrorHandler:
    """ErrorHandler 测试"""

    @pytest.mark.asyncio
    async def test_handle_rate_limit(self):
        """测试处理速率限制"""
        handler = ErrorHandler()

        should_retry, wait_time = await handler.handle(
            Exception("Rate limit exceeded"),
            operation_id="test_op",
        )

        assert should_retry is True
        assert wait_time is not None
        assert wait_time > 0

    @pytest.mark.asyncio
    async def test_handle_quota_exceeded(self):
        """测试处理配额用尽"""
        handler = ErrorHandler()

        should_retry, wait_time = await handler.handle(
            Exception("API quota exceeded"),
            operation_id="test_op",
        )

        assert should_retry is False
        assert wait_time is None

    @pytest.mark.asyncio
    async def test_max_retries_exceeded(self):
        """测试超过最大重试次数"""
        handler = ErrorHandler()
        operation_id = "test_op"

        # 第一次重试
        should_retry, _ = await handler.handle(
            Exception("Rate limit exceeded"),
            operation_id=operation_id,
        )
        assert should_retry is True

        # 重试 6 次（超过最大值 5）
        for i in range(6):
            should_retry, _ = await handler.handle(
                Exception("Rate limit exceeded"),
                operation_id=operation_id,
            )

        # 第 6 次应该拒绝重试
        assert should_retry is False

    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """测试指数退避"""
        handler = ErrorHandler()
        operation_id = "test_backoff"

        wait_times = []
        for i in range(3):
            _, wait_time = await handler.handle(
                Exception("Connection failed"),
                operation_id=operation_id,
            )
            wait_times.append(wait_time)

        # 验证退避时间递增
        assert wait_times[0] < wait_times[1] < wait_times[2]

    def test_reset(self):
        """测试重置"""
        handler = ErrorHandler()
        operation_id = "test_reset"

        # 添加重试计数
        handler.retry_count[operation_id] = 3

        # 重置
        handler.reset(operation_id)

        # 验证重置
        assert operation_id not in handler.retry_count


class TestWithErrorHandling:
    """with_error_handling 装饰器测试"""

    @pytest.mark.asyncio
    async def test_successful_execution(self):
        """测试成功执行"""
        handler = ErrorHandler()

        @with_error_handling(handler, operation_id="test_op")
        async def test_function():
            return "success"

        result = await test_function()
        assert result == "success"

    @pytest.mark.asyncio
    async def test_retry_on_recovery_error(self):
        """测试可恢复错误的重试"""
        handler = ErrorHandler()
        call_count = 0

        @with_error_handling(handler, operation_id="test_retry")
        async def failing_function():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise Exception("Rate limit exceeded")
            return "success"

        result = await failing_function()
        assert result == "success"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_abort_on_critical_error(self):
        """测试严重错误终止"""
        handler = ErrorHandler()

        @with_error_handling(handler, operation_id="test_abort")
        async def failing_function():
            raise Exception("API quota exceeded")

        with pytest.raises(Exception, match="API quota exceeded"):
            await failing_function()


class TestGlobalErrorHandler:
    """全局错误处理器测试"""

    def test_get_singleton(self):
        """测试获取单例"""
        handler1 = get_error_handler()
        handler2 = get_error_handler()

        assert handler1 is handler2


class TestErrorClassification:
    """ErrorClassification 数据类测试"""

    def test_create_classification(self):
        """测试创建分类"""
        classification = ErrorClassification(
            category=ErrorCategory.RATE_LIMIT,
            severity=ErrorSeverity.MEDIUM,
            action=RecoveryAction.RETRY_WITH_BACKOFF,
            message="Rate limit exceeded",
            retry_after=60,
            max_retries=5,
            backoff_base=2.0,
        )

        assert classification.category == ErrorCategory.RATE_LIMIT
        assert classification.severity == ErrorSeverity.MEDIUM
        assert classification.action == RecoveryAction.RETRY_WITH_BACKOFF
        assert classification.retry_after == 60
        assert classification.max_retries == 5
        assert classification.backoff_base == 2.0
