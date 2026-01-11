"""
监控和可观测性模块

提供指标收集、性能监控、错误统计等功能
"""
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict
from datetime import datetime, timedelta
from loguru import logger
import asyncio


class MetricType(str, Enum):
    """指标类型"""
    COUNTER = "counter"      # 计数器（只增不减）
    GAUGE = "gauge"          # 仪表（可增可减）
    HISTOGRAM = "histogram"  # 直方图（分布统计）
    SUMMARY = "summary"      # 摘要（百分位数）


@dataclass
class Metric:
    """基础指标"""
    name: str
    type: MetricType
    value: float = 0.0
    timestamp: float = field(default_factory=time.time)
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "type": self.type.value,
            "value": self.value,
            "timestamp": self.timestamp,
            "labels": self.labels,
            "metadata": self.metadata,
        }


@dataclass
class HistogramBucket:
    """直方图桶"""
    count: int = 0
    sum: float = 0.0


@dataclass
class Histogram:
    """直方图指标（用于统计分布）"""
    name: str
    buckets: List[float] = field(default_factory=list)  # 桶边界
    bucket_counts: List[int] = field(default_factory=list)  # 桶计数
    count: int = 0  # 总计数
    sum: float = 0.0  # 总和
    min: float = float('inf')  # 最小值
    max: float = float('-inf')  # 最大值

    def __post_init__(self):
        if not self.buckets:
            # 默认桶边界
            self.buckets = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        if len(self.bucket_counts) != len(self.buckets):
            self.bucket_counts = [0] * len(self.buckets)

    def observe(self, value: float) -> None:
        """观察一个值"""
        self.count += 1
        self.sum += value
        self.min = min(self.min, value)
        self.max = max(self.max, value)

        # 更新桶计数
        for i, boundary in enumerate(self.buckets):
            if value <= boundary:
                self.bucket_counts[i] += 1
                break

    def get_percentile(self, percentile: float) -> float:
        """获取百分位数"""
        if self.count == 0:
            return 0.0

        target_count = int(self.count * percentile / 100)
        cumulative = 0

        for i, boundary in enumerate(self.buckets):
            cumulative += self.bucket_counts[i]
            if cumulative >= target_count:
                return boundary

        return self.buckets[-1] if self.buckets else 0.0

    def get_average(self) -> float:
        """获取平均值"""
        return self.sum / self.count if self.count > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "count": self.count,
            "sum": self.sum,
            "average": self.get_average(),
            "min": self.min if self.min != float('inf') else 0,
            "max": self.max if self.max != float('-inf') else 0,
            "p50": self.get_percentile(50),
            "p95": self.get_percentile(95),
            "p99": self.get_percentile(99),
            "buckets": self.buckets,
            "bucket_counts": self.bucket_counts,
        }


class MetricsRegistry:
    """指标注册表"""

    def __init__(self):
        self._counters: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._gauges: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._histograms: Dict[str, Histogram] = {}

    def counter(
        self,
        name: str,
        value: float = 1.0,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        计数器操作

        Args:
            name: 指标名称
            value: 增加的值（默认为 1）
            labels: 标签
        """
        key = self._make_key(labels)
        self._counters[name][key] += value

    def gauge(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        仪表操作

        Args:
            name: 指标名称
            value: 设置的值
            labels: 标签
        """
        key = self._make_key(labels)
        self._gauges[name][key] = value

    def histogram(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        直方图操作

        Args:
            name: 指标名称
            value: 观察的值
            labels: 标签
        """
        key = self._make_key(labels)
        if key not in self._histograms:
            self._histograms[key] = Histogram(name=name)
        self._histograms[key].observe(value)

    def _make_key(self, labels: Optional[Dict[str, str]]) -> str:
        """生成标签键"""
        if not labels:
            return ""
        items = sorted(labels.items())
        return ",".join(f"{k}={v}" for k, v in items)

    def get_metrics(self) -> Dict[str, Any]:
        """获取所有指标"""
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                key: hist.to_dict()
                for key, hist in self._histograms.items()
            },
        }


class PerformanceTracker:
    """性能追踪器"""

    def __init__(self, registry: Optional[MetricsRegistry] = None):
        self.registry = registry or MetricsRegistry()
        self._active_spans: Dict[str, Any] = {}

    def start_span(
        self,
        name: str,
        labels: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        开始一个追踪跨度

        Args:
            name: 跨度名称
            labels: 标签

        Returns:
            跨度 ID
        """
        span_id = f"{name}_{id(self)}_{time.time()}"
        self._active_spans[span_id] = {
            "name": name,
            "start_time": time.time(),
            "labels": labels or {},
        }
        return span_id

    def end_span(
        self,
        span_id: str,
        success: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[float]:
        """
        结束一个追踪跨度

        Args:
            span_id: 跨度 ID
            success: 是否成功
            metadata: 元数据

        Returns:
            持续时间（秒）
        """
        span = self._active_spans.pop(span_id, None)
        if not span:
            return None

        duration = time.time() - span["start_time"]

        # 记录指标
        labels = span["labels"]
        labels["success"] = str(success)

        self.histogram(
            f"{span['name']}_duration",
            duration,
            labels,
        )
        self.counter(
            f"{span['name']}_total",
            1.0,
            labels,
        )

        if not success:
            self.counter(
                f"{span['name']}_errors",
                1.0,
                labels,
            )

        return duration


class ErrorTracker:
    """错误追踪器"""

    def __init__(self, registry: Optional[MetricsRegistry] = None):
        self.registry = registry or MetricsRegistry()
        self._errors: List[Dict[str, Any]] = []
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def record_error(
        self,
        error: Exception,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        记录错误

        Args:
            error: 错误对象
            context: 错误上下文
        """
        error_type = type(error).__name__
        error_msg = str(error)

        async with self._lock:
            self._error_counts[error_type] += 1
            self._errors.append({
                "type": error_type,
                "message": error_msg,
                "context": context or {},
                "timestamp": datetime.now().isoformat(),
            })

        # 更新指标
        self.registry.counter(
            "errors_total",
            1.0,
            {"error_type": error_type},
        )

    def get_error_stats(self) -> Dict[str, Any]:
        """获取错误统计"""
        total_errors = sum(self._error_counts.values())

        # 按类型分组
        by_type = {
            error_type: {
                "count": count,
                "percentage": count / total_errors * 100 if total_errors > 0 else 0,
            }
            for error_type, count in self._error_counts.items()
        }

        # 最近的错误
        recent_errors = sorted(
            self._errors,
            key=lambda e: e["timestamp"],
            reverse=True,
        )[:100]

        return {
            "total_errors": total_errors,
            "by_type": by_type,
            "recent_errors": recent_errors,
        }

    def clear_old_errors(self, older_than: timedelta = timedelta(hours=1)) -> None:
        """清理旧错误"""
        cutoff = datetime.now() - older_than
        self._errors = [
            e for e in self._errors
            if datetime.fromisoformat(e["timestamp"]) > cutoff
        ]


class MonitoringSystem:
    """监控系统（整合所有监控功能）"""

    def __init__(self):
        self.registry = MetricsRegistry()
        self.performance = PerformanceTracker(self.registry)
        self.errors = ErrorTracker(self.registry)
        self._start_time = time.time()

    def get_status(self) -> Dict[str, Any]:
        """获取监控系统状态"""
        uptime = time.time() - self._start_time

        return {
            "uptime_seconds": uptime,
            "metrics": self.registry.get_metrics(),
            "error_stats": self.errors.get_error_stats(),
            "timestamp": datetime.now().isoformat(),
        }

    async def record_llm_call(
        self,
        model: str,
        tokens_used: int,
        duration: float,
        success: bool = True,
        error: Optional[Exception] = None,
    ) -> None:
        """
        记录 LLM 调用

        Args:
            model: 模型名称
            tokens_used: 使用的 token 数
            duration: 持续时间（秒）
            success: 是否成功
            error: 错误对象
        """
        labels = {"model": model}

        # 记录指标
        self.registry.histogram("llm_duration", duration, labels)
        self.registry.histogram("llm_tokens", tokens_used, labels)
        self.registry.counter("llm_calls_total", 1.0, labels)
        self.registry.counter("llm_tokens_total", float(tokens_used), labels)

        if not success and error:
            await self.errors.record_error(error, {"model": model})
            self.registry.counter("llm_errors_total", 1.0, labels)

    async def record_tool_call(
        self,
        tool_name: str,
        duration: float,
        success: bool = True,
        error: Optional[Exception] = None,
    ) -> None:
        """
        记录工具调用

        Args:
            tool_name: 工具名称
            duration: 持续时间（秒）
            success: 是否成功
            error: 错误对象
        """
        labels = {"tool": tool_name}

        self.registry.histogram("tool_duration", duration, labels)
        self.registry.counter("tool_calls_total", 1.0, labels)

        if not success and error:
            await self.errors.record_error(error, {"tool": tool_name})
            self.registry.counter("tool_errors_total", 1.0, labels)

    def record_agent_execution(
        self,
        agent_type: str,
        duration: float,
        iterations: int,
        findings_count: int,
        success: bool = True,
    ) -> None:
        """
        记录 Agent 执行

        Args:
            agent_type: Agent 类型
            duration: 持续时间（秒）
            iterations: 迭代次数
            findings_count: 发现数
            success: 是否成功
        """
        labels = {"agent_type": agent_type}

        self.registry.histogram("agent_duration", duration, labels)
        self.registry.histogram("agent_iterations", iterations, labels)
        self.registry.counter("agent_findings", float(findings_count), labels)
        self.registry.counter("agent_executions_total", 1.0, labels)


# 全局监控系统实例
_monitoring_system: Optional[MonitoringSystem] = None


def get_monitoring_system() -> MonitoringSystem:
    """获取全局监控系统实例"""
    global _monitoring_system
    if _monitoring_system is None:
        _monitoring_system = MonitoringSystem()
    return _monitoring_system
