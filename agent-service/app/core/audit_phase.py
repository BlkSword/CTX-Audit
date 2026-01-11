"""
审计阶段管理模块

提供明确的审计阶段定义和进度权重系统
"""
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime
from loguru import logger


class AuditPhase(str, Enum):
    """审计阶段枚举"""
    # 初始化阶段
    INITIALIZATION = "initialization"
    # 规划阶段
    PLANNING = "planning"
    # 索引阶段（代码向量索引）
    INDEXING = "indexing"
    # 侦察阶段（项目结构分析）
    RECONNAISSANCE = "reconnaissance"
    # 分析阶段（漏洞检测）
    ANALYSIS = "analysis"
    # 验证阶段（漏洞验证）
    VERIFICATION = "verification"
    # 报告生成阶段
    REPORTING = "reporting"
    # 完成阶段
    COMPLETE = "complete"
    # 失败阶段
    FAILED = "failed"
    # 取消阶段
    CANCELLED = "cancelled"


# 阶段权重配置（用于计算整体进度）
PHASE_WEIGHTS: Dict[AuditPhase, float] = {
    AuditPhase.INITIALIZATION: 2,      # 2% - 初始化
    AuditPhase.PLANNING: 3,            # 3% - 规划
    AuditPhase.INDEXING: 10,           # 10% - 索引
    AuditPhase.RECONNAISSANCE: 15,     # 15% - 侦察
    AuditPhase.ANALYSIS: 50,           # 50% - 分析（最重要）
    AuditPhase.VERIFICATION: 15,       # 15% - 验证
    AuditPhase.REPORTING: 5,           # 5% - 报告
    AuditPhase.COMPLETE: 0,            # 0% - 完成标记
    AuditPhase.FAILED: 0,
    AuditPhase.CANCELLED: 0,
}


# 阶段显示配置
PHASE_DISPLAY_CONFIG: Dict[AuditPhase, Dict[str, Any]] = {
    AuditPhase.INITIALIZATION: {
        "label": "初始化",
        "icon": "🚀",
        "description": "初始化审计环境",
        "color": "#6b7280",  # gray
    },
    AuditPhase.PLANNING: {
        "label": "规划",
        "icon": "📋",
        "description": "制定审计策略",
        "color": "#3b82f6",  # blue
    },
    AuditPhase.INDEXING: {
        "label": "索引",
        "icon": "📚",
        "description": "构建代码向量索引",
        "color": "#8b5cf6",  # violet
    },
    AuditPhase.RECONNAISSANCE: {
        "label": "侦察",
        "icon": "🔍",
        "description": "分析项目结构和技术栈",
        "color": "#06b6d4",  # cyan
    },
    AuditPhase.ANALYSIS: {
        "label": "分析",
        "icon": "🔬",
        "description": "深度代码审计和漏洞检测",
        "color": "#f59e0b",  # amber
    },
    AuditPhase.VERIFICATION: {
        "label": "验证",
        "icon": "✅",
        "description": "验证发现的漏洞",
        "color": "#10b981",  # emerald
    },
    AuditPhase.REPORTING: {
        "label": "报告",
        "icon": "📊",
        "description": "生成审计报告",
        "color": "#ec4899",  # pink
    },
    AuditPhase.COMPLETE: {
        "label": "完成",
        "icon": "✨",
        "description": "审计完成",
        "color": "#10b981",  # emerald
    },
    AuditPhase.FAILED: {
        "label": "失败",
        "icon": "❌",
        "description": "审计失败",
        "color": "#ef4444",  # red
    },
    AuditPhase.CANCELLED: {
        "label": "已取消",
        "icon": "⏹️",
        "description": "审计已取消",
        "color": "#6b7280",  # gray
    },
}


@dataclass
class PhaseProgress:
    """阶段进度"""
    phase: AuditPhase
    progress: float = 0.0  # 0.0 - 1.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    message: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    @property
    def is_complete(self) -> bool:
        """阶段是否完成"""
        return self.progress >= 1.0

    @property
    def duration_seconds(self) -> Optional[float]:
        """阶段持续时间（秒）"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class AuditPhaseManager:
    """审计阶段管理器"""

    # 定义阶段转换规则
    VALID_TRANSITIONS: Dict[AuditPhase, List[AuditPhase]] = {
        AuditPhase.INITIALIZATION: [AuditPhase.PLANNING, AuditPhase.FAILED],
        AuditPhase.PLANNING: [AuditPhase.INDEXING, AuditPhase.RECONNAISSANCE, AuditPhase.FAILED],
        AuditPhase.INDEXING: [AuditPhase.RECONNAISSANCE, AuditPhase.FAILED],
        AuditPhase.RECONNAISSANCE: [AuditPhase.ANALYSIS, AuditPhase.FAILED],
        AuditPhase.ANALYSIS: [AuditPhase.VERIFICATION, AuditPhase.REPORTING, AuditPhase.COMPLETE, AuditPhase.FAILED],
        AuditPhase.VERIFICATION: [AuditPhase.ANALYSIS, AuditPhase.REPORTING, AuditPhase.COMPLETE, AuditPhase.FAILED],
        AuditPhase.REPORTING: [AuditPhase.COMPLETE, AuditPhase.FAILED],
        AuditPhase.COMPLETE: [],  # 终态
        AuditPhase.FAILED: [],    # 终态
        AuditPhase.CANCELLED: [], # 终态
    }

    def __init__(self):
        self._current_phase: AuditPhase = AuditPhase.INITIALIZATION
        self._phase_history: List[PhaseProgress] = []
        self._current_progress: Optional[PhaseProgress] = None

    @property
    def current_phase(self) -> AuditPhase:
        """当前阶段"""
        return self._current_phase

    @property
    def phase_history(self) -> List[PhaseProgress]:
        """阶段历史"""
        return self._phase_history.copy()

    def get_phase_info(self, phase: AuditPhase) -> Dict[str, Any]:
        """获取阶段信息"""
        config = PHASE_DISPLAY_CONFIG.get(phase, PHASE_DISPLAY_CONFIG[AuditPhase.INITIALIZATION])
        return {
            "phase": phase.value,
            "weight": PHASE_WEIGHTS.get(phase, 0),
            **config,
        }

    def can_transition_to(self, new_phase: AuditPhase) -> bool:
        """检查是否可以转换到新阶段"""
        valid_phases = self.VALID_TRANSITIONS.get(self._current_phase, [])
        return new_phase in valid_phases

    async def transition_to(
        self,
        new_phase: AuditPhase,
        message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        转换到新阶段

        Args:
            new_phase: 新阶段
            message: 阶段消息
            metadata: 阶段元数据
        """
        # 如果已经在目标阶段，只更新消息
        if self._current_phase == new_phase:
            if self._current_progress and message:
                self._current_progress.message = message
            if self._current_progress and metadata:
                self._current_progress.metadata.update(metadata)
            return

        # 验证转换
        if not self.can_transition_to(new_phase):
            raise ValueError(
                f"Cannot transition from {self._current_phase.value} to {new_phase.value}"
            )

        # 完成当前阶段
        if self._current_progress:
            self._current_progress.progress = 1.0
            self._current_progress.completed_at = datetime.now()
            self._phase_history.append(self._current_progress)

        # 开始新阶段
        self._current_phase = new_phase
        self._current_progress = PhaseProgress(
            phase=new_phase,
            started_at=datetime.now(),
            message=message,
            metadata=metadata or {},
        )

        phase_info = self.get_phase_info(new_phase)
        logger.info(
            f"Phase transition: {phase_info['icon']} {self._current_phase.value} - {message or phase_info['description']}"
        )

    def update_progress(
        self,
        progress: float,
        message: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        更新当前阶段进度

        Args:
            progress: 进度值 0.0 - 1.0
            message: 进度消息
            metadata: 元数据
        """
        if self._current_progress:
            self._current_progress.progress = max(0.0, min(1.0, progress))
            if message:
                self._current_progress.message = message
            if metadata:
                self._current_progress.metadata.update(metadata)

    def calculate_overall_progress(self) -> float:
        """
        计算整体进度

        Returns:
            整体进度百分比 (0-100)
        """
        # 已完成的阶段权重总和
        completed_weight = sum(
            PHASE_WEIGHTS.get(p.phase, 0)
            for p in self._phase_history
        )

        # 当前阶段的权重 * 进度
        current_weight = 0
        if self._current_progress and self._current_phase != AuditPhase.COMPLETE:
            current_weight = PHASE_WEIGHTS.get(self._current_phase, 0) * self._current_progress.progress

        # 总权重
        total_weight = sum(PHASE_WEIGHTS.values())

        # 计算百分比
        if total_weight > 0:
            percentage = (completed_weight + current_weight) / total_weight * 100
            return min(100.0, max(0.0, percentage))

        return 0.0

    def get_status(self) -> Dict[str, Any]:
        """
        获取阶段状态

        Returns:
            包含当前阶段、进度、历史等信息的字典
        """
        return {
            "current_phase": self.current_phase.value,
            "current_phase_info": self.get_phase_info(self._current_phase),
            "current_progress": self._current_progress.progress if self._current_progress else 0.0,
            "current_message": self._current_progress.message if self._current_progress else "",
            "overall_progress": self.calculate_overall_progress(),
            "phase_history": [
                {
                    "phase": p.phase.value,
                    "progress": p.progress,
                    "started_at": p.started_at.isoformat() if p.started_at else None,
                    "completed_at": p.completed_at.isoformat() if p.completed_at else None,
                    "message": p.message,
                    "duration_seconds": p.duration_seconds,
                }
                for p in self._phase_history
            ],
        }

    def mark_failed(self, error: str) -> None:
        """标记审计失败"""
        if self._current_progress:
            self._current_progress.message = error

        # 清理未完成的进度
        self._current_progress = None

        # 转换到失败阶段
        self._current_phase = AuditPhase.FAILED
        logger.error(f"Audit marked as failed: {error}")

    def mark_cancelled(self) -> None:
        """标记审计取消"""
        if self._current_progress:
            self._current_progress.message = "审计已取消"

        # 清理未完成的进度
        self._current_progress = None

        # 转换到取消阶段
        self._current_phase = AuditPhase.CANCELLED
        logger.info("Audit marked as cancelled")

    def mark_complete(self) -> None:
        """标记审计完成"""
        if self._current_progress:
            self._current_progress.progress = 1.0
            self._current_progress.completed_at = datetime.now()
            self._current_progress.message = "审计完成"
            self._phase_history.append(self._current_progress)
            self._current_progress = None

        # 转换到完成阶段
        self._current_phase = AuditPhase.COMPLETE
        logger.info("Audit marked as complete")

    async def initialize(self) -> None:
        """初始化阶段管理器"""
        await self.transition_to(
            AuditPhase.INITIALIZATION,
            message="审计初始化中...",
        )
        await self.transition_to(
            AuditPhase.PLANNING,
            message="审计规划中...",
        )


# 便捷函数
def create_phase_manager() -> AuditPhaseManager:
    """创建阶段管理器实例"""
    return AuditPhaseManager()


# 全局阶段管理器存储（按 audit_id 管理）
_phase_managers: Dict[str, AuditPhaseManager] = {}


def get_phase_manager(audit_id: str) -> AuditPhaseManager:
    """
    获取指定审计的阶段管理器

    Args:
        audit_id: 审计 ID

    Returns:
        阶段管理器实例（如果不存在则创建）
    """
    if audit_id not in _phase_managers:
        _phase_managers[audit_id] = AuditPhaseManager()
        logger.debug(f"Created phase manager for audit: {audit_id}")
    return _phase_managers[audit_id]


def remove_phase_manager(audit_id: str) -> None:
    """
    移除指定审计的阶段管理器

    Args:
        audit_id: 审计 ID
    """
    if audit_id in _phase_managers:
        del _phase_managers[audit_id]
        logger.debug(f"Removed phase manager for audit: {audit_id}")
