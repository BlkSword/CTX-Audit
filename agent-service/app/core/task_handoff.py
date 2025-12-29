"""
任务交接协议 (TaskHandoff)

Agent 之间结构化的上下文传递协议
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import json


@dataclass
class TaskHandoff:
    """
    Agent 间任务交接协议

    用于在 Agent 之间传递结构化的上下文信息，而非简单的数据传递。
    """

    # 基本信息
    from_agent: str
    to_agent: str
    handoff_id: str = field(default_factory=lambda: f"handoff_{uuid.uuid4().hex[:8]}")

    # 工作摘要
    summary: str = ""
    work_completed: List[str] = field(default_factory=list)

    # 关键发现
    key_findings: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)

    # 建议和关注点
    suggested_actions: List[Dict[str, Any]] = field(default_factory=list)
    attention_points: List[str] = field(default_factory=list)
    priority_areas: List[str] = field(default_factory=list)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_prompt_context(self) -> str:
        """
        转换为 LLM 提示词上下文格式

        Returns:
            格式化的上下文字符串
        """
        lines = [
            f"## 📋 来自 {self.from_agent} Agent 的任务交接",
            "",
            "### 工作摘要",
            self.summary,
            "",
            "### 已完成工作",
        ]

        for work in self.work_completed:
            lines.append(f"- {work}")

        if self.key_findings:
            lines.extend([
                "",
                "### 关键发现",
            ])
            for i, finding in enumerate(self.key_findings, 1):
                lines.append(f"**{i}. {finding.get('title', 'Untitled')}**")
                lines.append(f"   - 类型: {finding.get('type', finding.get('vulnerability_type', 'unknown'))}")
                lines.append(f"   - 严重性: {finding.get('severity', 'unknown')}")
                location = finding.get('location') or finding.get('file_path')
                if location:
                    lines.append(f"   - 位置: {location}")

        if self.insights:
            lines.extend([
                "",
                "### 分析洞察",
            ])
            for insight in self.insights:
                lines.append(f"- {insight}")

        if self.suggested_actions:
            lines.extend([
                "",
                "### 建议的后续操作",
            ])
            for i, action in enumerate(self.suggested_actions, 1):
                lines.append(f"{i}. {action.get('description', 'Unnamed action')}")

        if self.attention_points:
            lines.extend([
                "",
                "### 建议后续关注",
            ])
            for point in self.attention_points:
                lines.append(f"⚠️ {point}")

        if self.priority_areas:
            lines.extend([
                "",
                "### 优先处理区域",
            ])
            for area in self.priority_areas:
                lines.append(f"🔴 {area}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "handoff_id": self.handoff_id,
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "summary": self.summary,
            "work_completed": self.work_completed,
            "key_findings": self.key_findings,
            "insights": self.insights,
            "suggested_actions": self.suggested_actions,
            "attention_points": self.attention_points,
            "priority_areas": self.priority_areas,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskHandoff":
        """从字典创建"""
        return cls(
            from_agent=data["from_agent"],
            to_agent=data["to_agent"],
            handoff_id=data.get("handoff_id"),
            summary=data.get("summary", ""),
            work_completed=data.get("work_completed", []),
            key_findings=data.get("key_findings", []),
            insights=data.get("insights", []),
            suggested_actions=data.get("suggested_actions", []),
            attention_points=data.get("attention_points", []),
            priority_areas=data.get("priority_areas", []),
            metadata=data.get("metadata", {}),
            timestamp=data.get("timestamp"),
        )

    @classmethod
    def from_agent_result(
        cls,
        from_agent: str,
        to_agent: str,
        result: Dict[str, Any],
    ) -> "TaskHandoff":
        """
        从 Agent 执行结果创建交接协议

        Args:
            from_agent: 源 Agent 名称
            to_agent: 目标 Agent 名称
            result: Agent 执行结果

        Returns:
            TaskHandoff 实例
        """
        findings = result.get("findings", [])
        if isinstance(findings, dict):
            findings = []

        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            summary=result.get("summary", f"{from_agent} 完成任务"),
            work_completed=result.get("work_completed", []),
            key_findings=findings[:10],  # 最多传递 10 个关键发现
            insights=result.get("insights", []),
            suggested_actions=result.get("suggested_actions", []),
            attention_points=result.get("attention_points", []),
            priority_areas=result.get("priority_areas", []),
            metadata=result.get("metadata", {}),
        )


class TaskHandoffBuilder:
    """任务交接构建器"""

    def __init__(
        self,
        from_agent: str,
        to_agent: str,
    ):
        self.from_agent = from_agent
        self.to_agent = to_agent
        self._summary = ""
        self._work_completed = []
        self._key_findings = []
        self._insights = []
        self._suggested_actions = []
        self._attention_points = []
        self._priority_areas = []
        self._metadata = {}

    def summary(self, text: str) -> "TaskHandoffBuilder":
        """设置摘要"""
        self._summary = text
        return self

    def add_work(self, work: str) -> "TaskHandoffBuilder":
        """添加完成的工作"""
        self._work_completed.append(work)
        return self

    def add_finding(self, finding: Dict[str, Any]) -> "TaskHandoffBuilder":
        """添加关键发现"""
        self._key_findings.append(finding)
        return self

    def add_insight(self, insight: str) -> "TaskHandoffBuilder":
        """添加洞察"""
        self._insights.append(insight)
        return self

    def add_attention(self, point: str) -> "TaskHandoffBuilder":
        """添加关注点"""
        self._attention_points.append(point)
        return self

    def add_priority(self, area: str) -> "TaskHandoffBuilder":
        """添加优先区域"""
        self._priority_areas.append(area)
        return self

    def metadata(self, key: str, value: Any) -> "TaskHandoffBuilder":
        """添加元数据"""
        self._metadata[key] = value
        return self

    def build(self) -> TaskHandoff:
        """构建 TaskHandoff"""
        return TaskHandoff(
            from_agent=self.from_agent,
            to_agent=self.to_agent,
            summary=self._summary,
            work_completed=self._work_completed,
            key_findings=self._key_findings,
            insights=self._insights,
            suggested_actions=self._suggested_actions,
            attention_points=self._attention_points,
            priority_areas=self._priority_areas,
            metadata=self._metadata,
        )
