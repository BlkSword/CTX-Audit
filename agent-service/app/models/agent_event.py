"""
Agent 事件数据模型
"""
from sqlalchemy import Column, String, Integer, Text, JSON, DateTime, Index, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class AgentEvent(Base):
    """Agent 执行事件"""
    __tablename__ = "agent_events"

    # 主键
    id = Column(Integer, primary_key=True, autoincrement=True)

    # 审计信息
    audit_id = Column(String(100), nullable=False, index=True)
    task_id = Column(String(100), nullable=False, index=True)

    # 序列号（用于排序和断线重连）
    sequence = Column(Integer, nullable=False, index=True)

    # 事件信息
    event_type = Column(String(50), nullable=False, index=True)
    agent_type = Column(String(50), nullable=False)
    agent_id = Column(String(100))

    # 内容
    message = Column(Text)
    thought = Column(Text)
    accumulated_thought = Column(Text)

    # 结构化数据
    data = Column(JSON)
    metadata = Column(JSON)

    # 工具调用
    tool_name = Column(String(100))
    tool_input = Column(JSON)
    tool_output = Column(Text)

    # 漏洞发现
    finding = Column(JSON)

    # 进度
    progress = Column(JSON)

    # 时间戳
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # 索引
    __table_args__ = (
        Index('idx_audit_sequence', 'audit_id', 'sequence'),
        Index('idx_audit_type', 'audit_id', 'event_type'),
    )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "audit_id": self.audit_id,
            "task_id": self.task_id,
            "sequence": self.sequence,
            "event_type": self.event_type,
            "agent_type": self.agent_type,
            "agent_id": self.agent_id,
            "message": self.message,
            "thought": self.thought,
            "accumulated_thought": self.accumulated_thought,
            "data": self.data or {},
            "metadata": self.metadata or {},
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "tool_output": self.tool_output,
            "finding": self.finding,
            "progress": self.progress,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
