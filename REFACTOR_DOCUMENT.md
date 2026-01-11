# CTX-Audit 系统性改造文档

## 文档信息

- **项目名称**: CTX-Audit 审计系统升级改造
- **参考项目**: DeepAudit-3.0.0
- **版本**: v1.0
- **创建日期**: 2026-01-04
- **预计周期**: 6-8 周

---

## 目录

1. [改造目标](#1-改造目标)
2. [差距分析](#2-差距分析)
3. [改造计划总览](#3-改造计划总览)
4. [第一阶段：基础能力增强（Week 1-2）](#4-第一阶段基础能力增强week-1-2)
5. [第二阶段：审计能力提升（Week 3-4）](#5-第二阶段审计能力提升week-3-4)
6. [第三阶段：智能化优化（Week 5-6）](#6-第三阶段智能化优化week-5-6)
7. [第四阶段：高级特性（Week 7-8）](#7-第四阶段高级特性week-7-8)
8. [测试与验证](#8-测试与验证)
9. [部署与监控](#9-部署与监控)
10. [风险评估](#10-风险评估)

---

## 1. 改造目标

### 1.1 总体目标

将 CTX-Audit 从当前的 **基础审计能力** 提升至 **DeepAudit 级别的专业审计系统**，实现：

- ✅ 检测准确率提升 50% 以上
- ✅ 误报率降低 40% 以上
- ✅ 审计覆盖度提升 60%
- ✅ 系统稳定性达到 99.9%
- ✅ 支持主流编程语言和框架

### 1.2 关键指标

| 指标 | 当前值 | 目标值 | 提升 |
|------|--------|--------|------|
| 漏洞检测准确率 | ~45% | ≥70% | +56% |
| 误报率 | ~35% | ≤20% | -43% |
| 支持的漏洞类型 | 8类 | 15+类 | +87% |
| 外部工具集成 | 0个 | 7+个 | +∞ |
| 数据流分析 | ❌ | ✅ | 新增 |
| 事件持久化 | ❌ | ✅ | 新增 |
| 平均审计时间 | 10min | 8min | -20% |

---

## 2. 差距分析

### 2.1 架构层面差距

#### 2.1.1 事件系统 ❌ 严重

**当前状态**：
```python
# app/services/event_manager.py
class EventManager:
    def __init__(self):
        self._event_queues: Dict[str, asyncio.Queue] = {}
        # ❌ 仅内存存储，服务重启后丢失
        # ❌ 无法查询历史事件
        # ❌ 断线重连困难
```

**目标状态**：
```python
# app/services/event_manager.py (改造后)
class EventManager:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self._event_queues: Dict[str, asyncio.Queue] = {}
        # ✅ 内存队列 + 数据库双重存储
        # ✅ 支持历史事件查询
        # ✅ 支持断线重连
```

#### 2.1.2 状态管理 ❌ 严重

**当前状态**：
```python
# 简单字典存储
self._runtime_context = {
    "audit_id": audit_id,
    "project_id": project_id,
}
# ❌ 无分布式追踪
# ❌ 无上下文传递链
```

**目标状态**：
```python
@dataclass
class ExecutionContext:
    correlation_id: str      # 关联ID
    task_id: str             # 任务ID
    trace_path: List[str]    # 追踪路径
    parent_agent_id: str     # 父Agent ID

    def child_context(self, agent_id: str):
        """创建子上下文，维护追踪链"""
        return ExecutionContext(
            correlation_id=self.correlation_id,
            task_id=self.task_id,
            trace_path=self.trace_path + [agent_id],
            parent_agent_id=agent_id
        )
```

#### 2.1.3 错误处理 ❌ 严重

**当前状态**：
```python
# 只处理空响应和格式错误
if not response:
    return {"status": "error"}
if format_count >= 3:
    return {"status": "error"}
# ❌ 无API错误分类
# ❌ 无速率限制处理
# ❌ 无重试机制
```

**目标状态**：
```python
# API错误分类处理
if "rate limit" in error_msg:
    # 等待后重试
    await asyncio.sleep(60)
    return self._retry()
elif "quota" in error_msg:
    # 终止并通知
    return {"status": "failed", "reason": "quota_exceeded"}
elif "connection" in error_msg:
    # 自动重试
    return self._retry_with_backoff()
```

### 2.2 审计能力层面差距

#### 2.2.1 外部工具集成 ❌ 严重

**当前状态**：
- ❌ 零外部安全工具
- 完全依赖 LLM 自主分析
- 仅通过 Rust 后端做基础符号查询

**目标状态**：
```python
# 集成7+专业工具
TOOLS = {
    "semgrep": SemgrepTool(),      # 全语言静态分析
    "bandit": BanditTool(),        # Python安全扫描
    "gitleaks": GitleaksTool(),    # 密钥泄露检测
    "safety": SafetyTool(),        # Python依赖漏洞
    "npm_audit": NpmAuditTool(),   # Node.js依赖漏洞
    "kunlun": KunlunTool(),        # 深度代码审计
    "codespell": CodespellTool(),  # 拼写检查
}
```

#### 2.2.2 数据流分析 ❌ 严重

**当前状态**：
```python
# 仅有基础AST查询
async def get_ast_context(self, file_path: str):
    # 返回调用者/被调用者列表
    # ❌ 无污点追踪
    # ❌ 无净化检测
    # ❌ 无数据源识别
```

**目标状态**：
```python
# 完整的污点追踪
async def dataflow_analysis(
    self,
    source_code: str,
    variable_name: str,
    sink_code: Optional[str] = None
):
    # 1. 检测污染源（user_input, file_read, ...）
    # 2. 追踪数据流路径
    # 3. 检测净化方法（escape, sanitize, ...）
    # 4. 检测危险sink（sql_query, eval, ...）
    # 5. 计算风险等级
```

#### 2.2.3 Recon 深度 ❌ 严重

**当前状态**：
- 主要是文件列表和符号搜索
- 没有工具推荐逻辑
- 依赖 LLM 推测高风险区域

**目标状态**：
```python
# 智能Recon
class ReconAgent:
    async def execute(self, context):
        # 1. 识别技术栈
        tech_stack = await self._identify_tech_stack()

        # 2. 推荐外部工具
        tools = self._recommend_tools(tech_stack)

        # 3. 运行工具获取高风险区域
        high_risk = await self._scan_with_tools(tools)

        # 4. 生成优先级排序的扫描目标
        return {
            "tech_stack": tech_stack,
            "recommended_tools": tools,
            "high_risk_areas": high_risk,  # 带文件路径和行号
        }
```

### 2.3 差距汇总表

| 维度 | 当前状态 | 目标状态 | 优先级 | 工作量 | 状态 |
|------|----------|----------|--------|--------|------|
| 事件持久化 | 内存队列 | 内存+数据库 | P0 | 3天 | ✅ 已完成 |
| 状态管理 | 简单字典 | ExecutionContext | P0 | 2天 | ✅ 已完成 |
| 错误处理 | 基础 | 分类+重试 | P0 | 2天 | ✅ 已完成 |
| 外部工具 | 0个 | 5+个 | P0 | 5天 | ✅ 已完成 |
| 数据流分析 | 无 | 完整污点追踪 | P0 | 4天 | ✅ 已完成 |
| Recon深度 | 文件列表 | 工具推荐+风险定位 | P1 | 3天 | ✅ 已完成 |
| Prompt工程 | 通用 | 工具优先级 | P1 | 2天 | ✅ 已完成 |
| 发现去重 | 简单 | 智能合并 | P1 | 2天 | ✅ 已完成（原有） |
| 超时控制 | 基础 | 取消检查 | P2 | 2天 | ✅ 已完成（原有） |
| 分布式追踪 | 无 | correlation_id | P2 | 3天 | ✅ 已完成 |
| 单元测试 | 无 | 测试框架+用例 | P1 | 2天 | ✅ 已完成 |

**总体进度**: 11/11 核心任务全部完成 ✅

### 2.4 已完成改造文件清单

| # | 文件 | 说明 | 状态 |
|---|------|------|------|
| 1 | `app/models/agent_event.py` | AgentEvent 数据模型 | ✅ 已创建 |
| 2 | `app/services/event_manager.py` | EventManager 持久化改造 | ✅ 已完成 |
| 3 | `app/core/execution_context.py` | ExecutionContext 系统（含分布式追踪） | ✅ 已创建 |
| 4 | `app/core/error_classifier.py` | 错误分类处理器 | ✅ 已创建 |
| 5 | `app/services/external_tools.py` | 外部工具集成服务 | ✅ 已创建 |
| 6 | `app/core/dataflow_analysis.py` | 数据流分析工具 | ✅ 已创建 |
| 7 | `app/core/finding_dedup.py` | 智能发现去重 | ✅ 已存在 |
| 8 | `app/core/cancel_coordinator.py` | 取消协调器 | ✅ 已存在 |
| 9 | `app/agents/recon.py` | 增强的 Recon Agent | ✅ 已更新 |
| 10 | `app/prompts/templates.py` | 优化的 Prompt 模板 | ✅ 已创建 |
| 11 | `app/services/prompt_builder.py` | Prompt 构建器（集成优化模板） | ✅ 已更新 |
| 12 | `tests/test_execution_context.py` | ExecutionContext 单元测试 | ✅ 已创建 |
| 13 | `tests/test_error_classifier.py` | 错误分类器单元测试 | ✅ 已创建 |
| 14 | `tests/test_dataflow_analysis.py` | 数据流分析单元测试 | ✅ 已创建 |
| 15 | `pytest.ini` | Pytest 测试配置 | ✅ 已创建 |

---

## 3. 改造计划总览

### 3.1 四阶段改造路线图

```
┌─────────────────────────────────────────────────────────────────┐
│                    CTX-Audit 改造路线图                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  第一阶段 (Week 1-2)      ███████░░░░░░░░░░░░░░░░░░░░░░░░░░    │
│  ├─ 事件持久化            ████████                              │
│  ├─ 状态管理重构          █████████                              │
│  └─ 错误处理增强          █████████                              │
│                                                                 │
│  第二阶段 (Week 3-4)      ███████████████░░░░░░░░░░░░░░░░░░░░    │
│  ├─ 外部工具集成          ████████████████████                   │
│  ├─ 数据流分析实现        █████████████████████                  │
│  └─ Recon Agent 增强      ████████████████                      │
│                                                                 │
│  第三阶段 (Week 5-6)      ███████████████████████████░░░░░░░░░    │
│  ├─ Prompt 工程优化       ████████████████████████████           │
│  ├─ 发现去重增强          ███████████████████████████            │
│  └─ 超时和取消控制        ████████████████████                  │
│                                                                 │
│  第四阶段 (Week 7-8)      ███████████████████████████████████    │
│  ├─ 分布式追踪            █████████████████████████████████████   │
│  ├─ 性能监控              ████████████████████████████████████    │
│  └─ 高级特性              ██████████████████████████████████      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 关键里程碑

| 阶段 | 里程碑 | 验收标准 | 完成时间 |
|------|--------|----------|----------|
| Phase 1 | 基础架构增强 | 事件持久化、错误处理可用 | Week 2 |
| Phase 2 | 审计能力提升 | 外部工具集成、数据流分析可用 | Week 4 |
| Phase 3 | 智能化优化 | 误报率降低、检测准确率提升 | Week 6 |
| Phase 4 | 生产就绪 | 所有指标达标、文档完整 | Week 8 |

---

## 4. 第一阶段：基础能力增强（Week 1-2）

### 4.1 任务清单

- [ ] 4.1.1 实现事件持久化（3天）
- [ ] 4.1.2 重构状态管理系统（2天）
- [ ] 4.1.3 增强错误处理机制（2天）
- [ ] 4.1.4 单元测试和集成测试（3天）

### 4.2 任务 1：实现事件持久化

#### 4.2.1 需求描述

将当前仅存储在内存的事件系统改造为 **内存队列 + 数据库双重存储**，支持：

- 事件持久化到 SQLite 数据库
- 历史事件查询和断线重连
- 无效 UTF-8 字符清理
- 事件序列化和反序列化

#### 4.2.2 数据库模型设计

**新建文件**: `agent-service/app/models/agent_event.py`

```python
"""
Agent 事件数据模型
"""
from sqlalchemy import Column, String, Integer, Text, JSON, DateTime, Index
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
            "data": self.data,
            "metadata": self.metadata,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "tool_output": self.tool_output,
            "finding": self.finding,
            "progress": self.progress,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
```

#### 4.2.3 改造 EventManager

**修改文件**: `agent-service/app/services/event_manager.py`

```python
"""
事件管理器 - 增强版（支持持久化）
"""
import asyncio
import json
from typing import Dict, List, Any, Optional
from collections import defaultdict
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.agent_event import AgentEvent

class EventManager:
    """事件管理器 - 支持持久化"""

    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self._event_queues: Dict[str, asyncio.Queue] = {}
        self._sequence_counters: Dict[str, int] = defaultdict(int)
        self._latest_sequences: Dict[str, int] = {}

    def create_queue(self, audit_id: str) -> None:
        """创建事件队列"""
        if audit_id not in self._event_queues:
            self._event_queues[audit_id] = asyncio.Queue(maxsize=10000)
            self._sequence_counters[audit_id] = 0

    async def add_event(
        self,
        task_id: str,
        event_type: str,
        agent_type: str,
        message: str = "",
        thought: str = "",
        accumulated_thought: str = "",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tool_name: Optional[str] = None,
        tool_input: Optional[Dict[str, Any]] = None,
        tool_output: Optional[str] = None,
        finding: Optional[Dict[str, Any]] = None,
        progress: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        添加事件到队列和数据库

        Returns:
            事件序列号
        """
        audit_id = task_id  # task_id 就是 audit_id

        # 生成序列号
        sequence = self._sequence_counters[audit_id] + 1
        self._sequence_counters[audit_id] = sequence
        self._latest_sequences[audit_id] = sequence

        # 创建事件数据
        event_data = {
            "id": f"evt_{audit_id}_{sequence}",
            "task_id": task_id,
            "audit_id": audit_id,
            "sequence": sequence,
            "event_type": event_type,
            "agent_type": agent_type,
            "message": message,
            "thought": thought,
            "accumulated_thought": accumulated_thought,
            "data": data or {},
            "metadata": metadata or {},
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_output": tool_output,
            "finding": finding,
            "progress": progress,
            "timestamp": None,  # 将在数据库中设置
        }

        # 1. 添加到内存队列（实时推送）
        queue = self._event_queues.get(audit_id)
        if queue:
            try:
                queue.put_nowait(event_data)
            except asyncio.QueueFull:
                logger.warning(f"[EventManager] 队列已满: {audit_id}")

        # 2. 异步保存到数据库（持久化）
        asyncio.create_task(self._save_event_to_db(event_data))

        return sequence

    async def _save_event_to_db(self, event_data: Dict[str, Any]) -> None:
        """
        保存事件到数据库

        处理：
        1. 清理无效 UTF-8 字符
        2. 序列化复杂对象
        3. 错误处理
        """
        try:
            async with self.db_session_factory() as session:
                # 清理无效 UTF-8
                event_data = self._clean_event_data(event_data)

                # 创建数据库记录
                db_event = AgentEvent(
                    audit_id=event_data["audit_id"],
                    task_id=event_data["task_id"],
                    sequence=event_data["sequence"],
                    event_type=event_data["event_type"],
                    agent_type=event_data["agent_type"],
                    agent_id=event_data.get("agent_id"),
                    message=event_data.get("message"),
                    thought=event_data.get("thought"),
                    accumulated_thought=event_data.get("accumulated_thought"),
                    data=event_data.get("data"),
                    metadata=event_data.get("metadata"),
                    tool_name=event_data.get("tool_name"),
                    tool_input=event_data.get("tool_input"),
                    tool_output=event_data.get("tool_output"),
                    finding=event_data.get("finding"),
                    progress=event_data.get("progress"),
                )

                session.add(db_event)
                await session.commit()

        except Exception as e:
            logger.error(f"[EventManager] 保存事件失败: {e}")

    def _clean_event_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """清理无效 UTF-8 字符"""
        def clean_value(value: Any) -> Any:
            if isinstance(value, str):
                # 替换无效 UTF-8 字符
                try:
                    value.encode('utf-8').decode('utf-8')
                except UnicodeError:
                    value = value.encode('utf-8', errors='replace').decode('utf-8')
            elif isinstance(value, dict):
                return {k: clean_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [clean_value(v) for v in value]
            return value

        return {k: clean_value(v) for k, v in data.items()}

    async def get_events(
        self,
        audit_id: str,
        after_sequence: int = 0,
        limit: int = 100,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        从数据库获取历史事件

        用于断线重连和历史查询
        """
        try:
            async with self.db_session_factory() as session:
                query = session.query(AgentEvent).filter(
                    AgentEvent.audit_id == audit_id,
                    AgentEvent.sequence > after_sequence,
                )

                if event_types:
                    query = query.filter(AgentEvent.event_type.in_(event_types))

                query = query.order_by(AgentEvent.sequence.asc()).limit(limit)

                events = await query.all()

                return [event.to_dict() for event in events]

        except Exception as e:
            logger.error(f"[EventManager] 获取事件失败: {e}")
            return []

    def get_latest_sequence(self, audit_id: str) -> int:
        """获取最新序列号"""
        return self._latest_sequences.get(audit_id, 0)

    async def get_statistics(self, audit_id: str) -> Dict[str, Any]:
        """获取事件统计"""
        try:
            async with self.db_session_factory() as session:
                from sqlalchemy import func

                stats = await session.query(
                    AgentEvent.event_type,
                    func.count(AgentEvent.id).label('count')
                ).filter(
                    AgentEvent.audit_id == audit_id
                ).group_by(AgentEvent.event_type).all()

                return {event_type: count for event_type, count in stats}

        except Exception as e:
            logger.error(f"[EventManager] 获取统计失败: {e}")
            return {}
```

#### 4.2.4 更新数据库初始化

**修改文件**: `agent-service/app/services/database.py`

```python
"""
数据库服务 - 支持 AgentEvent 模型
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.models.agent_event import Base
from pathlib import Path

# 数据库路径
DB_DIR = Path(__file__).parent.parent.parent.parent / "data"
DB_DIR.mkdir(exist_ok=True)
DB_PATH = DB_DIR / "agent_events.db"

# 数据库 URL
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

# 引擎
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
)

# 会话工厂
async_session_maker = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def init_db():
    """初始化数据库"""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db_session():
    """获取数据库会话"""
    return async_session_maker()
```

### 4.3 任务 2：重构状态管理系统

#### 4.3.1 创建 ExecutionContext

**新建文件**: `agent-service/app/core/execution_context.py`

```python
"""
执行上下文 - 支持分布式追踪
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from uuid import uuid4

@dataclass
class ExecutionContext:
    """
    执行上下文

    用于追踪 Agent 调用链，支持分布式追踪
    """
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    task_id: str = ""
    trace_path: List[str] = field(default_factory=list)
    parent_agent_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def child_context(
        self,
        agent_id: str,
        agent_name: str,
        **extra_metadata
    ) -> 'ExecutionContext':
        """
        创建子上下文

        Args:
            agent_id: 子 Agent ID
            agent_name: 子 Agent 名称
            **extra_metadata: 额外的元数据

        Returns:
            子上下文
        """
        return ExecutionContext(
            correlation_id=self.correlation_id,
            task_id=self.task_id,
            trace_path=self.trace_path + [f"{agent_name}:{agent_id}"],
            parent_agent_id=agent_id,
            metadata={**self.metadata, **extra_metadata}
        )

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "correlation_id": self.correlation_id,
            "task_id": self.task_id,
            "trace_path": self.trace_path,
            "parent_agent_id": self.parent_agent_id,
            "depth": len(self.trace_path),
            "metadata": self.metadata,
        }

class ExecutionContextManager:
    """执行上下文管理器"""

    _contexts: Dict[str, ExecutionContext] = {}

    @classmethod
    def create_context(
        cls,
        task_id: str,
        agent_id: str,
        agent_name: str
    ) -> ExecutionContext:
        """创建新的上下文"""
        context = ExecutionContext(
            task_id=task_id,
            trace_path=[f"{agent_name}:{agent_id}"]
        )
        cls._contexts[agent_id] = context
        return context

    @classmethod
    def get_context(cls, agent_id: str) -> Optional[ExecutionContext]:
        """获取 Agent 的上下文"""
        return cls._contexts.get(agent_id)

    @classmethod
    def remove_context(cls, agent_id: str):
        """移除上下文"""
        cls._contexts.pop(agent_id, None)
```

#### 4.3.2 更新 BaseAgent 使用 ExecutionContext

**修改文件**: `agent-service/app/agents/base.py`

```python
"""
Agent 基类 - 支持 ExecutionContext
"""
from app.core.execution_context import ExecutionContext, ExecutionContextManager

class BaseAgent(ABC):
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.thinking_chain: list = []
        self.execution_start_time: Optional[float] = None
        self._audit_id: Optional[str] = None
        self.agent_id: Optional[str] = None

        # 新增：执行上下文
        self._execution_context: Optional[ExecutionContext] = None

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """运行 Agent（包含标准流程包装）"""
        self.execution_start_time = time.time()
        self.thinking_chain = []
        self._audit_id = context.get("audit_id")

        # 创建或获取执行上下文
        task_id = self._audit_id
        if self.agent_id:
            if not ExecutionContextManager.get_context(self.agent_id):
                # 创建新上下文
                self._execution_context = ExecutionContextManager.create_context(
                    task_id=task_id,
                    agent_id=self.agent_id,
                    agent_name=self.name
                )
            else:
                self._execution_context = ExecutionContextManager.get_context(self.agent_id)

        try:
            logger.info(f"[{self.name}] 开始执行...")
            logger.info(f"[{self.name}] Trace: {self._execution_context.to_dict()}")

            await self._before_execution(context)
            result = await self.execute(context)
            await self._after_execution(result)

            duration = time.time() - self.execution_start_time
            logger.info(f"[{self.name}] 执行完成，耗时 {duration:.2f}s")

            return result

        except Exception as e:
            logger.error(f"[{self.name}] 执行失败: {e}", exc_info=True)
            raise
        finally:
            # 清理上下文
            if self.agent_id:
                ExecutionContextManager.remove_context(self.agent_id)
```

### 4.4 任务 3：增强错误处理机制

#### 4.4.1 API 错误分类器

**新建文件**: `agent-service/app/core/error_handler.py`

```python
"""
错误处理器 - API 错误分类和恢复策略
"""
from enum import Enum
from typing import Optional, Dict, Any
import asyncio
import re
from loguru import logger

class ErrorType(Enum):
    """错误类型"""
    UNKNOWN = "unknown"
    RATE_LIMIT = "rate_limit"           # 速率限制
    QUOTA_EXCEEDED = "quota_exceeded"   # 配额用尽
    CONNECTION_ERROR = "connection"     # 连接错误
    TIMEOUT = "timeout"                 # 超时
    INVALID_RESPONSE = "invalid"        # 无效响应
    FORMAT_ERROR = "format"             # 格式错误
    TOKEN_LIMIT = "token_limit"         # Token 超限

class RecoveryStrategy(Enum):
    """恢复策略"""
    NONE = "none"           # 无恢复
    RETRY = "retry"         # 立即重试
    BACKOFF = "backoff"     # 退避重试
    WAIT = "wait"           # 等待后重试
    ABORT = "abort"         # 终止任务

class ErrorHandler:
    """错误处理器"""

    # API 错误模式
    ERROR_PATTERNS = {
        ErrorType.RATE_LIMIT: [
            r"rate limit",
            r"too many requests",
            r"429",
        ],
        ErrorType.QUOTA_EXCEEDED: [
            r"quota",
            r"limit.*exceed",
            r"no.*remaining",
        ],
        ErrorType.CONNECTION_ERROR: [
            r"connection",
            r"network",
            r"timeout",
            r"5\d{2}",
        ],
        ErrorType.TOKEN_LIMIT: [
            r"token.*limit",
            r"maximum.*context",
            r"too.*long",
        ],
    }

    # 重试配置
    RETRY_CONFIG = {
        ErrorType.RATE_LIMIT: {
            "strategy": RecoveryStrategy.WAIT,
            "wait_time": 60,  # 秒
            "max_retries": 3,
        },
        ErrorType.QUOTA_EXCEEDED: {
            "strategy": RecoveryStrategy.ABORT,
            "message": "API 配额已用尽，请检查账户状态",
        },
        ErrorType.CONNECTION_ERROR: {
            "strategy": RecoveryStrategy.BACKOFF,
            "initial_delay": 1,
            "max_delay": 30,
            "max_retries": 5,
        },
        ErrorType.TIMEOUT: {
            "strategy": RecoveryStrategy.BACKOFF,
            "initial_delay": 2,
            "max_delay": 60,
            "max_retries": 3,
        },
        ErrorType.FORMAT_ERROR: {
            "strategy": RecoveryStrategy.RETRY,
            "max_retries": 3,
        },
    }

    @classmethod
    def classify_error(
        cls,
        error_message: str,
        error_type: Optional[str] = None
    ) -> ErrorType:
        """
        分类错误类型

        Args:
            error_message: 错误消息
            error_type: 可选的错误类型提示

        Returns:
            错误类型
        """
        if not error_message:
            return ErrorType.UNKNOWN

        error_message_lower = error_message.lower()

        # 遍历所有错误模式
        for error, patterns in cls.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, error_message_lower):
                    return error

        return ErrorType.UNKNOWN

    @classmethod
    def get_recovery_strategy(cls, error_type: ErrorType) -> Dict[str, Any]:
        """
        获取恢复策略

        Args:
            error_type: 错误类型

        Returns:
            恢复策略配置
        """
        return cls.RETRY_CONFIG.get(
            error_type,
            {
                "strategy": RecoveryStrategy.RETRY,
                "max_retries": 1,
            }
        )

    @classmethod
    async def handle_error(
        cls,
        error: Exception,
        retry_count: int = 0
    ) -> Dict[str, Any]:
        """
        处理错误并返回恢复操作

        Args:
            error: 异常对象
            retry_count: 当前重试次数

        Returns:
            恢复操作配置
        """
        error_message = str(error)
        error_type = cls.classify_error(error_message)
        strategy = cls.get_recovery_strategy(error_type)

        logger.warning(f"[ErrorHandler] 错误类型: {error_type.value}, 策略: {strategy['strategy'].value}")

        # 根据策略执行恢复操作
        if strategy["strategy"] == RecoveryStrategy.ABORT:
            return {
                "action": "abort",
                "message": strategy.get("message", f"错误: {error_message}"),
                "error_type": error_type.value,
            }

        elif strategy["strategy"] == RecoveryStrategy.WAIT:
            wait_time = strategy.get("wait_time", 60)
            logger.info(f"[ErrorHandler] 等待 {wait_time} 秒后重试...")
            await asyncio.sleep(wait_time)
            return {
                "action": "retry",
                "error_type": error_type.value,
            }

        elif strategy["strategy"] == RecoveryStrategy.BACKOFF:
            if retry_count >= strategy.get("max_retries", 3):
                return {
                    "action": "abort",
                    "message": f"超过最大重试次数 ({strategy.get('max_retries')})",
                    "error_type": error_type.value,
                }

            # 指数退避
            initial_delay = strategy.get("initial_delay", 1)
            max_delay = strategy.get("max_delay", 30)
            delay = min(initial_delay * (2 ** retry_count), max_delay)

            logger.info(f"[ErrorHandler] 退避 {delay} 秒后重试...")
            await asyncio.sleep(delay)

            return {
                "action": "retry",
                "error_type": error_type.value,
            }

        elif strategy["strategy"] == RecoveryStrategy.RETRY:
            if retry_count >= strategy.get("max_retries", 3):
                return {
                    "action": "abort",
                    "message": f"超过最大重试次数 ({strategy.get('max_retries')})",
                    "error_type": error_type.value,
                }
            return {
                "action": "retry",
                "error_type": error_type.value,
            }

        return {
            "action": "abort",
            "message": f"未知错误: {error_message}",
            "error_type": ErrorType.UNKNOWN.value,
        }
```

#### 4.4.2 集成到 Orchestrator

**修改文件**: `agent-service/app/agents/orchestrator.py`

```python
"""
Orchestrator Agent - 增强错误处理
"""
from app.core.error_handler import ErrorHandler

class OrchestratorAgent(BaseAgent):
    async def _execute_with_llm(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """LLM 驱动的自主编排 - 带错误处理"""
        # ... 初始化代码 ...

        format_error_count = 0
        api_error_count = 0

        for iteration in range(self.max_iterations):
            try:
                # 调用 LLM
                response = await self.llm.generate(
                    messages=self._conversation,
                    system_prompt=system_prompt
                )
                llm_output = response.content

                # 检测 API 错误
                if llm_output.startswith("[API_ERROR:"):
                    # 提取错误信息
                    error_match = re.match(r'\[API_ERROR:\s*(\w+)\]\s*(.*)', llm_output)
                    if error_match:
                        error_type_str = error_match.group(1)
                        error_message = error_match.group(2)

                        # 使用错误处理器
                        recovery = await ErrorHandler.handle_error(
                            Exception(error_message),
                            api_error_count
                        )

                        if recovery["action"] == "abort":
                            return {
                                "agent": self.name,
                                "status": "failed",
                                "error": recovery["message"],
                                "error_type": recovery["error_type"],
                            }

                        # 重试
                        api_error_count += 1
                        continue

                # 解析 LLM 输出
                step = self._parse_llm_response(llm_output)

                # 重置错误计数
                format_error_count = 0
                api_error_count = 0

                # ... 继续正常流程 ...

            except Exception as e:
                # 处理未捕获的异常
                recovery = await ErrorHandler.handle_error(e, 0)

                if recovery["action"] == "abort":
                    return {
                        "agent": self.name,
                        "status": "error",
                        "error": recovery["message"],
                        "error_type": recovery.get("error_type", "unknown"),
                    }

                # 重试
                continue
```

### 4.5 测试验证

#### 4.5.1 单元测试

**新建文件**: `agent-service/tests/test_event_manager.py`

```python
"""
测试事件管理器
"""
import pytest
from app.services.event_manager import EventManager
from app.services.database import init_db

@pytest.mark.asyncio
async def test_event_persistence():
    """测试事件持久化"""
    await init_db()

    event_manager = EventManager(get_db_session)
    event_manager.create_queue("test_audit")

    # 添加事件
    sequence = await event_manager.add_event(
        task_id="test_audit",
        event_type="thinking",
        agent_type="orchestrator",
        message="测试消息",
    )

    assert sequence == 1

    # 从数据库获取
    events = await event_manager.get_events(
        audit_id="test_audit",
        after_sequence=0,
        limit=10,
    )

    assert len(events) == 1
    assert events[0]["message"] == "测试消息"

@pytest.mark.asyncio
async def test_error_classification():
    """测试错误分类"""
    from app.core.error_handler import ErrorHandler, ErrorType

    # 测试速率限制错误
    error_type = ErrorHandler.classify_error("Rate limit exceeded")
    assert error_type == ErrorType.RATE_LIMIT

    # 测试配额错误
    error_type = ErrorHandler.classify_error("API quota exceeded")
    assert error_type == ErrorType.QUOTA_EXCEEDED

    # 测试连接错误
    error_type = ErrorHandler.classify_error("Connection error")
    assert error_type == ErrorType.CONNECTION_ERROR
```

#### 4.5.2 集成测试

**新建文件**: `agent-service/tests/test_audit_flow.py`

```python
"""
测试审计流程
"""
import pytest
from app.agents.orchestrator import OrchestratorAgent

@pytest.mark.asyncio
async def test_orchestrator_with_error_recovery():
    """测试 Orchestrator 错误恢复"""
    orchestrator = OrchestratorAgent(config={
        "llm_provider": "anthropic",
        "llm_model": "claude-3-5-sonnet-20241022",
        "api_key": "test-key",
    })

    # 模拟 API 错误
    # ... 测试代码 ...
```

---

## 5. 第二阶段：审计能力提升（Week 3-4）

### 5.1 任务清单

- [ ] 5.1.1 集成外部安全工具（5天）
- [ ] 5.1.2 实现数据流分析（4天）
- [ ] 5.1.3 增强 Recon Agent（3天）
- [ ] 5.1.4 测试和验证（2天）

### 5.2 任务 1：集成外部安全工具

#### 5.2.1 外部工具架构设计

**新建文件**: `agent-service/app/services/external_tools.py`

```python
"""
外部安全工具服务
"""
import asyncio
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from loguru import logger
from abc import ABC, abstractmethod

class ExternalTool(ABC):
    """外部工具基类"""

    def __init__(self, name: str, executable: str):
        self.name = name
        self.executable = executable

    @abstractmethod
    async def scan(
        self,
        target_path: str,
        **kwargs
    ) -> Dict[str, Any]:
        """执行扫描"""
        pass

    @abstractmethod
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """解析扫描输出"""
        pass

    async def _run_command(
        self,
        args: List[str],
        timeout: int = 300
    ) -> str:
        """运行命令"""
        try:
            process = await asyncio.create_subprocess_exec(
                self.executable,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            if process.returncode != 0:
                logger.warning(f"[{self.name}] 执行失败: {stderr.decode()}")

            return stdout.decode('utf-8')

        except asyncio.TimeoutError:
            process.kill()
            logger.error(f"[{self.name}] 执行超时")
            raise
        except Exception as e:
            logger.error(f"[{self.name}] 执行异常: {e}")
            raise

class SemgrepTool(ExternalTool):
    """Semgrep 全语言静态分析工具"""

    def __init__(self):
        super().__init__(
            name="semgrep",
            executable="semgrep"
        )

    async def scan(
        self,
        target_path: str,
        rules: str = "auto",
        **kwargs
    ) -> Dict[str, Any]:
        """
        运行 Semgrep 扫描

        Args:
            target_path: 目标路径
            rules: 规则配置 (auto, security, 等)
            **kwargs: 其他参数

        Returns:
            扫描结果
        """
        logger.info(f"[Semgrep] 开始扫描: {target_path}")

        # 构建命令
        args = [
            "--config", rules,
            "--json",
            "--timeout",
            str(kwargs.get("timeout", 300)),
            target_path,
        ]

        # 执行扫描
        output = await self._run_command(args)

        # 解析结果
        findings = self.parse_output(output)

        logger.info(f"[Semgrep] 扫描完成，发现 {len(findings)} 个问题")

        return {
            "tool": "semgrep",
            "target_path": target_path,
            "findings": findings,
            "count": len(findings),
        }

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """解析 Semgrep JSON 输出"""
        try:
            data = json.loads(output)
            return data.get("results", [])
        except json.JSONDecodeError:
            logger.error(f"[Semgrep] 解析输出失败")
            return []

class BanditTool(ExternalTool):
    """Bandit Python 安全扫描工具"""

    def __init__(self):
        super().__init__(
            name="bandit",
            executable="bandit"
        )

    async def scan(
        self,
        target_path: str,
        severity: str = "medium",
        **kwargs
    ) -> Dict[str, Any]:
        """
        运行 Bandit 扫描

        Args:
            target_path: 目标路径
            severity: 最低严重级别 (low, medium, high)
            **kwargs: 其他参数

        Returns:
            扫描结果
        """
        logger.info(f"[Bandit] 开始扫描: {target_path}")

        # 构建命令
        args = [
            "-r", target_path,
            "-f", "json",
            "-ll", severity,
        ]

        # 执行扫描
        output = await self._run_command(args)

        # 解析结果
        findings = self.parse_output(output)

        logger.info(f"[Bandit] 扫描完成，发现 {len(findings)} 个问题")

        return {
            "tool": "bandit",
            "target_path": target_path,
            "findings": findings,
            "count": len(findings),
        }

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """解析 Bandit JSON 输出"""
        try:
            data = json.loads(output)
            return data.get("results", [])
        except json.JSONDecodeError:
            logger.error(f"[Bandit] 解析输出失败")
            return []

class GitleaksTool(ExternalTool):
    """Gitleaks 密钥泄露检测工具"""

    def __init__(self):
        super().__init__(
            name="gitleaks",
            executable="gitleaks"
        )

    async def scan(
        self,
        target_path: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        运行 Gitleaks 扫描

        Args:
            target_path: 目标路径
            **kwargs: 其他参数

        Returns:
            扫描结果
        """
        logger.info(f"[Gitleaks] 开始扫描: {target_path}")

        # 构建命令
        args = [
            "detect",
            "--source", target_path,
            "--report-format", "json",
        ]

        # 执行扫描
        output = await self._run_command(args)

        # 解析结果
        findings = self.parse_output(output)

        logger.info(f"[Gitleaks] 扫描完成，发现 {len(findings)} 个泄露")

        return {
            "tool": "gitleaks",
            "target_path": target_path,
            "findings": findings,
            "count": len(findings),
        }

    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """解析 Gitleaks JSON 输出"""
        try:
            data = json.loads(output)
            return data  # Gitleaks 输出格式根据版本可能不同
        except json.JSONDecodeError:
            logger.error(f"[Gitleaks] 解析输出失败")
            return []

class ExternalToolRegistry:
    """外部工具注册表"""

    def __init__(self):
        self._tools = {
            "semgrep": SemgrepTool(),
            "bandit": BanditTool(),
            "gitleaks": GitleaksTool(),
        }

    def get_tool(self, name: str) -> Optional[ExternalTool]:
        """获取工具"""
        return self._tools.get(name)

    async def run_tool(
        self,
        name: str,
        target_path: str,
        **kwargs
    ) -> Dict[str, Any]:
        """运行工具"""
        tool = self.get_tool(name)
        if not tool:
            raise ValueError(f"未知工具: {name}")

        return await tool.scan(target_path, **kwargs)

    async def run_all_tools(
        self,
        target_path: str,
        tool_names: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """运行所有工具"""
        if tool_names is None:
            tool_names = list(self._tools.keys())

        results = {}
        for tool_name in tool_names:
            try:
                result = await self.run_tool(tool_name, target_path, **kwargs)
                results[tool_name] = result
            except Exception as e:
                logger.error(f"[ExternalTools] {tool_name} 执行失败: {e}")
                results[tool_name] = {
                    "error": str(e),
                    "findings": [],
                    "count": 0,
                }

        return results

# 全局实例
external_tools = ExternalToolRegistry()
```

#### 5.2.2 创建 MCP 工具包装器

**新建文件**: `agent-service/app/core/tools/external_tools_mcp.py`

```python
"""
外部工具的 MCP 包装器
"""
from app.services.external_tools import external_tools
from app.core.mcp_tools import MCPTool, ToolResult

class SemgrepScanTool(MCPTool):
    """Semgrep 扫描工具"""

    name = "semgrep_scan"
    description = """
    使用 Semgrep 进行全语言静态分析。

    这是第一优先级的工具！每次分析都应该首先使用。

    Args:
        target_path: 目标路径（默认当前目录）
        rules: 规则配置 (auto, security, 等)
    """

    input_schema = {
        "type": "object",
        "properties": {
            "target_path": {
                "type": "string",
                "description": "目标扫描路径",
            },
            "rules": {
                "type": "string",
                "description": "规则配置 (auto, security)",
                "default": "auto",
            },
        },
    }

    async def execute(
        self,
        target_path: str = ".",
        rules: str = "auto",
        **kwargs
    ) -> ToolResult:
        """执行 Semgrep 扫描"""
        try:
            self.think(f"运行 Semgrep 扫描: {target_path}")

            result = await external_tools.run_tool(
                "semgrep",
                target_path,
                rules=rules,
            )

            findings = result.get("findings", [])

            self.think(f"Semgrep 扫描完成，发现 {len(findings)} 个问题")

            return ToolResult.success(
                content=f"Semgrep 扫描完成，发现 {len(findings)} 个问题",
                data={
                    "tool": "semgrep",
                    "findings": findings,
                    "count": len(findings),
                }
            )

        except Exception as e:
            return ToolResult.error(
                error=str(e),
                message=f"Semgrep 扫描失败: {str(e)}"
            )

class BanditScanTool(MCPTool):
    """Bandit 扫描工具"""

    name = "bandit_scan"
    description = """
    使用 Bandit 进行 Python 安全扫描。

    对于 Python 项目，这是必须使用的工具。

    Args:
        target_path: 目标路径
        severity: 最低严重级别 (low, medium, high)
    """

    input_schema = {
        "type": "object",
        "properties": {
            "target_path": {
                "type": "string",
                "description": "目标扫描路径",
            },
            "severity": {
                "type": "string",
                "description": "最低严重级别",
                "default": "medium",
            },
        },
    }

    async def execute(
        self,
        target_path: str = ".",
        severity: str = "medium",
        **kwargs
    ) -> ToolResult:
        """执行 Bandit 扫描"""
        try:
            self.think(f"运行 Bandit 扫描: {target_path}")

            result = await external_tools.run_tool(
                "bandit",
                target_path,
                severity=severity,
            )

            findings = result.get("findings", [])

            self.think(f"Bandit 扫描完成，发现 {len(findings)} 个问题")

            return ToolResult.success(
                content=f"Bandit 扫描完成，发现 {len(findings)} 个问题",
                data={
                    "tool": "bandit",
                    "findings": findings,
                    "count": len(findings),
                }
            )

        except Exception as e:
            return ToolResult.error(
                error=str(e),
                message=f"Bandit 扫描失败: {str(e)}"
            )

class GitleaksScanTool(MCPTool):
    """Gitleaks 扫描工具"""

    name = "gitleaks_scan"
    description = """
    使用 Gitleaks 进行密钥泄露检测。

    这是必须使用的工具，每次分析都应该运行。

    Args:
        target_path: 目标路径
    """

    input_schema = {
        "type": "object",
        "properties": {
            "target_path": {
                "type": "string",
                "description": "目标扫描路径",
            },
        },
    }

    async def execute(
        self,
        target_path: str = ".",
        **kwargs
    ) -> ToolResult:
        """执行 Gitleaks 扫描"""
        try:
            self.think(f"运行 Gitleaks 扫描: {target_path}")

            result = await external_tools.run_tool(
                "gitleaks",
                target_path,
            )

            findings = result.get("findings", [])

            self.think(f"Gitleaks 扫描完成，发现 {len(findings)} 个泄露")

            return ToolResult.success(
                content=f"Gitleaks 扫描完成，发现 {len(findings)} 个泄露",
                data={
                    "tool": "gitleaks",
                    "findings": findings,
                    "count": len(findings),
                }
            )

        except Exception as e:
            return ToolResult.error(
                error=str(e),
                message=f"Gitleaks 扫描失败: {str(e)}"
            )
```

### 5.3 任务 2：实现数据流分析

#### 5.3.1 创建数据流分析工具

**新建文件**: `agent-service/app/core/tools/dataflow_tool.py`

```python
"""
数据流分析工具 - 污点追踪
"""
import re
from typing import Dict, Any, Optional, List
from app.core.mcp_tools import MCPTool, ToolResult

class DataFlowAnalysisTool(MCPTool):
    """
    数据流分析工具

    功能：
    1. 检测污染源（user_input, file_read, database）
    2. 追踪数据流路径
    3. 检测净化方法（escape, sanitize, validate）
    4. 检测危险 sink（sql_query, eval, exec）
    5. 计算风险等级
    """

    name = "dataflow_analysis"
    description = """
    分析代码的数据流，检测潜在的污点追踪漏洞。

    功能：
    - 识别污染源（用户输入、文件读取等）
    - 追踪数据流
    - 检测净化方法
    - 识别危险 sink
    - 计算风险等级

    Args:
        source_code: 源代码
        variable_name: 要分析的变量名
        sink_code: 可选的 sink 代码
        language: 编程语言（python, php, javascript等）
    """

    input_schema = {
        "type": "object",
        "properties": {
            "source_code": {
                "type": "string",
                "description": "源代码",
            },
            "variable_name": {
                "type": "string",
                "description": "要分析的变量名",
            },
            "sink_code": {
                "type": "string",
                "description": "可选的 sink 代码",
            },
            "language": {
                "type": "string",
                "description": "编程语言",
                "default": "python",
            },
        },
        "required": ["source_code", "variable_name"],
    }

    # 污染源模式
    SOURCE_PATTERNS = {
        "python": {
            "user_input_get": [
                (r'\brequest\.GET\s*\[', "HTTP GET 参数"),
                (r'\brequest\.POST\s*\[', "HTTP POST 参数"),
                (r'\brequest\.args\.', "HTTP 请求参数"),
                (r'\bflask\.request\.', "Flask 请求"),
                (r'\binput\s*\(', "用户输入"),
            ],
            "file_read": [
                (r'\bopen\s*\(', "文件读取"),
                (r'\bPath\.open\s*\(', "路径打开"),
            ],
            "database": [
                (r'\bcursor\.execute\s*\(', "数据库查询"),
                (r'\bModel\.select\s*\(', "ORM 查询"),
            ],
        },
        "php": {
            "user_input_get": [
                (r'\$_GET\[', "HTTP GET 参数"),
                (r'\$_POST\[', "HTTP POST 参数"),
                (r'\$_REQUEST\[', "HTTP 请求"),
            ],
            "file_read": [
                (r'\bfopen\s*\(', "文件打开"),
                (r'\bfile_get_contents\s*\(', "文件读取"),
            ],
        },
        "javascript": {
            "user_input_get": [
                (r'request\.query', "Express 查询参数"),
                (r'request\.body', "请求体"),
                (r'\$\_GET\[', "GET 参数"),
                (r'\$\_POST\[', "POST 参数"),
            ],
        },
    }

    # 净化方法模式
    SANITIZE_PATTERNS = {
        "python": [
            (r'\bhtml\.escape\s*\(', "HTML 转义"),
            (r'\bescape\s*\(', "转义"),
            (r'\bsanitize\s*\(', "净化"),
            (r'\bvalidate\s*\(', "验证"),
            (r'\b bleach\.clean\s*\(', "Bleach 清理"),
            (r'\bmarkupsafe\.escape\s*\(', "MarkupSafe 转义"),
        ],
        "php": [
            (r'\bhtmlspecialchars\s*\(', "HTML 特殊字符转义"),
            (r'\bhtmlentities\s*\(', "HTML 实体编码"),
            (r'\bmysql_real_escape_string\s*\(', "MySQL 转义"),
            (r'\baddslashes\s*\(', "添加斜杠转义"),
            (r'\bfilter_var\s*\(', "过滤器"),
        ],
        "javascript": [
            (r'\bescape\s*\(', "转义"),
            (r'\bsanitize\s*\(', "净化"),
            (r'\bvalidator\.', "验证器"),
            (r'\bDOMPurify\.sanitize\s*\(', "DOMPurify 清理"),
        ],
    }

    # 危险 sink 模式
    SINK_PATTERNS = {
        "python": [
            (r'\bexecute\s*\(', "命令执行"),
            (r'\beval\s*\(', "代码执行"),
            (r'\bexec\s*\(', "代码执行"),
            (r'\b__import__\s*\(\s*\', "动态导入"),
            (r'\bcompile\s*\(', "代码编译"),
            (r'\bsubprocess\.', "子进程"),
            (r'\bos\.system\s*\(', "系统命令"),
            (r'\bcursor\.execute\s*\(', "SQL 执行"),
            (r'\bconnection\.execute\s*\(', "SQL 执行"),
        ],
        "php": [
            (r'\beval\s*\(', "代码执行"),
            (r'\bexec\s*\(', "命令执行"),
            (r'\bsystem\s*\(', "系统命令"),
            (r'\bpassthru\s*\(', "命令执行"),
            (r'\bshell_exec\s*\(', "Shell 执行"),
            (r'\bmysql_query\s*\(', "MySQL 查询"),
        ],
        "javascript": {
            (r'\beval\s*\(', "代码执行"),
            (r'\bFunction\s*\(', "函数构造器"),
            (r'\brequire\s*\(', "动态导入"),
            (r'\bimport\s*\(', "动态导入"),
            (r'\bchild_process\.', "子进程"),
            (r'\bexec\s*\(', "执行"),
        ],
    }

    async def execute(
        self,
        source_code: str,
        variable_name: str,
        sink_code: Optional[str] = None,
        language: str = "python",
        **kwargs
    ) -> ToolResult:
        """执行数据流分析"""
        try:
            self.think(f"分析变量 {variable_name} 的数据流")

            # 1. 快速模式匹配（不依赖 LLM）
            quick_result = self._quick_pattern_analysis(
                source_code, variable_name, sink_code, language
            )

            # 2. 如果快速分析结果明确，直接返回
            if quick_result["risk_level"] in ["high", "low"]:
                self.think(f"数据流分析完成，风险等级: {quick_result['risk_level']}")
                return ToolResult.success(
                    content=f"数据流分析完成，风险等级: {quick_result['risk_level']}",
                    data=quick_result
                )

            # 3. 否则使用 LLM 深度分析（带超时保护）
            self.think("使用 LLM 进行深度数据流分析")
            llm_result = await self._llm_dataflow_analysis(
                source_code, variable_name, sink_code, language
            )

            # 4. 合并结果
            final_result = self._merge_results(quick_result, llm_result)

            return ToolResult.success(
                content=f"数据流分析完成，风险等级: {final_result['risk_level']}",
                data=final_result
            )

        except Exception as e:
            return ToolResult.error(
                error=str(e),
                message=f"数据流分析失败: {str(e)}"
            )

    def _quick_pattern_analysis(
        self,
        source_code: str,
        variable_name: str,
        sink_code: Optional[str],
        language: str
    ) -> Dict[str, Any]:
        """基于规则的快速数据流分析"""
        result = {
            "source_type": "unknown",
            "source_description": "",
            "sanitized": False,
            "sanitization_methods": [],
            "dangerous_sinks": [],
            "risk_level": "low",
            "confidence": "medium",
            "analysis_method": "pattern_matching",
        }

        # 1. 检测污染源
        source_patterns = self.SOURCE_PATTERNS.get(language, {})
        for source_type, patterns in source_patterns.items():
            for pattern, description in patterns:
                if re.search(pattern, source_code):
                    result["source_type"] = source_type
                    result["source_description"] = description
                    result["risk_level"] = "medium"
                    break
            if result["source_type"] != "unknown":
                break

        # 2. 检测净化方法
        sanitize_patterns = self.SANITIZE_PATTERNS.get(language, [])
        for pattern, description in sanitize_patterns:
            if re.search(pattern, source_code):
                result["sanitized"] = True
                result["sanitization_methods"].append(description)
                # 降低风险等级
                if result["risk_level"] == "high":
                    result["risk_level"] = "medium"

        # 3. 检测危险 sink
        sink_patterns = self.SINK_PATTERNS.get(language, [])
        for pattern, description in sink_patterns:
            search_in = sink_code if sink_code else source_code
            if re.search(pattern, search_in):
                result["dangerous_sinks"].append(description)
                # 提升风险等级
                if result["source_type"] != "unknown":
                    if not result["sanitized"]:
                        result["risk_level"] = "high"
                        result["confidence"] = "high"
                    else:
                        result["risk_level"] = "medium"

        # 4. 检查变量是否被使用
        if variable_name not in source_code:
            result["risk_level"] = "low"
            result["confidence"] = "low"
            result["source_description"] = "变量未找到"

        return result

    async def _llm_dataflow_analysis(
        self,
        source_code: str,
        variable_name: str,
        sink_code: Optional[str],
        language: str
    ) -> Dict[str, Any]:
        """使用 LLM 进行深度数据流分析"""
        # 获取 LLM 服务
        from app.services.llm.adapters.base import LLMService
        llm = self._get_llm_service()

        # 构建 Prompt
        prompt = f"""
分析以下代码的数据流，识别潜在的安全漏洞。

## 代码
```{language}
{source_code}
```

## 目标变量
{variable_name}

## Sink 代码
{sink_code if sink_code else "未提供"}

## 任务
1. 识别污染源（用户输入、文件读取等）
2. 追踪数据流路径
3. 检测净化方法（escape, sanitize等）
4. 识别危险 sink（SQL执行、命令执行等）
5. 评估风险等级（high/medium/low）
6. 提供详细的分析理由

## 输出格式（JSON）:
{{
    "source_type": "污染源类型",
    "source_description": "污染源描述",
    "data_flow_path": ["数据流路径"],
    "sanitized": true/false,
    "sanitization_methods": ["净化方法"],
    "dangerous_sinks": ["危险sink"],
    "risk_level": "high/medium/low",
    "confidence": "high/medium/low",
    "reasoning": "详细分析理由"
}}
"""

        try:
            response = await llm.generate(
                messages=[{"role": "user", "content": prompt}],
                system_prompt="你是一个安全分析专家，专注于数据流分析和污点追踪。"
            )

            # 解析 LLM 输出
            import json
            try:
                # 尝试提取 JSON
                output = response.content
                json_match = re.search(r'\{.*\}', output, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group(0))
                    result["analysis_method"] = "llm"
                    return result
            except json.JSONDecodeError:
                pass

            # 如果无法解析，返回默认结果
            return {
                "risk_level": "medium",
                "confidence": "low",
                "analysis_method": "llm_fallback",
                "reasoning": "LLM 输出无法解析",
            }

        except Exception as e:
            logger.warning(f"[DataFlowTool] LLM 分析失败: {e}")
            return {
                "risk_level": "medium",
                "confidence": "low",
                "analysis_method": "llm_error",
                "error": str(e),
            }

    def _merge_results(
        self,
        quick_result: Dict[str, Any],
        llm_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """合并快速分析和 LLM 分析结果"""
        # 优先使用快速分析的高置信度结果
        if quick_result["confidence"] == "high" and quick_result["risk_level"] == "high":
            return quick_result

        # 否则合并两者
        merged = quick_result.copy()

        # 使用 LLM 的风险等级（如果有）
        if llm_result.get("confidence") == "high":
            merged["risk_level"] = llm_result.get("risk_level", merged["risk_level"])
            merged["reasoning"] = llm_result.get("reasoning", "")

        # 添加 LLM 分析备注
        merged["llm_analysis"] = llm_result.get("reasoning", "")

        return merged
```

### 5.4 任务 3：增强 Recon Agent

#### 5.4.1 改造 Recon Agent

**修改文件**: `agent-service/app/agents/recon.py`

```python
"""
Recon Agent - 增强版
"""
from typing import Dict, Any, List
from app.services.external_tools import external_tools
from app.agents.base import BaseAgent

class ReconAgent(BaseAgent):
    """信息收集 Agent - 增强版"""

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行信息收集"""
        audit_id = context.get("audit_id")
        project_id = context.get("project_id")
        project_path = context.get("project_path", "")

        self.think(f"开始侦察项目: {project_id}")

        # 1. 识别技术栈
        self.think("识别项目技术栈")
        tech_stack = await self._identify_tech_stack(project_path)

        # 2. 推荐外部工具
        self.think("推荐适合的外部工具")
        recommended_tools = self._recommend_tools(tech_stack)

        # 3. 运行工具获取高风险区域
        self.think("运行外部工具扫描高风险区域")
        high_risk_areas = await self._scan_with_tools(
            project_path,
            recommended_tools
        )

        # 4. 生成优先级排序的扫描目标
        scan_targets = self._prioritize_targets(
            high_risk_areas,
            tech_stack
        )

        result = {
            "tech_stack": tech_stack,
            "recommended_tools": recommended_tools,
            "high_risk_areas": high_risk_areas,
            "scan_targets": scan_targets,
            "project_info": {
                "project_id": project_id,
                "project_path": project_path,
            }
        }

        self.think(f"侦察完成，识别 {len(scan_targets)} 个优先目标")

        return result

    async def _identify_tech_stack(
        self,
        project_path: str
    ) -> List[str]:
        """识别项目技术栈"""
        from pathlib import Path

        tech_stack = []

        # 检查项目文件
        project_dir = Path(project_path)

        # Python 项目
        if (project_dir / "requirements.txt").exists():
            tech_stack.append("python")
        if (project_dir / "setup.py").exists():
            tech_stack.append("python")
        if (project_dir / "pyproject.toml").exists():
            tech_stack.append("python")

        # Node.js 项目
        if (project_dir / "package.json").exists():
            tech_stack.append("javascript")
            tech_stack.append("nodejs")

        # PHP 项目
        for php_file in project_dir.glob("*.php"):
            tech_stack.append("php")
            break

        # Java 项目
        if (project_dir / "pom.xml").exists():
            tech_stack.append("java")
            tech_stack.append("maven")
        if (project_dir / "build.gradle").exists():
            tech_stack.append("java")
            tech_stack.append("gradle")

        # Go 项目
        if (project_dir / "go.mod").exists():
            tech_stack.append("go")

        # 框架识别
        # ... 更多框架检测逻辑 ...

        return tech_stack

    def _recommend_tools(self, tech_stack: List[str]) -> List[str]:
        """根据技术栈推荐外部工具"""
        tools = []

        # 基础工具（所有项目）
        tools.append("semgrep")  # 全语言静态分析
        tools.append("gitleaks")  # 密钥泄露检测

        # Python 特定
        if "python" in tech_stack:
            tools.append("bandit")  # Python 安全扫描
            tools.append("safety")  # 依赖漏洞

        # JavaScript 特定
        if "javascript" in tech_stack or "nodejs" in tech_stack:
            tools.append("npm_audit")  # NPM 依赖检查
            tools.append("eslint_security")  # ESLint 安全规则

        # PHP 特定
        if "php" in tech_stack:
            tools.append("phpstan")  # PHP 静态分析

        return tools

    async def _scan_with_tools(
        self,
        project_path: str,
        tool_names: List[str]
    ) -> List[Dict[str, Any]]:
        """运行工具扫描高风险区域"""
        high_risk_areas = []

        for tool_name in tool_names:
            try:
                self.think(f"运行 {tool_name} 扫描")
                result = await external_tools.run_tool(
                    tool_name,
                    project_path,
                )

                # 提取高风险发现
                findings = result.get("findings", [])
                for finding in findings[:10]:  # 限制每个工具最多10个
                    high_risk_areas.append({
                        "tool": tool_name,
                        "file_path": finding.get("path", ""),
                        "line": finding.get("start", {}).get("line", 0),
                        "severity": finding.get("extra", {}).get("severity", "medium"),
                        "message": finding.get("message", ""),
                        "rule_id": finding.get("check_id", ""),
                    })

            except Exception as e:
                self.think(f"{tool_name} 扫描失败: {e}")

        return high_risk_areas

    def _prioritize_targets(
        self,
        high_risk_areas: List[Dict[str, Any]],
        tech_stack: List[str]
    ) -> List[Dict[str, Any]]:
        """优先级排序扫描目标"""
        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        sorted_areas = sorted(
            high_risk_areas,
            key=lambda x: severity_order.get(
                x.get("severity", "low"),
                4
            )
        )

        # 去重（同一文件和行号）
        seen = set()
        unique_areas = []
        for area in sorted_areas:
            key = (area["file_path"], area["line"])
            if key not in seen:
                seen.add(key)
                unique_areas.append(area)

        return unique_areas[:20]  # 返回前20个
```

---

## 6. 第三阶段：智能化优化（Week 5-6）

### 6.1 任务清单

- [ ] 6.1.1 优化 Prompt 工程（2天）
- [ ] 6.1.2 增强发现去重逻辑（2天）
- [ ] 6.1.3 实现超时和取消控制（2天）
- [ ] 6.1.4 测试和优化（4天）

### 6.2 任务 1：优化 Prompt 工程

#### 6.2.1 创建 Prompt 构建器

**新建文件**: `agent-service/app/services/prompt_builder.py`

```python
"""
Prompt 构建器 - 优化 LLM Prompt
"""
from typing import Dict, Any, List

class PromptBuilder:
    """Prompt 构建器"""

    @staticmethod
    def get_analysis_system_prompt(
        tech_stack: List[str],
        available_tools: List[str]
    ) -> str:
        """获取 Analysis Agent 的 System Prompt"""

        # 根据技术栈推荐工具
        tool_recommendations = PromptBuilder._get_tool_recommendations(
            tech_stack,
            available_tools
        )

        prompt = f"""你是 CTX-Audit 的 Analysis Agent，专注于代码安全审计。

## 🎯 核心目标
深度分析代码，发现潜在的安全漏洞，并提供详细的修复建议。

## 🔧 工具使用优先级（严格按此顺序）

### 第一优先级：外部专业工具 ⭐⭐⭐
首先运行以下工具（根据技术栈选择）：
{tool_recommendations}

这些工具是：
- **经过验证的专业规则库**
- **误报率更低**
- **覆盖更全面的漏洞类型**

### 第二优先级：AST 查询工具
- get_ast_context - 获取函数上下文和调用关系
- get_call_graph - 分析函数调用链
- search_symbol - 搜索符号定义

### 第三优先级：深度分析工具
- dataflow_analysis - 污点追踪（SQL注入、XSS等）
- read_file - 读取完整代码
- get_code_structure - 获取代码结构

## ⚠️ 防幻觉规则（严格遵守）
1. **file_path 必须来自实际工具返回**，禁止猜测典型项目结构
2. **行号必须从实际代码中提取**，不要估计
3. **漏洞类型必须使用标准分类**，不要自创类型
4. **如果不确定，使用工具验证**，不要猜测
5. **证据不足时标记为 medium 或 low confidence**

## 📊 输出格式

每个发现必须包含：
- file_path（来自工具）
- line_start/end（从代码提取）
- vulnerability_type（标准分类：sql_injection, xss, command_injection等）
- severity（critical/high/medium/low，基于影响）
- confidence（high/medium/low，基于证据强度）
- description（清晰的问题描述）
- recommendation（可执行的修复建议）
- code_snippet（相关代码片段）
- references（相关文档或CWE链接）

## 🎓 分析流程

1. **首先运行外部工具扫描**（60%时间）
2. **基于工具结果进行深度分析**（30%时间）
3. **使用 AST 查询工具验证**（10%时间）

## 💡 最佳实践

- 优先关注用户输入相关的漏洞（SQL注入、XSS、命令注入）
- 注意认证和授权逻辑的缺陷
- 检查敏感信息泄露
- 验证加密和随机数使用
- 关注业务逻辑漏洞

记住：**工具检测是基础，LLM 分析是补充**。工具的发现更可靠，LLM 的价值在于深度理解和上下文分析。
"""
        return prompt

    @staticmethod
    def _get_tool_recommendations(
        tech_stack: List[str],
        available_tools: List[str]
    ) -> str:
        """获取工具推荐"""
        recommendations = []

        # 基础工具
        if "semgrep_scan" in available_tools:
            recommendations.append("```python\nAction: semgrep_scan\nAction Input: {{'target_path': '.', 'rules': 'auto'}}\n```")

        if "gitleaks_scan" in available_tools:
            recommendations.append("```python\nAction: gitleaks_scan\nAction Input: {{'target_path': '.'}}\n```")

        # Python 特定
        if "python" in tech_stack and "bandit_scan" in available_tools:
            recommendations.append("```python\nAction: bandit_scan\nAction Input: {{'target_path': '.', 'severity': 'medium'}}\n```")

        # JavaScript 特定
        if "javascript" in tech_stack:
            recommendations.append("```javascript\n// 对于 JavaScript 项目\nAction: eslint_security_scan\nAction Input: {{'target_path': '.'}}\n```")

        if not recommendations:
            return "没有可用的外部工具，将使用 AST 查询进行手动分析。"

        return "\n\n".join(recommendations)

    @staticmethod
    def get_recon_system_prompt() -> str:
        """获取 Recon Agent 的 System Prompt"""
        return """你是 CTX-Audit 的 Recon Agent，负责信息收集和侦察。

## 🎯 核心目标
全面侦察项目结构，识别技术栈，定位高风险区域，为深度分析提供精准目标。

## 🔍 侦察流程

### 1. 技术栈识别
检查项目文件，识别：
- 编程语言（Python, JavaScript, PHP, Java, Go等）
- 框架（Django, Flask, Express, Laravel等）
- 依赖管理（requirements.txt, package.json, composer.json等）

### 2. 文件结构分析
- 入口文件（index.py, app.py, main.js等）
- 配置文件（config.py, settings.py等）
- 路由定义（urls.py, routes.py等）
- 数据模型（models.py, schema.py等）

### 3. 高风险区域定位
- 用户认证和授权
- 数据库操作
- 文件操作
- 命令执行
- 敏感数据处理

### 4. 外部工具推荐
根据技术栈推荐适合的外部扫描工具。

## ⚠️ 注意事项
- 使用实际文件路径，不要猜测
- 记录准确的行号
- 提供具体的代码证据

## 📊 输出格式
{
    "tech_stack": ["语言", "框架"],
    "recommended_tools": ["工具1", "工具2"],
    "high_risk_areas": [
        {
            "file_path": "实际路径",
            "line": 实际行号,
            "reason": "高风险原因",
            "tool": "检测工具"
        }
    ]
}
"""
```

### 6.3 任务 2：增强发现去重逻辑

#### 6.3.1 智能去重实现

**修改文件**: `agent-service/app/agents/orchestrator.py`

```python
"""
Orchestrator Agent - 增强发现去重
"""
from difflib import SequenceMatcher

class OrchestratorAgent(BaseAgent):

    def _merge_findings(
        self,
        existing_finding: Dict[str, Any],
        new_finding: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        智能合并发现

        合并策略：
        1. 文件路径匹配（支持相对路径）
        2. 行号范围重叠
        3. 描述相似度
        4. 漏洞类型匹配
        5. 保留更完整的数据
        """
        # 标准化新发现
        normalized_new = self._normalize_finding(new_finding)

        # 提取关键字段
        existing_file = existing_finding.get("file_path", "")
        new_file = normalized_new.get("file_path", "")
        existing_line = existing_finding.get("line_start")
        new_line = normalized_new.get("line_start")
        existing_desc = existing_finding.get("description", "")
        new_desc = normalized_new.get("description", "")
        existing_type = existing_finding.get("vulnerability_type", "")
        new_type = normalized_new.get("vulnerability_type", "")

        # 1. 文件路径匹配（支持相对路径和后缀匹配）
        same_file = False
        if existing_file and new_file:
            # 完全匹配
            if existing_file == new_file:
                same_file = True
            # 后缀匹配（处理相对路径）
            elif existing_file.endswith(new_file) or new_file.endswith(existing_file):
                same_file = True

        # 2. 行号范围重叠
        same_line = False
        if existing_line and new_line:
            # 精确匹配
            if existing_line == new_line:
                same_line = True
            # 范围重叠（允许5行误差）
            elif abs(existing_line - new_line) <= 5:
                same_line = True

        # 3. 描述相似度（使用字符串相似度）
        similar_desc = False
        if existing_desc and new_desc:
            similarity = SequenceMatcher(None, existing_desc, new_desc).ratio()
            if similarity > 0.6:  # 60% 相似度
                similar_desc = True

        # 4. 漏洞类型匹配
        same_type = existing_type == new_type

        # 判断是否为同一发现
        is_duplicate = False
        if same_file and (same_line or similar_desc or same_type):
            is_duplicate = True

        if is_duplicate:
            # 合并发现，保留更完整的数据
            merged = dict(existing_finding)

            # 优先保留非空字段
            for key, value in normalized_new.items():
                if value is not None and value != "":
                    # 特殊处理某些字段
                    if key == "severity":
                        # 保留更严重的等级
                        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                        existing_sev = existing_finding.get("severity", "low")
                        new_sev = value
                        if severity_order.get(new_sev, 4) < severity_order.get(existing_sev, 4):
                            merged[key] = new_sev
                    elif key == "is_verified":
                        # 保留已验证的状态
                        if value and not existing_finding.get("is_verified"):
                            merged[key] = True
                    elif key == "code_snippet":
                        # 保留更长的代码片段
                        if not existing_finding.get(key) or len(value) > len(str(existing_finding.get(key, ""))):
                            merged[key] = value
                    else:
                        merged[key] = value

            return merged

        # 不是重复发现，返回原发现
        return existing_finding

    def _normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """标准化发现格式"""
        normalized = {}

        # 处理文件路径
        if "file" in finding:
            normalized["file_path"] = finding["file"]
        elif "file_path" in finding:
            normalized["file_path"] = finding["file_path"]
        elif "path" in finding:
            normalized["file_path"] = finding["path"]

        # 处理行号
        if "line" in finding:
            normalized["line_start"] = finding["line"]
        elif "line_start" in finding:
            normalized["line_start"] = finding["line_start"]
        elif "start_line" in finding:
            normalized["line_start"] = finding["start_line"]

        # 处理漏洞类型
        if "type" in finding:
            normalized["vulnerability_type"] = finding["type"]
        elif "vulnerability_type" in finding:
            normalized["vulnerability_type"] = finding["vulnerability_type"]
        elif "category" in finding:
            normalized["vulnerability_type"] = finding["category"]

        # 处理描述
        if "msg" in finding:
            normalized["description"] = finding["msg"]
        elif "message" in finding:
            normalized["description"] = finding["message"]
        elif "description" in finding:
            normalized["description"] = finding["description"]

        # 处理严重程度
        if "level" in finding:
            normalized["severity"] = finding["level"]
        elif "severity" in finding:
            normalized["severity"] = finding["severity"]

        # 复制其他字段
        for key, value in finding.items():
            if key not in normalized:
                normalized[key] = value

        return normalized
```

### 6.4 任务 3：实现超时和取消控制

**新建文件**: `agent-service/app/core/cancel_coordinator.py`

```python
"""
取消协调器 - 支持 Agent 任务取消
"""
import asyncio
from typing import Set, Optional
from loguru import logger

class CancelCoordinator:
    """取消协调器"""

    _cancelled_tasks: Set[str] = set()
    _cancel_events: Dict[str, asyncio.Event] = {}

    @classmethod
    def is_cancelled(cls, task_id: str) -> bool:
        """检查任务是否已取消"""
        return task_id in cls._cancelled_tasks

    @classmethod
    def cancel_task(cls, task_id: str):
        """取消任务"""
        cls._cancelled_tasks.add(task_id)
        if task_id in cls._cancel_events:
            cls._cancel_events[task_id].set()
        logger.info(f"[CancelCoordinator] 任务已取消: {task_id}")

    @classmethod
    def reset_task(cls, task_id: str):
        """重置任务状态"""
        cls._cancelled_tasks.discard(task_id)
        if task_id in cls._cancel_events:
            cls._cancel_events[task_id].clear()

    @classmethod
    def get_cancel_event(cls, task_id: str) -> asyncio.Event:
        """获取取消事件"""
        if task_id not in cls._cancel_events:
            cls._cancel_events[task_id] = asyncio.Event()
        return cls._cancel_events[task_id]

async def run_with_cancel_check(
    task_id: str,
    coro,
    check_interval: float = 0.5
):
    """
    包装协程，支持取消检查

    Args:
        task_id: 任务 ID
        coro: 要执行的协程
        check_interval: 检查间隔（秒）

    Returns:
        协程结果

    Raises:
        asyncio.CancelledError: 任务被取消
    """
    cancel_event = CancelCoordinator.get_cancel_event(task_id)

    # 创建任务
    task = asyncio.create_task(coro)

    # 定期检查取消状态
    while not task.done():
        try:
            await asyncio.wait_for(
                cancel_event.wait(),
                timeout=check_interval
            )
            # 如果等待完成（未超时），说明收到取消信号
            if CancelCoordinator.is_cancelled(task_id):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                raise asyncio.CancelledError(f"任务已取消: {task_id}")
        except asyncio.TimeoutError:
            # 超时继续检查
            if task.done():
                break

    return await task
```

---

## 7. 第四阶段：高级特性（Week 7-8）

### 7.1 任务清单

- [ ] 7.1.1 实现分布式追踪（2天）
- [ ] 7.1.2 添加性能监控（2天）
- [ ] 7.1.3 实现高级特性（2天）
- [ ] 7.1.4 文档和部署（2天）

### 7.2 分布式追踪实现

**修改文件**: `agent-service/app/core/execution_context.py`

```python
"""
分布式追踪 - OpenTelemetry 集成
"""
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.jaeger.thrift import JaegerExporter

# 初始化 Tracer
def init_tracer(service_name: str = "ctx-audit"):
    """初始化分布式追踪"""
    resource = Resource(attributes={
        "service.name": service_name,
    })

    provider = TracerProvider(resource=resource)

    # 导出到 Jaeger（可选）
    # jaeger_exporter = JaegerExporter(
    #     agent_host_name="localhost",
    #     agent_port=6831,
    # )
    # provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))

    trace.set_tracer_provider(provider)
    return trace.get_tracer(__name__)

tracer = init_tracer()

@dataclass
class ExecutionContext:
    """执行上下文 - 支持分布式追踪"""
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    task_id: str = ""
    trace_path: List[str] = field(default_factory=list)
    parent_agent_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 新增：OpenTelemetry Span
    span: Optional[Any] = None

    def child_context(
        self,
        agent_id: str,
        agent_name: str,
        **extra_metadata
    ) -> 'ExecutionContext':
        """创建子上下文（带 Span）"""
        from opentelemetry import trace

        # 创建子 Span
        with tracer.start_as_current_span(
            f"{agent_name}.{agent_id}",
            attributes={
                "agent.id": agent_id,
                "agent.name": agent_name,
                "parent.agent": self.parent_agent_id or "",
            }
        ) as span:
            return ExecutionContext(
                correlation_id=self.correlation_id,
                task_id=self.task_id,
                trace_path=self.trace_path + [f"{agent_name}:{agent_id}"],
                parent_agent_id=agent_id,
                metadata={**self.metadata, **extra_metadata},
                span=span,
            )
```

---

## 8. 测试与验证

### 8.1 单元测试

### 8.2 集成测试

### 8.3 性能测试

---

## 9. 部署与监控

### 9.1 部署指南

### 9.2 监控配置

---

## 10. 风险评估

### 10.1 技术风险

### 10.2 业务风险

---

## 附录

### A. 完整的依赖清单

### B. 工具安装指南

### C. 配置示例
