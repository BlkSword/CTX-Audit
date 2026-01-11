"""
ExecutionContext - 审计执行上下文系统

提供审计会话级别的完整上下文管理，支持：
- 审计会话的完整生命周期管理
- 分布式追踪（所有 Agent 的执行路径）
- 中间状态存储（Recon、Analysis 等阶段的中间结果）
- 断线重连和状态恢复
- 全局统计和性能监控

参考 DeepAudit-3.0.0 实现
"""
import asyncio
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field
from loguru import logger
import json

from app.services.event_persistence import EventPersistence, get_event_persistence


class AuditStage(str, Enum):
    """审计阶段"""
    INIT = "init"                 # 初始化
    RECON = "recon"               # 侦察阶段
    ANALYSIS = "analysis"         # 分析阶段
    VERIFICATION = "verification" # 验证阶段
    REPORT = "report"             # 报告生成
    COMPLETE = "complete"         # 完成


class ExecutionContextState(str, Enum):
    """上下文状态"""
    CREATED = "created"       # 已创建
    RUNNING = "running"       # 运行中
    PAUSED = "paused"         # 已暂停
    COMPLETED = "completed"   # 已完成
    FAILED = "failed"         # 失败
    CANCELLED = "cancelled"   # 已取消


class TraceSpan(BaseModel):
    """追踪跨度（记录单个 Agent 的执行）"""
    span_id: str = Field(default_factory=lambda: f"span_{uuid.uuid4().hex[:8]}")
    parent_span_id: Optional[str] = None
    agent_id: str
    agent_type: str
    stage: AuditStage
    start_time: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: Optional[str] = None
    status: str = "running"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # 性能指标
    tokens_used: int = 0
    tool_calls: int = 0
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "stage": self.stage,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "metadata": self.metadata,
            "tokens_used": self.tokens_used,
            "tool_calls": self.tool_calls,
            "duration_ms": self.duration_ms,
        }


class ExecutionContext(BaseModel):
    """
    审计执行上下文

    管理整个审计会话的状态，支持分布式追踪和状态恢复
    """

    # ============ 基本信息 ============
    audit_id: str = Field(default_factory=lambda: f"audit_{uuid.uuid4().hex[:8]}")
    project_id: str = ""
    project_path: str = ""
    state: ExecutionContextState = ExecutionContextState.CREATED

    # ============ 审计配置 ============
    audit_type: str = "full"  # full, quick, custom
    config: Dict[str, Any] = Field(default_factory=dict)

    # ============ 当前阶段 ============
    current_stage: AuditStage = AuditStage.INIT
    stage_progress: Dict[AuditStage, float] = Field(
        default_factory=lambda: {
            AuditStage.INIT: 0.0,
            AuditStage.RECON: 0.0,
            AuditStage.ANALYSIS: 0.0,
            AuditStage.VERIFICATION: 0.0,
            AuditStage.REPORT: 0.0,
            AuditStage.COMPLETE: 0.0,
        }
    )

    # ============ 分布式追踪 ============
    spans: List[TraceSpan] = Field(default_factory=list)
    active_span_id: Optional[str] = None

    # ============ 中间状态存储 ============
    # Recon 结果
    recon_results: Dict[str, Any] = Field(default_factory=dict)
    # Analysis 结果
    analysis_results: Dict[str, Any] = Field(default_factory=dict)
    # Verification 结果
    verification_results: Dict[str, Any] = Field(default_factory=dict)

    # ============ 漏洞发现 ============
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    # 去重缓存
    finding_hashes: Set[str] = Field(default_factory=set)

    # ============ 全局统计 ============
    total_tokens: int = 0
    total_tool_calls: int = 0
    total_files_scanned: int = 0
    total_findings: int = 0

    # ============ 时间戳 ============
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ============ 错误和日志 ============
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    # ============ 元数据 ============
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True
        arbitrary_types_allowed = True  # 允许 Set 类型

    # ============ 生命周期管理 ============

    def start(self) -> None:
        """开始审计"""
        self.state = ExecutionContextState.RUNNING
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._update_timestamp()
        logger.info(f"[ExecutionContext] 审计 {self.audit_id} 开始")

    def complete(self) -> None:
        """完成审计"""
        self.state = ExecutionContextState.COMPLETED
        self.current_stage = AuditStage.COMPLETE
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self._update_timestamp()
        logger.info(f"[ExecutionContext] 审计 {self.audit_id} 完成")

    def fail(self, error: str) -> None:
        """审计失败"""
        self.state = ExecutionContextState.FAILED
        self.add_error(error)
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self._update_timestamp()
        logger.error(f"[ExecutionContext] 审计 {self.audit_id} 失败: {error}")

    def cancel(self) -> None:
        """取消审计"""
        self.state = ExecutionContextState.CANCELLED
        self.completed_at = datetime.now(timezone.utc).isoformat()
        self._update_timestamp()
        logger.info(f"[ExecutionContext] 审计 {self.audit_id} 已取消")

    def pause(self) -> None:
        """暂停审计"""
        self.state = ExecutionContextState.PAUSED
        self._update_timestamp()
        logger.info(f"[ExecutionContext] 审计 {self.audit_id} 已暂停")

    def resume(self) -> None:
        """恢复审计"""
        self.state = ExecutionContextState.RUNNING
        self._update_timestamp()
        logger.info(f"[ExecutionContext] 审计 {self.audit_id} 已恢复")

    # ============ 阶段管理 ============

    def set_stage(self, stage: AuditStage) -> None:
        """设置当前阶段"""
        logger.info(f"[ExecutionContext] 审计 {self.audit_id} 进入阶段: {stage}")
        self.current_stage = stage
        self._update_timestamp()

    def update_stage_progress(self, stage: AuditStage, progress: float) -> None:
        """更新阶段进度"""
        self.stage_progress[stage] = min(100.0, max(0.0, progress))
        self._update_timestamp()

    def get_overall_progress(self) -> float:
        """获取整体进度"""
        # 权重分配：Init 5%, Recon 25%, Analysis 50%, Verification 15%, Report 5%
        weights = {
            AuditStage.INIT: 0.05,
            AuditStage.RECON: 0.25,
            AuditStage.ANALYSIS: 0.50,
            AuditStage.VERIFICATION: 0.15,
            AuditStage.REPORT: 0.05,
        }
        total = sum(self.stage_progress.get(stage, 0) * weight
                   for stage, weight in weights.items())
        return min(100.0, total)

    # ============ 分布式追踪 ============

    def start_span(
        self,
        agent_id: str,
        agent_type: str,
        stage: AuditStage,
        parent_span_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """开始一个新的追踪跨度"""
        span = TraceSpan(
            agent_id=agent_id,
            agent_type=agent_type,
            stage=stage,
            parent_span_id=parent_span_id or self.active_span_id,
            metadata=metadata or {},
        )
        self.spans.append(span)
        self.active_span_id = span.span_id
        self._update_timestamp()
        logger.debug(f"[ExecutionContext] 开始追踪跨度: {span.span_id} ({agent_type})")
        return span.span_id

    def end_span(
        self,
        span_id: str,
        status: str = "completed",
        tokens_used: int = 0,
        tool_calls: int = 0,
    ) -> None:
        """结束追踪跨度"""
        for span in self.spans:
            if span.span_id == span_id:
                span.end_time = datetime.now(timezone.utc).isoformat()
                span.status = status
                span.tokens_used = tokens_used
                span.tool_calls = tool_calls

                # 计算持续时间
                try:
                    start = datetime.fromisoformat(span.start_time.replace('Z', '+00:00'))
                    end = datetime.fromisoformat(span.end_time.replace('Z', '+00:00'))
                    span.duration_ms = int((end - start).total_seconds() * 1000)
                except:
                    pass

                break

        if self.active_span_id == span_id:
            # 查找父跨度
            span = next((s for s in self.spans if s.span_id == span_id), None)
            if span:
                self.active_span_id = span.parent_span_id

        self._update_timestamp()
        logger.debug(f"[ExecutionContext] 结束追踪跨度: {span_id}")

    def get_active_span(self) -> Optional[TraceSpan]:
        """获取当前活跃的跨度"""
        if not self.active_span_id:
            return None
        return next((s for s in self.spans if s.span_id == self.active_span_id), None)

    def get_span_tree(self) -> List[Dict[str, Any]]:
        """获取跨度树（用于可视化）"""
        def build_tree(parent_id: Optional[str]) -> List[Dict[str, Any]]:
            children = []
            for span in self.spans:
                if span.parent_span_id == parent_id:
                    node = span.to_dict()
                    node['children'] = build_tree(span.span_id)
                    children.append(node)
            return children

        return build_tree(None)

    # ============ 中间状态存储 ============

    def store_recon_result(self, key: str, value: Any) -> None:
        """存储 Recon 结果"""
        self.recon_results[key] = value
        self._update_timestamp()

    def get_recon_result(self, key: str, default: Any = None) -> Any:
        """获取 Recon 结果"""
        return self.recon_results.get(key, default)

    def store_analysis_result(self, key: str, value: Any) -> None:
        """存储 Analysis 结果"""
        self.analysis_results[key] = value
        self._update_timestamp()

    def get_analysis_result(self, key: str, default: Any = None) -> Any:
        """获取 Analysis 结果"""
        return self.analysis_results.get(key, default)

    def store_verification_result(self, key: str, value: Any) -> None:
        """存储 Verification 结果"""
        self.verification_results[key] = value
        self._update_timestamp()

    def get_verification_result(self, key: str, default: Any = None) -> Any:
        """获取 Verification 结果"""
        return self.verification_results.get(key, default)

    # ============ 漏洞发现管理 ============

    def add_finding(self, finding: Dict[str, Any], hash_key: Optional[str] = None) -> bool:
        """
        添加漏洞发现（自动去重）

        Args:
            finding: 漏洞发现数据
            hash_key: 去重键（如果为 None，自动生成）

        Returns:
            是否添加成功（如果重复则返回 False）
        """
        if hash_key is None:
            # 自动生成去重键
            file_path = finding.get("file_path", "")
            line_number = finding.get("line_number", 0)
            vuln_type = finding.get("vulnerability_type", "")
            hash_key = f"{file_path}:{line_number}:{vuln_type}"

        if hash_key in self.finding_hashes:
            logger.debug(f"[ExecutionContext] 重复的漏洞发现: {hash_key}")
            return False

        finding["discovered_at"] = datetime.now(timezone.utc).isoformat()
        finding["hash_key"] = hash_key
        self.findings.append(finding)
        self.finding_hashes.add(hash_key)
        self.total_findings += 1
        self._update_timestamp()
        return True

    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """按严重程度获取漏洞"""
        return [f for f in self.findings if f.get("severity") == severity]

    def get_critical_findings(self) -> List[Dict[str, Any]]:
        """获取严重漏洞"""
        return self.get_findings_by_severity("critical")

    # ============ 统计管理 ============

    def add_tokens(self, tokens: int) -> None:
        """增加 token 使用量"""
        self.total_tokens += tokens
        self._update_timestamp()

    def add_tool_call(self) -> None:
        """增加工具调用次数"""
        self.total_tool_calls += 1
        self._update_timestamp()

    def increment_files_scanned(self, count: int = 1) -> None:
        """增加扫描文件数"""
        self.total_files_scanned += count
        self._update_timestamp()

    # ============ 错误和警告 ============

    def add_error(self, error: str) -> None:
        """添加错误"""
        self.errors.append(f"[{datetime.now(timezone.utc).isoformat()}] {error}")
        self._update_timestamp()

    def add_warning(self, warning: str) -> None:
        """添加警告"""
        self.warnings.append(f"[{datetime.now(timezone.utc).isoformat()}] {warning}")
        self._update_timestamp()

    # ============ 序列化和持久化 ============

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "audit_id": self.audit_id,
            "project_id": self.project_id,
            "project_path": self.project_path,
            "state": self.state,
            "audit_type": self.audit_type,
            "config": self.config,
            "current_stage": self.current_stage,
            "stage_progress": {str(k): v for k, v in self.stage_progress.items()},
            "spans": [s.to_dict() for s in self.spans],
            "active_span_id": self.active_span_id,
            "recon_results": self.recon_results,
            "analysis_results": self.analysis_results,
            "verification_results": self.verification_results,
            "findings": self.findings,
            "total_tokens": self.total_tokens,
            "total_tool_calls": self.total_tool_calls,
            "total_files_scanned": self.total_files_scanned,
            "total_findings": self.total_findings,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "last_updated": self.last_updated,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """转换为 JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionContext":
        """从字典恢复"""
        # 处理 stage_progress
        stage_progress = data.get("stage_progress", {})
        converted_progress = {}
        for k, v in stage_progress.items():
            if isinstance(k, str):
                converted_progress[AuditStage(k)] = v
            else:
                converted_progress[k] = v
        data["stage_progress"] = converted_progress

        # 处理 spans
        spans_data = data.pop("spans", [])
        context = cls(**data)
        context.spans = [TraceSpan(**s) for s in spans_data]

        # 重建 finding_hashes
        context.finding_hashes = {f.get("hash_key", "") for f in context.findings if "hash_key" in f}

        return context

    @classmethod
    def from_json(cls, json_str: str) -> "ExecutionContext":
        """从 JSON 恢复"""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def _update_timestamp(self) -> None:
        """更新最后修改时间"""
        self.last_updated = datetime.now(timezone.utc).isoformat()


class ExecutionContextManager:
    """
    执行上下文管理器

    管理多个审计会话的上下文，支持：
    - 上下文的创建、获取、删除
    - 持久化到数据库
    - 从历史事件恢复上下文
    """

    def __init__(self, persistence: Optional[EventPersistence] = None):
        """
        初始化管理器

        Args:
            persistence: 事件持久化服务
        """
        self._contexts: Dict[str, ExecutionContext] = {}
        self._persistence = persistence or get_event_persistence()
        self._lock = asyncio.Lock()

    async def create_context(
        self,
        project_id: str,
        project_path: str = "",
        audit_type: str = "full",
        config: Optional[Dict[str, Any]] = None,
    ) -> ExecutionContext:
        """创建新的执行上下文"""
        context = ExecutionContext(
            project_id=project_id,
            project_path=project_path,
            audit_type=audit_type,
            config=config or {},
        )

        async with self._lock:
            self._contexts[context.audit_id] = context

        logger.info(f"[ExecutionContextManager] 创建上下文: {context.audit_id}")
        return context

    async def get_context(self, audit_id: str) -> Optional[ExecutionContext]:
        """获取执行上下文"""
        # 先从内存获取
        if audit_id in self._contexts:
            return self._contexts[audit_id]

        # 尝试从数据库恢复
        context = await self._restore_from_database(audit_id)
        if context:
            async with self._lock:
                self._contexts[audit_id] = context

        return context

    async def update_context(self, audit_id: str, updates: Dict[str, Any]) -> bool:
        """更新上下文"""
        context = await self.get_context(audit_id)
        if not context:
            return False

        for key, value in updates.items():
            if hasattr(context, key):
                setattr(context, key, value)

        context._update_timestamp()
        return True

    async def delete_context(self, audit_id: str) -> bool:
        """删除上下文"""
        async with self._lock:
            if audit_id in self._contexts:
                del self._contexts[audit_id]
                return True
        return False

    async def save_context(self, audit_id: str) -> bool:
        """保存上下文到数据库"""
        context = await self.get_context(audit_id)
        if not context:
            return False

        try:
            # 将上下文作为事件保存
            await self._persistence.save_event({
                "id": f"ctx_{audit_id}",
                "audit_id": audit_id,
                "agent_type": "system",
                "event_type": "context_snapshot",
                "sequence": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": "执行上下文快照",
                "data": context.to_dict(),
            })
            logger.debug(f"[ExecutionContextManager] 保存上下文: {audit_id}")
            return True
        except Exception as e:
            logger.error(f"[ExecutionContextManager] 保存上下文失败: {e}")
            return False

    async def _restore_from_database(self, audit_id: str) -> Optional[ExecutionContext]:
        """从数据库恢复上下文"""
        try:
            # 查找最新的上下文快照
            events = self._persistence.get_events(
                audit_id=audit_id,
                event_types=["context_snapshot"],
                limit=10,
            )

            if not events:
                return None

            # 获取最新的快照
            latest_event = max(events, key=lambda e: e.get("timestamp", ""))
            context_data = latest_event.get("data", {})
            context = ExecutionContext.from_dict(context_data)

            logger.info(f"[ExecutionContextManager] 从数据库恢复上下文: {audit_id}")
            return context

        except Exception as e:
            logger.error(f"[ExecutionContextManager] 恢复上下文失败: {e}")
            return None

    async def restore_from_events(self, audit_id: str) -> Optional[ExecutionContext]:
        """
        从历史事件重建上下文

        用于断线重连时恢复完整的审计状态
        """
        try:
            # 获取所有事件
            events = self._persistence.get_events(
                audit_id=audit_id,
                limit=10000,
            )

            if not events:
                return None

            # 创建新的上下文
            context = ExecutionContext(audit_id=audit_id)

            # 重放事件
            for event in events:
                event_type = event.get("event_type")
                data = event.get("data", {})

                if event_type == "status":
                    # 更新状态
                    status = data.get("status")
                    if status == "running":
                        if not context.started_at:
                            context.start()
                    elif status == "completed":
                        context.complete()
                    elif status == "failed":
                        context.fail(data.get("error", "Unknown error"))

                elif event_type == "finding_new" or event_type == "finding_verified":
                    # 恢复漏洞发现
                    finding = data or {}
                    context.add_finding(finding)

                elif event_type == "span_start":
                    # 恢复追踪跨度
                    context.start_span(
                        agent_id=data.get("agent_id", ""),
                        agent_type=data.get("agent_type", ""),
                        stage=AuditStage(data.get("stage", "analysis")),
                        parent_span_id=data.get("parent_span_id"),
                    )

                elif event_type == "tool_call":
                    context.add_tool_call()

            logger.info(f"[ExecutionContextManager] 从事件重建上下文: {audit_id}")
            return context

        except Exception as e:
            logger.error(f"[ExecutionContextManager] 从事件重建上下文失败: {e}")
            return None

    async def get_all_contexts(self) -> List[ExecutionContext]:
        """获取所有上下文"""
        return list(self._contexts.values())

    async def cleanup(self, audit_id: str) -> None:
        """清理上下文"""
        await self.delete_context(audit_id)
        await self._persistence.delete_events(audit_id)
        logger.info(f"[ExecutionContextManager] 清理上下文: {audit_id}")


# 全局单例
_context_manager: Optional[ExecutionContextManager] = None


def get_execution_context_manager() -> ExecutionContextManager:
    """获取执行上下文管理器单例"""
    global _context_manager
    if _context_manager is None:
        _context_manager = ExecutionContextManager()
    return _context_manager
