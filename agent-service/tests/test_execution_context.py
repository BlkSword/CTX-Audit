"""
ExecutionContext 单元测试
"""
import pytest
import asyncio
from datetime import datetime, timezone

from app.core.execution_context import (
    ExecutionContext,
    ExecutionContextManager,
    ExecutionContextState,
    AuditStage,
    TraceSpan,
    get_execution_context_manager,
)


class TestExecutionContext:
    """ExecutionContext 测试"""

    def test_create_context(self):
        """测试创建上下文"""
        context = ExecutionContext(
            project_id="test_project",
            project_path="/test/path",
        )

        assert context.audit_id.startswith("audit_")
        assert context.project_id == "test_project"
        assert context.project_path == "/test/path"
        assert context.state == ExecutionContextState.CREATED
        assert context.current_stage == AuditStage.INIT

    def test_lifecycle(self):
        """测试生命周期管理"""
        context =ExecutionContext(audit_id="test_audit")

        # 开始
        context.start()
        assert context.state == ExecutionContextState.RUNNING
        assert context.started_at is not None

        # 暂停
        context.pause()
        assert context.state == ExecutionContextState.PAUSED

        # 恢复
        context.resume()
        assert context.state == ExecutionContextState.RUNNING

        # 完成
        context.complete()
        assert context.state == ExecutionContextState.COMPLETED
        assert context.completed_at is not None

    def test_fail(self):
        """测试失败状态"""
        context = ExecutionContext(audit_id="test_audit")
        context.start()
        context.fail("测试错误")

        assert context.state == ExecutionContextState.FAILED
        assert len(context.errors) == 1
        assert "测试错误" in context.errors[0]

    def test_cancel(self):
        """测试取消状态"""
        context = ExecutionContext(audit_id="test_audit")
        context.start()
        context.cancel()

        assert context.state == ExecutionContextState.CANCELLED

    def test_stage_management(self):
        """测试阶段管理"""
        context = ExecutionContext(audit_id="test_audit")

        # 设置阶段
        context.set_stage(AuditStage.RECON)
        assert context.current_stage == AuditStage.RECON

        # 更新进度
        context.update_stage_progress(AuditStage.RECON, 50.0)
        assert context.stage_progress[AuditStage.RECON] == 50.0

        # 获取整体进度
        progress = context.get_overall_progress()
        assert 0 <= progress <= 100

    def test_span_tracking(self):
        """测试跨度追踪"""
        context = ExecutionContext(audit_id="test_audit")

        # 开始跨度
        span_id = context.start_span(
            agent_id="agent_1",
            agent_type="recon",
            stage=AuditStage.RECON,
        )
        assert span_id.startswith("span_")
        assert context.active_span_id == span_id
        assert len(context.spans) == 1

        # 结束跨度
        context.end_span(span_id, status="completed", tokens_used=100, tool_calls=5)
        span = next(s for s in context.spans if s.span_id == span_id)
        assert span.status == "completed"
        assert span.tokens_used == 100
        assert span.tool_calls == 5
        assert span.duration_ms is not None

    def test_nested_spans(self):
        """测试嵌套跨度"""
        context = ExecutionContext(audit_id="test_audit")

        # 父跨度
        parent_id = context.start_span(
            agent_id="orchestrator",
            agent_type="orchestrator",
            stage=AuditStage.INIT,
        )

        # 子跨度
        child_id = context.start_span(
            agent_id="recon_1",
            agent_type="recon",
            stage=AuditStage.RECON,
            parent_span_id=parent_id,
        )

        child_span = next(s for s in context.spans if s.span_id == child_id)
        assert child_span.parent_span_id == parent_id

        # 获取跨度树
        tree = context.get_span_tree()
        assert len(tree) == 1
        assert len(tree[0]['children']) == 1

    def test_finding_management(self):
        """测试漏洞发现管理"""
        context = ExecutionContext(audit_id="test_audit")

        # 添加漏洞
        finding1 = {
            "file_path": "/test/file.py",
            "line_number": 10,
            "vulnerability_type": "sql_injection",
            "severity": "high",
        }
        assert context.add_finding(finding1) is True
        assert len(context.findings) == 1

        # 重复漏洞应该被拒绝
        assert context.add_finding(finding1) is False
        assert len(context.findings) == 1

        # 不同漏洞应该被接受
        finding2 = {
            "file_path": "/test/file2.py",
            "line_number": 20,
            "vulnerability_type": "xss",
            "severity": "medium",
        }
        assert context.add_finding(finding2) is True
        assert len(context.findings) == 2

    def test_get_findings_by_severity(self):
        """测试按严重程度获取漏洞"""
        context = ExecutionContext(audit_id="test_audit")

        findings = [
            {"severity": "critical", "title": "Critical Bug"},
            {"severity": "high", "title": "High Bug"},
            {"severity": "medium", "title": "Medium Bug"},
            {"severity": "critical", "title": "Another Critical"},
        ]
        for f in findings:
            context.add_finding({**f, "file_path": "test", "line_number": 1, "vulnerability_type": "test"})

        critical = context.get_critical_findings()
        assert len(critical) == 2

        high = context.get_findings_by_severity("high")
        assert len(high) == 1

    def test_statistics(self):
        """测试统计管理"""
        context = ExecutionContext(audit_id="test_audit")

        context.add_tokens(100)
        assert context.total_tokens == 100

        context.add_tokens(50)
        assert context.total_tokens == 150

        context.add_tool_call()
        assert context.total_tool_calls == 1

        context.increment_files_scanned(10)
        assert context.total_files_scanned == 10

    def test_serialization(self):
        """测试序列化"""
        context = ExecutionContext(
            audit_id="test_audit",
            project_id="test_project",
        )
        context.start()
        context.set_stage(AuditStage.RECON)

        # 转字典
        data = context.to_dict()
        assert data["audit_id"] == "test_audit"
        assert data["project_id"] == "test_project"
        assert data["state"] == "running"

        # 转 JSON
        json_str = context.to_json()
        assert "test_audit" in json_str

        # 从字典恢复
        restored = ExecutionContext.from_dict(data)
        assert restored.audit_id == "test_audit"
        assert restored.state == ExecutionContextState.RUNNING

        # 从 JSON 恢复
        restored_from_json = ExecutionContext.from_json(json_str)
        assert restored_from_json.audit_id == "test_audit"


class TestExecutionContextManager:
    """ExecutionContextManager 测试"""

    @pytest.mark.asyncio
    async def test_create_and_get_context(self):
        """测试创建和获取上下文"""
        manager = ExecutionContextManager()

        context = await manager.create_context(
            project_id="test_project",
            project_path="/test/path",
        )

        assert context.audit_id.startswith("audit_")
        assert context.project_id == "test_project"

        # 获取上下文
        retrieved = await manager.get_context(context.audit_id)
        assert retrieved is not None
        assert retrieved.audit_id == context.audit_id

    @pytest.mark.asyncio
    async def test_update_context(self):
        """测试更新上下文"""
        manager = ExecutionContextManager()

        context = await manager.create_context(project_id="test_project")

        # 更新
        success = await manager.update_context(
            context.audit_id,
            {"current_stage": AuditStage.RECON}
        )
        assert success is True

        # 验证更新
        retrieved = await manager.get_context(context.audit_id)
        assert retrieved.current_stage == AuditStage.RECON

    @pytest.mark.asyncio
    async def test_delete_context(self):
        """测试删除上下文"""
        manager = ExecutionContextManager()

        context = await manager.create_context(project_id="test_project")

        # 删除
        success = await manager.delete_context(context.audit_id)
        assert success is True

        # 验证删除
        retrieved = await manager.get_context(context.audit_id)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_get_all_contexts(self):
        """测试获取所有上下文"""
        manager = ExecutionContextManager()

        ctx1 = await manager.create_context(project_id="project1")
        ctx2 = await manager.create_context(project_id="project2")

        all_contexts = await manager.get_all_contexts()
        assert len(all_contexts) == 2


class TestTraceSpan:
    """TraceSpan 测试"""

    def test_create_span(self):
        """测试创建跨度"""
        span = TraceSpan(
            agent_id="agent_1",
            agent_type="recon",
            stage=AuditStage.RECON,
        )

        assert span.span_id.startswith("span_")
        assert span.agent_id == "agent_1"
        assert span.agent_type == "recon"
        assert span.stage == AuditStage.RECON
        assert span.status == "running"
        assert span.start_time is not None

    def test_span_to_dict(self):
        """测试跨度转字典"""
        span = TraceSpan(
            agent_id="agent_1",
            agent_type="recon",
            stage=AuditStage.RECON,
        )

        data = span.to_dict()
        assert data["agent_id"] == "agent_1"
        assert data["agent_type"] == "recon"
        assert data["stage"] == AuditStage.RECON
