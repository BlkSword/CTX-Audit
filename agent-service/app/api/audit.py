"""
审计 API 端点（集成 Agent）

处理 Agent 审计任务的创建、状态查询和结果获取
"""
from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List
import uuid

from app.agents.orchestrator import OrchestratorAgent
from app.agents.recon import ReconAgent
from app.agents.analysis import AnalysisAgent
from app.services.database import (
    create_audit_session,
    update_audit_status,
    get_audit_session,
)
from app.services.queue import publish_event

router = APIRouter()


# ========== 请求/响应模型 ==========

class AuditStartRequest(BaseModel):
    """启动审计请求"""
    project_id: str
    audit_type: str = "full"  # full | quick | targeted
    target_types: Optional[List[str]] = None
    config: Optional[dict] = None


class AuditStartResponse(BaseModel):
    """启动审计响应"""
    audit_id: str
    status: str
    estimated_time: int


class AuditStatusResponse(BaseModel):
    """审计状态响应"""
    audit_id: str
    status: str  # pending | running | completed | failed
    progress: dict
    agent_status: dict
    stats: dict


# ========== API 端点 ==========

@router.post("/start", response_model=AuditStartResponse, status_code=status.HTTP_201_CREATED)
async def start_audit(request: AuditStartRequest, background_tasks: BackgroundTasks):
    """
    启动新的审计任务

    将任务提交给 Orchestrator Agent 进行编排和执行
    """
    # 生成审计 ID
    audit_id = f"audit_{uuid.uuid4().hex[:12]}"

    # 创建数据库记录
    try:
        await create_audit_session(
            audit_id=audit_id,
            project_id=request.project_id,
            audit_type=request.audit_type,
            config=request.config or {},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"创建审计会话失败: {str(e)}"
        )

    # 在后台执行审计
    background_tasks.add_task(
        _execute_audit,
        audit_id=audit_id,
        project_id=request.project_id,
        audit_type=request.audit_type,
        target_types=request.target_types,
        config=request.config or {},
    )

    # 发布事件
    await publish_event("audit:started", {"audit_id": audit_id})

    return AuditStartResponse(
        audit_id=audit_id,
        status="pending",
        estimated_time=300,
    )


@router.get("/{audit_id}/status", response_model=AuditStatusResponse)
async def get_audit_status(audit_id: str):
    """获取审计任务状态"""
    session = await get_audit_session(audit_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )

    return AuditStatusResponse(
        audit_id=audit_id,
        status=session.get("status", "unknown"),
        progress={
            "current_stage": session.get("status", "unknown"),
            "percentage": 0,  # TODO: 从数据库获取实际进度
        },
        agent_status={
            "orchestrator": "idle",
            "recon": "pending",
            "analysis": "pending",
        },
        stats={
            "files_scanned": 0,
            "findings_detected": 0,
            "verified_vulnerabilities": 0,
        },
    )


@router.get("/{audit_id}/result")
async def get_audit_result(audit_id: str):
    """获取审计结果"""
    from app.services.database import get_findings

    session = await get_audit_session(audit_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )

    findings = await get_findings(audit_id)

    return {
        "audit_id": audit_id,
        "status": session.get("status"),
        "summary": {
            "total_vulnerabilities": len(findings),
            "by_severity": _group_by_severity(findings),
        },
        "vulnerabilities": findings,
    }


@router.get("/{audit_id}/stream")
async def stream_audit(audit_id: str):
    """
    订阅审计流（SSE）

    实时推送 Agent 思考链、进度更新等事件
    """
    # TODO: 实现 SSE 流
    return {
        "message": "SSE stream endpoint - to be implemented",
        "audit_id": audit_id,
    }


# ========== 内部函数 ==========

async def _execute_audit(
    audit_id: str,
    project_id: str,
    audit_type: str,
    target_types: Optional[List[str]],
    config: dict,
):
    """
    执行审计任务（后台任务）

    Args:
        audit_id: 审计 ID
        project_id: 项目 ID
        audit_type: 审计类型
        target_types: 目标漏洞类型
        config: 配置
    """
    try:
        # 更新状态为运行中
        await update_audit_status(audit_id, "running")

        # 创建上下文
        context = {
            "audit_id": audit_id,
            "project_id": project_id,
            "audit_type": audit_type,
            "target_types": target_types,
            "config": config,
        }

        # TODO: 执行完整的审计流程
        # 1. Recon Agent
        # 2. Scanner (Rust backend)
        # 3. Analysis Agent
        # 4. Verification Agent (可选)

        # 简化版本：只调用 Orchestrator
        orchestrator = OrchestratorAgent(config=config)
        result = await orchestrator.run(context)

        # 更新状态
        if result["status"] == "success":
            await update_audit_status(audit_id, "completed")
        else:
            await update_audit_status(audit_id, "failed")

    except Exception as e:
        from loguru import logger
        logger.error(f"审计执行失败: {e}")
        await update_audit_status(audit_id, "failed")


def _group_by_severity(findings: list) -> dict:
    """按严重程度分组统计"""
    grouped = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in grouped:
            grouped[severity] += 1

    return grouped
