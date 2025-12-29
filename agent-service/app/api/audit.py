"""
审计 API 端点（集成 Agent）

处理 Agent 审计任务的创建、状态查询和结果获取
"""
from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
import uuid
import asyncio
import json

from app.agents.orchestrator import OrchestratorAgent
from app.agents.recon import ReconAgent
from app.agents.analysis import AnalysisAgent
from app.services.database import (
    create_audit_session,
    update_audit_status,
    get_audit_session,
)
from app.services.event_bus import get_event_bus, EventType, create_status_event

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

    # 处理 LLM 配置 - 从内存中获取完整配置
    config = request.config or {}
    llm_config_id = config.get("llm_config_id")

    if llm_config_id:
        # 从 LLM API 的内存中获取完整配置
        from app.api import llm as llm_api
        llm_configs = llm_api._llm_configs

        if llm_config_id in llm_configs:
            llm_config = llm_configs[llm_config_id]
            # 将 LLM 配置信息合并到 config 中
            config["llm_provider"] = llm_config.provider
            config["llm_model"] = llm_config.model
            config["api_key"] = llm_config.api_key
            config["base_url"] = llm_config.api_endpoint
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"LLM 配置不存在: {llm_config_id}"
            )

    # 创建数据库记录
    try:
        await create_audit_session(
            audit_id=audit_id,
            project_id=request.project_id,
            audit_type=request.audit_type,
            config=config,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"创建审计会话失败: {str(e)}"
        )

    # 发布审计开始事件
    await create_status_event(audit_id, "pending", "审计任务已创建，正在初始化...")

    # 在后台执行审计
    background_tasks.add_task(
        _execute_audit,
        audit_id=audit_id,
        project_id=request.project_id,
        audit_type=request.audit_type,
        target_types=request.target_types,
        config=config,
    )

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
    from loguru import logger
    event_bus = get_event_bus()

    async def event_generator():
        """生成 SSE 事件流"""
        try:
            # 发送初始连接事件
            yield f"event: connected\ndata: {json.dumps({'audit_id': audit_id, 'message': '连接成功'})}\n\n"

            # 订阅事件流
            async for event in event_bus.subscribe(audit_id):
                # 根据 event_type 发送不同的事件类型
                sse_event = event.event_type

                # 构建事件数据
                event_data = event.to_dict()

                # 发送 SSE 格式数据
                yield f"event: {sse_event}\ndata: {json.dumps(event_data, ensure_ascii=False)}\n\n"

        except asyncio.CancelledError:
            # 客户端断开连接，正常关闭
            logger.debug(f"SSE 连接正常断开: {audit_id}")
            raise  # 重新抛出以正确清理资源
        except Exception as e:
            logger.error(f"SSE 流错误: {e}")
            try:
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
            except Exception:
                pass  # 客户端可能已经断开

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # 禁用 Nginx 缓冲
        },
    )


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
        await create_status_event(audit_id, "running", "审计任务开始执行...")

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
            await create_status_event(audit_id, "completed", "审计任务已完成")
        else:
            await update_audit_status(audit_id, "failed")
            await create_status_event(audit_id, "failed", f"审计失败: {result.get('error', '未知错误')}")

    except Exception as e:
        from loguru import logger
        logger.error(f"审计执行失败: {e}")
        await update_audit_status(audit_id, "failed")
        await create_status_event(audit_id, "failed", f"审计异常: {str(e)}")


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
