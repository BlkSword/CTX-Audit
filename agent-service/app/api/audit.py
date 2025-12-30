"""
审计 API 端点（集成 Agent）

处理 Agent 审计任务的创建、状态查询和结果获取
"""
from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, List
from pathlib import Path
import uuid
import asyncio
import json
import sqlite3
from loguru import logger

from app.agents.orchestrator import OrchestratorAgent
from app.agents.recon import ReconAgent
from app.agents.analysis import AnalysisAgent
from app.services.event_persistence import get_event_persistence
from app.services.event_bus_v2 import get_event_bus_v2, init_event_bus

router = APIRouter()

# 数据库路径（与 settings.py 共享）
DB_DIR = Path(__file__).parent.parent.parent.parent / "data"
DB_PATH = DB_DIR / "settings.db"


# ========== 辅助函数 ==========

async def create_audit_session_sqlite(
    audit_id: str,
    project_id: str,
    audit_type: str,
    config: dict,
) -> None:
    """
    创建审计会话（SQLite 版本）

    Args:
        audit_id: 审计 ID
        project_id: 项目 ID
        audit_type: 审计类型
        config: 配置
    """
    persistence = get_event_persistence()

    def _create():
        with sqlite3.connect(persistence.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audit_sessions
                (id, project_id, audit_type, status, config, updated_at)
                VALUES (?, ?, ?, 'pending', ?, CURRENT_TIMESTAMP)
                """,
                (audit_id, project_id, audit_type, json.dumps(config, ensure_ascii=False))
            )
            conn.commit()

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _create)


async def update_audit_status_sqlite(audit_id: str, status: str) -> None:
    """更新审计状态（SQLite 版本）"""
    persistence = get_event_persistence()

    def _update():
        with sqlite3.connect(persistence.db_path) as conn:
            conn.execute(
                "UPDATE audit_sessions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, audit_id)
            )
            conn.commit()

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _update)


async def get_audit_session_sqlite(audit_id: str) -> Optional[dict]:
    """获取审计会话（SQLite 版本）"""
    persistence = get_event_persistence()

    def _get():
        with sqlite3.connect(persistence.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_sessions WHERE id = ?",
                (audit_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get)

async def _get_llm_config_from_db(config_id: str) -> Optional[dict]:
    """从数据库获取 LLM 配置（包含完整的 API 密钥）"""
    if not DB_PATH.exists():
        return None

    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT provider, model, api_key, api_endpoint FROM llm_configs WHERE id = ?",
            (config_id,)
        )
        row = cursor.fetchone()

        conn.close()

        if row:
            return {
                "provider": row["provider"],
                "model": row["model"],
                "api_key": row["api_key"],
                "api_endpoint": row["api_endpoint"],
            }
        return None
    except Exception as e:
        from loguru import logger
        logger.error(f"获取 LLM 配置失败: {e}")
        return None


async def _get_default_llm_config_from_db() -> Optional[dict]:
    """从数据库获取默认 LLM 配置"""
    if not DB_PATH.exists():
        return None

    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT provider, model, api_key, api_endpoint FROM llm_configs WHERE is_default = 1 ORDER BY updated_at DESC LIMIT 1"
        )
        row = cursor.fetchone()

        conn.close()

        if row:
            return {
                "provider": row["provider"],
                "model": row["model"],
                "api_key": row["api_key"],
                "api_endpoint": row["api_endpoint"],
            }
        return None
    except Exception as e:
        from loguru import logger
        logger.error(f"获取默认 LLM 配置失败: {e}")
        return None


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

    # 处理 LLM 配置 - 从数据库获取完整配置
    config = dict(request.config or {})
    llm_config_id = config.get("llm_config_id")

    # 如果没有指定 llm_config_id，尝试加载默认配置
    if not llm_config_id:
        llm_config = await _get_default_llm_config_from_db()
        if llm_config:
            config["llm_provider"] = llm_config["provider"]
            config["llm_model"] = llm_config["model"]
            config["api_key"] = llm_config["api_key"]
            config["base_url"] = llm_config.get("api_endpoint")
            logger.info(f"已加载默认 LLM 配置: provider={llm_config['provider']}, model={llm_config['model']}")
        else:
            logger.warning("未找到 LLM 配置，将使用模拟模式")
    elif llm_config_id != "default":
        # 从数据库获取指定的 LLM 配置
        llm_config = await _get_llm_config_from_db(llm_config_id)
        if llm_config:
            # 将 LLM 配置信息合并到 config 中
            config["llm_provider"] = llm_config["provider"]
            config["llm_model"] = llm_config["model"]
            config["api_key"] = llm_config["api_key"]
            config["base_url"] = llm_config.get("api_endpoint")
            logger.info(f"LLM 配置已加载: provider={llm_config['provider']}, model={llm_config['model']}, api_key={'*' * 8}{llm_config['api_key'][-4:]}")
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"LLM 配置不存在: {llm_config_id}"
            )
    else:
        # llm_config_id 是 "default"，加载默认配置
        llm_config = await _get_default_llm_config_from_db()
        if llm_config:
            config["llm_provider"] = llm_config["provider"]
            config["llm_model"] = llm_config["model"]
            config["api_key"] = llm_config["api_key"]
            config["base_url"] = llm_config.get("api_endpoint")
            logger.info(f"已加载默认 LLM 配置: provider={llm_config['provider']}, model={llm_config['model']}")
        else:
            logger.warning("未找到默认 LLM 配置，将使用模拟模式")

    # 创建数据库记录
    try:
        await create_audit_session_sqlite(
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
    event_bus = get_event_bus_v2()
    await event_bus.publish(
        audit_id=audit_id,
        agent_type="system",
        event_type="status",
        data={"status": "pending", "message": "审计任务已创建，正在初始化..."},
        message="审计任务已创建，正在初始化...",
    )

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
    session = await get_audit_session_sqlite(audit_id)

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
    from app.services.event_persistence import get_event_persistence

    session = await get_audit_session_sqlite(audit_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"审计任务不存在: {audit_id}"
        )

    persistence = get_event_persistence()
    findings = persistence.get_findings(audit_id)

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
async def stream_audit(audit_id: str, after_sequence: int = 0):
    """
    订阅审计流（SSE）

    实时推送 Agent 思考链、进度更新等事件

    Args:
        audit_id: 审计 ID
        after_sequence: 从哪个序列号开始（用于断线重连）
    """
    from app.services.event_bus_v2 import get_event_bus_v2

    event_bus = get_event_bus_v2()

    async def event_generator():
        """生成 SSE 事件流"""
        try:
            # 发送初始连接事件
            yield f"event: connected\ndata: {json.dumps({'audit_id': audit_id, 'message': 'SSE 连接成功'}, ensure_ascii=False)}\n\n"

            # 订阅事件流
            async for event in event_bus.subscribe(audit_id, after_sequence=after_sequence):
                event_type = event.get("event_type", "unknown")

                # 发送 SSE 格式数据
                yield f"event: {event_type}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"

        except asyncio.CancelledError:
            # 客户端断开连接，正常关闭
            logger.info(f"SSE 连接断开: {audit_id}")
            raise
        except Exception as e:
            logger.error(f"SSE 流错误: {e}", exc_info=True)
            try:
                yield f"event: error\ndata: {json.dumps({'error': str(e)}, ensure_ascii=False)}\n\n"
            except Exception:
                pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{audit_id}/events")
async def get_audit_events(
    audit_id: str,
    after_sequence: int = 0,
    limit: int = 100,
    event_types: Optional[str] = None,
):
    """
    获取审计历史事件（从数据库）

    用于断线重连或查看历史事件

    Args:
        audit_id: 审计 ID
        after_sequence: 起始序列号
        limit: 返回数量限制（最大 1000）
        event_types: 事件类型过滤（逗号分隔）
    """
    from app.services.event_persistence import get_event_persistence

    persistence = get_event_persistence()

    # 解析事件类型过滤
    event_type_list = None
    if event_types:
        event_type_list = event_types.split(",")

    # 限制最大返回数量
    limit = min(limit, 1000)

    # 获取历史事件
    events = persistence.get_events(
        audit_id=audit_id,
        after_sequence=after_sequence,
        limit=limit,
        event_types=event_type_list,
    )

    return {
        "audit_id": audit_id,
        "count": len(events),
        "events": events,
    }


@router.get("/{audit_id}/events/stats")
async def get_audit_events_stats(audit_id: str):
    """
    获取审计事件统计

    Args:
        audit_id: 审计 ID
    """
    from app.services.event_persistence import get_event_persistence

    persistence = get_event_persistence()

    # 获取统计信息
    stats = persistence.get_statistics(audit_id=audit_id)

    # 获取最新序列号
    latest_seq = persistence.get_latest_sequence(audit_id)

    return {
        "audit_id": audit_id,
        "latest_sequence": latest_seq,
        "statistics": stats,
    }


@router.post("/{audit_id}/pause")
async def pause_audit(audit_id: str):
    """
    暂停审计任务

    Args:
        audit_id: 审计 ID

    Returns:
        操作结果
    """
    # 更新状态为暂停
    await update_audit_status_sqlite(audit_id, "paused")

    # 发布暂停事件
    event_bus = get_event_bus_v2()
    await event_bus.publish(
        audit_id=audit_id,
        agent_type="system",
        event_type="status",
        data={"status": "paused", "message": "审计任务已暂停"},
        message="审计任务已暂停",
    )

    return {"success": True, "message": "审计已暂停"}


@router.post("/{audit_id}/cancel")
async def cancel_audit(audit_id: str):
    """
    终止审计任务

    Args:
        audit_id: 审计 ID

    Returns:
        操作结果
    """
    # 更新状态为已取消
    await update_audit_status_sqlite(audit_id, "cancelled")

    # 发布终止事件
    event_bus = get_event_bus_v2()
    await event_bus.publish(
        audit_id=audit_id,
        agent_type="system",
        event_type="cancelled",
        data={"status": "cancelled", "message": "审计任务已终止"},
        message="审计任务已终止",
    )

    return {"success": True, "message": "审计已终止"}


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
        await update_audit_status_sqlite(audit_id, "running")

        event_bus = get_event_bus_v2()
        await event_bus.publish(
            audit_id=audit_id,
            agent_type="system",
            event_type="status",
            data={"status": "running", "message": "审计任务开始执行..."},
            message="审计任务开始执行...",
        )

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
        event_bus = get_event_bus_v2()
        if result["status"] == "success":
            await update_audit_status_sqlite(audit_id, "completed")
            await event_bus.publish(
                audit_id=audit_id,
                agent_type="system",
                event_type="status",
                data={"status": "completed", "message": "审计任务已完成"},
                message="审计任务已完成",
            )
        else:
            await update_audit_status_sqlite(audit_id, "failed")
            await event_bus.publish(
                audit_id=audit_id,
                agent_type="system",
                event_type="status",
                data={"status": "failed", "message": f"审计失败: {result.get('error', '未知错误')}"},
                message=f"审计失败: {result.get('error', '未知错误')}",
            )

    except Exception as e:
        from loguru import logger
        logger.error(f"审计执行失败: {e}")
        await update_audit_status_sqlite(audit_id, "failed")
        event_bus = get_event_bus_v2()
        await event_bus.publish(
            audit_id=audit_id,
            agent_type="system",
            event_type="status",
            data={"status": "failed", "message": f"审计异常: {str(e)}"},
            message=f"审计异常: {str(e)}",
        )


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
