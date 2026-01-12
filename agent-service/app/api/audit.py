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


async def get_audit_status_sqlite(audit_id: str) -> Optional[dict]:
    """获取审计状态（SQLite 版本）"""
    return await get_audit_session_sqlite(audit_id)


async def get_audit_result_sqlite(audit_id: str) -> dict:
    """获取审计结果（SQLite 版本）"""
    from app.services.event_persistence import get_event_persistence

    # 获取会话信息
    session = await get_audit_session_sqlite(audit_id)
    if not session:
        return {
            "audit_id": audit_id,
            "status": "not_found",
            "vulnerabilities": [],
        }

    # 获取发现列表
    persistence = get_event_persistence()
    findings = persistence.get_findings(audit_id)

    return {
        "audit_id": audit_id,
        "status": session.get("status", "unknown"),
        "vulnerabilities": findings,
        "total_vulnerabilities": len(findings),
    }

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

    # 新增配置选项
    branch_name: Optional[str] = None  # Git 分支名称
    exclude_patterns: Optional[List[str]] = None  # 排除的文件模式
    target_files: Optional[List[str]] = None  # 目标文件列表
    verification_level: Optional[str] = "basic"  # 验证级别: basic | standard | thorough
    max_iterations: Optional[int] = 50  # 最大迭代次数
    timeout_seconds: Optional[int] = 1800  # 超时时间（秒）
    enable_rag: Optional[bool] = True  # 是否启用 RAG
    parallel_agents: Optional[bool] = False  # 是否启用并行 Agent
    max_parallel_agents: Optional[int] = 3  # 最大并行 Agent 数


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

    # 从数据库获取实际统计数据
    total_tokens = session.get("total_tokens", 0) or 0
    tool_calls = session.get("tool_calls", 0) or 0
    analyzed_files = session.get("analyzed_files", 0) or 0
    findings_detected = session.get("findings_detected", 0) or 0
    progress_percentage = session.get("progress_percentage", 0) or 0

    return AuditStatusResponse(
        audit_id=audit_id,
        status=session.get("status", "unknown"),
        progress={
            "current_stage": session.get("current_stage") or session.get("status", "unknown"),
            "percentage": progress_percentage,
        },
        agent_status={
            "orchestrator": "running" if session.get("status") in ["running", "pending"] else "completed",
            "recon": "pending",
            "analysis": "pending",
        },
        stats={
            "files_scanned": analyzed_files,
            "findings_detected": findings_detected,
            "verified_vulnerabilities": 0,  # TODO: 从验证结果获取
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
    from app.services.streaming import stream_audit_events
    from app.services.event_manager import event_manager

    # 确保事件队列存在
    event_manager.create_queue(audit_id)

    async def event_generator():
        """生成 SSE 事件流"""
        try:
            async for event in stream_audit_events(audit_id, after_sequence):
                yield event
        except asyncio.CancelledError:
            logger.info(f"[SSE] Client disconnected: {audit_id}")
            raise
        except Exception as e:
            logger.error(f"[SSE] Stream error: {e}", exc_info=True)
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


@router.get("/{audit_id}/report")
async def export_audit_report(
    audit_id: str,
    format: str = "markdown",
):
    """
    导出审计报告

    Args:
        audit_id: 审计 ID
        format: 报告格式 (markdown, json, html)

    Returns:
        报告内容
    """
    from fastapi.responses import Response, JSONResponse
    from app.services.report_generator import ReportGenerator
    from app.services.rust_client import rust_client
    from loguru import logger

    try:
        # 获取审计任务信息
        task_info = await get_audit_status_sqlite(audit_id)

        # 获取漏洞发现列表
        result_data = await get_audit_result_sqlite(audit_id)
        findings = result_data.get("vulnerabilities", [])

        # 获取项目信息（如果有 project_id）
        project_info = None
        if task_info and task_info.get("project_id"):
            try:
                project_info = await rust_client.get_project(task_info["project_id"])
            except Exception as e:
                logger.warning(f"获取项目信息失败: {e}")

        # 生成报告
        generator = ReportGenerator()
        format_lower = format.lower()

        if format_lower == "json":
            report = generator.generate_json_report(
                audit_id=audit_id,
                findings=findings,
                task_info=task_info,
                project_info=project_info,
            )
            return JSONResponse(content=report)

        elif format_lower == "html":
            report = generator.generate_html_report(
                audit_id=audit_id,
                findings=findings,
                task_info=task_info,
                project_info=project_info,
            )
            return Response(
                content=report,
                media_type="text/html",
                headers={
                    "Content-Disposition": f"attachment; filename=audit_report_{audit_id}.html"
                }
            )

        else:  # markdown (default)
            report = generator.generate_markdown_report(
                audit_id=audit_id,
                findings=findings,
                task_info=task_info,
                project_info=project_info,
            )

            return Response(
                content=report,
                media_type="text/markdown",
                headers={
                    "Content-Disposition": f"attachment; filename=audit_report_{audit_id}.md"
                }
            )

    except Exception as e:
        logger.error(f"导出报告失败: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": f"导出报告失败: {str(e)}"}
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
        # 获取项目信息（包含路径）
        from app.services.rust_client import rust_client
        project_path = ""
        try:
            project_info = await rust_client.get_project(project_id)
            project_path = project_info.get("path", "")
            logger.info(f"[Audit] 获取项目信息成功: project_id={project_id}, path={project_path}")
        except Exception as e:
            logger.warning(f"[Audit] 获取项目信息失败: {e}")

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
            "project_path": project_path,
            "audit_type": audit_type,
            "target_types": target_types,
            "config": config,
        }

        # ========== 构建AST索引（必须在Agent执行前完成）==========
        if project_path:
            try:
                # 尝试将project_id转换为整数
                project_id_int = None
                try:
                    project_id_int = int(project_id)
                except (ValueError, TypeError):
                    logger.warning(f"无法转换project_id为整数: {project_id}")

                logger.info(f"[Audit] 开始构建AST索引 - project_path={project_path}, project_id={project_id_int}")
                index_result = await rust_client.build_ast_index(
                    project_path=project_path,
                    project_id=project_id_int,
                )
                files_processed = index_result.get("files_processed", 0)
                logger.info(f"[Audit] AST索引构建完成 - 处理了 {files_processed} 个文件")

                # 发布索引构建完成事件
                await event_bus.publish(
                    audit_id=audit_id,
                    agent_type="system",
                    event_type="status",
                    data={"status": "indexing", "message": f"AST索引构建完成，处理了 {files_processed} 个文件"},
                    message=f"AST索引构建完成，处理了 {files_processed} 个文件",
                )
            except Exception as e:
                logger.error(f"[Audit] AST索引构建失败: {e}")
                # 索引构建失败不阻断审计流程，但会记录警告
                await event_bus.publish(
                    audit_id=audit_id,
                    agent_type="system",
                    event_type="warning",
                    data={"warning": "AST索引构建失败，检索功能可能不可用", "error": str(e)},
                    message=f"警告: AST索引构建失败 ({str(e)})，检索功能可能不可用",
                )
        else:
            logger.warning("[Audit] 项目路径为空，跳过AST索引构建")

        # ========== 执行Agent审计流程 ==========
        # 完整流程：
        # 1. Recon Agent - 信息收集
        # 2. Scanner (Rust backend) - 规则扫描
        # 3. Analysis Agent - 深度分析
        # 4. Verification Agent - 漏洞验证（可选）

        # 使用Orchestrator Agent进行编排
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


@router.get("/monitoring/metrics")
async def get_monitoring_metrics():
    """
    获取监控系统指标

    Returns:
        监控指标数据
    """
    from app.core.monitoring import get_monitoring_system

    monitoring = get_monitoring_system()
    return monitoring.get_status()


@router.get("/monitoring/phase/{audit_id}")
async def get_audit_phase(audit_id: str):
    """
    获取审计阶段信息

    Args:
        audit_id: 审计 ID

    Returns:
        当前审计阶段和进度
    """
    from app.core.audit_phase import get_phase_manager, PHASE_WEIGHTS

    phase_manager = get_phase_manager(audit_id)
    return {
        "audit_id": audit_id,
        "current_phase": phase_manager.current_phase.value,
        "progress": phase_manager.calculate_overall_progress(),
        "status": phase_manager.get_status(),
        "phases": [
            {
                "phase": phase.value,
                "weight": weight,
            }
            for phase, weight in PHASE_WEIGHTS.items()
        ],
    }
