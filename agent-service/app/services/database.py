"""
数据库服务

PostgreSQL 连接和数据访问层
"""
from asyncpg import Pool, create_pool
from typing import Optional
from loguru import logger

from app.config import settings

# 全局连接池
_db_pool: Optional[Pool] = None


async def init_database():
    """初始化数据库连接池"""
    global _db_pool

    if _db_pool is not None:
        return

    try:
        _db_pool = await create_pool(
            settings.DATABASE_URL,
            min_size=5,
            max_size=20,
            command_timeout=30,
        )
        logger.info("PostgreSQL 连接池创建成功")

        # 运行迁移
        await _run_migrations()
    except Exception as e:
        logger.error(f"数据库连接失败: {e}")
        raise


async def _run_migrations():
    """运行数据库迁移"""
    pool = await get_pool()

    async with pool.acquire() as conn:
        # 添加 token 和工具调用统计字段到 audit_sessions
        try:
            await conn.execute("""
                ALTER TABLE audit_sessions
                ADD COLUMN IF NOT EXISTS total_tokens INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS tool_calls INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS total_files INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS indexed_files INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS analyzed_files INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS findings_detected INTEGER DEFAULT 0
            """)
            logger.info("数据库迁移完成: 添加统计字段")
        except Exception as e:
            logger.warning(f"迁移失败（可能已存在）: {e}")


async def close_database():
    """关闭数据库连接"""
    global _db_pool

    if _db_pool:
        await _db_pool.close()
        _db_pool = None
        logger.info("数据库连接已关闭")


async def get_pool() -> Pool:
    """获取数据库连接池"""
    if _db_pool is None:
        await init_database()
    return _db_pool


async def check_database() -> bool:
    """检查数据库连接状态"""
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return True
    except Exception:
        return False


# ========== 数据访问函数 ==========

async def create_audit_session(
    audit_id: str,
    project_id: str,
    audit_type: str,
    config: dict,
) -> str:
    """
    创建审计会话

    Args:
        audit_id: 审计 ID
        project_id: 项目 ID
        audit_type: 审计类型
        config: 配置

    Returns:
        audit_id
    """
    import json

    pool = await get_pool()

    # 将 config 字典序列化为 JSON 字符串
    config_json = json.dumps(config) if config else '{}'

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO audit_sessions (id, project_id, audit_type, status, config)
            VALUES ($1, $2, $3, 'pending', $4)
            """,
            audit_id,
            project_id,
            audit_type,
            config_json,
        )

    return audit_id


async def update_audit_status(audit_id: str, status: str) -> None:
    """更新审计状态"""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE audit_sessions SET status = $1 WHERE id = $2",
            status,
            audit_id,
        )


async def get_audit_session(audit_id: str) -> Optional[dict]:
    """获取审计会话"""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM audit_sessions WHERE id = $1",
            audit_id,
        )
        return dict(row) if row else None


async def create_agent_execution(
    audit_id: str,
    agent_name: str,
    input_data: dict,
) -> str:
    """创建 Agent 执行记录"""
    import uuid

    pool = await get_pool()
    execution_id = str(uuid.uuid4())

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO agent_executions (id, audit_id, agent_name, status, input)
            VALUES ($1, $2, $3, 'running', $4)
            """,
            execution_id,
            audit_id,
            agent_name,
            input_data,
        )

    return execution_id


async def update_agent_execution(
    execution_id: str,
    output: dict,
    thinking_chain: str,
) -> None:
    """更新 Agent 执行结果"""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE agent_executions
            SET output = $1, thinking_chain = $2, status = 'completed', completed_at = NOW()
            WHERE id = $3
            """,
            output,
            thinking_chain,
            execution_id,
        )


async def create_finding(audit_id: str, finding: dict) -> str:
    """创建漏洞发现记录"""
    import uuid

    pool = await get_pool()
    finding_id = str(uuid.uuid4())

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO findings (
                id, audit_id, vulnerability_type, severity, confidence,
                title, description, file_path, line_number, code_snippet,
                remediation
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            """,
            finding_id,
            audit_id,
            finding.get("vulnerability_type"),
            finding.get("severity"),
            finding.get("confidence"),
            finding.get("title"),
            finding.get("description"),
            finding.get("file_path"),
            finding.get("line_number"),
            finding.get("code_snippet"),
            finding.get("remediation"),
        )

    return finding_id


async def get_findings(audit_id: str) -> list:
    """获取审计的所有漏洞发现"""
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM findings WHERE audit_id = $1",
            audit_id,
        )
        return [dict(row) for row in rows]


async def save_thinking_chain(audit_id: str, agent_name: str, thoughts: list) -> None:
    """
    保存 Agent 思考链

    Args:
        audit_id: 审计 ID
        agent_name: Agent 名称
        thoughts: 思考链列表，每个元素包含 timestamp 和 thought
    """
    import json

    pool = await get_pool()

    async with pool.acquire() as conn:
        for thought in thoughts:
            await conn.execute(
                """
                INSERT INTO audit_events (audit_id, agent_name, event_type, data, created_at)
                VALUES ($1, $2, 'thinking', $3, to_timestamp($4))
                """,
                audit_id,
                agent_name,
                json.dumps({"thought": thought.get("thought")}),
                thought.get("timestamp", time.time()),
            )


async def save_audit_event(
    audit_id: str,
    agent_name: str,
    event_type: str,
    data: dict,
) -> None:
    """
    保存审计事件（用于 SSE 推送）

    Args:
        audit_id: 审计 ID
        agent_name: Agent 名称
        event_type: 事件类型 (thinking | action | observation | finding | error | status)
        data: 事件数据
    """
    import json
    import time

    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO audit_events (audit_id, agent_name, event_type, data, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            """,
            audit_id,
            agent_name,
            event_type,
            json.dumps(data),
        )


async def get_audit_events(audit_id: str, limit: int = 100) -> list:
    """
    获取审计事件（用于历史记录）

    Args:
        audit_id: 审计 ID
        limit: 返回数量限制

    Returns:
        事件列表
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM audit_events
            WHERE audit_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            """,
            audit_id,
            limit,
        )
        return [dict(row) for row in rows]


async def get_agent_executions(audit_id: str) -> list:
    """获取审计的所有 Agent 执行记录"""
    pool = await get_pool()

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT * FROM agent_executions
            WHERE audit_id = $1
            ORDER BY created_at ASC
            """,
            audit_id,
        )
        return [dict(row) for row in rows]


async def update_audit_progress(
    audit_id: str,
    current_stage: str,
    progress_percentage: int,
) -> None:
    """
    更新审计进度

    Args:
        audit_id: 审计 ID
        current_stage: 当前阶段
        progress_percentage: 进度百分比 (0-100)
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE audit_sessions
            SET current_stage = $1, progress_percentage = $2
            WHERE id = $3
            """,
            current_stage,
            progress_percentage,
            audit_id,
        )


async def update_audit_stats(
    audit_id: str,
    total_tokens: Optional[int] = None,
    tool_calls: Optional[int] = None,
    total_files: Optional[int] = None,
    indexed_files: Optional[int] = None,
    analyzed_files: Optional[int] = None,
    findings_detected: Optional[int] = None,
) -> None:
    """
    更新审计统计信息

    Args:
        audit_id: 审计 ID
        total_tokens: 总 Token 数量
        tool_calls: 工具调用次数
        total_files: 总文件数
        indexed_files: 已索引文件数
        analyzed_files: 已分析文件数
        findings_detected: 发现的漏洞数
    """
    pool = await get_pool()

    # 构建动态更新语句
    updates = []
    params = []
    param_idx = 1

    if total_tokens is not None:
        updates.append(f"total_tokens = total_tokens + ${param_idx}")
        params.append(total_tokens)
        param_idx += 1

    if tool_calls is not None:
        updates.append(f"tool_calls = tool_calls + ${param_idx}")
        params.append(tool_calls)
        param_idx += 1

    if total_files is not None:
        updates.append(f"total_files = ${param_idx}")
        params.append(total_files)
        param_idx += 1

    if indexed_files is not None:
        updates.append(f"indexed_files = ${param_idx}")
        params.append(indexed_files)
        param_idx += 1

    if analyzed_files is not None:
        updates.append(f"analyzed_files = ${param_idx}")
        params.append(analyzed_files)
        param_idx += 1

    if findings_detected is not None:
        updates.append(f"findings_detected = ${param_idx}")
        params.append(findings_detected)
        param_idx += 1

    if not updates:
        return

    params.append(audit_id)

    async with pool.acquire() as conn:
        await conn.execute(
            f"""
            UPDATE audit_sessions
            SET {', '.join(updates)}
            WHERE id = ${param_idx}
            """,
            *params,
        )


async def get_audit_summary(audit_id: str) -> Optional[dict]:
    """
    获取审计摘要

    Args:
        audit_id: 审计 ID

    Returns:
        审计摘要，包含统计信息
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        session = await conn.fetchrow(
            "SELECT * FROM audit_sessions WHERE id = $1",
            audit_id,
        )

        if not session:
            return None

        findings = await conn.fetch(
            "SELECT severity, COUNT(*) FROM findings WHERE audit_id = $1 GROUP BY severity",
            audit_id,
        )

        return {
            "session": dict(session),
            "findings_by_severity": {row["severity"]: row["count"] for row in findings},
            "total_findings": sum(row["count"] for row in findings),
        }


async def mark_finding_verified(
    finding_id: str,
    verified: bool,
    confidence: float,
    poc_output: str = "",
) -> None:
    """
    标记漏洞已验证

    Args:
        finding_id: 漏洞 ID
        verified: 是否验证为真实漏洞
        confidence: 置信度 (0.0-1.0)
        poc_output: PoC 执行输出
    """
    pool = await get_pool()

    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE findings
            SET verified = $1, verification_confidence = $2, poc_output = $3
            WHERE id = $4
            """,
            verified,
            confidence,
            poc_output,
            finding_id,
        )


# 初始化时导入 time
import time
