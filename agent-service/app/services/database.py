"""
数据库服务（SQLite 版本）

使用 SQLite 进行数据持久化，无需外部数据库
"""
import aiosqlite
import sqlite3
from typing import Optional, Dict, List, Any
from pathlib import Path
from loguru import logger

from app.config import settings

# 全局数据库连接
_db_connection: Optional[aiosqlite.Connection] = None


def get_db_path() -> Path:
    """获取数据库文件路径"""
    db_path = Path(settings.DATABASE_PATH)
    if not db_path.is_absolute():
        db_path = Path(__file__).parent.parent / settings.DATABASE_PATH
    return db_path


async def init_database():
    """初始化数据库连接和表结构"""
    global _db_connection

    if _db_connection is not None:
        return

    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        _db_connection = await aiosqlite.connect(db_path)
        _db_connection.row_factory = aiosqlite.Row

        # 启用外键约束
        await _db_connection.execute("PRAGMA foreign_keys = ON")

        logger.info(f"SQLite 数据库连接成功: {db_path}")

        # 运行迁移
        await _run_migrations()

    except Exception as e:
        logger.error(f"数据库连接失败: {e}")
        raise


async def _run_migrations():
    """运行数据库迁移，创建表结构"""
    conn = await get_connection()

    # 审计会话表
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_sessions (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL,
            audit_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            current_stage TEXT,
            progress_percentage INTEGER DEFAULT 0,
            config TEXT DEFAULT '{}',
            total_tokens INTEGER DEFAULT 0,
            tool_calls INTEGER DEFAULT 0,
            total_files INTEGER DEFAULT 0,
            indexed_files INTEGER DEFAULT 0,
            analyzed_files INTEGER DEFAULT 0,
            findings_detected INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )
    """)

    # Agent 执行记录表
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_executions (
            id TEXT PRIMARY KEY,
            audit_id TEXT NOT NULL,
            agent_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'running',
            input TEXT DEFAULT '{}',
            output TEXT,
            thinking_chain TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (audit_id) REFERENCES audit_sessions(id) ON DELETE CASCADE
        )
    """)

    # 漏洞发现表
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            audit_id TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL,
            title TEXT,
            description TEXT,
            file_path TEXT,
            line_number INTEGER,
            code_snippet TEXT,
            remediation TEXT,
            verified BOOLEAN DEFAULT 0,
            verification_confidence REAL,
            poc_output TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (audit_id) REFERENCES audit_sessions(id) ON DELETE CASCADE
        )
    """)

    # 审计事件表
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id TEXT NOT NULL,
            agent_name TEXT NOT NULL,
            event_type TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (audit_id) REFERENCES audit_sessions(id) ON DELETE CASCADE
        )
    """)

    # 创建索引
    await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_findings_audit_id ON findings(audit_id)
    """)
    await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_audit_id ON audit_events(audit_id)
    """)
    await conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_executions_audit_id ON agent_executions(audit_id)
    """)

    await conn.commit()
    logger.info("数据库迁移完成")


async def close_database():
    """关闭数据库连接"""
    global _db_connection

    if _db_connection:
        await _db_connection.close()
        _db_connection = None
        logger.info("数据库连接已关闭")


async def get_connection() -> aiosqlite.Connection:
    """获取数据库连接"""
    if _db_connection is None:
        await init_database()
    return _db_connection


async def check_database() -> bool:
    """检查数据库连接状态"""
    try:
        conn = await get_connection()
        await conn.execute("SELECT 1")
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
    """创建审计会话"""
    import json

    conn = await get_connection()
    config_json = json.dumps(config) if config else '{}'

    await conn.execute(
        """
        INSERT INTO audit_sessions (id, project_id, audit_type, status, config)
        VALUES (?, ?, ?, 'pending', ?)
        """,
        (audit_id, project_id, audit_type, config_json),
    )
    await conn.commit()

    return audit_id


async def update_audit_status(audit_id: str, status: str) -> None:
    """更新审计状态"""
    conn = await get_connection()
    await conn.execute(
        "UPDATE audit_sessions SET status = ? WHERE id = ?",
        (status, audit_id),
    )
    await conn.commit()


async def get_audit_session(audit_id: str) -> Optional[dict]:
    """获取审计会话"""
    conn = await get_connection()
    cursor = await conn.execute(
        "SELECT * FROM audit_sessions WHERE id = ?",
        (audit_id,),
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


async def create_agent_execution(
    audit_id: str,
    agent_name: str,
    input_data: dict,
) -> str:
    """创建 Agent 执行记录"""
    import uuid
    import json

    conn = await get_connection()
    execution_id = str(uuid.uuid4())

    await conn.execute(
        """
        INSERT INTO agent_executions (id, audit_id, agent_name, status, input)
        VALUES (?, ?, ?, 'running', ?)
        """,
        (execution_id, audit_id, agent_name, json.dumps(input_data)),
    )
    await conn.commit()

    return execution_id


async def update_agent_execution(
    execution_id: str,
    output: dict,
    thinking_chain: str,
) -> None:
    """更新 Agent 执行结果"""
    import json

    conn = await get_connection()
    await conn.execute(
        """
        UPDATE agent_executions
        SET output = ?, thinking_chain = ?, status = 'completed', completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (json.dumps(output), thinking_chain, execution_id),
    )
    await conn.commit()


async def create_finding(audit_id: str, finding: dict) -> str:
    """创建漏洞发现记录"""
    import uuid

    conn = await get_connection()
    finding_id = str(uuid.uuid4())

    await conn.execute(
        """
        INSERT INTO findings (
            id, audit_id, vulnerability_type, severity, confidence,
            title, description, file_path, line_number, code_snippet,
            remediation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
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
        ),
    )
    await conn.commit()

    return finding_id


async def get_findings(audit_id: str) -> list:
    """获取审计的所有漏洞发现"""
    conn = await get_connection()
    cursor = await conn.execute(
        "SELECT * FROM findings WHERE audit_id = ?",
        (audit_id,),
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def save_thinking_chain(audit_id: str, agent_name: str, thoughts: list) -> None:
    """保存 Agent 思考链"""
    import json
    import time

    conn = await get_connection()

    for thought in thoughts:
        await conn.execute(
            """
            INSERT INTO audit_events (audit_id, agent_name, event_type, data, created_at)
            VALUES (?, ?, 'thinking', ?, datetime(?, 'unixepoch'))
            """,
            (
                audit_id,
                agent_name,
                json.dumps({"thought": thought.get("thought")}),
                thought.get("timestamp", time.time()),
            ),
        )
    await conn.commit()


async def save_audit_event(
    audit_id: str,
    agent_name: str,
    event_type: str,
    data: dict,
) -> None:
    """保存审计事件"""
    import json

    conn = await get_connection()

    await conn.execute(
        """
        INSERT INTO audit_events (audit_id, agent_name, event_type, data, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (audit_id, agent_name, event_type, json.dumps(data)),
    )
    await conn.commit()


async def get_audit_events(audit_id: str, limit: int = 100) -> list:
    """获取审计事件"""
    conn = await get_connection()

    cursor = await conn.execute(
        """
        SELECT * FROM audit_events
        WHERE audit_id = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (audit_id, limit),
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_agent_executions(audit_id: str) -> list:
    """获取审计的所有 Agent 执行记录"""
    conn = await get_connection()

    cursor = await conn.execute(
        """
        SELECT * FROM agent_executions
        WHERE audit_id = ?
        ORDER BY created_at ASC
        """,
        (audit_id,),
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def update_audit_progress(
    audit_id: str,
    current_stage: str,
    progress_percentage: int,
) -> None:
    """更新审计进度"""
    conn = await get_connection()

    await conn.execute(
        """
        UPDATE audit_sessions
        SET current_stage = ?, progress_percentage = ?
        WHERE id = ?
        """,
        (current_stage, progress_percentage, audit_id),
    )
    await conn.commit()


async def update_audit_stats(
    audit_id: str,
    total_tokens: Optional[int] = None,
    tool_calls: Optional[int] = None,
    total_files: Optional[int] = None,
    indexed_files: Optional[int] = None,
    analyzed_files: Optional[int] = None,
    findings_detected: Optional[int] = None,
) -> None:
    """更新审计统计信息"""
    conn = await get_connection()

    # 构建动态更新语句
    updates = []
    params = []

    if total_tokens is not None:
        updates.append("total_tokens = total_tokens + ?")
        params.append(total_tokens)

    if tool_calls is not None:
        updates.append("tool_calls = tool_calls + ?")
        params.append(tool_calls)

    if total_files is not None:
        updates.append("total_files = ?")
        params.append(total_files)

    if indexed_files is not None:
        updates.append("indexed_files = ?")
        params.append(indexed_files)

    if analyzed_files is not None:
        updates.append("analyzed_files = ?")
        params.append(analyzed_files)

    if findings_detected is not None:
        updates.append("findings_detected = ?")
        params.append(findings_detected)

    if not updates:
        return

    params.append(audit_id)

    await conn.execute(
        f"""
        UPDATE audit_sessions
        SET {', '.join(updates)}
        WHERE id = ?
        """,
        params,
    )
    await conn.commit()


async def get_audit_summary(audit_id: str) -> Optional[dict]:
    """获取审计摘要"""
    conn = await get_connection()

    cursor = await conn.execute(
        "SELECT * FROM audit_sessions WHERE id = ?",
        (audit_id,),
    )
    row = await cursor.fetchone()

    if not row:
        return None

    session = dict(row)

    cursor = await conn.execute(
        "SELECT severity, COUNT(*) as count FROM findings WHERE audit_id = ? GROUP BY severity",
        (audit_id,),
    )
    severity_rows = await cursor.fetchall()

    findings_by_severity = {row["severity"]: row["count"] for row in severity_rows}
    total_findings = sum(row["count"] for row in severity_rows)

    return {
        "session": session,
        "findings_by_severity": findings_by_severity,
        "total_findings": total_findings,
    }


async def mark_finding_verified(
    finding_id: str,
    verified: bool,
    confidence: float,
    poc_output: str = "",
) -> None:
    """标记漏洞已验证"""
    conn = await get_connection()

    await conn.execute(
        """
        UPDATE findings
        SET verified = ?, verification_confidence = ?, poc_output = ?
        WHERE id = ?
        """,
        (1 if verified else 0, confidence, poc_output, finding_id),
    )
    await conn.commit()
