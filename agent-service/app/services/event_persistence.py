"""
Agent 事件持久化服务

提供事件的持久化存储和查询功能
使用 SQLite 统一管理：
- agent_events: Agent 事件
- audit_sessions: 审计会话
- findings: 漏洞发现
"""
from typing import Dict, Any, List, Optional
from loguru import logger
from datetime import datetime
import sqlite3
import json
import asyncio
from pathlib import Path

from app.config import settings


class EventPersistence:
    """
    事件持久化服务

    特性：
    - 异步保存事件到数据库
    - 查询历史事件
    - 按序列号范围查询
    - 自动清理旧事件
    """

    def __init__(self, db_path: Optional[Path] = None):
        """
        初始化持久化服务

        Args:
            db_path: 数据库路径，默认使用 SQLite
        """
        if db_path is None:
            # 使用 data 目录下的 SQLite
            data_dir = Path(__file__).parent.parent.parent.parent / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            db_path = data_dir / "agent.db"

        self.db_path = db_path
        self._write_lock = asyncio.Lock()
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        with sqlite3.connect(self.db_path) as conn:
            # ==================== Agent 事件表 ====================
            conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_events (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    message TEXT,
                    data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                    UNIQUE(audit_id, sequence)
                )
            """)

            # 索引
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_events_audit_id
                ON agent_events(audit_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_events_audit_sequence
                ON agent_events(audit_id, sequence)
            """)

            # ==================== 审计会话表 ====================
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_sessions (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    audit_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    config TEXT,
                    current_stage TEXT,
                    progress_percentage INTEGER DEFAULT 0,
                    total_tokens INTEGER DEFAULT 0,
                    tool_calls INTEGER DEFAULT 0,
                    total_files INTEGER DEFAULT 0,
                    indexed_files INTEGER DEFAULT 0,
                    analyzed_files INTEGER DEFAULT 0,
                    findings_detected INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 迁移：添加新列（如果表已存在）
            try:
                conn.execute("ALTER TABLE audit_sessions ADD COLUMN total_tokens INTEGER DEFAULT 0")
            except: pass
            try:
                conn.execute("ALTER TABLE audit_sessions ADD COLUMN tool_calls INTEGER DEFAULT 0")
            except: pass
            try:
                conn.execute("ALTER TABLE audit_sessions ADD COLUMN total_files INTEGER DEFAULT 0")
            except: pass
            try:
                conn.execute("ALTER TABLE audit_sessions ADD COLUMN indexed_files INTEGER DEFAULT 0")
            except: pass
            try:
                conn.execute("ALTER TABLE audit_sessions ADD COLUMN analyzed_files INTEGER DEFAULT 0")
            except: pass
            try:
                conn.execute("ALTER TABLE audit_sessions ADD COLUMN findings_detected INTEGER DEFAULT 0")
            except: pass

            # ==================== 漏洞发现表 ====================
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL,
                    title TEXT NOT NULL,
                    description TEXT,
                    file_path TEXT,
                    line_number INTEGER,
                    code_snippet TEXT,
                    remediation TEXT,
                    verified BOOLEAN DEFAULT FALSE,
                    verification_confidence REAL,
                    poc_output TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 索引
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_audit_id
                ON findings(audit_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                ON findings(severity)
            """)

            conn.commit()
            logger.info(f"事件持久化数据库初始化完成: {self.db_path}")

    async def save_event(self, event: Dict[str, Any]) -> bool:
        """
        保存事件到数据库（异步，不阻塞）

        Args:
            event: 事件字典

        Returns:
            是否保存成功
        """
        try:
            # 使用锁避免并发写入冲突
            async with self._write_lock:
                def _save():
                    with sqlite3.connect(self.db_path) as conn:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO agent_events
                            (id, audit_id, agent_type, event_type, sequence, timestamp, message, data)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                event.get("id"),
                                event.get("audit_id"),
                                event.get("agent_type"),
                                event.get("event_type"),
                                event.get("sequence", 0),
                                event.get("timestamp"),
                                event.get("message"),
                                json.dumps(event.get("data", {}), ensure_ascii=False),
                            )
                        )
                        conn.commit()

                # 在线程池中执行，避免阻塞事件循环
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _save)

            return True

        except Exception as e:
            logger.error(f"保存事件到数据库失败: {e}")
            return False

    async def save_events_batch(self, events: List[Dict[str, Any]]) -> int:
        """
        批量保存事件（更高性能）

        Args:
            events: 事件列表

        Returns:
            成功保存的数量
        """
        if not events:
            return 0

        try:
            async with self._write_lock:
                def _save_batch():
                    with sqlite3.connect(self.db_path) as conn:
                        # 使用事务批量插入
                        conn.execute("BEGIN TRANSACTION")
                        count = 0
                        for event in events:
                            try:
                                conn.execute(
                                    """
                                    INSERT OR REPLACE INTO agent_events
                                    (id, audit_id, agent_type, event_type, sequence, timestamp, message, data)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                    """,
                                    (
                                        event.get("id"),
                                        event.get("audit_id"),
                                        event.get("agent_type"),
                                        event.get("event_type"),
                                        event.get("sequence", 0),
                                        event.get("timestamp"),
                                        event.get("message"),
                                        json.dumps(event.get("data", {}), ensure_ascii=False),
                                    )
                                )
                                count += 1
                            except Exception as e:
                                logger.warning(f"保存单个事件失败: {e}")
                        conn.commit()
                        return count

                loop = asyncio.get_event_loop()
                count = await loop.run_in_executor(None, _save_batch)

                logger.debug(f"批量保存 {count}/{len(events)} 个事件")
                return count

        except Exception as e:
            logger.error(f"批量保存事件失败: {e}")
            return 0

    def get_events(
        self,
        audit_id: str,
        after_sequence: int = 0,
        limit: int = 100,
        event_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        从数据库获取历史事件

        Args:
            audit_id: 审计 ID
            after_sequence: 起始序列号
            limit: 返回数量限制
            event_types: 事件类型过滤（可选）

        Returns:
            事件列表
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                query = """
                    SELECT id, audit_id, agent_type, event_type, sequence,
                           timestamp, message, data
                    FROM agent_events
                    WHERE audit_id = ? AND sequence > ?
                """
                params = [audit_id, after_sequence]

                if event_types:
                    placeholders = ",".join("?" * len(event_types))
                    query += f" AND event_type IN ({placeholders})"
                    params.extend(event_types)

                query += " ORDER BY sequence ASC LIMIT ?"
                params.append(limit)

                cursor = conn.execute(query, params)
                rows = cursor.fetchall()

                events = []
                for row in rows:
                    event = {
                        "id": row["id"],
                        "audit_id": row["audit_id"],
                        "agent_type": row["agent_type"],
                        "event_type": row["event_type"],
                        "sequence": row["sequence"],
                        "timestamp": row["timestamp"],
                        "message": row["message"],
                        "data": json.loads(row["data"]) if row["data"] else {},
                    }
                    events.append(event)

                return events

        except Exception as e:
            logger.error(f"获取历史事件失败: {e}")
            return []

    def get_event_count(self, audit_id: str) -> int:
        """获取审计事件总数"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM agent_events WHERE audit_id = ?",
                    (audit_id,)
                )
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"获取事件数量失败: {e}")
            return 0

    def get_latest_sequence(self, audit_id: str) -> int:
        """获取最新的序列号"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT MAX(sequence) FROM agent_events WHERE audit_id = ?",
                    (audit_id,)
                )
                result = cursor.fetchone()[0]
                return result if result is not None else 0
        except Exception as e:
            logger.error(f"获取最新序列号失败: {e}")
            return 0

    async def delete_events(self, audit_id: str) -> int:
        """
        删除审计的所有事件

        Args:
            audit_id: 审计 ID

        Returns:
            删除的数量
        """
        try:
            async with self._write_lock:
                def _delete():
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.execute(
                            "DELETE FROM agent_events WHERE audit_id = ?",
                            (audit_id,)
                        )
                        conn.commit()
                        return cursor.rowcount

                loop = asyncio.get_event_loop()
                count = await loop.run_in_executor(None, _delete)

                logger.info(f"删除审计 {audit_id} 的 {count} 个事件")
                return count

        except Exception as e:
            logger.error(f"删除事件失败: {e}")
            return 0

    async def cleanup_old_events(self, days: int = 7) -> int:
        """
        清理旧事件（定期任务）

        Args:
            days: 保留天数

        Returns:
            删除的数量
        """
        try:
            async with self._write_lock:
                def _cleanup():
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.execute(
                            """DELETE FROM agent_events
                               WHERE created_at < datetime('now', '-' || ? || ' days')""",
                            (days,)
                        )
                        conn.commit()
                        return cursor.rowcount

                loop = asyncio.get_event_loop()
                count = await loop.run_in_executor(None, _cleanup)

                if count > 0:
                    logger.info(f"清理了 {count} 个旧事件（{days} 天前）")
                return count

        except Exception as e:
            logger.error(f"清理旧事件失败: {e}")
            return 0

    def get_statistics(self, audit_id: Optional[str] = None) -> Dict[str, Any]:
        """
        获取事件统计信息

        Args:
            audit_id: 审计 ID（可选，不指定则全局统计）

        Returns:
            统计信息字典
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                if audit_id:
                    # 单个审计的统计
                    cursor = conn.execute(
                        """
                        SELECT
                            event_type,
                            COUNT(*) as count
                        FROM agent_events
                        WHERE audit_id = ?
                        GROUP BY event_type
                        """,
                        (audit_id,)
                    )
                else:
                    # 全局统计
                    cursor = conn.execute(
                        """
                        SELECT
                            event_type,
                            COUNT(*) as count
                        FROM agent_events
                        GROUP BY event_type
                        """
                    )

                event_types = {}
                for row in cursor.fetchall():
                    event_types[row[0]] = row[1]

                total = sum(event_types.values())

                return {
                    "total_events": total,
                    "by_type": event_types,
                }

        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {}

    def get_findings(self, audit_id: str) -> List[Dict[str, Any]]:
        """
        获取审计的漏洞发现

        Args:
            audit_id: 审计 ID

        Returns:
            漏洞发现列表
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    """
                    SELECT * FROM findings
                    WHERE audit_id = ?
                    ORDER BY
                        CASE severity
                            WHEN 'critical' THEN 1
                            WHEN 'high' THEN 2
                            WHEN 'medium' THEN 3
                            WHEN 'low' THEN 4
                            WHEN 'info' THEN 5
                            ELSE 6
                        END,
                        created_at DESC
                    """,
                    (audit_id,)
                )
                rows = cursor.fetchall()

                findings = []
                for row in rows:
                    finding = {
                        "id": row["id"],
                        "audit_id": row["audit_id"],
                        "vulnerability_type": row["vulnerability_type"],
                        "severity": row["severity"],
                        "confidence": row["confidence"],
                        "title": row["title"],
                        "description": row["description"],
                        "file_path": row["file_path"],
                        "line_number": row["line_number"],
                        "code_snippet": row["code_snippet"],
                        "remediation": row["remediation"],
                        "verified": bool(row["verified"]),
                        "verification_confidence": row["verification_confidence"],
                        "poc_output": row["poc_output"],
                        "created_at": row["created_at"],
                    }
                    findings.append(finding)

                return findings

        except Exception as e:
            logger.error(f"获取漏洞发现失败: {e}")
            return []

    async def update_audit_stats(
        self,
        audit_id: str,
        total_tokens: Optional[int] = None,
        tool_calls: Optional[int] = None,
        total_files: Optional[int] = None,
        indexed_files: Optional[int] = None,
        analyzed_files: Optional[int] = None,
        findings_detected: Optional[int] = None,
    ) -> None:
        """
        更新审计统计信息（SQLite 版本）

        Args:
            audit_id: 审计 ID
            total_tokens: 总 Token 数量
            tool_calls: 工具调用次数
            total_files: 总文件数
            indexed_files: 已索引文件数
            analyzed_files: 已分析文件数
            findings_detected: 发现的漏洞数
        """
        try:
            async with self._write_lock:
                def _update():
                    with sqlite3.connect(self.db_path) as conn:
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

                        if updates:
                            params.append(audit_id)
                            conn.execute(
                                f"UPDATE audit_sessions SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                                params
                            )
                            conn.commit()

                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _update)

        except Exception as e:
            logger.error(f"更新审计统计失败: {e}")


# 全局单例
_persistence: Optional[EventPersistence] = None


def get_event_persistence() -> EventPersistence:
    """获取事件持久化服务单例"""
    global _persistence
    if _persistence is None:
        _persistence = EventPersistence()
    return _persistence
