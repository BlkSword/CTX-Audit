"""
审计事件总线

基于 Redis Streams 的审计事件发布和订阅系统，支持 SSE 实时推送
"""
from typing import Dict, Any, Optional, AsyncIterator
from loguru import logger
from datetime import datetime
import asyncio
import json
import uuid

from app.config import settings


# 事件类型定义
class EventType:
    """审计事件类型"""
    THINKING = "thinking"       # Agent 思考
    ACTION = "action"           # Agent 执行动作
    OBSERVATION = "observation" # Agent 观察结果
    FINDING = "finding"         # 发现漏洞
    ERROR = "error"             # 错误
    STATUS = "status"           # 状态更新


class AuditEvent:
    """
    审计事件

    Attributes:
        event_id: 事件唯一 ID
        audit_id: 审计 ID
        agent_type: Agent 类型 (orchestrator | recon | analysis | verification)
        event_type: 事件类型
        timestamp: 时间戳
        data: 事件数据
        metadata: 元数据
    """

    def __init__(
        self,
        audit_id: str,
        agent_type: str,
        event_type: str,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.event_id = str(uuid.uuid4())
        self.audit_id = audit_id
        self.agent_type = agent_type
        self.event_type = event_type
        self.timestamp = datetime.now().isoformat()
        self.data = data
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "event_id": self.event_id,
            "audit_id": self.audit_id,
            "agent_type": self.agent_type,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": self.data,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """从字典创建"""
        event = cls.__new__(cls)
        event.event_id = data.get("event_id", str(uuid.uuid4()))
        event.audit_id = data["audit_id"]
        event.agent_type = data["agent_type"]
        event.event_type = data["event_type"]
        event.timestamp = data.get("timestamp", datetime.now().isoformat())
        event.data = data.get("data", {})
        event.metadata = data.get("metadata", {})
        return event


class EventBus:
    """
    审计事件总线

    功能：
    - 发布审计事件到 Redis Streams
    - 订阅审计事件流
    - 支持内存缓存（用于 SSE）
    """

    def __init__(self):
        self._redis = None
        self._memory_cache: Dict[str, list[AuditEvent]] = {}
        self._cache_max_size = 1000  # 每个 audit_id 最多缓存 1000 条事件
        self._subscribers: Dict[str, list[asyncio.Queue]] = {}

    async def init(self):
        """初始化 Redis 连接"""
        try:
            import redis.asyncio as redis
            self._redis = await redis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
            )
            await self._redis.ping()
            logger.info("事件总线 Redis 连接成功")
        except Exception as e:
            logger.warning(f"事件总线 Redis 连接失败，使用内存模式: {e}")
            self._redis = None

    async def close(self):
        """关闭连接"""
        if self._redis:
            await self._redis.close()
            self._redis = None

    async def publish(self, event: AuditEvent) -> None:
        """
        发布审计事件

        Args:
            event: 审计事件
        """
        # 1. 存储到内存缓存（用于 SSE）
        if event.audit_id not in self._memory_cache:
            self._memory_cache[event.audit_id] = []

        self._memory_cache[event.audit_id].append(event)

        # 限制缓存大小
        if len(self._memory_cache[event.audit_id]) > self._cache_max_size:
            self._memory_cache[event.audit_id] = self._memory_cache[event.audit_id][-self._cache_max_size:]

        # 2. 推送到内存订阅者（SSE 连接）
        if event.audit_id in self._subscribers:
            for queue in self._subscribers[event.audit_id]:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    logger.warning(f"订阅者队列已满: {event.audit_id}")

        # 3. 写入 Redis Streams（可选，用于持久化）
        if self._redis:
            try:
                stream_key = f"audit_stream:{event.audit_id}"
                await self._redis.xadd(
                    stream_key,
                    {
                        "event_id": event.event_id,
                        "agent_type": event.agent_type,
                        "event_type": event.event_type,
                        "timestamp": event.timestamp,
                        "data": json.dumps(event.data, ensure_ascii=False),
                    },
                )
            except Exception as e:
                logger.error(f"写入 Redis Stream 失败: {e}")

        logger.debug(f"[{event.agent_type}] {event.event_type}: {event.data.get('message', '')[:50]}")

    async def subscribe(
        self,
        audit_id: str,
    ) -> AsyncIterator[AuditEvent]:
        """
        订阅审计事件流（用于 SSE）

        Args:
            audit_id: 审计 ID

        Yields:
            AuditEvent 实例
        """
        # 创建队列
        queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=100)

        # 添加到订阅者列表
        if audit_id not in self._subscribers:
            self._subscribers[audit_id] = []
        self._subscribers[audit_id].append(queue)

        # 发送历史事件
        if audit_id in self._memory_cache:
            for event in self._memory_cache[audit_id]:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    break

        try:
            # 实时推送新事件
            while True:
                event = await queue.get()
                yield event
        finally:
            # 清理订阅者
            if audit_id in self._subscribers:
                self._subscribers[audit_id].remove(queue)
                if not self._subscribers[audit_id]:
                    del self._subscribers[audit_id]

    async def get_events(
        self,
        audit_id: str,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """
        获取审计事件历史

        Args:
            audit_id: 审计 ID
            limit: 返回数量限制

        Returns:
            事件列表
        """
        if audit_id in self._memory_cache:
            return self._memory_cache[audit_id][-limit:]

        # 如果内存没有，尝试从 Redis 读取
        if self._redis:
            try:
                stream_key = f"audit_stream:{audit_id}"
                results = await self._redis.xrevrange(
                    stream_key,
                    count=limit,
                )

                events = []
                for result_id, data in reversed(results):
                    events.append(AuditEvent(
                        audit_id=audit_id,
                        agent_type=data["agent_type"],
                        event_type=data["event_type"],
                        data=json.loads(data["data"]),
                        metadata={"event_id": data["event_id"], "timestamp": data["timestamp"]},
                    ))
                return events
            except Exception as e:
                logger.error(f"从 Redis 读取事件失败: {e}")

        return []

    async def clear_events(self, audit_id: str) -> None:
        """
        清除审计事件缓存

        Args:
            audit_id: 审计 ID
        """
        if audit_id in self._memory_cache:
            del self._memory_cache[audit_id]

        if self._redis:
            try:
                stream_key = f"audit_stream:{audit_id}"
                await self._redis.delete(stream_key)
            except Exception as e:
                logger.error(f"清除 Redis Stream 失败: {e}")

    async def get_active_audits(self) -> list[str]:
        """获取活跃的审计 ID 列表"""
        return list(self._memory_cache.keys())

    def get_cache_stats(self) -> Dict[str, Any]:
        """获取缓存统计信息"""
        return {
            "active_audits": len(self._memory_cache),
            "total_events": sum(len(events) for events in self._memory_cache.values()),
            "subscribers": {aid: len(subs) for aid, subs in self._subscribers.items()},
        }


# 全局单例
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """获取全局事件总线实例"""
    global _event_bus

    if _event_bus is None:
        _event_bus = EventBus()

    return _event_bus


# 便捷函数
async def publish_event(
    audit_id: str,
    agent_type: str,
    event_type: str,
    data: Dict[str, Any],
) -> None:
    """发布审计事件（便捷函数）"""
    bus = get_event_bus()
    event = AuditEvent(
        audit_id=audit_id,
        agent_type=agent_type,
        event_type=event_type,
        data=data,
    )
    await bus.publish(event)


async def create_thinking_event(
    audit_id: str,
    agent_type: str,
    message: str,
) -> None:
    """创建思考事件（便捷函数）"""
    await publish_event(audit_id, agent_type, EventType.THINKING, {"message": message})


async def create_finding_event(
    audit_id: str,
    agent_type: str,
    finding: Dict[str, Any],
) -> None:
    """创建漏洞发现事件（便捷函数）"""
    await publish_event(audit_id, agent_type, EventType.FINDING, finding)


async def create_status_event(
    audit_id: str,
    status: str,
    message: str = "",
) -> None:
    """创建状态更新事件（便捷函数）"""
    await publish_event(audit_id, "system", EventType.STATUS, {
        "status": status,
        "message": message,
    })
