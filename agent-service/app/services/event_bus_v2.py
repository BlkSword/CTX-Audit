"""
审计事件总线 V2 - 参照 CTX-Audit 架构

基于 asyncio.Queue 的实时事件推送系统
特性：
- 内存队列缓存（无需 Redis）
- SSE 实时推送
- 事件持久化到 SQLite（可选）
- 序列号追踪
"""
from typing import Dict, Any, Optional, AsyncIterator, List
from loguru import logger
from datetime import datetime
import asyncio
import json
import uuid

from app.config import settings


class AuditEvent:
    """
    审计事件

    Attributes:
        event_id: 事件唯一 ID
        audit_id: 审计 ID
        agent_type: Agent 类型 (orchestrator | recon | analysis | verification)
        event_type: 事件类型
        sequence: 序列号
        timestamp: 时间戳
        data: 事件数据
    """

    def __init__(
        self,
        audit_id: str,
        agent_type: str,
        event_type: str,
        sequence: int = 0,
        data: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
    ):
        self.event_id = str(uuid.uuid4())
        self.audit_id = audit_id
        self.agent_type = agent_type
        self.event_type = event_type
        self.sequence = sequence
        self.timestamp = datetime.now().isoformat()
        self.data = data or {}
        self.message = message

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典（SSE 格式）"""
        return {
            "id": self.event_id,
            "audit_id": self.audit_id,
            "agent_type": self.agent_type,
            "event_type": self.event_type,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "data": self.data,
            "message": self.message,
        }

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False)


class EventBusV2:
    """
    审计事件总线 V2

    特性：
    - 使用 asyncio.Queue 缓存事件
    - SSE 实时推送
    - 支持多订阅者
    - 序列号追踪
    """

    def __init__(self, queue_size: int = 5000):
        """
        初始化事件总线

        Args:
            queue_size: 每个 audit_id 的队列大小
        """
        # 每个审计任务的事件队列 {audit_id: asyncio.Queue}
        self._queues: Dict[str, asyncio.Queue] = {}
        # 序列号计数器 {audit_id: int}
        self._sequences: Dict[str, int] = {}
        # 队列大小
        self._queue_size = queue_size
        # 订阅者计数 {audit_id: int}
        self._subscribers: Dict[str, int] = {}
        # 运行状态
        self._running = False

    async def initialize(self):
        """初始化事件总线"""
        self._running = True
        logger.info("事件总线 V2 已启动")

    async def shutdown(self):
        """关闭事件总线"""
        self._running = False
        # 关闭所有队列
        for audit_id, queue in self._queues.items():
            try:
                queue.put_nowait({"event_type": "shutdown", "timestamp": datetime.now().isoformat()})
            except asyncio.QueueFull:
                pass
        self._queues.clear()
        self._sequences.clear()
        self._subscribers.clear()
        logger.info("事件总线 V2 已关闭")

    def get_queue(self, audit_id: str) -> asyncio.Queue:
        """获取或创建事件队列"""
        if audit_id not in self._queues:
            self._queues[audit_id] = asyncio.Queue(maxsize=self._queue_size)
            self._sequences[audit_id] = 0
            logger.info(f"创建事件队列: {audit_id}")
        return self._queues[audit_id]

    def get_sequence(self, audit_id: str) -> int:
        """获取下一个序列号"""
        if audit_id not in self._sequences:
            self._sequences[audit_id] = 0
        self._sequences[audit_id] += 1
        return self._sequences[audit_id]

    async def publish(
        self,
        audit_id: str,
        agent_type: str,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
        persist: bool = True,
    ) -> str:
        """
        发布事件

        Args:
            audit_id: 审计 ID
            agent_type: Agent 类型
            event_type: 事件类型
            data: 事件数据
            message: 事件消息
            persist: 是否持久化到数据库

        Returns:
            事件 ID
        """
        if not self._running:
            logger.warning(f"事件总线未运行，丢弃事件: {agent_type}/{event_type}")
            return ""

        logger.info(f"[事件发布] {agent_type}/{event_type} - {message}")

        # 获取序列号
        sequence = self.get_sequence(audit_id)

        # 创建事件
        event = AuditEvent(
            audit_id=audit_id,
            agent_type=agent_type,
            event_type=event_type,
            sequence=sequence,
            data=data,
            message=message,
        )

        event_dict = event.to_dict()

        # 获取队列
        queue = self.get_queue(audit_id)

        # 1. 立即推送到队列（实时 SSE，不阻塞）
        try:
            queue.put_nowait(event_dict)
        except asyncio.QueueFull:
            logger.warning(f"事件队列已满: {audit_id}, 丢弃事件: {event_type}")

        # 2. 异步持久化到数据库（不阻塞推送）
        if persist:
            try:
                from app.services.event_persistence import get_event_persistence
                persistence = get_event_persistence()
                # 使用 create_task 异步保存，不阻塞
                asyncio.create_task(persistence.save_event(event_dict))
            except Exception as e:
                logger.warning(f"事件持久化失败（不影响推送）: {e}")

        logger.debug(f"[{agent_type}] {event_type}: {message or str(data)[:50]}")
        return event.event_id

    async def subscribe(
        self,
        audit_id: str,
        after_sequence: int = 0,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        订阅审计事件流（SSE）

        Args:
            audit_id: 审计 ID
            after_sequence: 从哪个序列号开始

        Yields:
            事件字典
        """
        queue = self.get_queue(audit_id)
        self._subscribers[audit_id] = self._subscribers.get(audit_id, 0) + 1

        logger.info(f"[SSE] 订阅事件流: {audit_id}, after_sequence={after_sequence}, queue_size={queue.qsize()}")

        try:
            # 1. 先发送队列中已缓存的事件（过滤序列号）
            buffered_count = 0
            skipped_count = 0
            initial_size = queue.qsize()

            # 只消耗连接时已存在的事件，避免无限循环
            for _ in range(initial_size):
                try:
                    event = queue.get_nowait()
                    event_seq = event.get("sequence", 0)

                    if event_seq <= after_sequence:
                        skipped_count += 1
                        continue

                    buffered_count += 1
                    logger.debug(f"[SSE] 发送缓存事件: {event.get('event_type')} (seq={event_seq})")
                    yield event

                    # 检查是否是结束事件
                    if event.get("event_type") in ["complete", "error", "cancelled"]:
                        logger.info(f"[SSE] 任务已完成，结束流: {audit_id}")
                        return

                except asyncio.QueueEmpty:
                    break

            if buffered_count > 0 or skipped_count > 0:
                logger.info(f"[SSE] {audit_id}: 发送 {buffered_count} 个缓存事件，跳过 {skipped_count} 个")

            # 2. 实时推送新事件
            logger.info(f"[SSE] {audit_id}: 进入实时循环")
            last_heartbeat = asyncio.get_event_loop().time()

            while True:
                try:
                    # 等待新事件，超时发送心跳
                    event = await asyncio.wait_for(queue.get(), timeout=5.0)

                    event_seq = event.get("sequence", 0)
                    if event_seq <= after_sequence:
                        logger.debug(f"[SSE] 跳过旧事件: seq={event_seq}")
                        continue

                    logger.debug(f"[SSE] 发送实时事件: {event.get('event_type')} (seq={event_seq})")
                    yield event

                    # 检查是否是结束事件
                    if event.get("event_type") in ["complete", "error", "cancelled"]:
                        logger.info(f"[SSE] 任务已完成，结束流: {audit_id}")
                        return

                    # 更新心跳时间
                    last_heartbeat = asyncio.get_event_loop().time()

                except asyncio.TimeoutError:
                    # 发送心跳保持连接
                    current_time = asyncio.get_event_loop().time()
                    if current_time - last_heartbeat > 15:
                        # 只在 15 秒后发送心跳，减少日志
                        last_heartbeat = current_time
                        logger.debug(f"[SSE] 发送心跳: {audit_id}")
                        yield {
                            "event_type": "heartbeat",
                            "timestamp": datetime.now().isoformat(),
                        }

        except GeneratorExit:
            logger.debug(f"[SSE] 客户端断开连接: {audit_id}")
        finally:
            self._subscribers[audit_id] = self._subscribers.get(audit_id, 1) - 1

    def remove_queue(self, audit_id: str):
        """移除事件队列"""
        if audit_id in self._queues:
            del self._queues[audit_id]
            logger.info(f"移除事件队列: {audit_id}")
        if audit_id in self._sequences:
            del self._sequences[audit_id]

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "queues": len(self._queues),
            "subscribers": sum(self._subscribers.values()),
            "queue_sizes": {
                audit_id: queue.qsize()
                for audit_id, queue in self._queues.items()
            },
        }


# 全局单例
_event_bus: Optional[EventBusV2] = None


def get_event_bus_v2() -> EventBusV2:
    """获取事件总线单例"""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBusV2()
    return _event_bus


async def init_event_bus():
    """初始化事件总线"""
    bus = get_event_bus_v2()
    await bus.initialize()
    return bus


async def shutdown_event_bus():
    """关闭事件总线"""
    global _event_bus
    if _event_bus:
        await _event_bus.shutdown()
        _event_bus = None
