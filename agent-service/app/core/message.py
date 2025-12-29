"""
Agent 间消息系统

支持 Agent 之间的异步通信
"""
from typing import Dict, Any, Optional, Callable, Awaitable
from datetime import datetime
from loguru import logger
import asyncio
import uuid
from enum import Enum


class MessagePriority(Enum):
    """消息优先级"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class MessageType(Enum):
    """消息类型"""
    INFORMATION = "information"
    INSTRUCTION = "instruction"
    COMPLETION_REPORT = "completion_report"
    ERROR = "error"
    TASK_HANDOFF = "task_handoff"
    STATUS_UPDATE = "status_update"
    THINKING = "thinking"


class AgentMessage:
    """
    Agent 消息

    Agent 之间传递信息的载体
    """

    def __init__(
        self,
        sender: str,
        recipient: str,
        message_type: MessageType,
        content: str = "",
        priority: MessagePriority = MessagePriority.NORMAL,
        data: Optional[Dict[str, Any]] = None,
    ):
        self.message_id = f"msg_{uuid.uuid4().hex}"
        self.sender = sender
        self.recipient = recipient
        self.message_type = message_type
        self.content = content
        self.priority = priority
        self.data = data or {}
        self.timestamp = datetime.now()
        self.delivered = False
        self.read = False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "message_id": self.message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "message_type": self.message_type.value,
            "content": self.content,
            "priority": self.priority.value,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "delivered": self.delivered,
            "read": self.read,
        }


class MessageHandler:
    """
    消息处理器基类

    Agent 可以继承此类来处理接收到的消息
    """

    async def handle_message(self, message: AgentMessage) -> Optional[str]:
        """
        处理接收到的消息

        Args:
            message: 接收到的消息

        Returns:
            可选的回复内容
        """
        # 子类覆盖此方法
        logger.debug(f"处理消息: {message.message_type} from {message.sender}")
        return None


class MessageBus:
    """
    Agent 消息总线

    管理 Agent 间的消息传递
    """

    def __init__(self):
        self._queues: Dict[str, asyncio.Queue] = {}
        self._handlers: Dict[str, Callable] = {}
        self._message_history: List[AgentMessage] = []
        self._max_history = 1000

    async def subscribe(
        self,
        agent_id: str,
        handler: Optional[Callable] = None,
    ) -> asyncio.Queue:
        """
        订阅消息

        Args:
            agent_id: Agent ID
            handler: 可选的消息处理器

        Returns:
            消息队列
        """
        if agent_id not in self._queues:
            self._queues[agent_id] = asyncio.Queue()

        if handler:
            self._handlers[agent_id] = handler

        logger.debug(f"Agent {agent_id} 订阅消息总线")
        return self._queues[agent_id]

    async def unsubscribe(self, agent_id: str) -> None:
        """
        取消订阅

        Args:
            agent_id: Agent ID
        """
        if agent_id in self._queues:
            del self._queues[agent_id]

        if agent_id in self._handlers:
            del self._handlers[agent_id]

        logger.debug(f"Agent {agent_id} 取消订阅")

    async def publish(
        self,
        sender: str,
        recipient: str,
        message_type: MessageType = MessageType.INFORMATION,
        content: str = "",
        priority: MessagePriority = MessagePriority.NORMAL,
        data: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        发布消息

        Args:
            sender: 发送者 Agent ID
            recipient: 接收者 Agent ID
            message_type: 消息类型
            content: 消息内容
            priority: 消息优先级
            data: 附加数据

        Returns:
            是否成功发送
        """
        if recipient not in self._queues:
            logger.warning(f"接收者 {recipient} 未订阅消息")
            return False

        # 创建消息
        message = AgentMessage(
            sender=sender,
            recipient=recipient,
            message_type=message_type,
            content=content,
            priority=priority,
            data=data,
        )

        # 加入历史
        self._add_to_history(message)

        # 发送到队列
        try:
            await self._queues[recipient].put(message)
            message.delivered = True
            logger.debug(f"消息发送: {sender} -> {recipient} ({message_type.value})")
            return True
        except Exception as e:
            logger.error(f"消息发送失败: {e}")
            return False

    async def receive_messages(
        self,
        agent_id: str,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[AgentMessage]:
        """
        接收消息（异步迭代器）

        Args:
            agent_id: Agent ID
            timeout: 超时时间（秒）

        Yields:
            接收到的消息
        """
        if agent_id not in self._queues:
            # 自动订阅
            await self.subscribe(agent_id)

        queue = self._queues[agent_id]

        while True:
            try:
                # 等待消息，支持超时
                message = await asyncio.wait_for(
                    queue.get(),
                    timeout=timeout,
                )
                message.read = True

                # 调用处理器（如果有）
                handler = self._handlers.get(agent_id)
                if handler:
                    try:
                        response = await handler(message)
                        if response:
                            # 发送回复
                            await self.publish(
                                sender=agent_id,
                                recipient=message.sender,
                                message_type=MessageType.INFORMATION,
                                content=response,
                            )
                    except Exception as e:
                        logger.error(f"消息处理器错误: {e}")

                yield message

            except asyncio.TimeoutError:
                # 超时继续
                continue
            except asyncio.CancelledError:
                # 取消
                break

    async def send_and_wait(
        self,
        sender: str,
        recipient: str,
        message_type: MessageType,
        content: str = "",
        data: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> Optional[AgentMessage]:
        """
        发送消息并等待回复

        Args:
            sender: 发送者
            recipient: 接收者
            message_type: 消息类型
            content: 消息内容
            data: 附加数据
            timeout: 超时时间

        Returns:
            回复消息，如果超时返回 None
        """
        # 临时订阅以接收回复
        temp_queue = asyncio.Queue()
        original_queue = self._queues.get(sender)
        self._queues[sender] = temp_queue

        try:
            # 发送消息
            await self.publish(
                sender=sender,
                recipient=recipient,
                message_type=message_type,
                content=content,
                data=data,
            )

            # 等待回复
            try:
                reply = await asyncio.wait_for(
                    temp_queue.get(),
                    timeout=timeout,
                )
                return reply
            except asyncio.TimeoutError:
                logger.warning(f"等待回复超时: {sender} <- {recipient}")
                return None

        finally:
            # 恢复原始队列
            if original_queue:
                self._queues[sender] = original_queue
            else:
                del self._queues[sender]

    def _add_to_history(self, message: AgentMessage) -> None:
        """添加到历史记录"""
        self._message_history.append(message)

        # 限制历史大小
        if len(self._message_history) > self._max_history:
            self._message_history = self._message_history[-self._max_history:]

    def get_message_history(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        获取消息历史

        Args:
            agent_id: 过滤特定 Agent 的消息
            limit: 返回数量限制

        Returns:
            消息历史列表
        """
        history = self._message_history

        # 过滤
        if agent_id:
            history = [
                m for m in history
                if m.sender == agent_id or m.recipient == agent_id
            ]

        # 限制数量
        history = history[-limit:]

        return [m.to_dict() for m in history]

    async def clear_history(self, older_than_seconds: int = 3600) -> int:
        """
        清理旧消息历史

        Args:
            older_than_seconds: 清理时间超过此值的消息

        Returns:
            清理的消息数量
        """
        now = datetime.now()
        cutoff = now.timestamp() - older_than_seconds

        old_size = len(self._message_history)
        self._message_history = [
            m for m in self._message_history
            if m.timestamp.timestamp() > cutoff
        ]

        removed = old_size - len(self._message_history)
        if removed > 0:
            logger.info(f"清理了 {removed} 条历史消息")

        return removed

    def get_queue_sizes(self) -> Dict[str, int]:
        """
        获取各 Agent 的队列大小

        Returns:
            队列大小字典
        """
        return {
            agent_id: queue.qsize()
            for agent_id, queue in self._queues.items()
        }


# 全局实例
message_bus = MessageBus()
