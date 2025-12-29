"""
Agent 图控制器

管理动态 Agent 树和 Agent 间通信
"""
from typing import Dict, Any, Optional, List
from loguru import logger
import uuid
import asyncio

from app.core.agent_registry import agent_registry, AgentRegistry
from app.core.message import MessageBus, MessageType, MessagePriority, AgentMessage


class AgentGraphController:
    """
    Agent 图控制器

    职责：
    1. 创建和管理 Agent 实例
    2. 处理 Agent 间消息传递
    3. 提供 Agent 树可视化数据
    """

    def __init__(self):
        self.registry = agent_registry
        self.message_bus = MessageBus()

        # Agent 类映射
        self._agent_classes = {}

    def register_agent_class(self, agent_type: str, agent_class: type) -> None:
        """
        注册 Agent 类

        Args:
            agent_type: Agent 类型标识
            agent_class: Agent 类
        """
        self._agent_classes[agent_type] = agent_class
        logger.info(f"注册 Agent 类: {agent_type} -> {agent_class.__name__}")

    async def create_agent(
        self,
        agent_type: str,
        task: str,
        parent_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        创建新 Agent

        Args:
            agent_type: Agent 类型
            task: 任务描述
            parent_id: 父 Agent ID
            config: 配置字典

        Returns:
            新创建的 Agent ID
        """
        agent_id = f"{agent_type}_{uuid.uuid4().hex[:8]}"

        # 获取 Agent 类
        agent_class = self._get_agent_class(agent_type)

        # 实例化 Agent
        try:
            agent_instance = agent_class(config=config)
        except Exception as e:
            logger.error(f"实例化 Agent 失败 ({agent_type}): {e}")
            raise

        # 注册到注册表
        await self.registry.register_agent(
            agent_id=agent_id,
            agent_name=agent_instance.name,
            agent_type=agent_type,
            task=task,
            parent_id=parent_id,
            agent_instance=agent_instance,
        )

        # 订阅消息
        await self.message_bus.subscribe(agent_id)

        logger.info(f"创建 Agent: {agent_id} ({agent_type})")

        return agent_id

    async def send_message_to_agent(
        self,
        from_agent: str,
        target_agent_id: str,
        message: Dict[str, Any],
        message_type: MessageType = MessageType.INFORMATION,
        priority: MessagePriority = MessagePriority.NORMAL,
    ) -> Dict[str, Any]:
        """
        向指定 Agent 发送消息

        Args:
            from_agent: 发送者 Agent ID
            target_agent_id: 目标 Agent ID
            message: 消息内容
            message_type: 消息类型
            priority: 消息优先级

        Returns:
            发送结果
        """
        # 检查目标 Agent 是否存在
        target_agent = await self.registry.get_agent(target_agent_id)
        if not target_agent:
            return {"error": "Target agent not found"}

        # 通过消息总线发送
        await self.message_bus.publish(
            sender=from_agent,
            recipient=target_agent_id,
            message_type=message_type,
            content=message.get("content", ""),
            priority=priority,
            data=message.get("data"),
        )

        logger.debug(f"发送消息: {from_agent} -> {target_agent_id}")

        return {"status": "message_sent", "target": target_agent_id}

    async def broadcast_message(
        self,
        from_agent: str,
        message: Dict[str, Any],
        recipient_type: Optional[str] = None,
    ) -> int:
        """
        广播消息到多个 Agent

        Args:
            from_agent: 发送者 Agent ID
            message: 消息内容
            recipient_type: 接收者类型（如果为 None 则发送给所有 Agent）

        Returns:
            接收者数量
        """
        all_agents = await self.registry.get_all_agents()

        recipients = []
        for agent in all_agents:
            # 跳过发送者
            if agent["agent_id"] == from_agent:
                continue

            # 类型过滤
            if recipient_type and agent["agent_type"] != recipient_type:
                continue

            recipients.append(agent["agent_id"])

        # 发送消息
        for recipient_id in recipients:
            await self.send_message_to_agent(
                from_agent=from_agent,
                target_agent_id=recipient_id,
                message=message,
            )

        logger.info(f"广播消息: {from_agent} -> {len(recipients)} 个 Agent")

        return len(recipients)

    async def get_agent_graph(
        self,
        current_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        获取 Agent 图结构

        Args:
            current_agent_id: 当前 Agent ID（作为根节点）

        Returns:
            Agent 树结构
        """
        return await self.registry.get_agent_tree(root_id=current_agent_id)

    async def stop_agent(
        self,
        agent_id: str,
        stop_children: bool = True,
    ) -> Dict[str, Any]:
        """
        停止 Agent

        Args:
            agent_id: Agent ID
            stop_children: 是否同时停止子 Agent

        Returns:
            停止结果
        """
        if stop_children:
            return await self.registry.stop_agent(agent_id)
        else:
            # 只停止当前 Agent，不影响子 Agent
            agent_info = await self.registry.get_agent(agent_id)
            if not agent_info:
                return {"error": "Agent not found"}

            # 停止实例
            instance = self.registry._agents[agent_id].instance
            if instance and hasattr(instance, "stop"):
                try:
                    await instance.stop()
                except Exception as e:
                    logger.warning(f"停止 Agent 实例失败: {e}")

            # 更新状态
            await self.registry.update_agent_status(agent_id, "stopped")

            return {"status": "stopped", "agent_id": agent_id}

    async def get_agent_status(
        self,
        agent_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        获取 Agent 状态

        Args:
            agent_id: Agent ID

        Returns:
            Agent 状态信息
        """
        agent_info = await self.registry.get_agent(agent_id)
        if not agent_info:
            return None

        # 获取 Agent 实例的状态（如果有）
        instance = self.registry._agents[agent_id].instance
        instance_status = None
        if instance and hasattr(instance, "get_status"):
            try:
                instance_status = await instance.get_status()
            except Exception as e:
                logger.warning(f"获取 Agent 状态失败: {e}")

        return {
            **agent_info,
            "instance_status": instance_status,
        }

    async def list_agents_by_type(
        self,
        agent_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        按类型和状态列出 Agent

        Args:
            agent_type: Agent 类型过滤
            status: 状态过滤

        Returns:
            Agent 列表
        """
        all_agents = await self.registry.get_all_agents()

        filtered = []
        for agent in all_agents:
            if agent_type and agent["agent_type"] != agent_type:
                continue
            if status and agent["status"] != status:
                continue
            filtered.append(agent)

        return filtered

    async def get_statistics(self) -> Dict[str, Any]:
        """
        获取 Agent 统计信息

        Returns:
            统计信息
        """
        stats = await self.registry.get_agent_stats()

        # 按类型分组
        all_agents = await self.registry.get_all_agents()
        by_type = {}
        for agent in all_agents:
            agent_type = agent["agent_type"]
            by_type[agent_type] = by_type.get(agent_type, 0) + 1

        return {
            **stats,
            "by_type": by_type,
        }

    def _get_agent_class(self, agent_type: str) -> type:
        """
        获取 Agent 类

        Args:
            agent_type: Agent 类型

        Returns:
            Agent 类

        Raises:
            ValueError: 如果 Agent 类型未注册
        """
        if agent_type not in self._agent_classes:
            # 尝试动态导入
            try:
                module_path = f"app.agents.{agent_type}"
                module = __import__(module_path, fromlist=[agent_type.capitalize()])
                agent_class = getattr(module, f"{agent_type.capitalize()}Agent")
                self.register_agent_class(agent_type, agent_class)
                return agent_class
            except ImportError:
                raise ValueError(f"未知的 Agent 类型: {agent_type}")

        return self._agent_classes[agent_type]


# 全局实例
agent_graph_controller = AgentGraphController()
