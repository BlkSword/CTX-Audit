"""
Agent 注册表

管理运行中的 Agent 实例，支持动态 Agent 树管理
"""
from typing import Dict, Optional, List, Any
from datetime import datetime
from loguru import logger
import asyncio
import uuid


class AgentInfo:
    """Agent 信息"""

    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        agent_type: str,
        task: str,
        parent_id: Optional[str] = None,
        agent_instance: Optional[Any] = None,
    ):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_type = agent_type
        self.task = task
        self.parent_id = parent_id
        self.instance = agent_instance
        self.status = "running"
        self.created_at = datetime.now().isoformat()
        self.children: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "task": self.task,
            "parent_id": self.parent_id,
            "status": self.status,
            "created_at": self.created_at,
            "children": self.children,
        }


class AgentRegistry:
    """
    Agent 注册表 - 单例模式

    管理 Agent 生命周期：
    1. 注册新 Agent
    2. 更新 Agent 状态
    3. 获取 Agent 树结构
    4. 停止 Agent
    """

    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._agents: Dict[str, AgentInfo] = {}
        return cls._instance

    async def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        agent_type: str,
        task: str,
        parent_id: Optional[str] = None,
        agent_instance: Optional[Any] = None,
    ) -> AgentInfo:
        """
        注册一个新 Agent

        Args:
            agent_id: Agent 唯一 ID
            agent_name: Agent 名称
            agent_type: Agent 类型
            task: 当前任务描述
            parent_id: 父 Agent ID
            agent_instance: Agent 实例

        Returns:
            AgentInfo 对象
        """
        async with self._lock:
            agent_info = AgentInfo(
                agent_id=agent_id,
                agent_name=agent_name,
                agent_type=agent_type,
                task=task,
                parent_id=parent_id,
                agent_instance=agent_instance,
            )

            self._agents[agent_id] = agent_info

            # 更新父 Agent 的子 Agent 列表
            if parent_id and parent_id in self._agents:
                self._agents[parent_id].children.append(agent_id)

            logger.info(
                f"注册 Agent: {agent_name} ({agent_type}) "
                f"[parent: {parent_id or 'none'}]"
            )

            return agent_info

    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        获取 Agent 信息

        Args:
            agent_id: Agent ID

        Returns:
            Agent 信息字典，如果不存在返回 None
        """
        agent_info = self._agents.get(agent_id)
        if agent_info:
            return agent_info.to_dict()
        return None

    async def update_agent_status(
        self,
        agent_id: str,
        status: str,
    ) -> None:
        """
        更新 Agent 状态

        Args:
            agent_id: Agent ID
            status: 新状态 (running, completed, stopped, error)
        """
        if agent_id in self._agents:
            self._agents[agent_id].status = status
            logger.info(f"Agent {agent_id} 状态更新: {status}")

    async def update_agent_task(
        self,
        agent_id: str,
        task: str,
    ) -> None:
        """
        更新 Agent 当前任务

        Args:
            agent_id: Agent ID
            task: 新任务描述
        """
        if agent_id in self._agents:
            self._agents[agent_id].task = task

    async def get_agent_tree(
        self,
        root_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        获取 Agent 树结构

        Args:
            root_id: 根 Agent ID，如果为 None 则自动查找

        Returns:
            Agent 树字典
        """
        if root_id is None:
            root_id = self._find_root_agent()

        if root_id not in self._agents:
            return {}

        return self._build_tree(root_id)

    def _build_tree(self, agent_id: str) -> Dict[str, Any]:
        """
        递归构建 Agent 树

        Args:
            agent_id: 当前 Agent ID

        Returns:
            Agent 子树
        """
        agent_info = self._agents[agent_id]
        tree = agent_info.to_dict()

        # 递归构建子树
        tree["children"] = [
            self._build_tree(child_id)
            for child_id in agent_info.children
        ]

        return tree

    def _find_root_agent(self) -> Optional[str]:
        """
        查找根 Agent（没有父节点的 Agent）

        Returns:
            根 Agent ID，如果没有找到返回 None
        """
        for agent_id, agent_info in self._agents.items():
            if agent_info.parent_id is None:
                return agent_id
        return None

    async def get_all_agents(self) -> List[Dict[str, Any]]:
        """
        获取所有 Agent 信息

        Returns:
            Agent 信息列表
        """
        return [info.to_dict() for info in self._agents.values()]

    async def stop_agent(self, agent_id: str) -> Dict[str, Any]:
        """
        停止指定 Agent 及其子 Agent

        Args:
            agent_id: Agent ID

        Returns:
            停止结果
        """
        async with self._lock:
            if agent_id not in self._agents:
                return {"error": "Agent not found"}

            # 递归停止子 Agent
            children = self._agents[agent_id].children.copy()
            for child_id in children:
                await self.stop_agent(child_id)

            # 停止 Agent 实例
            agent_info = self._agents[agent_id]
            instance = agent_info.instance
            if instance and hasattr(instance, "stop"):
                try:
                    await instance.stop()
                except Exception as e:
                    logger.warning(f"停止 Agent 实例失败: {e}")

            # 更新状态
            agent_info.status = "stopped"

            # 从父 Agent 的子列表中移除
            parent_id = agent_info.parent_id
            if parent_id and parent_id in self._agents:
                parent = self._agents[parent_id]
                if agent_id in parent.children:
                    parent.children.remove(agent_id)

            logger.info(f"Agent {agent_id} 已停止")

            return {"status": "stopped", "agent_id": agent_id}

    async def cleanup_stopped_agents(self, older_than_seconds: int = 3600) -> int:
        """
        清理已停止的 Agent

        Args:
            older_than_seconds: 清理停止时间超过此值的 Agent

        Returns:
            清理的 Agent 数量
        """
        async with self._lock:
            now = datetime.now()
            to_remove = []

            for agent_id, agent_info in self._agents.items():
                if agent_info.status == "stopped":
                    created_at = datetime.fromisoformat(agent_info.created_at)
                    # 简化计算：假设停止时间不久
                    if (now - created_at).total_seconds() > older_than_seconds:
                        to_remove.append(agent_id)

            for agent_id in to_remove:
                del self._agents[agent_id]

            if to_remove:
                logger.info(f"清理了 {len(to_remove)} 个已停止的 Agent")

            return len(to_remove)

    async def get_agent_stats(self) -> Dict[str, int]:
        """
        获取 Agent 统计信息

        Returns:
            统计信息字典
        """
        stats = {
            "total": len(self._agents),
            "running": 0,
            "completed": 0,
            "stopped": 0,
            "error": 0,
        }

        for agent_info in self._agents.values():
            status = agent_info.status
            if status in stats:
                stats[status] += 1

        return stats

    def __len__(self) -> int:
        """返回当前 Agent 数量"""
        return len(self._agents)

    def __contains__(self, agent_id: str) -> bool:
        """检查 Agent 是否存在"""
        return agent_id in self._agents


# 全局实例
agent_registry = AgentRegistry()
