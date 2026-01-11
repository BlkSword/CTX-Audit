"""
Cancellation Coordinator Module

实现级联取消机制 - 父Agent取消传播到子Agent
"""
import asyncio
from typing import Dict, Set, Optional, Callable, Awaitable, Any
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger


class CancelReason(str, Enum):
    """取消原因"""
    USER_REQUEST = "user_request"      # 用户主动取消
    TIMEOUT = "timeout"                # 超时取消
    ERROR = "error"                    # 错误导致取消
    PARENT_CANCELLED = "parent_cancelled"  # 父Agent被取消
    RESOURCE_LIMIT = "resource_limit"  # 资源限制


@dataclass
class CancellationToken:
    """取消令牌"""
    is_cancelled: bool = False
    reason: Optional[CancelReason] = None
    message: str = ""

    def cancel(self, reason: CancelReason = CancelReason.USER_REQUEST, message: str = ""):
        """标记为取消"""
        self.is_cancelled = True
        self.reason = reason
        self.message = message

    def reset(self):
        """重置取消状态"""
        self.is_cancelled = False
        self.reason = None
        self.message = ""


@dataclass
class AgentNode:
    """Agent节点（用于取消树）"""
    agent_id: str
    agent_name: str
    parent_id: Optional[str] = None
    children: Set[str] = field(default_factory=set)
    token: CancellationToken = field(default_factory=CancellationToken)
    cancel_callback: Optional[Callable[[], Awaitable[None]]] = None


class CancellationCoordinator:
    """
    取消协调器

    管理Agent之间的取消关系：
    1. 父Agent取消时，自动取消所有子Agent
    2. 支持取消令牌传递
    3. 支持取消回调
    """

    def __init__(self):
        self._agents: Dict[str, AgentNode] = {}
        self._lock = asyncio.Lock()

    async def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        parent_id: Optional[str] = None,
        cancel_callback: Optional[Callable[[], Awaitable[None]]] = None,
    ) -> CancellationToken:
        """
        注册Agent

        Args:
            agent_id: Agent ID
            agent_name: Agent名称
            parent_id: 父Agent ID
            cancel_callback: 取消回调函数

        Returns:
            取消令牌
        """
        async with self._lock:
            token = CancellationToken()
            node = AgentNode(
                agent_id=agent_id,
                agent_name=agent_name,
                parent_id=parent_id,
                token=token,
                cancel_callback=cancel_callback,
            )

            self._agents[agent_id] = node

            # 更新父节点的子节点列表
            if parent_id and parent_id in self._agents:
                self._agents[parent_id].children.add(agent_id)

            logger.debug(
                f"[CancelCoordinator] 注册 Agent: {agent_name} "
                f"(parent: {parent_id or 'none'})"
            )

            return token

    async def unregister_agent(self, agent_id: str):
        """注销Agent"""
        async with self._lock:
            if agent_id in self._agents:
                node = self._agents[agent_id]

                # 从父节点的子列表中移除
                if node.parent_id and node.parent_id in self._agents:
                    self._agents[node.parent_id].children.discard(agent_id)

                # 递归取消所有子节点
                for child_id in list(node.children):
                    await self.cancel_agent(
                        child_id,
                        reason=CancelReason.PARENT_CANCELLED,
                        message=f"父Agent {node.agent_name} 被注销"
                    )

                del self._agents[agent_id]

    async def cancel_agent(
        self,
        agent_id: str,
        reason: CancelReason = CancelReason.USER_REQUEST,
        message: str = "",
        propagate: bool = True,
    ) -> bool:
        """
        取消Agent

        Args:
            agent_id: Agent ID
            reason: 取消原因
            message: 取消消息
            propagate: 是否传播到子Agent

        Returns:
            是否成功取消
        """
        async with self._lock:
            if agent_id not in self._agents:
                logger.warning(f"[CancelCoordinator] Agent {agent_id} 不存在")
                return False

            node = self._agents[agent_id]

            # 标记取消
            node.token.cancel(reason, message or f"Agent {node.agent_name} 被取消")

            logger.info(
                f"[CancelCoordinator] 取消 Agent: {node.agent_name} "
                f"(reason: {reason.value}, propagate: {propagate})"
            )

            # 调用取消回调
            if node.cancel_callback:
                try:
                    await node.cancel_callback()
                except Exception as e:
                    logger.error(f"[CancelCoordinator] 取消回调失败: {e}")

            # 级联取消子Agent
            if propagate:
                for child_id in list(node.children):
                    await self.cancel_agent(
                        child_id,
                        reason=CancelReason.PARENT_CANCELLED,
                        message=f"父Agent {node.agent_name} 被取消",
                        propagate=True,
                    )

            return True

    def is_cancelled(self, agent_id: str) -> bool:
        """检查Agent是否被取消"""
        node = self._agents.get(agent_id)
        return node.token.is_cancelled if node else False

    def get_token(self, agent_id: str) -> Optional[CancellationToken]:
        """获取Agent的取消令牌"""
        node = self._agents.get(agent_id)
        return node.token if node else None

    async def cancel_all(
        self,
        reason: CancelReason = CancelReason.USER_REQUEST,
        message: str = "",
    ):
        """取消所有Agent"""
        async with self._lock:
            # 找出所有根Agent（没有父节点的）
            root_agents = [
                agent_id
                for agent_id, node in self._agents.items()
                if node.parent_id is None
            ]

            # 取消所有根Agent（会自动级联到子Agent）
            for agent_id in root_agents:
                await self.cancel_agent(agent_id, reason, message)

    def get_cancel_tree(self) -> Dict[str, Any]:
        """获取取消树结构"""
        def build_tree(agent_id: str) -> Dict[str, Any]:
            node = self._agents.get(agent_id)
            if not node:
                return {}

            return {
                "agent_id": node.agent_id,
                "agent_name": node.agent_name,
                "is_cancelled": node.token.is_cancelled,
                "cancel_reason": node.token.reason.value if node.token.reason else None,
                "children": [
                    build_tree(child_id)
                    for child_id in node.children
                ],
            }

        # 找出根Agent
        roots = [
            agent_id
            for agent_id, node in self._agents.items()
            if node.parent_id is None
        ]

        return {
            "roots": [build_tree(root_id) for root_id in roots],
            "total_agents": len(self._agents),
        }


class CancellableTask:
    """
    可取消的任务包装器

    用法：
        async def my_agent_task(token: CancellationToken):
            while not token.is_cancelled:
                # 执行任务
                await do_work()
                # 检查取消
                await token.wait_if_cancelled()

        coordinator = CancellationCoordinator()
        token = await coordinator.register_agent("agent1", "Agent 1")

        # 创建可取消任务
        task = CancellableTask(my_agent_task, token)
        result = await task.run()
    """

    def __init__(
        self,
        coro: Callable[[CancellationToken], Awaitable[Any]],
        token: CancellationToken,
        check_interval: float = 0.5,
    ):
        """
        初始化可取消任务

        Args:
            coro: 协程函数，接收CancellationToken参数
            token: 取消令牌
            check_interval: 取消检查间隔（秒）
        """
        self.coro = coro
        self.token = token
        self.check_interval = check_interval
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def run(self) -> Any:
        """运行任务"""
        self._task = asyncio.create_task(self._run_with_cancel_check())
        return await self._task

    async def _run_with_cancel_check(self) -> Any:
        """带取消检查的任务运行"""
        try:
            # 创建一个包装任务来定期检查取消状态
            result = await self.coro(self.token)
            return result
        except asyncio.CancelledError:
            logger.info("[CancellableTask] 任务被取消")
            raise
        except Exception as e:
            logger.error(f"[CancellableTask] 任务执行失败: {e}")
            raise

    async def cancel(self):
        """取消任务"""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass


# 全局取消协调器
_global_coordinator: Optional[CancellationCoordinator] = None


def get_cancellation_coordinator() -> CancellationCoordinator:
    """获取全局取消协调器"""
    global _global_coordinator
    if _global_coordinator is None:
        _global_coordinator = CancellationCoordinator()
    return _global_coordinator


async def register_cancellable_agent(
    agent_id: str,
    agent_name: str,
    parent_id: Optional[str] = None,
    cancel_callback: Optional[Callable[[], Awaitable[None]]] = None,
) -> CancellationToken:
    """
    注册可取消的Agent

    Args:
        agent_id: Agent ID
        agent_name: Agent名称
        parent_id: 父Agent ID
        cancel_callback: 取消回调

    Returns:
        取消令牌
    """
    coordinator = get_cancellation_coordinator()
    return await coordinator.register_agent(
        agent_id, agent_name, parent_id, cancel_callback
    )


async def cancel_agent_tree(
    agent_id: str,
    reason: CancelReason = CancelReason.USER_REQUEST,
    message: str = "",
) -> bool:
    """
    取消Agent及其所有子Agent

    Args:
        agent_id: Agent ID
        reason: 取消原因
        message: 取消消息

    Returns:
        是否成功取消
    """
    coordinator = get_cancellation_coordinator()
    return await coordinator.cancel_agent(agent_id, reason, message)
