"""
动态 Agent 执行器

支持动态创建 Agent、并行执行、优先级调度等高级功能
"""
import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Callable, Awaitable
from loguru import logger
from collections import deque

from app.core.monitoring import get_monitoring_system


class AgentPriority(str, Enum):
    """Agent 优先级"""
    CRITICAL = "critical"  # 关键（最高优先级）
    HIGH = "high"          # 高
    NORMAL = "normal"      # 正常
    LOW = "low"           # 低


@dataclass
class AgentTask:
    """Agent 任务"""
    task_id: str
    agent_type: str
    agent_factory: Callable[[], Awaitable[Any]]
    input_data: Dict[str, Any]
    priority: AgentPriority = AgentPriority.NORMAL
    dependencies: List[str] = field(default_factory=list)  # 依赖的任务 ID
    timeout: float = 300.0  # 超时时间（秒）
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    status: str = "pending"  # pending | running | completed | failed | cancelled
    result: Optional[Any] = None
    error: Optional[Exception] = None

    @property
    def duration(self) -> Optional[float]:
        """任务持续时间"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def is_ready(self) -> bool:
        """是否准备好执行（依赖已满足）"""
        return self.status == "pending" and not self.dependencies

    def mark_started(self) -> None:
        """标记任务开始"""
        self.status = "running"
        self.started_at = time.time()

    def mark_completed(self, result: Any) -> None:
        """标记任务完成"""
        self.status = "completed"
        self.completed_at = time.time()
        self.result = result

    def mark_failed(self, error: Exception) -> None:
        """标记任务失败"""
        self.status = "failed"
        self.completed_at = time.time()
        self.error = error

    def mark_cancelled(self) -> None:
        """标记任务取消"""
        self.status = "cancelled"
        self.completed_at = time.time()


@dataclass
class AgentNode:
    """Agent 节点（用于构建 Agent 树）"""
    node_id: str
    agent_type: str
    task: AgentTask
    parent_id: Optional[str] = None
    children: List[str] = field(default_factory=list)

    @property
    def depth(self) -> int:
        """节点深度（根节点为 0）"""
        return 0  # 需要通过树结构计算


class DynamicAgentExecutor:
    """
    动态 Agent 执行器

    功能：
    - 动态创建和管理 Agent
    - 并行执行多个 Agent
    - 处理 Agent 间的依赖关系
    - 支持优先级调度
    """

    def __init__(
        self,
        max_parallel: int = 5,
        default_timeout: float = 600.0,
        monitoring_enabled: bool = True,
    ):
        self.max_parallel = max_parallel
        self.default_timeout = default_timeout
        self.monitoring_enabled = monitoring_enabled
        self._semaphore = asyncio.Semaphore(max_parallel)
        self._tasks: Dict[str, AgentTask] = {}
        self._nodes: Dict[str, AgentNode] = {}
        self._running_tasks: set[str] = set()
        self._cancelled = False
        self._monitoring = get_monitoring_system() if monitoring_enabled else None

    async def submit_agent(
        self,
        task_id: str,
        agent_type: str,
        agent_factory: Callable[[], Awaitable[Any]],
        input_data: Dict[str, Any],
        priority: AgentPriority = AgentPriority.NORMAL,
        dependencies: Optional[List[str]] = None,
        parent_id: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """
        提交 Agent 任务

        Args:
            task_id: 任务 ID
            agent_type: Agent 类型
            agent_factory: Agent 工厂函数
            input_data: 输入数据
            priority: 优先级
            dependencies: 依赖的任务 ID 列表
            parent_id: 父节点 ID
            timeout: 超时时间

        Returns:
            任务 ID
        """
        task = AgentTask(
            task_id=task_id,
            agent_type=agent_type,
            agent_factory=agent_factory,
            input_data=input_data,
            priority=priority,
            dependencies=dependencies or [],
            timeout=timeout or self.default_timeout,
        )

        self._tasks[task_id] = task

        # 创建节点
        node = AgentNode(
            node_id=task_id,
            agent_type=agent_type,
            task=task,
            parent_id=parent_id,
        )
        self._nodes[task_id] = node

        # 更新父节点的子节点列表
        if parent_id and parent_id in self._nodes:
            self._nodes[parent_id].children.append(task_id)

        logger.info(f"Agent task submitted: {task_id} (type={agent_type}, priority={priority})")

        # 尝试执行任务
        asyncio.create_task(self._try_execute_task(task_id))

        return task_id

    async def _try_execute_task(self, task_id: str) -> None:
        """尝试执行任务"""
        task = self._tasks.get(task_id)
        if not task:
            return

        # 检查依赖
        if task.dependencies:
            for dep_id in task.dependencies:
                dep_task = self._tasks.get(dep_id)
                if dep_task and dep_task.status != "completed":
                    logger.debug(f"Task {task_id} waiting for dependency {dep_id}")
                    return

        # 检查是否可以执行
        if not task.is_ready:
            return

        # 执行任务
        asyncio.create_task(self._execute_task(task_id))

    async def _execute_task(self, task_id: str) -> None:
        """执行 Agent 任务"""
        task = self._tasks.get(task_id)
        if not task:
            return

        async with self._semaphore:  # 限制并行数
            if self._cancelled or task.status == "cancelled":
                return

            task.mark_started()
            self._running_tasks.add(task_id)

            try:
                # 执行 Agent
                agent = await task.agent_factory()
                result = await agent.run(task.input_data)

                task.mark_completed(result)

                # 记录监控数据
                if self._monitoring:
                    self._monitoring.record_agent_execution(
                        agent_type=task.agent_type,
                        duration=task.duration or 0,
                        iterations=0,  # 可以从 result 中提取
                        findings_count=0,  # 可以从 result 中提取
                        success=True,
                    )

                logger.info(f"Agent task completed: {task_id}")

            except asyncio.TimeoutError:
                error = TimeoutError(f"Agent task {task_id} timed out")
                task.mark_failed(error)
                logger.error(f"Agent task timed out: {task_id}")

            except asyncio.CancelledError:
                task.mark_cancelled()
                logger.info(f"Agent task cancelled: {task_id}")

            except Exception as e:
                task.mark_failed(e)
                logger.error(f"Agent task failed: {task_id} - {e}")

                # 记录错误
                if self._monitoring:
                    await self._monitoring.errors.record_error(
                        e, {"task_id": task_id, "agent_type": task.agent_type}
                    )

            finally:
                self._running_tasks.discard(task_id)

                # 触发依赖此任务的其他任务
                for other_id, other_task in self._tasks.items():
                    if task_id in other_task.dependencies:
                        asyncio.create_task(self._try_execute_task(other_id))

    async def execute_parallel(
        self,
        agent_configs: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        并行执行多个 Agent

        Args:
            agent_configs: Agent 配置列表，每个配置包含：
                - task_id: 任务 ID
                - agent_type: Agent 类型
                - agent_factory: Agent 工厂
                - input_data: 输入数据
                - priority: 优先级（可选）

        Returns:
            所有任务的结果
        """
        # 提交所有任务
        task_ids = []
        for config in agent_configs:
            task_id = await self.submit_agent(**config)
            task_ids.append(task_id)

        # 等待所有任务完成
        results = {}
        for task_id in task_ids:
            task = self._tasks[task_id]
            while task.status not in ("completed", "failed", "cancelled"):
                await asyncio.sleep(0.1)
            results[task_id] = task.result

        return results

    async def wait_for_completion(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        等待所有任务完成

        Args:
            timeout: 超时时间（秒）

        Returns:
            所有任务的结果
        """
        start_time = time.time()

        while True:
            # 检查是否所有任务都完成
            all_completed = all(
                task.status in ("completed", "failed", "cancelled")
                for task in self._tasks.values()
            )

            if all_completed:
                break

            # 检查超时
            if timeout and (time.time() - start_time) > timeout:
                logger.warning("Wait for completion timed out")
                break

            await asyncio.sleep(0.5)

        return {
            task_id: task.result
            for task_id, task in self._tasks.items()
        }

    def cancel(self) -> None:
        """取消所有任务"""
        self._cancelled = True
        for task in self._tasks.values():
            if task.status == "pending":
                task.mark_cancelled()
        logger.info("All agent tasks cancelled")

    def get_status(self) -> Dict[str, Any]:
        """获取执行器状态"""
        return {
            "max_parallel": self.max_parallel,
            "total_tasks": len(self._tasks),
            "running_tasks": len(self._running_tasks),
            "cancelled": self._cancelled,
            "tasks": {
                task_id: {
                    "agent_type": task.agent_type,
                    "status": task.status,
                    "priority": task.priority.value,
                    "duration": task.duration,
                    "dependencies": task.dependencies,
                }
                for task_id, task in self._tasks.items()
            },
        }

    def get_agent_tree(self) -> List[Dict[str, Any]]:
        """
        获取 Agent 树结构

        Returns:
            Agent 树列表（从根节点开始）
        """
        # 找到根节点（没有父节点的节点）
        root_nodes = [
            node for node in self._nodes.values()
            if node.parent_id is None
        ]

        def build_tree(node: AgentNode) -> Dict[str, Any]:
            """递归构建树"""
            return {
                "node_id": node.node_id,
                "agent_type": node.agent_type,
                "status": node.task.status,
                "priority": node.task.priority.value,
                "children": [
                    build_tree(self._nodes[child_id])
                    for child_id in node.children
                    if child_id in self._nodes
                ],
            }

        return [build_tree(node) for node in root_nodes]

    async def execute_workflow(
        self,
        workflow: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        执行 Agent 工作流

        Args:
            workflow: 工作流配置，包含：
                - stages: 阶段列表
                - parallel: 是否并行执行
                - dependencies: 依赖关系

        Returns:
            执行结果
        """
        stages = workflow.get("stages", [])
        parallel = workflow.get("parallel", False)

        results = {}

        if parallel:
            # 并行执行所有阶段
            agent_configs = []
            for stage in stages:
                agent_configs.append({
                    "task_id": f"stage_{stage['name']}_{id(self)}",
                    "agent_type": stage["agent_type"],
                    "agent_factory": stage["agent_factory"],
                    "input_data": stage.get("input_data", {}),
                    "priority": AgentPriority(stage.get("priority", "normal")),
                })

            results = await self.execute_parallel(agent_configs)

        else:
            # 串行执行阶段
            for stage in stages:
                task_id = f"stage_{stage['name']}_{id(self)}"
                await self.submit_agent(
                    task_id=task_id,
                    agent_type=stage["agent_type"],
                    agent_factory=stage["agent_factory"],
                    input_data=stage.get("input_data", {}),
                    priority=AgentPriority(stage.get("priority", "normal")),
                )

                # 等待此阶段完成
                task = self._tasks[task_id]
                while task.status not in ("completed", "failed", "cancelled"):
                    await asyncio.sleep(0.1)

                results[task_id] = task.result

                # 如果失败，停止执行
                if task.status == "failed":
                    logger.error(f"Stage {stage['name']} failed, stopping workflow")
                    break

        return results


# 便捷函数
async def execute_agents_parallel(
    agent_configs: List[Dict[str, Any]],
    max_parallel: int = 5,
) -> Dict[str, Any]:
    """
    并行执行多个 Agent（便捷函数）

    Args:
        agent_configs: Agent 配置列表
        max_parallel: 最大并行数

    Returns:
        所有任务的结果
    """
    executor = DynamicAgentExecutor(max_parallel=max_parallel)
    return await executor.execute_parallel(agent_configs)
