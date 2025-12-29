"""
Agent 基类

定义所有 Agent 的通用接口和基础功能
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from loguru import logger
import time


class BaseAgent(ABC):
    """
    Agent 基类

    所有 CTX-Audit Agent 的基础类，提供：
    - 统一的初始化接口
    - 标准的执行流程
    - 思考链记录
    - 事件发布
    - 错误处理
    """

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        """
        初始化 Agent

        Args:
            name: Agent 名称
            config: Agent 配置
        """
        self.name = name
        self.config = config or {}
        self.thinking_chain: list = []
        self.execution_start_time: Optional[float] = None
        self._audit_id: Optional[str] = None

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行 Agent 逻辑

        Args:
            context: 执行上下文，包含：
                - audit_id: 审计 ID
                - project_id: 项目 ID
                - previous_results: 前置 Agent 的结果
                - 其他必要信息

        Returns:
            Agent 执行结果
        """
        pass

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        运行 Agent（包含标准流程包装）

        标准流程：
        1. 记录开始时间
        2. 执行前置处理
        3. 调用 execute 方法
        4. 执行后置处理
        5. 记录执行时间
        """
        self.execution_start_time = time.time()
        self.thinking_chain = []
        self._audit_id = context.get("audit_id")

        try:
            logger.info(f"[{self.name}] 开始执行...")
            await self._before_execution(context)

            result = await self.execute(context)

            await self._after_execution(result)

            duration = time.time() - self.execution_start_time
            logger.info(f"[{self.name}] 执行完成，耗时: {duration:.2f}s")

            return {
                "agent": self.name,
                "status": "success",
                "result": result,
                "thinking_chain": self.thinking_chain,
                "duration_ms": int(duration * 1000),
            }

        except Exception as e:
            logger.error(f"[{self.name}] 执行失败: {e}")
            # 发布错误事件
            await self._publish_event("error", {"error": str(e)})
            return {
                "agent": self.name,
                "status": "error",
                "error": str(e),
                "thinking_chain": self.thinking_chain,
            }

    async def _before_execution(self, context: Dict[str, Any]) -> None:
        """执行前的准备工作"""
        self.think(f"开始执行任务，审计 ID: {context.get('audit_id')}")
        self.think(f"项目 ID: {context.get('project_id')}")

    async def _after_execution(self, result: Dict[str, Any]) -> None:
        """执行后的清理工作"""
        self.think(f"任务完成，生成结果: {len(str(result))} 字符")

    def think(self, thought: str) -> None:
        """
        记录思考过程

        Args:
            thought: 思考内容
        """
        timestamp = time.time()
        self.thinking_chain.append({
            "timestamp": timestamp,
            "thought": thought,
        })
        logger.debug(f"[{self.name}] 思考: {thought}")

        # 自动发布思考事件
        if self._audit_id:
            from app.services.event_bus import publish_event
            # 使用 asyncio.create_task 避免阻塞
            try:
                import asyncio
                asyncio.create_task(publish_event(
                    self._audit_id,
                    self.name,
                    "thinking",
                    {"message": thought}
                ))
            except Exception as e:
                logger.warning(f"发布思考事件失败: {e}")

    async def _publish_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        发布 Agent 事件

        Args:
            event_type: 事件类型
            data: 事件数据
        """
        if not self._audit_id:
            return

        try:
            from app.services.event_bus import publish_event
            await publish_event(
                self._audit_id,
                self.name,
                event_type,
                data
            )
        except Exception as e:
            logger.warning(f"发布事件失败: {e}")

    async def call_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        调用 LLM（统一接口）

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            **kwargs: 其他参数

        Returns:
            LLM 响应
        """
        self.think("调用 LLM 进行分析...")
        from app.core.llm import llm_client
        return await llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            **kwargs
        )

    async def get_ast_context(
        self,
        file_path: str,
        line_range: list,
    ) -> Dict[str, Any]:
        """
        获取 AST 上下文

        Args:
            file_path: 文件路径
            line_range: 行范围

        Returns:
            AST 上下文信息
        """
        from app.services.rust_client import rust_client

        self.think(f"获取文件 {file_path}:{line_range} 的 AST 上下文")
        return await rust_client.get_ast_context(
            file_path=file_path,
            line_range=line_range,
            include_callers=True,
            include_callees=True,
        )

    async def search_similar_code(self, query: str, top_k: int = 5) -> list:
        """
        搜索相似代码

        Args:
            query: 查询文本
            top_k: 返回数量

        Returns:
            相似代码列表
        """
        from app.services.vector_store import search_similar_code

        self.think(f"搜索相似代码: {query[:50]}...")
        results = await search_similar_code(query=query, top_k=top_k)

        if results:
            self.think(f"找到 {len(results)} 个相似代码片段")
        else:
            self.think("未找到相似代码片段")

        return results

    async def search_vulnerability_patterns(self, query: str, top_k: int = 3) -> list:
        """
        搜索漏洞模式

        Args:
            query: 查询文本
            top_k: 返回数量

        Returns:
            相似漏洞模式列表
        """
        from app.services.vector_store import search_vulnerability_patterns

        self.think(f"搜索漏洞模式: {query[:50]}...")
        results = await search_vulnerability_patterns(query=query, top_k=top_k)

        if results:
            self.think(f"找到 {len(results)} 个相关漏洞模式")
        else:
            self.think("未找到相关漏洞模式")

        return results


class AgentError(Exception):
    """Agent 执行错误"""
    pass
