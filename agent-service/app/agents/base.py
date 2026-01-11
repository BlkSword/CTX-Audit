"""
Agent 基类

定义所有 Agent 的通用接口和基础功能
参考 DeepAudit-3.0.0 设计，增加：
- 流式 LLM 调用
- 工具执行器
- 消息处理
- 知识模块加载
- 事件发射增强
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Callable, AsyncIterator
from loguru import logger
import time
import asyncio
import json


class BaseAgent(ABC):
    """
    Agent 基类（增强版）

    所有 CTX-Audit Agent 的基础类，提供：
    - 统一的初始化接口
    - 标准的执行流程
    - 思考链记录
    - 事件发布
    - 错误处理
    - 流式 LLM 调用（新增）
    - 工具执行器（新增）
    - 消息处理（新增）
    - 知识模块加载（新增）
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
        # Agent ID（在注册时设置）
        self.agent_id: Optional[str] = None

        # 新增：运行时上下文
        self._runtime_context: Dict[str, Any] = {}
        self._knowledge_modules: List[str] = []
        self._loaded_knowledge: Dict[str, str] = {}

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

        # 自动发布思考事件到 event_bus_v2
        if self._audit_id:
            # 使用 asyncio.create_task 避免阻塞
            try:
                import asyncio
                # 显式使用 'thinking' 事件类型，对应前端映射
                asyncio.create_task(self._publish_event("thinking", {"message": thought}))
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
            from app.services.event_manager import event_manager

            # 创建事件数据
            message = data.get("message") or str(data)

            # 提取重要字段到根级别，同时也保留在 metadata 中
            await event_manager.add_event(
                task_id=self._audit_id,
                sequence=0,  # EventManager 会自动分配序列号
                event_type=event_type,
                agent_type=self.name,
                message=message,
                # 重要字段直接放在根级别
                progress=data.get("progress"),
                status=data.get("status"),
                phase=data.get("phase"),
                # 工具相关
                tool_name=data.get("tool"),
                tool_input=data.get("tool_input"),
                tool_output=data.get("tool_output"),
                tool_duration_ms=data.get("tool_duration_ms"),
                # 其他
                finding_id=data.get("finding_id"),
                tokens_used=data.get("tokens_used", 0),
                # 完整数据保存在 metadata 中
                metadata=data,
            )
        except Exception as e:
            logger.warning(f"[{self.name}] 发布事件失败: {e}")

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

    # ==================== 新增：DeepAudit-3.0.0 风格的增强方法 ====================

    async def call_llm_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        on_chunk: Optional[Callable[[str], None]] = None,
        **kwargs
    ) -> str:
        """
        流式调用 LLM（参考 DeepAudit-3.0.0）

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            on_chunk: 流式回调函数
            **kwargs: 其他参数

        Returns:
            完整的 LLM 响应
        """
        self.think("开始流式 LLM 调用...")
        from app.core.llm import llm_client

        full_response = ""
        async for chunk in llm_client.generate_stream(
            prompt=prompt,
            system_prompt=system_prompt,
            **kwargs
        ):
            if chunk:
                full_response += chunk
                if on_chunk:
                    on_chunk(chunk)

        return full_response

    async def execute_tool(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        timeout_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        执行工具（参考 DeepAudit-3.0.0 的工具执行器）

        Args:
            tool_name: 工具名称
            tool_input: 工具输入
            timeout_seconds: 超时时间

        Returns:
            工具执行结果
        """
        self.think(f"执行工具: {tool_name}")

        # 从工具适配器获取工具处理器
        from app.core.tool_adapter import get_tool_handler

        handler = get_tool_handler(tool_name)
        if not handler:
            return {
                "success": False,
                "error": f"工具 {tool_name} 不存在"
            }

        try:
            # 使用 asyncio.wait_for 实现超时
            result = await asyncio.wait_for(
                handler(tool_input),
                timeout=timeout_seconds
            )
            self.think(f"工具 {tool_name} 执行成功")
            return {
                "success": True,
                "result": result
            }
        except asyncio.TimeoutError:
            self.think(f"工具 {tool_name} 执行超时")
            return {
                "success": False,
                "error": f"工具执行超时（{timeout_seconds}秒）"
            }
        except Exception as e:
            self.think(f"工具 {tool_name} 执行失败: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    async def load_knowledge_module(self, module_name: str) -> Optional[str]:
        """
        加载知识模块（参考 DeepAudit-3.0.0）

        Args:
            module_name: 模块名称

        Returns:
            模块内容
        """
        if module_name in self._loaded_knowledge:
            return self._loaded_knowledge[module_name]

        try:
            # 这里可以从文件或数据库加载知识模块
            # 参考 DeepAudit-3.0.0 的 prompts 模块
            from app.services.prompt_builder import prompt_builder

            content = await prompt_builder.get_knowledge_module(module_name)
            if content:
                self._loaded_knowledge[module_name] = content
                self._knowledge_modules.append(module_name)
                self.think(f"已加载知识模块: {module_name}")
                return content
        except Exception as e:
            logger.warning(f"加载知识模块 {module_name} 失败: {e}")

        return None

    async def load_knowledge_for_tech_stack(self, tech_stack: Dict[str, Any]) -> List[str]:
        """
        根据技术栈加载相关知识模块（参考 DeepAudit-3.0.0）

        Args:
            tech_stack: 技术栈信息

        Returns:
            加载的模块列表
        """
        languages = tech_stack.get("languages", [])
        frameworks = tech_stack.get("frameworks", [])

        # 定义语言到模块的映射
        language_modules = {
            "Python": ["python_security", "django", "flask"],
            "JavaScript": ["javascript_security", "nodejs", "react", "express"],
            "TypeScript": ["typescript_security", "nodejs", "react", "express"],
            "Java": ["java_security", "spring"],
            "Go": ["go_security"],
            "PHP": ["php_security", "laravel"],
        }

        # 定义框架到模块的映射
        framework_modules = {
            "Django": ["django"],
            "Flask": ["flask"],
            "React": ["react"],
            "Express": ["express"],
            "Spring": ["spring"],
            "Laravel": ["laravel"],
        }

        loaded = []

        # 加载语言相关模块
        for lang in languages:
            modules = language_modules.get(lang, [])
            for module in modules:
                if await self.load_knowledge_module(module):
                    loaded.append(module)

        # 加载框架相关模块
        for framework in frameworks:
            modules = framework_modules.get(framework, [])
            for module in modules:
                if await self.load_knowledge_module(module):
                    loaded.append(module)

        # 总是加载核心安全模块
        core_modules = ["core_security", "owasp_top_10"]
        for module in core_modules:
            if await self.load_knowledge_module(module):
                loaded.append(module)

        return loaded

    async def check_messages(
        self,
        message_bus: Any,
        unread_only: bool = True,
        mark_as_read: bool = True
    ) -> List[Any]:
        """
        检查消息（参考 DeepAudit-3.0.0）

        Args:
            message_bus: 消息总线实例
            unread_only: 是否只获取未读消息
            mark_as_read: 是否标记为已读

        Returns:
            消息列表
        """
        if not self.agent_id:
            return []

        return await message_bus.get_messages(
            agent_id=self.agent_id,
            unread_only=unread_only,
            mark_as_read=mark_as_read
        )

    async def send_message(
        self,
        message_bus: Any,
        to_agent: str,
        content: str,
        message_type: str = "information",
        priority: str = "normal"
    ) -> Any:
        """
        发送消息（参考 DeepAudit-3.0.0）

        Args:
            message_bus: 消息总线实例
            to_agent: 目标 Agent
            content: 消息内容
            message_type: 消息类型
            priority: 优先级

        Returns:
            发送的消息
        """
        return await message_bus.send_message(
            from_agent=self.agent_id or "unknown",
            to_agent=to_agent,
            content=content,
            message_type=message_type,
            priority=priority
        )

    def emit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        发射事件（同步版本，用于快速发射）

        Args:
            event_type: 事件类型
            data: 事件数据
        """
        if self._audit_id:
            try:
                asyncio.create_task(self._publish_event(event_type, data))
            except Exception as e:
                logger.warning(f"发射事件失败: {e}")

    async def emit_event_async(self, event_type: str, data: Dict[str, Any]) -> None:
        """
        发射事件（异步版本）

        Args:
            event_type: 事件类型
            data: 事件数据
        """
        await self._publish_event(event_type, data)

    async def tool(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        emit_events: bool = True
    ) -> Dict[str, Any]:
        """
        工具调用（参考 DeepAudit-3.0.0 的 tool 方法）

        Args:
            tool_name: 工具名称
            tool_input: 工具输入
            emit_events: 是否发射事件

        Returns:
            工具执行结果
        """
        start_time = time.time()

        if emit_events:
            await self.emit_event_async("tool_call", {
                "tool": tool_name,
                "tool_input": tool_input
            })

        result = await self.execute_tool(tool_name, tool_input)

        duration_ms = int((time.time() - start_time) * 1000)

        if emit_events:
            await self.emit_event_async("tool_result", {
                "tool": tool_name,
                "tool_output": result,
                "tool_duration_ms": duration_ms
            })

        return result

    async def agent_finish(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        完成 Agent 任务（参考 DeepAudit-3.0.0）

        Args:
            result: 任务结果

        Returns:
            格式化的完成结果
        """
        await self.emit_event_async("agent_complete", {
            "agent": self.name,
            "result": result
        })

        return {
            "status": "completed",
            "agent": self.name,
            "result": result
        }

    def should_continue(self) -> bool:
        """
        判断是否应该继续执行（参考 DeepAudit-3.0.0）

        Returns:
            是否继续
        """
        # 子类可以重写此方法实现自定义的停止条件
        return True

    def get_knowledge_context(self) -> str:
        """
        获取已加载知识的上下文字符串

        Returns:
            知识上下文
        """
        if not self._knowledge_modules:
            return ""

        sections = []
        for module in self._knowledge_modules:
            content = self._loaded_knowledge.get(module)
            if content:
                sections.append(f"## {module}\n{content}")

        return "\n\n".join(sections) if sections else ""


class AgentError(Exception):
    """Agent 执行错误"""
    pass
