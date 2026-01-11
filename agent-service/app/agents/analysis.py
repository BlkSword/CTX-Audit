"""
Analysis Agent - LLM 驱动的深度分析者

负责深度代码分析、漏洞挖掘和误报过滤

使用 MCP (Model Context Protocol) 标准工具系统
"""
from typing import Dict, Any, List, Optional
from loguru import logger
import time

from app.agents.base import BaseAgent
from app.services.llm import LLMService, LLMProvider
from app.core.task_handoff import TaskHandoff, TaskHandoffBuilder
from app.services.prompt_builder import prompt_builder
from app.core.tool_loop import ToolCallLoop
from app.core.tool_adapter import create_tool_bridge
from app.core.monitoring import get_monitoring_system
from app.core.resilience import get_llm_circuit, get_llm_rate_limiter, get_tool_circuit


class AnalysisAgent(BaseAgent):
    """
    LLM 驱动的 Analysis Agent

    使用 MCP 标准工具系统进行代码安全分析
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="analysis", config=config)

        config = config or {}
        self._llm_config = config
        self._llm: Optional[LLMService] = None

        self.use_rag = config.get("use_rag", True)
        self.max_iterations = config.get("max_iterations", 15)
        self.max_findings_to_analyze = config.get("max_findings_to_analyze", 20)

        self._conversation: List[Dict[str, Any]] = []
        self._confirmed_findings: List[Dict[str, Any]] = []
        self._false_positives: List[str] = []

        # 集成监控和容错系统
        self._monitoring = get_monitoring_system()
        self._llm_circuit = get_llm_circuit()
        self._llm_rate_limiter = get_llm_rate_limiter()
        # 工具熔断器在需要时动态获取
        self._tool_circuits: Dict[str, Any] = {}

    @property
    def llm(self):
        """延迟初始化 LLM 服务"""
        if self._llm is None:
            try:
                # 从配置或运行时上下文获取 LLM 配置
                provider_str = self._llm_config.get("llm_provider", "anthropic")
                model = self._llm_config.get("llm_model", "claude-3-5-sonnet-20241022")
                api_key = self._llm_config.get("api_key")
                base_url = self._llm_config.get("base_url")

                # 如果配置为空，尝试从运行时上下文获取（由 orchestrator 传递）
                if not api_key and hasattr(self, '_runtime_context'):
                    api_key = self._runtime_context.get("api_key")
                    provider_str = self._runtime_context.get("llm_provider", provider_str)
                    model = self._runtime_context.get("llm_model", model)
                    base_url = self._runtime_context.get("base_url")

                try:
                    provider = LLMProvider(provider_str)
                except ValueError:
                    logger.warning(f"未知的 LLM provider '{provider_str}'，使用 OpenAI 兼容模式")
                    provider = LLMProvider.OPENAI

                self._llm = LLMService(
                    provider=provider,
                    model=model,
                    api_key=api_key,
                    base_url=base_url,
                )
            except Exception as e:
                logger.error(f"LLM 服务初始化失败: {e}")
                raise ValueError("LLM 服务未配置，请在设置中配置 API Key")
        return self._llm

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行 LLM 驱动的深度分析"""
        audit_id = context.get("audit_id")
        scan_results = context.get("scan_results", [])

        # 保存运行时上下文（包含 LLM 配置）
        self._runtime_context = context

        # 重置状态
        self._confirmed_findings = []
        self._false_positives = []

        logger.info(f"[Analysis Agent] 开始分析，收到 {len(scan_results)} 个扫描结果")
        logger.info(f"[Analysis Agent] scan_results 示例: {scan_results[:3] if scan_results else 'None'}")

        # 限制分析数量
        if len(scan_results) > self.max_findings_to_analyze:
            self.think(f"扫描结果过多 ({len(scan_results)})，仅分析前 {self.max_findings_to_analyze} 个高危问题")
            scan_results = self._prioritize_findings(scan_results)[:self.max_findings_to_analyze]
            # 更新 context 中的 scan_results，以便 prompt 使用
            context["scan_results"] = scan_results

        # 构建上下文和提示词
        analysis_context = await self._build_initial_context(context)
        system_prompt = await self._build_system_prompt(analysis_context)
        initial_message = self._format_initial_message(analysis_context)

        # 使用 MCP 工具适配器获取工具处理器和 LLM 工具列表
        # 添加状态到上下文供工具使用
        analysis_context["_confirmed_findings"] = self._confirmed_findings
        analysis_context["_false_positives"] = self._false_positives
        analysis_context["use_rag"] = self.use_rag

        tool_handlers, llm_tools = create_tool_bridge(context=analysis_context)

        self.think(f"已加载 {len(llm_tools)} 个 MCP 工具")
        logger.info(f"[Analysis Agent] 已加载 {len(llm_tools)} 个工具: {[t.get('function', {}).get('name') for t in llm_tools]}")

        # 创建并运行循环
        loop = ToolCallLoop(
            llm=self.llm,
            tools=llm_tools,
            tool_handlers=tool_handlers,
            system_prompt=system_prompt,
            max_iterations=self.max_iterations,
            event_callback=self._publish_event
        )

        await loop.run(user_input=initial_message)
        self._conversation = loop.history

        # 从上下文中获取工具更新后的状态
        self._confirmed_findings = analysis_context.get("_confirmed_findings", [])
        self._false_positives = analysis_context.get("_false_positives", [])

        # 创建任务交接
        next_handoff = self._create_task_handoff(context)

        return {
            "status": "success",
            "result": self._confirmed_findings,
            "findings": self._confirmed_findings,
            "task_handoff": next_handoff.to_dict() if next_handoff else None,
            "stats": {
                "total_analyzed": len(scan_results),
                "confirmed": len(self._confirmed_findings),
                "false_positives": len(self._false_positives),
            },
        }

    # ==================== 辅助方法 ====================

    async def _build_initial_context(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        scan_results = input_data.get("scan_results", [])
        return {
            "audit_id": input_data.get("audit_id"),
            "project_id": input_data.get("project_id"),
            "project_path": input_data.get("project_path"),
            "scan_results": scan_results,
        }

    async def _build_system_prompt(self, context: Dict[str, Any]) -> str:
        return await prompt_builder.build_analysis_prompt(context)

    def _format_initial_message(self, context: Dict[str, Any]) -> str:
        scan_results = context["scan_results"]
        return f"""开始分析。共收到 {len(scan_results)} 个扫描结果。

**可用工具:**
- `read_file` - 读取文件内容
- `get_ast_context` - 获取AST上下文
- `search_similar_code` - 相似代码搜索（需要RAG）
- `search_vulnerability_patterns` - 漏洞模式搜索（需要RAG）
- `get_call_graph` - 获取调用图
- `get_knowledge_graph` - 获取知识图谱
- `search_symbol` - 符号搜索
- `get_code_structure` - 代码结构
- `list_files` - 列出文件
- `report_finding` - 报告漏洞
- `mark_false_positive` - 标记误报
- `finish_analysis` - 完成分析

请对高危结果进行逐一验证：
1. 使用 `read_file` 或 `get_ast_context` 查看代码
2. 使用 `search_vulnerability_patterns` 查找相关漏洞模式
3. 判断是否为误报
4. 如果是真实漏洞，使用 `report_finding` 记录
5. 如果是误报，使用 `mark_false_positive` 记录
6. 完成后调用 `finish_analysis`
"""

    def _prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5)
        )

    def _create_task_handoff(self, context: Dict[str, Any]) -> Optional[TaskHandoff]:
        if not self._confirmed_findings:
            return None
        return TaskHandoffBuilder(from_agent="analysis", to_agent="verification").summary(f"发现 {len(self._confirmed_findings)} 个漏洞").build()


# 创建全局实例
analysis_agent = AnalysisAgent()
