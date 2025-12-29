"""
Orchestrator Agent - LLM 驱动的自主编排者

支持两种编排模式：
1. LLM 自主决策：LLM 决定下一步操作和 Agent 调度
2. LangGraph 辅助：确定性流程作为备用方案
"""
from typing import Dict, Any, Optional, List, TypedDict, Annotated, Sequence, TYPE_CHECKING
from loguru import logger
import operator
import time
import json

from app.agents.base import BaseAgent
from app.services.event_bus import EventType, create_status_event
from app.services.llm import LLMService, LLMMessage, LLMProvider
from app.core.task_handoff import TaskHandoff

# LangGraph imports
try:
    from langgraph.graph import StateGraph, END
    LANGGRAPH_AVAILABLE = True
except ImportError:
    logger.warning("LangGraph 未安装，将使用 LLM 自主编排")
    LANGGRAPH_AVAILABLE = False


class AgentAuditState(TypedDict):
    """Agent 审计工作流状态"""
    # 基本信息
    audit_id: str
    project_id: str
    audit_type: str
    config: Dict[str, Any]

    # 消息/日志
    messages: Annotated[Sequence[str], operator.add]

    # 执行控制
    current_step: str
    current_agent: str
    steps_completed: List[str]

    # 各 Agent 的执行结果
    project_info: Optional[Dict[str, Any]]
    recon_result: Optional[Dict[str, Any]]
    scan_results: List[Dict[str, Any]]
    analysis_results: List[Dict[str, Any]]
    verification_results: List[Dict[str, Any]]

    # 统计信息
    files_scanned: int
    findings_count: int
    verified_findings: int

    # 错误处理
    errors: List[str]
    should_retry: bool

    # 最终输出
    final_report: Optional[Dict[str, Any]]


class OrchestratorAgent(BaseAgent):
    """
    LLM 驱动的自主编排 Agent

    核心特性：
    1. LLM 全程参与决策，决定下一步操作
    2. 通过工具调用调度子 Agent
    3. 支持 LangGraph 作为确定性流程备用
    4. 使用 TaskHandoff 协议传递上下文
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="orchestrator", config=config)

        # 确保 config 不为 None
        config = config or {}

        # LLM 服务（延迟初始化，允许无 API 密钥启动）
        self._llm_config = config
        self._llm: Optional[LLMService] = None

        # 编排模式
        self.use_llm_orchestration = config.get("use_llm_orchestration", True)
        self.max_iterations = config.get("max_iterations", 20)

        # LangGraph（作为辅助）
        self._graph = None
        if LANGGRAPH_AVAILABLE and config.get("use_langgraph", False):
            self._graph = self._build_graph()
            logger.info("LangGraph 编排图已构建（辅助模式）")

        # 对话历史
        self._conversation: List[Dict[str, Any]] = []

    @property
    def llm(self):  # type: ignore
        """延迟初始化 LLM 服务"""
        if self._llm is None:
            try:
                self._llm = LLMService(
                    provider=LLMProvider(self._llm_config.get("llm_provider", "anthropic")),
                    model=self._llm_config.get("llm_model", "claude-3-5-sonnet-20241022"),
                    api_key=self._llm_config.get("api_key"),
                    base_url=self._llm_config.get("base_url"),
                )
            except Exception as e:
                logger.warning(f"LLM 服务初始化失败（将使用模拟模式）: {e}")
                # 创建一个模拟的 LLM 服务
                self._llm = self._create_mock_llm()
        return self._llm

    def _create_mock_llm(self):  # type: ignore
        """创建模拟 LLM 服务（用于无 API 密钥时）"""
        # 这里返回一个模拟对象，避免崩溃
        class MockLLMService:
            async def generate(self, *args, **kwargs):
                from app.services.llm.adapters.base import LLMResponse
                return LLMResponse(
                    content="[模拟模式] LLM 未配置，请在前端设置中配置 API 密钥",
                    model="mock",
                    usage={"total_tokens": 0},
                )

            async def generate_with_tools(self, *args, **kwargs):
                return {
                    "content": "[模拟模式] LLM 未配置",
                    "tool_calls": [],
                    "usage": {"total_tokens": 0},
                }
        return MockLLMService()  # type: ignore

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行审计编排

        Args:
            context: 包含 audit_id, project_id 等信息

        Returns:
            审计结果
        """
        audit_id = context.get("audit_id")
        self.think(f"开始编排审计任务: {audit_id}")

        # 根据配置选择编排模式
        if self.use_llm_orchestration:
            return await self._execute_with_llm(context)
        elif LANGGRAPH_AVAILABLE and self._graph:
            return await self._execute_with_graph(context)
        else:
            return await self._execute_sequential(context)

    # ==================== LLM 自主编排 ====================

    async def _execute_with_llm(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """LLM 驱动的自主编排"""
        audit_id = context["audit_id"]
        project_id = context["project_id"]
        start_time = time.time()

        self.think("启动 LLM 自主编排模式")

        # 1. 构建初始上下文
        audit_context = await self._build_initial_context(context)

        # 2. 初始化对话历史
        system_prompt = await self._load_system_prompt()
        initial_message = self._format_initial_message(audit_context)

        self._conversation = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_message},
        ]

        # 3. LLM 决策循环
        for iteration in range(self.max_iterations):
            self.think(f"LLM 决策循环 #{iteration + 1}")

            # 发布状态事件
            await self._publish_event(EventType.THINKING, {
                "message": f"LLM 正在规划下一步操作 (迭代 {iteration + 1}/{self.max_iterations})...",
                "iteration": iteration + 1,
            })

            # 调用 LLM 进行决策
            try:
                llm_response = await self.llm.generate_with_tools(
                    messages=self._conversation,
                    tools=self._get_available_tools(),
                )
            except Exception as e:
                logger.error(f"LLM 调用失败: {e}")
                return {
                    "agent": self.name,
                    "status": "error",
                    "error": f"LLM 调用失败: {str(e)}",
                    "thinking_chain": self.thinking_chain,
                }

            # 添加 LLM 响应到对话历史
            self._conversation.append({
                "role": "assistant",
                "content": llm_response.get("content", ""),
            })
            if llm_response.get("tool_calls"):
                self._conversation.append({"tool_calls": llm_response["tool_calls"]})

            # 解析决策
            tool_calls = llm_response.get("tool_calls", [])

            if not tool_calls:
                # LLM 决定完成审计
                self.think("LLM 决定完成审计")
                break

            # 执行工具调用
            observations = []
            for tool_call in tool_calls:
                observation = await self._execute_tool(tool_call, audit_context)
                observations.append(observation)

            # 添加观察结果到对话历史
            self._conversation.append({
                "role": "user",
                "content": "\n\n".join(observations),
            })

            # 更新上下文
            audit_context = self._update_context(audit_context, observations)

        # 4. 生成最终报告
        final_report = await self._generate_final_report(audit_context)

        duration = time.time() - start_time
        self.think(f"LLM 编排完成，耗时: {duration:.2f}s")

        return {
            "agent": self.name,
            "status": "success",
            "result": final_report,
            "thinking_chain": self.thinking_chain,
            "duration_ms": int(duration * 1000),
            "iterations": len([m for m in self._conversation if m.get("role") == "user"]) - 1,
            "stats": {
                "files_scanned": audit_context.get("files_scanned", 0),
                "findings_count": audit_context.get("findings_count", 0),
                "verified_findings": audit_context.get("verified_findings", 0),
            }
        }

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        """获取可用工具列表"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "dispatch_recon_agent",
                    "description": "启动 Recon Agent 进行信息收集，分析项目结构、技术栈和攻击面",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "focus_areas": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "重点关注区域（如：认证、授权、数据库操作等）",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "rust_scan",
                    "description": "调用 Rust 后端进行静态安全扫描，使用预定义规则检测常见漏洞",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "rules": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "启用的规则类型（如：sql_injection, xss, ssrf 等）",
                            },
                            "target_files": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "目标文件路径列表（可选，为空则扫描全部）",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "dispatch_analysis_agent",
                    "description": "启动 Analysis Agent 进行 LLM 深度分析，对扫描结果进行智能判断",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "file_path": {"type": "string"},
                                        "issue_type": {"type": "string"},
                                    },
                                },
                                "description": "待分析的目标列表",
                            },
                            "focus_severity": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "重点关注严重级别（critical, high, medium, low）",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "dispatch_verification_agent",
                    "description": "启动 Verification Agent 验证漏洞，生成 PoC 并在沙箱中执行",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "findings": {
                                "type": "array",
                                "items": {"type": "object"},
                                "description": "待验证的漏洞列表",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finish_audit",
                    "description": "完成审计并生成最终报告",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {
                                "type": "string",
                                "description": "审计总结",
                            },
                            "total_findings": {
                                "type": "integer",
                                "description": "发现的问题总数",
                            },
                        },
                    },
                },
            },
        ]

    async def _execute_tool(
        self,
        tool_call: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """执行工具调用"""
        function = tool_call.get("function", {})
        tool_name = function.get("name")
        arguments = function.get("arguments", {})

        # 如果 arguments 是字符串，尝试解析 JSON
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                pass

        self.think(f"执行工具: {tool_name}")

        try:
            if tool_name == "dispatch_recon_agent":
                return await self._dispatch_recon(arguments, context)

            elif tool_name == "rust_scan":
                return await self._run_rust_scan(arguments, context)

            elif tool_name == "dispatch_analysis_agent":
                return await self._dispatch_analysis(arguments, context)

            elif tool_name == "dispatch_verification_agent":
                return await self._dispatch_verification(arguments, context)

            elif tool_name == "finish_audit":
                return await self._finish_audit(arguments, context)

            else:
                return f"未知工具: {tool_name}"

        except Exception as e:
            error_msg = f"工具执行失败 ({tool_name}): {str(e)}"
            logger.error(error_msg)
            return error_msg

    async def _dispatch_recon(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """调度 Recon Agent"""
        await self._publish_event(EventType.STATUS, {
            "status": "running",
            "message": "Recon Agent 正在扫描项目结构..."
        })

        from app.agents.recon import ReconAgent

        recon = ReconAgent()
        result = await recon.run({
            "audit_id": context["audit_id"],
            "project_id": context["project_id"],
            "focus_areas": arguments.get("focus_areas", []),
        })

        if result.get("status") == "success":
            recon_result = result.get("result", {})
            context["recon_result"] = recon_result
            context["steps_completed"].append("recon")

            # 创建任务交接
            handoff = TaskHandoff.from_agent_result(
                from_agent="recon",
                to_agent="orchestrator",
                result=recon_result,
            )
            context["last_handoff"] = handoff.to_dict()

            return f"""
Recon Agent 完成。

{handoff.to_prompt_context()}

**技术栈识别**: {', '.join(recon_result.get('tech_stack', []))}
**攻击面数量**: {len(recon_result.get('attack_surface', []))}
"""
        else:
            return f"Recon Agent 失败: {result.get('error', 'Unknown error')}"

    async def _run_rust_scan(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """运行 Rust 扫描"""
        await self._publish_event(EventType.STATUS, {
            "status": "running",
            "message": "正在执行 Rust 后端扫描..."
        })

        from app.services.rust_client import rust_client

        try:
            scan_result = await rust_client.scan_project(
                context["project_id"],
                target_types=arguments.get("rules"),
            )

            findings = scan_result.get("findings", [])
            context["scan_results"] = findings
            context["files_scanned"] = scan_result.get("files_scanned", 0)
            context["findings_count"] = len(findings)
            context["steps_completed"].append("scan")

            # 按严重程度分组
            severity_count = {}
            for f in findings:
                sev = f.get("severity", "info").lower()
                severity_count[sev] = severity_count.get(sev, 0) + 1

            summary = ", ".join([f"{k}: {v}" for k, v in severity_count.items()])

            return f"""
Rust 扫描完成。

**扫描文件数**: {scan_result.get('files_scanned', 0)}
**发现问题数**: {len(findings)}
**严重程度分布**: {summary}

**需要关注的发现**:
{chr(10).join([f"- {f.get('title', 'Untitled')} ({f.get('severity', 'unknown')})" for f in findings[:5]])}
"""
        except Exception as e:
            return f"Rust 扫描失败: {str(e)}"

    async def _dispatch_analysis(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """调度 Analysis Agent"""
        await self._publish_event(EventType.STATUS, {
            "status": "running",
            "message": "Analysis Agent 正在进行 LLM 深度分析..."
        })

        from app.agents.analysis import AnalysisAgent

        # 传递任务交接（如果有）
        last_handoff = context.get("last_handoff")

        analysis = AnalysisAgent()
        result = await analysis.run({
            "audit_id": context["audit_id"],
            "project_id": context["project_id"],
            "scan_results": context.get("scan_results", []),
            "recon_result": context.get("recon_result"),
            "task_handoff": last_handoff,
            "focus_severity": arguments.get("focus_severity"),
        })

        if result.get("status") == "success":
            analysis_results = result.get("result", [])
            findings = analysis_results if isinstance(analysis_results, list) else analysis_results.get("findings", [])
            context["analysis_results"] = findings
            context["steps_completed"].append("analysis")

            # 如果有任务交接，保存
            if "task_handoff" in analysis_results:
                context["last_handoff"] = analysis_results["task_handoff"]

            return f"""
Analysis Agent 完成。

**分析结果**: 发现 {len(findings)} 个潜在安全问题
**置信度分布**: 高风险 {len([f for f in findings if f.get('confidence', 0) > 0.7])} 个

**关键发现**:
{chr(10).join([f"- {f.get('title', 'Untitled')} (置信度: {f.get('confidence', 0):.2f})" for f in findings[:5]])}
"""
        else:
            return f"Analysis Agent 失败: {result.get('error', 'Unknown error')}"

    async def _dispatch_verification(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """调度 Verification Agent"""
        await self._publish_event(EventType.STATUS, {
            "status": "running",
            "message": "Verification Agent 正在验证漏洞..."
        })

        from app.agents.verification import VerificationAgent

        findings_to_verify = arguments.get("findings") or context.get("analysis_results", [])

        verification = VerificationAgent()
        result = await verification.run({
            "audit_id": context["audit_id"],
            "findings": findings_to_verify,
        })

        if result.get("status") == "success":
            verified = result.get("result", {}).get("verified", [])
            context["verification_results"] = verified
            context["verified_findings"] = len([v for v in verified if v.get("verified")])
            context["steps_completed"].append("verification")

            return f"""
Verification Agent 完成。

**验证结果**: {len([v for v in verified if v.get('verified')])} / {len(verified)} 个漏洞确认
**误报率**: {len([v for v in verified if not v.get('verified')]) / len(verified) * 100:.1f}%
"""
        else:
            return f"Verification Agent 失败: {result.get('error', 'Unknown error')}"

    async def _finish_audit(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """完成审计"""
        # 这个工具主要用于 LLM 表达完成意图
        summary = arguments.get("summary", "审计完成")
        total_findings = arguments.get("total_findings", context.get("findings_count", 0))

        return f"""
审计完成。

**总结**: {summary}
**发现问题**: {total_findings} 个
**验证漏洞**: {context.get('verified_findings', 0)} 个
**已完成步骤**: {', '.join(context.get('steps_completed', []))}
"""

    # ==================== 辅助方法 ====================

    async def _build_initial_context(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """构建初始上下文"""
        return {
            "audit_id": input_data["audit_id"],
            "project_id": input_data["project_id"],
            "audit_type": input_data.get("audit_type", "quick"),
            "config": input_data.get("config", {}),
            "steps_completed": [],
            "files_scanned": 0,
            "findings_count": 0,
            "verified_findings": 0,
        }

    def _format_initial_message(self, context: Dict[str, Any]) -> str:
        """格式化初始消息"""
        return f"""请开始审计以下项目：

**项目 ID**: {context['project_id']}
**审计 ID**: {context['audit_id']}
**审计类型**: {context['audit_type']}

请根据项目情况，自主决定执行以下操作：
1. 使用 dispatch_recon_agent 进行信息收集
2. 使用 rust_scan 进行静态扫描
3. 使用 dispatch_analysis_agent 进行深度分析
4. 使用 dispatch_verification_agent 验证漏洞

完成后，调用 finish_audit 生成报告。

注意事项：
- 优先关注高危漏洞
- 合理使用工具，避免重复操作
- 每次操作后，根据结果决定下一步
- 最多执行 {self.max_iterations} 次迭代
"""

    async def _load_system_prompt(self) -> str:
        """加载系统提示词"""
        from app.services.prompt_loader import load_system_prompt

        try:
            return await load_system_prompt("orchestrator")
        except Exception as e:
            logger.warning(f"加载系统提示词失败: {e}，使用默认提示词")
            return self._get_default_system_prompt()

    def _get_default_system_prompt(self) -> str:
        """获取默认系统提示词"""
        return """你是 CTX-Audit 的 Orchestrator Agent，负责编排整个代码安全审计流程。

**你的职责**：
1. 分析项目特点，制定审计策略
2. 调度各个子 Agent 执行任务
3. 根据中间结果动态调整计划
4. 汇总发现并生成最终报告

**可用工具**：
- dispatch_recon_agent: 信息收集，识别技术栈和攻击面
- rust_scan: 静态扫描，使用规则检测常见漏洞
- dispatch_analysis_agent: LLM 深度分析，智能判断安全问题
- dispatch_verification_agent: 漏洞验证，生成 PoC 并执行
- finish_audit: 完成审计并生成报告

**工作流程建议**：
1. 先调用 dispatch_recon_agent 了解项目结构
2. 使用 rust_scan 进行初步扫描
3. 对发现的问题调用 dispatch_analysis_agent 深度分析
4. 对高危漏洞调用 dispatch_verification_agent 验证
5. 调用 finish_audit 完成审计

**决策原则**：
- 快速审计：跳过 recon，直接扫描
- 完整审计：完整执行所有步骤
- 优先处理高危漏洞
- 避免重复操作

请保守、准确地完成审计任务。"""

    def _update_context(self, context: Dict[str, Any], observations: List[str]) -> Dict[str, Any]:
        """根据观察结果更新上下文"""
        # 这里可以解析观察结果，提取结构化信息
        return context

    async def _generate_final_report(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """生成最终报告"""
        # 合并所有发现
        all_findings = []
        all_findings.extend(context.get("scan_results", []))
        all_findings.extend(context.get("analysis_results", []))
        all_findings.extend(context.get("verification_results", []))

        # 按严重程度分组
        severity_count = self._group_by_severity(all_findings)

        return {
            "audit_id": context["audit_id"],
            "project_id": context["project_id"],
            "status": "completed",
            "summary": {
                "total_findings": len(all_findings),
                "files_scanned": context.get("files_scanned", 0),
                "verified_findings": context.get("verified_findings", 0),
                "by_severity": severity_count,
            },
            "findings": all_findings,
            "steps": context.get("steps_completed", []),
            "iterations": len(context.get("steps_completed", [])),
        }

    def _group_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """按严重程度分组"""
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_count:
                severity_count[severity] += 1

        return severity_count

    # ==================== LangGraph 辅助模式 ====================

    def _build_graph(self) -> Optional["StateGraph"]:
        """构建 LangGraph 作为备用"""
        if not LANGGRAPH_AVAILABLE:
            return None

        workflow = StateGraph(AgentAuditState)

        # 添加节点
        workflow.add_node("planner", self._plan_audit)
        workflow.add_node("recon_agent", self._run_recon)
        workflow.add_node("scanner", self._run_scan)
        workflow.add_node("analysis_agent", self._run_analysis)
        workflow.add_node("verify_agent", self._run_verification)
        workflow.add_node("reporter", self._generate_report)

        # 设置入口点
        workflow.set_entry_point("planner")

        # 添加边
        workflow.add_conditional_edges(
            "planner",
            self._should_recon,
            {"recon": "recon_agent", "scan": "scanner"}
        )
        workflow.add_edge("recon_agent", "scanner")
        workflow.add_conditional_edges(
            "scanner",
            self._should_analyze,
            {"analyze": "analysis_agent", "skip": "reporter"}
        )
        workflow.add_conditional_edges(
            "analysis_agent",
            self._should_verify,
            {"verify": "verify_agent", "report": "reporter"}
        )
        workflow.add_conditional_edges(
            "verify_agent",
            self._verify_complete,
            {"report": "reporter", "retry": "analysis_agent"}
        )
        workflow.add_edge("reporter", END)

        return workflow.compile()

    async def _execute_with_graph(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """使用 LangGraph 执行（备用）"""
        initial_state = AgentAuditState(
            audit_id=context["audit_id"],
            project_id=context["project_id"],
            audit_type=context.get("audit_type", "quick"),
            config=context.get("config", {}),
            messages=[],
            current_step="init",
            current_agent="orchestrator",
            steps_completed=[],
            project_info=None,
            recon_result=None,
            scan_results=[],
            analysis_results=[],
            verification_results=[],
            files_scanned=0,
            findings_count=0,
            verified_findings=0,
            errors=[],
            should_retry=False,
            final_report=None,
        )

        start_time = time.time()

        try:
            result = await self._graph.ainvoke(initial_state)
            duration = time.time() - start_time

            return {
                "agent": self.name,
                "status": "success",
                "result": result.get("final_report", {}),
                "thinking_chain": self.thinking_chain,
                "duration_ms": int(duration * 1000),
            }
        except Exception as e:
            return {
                "agent": self.name,
                "status": "error",
                "error": str(e),
                "thinking_chain": self.thinking_chain,
            }

    # ==================== 串行执行（兜底） ====================

    async def _execute_sequential(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """串行执行（兜底模式）"""
        state = {
            "audit_id": context["audit_id"],
            "project_id": context["project_id"],
            "audit_type": context.get("audit_type", "quick"),
            "config": context.get("config", {}),
            "steps_completed": [],
            "scan_results": [],
            "analysis_results": [],
            "verification_results": [],
            "files_scanned": 0,
            "findings_count": 0,
            "verified_findings": 0,
        }

        # 执行各阶段
        state = await self._run_recon(state)
        state = await self._run_scan(state)
        state = await self._run_analysis(state)
        state = await self._run_verification(state)

        return {
            "agent": self.name,
            "status": "success",
            "result": await self._generate_final_report(state),
            "thinking_chain": self.thinking_chain,
        }

    # 以下是 LangGraph 节点函数（复用）
    async def _plan_audit(self, state: AgentAuditState) -> AgentAuditState:
        """规划审计"""
        self.think("制定审计计划")
        state["current_step"] = "planning"
        return state

    async def _run_recon(self, state: Dict) -> Dict:
        """运行 Recon"""
        from app.agents.recon import ReconAgent
        recon = ReconAgent()
        result = await recon.run({
            "audit_id": state["audit_id"],
            "project_id": state["project_id"],
        })
        state["recon_result"] = result.get("result")
        if "steps_completed" not in state:
            state["steps_completed"] = []
        state["steps_completed"].append("recon")
        return state

    async def _run_scan(self, state: Dict) -> Dict:
        """运行扫描"""
        from app.services.rust_client import rust_client
        try:
            result = await rust_client.scan_project(state["project_id"])
            state["scan_results"] = result.get("findings", [])
            state["files_scanned"] = result.get("files_scanned", 0)
            state["findings_count"] = len(state["scan_results"])
            if "steps_completed" not in state:
                state["steps_completed"] = []
            state["steps_completed"].append("scan")
        except Exception as e:
            self.think(f"扫描失败: {e}")
        return state

    async def _run_analysis(self, state: Dict) -> Dict:
        """运行分析"""
        from app.agents.analysis import AnalysisAgent
        analysis = AnalysisAgent()
        result = await analysis.run({
            "audit_id": state["audit_id"],
            "project_id": state["project_id"],
            "scan_results": state["scan_results"],
            "recon_result": state.get("recon_result"),
        })
        state["analysis_results"] = result.get("result", [])
        if "steps_completed" not in state:
            state["steps_completed"] = []
        state["steps_completed"].append("analysis")
        return state

    async def _run_verification(self, state: Dict) -> Dict:
        """运行验证"""
        from app.agents.verification import VerificationAgent
        verification = VerificationAgent()
        result = await verification.run({
            "audit_id": state["audit_id"],
            "findings": state["analysis_results"],
        })
        verified = result.get("result", {}).get("verified", [])
        state["verification_results"] = verified
        state["verified_findings"] = len([v for v in verified if v.get("verified")])
        if "steps_completed" not in state:
            state["steps_completed"] = []
        state["steps_completed"].append("verification")
        return state

    async def _generate_report(self, state: AgentAuditState) -> AgentAuditState:
        """生成报告"""
        self.think("生成报告")
        state["final_report"] = {}
        state["current_step"] = "complete"
        return state

    # 条件边函数
    def _should_recon(self, state: AgentAuditState) -> str:
        return "recon" if state["audit_type"] != "quick" else "scan"

    def _should_analyze(self, state: AgentAuditState) -> str:
        return "analyze" if state.get("scan_results") else "skip"

    def _should_verify(self, state: AgentAuditState) -> str:
        if state.get("config", {}).get("enable_verification", False):
            high_severity = [f for f in state.get("analysis_results", []) if f.get("severity") in ["critical", "high"]]
            return "verify" if high_severity else "report"
        return "report"

    def _verify_complete(self, state: AgentAuditState) -> str:
        return "retry" if state.get("should_retry") else "report"


# 创建全局实例
orchestrator_agent = OrchestratorAgent()
