"""
Orchestrator Agent - LLM 驱动的自主编排者

使用 ReAct 模式：
- LLM 思考当前状态
- LLM 决定下一步操作
- 执行操作，获取结果
- LLM 分析结果，决定下一步
- 重复直到 LLM 决定完成
"""
from typing import Dict, Any, Optional, List
from loguru import logger
import time
import json
import re
from dataclasses import dataclass

from app.agents.base import BaseAgent
from app.services.llm import LLMService, LLMProvider
from app.services.llm.adapters.base import LLMMessage
from app.core.agent_registry import agent_registry
from app.core.graph_controller import agent_graph_controller
from app.services.rust_client import rust_client
from app.core.audit_phase import AuditPhaseManager, AuditPhase, get_phase_manager
from app.core.monitoring import get_monitoring_system
from app.core.resilience import get_llm_circuit, get_llm_rate_limiter, with_retry, LLM_RETRY_CONFIG


@dataclass
class AgentStep:
    """执行步骤"""
    thought: str
    action: str
    action_input: Dict[str, Any]
    observation: Optional[str] = None
    sub_agent_result: Optional[Any] = None


class OrchestratorAgent(BaseAgent):
    """
    编排 Agent - ReAct 模式

    LLM 全程参与决策：
    1. LLM 思考当前状态
    2. LLM 决定下一步操作
    3. 执行操作，获取结果
    4. LLM 分析结果，决定下一步
    5. 重复直到 LLM 决定完成
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="orchestrator", config=config)

        config = config or {}
        self._llm_config = config
        self._llm: Optional[LLMService] = None

        self.max_iterations = config.get("max_iterations", 20)
        self._conversation: List[Dict[str, Any]] = []
        self._steps: List[AgentStep] = []
        self._all_findings: List[Dict[str, Any]] = []

        # 运行时上下文
        self._runtime_context: Dict[str, Any] = {}

        # 跟踪已调度的 Agent 任务，避免重复调度
        self._dispatched_tasks: Dict[str, int] = {}

        # 保存各个 Agent 的完整结果
        self._agent_results: Dict[str, Dict[str, Any]] = {}

        # 进度跟踪
        self._progress: int = 0

        # 集成审计阶段管理
        self._phase_manager: Optional[AuditPhaseManager] = None
        self._monitoring = get_monitoring_system()

        # 容错机制
        self._llm_circuit = get_llm_circuit()
        self._llm_rate_limiter = get_llm_rate_limiter()

    def _update_progress(self, progress: int, message: str = ""):
        """更新审计进度"""
        self._progress = min(100, max(0, progress))
        if message:
            logger.info(f"[Orchestrator] 进度: {self._progress}% - {message}")

        # 发布进度事件到前端
        # 创建异步任务来发布事件（不阻塞主流程）
        import asyncio

        async def _publish_progress():
            try:
                await self._publish_event("progress", {
                    "progress": self._progress,
                    "message": message
                })
            except Exception as e:
                logger.warning(f"[Orchestrator] 发布进度事件失败: {e}")

        # 如果在异步上下文中，直接创建任务
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(_publish_progress())
        except:
            pass

    @property
    def llm(self):
        """延迟初始化 LLM 服务"""
        if self._llm is None:
            try:
                provider_str = self._llm_config.get("llm_provider", "anthropic")
                try:
                    provider = LLMProvider(provider_str)
                except ValueError:
                    logger.warning(f"未知的 LLM provider '{provider_str}'，使用 OpenAI 兼容模式")
                    provider = LLMProvider.OPENAI

                self._llm = LLMService(
                    provider=provider,
                    model=self._llm_config.get("llm_model", "claude-3-5-sonnet-20241022"),
                    api_key=self._llm_config.get("api_key"),
                    base_url=self._llm_config.get("base_url"),
                )
            except Exception as e:
                logger.error(f"LLM 服务初始化失败: {e}")
                raise ValueError("LLM 服务未配置，请在设置中配置 API Key")
        return self._llm

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行审计编排"""
        audit_id = context.get("audit_id")
        self.think(f"开始编排审计任务: {audit_id}")

        try:
            return await self._execute_with_llm(context)
        except Exception as e:
            logger.error(f"审计执行失败: {e}", exc_info=True)
            return {
                "agent": self.name,
                "status": "error",
                "error": str(e),
                "thinking_chain": self.thinking_chain
            }

    async def _execute_with_llm(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """LLM 驱动的自主编排 - ReAct 模式"""
        audit_id = context["audit_id"]
        project_id = context["project_id"]
        start_time = time.time()

        # 初始化阶段管理器
        self._phase_manager = get_phase_manager(audit_id)

        # 注册 Orchestrator
        orchestrator_id = f"orchestrator_{audit_id}"
        self.agent_id = orchestrator_id
        await agent_registry.register_agent(
            agent_id=orchestrator_id,
            agent_name="Orchestrator",
            agent_type="orchestrator",
            task=f"编排审计: {audit_id}",
            parent_id=None,
            agent_instance=self,
        )

        # 保存运行时上下文
        self._runtime_context = {
            "audit_id": audit_id,
            "project_id": project_id,
            "project_path": context.get("project_path", ""),
            "audit_type": context.get("audit_type", "quick"),
            "config": context.get("config", {}),
        }

        # 初始化进度
        self._progress = 0
        self._update_progress(5, "初始化审计任务")

        # 初始化审计阶段
        await self._phase_manager.transition_to(AuditPhase.INITIALIZATION)
        await self._publish_event("thinking", {
            "message": f"审计阶段: {self._phase_manager.current_phase.value}"
        })

        # 构建初始消息
        system_prompt = self._get_system_prompt()
        initial_message = self._format_initial_message(context)

        # 初始化对话历史 - 使用 LLMMessage 对象
        self._conversation = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=initial_message),
        ]

        self._steps = []
        self._all_findings = []
        self._agent_results = {}
        self._dispatched_tasks = {}
        final_result = None

        # 初始化错误计数器
        self._empty_response_count = 0
        self._format_error_count = 0

        self.think("Orchestrator Agent 启动，LLM 开始自主编排决策...")
        await self._publish_event("thinking", {
            "message": "Orchestrator Agent 启动，开始审计编排..."
        })

        try:
            # 转换到规划阶段
            await self._phase_manager.transition_to(AuditPhase.PLANNING)

            for iteration in range(self.max_iterations):
                self._iteration = iteration + 1
                logger.info(f"[Orchestrator] Iteration {iteration + 1}/{self.max_iterations}")

                # 调用 LLM 进行思考和决策（带容错机制）
                try:
                    logger.debug(f"[Orchestrator] 发送 LLM 请求，当前对话历史长度: {len(self._conversation)}")

                    # 应用速率限制
                    await self._llm_rate_limiter.acquire()

                    # 使用熔断器保护 LLM 调用
                    async def _llm_call():
                        return await self.llm.generate(messages=self._conversation)

                    response = await self._llm_circuit.call(_llm_call)
                    llm_output = response.content if hasattr(response, 'content') else ""

                    # 记录 LLM 调用指标
                    await self._monitoring.record_llm_call(
                        model=self._llm_config.get("llm_model", "unknown"),
                        tokens_used=len(llm_output.split()),  # 粗略估计
                        duration=0.1,  # TODO: 实际测量
                        success=True,
                    )

                    logger.info(f"[Orchestrator] LLM 响应长度: {len(llm_output)} 字符")
                    logger.debug(f"[Orchestrator] LLM 响应内容: {llm_output[:500]}...")
                except Exception as e:
                    logger.error(f"[Orchestrator] LLM call failed: {e}")

                    # 记录错误
                    await self._monitoring.record_llm_call(
                        model=self._llm_config.get("llm_model", "unknown"),
                        tokens_used=0,
                        duration=0,
                        success=False,
                        error=e,
                    )

                    await self._publish_event("error", {
                        "message": f"LLM 调用失败: {str(e)}"
                    })
                    # 返回错误状态
                    return {
                        "agent": self.name,
                        "status": "error",
                        "error": f"LLM 调用失败: {str(e)}",
                        "thinking_chain": self.thinking_chain,
                    }

                if not llm_output or not llm_output.strip():
                    logger.warning(f"[Orchestrator] Empty LLM response")
                    # 空响应重试机制
                    empty_count = getattr(self, '_empty_response_count', 0) + 1
                    self._empty_response_count = empty_count
                    if empty_count >= 3:
                        error_msg = "连续 3 次收到空响应，停止审计"
                        await self._publish_event("error", {"message": error_msg})
                        return {
                            "agent": self.name,
                            "status": "error",
                            "error": error_msg,
                            "thinking_chain": self.thinking_chain,
                        }
                    # 提示 LLM 重新输出
                    self._conversation.append(LLMMessage(role="user", content="请输出你的决策：Thought + Action + Action Input"))
                    continue

                # 重置空响应计数
                self._empty_response_count = 0

                # 解析 LLM 的决策
                step = self._parse_llm_response(llm_output)

                if step:
                    logger.info(f"[Orchestrator] 解析成功: action={step.action}, thought={step.thought[:50]}...")
                else:
                    logger.warning(f"[Orchestrator] 解析失败，无法提取 Thought/Action")

                if not step:
                    # LLM 输出格式不正确，提示重试
                    format_count = getattr(self, '_format_error_count', 0) + 1
                    self._format_error_count = format_count
                    if format_count >= 3:
                        error_msg = "连续 3 次格式错误，停止审计"
                        await self._publish_event("error", {"message": error_msg})
                        return {
                            "agent": self.name,
                            "status": "error",
                            "error": error_msg,
                            "thinking_chain": self.thinking_chain,
                        }
                    await self._publish_event("thinking", {
                        "message": f"LLM 输出格式错误 ({format_count}/3)，请重新输出"
                    })
                    self._conversation.append(LLMMessage(role="assistant", content=llm_output))
                    self._conversation.append(LLMMessage(role="user", content="请按照规定格式输出：Thought + Action + Action Input"))
                    continue

                # 重置格式错误计数
                self._format_error_count = 0

                self._steps.append(step)

                # 发送思考内容事件
                if step.thought:
                    self.think(step.thought)
                    await self._publish_event("thinking", {
                        "message": step.thought
                    })

                # 添加 LLM 响应到历史
                self._conversation.append(LLMMessage(role="assistant", content=llm_output))

                # 执行 LLM 决定的操作
                if step.action == "finish":
                    # 检查是否已经执行了必要的步骤
                    if len(self._steps) <= 2 and iteration == 1:
                        # 第一步就调用 finish，拒绝并要求先调度 recon
                        logger.warning(f"[Orchestrator] LLM 尝试在第一步直接调用 finish，拒绝")
                        await self._publish_event("thinking", {
                            "message": "不能直接完成审计，必须先调度 recon Agent"
                        })
                        self._conversation.append(LLMMessage(role="user", content="""
你不能直接调用 finish。必须按照审计流程执行：

1. 首先调用 dispatch_agent 调度 recon Agent
2. 然后根据结果调度 analysis Agent
3. 最后才能调用 finish

请重新开始，先调用 recon Agent。

示例：
Thought: 我需要先了解项目的结构和技术栈
Action: dispatch_agent
Action Input: {"agent": "recon", "task": "侦察项目结构和技术栈"}
"""))
                        continue

                    # LLM 决定完成审计
                    self.think("审计完成，LLM 判断审计已充分完成")
                    await self._publish_event("status", {
                        "status": "completed",
                        "message": f"审计完成，发现 {len(self._all_findings)} 个漏洞"
                    })
                    final_result = step.action_input
                    break

                elif step.action == "dispatch_agent":
                    # LLM 决定调度子 Agent
                    agent_name = step.action_input.get("agent", "")
                    task = step.task = step.action_input.get("task", "")

                    # 根据agent类型转换审计阶段
                    if agent_name == "recon":
                        await self._phase_manager.transition_to(AuditPhase.RECONNAISSANCE)
                        self._update_progress(15, f"开始侦察项目结构")
                    elif agent_name == "analysis":
                        await self._phase_manager.transition_to(AuditPhase.ANALYSIS)
                        self._update_progress(45, f"开始分析漏洞")
                    elif agent_name == "verification":
                        await self._phase_manager.transition_to(AuditPhase.VERIFICATION)
                        self._update_progress(75, f"开始验证漏洞")

                    self.think(f"调度 {agent_name} Agent: {task[:100]}")
                    await self._publish_event("action", {
                        "message": f"调度 {agent_name} Agent",
                        "agent": agent_name,
                        "task": task
                    })

                    try:
                        observation = await self._dispatch_agent(step.action_input)
                        step.observation = observation

                        # 更新进度和阶段
                        if agent_name == "recon":
                            await self._phase_manager.transition_to(AuditPhase.ANALYSIS)
                            self._update_progress(35, "侦察完成，准备分析")
                        elif agent_name == "analysis":
                            # 分析完成后，建议进入验证阶段
                            await self._phase_manager.transition_to(AuditPhase.VERIFICATION)
                            self._update_progress(70, "分析完成，准备验证")

                            # 添加提示，告诉LLM接下来的选择
                            observation = f"""{observation}

---

## 📊 分析已完成

分析Agent已完成代码审计。现在你可以：

1. **查看上述分析结果**
2. **如果发现高危漏洞，强烈建议调度 `verification` Agent 进行验证**
3. 如果满意，也可以调用 `finish` 完成审计

**建议：如果有高危漏洞，请务必验证！**
"""
                            step.observation = observation
                        
                        elif agent_name == "verification":
                            await self._phase_manager.transition_to(AuditPhase.COMPLETE)
                            self._update_progress(95, "验证完成，准备生成报告")

                    except Exception as e:
                        logger.error(f"[Orchestrator] Sub-agent {agent_name} failed: {e}")
                        observation = f"## {agent_name} Agent 执行失败\n\n错误: {str(e)}"
                        step.observation = observation
                        await self._publish_event("error", {
                            "message": f"{agent_name} Agent 执行失败: {str(e)[:100]}"
                        })

                    # 发送观察事件
                    self.think(f"{agent_name} Agent 执行完成")

                elif step.action == "summarize":
                    # LLM 要求汇总
                    self.think("汇总当前发现")
                    await self._publish_event("thinking", {
                        "message": "汇总当前发现"
                    })
                    observation = self._summarize_findings()
                    step.observation = observation

                else:
                    observation = f"未知操作: {step.action}，可用操作: dispatch_agent, summarize, finish"
                    step.observation = observation
                    await self._publish_event("thinking", {
                        "message": observation
                    })

                # 添加观察结果到历史
                self._conversation.append(LLMMessage(role="user", content=f"Observation:\n{step.observation}"))

            # 生成最终结果
            duration_ms = int((time.time() - start_time) * 1000)

            # 更新进度到 100%
            self._update_progress(100, "审计完成")

            await self._publish_event("status", {
                "status": "completed",
                "message": f"Orchestrator 完成: {len(self._all_findings)} 个发现, {len(self._steps)} 轮决策"
            })

            return {
                "agent": self.name,
                "status": "success",
                "result": {
                    "findings": self._all_findings,
                    "summary": final_result or self._generate_default_summary(),
                    "steps": [
                        {
                            "thought": s.thought,
                            "action": s.action,
                            "action_input": s.action_input,
                            "observation": s.observation[:500] if s.observation else None,
                        }
                        for s in self._steps
                    ],
                },
                "thinking_chain": self.thinking_chain,
                "duration_ms": duration_ms,
                "stats": {
                    "files_scanned": self._runtime_context.get("files_scanned", 0),
                    "findings_count": len(self._all_findings),
                }
            }

        except Exception as e:
            logger.error(f"Orchestrator execution failed: {e}", exc_info=True)
            return {
                "agent": self.name,
                "status": "error",
                "error": str(e),
                "thinking_chain": self.thinking_chain
            }

    def _get_system_prompt(self) -> str:
        """获取系统提示词"""
        return """你是 CTX-Audit 的编排 Agent，负责**自主**协调整个安全审计流程。

## 你的角色
你是整个审计流程的**大脑**，你需要：
1. 自主思考和决策
2. 根据观察结果动态调整策略
3. 决定何时调用哪个子 Agent
4. 判断何时审计完成

## 🧠 战略思考协议 (Strategic Thinking Protocol) ⚡⚡⚡
作为编排者，你的 `Thought` 必须包含以下维度：

### 1. 全局态势感知 (Situational Awareness)
- **当前阶段**：我们在审计的哪个阶段？(侦察/分析/验证)
- **信息完整性**：我们对项目结构、技术栈、攻击面了解多少？是否还有盲区？

### 2. 决策逻辑 (Decision Logic)
- **Why**: 为什么要调用这个 Agent？(例如："Recon 发现大量 API 端点，需要 Analysis 深度扫描")
- **Expectation**: 期望它返回什么？(例如："期望发现未授权访问漏洞")

### 3. 自我反思 (Self-Reflection)
- 我是否在重复调度同一个 Agent 而没有新发现？
- 我是否遗漏了某些高危文件？

## 你可以调度的子 Agent
1. **recon**: 信息收集 Agent - 分析项目结构、技术栈、入口点
2. **analysis**: 分析 Agent - 深度代码审计、漏洞检测
3. **verification**: 验证 Agent - 验证发现的漏洞，生成 PoC

## 你可以使用的操作

### 1. 调度子 Agent
```
Action: dispatch_agent
Action Input: {"agent": "recon", "task": "侦察项目结构和技术栈"}
```

### 2. 汇总发现
```
Action: summarize
Action Input: {}
```

### 3. 完成审计
```
Action: finish
Action Input: {"conclusion": "审计结论"}
```

## 工作方式
每一步，你需要：

1. **Thought**: 严格遵循 [战略思考协议]。分析当前状态，评估已有的发现，决定下一步的最佳策略。
2. **Action**: 选择一个操作 (dispatch_agent/summarize/finish)
3. **Action Input**: 提供操作参数 (必须是有效的 JSON)

## 输出格式
每一步必须严格按照以下格式（禁止使用 Markdown 格式标记）：

```
Thought: 
[Situational Awareness] Recon 已完成，确认项目为 Python Flask 应用，发现 3 个 API 端点和 1 个数据库连接文件。
[Decision Logic] 由于发现了数据库连接代码，存在 SQL 注入风险，需要调度 Analysis Agent 进行深度扫描。
[Expectation] 期望 Analysis Agent 能覆盖这些高风险文件。

Action: dispatch_agent
Action Input: {"agent": "analysis", "task": "深度分析数据库连接和API接口"}
```

## ⚠️ 重要格式要求

**禁止使用 Markdown 格式标记！** 你的输出必须是纯文本格式。

## 审计流程要求

虽然你需要自主决策，但通常遵循以下逻辑：

1. **侦察阶段**：调用 `recon` Agent 了解项目。如果信息不足，可以再次调用。
2. **分析阶段**：调用 `analysis` Agent 进行深度分析。
   - 如果发现大量漏洞，可以考虑分批分析。
   - 如果没有发现漏洞，但你怀疑有遗漏，可以指定特定的关注点再次调用 `analysis`。
3. **验证阶段**（推荐）：如果有高危漏洞，调用 `verification` Agent 进行验证。
4. **完成**：调用 `finish` 完成审计。

**重要：**
- 必须先侦察 (recon)。
- 不要急于 finish，确保已充分挖掘潜在漏洞。
- 只有在确认没有更多工作需要做时，才调用 finish。
- Action Input 必须是有效的 JSON 格式。

## 示例流程

```
Thought: 我需要先了解项目的结构和技术栈，以便进行后续的安全审计
Action: dispatch_agent
Action Input: {"agent": "recon", "task": "分析项目结构、技术栈和入口点"}

Observation: [recon 结果...]

Thought: 
[Situational Awareness] 项目是 Python Flask 应用，发现了一些高风险区域。
[Decision Logic] 现在我需要对这些区域进行深度分析。

Action: dispatch_agent
Action Input: {"agent": "analysis", "task": "深度分析高风险区域的代码安全问题"}

Observation: [analysis 结果...]

Thought: 分析发现了一个 SQL 注入漏洞，我需要验证它是否真实存在
Action: dispatch_agent
Action Input: {"agent": "verification", "task": "验证 SQL 注入漏洞"}

Observation: [verification 结果...]

Thought: 已完成验证，漏洞确认为真实。审计工作已经充分完成
Action: finish
Action Input: {"conclusion": "审计结论"}
```

现在开始审计，请先调用 recon Agent！"""

    def _format_initial_message(self, context: Dict[str, Any]) -> str:
        """构建初始消息"""
        return f"""请开始对以下项目进行安全审计。

## 项目信息
- Project ID: {context.get("project_id", "unknown")}
- Audit ID: {context.get("audit_id", "unknown")}
- Audit Type: {context.get("audit_type", "quick")}

## 可用子 Agent
- recon: 信息收集 Agent，用于分析项目结构和技术栈
- analysis: 分析 Agent，用于深度代码审计和漏洞检测
- verification: 验证 Agent，用于验证发现的漏洞

## ⚠️ 重要提示
推荐的执行步骤：
1. **首先**调用 recon Agent 了解项目
2. **然后**调用 analysis Agent 进行分析
3. **可选**调用 verification Agent 验证高危漏洞
4. **最后**调用 finish 完成审计

**不能直接调用 finish！必须先调度 recon Agent！**

请立即开始：首先输出你的思考，然后调用 dispatch_agent 调度 recon Agent。

示例：
Thought: 我需要先了解项目的结构和技术栈
Action: dispatch_agent
Action Input: {{"agent": "recon", "task": "侦察项目结构和技术栈"}}"""


    def _parse_llm_response(self, response: str) -> Optional[AgentStep]:
        """解析 LLM 响应"""
        # 预处理 - 移除 Markdown 格式标记
        cleaned_response = response
        cleaned_response = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned_response)

        # 提取 Thought
        thought_match = re.search(r'Thought:\s*(.*?)(?=Action:|$)', cleaned_response, re.DOTALL)
        thought = thought_match.group(1).strip() if thought_match else ""

        # 提取 Action
        action_match = re.search(r'Action:\s*(\w+)', cleaned_response)
        if not action_match:
            return None
        action = action_match.group(1).strip()

        # 提取 Action Input
        input_match = re.search(r'Action Input:\s*(.*?)(?=Thought:|Observation:|$)', cleaned_response, re.DOTALL)
        if not input_match:
            return None

        input_text = input_match.group(1).strip()
        # 移除 markdown 代码块
        input_text = re.sub(r'```json\s*', '', input_text)
        input_text = re.sub(r'```\s*', '', input_text)

        try:
            action_input = json.loads(input_text)
        except json.JSONDecodeError:
            # 如果 JSON 解析失败，尝试提取原始文本
            action_input = {"raw": input_text}

        return AgentStep(
            thought=thought,
            action=action,
            action_input=action_input,
        )

    async def _dispatch_agent(self, params: Dict[str, Any]) -> str:
        """调度子 Agent"""
        agent_name = params.get("agent", "")
        task = params.get("task", "")

        logger.info(f"[Orchestrator] Dispatching {agent_name} Agent: {task[:50]}...")

        # 检查是否重复调度同一个 Agent
        dispatch_count = self._dispatched_tasks.get(agent_name, 0)
        # 放宽重复调度限制，允许 Analysis 多次运行
        if dispatch_count >= 3:
            return f"""## 重复调度警告

你已经调度 {agent_name} Agent {dispatch_count} 次了。

如果之前的调度没有返回有用的结果，请考虑：
1. 尝试调度其他 Agent
2. 使用 finish 操作结束审计并汇总已有发现

当前已收集的发现数量: {len(self._all_findings)}
"""

        self._dispatched_tasks[agent_name] = dispatch_count + 1

        try:
            # 创建子 Agent
            agent_id = await agent_graph_controller.create_agent(
                agent_type=agent_name,
                task=task,
                parent_id=self.agent_id,
            )

            # 获取 agent 实例
            agent = await agent_registry.get_agent_instance(agent_id)
            if not agent:
                return f"## 调度失败\n\n错误: 无法获取 Agent 实例: {agent_id}"

            # 准备 LLM 配置参数
            llm_params = {}
            
            # 1. 从 Orchestrator 配置获取
            if self._llm_config.get("llm_provider"):
                llm_params["llm_provider"] = self._llm_config.get("llm_provider")
            if self._llm_config.get("llm_model"):
                llm_params["llm_model"] = self._llm_config.get("llm_model")
            if self._llm_config.get("api_key"):
                llm_params["api_key"] = self._llm_config.get("api_key")
            if self._llm_config.get("base_url"):
                llm_params["base_url"] = self._llm_config.get("base_url")
                
            # 2. 如果缺失，尝试从运行时上下文的 config 获取 (Global Config)
            global_config = self._runtime_context.get("config", {})
            if not llm_params.get("api_key") and global_config.get("api_key"):
                llm_params["api_key"] = global_config.get("api_key")
                # Also check for provider/model in global config
                if not llm_params.get("llm_provider") and global_config.get("llm_provider"):
                    llm_params["llm_provider"] = global_config.get("llm_provider")
                if not llm_params.get("llm_model") and global_config.get("llm_model"):
                    llm_params["llm_model"] = global_config.get("llm_model")

            # Log dispatch info (mask key)
            has_key = bool(llm_params.get("api_key"))
            logger.info(f"[Orchestrator] Dispatching {agent_name} with LLM config: provider={llm_params.get('llm_provider')}, has_key={has_key}")

            # 执行子 Agent
            result_data = await agent.run({
                "audit_id": self._runtime_context.get("audit_id"),
                "project_id": self._runtime_context.get("project_id"),
                "project_path": self._runtime_context.get("project_path"),
                "task": task,
                # 传递已有的发现给验证 Agent
                "findings": self._all_findings if agent_name == "verification" else [],
                # 传递之前 Agent 的结果
                **self._agent_results,
                # 传递 LLM 配置给子 Agent
                **llm_params
            })

            # 提取结果
            status = result_data.get("status")
            result = result_data.get("result", {})
            
            if status == "error":
                return f"## {agent_name} Agent 执行出错\n\n错误: {result_data.get('error')}"

            # ------------------------------------------------------------------
            # CRITICAL FIX: 收集子 Agent 的发现
            # ------------------------------------------------------------------
            new_findings = []
            
            # Recon Agent 返回 findings 在 tool_findings, dataflow_findings 等字段
            if agent_name == "recon":
                if isinstance(result, dict):
                    # 提取工具发现
                    if "tool_findings" in result:
                        new_findings.extend(result["tool_findings"])
                    # 提取数据流发现
                    if "dataflow_findings" in result:
                        new_findings.extend(result["dataflow_findings"])
            
            # Analysis Agent 通常直接返回 findings 列表或包含 findings 的字典
            elif agent_name == "analysis":
                if isinstance(result, dict):
                    if "findings" in result:
                        new_findings.extend(result["findings"])
                elif isinstance(result, list):
                    new_findings.extend(result)

            # Verification Agent 返回验证后的 findings
            elif agent_name == "verification":
                # 验证 Agent 不产生新漏洞，而是更新现有漏洞的状态
                # 这里我们可以获取验证结果报告
                verified_results = result.get("verified", [])
                # 更新 _all_findings 中的验证状态
                for v_res in verified_results:
                    f_id = v_res.get("finding_id")
                    is_verified = v_res.get("verified", False)
                    for finding in self._all_findings:
                        if finding.get("id") == f_id:
                            finding["verified"] = is_verified
                            finding["verification_evidence"] = v_res.get("evidence")
                            finding["poc_code"] = v_res.get("poc_code")

            # 将新发现添加到总列表中 (去重)
            added_count = 0
            existing_ids = {f.get("id") for f in self._all_findings if f.get("id")}
            
            for f in new_findings:
                # 确保每个 finding 都有 ID
                if not f.get("id"):
                    import uuid
                    f["id"] = str(uuid.uuid4())
                
                if f.get("id") not in existing_ids:
                    self._all_findings.append(f)
                    existing_ids.add(f.get("id"))
                    added_count += 1
            
            logger.info(f"[Orchestrator] 从 {agent_name} 收集到 {added_count} 个新发现 (总计: {len(self._all_findings)})")
            
            # 实时通知前端有新发现
            if added_count > 0:
                await self._publish_event("findings_detected", {
                    "message": f"由 {agent_name} 发现 {added_count} 个新问题",
                    "count": added_count,
                    "total": len(self._all_findings),
                    "agent": agent_name
                })
            
            # ------------------------------------------------------------------

            # 保存 Agent 结果
            self._agent_results[agent_name] = result

            # 格式化观察结果供 LLM 阅读
            if agent_name == "recon":
                summary = f"发现 {len(new_findings)} 个潜在问题。项目技术栈: {result.get('tech_stack', {}).get('languages', [])}"
            elif agent_name == "analysis":
                summary = f"分析完成，发现 {len(new_findings)} 个漏洞。"
            elif agent_name == "verification":
                summary = f"验证完成。确认 {result.get('total_verified', 0)} 个漏洞，排除 {result.get('total_false_positives', 0)} 个误报。"
            else:
                summary = "执行完成"

            return f"""## {agent_name} 执行成功

{summary}

### 详细结果摘要
- 新增发现: {added_count}
- 当前总发现: {len(self._all_findings)}

(完整结果已保存到上下文)
"""

        except Exception as e:
            logger.error(f"调度 {agent_name} 失败: {e}", exc_info=True)
            return f"调度失败: {str(e)}"

    def _normalize_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """标准化发现格式"""
        normalized = dict(finding)

        # 处理 file -> file_path
        if "file" in normalized and "file_path" not in normalized:
            normalized["file_path"] = normalized["file"]

        # 处理 line -> line_start
        if "line" in normalized and "line_start" not in normalized:
            normalized["line_start"] = normalized["line"]

        # 处理 type -> vulnerability_type
        if "type" in normalized and "vulnerability_type" not in normalized:
            type_val = normalized["type"]
            if type_val and type_val.lower() not in ["vulnerability", "finding", "issue"]:
                normalized["vulnerability_type"] = type_val

        # 确保 severity 存在
        if "severity" not in normalized:
            normalized["severity"] = "medium"

        # 生成 title 如果不存在
        if "title" not in normalized:
            vuln_type = normalized.get("vulnerability_type", "Unknown")
            file_path = normalized.get("file_path", "")
            if file_path:
                import os
                normalized["title"] = f"{vuln_type.replace('_', ' ').title()} in {os.path.basename(file_path)}"
            else:
                normalized["title"] = f"{vuln_type.replace('_', ' ').title()} Vulnerability"

        return normalized

    def _summarize_findings(self) -> str:
        """汇总当前发现"""
        if not self._all_findings:
            return "目前还没有发现任何漏洞。"

        # 统计
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        type_counts = {}

        for f in self._all_findings:
            if not isinstance(f, dict):
                continue

            sev = f.get("severity", "low")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            vtype = f.get("vulnerability_type", "other")
            type_counts[vtype] = type_counts.get(vtype, 0) + 1

        summary = f"""## 当前发现汇总

**总计**: {len(self._all_findings)} 个漏洞

### 严重程度分布
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}

### 漏洞类型分布
"""
        for vtype, count in type_counts.items():
            summary += f"- {vtype}: {count}\n"

        summary += "\n### 详细列表\n"
        for i, f in enumerate(self._all_findings):
            if isinstance(f, dict):
                summary += f"{i+1}. [{f.get('severity')}] {f.get('title')} ({f.get('file_path')})\n"

        return summary

    def _generate_default_summary(self) -> Dict[str, Any]:
        """生成默认摘要"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for f in self._all_findings:
            if isinstance(f, dict):
                sev = f.get("severity", "low")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_findings": len(self._all_findings),
            "severity_distribution": severity_counts,
            "conclusion": "审计完成",
        }


# 创建全局实例
orchestrator_agent = OrchestratorAgent()
