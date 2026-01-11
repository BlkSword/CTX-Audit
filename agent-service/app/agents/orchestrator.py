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
                            await self._phase_manager.transition_to(AuditPhase.VERIFICATION)
                            self._update_progress(85, "分析完成，准备验证")
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

## 你可以调度的子 Agent
1. **recon**: 信息收集 Agent - 分析项目结构、技术栈、入口点
2. **analysis**: 分析 Agent - 深度代码审计、漏洞检测

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

1. **Thought**: 分析当前状态，思考下一步应该做什么
2. **Action**: 选择一个操作 (dispatch_agent/summarize/finish)
3. **Action Input**: 提供操作参数 (必须是有效的 JSON)

## 输出格式
每一步必须严格按照以下格式（禁止使用 Markdown 格式标记）：

```
Thought: [你的思考过程]
Action: dispatch_agent
Action Input: {"agent": "recon", "task": "侦察项目结构和技术栈"}
```

## ⚠️ 重要格式要求

**禁止使用 Markdown 格式标记！** 你的输出必须是纯文本格式：

✅ 正确格式：
```
Thought: 我需要先了解项目结构
Action: dispatch_agent
Action Input: {"agent": "recon", "task": "侦察项目结构和技术栈"}
```

❌ 错误格式（禁止使用）：
```
**Thought:** 我需要先了解项目结构
**Action:** dispatch_agent
**Action Input:** {"agent": "recon", "task": "侦察项目结构和技术栈"}
```

## 审计流程要求

**你必须按照以下顺序执行审计，不能跳过步骤：**

1. **第一步**：必须先调用 `dispatch_agent` 调度 `recon` Agent 来了解项目
2. **第二步**：根据 recon 结果，调度 `analysis` Agent 进行深度分析
3. **第三步**：如果分析有发现，可以再次调度 analysis 或直接完成审计
4. **最后**：调用 `finish` 完成审计

**重要：**
- 你必须先调度 recon Agent，不能直接调用 finish
- 每个步骤都要思考为什么这么做
- Action Input 必须是有效的 JSON 格式

## 示例流程

```
Thought: 我需要先了解项目的结构和技术栈，以便进行后续的安全审计
Action: dispatch_agent
Action Input: {"agent": "recon", "task": "分析项目结构、技术栈和入口点"}

Observation: [recon 结果...]

Thought: 项目是 Python Flask 应用，发现了一些高风险区域。现在我需要对这些区域进行深度分析
Action: dispatch_agent
Action Input: {"agent": "analysis", "task": "深度分析高风险区域的代码安全问题"}

Observation: [analysis 结果...]

Thought: 已完成深度分析，发现了 X 个漏洞。审计工作已经充分完成
Action: finish
Action Input: {"conclusion": "审计完成，共发现 X 个漏洞"}
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

## ⚠️ 重要提示
你必须按照以下步骤执行审计：
1. **首先**调用 dispatch_agent 调度 recon Agent 了解项目
2. **然后**根据结果调度 analysis Agent 进行分析
3. **最后**调用 finish 完成审计

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
        if dispatch_count >= 2:
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

            # 获取 agent 实例（不使用 to_dict 返回的数据）
            agent = await agent_registry.get_agent_instance(agent_id)
            if not agent:
                return f"## 调度失败\n\n错误: 无法获取 Agent 实例: {agent_id}"

            # 构建子 Agent 输入
            sub_input = {
                "audit_id": self._runtime_context.get("audit_id"),
                "project_id": self._runtime_context.get("project_id"),
                "project_path": self._runtime_context.get("project_path", ""),
                "task": task,
                "previous_results": {
                    "findings": self._all_findings,
                },
                # 传递之前 Agent 的结果
                **self._agent_results,
                # 传递 LLM 配置给子 Agent
                "llm_provider": self._llm_config.get("llm_provider"),
                "llm_model": self._llm_config.get("llm_model"),
                "api_key": self._llm_config.get("api_key"),
                "base_url": self._llm_config.get("base_url"),
            }

            # 执行子 Agent
            result = await agent.run(sub_input)

            if result.get("status") == "success":
                data = result.get("result", {})

                # 保存 Agent 结果
                self._agent_results[agent_name] = data

                # 收集发现
                findings = data.get("findings", [])
                if findings:
                    for finding in findings:
                        if isinstance(finding, dict):
                            # 标准化发现格式
                            normalized = self._normalize_finding(finding)
                            if normalized:
                                self._all_findings.append(normalized)

                # 更新统计
                if agent_name == "analysis":
                    self._runtime_context["files_scanned"] = data.get("files_analyzed", 0)

                # 构建观察结果
                if agent_name == "recon":
                    # Recon 返回的格式: project_info, structure, tech_stack, attack_surface, dependencies
                    structure = data.get('structure', {})
                    attack_surface = data.get('attack_surface', {})
                    tech_stack = data.get('tech_stack', {})
                    dependencies = data.get('dependencies', {})

                    # 将 attack_surface 转换为 scan_results 格式供 analysis agent 使用
                    scan_results = []
                    for entry_point in attack_surface.get('entry_points', []):
                        scan_results.append({
                            "id": f"recon_{len(scan_results)}",
                            "title": f"潜在攻击面: {entry_point.get('description', '未知')}",
                            "severity": entry_point.get('severity', 'medium'),
                            "file_path": entry_point.get('file', ''),
                            "type": entry_point.get('type', 'unknown'),
                            "description": entry_point.get('description', ''),
                            "source": "recon"
                        })

                    # 保存 scan_results 供 analysis 使用
                    self._agent_results['scan_results'] = scan_results
                    self._runtime_context['scan_results'] = scan_results

                    logger.info(f"[Orchestrator] Recon 完成，生成 {len(scan_results)} 个扫描候选")

                    observation = f"""## Recon Agent 执行结果

**状态**: 成功

### 项目结构
- 文件数: {len(structure.get('files', []))}
- 目录数: {len(structure.get('directories', []))}

### 技术栈
- 语言: {tech_stack.get('languages', [])}
- 框架: {tech_stack.get('frameworks', [])}

### 攻击面分析
- 入口点数量: {len(attack_surface.get('entry_points', []))}
- API 端点: {len(attack_surface.get('api_endpoints', []))}
- 用户输入点: {len(attack_surface.get('user_inputs', []))}
- 文件操作: {len(attack_surface.get('file_operations', []))}
- 命令执行: {len(attack_surface.get('command_executions', []))}

### 依赖分析
- 依赖库数量: {dependencies.get('total_libraries', 0)}

### 生成的扫描候选
已生成 {len(scan_results)} 个需要分析的候选区域
"""

                else:
                    observation = f"""## {agent_name} Agent 执行结果

**状态**: 成功
**发现数量**: {len(findings)}

### 发现摘要
"""
                    for i, f in enumerate(findings[:10]):
                        if isinstance(f, dict):
                            observation += f"""
{i+1}. [{f.get('severity', 'unknown')}] {f.get('title', 'Unknown')}
   - 类型: {f.get('vulnerability_type', 'unknown')}
   - 文件: {f.get('file_path', 'unknown')}
"""

                    if len(findings) > 10:
                        observation += f"\n... 还有 {len(findings) - 10} 个发现"

                if data.get("summary"):
                    observation += f"\n\n### Agent 总结\n{data['summary']}"

                return observation
            else:
                return f"## {agent_name} Agent 执行失败\n\n错误: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"Sub-agent dispatch failed: {e}", exc_info=True)
            return f"## 调度失败\n\n错误: {str(e)}"

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
