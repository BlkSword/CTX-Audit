"""
ReAct Agent Module

实现 Thought-Action-Observation 循环的推理模式
"""
import re
import json
import asyncio
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Callable, Awaitable, Tuple
from loguru import logger

from app.core.agent_state import AgentState, AgentStatus


@dataclass
class AgentStep:
    """执行步骤"""
    iteration: int
    thought: str
    action: str
    action_input: Dict[str, Any]
    observation: Optional[str] = None
    sub_agent_result: Optional[Any] = None
    success: bool = True
    error: Optional[str] = None


@dataclass
class ReActConfig:
    """ReAct模式配置"""
    max_iterations: int = 20
    thought_prefix: str = "Thought:"
    action_prefix: str = "Action:"
    action_input_prefix: str = "Action Input:"
    observation_prefix: str = "Observation:"
    enable_thinking: bool = True
    enable_streaming: bool = True


class ReActLoop:
    """
    ReAct循环执行器

    实现 Thought -> Action -> Observation 的循环模式：
    1. Thought: LLM分析当前状态，思考下一步
    2. Action: LLM选择并执行操作
    3. Observation: 观察操作结果，更新状态
    4. 重复直到LLM决定完成
    """

    def __init__(
        self,
        state: AgentState,
        config: ReActConfig,
        llm_call_fn: Callable[[List[Dict]], Awaitable[Tuple[str, int]]],
        tool_executor: Callable[[str, Dict[str, Any]], Awaitable[str]],
        event_emitter: Optional[Any] = None,
    ):
        """
        初始化ReAct循环

        Args:
            state: Agent状态
            config: ReAct配置
            llm_call_fn: LLM调用函数，返回 (response, tokens)
            tool_executor: 工具执行函数
            event_emitter: 事件发射器（可选）
        """
        self.state = state
        self.config = config
        self.llm_call_fn = llm_call_fn
        self.tool_executor = tool_executor
        self.event_emitter = event_emitter

        self.steps: List[AgentStep] = []
        self.all_findings: List[Dict[str, Any]] = []

    async def run(self, initial_message: str) -> List[AgentStep]:
        """
        执行ReAct循环

        Args:
            initial_message: 初始消息

        Returns:
            执行步骤列表
        """
        self.state.start()
        await self._emit_event("info", "ReAct循环启动")

        # 添加初始消息到对话历史
        self.state.add_message("user", initial_message)

        try:
            for iteration in range(self.config.max_iterations):
                # 检查停止条件
                if self.state.should_stop():
                    logger.info(f"[{self.state.agent_name}] 停止信号收到，退出循环")
                    break

                self.state.increment_iteration()
                step = await self._execute_iteration(iteration + 1)
                self.steps.append(step)

                # 如果是不成功的步骤，根据配置决定是否继续
                if not step.success:
                    if step.error and "完成" in step.error:
                        # LLM决定完成
                        await self._emit_event("info", f"审计完成: {step.thought[:100]}")
                        break
                    elif step.error:
                        # 发生错误，记录但继续
                        logger.warning(f"[{self.state.agent_name}] 步骤错误: {step.error}")

                # 检查是否达到最大迭代次数
                if self.state.has_reached_max_iterations():
                    await self._emit_event(
                        "warning",
                        f"达到最大迭代次数 ({self.config.max_iterations})"
                    )
                    break

            # 完成执行
            self.state.set_completed({
                "steps": len(self.steps),
                "findings": len(self.all_findings),
            })

            return self.steps

        except Exception as e:
            logger.error(f"[{self.state.agent_name}] ReAct循环异常: {e}")
            self.state.set_failed(str(e))
            raise

    async def _execute_iteration(self, iteration: int) -> AgentStep:
        """执行单次迭代"""
        await self._emit_event(
            "thinking",
            f"[迭代 {iteration}/{self.config.max_iterations}] LLM正在思考..."
        )

        # 1. Thought: LLM思考
        llm_response, tokens = await self._call_llm()
        self.state.add_tokens(tokens)

        # 解析LLM响应
        thought, action, action_input = self._parse_llm_response(llm_response)

        # 发射思考事件
        if thought:
            await self._emit_event("llm_thought", thought)

        # 2. Action: 执行操作
        observation = None
        success = True
        error = None

        if action == "finish":
            # 完成审计
            observation = json.dumps(action_input, ensure_ascii=False)
            self.state.request_stop()

        elif action:
            await self._emit_event("llm_action", f"执行操作: {action}")

            try:
                observation = await self.tool_executor(action, action_input)
            except Exception as e:
                success = False
                error = str(e)
                observation = f"错误: {str(e)}"
                logger.error(f"[{self.state.agent_name}] 工具执行失败: {e}")

        # 3. Observation: 添加观察结果到对话历史
        self.state.add_message("assistant", llm_response)
        self.state.add_message("user", observation or "操作完成")

        # 记录步骤
        step = AgentStep(
            iteration=iteration,
            thought=thought,
            action=action,
            action_input=action_input,
            observation=observation,
            success=success,
            error=error,
        )

        return step

    async def _call_llm(self) -> Tuple[str, int]:
        """调用LLM"""
        messages = self.state.get_conversation_history()

        try:
            response, tokens = await self.llm_call_fn(messages)
            return response, tokens
        except Exception as e:
            logger.error(f"[{self.state.agent_name}] LLM调用失败: {e}")
            # 返回错误响应
            return f"错误: {str(e)}", 0

    def _parse_llm_response(self, response: str) -> Tuple[str, Optional[str], Dict[str, Any]]:
        """
        解析LLM响应

        Returns:
            (thought, action, action_input)
        """
        # 清理响应（移除markdown格式）
        cleaned = response
        cleaned = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned)
        cleaned = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned)
        cleaned = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned)

        # 提取 Thought
        thought_match = re.search(r'Thought:\s*(.*?)(?=Action:|$)', cleaned, re.DOTALL)
        thought = thought_match.group(1).strip() if thought_match else ""

        # 提取 Action
        action_match = re.search(r'Action:\s*(\w+)', cleaned)
        action = action_match.group(1).strip() if action_match else None

        # 提取 Action Input
        action_input = {}
        if action:
            input_match = re.search(r'Action Input:\s*(.*?)(?=Thought:|Observation:|$)', cleaned, re.DOTALL)
            if input_match:
                input_text = input_match.group(1).strip()
                # 移除 markdown 代码块
                input_text = re.sub(r'```json\s*', '', input_text)
                input_text = re.sub(r'```\s*', '', input_text)

                # 解析JSON
                try:
                    action_input = json.loads(input_text)
                except json.JSONDecodeError:
                    # 尝试提取关键信息
                    action_input = {"raw": input_text}

        return thought, action, action_input

    async def _emit_event(self, event_type: str, message: str, **kwargs):
        """发射事件"""
        if self.event_emitter:
            try:
                await self.event_emitter.emit_event(event_type, message, **kwargs)
            except Exception as e:
                logger.warning(f"事件发射失败: {e}")


# ReAct系统提示词模板
REACT_SYSTEM_PROMPT = """你是 {agent_name}，负责代码安全审计。

## 你的角色
你是审计流程的**大脑**，需要自主思考和决策。

## 你可以使用的操作

{tools_description}

## 输出格式
每一步必须严格按照以下格式：

```
Thought: [你的思考过程]
Action: [操作名称]
Action Input: [JSON 格式的参数]
```

## 工作方式
1. **Thought**: 分析当前状态，思考下一步应该做什么
2. **Action**: 选择一个操作并执行
3. **Observation**: 观察结果，然后继续下一步

## 重要原则
- 每一步都要思考，不要机械执行
- 根据观察结果动态调整策略
- 避免重复执行相同的操作
- 当你认为审计足够全面时，选择 finish 操作

现在，基于当前信息开始你的审计工作！
"""


def build_react_system_prompt(agent_name: str, tools: List[Dict[str, Any]]) -> str:
    """
    构建ReAct系统提示词

    Args:
        agent_name: Agent名称
        tools: 可用工具列表

    Returns:
        系统提示词字符串
    """
    # 格式化工具描述
    tools_desc = []
    for tool in tools:
        func = tool.get("function", {})
        name = func.get("name", "")
        desc = func.get("description", "")
        tools_desc.append(f"- **{name}**: {desc}")

    tools_description = "\n".join(tools_desc)

    return REACT_SYSTEM_PROMPT.format(
        agent_name=agent_name,
        tools_description=tools_description
    )
