"""
Tool Call Loop
基于 OpenAI/Anthropic Tool Calling (Function Calling) 的 Agent 循环

支持流式思考展示和显式 ReAct 格式
"""
from typing import List, Dict, Any, Callable, Optional
import json
import asyncio
from loguru import logger
from datetime import datetime

from app.services.llm.service import LLMService
from app.services.llm.adapters.base import LLMMessage
from app.core.react_parser import extract_thought


class ToolCallLoop:
    """
    基于 Tool Calling 的执行循环

    支持：
    - 流式思考展示
    - 显式 ReAct 格式事件（Thought/Action/Observation）
    - 工具调用追踪
    """

    def __init__(
        self,
        llm: LLMService,
        tools: List[Dict[str, Any]],
        tool_handlers: Dict[str, Callable],
        system_prompt: str,
        max_iterations: int = 15,
        history: Optional[List[Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
        enable_streaming: bool = True,
        react_format: bool = True,  # 新增：是否使用 ReAct 格式
    ):
        self.llm = llm
        self.tools = tools
        self.tool_handlers = tool_handlers
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.history = history or []
        self.event_callback = event_callback
        self.enable_streaming = enable_streaming
        self.react_format = react_format

        # 统计信息
        self.tool_call_count = 0
        self.total_tokens_used = 0

        # 如果历史为空，初始化 system prompt
        if not self.history:
            self.history.append({
                "role": "system",
                "content": self.system_prompt
            })

    async def run(self, user_input: str = None) -> str:
        """
        运行循环

        Args:
            user_input: 用户输入，如果是首次运行可以传入

        Returns:
            最终回复内容
        """
        if user_input:
            self.history.append({
                "role": "user",
                "content": user_input
            })

        iteration = 0
        final_response = ""

        while iteration < self.max_iterations:
            iteration += 1
            logger.info(f"ToolCallLoop Iteration {iteration}/{self.max_iterations}")

            # 1. 调用 LLM（流式或非流式）
            content = ""
            tool_calls = []
            total_tokens = 0

            if self.enable_streaming:
                # 流式调用
                try:
                    # 发送思考开始事件（ReAct 格式）
                    if self.event_callback:
                        try:
                            if self.react_format:
                                await self.event_callback("thought_start", {
                                    "message": "开始思考...",
                                    "iteration": iteration
                                })
                            else:
                                await self.event_callback("thinking_start", {
                                    "message": "开始思考...",
                                    "iteration": iteration
                                })
                        except Exception as e:
                            logger.warning(f"Failed to emit thinking_start event: {e}")

                    # 流式接收响应
                    buffer = ""
                    async for chunk in self.llm.generate_stream_with_tools(
                        messages=self.history,
                        tools=self.tools
                    ):
                        # 文本内容
                        if chunk.content:
                            buffer += chunk.content
                            # 发送思考 token 事件
                            if self.event_callback:
                                try:
                                    if self.react_format:
                                        # ReAct 格式：发送 thought_token
                                        await self.event_callback("thought_token", {
                                            "token": chunk.content,
                                            "accumulated": buffer
                                        })
                                    else:
                                        await self.event_callback("thinking_token", {
                                            "token": chunk.content,
                                            "accumulated": buffer
                                        })
                                except Exception as e:
                                    logger.warning(f"Failed to emit thinking_token event: {e}")

                        # 工具调用
                        if chunk.tool_calls:
                            tool_calls = chunk.tool_calls

                        # 完成
                        if chunk.is_complete:
                            content = buffer
                            break

                    # 发送思考完成事件（ReAct 格式）
                    if self.event_callback:
                        try:
                            # 提取思考内容
                            thought = extract_thought(content) if self.react_format else content

                            if self.react_format:
                                # ReAct 格式事件
                                await self.event_callback("thought_end", {
                                    "thought": thought,
                                    "full_content": content,
                                    "iteration": iteration
                                })
                            else:
                                await self.event_callback("thinking_end", {
                                    "message": "思考完成",
                                    "content": content
                                })
                        except Exception as e:
                            logger.warning(f"Failed to emit thinking_end event: {e}")

                except Exception as e:
                    logger.error(f"LLM streaming failed: {e}")
                    # 降级到非流式
                    response = await self.llm.generate_with_tools(
                        messages=self.history,
                        tools=self.tools
                    )
                    content = response.get("content", "")
                    tool_calls = response.get("tool_calls", [])
                    total_tokens = response.get("usage", {}).get("total_tokens", 0)
            else:
                # 非流式调用
                try:
                    response = await self.llm.generate_with_tools(
                        messages=self.history,
                        tools=self.tools
                    )
                except Exception as e:
                    logger.error(f"LLM generation failed: {e}")
                    raise

                content = response.get("content")
                tool_calls = response.get("tool_calls")
                usage = response.get("usage", {})
                total_tokens = usage.get("total_tokens", 0)

                # 发送思考内容事件（非流式）
                if content and self.event_callback:
                    try:
                        thought = extract_thought(content) if self.react_format else content

                        if self.react_format:
                            # ReAct 格式：发送完整的 thought
                            await self.event_callback("thought", {
                                "thought": thought,
                                "full_content": content
                            })
                        else:
                            await self.event_callback("thinking", {
                                "message": content,
                                "tokens_used": total_tokens
                            })
                    except Exception as e:
                        logger.warning(f"Failed to emit thinking event: {e}")

            # 2. 记录 Assistant 回复
            assistant_msg = {
                "role": "assistant",
                "content": content
            }
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls

            self.history.append(assistant_msg)

            # 3. 如果有内容，更新最终回复
            if content:
                final_response = content

            # 4. 如果没有工具调用，结束循环
            if not tool_calls:
                logger.info("No tool calls, finishing loop")
                break

            # 5. 执行工具调用
            for tool_call in tool_calls:
                function_name = tool_call["function"]["name"]
                arguments_str = tool_call["function"]["arguments"]
                call_id = tool_call["id"]

                try:
                    arguments = json.loads(arguments_str)
                    logger.info(f"Executing tool: {function_name} with args: {arguments}")
                    self.tool_call_count += 1

                    # 发送 Action 事件（ReAct 格式）
                    if self.event_callback:
                        try:
                            if self.react_format:
                                # ReAct 格式：发送 action 事件
                                await self.event_callback("action", {
                                    "action": function_name,
                                    "action_input": arguments,
                                    "iteration": iteration
                                })
                            else:
                                await self.event_callback("tool_call", {
                                    "tool_name": function_name,
                                    "tool_input": arguments,
                                    "message": f"调用工具: {function_name}"
                                })
                        except Exception as e:
                            logger.warning(f"Failed to emit tool_call event: {e}")

                    start_time = datetime.now()

                    if function_name in self.tool_handlers:
                        handler = self.tool_handlers[function_name]
                        if asyncio.iscoroutinefunction(handler):
                            result = await handler(**arguments)
                        else:
                            result = handler(**arguments)
                            # 如果 handler 返回的是 coroutine（例如 lambda 返回 async 函数调用），则 await 它
                            if asyncio.iscoroutine(result):
                                result = await result

                        # 序列化结果
                        if not isinstance(result, str):
                            result = json.dumps(result, ensure_ascii=False)
                    else:
                        result = f"Error: Tool '{function_name}' not found"

                    duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)

                    # 发送 Observation 事件（ReAct 格式）
                    if self.event_callback:
                        try:
                            # 截断过长的结果
                            result_display = result[:2000] + "..." if len(result) > 2000 else result

                            if self.react_format:
                                # ReAct 格式：发送 observation 事件
                                await self.event_callback("observation", {
                                    "action": function_name,
                                    "observation": result_display,
                                    "duration_ms": duration_ms,
                                    "iteration": iteration
                                })
                            else:
                                await self.event_callback("tool_result", {
                                    "tool_name": function_name,
                                    "tool_output": result_display,
                                    "tool_duration_ms": duration_ms,
                                    "message": f"工具 {function_name} 执行完成"
                                })
                        except Exception as e:
                            logger.warning(f"Failed to emit tool_result event: {e}")

                except json.JSONDecodeError:
                    result = f"Error: Invalid JSON arguments for {function_name}"
                except Exception as e:
                    logger.error(f"Tool execution failed: {e}")
                    result = f"Error executing {function_name}: {str(e)}"
                    # 发送错误事件
                    if self.event_callback:
                        try:
                            if self.react_format:
                                await self.event_callback("observation", {
                                    "action": function_name,
                                    "observation": f"错误: {str(e)}",
                                    "error": True,
                                    "iteration": iteration
                                })
                            else:
                                await self.event_callback("error", {
                                    "message": f"工具执行失败: {function_name}",
                                    "error": str(e)
                                })
                        except Exception as e_emit:
                            logger.warning(f"Failed to emit error event: {e_emit}")

                # 6. 记录工具结果
                self.history.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "name": function_name,
                    "content": str(result)
                })

                # 检查是否是审计完成标记
                try:
                    result_obj = json.loads(result) if isinstance(result, str) else result
                    if isinstance(result_obj, dict) and result_obj.get("__audit_complete__"):
                        logger.info("Audit completion signal received, finishing loop")
                        final_response = result_obj.get("summary", "审计已完成")
                        # 继续让循环自然结束，不再发起更多 LLM 调用
                        iteration = self.max_iterations  # 强制退出循环
                except (json.JSONDecodeError, TypeError):
                    pass  # 不是 JSON，继续正常流程

        return final_response

    def get_stats(self) -> Dict[str, Any]:
        """获取执行统计信息"""
        return {
            "tool_call_count": self.tool_call_count,
            "total_tokens_used": self.total_tokens_used,
            "iterations": len([h for h in self.history if h["role"] == "assistant"]),
        }
