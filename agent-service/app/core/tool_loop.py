"""
Tool Call Loop
基于 OpenAI/Anthropic Tool Calling (Function Calling) 的 Agent 循环
"""
from typing import List, Dict, Any, Callable, Optional, Union
import json
import asyncio
from loguru import logger
from datetime import datetime

from app.services.llm.service import LLMService
from app.services.llm.adapters.base import LLMMessage

class ToolCallLoop:
    """
    基于 Tool Calling 的执行循环
    """

    def __init__(
        self,
        llm: LLMService,
        tools: List[Dict[str, Any]],
        tool_handlers: Dict[str, Callable],
        system_prompt: str,
        max_iterations: int = 15,
        history: Optional[List[Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], Any]] = None
    ):
        self.llm = llm
        self.tools = tools
        self.tool_handlers = tool_handlers
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.history = history or []
        self.event_callback = event_callback
        
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

            # 1. 调用 LLM
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
            
            # 记录 Assistant 回复
            assistant_msg = {
                "role": "assistant",
                "content": content
            }
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            
            self.history.append(assistant_msg)
            
            # 如果有内容，更新最终回复
            if content:
                final_response = content
                # 发送思考内容事件
                if self.event_callback:
                    try:
                        await self.event_callback("thinking", {
                            "message": content,
                            "tokens_used": total_tokens
                        })
                    except Exception as e:
                        logger.warning(f"Failed to emit thinking event: {e}")

            # 2. 如果没有工具调用，结束循环
            if not tool_calls:
                logger.info("No tool calls, finishing loop")
                break

            # 3. 执行工具调用
            for tool_call in tool_calls:
                function_name = tool_call["function"]["name"]
                arguments_str = tool_call["function"]["arguments"]
                call_id = tool_call["id"]
                
                try:
                    arguments = json.loads(arguments_str)
                    logger.info(f"Executing tool: {function_name} with args: {arguments}")
                    
                    # 发送工具调用开始事件
                    if self.event_callback:
                        try:
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

                    # 发送工具结果事件
                    if self.event_callback:
                        try:
                            await self.event_callback("tool_result", {
                                "tool_name": function_name,
                                "tool_output": result,
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
                            await self.event_callback("error", {
                                "message": f"工具执行失败: {function_name}",
                                "error": str(e)
                            })
                        except Exception as e_emit:
                            logger.warning(f"Failed to emit error event: {e_emit}")

                # 4. 记录工具结果
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
