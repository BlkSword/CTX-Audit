"""
SSE (Server-Sent Events) 流式处理器

支持实时推送 Agent 事件到前端
"""
import json
import asyncio
from typing import AsyncGenerator, Optional, Dict, Any
from loguru import logger
from datetime import datetime, timezone

from app.services.event_manager import event_manager, AgentEventData


class StreamEventType:
    """流式事件类型"""
    # LLM 相关
    LLM_START = "llm_start"
    LLM_THOUGHT = "llm_thought"
    LLM_DECISION = "llm_decision"
    LLM_ACTION = "llm_action"
    LLM_COMPLETE = "llm_complete"

    # 工具调用相关
    TOOL_CALL_START = "tool_call_start"
    TOOL_CALL_END = "tool_call_end"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"

    # 阶段相关
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"

    # 发现相关
    FINDING_NEW = "finding_new"
    FINDING_VERIFIED = "finding_verified"

    # 状态相关
    THINKING = "thinking"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    STATUS = "status"

    # 任务相关
    TASK_START = "task_start"
    TASK_COMPLETE = "task_complete"
    TASK_ERROR = "task_error"
    TASK_CANCEL = "task_cancel"

    # 心跳
    HEARTBEAT = "heartbeat"


class SSEEvent:
    """SSE 事件"""

    def __init__(
        self,
        event_type: str,
        data: Dict[str, Any],
        sequence: int = 0,
    ):
        self.event_type = event_type
        self.data = data
        self.sequence = sequence
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_sse(self) -> str:
        """转换为 SSE 格式"""
        data_with_meta = {
            "type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp,
            "sequence": self.sequence,
        }
        return f"event: {self.event_type}\ndata: {json.dumps(data_with_meta, ensure_ascii=False)}\n\n"


class StreamHandler:
    """
    SSE 流式处理器

    将 Agent 事件转换为 SSE 格式并推送给前端
    """

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.event_queue: Optional[asyncio.Queue] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._is_running = False

    async def stream_events(
        self,
        after_sequence: int = 0,
    ) -> AsyncGenerator[str, None]:
        """
        流式推送事件

        Args:
            after_sequence: 起始序列号

        Yields:
            SSE 格式的事件字符串
        """
        self._is_running = True
        self.event_queue = await event_manager.subscribe(self.task_id, after_sequence)

        # 启动心跳任务
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        logger.info(f"[StreamHandler] Started streaming for task {self.task_id}, after_sequence={after_sequence}")

        try:
            # 发送连接成功事件
            yield SSEEvent(
                event_type="info",
                data={"message": "已连接到审计流"},
                sequence=0,
            ).to_sse()

            # 持续推送事件
            while self._is_running:
                try:
                    # 等待事件（带超时，用于心跳检查）
                    event = await asyncio.wait_for(self.event_queue.get(), timeout=5.0)

                    # 转换为 SSE 格式
                    sse_event = SSEEvent(
                        event_type=event.get("event_type", "info"),
                        data=event,
                        sequence=event.get("sequence", 0),
                    )
                    yield sse_event.to_sse()

                except asyncio.TimeoutError:
                    # 超时是正常的，继续循环
                    continue
                except Exception as e:
                    logger.error(f"[StreamHandler] Error processing event: {e}")
                    yield SSEEvent(
                        event_type="error",
                        data={"message": f"事件处理错误: {str(e)}"},
                        sequence=0,
                    ).to_sse()

        finally:
            await self._cleanup()

    async def _heartbeat_loop(self):
        """心跳循环"""
        while self._is_running:
            try:
                await asyncio.sleep(15)  # 每 15 秒发送心跳
                if self.event_queue:
                    await self.event_queue.put({
                        "event_type": StreamEventType.HEARTBEAT,
                        "sequence": 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[StreamHandler] Heartbeat error: {e}")

    async def _cleanup(self):
        """清理资源"""
        self._is_running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        if self.event_queue:
            await event_manager.unsubscribe(self.task_id, self.event_queue)

        logger.info(f"[StreamHandler] Stopped streaming for task {self.task_id}")

    def stop(self):
        """停止流式推送"""
        self._is_running = False


async def stream_audit_events(
    task_id: str,
    after_sequence: int = 0,
) -> AsyncGenerator[str, None]:
    """
    流式推送审计事件（便捷函数）

    Args:
        task_id: 任务 ID
        after_sequence: 起始序列号

    Yields:
        SSE 格式的事件字符串
    """
    handler = StreamHandler(task_id)
    async for event in handler.stream_events(after_sequence):
        yield event
