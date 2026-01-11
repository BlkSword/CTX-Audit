"""
Agent 事件管理器

负责事件的创建、存储和推送
支持 SSE (Server-Sent Events) 实时流式推送
集成 EventPersistence 实现数据库持久化
"""
import asyncio
import json
import logging
from typing import Optional, Dict, Any, List, Set
from datetime import datetime, timezone
from dataclasses import dataclass, field
from loguru import logger
from collections import deque
import uuid
import time
import re

logger = logging.getLogger(__name__)

# 需要节流的事件类型（高频率事件）
THROTTLED_EVENT_TYPES = {
    'thinking', 'llm_thought', 'thinking_token'
}

# 需要批处理的事件类型
BATCHABLE_EVENT_TYPES = {
    'thinking', 'llm_thought'
}

# 批处理配置
BATCH_MAX_SIZE = 10  # 最大批处理数量
BATCH_MAX_WAIT_MS = 100  # 最大等待时间（毫秒）
THROTTLE_INTERVAL_MS = 50  # 节流间隔（毫秒）

# UTF-8 无效字符清理模式
INVALID_UTF8_PATTERN = re.compile(r'[^\x00-\x7F\x80-\xFF\u0100-\uFFFF]')


def _clean_utf8(text: str) -> str:
    """清理字符串中的无效 UTF-8 字符"""
    if not isinstance(text, str):
        return text
    # 移除控制字符（保留换行、制表符）
    cleaned = INVALID_UTF8_PATTERN.sub('', text)
    # 进一步清理控制字符
    cleaned = ''.join(char for char in cleaned if char == '\n' or char == '\t' or not (ord(char) < 32))
    return cleaned


def _sanitize_event_data(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """递归清理事件数据中的无效 UTF-8 字符"""
    cleaned = {}
    for key, value in event_data.items():
        if isinstance(value, str):
            cleaned[key] = _clean_utf8(value)
        elif isinstance(value, dict):
            cleaned[key] = _sanitize_event_data(value)
        elif isinstance(value, list):
            cleaned[key] = [_sanitize_event_data(item) if isinstance(item, dict) else _clean_utf8(item) if isinstance(item, str) else item for item in value]
        else:
            cleaned[key] = value
    return cleaned


@dataclass
class AgentEventData:
    """Agent 事件数据"""
    event_type: str
    phase: Optional[str] = None
    message: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[Dict[str, Any]] = None
    tool_duration_ms: Optional[int] = None
    finding_id: Optional[str] = None
    tokens_used: int = 0
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(uuid.uuid4()),
            "event_type": self.event_type,
            "phase": self.phase,
            "message": self.message,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "tool_output": self.tool_output,
            "tool_duration_ms": self.tool_duration_ms,
            "finding_id": self.finding_id,
            "tokens_used": self.tokens_used,
            "metadata": self.metadata,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


class AgentEventEmitter:
    """
    Agent 事件发射器
    用于在 Agent 执行过程中发射事件
    """

    def __init__(self, task_id: str, event_manager: 'EventManager'):
        self.task_id = task_id
        self.event_manager = event_manager
        self._sequence = 0
        self._current_phase = None

    async def emit(self, event_data: AgentEventData):
        """发射事件"""
        self._sequence += 1
        event_data.phase = event_data.phase or self._current_phase

        await self.event_manager.add_event(
            task_id=self.task_id,
            sequence=self._sequence,
            **event_data.to_dict()
        )

    async def emit_phase_start(self, phase: str, message: Optional[str] = None):
        """发射阶段开始事件"""
        self._current_phase = phase
        await self.emit(AgentEventData(
            event_type="phase_start",
            phase=phase,
            message=message or f"开始 {phase} 阶段",
        ))

    async def emit_phase_complete(self, phase: str, message: Optional[str] = None):
        """发射阶段完成事件"""
        await self.emit(AgentEventData(
            event_type="phase_complete",
            phase=phase,
            message=message or f"{phase} 阶段完成",
        ))

    async def emit_thinking(self, message: str, metadata: Optional[Dict] = None):
        """发射思考事件"""
        await self.emit(AgentEventData(
            event_type="thinking",
            message=message,
            metadata=metadata,
        ))

    async def emit_llm_thought(self, thought: str, iteration: int = 0):
        """发射 LLM 思考内容事件"""
        display = thought[:500] + "..." if len(thought) > 500 else thought
        await self.emit(AgentEventData(
            event_type="llm_thought",
            message=f"💭 {display}",
            metadata={"thought": thought, "iteration": iteration},
        ))

    async def emit_llm_decision(self, decision: str, reason: str = ""):
        """发射 LLM 决策事件"""
        await self.emit(AgentEventData(
            event_type="llm_decision",
            message=f"💡 {decision}" + (f" ({reason})" if reason else ""),
            metadata={"decision": decision, "reason": reason},
        ))

    async def emit_llm_action(self, action: str, action_input: Dict):
        """发射 LLM 动作事件"""
        input_str = json.dumps(action_input, ensure_ascii=False)[:200]
        await self.emit(AgentEventData(
            event_type="llm_action",
            message=f"⚡ {action}\n   参数: {input_str}",
            metadata={"action": action, "action_input": action_input},
        ))

    async def emit_tool_call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        message: Optional[str] = None,
    ):
        """发射工具调用事件"""
        await self.emit(AgentEventData(
            event_type="tool_call",
            tool_name=tool_name,
            tool_input=tool_input,
            message=message or f"调用工具: {tool_name}",
        ))

    async def emit_tool_result(
        self,
        tool_name: str,
        tool_output: Any,
        duration_ms: int,
        message: Optional[str] = None,
    ):
        """发射工具结果事件"""
        # 处理输出，确保可序列化
        if hasattr(tool_output, 'to_dict'):
            output_data = tool_output.to_dict()
        elif isinstance(tool_output, str):
            output_data = {"result": tool_output[:2000]}
        else:
            output_data = {"result": str(tool_output)[:2000]}

        await self.emit(AgentEventData(
            event_type="tool_result",
            tool_name=tool_name,
            tool_output=output_data,
            tool_duration_ms=duration_ms,
            message=message or f"工具 {tool_name} 执行完成 ({duration_ms}ms)",
        ))

    async def emit_finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        vulnerability_type: str,
        is_verified: bool = False,
    ):
        """发射漏洞发现事件"""
        event_type = "finding_verified" if is_verified else "finding_new"
        await self.emit(AgentEventData(
            event_type=event_type,
            finding_id=finding_id,
            message=f"{'✅ 已验证' if is_verified else '🔍 新发现'}: [{severity.upper()}] {title}",
            metadata={
                "id": finding_id,
                "title": title,
                "severity": severity,
                "vulnerability_type": vulnerability_type,
                "is_verified": is_verified,
            },
        ))

    async def emit_info(self, message: str, metadata: Optional[Dict] = None):
        """发射信息事件"""
        await self.emit(AgentEventData(
            event_type="info",
            message=message,
            metadata=metadata,
        ))

    async def emit_warning(self, message: str, metadata: Optional[Dict] = None):
        """发射警告事件"""
        await self.emit(AgentEventData(
            event_type="warning",
            message=message,
            metadata=metadata,
        ))

    async def emit_error(self, message: str, metadata: Optional[Dict] = None):
        """发射错误事件"""
        await self.emit(AgentEventData(
            event_type="error",
            message=message,
            metadata=metadata,
        ))

    async def emit_status(self, status: str, message: Optional[str] = None):
        """发射状态更新事件"""
        await self.emit(AgentEventData(
            event_type="status",
            message=message or f"状态更新: {status}",
            metadata={"status": status},
        ))

    async def emit_complete(
        self,
        summary: str,
        findings_count: int,
        security_score: Optional[float] = None,
    ):
        """发射任务完成事件"""
        await self.emit(AgentEventData(
            event_type="task_complete",
            message=summary,
            metadata={
                "findings_count": findings_count,
                "security_score": security_score,
            },
        ))


class EventManager:
    """
    事件管理器

    管理 Agent 事件的存储和流式推送
    支持事件批处理和节流优化
    集成 EventPersistence 实现数据库持久化
    """

    def __init__(self, persistence=None):
        """
        初始化事件管理器

        Args:
            persistence: EventPersistence 实例（可选，默认使用全局单例）
        """
        # 延迟导入避免循环依赖
        from app.services.event_persistence import get_event_persistence

        # 每个任务的事件队列
        self._event_queues: Dict[str, deque] = {}
        # 每个任务的订阅者
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        # 持久化的事件（用于历史查询）- 现在仅作为内存缓存
        self._persistent_events: Dict[str, List[Dict]] = {}
        # 每个 task 的序列号
        self._sequences: Dict[str, int] = {}
        self._lock = asyncio.Lock()

        # 性能优化相关
        self._last_emit_time: Dict[str, Dict[str, float]] = {}  # {task_id: {event_type: timestamp}}
        self._batch_buffers: Dict[str, List[Dict]] = {}  # {task_id: [events]}
        self._batch_tasks: Dict[str, asyncio.Task] = {}  # {task_id: task}
        self._dedup_cache: Dict[str, Set[str]] = {}  # {task_id: set(event_ids)}

        # 数据库持久化服务
        self._persistence = persistence or get_event_persistence()
        logger.info("[EventManager] 初始化完成，已集成数据库持久化")

    def create_queue(self, task_id: str, max_size: int = 1000):
        """创建任务事件队列"""
        if task_id not in self._event_queues:
            self._event_queues[task_id] = deque(maxlen=max_size)
            self._subscribers[task_id] = []
            self._persistent_events[task_id] = []
            self._sequences[task_id] = 0
            # 初始化性能优化数据结构
            self._last_emit_time[task_id] = {}
            self._batch_buffers[task_id] = []
            self._dedup_cache[task_id] = set()
            logger.info(f"[EventManager] Created event queue for task {task_id}")

    def _should_throttle(self, task_id: str, event_type: str) -> bool:
        """检查事件是否应该被节流"""
        if event_type not in THROTTLED_EVENT_TYPES:
            return False

        now = time.time()
        last_time = self._last_emit_time.get(task_id, {}).get(event_type, 0)
        time_since_last = (now - last_time) * 1000  # 转换为毫秒

        if time_since_last < THROTTLE_INTERVAL_MS:
            return True
        return False

    async def _flush_batch(self, task_id: str):
        """刷新批处理缓冲区"""
        if task_id not in self._batch_buffers:
            return

        buffer = self._batch_buffers[task_id]
        if not buffer:
            return

        # 批量推送事件
        for event in buffer:
            await self._push_to_subscribers(task_id, event)

        self._batch_buffers[task_id] = []
        logger.debug(f"[EventManager] Flushed batch for {task_id}, size: {len(buffer)}")

    async def _push_to_subscribers(self, task_id: str, event: Dict):
        """推送事件到订阅者"""
        for queue in self._subscribers.get(task_id, []):
            try:
                await queue.put(event)
            except Exception as e:
                logger.warning(f"[EventManager] Failed to push event to subscriber: {e}")

    async def add_event(self, task_id: str, sequence: int = 0, **event_data):
        """
        添加事件到队列（支持节流和批处理）

        Args:
            task_id: 任务 ID
            sequence: 序列号（0 表示自动分配）
            **event_data: 事件数据
        """
        event_type = event_data.get("event_type", "")

        # 检查是否需要节流
        if self._should_throttle(task_id, event_type):
            logger.debug(f"[EventManager] Throttled event {event_type} for {task_id}")
            return  # 跳过此事件

        async with self._lock:
            if task_id not in self._event_queues:
                self.create_queue(task_id)

            # 如果 sequence 为 0，自动分配下一个序列号
            if sequence == 0:
                self._sequences[task_id] += 1
                sequence = self._sequences[task_id]
            else:
                # 更新序列号
                if sequence > self._sequences[task_id]:
                    self._sequences[task_id] = sequence

            # 更新最后发送时间
            self._last_emit_time[task_id][event_type] = time.time()

            # 去重检查
            event_id = event_data.get("id", str(uuid.uuid4()))
            if event_id in self._dedup_cache.get(task_id, set()):
                logger.debug(f"[EventManager] Duplicated event {event_id} for {task_id}")
                return

            # 添加到队列
            event = {
                "id": event_id,
                "task_id": task_id,
                "sequence": sequence,
                **event_data
            }

            # 清理无效 UTF-8 字符
            try:
                event = _sanitize_event_data(event)
            except Exception as e:
                logger.warning(f"[EventManager] 清理事件数据失败: {e}")

            self._event_queues[task_id].append(event)
            self._persistent_events[task_id].append(event)
            self._dedup_cache[task_id].add(event_id)

            # 异步保存到数据库（不阻塞）
            try:
                # 准备持久化数据
                persistence_event = {
                    "id": event.get("id"),
                    "audit_id": task_id,  # task_id 在持久化层作为 audit_id
                    "agent_type": event.get("agent_type", "unknown"),
                    "event_type": event.get("event_type"),
                    "sequence": sequence,
                    "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "message": event.get("message"),
                    "data": event,  # 存储完整事件数据
                }
                asyncio.create_task(self._persistence.save_event(persistence_event))
            except Exception as e:
                logger.warning(f"[EventManager] 异步保存事件到数据库失败: {e}")

            # 批处理逻辑
            if event_type in BATCHABLE_EVENT_TYPES:
                # 添加到批处理缓冲区
                self._batch_buffers[task_id].append(event)

                # 检查是否需要刷新批处理
                buffer_size = len(self._batch_buffers[task_id])
                if buffer_size >= BATCH_MAX_SIZE:
                    await self._flush_batch(task_id)
                elif buffer_size == 1:
                    # 创建自动刷新任务
                    if task_id in self._batch_tasks:
                        self._batch_tasks[task_id].cancel()

                    async def flush_after_delay():
                        await asyncio.sleep(BATCH_MAX_WAIT_MS / 1000)
                        await self._flush_batch(task_id)

                    self._batch_tasks[task_id] = asyncio.create_task(flush_after_delay())
            else:
                # 非批处理事件直接推送
                await self._push_to_subscribers(task_id, event)

    async def subscribe(self, task_id: str, after_sequence: int = 0) -> asyncio.Queue:
        """
        订阅任务事件流

        Args:
            task_id: 任务 ID
            after_sequence: 从哪个序列号开始

        Returns:
            事件队列
        """
        async with self._lock:
            if task_id not in self._event_queues:
                self.create_queue(task_id)

            queue = asyncio.Queue()
            self._subscribers[task_id].append(queue)

            # 发送历史事件（如果指定了 after_sequence）
            if after_sequence > 0:
                # 先从内存缓存获取
                for event in self._persistent_events.get(task_id, []):
                    if event.get("sequence", 0) > after_sequence:
                        await queue.put(event)

                # 如果内存中没有足够的事件，从数据库获取
                latest_mem_sequence = max(
                    [e.get("sequence", 0) for e in self._persistent_events.get(task_id, [])],
                    default=0
                )
                if latest_mem_sequence < after_sequence:
                    try:
                        # 从数据库查询更早的事件
                        db_events = self._persistence.get_events(
                            audit_id=task_id,
                            after_sequence=after_sequence,
                            limit=1000
                        )
                        # 发送数据库中的事件（只发送不在内存中的）
                        for event in db_events:
                            if event.get("sequence", 0) > latest_mem_sequence:
                                # 从 data 字段中恢复完整事件
                                full_event = event.get("data", event)
                                await queue.put(full_event)
                        logger.info(f"[EventManager] 从数据库加载了 {len(db_events)} 个历史事件")
                    except Exception as e:
                        logger.warning(f"[EventManager] 从数据库加载历史事件失败: {e}")

            logger.info(f"[EventManager] New subscriber for task {task_id}, after_sequence={after_sequence}")
            return queue

    async def unsubscribe(self, task_id: str, queue: asyncio.Queue):
        """取消订阅"""
        async with self._lock:
            if task_id in self._subscribers:
                if queue in self._subscribers[task_id]:
                    self._subscribers[task_id].remove(queue)
                    logger.info(f"[EventManager] Unsubscribed from task {task_id}")

    def get_events(self, task_id: str, after_sequence: int = 0, limit: int = 100) -> List[Dict]:
        """
        获取历史事件

        Args:
            task_id: 任务 ID
            after_sequence: 起始序列号
            limit: 最大数量

        Returns:
            事件列表
        """
        # 先尝试从内存缓存获取
        mem_events = self._persistent_events.get(task_id, [])
        mem_filtered = [e for e in mem_events if e.get("sequence", 0) > after_sequence]

        # 如果内存中有足够的事件，直接返回
        if len(mem_filtered) >= limit:
            return mem_filtered[-limit:]

        # 否则从数据库补充
        try:
            latest_mem_seq = max([e.get("sequence", 0) for e in mem_events], default=0)
            db_events = self._persistence.get_events(
                audit_id=task_id,
                after_sequence=max(after_sequence, latest_mem_seq),
                limit=limit
            )

            # 合并内存和数据库的事件
            all_events = mem_filtered.copy()
            seen_sequences = {e.get("sequence") for e in mem_filtered}

            for db_event in db_events:
                seq = db_event.get("sequence")
                if seq not in seen_sequences:
                    # 从 data 字段中恢复完整事件
                    full_event = db_event.get("data", db_event)
                    all_events.append(full_event)
                    seen_sequences.add(seq)

            # 按序列号排序并返回最后 limit 个
            all_events.sort(key=lambda e: e.get("sequence", 0))
            return all_events[-limit:]

        except Exception as e:
            logger.warning(f"[EventManager] 从数据库获取事件失败: {e}，返回内存缓存")
            return mem_filtered[-limit:]

    def get_latest_sequence(self, task_id: str) -> int:
        """获取最新序列号"""
        # 先从内存获取
        mem_sequence = self._sequences.get(task_id, 0)

        # 如果内存中没有，尝试从数据库获取
        if mem_sequence == 0:
            try:
                db_sequence = self._persistence.get_latest_sequence(audit_id=task_id)
                if db_sequence > 0:
                    logger.debug(f"[EventManager] 从数据库获取最新序列号: {db_sequence}")
                    return db_sequence
            except Exception as e:
                logger.warning(f"[EventManager] 从数据库获取序列号失败: {e}")

        return mem_sequence

    def cleanup(self, task_id: str):
        """清理任务事件"""
        if task_id in self._event_queues:
            del self._event_queues[task_id]
        if task_id in self._subscribers:
            del self._subscribers[task_id]
        if task_id in self._persistent_events:
            del self._persistent_events[task_id]
        if task_id in self._sequences:
            del self._sequences[task_id]
        # 清理性能优化数据结构
        if task_id in self._last_emit_time:
            del self._last_emit_time[task_id]
        if task_id in self._batch_buffers:
            del self._batch_buffers[task_id]
        if task_id in self._batch_tasks:
            self._batch_tasks[task_id].cancel()
            del self._batch_tasks[task_id]
        if task_id in self._dedup_cache:
            del self._dedup_cache[task_id]
        logger.info(f"[EventManager] Cleaned up task {task_id}")


# 全局事件管理器实例
event_manager = EventManager()
