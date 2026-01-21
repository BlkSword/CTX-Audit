"""
消息队列服务（内存版本）

使用 asyncio.Queue 实现内存队列，无需 Redis
"""
from typing import Optional, Any, Dict
from loguru import logger
import asyncio

# 全局队列存储
_queues: Dict[str, asyncio.Queue] = {}
_cache: Dict[str, Any] = {}


async def init_redis():
    """初始化队列服务（兼容接口）"""
    logger.info("内存队列服务初始化成功")


async def close_redis():
    """关闭队列服务（兼容接口）"""
    global _queues, _cache
    _queues.clear()
    _cache.clear()
    logger.info("内存队列服务已关闭")


async def check_redis() -> bool:
    """检查队列服务状态（兼容接口）"""
    return True


def get_client():
    """获取客户端（兼容接口，返回 None）"""
    return None


# ========== 队列操作函数 ==========

async def push_task(queue_name: str, task_data: dict) -> None:
    """
    推送任务到队列

    Args:
        queue_name: 队列名称
        task_data: 任务数据（字典）
    """
    global _queues

    if queue_name not in _queues:
        _queues[queue_name] = asyncio.Queue()

    try:
        await _queues[queue_name].put(task_data)
        logger.debug(f"任务推送到队列 {queue_name}")
    except Exception as e:
        logger.error(f"推送任务失败: {e}")


async def pop_task(queue_name: str, timeout: int = 5) -> Optional[dict]:
    """
    从队列弹出任务（阻塞）

    Args:
        queue_name: 队列名称
        timeout: 超时时间（秒）

    Returns:
        任务数据字典，超时返回 None
    """
    global _queues

    if queue_name not in _queues:
        _queues[queue_name] = asyncio.Queue()

    try:
        # 使用 asyncio.wait_for 实现超时
        task_data = await asyncio.wait_for(
            _queues[queue_name].get(),
            timeout=timeout
        )
        return task_data
    except asyncio.TimeoutError:
        return None
    except Exception as e:
        logger.error(f"弹出任务失败: {e}")
        return None


async def get_queue_size(queue_name: str) -> int:
    """获取队列长度"""
    global _queues

    if queue_name not in _queues:
        return 0

    try:
        return _queues[queue_name].qsize()
    except Exception:
        return 0


# ========== 缓存操作函数 ==========

async def set_cache(key: str, value: Any, ttl: int = 3600) -> None:
    """
    设置缓存

    Args:
        key: 缓存键
        value: 缓存值
        ttl: 过期时间（秒）- 注意：内存版本不支持 TTL
    """
    global _cache

    _cache[key] = value
    if ttl > 0:
        # 使用 asyncio 创建 TTL
        async def _expire():
            await asyncio.sleep(ttl)
            if key in _cache:
                del _cache[key]

        asyncio.create_task(_expire())


async def get_cache(key: str) -> Optional[Any]:
    """
    获取缓存

    Args:
        key: 缓存键

    Returns:
        缓存值，不存在返回 None
    """
    global _cache
    return _cache.get(key)


async def delete_cache(key: str) -> None:
    """删除缓存"""
    global _cache
    _cache.pop(key, None)


# ========== 发布订阅（简化版本） ==========

_subscribers: Dict[str, list] = {}


async def publish_event(channel: str, event_data: dict) -> None:
    """
    发布事件

    Args:
        channel: 频道名称
        event_data: 事件数据
    """
    global _subscribers

    if channel in _subscribers:
        for callback in _subscribers[channel]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event_data)
                else:
                    callback(event_data)
            except Exception as e:
                logger.error(f"事件回调失败: {e}")

    logger.debug(f"事件发布到频道 {channel}")


async def subscribe(channel: str, callback) -> None:
    """
    订阅频道

    Args:
        channel: 频道名称
        callback: 回调函数
    """
    global _subscribers

    if channel not in _subscribers:
        _subscribers[channel] = []

    _subscribers[channel].append(callback)
    logger.debug(f"已订阅频道 {channel}")
