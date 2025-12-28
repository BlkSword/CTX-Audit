"""
消息队列服务

Redis 连接和消息队列操作
"""
from typing import Optional, Any, List
from loguru import logger
import redis.asyncio as redis

from app.config import settings

# 全局 Redis 客户端
_redis_client: Optional[redis.Redis] = None


async def init_redis():
    """初始化 Redis 连接"""
    global _redis_client

    if _redis_client is not None:
        return

    try:
        _redis_client = redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        # 测试连接
        await _redis_client.ping()
        logger.info("Redis 连接初始化成功")
    except Exception as e:
        logger.error(f"Redis 连接失败: {e}")
        # 不抛出异常，允许在没有 Redis 的情况下运行
        _redis_client = None


async def close_redis():
    """关闭 Redis 连接"""
    global _redis_client

    if _redis_client:
        await _redis_client.close()
        _redis_client = None
        logger.info("Redis 连接已关闭")


async def check_redis() -> bool:
    """检查 Redis 连接状态"""
    if not _redis_client:
        return False

    try:
        await _redis_client.ping()
        return True
    except Exception:
        return False


def get_client() -> Optional[redis.Redis]:
    """获取 Redis 客户端"""
    return _redis_client


# ========== 队列操作函数 ==========

async def push_task(queue_name: str, task_data: dict) -> None:
    """
    推送任务到队列

    Args:
        queue_name: 队列名称
        task_data: 任务数据（字典）
    """
    client = get_client()
    if not client:
        logger.warning("Redis 未连接，跳过任务推送")
        return

    try:
        import json
        await client.lpush(queue_name, json.dumps(task_data))
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
    client = get_client()
    if not client:
        return None

    try:
        import json
        result = await client.brpop(queue_name, timeout=timeout)
        if result:
            _, data = result
            return json.loads(data)
        return None
    except Exception as e:
        logger.error(f"弹出任务失败: {e}")
        return None


async def get_queue_size(queue_name: str) -> int:
    """获取队列长度"""
    client = get_client()
    if not client:
        return 0

    try:
        return await client.llen(queue_name)
    except Exception:
        return 0


# ========== 缓存操作函数 ==========

async def set_cache(key: str, value: Any, ttl: int = 3600) -> None:
    """
    设置缓存

    Args:
        key: 缓存键
        value: 缓存值
        ttl: 过期时间（秒）
    """
    client = get_client()
    if not client:
        return

    try:
        import json
        await client.setex(key, ttl, json.dumps(value))
    except Exception as e:
        logger.error(f"设置缓存失败: {e}")


async def get_cache(key: str) -> Optional[Any]:
    """
    获取缓存

    Args:
        key: 缓存键

    Returns:
        缓存值，不存在返回 None
    """
    client = get_client()
    if not client:
        return None

    try:
        import json
        data = await client.get(key)
        if data:
            return json.loads(data)
        return None
    except Exception as e:
        logger.error(f"获取缓存失败: {e}")
        return None


async def delete_cache(key: str) -> None:
    """删除缓存"""
    client = get_client()
    if not client:
        return

    try:
        await client.delete(key)
    except Exception as e:
        logger.error(f"删除缓存失败: {e}")


# ========== 发布订阅 ==========

async def publish_event(channel: str, event_data: dict) -> None:
    """
    发布事件

    Args:
        channel: 频道名称
        event_data: 事件数据
    """
    client = get_client()
    if not client:
        return

    try:
        import json
        await client.publish(channel, json.dumps(event_data))
        logger.debug(f"事件发布到频道 {channel}")
    except Exception as e:
        logger.error(f"发布事件失败: {e}")


async def subscribe(channel: str) -> Any:
    """
    订阅频道

    Args:
        channel: 频道名称

    Returns:
        订阅对象
    """
    client = get_client()
    if not client:
        return None

    try:
        pubsub = client.pubsub()
        await pubsub.subscribe(channel)
        return pubsub
    except Exception as e:
        logger.error(f"订阅频道失败: {e}")
        return None
