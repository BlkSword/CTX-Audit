"""
Agent 管理和可视化 API

提供 Agent 注册表、图结构和消息历史的查询接口
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.core.agent_registry import agent_registry
from app.core.graph_controller import agent_graph_controller
from app.core.message import message_bus

router = APIRouter()


# ========== 请求/响应模型 ==========

class AgentCreateRequest(BaseModel):
    """创建 Agent 请求"""
    agent_type: str
    task: str
    parent_id: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class AgentCreateResponse(BaseModel):
    """创建 Agent 响应"""
    agent_id: str
    status: str


class MessageSendRequest(BaseModel):
    """发送消息请求"""
    from_agent: str
    target_agent_id: str
    content: str
    data: Optional[Dict[str, Any]] = None


class MessageBroadcastRequest(BaseModel):
    """广播消息请求"""
    from_agent: str
    content: str
    recipient_type: Optional[str] = None


# ========== API 端点 ==========

@router.get("/tree")
async def get_agent_tree(root_id: Optional[str] = None) -> Dict[str, Any]:
    """
    获取 Agent 树结构

    Args:
        root_id: 根节点 Agent ID，如果为 None 则自动查找
    """
    tree = await agent_graph_controller.get_agent_graph(current_agent_id=root_id)
    return tree


@router.get("/list")
async def list_agents(
    agent_type: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    列出所有 Agent

    Args:
        agent_type: 按 Agent 类型过滤
        status: 按状态过滤
    """
    agents = await agent_graph_controller.list_agents_by_type(
        agent_type=agent_type,
        status=status,
    )
    return agents


@router.get("/{agent_id}")
async def get_agent_info(agent_id: str) -> Dict[str, Any]:
    """获取单个 Agent 的详细信息"""
    agent_info = await agent_graph_controller.get_agent_status(agent_id)

    if not agent_info:
        raise HTTPException(status_code=404, detail=f"Agent not found: {agent_id}")

    return agent_info


@router.post("/create", response_model=AgentCreateResponse)
async def create_agent(request: AgentCreateRequest):
    """
    创建新 Agent

    用于动态创建特定类型的 Agent 实例
    """
    try:
        agent_id = await agent_graph_controller.create_agent(
            agent_type=request.agent_type,
            task=request.task,
            parent_id=request.parent_id,
            config=request.config,
        )
        return AgentCreateResponse(agent_id=agent_id, status="created")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create agent: {str(e)}")


@router.post("/{agent_id}/stop")
async def stop_agent(agent_id: str, stop_children: bool = True) -> Dict[str, Any]:
    """
    停止 Agent

    Args:
        agent_id: Agent ID
        stop_children: 是否同时停止子 Agent
    """
    result = await agent_graph_controller.stop_agent(
        agent_id=agent_id,
        stop_children=stop_children,
    )

    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])

    return result


@router.get("/statistics/overview")
async def get_agent_statistics() -> Dict[str, Any]:
    """获取 Agent 统计信息"""
    stats = await agent_graph_controller.get_statistics()
    return stats


@router.post("/message/send")
async def send_message_to_agent(request: MessageSendRequest):
    """
    向指定 Agent 发送消息

    通过消息总线向目标 Agent 发送消息
    """
    from app.core.message import MessageType, MessagePriority

    result = await agent_graph_controller.send_message_to_agent(
        from_agent=request.from_agent,
        target_agent_id=request.target_agent_id,
        message={"content": request.content, "data": request.data},
        message_type=MessageType.INFORMATION,
        priority=MessagePriority.NORMAL,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.post("/message/broadcast")
async def broadcast_message(request: MessageBroadcastRequest):
    """
    广播消息到多个 Agent

    Args:
        from_agent: 发送者 Agent ID
        content: 消息内容
        recipient_type: 接收者类型过滤
    """
    count = await agent_graph_controller.broadcast_message(
        from_agent=request.from_agent,
        message={"content": request.content},
        recipient_type=request.recipient_type,
    )

    return {"recipients_count": count}


@router.get("/message/history")
async def get_message_history(
    agent_id: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """
    获取消息历史

    Args:
        agent_id: 过滤特定 Agent 的消息
        limit: 返回数量限制
    """
    history = message_bus.get_message_history(agent_id=agent_id, limit=limit)
    return history


@router.get("/message/queue-sizes")
async def get_queue_sizes() -> Dict[str, int]:
    """获取各 Agent 的消息队列大小"""
    return message_bus.get_queue_sizes()
