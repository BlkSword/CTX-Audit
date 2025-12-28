"""
健康检查 API
"""
from fastapi import APIRouter, status
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    """健康检查响应"""
    status: str
    version: str
    service: str


@router.get("", response_model=HealthResponse, status_code=status.HTTP_200_OK)
@router.get("/", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health_check():
    """基础健康检查"""
    from app.config import settings

    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        service=settings.APP_NAME,
    )


@router.get("/detailed", status_code=status.HTTP_200_OK)
async def detailed_health_check():
    """详细健康检查（检查各服务连接状态）"""
    from app.config import settings

    # 检查数据库连接
    db_status = "unknown"
    try:
        from app.services.database import check_database
        db_status = "up" if await check_database() else "down"
    except Exception as e:
        db_status = f"error: {str(e)}"

    # 检查向量数据库
    chroma_status = "unknown"
    try:
        from app.services.vector_store import check_vector_store
        chroma_status = "up" if await check_vector_store() else "down"
    except Exception as e:
        chroma_status = f"error: {str(e)}"

    # 检查 Redis
    redis_status = "unknown"
    try:
        from app.services.queue import check_redis
        redis_status = "up" if await check_redis() else "down"
    except Exception as e:
        redis_status = f"error: {str(e)}"

    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "service": settings.APP_NAME,
        "services": {
            "postgres": db_status,
            "chromadb": chroma_status,
            "redis": redis_status,
        },
    }
