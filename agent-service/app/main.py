"""
CTX-Audit Agent Service 主应用入口

Multi-Agent 代码审计系统的 FastAPI 服务
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.config import settings


def create_app() -> FastAPI:
    """创建 FastAPI 应用实例"""

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Multi-Agent 代码审计系统 - 智能漏洞检测与分析服务",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # 配置 CORS - 允许所有本地开发源
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # 开发环境允许所有源
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=3600,
    )

    # 注册路由
    _register_routes(app)

    # 注册生命周期事件
    _register_lifecycle(app)

    return app


def _register_routes(app: FastAPI) -> None:
    """注册所有路由"""
    from app.api import audit, agents, health, llm, prompts, settings

    app.include_router(health.router, prefix="/health", tags=["Health"])
    app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
    app.include_router(llm.router, prefix="/api/llm", tags=["LLM"])
    app.include_router(prompts.router, prefix="/api/prompts", tags=["Prompts"])
    app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
    app.include_router(settings.router, prefix="/api/settings", tags=["Settings"])

    logger.info("API 路由注册完成")


def _register_lifecycle(app: FastAPI) -> None:
    """注册应用生命周期事件"""

    @app.on_event("startup")
    async def on_startup():
        """应用启动时的初始化"""
        logger.info(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} 启动中...")
        logger.info(f"LLM Provider: {settings.LLM_PROVIDER}")
        logger.info(f"LLM Model: {settings.LLM_MODEL}")

        # 初始化事件总线（V2）- 核心功能，必须
        try:
            from app.services.event_bus_v2 import init_event_bus
            await init_event_bus()
            logger.info("✅ 事件总线 V2 初始化完成")
        except Exception as e:
            logger.error(f"❌ 事件总线初始化失败: {e}")
            raise

        # 初始化 SQLite 持久化 - 核心功能，必须
        try:
            from app.services.event_persistence import get_event_persistence
            persistence = get_event_persistence()
            logger.info(f"✅ SQLite 数据库初始化完成: {persistence.db_path}")
        except Exception as e:
            logger.error(f"❌ SQLite 数据库初始化失败: {e}")
            raise

        # PostgreSQL - 可选，由 ENABLE_POSTGRES 控制
        if settings.ENABLE_POSTGRES:
            try:
                from app.services.database import init_database
                await init_database()
                logger.info("✅ PostgreSQL 连接池创建成功")
            except Exception as e:
                logger.warning(f"⚠️ PostgreSQL 连接失败: {e}")
        else:
            logger.info("ℹ️ PostgreSQL 已禁用，使用 SQLite")

        # ChromaDB - 可选，由 ENABLE_CHROMADB 控制
        if settings.ENABLE_CHROMADB:
            try:
                from app.services.vector_store import init_vector_store
                await init_vector_store()
                logger.info("✅ ChromaDB 初始化完成（RAG 功能已启用）")
            except Exception as e:
                logger.warning(f"⚠️ ChromaDB 初始化失败: {e}")
        else:
            logger.info("ℹ️ ChromaDB 已禁用，RAG 功能不可用")

        logger.info(f"🎉 服务启动完成，监听端口: {settings.AGENT_PORT}")

    @app.on_event("shutdown")
    async def on_shutdown():
        """应用关闭时的清理"""
        logger.info("🛑 服务正在关闭...")

        # 关闭事件总线
        try:
            from app.services.event_bus_v2 import shutdown_event_bus
            await shutdown_event_bus()
            logger.info("✅ 事件总线已关闭")
        except Exception as e:
            logger.warning(f"⚠️ 关闭事件总线失败: {e}")


# 创建应用实例
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.AGENT_PORT,
        reload=True,
        log_level=settings.LOG_LEVEL,
        # 快速关闭配置
        timeout_graceful_shutdown=1,  # 优雅关闭只等待 1 秒
        limit_concurrency=None,
        limit_max_requests=None,
    )
