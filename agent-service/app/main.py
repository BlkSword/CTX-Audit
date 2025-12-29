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

    # 配置 CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 注册路由
    _register_routes(app)

    # 注册生命周期事件
    _register_lifecycle(app)

    return app


def _register_routes(app: FastAPI) -> None:
    """注册所有路由"""
    from app.api import audit, agents, health, llm, prompts

    app.include_router(health.router, prefix="/health", tags=["Health"])
    app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
    app.include_router(llm.router, prefix="/api/llm", tags=["LLM"])
    app.include_router(prompts.router, prefix="/api/prompts", tags=["Prompts"])
    app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])

    logger.info("API 路由注册完成")


def _register_lifecycle(app: FastAPI) -> None:
    """注册应用生命周期事件"""

    @app.on_event("startup")
    async def on_startup():
        """应用启动时的初始化"""
        logger.info(f"🚀 {settings.APP_NAME} v{settings.APP_VERSION} 启动中...")
        logger.info(f"LLM Provider: {settings.LLM_PROVIDER}")
        logger.info(f"LLM Model: {settings.LLM_MODEL}")
        logger.info(f"RAG Enabled: {settings.RAG_ENABLED}")

        # 初始化数据库连接（可选）
        try:
            from app.services.database import init_database
            await init_database()
            logger.info("✅ 数据库连接初始化完成")
        except Exception as e:
            logger.warning(f"⚠️ 数据库连接失败（部分功能将不可用）: {e}")

        # 初始化向量数据库（可选）
        try:
            from app.services.vector_store import init_vector_store
            await init_vector_store()
            logger.info("✅ 向量数据库初始化完成")
        except Exception as e:
            logger.warning(f"⚠️ 向量数据库连接失败: {e}")

        logger.info(f"🎉 服务启动完成，监听端口: {settings.AGENT_PORT}")

    @app.on_event("shutdown")
    async def on_shutdown():
        """应用关闭时的清理"""
        logger.info("🛑 服务正在关闭...")


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
    )
