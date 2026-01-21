"""
CTX-Audit Agent Service 主应用入口（精简版）

Multi-Agent 代码审计系统的 FastAPI 服务
使用 SQLite 持久化，无需外部数据库
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    # ==================== 启动时的初始化 ====================
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

    # 初始化监控系统
    try:
        from app.core.monitoring import get_monitoring_system
        monitoring = get_monitoring_system()
        logger.info("✅ 监控系统初始化完成")
    except Exception as e:
        logger.warning(f"⚠️ 监控系统初始化失败: {e}")

    # 初始化认证系统
    try:
        from app.core.auth import get_auth_service
        auth_service = get_auth_service()
        logger.info("✅ 认证系统初始化完成")
    except Exception as e:
        logger.warning(f"⚠️ 认证系统初始化失败: {e}")

    logger.info(f"🎉 服务启动完成，监听端口: {settings.AGENT_PORT}")

    yield  # ==================== 应用运行中... ====================

    # ==================== 关闭时的清理 ====================
    logger.info("🛑 服务正在关闭...")

    # 关闭事件总线
    try:
        from app.services.event_bus_v2 import shutdown_event_bus
        await shutdown_event_bus()
        logger.info("✅ 事件总线已关闭")
    except Exception as e:
        logger.warning(f"⚠️ 关闭事件总线失败: {e}")

    # 取消所有挂起的任务
    try:
        import asyncio
        tasks = [task for task in asyncio.all_tasks() if not task.done()]
        if tasks:
            logger.info(f"取消 {len(tasks)} 个挂起的任务...")
            for task in tasks:
                task.cancel()
            # 等待任务取消（最多1秒）
            await asyncio.wait(tasks, timeout=1.0)
            logger.info("✅ 后台任务已取消")
    except Exception as e:
        logger.warning(f"⚠️ 取消后台任务失败: {e}")


def create_app() -> FastAPI:
    """创建 FastAPI 应用实例"""

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="Multi-Agent 代码审计系统 - 智能漏洞检测与分析服务",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
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

    return app


def _register_routes(app: FastAPI) -> None:
    """注册所有路由"""
    from app.api import audit, agents, health, llm, prompts, settings, auth

    app.include_router(health.router, prefix="/health", tags=["Health"])
    app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])
    app.include_router(llm.router, prefix="/api/llm", tags=["LLM"])
    app.include_router(prompts.router, prefix="/api/prompts", tags=["Prompts"])
    app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
    app.include_router(settings.router, prefix="/api/settings", tags=["Settings"])
    app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])

    logger.info("API 路由注册完成")


# 创建应用实例
app = create_app()


if __name__ == "__main__":
    import uvicorn
    import os

    # 检查是否是开发模式（启用热重载）
    is_dev = os.environ.get("CTX_AUDIT_DEV", "0") == "1"

    # 运行服务器（直接传入 app 对象，避免模块路径问题）
    try:
        uvicorn.run(
            app,  # 直接使用 app 对象
            host="0.0.0.0",
            port=settings.AGENT_PORT,
            reload=is_dev,
            log_level=settings.LOG_LEVEL,
            # 关闭配置 - 快速关闭
            timeout_graceful_shutdown=2,
            # 禁用监控线程以加快关闭
            access_log=False,
        )
    except KeyboardInterrupt:
        logger.info("收到 Ctrl+C，服务已停止")
    except Exception as e:
        logger.error(f"服务异常: {e}")
        raise
    finally:
        logger.info("服务已关闭")
