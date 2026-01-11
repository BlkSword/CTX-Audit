"""
CTX-Audit Agent Service 配置管理
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """应用配置"""

    # ========== 服务配置 ==========
    APP_NAME: str = "CTX-Audit Agent Service"
    APP_VERSION: str = "1.0.0"
    AGENT_PORT: int = 8001
    LOG_LEVEL: str = "info"

    # ========== Rust 后端配置 ==========
    RUST_BACKEND_URL: str = "http://localhost:8000"

    # ========== PostgreSQL 配置 ==========
    DATABASE_URL: str = "postgresql://audit_user:audit_pass@localhost:5432/audit_db"
    ENABLE_POSTGRES: bool = False  # 是否启用 PostgreSQL（默认使用 SQLite）

    # ========== Qdrant 配置 ==========
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    ENABLE_QDRANT: bool = True  # 是否启用 Qdrant（RAG 功能）

    # ========== Redis 配置 ==========
    REDIS_URL: str = "redis://localhost:6379/0"  # 保留配置但未使用

    # ========== LLM 配置 ==========
    LLM_PROVIDER: str = "anthropic"  # anthropic | openai | litellm
    LLM_MODEL: str = "claude-3-5-sonnet-20241022"
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""

    # ========== RAG 配置 ==========
    RAG_ENABLED: bool = True
    EMBEDDING_MODEL: str = "text-embedding-3-small"
    CHUNK_SIZE: int = 500
    CHUNK_OVERLAP: int = 50
    TOP_K_RETRIEVAL: int = 5

    # ========== Agent 配置 ==========
    MAX_CONCURRENT_AGENTS: int = 3
    AGENT_TIMEOUT: int = 300
    ENABLE_VERIFICATION: bool = False

    # ========== 安全配置 ==========
    API_KEY_HEADER: str = "X-API-Key"
    API_KEY: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """获取配置单例"""
    return Settings()


# 全局配置实例
settings = get_settings()
