"""
CTX-Audit Agent Service 配置管理（精简版）
"""
from pathlib import Path
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

    # ========== SQLite 配置 ==========
    # 数据库文件路径（相对于应用根目录）
    DATABASE_PATH: str = "audit_agent.db"

    # ========== LLM 配置 ==========
    LLM_PROVIDER: str = "anthropic"  # anthropic | openai | ollama
    LLM_MODEL: str = "claude-3-5-sonnet-20241022"
    ANTHROPIC_API_KEY: str = ""
    OPENAI_API_KEY: str = ""
    OLLAMA_BASE_URL: str = "http://localhost:11434"

    # ========== RAG 配置 ==========
    RAG_ENABLED: bool = False  # 禁用 RAG，使用云端 LLM

    # ========== Agent 配置 ==========
    MAX_CONCURRENT_AGENTS: int = 3
    AGENT_TIMEOUT: int = 300
    ENABLE_VERIFICATION: bool = False

    # ========== 安全配置 ==========
    API_KEY_HEADER: str = "X-API-Key"
    API_KEY: str = ""

    @property
    def database_url(self) -> str:
        """获取 SQLite 数据库 URL"""
        # 确保路径是绝对路径
        db_path = Path(self.DATABASE_PATH)
        if not db_path.is_absolute():
            # 使用应用根目录
            db_path = Path(__file__).parent.parent / self.DATABASE_PATH
        return f"sqlite:///{db_path}"

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
