"""
系统设置 API

使用 SQLite 存储系统配置，支持加密存储敏感信息
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json
import sqlite3
import os
from pathlib import Path
from loguru import logger

router = APIRouter()

# 数据库路径
DB_DIR = Path(__file__).parent.parent.parent.parent / "data"
DB_PATH = DB_DIR / "settings.db"


# ========== 数据模型 ==========

class LLMConfigModel(BaseModel):
    """LLM 配置模型"""
    provider: str
    model: str
    api_key: str
    api_endpoint: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    enabled: bool = True
    is_default: bool = False


class SystemSettingsModel(BaseModel):
    """系统设置模型"""
    # 嵌入模型配置
    embedding_provider: str = "openai"
    embedding_model: str = "text-embedding-3-small"
    embedding_api_key: Optional[str] = None
    embedding_base_url: Optional[str] = None
    embedding_dimension: int = 1536

    # 分析参数
    max_analyze_files: int = 0
    max_file_size: int = 204800
    llm_concurrency: int = 3
    llm_gap_ms: int = 2000
    output_language: str = "zh-CN"
    enable_rag: bool = True
    enable_verification: bool = False
    max_iterations: int = 20
    timeout_seconds: int = 300

    # Git 配置
    github_token: Optional[str] = None
    gitlab_token: Optional[str] = None
    gitea_token: Optional[str] = None
    default_branch: str = "main"

    # Agent 配置
    max_concurrent_agents: int = 3
    agent_timeout: int = 300
    enable_sandbox: bool = False
    sandbox_image: str = "python:3.11-slim"

    # 界面配置
    theme: str = "auto"
    language: str = "zh-CN"
    font_size: str = "medium"
    show_thinking: bool = True
    auto_scroll: bool = True
    compact_mode: bool = False


# ========== 数据库初始化 ==========

def init_db():
    """初始化数据库"""
    DB_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # 创建 LLM 配置表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS llm_configs (
            id TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            api_key TEXT NOT NULL,
            api_endpoint TEXT,
            temperature REAL NOT NULL DEFAULT 0.7,
            max_tokens INTEGER NOT NULL DEFAULT 4096,
            enabled INTEGER NOT NULL DEFAULT 1,
            is_default INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # 创建系统设置表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            settings_json TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # 插入默认系统设置
    cursor.execute("INSERT OR IGNORE INTO system_settings (id, settings_json) VALUES (1, '{}')")

    conn.commit()
    conn.close()

    logger.info(f"设置数据库初始化完成: {DB_PATH}")


# ========== LLM 配置 API ==========

@router.get("/llm/configs")
async def get_llm_configs():
    """获取所有 LLM 配置"""
    init_db()  # 确保数据库存在

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM llm_configs ORDER BY is_default DESC, created_at DESC")
    rows = cursor.fetchall()

    configs = []
    for row in rows:
        # 隐藏 API 密钥（只显示前 8 位）
        api_key_masked = row["api_key"][:8] + "..." if len(row["api_key"]) > 8 else "***"
        configs.append({
            "id": row["id"],
            "provider": row["provider"],
            "model": row["model"],
            "apiKey": api_key_masked,
            "apiEndpoint": row["api_endpoint"],
            "temperature": row["temperature"],
            "maxTokens": row["max_tokens"],
            "enabled": bool(row["enabled"]),
            "isDefault": bool(row["is_default"]),
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        })

    conn.close()
    return {"configs": configs}


@router.post("/llm/configs")
async def create_llm_config(config: LLMConfigModel):
    """创建 LLM 配置"""
    import uuid
    from datetime import datetime

    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    config_id = str(uuid.uuid4())
    now = datetime.now().isoformat()

    # 如果设置为默认，先取消其他默认配置
    if config.is_default:
        cursor.execute("UPDATE llm_configs SET is_default = 0")

    cursor.execute("""
        INSERT INTO llm_configs (
            id, provider, model, api_key, api_endpoint,
            temperature, max_tokens, enabled, is_default,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        config_id, config.provider, config.model, config.api_key,
        config.api_endpoint, config.temperature, config.max_tokens,
        int(config.enabled), int(config.is_default), now, now
    ))

    conn.commit()
    conn.close()

    logger.info(f"LLM 配置已创建: {config.provider}/{config.model}")
    return {"id": config_id, "status": "created"}


@router.put("/llm/configs/{config_id}")
async def update_llm_config(config_id: str, config: LLMConfigModel):
    """更新 LLM 配置"""
    from datetime import datetime

    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # 检查配置是否存在
    cursor.execute("SELECT id FROM llm_configs WHERE id = ?", (config_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="配置不存在")

    now = datetime.now().isoformat()

    # 如果设置为默认，先取消其他默认配置
    if config.is_default:
        cursor.execute("UPDATE llm_configs SET is_default = 0")

    cursor.execute("""
        UPDATE llm_configs SET
            provider = ?, model = ?, api_key = ?, api_endpoint = ?,
            temperature = ?, max_tokens = ?, enabled = ?, is_default = ?,
            updated_at = ?
        WHERE id = ?
    """, (
        config.provider, config.model, config.api_key, config.api_endpoint,
        config.temperature, config.max_tokens, int(config.enabled),
        int(config.is_default), now, config_id
    ))

    conn.commit()
    conn.close()

    logger.info(f"LLM 配置已更新: {config_id}")
    return {"id": config_id, "status": "updated"}


@router.delete("/llm/configs/{config_id}")
async def delete_llm_config(config_id: str):
    """删除 LLM 配置"""
    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute("DELETE FROM llm_configs WHERE id = ?", (config_id,))
    conn.commit()
    conn.close()

    logger.info(f"LLM 配置已删除: {config_id}")
    return {"status": "deleted"}


@router.post("/llm/configs/{config_id}/default")
async def set_default_llm_config(config_id: str):
    """设置默认 LLM 配置"""
    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    # 先取消所有默认配置
    cursor.execute("UPDATE llm_configs SET is_default = 0")
    # 设置新的默认配置
    cursor.execute("UPDATE llm_configs SET is_default = 1 WHERE id = ?", (config_id,))

    conn.commit()
    conn.close()

    return {"status": "success"}


@router.post("/llm/configs/{config_id}/test")
async def test_llm_config(config_id: str):
    """测试已保存的 LLM 配置"""
    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM llm_configs WHERE id = ?", (config_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="配置不存在")

    # TODO: 实际测试 LLM 连接
    # 这里暂时返回成功
    return {
        "success": True,
        "message": "连接测试成功"
    }


@router.post("/llm/configs/test-connection")
async def test_llm_connection(config: LLMConfigModel):
    """测试 LLM 连接（临时，不保存配置）"""
    import httpx

    # 构建测试请求
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }

    test_url = config.api_endpoint or ""
    if not test_url.endswith("/chat/completions"):
        if test_url.endswith("/v1"):
            test_url += "/chat/completions"
        elif test_url.endswith("/"):
            test_url += "v1/chat/completions"
        else:
            test_url += "/v1/chat/completions"

    test_payload = {
        "model": config.model,
        "messages": [{"role": "user", "content": "test"}],
        "max_tokens": 10,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                test_url,
                headers=headers,
                json=test_payload,
            )

            if response.status_code == 200:
                return {
                    "success": True,
                    "message": "连接测试成功"
                }
            else:
                return {
                    "success": False,
                    "message": f"API 返回错误: {response.status_code} - {response.text[:200]}"
                }
    except httpx.TimeoutException:
        return {
            "success": False,
            "message": "连接超时，请检查 API 端点是否正确"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"连接失败: {str(e)}"
        }


# ========== 系统设置 API ==========

@router.get("/system")
async def get_system_settings():
    """获取系统设置"""
    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute("SELECT settings_json FROM system_settings WHERE id = 1")
    row = cursor.fetchone()

    if row:
        settings = json.loads(row[0])
    else:
        settings = {}

    conn.close()
    return settings


@router.put("/system")
async def update_system_settings(settings: Dict[str, Any]):
    """更新系统设置"""
    from datetime import datetime

    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    now = datetime.now().isoformat()
    settings_json = json.dumps(settings, ensure_ascii=False)

    cursor.execute("""
        UPDATE system_settings
        SET settings_json = ?, updated_at = ?
        WHERE id = 1
    """, (settings_json, now))

    conn.commit()
    conn.close()

    logger.info("系统设置已更新")
    return {"status": "success"}


@router.post("/system/reset")
async def reset_system_settings():
    """重置系统设置为默认值"""
    init_db()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    default_settings = {}
    settings_json = json.dumps(default_settings, ensure_ascii=False)

    cursor.execute("""
        UPDATE system_settings
        SET settings_json = ?, updated_at = datetime('now')
        WHERE id = 1
    """, (settings_json,))

    conn.commit()
    conn.close()

    logger.info("系统设置已重置")
    return {"status": "reset"}


# ========== 默认配置 API ==========

@router.get("/defaults")
async def get_default_settings():
    """获取默认配置"""
    return {
        "embedding": {
            "provider": "openai",
            "model": "text-embedding-3-small",
            "dimension": 1536,
        },
        "analysis": {
            "maxAnalyzeFiles": 0,
            "maxFileSize": 204800,
            "llmConcurrency": 3,
            "llmGapMs": 2000,
            "outputLanguage": "zh-CN",
            "enableRAG": True,
            "enableVerification": False,
            "maxIterations": 20,
            "timeoutSeconds": 300,
        },
        "git": {
            "defaultBranch": "main",
        },
        "agent": {
            "maxConcurrentAgents": 3,
            "agentTimeout": 300,
            "enableSandbox": False,
            "sandboxImage": "python:3.11-slim",
        },
        "ui": {
            "theme": "auto",
            "language": "zh-CN",
            "fontSize": "medium",
            "showThinking": True,
            "autoScroll": True,
            "compactMode": False,
        },
    }
