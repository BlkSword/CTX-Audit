"""
LLM 配置 API 端点

管理 LLM 提供商配置
"""
# API Router for LLM configuration management
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List, Dict
import uuid

router = APIRouter()

# ========== 数据模型 ==========

class LLMConfig(BaseModel):
    """LLM 配置"""
    id: str
    provider: str  # openai, anthropic, azure, ollama, custom
    model: str
    api_key: Optional[str] = None
    api_endpoint: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    enabled: bool = True
    is_default: bool = False

class CreateLLMConfig(BaseModel):
    """创建 LLM 配置请求"""
    provider: str
    model: str
    api_key: Optional[str] = None
    api_endpoint: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    enabled: bool = True
    is_default: bool = False

class UpdateLLMConfig(BaseModel):
    """更新 LLM 配置请求"""
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    api_endpoint: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    enabled: Optional[bool] = None
    is_default: Optional[bool] = None

# ========== 内存存储 (生产环境应使用数据库) ==========
_llm_configs: Dict[str, LLMConfig] = {}

# ========== API 端点 ==========

@router.get("/configs", response_model=List[LLMConfig])
async def get_llm_configs():
    """获取所有 LLM 配置"""
    return list(_llm_configs.values())

@router.post("/configs", response_model=LLMConfig, status_code=status.HTTP_201_CREATED)
async def create_llm_config(config: CreateLLMConfig):
    """创建新的 LLM 配置"""
    config_id = f"llm_{uuid.uuid4().hex[:8]}"

    # 如果设置为默认，取消其他配置的默认状态
    if config.is_default:
        for existing in _llm_configs.values():
            existing.is_default = False

    llm_config = LLMConfig(id=config_id, **config.model_dump())
    _llm_configs[config_id] = llm_config
    return llm_config

@router.put("/configs/{config_id}", response_model=LLMConfig)
async def update_llm_config(config_id: str, config: UpdateLLMConfig):
    """更新 LLM 配置"""
    if config_id not in _llm_configs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM 配置不存在: {config_id}"
        )

    existing = _llm_configs[config_id]

    # 更新字段
    update_data = config.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(existing, key, value)

    # 如果设置为默认，取消其他配置的默认状态
    if existing.is_default:
        for other in _llm_configs.values():
            if other.id != config_id:
                other.is_default = False

    _llm_configs[config_id] = existing
    return existing

@router.delete("/configs/{config_id}")
async def delete_llm_config(config_id: str):
    """删除 LLM 配置"""
    if config_id not in _llm_configs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM 配置不存在: {config_id}"
        )

    del _llm_configs[config_id]
    return {"message": "LLM 配置已删除"}

@router.post("/configs/{config_id}/test")
async def test_llm_config(config_id: str):
    """测试 LLM 配置"""
    if config_id not in _llm_configs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM 配置不存在: {config_id}"
        )

    config = _llm_configs[config_id]

    # 简单测试 - 生产环境应实际调用 LLM API
    if not config.api_key and config.provider in ["openai", "anthropic", "azure"]:
        return {"success": False, "error": "缺少 API 密钥"}

    return {"success": True}

@router.post("/configs/{config_id}/default")
async def set_default_llm_config(config_id: str):
    """设置默认 LLM 配置"""
    if config_id not in _llm_configs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"LLM 配置不存在: {config_id}"
        )

    # 取消所有默认状态
    for config in _llm_configs.values():
        config.is_default = False

    # 设置新的默认
    _llm_configs[config_id].is_default = True

    return _llm_configs[config_id]
