"""
提示词模板 API 端点

管理 Agent 提示词模板
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import uuid
import re

router = APIRouter()

# ========== 数据模型 ==========

class PromptVariable(BaseModel):
    """提示词变量"""
    name: str
    description: Optional[str] = None
    required: bool = True

class PromptTemplate(BaseModel):
    """提示词模板"""
    id: str
    name: str
    description: str
    category: str  # system, agent, tool, custom
    language: str  # zh, en
    agent_type: Optional[str] = None  # ORCHESTRATOR, RECON, ANALYSIS, VERIFICATION
    template: str
    variables: List[PromptVariable] = []
    is_system: bool = False
    is_active: bool = True
    created_at: str
    updated_at: str

class CreatePromptTemplate(BaseModel):
    """创建提示词模板请求"""
    name: str
    description: str
    category: str
    language: str
    agent_type: Optional[str] = None
    template: str
    variables: List[PromptVariable] = []
    is_active: bool = True

class UpdatePromptTemplate(BaseModel):
    """更新提示词模板请求"""
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    language: Optional[str] = None
    agent_type: Optional[str] = None
    template: Optional[str] = None
    variables: Optional[List[PromptVariable]] = None
    is_active: Optional[bool] = None

# ========== 内存存储 (生产环境应使用数据库) ==========
_prompt_templates: Dict[str, PromptTemplate] = {}

# 预定义系统模板
def _init_system_templates():
    """初始化系统提示词模板"""
    now = datetime.now().isoformat()

    templates = [
        PromptTemplate(
            id="sys_orchestrator_zh",
            name="编排者系统提示词",
            description="编排者 Agent 的系统提示词",
            category="system",
            language="zh",
            agent_type="ORCHESTRATOR",
            template="你是一个经验丰富的代码安全审计专家，负责协调其他 Agent 完成代码审计任务。\n\n## 你的职责\n1. 分析项目结构，制定审计计划\n2. 协调侦察者、分析者、验证者 Agent\n3. 汇总审计结果，生成最终报告\n\n## 当前项目\n项目路径: {{project_path}}\n审计类型: {{audit_type}}",
            variables=[
                PromptVariable(name="project_path", description="项目路径", required=True),
                PromptVariable(name="audit_type", description="审计类型", required=True),
            ],
            is_system=True,
            is_active=True,
            created_at=now,
            updated_at=now,
        ),
        PromptTemplate(
            id="sys_recon_zh",
            name="侦察者系统提示词",
            description="侦察者 Agent 的系统提示词",
            category="system",
            language="zh",
            agent_type="RECON",
            template="你是侦察者 Agent，负责收集项目的基础信息。\n\n## 任务\n1. 扫描项目结构\n2. 识别关键文件和目录\n3. 检测使用的技术栈\n4. 发现潜在的风险点\n\n项目路径: {{project_path}}",
            variables=[
                PromptVariable(name="project_path", description="项目路径", required=True),
            ],
            is_system=True,
            is_active=True,
            created_at=now,
            updated_at=now,
        ),
    ]

    for template in templates:
        _prompt_templates[template.id] = template

# 初始化
_init_system_templates()

# ========== 辅助函数 ==========

def _extract_variables(template: str) -> List[str]:
    """从模板中提取变量"""
    pattern = r'\{\{(\w+)\}\}'
    return list(set(re.findall(pattern, template)))

# ========== API 端点 ==========

@router.get("/templates")
async def get_prompt_templates(category: Optional[str] = None):
    """获取提示词模板列表"""
    templates = list(_prompt_templates.values())

    if category:
        templates = [t for t in templates if t.category == category]

    return templates

@router.post("/templates", response_model=PromptTemplate, status_code=status.HTTP_201_CREATED)
async def create_prompt_template(template: CreatePromptTemplate):
    """创建新的提示词模板"""
    template_id = f"tpl_{uuid.uuid4().hex[:8]}"
    now = datetime.now().isoformat()

    # 自动提取变量
    if not template.variables:
        found_vars = _extract_variables(template.template)
        template.variables = [
            PromptVariable(name=var, required=True)
            for var in found_vars
        ]

    prompt_template = PromptTemplate(
        id=template_id,
        **template.model_dump(),
        is_system=False,
        created_at=now,
        updated_at=now,
    )

    _prompt_templates[template_id] = prompt_template
    return prompt_template

@router.put("/templates/{template_id}", response_model=PromptTemplate)
async def update_prompt_template(template_id: str, template: UpdatePromptTemplate):
    """更新提示词模板"""
    if template_id not in _prompt_templates:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"提示词模板不存在: {template_id}"
        )

    existing = _prompt_templates[template_id]

    # 系统模板不允许修改
    if existing.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="系统模板不允许修改"
        )

    # 更新字段
    update_data = template.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(existing, key, value)

    existing.updated_at = datetime.now().isoformat()
    _prompt_templates[template_id] = existing
    return existing

@router.delete("/templates/{template_id}")
async def delete_prompt_template(template_id: str):
    """删除提示词模板"""
    if template_id not in _prompt_templates:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"提示词模板不存在: {template_id}"
        )

    existing = _prompt_templates[template_id]

    # 系统模板不允许删除
    if existing.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="系统模板不允许删除"
        )

    del _prompt_templates[template_id]
    return {"message": "提示词模板已删除"}
