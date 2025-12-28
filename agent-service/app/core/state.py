"""
Agent 工作流状态管理

定义审计任务的状态结构和流转
"""
from typing import TypedDict, List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class AuditStatus(str, Enum):
    """审计状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentStatus(str, Enum):
    """Agent 状态"""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditState(TypedDict):
    """
    审计工作流状态

    这是 LangGraph 工作流的状态定义
    """
    # 基本信息
    audit_id: str
    project_id: str
    audit_type: str

    # 状态
    status: AuditStatus
    current_stage: str

    # 各 Agent 的结果
    recon_result: Optional[Dict[str, Any]]
    scan_results: List[Dict[str, Any]]
    analysis_results: List[Dict[str, Any]]
    verification_results: List[Dict[str, Any]]

    # 最终报告
    final_report: Optional[Dict[str, Any]]

    # 错误处理
    errors: List[str]
    retry_count: int


@dataclass
class ProjectContext:
    """
    项目上下文

    由 Recon Agent 收集的项目信息
    """
    project_id: str
    project_path: str
    languages: List[str]
    frameworks: List[str]
    entry_points: List[Dict[str, Any]]
    dependencies: List[str]
    file_count: int
    total_lines: int


@dataclass
class VulnerabilityFinding:
    """
    漏洞发现

    由 Analysis Agent 生成
    """
    id: str
    audit_id: str
    vulnerability_type: str
    severity: str  # critical, high, medium, low, info
    confidence: float  # 0.0 - 1.0
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    remediation: str
    references: List[Dict[str, str]]
    verified: bool = False
    is_false_positive: bool = False
    agent_found: str = ""


@dataclass
class AgentExecutionResult:
    """
    Agent 执行结果

    统一的 Agent 执行结果格式
    """
    agent_name: str
    status: str  # success, error
    result: Optional[Dict[str, Any]]
    thinking_chain: List[Dict[str, Any]]
    duration_ms: int
    error: Optional[str] = None


def create_initial_audit_state(
    audit_id: str,
    project_id: str,
    audit_type: str,
) -> AuditState:
    """
    创建初始审计状态

    Args:
        audit_id: 审计 ID
        project_id: 项目 ID
        audit_type: 审计类型

    Returns:
        初始状态字典
    """
    return AuditState(
        audit_id=audit_id,
        project_id=project_id,
        audit_type=audit_type,
        status=AuditStatus.PENDING,
        current_stage="initialization",
        recon_result=None,
        scan_results=[],
        analysis_results=[],
        verification_results=[],
        final_report=None,
        errors=[],
        retry_count=0,
    )


def merge_agent_result(
    state: AuditState,
    agent_result: AgentExecutionResult,
) -> AuditState:
    """
    将 Agent 结果合并到状态中

    Args:
        state: 当前状态
        agent_result: Agent 执行结果

    Returns:
        更新后的状态
    """
    state["current_stage"] = agent_result.agent_name

    if agent_result.status == "success":
        # 根据 Agent 类型存储结果
        if agent_result.agent_name == "recon":
            state["recon_result"] = agent_result.result
        elif agent_result.agent_name == "scanner":
            state["scan_results"] = agent_result.result.get("findings", [])
        elif agent_result.agent_name == "analysis":
            state["analysis_results"] = agent_result.result.get("vulnerabilities", [])
        elif agent_result.agent_name == "verification":
            state["verification_results"] = agent_result.result.get("verified", [])

        state["status"] = AuditStatus.RUNNING
    else:
        state["errors"].append(agent_result.error or "Unknown error")
        state["retry_count"] += 1

        if state["retry_count"] >= 3:
            state["status"] = AuditStatus.FAILED

    return state
