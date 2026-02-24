// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 多 Agent 系统任务定义

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit_state::AuditPhase;

/// 审计任务
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTask {
    /// 任务 ID
    pub id: String,

    /// 任务类型
    pub task_type: TaskType,

    /// 任务目标（文件路径、函数名等）
    pub target: String,

    /// 所需专业领域
    pub specialty_required: AgentSpecialty,

    /// 任务优先级
    pub priority: TaskPriority,

    /// 任务上下文
    pub context: TaskContext,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 开始时间
    pub started_at: Option<DateTime<Utc>>,

    /// 完成时间
    pub completed_at: Option<DateTime<Utc>>,

    /// 任务状态
    pub status: TaskStatus,

    /// 重试次数
    pub retry_count: u32,
}

/// 任务类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskType {
    /// 项目侦察 - 初始项目结构分析
    Reconnaissance,

    /// 文件分析 - 单文件深度分析
    FileAnalysis,

    /// 全局数据流分析 - 跨文件污点追踪
    GlobalDataFlow,

    /// 业务逻辑分析 - 权限、状态机、业务规则
    BusinessLogicAnalysis,

    /// 漏洞验证 - PoC 生成和验证
    VulnerabilityVerification,

    /// Git 历史分析 - 举一反三
    GitHistoryAnalysis,

    /// 语义分析 - 代码意图理解
    SemanticAnalysis,
}

/// 任务优先级
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    /// 低优先级
    Low = 1,
    /// 中等优先级
    Medium = 2,
    /// 高优先级
    High = 3,
    /// 关键优先级
    Critical = 4,
}

/// 任务状态
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    /// 待分配
    Pending,
    /// 已分配
    Assigned,
    /// 执行中
    InProgress,
    /// 已完成
    Completed,
    /// 失败
    Failed,
    /// 已取消
    Cancelled,
    /// 等待协助
    WaitingForAssistance,
}

/// 任务上下文
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TaskContext {
    /// 文件信息
    pub file_info: Option<FileContext>,

    /// 端点信息
    pub endpoint_info: Option<EndpointContext>,

    /// 全局项目信息引用
    pub project_overview_ref: Option<String>,

    /// 相关任务 ID
    pub related_tasks: Vec<String>,

    /// 额外上下文数据
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// 文件上下文
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileContext {
    /// 文件路径
    pub path: String,

    /// 文件语言
    pub language: String,

    /// 文件大小
    pub size: usize,

    /// 关键函数列表
    pub key_functions: Vec<String>,

    /// 相关候选漏洞 ID
    pub related_candidates: Vec<String>,
}

/// 端点上下文
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EndpointContext {
    /// 端点路径
    pub path: String,

    /// HTTP 方法
    pub method: String,

    /// 控制器函数
    pub controller: String,

    /// 认证要求
    pub auth_required: bool,

    /// 资源 ID 参数名
    pub resource_id_param: Option<String>,
}

/// 后续请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowUpRequest {
    /// 请求类型
    pub request_type: FollowUpRequestType,

    /// 原因
    pub reason: String,

    /// 建议的专家类型
    pub suggested_specialty: Option<AgentSpecialty>,

    /// 请求的数据
    pub data: serde_json::Value,
}

/// 后续请求类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FollowUpRequestType {
    /// 请求额外的文件分析
    AdditionalFileAnalysis,

    /// 请求专家协助
    ExpertAssistance,

    /// 请求全局数据流分析
    GlobalDataFlowRequest,

    /// 请求业务逻辑验证
    BusinessLogicVerification,

    /// 请求漏洞验证
    VulnerabilityConfirmation,
}

/// Agent 专业领域
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AgentSpecialty {
    /// SQL 注入专家
    SqlInjectionExpert,

    /// XSS 专家
    XssExpert,

    /// 命令注入专家
    CommandInjectionExpert,

    /// 路径遍历专家
    PathTraversalExpert,

    /// SSRF 专家
    SsrfExpert,

    /// 认证/授权专家
    AuthExpert,

    /// 业务逻辑专家
    BusinessLogicExpert,

    /// 密码学专家
    CryptoExpert,

    /// 配置安全专家
    ConfigExpert,

    /// 通用分析师
    GeneralAnalyst,
}

impl std::fmt::Display for AgentSpecialty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentSpecialty::SqlInjectionExpert => write!(f, "SQL注入专家"),
            AgentSpecialty::XssExpert => write!(f, "XSS专家"),
            AgentSpecialty::CommandInjectionExpert => write!(f, "命令注入专家"),
            AgentSpecialty::PathTraversalExpert => write!(f, "路径遍历专家"),
            AgentSpecialty::SsrfExpert => write!(f, "SSRF专家"),
            AgentSpecialty::AuthExpert => write!(f, "认证授权专家"),
            AgentSpecialty::BusinessLogicExpert => write!(f, "业务逻辑专家"),
            AgentSpecialty::CryptoExpert => write!(f, "密码学专家"),
            AgentSpecialty::ConfigExpert => write!(f, "配置安全专家"),
            AgentSpecialty::GeneralAnalyst => write!(f, "通用分析师"),
        }
    }
}

impl AuditTask {
    /// 创建新任务
    pub fn new(
        task_type: TaskType,
        target: String,
        specialty: AgentSpecialty,
        priority: TaskPriority,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            task_type,
            target,
            specialty_required: specialty,
            priority,
            context: TaskContext::default(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            status: TaskStatus::Pending,
            retry_count: 0,
        }
    }

    /// 创建文件分析任务
    pub fn file_analysis(file_path: String, specialty: AgentSpecialty, priority: TaskPriority) -> Self {
        Self::new(TaskType::FileAnalysis, file_path, specialty, priority)
    }

    /// 创建业务逻辑分析任务
    pub fn business_logic_analysis(endpoint_path: String, priority: TaskPriority) -> Self {
        Self::new(
            TaskType::BusinessLogicAnalysis,
            endpoint_path,
            AgentSpecialty::BusinessLogicExpert,
            priority,
        )
    }

    /// 标记为已分配
    pub fn mark_assigned(&mut self) {
        self.status = TaskStatus::Assigned;
        self.started_at = Some(Utc::now());
    }

    /// 标记为进行中
    pub fn mark_in_progress(&mut self) {
        self.status = TaskStatus::InProgress;
    }

    /// 标记为已完成
    pub fn mark_completed(&mut self) {
        self.status = TaskStatus::Completed;
        self.completed_at = Some(Utc::now());
    }

    /// 标记为失败
    pub fn mark_failed(&mut self) {
        self.status = TaskStatus::Failed;
        self.completed_at = Some(Utc::now());
    }

    /// 增加重试次数
    pub fn increment_retry(&mut self) {
        self.retry_count += 1;
    }

    /// 检查是否可重试
    pub fn can_retry(&self, max_retries: u32) -> bool {
        return self.retry_count < max_retries && matches!(self.status, TaskStatus::Failed);
    }
}

impl Default for TaskPriority {
    fn default() -> Self {
        TaskPriority::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_creation() {
        let task = AuditTask::file_analysis(
            "/test/path.rs".to_string(),
            AgentSpecialty::SqlInjectionExpert,
            TaskPriority::High,
        );

        assert_eq!(task.task_type, TaskType::FileAnalysis);
        assert_eq!(task.specialty_required, AgentSpecialty::SqlInjectionExpert);
        assert_eq!(task.priority, TaskPriority::High);
        assert_eq!(task.status, TaskStatus::Pending);
    }

    #[test]
    fn test_task_status_transitions() {
        let mut task = AuditTask::new(
            TaskType::Reconnaissance,
            "/project".to_string(),
            AgentSpecialty::GeneralAnalyst,
            TaskPriority::Critical,
        );

        task.mark_assigned();
        assert_eq!(task.status, TaskStatus::Assigned);
        assert!(task.started_at.is_some());

        task.mark_in_progress();
        assert_eq!(task.status, TaskStatus::InProgress);

        task.mark_completed();
        assert_eq!(task.status, TaskStatus::Completed);
        assert!(task.completed_at.is_some());
    }

    #[test]
    fn test_task_retry() {
        let mut task = AuditTask::new(
            TaskType::FileAnalysis,
            "/test.rs".to_string(),
            AgentSpecialty::XssExpert,
            TaskPriority::Medium,
        );

        task.mark_failed();

        assert!(task.can_retry(3));
        assert_eq!(task.retry_count, 0);

        task.increment_retry();
        assert_eq!(task.retry_count, 1);

        task.increment_retry();
        task.increment_retry();
        assert_eq!(task.retry_count, 3);
        // retry_count=3, max_retries=3: 3 < 3 = false (不能重试)
        assert!(!task.can_retry(3));
        // retry_count=3, max_retries=4: 3 < 4 = true (可以重试)
        assert!(task.can_retry(4));
    }
}

/// Worker/Specialist 执行结果
///
/// 这个结构被 ResultAggregator 使用，用于聚合多个专家的审计结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    /// Worker ID
    pub worker_id: String,

    /// 任务 ID
    pub task_id: String,

    /// 专业领域
    pub specialty: AgentSpecialty,

    /// 发现的漏洞
    pub findings: Vec<ctx_audit_tools::FindingData>,

    /// 置信度
    pub confidence: f32,

    /// 思考笔记
    pub notes: Vec<String>,

    /// 后续请求
    pub requests: Vec<FollowUpRequest>,

    /// 工具调用记录
    pub tool_calls: Vec<crate::base::ToolCallRecord>,

    /// 错误信息
    pub error: Option<String>,

    /// 完成时间
    pub completed_at: DateTime<Utc>,
}
