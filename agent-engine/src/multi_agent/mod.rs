// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 多 Agent 系统 - Coordinator-Specialist 架构
//!
//! ## 架构特性
//!
//! - 共享任务列表 + 自我认领机制
//! - Peer-to-Peer 消息系统 (Mailbox)
//! - 任务依赖管理
//! - 委派模式 (Delegation Mode)
//! - 文件锁定机制
//! - 动态优先级调整
//! - 实时发现共享
//!
//! ## 使用方式
//!
//! ```rust,no_run
//! use ctx_audit_agent_engine::multi_agent::{MultiAgentConfig, create_multi_agent_system};
//!
//! // 使用默认配置（Coordinator-Specialist 架构）
//! let config = MultiAgentConfig::standard();
//! let mut system = create_multi_agent_system(llm, tools, config).await.unwrap();
//! system.start(project_path).await.unwrap();
//! let report = system.audit(project_path, audit_state).await.unwrap();
//! ```

mod aggregator;
mod helpers;
mod prompts;
mod system;
mod task;
mod validator;

// Coordinator-Specialist 架构
pub mod coordinator;

// 重新导出核心类型（从 system.rs 重新导出）
pub use system::{
    AuditReport, MultiAgentConfig, SpecialistConfig,
    UnifiedAuditReport, UnifiedMultiAgentSystem, UnifiedSystemStats,
    create_multi_agent_system,
    // task 类型也从 system 导出，避免重复定义
    AgentSpecialty, AuditTask, EndpointContext, FileContext, FollowUpRequest, FollowUpRequestType,
    TaskContext, TaskPriority, TaskStatus, TaskType, WorkerResult, FindingData,
};

// 重新导出复用的 Boss-Worker 组件
pub use aggregator::{AggregatedFinding, AggregatedResults, AggregationStatistics, ExpertCoverage};

pub use validator::{
    ValidatedFinding, ValidatedResults, ValidationStatistics, ValidationStatus, ValidationStrategy,
};

pub use prompts::{get_expert_name, get_expert_prompt};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_specialty_display() {
        assert_eq!(
            format!("{}", AgentSpecialty::SqlInjectionExpert),
            "SQL注入专家"
        );
        assert_eq!(format!("{}", AgentSpecialty::XssExpert), "XSS专家");
    }

    #[test]
    fn test_task_priority_ordering() {
        assert!(TaskPriority::Critical > TaskPriority::High);
        assert!(TaskPriority::High > TaskPriority::Medium);
        assert!(TaskPriority::Medium > TaskPriority::Low);
    }
}
