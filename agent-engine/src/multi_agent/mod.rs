// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 多 Agent 系统
//!
//! 实现 Boss-Worker 架构，支持并行安全审计

mod aggregator;
mod boss;
mod helpers;
mod prompts;
mod system;
mod task;
mod validator;
mod worker;

// 重新导出核心类型
pub use system::{
    AgentChannels, AuditReport, MultiAgentConfig, MultiAgentStats, MultiAgentSystem,
    SpecialistConfig,
};

pub use task::{
    AgentSpecialty, AuditTask, EndpointContext, FileContext, FollowUpRequest,
    FollowUpRequestType, TaskContext, TaskPriority, TaskStatus, TaskType,
};

pub use boss::{BossAgent, BossConfig, BossCommandResult, FileInfo, ProjectOverview};

pub use worker::{WorkerAgent, WorkerConfig, WorkerResult, WorkerStatus};

pub use aggregator::{AggregatedFinding, AggregatedResults, AggregationStatistics, ExpertCoverage};

pub use validator::{
    ValidationStatus, ValidationStatistics, ValidationStrategy,
    ValidatedFinding, ValidatedResults,
};

pub use prompts::{get_expert_name, get_expert_prompt};

// BossCommand is defined in worker.rs, re-export it
pub use worker::BossCommand;

/// 多 Agent 系统预置配置
pub mod presets {
    use super::*;

    /// 轻量级配置（适合小型项目）
    pub fn lightweight() -> MultiAgentConfig {
        MultiAgentConfig {
            worker_count: 3,
            specialist_config: SpecialistConfig {
                sql_experts: 0,
                xss_experts: 0,
                auth_experts: 0,
                business_logic_experts: 0,
                crypto_experts: 0,
                general_analysts: 3,
            },
            max_parallel_tasks: 2,
            task_timeout_secs: 300,
            boss_config: BossConfig::default(),
        }
    }

    /// 标准配置（适合中型项目）
    pub fn standard() -> MultiAgentConfig {
        MultiAgentConfig::default()
    }

    /// 重量级配置（适合大型项目）
    pub fn heavyweight() -> MultiAgentConfig {
        MultiAgentConfig {
            worker_count: 10,
            specialist_config: SpecialistConfig {
                sql_experts: 2,
                xss_experts: 2,
                auth_experts: 2,
                business_logic_experts: 2,
                crypto_experts: 1,
                general_analysts: 1,
            },
            max_parallel_tasks: 8,
            task_timeout_secs: 600,
            boss_config: BossConfig::default(),
        }
    }
}

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

    #[test]
    fn test_presets() {
        let lightweight = presets::lightweight();
        assert_eq!(lightweight.worker_count, 3);

        let standard = presets::standard();
        assert_eq!(standard.worker_count, 6);

        let heavyweight = presets::heavyweight();
        assert_eq!(heavyweight.worker_count, 10);
    }
}
