// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 多 Agent 系统架构 - Coordinator-Specialist
//!
//! 本模块提供统一的系统接口，内部使用 Coordinator-Specialist 架构。

use crate::audit_state::SecurityAuditState;
use crate::multi_agent::coordinator;
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::ToolRegistry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// 重新导出 coordinator 模块的类型
pub use coordinator::{
    AuditReport, AuditTeamConfig, AuditTeamSystem, CoordinatorConfig, FindingSummary, Mailbox,
    SpecialistConfig, SpecialistTypesConfig, SystemStats,
};

// 重新导出 task 类型
pub use crate::multi_agent::task::{
    AgentSpecialty, AuditTask, EndpointContext, FileContext, FollowUpRequest, FollowUpRequestType,
    TaskContext, TaskPriority, TaskStatus, TaskType, WorkerResult,
};

// 重新导出 FindingData
pub use ctx_audit_tools::FindingData;

// 从 aggregator 重新导出
pub use crate::multi_agent::aggregator::{
    AggregatedFinding, AggregatedResults, AggregationStatistics, ExpertCoverage, ResultAggregator,
};

// 从 validator 重新导出
pub use crate::multi_agent::validator::{
    CrossValidator, ValidatedFinding, ValidatedResults, ValidationStatistics, ValidationStatus,
    ValidationStrategy,
};

// 从 prompts 重新导出
pub use crate::multi_agent::prompts::{get_expert_name, get_expert_prompt};

/// 多 Agent 系统配置
///
/// 此配置用于创建 Coordinator-Specialist 架构的审计团队系统。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentConfig {
    /// 协调器配置
    pub coordinator: CoordinatorConfig,

    /// 专家配置
    pub specialist: SpecialistConfig,

    /// 专家类型配置
    pub specialists: SpecialistTypesConfig,
}

impl Default for MultiAgentConfig {
    fn default() -> Self {
        Self {
            coordinator: CoordinatorConfig::default(),
            specialist: SpecialistConfig::default(),
            specialists: SpecialistTypesConfig::default(),
        }
    }
}

impl From<MultiAgentConfig> for coordinator::AuditTeamConfig {
    fn from(config: MultiAgentConfig) -> Self {
        Self {
            coordinator: config.coordinator,
            specialist: config.specialist,
            specialists: config.specialists,
        }
    }
}

/// 统一的多 Agent 系统接口
///
/// 包装 Coordinator-Specialist 架构，提供统一的接口
pub enum UnifiedMultiAgentSystem {
    /// Coordinator-Specialist 架构
    CoordinatorSpecialist(AuditTeamSystem),
}

impl UnifiedMultiAgentSystem {
    /// 启动系统
    pub async fn start(&mut self, project_path: String) -> Result<(), String> {
        match self {
            UnifiedMultiAgentSystem::CoordinatorSpecialist(system) => {
                system.start(project_path).await.map_err(|e| e.to_string())
            }
        }
    }

    /// 执行审计
    pub async fn audit(
        &mut self,
        project_path: String,
        _audit_state: SecurityAuditState,
    ) -> Result<UnifiedAuditReport, String> {
        match self {
            UnifiedMultiAgentSystem::CoordinatorSpecialist(system) => {
                let report = system.orchestrate_audit(project_path).await.map_err(|e| e.to_string())?;
                Ok(UnifiedAuditReport::CoordinatorSpecialist(report))
            }
        }
    }

    /// 关闭系统
    pub async fn shutdown(&mut self) -> Result<(), String> {
        match self {
            UnifiedMultiAgentSystem::CoordinatorSpecialist(system) => {
                system.shutdown().await.map_err(|e| e.to_string())
            }
        }
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> UnifiedSystemStats {
        match self {
            UnifiedMultiAgentSystem::CoordinatorSpecialist(system) => {
                let stats = system.get_stats().await;
                UnifiedSystemStats::CoordinatorSpecialist(stats)
            }
        }
    }
}

/// 统一的审计报告
pub enum UnifiedAuditReport {
    CoordinatorSpecialist(AuditReport),
}

impl UnifiedAuditReport {
    /// 获取所有发现
    pub fn get_all_findings(&self) -> Vec<ctx_audit_tools::FindingData> {
        match self {
            UnifiedAuditReport::CoordinatorSpecialist(report) => {
                report.findings.clone()
            }
        }
    }

    /// 获取确认的发现（验证分数 >= 60）
    pub fn get_confirmed_findings(&self) -> Vec<ctx_audit_tools::FindingData> {
        match self {
            UnifiedAuditReport::CoordinatorSpecialist(report) => {
                if let Some(ref validated) = report.validated_results {
                    validated.confirmed
                        .iter()
                        .map(|f| f.finding.clone())
                        .collect()
                } else {
                    report.findings.clone()
                }
            }
        }
    }

    /// 获取需要审核的发现
    pub fn get_findings_needing_review(&self) -> Vec<ctx_audit_tools::FindingData> {
        match self {
            UnifiedAuditReport::CoordinatorSpecialist(report) => {
                if let Some(ref validated) = report.validated_results {
                    validated.needs_review
                        .iter()
                        .map(|f| f.finding.clone())
                        .collect()
                } else {
                    vec![]
                }
            }
        }
    }

    /// 生成摘要
    pub fn generate_summary(&self) -> String {
        match self {
            UnifiedAuditReport::CoordinatorSpecialist(report) => {
                let mut summary = format!(
                    "=== 审计报告 ===\n\
                     项目路径: {}\n\
                     生成时间: {}\n\
                     总发现数: {}\n",
                    report.project_path,
                    report.generated_at.format("%Y-%m-%d %H:%M:%S"),
                    report.total_findings
                );

                if let Some(ref validated) = report.validated_results {
                    summary.push_str(&format!(
                        "\n--- 验证结果 ---\n\
                         确认: {}\n\
                         需审核: {}\n\
                         可能误报: {}\n\
                         平均验证分数: {:.1}\n\
                         平均置信度: {:.2}",
                        validated.statistics.confirmed_count,
                        validated.statistics.needs_review_count,
                        validated.statistics.likely_false_positive_count,
                        validated.statistics.avg_validation_score,
                        validated.statistics.avg_confidence
                    ));
                }

                summary
            }
        }
    }
}

/// 统一的系统统计
pub enum UnifiedSystemStats {
    CoordinatorSpecialist(SystemStats),
}

/// 预设配置生成器
impl MultiAgentConfig {
    /// 轻量级配置 (适用于小型项目)
    pub fn lightweight() -> Self {
        Self {
            coordinator: CoordinatorConfig {
                max_parallel_tasks: 2,
                monitoring_interval_ms: 100,
                delegation_mode: true,
                task_timeout_secs: 300,
            },
            specialist: SpecialistConfig::default(),
            specialists: SpecialistTypesConfig {
                sql_experts: 0,
                xss_experts: 0,
                auth_experts: 0,
                business_logic_experts: 0,
                crypto_experts: 0,
                general_analysts: 2,
            },
        }
    }

    /// 标准配置 (适用于中型项目)
    pub fn standard() -> Self {
        Self {
            coordinator: CoordinatorConfig {
                max_parallel_tasks: 4,
                monitoring_interval_ms: 100,
                delegation_mode: true,
                task_timeout_secs: 300,
            },
            specialist: SpecialistConfig::default(),
            specialists: SpecialistTypesConfig {
                sql_experts: 1,
                xss_experts: 1,
                auth_experts: 1,
                business_logic_experts: 1,
                crypto_experts: 1,
                general_analysts: 1,
            },
        }
    }

    /// 重量级配置 (适用于大型项目)
    pub fn heavyweight() -> Self {
        Self {
            coordinator: CoordinatorConfig {
                max_parallel_tasks: 8,
                monitoring_interval_ms: 100,
                delegation_mode: true,
                task_timeout_secs: 600,
            },
            specialist: SpecialistConfig::default(),
            specialists: SpecialistTypesConfig {
                sql_experts: 2,
                xss_experts: 2,
                auth_experts: 2,
                business_logic_experts: 2,
                crypto_experts: 1,
                general_analysts: 1,
            },
        }
    }
}

/// 创建多 Agent 系统
///
/// 使用 Coordinator-Specialist 架构创建审计团队系统
pub async fn create_multi_agent_system(
    llm: Arc<dyn LLMClient>,
    tools: Arc<ToolRegistry>,
    config: MultiAgentConfig,
) -> Result<UnifiedMultiAgentSystem, String> {
    let team_config: coordinator::AuditTeamConfig = config.into();
    Ok(UnifiedMultiAgentSystem::CoordinatorSpecialist(
        AuditTeamSystem::new(team_config, llm, tools)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_agent_config_default() {
        let config = MultiAgentConfig::default();
        assert_eq!(config.coordinator.max_parallel_tasks, 5);
        assert_eq!(config.coordinator.task_timeout_secs, 300);
    }

    #[test]
    fn test_get_expert_name() {
        assert_eq!(
            get_expert_name(&AgentSpecialty::SqlInjectionExpert),
            "SQL注入专家"
        );
        assert_eq!(get_expert_name(&AgentSpecialty::XssExpert), "XSS专家");
        assert_eq!(
            get_expert_name(&AgentSpecialty::AuthExpert),
            "认证授权专家"
        );
    }

    #[test]
    fn test_preset_configs() {
        let lightweight = MultiAgentConfig::lightweight();
        assert_eq!(lightweight.specialists.general_analysts, 2);

        let standard = MultiAgentConfig::standard();
        assert_eq!(standard.specialists.general_analysts, 1);

        let heavyweight = MultiAgentConfig::heavyweight();
        assert_eq!(heavyweight.coordinator.max_parallel_tasks, 8);
    }
}
