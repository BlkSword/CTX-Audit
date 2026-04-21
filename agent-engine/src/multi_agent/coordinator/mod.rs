// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Coordinator-Specialist 架构
//!

mod coordinator;
mod cross_validation;
mod dynamic_priority;
mod mailbox;
mod shared_task_list;
mod specialist;

pub use shared_task_list::{SharedTaskList, TaskListStats, TaskResult};

pub use mailbox::{
    AuditPhase, CoordinatorDirective, InternalFinding, Mailbox, Message, MessageContent, MessageHandler,
};

pub use coordinator::{AuditReport, Coordinator, CoordinatorConfig, FindingSummary};

pub use specialist::{
    Specialist, SpecialistConfig, SpecialistInfo, SpecialistMetrics, SpecialistStatus,
};

pub use cross_validation::{
    CrossValidationManager, FindingChallenge, FindingValidation, FindingValidationStatus,
    ChallengeType, ChallengeStatus, FindingValidator, ValidationResult, ValidationContext,
    create_validation_context, AutoValidationRules, AutoValidationResult, CrossValidationStats,
};

pub use dynamic_priority::{
    DynamicPriorityManager, PriorityAdjustment, PriorityAdjustmentReason,
    PriorityAdjustmentStrategy, PriorityManagerStats,
};

// 重新导出标准的 FindingData
pub use ctx_audit_tools::FindingData;

use std::sync::Arc;
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::ToolRegistry;
use serde::{Deserialize, Serialize};

/// Coordinator-Specialist 系统
///
/// 新架构核心特性：
/// 1. 共享任务列表 + 自我认领机制
/// 2. Peer-to-Peer 消息系统 (Mailbox)
/// 3. 任务依赖管理
/// 4. 委派模式 (Delegation Mode)
/// 5. 文件锁定机制
pub struct AuditTeamSystem {
    /// 协调器
    coordinator: Coordinator,

    /// 专家列表
    specialists: Vec<Specialist>,

    /// 共享任务列表
    task_list: Arc<shared_task_list::SharedTaskList>,

    /// 消息系统
    mailbox: Arc<mailbox::Mailbox>,

    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 工具注册表
    tools: Arc<ToolRegistry>,

    /// 项目路径
    project_path: Option<String>,
}

impl AuditTeamSystem {
    /// 创建新的审计团队系统
    pub fn new(
        config: AuditTeamConfig,
        llm: Arc<dyn LLMClient>,
        tools: Arc<ToolRegistry>,
    ) -> Self {
        let task_list = Arc::new(SharedTaskList::new());
        let mailbox = Arc::new(Mailbox::new());

        let coordinator_config = config.coordinator.clone();
        let specialist_config = config.specialist.clone();
        let specialties = config.get_specialties();

        let coordinator = Coordinator::new(task_list.clone(), mailbox.clone(), coordinator_config);

        // 创建 Specialists
        let mut specialists = Vec::new();
        for (i, specialty) in specialties.into_iter().enumerate() {
            let spec = Specialist::new(
                format!("specialist-{}", i),
                specialty,
                mailbox.clone(),
                task_list.clone(),
                specialist_config.clone(),
                llm.clone(),
                tools.clone(),
                String::new(), // project_path 会在 start 中设置
            );
            specialists.push(spec);
        }

        Self {
            coordinator,
            specialists,
            task_list,
            mailbox,
            llm,
            tools,
            project_path: None,
        }
    }

    /// 启动系统
    pub async fn start(&mut self, project_path: String) -> anyhow::Result<()> {
        tracing::info!("[AuditTeamSystem] 启动审计团队系统");

        self.project_path = Some(project_path.clone());

        // 更新所有 specialists 的项目路径
        for specialist in &mut self.specialists {
            specialist.update_project_path(project_path.clone());
        }

        // 注册所有 Specialists 到 Mailbox 并启动
        // 每个 specialist 只注册一次，获取接收器后直接 spawn
        for specialist in &mut self.specialists {
            let specialist_id = specialist.id.clone();
            let spec_config = specialist.get_config().clone();
            let spec_specialty = specialist.specialty.clone();

            // 注册到 Mailbox，获取消息接收器
            let rx = self.mailbox.register_specialist(&specialist_id).await;

            // 创建新的 specialist 实例用于 spawn，并设置消息接收器
            let mut spawned_spec = Specialist::new(
                specialist_id.clone(),
                spec_specialty,
                self.mailbox.clone(),
                self.task_list.clone(),
                spec_config,
                self.llm.clone(),
                self.tools.clone(),
                project_path.clone(),
            );
            spawned_spec.set_message_receiver(rx);

            tokio::spawn(async move {
                tracing::info!("[{}] Specialist 启动", specialist_id);
                let _ = spawned_spec.run().await;
            });
        }

        Ok(())
    }

    /// 执行审计
    pub async fn orchestrate_audit(&mut self, project_path: String) -> anyhow::Result<AuditReport> {
        // 如果还没启动，先启动
        if self.project_path.is_none() || self.project_path.as_ref() != Some(&project_path) {
            self.start(project_path.clone()).await?;
        }

        self.coordinator.orchestrate_audit(project_path).await
    }

    /// 获取系统统计
    pub async fn get_stats(&self) -> SystemStats {
        let task_stats = self.task_list.get_stats().await;
        let specialist_count = self.specialists.len();

        SystemStats {
            total_specialists: specialist_count,
            pending_tasks: task_stats.pending,
            in_progress_tasks: task_stats.in_progress,
            completed_tasks: task_stats.completed,
            failed_tasks: task_stats.failed,
        }
    }

    /// 关闭系统
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        tracing::info!("[AuditTeamSystem] 关闭审计团队系统");

        // 向所有 Specialists 发送关闭指令
        for specialist in &self.specialists {
            let _ = self
                .mailbox
                .send_command(
                    &specialist.id,
                    CoordinatorDirective::SuspendTask("shutdown".to_string()),
                )
                .await;
        }

        // 注销所有 Specialists
        for specialist in &self.specialists {
            self.mailbox.unregister_specialist(&specialist.id).await;
        }

        Ok(())
    }
}

/// 系统统计
#[derive(Debug, Clone)]
pub struct SystemStats {
    pub total_specialists: usize,
    pub pending_tasks: usize,
    pub in_progress_tasks: usize,
    pub completed_tasks: usize,
    pub failed_tasks: usize,
}

/// 审计团队配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTeamConfig {
    /// 协调器配置
    pub coordinator: CoordinatorConfig,

    /// 专家配置
    pub specialist: SpecialistConfig,

    /// 专家类型配置
    pub specialists: SpecialistTypesConfig,
}

/// 专家类型配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistTypesConfig {
    /// SQL 注入专家数量
    pub sql_experts: usize,

    /// XSS 专家数量
    pub xss_experts: usize,

    /// 认证专家数量
    pub auth_experts: usize,

    /// 业务逻辑专家数量
    pub business_logic_experts: usize,

    /// 加密专家数量
    pub crypto_experts: usize,

    /// 通用分析师数量
    pub general_analysts: usize,
}

impl SpecialistTypesConfig {
    /// 获取所有专家类型
    pub fn get_specialties(&self) -> Vec<crate::multi_agent::task::AgentSpecialty> {
        use crate::multi_agent::task::AgentSpecialty;

        let mut specialties = Vec::new();

        for _ in 0..self.sql_experts {
            specialties.push(AgentSpecialty::SqlInjectionExpert);
        }
        for _ in 0..self.xss_experts {
            specialties.push(AgentSpecialty::XssExpert);
        }
        for _ in 0..self.auth_experts {
            specialties.push(AgentSpecialty::AuthExpert);
        }
        for _ in 0..self.business_logic_experts {
            specialties.push(AgentSpecialty::BusinessLogicExpert);
        }
        for _ in 0..self.crypto_experts {
            specialties.push(AgentSpecialty::CryptoExpert);
        }
        for _ in 0..self.general_analysts {
            specialties.push(AgentSpecialty::GeneralAnalyst);
        }

        specialties
    }
}

impl AuditTeamConfig {
    /// 创建默认配置
    pub fn default() -> Self {
        Self {
            coordinator: CoordinatorConfig::default(),
            specialist: SpecialistConfig::default(),
            specialists: SpecialistTypesConfig::default(),
        }
    }

    /// 获取所有专家类型
    pub fn get_specialties(&self) -> Vec<crate::multi_agent::task::AgentSpecialty> {
        self.specialists.get_specialties()
    }

    /// 轻量级配置
    pub fn lightweight() -> Self {
        Self {
            coordinator: CoordinatorConfig::default(),
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

    /// 标准配置
    pub fn standard() -> Self {
        Self {
            coordinator: CoordinatorConfig::default(),
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

    /// 重量级配置
    pub fn heavyweight() -> Self {
        Self {
            coordinator: CoordinatorConfig::default(),
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

impl Default for SpecialistTypesConfig {
    fn default() -> Self {
        Self {
            sql_experts: 1,
            xss_experts: 1,
            auth_experts: 1,
            business_logic_experts: 1,
            crypto_experts: 1,
            general_analysts: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specialist_types_config() {
        let config = SpecialistTypesConfig::default();

        // 检查默认配置
        assert_eq!(config.sql_experts, 1);
        assert_eq!(config.xss_experts, 1);
        assert_eq!(config.auth_experts, 1);
        assert_eq!(config.business_logic_experts, 1);
        assert_eq!(config.crypto_experts, 1);
        assert_eq!(config.general_analysts, 1);

        // 检查获取专家类型
        let specialties = config.get_specialties();
        assert_eq!(specialties.len(), 6);
    }

    #[test]
    fn test_audit_team_config_presets() {
        let lightweight = AuditTeamConfig::lightweight();
        assert_eq!(lightweight.specialists.general_analysts, 2);
        assert_eq!(lightweight.specialists.get_specialties().len(), 2);

        let standard = AuditTeamConfig::standard();
        assert_eq!(standard.specialists.get_specialties().len(), 6);

        let heavyweight = AuditTeamConfig::heavyweight();
        assert_eq!(heavyweight.specialists.get_specialties().len(), 10);
    }
}
