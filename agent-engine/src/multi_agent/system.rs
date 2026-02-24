// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 多 Agent 系统架构

use crate::audit_state::SecurityAuditState;
use crate::multi_agent::boss::{BossAgent, BossConfig};
use crate::multi_agent::task::AgentSpecialty;
use crate::multi_agent::validator::{CrossValidator, ValidationStrategy};
use crate::multi_agent::{
    aggregator::ResultAggregator, prompts::get_expert_name, worker::WorkerAgent,
};
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::ToolRegistry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

/// 多 Agent 系统
pub struct MultiAgentSystem {
    /// Boss Agent
    boss: BossAgent,

    /// Worker 信息（用于跟踪，不包含实际的 WorkerAgent）
    worker_infos: Vec<WorkerInfo>,

    /// Worker 任务句柄
    worker_handles: Vec<JoinHandle<()>>,

    /// 结果聚合器
    aggregator: ResultAggregator,

    /// 交叉验证器
    validator: CrossValidator,

    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 工具注册表
    tools: Arc<ToolRegistry>,

    /// 配置
    config: MultiAgentConfig,

    /// 通信通道
    channels: AgentChannels,
}

/// Worker 信息
#[derive(Debug, Clone)]
struct WorkerInfo {
    id: String,
    specialty: AgentSpecialty,
}

/// Agent 通信通道
#[derive(Debug)]
pub struct AgentChannels {
    /// Boss 命令发送器
    pub command_tx: broadcast::Sender<super::worker::BossCommand>,

    /// Worker 结果发送器
    pub result_tx: mpsc::Sender<super::worker::WorkerResult>,

    /// Boss 结果接收器
    pub result_rx: mpsc::Receiver<super::worker::WorkerResult>,
}

/// 系统配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentConfig {
    /// Worker 数量
    pub worker_count: usize,

    /// 专家配置
    pub specialist_config: SpecialistConfig,

    /// 最大并行任务数
    pub max_parallel_tasks: usize,

    /// 任务超时（秒）
    pub task_timeout_secs: u64,

    /// Boss 配置
    pub boss_config: BossConfig,
}

/// 专家配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistConfig {
    pub sql_experts: usize,
    pub xss_experts: usize,
    pub auth_experts: usize,
    pub business_logic_experts: usize,
    pub crypto_experts: usize,
    pub general_analysts: usize,
}

impl Default for SpecialistConfig {
    fn default() -> Self {
        Self {
            sql_experts: 1,
            xss_experts: 1,
            auth_experts: 1,
            business_logic_experts: 1,
            crypto_experts: 0,
            general_analysts: 2,
        }
    }
}

impl Default for MultiAgentConfig {
    fn default() -> Self {
        Self {
            worker_count: 6,
            specialist_config: SpecialistConfig::default(),
            max_parallel_tasks: 4,
            task_timeout_secs: 300,
            boss_config: BossConfig::default(),
        }
    }
}

/// 多 Agent 系统统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentStats {
    /// 总任务数
    pub total_tasks: usize,

    /// 已完成任务数
    pub completed_tasks: usize,

    /// 运行中任务数
    pub running_tasks: usize,

    /// 总发现数
    pub total_findings: usize,

    /// 系统运行时间（秒）
    pub uptime_secs: u64,

    /// 各 Worker 统计
    pub worker_stats: Vec<WorkerStats>,
}

/// Worker 统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStats {
    /// Worker ID
    pub worker_id: String,

    /// 专业领域
    pub specialty: AgentSpecialty,

    /// 已完成任务数
    pub completed_tasks: usize,

    /// 当前状态
    pub status: String,
}

impl MultiAgentSystem {
    /// 创建新的多 Agent 系统
    pub async fn new(
        llm: Arc<dyn LLMClient>,
        tools: Arc<ToolRegistry>,
        config: MultiAgentConfig,
    ) -> Result<Self, String> {
        // 创建通信通道
        let (command_tx, _) = broadcast::channel(1000);
        let (result_tx, result_rx_for_boss) = mpsc::channel(1000);
        let (_, result_rx_for_system) = mpsc::channel(1000); // 系统自己保留一个接收器

        let channels = AgentChannels {
            command_tx,
            result_tx: result_tx.clone(),
            result_rx: result_rx_for_system,
        };

        // 创建聚合器和验证器
        let aggregator = ResultAggregator::new();
        let validator = CrossValidator::new().with_strategy(ValidationStrategy::MultiExpertConsensus {
            min_experts: 2,
        });

        Ok(Self {
            boss: BossAgent::new(
                String::new(), // 稍后设置
                channels.command_tx.clone(),
                result_rx_for_boss,
            ),
            worker_infos: Vec::new(),
            worker_handles: Vec::new(),
            aggregator,
            validator,
            llm,
            tools,
            config,
            channels,
        })
    }

    /// 启动系统
    pub async fn start(&mut self, project_path: String) -> Result<(), String> {
        tracing::info!("[MultiAgentSystem] 启动多 Agent 系统");

        // 重新创建 Boss（因为项目路径是必需的）
        self.boss = BossAgent::new(
            project_path.clone(),
            self.channels.command_tx.clone(),
            // 注意：result_rx 已经被消费，需要重新创建
            tokio::sync::mpsc::channel(100).1,
        );

        // 创建并启动 Workers
        // 提前复制配置值，避免借用检查问题
        let spec = self.config.specialist_config.clone();

        // SQL 专家
        for i in 0..spec.sql_experts {
            self.spawn_worker(
                format!("sql-expert-{}", i),
                AgentSpecialty::SqlInjectionExpert,
            )
            .await?;
        }

        // XSS 专家
        for i in 0..spec.xss_experts {
            self.spawn_worker(
                format!("xss-expert-{}", i),
                AgentSpecialty::XssExpert,
            )
            .await?;
        }

        // 认证专家
        for i in 0..spec.auth_experts {
            self.spawn_worker(
                format!("auth-expert-{}", i),
                AgentSpecialty::AuthExpert,
            )
            .await?;
        }

        // 业务逻辑专家
        for i in 0..spec.business_logic_experts {
            self.spawn_worker(
                format!("biz-logic-expert-{}", i),
                AgentSpecialty::BusinessLogicExpert,
            )
            .await?;
        }

        // 密码学专家
        for i in 0..spec.crypto_experts {
            self.spawn_worker(
                format!("crypto-expert-{}", i),
                AgentSpecialty::CryptoExpert,
            )
            .await?;
        }

        // 通用分析师
        for i in 0..spec.general_analysts {
            self.spawn_worker(
                format!("analyst-{}", i),
                AgentSpecialty::GeneralAnalyst,
            )
            .await?;
        }

        // 向 Boss 注册所有 Workers
        for worker_info in &self.worker_infos {
            self.boss.register_worker(worker_info.id.clone(), worker_info.specialty.clone());
        }

        tracing::info!(
            "[MultiAgentSystem] 多 Agent 系统已启动，共 {} 个 Worker",
            self.worker_infos.len()
        );

        Ok(())
    }

    /// 生成并启动 Worker
    async fn spawn_worker(
        &mut self,
        id: String,
        specialty: AgentSpecialty,
    ) -> Result<(), String> {
        tracing::info!("[MultiAgentSystem] 创建 Worker: {} ({})", id, specialty);

        let worker = WorkerAgent::new(
            id.clone(),
            specialty.clone(),
            self.llm.clone(),
            self.tools.clone(),
            self.channels.command_tx.subscribe(),
            self.channels.result_tx.clone(),
        );

        // 启动 Worker 任务（直接将 worker 移动到 async 块中）
        let handle = tokio::spawn(async move {
            let mut w = worker;
            w.run().await;
        });

        self.worker_handles.push(handle);
        // 保存 WorkerInfo 而不是 WorkerAgent
        self.worker_infos.push(WorkerInfo {
            id: id.clone(),
            specialty,
        });

        Ok(())
    }

    /// 执行审计
    pub async fn audit(
        &mut self,
        project_path: String,
        audit_state: SecurityAuditState,
    ) -> Result<AuditReport, String> {
        // 设置 Boss 审计状态
        // 由于 BossAgent 不实现 Clone，我们需要重新创建 Boss
        let current_boss = std::mem::replace(
            &mut self.boss,
            BossAgent::new(
                project_path.clone(),
                self.channels.command_tx.clone(),
                tokio::sync::mpsc::channel(100).1,
            ),
        );
        self.boss = current_boss.with_audit_state(audit_state);

        // 执行编排
        let report = self.boss.orchestrate_audit().await?;

        // 聚合结果
        let aggregated = self.aggregator.aggregate(report.worker_results.clone());

        // 交叉验证
        let validated = self.validator.cross_validate(aggregated);

        // 构建最终报告
        let final_report = AuditReport {
            project_path: report.project_path,
            generated_at: report.generated_at,
            total_findings: validated.statistics.total_validated,
            worker_results: report.worker_results,
            validated_results: Some(validated),
            project_overview: report.project_overview,
        };

        Ok(final_report)
    }

    /// 关闭系统
    pub async fn shutdown(&mut self) {
        tracing::info!("[MultiAgentSystem] 关闭多 Agent 系统");

        // 发送关闭命令给所有 Workers
        let _ = self
            .channels
            .command_tx
            .send(super::worker::BossCommand::Shutdown);

        // 等待所有 Workers 完成
        for handle in self.worker_handles.drain(..) {
            let _ = handle.await;
        }

        tracing::info!("[MultiAgentSystem] 所有 Workers 已关闭");
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> MultiAgentStats {
        let worker_stats: Vec<WorkerStats> = self
            .worker_infos
            .iter()
            .map(|w| WorkerStats {
                worker_id: w.id.clone(),
                specialty: w.specialty.clone(),
                completed_tasks: 0, // 需要从 Boss 获取
                status: "Idle".to_string(),
            })
            .collect();

        MultiAgentStats {
            total_tasks: 0,
            completed_tasks: 0,
            running_tasks: 0,
            total_findings: 0,
            uptime_secs: 0,
            worker_stats,
        }
    }
}

/// 审计报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// 项目路径
    pub project_path: String,

    /// 生成时间
    pub generated_at: chrono::DateTime<chrono::Utc>,

    /// 总发现数
    pub total_findings: usize,

    /// Worker 结果
    pub worker_results: Vec<super::worker::WorkerResult>,

    /// 验证结果
    pub validated_results: Option<super::validator::ValidatedResults>,

    /// 项目概览
    pub project_overview: Option<super::boss::ProjectOverview>,
}

impl AuditReport {
    /// 获取确认的发现
    pub fn get_confirmed_findings(&self) -> Vec<ctx_audit_tools::FindingData> {
        if let Some(ref validated) = self.validated_results {
            validated
                .confirmed
                .iter()
                .map(|f| f.finding.clone())
                .collect()
        } else {
            self.worker_results
                .iter()
                .flat_map(|r| r.findings.clone())
                .collect()
        }
    }

    /// 获取需要审核的发现
    pub fn get_findings_needing_review(&self) -> Vec<ctx_audit_tools::FindingData> {
        if let Some(ref validated) = self.validated_results {
            validated
                .needs_review
                .iter()
                .map(|f| f.finding.clone())
                .collect()
        } else {
            vec![]
        }
    }

    /// 生成摘要
    pub fn generate_summary(&self) -> String {
        let mut summary = format!(
            "=== 审计报告 ===\n\
             项目路径: {}\n\
             生成时间: {}\n\
             总发现数: {}\n",
            self.project_path,
            self.generated_at.format("%Y-%m-%d %H:%M:%S"),
            self.total_findings
        );

        if let Some(ref validated) = self.validated_results {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_agent_config_default() {
        let config = MultiAgentConfig::default();
        assert_eq!(config.worker_count, 6);
        assert_eq!(config.max_parallel_tasks, 4);
        assert_eq!(config.task_timeout_secs, 300);
    }

    #[test]
    fn test_specialist_config_default() {
        let config = SpecialistConfig::default();
        assert_eq!(config.sql_experts, 1);
        assert_eq!(config.xss_experts, 1);
        assert_eq!(config.auth_experts, 1);
        assert_eq!(config.business_logic_experts, 1);
        assert_eq!(config.crypto_experts, 0);
        assert_eq!(config.general_analysts, 2);
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
}
