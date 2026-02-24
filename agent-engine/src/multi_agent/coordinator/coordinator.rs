// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Coordinator (协调器)
//!
//! Coordinator-Specialist 架构中的协调器，负责任务分解、依赖管理和结果综合。

use super::{
    SharedTaskList, Mailbox, CoordinatorDirective, AuditPhase,
    shared_task_list::TaskResult, CrossValidationManager, DynamicPriorityManager,
};
use crate::multi_agent::task::{AuditTask, TaskType, TaskPriority, TaskContext, TaskStatus, FileContext, AgentSpecialty, WorkerResult};

// 复用 Boss-Worker 的核心组件
use crate::multi_agent::aggregator::{ResultAggregator, AggregatedResults, AggregatedFinding};
use crate::multi_agent::validator::{CrossValidator, ValidatedResults, ValidationStrategy};

use std::sync::Arc;
use std::collections::HashMap;
use std::time::Duration;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use ctx_audit_tools::FindingData;

/// Coordinator 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    /// 最大并行任务数
    pub max_parallel_tasks: usize,

    /// 监控间隔 (毫秒)
    pub monitoring_interval_ms: u64,

    /// 是否启用委派模式
    pub delegation_mode: bool,

    /// 任务超时时间 (秒)
    pub task_timeout_secs: u64,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            max_parallel_tasks: 5,
            monitoring_interval_ms: 100,
            delegation_mode: true,
            task_timeout_secs: 300,
        }
    }
}

/// 审计报告
///
/// 兼容 Boss-Worker 的报告格式，但使用 Coordinator-Specialist 的统计数据
#[derive(Debug, Clone)]
pub struct AuditReport {
    /// 项目路径
    pub project_path: String,

    /// 生成时间
    pub generated_at: chrono::DateTime<chrono::Utc>,

    /// 总发现数（去重后）
    pub total_findings: usize,

    /// 发现的漏洞列表（来自验证结果）
    pub findings: Vec<FindingData>,

    /// 原始 Worker 结果（兼容性字段）
    pub worker_results: Vec<WorkerResult>,

    /// 验证结果（使用 Boss-Worker 的 CrossValidator）
    pub validated_results: Option<ValidatedResults>,

    /// 审计统计
    pub stats: AuditStatistics,

    /// 元数据
    pub metadata: ReportMetadata,
}

/// 发现摘要（内部使用）
#[derive(Debug, Clone)]
pub struct FindingSummary {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub confidence: f32,
    pub location: String,
    pub description: String,
}

impl From<FindingSummary> for FindingData {
    fn from(summary: FindingSummary) -> Self {
        let mut extra = std::collections::HashMap::new();
        extra.insert("confidence".to_string(), serde_json::json!(summary.confidence));

        FindingData {
            id: Some(summary.id),
            title: Some(summary.title),
            description: summary.description,
            severity: summary.severity.to_lowercase(),
            category: "security".to_string(),
            cwe_id: None,
            file_path: summary.location.clone(),
            start_line: 0,
            end_line: None,
            code_snippet: None,
            recommendation: None,
            status: "detected".to_string(),
            verification_status: None,
            discovered_by: None,
            extra,
        }
    }
}

/// 审计统计
#[derive(Debug, Clone)]
pub struct AuditStatistics {
    pub total_tasks: usize,
    pub completed_tasks: usize,
    pub failed_tasks: usize,
    pub total_findings: usize,
    pub duration_secs: u64,
}

/// 报告元数据
#[derive(Debug, Clone)]
pub struct ReportMetadata {
    pub project_path: String,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub specialist_count: usize,
}

/// Coordinator (协调器)
///
/// 核心职责：
/// 1. 任务分解与依赖管理
/// 2. 监控任务进度
/// 3. 处理协助请求
/// 4. 结果综合（使用 ResultAggregator）
/// 5. 交叉验证（使用 CrossValidator，复用 Boss-Worker）
/// 6. 动态优先级调整
pub struct Coordinator {
    /// 共享任务列表
    task_list: Arc<SharedTaskList>,

    /// 消息系统
    mailbox: Arc<Mailbox>,

    /// Specialist 注册表
    specialists: HashMap<String, SpecialistState>,

    /// 配置
    config: CoordinatorConfig,

    /// 当前阶段
    current_phase: AuditPhase,

    /// 交叉验证管理器（新架构）
    validation_manager: Arc<CrossValidationManager>,

    /// 动态优先级管理器
    priority_manager: Arc<DynamicPriorityManager>,

    /// 项目路径
    project_path: Option<String>,

    /// 侦察结果
    reconnaissance_result: Option<ReconnaissanceResult>,

    // ========== 复用 Boss-Worker 的核心组件 ==========
    /// 结果聚合器（复用 Boss-Worker）
    aggregator: ResultAggregator,

    /// 交叉验证器（复用 Boss-Worker）
    validator: CrossValidator,
}

/// Specialist 状态
#[derive(Debug, Clone)]
struct SpecialistState {
    pub id: String,
    pub specialty: AgentSpecialty,
    pub status: String,
    pub current_task: Option<String>,
}

/// 侦察结果
#[derive(Debug, Clone)]
struct ReconnaissanceResult {
    pub project_type: String,
    pub tech_stack: Vec<String>,
    pub files: Vec<FileInfo>,
    pub endpoints: Vec<EndpointInfo>,
    pub attack_surface: Vec<String>,
}

#[derive(Debug, Clone)]
struct FileInfo {
    pub path: String,
    pub language: String,
    pub size: usize,
    pub is_entry_point: bool,
}

#[derive(Debug, Clone)]
struct EndpointInfo {
    pub path: String,
    pub method: String,
    pub controller: String,
}

impl Coordinator {
    /// 创建新的协调器
    pub fn new(
        task_list: Arc<SharedTaskList>,
        mailbox: Arc<Mailbox>,
        config: CoordinatorConfig,
    ) -> Self {
        let validation_manager = Arc::new(CrossValidationManager::new());
        let priority_manager = Arc::new(DynamicPriorityManager::new(config.task_timeout_secs));

        // 复用 Boss-Worker 的核心组件
        let aggregator = ResultAggregator::new();
        let validator = CrossValidator::new()
            .with_strategy(ValidationStrategy::MultiExpertConsensus { min_experts: 2 });

        Self {
            task_list,
            mailbox,
            specialists: HashMap::new(),
            config,
            current_phase: AuditPhase::Initialization,
            validation_manager,
            priority_manager,
            project_path: None,
            reconnaissance_result: None,
            aggregator,
            validator,
        }
    }

    /// 注册 Specialist
    pub async fn register_specialist(&mut self, specialist_id: String, specialty: AgentSpecialty) {
        self.specialists.insert(specialist_id.clone(), SpecialistState {
            id: specialist_id,
            specialty,
            status: "Idle".to_string(),
            current_task: None,
        });
    }

    /// 更新 Specialist 状态
    pub async fn update_specialist_status(&mut self, specialist_id: &str, status: String, current_task: Option<String>) {
        if let Some(state) = self.specialists.get_mut(specialist_id) {
            state.status = status;
            state.current_task = current_task;
        }
    }

    /// 编排审计
    pub async fn orchestrate_audit(&mut self, project_path: String) -> Result<AuditReport> {
        let start_time = chrono::Utc::now();
        tracing::info!("[Coordinator] 开始编排审计: {}", project_path);

        self.project_path = Some(project_path.clone());

        // Phase 1: 项目侦察
        self.transition_phase(AuditPhase::Initialization).await;
        let recon_task = self.create_reconnaissance_task(project_path.clone());
        self.task_list.add_task(recon_task).await?;

        // 等待侦察完成
        self.wait_for_reconnaissance().await?;

        // Phase 2: 任务分解 (带依赖管理)
        self.transition_phase(AuditPhase::DeterministicScan).await;
        let tasks = self.decompose_project_with_dependencies().await?;
        for task in tasks {
            self.task_list.add_task(task).await?;
        }

        // Phase 3: 自我协调执行
        self.transition_phase(AuditPhase::DeepAnalysis).await;
        self.monitor_and_coordinate().await?;

        // Phase 4: 结果综合 + 聚合（使用 ResultAggregator）
        self.transition_phase(AuditPhase::Verification).await;

        // 收集所有任务的原始结果
        let worker_results = self.collect_worker_results().await?;

        // 使用 ResultAggregator 进行去重和聚合
        let aggregated = self.aggregator.aggregate(worker_results.clone());

        // 使用 CrossValidator 进行交叉验证（复用 Boss-Worker）
        let validated = self.validator.cross_validate(aggregated);

        tracing::info!(
            "[Coordinator] 验证完成: 确认={}, 需审核={}",
            validated.statistics.confirmed_count,
            validated.statistics.needs_review_count
        );

        // 获取统计数据
        let task_stats = self.task_list.get_stats().await;

        // Phase 5: 生成报告
        self.transition_phase(AuditPhase::Reporting).await;
        let end_time = chrono::Utc::now();
        let duration = (end_time - start_time).num_seconds() as u64;

        Ok(self.generate_report(
            validated,
            worker_results,
            project_path,
            start_time,
            end_time,
            duration,
            task_stats,
        )?)
    }

    /// 切换阶段
    async fn transition_phase(&mut self, phase: AuditPhase) {
        tracing::info!("[Coordinator] 切换阶段: {:?}", phase);
        self.current_phase = phase;

        // 通知所有 Specialists
        let _ = self.mailbox.broadcast(
            "coordinator",
            super::mailbox::MessageContent::TaskCompleted {
                task_id: format!("phase-{:?}", phase),
                success: true,
                summary: format!("进入阶段: {:?}", phase),
            }
        ).await;
    }

    /// 创建侦察任务
    fn create_reconnaissance_task(&self, project_path: String) -> AuditTask {
        let mut task = AuditTask::new(
            TaskType::Reconnaissance,
            project_path.clone(),
            AgentSpecialty::GeneralAnalyst,
            TaskPriority::Critical,
        );
        task.target = project_path;
        task
    }

    /// 等待侦察完成
    async fn wait_for_reconnaissance(&mut self) -> Result<()> {
        loop {
            let all_tasks = self.task_list.get_all_tasks().await;
            let recon_done = all_tasks.iter()
                .filter(|t| t.task_type == TaskType::Reconnaissance)
                .all(|t| matches!(t.status, TaskStatus::Completed | TaskStatus::Failed));

            if recon_done {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // 模拟侦察结果 (实际应该从任务结果获取)
        self.reconnaissance_result = Some(self.simulate_reconnaissance_result());

        Ok(())
    }

    /// 模拟侦察结果 (实际应该从 Recon Agent 获取)
    fn simulate_reconnaissance_result(&self) -> ReconnaissanceResult {
        let project_path = self.project_path.as_ref().map(|s| s.as_str()).unwrap_or("");

        ReconnaissanceResult {
            project_type: "Web Application".to_string(),
            tech_stack: vec!["TypeScript".to_string(), "Node.js".to_string(), "Express".to_string()],
            files: vec![
                FileInfo {
                    path: format!("{}/src/index.ts", project_path),
                    language: "TypeScript".to_string(),
                    size: 1024,
                    is_entry_point: true,
                },
                FileInfo {
                    path: format!("{}/src/routes/auth.ts", project_path),
                    language: "TypeScript".to_string(),
                    size: 2048,
                    is_entry_point: false,
                },
                FileInfo {
                    path: format!("{}/src/routes/users.ts", project_path),
                    language: "TypeScript".to_string(),
                    size: 1536,
                    is_entry_point: false,
                },
            ],
            endpoints: vec![
                EndpointInfo {
                    path: "/api/auth/login".to_string(),
                    method: "POST".to_string(),
                    controller: "AuthController".to_string(),
                },
                EndpointInfo {
                    path: "/api/users/:id".to_string(),
                    method: "GET".to_string(),
                    controller: "UserController".to_string(),
                },
            ],
            attack_surface: vec![
                "用户输入: login form".to_string(),
                "API 端点: /api/*".to_string(),
                "数据库查询".to_string(),
            ].into_iter().collect(),
        }
    }

    /// 分解项目任务（带依赖关系）
    async fn decompose_project_with_dependencies(&self) -> Result<Vec<AuditTask>> {
        let mut tasks = Vec::new();

        if let Some(ref recon) = self.reconnaissance_result {
            // 根据侦察结果创建文件分析任务
            for file in &recon.files {
                let priority = if file.is_entry_point {
                    TaskPriority::Critical
                } else {
                    TaskPriority::High
                };

                let specialty = self.determine_specialty_for_file(&file.language);
                let mut task = AuditTask::new(TaskType::FileAnalysis, file.path.clone(), specialty, priority);
                task.context = TaskContext {
                    file_info: Some(FileContext {
                        path: file.path.clone(),
                        language: file.language.clone(),
                        size: file.size,
                        key_functions: vec![],
                        related_candidates: vec![],
                    }),
                    ..Default::default()
                };
                tasks.push(task);
            }

            // 创建端点分析任务
            for endpoint in &recon.endpoints {
                let mut task = AuditTask::new(
                    TaskType::BusinessLogicAnalysis,
                    endpoint.path.clone(),
                    AgentSpecialty::AuthExpert,
                    TaskPriority::High,
                );
                task.context = TaskContext {
                    endpoint_info: Some(crate::multi_agent::task::EndpointContext {
                        path: endpoint.path.clone(),
                        method: endpoint.method.clone(),
                        controller: endpoint.controller.clone(),
                        auth_required: endpoint.path.contains("/auth"),
                        resource_id_param: endpoint.path.contains(":id").then(|| "id".to_string()),
                    }),
                    ..Default::default()
                };
                tasks.push(task);
            }

            // 创建全局数据流任务
            let dataflow_task = AuditTask::new(
                TaskType::GlobalDataFlow,
                "global-dataflow".to_string(),
                AgentSpecialty::GeneralAnalyst,
                TaskPriority::High,
            );
            tasks.push(dataflow_task);
        }

        // 添加依赖关系
        let file_task_ids: Vec<String> = tasks.iter()
            .filter(|t| t.task_type == TaskType::FileAnalysis)
            .map(|t| t.id.clone())
            .collect();

        for task in &mut tasks {
            if task.task_type == TaskType::GlobalDataFlow {
                for file_id in &file_task_ids {
                    self.task_list.add_dependency(&task.id, file_id).await;
                }
            }
        }

        // 创建验证任务
        let verification_task = AuditTask::new(
            TaskType::VulnerabilityVerification,
            "verification".to_string(),
            AgentSpecialty::GeneralAnalyst,
            TaskPriority::High,
        );
        tasks.push(verification_task);

        tracing::info!("[Coordinator] 分解了 {} 个任务", tasks.len());

        Ok(tasks)
    }

    /// 确定文件的专家类型
    fn determine_specialty_for_file(&self, language: &str) -> AgentSpecialty {
        match language {
            "SQL" | "sql" => AgentSpecialty::SqlInjectionExpert,
            l if l.contains("TypeScript") || l.contains("JavaScript") => AgentSpecialty::XssExpert,
            l if l.contains("Python") => AgentSpecialty::SqlInjectionExpert,
            _ => AgentSpecialty::GeneralAnalyst,
        }
    }

    /// 监控和协调 (委派模式核心)
    async fn monitor_and_coordinate(&mut self) -> Result<()> {
        let interval = Duration::from_millis(self.config.monitoring_interval_ms);
        let mut check_count = 0;
        let max_checks = 3000; // 5 分钟超时 (100ms * 3000)

        loop {
            // 处理协助请求
            self.process_assistance_requests().await?;

            // 检查任务进度
            self.check_task_progress().await?;

            // 检查即将超时的任务
            let boosted = self.priority_manager.check_and_boost_near_timeout(60).await;
            for task_id in boosted {
                tracing::warn!("[Coordinator] 任务即将超时，已提升优先级: {}", task_id);
            }

            // 检查是否所有任务完成
            if self.all_tasks_completed().await? {
                break;
            }

            check_count += 1;
            if check_count >= max_checks {
                tracing::warn!("[Coordinator] 监控超时，强制进入下一阶段");
                break;
            }

            tokio::time::sleep(interval).await;
        }

        Ok(())
    }

    /// 处理协助请求
    async fn process_assistance_requests(&mut self) -> Result<()> {
        // 从 Mailbox 获取消息并处理
        let messages = self.mailbox.get_message_history().await;

        for msg in messages.iter() {
            if let super::mailbox::Message::Direct { from, content, .. } = msg {
                if let super::mailbox::MessageContent::AssistanceRequest { task_id, reason, suggested_specialty } = content {
                    tracing::info!("[Coordinator] 来自 {} 的协助请求: {} - {}", from, task_id, reason);

                    // 根据请求类型分配给合适的 Specialist
                    if let Some(specialty_str) = suggested_specialty {
                        let specialty = self.parse_specialty(specialty_str);
                        if let Some(spec_id) = self.find_available_specialist(&specialty).await {
                            let _ = self.mailbox.send_command(
                                &spec_id,
                                CoordinatorDirective::ResumeTask(task_id.clone()),
                            ).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 解析专业领域
    fn parse_specialty(&self, specialty_str: &str) -> AgentSpecialty {
        // 简化解析，实际应该更完善
        if specialty_str.contains("SQL") {
            AgentSpecialty::SqlInjectionExpert
        } else if specialty_str.contains("XSS") {
            AgentSpecialty::XssExpert
        } else if specialty_str.contains("Auth") {
            AgentSpecialty::AuthExpert
        } else if specialty_str.contains("Business") {
            AgentSpecialty::BusinessLogicExpert
        } else if specialty_str.contains("Crypto") {
            AgentSpecialty::CryptoExpert
        } else {
            AgentSpecialty::GeneralAnalyst
        }
    }

    /// 检查任务进度
    async fn check_task_progress(&self) -> Result<()> {
        let stats = self.task_list.get_stats().await;
        tracing::debug!(
            "[Coordinator] 任务进度: 待处理={}, 进行中={}, 完成={}, 失败={}",
            stats.pending,
            stats.in_progress,
            stats.completed,
            stats.failed
        );
        Ok(())
    }

    /// 查找可用的 Specialist (实现)
    async fn find_available_specialist(&self, specialty: &AgentSpecialty) -> Option<String> {
        for (_id, state) in &self.specialists {
            // 检查是否匹配专业领域
            if state.specialty == *specialty || *specialty == AgentSpecialty::GeneralAnalyst {
                // 检查是否空闲
                if state.status == "Idle" {
                    return Some(state.id.clone());
                }
            }
        }
        None
    }

    /// 检查所有任务是否完成
    async fn all_tasks_completed(&self) -> Result<bool> {
        Ok(self.task_list.all_tasks_completed().await)
    }

    /// 收集所有任务的原始结果（转换为 WorkerResult 格式）
    async fn collect_worker_results(&self) -> Result<Vec<WorkerResult>> {
        let tasks = self.task_list.get_all_tasks().await;
        let mut worker_results = Vec::new();

        for task in tasks {
            if matches!(task.status, TaskStatus::Completed) {
                // 从任务结果中提取发现
                if let Some(task_result) = self.task_list.get_task_result(&task.id).await {
                    // 转换为 WorkerResult 格式
                    let findings = self.extract_findings_from_task_result(&task_result);

                    worker_results.push(WorkerResult {
                        worker_id: self.find_specialist_for_task(&task.id).await.unwrap_or_else(|| "unknown".to_string()),
                        specialty: task.specialty_required.clone(),
                        task_id: task.id.clone(),
                        findings,
                        confidence: 0.7, // 默认置信度
                        notes: vec![],
                        requests: vec![],
                        tool_calls: vec![],
                        error: None,
                        completed_at: chrono::Utc::now(),
                    });
                }
            }
        }

        tracing::info!("[Coordinator] 收集了 {} 个 Worker 结果", worker_results.len());
        Ok(worker_results)
    }

    /// 查找执行任务的 Specialist
    async fn find_specialist_for_task(&self, task_id: &str) -> Option<String> {
        // 从 specialists 状态中查找
        for (id, state) in &self.specialists {
            if state.current_task.as_ref() == Some(&task_id.to_string()) {
                return Some(id.clone());
            }
        }

        // 如果找不到，尝试根据任务ID推断
        // 实际实现中应该在 Specialist 状态中记录完成的任务
        None
    }

    /// 从任务结果中提取发现
    fn extract_findings_from_task_result(&self, task_result: &TaskResult) -> Vec<FindingData> {
        // 将 serde_json::Value 转换为 FindingData
        task_result.findings.iter().filter_map(|v| {
            serde_json::from_value::<FindingData>(v.clone()).ok()
        }).collect()
    }

    /// 综合结果（保留用于向后兼容）
    async fn synthesize_results(&self) -> Result<Vec<FindingSummary>> {
        let tasks = self.task_list.get_all_tasks().await;

        // 从所有完成的任务中提取发现
        let mut findings = Vec::new();

        for task in tasks {
            if matches!(task.status, TaskStatus::Completed) {
                // 创建示例发现 (实际应该从任务结果中提取)
                findings.push(FindingSummary {
                    id: format!("finding-{}", task.id),
                    title: format!("{} 分析结果", task.target),
                    severity: "Medium".to_string(),
                    confidence: 0.75,
                    location: task.target,
                    description: format!("任务类型: {:?}", task.task_type),
                });
            }
        }

        tracing::info!("[Coordinator] 综合了 {} 个发现", findings.len());
        Ok(findings)
    }

    /// 生成报告（使用验证结果）
    fn generate_report(
        &self,
        validated: ValidatedResults,
        worker_results: Vec<WorkerResult>,
        project_path: String,
        start_time: chrono::DateTime<chrono::Utc>,
        end_time: chrono::DateTime<chrono::Utc>,
        duration: u64,
        task_stats: super::shared_task_list::TaskListStats,
    ) -> Result<AuditReport> {
        // 从验证结果中提取所有发现（包括已确认和需审核的）
        let findings: Vec<FindingData> = validated.confirmed
            .iter()
            .chain(validated.needs_review.iter())
            .map(|v| v.finding.clone())
            .collect();

        // 计算统计数据
        let stats = AuditStatistics {
            total_tasks: task_stats.total,
            completed_tasks: task_stats.completed,
            failed_tasks: task_stats.failed,
            total_findings: findings.len(),
            duration_secs: duration,
        };

        Ok(AuditReport {
            project_path: project_path.clone(),
            generated_at: end_time,
            total_findings: findings.len(),
            findings,
            worker_results,
            validated_results: Some(validated),
            stats,
            metadata: ReportMetadata {
                project_path,
                start_time,
                end_time,
                specialist_count: self.specialists.len(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_coordinator_creation() {
        let task_list = Arc::new(SharedTaskList::new());
        let mailbox = Arc::new(Mailbox::new());
        let config = CoordinatorConfig::default();

        let coordinator = Coordinator::new(task_list, mailbox, config);

        assert_eq!(coordinator.specialists.len(), 0);
    }

    #[tokio::test]
    async fn test_specialist_registration() {
        let task_list = Arc::new(SharedTaskList::new());
        let mailbox = Arc::new(Mailbox::new());
        let mut coordinator = Coordinator::new(task_list, mailbox, CoordinatorConfig::default());

        coordinator.register_specialist("spec-1".to_string(), AgentSpecialty::SqlInjectionExpert).await;
        assert_eq!(coordinator.specialists.len(), 1);
        assert_eq!(coordinator.specialists["spec-1"].specialty, AgentSpecialty::SqlInjectionExpert);
    }

    #[tokio::test]
    async fn test_find_available_specialist() {
        let task_list = Arc::new(SharedTaskList::new());
        let mailbox = Arc::new(Mailbox::new());
        let mut coordinator = Coordinator::new(task_list, mailbox, CoordinatorConfig::default());

        coordinator.register_specialist("sql-1".to_string(), AgentSpecialty::SqlInjectionExpert).await;
        coordinator.register_specialist("xss-1".to_string(), AgentSpecialty::XssExpert).await;

        // 查找 SQL 专家
        let found = coordinator.find_available_specialist(&AgentSpecialty::SqlInjectionExpert).await;
        assert_eq!(found, Some("sql-1".to_string()));

        // 查找不存在的专家
        let not_found = coordinator.find_available_specialist(&AgentSpecialty::AuthExpert).await;
        assert_eq!(not_found, None);
    }

    #[tokio::test]
    async fn test_phase_transition() {
        let task_list = Arc::new(SharedTaskList::new());
        let mailbox = Arc::new(Mailbox::new());
        let mut coordinator = Coordinator::new(task_list, mailbox, CoordinatorConfig::default());

        coordinator.transition_phase(AuditPhase::DeepAnalysis).await;
        assert!(matches!(coordinator.current_phase, AuditPhase::DeepAnalysis));
    }
}
