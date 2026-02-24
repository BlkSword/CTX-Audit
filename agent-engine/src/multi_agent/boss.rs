// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Boss Agent - 调度中心

use crate::audit_state::{AuditPhase, ProjectInfo, SecurityAuditState, TargetPriority};
use crate::multi_agent::task::{
    AgentSpecialty, AuditTask, EndpointContext, FileContext, TaskPriority, TaskStatus, TaskType,
};
use crate::multi_agent::validator::ValidatedResults;
use crate::multi_agent::worker::{BossCommand, WorkerResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use tokio::sync::{broadcast, mpsc};

/// Boss Agent - 任务调度中心
pub struct BossAgent {
    /// Boss ID
    pub id: String,

    /// 项目路径
    project_path: String,

    /// 项目全局视图
    project_overview: Option<ProjectOverview>,

    /// 任务队列（优先级队列）
    task_queue: VecDeque<AuditTask>,

    /// 待处理任务
    pending_tasks: HashMap<String, AuditTask>,

    /// 运行中的任务
    running_tasks: HashMap<String, RunningTask>,

    /// Worker 状态
    workers: HashMap<String, WorkerState>,

    /// Boss 命令发送器
    command_tx: broadcast::Sender<BossCommand>,

    /// Worker 结果接收器
    result_rx: mpsc::Receiver<WorkerResult>,

    /// 结果收集
    collected_results: Vec<WorkerResult>,

    /// 当前阶段
    current_phase: AuditPhase,

    /// 审计状态
    audit_state: Option<SecurityAuditState>,

    /// 配置
    config: BossConfig,
}

/// Boss 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BossConfig {
    /// 最大并行任务数
    pub max_parallel_tasks: usize,

    /// 任务超时（秒）
    pub task_timeout_secs: u64,

    /// 最大重试次数
    pub max_retries: u32,
}

impl Default for BossConfig {
    fn default() -> Self {
        Self {
            max_parallel_tasks: 4,
            task_timeout_secs: 300,
            max_retries: 2,
        }
    }
}

/// 项目全局视图
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectOverview {
    /// 项目根路径
    pub root_path: String,

    /// 项目类型
    pub project_type: String,

    /// 技术栈
    pub tech_stack: Vec<String>,

    /// 源文件列表
    pub source_files: Vec<FileInfo>,

    /// API 端点列表
    pub api_endpoints: Vec<EndpointInfo>,

    /// 入口点
    pub entry_points: Vec<String>,

    /// 敏感文件
    pub sensitive_files: Vec<String>,

    /// 框架
    pub frameworks: Vec<String>,
}

/// 文件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// 文件路径
    pub path: String,

    /// 语言
    pub language: String,

    /// 大小
    pub size: usize,

    /// 关键函数
    pub key_functions: Vec<String>,

    /// 风险评分
    pub risk_score: f32,
}

/// 端点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointInfo {
    /// 端点路径
    pub path: String,

    /// HTTP 方法
    pub method: String,

    /// 控制器
    pub controller: String,

    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 是否需要认证
    pub auth_required: bool,

    /// 资源 ID 参数
    pub resource_id_param: Option<String>,
}

/// 运行中的任务
#[derive(Debug, Clone)]
struct RunningTask {
    task_id: String,
    worker_id: String,
    started_at: DateTime<Utc>,
}

/// Worker 状态
#[derive(Debug, Clone)]
struct WorkerState {
    id: String,
    specialty: AgentSpecialty,
    status: WorkerStatus,
    current_task_id: Option<String>,
    completed_tasks: usize,
}

/// Worker 状态
#[derive(Debug, Clone, PartialEq, Eq)]
enum WorkerStatus {
    Idle,
    Working,
    Error(String),
}

/// Boss 命令结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BossCommandResult {
    /// 任务已分配
    TaskAssigned { task_id: String, worker_id: String },

    /// 任务已取消
    TaskCancelled { task_id: String },

    /// 错误
    Error(String),
}

impl BossAgent {
    /// 创建新的 Boss Agent
    pub fn new(
        project_path: String,
        command_tx: broadcast::Sender<BossCommand>,
        result_rx: mpsc::Receiver<WorkerResult>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            project_path,
            project_overview: None,
            task_queue: VecDeque::new(),
            pending_tasks: HashMap::new(),
            running_tasks: HashMap::new(),
            workers: HashMap::new(),
            command_tx,
            result_rx,
            collected_results: Vec::new(),
            current_phase: AuditPhase::Initialization,
            audit_state: None,
            config: BossConfig::default(),
        }
    }

    /// 设置配置
    pub fn with_config(mut self, config: BossConfig) -> Self {
        self.config = config;
        self
    }

    /// 设置审计状态
    pub fn with_audit_state(mut self, state: SecurityAuditState) -> Self {
        self.audit_state = Some(state);
        self
    }

    /// 注册 Worker
    pub fn register_worker(&mut self, worker_id: String, specialty: AgentSpecialty) {
        let specialty_name = format!("{}", specialty);
        self.workers.insert(
            worker_id.clone(),
            WorkerState {
                id: worker_id.clone(),
                specialty,
                status: WorkerStatus::Idle,
                current_task_id: None,
                completed_tasks: 0,
            },
        );
        tracing::info!("[Boss] 注册 Worker: {} ({})", worker_id, specialty_name);
    }

    /// 执行完整审计
    pub async fn orchestrate_audit(&mut self) -> Result<AuditReport, String> {
        tracing::info!("[Boss] 开始审计编排");

        // ========== Phase 1: 项目侦察 ==========
        self.transition_to_phase(AuditPhase::Initialization).await;

        let recon_task = self.create_reconnaissance_task();
        self.dispatch_task(recon_task).await?;

        // 等待侦察完成
        self.wait_for_phase_completion().await?;

        // ========== Phase 2: 任务分解 ==========
        if let Some(overview) = &self.project_overview {
            let tasks = self.decompose_project_into_tasks(overview);
            for task in tasks {
                self.add_task_to_queue(task);
            }
        }

        // ========== Phase 3: 并行分析 ==========
        self.transition_to_phase(AuditPhase::DeepAnalysis).await;

        // 分发任务给 Worker
        while let Some(task) = self.task_queue.pop_front() {
            if self.running_tasks.len() >= self.config.max_parallel_tasks {
                // 等待有 Worker 空闲
                self.wait_for_worker_slot().await;
            }

            self.dispatch_task(task).await?;
        }

        // 等待所有任务完成
        self.wait_for_all_tasks_completion().await;

        // ========== Phase 4: 结果聚合 ==========
        self.transition_to_phase(AuditPhase::Verification).await;

        // 聚合结果在验证阶段进行

        // ========== Phase 5: 生成报告 ==========
        self.transition_to_phase(AuditPhase::Reporting).await;

        let report = self.generate_audit_report()?;

        Ok(report)
    }

    /// 创建侦察任务
    fn create_reconnaissance_task(&self) -> AuditTask {
        AuditTask {
            id: uuid::Uuid::new_v4().to_string(),
            task_type: TaskType::Reconnaissance,
            target: self.project_path.clone(),
            specialty_required: AgentSpecialty::GeneralAnalyst,
            priority: TaskPriority::Critical,
            context: Default::default(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            status: TaskStatus::Pending,
            retry_count: 0,
        }
    }

    /// 将项目分解为任务
    fn decompose_project_into_tasks(&self, overview: &ProjectOverview) -> Vec<AuditTask> {
        let mut tasks = Vec::new();

        // 1. 高风险文件优先
        let mut high_risk_files: Vec<_> = overview
            .source_files
            .iter()
            .filter(|f| f.risk_score > 0.5)
            .collect();
        high_risk_files.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());

        for file in &high_risk_files {
            // 根据文件类型推断所需专家
            let specialties = self.infer_required_specialties(file);

            for specialty in specialties {
                tasks.push(AuditTask::file_analysis(
                    file.path.clone(),
                    specialty,
                    TaskPriority::High,
                ));
            }
        }

        // 2. API 端点业务逻辑分析
        for endpoint in &overview.api_endpoints {
            if endpoint.auth_required {
                // 需要认证的端点更需要业务逻辑分析
                tasks.push(AuditTask::business_logic_analysis(
                    endpoint.path.clone(),
                    TaskPriority::High,
                ));
            }
        }

        // 3. 全局数据流分析
        tasks.push(AuditTask {
            id: uuid::Uuid::new_v4().to_string(),
            task_type: TaskType::GlobalDataFlow,
            target: overview.root_path.clone(),
            specialty_required: AgentSpecialty::GeneralAnalyst,
            priority: TaskPriority::Medium,
            context: Default::default(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            status: TaskStatus::Pending,
            retry_count: 0,
        });

        tasks
    }

    /// 推断所需专家类型
    fn infer_required_specialties(&self, file: &FileInfo) -> Vec<AgentSpecialty> {
        let mut specialties = Vec::new();

        // 根据文件路径和语言推断
        let path_lower = file.path.to_lowercase();

        // 认证相关文件
        if path_lower.contains("auth")
            || path_lower.contains("login")
            || path_lower.contains("user")
            || path_lower.contains("permission")
        {
            specialties.push(AgentSpecialty::AuthExpert);
        }

        // 数据库相关
        if path_lower.contains("db")
            || path_lower.contains("query")
            || path_lower.contains("sql")
            || path_lower.contains("model")
        {
            specialties.push(AgentSpecialty::SqlInjectionExpert);
        }

        // 输入处理
        if path_lower.contains("input") || path_lower.contains("form") || path_lower.contains("upload") {
            specialties.push(AgentSpecialty::XssExpert);
            specialties.push(AgentSpecialty::CommandInjectionExpert);
        }

        // 配置文件
        if path_lower.ends_with(".env")
            || path_lower.ends_with(".config")
            || path_lower.contains("config")
            || path_lower.contains("setting")
        {
            specialties.push(AgentSpecialty::ConfigExpert);
        }

        // 默认通用分析师
        if specialties.is_empty() {
            specialties.push(AgentSpecialty::GeneralAnalyst);
        }

        specialties
    }

    /// 添加任务到队列
    fn add_task_to_queue(&mut self, task: AuditTask) {
        // 按优先级插入
        let priority = task.priority;
        let insert_pos = self
            .task_queue
            .iter()
            .position(|t| t.priority < priority)
            .unwrap_or(self.task_queue.len());

        self.task_queue.insert(insert_pos, task);
    }

    /// 分发任务给 Worker
    async fn dispatch_task(&mut self, task: AuditTask) -> Result<(), String> {
        // 选择最佳 Worker
        let worker_id = self.select_best_worker(&task.specialty_required)
            .ok_or_else(|| "没有可用的 Worker".to_string())?;

        // 发送命令
        let _ = self
            .command_tx
            .send(BossCommand::AssignTask(task.clone()));

        // 更新状态
        self.running_tasks.insert(
            task.id.clone(),
            RunningTask {
                task_id: task.id.clone(),
                worker_id: worker_id.clone(),
                started_at: Utc::now(),
            },
        );

        if let Some(worker) = self.workers.get_mut(&worker_id) {
            worker.status = WorkerStatus::Working;
            worker.current_task_id = Some(task.id.clone());
        }

        tracing::info!(
            "[Boss] 任务 {} 已分配给 Worker {} ({})",
            task.id,
            worker_id,
            task.specialty_required
        );

        Ok(())
    }

    /// 选择最佳 Worker
    fn select_best_worker(&self, specialty: &AgentSpecialty) -> Option<String> {
        // 优先选择专业匹配的空闲 Worker
        if let Some(worker) = self
            .workers
            .values()
            .find(|w| w.specialty == *specialty && w.status == WorkerStatus::Idle)
        {
            return Some(worker.id.clone());
        }

        // 如果没有专业匹配的，选择任意空闲 Worker
        if let Some(worker) = self.workers.values().find(|w| w.status == WorkerStatus::Idle) {
            return Some(worker.id.clone());
        }

        None
    }

    /// 收集 Worker 结果
    pub async fn collect_results(&mut self) -> Vec<WorkerResult> {
        let mut results = Vec::new();

        while let Ok(result) = self.result_rx.try_recv() {
            self.handle_worker_result(result.clone()).await;
            results.push(result);
        }

        results
    }

    /// 处理 Worker 结果
    async fn handle_worker_result(&mut self, result: WorkerResult) {
        // 在移动之前保存需要的值
        let worker_id = result.worker_id.clone();
        let task_id = result.task_id.clone();
        let findings_count = result.findings.len();

        // 更新 Worker 状态
        if let Some(worker) = self.workers.get_mut(&worker_id) {
            worker.status = WorkerStatus::Idle;
            worker.current_task_id = None;
            worker.completed_tasks += 1;
        }

        // 从运行任务中移除
        self.running_tasks.remove(&task_id);

        // 保存结果
        self.collected_results.push(result);

        tracing::info!(
            "[Boss] Worker {} 完成任务 {}，发现 {} 个漏洞",
            worker_id,
            task_id,
            findings_count
        );
    }

    /// 等待阶段完成
    async fn wait_for_phase_completion(&mut self) -> Result<(), String> {
        // 收集结果直到满足条件
        loop {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            let results = self.collect_results().await;

            // 检查是否完成
            if self.current_phase == AuditPhase::Initialization && !results.is_empty() {
                // 侦察阶段完成
                break;
            }
        }

        Ok(())
    }

    /// 等待 Worker 空闲槽位
    async fn wait_for_worker_slot(&mut self) {
        while self.running_tasks.len() >= self.config.max_parallel_tasks {
            self.collect_results().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    /// 等待所有任务完成
    async fn wait_for_all_tasks_completion(&mut self) {
        while !self.running_tasks.is_empty() || !self.task_queue.is_empty() {
            self.collect_results().await;
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    /// 切换阶段
    async fn transition_to_phase(&mut self, new_phase: AuditPhase) {
        let _ = self
            .command_tx
            .send(BossCommand::PhaseTransition(new_phase));

        self.current_phase = new_phase;

        tracing::info!("[Boss] 切换到阶段: {}", new_phase);
    }

    /// 生成审计报告
    fn generate_audit_report(&self) -> Result<AuditReport, String> {
        Ok(AuditReport {
            project_path: self.project_path.clone(),
            generated_at: Utc::now(),
            total_findings: self.collected_results.len(),
            worker_results: self.collected_results.clone(),
            validated_results: None,
            project_overview: self.project_overview.clone(),
        })
    }

    /// 处理验证结果
    pub fn process_validation_results(&mut self, validated: ValidatedResults) {
        if let Some(ref mut report) = self.collected_results.iter_mut().next() {
            // 更新报告（这里简化处理）
        }
    }
}

/// 审计报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// 项目路径
    pub project_path: String,

    /// 生成时间
    pub generated_at: DateTime<Utc>,

    /// 总发现数
    pub total_findings: usize,

    /// Worker 结果
    pub worker_results: Vec<WorkerResult>,

    /// 验证结果
    pub validated_results: Option<ValidatedResults>,

    /// 项目概览
    pub project_overview: Option<ProjectOverview>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boss_config_default() {
        let config = BossConfig::default();
        assert_eq!(config.max_parallel_tasks, 4);
        assert_eq!(config.task_timeout_secs, 300);
        assert_eq!(config.max_retries, 2);
    }

    #[test]
    fn test_infer_specialties() {
        let boss = BossAgent::new(
            "/test/project".to_string(),
            broadcast::channel(10).0,
            tokio::sync::mpsc::channel(10).1,
        );

        let auth_file = FileInfo {
            path: "/src/auth/login.rs".to_string(),
            language: "rust".to_string(),
            size: 1000,
            key_functions: vec![],
            risk_score: 0.7,
        };

        let specialties = boss.infer_required_specialties(&auth_file);
        assert!(specialties.contains(&AgentSpecialty::AuthExpert));
    }
}
