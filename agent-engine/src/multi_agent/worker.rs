// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Worker Agent - 专家执行者

use crate::base::{AgentContext, ToolCallRecord};
use crate::multi_agent::helpers::get_confidence;
use crate::multi_agent::prompts::get_expert_prompt;
use crate::multi_agent::task::{AgentSpecialty, AuditTask, FollowUpRequest, TaskStatus};
use crate::react::executor::{ExecutionConfig, ReactExecutor};
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::FindingData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

/// Worker Agent
pub struct WorkerAgent {
    /// Worker ID
    pub id: String,

    /// 专业领域
    pub specialty: AgentSpecialty,

    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 工具注册表
    tools: Arc<ctx_audit_tools::ToolRegistry>,

    /// Boss 命令接收器
    command_rx: broadcast::Receiver<BossCommand>,

    /// 结果发送器
    result_tx: mpsc::Sender<WorkerResult>,

    /// 工作记忆
    working_memory: HashMap<String, serde_json::Value>,

    /// 当前状态
    status: WorkerStatus,

    /// 执行配置
    config: WorkerConfig,
}

/// Worker 状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerStatus {
    /// 空闲
    Idle,
    /// 工作中
    Working { task_id: String },
    /// 等待协助
    WaitingForAssistance { task_id: String },
    /// 错误
    Error(String),
}

/// Worker 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// 最大迭代次数
    pub max_iterations: Option<u32>,

    /// 任务超时（秒）
    pub task_timeout_secs: u64,

    /// 温度参数
    pub temperature: f32,

    /// 最大 tokens
    pub max_tokens: u32,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            max_iterations: Some(20),
            task_timeout_secs: 300,
            temperature: 0.7,
            max_tokens: 4096,
        }
    }
}

/// Boss 命令
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BossCommand {
    /// 分配任务
    AssignTask(AuditTask),

    /// 请求协助
    RequestAssistance {
        from_worker: String,
        task_id: String,
        reason: String,
    },

    /// 任务优先级调整
    Reprioritize {
        task_id: String,
        new_priority: crate::multi_agent::task::TaskPriority,
    },

    /// 终止任务
    TerminateTask(String),

    /// 阶段切换
    PhaseTransition(crate::audit_state::AuditPhase),

    /// 关闭
    Shutdown,
}

/// Worker 结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    /// Worker ID
    pub worker_id: String,

    /// 任务 ID
    pub task_id: String,

    /// 专业领域
    pub specialty: AgentSpecialty,

    /// 发现的漏洞
    pub findings: Vec<FindingData>,

    /// 置信度
    pub confidence: f32,

    /// 思考笔记
    pub notes: Vec<String>,

    /// 后续请求
    pub requests: Vec<FollowUpRequest>,

    /// 工具调用记录
    pub tool_calls: Vec<ToolCallRecord>,

    /// 错误信息
    pub error: Option<String>,

    /// 完成时间
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

impl WorkerAgent {
    /// 创建新的 Worker Agent
    pub fn new(
        id: String,
        specialty: AgentSpecialty,
        llm: Arc<dyn LLMClient>,
        tools: Arc<ctx_audit_tools::ToolRegistry>,
        command_rx: broadcast::Receiver<BossCommand>,
        result_tx: mpsc::Sender<WorkerResult>,
    ) -> Self {
        Self {
            id,
            specialty,
            llm,
            tools,
            command_rx,
            result_tx,
            working_memory: HashMap::new(),
            status: WorkerStatus::Idle,
            config: WorkerConfig::default(),
        }
    }

    /// 设置配置
    pub fn with_config(mut self, config: WorkerConfig) -> Self {
        self.config = config;
        self
    }

    /// 获取状态
    pub fn get_status(&self) -> WorkerStatus {
        self.status.clone()
    }

    /// Worker 主循环
    pub async fn run(&mut self) {
        tracing::info!("[Worker {} - {}] 启动", self.id, self.specialty);

        loop {
            match self.command_rx.recv().await {
                Ok(BossCommand::AssignTask(task)) => {
                    self.execute_task(task).await;
                }
                Ok(BossCommand::PhaseTransition(phase)) => {
                    self.handle_phase_transition(phase).await;
                }
                Ok(BossCommand::TerminateTask(task_id)) => {
                    if let WorkerStatus::Working { task_id: current } = &self.status {
                        if current == &task_id {
                            self.status = WorkerStatus::Idle;
                            tracing::info!("[Worker {}] 任务 {} 被终止", self.id, task_id);
                        }
                    }
                }
                Ok(BossCommand::Shutdown) => {
                    tracing::info!("[Worker {} - {}] 收到关闭命令", self.id, self.specialty);
                    break;
                }
                Ok(_) => {
                    // 其他命令暂不处理
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!("[Worker {}] 错过 {} 条消息", self.id, count);
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::info!("[Worker {}] Boss 通道关闭", self.id);
                    break;
                }
            }
        }
    }

    /// 执行任务
    async fn execute_task(&mut self, task: AuditTask) {
        let task_id = task.id.clone();
        self.status = WorkerStatus::Working { task_id: task_id.clone() };

        tracing::info!(
            "[Worker {} - {}] 开始任务: {}",
            self.id,
            self.specialty,
            task.target
        );

        // 获取专业提示词
        let system_prompt = get_expert_prompt(&self.specialty);

        // 构建任务上下文
        let context = self.build_agent_context(&task);

        // 构建用户提示
        let user_prompt = self.build_user_prompt(&task);

        // 创建 ReAct 执行器
        let execution_config = ExecutionConfig {
            max_iterations: self.config.max_iterations,
            timeout_secs: Some(self.config.task_timeout_secs),
            enable_streaming: false,
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
        };

        let executor = ReactExecutor::new(
            self.llm.clone(),
            self.tools.clone(),
            execution_config,
        );

        // 执行 ReAct 循环
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(self.config.task_timeout_secs),
            executor.execute(&context, system_prompt, &user_prompt),
        )
        .await;

        let worker_result = match result {
            Ok(Ok(exec_result)) => {
                // 成功完成
                let findings = exec_result.get_findings();
                let tool_calls = exec_result.get_tool_call_records();
                let notes: Vec<String> = exec_result
                    .state
                    .thought_chain
                    .iter()
                    .map(|t| t.thought.clone())
                    .collect();

                let confidence = self.calculate_confidence(&exec_result);
                let requests = self.identify_follow_up_needs(&exec_result, &task);

                WorkerResult {
                    worker_id: self.id.clone(),
                    task_id: task_id.clone(),
                    specialty: self.specialty.clone(),
                    findings,
                    confidence,
                    notes,
                    requests,
                    tool_calls,
                    error: None,
                    completed_at: chrono::Utc::now(),
                }
            }
            Ok(Err(e)) => {
                // 执行错误
                tracing::error!("[Worker {}] 任务执行失败: {}", self.id, e);
                WorkerResult {
                    worker_id: self.id.clone(),
                    task_id: task_id.clone(),
                    specialty: self.specialty.clone(),
                    findings: vec![],
                    confidence: 0.0,
                    notes: vec![],
                    requests: vec![],
                    tool_calls: vec![],
                    error: Some(e),
                    completed_at: chrono::Utc::now(),
                }
            }
            Err(_) => {
                // 超时
                tracing::error!("[Worker {}] 任务执行超时", self.id);
                WorkerResult {
                    worker_id: self.id.clone(),
                    task_id: task_id.clone(),
                    specialty: self.specialty.clone(),
                    findings: vec![],
                    confidence: 0.0,
                    notes: vec![],
                    requests: vec![],
                    tool_calls: vec![],
                    error: Some("任务超时".to_string()),
                    completed_at: chrono::Utc::now(),
                }
            }
        };

        // 发送结果
        let _ = self.result_tx.send(worker_result).await;

        // 更新状态
        self.status = WorkerStatus::Idle;
    }

    /// 构建 Agent 上下文
    fn build_agent_context(&self, task: &AuditTask) -> AgentContext {
        AgentContext {
            project_id: uuid::Uuid::new_v4().to_string(),
            project_path: task.target.clone(),
            session_id: task.id.clone(),
            inherited_context: HashMap::new(),
            user_context: HashMap::new(),
        }
    }

    /// 构建用户提示
    fn build_user_prompt(&self, task: &AuditTask) -> String {
        match task.task_type {
            crate::multi_agent::task::TaskType::FileAnalysis => {
                format!(
                    "请分析文件: {}\n\n\
                     任务: 深度安全审计\n\
                     专业领域: {}\n\
                     优先级: {:?}\n\n\
                     请使用专业工具进行深度分析，发现潜在的安全漏洞。",
                    task.target, self.specialty, task.priority
                )
            }
            crate::multi_agent::task::TaskType::BusinessLogicAnalysis => {
                format!(
                    "请分析端点的业务逻辑安全性: {}\n\n\
                     任务: 业务逻辑漏洞检测\n\
                     专业领域: {}\n\n\
                     请重点检查:\n\
                     - IDOR（不安全的直接对象引用）\n\
                     - 权限绕过（水平/垂直越权）\n\
                     - 状态机异常\n\
                     - 业务规则违反",
                    task.target, self.specialty
                )
            }
            crate::multi_agent::task::TaskType::GlobalDataFlow => {
                format!(
                    "请执行全局数据流分析\n\n\
                     项目路径: {}\n\
                     任务: 跨文件污点追踪\n\
                     专业领域: {}\n\n\
                     请使用 global_taint_analysis 工具追踪完整的数据流路径。",
                    task.target, self.specialty
                )
            }
            crate::multi_agent::task::TaskType::Reconnaissance => {
                format!(
                    "请执行项目侦察: {}\n\n\
                     任务: 项目结构分析\n\
                     请识别:\n\
                     - 项目类型和技术栈\n\
                     - 入口点\n\
                     - 关键文件和函数\n\
                     - 潜在的风险区域",
                    task.target
                )
            }
            _ => {
                format!(
                    "请执行任务: {}\n\n\
                     任务类型: {:?}\n\
                     专业领域: {}",
                    task.target, task.task_type, self.specialty
                )
            }
        }
    }

    /// 计算置信度
    fn calculate_confidence(&self, exec_result: &crate::react::executor::ReactExecutionResult) -> f32 {
        // 基于迭代次数和工具使用情况计算置信度
        let iteration_count = exec_result.state.iteration;
        let tool_usage_count = exec_result.tool_calls.len();

        // 基础置信度
        let base_confidence = 0.5;

        // 迭代次数加成（更多迭代通常意味着更深入的分析）
        let iteration_bonus = (iteration_count as f32 * 0.02).min(0.2);

        // 工具使用加成
        let tool_bonus = (tool_usage_count as f32 * 0.05).min(0.2);

        // 最终置信度
        (base_confidence + iteration_bonus + tool_bonus).min(0.95)
    }

    /// 识别后续需求
    fn identify_follow_up_needs(
        &self,
        exec_result: &crate::react::executor::ReactExecutionResult,
        task: &AuditTask,
    ) -> Vec<FollowUpRequest> {
        let mut requests = Vec::new();

        // 检查是否发现高置信度漏洞
        let has_high_confidence_findings = exec_result
            .get_findings()
            .iter()
            .any(|f| get_confidence(f) > 0.7);

        if has_high_confidence_findings {
            // 建议其他专家确认
            requests.push(FollowUpRequest {
                request_type: crate::multi_agent::task::FollowUpRequestType::ExpertAssistance,
                reason: "发现高置信度漏洞，建议其他专家确认".to_string(),
                suggested_specialty: Some(self.specialty.clone()),
                data: serde_json::json!({
                    "task_id": task.id,
                }),
            });
        }

        // 检查是否需要跨文件分析
        let needs_cross_file = exec_result
            .state
            .thought_chain
            .iter()
            .any(|t| {
                t.thought.contains("跨文件") ||
                t.thought.contains("数据流") ||
                t.thought.contains("调用")
            });

        if needs_cross_file {
            requests.push(FollowUpRequest {
                request_type: crate::multi_agent::task::FollowUpRequestType::GlobalDataFlowRequest,
                reason: "需要跨文件数据流分析".to_string(),
                suggested_specialty: Some(AgentSpecialty::GeneralAnalyst),
                data: serde_json::json!({}),
            });
        }

        requests
    }

    /// 处理阶段转换
    async fn handle_phase_transition(&mut self, _phase: crate::audit_state::AuditPhase) {
        // 可以在这里做阶段切换时的清理工作
        tracing::info!("[Worker {} - {}] 阶段转换", self.id, self.specialty);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.max_iterations, Some(20));
        assert_eq!(config.task_timeout_secs, 300);
    }

    #[test]
    fn test_worker_status() {
        let status_idle = WorkerStatus::Idle;
        let status_working = WorkerStatus::Working {
            task_id: "test-task".to_string(),
        };
        let status_error = WorkerStatus::Error("test error".to_string());

        assert_eq!(status_idle, WorkerStatus::Idle);
        assert_ne!(status_idle, status_working);
        assert!(matches!(status_error, WorkerStatus::Error(_)));
    }
}
