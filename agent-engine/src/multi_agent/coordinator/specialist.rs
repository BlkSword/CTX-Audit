// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Specialist (专家)
//!
//! Coordinator-Specialist 架构中的专家 Agent，负责认领和执行特定领域的审计任务。

use super::{
    SharedTaskList, Mailbox, Message, MessageContent, CoordinatorDirective,
    shared_task_list::TaskResult, AuditPhase, InternalFinding,
};
use crate::multi_agent::task::{AgentSpecialty, AuditTask, TaskStatus};
use crate::base::AgentContext;
use crate::react::{ReactExecutor, ExecutionConfig, ReactExecutionResult};
use crate::multi_agent::prompts::get_expert_prompt;
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::ToolRegistry;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Specialist 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistConfig {
    /// 最大重试次数
    pub max_retries: usize,

    /// 任务超时时间 (秒)
    pub task_timeout_secs: u64,

    /// 是否启用发现共享
    pub enable_finding_sharing: bool,

    /// 发现共享阈值 (置信度高于此值才会共享)
    pub finding_sharing_threshold: f32,

    /// LLM 配置
    pub llm_temperature: f32,

    pub llm_max_tokens: u32,

    /// 最大迭代次数
    pub max_iterations: Option<u32>,
}

impl Default for SpecialistConfig {
    fn default() -> Self {
        Self {
            max_retries: 2,
            task_timeout_secs: 300,
            enable_finding_sharing: true,
            finding_sharing_threshold: 0.7,
            llm_temperature: 0.7,
            llm_max_tokens: 4096,
            max_iterations: Some(20),
        }
    }
}

/// Specialist 状态
#[derive(Debug, Clone, PartialEq)]
pub enum SpecialistStatus {
    /// 空闲
    Idle,

    /// 工作中
    Working { task_id: String },

    /// 等待指导
    AwaitingGuidance { task_id: String, question: String },

    /// 已关闭
    Shutdown,
}

/// Specialist 指标
#[derive(Debug, Clone, Default)]
pub struct SpecialistMetrics {
    /// 完成的任务数
    pub completed_tasks: usize,

    /// 失败的任务数
    pub failed_tasks: usize,

    /// 发现的漏洞数
    pub findings_found: usize,

    /// 发送的消息数
    pub messages_sent: usize,

    /// 接收的消息数
    pub messages_received: usize,

    /// 总迭代次数
    pub total_iterations: usize,

    /// 总工具调用次数
    pub total_tool_calls: usize,
}

/// Specialist 信息
#[derive(Debug, Clone)]
pub struct SpecialistInfo {
    pub id: String,
    pub specialty: AgentSpecialty,
    pub status: SpecialistStatus,
    pub metrics: SpecialistMetrics,
}

/// Specialist (专家)
///
/// 核心职责：
/// 1. 自我认领匹配的任务
/// 2. 执行 ReAct 循环完成任务
/// 3. 与其他 Specialist 进行 Peer-to-Peer 通信
/// 4. 共享高置信度发现
/// 5. 处理协助请求
pub struct Specialist {
    /// Specialist ID
    pub id: String,

    /// 专业领域
    pub specialty: AgentSpecialty,

    /// 共享任务列表
    task_list: Arc<SharedTaskList>,

    /// 消息系统
    mailbox: Arc<Mailbox>,

    /// 消息接收器
    message_rx: Option<tokio::sync::mpsc::Receiver<Message>>,

    /// 广播接收器
    broadcast_rx: Option<tokio::sync::broadcast::Receiver<Message>>,

    /// 当前任务
    current_task: Option<AuditTask>,

    /// 状态
    status: SpecialistStatus,

    /// 配置
    config: SpecialistConfig,

    /// 指标
    metrics: SpecialistMetrics,

    /// 工作记忆
    working_memory: std::collections::HashMap<String, serde_json::Value>,

    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 工具注册表
    tools: Arc<ToolRegistry>,

    /// 项目路径
    project_path: String,
}

impl Specialist {
    /// 创建新的 Specialist
    pub fn new(
        id: String,
        specialty: AgentSpecialty,
        mailbox: Arc<Mailbox>,
        task_list: Arc<SharedTaskList>,
        config: SpecialistConfig,
        llm: Arc<dyn LLMClient>,
        tools: Arc<ToolRegistry>,
        project_path: String,
    ) -> Self {
        Self {
            id: id.clone(),
            specialty,
            task_list,
            mailbox,
            message_rx: None,
            broadcast_rx: None,
            current_task: None,
            status: SpecialistStatus::Idle,
            config,
            metrics: SpecialistMetrics::default(),
            working_memory: std::collections::HashMap::new(),
            llm,
            tools,
            project_path,
        }
    }

    /// 设置消息接收器
    pub fn set_message_receiver(&mut self, rx: tokio::sync::mpsc::Receiver<Message>) {
        self.message_rx = Some(rx);
    }

    /// 设置广播接收器
    pub fn set_broadcast_receiver(&mut self, rx: tokio::sync::broadcast::Receiver<Message>) {
        self.broadcast_rx = Some(rx);
    }

    /// Specialist 主循环
    pub async fn run(&mut self) -> Result<()> {
        tracing::info!("[Specialist {} - {:?}] 启动", self.id, self.specialty);

        // 订阅广播
        let mut broadcast_rx = self.mailbox.subscribe();

        loop {
            // 检查是否应该关闭
            if self.status == SpecialistStatus::Shutdown {
                tracing::info!("[Specialist {}] 关闭", self.id);
                break;
            }

            tokio::select! {
                // 处理直接消息
                msg = self.receive_message() => {
                    if let Some(msg) = msg {
                        self.metrics.messages_received += 1;
                        self.handle_message(msg).await;
                    }
                }

                // 处理广播消息
                msg = broadcast_rx.recv() => {
                    if let Ok(msg) = msg {
                        self.metrics.messages_received += 1;
                        self.handle_broadcast(msg).await;
                    }
                }

                // 空闲时定期尝试认领任务（带 sleep 防止忙等待）
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {
                    if self.current_task.is_none() && self.status == SpecialistStatus::Idle {
                        if let Some(task) = self.task_list.claim_task(
                            &self.id,
                            &self.specialty
                        ).await {
                            self.execute_task(task).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 接收消息
    async fn receive_message(&mut self) -> Option<Message> {
        if let Some(ref mut rx) = self.message_rx {
            rx.recv().await
        } else {
            None
        }
    }

    /// 处理直接消息
    async fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::Direct { from, content, .. } => {
                match content {
                    MessageContent::FindingShared { finding, context } => {
                        self.remember_finding(&from, finding, context).await;
                    }

                    MessageContent::FindingChallenge { finding_id, challenge_reason } => {
                        self.handle_challenge(&finding_id, &challenge_reason).await;
                    }

                    MessageContent::AssistanceRequest { task_id, reason, suggested_specialty } => {
                        self.handle_assistance_request(&task_id, &reason, suggested_specialty.as_deref()).await;
                    }

                    MessageContent::ProgressUpdate { task_id, progress, notes } => {
                        tracing::info!(
                            "[Specialist {}] 来自 {} 的进度: {} - {}% - {}",
                            self.id, from, task_id, (progress * 100.0) as u32, notes
                        );
                    }

                    MessageContent::TaskCompleted { task_id, success, summary } => {
                        tracing::info!(
                            "[Specialist {}] 来自 {} 的任务完成: {} - {} - {}",
                            self.id, from, task_id, success, summary
                        );
                    }

                    MessageContent::Custom { message_type, data } => {
                        tracing::debug!("[Specialist {}] 自定义消息: {}", self.id, message_type);
                        // 可以存储到工作记忆中
                        self.working_memory.insert(message_type, data);
                    }
                }
            }

            Message::CoordinatorCommand { command, .. } => {
                self.handle_coordinator_command(command).await;
            }

            Message::Broadcast { .. } => {
                // 广播消息由 handle_broadcast 处理
            }
        }
    }

    /// 处理广播消息
    async fn handle_broadcast(&mut self, msg: Message) {
        match msg {
            Message::Broadcast { from, content } => {
                match content {
                    MessageContent::FindingShared { finding, context } => {
                        // 记录其他 Specialist 的发现
                        self.remember_finding(&from, finding, context).await;
                    }

                    MessageContent::TaskCompleted { task_id, success, summary } => {
                        tracing::debug!(
                            "[Specialist {}] 广播: {} 完成 {} - {}",
                            self.id, from, task_id, summary
                        );
                    }

                    _ => {
                        // 其他广播消息不需要特殊处理
                    }
                }
            }

            _ => {}
        }
    }

    /// 处理协调器指令
    async fn handle_coordinator_command(&mut self, command: CoordinatorDirective) {
        match command {
            CoordinatorDirective::PhaseTransition(phase) => {
                self.handle_phase_transition(phase).await;
            }

            CoordinatorDirective::SuspendTask(task_id) => {
                if task_id == "shutdown" {
                    self.status = SpecialistStatus::Shutdown;
                } else if let Some(ref task) = self.current_task {
                    if task.id == task_id {
                        tracing::warn!("[Specialist {}] 任务被暂停: {}", self.id, task_id);
                    }
                }
            }

            CoordinatorDirective::ResumeTask(task_id) => {
                tracing::info!("[Specialist {}] 任务被恢复: {}", self.id, task_id);
            }

            CoordinatorDirective::ReassignTask { task_id, new_specialist } => {
                tracing::info!(
                    "[Specialist {}] 任务重新分配: {} -> {}",
                    self.id, task_id, new_specialist
                );
            }

            CoordinatorDirective::RequestStatusReport => {
                self.send_status_report().await;
            }

            CoordinatorDirective::PlanApprovalResponse { approved, feedback } => {
                tracing::info!(
                    "[Specialist {}] 计划批准: {} - {:?}",
                    self.id, approved, feedback
                );
            }

            CoordinatorDirective::AdjustPriority { task_id, new_priority } => {
                tracing::info!(
                    "[Specialist {}] 优先级调整: {} -> {}",
                    self.id, task_id, new_priority
                );
            }
        }
    }

    /// 处理阶段切换
    async fn handle_phase_transition(&mut self, phase: AuditPhase) {
        tracing::info!("[Specialist {}] 切换阶段: {:?}", self.id, phase);

        // 阶段切换时可能需要清理工作记忆或执行其他操作
        match phase {
            AuditPhase::Initialization => {
                // 清空工作记忆
                self.working_memory.clear();
            }

            AuditPhase::Reporting => {
                // 报告阶段，可能发送总结
            }

            _ => {
                // 其他阶段不需要特殊处理
            }
        }
    }

    /// 记录发现
    async fn remember_finding(&mut self, from: &str, finding: InternalFinding, _context: String) {
        tracing::info!(
            "[Specialist {}] 记录来自 {} 的发现: {} (置信度: {})",
            self.id, from, finding.title, finding.confidence
        );

        // 存储到工作记忆
        let key = format!("finding_{}", finding.id);
        self.working_memory.insert(
            key,
            serde_json::to_value(&finding).unwrap_or_default()
        );
    }

    /// 处理质疑
    async fn handle_challenge(&mut self, finding_id: &str, challenge_reason: &str) {
        tracing::warn!(
            "[Specialist {}] 发现被质疑: {} - 原因: {}",
            self.id, finding_id, challenge_reason
        );

        // 可以重新评估发现或提供更多证据
        // 这里简化处理，记录到工作记忆
        self.working_memory.insert(
            format!("challenge_{}", finding_id),
            serde_json::json!({
                "reason": challenge_reason,
                "timestamp": chrono::Utc::now().to_rfc3339()
            })
        );
    }

    /// 处理协助请求
    async fn handle_assistance_request(
        &mut self,
        task_id: &str,
        reason: &str,
        suggested_specialty: Option<&str>,
    ) {
        tracing::info!(
            "[Specialist {}] 收到协助请求: {} - 原因: {} - 建议专家: {:?}",
            self.id, task_id, reason, suggested_specialty
        );

        // 检查是否在自己的专业范围内
        // 这里简化处理，实际应该检查 specialty 匹配
    }

    /// 发送状态报告
    async fn send_status_report(&self) {
        let status = match &self.status {
            SpecialistStatus::Idle => "空闲".to_string(),
            SpecialistStatus::Working { task_id } => format!("工作中: {}", task_id),
            SpecialistStatus::AwaitingGuidance { task_id, question } => {
                format!("等待指导: {} - {}", task_id, question)
            }
            SpecialistStatus::Shutdown => "已关闭".to_string(),
        };

        let report = serde_json::json!({
            "specialist_id": self.id,
            "specialty": format!("{:?}", self.specialty),
            "status": status,
            "completed_tasks": self.metrics.completed_tasks,
            "failed_tasks": self.metrics.failed_tasks,
            "findings_found": self.metrics.findings_found,
        });

        let _ = self.mailbox.send_direct(
            &self.id,
            "coordinator",
            MessageContent::Custom {
                message_type: "status_report".to_string(),
                data: report,
            }
        ).await;
    }

    /// 执行任务 (连接到真实 ReAct 执行器)
    async fn execute_task(&mut self, task: AuditTask) {
        self.current_task = Some(task.clone());
        self.status = SpecialistStatus::Working { task_id: task.id.clone() };

        tracing::info!(
            "[Specialist {} - {:?}] 开始执行任务: {}",
            self.id, self.specialty, task.id
        );

        // 创建 ReAct 执行器
        let exec_config = ExecutionConfig {
            max_iterations: self.config.max_iterations,
            timeout_secs: Some(self.config.task_timeout_secs),
            enable_streaming: false,
            temperature: self.config.llm_temperature,
            max_tokens: self.config.llm_max_tokens,
        };

        let executor = ReactExecutor::new(
            self.llm.clone(),
            self.tools.clone(),
            exec_config,
        );

        // 构建系统提示词
        let system_prompt = self.build_system_prompt(&task);

        // 构建用户消息
        let user_message = self.build_user_message(&task);

        // 构建 Agent 上下文
        let context = AgentContext {
            project_id: uuid::Uuid::new_v4().to_string(),
            project_path: self.project_path.clone(),
            session_id: uuid::Uuid::new_v4().to_string(),
            inherited_context: std::collections::HashMap::new(),
            user_context: {
                let mut map = std::collections::HashMap::new();
                map.insert("task".to_string(), serde_json::json!(task.id.clone()));
                map.insert("target".to_string(), serde_json::json!(task.target.clone()));
                map.insert("task_type".to_string(), serde_json::json!(format!("{:?}", task.task_type)));
                map.insert("specialist_id".to_string(), serde_json::json!(self.id.clone()));
                map
            },
        };

        // 执行 ReAct 循环
        let exec_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(self.config.task_timeout_secs),
            executor.execute(&context, &system_prompt, &user_message)
        ).await;

        match exec_result {
            Ok(Ok(exec_result)) => {
                // 转换执行结果
                let task_result = self.convert_exec_result(&exec_result, &task).await;

                // 提取发现（克隆以便后续使用）
                let findings_count = task_result.findings.len();
                let findings = task_result.findings.clone();

                // 共享高置信度发现给其他 Specialist
                if self.config.enable_finding_sharing {
                    for finding in &findings {
                        if let Some(confidence) = finding.get("confidence").and_then(|v| v.as_f64()) {
                            if confidence as f32 > self.config.finding_sharing_threshold {
                                self.share_finding(finding, &task).await;
                            }
                        }
                    }
                }

                // 完成任务
                self.task_list.complete_task(&task.id, task_result).await;
                self.metrics.completed_tasks += 1;
                self.metrics.findings_found += findings_count;
                self.metrics.total_iterations += exec_result.state.iteration as usize;
                self.metrics.total_tool_calls += exec_result.tool_calls.len();

                // 发送完成通知
                let _ = self.mailbox.broadcast(
                    &self.id,
                    MessageContent::TaskCompleted {
                        task_id: task.id.clone(),
                        success: true,
                        summary: format!("完成，发现 {} 个漏洞", findings.len()),
                    }
                ).await;
            }

            Ok(Err(e)) => {
                // 执行失败
                tracing::error!("[Specialist {}] 任务执行失败: {}", self.id, e);
                self.task_list.fail_task(&task.id, e.clone()).await;
                self.metrics.failed_tasks += 1;
            }

            Err(_) => {
                // 超时
                let error_msg = "任务超时".to_string();
                tracing::error!("[Specialist {}] 任务执行失败: {}", self.id, error_msg);
                self.task_list.fail_task(&task.id, error_msg.clone()).await;
                self.metrics.failed_tasks += 1;
            }
        }

        self.current_task = None;
        self.status = SpecialistStatus::Idle;
    }

    /// 构建系统提示词
    fn build_system_prompt(&self, task: &AuditTask) -> String {
        let expert_prompt = get_expert_prompt(&self.specialty);

        // 注入框架特定的污点规则知识
        let taint_knowledge = self.build_taint_knowledge_section();

        format!(
            r#"你是 {}，专门负责安全代码审计。

{}

{}

当前任务信息：
- 任务类型: {:?}
- 目标: {}
- 优先级: {:?}

你需要在审计过程中：
1. 使用合适的工具分析代码
2. 追踪数据流，识别潜在的安全问题
3. 验证漏洞的可利用性
4. 使用 report_finding 工具报告每个发现

完成所有分析后，使用 finish_analysis 工具结束任务。

请使用以下格式进行推理：
Thought: [你的思考过程]
Action: [工具名称]
Action Input: {{"参数名": "参数值"}}

可用工具将动态提供。"#,
            self.specialty,
            expert_prompt,
            taint_knowledge,
            task.task_type,
            task.target,
            task.priority
        )
    }

    /// 构建框架特定的污点规则知识
    fn build_taint_knowledge_section(&self) -> String {
        use deepaudit_core::load_taint_rules_from_dir;

        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let rules_dir = std::path::Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("rules").join("taint"));

        let rules_dir = match rules_dir {
            Some(d) if d.exists() => d,
            _ => {
                let alt = std::path::Path::new(&self.project_path)
                    .join("rules").join("taint");
                if alt.exists() { alt } else { return String::new() }
            }
        };

        let loaded = match load_taint_rules_from_dir(&rules_dir) {
            Ok(l) if !l.sources.is_empty() || !l.sinks.is_empty() => l,
            _ => return String::new(),
        };

        let mut section = String::from("\n## 框架特定的污点规则知识\n\n");

        // 所有专家都获取 source 知识
        if !loaded.sources.is_empty() {
            section.push_str("### 重点关注的用户输入源\n");
            for source in &loaded.sources {
                section.push_str(&format!(
                    "- **{}**: {} (模式: {})\n",
                    source.name,
                    source.description,
                    source.patterns.join(", "),
                ));
            }
            section.push('\n');
        }

        // 根据专家领域过滤相关的 sinks
        let relevant_sinks: Vec<_> = loaded.sinks.iter().filter(|sink| {
            let vuln_type = format!("{:?}", sink.vulnerability_type).to_lowercase();
            match self.specialty {
                AgentSpecialty::SqlInjectionExpert => vuln_type.contains("sql"),
                AgentSpecialty::XssExpert => vuln_type.contains("xss") || vuln_type.contains("script"),
                AgentSpecialty::CommandInjectionExpert => vuln_type.contains("command"),
                AgentSpecialty::PathTraversalExpert => vuln_type.contains("path") || vuln_type.contains("traversal"),
                AgentSpecialty::SsrfExpert => vuln_type.contains("ssrf") || vuln_type.contains("request"),
                AgentSpecialty::CryptoExpert => vuln_type.contains("crypto") || vuln_type.contains("weak"),
                _ => true,
            }
        }).collect();

        if !relevant_sinks.is_empty() {
            section.push_str("### 重点关注的危险函数\n");
            for sink in relevant_sinks {
                section.push_str(&format!(
                    "- **{}**: {} (模式: {})\n",
                    sink.name,
                    sink.description,
                    sink.patterns.join(", "),
                ));
            }
        }

        section
    }

    /// 构建用户消息
    fn build_user_message(&self, task: &AuditTask) -> String {
        let mut message = format!(
            "请审计以下目标：\n\n目标: {}\n任务类型: {:?}\n",
            task.target, task.task_type
        );

        // 添加文件上下文
        if let Some(ref file_info) = task.context.file_info {
            message.push_str(&format!(
                "\n文件信息:\n- 路径: {}\n- 语言: {}\n- 大小: {} bytes",
                file_info.path, file_info.language, file_info.size
            ));

            if !file_info.key_functions.is_empty() {
                message.push_str(&format!("\n- 关键函数: {}", file_info.key_functions.join(", ")));
            }
        }

        // 添加端点上下文
        if let Some(ref endpoint_info) = task.context.endpoint_info {
            message.push_str(&format!(
                "\n\n端点信息:\n- 路径: {}\n- 方法: {}\n- 控制器: {}",
                endpoint_info.path, endpoint_info.method, endpoint_info.controller
            ));

            if endpoint_info.auth_required {
                message.push_str("\n- 需要认证: 是");
            }
        }

        // 添加相关工作记忆
        if !task.context.related_tasks.is_empty() {
            message.push_str(&format!("\n\n相关任务: {}", task.context.related_tasks.join(", ")));
        }

        message
    }

    /// 转换执行结果为 TaskResult
    async fn convert_exec_result(&self, exec_result: &ReactExecutionResult, task: &AuditTask) -> TaskResult {
        // 获取发现
        let findings_from_tools: Vec<serde_json::Value> = exec_result.get_findings()
            .into_iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "category": f.category,
                    "file_path": f.file_path,
                    "start_line": f.start_line,
                    "code_snippet": f.code_snippet,
                    "recommendation": f.recommendation,
                    "confidence": f.extra.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.75),
                    "discovered_by": f.discovered_by,
                })
            })
            .collect();

        // 没有发现时返回空列表，不创建虚假发现
        let findings = findings_from_tools;

        TaskResult {
            findings,
            execution_result: Some(serde_json::json!({
                "status": if exec_result.state.completed { "success" } else { "incomplete" },
                "iterations": exec_result.state.iteration,
                "tool_calls": exec_result.tool_calls,
            })),
        }
    }

    /// 共享发现
    async fn share_finding(&mut self, finding: &serde_json::Value, task: &AuditTask) {
        let finding_data = InternalFinding {
            id: finding["id"].as_str().unwrap_or("").to_string(),
            title: finding["title"].as_str().unwrap_or("").to_string(),
            severity: finding["severity"].as_str().unwrap_or("Medium").to_string(),
            confidence: finding["confidence"].as_f64().unwrap_or(0.75) as f32,
            location: finding["file_path"].as_str().unwrap_or(&task.target).to_string(),
            description: finding["description"].as_str().unwrap_or("").to_string(),
            evidence: finding["code_snippet"].as_str().map(|s| s.to_string()),
        };

        let _ = self.mailbox.broadcast(
            &self.id,
            MessageContent::FindingShared {
                finding: finding_data,
                context: format!("Task: {}", task.id),
            }
        ).await;

        self.metrics.messages_sent += 1;
    }

    /// 获取状态
    pub fn get_status(&self) -> &SpecialistStatus {
        &self.status
    }

    /// 获取指标
    pub fn get_metrics(&self) -> &SpecialistMetrics {
        &self.metrics
    }

    /// 获取配置 (仅供 AuditTeamSystem 内部使用)
    pub(crate) fn get_config(&self) -> &SpecialistConfig {
        &self.config
    }

    /// 更新项目路径
    pub fn update_project_path(&mut self, project_path: String) {
        self.project_path = project_path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 简化的测试 - 不需要 LLM 和 Tools 来测试基本功能
    #[test]
    fn test_specialist_config_default() {
        let config = SpecialistConfig::default();
        assert_eq!(config.max_retries, 2);
        assert_eq!(config.task_timeout_secs, 300);
        assert_eq!(config.llm_temperature, 0.7);
        assert_eq!(config.max_iterations, Some(20));
    }

    #[test]
    fn test_specialist_status_display() {
        let status = SpecialistStatus::Working {
            task_id: "task-1".to_string()
        };

        match status {
            SpecialistStatus::Working { task_id } => {
                assert_eq!(task_id, "task-1");
            }
            _ => panic!("Expected Working status"),
        }
    }

    #[test]
    fn test_specialist_metrics_default() {
        let metrics = SpecialistMetrics::default();
        assert_eq!(metrics.completed_tasks, 0);
        assert_eq!(metrics.failed_tasks, 0);
        assert_eq!(metrics.findings_found, 0);
    }
}
