// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! TUI 审计集成

use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use ctx_audit_agent_engine::{
    Agent, AgentConfig, AgentContext, AgentRegistry, AgentType,
    LLMConfig, ExecutionStats,
};
use ctx_audit_tools::{register_built_in_tools, ToolRegistry, FindingData};
use ctx_audit_llm::LLMFactory;

use super::app::{AppEvent, FindingEvent};

/// 审计管理器
pub struct AuditManager {
    /// LLM 工厂
    llm_factory: Arc<LLMFactory>,
    /// 是否正在运行
    running: Arc<RwLock<bool>>,
    /// 当前审计会话 ID
    session_id: Arc<RwLock<Option<String>>>,
    /// 进度
    progress: Arc<RwLock<AuditProgress>>,
}

/// 审计进度
#[derive(Debug, Clone)]
pub struct AuditProgress {
    /// 当前阶段
    pub phase: AuditPhase,
    /// 总进度 (0-100)
    pub progress: u8,
    /// 当前消息
    pub message: String,
    /// 发现的漏洞数量
    pub findings_count: usize,
}

/// 审计阶段
#[derive(Debug, Clone, PartialEq)]
pub enum AuditPhase {
    Idle,
    Initializing,
    Recon,
    Analysis,
    Verification,
    Completed,
    Failed(String),
}

impl AuditManager {
    /// 创建新的审计管理器
    pub fn new() -> Self {
        Self {
            llm_factory: Arc::new(LLMFactory::with_default_config()),
            running: Arc::new(RwLock::new(false)),
            session_id: Arc::new(RwLock::new(None)),
            progress: Arc::new(RwLock::new(AuditProgress {
                phase: AuditPhase::Idle,
                progress: 0,
                message: "就绪".to_string(),
                findings_count: 0,
            })),
        }
    }

    /// 启动审计
    pub async fn start_audit(
        &self,
        project_path: String,
        tx: mpsc::UnboundedSender<AppEvent>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 设置运行状态
        *self.running.write().await = true;

        let session_id = uuid::Uuid::new_v4().to_string();
        *self.session_id.write().await = Some(session_id.clone());

        // 发送开始事件
        let _ = tx.send(AppEvent::AuditProgress(0, "初始化中...".to_string()));

        // 在后台任务中运行审计
        let running = self.running.clone();
        let progress = self.progress.clone();
        let llm_factory = self.llm_factory.clone();
        let event_tx = tx.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::run_audit_internal(
                project_path,
                session_id,
                llm_factory,
                running,
                progress,
                event_tx,
            ).await {
                tracing::error!("Audit failed: {:?}", e);
            }
        });

        Ok(())
    }

    /// 内部审计运行逻辑
    async fn run_audit_internal(
        project_path: String,
        session_id: String,
        llm_factory: Arc<LLMFactory>,
        running: Arc<RwLock<bool>>,
        progress: Arc<RwLock<AuditProgress>>,
        tx: mpsc::UnboundedSender<AppEvent>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 初始化 LLM
        let llm = llm_factory.get_client().await?;

        // 初始化工具注册表
        let tool_registry = Arc::new(ToolRegistry::new());
        register_built_in_tools(&tool_registry, project_path.clone()).await;

        // 创建 Agent 注册表
        let agent_registry = AgentRegistry::new(llm, tool_registry.clone());

        // 阶段 1: 侦察
        Self::update_progress(&progress, &tx, AuditPhase::Recon, 5, "侦察项目结构".to_string()).await;

        let recon_agent = agent_registry.create_agent(
            AgentType::Recon,
            AgentConfig {
                agent_type: AgentType::Recon,
                name: "Recon Agent".to_string(),
                description: Some("项目结构分析".to_string()),
                llm_config: LLMConfig::default(),
                max_iterations: 10,
                timeout_secs: Some(300),
                extra: Default::default(),
            },
        )?;

        let recon_context = AgentContext {
            project_id: uuid::Uuid::new_v4().to_string(),
            project_path: project_path.clone(),
            session_id: session_id.clone(),
            inherited_context: Default::default(),
            user_context: Default::default(),
        };

        // 检查是否应该继续
        if !*running.read().await {
            return Ok(());
        }

        let _ = recon_agent.execute(recon_context).await;

        // 阶段 2: 分析
        Self::update_progress(&progress, &tx, AuditPhase::Analysis, 50, "分析漏洞".to_string()).await;

        let analysis_agent = agent_registry.create_agent(
            AgentType::Analysis,
            AgentConfig {
                agent_type: AgentType::Analysis,
                name: "Analysis Agent".to_string(),
                description: Some("漏洞分析".to_string()),
                llm_config: LLMConfig::default(),
                max_iterations: 50,
                timeout_secs: Some(600),
                extra: Default::default(),
            },
        )?;

        let mut analysis_context = AgentContext {
            project_id: uuid::Uuid::new_v4().to_string(),
            project_path: project_path.clone(),
            session_id: session_id.clone(),
            inherited_context: Default::default(),
            user_context: Default::default(),
        };

        // 传递侦察完成信息
        analysis_context
            .inherited_context
            .insert("recon_completed".to_string(), serde_json::json!(true));

        // 检查是否应该继续
        if !*running.read().await {
            return Ok(());
        }

        let result = analysis_agent.execute(analysis_context).await;

        // 处理漏洞发现
        for finding in &result.findings {
            let _ = tx.send(AppEvent::NewFinding(FindingEvent {
                id: uuid::Uuid::new_v4().to_string(),
                severity: finding.severity.clone(),
                title: finding.title.clone().unwrap_or_default(),
                file_path: finding.file_path.clone(),
                line: Some(finding.start_line),
            }));
        }

        // 更新进度
        Self::update_progress(&progress, &tx, AuditPhase::Completed, 100,
            format!("审计完成，发现 {} 个漏洞", result.findings.len())).await;

        // 完成审计
        *running.write().await = false;

        Ok(())
    }

    /// 更新进度
    async fn update_progress(
        progress: &Arc<RwLock<AuditProgress>>,
        tx: &mpsc::UnboundedSender<AppEvent>,
        phase: AuditPhase,
        value: u8,
        message: String,
    ) {
        let mut prog = progress.write().await;
        prog.phase = phase.clone();
        prog.progress = value;
        prog.message = message.clone();

        // 发送事件
        let _ = tx.send(AppEvent::AuditProgress(value, message));
    }

    /// 暂停审计
    pub async fn pause(&self) {
        *self.running.write().await = false;
    }

    /// 取消审计
    pub async fn cancel(&self) {
        *self.running.write().await = false;

        // 重置进度
        let mut prog = self.progress.write().await;
        prog.phase = AuditPhase::Idle;
        prog.progress = 0;
        prog.message = "已取消".to_string();
    }

    /// 获取进度
    pub async fn progress(&self) -> AuditProgress {
        self.progress.read().await.clone()
    }

    /// 是否正在运行
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

impl Default for AuditManager {
    fn default() -> Self {
        Self::new()
    }
}
