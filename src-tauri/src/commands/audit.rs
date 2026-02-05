//! 审计命令
//!
//! 处理审计会话的启动、暂停、取消等操作

use tauri::{State, Manager};
use std::sync::Arc;
use tokio::sync::Mutex;

// 重新导出类型以供 commands/mod.rs 使用
pub use crate::models::audit::{AuditStartRequest, AuditStartResponse, AuditStatus, AuditStatusResponse};

use crate::models::audit::{AuditSession, AuditType};
use crate::models::events::ProgressData;
use crate::services::agent_engine::{Agent, OrchestratorAgent};
use crate::services::database::Database;
use crate::services::llm::LLMFactory;
use crate::services::tools::registry::ToolRegistry;

/// 启动审计
#[tauri::command]
pub async fn start_audit(
    request: AuditStartRequest,
    db: State<'_, Database>,
    llm_factory: State<'_, Arc<Mutex<LLMFactory>>>,
) -> Result<AuditStartResponse, String> {
    // 1. 创建审计会话
    let audit_id = uuid::Uuid::new_v4().to_string();
    let mut session = AuditSession::new(&audit_id, &request.project_id, request.audit_type);

    // 设置配置
    if let Some(config) = request.config {
        // 将配置序列化存储
        session.config = Some(serde_json::to_value(config).map_err(|e| e.to_string())?);
    }

    // 保存到数据库
    db.create_audit_session(&session).await.map_err(|e| e.to_string())?;

    // 2. 获取项目信息
    let project_id: i64 = request.project_id.parse().map_err(|e| format!("无效的项目ID: {}", e))?;
    let project = db.get_project_by_id(project_id).await.map_err(|e| e.to_string())?;

    // 3. 创建 Agent 配置
    let llm_factory = llm_factory.lock().await;
    let llm = llm_factory.create_default_client().await.map_err(|e| e.to_string())?;

    let agent_config = crate::models::agent::AgentConfig {
        agent_type: crate::models::agent::AgentType::Orchestrator,
        max_iterations: 50,
        iteration_timeout_seconds: 300,
        waiting_timeout_seconds: 60,
        debug_mode: false,
        llm_config: crate::models::llm::LLMProviderConfig {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            api_base: None,
            api_key: None,
            max_tokens: 4096,
            temperature: 0.7,
            enable_tools: true,
        },
        extra: Default::default(),
    };

    // 4. 创建工具注册表并注册内置工具
    let tool_registry = Arc::new(ToolRegistry::new());
    crate::services::tools::register_built_in_tools(&tool_registry, project.path.clone()).await;

    // 5. 创建并启动 Orchestrator（后台任务）
    let orchestrator = OrchestratorAgent::new(agent_config.clone(), llm, tool_registry);

    let audit_id_clone = audit_id.clone();
    let db_inner = db.inner().clone();
    let project_path = project.path.clone();
    let project_id_clone = request.project_id.clone();

    tokio::spawn(async move {
        // 创建 Agent 上下文
        let context = crate::models::agent::AgentContext {
            audit_id: audit_id_clone.clone(),
            project_id: project_id_clone,
            project_path: project_path.clone(),
            audit_type: AuditType::Full,
            config: agent_config,
            parent_agent_id: None,
            previous_results: Vec::new(),
            inherited_context: Default::default(),
        };

        // 执行 Agent
        let result = orchestrator.run(context).await;

        // 更新完成状态
        match result.status {
            crate::models::agent::AgentStatus::Completed => {
                let _ = db_inner.update_audit_status(&audit_id_clone, AuditStatus::Completed).await;
            }
            crate::models::agent::AgentStatus::Failed => {
                let error = result.error.unwrap_or_else(|| "未知错误".to_string());
                let _ = db_inner.update_audit_status(&audit_id_clone, AuditStatus::Failed).await;
                let _ = db_inner.update_audit_error(&audit_id_clone, &error).await;
            }
            _ => {
                let _ = db_inner.update_audit_status(&audit_id_clone, AuditStatus::Cancelled).await;
            }
        }
    });

    Ok(AuditStartResponse {
        audit_id,
        status: AuditStatus::Running,
    })
}

/// 获取审计状态
#[tauri::command]
pub async fn get_audit_status(
    audit_id: String,
    db: State<'_, Database>,
) -> Result<AuditStatusResponse, String> {
    let session = db.get_audit_session(&audit_id).await?;

    Ok(AuditStatusResponse {
        audit_id: session.id.clone(),
        status: session.status,
        progress: ProgressData {
            current_stage: session.current_phase.map(|p| p.to_string()).unwrap_or_default(),
            percentage: session.progress_percentage,
            total_files: session.total_files,
            indexed_files: session.indexed_files,
            analyzed_files: session.analyzed_files,
            findings_detected: session.findings_detected,
            extra: Default::default(),
        },
        stats: crate::models::audit::AuditStats {
            total_tokens: session.total_tokens,
            tool_calls: session.tool_calls,
            llm_calls: session.tool_calls, // 使用 tool_calls 作为近似值
            duration_seconds: session
                .started_at
                .and_then(|start| {
                    session
                        .completed_at
                        .or_else(|| Some(chrono::Utc::now()))
                        .map(|end| (end - start).num_seconds() as u64)
                })
                .unwrap_or(0),
        },
    })
}

/// 暂停审计
#[tauri::command]
pub async fn pause_audit(
    audit_id: String,
    _db: State<'_, Database>,
) -> Result<(), String> {
    // TODO: 实现暂停逻辑
    tracing::info!("Pausing audit: {}", audit_id);
    Ok(())
}

/// 取消审计
#[tauri::command]
pub async fn cancel_audit(
    audit_id: String,
    db: State<'_, Database>,
) -> Result<(), String> {
    // 更新状态为已取消
    db.update_audit_status(&audit_id, AuditStatus::Cancelled).await.map_err(|e| e.to_string())?;
    tracing::info!("Cancelled audit: {}", audit_id);
    Ok(())
}

/// 获取审计结果
#[tauri::command]
pub async fn get_audit_result(
    audit_id: String,
    db: State<'_, Database>,
) -> Result<Vec<crate::models::events::FindingData>, String> {
    // 从数据库获取漏洞
    let findings = db.get_findings_by_audit(&audit_id).await?;
    Ok(findings)
}

/// 获取审计事件
#[tauri::command]
pub async fn get_audit_events(
    audit_id: String,
    after_sequence: Option<i64>,
    limit: Option<usize>,
    db: State<'_, Database>,
) -> Result<Vec<crate::models::events::AgentEvent>, String> {
    // 从数据库获取事件
    let events = db.get_agent_events(&audit_id, after_sequence, limit).await?;
    Ok(events)
}

/// 获取 Agent 树
#[tauri::command]
pub async fn get_agent_tree(
    audit_id: String,
) -> Result<crate::services::agent_engine::AgentTreeData, String> {
    // TODO: 从内存获取 Agent 树
    Ok(crate::services::agent_engine::AgentTreeData {
        nodes: Vec::new(),
        edges: Vec::new(),
    })
}
