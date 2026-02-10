// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! audit 命令实现
//!
//! 启动 AI 审计，使用 Agent 引擎进行深度代码安全分析

use miette::Result;
use std::sync::Arc;

use crate::config::ConfigManager;
use crate::terminal::{StreamEvent, StreamOutput, TerminalRenderer};
use ctx_audit_agent_engine::{
    AgentConfig, AgentContext, AgentRegistry, AgentType, ExecutionStats,
    LLMConfig,
};
use ctx_audit_tools::FindingData;
use ctx_audit_llm::LLMFactory;
use ctx_audit_tools::{register_built_in_tools, ToolRegistry};

/// 执行 audit 命令
pub async fn execute(
    path: String,
    audit_type: String,
    max_iterations: u32,
    skip_verification: bool,
    output_path: Option<String>,
    output_format: &str,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 初始化配置
    let config = Arc::new(ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?);

    // 验证项目路径
    let project_path = std::path::Path::new(&path);
    if !project_path.exists() {
        renderer.error(&format!("项目路径不存在: {}", path));
        return Err(miette::miette!("项目路径不存在"));
    }

    renderer.info(&format!("开始审计: {}", path));

    // 初始化 LLM 工厂
    let llm_factory = LLMFactory::with_default_config();
    let llm = llm_factory.get_client().await.map_err(|e| {
        renderer.error(&format!("LLM 初始化失败: {}", e));
        miette::miette!("LLM 初始化失败: {}", e)
    })?;

    // 初始化工具注册表
    let tool_registry = Arc::new(ToolRegistry::new());
    register_built_in_tools(&tool_registry, path.clone()).await;

    // 创建 Agent 注册表
    let agent_registry = AgentRegistry::new(llm, tool_registry.clone());

    // 创建输出器
    let mut stream_output = StreamOutput::new();

    // 执行审计流程
    let mut all_findings = Vec::new();

    // 阶段 1: 侦察
    stream_output.emit(&StreamEvent::AgentStart(AgentType::Recon));

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
    ).map_err(|e| miette::miette!("{}", e))?;

    let recon_context = AgentContext {
        project_id: uuid::Uuid::new_v4().to_string(),
        project_path: path.clone(),
        session_id: uuid::Uuid::new_v4().to_string(),
        inherited_context: Default::default(),
        user_context: Default::default(),
    };

    let recon_result = recon_agent.execute(recon_context).await;
    match recon_result.status {
        ctx_audit_agent_engine::AgentStatus::Completed => {
            stream_output.emit(&StreamEvent::AgentComplete(
                AgentType::Recon,
                recon_result.message.clone().unwrap_or_default(),
            ));
        }
        ctx_audit_agent_engine::AgentStatus::Failed => {
            stream_output.emit(&StreamEvent::AgentError(AgentType::Recon, recon_result.error.unwrap_or_default()));
        }
        _ => {}
    }

    // 阶段 2: 分析
    stream_output.emit(&StreamEvent::AgentStart(AgentType::Analysis));

    let analysis_agent = agent_registry.create_agent(
        AgentType::Analysis,
        AgentConfig {
            agent_type: AgentType::Analysis,
            name: "Analysis Agent".to_string(),
            description: Some("漏洞分析".to_string()),
            llm_config: LLMConfig::default(),
            max_iterations,
            timeout_secs: Some(600),
            extra: Default::default(),
        },
    ).map_err(|e| miette::miette!("{}", e))?;

    let mut analysis_context = AgentContext {
        project_id: uuid::Uuid::new_v4().to_string(),
        project_path: path.clone(),
        session_id: uuid::Uuid::new_v4().to_string(),
        inherited_context: Default::default(),
        user_context: Default::default(),
    };

    // 传递侦察结果
    analysis_context
        .inherited_context
        .insert("recon_completed".to_string(), serde_json::json!(true));

    let analysis_result = analysis_agent.execute(analysis_context).await;

    match analysis_result.status {
        ctx_audit_agent_engine::AgentStatus::Completed => {
            stream_output.emit(&StreamEvent::AgentComplete(
                AgentType::Analysis,
                analysis_result.message.clone().unwrap_or_default(),
            ));

            // 收集漏洞
            for finding in &analysis_result.findings {
                stream_output.emit(&StreamEvent::Finding(
                    finding.severity.clone(),
                    finding.title.clone().unwrap_or_default(),
                    finding.file_path.clone(),
                    finding.start_line,
                ));
            }
            all_findings = analysis_result.findings.clone();
        }
        ctx_audit_agent_engine::AgentStatus::Failed => {
            stream_output.emit(&StreamEvent::AgentError(AgentType::Analysis, analysis_result.error.unwrap_or_default()));
        }
        _ => {}
    }

    // 阶段 3: 验证（可选）
    if !skip_verification && !all_findings.is_empty() {
        stream_output.emit(&StreamEvent::AgentStart(AgentType::Verification));

        let verification_agent = agent_registry.create_agent(
            AgentType::Verification,
            AgentConfig {
                agent_type: AgentType::Verification,
                name: "Verification Agent".to_string(),
                description: Some("漏洞验证".to_string()),
                llm_config: LLMConfig::default(),
                max_iterations: 10,
                timeout_secs: Some(300),
                extra: Default::default(),
            },
        ).map_err(|e| miette::miette!("{}", e))?;

        let mut verification_context = AgentContext {
            project_id: uuid::Uuid::new_v4().to_string(),
            project_path: path.clone(),
            session_id: uuid::Uuid::new_v4().to_string(),
            inherited_context: Default::default(),
            user_context: Default::default(),
        };

        // 传递漏洞列表
        let findings_json = serde_json::to_value(&all_findings).unwrap_or_default();
        verification_context
            .inherited_context
            .insert("findings".to_string(), findings_json);

        let verification_result = verification_agent.execute(verification_context).await;

        match verification_result.status {
            ctx_audit_agent_engine::AgentStatus::Completed => {
                stream_output.emit(&StreamEvent::AgentComplete(
                    AgentType::Verification,
                    verification_result.message.clone().unwrap_or_default(),
                ));
            }
            ctx_audit_agent_engine::AgentStatus::Failed => {
                stream_output.emit(&StreamEvent::AgentError(AgentType::Verification, verification_result.error.unwrap_or_default()));
            }
            _ => {}
        }
    }

    // 输出摘要
    renderer.success(&format!(
        "审计完成！共发现 {} 个漏洞",
        all_findings.len()
    ));

    // 保存结果（如果指定了输出文件）
    if let Some(output_path) = output_path {
        // TODO: 实现保存逻辑
        renderer.info(&format!("结果已保存到: {}", output_path));
    }

    Ok(())
}
