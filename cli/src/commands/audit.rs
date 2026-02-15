// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! audit 命令实现
//!
//! 启动 AI 审计，使用 Agent 引擎进行深度代码安全分析

use miette::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::config::ConfigManager;
use crate::terminal::{StreamEvent, StreamOutput, TerminalRenderer};
use ctx_audit_agent_engine::{
    AgentConfig, AgentContext, AgentRegistry, AgentType, ExecutionEvent, ExecutionStats, LLMConfig,
};
use ctx_audit_llm::LLMFactory;
use ctx_audit_tools::FindingData;
use ctx_audit_tools::ToolRegistry;

/// 安全地截断 UTF-8 字符串到指定字节长度
fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut result = String::with_capacity(max_bytes);
    let mut byte_count = 0;
    for c in s.chars() {
        let char_len = c.len_utf8();
        if byte_count + char_len > max_bytes {
            break;
        }
        result.push(c);
        byte_count += char_len;
    }
    if byte_count < s.len() {
        result.push_str("...");
    }
    result
}

/// 执行 audit 命令
pub async fn execute(
    path: String,
    audit_type: String,
    max_iterations: u32,
    skip_verification: bool,
    output_path: Option<String>,
    output_format: &str,
    verbose: bool,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 初始化配置
    let config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let config = config_manager.config();

    // 验证项目路径
    let project_path = std::path::Path::new(&path);
    if !project_path.exists() {
        renderer.error(&format!("项目路径不存在: {}", path));
        return Err(miette::miette!("项目路径不存在"));
    }

    renderer.info(&format!("开始审计: {}", path));
    if verbose {
        renderer.info("详细模式已启用，将显示 LLM 思考过程");
    }

    // 初始化 LLM 工厂 - 使用用户配置
    let llm_factory = LLMFactory::new();
    let llm_config = ctx_audit_llm::LLMConfig {
        provider: config.llm.provider.clone(),
        api_key: config.llm.api_key.clone(),
        model: config.llm.model.clone(),
        base_url: config.llm.base_url.clone(),
        timeout_secs: Some(config.llm.timeout_secs),
    };
    llm_factory.set_config(llm_config);

    let llm = llm_factory.get_client().await.map_err(|e| {
        renderer.error(&format!("LLM 初始化失败: {}", e));
        miette::miette!("LLM 初始化失败: {}", e)
    })?;

    // 初始化工具注册表
    let tool_registry = Arc::new(ToolRegistry::new());

    // 初始化 AST 引擎（可选，使用临时缓存目录）
    let cache_dir = std::env::temp_dir().join("ctx-audit-cache");
    let _ = std::fs::create_dir_all(&cache_dir);
    let ast_engine = Some(Arc::new(deepaudit_core::ASTEngine::new(
        cache_dir.to_string_lossy().as_ref(),
    )));

    // 注册所有工具
    ctx_audit_tools::register_all_tools(&tool_registry, path.clone(), ast_engine).await;

    // 创建 Agent 注册表
    let agent_registry = AgentRegistry::new(llm, tool_registry.clone());

    // 创建输出器
    let mut stream_output = StreamOutput::new();

    // 执行审计流程
    let mut all_findings = Vec::new();

    // 阶段 1: 侦察
    stream_output.emit(&StreamEvent::AgentStart(AgentType::Recon));

    let recon_agent = agent_registry
        .create_agent(
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
        )
        .map_err(|e| miette::miette!("{}", e))?;

    let recon_context = AgentContext {
        project_id: uuid::Uuid::new_v4().to_string(),
        project_path: path.clone(),
        session_id: uuid::Uuid::new_v4().to_string(),
        inherited_context: Default::default(),
        user_context: Default::default(),
    };

    // 执行侦察 Agent（带详细输出）
    let recon_result = if verbose {
        execute_agent_with_verbose(recon_agent, recon_context, &mut renderer).await
    } else {
        recon_agent.execute(recon_context).await
    };

    match recon_result.status {
        ctx_audit_agent_engine::AgentStatus::Completed => {
            stream_output.emit(&StreamEvent::AgentComplete(
                AgentType::Recon,
                recon_result.message.clone().unwrap_or_default(),
            ));
        }
        ctx_audit_agent_engine::AgentStatus::Failed => {
            stream_output.emit(&StreamEvent::AgentError(
                AgentType::Recon,
                recon_result.error.unwrap_or_default(),
            ));
        }
        _ => {}
    }

    // 阶段 2: 分析
    stream_output.emit(&StreamEvent::AgentStart(AgentType::Analysis));

    let analysis_agent = agent_registry
        .create_agent(
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
        )
        .map_err(|e| miette::miette!("{}", e))?;

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

    // 执行分析 Agent（带详细输出）
    let analysis_result = if verbose {
        execute_agent_with_verbose(analysis_agent, analysis_context, &mut renderer).await
    } else {
        analysis_agent.execute(analysis_context).await
    };

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
            stream_output.emit(&StreamEvent::AgentError(
                AgentType::Analysis,
                analysis_result.error.unwrap_or_default(),
            ));
        }
        _ => {}
    }

    // 阶段 3: 验证（可选）
    if !skip_verification && !all_findings.is_empty() {
        stream_output.emit(&StreamEvent::AgentStart(AgentType::Verification));

        let verification_agent = agent_registry
            .create_agent(
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
            )
            .map_err(|e| miette::miette!("{}", e))?;

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

        // 执行验证 Agent（带详细输出）
        let verification_result = if verbose {
            execute_agent_with_verbose(verification_agent, verification_context, &mut renderer)
                .await
        } else {
            verification_agent.execute(verification_context).await
        };

        match verification_result.status {
            ctx_audit_agent_engine::AgentStatus::Completed => {
                stream_output.emit(&StreamEvent::AgentComplete(
                    AgentType::Verification,
                    verification_result.message.clone().unwrap_or_default(),
                ));
            }
            ctx_audit_agent_engine::AgentStatus::Failed => {
                stream_output.emit(&StreamEvent::AgentError(
                    AgentType::Verification,
                    verification_result.error.unwrap_or_default(),
                ));
            }
            _ => {}
        }
    }

    // 输出摘要
    renderer.success(&format!("审计完成！共发现 {} 个漏洞", all_findings.len()));

    // 保存结果（如果指定了输出文件）
    if let Some(output_path) = output_path {
        save_findings(&output_path, &all_findings, output_format, &mut renderer).await?;
    }

    Ok(())
}

/// 带 LLM 详细输出的 Agent 执行
async fn execute_agent_with_verbose(
    agent: std::sync::Arc<dyn ctx_audit_agent_engine::Agent>,
    context: AgentContext,
    _renderer: &mut TerminalRenderer,
) -> ctx_audit_agent_engine::AgentResult {
    use console::Style;
    use std::io::{stdout, Write};

    let dim_style = Style::new().dim();
    let cyan_style = Style::new().cyan();
    let green_style = Style::new().green();
    let yellow_style = Style::new().yellow();

    // 创建事件通道
    let (event_tx, event_rx) = mpsc::unbounded_channel::<ExecutionEvent>();

    // 在后台线程中输出事件
    tokio::spawn(async move {
        let mut rx = event_rx;
        while let Some(event) = rx.recv().await {
            match event {
                ExecutionEvent::IterationStart(iteration) => {
                    let _ = writeln!(
                        stdout(),
                        "{}",
                        cyan_style.apply_to(format!("  [迭代 {}]", iteration))
                    );
                }
                ExecutionEvent::ThoughtComplete {
                    iteration: _,
                    thought,
                    action,
                } => {
                    // 输出思考过程
                    let _ = writeln!(
                        stdout(),
                        "{}",
                        dim_style.apply_to(format!("    💭 思考: {}", thought))
                    );
                    if let Some(action_name) = action {
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            yellow_style.apply_to(format!("    🎯 决定: {}", action_name))
                        );
                    }
                }
                ExecutionEvent::ToolCallStart { tool_name, input } => {
                    let input_str = truncate_utf8(&input.to_string(), 200);
                    let _ = writeln!(
                        stdout(),
                        "{}",
                        cyan_style
                            .apply_to(format!("    🔧 调用工具: {}({})", tool_name, input_str))
                    );
                }
                ExecutionEvent::ToolCallComplete {
                    tool_name,
                    result,
                    duration_ms,
                } => {
                    let status = if result.is_error { "❌" } else { "✅" };
                    let result_preview = truncate_utf8(&result.text, 300);
                    let _ = writeln!(
                        stdout(),
                        "{}",
                        green_style.apply_to(format!(
                            "    {} 工具结果 ({}ms): {}",
                            status, duration_ms, result_preview
                        ))
                    );
                }
                ExecutionEvent::ToolCallFailed { tool_name, error } => {
                    let _ = writeln!(
                        stdout(),
                        "{}",
                        console::style(format!("    ❌ 工具失败: {} - {}", tool_name, error)).red()
                    );
                }
                ExecutionEvent::StreamToken(token) => {
                    // 流式输出 token（实时输出思考）
                    print!("{}", dim_style.apply_to(&token));
                    let _ = stdout().flush();
                }
                ExecutionEvent::Complete {
                    iterations,
                    tool_calls,
                } => {
                    let _ = writeln!(
                        stdout(),
                        "{}",
                        green_style.apply_to(format!(
                            "  ✓ 完成: {} 次迭代, {} 次工具调用",
                            iterations, tool_calls
                        ))
                    );
                }
                ExecutionEvent::Failed(error) => {
                    let _ = writeln!(
                        stdout(),
                        "{}",
                        console::style(format!("  ✗ 失败: {}", error)).red()
                    );
                }
            }
        }
    });

    // 执行 Agent
    agent.execute_with_events(context, Some(event_tx)).await
}

/// 保存漏洞结果到文件
async fn save_findings(
    output_path: &str,
    findings: &[FindingData],
    format: &str,
    renderer: &mut TerminalRenderer,
) -> Result<()> {
    let content = match format {
        "json" => serde_json::to_string_pretty(findings)
            .map_err(|e| miette::miette!("JSON 序列化失败: {}", e))?,
        "sarif" => to_sarif(findings),
        "markdown" => to_markdown(findings),
        _ => to_text(findings),
    };

    tokio::fs::write(output_path, content)
        .await
        .map_err(|e| miette::miette!("写入文件失败: {}", e))?;

    renderer.info(&format!("结果已保存到: {}", output_path));
    Ok(())
}

/// 转换为 SARIF 格式
fn to_sarif(findings: &[FindingData]) -> String {
    let sarif = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CTX-Audit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/ctx-audit/ctx-audit"
                }
            },
            "results": findings.iter().map(|f| {
                serde_json::json!({
                    "ruleId": f.category.clone(),
                    "level": severity_to_level(&f.severity),
                    "message": {
                        "text": f.title.clone().unwrap_or_else(|| f.category.clone())
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path.clone()
                            },
                            "region": {
                                "startLine": f.start_line,
                                "endLine": f.end_line.unwrap_or(f.start_line)
                            }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

/// 转换为 Markdown 格式
fn to_markdown(findings: &[FindingData]) -> String {
    let mut md = String::from("# 审计报告\n\n");
    md.push_str(&format!(
        "**生成时间**: {}\n\n",
        chrono::Utc::now().to_rfc3339()
    ));
    md.push_str(&format!("**漏洞数量**: {}\n\n", findings.len()));

    // 按严重程度分组
    let mut by_severity = std::collections::HashMap::new();
    for finding in findings {
        by_severity
            .entry(finding.severity.clone())
            .or_insert_with(Vec::new)
            .push(finding);
    }

    for severity in ["critical", "high", "medium", "low", "info"] {
        if let Some(items) = by_severity.get(severity) {
            md.push_str(&format!(
                "## {} ({})\n\n",
                severity.to_uppercase(),
                items.len()
            ));
            for finding in items {
                md.push_str(&format!("### {}\n\n", finding.category));
                if let Some(title) = &finding.title {
                    md.push_str(&format!("**标题**: {}\n\n", title));
                }
                md.push_str(&format!(
                    "**文件**: {}:{}\n\n",
                    finding.file_path, finding.start_line
                ));
                md.push_str(&format!("**描述**: {}\n\n", finding.description));
                if let Some(code) = &finding.code_snippet {
                    md.push_str("**代码**:\n```");
                    md.push_str(code);
                    md.push_str("```\n\n");
                }
            }
        }
    }

    md
}

/// 转换为文本格式
fn to_text(findings: &[FindingData]) -> String {
    let mut text = String::from("审计报告\n");
    text.push_str(&format!("生成时间: {}\n", chrono::Utc::now().to_rfc3339()));
    text.push_str(&format!("漏洞数量: {}\n\n", findings.len()));

    for (i, finding) in findings.iter().enumerate() {
        text.push_str(&format!(
            "[{}] {} - {}\n",
            i + 1,
            finding.severity.to_uppercase(),
            finding.category
        ));
        text.push_str(&format!(
            "    文件: {}:{}\n",
            finding.file_path, finding.start_line
        ));
        if let Some(title) = &finding.title {
            text.push_str(&format!("    标题: {}\n", title));
        }
        text.push('\n');
    }

    text
}

/// SARIF 严重程度映射
fn severity_to_level(severity: &str) -> &str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "none",
    }
}
