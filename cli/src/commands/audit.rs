// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! audit 命令实现
//!
//! 使用专业安全审计框架进行深度代码安全分析

use miette::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::config::ConfigManager;
use crate::terminal::{StreamEvent, StreamOutput, TerminalRenderer};
use ctx_audit_agent_engine::{
    SecurityAuditState, AuditPhase, PhaseAwareExecutor, PhaseResult,
    DeterministicPrescanner, PrescanConfig, ProjectInfoCollector,
    ExecutionEvent, ExecutionConfig, SecurityAuditChain,
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

/// 执行 audit 命令（使用新的专业审计框架）
pub async fn execute(
    path: String,
    _audit_type: String,
    max_iterations: Option<u32>,
    _skip_verification: bool,
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

    renderer.info(&format!("[安全] 开始专业安全审计: {}", path));
    if verbose {
        renderer.info("[信息] 详细模式已启用");
    }

    // 初始化 LLM 工厂
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

    // 初始化 AST 引擎
    let cache_dir = std::env::temp_dir().join("ctx-audit-cache");
    let _ = std::fs::create_dir_all(&cache_dir);
    let ast_engine = Some(Arc::new(deepaudit_core::ASTEngine::new(
        cache_dir.to_string_lossy().as_ref(),
    )));

    // 注册所有工具
    ctx_audit_tools::register_all_tools(&tool_registry, path.clone(), ast_engine).await;

    // 创建审计状态
    let mut audit_state = SecurityAuditState::new(path.clone());

    // 创建执行配置
    let exec_config = ExecutionConfig {
        max_iterations,
        timeout_secs: Some(600),
        enable_streaming: verbose,
        temperature: 0.7,
        max_tokens: 4096,
    };

    // 创建阶段感知执行器
    let executor = PhaseAwareExecutor::new(llm, tool_registry, exec_config);

    // 创建事件通道（用于详细输出）
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<ExecutionEvent>();

    // 启动事件处理任务
    let event_handle = if verbose {
        Some(tokio::spawn(async move {
            use console::Style;
            use std::io::{stdout, Write};

            let dim_style = Style::new().dim();
            let cyan_style = Style::new().cyan();
            let green_style = Style::new().green();
            let yellow_style = Style::new().yellow();

            while let Some(event) = event_rx.recv().await {
                match event {
                    ExecutionEvent::IterationStart(iteration) => {
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            cyan_style.apply_to(format!("  [迭代 {}]", iteration))
                        );
                    }
                    ExecutionEvent::ThoughtComplete { iteration: _, thought, action } => {
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            dim_style.apply_to(format!("    [思考] {}", truncate_utf8(&thought, 200)))
                        );
                        if let Some(action_name) = action {
                            let _ = writeln!(
                                stdout(),
                                "{}",
                                yellow_style.apply_to(format!("    [决定] {}", action_name))
                            );
                        }
                    }
                    ExecutionEvent::ToolCallStart { tool_name, input } => {
                        let input_str = truncate_utf8(&input.to_string(), 100);
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            cyan_style.apply_to(format!("    [工具] {}: {}", tool_name, input_str))
                        );
                    }
                    ExecutionEvent::ToolCallComplete { tool_name, result, duration_ms } => {
                        let status = if result.is_error { "[失败]" } else { "[成功]" };
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            green_style.apply_to(format!(
                                "    {} {} ({}ms)",
                                status, tool_name, duration_ms
                            ))
                        );
                    }
                    ExecutionEvent::ToolCallFailed { tool_name, error } => {
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            console::style(format!("    [错误] {}: {}", tool_name, error)).red()
                        );
                    }
                    ExecutionEvent::StreamToken(token) => {
                        print!("{}", dim_style.apply_to(&token));
                        let _ = stdout().flush();
                    }
                    ExecutionEvent::Complete { iterations, tool_calls } => {
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            green_style.apply_to(format!(
                                "  [完成] {} 次迭代, {} 次工具调用",
                                iterations, tool_calls
                            ))
                        );
                    }
                    ExecutionEvent::Failed(error) => {
                        let _ = writeln!(
                            stdout(),
                            "{}",
                            console::style(format!("  [失败] {}", error)).red()
                        );
                    }
                }
            }
        }))
    } else {
        None
    };

    // 创建带事件发送器的执行器
    let mut executor = executor.with_event_tx(event_tx);

    renderer.info("");
    renderer.info("================================================");
    renderer.info("           [阶段1] 项目初始化                   ");
    renderer.info("================================================");

    // 阶段 1: 初始化
    let init_result = executor.execute_initialization(&mut audit_state).await;
    print_phase_result(&init_result, &mut renderer);

    renderer.info("");
    renderer.info("================================================");
    renderer.info("           [阶段2] 确定性扫描                   ");
    renderer.info("================================================");

    // 阶段 2: 确定性扫描
    let scan_result = executor.execute_deterministic_scan(&mut audit_state).await;
    print_phase_result(&scan_result, &mut renderer);

    // 显示候选漏洞摘要
    if !audit_state.vulnerability_candidates.is_empty() {
        renderer.info("");
        renderer.info(&format!(
            "[信息] 发现 {} 个候选漏洞待验证",
            audit_state.vulnerability_candidates.len()
        ));

        // 按严重程度统计
        let mut by_severity: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for candidate in &audit_state.vulnerability_candidates {
            *by_severity.entry(candidate.severity.as_str()).or_insert(0) += 1;
        }
        for severity in ["critical", "high", "medium", "low"] {
            if let Some(&count) = by_severity.get(severity) {
                renderer.info(&format!("   {}: {}", severity.to_uppercase(), count));
            }
        }
    }

    renderer.info("");
    renderer.info("================================================");
    renderer.info("           [阶段3] 深度分析                     ");
    renderer.info("================================================");

    // 阶段 3: 深度分析
    let analysis_result = executor.execute_deep_analysis(&mut audit_state).await;
    print_phase_result(&analysis_result, &mut renderer);

    renderer.info("");
    renderer.info("================================================");
    renderer.info("           [阶段4] 漏洞验证                     ");
    renderer.info("================================================");

    // 阶段 4: 验证
    let verification_result = executor.execute_verification(&mut audit_state).await;
    print_phase_result(&verification_result, &mut renderer);

    renderer.info("");
    renderer.info("================================================");
    renderer.info("           [阶段5] 生成报告                     ");
    renderer.info("================================================");

    // 阶段 5: 报告
    let report_result = executor.execute_reporting(&mut audit_state).await;
    print_phase_result(&report_result, &mut renderer);

    // 清理事件处理任务
    if let Some(handle) = event_handle {
        handle.abort();
    }

    // 转换确认的漏洞为 FindingData
    let all_findings: Vec<FindingData> = audit_state.confirmed_vulnerabilities
        .iter()
        .map(|v| FindingData {
            id: Some(v.id.clone()),
            title: Some(v.vulnerability_type.clone()),
            description: format!(
                "来源: {}\n置信度: {:.0}%\n{}",
                v.source,
                v.confidence * 100.0,
                v.code_snippet.as_deref().unwrap_or("")
            ),
            severity: v.severity.clone(),
            category: v.vulnerability_type.clone(),
            cwe_id: None,
            file_path: v.file_path.clone(),
            start_line: v.line as u32,
            end_line: Some(v.line as u32),
            code_snippet: v.code_snippet.clone(),
            recommendation: None,
            status: "confirmed".to_string(),
            verification_status: Some(format!("{:?}", v.verification_status)),
            discovered_by: Some(v.source.clone()),
            extra: std::collections::HashMap::new(),
        })
        .collect();

    // 输出最终摘要
    renderer.info("");
    renderer.info("================================================");
    renderer.success(&format!(
        "[完成] 审计完成！共发现 {} 个确认漏洞",
        all_findings.len()
    ));
    renderer.info(&format!(
        "[统计] LLM 调用 {} 次, 工具调用 {} 次, 分析文件 {} 个",
        audit_state.stats.llm_calls,
        audit_state.stats.tool_calls,
        audit_state.stats.files_analyzed
    ));
    renderer.info("================================================");

    // 显示漏洞摘要
    if !all_findings.is_empty() {
        renderer.info("");
        renderer.info("[漏洞] 确认的漏洞:");

        // 按严重程度分组显示
        let mut by_severity: std::collections::HashMap<&str, Vec<&FindingData>> = std::collections::HashMap::new();
        for finding in &all_findings {
            by_severity.entry(&finding.severity).or_default().push(finding);
        }

        for severity in ["critical", "high", "medium", "low"] {
            if let Some(findings) = by_severity.get(severity) {
                let level = match severity {
                    "critical" => "[!!!]",
                    "high" => "[!!]",
                    "medium" => "[!]",
                    _ => "[*]",
                };
                renderer.info(&format!(
                    "  {} {} ({}):",
                    level,
                    severity.to_uppercase(),
                    findings.len()
                ));
                for finding in findings {
                    renderer.info(&format!(
                        "    - {}:{} - {}",
                        finding.file_path,
                        finding.start_line,
                        finding.title.as_deref().unwrap_or(&finding.category)
                    ));
                }
            }
        }
    }

    // 自动生成报告文件
    let report_timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let project_name = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project");
    let default_output_path = format!("./{}_audit_{}.json", project_name, report_timestamp);
    let final_output_path = output_path.unwrap_or(default_output_path);

    // 生成完整报告
    let full_report = generate_full_report(
        &audit_state,
        &all_findings,
        executor.get_audit_chain(),
        &path,
    );

    // 保存报告
    save_full_report(&final_output_path, &full_report, &mut renderer).await?;

    renderer.info("");
    renderer.success(&format!("[报告] 已保存到: {}", final_output_path));

    Ok(())
}

/// 打印阶段结果
fn print_phase_result(result: &PhaseResult, renderer: &mut TerminalRenderer) {
    if result.success {
        renderer.success(&format!("[OK] {} 完成 ({})", result.phase, format_duration(result.duration_ms)));
        if !result.message.is_empty() {
            for line in result.message.lines().take(10) {
                renderer.info(&format!("   {}", line));
            }
        }
    } else {
        renderer.error(&format!("[ERR] {} 失败: {}", result.phase, result.message));
    }
}

/// 格式化持续时间
fn format_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{:.1}m", ms as f64 / 60000.0)
    }
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

    renderer.info(&format!("[保存] 结果已保存到: {}", output_path));
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
    let mut md = String::from("# 安全审计报告\n\n");
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
                    md.push_str("**代码**:\n```\n");
                    md.push_str(code);
                    md.push_str("\n```\n\n");
                }
            }
        }
    }

    md
}

/// 转换为文本格式
fn to_text(findings: &[FindingData]) -> String {
    let mut text = String::from("安全审计报告\n");
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

/// 生成完整的审计报告
fn generate_full_report(
    state: &SecurityAuditState,
    findings: &[FindingData],
    audit_chain: &SecurityAuditChain,
    project_path: &str,
) -> serde_json::Value {
    let completed_at = chrono::Utc::now();

    serde_json::json!({
        "meta": {
            "tool": "CTX-Audit",
            "version": env!("CARGO_PKG_VERSION"),
            "generated_at": completed_at.to_rfc3339(),
        },
        "session": {
            "id": state.session_id,
            "project_path": project_path,
            "started_at": state.started_at.to_rfc3339(),
            "completed_at": completed_at.to_rfc3339(),
            "duration_seconds": (completed_at - state.started_at).num_seconds(),
        },
        "project": {
            "tech_stack": state.project_info.tech_stack,
            "frameworks": state.project_info.frameworks,
            "project_type": state.project_info.project_type,
            "entry_points": state.project_info.entry_points,
        },
        "statistics": {
            "files_scanned": state.stats.files_analyzed,
            "llm_calls": state.stats.llm_calls,
            "tool_calls": state.stats.tool_calls,
            "total_candidates": state.vulnerability_candidates.len(),
            "confirmed_vulnerabilities": findings.len(),
            "false_positives": state.false_positives.len(),
            "by_severity": {
                "critical": findings.iter().filter(|f| f.severity == "critical").count(),
                "high": findings.iter().filter(|f| f.severity == "high").count(),
                "medium": findings.iter().filter(|f| f.severity == "medium").count(),
                "low": findings.iter().filter(|f| f.severity == "low").count(),
            },
        },
        "audit_chain": {
            "phase": audit_chain.phase.display_name(),
            "hypotheses_generated": audit_chain.stats.hypotheses_generated,
            "hypotheses_confirmed": audit_chain.stats.confirmed_vulnerabilities,
            "false_positives_excluded": audit_chain.stats.false_positives_excluded,
            "evidence_collected": audit_chain.stats.evidence_collected,
            "thought_iterations": audit_chain.stats.thought_iterations,
        },
        "vulnerabilities": findings.iter().map(|f| serde_json::json!({
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "cwe_id": f.cwe_id,
            "file_path": f.file_path,
            "line": f.start_line,
            "end_line": f.end_line,
            "code_snippet": f.code_snippet,
            "description": f.description,
            "recommendation": f.recommendation,
            "status": f.status,
            "verification_status": f.verification_status,
            "discovered_by": f.discovered_by,
        })).collect::<Vec<_>>(),
        "vulnerability_candidates": state.vulnerability_candidates.iter().map(|c| serde_json::json!({
            "id": c.id,
            "type": c.vulnerability_type,
            "severity": c.severity,
            "confidence": c.confidence,
            "file_path": c.file_path,
            "line": c.line,
            "code_snippet": c.code_snippet,
            "source": c.source,
            "verification_status": format!("{:?}", c.verification_status),
        })).collect::<Vec<_>>(),
    })
}

/// 保存完整报告到文件
async fn save_full_report(
    output_path: &str,
    report: &serde_json::Value,
    renderer: &mut TerminalRenderer,
) -> Result<()> {
    let content = serde_json::to_string_pretty(report)
        .map_err(|e| miette::miette!("JSON 序列化失败: {}", e))?;

    tokio::fs::write(output_path, content)
        .await
        .map_err(|e| miette::miette!("写入报告文件失败: {}", e))?;

    renderer.info(&format!("[保存] 报告已保存到: {}", output_path));
    Ok(())
}
