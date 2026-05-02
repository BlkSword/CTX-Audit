// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! scan 命令实现
//!
//! 使用预定义规则快速扫描代码

use miette::Result;

use crate::terminal::TerminalRenderer;
use deepaudit_core::scan_directory;
use deepaudit_core::scan_directory_deep;
use deepaudit_core::scan_directory_with_rules;
use deepaudit_core::scan_directory_deep_with_rules;
use deepaudit_core::sarif::{SarifConverter, FindingInput};

/// 执行 scan 命令
pub async fn execute(
    path: String,
    rules_dir: Option<String>,
    severity: Option<String>,
    pattern: Option<String>,
    output_path: Option<String>,
    threads: usize,
    output_format: &str,
    deep: bool,
    daemon: bool,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 验证项目路径
    let project_path = std::path::Path::new(&path);
    if !project_path.exists() {
        renderer.error(&format!("项目路径不存在: {}", path));
        return Err(miette::miette!("项目路径不存在"));
    }

    // 守护进程模式
    if daemon {
        return scan_via_daemon(path, severity, pattern, output_path, output_format, deep, &mut renderer).await;
    }

    scan_local(path, rules_dir, severity, pattern, output_path, output_format, deep, &mut renderer).await
}

/// 本地扫描（直接调用 core）
async fn scan_local(
    path: String,
    rules_dir: Option<String>,
    severity: Option<String>,
    pattern: Option<String>,
    output_path: Option<String>,
    output_format: &str,
    deep: bool,
    renderer: &mut TerminalRenderer,
) -> Result<()> {
    let mode = if deep { "深度扫描" } else { "快速扫描" };
    renderer.info(&format!("{}: {}", mode, path));

    if let Some(ref r) = rules_dir {
        renderer.info(&format!("自定义规则目录: {}", r));
    }

    // 创建进度条
    let pb = renderer.progress_bar(100);
    pb.set_message("正在扫描...");

    let rules_ref = rules_dir.as_deref();
    let findings_result = if deep {
        scan_directory_deep_with_rules(&path, rules_ref).await
    } else {
        scan_directory_with_rules(&path, rules_ref).await
    };

    pb.finish_with_message("扫描完成");

    let findings = match findings_result {
        Ok(f) => f,
        Err(e) => {
            renderer.error(&format!("扫描失败: {}", e));
            return Err(miette::miette!("扫描失败: {}", e));
        }
    };

    // 过滤严重程度
    let filtered_findings = if let Some(sev) = &severity {
        findings
            .into_iter()
            .filter(|f| f.severity.to_lowercase() == sev.to_lowercase())
            .collect()
    } else {
        findings
    };

    // 过滤文件模式
    let filtered_findings = if let Some(pat) = &pattern {
        filtered_findings
            .into_iter()
            .filter(|f| f.file_path.contains(pat.as_str()))
            .collect()
    } else {
        filtered_findings
    };

    for finding in &filtered_findings {
        renderer.finding(
            &finding.severity,
            &finding.vuln_type,
            &finding.file_path,
            finding.line_start as u32,
        );
    }

    renderer.success(&format!(
        "扫描完成！共发现 {} 个漏洞",
        filtered_findings.len()
    ));

    if let Some(output_path) = output_path {
        save_scan_results(&output_path, &filtered_findings, output_format, renderer).await?;
    }

    Ok(())
}

/// 保存扫描结果到文件
async fn save_scan_results(
    output_path: &str,
    findings: &[deepaudit_core::Finding],
    format: &str,
    renderer: &mut TerminalRenderer,
) -> miette::Result<()> {
    // 确保输出目录存在
    if let Some(parent) = std::path::Path::new(output_path).parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    let content = match format {
        "json" => {
            serde_json::to_string_pretty(findings)
                .map_err(|e| miette::miette!("JSON 序列化失败: {}", e))?
        }
        "sarif" => {
            to_sarif(findings)
        }
        "markdown" => {
            to_markdown(findings)
        }
        _ => {
            to_text(findings)
        }
    };

    tokio::fs::write(output_path, content)
        .await
        .map_err(|e| miette::miette!("写入文件失败: {}", e))?;

    renderer.info(&format!("结果已保存到: {}", output_path));
    Ok(())
}

/// 转换为 SARIF 格式 — 使用统一 SarifConverter
fn to_sarif(findings: &[deepaudit_core::Finding]) -> String {
    let converter = SarifConverter::new();
    let inputs: Vec<FindingInput> = findings.iter().map(|f| FindingInput {
        id: Some(f.finding_id.clone()),
        title: Some(f.vuln_type.clone()),
        description: f.description.clone(),
        severity: f.severity.clone(),
        category: f.vuln_type.clone(),
        cwe_id: None, // core::Finding 没有 cwe_id 字段
        file_path: f.file_path.clone(),
        start_line: f.line_start as u32,
        end_line: Some(f.line_end as u32),
        start_column: None,
        end_column: None,
        code_snippet: None,
        recommendation: None,
        status: "detected".to_string(),
        verification_status: None,
        discovered_by: Some(f.detector.clone()),
        code_flows: None,
        fix_suggestions: None,
        confidence: None,
    }).collect();

    converter.convert_to_json(&inputs).unwrap_or_default()
}

/// 转换为 Markdown 格式
fn to_markdown(findings: &[deepaudit_core::Finding]) -> String {
    let mut md = String::from("# 扫描报告\n\n");
    md.push_str(&format!("**生成时间**: {}\n\n", chrono::Utc::now().to_rfc3339()));
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
            md.push_str(&format!("## {} ({})\n\n", severity.to_uppercase(), items.len()));
            for finding in items {
                md.push_str(&format!("### {}\n\n", finding.vuln_type));
                md.push_str(&format!("**文件**: {}:{}\n\n", finding.file_path, finding.line_start));
                md.push_str(&format!("**描述**: {}\n\n", finding.description));
            }
        }
    }

    md
}

/// 转换为文本格式
fn to_text(findings: &[deepaudit_core::Finding]) -> String {
    let mut text = String::from("扫描报告\n");
    text.push_str(&format!("生成时间: {}\n", chrono::Utc::now().to_rfc3339()));
    text.push_str(&format!("漏洞数量: {}\n\n", findings.len()));

    for (i, finding) in findings.iter().enumerate() {
        text.push_str(&format!("[{}] {} - {}\n", i + 1, finding.severity.to_uppercase(), finding.vuln_type));
        text.push_str(&format!("    文件: {}:{}\n", finding.file_path, finding.line_start));
        text.push_str(&format!("    描述: {}\n", finding.description));
        text.push('\n');
    }

    text
}

/// 通过守护进程执行扫描（带优雅降级）
async fn scan_via_daemon(
    path: String,
    severity: Option<String>,
    pattern: Option<String>,
    output_path: Option<String>,
    output_format: &str,
    deep: bool,
    renderer: &mut TerminalRenderer,
) -> Result<()> {
    let mut client = match ctx_audit_daemon::client::DaemonClient::connect_with_retry().await {
        Ok(c) => c,
        Err(e) => {
            renderer.warning(&format!("连接守护进程失败: {}", e));
            renderer.info("降级为本地扫描模式...");
            return scan_local(path, None, severity, pattern, output_path, output_format, deep, renderer).await;
        }
    };

    renderer.info(&format!("通过守护进程扫描: {}", path));
    let pb = renderer.progress_bar(100);
    pb.set_message("扫描中...");

    let response = match client.scan(path.clone(), deep, severity.clone(), pattern.clone()).await {
        Ok(r) => r,
        Err(e) => {
            pb.finish_with_message("守护进程扫描失败");
            renderer.warning(&format!("守护进程扫描失败: {}", e));
            renderer.info("降级为本地扫描模式...");
            return scan_local(path, None, severity, pattern, output_path, output_format, deep, renderer).await;
        }
    };

    pb.finish_with_message("扫描完成");

    match response {
        ctx_audit_daemon::protocol::Response::ScanResult { findings, duration_ms, files_scanned } => {
            renderer.success(&format!(
                "扫描完成！发现 {} 个问题 (耗时 {}ms, 扫描 {} 个文件)",
                findings.len(), duration_ms, files_scanned
            ));

            for finding in &findings {
                if let (Some(sev), Some(title), Some(file), Some(line)) = (
                    finding.get("severity").and_then(|v| v.as_str()),
                    finding.get("vuln_type").and_then(|v| v.as_str()),
                    finding.get("file_path").and_then(|v| v.as_str()),
                    finding.get("line_start").and_then(|v| v.as_u64()),
                ) {
                    renderer.finding(sev, title, file, line as u32);
                }
            }

            if let Some(output_path) = output_path {
                // 将 JSON values 转回 Finding 结构用于格式化输出
                let parsed_findings: Vec<deepaudit_core::Finding> = findings.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect();

                if let Some(parent) = std::path::Path::new(&output_path).parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }

                let content = match output_format {
                    "sarif" => {
                        let converter = deepaudit_core::sarif::SarifConverter::new();
                        let inputs: Vec<deepaudit_core::sarif::FindingInput> = parsed_findings.iter().map(|f| deepaudit_core::sarif::FindingInput {
                            id: Some(f.finding_id.clone()),
                            title: Some(f.vuln_type.clone()),
                            description: f.description.clone(),
                            severity: f.severity.clone(),
                            category: f.vuln_type.clone(),
                            cwe_id: None,
                            file_path: f.file_path.clone(),
                            start_line: f.line_start as u32,
                            end_line: Some(f.line_end as u32),
                            start_column: None,
                            end_column: None,
                            code_snippet: None,
                            recommendation: None,
                            status: "detected".to_string(),
                            verification_status: None,
                            discovered_by: Some(f.detector.clone()),
                            code_flows: None,
                            fix_suggestions: None,
                            confidence: None,
                        }).collect();
                        converter.convert_to_json(&inputs).unwrap_or_default()
                    }
                    "markdown" => to_markdown(&parsed_findings),
                    "json" => serde_json::to_string_pretty(&findings)
                        .map_err(|e| miette::miette!("JSON 序列化失败: {}", e))?,
                    _ => to_text(&parsed_findings),
                };
                tokio::fs::write(&output_path, content).await
                    .map_err(|e| miette::miette!("写入文件失败: {}", e))?;
                renderer.info(&format!("结果已保存到: {}", output_path));
            }
        }
        ctx_audit_daemon::protocol::Response::Error { message, .. } => {
            renderer.error(&format!("扫描失败: {}", message));
            return Err(miette::miette!("扫描失败: {}", message));
        }
        _ => {
            renderer.error("意外的响应类型");
        }
    }

    Ok(())
}
