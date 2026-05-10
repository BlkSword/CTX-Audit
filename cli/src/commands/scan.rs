// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! scan 命令实现
//!
//! 使用预定义规则快速扫描代码

use miette::Result;

use crate::terminal::TerminalRenderer;
use ctx_audit_daemon::client::DaemonClient;
use ctx_audit_daemon::protocol::Response;
use deepaudit_core::scanning::{
    scan_directory, scan_directory_deep,
    scan_directory_with_rules, scan_directory_deep_with_rules,
    scan_directory_with_rules_progress, scan_directory_deep_with_rules_progress,
    scan_directory_with_opts,
    Finding, ScaScanOptions, ScaSeverityMapping,
    ScanOptions, ScanPhase, ScanProgress,
};
use deepaudit_core::sarif::{SarifConverter, FindingInput};
use std::sync::Arc;

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
    exclude: String,
    sca_enabled: bool,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 验证项目路径
    let project_path = std::path::Path::new(&path);
    if !project_path.exists() {
        renderer.error(&format!("项目路径不存在: {}", path));
        return Err(miette::miette!("项目路径不存在"));
    }

    // 解析排除目录
    let exclude_dirs: Vec<String> = exclude
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // 加载 SCA 配置
    let sca_options = build_sca_options(sca_enabled);

    // 守护进程模式
    if daemon {
        return scan_via_daemon(path, severity, pattern, output_path, output_format, deep, &mut renderer).await;
    }

    scan_local(path, rules_dir, severity, pattern, output_path, output_format, deep, exclude_dirs, &mut renderer, sca_options).await
}

/// 从配置文件 + CLI flag 构建 SCA 选项
fn build_sca_options(cli_enabled: bool) -> ScaScanOptions {
    let config = crate::config::ConfigManager::new(None)
        .ok()
        .map(|m| m.config().sca.clone());

    match config {
        Some(sca_cfg) => {
            // CLI --sca flag 覆盖配置文件
            let enabled = cli_enabled || sca_cfg.enabled;
            ScaScanOptions {
                enabled,
                ignore_vulns: sca_cfg.ignore_vulns,
                ignore_packages: sca_cfg.ignore_packages,
                ignore_ecosystems: sca_cfg.ignore_ecosystems,
                dev_dependencies: sca_cfg.dev_dependencies,
                severity_threshold: sca_cfg.severity_threshold,
                severity_mapping: ScaSeverityMapping {
                    critical: sca_cfg.severity_mapping.critical,
                    high: sca_cfg.severity_mapping.high,
                    medium: sca_cfg.severity_mapping.medium,
                },
                cache_ttl_hours: sca_cfg.cache_ttl_hours,
                osv_timeout_sec: sca_cfg.osv_timeout_sec,
                fail_offline: sca_cfg.fail_offline,
            }
        }
        None => ScaScanOptions {
            enabled: cli_enabled,
            ..ScaScanOptions::default()
        },
    }
}

/// 从配置文件构建 ScanOptions
fn build_scan_options() -> ScanOptions {
    let config = crate::config::ConfigManager::new(None)
        .ok()
        .map(|m| {
            let scan = &m.config().scan;
            (scan.threads, scan.max_file_size_mb, scan.memory_budget_mb, scan.batch_size, scan.line_tolerance, scan.include_tests)
        });

    match config {
        Some((threads, max_mb, mem_mb, batch, tol, include_tests)) => ScanOptions {
            threads,
            max_file_size: max_mb * 1024 * 1024,
            memory_budget: mem_mb * 1024 * 1024,
            batch_size: batch,
            line_tolerance: tol,
            include_tests,
        },
        None => ScanOptions::default(),
    }
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
    exclude_dirs: Vec<String>,
    renderer: &mut TerminalRenderer,
    sca_options: ScaScanOptions,
) -> Result<()> {
    let mode = if deep { "深度扫描" } else { "快速扫描" };
    renderer.info(&format!("{}: {}", mode, path));

    if let Some(ref r) = rules_dir {
        renderer.info(&format!("自定义规则目录: {}", r));
    }

    // 从配置文件构建 ScanOptions
    let scan_opts = build_scan_options();

    // 配置 rayon 线程池（仅在配置值非默认时）
    let _thread_pool = if scan_opts.threads != 4 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(scan_opts.threads)
            .build_global()
            .ok()
    } else {
        None
    };

    // 创建带 ETA 的进度条
    let pb = renderer.progress_bar(0); // total will be set dynamically
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ETA:{eta} {msg}"
        )
        .expect("valid template")
        .progress_chars("##>-")
    );
    pb.set_message("准备扫描...");

    let pb_clone = pb.clone();
    let progress_cb: Option<Arc<dyn Fn(ScanProgress) + Send + Sync>> = Some(Arc::new(move |p: ScanProgress| {
        let label = match p.phase {
            ScanPhase::FileWalking => "文件收集",
            ScanPhase::ScaScanning => "SCA 扫描",
            ScanPhase::RuleScanning => "规则扫描",
            ScanPhase::CandidateSelection => "候选选取",
            ScanPhase::TaintAnalysis => "污点分析",
            ScanPhase::CrossFileAnalysis => "跨文件分析",
        };
        if p.total > 0 {
            pb_clone.set_length(p.total as u64);
        }
        pb_clone.set_position(p.current as u64);
        pb_clone.set_message(format!("[{}] {}", label, p.message));
    }));

    let rules_ref = rules_dir.as_deref();
    let exclude_opt = if exclude_dirs.is_empty() { None } else { Some(exclude_dirs) };
    let sca_opt = Some(sca_options);
    let findings_result = if deep {
        scan_directory_deep_with_rules_progress(&path, rules_ref, exclude_opt, sca_opt, Some(scan_opts), progress_cb).await
    } else {
        scan_directory_with_opts(&path, rules_ref, exclude_opt, sca_opt, scan_opts, progress_cb).await
    };

    pb.finish_with_message("完成");

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
    findings: &[Finding],
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
fn to_sarif(findings: &[Finding]) -> String {
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
fn to_markdown(findings: &[Finding]) -> String {
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
fn to_text(findings: &[Finding]) -> String {
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
    let mut client = match DaemonClient::connect_with_retry().await {
        Ok(c) => c,
        Err(e) => {
            renderer.warning(&format!("连接守护进程失败: {}", e));
            renderer.info("降级为本地扫描模式...");
            return scan_local(path, None, severity, pattern, output_path, output_format, deep, vec![], renderer, ScaScanOptions::default()).await;
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
            return scan_local(path, None, severity, pattern, output_path, output_format, deep, vec![], renderer, ScaScanOptions::default()).await;
        }
    };

    pb.finish_with_message("扫描完成");

    match response {
        Response::ScanResult { findings, duration_ms, files_scanned } => {
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
                let parsed_findings: Vec<Finding> = findings.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect();

                if let Some(parent) = std::path::Path::new(&output_path).parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }

                let content = match output_format {
                    "sarif" => {
                        let converter = SarifConverter::new();
                        let inputs: Vec<FindingInput> = parsed_findings.iter().map(|f| FindingInput {
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
        Response::Error { message, .. } => {
            renderer.error(&format!("扫描失败: {}", message));
            return Err(miette::miette!("扫描失败: {}", message));
        }
        _ => {
            renderer.error("意外的响应类型");
        }
    }

    Ok(())
}
