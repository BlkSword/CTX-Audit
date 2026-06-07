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

/// 严重程度排序值
fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "info" => 0,
        _ => 0,
    }
}

/// 加载扫描配置（合并配置文件 + CLI 覆盖）
fn load_scan_filter_config(cli_min_severity: Option<String>) -> (String, usize, Vec<String>, bool) {
    let config = crate::config::ConfigManager::new(None)
        .ok()
        .map(|m| {
            let scan = &m.config().scan;
            (scan.min_severity.clone(), scan.context_lines, scan.exclude_extra.clone(), scan.include_tests)
        });

    match config {
        Some((min_sev, ctx_lines, extra_excludes, include_tests)) => {
            let effective_min = cli_min_severity.unwrap_or(min_sev);
            (effective_min, ctx_lines, extra_excludes, include_tests)
        }
        None => {
            let effective_min = cli_min_severity.unwrap_or_else(|| "medium".to_string());
            (effective_min, 3, Vec::new(), false)
        }
    }
}

/// 执行 scan 命令
pub async fn execute(
    path: String,
    rules_dir: Option<String>,
    severity: Option<String>,
    min_severity: Option<String>,
    pattern: Option<String>,
    output_path: Option<String>,
    threads: usize,
    output_format: &str,
    deep: bool,
    taint: bool,
    cross_file: bool,
    daemon: bool,
    exclude: String,
    sca_enabled: bool,
    graph_output: Option<String>,
    query_mode: bool,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 解析引擎标志：--deep = --taint --cross-file；--cross-file 隐含 --taint
    let enable_taint = taint || deep || cross_file;
    let enable_cross_file = cross_file || deep;

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

    // 加载配置文件驱动的过滤参数
    let (effective_min_severity, _context_lines, _extra_excludes, _include_tests) =
        load_scan_filter_config(min_severity);

    // 加载 SCA 配置
    let sca_options = build_sca_options(sca_enabled);

    // 守护进程模式
    if daemon {
        if graph_output.is_some() || query_mode {
            renderer.warning("--graph-output 和 --query-mode 在 daemon 模式下不可用，降级为本地扫描");
            return scan_local(path, rules_dir, severity, effective_min_severity, pattern, output_path, output_format, enable_taint, enable_cross_file, exclude_dirs, &mut renderer, sca_options, graph_output, query_mode).await;
        }
        return scan_via_daemon(path, severity, effective_min_severity, pattern, output_path, output_format, enable_taint, enable_cross_file, &mut renderer).await;
    }

    scan_local(path, rules_dir, severity, effective_min_severity, pattern, output_path, output_format, enable_taint, enable_cross_file, exclude_dirs, &mut renderer, sca_options, graph_output, query_mode).await
}

/// 从配置文件 + CLI flag 构建 SCA 选项
fn build_sca_options(cli_enabled: bool) -> ScaScanOptions {
    let config = crate::config::ConfigManager::new(None)
        .ok()
        .map(|m| m.config().sca.clone());

    match config {
        Some(sca_cfg) => {
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
            enable_taint: false,
            enable_cross_file: false,
        },
        None => ScanOptions::default(),
    }
}

/// 构建完整排除列表：配置文件 exclude_patterns + exclude_extra + CLI --exclude
/// 配置文件为准：若文件存在则完全使用文件中的 exclude_patterns，否则使用代码默认值
fn build_exclude_dirs(cli_excludes: Vec<String>) -> Vec<String> {
    let config = crate::config::ConfigManager::new(None)
        .ok()
        .map(|m| {
            let scan = &m.config().scan;
            (scan.exclude_patterns.clone(), scan.exclude_extra.clone())
        });

    // 配置文件存在时以其 exclude_patterns 为准；不存在时 Default impl 提供完整默认值
    let (base_patterns, extra_patterns) = match config {
        Some((base, extra)) => (base, extra),
        None => {
            // ConfigManager 加载失败（路径找不到等极端情况），使用硬编码默认值
            let defaults = vec![
                "node_modules", ".git", "target", "build", "dist", "vendor",
                "__pycache__", ".gradle", ".idea", ".vscode", ".cache",
                "bower_components", ".next", ".nuxt", "coverage",
                "test", "tests", "__tests__", "spec", "fixtures", "e2e",
                "examples", "example", "scripts",
                "*.min.js", "*.min.css", "*.bundle.js", "*.chunk.js",
                "*.map", ".env.*", "*.test.*", "*.spec.*",
            ];
            (defaults.iter().map(|s| s.to_string()).collect(), vec![])
        }
    };

    let mut combined = base_patterns;
    for extra in extra_patterns {
        let trimmed = extra.trim().to_string();
        if !trimmed.is_empty() && !combined.contains(&trimmed) {
            combined.push(trimmed);
        }
    }
    for cli in cli_excludes {
        let trimmed = cli.trim().to_string();
        if !trimmed.is_empty() && !combined.contains(&trimmed) {
            combined.push(trimmed);
        }
    }
    combined
}

/// 本地扫描（直接调用 core）
async fn scan_local(
    path: String,
    rules_dir: Option<String>,
    severity: Option<String>,
    min_severity: String,
    pattern: Option<String>,
    output_path: Option<String>,
    output_format: &str,
    enable_taint: bool,
    enable_cross_file: bool,
    exclude_dirs: Vec<String>,
    renderer: &mut TerminalRenderer,
    sca_options: ScaScanOptions,
    graph_output: Option<String>,
    query_mode: bool,
) -> Result<()> {
    let mode = match (enable_taint, enable_cross_file) {
        (true, true) => "深度扫描 (规则 + 污点 + 跨文件)",
        (true, false) => "扫描 (规则 + 污点分析)",
        (false, _) => "快速扫描 (规则)",
    };
    renderer.info(&format!("{}: {}", mode, path));

    if let Some(ref r) = rules_dir {
        renderer.info(&format!("自定义规则目录: {}", r));
    }

    // 从配置文件构建 ScanOptions
    let mut scan_opts = build_scan_options();
    scan_opts.enable_taint = enable_taint;
    scan_opts.enable_cross_file = enable_cross_file;

    // 合并排除列表：CLI + 配置文件 exclude_extra
    let all_excludes = build_exclude_dirs(exclude_dirs);

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
    let exclude_opt = if all_excludes.is_empty() { None } else { Some(all_excludes) };
    let sca_opt = Some(sca_options);
    let findings_result = if enable_taint || enable_cross_file {
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

    // 过滤严重程度：先按最低阈值过滤，再按精确级别过滤
    let min_rank = severity_rank(&min_severity);
    let total_before = findings.len();
    let mut filtered_findings: Vec<Finding> = findings
        .into_iter()
        .filter(|f| severity_rank(&f.severity) >= min_rank)
        .collect();
    let suppressed_count = total_before - filtered_findings.len();

    // 精确级别过滤（--severity）
    let filtered_findings = if let Some(sev) = &severity {
        filtered_findings
            .into_iter()
            .filter(|f| f.severity.to_lowercase() == sev.to_lowercase())
            .collect()
    } else {
        filtered_findings
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
        "扫描完成！共发现 {} 个漏洞{}",
        filtered_findings.len(),
        if suppressed_count > 0 {
            format!("（已过滤 {} 个低级别发现）", suppressed_count)
        } else {
            String::new()
        }
    ));

    if let Some(output_path) = output_path {
        // 区分格式名 vs 真实文件路径
        let is_format_shorthand = !output_path.contains(std::path::MAIN_SEPARATOR)
            && !output_path.contains('/')
            && std::path::Path::new(&output_path).extension().is_none()
            && matches!(
                output_path.to_lowercase().as_str(),
                "json" | "sarif" | "llm" | "markdown" | "md"
            );

        let (effective_format, effective_file_path) = if is_format_shorthand {
            let lower = output_path.to_lowercase();
            let format_name = match lower.as_str() {
                "md" => "markdown",
                other => other,
            };
            let format_name = format_name.to_string();
            let ext = match format_name.as_str() {
                "llm" => "json",
                "sarif" => "sarif",
                other => other,
            };
            let timestamp = chrono::Local::now().format("%Y-%m-%d");
            let filename = format!("ctx-audit-{}-{}.{}", format_name, timestamp, ext);
            (format_name, filename)
        } else {
            let format = std::path::Path::new(&output_path)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| match e.to_lowercase().as_str() {
                    "json" => "json",
                    "sarif" => "sarif",
                    "md" => "markdown",
                    _ => output_format,
                })
                .unwrap_or(output_format);
            (format.to_string(), output_path.clone())
        };

        save_scan_results(&effective_file_path, &filtered_findings, &effective_format, renderer).await?;
    }

    // --graph-output: 单独构建并导出调用图
    if let Some(ref graph_path) = graph_output {
        renderer.info("构建跨文件调用图...");
        let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(std::path::Path::new(&path));
        let engine = deepaudit_core::CallGraphQueryEngine::from_result(&result);

        let stats = engine.query_graph_stats();
        let all_functions: Vec<_> = engine.query_files().iter()
            .flat_map(|f| engine.query_functions_in_file(f))
            .collect();
        let all_callers: Vec<_> = all_functions.iter()
            .flat_map(|f| engine.query_callers(&f.id.split(':').next().unwrap_or(""), &f.name))
            .take(500)
            .collect();
        let all_callees: Vec<_> = all_functions.iter()
            .flat_map(|f| engine.query_callees(&f.id.split(':').next().unwrap_or(""), &f.name))
            .take(500)
            .collect();

        let graph_json = serde_json::json!({
            "project_path": &path,
            "stats": stats,
            "functions": all_functions,
            "sample_callers": all_callers,
            "sample_callees": all_callees,
        });

        let graph_content = serde_json::to_string_pretty(&graph_json)
            .map_err(|e| miette::miette!("JSON serialization failed: {}", e))?;
        tokio::fs::write(graph_path, graph_content)
            .await
            .map_err(|e| miette::miette!("Failed to write graph: {}", e))?;
        renderer.info(&format!("调用图已导出到: {}", graph_path));
    }

    // --query-mode: 仅构建调用图，不运行规则扫描输出
    if query_mode {
        renderer.info("查询模式：构建跨文件调用图...");
        let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(std::path::Path::new(&path));
        let engine = deepaudit_core::CallGraphQueryEngine::from_result(&result);
        let stats = engine.query_graph_stats();

        renderer.info(&format!(
            "调用图已就绪: {} 节点, {} 边, {} 跨文件边, {} source, {} sink, {} 类型, {} 中间件",
            stats.total_nodes, stats.total_edges, stats.cross_file_edges,
            stats.taint_sources, stats.taint_sinks,
            stats.type_count, stats.middleware_count,
        ));
        renderer.info("调用图已加载到内存，可通过 MCP 工具查询 (query_callers, trace_variable_flow 等)");
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
        "llm" => {
            to_llm_json(findings)
        }
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
        if let Some(ref trail) = finding.analysis_trail {
            if !trail.is_empty() {
                text.push_str("    污点链:\n");
                for step in trail {
                    text.push_str(&format!("      → {}\n", step));
                }
            }
        }
        text.push('\n');
    }

    text
}

/// 转换为 LLM 面向的 JSON 格式
fn to_llm_json(findings: &[Finding]) -> String {
    use serde_json::{json, Value};

    let mut by_severity = std::collections::HashMap::new();
    let mut by_detector = std::collections::HashMap::new();
    let mut by_file_role = std::collections::HashMap::new();
    for f in findings {
        *by_severity.entry(f.severity.clone()).or_insert(0usize) += 1;
        *by_detector.entry(f.detector.clone()).or_insert(0usize) += 1;
        if let Some(ref role) = f.file_role {
            *by_file_role.entry(role.clone()).or_insert(0usize) += 1;
        }
    }

    let findings_json: Vec<Value> = findings.iter().map(|f| {
        let mut obj = json!({
            "id": f.finding_id,
            "severity": f.severity,
            "vulnerability_type": f.vuln_type,
            "detector": f.detector,
            "file": f.file_path,
            "line": f.line_start,
            "end_line": f.line_end,
            "description": f.description,
            "code_context": f.code_snippet,
        });

        // 文件角色标签
        if let Some(ref role) = f.file_role {
            obj.as_object_mut().unwrap().insert(
                "file_role".to_string(),
                json!(role),
            );
        }

        // 安全屏障
        if let Some(ref barriers) = f.barriers {
            if !barriers.is_empty() {
                obj.as_object_mut().unwrap().insert(
                    "barriers".to_string(),
                    json!(barriers),
                );
            }
        }

        // 标记原因
        if let Some(ref hint) = f.reasoning_hint {
            obj.as_object_mut().unwrap().insert(
                "reasoning_hint".to_string(),
                json!(hint),
            );
        }

        if let Some(ref trail) = f.analysis_trail {
            if !trail.is_empty() {
                obj.as_object_mut().unwrap().insert(
                    "taint_chain".to_string(),
                    json!(trail),
                );
            }
        }

        if let Some(ref source) = f.source_snippet {
            obj.as_object_mut().unwrap().insert(
                "source_snippet".to_string(),
                json!(source),
            );
        }

        if let Some(ref sink) = f.sink_snippet {
            obj.as_object_mut().unwrap().insert(
                "sink_snippet".to_string(),
                json!(sink),
            );
        }

        if let Some(conf) = f.confidence {
            obj.as_object_mut().unwrap().insert(
                "confidence".to_string(),
                json!(format!("{:.2}", conf)),
            );
        }

        if let Some(count) = f.corroboration_count {
            obj.as_object_mut().unwrap().insert(
                "corroboration_count".to_string(),
                json!(count),
            );
        }

        if let Some(ref llm_out) = f.llm_output {
            if !llm_out.is_empty() {
                obj.as_object_mut().unwrap().insert(
                    "llm_analysis".to_string(),
                    json!(llm_out),
                );
            }
        }

        obj
    }).collect();

    let result = json!({
        "scan_summary": {
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "total_findings": findings.len(),
            "by_severity": by_severity,
            "by_detector": by_detector,
            "by_file_role": by_file_role,
        },
        "findings": findings_json,
    });

    serde_json::to_string_pretty(&result).unwrap_or_default()
}

/// 通过守护进程执行扫描（带优雅降级）
async fn scan_via_daemon(
    path: String,
    severity: Option<String>,
    min_severity: String,
    pattern: Option<String>,
    output_path: Option<String>,
    output_format: &str,
    enable_taint: bool,
    enable_cross_file: bool,
    renderer: &mut TerminalRenderer,
) -> Result<()> {
    let mut client = match DaemonClient::connect_with_retry().await {
        Ok(c) => c,
        Err(e) => {
            renderer.warning(&format!("连接守护进程失败: {}", e));
            renderer.info("降级为本地扫描模式...");
            return scan_local(path, None, severity, min_severity, pattern, output_path, output_format, enable_taint, enable_cross_file, vec![], renderer, ScaScanOptions::default(), None, false).await;
        }
    };

    renderer.info(&format!("通过守护进程扫描: {}", path));
    let pb = renderer.progress_bar(100);
    pb.set_message("扫描中...");

    let deep = enable_taint && enable_cross_file;
    let response = match client.scan(path.clone(), deep, enable_taint, enable_cross_file, severity.clone(), pattern.clone()).await {
        Ok(r) => r,
        Err(e) => {
            pb.finish_with_message("守护进程扫描失败");
            renderer.warning(&format!("守护进程扫描失败: {}", e));
            renderer.info("降级为本地扫描模式...");
            return scan_local(path, None, severity, min_severity, pattern, output_path, output_format, enable_taint, enable_cross_file, vec![], renderer, ScaScanOptions::default(), None, false).await;
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
