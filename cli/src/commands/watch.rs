// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! watch 命令实现
//!
//! 守护模式：监听文件变更并增量扫描，持续更新 SARIF 文件

use miette::Result;
use std::time::Duration;

use crate::terminal::TerminalRenderer;
use deepaudit_core::watcher::{FileWatcher, WatcherConfig, WatchEvent, is_source_file};
use deepaudit_core::scan_directory;
use deepaudit_core::sarif::{SarifConverter, FindingInput};
use deepaudit_core::analysis::TaintAnalyzer;

/// 执行 watch 命令
pub async fn execute(
    path: String,
    severity: Option<String>,
    output_format: &str,
    output_path: String,
    ignore: String,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 验证项目路径
    let project_path = std::path::Path::new(&path);
    if !project_path.exists() {
        renderer.error(&format!("项目路径不存在: {}", path));
        return Err(miette::miette!("项目路径不存在"));
    }

    let ignore_patterns: Vec<String> = ignore.split(',').map(|s| s.trim().to_string()).collect();

    let config = WatcherConfig {
        project_path: path.clone(),
        sarif_output_path: output_path.clone(),
        ignore_patterns,
        debounce_ms: 2000,
        severity_filter: severity.clone(),
    };

    renderer.info(&format!("[Watch] 守护模式启动: {}", path));
    renderer.info(&format!("[Watch] SARIF 输出: {}", config.sarif_output_path));
    renderer.info(&format!("[Watch] 输出格式: {}", output_format));
    renderer.info("[Watch] 按 Ctrl+C 停止");

    let mut watcher = FileWatcher::new(config);

    // ========== 初始全量扫描 ==========
    renderer.info("");
    renderer.info("[Watch] 执行初始全量扫描...");

    let initial_result = watcher.initial_scan()
        .map_err(|e| miette::miette!("初始扫描失败: {}", e))?;

    renderer.success(&format!(
        "[Watch] 初始扫描完成: {} 个文件",
        initial_result.total_files
    ));

    // 执行初始安全扫描
    let findings = run_scan(&path, &severity).await;
    let finding_count = findings.len();

    // 生成 SARIF
    generate_and_save_sarif(&findings, watcher.sarif_output_path())
        .await
        .map_err(|e| miette::miette!("SARIF 生成失败: {}", e))?;

    renderer.success(&format!(
        "[Watch] 初始扫描发现 {} 个漏洞，SARIF 已保存",
        finding_count
    ));

    // ========== 进入监听循环 ==========
    renderer.info("");
    renderer.info("[Watch] 开始监听文件变更...");

    let check_interval = Duration::from_secs(2);
    loop {
        tokio::time::sleep(check_interval).await;

        // 检测变更
        match watcher.detect_changes() {
            Ok(delta) => {
                if !delta.has_changes() {
                    continue;
                }

                let changed_source_files: Vec<_> = delta.changed_files.iter()
                    .chain(delta.added_files.iter())
                    .filter(|p| is_source_file(p))
                    .collect();

                if changed_source_files.is_empty() {
                    continue;
                }

                let changed_count = changed_source_files.len();

                // 显示变更信息
                for file in &changed_source_files {
                    if let Some(path_str) = file.to_str() {
                        renderer.info(&format!("  [变更] {}", path_str));
                    }
                }

                // 增量扫描（当前简化为全量重扫描）
                // TODO: Phase 2 中实现真正的增量扫描
                renderer.info(&format!(
                    "[Watch] 检测到 {} 个源码文件变更，重新扫描...",
                    changed_count
                ));

                let new_findings = run_scan(&path, &severity).await;
                let new_count = new_findings.len();

                // 更新 SARIF
                generate_and_save_sarif(&new_findings, watcher.sarif_output_path())
                    .await
                    .map_err(|e| miette::miette!("SARIF 更新失败: {}", e))?;

                let diff = new_count as i64 - finding_count as i64;
                let diff_str = if diff > 0 {
                    format!("+{}", diff)
                } else {
                    format!("{}", diff)
                };

                renderer.success(&format!(
                    "[Watch] 扫描完成: {} 个漏洞 ({})",
                    new_count, diff_str
                ));
            }
            Err(e) => {
                renderer.error(&format!("[Watch] 变更检测失败: {}", e));
            }
        }
    }
}

/// 执行安全扫描
async fn run_scan(path: &str, severity: &Option<String>) -> Vec<deepaudit_core::Finding> {
    match scan_directory(path).await {
        Ok(findings) => {
            if let Some(sev) = severity {
                findings
                    .into_iter()
                    .filter(|f| f.severity.to_lowercase() == sev.to_lowercase())
                    .collect()
            } else {
                findings
            }
        }
        Err(_) => vec![],
    }
}

/// 生成并保存 SARIF 文件
async fn generate_and_save_sarif(
    findings: &[deepaudit_core::Finding],
    output_path: &str,
) -> anyhow::Result<()> {
    let converter = SarifConverter::new();
    let inputs: Vec<FindingInput> = findings.iter().map(|f| FindingInput {
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

    let sarif_json = converter.convert_to_json(&inputs)?;
    tokio::fs::write(output_path, sarif_json).await?;
    Ok(())
}
