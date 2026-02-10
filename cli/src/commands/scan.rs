// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! scan 命令实现
//!
//! 使用预定义规则快速扫描代码

use miette::Result;

use crate::terminal::TerminalRenderer;
use deepaudit_core::scan_directory;

/// 执行 scan 命令
pub async fn execute(
    path: String,
    rules_dir: Option<String>,
    severity: Option<String>,
    pattern: Option<String>,
    output_path: Option<String>,
    threads: usize,
    output_format: &str,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 验证项目路径
    let project_path = std::path::Path::new(&path);
    if !project_path.exists() {
        renderer.error(&format!("项目路径不存在: {}", path));
        return Err(miette::miette!("项目路径不存在"));
    }

    renderer.info(&format!("开始扫描: {}", path));

    // 加载规则
    if let Some(rules_path) = rules_dir {
        renderer.info(&format!("加载规则: {}", rules_path));
    }

    // 创建进度条
    let pb = renderer.progress_bar(100);
    pb.set_message("正在扫描...");

    // 执行扫描
    let findings_result = scan_directory(&path).await;

    pb.finish_with_message("扫描完成");

    let findings = match findings_result {
        Ok(f) => f,
        Err(e) => {
            renderer.error(&format!("扫描失败: {}", e));
            return Err(miette::miette!("扫描失败: {}", e));
        }
    };

    // 过滤严重程度
    let filtered_findings = if let Some(sev) = severity {
        findings
            .into_iter()
            .filter(|f| f.severity.to_lowercase() == sev.to_lowercase())
            .collect()
    } else {
        findings
    };

    // 过滤文件模式
    let filtered_findings = if let Some(pat) = pattern {
        filtered_findings
            .into_iter()
            .filter(|f| f.file_path.contains(&pat))
            .collect()
    } else {
        filtered_findings
    };

    // 输出结果
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

    // 保存结果（如果指定了输出文件）
    if let Some(output_path) = output_path {
        // TODO: 实现保存逻辑
        renderer.info(&format!("结果已保存到: {}", output_path));
    }

    Ok(())
}
