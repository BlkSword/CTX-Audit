// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! findings 命令实现
//!
//! 管理漏洞发现

use miette::Result;
use crate::database::{Database, FindingQueries, FindingStatus};
use crate::output::OutputFormat;
use crate::terminal::TerminalRenderer;

/// 列出漏洞
pub async fn list(
    severity: Option<String>,
    status: Option<String>,
    file: Option<String>,
    json: bool,
    output_format: &str,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let db = Database::with_default_path().await.map_err(|e| miette::miette!("{}", e))?;

    let findings = FindingQueries::list(
        db.pool(),
        None, // project_id
        severity.as_deref(),
        status.as_deref(),
        file.as_deref(),
    ).await.map_err(|e| miette::miette!("{}", e))?;

    if findings.is_empty() {
        renderer.info("暂无漏洞记录");
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&findings).map_err(|e| miette::miette!("{}", e))?);
    } else {
        renderer.info(&format!("共 {} 个漏洞:", findings.len()));
        for finding in findings {
            renderer.print_finding(&finding);
        }
    }

    Ok(())
}

/// 查看漏洞详情
pub async fn view(id: String, output_format: &str) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let db = Database::with_default_path().await.map_err(|e| miette::miette!("{}", e))?;

    // 尝试按 ID 或 finding_id 查找
    let finding = if let Ok(id_num) = id.parse::<i64>() {
        FindingQueries::get_by_id(db.pool(), id_num).await.map_err(|e| miette::miette!("{}", e))?
    } else {
        FindingQueries::get_by_finding_id(db.pool(), &id).await.map_err(|e| miette::miette!("{}", e))?
    };

    match finding {
        Some(f) => {
            renderer.print_finding_detail(&f);
            Ok(())
        }
        None => {
            renderer.error(&format!("未找到漏洞: {}", id));
            Err(miette::miette!("未找到漏洞"))
        }
    }
}

/// 更新漏洞状态
pub async fn update(id: String, status: String, note: Option<String>) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let db = Database::with_default_path().await.map_err(|e| miette::miette!("{}", e))?;

    let finding_id = if let Ok(id_num) = id.parse::<i64>() {
        id_num
    } else {
        // 查找 finding_id 对应的数据库 ID
        let finding = FindingQueries::get_by_finding_id(db.pool(), &id).await.map_err(|e| miette::miette!("{}", e))?
            .ok_or_else(|| miette::miette!("未找到漏洞: {}", id))?;
        finding.id
    };

    // 验证状态值
    let _ = status.parse::<FindingStatus>()
        .map_err(|_| miette::miette!("无效的状态值: {}. 可用值: open, fixed, ignored", status))?;

    let update = crate::database::UpdateFinding {
        status: Some(status.clone()),
        note,
        false_positive: None,
    };

    FindingQueries::update(db.pool(), finding_id, &update).await.map_err(|e| miette::miette!("{}", e))?;
    renderer.info(&format!("漏洞状态已更新为: {}", status));

    Ok(())
}

/// 删除漏洞
pub async fn delete(id: String, confirm: bool) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let db = Database::with_default_path().await.map_err(|e| miette::miette!("{}", e))?;

    if !confirm {
        renderer.warning("请使用 --confirm 确认删除");
        return Ok(());
    }

    let finding_id = if let Ok(id_num) = id.parse::<i64>() {
        id_num
    } else {
        // 查找 finding_id 对应的数据库 ID
        let finding = FindingQueries::get_by_finding_id(db.pool(), &id).await.map_err(|e| miette::miette!("{}", e))?
            .ok_or_else(|| miette::miette!("未找到漏洞: {}", id))?;
        finding.id
    };

    FindingQueries::delete(db.pool(), finding_id).await.map_err(|e| miette::miette!("{}", e))?;
    renderer.info(&format!("漏洞 {} 已删除", id));

    Ok(())
}

/// 导出漏洞报告
pub async fn export(output: String, format: String) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let db = Database::with_default_path().await.map_err(|e| miette::miette!("{}", e))?;

    let findings = FindingQueries::list(
        db.pool(),
        None,
        None,
        None,
        None,
    ).await.map_err(|e| miette::miette!("{}", e))?;

    let content = match format.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(&findings).map_err(|e| miette::miette!("{}", e))?,
        "sarif" => export_sarif(&findings)?,
        "markdown" => export_markdown(&findings)?,
        _ => return Err(miette::miette!("不支持的格式: {}. 可用格式: json, sarif, markdown", format)),
    };

    tokio::fs::write(&output, content).await.map_err(|e| miette::miette!("{}", e))?;
    renderer.info(&format!("漏洞报告已导出到: {}", output));

    Ok(())
}

/// 导出为 SARIF 格式
fn export_sarif(findings: &[crate::database::Finding]) -> miette::Result<String> {
    // 简化的 SARIF 格式
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
                    "ruleId": f.finding_id,
                    "level": severity_to_level(&f.severity),
                    "message": {
                        "text": f.title
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path
                            },
                            "region": {
                                "startLine": f.start_line,
                                "endLine": f.end_line
                            }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });

    Ok(serde_json::to_string_pretty(&sarif).map_err(|e| miette::miette!("{}", e))?)
}

/// 导出为 Markdown 格式
fn export_markdown(findings: &[crate::database::Finding]) -> Result<String> {
    let mut output = String::from("# 安全审计报告\n\n");
    output.push_str(&format!("生成时间: {}\n\n", chrono::Utc::now().to_rfc3339()));
    output.push_str(&format!("漏洞总数: {}\n\n", findings.len()));

    // 按严重程度分组
    let by_severity = |sev: &str| -> Vec<_> {
        findings.iter().filter(|f| f.severity == sev).collect()
    };

    for severity in ["critical", "high", "medium", "low", "info"] {
        let items = by_severity(severity);
        if !items.is_empty() {
            output.push_str(&format!("## {} ({})\n\n", severity.to_uppercase(), items.len()));
            for f in items {
                output.push_str(&format!("### {}\n\n", f.title));
                output.push_str(&format!("- **文件**: {}\n", f.file_path));
                if let Some(line) = f.start_line {
                    output.push_str(&format!("- **行号**: {}\n", line));
                }
                if let Some(desc) = &f.description {
                    output.push_str(&format!("- **描述**: {}\n", desc));
                }
                output.push_str("\n");
            }
        }
    }

    Ok(output)
}

/// 将严重程度转换为 SARIF level
fn severity_to_level(severity: &str) -> &str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}
