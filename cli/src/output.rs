// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 输出格式化模块
//!
//! 支持多种输出格式：text, json, markdown, sarif

use anyhow::Result;
use serde_json;
use std::io::Write;

use ctx_audit_tools::FindingData;

/// 输出格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// 纯文本
    Text,

    /// JSON
    Json,

    /// Markdown
    Markdown,

    /// SARIF (Static Analysis Results Interchange Format)
    Sarif,
}

impl OutputFormat {
    /// 从字符串解析
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "text" => Some(OutputFormat::Text),
            "json" => Some(OutputFormat::Json),
            "markdown" | "md" => Some(OutputFormat::Markdown),
            "sarif" => Some(OutputFormat::Sarif),
            _ => None,
        }
    }
}

/// 输出格式化器
pub struct OutputFormatter;

impl OutputFormatter {
    /// 格式化漏洞列表
    pub fn format_findings(
        findings: &[FindingData],
        format: OutputFormat,
    ) -> Result<String> {
        match format {
            OutputFormat::Text => Self::format_findings_text(findings),
            OutputFormat::Json => Self::format_findings_json(findings),
            OutputFormat::Markdown => Self::format_findings_markdown(findings),
            OutputFormat::Sarif => Self::format_findings_sarif(findings),
        }
    }

    /// 文本格式
    fn format_findings_text(findings: &[FindingData]) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("共发现 {} 个漏洞\n\n", findings.len()));

        for (i, finding) in findings.iter().enumerate() {
            output.push_str(&format!("#{} [{}] {}\n", i + 1, finding.severity, finding.title.as_ref().unwrap_or(&"未命名漏洞".to_string())));
            output.push_str(&format!("  位置: {}:{}\n", finding.file_path, finding.start_line));
            output.push_str(&format!("  描述: {}\n", finding.description));

            if let Some(code) = &finding.code_snippet {
                output.push_str(&format!("  代码:\n{}\n", code));
            }

            if let Some(rec) = &finding.recommendation {
                output.push_str(&format!("  建议: {}\n", rec));
            }

            output.push_str("\n");
        }

        Ok(output)
    }

    /// JSON 格式
    fn format_findings_json(findings: &[FindingData]) -> Result<String> {
        serde_json::to_string_pretty(findings).map_err(Into::into)
    }

    /// Markdown 格式
    fn format_findings_markdown(findings: &[FindingData]) -> Result<String> {
        let mut output = String::new();

        output.push_str("# 漏洞报告\n\n");
        output.push_str(&format!("共发现 **{}** 个漏洞\n\n", findings.len()));

        // 按严重程度分组
        let mut by_severity = std::collections::HashMap::new();
        for finding in findings {
            by_severity
                .entry(finding.severity.clone())
                .or_insert_with(Vec::new)
                .push(finding);
        }

        for severity in ["critical", "high", "medium", "low", "info"] {
            if let Some(findings) = by_severity.get(severity) {
                output.push_str(&format!("## {} ({})\n\n", severity.to_uppercase(), findings.len()));

                for finding in findings {
                    let title = finding.title.as_deref().unwrap_or("未命名漏洞");
                    output.push_str(&format!("### {}\n\n", title));
                    output.push_str(&format!("- **位置**: `{}:{}`\n", finding.file_path, finding.start_line));
                    output.push_str(&format!("- **描述**: {}\n", finding.description));

                    if let Some(cwe) = &finding.cwe_id {
                        output.push_str(&format!("- **CWE**: {}\n", cwe));
                    }

                    if let Some(code) = &finding.code_snippet {
                        output.push_str(&format!("\n```javascript\n{}\n```\n\n", code));
                    }

                    if let Some(rec) = &finding.recommendation {
                        output.push_str(&format!("**修复建议**: {}\n\n", rec));
                    }
                }
            }
        }

        Ok(output)
    }

    /// SARIF 格式
    fn format_findings_sarif(findings: &[FindingData]) -> Result<String> {
        use serde_json::json;

        let sarif = json!({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CTX-Audit",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/ctx-audit/ctx-audit",
                        "rules": []
                    }
                },
                "results": findings.iter().map(|f| {
                    json!({
                        "ruleId": f.cwe_id.as_ref().unwrap_or(&"generic".to_string()),
                        "level": severity_to_level(f.severity.as_str()),
                        "message": {
                            "text": f.description
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": f.file_path
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

        serde_json::to_string_pretty(&sarif).map_err(Into::into)
    }
}

/// 将严重程度转换为 SARIF 级别
fn severity_to_level(severity: &str) -> &str {
    match severity.to_lowercase().as_str() {
        "critical" => "error",
        "high" => "error",
        "medium" => "warning",
        "low" => "note",
        "info" => "note",
        _ => "warning",
    }
}

/// 输出管理器
pub struct OutputManager {
    format: OutputFormat,
}

impl OutputManager {
    /// 创建新的输出管理器
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    /// 写入漏洞报告
    pub fn write_findings<W: Write>(
        &self,
        writer: &mut W,
        findings: &[FindingData],
    ) -> Result<()> {
        let output = OutputFormatter::format_findings(findings, self.format)?;
        writeln!(writer, "{}", output)?;
        Ok(())
    }

    /// 保存漏洞报告到文件
    pub async fn save_findings(&self, path: &str, findings: &[FindingData]) -> Result<()> {
        let output = OutputFormatter::format_findings(findings, self.format)?;
        tokio::fs::write(path, output).await?;
        Ok(())
    }
}
