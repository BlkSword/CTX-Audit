// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 输出格式化模块
//!
//! 支持多种输出格式：text, json, markdown, sarif
//! SARIF 输出统一使用 deepaudit_core::sarif::SarifConverter

use anyhow::Result;
use std::io::Write;

use ctx_audit_tools::FindingData;
use deepaudit_core::sarif::{SarifConverter, FindingInput};

/// 输出格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// 纯文本
    Text,

    /// JSON
    Json,

    /// LLM 面向的结构化 JSON（含代码上下文、污点链、置信度）
    Llm,

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
            "llm" => Some(OutputFormat::Llm),
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
            OutputFormat::Llm => Self::format_findings_llm(findings),
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

            // 显示污点路径
            if let Some(flows) = &finding.code_flows {
                for flow in flows {
                    if let Some(source) = flow.get("source") {
                        if let Some(symbol) = source.get("symbol") {
                            output.push_str(&format!("  污点源: {}\n", symbol));
                        }
                    }
                    if let Some(sink) = flow.get("sink") {
                        if let Some(symbol) = sink.get("symbol") {
                            output.push_str(&format!("  污点汇: {}\n", symbol));
                        }
                    }
                }
            }

            output.push_str("\n");
        }

        Ok(output)
    }

    /// JSON 格式
    fn format_findings_json(findings: &[FindingData]) -> Result<String> {
        serde_json::to_string_pretty(findings).map_err(Into::into)
    }

    /// LLM 面向的结构化 JSON 输出（含统计摘要）
    fn format_findings_llm(findings: &[FindingData]) -> Result<String> {
        let mut by_severity = std::collections::HashMap::new();
        for f in findings {
            *by_severity.entry(f.severity.clone()).or_insert(0) += 1;
        }
        let output = serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "total_findings": findings.len(),
            "by_severity": by_severity,
            "findings": findings,
        });
        serde_json::to_string_pretty(&output).map_err(Into::into)
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

                    if let Some(conf) = finding.confidence {
                        output.push_str(&format!("- **置信度**: {:.0}%\n", conf * 100.0));
                    }

                    if let Some(code) = &finding.code_snippet {
                        output.push_str(&format!("\n```\n{}\n```\n\n", code));
                    }

                    if let Some(rec) = &finding.recommendation {
                        output.push_str(&format!("**修复建议**: {}\n\n", rec));
                    }
                }
            }
        }

        Ok(output)
    }

    /// SARIF 格式 — 使用统一的 SarifConverter
    fn format_findings_sarif(findings: &[FindingData]) -> Result<String> {
        let converter = SarifConverter::new();
        let inputs: Vec<FindingInput> = findings.iter().map(finding_to_input).collect();
        converter.convert_to_json(&inputs).map_err(Into::into)
    }
}

/// FindingData → FindingInput 转换
pub fn finding_to_input(f: &FindingData) -> FindingInput {
    FindingInput {
        id: f.id.clone(),
        title: f.title.clone(),
        description: f.description.clone(),
        severity: f.severity.clone(),
        category: f.category.clone(),
        cwe_id: f.cwe_id.clone(),
        file_path: f.file_path.clone(),
        start_line: f.start_line,
        end_line: f.end_line,
        start_column: f.start_column,
        end_column: f.end_column,
        code_snippet: f.code_snippet.clone(),
        recommendation: f.recommendation.clone(),
        status: f.status.clone(),
        verification_status: f.verification_status.clone(),
        discovered_by: f.discovered_by.clone(),
        code_flows: None, // 将在 Phase 2 中通过 taint_flow_to_summary 填充
        fix_suggestions: None,
        confidence: f.confidence,
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
