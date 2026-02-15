// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 报告导出模块
//!
//! 支持多种格式的审计报告导出: JSON, Markdown, HTML, SARIF

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// 审计报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// 报告元数据
    pub metadata: ReportMetadata,

    /// 漏洞发现列表
    pub findings: Vec<FindingEntry>,

    /// 统计信息
    pub statistics: ReportStatistics,

    /// 修复建议
    pub repairs: Vec<RepairEntry>,

    /// PoC 列表
    pub pocs: Vec<PoCEntry>,
}

impl AuditReport {
    /// 创建新的审计报告
    pub fn new(project_name: &str) -> Self {
        Self {
            metadata: ReportMetadata {
                project_name: project_name.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                auditor: "CTX-Audit".to_string(),
                tool_info: ToolInfo {
                    name: "CTX-Audit".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
            },
            findings: Vec::new(),
            statistics: ReportStatistics::default(),
            repairs: Vec::new(),
            pocs: Vec::new(),
        }
    }

    /// 添加漏洞发现
    pub fn add_finding(&mut self, finding: FindingEntry) {
        // 更新统计
        match finding.severity {
            Severity::Critical => self.statistics.critical_count += 1,
            Severity::High => self.statistics.high_count += 1,
            Severity::Medium => self.statistics.medium_count += 1,
            Severity::Low => self.statistics.low_count += 1,
            Severity::Info => self.statistics.info_count += 1,
        }
        self.statistics.total_count += 1;
        self.findings.push(finding);
    }

    /// 添加修复建议
    pub fn add_repair(&mut self, repair: RepairEntry) {
        self.repairs.push(repair);
    }

    /// 添加 PoC
    pub fn add_poc(&mut self, poc: PoCEntry) {
        self.pocs.push(poc);
    }

    /// 按严重程度排序漏洞
    pub fn sort_by_severity(&mut self) {
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    }
}

/// 报告元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// 项目名称
    pub project_name: String,

    /// 工具版本
    pub version: String,

    /// 生成时间
    pub generated_at: String,

    /// 审计者
    pub auditor: String,

    /// 工具信息
    pub tool_info: ToolInfo,
}

/// 工具信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// 工具名称
    pub name: String,

    /// 工具版本
    pub version: String,
}

/// 漏洞严重程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// 严重
    Critical,
    /// 高危
    High,
    /// 中危
    Medium,
    /// 低危
    Low,
    /// 信息
    Info,
}

impl Severity {
    /// 获取显示名称
    pub fn display_name(&self) -> &str {
        match self {
            Severity::Critical => "严重",
            Severity::High => "高危",
            Severity::Medium => "中危",
            Severity::Low => "低危",
            Severity::Info => "信息",
        }
    }

    /// 获取颜色 (用于 HTML/Markdown)
    pub fn color(&self) -> &str {
        match self {
            Severity::Critical => "#dc3545",
            Severity::High => "#fd7e14",
            Severity::Medium => "#ffc107",
            Severity::Low => "#0d6efd",
            Severity::Info => "#6c757d",
        }
    }

    /// 获取 SARIF 级别
    pub fn sarif_level(&self) -> &str {
        match self {
            Severity::Critical => "error",
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low => "note",
            Severity::Info => "none",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// 漏洞发现条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEntry {
    /// 唯一标识
    pub id: String,

    /// 漏洞类型
    pub vuln_type: String,

    /// 严重程度
    pub severity: Severity,

    /// 标题
    pub title: String,

    /// 描述
    pub description: String,

    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 列号
    pub column: usize,

    /// 代码片段
    pub code_snippet: Option<String>,

    /// CWE
    pub cwe: Option<String>,

    /// OWASP Top 10
    pub owasp: Option<String>,

    /// 参考链接
    pub references: Vec<String>,

    /// 置信度
    pub confidence: f32,
}

impl FindingEntry {
    /// 创建新的漏洞条目
    pub fn new(id: &str, vuln_type: &str, severity: Severity, title: &str) -> Self {
        Self {
            id: id.to_string(),
            vuln_type: vuln_type.to_string(),
            severity,
            title: title.to_string(),
            description: String::new(),
            file_path: String::new(),
            line: 0,
            column: 0,
            code_snippet: None,
            cwe: None,
            owasp: None,
            references: Vec::new(),
            confidence: 0.5,
        }
    }

    /// 设置位置
    pub fn with_location(mut self, file: &str, line: usize, column: usize) -> Self {
        self.file_path = file.to_string();
        self.line = line;
        self.column = column;
        self
    }

    /// 设置描述
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    /// 设置代码片段
    pub fn with_snippet(mut self, snippet: &str) -> Self {
        self.code_snippet = Some(snippet.to_string());
        self
    }

    /// 设置 CWE
    pub fn with_cwe(mut self, cwe: &str) -> Self {
        self.cwe = Some(cwe.to_string());
        self
    }
}

/// 修复条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairEntry {
    /// 关联的漏洞 ID
    pub finding_id: String,

    /// 原始代码
    pub original_code: String,

    /// 修复代码
    pub fixed_code: String,

    /// 修复说明
    pub explanation: String,

    /// 置信度
    pub confidence: f32,
}

/// PoC 条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCEntry {
    /// 关联的漏洞 ID
    pub finding_id: String,

    /// PoC 代码
    pub code: String,

    /// 语言
    pub language: String,

    /// 使用说明
    pub usage: String,
}

/// 报告统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportStatistics {
    /// 总数
    pub total_count: usize,

    /// 严重数量
    pub critical_count: usize,

    /// 高危数量
    pub high_count: usize,

    /// 中危数量
    pub medium_count: usize,

    /// 低危数量
    pub low_count: usize,

    /// 信息数量
    pub info_count: usize,
}

/// 报告导出器
pub struct ReportExporter {
    /// 格式
    format: ExportFormat,
}

/// 导出格式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// JSON 格式
    Json,
    /// Markdown 格式
    Markdown,
    /// HTML 格式
    Html,
    /// SARIF 格式 (用于 CI/CD)
    Sarif,
}

impl ExportFormat {
    /// 从文件扩展名解析
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext.to_lowercase().as_str() {
            "json" => Some(ExportFormat::Json),
            "md" | "markdown" => Some(ExportFormat::Markdown),
            "html" | "htm" => Some(ExportFormat::Html),
            "sarif" => Some(ExportFormat::Sarif),
            _ => None,
        }
    }

    /// 获取文件扩展名
    pub fn extension(&self) -> &str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Markdown => "md",
            ExportFormat::Html => "html",
            ExportFormat::Sarif => "sarif.json",
        }
    }

    /// 获取 MIME 类型
    pub fn mime_type(&self) -> &str {
        match self {
            ExportFormat::Json => "application/json",
            ExportFormat::Markdown => "text/markdown",
            ExportFormat::Html => "text/html",
            ExportFormat::Sarif => "application/json",
        }
    }
}

impl ReportExporter {
    /// 创建新的导出器
    pub fn new(format: ExportFormat) -> Self {
        Self { format }
    }

    /// 导出报告
    pub fn export(&self, report: &AuditReport) -> Result<String, String> {
        match self.format {
            ExportFormat::Json => self.export_json(report),
            ExportFormat::Markdown => self.export_markdown(report),
            ExportFormat::Html => self.export_html(report),
            ExportFormat::Sarif => self.export_sarif(report),
        }
    }

    /// 导出到文件
    pub fn export_to_file(&self, report: &AuditReport, path: &Path) -> Result<(), String> {
        let content = self.export(report)?;
        std::fs::write(path, content)
            .map_err(|e| format!("写入文件失败: {}", e))?;
        Ok(())
    }

    /// 导出为 JSON
    fn export_json(&self, report: &AuditReport) -> Result<String, String> {
        serde_json::to_string_pretty(report)
            .map_err(|e| format!("JSON 序列化失败: {}", e))
    }

    /// 导出为 Markdown
    fn export_markdown(&self, report: &AuditReport) -> Result<String, String> {
        let mut md = String::new();

        // 标题
        md.push_str(&format!("# {} - 安全审计报告\n\n", report.metadata.project_name));

        // 元数据
        md.push_str("## 报告信息\n\n");
        md.push_str(&format!("- **生成时间**: {}\n", report.metadata.generated_at));
        md.push_str(&format!("- **审计工具**: {} v{}\n", report.metadata.tool_info.name, report.metadata.tool_info.version));
        md.push_str("\n");

        // 统计摘要
        md.push_str("## 漏洞统计\n\n");
        md.push_str("| 严重程度 | 数量 |\n");
        md.push_str("|----------|------|\n");
        md.push_str(&format!("| 🔴 严重 | {} |\n", report.statistics.critical_count));
        md.push_str(&format!("| 🟠 高危 | {} |\n", report.statistics.high_count));
        md.push_str(&format!("| 🟡 中危 | {} |\n", report.statistics.medium_count));
        md.push_str(&format!("| 🔵 低危 | {} |\n", report.statistics.low_count));
        md.push_str(&format!("| ⚪ 信息 | {} |\n", report.statistics.info_count));
        md.push_str(&format!("| **总计** | **{}** |\n", report.statistics.total_count));
        md.push_str("\n");

        // 漏洞详情
        md.push_str("## 漏洞详情\n\n");
        for finding in &report.findings {
            md.push_str(&format!("### {} - {}\n\n", finding.severity.display_name(), finding.title));
            md.push_str(&format!("- **ID**: {}\n", finding.id));
            md.push_str(&format!("- **类型**: {}\n", finding.vuln_type));
            md.push_str(&format!("- **严重程度**: {}\n", finding.severity));
            md.push_str(&format!("- **置信度**: {:.0}%\n", finding.confidence * 100.0));

            if !finding.file_path.is_empty() {
                md.push_str(&format!("- **位置**: `{}:{}:{}`\n", finding.file_path, finding.line, finding.column));
            }

            if let Some(ref cwe) = finding.cwe {
                md.push_str(&format!("- **CWE**: [{}]({}{})\n", cwe, "https://cwe.mitre.org/data/definitions/", cwe.replace("CWE-", "")));
            }

            md.push_str("\n");
            md.push_str(&format!("{}\n\n", finding.description));

            if let Some(ref snippet) = finding.code_snippet {
                md.push_str("```\n");
                md.push_str(snippet);
                md.push_str("\n```\n\n");
            }

            md.push_str("---\n\n");
        }

        // 修复建议
        if !report.repairs.is_empty() {
            md.push_str("## 修复建议\n\n");
            for repair in &report.repairs {
                md.push_str(&format!("### 漏洞 {} 的修复\n\n", repair.finding_id));
                md.push_str(&format!("{}\n\n", repair.explanation));
                md.push_str(&format!("**原代码:**\n```\n{}\n```\n\n", repair.original_code));
                md.push_str(&format!("**修复后:**\n```\n{}\n```\n\n", repair.fixed_code));
            }
        }

        Ok(md)
    }

    /// 导出为 HTML
    fn export_html(&self, report: &AuditReport) -> Result<String, String> {
        let mut html = String::new();

        html.push_str(r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全审计报告</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        h3 { margin-top: 20px; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
        .stat-card { padding: 15px 25px; border-radius: 8px; color: white; text-align: center; }
        .stat-card .count { font-size: 2em; font-weight: bold; }
        .stat-card .label { font-size: 0.9em; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #333; }
        .low { background: #0d6efd; }
        .info { background: #6c757d; }
        .finding { border-left: 4px solid #007bff; padding: 15px; margin: 15px 0; background: #f8f9fa; }
        .finding.critical { border-color: #dc3545; }
        .finding.high { border-color: #fd7e14; }
        .finding.medium { border-color: #ffc107; }
        .finding.low { border-color: #0d6efd; }
        .finding.info { border-color: #6c757d; }
        .meta { color: #666; font-size: 0.9em; }
        .code { background: #282c34; color: #abb2bf; padding: 15px; border-radius: 4px; overflow-x: auto; }
        .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.8em; margin-right: 10px; }
    </style>
</head>
<body>
"#);

        // 标题
        html.push_str(&format!("<h1>{} - 安全审计报告</h1>\n", report.metadata.project_name));

        // 元数据
        html.push_str("<div class=\"meta\">\n");
        html.push_str(&format!("<p>生成时间: {} | 工具: {} v{}</p>\n",
            report.metadata.generated_at,
            report.metadata.tool_info.name,
            report.metadata.tool_info.version));
        html.push_str("</div>\n");

        // 统计卡片
        html.push_str("<h2>漏洞统计</h2>\n");
        html.push_str("<div class=\"stats\">\n");

        html.push_str(&format!(
            "<div class=\"stat-card critical\"><div class=\"count\">{}</div><div class=\"label\">严重</div></div>\n",
            report.statistics.critical_count
        ));
        html.push_str(&format!(
            "<div class=\"stat-card high\"><div class=\"count\">{}</div><div class=\"label\">高危</div></div>\n",
            report.statistics.high_count
        ));
        html.push_str(&format!(
            "<div class=\"stat-card medium\"><div class=\"count\">{}</div><div class=\"label\">中危</div></div>\n",
            report.statistics.medium_count
        ));
        html.push_str(&format!(
            "<div class=\"stat-card low\"><div class=\"count\">{}</div><div class=\"label\">低危</div></div>\n",
            report.statistics.low_count
        ));
        html.push_str(&format!(
            "<div class=\"stat-card info\"><div class=\"count\">{}</div><div class=\"label\">信息</div></div>\n",
            report.statistics.info_count
        ));

        html.push_str("</div>\n");

        // 漏洞列表
        html.push_str("<h2>漏洞详情</h2>\n");

        for finding in &report.findings {
            let severity_class = format!("{:?}", finding.severity).to_lowercase();
            html.push_str(&format!(
                "<div class=\"finding {}\">\n",
                severity_class
            ));

            html.push_str(&format!(
                "<h3><span class=\"severity-badge {}\">{}</span>{} - {}</h3>\n",
                severity_class,
                finding.severity.display_name(),
                finding.id,
                finding.title
            ));

            html.push_str("<div class=\"meta\">\n");
            html.push_str(&format!("<strong>类型:</strong> {} | ", finding.vuln_type));
            if !finding.file_path.is_empty() {
                html.push_str(&format!("<strong>位置:</strong> <code>{}:{}:{}</code> | ", finding.file_path, finding.line, finding.column));
            }
            html.push_str(&format!("<strong>置信度:</strong> {:.0}%", finding.confidence * 100.0));
            html.push_str("</div>\n");

            html.push_str(&format!("<p>{}</p>\n", finding.description));

            if let Some(ref snippet) = finding.code_snippet {
                html.push_str("<pre class=\"code\">\n");
                html.push_str(&html_escape(snippet));
                html.push_str("\n</pre>\n");
            }

            html.push_str("</div>\n");
        }

        html.push_str("</body>\n</html>");

        Ok(html)
    }

    /// 导出为 SARIF (Static Analysis Results Interchange Format)
    fn export_sarif(&self, report: &AuditReport) -> Result<String, String> {
        let mut sarif = serde_json::Map::new();

        // 版本
        sarif.insert("$schema".to_string(), serde_json::json!("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"));
        sarif.insert("version".to_string(), serde_json::json!("2.1.0"));

        // Runs
        let mut run = serde_json::Map::new();

        // Tool info
        let mut tool = serde_json::Map::new();
        let mut driver = serde_json::Map::new();
        driver.insert("name".to_string(), serde_json::json!(report.metadata.tool_info.name));
        driver.insert("version".to_string(), serde_json::json!(report.metadata.tool_info.version));
        driver.insert("informationUri".to_string(), serde_json::json!("https://github.com/ctx-audit"));
        tool.insert("driver".to_string(), serde_json::Value::Object(driver));
        run.insert("tool".to_string(), serde_json::Value::Object(tool));

        // Results
        let mut results = Vec::new();
        for finding in &report.findings {
            let mut result = serde_json::Map::new();

            result.insert("ruleId".to_string(), serde_json::json!(finding.vuln_type));
            result.insert("level".to_string(), serde_json::json!(finding.severity.sarif_level()));

            // Message
            let mut message = serde_json::Map::new();
            message.insert("text".to_string(), serde_json::json!(finding.description));
            result.insert("message".to_string(), serde_json::Value::Object(message));

            // Locations
            if !finding.file_path.is_empty() {
                let mut location = serde_json::Map::new();
                let mut physical_location = serde_json::Map::new();
                let mut artifact_location = serde_json::Map::new();
                artifact_location.insert("uri".to_string(), serde_json::json!(finding.file_path));
                physical_location.insert("artifactLocation".to_string(), serde_json::Value::Object(artifact_location));

                if finding.line > 0 {
                    let mut region = serde_json::Map::new();
                    region.insert("startLine".to_string(), serde_json::json!(finding.line));
                    if finding.column > 0 {
                        region.insert("startColumn".to_string(), serde_json::json!(finding.column));
                    }
                    physical_location.insert("region".to_string(), serde_json::Value::Object(region));
                }

                location.insert("physicalLocation".to_string(), serde_json::Value::Object(physical_location));
                result.insert("locations".to_string(), serde_json::json!([location]));
            }

            results.push(serde_json::Value::Object(result));
        }

        run.insert("results".to_string(), serde_json::Value::Array(results));
        sarif.insert("runs".to_string(), serde_json::json!([run]));

        serde_json::to_string_pretty(&sarif)
            .map_err(|e| format!("SARIF 序列化失败: {}", e))
    }
}

/// HTML 转义
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_report_creation() {
        let report = AuditReport::new("test-project");
        assert_eq!(report.metadata.project_name, "test-project");
        assert_eq!(report.statistics.total_count, 0);
    }

    #[test]
    fn test_add_finding() {
        let mut report = AuditReport::new("test");
        let finding = FindingEntry::new("vuln-1", "SQL_INJECTION", Severity::High, "SQL Injection");
        report.add_finding(finding);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.statistics.high_count, 1);
        assert_eq!(report.statistics.total_count, 1);
    }

    #[test]
    fn test_severity_order() {
        // 枚举顺序: Critical < High < Medium < Low < Info
        // Critical 是最严重的，但在枚举中值最小
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn test_export_format_from_extension() {
        assert_eq!(ExportFormat::from_extension("json"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::from_extension("md"), Some(ExportFormat::Markdown));
        assert_eq!(ExportFormat::from_extension("html"), Some(ExportFormat::Html));
        assert_eq!(ExportFormat::from_extension("sarif"), Some(ExportFormat::Sarif));
    }

    #[test]
    fn test_export_json() {
        let mut report = AuditReport::new("test-project");
        report.add_finding(FindingEntry::new("v1", "XSS", Severity::Medium, "XSS Vulnerability"));

        let exporter = ReportExporter::new(ExportFormat::Json);
        let result = exporter.export(&report);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("test-project"));
        assert!(json.contains("XSS"));
    }

    #[test]
    fn test_export_markdown() {
        let mut report = AuditReport::new("test-project");
        report.add_finding(FindingEntry::new("v1", "SQL_INJECTION", Severity::Critical, "SQL Injection"));

        let exporter = ReportExporter::new(ExportFormat::Markdown);
        let result = exporter.export(&report);

        assert!(result.is_ok());
        let md = result.unwrap();
        assert!(md.contains("# test-project"));
        assert!(md.contains("SQL_INJECTION"));
        assert!(md.contains("严重"));
    }

    #[test]
    fn test_export_html() {
        let mut report = AuditReport::new("test-project");
        report.add_finding(FindingEntry::new("v1", "XSS", Severity::High, "XSS Bug"));

        let exporter = ReportExporter::new(ExportFormat::Html);
        let result = exporter.export(&report);

        assert!(result.is_ok());
        let html = result.unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("test-project"));
        assert!(html.contains("XSS Bug"));
    }

    #[test]
    fn test_export_sarif() {
        let mut report = AuditReport::new("test-project");
        report.add_finding(
            FindingEntry::new("v1", "SQL_INJECTION", Severity::High, "SQL Injection")
                .with_location("src/db.rs", 42, 10)
        );

        let exporter = ReportExporter::new(ExportFormat::Sarif);
        let result = exporter.export(&report);

        assert!(result.is_ok());
        let sarif = result.unwrap();
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("SQL_INJECTION"));
        assert!(sarif.contains("src/db.rs"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }
}
