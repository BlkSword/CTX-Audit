// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 审计报告输出

use anyhow::{Context, Result};
use serde::Serialize;

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::Verdict;
use crate::output::OutputFormat;

/// 完整审计报告
#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub session_id: String,
    pub project_path: String,
    pub total_findings: usize,
    pub investigated_count: usize,
    pub investigations: Vec<InvestigationResult>,
}

/// 单个调查结果
#[derive(Debug, Clone, Serialize)]
pub struct InvestigationResult {
    pub investigation_id: String,
    pub session_id: String,
    pub finding_id: String,
    pub file_path: String,
    pub line: usize,
    pub vulnerability_type: String,
    pub severity: String,
    pub hypothesis: String,
    pub evidence: Evidence,
    pub verdict: Verdict,
    pub reasoning: String,
    pub audited_at: String,
}

/// 将报告输出到 stdout 或文件
pub fn write_report(
    report: &AuditReport,
    format: OutputFormat,
    output_path: Option<&str>,
) -> Result<()> {
    let text = match format {
        OutputFormat::Json | OutputFormat::Llm => {
            serde_json::to_string_pretty(report).context("序列化报告失败")?
        }
        OutputFormat::Markdown => format_markdown(report),
        _ => format_text(report),
    };

    if let Some(path) = output_path {
        std::fs::write(path, text).with_context(|| format!("写入报告失败: {}", path))?;
        eprintln!("审计报告已保存: {}", path);
    } else {
        println!("{}", text);
    }

    Ok(())
}

fn format_text(report: &AuditReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("CTX-Audit Agent 审计报告\n"));
    s.push_str(&format!("Session: {}\n", report.session_id));
    s.push_str(&format!("Project: {}\n", report.project_path));
    s.push_str(&format!(
        "Findings: {} total, {} investigated\n\n",
        report.total_findings, report.investigated_count
    ));

    let counts = verdict_counts(report);
    s.push_str(&format!(
        "Verdicts: {} true_positive, {} false_positive, {} needs_review\n\n",
        counts.0, counts.1, counts.2
    ));

    for (i, inv) in report.investigations.iter().enumerate() {
        s.push_str(&format!(
            "#{} [{}] {} — {}:{}\n",
            i + 1,
            inv.verdict.as_str(),
            inv.vulnerability_type,
            inv.file_path,
            inv.line
        ));
        s.push_str(&format!("  Reasoning: {}\n", inv.reasoning));
        s.push('\n');
    }

    s
}

fn format_markdown(report: &AuditReport) -> String {
    let mut s = String::new();
    s.push_str("# CTX-Audit Agent 审计报告\n\n");
    s.push_str(&format!("- **Session**: {}\n", report.session_id));
    s.push_str(&format!("- **Project**: {}\n", report.project_path));
    s.push_str(&format!(
        "- **Findings**: {} total, {} investigated\n\n",
        report.total_findings, report.investigated_count
    ));

    let counts = verdict_counts(report);
    s.push_str(&format!(
        "| Verdict | Count |\n|---------|-------|\n| true_positive | {} |\n| false_positive | {} |\n| needs_review | {} |\n\n",
        counts.0, counts.1, counts.2
    ));

    s.push_str("| # | Verdict | Vulnerability | File | Line | Reasoning |\n");
    s.push_str("|---|---------|---------------|------|------|-----------|\n");
    for (i, inv) in report.investigations.iter().enumerate() {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            inv.verdict.as_str(),
            inv.vulnerability_type,
            inv.file_path,
            inv.line,
            inv.reasoning.replace('|', "\\|")
        ));
    }

    s
}

fn verdict_counts(report: &AuditReport) -> (usize, usize, usize) {
    let mut tp = 0;
    let mut fp = 0;
    let mut nr = 0;
    for inv in &report.investigations {
        match inv.verdict {
            Verdict::TruePositive => tp += 1,
            Verdict::FalsePositive => fp += 1,
            Verdict::NeedsReview => nr += 1,
        }
    }
    (tp, fp, nr)
}
