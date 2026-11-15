// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 规则扫描工具面：把 `ctx-audit scan` 的规则引擎暴露给 Agent。
//!
//! 与高阶工具面的区别：这里跑的是**规则/污点/跨文件**三档扫描，产出的是
//! 传统 SAST 风格的 finding（文件/行/规则/严重度/置信度），用于快速建立
//! "哪里可能有洞"的候选集；后续仍应交给链档与载荷判定做证据化收敛。
//!
//! 输出有界：默认只返回前 N 条，并显式标注总数与截断。

use deepaudit_core::scanning::{scan_directory_with_opts, Finding, ScanOptions};
use serde_json::{json, Value};
use std::path::Path;

/// 扫描档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    /// 仅规则（最快）
    Rules,
    /// 规则 + 单文件 AST 污点
    Taint,
    /// 规则 + 污点 + 跨文件
    Deep,
}

impl ScanMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "rules" | "fast" => Some(ScanMode::Rules),
            "taint" => Some(ScanMode::Taint),
            "deep" | "cross-file" | "crossfile" => Some(ScanMode::Deep),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            ScanMode::Rules => "rules",
            ScanMode::Taint => "taint",
            ScanMode::Deep => "deep",
        }
    }
}

/// 规则扫描报告。
pub fn scan_report(
    project: &Path,
    mode: ScanMode,
    min_severity: &str,
    limit: usize,
) -> Result<Value, String> {
    let root = project
        .canonicalize()
        .map_err(|e| format!("项目路径无效: {e}"))?;
    let root_str = root.to_string_lossy().to_string();

    let mut opts = ScanOptions::default();
    opts.enable_taint = matches!(mode, ScanMode::Taint | ScanMode::Deep);
    opts.enable_cross_file = matches!(mode, ScanMode::Deep);
    // 扫描侧不把测试文件当噪声排除（用户可能就想扫测试），但会在输出里标注角色。
    opts.include_tests = true;

    let started = std::time::Instant::now();
    let findings = futures_lite_block_on(scan_directory_with_opts(
        &root_str,
        None,
        None,
        None,
        opts,
        None,
    ))?;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let min_rank = severity_rank(min_severity);
    let total_before = findings.len();
    let mut kept: Vec<&Finding> = findings
        .iter()
        .filter(|f| severity_rank(&f.severity) >= min_rank)
        .collect();
    // 稳定排序：严重度降序 → 文件 → 行
    kept.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line_start.cmp(&b.line_start))
    });

    let cap = if limit == 0 { 200 } else { limit.min(500) };
    let truncated = kept.len() > cap;
    let items: Vec<Value> = kept
        .iter()
        .take(cap)
        .map(|f| {
            json!({
                "file": f.file_path,
                "line": f.line_start,
                "line_end": f.line_end,
                "rule": f.detector,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "corroboration": f.corroboration_count,
                "description": f.description.chars().take(300).collect::<String>(),
            })
        })
        .collect();

    let mut by_severity: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut by_type: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in kept.iter() {
        *by_severity.entry(f.severity.clone()).or_insert(0) += 1;
        *by_type.entry(f.vuln_type.clone()).or_insert(0) += 1;
    }

    Ok(json!({
        "schema": "scan-report/v1",
        "project": root_str,
        "mode": mode.label(),
        "min_severity": min_severity,
        "elapsed_ms": elapsed_ms,
        "total": total_before,
        "after_severity_filter": kept.len(),
        "returned": items.len(),
        "truncated": truncated,
        "by_severity": by_severity,
        "by_type": by_type,
        "findings": items,
        "limits": [
            "规则扫描是候选集，不是判定结论",
            "无数据流证据的结构链默认降级为 info",
            format!("单次最多返回 {cap} 条"),
        ],
        "uncertainty": {
            "level": "medium",
            "reasons": ["pattern_rules", "heuristic_confidence"],
        },
    }))
}

fn severity_rank(s: &str) -> u8 {
    match s.to_ascii_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// 在同步上下文里跑 async 扫描（工具执行本身是 async，但扫描 API 是 async fn）。
fn futures_lite_block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(fut)
    })
}
