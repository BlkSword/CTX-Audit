// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit workflow` —— 一键审计工作流（覆盖率 → 待审 → 候选链 → 链档 → 载荷）。
//!
//! 输出 `audit-workflow/v1`：每阶段耗时、证据列表（带稳定 id）、下一步动作、边界。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

pub async fn execute(
    path: String,
    triage_limit: usize,
    chain_limit: usize,
    deep_limit: usize,
    stop_after: Option<String>,
    output: String,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    let opts = ctx_audit_tools::code_intel_tools::workflow::WorkflowOptions {
        triage_limit,
        chain_limit,
        deep_limit,
        stop_after,
        verify: false,
    };
    let data = ctx_audit_tools::code_intel_tools::workflow::audit_workflow_report(&root, &opts)
        .map_err(|e| miette!("{}", e))?;

    if output.eq_ignore_ascii_case("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).into_diagnostic()?
        );
        return Ok(());
    }

    println!(
        "一键审计工作流 — {}",
        data["project"].as_str().unwrap_or("")
    );
    println!(
        "  阶段：{}（停在 {}）· 总耗时 {}ms",
        data["stages"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        data["stopped_after"].as_str().unwrap_or(""),
        data["total_ms"].as_u64().unwrap_or(0)
    );
    for stage in data["stages"].as_array().cloned().unwrap_or_default() {
        println!(
            "  - {:<9} {:<8} {:>6}ms  证据 {}",
            stage["stage"].as_str().unwrap_or(""),
            stage["status"].as_str().unwrap_or(""),
            stage["ms"].as_u64().unwrap_or(0),
            stage["evidence_ids"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0)
        );
    }
    let counts = &data["evidence_counts"];
    println!(
        "  证据合计 {}（coverage {} / triage {} / chains {} / dossier {} / payload {}）",
        counts["total"].as_u64().unwrap_or(0),
        counts["coverage"].as_u64().unwrap_or(0),
        counts["triage"].as_u64().unwrap_or(0),
        counts["chains"].as_u64().unwrap_or(0),
        counts["dossier"].as_u64().unwrap_or(0),
        counts["payload"].as_u64().unwrap_or(0),
    );
    for action in data["next_actions"].as_array().cloned().unwrap_or_default() {
        println!(
            "  → {} {}（证据 {}）",
            action["tool"].as_str().unwrap_or(""),
            action["hint"].as_str().unwrap_or(""),
            action["evidence_id"].as_str().unwrap_or("-")
        );
    }
    Ok(())
}
