// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit autopilot` —— 带预算上限的确定性审计循环。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    path: String,
    budget: usize,
    verify: bool,
    poc: bool,
    triage_limit: usize,
    chain_limit: usize,
    output: String,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    let opts = ctx_audit_tools::AutopilotOptions {
        budget,
        verify,
        poc,
        triage_limit,
        chain_limit,
    };
    let data = ctx_audit_tools::autopilot_report(&root, &opts).map_err(|e| miette!("{}", e))?;

    if output.eq_ignore_ascii_case("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).into_diagnostic()?
        );
        return Ok(());
    }

    println!("自动驾驶 — {}", data["project"].as_str().unwrap_or(""));
    println!(
        "  结论 {} · 预算 {} 条链 · 总耗时 {}ms",
        data["verdict"].as_str().unwrap_or(""),
        data["budget"].as_u64().unwrap_or(0),
        data["total_ms"].as_u64().unwrap_or(0)
    );
    let c = &data["counts"];
    println!(
        "  候选 {} / 尝试 {} / 已确认 {} / 已击杀 {} / 未决 {} / 工件 {}",
        c["candidates"].as_u64().unwrap_or(0),
        c["attempted"].as_u64().unwrap_or(0),
        c["verified"].as_u64().unwrap_or(0),
        c["killed"].as_u64().unwrap_or(0),
        c["undecided"].as_u64().unwrap_or(0),
        c["packaged"].as_u64().unwrap_or(0),
    );
    for f in data["findings"].as_array().cloned().unwrap_or_default() {
        println!(
            "  ✔ {} · {} · {}",
            f["chain_id"].as_str().unwrap_or(""),
            f["archetype"].as_str().unwrap_or(""),
            f["verify_tier"].as_str().unwrap_or("")
        );
    }
    for p in data["packages"].as_array().cloned().unwrap_or_default() {
        println!(
            "  ▸ 工件 {} · {} · {}",
            p["chain_id"].as_str().unwrap_or(""),
            p["payload_tier"].as_str().unwrap_or(""),
            p["guard_gap"].as_str().unwrap_or("")
        );
    }
    println!("\n## 决策轨迹");
    for t in data["trace"].as_array().cloned().unwrap_or_default() {
        println!(
            "  {}. {} — {}",
            t["step"].as_u64().unwrap_or(0),
            t["action"].as_str().unwrap_or(""),
            t.get("status")
                .and_then(|v| v.as_str())
                .or_else(|| t.get("verdict").and_then(|v| v.as_str()))
                .unwrap_or("ok")
        );
    }
    Ok(())
}
