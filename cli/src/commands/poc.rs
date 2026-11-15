// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit poc` —— PoC 工件打包（Mermaid 拓扑 + 请求骨架 + Guard Gap + 修复建议）。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

pub async fn execute(
    path: String,
    chain_id: Option<String>,
    entry_file: Option<String>,
    entry_line: Option<u32>,
    sink_file: Option<String>,
    sink_line: Option<u32>,
    output: String,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    let data = ctx_audit_tools::poc_package_report(
        &root,
        chain_id.as_deref(),
        entry_file.as_deref(),
        entry_line,
        sink_file.as_deref(),
        sink_line,
    )
    .map_err(|e| miette!("{}", e))?;

    if output.eq_ignore_ascii_case("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).into_diagnostic()?
        );
        return Ok(());
    }

    println!("PoC 工件 — {}", data["project"].as_str().unwrap_or(""));
    println!(
        "  链 {} · 载荷档位 {} · archetype {}",
        data["chain"]["chain_id"].as_str().unwrap_or("-"),
        data["verdict"]["payload_tier"].as_str().unwrap_or("unknown"),
        data["verdict"]["archetype"].as_str().unwrap_or(""),
    );
    println!("\n## 拓扑\n");
    println!("{}", data["topology"]["diagram"].as_str().unwrap_or(""));
    if let Some(req) = data.get("request").filter(|v| !v.is_null()) {
        println!("\n## 请求骨架\n");
        println!("  {} {}", req["method"].as_str().unwrap_or(""), req["route"].as_str().unwrap_or(""));
        println!("  {}", req["curl"].as_str().unwrap_or(""));
    }
    println!("\n## Guard Gap\n");
    println!("  {}", data["guard_gap"]["summary"].as_str().unwrap_or(""));
    println!("\n## 修复建议\n");
    println!("  {}", data["remediation"]["summary"].as_str().unwrap_or(""));
    for step in data["remediation"]["steps"].as_array().cloned().unwrap_or_default() {
        println!("  - {}", step.as_str().unwrap_or(""));
    }
    println!("\n## 复现步骤\n");
    for step in data["reproduce"].as_array().cloned().unwrap_or_default() {
        println!("  {}", step.as_str().unwrap_or(""));
    }
    Ok(())
}
