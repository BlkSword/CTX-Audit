// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit chain` —— 法医台：候选链 / 链档 / 步骤证伪。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

pub async fn execute(
    path: String,
    list: bool,
    id: Option<String>,
    sink: Option<String>,
    entry: Option<String>,
    limit: usize,
    output: String,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }

    if let Some(chain_id) = id {
        if output.eq_ignore_ascii_case("md") {
            let md = ctx_audit_tools::chain_dossier_markdown(&root, &chain_id)
                .map_err(|e| miette!("{}", e))?;
            println!("{md}");
            return Ok(());
        }
        let d = ctx_audit_tools::chain_dossier_report(&root, &chain_id)
            .map_err(|e| miette!("{}", e))?;
        println!("{}", serde_json::to_string_pretty(&d).into_diagnostic()?);
        return Ok(());
    }

    // 默认：列出候选链
    let _ = list;
    let data = ctx_audit_tools::chain_candidates_report(&root, limit, sink.as_deref(), entry.as_deref())
        .map_err(|e| miette!("{}", e))?;
    if output.eq_ignore_ascii_case("md") {
        println!("# 候选链（入口→危险汇）\n");
        if let Some(stats) = data.get("stats") {
            println!(
                "- 扫描汇: {} · 可达链: {} · 无入口候选: {}",
                stats.get("sinks_scanned").and_then(|v| v.as_u64()).unwrap_or(0),
                stats.get("chains_found").and_then(|v| v.as_u64()).unwrap_or(0),
                stats.get("sinks_reached").and_then(|v| v.as_u64()).unwrap_or(0),
            );
        }
        println!("\n| ID | 入口 | auth | 汇 | 步数 | 不确定度 |");
        println!("|---|---|---|---|---|---|");
        if let Some(chains) = data.get("chains").and_then(|v| v.as_array()) {
            for c in chains {
                println!(
                    "| `{}` | {} {} ({}:{}) | {} | {} ({}:{}) | {} | {} |",
                    c["chain_id"].as_str().unwrap_or(""),
                    c["entry"]["method"].as_str().unwrap_or("ANY"),
                    c["entry"]["route"].as_str().unwrap_or(""),
                    c["entry"]["file"].as_str().unwrap_or(""),
                    c["entry"]["handler_line"].as_u64().unwrap_or(0),
                    c["entry"]["auth"].as_str().unwrap_or("unknown"),
                    c["sink"]["kind"].as_str().unwrap_or(""),
                    c["sink"]["file"].as_str().unwrap_or(""),
                    c["sink"]["line"].as_u64().unwrap_or(0),
                    c["steps"].as_array().map(|v| v.len()).unwrap_or(0),
                    c["uncertainty"]["level"].as_str().unwrap_or(""),
                );
            }
        }
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(&data).into_diagnostic()?);
    Ok(())
}
