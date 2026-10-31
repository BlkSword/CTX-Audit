// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit chain` —— 法医台：候选链 / 链档 / 步骤证伪。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    path: String,
    list: bool,
    id: Option<String>,
    sink: Option<String>,
    entry: Option<String>,
    learn: bool,
    before: Option<String>,
    after: Option<String>,
    vocab: Option<String>,
    out: Option<String>,
    no_builtin_vocab: bool,
    limit: usize,
    output: String,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }

    // `chain learn`：从 漏洞版→修复版 的 diff 派生词表
    if learn {
        let (Some(b), Some(a)) = (before, after) else {
            return Err(miette!("--learn 需要同时提供 --before 与 --after"));
        };
        let before_root = PathBuf::from(b);
        let after_root = PathBuf::from(a);
        let vocab = ctx_audit_tools::learn_vocab(&before_root, &after_root)
            .map_err(|e| miette!("{}", e))?;
        let text = serde_json::to_string_pretty(&vocab).into_diagnostic()?;
        if let Some(out_path) = out {
            if let Some(parent) = std::path::Path::new(&out_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&out_path, &text).into_diagnostic()?;
            eprintln!(
                "vocab written: {} (sinks={}, entries={})",
                out_path,
                vocab["sink_patterns"].as_array().map(|a| a.len()).unwrap_or(0),
                vocab["entry_names"].as_array().map(|a| a.len()).unwrap_or(0)
            );
        } else {
            println!("{text}");
        }
        return Ok(());
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
    let data = ctx_audit_tools::chain_candidates_report(
        &root,
        limit,
        sink.as_deref(),
        entry.as_deref(),
        vocab.as_deref(),
        !no_builtin_vocab,
    )
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
