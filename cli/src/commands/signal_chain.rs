// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit signal-chain` —— 三角色信号链候选（只读证据入口）。
//!
//! 只产**候选与证据**：不读规则、不产出 findings、不触碰 `scan` 的任何输出路径。
//! 判定仍由人/LLM 做。

use ctx_audit_tools::signal_chain::{scan_path, ConstructSet, SignalChainOptions, SignalChainReport};
use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

/// 执行 `signal-chain` 子命令。
pub async fn execute(
    path: String,
    output: String,
    constructs: String,
    candidates_only: bool,
    max_files: usize,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    let set = ConstructSet::parse(&constructs)
        .ok_or_else(|| miette!("未知构造族 '{}'（可选 all | loop | lenarg）", constructs))?;
    let report = scan_path(
        &root,
        &SignalChainOptions {
            constructs: set,
            max_files,
        },
    )
    .into_diagnostic()?;

    if output.eq_ignore_ascii_case("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else if output.eq_ignore_ascii_case("text") {
        print_text(&report, candidates_only);
    } else {
        return Err(miette!("未知输出格式 '{}'（可选 text | json）", output));
    }
    Ok(())
}

fn print_text(rep: &SignalChainReport, candidates_only: bool) {
    println!("信号链候选（三角色：trigger → path → effect）");
    println!("  schema            : {}", rep.schema);
    println!("  root              : {}", rep.root);
    println!("  files_scanned     : {}", rep.files_scanned);
    println!("  constructs_scanned: {}", rep.constructs_scanned);
    println!("  candidates        : {}", rep.candidate_count);
    let by: Vec<String> = rep
        .candidate_count_by_construct
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    println!("  candidates_by_kind: {}", by.join(", "));
    println!("  not_upgraded      : {}", rep.not_upgraded_count);
    println!();
    for c in &rep.candidates {
        println!(
            "CAND {}:{}  [{}] {}()  sink={} acc={} trigger({})={} path(guard={})",
            c.file,
            c.line,
            c.construct,
            c.function,
            c.effect.sink,
            c.effect.accumulating,
            c.trigger.origin,
            c.trigger.expr,
            c.path.guard_scope,
        );
    }
    if !candidates_only {
        if !rep.not_upgraded.is_empty() {
            println!();
            println!("-- not_upgraded（三角色不齐备，登记备查）--");
        }
        for c in &rep.not_upgraded {
            println!(
                "SKIP {}:{}  [{}] {}()  cause={} trigger({})={}",
                c.file,
                c.line,
                c.construct,
                c.function,
                c.cause.clone().unwrap_or_else(|| "-".to_string()),
                c.trigger.origin,
                c.trigger.expr,
            );
        }
    }
}
