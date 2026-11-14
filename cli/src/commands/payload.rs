// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit payload` —— 载荷存活判定（ant 档位）。
//!
//! 把 MCP 的 `payload_viability` 能力暴露为 CLI，供控制台与脚本直接调用：
//! 输入入口坐标与汇坐标，输出 `payload-ant/v1`（reachable / viability / tier /
//! steps / guards / falsify）。

use crate::PayloadCommand;
use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

pub async fn execute(cmd: PayloadCommand) -> Result<()> {
    match cmd {
        PayloadCommand::Viability {
            root,
            entry_file,
            entry_line,
            sink_file,
            sink_line,
            archetype,
            output,
        } => {
            let root = check_root(root)?;
            let data = ctx_audit_tools::payload_viability_report(
                &root,
                &entry_file,
                entry_line,
                &sink_file,
                sink_line,
                &archetype,
            )
            .map_err(|e| miette!("{}", e))?;

            if output.eq_ignore_ascii_case("json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).into_diagnostic()?
                );
                return Ok(());
            }

            let tier = data["tier"].as_str().unwrap_or("unknown");
            let viability = data["viability"].as_str().unwrap_or("unknown");
            println!("载荷存活判定 — {archetype}");
            println!("  入口 {entry_file}:{entry_line} → 汇 {sink_file}:{sink_line}");
            println!(
                "  可达 {} · 档位 {tier} · viability {viability}",
                data["reachable"].as_bool().unwrap_or(false)
            );
            if let Some(steps) = data["steps"].as_array() {
                for step in steps {
                    println!(
                        "    {} {}:{}",
                        step["role"].as_str().unwrap_or("?"),
                        step["file"].as_str().unwrap_or(""),
                        step["line"].as_u64().unwrap_or(0)
                    );
                }
            }
            if let Some(reasons) = data["uncertainty"]["reasons"].as_array() {
                let joined: Vec<&str> = reasons.iter().filter_map(|r| r.as_str()).collect();
                if !joined.is_empty() {
                    println!("  不确定：{}", joined.join(", "));
                }
            }
            Ok(())
        }
    }
}

fn check_root(root: String) -> Result<PathBuf> {
    let p = PathBuf::from(&root);
    if !p.exists() {
        return Err(miette!("路径不存在: {}", root));
    }
    Ok(p)
}
