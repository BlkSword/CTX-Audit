// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit baseline` —— 鉴权基线卡（与 MCP `get_security_baseline` 同一实现）。
//!
//! 目的：把"这个项目的'受保护'是什么意思"压成一屏可复核的事实，
//! 省掉审计员重新读一遍安全配置的固定成本。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

/// 执行 `baseline` 子命令。
pub async fn execute(path: String, output: String) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    let data = ctx_audit_tools::security_baseline_report(&root).map_err(|e| miette!("{}", e))?;

    if output.eq_ignore_ascii_case("json") {
        println!("{}", serde_json::to_string_pretty(&data).into_diagnostic()?);
        return Ok(());
    }

    let summary = &data["summary"];
    println!("== 鉴权基线 ==");
    println!(
        "链 {} 条 / 规则 {} 条 / 过滤器 {} 条 / 索引截断 {}",
        summary["chains"],
        summary["rules"],
        summary["container_filters"],
        data["index_truncated_at_limit"]
    );
    let unconsumed = summary["annotations_without_consumer"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !unconsumed.is_empty() {
        println!(
            "⚠ 被使用但没有消费者的鉴权注解: {}",
            unconsumed
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(chains) = data["chains"].as_array() {
        for c in chains {
            println!(
                "\n-- 链 @ {}:{} (order={}, matcher={})",
                c["file"].as_str().unwrap_or(""),
                c["line"],
                c["order"],
                c["matcher"]
            );
            for r in c["rules"].as_array().cloned().unwrap_or_default() {
                println!(
                    "   {} -> {}   [{}:{}]",
                    r["match"].as_str().unwrap_or(""),
                    r["clause"].as_str().unwrap_or(""),
                    r["file"].as_str().unwrap_or(""),
                    r["line"]
                );
            }
        }
    }
    if let Some(hooks) = data["disabled_hooks"].as_array() {
        for h in hooks {
            println!(
                "\n⚠ 被关闭/改写的钩子 [{}] {}:{}  {}",
                h["hook"].as_str().unwrap_or(""),
                h["file"].as_str().unwrap_or(""),
                h["line"],
                h["text"].as_str().unwrap_or("")
            );
        }
    }
    Ok(())
}
