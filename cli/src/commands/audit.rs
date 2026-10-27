// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0
//! 审计驾驶舱（`ctx-audit audit`）：覆盖率摘要 + 排序待审清单 + 证据包。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

pub async fn execute(path: String, out: String, limit: usize, output: String) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    let out_dir = PathBuf::from(&out);
    // 一次全量扫描：同一份 bundle 既用于打印摘要，也用于写全部产物
    let bundle = ctx_audit_tools::audit_bundle(&root).map_err(|e| miette!("{}", e))?;
    let written = ctx_audit_tools::audit_write_from_bundle(&root, &out_dir, limit, &bundle)
        .map_err(|e| miette!("{}", e))?;

    if output.eq_ignore_ascii_case("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&bundle).into_diagnostic()?
        );
        return Ok(());
    }

    let cov = &bundle["coverage"];
    println!("审计驾驶舱 — {}", bundle["project"].as_str().unwrap_or(""));
    println!(
        "  method 级端点 {}  ·  文件 {}  ·  置信 {}",
        cov["method_routes"].as_u64().unwrap_or(0),
        bundle["files_indexed"].as_u64().unwrap_or(0),
        cov["confidence"].as_str().unwrap_or("unknown"),
    );
    println!(
        "  未覆盖 {}  ·  注解覆盖 {}  ·  显式放行 {}  ·  未知 {}",
        cov["uncovered"].as_u64().unwrap_or(0),
        cov["annotation_covered"].as_u64().unwrap_or(0),
        cov["by_verdict"]
            .get("permitted_by_global_config")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        cov["by_verdict"]
            .get("coverage_unknown")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    );
    println!(
        "  边界：动态注册 {} · 未建模路由文件 {} · 索引截断 {}",
        cov["dynamic_endpoint_registrations"].as_u64().unwrap_or(0),
        cov["unmodelled_route_files"].as_u64().unwrap_or(0),
        cov["index_truncated_at_limit"].as_bool().unwrap_or(false),
    );
    println!(
        "  待审 {} 条，已写出 {} 个文件到 {}",
        bundle["worklist"].as_array().map(|a| a.len()).unwrap_or(0),
        written.len(),
        out_dir.display()
    );
    for p in written.iter().take(6) {
        println!("    - {}", p);
    }
    Ok(())
}
