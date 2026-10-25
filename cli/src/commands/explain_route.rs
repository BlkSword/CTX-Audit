// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit explain-route` —— 单条路由判定 + 可机械证伪（`--assert` 退出码）。
//!
//! 这是"把信任成本换成运行一条命令"的入口：审计员不需要相信引擎，
//! 只需要跑一次并看退出码。

use miette::{miette, IntoDiagnostic, Result};
use std::path::PathBuf;

/// 断言目标。`covered` = 该路由被声明式规则覆盖；`uncovered` = 未被覆盖；
/// `permitted` = 被显式放行（permitAll）；`any` = 只求有匹配。
fn verdict_matches(expect: &str, actual: &str) -> bool {
    match expect.to_ascii_lowercase().as_str() {
        "any" => true,
        "covered" => actual == "covered",
        "uncovered" => actual == "uncovered",
        "permitted" => actual == "permitted",
        other => other == actual,
    }
}

/// 执行 `explain-route` 子命令。
pub async fn execute(
    path: String,
    route: Option<String>,
    file: Option<String>,
    handler: Option<String>,
    assert: Option<String>,
    output: String,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    if route.is_none() && file.is_none() && handler.is_none() {
        return Err(miette!(
            "需要至少一个定位参数：<ROUTE> 或 --file / --handler"
        ));
    }
    let data = ctx_audit_tools::explain_route_report(
        &root,
        route.as_deref(),
        file.as_deref(),
        handler.as_deref(),
    )
    .map_err(|e| miette!("{}", e))?;

    if output.eq_ignore_ascii_case("json") {
        println!("{}", serde_json::to_string_pretty(&data).into_diagnostic()?);
    } else if data["matched"].as_bool() == Some(true) {
        println!(
            "{} {}  ->  {}",
            data["http_method"].as_str().unwrap_or("ANY"),
            data["route"].as_str().unwrap_or(""),
            data["verdict"].as_str().unwrap_or("unknown")
        );
        println!(
            "位置: {}:{}  scope={}  coverage_scope={}",
            data["file"].as_str().unwrap_or(""),
            data["line"],
            data["scope"].as_str().unwrap_or(""),
            data["coverage_scope"].as_str().unwrap_or("")
        );
        if let Some(checks) = data["decided_by"].as_array() {
            println!("判定依据:");
            for c in checks {
                println!(
                    "  - {:<42} {}",
                    c["check"].as_str().unwrap_or(""),
                    c["result"]
                );
            }
        }
        let sens = &data["sensitive_return"];
        if sens["risky_return"].as_bool() == Some(true) {
            let fields: Vec<String> = sens["sensitive_fields"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|f| f["field"].as_str().map(|s| s.to_string()))
                .collect();
            println!("敏感返回面: {}", fields.join(", "));
        }
        println!("证伪命令: {}", data["falsify"].as_str().unwrap_or(""));
    } else {
        println!(
            "未匹配到路由（考虑过 {} 条）：检查 route 写法或改用 --file/--handler",
            data["routes_considered"]
        );
    }

    if let Some(expect) = assert {
        if data["matched"].as_bool() != Some(true) {
            eprintln!("ASSERT FAILED: 没有匹配到路由，无法断言 {expect}");
            std::process::exit(1);
        }
        let actual = data["asserted_verdict"].as_str().unwrap_or("unknown");
        if verdict_matches(&expect, actual) {
            if !output.eq_ignore_ascii_case("json") {
                println!("ASSERT OK: {actual} == {expect}");
            }
        } else {
            eprintln!(
                "ASSERT FAILED: 期望 {expect}，实际 {actual}（{}:{}）",
                data["file"].as_str().unwrap_or(""),
                data["line"]
            );
            std::process::exit(1);
        }
    }
    Ok(())
}
