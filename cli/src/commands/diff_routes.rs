// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit diff-routes` —— 端点与覆盖判定的基线 diff（CI 门禁用）。
//!
//! 价值主张：**重复审计**里真正昂贵的不是"再看一遍"，而是"判断哪些是新变的"。
//! 一条命令给出：新增端点 / 删除端点 / 判定翻转，并对"新增且未被覆盖"返回非零退出码。

use miette::{miette, IntoDiagnostic, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const UNCOVERED: [&str; 3] = [
    "no_global_config_found",
    "no_global_match_found",
    "coverage_unknown",
];

fn snapshot(project: &Path) -> Result<Value> {
    let report =
        ctx_audit_tools::project_route_report(project, "brief").map_err(|e| miette!("{}", e))?;
    let mut rows: Vec<Value> = report["routes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r["scope"].as_str() != Some("class"))
        .map(|r| {
            json!({
                "method": r["http_method"].as_str().unwrap_or("ANY"),
                "route": r["route"].as_str().unwrap_or(""),
                "file": r["file"].as_str().unwrap_or(""),
                "line": r["line"],
                "verdict": r["global_coverage"].as_str().unwrap_or("unknown"),
                "coverage_scope": r["coverage_scope"].as_str().unwrap_or(""),
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        let ka = format!(
            "{} {}",
            a["method"].as_str().unwrap_or(""),
            a["route"].as_str().unwrap_or("")
        );
        let kb = format!(
            "{} {}",
            b["method"].as_str().unwrap_or(""),
            b["route"].as_str().unwrap_or("")
        );
        ka.cmp(&kb)
    });
    Ok(json!({
        "version": 1,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "index_truncated_at_limit": report["index_truncated_at_limit"],
        "routes": rows,
    }))
}

fn key(r: &Value) -> String {
    format!(
        "{} {}",
        r["method"].as_str().unwrap_or("ANY"),
        r["route"].as_str().unwrap_or("")
    )
}

/// 执行 `diff-routes` 子命令。
pub async fn execute(
    path: String,
    since: Option<String>,
    write_baseline: bool,
    fail_on_new_uncovered: bool,
    output: String,
) -> Result<()> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(miette!("路径不存在: {}", path));
    }
    let current = snapshot(&root)?;
    let base_path = match since {
        Some(p) => PathBuf::from(p),
        None => root.join(".ctx-audit").join("routes-baseline.json"),
    };
    let previous: Option<Value> = if base_path.exists() {
        let text = std::fs::read_to_string(&base_path).into_diagnostic()?;
        serde_json::from_str(&text).ok()
    } else {
        None
    };

    let cur_rows = current["routes"].as_array().cloned().unwrap_or_default();
    let prev_rows = previous
        .as_ref()
        .and_then(|p| p["routes"].as_array().cloned())
        .unwrap_or_default();
    let prev_map: std::collections::BTreeMap<String, Value> =
        prev_rows.iter().map(|r| (key(r), r.clone())).collect();
    let cur_map: std::collections::BTreeMap<String, Value> =
        cur_rows.iter().map(|r| (key(r), r.clone())).collect();

    let mut added: Vec<Value> = Vec::new();
    let mut removed: Vec<Value> = Vec::new();
    let mut changed: Vec<Value> = Vec::new();
    for (k, r) in cur_map.iter() {
        match prev_map.get(k) {
            None => added.push(r.clone()),
            Some(p) => {
                let pv = p["verdict"].as_str().unwrap_or("unknown");
                let cv = r["verdict"].as_str().unwrap_or("unknown");
                if pv != cv {
                    changed.push(json!({
                        "route": r["route"], "method": r["method"],
                        "file": r["file"], "line": r["line"],
                        "before": pv, "after": cv,
                    }));
                }
            }
        }
    }
    for (k, r) in prev_map.iter() {
        if !cur_map.contains_key(k) {
            removed.push(r.clone());
        }
    }
    let new_uncovered: Vec<&Value> = added
        .iter()
        .filter(|r| {
            let v = r["verdict"].as_str().unwrap_or("unknown");
            UNCOVERED.contains(&v)
        })
        .collect();
    let baseline_missing = previous.is_none();
    let report = json!({
        "project": root.display().to_string(),
        "baseline": base_path.display().to_string(),
        "baseline_missing": baseline_missing,
        "index_truncated_at_limit": current["index_truncated_at_limit"],
        "summary": {
            "routes_total": cur_map.len(),
            "added": added.len(),
            "removed": removed.len(),
            "verdict_changed": changed.len(),
            "new_uncovered": new_uncovered.len(),
        },
        "added": added,
        "removed": removed,
        "verdict_changed": changed,
        "new_uncovered": new_uncovered,
    });

    if write_baseline {
        if let Some(parent) = base_path.parent() {
            std::fs::create_dir_all(parent).into_diagnostic()?;
        }
        std::fs::write(
            &base_path,
            serde_json::to_string_pretty(&current).into_diagnostic()?,
        )
        .into_diagnostic()?;
    }

    if output.eq_ignore_ascii_case("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).into_diagnostic()?
        );
    } else {
        let s = &report["summary"];
        println!(
            "端点 {} 条 | 新增 {} | 删除 {} | 判定翻转 {} | 新增未覆盖 {}",
            s["routes_total"], s["added"], s["removed"], s["verdict_changed"], s["new_uncovered"]
        );
        if baseline_missing {
            println!(
                "（无基线文件：{}，本次只列现有端点；用 --write-baseline 建立基线）",
                base_path.display()
            );
        }
        for r in added.iter() {
            println!(
                "  + {} {}  {}:{}  [{}]",
                r["method"].as_str().unwrap_or(""),
                r["route"].as_str().unwrap_or(""),
                r["file"].as_str().unwrap_or(""),
                r["line"],
                r["verdict"].as_str().unwrap_or("")
            );
        }
        for r in removed.iter() {
            println!(
                "  - {} {}  {}",
                r["method"].as_str().unwrap_or(""),
                r["route"].as_str().unwrap_or(""),
                r["file"].as_str().unwrap_or("")
            );
        }
        for c in changed.iter() {
            println!(
                "  ~ {} {}  {} -> {}",
                c["method"].as_str().unwrap_or(""),
                c["route"].as_str().unwrap_or(""),
                c["before"].as_str().unwrap_or(""),
                c["after"].as_str().unwrap_or("")
            );
        }
        if write_baseline {
            println!("基线已写入 {}", base_path.display());
        }
    }

    if fail_on_new_uncovered && !new_uncovered.is_empty() {
        eprintln!(
            "GATE FAILED: {} 条新增端点没有任何声明式鉴权覆盖",
            new_uncovered.len()
        );
        std::process::exit(1);
    }
    Ok(())
}
