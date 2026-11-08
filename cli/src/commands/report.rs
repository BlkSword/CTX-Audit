// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit report` —— 汇总多份 gate JSON 报告（CI artifact）。

use miette::{miette, IntoDiagnostic, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn collect(path: &PathBuf) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(path) else { return out };
    for entry in rd.flatten() {
        let p = entry.path();
        let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        if !name.ends_with(".json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        if v.get("verdicts").is_none() && v.get("summary").is_none() {
            continue;
        }
        out.push((name, v));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn fmt_ms(sum: u64, runs: usize) -> String {
    if runs == 0 {
        "0ms".to_string()
    } else {
        format!("{}ms", sum / runs as u64)
    }
}

pub async fn execute(from: String, output: String) -> Result<()> {
    let dir = PathBuf::from(&from);
    if !dir.is_dir() {
        return Err(miette!("目录不存在: {from}"));
    }
    let runs = collect(&dir);
    if runs.is_empty() {
        return Err(miette!("目录中没有 gate JSON 报告: {from}"));
    }
    let mut total_runs = 0usize;
    let mut blocked_runs = 0usize;
    let mut total_blocks = 0usize;
    let mut total_waived = 0usize;
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut routes: BTreeMap<String, usize> = BTreeMap::new();
    let mut duration_sum = 0u64;
    let mut duration_max = 0u64;
    for (_name, v) in runs.iter() {
        total_runs += 1;
        let summary = v.get("summary").cloned().unwrap_or(Value::Null);
        let blocks = summary.get("blocks").and_then(|x| x.as_u64()).unwrap_or(0);
        let waived = summary.get("waived").and_then(|x| x.as_u64()).unwrap_or(0);
        total_blocks += blocks as usize;
        total_waived += waived as usize;
        if blocks > 0 {
            blocked_runs += 1;
        }
        let dur = v.get("duration_ms").and_then(|x| x.as_u64()).unwrap_or(0);
        duration_sum += dur;
        duration_max = duration_max.max(dur);
        if let Some(vs) = v.get("verdicts").and_then(|x| x.as_array()) {
            for vv in vs {
                if vv.get("severity").and_then(|x| x.as_str()) != Some("block") {
                    continue;
                }
                let kind = vv.get("kind").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
                *kinds.entry(kind).or_default() += 1;
                let route = vv
                    .get("route")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                if !route.is_empty() {
                    *routes.entry(route).or_default() += 1;
                }
            }
        }
    }
    let block_rate = if total_runs == 0 {
        "0.0%".to_string()
    } else {
        format!("{:.1}%", (blocked_runs as f64 / total_runs as f64) * 100.0)
    };
    let mut top_routes: Vec<(String, usize)> = routes.into_iter().collect();
    top_routes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    top_routes.truncate(10);

    if output.eq_ignore_ascii_case("json") {
        let agg = serde_json::json!({
            "schema": "gate-report/v1",
            "runs": total_runs,
            "blocked_runs": blocked_runs,
            "block_rate": block_rate,
            "block_verdicts": total_blocks,
            "waived": total_waived,
            "kinds": kinds,
            "top_routes": top_routes.iter().map(|(r, c)| serde_json::json!({"route": r, "count": c})).collect::<Vec<_>>(),
            "duration_ms_mean": duration_sum / total_runs as u64,
            "duration_ms_max": duration_max,
        });
        println!("{}", serde_json::to_string_pretty(&agg).into_diagnostic()?);
        return Ok(());
    }

    let mut out = String::new();
    out.push_str("# CTX-Audit PR 闸门汇总\n\n");
    out.push_str(&format!(
        "- 运行次数：**{}**；有拦截的运行：**{}**（block 率 **{}**）\n",
        total_runs, blocked_runs, block_rate
    ));
    out.push_str(&format!(
        "- block verdicts：**{}**；已豁免：**{}**\n",
        total_blocks, total_waived
    ));
    out.push_str(&format!(
        "- 单次耗时：均值 **{}**，最大 **{}ms**\n",
        fmt_ms(duration_sum, total_runs),
        duration_max
    ));
    out.push_str("\n| kind | 次数 |\n|---|---|\n");
    for (k, c) in kinds.iter() {
        out.push_str(&format!("| `{k}` | {c} |\n"));
    }
    if !top_routes.is_empty() {
        out.push_str("\n| 路由 | 次数 |\n|---|---|\n");
        for (r, c) in top_routes.iter() {
            out.push_str(&format!("| `{r}` | {c} |\n"));
        }
    }
    println!("{out}");
    Ok(())
}
