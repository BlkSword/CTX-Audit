// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! `ctx-audit probe` —— 路线 B 探针原语（can_reach / slice_between）。

use crate::ProbeCommand;
use miette::{miette, IntoDiagnostic, Result};
use serde_json::Value;
use std::path::PathBuf;

pub async fn execute(cmd: ProbeCommand) -> Result<()> {
    match cmd {
        ProbeCommand::Reach {
            root,
            from_file,
            from_line,
            to_file,
            to_line,
            output,
        } => {
            let root = check_root(root)?;
            let d = ctx_audit_tools::can_reach_report(
                &root, &from_file, from_line, &to_file, to_line,
            )
            .map_err(|e| miette!("{}", e))?;
            render(&d, &output)?;
        }
        ProbeCommand::Slice {
            root,
            from_file,
            from_line,
            to_file,
            to_line,
            radius,
            output,
        } => {
            let root = check_root(root)?;
            let d = ctx_audit_tools::slice_between_report(
                &root, &from_file, from_line, &to_file, to_line, radius,
            )
            .map_err(|e| miette!("{}", e))?;
            render(&d, &output)?;
        }
    }
    Ok(())
}

fn check_root(root: String) -> Result<PathBuf> {
    let p = PathBuf::from(&root);
    if !p.exists() {
        return Err(miette!("路径不存在: {}", root));
    }
    Ok(p)
}

fn render(data: &Value, output: &str) -> Result<()> {
    if output.eq_ignore_ascii_case("md") {
        println!("{}", render_md(data));
    } else {
        println!("{}", serde_json::to_string_pretty(data).into_diagnostic()?);
    }
    Ok(())
}

fn render_md(d: &Value) -> String {
    let mut out = String::new();
    if d.get("slices").is_some() {
        out.push_str(&format!(
            "# 探针切片\n\n- reachable: `{}`\n- bytes: `{}`\n\n",
            d["reachable"], d["bytes"]
        ));
        if let Some(slices) = d["slices"].as_array() {
            for s in slices {
                out.push_str(&format!(
                    "## {} :: {} ({}–{})\n\n```\n{}\n```\n\n",
                    s["file"].as_str().unwrap_or(""),
                    s["symbol"].as_str().unwrap_or(""),
                    s["from_line"],
                    s["to_line"],
                    s["text"].as_str().unwrap_or("")
                ));
            }
        }
        return out;
    }
    out.push_str(&format!(
        "# 可达性查询\n\n- reachable: `{}`\n- hops: `{}`\n- method: `{}`\n\n",
        d["reachable"], d["hops"], d["method"]
    ));
    if let Some(path) = d["path"].as_array() {
        out.push_str("| # | file | line | symbol | edge |\n|---|---|---|---|---|\n");
        for (i, p) in path.iter().enumerate() {
            out.push_str(&format!(
                "| {} | {} | {} | `{}` | {} |\n",
                i + 1,
                p["file"].as_str().unwrap_or(""),
                p["line"],
                p["symbol"].as_str().unwrap_or(""),
                p["edge"].as_str().unwrap_or("")
            ));
        }
    }
    if let Some(u) = d["uncertainty"]["reasons"].as_array() {
        out.push_str(&format!(
            "\n不确定性: {}\n",
            u.iter().filter_map(|r| r.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    out
}
