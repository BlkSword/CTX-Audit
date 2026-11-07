// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CLI `ctx-audit verify`：受限动态验证包装。

use miette::{miette, IntoDiagnostic, Result};
use serde_json::Value;
use std::path::PathBuf;

pub async fn execute(
    root: String,
    file: String,
    function: String,
    payload: String,
    archetype: String,
    output: String,
) -> Result<()> {
    let root_path = PathBuf::from(&root);
    if !root_path.exists() {
        return Err(miette!("路径不存在: {root}"));
    }
    let data = ctx_audit_tools::verify_payload_report(
        &root_path,
        &file,
        &function,
        &payload,
        &archetype,
    )
    .map_err(|e| miette!("{}", e))?;
    if output.eq_ignore_ascii_case("md") {
        println!("{}", render_md(&data));
    } else {
        println!("{}", serde_json::to_string_pretty(&data).into_diagnostic()?);
    }
    Ok(())
}

fn render_md(d: &Value) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# 动态验证\n\n- file: `{}`\n- function: `{}`\n- archetype: `{}`\n- tier: `{}`\n",
        d["file"], d["function"], d["archetype"], d["tier"]
    ));
    if let Some(reason) = d.get("reason").and_then(|v| v.as_str()) {
        out.push_str(&format!("- reason: `{reason}`\n"));
    }
    if let Some(enable) = d.get("enable").and_then(|v| v.as_str()) {
        out.push_str(&format!("- enable: {enable}\n"));
    }
    if let Some(ev) = d.get("evidence").filter(|v| v.is_object()) {
        out.push_str(&format!(
            "\n```json\n{}\n```\n",
            serde_json::to_string_pretty(ev).unwrap_or_default()
        ));
    }
    out
}
