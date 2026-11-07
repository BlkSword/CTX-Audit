// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Phase 3：抽象载荷蚂蚁 v1（确定性有限状态机，非随机 ACO）。
//!
//! 给定入口与汇，沿 `can_reach` 骨架逐跳推演"载荷是否存活"：
//! - 守卫 = 杀伤（`guards_range` 命中 archetype 杀伤表 → payload_killed）；
//! - 参数化查询 / escape / 白名单等函数体标记 = 杀伤（名字级，显式标注）；
//! - decode/parse/encode 等调用 = 变异（记录 payload_state）；
//! - 输出**证据分级**：payload_killed / guard_ineffective_token / payload_may_survive / unreachable。
//!
//! 明确边界：名字级、不做类型/别名推断，不给 BYPASS 结论；验证需 Phase 4 动态 harness。

use super::chain;
use super::index;
use super::probe;
use super::ssa;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

/// archetype 归一化。
fn normalize_archetype(s: &str) -> &'static str {
    let l = s.to_ascii_lowercase();
    if l.contains("sql") {
        "sql_quote"
    } else if l.contains("travers") || l.contains("path") {
        "traversal"
    } else if l.contains("jndi") || l.contains("ldap") {
        "jndi"
    } else if l.contains("template") || l.contains("spel") || l.contains("expression") {
        "template"
    } else if l.contains("deser") || l.contains("serial") {
        "deserialization"
    } else if l.contains("command") || l.contains("exec") {
        "command"
    } else if l.contains("ssrf") {
        "ssrf"
    } else if l.contains("xss") || l.contains("html") {
        "xss"
    } else {
        "generic"
    }
}

fn guard_kills(archetype: &str) -> &'static [&'static str] {
    match archetype {
        "sql_quote" => &["sanitize", "allowlist"],
        "traversal" => &["path_check", "allowlist"],
        "jndi" => &["allowlist", "ssrf_check"],
        "template" => &["template_escape", "sanitize", "allowlist"],
        "deserialization" => &["allowlist", "bounds"],
        "command" => &["sanitize", "allowlist"],
        "ssrf" => &["ssrf_check", "allowlist"],
        "xss" => &["template_escape", "sanitize"],
        _ => &[],
    }
}

/// 函数体里的"杀伤标记"（名字级，按 archetype）。
fn body_kill(archetype: &str, content: &str, start: u32, end: u32) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let lo = (start as usize).saturating_sub(1);
    let hi = (end as usize).min(lines.len());
    if lo >= hi {
        return None;
    }
    let body = lines[lo..hi].join("\n");
    match archetype {
        "sql_quote" => {
            if body.contains("prepareStatement") || body.contains("setString(") || body.contains("setObject(") {
                return Some("parameterized_query".to_string());
            }
            // Python 参数化：execute("...%s", (x,))
            for l in &lines[lo..hi] {
                if l.contains("execute(") && (l.contains("%s") && l.contains(", (") || l.contains("?")) {
                    return Some("parameterized_query".to_string());
                }
            }
            None
        }
        "traversal" => {
            if body.contains(".normalize(") || body.contains("normalize(") || body.contains("getCanonicalPath") || body.contains("filepath.Clean") {
                Some("path_normalized".to_string())
            } else {
                None
            }
        }
        "template" | "xss" => {
            if body.contains("escapeHtml") || body.contains("autoescape") || body.contains("HtmlUtils") {
                Some("output_escaped".to_string())
            } else {
                None
            }
        }
        "deserialization" => {
            if body.contains("ObjectInputFilter") || body.contains("setObjectInputFilter") {
                Some("input_filter".to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn transforms(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (tok, name) in [
        ("decode", "decode"),
        ("decodeURIComponent", "decode"),
        ("parseObject", "parse"),
        ("JSON.parse", "parse"),
        ("base64", "base64"),
        ("Base64", "base64"),
        ("encode", "encode"),
    ] {
        if line.contains(tok) {
            out.push(name.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 载荷存活推演（确定性；名字级）。
pub fn payload_viability_report(
    project: &Path,
    entry_file: &str,
    entry_line: u32,
    sink_file: &str,
    sink_line: u32,
    archetype: &str,
) -> Result<Value, String> {
    let arch = normalize_archetype(archetype);
    let reach = probe::can_reach_report(project, entry_file, entry_line, sink_file, sink_line)?;
    let reachable = reach["reachable"].as_bool().unwrap_or(false);
    if !reachable {
        return Ok(json!({
            "schema": "payload-ant/v1",
            "archetype": arch,
            "reachable": false,
            "viability": "unreachable",
            "tier": "unreachable",
            "steps": [],
            "uncertainty": {"level": "high", "reasons": ["structural_path_not_found"]},
        }));
    }
    let loaded = index::load_files(project);
    let contents: BTreeMap<&str, &str> = loaded
        .files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    let path: Vec<Value> = reach["path"].as_array().cloned().unwrap_or_default();
    let mut steps: Vec<Value> = Vec::new();
    let mut killed: Option<Value> = None;
    let mut state: Vec<String> = vec!["raw".to_string()];

    for i in 0..path.len().saturating_sub(1) {
        let caller_file = path[i]["file"].as_str().unwrap_or("");
        let caller_line = path[i]["line"].as_u64().unwrap_or(0) as u32;
        let caller_sym = path[i]["symbol"].as_str().unwrap_or("");
        let callee_sym = path[i + 1]["symbol"].as_str().unwrap_or("");
        let Some(content) = contents.get(caller_file) else { continue };
        let def_end = probe_def_end(content, caller_line);
        let guards = chain::guards_range(content, caller_line, def_end, caller_file);
        let guard_kind: Vec<String> = guards
            .iter()
            .filter_map(|g| g.get("kind").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();
        let kill_guard = guards.iter().find(|g| {
            g.get("kind")
                .and_then(|v| v.as_str())
                .map(|k| guard_kills(arch).contains(&k))
                .unwrap_or(false)
        });
        let flow = ssa::param_flow_report(project, caller_file, caller_line).ok();
        let mut tainted_args: Vec<Value> = Vec::new();
        if let Some(flow) = &flow {
            if let Some(calls) = flow["calls"].as_array() {
                for c in calls {
                    let callee = c["callee"].as_str().unwrap_or("");
                    let cands = c["candidates"].as_array().cloned().unwrap_or_default();
                    let matched = callee == callee_sym
                        || cands.iter().any(|cd| {
                            cd["file"].as_str() == Some(path[i + 1]["file"].as_str().unwrap_or(""))
                                && cd["line"].as_u64() == path[i + 1]["line"].as_u64()
                        });
                    if matched {
                        if let Some(ta) = c["tainted_args"].as_array() {
                            tainted_args = ta.clone();
                        }
                        break;
                    }
                }
            }
        }
        let call_line = path[i]["line"].as_u64().unwrap_or(0);
        let _ = call_line;
        // 变形：调用行文本（在 caller 文件里按 callee 名找一行）
        let call_text = content
            .lines()
            .find(|l| l.contains(&format!("{callee_sym}(")))
            .unwrap_or("");
        let mut mutations = transforms(call_text);
        if !tainted_args.is_empty() {
            state.push(format!("hop{i}:tainted"));
        }
        if killed.is_none() {
            if let Some(g) = kill_guard {
                killed = Some(json!({
                    "hop": i,
                    "file": caller_file,
                    "def_line": caller_line,
                    "symbol": caller_sym,
                    "guard": g,
                    "kind": arch,
                }));
            } else if let Some(bk) = body_kill(arch, content, caller_line, def_end) {
                killed = Some(json!({
                    "hop": i,
                    "file": caller_file,
                    "def_line": caller_line,
                    "symbol": caller_sym,
                    "guard": {"kind": "body_token", "evidence": bk},
                    "kind": arch,
                }));
            }
        }
        steps.push(json!({
            "hop": i,
            "file": caller_file,
            "def_line": caller_line,
            "symbol": caller_sym,
            "next": callee_sym,
            "guards": guard_kind,
            "tainted_args": tainted_args,
            "mutations": mutations,
            "state": state.clone(),
        }));
    }

    // 汇节点自身函数的守卫/杀伤标记
    if killed.is_none() {
        let sf = path.last().map(|v| v["file"].as_str().unwrap_or("")).unwrap_or(sink_file);
        let sl = path.last().map(|v| v["line"].as_u64().unwrap_or(sink_line as u64) as u32).unwrap_or(sink_line);
        if let Some(content) = contents.get(sf) {
            let def_end = probe_def_end(content, sl);
            let guards = chain::guards_range(content, sl, def_end, sf);
            let kill_guard = guards.iter().find(|g| {
                g.get("kind")
                    .and_then(|v| v.as_str())
                    .map(|k| guard_kills(arch).contains(&k))
                    .unwrap_or(false)
            });
            if let Some(g) = kill_guard {
                killed = Some(json!({"hop": steps.len(), "file": sf, "def_line": sl, "symbol": path.last().and_then(|v| v["symbol"].as_str()).unwrap_or(""), "guard": g, "kind": arch}));
            } else if let Some(bk) = body_kill(arch, content, sl, def_end) {
                killed = Some(json!({"hop": steps.len(), "file": sf, "def_line": sl, "symbol": path.last().and_then(|v| v["symbol"].as_str()).unwrap_or(""), "guard": {"kind": "body_token", "evidence": bk}, "kind": arch}));
            }
        }
    }

    let (tier, viability) = if killed.is_some() {
        ("payload_killed", "killed")
    } else {
        ("payload_may_survive", "may_survive")
    };

    Ok(json!({
        "schema": "payload-ant/v1",
        "archetype": arch,
        "reachable": true,
        "viability": viability,
        "tier": tier,
        "hops": steps.len(),
        "steps": steps,
        "killed_at": killed,
        "method": "deterministic_payload_state_machine_v1",
        "evidence_tiers": ["payload_killed", "guard_ineffective_token", "payload_may_survive", "payload_verified"],
        "uncertainty": {
            "level": "medium",
            "reasons": ["name_level_dataflow", "guard_kill_table_v1", "no_dynamic_verification"],
        },
    }))
}

fn probe_def_end(content: &str, def_line: u32) -> u32 {
    let total = content.lines().count() as u32;
    // 与 probe/ssa 相同的近似：到下一条同缩进/更浅缩进的 def 为止；此处简化为 +120 上限
    (def_line.saturating_add(120)).min(total.max(def_line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tree(root: &Path, files: &[(&str, &str)]) {
        for (p, c) in files {
            let full = root.join(p);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let mut f = std::fs::File::create(&full).unwrap();
            f.write_all(c.as_bytes()).unwrap();
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ctx-ant-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn payload_survives_without_guard_and_dies_with_normalize() {
        let dir = tmp("path");
        write_tree(
            &dir,
            &[(
                "App.java",
                r#"
public class App {
    public String download(String name) {
        String p = "/data/" + name;
        return read(p);
    }
    String read(String p) { return p; }
}
"#,
            )],
        );
        let ok = payload_viability_report(&dir, "App.java", 3, "App.java", 5, "traversal").unwrap();
        assert_eq!(ok["viability"], "may_survive", "{ok}");
        assert_eq!(ok["tier"], "payload_may_survive");

        write_tree(
            &dir,
            &[(
                "Fixed.java",
                r#"
public class Fixed {
    public String download(String name) {
        String p = normalize(name);
        return read(p);
    }
    String read(String p) { return p; }
}
"#,
            )],
        );
        let killed = payload_viability_report(&dir, "Fixed.java", 3, "Fixed.java", 5, "traversal").unwrap();
        assert_eq!(killed["viability"], "killed", "{killed}");
        assert_eq!(killed["tier"], "payload_killed");
    }
}
