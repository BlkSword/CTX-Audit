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
        "template" => &["allowlist"],
        "deserialization" => &["allowlist"],
        "command" => &["allowlist"],
        "ssrf" => &["ssrf_check", "allowlist"],
        "xss" => &["template_escape", "sanitize"],
        _ => &[],
    }
}

/// 通用 sanitize 是否对该载荷类型真正有效。
///
/// HTML 转义杀不掉 SQL/命令/表达式注入，长度校验杀不掉反序列化；只有
/// archetype 相关的清洗证据才算。
fn sanitize_effective(archetype: &str, content: &str, start: u32, end: u32) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    let lo = (start as usize).saturating_sub(1);
    let hi = (end as usize).min(lines.len());
    if lo >= hi {
        return false;
    }
    let body = lines[lo..hi].join("\n");
    match archetype {
        "sql_quote" => {
            body.contains("escapeSql")
                || body.contains("EscapeUtils")
                || body.contains("replaceAll(\"'\"")
                || body.contains("replace(\"'\"")
                || body.contains("prepareStatement")
                || body.contains("setString(")
        }
        "xss" => {
            body.contains("escapeHtml")
                || body.contains("HtmlUtils")
                || body.contains("encodeForHTML")
                || body.contains("html.EscapeString")
                || body.contains("autoescape")
        }
        "command" => {
            body.contains("shellEscape") || body.contains("quoteShell") || body.contains("escapeShellArg")
        }
        _ => false,
    }
}

/// 允许清单是否真正生效：必须存在比较/拒绝调用；仅声明常量不算守卫。
fn allowlist_enforced(content: &str, start: u32, end: u32) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    let lo = (start as usize).saturating_sub(1);
    let hi = (end as usize).min(lines.len());
    if lo >= hi {
        return false;
    }
    let body = lines[lo..hi].join("\n");
    const TOKENS: [&str; 12] = [
        "contains(",
        ".equals(",
        "matches(",
        "hasOwnProperty(",
        "checkAutoType(",
        "ObjectInputFilter",
        "allowTypes",
        "acceptTypes",
        "acceptList",
        "denyList",
        "startsWith(",
        "in ALLOWED",
    ];
    TOKENS.iter().any(|t| body.contains(t))
}

/// SQL 上下文：参数化查询保护不到的拼接位置（ORDER BY / IN 列表 / LIKE）。
fn sql_clause_context(line: &str) -> Option<&'static str> {
    let up = line.to_ascii_uppercase();
    if up.contains("ORDER BY") {
        Some("order_by")
    } else if up.contains(" IN (") || up.contains(" IN(") {
        Some("in_list")
    } else if up.contains("LIKE") {
        Some("like")
    } else {
        None
    }
}

/// 反序列化传输包装层（仅作证据标注，不改变"是否被过滤"的判定）。
fn deserialization_wrappers(content: &str, start: u32, end: u32) -> Vec<&'static str> {
    let lines: Vec<&str> = content.lines().collect();
    let lo = (start as usize).saturating_sub(1);
    let hi = (end as usize).min(lines.len());
    let body = lines[lo..hi].join("\n");
    let mut out: Vec<&'static str> = Vec::new();
    if body.contains("Base64") || body.contains("base64") {
        out.push("base64");
    }
    if body.contains("GZIP") || body.contains("Gzip") || body.contains("Inflater") {
        out.push("gzip");
    }
    if body.contains("JSON.parse") || body.contains("ObjectMapper") || body.contains("readValue") {
        out.push("json");
    }
    out
}

/// 路径校验顺序问题：先 startsWith/resolve 校验、后 normalize → 可被 ../ 绕过。
fn path_order_issue(content: &str, start: u32, end: u32) -> Option<&'static str> {
    let lines: Vec<&str> = content.lines().collect();
    let lo = (start as usize).saturating_sub(1);
    let hi = (end as usize).min(lines.len());
    let mut norm_idx: Option<usize> = None;
    let mut check_idx: Option<usize> = None;
    for i in lo..hi {
        let l = lines[i];
        if norm_idx.is_none() && (l.contains("normalize(") || l.contains("path.Clean") || l.contains("filepath.Clean")) {
            norm_idx = Some(i);
        }
        if check_idx.is_none()
            && (l.contains("startsWith(") || l.contains(".resolve(") || l.contains("getCanonicalPath("))
            && !l.contains("normalize(")
        {
            check_idx = Some(i);
        }
    }
    match (norm_idx, check_idx) {
        (Some(n), Some(c)) if c < n => Some("validate_before_normalize"),
        _ => None,
    }
}

/// 路径守卫是否有效：仅有 normalize/Clean 不足以防穿越，必须配合基目录/前缀校验。
fn path_guard_effective(content: &str, start: u32, end: u32) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    let lo = (start as usize).saturating_sub(1);
    let hi = (end as usize).min(lines.len());
    if lo >= hi {
        return false;
    }
    let body = lines[lo..hi].join("\n");
    let has_check = body.contains("startsWith(")
        || body.contains("secureJoin")
        || body.contains(".resolve(")
        || body.contains("getCanonicalPath(");
    if !has_check {
        return false;
    }
    // 校验必须在 normalize 之后；先校验后 normalize 可被 "../" 绕过
    if path_order_issue(content, start, end).is_some() {
        return false;
    }
    true
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
    let declares_allowlist = body.contains("ALLOWED")
        || body.contains("allowlist")
        || body.contains("whitelist");
    if archetype == "deserialization" {
        // 反序列化：autoTypeSupport / checkAutoType 是风险标记，不是守卫；
        // 只有真实输入过滤（ObjectInputFilter/acceptList/denyList/allowTypes）才算杀伤。
        if body.contains("ObjectInputFilter")
            || body.contains("setObjectInputFilter")
            || body.contains("acceptList")
            || body.contains("denyList")
            || body.contains("allowTypes")
        {
            return Some("input_filter".to_string());
        }
    } else if declares_allowlist && allowlist_enforced(content, start, end) {
        return Some("allowlist_guard".to_string());
    }
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
            let has_normalize = body.contains(".normalize(")
                || body.contains("normalize(")
                || body.contains("getCanonicalPath")
                || body.contains("filepath.Clean");
            if has_normalize {
                if (body.contains("startsWith(")
                    || body.contains("secureJoin")
                    || body.contains(".resolve(")
                    || body.contains("getCanonicalPath("))
                    && path_order_issue(content, start, end).is_none()
                {
                    Some("path_normalized_with_prefix_check".to_string())
                } else {
                    // 仅词法规整，不足以阻断穿越：交给 guard_ineffective 档
                    None
                }
            } else {
                None
            }
        }
        "template" => {
            if body.contains("SimpleEvaluationContext")
                || body.contains("restricted_expression")
                || body.contains("SimpleEvaluationContext")
            {
                Some("restricted_expression_context".to_string())
            } else {
                None
            }
        }
        "xss" => {
            if body.contains("escapeHtml") || body.contains("autoescape") || body.contains("HtmlUtils") {
                Some("output_escaped".to_string())
            } else if body.contains("ALLOWED") || body.contains("allowlist") || body.contains("whitelist") {
                Some("allowlist_guard".to_string())
            } else {
                None
            }
        }
        "ssrf" => {
            if body.contains("ALLOWED") || body.contains("allowlist") || body.contains("whitelist") {
                Some("host_allowlist".to_string())
            } else if body.contains(".getHost(") || body.contains("isAllowedHost") {
                Some("host_check".to_string())
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
    let files = super::file_cache::project_files(project);
    let contents: BTreeMap<&str, &str> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    let path: Vec<Value> = reach["path"].as_array().cloned().unwrap_or_default();
    let mut steps: Vec<Value> = Vec::new();
    let mut killed: Option<Value> = None;
    let mut state: Vec<String> = vec!["raw".to_string()];
    // 入口参数与污点变量（参数 + assign 链）：无外部入参 → 载荷无从进入（taint_lost）
    let entry_flow = ssa::param_flow_report(project, entry_file, entry_line).ok();
    let entry_params: Vec<String> = entry_flow
        .as_ref()
        .and_then(|f| f["params"].as_array().cloned())
        .map(|v| v.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let entry_taint_vars: Vec<String> = entry_flow
        .as_ref()
        .and_then(|f| f["taints"].as_array().cloned())
        .map(|v| {
            v.iter()
                .filter_map(|t| t["name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut taint_lost_at: Option<Value> = None;
    let mut tainted_params: Vec<String> = Vec::new();
    let mut mapping_gaps: Vec<Value> = Vec::new();
    let mut context_notes: Vec<Value> = Vec::new();
    let mut same_function_step: Option<Value> = None;
    let mut ineffective_guards: Vec<String> = Vec::new();
    if entry_params.is_empty() {
        taint_lost_at = Some(json!({"hop": 0, "reason": "entry_has_no_params"}));
    }

    for i in 0..path.len().saturating_sub(1) {
        let caller_file = path[i]["file"].as_str().unwrap_or("");
        let caller_line = path[i]["line"].as_u64().unwrap_or(0) as u32;
        let caller_sym = path[i]["symbol"].as_str().unwrap_or("");
        let callee_sym = path[i + 1]["symbol"].as_str().unwrap_or("");
        let Some(content) = contents.get(caller_file) else { continue };
        let def_end = precise_def_end(content, caller_file, caller_line);
        let guards = chain::guards_range(content, caller_line, def_end, caller_file);
        let guard_kind: Vec<String> = guards
            .iter()
            .filter_map(|g| g.get("kind").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();
        let mut ineffective_here: Vec<String> = Vec::new();
        let kill_guard = guards.iter().find(|g| {
            let kind = g.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if !guard_kills(arch).contains(&kind) {
                return false;
            }
            if arch == "traversal" && kind == "path_check" && !path_guard_effective(content, caller_line, def_end) {
                ineffective_here.push("path_check_lexical_only".to_string());
                return false;
            }
            if arch == "traversal"
                && kind == "allowlist"
                && (g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("startsWith(")
                    || g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("secureJoin"))
                && !path_guard_effective(content, caller_line, def_end)
            {
                ineffective_here.push("path_check_validate_before_normalize".to_string());
                return false;
            }
            if kind == "allowlist" && !allowlist_enforced(content, caller_line, def_end) {
                ineffective_here.push("allowlist_declaration_only".to_string());
                return false;
            }
            if kind == "allowlist"
                && (arch == "template" || arch == "command")
                && (g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("isAssignableFrom")
                    || g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("startsWith("))
            {
                ineffective_here.push("type_check_not_guard".to_string());
                return false;
            }
            if kind == "allowlist"
                && arch == "deserialization"
                && (g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("autoTypeSupport")
                    || g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("checkAutoType"))
                && !content.contains("ObjectInputFilter")
                && !content.contains("acceptList")
                && !content.contains("denyList")
            {
                ineffective_here.push("autotype_marker_not_guard".to_string());
                return false;
            }
            if kind == "sanitize" && !sanitize_effective(arch, content, caller_line, def_end) {
                ineffective_here.push("sanitize_generic".to_string());
                return false;
            }
            true
        });
        for g in &ineffective_here {
            if !ineffective_guards.contains(g) {
                ineffective_guards.push(g.clone());
            }
        }
        let flow = ssa::param_flow_report(project, caller_file, caller_line).ok();
        let mut tainted_args: Vec<Value> = Vec::new();
        let mut call_matched = false;
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
                        call_matched = true;
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
        let coercion = tainted_args.iter().find(|ta| {
            let e = ta["expr"].as_str().unwrap_or("");
            ["parseInt(", "Integer.valueOf(", "Long.parseLong(", "Double.parseDouble(", "(int)", "(long)"]
                .iter()
                .any(|t| e.contains(t))
        });
        if killed.is_none() {
            if let Some(c) = coercion {
                killed = Some(json!({
                    "hop": i,
                    "file": caller_file,
                    "def_line": caller_line,
                    "symbol": caller_sym,
                    "guard": {"kind": "numeric_coercion", "evidence": c["expr"]},
                    "kind": arch,
                }));
            }
        }
        let tainted_ok = !tainted_args.is_empty();
        if tainted_ok {
            state.push(format!("hop{i}:tainted"));
            let callee_file = path[i + 1]["file"].as_str().unwrap_or("");
            let callee_line = path[i + 1]["line"].as_u64().unwrap_or(0) as u32;
            if let Ok(cf) = ssa::param_flow_report(project, callee_file, callee_line) {
                let params: Vec<String> = cf["params"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_str().map(|x| x.to_string()))
                    .collect();
                for ta in tainted_args.iter() {
                    if let Some(pos) = ta["pos"].as_u64() {
                        if let Some(pname) = params.get(pos as usize) {
                            if !tainted_params.contains(pname) {
                                tainted_params.push(pname.clone());
                            }
                        }
                    }
                }
            }
        } else if taint_lost_at.is_none() {
            if call_matched && path.len() <= 3 {
                taint_lost_at = Some(json!({
                    "hop": i,
                    "file": caller_file,
                    "def_line": caller_line,
                    "reason": "tainted_args_not_bound_at_hop",
                }));
            } else {
                mapping_gaps.push(json!({
                    "hop": i,
                    "file": caller_file,
                    "def_line": caller_line,
                    "reason": if call_matched { "tainted_args_not_bound_long_chain" } else { "call_not_matched" },
                }));
            }
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

    // 同函数链（hops=0）：补一条同函数 step，携带 guards/tainted_args，避免"结构事实无守卫"的误导
    if steps.is_empty() {
        if let Some(content) = contents.get(entry_file) {
            let def_end = precise_def_end(content, entry_file, entry_line);
            let guards_all = chain::guards_range(content, entry_line, def_end, entry_file);
            let guard_kinds: Vec<String> = guards_all
                .iter()
                .filter_map(|g| g.get("kind").and_then(|v| v.as_str()).map(|x| x.to_string()))
                .collect();
            let mut same_args: Vec<Value> = Vec::new();
            if let Some(flow) = &entry_flow {
                if let Some(calls) = flow["calls"].as_array() {
                    for c in calls {
                        if c["line"].as_u64() == Some(sink_line as u64) {
                            if let Some(ta) = c["tainted_args"].as_array() {
                                same_args = ta.clone();
                            }
                        }
                    }
                }
            }
            same_function_step = Some(json!({
                "hop": 0,
                "same_function": true,
                "file": entry_file,
                "def_line": entry_line,
                "symbol": path.first().and_then(|v| v["symbol"].as_str()).unwrap_or(""),
                "next": path.first().and_then(|v| v["symbol"].as_str()).unwrap_or(""),
                "guards": guard_kinds,
                "tainted_args": same_args,
                "mutations": [],
                "state": state.clone(),
            }));
        }
    }

    // 同函数链（hops=0）：用调用方给的 sink 行检查是否引用入口参数
    if steps.is_empty() && taint_lost_at.is_none() {
        let sf = sink_file;
        let sl = sink_line;
        if let Some(content) = contents.get(sf) {
            let sink_text = content
                .lines()
                .nth(sl.saturating_sub(1) as usize)
                .unwrap_or("");
            let hit = entry_taint_vars.iter().any(|p| sink_text.contains(p.as_str()));
            if !hit {
                taint_lost_at = Some(json!({"hop": 0, "file": sf, "def_line": sl, "reason": "sink_args_do_not_reference_entry_params"}));
            }
        }
    }

    // 跨跳：最终 sink 所在函数体内必须引用被传递进来的污点参数名，否则 taint_lost
    if killed.is_none() && taint_lost_at.is_none() && !steps.is_empty() && !tainted_params.is_empty() {
        if let Some(content) = contents.get(sink_file) {
            let lang = chain::chain_language_of(sink_file);
            let defs = probe::definitions_multi(content, lang);
            let def_line = defs
                .iter()
                .filter(|(_, l)| *l <= sink_line)
                .map(|(_, l)| *l)
                .max()
                .unwrap_or(sink_line);
            let def_end = precise_def_end(content, sink_file, def_line);
            let body: String = content
                .lines()
                .skip(def_line.saturating_sub(1) as usize)
                .take((def_end.saturating_sub(def_line) + 1) as usize)
                .collect::<Vec<_>>()
                .join("\n");
            if !tainted_params.iter().any(|p| body.contains(p.as_str())) {
                taint_lost_at = Some(json!({
                    "hop": steps.len(),
                    "file": sink_file,
                    "def_line": sink_line,
                    "reason": "sink_args_do_not_reference_tainted_params",
                }));
            }
        }
    }

    // 同函数链：sink 实参若经过数值强制转换，字符串载荷无法存活
    if killed.is_none() {
        for st in steps.iter() {
            if let Some(args) = st["tainted_args"].as_array() {
                for a in args {
                    let expr = a["expr"].as_str().unwrap_or("");
                    if ["parseInt(", "Integer.valueOf(", "Long.parseLong(", "Double.parseDouble(", "(int)", "(long)"]
                        .iter()
                        .any(|t| expr.contains(t))
                    {
                        killed = Some(json!({
                            "hop": st["hop"].clone(),
                            "file": st["file"].clone(),
                            "def_line": st["def_line"].clone(),
                            "symbol": st["symbol"].clone(),
                            "guard": {"kind": "numeric_coercion", "evidence": expr},
                            "kind": arch,
                        }));
                        break;
                    }
                }
            }
            if killed.is_some() {
                break;
            }
        }
    }

    // 汇节点自身函数的守卫/杀伤标记
    if killed.is_none() {
        let sf = path.last().map(|v| v["file"].as_str().unwrap_or("")).unwrap_or(sink_file);
        let sl = path.last().map(|v| v["line"].as_u64().unwrap_or(sink_line as u64) as u32).unwrap_or(sink_line);
        if let Some(content) = contents.get(sf) {
            let def_end = precise_def_end(content, sf, sl);
            let guards = chain::guards_range(content, sl, def_end, sf);
            let kill_guard = guards.iter().find(|g| {
                let kind = g.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                if !guard_kills(arch).contains(&kind) {
                    return false;
                }
                if arch == "traversal" && kind == "path_check" && !path_guard_effective(content, sl, def_end) {
                    return false;
                }
                if arch == "traversal"
                    && kind == "allowlist"
                    && (g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("startsWith(")
                        || g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("secureJoin"))
                    && !path_guard_effective(content, sl, def_end)
                {
                    return false;
                }
                if kind == "allowlist" && !allowlist_enforced(content, sl, def_end) {
                    return false;
                }
                if kind == "allowlist"
                    && (arch == "template" || arch == "command")
                    && (g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("isAssignableFrom")
                        || g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("startsWith("))
                {
                    return false;
                }
                if kind == "allowlist"
                    && arch == "deserialization"
                    && (g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("autoTypeSupport")
                        || g.get("evidence").and_then(|v| v.as_str()).unwrap_or("").contains("checkAutoType"))
                    && !content.contains("ObjectInputFilter")
                    && !content.contains("acceptList")
                    && !content.contains("denyList")
                {
                    return false;
                }
                if kind == "sanitize" && !sanitize_effective(arch, content, sl, def_end) {
                    return false;
                }
                true
            });
            if let Some(g) = kill_guard {
                killed = Some(json!({"hop": steps.len(), "file": sf, "def_line": sl, "symbol": path.last().and_then(|v| v["symbol"].as_str()).unwrap_or(""), "guard": g, "kind": arch}));
            } else if let Some(bk) = body_kill(arch, content, sl, def_end) {
                killed = Some(json!({"hop": steps.len(), "file": sf, "def_line": sl, "symbol": path.last().and_then(|v| v["symbol"].as_str()).unwrap_or(""), "guard": {"kind": "body_token", "evidence": bk}, "kind": arch}));
            }
        }
    }

    if let Some(st) = same_function_step {
        steps.push(st);
    }

    for st in steps.iter() {
        for g in st["guards"].as_array().cloned().unwrap_or_default() {
            if let Some(name) = g.as_str() {
                if (name == "bounds" || name == "signature") && !ineffective_guards.contains(&name.to_string()) {
                    ineffective_guards.push(name.to_string());
                }
            }
        }
    }
    // B1 上下文矩阵：沿链条收集函数体（入口 + 每个 hop + 汇所在函数），
    // 用于 SQL 子句上下文、路径校验顺序与反序列化包装层证据。
    let mut bodies: Vec<String> = Vec::new();
    {
        let mut ranges: Vec<(String, u32)> = Vec::new();
        ranges.push((entry_file.to_string(), entry_line));
        for st in path.iter() {
            if let (Some(f), Some(l)) = (st["file"].as_str(), st["line"].as_u64()) {
                ranges.push((f.to_string(), l as u32));
            }
        }
        for st in steps.iter() {
            if let (Some(f), Some(l)) = (st["file"].as_str(), st["def_line"].as_u64()) {
                ranges.push((f.to_string(), l as u32));
            }
        }
        let mut seen: Vec<(String, u32)> = Vec::new();
        for (f, l) in ranges {
            if seen.contains(&(f.clone(), l)) {
                continue;
            }
            seen.push((f.clone(), l));
            if let Some(content) = contents.get(f.as_str()) {
                let end = precise_def_end(content, &f, l);
                let body: String = content
                    .lines()
                    .skip(l.saturating_sub(1) as usize)
                    .take((end.saturating_sub(l) + 1) as usize)
                    .collect::<Vec<_>>()
                    .join("\n");
                bodies.push(body);
            }
        }
    }
    let combined = bodies.join("\n");
    if arch == "sql_quote" {
        if let Some(clause) = sql_clause_context(&combined) {
            if let Some(k) = killed.clone() {
                let guard_kind = k["guard"]["kind"].as_str().unwrap_or("");
                let evidence = k["guard"]["evidence"].as_str().unwrap_or("");
                if guard_kind == "body_token" && evidence == "parameterized_query" {
                    context_notes.push(json!({"kind": "sql_clause", "clause": clause,
                        "note": "parameterized_query_does_not_cover_clause"}));
                    killed = None;
                }
            }
        }
    }
    if arch == "deserialization" {
        let wrappers = deserialization_wrappers(&combined, 1, combined.lines().count() as u32);
        if !wrappers.is_empty() {
            context_notes.push(json!({"kind": "deserialization_wrapper", "wrappers": wrappers}));
        }
    }
    if arch == "traversal" {
        if let Some(issue) = path_order_issue(&combined, 1, combined.lines().count() as u32) {
            context_notes.push(json!({"kind": "path_check_order", "issue": issue}));
        }
    }
    let (tier, viability) = if killed.is_some() {
        ("payload_killed", "killed")
    } else if taint_lost_at.is_some() {
        ("taint_lost", "taint_lost")
    } else if !ineffective_guards.is_empty() {
        ("guard_ineffective_token", "may_survive")
    } else {
        ("payload_may_survive", "may_survive")
    };

    Ok(json!({
        "schema": "payload-ant/v1",
        "archetype": arch,
        "reachable": true,
        "viability": viability,
        "tier": tier,
        "entry_params": entry_params,
        "taint_lost_at": taint_lost_at,
        "hops": steps.len(),
        "steps": steps,
        "killed_at": killed,
        "method": "deterministic_payload_state_machine_v1",
        "evidence_tiers": ["payload_killed", "guard_ineffective_token", "payload_may_survive", "payload_verified"],
        "mapping_gaps": mapping_gaps,
        "context": context_notes,
        "uncertainty": {
            "level": if mapping_gaps.is_empty() { "medium" } else { "high" },
            "reasons": if mapping_gaps.is_empty() {
                json!(["name_level_dataflow", "guard_kill_table_v1", "no_dynamic_verification"])
            } else {
                json!(["name_level_dataflow", "guard_kill_table_v1", "no_dynamic_verification", "hop_call_mapping_failed"])
            },
        },
    }))
}

fn precise_def_end(content: &str, file: &str, def_line: u32) -> u32 {
    let total = content.lines().count() as u32;
    let lang = chain::chain_language_of(file);
    let defs = probe::definitions_multi(content, lang);
    defs.iter()
        .filter(|(_, l)| *l > def_line)
        .map(|(_, l)| *l)
        .min()
        .map(|n| n.saturating_sub(1))
        .unwrap_or(total)
        .max(def_line)
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
    fn sql_clause_context_detection() {
        assert_eq!(sql_clause_context(r#"SELECT * FROM t ORDER BY " + q"#), Some("order_by"));
        assert_eq!(sql_clause_context(r#"SELECT * FROM t WHERE id IN (" + q + ")"#), Some("in_list"));
        assert_eq!(sql_clause_context(r#"SELECT * FROM t WHERE n LIKE '" + q + "'"#), Some("like"));
        assert_eq!(sql_clause_context("SELECT * FROM t WHERE n = ?"), None);
    }

    #[test]
    fn path_order_and_wrappers() {
        let body = "String raw = \"/data/\" + q;\nif (!raw.startsWith(\"/data/\")) throw new RuntimeException();\njava.nio.file.Path n = Paths.get(raw).normalize();\n";
        assert_eq!(path_order_issue(body, 1, 3), Some("validate_before_normalize"));
        let ok = "java.nio.file.Path n = Paths.get(q).normalize();\nif (!n.startsWith(\"/data/\")) throw new RuntimeException();\n";
        assert_eq!(path_order_issue(ok, 1, 2), None);
        let w = "byte[] b = Base64.getDecoder().decode(in);\nreturn new ObjectInputStream(new ByteArrayInputStream(b)).readObject();\n";
        assert!(deserialization_wrappers(w, 1, 2).contains(&"base64"));
    }

    #[test]
    fn html_escape_does_not_kill_template_payload() {
        let dir = tmp("template-escape");
        write_tree(
            &dir,
            &[(
                "App.java",
                r#"
public class App {
    public Object render(String tpl) {
        String safe = escapeHtml(tpl);
        return parser.parseExpression(safe).getValue();
    }
}
"#,
            )],
        );
        let r = payload_viability_report(&dir, "App.java", 3, "App.java", 5, "template").unwrap();
        assert_ne!(r["tier"], "payload_killed", "HTML 转义不应杀死 SpEL 载荷: {r}");
    }

    #[test]
    fn declared_allowlist_without_check_does_not_kill() {
        let dir = tmp("allowlist-declared");
        write_tree(
            &dir,
            &[(
                "App.java",
                r#"
public class App {
    private static final java.util.Set<String> ALLOWED = java.util.Set.of("safe");
    public void query(String q) throws Exception {
        java.sql.Statement st = null;
        st.executeQuery("SELECT * FROM t WHERE name = '" + q + "'");
    }
}
"#,
            )],
        );
        let r = payload_viability_report(&dir, "App.java", 4, "App.java", 6, "sql").unwrap();
        assert_ne!(r["tier"], "payload_killed", "仅声明常量不应被当作有效 allowlist: {r}");
    }

    #[test]
    fn payload_survives_without_guard_and_dies_with_normalize() {
        let dir = tmp("path-unfixed");
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

        let dir2 = tmp("path-fixed");
        write_tree(
            &dir2,
            &[(
                "Fixed.java",
                r#"
public class Fixed {
    public String download(String name) {
        String p = normalize(name);
        if (!p.startsWith("/data/")) { throw new IllegalArgumentException(); }
        return read(p);
    }
    String read(String p) { return p; }
}
"#,
            )],
        );
        let killed = payload_viability_report(&dir2, "Fixed.java", 3, "Fixed.java", 6, "traversal").unwrap();
        assert_eq!(killed["viability"], "killed", "{killed}");
        assert_eq!(killed["tier"], "payload_killed");
    }
}
