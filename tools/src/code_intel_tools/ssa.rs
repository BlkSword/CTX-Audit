// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Phase 2：Java/通用函数内 mini-SSA（参数 def-use → 调用实参绑定）。
//!
//! 目标：不做编译器前端，只回答代审/载荷分析最常用的三件事：
//! 1. 入口参数在当前函数体内流到了哪些局部变量（assign 链）；
//! 2. 这些变量作为第几个实参传给了哪些被调函数（call 绑定）；
//! 3. 被调函数里有没有隐式汇（反射/属性访问/表达式/JNDI/反序列化）基因库命中。
//!
//! 输出带 provenance 与不确定性；名字级、不做类型/别名推断（显式标注）。

use super::chain;
use super::index;
use super::probe;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::path::Path;

/// 隐式汇 / 伪守卫基因库 v0（名字级；后续从 CVE diff 扩充并标注出处）。
pub(crate) fn implicit_sink_kind(name: &str) -> Option<&'static str> {
    const TABLE: &[(&str, &str)] = &[
        ("invoke", "reflection.invoke"),
        ("newInstance", "reflection.new_instance"),
        ("getProperty", "property_accessor"),
        ("getMethod", "reflection.get_method"),
        ("lookup", "jndi.lookup"),
        ("parseExpression", "expression.parsetree"),
        ("readObject", "deserialization.read_object"),
        ("loadClass", "class_loading"),
        ("forName", "class_loading"),
        ("getObject", "deserialization.read_object"),
    ];
    TABLE.iter().find(|(n, _)| name == *n).map(|(_, k)| *k)
}

struct SsaGraph {
    contents: BTreeMap<String, String>,
    defs: BTreeMap<String, Arc<Vec<(String, u32)>>>,
    calls: BTreeMap<String, Arc<Vec<(String, u32, bool)>>>,
    name_index: BTreeMap<String, Vec<(String, u32)>>,
}

impl SsaGraph {
    fn build(project: &Path) -> SsaGraph {
        let files = super::file_cache::project_files(project);
        let mut g = SsaGraph {
            contents: BTreeMap::new(),
            defs: BTreeMap::new(),
            calls: BTreeMap::new(),
            name_index: BTreeMap::new(),
        };
        for (path, content) in files.iter() {
            let parsed = super::file_cache::parsed_file(path, content);
            for (name, line) in parsed.defs.iter() {
                g.name_index
                    .entry(name.clone())
                    .or_default()
                    .push((path.clone(), *line));
            }
            g.defs.insert(path.clone(), parsed.defs.clone());
            g.calls.insert(path.clone(), parsed.calls.clone());
            g.contents.insert(path.clone(), content.clone());
        }
        g
    }

    fn enclosing(&self, file: &str, line: u32) -> Option<(String, u32)> {
        let defs = self.defs.get(file)?;
        defs.iter()
            .filter(|(_, l)| *l <= line)
            .max_by_key(|(_, l)| *l)
            .map(|(n, l)| (n.clone(), *l))
            .or_else(|| {
                defs.iter()
                    .min_by_key(|(_, l)| l.abs_diff(line))
                    .map(|(n, l)| (n.clone(), *l))
            })
    }

    fn def_end(&self, file: &str, def_line: u32) -> u32 {
        let total = self
            .contents
            .get(file)
            .map(|c| c.lines().count() as u32)
            .unwrap_or(def_line);
        self.defs
            .get(file)
            .and_then(|defs| {
                defs.iter()
                    .filter(|(_, l)| *l > def_line)
                    .map(|(_, l)| *l)
                    .min()
            })
            .map(|n| n.saturating_sub(1))
            .unwrap_or(total)
            .max(def_line)
    }
}

fn word_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let nb = needle.as_bytes();
    let mut i = 0;
    while i + nb.len() <= bytes.len() {
        if &bytes[i..i + nb.len()] == nb {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_ok = i + nb.len() == bytes.len() || !is_ident_byte(bytes[i + nb.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn last_ident(s: &str) -> String {
    let mut out: Vec<char> = Vec::new();
    for ch in s.trim().chars().rev() {
        if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            out.push(ch);
        } else if out.is_empty() {
            continue;
        } else {
            break;
        }
    }
    out.into_iter().rev().collect()
}

fn split_top_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' | '[' | '{' | '<' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' | '>' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// 参数列表（从签名里提取；跳过注解与泛型）。
fn signature_params(content: &str, def_line: u32, symbol: &str) -> Vec<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut sig = String::new();
    let mut depth = 0i32;
    let mut opened = false;
    for i in (def_line.saturating_sub(1) as usize)..lines.len().min(def_line as usize + 8) {
        let t = lines[i];
        sig.push_str(t);
        sig.push('\n');
        for ch in t.chars() {
            if ch == '(' {
                depth += 1;
                opened = true;
            } else if ch == ')' {
                depth -= 1;
            }
        }
        if opened && depth <= 0 {
            break;
        }
    }
    let chars: Vec<char> = sig.chars().collect();
    let sym_pos = sig.find(symbol).unwrap_or(0);
    let mut start = None;
    let mut end = None;
    let mut d = 0i32;
    for (i, ch) in chars.iter().enumerate().skip(sym_pos) {
        if *ch == '(' {
            if start.is_none() {
                start = Some(i);
            }
            d += 1;
        } else if *ch == ')' {
            d -= 1;
            if d == 0 && start.is_some() {
                end = Some(i);
                break;
            }
        }
    }
    let inner: String = match (start, end) {
        (Some(a), Some(b)) if b > a => chars[a + 1..b].iter().collect(),
        _ => String::new(),
    };
    let mut out = Vec::new();
    for part in split_top_commas(&inner) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let name = last_ident(p);
        if name.is_empty() {
            continue;
        }
        // 跳过纯注解/关键字样式
        if name == "final" || name == "this" || name == "super" {
            continue;
        }
        out.push(name);
    }
    out
}

/// 响应体重绑定（source switch）：污点链在这里断开。
///
/// 典型：`String body = execute.body()` / `String body = httpResponse.body()` /
/// `data = requests.get(url).content` —— 左值来自网络响应，不是入口参数。
/// 数值强制转换：字符串载荷被 parseInt/valueOf 等切断。
fn numeric_coercion(rhs: &str) -> bool {
    const TOKENS: [&str; 7] = [
        "parseInt(",
        "Integer.valueOf(",
        "Long.parseLong(",
        "Double.parseDouble(",
        "Float.parseFloat(",
        "(int)",
        "(long)",
    ];
    TOKENS.iter().any(|t| rhs.contains(t))
}

fn source_switch(rhs: &str) -> bool {
    const TOKENS: [&str; 8] = [
        ".body()",
        "execute()",
        "HttpResponse",
        "HttpUtil.create",
        "requests.get(",
        "requests.post(",
        "res.json(",
        ".content",
    ];
    TOKENS.iter().any(|t| rhs.contains(t))
}

/// 简单赋值拆分（单 `=`，排除 `==`/`=>`/`<=`/`>=`/`!=`）。
fn split_assignment(line: &str) -> Option<(String, String)> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            let prev = if i > 0 { bytes[i - 1] } else { b' ' };
            let next = if i + 1 < bytes.len() { bytes[i + 1] } else { b' ' };
            if prev != b'=' && prev != b'!' && prev != b'<' && prev != b'>' && next != b'=' && next != b'>' {
                let lhs = &line[..i];
                let rhs = &line[i + 1..];
                let name = last_ident(lhs);
                if !name.is_empty() {
                    return Some((name, rhs.to_string()));
                }
                return None;
            }
        }
        i += 1;
    }
    None
}

/// 取 `name(` 的参数原文。
fn call_args(line: &str, name: &str) -> Option<String> {
    let pos = line.find(&format!("{name}("))? + name.len();
    let rest = &line[pos..];
    let mut d = 0i32;
    let mut end = None;
    for (i, ch) in rest.char_indices() {
        if ch == '(' {
            d += 1;
        } else if ch == ')' {
            d -= 1;
            if d == 0 {
                end = Some(i);
                break;
            }
        }
    }
    let e = end?;
    Some(rest[1..e].to_string())
}

/// 函数内参数 def-use 报告（mini-SSA v0）。
pub fn param_flow_report(project: &Path, file: &str, line: u32) -> Result<Value, String> {
    let g = SsaGraph::build(project);
    flow_of(&g, file, line)
}

/// 在已构建的图上计算单函数参数流（供批量摘要复用）。
fn flow_of(g: &SsaGraph, file: &str, line: u32) -> Result<Value, String> {
    let Some((symbol, def_line)) = g.enclosing(file, line) else {
        return Err(format!("{file}:{line} 不在任何函数定义内"));
    };
    let Some(content) = g.contents.get(file) else {
        return Err(format!("文件不在索引中: {file}"));
    };
    let lines: Vec<&str> = content.lines().collect();
    let end = g.def_end(file, def_line);
    let params = signature_params(content, def_line, &symbol);
    let calls = g.calls.get(file).cloned().unwrap_or_default();

    let mut taint: BTreeMap<String, String> = params
        .iter()
        .map(|p| (p.clone(), format!("param:{p}")))
        .collect();
    let mut assignments: Vec<Value> = Vec::new();

    // 单调 in-order 迭代（最多 8 轮直到稳定）
    for _ in 0..8 {
        let mut changed = false;
        for i in def_line as usize..=(end as usize).min(lines.len()) {
            if i == 0 || i > lines.len() {
                continue;
            }
            let raw = lines[i - 1];
            if let Some((lhs, rhs)) = split_assignment(raw) {
                if taint.contains_key(&lhs) {
                    continue;
                }
                if let Some(src) = taint.keys().find(|t| word_contains(&rhs, t)).cloned() {
                    if source_switch(&rhs) {
                        // 响应体重绑定：记录断点，但不传播污点
                        assignments.push(json!({
                            "name": lhs,
                            "from": src,
                            "line": i,
                            "taint_broken": "source_switch",
                        }));
                        continue;
                    }
                    if numeric_coercion(&rhs) {
                        // 数值强制转换：字符串载荷在此切断
                        assignments.push(json!({
                            "name": lhs,
                            "from": src,
                            "line": i,
                            "taint_broken": "numeric_coercion",
                        }));
                        continue;
                    }
                    assignments.push(json!({
                        "name": lhs,
                        "from": src,
                        "line": i,
                    }));
                    taint.insert(lhs, format!("assign:{i}"));
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    // 调用点绑定：函数体内每一条 call，检查实参是否携带污点
    let mut call_hits: Vec<Value> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for i in def_line as usize..=(end as usize).min(lines.len()) {
        if i == 0 || i > lines.len() {
            continue;
        }
        let raw = lines[i - 1];
        for (name, cline, member) in calls.iter() {
            if *cline != i as u32 {
                continue;
            }
            let Some(args_text) = call_args(raw, name) else { continue };
            let args = split_top_commas(&args_text);
            let mut hits: Vec<Value> = Vec::new();
            for (pos, arg) in args.iter().enumerate() {
                for (t, via) in taint.iter() {
                    if word_contains(arg, t) {
                        hits.push(json!({"pos": pos, "expr": arg.trim(), "var": t, "via": via}));
                        break;
                    }
                }
            }
            if hits.is_empty() {
                continue;
            }
            let key = format!("{name}:{i}");
            if !seen.insert(key) {
                continue;
            }
            let candidates: Vec<Value> = g
                .name_index
                .get(name)
                .map(|v| v.iter().take(5).map(|(f, l)| json!({"file": f, "line": l})).collect())
                .unwrap_or_default();
            call_hits.push(json!({
                "callee": name,
                "line": i,
                "member": member,
                "tainted_args": hits,
                "candidates": candidates,
                "implicit_sink": implicit_sink_kind(name),
            }));
        }
    }

    Ok(json!({
        "schema": "param-flow/v1",
        "file": file,
        "line": line,
        "symbol": symbol,
        "def_line": def_line,
        "body_range": [def_line, end],
        "params": params,
        "taints": taint.iter().map(|(k, v)| json!({"name": k, "via": v})).collect::<Vec<_>>(),
        "assignments": assignments,
        "calls": call_hits,
        "method": "intra_procedural_mini_ssa_v0",
        "uncertainty": {
            "level": "medium",
            "reasons": ["name_level_dataflow", "no_type_or_alias_resolution"],
        },
    }))
}

/// 函数级轻量摘要：参数 → 调用实参的污点转移、断污点、守卫（KilledBy）、return 是否带污点。
fn summary_from_flow(g: &SsaGraph, flow: &Value) -> Value {
    let file = flow["file"].as_str().unwrap_or("");
    let symbol = flow["symbol"].as_str().unwrap_or("");
    let def_line = flow["def_line"].as_u64().unwrap_or(0) as u32;
    let end = g.def_end(file, def_line);
    let content = g.contents.get(file).map(|s| s.as_str()).unwrap_or("");
    let mut transfers: Vec<Value> = Vec::new();
    if let Some(calls) = flow["calls"].as_array() {
        for c in calls.iter().take(12) {
            let tainted: Vec<Value> = c["tainted_args"]
                .as_array()
                .map(|a| a.iter().take(4).cloned().collect())
                .unwrap_or_default();
            let candidates: Vec<Value> = c["candidates"]
                .as_array()
                .map(|a| a.iter().take(2).cloned().collect())
                .unwrap_or_default();
            transfers.push(json!({
                "callee": c["callee"].clone(),
                "line": c["line"].clone(),
                "implicit_sink": c["implicit_sink"].clone(),
                "tainted_args": tainted,
                "candidates": candidates,
            }));
        }
    }
    let mut broken: Vec<Value> = Vec::new();
    if let Some(assigns) = flow["assignments"].as_array() {
        for a in assigns {
            if let Some(kind) = a.get("taint_broken").and_then(|v| v.as_str()) {
                broken.push(json!({
                    "name": a["name"].clone(),
                    "from": a["from"].clone(),
                    "line": a["line"].clone(),
                    "kind": kind,
                }));
            }
        }
    }
    let mut kills: Vec<Value> = Vec::new();
    let mut seen_kinds: Vec<String> = Vec::new();
    for gv in chain::guards_range(content, def_line, end, file) {
        let kind = gv.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if kind.is_empty() || seen_kinds.contains(&kind) {
            continue;
        }
        seen_kinds.push(kind.clone());
        kills.push(json!({
            "kind": kind,
            "line": gv.get("line").cloned().unwrap_or(Value::Null),
            "evidence": gv.get("evidence").cloned().unwrap_or(Value::Null),
        }));
        if kills.len() >= 6 {
            break;
        }
    }
    let tainted: Vec<String> = flow["taints"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let return_taint = content
        .lines()
        .skip(def_line.saturating_sub(1) as usize)
        .take((end.saturating_sub(def_line) + 1) as usize)
        .any(|l| {
            let t = l.trim_start();
            t.starts_with("return ")
                && tainted.iter().any(|name| !name.is_empty() && t.contains(name.as_str()))
        });
    json!({
        "schema": "func-summary/v1",
        "file": file,
        "line": def_line,
        "symbol": symbol,
        "params": flow["params"].clone(),
        "taint_transfers": transfers,
        "taint_broken": broken,
        "return_taint": return_taint,
        "killed_by": kills,
        "body_lines": end.saturating_sub(def_line) + 1,
        "uncertainty": {"level": "medium", "reasons": ["name_level_dataflow", "no_type_or_alias_resolution"]},
    })
}

/// 单函数摘要（独立构图）。
pub fn summary_report(project: &Path, file: &str, line: u32) -> Result<Value, String> {
    let g = SsaGraph::build(project);
    let flow = flow_of(&g, file, line)?;
    Ok(summary_from_flow(&g, &flow))
}

/// 批量函数摘要：一次构图，供链路追踪等场景复用。
pub fn summaries_for(project: &Path, targets: &[(String, u32)], cap: usize) -> Vec<Value> {
    let g = SsaGraph::build(project);
    let mut out: Vec<Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, u32)> = std::collections::BTreeSet::new();
    for (file, line) in targets.iter() {
        if out.len() >= cap.max(1) {
            break;
        }
        if !seen.insert((file.clone(), *line)) {
            continue;
        }
        if let Ok(flow) = flow_of(&g, file, *line) {
            out.push(summary_from_flow(&g, &flow));
        }
    }
    out
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
        let dir = std::env::temp_dir().join(format!("ctx-ssa-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn function_summary_reports_transfer_and_kill() {
        let dir = tmp("summary");
        write_tree(
            &dir,
            &[
                (
                    "A.java",
                    r#"
public class A {
    public void entry(String q) {
        B.run(q);
    }
}
"#,
                ),
                (
                    "B.java",
                    r#"
public class B {
    public static void run(String q) {
        String ALLOWED_SET = "x";
        if (!ALLOWED_SET.contains(q)) { throw new RuntimeException(); }
        Runtime.getRuntime().exec(q);
    }
}
"#,
                ),
            ],
        );
        let sums = summaries_for(&dir, &[("A.java".to_string(), 3)], 4);
        assert_eq!(sums.len(), 1, "{sums:?}");
        let tr = sums[0]["taint_transfers"].as_array().unwrap();
        assert!(tr.iter().any(|t| t["callee"] == "run"), "{sums:?}");
        let b = summary_report(&dir, "B.java", 3).unwrap();
        let kills = b["killed_by"].as_array().unwrap();
        assert!(kills.iter().any(|k| k["kind"] == "allowlist"), "{b:?}");
    }

    #[test]
    fn param_flows_into_call_and_implicit_sink() {
        let dir = tmp("java");
        write_tree(
            &dir,
            &[
                (
                    "Entry.java",
                    r#"
public class Entry {
    public void entry(String name) {
        String url = build(name);
        handler.invoke(url);
    }
    String build(String x) { return x; }
}
"#,
                ),
                (
                    "Handler.java",
                    r#"
public class Handler {
    public Object invoke(Object o) { return o; }
}
"#,
                ),
            ],
        );
        let r = param_flow_report(&dir, "Entry.java", 3).unwrap();
        assert_eq!(r["params"][0], "name");
        let assigns = r["assignments"].as_array().unwrap();
        assert!(assigns.iter().any(|a| a["name"] == "url" && a["from"] == "name"), "{assigns:?}");
        let calls = r["calls"].as_array().unwrap();
        assert!(
            calls.iter().any(|c| c["callee"] == "invoke" && c["implicit_sink"] == "reflection.invoke"),
            "{calls:?}"
        );
    }
}
