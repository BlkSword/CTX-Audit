// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 词汇派生与框架隐式入口。
//!
//! 解决 R258 暴露的两个"死"问题：
//! 1. 汇/入口词汇原本是手工加的（`module_access`、`decodeReply`）——现在可以从
//!    **安全修复 diff** 自动派生：修复新增的守卫行 → 它守的是什么表达式 → 提炼成汇模式；
//!    修复涉及文件里的导出函数 → 入口候选。
//! 2. 现代全栈框架的隐式控制流（Next.js `'use server'` Server Actions、`route.ts` handler）
//!    现在会被当作入口，而不是靠人工白名单。

use super::*;
use std::collections::{BTreeMap, BTreeSet};

/// 修复补丁里"守卫形态"的词汇（用于从 diff 反推被保护的汇）。
pub(crate) const GUARD_TOKENS: [&str; 18] = [
    "hasOwnProperty",
    "Object.hasOwn",
    "allowlist",
    "whitelist",
    "sanitize",
    "escape",
    "checkLogin",
    "isAuthenticated",
    "hasPermission",
    "hasRole",
    "Preconditions",
    "maxLength",
    "startsWith",
    "Pattern.compile",
    "verify",
    "validate",
    "encodeURI",
    "instanceof",
];

/// 从修复 diff 的**新增行**里提炼汇模式。
fn kind_for_expr(expr: &str) -> &'static str {
    let e = expr.to_ascii_lowercase();
    if e.contains("moduleexports") || e.contains("servermanifest") || e.contains("clientmanifest") {
        "module_access"
    } else if e.contains("exec") || e.contains("spawn") || e.contains("system(") || e.contains("processbuilder") {
        "exec"
    } else if e.contains("eval") || e.contains("function(") || e.contains("scriptengine") {
        "eval"
    } else if e.contains("json.parse")
        || e.contains("deserial")
        || e.contains("readobject")
        || e.contains("unserialize")
        || e.contains("decodereply")
    {
        "deserialize"
    } else if e.contains("forname") || e.contains("getdeclaredmethod") || e.contains("newinstance") {
        "reflect"
    } else if e.contains("writefile") || e.contains("files.write") || e.contains("fileoutputstream") {
        "file_write"
    } else if e.contains("query(") || e.contains("executequery") {
        "sql"
    } else if e.contains("fetch(") || e.contains("axios") || e.contains("requests.") {
        "ssrf"
    } else {
        "dynamic_index"
    }
}

/// 在一行里找"可疑取值表达式"：`容器[` 或危险调用。
fn sink_pattern_in(line: &str) -> Option<(String, &'static str)> {
    // 1) 动态下标：ident[...]
    let bytes = line.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b'[' || i == 0 {
            continue;
        }
        let head = &line[..i];
        let ident: String = head
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$' || *c == '.')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if ident.is_empty() || ident.starts_with('.') {
            continue;
        }
        let pattern = format!("{ident}[");
        if pattern.len() >= 6 {
            return Some((pattern.clone(), kind_for_expr(&pattern)));
        }
    }
    // 2) 危险调用名
    for name in [
        "execSync(", "execFile(", "spawnSync(", "child_process.exec", "Runtime.getRuntime",
        "eval(", "new Function(", "JSON.parse(", "readValue(", "parseObject(", "ObjectInputStream",
    ] {
        if line.contains(name) {
            return Some((name.to_string(), kind_for_expr(name)));
        }
    }
    None
}

/// 简化的行级 diff：返回 after 中"新增"的行（含行号）。
///
/// 大文件（行数乘积过大）退化为"不在 before 行集合里"的近似——慢一点也没有关系，
/// 因为只对**内容变化过的文件**调用。
fn added_lines(before: &str, after: &str) -> Vec<(u32, String)> {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    if a.len().saturating_mul(b.len()) > 6_000_000 {
        let set: BTreeSet<&str> = a.iter().copied().collect();
        return b
            .iter()
            .enumerate()
            .filter(|(_, l)| !set.contains(**l))
            .map(|(i, l)| ((i + 1) as u32, (*l).to_string()))
            .collect();
    }
    let n = a.len();
    let m = b.len();
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut out: Vec<(u32, String)> = Vec::new();
    while i < n && j < m {
        if a[i] == b[j] {
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            i += 1;
        } else {
            out.push(((j + 1) as u32, b[j].to_string()));
            j += 1;
        }
    }
    while j < m {
        out.push(((j + 1) as u32, b[j].to_string()));
        j += 1;
    }
    out
}

/// 导出函数名（JS/TS：export function / export const / export {}；Java：public 方法）。
fn exported_names(content: &str, lang: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let t = raw.trim();
        let ln = (idx + 1) as u32;
        match lang {
            "js" | "ts" => {
                if let Some(rest) = t.strip_prefix("export function ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    if !name.is_empty() {
                        out.push((name, ln));
                    }
                } else if let Some(rest) = t.strip_prefix("export async function ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    if !name.is_empty() {
                        out.push((name, ln));
                    }
                } else if t.starts_with("export {") {
                    // 支持单行与多行导出块（React 源码的 `export { ... }` 常跨多行）
                    let mut inner = t.trim_start_matches("export {").to_string();
                    let mut closed = inner.contains('}');
                    if !closed {
                        for next in content.lines().skip(idx + 1) {
                            inner.push_str(next.trim());
                            if next.contains('}') {
                                closed = true;
                                break;
                            }
                        }
                    }
                    let inner = inner.trim_end_matches('}').trim_end_matches(';');
                    for part in inner.split(',') {
                        let name = part.trim().split(" as ").last().unwrap_or("").trim();
                        let name: String = name
                            .chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                            .collect();
                        if !name.is_empty() {
                            out.push((name, ln));
                        }
                    }
                    let _ = closed;
                }
            }
            "java" => {
                if (t.starts_with("public ") || t.starts_with("protected "))
                    && t.contains('(')
                    && !t.contains('=')
                    && !t.starts_with("public class")
                    && !t.starts_with("public interface")
                {
                    if let Some(name) = ident_before_paren_pub(t) {
                        out.push((name, ln));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn ident_before_paren_pub(line: &str) -> Option<String> {
    let paren = line.find('(')?;
    let head = &line[..paren];
    let name: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Next.js 隐式入口：`'use server'` 模块里的导出函数 = Server Action；`route.(ts|js)` 导出 = Route Handler。
pub(crate) fn nextjs_entries(files: &[(String, String)]) -> Vec<Value> {
    let mut out = Vec::new();
    for (path, content) in files.iter().take(max_index_files()) {
        let lang = match path.rsplit('.').next().unwrap_or("") {
            "js" | "mjs" | "cjs" => "js",
            "ts" | "tsx" | "jsx" => "ts",
            _ => continue,
        };
        let is_route_handler = path.contains("/app/")
            && (path.ends_with("/route.ts")
                || path.ends_with("/route.js")
                || path.ends_with("/route.tsx")
                || path.ends_with("/route.jsx"));
        let head: String = content.lines().take(5).collect::<Vec<_>>().join("\n");
        let is_server_action = head.contains("'use server'")
            || head.contains("\"use server\"")
            || (path.contains("/app/") && content.contains("'use server'"));
        if !is_route_handler && !is_server_action {
            continue;
        }
        for (name, line) in exported_names(content, lang) {
            let (kind, method) = if is_route_handler {
                let upper = name.to_ascii_uppercase();
                const METHODS: [&str; 7] = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
                if !METHODS.contains(&upper.as_str()) {
                    continue;
                }
                ("route_handler", upper)
            } else {
                ("server_action", "POST".to_string())
            };
            out.push(json!({
                "file": path,
                "line": line,
                "method": method,
                "route": name,
                "entry_kind": kind,
            }));
        }
    }
    out
}

/// 文件级 import 图（JS/TS 相对模块 + Java 类名），用于给调用边定置信度。
pub(crate) fn import_graph(files: &[(String, String)]) -> BTreeMap<String, BTreeSet<String>> {
    let all: BTreeSet<String> = files.iter().map(|(p, _)| p.clone()).collect();
    let mut by_basename: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in all.iter() {
        if let Some(name) = p.rsplit('/').next() {
            by_basename.entry(name.to_string()).or_default().push(p.clone());
        }
    }
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (path, content) in files.iter() {
        let ext = path.rsplit('.').next().unwrap_or("");
        let mut targets: BTreeSet<String> = BTreeSet::new();
        if matches!(ext, "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx") {
            for line in content.lines() {
                let spec = if let Some(pos) = line.find("require(") {
                    let rest = line[pos + 8..].trim_start();
                    let q = rest.chars().next().unwrap_or(' ');
                    if q == '\'' || q == '"' {
                        rest[1..].split(q).next().map(|s| s.to_string())
                    } else {
                        None
                    }
                } else if line.trim_start().starts_with("import ") {
                    line.find(" from ").map(|pos| {
                        let rest = line[pos + 6..].trim();
                        let q = rest.chars().next().unwrap_or(' ');
                        rest[1..]
                            .split(q)
                            .next()
                            .unwrap_or("")
                            .to_string()
                    })
                } else {
                    None
                };
                if let Some(spec) = spec {
                    if let Some(target) = resolve_js_target(path, &spec, &all) {
                        targets.insert(target);
                    }
                }
            }
        } else if ext == "java" {
            for line in content.lines() {
                if let Some(rest) = line.trim().strip_prefix("import ") {
                    let cls = rest.trim_end_matches(';').rsplit('.').next().unwrap_or("");
                    if let Some(cands) = by_basename.get(&format!("{cls}.java")) {
                        for c in cands {
                            targets.insert(c.clone());
                        }
                    }
                }
            }
        }
        graph.insert(path.clone(), targets);
    }
    graph
}

fn resolve_js_target(from: &str, spec: &str, all: &BTreeSet<String>) -> Option<String> {
    if !spec.starts_with('.') {
        return None;
    }
    let dir = match from.rsplit_once('/') {
        Some((d, _)) => d,
        None => "",
    };
    let raw = if dir.is_empty() {
        spec.to_string()
    } else {
        format!("{dir}/{spec}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    let cands = [
        joined.clone(),
        format!("{joined}.js"),
        format!("{joined}.ts"),
        format!("{joined}.tsx"),
        format!("{joined}/index.js"),
        format!("{joined}/index.ts"),
    ];
    cands.into_iter().find(|c| all.contains(c))
}

/// 读取外部词表（`--vocab` / `CTX_AUDIT_CHAIN_VOCAB` / `.ctx-audit/chain-vocab.json`）。
pub(crate) fn load_vocab(root: &Path) -> Option<Value> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(p) = std::env::var("CTX_AUDIT_CHAIN_VOCAB") {
        candidates.push(std::path::PathBuf::from(p));
    }
    candidates.push(root.join(".ctx-audit/chain-vocab.json"));
    for p in candidates {
        if let Ok(s) = std::fs::read_to_string(&p) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                return Some(v);
            }
        }
    }
    None
}

/// 从 (漏洞版, 修复版) 两个目录自动派生词表。
pub fn learn_vocab(before_root: &Path, after_root: &Path) -> Result<Value, String> {
    let before = index::load_files(before_root);
    let after = index::load_files(after_root);
    let before_map: BTreeMap<String, String> = before.files.iter().cloned().collect();

    let mut sink_patterns: Vec<Value> = Vec::new();
    let mut entry_names: Vec<Value> = Vec::new();
    let mut changed_files: Vec<String> = Vec::new();
    let mut seen_sinks: BTreeSet<String> = BTreeSet::new();
    let mut seen_entries: BTreeSet<String> = BTreeSet::new();

    for (path, content) in after.files.iter() {
        let lang = match path.rsplit('.').next().unwrap_or("") {
            "js" | "mjs" | "cjs" => "js",
            "ts" | "tsx" | "jsx" => "ts",
            "java" => "java",
            "py" => "py",
            _ => continue,
        };
        let Some(old) = before_map.get(path) else { continue };
        if old == content {
            continue;
        }
        changed_files.push(path.clone());
        let lines: Vec<&str> = content.lines().collect();
        for (ln, added) in added_lines(old, content) {
            let is_guard = GUARD_TOKENS.iter().any(|g| added.contains(g));
            if !is_guard {
                continue;
            }
            // 守卫前后 ±10 行里找被保护的取值表达式
            let start = ln.saturating_sub(10) as usize;
            let end = ((ln + 10) as usize).min(lines.len());
            for i in start..end {
                let Some(line) = lines.get(i) else { continue };
                if let Some((pattern, kind)) = sink_pattern_in(line) {
                    if seen_sinks.insert(format!("{kind}|{pattern}")) {
                        sink_patterns.push(json!({
                            "kind": kind,
                            "pattern": pattern,
                            "evidence": {
                                "guard": added.trim().chars().take(120).collect::<String>(),
                                "guard_line": ln,
                                "sink_file": path,
                                "sink_line": (i + 1) as u32,
                            },
                            "derived_from": "fix_diff",
                        }));
                    }
                    break;
                }
            }
        }
        // 入口候选：修复涉及的导出函数
        for (name, ln) in exported_names(content, lang) {
            if seen_entries.insert(name.clone()) {
                entry_names.push(json!({
                    "name": name,
                    "file": path,
                    "line": ln,
                    "derived_from": "fix_diff_exports",
                }));
            }
        }
    }

    Ok(json!({
        "schema": "chain-vocab/v1",
        "source": {"before": before_root.to_string_lossy(), "after": after_root.to_string_lossy()},
        "changed_files": changed_files,
        "sink_patterns": sink_patterns,
        "entry_names": entry_names,
        "stats": {
            "changed_files": changed_files.len(),
            "sink_patterns": sink_patterns.len(),
            "entry_names": entry_names.len(),
        }
    }))
}
