// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! PR 安全漂移闸门（gate/v1）。
//!
//! 输入 base / head 两棵源码树，输出"本次改动是否引入安全漂移"的判决：
//! - `new_unauthenticated_route`：新增/变更后未被鉴权覆盖的 HTTP 入口；
//! - `auth_regression`：既有入口从"被覆盖"变成"未覆盖"；
//! - `auth_config_regression`：声明式鉴权配置回退（覆盖路径被删 / 排除路径新增）；
//! - `guard_removed`：同一入口的链上守卫从有到无；
//! - `dangerous_sink_added`：新增的危险汇（且能连到入口）。
//!
//! 闸门只做"漂移"判定，不做漏洞定性：它不宣称 base 是安全的，只断言
//! "这次改动让原本受保护的路径变得不受保护 / 新增了可达的危险汇"。

use super::chain::{auth_map, collect_entries};
use super::chain_scan;
use super::index;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const GATE_SCHEMA: &str = "gate/v1";
const SENSITIVE_KINDS: [&str; 10] = [
    "exec",
    "eval",
    "deserialize",
    "reflect",
    "module_access",
    "template",
    "sql",
    "file_write",
    "jndi",
    "ssrf",
];

fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[derive(Default, Clone, Serialize, Deserialize)]
struct AuthPatterns {
    include: BTreeSet<String>,
    exclude: BTreeSet<String>,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    file_hash: BTreeMap<String, u64>,
    routes: BTreeMap<String, Value>,
    route_guards: BTreeMap<String, BTreeSet<String>>,
    route_auth: BTreeMap<String, String>,
    sinks: BTreeSet<(String, String)>,
    shown_sinks: BTreeSet<(String, String)>,
    linked_sinks: BTreeSet<(String, String)>,
    indirect_sinks: BTreeSet<(String, String)>,
    auth_patterns: BTreeMap<String, AuthPatterns>,
    chain_count: usize,
    shown_count: usize,
}

fn load_snapshot(root: &Path) -> Result<Snapshot, String> {
    let loaded = index::load_files(root);
    let id = index::build_id(&loaded.files);
    let auth = auth_map(root, &loaded.files, &id);
    let entries = collect_entries(&loaded.files, &id);
    let (chains, _stats) =
        chain_scan::candidates(&loaded.files, &entries, &auth, None, None, None, true, 0);

    let mut routes: BTreeMap<String, Value> = BTreeMap::new();
    let mut route_guards: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut route_auth: BTreeMap<String, String> = BTreeMap::new();
    let mut sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut shown_sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut linked_sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut indirect_sinks: BTreeSet<(String, String)> = BTreeSet::new();

    for e in entries.iter() {
        let kind = e.get("entry_kind").and_then(|v| v.as_str()).unwrap_or("http");
        let route = e.get("route").and_then(|v| v.as_str()).unwrap_or("");
        if kind == "library_entry" || !route.starts_with('/') {
            continue;
        }
        let file = e.get("file").and_then(|v| v.as_str()).unwrap_or("");
        let line = e.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let handler_line = e
            .get("handler_line")
            .and_then(|v| v.as_u64())
            .unwrap_or(line as u64) as u32;
        let method = e
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("ANY")
            .to_string();
        let key = format!("{method} {route}");
        let label = auth
            .get(&(file.to_string(), line))
            .or_else(|| auth.get(&(file.to_string(), handler_line)))
            .cloned()
            .or_else(|| e.get("auth").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        route_auth.insert(key.clone(), label);
        routes.insert(
            key,
            json!({
                "file": file,
                "line": line,
                "handler_line": handler_line,
                "route": route,
                "method": method,
            }),
        );
    }

    for c in chains.iter() {
        let Some(entry) = c.get("entry") else { continue };
        if entry.is_null() {
            continue;
        }
        let route = entry.get("route").and_then(|v| v.as_str()).unwrap_or("");
        let method = entry.get("method").and_then(|v| v.as_str()).unwrap_or("ANY");
        if route.starts_with('/') {
            let key = format!("{method} {route}");
            let gset = route_guards.entry(key).or_default();
            if let Some(gs) = c.get("guards").and_then(|v| v.as_array()) {
                for g in gs {
                    if let Some(k) = g.get("kind").and_then(|v| v.as_str()) {
                        gset.insert(k.to_string());
                    }
                }
            }
        }
        if let Some(sink) = c.get("sink") {
            if let (Some(f), Some(k)) = (
                sink.get("file").and_then(|v| v.as_str()),
                sink.get("kind").and_then(|v| v.as_str()),
            ) {
                sinks.insert((f.to_string(), k.to_string()));
                linked_sinks.insert((f.to_string(), k.to_string()));
                let entry_auth = entry
                    .get("auth")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let gated = c.get("tier").and_then(|v| v.as_str()) == Some("shown")
                    && entry_auth != "not_applicable"
                    && !entry_auth.starts_with("covered");
                let steps = c.get("steps").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                if gated {
                    if steps <= 3 {
                        shown_sinks.insert((f.to_string(), k.to_string()));
                    } else {
                        // 服务层/切面里的新增汇：链较长，先记为 info，避免把框架切面误判为阻断
                        indirect_sinks.insert((f.to_string(), k.to_string()));
                    }
                }
            }
        }
    }

    let mut file_hash = BTreeMap::new();
    for (p, c) in loaded.files.iter() {
        file_hash.insert(p.clone(), fnv64(c));
    }
    let auth_patterns = extract_auth_patterns(&loaded.files);

    Ok(Snapshot {
        file_hash,
        routes,
        route_guards,
        route_auth,
        sinks,
        shown_sinks,
        linked_sinks,
        indirect_sinks,
        auth_patterns,
        chain_count: chains.len(),
        shown_count: chains
            .iter()
            .filter(|c| c.get("tier").and_then(|v| v.as_str()) == Some("shown"))
            .count(),
    })
}

fn string_literals(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\'' || b == b'`' {
            let quote = b;
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i <= bytes.len() {
                out.push(line[start..i.min(line.len())].to_string());
            }
        }
        i += 1;
    }
    out
}

fn extract_auth_patterns(files: &[(String, String)]) -> BTreeMap<String, AuthPatterns> {
    const INCLUDE: [&str; 6] = [
        "addpathpatterns",
        "addinclude",
        "sarouter.match",
        "requestmatchers",
        "antmatchers",
        "pathmatchers",
    ];
    const EXCLUDE: [&str; 3] = ["excludepathpatterns", "addexclude", "permitall"];
    let mut out: BTreeMap<String, AuthPatterns> = BTreeMap::new();
    for (path, content) in files.iter() {
        if !content.contains("addPathPatterns")
            && !content.contains("addInclude")
            && !content.contains("SaRouter")
            && !content.contains("permitAll")
            && !content.contains("requestMatchers")
            && !content.contains("antMatchers")
        {
            continue;
        }
        let mut ap = AuthPatterns::default();
        for raw in content.lines() {
            let t = raw.trim();
            if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
                continue;
            }
            let lower = t.to_ascii_lowercase();
            let is_inc = INCLUDE.iter().any(|k| lower.contains(k));
            let is_exc = EXCLUDE.iter().any(|k| lower.contains(k));
            if !is_inc && !is_exc {
                continue;
            }
            for lit in string_literals(t) {
                if !(lit.starts_with('/') || lit.contains("**") || lit.contains('/')) {
                    continue;
                }
                // 同一行可能同时出现 addPathPatterns 与 excludePathPatterns：
                // 按"字面量之前最近的关键字"归类。
                let pos = t.find(&lit).unwrap_or(0);
                let before = t[..pos].to_ascii_lowercase();
                let last_inc = INCLUDE
                    .iter()
                    .filter_map(|k| before.rfind(k).map(|i| (i, true)))
                    .max_by_key(|(i, _)| *i);
                let last_exc = EXCLUDE
                    .iter()
                    .filter_map(|k| before.rfind(k).map(|i| (i, false)))
                    .max_by_key(|(i, _)| *i);
                let is_exclude = match (last_inc, last_exc) {
                    (Some((i, _)), Some((j, _))) => j > i,
                    (None, Some(_)) => true,
                    _ => false,
                };
                if is_exclude {
                    ap.exclude.insert(lit);
                } else {
                    ap.include.insert(lit);
                }
            }
        }
        if !ap.include.is_empty() || !ap.exclude.is_empty() {
            out.insert(path.clone(), ap);
        }
    }
    out
}

fn is_covered(label: &str) -> bool {
    label.starts_with("covered") || label.starts_with("auth")
}

fn verdict(kind: &str, severity: &str, title: &str, evidence: String, extra: Value) -> Value {
    let mut v = json!({
        "kind": kind,
        "severity": severity,
        "title": title,
        "evidence": evidence,
    });
    if let (Some(obj), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in extra.iter() {
            obj.insert(k.clone(), val.clone());
        }
    }
    v
}

fn diff_fields(
    base: &Snapshot,
    head: &Snapshot,
    strict_sinks: bool,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<Value>,
) {
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    for (p, h) in head.file_hash.iter() {
        match base.file_hash.get(p) {
            None => added.push(p.clone()),
            Some(bh) if bh != h => modified.push(p.clone()),
            _ => {}
        }
    }
    for p in base.file_hash.keys() {
        if !head.file_hash.contains_key(p) {
            deleted.push(p.clone());
        }
    }
    added.sort();
    modified.sort();
    deleted.sort();

    let mut verdicts = Vec::new();

    // 1) 新增未鉴权入口 / 既有入口鉴权回退
    for (key, info) in head.routes.iter() {
        let label = head.route_auth.get(key).cloned().unwrap_or_default();
        if !base.routes.contains_key(key) {
            if is_covered(&label) {
                verdicts.push(verdict(
                    "new_route_covered",
                    "info",
                    "新增入口：已有全局鉴权覆盖",
                    format!("{} auth={}", key, label),
                    json!({"route": key, "entry": info, "auth": label}),
                ));
            } else {
                verdicts.push(verdict(
                    "new_unauthenticated_route",
                    "block",
                    "新增入口：未被鉴权覆盖",
                    format!("{} auth={}", key, label),
                    json!({"route": key, "entry": info, "auth": label}),
                ));
            }
        } else {
            let blabel = base.route_auth.get(key).cloned().unwrap_or_default();
            if is_covered(&blabel) && !is_covered(&label) {
                verdicts.push(verdict(
                    "auth_regression",
                    "block",
                    "既有入口：鉴权覆盖从有到无",
                    format!("{} {} -> {}", key, blabel, label),
                    json!({"route": key, "entry": info, "base_auth": blabel, "head_auth": label}),
                ));
            }
        }
    }

    // 2) 声明式鉴权配置回退
    for (file, hpat) in head.auth_patterns.iter() {
        let Some(bpat) = base.auth_patterns.get(file) else { continue };
        for removed in bpat.include.difference(&hpat.include) {
            verdicts.push(verdict(
                "auth_config_regression",
                "block",
                "鉴权配置：覆盖路径被删除",
                format!("{} 移除覆盖模式 {}", file, removed),
                json!({"file": file, "pattern": removed, "change": "removed_include"}),
            ));
        }
        for added in hpat.exclude.difference(&bpat.exclude) {
            verdicts.push(verdict(
                "auth_config_regression",
                "block",
                "鉴权配置：新增排除（放行）路径",
                format!("{} 新增排除模式 {}", file, added),
                json!({"file": file, "pattern": added, "change": "added_exclude"}),
            ));
        }
    }

    // 3) 守卫从有到无 / 新增守卫（info）
    for (key, hguards) in head.route_guards.iter() {
        let Some(bguards) = base.route_guards.get(key) else { continue };
        if !bguards.is_empty() && hguards.is_empty() {
            verdicts.push(verdict(
                "guard_removed",
                "block",
                "入口守卫从有到无",
                format!("{} base={:?} head=[]", key, bguards),
                json!({"route": key, "base_guards": bguards.iter().collect::<Vec<_>>()}),
            ));
        } else if bguards.is_empty() && !hguards.is_empty() {
            verdicts.push(verdict(
                "guard_added",
                "info",
                "入口新增守卫",
                format!("{} {:?}", key, hguards),
                json!({"route": key, "head_guards": hguards.iter().collect::<Vec<_>>()}),
            ));
        }
    }

    // 4) 新增危险汇：只有"新增且已 shown（入口可达 + 注入类可控）"才阻断；
    //    base 未出现、但仅 candidate 的新汇记为 info，避免把修复 PR 里的加固代码当阻断。
    let mut new_sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut new_unshown: BTreeSet<(String, String)> = BTreeSet::new();
    let candidate_sinks: &BTreeSet<(String, String)> = if strict_sinks {
        &head.linked_sinks
    } else {
        &head.shown_sinks
    };
    for (f, k) in head.sinks.iter() {
        if !base.sinks.contains(&(f.clone(), k.clone())) {
            if candidate_sinks.contains(&(f.clone(), k.clone())) {
                new_sinks.insert((f.clone(), k.clone()));
            } else {
                new_unshown.insert((f.clone(), k.clone()));
            }
        }
    }
    for (file, kind) in new_sinks.iter() {
        if SENSITIVE_KINDS.contains(&kind.as_str()) {
            verdicts.push(verdict(
                "dangerous_sink_added",
                "block",
                if strict_sinks { "新增危险汇（严格模式：任意可达入口）" } else { "新增危险汇（已连到未鉴权入口）" },
                format!("{}:{}", file, kind),
                json!({"sink_file": file, "sink_kind": kind}),
            ));
        }
    }
    for (file, kind) in new_unshown.iter() {
        if SENSITIVE_KINDS.contains(&kind.as_str()) {
            let long_chain = head.indirect_sinks.contains(&(file.clone(), kind.clone()));
            verdicts.push(verdict(
                "new_sink_candidate",
                "info",
                if long_chain { "新增危险汇（服务/切面层，链较长，未阻断）" } else { "新增危险汇（仅 candidate，未阻断）" },
                format!("{}:{}", file, kind),
                json!({"sink_file": file, "sink_kind": kind}),
            ));
        }
    }

    verdicts.sort_by(|a, b| {
        (a["severity"].as_str().unwrap_or(""), a["kind"].as_str().unwrap_or(""))
            .cmp(&(b["severity"].as_str().unwrap_or(""), b["kind"].as_str().unwrap_or("")))
    });
    (added, modified, deleted, verdicts)
}

/// 闸门选项：严格汇模式与豁免规则文件。
#[derive(Default, Clone, Debug)]
pub struct GateOptions {
    /// 受保护接口新增危险汇也阻断（默认只拦未鉴权入口 + shown 链）
    pub strict_sinks: bool,
    /// 豁免规则 JSON（也可放在 <head>/.ctx-audit/gate-allow.json 自动加载）
    pub allow_path: Option<std::path::PathBuf>,
    /// 快照缓存目录（CI 里对 base/head 分别缓存可把冷启动降到热启动）
    pub cache_dir: Option<std::path::PathBuf>,
    /// git tree sha（base, head）：提供后缓存 key 不再依赖读文件，热启动可跳过索引
    pub cache_keys: Option<(String, String)>,
    /// 轻量快照：只做路由/守卫/汇，不做反向可达 BFS（大仓库用，判决口径略保守）
    pub light: bool,
}

/// 轻量快照：路由/守卫/汇 + 鉴权模式，不做反向可达 BFS。
///
/// 判决口径：新增汇只有"落在路由 handler 同一函数内"才算已连到入口；
/// 服务/切面层的汇一律按 indirect 处理（info），与完整模式的长链规则一致。
fn load_snapshot_light(root: &Path) -> Result<Snapshot, String> {
    let loaded = super::index::load_files(root);
    let id = super::index::build_id(&loaded.files);
    let auth = super::chain::auth_map(root, &loaded.files, &id);
    let entries = super::chain::collect_entries(&loaded.files, &id);

    let content_of: BTreeMap<&str, &str> = loaded
        .files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();

    let mut routes: BTreeMap<String, Value> = BTreeMap::new();
    let mut route_guards: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut route_auth: BTreeMap<String, String> = BTreeMap::new();
    // file -> [(handler_line, key, auth)]
    let mut handlers_by_file: BTreeMap<String, Vec<(u32, String, String)>> = BTreeMap::new();

    for e in entries.iter() {
        let kind = e.get("entry_kind").and_then(|v| v.as_str()).unwrap_or("http");
        let route = e.get("route").and_then(|v| v.as_str()).unwrap_or("");
        if kind == "library_entry" || !route.starts_with('/') {
            continue;
        }
        let file = e.get("file").and_then(|v| v.as_str()).unwrap_or("");
        let line = e.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        // 轻量模式没有 entry_index，按 handler 名/first def after mapping 自行推导 handler_line
        let handler_line = {
            let defs: Vec<(String, u32)> = content_of
                .get(file)
                .map(|c| {
                    super::chain::definitions(c, super::chain::chain_language_of(file))
                })
                .unwrap_or_default();
            let by_name = e
                .get("handler")
                .and_then(|v| v.as_str())
                .and_then(|h| defs.iter().find(|(n, _)| n == h).map(|(_, l)| *l));
            by_name
                .or_else(|| defs.iter().filter(|(_, l)| *l >= line).map(|(_, l)| *l).min())
                .unwrap_or(line)
        };
        let method = e.get("method").and_then(|v| v.as_str()).unwrap_or("ANY").to_string();
        let key = format!("{method} {route}");
        let label = auth
            .get(&(file.to_string(), line))
            .or_else(|| auth.get(&(file.to_string(), handler_line)))
            .cloned()
            .or_else(|| e.get("auth").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        route_auth.insert(key.clone(), label.clone());
        routes.insert(
            key.clone(),
            json!({"file": file, "line": line, "handler_line": handler_line, "route": route, "method": method}),
        );
        handlers_by_file.entry(file.to_string()).or_default().push((
            handler_line,
            key.clone(),
            label,
        ));
        if let Some(content) = content_of.get(file) {
            let end_line = content_of
                .get(file)
                .map(|c| super::chain::definitions(c, super::chain::chain_language_of(file)))
                .unwrap_or_default()
                .iter()
                .filter(|(_, l)| *l > handler_line)
                .map(|(_, l)| *l)
                .min()
                .map(|n| n.saturating_sub(1))
                .unwrap_or(handler_line.saturating_add(120));
            let gs = super::chain::guards_range(
                content,
                line.min(handler_line),
                end_line.max(handler_line),
                file,
            );
            let set = route_guards.entry(key).or_default();
            for g in gs {
                if let Some(k) = g.get("kind").and_then(|v| v.as_str()) {
                    set.insert(k.to_string());
                }
            }
        }
    }

    // 汇扫描（无 BFS）：direct = 汇与路由 handler 在同一函数
    let sinks_all = super::chain::scan_sinks_with(&loaded.files, &[], true);
    let mut sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut shown_sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut linked_sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let mut indirect_sinks: BTreeSet<(String, String)> = BTreeSet::new();
    let defs_cache: std::sync::Mutex<BTreeMap<String, Vec<(String, u32)>>> =
        std::sync::Mutex::new(BTreeMap::new());
    for sw in sinks_all.iter() {
        let Some(file) = sw.get("file").and_then(|v| v.as_str()) else { continue };
        let kind = sw.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let line = sw.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        sinks.insert((file.to_string(), kind.to_string()));
        let def_line = {
            let mut cache = defs_cache.lock().unwrap();
            let defs = cache.entry(file.to_string()).or_insert_with(|| {
                content_of
                    .get(file)
                    .map(|c| super::chain::definitions(c, super::chain::chain_language_of(file)))
                    .unwrap_or_default()
            });
            defs.iter().filter(|(_, l)| *l <= line).map(|(_, l)| *l).max()
        };
        let direct = def_line
            .and_then(|dl| {
                handlers_by_file
                    .get(file)
                    .and_then(|hs| hs.iter().find(|(hl, _, _)| *hl == dl).cloned())
            });
        match direct {
            Some((_hl, key, label)) => {
                linked_sinks.insert((file.to_string(), kind.to_string()));
                let gated = label != "not_applicable" && !label.starts_with("covered");
                if gated {
                    shown_sinks.insert((file.to_string(), kind.to_string()));
                } else {
                    indirect_sinks.insert((file.to_string(), kind.to_string()));
                }
                let _ = key;
            }
            None => {
                indirect_sinks.insert((file.to_string(), kind.to_string()));
            }
        }
    }

    let mut file_hash = BTreeMap::new();
    for (p, c) in loaded.files.iter() {
        file_hash.insert(p.clone(), fnv64(c));
    }
    let auth_patterns = extract_auth_patterns(&loaded.files);
    let chain_count = 0usize;
    let shown_count = shown_sinks.len();
    Ok(Snapshot {
        file_hash,
        routes,
        route_guards,
        route_auth,
        sinks,
        shown_sinks,
        linked_sinks,
        indirect_sinks,
        auth_patterns,
        chain_count,
        shown_count,
    })
}

fn tree_key(file_hash: &BTreeMap<String, u64>) -> u64 {
    // 版本盐：快照结构/判定规则变化时让旧缓存失效
    let mut acc: u64 = fnv64("gate-snapshot-v3");
    let mut items: Vec<(&String, &u64)> = file_hash.iter().collect();
    items.sort();
    for (p, h) in items {
        acc ^= fnv64(p);
        acc = acc.wrapping_mul(0x100000001b3);
        acc ^= *h;
        acc = acc.wrapping_mul(0x100000001b3);
    }
    acc
}

fn load_snapshot_or_light(root: &Path, light: bool) -> Result<Snapshot, String> {
    if light {
        load_snapshot_light(root)
    } else {
        load_snapshot(root)
    }
}

fn load_snapshot_cached(
    root: &Path,
    cache_dir: Option<&Path>,
    explicit_key: Option<&str>,
    light: bool,
) -> Result<Snapshot, String> {
    let Some(dir) = cache_dir else { return load_snapshot_or_light(root, light) };
    // 有 git tree sha 时完全不用读文件即可判缓存；否则回退到"读文件 + 哈希"。
    let key = match explicit_key {
        Some(ns) => fnv64(if light { "gate-snapshot-light-v1" } else { "gate-snapshot-v3" }).wrapping_mul(0x100000001b3) ^ fnv64(ns),
        None => {
            let loaded = super::index::load_files(root);
            let mut file_hash: BTreeMap<String, u64> = BTreeMap::new();
            for (p, c) in loaded.files.iter() {
                file_hash.insert(p.clone(), fnv64(c));
            }
            tree_key(&file_hash)
        }
    };
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(format!("{:016x}.json", key));
    if path.exists() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(cached) = serde_json::from_str::<Snapshot>(&text) {
                return Ok(cached);
            }
        }
    }
    let snap = load_snapshot_or_light(root, light)?;
    if let Ok(text) = serde_json::to_string(&snap) {
        let _ = std::fs::write(&path, text);
    }
    Ok(snap)
}

fn load_waivers(head: &Path, allow: Option<&Path>) -> Vec<Value> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    if let Some(p) = allow {
        files.push(p.to_path_buf());
    }
    let auto = head.join(".ctx-audit").join("gate-allow.json");
    if auto.exists() && allow.map(|p| p != auto).unwrap_or(true) {
        files.push(auto);
    }
    let mut out = Vec::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        match v {
            Value::Array(items) => out.extend(items),
            Value::Object(obj) => {
                if let Some(items) = obj.get("rules").and_then(|v| v.as_array()) {
                    out.extend(items.clone());
                }
            }
            _ => {}
        }
    }
    out
}

fn waived(v: &Value, waivers: &[Value]) -> Option<String> {
    for w in waivers {
        let kind_ok = w.get("kind").and_then(|x| x.as_str()).map(|k| v["kind"].as_str() == Some(k)).unwrap_or(true);
        let route_ok = w
            .get("route")
            .and_then(|x| x.as_str())
            .map(|r| v["evidence"].as_str().unwrap_or("").contains(r) || v["route"].as_str() == Some(r))
            .unwrap_or(true);
        let file_ok = w
            .get("file")
            .and_then(|x| x.as_str())
            .map(|f| {
                v["evidence"].as_str().unwrap_or("").contains(f)
                    || v["sink_file"].as_str() == Some(f)
                    || v["file"].as_str() == Some(f)
            })
            .unwrap_or(true);
        if kind_ok && route_ok && file_ok {
            return Some(
                w.get("reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or("waived by gate-allow")
                    .to_string(),
            );
        }
    }
    None
}

/// PR 漂移闸门：对比 base/head 两棵源码树（默认选项）。
pub fn gate_report(base: &Path, head: &Path) -> Result<Value, String> {
    gate_report_with_options(base, head, &GateOptions::default())
}

/// PR 漂移闸门（带选项）。
pub fn gate_report_with_options(
    base: &Path,
    head: &Path,
    opts: &GateOptions,
) -> Result<Value, String> {
    let t0 = std::time::Instant::now();
    // 双树并行扫描：两棵树互不依赖，用 thread scope 同时构建快照（可选快照缓存）。
    let cache = opts.cache_dir.as_deref();
    let opts_light = opts.light;
    let (bkey, hkey) = opts
        .cache_keys
        .as_ref()
        .map(|(b, h)| (Some(b.as_str()), Some(h.as_str())))
        .unwrap_or((None, None));
    let (bsnap, hsnap) = std::thread::scope(|scope| {
        let h = scope.spawn(|| load_snapshot_cached(head, cache, hkey, opts_light));
        let b = load_snapshot_cached(base, cache, bkey, opts_light);
        (b, h.join().unwrap())
    });
    let bsnap = bsnap?;
    let hsnap = hsnap?;
    let (added, modified, deleted, mut verdicts) =
        diff_fields(&bsnap, &hsnap, opts.strict_sinks);
    let waivers = load_waivers(head, opts.allow_path.as_deref());
    let mut waived_count = 0usize;
    for v in verdicts.iter_mut() {
        if let Some(reason) = waived(v, &waivers) {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("waived".to_string(), json!(true));
                obj.insert("waive_reason".to_string(), json!(reason));
                if obj.get("severity").and_then(|s| s.as_str()) == Some("block") {
                    obj.insert("severity".to_string(), json!("waived"));
                    waived_count += 1;
                }
            }
        }
    }
    let blocks = verdicts
        .iter()
        .filter(|v| v["severity"].as_str() == Some("block"))
        .count();
    let _ = waived_count;
    let warns = verdicts
        .iter()
        .filter(|v| v["severity"].as_str() == Some("warn"))
        .count();
    let infos = verdicts
        .iter()
        .filter(|v| v["severity"].as_str() == Some("info"))
        .count();
    let duration_ms = t0.elapsed().as_millis() as u64;
    Ok(json!({
        "schema": GATE_SCHEMA,
        "base": {
            "files": bsnap.file_hash.len(),
            "routes": bsnap.routes.len(),
            "chains": bsnap.chain_count,
            "chains_shown": bsnap.shown_count,
        },
        "head": {
            "files": hsnap.file_hash.len(),
            "routes": hsnap.routes.len(),
            "chains": hsnap.chain_count,
            "chains_shown": hsnap.shown_count,
        },
        "changed_files": {
            "added": added,
            "modified": modified,
            "deleted": deleted,
        },
        "summary": {
            "blocks": blocks,
            "warns": warns,
            "infos": infos,
            "waived": verdicts
                .iter()
                .filter(|v| v["severity"].as_str() == Some("waived"))
                .count(),
            "strict_sinks": opts.strict_sinks,
            "light": opts.light,
            "cache_dir": opts.cache_dir.as_ref().map(|p| p.display().to_string()),
            "exit_code": if blocks > 0 { 2 } else { 0 },
        },
        "verdicts": verdicts,
        "duration_ms": duration_ms,
    }))
}

/// 把 gate 报告渲染成 PR 评论用的 Markdown。
pub fn gate_markdown(report: &Value) -> String {
    let blocks = report["summary"]["blocks"].as_u64().unwrap_or(0);
    let warns = report["summary"]["warns"].as_u64().unwrap_or(0);
    let infos = report["summary"]["infos"].as_u64().unwrap_or(0);
    let mut out = String::new();
    out.push_str(if blocks > 0 {
        "## ❌ CTX-Audit PR 安全漂移闸门：拦截\n\n"
    } else {
        "## ✅ CTX-Audit PR 安全漂移闸门：通过\n\n"
    });
    out.push_str(&format!(
        "block={} warn={} info={} ｜ 变更文件 {}/{}/{}（新增/修改/删除）\n\n",
        blocks,
        warns,
        infos,
        report["changed_files"]["added"].as_array().map(|a| a.len()).unwrap_or(0),
        report["changed_files"]["modified"].as_array().map(|a| a.len()).unwrap_or(0),
        report["changed_files"]["deleted"].as_array().map(|a| a.len()).unwrap_or(0),
    ));
    if let Some(verdicts) = report["verdicts"].as_array() {
        if verdicts.is_empty() {
            out.push_str("本次改动未发现安全漂移。\n");
            return out;
        }
        // 三行化：先给"判决 / 原因 / 证据"，细节表折叠在后
        out.push_str("### 阻断判决\n\n");
        for v in verdicts.iter().filter(|v| v["severity"].as_str() == Some("block")) {
            out.push_str(&format!(
                "- ❌ **BLOCK** `{}` — {}\n  - 原因：{}\n  - 证据：{}\n",
                v["kind"].as_str().unwrap_or(""),
                v["evidence"].as_str().unwrap_or("").replace('|', "\\|"),
                v["title"].as_str().unwrap_or(""),
                v["evidence"].as_str().unwrap_or("").replace('|', "\\|"),
            ));
        }
        out.push_str("\n### 明细\n\n");
        out.push_str("| 严重度 | 类型 | 证据 |\n|---|---|---|\n");
        for v in verdicts {
            let sev = match v["severity"].as_str().unwrap_or("info") {
                "block" => "❌ block",
                "warn" => "⚠️ warn",
                _ => "ℹ️ info",
            };
            out.push_str(&format!(
                "| {} | `{}` | {} |\n",
                sev,
                v["kind"].as_str().unwrap_or(""),
                v["evidence"].as_str().unwrap_or("").replace('|', "\\|")
            ));
        }
    }
    out
}

/// 从一次 gate 报告生成 `gate-allow.json` 草稿。
///
/// 安全边界：只对"新增未鉴权入口"生成候选；鉴权回退、配置回退、守卫删除
/// 必须人工判断，只记录到 `skipped` 统计里。
pub fn suggest_waivers(report: &Value) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut skipped: std::collections::BTreeMap<String, usize> = Default::default();
    if let Some(vs) = report.get("verdicts").and_then(|v| v.as_array()) {
        for v in vs {
            if v.get("severity").and_then(|x| x.as_str()) != Some("block") {
                continue;
            }
            let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
            if kind != "new_unauthenticated_route" {
                *skipped.entry(kind.to_string()).or_default() += 1;
                continue;
            }
            let route = v
                .get("route")
                .and_then(|x| x.as_str())
                .or_else(|| v.get("evidence").and_then(|x| x.as_str()))
                .unwrap_or("")
                .trim()
                .to_string();
            if route.is_empty() || rules.iter().any(|r| r["route"].as_str() == Some(route.as_str())) {
                continue;
            }
            rules.push(json!({
                "kind": kind,
                "route": route,
                "reason": "<填理由：为何该路由设计上公开>",
                "owner": "",
                "expires": "",
                "evidence": v.get("evidence").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    rules.sort_by(|a, b| {
        a["route"]
            .as_str()
            .unwrap_or("")
            .cmp(b["route"].as_str().unwrap_or(""))
    });
    json!({
        "schema": "gate-allow/v1",
        "source": "gate_observe",
        "rules": rules,
        "skipped": skipped,
        "note": "仅路由级新入口可自动建议；鉴权回退/配置回退/守卫删除必须人工判断",
    })
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
        let dir = std::env::temp_dir().join(format!("ctx-gate-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detects_new_unauthenticated_route() {
        let base = tmp("base");
        let head = tmp("head");
        let common = r#"
@RestController
public class A {
    @GetMapping("/ok")
    public String ok() { return "ok"; }
}
"#;
        write_tree(&base, &[("src/A.java", common)]);
        write_tree(
            &head,
            &[
                ("src/A.java", common),
                (
                    "src/B.java",
                    r#"
@RestController
public class B {
    @GetMapping("/anon/new")
    public String run(String cmd) throws Exception {
        return Runtime.getRuntime().exec(cmd).toString();
    }
}
"#,
                ),
            ],
        );
        let r = gate_report(&base, &head).unwrap();
        let kinds: Vec<&str> = r["verdicts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["kind"].as_str().unwrap_or(""))
            .collect();
        assert!(kinds.contains(&"new_unauthenticated_route"), "kinds={kinds:?}");
        assert!(kinds.contains(&"dangerous_sink_added"), "kinds={kinds:?}");
        assert_eq!(r["summary"]["exit_code"], 2);
    }

    #[test]
    fn strict_sinks_blocks_covered_route_sink() {
        let base = tmp("base3");
        let head = tmp("head3");
        let cfg = r#"
@Configuration
public class SaTokenConfigure implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new SaInterceptor(handle -> {
            SaRouter.match("/admin/**", () -> {
                StpUtil.checkLogin();
                StpUtil.checkRole("admin");
            });
        })).addPathPatterns("/**").excludePathPatterns("/admin");
    }
}
"#;
        let ctrl = r#"
@RestController
@RequestMapping("/admin")
public class AdminController {
    @GetMapping("/run")
    public String run(String cmd) { return "ok"; }
}
"#;
        let head_ctrl = ctrl.replace(
            "public String run(String cmd) { return \"ok\"; }",
            "public String run(String cmd) throws Exception { return Runtime.getRuntime().exec(cmd).toString(); }",
        );
        write_tree(&base, &[("src/SaTokenConfigure.java", cfg), ("src/AdminController.java", ctrl)]);
        write_tree(&head, &[("src/SaTokenConfigure.java", cfg), ("src/AdminController.java", &head_ctrl)]);
        let default = gate_report(&base, &head).unwrap();
        assert_eq!(default["summary"]["blocks"], 0, "covered route should not block by default");
        let strict = gate_report_with_options(
            &base,
            &head,
            &GateOptions { strict_sinks: true, allow_path: None, cache_dir: None, cache_keys: None, light: false },
        )
        .unwrap();
        let kinds: Vec<&str> = strict["verdicts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["kind"].as_str().unwrap_or(""))
            .collect();
        assert!(kinds.contains(&"dangerous_sink_added"), "kinds={kinds:?}");
    }

    #[test]
    fn suggest_waivers_only_route_level() {
        let report = json!({"verdicts": [
            {"severity": "block", "kind": "new_unauthenticated_route", "route": "GET /api/share/list", "evidence": "GET /api/share/list auth=no_global_match_found"},
            {"severity": "block", "kind": "auth_regression", "route": "POST /admin", "evidence": "POST /admin"},
            {"severity": "block", "kind": "new_unauthenticated_route", "route": "GET /api/share/list", "evidence": "dup"},
            {"severity": "info", "kind": "new_route_covered", "route": "GET /ok"}
        ]});
        let draft = suggest_waivers(&report);
        let rules = draft["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1, "{draft}");
        assert_eq!(rules[0]["route"], "GET /api/share/list");
        assert_eq!(draft["skipped"]["auth_regression"], 1);
    }

    #[test]
    fn waivers_downgrade_block() {
        let base = tmp("base4");
        let head = tmp("head4");
        let f = r#"
@RestController
public class A {
    @GetMapping("/ok")
    public String ok() { return "ok"; }
}
"#;
        write_tree(&base, &[("src/A.java", f)]);
        write_tree(
            &head,
            &[
                ("src/A.java", f),
                (
                    "src/B.java",
                    r#"
@RestController
public class B {
    @GetMapping("/anon/new")
    public String run() { return "ok"; }
}
"#,
                ),
            ],
        );
        let allow = head.join("allow.json");
        std::fs::write(
            &allow,
            r#"{"rules":[{"kind":"new_unauthenticated_route","route":"/anon/new","reason":"public by design"}]}"#,
        )
        .unwrap();
        let r = gate_report_with_options(
            &base,
            &head,
            &GateOptions { strict_sinks: false, allow_path: Some(allow), cache_dir: None, cache_keys: None, light: false },
        )
        .unwrap();
        assert_eq!(r["summary"]["blocks"], 0);
        assert_eq!(r["summary"]["waived"], 1);
        assert_eq!(r["summary"]["exit_code"], 0);
    }

    #[test]
    fn clean_refactor_passes() {
        let base = tmp("base2");
        let head = tmp("head2");
        let f1 = r#"
@RestController
public class A {
    @GetMapping("/ok")
    public String ok() { String x = "ok"; return x; }
}
"#;
        let f2 = f1.replace("String x = \"ok\"; return x;", "String y = \"ok\"; return y;");
        write_tree(&base, &[("src/A.java", f1)]);
        write_tree(&head, &[("src/A.java", &f2)]);
        let r = gate_report(&base, &head).unwrap();
        assert_eq!(r["summary"]["blocks"], 0);
        assert_eq!(r["summary"]["exit_code"], 0);
    }
}
