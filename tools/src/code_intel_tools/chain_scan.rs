// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 链候选生成 v2（I1–I3）：
//! - **I1 跨文件绑定**：JS/TS 的 `import {a as b} from './x'` / `@/` 别名 → 目标文件+定义；
//!   Java 的 `import a.b.C` → 目标文件。调用边优先走绑定边，解决"名字级串台/连不上"。
//! - **I2 分层降噪**：链分 `shown`（可达 + 无守卫 + 敏感汇 + 有界步数）与 `candidate`；
//!   全量链按分数排序后截断到硬上限，输出 `chains_raw/shown/candidate`。
//! - **I3 性能**：并行扫描（rayon）+ 定义行二分 + 反向调用索引（不再按名字线性扫）+ BFS 预算。

use super::chain::{
    calls, chain_language_of as language_of, definitions, fnv_chain_id, guards_in, scan_sinks_with, DOSSIER_SCHEMA,
    MAX_STEPS,
};
use super::chain_vocab;
use super::*;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

const MAX_DEPTH: usize = 12;
const MAX_FANOUT: usize = 8;
const MAX_VISIT_PER_SINK: usize = 160;
const MAX_TOTAL_VISITS: usize = 400_000;
const MAX_CHAINS_KEPT: usize = 200;
const MAX_ENTRY_HITS: usize = 6;

struct Extracted {
    defs: Vec<(String, u32)>,
    calls: Vec<(String, u32, bool)>, // (name, line, member)
}

/// 测试/构建产物目录不作为链证据来源（避免 __tests__ 噪声与 dist 干扰）。
fn skipped_path(path: &str) -> bool {
    const BAD: [&str; 8] = [
        "/__tests__/", "/__mocks__/", "/node_modules/", "/dist/", "/build/", "/.next/", "/test/", "/tests/",
    ];
    BAD.iter().any(|seg| path.contains(seg))
}

/// 非相对、非别名、且包目录在仓库里根本不存在 → 视为"跨包未知"，禁止同名兜底。
/// 相对路径解析失败（React 的 virtual `./ReactFlightClientConfig` 之类）→ 允许同名兜底，
/// 但该边只会被标为 ambiguous（不冒充 certain）。
fn blocked_import_spec(spec: &str, top_dirs: &BTreeSet<String>) -> bool {
    if spec.starts_with('.') || spec.starts_with("@/") {
        return false;
    }
    let first = spec.split('/').next().unwrap_or("");
    !top_dirs.contains(first)
}

fn enclosing_line(lines: &[u32], line: u32) -> Option<u32> {
    // lines 已升序：找 <= line 的最后一个
    let idx = lines.partition_point(|l| *l <= line);
    if idx == 0 {
        None
    } else {
        Some(lines[idx - 1])
    }
}

fn def_line_of(defs: &[(String, u32)], name: &str, after: u32) -> Option<u32> {
    let mut best: Option<u32> = None;
    for (n, l) in defs {
        if n == name && *l >= after && best.map(|b| *l < b).unwrap_or(true) {
            best = Some(*l);
        }
    }
    best
}

/// 解析 JS/TS import：返回 (本地名, 模块说明符, 目标导出名)。
fn parse_js_imports(content: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = content[cursor..].find("import ") {
        let start = cursor + rel;
        let rest = &content[start..];
        // 只在合理窗口内找 ` from '...'`，避免跨语句误配
        let mut win_end = rest.len().min(1200);
        while win_end > 0 && !rest.is_char_boundary(win_end) {
            win_end -= 1;
        }
        let window = &rest[..win_end];
        let Some(fp) = window.find(" from ") else {
            cursor = start + 7;
            continue;
        };
        let head = &window[7..fp].trim();
        let after = &window[fp + 6..];
        let mut chars = after.chars();
        let q = chars.next().unwrap_or(' ');
        if q != '\'' && q != '"' {
            cursor = start + 7;
            continue;
        }
        let spec = after[1..].split(q).next().unwrap_or("").to_string();
        if spec.is_empty() {
            cursor = start + 7;
            continue;
        }
        // head 可能是 `{a, b as c}`、`X`、`X, {..}`、`* as ns`
        if let Some(bstart) = head.find('{') {
            if let Some(bend) = head.rfind('}') {
                let inner = &head[bstart + 1..bend];
                for part in inner.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    let mut it = part.split_whitespace();
                    let imported = it.next().unwrap_or("").to_string();
                    let local = match (it.next(), it.next()) {
                        (Some("as"), Some(l)) => l.to_string(),
                        _ => imported.clone(),
                    };
                    if !local.is_empty() && !imported.is_empty() {
                        out.push((local, spec.clone(), imported));
                    }
                }
            }
        } else {
            let local = head.trim().trim_start_matches("type ").trim();
            if !local.is_empty() && !local.starts_with('*') {
                out.push((local.to_string(), spec.clone(), "default".to_string()));
            }
        }
        cursor = start + 7;
    }
    out
}

struct Pre {
    paths: Vec<String>,
    pos: BTreeMap<String, usize>,
    defs: Vec<Vec<(String, u32)>>,
    def_lines: Vec<Vec<u32>>,
    name_defs: BTreeMap<String, Vec<(usize, u32)>>,
    // 反向调用索引：被调 (文件 idx, 定义名) → 调用点 (文件 idx, 行, 绑定边?, 直接调用?)
    incoming: BTreeMap<(usize, String), Vec<(usize, u32, bool, bool)>>,
    contents_bytes: Vec<usize>,
    bindings: BTreeMap<(usize, String), (usize, String)>,
    imports: BTreeMap<usize, BTreeSet<usize>>,
}

fn build_pre(files: &[(String, String)]) -> Pre {
    let extracted: Vec<Extracted> = files
        .par_iter()
        .map(|(path, content)| {
            let lang = language_of(path);
            if skipped_path(path) || !matches!(lang, "js" | "ts" | "java" | "py" | "go") {
                return Extracted {
                    defs: Vec::new(),
                    calls: Vec::new(),
                };
            }
            Extracted {
                defs: definitions(content, lang),
                calls: calls(content),
            }
        })
        .collect();

    let mut pos: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, (p, _)) in files.iter().enumerate() {
        pos.insert(p.clone(), idx);
    }

    let mut defs: Vec<Vec<(String, u32)>> = Vec::with_capacity(files.len());
    let mut def_lines: Vec<Vec<u32>> = Vec::with_capacity(files.len());
    let mut name_defs: BTreeMap<String, Vec<(usize, u32)>> = BTreeMap::new();
    let mut contents_bytes: Vec<usize> = Vec::with_capacity(files.len());
    for (idx, e) in extracted.iter().enumerate() {
        let mut ds = e.defs.clone();
        ds.sort_by(|a, b| a.1.cmp(&b.1));
        let mut lines: Vec<u32> = ds.iter().map(|(_, l)| *l).collect();
        lines.sort_unstable();
        lines.dedup();
        for (n, l) in ds.iter() {
            name_defs.entry(n.clone()).or_default().push((idx, *l));
        }
        defs.push(ds);
        def_lines.push(lines);
        contents_bytes.push(files[idx].1.len());
    }

    // 绑定：JS/TS import + Java import
    let all_paths: BTreeSet<String> = files.iter().map(|(p, _)| p.clone()).collect();
    // Java 类名 → 文件 idx（预建索引，避免每个 import 线性扫描全仓库）
    let mut java_class_idx: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, (p, _)) in files.iter().enumerate() {
        if let Some(name) = p.rsplit('/').next() {
            if let Some(cls) = name.strip_suffix(".java") {
                java_class_idx.entry(cls.to_string()).or_insert(idx);
            }
        }
    }
    let mut bindings: BTreeMap<(usize, String), (usize, String)> = BTreeMap::new();
    let mut imports: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    // 顶部目录（用于判断"包是否存在"）
    let mut top_dirs: BTreeSet<String> = BTreeSet::new();
    for (p, _) in files.iter() {
        if let Some(seg) = p.split('/').next() {
            top_dirs.insert(seg.to_string());
        }
    }
    // 从"仓库里不存在的包"导入的本地名：禁止按同名跨文件兜底连边
    let mut blocked_imports: BTreeSet<(usize, String)> = BTreeSet::new();
    for (idx, (path, content)) in files.iter().enumerate() {
        let lang = language_of(path);
        if lang == "js" || lang == "ts" {
            for (local, spec, imported) in parse_js_imports(content) {
                let resolved = chain_vocab::resolve_js_target(path, &spec, &all_paths);
                if resolved.is_none() && blocked_import_spec(&spec, &top_dirs) {
                    blocked_imports.insert((idx, local.clone()));
                }
                if let Some(target) = resolved {
                    if let Some(&ti) = pos.get(&target) {
                        imports.entry(idx).or_default().insert(ti);
                        if imported != "default" {
                            bindings.insert((idx, local), (ti, imported));
                        }
                    }
                }
            }
        } else if lang == "java" {
            for raw in content.lines() {
                let t = raw.trim();
                let Some(rest) = t.strip_prefix("import ") else { continue };
                let rest = rest.trim_end_matches(';').trim();
                if rest.starts_with("static ") {
                    continue;
                }
                let cls = rest.rsplit('.').next().unwrap_or("");
                if cls.is_empty() {
                    continue;
                }
                if let Some(&ti) = java_class_idx.get(cls) {
                    imports.entry(idx).or_default().insert(ti);
                    bindings.insert((idx, cls.to_string()), (ti, cls.to_string()));
                }
            }
        }
    }

    // 反向调用索引
    let mut incoming: BTreeMap<(usize, String), Vec<(usize, u32, bool, bool)>> = BTreeMap::new();
    for (idx, e) in extracted.iter().enumerate() {
        for (name, line, member) in e.calls.iter() {
            if blocked_imports.contains(&(idx, name.clone())) {
                continue;
            }
            let direct = !*member;
            if let Some((tf, tname)) = bindings.get(&(idx, name.clone())) {
                let has_def = defs.get(*tf).map(|d| d.iter().any(|(n, _)| n == tname)).unwrap_or(false);
                if has_def {
                    incoming
                        .entry((*tf, tname.clone()))
                        .or_default()
                        .push((idx, *line, true, direct));
                } else if let Some(targets) = name_defs.get(tname) {
                    for (df, _dl) in targets.iter().take(4) {
                        incoming
                            .entry((*df, tname.clone()))
                            .or_default()
                            .push((idx, *line, false, direct));
                    }
                }
            } else if let Some(targets) = name_defs.get(name) {
                for (tf, _dl) in targets.iter().take(4) {
                    incoming
                        .entry((*tf, name.clone()))
                        .or_default()
                        .push((idx, *line, false, direct));
                }
            }
        }
    }
    for v in incoming.values_mut() {
        v.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        v.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    }

    let paths: Vec<String> = files.iter().map(|(p, _)| p.clone()).collect();
    Pre {
        paths,
        pos,
        defs,
        def_lines,
        name_defs,
        incoming,
        contents_bytes,
        bindings,
        imports,
    }
}

fn entry_index(pre: &Pre, entries: &[Value]) -> BTreeMap<(usize, u32), Value> {
    let mut out: BTreeMap<(usize, u32), Value> = BTreeMap::new();
    for e in entries {
        let file = e.get("file").and_then(|v| v.as_str()).unwrap_or("");
        let line = e.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let Some(&fi) = pre.pos.get(file) else { continue };
        let route = e.get("route").and_then(|v| v.as_str()).unwrap_or("");
        let dl = def_line_of(&pre.defs[fi], route, 0)
            .or_else(|| {
                // 注解在方法上方：取映射行之后最近的函数定义
                pre.def_lines[fi].iter().copied().find(|l| *l > line)
            })
            .or_else(|| enclosing_line(&pre.def_lines[fi], line))
            .or(Some(line));
        let Some(dl) = dl else { continue };
        let auth = e.get("auth").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let kind_label = e
            .get("entry_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("http")
            .to_string();
        let auth_label = if kind_label == "library_entry" || auth.is_empty() {
            if kind_label == "library_entry" { "not_applicable".to_string() } else { "unknown".to_string() }
        } else {
            auth
        };
        let info = json!({
            "kind": kind_label,
            "method": e.get("method").cloned().unwrap_or(Value::Null),
            "route": if route.is_empty() { e.get("route").cloned().unwrap_or(Value::Null) } else { json!(route) },
            "file": file,
            "mapping_line": line,
            "handler_line": dl,
            "entry_kind": e.get("entry_kind").cloned().unwrap_or(Value::Null),
            "auth": auth_label,
        });
        out.insert((fi, dl), info);
    }
    out
}

fn confidence_of(pre: &Pre, caller: usize, callee: usize, bound: bool, direct: bool) -> &'static str {
    if bound || caller == callee || direct {
        "certain"
    } else if pre
        .imports
        .get(&caller)
        .map(|s| s.contains(&callee))
        .unwrap_or(false)
    {
        "certain"
    } else {
        "inferred"
    }
}

struct WorkBudget {
    visits: usize,
}

/// 从 sink 反向可达入口；返回 (path, breakpoints, entry, sink_def)。
#[allow(clippy::type_complexity)]
fn reverse_reach(
    pre: &Pre,
    sink_file: usize,
    sink_line: u32,
    entries: &BTreeMap<(usize, u32), Value>,
    budget: &mut WorkBudget,
) -> (Vec<(usize, u32, String, &'static str)>, Vec<Value>, Value) {
    let Some(start_def) = enclosing_line(&pre.def_lines[sink_file], sink_line) else {
        return (Vec::new(), Vec::new(), Value::Null);
    };
    let start_name = pre.defs[sink_file]
        .iter()
        .find(|(_, l)| *l == start_def)
        .map(|(n, _)| n.clone())
        .unwrap_or_default();

    // 汇所在函数即入口（但不能是"汇自身所在函数"被词表误列为入口）
    if let Some(info) = entries.get(&(sink_file, start_def)).cloned() {
        let route = info.get("route").and_then(|v| v.as_str()).unwrap_or("");
        if route == start_name {
            return (Vec::new(), Vec::new(), Value::Null);
        }
        return (
            vec![
                (sink_file, start_def, start_name.clone(), "certain"),
                (sink_file, start_def, start_name, "certain"),
            ],
            Vec::new(),
            info,
        );
    }

    let mut visited: BTreeSet<(usize, u32)> = BTreeSet::new();
    let mut queue: VecDeque<((usize, u32, String), Vec<(usize, u32, String, &'static str)>)> =
        VecDeque::new();
    queue.push_back((
        (sink_file, start_def, start_name.clone()),
        vec![(sink_file, start_def, start_name, "certain")],
    ));
    let mut hits: Vec<(Vec<(usize, u32, String, &'static str)>, Value)> = Vec::new();
    let mut breakpoints: Vec<Value> = Vec::new();

    while let Some(((cf, cl, cn), path)) = queue.pop_front() {
        if visited.contains(&(cf, cl)) {
            continue;
        }
        visited.insert((cf, cl));
        budget.visits += 1;
        if budget.visits > MAX_TOTAL_VISITS {
            break;
        }
        if visited.len() > MAX_VISIT_PER_SINK {
            breakpoints.push(json!({
                "kind": "ambiguous_chain",
                "at": format!("{}:{}", files_path(pre, cf), cl),
                "candidates": [],
                "confidence": "low",
            }));
            break;
        }
        if path.len() > MAX_DEPTH {
            breakpoints.push(json!({
                "kind": "ambiguous_chain",
                "at": format!("{}:{}", files_path(pre, cf), cl),
                "candidates": [],
                "confidence": "low",
            }));
            break;
        }
        // 命中入口
        if let Some(info) = entries.get(&(cf, cl)) {
            hits.push((path.clone(), info.clone()));
            if hits.len() >= MAX_ENTRY_HITS {
                break;
            }
        }
        let Some(callers) = pre.incoming.get(&(cf, cn.clone())) else {
            continue;
        };
        let mut next: Vec<(usize, u32, bool, bool)> = callers.clone();
        next.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        next.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        if next.len() > MAX_FANOUT {
            next.truncate(MAX_FANOUT);
            breakpoints.push(json!({
                "kind": "dynamic_dispatch",
                "at": format!("{}:{}", files_path(pre, cf), cl),
                "candidates": [],
                "confidence": "low",
            }));
        }
        for (sf, sl, bound, direct) in next {
            let Some(caller_def) = enclosing_line(&pre.def_lines[sf], sl) else {
                continue;
            };
            let caller_name = pre.defs[sf]
                .iter()
                .find(|(_, l)| *l == caller_def)
                .map(|(n, _)| n.clone())
                .unwrap_or_default();
            let conf = confidence_of(pre, sf, cf, bound, direct);
            let mut p = path.clone();
            p.push((sf, caller_def, caller_name.clone(), conf));
            queue.push_back(((sf, caller_def, caller_name), p));
        }
    }

    if let Some((path, info)) = hits.into_iter().next() {
        (path, breakpoints, info)
    } else {
        (Vec::new(), breakpoints, Value::Null)
    }
}

fn files_path(pre: &Pre, idx: usize) -> String {
    pre.paths.get(idx).cloned().unwrap_or_default()
}

/// 数据可控性（启发式）：sink 表达式/所在函数签名/前几步是否出现"请求侧"标识符。
/// 只判断"看起来来自请求"，不判断能否注入；basis 显式标注为 name_heuristic。
fn request_sourced(sink_expr: &str, sink_def_sig: &str, context: &str, steps: &[Value]) -> bool {
    // 证据优先级：函数签名（参数/注解）> 表达式里的高信号请求对象。
    // 只看签名可避免把"远程响应 body"误判成请求输入（zfile 的 /115、/sharepoint 即此误报）。
    let sig = sink_def_sig.to_ascii_lowercase();
    const STRONG_SIG: [&str; 14] = [
        "request", "req.", "getparameter", "httpservletrequest", "requestbody",
        "requestparam", "multipartfile", "form", "query", "args", "cmd", "target",
        "filename", "payload",
    ];
    if STRONG_SIG.iter().any(|t| sig.contains(t)) {
        return true;
    }
    // Python 等无签名注解：只认明确的请求取值访问器（避免把 HttpRequest 之类的
    // 上游 HTTP 客户端误判为请求输入）
    const ACCESSORS: [&str; 8] = [
        "request.args", "request.form", "request.get_json", "request.query",
        "request.json", "request.values", "request.headers", "request.data",
    ];
    let ctx = context.to_ascii_lowercase();
    if ACCESSORS.iter().any(|t| ctx.contains(t)) {
        return true;
    }
    let expr = sink_expr.to_ascii_lowercase();
    if ACCESSORS.iter().any(|t| expr.contains(t)) {
        return true;
    }
    let _ = steps;
    false
}

fn injection_kind(kind: &str) -> bool {
    matches!(kind, "exec" | "eval" | "sql" | "template" | "ssrf" | "file_write")
}

fn sensitive(kind: &str) -> bool {
    matches!(
        kind,
        "exec" | "eval" | "deserialize" | "reflect" | "module_access" | "template" | "sql" | "file_write"
    )
}

fn chain_score(c: &Value) -> i32 {
    let mut s = 0i32;
    if !c["entry"].is_null() {
        s += 50;
    }
    let kind = c["sink"]["kind"].as_str().unwrap_or("");
    s += match kind {
        "exec" | "eval" | "deserialize" | "reflect" | "module_access" | "template" => 30,
        "sql" | "file_write" => 20,
        "ssrf" => 8,
        _ => 0,
    };
    let unguarded = c["guards"]
        .as_array()
        .map(|a| a.iter().all(|g| g["verdict"].as_str() != Some("blocking")))
        .unwrap_or(true);
    if unguarded {
        s += 15;
    }
    let steps = c["steps"].as_array().map(|a| a.len()).unwrap_or(0) as i32;
    s += (12 - steps.min(12)).max(0);
    if c["breakpoints"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
        s += 5;
    }
    s
}

fn is_shown(c: &Value) -> bool {
    let kind = c["sink"]["kind"].as_str().unwrap_or("");
    let steps = c["steps"].as_array().map(|a| a.len()).unwrap_or(0);
    let controllable = c["controllability"].as_str() == Some("request_sourced");
    !c["entry"].is_null()
        && sensitive(kind)
        && steps <= 12
        && (!injection_kind(kind) || controllable)
}

/// 生成候选链 v2。
pub(crate) fn candidates(
    files: &[(String, String)],
    entries: &[Value],
    auth: &BTreeMap<(String, u32), String>,
    sink_kind: Option<&str>,
    entry_filter: Option<&str>,
    vocab: Option<&Value>,
    include_builtin_sinks: bool,
    limit: usize,
) -> (Vec<Value>, BTreeMap<String, usize>) {
    // 入口扩展：框架隐式入口 + 词表派生
    let mut all_entries: Vec<Value> = entries.to_vec();
    let nextjs = chain_vocab::nextjs_entries(files);
    let nextjs_count = nextjs.len();
    all_entries.extend(nextjs);
    let python = chain_vocab::python_entries(files);
    let python_count = python.len();
    all_entries.extend(python);
    if let Some(v) = vocab {
        if let Some(names) = v.get("entry_names").and_then(|x| x.as_array()) {
            for n in names.iter().take(300) {
                let name = n.get("name").and_then(|x| x.as_str()).unwrap_or("");
                let file = n.get("file").and_then(|x| x.as_str()).unwrap_or("");
                let line = n.get("line").and_then(|x| x.as_u64()).unwrap_or(0);
                const STEMS: [&str; 19] = [
                    "decode", "action", "request", "handler", "route", "render", "create",
                    "fetch", "stream", "dispatch", "endpoint", "invoke", "parse",
                    "deserialize", "read", "exec", "from", "unmarshal", "load",
                ];
                let lower = name.to_ascii_lowercase();
                if name.is_empty() || file.is_empty() || !STEMS.iter().any(|s| lower.contains(s)) {
                    continue;
                }
                all_entries.push(json!({
                    "file": file, "line": line, "method": "LIB", "route": name,
                    "entry_kind": "library_entry",
                }));
            }
        }
    }
    // 入口鉴权补齐（来自路由表）
    for e in all_entries.iter_mut() {
        if let Some(f) = e.get("file").and_then(|v| v.as_str()) {
            if let Some(l) = e.get("line").and_then(|v| v.as_u64()) {
                if let Some(v) = auth.get(&(f.to_string(), l as u32)) {
                    if let Some(o) = e.as_object_mut() {
                        o.insert("auth".to_string(), json!(v));
                    }
                }
            }
        }
    }

    let t0 = Instant::now();
    let pre = build_pre(files);
    let t_extract = t0.elapsed().as_millis() as u64;
    let entry_idx = entry_index(&pre, &all_entries);

    let extra_sinks: Vec<(String, String)> = vocab
        .and_then(|v| v.get("sink_patterns").and_then(|x| x.as_array()))
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    Some((
                        p.get("kind")?.as_str()?.to_string(),
                        p.get("pattern")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let t1 = Instant::now();
    let mut sinks = scan_sinks_with(files, &extra_sinks, include_builtin_sinks);
    let t_sinks = t1.elapsed().as_millis() as u64;
    sinks.sort_by(|a, b| {
        (
            a["file"].as_str().unwrap_or(""),
            a["line"].as_u64().unwrap_or(0),
            a["kind"].as_str().unwrap_or(""),
        )
            .cmp(&(
                b["file"].as_str().unwrap_or(""),
                b["line"].as_u64().unwrap_or(0),
                b["kind"].as_str().unwrap_or(""),
            ))
    });

    let mut stats: BTreeMap<String, usize> = BTreeMap::new();
    stats.insert("sinks_scanned".to_string(), sinks.len());
    stats.insert("entries".to_string(), all_entries.len());
    stats.insert("entries_nextjs".to_string(), nextjs_count);
    stats.insert("entries_python".to_string(), python_count);

    let t2 = Instant::now();
    // 入边集合：用于过滤"无人 import 的死代码文件"的兜底候选
    let mut inbound: BTreeSet<usize> = BTreeSet::new();
    for targets in pre.imports.values() {
        for t in targets.iter() {
            inbound.insert(*t);
        }
    }
    let mut budget = WorkBudget { visits: 0 };
    let mut chains: Vec<Value> = Vec::new();
    let mut reached = 0usize;

    for sink in sinks.iter() {
        if let Some(k) = sink_kind {
            if sink.get("kind").and_then(|v| v.as_str()) != Some(k) {
                continue;
            }
        }
        let file = sink.get("file").and_then(|v| v.as_str()).unwrap_or("");
        let line = sink.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let kind = sink.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let Some(&fi) = pre.pos.get(file) else { continue };
        let Some(sink_def_line) = enclosing_line(&pre.def_lines[fi], line) else { continue };

        let (path, mut breakpoints, entry_info) = reverse_reach(&pre, fi, line, &entry_idx, &mut budget);
        let sink_def_name = pre.defs[fi]
            .iter()
            .find(|(_, l)| *l == sink_def_line)
            .map(|(n, _)| n.clone())
            .unwrap_or_default();

        if !entry_info.is_null() && path.len() >= 2 {
            reached += 1;
            let mut rev: Vec<(usize, u32, String, &'static str)> = path;
            rev.reverse();
            let mut steps: Vec<Value> = Vec::new();
            for (i, (f, l, name, conf)) in rev.iter().enumerate() {
                let role = if i == 0 {
                    "source"
                } else if i + 1 == rev.len() {
                    "sink"
                } else {
                    "propagation"
                };
                steps.push(json!({
                    "file": files.get(*f).map(|(p, _)| p.clone()).unwrap_or_default(),
                    "line": l,
                    "symbol": name,
                    "role": role,
                    "certainty": if i == 0 { "certain" } else { conf },
                }));
            }
            if steps.len() > MAX_STEPS {
                steps.truncate(MAX_STEPS);
                breakpoints.push(json!({
                    "kind": "ambiguous_chain", "at": format!("{}:{}", file, line),
                    "candidates": [], "confidence": "low",
                }));
            }
            if let Some(last) = steps.last_mut() {
                if let Some(o) = last.as_object_mut() {
                    o.insert("line".to_string(), json!(line));
                    o.insert("expr".to_string(), sink.get("expr").cloned().unwrap_or(Value::Null));
                }
            }
            // 守卫：入口与汇窗口
            let mut guards: Vec<Value> = Vec::new();
            // 守卫扫描：入口区间 + 汇区间 + 链上每个中间步骤的窗口
            // （CVE 修复的闸门常落在中间步骤，如 fastjson 的 checkAutoType）
            let mut seen_guard: BTreeSet<(String, u64)> = BTreeSet::new();
            let mut push_guards = |c: &str, lo: u32, hi: u32, p: &str, guards: &mut Vec<Value>| {
                for g in super::chain::guards_range(c, lo, hi, p) {
                    let key = (
                        g.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        g.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
                    );
                    if seen_guard.insert(key) {
                        guards.push(g);
                    }
                }
            };
            let (f0, l0) = (rev[0].0, rev[0].1);
            if let Some((p, c)) = files.get(f0) {
                let handler_line = entry_info
                    .get("handler_line")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
                    .unwrap_or(l0);
                push_guards(c, l0, handler_line, p, &mut guards);
            }
            if let Some((p, c)) = files.get(fi) {
                push_guards(c, sink_def_line, line, p, &mut guards);
            }
            for (sf, sl, _sym, _conf) in rev.iter().take(8) {
                if let Some((p, c)) = files.get(*sf) {
                    push_guards(c, sl.saturating_sub(2), sl + 2, p, &mut guards);
                }
            }
            // 断点降噪：只保留贴着链上步骤的断点，其余只作为 uncertainty 理由
            let step_pos: Vec<(String, u64)> = steps
                .iter()
                .map(|st| {
                    (
                        st.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        st.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
                    )
                })
                .collect();
            breakpoints.retain(|b| {
                let at = b.get("at").and_then(|v| v.as_str()).unwrap_or("");
                let Some((f, l)) = at.rsplit_once(':') else { return false };
                let Ok(line) = l.parse::<u64>() else { return false };
                step_pos.iter().any(|(sf, sl)| {
                    sf.ends_with(f.rsplit('/').next().unwrap_or(f)) && (*sl as i64 - line as i64).abs() <= 2
                })
            });
            let mut reasons: Vec<String> = Vec::new();
            for b in breakpoints.iter() {
                if let Some(k) = b.get("kind").and_then(|v| v.as_str()) {
                    if !reasons.iter().any(|r| r == k) {
                        reasons.push(k.to_string());
                    }
                }
            }
            let auth_v = entry_info.get("auth").and_then(|v| v.as_str()).unwrap_or("unknown");
            if auth_v == "unknown" && !reasons.iter().any(|r| r == "unmodelled_framework") {
                reasons.push("unmodelled_framework".to_string());
            }
            let steps_total = steps.len();
            let sink_expr = sink.get("expr").and_then(|v| v.as_str()).unwrap_or("");
            let sink_sig = files
                .get(fi)
                .and_then(|(_, c)| c.lines().nth(sink_def_line.saturating_sub(1) as usize))
                .unwrap_or("");
            let ctx: String = files
                .get(fi)
                .map(|(_, c)| {
                    c.lines()
                        .skip(line.saturating_sub(6) as usize)
                        .take(5)
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            let controllable = request_sourced(sink_expr, sink_sig, &ctx, &steps);
            let cid = fnv_chain_id(file, line, &steps);
            chains.push(json!({
                "schema": DOSSIER_SCHEMA,
                "chain_id": cid,
                "entry": entry_info,
                "sink": {
                    "kind": kind,
                    "file": sink.get("file").cloned().unwrap_or(Value::Null),
                    "line": sink.get("line").cloned().unwrap_or(Value::Null),
                    "expr": sink.get("expr").cloned().unwrap_or(Value::Null),
                },
                "steps": steps,
                "guards": guards,
                "breakpoints": breakpoints,
                "controllability": if controllable { "request_sourced" } else { "unknown" },
                "controllability_basis": "name_heuristic",
                "uncertainty": {"level": if reasons.is_empty() { "low" } else { "medium" }, "reasons": reasons},
                "verdict_candidates": ["reachable_unauthenticated", "reachable_authenticated", "unreachable"],
                "falsify": [format!("ctx-audit chain <ROOT> --id {cid}")],
                "steps_total": steps_total,
            }));
        } else {
            // 死代码过滤：无人 import 且无路由/框架入口指向的文件，不产出兜底档
            if !inbound.contains(&fi)
                && !all_entries.iter().any(|e| {
                    e.get("file").and_then(|v| v.as_str()) == files.get(fi).map(|(p, _)| p.as_str())
                })
            {
                continue;
            }
            // 汇级兜底档
            let cand_entries: Vec<Value> = all_entries
                .iter()
                .take(3)
                .map(|e| json!({
                    "route": e.get("route").cloned().unwrap_or(Value::Null),
                    "file": e.get("file").cloned().unwrap_or(Value::Null),
                    "line": e.get("line").cloned().unwrap_or(Value::Null),
                    "entry_kind": e.get("entry_kind").cloned().unwrap_or(Value::Null),
                }))
                .collect();
            let mut guards: Vec<Value> = Vec::new();
            if let Some((p, c)) = files.get(fi) {
                guards.extend(guards_in(c, line, p));
            }
            let cid_fb = fnv_chain_id(file, line, &[]);
            chains.push(json!({
                "schema": DOSSIER_SCHEMA,
                "chain_id": cid_fb,
                "entry": Value::Null,
                "sink": {
                    "kind": kind,
                    "file": sink.get("file").cloned().unwrap_or(Value::Null),
                    "line": sink.get("line").cloned().unwrap_or(Value::Null),
                    "expr": sink.get("expr").cloned().unwrap_or(Value::Null),
                },
                "steps": [{
                    "file": file, "line": line, "symbol": sink_def_name,
                    "role": "sink", "certainty": "certain",
                }],
                "guards": guards,
                "breakpoints": [{
                    "kind": if cand_entries.is_empty() { "ambiguous_chain" } else { "framework_magic" },
                    "at": format!("{}:{}", file, line),
                    "candidates": cand_entries.iter().filter_map(|c| c["route"].as_str()).collect::<Vec<_>>(),
                    "candidate_entries": cand_entries,
                    "confidence": "low",
                }],
                "uncertainty": {"level": "high", "reasons": ["unmodelled_framework"]},
                "verdict_candidates": ["reachable_unauthenticated", "reachable_authenticated", "unreachable"],
                "falsify": [format!("ctx-audit chain <ROOT> --id {cid_fb}")],
                "steps_total": 1,
            }));
        }
    }

    stats.insert("t_extract_ms".to_string(), t_extract as usize);
    stats.insert("t_sinks_ms".to_string(), t_sinks as usize);
    stats.insert("t_bfs_ms".to_string(), t2.elapsed().as_millis() as usize);
    stats.insert(
        "chains_linked".to_string(),
        chains.iter().filter(|c| !c["entry"].is_null()).count(),
    );
    stats.insert("chains_raw".to_string(), chains.len());
    stats.insert("sinks_reached".to_string(), reached);

    // I2：分层 + 排序 + 硬上限
    for c in chains.iter_mut() {
        let shown = is_shown(c);
        let score = chain_score(c);
        if let Some(o) = c.as_object_mut() {
            o.insert("tier".to_string(), json!(if shown { "shown" } else { "candidate" }));
            o.insert("score".to_string(), json!(score));
        }
    }
    chains.sort_by(|a, b| {
        let sa = (a["tier"].as_str() == Some("shown")) as u8;
        let sb = (b["tier"].as_str() == Some("shown")) as u8;
        sb.cmp(&sa).then_with(|| {
            chain_score(b)
                .cmp(&chain_score(a))
                .then_with(|| a["sink"]["file"].as_str().cmp(&b["sink"]["file"].as_str()))
                .then_with(|| a["sink"]["line"].as_u64().cmp(&b["sink"]["line"].as_u64()))
        })
    });
    if let Some(filter) = entry_filter {
        chains.retain(|c| {
            c["entry"]["route"].as_str().map(|r| r.contains(filter)).unwrap_or(false)
                || c["entry"]["file"].as_str().map(|f| f.contains(filter)).unwrap_or(false)
        });
    }
    let shown = chains.iter().filter(|c| c["tier"] == "shown").count();
    let candidate = chains.len() - shown;
    stats.insert("chains_shown".to_string(), shown);
    stats.insert("chains_candidate".to_string(), candidate);
    stats.insert("budget_visits".to_string(), budget.visits);
    chains.truncate(MAX_CHAINS_KEPT);
    let take = if limit == 0 {
        chains.len()
    } else {
        limit.min(chains.len())
    };
    chains.truncate(take);
    stats.insert("chains_found".to_string(), chains.len());
    (chains, stats)
}
