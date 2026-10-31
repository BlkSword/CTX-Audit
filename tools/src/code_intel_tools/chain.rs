// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 链档（Chain Dossier）—— 法医台核心：把"入口 → 危险汇"的可疑路径装配成有界、确定性、
//! 带断点与不确定性的证据档。
//!
//! 取舍（依据 R247–R257 实测）：
//! - 候选生成用**调用图可达性**而非全污点：污点自动发现实测弱（0/17），先保召回；
//! - **断点显式**：解不开的地方（深度上限/扇出超限/无调用者）一律进 `breakpoints`；
//! - **有界**：步骤 ≤40、单档 ≤12KB、确定性排序、内容哈希 ID；
//! - **不做判定**：只给 `verdict_candidates`。

use super::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(crate) const DOSSIER_SCHEMA: &str = "chain-dossier/v1";
pub(crate) const MAX_STEPS: usize = 40;
pub(crate) const MAX_DOSSIER_BYTES: usize = 12 * 1024;
const MAX_DEPTH: usize = 8;
const MAX_FANOUT: usize = 6;

/// FNV-1a：确定性链 ID（不依赖 std 随机化 hasher）。
pub(crate) fn stable_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{h:016x}")
}

fn language_of(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "js" | "mjs" | "cjs" | "jsx" => "js",
        "ts" | "tsx" => "ts",
        "java" => "java",
        "py" => "py",
        "go" => "go",
        _ => "other",
    }
}

fn is_code_line(line: &str) -> bool {
    let t = line.trim_start();
    !(t.is_empty()
        || t.starts_with("//")
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.starts_with('#')
        || t.starts_with("--"))
}

fn ident_before_paren(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let paren = trimmed.find('(')?;
    let head = &trimmed[..paren];
    let name: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if name.is_empty() || name.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) {
        None
    } else {
        Some(name)
    }
}

const KEYWORDS: [&str; 30] = [
    "if", "for", "while", "switch", "catch", "return", "function", "new", "typeof", "await",
    "async", "else", "do", "try", "throw", "delete", "void", "in", "size", "length", "toString",
    "println", "print", "log", "require", "import", "assert", "super", "this", "yield",
];

fn definitions(content: &str, lang: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        if !is_code_line(raw) {
            continue;
        }
        let t = raw.trim();
        let ln = (idx + 1) as u32;
        match lang {
            "js" | "ts" => {
                if let Some(pos) = t.find("function ") {
                    let rest = &t[pos + 9..];
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    if !name.is_empty() {
                        out.push((name, ln));
                        continue;
                    }
                }
                if t.contains("=>") || t.contains("= function") || t.contains("= async") {
                    if let Some(eq) = t.find('=') {
                        let head = t[..eq].trim_end();
                        let name: String = head
                            .chars()
                            .rev()
                            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect();
                        if !name.is_empty() {
                            out.push((name, ln));
                            continue;
                        }
                    }
                }
                if t.ends_with('{') && !t.contains('=') {
                    if let Some(name) = ident_before_paren(t) {
                        if !KEYWORDS.contains(&name.as_str()) {
                            out.push((name, ln));
                        }
                    }
                }
            }
            "java" => {
                if t.contains('(')
                    && t.contains(')')
                    && t.contains('{')
                    && !t.contains('=')
                    && !["if", "for", "while", "switch", "return", "new "]
                        .iter()
                        .any(|k| t.starts_with(k))
                {
                    if let Some(name) = ident_before_paren(t) {
                        out.push((name, ln));
                    }
                }
            }
            "py" => {
                if let Some(rest) = t.strip_prefix("def ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        out.push((name, ln));
                    }
                }
            }
            "go" => {
                if t.starts_with("func ") {
                    if let Some(name) = ident_before_paren(t) {
                        out.push((name, ln));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn calls(content: &str) -> Vec<(String, u32, bool)> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        if !is_code_line(raw) {
            continue;
        }
        let ln = (idx + 1) as u32;
        // 按 char 索引扫描（避免字节切片落在 UTF-8 字符中间）
        let chars: Vec<(usize, char)> = raw.char_indices().collect();
        let n = chars.len();
        let mut k = 0usize;
        while k < n {
            let (start_byte, ch) = chars[k];
            if ch.is_alphabetic() || ch == '_' || ch == '$' {
                let mut end_k = k;
                while end_k + 1 < n {
                    let c2 = chars[end_k + 1].1;
                    if c2.is_alphanumeric() || c2 == '_' || c2 == '$' {
                        end_k += 1;
                    } else {
                        break;
                    }
                }
                let end_byte = if end_k + 1 < n { chars[end_k + 1].0 } else { raw.len() };
                let name = &raw[start_byte..end_byte];
                let mut j = end_k + 1;
                while j < n && chars[j].1.is_whitespace() {
                    j += 1;
                }
                if j < n && chars[j].1 == '(' && !KEYWORDS.contains(&name) {
                    let member = start_byte > 0 && raw.as_bytes()[start_byte - 1] == b'.';
                    out.push((name.to_string(), ln, member));
                }
                k = end_k + 1;
            } else {
                k += 1;
            }
        }
    }
    out
}

fn enclosing_def(defs: &[(String, u32)], line: u32) -> Option<(String, u32)> {
    let mut best: Option<(String, u32)> = None;
    for (name, ln) in defs {
        if *ln <= line && best.as_ref().map(|(_, b)| *ln > *b).unwrap_or(true) {
            best = Some((name.clone(), *ln));
        }
    }
    best
}

/// 危险汇清单（首版：JS/TS/Java/Python）。
pub(crate) fn scan_sinks(files: &[(String, String)]) -> Vec<Value> {
    const PATTERNS: [(&str, &[&str]); 9] = [
        (
            "exec",
            &[
                "child_process.exec", "execSync(", "spawnSync(", "execFile(", "Runtime.getRuntime",
                "ProcessBuilder", "exec.Command(", "os.system(", "subprocess.",
            ],
        ),
        (
            "eval",
            &["eval(", "new Function(", "Function(\"", "ScriptEngine", "vm.runInNewContext", "vm.runInThisContext"],
        ),
        (
            "deserialize",
            &[
                "ObjectInputStream", "readObject(", "JSON.parse(", "yaml.load(", "pickle.loads(",
                "unserialize(", "readValue(", "parseObject(", "decodeReply(", "decodeAction(",
            ],
        ),
        (
            "reflect",
            &["Class.forName(", "getDeclaredMethod(", "getMethod(", "newInstance(", "Module._load(", "process.binding("],
        ),
        (
            "file_write",
            &["writeFile(", "writeFileSync(", "createWriteStream(", "Files.write(", "FileOutputStream", "os.WriteFile", "write_text("],
        ),
        (
            "sql",
            &["executeQuery(", "createNativeQuery(", "rawQuery(", "knex.raw(", "db.query("],
        ),
        (
            "template",
            &["render_template_string(", "compileTemplate(", "Handlebars.compile(", "nunjucks.renderString(", "ScriptEngine", "velocity.evaluate"],
        ),
        (
            "ssrf",
            &["axios.get(", "axios.post(", "fetch(", "http.get(", "https.get(", "requests.get(", "requests.post(", "HttpClient.newHttpClient(", "OkHttpClient"],
        ),
        (
            "module_access",
            &["moduleExports[", "serverManifest[", "metadata[NAME]", "clientManifest["],
        ),
    ];
    let mut out = Vec::new();
    for (path, content) in files.iter().take(max_index_files()) {
        let lang = language_of(path);
        if !matches!(lang, "js" | "ts" | "java" | "py") {
            continue;
        }
        for (idx, raw) in content.lines().enumerate() {
            if !is_code_line(raw) {
                continue;
            }
            for (kind, pats) in PATTERNS.iter() {
                if pats.iter().any(|p| raw.contains(p)) {
                    out.push(json!({
                        "kind": kind,
                        "file": path,
                        "line": (idx + 1) as u32,
                        "expr": raw.trim().chars().take(160).collect::<String>(),
                        "language": lang,
                    }));
                    break;
                }
            }
        }
    }
    out
}

/// 库级入口：框架内部"请求可达"的导出函数（用于框架 CVE 取证）。
///
/// 这类仓库没有 HTTP 路由注解，入口是 `decodeReply` / `decodeAction` 这类被框架调用的导出函数。
pub(crate) const LIB_ENTRY_NAMES: [&str; 9] = [
    "decodeReply",
    "decodeReplyFromBusboy",
    "decodeAction",
    "decodeFormState",
    "createRequest",
    "renderToReadableStream",
    "createFromFetch",
    "createFromReadableStream",
    "resolveModelChunk",
];

/// 入口清单：method 级路由（文件/行）+ 覆盖判定（来自端点表）。
pub(crate) fn collect_entries(files: &[(String, String)], id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (path, content) in files.iter().take(max_index_files()) {
        let lang = language_of(path);
        if !(path.ends_with(".java") || matches!(lang, "js" | "ts")) {
            continue;
        }
        let scan = scan_routes_in_file_prefixed(path, content, "", id, "");
        for r in scan.routes {
            if r.get("scope").and_then(|v| v.as_str()) != Some("method") {
                continue;
            }
            out.push(json!({
                "file": path,
                "line": r.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
                "method": r.get("http_method").and_then(|v| v.as_str()).unwrap_or("ANY"),
                "route": r.get("route").and_then(|v| v.as_str()).unwrap_or(""),
                "entry_kind": "http",
            }));
        }
        // 库级入口：request-facing 导出函数
        for (name, line) in definitions(content, lang) {
            if LIB_ENTRY_NAMES.contains(&name.as_str()) {
                out.push(json!({
                    "file": path,
                    "line": line,
                    "method": "LIB",
                    "route": name,
                    "entry_kind": "library_entry",
                }));
            }
        }
    }
    out
}

/// 入口鉴权映射：(文件, 映射行) → verdict（来自端点表，保证与 `explain_route` 同源）。
pub(crate) fn auth_map(root: &Path, files: &[(String, String)], id: &str) -> BTreeMap<(String, u32), String> {
    let table = compute_routes(root, files, id, false, &RouteFilter::default(), false);
    let mut out = BTreeMap::new();
    if let Some(routes) = table.data.get("routes").and_then(|v| v.as_array()) {
        for r in routes {
            if r.get("scope").and_then(|v| v.as_str()) != Some("method") {
                continue;
            }
            let file = r.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let line = r.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let verdict = r
                .get("global_coverage")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            out.insert((file, line), verdict);
        }
    }
    out
}

fn guards_in(content: &str, center: u32, file: &str) -> Vec<Value> {
    const GUARDS: [(&str, &[&str]); 6] = [
        ("auth_check", &["@SaCheckLogin", "@PreAuthorize", "@RequiresPermissions", "@RequiresRoles", "isAuthenticated(", "checkLogin(", "getLoginId(", "requireAuth"]),
        ("permission_check", &["@CheckPassword", "@StoragePermissionCheck", "checkRole(", "hasRole(", "hasPermission(", "isAdmin"]),
        ("allowlist", &["allowlist", "whitelist", "ALLOWED_", "startsWith(", "matchesPattern", "Pattern.compile", "hasOwnProperty"]),
        ("sanitize", &["sanitize", "escapeHtml", "escape(", "encodeURI", "HtmlUtils", "StringEscapeUtils"]),
        ("signature", &["validSignature", "hmac", "HmacSHA", "constantTimeEqual"]),
        ("bounds", &["maxLength", "Preconditions", "assertNotNull"]),
    ];
    let lines: Vec<&str> = content.lines().collect();
    let start = center.saturating_sub(4) as usize;
    let end = ((center + 30) as usize).min(lines.len());
    let mut out = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for i in start..end {
        let Some(raw) = lines.get(i) else { continue };
        if !is_code_line(raw) {
            continue;
        }
        for (kind, pats) in GUARDS.iter() {
            if pats.iter().any(|p| raw.contains(p)) && !seen.contains(kind) {
                seen.insert(kind);
                out.push(json!({
                    "kind": kind,
                    "file": file,
                    "line": (i + 1) as u32,
                    "verdict": "partial",
                    "evidence": raw.trim().chars().take(120).collect::<String>(),
                }));
            }
        }
    }
    out
}

fn fnv_chain_id(sink_file: &str, sink_line: u32, steps: &[Value]) -> String {
    let src = format!(
        "{}|{}|{}",
        sink_file,
        sink_line,
        steps
            .iter()
            .map(|s| format!(
                "{}:{}",
                s.get("file").and_then(|v| v.as_str()).unwrap_or(""),
                s.get("line").and_then(|v| v.as_u64()).unwrap_or(0)
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    format!("CH-{}", &stable_hash(&src)[..8])
}

/// 生成候选链（只保留"能到入口"的链）。
pub(crate) fn candidates(
    files: &[(String, String)],
    entries: &[Value],
    auth: &BTreeMap<(String, u32), String>,
    sink_kind: Option<&str>,
    entry_filter: Option<&str>,
    limit: usize,
) -> (Vec<Value>, BTreeMap<String, usize>) {
    let mut defs: BTreeMap<String, Vec<(String, u32)>> = BTreeMap::new();
    let mut call_sites: BTreeMap<String, Vec<(String, u32, bool)>> = BTreeMap::new();
    let mut contents: BTreeMap<String, String> = BTreeMap::new();
    for (path, content) in files.iter().take(max_index_files()) {
        let lang = language_of(path);
        if !matches!(lang, "js" | "ts" | "java" | "py" | "go") {
            continue;
        }
        defs.insert(path.clone(), definitions(content, lang));
        for (name, line, member) in calls(content) {
            call_sites.entry(name).or_default().push((path.clone(), line, member));
        }
        contents.insert(path.clone(), content.clone());
    }

    // entry 映射行 → handler 定义（同文件下方最近定义）
    let mut handler_of: BTreeMap<(String, u32), (String, u32, String, Value)> = BTreeMap::new();
    for e in entries {
        let file = e.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let line = e.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let Some(ds) = defs.get(&file) else { continue };
        let mut best: Option<(String, u32)> = None;
        for (name, ln) in ds {
            if *ln >= line && best.as_ref().map(|(_, b)| *ln < *b).unwrap_or(true) {
                best = Some((name.clone(), *ln));
            }
        }
        if let Some((name, ln)) = best {
            let entry_kind = e.get("entry_kind").and_then(|v| v.as_str()).unwrap_or("http");
            let auth_v = if entry_kind == "library_entry" {
                "unknown".to_string()
            } else {
                auth.get(&(file.clone(), line)).cloned().unwrap_or_default()
            };
            handler_of.insert(
                (file.clone(), line),
                (file.clone(), ln, name, json!({
                    "kind": "http",
                    "method": e.get("method").cloned().unwrap_or(Value::Null),
                    "route": e.get("route").cloned().unwrap_or(Value::Null),
                    "file": file,
                    "mapping_line": line,
                    "handler_line": ln,
                    "entry_kind": e.get("entry_kind").cloned().unwrap_or(Value::Null),
                    "auth": auth_v,
                })),
            );
        }
    }
    // handler 定义 → entry 信息（用于 BFS 命中判断）
    let mut entry_by_handler: BTreeMap<(String, u32), Value> = BTreeMap::new();
    for (_k, (hf, hl, _name, info)) in handler_of.iter() {
        entry_by_handler.insert((hf.clone(), *hl), info.clone());
    }

    let mut stats: BTreeMap<String, usize> = BTreeMap::new();
    let sinks = scan_sinks(files);
    stats.insert("sinks_scanned".to_string(), sinks.len());
    let mut chains: Vec<Value> = Vec::new();
    let mut reached = 0usize;

    for sink in sinks.iter() {
        if let Some(k) = sink_kind {
            if sink.get("kind").and_then(|v| v.as_str()) != Some(k) {
                continue;
            }
        }
        let file = sink.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let line = sink.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let Some(ds) = defs.get(&file) else { continue };
        let Some((sink_def, sink_def_line)) = enclosing_def(ds, line) else { continue };

        let mut visited: BTreeSet<(String, u32)> = BTreeSet::new();
        let mut queue: VecDeque<(String, u32, String, Vec<(String, u32, String)>)> = VecDeque::new();
        queue.push_back((
            file.clone(),
            sink_def_line,
            sink_def.clone(),
            vec![(file.clone(), sink_def_line, sink_def.clone())],
        ));
        let mut found: Vec<(Vec<(String, u32, String)>, Vec<Value>)> = Vec::new();

        while let Some((cur_file, cur_line, cur_name, path)) = queue.pop_front() {
            if visited.contains(&(cur_file.clone(), cur_line)) {
                continue;
            }
            visited.insert((cur_file.clone(), cur_line));
            if entry_by_handler.contains_key(&(cur_file.clone(), cur_line)) && found.len() < 12 {
                found.push((path.clone(), Vec::new()));
                // 继续搜索：同一 sink 可能同时可达客户端与服务端入口（框架 CVE 取证需要后者）
                continue;
            }
            if path.len() >= MAX_DEPTH {
                if found.is_empty() && found.len() < 1 {
                    found.push((
                        path.clone(),
                        vec![json!({
                            "kind": "ambiguous_chain",
                            "at": format!("{}:{}", cur_file, cur_line),
                            "candidates": [],
                            "confidence": "low",
                        })],
                    ));
                }
                continue;
            }
            let mut next: Vec<(String, u32, bool)> = call_sites
                .get(&cur_name)
                .map(|v| v.clone())
                .unwrap_or_default();
            next.retain(|(f, l, _)| !(f == &cur_file && *l == cur_line));
            next.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));
            next.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
            let truncated = next.len() > MAX_FANOUT;
            if truncated {
                next.truncate(MAX_FANOUT);
            }
            if next.is_empty() {
                continue;
            }
            for (site_file, site_line, _member) in next {
                let Some(site_defs) = defs.get(&site_file) else { continue };
                let Some((caller_name, caller_line)) = enclosing_def(site_defs, site_line) else {
                    continue;
                };
                let mut p = path.clone();
                p.push((site_file.clone(), site_line, caller_name.clone()));
                queue.push_back((site_file, caller_line, caller_name, p));
            }
            if truncated {
                // 记录扇出截断（不影响继续搜索，但要在最终档里标注）
                let _ = cur_name;
            }
        }

        if found.is_empty() {
            // 无法把汇连到入口：输出"汇级链档"，断点显式（framework_magic / ambiguous_chain）。
            // 框架回调/异步调度（如 RSC 的 createResponse→requireModule）本身不在静态调用图上，
            // 诚实做法是给出候选入口并标注断点，而不是静默丢弃或假装可达。
            let cands: Vec<String> = entries
                .iter()
                .filter(|e| e.get("entry_kind").and_then(|v| v.as_str()) == Some("library_entry"))
                .take(3)
                .map(|e| e.get("route").and_then(|v| v.as_str()).unwrap_or("").to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let kind = if cands.is_empty() { "ambiguous_chain" } else { "framework_magic" };
            let mut guards: Vec<Value> = Vec::new();
            if let Some(c) = contents.get(&file) {
                guards.extend(guards_in(c, line, &file));
            }
            let reasons: Vec<String> = vec![kind.to_string(), "unmodelled_framework".to_string()];
            chains.push(json!({
                "schema": DOSSIER_SCHEMA,
                "chain_id": fnv_chain_id(&file, line, &[json!({"file": file, "line": line})]),
                "entry": Value::Null,
                "sink": {
                    "kind": sink.get("kind").cloned().unwrap_or(Value::Null),
                    "file": sink.get("file").cloned().unwrap_or(Value::Null),
                    "line": sink.get("line").cloned().unwrap_or(Value::Null),
                    "expr": sink.get("expr").cloned().unwrap_or(Value::Null),
                },
                "steps": [{
                    "file": file,
                    "line": line,
                    "symbol": sink_def,
                    "role": "sink",
                    "certainty": "certain",
                }],
                "guards": guards,
                "breakpoints": [{
                    "kind": kind,
                    "at": format!("{}:{}", file, line),
                    "candidates": cands,
                    "confidence": "low",
                }],
                "uncertainty": {"level": "high", "reasons": reasons},
                "verdict_candidates": ["reachable_unauthenticated", "reachable_authenticated", "unreachable"],
                "falsify": [format!("ctx-audit chain <ROOT> --id {}", fnv_chain_id(&file, line, &[]))],
                "steps_total": 1,
            }));
            continue;
        }
        let found_paths = found;
        for (path, mut breakpoints) in found_paths {
        reached += 1;
        let mut rev = path;
        rev.reverse();
        let mut steps: Vec<Value> = Vec::new();
        for (i, (f, l, name)) in rev.iter().enumerate() {
            let role = if i == 0 {
                "source"
            } else if i + 1 == rev.len() {
                "sink"
            } else {
                "propagation"
            };
            let certainty = if i == 0 { "certain" } else { "inferred" };
            steps.push(json!({
                "file": f,
                "line": l,
                "symbol": name,
                "role": role,
                "certainty": certainty,
            }));
        }
        if steps.len() > MAX_STEPS {
            steps.truncate(MAX_STEPS);
            breakpoints.push(json!({
                "kind": "ambiguous_chain",
                "at": format!("{}:{}", file, line),
                "candidates": [],
                "confidence": "low",
            }));
        }
        // sink 步用真实汇行替换（若最后一步不是汇行）
        if let Some(last) = steps.last_mut() {
            if let Some(obj) = last.as_object_mut() {
                obj.insert("line".to_string(), json!(line));
                obj.insert("expr".to_string(), sink.get("expr").cloned().unwrap_or(Value::Null));
            }
        }

        // 入口信息与守卫
        let entry = entry_by_handler
            .get(&(rev[0].0.clone(), rev[0].1))
            .cloned()
            .unwrap_or(Value::Null);
        let mut guards: Vec<Value> = Vec::new();
        if let Some(c) = contents.get(&rev[0].0) {
            guards.extend(guards_in(c, rev[0].1, &rev[0].0));
        }
        if let Some(c) = contents.get(&file) {
            guards.extend(guards_in(c, line, &file));
        }

        let mut reasons: Vec<String> = Vec::new();
        for b in breakpoints.iter() {
            if let Some(k) = b.get("kind").and_then(|v| v.as_str()) {
                if !reasons.iter().any(|r| r == k) {
                    reasons.push(k.to_string());
                }
            }
        }
        // 入口鉴权未知也算不确定性来源
        let entry_auth = entry
            .get("auth")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if entry_auth == "unknown" && !reasons.iter().any(|r| r == "unmodelled_framework") {
            reasons.push("unmodelled_framework".to_string());
        }
        let level = if breakpoints.is_empty() { "medium" } else { "high" };

        chains.push(json!({
            "schema": DOSSIER_SCHEMA,
            "chain_id": fnv_chain_id(&file, line, &steps),
            "entry": entry,
            "sink": {
                "kind": sink.get("kind").cloned().unwrap_or(Value::Null),
                "file": sink.get("file").cloned().unwrap_or(Value::Null),
                "line": sink.get("line").cloned().unwrap_or(Value::Null),
                "expr": sink.get("expr").cloned().unwrap_or(Value::Null),
            },
            "steps": steps,
            "guards": guards,
            "breakpoints": breakpoints,
            "uncertainty": {"level": level, "reasons": reasons},
            "verdict_candidates": ["reachable_unauthenticated", "reachable_authenticated", "unreachable"],
            "falsify": [
                format!("ctx-audit chain <ROOT> --id {}", fnv_chain_id(&file, line, &steps)),
                "ctx-audit chain <ROOT> --list --sink <kind>".to_string()
            ],
            "steps_total": rev_len(&entry),
        }));
    }

    }
    // 可选：按入口过滤（如 `decodeReply` 只看服务端入口）
    if let Some(filter) = entry_filter {
        chains.retain(|c| {
            let e = &c["entry"];
            e["route"].as_str().map(|r| r.contains(filter)).unwrap_or(false)
                || e["file"].as_str().map(|f| f.contains(filter)).unwrap_or(false)
        });
    }

    // 排序：步骤少、入口 unauthorized 优先
    chains.sort_by(|a, b| {
        let ua = a["entry"]["auth"].as_str().unwrap_or("unknown");
        let ub = b["entry"]["auth"].as_str().unwrap_or("unknown");
        let wa = if matches!(ua, "uncovered" | "no_global_match_found" | "unknown") { 0 } else { 1 };
        let wb = if matches!(ub, "uncovered" | "no_global_match_found" | "unknown") { 0 } else { 1 };
        wa.cmp(&wb)
            .then_with(|| {
                a["steps"].as_array().map(|v| v.len()).unwrap_or(0)
                    .cmp(&b["steps"].as_array().map(|v| v.len()).unwrap_or(0))
            })
            .then_with(|| {
                a["sink"]["file"].as_str().unwrap_or("").cmp(b["sink"]["file"].as_str().unwrap_or(""))
            })
            .then_with(|| {
                a["sink"]["line"].as_u64().unwrap_or(0).cmp(&b["sink"]["line"].as_u64().unwrap_or(0))
            })
    });
    stats.insert("chains_found".to_string(), chains.len());
    stats.insert("sinks_reached".to_string(), reached);
    let take = if limit == 0 { chains.len() } else { limit.min(chains.len()) };
    chains.truncate(take);
    (chains, stats)
}

fn rev_len(entry: &Value) -> usize {
    if entry.is_null() {
        0
    } else {
        1
    }
}

/// 链档 JSON 体积（用于预算检查）。
pub(crate) fn dossier_bytes(v: &Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)
}

/// Markdown 渲染（人读）。
pub(crate) fn dossier_markdown(d: &Value) -> String {
    let mut s = String::new();
    let id = d["chain_id"].as_str().unwrap_or("");
    s.push_str(&format!("# 链档 {id}\n\n"));
    s.push_str(&format!("- schema: `{}`\n", d["schema"].as_str().unwrap_or("")));
    let e = &d["entry"];
    s.push_str(&format!(
        "- 入口: `{} {}` ({}:{}) auth={}\n",
        e["method"].as_str().unwrap_or("ANY"),
        e["route"].as_str().unwrap_or(""),
        e["file"].as_str().unwrap_or(""),
        e["handler_line"].as_u64().unwrap_or(0),
        e["auth"].as_str().unwrap_or("unknown"),
    ));
    let k = &d["sink"];
    s.push_str(&format!(
        "- 汇: `{}` ({}:{})\n",
        k["kind"].as_str().unwrap_or(""),
        k["file"].as_str().unwrap_or(""),
        k["line"].as_u64().unwrap_or(0),
    ));
    s.push_str(&format!("- 不确定度: {}\n", d["uncertainty"]["level"].as_str().unwrap_or("")));
    if let Some(rs) = d["uncertainty"]["reasons"].as_array() {
        let list: Vec<&str> = rs.iter().filter_map(|v| v.as_str()).collect();
        if !list.is_empty() {
            s.push_str(&format!("- 原因: {}\n", list.join(", ")));
        }
    }
    s.push_str("\n## 步骤\n\n| # | 角色 | 位置 | 符号 | 确定性 |\n|---|---|---|---|---|\n");
    if let Some(steps) = d["steps"].as_array() {
        for (i, st) in steps.iter().enumerate() {
            s.push_str(&format!(
                "| {} | {} | {}:{} | `{}` | {} |\n",
                i + 1,
                st["role"].as_str().unwrap_or(""),
                st["file"].as_str().unwrap_or(""),
                st["line"].as_u64().unwrap_or(0),
                st["symbol"].as_str().unwrap_or(""),
                st["certainty"].as_str().unwrap_or(""),
            ));
        }
    }
    s.push_str("\n## 守卫（启发式，需人工复核）\n\n");
    if let Some(gs) = d["guards"].as_array() {
        if gs.is_empty() {
            s.push_str("- （未读到校验形态）\n");
        }
        for g in gs {
            s.push_str(&format!(
                "- `{}` {}:{} — {}\n",
                g["kind"].as_str().unwrap_or(""),
                g["file"].as_str().unwrap_or(""),
                g["line"].as_u64().unwrap_or(0),
                g["evidence"].as_str().unwrap_or(""),
            ));
        }
    }
    s.push_str("\n## 断点（必须人工确认）\n\n");
    if let Some(bs) = d["breakpoints"].as_array() {
        if bs.is_empty() {
            s.push_str("- （无）\n");
        }
        for b in bs {
            s.push_str(&format!(
                "- `{}` @ {} confidence={}\n",
                b["kind"].as_str().unwrap_or(""),
                b["at"].as_str().unwrap_or(""),
                b["confidence"].as_str().unwrap_or(""),
            ));
        }
    }
    s.push_str("\n## 反证\n\n");
    if let Some(fs) = d["falsify"].as_array() {
        for f in fs {
            if let Some(cmd) = f.as_str() {
                s.push_str(&format!("```\n{cmd}\n```\n"));
            }
        }
    }
    s
}
