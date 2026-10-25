// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 路由声明的**语法级**扫描（非注解式栈）与**模块图**（多模块配置归属）。
//!
//! 与旧实现的区别：不再靠字面 marker + "取行内首个字面量"，而是
//! ① 识别"接收者.动词("的调用形态（区分路由注册与 HTTP 客户端调用）；
//! ② 组/mount 前缀链（Go `Group`、Express `use`）；
//! ③ 字面量种类（单/双引号、模板字符串）与**跨行**声明；
//! ④ 函数式路由（WebFlux `RouterFunctions.route(...)` / `.GET(...)`）用**括号窗口**取路径，
//!    覆盖多行与 `.or()` 嵌套。
//!
//! 一切都只做"声明事实"抽取，不判断语义；取不到就留空并由上层如实标注。

use serde_json::{json, Value};

use super::*;

// ────────────────────────────── 通用小工具 ──────────────────────────────

/// 非 Java 栈里"接收者是 HTTP 客户端"的常见名字：它们的 `.get(...)` 不是路由声明。
const CLIENT_BASES: [&str; 19] = [
    "axios", "http", "https", "request", "fetch", "supertest", "agent", "client", "ky", "got",
    "page", "this", "window", "document", "conn",
    // 端到端测试里的链式调用（`cy.get('/api/x')`）不是路由声明
    "cy", "cypress", "visit", "intercept",
];

fn normalize_path(p: &str) -> String {
    let t = p.trim();
    if t.is_empty() {
        return String::new();
    }
    if t.starts_with('/') {
        t.to_string()
    } else {
        format!("/{t}")
    }
}

/// 拼接组/mount 前缀与相对路径（单斜杠规范化）。
pub(crate) fn join_route_path(prefix: Option<&str>, path: &str) -> String {
    let p = normalize_path(path);
    match prefix {
        Some(px) if !px.trim().is_empty() => {
            let mut s = format!(
                "{}/{}",
                normalize_path(px).trim_end_matches('/'),
                p.trim_start_matches('/')
            );
            while s.contains("//") {
                s = s.replace("//", "/");
            }
            s
        }
        _ => p,
    }
}

/// 形如 `<recv>.<verb>(` 的调用头。返回 (接收者, 动词, 实参起点)。
fn parse_call_head(t: &str) -> Option<(String, String, usize)> {
    let dot = t.find('.')?;
    let recv = t[..dot].trim();
    if recv.is_empty() || !recv.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$') {
        return None;
    }
    let rest = &t[dot + 1..];
    let paren = rest.find('(')?;
    let verb = rest[..paren].trim();
    if verb.is_empty() || !verb.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    Some((recv.to_string(), verb.to_string(), dot + 1 + paren + 1))
}

fn verb_to_method(verb: &str, go_style: bool) -> Option<&'static str> {
    let v = if go_style {
        match verb {
            "GET" => "get",
            "POST" => "post",
            "PUT" => "put",
            "DELETE" => "delete",
            "PATCH" => "patch",
            "HEAD" => "head",
            "OPTIONS" => "options",
            "Any" => "any",
            "Handle" => "handle",
            other => other,
        }
    } else {
        verb
    };
    match v.to_ascii_lowercase().as_str() {
        "get" => Some("GET"),
        "post" => Some("POST"),
        "put" => Some("PUT"),
        "delete" => Some("DELETE"),
        "patch" => Some("PATCH"),
        "head" => Some("HEAD"),
        "options" => Some("OPTIONS"),
        "any" | "all" => Some("ANY"),
        "handle" => Some("ANY"),
        _ => None,
    }
}

/// 从（可能跨行的）片段里取首个路由字面量。
///
/// 模板字符串含插值（`` `/api/${id}` ``）时**不猜**：路径不可静态确定，交给上层标注未解析。
fn literal_in(segment: &str) -> Option<String> {
    let templated = segment.split('`').nth(1);
    if let Some(t) = templated {
        if t.contains("${") {
            return None;
        }
    }
    let raw = segment
        .split('"')
        .nth(1)
        .or_else(|| segment.split('\'').nth(1))
        .or_else(|| templated)?
        .trim();
    if raw.is_empty() || raw.contains(char::is_whitespace) && raw.len() > 200 {
        return None;
    }
    Some(normalize_path(raw))
}

/// 解析 `methods=['GET','POST']` / `methods={GET, POST}`（Flask/FastAPI）。
fn parse_methods_list(segment: &str) -> Vec<&'static str> {
    let Some(pos) = segment.find("methods") else {
        return Vec::new();
    };
    let rest = &segment[pos..];
    let mut out: Vec<&'static str> = Vec::new();
    for (kw, m) in [
        ("GET", "GET"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("DELETE", "DELETE"),
        ("PATCH", "PATCH"),
        ("HEAD", "HEAD"),
        ("OPTIONS", "OPTIONS"),
    ] {
        if rest.to_uppercase().contains(kw) {
            out.push(m);
        }
    }
    out
}

fn push_route(
    out: &mut Vec<Value>,
    line: u32,
    text: &str,
    method: Option<&str>,
    full: String,
    raw: &str,
    role: &'static str,
    source: &str,
) {
    if out.iter().any(|r| {
        r["line"].as_u64() == Some(line as u64)
            && r["route"].as_str() == Some(full.as_str())
            && r["http_method"].as_str() == method
    }) {
        return;
    }
    out.push(json!({
        "line": line,
        "text": text.trim().chars().take(200).collect::<String>(),
        "route": if full.is_empty() { Value::Null } else { json!(full) },
        "route_raw": if raw.is_empty() { Value::Null } else { json!(raw) },
        "scope": "method",
        "http_method": method,
        "route_source": source,
        "file_role": role,
        "route_path_unresolved": full.is_empty(),
    }));
}

// ────────────────────────────── 非注解式路由扫描 ──────────────────────────────

/// 该文件是否由**语法扫描器**处理（Go / JS / TS / Python）。
///
/// 其它非 Java 语言（PHP / Ruby / Rust…）没有语法扫描器，继续走标记扫描路径，
/// 免得"换了实现反而丢了原来能认出来的路由"。
pub(crate) fn has_syntax_scanner(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("");
    matches!(ext, "go" | "py" | "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx")
}

/// 语法级扫描：Go（gin 风格 Group）、JS/TS（Express 风格 use/mount）、Python（Flask 装饰器）。
///
/// 只对**代码视图**做调用识别（注释里的不算），路径字面量从**原文**取（代码视图会抹字符串）。
pub(crate) fn scan_non_java_routes(path: &str, content: &str) -> Vec<Value> {
    scan_non_java_routes_with_prefix(path, content, "")
}

/// 带跨文件 mount 前缀的语法扫描：`app.use('/api', posts)` 挂载的子路由文件整体加前缀。
pub(crate) fn scan_non_java_routes_with_prefix(
    path: &str,
    content: &str,
    mount_prefix: &str,
) -> Vec<Value> {
    let role = policy_file_role(path);
    let raw: Vec<&str> = content.lines().collect();
    let code = code_lines(content, hash_comment_language(path));
    let ext = path.rsplit('.').next().unwrap_or("");
    let is_go = ext == "go";
    let is_py = ext == "py";
    if !(is_go || is_py || matches!(ext, "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx")) {
        return Vec::new();
    }
    let mut prefixes: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut out: Vec<Value> = Vec::new();

    // 前置：组 / mount 前缀（同文件内）
    for (idx, line) in code.iter().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        // 前缀声明要从**原文**（含字符串）里解析：代码视图会把字面量抹掉
        let raw_t = raw.get(idx).copied().unwrap_or("").trim();
        if is_go {
            // `api := r.Group("/api")`
            if let Some(g) = raw_t.find(".Group(") {
                // `lhs := parent.Group("/prefix")`：lhs 是新组变量，parent 是父接收者。
                // 注意：`:=` 里含 `:`，必须先按 `:=`/`=` 切分再取 parent，
                // 否则 `v1 := api.Group(...)` 的 parent 会被切成空串（嵌套组前缀丢失）。
                let head = &raw_t[..g];
                let (lhs_raw, rhs_raw) = match head.split_once(":=") {
                    Some((l, r)) => (l, r),
                    None => head.split_once('=').unwrap_or((head, "")),
                };
                let lhs = lhs_raw.trim().to_string();
                let parent = rhs_raw
                    .trim()
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if let Some(pre) = literal_in(&raw_t[g + 7..]) {
                    let base = prefixes.get(&parent).cloned().unwrap_or_default();
                    let full = join_route_path(Some(&base), &pre);
                    if !lhs.is_empty() {
                        prefixes.insert(lhs, full);
                    }
                }
            }
        } else if !is_py {
            // `app.use('/api', router)`
            if let Some(u) = raw_t.find(".use(") {
                let recv = raw_t[..u]
                    .rsplit([':', '=', ' '])
                    .find(|s| !s.trim().is_empty())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let seg = raw_t;
                if let Some(pre) = literal_in(&seg[u..]) {
                    let after = &seg[u..];
                    let child = after
                        .split_once(',')
                        .map(|(_, rest)| {
                            rest.trim()
                                .trim_end_matches(')')
                                .trim()
                                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                                .next()
                                .unwrap_or("")
                                .to_string()
                        })
                        .unwrap_or_default();
                    if !child.is_empty() {
                        let base = prefixes.get(&recv).cloned().unwrap_or_default();
                        prefixes.insert(child, join_route_path(Some(&base), &pre));
                    }
                }
            }
        }
    }

    // 路由声明
    for (idx, line) in code.iter().enumerate() {
        let t = line.trim();
        if t.is_empty() || is_import_or_package_line(t) {
            continue;
        }
        let raw_line = raw.get(idx).copied().unwrap_or("");
        let ln = (idx + 1) as u32;

        // Python：装饰器
        if is_py {
            if let Some(rest) = t.strip_prefix('@') {
                if let Some(dot) = rest.find('.') {
                    let rest2 = &rest[dot + 1..];
                    if let Some(paren) = rest2.find('(') {
                        let name = &rest2[..paren];
                        // 只认**路由类**装饰器：`@app.route` / `@bp.get` / `@api_route`。
                        // 其它装饰器（`@register.filter()`、`@login_required` 等）不是路由，不能默认成 GET。
                        let recv = &rest[..dot];
                        let known_verb = verb_to_method(name, false).is_some();
                        // 接收者必须像 Web 应用/蓝图（`@app.get` / `@bp.post` / `@api_x.get`），
                        // 否则 `@mock.patch()` 会被当成 PATCH 路由。
                        let recv_ok = matches!(
                            recv,
                            "app" | "bp" | "blueprint" | "router" | "api" | "web" | "server"
                        ) || recv.ends_with("_app")
                            || recv.ends_with("_bp")
                            || recv.ends_with("_router")
                            || recv.ends_with("_api")
                            || recv.ends_with("api")
                            || recv.ends_with("router");
                        let is_route_name = name == "route"
                            || name == "api_route"
                            || name.ends_with("route");
                        if !(is_route_name || (known_verb && recv_ok)) {
                            continue;
                        }
                        let seg = raw_line;
                        if let Some(p) = literal_in(&seg[seg.find('(').unwrap_or(0)..]) {
                            let args = &seg[seg.find('(').unwrap_or(0)..];
                            let methods = if name == "route" || name == "api_route" {
                                parse_methods_list(args)
                            } else {
                                verb_to_method(name, false).map(|m| vec![m]).unwrap_or_default()
                            };
                            for m in if methods.is_empty() { vec!["GET"] } else { methods } {
                                push_route(&mut out, ln, t, Some(m), p.clone(), &p, role, "syntax_scan");
                            }
                            continue;
                        }
                    }
                }
            }
        }

        // Python 只认装饰器声明（`@app.route` / `@bp.get` …）；`x.get('/p')` 不是路由
        if is_py {
            continue;
        }
        let Some((recv, verb, _)) = parse_call_head(t) else {
            continue;
        };
        let Some(method) = verb_to_method(&verb, is_go) else {
            continue;
        };
        if !is_go && !is_py && CLIENT_BASES.contains(&recv.as_str()) {
            continue;
        }
        // 路径字面量：本行优先，其次有界前瞻（≤3 行，跨行声明）
        let mut lit: Option<String> = None;
        if let Some(p) = literal_in(raw_line) {
            lit = Some(p);
        } else {
            for off in 1..=3usize {
                if let Some(next) = raw.get(idx + off) {
                    if next.trim().is_empty() {
                        continue;
                    }
                    if let Some(p) = literal_in(next) {
                        lit = Some(p);
                        break;
                    }
                }
            }
        }
        if let Some(p) = lit {
            let full = join_route_path(prefixes.get(&recv).map(|s| s.as_str()), &p);
            push_route(&mut out, ln, t, Some(method), full, &p, role, "syntax_scan");
        }
    }

    // Express：`router.route('/x').get(h).post(h)`
    if !is_py && !is_go {
        for (idx, line) in code.iter().enumerate() {
            let t = line.trim();
            if let Some(r) = t.find(".route(") {
                let raw_line = raw.get(idx).copied().unwrap_or("");
                let Some(route_path) = literal_in(&raw_line[r..]) else {
                    continue;
                };
                // 链式声明也要带 mount 前缀：取 `.route(` 之前的接收者（可能是 `this.router`）
                let recv = t[..r]
                    .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '.'))
                    .filter(|s| !s.is_empty())
                    .last()
                    .unwrap_or("")
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .to_string();
                let prefixed = join_route_path(prefixes.get(&recv).map(|s| s.as_str()), &route_path);
                let after = &raw_line[r..];
                let mut found = false;
                for (kw, m) in [
                    (".get(", "GET"),
                    (".post(", "POST"),
                    (".put(", "PUT"),
                    (".delete(", "DELETE"),
                    (".patch(", "PATCH"),
                ] {
                    if after.contains(kw) {
                        push_route(
                            &mut out,
                            (idx + 1) as u32,
                            t,
                            Some(m),
                            prefixed.clone(),
                            &route_path,
                            role,
                            "syntax_scan",
                        );
                        found = true;
                    }
                }
                let _ = found;
            }
        }
    }
    // 跨文件 mount 前缀：整个文件的相对路由再拼一层
    if !mount_prefix.is_empty() && mount_prefix != "/" {
        for r in out.iter_mut() {
            if let Some(obj) = r.as_object_mut() {
                let cur = obj
                    .get("route")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !cur.is_empty() {
                    obj.insert(
                        "route".to_string(),
                        json!(join_route_path(Some(mount_prefix), &cur)),
                    );
                }
            }
        }
    }
    out
}

// ────────────────────────────── 函数式路由（WebFlux）──────────────────────────────

/// 函数式路由：`RouterFunctions.route(...)` / builder 风格 `.GET("/x", ...)`。
///
/// 两件事：
/// 1. **前缀作用域**：`route().nest(path("/p"), () -> route()...)` 与
///    `route().path("/p", b -> b.GET(...))` 里的动词声明要带上前缀（Spring 语义是拼接）；
///    作用域用**括号配平**在代码视图上求，路径字面量从原文取（代码视图会抹掉字符串）。
/// 2. **动词窗口**：不在前缀作用域里的动词，从本行起向后最多 5 行 / 240 字符找路径字面量，
///    覆盖跨行与 `.or()` 嵌套；同一次声明去重。
pub(crate) fn functional_routes_window(content: &str) -> Vec<(u32, String, String)> {
    let looks_functional = content.contains("RouterFunction")
        || content.contains("RouterFunctions")
        || content.contains("ServerResponse");
    if !looks_functional {
        return Vec::new();
    }
    let code = code_lines(content, hash_comment_language("FunctionalRoutes.java"));
    let raw_lines: Vec<&str> = content.lines().collect();
    // 行首在扁平文本里的偏移（代码视图；用于括号配平与位置→行号映射）
    let mut offsets: Vec<usize> = Vec::with_capacity(code.len());
    let mut flat = String::new();
    for line in code.iter() {
        offsets.push(flat.len());
        flat.push_str(line);
        flat.push('\n');
    }
    let line_of = |pos: usize| -> usize {
        match offsets.binary_search(&pos) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        }
    };

    // ① 前缀作用域：nest(path("/p"), ...) 与 .path("/p", ...)
    let mut scopes: Vec<(usize, usize, String)> = Vec::new(); // (start, end, prefix)
    for kw in [".nest(", ".path("] {
        let mut from = 0usize;
        while let Some(p) = flat[from..].find(kw) {
            let open = from + p + kw.len() - 1; // '(' 的位置
            if let Some(close) = matching_paren(&flat, open) {
                let line = line_of(from + p);
                // 前缀字面量：作用域开头附近最多 4 行内取 `path("...")` 或 `.path("...")` 的首个字面量
                let mut prefix: Option<String> = None;
                for off in 0..4usize {
                    if let Some(raw) = raw_lines.get(line + off) {
                        if let Some(v) = literal_in(raw) {
                            prefix = Some(normalize_path(&v));
                            break;
                        }
                    }
                }
                if let Some(px) = prefix {
                    scopes.push((open, close, px));
                }
                from = close.max(from + 1);
            } else {
                from = from + p + kw.len();
            }
        }
    }

    // ② 动词声明：取最近的**最内层**前缀作用域
    const VERBS: [(&str, &str); 5] = [
        ("GET(", "GET"),
        ("POST(", "POST"),
        ("PUT(", "PUT"),
        ("DELETE(", "DELETE"),
        ("PATCH(", "PATCH"),
    ];
    let mut out: Vec<(u32, String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<(usize, String, String)> = std::collections::HashSet::new();
    for (marker, method) in VERBS {
        let mut from = 0usize;
        while let Some(p) = flat[from..].find(marker) {
            let abs = from + p;
            let line = line_of(abs);
            // 只认**行内**的动词（跨行匹配由窗口负责）
            if abs < offsets[line] || abs >= offsets.get(line + 1).copied().unwrap_or(flat.len()) {
                from = abs + marker.len();
                continue;
            }
            let mut prefix: Option<&str> = None;
            let mut best = usize::MAX;
            for (s0, s1, px) in scopes.iter() {
                if abs > *s0 && abs < *s1 && (*s0) < best {
                    best = *s0;
                    prefix = Some(px.as_str());
                }
            }
            // 路径字面量：本行优先，其次向后最多 4 行（跨行声明）
            let mut path: Option<String> = None;
            for off in 0..5usize {
                if let Some(raw) = raw_lines.get(line + off) {
                    if off == 0 {
                        // 本行：从动词之后找，避免把接收者里的字符串当路径
                        let seg_start = raw.find(marker).map(|x| x + marker.len()).unwrap_or(0);
                        if let Some(v) = literal_in(&raw[seg_start..]) {
                            path = Some(v);
                            break;
                        }
                    } else if !raw.trim().is_empty() {
                        if let Some(v) = literal_in(raw) {
                            path = Some(v);
                            break;
                        }
                    }
                }
            }
            let full = match (&path, prefix) {
                (Some(p), Some(px)) => join_route_path(Some(px), p),
                (Some(p), None) => normalize_path(p),
                // 只有前缀、动词本身没有路径：端点就是前缀（Spring `nest` 语义）
                (None, Some(px)) => px.to_string(),
                (None, None) => String::new(),
            };
            if !full.is_empty() && seen.insert((line, method.to_string(), full.clone())) {
                out.push((line as u32 + 1, method.to_string(), full));
            }
            from = abs + marker.len();
        }
    }
    out.sort_by_key(|(l, _, _)| *l);
    out
}

/// 在扁平代码文本上做括号配平（代码视图已抹掉字符串与注释，所以括号计数安全）。
fn matching_paren(flat: &str, open: usize) -> Option<usize> {
    if flat.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    for (i, ch) in flat.char_indices().skip_while(|(i, _)| *i < open) {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// ────────────────────────────── 模块图（多模块配置归属）──────────────────────────────

/// Maven 模块图：模块目录 → (artifactId, 依赖 artifactId)。
///
/// 用途：多模块项目里"某条安全链是否作用于某个端点文件"。判定规则与工具链语义一致：
/// **同模块，或链所在模块是端点模块的（传递）依赖** ⇒ 生效；根目录 pom 视为全局配置。
pub(crate) struct ModuleGraph {
    modules: Vec<(String, String, Vec<String>)>,
}

impl ModuleGraph {
    pub(crate) fn from_files(files: &[(String, String)]) -> Self {
        let mut modules: Vec<(String, String, Vec<String>)> = Vec::new();
        for (path, content) in files.iter() {
            if !path.ends_with("pom.xml") {
                continue;
            }
            let dir = path
                .rsplit_once('/')
                .map(|(d, _)| d.to_string())
                .unwrap_or_default()
                .replace('\\', "/");
            let dir = dir.trim_end_matches('/').to_string();
            // `<parent>` 块里的 artifactId 是父 POM，不是本模块；先剥掉再解析
            let mut body = content.to_string();
            if let Some(p) = body.find("<parent>") {
                if let Some(e) = body[p..].find("</parent>") {
                    body.replace_range(p..p + e + "</parent>".len(), "");
                }
            }
            let mut arts: Vec<String> = Vec::new();
            let mut rest = body.as_str();
            while let Some(start) = rest.find("<artifactId>") {
                let after = &rest[start + "<artifactId>".len()..];
                let Some(end) = after.find("</artifactId>") else {
                    break;
                };
                let v = after[..end].trim();
                if !v.is_empty() {
                    arts.push(v.to_string());
                }
                rest = &after[end + "</artifactId>".len()..];
            }
            if arts.is_empty() {
                continue;
            }
            let own = arts[0].clone();
            let deps: Vec<String> = arts.into_iter().skip(1).collect();
            modules.push((dir, own, deps));
        }
        // 深的目录优先（最长前缀匹配）
        modules.sort_by_key(|(d, _, _)| std::cmp::Reverse(d.len()));
        Self { modules }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// 文件属于哪个模块（最长目录前缀；根目录 pom 不算模块，返回 None）。
    pub(crate) fn module_of(&self, path: &str) -> Option<usize> {
        let p = path.replace('\\', "/");
        for (i, (dir, _, _)) in self.modules.iter().enumerate() {
            if dir.is_empty() {
                continue;
            }
            if p.starts_with(dir.as_str())
                && (p.len() == dir.len() || p[dir.len()..].starts_with('/'))
            {
                return Some(i);
            }
        }
        None
    }

    fn depends_on(&self, module: usize, dep: usize) -> bool {
        if module == dep {
            return true;
        }
        let target = &self.modules[dep].1;
        let mut stack = vec![module];
        let mut seen = std::collections::HashSet::new();
        while let Some(m) = stack.pop() {
            if !seen.insert(m) {
                continue;
            }
            for d in &self.modules[m].2 {
                if d == target {
                    return true;
                }
                if let Some(next) = self.modules.iter().position(|(_, a, _)| a == d) {
                    stack.push(next);
                }
            }
        }
        false
    }

    /// 某条安全链是否作用于某端点文件。
    pub(crate) fn chain_applies(&self, chain_file: &str, route_file: &str) -> bool {
        let cm = self.module_of(chain_file);
        let rm = self.module_of(route_file);
        match (cm, rm) {
            (None, _) => true,          // 根/全局配置
            (Some(_), None) => true,    // 端点不在任何模块内：保守保留
            (Some(c), Some(r)) => self.depends_on(r, c),
        }
    }

    /// 为某个端点文件挑选生效链；返回（链, 作用域口径）。
    ///
    /// 口径：`module_affinity`（按模块筛过）、`all_modules_single`（没有可筛的依据）、
    /// `fallback_all_modules`（按模块筛完为空 ⇒ 回退全量，避免误报"无保护"）。
    pub(crate) fn scoped_chains(
        &self,
        chains: &[SecurityChain],
        route_file: &str,
    ) -> (Vec<SecurityChain>, &'static str) {
        if self.is_empty() || chains.is_empty() {
            return (chains.to_vec(), "all_modules_single");
        }
        let keep: Vec<SecurityChain> = chains
            .iter()
            .filter(|c| self.chain_applies(&c.file, route_file))
            .cloned()
            .collect();
        if keep.is_empty() {
            return (chains.to_vec(), "fallback_all_modules");
        }
        if keep.len() == chains.len() {
            return (keep, "all_modules_single");
        }
        (keep, "module_affinity")
    }
}


// ────────────────────────── 跨文件 Express mount 前缀（R253）──────────────────────────

fn is_js_like(path: &str) -> bool {
    matches!(
        path.rsplit('.').next().unwrap_or(""),
        "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx"
    )
}

fn is_ident_str(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .next()
            .map(|c| c.is_alphabetic() || c == '_' || c == '$')
            .unwrap_or(false)
        && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// `require('...')` / `require("...")` 里的模块说明符。
fn require_spec(text: &str) -> Option<String> {
    let pos = text.find("require(")?;
    let rest = text[pos + "require(".len()..].trim_start();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after = &rest[1..];
    let end = after.find(quote)?;
    Some(after[..end].to_string())
}

/// `import x from './x'` 的模块说明符。
fn import_spec(line: &str) -> Option<String> {
    let t = line.trim();
    if !t.starts_with("import ") {
        return None;
    }
    let pos = t.find(" from ")?;
    let rest = t[pos + " from ".len()..].trim();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let after = &rest[1..];
    let end = after.find(quote)?;
    Some(after[..end].to_string())
}

/// 相对模块说明符 → 项目内文件路径（尝试常见扩展名与 index 文件）。
fn resolve_js_module(from_path: &str, spec: &str, files: &[(String, String)]) -> Option<String> {
    if !spec.starts_with('.') {
        return None;
    }
    let dir = match from_path.rsplit_once('/') {
        Some((d, _)) => d.to_string(),
        None => String::new(),
    };
    let joined_raw = if dir.is_empty() {
        spec.to_string()
    } else {
        format!("{dir}/{spec}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in joined_raw.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    let candidates = [
        joined.clone(),
        format!("{joined}.js"),
        format!("{joined}.mjs"),
        format!("{joined}.cjs"),
        format!("{joined}.ts"),
        format!("{joined}.tsx"),
        format!("{joined}/index.js"),
        format!("{joined}/index.ts"),
    ];
    let set: std::collections::BTreeSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    candidates.into_iter().find(|c| set.contains(c.as_str()))
}

/// 跨文件 Express mount 前缀：`app.use('/api', posts)` + `const posts = require('./routes/posts')`
/// ⇒ `routes/posts.js` 里的 `router.get('/x')` 合成 `/api/x`。
///
/// 只处理相对模块说明符，嵌套深度上限 5；同一文件多处挂载时取首个前缀（更复杂的场景保留待办）。
pub(crate) fn express_mount_prefixes(
    files: &[(String, String)],
) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;
    let mut bindings: HashMap<String, HashMap<String, String>> = HashMap::new();
    for (path, content) in files.iter() {
        if !is_js_like(path) {
            continue;
        }
        let mut map: HashMap<String, String> = HashMap::new();
        for line in content.lines() {
            let t = line.trim();
            if let Some((lhs, rhs)) = t.split_once('=') {
                let ident = lhs
                    .trim()
                    .trim_start_matches("const ")
                    .trim_start_matches("let ")
                    .trim_start_matches("var ")
                    .trim();
                if is_ident_str(ident) {
                    if let Some(spec) = require_spec(rhs) {
                        if let Some(target) = resolve_js_module(path, &spec, files) {
                            map.insert(ident.to_string(), target);
                        }
                    }
                }
            }
            if let Some(spec) = import_spec(t) {
                let head = t.trim_start_matches("import ").trim();
                let ident = head.split_whitespace().next().unwrap_or("");
                if is_ident_str(ident) {
                    if let Some(target) = resolve_js_module(path, &spec, files) {
                        map.insert(ident.to_string(), target);
                    }
                }
            }
        }
        if !map.is_empty() {
            bindings.insert(path.clone(), map);
        }
    }

    let mut edges: Vec<(String, String, String)> = Vec::new();
    for (path, content) in files.iter() {
        if !is_js_like(path) {
            continue;
        }
        for line in content.lines() {
            let t = line.trim();
            let Some(u) = t.find(".use(") else { continue };
            let Some(pre) = literal_in(&t[u..]) else { continue };
            let after = &t[u..];
            let child_expr = after
                .split_once(',')
                .map(|(_, r)| r.trim().trim_end_matches(')').trim())
                .unwrap_or("");
            if child_expr.is_empty() {
                continue;
            }
            let child_file = if let Some(spec) = require_spec(child_expr) {
                resolve_js_module(path, &spec, files)
            } else {
                let ident = child_expr
                    .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                    .next()
                    .unwrap_or("");
                bindings.get(path).and_then(|b| b.get(ident)).cloned()
            };
            if let Some(cf) = child_file {
                edges.push((path.clone(), pre, cf));
            }
        }
    }

    let mut prefix: HashMap<String, String> = HashMap::new();
    for _ in 0..5 {
        let mut changed = false;
        for (parent, pre, child) in edges.iter() {
            if prefix.contains_key(child) {
                continue;
            }
            let base = prefix.get(parent).cloned().unwrap_or_default();
            let full = if base.is_empty() {
                join_route_path(None, pre)
            } else {
                join_route_path(Some(&base), pre)
            };
            prefix.insert(child.clone(), full);
            changed = true;
        }
        if !changed {
            break;
        }
    }
    prefix
}
