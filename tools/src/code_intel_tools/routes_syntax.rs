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
                // `lhs := parent.Group("/prefix")`：lhs 是新组变量，parent 是父接收者
                let head = &raw_t[..g];
                let lhs = head
                    .split([':', '='])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let parent = head
                    .split([':', '='])
                    .nth(1)
                    .unwrap_or("")
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
    out
}

// ────────────────────────────── 函数式路由（WebFlux）──────────────────────────────

/// 函数式路由：`RouterFunctions.route(...)` / builder 风格 `.GET("/x", ...)`。
///
/// 窗口法：动词（`GET(`/`POST(`…）出现在**代码视图**里，但路径字面量必须从**原文**取；
/// 允许**跨多行**与 `.or(...)` 嵌套（每个动词各自成一条），窗口上限 240 字符 / 5 行。
pub(crate) fn functional_routes_window(content: &str) -> Vec<(u32, String, String)> {
    let looks_functional = content.contains("RouterFunction")
        || content.contains("RouterFunctions")
        || content.contains("ServerResponse");
    if !looks_functional {
        return Vec::new();
    }
    let code = code_lines(content, hash_comment_language("FunctionalRoutes.java"));
    let raw_lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<(u32, String, String)> = Vec::new();
    const VERBS: [(&str, &str); 5] = [
        ("GET(", "GET"),
        ("POST(", "POST"),
        ("PUT(", "PUT"),
        ("DELETE(", "DELETE"),
        ("PATCH(", "PATCH"),
    ];
    for (idx, line) in code.iter().enumerate() {
        let t = line.trim();
        if t.is_empty() || is_import_or_package_line(t) {
            continue;
        }
        let first = raw_lines.get(idx).copied().unwrap_or("");
        // 原文窗口：本行 + 后续 4 行（跨行声明与 .or() 嵌套）
        let mut window = String::new();
        for off in 0..5 {
            if let Some(l) = raw_lines.get(idx + off) {
                window.push_str(l);
                window.push('\n');
            }
        }
        for (marker, method) in VERBS {
            let mut from = 0usize;
            while let Some(pos) = first[from..].find(marker) {
                let abs = from + pos;
                let after_start = abs + marker.len();
                if after_start < window.len() {
                    let after = &window[after_start..];
                    let slice = &after[..after.len().min(240)];
                    if let Some(p) = url_patterns_in(slice).into_iter().next() {
                        if !out.iter().any(|(l, m, path)| {
                            *l == (idx + 1) as u32 && m == method && *path == p
                        }) {
                            out.push(((idx + 1) as u32, method.to_string(), p));
                        }
                    }
                }
                from = abs + marker.len();
                if from >= first.len() {
                    break;
                }
            }
        }
    }
    out
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
