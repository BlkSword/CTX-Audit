// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 端点表 / 单条路由判定 / 敏感返回面 —— `get_project_routes`、`explain_route` 与 CLI 共用。
//!
//! 设计要点（R249 能力实测的产物）：
//!
//! - **端点表逻辑只写一次**：项目级扫描（策略链只构建一次 → 逐文件标注覆盖）在这里实现，
//!   MCP 工具与 `ctx-audit diff-routes` 都调它，避免两条口径漂移。
//! - **索引截断必须影响结论**：内容索引达到文件数上限时，路由表本身就是残缺的，
//!   此时任何 `no_global_config_found` 都不可信 → 降级为 `coverage_unknown` 并带 caveat，
//!   而不是继续输出"高置信的错答案"。
//! - **单条路由判定要可机械证伪**：`explain_route` 输出 decided_by（逐项检查 + 出处）
//!   与 `falsify`（一条能跑的命令），把"信任成本"换成"运行一条命令"。
//! - **敏感返回面**是启发式：只报在 handler 窗口里**读到**的字段名命中，不推断泄漏。

use super::*;

/// 敏感字段命名线索（小写匹配）。只做"读到即报"，不做推断。
pub(crate) const SENSITIVE_FIELD_HINTS: [&str; 17] = [
    "password",
    "passwd",
    "pwd",
    "secret",
    "aes",
    "aeskey",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "api_key",
    "accesskey",
    "secretkey",
    "credential",
    "privatekey",
    "adminusername",
    "sessionid",
];

/// 鉴权注解名单（方法级/类级）。命中即视为"声明式鉴权注解存在"。
pub(crate) const AUTH_ANNOTATIONS: [&str; 12] = [
    "SaCheckLogin",
    "SaCheckRole",
    "SaCheckPermission",
    "SaCheckSafe",
    "PreAuthorize",
    "PostAuthorize",
    "RequiresPermissions",
    "RequiresRoles",
    "Secured",
    "RolesAllowed",
    "PermitAll",
    "DenyAll",
];

/// 端点表过滤参数（与工具入参一一对应）。
#[derive(Clone, Debug)]
pub(crate) struct RouteFilter {
    pub(crate) min_role: String,
    pub(crate) route_pattern: String,
    pub(crate) only_uncovered: bool,
}

impl Default for RouteFilter {
    fn default() -> Self {
        Self {
            min_role: "production".to_string(),
            route_pattern: String::new(),
            only_uncovered: false,
        }
    }
}

/// 一次端点扫描的完整产物：`data` 即信封里的 `data` 对象。
pub(crate) struct RouteTable {
    pub(crate) data: Value,
    pub(crate) provenance: Vec<Provenance>,
    pub(crate) reasons: Vec<&'static str>,
    /// 内容索引是否因文件数上限被截断（决定结论可信度）
    pub(crate) index_truncated: bool,
}

/// `coverage_unknown` 之外的"未覆盖"判定集合。
pub(crate) fn is_uncovered_verdict(v: &str) -> bool {
    matches!(
        v,
        "no_global_config_found" | "no_global_match_found" | "coverage_unknown"
    )
}

/// 项目级端点表：策略链只构建一次，再逐文件标注覆盖（O(N) 而非逐文件 O(N²)）。
pub(crate) fn compute_routes(
    root: &Path,
    files: &[(String, String)],
    id: &str,
    refresh: bool,
    filter: &RouteFilter,
    index_truncated: bool,
) -> RouteTable {
    let bundle = policy_bundle(root, files, id);
    let policy_files: &[(String, String)] = &bundle.files;
    let excluded_policy_sources = bundle.excluded.clone();
    let mut all_chains = security_config_chains(policy_files);
    all_chains.extend(reactive_security_chains(policy_files));
    all_chains.extend(spring_xml_security_chains(policy_files));
    all_chains.extend(shiro_filter_chains(policy_files));
    all_chains.extend(sa_token_security_chains(policy_files));
    let container_filters = container_filter_registrations(policy_files);
    let interceptor_regs = interceptor_registrations(policy_files);
    let mut routes: Vec<Value> = Vec::new();
    let mut provenance: Vec<Provenance> = Vec::new();
    let mut routes_total = 0usize;
    let mut files_with_routes = 0usize;
    let mut truncated_at_limit = false;
    let mut nonproduction_files_present = 0usize;
    let mut unparsed_route_files = 0usize;
    let mut unparsed_route_samples: Vec<Value> = Vec::new();
    let mut route_roles: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let (sindex, _, _) = crate::symbol_index::get_or_build(root, refresh, None);
    for (path, content) in files.iter() {
        if !crate::symbol_index::is_code_file(path) {
            continue;
        }
        if policy_file_role(path) != "production" {
            nonproduction_files_present += 1;
        }
        if let Some(fw_name) = unmodelled_route_declaration(path, content) {
            unparsed_route_files += 1;
            if unparsed_route_samples.len() < 5 {
                unparsed_route_samples.push(json!({"file": path, "framework": fw_name}));
            }
        }
        let scan = scan_routes_in_file(path, content, "", id);
        if scan.routes_total > 0 {
            files_with_routes += 1;
        }
        routes_total += scan.routes_total;
        for mut r in scan.routes {
            if routes.len() >= MAX_PROJECT_ROUTE_HITS {
                truncated_at_limit = true;
                break;
            }
            if let Some(obj) = r.as_object_mut() {
                obj.insert("file".to_string(), json!(path));
            }
            let role = r
                .get("file_role")
                .and_then(|v| v.as_str())
                .unwrap_or("production")
                .to_string();
            *route_roles.entry(role).or_insert(0) += 1;
            if let Some(line) = r.get("line").and_then(|v| v.as_u64()) {
                provenance.push(prov(path, line as u32, id));
            }
            routes.push(r);
        }
        if truncated_at_limit {
            break;
        }
    }
    // 多模块：按端点所在文件挑生效链，逐文件标注 `coverage_scope`
    let graph = &bundle.graph;
    let mut by_file: std::collections::BTreeMap<String, Vec<usize>> = Default::default();
    for (i, r) in routes.iter().enumerate() {
        if let Some(f) = r.get("file").and_then(|v| v.as_str()) {
            by_file.entry(f.to_string()).or_default().push(i);
        }
    }
    for (file, idxs) in by_file.iter() {
        let (scoped, scope_label) = graph.scoped_chains(&all_chains, file);
        let mut group: Vec<Value> = idxs.iter().map(|i| routes[*i].clone()).collect();
        annotate_route_coverage(&mut group, &scoped);
        annotate_container_filters(&mut group, &container_filters);
        annotate_interceptors(&mut group, &interceptor_regs);
        // 类不是 Spring Bean ⇒ 映射注解不会被注册：与 explain_route 口径保持一致，
        // 否则端点表会说"未覆盖"、单条判定会说"非端点"（R250 实测到的自相矛盾）。
        if let Some((_, content)) = files.iter().find(|(p, _)| p == file) {
            for (k, i) in idxs.iter().enumerate() {
                if group[k].get("scope").and_then(|v| v.as_str()) != Some("method") {
                    continue;
                }
                let line = routes[*i].get("line").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                if file_route_is_bean(content, line, file) == Some(false) {
                    if let Some(obj) = group[k].as_object_mut() {
                        obj.insert("not_an_endpoint".to_string(), json!(true));
                        obj.insert(
                            "coverage_caveat".to_string(),
                            json!("declaring_class_not_a_bean"),
                        );
                    }
                }
            }
        }
        for (k, i) in idxs.iter().enumerate() {
            let mut v = std::mem::take(&mut group[k]);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("coverage_scope".to_string(), json!(scope_label));
            }
            routes[*i] = v;
        }
    }
    let route_paths_unresolved = routes
        .iter()
        .filter(|r| r.get("route").map(|v| v.is_null()).unwrap_or(true))
        .count();
    let excluded_policy_json: Vec<Value> = excluded_policy_sources
        .iter()
        .map(|(p, role)| json!({"file": p, "role": role}))
        .collect();
    // 未建模保护栈（如 JAX-RS 过滤器）：项目级同样不得报"没有保护"，
    // 与单文件口径保持一致 —— 改写为 framework_not_modeled 并带 caveat。
    let unmodeled_signals = unmodeled_protection_signals(policy_files);
    if !unmodeled_signals.is_empty() && all_chains.is_empty() {
        let (fw_name, fw_file, fw_line) = unmodeled_signals[0].clone();
        for r in routes.iter_mut() {
            if r.get("scope").and_then(|v| v.as_str()) == Some("class") {
                continue;
            }
            if r.get("global_coverage").and_then(|v| v.as_str()) == Some("no_global_config_found") {
                if let Some(obj) = r.as_object_mut() {
                    obj.insert(
                        "global_coverage".to_string(),
                        json!("framework_not_modeled"),
                    );
                    obj.insert(
                        "coverage_caveat".to_string(),
                        json!("unmodeled_protection_signal"),
                    );
                    obj.insert("unmodeled_framework".to_string(), json!(fw_name));
                    obj.insert(
                        "unmodeled_source".to_string(),
                        json!({"file": fw_file, "line": fw_line}),
                    );
                }
            }
        }
    }
    // 索引截断：路由表本身残缺 → 一切"没有保护"的结论降级为 coverage_unknown。
    // 这是 R249 实测暴露的最坏失败模式（halo：3 vs 221 条路由，结论整体翻转）。
    if index_truncated {
        for r in routes.iter_mut() {
            if r.get("scope").and_then(|v| v.as_str()) == Some("class") {
                continue;
            }
            let verdict = r
                .get("global_coverage")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if verdict == "no_global_config_found" || verdict == "no_global_match_found" {
                if let Some(obj) = r.as_object_mut() {
                    obj.insert("global_coverage".to_string(), json!("coverage_unknown"));
                    obj.insert(
                        "coverage_caveat".to_string(),
                        json!("index_truncated_at_limit"),
                    );
                }
            }
        }
    }
    // A1：端点过滤（默认只保留生产角色）与「未覆盖清单」
    let min_role = filter.min_role.to_lowercase();
    let route_pattern = filter.route_pattern.to_lowercase();
    let total_before_filter = routes.len();
    let mut filtered_by_role = 0usize;
    let mut filtered_by_pattern = 0usize;
    let mut kept: Vec<Value> = Vec::new();
    for r in routes.into_iter() {
        let role = r
            .get("file_role")
            .and_then(|v| v.as_str())
            .unwrap_or("production");
        if min_role != "any" && role != min_role {
            filtered_by_role += 1;
            continue;
        }
        if !route_pattern.is_empty() {
            let rt = r
                .get("route")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if !rt.contains(&route_pattern) {
                filtered_by_pattern += 1;
                continue;
            }
        }
        kept.push(r);
    }
    let key = |r: &Value| {
        (
            r.get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            r.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
        )
    };
    kept.sort_by_key(key);
    let mut verdict_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut uncovered: Vec<Value> = Vec::new();
    let mut not_an_endpoint_count = 0usize;
    for r in kept.iter() {
        if r.get("not_an_endpoint").and_then(|v| v.as_bool()) == Some(true) {
            not_an_endpoint_count += 1;
            *verdict_counts
                .entry("not_an_endpoint".to_string())
                .or_default() += 1;
            continue;
        }
        let v = r
            .get("global_coverage")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        *verdict_counts.entry(v.clone()).or_default() += 1;
        if v == "no_global_config_found" || v == "no_global_match_found" {
            uncovered.push(r.clone());
        }
    }
    let routes: Vec<Value> = if filter.only_uncovered {
        uncovered.clone()
    } else {
        kept
    };
    let class_declarations = routes
        .iter()
        .filter(|r| r.get("scope").and_then(|v| v.as_str()) == Some("class"))
        .count();
    let mut reasons: Vec<&'static str> = vec!["project_level_scan", "syntax_scan"];
    if truncated_at_limit {
        reasons.push("truncated_at_limit");
    }
    if index_truncated {
        reasons.push("index_truncated_at_limit");
    }
    if route_paths_unresolved > 0 {
        reasons.push("route_paths_unresolved");
    }
    if !excluded_policy_json.is_empty() {
        reasons.push("policy_sources_excluded_nonproduction");
    }
    if nonproduction_files_present > 0 {
        reasons.push("nonproduction_files_present_see_route_roles");
    }
    if unparsed_route_files > 0 {
        reasons.push("unmodelled_route_declarations_present");
    }
    provenance.truncate(MAX_PROJECT_ROUTE_HITS);
    let data = json!({
        "files_indexed": files.len(),
        "files_with_routes": files_with_routes,
        "routes": routes,
        // 索引截断时"未覆盖清单"不可信：显式抑制，而不是给一份残缺工单
        "uncovered_endpoints": if index_truncated { Vec::<Value>::new() } else { uncovered.clone() },
        "uncovered_suppressed_by_truncation": index_truncated,
        "verdict_counts": verdict_counts,
        "filter": {
            "min_role": min_role,
            "route_pattern": route_pattern,
            "only_uncovered": filter.only_uncovered,
            "total_before": total_before_filter,
            "filtered_by_role": filtered_by_role,
            "filtered_by_pattern": filtered_by_pattern,
        },
        "route_roles": route_roles,
        "route_paths_unresolved": route_paths_unresolved,
        "not_an_endpoint_routes": not_an_endpoint_count,
        "total_hits": {
            "routes": routes.len(),
            "method_routes": routes.len() - class_declarations,
            "class_declarations": class_declarations,
            "counts_scope": "returned",
            "scanned_routes": routes_total,
        },
        "limit": MAX_PROJECT_ROUTE_HITS,
        "truncated_at_limit": truncated_at_limit,
        "index_truncated_at_limit": index_truncated,
        "limits": {
            "max_files": max_index_files(),
            "max_project_routes": MAX_PROJECT_ROUTE_HITS,
        },
        "unmodelled_route_files": unparsed_route_files,
        "unmodelled_route_samples": unparsed_route_samples,
        "policy_sources": {
            "used": policy_files.len(),
            "excluded_total": excluded_policy_json.len(),
            "excluded": excluded_policy_json,
        },
        "index": symbol_index_stats(&sindex, crate::symbol_index::HitSource::Miss, 0),
    });
    RouteTable {
        data,
        provenance,
        reasons,
        index_truncated,
    }
}

/// brief 视图：只留"判定所需"的字段（R249：完整信封 2.9KB/路由，无法进上下文）。
///
/// 保留字段刻意与既有消费方（工单生成器/回放脚本）对齐：
/// `route / http_method / file / line / scope / global_coverage / coverage_scope / global_match`。
pub(crate) fn brief_route(r: &Value) -> Value {
    let pick = |k: &str| r.get(k).cloned().unwrap_or(Value::Null);
    let mut out = json!({
        "route": pick("route"),
        "http_method": pick("http_method"),
        "file": pick("file"),
        "line": pick("line"),
        "scope": pick("scope"),
        "global_coverage": pick("global_coverage"),
        "coverage_scope": pick("coverage_scope"),
    });
    if let Some(m) = r.get("global_match").filter(|m| m.is_object()) {
        if let Some(obj) = out.as_object_mut() {
            obj.insert(
                "global_match".to_string(),
                json!({
                    "pattern": m.get("pattern").cloned().unwrap_or(Value::Null),
                    "clause": m.get("clause").cloned().unwrap_or(Value::Null),
                    "file": m.get("file").cloned().unwrap_or(Value::Null),
                    "line": m.get("line").cloned().unwrap_or(Value::Null),
                }),
            );
        }
    }
    if r.get("not_an_endpoint").and_then(|v| v.as_bool()) == Some(true) {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("not_an_endpoint".to_string(), json!(true));
        }
    }
    if let Some(caveat) = r.get("coverage_caveat").filter(|v| !v.is_null()) {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("coverage_caveat".to_string(), caveat.clone());
        }
    }
    out
}

/// 一行一条的文本视图（LLM 可直接读，154 路由约 15KB）。
///
/// 格式：`METHOD route  file:line  verdict  [<- matched pattern @ file:line]`
pub(crate) fn brief_route_line(r: &Value) -> String {
    let method = r
        .get("http_method")
        .and_then(|v| v.as_str())
        .unwrap_or("ANY");
    let route = r
        .get("route")
        .and_then(|v| v.as_str())
        .unwrap_or("<unresolved>");
    let file = r.get("file").and_then(|v| v.as_str()).unwrap_or("");
    let line = r.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
    let verdict = if r.get("not_an_endpoint").and_then(|v| v.as_bool()) == Some(true) {
        "not_an_endpoint"
    } else {
        r.get("global_coverage")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    };
    let matched = match r.get("global_match").filter(|m| m.is_object()) {
        Some(m) => format!(
            "  <- {} @ {}:{}",
            m.get("pattern").and_then(|v| v.as_str()).unwrap_or(""),
            m.get("file").and_then(|v| v.as_str()).unwrap_or(""),
            m.get("line").and_then(|v| v.as_u64()).unwrap_or(0)
        ),
        None => String::new(),
    };
    format!("{method} {route}  {file}:{line}  {verdict}{matched}")
}

/// 把完整 `data` 压成 brief 视图（可选分页：`limit`/`offset`）。
pub(crate) fn brief_data(data: &Value, limit: usize, offset: usize) -> Value {
    let mut out = data.clone();
    let Some(obj) = out.as_object_mut() else {
        return out;
    };
    let src_routes = data
        .get("routes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let total = src_routes.len();
    let start = offset.min(total);
    let end = if limit == 0 {
        total
    } else {
        (start + limit).min(total)
    };
    let page: Vec<Value> = src_routes[start..end].iter().map(brief_route).collect();
    obj.insert("routes".to_string(), Value::Array(page));
    let uncovered = data
        .get("uncovered_endpoints")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    obj.insert(
        "uncovered_endpoints".to_string(),
        Value::Array(uncovered.iter().map(brief_route).collect()),
    );
    let lines: Vec<Value> = obj
        .get("routes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|r| json!(brief_route_line(r)))
        .collect();
    obj.insert("routes_text".to_string(), Value::Array(lines));
    obj.insert("detail".to_string(), json!("brief"));
    obj.insert("provenance_omitted".to_string(), json!(true));
    obj.insert(
        "page".to_string(),
        json!({"offset": start, "limit": if limit == 0 { total } else { limit }, "returned": end - start, "total": total}),
    );
    out
}

/// `detail=lines`：只给文本行 + 摘要（154 路由约 15KB；结构化 brief 约 100KB）。
pub(crate) fn lines_data(data: &Value) -> Value {
    let routes = data
        .get("routes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let text: Vec<Value> = routes
        .iter()
        .map(|r| json!(brief_route_line(&brief_route(r))))
        .collect();
    json!({
        "detail": "lines",
        "files_indexed": data.get("files_indexed").cloned().unwrap_or(Value::Null),
        "index_truncated_at_limit": data.get("index_truncated_at_limit").cloned().unwrap_or(Value::Null),
        "verdict_counts": data.get("verdict_counts").cloned().unwrap_or(Value::Null),
        "filter": data.get("filter").cloned().unwrap_or(Value::Null),
        "total_hits": data.get("total_hits").cloned().unwrap_or(Value::Null),
        "uncovered_suppressed_by_truncation": data.get("uncovered_suppressed_by_truncation").cloned().unwrap_or(Value::Null),
        "routes_total": routes.len(),
        "routes_text": text,
        "format": "METHOD route  file:line  verdict  [<- matched_pattern @ file:line]",
    })
}

fn line_at<'a>(content: &'a str, line: usize) -> Option<&'a str> {
    content.lines().nth(line.saturating_sub(1))
}

/// 在路由声明行附近（含类级区域）扫描鉴权注解。只报**读到**的行，不推断。
fn auth_annotations_near(content: &str, line: usize) -> Vec<Value> {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(90);
    let end = (line + 2).min(lines.len());
    let mut out: Vec<Value> = Vec::new();
    for (i, text) in lines.iter().enumerate().take(end).skip(start) {
        let t = text.trim();
        if t.starts_with("import ") || t.starts_with("package ") {
            continue;
        }
        for ann in AUTH_ANNOTATIONS {
            if t.contains(&format!("@{ann}")) {
                out.push(json!({
                    "annotation": ann,
                    "file_line": (i + 1) as u64,
                    "text": t.chars().take(120).collect::<String>(),
                }));
                break;
            }
        }
        if out.len() >= 6 {
            break;
        }
    }
    out
}

/// 取 handler 的代码窗口（按首个 `{` 起做花括号配平，最多 80 行）。
fn handler_window(content: &str, line: usize) -> (usize, usize) {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(1).min(lines.len());
    let mut depth = 0i32;
    let mut opened = false;
    let mut end = start;
    for (i, text) in lines.iter().enumerate().skip(start).take(120) {
        for ch in text.chars() {
            if ch == '{' {
                depth += 1;
                opened = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        end = i;
        if opened && depth <= 0 {
            break;
        }
    }
    (start + 1, end + 1)
}

/// 返回类型：从 handler 声明行往上看最近的 `public|protected|private ... 类型 名字(`。
fn handler_return_type(content: &str, line: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let start = line.saturating_sub(1);
    for i in (0..=start.min(lines.len().saturating_sub(1)))
        .rev()
        .take(12)
    {
        let t = lines[i].trim();
        if t.starts_with("import ") || t.starts_with("@") || t.is_empty() {
            continue;
        }
        if !(t.contains('(')
            && (t.contains("public ") || t.contains("protected ") || t.contains("private ")))
        {
            continue;
        }
        let head = t.split('(').next().unwrap_or("");
        let mut toks = head.split_whitespace().rev();
        let _name = toks.next()?;
        let ty = toks.next()?;
        if ty.len() <= 64 && !ty.contains('=') {
            return Some(ty.trim().to_string());
        }
    }
    None
}

fn looks_sensitive(name: &str) -> bool {
    let l = name.to_lowercase();
    SENSITIVE_FIELD_HINTS.iter().any(|h| l.contains(h))
}

/// 敏感返回面：只报 handler 窗口里**读到的**敏感字段名/调用，不推断是否泄漏。
pub(crate) fn sensitive_surface(files: &[(String, String)], file: &str, line: usize) -> Value {
    let content = files
        .iter()
        .find(|(p, _)| p == file)
        .map(|(_, c)| c.as_str())
        .unwrap_or("");
    if content.is_empty() {
        return json!({"available": false, "reason": "file_not_indexed"});
    }
    let (start, end) = handler_window(content, line);
    let lines: Vec<&str> = content.lines().collect();
    let mut hits: Vec<Value> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    for (i, text) in lines
        .iter()
        .enumerate()
        .take(end.min(lines.len()))
        .skip(start.saturating_sub(1))
    {
        // getXxx() / setXxx(...) 形式的字段访问
        for token in text.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if token.len() < 4 || token.len() > 48 {
                continue;
            }
            // 只认 getter/setter/is 访问器，或小写开头的字段名：
            // 类型名（`SystemConfigDTO`）与基础设施名（`systemConfigService`）不是返回面字段。
            let accessor = ["get", "set", "is"].iter().find_map(|p| {
                token.strip_prefix(p).and_then(|rest| {
                    rest.strip_prefix(|c: char| c.is_uppercase())
                        .map(|_| rest)
                        .filter(|_| {
                            rest.chars()
                                .next()
                                .map(|c| c.is_uppercase())
                                .unwrap_or(false)
                        })
                })
            });
            let core = match accessor {
                Some(rest) => rest,
                None => {
                    if !token
                        .chars()
                        .next()
                        .map(|c| c.is_lowercase())
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    token
                }
            };
            if core.is_empty() {
                continue;
            }
            const INFRA_SUFFIX: [&str; 9] = [
                "Service",
                "Utils",
                "Context",
                "DTO",
                "Config",
                "Manager",
                "Controller",
                "Repository",
                "Mapper",
            ];
            if INFRA_SUFFIX.iter().any(|s| core.ends_with(s)) {
                continue;
            }
            if !looks_sensitive(core) {
                continue;
            }
            let key = core.to_lowercase();
            if !seen.insert(key) {
                continue;
            }
            hits.push(json!({
                "field": core,
                "line": (i + 1) as u64,
            }));
            if hits.len() >= 8 {
                break;
            }
        }
        if hits.len() >= 8 {
            break;
        }
    }
    json!({
        "available": true,
        "handler_window": {"start_line": start, "end_line": end},
        "return_type": handler_return_type(content, line),
        "sensitive_fields": hits,
        "risky_return": !hits.is_empty(),
        "basis": "identifier_heuristic",
        "caveat": "name_based_only_does_not_prove_leak",
    })
}

/// 路由所在类是否是 Spring Bean（只对 JVM 语言生效，读不到类声明则返回 None=未知）。
///
/// 动机：注解扫描会把"没有 `@Controller`/`@Component`、也不是 `@Bean` 注册"的普通类上的
/// `@GetMapping` 当成端点（R249 的 D2 诱饵）。这一条检查把它变成可机械判定的结论。
fn spring_bean_evidence(content: &str, route_line: usize, path: &str) -> Option<Value> {
    let is_jvm = path.ends_with(".java") || path.ends_with(".kt");
    if !is_jvm {
        return None;
    }
    let lines: Vec<&str> = content.lines().collect();
    let class_line = class_decl_line_before(&lines, route_line)?;
    let annotations = class_bean_annotations(&lines, class_line);
    Some(json!({
        "is_spring_bean": !annotations.is_empty(),
        "class_line": (class_line + 1) as u64,
        "annotations": annotations,
    }))
}

/// route_line 之前最近的类型声明行（class/interface/enum/record）。
fn class_decl_line_before(lines: &[&str], route_line: usize) -> Option<usize> {
    let upto = route_line.min(lines.len());
    for i in (0..upto).rev() {
        let t = lines[i].trim();
        if t.contains(" class ")
            || t.starts_with("class ")
            || t.contains(" interface ")
            || t.contains(" enum ")
            || t.contains(" record ")
        {
            return Some(i);
        }
    }
    None
}

/// 类声明上方（30 行内）读到的 Bean 注解；注释行不算。
fn class_bean_annotations(lines: &[&str], class_line: usize) -> Vec<Value> {
    const BEAN_ANNOTATIONS: [&str; 12] = [
        "@Controller",
        "@RestController",
        "@Component",
        "@Service",
        "@Repository",
        "@Configuration",
        "@Bean",
        "@Endpoint",
        "@WebServlet",
        "@ServerEndpoint",
        "@Path",
        "@RequestMapping",
    ];
    let start = class_line.saturating_sub(30);
    let mut found: Vec<Value> = Vec::new();
    for (i, text) in lines.iter().enumerate().take(class_line + 1).skip(start) {
        let t = text.trim();
        // 注释行不是注解：Javadoc 里提到 `@Bean` 不等于类被注册过（R249 的 D2 诱饵就靠这个坑）。
        if t.starts_with("import ")
            || t.starts_with("package ")
            || t.starts_with("*")
            || t.starts_with("/*")
            || t.starts_with("//")
            || t.starts_with("*/")
        {
            continue;
        }
        for ann in BEAN_ANNOTATIONS {
            // 类级注解总是行首（缩进后）；正文里出现的 `@Bean` 字样不算。
            if t.starts_with(ann) {
                found.push(json!({"annotation": ann, "line": (i + 1) as u64}));
                break;
            }
        }
    }
    found
}

/// 该文件里 route_line 之前最近一个类是否带 Bean 注解；非 JVM 语言返回 None（未知）。
pub(crate) fn file_route_is_bean(content: &str, route_line: usize, path: &str) -> Option<bool> {
    if !(path.ends_with(".java") || path.ends_with(".kt")) {
        return None;
    }
    let lines: Vec<&str> = content.lines().collect();
    let class_line = class_decl_line_before(&lines, route_line)?;
    Some(!class_bean_annotations(&lines, class_line).is_empty())
}

/// 该鉴权注解在这个项目里是否**有消费者**（决定"注解写了"是否等于"受保护"）。
///
/// 只认标准框架的消费入口；认不出就返回 false（保守，避免把死注解当保护）。
fn annotation_effective(annotation: &str, files: &[(String, String)]) -> bool {
    let mut sa_interceptor = false;
    let mut method_security = false;
    let mut shiro = false;
    for (_p, content) in files.iter().take(max_index_files()) {
        if !sa_interceptor && content.contains("SaInterceptor") {
            sa_interceptor = true;
        }
        if !method_security
            && (content.contains("@EnableMethodSecurity")
                || content.contains("@EnableGlobalMethodSecurity"))
        {
            method_security = true;
        }
        if !shiro
            && (content.contains("AuthorizationAttributeSourceAdvisor")
                || content.contains("ShiroAnnotationProcessor"))
        {
            shiro = true;
        }
        if sa_interceptor && method_security && shiro {
            break;
        }
    }
    if annotation.starts_with("Sa") {
        sa_interceptor
    } else if matches!(
        annotation,
        "PreAuthorize" | "PostAuthorize" | "Secured" | "RolesAllowed" | "PermitAll" | "DenyAll"
    ) {
        method_security
    } else if matches!(annotation, "RequiresPermissions" | "RequiresRoles") {
        shiro
    } else {
        false
    }
}

/// 单条路由判定：verdict + 逐项 decided_by + 可机械证伪命令 + 敏感返回面。
#[allow(clippy::too_many_arguments)]
pub(crate) fn explain_route(
    root: &Path,
    files: &[(String, String)],
    id: &str,
    refresh: bool,
    file: Option<&str>,
    route: Option<&str>,
    handler: Option<&str>,
    index_truncated: bool,
) -> Result<Value, ToolError> {
    if file.is_none() && route.is_none() && handler.is_none() {
        return Err(ToolError::InvalidArgument(
            "explain_route 需要 route / file / handler 至少一个参数".to_string(),
        ));
    }
    let filter = RouteFilter {
        min_role: "any".to_string(),
        route_pattern: route.unwrap_or("").to_string(),
        only_uncovered: false,
    };
    let table = compute_routes(root, files, id, refresh, &filter, index_truncated);
    let empty: Vec<Value> = Vec::new();
    let all = table
        .data
        .get("routes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or(empty);
    // handler 定位：在指定文件里找 `handler(` 所在行，再取最近的 method 级路由
    let handler_line: Option<u64> = match (handler, file) {
        (Some(h), Some(f)) => files.iter().find(|(p, _)| p == f).and_then(|(_, c)| {
            c.lines()
                .position(|l| l.contains(&format!("{h}(")))
                .map(|i| (i + 1) as u64)
        }),
        _ => None,
    };
    let norm = |s: &str| s.trim_start_matches("./").replace('\\', "/");
    let want_file = file.map(norm);
    let mut candidates: Vec<&Value> = all
        .iter()
        .filter(|r| r.get("scope").and_then(|v| v.as_str()) == Some("method"))
        .filter(|r| match &want_file {
            Some(f) => r.get("file").and_then(|v| v.as_str()).map(norm) == Some(f.clone()),
            None => true,
        })
        .filter(|r| match (handler, handler_line) {
            (Some(_), Some(h)) => {
                let l = r.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
                l.abs_diff(h) <= 8
            }
            _ => true,
        })
        .collect();
    if candidates.is_empty() {
        return Ok(json!({
            "matched": false,
            "query": {"file": file, "route": route, "handler": handler},
            "reason": "no_route_found",
            "download_hint": "检查 route 写法（含类级前缀）或改用 file + handler",
            "routes_considered": all.len(),
        }));
    }
    candidates.sort_by_key(|r| {
        (
            r.get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            r.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
        )
    });
    let best = candidates[0];
    let best_file = best.get("file").and_then(|v| v.as_str()).unwrap_or("");
    let best_line = best.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let verdict = best
        .get("global_coverage")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let content = files
        .iter()
        .find(|(p, _)| p == best_file)
        .map(|(_, c)| c.as_str())
        .unwrap_or("");
    let annotations = auth_annotations_near(content, best_line);
    let mut checks: Vec<Value> = Vec::new();
    if let Some(gm) = best.get("global_match").filter(|v| v.is_object()) {
        checks.push(json!({
            "check": "path matched a declared rule",
            "result": "covered",
            "evidence": gm,
        }));
    } else if let Some(gs) = best.get("global_scope").filter(|v| v.is_object()) {
        checks.push(json!({
            "check": "no declared rule matches this path",
            "result": "no_match",
            "evidence": {
                "rules_total": gs.get("total_hits").cloned().unwrap_or(Value::Null),
                "rules": gs.get("rules").cloned().unwrap_or(Value::Null),
            },
        }));
    } else {
        checks.push(json!({
            "check": "no security chain / no rules found in the project",
            "result": "no_config",
            "evidence": Value::Null,
        }));
    }
    // 注解级保护：写了注解 ≠ 生效 —— 必须能指出消费者，否则只能报 "annotation_without_consumer"。
    let effective_annotation = annotations.iter().find_map(|a| {
        let name = a.get("annotation").and_then(|v| v.as_str()).unwrap_or("");
        annotation_effective(name, files).then(|| name.to_string())
    });
    checks.push(json!({
        "check": "method/class auth annotation",
        "result": if annotations.is_empty() {
            "absent"
        } else if effective_annotation.is_some() {
            "present_and_consumed"
        } else {
            "present_without_consumer"
        },
        "effective_by": effective_annotation,
        "evidence": annotations,
    }));
    let auth_filters: Vec<Value> = best
        .get("container_filters")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|f| {
            let name = f
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            name.contains("auth")
                || name.contains("security")
                || name.contains("jwt")
                || name.contains("token")
        })
        .collect();
    let all_filters = best
        .get("container_filters")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    checks.push(json!({
        "check": "container filters with auth semantics",
        "result": if auth_filters.is_empty() { "none" } else { "present" },
        "evidence": {
            "count": all_filters.len(),
            "auth_semantic": auth_filters.iter().map(|f| json!({
                "name": f.get("name").cloned().unwrap_or(Value::Null),
                "file": f.get("file").cloned().unwrap_or(Value::Null),
                "line": f.get("line").cloned().unwrap_or(Value::Null),
            })).collect::<Vec<Value>>(),
        },
    }));
    checks.push(json!({
        "check": "registered interceptors",
        "result": best.get("interceptor_count").cloned().unwrap_or(json!(0)),
        "evidence": best.get("interceptors").and_then(|v| v.as_array()).cloned().unwrap_or_default()
            .iter().map(|x| json!({
                "name": x.get("name").cloned().unwrap_or(Value::Null),
                "pattern": x.get("pattern").cloned().unwrap_or(Value::Null),
                "file": x.get("file").cloned().unwrap_or(Value::Null),
                "line": x.get("line").cloned().unwrap_or(Value::Null),
            })).collect::<Vec<Value>>(),
    }));
    // 类是否真的是 Spring Bean：非 Bean 上的映射注解不是端点（R249 的 D2 诱饵）。
    let bean = spring_bean_evidence(content, best_line, best_file);
    let not_an_endpoint = bean
        .as_ref()
        .and_then(|b| b.get("is_spring_bean"))
        .and_then(|v| v.as_bool())
        .map(|is_bean| !is_bean)
        .unwrap_or(false);
    checks.push(json!({
        "check": "declaring class is a Spring bean",
        "result": match bean.as_ref().and_then(|b| b.get("is_spring_bean")).and_then(|v| v.as_bool()) {
            Some(true) => "present",
            Some(false) => "absent",
            None => "unknown",
        },
        "evidence": bean,
    }));
    // 断言优先级：非端点 > 全局规则覆盖/放行 > 注解级覆盖（需有消费者）> 未知 > 未覆盖
    let asserted = if not_an_endpoint {
        "not_an_endpoint"
    } else {
        match verdict.as_str() {
            "covered_by_global_config" => "covered",
            "permitted_by_global_config" => "permitted",
            "coverage_unknown" => "unknown",
            _ => {
                if effective_annotation.is_some() {
                    "covered"
                } else if annotations.is_empty() {
                    "uncovered"
                } else {
                    "annotation_without_consumer"
                }
            }
        }
    };
    let route_for_cmd = best.get("route").and_then(|v| v.as_str()).unwrap_or("");
    let falsify = format!(
        "ctx-audit explain-route {} {} --assert {}",
        root.display(),
        route_for_cmd,
        asserted
    );
    let sensitive = sensitive_surface(files, best_file, best_line);
    Ok(json!({
        "matched": true,
        "route": route_for_cmd,
        "http_method": best.get("http_method").cloned().unwrap_or(Value::Null),
        "file": best_file,
        "line": best_line,
        "scope": best.get("scope").cloned().unwrap_or(Value::Null),
        "verdict": verdict,
        "asserted_verdict": asserted,
        "coverage_scope": best.get("coverage_scope").cloned().unwrap_or(Value::Null),
        "coverage_caveat": best.get("coverage_caveat").cloned().unwrap_or(Value::Null),
        "decided_by": checks,
        "falsify": falsify,
        "sensitive_return": sensitive,
        "limits": {
            "index_truncated_at_limit": index_truncated,
            "max_files": max_index_files(),
        },
        "candidates_considered": candidates.len(),
        "not_an_endpoint": not_an_endpoint,
    }))
}

/// 路由指纹（diff 基线用）：method + 规范化路由 + 文件。
pub(crate) fn route_fingerprint(r: &Value) -> String {
    let method = r
        .get("http_method")
        .and_then(|v| v.as_str())
        .unwrap_or("ANY");
    let route = r.get("route").and_then(|v| v.as_str()).unwrap_or("");
    let file = r.get("file").and_then(|v| v.as_str()).unwrap_or("");
    format!("{method} {route} ({file})")
}
