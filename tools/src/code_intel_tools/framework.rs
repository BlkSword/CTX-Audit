// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Web 框架证据：端点路由、安全链（注解/Java DSL/XML/反应式）、容器过滤器与拦截器、
//! 授权落点，以及"检测到但未建模的保护栈"信号。

use super::*;

/// `no_global_match_found` 时带出的"考虑过的规则"上限。
///
/// 与既有封顶口径一致：超限时同时报 `total_hits` 与 `truncated_at_limit`，不静默截断。
const MAX_SCOPE_RULES: usize = 8;
/// 路径模式匹配：精确匹配、`/**` 前缀、`/*` 单段通配。`/**` 亦用于 `anyRequest()` 的 Catch-all。
pub(crate) fn route_matches_pattern(route: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return route.starts_with(prefix.trim_end_matches('/'));
    }
    if let Some(base) = pattern.strip_suffix("/*") {
        if !route.starts_with(base) {
            return false;
        }
        let rest = &route[base.len()..];
        return !rest.is_empty() && !rest.trim_matches('/').contains('/');
    }
    route == pattern
}

/// 安全配置判定里使用的授权子句关键词。
pub(crate) const AUTH_CLAUSES: [&str; 9] = [
    "permitAll",
    "hasRole",
    "hasAnyRole",
    "hasAuthority",
    "hasAnyAuthority",
    "isAuthenticated",
    "authenticated",
    "denyAll",
    "access(",
];

/// 该文件是否像安全配置（含全局安全配置形态）。
pub(crate) fn looks_like_security_config(content: &str) -> bool {
    content.lines().any(|l| {
        let t = l.trim();
        !is_import_or_package_line(t)
            && (t.contains("SecurityFilterChain")
                || t.contains("SecurityWebFilterChain")
                || t.contains("WebSecurityConfigurerAdapter")
                || t.contains("@EnableWebSecurity")
                || t.contains("authorizeHttpRequests")
                || t.contains("authorizeRequests"))
    })
}

/// 一条安全规则：路径匹配器 + 授权子句 + 出处。
#[derive(Clone, Debug)]
pub(crate) struct SecurityRule {
    pub(crate) pattern: String,
    pub(crate) clause: String,
    pub(crate) file: String,
    pub(crate) line: u32,
    /// 匹配语义来源：`spring` = Spring 通配，`shiro` = Shiro 通配
    pub(crate) kind: String,
}

/// 链上读到的 CSRF 声明（**只记读到的文本事实**，不推断框架默认值）。
///
/// 未读到时不产字段：静默不等于"已启用"或"未启用"。
#[derive(Clone, Debug)]
pub(crate) struct CsrfDeclaration {
    /// `disabled` / `ignoring_paths` / `custom_repository` / `declared`
    pub(crate) state: String,
    /// `ignoringRequestMatchers(...)` 上的路径字面量（仅 `ignoring_paths` 会有）
    pub(crate) patterns: Vec<String>,
    pub(crate) file: String,
    pub(crate) line: u32,
}

/// 一条过滤器链：顺序、适用范围、链内规则（保持声明顺序）。
#[derive(Clone, Debug)]
pub(crate) struct SecurityChain {
    /// `@Order` 值；未声明时为 None（求值时排在声明了顺序的链之后）
    pub(crate) order: Option<i64>,
    /// 链的 `securityMatcher(...)` 模式；未声明时为 None（视为 Catch-all）
    pub(crate) matcher: Option<String>,
    /// 声明位置（用于同序时的稳定排序）
    pub(crate) decl_index: usize,
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) rules: Vec<SecurityRule>,
    /// 该链上读到的 CSRF 声明（未读到即 None）
    pub(crate) csrf: Option<CsrfDeclaration>,
}

/// 从 `@Order(...)` 文本里取数字；取不到数字（如常量表达式）即视为未声明。
pub(crate) fn parse_order_value(text: &str) -> Option<i64> {
    let start = text.find("@Order")?;
    let rest = &text[start..];
    let open = rest.find('(')?;
    let close = rest[open..].find(')')? + open;
    rest[open + 1..close].trim().parse::<i64>().ok()
}

/// 跨文件证据：把安全配置按**过滤器链**切分，链内规则保持声明顺序。
///
/// 顺序语义是安全相关的事实：多条链并存时 `@Order` 小者先求值，同一条链内**首个匹配的规则生效**。
/// 这里只做**行窗**启发式切分（不做括号配平），因此每条链都带出可复核的声明位置。
pub(crate) fn security_config_chains(project_files: &[(String, String)]) -> Vec<SecurityChain> {
    let mut chains: Vec<SecurityChain> = Vec::new();
    for (cfg_path, cfg_content) in project_files.iter().take(max_index_files()) {
        if !looks_like_security_config(cfg_content) {
            continue;
        }
        let cfg_code = code_lines(cfg_content, hash_comment_language(cfg_path));
        let cfg_lines: Vec<&str> = cfg_content.lines().collect();
        let mut current: Option<usize> = None;
        for (idx, code_line) in cfg_code.iter().enumerate() {
            let ct = code_line.trim();
            // 导入行不是证据：`import ...SecurityWebFilterChain;` 曾在此凭空建链
            if is_import_or_package_line(ct) {
                continue;
            }
            // 只认**类型位置**的 `SecurityFilterChain`（后跟空格）：方法名 `springSecurityFilterChain`
            // 与反应式的 `SecurityWebFilterChain` 都含该子串，否则会凭空建链
            if ct.contains("SecurityFilterChain ") {
                let order = cfg_lines
                    .iter()
                    .skip(idx.saturating_sub(5))
                    .take(6)
                    .find_map(|l| parse_order_value(l));
                // 链的适用范围只认 `securityMatcher(...)` 行，避免把链内规则的字面量误当范围
                let matcher = cfg_lines
                    .iter()
                    .skip(idx)
                    .take(7)
                    .find(|l| l.contains("securityMatcher"))
                    .and_then(|l| l.split('"').nth(1).map(|s| s.to_string()))
                    .filter(|s| s.starts_with('/'));
                chains.push(SecurityChain {
                    order,
                    matcher,
                    decl_index: chains.len(),
                    file: cfg_path.clone(),
                    line: (idx + 1) as u32,
                    rules: Vec::new(),
                    csrf: None,
                });
                current = Some(chains.len() - 1);
                continue;
            }
            // 链上读到的 CSRF 声明（`.csrf(...)`）：只记读到的文本事实，未读到不产字段
            if ct.contains(".csrf(") {
                let Some(ci) = current else { continue };
                if chains[ci].csrf.is_none() {
                    if let Some((state, patterns, line)) =
                        csrf_declaration_at(&cfg_code, &cfg_lines, idx)
                    {
                        chains[ci].csrf = Some(CsrfDeclaration {
                            state,
                            patterns,
                            file: cfg_path.clone(),
                            line,
                        });
                    }
                }
                continue;
            }
            // `anyRequest()` 是 Catch-all 匹配器：等价于 `/**`，漏掉它会让判定偏乐观
            let is_any_request = ct.contains("anyRequest()");
            let is_matcher = ct.contains("requestMatchers(")
                || ct.contains("antMatchers(")
                || ct.contains("mvcMatchers(");
            if !is_matcher && !is_any_request {
                continue;
            }
            let Some(ci) = current else { continue };
            let pattern = if is_any_request {
                "/**".to_string()
            } else {
                let raw = cfg_lines.get(idx).copied().unwrap_or("");
                match raw.split('"').nth(1) {
                    Some(p) if !p.is_empty() => p.to_string(),
                    // 非字面量匹配器（如 `requestMatchers(变量)`）不得静默丢弃：
                    // 登记为 `<dynamic>`，并在覆盖判定上如实提示"有一条未解析"
                    _ => "<dynamic>".to_string(),
                }
            };
            let window: String = cfg_lines
                .iter()
                .skip(idx)
                .take(4)
                .cloned()
                .collect::<Vec<&str>>()
                .join(" ");
            let clause = AUTH_CLAUSES
                .iter()
                .filter_map(|k| window.find(*k).map(|p| (p, *k)))
                .min_by_key(|(p, _)| *p)
                .map(|(_, k)| k.trim_end_matches('(').to_string())
                .unwrap_or_else(|| "unspecified".to_string());
            chains[ci].rules.push(SecurityRule {
                pattern,
                clause,
                kind: "spring".to_string(),
                file: cfg_path.clone(),
                line: (idx + 1) as u32,
            });
        }
    }
    chains.sort_by_key(|c| (c.order.unwrap_or(i64::MAX), c.decl_index));
    chains
}

/// 跨文件证据：安全配置的声明位置（用于中间件链上的配置证据）。
pub(crate) fn security_config_declarations(
    project_files: &[(String, String)],
) -> Vec<(String, u32, String)> {
    let mut out = Vec::new();
    for (cfg_path, cfg_content) in project_files.iter().take(max_index_files()) {
        if !looks_like_security_config(cfg_content) {
            continue;
        }
        let cfg_code = code_lines(cfg_content, hash_comment_language(cfg_path));
        let cfg_lines: Vec<&str> = cfg_content.lines().collect();
        for (idx, code_line) in cfg_code.iter().enumerate() {
            let ct = code_line.trim();
            if ct.contains("class ")
                && (ct.contains("SecurityConfig") || ct.contains("WebSecurityConfig"))
            {
                out.push((
                    cfg_path.clone(),
                    (idx + 1) as u32,
                    cfg_lines
                        .get(idx)
                        .copied()
                        .unwrap_or("")
                        .trim()
                        .chars()
                        .take(200)
                        .collect::<String>(),
                ));
                break;
            }
        }
    }
    out
}

/// 单条链内的判定：链内**首个匹配的规则生效**。
pub(crate) fn rule_for_route(route: &str, chain: &SecurityChain) -> Option<SecurityRule> {
    chain
        .rules
        .iter()
        .find(|r| {
            if r.kind == "shiro" {
                shiro_pattern_matches(route, &r.pattern)
            } else {
                route_matches_pattern(route, &r.pattern)
            }
        })
        .cloned()
}

/// 给路由条目补上全局覆盖判定（纯数据变换）。
///
/// 顺序语义按实际行为：多条链按 `@Order` 升序求值（未声明顺序者排后），链的 `securityMatcher`
/// 不匹配则跳过，链内首个匹配的规则生效。**只有当胜出链没有声明顺序、且与其它链的结论矛盾时**，
/// 才如实报 `ambiguous_across_chains` —— 不挑乐观的那条。
pub(crate) fn annotate_route_coverage(routes: &mut [Value], chains: &[SecurityChain]) {
    let total_rules: usize = chains.iter().map(|c| c.rules.len()).sum();
    for entry in routes.iter_mut() {
        if entry.get("scope").and_then(|v| v.as_str()) == Some("class") {
            continue;
        }
        let route = entry
            .get("route")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut verdict = if chains.is_empty() || total_rules == 0 {
            "no_global_config_found"
        } else {
            "no_global_match_found"
        };
        let mut detail: Option<Value> = None;
        let mut csrf_fact: Option<Value> = None;
        let mut global_scope: Option<Value> = None;
        let mut considered = 0usize;
        let mut dynamic_unresolved = false;
        if !route.is_empty() && total_rules > 0 {
            let mut results: Vec<(usize, SecurityRule)> = Vec::new();
            for (ci, chain) in chains.iter().enumerate() {
                if let Some(m) = chain.matcher.as_deref() {
                    if !route_matches_pattern(&route, m) {
                        continue;
                    }
                }
                considered += 1;
                if chain.rules.iter().any(|r| r.pattern == "<dynamic>") {
                    dynamic_unresolved = true;
                }
                if let Some(rule) = rule_for_route(&route, chain) {
                    results.push((ci, rule));
                }
            }
            let mut kinds: Vec<&str> = results
                .iter()
                .map(|(_, r)| {
                    if r.clause == "permitAll" {
                        "permitAll"
                    } else {
                        "restricted"
                    }
                })
                .collect();
            kinds.sort_unstable();
            kinds.dedup();
            let winner = results.first();
            let ambiguous = kinds.len() > 1
                && winner
                    .map(|(ci, _)| chains[*ci].order.is_none())
                    .unwrap_or(false);
            if ambiguous {
                verdict = "ambiguous_across_chains";
            } else if let Some((ci, rule)) = winner {
                verdict = if rule.clause == "permitAll" {
                    "permitted_by_global_config"
                } else {
                    "covered_by_global_config"
                };
                detail = Some(json!({
                    "pattern": rule.pattern,
                    "clause": rule.clause,
                    "file": rule.file,
                    "line": rule.line,
                    "chain_order": chains[*ci].order,
                    "chain_matcher": chains[*ci].matcher,
                    "chain_file": chains[*ci].file,
                    "chain_line": chains[*ci].line,
                }));
                // CSRF 证据：只报**胜出链上读到的**声明。未读到不产字段，也不否定
                // （负向断言会读成"没有 CSRF 配置"）。Shiro 的 CSRF 不由本口径覆盖。
                if rule.kind != "shiro" {
                    if let Some(c) = chains[*ci].csrf.as_ref() {
                        let (state, matched) = if c.state == "ignoring_paths" {
                            match c.patterns.iter().find(|p| route_matches_pattern(&route, p)) {
                                Some(p) => ("disabled_for_this_path".to_string(), Some(p.clone())),
                                None => (c.state.clone(), None),
                            }
                        } else {
                            (c.state.clone(), None)
                        };
                        csrf_fact = Some(json!({
                            "state": state,
                            "file": c.file,
                            "line": c.line,
                            "ignored_patterns": c.patterns,
                            "matched_ignored_pattern": matched,
                        }));
                    }
                }
            }
            // 没有规则匹配到该路由时，把"**考虑过哪些规则**"如实带出来：否则读者无法区分
            // 「端点落在已声明范围之外」（漏鉴权的线索）与「解析不出规则」——而"范围是什么"
            // 正是判定这件事所必需的事实（如只声明了 `/admin/**`）。
            if results.is_empty() {
                let mut rules: Vec<Value> = Vec::new();
                let mut total = 0usize;
                for chain in chains.iter() {
                    if let Some(m) = chain.matcher.as_deref() {
                        if !route_matches_pattern(&route, m) {
                            continue;
                        }
                    }
                    for r in chain.rules.iter() {
                        total += 1;
                        if rules.len() < MAX_SCOPE_RULES {
                            rules.push(json!({
                                "pattern": r.pattern,
                                "clause": r.clause,
                                "kind": r.kind,
                                "file": r.file,
                                "line": r.line,
                            }));
                        }
                    }
                }
                if total > 0 {
                    global_scope = Some(json!({
                        "rules": rules,
                        "total_hits": total,
                        "limit": MAX_SCOPE_RULES,
                        "truncated_at_limit": total > MAX_SCOPE_RULES,
                    }));
                }
            }
        }
        let ordering_basis = if chains.iter().any(|c| c.order.is_some()) {
            "@Order"
        } else {
            "declaration_order"
        };
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("global_coverage".to_string(), json!(verdict));
            obj.insert("global_match".to_string(), detail.unwrap_or(Value::Null));
            // 该端点胜出链上的 CSRF 声明；未读到即 null（不否定）
            obj.insert("csrf".to_string(), csrf_fact.take().unwrap_or(Value::Null));
            // 无规则匹配时带出"考虑过的规则"（有界）；有结论时为 null
            obj.insert(
                "global_scope".to_string(),
                global_scope.take().unwrap_or(Value::Null),
            );
            obj.insert("ordering_basis".to_string(), json!(ordering_basis));
            obj.insert("chains_considered".to_string(), json!(considered));
            // 链里存在未解析的非字面量匹配器时，如实提示该判定可能不完整
            obj.insert(
                "coverage_caveat".to_string(),
                if dynamic_unresolved {
                    json!("dynamic_matcher_unresolved")
                } else {
                    Value::Null
                },
            );
        }
    }
}

/// 容器级过滤器注册：注解、注册 Bean、web.xml 三类，均可复核到行。
#[derive(Clone, Debug)]
pub(crate) struct ContainerFilter {
    pub(crate) pattern: String,
    pub(crate) kind: String,
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) name: Option<String>,
    pub(crate) basis: String,
    /// `<dispatcher>`（web.xml 过滤映射限定生效的派发类型；缺省为 None）
    pub(crate) dispatcher: Option<String>,
}

/// Servlet 风格的 URL 模式匹配：`/*` 全匹配、`/x/*` 前缀、`*.ext` 后缀、其余精确匹配。
pub(crate) fn servlet_pattern_matches(route: &str, pattern: &str) -> bool {
    if pattern == "/*" || pattern == "*" || pattern == "/**" || pattern == "**" {
        return true;
    }
    // Spring 拦截器/路径匹配使用 `/**` 前缀语义（servlet 的 `/*` 之外）
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return route == prefix || route.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return route == prefix || route.starts_with(prefix);
    }
    if let Some(ext) = pattern.strip_prefix("*.") {
        return route.ends_with(&format!(".{}", ext));
    }
    route == pattern
}

/// 取一行里所有像 URL 模式的字符串字面量（以 `/` 或 `*.` 开头）。
pub(crate) fn url_patterns_in(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find('"') {
        let after = &rest[i + 1..];
        let Some(j) = after.find('"') else { break };
        let val = &after[..j];
        if val.starts_with('/') || val.starts_with("*.") {
            out.push(val.to_string());
        }
        rest = &after[j + 1..];
    }
    out
}

/// 读一条 `.csrf(...)` 调用：按**括号配平**取该调用覆盖到的行，再分类。
///
/// 只认读到的文本事实（`disable` / `ignoringRequestMatchers` / `csrfTokenRepository`），
/// 读不出形态即 `declared`（**不推断框架默认值**）。括号配平在**代码视图**上做（注释与字符串
/// 内容已被抹掉，串里的括号不干扰配平），路径取值在**原文**上做（字面量只在原文里存在）。
pub(crate) fn csrf_declaration_at(
    code: &[String],
    originals: &[&str],
    idx: usize,
) -> Option<(String, Vec<String>, u32)> {
    let start = code.get(idx)?;
    let col = start.find(".csrf(")?;
    let joined: String = code[idx..]
        .iter()
        .enumerate()
        .map(|(k, l)| if k == 0 { &l[col..] } else { l.as_str() })
        .collect::<Vec<&str>>()
        .join("\n");
    let mut depth = 0i32;
    let mut end = None;
    for (i, ch) in joined.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let span = joined.get(..=end?)?.to_string();
    let covered = span.matches('\n').count() + 1;
    let state = if span.trim() == ".csrf()" {
        // 空实参形态：只有紧随其后的链式 `.disable()` 才算同一条语句
        // （否则会把下一个配置器的 `disable` 误算成本链禁用 CSRF）
        let chained_disable = originals
            .iter()
            .skip(idx + 1)
            .take_while(|l| l.trim().starts_with('.'))
            .any(|l| l.trim().starts_with(".disable("));
        if chained_disable {
            "disabled"
        } else {
            "declared"
        }
    } else if span.contains("disable") {
        "disabled"
    } else if span.contains("ignoringRequestMatchers(") || span.contains("ignoringAntMatchers(") {
        "ignoring_paths"
    } else if span.contains("csrfTokenRepository(") {
        "custom_repository"
    } else {
        "declared"
    };
    let patterns: Vec<String> = originals
        .iter()
        .skip(idx)
        .take(covered)
        .flat_map(|l| url_patterns_in(l))
        .collect();
    Some((state.to_string(), patterns, (idx + 1) as u32))
}

/// 跨文件证据：容器级过滤器注册（`@WebFilter` / `FilterRegistrationBean` / `web.xml`）。
///
/// 只交付"注册事实 + 适用模式"：过滤器内部是否做鉴权无法从注册信息推断，因此本项与过滤器链的
/// 覆盖判定**分开陈述**，不用它去改 `global_coverage`。
pub(crate) fn container_filter_registrations(project_files: &[(String, String)]) -> Vec<ContainerFilter> {
    let mut out: Vec<ContainerFilter> = Vec::new();
    for (f, content) in project_files.iter().take(max_index_files()) {
        let lines: Vec<&str> = content.lines().collect();
        if f.ends_with(".xml") {
            // 按**区段**归类：只有 <filter-mapping> 是过滤器证据，<security-constraint> 是声明式约束证据，
            // <servlet-mapping> 是路由（不是保护面），无上下文的 <url-pattern> 不作证据。
            let mut section: Option<&str> = None;
            let mut mapping_name: Option<String> = None;
            let mut dispatcher: Option<String> = None;
            let mut mapping_start: usize = 0;
            let text_of = |line: &str, tag: &str| -> Option<String> {
                line.split(&format!("<{}>", tag))
                    .nth(1)
                    .and_then(|s| s.split('<').next())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            };
            for (idx, raw) in lines.iter().enumerate() {
                let t = raw.trim();
                if t.contains("<filter-mapping") {
                    section = Some("filter-mapping");
                    mapping_name = None;
                    dispatcher = None;
                    mapping_start = out.len();
                    continue;
                }
                if t.contains("<servlet-mapping") {
                    section = Some("servlet-mapping");
                    continue;
                }
                if t.contains("<security-constraint") {
                    section = Some("security-constraint");
                    continue;
                }
                if t.contains("</filter-mapping>")
                    || t.contains("</servlet-mapping>")
                    || t.contains("</security-constraint>")
                {
                    section = None;
                    continue;
                }
                if section == Some("filter-mapping") {
                    if let Some(n) = text_of(t, "filter-name") {
                        mapping_name = Some(n);
                        continue;
                    }
                    if let Some(d) = text_of(t, "dispatcher") {
                        // `<dispatcher>` 常写在 `<url-pattern>` **之后**：回填本映射已产出的条目
                        for e in out[mapping_start..].iter_mut() {
                            e.dispatcher = Some(d.clone());
                        }
                        dispatcher = Some(d);
                        continue;
                    }
                }
                if let Some(pattern) = text_of(t, "url-pattern") {
                    let kind = match section {
                        Some("filter-mapping") => "web_xml_filter_mapping",
                        Some("security-constraint") => "web_xml_security_constraint",
                        _ => continue,
                    };
                    let name = if kind == "web_xml_filter_mapping" {
                        mapping_name.clone()
                    } else {
                        None
                    };
                    out.push(ContainerFilter {
                        pattern,
                        kind: kind.to_string(),
                        file: f.clone(),
                        line: (idx + 1) as u32,
                        name,
                        basis: "url-pattern".to_string(),
                        dispatcher: dispatcher.clone(),
                    });
                }
            }
            continue;
        }
        let code = code_lines(content, hash_comment_language(f));
        for (idx, code_line) in code.iter().enumerate() {
            let ct = code_line.trim();
            let raw = lines.get(idx).copied().unwrap_or("");
            if ct.contains("@WebFilter") {
                // 类名常在手写注解**下方**（可能隔着 @Order/@Component）
                let name = lines
                    .iter()
                    .skip(idx)
                    .take(7)
                    .find_map(|l| {
                        let t = l.trim();
                        t.split("class ").nth(1).and_then(|s| {
                            s.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                                .next()
                                .map(|s| s.to_string())
                        })
                    })
                    .filter(|s| !s.is_empty());
                for p in url_patterns_in(raw) {
                    out.push(ContainerFilter {
                        pattern: p,
                        kind: "web_filter".to_string(),
                        file: f.clone(),
                        line: (idx + 1) as u32,
                        name: name.clone(),
                        basis: "annotation".to_string(),
                        dispatcher: None,
                    });
                }
                continue;
            }
            if ct.contains("FilterRegistrationBean") && !is_import_or_package_line(ct) {
                let window: Vec<&str> = lines.iter().skip(idx).take(10).cloned().collect();
                let name = filter_class_name(&window);
                let mut found: Vec<String> = Vec::new();
                for l in &window {
                    if l.contains("addUrlPatterns") || l.contains("setUrlPatterns") {
                        found.extend(url_patterns_in(l));
                    }
                }
                if found.is_empty() {
                    out.push(ContainerFilter {
                        pattern: "/*".to_string(),
                        kind: "filter_registration".to_string(),
                        file: f.clone(),
                        line: (idx + 1) as u32,
                        name: name.clone(),
                        basis: "default_all_urls".to_string(),
                        dispatcher: None,
                    });
                } else {
                    for p in found {
                        out.push(ContainerFilter {
                            pattern: p,
                            kind: "filter_registration".to_string(),
                            file: f.clone(),
                            line: (idx + 1) as u32,
                            name: name.clone(),
                            basis: "url_patterns".to_string(),
                        dispatcher: None,
                        });
                    }
                }
            }
        }
    }
    // 同一注册可能被"声明行 + 构造行"各命中一次：按 (kind, pattern, file) 去重，保留首次出现
    let mut seen: std::collections::HashSet<(String, String, String)> =
        std::collections::HashSet::new();
    out.retain(|f| seen.insert((f.kind.clone(), f.pattern.clone(), f.file.clone())));
    out
}

/// 给路由条目补上容器级过滤器证据（命中最多 3 条，附注册位置）。
pub(crate) fn annotate_container_filters(routes: &mut [Value], filters: &[ContainerFilter]) {
    for entry in routes.iter_mut() {
        if entry.get("scope").and_then(|v| v.as_str()) == Some("class") {
            continue;
        }
        let route = entry
            .get("route")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let matched: Vec<Value> = if route.is_empty() {
            Vec::new()
        } else {
            filters
                .iter()
                .filter(|flt| servlet_pattern_matches(&route, &flt.pattern))
                .take(3)
                .map(|flt| {
                    json!({
                        "pattern": flt.pattern,
                        "kind": flt.kind,
                        "basis": flt.basis,
                        "file": flt.file,
                        "line": flt.line,
                        "name": flt.name,
                    })
                })
                .collect()
        };
        let count = matched.len();
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("container_filters".to_string(), json!(matched));
            obj.insert("container_filter_count".to_string(), json!(count));
        }
    }
}

/// 类级授权注解：`@PreAuthorize` 等打在**类**上时对整批方法生效。
pub(crate) const AUTH_ANNOTATION_MARKERS: [&str; 15] = [
    // Spring Security 方法/类级授权
    "@PreAuthorize",
    "@PostAuthorize",
    "@Secured",
    "@RolesAllowed",
    "@PermitAll",
    "@DenyAll",
    // Shiro 注解式授权（@RequiresPermissions / @RequiresRoles / @RequiresAuthentication 等）
    "@RequiresPermissions",
    "@RequiresRoles",
    "@RequiresAuthentication",
    "@RequiresUser",
    "@RequiresGuest",
    // Sa-Token 注解式鉴权
    "@SaCheckLogin",
    "@SaCheckRole",
    "@SaCheckPermission",
    "@SaCheckSafe",
];

/// 取**类声明正上方**那段连续注解行里的授权注解。
///
/// 只向上收集连续注解（遇到空行或非注解行即停），避免把别处方法的注解算作类级；
/// 方法级注解会覆盖类级注解，因此本项只作为**类级可见证据**陈述。
pub(crate) fn class_level_auth_annotations(content: &str) -> Vec<(u32, String)> {
    let lines: Vec<&str> = content.lines().collect();
    let code = code_lines(content, false);
    let mut class_idx: Option<usize> = None;
    for (idx, code_line) in code.iter().enumerate() {
        let t = code_line.trim();
        if is_type_declaration(&code, idx, t) {
            class_idx = Some(idx);
            break;
        }
    }
    let Some(ci) = class_idx else {
        return Vec::new();
    };
    let mut out: Vec<(u32, String)> = Vec::new();
    let mut i = ci;
    while i > 0 {
        i -= 1;
        let raw = lines.get(i).copied().unwrap_or("");
        let t = raw.trim();
        if t.is_empty() {
            if out.is_empty() {
                continue;
            }
            break;
        }
        if !t.starts_with('@') {
            break;
        }
        if AUTH_ANNOTATION_MARKERS.iter().any(|m| t.contains(*m)) {
            out.push(((i + 1) as u32, t.chars().take(200).collect::<String>()));
        }
    }
    out.reverse();
    out
}

/// 给端点补上类级授权证据（与该文件的其余证据分开陈述）。
pub(crate) fn annotate_class_level_auth(routes: &mut [Value], class_auth: &[(u32, String)]) {
    for entry in routes.iter_mut() {
        if entry.get("scope").and_then(|v| v.as_str()) == Some("class") {
            continue;
        }
        let items: Vec<Value> = class_auth
            .iter()
            .map(|(l, t)| json!({"line": l, "text": t}))
            .collect();
        let count = items.len();
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("class_level_auth".to_string(), json!(items));
            obj.insert("class_level_auth_count".to_string(), json!(count));
            obj.insert(
                "auth_scope".to_string(),
                json!(if count > 0 {
                    "class_level_visible"
                } else {
                    "none_visible_in_file"
                }),
            );
        }
    }
}

/// 取某一行（1-based）**正上方**连续注解行里的授权注解。
///
/// 与方法级证据配套：由调用方先用 AST 定位"包含该映射注解的方法起始行"，再向上取注解，
/// 这样方法级判定不依赖正则去猜函数边界。
/// 类型声明（class / interface / enum / record）所在行（1-based）；找不到返回 0。
pub(crate) fn type_declaration_line(content: &str) -> u32 {
    let code = code_lines(content, false);
    for (idx, code_line) in code.iter().enumerate() {
        let t = code_line.trim();
        if is_type_declaration(&code, idx, t) {
            return (idx + 1) as u32;
        }
    }
    0
}
pub(crate) fn method_level_auth_annotations(
    content: &str,
    start_line: u32,
    body_start_line: u32,
    floor_line: u32,
) -> Vec<(u32, String)> {
    let lines: Vec<&str> = content.lines().collect();
    // 注解可能落在 AST 起始行**之前或之内**（tree-sitter 把注解计入方法节点），
    // 因此按 [start-3, body_start] 这个声明区间取，覆盖两种排版。
    // 下界不得越过类声明行，否则类级注解会被误算作方法级
    let lo = start_line.saturating_sub(1).max(floor_line).max(1) as usize;
    let hi = (body_start_line.max(start_line) as usize).min(lines.len());
    let mut out: Vec<(u32, String)> = Vec::new();
    for i in lo..=hi {
        let t = lines.get(i - 1).copied().unwrap_or("").trim();
        if t.starts_with('@') && AUTH_ANNOTATION_MARKERS.iter().any(|m| t.contains(*m)) {
            out.push((i as u32, t.chars().take(200).collect::<String>()));
        }
    }
    out
}

/// 授权落点：**方法级覆盖类级**；两者都不可见时如实报不可见。
pub(crate) fn auth_effect(class_count: usize, method_count: usize) -> &'static str {
    if method_count > 0 {
        "method_level"
    } else if class_count > 0 {
        "class_level"
    } else {
        "none_visible"
    }
}

/// Shiro 链定义里的过滤子句 → 现有子句词表（`anon` 等价放行，其余视为受限）。
///
/// 映射后复用同一条覆盖判定路径，避免为每种安全栈再写一套判定。
pub(crate) fn shiro_clause(definition: &str) -> String {
    let d = definition.trim();
    if d.split(',').any(|t| t.trim() == "anon" || t.trim() == "anon,") {
        return "permitAll".to_string();
    }
    if d.contains("roles[") {
        return "hasRole".to_string();
    }
    if d.contains("perms[") {
        return "hasAuthority".to_string();
    }
    "authenticated".to_string()
}

/// Shiro 的 URL 通配：`/**` 与 `**` 为任意多段，`/*` 与 `*` 为单段，其余精确匹配。
pub(crate) fn shiro_pattern_matches(route: &str, pattern: &str) -> bool {
    if pattern == "/**" || pattern == "**" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return route == prefix || route.starts_with(prefix);
    }
    if let Some(prefix) = pattern.strip_suffix("**") {
        return route.starts_with(prefix);
    }
    if let Some(base) = pattern.strip_suffix("/*") {
        if !route.starts_with(base) {
            return false;
        }
        let rest = &route[base.len()..];
        return !rest.is_empty() && !rest.trim_matches('/').contains('/');
    }
    if let Some(stem) = pattern.strip_suffix('*') {
        if !route.starts_with(stem) {
            return false;
        }
        let rest = &route[stem.len()..];
        return !rest.contains('/');
    }
    route == pattern
}

/// 该文件是否像 Shiro 链配置。
pub(crate) fn looks_like_shiro_config(content: &str) -> bool {
    content.lines().any(|l| {
        let t = l.trim();
        !is_import_or_package_line(t)
            && (t.contains("filterChainDefinitionMap")
                || t.contains("ShiroFilterFactoryBean")
                || t.contains("FilterChainDefinition"))
    })
}

/// 跨文件证据：Shiro 过滤器链。
///
/// 链内规则**保持声明顺序**（`LinkedHashMap` 的插入序即求值序，首个匹配生效），
/// 链没有"适用范围"与 `@Order`，因此 `matcher`/`order` 均为 None、顺序依据为声明序。
pub(crate) fn shiro_filter_chains(project_files: &[(String, String)]) -> Vec<SecurityChain> {
    let mut chains: Vec<SecurityChain> = Vec::new();
    for (cfg_path, cfg_content) in project_files.iter().take(max_index_files()) {
        if !looks_like_shiro_config(cfg_content) {
            continue;
        }
        let code = code_lines(cfg_content, hash_comment_language(cfg_path));
        let lines: Vec<&str> = cfg_content.lines().collect();
        let mut rules: Vec<SecurityRule> = Vec::new();
        let mut first_line: Option<u32> = None;
        for (idx, code_line) in code.iter().enumerate() {
            let ct = code_line.trim();
            if !(ct.contains("filterChainDefinitionMap.put(")
                || (ct.contains(".put(") && ct.contains("filterChainDefinitionMap")))
            {
                continue;
            }
            let raw = lines.get(idx).copied().unwrap_or("");
            let quoted: Vec<String> = {
                let mut acc = Vec::new();
                let mut rest = raw;
                while let Some(i) = rest.find('"') {
                    let after = &rest[i + 1..];
                    let Some(j) = after.find('"') else { break };
                    acc.push(after[..j].to_string());
                    rest = &after[j + 1..];
                }
                acc
            };
            if quoted.len() < 2 {
                continue;
            }
            let pattern = quoted[0].clone();
            let clause = shiro_clause(&quoted[1]);
            if first_line.is_none() {
                first_line = Some((idx + 1) as u32);
            }
            rules.push(SecurityRule {
                pattern,
                clause,
                kind: "shiro".to_string(),
                file: cfg_path.clone(),
                line: (idx + 1) as u32,
            });
        }
        if !rules.is_empty() {
            chains.push(SecurityChain {
                order: None,
                matcher: None,
                decl_index: chains.len(),
                file: cfg_path.clone(),
                line: first_line.unwrap_or(1),
                rules,
                // Shiro 的 CSRF 由它自己的过滤器承担，不在本证据面口径内
                csrf: None,
            });
        }
    }
    chains
}

/// 类型声明判定：`class`/`interface`/`enum`/`record` 且**本行或下一非空行**出现 `{`。
///
/// Allman 排版（`{` 独占下一行）在真实 Java 项目里很常见，只认同行会整批漏判。
pub(crate) fn is_type_declaration(code: &[String], idx: usize, line_trimmed: &str) -> bool {
    let head = line_trimmed.contains("class ")
        || line_trimmed.contains("interface ")
        || line_trimmed.contains("enum ")
        || line_trimmed.contains("record ");
    if !head {
        return false;
    }
    if line_trimmed.contains('{') {
        return true;
    }
    code.iter()
        .skip(idx + 1)
        .find(|l| !l.trim().is_empty())
        .map(|l| l.trim().starts_with('{'))
        .unwrap_or(false)
}

/// 模块根判定：取**最深的**、含构建文件（`pom.xml`/`build.gradle*`/`settings.gradle`）的祖先目录。
///
/// 一个仓库里可能并存多个独立应用（多模块 / 样例集合）⇒ 跨文件证据若按"仓库根=一个应用"取数，
/// 会把**别的应用**的安全链与过滤器算进本端点的覆盖判定（实测：某样例仓库混入 87 条链与外来 web.xml）。
/// 找不到构建文件时返回 None，由调用方保持"全项目"范围并如实标注。
pub(crate) fn module_root_of(
    project_files: &[(String, String)],
    file: &str,
) -> Option<String> {
    const MARKERS: [&str; 4] = ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"];
    let norm = file.replace('\\', "/");
    let mut dirs: Vec<&str> = norm.split('/').collect();
    dirs.pop(); // 去掉文件名，只保留目录
    // ① 最深的、含构建文件的祖先目录 = 该文件所属模块
    let mut probe = dirs.clone();
    let mut current: Option<String> = None;
    while !probe.is_empty() {
        let candidate_prefix = probe.join("/");
        let has_marker = MARKERS.iter().any(|m| {
            let candidate = format!("{}/{}", candidate_prefix, m);
            project_files
                .iter()
                .any(|(f, _)| f.replace('\\', "/") == candidate)
        });
        if has_marker {
            current = Some(candidate_prefix);
            break;
        }
        probe.pop();
    }
    let mut current = current?;
    // ② 沿**聚合链**上溯：父目录的构建文件若把本模块列为子模块，则应用根上移。
    //    （多模块单应用必须跨模块取证据；而"各自独立的应用集合"里父目录没有构建文件，自然停住）
    loop {
        let segs: Vec<&str> = current.split('/').collect();
        if segs.is_empty() {
            break;
        }
        let name = segs[segs.len() - 1];
        let parent = segs[..segs.len() - 1].join("/");
        let parent_build = MARKERS.iter().find_map(|m| {
            let c = if parent.is_empty() {
                m.to_string()
            } else {
                format!("{}/{}", parent, m)
            };
            project_files
                .iter()
                .find(|(f, _)| f.replace('\\', "/") == c)
                .map(|(_, content)| content.clone())
        });
        let aggregated = parent_build
            .map(|c| {
                c.contains(&format!("<module>{}</module>", name))
                    || c.contains(&format!("'{}'", name))
                    || c.contains(&format!("\"{}\"", name))
            })
            .unwrap_or(false);
        if !aggregated {
            break;
        }
        current = parent;
    }
    if current.is_empty() {
        Some(String::new())
    } else {
        Some(format!("{}/", current))
    }
}

/// 证据范围标签（如实陈述）。
pub(crate) fn evidence_scope_label(module_root: &Option<String>) -> &'static str {
    if module_root.is_some() {
        "module"
    } else {
        "project"
    }
}

/// 取 XML 元素属性值（`attr="value"`）。
pub(crate) fn xml_attr(line: &str, attr: &str) -> Option<String> {
    let key = format!("{}=\"", attr);
    line.split(&key)
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 行内是否出现该 XML **元素**（忽略任意命名空间前缀）：`<filter-chain`、`<sec:filter-chain`、
/// `<security:filter-chain` 都算；闭合标签（`</sec:filter-chain>`）不算。
///
/// 之所以不做字面前缀匹配：命名空间前缀是**任意取名**的（`sec:`/`security:`/自定义），
/// 只认某一种拼写会让另一种写法被静默漏读 —— 那会读成"没有配置保护"。
fn line_has_xml_element(line: &str, name: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = line[from..].find(name) {
        let abs = from + pos;
        let after = line[abs + name.len()..].chars().next();
        let after_ok = matches!(
            after,
            None | Some(' ') | Some('\t') | Some('/') | Some('>') | Some('\r') | Some('\n')
        );
        let before_ok = match line[..abs].chars().next_back() {
            Some('<') => true,
            Some(':') => line[..abs - 1].rfind('<').is_some_and(|lt| {
                let prefix = &line[lt + 1..abs - 1];
                !prefix.is_empty()
                    && prefix
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            }),
            _ => false,
        };
        if before_ok && after_ok {
            return true;
        }
        from = abs + name.len();
    }
    false
}

/// Ant 的 `*` 后缀按**前缀**处理（如 `/login.jsp*` 应命中 `/login.jsp` 及其后），
/// 与既有前缀语义（`/x/*`）保持一致，避免被当成字面量而不匹配。
pub(crate) fn normalize_ant_pattern(pattern: &str) -> String {
    if pattern.ends_with('*') && !pattern.ends_with("/**") && !pattern.ends_with("/*") {
        // 用 /**（前缀含自身）而不是 /*（单段）：Ant 的 /x* 应命中 /x 本身
        format!("{}/**", pattern.trim_end_matches('*'))
    } else {
        pattern.to_string()
    }
}

/// XML 里 `access="..."` 的子句：复用与注解侧同一套词汇，取不到即 `unspecified`（不猜）。
pub(crate) fn xml_access_clause(access: &str) -> String {
    if access.trim().is_empty() {
        return "unspecified".to_string();
    }
    if let Some(k) = AUTH_CLAUSES
        .iter()
        .filter_map(|k| access.find(*k).map(|p| (p, *k)))
        .min_by_key(|(p, _)| *p)
        .map(|(_, k)| k.trim_end_matches('(').to_string())
    {
        return k;
    }
    if access.contains("ROLE_") {
        return "hasRole".to_string();
    }
    "unspecified".to_string()
}

/// Spring Security 的 **XML 命名空间配置**：`<http>` 与其下的 `<intercept-url>`，
/// 以及旧式 `FilterChainProxy` 的 `<filter-chain>`（命名空间前缀任意）。
///
/// 与注解/Java DSL 侧**同语义**：`<http pattern="...">` 是链的适用范围（无 pattern 即全路径），
/// `<intercept-url pattern="..." access="..."/>` 是链内规则（顺序即生效顺序）；
/// `security="none"` 表示该范围不做安全（等价"公开"）。
pub(crate) fn spring_xml_security_chains(project_files: &[(String, String)]) -> Vec<SecurityChain> {
    let mut chains: Vec<SecurityChain> = Vec::new();
    let mut decl_index = 0usize;
    for (path, content) in project_files.iter().take(max_index_files()) {
        if !path.ends_with(".xml") {
            continue;
        }
        let looks_supported = content.contains("<intercept-url")
            || line_has_xml_element(content, "filter-chain")
            || content.contains("springframework.org/schema/security");
        if !looks_supported {
            continue;
        }
        let mut current: Option<usize> = None;
        for (idx, raw) in content.lines().enumerate() {
            let t = raw.trim();
            if t.starts_with("<http ") || t.starts_with("<http>") || t.starts_with("<security:http") {
                decl_index += 1;
                let matcher = xml_attr(t, "pattern").map(|p| normalize_ant_pattern(&p));
                let mut rules: Vec<SecurityRule> = Vec::new();
                if xml_attr(t, "security").as_deref() == Some("none") {
                    if let Some(m) = matcher.clone() {
                        rules.push(SecurityRule {
                            pattern: m,
                            clause: "permitAll".to_string(),
                            kind: "spring_xml".to_string(),
                            file: path.clone(),
                            line: (idx + 1) as u32,
                        });
                    }
                }
                chains.push(SecurityChain {
                    order: None,
                    matcher,
                    decl_index,
                    file: path.clone(),
                    line: (idx + 1) as u32,
                    rules,
                    csrf: None,
                });
                current = Some(chains.len() - 1);
                continue;
            }
            if t.starts_with("</http>") || t.starts_with("</security:http>") {
                current = None;
                continue;
            }
            // XML 命名空间里的 CSRF 配置：`<csrf disabled="true"/>` 即显式禁用，`<csrf/>` 即显式声明
            if line_has_xml_element(t, "csrf") {
                if let Some(ci) = current {
                    if chains[ci].csrf.is_none() {
                        chains[ci].csrf = Some(CsrfDeclaration {
                            state: if xml_attr(t, "disabled").as_deref() == Some("true") {
                                "disabled".to_string()
                            } else {
                                "declared".to_string()
                            },
                            patterns: Vec::new(),
                            file: path.clone(),
                            line: (idx + 1) as u32,
                        });
                    }
                }
                continue;
            }
            // 旧式 FilterChainProxy 的 <filter-chain>：filters=none → 公开；其它 → 无法推断 → unspecified
            if line_has_xml_element(t, "filter-chain") {
                let Some(p) = xml_attr(t, "pattern") else {
                    continue;
                };
                let filters = xml_attr(t, "filters").unwrap_or_default();
                let clause = if filters == "none" {
                    "permitAll"
                } else if filters.is_empty() {
                    continue;
                } else {
                    "unspecified"
                };
                if current.is_none() {
                    decl_index += 1;
                    chains.push(SecurityChain {
                        order: None,
                        matcher: None,
                        decl_index,
                        file: path.clone(),
                        line: (idx + 1) as u32,
                        rules: Vec::new(),
                        csrf: None,
                    });
                    current = Some(chains.len() - 1);
                }
                let ci = current.unwrap();
                chains[ci].rules.push(SecurityRule {
                    pattern: normalize_ant_pattern(&p),
                    clause: clause.to_string(),
                    kind: "spring_xml".to_string(),
                    file: path.clone(),
                    line: (idx + 1) as u32,
                });
                continue;
            }
            let Some(ci) = current else { continue };
            if !t.contains("<intercept-url") {
                continue;
            }
            let Some(p) = xml_attr(t, "pattern") else {
                continue;
            };
            let access = xml_attr(t, "access").unwrap_or_default();
            chains[ci].rules.push(SecurityRule {
                pattern: normalize_ant_pattern(&p),
                clause: xml_access_clause(&access),
                kind: "spring_xml".to_string(),
                file: path.clone(),
                line: (idx + 1) as u32,
            });
        }
    }
    chains
}

/// 函数式路由（WebFlux `RouterFunctions` 风格）：`route(GET("/x"), handler)` 里的谓词与路径。
///
/// 仅在文件确实引用了 WebFlux 函数式类型时才启用——否则普通 `GET("...")` 会被误当端点。
/// 返回 (行号, HTTP 方法, 路径)。路径本身即完整路径，不参与类级前缀拼接。
pub(crate) fn functional_routes(content: &str) -> Vec<(u32, String, String)> {
    // 窗口法实现（跨行 / .or() 嵌套）：见 `routes_syntax::functional_routes_window`
    functional_routes_window(content)
}

/// Sa-Token 的检查调用 → 子句词汇（与其它栈统一）；取不到即 `unspecified`（不猜）。
fn sa_token_clause(window: &str) -> String {
    const MAP: [(&str, &str); 3] = [
        ("checkLogin", "authenticated"),
        ("checkRole", "hasRole"),
        ("checkPermission", "hasAuthority"),
    ];
    MAP.iter()
        .filter_map(|(k, v)| window.find(*k).map(|p| (p, *v)))
        .min_by_key(|(p, _)| *p)
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| "unspecified".to_string())
}

/// Sa-Token 链：`SaInterceptor` 注册处为链，`SaRouter.match(pattern, () -> { StpUtil.checkXxx(); })`
/// 为链内规则。
///
/// 与其它栈**同语义**：pattern 用 Spring 通配（`/admin/**`），链内首个匹配的规则生效；
/// `checkLogin→authenticated`、`checkRole→hasRole`、`checkPermission→hasAuthority`，
/// 其余 check 一律 `unspecified`。拦截器上的 `addPathPatterns` 作为链的适用范围。
/// `SaRouter.notMatch(...)` 的排除语义**未建模**（实测靶未出现，不猜）。
pub(crate) fn sa_token_security_chains(project_files: &[(String, String)]) -> Vec<SecurityChain> {
    let mut chains: Vec<SecurityChain> = Vec::new();
    let mut decl_index = 0usize;
    for (path, content) in project_files.iter().take(max_index_files()) {
        let has_rule = content.lines().any(|l| {
            let t = l.trim();
            !is_import_or_package_line(t) && t.contains("SaRouter.match(")
        });
        if !has_rule {
            continue;
        }
        let lines: Vec<&str> = content.lines().collect();
        let code = code_lines(content, hash_comment_language(path));
        let start = code
            .iter()
            .position(|l| l.contains("SaInterceptor") && !is_import_or_package_line(l.trim()))
            .or_else(|| code.iter().position(|l| l.contains("SaRouter.match(")));
        let Some(start) = start else { continue };
        decl_index += 1;
        let matcher = code
            .iter()
            .skip(start)
            .take(8)
            .find(|l| l.contains("addPathPatterns"))
            .and_then(|l| url_patterns_in(l).into_iter().next())
            .map(|p| normalize_ant_pattern(&p));
        let mut rules: Vec<SecurityRule> = Vec::new();
        for (idx, code_line) in code.iter().enumerate() {
            if idx < start || !code_line.contains("SaRouter.match(") {
                continue;
            }
            let raw = lines.get(idx).copied().unwrap_or("");
            let mut patterns = url_patterns_in(raw);
            if patterns.is_empty() {
                patterns.push("<dynamic>".to_string());
            }
            let window: String = lines
                .iter()
                .skip(idx)
                .take(5)
                .cloned()
                .collect::<Vec<&str>>()
                .join(" ");
            let clause = sa_token_clause(&window);
            for p in patterns {
                rules.push(SecurityRule {
                    pattern: normalize_ant_pattern(&p),
                    clause: clause.clone(),
                    kind: "sa-token".to_string(),
                    file: path.clone(),
                    line: (idx + 1) as u32,
                });
            }
        }
        chains.push(SecurityChain {
            order: None,
            matcher,
            decl_index,
            file: path.clone(),
            line: (start + 1) as u32,
            rules,
            // Sa-Token 的 CSRF 不在本证据面口径内
            csrf: None,
        });
    }
    chains.sort_by_key(|c| (c.order.unwrap_or(i64::MAX), c.decl_index));
    chains
}

/// 反应式（WebFlux）安全链：`ServerHttpSecurity.authorizeExchange(...)` 里的
/// `pathMatchers(...)` / `matchers(...)` / `anyExchange()` 规则。
///
/// 与 servlet 侧**同语义**：链内首个匹配的规则生效；`anyExchange()` 等价 `/**` 兜底；
/// 非字面量匹配器（如 `PathRequest.toStaticResources()`）登记为 `<dynamic>`，不猜。
pub(crate) fn reactive_security_chains(project_files: &[(String, String)]) -> Vec<SecurityChain> {
    let mut chains: Vec<SecurityChain> = Vec::new();
    let mut decl_index = 0usize;
    for (cfg_path, cfg_content) in project_files.iter().take(max_index_files()) {
        let has_marker = cfg_content.lines().any(|l| {
            let t = l.trim();
            !is_import_or_package_line(t)
                && (t.contains("ServerHttpSecurity")
                    || t.contains("SecurityWebFilterChain")
                    || t.contains("@EnableWebFluxSecurity"))
        });
        if !has_marker {
            continue;
        }
        let cfg_code = code_lines(cfg_content, hash_comment_language(cfg_path));
        let cfg_lines: Vec<&str> = cfg_content.lines().collect();
        let mut current: Option<usize> = None;
        for (idx, code_line) in cfg_code.iter().enumerate() {
            let ct = code_line.trim();
            if ct.contains("return http.build();") {
                current = None;
                continue;
            }
            // 链起点：返回 `SecurityWebFilterChain` 的方法声明
            if ct.contains("SecurityWebFilterChain") && ct.contains('(') && !ct.contains("class ") {
                decl_index += 1;
                let order = cfg_lines
                    .iter()
                    .take(idx)
                    .rev()
                    .take(4)
                    .find_map(|l| {
                        let t = l.trim();
                        t.strip_prefix("@Order(")
                            .and_then(|s| s.split(')').next())
                            .and_then(|s| s.trim().parse::<i64>().ok())
                    });
                chains.push(SecurityChain {
                    order,
                    matcher: None,
                    decl_index,
                    file: cfg_path.clone(),
                    line: (idx + 1) as u32,
                    rules: Vec::new(),
                    csrf: None,
                });
                current = Some(chains.len() - 1);
                continue;
            }
            // 反应式链上的 CSRF 声明（`.csrf(...)`）：与 servlet 侧同一读法
            if ct.contains(".csrf(") {
                let Some(ci) = current else { continue };
                if chains[ci].csrf.is_none() {
                    if let Some((state, patterns, line)) =
                        csrf_declaration_at(&cfg_code, &cfg_lines, idx)
                    {
                        chains[ci].csrf = Some(CsrfDeclaration {
                            state,
                            patterns,
                            file: cfg_path.clone(),
                            line,
                        });
                    }
                }
                continue;
            }
            let Some(ci) = current else { continue };
            let is_path = ct.contains("pathMatchers(");
            let is_matchers = ct.contains("matchers(") && !is_path;
            let is_any_exchange = ct.contains("anyExchange()");
            if !is_path && !is_matchers && !is_any_exchange {
                continue;
            }
            let raw = cfg_lines.get(idx).copied().unwrap_or("");
            let window: String = cfg_lines
                .iter()
                .skip(idx)
                .take(4)
                .cloned()
                .collect::<Vec<&str>>()
                .join(" ");
            let clause = AUTH_CLAUSES
                .iter()
                .filter_map(|k| window.find(*k).map(|p| (p, *k)))
                .min_by_key(|(p, _)| *p)
                .map(|(_, k)| k.trim_end_matches('(').to_string())
                .unwrap_or_else(|| "unspecified".to_string());
            let mut patterns: Vec<String> = if is_any_exchange {
                vec!["/**".to_string()]
            } else {
                url_patterns_in(raw)
            };
            if patterns.is_empty() {
                patterns.push("<dynamic>".to_string());
            }
            for pattern in patterns {
                chains[ci].rules.push(SecurityRule {
                    pattern,
                    clause: clause.clone(),
                    kind: "spring_webflux".to_string(),
                    file: cfg_path.clone(),
                    line: (idx + 1) as u32,
                });
            }
        }
    }
    chains.sort_by_key(|c| (c.order.unwrap_or(i64::MAX), c.decl_index));
    chains
}
/// 自动配置保护：构建文件声明了安全 starter，但取数范围内**没有任何可读的安全配置**。
///
/// 此时"未找到显式配置"是事实，但**不等于没有保护**（框架默认配置会生效）⇒ 端点上带出
/// `security_starter_without_explicit_config` 提示与 starter 出处，结论本身不改写。
pub(crate) fn security_starter_without_config(
    project_files: &[(String, String)],
) -> Option<(String, u32)> {
    const STARTERS: [&str; 5] = [
        "spring-boot-starter-security",
        "spring-security-web",
        "spring-boot-starter-oauth2",
        "shiro-spring",
        "sa-token",
    ];
    for (path, content) in project_files.iter().take(max_index_files()) {
        let name = path.rsplit('/').next().unwrap_or(path);
        if name != "pom.xml" && name != "build.gradle" && name != "build.gradle.kts" {
            continue;
        }
        for (idx, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with("*") {
                continue;
            }
            if STARTERS.iter().any(|s| t.contains(s)) {
                return Some((path.clone(), (idx + 1) as u32));
            }
        }
    }
    None
}

/// 已识别但**未建模**的保护栈信号：命中即说明"这里有保护机制，但我们不建模它"，
/// 必须如实标注，绝不静默给出"没有保护"的结论。
///
/// 收录判据（三条缺一不可）：① 该串**明确指向某个保护框架**（不是通用基类或库调用）；
/// ② 该框架当前未建模；③ 真实项目里出现过。
/// 刻意**不收录** `OncePerRequestFilter` / `Jwts.parser` 这类通用串——它们可能只是日志过滤器
/// 或令牌签发，收录会让"未建模"到处出现，反而噪声化；这类判定不了的东西只作证据、不参与判定。
pub(crate) const UNMODELED_PROTECTION_SIGNALS: [(&str, &str); 5] = [
    ("SaInterceptor", "sa-token"),
    ("StpUtil", "sa-token"),
    ("@SaCheck", "sa-token"),
    ("SaTokenConfig", "sa-token"),
    // JAX-RS 请求过滤器：资源/方法级注解（`@PermitAll`/`@DenyAll`/`@RolesAllowed`）已作为授权证据，
    // 但过滤器里的**全局规则不可读** ⇒ 作为信号如实提示"未建模"，而不是说成"没有保护"。
    ("ContainerRequestFilter", "jax-rs"),
];

/// 扫描取数范围内的未建模保护栈信号（按框架去重，返回 (框架, 文件, 行)）。
pub(crate) fn unmodeled_protection_signals(project_files: &[(String, String)]) -> Vec<(String, String, u32)> {
    let mut out: Vec<(String, String, u32)> = Vec::new();
    for (path, content) in project_files.iter().take(max_index_files()) {
        for (idx, raw) in content.lines().enumerate() {
            let t = raw.trim();
            if is_import_or_package_line(t) {
                continue;
            }
            for (marker, framework) in UNMODELED_PROTECTION_SIGNALS.iter() {
                if t.contains(marker) && !out.iter().any(|(f, _, _)| f == framework) {
                    out.push((framework.to_string(), path.clone(), (idx + 1) as u32));
                }
            }
        }
    }
    out
}

/// 反应式（WebFlux）安全配置：`SecurityWebFilterChain` / `ServerHttpSecurity` / `@EnableWebFluxSecurity`。
///
/// 该类配置当前**未建模**；把它探测出来是为了能**如实**说"未建模"，而不是给出会被读成
/// "没有保护"的 `no_global_config_found`。导入行不算（`import ...ServerHttpSecurity;` 到处都是）。
pub(crate) fn reactive_security_config(project_files: &[(String, String)]) -> Option<(String, u32)> {
    for (f, content) in project_files.iter().take(max_index_files()) {
        if !content.contains("ServerHttpSecurity") && !content.contains("@EnableWebFluxSecurity") {
            continue;
        }
        for (idx, raw) in content.lines().enumerate() {
            let t = raw.trim();
            if is_import_or_package_line(t) {
                continue;
            }
            if t.contains("ServerHttpSecurity")
                || t.contains("SecurityWebFilterChain")
                || t.contains("@EnableWebFluxSecurity")
            {
                return Some((f.clone(), (idx + 1) as u32));
            }
        }
    }
    None
}
/// 声明性噪声行：`import` / `package` / `using` 是声明，不是证据。
///
/// 放在共享位置，避免"导入语句被当成保护证据或配置"——实测中容器过滤器注册曾在
/// `import ...FilterRegistrationBean;` 这一行上命中。
pub(crate) fn is_import_or_package_line(t: &str) -> bool {
    t.starts_with("import ") || t.starts_with("package ") || t.starts_with("using ")
}

/// 从注册窗口里取过滤器名：优先 `setName("...")`，其次泛型 `FilterRegistrationBean<Xxx>`，
/// 再次 `setFilter(... new Xxx())`；取不到即 None（不编造名字）。
pub(crate) fn filter_class_name(window: &[&str]) -> Option<String> {
    if let Some(n) = window.iter().find_map(|l| {
        l.split("setName(\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }) {
        return Some(n);
    }
    if let Some(n) = window.iter().find_map(|l| {
        l.split("FilterRegistrationBean<")
            .nth(1)
            .and_then(|s| s.split('>').next())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }) {
        return Some(n);
    }
    window
        .iter()
        .filter_map(|l| l.split("new ").nth(1))
        .filter_map(|s| s.split(['(', '<', ' ']).next())
        .map(|s| s.to_string())
        .find(|s| !s.is_empty() && s != "FilterRegistrationBean")
}

/// 拦截器注册：`registry.addInterceptor(x).addPathPatterns("/**")` 形态。
///
/// 只交付**注册事实 + 适用路径**，不判定鉴权——拦截器内部做了什么无法从注册信息推断。
/// 它与容器过滤器、安全配置并列，构成第三条保护面。
pub(crate) fn interceptor_registrations(project_files: &[(String, String)]) -> Vec<ContainerFilter> {
    let mut out: Vec<ContainerFilter> = Vec::new();
    for (f, content) in project_files.iter().take(max_index_files()) {
        if !content.contains("addInterceptor(") {
            continue;
        }
        let lines: Vec<&str> = content.lines().collect();
        let code = code_lines(content, hash_comment_language(f));
        for (idx, code_line) in code.iter().enumerate() {
            if !code_line.contains("addInterceptor(") {
                continue;
            }
            let raw = lines.get(idx).copied().unwrap_or("");
            // 拦截器名：优先取 `new Xxx(` 里的类型名，否则取实参里的首个标识符
            let after = raw.split("addInterceptor(").nth(1).unwrap_or("");
            let name = after
                .split("new ")
                .nth(1)
                .and_then(|s| s.split(|c: char| !(c.is_alphanumeric() || c == '_')).next())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    after
                        .trim_start_matches('(')
                        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .next()
                        .filter(|s| !s.is_empty())
                })
                .map(|s| s.to_string());
            // 适用路径：本行或其后 3 行内的 addPathPatterns(...)
            let mut patterns: Vec<String> = Vec::new();
            for l in lines.iter().skip(idx).take(4) {
                if l.contains("addPathPatterns") {
                    patterns.extend(url_patterns_in(l));
                }
            }
            let (pattern, basis) = if patterns.is_empty() {
                ("/**".to_string(), "default_all_paths")
            } else {
                (patterns[0].clone(), "add_path_patterns")
            };
            // 同一注册可能被多行命中：按 (kind, pattern, file) 去重
            if out.iter().any(|e| {
                e.kind == "handler_interceptor" && e.pattern == pattern && e.file == *f
            }) {
                continue;
            }
            out.push(ContainerFilter {
                pattern,
                kind: "handler_interceptor".to_string(),
                file: f.clone(),
                line: (idx + 1) as u32,
                name,
                basis: basis.to_string(),
                dispatcher: None,
            });
        }
    }
    out
}

/// 给端点补上拦截器注册证据（类级映射不参与）。
pub(crate) fn annotate_interceptors(routes: &mut [Value], regs: &[ContainerFilter]) {
    for entry in routes.iter_mut() {
        if entry.get("scope").and_then(|v| v.as_str()) == Some("class") {
            continue;
        }
        let route = entry
            .get("route")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let matched: Vec<Value> = if route.is_empty() {
            Vec::new()
        } else {
            regs.iter()
                .filter(|r| servlet_pattern_matches(&route, &r.pattern))
                .take(3)
                .map(|r| {
                    json!({
                        "pattern": r.pattern,
                        "basis": r.basis,
                        "name": r.name,
                        "file": r.file,
                        "line": r.line,
                    })
                })
                .collect()
        };
        let count = matched.len();
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("interceptors".to_string(), json!(matched));
            obj.insert("interceptor_count".to_string(), json!(count));
        }
    }
}

/// 映射注解的作用域：位于类声明**之上**的是类级前缀，不是端点。
///
/// 类级 `@RequestMapping` 只提供前缀，把它当端点会让"端点清单"多出并不存在的请求路径。
pub(crate) fn route_scope(content: &str, line: u32) -> &'static str {
    let class_line = type_declaration_line(content);
    if class_line > 0 && line <= class_line {
        "class"
    } else {
        "method"
    }
}

/// 方法级映射才继承类级前缀；类声明**自身**的 `@RequestMapping` 行不重复拼接。
pub(crate) fn annotate_route_with_prefix(content: &str, line: u32, route: Option<&str>) -> Option<String> {
    let class_line = type_declaration_line(content);
    if class_line > 0 && line <= class_line {
        return route.map(|s| s.to_string());
    }
    join_route_paths(class_route_prefix(content).as_deref(), route)
}
/// 类级路由前缀：`@RequestMapping("...")`（Spring MVC）或 `@Path("...")`（JAX-RS 资源类）。
///
/// 只扫描**类声明正上方**那段连续注解，避免把方法级映射当类级前缀；
/// 两种注解都在时以 `@RequestMapping` 为准（同一文件不会混用两种风格）。
pub(crate) fn class_route_prefix(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let code = code_lines(content, false);
    let mut class_idx: Option<usize> = None;
    for (idx, code_line) in code.iter().enumerate() {
        let t = code_line.trim();
        if is_type_declaration(&code, idx, t) {
            class_idx = Some(idx);
            break;
        }
    }
    let ci = class_idx?;
    let mut i = ci;
    let mut jaxrs_prefix: Option<String> = None;
    while i > 0 {
        i -= 1;
        let raw = lines.get(i).copied().unwrap_or("");
        let t = raw.trim();
        if t.is_empty() {
            break;
        }
        if !t.starts_with('@') {
            break;
        }
        if t.contains("@RequestMapping") {
            let path = raw.split('"').nth(1)?;
            if !path.is_empty() {
                return Some(path.to_string());
            }
        }
        // JAX-RS：类级 `@Path` 与 Spring 的类级 `@RequestMapping` 同义（都是**拼接**前缀）
        if jaxrs_prefix.is_none() && t.contains("@Path(") {
            if let Some(p) = raw.split('"').nth(1) {
                if !p.is_empty() {
                    jaxrs_prefix = Some(p.to_string());
                }
            }
        }
    }
    jaxrs_prefix
}

/// 拼接类级前缀与方法级路径（Spring 的语义是**拼接**，方法级以 `/` 开头也不例外）。
///
/// 两者都缺时不产出路由（如实留空，而不是造一个空路径）。
pub(crate) fn join_route_paths(prefix: Option<&str>, path: Option<&str>) -> Option<String> {
    fn norm(s: &str) -> String {
        let t = s.trim();
        if t.is_empty() {
            String::new()
        } else if t.starts_with('/') {
            t.to_string()
        } else {
            format!("/{}", t)
        }
    }
    let p = prefix.map(norm).unwrap_or_default();
    let m = path.map(norm).unwrap_or_default();
    if p.is_empty() && m.is_empty() {
        return None;
    }
    if p.is_empty() {
        return Some(m);
    }
    if m.is_empty() {
        return Some(p);
    }
    Some(format!("{}{}", p.trim_end_matches('/'), m))
}

/// 行内是否为 JAX-RS 动词注解（`@GET`/`@POST`…）。
///
/// 注解名后必须不是标识符字符：`@GetMapping`（Spring）含 `@GET` 子串但**不算** JAX-RS 动词。
pub(crate) fn jaxrs_verb_on_line(line: &str) -> Option<&'static str> {
    const VERBS: [(&str, &str); 7] = [
        ("@GET", "GET"),
        ("@POST", "POST"),
        ("@PUT", "PUT"),
        ("@DELETE", "DELETE"),
        ("@PATCH", "PATCH"),
        ("@HEAD", "HEAD"),
        ("@OPTIONS", "OPTIONS"),
    ];
    let t = line.trim();
    if !t.starts_with('@') {
        return None;
    }
    VERBS
        .iter()
        .find(|(m, _)| {
            t.starts_with(*m)
                && !t[m.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .map(|(_, v)| *v)
}

/// JAX-RS 的"**仅动词**路由"：动词注解所在方法（同一段连续注解块）里**没有**方法级 `@Path`，
/// 此时有效路径就是类级 `@Path` ⇒ 这条路由必须由动词行本身声明。
///
/// 反之，注解块里已有 `@Path` 时路由由那一行声明，动词行**不得**再产生第二条路由。
pub(crate) fn jaxrs_verb_only_route(content: &str, line: u32) -> Option<&'static str> {
    let lines: Vec<&str> = content.lines().collect();
    let idx = (line.checked_sub(1)?) as usize;
    let verb = jaxrs_verb_on_line(*lines.get(idx)?)?;
    // 注解块 = 包含该行的那段连续 `@` 行（止于第一个非注解行）
    let mut lo = idx;
    while lo > 0 {
        let t = lines[lo - 1].trim();
        if t.is_empty() || !t.starts_with('@') {
            break;
        }
        lo -= 1;
    }
    let mut hi = idx;
    while hi + 1 < lines.len() {
        let t = lines[hi + 1].trim();
        if t.is_empty() || !t.starts_with('@') {
            break;
        }
        hi += 1;
    }
    let has_path = (lo..=hi).any(|i| lines[i].trim().contains("@Path("));
    (!has_path).then_some(verb)
}

/// JAX-RS 的动词注解（`@GET`/`@POST`…）通常与 `@Path` **不在同一行**（先后两种顺序都常见），
/// 因此在本行与方法所在的那段**连续注解块**（向上、向下，止于第一个非注解行）里找动词。
///
/// 取不到即 `None`——子资源定位方法只有 `@Path` 而没有动词，此时由调用方按既有口径记 `ANY`。
pub(crate) fn jaxrs_http_method(content: &str, line: u32) -> Option<&'static str> {
    let lines: Vec<&str> = content.lines().collect();
    let idx = (line.checked_sub(1)?) as usize;
    if idx >= lines.len() {
        return None;
    }
    if let Some(v) = jaxrs_verb_on_line(lines[idx]) {
        return Some(v);
    }
    let mut i = idx;
    while i > 0 {
        i -= 1;
        let t = lines[i].trim();
        if t.is_empty() || !t.starts_with('@') {
            break;
        }
        if let Some(v) = jaxrs_verb_on_line(lines[i]) {
            return Some(v);
        }
    }
    for raw in lines.iter().skip(idx + 1) {
        if !raw.trim().starts_with('@') {
            break;
        }
        if let Some(v) = jaxrs_verb_on_line(raw) {
            return Some(v);
        }
    }
    None
}

/// 判定要素里"看起来像检查"的标记（与 `get_sanitizer_guards` 同族，但这里只用于**命中计数**）。
pub(crate) const LOCUS_CHECK_TOKENS: [&str; 12] = [
    "if ", "if(", ">=", "<=", "==", "!=", "sizeof", "assert", "return", "break", "continue", "switch",
];

// ── 策略来源与路由声明的共用判定 ──────────────────────────────────────────────

/// 文件角色：在 core 的路径角色（test/build/vendor）之上，把**文档与示例**单列。
///
/// 安全策略只能来自生产源码/配置：文档里的示例代码、测试夹具与示例工程都不是"项目策略"。
/// 实测：把 `.adoc` 文档里的示例当策略，会让端点被判成"已保护"（假安全）。
pub(crate) fn policy_file_role(path: &str) -> &'static str {
    let role = deepaudit_core::scanning::classify_file_role(path);
    if role != "production" {
        return role;
    }
    let normalized = path.replace('\\', "/").to_lowercase();
    // 路径首段也要能命中（`docs/x.adoc`、`sample/x.java`）：统一补一个前导 `/` 再匹配
    let padded = format!("/{normalized}");
    let file_name = normalized.rsplit('/').next().unwrap_or("");
    let ext = file_name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if matches!(
        ext,
        "adoc" | "asciidoc" | "md" | "markdown" | "rst" | "txt" | "org" | "textile"
    ) {
        return "documentation";
    }
    // 只收**目录形态**明确表示示例/文档的标记。`/demo/`、`/example/`、`/samples/` 都太宽：
    // 常见包名是 `com.example.demo`，而真实工程目录也常叫 `samples/`（会把生产代码误降级）。
    for marker in [
        "/docs/",
        "/doc/",
        "/documentation/",
        "/examples/",
        "/testdata/",
    ] {
        if padded.contains(marker) {
            return "example";
        }
    }
    "production"
}

/// 被排除的非生产策略来源上限（有界上报，不静默）。
pub(crate) const MAX_EXCLUDED_POLICY_SOURCES: usize = 8;

/// 策略来源：只保留生产源码/配置。
///
/// 返回 `(可用文件, 被排除的策略文件)`；后者**有界**，用于在响应里如实上报"读到了但没当策略"。
pub(crate) fn policy_sources(
    project_files: &[(String, String)],
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut used: Vec<(String, String)> = Vec::new();
    let mut excluded: Vec<(String, String)> = Vec::new();
    for (path, content) in project_files.iter().take(max_index_files()) {
        let role = policy_file_role(path);
        if role == "production" {
            used.push((path.clone(), content.clone()));
        } else if excluded.len() < MAX_EXCLUDED_POLICY_SOURCES && looks_like_security_config(content) {
            excluded.push((path.clone(), role.to_string()));
        }
    }
    (used, excluded)
}

/// 识别"声明式路由但本引擎未建模"的文件形态（返回框架名）。
///
/// 这类文件里端点**一定存在**，但语法没被解析；上层必须据此报"未建模"，不能给出空端点表让人读成
/// "没有攻击面"。当前识别：Django（`urls.py` + `urlpatterns`）、Rails（`routes.rb` + `get '`）。
pub(crate) fn unmodelled_route_declaration(path: &str, content: &str) -> Option<&'static str> {
    let normalized = path.replace('\\', "/").to_lowercase();
    let file_name = normalized.rsplit('/').next().unwrap_or("");
    if (file_name == "urls.py" || normalized.contains("/urls/")) && content.contains("urlpatterns") {
        return Some("django");
    }
    if file_name == "routes.rb" && (content.contains(" get '") || content.contains(" post '") || content.contains("resources ")) {
        return Some("rails");
    }
    None
}

/// 从一行原始文本里取路由字面量：双引号优先，其次单引号；非空时保证以 `/` 开头。
///
/// 只认双引号会让 JS/Python 的 `'/path'` 变成 `route=None`
/// （实测：Express/Flask 的路由条目全部没有路径，消费者无法知道是哪个端点）。
pub(crate) fn extract_route_literal(line: &str) -> Option<String> {
    let raw = line
        .split('"')
        .nth(1)
        .or_else(|| line.split('\'').nth(1))?
        .trim();
    if raw.is_empty() {
        return None;
    }
    Some(if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("/{raw}")
    })
}

/// 非注解式声明（Express/Gin/Flask 等）的 HTTP 动词推断。
///
/// 只对**已命中路由标记**的行调用，因此误判面很小；拿不到就返回 `None`（由上层如实标注）。
pub(crate) fn infer_http_method(code_line: &str) -> Option<&'static str> {
    const VERBS: [(&str, &str); 7] = [
        ("GET", "GET"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("DELETE", "DELETE"),
        ("PATCH", "PATCH"),
        ("HEAD", "HEAD"),
        ("OPTIONS", "OPTIONS"),
    ];
    for (name, method) in VERBS {
        if code_line.contains(&format!(".{name}(")) {
            return Some(method);
        }
    }
    for (name, method) in VERBS {
        let lower = format!(".{}(", name.to_lowercase());
        if code_line.contains(&lower)
            && (code_line.contains("app.")
                || code_line.contains("router.")
                || code_line.contains("route(")
                || code_line.contains("@app.")
                || code_line.contains("@router.")
                || code_line.contains("@bp."))
        {
            return Some(method);
        }
    }
    None
}

/// 路由声明标记（字面子串）。
///
/// 精度要求：`Route::` 必须带动词（PHP 框架的 `Route::get(`），否则会命中任意
/// `SomeRoute::method` 引用（实测：Java 测试代码里的 `HelloRoute::handle` 被当成 8 条路由）。
pub(crate) const ROUTE_MARKERS: [&str; 21] = [
    "@app.route",
    "@router.",
    "@RequestMapping",
    "app.get(",
    "router.get(",
    "r.GET(",
    "Route::get(",
    "Route::post(",
    "Route::put(",
    "Route::patch(",
    "Route::delete(",
    "Route::any(",
    "Route::match(",
    "#[get(",
    "#[post(",
    "@GetMapping",
    "@PostMapping",
    "@PutMapping",
    "@DeleteMapping",
    "@PatchMapping",
    "@Path(",
];

/// 中间件/保护声明标记。
pub(crate) const MIDDLEWARE_MARKERS: [&str; 26] = [
    "middleware",
    "before_action",
    "@UseGuards",
    "interceptor",
    "filter_chain",
    "login_required",
    "permission_required",
    "before_request",
    "app.use(",
    ".use(",
    "@PreAuthorize",
    "@PostAuthorize",
    "@Secured",
    "@RolesAllowed",
    "@PermitAll",
    "@DenyAll",
    "@EnableWebSecurity",
    "@EnableMethodSecurity",
    "SecurityFilterChain",
    "WebSecurityConfigurerAdapter",
    "authorizeHttpRequests",
    "authorizeRequests",
    "addFilterBefore",
    "addFilterAfter",
    "OncePerRequestFilter",
    "HttpSecurity",
];

/// 单文件路由扫描结果（`get_framework_context` 与项目级端点表共用同一套口径）。
pub(crate) struct FileRouteScan {
    pub routes: Vec<Value>,
    pub middleware: Vec<Value>,
    pub provenance: Vec<Provenance>,
    pub routes_total: usize,
    pub middleware_total: usize,
    pub preproc_note: Option<String>,
    pub cpp_fallback: bool,
}

/// 逐行扫描单个文件里的路由/中间件声明。
///
/// 口径（与旧实现逐字一致，除下列显式修正）：
/// - 注释/字符串里出现的标记不算（走代码视图）；未激活的预处理分支不算；
/// - JAX-RS 动词注解只有在"该方法没有自己的 `@Path`"时才是路由声明；
/// - 路由字面量：双引号优先、其次单引号，并补前导 `/`；
/// - 每条路由带 `file_role`，消费者可据此区分生产/测试/示例；
/// - 路径解析不出时给 `route_path_unresolved: true`（不静默）。
pub(crate) fn scan_routes_in_file(
    path: &str,
    content: &str,
    handler: &str,
    id: &str,
) -> FileRouteScan {
    let code = code_lines(content, hash_comment_language(path));
    let originals: Vec<&str> = content.lines().collect();
    let (pp_states, pp_note) = preproc_view(path, content, false);
    let jaxrs_resource = code.iter().any(|l| l.trim().contains("@Path("));
    let role = policy_file_role(path);
    // 非注解式栈（JS/TS/Go/Python）：走语法扫描（接收者感知的动词、组/mount 前缀、跨行字面量），
    // 不再用"字面 marker + 行内首个字面量"；中间件/保护声明仍用标记扫描供上层算 effective_chain。
    let non_java = !(path.ends_with(".java")
        || path.ends_with(".kt")
        || path.ends_with(".xml"));
    let mut out = FileRouteScan {
        routes: Vec::new(),
        middleware: Vec::new(),
        provenance: Vec::new(),
        routes_total: 0,
        middleware_total: 0,
        preproc_note: pp_note.clone(),
        cpp_fallback: pp_note.is_some(),
    };
    if non_java && has_syntax_scanner(path) {
        out.routes = scan_non_java_routes(path, content);
        out.routes_total = out.routes.len();
        for (idx, code_line) in code.iter().enumerate() {
            let t = code_line.trim();
            if t.is_empty() || is_import_or_package_line(t) {
                continue;
            }
            if pp_states.get(idx).map(|s| s.dead).unwrap_or(false) {
                continue;
            }
            if MIDDLEWARE_MARKERS.iter().any(|m| t.contains(*m)) {
                out.middleware_total += 1;
                if out.middleware.len() < MAX_HITS {
                    let text = originals.get(idx).copied().unwrap_or("").trim();
                    out.provenance.push(prov(path, (idx + 1) as u32, id));
                    out.middleware.push(json!({
                        "line": idx + 1,
                        "text": text.chars().take(200).collect::<String>(),
                        "file_role": role,
                    }));
                }
            }
        }
        out.routes.sort_by_key(|r| r["line"].as_u64().unwrap_or(0));
        out.routes.truncate(MAX_HITS);
        return out;
    }

    for (idx, code_line) in code.iter().enumerate() {
        let ln = (idx + 1) as u32;
        let text = originals.get(idx).copied().unwrap_or("");
        let trimmed = text.trim();
        let code_trimmed = code_line.trim();
        if code_trimmed.is_empty() {
            continue;
        }
        if is_import_or_package_line(code_trimmed) {
            continue;
        }
        if pp_states.get(idx).map(|s| s.dead).unwrap_or(false) {
            continue;
        }
        // JAX-RS 动词注解只有在"该方法没有自己的 `@Path`"时才是路由声明
        let jaxrs_verb = if jaxrs_resource {
            jaxrs_verb_only_route(content, ln)
        } else {
            None
        };
        if (ROUTE_MARKERS.iter().any(|m| code_trimmed.contains(*m)) || jaxrs_verb.is_some())
            && (handler.is_empty() || trimmed.contains(handler))
        {
            out.routes_total += 1;
            if out.routes.len() + out.middleware.len() < MAX_HITS {
                out.provenance.push(prov(path, ln, id));
                // 动词注解本身没有实参 ⇒ 路由完全由类级前缀给出（行内注释里的字符串也不得被当成路径）
                let route_value = if jaxrs_verb.is_some() && !code_trimmed.contains("@Path(") {
                    None
                } else {
                    // 非 Java 栈的声明常跨行（`router.get(` 与路径字面量分行）：做**有界前瞻**（≤3 行），
                    // 否则路径会静默为空。Java/注解式不前瞻（类级前缀语义由前缀函数负责）。
                    let marker_only_file = !(path.ends_with(".java")
                        || path.ends_with(".kt")
                        || path.ends_with(".xml"));
                    extract_route_literal(trimmed).or_else(|| {
                        if !marker_only_file {
                            return None;
                        }
                        for off in 1..=3usize {
                            let next = originals.get(idx + off).copied().unwrap_or("");
                            if next.trim().is_empty() {
                                continue;
                            }
                            if let Some(v) = extract_route_literal(next) {
                                return Some(v);
                            }
                        }
                        None
                    })
                };
                let http_method = [
                    ("@GetMapping", "GET"),
                    ("@PostMapping", "POST"),
                    ("@PutMapping", "PUT"),
                    ("@DeleteMapping", "DELETE"),
                    ("@PatchMapping", "PATCH"),
                    ("@RequestMapping", "ANY"),
                ]
                .iter()
                .find(|(m, _)| code_trimmed.contains(*m))
                .map(|(_, v)| v.to_string())
                .or_else(|| {
                    (jaxrs_verb.is_some() || (jaxrs_resource && code_trimmed.contains("@Path(")))
                        .then(|| jaxrs_http_method(content, ln).unwrap_or("ANY").to_string())
                })
                .or_else(|| infer_http_method(code_trimmed).map(|m| m.to_string()));
                let route = if jaxrs_verb.is_some() && !code_trimmed.contains("@Path(") {
                    // 仅动词路由：路径继承类级前缀，由前缀函数补齐
                    annotate_route_with_prefix(content, ln, None)
                } else {
                    annotate_route_with_prefix(content, ln, route_value.as_deref())
                };
                out.routes.push(json!({
                    "line": ln,
                    "text": trimmed.chars().take(200).collect::<String>(),
                    "route": route,
                    "route_raw": route_value,
                    // 类级映射只提供前缀，不是端点
                    "scope": route_scope(content, ln),
                    "http_method": http_method,
                    "file_role": role,
                    "route_path_unresolved": route.is_none(),
                }));
            }
        }
        if MIDDLEWARE_MARKERS.iter().any(|m| code_trimmed.contains(*m)) {
            out.middleware_total += 1;
            if out.routes.len() + out.middleware.len() < MAX_HITS {
                out.provenance.push(prov(path, ln, id));
                out.middleware.push(json!({
                    "line": ln,
                    "text": trimmed.chars().take(200).collect::<String>(),
                    "file_role": role,
                }));
            }
        }
    }
    // 函数式路由（WebFlux RouterFunctions 风格）：与注解式并列的端点声明方式
    for (fln, fmethod, fpath) in functional_routes(content) {
        if out.routes.iter().any(|r| {
            r["line"].as_u64() == Some(fln as u64) && r["route"].as_str() == Some(fpath.as_str())
        }) {
            continue;
        }
        if out.routes.len() + out.middleware.len() >= MAX_HITS {
            break;
        }
        out.provenance.push(prov(path, fln, id));
        out.routes.push(json!({
            "line": fln,
            "text": content
                .lines()
                .nth(fln as usize - 1)
                .unwrap_or("")
                .trim()
                .chars()
                .take(200)
                .collect::<String>(),
            "route": fpath,
            "route_raw": fpath,
            "scope": "method",
            "http_method": fmethod,
            "route_source": "functional",
            "file_role": role,
            "route_path_unresolved": false,
        }));
    }
    out
}

