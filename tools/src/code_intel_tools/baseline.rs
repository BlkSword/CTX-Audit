// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 鉴权基线卡（`get_security_baseline`）—— 把"这个项目的'受保护'是什么意思"
//! 压缩成一屏可复核的事实，替代审计员重新读一遍安全配置。
//!
//! 只报**读到的事实**（链/规则/过滤器/注解/被关闭的钩子）与**未找到什么**，
//! 不推断运行时行为。体量目标 ≤ 3KB：链 ≤ 8 条、规则 ≤ 12 条/链、过滤器 ≤ 12 条。

use super::*;

/// 把一条过滤器链压成基线卡里的一行。
fn chain_json(c: &SecurityChain) -> Value {
    let rules: Vec<Value> = c
        .rules
        .iter()
        .take(8)
        .map(|r| {
            json!({
                "match": r.pattern,
                "clause": r.clause,
                "kind": r.kind,
                "file": r.file,
                "line": r.line,
            })
        })
        .collect();
    json!({
        "order": c.order,
        "matcher": c.matcher,
        "file": c.file,
        "line": c.line,
        "rules": rules,
        "rules_total": c.rules.len(),
        "csrf": c.csrf.as_ref().map(|x| json!({
            "state": x.state,
            "patterns": x.patterns,
            "file": x.file,
            "line": x.line,
        })),
    })
}

fn filter_json(f: &ContainerFilter) -> Value {
    json!({
        "name": f.name,
        "kind": f.kind,
        "pattern": f.pattern,
        "file": f.file,
        "line": f.line,
    })
}

/// 注解消费者：每个鉴权注解是否**有代码真的消费它**。
///
/// 这是 R248/R249 里最费审计员时间的一步：注解写了不等于生效（`@ProCheck` 就是空注解）。
/// 只认能读到消费者的证据（Sa-Token 拦截器、@EnableMethodSecurity、Shiro 注解处理器）。
fn annotation_consumers(project_files: &[(String, String)]) -> Vec<Value> {
    let max_files = max_index_files();
    let mut sa_interceptor: Option<(String, u32)> = None;
    let mut method_security: Option<(String, u32)> = None;
    let mut shiro_annotations: Option<(String, u32)> = None;
    let mut present: std::collections::BTreeMap<&'static str, (String, u32)> = Default::default();
    for (path, content) in project_files.iter().take(max_files) {
        for (idx, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("import ") || t.starts_with("package ") {
                continue;
            }
            let lineno = (idx + 1) as u32;
            if t.contains("new SaInterceptor") || t.contains("SaInterceptor(") {
                if sa_interceptor.is_none() {
                    sa_interceptor = Some((path.clone(), lineno));
                }
            }
            // 注意：`@EnableWebSecurity` 只启用过滤器链，**不**启用方法级鉴权
            // （`@PreAuthorize` 需要 `@EnableMethodSecurity` / `@EnableGlobalMethodSecurity`）。
            if t.contains("@EnableMethodSecurity") || t.contains("@EnableGlobalMethodSecurity") {
                if method_security.is_none() {
                    method_security = Some((path.clone(), lineno));
                }
            }
            if t.contains("AuthorizationAttributeSourceAdvisor")
                || t.contains("ShiroAnnotationProcessor")
            {
                if shiro_annotations.is_none() {
                    shiro_annotations = Some((path.clone(), lineno));
                }
            }
            for ann in AUTH_ANNOTATIONS {
                if present.contains_key(ann) {
                    continue;
                }
                if mentions_annotation(t, ann) {
                    present.insert(ann, (path.clone(), lineno));
                }
            }
        }
    }
    let mut out: Vec<Value> = Vec::new();
    for (ann, (file, line)) in present.iter() {
        let consumer = if ann.starts_with("Sa") {
            sa_interceptor.clone()
        } else if matches!(
            *ann,
            "PreAuthorize" | "PostAuthorize" | "Secured" | "RolesAllowed" | "PermitAll" | "DenyAll"
        ) {
            method_security.clone()
        } else {
            shiro_annotations.clone()
        };
        out.push(match consumer {
            Some((cf, cl)) => json!({
                "annotation": ann,
                "used_at": {"file": file, "line": line},
                "consumer": {"file": cf, "line": cl},
                "consumed": true,
            }),
            None => json!({
                "annotation": ann,
                "used_at": {"file": file, "line": line},
                "consumer": Value::Null,
                "consumed": false,
                "caveat": "annotation_present_without_detected_consumer",
            }),
        });
    }
    out
}

/// 被显式关闭/改写的安全钩子（读到即报）。
fn disabled_hooks(project_files: &[(String, String)]) -> Vec<Value> {
    let max_files = max_index_files();
    let mut out: Vec<Value> = Vec::new();
    for (path, content) in project_files.iter().take(max_files) {
        for (idx, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("import ") || t.starts_with("package ") {
                continue;
            }
            let hit = t.contains("checkRequestPath")
                || t.contains("csrf(AbstractHttpConfigurer::disable)")
                || (t.contains(".csrf(") && t.contains("disable"))
                || t.contains("checkElementAnnotation")
                || t.contains("isAnnotation = false");
            if !hit {
                continue;
            }
            out.push(json!({
                "hook": if t.contains("checkRequestPath") { "sa-token.path_check" }
                        else if t.contains("csrf") { "spring.csrf" }
                        else { "annotation_switch" },
                "file": path,
                "line": (idx + 1) as u32,
                "text": t.chars().take(160).collect::<String>(),
            }));
            if out.len() >= 8 {
                return out;
            }
        }
    }
    out
}

/// 基线卡主体。
pub(crate) fn security_baseline(
    files: &[(String, String)],
    index_truncated: bool,
) -> (Value, &'static str, Vec<&'static str>) {
    let policy_files: &[(String, String)] = files;
    let mut chains: Vec<SecurityChain> = Vec::new();
    chains.extend(security_config_chains(policy_files));
    chains.extend(reactive_security_chains(policy_files));
    chains.extend(spring_xml_security_chains(policy_files));
    chains.extend(shiro_filter_chains(policy_files));
    chains.extend(sa_token_security_chains(policy_files));
    let chains_total = chains.len();
    let rules_total: usize = chains.iter().map(|c| c.rules.len()).sum();
    let mut filters: Vec<ContainerFilter> = Vec::new();
    filters.extend(container_filter_registrations(policy_files));
    filters.extend(interceptor_registrations(policy_files));
    let filters_total = filters.len();
    let unmodeled = unmodeled_protection_signals(policy_files);
    let consumers = annotation_consumers(policy_files);
    let disabled = disabled_hooks(policy_files);
    let unconsumed: Vec<&str> = consumers
        .iter()
        .filter(|c| c.get("consumed").and_then(|v| v.as_bool()) == Some(false))
        .filter_map(|c| c.get("annotation").and_then(|v| v.as_str()))
        .collect();
    let mut reasons: Vec<&'static str> = vec!["project_level_scan", "syntax_scan"];
    if index_truncated {
        reasons.push("index_truncated_at_limit");
    }
    if chains_total == 0 {
        reasons.push("no_security_chain_found");
    }
    if !unconsumed.is_empty() {
        reasons.push("annotations_without_consumer");
    }
    let level = if index_truncated {
        "high"
    } else if chains_total == 0 {
        "high"
    } else if rules_total == 0 {
        "medium"
    } else {
        "low"
    };
    let data = json!({
        "files_indexed": files.len(),
        "index_truncated_at_limit": index_truncated,
        "limits": {"max_files": max_index_files()},
        "summary": {
            "chains": chains_total,
            "rules": rules_total,
            "container_filters": filters_total,
            "has_path_level_policy": rules_total > 0,
            "annotation_level_consumed": consumers.iter().filter(|c| c.get("consumed").and_then(|v| v.as_bool()) == Some(true)).count(),
            "annotations_without_consumer": unconsumed,
            "unmodeled_protection_frameworks": unmodeled.iter().take(4).map(|(n, f, l)| json!({"framework": n, "file": f, "line": l})).collect::<Vec<Value>>(),
        },
        "chains": chains.iter().take(8).map(chain_json).collect::<Vec<Value>>(),
        "chains_total": chains_total,
        "container_filters": filters.iter().take(6).map(filter_json).collect::<Vec<Value>>(),
        "container_filters_total": filters_total,
        "annotation_consumers": consumers,
        "disabled_hooks": disabled,
    });
    (data, level, reasons)
}
