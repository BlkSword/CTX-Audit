// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CPG 自动函数摘要生成
//!
//! 从 FunctionCPG 的分析结果自动生成精确的 FunctionSummary，
//! 替代 cross_file.rs 中基于 heuristics 的 compute_single_summary。

use crate::analysis::alias::AccessPath;
use crate::analysis::cpg::FunctionCPG;
use crate::analysis::cross_file::{FunctionSummary, ParamToCall, SinkReachability};
use crate::analysis::taint::{TaintFlow, TaintSink, VulnerabilityType};
use std::collections::HashMap;

/// 从 FunctionCPG 的污点分析结果自动生成函数摘要
///
/// 遍历每个参数，通过 AccessPath 追踪：
/// - 参数是否到达返回节点（affects_return）
/// - 参数是否到达 sink（direct_sinks）
pub fn compute_summary_from_cpg(
    func_cpg: &FunctionCPG,
    taint_flows: &[TaintFlow],
    body_text: &str,
    sink_rules: &[TaintSink],
) -> FunctionSummary {
    let sig = &func_cpg.signature;
    let func_id = sig.id();

    let mut taint_propagation = Vec::new();
    let mut direct_sinks = Vec::new();

    for (param_idx, param) in sig.params.iter().enumerate() {
        let param_name = &param.name;

        // 收集从该参数出发的污点流。
        // source.symbol 与参数名精确匹配，或参数作为对象/数组根（如 input.xxx / input[0]）。
        let param_flows: Vec<&TaintFlow> = taint_flows
            .iter()
            .filter(|f| {
                let src = f.source.symbol.trim();
                src == param_name
                    || src.starts_with(&format!("{}.", param_name))
                    || src.starts_with(&format!("{}[", param_name))
            })
            .collect();

        // 参数存在污点流：保守认为它可能影响返回值（caller 需继续追踪）。
        // 后续可通过返回语句分析进一步精确化。
        let affects_return = !param_flows.is_empty();
        taint_propagation.push((param_idx, affects_return));

        // 参数是否到达 sink
        for flow in &param_flows {
            let sink_symbol = &flow.sink.symbol;
            let vuln_type = flow.vulnerability_type.clone();

            // 检查是否已有同 param + sink 的记录
            let already_recorded = direct_sinks.iter().any(|ds: &SinkReachability| {
                ds.from_param == param_idx && ds.sink_name == *sink_symbol
            });

            if !already_recorded {
                let (sanitized, sanitizer) =
                    detect_sink_sanitization(body_text, sink_symbol, sink_rules);
                direct_sinks.push(SinkReachability {
                    sink_name: sink_symbol.clone(),
                    from_param: param_idx,
                    sanitized: flow.confidence < 0.5 || sanitized,
                    sanitizer,
                    sink_line: flow.sink.line,
                    vuln_type,
                });
            }
        }
    }

    // 构建“变量 -> 下游调用参数”映射，用于 param_to_calls
    let mut var_to_calls: HashMap<String, Vec<(String, usize, usize)>> = HashMap::new();
    for node_meta in func_cpg.node_meta.values() {
        if let Some(ref call) = node_meta.call_info {
            for (arg_idx, arg) in call.arguments.iter().enumerate() {
                for var in &arg.referenced_vars {
                    var_to_calls.entry(var.clone()).or_default().push((
                        call.callee.clone(),
                        arg_idx,
                        call.line,
                    ));
                }
            }
        }
    }

    let mut param_to_calls = Vec::new();
    for (param_idx, param) in sig.params.iter().enumerate() {
        let param_name = &param.name;
        for flow in taint_flows.iter().filter(|f| {
            let src = f.source.symbol.trim();
            src == param_name
                || src.starts_with(&format!("{}.", param_name))
                || src.starts_with(&format!("{}[", param_name))
        }) {
            let sink_var = flow.sink.symbol.trim();
            if let Some(calls) = var_to_calls.get(sink_var) {
                for (callee, arg_idx, call_line) in calls {
                    param_to_calls.push(crate::analysis::cross_file::ParamToCall {
                        param_idx,
                        callee: callee.clone(),
                        arg_idx: *arg_idx,
                        call_line: *call_line,
                    });
                }
            }
        }
    }

    // 也从调用图中提取 sink 信息（补充 CPG 未覆盖的）
    for node_meta in func_cpg.node_meta.values() {
        if let Some(ref call) = node_meta.call_info {
            if sink_rules.iter().any(|rule| {
                rule.patterns
                    .iter()
                    .any(|p| call.callee.contains(p) || p.contains(&call.callee))
            }) {
                // 找到 sink 调用 — 检查是否有对应的 param_idx
                let already = direct_sinks.iter().any(|ds| ds.sink_line == call.line);
                if !already {
                    // 无法确定是哪个参数到达的，标记为 param 0
                    if direct_sinks.iter().all(|ds| ds.sink_name != call.callee) {
                        let (sanitized, sanitizer) =
                            detect_sink_sanitization(body_text, &call.callee, sink_rules);
                        direct_sinks.push(SinkReachability {
                            sink_name: call.callee.clone(),
                            from_param: 0,
                            sanitized: sanitized,
                            sanitizer,
                            sink_line: call.line,
                            vuln_type: infer_vuln_type(&call.callee),
                        });
                    }
                }
            }
        }
    }

    FunctionSummary {
        func_id,
        func_name: sig.name.clone(),
        file_path: sig.file_path.clone(),
        taint_propagation,
        direct_sinks,
        param_to_calls,
        body_hash: None,
    }
}

/// 通用 sink 净化检测。
///
/// 遍历 `sink_rules`，找出其 sink pattern 与 `sink_symbol` 匹配的规则；
/// 若该规则声明了 sanitizers，且 `body_text` 中在 sink 出现之前存在任一 sanitizer
/// 模式，则判定已净化。
fn detect_sink_sanitization(
    body_text: &str,
    sink_symbol: &str,
    sink_rules: &[TaintSink],
) -> (bool, Option<String>) {
    let lines: Vec<&str> = body_text.lines().collect();
    if lines.is_empty() {
        return (false, None);
    }

    for rule in sink_rules {
        if rule.sanitizers.is_empty() {
            continue;
        }
        // 该规则是否与当前 sink 相关
        let relevant = rule.patterns.iter().any(|p| {
            let pl = p.to_lowercase();
            let sl = sink_symbol.to_lowercase();
            sl.contains(&pl) || pl.contains(&sl)
        });
        if !relevant {
            continue;
        }

        // 找到该规则 sink pattern 首次出现的行号
        let mut sink_line: Option<usize> = None;
        for (idx, line) in lines.iter().enumerate() {
            let lower = line.to_lowercase();
            if rule
                .patterns
                .iter()
                .any(|p| lower.contains(&p.to_lowercase()))
            {
                sink_line = Some(idx);
                break;
            }
        }
        let Some(sl) = sink_line else {
            continue;
        };

        // 检查 sink 之前（含同行）是否出现 sanitizer
        for (idx, line) in lines.iter().enumerate().take(sl + 1) {
            let lower = line.to_lowercase();
            for san in &rule.sanitizers {
                if lower.contains(&san.to_lowercase()) {
                    return (true, Some(san.clone()));
                }
            }
        }
    }

    (false, None)
}

/// 从 sink 函数名推断漏洞类型
fn infer_vuln_type(func_name: &str) -> VulnerabilityType {
    let lower = func_name.to_lowercase();

    // 排除辅助函数（与 cross_file.rs 保持一致）
    let helper_prefixes: &[&str] = &[
        "get_", "build_", "list_", "load_", "init_", "setup_",
        "parse_", "format_", "validate_", "check_", "verify_",
        "serialize_", "encode_", "decode_", "read_", "write_",
        "scan_", "walk_", "postprocess_", "preprocess_", "deserialize_",
        "close_", "handle_", "resolve_", "extract_", "convert_",
        "simplify_", "populate_", "compute_", "generate_", "register_",
        "install_", "deploy_", "upload_", "download_", "stream_",
        "preview_", "render_", "display_", "transform_", "combine_",
        "process_", "collect_", "normalize_", "clean_", "filter_",
        "sort_", "find_", "search_",
    ];
    for prefix in helper_prefixes {
        if lower.starts_with(prefix) {
            return VulnerabilityType::Generic;
        }
    }

    // SQL 先检查（cursor.execute 包含 exec，需在命令注入前匹配）
    if lower.contains("query")
        || lower.contains("sql")
        || lower.contains("cursor")
        || lower.contains("jdbctemplate")
        || lower.contains("preparedstatement")
        || lower.contains("database")
    {
        return VulnerabilityType::SqlInjection;
    }

    if lower.contains("exec")
        || lower.contains("system")
        || lower.contains("spawn")
        || lower.contains("shell_exec")
        || lower.contains("passthru")
    {
        return VulnerabilityType::CommandInjection;
    }

    if lower.contains("eval") || lower.contains("compile") || lower.contains("__import__") {
        return VulnerabilityType::CodeInjection;
    }

    if lower.contains("fetch")
        || lower.contains("axios")
        || lower.contains("http")
        || lower.contains("urllib")
    {
        return VulnerabilityType::ServerSideRequestForgery;
    }

    // PathTraversal: 更精确的匹配，避免误报 built-in open()
    if lower.contains("fileinputstream")
        || lower.contains("fileoutputstream")
        || lower.contains("readfile")
        || lower.contains("writefile")
        || (lower.contains("open") && !lower.contains("openapi") && !lower.contains("open_api"))
        || (lower.contains("file") && !lower.contains("profile"))
        || lower.contains("fs.")
        || (lower.contains("read") && lower.contains("file"))
        || (lower.contains("write") && lower.contains("file"))
    {
        return VulnerabilityType::PathTraversal;
    }

    if lower.contains("ldap") {
        return VulnerabilityType::LdapInjection;
    }

    if lower.contains("xpath") || lower.contains("jxpath") {
        return VulnerabilityType::XPathInjection;
    }

    if lower.contains("md5") || lower.contains("sha1") || lower.contains("messagedigest") {
        return VulnerabilityType::WeakHashAlgorithm;
    }

    if lower.contains("addcookie") || lower.contains("responsecookie") {
        return VulnerabilityType::InsecureCookie;
    }

    if lower.contains("setattribute") || lower.contains("putvalue") {
        return VulnerabilityType::TrustBoundaryViolation;
    }

    VulnerabilityType::Generic
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_vuln_type_command_injection() {
        assert!(matches!(
            infer_vuln_type("exec"),
            VulnerabilityType::CommandInjection
        ));
        assert!(matches!(
            infer_vuln_type("child_process.exec"),
            VulnerabilityType::CommandInjection
        ));
    }

    #[test]
    fn test_infer_vuln_type_sql_injection() {
        assert!(matches!(
            infer_vuln_type("cursor.execute"),
            VulnerabilityType::SqlInjection
        ));
        assert!(matches!(
            infer_vuln_type("db.query"),
            VulnerabilityType::SqlInjection
        ));
    }

    #[test]
    fn test_infer_vuln_type_code_injection() {
        assert!(matches!(
            infer_vuln_type("eval"),
            VulnerabilityType::CodeInjection
        ));
    }

    #[test]
    fn test_infer_vuln_type_ssrf() {
        assert!(matches!(
            infer_vuln_type("fetch"),
            VulnerabilityType::ServerSideRequestForgery
        ));
    }

    #[test]
    fn test_infer_vuln_type_unknown() {
        assert!(matches!(
            infer_vuln_type("some_unknown_func"),
            VulnerabilityType::Generic
        ));
    }
}
