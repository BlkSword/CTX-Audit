// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CPG 自动函数摘要生成
//!
//! 从 FunctionCPG 的分析结果自动生成精确的 FunctionSummary，
//! 替代 cross_file.rs 中基于 heuristics 的 compute_single_summary。

use crate::analysis::alias::AccessPath;
use crate::analysis::cpg::FunctionCPG;
use crate::analysis::cross_file::{FunctionSummary, SinkReachability};
use crate::analysis::taint::{TaintFlow, VulnerabilityType};

/// 从 FunctionCPG 的污点分析结果自动生成函数摘要
///
/// 遍历每个参数，通过 AccessPath 追踪：
/// - 参数是否到达返回节点（affects_return）
/// - 参数是否到达 sink（direct_sinks）
pub fn compute_summary_from_cpg(
    func_cpg: &FunctionCPG,
    taint_flows: &[TaintFlow],
    sink_names: &[&str],
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
                direct_sinks.push(SinkReachability {
                    sink_name: sink_symbol.clone(),
                    from_param: param_idx,
                    sanitized: flow.confidence < 0.5,
                    sanitizer: None,
                    sink_line: flow.sink.line,
                    vuln_type,
                });
            }
        }
    }

    // 也从调用图中提取 sink 信息（补充 CPG 未覆盖的）
    for node_meta in func_cpg.node_meta.values() {
        if let Some(ref call) = node_meta.call_info {
            if sink_names
                .iter()
                .any(|s| call.callee.contains(s) || s.contains(&call.callee))
            {
                // 找到 sink 调用 — 检查是否有对应的 param_idx
                let already = direct_sinks.iter().any(|ds| ds.sink_line == call.line);
                if !already {
                    // 无法确定是哪个参数到达的，标记为 param 0
                    if direct_sinks.iter().all(|ds| ds.sink_name != call.callee) {
                        direct_sinks.push(SinkReachability {
                            sink_name: call.callee.clone(),
                            from_param: 0,
                            sanitized: false,
                            sanitizer: None,
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
        body_hash: None,
    }
}

/// 从 sink 函数名推断漏洞类型
fn infer_vuln_type(func_name: &str) -> VulnerabilityType {
    let lower = func_name.to_lowercase();

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
        || lower.contains("request")
        || lower.contains("http")
        || lower.contains("urllib")
    {
        return VulnerabilityType::ServerSideRequestForgery;
    }

    if lower.contains("write")
        || lower.contains("read")
        || lower.contains("open")
        || lower.contains("file")
        || lower.contains("fs.")
    {
        return VulnerabilityType::PathTraversal;
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
