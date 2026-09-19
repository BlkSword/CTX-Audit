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

    // 每个被调用函数的实参变量名（按 callee 聚合，避免行号空间差异）。
    // 用于校验形参到 sink 的归因：形参污点经其它变量/结构体字段扩散出来的流，
    // 不应归因给该形参（实测某多参辅助函数 f(r, of, path, pool) 的 param0(r)
    // 被归因到 open(of->file->name)，产生 13 条路径遍历误报）。
    let mut callee_arg_vars: HashMap<String, Vec<String>> = HashMap::new();
    let mut meta_ids_for_args: Vec<usize> = func_cpg.node_meta.keys().copied().collect();
    meta_ids_for_args.sort_unstable();
    for node_id in &meta_ids_for_args {
        let Some(node_meta) = func_cpg.node_meta.get(node_id) else {
            continue;
        };
        if let Some(ref call) = node_meta.call_info {
            let entry = callee_arg_vars.entry(call.callee.clone()).or_default();
            for arg in &call.arguments {
                entry.extend(arg.referenced_vars.iter().cloned());
            }
        }
    }

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

            // 归因校验（有实参信息时）：sink 调用的实参必须真的引用该形参，
            // 或流路径中存在实参变量与形参的赋值证据；否则该流是形参污点
            // 扩散到其它变量/字段后的产物，不归因给本形参。
            if let Some(arg_vars) = callee_arg_vars.get(sink_symbol) {
                let direct = arg_vars.iter().any(|v| {
                    v == param_name
                        || v.starts_with(&format!("{}.", param_name))
                        || v.starts_with(&format!("{}->", param_name))
                        || v.starts_with(&format!("{}[", param_name))
                });
                let alias_backed = !direct
                    && arg_vars.iter().any(|a| {
                        flow.path.iter().any(|st| {
                            let text = st.code_snippet.as_deref().unwrap_or("");
                            (st.symbol == *a
                                || crate::analysis::cross_file::line_references_var(text, a))
                                && crate::analysis::cross_file::line_references_var(
                                    text, param_name,
                                )
                        })
                    });
                if !direct && !alias_backed {
                    continue;
                }
            }

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
    // 确定性：node_meta 是 HashMap，直接 values() 迭代顺序随进程随机。
    // 下面两处收集都受顺序影响（尤其 direct_sinks 的"同名 sink 只记第一个"
    // 去重：哪个调用点被记录取决于迭代序 → sink 行号/from_param 随机 →
    // 跨文件流集合跨运行抖动）。统一按节点 id 升序遍历。
    let mut meta_ids: Vec<usize> = func_cpg.node_meta.keys().copied().collect();
    meta_ids.sort_unstable();

    let mut var_to_calls: HashMap<String, Vec<(String, usize, usize)>> = HashMap::new();
    for node_id in &meta_ids {
        let Some(node_meta) = func_cpg.node_meta.get(node_id) else {
            continue;
        };
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
            if src == param_name
                || src.starts_with(&format!("{}.", param_name))
                || src.starts_with(&format!("{}[", param_name))
            {
                return true;
            }
            // Stage B 的 flow.source.symbol 常是"赋值左侧局部变量"
            // （`let ts = params.get(k)` → source 是 ts）。若源符号或流路径中
            // 出现该形参，则该流同样源自此形参 —— 这是 param_to_calls 能命中的关键。
            if crate::analysis::cross_file::line_references_var(&f.source.symbol, param_name) {
                return true;
            }
            f.path.iter().any(|step| {
                crate::analysis::cross_file::line_references_var(&step.symbol, param_name)
                    || step
                        .code_snippet
                        .as_deref()
                        .map(|code| {
                            crate::analysis::cross_file::line_references_var(code, param_name)
                        })
                        .unwrap_or(false)
            })
        }) {
            // `flow.sink.symbol` 是"被调用的 sink 函数名"（如 exec），而
            // `var_to_calls` 按实参变量名建索引 —— 直接拿 sink 名查恒为空。
            // 正确做法：用该流路径上的"值承载变量"（PropagationStep.to_var /
            // 步骤符号 / 源符号）去查，找出"哪个实参携带了该污染值"。
            let mut value_vars: Vec<String> = Vec::new();
            let src = flow.source.symbol.trim();
            if !src.is_empty() {
                value_vars.push(src.to_string());
            }
            for step in &flow.path {
                let sym = step.symbol.trim();
                if !sym.is_empty() {
                    value_vars.push(sym.to_string());
                }
                // 代码片段里出现、且确实是某次调用的实参变量名 ⇒ 该值可能被传入该调用
                if let Some(code) = step.code_snippet.as_deref() {
                    for key in var_to_calls.keys() {
                        if crate::analysis::cross_file::line_references_var(code, key) {
                            value_vars.push(key.clone());
                        }
                    }
                }
            }
            for var in value_vars {
                if let Some(calls) = var_to_calls.get(var.as_str()) {
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
    }

    // 补充：形参**直接**作为实参传入下游调用（不依赖单文件污点流）。
    // 这是最基础的数据流事实：`fn f(p) { g(p); }` 中 p → g 的第 0 个实参。
    // 单文件 CPG 污点流在各语言上都很少（实测某 Rust 目标整仓仅 1 条、某 Java
    // 目标 111 条、某 TS 目标 20 条），只靠流推导会让 param_to_calls 几乎恒空，
    // 而"形参被直接传出"不需要流即可确定，且正是跨文件传播所需的信息。
    for (param_idx, param) in sig.params.iter().enumerate() {
        let param_name = param.name.trim();
        if param_name.is_empty() {
            continue;
        }
        if let Some(calls) = var_to_calls.get(param_name) {
            for (callee, arg_idx, call_line) in calls {
                let already = param_to_calls.iter().any(|p| {
                    p.param_idx == param_idx
                        && p.callee == *callee
                        && p.arg_idx == *arg_idx
                        && p.call_line == *call_line
                });
                if !already {
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
    // 确定性：上面的补充按 sig.params/Vec 顺序追加，但仍统一排序，
    // 使摘要内容不依赖任何 HashMap 迭代序（跨运行比较流集合指纹时更稳）。
    param_to_calls.sort_by(|a, b| {
        (a.param_idx, a.call_line, a.callee.as_str(), a.arg_idx).cmp(&(
            b.param_idx,
            b.call_line,
            b.callee.as_str(),
            b.arg_idx,
        ))
    });

    // 也从调用图中提取 sink 信息（补充 CPG 未覆盖的）
    // 同一 meta_ids 顺序遍历（确定性）
    for node_id in &meta_ids {
        let Some(node_meta) = func_cpg.node_meta.get(node_id) else {
            continue;
        };
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
