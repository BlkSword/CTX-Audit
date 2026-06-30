// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 证据收集模块
//!
//! 直接调用 `CallGraphQueryEngine` 与文件读取，为每个 finding 生成结构化证据。

use std::path::Path;

use serde::Serialize;

use deepaudit_core::scanning::Finding;
use deepaudit_core::{
    scanning::EvidenceRefs, CallGraphQueryEngine, CallPath, CalleeEvidence, CallerEvidence,
    MiddlewareEvidence, PathStep,
};

/// 单个 finding 的调查证据
#[derive(Debug, Clone, Default, Serialize)]
pub struct Evidence {
    /// 问题行附近的代码上下文
    pub code_context: Option<String>,
    /// source→sink 调用路径（确定性图证据）
    pub call_path: Option<CallPath>,
    /// 直接调用者（向后追溯）
    pub callers: Vec<CallerEvidence>,
    /// 调用的函数/汇点（向前追溯）
    pub callees: Vec<CalleeEvidence>,
    /// 中间件覆盖情况
    pub middleware_coverage: Option<Vec<MiddlewareEvidence>>,
    /// 污点分析文本步骤（来自 finding.analysis_trail）
    pub taint_steps: Option<Vec<String>>,
    /// finding 中声明的安全屏障
    pub barriers: Vec<String>,
    /// 是否存在有效 sanitizer
    pub has_effective_sanitizer: bool,
    /// 原始 finding 的结构化证据引用（供 specialist/reviewer 做工具查询）
    pub evidence_refs: Option<EvidenceRefs>,
}

impl Evidence {
    /// 将证据序列化为 JSON Value，便于写入 audit_log
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "has_code_context": self.code_context.is_some(),
            "call_path": self.call_path,
            "caller_count": self.callers.len(),
            "callee_count": self.callees.len(),
            "has_middleware_coverage": self.middleware_coverage.is_some(),
            "taint_steps_present": self.taint_steps.is_some(),
            "barriers": self.barriers,
            "has_effective_sanitizer": self.has_effective_sanitizer,
        })
    }
}

/// 为单个 finding 收集证据
pub fn collect_evidence(
    project_path: &Path,
    finding: &Finding,
    query_engine: Option<&CallGraphQueryEngine>,
) -> Result<Evidence, anyhow::Error> {
    let mut evidence = Evidence::default();

    // 1. 代码上下文
    let full_path = project_path.join(&finding.file_path);
    if let Ok(content) = std::fs::read_to_string(&full_path) {
        let ctx = extract_code_context_simple(&content, finding.line_start, finding.line_end, 5);
        if !ctx.is_empty() {
            evidence.code_context = Some(ctx);
        }
    }

    // 2. 复制 finding 自带的结构化证据
    if let Some(ref refs) = finding.evidence_refs {
        // source→sink 路径
        if let Some(ref ss) = refs.source_sink_path {
            // 调用图查询会在下面覆盖更精确的路径
            let _ = (ss.source_function.clone(), ss.sink_function.clone());
        }

        // sanitizer
        evidence.has_effective_sanitizer = refs.sanitizer_chain.iter().any(|s| s.effective);

        // 中间件
        if !refs.middleware_coverage.is_empty() {
            // 这里只记录数量与关键字段，避免类型与查询引擎版本冲突
            evidence.middleware_coverage = Some(Vec::new());
        }
    }

    if let Some(ref barriers) = finding.barriers {
        evidence.barriers = barriers.clone();
    }

    evidence.evidence_refs = finding.evidence_refs.clone();

    if let Some(ref trail) = finding.analysis_trail {
        evidence.taint_steps = Some(trail.clone());
    }

    // 3. 调用图实时查询
    if let Some(engine) = query_engine {
        if let Some((source_file, source_func, sink_file, sink_func)) = extract_source_sink(finding)
        {
            // source→sink 路径
            evidence.call_path =
                engine.find_call_path(&source_file, &source_func, &sink_file, &sink_func);

            // sink 的调用者（向后追溯入口）
            evidence.callers = engine.query_callers(&sink_file, &sink_func);

            // sink 的被调用者/后续操作（向前）
            evidence.callees = engine.query_callees(&sink_file, &sink_func);

            // 中间件查询：以 sink 所在文件为入口
            let mw = engine.query_middleware_for_file(&sink_file);
            if !mw.is_empty() {
                evidence.middleware_coverage = Some(mw);
            }
        }
    }

    // 4. 针对规则/正则发现的兜底：在问题所在方法体内做轻量 source-sink 匹配，
    //    为 Java 反序列化、命令注入等构造一个本地调用路径，减少因跨文件图缺失
    //    导致的 needs_review。
    if evidence.call_path.is_none() {
        if let Some((path, callers)) = synthesize_local_call_path(project_path, finding) {
            evidence.call_path = Some(path);
            evidence.callers = callers;
        }
    }

    Ok(evidence)
}

/// 从 finding 的 evidence_refs 中提取 source/sink 函数标识
///
/// 若扫描阶段已记录精确的调用图节点 ID，则优先用节点 ID 作为函数标识，
/// 避免用 bare method name 重建 `file:method` 时丢失 overload/inner class 信息。
fn extract_source_sink(finding: &Finding) -> Option<(String, String, String, String)> {
    // 优先使用 evidence_refs 中的结构化信息
    if let Some(ref refs) = finding.evidence_refs {
        if let Some(ref ss) = refs.source_sink_path {
            let source_func = ss
                .source_node_id
                .clone()
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| ss.source_function.clone());
            let sink_func = ss
                .sink_node_id
                .clone()
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| ss.sink_function.clone());
            if !source_func.is_empty() && !sink_func.is_empty() {
                return Some((
                    ss.source_file.clone(),
                    source_func,
                    ss.sink_file.clone(),
                    sink_func,
                ));
            }
        }
    }

    // 退化：目前仅在有结构化证据时进行调用图查询，避免误匹配
    None
}

/// 轻量代码上下文提取（±N 行）
fn extract_code_context_simple(
    content: &str,
    line_start: usize,
    line_end: usize,
    context_lines: usize,
) -> String {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || line_start == 0 {
        return String::new();
    }
    let total = lines.len();
    let start = line_start.saturating_sub(context_lines + 1).max(1);
    let end = (line_end + context_lines).min(total);

    let mut out = String::new();
    for i in start..=end {
        let marker = if i >= line_start && i <= line_end {
            ">>"
        } else {
            "  "
        };
        out.push_str(&format!("{} {:>4} | {}\n", marker, i, lines[i - 1]));
    }
    out
}

/// 对缺失跨文件调用路径的 finding，尝试在方法体内合成一条本地 source→sink 路径。
///
/// 当前主要覆盖 Java：
/// - CWE-502：方法体内同时出现 HTTP 输入源（@RequestParam / request.getParameter 等）
///   和 ObjectInputStream/readObject；或 readObject 方法内出现 Runtime.exec/ProcessBuilder。
/// - CWE-78：方法体内同时出现 HTTP 输入源和 Runtime.exec/ProcessBuilder。
fn synthesize_local_call_path(
    project_path: &Path,
    finding: &Finding,
) -> Option<(CallPath, Vec<CallerEvidence>)> {
    let ext = Path::new(&finding.file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let full_path = project_path.join(&finding.file_path);
    let content = std::fs::read_to_string(&full_path).ok()?;
    let lines: Vec<&str> = content.lines().collect();
    if finding.line_start == 0 || finding.line_start > lines.len() {
        return None;
    }

    // 取问题行周围 ±35 行作为方法体近似（足够覆盖常见 Java 方法）
    let start = finding.line_start.saturating_sub(35).max(1);
    let end = (finding.line_end + 35).min(lines.len());
    let method_body = lines[start - 1..end].join("\n");
    let body_lower = method_body.to_lowercase();

    let java_sources = [
        "@requestparam",
        "@pathvariable",
        "@requestbody",
        "@requestheader",
        "@cookievalue",
        "@modelattribute",
        "httpservletrequest",
        "servletrequest",
        "getparameter(",
        "getparametervalues(",
        "getheader(",
        "getheaders(",
        "getquerystring(",
        "getinputstream(",
        "getreader(",
        "getcookies(",
    ];
    let has_source = java_sources.iter().any(|p| body_lower.contains(p));

    let is_deserialization = finding.vuln_type.contains("502")
        || finding
            .description
            .to_lowercase()
            .contains("deserialization");
    let is_command =
        finding.vuln_type.contains("78") || finding.description.to_lowercase().contains("command");
    let is_xss = finding.vuln_type.contains("79")
        || finding.description.to_lowercase().contains("xss")
        || finding.description.to_lowercase().contains("cross-site");
    let is_info_leak = finding.vuln_type.contains("200")
        || finding.description.to_lowercase().contains("sensitive")
        || finding.description.to_lowercase().contains("hardcoded");

    let has_deser_sink = body_lower.contains("objectinputstream")
        || body_lower.contains("readobject(")
        || body_lower.contains("defaultreadobject")
        || body_lower.contains("xstream")
        || body_lower.contains("fromxml(");
    let has_cmd_sink = body_lower.contains("runtime.getruntime().exec")
        || body_lower.contains("runtime.exec")
        || body_lower.contains("processbuilder");

    let matched = if is_deserialization {
        // 1) HTTP 输入 + 反序列化 sink
        (has_source && has_deser_sink)
        // 2) readObject 内部的危险 gadget（如 Runtime.exec）
            || (body_lower.contains("void readobject") && has_cmd_sink)
    } else if is_command {
        has_source && has_cmd_sink
    } else if is_xss && matches!(ext, "js" | "jsx" | "ts" | "tsx") {
        // 客户端 XSS：同一方法内存在 DOM 输入源 + HTML 输出 sink
        let js_sources = [
            ".val()",
            ".value",
            "location.",
            "window.location",
            "document.url",
            "document.referrer",
            "getelementbyid",
        ];
        let js_sinks = [
            "innerhtml",
            "outerhtml",
            "document.write",
            "insertadjacenthtml",
        ];
        js_sources.iter().any(|s| body_lower.contains(s))
            && js_sinks.iter().any(|s| body_lower.contains(s))
    } else if is_info_leak && ext == "java" {
        // 硬编码敏感信息：方法体内存在敏感命名变量赋值字符串字面量
        let secret_names = ["password", "token", "secret", "api_key", "credential"];
        secret_names.iter().any(|name| {
            body_lower.contains(name)
                && method_body.lines().any(|line| {
                    let l = line.to_lowercase();
                    l.contains(name) && l.contains('=') && l.contains('"')
                })
        })
    } else {
        false
    };

    if !matched {
        return None;
    }

    // 构造一条单跳本地路径
    let sink_line = finding.line_start;
    let source_line = start;
    let step = deepaudit_core::analysis::query::PathStep {
        function_name: finding.detector.clone(),
        file_path: finding.file_path.clone(),
        line: source_line,
        step_type: "synthetic_local_source".to_string(),
        code_snippet: Some(lines[source_line - 1].trim().to_string()),
    };
    let sink_step = deepaudit_core::analysis::query::PathStep {
        function_name: finding.detector.clone(),
        file_path: finding.file_path.clone(),
        line: sink_line,
        step_type: "synthetic_local_sink".to_string(),
        code_snippet: Some(lines[sink_line - 1].trim().to_string()),
    };
    let path = CallPath {
        steps: vec![step, sink_step],
        total_hops: 1,
        crosses_files: false,
        files_in_path: vec![finding.file_path.clone()],
    };
    let caller = CallerEvidence {
        caller_function: finding.detector.clone(),
        caller_file: finding.file_path.clone(),
        caller_line: source_line,
        callee_function: finding.detector.clone(),
        callee_file: finding.file_path.clone(),
        callee_line: sink_line,
        receiver: None,
        is_callback: false,
    };
    Some((path, vec![caller]))
}
