// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 证据收集模块
//!
//! 直接调用 `CallGraphQueryEngine` 与文件读取，为每个 finding 生成结构化证据。

use std::path::Path;

use serde::Serialize;

use deepaudit_core::scanning::Finding;
use deepaudit_core::{
    CallGraphQueryEngine, CallPath, CalleeEvidence, CallerEvidence, MiddlewareEvidence,
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

    Ok(evidence)
}

/// 从 finding 的 evidence_refs 中提取 source/sink 函数标识
fn extract_source_sink(finding: &Finding) -> Option<(String, String, String, String)> {
    // 优先使用 evidence_refs 中的结构化信息
    if let Some(ref refs) = finding.evidence_refs {
        if let Some(ref ss) = refs.source_sink_path {
            if !ss.source_function.is_empty() && !ss.sink_function.is_empty() {
                return Some((
                    ss.source_file.clone(),
                    ss.source_function.clone(),
                    ss.sink_file.clone(),
                    ss.sink_function.clone(),
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
