// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent Prompt 模板
//!
//! 为 LLM triage 和 specialist 提供结构化 prompt。

use serde_json::json;

use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;
use crate::agent::investigator::{InvestigationMemory, ToolDescription};

/// 构建 triage prompt
pub fn build_triage_prompt(finding: &Finding, evidence: &Evidence) -> String {
    let system = r#"你是一名代码安全审计助手。请基于下方提供的**确定性证据**对漏洞发现进行判定。

判定规则：
- true_positive：存在 source→sink 调用路径，且无有效 sanitizer/barrier 阻断。
- false_positive：存在有效 sanitizer、安全屏障、中间件防护，或污点路径已被阻断。
- needs_review：证据不足，无法确定。

注意：
- 只依据提供的证据做判定，不要猜测未显示的代码行为。
- 若证据中存在冲突（例如路径存在但同时有 sanitizer），请说明冲突并给出倾向性判定。
- 输出必须是 JSON，不要包含其他解释性文字。

输出格式：
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": 0.0-1.0,
  "reasoning": "简短中文理由",
  "suggested_specialist": null | "sqli" | "xss" | "auth_bypass" | "ssrf" | "deserialization"
}"#;

    let evidence_json = json!({
        "vulnerability_type": finding.vuln_type,
        "severity": finding.severity,
        "file": finding.file_path,
        "line": finding.line_start,
        "description": finding.description,
        "has_code_context": evidence.code_context.is_some(),
        "has_call_path": evidence.call_path.is_some(),
        "caller_count": evidence.callers.len(),
        "callee_count": evidence.callees.len(),
        "barriers": evidence.barriers,
        "has_effective_sanitizer": evidence.has_effective_sanitizer,
        "has_middleware_coverage": evidence.middleware_coverage.is_some(),
        "taint_steps_present": evidence.taint_steps.is_some(),
    });

    format!(
        "{}\n\n【Finding】\n{}\n\n【Evidence】\n{}\n\n请输出 JSON 判定结果：",
        system,
        serde_json::to_string_pretty(&finding_to_json(finding)).unwrap_or_default(),
        serde_json::to_string_pretty(&evidence_json).unwrap_or_default()
    )
}

fn finding_to_json(finding: &Finding) -> serde_json::Value {
    json!({
        "id": finding.finding_id,
        "vulnerability_type": finding.vuln_type,
        "severity": finding.severity,
        "file": finding.file_path,
        "line": finding.line_start,
        "description": finding.description,
        "detector": finding.detector,
        "file_role": finding.file_role,
        "barriers": finding.barriers,
        "reasoning_hint": finding.reasoning_hint,
    })
}

/// 构建 ReAct 调查 prompt
pub fn build_investigation_prompt(
    finding: &Finding,
    evidence: &Evidence,
    memory: &InvestigationMemory,
    available_tools: &[ToolDescription],
) -> String {
    let system = r#"你是一名代码安全审计调查员。请基于当前 finding 和已收集证据，决定下一步行动。

你的任务是：
1. 如果证据已足够做出 TP/FP 判定，直接结束调查。
2. 如果证据不足，从候选工具中选择最能补充证据的下一个工具，并给出具体参数。

判定标准：
- true_positive：存在从用户输入 source 到危险 sink 的可达路径，且无有效 sanitizer/barrier 阻断。
- false_positive：存在有效 sanitizer、安全屏障、中间件防护，或路径不可达。
- needs_review：证据仍不足，无法确定。

输出必须是 JSON，不要包含其他解释性文字。

输出格式（继续调查）：
{
  "thought": "当前已有什么证据，还缺什么",
  "next_tool": "find_call_path",
  "tool_input": { "source_file": "...", "source_function": "...", "sink_file": "...", "sink_function": "..." },
  "reasoning": "为什么选择这个工具以及期望得到什么"
}

输出格式（结束调查）：
{
  "thought": "证据已足够",
  "finish": true,
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": 0.0-1.0,
  "reasoning": "基于哪些证据做出的判定"
}"#;

    let tools_json: Vec<serde_json::Value> = available_tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters_schema,
            })
        })
        .collect();

    let memory_json = json!({
        "hypothesis": memory.hypothesis,
        "steps_so_far": memory.steps,
    });

    let evidence_json = json!({
        "vulnerability_type": finding.vuln_type,
        "severity": finding.severity,
        "file": finding.file_path,
        "line": finding.line_start,
        "has_code_context": evidence.code_context.is_some(),
        "has_call_path": evidence.call_path.is_some(),
        "caller_count": evidence.callers.len(),
        "callee_count": evidence.callees.len(),
        "barriers": evidence.barriers,
        "has_effective_sanitizer": evidence.has_effective_sanitizer,
        "has_middleware_coverage": evidence.middleware_coverage.is_some(),
        "taint_steps_present": evidence.taint_steps.is_some(),
    });

    format!(
        "{}\n\n【Finding】\n{}\n\n【Evidence】\n{}\n\n【候选工具】\n{}\n\n【已执行步骤】\n{}\n\n请输出 JSON 决策：",
        system,
        serde_json::to_string_pretty(&finding_to_json(finding)).unwrap_or_default(),
        serde_json::to_string_pretty(&evidence_json).unwrap_or_default(),
        serde_json::to_string_pretty(&tools_json).unwrap_or_default(),
        serde_json::to_string_pretty(&memory_json).unwrap_or_default(),
    )
}
