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

/// 构建污点步进式调查 prompt
///
/// 让 LLM 像审计员一样，从 sink 出发沿着变量/调用链反向追踪到 source，
/// 每步决定读取哪段代码、查询哪个调用关系、检查哪个 sanitizer。
pub fn build_taint_walk_prompt(
    finding: &Finding,
    evidence: &Evidence,
    focus: &TaintFocus,
    chain: &[TaintChainStep],
    available_actions: &[serde_json::Value],
) -> String {
    let system = r#"你是一名代码安全审计员，正在进行“污点步进调查”。

任务：从当前发现的 sink（危险操作）出发，沿着数据流反向追踪到用户输入 source，确认是否存在可利用的漏洞路径。

工作方式：
1. 每次只关注一个“当前焦点”：一个文件、一行代码、一个变量或函数。
2. 根据当前代码上下文，决定下一步行动：读取更多代码、查询调用者/被调用者、解析方法调用、检查 sanitizer，或直接结束。
3. 必须引用你实际看到的代码行和变量名，不要猜测未显示的代码。
4. 如果找到 source→sink 的完整路径且无有效 sanitizer，判 true_positive；如果路径被阻断或 source 不可控，判 false_positive；如果关键代码缺失无法判断，判 needs_review。

判定标准：
- true_positive：source 处的用户输入能沿数据流到达 sink，中间没有有效 sanitizer/barrier 阻断。
- false_positive：存在有效 sanitizer、类型转换、权限检查、中间件防护，或 source 不可控/路径不存在。
- needs_review：关键代码不可见，无法完成追踪。

输出必须是 JSON，不要包含任何解释性文字。

输出格式（继续调查）：
{
  "thought": "当前已确认...，还缺...",
  "action": "read_context" | "query_callers" | "query_callees" | "resolve_call" | "check_sanitizer" | "finish",
  "params": { 根据 action 填写参数 },
  "reasoning": "为什么选择这一步"
}

输出格式（结束调查）：
{
  "thought": "已完成追踪",
  "action": "finish",
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": 0.0-1.0,
  "reasoning": "基于哪些代码/调用关系做出的判定",
  "chain_summary": "source ... -> ... -> sink 的简要路径"
}

可执行动作说明：
- read_context：读取当前焦点附近代码。params: { "file_path": "...", "line": N, "radius": 30 }
- query_callers：反向查谁调用了某个函数。params: { "file_path": "...", "function_name": "...", "recursive": false }
- query_callees：正向查某个函数调用了谁。params: { "file_path": "...", "function_name": "...", "recursive": false }
- resolve_call：解析 obj.method() 的实际实现。params: { "file_path": "...", "line": N, "receiver": "obj", "method": "method" }
- check_sanitizer：检查某函数/变量是否被认定为 sanitizer。params: { "symbol": "...", "vuln_type": "..." }
- finish：结束调查并给出判定。"#;

    let evidence_json = json!({
        "vulnerability_type": finding.vuln_type,
        "severity": finding.severity,
        "file": finding.file_path,
        "line": finding.line_start,
        "description": finding.description,
        "code_context": evidence.code_context,
        "barriers": evidence.barriers,
        "has_effective_sanitizer": evidence.has_effective_sanitizer,
    });

    format!(
        "{}\n\n【Finding】\n{}\n\n【Evidence】\n{}\n\n【当前焦点】\n{}\n\n【已走链】\n{}\n\n【候选动作】\n{}\n\n请输出 JSON 决策：",
        system,
        serde_json::to_string_pretty(&finding_to_json(finding)).unwrap_or_default(),
        serde_json::to_string_pretty(&evidence_json).unwrap_or_default(),
        serde_json::to_string_pretty(&json!(focus)).unwrap_or_default(),
        serde_json::to_string_pretty(&json!(chain)).unwrap_or_default(),
        serde_json::to_string_pretty(&json!(available_actions)).unwrap_or_default(),
    )
}

/// 污点步进焦点
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaintFocus {
    pub file_path: String,
    pub line: usize,
    pub symbol: String,
    pub role: String, // "sink" | "source_candidate" | "propagation" | "sanitizer"
}

/// 污点链单步
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaintChainStep {
    pub step_number: usize,
    pub file_path: String,
    pub line: usize,
    pub symbol: String,
    pub step_type: String, // "sink" | "source" | "propagation" | "sanitizer" | "barrier"
    pub code_snippet: String,
    pub reasoning: String,
    pub confidence: f64,
}
