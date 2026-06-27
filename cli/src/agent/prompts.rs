// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent Prompt 模板
//!
//! 为 LLM triage 和 specialist 提供结构化 prompt。

use serde_json::json;

use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;

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
