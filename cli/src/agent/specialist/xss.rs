// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! XSS Specialist
//!
//! 基于代码上下文识别 XSS sink（DOM/反射/存储）与常见编码/过滤措施，
//! 结合调用图证据给出判定。

use std::collections::HashSet;

use anyhow::Result;
use async_trait::async_trait;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;

use deepaudit_core::scanning::Finding;

use crate::agent::heuristics::Verdict;
use crate::agent::specialist::{Specialist, SpecialistContext, SpecialistResult};

/// XSS sink 模式
static XSS_SINKS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|\.html\s*\()"#).unwrap(),
        Regex::new(r#"(?i)(document\.write\s*\(|document\.writeln\s*\()"#).unwrap(),
        Regex::new(r#"(?i)(eval\s*\(|setTimeout\s*\(|setInterval\s*\()"#).unwrap(),
        Regex::new(r#"(?i)(dangerouslySetInnerHTML|v-html|\{@html)"#).unwrap(),
        Regex::new(r#"(?i)(res\.send\s*\(|res\.write\s*\(|response\.write\s*\()"#).unwrap(),
    ]
});

/// XSS 防护/编码模式
static XSS_SAFE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r#"(?i)(textContent|innerText|createTextNode|\.text\s*\()"#).unwrap(),
        Regex::new(r#"(?i)(DOMPurify|sanitize|encodeURIComponent|escapeHtml|htmlEscape)"#).unwrap(),
        Regex::new(r#"(?i)(setAttribute\s*\(\s*['\"](href|src)['\"]\s*,)"#).unwrap(),
    ]
});

/// XSS barrier 关键词
static XSS_BARRIER_KEYWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "DOMPurify",
        "sanitize",
        "encodeURIComponent",
        "escapeHtml",
        "textContent",
        "innerText",
        "createTextNode",
    ]
    .iter()
    .copied()
    .collect()
});

pub struct XssSpecialist;

#[async_trait]
impl Specialist for XssSpecialist {
    fn name(&self) -> &'static str {
        "xss"
    }

    fn can_handle(&self, finding: &Finding) -> bool {
        let vt = finding.vuln_type.to_lowercase();
        vt.contains("cwe-79")
            || vt.contains("xss")
            || vt.contains("cross_site_scripting")
            || vt.contains("cross site scripting")
            || vt.contains("reflected_xss")
            || vt.contains("stored_xss")
            || vt.contains("dom_xss")
    }

    async fn investigate(&self, ctx: SpecialistContext) -> Result<SpecialistResult> {
        let code = ctx.code_context().unwrap_or("").to_lowercase();
        let mut observations = json!({
            "sink_patterns": detect_patterns(&code, &XSS_SINKS),
            "safe_patterns": detect_patterns(&code, &XSS_SAFE_PATTERNS),
            "barriers_from_evidence": ctx.evidence.barriers.clone(),
            "has_effective_sanitizer": ctx.evidence.has_effective_sanitizer,
            "call_path_present": ctx.evidence.call_path.is_some(),
        });

        if ctx.evidence.has_effective_sanitizer {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::FalsePositive,
                confidence: 0.92,
                reasoning: "污点路径上存在有效 sanitizer，XSS specialist 判定为误报。".to_string(),
                observations,
            });
        }

        let barrier_detected = ctx.evidence.barriers.iter().any(|b| {
            XSS_BARRIER_KEYWORDS
                .iter()
                .any(|kw| b.to_lowercase().contains(&kw.to_lowercase()))
        });

        if barrier_detected {
            if let Some(arr) = observations
                .get_mut("safe_patterns")
                .and_then(|v| v.as_array_mut())
            {
                arr.push(json!("barrier_keyword"));
            }
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::FalsePositive,
                confidence: 0.88,
                reasoning:
                    "发现 XSS 安全屏障关键词（如 DOMPurify/sanitize/编码函数），判定为误报。"
                        .to_string(),
                observations,
            });
        }

        let safe_patterns = observations["safe_patterns"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        let sink_patterns = observations["sink_patterns"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);

        // 存在安全输出/编码模式 → 误报
        if safe_patterns > 0 {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::FalsePositive,
                confidence: 0.84,
                reasoning: "代码上下文中检测到安全输出或编码模式，判定为误报。".to_string(),
                observations,
            });
        }

        if sink_patterns == 0 {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::NeedsReview,
                confidence: 0.5,
                reasoning: "代码上下文中未识别到典型 XSS sink，specialist 无法进一步判定。"
                    .to_string(),
                observations,
            });
        }

        // 存在 sink 但同时使用安全输出方式 → 误报（兜底）
        if safe_patterns > 0 {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::FalsePositive,
                confidence: 0.84,
                reasoning: "XSS sink 附近检测到安全输出/编码模式，判定为误报。".to_string(),
                observations,
            });
        }

        // 存在 sink + 调用图路径 + 无防护 → 真阳性
        if ctx.evidence.call_path.is_some() || !ctx.evidence.callees.is_empty() {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::TruePositive,
                confidence: 0.87,
                reasoning: "XSS sink 与 source→sink 调用路径同时存在，且未检测到安全输出/编码，判定为真阳性。".to_string(),
                observations,
            });
        }

        Ok(SpecialistResult {
            specialist_name: self.name().to_string(),
            verdict: Verdict::NeedsReview,
            confidence: 0.6,
            reasoning: "识别到 XSS sink，但缺少完整 source→sink 调用路径，需进一步复核。"
                .to_string(),
            observations,
        })
    }
}

fn detect_patterns(code: &str, patterns: &[Regex]) -> Vec<String> {
    let mut matched = Vec::new();
    for (idx, re) in patterns.iter().enumerate() {
        if re.is_match(code) {
            matched.push(format!("pattern_{}", idx));
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::evidence::Evidence;

    fn ctx_with_code(code: &str) -> SpecialistContext {
        SpecialistContext {
            project_path: std::path::PathBuf::from("."),
            finding: Finding {
                finding_id: "f1".to_string(),
                file_path: "app.js".to_string(),
                line_start: 10,
                line_end: 10,
                detector: "test".to_string(),
                vuln_type: "CWE-79".to_string(),
                severity: "high".to_string(),
                description: "xss".to_string(),
                analysis_trail: None,
                llm_output: None,
                confidence: None,
                corroboration_count: None,
                code_snippet: None,
                source_snippet: None,
                sink_snippet: None,
                file_role: Some("production".to_string()),
                barriers: None,
                reasoning_hint: None,
                evidence_refs: None,
            },
            evidence: Evidence {
                code_context: Some(code.to_string()),
                ..Evidence::default()
            },
            query_engine: None,
        }
    }

    #[tokio::test]
    async fn test_xss_detects_safe_text_content() {
        let ctx = ctx_with_code(
            r#"
            const userInput = req.query.name;
            document.getElementById('out').textContent = userInput;
        "#,
        );
        let res = XssSpecialist.investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::FalsePositive);
    }

    #[tokio::test]
    async fn test_xss_detects_innerhtml_with_path() {
        let ctx = ctx_with_code(
            r#"
            const userInput = req.query.name;
            document.getElementById('out').innerHTML = userInput;
        "#,
        );
        let mut ctx = ctx;
        ctx.evidence.call_path = Some(deepaudit_core::CallPath {
            steps: vec![],
            total_hops: 1,
            crosses_files: false,
            files_in_path: vec![],
        });

        let res = XssSpecialist.investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::TruePositive);
    }

    #[tokio::test]
    async fn test_xss_barrier_keyword_overrides() {
        let ctx = ctx_with_code(
            r#"
            const userInput = req.query.name;
            element.innerHTML = DOMPurify.sanitize(userInput);
        "#,
        );
        let res = XssSpecialist.investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::FalsePositive);
    }
}
