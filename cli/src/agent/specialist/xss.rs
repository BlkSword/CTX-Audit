// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! XSS Specialist
//!
//! 基于代码上下文识别 XSS sink（DOM/反射/存储）与常见编码/过滤措施，
//! 结合调用图证据给出判定。

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use serde_json::json;

use deepaudit_core::scanning::Finding;

use crate::agent::heuristics::Verdict;
use crate::agent::specialist::{
    default_xss_rules, Specialist, SpecialistContext, SpecialistResult, SpecialistRuleSet,
};

pub struct XssSpecialist {
    rules: SpecialistRuleSet,
    sinks: Vec<Regex>,
    safe_patterns: Vec<Regex>,
    language_sinks: HashMap<String, Vec<Regex>>,
    language_safe: HashMap<String, Vec<Regex>>,
    barrier_keywords: HashSet<String>,
}

impl XssSpecialist {
    /// 使用指定规则集构造
    pub fn new(rules: SpecialistRuleSet) -> Result<Self> {
        let sinks = rules.compiled_sinks()?;
        let safe_patterns = rules.compiled_safe()?;
        let mut language_sinks = HashMap::new();
        let mut language_safe = HashMap::new();
        for (lang, _) in &rules.per_language {
            let mut combined_sinks = sinks.clone();
            combined_sinks.extend(rules.compiled_language_sinks(lang)?);
            language_sinks.insert(lang.clone(), combined_sinks);

            let mut combined_safe = safe_patterns.clone();
            combined_safe.extend(rules.compiled_language_safe(lang)?);
            language_safe.insert(lang.clone(), combined_safe);
        }
        Ok(Self {
            sinks,
            safe_patterns,
            language_sinks,
            language_safe,
            barrier_keywords: rules.barrier_set(),
            rules,
        })
    }

    /// 使用内置默认规则
    pub fn default() -> Self {
        Self::new(default_xss_rules()).expect("默认 XSS 规则应能编译")
    }

    fn sinks_for(&self, lang: &str) -> &[Regex] {
        self.language_sinks
            .get(lang)
            .map(|v| v.as_slice())
            .unwrap_or(&self.sinks)
    }

    fn safe_for(&self, lang: &str) -> &[Regex] {
        self.language_safe
            .get(lang)
            .map(|v| v.as_slice())
            .unwrap_or(&self.safe_patterns)
    }
}

#[async_trait]
impl Specialist for XssSpecialist {
    fn name(&self) -> &'static str {
        "xss"
    }

    fn can_handle(&self, finding: &Finding) -> bool {
        self.rules.matches_vuln_type(&finding.vuln_type)
    }

    async fn investigate(&self, ctx: SpecialistContext) -> Result<SpecialistResult> {
        let code = ctx.code_context().unwrap_or("").to_lowercase();
        let lang = crate::agent::specialist::sqli::language_from_path(&ctx.finding.file_path);
        let mut observations = json!({
            "language": lang,
            "sink_patterns": detect_patterns(&code, self.sinks_for(&lang)),
            "safe_patterns": detect_patterns(&code, self.safe_for(&lang)),
            "barriers_from_evidence": ctx.evidence.barriers.clone(),
            "has_effective_sanitizer": ctx.evidence.has_effective_sanitizer,
            "call_path_present": ctx.evidence.call_path.is_some(),
            "tool_call_results": [],
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
            self.barrier_keywords
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

        // 尝试用工具查询 source→sink 路径
        if let Some(path) = ctx.query_attack_path() {
            if let Some(arr) = observations
                .get_mut("tool_call_results")
                .and_then(|v| v.as_array_mut())
            {
                arr.push(json!({"kind": "find_call_path", "total_hops": path.total_hops, "crosses_files": path.crosses_files}));
            }
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::TruePositive,
                confidence: 0.84,
                reasoning: "XSS sink 已识别，工具查询确认存在 source→sink 调用路径，判定为真阳性。"
                    .to_string(),
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
                enclosing_function: None,
                enclosing_function_line: None,
            },
            evidence: Evidence {
                code_context: Some(code.to_string()),
                ..Evidence::default()
            },
            query_engine: None,
            tool_context: None,
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
        let res = XssSpecialist::default().investigate(ctx).await.unwrap();
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

        let res = XssSpecialist::default().investigate(ctx).await.unwrap();
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
        let res = XssSpecialist::default().investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::FalsePositive);
    }
}
