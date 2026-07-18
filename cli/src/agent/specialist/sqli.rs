// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! SQL 注入 Specialist
//!
//! 基于代码上下文识别 SQL sink 与参数化/转义等防护手段，结合调用图证据给出判定。

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use serde_json::json;

use deepaudit_core::scanning::Finding;

use crate::agent::heuristics::Verdict;
use crate::agent::specialist::{
    default_sqli_rules, Specialist, SpecialistContext, SpecialistResult, SpecialistRuleSet,
};

pub struct SQLiSpecialist {
    rules: SpecialistRuleSet,
    sinks: Vec<Regex>,
    safe_patterns: Vec<Regex>,
    language_sinks: HashMap<String, Vec<Regex>>,
    language_safe: HashMap<String, Vec<Regex>>,
    barrier_keywords: HashSet<String>,
}

impl SQLiSpecialist {
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
        Self::new(default_sqli_rules()).expect("默认 SQLi 规则应能编译")
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
impl Specialist for SQLiSpecialist {
    fn name(&self) -> &'static str {
        "sqli"
    }

    fn can_handle(&self, finding: &Finding) -> bool {
        self.rules.matches_vuln_type(&finding.vuln_type)
    }

    async fn investigate(&self, ctx: SpecialistContext) -> Result<SpecialistResult> {
        let code = ctx.code_context().unwrap_or("").to_lowercase();
        let lang = language_from_path(&ctx.finding.file_path);
        let mut observations = json!({
            "language": lang,
            "sink_patterns": detect_patterns(&code, self.sinks_for(&lang)),
            "safe_patterns": detect_patterns(&code, self.safe_for(&lang)),
            "barriers_from_evidence": ctx.evidence.barriers.clone(),
            "has_effective_sanitizer": ctx.evidence.has_effective_sanitizer,
            "call_path_present": ctx.evidence.call_path.is_some(),
            "tool_call_results": [],
        });

        // 若 evidence 中已有有效 sanitizer，直接判定为误报
        if ctx.evidence.has_effective_sanitizer {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::FalsePositive,
                confidence: 0.92,
                reasoning: "污点路径上存在有效 sanitizer，SQLi specialist 判定为误报。".to_string(),
                observations,
            });
        }

        // 若 finding 显式声明了安全屏障关键词
        let barrier_detected = ctx.evidence.barriers.iter().any(|b| {
            self.barrier_keywords
                .iter()
                .any(|kw| b.to_lowercase().contains(kw))
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
                    "发现 SQL 安全屏障关键词（如 parameterized/prepared/escape），判定为误报。"
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

        // 存在安全编码模式（参数化/占位符/转义）→ 误报
        if safe_patterns > 0 {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::FalsePositive,
                confidence: 0.85,
                reasoning: "代码上下文中检测到参数化查询、占位符或转义模式，判定为误报。"
                    .to_string(),
                observations,
            });
        }

        // 无 sink 模式时证据不足
        if sink_patterns == 0 {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::NeedsReview,
                confidence: 0.5,
                reasoning: "代码上下文中未识别到典型 SQL sink， specialist 无法进一步判定。"
                    .to_string(),
                observations,
            });
        }

        // sink 与参数化同时存在 → 误报（兜底，理论上已被 safe_patterns 捕获）
        if safe_patterns > 0 {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::FalsePositive,
                confidence: 0.85,
                reasoning: "SQL sink 附近检测到参数化查询或占位符，判定为误报。".to_string(),
                observations,
            });
        }

        // 存在 sink + 调用图路径 + 无防护 → 真阳性
        if ctx.evidence.call_path.is_some() || !ctx.evidence.callees.is_empty() {
            return Ok(SpecialistResult {
                specialist_name: self.name().to_string(),
                verdict: Verdict::TruePositive,
                confidence: 0.88,
                reasoning: "SQL sink 与 source→sink 调用路径同时存在，且未检测到参数化或转义防护，判定为真阳性。".to_string(),
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
                confidence: 0.85,
                reasoning: "SQL sink 已识别，工具查询确认存在 source→sink 调用路径，判定为真阳性。"
                    .to_string(),
                observations,
            });
        }

        // 仅有 sink 但无路径证据
        Ok(SpecialistResult {
            specialist_name: self.name().to_string(),
            verdict: Verdict::NeedsReview,
            confidence: 0.6,
            reasoning: "识别到 SQL sink，但缺少完整 source→sink 调用路径，需进一步复核。"
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

pub fn language_from_path(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.ends_with(".java") {
        "java".to_string()
    } else if lower.ends_with(".py") {
        "python".to_string()
    } else if lower.ends_with(".go") {
        "go".to_string()
    } else if lower.ends_with(".rb") {
        "ruby".to_string()
    } else if lower.ends_with(".php") {
        "php".to_string()
    } else if lower.ends_with(".rs") {
        "rust".to_string()
    } else if lower.ends_with(".js")
        || lower.ends_with(".ts")
        || lower.ends_with(".jsx")
        || lower.ends_with(".tsx")
    {
        "javascript".to_string()
    } else {
        "generic".to_string()
    }
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
                vuln_type: "CWE-89".to_string(),
                severity: "high".to_string(),
                description: "sql injection".to_string(),
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
    async fn test_sqli_detects_parameterized_safe() {
        let ctx = ctx_with_code(
            r#"
            const userId = req.query.id;
            db.query('SELECT * FROM users WHERE id = ?', [userId]);
        "#,
        );
        let res = SQLiSpecialist::default().investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::FalsePositive);
        assert!(res.confidence > 0.8);
    }

    #[tokio::test]
    async fn test_sqli_detects_raw_concat() {
        let ctx = ctx_with_code(
            r#"
            const userId = req.query.id;
            db.query('SELECT * FROM users WHERE id = ' + userId);
        "#,
        );
        let mut ctx = ctx;
        ctx.evidence.call_path = Some(deepaudit_core::CallPath {
            steps: vec![],
            total_hops: 1,
            crosses_files: false,
            files_in_path: vec![],
        });

        let res = SQLiSpecialist::default().investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::TruePositive);
    }

    #[tokio::test]
    async fn test_sqli_evidence_sanitizer_overrides() {
        let ctx = ctx_with_code(
            r#"
            const userId = req.query.id;
            db.query('SELECT * FROM users WHERE id = ' + userId);
        "#,
        );
        let mut ctx = ctx;
        ctx.evidence.has_effective_sanitizer = true;

        let res = SQLiSpecialist::default().investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::FalsePositive);
    }

    #[tokio::test]
    async fn test_sqli_detects_java_statement_sink() {
        let mut ctx = ctx_with_code(
            r#"
            String id = request.getParameter("id");
            Statement stmt = connection.createStatement();
            stmt.execute("SELECT * FROM users WHERE id = " + id);
        "#,
        );
        ctx.finding.file_path = "UserController.java".to_string();
        ctx.evidence.call_path = Some(deepaudit_core::CallPath {
            steps: vec![],
            total_hops: 1,
            crosses_files: false,
            files_in_path: vec![],
        });

        let res = SQLiSpecialist::default().investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::TruePositive);
        let observations = res.observations;
        assert_eq!(observations["language"].as_str(), Some("java"));
    }

    #[tokio::test]
    async fn test_sqli_java_parameterized_is_safe() {
        let mut ctx = ctx_with_code(
            r#"
            String id = request.getParameter("id");
            PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
            ps.setString(1, id);
            ps.execute();
        "#,
        );
        ctx.finding.file_path = "UserController.java".to_string();

        let res = SQLiSpecialist::default().investigate(ctx).await.unwrap();
        assert_eq!(res.verdict, Verdict::FalsePositive);
    }
}
