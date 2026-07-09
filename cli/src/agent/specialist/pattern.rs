// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 通用模式匹配 Specialist
//!
//! 基于 sink/safe/barrier 正则规则对特定 CWE 做深度判定。
//! 规则通过 `SpecialistRuleSet` 配置，可从 `rules/specialists/*.yaml` 热加载。

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use async_trait::async_trait;
use regex::Regex;
use serde_json::json;

use deepaudit_core::scanning::Finding;

use crate::agent::heuristics::Verdict;
use crate::agent::specialist::{
    Specialist, SpecialistContext, SpecialistResult, SpecialistRuleSet,
};

/// 基于正则规则的通用 Specialist
pub struct PatternBasedSpecialist {
    name: String,
    display_name: String,
    rules: SpecialistRuleSet,
    sinks: Vec<Regex>,
    safe_patterns: Vec<Regex>,
    language_sinks: HashMap<String, Vec<Regex>>,
    language_safe: HashMap<String, Vec<Regex>>,
    barrier_keywords: HashSet<String>,
}

impl PatternBasedSpecialist {
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
        let name = rules.name.clone();
        let display_name = rules.name.clone();
        let barrier_keywords = rules.barrier_set();
        Ok(Self {
            name,
            display_name,
            rules,
            sinks,
            safe_patterns,
            language_sinks,
            language_safe,
            barrier_keywords,
        })
    }

    /// 使用内置默认规则（通过 include_str 编译时嵌入）
    pub fn default() -> Self {
        Self::new(crate::agent::specialist::rules::SpecialistRuleSet::empty("generic"))
            .expect("空规则集应能编译")
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
impl Specialist for PatternBasedSpecialist {
    fn name(&self) -> &'static str {
        // Specialist trait 要求 &'static str，但规则名是运行期字符串。
        // 这里返回规则名对应的静态字面量；新增规则时需要在此补充分支。
        match self.name.as_str() {
            "command_injection" => "command_injection",
            "deserialization" => "deserialization",
            "path_traversal" => "path_traversal",
            "ssrf" => "ssrf",
            _ => "pattern_based",
        }
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
                specialist_name: self.display_name.clone(),
                verdict: Verdict::FalsePositive,
                confidence: 0.92,
                reasoning: format!(
                    "污点路径上存在有效 sanitizer，{} specialist 判定为误报。",
                    self.display_name
                ),
                observations,
            });
        }

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
                specialist_name: self.display_name.clone(),
                verdict: Verdict::FalsePositive,
                confidence: 0.88,
                reasoning: format!(
                    "发现 {} 安全屏障关键词，判定为误报。",
                    self.display_name
                ),
                observations,
            });
        }

        let safe_count = observations["safe_patterns"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        let sink_count = observations["sink_patterns"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);

        if safe_count > 0 {
            return Ok(SpecialistResult {
                specialist_name: self.display_name.clone(),
                verdict: Verdict::FalsePositive,
                confidence: 0.85,
                reasoning: format!(
                    "代码上下文中检测到 {} 安全编码模式，判定为误报。",
                    self.display_name
                ),
                observations,
            });
        }

        if sink_count == 0 {
            return Ok(SpecialistResult {
                specialist_name: self.display_name.clone(),
                verdict: Verdict::NeedsReview,
                confidence: 0.5,
                reasoning: format!(
                    "代码上下文中未识别到典型 {} sink，specialist 无法进一步判定。",
                    self.display_name
                ),
                observations,
            });
        }

        if ctx.evidence.call_path.is_some() || !ctx.evidence.callees.is_empty() {
            return Ok(SpecialistResult {
                specialist_name: self.display_name.clone(),
                verdict: Verdict::TruePositive,
                confidence: 0.88,
                reasoning: format!(
                    "{} sink 与 source→sink 调用路径同时存在，且未检测到防护，判定为真阳性。",
                    self.display_name
                ),
                observations,
            });
        }

        if let Some(path) = ctx.query_attack_path() {
            if let Some(arr) = observations
                .get_mut("tool_call_results")
                .and_then(|v| v.as_array_mut())
            {
                arr.push(json!({"kind": "find_call_path", "total_hops": path.total_hops, "crosses_files": path.crosses_files}));
            }
            return Ok(SpecialistResult {
                specialist_name: self.display_name.clone(),
                verdict: Verdict::TruePositive,
                confidence: 0.85,
                reasoning: format!(
                    "{} sink 已识别，工具查询确认存在 source→sink 调用路径，判定为真阳性。",
                    self.display_name
                ),
                observations,
            });
        }

        Ok(SpecialistResult {
            specialist_name: self.display_name.clone(),
            verdict: Verdict::NeedsReview,
            confidence: 0.6,
            reasoning: format!(
                "识别到 {} sink，但缺少完整 source→sink 调用路径，需进一步复核。",
                self.display_name
            ),
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
