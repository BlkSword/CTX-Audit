// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Reviewer Agent 框架
//!
//! 对单个 `InvestigationResult` 进行独立复核，输出 `ReviewOpinion`。
//! 当前实现为确定性规则复核器，后续可接入 LLMReviewer。

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::agent::heuristics::Verdict;
use crate::agent::report::InvestigationResult;

/// 复核意见
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReviewOpinion {
    /// 复核器名称
    pub reviewer_name: String,
    /// 是否同意初审判定
    pub agrees_with_primary: bool,
    /// 复核后的判定
    pub verdict: Verdict,
    /// 置信度 0.0-1.0
    pub confidence: f64,
    /// 复核理由
    pub reasoning: String,
}

/// Reviewer trait
pub trait Reviewer: Send + Sync {
    /// 对调查结果进行复核
    fn review(&self, result: &InvestigationResult) -> Result<ReviewOpinion>;
}

/// 基于规则的复核器
pub struct RuleBasedReviewer;

impl Reviewer for RuleBasedReviewer {
    fn review(&self, result: &InvestigationResult) -> Result<ReviewOpinion> {
        let primary = result.verdict;
        let evidence = &result.evidence;

        // 1. 初审为 TP 且调用图/污点链充分 → 同意
        if primary == Verdict::TruePositive
            && (evidence.call_path.is_some() || evidence.taint_steps.is_some())
            && !evidence.has_effective_sanitizer
            && evidence.barriers.is_empty()
        {
            return Ok(ReviewOpinion {
                reviewer_name: "rule_based".to_string(),
                agrees_with_primary: true,
                verdict: Verdict::TruePositive,
                confidence: 0.9,
                reasoning:
                    "初审为真阳性，且存在调用图/污点链证据，无有效 sanitizer 或 barrier，同意。"
                        .to_string(),
            });
        }

        // 2. 初审为 FP 且存在有效 sanitizer/barrier → 同意
        if primary == Verdict::FalsePositive
            && (evidence.has_effective_sanitizer || !evidence.barriers.is_empty())
        {
            return Ok(ReviewOpinion {
                reviewer_name: "rule_based".to_string(),
                agrees_with_primary: true,
                verdict: Verdict::FalsePositive,
                confidence: 0.88,
                reasoning: "初审为误报，且存在有效 sanitizer 或 barrier，同意。".to_string(),
            });
        }

        // 3. Specialist 结果与初审冲突 → 不同意
        if let Some(ref sp) = result.specialist_result {
            let sp_verdict = sp
                .get("verdict")
                .and_then(|v| v.as_str())
                .and_then(parse_verdict);
            if let Some(sp_verdict) = sp_verdict {
                if sp_verdict != primary {
                    return Ok(ReviewOpinion {
                        reviewer_name: "rule_based".to_string(),
                        agrees_with_primary: false,
                        verdict: sp_verdict,
                        confidence: sp.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.7),
                        reasoning: format!(
                            "Specialist ({}) 判定与初审冲突，按 specialist 意见复核。",
                            sp.get("specialist_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                        ),
                    });
                }
            }
        }

        // 4. 工具查询：若 evidence_refs 提供 source→sink，确认调用路径存在 → 真阳性
        if let Some(ref tc) = result.tool_context {
            if let Some(ref refs) = result.evidence.evidence_refs {
                if let Some(ref ss) = refs.source_sink_path {
                    if tc
                        .try_find_attack_path(
                            &ss.source_file,
                            &ss.source_function,
                            &ss.sink_file,
                            &ss.sink_function,
                        )
                        .is_some()
                    {
                        return Ok(ReviewOpinion {
                            reviewer_name: "rule_based".to_string(),
                            agrees_with_primary: primary == Verdict::TruePositive,
                            verdict: Verdict::TruePositive,
                            confidence: 0.85,
                            reasoning: "Reviewer 通过调用图工具确认 source→sink 路径存在，判定为真阳性。".to_string(),
                        });
                    }
                }
            }
        }

        // 5. 其他情况证据不足
        Ok(ReviewOpinion {
            reviewer_name: "rule_based".to_string(),
            agrees_with_primary: false,
            verdict: Verdict::NeedsReview,
            confidence: 0.5,
            reasoning: "证据不足或初审理由不充分，需人工复核。".to_string(),
        })
    }
}

fn parse_verdict(s: &str) -> Option<Verdict> {
    match s {
        "true_positive" => Some(Verdict::TruePositive),
        "false_positive" => Some(Verdict::FalsePositive),
        "needs_review" => Some(Verdict::NeedsReview),
        _ => None,
    }
}

/// 融合复核意见：若不同意且置信度不低于初审，则覆盖 verdict
pub fn apply_review(
    primary_verdict: Verdict,
    primary_confidence: f64,
    review: &ReviewOpinion,
) -> (Verdict, String) {
    if review.agrees_with_primary || review.confidence < primary_confidence {
        (primary_verdict, "Reviewer 同意初审。".to_string())
    } else {
        (
            review.verdict,
            format!(
                "Reviewer ({}) 与初审冲突且置信度更高，覆盖为 {}。",
                review.reviewer_name,
                review.verdict.as_str()
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::evidence::Evidence;
    use deepaudit_core::scanning::Finding;

    fn result_with_evidence(evidence: Evidence, verdict: Verdict) -> InvestigationResult {
        InvestigationResult {
            investigation_id: "i1".to_string(),
            session_id: "s1".to_string(),
            finding_id: "f1".to_string(),
            file_path: "app.js".to_string(),
            line: 10,
            vulnerability_type: "CWE-79".to_string(),
            severity: "high".to_string(),
            hypothesis: "h".to_string(),
            evidence,
            verdict,
            reasoning: "primary reasoning".to_string(),
            specialist_result: None,
            reviews: Vec::new(),
            confidence: 0.8,
            tool_context: None,
            investigation_steps: Vec::new(),
            audited_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn test_reviewer_agrees_with_true_positive() {
        let mut evidence = Evidence::default();
        evidence.call_path = Some(deepaudit_core::CallPath {
            steps: vec![],
            total_hops: 1,
            crosses_files: false,
            files_in_path: vec![],
        });
        let result = result_with_evidence(evidence, Verdict::TruePositive);
        let op = RuleBasedReviewer.review(&result).unwrap();
        assert!(op.agrees_with_primary);
        assert_eq!(op.verdict, Verdict::TruePositive);
    }

    #[test]
    fn test_reviewer_agrees_with_false_positive() {
        let mut evidence = Evidence::default();
        evidence.has_effective_sanitizer = true;
        let result = result_with_evidence(evidence, Verdict::FalsePositive);
        let op = RuleBasedReviewer.review(&result).unwrap();
        assert!(op.agrees_with_primary);
        assert_eq!(op.verdict, Verdict::FalsePositive);
    }

    #[test]
    fn test_reviewer_disagrees_when_specialist_conflicts() {
        let mut evidence = Evidence::default();
        evidence.has_effective_sanitizer = true;
        let mut result = result_with_evidence(evidence, Verdict::TruePositive);
        result.specialist_result = Some(serde_json::json!({
            "specialist_name": "xss",
            "verdict": "false_positive",
            "confidence": 0.9,
            "reasoning": "safe output",
            "observations": {},
        }));
        let op = RuleBasedReviewer.review(&result).unwrap();
        assert!(!op.agrees_with_primary);
        assert_eq!(op.verdict, Verdict::FalsePositive);
    }

    #[test]
    fn test_apply_review_keeps_primary_when_agrees() {
        let review = ReviewOpinion {
            reviewer_name: "rule_based".to_string(),
            agrees_with_primary: true,
            verdict: Verdict::FalsePositive,
            confidence: 0.9,
            reasoning: "agree".to_string(),
        };
        let (v, note) = apply_review(Verdict::TruePositive, 0.8, &review);
        assert_eq!(v, Verdict::TruePositive);
        assert!(note.contains("同意"));
    }

    #[test]
    fn test_apply_review_overrides_when_confident_disagree() {
        let review = ReviewOpinion {
            reviewer_name: "rule_based".to_string(),
            agrees_with_primary: false,
            verdict: Verdict::FalsePositive,
            confidence: 0.9,
            reasoning: "disagree".to_string(),
        };
        let (v, note) = apply_review(Verdict::TruePositive, 0.7, &review);
        assert_eq!(v, Verdict::FalsePositive);
        assert!(note.contains("冲突"));
    }
}
