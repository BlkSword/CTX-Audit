// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 交叉验证器

use crate::multi_agent::aggregator::AggregatedResults;
use crate::multi_agent::aggregator::AggregatedFinding;
use ctx_audit_tools::FindingData;
use serde::{Deserialize, Serialize};

/// 交叉验证器
pub struct CrossValidator {
    /// 验证策略
    strategy: ValidationStrategy,
}

/// 验证策略
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationStrategy {
    /// 单专家确认即可
    SingleExpert,

    /// 多专家共识（至少 N 个专家确认）
    MultiExpertConsensus { min_experts: usize },

    /// 多样化专业知识（至少 N 种不同类型专家确认）
    DiverseExpertise { min_specialties: usize },

    /// 高置信度优先（置信度 > 阈值即通过）
    HighConfidenceFirst { threshold: f32 },
}

/// 验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedResults {
    /// 确认的发现
    pub confirmed: Vec<ValidatedFinding>,

    /// 需要人工审核的发现
    pub needs_review: Vec<ValidatedFinding>,

    /// 统计信息
    pub statistics: ValidationStatistics,
}

/// 验证后的发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedFinding {
    /// 发现数据
    pub finding: FindingData,

    /// 验证状态
    pub validation_status: ValidationStatus,

    /// 验证分数（0-100）
    pub validation_score: u32,

    /// 确认者数量
    pub confirmations: usize,

    /// 确认者的专业类型数量
    pub specialty_diversity: usize,

    /// 合并后的置信度
    pub final_confidence: f32,

    /// 验证原因
    pub validation_reason: String,
}

/// 验证状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    /// 已确认
    Confirmed,

    /// 需要审核
    NeedsReview,

    /// 可能误报
    LikelyFalsePositive,

    /// 已拒绝
    Rejected,
}

/// 验证统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationStatistics {
    /// 总验证发现数
    pub total_validated: usize,

    /// 确认数
    pub confirmed_count: usize,

    /// 需要审核数
    pub needs_review_count: usize,

    /// 可能误报数
    pub likely_false_positive_count: usize,

    /// 拒绝数
    pub rejected_count: usize,

    /// 多专家确认数
    pub multi_expert_confirmed: usize,

    /// 平均验证分数
    pub avg_validation_score: f32,

    /// 平均置信度
    pub avg_confidence: f32,
}

impl Default for CrossValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ValidationStrategy {
    fn default() -> Self {
        ValidationStrategy::MultiExpertConsensus { min_experts: 2 }
    }
}

impl CrossValidator {
    /// 创建新的验证器
    pub fn new() -> Self {
        Self {
            strategy: ValidationStrategy::default(),
        }
    }

    /// 设置验证策略
    pub fn with_strategy(mut self, strategy: ValidationStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// 执行交叉验证
    pub fn cross_validate(&self, aggregated: AggregatedResults) -> ValidatedResults {
        let mut validated_findings = Vec::new();
        let mut needs_review = Vec::new();

        for finding in aggregated.findings {
            let validated = self.validate_finding(&finding);

            match validated.validation_status {
                ValidationStatus::Confirmed => validated_findings.push(validated),
                _ => needs_review.push(validated),
            }
        }

        // 按验证分数和置信度排序
        validated_findings.sort_by(|a, b| {
            b.validation_score
                .cmp(&a.validation_score)
                .then(b.final_confidence.partial_cmp(&a.final_confidence).unwrap())
        });

        needs_review.sort_by(|a, b| {
            b.validation_score
                .cmp(&a.validation_score)
                .then(b.final_confidence.partial_cmp(&a.final_confidence).unwrap())
        });

        let statistics = self.calculate_statistics(&validated_findings, &needs_review);

        ValidatedResults {
            confirmed: validated_findings,
            needs_review,
            statistics,
        }
    }

    /// 验证单个发现
    fn validate_finding(&self, finding: &AggregatedFinding) -> ValidatedFinding {
        let confirmations = finding.confirmed_by.len();
        let specialty_diversity = finding.confirmed_by_specialties.len();
        let confidence = finding.merged_confidence;

        let (validation_status, validation_score, reason) = match &self.strategy {
            ValidationStrategy::SingleExpert => {
                // 单专家策略：只要有确认即可
                if confirmations >= 1 && confidence >= 0.5 {
                    (
                        ValidationStatus::Confirmed,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "单专家确认".to_string(),
                    )
                } else {
                    (
                        ValidationStatus::NeedsReview,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "置信度较低，需要审核".to_string(),
                    )
                }
            }

            ValidationStrategy::MultiExpertConsensus { min_experts } => {
                // 多专家共识策略
                if confirmations >= *min_experts {
                    (
                        ValidationStatus::Confirmed,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        format!("{} 位专家确认", confirmations),
                    )
                } else if confidence >= 0.85 {
                    (
                        ValidationStatus::Confirmed,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "高置信度单专家确认".to_string(),
                    )
                } else if confidence >= 0.6 {
                    (
                        ValidationStatus::NeedsReview,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        format!("专家数量不足（{}/{}），需要审核", confirmations, min_experts),
                    )
                } else {
                    (
                        ValidationStatus::LikelyFalsePositive,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "低置信度，可能是误报".to_string(),
                    )
                }
            }

            ValidationStrategy::DiverseExpertise { min_specialties } => {
                // 多样化专业知识策略
                if specialty_diversity >= *min_specialties {
                    (
                        ValidationStatus::Confirmed,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        format!("{} 种不同类型专家确认", specialty_diversity),
                    )
                } else if confirmations >= 2 && confidence >= 0.75 {
                    (
                        ValidationStatus::Confirmed,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "多位同类专家确认，置信度较高".to_string(),
                    )
                } else if confidence >= 0.6 {
                    (
                        ValidationStatus::NeedsReview,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        format!("专业多样性不足（{}/{}），需要审核", specialty_diversity, min_specialties),
                    )
                } else {
                    (
                        ValidationStatus::LikelyFalsePositive,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "专业多样性和置信度均不足".to_string(),
                    )
                }
            }

            ValidationStrategy::HighConfidenceFirst { threshold } => {
                // 高置信度优先策略
                if confidence >= *threshold {
                    (
                        ValidationStatus::Confirmed,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        format!("高置信度确认（{:.2}）", confidence),
                    )
                } else if confirmations >= 2 {
                    (
                        ValidationStatus::Confirmed,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "多专家确认".to_string(),
                    )
                } else if confidence >= 0.5 {
                    (
                        ValidationStatus::NeedsReview,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "置信度中等，需要审核".to_string(),
                    )
                } else {
                    (
                        ValidationStatus::LikelyFalsePositive,
                        self.calculate_score(confirmations, specialty_diversity, confidence),
                        "低置信度，可能是误报".to_string(),
                    )
                }
            }
        };

        ValidatedFinding {
            finding: finding.finding.clone(),
            validation_status,
            validation_score,
            confirmations,
            specialty_diversity,
            final_confidence: confidence,
            validation_reason: reason,
        }
    }

    /// 计算验证分数（0-100）
    fn calculate_score(
        &self,
        confirmations: usize,
        specialty_diversity: usize,
        confidence: f32,
    ) -> u32 {
        // 置信度分数（0-60）
        let confidence_score = (confidence * 60.0) as u32;

        // 确认者分数（0-25，每个确认者 5 分，最多 25 分）
        let confirmation_score = (confirmations as u32 * 5).min(25);

        // 专业多样性分数（0-15，每种专业 3 分，最多 15 分）
        let diversity_score = (specialty_diversity as u32 * 3).min(15);

        confidence_score + confirmation_score + diversity_score
    }

    /// 计算统计信息
    fn calculate_statistics(
        &self,
        confirmed: &[ValidatedFinding],
        needs_review: &[ValidatedFinding],
    ) -> ValidationStatistics {
        let total_validated = confirmed.len() + needs_review.len();

        let confirmed_count = confirmed.len();
        let needs_review_count = needs_review.len();
        let likely_false_positive_count = needs_review
            .iter()
            .filter(|f| f.validation_status == ValidationStatus::LikelyFalsePositive)
            .count();
        let rejected_count = needs_review
            .iter()
            .filter(|f| f.validation_status == ValidationStatus::Rejected)
            .count();

        let multi_expert_confirmed = confirmed
            .iter()
            .filter(|f| f.confirmations > 1)
            .count();

        let avg_validation_score = if total_validated > 0 {
            let all_scores: Vec<u32> = confirmed
                .iter()
                .chain(needs_review.iter())
                .map(|f| f.validation_score)
                .collect();
            all_scores.iter().sum::<u32>() / total_validated as u32
        } else {
            0
        };

        let avg_confidence = if total_validated > 0 {
            let all_confidences: Vec<f32> = confirmed
                .iter()
                .chain(needs_review.iter())
                .map(|f| f.final_confidence)
                .collect();
            all_confidences.iter().sum::<f32>() / total_validated as f32
        } else {
            0.0
        };

        ValidationStatistics {
            total_validated,
            confirmed_count,
            needs_review_count,
            likely_false_positive_count,
            rejected_count,
            multi_expert_confirmed,
            avg_validation_score: avg_validation_score as f32,
            avg_confidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_agent::task::AgentSpecialty;
    use std::collections::HashMap;

    fn create_test_aggregated_finding(
        confidence: f32,
        confirmations: usize,
        specialties: usize,
    ) -> AggregatedFinding {
        let mut extra = HashMap::new();
        extra.insert("confidence".to_string(), serde_json::json!(confidence));

        AggregatedFinding {
            finding: FindingData {
                id: Some("test-id".to_string()),
                title: Some("Test Finding".to_string()),
                description: "Test description".to_string(),
                severity: "high".to_string(),
                category: "other".to_string(),
                file_path: "/test/file.rs".to_string(),
                start_line: 10,
                code_snippet: Some("code".to_string()),
                extra,
                ..Default::default()
            },
            confirmed_by: (0..confirmations)
                .map(|i| format!("worker-{}", i))
                .collect(),
            confirmed_by_specialties: vec![AgentSpecialty::SqlInjectionExpert; specialties],
            merged_confidence: confidence,
            is_multi_expert_confirmed: confirmations > 1,
        }
    }

    #[test]
    fn test_single_expert_strategy() {
        let validator = CrossValidator::new()
            .with_strategy(ValidationStrategy::SingleExpert);

        let finding = create_test_aggregated_finding(0.7, 1, 1);
        let aggregated = AggregatedResults {
            findings: vec![finding],
            statistics: crate::multi_agent::aggregator::AggregationStatistics {
                total_worker_results: 1,
                raw_findings_count: 1,
                unique_findings_count: 1,
                multi_expert_confirmed_count: 0,
                unique_specialty_count: 1,
            },
            expert_coverage: crate::multi_agent::aggregator::ExpertCoverage {
                participating_specialties: vec![AgentSpecialty::SqlInjectionExpert],
                findings_by_specialty: std::collections::HashMap::new(),
                avg_confidence_by_specialty: std::collections::HashMap::new(),
            },
        };

        let result = validator.cross_validate(aggregated);

        assert_eq!(result.confirmed.len(), 1);
        assert_eq!(result.confirmed[0].validation_status, ValidationStatus::Confirmed);
    }

    #[test]
    fn test_multi_expert_consensus() {
        let validator = CrossValidator::new()
            .with_strategy(ValidationStrategy::MultiExpertConsensus { min_experts: 2 });

        // 单专家，高置信度
        let finding1 = create_test_aggregated_finding(0.9, 1, 1);
        // 双专家，中等置信度
        let finding2 = create_test_aggregated_finding(0.7, 2, 1);
        // 单专家，低置信度
        let finding3 = create_test_aggregated_finding(0.5, 1, 1);

        let aggregated = AggregatedResults {
            findings: vec![finding1, finding2, finding3],
            statistics: crate::multi_agent::aggregator::AggregationStatistics {
                total_worker_results: 3,
                raw_findings_count: 3,
                unique_findings_count: 3,
                multi_expert_confirmed_count: 1,
                unique_specialty_count: 1,
            },
            expert_coverage: crate::multi_agent::aggregator::ExpertCoverage {
                participating_specialties: vec![AgentSpecialty::SqlInjectionExpert],
                findings_by_specialty: std::collections::HashMap::new(),
                avg_confidence_by_specialty: std::collections::HashMap::new(),
            },
        };

        let result = validator.cross_validate(aggregated);

        // finding1: 高置信度单专家应该被确认
        // finding2: 双专家应该被确认
        // finding3: 低置信度需要审核
        assert_eq!(result.confirmed.len(), 2);
        assert_eq!(result.needs_review.len(), 1);
    }

    #[test]
    fn test_diverse_expertise_strategy() {
        let validator = CrossValidator::new()
            .with_strategy(ValidationStrategy::DiverseExpertise { min_specialties: 2 });

        let finding = create_test_aggregated_finding(0.7, 2, 1); // 同类专业
        let aggregated = AggregatedResults {
            findings: vec![finding],
            statistics: crate::multi_agent::aggregator::AggregationStatistics {
                total_worker_results: 2,
                raw_findings_count: 1,
                unique_findings_count: 1,
                multi_expert_confirmed_count: 1,
                unique_specialty_count: 1,
            },
            expert_coverage: crate::multi_agent::aggregator::ExpertCoverage {
                participating_specialties: vec![AgentSpecialty::SqlInjectionExpert],
                findings_by_specialty: std::collections::HashMap::new(),
                avg_confidence_by_specialty: std::collections::HashMap::new(),
            },
        };

        let result = validator.cross_validate(aggregated);

        // 同类专业，多样性不足
        assert_eq!(result.needs_review.len(), 1);
    }

    #[test]
    fn test_validation_score_calculation() {
        let validator = CrossValidator::new();

        let score = validator.calculate_score(3, 2, 0.8);

        // 置信度分数: 0.8 * 60 = 48
        // 确认者分数: 3 * 5 = 15
        // 多样性分数: 2 * 3 = 6
        // 总分: 48 + 15 + 6 = 69
        assert_eq!(score, 69);
    }
}
