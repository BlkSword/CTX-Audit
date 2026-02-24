// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 结果聚合器

use crate::multi_agent::helpers::{get_confidence, get_line_number, get_severity_enum, FindingCategory};
use crate::multi_agent::task::AgentSpecialty;
use crate::multi_agent::worker::WorkerResult;
use ctx_audit_tools::FindingData;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// 结果聚合器
pub struct ResultAggregator {
    /// 去重策略
    dedup_strategy: DeduplicationStrategy,

    /// 置信度计算器
    confidence_calculator: ConfidenceCalculator,
}

/// 去重策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationStrategy {
    /// 位置阈值（行号差值小于此值视为同一位置）
    pub location_threshold: usize,

    /// 类型匹配规则
    pub type_matching: TypeMatchingRules,
}

/// 类型匹配规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeMatchingRules {
    /// 严格匹配 - 类型必须完全相同
    Strict,

    /// 宽松匹配 - 允许子类型匹配
    Relaxed,

    /// 类别匹配 - 按类别分组（如注入类）
    Category,
}

/// 置信度计算器
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceCalculator {
    /// 多专家加成权重
    pub multi_expert_bonus_weight: f32,

    /// 基础置信度权重
    pub base_confidence_weight: f32,
}

/// 聚合结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedResults {
    /// 所有发现（去重后）
    pub findings: Vec<AggregatedFinding>,

    /// 统计信息
    pub statistics: AggregationStatistics,

    /// 专家覆盖分析
    pub expert_coverage: ExpertCoverage,
}

/// 聚合的发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedFinding {
    /// 发现数据
    pub finding: FindingData,

    /// 确认者列表（Worker ID）
    pub confirmed_by: Vec<String>,

    /// 确认者的专业领域
    pub confirmed_by_specialties: Vec<AgentSpecialty>,

    /// 合并后的置信度
    pub merged_confidence: f32,

    /// 是否多专家确认
    pub is_multi_expert_confirmed: bool,
}

/// 聚合统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationStatistics {
    /// 总 Worker 结果数
    pub total_worker_results: usize,

    /// 原始发现数
    pub raw_findings_count: usize,

    /// 去重后发现数
    pub unique_findings_count: usize,

    /// 多专家确认的发现数
    pub multi_expert_confirmed_count: usize,

    /// 涉及的专家类型数量
    pub unique_specialty_count: usize,
}

/// 专家覆盖分析
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertCoverage {
    /// 参与的专家类型
    pub participating_specialties: Vec<AgentSpecialty>,

    /// 各专家类型的发现数
    pub findings_by_specialty: HashMap<String, usize>,

    /// 各专家类型的平均置信度
    pub avg_confidence_by_specialty: HashMap<String, f32>,
}

impl Default for DeduplicationStrategy {
    fn default() -> Self {
        Self {
            location_threshold: 5,
            type_matching: TypeMatchingRules::Relaxed,
        }
    }
}

impl Default for ConfidenceCalculator {
    fn default() -> Self {
        Self {
            multi_expert_bonus_weight: 0.1,
            base_confidence_weight: 0.9,
        }
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl ResultAggregator {
    /// 创建新的聚合器
    pub fn new() -> Self {
        Self {
            dedup_strategy: DeduplicationStrategy::default(),
            confidence_calculator: ConfidenceCalculator::default(),
        }
    }

    /// 设置去重策略
    pub fn with_dedup_strategy(mut self, strategy: DeduplicationStrategy) -> Self {
        self.dedup_strategy = strategy;
        self
    }

    /// 聚合多个 Worker 的结果
    pub fn aggregate(&self, results: Vec<WorkerResult>) -> AggregatedResults {
        // 提取所有发现
        let mut all_findings: Vec<FindingWithContext> = results
            .iter()
            .flat_map(|r| {
                r.findings
                    .iter()
                    .map(move |f| FindingWithContext {
                        finding: f.clone(),
                        worker_id: r.worker_id.clone(),
                        specialty: r.specialty.clone(),
                        original_confidence: get_confidence(f),
                    })
            })
            .collect();

        // 保存原始数量（在移动之前）
        let raw_count = all_findings.len();

        // 去重
        let unique_findings = self.deduplicate(all_findings);

        // 计算置信度
        let aggregated_findings: Vec<AggregatedFinding> = self
            .calculate_confidence(unique_findings, &results)
            .into_iter()
            .map(|af| {
                let confirmed_count = af.confirmed_by.len();
                AggregatedFinding {
                    finding: af.finding,
                    confirmed_by: af.confirmed_by,
                    confirmed_by_specialties: af.confirmed_by_specialties,
                    merged_confidence: af.merged_confidence,
                    is_multi_expert_confirmed: confirmed_count > 1,
                }
            })
            .collect();

        // 按严重程度和置信度排序
        let mut sorted_findings = aggregated_findings;
        sorted_findings.sort_by(|a, b| {
            get_severity_enum(&b.finding)
                .cmp(&get_severity_enum(&a.finding))
                .then(b.merged_confidence.partial_cmp(&a.merged_confidence).unwrap())
        });

        // 统计信息
        let statistics = AggregationStatistics {
            total_worker_results: results.len(),
            raw_findings_count: raw_count,
            unique_findings_count: sorted_findings.len(),
            multi_expert_confirmed_count: sorted_findings
                .iter()
                .filter(|f| f.is_multi_expert_confirmed)
                .count(),
            unique_specialty_count: results
                .iter()
                .map(|r| &r.specialty)
                .collect::<HashSet<_>>()
                .len(),
        };

        // 专家覆盖分析
        let expert_coverage = self.analyze_expert_coverage(&sorted_findings, &results);

        AggregatedResults {
            findings: sorted_findings,
            statistics,
            expert_coverage,
        }
    }

    /// 去重
    fn deduplicate(&self, findings: Vec<FindingWithContext>) -> Vec<DedupedFinding> {
        let mut unique: Vec<DedupedFinding> = Vec::new();

        for finding_ctx in findings {
            // 查找相似的已有发现
            let similar = unique.iter().position(|f| {
                self.findings_are_similar(&f.finding, &finding_ctx.finding)
                    && self.types_match(&f.finding.category, &finding_ctx.finding.category)
            });

            match similar {
                Some(idx) => {
                    // 合并到已有发现
                    let existing = &mut unique[idx];
                    if !existing.confirmed_by.contains(&finding_ctx.worker_id) {
                        existing.confirmed_by.push(finding_ctx.worker_id.clone());
                    }
                    if !existing
                        .confirmed_by_specialties
                        .contains(&finding_ctx.specialty)
                    {
                        existing
                            .confirmed_by_specialties
                            .push(finding_ctx.specialty);
                    }
                    // 保留高置信度的发现
                    if finding_ctx.original_confidence > get_confidence(&existing.finding) {
                        existing.finding = finding_ctx.finding;
                    }
                }
                None => {
                    // 新发现
                    unique.push(DedupedFinding {
                        finding: finding_ctx.finding,
                        confirmed_by: vec![finding_ctx.worker_id],
                        confirmed_by_specialties: vec![finding_ctx.specialty],
                        merged_confidence: finding_ctx.original_confidence,
                    });
                }
            }
        }

        unique
    }

    /// 判断发现是否相似
    fn findings_are_similar(&self, a: &FindingData, b: &FindingData) -> bool {
        // 文件路径相同
        if a.file_path != b.file_path {
            return false;
        }

        // 行号差值在阈值内
        let line_diff = if get_line_number(a) > get_line_number(b) {
            get_line_number(a) - get_line_number(b)
        } else {
            get_line_number(b) - get_line_number(a)
        };

        line_diff <= self.dedup_strategy.location_threshold
    }

    /// 判断类型是否匹配
    fn types_match(&self, type_a: &str, type_b: &str) -> bool {
        match self.dedup_strategy.type_matching {
            TypeMatchingRules::Strict => type_a == type_b,
            TypeMatchingRules::Relaxed => {
                // 允许子类型匹配（如 sql-injection 和 sql-injection-union）
                let base_a = type_a.split('-').next().unwrap_or(type_a);
                let base_b = type_b.split('-').next().unwrap_or(type_b);
                base_a == base_b
            }
            TypeMatchingRules::Category => {
                // 按类别分组
                self.get_category(type_a) == self.get_category(type_b)
            }
        }
    }

    /// 获取漏洞类别
    fn get_category(&self, vuln_type: &str) -> &str {
        if vuln_type.contains("sql") || vuln_type.contains("nosql") {
            "injection"
        } else if vuln_type.contains("xss") {
            "xss"
        } else if vuln_type.contains("auth")
            || vuln_type.contains("idor")
            || vuln_type.contains("authorization")
        {
            "auth"
        } else if vuln_type.contains("command") || vuln_type.contains("rce") {
            "command"
        } else if vuln_type.contains("path") || vuln_type.contains("traversal") {
            "path"
        } else if vuln_type.contains("ssrf") {
            "ssrf"
        } else if vuln_type.contains("crypto") || vuln_type.contains("encrypt") {
            "crypto"
        } else if vuln_type.contains("config") {
            "config"
        } else {
            "other"
        }
    }

    /// 计算置信度
    fn calculate_confidence(
        &self,
        deduped: Vec<DedupedFinding>,
        _results: &[WorkerResult],
    ) -> Vec<DedupedFinding> {
        deduped
            .into_iter()
            .map(|mut f| {
                f.merged_confidence = self.confidence_calculator.calculate_multi_expert_confidence(
                    &f.finding,
                    f.confirmed_by.len(),
                    f.confirmed_by_specialties.len(),
                );
                f
            })
            .collect()
    }

    /// 分析专家覆盖
    fn analyze_expert_coverage(
        &self,
        findings: &[AggregatedFinding],
        results: &[WorkerResult],
    ) -> ExpertCoverage {
        let participating_specialties: HashSet<_> =
            results.iter().map(|r| r.specialty.clone()).collect();

        let mut findings_by_specialty: HashMap<String, usize> = HashMap::new();
        let mut confidence_by_specialty: HashMap<String, Vec<f32>> = HashMap::new();

        for result in results {
            let specialty_name = format!("{}", result.specialty);
            *findings_by_specialty
                .entry(specialty_name.clone())
                .or_insert(0) += result.findings.len();

            for finding in &result.findings {
                confidence_by_specialty
                    .entry(specialty_name.clone())
                    .or_insert_with(Vec::new)
                    .push(get_confidence(finding));
            }
        }

        let avg_confidence_by_specialty: HashMap<String, f32> = confidence_by_specialty
            .into_iter()
            .map(|(k, v)| {
                let avg = if v.is_empty() {
                    0.0
                } else {
                    v.iter().sum::<f32>() / v.len() as f32
                };
                (k, avg)
            })
            .collect();

        ExpertCoverage {
            participating_specialties: participating_specialties.into_iter().collect(),
            findings_by_specialty,
            avg_confidence_by_specialty,
        }
    }
}

impl ConfidenceCalculator {
    /// 计算多专家确认的置信度
    pub fn calculate_multi_expert_confidence(
        &self,
        finding: &FindingData,
        expert_count: usize,
        specialty_count: usize,
    ) -> f32 {
        let base = get_confidence(finding);

        // 多专家确认加成
        let expert_bonus = if expert_count > 1 {
            (expert_count as f32 - 1.0) * self.multi_expert_bonus_weight
        } else {
            0.0
        };

        // 专家多样性加成
        let diversity_bonus = if specialty_count > 1 {
            (specialty_count as f32 - 1.0) * 0.05
        } else {
            0.0
        };

        // 基础置信度权重
        let weighted_base = base * self.base_confidence_weight;

        // 最终置信度
        (weighted_base + expert_bonus + diversity_bonus).min(0.98)
    }
}

/// 带上下文的发现
#[derive(Debug, Clone)]
struct FindingWithContext {
    finding: FindingData,
    worker_id: String,
    specialty: AgentSpecialty,
    original_confidence: f32,
}

/// 去重后的发现
#[derive(Debug, Clone)]
struct DedupedFinding {
    finding: FindingData,
    confirmed_by: Vec<String>,
    confirmed_by_specialties: Vec<AgentSpecialty>,
    merged_confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_finding(
        file_path: &str,
        line: u32,
        category: &str,
        confidence: f32,
    ) -> FindingData {
        let mut extra = HashMap::new();
        extra.insert("confidence".to_string(), serde_json::json!(confidence));

        FindingData {
            id: Some("test-id".to_string()),
            title: Some("Test Finding".to_string()),
            description: "Test description".to_string(),
            severity: "high".to_string(),
            category: category.to_string(),
            cwe_id: None,
            file_path: file_path.to_string(),
            start_line: line,
            end_line: None,
            code_snippet: Some("code".to_string()),
            recommendation: None,
            status: "open".to_string(),
            verification_status: None,
            discovered_by: None,
            extra,
        }
    }

    #[test]
    fn test_findings_are_similar() {
        let aggregator = ResultAggregator::new();

        let finding_a = create_test_finding("/test/file.rs", 10, "sql-injection", 0.8);
        let finding_b = create_test_finding("/test/file.rs", 12, "sql-injection", 0.7);
        let finding_c = create_test_finding("/test/file.rs", 20, "sql-injection", 0.6);

        assert!(aggregator.findings_are_similar(&finding_a, &finding_b));
        assert!(!aggregator.findings_are_similar(&finding_a, &finding_c));
    }

    #[test]
    fn test_types_match() {
        let aggregator = ResultAggregator::new();

        assert!(aggregator.types_match("sql-injection", "sql-injection"));
        assert!(aggregator.types_match("sql-injection", "sql-injection-union"));
    }

    #[test]
    fn test_get_category() {
        let aggregator = ResultAggregator::new();

        assert_eq!(aggregator.get_category("sql-injection"), "injection");
        assert_eq!(aggregator.get_category("reflected-xss"), "xss");
        assert_eq!(aggregator.get_category("idor"), "auth");
        assert_eq!(aggregator.get_category("command-injection"), "command");
        assert_eq!(aggregator.get_category("path-traversal"), "path");
    }

    #[test]
    fn test_confidence_calculator() {
        let calculator = ConfidenceCalculator::default();
        let finding = create_test_finding("/test/file.rs", 10, "test", 0.7);

        // 单专家
        let single_confidence = calculator.calculate_multi_expert_confidence(&finding, 1, 1);
        assert!((single_confidence - 0.63).abs() < 0.01); // 0.7 * 0.9

        // 多专家
        let multi_confidence = calculator.calculate_multi_expert_confidence(&finding, 3, 2);
        assert!(multi_confidence > single_confidence);
        assert!(multi_confidence < 1.0);
    }
}
