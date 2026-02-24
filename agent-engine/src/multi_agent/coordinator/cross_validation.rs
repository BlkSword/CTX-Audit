// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 交叉验证与发现质疑
//!
//! 实现 Coordinator-Specialist 架构中的发现质疑和交叉验证机制。

use crate::multi_agent::task::AgentSpecialty;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// 发现挑战
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingChallenge {
    /// 挑战 ID
    pub id: String,

    /// 发现 ID
    pub finding_id: String,

    /// 挑战者 Specialist ID
    pub challenger_id: String,

    /// 挑战者专业领域
    pub challenger_specialty: AgentSpecialty,

    /// 挑战原因
    pub reason: String,

    /// 挑战类型
    pub challenge_type: ChallengeType,

    /// 请求额外验证
    pub request_verification: bool,

    /// 挑战时间
    pub challenged_at: chrono::DateTime<chrono::Utc>,

    /// 状态
    pub status: ChallengeStatus,
}

/// 挑战类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeType {
    /// 假阳性质疑
    FalsePositive,

    /// 证据不足
    InsufficientEvidence,

    /// 上下文误解
    ContextMisunderstanding,

    /// 规则误报
    RuleMisapplication,

    /// 需要人工审核
    NeedsManualReview,

    /// 其他
    Other { reason: String },
}

/// 挑战状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// 待响应
    Pending,

    /// 已接受 (发现者同意质疑)
    Accepted,

    /// 已拒绝 (发现者反驳质疑)
    Rejected { rebuttal: String },

    /// 已验证 (经过进一步验证)
    Verified { confirmed: bool },

    /// 已取消
    Cancelled,
}

/// 发现验证状态
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingValidationStatus {
    /// 未验证
    Unvalidated,

    /// 已确认
    Confirmed {
        /// 确认专家数量
        expert_count: usize,
    },

    /// 已质疑
    Challenged {
        /// 质疑数量
        challenge_count: usize,
    },

    /// 已拒绝 (假阳性)
    Rejected,

    /// 需要人工审核
    NeedsManualReview,
}

/// 发现验证记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingValidation {
    /// 发现 ID
    pub finding_id: String,

    /// 发现者 Specialist ID
    pub discoverer_id: String,

    /// 验证状态
    pub status: FindingValidationStatus,

    /// 确认者列表
    confirmed_by: Vec<String>,

    /// 质疑者列表
    challenged_by: Vec<String>,

    /// 挑战记录
    pub challenges: Vec<FindingChallenge>,

    /// 综合置信度 (考虑质疑后的调整)
    pub adjusted_confidence: f32,

    /// 创建时间
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// 更新时间
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl FindingValidation {
    /// 创建新的验证记录
    pub fn new(finding_id: String, discoverer_id: String, initial_confidence: f32) -> Self {
        let now = chrono::Utc::now();
        Self {
            finding_id,
            discoverer_id,
            status: FindingValidationStatus::Unvalidated,
            confirmed_by: Vec::new(),
            challenged_by: Vec::new(),
            challenges: Vec::new(),
            adjusted_confidence: initial_confidence,
            created_at: now,
            updated_at: now,
        }
    }

    /// 添加确认
    pub fn add_confirmation(&mut self, specialist_id: &str) {
        if !self.confirmed_by.contains(&specialist_id.to_string()) {
            self.confirmed_by.push(specialist_id.to_string());
            self.update_status();
            self.recalculate_confidence();
            self.updated_at = chrono::Utc::now();
        }
    }

    /// 添加挑战
    pub fn add_challenge(&mut self, challenge: FindingChallenge) {
        let challenger_id = challenge.challenger_id.clone();
        self.challenges.push(challenge);

        if !self.challenged_by.contains(&challenger_id) {
            self.challenged_by.push(challenger_id);
        }

        self.update_status();
        self.recalculate_confidence();
        self.updated_at = chrono::Utc::now();
    }

    /// 更新验证状态
    fn update_status(&mut self) {
        self.status = if !self.challenged_by.is_empty() {
            FindingValidationStatus::Challenged {
                challenge_count: self.challenged_by.len(),
            }
        } else if !self.confirmed_by.is_empty() {
            FindingValidationStatus::Confirmed {
                expert_count: self.confirmed_by.len(),
            }
        } else {
            FindingValidationStatus::Unvalidated
        };
    }

    /// 重新计算置信度 (考虑质疑和确认)
    fn recalculate_confidence(&mut self) {
        let confirmation_bonus = self.confirmed_by.len() as f32 * 0.05;
        let challenge_penalty = self.challenged_by.len() as f32 * 0.15;

        // 基础置信度需要从外部获取，这里简化处理
        self.adjusted_confidence = (self.adjusted_confidence + confirmation_bonus - challenge_penalty).clamp(0.0, 1.0);
    }

    /// 是否需要人工审核
    pub fn needs_manual_review(&self) -> bool {
        match self.status {
            FindingValidationStatus::Challenged { challenge_count } => {
                // 多个专家质疑或严重质疑需要人工审核
                challenge_count >= 2 || self.challenges.iter().any(|c| {
                    matches!(c.challenge_type, ChallengeType::NeedsManualReview)
                })
            }
            FindingValidationStatus::NeedsManualReview => true,
            _ => false,
        }
    }

    /// 获取验证摘要
    pub fn summary(&self) -> String {
        match self.status {
            FindingValidationStatus::Unvalidated => "未验证".to_string(),
            FindingValidationStatus::Confirmed { expert_count } => {
                format!("已确认 ({} 位专家)", expert_count)
            }
            FindingValidationStatus::Challenged { challenge_count } => {
                format!("已质疑 ({} 次挑战)", challenge_count)
            }
            FindingValidationStatus::Rejected => "已拒绝".to_string(),
            FindingValidationStatus::NeedsManualReview => "需要人工审核".to_string(),
        }
    }
}

/// 交叉验证管理器
#[derive(Clone)]
pub struct CrossValidationManager {
    /// 验证记录 (finding_id -> validation)
    validations: Arc<RwLock<HashMap<String, FindingValidation>>>,

    /// 质疑阈值 (超过此数量的质疑需要人工审核)
    challenge_threshold: usize,

    /// 确认阈值 (超过此数量的确认自动通过)
    confirmation_threshold: usize,
}

impl CrossValidationManager {
    /// 创建新的交叉验证管理器
    pub fn new() -> Self {
        Self {
            validations: Arc::new(RwLock::new(HashMap::new())),
            challenge_threshold: 2,
            confirmation_threshold: 3,
        }
    }

    /// 设置阈值
    pub fn with_thresholds(mut self, challenge_threshold: usize, confirmation_threshold: usize) -> Self {
        self.challenge_threshold = challenge_threshold;
        self.confirmation_threshold = confirmation_threshold;
        self
    }

    /// 注册发现 (创建验证记录)
    pub async fn register_finding(
        &self,
        finding_id: String,
        discoverer_id: String,
        initial_confidence: f32,
    ) {
        let validation = FindingValidation::new(finding_id.clone(), discoverer_id, initial_confidence);
        self.validations.write().await.insert(finding_id, validation);
    }

    /// 确认发现
    pub async fn confirm_finding(
        &self,
        finding_id: &str,
        specialist_id: &str,
    ) -> anyhow::Result<FindingValidationStatus> {
        let mut validations = self.validations.write().await;
        if let Some(validation) = validations.get_mut(finding_id) {
            validation.add_confirmation(specialist_id);
            Ok(validation.status.clone())
        } else {
            Err(anyhow::anyhow!("发现不存在: {}", finding_id))
        }
    }

    /// 质疑发现
    pub async fn challenge_finding(
        &self,
        finding_id: &str,
        challenge: FindingChallenge,
    ) -> anyhow::Result<FindingValidationStatus> {
        let mut validations = self.validations.write().await;
        if let Some(validation) = validations.get_mut(finding_id) {
            validation.add_challenge(challenge);
            Ok(validation.status.clone())
        } else {
            Err(anyhow::anyhow!("发现不存在: {}", finding_id))
        }
    }

    /// 获取验证状态
    pub async fn get_validation(&self, finding_id: &str) -> Option<FindingValidation> {
        self.validations.read().await.get(finding_id).cloned()
    }

    /// 检查发现是否被确认
    pub async fn is_confirmed(&self, finding_id: &str) -> bool {
        if let Some(validation) = self.get_validation(finding_id).await {
            matches!(validation.status, FindingValidationStatus::Confirmed { .. })
        } else {
            false
        }
    }

    /// 检查发现是否需要人工审核
    pub async fn needs_manual_review(&self, finding_id: &str) -> bool {
        if let Some(validation) = self.get_validation(finding_id).await {
            validation.needs_manual_review()
        } else {
            false
        }
    }

    /// 获取所有需要审核的发现
    pub async fn get_findings_needing_review(&self) -> Vec<String> {
        self.validations
            .read()
            .await
            .iter()
            .filter(|(_, v)| v.needs_manual_review())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// 获取验证统计
    pub async fn get_stats(&self) -> CrossValidationStats {
        let validations = self.validations.read().await;
        let mut stats = CrossValidationStats::default();

        for validation in validations.values() {
            match validation.status {
                FindingValidationStatus::Unvalidated => stats.unvalidated += 1,
                FindingValidationStatus::Confirmed { .. } => stats.confirmed += 1,
                FindingValidationStatus::Challenged { .. } => stats.challenged += 1,
                FindingValidationStatus::Rejected => stats.rejected += 1,
                FindingValidationStatus::NeedsManualReview => stats.needs_review += 1,
            }
        }

        stats.total_findings = validations.len();
        stats
    }

    /// 批量确认发现 (来自同一 Specialist)
    pub async fn batch_confirm(
        &self,
        specialist_id: &str,
        finding_ids: Vec<String>,
    ) -> usize {
        let mut confirmed_count = 0;
        for finding_id in finding_ids {
            if self.confirm_finding(&finding_id, specialist_id).await.is_ok() {
                confirmed_count += 1;
            }
        }
        confirmed_count
    }

    /// 自动验证 (基于规则自动确认/拒绝)
    pub async fn auto_validate(
        &self,
        finding_id: &str,
        rules: &AutoValidationRules,
    ) -> anyhow::Result<AutoValidationResult> {
        let validation = self.get_validation(finding_id).await
            .ok_or_else(|| anyhow::anyhow!("发现不存在: {}", finding_id))?;

        // 高置信度 + 无质疑 -> 自动确认
        if validation.adjusted_confidence >= rules.auto_confirm_threshold
            && validation.challenged_by.is_empty()
        {
            return Ok(AutoValidationResult::AutoConfirmed);
        }

        // 多个质疑 -> 自动拒绝或标记需审核
        if validation.challenged_by.len() >= self.challenge_threshold {
            if validation.challenged_by.len() >= rules.auto_reject_threshold {
                return Ok(AutoValidationResult::AutoRejected);
            } else {
                return Ok(AutoValidationResult::NeedsManualReview);
            }
        }

        Ok(AutoValidationResult::NoAction)
    }

    /// 清理旧的验证记录
    pub async fn cleanup_old(&self, older_than: chrono::Duration) {
        let cutoff = chrono::Utc::now() - older_than;
        let mut validations = self.validations.write().await;

        validations.retain(|_, v| v.updated_at > cutoff);
    }
}

impl Default for CrossValidationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 交叉验证统计
#[derive(Debug, Clone, Default)]
pub struct CrossValidationStats {
    pub total_findings: usize,
    pub unvalidated: usize,
    pub confirmed: usize,
    pub challenged: usize,
    pub rejected: usize,
    pub needs_review: usize,
}

/// 自动验证规则
#[derive(Debug, Clone)]
pub struct AutoValidationRules {
    /// 自动确认阈值 (置信度高于此值且无质疑则自动确认)
    pub auto_confirm_threshold: f32,

    /// 自动拒绝阈值 (质疑数量超过此值则自动拒绝)
    pub auto_reject_threshold: usize,
}

impl Default for AutoValidationRules {
    fn default() -> Self {
        Self {
            auto_confirm_threshold: 0.9,
            auto_reject_threshold: 3,
        }
    }
}

/// 自动验证结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoValidationResult {
    /// 自动确认
    AutoConfirmed,

    /// 自动拒绝
    AutoRejected,

    /// 需要人工审核
    NeedsManualReview,

    /// 无操作
    NoAction,
}

/// Specialist 发现验证接口
///
/// Specialist 可以实现此接口来参与发现验证
#[async_trait::async_trait]
pub trait FindingValidator: Send + Sync {
    /// 验证发现是否有效
    async fn validate_finding(
        &self,
        finding: &super::super::coordinator::FindingData,
        context: &ValidationContext,
    ) -> ValidationResult;

    /// 获取验证器专业领域
    fn specialty(&self) -> AgentSpecialty;
}

/// 验证结果
#[derive(Debug, Clone)]
pub enum ValidationResult {
    /// 确认发现有效
    Confirm {
        confidence_adjustment: f32,
        notes: String,
    },

    /// 质疑发现
    Challenge {
        reason: String,
        challenge_type: ChallengeType,
    },

    /// 跳过验证 (不感兴趣/超出专业范围)
    Skip,

    /// 需要更多信息
    NeedMoreInfo {
        required_info: Vec<String>,
    },
}

/// 验证上下文
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// 原始发现
    pub finding: super::super::coordinator::FindingData,

    /// 发现者 ID
    pub discoverer_id: String,

    /// 发现者专业领域
    pub discoverer_specialty: AgentSpecialty,

    /// 相关代码片段
    pub code_snippets: Vec<String>,

    /// 项目上下文
    pub project_context: String,

    /// 已有的验证数量
    pub existing_validations: usize,

    /// 已有的质疑数量
    pub existing_challenges: usize,
}

/// 创建验证上下文
pub fn create_validation_context(
    finding: super::super::coordinator::FindingData,
    discoverer_id: String,
    discoverer_specialty: AgentSpecialty,
) -> ValidationContext {
    ValidationContext {
        finding: finding.clone(),
        discoverer_id,
        discoverer_specialty,
        code_snippets: Vec::new(),
        project_context: String::new(),
        existing_validations: 0,
        existing_challenges: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_validation_creation() {
        let validation = FindingValidation::new("finding-1".to_string(), "specialist-1".to_string(), 0.85);
        assert_eq!(validation.finding_id, "finding-1");
        assert_eq!(validation.status, FindingValidationStatus::Unvalidated);
        assert_eq!(validation.adjusted_confidence, 0.85);
    }

    #[test]
    fn test_add_confirmation() {
        let mut validation = FindingValidation::new("finding-1".to_string(), "specialist-1".to_string(), 0.75);
        validation.add_confirmation("specialist-2");
        validation.add_confirmation("specialist-3");

        assert_eq!(validation.confirmed_by.len(), 2);
        assert!(matches!(validation.status, FindingValidationStatus::Confirmed { expert_count: 2 }));
    }

    #[test]
    fn test_add_challenge() {
        let mut validation = FindingValidation::new("finding-1".to_string(), "specialist-1".to_string(), 0.75);
        let challenge = FindingChallenge {
            id: "challenge-1".to_string(),
            finding_id: "finding-1".to_string(),
            challenger_id: "specialist-2".to_string(),
            challenger_specialty: AgentSpecialty::XssExpert,
            reason: "误报".to_string(),
            challenge_type: ChallengeType::FalsePositive,
            request_verification: false,
            challenged_at: chrono::Utc::now(),
            status: ChallengeStatus::Pending,
        };
        validation.add_challenge(challenge);

        assert_eq!(validation.challenged_by.len(), 1);
        assert!(matches!(validation.status, FindingValidationStatus::Challenged { .. }));
    }

    #[test]
    fn test_needs_manual_review() {
        let mut validation = FindingValidation::new("finding-1".to_string(), "specialist-1".to_string(), 0.75);

        // 无挑战，不需要审核
        assert!(!validation.needs_manual_review());

        // 添加需要人工审核的挑战
        let challenge = FindingChallenge {
            id: "challenge-1".to_string(),
            finding_id: "finding-1".to_string(),
            challenger_id: "specialist-2".to_string(),
            challenger_specialty: AgentSpecialty::XssExpert,
            reason: "需要人工审核".to_string(),
            challenge_type: ChallengeType::NeedsManualReview,
            request_verification: false,
            challenged_at: chrono::Utc::now(),
            status: ChallengeStatus::Pending,
        };
        validation.add_challenge(challenge);

        assert!(validation.needs_manual_review());
    }

    #[tokio::test]
    async fn test_cross_validation_manager() {
        let manager = CrossValidationManager::new();

        // 注册发现
        manager.register_finding("finding-1".to_string(), "specialist-1".to_string(), 0.8).await;

        // 确认发现
        let status = manager.confirm_finding("finding-1", "specialist-2").await.unwrap();
        assert!(matches!(status, FindingValidationStatus::Confirmed { .. }));

        // 检查是否确认
        assert!(manager.is_confirmed("finding-1").await);
    }

    #[tokio::test]
    async fn test_get_stats() {
        let manager = CrossValidationManager::new();

        // 注册多个发现
        for i in 1..=3 {
            let finding_id = format!("finding-{}", i);
            manager.register_finding(finding_id, format!("specialist-{}", i), 0.8).await;
        }

        // 确认一个
        manager.confirm_finding("finding-1", "specialist-2").await.unwrap();

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_findings, 3);
        assert_eq!(stats.confirmed, 1);
        assert_eq!(stats.unvalidated, 2);
    }
}
