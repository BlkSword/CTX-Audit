// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 双重验证系统
//!
//! 实现初次发现 -> 自我质疑 -> 确认/排除的验证流程

pub mod dual_verification;
pub mod self_questioner;

pub use dual_verification::{
    DualVerificationSystem, DualVerificationConfig,
    EnhancedVerificationResult, Judgment, SelfQuestioningResult,
    FinalConclusion, ConfidenceRecord, ConclusionType,
    VerificationContext, FrameworkInfo,
};
pub use self_questioner::{
    SelfQuestioner, ContradictionEvidence,
    AssumptionCheck, AttackerPerspective, MissedProtection, QuestioningStrategy,
};
