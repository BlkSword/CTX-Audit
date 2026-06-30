// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 启发式判定模块
//!
//! 基于收集到的确定性证据做出 TP/FP/NeedsReview 判定。
//! 规则简单、可解释，便于后续替换为 LLM 判定器。

use anyhow::Result;
use serde::{Deserialize, Serialize};

use deepaudit_core::analysis::attack_surface::is_non_production_path;
use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;

/// 判定结果
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    TruePositive,
    FalsePositive,
    NeedsReview,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::TruePositive => "true_positive",
            Verdict::FalsePositive => "false_positive",
            Verdict::NeedsReview => "needs_review",
        }
    }
}

/// 判定 trait —— 后续 LLM 判定器可实现此 trait
pub trait Judge {
    fn judge(&self, finding: &Finding, evidence: &Evidence) -> Result<Verdict>;
}

/// 基于规则的判定器
pub struct RuleBasedJudge;

impl Judge for RuleBasedJudge {
    fn judge(&self, finding: &Finding, evidence: &Evidence) -> Result<Verdict> {
        Ok(judge_finding(finding, evidence))
    }
}

/// 默认启发式判定逻辑
pub fn judge_finding(finding: &Finding, evidence: &Evidence) -> Verdict {
    // 0. 非生产代码中的命中通常是噪声，直接判为误报。
    // 优先使用扫描阶段标记的 file_role，未标记时回退到默认路径模式。
    if finding
        .file_role
        .as_deref()
        .map(|r| r.eq_ignore_ascii_case("non-production"))
        .unwrap_or_else(|| is_non_production_path(&finding.file_path))
    {
        return Verdict::FalsePositive;
    }

    // 0.5 访问控制类漏洞（UnauthenticatedEndpoint）不依赖 source→sink 污点路径；
    //     只要没有认证/授权屏障，就视为真阳性。
    if finding.vuln_type == "UnauthenticatedEndpoint"
        && !evidence.has_effective_sanitizer
        && !has_confirmed_barrier(evidence, finding)
    {
        return Verdict::TruePositive;
    }

    // 1. 存在有效 sanitizer 或明确安全屏障 → 误报
    if evidence.has_effective_sanitizer || has_confirmed_barrier(evidence, finding) {
        return Verdict::FalsePositive;
    }

    // 2. 调用图确认 source→sink 可达，且无屏障 → 真阳性
    if evidence.call_path.is_some() && !evidence.callers.is_empty() {
        return Verdict::TruePositive;
    }

    // 3. 污点分析本身给出完整链（且 finding 未声明屏障） → 真阳性
    if let Some(ref steps) = evidence.taint_steps {
        if !steps.is_empty() && evidence.barriers.is_empty() {
            return Verdict::TruePositive;
        }
    }

    // 4. finding 自带 source_sink_path 且路径长度 > 0
    if let Some(ref refs) = finding.evidence_refs {
        if let Some(ref ss) = refs.source_sink_path {
            let has_barrier = refs.sanitizer_chain.iter().any(|s| s.effective)
                || !refs.middleware_coverage.is_empty();
            if ss.path_length > 0 && !has_barrier {
                return Verdict::TruePositive;
            }
        }
    }

    // 5. 其余情况证据不足，需人工复核
    Verdict::NeedsReview
}

/// 判断是否有针对该漏洞类型的确认屏障
fn has_confirmed_barrier(evidence: &Evidence, _finding: &Finding) -> bool {
    if !evidence.barriers.is_empty() {
        return true;
    }
    false
}
