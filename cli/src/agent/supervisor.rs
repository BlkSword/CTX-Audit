// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent Supervisor 与 TriageActor
//!
//! 使用 tokio 并发任务 + Semaphore 实现 per-finding Actor 调度。
//! 每个 finding 一个独立任务，具备 panic 隔离和并发控制。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinSet;

use deepaudit_core::scanning::Finding;
use deepaudit_core::CallGraphQueryEngine;

use crate::agent::blackboard::BlackboardState;
use crate::agent::evidence::{collect_evidence, Evidence};
use crate::agent::heuristics::Verdict;
use crate::agent::llm_client::LlmClient;
use crate::agent::report::InvestigationResult;
use crate::agent::investigator::{TaintWalkInvestigator, ToolUsingInvestigator};
use crate::agent::reviewer::{apply_review, Reviewer};
use crate::agent::specialist::{
    merge_specialist_verdict, SpecialistContext, SpecialistRegistry, SpecialistResult,
};
use crate::agent::tools::AgentToolContext;

/// 调度器
#[derive(Clone)]
pub struct Supervisor {
    project_path: PathBuf,
    query_engine: Option<Arc<CallGraphQueryEngine>>,
    llm_client: Arc<dyn LlmClient>,
    blackboard: Arc<RwLock<BlackboardState>>,
    concurrency: usize,
    specialist_enabled: bool,
    specialist_registry: Arc<SpecialistRegistry>,
    review_mode: String,
    reviewer: Arc<dyn Reviewer>,
    tool_context: Option<AgentToolContext>,
    investigator_enabled: bool,
    max_investigation_steps: usize,
    taint_walk_enabled: bool,
    max_taint_walk_steps: usize,
}

impl Supervisor {
    pub fn new(
        project_path: PathBuf,
        query_engine: Option<Arc<CallGraphQueryEngine>>,
        llm_client: Arc<dyn LlmClient>,
        blackboard: Arc<RwLock<BlackboardState>>,
        concurrency: usize,
    ) -> Self {
        Self {
            project_path,
            query_engine,
            llm_client,
            blackboard,
            concurrency: concurrency.max(1),
            specialist_enabled: false,
            specialist_registry: Arc::new(SpecialistRegistry::with_defaults()),
            review_mode: "off".to_string(),
            reviewer: Arc::new(crate::agent::reviewer::RuleBasedReviewer),
            tool_context: None,
            investigator_enabled: false,
            max_investigation_steps: 5,
            taint_walk_enabled: false,
            max_taint_walk_steps: 5,
        }
    }

    /// 启用 Specialist Agent 并指定注册表
    pub fn with_specialists(mut self, registry: Arc<SpecialistRegistry>, enabled: bool) -> Self {
        self.specialist_registry = registry;
        self.specialist_enabled = enabled;
        self
    }

    /// 启用 Reviewer（debate / single 模式）
    pub fn with_reviewer(mut self, reviewer: Arc<dyn Reviewer>, review_mode: String) -> Self {
        self.reviewer = reviewer;
        self.review_mode = review_mode;
        self
    }

    /// 注入 Agent 工具上下文（缓存的 CallGraphQueryEngine）
    pub fn with_tool_context(mut self, tool_context: Option<AgentToolContext>) -> Self {
        self.tool_context = tool_context;
        self
    }

    /// 启用 ReAct 调查器
    pub fn with_investigator(mut self, enabled: bool, max_steps: usize) -> Self {
        self.investigator_enabled = enabled;
        self.max_investigation_steps = max_steps.max(1);
        self
    }

    /// 启用污点步进调查器
    pub fn with_taint_walk(mut self, enabled: bool, max_steps: usize) -> Self {
        self.taint_walk_enabled = enabled;
        self.max_taint_walk_steps = max_steps.max(1);
        self
    }

    /// 并发 triage 所有 finding
    pub async fn run(&self, findings: Vec<Finding>) -> Vec<InvestigationResult> {
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let mut join_set = JoinSet::new();

        for finding in findings {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("Failed to acquire semaphore: {}", e);
                    continue;
                }
            };

            let task = TriageTask {
                finding,
                project_path: self.project_path.clone(),
                query_engine: self.query_engine.clone(),
                llm_client: self.llm_client.clone(),
                blackboard: self.blackboard.clone(),
                specialist_enabled: self.specialist_enabled,
                specialist_registry: self.specialist_registry.clone(),
                review_mode: self.review_mode.clone(),
                reviewer: self.reviewer.clone(),
                tool_context: self.tool_context.clone(),
                investigator_enabled: self.investigator_enabled,
                max_investigation_steps: self.max_investigation_steps,
                taint_walk_enabled: self.taint_walk_enabled,
                max_taint_walk_steps: self.max_taint_walk_steps,
            };

            join_set.spawn(async move {
                let _permit = permit;
                investigate(task).await
            });
        }

        let mut results = Vec::new();
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(inv)) => results.push(inv),
                Ok(Err(e)) => {
                    tracing::warn!("Triage task failed: {}", e);
                }
                Err(e) => {
                    if e.is_panic() {
                        tracing::warn!("Triage task panicked");
                    } else {
                        tracing::warn!("Triage task cancelled");
                    }
                }
            }
        }

        results
    }
}

/// 单个 triage 任务上下文
struct TriageTask {
    finding: Finding,
    project_path: PathBuf,
    query_engine: Option<Arc<CallGraphQueryEngine>>,
    llm_client: Arc<dyn LlmClient>,
    blackboard: Arc<RwLock<BlackboardState>>,
    specialist_enabled: bool,
    specialist_registry: Arc<SpecialistRegistry>,
    review_mode: String,
    reviewer: Arc<dyn Reviewer>,
    tool_context: Option<AgentToolContext>,
    investigator_enabled: bool,
    max_investigation_steps: usize,
    taint_walk_enabled: bool,
    max_taint_walk_steps: usize,
}

/// 实际调查逻辑
async fn investigate(task: TriageTask) -> Result<InvestigationResult> {
    let investigation_id = uuid::Uuid::new_v4().to_string();
    let hypothesis = generate_hypothesis(&task.finding);

    let evidence = collect_evidence(
        &task.project_path,
        &task.finding,
        task.query_engine.as_deref(),
    )
    .unwrap_or_default();

    // 调用 LlmClient（默认 NoopLlmClient 退化为规则判定）
    let triage_result = task.llm_client.triage(&task.finding, &evidence).await?;

    // 可选：调用 Specialist Agent 进行深度判定
    let mut specialist_result: Option<SpecialistResult> = None;
    if task.specialist_enabled {
        let handlers = task.specialist_registry.find_handlers(&task.finding);
        if let Some(specialist) = handlers.into_iter().next() {
            let ctx = SpecialistContext {
                project_path: task.project_path.clone(),
                finding: task.finding.clone(),
                evidence: evidence.clone(),
                query_engine: task.query_engine.clone(),
                tool_context: task.tool_context.clone(),
            };
            match specialist.investigate(ctx).await {
                Ok(sp) => {
                    tracing::debug!(
                        "Specialist {} handled finding {}",
                        sp.specialist_name,
                        task.finding.finding_id
                    );
                    specialist_result = Some(sp);
                }
                Err(e) => {
                    tracing::warn!(
                        "Specialist failed for finding {}: {}",
                        task.finding.finding_id,
                        e
                    );
                }
            }
        }
    }

    // 融合 specialist 判定
    let (mut verdict, mut primary_confidence) = if let Some(ref sp) = specialist_result {
        merge_specialist_verdict(triage_result.verdict, triage_result.confidence, sp)
    } else {
        (triage_result.verdict, triage_result.confidence)
    };

    // ReAct 自主调查（Phase 6）：让 LLM 动态选择工具迭代收集证据
    let mut investigation_steps = Vec::new();
    let mut investigator_reasoning = String::new();
    if task.investigator_enabled {
        let investigator = crate::agent::investigator::ToolUsingInvestigator::new(
            task.llm_client.clone(),
            task.max_investigation_steps,
        );
        let ctx = SpecialistContext {
            project_path: task.project_path.clone(),
            finding: task.finding.clone(),
            evidence: evidence.clone(),
            query_engine: task.query_engine.clone(),
            tool_context: task.tool_context.clone(),
        };
        match investigator.investigate(&ctx, &hypothesis).await {
            Ok(outcome) => {
                investigation_steps = outcome.steps;
                investigator_reasoning = outcome.reasoning.clone();
                // 调查器置信度更高时覆盖 verdict
                if outcome.confidence >= primary_confidence {
                    verdict = outcome.verdict;
                    primary_confidence = outcome.confidence;
                    tracing::debug!(
                        "Investigator overridden verdict for finding {}: {:?} (conf {})",
                        task.finding.finding_id,
                        outcome.verdict,
                        outcome.confidence
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Investigator failed for finding {}: {}",
                    task.finding.finding_id,
                    e
                );
            }
        }
    }

    // 污点步进调查（Phase 7）：从 sink 反向逐步追踪到 source，补全证据链
    let mut taint_walk_reasoning = String::new();
    if task.taint_walk_enabled
        && (verdict == Verdict::NeedsReview || evidence.call_path.is_none())
    {
        let taint_walk = TaintWalkInvestigator::new(
            task.llm_client.clone(),
            task.max_taint_walk_steps,
        );
        let ctx = SpecialistContext {
            project_path: task.project_path.clone(),
            finding: task.finding.clone(),
            evidence: evidence.clone(),
            query_engine: task.query_engine.clone(),
            tool_context: task.tool_context.clone(),
        };
        match taint_walk.investigate(&ctx, &hypothesis).await {
            Ok(outcome) => {
                investigation_steps.extend(outcome.steps);
                taint_walk_reasoning = outcome.reasoning.clone();
                if outcome.confidence >= primary_confidence {
                    verdict = outcome.verdict;
                    primary_confidence = outcome.confidence;
                    tracing::debug!(
                        "TaintWalk overridden verdict for finding {}: {:?} (conf {})",
                        task.finding.finding_id,
                        outcome.verdict,
                        outcome.confidence
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "TaintWalk failed for finding {}: {}",
                    task.finding.finding_id,
                    e
                );
            }
        }
    }

    let combined_reasoning = if let Some(ref sp) = specialist_result {
        if investigator_reasoning.is_empty() {
            format!(
                "{} [Specialist {}] 补充: {}",
                triage_result.reasoning, sp.specialist_name, sp.reasoning
            )
        } else {
            format!(
                "{} [Specialist {}] 补充: {} [Investigator] 调查结论: {}",
                triage_result.reasoning, sp.specialist_name, sp.reasoning, investigator_reasoning
            )
        }
    } else if !investigator_reasoning.is_empty() {
        format!(
            "{} [Investigator] 调查结论: {}",
            triage_result.reasoning, investigator_reasoning
        )
    } else {
        triage_result.reasoning
    };

    let combined_reasoning = if !taint_walk_reasoning.is_empty() {
        format!(
            "{} [TaintWalk] 污点步进结论: {}",
            combined_reasoning, taint_walk_reasoning
        )
    } else {
        combined_reasoning
    };

    let reasoning = build_reasoning(&task.finding, &evidence, &verdict, &combined_reasoning);

    let specialist_result_json = specialist_result.map(|sp| {
        serde_json::json!({
            "specialist_name": sp.specialist_name,
            "verdict": sp.verdict.as_str(),
            "confidence": sp.confidence,
            "reasoning": sp.reasoning,
            "observations": sp.observations,
        })
    });

    let mut result = InvestigationResult {
        investigation_id,
        session_id: String::new(), // 由调用方统一填充
        finding_id: task.finding.finding_id.clone(),
        file_path: task.finding.file_path.clone(),
        line: task.finding.line_start,
        vulnerability_type: task.finding.vuln_type.clone(),
        severity: task.finding.severity.clone(),
        hypothesis,
        evidence,
        verdict,
        reasoning,
        specialist_result: specialist_result_json,
        reviews: Vec::new(),
        confidence: primary_confidence,
        tool_context: task.tool_context.clone(),
        investigation_steps,
        audited_at: chrono::Utc::now().to_rfc3339(),
    };

    // Debate / Single Reviewer 复核
    if task.review_mode != "off" {
        match task.reviewer.review(&result).await {
            Ok(opinion) => {
                let (reviewed_verdict, review_note) =
                    apply_review(result.verdict, result.confidence, &opinion);
                if reviewed_verdict != result.verdict {
                    result.verdict = reviewed_verdict;
                    result.confidence = opinion.confidence;
                    result.reasoning = format!("{} [Debate] {}", result.reasoning, review_note);
                } else if !opinion.agrees_with_primary {
                    result.reasoning = format!(
                        "{} [Debate] Reviewer 未覆盖初审（置信度不足）：{}",
                        result.reasoning, opinion.reasoning
                    );
                }
                result.reviews.push(opinion);
            }
            Err(e) => {
                tracing::warn!(
                    "Reviewer failed for finding {}: {}",
                    task.finding.finding_id,
                    e
                );
            }
        }
    }

    {
        let mut bb: tokio::sync::RwLockWriteGuard<'_, BlackboardState> =
            task.blackboard.write().await;
        bb.update_pheromone(&task.finding, &result.evidence, &result.verdict);
        bb.add_investigation(&result);
    }

    Ok(result)
}

fn generate_hypothesis(finding: &Finding) -> String {
    format!(
        "{} 在 {}:{} 被报告为 {}。假设：用户可控输入能够未经充分净化到达该危险操作。",
        finding.vuln_type, finding.file_path, finding.line_start, finding.description
    )
}

fn build_reasoning(
    finding: &Finding,
    evidence: &Evidence,
    verdict: &Verdict,
    llm_reasoning: &str,
) -> String {
    let mut parts = Vec::new();

    match verdict {
        Verdict::TruePositive => {
            parts.push("判定为真阳性。".to_string());
            if evidence.call_path.is_some() {
                parts.push("调用图确认 source→sink 路径存在。".to_string());
            }
            if evidence.taint_steps.is_some() {
                parts.push("污点分析发现完整数据流链。".to_string());
            }
            if evidence.barriers.is_empty() {
                parts.push("未检测到有效安全屏障或 sanitizer。".to_string());
            }
        }
        Verdict::FalsePositive => {
            parts.push("判定为误报。".to_string());
            if !evidence.barriers.is_empty() {
                parts.push(format!(
                    "检测到安全屏障: {}。",
                    evidence.barriers.join(", ")
                ));
            }
            if evidence.has_effective_sanitizer {
                parts.push("污点路径上存在有效 sanitizer。".to_string());
            }
            if evidence.middleware_coverage.is_some() {
                parts.push("中间件提供了额外防护。".to_string());
            }
        }
        Verdict::NeedsReview => {
            parts.push("证据不足，需人工复核。".to_string());
            if evidence.call_path.is_none() && evidence.taint_steps.is_none() {
                parts.push("未找到 source→sink 调用路径或完整污点链。".to_string());
            }
        }
    }

    parts.push(format!("LLM/规则判定理由: {}", llm_reasoning));

    if parts.len() <= 1 {
        format!("对 {} 的自动审计未能形成明确结论。", finding.vuln_type)
    } else {
        parts.join("")
    }
}
