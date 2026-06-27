// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent Supervisor 与 TriageActor
//!
//! 使用 tokio 并发任务 + Semaphore 实现 per-finding Actor 调度。
//! 每个 finding 一个独立任务，具备 panic 隔离和并发控制。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use deepaudit_core::scanning::Finding;
use deepaudit_core::CallGraphQueryEngine;

use crate::agent::evidence::{collect_evidence, Evidence};
use crate::agent::heuristics::Verdict;
use crate::agent::llm_client::LlmClient;
use crate::agent::report::InvestigationResult;

/// 调度器
pub struct Supervisor {
    project_path: PathBuf,
    query_engine: Option<Arc<CallGraphQueryEngine>>,
    llm_client: Arc<dyn LlmClient>,
    concurrency: usize,
}

impl Supervisor {
    pub fn new(
        project_path: PathBuf,
        query_engine: Option<Arc<CallGraphQueryEngine>>,
        llm_client: Arc<dyn LlmClient>,
        concurrency: usize,
    ) -> Self {
        Self {
            project_path,
            query_engine,
            llm_client,
            concurrency: concurrency.max(1),
        }
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

    let reasoning = build_reasoning(
        &task.finding,
        &evidence,
        &triage_result.verdict,
        &triage_result.reasoning,
    );

    Ok(InvestigationResult {
        investigation_id,
        session_id: String::new(), // 由调用方统一填充
        finding_id: task.finding.finding_id,
        file_path: task.finding.file_path,
        line: task.finding.line_start,
        vulnerability_type: task.finding.vuln_type,
        severity: task.finding.severity,
        hypothesis,
        evidence,
        verdict: triage_result.verdict,
        reasoning,
        audited_at: chrono::Utc::now().to_rfc3339(),
    })
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
