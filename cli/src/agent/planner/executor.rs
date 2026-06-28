// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! PlanExecutor —— 执行 Planner 生成的 Action 序列

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;

use deepaudit_core::scanning::Finding;

use crate::agent::environment::EnvironmentModel;
use crate::agent::heuristics::Verdict;
use crate::agent::planner::{
    Action, Plan, PlanExecutionMetadata, ToolCall,
};
use crate::agent::report::InvestigationResult;
use crate::agent::supervisor::Supervisor;
use crate::agent::tools::AgentToolContext;

/// 计划执行器
pub struct PlanExecutor {
    supervisor: Arc<Supervisor>,
    tool_context: Option<AgentToolContext>,
    environment: Arc<EnvironmentModel>,
    investigated_ids: std::sync::Mutex<HashSet<String>>,
}

impl PlanExecutor {
    pub fn new(
        supervisor: Arc<Supervisor>,
        tool_context: Option<AgentToolContext>,
        environment: Arc<EnvironmentModel>,
    ) -> Self {
        Self {
            supervisor,
            tool_context,
            environment,
            investigated_ids: std::sync::Mutex::new(HashSet::new()),
        }
    }

    /// 执行一个 Plan，返回调查结果与执行元数据
    pub async fn execute_plan(
        &self,
        plan: &Plan,
    ) -> Result<(Vec<InvestigationResult>, PlanExecutionMetadata)> {
        let mut results = Vec::new();
        let mut meta = PlanExecutionMetadata {
            actions_total: plan.actions.len(),
            ..Default::default()
        };

        // 把 InvestigateFinding 批量收集，统一交给 Supervisor；跳过已调查过的 finding
        let mut previously_investigated = self.investigated_ids.lock().unwrap();
        let investigate_ids: HashSet<String> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::InvestigateFinding { finding_id, .. } => {
                    if previously_investigated.contains(finding_id) {
                        None
                    } else {
                        Some(finding_id.clone())
                    }
                }
                _ => None,
            })
            .collect();
        previously_investigated.extend(investigate_ids.iter().cloned());
        drop(previously_investigated);

        if !investigate_ids.is_empty() {
            let batch: Vec<Finding> = self
                .environment
                .findings
                .iter()
                .filter(|f| investigate_ids.contains(&f.finding_id))
                .cloned()
                .collect();
            match self.supervisor.run(batch).await {
                mut invs => {
                    meta.actions_completed += investigate_ids.len();
                    results.append(&mut invs);
                }
            }
        }

        // 顺序执行其他行动
        for action in &plan.actions {
            match action {
                Action::InvestigateFinding { .. } => {
                    // 已批量处理
                    continue;
                }
                Action::ExploreEntryPoint {
                    file_path,
                    function_name,
                    route,
                    reason,
                } => {
                    match self
                        .execute_explore_entry_point(file_path, function_name.as_deref(), route.as_deref(), reason)
                        .await
                    {
                        Ok(mut invs) => {
                            meta.actions_completed += 1;
                            meta.new_findings += invs.len();
                            results.append(&mut invs);
                        }
                        Err(e) => {
                            meta.actions_failed += 1;
                            tracing::warn!("ExploreEntryPoint 失败: {}", e);
                        }
                    }
                }
                Action::VerifyHypothesis { hypothesis, tools } => {
                    match self.execute_verify_hypothesis(hypothesis, tools).await {
                        Ok(mut invs) => {
                            meta.actions_completed += 1;
                            meta.new_findings += invs.len();
                            results.append(&mut invs);
                        }
                        Err(e) => {
                            meta.actions_failed += 1;
                            tracing::warn!("VerifyHypothesis 失败: {}", e);
                        }
                    }
                }
                Action::ReScanWithRule {
                    rule_yaml,
                    rule_name,
                } => {
                    match self.execute_rescan_with_rule(rule_yaml, rule_name).await {
                        Ok(()) => {
                            meta.actions_completed += 1;
                        }
                        Err(e) => {
                            meta.actions_failed += 1;
                            tracing::warn!("ReScanWithRule 失败: {}", e);
                        }
                    }
                }
                Action::ReportFinding {
                    file_path,
                    line,
                    vuln_type,
                    severity,
                    description,
                    verdict,
                    reasoning,
                } => {
                    results.push(self.build_report_result(
                        file_path, *line, vuln_type, severity, description, *verdict, reasoning,
                    ));
                    meta.actions_completed += 1;
                    meta.new_findings += 1;
                }
            }
        }

        Ok((results, meta))
    }

    async fn execute_explore_entry_point(
        &self,
        file_path: &str,
        function_name: Option<&str>,
        _route: Option<&str>,
        reason: &str,
    ) -> Result<Vec<InvestigationResult>> {
        let mut results = Vec::new();
        let Some(ref ctx) = self.tool_context else {
            return Ok(results);
        };

        let func = function_name.unwrap_or("");

        // 1. 追踪变量流：从入口函数出发找可达 sink
        let flow_result = ctx.trace_variable_flow(file_path, func);
        if !flow_result.flows_to_sinks.is_empty() {
            for path in &flow_result.flows_to_sinks {
                let observation = format!(
                    "入口点 {}:{} 可达 sink {}:{}（{}）",
                    file_path, func, path.sink_file, path.sink_line, path.sink_function
                );
                let mut result = self.build_report_result(
                    &path.sink_file,
                    path.sink_line,
                    &path.vulnerability_type,
                    "high",
                    format!("从入口点 {} 追踪到潜在 sink", file_path),
                    Verdict::NeedsReview,
                    format!("{} 探索发现：{}", reason, observation),
                );
                result.reasoning = format!(
                    "[ExploreEntryPoint] {}\n变量流追踪发现 {} 个可达 sink。",
                    reason,
                    flow_result.flows_to_sinks.len()
                );
                results.push(result);
            }
        }

        // 2. 查询调用者（从入口点反向，确认信任边界）
        let _callers = ctx.query_callers(file_path, func);

        Ok(results)
    }

    async fn execute_verify_hypothesis(
        &self,
        hypothesis: &crate::agent::planner::Hypothesis,
        tools: &[ToolCall],
    ) -> Result<Vec<InvestigationResult>> {
        let mut observations = Vec::new();
        let Some(ref ctx) = self.tool_context else {
            return Ok(Vec::new());
        };

        for call in tools {
            let mut input = call.input.clone();
            if let Some(obj) = input.as_object_mut() {
                if !obj.contains_key("project_path") {
                    obj.insert(
                        "project_path".to_string(),
                        serde_json::json!(self.environment.project_path.to_string_lossy().to_string()),
                    );
                }
            }
            match ctx.execute_tool(&call.tool_name, input).await {
                Ok(out) => {
                    observations.push(format!(
                        "[{}] {}\n{}",
                        call.tool_name,
                        call.purpose,
                        if out.is_error { format!("ERROR: {}", out.text) } else { out.text }
                    ));
                }
                Err(e) => {
                    observations.push(format!("[{}] 工具调用失败: {}", call.tool_name, e));
                }
            }
        }

        // 规则判定：若观察到中间件覆盖或 sink 不可达，则判 FP/needs_review
        let middleware_covers = observations
            .iter()
            .any(|o| o.contains("中间件") && o.contains("认证"));
        let no_sink = observations
            .iter()
            .all(|o| !o.contains("sink") && !o.contains("Sink"));

        let verdict = if middleware_covers || no_sink {
            Verdict::FalsePositive
        } else {
            Verdict::NeedsReview
        };

        let result = self.build_report_result(
            "verify-hypothesis",
            0,
            "hypothesis-verification",
            "medium",
            hypothesis.statement.clone(),
            verdict,
            format!(
                "[VerifyHypothesis] {}\n观察结果：\n{}",
                hypothesis.statement,
                observations.join("\n")
            ),
        );

        Ok(vec![result])
    }

    async fn execute_rescan_with_rule(&self, rule_yaml: &str, rule_name: &str) -> Result<()> {
        let rules_dir = self.environment.project_path.join(".ctx-audit").join("rules");
        std::fs::create_dir_all(&rules_dir)?;
        let file_name = format!("llm-generated-{}.yaml", sanitize_filename(rule_name));
        let path = rules_dir.join(&file_name);
        std::fs::write(&path, rule_yaml)
            .map_err(|e| anyhow::anyhow!("写入规则失败: {}", e))?;
        tracing::info!("已写入动态规则: {}", path.display());
        Ok(())
    }

    fn build_report_result(
        &self,
        file_path: &str,
        line: usize,
        vuln_type: &str,
        severity: &str,
        _description: impl Into<String>,
        verdict: Verdict,
        reasoning: impl Into<String>,
    ) -> InvestigationResult {
        InvestigationResult {
            investigation_id: uuid::Uuid::new_v4().to_string(),
            session_id: String::new(),
            finding_id: format!("proactive-{}-{}", file_path, line),
            file_path: file_path.to_string(),
            line,
            vulnerability_type: vuln_type.to_string(),
            severity: severity.to_string(),
            hypothesis: String::new(),
            evidence: crate::agent::evidence::Evidence::default(),
            verdict,
            reasoning: reasoning.into(),
            specialist_result: None,
            reviews: Vec::new(),
            confidence: 0.5,
            tool_context: self.tool_context.clone(),
            investigation_steps: Vec::new(),
            audited_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect::<String>()
        .to_lowercase()
}
