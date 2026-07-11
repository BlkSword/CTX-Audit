// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! StrategyPlanner —— 根据 EnvironmentModel 生成审计目标与优先级

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::agent::environment::EnvironmentModel;
use crate::agent::llm_client::LlmClient;
use crate::agent::planner::AuditGoal;
use deepaudit_core::analysis::attack_surface::{
    is_non_production_path_with_patterns, is_public_route_with_patterns,
};
use deepaudit_core::scanning::Finding;

/// 策略模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlannerStrategy {
    /// 规则驱动（默认，无需 LLM）
    Rule,
    /// LLM 驱动（需要配置 LLM）
    Llm,
    /// 自动选择：有 LLM 时用 LLM，否则规则
    Auto,
}

impl PlannerStrategy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "llm" => PlannerStrategy::Llm,
            "rule" => PlannerStrategy::Rule,
            _ => PlannerStrategy::Auto,
        }
    }
}

/// Planner 配置
#[derive(Debug, Clone)]
pub struct PlannerConfig {
    pub strategy: PlannerStrategy,
    pub max_goals: usize,
    pub max_exploration_actions: usize,
    pub enable_proactive_scan: bool,
    pub enable_reflection: bool,
    pub convergence_threshold: f64,
    pub public_route_patterns: Vec<String>,
    pub non_production_path_patterns: Vec<String>,
}

impl Default for PlannerConfig {
    fn default() -> Self {
        Self {
            strategy: PlannerStrategy::Auto,
            max_goals: 10,
            max_exploration_actions: 5,
            enable_proactive_scan: false,
            enable_reflection: true,
            convergence_threshold: 5.0,
            public_route_patterns:
                deepaudit_core::analysis::attack_surface::default_public_route_patterns(),
            non_production_path_patterns:
                deepaudit_core::analysis::attack_surface::default_non_production_path_patterns(),
        }
    }
}

/// 策略规划器
pub struct StrategyPlanner {
    config: PlannerConfig,
    llm_client: Option<Arc<dyn LlmClient>>,
}

impl StrategyPlanner {
    pub fn new(llm_client: Arc<dyn LlmClient>, config: PlannerConfig) -> Self {
        let strategy = config.strategy;
        // Auto 模式下根据实际客户端类型判断 LLM 是否可用，不再依赖环境变量
        let has_real_llm = !llm_client.is_noop();
        let llm_client = if strategy == PlannerStrategy::Llm
            || (strategy == PlannerStrategy::Auto && has_real_llm)
        {
            Some(llm_client)
        } else {
            None
        };
        Self { config, llm_client }
    }

    /// 生成审计目标列表
    pub async fn plan_goals(&self, env: &EnvironmentModel) -> Vec<AuditGoal> {
        if let Some(ref llm) = self.llm_client {
            match self.plan_goals_with_llm(env, llm).await {
                Ok(goals) if !goals.is_empty() => return goals,
                Err(e) => {
                    tracing::warn!("LLM 目标生成失败，回退到规则模式: {}", e);
                }
                _ => {}
            }
        }
        self.plan_goals_rule_based(env)
    }

    /// 规则模式目标生成
    fn plan_goals_rule_based(&self, env: &EnvironmentModel) -> Vec<AuditGoal> {
        let mut goals = Vec::new();
        let mut covered_vuln_types: HashSet<String> = HashSet::new();

        let injection_types = ["CWE-78", "CWE-79", "CWE-89", "CWE-94"];
        let mut injection_findings: Vec<&Finding> = Vec::new();
        for vt in &injection_types {
            injection_findings.extend(env.findings_by_vuln_type(vt));
        }
        injection_findings.retain(|f| {
            matches!(f.severity.to_lowercase().as_str(), "critical" | "high")
                && !env.is_baselined(f)
        });
        injection_findings.sort_by(|a, b| {
            let rank = |s: &str| match s.to_lowercase().as_str() {
                "critical" => 0,
                "high" => 1,
                _ => 2,
            };
            rank(&a.severity).cmp(&rank(&b.severity))
        });
        injection_findings.truncate(50);

        if !injection_findings.is_empty() {
            let entry_files: Vec<String> = env
                .high_risk_unauthenticated_entries()
                .iter()
                .take(10)
                .map(|ep| ep.file_path.clone())
                .collect();
            goals.push(AuditGoal {
                objective:
                    "验证可被未认证/高风险入口触发的注入类漏洞（命令注入、XSS、SQLi、代码注入）"
                        .to_string(),
                priority: 1.0,
                target_vuln_types: injection_types.iter().map(|s| s.to_string()).collect(),
                target_severities: vec!["critical".to_string(), "high".to_string()],
                focus_entry_points: entry_files,
                max_findings: 20,
            });
            covered_vuln_types.extend(injection_types.iter().map(|s| s.to_string()));
        }

        // 架构风险模式驱动的目标
        for risk in &env.risk_matches {
            if risk.confidence < 0.5 {
                continue;
            }
            let cwe = risk.cwe.clone().unwrap_or_else(|| "CWE-???".to_string());
            if covered_vuln_types.contains(&cwe) {
                continue;
            }

            // 过滤公开路由和非生产代码路径，避免把设计上公开的端点
            // 或示例/教学代码当作架构风险目标
            let entry_files: Vec<String> = risk
                .affected_entries
                .iter()
                .filter(|e| {
                    if let Some(ref route) = e.route {
                        if is_public_route_with_patterns(route, &self.config.public_route_patterns)
                        {
                            return false;
                        }
                    }
                    !is_non_production_path_with_patterns(
                        &e.file_path,
                        &self.config.non_production_path_patterns,
                    )
                })
                .take(5)
                .map(|e| e.file_path.clone())
                .collect();

            // 没有具体可疑入口点时，不生成抽象的架构风险目标
            if entry_files.is_empty() {
                continue;
            }

            goals.push(AuditGoal {
                objective: format!("审计架构风险：{}（{}）", risk.pattern_name, risk.pattern_id),
                priority: (risk.confidence as f64).clamp(0.5, 1.0),
                target_vuln_types: vec![cwe.clone()],
                target_severities: vec![
                    "critical".to_string(),
                    "high".to_string(),
                    "medium".to_string(),
                ],
                focus_entry_points: entry_files,
                max_findings: 10,
            });
            covered_vuln_types.insert(cwe);
        }

        // 兜底目标：审查剩余 high/critical findings
        let remaining: Vec<&Finding> = env
            .findings
            .iter()
            .filter(|f| {
                matches!(f.severity.to_lowercase().as_str(), "critical" | "high")
                    && !env.is_baselined(f)
                    && !covered_vuln_types.contains(&f.vuln_type)
            })
            .collect();
        if !remaining.is_empty() {
            goals.push(AuditGoal {
                objective: "审查剩余未收敛的 critical/high 发现".to_string(),
                priority: 0.7,
                target_vuln_types: vec!["*".to_string()],
                target_severities: vec!["critical".to_string(), "high".to_string()],
                focus_entry_points: Vec::new(),
                max_findings: 20,
            });
        }

        goals.sort_by(|a, b| b.priority.partial_cmp(&a.priority).unwrap());
        goals.truncate(self.config.max_goals);
        goals
    }

    /// LLM 模式目标生成
    ///
    /// 把 EnvironmentModel 的关键信息压缩后交给 LLM，要求返回 JSON 格式的 AuditGoal 数组。
    /// 失败或返回空时由调用方回退到规则模式。
    async fn plan_goals_with_llm(
        &self,
        env: &EnvironmentModel,
        llm: &Arc<dyn LlmClient>,
    ) -> Result<Vec<AuditGoal>> {
        let prompt = self.build_goal_prompt(env);
        let text = llm.chat(&prompt).await?;
        let value = crate::agent::llm_client::extract_json_value(&text)?;

        // 兼容 LLM 直接返回数组或包装在 { "goals": [...] } 中
        let goals_value = if value.is_array() {
            value
        } else {
            value
                .get("goals")
                .cloned()
                .context("LLM 目标生成返回既不是数组也没有 goals 字段")?
        };

        let goals: Vec<AuditGoal> = serde_json::from_value(goals_value)
            .context("LLM 目标生成返回格式不符合 AuditGoal 数组")?;

        // 过滤并截断，避免 LLM 返回过多目标
        let mut goals: Vec<AuditGoal> = goals
            .into_iter()
            .filter(|g| !g.objective.is_empty())
            .take(self.config.max_goals)
            .collect();

        // 归一化优先级到 [0,1]
        for g in &mut goals {
            g.priority = g.priority.clamp(0.0, 1.0);
        }

        Ok(goals)
    }

    /// 构造 LLM 目标生成 prompt
    fn build_goal_prompt(&self, env: &EnvironmentModel) -> String {
        let mut vuln_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for f in &env.findings {
            *vuln_counts.entry(f.vuln_type.clone()).or_insert(0) += 1;
        }
        let mut top_vulns: Vec<(String, usize)> = vuln_counts.into_iter().collect();
        top_vulns.sort_by(|a, b| b.1.cmp(&a.1));
        let top_vulns: Vec<String> = top_vulns.into_iter().take(10).map(|(k, _)| k).collect();

        let entries = env.high_risk_unauthenticated_entries();
        let entry_summary: Vec<serde_json::Value> = entries
            .iter()
            .take(10)
            .map(|e| {
                serde_json::json!({
                    "file": e.file_path,
                    "route": e.route,
                    "method": e.http_method,
                    "auth_required": e.auth_required,
                })
            })
            .collect();

        let risk_summary: Vec<serde_json::Value> = env
            .risk_matches
            .iter()
            .take(10)
            .map(|r| {
                serde_json::json!({
                    "pattern": r.pattern_name,
                    "cwe": r.cwe,
                    "confidence": r.confidence,
                    "affected_files": r.affected_entries.iter().take(3).map(|e| &e.file_path).collect::<Vec<_>>(),
                })
            })
            .collect();

        let context = serde_json::json!({
            "total_findings": env.findings.len(),
            "entry_points": env.attack_surface.entry_points.len(),
            "unauthenticated_entries": entries.len(),
            "top_vulnerability_types": top_vulns,
            "entry_points_sample": entry_summary,
            "architecture_risks": risk_summary,
            "max_goals": self.config.max_goals,
        });

        format!(
            r#"你是一名资深安全审计架构师。请基于下方项目上下文，生成本次审计的 3-{} 个高价值审计目标。

要求：
1. 只返回单个 JSON 对象，不要 Markdown 代码块、不要解释、不要 trailing 字符。
2. JSON 必须包含一个 "goals" 数组，每个元素符合以下 schema：
{{
  "objective": "目标描述（中文）",
  "priority": 0.0-1.0,
  "target_vuln_types": ["CWE-89", "CWE-78", ...],
  "target_severities": ["critical", "high"],
  "focus_entry_points": ["src/main/java/..."],
  "max_findings": 20
}}
3. 优先关注：未认证入口可触发的注入类漏洞、架构风险模式、置信度低但影响大的 findings。
4. 若证据不足，可以返回空数组 []。
5. reasoning 字段使用中文，内容中不要出现未转义的双引号。

项目上下文：
{context}

请输出 JSON："#,
            self.config.max_goals,
            context = serde_json::to_string_pretty(&context).unwrap_or_default()
        )
    }

    /// 根据目标对 findings 重新排序并截断
    pub fn prioritize_findings(&self, env: &EnvironmentModel, goals: &[AuditGoal]) -> Vec<Finding> {
        if goals.is_empty() {
            return env.findings.clone();
        }

        let target_vuln_types: HashSet<String> = goals
            .iter()
            .flat_map(|g| g.target_vuln_types.clone())
            .collect();
        let target_severities: HashSet<String> = goals
            .iter()
            .flat_map(|g| g.target_severities.clone())
            .collect();
        let focus_files: HashSet<String> = goals
            .iter()
            .flat_map(|g| g.focus_entry_points.clone())
            .collect();

        let rank = |s: &str| match s.to_lowercase().as_str() {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            "info" => 4,
            _ => 5,
        };

        let mut filtered: Vec<Finding> = env
            .findings
            .iter()
            .filter(|f| !env.is_baselined(f))
            .filter(|f| {
                let severity_ok = target_severities.contains(&f.severity)
                    || target_severities
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case("*"));
                let vuln_ok = target_vuln_types.contains(&f.vuln_type)
                    || target_vuln_types
                        .iter()
                        .any(|v| v.eq_ignore_ascii_case("*"));
                severity_ok && vuln_ok
            })
            .cloned()
            .collect();

        filtered.sort_by(|a, b| {
            let in_focus_a = focus_files.contains(&a.file_path);
            let in_focus_b = focus_files.contains(&b.file_path);
            let risk_a = env.file_risk.get(&a.file_path).copied().unwrap_or(0);
            let risk_b = env.file_risk.get(&b.file_path).copied().unwrap_or(0);

            in_focus_b
                .cmp(&in_focus_a)
                .then_with(|| rank(&a.severity).cmp(&rank(&b.severity)))
                .then_with(|| risk_b.cmp(&risk_a))
        });

        let max = goals.iter().map(|g| g.max_findings).sum::<usize>().max(50);
        filtered.truncate(max);
        filtered
    }

    /// 是否全局收敛：所有目标相关的漏洞类型都已收敛
    pub async fn has_converged(&self, env: &EnvironmentModel) -> bool {
        let threshold = self.config.convergence_threshold;
        let vuln_types: HashSet<String> = env
            .findings
            .iter()
            .filter(|f| matches!(f.severity.to_lowercase().as_str(), "critical" | "high"))
            .map(|f| f.vuln_type.clone())
            .collect();

        if vuln_types.is_empty() {
            return true;
        }

        let mut all_converged = true;
        for vt in &vuln_types {
            if !env.has_converged(vt, threshold).await {
                all_converged = false;
                break;
            }
        }
        all_converged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::blackboard::BlackboardState;
    use crate::agent::environment::EnvironmentModel;
    use crate::agent::llm_client::{LlmClient, LlmTriageResult};
    use async_trait::async_trait;
    use deepaudit_core::scanning::Finding;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    fn mock_environment() -> EnvironmentModel {
        let mut findings = Vec::new();
        findings.push(Finding {
            finding_id: "f1".to_string(),
            file_path: "app.js".to_string(),
            line_start: 7,
            line_end: 7,
            detector: "test".to_string(),
            vuln_type: "CWE-94".to_string(),
            severity: "high".to_string(),
            description: "code injection".to_string(),
            analysis_trail: None,
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: None,
            sink_snippet: None,
            file_role: Some("production".to_string()),
            barriers: None,
            reasoning_hint: None,
            evidence_refs: None,
        });

        let mut surface = deepaudit_core::attack_surface::AttackSurface::default();
        surface
            .entry_points
            .push(deepaudit_core::attack_surface::EntryPoint {
                file_path: "app.js".to_string(),
                line: 4,
                entry_type: deepaudit_core::attack_surface::EntryType::HttpEndpoint,
                route: Some("/greet".to_string()),
                http_method: Some("GET".to_string()),
                auth_required: false,
                auth_mechanism: None,
                risk_score: 0.8,
                function_name: Some("handler".to_string()),
                context: deepaudit_core::attack_surface::EntryContext::default(),
            });
        surface.stats.total_entry_points = 1;
        surface.stats.unauthenticated_count = 1;
        surface.high_risk_files.push("app.js".to_string());

        let call_graph = Arc::new(deepaudit_core::CallGraphQueryEngine::new(
            Arc::new(deepaudit_core::taint::CallGraph::new()),
            deepaudit_core::analysis::type_hierarchy::TypeHierarchy::new(),
            deepaudit_core::analysis::middleware::MiddlewareModel::new(),
            HashMap::new(),
        ));

        EnvironmentModel {
            project_path: std::path::PathBuf::from("."),
            attack_surface: surface,
            risk_matches: Vec::new(),
            graph_stats: call_graph.query_graph_stats(),
            file_risk: [("app.js".to_string(), 11)].into_iter().collect(),
            baseline: HashSet::new(),
            blackboard: Arc::new(tokio::sync::RwLock::new(BlackboardState::new(
                "test".to_string(),
                ".".to_string(),
            ))),
            call_graph,
            findings,
            project_summary: crate::agent::environment::ProjectSummary {
                total_findings: 1,
                severity_counts: [("high".to_string(), 1)].into_iter().collect(),
                vuln_type_counts: [("CWE-94".to_string(), 1)].into_iter().collect(),
                detected_frameworks: vec!["Express".to_string()],
                total_entry_points: 1,
                unauthenticated_entry_points: 1,
                graph_total_nodes: 0,
                graph_taint_sources: 0,
                graph_taint_sinks: 0,
            },
        }
    }

    struct DummyLlm;

    #[async_trait]
    impl LlmClient for DummyLlm {
        async fn triage(
            &self,
            _finding: &Finding,
            _evidence: &crate::agent::evidence::Evidence,
        ) -> anyhow::Result<LlmTriageResult> {
            Ok(LlmTriageResult {
                verdict: crate::agent::heuristics::Verdict::NeedsReview,
                confidence: 0.5,
                reasoning: "dummy".to_string(),
                suggested_specialist: None,
            })
        }
    }

    #[tokio::test]
    async fn test_rule_based_planner_generates_injection_goal() {
        let env = mock_environment();
        let planner = StrategyPlanner::new(
            Arc::new(DummyLlm),
            PlannerConfig {
                strategy: PlannerStrategy::Rule,
                max_goals: 5,
                max_exploration_actions: 3,
                enable_proactive_scan: false,
                enable_reflection: true,
                convergence_threshold: 5.0,
                public_route_patterns:
                    deepaudit_core::analysis::attack_surface::default_public_route_patterns(),
                non_production_path_patterns:
                    deepaudit_core::analysis::attack_surface::default_non_production_path_patterns(),
            },
        );
        let goals = planner.plan_goals(&env).await;
        assert!(!goals.is_empty());
        let first = &goals[0];
        assert!(
            first.objective.contains("注入")
                || first.target_vuln_types.iter().any(|v| v.contains("CWE-94"))
        );
        assert!(!first.focus_entry_points.is_empty());
    }

    #[tokio::test]
    async fn test_prioritize_findings_focuses_on_goal() {
        let env = mock_environment();
        let planner = StrategyPlanner::new(
            Arc::new(DummyLlm),
            PlannerConfig {
                strategy: PlannerStrategy::Rule,
                max_goals: 5,
                max_exploration_actions: 3,
                enable_proactive_scan: false,
                enable_reflection: true,
                convergence_threshold: 5.0,
                public_route_patterns:
                    deepaudit_core::analysis::attack_surface::default_public_route_patterns(),
                non_production_path_patterns:
                    deepaudit_core::analysis::attack_surface::default_non_production_path_patterns(),
            },
        );
        let goals = planner.plan_goals(&env).await;
        let prioritized = planner.prioritize_findings(&env, &goals);
        assert!(!prioritized.is_empty());
        assert_eq!(prioritized[0].vuln_type, "CWE-94");
    }
}
