// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! RuleBasedPlanner —— 确定性计划生成器
//!
//! 无需 LLM，根据 AuditGoal 和 EnvironmentModel 直接生成 Action 序列。

use anyhow::Result;
use async_trait::async_trait;

use crate::agent::environment::EnvironmentModel;
use crate::agent::planner::{Action, AuditGoal, Hypothesis, Plan, Planner, ToolCall};

/// 基于规则的计划器
pub struct RuleBasedPlanner {
    max_exploration_actions: usize,
}

impl RuleBasedPlanner {
    pub fn new(max_exploration_actions: usize) -> Self {
        Self {
            max_exploration_actions: max_exploration_actions.max(1),
        }
    }
}

#[async_trait]
impl Planner for RuleBasedPlanner {
    async fn plan(&self, env: &EnvironmentModel, goal: &AuditGoal) -> Result<Plan> {
        let mut actions = Vec::new();

        // 1. 把目标相关的 findings 映射为 InvestigateFinding
        let related = env.findings_for_goal(goal);
        let limit = goal.max_findings.min(related.len());
        for f in related.iter().take(limit) {
            actions.push(Action::InvestigateFinding {
                finding_id: f.finding_id.clone(),
                file_path: f.file_path.clone(),
                line: f.line_start,
                vuln_type: f.vuln_type.clone(),
                hypothesis: format!(
                    "{} 在 {}:{} 被报告为 {}。假设：用户可控输入能够未经充分净化到达该危险操作。",
                    f.vuln_type, f.file_path, f.line_start, f.description
                ),
            });
        }

        // 2. 对关注入口点生成 ExploreEntryPoint
        let focus_entries = if goal.focus_entry_points.is_empty() {
            env.high_risk_unauthenticated_entries()
                .into_iter()
                .take(self.max_exploration_actions)
                .map(|e| (e.file_path.clone(), e.function_name.clone(), e.route.clone()))
                .collect::<Vec<_>>()
        } else {
            let focus: std::collections::HashSet<String> =
                goal.focus_entry_points.iter().cloned().collect();
            env.attack_surface
                .entry_points
                .iter()
                .filter(|e| focus.contains(&e.file_path))
                .take(self.max_exploration_actions)
                .map(|e| (e.file_path.clone(), e.function_name.clone(), e.route.clone()))
                .collect::<Vec<_>>()
        };

        for (file, function, route) in focus_entries {
            actions.push(Action::ExploreEntryPoint {
                file_path: file,
                function_name: function,
                route,
                reason: format!(
                    "目标「{}」要求关注入口点，主动追踪其可达的敏感操作。",
                    goal.objective
                ),
            });
        }

        // 3. 架构风险目标：增加 VerifyHypothesis（中间件 + 调用者组合验证）
        if goal.objective.contains("架构风险") || goal.objective.contains("认证") {
            actions.push(Action::VerifyHypothesis {
                hypothesis: Hypothesis {
                    statement: format!("{} 存在可被利用的安全问题", goal.objective),
                    evidence_so_far: Vec::new(),
                    confidence: 0.5,
                },
                tools: vec![
                    ToolCall {
                        tool_name: "get_graph_stats".to_string(),
                        input: serde_json::json!({}),
                        purpose: "了解调用图规模与 source/sink 分布".to_string(),
                    },
                    ToolCall {
                        tool_name: "query_middleware_chain".to_string(),
                        input: serde_json::json!({
                            "file_path": goal.focus_entry_points.first().cloned().unwrap_or_default()
                        }),
                        purpose: "检查入口点是否被认证中间件覆盖".to_string(),
                    },
                ],
            });
        }

        Ok(Plan {
            goal: goal.clone(),
            actions,
        })
    }
}
