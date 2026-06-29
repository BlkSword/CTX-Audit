// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! RuleBasedPlanner —— 确定性计划生成器
//!
//! 无需 LLM，根据 AuditGoal 和 EnvironmentModel 直接生成 Action 序列。

use anyhow::Result;
use async_trait::async_trait;

use crate::agent::environment::EnvironmentModel;
use crate::agent::planner::{Action, AuditGoal, Plan, Planner};
use deepaudit_core::analysis::attack_surface::is_public_route_with_patterns;

/// 基于规则的计划器
pub struct RuleBasedPlanner {
    max_exploration_actions: usize,
    public_route_patterns: Vec<String>,
}

impl RuleBasedPlanner {
    pub fn new(max_exploration_actions: usize, public_route_patterns: Vec<String>) -> Self {
        Self {
            max_exploration_actions: max_exploration_actions.max(1),
            public_route_patterns,
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
        // 跳过设计上公开的端点（登录/注册/健康检查等），避免在无风险入口上浪费行动
        let focus_entries = if goal.focus_entry_points.is_empty() {
            env.high_risk_unauthenticated_entries()
                .into_iter()
                .filter(|e| {
                    !e.route
                        .as_deref()
                        .map(|r| is_public_route_with_patterns(r, &self.public_route_patterns))
                        .unwrap_or(false)
                })
                .take(self.max_exploration_actions)
                .map(|e| {
                    (
                        e.file_path.clone(),
                        e.function_name.clone(),
                        e.route.clone(),
                    )
                })
                .collect::<Vec<_>>()
        } else {
            let focus: std::collections::HashSet<String> =
                goal.focus_entry_points.iter().cloned().collect();
            env.attack_surface
                .entry_points
                .iter()
                .filter(|e| {
                    focus.contains(&e.file_path)
                        && !e
                            .route
                            .as_deref()
                            .map(|r| is_public_route_with_patterns(r, &self.public_route_patterns))
                            .unwrap_or(false)
                })
                .take(self.max_exploration_actions)
                .map(|e| {
                    (
                        e.file_path.clone(),
                        e.function_name.clone(),
                        e.route.clone(),
                    )
                })
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

        // 3. 架构风险目标：VerifyHypothesis（中间件 + 调用者组合验证）
        //
        // 当前工具只能拿到全局调用图统计和文件级中间件信息，无法定位到
        // "具体哪个路由缺少 schema 校验 / 哪个特权操作可被未认证访问"，会持续
        // 产生无证据支持的抽象误报。暂时禁用，待后续引入 route-level 中间件
        // 与特权操作查询后再恢复。
        //
        // let has_call_graph = env.graph_stats.total_nodes > 0;
        // let has_concrete_entry_points = !goal.focus_entry_points.is_empty();
        // if has_call_graph
        //     && has_concrete_entry_points
        //     && goal.objective.contains("架构风险")
        // {
        //     actions.push(Action::VerifyHypothesis { ... });
        // }

        Ok(Plan {
            goal: goal.clone(),
            actions,
        })
    }
}
