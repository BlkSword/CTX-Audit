// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LlmBasedPlanner —— 使用 LLM 生成审计行动计划
//!
//! 设计为“谨慎落地”：仅在配置为 llm 策略且 LLM 可用时调用；
//! 任何解析失败、超时或空结果都会安全回退到 RuleBasedPlanner，
//! 确保审计流程不依赖外部 LLM 也能稳定完成。

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::agent::environment::EnvironmentModel;
use crate::agent::llm_client::LlmClient;
use crate::agent::planner::rule_based::RuleBasedPlanner;
use crate::agent::planner::{Action, AuditGoal, Plan, Planner};

/// 基于 LLM 的计划器
pub struct LlmBasedPlanner {
    llm_client: Arc<dyn LlmClient>,
    fallback: RuleBasedPlanner,
    max_actions: usize,
}

impl LlmBasedPlanner {
    pub fn new(
        llm_client: Arc<dyn LlmClient>,
        fallback: RuleBasedPlanner,
        max_actions: usize,
    ) -> Self {
        Self {
            llm_client,
            fallback,
            max_actions: max_actions.max(1),
        }
    }

    fn build_prompt(&self, env: &EnvironmentModel, goal: &AuditGoal) -> String {
        const JSON_EXAMPLE: &str = r#"{"actions": [{"action": "InvestigateFinding", "params": {"finding_id": "f1", "file_path": "a.js", "line": 10, "vuln_type": "SQL Injection", "hypothesis": "h"}}]}"#;
        const EMPTY_ACTIONS: &str = r#"{"actions": []}"#;

        let findings_summary: Vec<String> = env
            .findings_for_goal(goal)
            .into_iter()
            .take(20)
            .map(|f| {
                format!(
                    "- {} {} at {}:{} ({})",
                    f.severity, f.vuln_type, f.file_path, f.line_start, f.finding_id
                )
            })
            .collect();

        let entries_summary: Vec<String> = env
            .high_risk_unauthenticated_entries()
            .into_iter()
            .take(10)
            .map(|e| {
                format!(
                    "- {}:{} route={} score={:.2}",
                    e.file_path,
                    e.line,
                    e.route.as_deref().unwrap_or("-"),
                    e.risk_score
                )
            })
            .collect();

        format!(
            "你是一个代码审计规划助手。请根据以下审计目标和项目环境，生成一个 JSON 行动计划。\
只返回 JSON，不要包含解释。JSON 格式为 {json_example}。\
允许的 action 类型：InvestigateFinding、ExploreEntryPoint、VerifyHypothesis。\
如果无法生成可靠计划，返回空数组 {empty_actions}。\n\n\
审计目标：{objective}\n\
关注漏洞类型：{vuln_types:?}\n\
关注严重度：{severities:?}\n\
相关 findings（最多 20 条）：\n{findings}\n\
高风险未认证入口点（最多 10 个）：\n{entries}\n",
            json_example = JSON_EXAMPLE,
            empty_actions = EMPTY_ACTIONS,
            objective = goal.objective,
            vuln_types = goal.target_vuln_types,
            severities = goal.target_severities,
            findings = findings_summary.join("\n"),
            entries = entries_summary.join("\n"),
        )
    }

    async fn plan_with_llm(&self, env: &EnvironmentModel, goal: &AuditGoal) -> Result<Vec<Action>> {
        let prompt = self.build_prompt(env, goal);
        let value = self.llm_client.chat_json(&prompt).await?;
        parse_llm_value(&value, self.max_actions)
    }
}

/// 解析 LLM 返回的 JSON Value
fn parse_llm_value(value: &serde_json::Value, max_actions: usize) -> Result<Vec<Action>> {
    let actions = value
        .get("actions")
        .and_then(|v| v.as_array())
        .context("JSON 中缺少 actions 数组")?;

    let mut parsed = Vec::new();
    for a in actions {
        if let Ok(action) = serde_json::from_value::<Action>(a.clone()) {
            parsed.push(action);
        } else {
            tracing::debug!("LLM 返回了无法解析的行动: {:?}", a);
        }
    }

    parsed.truncate(max_actions.max(1));
    Ok(parsed)
}

#[async_trait]
impl Planner for LlmBasedPlanner {
    async fn plan(&self, env: &EnvironmentModel, goal: &AuditGoal) -> Result<Plan> {
        match self.plan_with_llm(env, goal).await {
            Ok(actions) if !actions.is_empty() => Ok(Plan {
                goal: goal.clone(),
                actions,
            }),
            Ok(_) => {
                tracing::info!("LLM 计划器返回空计划，回退到规则计划器");
                self.fallback.plan(env, goal).await
            }
            Err(e) => {
                tracing::warn!("LLM 计划器失败，回退到规则计划器: {}", e);
                self.fallback.plan(env, goal).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_llm_value_valid() {
        let value: serde_json::Value = serde_json::from_str(r#"{"actions": [{"action": "InvestigateFinding", "params": {"finding_id": "f1", "file_path": "a.js", "line": 10, "vuln_type": "SQL Injection", "hypothesis": "h"}}]}"#).unwrap();
        let actions = parse_llm_value(&value, 5).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::InvestigateFinding {
                finding_id,
                file_path,
                ..
            } => {
                assert_eq!(finding_id, "f1");
                assert_eq!(file_path, "a.js");
            }
            _ => panic!("expected InvestigateFinding"),
        }
    }

    #[test]
    fn test_parse_llm_value_empty() {
        let value: serde_json::Value = serde_json::from_str(r#"{"actions": []}"#).unwrap();
        let actions = parse_llm_value(&value, 5).unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_extract_json_from_markdown() {
        let text = "```json
{\"actions\": []}
```";
        let value = crate::agent::llm_client::extract_json_value(text).unwrap();
        let actions = parse_llm_value(&value, 5).unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_parse_llm_value_missing_actions() {
        let value: serde_json::Value = serde_json::from_str(r#"{"other": []}"#).unwrap();
        assert!(parse_llm_value(&value, 5).is_err());
    }
}
