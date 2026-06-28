// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 计划层 —— 把审计目标展开为可执行的行动序列

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::agent::environment::EnvironmentModel;
use crate::agent::heuristics::Verdict;

pub mod executor;
pub mod rule_based;
pub mod strategy;

/// 审计目标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditGoal {
    pub objective: String,
    pub priority: f64,
    pub target_vuln_types: Vec<String>,
    pub target_severities: Vec<String>,
    pub focus_entry_points: Vec<String>,
    pub max_findings: usize,
}

impl AuditGoal {
    /// 创建通用高优先级目标
    pub fn high_priority(objective: impl Into<String>, vuln_type: impl Into<String>) -> Self {
        Self {
            objective: objective.into(),
            priority: 1.0,
            target_vuln_types: vec![vuln_type.into()],
            target_severities: vec!["critical".to_string(), "high".to_string()],
            focus_entry_points: Vec::new(),
            max_findings: 20,
        }
    }
}

/// 工具调用描述
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub input: serde_json::Value,
    pub purpose: String,
}

/// 架构级假设
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub statement: String,
    pub evidence_so_far: Vec<String>,
    pub confidence: f64,
}

/// 可执行行动
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", content = "params")]
pub enum Action {
    /// 对单个 finding 展开调查
    InvestigateFinding {
        finding_id: String,
        file_path: String,
        line: usize,
        vuln_type: String,
        hypothesis: String,
    },
    /// 主动探索某个入口点
    ExploreEntryPoint {
        file_path: String,
        function_name: Option<String>,
        route: Option<String>,
        reason: String,
    },
    /// 用一组工具验证假设
    VerifyHypothesis {
        hypothesis: Hypothesis,
        tools: Vec<ToolCall>,
    },
    /// 动态生成规则并重扫描（ proactive 能力）
    ReScanWithRule {
        rule_yaml: String,
        rule_name: String,
    },
    /// 直接报告发现（由探索产生的新 finding）
    ReportFinding {
        file_path: String,
        line: usize,
        vuln_type: String,
        severity: String,
        description: String,
        verdict: Verdict,
        reasoning: String,
    },
}

/// 计划：一个目标 + 行动序列
#[derive(Debug, Clone)]
pub struct Plan {
    pub goal: AuditGoal,
    pub actions: Vec<Action>,
}

/// Planner trait
#[async_trait]
pub trait Planner: Send + Sync {
    async fn plan(&self, env: &EnvironmentModel, goal: &AuditGoal) -> Result<Plan>;
}

/// 把行动序列序列化为 audit_log / report 可读的 JSON
pub fn actions_to_json(actions: &[Action]) -> Vec<serde_json::Value> {
    actions
        .iter()
        .map(|a| match serde_json::to_value(a) {
            Ok(v) => v,
            Err(_) => serde_json::json!({"error": "无法序列化行动"}),
        })
        .collect()
}

/// 简单元数据：记录计划执行结果
#[derive(Debug, Clone, Default)]
pub struct PlanExecutionMetadata {
    pub actions_total: usize,
    pub actions_completed: usize,
    pub actions_failed: usize,
    pub new_findings: usize,
}
