// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent Blackboard —— 共享状态与证据图谱
//!
//! 承载 session、investigation 结果、evidence graph 和 ACO pheromone，
//! 并持久化到 `.ctx-audit/blackboard.json`。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent::report::InvestigationResult;

/// Blackboard 状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackboardState {
    pub session_id: String,
    pub project_path: String,
    pub started_at: String,
    pub investigations: Vec<BlackboardInvestigation>,
    pub evidence_graph: EvidenceGraph,
    pub pheromone: PheromoneTable,
    pub convergence_state: HashMap<String, ConvergenceStatus>,
}

impl BlackboardState {
    pub fn new(session_id: String, project_path: String) -> Self {
        Self {
            session_id,
            project_path,
            started_at: chrono::Utc::now().to_rfc3339(),
            investigations: Vec::new(),
            evidence_graph: EvidenceGraph::default(),
            pheromone: PheromoneTable::default(),
            convergence_state: HashMap::new(),
        }
    }

    /// 添加一个调查结果
    pub fn add_investigation(&mut self, inv: &InvestigationResult) {
        self.investigations.push(BlackboardInvestigation::from(inv));
    }

    /// 更新某类漏洞的 pheromone（ACO 收敛）
    pub fn update_pheromone(
        &mut self,
        vuln_type: &str,
        verdict: &crate::agent::heuristics::Verdict,
    ) {
        let delta = match verdict {
            crate::agent::heuristics::Verdict::TruePositive => 1.0,
            crate::agent::heuristics::Verdict::FalsePositive => -1.0,
            crate::agent::heuristics::Verdict::NeedsReview => 0.2,
        };
        let key = vuln_type.to_string();
        let entry = self.pheromone.entries.entry(key.clone()).or_insert(0.0);
        *entry += delta;
        // 限制在 [-10.0, 10.0] 避免极端值
        *entry = entry.clamp(-10.0, 10.0);

        // 收敛判定：连续同向超过阈值时标记
        let threshold = 5.0;
        if *entry >= threshold {
            self.convergence_state
                .insert(key, ConvergenceStatus::TruePositive);
        } else if *entry <= -threshold {
            self.convergence_state
                .insert(key, ConvergenceStatus::FalsePositive);
        }
    }

    /// 判断某类漏洞是否已收敛（连续同向判定达到阈值）
    pub fn has_converged(&self, vuln_type: &str, threshold: f64) -> bool {
        self.pheromone
            .entries
            .get(vuln_type)
            .map(|v| v.abs() >= threshold)
            .unwrap_or(false)
    }

    /// 保存到 <project_path>/.ctx-audit/blackboard.json
    pub fn save(&self, project_path: &Path) -> Result<()> {
        let dir = project_path.join(".ctx-audit");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("blackboard.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(self).context("序列化 Blackboard 失败")?,
        )
        .with_context(|| format!("写入 Blackboard 失败: {}", path.display()))?;
        Ok(())
    }

    /// 从 <project_path>/.ctx-audit/blackboard.json 加载
    pub fn load(project_path: &Path) -> Option<Self> {
        let path = project_path.join(".ctx-audit").join("blackboard.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlackboardInvestigation {
    pub investigation_id: String,
    pub finding_id: String,
    pub file_path: String,
    pub line: usize,
    pub vulnerability_type: String,
    pub severity: String,
    pub verdict: String,
    pub reasoning: String,
    pub audited_at: String,
}

impl From<&InvestigationResult> for BlackboardInvestigation {
    fn from(inv: &InvestigationResult) -> Self {
        Self {
            investigation_id: inv.investigation_id.clone(),
            finding_id: inv.finding_id.clone(),
            file_path: inv.file_path.clone(),
            line: inv.line,
            vulnerability_type: inv.vulnerability_type.clone(),
            severity: inv.severity.clone(),
            verdict: inv.verdict.as_str().to_string(),
            reasoning: inv.reasoning.clone(),
            audited_at: inv.audited_at.clone(),
        }
    }
}

/// 证据图谱（为后续 cross-finding 分析预留）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub nodes: Vec<EvidenceNode>,
    pub edges: Vec<EvidenceEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceNode {
    pub id: String,
    pub kind: String,
    pub file_path: String,
    pub line: usize,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

/// ACO pheromone 表（为后续收敛判定预留）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PheromoneTable {
    pub entries: HashMap<String, f64>,
}

/// 收敛状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConvergenceStatus {
    /// 尚未收敛
    Open,
    /// 已确认为真阳性模式
    TruePositive,
    /// 已确认为误报模式
    FalsePositive,
}

impl Default for ConvergenceStatus {
    fn default() -> Self {
        ConvergenceStatus::Open
    }
}
