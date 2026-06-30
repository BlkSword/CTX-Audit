// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent Blackboard —— 共享状态与证据图谱
//!
//! 承载 session、investigation 结果、evidence graph 和 ACO pheromone，
//! 并持久化到 `.ctx-audit/blackboard.json`。
//!
//! ACO pheromone 采用 (source_type, sink_type, path_shape) 三元组作为 key，
//! 同时保留按漏洞类型的聚合值，用于全局收敛判定。

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent::evidence::Evidence;
use crate::agent::report::InvestigationResult;
use deepaudit_core::scanning::Finding;

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

    /// 根据 finding 与证据更新 pheromone（三元组 + 聚合）。
    pub fn update_pheromone(
        &mut self,
        finding: &Finding,
        evidence: &Evidence,
        verdict: &crate::agent::heuristics::Verdict,
    ) {
        let delta = match verdict {
            crate::agent::heuristics::Verdict::TruePositive => 1.0,
            crate::agent::heuristics::Verdict::FalsePositive => -1.0,
            crate::agent::heuristics::Verdict::NeedsReview => 0.2,
        };

        let key = PheromoneKey::from_finding_evidence(finding, evidence);
        let triplet_key = key.to_string();

        // 更新三元组信息素
        let triplet_entry = self
            .pheromone
            .triplet_entries
            .entry(triplet_key)
            .or_insert(0.0);
        *triplet_entry += delta;
        *triplet_entry = triplet_entry.clamp(-10.0, 10.0);

        // 更新按漏洞类型的聚合信息素
        let aggregate_key = finding.vuln_type.clone();
        let aggregate_entry = self
            .pheromone
            .entries
            .entry(aggregate_key.clone())
            .or_insert(0.0);
        *aggregate_entry += delta;
        *aggregate_entry = aggregate_entry.clamp(-10.0, 10.0);

        // 收敛判定：聚合值连续同向超过阈值时标记
        let threshold = 5.0;
        if *aggregate_entry >= threshold {
            self.convergence_state
                .insert(aggregate_key, ConvergenceStatus::TruePositive);
        } else if *aggregate_entry <= -threshold {
            self.convergence_state
                .insert(aggregate_key, ConvergenceStatus::FalsePositive);
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

    /// 判断某个三元组是否已收敛
    pub fn has_triplet_converged(&self, key: &PheromoneKey, threshold: f64) -> bool {
        self.pheromone
            .triplet_entries
            .get(&key.to_string())
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

/// ACO pheromone 表
/// entries: 按漏洞类型聚合的信息素
/// triplet_entries: 按 (source_type, sink_type, path_shape) 三元组细分的信息素
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PheromoneTable {
    pub entries: HashMap<String, f64>,
    #[serde(default)]
    pub triplet_entries: HashMap<String, f64>,
}

/// ACO 信息素三元组 key
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PheromoneKey {
    pub vuln_type: String,
    pub source_type: String,
    pub sink_type: String,
    pub path_shape: String,
}

impl PheromoneKey {
    pub fn new(
        vuln_type: impl Into<String>,
        source_type: impl Into<String>,
        sink_type: impl Into<String>,
        path_shape: impl Into<String>,
    ) -> Self {
        Self {
            vuln_type: vuln_type.into(),
            source_type: source_type.into(),
            sink_type: sink_type.into(),
            path_shape: path_shape.into(),
        }
    }

    /// 从 finding 与证据中派生三元组 key
    pub fn from_finding_evidence(finding: &Finding, evidence: &Evidence) -> Self {
        let source_type = classify_source(finding, evidence);
        let sink_type = classify_sink(finding, evidence);
        let path_shape = classify_path_shape(evidence);
        Self::new(&finding.vuln_type, source_type, sink_type, path_shape)
    }
}

impl fmt::Display for PheromoneKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}|{}|{}|{}",
            self.vuln_type, self.source_type, self.sink_type, self.path_shape
        )
    }
}

fn classify_source(finding: &Finding, _evidence: &Evidence) -> String {
    let text = source_text(finding).to_lowercase();
    if text.contains("req")
        || text.contains("request")
        || text.contains("param")
        || text.contains("query")
        || text.contains("body")
        || text.contains("header")
        || text.contains("cookie")
        || text.contains("form")
        || text.contains("input")
    {
        "http_input".to_string()
    } else if text.contains("file") || text.contains("fs") || text.contains("read") {
        "file_input".to_string()
    } else if text.contains("db") || text.contains("database") || text.contains("sql") {
        "db_input".to_string()
    } else if text.contains("env") || text.contains("process.env") {
        "env_input".to_string()
    } else {
        "other".to_string()
    }
}

fn classify_sink(finding: &Finding, _evidence: &Evidence) -> String {
    let text = sink_text(finding).to_lowercase();
    if text.contains("exec")
        || text.contains("spawn")
        || text.contains("eval")
        || text.contains("function")
    {
        "code_exec".to_string()
    } else if text.contains("query")
        || text.contains("execute")
        || text.contains("raw")
        || text.contains("sequelize")
        || text.contains("mongoose")
    {
        "sql_query".to_string()
    } else if text.contains("innerhtml")
        || text.contains("write")
        || text.contains("send")
        || text.contains("html")
        || text.contains("render")
    {
        "html_sink".to_string()
    } else if text.contains("redirect") || text.contains("open") || text.contains("fetch") {
        "network".to_string()
    } else {
        "other".to_string()
    }
}

fn classify_path_shape(evidence: &Evidence) -> String {
    if evidence.has_effective_sanitizer {
        return "sanitized".to_string();
    }
    if !evidence.barriers.is_empty() {
        return "barrier".to_string();
    }
    if evidence.call_path.is_some() {
        return "tracked".to_string();
    }
    "unknown".to_string()
}

fn source_text(finding: &Finding) -> String {
    finding
        .source_snippet
        .clone()
        .or_else(|| {
            finding
                .analysis_trail
                .as_ref()
                .and_then(|t| t.first().cloned())
        })
        .or_else(|| {
            finding.evidence_refs.as_ref().and_then(|e| {
                e.source_sink_path
                    .as_ref()
                    .map(|p| p.source_function.clone())
            })
        })
        .unwrap_or_default()
}

fn sink_text(finding: &Finding) -> String {
    finding
        .sink_snippet
        .clone()
        .or_else(|| {
            finding
                .analysis_trail
                .as_ref()
                .and_then(|t| t.last().cloned())
        })
        .or_else(|| {
            finding
                .evidence_refs
                .as_ref()
                .and_then(|e| e.source_sink_path.as_ref().map(|p| p.sink_function.clone()))
        })
        .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::heuristics::Verdict;

    #[test]
    fn test_pheromone_triplet_update_and_convergence() {
        let mut bb = BlackboardState::new("s1".to_string(), "/tmp/p".to_string());
        let finding = Finding {
            finding_id: "f1".to_string(),
            file_path: "a.js".to_string(),
            line_start: 1,
            line_end: 1,
            detector: "test".to_string(),
            vuln_type: "SQL Injection".to_string(),
            severity: "high".to_string(),
            description: "test".to_string(),
            analysis_trail: None,
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: None,
            sink_snippet: None,
            file_role: None,
            barriers: None,
            reasoning_hint: None,
            evidence_refs: None,
        };
        let evidence = Evidence::default();

        for _ in 0..6 {
            bb.update_pheromone(&finding, &evidence, &Verdict::TruePositive);
        }

        assert!(bb.has_converged("SQL Injection", 5.0));

        let key = PheromoneKey::from_finding_evidence(&finding, &evidence);
        assert!(bb.has_triplet_converged(&key, 5.0));
        assert_eq!(key.source_type, "other");
        assert_eq!(key.sink_type, "other");
        assert_eq!(key.path_shape, "unknown");
    }

    #[test]
    fn test_pheromone_triplet_false_positive_convergence() {
        let mut bb = BlackboardState::new("s2".to_string(), "/tmp/p".to_string());
        let finding = Finding {
            finding_id: "f2".to_string(),
            file_path: "b.js".to_string(),
            line_start: 2,
            line_end: 2,
            detector: "test".to_string(),
            vuln_type: "XSS".to_string(),
            severity: "high".to_string(),
            description: "test".to_string(),
            analysis_trail: None,
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: Some("req.query.name".to_string()),
            sink_snippet: Some("res.send".to_string()),
            file_role: None,
            barriers: None,
            reasoning_hint: None,
            evidence_refs: None,
        };
        let evidence = Evidence {
            call_path: Some(deepaudit_core::CallPath {
                steps: vec![],
                total_hops: 0,
                crosses_files: false,
                files_in_path: vec![],
            }),
            ..Evidence::default()
        };

        for _ in 0..6 {
            bb.update_pheromone(&finding, &evidence, &Verdict::FalsePositive);
        }

        let key = PheromoneKey::from_finding_evidence(&finding, &evidence);
        assert!(bb.has_triplet_converged(&key, 5.0));
        assert_eq!(key.source_type, "http_input");
        assert_eq!(key.sink_type, "html_sink");
        assert_eq!(key.path_shape, "tracked");
    }
}
