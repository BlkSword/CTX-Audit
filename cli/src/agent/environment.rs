// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 环境模型 —— 把项目全局状态聚合为统一的感知上下文
//!
//! 整合攻击面、架构风险模式、调用图统计、历史 Blackboard、基线与扫描结果，
//! 为 StrategyPlanner / Planner / Investigator 提供环境感知能力。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;

use deepaudit_core::attack_surface::{
    AttackSurface, AttackSurfaceMapper, EntryPoint, RiskPatternMatch, RiskPatternScanner,
};
use deepaudit_core::scanning::{Finding, ScanResult};
use deepaudit_core::{CallGraphQueryEngine, GraphStats};
use tokio::sync::RwLock;

use crate::agent::blackboard::BlackboardState;

/// 项目摘要
#[derive(Debug, Clone)]
pub struct ProjectSummary {
    pub total_findings: usize,
    pub severity_counts: HashMap<String, usize>,
    pub vuln_type_counts: HashMap<String, usize>,
    pub detected_frameworks: Vec<String>,
    pub total_entry_points: usize,
    pub unauthenticated_entry_points: usize,
    pub graph_total_nodes: usize,
    pub graph_taint_sources: usize,
    pub graph_taint_sinks: usize,
}

/// 环境模型：Agent 对项目的统一认知
#[derive(Clone)]
pub struct EnvironmentModel {
    pub project_path: PathBuf,
    pub attack_surface: AttackSurface,
    pub risk_matches: Vec<RiskPatternMatch>,
    pub graph_stats: GraphStats,
    pub file_risk: HashMap<String, i32>,
    pub baseline: HashSet<String>,
    pub blackboard: Arc<RwLock<BlackboardState>>,
    pub call_graph: Arc<CallGraphQueryEngine>,
    pub findings: Vec<Finding>,
    pub project_summary: ProjectSummary,
}

impl std::fmt::Debug for EnvironmentModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvironmentModel")
            .field("project_path", &self.project_path)
            .field("findings", &self.findings.len())
            .field("entry_points", &self.attack_surface.entry_points.len())
            .field("risk_matches", &self.risk_matches.len())
            .field("graph_stats", &self.graph_stats)
            .finish()
    }
}

impl EnvironmentModel {
    /// 从扫描结果与项目路径构建环境模型
    pub async fn build(
        project_path: impl Into<PathBuf>,
        _scan_result: &ScanResult,
        findings: Vec<Finding>,
        baseline: HashSet<String>,
        call_graph: Arc<CallGraphQueryEngine>,
    ) -> Result<Self> {
        let project_path = project_path.into();

        // 1. 攻击面映射
        let attack_surface = AttackSurfaceMapper::map_project(&project_path);

        // 2. 架构风险模式
        let risk_scanner = RiskPatternScanner::new(&project_path);
        let risk_matches = risk_scanner.scan(&attack_surface, &project_path);

        // 3. 调用图统计
        let graph_stats = call_graph.query_graph_stats();

        // 4. 文件风险评分
        let file_risk = compute_file_risk(&attack_surface);

        // 5. 加载历史 Blackboard 并合并 pheromone / evidence graph
        let blackboard = match BlackboardState::load(&project_path) {
            Some(mut historical) => {
                // 开启新 session，但保留历史学习状态
                historical.session_id = String::new();
                historical.project_path = project_path.to_string_lossy().to_string();
                Arc::new(RwLock::new(historical))
            }
            None => Arc::new(RwLock::new(BlackboardState::new(
                String::new(),
                project_path.to_string_lossy().to_string(),
            ))),
        };

        let project_summary = build_project_summary(&findings, &attack_surface, &graph_stats);

        Ok(Self {
            project_path,
            attack_surface,
            risk_matches,
            graph_stats,
            file_risk,
            baseline,
            blackboard,
            call_graph,
            findings,
            project_summary,
        })
    }

    /// 某 finding 是否被基线抑制
    pub fn is_baselined(&self, finding: &Finding) -> bool {
        let key = format!(
            "{}:{}:{}",
            finding.file_path, finding.line_start, finding.vuln_type
        );
        self.baseline.contains(&key)
    }

    /// 获取未认证且高风险的入口点（按风险评分降序）
    pub fn high_risk_unauthenticated_entries(&self) -> Vec<&EntryPoint> {
        let mut entries: Vec<&EntryPoint> = self
            .attack_surface
            .entry_points
            .iter()
            .filter(|ep| !ep.auth_required && ep.risk_score >= 0.5)
            .collect();
        entries.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
        entries
    }

    /// 按漏洞类型聚合 findings
    pub fn findings_by_vuln_type(&self, vuln_type: &str) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.vuln_type == vuln_type)
            .collect()
    }

    /// 按目标过滤 findings
    pub fn findings_for_goal(&self, goal: &crate::agent::planner::AuditGoal) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| {
                let severity_match = goal
                    .target_severities
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&f.severity));
                let vuln_match = goal
                    .target_vuln_types
                    .iter()
                    .any(|v| f.vuln_type.contains(v) || v.eq_ignore_ascii_case("*"));
                severity_match && vuln_match && !self.is_baselined(f)
            })
            .collect()
    }

    /// 判断某类漏洞是否已收敛（历史 Blackboard 信息素绝对值超过阈值）
    pub async fn has_converged(&self, vuln_type: &str, threshold: f64) -> bool {
        let bb = self.blackboard.read().await;
        bb.has_converged(vuln_type, threshold)
    }

    /// 序列化为 LLM prompt 可用的结构化摘要
    pub fn to_prompt_summary(&self) -> String {
        let mut s = String::new();
        s.push_str("# 项目环境摘要\n\n");
        s.push_str(&format!(
            "- 项目路径: {}\n",
            self.project_path.to_string_lossy()
        ));
        s.push_str(&format!(
            "- 总 findings: {}\n",
            self.project_summary.total_findings
        ));
        s.push_str(&format!(
            "- 严重度分布: {:?}\n",
            self.project_summary.severity_counts
        ));
        s.push_str(&format!(
            "- 检测框架: {}\n",
            self.project_summary.detected_frameworks.join(", ")
        ));
        s.push_str(&format!(
            "- 入口点: {} 个（未认证 {} 个）\n",
            self.project_summary.total_entry_points,
            self.project_summary.unauthenticated_entry_points
        ));
        s.push_str(&format!(
            "- 调用图: {} 节点, {} source, {} sink\n",
            self.project_summary.graph_total_nodes,
            self.project_summary.graph_taint_sources,
            self.project_summary.graph_taint_sinks
        ));
        s.push_str(&format!(
            "- 架构风险模式命中: {}\n",
            self.risk_matches.len()
        ));
        if !self.risk_matches.is_empty() {
            s.push_str("\n## 主要架构风险\n");
            for m in self.risk_matches.iter().take(10) {
                s.push_str(&format!(
                    "- {} (confidence={:.2}): {}\n",
                    m.pattern_name, m.confidence, m.pattern_id
                ));
            }
        }
        if !self.high_risk_unauthenticated_entries().is_empty() {
            s.push_str("\n## 高风险未认证入口点\n");
            for ep in self.high_risk_unauthenticated_entries().iter().take(10) {
                s.push_str(&format!(
                    "- {}:{} score={:.2} route={} type={:?}\n",
                    ep.file_path,
                    ep.line,
                    ep.risk_score,
                    ep.route.as_deref().unwrap_or("-"),
                    ep.entry_type
                ));
            }
        }
        s
    }
}

fn compute_file_risk(surface: &AttackSurface) -> HashMap<String, i32> {
    let mut risk: HashMap<String, i32> = HashMap::new();
    for file in &surface.high_risk_files {
        *risk.entry(file.clone()).or_insert(0) += 10;
    }
    for ep in &surface.entry_points {
        *risk.entry(ep.file_path.clone()).or_insert(0) += 1;
    }
    risk
}

fn build_project_summary(
    findings: &[Finding],
    surface: &AttackSurface,
    stats: &GraphStats,
) -> ProjectSummary {
    let mut severity_counts: HashMap<String, usize> = HashMap::new();
    let mut vuln_type_counts: HashMap<String, usize> = HashMap::new();
    for f in findings {
        *severity_counts.entry(f.severity.clone()).or_insert(0) += 1;
        *vuln_type_counts.entry(f.vuln_type.clone()).or_insert(0) += 1;
    }

    let mut frameworks = surface.stats.detected_frameworks.clone();
    frameworks.sort();
    frameworks.dedup();

    ProjectSummary {
        total_findings: findings.len(),
        severity_counts,
        vuln_type_counts,
        detected_frameworks: frameworks,
        total_entry_points: surface.stats.total_entry_points,
        unauthenticated_entry_points: surface.stats.unauthenticated_count,
        graph_total_nodes: stats.total_nodes,
        graph_taint_sources: stats.taint_sources,
        graph_taint_sinks: stats.taint_sinks,
    }
}
