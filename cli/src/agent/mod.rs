// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 本地审计 Agent —— 自动执行 SURVEY → HYPOTHESIZE → VERIFY → JUDGE 闭环。
//!
//! 当前实现为确定性/启发式 Agent：直接复用 `CallGraphQueryEngine` 与扫描结果中的
//! 结构化证据（调用路径、sanitizer、barrier）做出 TP/FP 判定，不依赖外部 LLM。
//! 模块已预留 LLM 判定插槽，方便后续接入大模型。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use deepaudit_core::attack_surface::AttackSurfaceMapper;
use deepaudit_core::scanning::{
    scan_directory_deep_with_rules_progress, Finding, ScanOptions, ScanResult,
};
use deepaudit_core::CallGraphQueryEngine;

pub mod blackboard;
pub mod evidence;
pub mod heuristics;
pub mod llm;
pub mod llm_client;
pub mod prompts;
pub mod report;
pub mod reviewer;
pub mod specialist;
pub mod supervisor;

use llm_client::create_llm_client;
use report::{AuditReport, InvestigationResult};
use specialist::SpecialistRegistry;
use supervisor::Supervisor;

/// Agent 运行配置
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// 项目根目录
    pub project_path: PathBuf,
    /// 是否启用深度扫描（默认 true，Agent 需要跨文件调用图）
    pub deep: bool,
    /// 最低严重程度阈值
    pub min_severity: String,
    /// 最多调查的 finding 数量（None = 无限制）
    pub max_findings: Option<usize>,
    /// 输出格式
    pub output_format: crate::output::OutputFormat,
    /// 输出文件路径（None 则输出到 stdout）
    pub output_path: Option<String>,
    /// 是否启用 Specialist Agent（覆盖配置文件默认值）
    pub specialist_enabled: bool,
    /// Review 模式：off / debate / single（覆盖配置文件默认值）
    pub review_mode: String,
}

impl AuditConfig {
    /// 从 CLI 参数构造默认配置
    pub fn new(
        project_path: impl Into<PathBuf>,
        deep: bool,
        min_severity: Option<String>,
        max_findings: Option<usize>,
        output_format: crate::output::OutputFormat,
        output_path: Option<String>,
    ) -> Self {
        Self {
            project_path: project_path.into(),
            deep,
            min_severity: min_severity.unwrap_or_else(|| "medium".to_string()),
            max_findings,
            output_format,
            output_path,
            specialist_enabled: false,
            review_mode: "off".to_string(),
        }
    }
}

/// Agent 运行入口
pub async fn run_audit(config: AuditConfig) -> Result<AuditReport> {
    let project_path_str = config.project_path.to_string_lossy().to_string();

    // 加载应用配置中的 agent 段
    let config_manager = crate::config::ConfigManager::new(None)?;
    let agent_config = config_manager.config().agent.clone();
    let specialist_enabled = config.specialist_enabled || agent_config.specialist_enabled;
    let review_mode = if config.review_mode.is_empty() {
        agent_config.review_mode.clone()
    } else {
        config.review_mode.clone()
    };

    // ── SURVEY：做一次深度扫描拿到 findings ──────────────────────
    let scan_result = run_security_scan(&config).await?;

    let query_engine = build_query_engine(&config.project_path, &scan_result)?;

    // 过滤、基线抑制、攻击面排序
    let baseline = load_baseline(&config.project_path);
    let mut findings = filter_and_prioritize_findings(
        scan_result.findings,
        &config.min_severity,
        &config.project_path,
        &baseline,
    );

    let total_findings = findings.len();
    let to_investigate: Vec<Finding> = findings
        .into_iter()
        .take(config.max_findings.unwrap_or(usize::MAX))
        .collect();

    let session_id = uuid::Uuid::new_v4().to_string();

    // Blackboard 共享状态
    let blackboard = Arc::new(tokio::sync::RwLock::new(blackboard::BlackboardState::new(
        session_id.clone(),
        project_path_str.clone(),
    )));

    // ── HYPOTHESIZE → VERIFY → JUDGE：并发 Actor 调度 ─────────────
    let llm_client = create_llm_client(&agent_config);
    let supervisor = Supervisor::new(
        config.project_path.clone(),
        query_engine.map(Arc::new),
        llm_client,
        blackboard.clone(),
        agent_config.triage_concurrency,
    )
    .with_specialists(
        Arc::new(SpecialistRegistry::with_defaults()),
        specialist_enabled,
    )
    .with_reviewer(
        Arc::new(crate::agent::reviewer::RuleBasedReviewer),
        review_mode,
    );

    let mut results = supervisor.run(to_investigate).await;
    for inv in &mut results {
        inv.session_id = session_id.clone();
    }

    // ── 汇总并持久化 ─────────────────────────────────────────────
    write_audit_log(&config.project_path, &results)?;
    {
        let bb = blackboard.read().await;
        bb.save(&config.project_path)?;
    }

    let report = AuditReport {
        session_id,
        project_path: project_path_str,
        total_findings,
        investigated_count: results.len(),
        investigations: results,
    };

    report::write_report(&report, config.output_format, config.output_path.as_deref())?;

    Ok(report)
}

/// 运行安全扫描，默认启用跨文件污点分析
async fn run_security_scan(config: &AuditConfig) -> Result<ScanResult> {
    let path = config
        .project_path
        .to_str()
        .context("项目路径包含非法字符")?;

    let mut opts = ScanOptions::default();
    opts.enable_taint = true;
    opts.enable_cross_file = true;
    // Agent 需要调用图，因此即使 CLI 没传 --deep 也强制启用跨文件分析
    if !config.deep {
        opts.enable_taint = true;
        opts.enable_cross_file = true;
    }

    scan_directory_deep_with_rules_progress(path, None, None, None, Some(opts), None)
        .await
        .map_err(|e| anyhow::anyhow!("扫描失败: {}", e))
}

/// 从扫描结果或独立分析构建调用图查询引擎
fn build_query_engine(
    project_path: &Path,
    scan_result: &ScanResult,
) -> Result<Option<CallGraphQueryEngine>> {
    // 优先复用扫描管线已经构建好的 CrossFileTaintResult
    if let Some(ref cross_file) = scan_result.cross_file_result {
        return Ok(Some(CallGraphQueryEngine::from_result(cross_file)));
    }

    // 退化路径：扫描未产生跨文件结果时，单独构建一次调用图
    let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
    let result = analyzer.analyze_project(project_path);
    Ok(Some(CallGraphQueryEngine::from_result(&result)))
}

/// 加载历史 baseline，返回被忽略的 key 集合
fn load_baseline(project_path: &Path) -> HashSet<String> {
    let baseline_path = project_path.join(".ctx-audit").join("baseline.json");
    let content = match std::fs::read_to_string(&baseline_path) {
        Ok(c) => c,
        Err(_) => return HashSet::new(),
    };

    let value: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return HashSet::new(),
    };

    let mut keys = HashSet::new();
    if let Some(ignored) = value.get("ignored").and_then(|v| v.as_object()) {
        for key in ignored.keys() {
            keys.insert(key.clone());
        }
    }
    keys
}

/// 过滤、基线抑制、攻击面排序
fn filter_and_prioritize_findings(
    findings: Vec<Finding>,
    min_severity: &str,
    project_path: &Path,
    baseline: &HashSet<String>,
) -> Vec<Finding> {
    let rank = |s: &str| match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    };
    let min_rank = rank(min_severity);

    // 攻击面风险评分：文件 → 分数
    let file_risk = compute_file_risk(project_path);

    let mut filtered: Vec<Finding> = findings
        .into_iter()
        .filter(|f| rank(&f.severity) <= min_rank)
        .filter(|f| {
            let key = format!("{}:{}:{}", f.file_path, f.line_start, f.vuln_type);
            !baseline.contains(&key)
        })
        .map(|mut f| {
            // 确保 file_role 有默认值，便于排序
            if f.file_role.is_none() {
                f.file_role = Some("production".to_string());
            }
            f
        })
        .collect();

    filtered.sort_by(|a, b| {
        let role_rank = |f: &Finding| match f.file_role.as_deref().unwrap_or("production") {
            "production" => 0,
            "test" => 2,
            "build" => 3,
            "vendor" => 4,
            _ => 1,
        };

        let risk_a = file_risk.get(&a.file_path).copied().unwrap_or(0);
        let risk_b = file_risk.get(&b.file_path).copied().unwrap_or(0);

        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then_with(|| risk_b.cmp(&risk_a))
            .then_with(|| role_rank(a).cmp(&role_rank(b)))
            .then_with(|| a.file_path.cmp(&b.file_path))
    });

    filtered
}

/// 计算每个文件的风险分数
fn compute_file_risk(project_path: &Path) -> HashMap<String, i32> {
    let surface = AttackSurfaceMapper::map_project(project_path);
    let mut risk: HashMap<String, i32> = HashMap::new();

    for file in &surface.high_risk_files {
        *risk.entry(file.clone()).or_insert(0) += 10;
    }

    for ep in &surface.entry_points {
        *risk.entry(ep.file_path.clone()).or_insert(0) += 1;
    }

    risk
}

/// 将调查结果追加写入 <project_path>/.ctx-audit/audit_log.json
fn write_audit_log(project_path: &Path, results: &[InvestigationResult]) -> Result<()> {
    let audit_dir = project_path.join(".ctx-audit");
    std::fs::create_dir_all(&audit_dir)?;

    let audit_log_path = audit_dir.join("audit_log.json");
    let mut log: Vec<serde_json::Value> = if audit_log_path.exists() {
        std::fs::read_to_string(&audit_log_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    for result in results {
        let entry = serde_json::json!({
            "finding_id": result.finding_id,
            "file_path": result.file_path,
            "line": result.line,
            "vulnerability_type": result.vulnerability_type,
            "verdict": result.verdict.as_str(),
            "reasoning": result.reasoning,
            "session_id": result.session_id,
            "investigation_id": result.investigation_id,
            "hypothesis": result.hypothesis,
            "evidence": result.evidence.to_json(),
            "specialist_result": result.specialist_result,
            "reviews": result.reviews,
            "confidence": result.confidence,
            "audited_at": result.audited_at,
        });
        log.push(entry);
    }

    std::fs::write(
        &audit_log_path,
        serde_json::to_string_pretty(&log).unwrap_or_default(),
    )
    .with_context(|| format!("写入审计日志失败: {}", audit_log_path.display()))?;

    Ok(())
}
