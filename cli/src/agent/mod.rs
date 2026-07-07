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
pub mod environment;
pub mod evidence;
pub mod heuristics;
pub mod investigator;
pub mod llm;
pub mod llm_client;
pub mod onboarding;
pub mod planner;
pub mod prompts;
pub mod report;
pub mod reviewer;
pub mod specialist;
pub mod supervisor;
pub mod tools;

use environment::EnvironmentModel;
use llm_client::create_llm_client;
use planner::{
    executor::PlanExecutor,
    llm_based::LlmBasedPlanner,
    rule_based::RuleBasedPlanner,
    strategy::{PlannerConfig, PlannerStrategy, StrategyPlanner},
    Planner,
};
use report::{AuditReport, InvestigationResult};
use specialist::SpecialistRegistry;
use supervisor::Supervisor;
use tools::AgentToolContext;

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
    /// 是否启用 ReAct 调查器（覆盖配置文件默认值）
    pub investigator_enabled: bool,
    /// 是否启用污点步进调查器（覆盖配置文件默认值）
    pub taint_walk_enabled: bool,
    /// 最大调查步数（None 表示使用配置文件默认值）
    pub max_investigation_steps: Option<usize>,
    /// 是否启用自动目标生成（覆盖配置文件默认值）
    pub auto_goal: bool,
    /// 策略模式（覆盖配置文件默认值）
    pub strategy: Option<String>,
    /// 最大审计目标数（None 表示使用配置文件默认值）
    pub max_goals: Option<usize>,
    /// 每个目标最大探索行动数（None 表示使用配置文件默认值）
    pub max_exploration_actions: Option<usize>,
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
            review_mode: String::new(),
            investigator_enabled: false,
            taint_walk_enabled: false,
            max_investigation_steps: None,
            auto_goal: true,
            strategy: None,
            max_goals: None,
            max_exploration_actions: None,
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
    let investigator_enabled = config.investigator_enabled || agent_config.investigator_enabled;
    let taint_walk_enabled = config.taint_walk_enabled || agent_config.taint_walk_enabled;
    let max_investigation_steps = config
        .max_investigation_steps
        .unwrap_or(agent_config.max_investigation_steps);

    let auto_goal = config.auto_goal;
    let strategy = config
        .strategy
        .clone()
        .unwrap_or_else(|| match agent_config.planner.strategy {
            crate::config::PlannerStrategy::Rule => "rule".to_string(),
            crate::config::PlannerStrategy::Llm => "llm".to_string(),
            crate::config::PlannerStrategy::Auto => "auto".to_string(),
        });
    let max_goals = config.max_goals.unwrap_or(agent_config.planner.max_goals);
    let max_exploration_actions = config
        .max_exploration_actions
        .unwrap_or(agent_config.planner.max_exploration_actions);

    // ── 启动引导：让用户确认非生产目录并持久化 ─────────────────
    let mut renderer = crate::terminal::TerminalRenderer::new();
    let onboarding_llm: Option<Arc<dyn crate::agent::llm_client::LlmClient>> =
        if agent_config.llm_mode == "http" {
            Some(Arc::new(crate::agent::llm_client::HttpLlmClient {
                provider: agent_config.llm.provider.clone(),
                model: agent_config.llm.model.clone(),
                api_key: agent_config.llm.api_key.clone(),
                endpoint: agent_config.llm.endpoint.clone(),
                timeout_sec: agent_config.llm.timeout_sec,
                max_tokens: agent_config.llm.max_tokens,
            }))
        } else {
            None
        };
    let _ = onboarding::maybe_prompt_non_production_paths(
        &config.project_path,
        &mut renderer,
        onboarding_llm,
    )
    .await;

    // ── SURVEY：做一次深度扫描拿到 findings ──────────────────────
    let scan_result = run_security_scan(&config).await?;

    let query_engine = build_query_engine(&config.project_path, &scan_result)?;

    // 过滤、基线抑制、攻击面排序
    let baseline = load_baseline(&config.project_path);
    let findings = filter_and_prioritize_findings(
        scan_result.findings.clone(),
        &config.min_severity,
        &config.project_path,
        &baseline,
    );

    let total_findings = findings.len();
    let session_id = uuid::Uuid::new_v4().to_string();

    let query_engine_arc = query_engine.map(Arc::new);
    let tool_context = if let Some(ref engine) = query_engine_arc {
        Some(AgentToolContext::new_with_registry(engine.clone(), project_path_str.clone()).await)
    } else {
        None
    };

    // ── ENVIRONMENT：构建全局环境模型 ─────────────────────────────
    let call_graph = query_engine_arc
        .clone()
        .context("Agent 需要调用图引擎才能构建环境模型")?;
    let env_arc = Arc::new(
        EnvironmentModel::build(
            &config.project_path,
            &scan_result,
            findings.clone(),
            baseline,
            call_graph,
        )
        .await?,
    );
    {
        let mut bb = env_arc.blackboard.write().await;
        bb.session_id = session_id.clone();
    }

    // ── HYPOTHESIZE → VERIFY → JUDGE：并发 Actor 调度 ─────────────
    let llm_client = create_llm_client(&agent_config);

    let supervisor = Supervisor::new(
        config.project_path.clone(),
        query_engine_arc,
        llm_client.clone(),
        env_arc.blackboard.clone(),
        agent_config.triage_concurrency,
    )
    .with_specialists(
        Arc::new(SpecialistRegistry::with_defaults()),
        specialist_enabled,
    )
    .with_reviewer(
        if review_mode == "debate" && agent_config.llm_mode == "http" {
            Arc::new(crate::agent::reviewer::DebateReviewer::new(
                llm_client.clone(),
            )) as Arc<dyn crate::agent::reviewer::Reviewer>
        } else if review_mode == "single" && agent_config.llm_mode == "http" {
            Arc::new(crate::agent::reviewer::LlmBasedReviewer::new(
                llm_client.clone(),
            )) as Arc<dyn crate::agent::reviewer::Reviewer>
        } else {
            Arc::new(crate::agent::reviewer::RuleBasedReviewer)
                as Arc<dyn crate::agent::reviewer::Reviewer>
        },
        review_mode,
    )
    .with_tool_context(tool_context.clone())
    .with_investigator(investigator_enabled, max_investigation_steps)
    .with_taint_walk(taint_walk_enabled, max_investigation_steps);

    let mut results = Vec::new();

    if auto_goal {
        let planner_config = PlannerConfig {
            strategy: planner::strategy::PlannerStrategy::from_str(&strategy),
            max_goals,
            max_exploration_actions,
            enable_proactive_scan: agent_config.planner.enable_proactive_scan,
            enable_reflection: agent_config.planner.enable_reflection,
            convergence_threshold: agent_config.planner.convergence_threshold,
            public_route_patterns: agent_config.planner.public_route_patterns.clone(),
            non_production_path_patterns: agent_config.planner.non_production_path_patterns.clone(),
        };
        let strategy_planner = StrategyPlanner::new(llm_client.clone(), planner_config);
        let goals = strategy_planner.plan_goals(&env_arc).await;

        if !goals.is_empty() {
            let planner: Arc<dyn Planner> =
                if strategy == "llm" || (strategy == "auto" && agent_config.llm_mode == "http") {
                    Arc::new(LlmBasedPlanner::new(
                        llm_client.clone(),
                        RuleBasedPlanner::new(
                            max_exploration_actions,
                            agent_config.planner.public_route_patterns.clone(),
                        ),
                        max_exploration_actions,
                    ))
                } else {
                    Arc::new(RuleBasedPlanner::new(
                        max_exploration_actions,
                        agent_config.planner.public_route_patterns.clone(),
                    ))
                };
            let executor = PlanExecutor::new(
                Arc::new(supervisor.clone()),
                tool_context.clone(),
                env_arc.clone(),
            );

            for goal in &goals {
                if strategy_planner.has_converged(&env_arc).await {
                    tracing::info!("所有目标相关漏洞类型已收敛，提前结束审计");
                    break;
                }
                match planner.plan(&env_arc, goal).await {
                    Ok(plan) => {
                        tracing::info!(
                            "执行目标: {} ({} actions)",
                            goal.objective,
                            plan.actions.len()
                        );
                        match executor.execute_plan(&plan).await {
                            Ok((mut invs, _meta)) => {
                                results.append(&mut invs);
                            }
                            Err(e) => {
                                tracing::warn!("执行目标 {} 失败: {}", goal.objective, e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("生成计划失败: {}", e);
                    }
                }
            }
        } else {
            // 没有生成目标，回退到传统行为
            let to_investigate: Vec<Finding> = findings
                .into_iter()
                .take(config.max_findings.unwrap_or(usize::MAX))
                .collect();
            results = supervisor.run(to_investigate).await;
        }
    } else {
        let to_investigate: Vec<Finding> = findings
            .into_iter()
            .take(config.max_findings.unwrap_or(usize::MAX))
            .collect();
        results = supervisor.run(to_investigate).await;
    }

    for inv in &mut results {
        inv.session_id = session_id.clone();
    }

    // ── 汇总并持久化 ─────────────────────────────────────────────
    write_audit_log(&config.project_path, &results)?;
    {
        let bb: tokio::sync::RwLockReadGuard<'_, crate::agent::blackboard::BlackboardState> =
            env_arc.blackboard.read().await;
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

    // 加载扫描配置，保持与 scan 子命令一致的默认值
    let scan_cfg = crate::config::ConfigManager::new(None).ok().map(|m| m.config().scan.clone());
    let (public_route_patterns, mut non_production_path_patterns, exclude_patterns) =
        match scan_cfg {
            Some(ref scan) => (
                scan.public_route_patterns.clone(),
                scan.non_production_path_patterns.clone(),
                scan.exclude_patterns.clone(),
            ),
            None => (
                deepaudit_core::analysis::attack_surface::default_public_route_patterns(),
                deepaudit_core::analysis::attack_surface::default_non_production_path_patterns(),
                Vec::new(),
            ),
        };

    let mut opts = ScanOptions::default();
    opts.enable_taint = true;
    opts.enable_cross_file = true;
    opts.public_route_patterns = public_route_patterns;
    // 合并项目级配置中的非生产路径模式
    let project_patterns = onboarding::load_project_non_production_patterns(&config.project_path);
    for p in project_patterns {
        if !non_production_path_patterns.contains(&p) {
            non_production_path_patterns.push(p);
        }
    }

    opts.non_production_path_patterns = non_production_path_patterns;

    // 合并排除列表：配置文件 exclude_patterns + exclude_extra
    let exclude_extra = scan_cfg.as_ref().map(|s| s.exclude_extra.clone()).unwrap_or_default();
    let mut all_excludes = exclude_patterns;
    for p in exclude_extra {
        let p = p.trim().to_string();
        if !p.is_empty() && !all_excludes.contains(&p) {
            all_excludes.push(p);
        }
    }

    // 尝试从缓存加载扫描结果（项目/规则/选项未变时跳过扫描）
    let cache_dir = config.project_path.join(".ctx-audit").join("cache");
    let rules_dir = std::path::Path::new("rules");
    let rules_hash = deepaudit_core::scan_cache::compute_rules_hash(rules_dir);
    let options_hash = deepaudit_core::scan_cache::compute_options_hash(&opts);

    if let Some(cached) = deepaudit_core::scan_cache::load_scan_result(
        &cache_dir,
        &config.project_path,
        &rules_hash,
        &options_hash,
    ) {
        return Ok(cached);
    }

    let exclude_opt = if all_excludes.is_empty() {
        None
    } else {
        Some(all_excludes)
    };

    let scan_result = scan_directory_deep_with_rules_progress(
        path, None, exclude_opt, None, Some(opts), None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("扫描失败: {}", e))?;

    // 保存扫描结果供下次复用（失败不影响本次审计）
    if let Err(e) = deepaudit_core::scan_cache::save_scan_result(
        &cache_dir,
        &config.project_path,
        &scan_result,
        &rules_hash,
        &options_hash,
    ) {
        tracing::warn!("保存扫描缓存失败: {}", e);
    }

    Ok(scan_result)
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
        .filter(|f| {
            // 根据项目配置排除非生产代码目录中的 finding
            f.file_role.as_deref() != Some("non-production")
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
            "investigation_steps": result.investigation_steps,
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
