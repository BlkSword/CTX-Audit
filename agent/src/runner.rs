// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! runner：轮状态机（M2）
//!
//! 六阶段：选目标 → 资格核实 → 扫描 → 初审 → 深审 → 登记草稿 → 反哺（M4）
//!
//! - 确定性阶段（选目标/资格核实/扫描）直接调 deepaudit-core 扫描 API，不经 LLM；
//! - 初审/深审调 M1 `Agent::run`，system prompt 从 round-agent.md 加载；
//! - 初审分片（M4）：findings 数 > `subagent_threshold`（默认 50）时按 (漏洞类型, 文件)
//!   分片，每片 spawn 一个子 agent 并行初审（JoinSet），汇总后写同一 triage 产物；
//! - 反哺阶段（M4）：0 TP 轮且配置 `feedback_tasks` 时自动执行 CVE 回放机械层，
//!   产出 replay-report JSON；无任务或有 TP 候选则跳过；
//! - 每阶段完成即写状态文件，崩溃后按轮次 ID 从断点续跑；
//! - 深审产出 TP 候选 → 写 gate 通知（文件+可选 webhook）→ 轮暂停在 AwaitHuman，
//!   人工 approve/reject 后才进入登记草稿。
//!
//! 注：§3.1 撞号四步协议针对"写 docs registry"场景，M2 登记产物仅为
//! state_dir 内的草稿 Markdown（人工合入 registry 时走人工撞号约定），故未实现。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

use deepaudit_core::scanning::{scan_directory_deep_with_rules_progress, Finding, ScanOptions};

use crate::agent::{Agent, AgentBudget, AgentError};
use crate::confirm::{ApprovalMode, ToolGate};
use crate::event::AgentEvent;
use crate::feedback::FeedbackTask;
use crate::gate::{self, GateDecision, GateNotice, TpCandidate};
use crate::pipeline::PipelineConfig;
use crate::provider::LLMProvider;
use crate::session::Session;
use crate::subagent::{register_delegate_tool, SubAgentConfig, SubAgentSpawner};
use crate::tool_adapter::ToolAdapter;
use ctx_audit_tools::{register_all_tools, ToolRegistry};

// ── 阶段定义 ────────────────────────────────────────────

/// 轮阶段
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundPhase {
    /// 选目标（路径校验 / git clone）
    SelectTarget,
    /// 资格核实
    Eligibility,
    /// 引擎扫描（确定性，无 LLM）
    Scan,
    /// 初审（triage，LLM）
    Triage,
    /// 深审（deep_review，LLM）
    DeepReview,
    /// 人工闸门暂停态（等待 approve/reject）
    AwaitHuman,
    /// 登记草稿
    RegistrationDraft,
    /// 反哺（M4 占位，当前直接跳过）
    Feedback,
    /// 完结
    Done,
}

impl RoundPhase {
    /// 展示名
    pub fn label(&self) -> &'static str {
        match self {
            RoundPhase::SelectTarget => "选目标",
            RoundPhase::Eligibility => "资格核实",
            RoundPhase::Scan => "扫描",
            RoundPhase::Triage => "初审",
            RoundPhase::DeepReview => "深审",
            RoundPhase::AwaitHuman => "等待人工闸门",
            RoundPhase::RegistrationDraft => "登记草稿",
            RoundPhase::Feedback => "反哺",
            RoundPhase::Done => "完结",
        }
    }
}

// ── 状态文件 ────────────────────────────────────────────

/// 目标信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// 用户输入（路径或 git URL）
    pub input: String,
    /// 本地路径（clone 后为 targets/<name>/）
    #[serde(default)]
    pub local_path: Option<PathBuf>,
    /// 是否 git URL 目标
    pub is_git_url: bool,
    /// 是否由 runner clone 而来
    #[serde(default)]
    pub cloned: bool,
}

/// 资格核实报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EligibilityReport {
    /// 路径存在且为目录
    pub path_exists: bool,
    /// 是否 git 仓库（含 .git）
    pub is_git_repo: bool,
    /// 源码文件数
    pub source_files: usize,
    /// 按语言统计（语言名 → 文件数）
    pub languages: BTreeMap<String, usize>,
    /// 主语言
    pub primary_language: Option<String>,
    /// 是否有审计资格
    pub eligible: bool,
    /// 判定理由
    pub reasons: Vec<String>,
}

/// 轮状态（每阶段完成即落盘）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunnerState {
    /// 轮次 ID
    pub round_id: String,
    /// 目标
    pub target: TargetInfo,
    /// 下一个待执行阶段（AwaitHuman/Done 为终止态）
    pub current_phase: RoundPhase,
    /// 已完成阶段
    #[serde(default)]
    pub completed: Vec<RoundPhase>,
    /// 阶段产物路径（阶段名 → 文件路径）
    #[serde(default)]
    pub artifacts: BTreeMap<String, String>,
    /// 资格报告
    #[serde(default)]
    pub eligibility: Option<EligibilityReport>,
    /// 深审产出的 TP 候选
    #[serde(default)]
    pub tp_candidates: Vec<TpCandidate>,
    /// 人工闸门决策
    #[serde(default)]
    pub gate_decision: Option<GateDecision>,
    /// 最近一次错误（断点续跑时保留现场）
    #[serde(default)]
    pub last_error: Option<String>,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

// ── 错误类型 ────────────────────────────────────────────

/// runner 错误
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    /// 扫描失败
    #[error("扫描失败: {0}")]
    Scan(String),

    /// 判定层 prompt 未找到
    #[error("判定层 prompt 未找到: {0}")]
    PromptMissing(String),

    /// 未配置 provider（LLM 阶段无法执行）
    #[error(
        "未配置 LLM provider，无法执行判定阶段（请配置 agent.native_provider.* 与环境变量密钥）"
    )]
    ProviderMissing,

    /// agent 层错误
    #[error("agent 错误: {0}")]
    Agent(#[from] AgentError),

    /// agent 输出 JSON 解析失败
    #[error("判定输出 JSON 解析失败: {0}")]
    Parse(String),

    /// git 操作失败
    #[error("git 操作失败: {0}")]
    Git(String),

    /// 轮次状态不存在
    #[error("轮次状态不存在: {0}")]
    StateNotFound(String),

    /// 轮次状态非法
    #[error("轮次状态非法: {0}")]
    InvalidState(String),

    /// 目标无审计资格
    #[error("目标无审计资格: {0}")]
    Ineligible(String),

    /// 初审分片子 agent 失败（M4）
    #[error("初审分片失败: {0}")]
    Shard(String),
}

// ── 配置 ────────────────────────────────────────────────

/// runner 配置
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// 状态目录（默认 <cwd>/.ctx-audit/runner）
    pub state_dir: PathBuf,
    /// 判定层 prompt（round-agent.md）路径覆盖；None 则按默认顺序搜索
    pub judge_prompt_path: Option<PathBuf>,
    /// LLM 阶段预算
    pub budget: AgentBudget,
    /// 工具审批模式
    pub approval: ApprovalMode,
    /// gate webhook URL（可选）
    pub webhook_url: Option<String>,
    /// 登记草稿是否用 LLM 润色（默认 false=纯模板）
    pub llm_polish_draft: bool,
    /// 初审分片阈值（M4）：findings 数 > 该值时按 (漏洞类型, 文件) 分片并行初审，
    /// 0 = 禁用分片（默认 50）
    pub subagent_threshold: usize,
    /// 反哺任务（M4）：0 TP 轮自动执行 CVE 回放机械层（默认空=跳过）
    pub feedback_tasks: Vec<FeedbackTask>,
    /// 可配置审计流水线（默认等于 CTX-Audit 当前行为）
    pub pipeline: PipelineConfig,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from(".ctx-audit").join("runner"),
            judge_prompt_path: None,
            budget: AgentBudget::default(),
            approval: ApprovalMode::Gate,
            webhook_url: None,
            llm_polish_draft: false,
            subagent_threshold: 50,
            feedback_tasks: Vec::new(),
            pipeline: PipelineConfig::default(),
        }
    }
}

// ── Runner ──────────────────────────────────────────────

/// 轮 runner
pub struct Runner {
    config: RunnerConfig,
    provider: Option<Arc<dyn LLMProvider>>,
}

impl Runner {
    /// 创建 runner（provider 可为 None，仅 LLM 阶段需要）
    pub fn new(config: RunnerConfig, provider: Option<Arc<dyn LLMProvider>>) -> Self {
        Self { config, provider }
    }

    /// 启动或续跑一轮
    ///
    /// `round_id` 指定且状态文件存在且未完结时，从断点阶段继续（target 以状态文件为准）。
    pub async fn run(
        &self,
        target: &str,
        round_id: Option<String>,
        event_tx: mpsc::Sender<AgentEvent>,
    ) -> Result<RunnerState, RunnerError> {
        let round_id = round_id.unwrap_or_else(|| {
            format!(
                "AR-{}-{}",
                Utc::now().format("%Y%m%d"),
                &uuid::Uuid::new_v4().to_string()[..8]
            )
        });

        match Self::load_state(&self.config.state_dir, &round_id) {
            Ok(state) => {
                if state.target.input != target {
                    return Err(RunnerError::InvalidState(format!(
                        "轮次 {} 已存在且目标为 {}，与本次输入 {} 不一致",
                        round_id, state.target.input, target
                    )));
                }
                if state.current_phase == RoundPhase::Done {
                    tracing::info!("轮次 {} 已完结，直接返回", round_id);
                    return Ok(state);
                }
                tracing::info!(
                    "轮次 {} 从断点 {} 续跑",
                    round_id,
                    state.current_phase.label()
                );
                self.execute_loop(state, &event_tx).await
            }
            Err(_) => {
                let state = RunnerState {
                    round_id: round_id.clone(),
                    target: TargetInfo {
                        input: target.to_string(),
                        local_path: None,
                        is_git_url: is_git_url(target),
                        cloned: false,
                    },
                    current_phase: RoundPhase::SelectTarget,
                    completed: Vec::new(),
                    artifacts: BTreeMap::new(),
                    eligibility: None,
                    tp_candidates: Vec::new(),
                    gate_decision: None,
                    last_error: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                };
                self.save_state(&state)?;
                self.execute_loop(state, &event_tx).await
            }
        }
    }

    /// 续跑已有轮次（target 从状态文件读）
    pub async fn resume(
        &self,
        round_id: &str,
        event_tx: mpsc::Sender<AgentEvent>,
    ) -> Result<RunnerState, RunnerError> {
        let state = Self::load_state(&self.config.state_dir, round_id)?;
        if state.current_phase == RoundPhase::AwaitHuman {
            // 闸门未决，不推进
            return Ok(state);
        }
        if state.current_phase == RoundPhase::Done {
            return Ok(state);
        }
        self.execute_loop(state, &event_tx).await
    }

    /// 人工闸门决策：approve/reject 后进入登记草稿阶段
    pub async fn gate_decide(
        &self,
        round_id: &str,
        approve: bool,
        note: Option<String>,
        event_tx: mpsc::Sender<AgentEvent>,
    ) -> Result<RunnerState, RunnerError> {
        let mut state = Self::load_state(&self.config.state_dir, round_id)?;
        if state.current_phase != RoundPhase::AwaitHuman {
            return Err(RunnerError::InvalidState(format!(
                "轮次 {} 当前阶段为 {}，不在人工闸门等待态",
                round_id,
                state.current_phase.label()
            )));
        }

        let decision = GateDecision {
            approve,
            note,
            decided_at: Utc::now(),
        };
        gate::write_decision(&self.config.state_dir, round_id, &decision)?;
        state.gate_decision = Some(decision);
        state.current_phase = RoundPhase::RegistrationDraft;
        state.last_error = None;
        self.save_state(&state)?;

        self.execute_loop(state, &event_tx).await
    }

    // ── 阶段循环 ────────────────────────────────────────

    /// 逐阶段执行，直到 AwaitHuman / Done / 出错
    async fn execute_loop(
        &self,
        mut state: RunnerState,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<RunnerState, RunnerError> {
        loop {
            if state.current_phase == RoundPhase::AwaitHuman
                || state.current_phase == RoundPhase::Done
            {
                return Ok(state);
            }

            let phase = state.current_phase;
            tracing::info!("轮次 {} 进入阶段: {}", state.round_id, phase.label());
            if let Err(e) = self.execute_phase(&mut state, event_tx).await {
                // 阶段失败：保留断点现场（current_phase 不变），可续跑重试
                state.last_error = Some(e.to_string());
                let _ = self.save_state(&state);
                return Err(e);
            }
        }
    }

    /// 执行单个阶段并推进状态
    async fn execute_phase(
        &self,
        state: &mut RunnerState,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<(), RunnerError> {
        match state.current_phase {
            RoundPhase::SelectTarget => {
                self.phase_select_target(state).await?;
                self.advance(state, RoundPhase::Eligibility)
            }
            RoundPhase::Eligibility => {
                self.phase_eligibility(state)?;
                self.advance(state, RoundPhase::Scan)
            }
            RoundPhase::Scan => {
                self.phase_scan(state).await?;
                self.advance(state, RoundPhase::Triage)
            }
            RoundPhase::Triage => {
                self.phase_judge(state, JudgeStage::Triage, event_tx)
                    .await?;
                self.advance(state, RoundPhase::DeepReview)
            }
            RoundPhase::DeepReview => {
                self.phase_judge(state, JudgeStage::DeepReview, event_tx)
                    .await?;
                let has_tp = !state.tp_candidates.is_empty();
                if has_tp {
                    self.enter_gate(state).await?;
                    // 不 advance：current_phase 置为 AwaitHuman 后返回，循环在下一轮退出
                    Ok(())
                } else {
                    self.advance(state, RoundPhase::RegistrationDraft)
                }
            }
            RoundPhase::RegistrationDraft => {
                self.phase_registration(state, event_tx).await?;
                self.advance(state, RoundPhase::Feedback)
            }
            RoundPhase::Feedback => {
                self.phase_feedback(state, event_tx).await?;
                self.advance(state, RoundPhase::Done)
            }
            RoundPhase::AwaitHuman | RoundPhase::Done => Ok(()),
        }
    }

    /// 推进到下一阶段并落盘
    fn advance(&self, state: &mut RunnerState, next: RoundPhase) -> Result<(), RunnerError> {
        state.completed.push(state.current_phase);
        state.current_phase = next;
        state.last_error = None;
        self.save_state(state)
    }

    // ── 阶段一：选目标 ──────────────────────────────────

    async fn phase_select_target(&self, state: &mut RunnerState) -> Result<(), RunnerError> {
        let input = state.target.input.clone();
        let local_path = if state.target.is_git_url {
            self.clone_target(&input).await?
        } else {
            let path = Path::new(&input);
            if !path.is_dir() {
                return Err(RunnerError::InvalidState(format!(
                    "目标路径不存在或不是目录: {}",
                    input
                )));
            }
            path.canonicalize()?
        };
        state.target.local_path = Some(local_path);
        Ok(())
    }

    /// clone git URL 目标到 <state_dir>/targets/<name>/（已存在则复用）
    async fn clone_target(&self, url: &str) -> Result<PathBuf, RunnerError> {
        let targets_dir = self.config.state_dir.join("targets");
        std::fs::create_dir_all(&targets_dir)?;
        let dest = targets_dir.join(repo_name_from_url(url));
        if dest.exists() {
            tracing::info!("目标已 clone 过，复用: {}", dest.display());
            return Ok(dest);
        }
        let output = tokio::process::Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg(url)
            .arg(&dest)
            .output()
            .await
            .map_err(|e| RunnerError::Git(format!("启动 git 失败: {}", e)))?;
        if !output.status.success() {
            return Err(RunnerError::Git(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        Ok(dest)
    }

    // ── 阶段二：资格核实 ────────────────────────────────

    fn phase_eligibility(&self, state: &mut RunnerState) -> Result<(), RunnerError> {
        let path = state
            .target
            .local_path
            .clone()
            .ok_or_else(|| RunnerError::InvalidState("目标本地路径未解析".into()))?;
        let report = Self::check_eligibility(&path);

        let artifact = self.write_artifact(state, "eligibility", &report)?;
        state
            .artifacts
            .insert("eligibility".to_string(), artifact.display().to_string());
        state.eligibility = Some(report.clone());

        if !report.eligible {
            self.save_state(state)?;
            return Err(RunnerError::Ineligible(report.reasons.join("；")));
        }
        Ok(())
    }

    /// 资格核实：路径存在、git 仓库标记、源码文件统计、主语言识别
    pub fn check_eligibility(path: &Path) -> EligibilityReport {
        let path_exists = path.is_dir();
        let is_git_repo = path.join(".git").exists();
        let mut languages: BTreeMap<String, usize> = BTreeMap::new();
        if path_exists {
            walk_sources(path, &mut languages, 0);
        }
        let source_files: usize = languages.values().sum();
        let primary_language = languages
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang.clone());

        let mut reasons = Vec::new();
        if !path_exists {
            reasons.push("路径不存在或不是目录".to_string());
        }
        if path_exists && source_files == 0 {
            reasons.push("未发现源码文件".to_string());
        }
        if path_exists && !is_git_repo {
            reasons.push("不是 git 仓库（仅标记，不影响资格）".to_string());
        }
        let eligible = path_exists && source_files > 0;
        if eligible {
            reasons.push(format!(
                "发现 {} 个源码文件，主语言 {}",
                source_files,
                primary_language.as_deref().unwrap_or("未知")
            ));
        }

        EligibilityReport {
            path_exists,
            is_git_repo,
            source_files,
            languages,
            primary_language,
            eligible,
            reasons,
        }
    }

    // ── 阶段三：扫描（确定性，无 LLM） ──────────────────

    async fn phase_scan(&self, state: &mut RunnerState) -> Result<(), RunnerError> {
        let path = state
            .target
            .local_path
            .clone()
            .ok_or_else(|| RunnerError::InvalidState("目标本地路径未解析".into()))?;
        let path_str = path.to_string_lossy().to_string();

        let scan = &self.config.pipeline.scan;
        let mut opts = ScanOptions::default();
        opts.enable_taint = scan.enable_taint;
        opts.enable_cross_file = scan.enable_cross_file;

        let rules_dir = scan.rules_dir.as_deref().and_then(|r| r.to_str());
        let result = scan_directory_deep_with_rules_progress(
            &path_str,
            rules_dir,
            None,
            None,
            Some(opts),
            None,
        )
        .await
        .map_err(RunnerError::Scan)?;

        let findings = result.findings;
        let findings: Vec<Finding> = match scan.min_severity.as_deref() {
            Some(min) => findings
                .into_iter()
                .filter(|f| severity_at_least(&f.severity, min))
                .collect(),
            None => findings,
        };
        let artifact_json = build_scan_artifact(&path_str, &findings);
        let artifact = self.write_artifact(state, "scan", &artifact_json)?;
        state
            .artifacts
            .insert("scan".to_string(), artifact.display().to_string());
        tracing::info!(
            "轮次 {} 扫描完成：{} 个 findings",
            state.round_id,
            findings.len()
        );
        Ok(())
    }

    // ── 阶段四/五：初审 / 深审（LLM 判定） ──────────────

    async fn phase_judge(
        &self,
        state: &mut RunnerState,
        stage: JudgeStage,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<(), RunnerError> {
        let target_path = state
            .target
            .local_path
            .clone()
            .ok_or_else(|| RunnerError::InvalidState("目标本地路径未解析".into()))?;

        // Pipeline 可关闭某个 LLM 判定阶段：写一个空产物并直接返回
        let stage_enabled = match stage {
            JudgeStage::Triage => self.config.pipeline.triage.enabled,
            JudgeStage::DeepReview => self.config.pipeline.deep_review.enabled,
        };
        if !stage_enabled {
            let empty = serde_json::json!({
                "phase": stage.name(),
                "summary": {"tp_candidates": 0, "fp": 0, "hardening": 0},
                "tp_candidates": [],
                "fp_families": [],
                "hardening": [],
                "human_gate": false,
                "skipped_by_pipeline": true,
            });
            let artifact = self.write_artifact(state, stage.name(), &empty)?;
            state
                .artifacts
                .insert(stage.name().to_string(), artifact.display().to_string());
            if stage == JudgeStage::DeepReview {
                state.tp_candidates.clear();
            }
            return Ok(());
        }

        // 组阶段输入并执行（初审支持 M4 阈值分片并行）
        let output = match stage {
            JudgeStage::Triage => self.run_triage(state, &target_path, event_tx).await?,
            JudgeStage::DeepReview => {
                let triage_artifact = self.read_artifact(state, "triage")?;
                let user_prompt = format!(
                    "【轮次 {} 深审输入】\n目标项目根路径: {}\n初审结果 JSON:\n{}\n\n请按附录 B 假设清单逐面做代码级深审，按输出契约给出深审 JSON，phase=deep_review。",
                    state.round_id,
                    target_path.display(),
                    triage_artifact
                );
                let deep_cfg = self.config.pipeline.deep_review.clone();
                let agent = self
                    .build_phase_agent_async(
                        &target_path,
                        Some(JudgeStage::DeepReview),
                        deep_cfg.system_prompt.clone(),
                    )
                    .await?;
                let run = agent.run(&user_prompt, event_tx.clone()).await?;
                extract_json(&run.final_text)?
            }
        };

        // 解析结构化输出并落产物
        let stage_name = stage.name();
        let artifact = self.write_artifact(state, stage_name, &output)?;
        state
            .artifacts
            .insert(stage_name.to_string(), artifact.display().to_string());

        // 深审阶段提取 TP 候选（gate 触发依据）
        if stage == JudgeStage::DeepReview {
            state.tp_candidates = self.config.pipeline.extract_tp_candidates(&output);
            // 执行 Pipeline 配置的额外审计阶段（可产出更多 TP 候选）
            self.run_extra_phases(state, &target_path, event_tx).await?;
        }
        Ok(())
    }

    /// 执行 Pipeline 配置的额外 LLM 审计阶段
    ///
    /// 每个额外阶段独立 prompt / 输出契约，产物写入 `extra_phase_<id>.json`，
    /// TP 候选与深审候选合并后统一进入人工闸门。
    async fn run_extra_phases(
        &self,
        state: &mut RunnerState,
        target_path: &Path,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<(), RunnerError> {
        for phase in self
            .config
            .pipeline
            .extra_phases
            .iter()
            .filter(|p| p.enabled)
        {
            let previous = self.read_artifact(state, "deep_review")?;
            let user_prompt = format!(
                "【轮次 {} 额外审计阶段 {}】
目标项目根路径: {}
深审结果 JSON:
{}

请按输出契约给出结构化 JSON，phase={}。",
                state.round_id,
                phase.id,
                target_path.display(),
                previous,
                phase.id
            );
            let system_prompt = if let Some(ref sp) = phase.system_prompt {
                sp.clone()
            } else if let Some(ref pp) = phase.prompt_path {
                std::fs::read_to_string(pp).map_err(RunnerError::Io)?
            } else {
                self.load_judge_prompt(target_path, JudgeStage::DeepReview)?
            };
            let agent = self
                .build_phase_agent_with_system_prompt(target_path, system_prompt)
                .await?;
            let run = agent.run(&user_prompt, event_tx.clone()).await?;
            let extra_output = extract_json(&run.final_text)?;

            let artifact_key = format!("extra_phase_{}", phase.id);
            let artifact = self.write_artifact(state, &artifact_key, &extra_output)?;
            state
                .artifacts
                .insert(artifact_key.clone(), artifact.display().to_string());

            let contract = phase
                .output
                .clone()
                .unwrap_or_else(|| self.config.pipeline.output.clone());
            let candidates = self
                .config
                .pipeline
                .extract_tp_candidates_with_contract(&extra_output, &contract);
            if !candidates.is_empty() {
                tracing::info!(
                    "额外阶段 {} 产出 {} 个 TP 候选",
                    phase.id,
                    candidates.len()
                );
            }
            state.tp_candidates.extend(candidates);
        }
        Ok(())
    }

    /// 初审：findings 超阈值走子 agent 分片并行（M4），否则单 agent
    async fn run_triage(
        &self,
        state: &mut RunnerState,
        target_path: &Path,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<serde_json::Value, RunnerError> {
        let scan_artifact = self.read_artifact(state, "scan")?;
        let primary_lang = state
            .eligibility
            .as_ref()
            .and_then(|e| e.primary_language.clone())
            .unwrap_or_else(|| "未知".to_string());

        // ── M4 分片判定：findings > subagent_threshold 时按 (漏洞类型, 文件) 分片 ──
        let scan_json: serde_json::Value = serde_json::from_str(&scan_artifact)
            .map_err(|e| RunnerError::Parse(format!("扫描产物 JSON 损坏: {}", e)))?;
        let total = scan_json.get("total").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let findings = scan_json
            .get("findings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let triage_threshold = self
            .config
            .pipeline
            .triage
            .shard_threshold
            .unwrap_or(self.config.subagent_threshold);
        if should_shard(total, triage_threshold) && !findings.is_empty() {
            return self
                .run_triage_sharded(
                    state,
                    target_path,
                    &findings,
                    total,
                    &primary_lang,
                    event_tx,
                )
                .await;
        }

        // ── 单 agent 初审（registry 注册 delegate_triage，LLM 可自主分片） ──
        let user_prompt = format!(
            "【轮次 {} 初审输入】\n目标项目根路径: {}\n主语言: {}\n引擎扫描 findings（JSON）:\n{}\n\n请按输出契约给出初审 JSON，phase=triage。",
            state.round_id,
            target_path.display(),
            primary_lang,
            scan_artifact
        );
        let provider = self.provider.clone().ok_or(RunnerError::ProviderMissing)?;
        let system_prompt = self.load_judge_prompt(target_path, JudgeStage::Triage)?;
        let registry = Arc::new(ToolRegistry::new());
        register_all_tools(
            &registry,
            target_path.to_string_lossy().to_string(),
            None,
            None,
        )
        .await;
        // M4：delegate_triage 工具注册给初审主 agent（子 agent 输出仅作线索，关键判定主 agent 独立复核）
        let spawner = SubAgentSpawner::new(
            Arc::clone(&provider),
            Arc::clone(&registry),
            self.config.approval,
            target_path.to_path_buf(),
            self.config.budget.clone(),
            system_prompt.clone(),
            Some(format!("{}-triage", state.round_id)),
        );
        if let Err(e) = register_delegate_tool(&registry, spawner).await {
            // delegate 注册失败不阻断初审（退回无分片能力的主循环）
            tracing::warn!("delegate_triage 注册失败（初审退化为无分片）: {}", e);
        }
        let adapter = ToolAdapter::new(registry, ToolGate::new(self.config.approval));
        let session = Session::create(target_path)?;
        let agent = Agent::new(
            provider,
            adapter,
            session,
            self.config.budget.clone(),
            Some(system_prompt),
        );
        let run = agent.run(&user_prompt, event_tx.clone()).await?;
        extract_json(&run.final_text)
    }

    /// 初审分片并行（M4）：每片一个子 agent（JoinSet），汇总各片判定进同一 triage 产物
    async fn run_triage_sharded(
        &self,
        state: &RunnerState,
        target_path: &Path,
        findings: &[serde_json::Value],
        total: usize,
        primary_lang: &str,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<serde_json::Value, RunnerError> {
        let provider = self.provider.clone().ok_or(RunnerError::ProviderMissing)?;
        let system_prompt = self.load_judge_prompt(target_path, JudgeStage::Triage)?;
        let triage_threshold = self
            .config
            .pipeline
            .triage
            .shard_threshold
            .unwrap_or(self.config.subagent_threshold);
        let shards = shard_findings(findings, triage_threshold);
        let shard_count = shards.len();
        tracing::info!(
            "轮次 {} 初审分片: {} findings → {} 片并行",
            state.round_id,
            total,
            shard_count
        );
        let _ = event_tx
            .send(AgentEvent::Text {
                delta: format!(
                    "\n[初审分片] {} findings 超过阈值 {}，按 (漏洞类型, 文件) 分为 {} 片并行初审\n",
                    total, triage_threshold, shard_count
                ),
            })
            .await;

        // 子 agent 共享同一 registry（只读工具集），session 带轮次前缀
        let registry = Arc::new(ToolRegistry::new());
        register_all_tools(
            &registry,
            target_path.to_string_lossy().to_string(),
            None,
            None,
        )
        .await;
        let spawner = SubAgentSpawner::new(
            provider,
            registry,
            self.config.approval,
            target_path.to_path_buf(),
            shard_budget(&self.config.budget),
            system_prompt,
            Some(format!("{}-triage", state.round_id)),
        );

        let mut set = tokio::task::JoinSet::new();
        for (i, shard) in shards.into_iter().enumerate() {
            let prompt = format!(
                "【轮次 {} 初审分片 {}/{}】\n目标项目根路径: {}\n主语言: {}\n本分片 findings（JSON，已按漏洞类型+文件分片）:\n{}\n\n请按输出契约给出初审 JSON，phase=triage。只判定本分片内的 findings。",
                state.round_id,
                i + 1,
                shard_count,
                target_path.display(),
                primary_lang,
                serde_json::to_string_pretty(&serde_json::json!({
                    "count": shard.len(),
                    "findings": shard,
                }))
                .unwrap_or_default()
            );
            let spawner = spawner.clone();
            // JoinHandle 再 spawn 进 JoinSet 会多套一层 Result，用 async 块拍平错误
            set.spawn(async move {
                match spawner.spawn(prompt, SubAgentConfig::default()).await {
                    Ok(r) => r.map_err(|e| e.to_string()),
                    Err(e) => Err(format!("分片任务被取消: {}", e)),
                }
            });
        }

        let mut outputs = Vec::new();
        while let Some(res) = set.join_next().await {
            let text = res
                .map_err(|e| RunnerError::Shard(format!("分片 join 失败: {}", e)))?
                .map_err(RunnerError::Shard)?;
            outputs.push(extract_json(&text)?);
        }
        Ok(merge_triage_shards(&state.round_id, outputs))
    }

    // ── 阶段六：登记草稿 ────────────────────────────────

    async fn phase_registration(
        &self,
        state: &mut RunnerState,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<(), RunnerError> {
        let mut draft = self.render_draft_template(state)?;

        // 可选 LLM 润色（Pipeline 配置优先；兼容旧 RunnerConfig 开关）
        if self.config.pipeline.registration.polish_draft || self.config.llm_polish_draft {
            let target_path = state
                .target
                .local_path
                .clone()
                .ok_or_else(|| RunnerError::InvalidState("目标本地路径未解析".into()))?;
            let agent = self
                .build_phase_agent_async(
                    &target_path,
                    None,
                    Some(
                        "你是安全审计报告编辑。只润色文字结构与措辞，不得改动事实、数字、文件路径与行号，输出 Markdown。"
                            .to_string(),
                    ),
                )
                .await?;
            let polish_prompt = format!(
                "请润色以下轮次登记草稿并直接输出 Markdown 全文：\n\n{}",
                draft
            );
            let run = agent.run(&polish_prompt, event_tx.clone()).await?;
            if !run.final_text.trim().is_empty() {
                draft = run.final_text;
            }
        }

        let path = self
            .config
            .state_dir
            .join(format!("draft-{}.md", state.round_id));
        std::fs::write(&path, &draft)?;
        state
            .artifacts
            .insert("registration_draft".to_string(), path.display().to_string());
        Ok(())
    }

    /// 模板渲染登记草稿（默认路径，无需 LLM）
    fn render_draft_template(&self, state: &RunnerState) -> Result<String, RunnerError> {
        let mut out = String::new();
        out.push_str(&format!("# 轮次 {} 登记草稿\n\n", state.round_id));
        out.push_str(&format!("- 目标: {}\n", state.target.input));
        if let Some(ref path) = state.target.local_path {
            out.push_str(&format!("- 本地路径: {}\n", path.display()));
        }
        out.push_str(&format!(
            "- 创建时间: {}\n",
            state.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        if let Some(ref e) = state.eligibility {
            out.push_str(&format!(
                "- 主语言: {}（源码文件 {} 个）\n",
                e.primary_language.as_deref().unwrap_or("未知"),
                e.source_files
            ));
        }

        // 扫描统计
        out.push_str("\n## 扫描\n\n");
        if let Ok(scan) = self.read_artifact(state, "scan") {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&scan) {
                out.push_str(&format!(
                    "- findings 总数: {}\n",
                    v.get("total").and_then(|t| t.as_u64()).unwrap_or(0)
                ));
                if let Some(by_sev) = v.get("by_severity").and_then(|s| s.as_object()) {
                    let parts: Vec<String> =
                        by_sev.iter().map(|(k, v)| format!("{} {}", k, v)).collect();
                    out.push_str(&format!("- 按严重度: {}\n", parts.join(" / ")));
                }
            }
        }

        // 初审/深审摘要
        for (stage, title) in [("triage", "初审"), ("deep_review", "深审")] {
            out.push_str(&format!("\n## {}\n\n", title));
            if let Ok(content) = self.read_artifact(state, stage) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(summary) = v.get("summary").and_then(|s| s.as_object()) {
                        let parts: Vec<String> = summary
                            .iter()
                            .map(|(k, v)| format!("{} {}", k, v))
                            .collect();
                        out.push_str(&format!("- 摘要: {}\n", parts.join(" / ")));
                    }
                    if let Some(arr) = v.get("tp_candidates").and_then(|a| a.as_array()) {
                        out.push_str(&format!("- TP 候选数: {}\n", arr.len()));
                    }
                }
            } else {
                out.push_str("- （未产出）\n");
            }
        }

        // TP 候选与闸门
        out.push_str("\n## TP 判定汇总\n\n");
        if state.tp_candidates.is_empty() {
            out.push_str("- 本轮无 TP 候选（未触发人工闸门）\n");
        } else {
            for (i, c) in state.tp_candidates.iter().enumerate() {
                out.push_str(&format!(
                    "{}. {}（{}）\n",
                    i + 1,
                    c.title,
                    c.cwe.as_deref().unwrap_or("CWE 未标")
                ));
            }
            match &state.gate_decision {
                Some(d) if d.approve => {
                    out.push_str(&format!(
                        "\n- 人工闸门: 通过（TP 认定成立，{}）\n",
                        d.decided_at.format("%Y-%m-%d %H:%M:%S UTC")
                    ));
                }
                Some(_) => {
                    out.push_str("\n- 人工闸门: 驳回（TP 候选不成立）\n");
                }
                None => {
                    out.push_str("\n- 人工闸门: 待决\n");
                }
            }
            if let Some(note) = state.gate_decision.as_ref().and_then(|d| d.note.as_deref()) {
                out.push_str(&format!("- 备注: {}\n", note));
            }
        }

        out.push_str("\n## 下一步建议\n\n");
        if state.tp_candidates.is_empty() {
            out.push_str("- 登记本轮为 0 TP 轮，配置反哺任务时反哺阶段自动执行 CVE 回放\n");
        } else if state
            .gate_decision
            .as_ref()
            .map(|d| d.approve)
            .unwrap_or(false)
        {
            out.push_str("- TP 已经人工认定：按 verify_plan 做实弹验证（M4 livefire），随后走披露流程（人工）\n");
        } else {
            out.push_str("- TP 候选已被人工驳回：归档候选与驳回理由，供 FP 家族附录回流\n");
        }
        out.push_str("\n> 本草稿由 CTX-Audit runner 自动生成，人工审核后方可合入 registry。\n");
        Ok(out)
    }

    // ── 阶段七：反哺（M4 机械层） ───────────────────────

    /// 反哺阶段：0 TP 轮且配置 feedback_tasks 时自动执行 CVE 回放机械层
    ///
    /// 有 TP 候选的轮次反哺走人工流程（跳过）；单任务失败只记录不阻断轮次。
    async fn phase_feedback(
        &self,
        state: &mut RunnerState,
        event_tx: &mpsc::Sender<AgentEvent>,
    ) -> Result<(), RunnerError> {
        if !state.tp_candidates.is_empty() {
            tracing::info!(
                "轮次 {} 含 {} 个 TP 候选，反哺走人工流程，机械层跳过",
                state.round_id,
                state.tp_candidates.len()
            );
            return Ok(());
        }
        if self.config.feedback_tasks.is_empty() {
            tracing::info!("轮次 {} 无反哺任务，跳过", state.round_id);
            return Ok(());
        }

        // 回放工作区：state_dir 的同级 feedback/（state_dir=<cwd>/.ctx-audit/runner
        // → <cwd>/.ctx-audit/feedback）
        let feedback_root = self
            .config
            .state_dir
            .parent()
            .map(|p| p.join("feedback"))
            .unwrap_or_else(|| self.config.state_dir.join("feedback"));

        let mut errors = Vec::new();
        for task in &self.config.feedback_tasks {
            let _ = event_tx
                .send(AgentEvent::Text {
                    delta: format!("\n[反哺] 开始回放 {}（{}）\n", task.cve_id, task.git_url),
                })
                .await;
            match crate::feedback::run_replay(task, &feedback_root).await {
                Ok((report, path)) => {
                    let _ = event_tx
                        .send(AgentEvent::Text {
                            delta: format!(
                                "[反哺] {} 结论: {}（漏洞版命中={} 修复版豁免={}）\n",
                                task.cve_id,
                                report.verdict.conclusion,
                                report.verdict.vulnerable_hit_expected,
                                report.verdict.fixed_exempt
                            ),
                        })
                        .await;
                    state.artifacts.insert(
                        format!("feedback_report:{}", task.cve_id),
                        path.display().to_string(),
                    );
                }
                Err(e) => {
                    // 单任务失败不阻断轮次：记录后继续
                    tracing::warn!(
                        "轮次 {} 反哺任务 {} 失败: {}",
                        state.round_id,
                        task.cve_id,
                        e
                    );
                    errors.push(format!("{}: {}", task.cve_id, e));
                }
            }
        }
        if !errors.is_empty() {
            let artifact = self.write_artifact(state, "feedback_errors", &errors)?;
            state.artifacts.insert(
                "feedback_errors".to_string(),
                artifact.display().to_string(),
            );
        }
        Ok(())
    }

    // ── 人工闸门 ────────────────────────────────────────

    /// 进入闸门：写通知文件 + 可选 webhook，状态置 AwaitHuman
    async fn enter_gate(&self, state: &mut RunnerState) -> Result<(), RunnerError> {
        let notice = GateNotice {
            round_id: state.round_id.clone(),
            target: state.target.input.clone(),
            phase: "deep_review".to_string(),
            tp_candidates: state.tp_candidates.clone(),
            evidence_summary: gate::build_evidence_summary(&state.tp_candidates),
            artifacts: state.artifacts.clone(),
            created_at: Utc::now(),
        };
        let path = gate::write_notice(&self.config.state_dir, &notice)?;
        state
            .artifacts
            .insert("gate_notice".to_string(), path.display().to_string());

        if let Some(ref url) = self.config.webhook_url {
            if let Err(e) = gate::send_webhook(url, &notice).await {
                // webhook 失败不阻断轮次，通知文件已落地
                tracing::warn!("gate webhook 发送失败（已降级为文件通知）: {}", e);
            }
        }

        state.completed.push(state.current_phase);
        state.current_phase = RoundPhase::AwaitHuman;
        state.last_error = None;
        self.save_state(state)?;
        tracing::info!(
            "轮次 {} 检出 {} 个 TP 候选，进入人工闸门: {}",
            state.round_id,
            state.tp_candidates.len(),
            path.display()
        );
        Ok(())
    }

    // ── 判定层 prompt 加载 ──────────────────────────────

    /// 加载判定层 system prompt
    ///
    /// 优先级：
    /// 1. `RunnerConfig.judge_prompt_path`（兼容旧配置/测试）
    /// 2. `PipelineConfig.{triage,deep_review}.system_prompt`（纯文本覆盖）
    /// 3. `PipelineConfig.{triage,deep_review}.prompt_path`（配置文件）
    /// 4. 默认相对路径 `docs/audit-rounds/automation/round-agent.md`（目标项目内 > 当前工作目录）
    pub(crate) fn load_judge_prompt(
        &self,
        target_path: &Path,
        stage: JudgeStage,
    ) -> Result<String, RunnerError> {
        const REL: &str = "docs/audit-rounds/automation/round-agent.md";
        let cfg = match stage {
            JudgeStage::Triage => &self.config.pipeline.triage,
            JudgeStage::DeepReview => &self.config.pipeline.deep_review,
        };

        // 纯文本 system prompt 覆盖：最高优先（无需读文件）
        if let Some(ref prompt) = cfg.system_prompt {
            return Ok(prompt.clone());
        }

        let mut searched = Vec::new();

        // 兼容旧配置的显式 prompt 路径
        if let Some(ref explicit) = self.config.judge_prompt_path {
            searched.push(explicit.clone());
            if explicit.is_file() {
                return Ok(std::fs::read_to_string(explicit)?);
            }
        }
        // 流水线阶段的显式 prompt 路径
        if let Some(ref explicit) = cfg.prompt_path {
            searched.push(explicit.clone());
            if explicit.is_file() {
                return Ok(std::fs::read_to_string(explicit)?);
            }
        }
        let in_target = target_path.join(REL);
        searched.push(in_target.clone());
        if in_target.is_file() {
            return Ok(std::fs::read_to_string(&in_target)?);
        }
        if let Ok(cwd) = std::env::current_dir() {
            let in_cwd = cwd.join(REL);
            searched.push(in_cwd.clone());
            if in_cwd.is_file() {
                return Ok(std::fs::read_to_string(&in_cwd)?);
            }
        }

        Err(RunnerError::PromptMissing(format!(
            "判定层 prompt 未找到，已搜索: {}",
            searched
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )))
    }

    /// 构建 LLM 阶段 Agent（async 版：注册工具需要 await）
    async fn build_phase_agent_async(
        &self,
        target_path: &Path,
        stage: Option<JudgeStage>,
        system_prompt_override: Option<String>,
    ) -> Result<Agent, RunnerError> {
        let system_prompt = match system_prompt_override {
            Some(p) => p,
            None => {
                let stage = stage
                    .ok_or_else(|| RunnerError::InvalidState("缺少判定阶段参数".to_string()))?;
                self.load_judge_prompt(target_path, stage)?
            }
        };
        self.build_phase_agent_with_system_prompt(target_path, system_prompt)
            .await
    }

    /// 使用指定 system prompt 构建 LLM 阶段 Agent（额外阶段复用）
    async fn build_phase_agent_with_system_prompt(
        &self,
        target_path: &Path,
        system_prompt: String,
    ) -> Result<Agent, RunnerError> {
        let provider = self.provider.clone().ok_or(RunnerError::ProviderMissing)?;

        let registry = Arc::new(ToolRegistry::new());
        register_all_tools(
            &registry,
            target_path.to_string_lossy().to_string(),
            None,
            None,
        )
        .await;
        let adapter = ToolAdapter::new(registry, ToolGate::new(self.config.approval));
        let session = Session::create(target_path)?;
        Ok(Agent::new(
            provider,
            adapter,
            session,
            self.config.budget.clone(),
            Some(system_prompt),
        ))
    }

    // ── 状态持久化 ──────────────────────────────────────

    /// 单轮状态文件路径
    pub fn state_path(state_dir: &Path, round_id: &str) -> PathBuf {
        state_dir.join(format!("runner-state-{}.json", round_id))
    }

    /// 保存状态（每阶段完成即写；同时刷新 runner-state.json 指向最新一轮）
    pub fn save_state(&self, state: &RunnerState) -> Result<(), RunnerError> {
        let mut state = state.clone();
        state.updated_at = Utc::now();
        std::fs::create_dir_all(&self.config.state_dir)?;
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let path = Self::state_path(&self.config.state_dir, &state.round_id);
        std::fs::write(&path, &json)?;
        // 兼容 spec 路径：runner-state.json 始终指向最新一轮
        std::fs::write(self.config.state_dir.join("runner-state.json"), &json)?;
        Ok(())
    }

    /// 加载轮状态
    pub fn load_state(state_dir: &Path, round_id: &str) -> Result<RunnerState, RunnerError> {
        let path = Self::state_path(state_dir, round_id);
        if !path.exists() {
            return Err(RunnerError::StateNotFound(format!(
                "{}（{}）",
                round_id,
                path.display()
            )));
        }
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str(&content)
            .map_err(|e| RunnerError::Parse(format!("状态文件损坏 {}: {}", path.display(), e)))
    }

    /// 列出全部轮状态（按更新时间倒序）
    pub fn list_states(state_dir: &Path) -> Vec<RunnerState> {
        let mut states = Vec::new();
        if let Ok(entries) = std::fs::read_dir(state_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("runner-state-") && name.ends_with(".json") {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(state) = serde_json::from_str::<RunnerState>(&content) {
                            states.push(state);
                        }
                    }
                }
            }
        }
        states.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        states
    }

    // ── 产物读写 ────────────────────────────────────────

    /// 写阶段产物 JSON：<state_dir>/<stage>-<round_id>.json
    fn write_artifact<T: Serialize>(
        &self,
        state: &RunnerState,
        stage: &str,
        value: &T,
    ) -> Result<PathBuf, RunnerError> {
        std::fs::create_dir_all(&self.config.state_dir)?;
        let path = self
            .config
            .state_dir
            .join(format!("{}-{}.json", stage, state.round_id));
        let json = serde_json::to_string_pretty(value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// 读阶段产物文本
    fn read_artifact(&self, state: &RunnerState, stage: &str) -> Result<String, RunnerError> {
        let path = state.artifacts.get(stage).ok_or_else(|| {
            RunnerError::InvalidState(format!("轮次 {} 缺少 {} 阶段产物", state.round_id, stage))
        })?;
        Ok(std::fs::read_to_string(path)?)
    }
}

/// 判定阶段（初审/深审）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JudgeStage {
    Triage,
    DeepReview,
}

impl JudgeStage {
    fn name(&self) -> &'static str {
        match self {
            JudgeStage::Triage => "triage",
            JudgeStage::DeepReview => "deep_review",
        }
    }
}

// ── 工具函数 ────────────────────────────────────────────

/// 判断目标是否为 git URL
pub fn is_git_url(target: &str) -> bool {
    target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("git@")
        || target.ends_with(".git")
}

/// 从 git URL 提取仓库名
pub fn repo_name_from_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    let name = trimmed.rsplit(['/', ':']).next().unwrap_or("target");
    name.trim_end_matches(".git").to_string()
}

/// 从 agent 最终文本提取 JSON（容忍 ```json 围栏与前后散文）
pub fn extract_json(text: &str) -> Result<serde_json::Value, RunnerError> {
    let stripped = text
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();
    // 先尝试整体解析，失败则取首尾花括号区间
    if let Ok(v) = serde_json::from_str(stripped) {
        return Ok(v);
    }
    let start = stripped.find('{');
    let end = stripped.rfind('}');
    match (start, end) {
        (Some(s), Some(e)) if s < e => serde_json::from_str(&stripped[s..=e]).map_err(|e| {
            RunnerError::Parse(format!(
                "{}（原文前 200 字符: {}）",
                e,
                &stripped.chars().take(200).collect::<String>()
            ))
        }),
        _ => Err(RunnerError::Parse(format!(
            "输出中未找到 JSON 对象（原文前 200 字符: {}）",
            stripped.chars().take(200).collect::<String>()
        ))),
    }
}

/// 初审分片判定（M4）：findings 总数 > 阈值时启用分片（0 = 禁用）
pub fn should_shard(total: usize, threshold: usize) -> bool {
    threshold > 0 && total > threshold
}

/// 按 (vuln_type, file_path) 分组后轮询装入分片（组不拆散，保证同文件同类型的
/// findings 完整落在同一片内）
pub fn shard_findings(
    findings: &[serde_json::Value],
    threshold: usize,
) -> Vec<Vec<serde_json::Value>> {
    let mut groups: BTreeMap<(String, String), Vec<serde_json::Value>> = BTreeMap::new();
    for f in findings {
        let key = (
            f.get("vuln_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            f.get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
        );
        groups.entry(key).or_default().push(f.clone());
    }

    let shard_count = findings
        .len()
        .div_ceil(threshold.max(1))
        .max(1)
        .min(groups.len().max(1));
    let mut shards: Vec<Vec<serde_json::Value>> = (0..shard_count).map(|_| Vec::new()).collect();
    for (i, (_, group)) in groups.into_iter().enumerate() {
        shards[i % shard_count].extend(group);
    }
    shards.retain(|s| !s.is_empty());
    shards
}

/// 汇总各分片的初审 JSON 为单一 triage 产物：
/// summary 数值字段求和，tp_candidates / fp_families 数组拼接
fn merge_triage_shards(round_id: &str, outputs: Vec<serde_json::Value>) -> serde_json::Value {
    let mut summary: BTreeMap<String, u64> = BTreeMap::new();
    let mut tp_candidates = Vec::new();
    let mut fp_families = Vec::new();
    let shard_count = outputs.len();

    for out in outputs {
        if let Some(obj) = out.get("summary").and_then(|s| s.as_object()) {
            for (k, v) in obj {
                if let Some(n) = v.as_u64() {
                    *summary.entry(k.clone()).or_insert(0) += n;
                }
            }
        }
        if let Some(arr) = out.get("tp_candidates").and_then(|a| a.as_array()) {
            tp_candidates.extend(arr.iter().cloned());
        }
        if let Some(arr) = out.get("fp_families").and_then(|a| a.as_array()) {
            fp_families.extend(arr.iter().cloned());
        }
    }

    serde_json::json!({
        "round": round_id,
        "phase": "triage",
        "sharded": true,
        "shard_count": shard_count,
        "summary": summary,
        "tp_candidates": tp_candidates,
        "fp_families": fp_families,
    })
}

/// 初审分片子 agent 预算：max_turns 上限 10（分片任务应短小）
fn shard_budget(base: &AgentBudget) -> AgentBudget {
    let mut budget = base.clone();
    budget.max_turns = budget.max_turns.min(10);
    budget
}

/// 构建扫描产物 JSON（findings 简化版，上限 100 条，供初审输入）
/// 严重度排序比较：actual 是否 >= min
fn severity_at_least(actual: &str, min: &str) -> bool {
    fn rank(s: &str) -> u8 {
        match s.to_ascii_lowercase().as_str() {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        }
    }
    rank(actual) >= rank(min)
}

fn build_scan_artifact(target: &str, findings: &[Finding]) -> serde_json::Value {
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        *by_severity.entry(f.severity.clone()).or_insert(0) += 1;
    }
    let simplified: Vec<serde_json::Value> = findings
        .iter()
        .take(100)
        .map(|f| {
            serde_json::json!({
                "file_path": f.file_path,
                "line_start": f.line_start,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "code_snippet": f.code_snippet.as_ref().map(|s| s.chars().take(300).collect::<String>()),
                "enclosing_function": f.enclosing_function,
            })
        })
        .collect();
    serde_json::json!({
        "target": target,
        "scanned_at": Utc::now().to_rfc3339(),
        "total": findings.len(),
        "truncated_to": simplified.len(),
        "by_severity": by_severity,
        "findings": simplified,
    })
}

/// 跳过统计的目录
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".next",
    ".ctx-audit",
];

/// 扩展名 → 语言名
fn language_of(ext: &str) -> Option<&'static str> {
    Some(match ext {
        "js" | "jsx" | "mjs" | "cjs" => "JavaScript",
        "ts" | "tsx" => "TypeScript",
        "py" => "Python",
        "java" => "Java",
        "rs" => "Rust",
        "go" => "Go",
        "c" | "h" => "C",
        "cc" | "cpp" | "cxx" | "hpp" => "C++",
        "php" => "PHP",
        "rb" => "Ruby",
        "cs" => "C#",
        "vue" => "Vue",
        "html" | "htm" => "HTML",
        _ => return None,
    })
}

/// 递归统计源码文件（限深 12 层）
fn walk_sources(dir: &Path, languages: &mut BTreeMap<String, usize>, depth: usize) {
    if depth > 12 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                walk_sources(&path, languages, depth + 1);
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if let Some(lang) = language_of(&ext.to_lowercase()) {
                *languages.entry(lang.to_string()).or_insert(0) += 1;
            }
        }
    }
}

// ── 测试 ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use crate::provider::{ChatRequest, ChatResponse, ProviderError, Usage};

    // ── MockProvider：脚本化响应队列（支持脚本化错误） ──

    struct MockProvider {
        responses: Mutex<VecDeque<Result<ChatResponse, ProviderError>>>,
        requests: Mutex<Vec<ChatRequest>>,
    }

    impl MockProvider {
        fn new(responses: Vec<Result<ChatResponse, ProviderError>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn json_text(json: serde_json::Value) -> ChatResponse {
            ChatResponse {
                content: serde_json::to_string_pretty(&json).unwrap(),
                tool_calls: vec![],
                usage: Some(Usage {
                    prompt_tokens: 10,
                    completion_tokens: 5,
                    total_tokens: 15,
                }),
                finish_reason: Some("stop".to_string()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl LLMProvider for MockProvider {
        async fn chat(
            &self,
            request: &ChatRequest,
            _event_tx: Option<mpsc::Sender<AgentEvent>>,
        ) -> Result<ChatResponse, ProviderError> {
            self.requests.lock().unwrap().push(request.clone());
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock 脚本耗尽")
        }

        fn model_name(&self) -> String {
            "mock-judge".to_string()
        }
    }

    // ── 测试基建 ──

    struct TestEnv {
        root: PathBuf,
        target: PathBuf,
        state_dir: PathBuf,
    }

    /// 造一个带命令注入的迷你 JS 项目 + 判定层 prompt
    fn make_env(tag: &str) -> TestEnv {
        let root = std::env::temp_dir().join(format!(
            "ctx-audit-runner-test-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        let target = root.join("target");
        let state_dir = root.join("runner");
        std::fs::create_dir_all(target.join("src")).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();

        // 命令注入源码（确定性触发引擎规则）
        std::fs::write(
            target.join("src/index.js"),
            "const { exec } = require('child_process');\n\
             const cmd = process.argv[2];\n\
             exec('ping ' + cmd, (err, out) => console.log(out));\n",
        )
        .unwrap();
        std::fs::write(
            target.join("package.json"),
            r#"{"name":"fake-target","version":"0.1.0"}"#,
        )
        .unwrap();

        // 迷你判定层 prompt
        std::fs::write(
            root.join("round-agent.md"),
            "你是 CTX-Audit 判定层。输出只许 JSON。",
        )
        .unwrap();

        TestEnv {
            root,
            target,
            state_dir,
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    fn make_runner(env: &TestEnv, provider: Option<Arc<dyn LLMProvider>>) -> Runner {
        Runner::new(
            RunnerConfig {
                state_dir: env.state_dir.clone(),
                judge_prompt_path: Some(env.root.join("round-agent.md")),
                ..RunnerConfig::default()
            },
            provider,
        )
    }

    fn triage_json_no_tp() -> serde_json::Value {
        serde_json::json!({
            "round": "T", "phase": "triage",
            "summary": {"tp_candidates": 0, "fp": 1, "hardening": 0},
            "fp_families": [{"family": "测试 fixture", "count": 1, "reason": "示例", "examples": []}]
        })
    }

    fn deep_review_json_no_tp() -> serde_json::Value {
        serde_json::json!({
            "round": "T", "phase": "deep_review",
            "summary": {"tp_candidates": 0, "fp": 1, "hardening": 0},
            "deep_review_suggestions": []
        })
    }

    fn deep_review_json_with_tp() -> serde_json::Value {
        serde_json::json!({
            "round": "T", "phase": "deep_review",
            "summary": {"tp_candidates": 1, "fp": 0, "hardening": 0},
            "tp_candidates": [{
                "title": "命令注入",
                "cwe": "CWE-78",
                "chain": ["源 src/index.js:2", "sink src/index.js:3"],
                "scenario": "攻击者控制 argv",
                "verified": false,
                "verify_plan": "本地实跑"
            }]
        })
    }

    // ── 资格核实 ──

    #[test]
    fn test_eligibility_report() {
        let env = make_env("elig");
        let report = Runner::check_eligibility(&env.target);
        assert!(report.eligible);
        assert!(report.path_exists);
        assert!(!report.is_git_repo);
        assert!(report.source_files >= 1);
        assert_eq!(report.primary_language.as_deref(), Some("JavaScript"));
        assert!(report.reasons.iter().any(|r| r.contains("源码文件")));

        // 空目录无资格
        let empty = env.root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let report = Runner::check_eligibility(&empty);
        assert!(!report.eligible);
        assert!(report.reasons.iter().any(|r| r.contains("未发现源码文件")));
    }

    // ── git URL 工具函数 ──

    #[test]
    fn test_git_url_helpers() {
        assert!(is_git_url("https://github.com/a/b"));
        assert!(is_git_url("git@github.com:a/b.git"));
        assert!(is_git_url("https://x.com/a/b.git"));
        assert!(!is_git_url("/tmp/proj"));
        assert!(!is_git_url("C:\\proj"));

        assert_eq!(repo_name_from_url("https://github.com/a/b"), "b");
        assert_eq!(repo_name_from_url("git@github.com:a/b.git"), "b");
        assert_eq!(repo_name_from_url("https://x.com/a/b.git/"), "b");
    }

    // ── JSON 提取 ──

    #[test]
    fn test_extract_json() {
        assert!(extract_json(r#"{"a":1}"#).is_ok());
        assert!(extract_json("```json\n{\"a\":1}\n```").is_ok());
        let v = extract_json("前言\n{\"a\":1}\n后记").unwrap();
        assert_eq!(v["a"], 1);
        assert!(extract_json("没有 JSON").is_err());
    }

    // ── 状态机：中断续跑（真扫描 + MockProvider 判定） ──

    #[tokio::test]
    async fn test_state_machine_crash_and_resume() {
        let env = make_env("resume");

        // 第一次运行：初审阶段 provider 故障 → 断在 triage
        let failing = MockProvider::new(vec![Err(ProviderError::Api("模拟中断".into()))]);
        let runner1 = make_runner(&env, Some(failing));
        let (tx, _rx) = mpsc::channel(256);
        let err = runner1
            .run(env.target.to_str().unwrap(), Some("R1".to_string()), tx)
            .await
            .expect_err("初审应失败");
        assert!(err.to_string().contains("模拟中断") || err.to_string().contains("provider"));

        // 状态文件：停在 triage，前三个阶段已完成
        let state = Runner::load_state(&env.state_dir, "R1").unwrap();
        assert_eq!(state.current_phase, RoundPhase::Triage);
        assert_eq!(
            state.completed,
            vec![
                RoundPhase::SelectTarget,
                RoundPhase::Eligibility,
                RoundPhase::Scan
            ]
        );
        assert!(state.last_error.is_some());
        assert!(state.artifacts.contains_key("scan"));

        // 扫描产物真实存在且有 findings（命令注入 JS）
        let scan_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state.artifacts["scan"]).unwrap())
                .unwrap();
        assert!(
            scan_json["total"].as_u64().unwrap() >= 1,
            "命令注入 JS 应被引擎扫出: {}",
            scan_json
        );
        let scan_mtime = std::fs::metadata(&state.artifacts["scan"])
            .unwrap()
            .modified()
            .unwrap();

        // 兼容 spec 路径：runner-state.json 指向最新轮
        assert!(env.state_dir.join("runner-state.json").exists());

        // 第二次运行：同轮次续跑，判定阶段正常 → 一路到 Done
        let good = MockProvider::new(vec![
            Ok(MockProvider::json_text(triage_json_no_tp())),
            Ok(MockProvider::json_text(deep_review_json_no_tp())),
        ]);
        let good_ref = good.clone();
        let runner2 = make_runner(&env, Some(good));
        let (tx, _rx) = mpsc::channel(256);
        let state = runner2
            .run(env.target.to_str().unwrap(), Some("R1".to_string()), tx)
            .await
            .expect("续跑应成功");

        assert_eq!(state.current_phase, RoundPhase::Done);
        assert_eq!(good_ref.request_count(), 2, "只应补跑初审+深审两轮 LLM");
        assert!(state.artifacts.contains_key("registration_draft"));
        assert!(state.last_error.is_none());

        // 断点续跑不重扫：scan 产物未变
        let new_mtime = std::fs::metadata(&state.artifacts["scan"])
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(scan_mtime, new_mtime, "续跑不应重扫");

        // 登记草稿内容
        let draft = std::fs::read_to_string(&state.artifacts["registration_draft"]).unwrap();
        assert!(draft.contains("轮次 R1 登记草稿"));
        assert!(draft.contains("本轮无 TP 候选"));
    }

    // ── gate 流程：approve 分支 ──

    #[tokio::test]
    async fn test_gate_flow_approve() {
        let env = make_env("approve");
        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(serde_json::json!({
                "phase": "triage",
                "summary": {"tp_candidates": 1, "fp": 0, "hardening": 0}
            }))),
            Ok(MockProvider::json_text(deep_review_json_with_tp())),
        ]);
        let runner = make_runner(&env, Some(mock));
        let (tx, _rx) = mpsc::channel(256);

        // 跑到闸门
        let state = runner
            .run(env.target.to_str().unwrap(), Some("R2".to_string()), tx)
            .await
            .expect("应正常进入闸门");
        assert_eq!(state.current_phase, RoundPhase::AwaitHuman);
        assert_eq!(state.tp_candidates.len(), 1);
        assert_eq!(state.tp_candidates[0].title, "命令注入");

        // gate 通知文件
        let notice_path = gate::notice_path(&env.state_dir, "R2");
        assert!(notice_path.exists());
        let notice: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&notice_path).unwrap()).unwrap();
        assert_eq!(notice["tp_candidates"][0]["cwe"], "CWE-78");
        assert!(notice["evidence_summary"]
            .as_str()
            .unwrap()
            .contains("src/index.js"));

        // resume 在闸门未决时不推进
        let (tx, _rx) = mpsc::channel(256);
        let state = runner.resume("R2", tx).await.unwrap();
        assert_eq!(state.current_phase, RoundPhase::AwaitHuman);

        // approve → 登记草稿 → Done
        let (tx, _rx) = mpsc::channel(256);
        let state = runner
            .gate_decide("R2", true, Some("人工确认成立".to_string()), tx)
            .await
            .expect("approve 后应完成");
        assert_eq!(state.current_phase, RoundPhase::Done);
        assert!(state.gate_decision.unwrap().approve);

        // 决策文件与草稿
        assert!(gate::decision_path(&env.state_dir, "R2").exists());
        let draft = std::fs::read_to_string(&state.artifacts["registration_draft"]).unwrap();
        assert!(draft.contains("人工闸门: 通过"));
        assert!(draft.contains("人工确认成立"));
    }

    // ── gate 流程：reject 分支 ──

    #[tokio::test]
    async fn test_gate_flow_reject() {
        let env = make_env("reject");
        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(serde_json::json!({
                "phase": "triage", "summary": {}
            }))),
            Ok(MockProvider::json_text(deep_review_json_with_tp())),
        ]);
        let runner = make_runner(&env, Some(mock));
        let (tx, _rx) = mpsc::channel(256);
        runner
            .run(env.target.to_str().unwrap(), Some("R3".to_string()), tx)
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel(256);
        let state = runner
            .gate_decide("R3", false, Some("证据不足".to_string()), tx)
            .await
            .expect("reject 后应完成");
        assert_eq!(state.current_phase, RoundPhase::Done);

        let draft = std::fs::read_to_string(&state.artifacts["registration_draft"]).unwrap();
        assert!(draft.contains("人工闸门: 驳回"));
        assert!(draft.contains("证据不足"));
    }

    // ── gate 决策状态校验 ──

    #[tokio::test]
    async fn test_gate_decide_requires_await_human() {
        let env = make_env("gatecheck");
        let runner = make_runner(&env, None);
        let (tx, _rx) = mpsc::channel(256);
        let err = runner
            .gate_decide("NO_SUCH_ROUND", true, None, tx)
            .await
            .expect_err("不存在的轮次应报错");
        assert!(matches!(err, RunnerError::StateNotFound(_)));
    }

    // ── 目标不一致防护 ──

    #[tokio::test]
    async fn test_run_rejects_mismatched_target() {
        let env = make_env("mismatch");
        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(triage_json_no_tp())),
            Ok(MockProvider::json_text(deep_review_json_no_tp())),
        ]);
        let runner = make_runner(&env, Some(mock));
        let (tx, _rx) = mpsc::channel(256);
        runner
            .run(env.target.to_str().unwrap(), Some("R4".to_string()), tx)
            .await
            .unwrap();

        let (tx, _rx) = mpsc::channel(256);
        let err = runner
            .run("/some/other/path", Some("R4".to_string()), tx)
            .await
            .expect_err("目标不一致应报错");
        assert!(matches!(err, RunnerError::InvalidState(_)));
    }

    // ── 状态列表 ──

    #[tokio::test]
    async fn test_list_states() {
        let env = make_env("list");
        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(triage_json_no_tp())),
            Ok(MockProvider::json_text(deep_review_json_no_tp())),
        ]);
        let runner = make_runner(&env, Some(mock));
        let (tx, _rx) = mpsc::channel(256);
        runner
            .run(env.target.to_str().unwrap(), Some("R5".to_string()), tx)
            .await
            .unwrap();

        let states = Runner::list_states(&env.state_dir);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].round_id, "R5");
        assert_eq!(states[0].current_phase, RoundPhase::Done);
    }

    // ── M4：初审分片阈值判定 ──

    #[test]
    fn test_shard_threshold_decision() {
        // 51 触发分片，50 不触发（默认阈值 50）
        assert!(should_shard(51, 50));
        assert!(!should_shard(50, 50));
        assert!(!should_shard(51, 0), "阈值 0 = 禁用分片");

        // 51 findings 分 3 个 (类型,文件) 组 → 2 片，组不拆散
        let findings: Vec<serde_json::Value> = (0..51)
            .map(|i| {
                serde_json::json!({
                    "vuln_type": "CWE-78",
                    "file_path": format!("f{}.js", i % 3),
                    "line_start": i,
                })
            })
            .collect();
        let shards = shard_findings(&findings, 50);
        assert_eq!(shards.len(), 2);
        assert_eq!(shards.iter().map(|s| s.len()).sum::<usize>(), 51);
        for file in ["f0.js", "f1.js", "f2.js"] {
            let per_shard: Vec<usize> = shards
                .iter()
                .map(|s| s.iter().filter(|f| f["file_path"] == file).count())
                .collect();
            assert!(
                per_shard.iter().any(|&c| c == 0),
                "组 {} 被拆散: {:?}",
                file,
                per_shard
            );
        }
    }

    // ── M4：初审分片并行（预置 51 findings 扫描产物 → 3 片子 agent） ──

    #[tokio::test]
    async fn test_triage_sharded_parallel() {
        let env = make_env("sharded");

        // 预置状态：断点在初审，扫描产物为合成的 51 findings（3 个 (类型,文件) 组）
        let findings: Vec<serde_json::Value> = (0..51)
            .map(|i| {
                serde_json::json!({
                    "vuln_type": "CWE-78",
                    "file_path": format!("src/f{}.js", i % 3),
                    "line_start": i + 1,
                    "severity": "high",
                })
            })
            .collect();
        let scan_artifact = env.state_dir.join("scan-RS.json");
        std::fs::write(
            &scan_artifact,
            serde_json::to_string_pretty(&serde_json::json!({
                "target": env.target.to_string_lossy(),
                "total": 51,
                "findings": findings,
            }))
            .unwrap(),
        )
        .unwrap();
        let mut artifacts = BTreeMap::new();
        artifacts.insert("scan".to_string(), scan_artifact.display().to_string());
        let state = RunnerState {
            round_id: "RS".to_string(),
            target: TargetInfo {
                input: env.target.to_string_lossy().to_string(),
                local_path: Some(env.target.clone()),
                is_git_url: false,
                cloned: false,
            },
            current_phase: RoundPhase::Triage,
            completed: vec![
                RoundPhase::SelectTarget,
                RoundPhase::Eligibility,
                RoundPhase::Scan,
            ],
            artifacts,
            eligibility: None,
            tp_candidates: Vec::new(),
            gate_decision: None,
            last_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // mock：3 片初审（各 fp:1）+ 1 深审
        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(serde_json::json!({
                "phase": "triage", "summary": {"tp_candidates": 0, "fp": 1}
            }))),
            Ok(MockProvider::json_text(serde_json::json!({
                "phase": "triage", "summary": {"tp_candidates": 0, "fp": 1}
            }))),
            Ok(MockProvider::json_text(serde_json::json!({
                "phase": "triage", "summary": {"tp_candidates": 0, "fp": 1}
            }))),
            Ok(MockProvider::json_text(deep_review_json_no_tp())),
        ]);
        let mock_ref = mock.clone();
        let runner = Runner::new(
            RunnerConfig {
                state_dir: env.state_dir.clone(),
                judge_prompt_path: Some(env.root.join("round-agent.md")),
                subagent_threshold: 25, // 51 > 25 → ceil(51/25) = 3 片
                ..RunnerConfig::default()
            },
            Some(mock),
        );
        runner.save_state(&state).unwrap();

        let (tx, _rx) = mpsc::channel(256);
        let state = runner
            .run(env.target.to_str().unwrap(), Some("RS".to_string()), tx)
            .await
            .expect("分片初审应成功");

        assert_eq!(state.current_phase, RoundPhase::Done);
        // 3 片初审 + 1 深审 = 4 次 LLM 调用
        assert_eq!(mock_ref.request_count(), 4);

        // 汇总后的 triage 产物：分片标记 + summary 求和
        let triage: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state.artifacts["triage"]).unwrap())
                .unwrap();
        assert_eq!(triage["sharded"], true);
        assert_eq!(triage["shard_count"], 3);
        assert_eq!(triage["summary"]["fp"], 3, "3 片各 fp:1，求和应为 3");

        // 前 3 次请求为分片初审 prompt，第 4 次为深审
        let requests = mock_ref.requests.lock().unwrap();
        for req in &requests[..3] {
            let user = req.messages[1].content.as_deref().unwrap();
            assert!(
                user.contains("初审分片"),
                "应为分片初审 prompt: {}",
                &user[..80]
            );
        }
        let deep = requests[3].messages[1].content.as_deref().unwrap();
        assert!(deep.contains("深审输入"));
    }

    // ── M4：0 TP 轮自动执行反哺阶段 ──

    /// 造本地 CVE 仓库（漏洞 commit 含 python 命令注入，修复 commit 移除）
    fn make_cve_repo(root: &Path, cve_id: &str) -> crate::feedback::FeedbackTask {
        let repo_src = root.join("cve-repo-src");
        std::fs::create_dir_all(&repo_src).unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(&repo_src)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .expect("git 应可执行");
            assert!(
                output.status.success(),
                "git {:?} 失败: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        };
        git(&["init", "--quiet"]);
        std::fs::write(
            repo_src.join("app.py"),
            "import os\ncmd = input('cmd:')\nos.system(cmd)\n",
        )
        .unwrap();
        git(&["-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"]);
        git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "--quiet",
            "-m",
            "vulnerable",
        ]);
        let vulnerable_ref = git(&["rev-parse", "HEAD"]);
        std::fs::write(repo_src.join("app.py"), "print('fixed')\n").unwrap();
        git(&["-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"]);
        git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "--quiet",
            "-m",
            "fix",
        ]);
        let fixed_ref = git(&["rev-parse", "HEAD"]);

        crate::feedback::FeedbackTask {
            cve_id: cve_id.to_string(),
            git_url: repo_src.to_string_lossy().to_string(),
            vulnerable_ref,
            fixed_ref,
            expected_rule_ids: vec!["command-injection".to_string()],
            expected_vuln_types: vec!["CWE-78".to_string()],
        }
    }

    #[tokio::test]
    async fn test_zero_tp_round_auto_feedback() {
        let env = make_env("feedback");
        let task = make_cve_repo(&env.root, "CVE-TEST-RUNNER");

        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(triage_json_no_tp())),
            Ok(MockProvider::json_text(deep_review_json_no_tp())),
        ]);
        let runner = Runner::new(
            RunnerConfig {
                state_dir: env.state_dir.clone(),
                judge_prompt_path: Some(env.root.join("round-agent.md")),
                feedback_tasks: vec![task],
                ..RunnerConfig::default()
            },
            Some(mock),
        );

        let (tx, _rx) = mpsc::channel(256);
        let state = runner
            .run(env.target.to_str().unwrap(), Some("RF".to_string()), tx)
            .await
            .expect("0 TP 轮应自动完成反哺闭环");

        assert_eq!(state.current_phase, RoundPhase::Done);
        assert!(
            state.completed.contains(&RoundPhase::Feedback),
            "反哺阶段应已执行: {:?}",
            state.completed
        );

        // 报告产物存在且结论正确（漏洞版命中、修复版豁免 → pass）
        let report_path = state
            .artifacts
            .get("feedback_report:CVE-TEST-RUNNER")
            .expect("应产出反哺报告");
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(report_path).unwrap()).unwrap();
        assert_eq!(report["verdict"]["conclusion"], "pass");
        assert_eq!(report["verdict"]["vulnerable_hit_expected"], true);
        assert_eq!(report["verdict"]["fixed_exempt"], true);
    }

    /// Pipeline 可完全关闭 LLM 判定阶段：无 provider 也能跑完整状态机
    #[tokio::test]
    async fn test_pipeline_disabled_llm_phases_skip_provider() {
        let env = make_env("pipeline-disabled");
        let pipeline = crate::pipeline::PipelineConfig {
            triage: crate::pipeline::JudgeConfig {
                enabled: false,
                ..Default::default()
            },
            deep_review: crate::pipeline::JudgeConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        let runner = Runner::new(
            RunnerConfig {
                state_dir: env.state_dir.clone(),
                judge_prompt_path: None,
                pipeline,
                ..RunnerConfig::default()
            },
            None, // 不需要 provider
        );

        let (tx, _rx) = mpsc::channel(256);
        let state = runner
            .run(env.target.to_str().unwrap(), Some("RD".to_string()), tx)
            .await
            .expect("跳过 LLM 阶段后应正常跑到 Done");

        assert_eq!(state.current_phase, RoundPhase::Done);
        let triage_path = state.artifacts.get("triage").expect("triage 应产出空产物");
        let triage_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(triage_path).unwrap()).unwrap();
        assert_eq!(triage_json["skipped_by_pipeline"], true);

        let deep_review_path = state
            .artifacts
            .get("deep_review")
            .expect("deep_review 应产出空产物");
        let deep_review_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(deep_review_path).unwrap()).unwrap();
        assert_eq!(deep_review_json["skipped_by_pipeline"], true);
        assert!(state.tp_candidates.is_empty());
    }

    /// Pipeline 自定义输出契约：从 candidates 数组提取 TP 并触发人工闸门
    #[tokio::test]
    async fn test_pipeline_custom_output_contract_extracts_tp() {
        let env = make_env("custom-contract");
        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(triage_json_no_tp())),
            Ok(MockProvider::json_text(serde_json::json!({
                "phase": "deep_review",
                "candidates": [{
                    "title": "自定义输出 TP",
                    "cwe": "CWE-79",
                    "chain": ["source.js:1", "sink.js:2"]
                }]
            }))),
        ]);
        let pipeline = crate::pipeline::PipelineConfig {
            output: crate::pipeline::OutputContract {
                tp_candidates_path: vec!["candidates".to_string()],
                verdict_findings_path: vec![],
                ..Default::default()
            },
            ..Default::default()
        };
        let runner = Runner::new(
            RunnerConfig {
                state_dir: env.state_dir.clone(),
                judge_prompt_path: Some(env.root.join("round-agent.md")),
                pipeline,
                ..RunnerConfig::default()
            },
            Some(mock),
        );

        let (tx, _rx) = mpsc::channel(256);
        let state = runner
            .run(env.target.to_str().unwrap(), Some("RC".to_string()), tx)
            .await
            .expect("自定义输出契约应正常提取 TP 候选");

        assert_eq!(state.current_phase, RoundPhase::AwaitHuman);
        assert_eq!(state.tp_candidates.len(), 1);
        assert_eq!(state.tp_candidates[0].title, "自定义输出 TP");
        assert_eq!(state.tp_candidates[0].cwe.as_deref(), Some("CWE-79"));
    }

    /// Pipeline 额外审计阶段：深审后按顺序执行，并可产出独立 TP 候选
    #[tokio::test]
    async fn test_pipeline_extra_phase_runs_after_deep_review() {
        let env = make_env("extra-phase");
        let mock = MockProvider::new(vec![
            Ok(MockProvider::json_text(triage_json_no_tp())),
            Ok(MockProvider::json_text(deep_review_json_no_tp())),
            Ok(MockProvider::json_text(serde_json::json!({
                "phase": "logic_audit",
                "candidates": [{
                    "title": "额外阶段 TP",
                    "cwe": "CWE-352",
                    "chain": ["a.js:1", "b.js:2"]
                }]
            }))),
        ]);
        let pipeline = crate::pipeline::PipelineConfig {
            extra_phases: vec![crate::pipeline::ExtraJudgePhase {
                id: "logic_audit".to_string(),
                system_prompt: Some("你是额外逻辑审计员。".to_string()),
                output: Some(crate::pipeline::OutputContract {
                    tp_candidates_path: vec!["candidates".to_string()],
                    verdict_findings_path: vec![],
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let runner = Runner::new(
            RunnerConfig {
                state_dir: env.state_dir.clone(),
                judge_prompt_path: Some(env.root.join("round-agent.md")),
                pipeline,
                ..RunnerConfig::default()
            },
            Some(mock),
        );

        let (tx, _rx) = mpsc::channel(256);
        let state = runner
            .run(env.target.to_str().unwrap(), Some("RE".to_string()), tx)
            .await
            .expect("额外阶段应正常执行");

        assert_eq!(state.current_phase, RoundPhase::AwaitHuman);
        assert_eq!(state.tp_candidates.len(), 1);
        assert_eq!(state.tp_candidates[0].title, "额外阶段 TP");
        assert!(state.artifacts.contains_key("extra_phase_logic_audit"));
    }
}
