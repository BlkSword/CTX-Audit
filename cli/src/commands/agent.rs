// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! agent 命令实现
//!
//! 默认进程内直接跑主循环/轮次状态机；带 `--daemon` 时作为瘦客户端
//! 走 daemon IPC（流式事件转发），cron 定时轮仅支持 daemon 路径。

use miette::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ctx_audit_agent::{
    session::list_sessions, Agent, AgentBudget, AgentError, AgentEvent, ApprovalMode, LLMProvider,
    OpenAIProvider, OpenAIProviderConfig, RoundPhase, Runner, RunnerConfig, Session, ToolAdapter,
    ToolGate,
};
use ctx_audit_daemon::{
    client::DaemonClient,
    protocol::{RequestCommand, Response},
};
use ctx_audit_tools::{register_all_tools, ToolRegistry};

use crate::config::ConfigManager;

/// 从配置构建原生 provider（配置不完整时给出可操作指引）
fn build_native_provider(manager: &ConfigManager) -> Result<Arc<OpenAIProvider>> {
    let provider_cfg = &manager.config().agent.native_provider;

    let base_url = provider_cfg.base_url.clone().ok_or_else(|| {
        miette::miette!(
            "未配置 agent.native_provider.base_url，请先执行：\n  ctx-audit config set agent.native_provider.base_url <OpenAI 兼容端点，如 https://api.deepseek.com/v1>"
        )
    })?;
    let model = provider_cfg.model.clone().ok_or_else(|| {
        miette::miette!(
            "未配置 agent.native_provider.model，请先执行：\n  ctx-audit config set agent.native_provider.model <模型名>"
        )
    })?;
    // 密钥只从环境变量读取，绝不落盘、不写日志
    let api_key = std::env::var(&provider_cfg.api_key_env).map_err(|_| {
        miette::miette!(
            "环境变量 {} 未设置（agent.native_provider.api_key_env 指定的密钥变量）",
            provider_cfg.api_key_env
        )
    })?;

    Ok(Arc::new(OpenAIProvider::new(OpenAIProviderConfig {
        base_url,
        api_key,
        model,
        max_retries: 5,
    })))
}

/// 从配置组装 RunnerConfig（state_dir = <cwd>/.ctx-audit/runner）
fn build_runner_config(manager: &ConfigManager) -> Result<RunnerConfig> {
    build_runner_config_with_pipeline(manager, None)
}

fn build_runner_config_with_pipeline(
    manager: &ConfigManager,
    explicit_pipeline: Option<&str>,
) -> Result<RunnerConfig> {
    let budget_cfg = &manager.config().agent.native_budget;
    let cwd = std::env::current_dir().map_err(|e| miette::miette!("{}", e))?;
    let pipeline = load_pipeline_config_opt(manager, explicit_pipeline)?;
    Ok(RunnerConfig {
        state_dir: cwd.join(".ctx-audit").join("runner"),
        judge_prompt_path: manager
            .config()
            .agent
            .native_pipeline
            .judge_prompt_path
            .clone(),
        budget: AgentBudget {
            max_tokens: budget_cfg.max_tokens,
            max_turns: budget_cfg.max_turns,
            max_minutes: budget_cfg.max_minutes,
        },
        approval: ApprovalMode::Gate,
        webhook_url: manager.config().agent.native_gate.webhook_url.clone(),
        llm_polish_draft: false,
        subagent_threshold: budget_cfg.subagent_threshold,
        // 反哺任务经 `agent feedback run` 单独执行；轮内自动反哺预留（暂无配置面）
        feedback_tasks: Vec::new(),
        pipeline,
    })
}

/// 加载 Pipeline 配置：显式配置文件 > CTX_AUDIT_PIPELINE_FILE 环境变量 > 内置默认
fn load_pipeline_config(manager: &ConfigManager) -> Result<ctx_audit_agent::PipelineConfig> {
    load_pipeline_config_opt(manager, None)
}

/// 加载 Pipeline 配置，支持命令行显式覆盖
fn load_pipeline_config_opt(
    manager: &ConfigManager,
    explicit: Option<&str>,
) -> Result<ctx_audit_agent::PipelineConfig> {
    let from_cli = explicit
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let from_config = manager
        .config()
        .agent
        .native_pipeline
        .file
        .clone()
        .filter(|p| !p.as_os_str().is_empty());
    let from_env = std::env::var("CTX_AUDIT_PIPELINE_FILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);

    let path = from_cli.or(from_config).or(from_env);
    match path {
        Some(path) => ctx_audit_agent::PipelineConfig::load(&path)
            .map_err(|e| miette::miette!("加载流水线配置失败: {}", e)),
        None => Ok(ctx_audit_agent::PipelineConfig::default()),
    }
}

/// 显示当前生效的 Pipeline 配置摘要
pub async fn pipeline_show() -> Result<()> {
    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let pipeline = load_pipeline_config(&manager)?;
    let summary = serde_json::json!({
        "name": pipeline.name,
        "description": pipeline.description,
        "scan": {
            "enable_taint": pipeline.scan.enable_taint,
            "enable_cross_file": pipeline.scan.enable_cross_file,
            "min_severity": pipeline.scan.min_severity,
            "rules_dir": pipeline.scan.rules_dir.map(|p| p.display().to_string()),
        },
        "triage_enabled": pipeline.triage.enabled,
        "deep_review_enabled": pipeline.deep_review.enabled,
        "gate_enabled": pipeline.gate_enabled,
        "registration_polish_draft": pipeline.registration.polish_draft,
        "phases": pipeline.phases.as_ref().map(|p| serde_json::to_value(p).unwrap_or(serde_json::Value::Null)),
        "extra_phases": pipeline.extra_phases.iter().map(|p| {
            serde_json::json!({
                "id": p.id,
                "prompt_path": p.prompt_path.as_ref().map(|x| x.display().to_string()),
                "enabled": p.enabled,
            })
        }).collect::<Vec<_>>(),
        "output": {
            "tp_candidates_path": pipeline.output.tp_candidates_path,
            "verdict_findings_path": pipeline.output.verdict_findings_path,
            "verdict_field": pipeline.output.verdict_field,
            "accepted_verdicts": pipeline.output.accepted_verdicts,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&summary)
            .map_err(|e| miette::miette!("序列化 Pipeline 摘要失败: {}", e))?
    );
    Ok(())
}

/// 校验 Pipeline 配置文件
pub async fn pipeline_validate(file: Option<&str>) -> Result<()> {
    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    // 显式文件 > 环境变量 > 全局配置 > 内置默认
    let path = file
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("CTX_AUDIT_PIPELINE_FILE")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| manager.config().agent.native_pipeline.file.clone());

    match path {
        Some(path) => {
            ctx_audit_agent::PipelineConfig::load(&path)
                .map_err(|e| miette::miette!("Pipeline 无效: {}", e))?;
            println!("Pipeline 有效: {}", path.display());
        }
        None => {
            let default = ctx_audit_agent::PipelineConfig::default();
            println!("未配置 Pipeline 文件，当前使用内置默认: {}", default.name);
        }
    }
    Ok(())
}

/// 事件渲染 sink（人性化 / NDJSON），返回发送端与渲染任务句柄
fn spawn_renderer(
    json: bool,
) -> (
    tokio::sync::mpsc::Sender<AgentEvent>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<AgentEvent>(256);
    let handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if json {
                render_event_json(&event);
            } else {
                render_event_human(&event);
            }
        }
    });
    (tx, handle)
}

/// 运行一轮 agent
pub async fn run(prompt: String, project: Option<String>, json: bool) -> Result<()> {
    let project_dir = resolve_project_dir(project.as_deref())?;

    // ── 加载配置并构建 provider ──
    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let provider = build_native_provider(&manager)?;
    let budget_cfg = &manager.config().agent.native_budget;

    // ── 工具注册（M1 不起 AST 引擎，注册基础/搜索/污点/模式/调用图工具） ──
    let registry = Arc::new(ToolRegistry::new());
    register_all_tools(
        &registry,
        project_dir.to_string_lossy().to_string(),
        None,
        None,
    )
    .await;

    // ── 组装 Agent ──
    // 非交互默认 Gate：写工具 deny，只读白名单短路
    let adapter = ToolAdapter::new(registry, ToolGate::new(ApprovalMode::Gate));
    let session = Session::create(&project_dir).map_err(|e| miette::miette!("{}", e))?;
    let budget = AgentBudget {
        max_tokens: budget_cfg.max_tokens,
        max_turns: budget_cfg.max_turns,
        max_minutes: budget_cfg.max_minutes,
    };
    let agent = Agent::new(provider, adapter, session, budget, None);

    if !json {
        eprintln!("会话 ID: {}", agent.session().id());
        eprintln!("会话文件: {}", agent.session().path().display());
    }

    // ── 事件渲染（人性化 / NDJSON 两个 sink） ──
    let (tx, renderer) = spawn_renderer(json);

    let result = agent.run(&prompt, tx).await;
    // 等渲染任务排空事件
    let _ = renderer.await;

    match result {
        Ok(run) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "run_finish",
                        "session_id": run.session_id,
                        "rounds": run.rounds,
                        "usage": run.total_usage,
                    })
                );
            } else {
                println!(
                    "\n--- 完成：{} 轮，累计 {} tokens（prompt {} / completion {}） ---",
                    run.rounds,
                    run.total_usage.total_tokens,
                    run.total_usage.prompt_tokens,
                    run.total_usage.completion_tokens,
                );
            }
            Ok(())
        }
        Err(e) => Err(match e {
            AgentError::BudgetExceeded(reason) => {
                miette::miette!("预算熔断：{}（会话已保存，可查看 JSONL 复盘）", reason)
            }
            AgentError::LoopDetected { tool, count } => {
                miette::miette!("doom loop 熔断：工具 {} 连续重复 {} 次", tool, count)
            }
            other => miette::miette!("agent 运行失败：{}", other),
        }),
    }
}

/// 列出项目下的会话
pub async fn sessions(project: Option<String>) -> Result<()> {
    let project_dir = resolve_project_dir(project.as_deref())?;
    let infos = list_sessions(&project_dir).map_err(|e| miette::miette!("{}", e))?;

    if infos.is_empty() {
        println!(
            "暂无会话（目录：{}）",
            Session::sessions_dir(&project_dir).display()
        );
        return Ok(());
    }

    println!("共 {} 个会话:", infos.len());
    for info in &infos {
        let created = info
            .created_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "未知时间".to_string());
        let prompt_preview: String = info
            .prompt
            .as_deref()
            .unwrap_or("(无 Meta)")
            .chars()
            .take(60)
            .collect();
        println!(
            "- {} | {} | {} 条记录 | {} | {}",
            info.id,
            created,
            info.records,
            info.model.as_deref().unwrap_or("未知模型"),
            prompt_preview,
        );
    }
    Ok(())
}

// ── 轮次 runner（M2） ─────────────────────────────────

/// 启动或续跑一轮
pub async fn round_run(
    target: String,
    round_id: Option<String>,
    pipeline: Option<String>,
    json: bool,
    daemon: bool,
) -> Result<()> {
    // ── daemon 路径：流式转发 daemon 内的轮次事件 ──
    if daemon {
        return stream_daemon_round(RequestCommand::AgentRoundRun { target, round_id }, json).await;
    }

    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let provider: Option<Arc<dyn LLMProvider>> = build_native_provider(&manager)
        .ok()
        .map(|p| p as Arc<dyn LLMProvider>);
    let config = build_runner_config_with_pipeline(&manager, pipeline.as_deref())?;
    let runner = Runner::new(config, provider);

    let (tx, renderer) = spawn_renderer(json);
    let result = runner.run(&target, round_id, tx).await;
    let _ = renderer.await;

    let state = result.map_err(|e| miette::miette!("轮次执行失败：{}", e))?;
    print_round_summary(&state, json);
    Ok(())
}

/// 续跑已有轮次
pub async fn round_resume(round_id: String, json: bool, daemon: bool) -> Result<()> {
    if daemon {
        return stream_daemon_round(
            RequestCommand::AgentRoundResume {
                round_id,
                approve: None,
                note: None,
            },
            json,
        )
        .await;
    }

    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let provider: Option<Arc<dyn LLMProvider>> = build_native_provider(&manager)
        .ok()
        .map(|p| p as Arc<dyn LLMProvider>);
    let config = build_runner_config(&manager)?;
    let runner = Runner::new(config, provider);

    let (tx, renderer) = spawn_renderer(json);
    let result = runner.resume(&round_id, tx).await;
    let _ = renderer.await;

    let state = result.map_err(|e| miette::miette!("轮次续跑失败：{}", e))?;
    print_round_summary(&state, json);
    Ok(())
}

/// 查看轮次状态（缺省列出全部）
pub async fn round_status(round_id: Option<String>, daemon: bool) -> Result<()> {
    // ── daemon 路径：状态来自 daemon 进程内的 runner state_dir ──
    if daemon {
        let mut client = daemon_client().await?;
        let resp = client
            .send_request(RequestCommand::AgentRoundStatus {
                round_id: round_id.clone(),
            })
            .await
            .map_err(|e| miette::miette!("daemon 请求失败: {}", e))?;
        return match resp {
            Response::AgentRoundInfo { state } => {
                if round_id.is_some() {
                    let state: ctx_audit_agent::RunnerState = serde_json::from_value(state)
                        .map_err(|e| miette::miette!("轮次状态解析失败: {}", e))?;
                    print_round_detail(&state);
                } else {
                    let states: Vec<ctx_audit_agent::RunnerState> =
                        serde_json::from_value(state)
                            .map_err(|e| miette::miette!("轮次列表解析失败: {}", e))?;
                    if states.is_empty() {
                        println!("暂无轮次");
                        return Ok(());
                    }
                    println!("共 {} 轮:", states.len());
                    for s in &states {
                        println!(
                            "- {} | {} | 目标 {} | 更新于 {}",
                            s.round_id,
                            s.current_phase.label(),
                            s.target.input,
                            s.updated_at.format("%Y-%m-%d %H:%M:%S"),
                        );
                    }
                }
                Ok(())
            }
            Response::Error { code, message } => {
                Err(miette::miette!("daemon 返回错误 [{}]: {}", code, message))
            }
            other => Err(miette::miette!("daemon 意外响应: {:?}", other)),
        };
    }

    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let config = build_runner_config(&manager)?;

    match round_id {
        Some(id) => {
            let state =
                Runner::load_state(&config.state_dir, &id).map_err(|e| miette::miette!("{}", e))?;
            print_round_detail(&state);
        }
        None => {
            let states = Runner::list_states(&config.state_dir);
            if states.is_empty() {
                println!("暂无轮次（目录：{}）", config.state_dir.display());
                return Ok(());
            }
            println!("共 {} 轮:", states.len());
            for s in &states {
                println!(
                    "- {} | {} | 目标 {} | 更新于 {}",
                    s.round_id,
                    s.current_phase.label(),
                    s.target.input,
                    s.updated_at.format("%Y-%m-%d %H:%M:%S"),
                );
            }
        }
    }
    Ok(())
}

/// 列出待决闸门
pub async fn gate_list() -> Result<()> {
    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let config = build_runner_config(&manager)?;

    let pending: Vec<_> = Runner::list_states(&config.state_dir)
        .into_iter()
        .filter(|s| s.current_phase == RoundPhase::AwaitHuman)
        .collect();

    if pending.is_empty() {
        println!("暂无待决闸门");
        return Ok(());
    }

    println!("共 {} 个待决闸门:", pending.len());
    for s in &pending {
        println!("- 轮次 {} | 目标 {}", s.round_id, s.target.input);
        for (i, c) in s.tp_candidates.iter().enumerate() {
            println!(
                "  {}. {}（{}）",
                i + 1,
                c.title,
                c.cwe.as_deref().unwrap_or("CWE 未标")
            );
        }
        if let Some(notice) = s.artifacts.get("gate_notice") {
            println!("  通知文件: {}", notice);
        }
        println!(
            "  决策: ctx-audit agent gate approve {} [--note ...] / reject {} [--note ...]",
            s.round_id, s.round_id
        );
    }
    Ok(())
}

/// 闸门决策（approve/reject）后轮次进入登记草稿阶段
pub async fn gate_decide(
    round_id: String,
    approve: bool,
    note: Option<String>,
    daemon: bool,
) -> Result<()> {
    // ── daemon 路径：决策经 AgentRoundResume 透传（approve 带值即闸门决策） ──
    if daemon {
        return stream_daemon_round(
            RequestCommand::AgentRoundResume {
                round_id,
                approve: Some(approve),
                note,
            },
            false,
        )
        .await;
    }

    let manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    // 决策后续阶段默认模板草稿，无需 LLM；provider 配置齐全时也注入（预留润色能力）
    let provider: Option<Arc<dyn LLMProvider>> = build_native_provider(&manager)
        .ok()
        .map(|p| p as Arc<dyn LLMProvider>);
    let config = build_runner_config(&manager)?;
    let runner = Runner::new(config, provider);

    let (tx, renderer) = spawn_renderer(false);
    let result = runner.gate_decide(&round_id, approve, note, tx).await;
    let _ = renderer.await;

    let state = result.map_err(|e| miette::miette!("闸门决策失败：{}", e))?;
    println!(
        "轮次 {} 闸门已{}，当前阶段: {}",
        round_id,
        if approve { "通过" } else { "驳回" },
        state.current_phase.label()
    );
    if let Some(draft) = state.artifacts.get("registration_draft") {
        println!("登记草稿: {}", draft);
    }
    Ok(())
}

// ── cron 定时轮（M3，仅 daemon 路径） ──────────────────

/// 注册 cron 定时轮
pub async fn cron_add(schedule: String, target: String) -> Result<()> {
    let mut client = daemon_client().await?;
    let resp = client
        .send_request(RequestCommand::CronAdd {
            schedule: schedule.clone(),
            target: target.clone(),
        })
        .await
        .map_err(|e| miette::miette!("daemon 请求失败: {}", e))?;
    match resp {
        Response::Ack { message } => {
            // message 形如 "cron_added: <id>"
            let id = message.strip_prefix("cron_added: ").unwrap_or(&message);
            println!("已注册 cron 任务: {}", id);
            println!("  计划: {}", schedule);
            println!("  目标: {}", target);
            Ok(())
        }
        Response::Error { code, message } => {
            Err(miette::miette!("daemon 返回错误 [{}]: {}", code, message))
        }
        other => Err(miette::miette!("daemon 意外响应: {:?}", other)),
    }
}

/// 列出 cron 定时轮
pub async fn cron_list() -> Result<()> {
    let mut client = daemon_client().await?;
    let resp = client
        .send_request(RequestCommand::CronList)
        .await
        .map_err(|e| miette::miette!("daemon 请求失败: {}", e))?;
    match resp {
        Response::CronJobList { jobs } => {
            let jobs = jobs
                .as_array()
                .ok_or_else(|| miette::miette!("cron 任务列表格式异常"))?;
            if jobs.is_empty() {
                println!("暂无 cron 任务");
                return Ok(());
            }
            println!("共 {} 个 cron 任务:", jobs.len());
            for job in jobs {
                let id = job["id"].as_str().unwrap_or("?");
                let schedule = job["schedule"].as_str().unwrap_or("?");
                let target = job["target"].as_str().unwrap_or("?");
                let last_fired = job["last_fired"].as_str().unwrap_or("从未触发");
                println!(
                    "- {} | {} | 目标 {} | 上次触发 {}",
                    id, schedule, target, last_fired
                );
            }
            Ok(())
        }
        Response::Error { code, message } => {
            Err(miette::miette!("daemon 返回错误 [{}]: {}", code, message))
        }
        other => Err(miette::miette!("daemon 意外响应: {:?}", other)),
    }
}

/// 删除 cron 定时轮
pub async fn cron_delete(id: String) -> Result<()> {
    let mut client = daemon_client().await?;
    let resp = client
        .send_request(RequestCommand::CronDelete { id: id.clone() })
        .await
        .map_err(|e| miette::miette!("daemon 请求失败: {}", e))?;
    match resp {
        Response::Ack { .. } => {
            println!("已删除 cron 任务: {}", id);
            Ok(())
        }
        Response::Error { code, message } => {
            Err(miette::miette!("daemon 返回错误 [{}]: {}", code, message))
        }
        other => Err(miette::miette!("daemon 意外响应: {:?}", other)),
    }
}

// ── CVE 回放反哺（M4 机械层） ──────────────────────────

/// 单独执行一个 CVE 回放任务（确定性，无 LLM）
pub async fn feedback_run(task_path: String, daemon: bool) -> Result<()> {
    // ── daemon 路径：回放跑在 daemon 进程内 ──
    if daemon {
        let mut client = daemon_client().await?;
        let resp = client
            .send_request(RequestCommand::AgentFeedbackRun {
                task_path: task_path.clone(),
            })
            .await
            .map_err(|e| miette::miette!("daemon 请求失败: {}", e))?;
        return match resp {
            Response::AgentFeedbackReport { report } => {
                print_feedback_report(&report);
                Ok(())
            }
            Response::Error { code, message } => {
                Err(miette::miette!("daemon 返回错误 [{}]: {}", code, message))
            }
            other => Err(miette::miette!("daemon 意外响应: {:?}", other)),
        };
    }

    let content = std::fs::read_to_string(&task_path)
        .map_err(|e| miette::miette!("任务文件读取失败 {}: {}", task_path, e))?;
    let task: ctx_audit_agent::FeedbackTask =
        serde_json::from_str(&content).map_err(|e| miette::miette!("任务 JSON 解析失败: {}", e))?;
    let feedback_root = std::env::current_dir()
        .map_err(|e| miette::miette!("{}", e))?
        .join(".ctx-audit")
        .join("feedback");

    println!("回放 {}（{}）...", task.cve_id, task.git_url);
    let (report, path) = ctx_audit_agent::replay::run_replay(&task, &feedback_root)
        .await
        .map_err(|e| miette::miette!("回放失败: {}", e))?;
    println!("报告: {}", path.display());
    let value = serde_json::to_value(&report).map_err(|e| miette::miette!("{}", e))?;
    print_feedback_report(&value);
    Ok(())
}

/// 打印回放报告结论摘要
fn print_feedback_report(report: &serde_json::Value) {
    let cve = report["cve_id"].as_str().unwrap_or("?");
    let verdict = &report["verdict"];
    println!(
        "\n=== {} 回放结论: {} ===",
        cve,
        verdict["conclusion"].as_str().unwrap_or("?")
    );
    println!("  漏洞版命中预期: {}", verdict["vulnerable_hit_expected"]);
    println!("  修复版豁免: {}", verdict["fixed_exempt"]);
    let reg = &report["regression"];
    println!(
        "  回归: 漏洞版 {} findings / 修复版 {}（新增 {} / 消除 {}）",
        reg["vulnerable_total"], reg["fixed_total"], reg["new_in_fixed"], reg["resolved_in_fixed"]
    );
}

// ── daemon IPC 辅助（M3） ─────────────────────────────

/// 连接 daemon（失败时给出可操作指引）
async fn daemon_client() -> Result<DaemonClient> {
    DaemonClient::connect_with_retry()
        .await
        .map_err(|_| miette::miette!("无法连接 daemon，请先启动：ctx-audit daemon start"))
}

/// 经 daemon IPC 流式执行轮次命令（run / resume / 闸门决策），事件实时渲染
///
/// 序列：AgentRoundStarted → AgentEvent* → 终止帧（AgentRoundDone / Error）。
/// 终止帧 status 以 "failed" 开头时按失败处理。
async fn stream_daemon_round(command: RequestCommand, json: bool) -> Result<()> {
    let mut client = daemon_client().await?;
    let terminal = client
        .send_streaming_request(command, |resp| match resp {
            Response::AgentRoundStarted { round_id } => {
                eprintln!("轮次已启动: {}", round_id);
            }
            Response::AgentEvent { event, .. } => match serde_json::from_value::<AgentEvent>(event)
            {
                Ok(ev) => {
                    if json {
                        render_event_json(&ev);
                    } else {
                        render_event_human(&ev);
                    }
                }
                Err(e) => eprintln!("事件解析失败: {}", e),
            },
            _ => {}
        })
        .await
        .map_err(|e| miette::miette!("daemon 流式请求失败: {}", e))?;

    match terminal {
        Response::AgentRoundDone { round_id, status } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "round_finish",
                        "round_id": round_id,
                        "status": status,
                    })
                );
            } else {
                println!("\n=== 轮次 {} 结束: {} ===", round_id, status);
            }
            if status.starts_with("failed") {
                return Err(miette::miette!("轮次 {} 执行失败: {}", round_id, status));
            }
            Ok(())
        }
        Response::Error { code, message } => {
            Err(miette::miette!("daemon 返回错误 [{}]: {}", code, message))
        }
        other => Err(miette::miette!("daemon 意外终止帧: {:?}", other)),
    }
}

/// 轮次终态摘要
fn print_round_summary(state: &ctx_audit_agent::RunnerState, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "type": "round_finish",
                "round_id": state.round_id,
                "phase": state.current_phase,
                "tp_candidates": state.tp_candidates.len(),
                "artifacts": state.artifacts,
            })
        );
        return;
    }
    println!(
        "\n=== 轮次 {} | 阶段: {} ===",
        state.round_id,
        state.current_phase.label()
    );
    match state.current_phase {
        RoundPhase::AwaitHuman => {
            println!(
                "检出 {} 个 TP 候选，已进入人工闸门:",
                state.tp_candidates.len()
            );
            for (i, c) in state.tp_candidates.iter().enumerate() {
                println!(
                    "  {}. {}（{}）",
                    i + 1,
                    c.title,
                    c.cwe.as_deref().unwrap_or("CWE 未标")
                );
            }
            if let Some(notice) = state.artifacts.get("gate_notice") {
                println!("通知文件: {}", notice);
            }
            println!(
                "决策命令: ctx-audit agent gate approve/reject {}",
                state.round_id
            );
        }
        RoundPhase::Done => {
            if let Some(draft) = state.artifacts.get("registration_draft") {
                println!("登记草稿: {}", draft);
            }
        }
        _ => {}
    }
}

/// 轮次详情
fn print_round_detail(state: &ctx_audit_agent::RunnerState) {
    println!("轮次: {}", state.round_id);
    println!("目标: {}", state.target.input);
    if let Some(ref path) = state.target.local_path {
        println!("本地路径: {}", path.display());
    }
    println!("当前阶段: {}", state.current_phase.label());
    let completed: Vec<String> = state
        .completed
        .iter()
        .map(|p| p.label().to_string())
        .collect();
    println!("已完成: {}", completed.join(" → "));
    if let Some(ref e) = state.eligibility {
        println!(
            "资格: {}（源码文件 {}，主语言 {}）",
            if e.eligible { "通过" } else { "未通过" },
            e.source_files,
            e.primary_language.as_deref().unwrap_or("未知")
        );
    }
    if !state.tp_candidates.is_empty() {
        println!("TP 候选: {} 个", state.tp_candidates.len());
    }
    if let Some(ref d) = state.gate_decision {
        println!(
            "闸门决策: {}{}",
            if d.approve { "通过" } else { "驳回" },
            d.note
                .as_deref()
                .map(|n| format!("（{}）", n))
                .unwrap_or_default()
        );
    }
    if let Some(ref err) = state.last_error {
        println!("最近错误: {}", err);
    }
    if !state.artifacts.is_empty() {
        println!("产物:");
        for (k, v) in &state.artifacts {
            println!("  {}: {}", k, v);
        }
    }
}

/// 解析项目路径（默认当前目录，规范化）
fn resolve_project_dir(project: Option<&str>) -> Result<PathBuf> {
    let raw = project.unwrap_or(".");
    let path = Path::new(raw);
    let canonical = path
        .canonicalize()
        .map_err(|e| miette::miette!("项目路径无效 {}: {}", raw, e))?;
    if !canonical.is_dir() {
        return Err(miette::miette!("项目路径不是目录: {}", raw));
    }
    Ok(canonical)
}

/// NDJSON 事件输出
fn render_event_json(event: &AgentEvent) {
    match serde_json::to_string(event) {
        Ok(line) => println!("{}", line),
        Err(e) => eprintln!("事件序列化失败: {}", e),
    }
}

/// 人性化事件渲染
fn render_event_human(event: &AgentEvent) {
    match event {
        AgentEvent::Text { delta } => {
            print!("{}", delta);
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
        AgentEvent::Thinking { delta } => {
            eprint!("\x1b[2m{}\x1b[0m", delta);
        }
        AgentEvent::ToolCallRequest {
            name, arguments, ..
        } => {
            let args_preview: String = arguments.chars().take(120).collect();
            println!("\n→ 调用工具 {}({})", name, args_preview);
        }
        AgentEvent::ToolResult {
            name,
            output,
            is_error,
            ..
        } => {
            let preview: String = output.chars().take(200).collect();
            let status = if *is_error { "错误" } else { "完成" };
            println!("← {} {}: {}", name, status, preview);
        }
        AgentEvent::RoundFinish {
            round,
            total_tokens,
            ..
        } => {
            eprintln!(
                "--- 第 {} 轮结束（累计 {} tokens） ---",
                round, total_tokens
            );
        }
        AgentEvent::Error { message } => {
            eprintln!("[错误] {}", message);
        }
        AgentEvent::LoopDetected { tool_name, count } => {
            eprintln!("[熔断] 检测到重复调用 {} ×{}", tool_name, count);
        }
        AgentEvent::BudgetExceeded { reason } => {
            eprintln!("[熔断] 预算耗尽: {}", reason);
        }
    }
}
