// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! daemon 内 agent 宿主（M3）
//!
//! 在 daemon 进程内托管 ctx-audit-agent 的轮次 runner：
//! - AgentRoundRun/Resume → tokio task 起跑 runner，事件经 mpsc 转发回客户端连接；
//! - AgentAbort → 取消对应 task（AbortHandle）；
//! - cron 调度器经 RoundLauncher 复用同一宿主通道 fire 定时轮。
//!
//! LLM provider 从环境变量装配（CTX_AUDIT_LLM_API_KEY / CTX_AUDIT_LLM_BASE_URL /
//! CTX_AUDIT_LLM_MODEL），密钥绝不落盘、不落日志。

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use ctx_audit_agent::cron::RoundLauncher;
use ctx_audit_agent::{
    AgentBudget, AgentEvent, ApprovalMode, LLMProvider, OpenAIProvider, OpenAIProviderConfig,
    RoundPhase, Runner, RunnerConfig, RunnerError, RunnerState,
};

/// 宿主内部通道消息（事件流 + 终止标记）
#[derive(Debug)]
pub enum HostEvent {
    /// agent 事件（AgentEvent 的 JSON）
    Event(serde_json::Value),
    /// 轮次终止（status: done / await_human / aborted / failed:... / paused:...）
    Done(String),
}

/// 起跑方式
enum RoundKind {
    /// 新起/断点续跑一轮
    Run(String),
    /// 续跑（target 从状态文件读）
    Resume,
    /// 人工闸门决策后进入登记草稿
    Gate(bool, Option<String>),
}

/// agent 宿主
pub struct AgentHost {
    config: RunnerConfig,
    provider: Option<Arc<dyn LLMProvider>>,
    /// 正在执行的轮次: round_id → task abort 句柄
    rounds: RwLock<HashMap<String, tokio::task::AbortHandle>>,
}

impl AgentHost {
    /// 从环境装配（daemon 生产路径）
    ///
    /// - state_dir: `<cwd>/.ctx-audit/runner`
    /// - provider: 环境变量装配，缺任一项则为 None（LLM 阶段会给出清晰错误）
    /// - webhook/budget: 读全局 config.toml 的 agent.native_gate / agent.native_budget
    pub fn from_env() -> Self {
        let webhook = read_global_config_str(&["agent", "native_gate", "webhook_url"]);
        let budget = AgentBudget {
            max_tokens: read_global_config_int(&["agent", "native_budget", "max_tokens"], 8192)
                as usize,
            max_turns: read_global_config_int(&["agent", "native_budget", "max_turns"], 20)
                as usize,
            max_minutes: read_global_config_int(&["agent", "native_budget", "max_minutes"], 30),
        };
        let pipeline = pipeline_from_env_or_config();
        Self {
            config: RunnerConfig {
                state_dir: PathBuf::from(".ctx-audit").join("runner"),
                judge_prompt_path: read_global_config_str(&[
                    "agent",
                    "native_pipeline",
                    "judge_prompt_path",
                ])
                .map(PathBuf::from),
                budget,
                approval: ApprovalMode::Gate,
                webhook_url: webhook,
                llm_polish_draft: false,
                subagent_threshold: read_global_config_int(
                    &["agent", "native_budget", "subagent_threshold"],
                    50,
                ) as usize,
                feedback_tasks: Vec::new(),
                pipeline,
            },
            provider: provider_from_env(),
            rounds: RwLock::new(HashMap::new()),
        }
    }

    /// 显式装配（测试路径）
    pub fn new(config: RunnerConfig, provider: Option<Arc<dyn LLMProvider>>) -> Self {
        Self {
            config,
            provider,
            rounds: RwLock::new(HashMap::new()),
        }
    }

    /// 起跑一轮（新建或断点续跑）
    pub async fn start_round(
        &self,
        target: &str,
        round_id: Option<String>,
    ) -> Result<(String, mpsc::Receiver<HostEvent>), String> {
        let round_id = round_id.unwrap_or_else(|| {
            format!(
                "AR-{}-{}",
                Utc::now().format("%Y%m%d"),
                &uuid::Uuid::new_v4().to_string()[..8]
            )
        });
        Ok(self
            .spawn_streaming(round_id, RoundKind::Run(target.to_string()))
            .await)
    }

    /// 续跑或闸门决策
    pub async fn resume_round(
        &self,
        round_id: &str,
        approve: Option<bool>,
        note: Option<String>,
    ) -> Result<(String, mpsc::Receiver<HostEvent>), String> {
        // 状态必须存在
        Runner::load_state(&self.config.state_dir, round_id).map_err(|e| e.to_string())?;
        let kind = match approve {
            Some(v) => RoundKind::Gate(v, note),
            None => RoundKind::Resume,
        };
        Ok(self.spawn_streaming(round_id.to_string(), kind).await)
    }

    /// 中止正在执行的轮次
    pub async fn abort_round(&self, round_id: &str) -> bool {
        let mut rounds = self.rounds.write().await;
        if let Some(handle) = rounds.remove(round_id) {
            handle.abort();
            tracing::info!("轮次 {} 已中止", round_id);
            true
        } else {
            false
        }
    }

    /// 轮次状态查询（None = 全部）
    pub async fn round_status(
        &self,
        round_id: Option<String>,
    ) -> Result<serde_json::Value, String> {
        match round_id {
            Some(id) => {
                let state =
                    Runner::load_state(&self.config.state_dir, &id).map_err(|e| e.to_string())?;
                serde_json::to_value(&state).map_err(|e| e.to_string())
            }
            None => {
                let states = Runner::list_states(&self.config.state_dir);
                serde_json::to_value(&states).map_err(|e| e.to_string())
            }
        }
    }

    /// 组装流式轮次任务：runner 执行 + 事件转发 + 终止标记
    async fn spawn_streaming(
        &self,
        round_id: String,
        kind: RoundKind,
    ) -> (String, mpsc::Receiver<HostEvent>) {
        let (agent_tx, mut agent_rx) = mpsc::channel::<AgentEvent>(256);
        let (tx, rx) = mpsc::channel::<HostEvent>(256);

        // 事件转发：AgentEvent → HostEvent（客户端断开时发送失败即退出）
        let tx_fwd = tx.clone();
        let fwd = tokio::spawn(async move {
            while let Some(ev) = agent_rx.recv().await {
                let json = serde_json::to_value(ev).unwrap_or_default();
                if tx_fwd.send(HostEvent::Event(json)).await.is_err() {
                    break;
                }
            }
        });

        let config = self.config.clone();
        let provider = self.provider.clone();
        let rid = round_id.clone();
        let join = tokio::spawn(async move {
            let runner = Runner::new(config, provider);
            let result: Result<RunnerState, RunnerError> = match kind {
                RoundKind::Run(target) => runner.run(&target, Some(rid.clone()), agent_tx).await,
                RoundKind::Resume => runner.resume(&rid, agent_tx).await,
                RoundKind::Gate(approve, note) => {
                    runner.gate_decide(&rid, approve, note, agent_tx).await
                }
            };
            // agent_tx 已被 run 消费并随其返回而 drop，转发任务随之结束
            let status = match &result {
                Ok(state) => match state.current_phase {
                    RoundPhase::Done => "done".to_string(),
                    RoundPhase::AwaitHuman => "await_human".to_string(),
                    other => format!("paused: {}", other.label()),
                },
                Err(e) => format!("failed: {}", e),
            };
            let _ = fwd.await;
            let _ = tx.send(HostEvent::Done(status)).await;
        });

        self.rounds
            .write()
            .await
            .insert(round_id.clone(), join.abort_handle());
        (round_id, rx)
    }
}

/// cron 调度器经此通道 fire 定时轮（同一宿主）
#[async_trait]
impl RoundLauncher for AgentHost {
    async fn launch(&self, target: &str, round_id: &str) -> Result<(), String> {
        let (_id, mut rx) = self.start_round(target, Some(round_id.to_string())).await?;
        while let Some(ev) = rx.recv().await {
            if let HostEvent::Done(status) = ev {
                return match status.as_str() {
                    "done" | "await_human" => Ok(()),
                    other => Err(other.to_string()),
                };
            }
        }
        Err("aborted".to_string())
    }
}

/// 从环境变量装配 provider（缺任一项返回 None；密钥不落盘不落日志）
fn provider_from_env() -> Option<Arc<dyn LLMProvider>> {
    let api_key = std::env::var("CTX_AUDIT_LLM_API_KEY").ok()?;
    let base_url = std::env::var("CTX_AUDIT_LLM_BASE_URL").ok()?;
    let model = std::env::var("CTX_AUDIT_LLM_MODEL").ok()?;
    Some(Arc::new(OpenAIProvider::new(OpenAIProviderConfig {
        base_url,
        api_key,
        model,
        max_retries: 5,
    })))
}

/// 加载 Pipeline 配置：CTX_AUDIT_PIPELINE_FILE > agent.native_pipeline.file > 默认
fn pipeline_from_env_or_config() -> ctx_audit_agent::PipelineConfig {
    let path = std::env::var("CTX_AUDIT_PIPELINE_FILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            read_global_config_str(&["agent", "native_pipeline", "file"]).map(PathBuf::from)
        });

    match path {
        Some(path) => match ctx_audit_agent::PipelineConfig::load(&path) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    "加载流水线配置失败，回退到内置默认: {} ({})",
                    path.display(),
                    e
                );
                ctx_audit_agent::PipelineConfig::default()
            }
        },
        None => ctx_audit_agent::PipelineConfig::default(),
    }
}

/// 读全局 config.toml 字符串配置（agent.native_gate.webhook_url 等）
fn read_global_config_str(path: &[&str]) -> Option<String> {
    let value = read_global_config(path)?;
    value.as_str().map(|s| s.to_string())
}

/// 读全局 config.toml 整数配置
fn read_global_config_int(path: &[&str], default: u64) -> u64 {
    read_global_config(path)
        .and_then(|v| v.as_integer().map(|i| i as u64))
        .unwrap_or(default)
}

/// 读全局 config.toml 任意节点
fn read_global_config(path: &[&str]) -> Option<toml::Value> {
    let content = dirs::config_dir()
        .map(|dir| dir.join("ctx-audit").join("config.toml"))
        .and_then(|p| std::fs::read_to_string(p).ok())?;
    let mut value: toml::Value = toml::from_str(&content).ok()?;
    for key in path {
        value = value.get(key)?.clone();
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ctx_audit_agent::provider::{ChatRequest, ChatResponse, ProviderError, Usage};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    // ── MockProvider：脚本化响应（支持阻塞） ──

    struct MockProvider {
        responses: Mutex<VecDeque<ChatResponse>>,
        block_on: Option<Arc<tokio::sync::Notify>>,
    }

    impl MockProvider {
        fn json(json: serde_json::Value) -> ChatResponse {
            ChatResponse {
                content: serde_json::to_string_pretty(&json).unwrap(),
                tool_calls: vec![],
                usage: Some(Usage {
                    prompt_tokens: 1,
                    completion_tokens: 1,
                    total_tokens: 2,
                }),
                finish_reason: Some("stop".to_string()),
            }
        }

        fn no_tp_script() -> Vec<ChatResponse> {
            vec![
                Self::json(serde_json::json!({
                    "phase": "triage", "summary": {"tp_candidates": 0}
                })),
                Self::json(serde_json::json!({
                    "phase": "deep_review", "summary": {"tp_candidates": 0}
                })),
            ]
        }
    }

    #[async_trait]
    impl LLMProvider for MockProvider {
        async fn chat(
            &self,
            _request: &ChatRequest,
            _event_tx: Option<mpsc::Sender<AgentEvent>>,
        ) -> Result<ChatResponse, ProviderError> {
            if let Some(ref notify) = self.block_on {
                notify.notified().await;
            }
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock 脚本耗尽"))
        }
    }

    // ── 测试基建 ──

    struct TestEnv {
        root: PathBuf,
        target: PathBuf,
        state_dir: PathBuf,
    }

    fn make_env(tag: &str) -> TestEnv {
        let root = std::env::temp_dir().join(format!(
            "ctx-audit-host-test-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        let target = root.join("target");
        let state_dir = root.join("runner");
        std::fs::create_dir_all(target.join("src")).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            target.join("src/index.js"),
            "const { exec } = require('child_process');\n\
             exec('ping ' + process.argv[2]);\n",
        )
        .unwrap();
        std::fs::write(root.join("round-agent.md"), "你是判定层。输出 JSON。").unwrap();
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

    fn make_host(env: &TestEnv, provider: Option<Arc<dyn LLMProvider>>) -> AgentHost {
        AgentHost::new(
            RunnerConfig {
                state_dir: env.state_dir.clone(),
                judge_prompt_path: Some(env.root.join("round-agent.md")),
                ..RunnerConfig::default()
            },
            provider,
        )
    }

    /// 收集事件流直到 Done
    async fn collect_until_done(
        mut rx: mpsc::Receiver<HostEvent>,
    ) -> (Vec<serde_json::Value>, String) {
        let mut events = Vec::new();
        loop {
            match rx.recv().await {
                Some(HostEvent::Event(j)) => events.push(j),
                Some(HostEvent::Done(status)) => return (events, status),
                None => return (events, "closed_without_done".to_string()),
            }
        }
    }

    // ── 起跑 → Started → 事件流 → Done（不连 LLM） ──

    #[tokio::test]
    async fn test_host_round_stream_to_done() {
        let env = make_env("stream");
        let provider = Arc::new(MockProvider {
            responses: Mutex::new(MockProvider::no_tp_script().into()),
            block_on: None,
        });
        let host = make_host(&env, Some(provider));

        let (round_id, rx) = host
            .start_round(env.target.to_str().unwrap(), Some("DR1".to_string()))
            .await
            .expect("起跑应成功");
        assert_eq!(round_id, "DR1");

        let (events, status) = collect_until_done(rx).await;
        assert_eq!(status, "done", "无 TP 轮应一路到 done");
        // 初审+深审各一个 round_finish 事件
        let round_finishes = events
            .iter()
            .filter(|e| e["type"] == "round_finish")
            .count();
        assert_eq!(
            round_finishes, 2,
            "事件流应含两轮 round_finish: {:?}",
            events
        );

        // 状态文件已完结
        let state = Runner::load_state(&env.state_dir, "DR1").unwrap();
        assert_eq!(state.current_phase, RoundPhase::Done);

        // 状态查询
        let info = host.round_status(Some("DR1".to_string())).await.unwrap();
        assert_eq!(info["round_id"], "DR1");
    }

    // ── abort：阻塞中的轮次被取消，通道关闭 ──

    #[tokio::test]
    async fn test_host_abort_round() {
        let env = make_env("abort");
        let gate = Arc::new(tokio::sync::Notify::new());
        let provider = Arc::new(MockProvider {
            responses: Mutex::new(MockProvider::no_tp_script().into()),
            block_on: Some(gate),
        });
        let host = make_host(&env, Some(provider));

        let (round_id, rx) = host
            .start_round(env.target.to_str().unwrap(), Some("DR2".to_string()))
            .await
            .unwrap();
        // 等 runner 跑到 LLM 阶段（扫描是真实扫描，需要一点时间）
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        assert!(host.abort_round(&round_id).await, "轮次在跑应可中止");
        assert!(!host.abort_round(&round_id).await, "重复中止返回 false");

        let (_events, status) = collect_until_done(rx).await;
        assert_eq!(status, "closed_without_done", "abort 后通道应直接关闭");
    }

    // ── resume：未完结轮次续跑；不存在轮次报错 ──

    #[tokio::test]
    async fn test_host_resume_round() {
        let env = make_env("resume");
        let host = make_host(&env, None);

        // 不存在的轮次
        let err = host
            .resume_round("NO_SUCH", None, None)
            .await
            .expect_err("不存在轮次应报错");
        assert!(err.contains("NO_SUCH") || err.contains("状态不存在"));

        // 无 provider 起跑 → 断在初审（ProviderMissing），之后用 mock 续跑到 done
        let (_id, rx) = host
            .start_round(env.target.to_str().unwrap(), Some("DR3".to_string()))
            .await
            .unwrap();
        let (_ev, status) = collect_until_done(rx).await;
        assert!(
            status.starts_with("failed"),
            "无 provider 应失败: {}",
            status
        );

        let state = Runner::load_state(&env.state_dir, "DR3").unwrap();
        assert_eq!(state.current_phase, RoundPhase::Triage);

        let provider = Arc::new(MockProvider {
            responses: Mutex::new(MockProvider::no_tp_script().into()),
            block_on: None,
        });
        let host2 = make_host(&env, Some(provider));
        let (_id, rx) = host2.resume_round("DR3", None, None).await.unwrap();
        let (_ev, status) = collect_until_done(rx).await;
        assert_eq!(status, "done");
    }

    // ── RoundLauncher（cron 通道） ──

    #[tokio::test]
    async fn test_host_as_round_launcher() {
        let env = make_env("launcher");
        let provider = Arc::new(MockProvider {
            responses: Mutex::new(MockProvider::no_tp_script().into()),
            block_on: None,
        });
        let host = make_host(&env, Some(provider));

        let result = host
            .launch(env.target.to_str().unwrap(), "cron-x-20260809-1000")
            .await;
        assert!(result.is_ok(), "done 状态应映射为 Ok: {:?}", result.err());

        let state = Runner::load_state(&env.state_dir, "cron-x-20260809-1000").unwrap();
        assert_eq!(state.current_phase, RoundPhase::Done);
    }
}
