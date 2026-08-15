// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 子 agent（M4，qwen-code 模式）
//!
//! 同引擎新实例：独立 history/session + 工具白名单（schema/执行双层过滤）+
//! 独立预算，只回传 final text，不回传中间消息。
//!
//! 两个入口：
//! - `Agent::spawn(task, config, prefix)`：主 agent 直接派生（审计铁律：
//!   主 agent 对关键 TP 判定独立复核，子 agent 输出仅作线索）；
//! - `DelegateTool`（`delegate_triage`）：注册进主 agent 的 registry 后，
//!   LLM 可像普通工具一样自主决定分片委托。
//!
//! 子 agent 事件流不回传（只回传 final text），全程落独立 session JSONL
//! （文件名带父轮次/父会话前缀），供事后审计。

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use ctx_audit_tools::{
    Tool, ToolCategory, ToolDefinition, ToolParameter, ToolParameterType, ToolRegistry, ToolResult,
};
use tokio::task::JoinHandle;

use crate::agent::{Agent, AgentBudget, AgentError};
use crate::confirm::{ApprovalMode, ToolGate};
use crate::provider::LLMProvider;
use crate::session::Session;
use crate::tool_adapter::ToolAdapter;

/// delegate 工具名（主 agent 视角的子 agent 入口）
pub const DELEGATE_TOOL_NAME: &str = "delegate_triage";

/// 子 agent spawn 配置覆盖
#[derive(Debug, Clone, Default)]
pub struct SubAgentConfig {
    /// 工具白名单（None = 继承父 agent 全部工具）
    pub tool_whitelist: Option<Vec<String>>,
    /// 独立预算（None = 继承父预算；建议显式设更小上限，如 max_turns 减半）
    pub budget: Option<AgentBudget>,
    /// system prompt 覆盖（None = 继承父 agent 的 system prompt）
    pub system_prompt: Option<String>,
}

/// 子 agent 工厂：持有派生所需的全部上下文，可 Clone 到多个并行任务
#[derive(Clone)]
pub struct SubAgentSpawner {
    provider: Arc<dyn LLMProvider>,
    registry: Arc<ToolRegistry>,
    approval: ApprovalMode,
    /// 子 agent session 所在的项目目录（session 落 <dir>/.ctx-audit/sessions/）
    project_dir: PathBuf,
    base_budget: AgentBudget,
    base_system_prompt: String,
    /// session 文件名前缀（通常为父 round_id）
    session_prefix: Option<String>,
}

impl SubAgentSpawner {
    /// 显式装配
    pub fn new(
        provider: Arc<dyn LLMProvider>,
        registry: Arc<ToolRegistry>,
        approval: ApprovalMode,
        project_dir: PathBuf,
        base_budget: AgentBudget,
        base_system_prompt: String,
        session_prefix: Option<String>,
    ) -> Self {
        Self {
            provider,
            registry,
            approval,
            project_dir,
            base_budget,
            base_system_prompt,
            session_prefix,
        }
    }

    /// 从主 Agent 派生（session 目录与主 agent 相同）
    pub fn from_agent(agent: &Agent, session_prefix: Option<String>) -> Self {
        // 主 agent 的 session 文件在 <project>/.ctx-audit/sessions/ 下，
        // 向上两级即项目目录
        let project_dir = agent
            .session()
            .path()
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self::new(
            Arc::clone(agent.provider()),
            Arc::clone(agent.adapter().registry()),
            agent.adapter().gate().mode(),
            project_dir,
            agent.budget().clone(),
            agent.system_prompt().to_string(),
            session_prefix,
        )
    }

    /// spawn 一个子 agent 跑 task
    ///
    /// 返回 JoinHandle：Ok(final_text) 为子 agent 最终文本；
    /// Err 为子 agent 熔断/provider 错误。事件流在任务内排空（不回传）。
    pub fn spawn(
        &self,
        task: String,
        config: SubAgentConfig,
    ) -> JoinHandle<Result<String, AgentError>> {
        let provider = Arc::clone(&self.provider);
        let registry = Arc::clone(&self.registry);
        let approval = self.approval;
        let project_dir = self.project_dir.clone();
        let budget = config.budget.unwrap_or_else(|| self.base_budget.clone());
        let system_prompt = config
            .system_prompt
            .unwrap_or_else(|| self.base_system_prompt.clone());
        let session_prefix = self.session_prefix.clone();

        tokio::spawn(async move {
            // 独立 session：带父前缀便于审计隔离
            let session = match &session_prefix {
                Some(prefix) => Session::create_with_prefix(&project_dir, prefix)?,
                None => Session::create(&project_dir)?,
            };
            let adapter = ToolAdapter::new(registry, ToolGate::new(approval))
                .with_whitelist(config.tool_whitelist);
            let child = Agent::new(provider, adapter, session, budget, Some(system_prompt));

            // 子 agent 事件只排空（审计已落 session 文件），不向上转发
            let (tx, mut rx) = tokio::sync::mpsc::channel(256);
            let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
            let result = child.run(&task, tx).await;
            let _ = drain.await;
            result.map(|r| r.final_text)
        })
    }
}

/// `delegate_triage` 工具：主 agent 可调用的子 agent 入口
///
/// 参数 = 任务描述 + findings 子集（JSON 文本），返回 = 子 agent final text。
/// 注册进主 agent 的 registry 后，LLM 可自主决定把大批次初审分片并行。
pub struct DelegateTool {
    spawner: SubAgentSpawner,
    /// 子 agent 工具白名单（None = 全部）
    child_whitelist: Option<Vec<String>>,
    /// 子 agent 独立预算（默认比主 agent 保守：max_turns 上限 10）
    child_budget: AgentBudget,
}

impl DelegateTool {
    /// 创建 delegate 工具（默认子预算 max_turns=10）
    pub fn new(spawner: SubAgentSpawner) -> Self {
        let mut child_budget = spawner.base_budget.clone();
        child_budget.max_turns = child_budget.max_turns.min(10);
        Self {
            spawner,
            child_whitelist: None,
            child_budget,
        }
    }

    /// 限定子 agent 工具白名单
    pub fn with_whitelist(mut self, whitelist: Vec<String>) -> Self {
        self.child_whitelist = Some(whitelist);
        self
    }

    /// 覆盖子 agent 预算
    pub fn with_budget(mut self, budget: AgentBudget) -> Self {
        self.child_budget = budget;
        self
    }
}

#[async_trait]
impl Tool for DelegateTool {
    fn name(&self) -> &str {
        DELEGATE_TOOL_NAME
    }

    fn description(&self) -> &str {
        "将一段初审/分析任务委托给子 agent 执行（独立会话与预算），\
         适用于大批量 findings 的分片并行初筛。返回子 agent 的最终结论文本。\
         注意：子 agent 输出仅作线索，关键 TP 判定须由你自己独立复核"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Custom
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(DELEGATE_TOOL_NAME, self.description(), ToolCategory::Custom)
            .add_parameter(ToolParameter {
                name: "task".to_string(),
                param_type: ToolParameterType::String,
                description: "委托给子 agent 的任务描述（含判定要求与输出契约）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "findings".to_string(),
                param_type: ToolParameterType::String,
                description: "findings 子集（JSON 文本），可选".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ctx_audit_tools::ToolError> {
        let task = match input.get("task").and_then(|v| v.as_str()) {
            Some(t) if !t.trim().is_empty() => t.to_string(),
            _ => {
                return Ok(ToolResult::error(
                    "缺少必填参数 task（任务描述）".to_string(),
                    Some("invalid_params".to_string()),
                ))
            }
        };
        // findings 子集：字符串原样透传，其他 JSON 类型序列化透传
        let prompt = match input.get("findings") {
            Some(v) if v.is_string() => {
                format!("{}\n\nfindings 子集（JSON）：\n{}", task, v.as_str().unwrap())
            }
            Some(v) if !v.is_null() => format!(
                "{}\n\nfindings 子集（JSON）：\n{}",
                task,
                serde_json::to_string_pretty(v).unwrap_or_default()
            ),
            _ => task,
        };

        let handle = self.spawner.spawn(
            prompt,
            SubAgentConfig {
                tool_whitelist: self.child_whitelist.clone(),
                budget: Some(self.child_budget.clone()),
                system_prompt: None,
            },
        );
        match handle.await {
            Ok(Ok(text)) => Ok(ToolResult::text(text)),
            Ok(Err(e)) => Ok(ToolResult::error(
                format!("子 agent 执行失败: {}", e),
                Some("subagent_failed".to_string()),
            )),
            Err(e) => Ok(ToolResult::error(
                format!("子 agent 任务被取消或 panic: {}", e),
                Some("subagent_join".to_string()),
            )),
        }
    }
}

/// 把 `delegate_triage` 注册进 registry（主 agent LLM 可自主决定分片）
pub async fn register_delegate_tool(
    registry: &Arc<ToolRegistry>,
    spawner: SubAgentSpawner,
) -> Result<(), ctx_audit_tools::ToolError> {
    registry.register(Arc::new(DelegateTool::new(spawner))).await
}

// ── 测试 ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::AgentEvent;
    use crate::provider::{
        ChatRequest, ChatResponse, ProviderError, ToolCall, Usage,
    };
    use ctx_audit_tools::ToolError;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    // ── MockProvider：脚本化响应队列 ──

    struct MockProvider {
        responses: Mutex<VecDeque<ChatResponse>>,
        requests: Mutex<Vec<ChatRequest>>,
    }

    impl MockProvider {
        fn new(responses: Vec<ChatResponse>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn text(text: &str) -> ChatResponse {
            ChatResponse {
                content: text.to_string(),
                tool_calls: vec![],
                usage: Some(Usage {
                    prompt_tokens: 1,
                    completion_tokens: 1,
                    total_tokens: 2,
                }),
                finish_reason: Some("stop".to_string()),
            }
        }

        fn tool_call(name: &str) -> ChatResponse {
            ChatResponse {
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: "c1".to_string(),
                    name: name.to_string(),
                    arguments: "{}".to_string(),
                }],
                usage: None,
                finish_reason: Some("tool_calls".to_string()),
            }
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
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock 脚本耗尽"))
        }

        fn model_name(&self) -> String {
            "mock-sub".to_string()
        }
    }

    // ── 测试用 echo 工具 ──

    struct EchoTool;

    #[async_trait]
    impl Tool for EchoTool {
        fn name(&self) -> &str {
            "echo_tool"
        }
        fn description(&self) -> &str {
            "回显输入"
        }
        fn category(&self) -> ToolCategory {
            ToolCategory::Custom
        }
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::new("echo_tool", "回显输入", ToolCategory::Custom)
        }
        async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
            Ok(ToolResult::text(format!("echo: {}", input)))
        }
    }

    // ── 测试基建 ──

    struct TestEnv {
        root: PathBuf,
    }

    fn make_env(tag: &str) -> TestEnv {
        let root = std::env::temp_dir().join(format!(
            "ctx-audit-subagent-test-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        TestEnv { root }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).ok();
        }
    }

    async fn make_spawner(
        env: &TestEnv,
        provider: Arc<MockProvider>,
        prefix: Option<String>,
    ) -> SubAgentSpawner {
        let registry = Arc::new(ToolRegistry::new());
        registry.register(Arc::new(EchoTool)).await.unwrap();
        SubAgentSpawner::new(
            provider,
            registry,
            ApprovalMode::Auto,
            env.root.clone(),
            AgentBudget::default(),
            "测试 system prompt".to_string(),
            prefix,
        )
    }

    /// spawn：只回传 final text，session 文件带父前缀
    #[tokio::test]
    async fn test_spawn_returns_final_text_and_prefixed_session() {
        let env = make_env("final");
        let provider = MockProvider::new(vec![MockProvider::text("子 agent 结论")]);
        let spawner = make_spawner(&env, provider, Some("AR-TEST".to_string())).await;

        let handle = spawner.spawn("初审分片任务".to_string(), SubAgentConfig::default());
        let text = handle.await.unwrap().expect("子 agent 应正常结束");
        assert_eq!(text, "子 agent 结论");

        // 独立 session：sessions 目录下恰有一个带父前缀的文件
        let sessions_dir = Session::sessions_dir(&env.root);
        let files: Vec<_> = std::fs::read_dir(&sessions_dir)
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(files.len(), 1);
        let name = files[0].file_name().to_string_lossy().to_string();
        assert!(name.starts_with("AR-TEST-"), "session 文件名应带父前缀: {}", name);
    }

    /// 独立 history：子 agent 请求只见自己的消息，不含父 agent 历史
    #[tokio::test]
    async fn test_child_history_isolated() {
        let env = make_env("history");
        let provider = MockProvider::new(vec![
            MockProvider::tool_call("echo_tool"),
            MockProvider::text("done"),
        ]);
        let requests_ref = provider.clone();
        let spawner = make_spawner(&env, provider, None).await;

        let handle = spawner.spawn("子任务".to_string(), SubAgentConfig::default());
        handle.await.unwrap().unwrap();

        // 子 agent 首轮请求：system + user（自己的 task），无父历史
        let requests = requests_ref.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let first = &requests[0].messages;
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].role, "system");
        assert_eq!(first[1].role, "user");
        assert_eq!(first[1].content.as_deref(), Some("子任务"));
    }

    /// 独立预算：子 agent max_turns 独立生效
    #[tokio::test]
    async fn test_child_independent_budget() {
        let env = make_env("budget");
        // 子 agent 会一直请求工具，max_turns=1 → 首轮即最后一轮，仍请求工具则熔断
        let provider = MockProvider::new(vec![MockProvider::tool_call("echo_tool")]);
        let spawner = make_spawner(&env, provider, None).await;

        let handle = spawner.spawn(
            "预算测试".to_string(),
            SubAgentConfig {
                tool_whitelist: None,
                budget: Some(AgentBudget {
                    max_tokens: 8192,
                    max_turns: 1,
                    max_minutes: 30,
                }),
                system_prompt: None,
            },
        );
        let err = handle.await.unwrap().expect_err("应预算熔断");
        assert!(matches!(err, AgentError::BudgetExceeded(_)));
    }

    /// 白名单：子 agent 调用白名单外工具被拦截（schema+执行双层，双层之一在此验证执行链路）
    #[tokio::test]
    async fn test_child_whitelist_blocks_tool() {
        let env = make_env("whitelist");
        let provider = MockProvider::new(vec![
            MockProvider::tool_call("echo_tool"), // 白名单外 → 拦截回喂
            MockProvider::text("无法使用工具，直接结论"),
        ]);
        let spawner = make_spawner(&env, provider, None).await;

        let handle = spawner.spawn(
            "白名单测试".to_string(),
            SubAgentConfig {
                tool_whitelist: Some(vec!["no_such_tool".to_string()]),
                budget: None,
                system_prompt: None,
            },
        );
        let text = handle.await.unwrap().unwrap();
        assert_eq!(text, "无法使用工具，直接结论");
    }

    /// 并行：3 个子 agent 经 JoinSet 并发跑完，各自回传 final text
    #[tokio::test]
    async fn test_parallel_three_children() {
        let env = make_env("parallel");
        let provider = MockProvider::new(vec![
            MockProvider::text("分片1结论"),
            MockProvider::text("分片2结论"),
            MockProvider::text("分片3结论"),
        ]);
        let spawner = make_spawner(&env, provider, Some("AR-PAR".to_string())).await;

        let mut set = tokio::task::JoinSet::new();
        for i in 0..3 {
            let spawner = spawner.clone();
            set.spawn(async move {
                spawner
                    .spawn(format!("分片{}任务", i + 1), SubAgentConfig::default())
                    .await
                    .unwrap()
            });
        }
        let mut results = Vec::new();
        while let Some(res) = set.join_next().await {
            results.push(res.unwrap().unwrap());
        }
        assert_eq!(results.len(), 3);
        // 三片各出结论（顺序不定，内容齐全即可）
        for expected in ["分片1结论", "分片2结论", "分片3结论"] {
            assert!(results.iter().any(|r| r == expected), "缺少 {}", expected);
        }

        // 3 个独立 session 文件，均带父前缀
        let files: Vec<_> = std::fs::read_dir(Session::sessions_dir(&env.root))
            .unwrap()
            .flatten()
            .collect();
        assert_eq!(files.len(), 3);
        assert!(files
            .iter()
            .all(|f| f.file_name().to_string_lossy().starts_with("AR-PAR-")));
    }

    /// delegate_triage 工具：参数组装 + final text 透传 + 缺参报错
    #[tokio::test]
    async fn test_delegate_tool() {
        let env = make_env("delegate");
        let provider = MockProvider::new(vec![MockProvider::text("委托结论")]);
        let requests_ref = provider.clone();
        let spawner = make_spawner(&env, provider, Some("AR-DLG".to_string())).await;
        let tool = DelegateTool::new(spawner);

        // 缺 task → 错误结果
        let out = tool.execute(serde_json::json!({})).await.unwrap();
        assert!(out.is_error);

        // 正常委托：task + findings 拼进子 agent prompt
        let out = tool
            .execute(serde_json::json!({
                "task": "初审以下 findings",
                "findings": [{"file_path": "a.js", "vuln_type": "CWE-78"}]
            }))
            .await
            .unwrap();
        assert!(!out.is_error);
        assert_eq!(out.get_text(), "委托结论");

        // 子 agent 首轮 user 消息含 task 与 findings JSON
        let requests = requests_ref.requests.lock().unwrap();
        let user_msg = requests[0].messages[1].content.as_deref().unwrap();
        assert!(user_msg.contains("初审以下 findings"));
        assert!(user_msg.contains("a.js"));
    }
}
