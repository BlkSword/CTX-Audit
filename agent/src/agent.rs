// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 主循环（消息驱动）
//!
//! 每轮：从会话重读全部消息 → 组 system+tools+history → provider 流式调用 →
//! tool_call 经 adapter 执行 → 结果回喂；无 tool_call 即结束。
//!
//! 防护机制（对齐 opencode 策略）：
//! - doom loop 熔断：连续 3 次同名同参 tool call 触发拦截提示，再犯即熔断；
//! - max_turns 最后一轮注入收尾提示，仍请求工具则熔断；
//! - Budget 三层：单次 max_tokens / 单轮 max_turns + max_minutes，破即返回 BudgetExceeded。

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::mpsc;

use crate::event::AgentEvent;
use crate::provider::{ChatMessage, ChatRequest, LLMProvider, ProviderError, Usage};
use crate::session::{Session, SessionRecord};
use crate::tool_adapter::ToolAdapter;

/// 预算配置（三层）
#[derive(Debug, Clone)]
pub struct AgentBudget {
    /// 单次 LLM 调用 max_tokens（第一层）
    pub max_tokens: usize,
    /// 单轮 agent 最大轮数（第二层）
    pub max_turns: usize,
    /// 单轮 agent 最大时长（分钟，第三层）
    pub max_minutes: u64,
}

impl Default for AgentBudget {
    fn default() -> Self {
        Self {
            max_tokens: 8192,
            max_turns: 20,
            max_minutes: 30,
        }
    }
}

/// Agent 错误
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// provider 层错误
    #[error("provider 错误: {0}")]
    Provider(#[from] ProviderError),

    /// 会话存储错误
    #[error("会话存储错误: {0}")]
    Session(#[from] std::io::Error),

    /// 预算耗尽熔断
    #[error("预算耗尽: {0}")]
    BudgetExceeded(String),

    /// doom loop 熔断
    #[error("doom loop 熔断: 工具 {tool} 连续重复 {count} 次")]
    LoopDetected {
        /// 工具名
        tool: String,
        /// 重复次数
        count: usize,
    },
}

/// 一次运行的结果
#[derive(Debug, Clone)]
pub struct AgentRunResult {
    /// 最终文本输出
    pub final_text: String,
    /// 实际轮数
    pub rounds: usize,
    /// 累计 token 用量
    pub total_usage: Usage,
    /// 会话 ID
    pub session_id: String,
}

/// 默认 system prompt（安全审计场景）
pub const DEFAULT_SYSTEM_PROMPT: &str = "你是 CTX-Audit 的安全审计 Agent。\
通过工具收集代码证据，基于证据做漏洞判定，不要臆测。\
工具结果不足以判定时明确说明缺什么证据，再决定下一步。\
完成后直接输出结构化结论，不要再调用工具。";

/// Agent（M1 最小闭环）
pub struct Agent {
    provider: Arc<dyn LLMProvider>,
    adapter: ToolAdapter,
    session: Session,
    budget: AgentBudget,
    system_prompt: String,
}

impl Agent {
    /// 创建 Agent
    pub fn new(
        provider: Arc<dyn LLMProvider>,
        adapter: ToolAdapter,
        session: Session,
        budget: AgentBudget,
        system_prompt: Option<String>,
    ) -> Self {
        Self {
            provider,
            adapter,
            session,
            budget,
            system_prompt: system_prompt.unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string()),
        }
    }

    /// 会话访问（测试与续跑用）
    pub fn session(&self) -> &Session {
        &self.session
    }

    /// provider 访问（子 agent 派生用）
    pub fn provider(&self) -> &Arc<dyn LLMProvider> {
        &self.provider
    }

    /// 工具适配器访问（子 agent 派生用）
    pub fn adapter(&self) -> &ToolAdapter {
        &self.adapter
    }

    /// 预算访问（子 agent 派生用）
    pub fn budget(&self) -> &AgentBudget {
        &self.budget
    }

    /// system prompt 访问（子 agent 派生用）
    pub fn system_prompt(&self) -> &str {
        &self.system_prompt
    }

    /// 派生子 agent（M4，qwen-code 模式：同引擎新实例）
    ///
    /// 独立 history/session（文件名带 `session_prefix` 前缀便于审计隔离）、
    /// 工具白名单、独立预算；只回传 final text。实现见 `crate::subagent`。
    pub fn spawn(
        &self,
        task: String,
        config: crate::subagent::SubAgentConfig,
        session_prefix: Option<String>,
    ) -> tokio::task::JoinHandle<Result<String, AgentError>> {
        crate::subagent::SubAgentSpawner::from_agent(self, session_prefix).spawn(task, config)
    }

    /// doom loop 触发阈值（连续同名同参次数）
    const DOOM_LOOP_THRESHOLD: usize = 3;

    /// 运行主循环
    ///
    /// 事件通过 `event_tx` 实时推送；正常结束返回 Ok，熔断/错误返回 Err。
    pub async fn run(
        &self,
        prompt: &str,
        event_tx: mpsc::Sender<AgentEvent>,
    ) -> Result<AgentRunResult, AgentError> {
        let started = Instant::now();
        let mut round = 0usize;
        let mut total_usage = Usage::default();

        // doom loop 状态：上一次调用签名、连续重复次数、是否已拦截提示过
        let mut last_sig: Option<String> = None;
        let mut repeat_count = 0usize;
        let mut loop_warned = false;

        // ── 会话落库：Meta + 初始 user ──
        self.session.append(&SessionRecord::Meta {
            prompt: prompt.to_string(),
            model: self.provider.model_name(),
            created_at: Utc::now(),
        })?;
        self.session.append(&SessionRecord::User {
            content: prompt.to_string(),
        })?;

        loop {
            // ── 预算检查：时长 ──
            if started.elapsed() > Duration::from_secs(self.budget.max_minutes * 60) {
                let reason = format!("超过时长上限 {} 分钟", self.budget.max_minutes);
                Self::send(&event_tx, AgentEvent::BudgetExceeded {
                    reason: reason.clone(),
                })
                .await;
                return Err(AgentError::BudgetExceeded(reason));
            }
            // ── 预算检查：轮数 ──
            if round >= self.budget.max_turns {
                let reason = format!("超过轮数上限 {} 轮", self.budget.max_turns);
                Self::send(&event_tx, AgentEvent::BudgetExceeded {
                    reason: reason.clone(),
                })
                .await;
                return Err(AgentError::BudgetExceeded(reason));
            }
            round += 1;

            // ── 消息驱动：每轮从会话重读全部消息 ──
            let mut messages = vec![ChatMessage::system(&self.system_prompt)];
            messages.extend(self.session.build_messages()?);

            // ── 最后一轮注入收尾提示（防烂尾输出） ──
            if round == self.budget.max_turns {
                let hint = "【系统提示】这是最后一轮，禁止再调用任何工具，请立即输出最终结论。";
                self.session.append(&SessionRecord::User {
                    content: hint.to_string(),
                })?;
                messages.push(ChatMessage::user(hint));
            }

            // ── 调 provider（流式增量由 provider 直接推事件） ──
            let request = ChatRequest {
                messages,
                tools: self.adapter.tool_schemas().await,
                max_tokens: self.budget.max_tokens,
            };
            let response = match self.provider.chat(&request, Some(event_tx.clone())).await {
                Ok(resp) => resp,
                Err(e) => {
                    Self::send(&event_tx, AgentEvent::Error {
                        message: e.to_string(),
                    })
                    .await;
                    return Err(e.into());
                }
            };
            if let Some(ref usage) = response.usage {
                total_usage.add(usage);
            }

            // ── assistant 消息落库 ──
            self.session.append(&SessionRecord::Assistant {
                content: if response.content.is_empty() {
                    None
                } else {
                    Some(response.content.clone())
                },
                tool_calls: response.tool_calls.clone(),
            })?;
            Self::send(&event_tx, AgentEvent::RoundFinish {
                round,
                prompt_tokens: response.usage.map(|u| u.prompt_tokens).unwrap_or(0),
                completion_tokens: response
                    .usage
                    .map(|u| u.completion_tokens)
                    .unwrap_or(0),
                total_tokens: total_usage.total_tokens,
            })
            .await;

            // ── 无 tool_call 即结束 ──
            if response.tool_calls.is_empty() {
                return Ok(AgentRunResult {
                    final_text: response.content,
                    rounds: round,
                    total_usage,
                    session_id: self.session.id().to_string(),
                });
            }

            // ── 最后一轮仍请求工具：收尾失败，预算熔断 ──
            if round >= self.budget.max_turns {
                let reason = format!(
                    "第 {} 轮（最后一轮）模型仍请求 {} 个工具调用，已熔断",
                    round,
                    response.tool_calls.len()
                );
                Self::send(&event_tx, AgentEvent::BudgetExceeded {
                    reason: reason.clone(),
                })
                .await;
                return Err(AgentError::BudgetExceeded(reason));
            }

            // ── 执行工具调用 ──
            for call in &response.tool_calls {
                Self::send(&event_tx, AgentEvent::ToolCallRequest {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    arguments: call.arguments.clone(),
                })
                .await;

                // ── doom loop 检测 ──
                let sig = format!("{}:{}", call.name, call.arguments);
                if last_sig.as_deref() == Some(sig.as_str()) {
                    repeat_count += 1;
                } else {
                    repeat_count = 1;
                    loop_warned = false;
                    last_sig = Some(sig);
                }
                if repeat_count >= Self::DOOM_LOOP_THRESHOLD {
                    Self::send(&event_tx, AgentEvent::LoopDetected {
                        tool_name: call.name.clone(),
                        count: repeat_count,
                    })
                    .await;
                    if loop_warned {
                        // 提示后仍重复，熔断
                        return Err(AgentError::LoopDetected {
                            tool: call.name.clone(),
                            count: repeat_count,
                        });
                    }
                    loop_warned = true;
                    // 不执行，回喂拦截提示（保持 tool_call/tool 配对完整）
                    let notice = format!(
                        "检测到连续 {} 次重复调用 {}（参数完全相同），本次调用已被拦截。\
请停止重复，改用不同工具或参数，或直接输出结论。",
                        repeat_count, call.name
                    );
                    self.session.append(&SessionRecord::Tool {
                        tool_call_id: call.id.clone(),
                        name: call.name.clone(),
                        output: notice.clone(),
                        is_error: true,
                        interrupted: false,
                    })?;
                    Self::send(&event_tx, AgentEvent::ToolResult {
                        id: call.id.clone(),
                        name: call.name.clone(),
                        output: notice,
                        is_error: true,
                    })
                    .await;
                    continue;
                }

                // ── 正常执行 ──
                let output = self.adapter.execute(call).await;
                self.session.append(&SessionRecord::Tool {
                    tool_call_id: output.call_id.clone(),
                    name: output.name.clone(),
                    output: output.content.clone(),
                    is_error: output.is_error,
                    interrupted: false,
                })?;
                Self::send(&event_tx, AgentEvent::ToolResult {
                    id: output.call_id,
                    name: output.name,
                    output: output.content,
                    is_error: output.is_error,
                })
                .await;
            }
        }
    }

    /// 发送事件（接收端关闭时忽略）
    async fn send(tx: &mpsc::Sender<AgentEvent>, event: AgentEvent) {
        let _ = tx.send(event).await;
    }
}

// ── 测试 ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ctx_audit_tools::{
        Tool, ToolCategory, ToolDefinition, ToolError, ToolRegistry, ToolResult,
    };
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    use crate::confirm::{ApprovalMode, ToolGate};
    use crate::provider::{ChatResponse, ToolCall};

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

        fn tool_call_response(id: &str, name: &str, args: &str) -> ChatResponse {
            ChatResponse {
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: id.to_string(),
                    name: name.to_string(),
                    arguments: args.to_string(),
                }],
                usage: Some(Usage {
                    prompt_tokens: 10,
                    completion_tokens: 5,
                    total_tokens: 15,
                }),
                finish_reason: Some("tool_calls".to_string()),
            }
        }

        fn text_response(text: &str) -> ChatResponse {
            ChatResponse {
                content: text.to_string(),
                tool_calls: vec![],
                usage: Some(Usage {
                    prompt_tokens: 20,
                    completion_tokens: 10,
                    total_tokens: 30,
                }),
                finish_reason: Some("stop".to_string()),
            }
        }
    }

    #[async_trait]
    impl LLMProvider for MockProvider {
        async fn chat(
            &self,
            request: &ChatRequest,
            event_tx: Option<mpsc::Sender<AgentEvent>>,
        ) -> Result<ChatResponse, ProviderError> {
            self.requests.lock().unwrap().push(request.clone());
            let resp = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock 脚本耗尽：主循环多调了一轮");
            // 模拟流式文本事件
            if let (Some(tx), false) = (event_tx, resp.content.is_empty()) {
                let _ = tx
                    .send(AgentEvent::Text {
                        delta: resp.content.clone(),
                    })
                    .await;
            }
            Ok(resp)
        }

        fn model_name(&self) -> String {
            "mock-model".to_string()
        }
    }

    // ── 测试用工具 ──

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

    fn temp_project(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ctx-audit-agent-loop-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct TestRig {
        agent: Agent,
        provider: Arc<MockProvider>,
        project: PathBuf,
    }

    async fn make_rig(
        tag: &str,
        responses: Vec<ChatResponse>,
        budget: AgentBudget,
    ) -> TestRig {
        let project = temp_project(tag);
        let session = Session::create(&project).unwrap();
        let registry = Arc::new(ToolRegistry::new());
        registry.register(Arc::new(EchoTool)).await.unwrap();
        let adapter = ToolAdapter::new(registry, ToolGate::new(ApprovalMode::Auto));
        let provider = MockProvider::new(responses);
        let agent = Agent::new(
            provider.clone(),
            adapter,
            session,
            budget,
            Some("测试 system prompt".to_string()),
        );
        TestRig {
            agent,
            provider,
            project,
        }
    }

    impl Drop for TestRig {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.project).ok();
        }
    }

    /// 收集运行期间的全部事件
    fn collect_events(mut rx: mpsc::Receiver<AgentEvent>) -> Vec<AgentEvent> {
        let mut events = Vec::new();
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        events
    }

    /// 主循环：tool_call → 执行 → 第二轮纯文本 → break
    #[tokio::test]
    async fn test_main_loop_tool_call_then_text() {
        let rig = make_rig(
            "main",
            vec![
                MockProvider::tool_call_response("c1", "echo_tool", r#"{"msg":"hi"}"#),
                MockProvider::text_response("审计完成"),
            ],
            AgentBudget::default(),
        )
        .await;
        let (tx, rx) = mpsc::channel(100);

        let result = rig.agent.run("审计 src/", tx).await.expect("应正常结束");
        assert_eq!(result.final_text, "审计完成");
        assert_eq!(result.rounds, 2);
        assert_eq!(result.total_usage.total_tokens, 45);

        // 第二轮请求应包含完整历史：system + user + assistant(tool_call) + tool
        let requests = rig.provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let history = &requests[1].messages;
        assert_eq!(history[0].role, "system");
        assert_eq!(history[1].role, "user");
        assert_eq!(history[2].role, "assistant");
        assert_eq!(history[2].tool_calls.as_ref().unwrap().len(), 1);
        assert_eq!(history[3].role, "tool");
        assert_eq!(history[3].tool_call_id.as_deref(), Some("c1"));
        assert!(history[3]
            .content
            .as_deref()
            .unwrap()
            .contains("echo:"));

        // 事件序列：ToolCallRequest → ToolResult → RoundFinish → Text → RoundFinish
        let events = collect_events(rx);
        assert!(events
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolCallRequest { name, .. } if name == "echo_tool")));
        assert!(events
            .iter()
            .any(|e| matches!(e, AgentEvent::ToolResult { name, is_error, .. } if name == "echo_tool" && !is_error)));
        assert!(events
            .iter()
            .any(|e| matches!(e, AgentEvent::Text { delta } if delta == "审计完成")));
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, AgentEvent::RoundFinish { .. }))
                .count(),
            2
        );
    }

    /// doom loop：连续 4 次同名同参 → 第 3 次拦截提示，第 4 次熔断
    #[tokio::test]
    async fn test_doom_loop_breaker() {
        let responses = (0..4)
            .map(|_| MockProvider::tool_call_response("c", "echo_tool", r#"{"x":1}"#))
            .collect();
        let rig = make_rig("doom", responses, AgentBudget::default()).await;
        let (tx, rx) = mpsc::channel(100);

        let err = rig.agent.run("loop", tx).await.expect_err("应触发熔断");
        assert!(matches!(
            err,
            AgentError::LoopDetected { ref tool, count } if tool == "echo_tool" && count == 4
        ));

        let events = collect_events(rx);
        let loop_events = events
            .iter()
            .filter(|e| matches!(e, AgentEvent::LoopDetected { .. }))
            .count();
        assert_eq!(loop_events, 2, "第 3、4 次重复各产生一个 LoopDetected 事件");

        // 前两次正常执行，第三次被拦截（错误结果回喂）
        let tool_results: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                AgentEvent::ToolResult { is_error, .. } => Some(*is_error),
                _ => None,
            })
            .collect();
        assert_eq!(tool_results, vec![false, false, true]);
    }

    /// 预算熔断：max_turns=2，模型一直请求工具 → 第二轮收尾失败熔断
    #[tokio::test]
    async fn test_budget_max_turns_breaker() {
        let responses = (0..3)
            .map(|i| {
                MockProvider::tool_call_response(&format!("c{}", i), "echo_tool", "{}")
            })
            .collect();
        let budget = AgentBudget {
            max_tokens: 8192,
            max_turns: 2,
            max_minutes: 30,
        };
        let rig = make_rig("budget", responses, budget).await;
        let (tx, rx) = mpsc::channel(100);

        let err = rig.agent.run("budget", tx).await.expect_err("应预算熔断");
        assert!(matches!(err, AgentError::BudgetExceeded(_)));

        // 只调了 2 轮 LLM；第二轮请求末尾应注入收尾提示
        let requests = rig.provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        let last = requests[1].messages.last().unwrap();
        assert_eq!(last.role, "user");
        assert!(last.content.as_deref().unwrap().contains("最后一轮"));

        let events = collect_events(rx);
        assert!(events
            .iter()
            .any(|e| matches!(e, AgentEvent::BudgetExceeded { .. })));
    }

    /// 首轮即纯文本：一轮结束
    #[tokio::test]
    async fn test_immediate_text_break() {
        let rig = make_rig(
            "immediate",
            vec![MockProvider::text_response("直接回答")],
            AgentBudget::default(),
        )
        .await;
        let (tx, _rx) = mpsc::channel(100);

        let result = rig.agent.run("q", tx).await.expect("应正常结束");
        assert_eq!(result.final_text, "直接回答");
        assert_eq!(result.rounds, 1);

        let requests = rig.provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
    }

    /// 会话落库：一轮 tool_call + 一轮文本后，JSONL 记录完整可重放
    #[tokio::test]
    async fn test_session_persistence_across_loop() {
        let rig = make_rig(
            "persist",
            vec![
                MockProvider::tool_call_response("c1", "echo_tool", "{}"),
                MockProvider::text_response("done"),
            ],
            AgentBudget::default(),
        )
        .await;
        let (tx, _rx) = mpsc::channel(100);
        rig.agent.run("p", tx).await.unwrap();

        let session = Session::open(rig.agent.session().path().to_path_buf());
        let messages = session.build_messages().unwrap();
        // user + assistant + tool + assistant
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[3].content.as_deref(), Some("done"));
    }
}
