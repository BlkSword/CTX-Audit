// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct 循环执行器
//!
//! 执行 Thought -> Action -> Observation 循环

use super::parser::{ActionType, ParseResult, ReactParser};
use super::state::{Observation, ReactState, ThoughtEntry as ReactThoughtEntry};
use crate::base::{AgentContext, ToolCallRecord};
use ctx_audit_llm::{LLMClient, LLMMessage, MessageRole};
use ctx_audit_tools::{ToolRegistry, ToolResult};
use futures::stream::StreamExt;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// 执行配置
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// 最大迭代次数
    pub max_iterations: u32,

    /// 超时时间（秒）
    pub timeout_secs: Option<u64>,

    /// 是否启用流式输出
    pub enable_streaming: bool,

    /// 温度参数
    pub temperature: f32,

    /// 最大 tokens
    pub max_tokens: u32,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            max_iterations: 50,
            timeout_secs: Some(600),
            enable_streaming: true,
            temperature: 0.7,
            max_tokens: 4096,
        }
    }
}

/// 执行事件
#[derive(Debug, Clone)]
pub enum ExecutionEvent {
    /// 开始迭代
    IterationStart(u32),

    /// 思考完成
    ThoughtComplete {
        iteration: u32,
        thought: String,
        action: Option<String>,
    },

    /// 工具调用开始
    ToolCallStart {
        tool_name: String,
        input: serde_json::Value,
    },

    /// 工具调用完成
    ToolCallComplete {
        tool_name: String,
        result: ToolResult,
        duration_ms: u64,
    },

    /// 工具调用失败
    ToolCallFailed {
        tool_name: String,
        error: String,
    },

    /// 流式输出
    StreamToken(String),

    /// 完成
    Complete {
        iterations: u32,
        tool_calls: usize,
    },

    /// 失败
    Failed(String),
}

/// ReAct 执行器
pub struct ReactExecutor {
    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 工具注册表
    tool_registry: Arc<ToolRegistry>,

    /// 解析器
    parser: ReactParser,

    /// 配置
    config: ExecutionConfig,

    /// 事件发送器
    event_tx: Option<mpsc::UnboundedSender<ExecutionEvent>>,
}

impl ReactExecutor {
    /// 创建新的执行器
    pub fn new(
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<ToolRegistry>,
        config: ExecutionConfig,
    ) -> Self {
        Self {
            llm,
            tool_registry,
            parser: ReactParser::new(),
            config,
            event_tx: None,
        }
    }

    /// 设置事件发送器
    pub fn with_event_tx(mut self, tx: mpsc::UnboundedSender<ExecutionEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// 执行 ReAct 循环
    pub async fn execute(
        &self,
        context: &AgentContext,
        system_prompt: &str,
        user_message: &str,
    ) -> Result<ReactExecutionResult, String> {
        let mut state = ReactState::new();

        // 设置初始目标
        state.add_goal(format!("审计项目: {}", context.project_path));

        // 构建初始消息
        let mut messages = vec![
            LLMMessage::system(system_prompt.to_string()),
            LLMMessage::user(format!(
                "项目路径: {}\n用户请求: {}",
                context.project_path, user_message
            )),
        ];

        // 执行循环
        while state.should_continue(self.config.max_iterations) {
            state.next_iteration();

            // 发送迭代开始事件
            self.send_event(ExecutionEvent::IterationStart(state.iteration));

            // 构建当前提示
            let current_prompt = self.build_prompt(&state, &messages).await;

            // 调用 LLM
            let llm_start = Instant::now();
            let response = if self.config.enable_streaming {
                self.call_llm_streaming(&messages).await?
            } else {
                let resp = self
                    .llm
                    .generate(
                        messages.to_vec(),
                        self.config.max_tokens,
                        self.config.temperature,
                    )
                    .await
                    .map_err(|e| format!("LLM 调用失败: {}", e))?;
                resp.get_text()
            };
            let llm_duration = llm_start.elapsed();

            // 解析 LLM 输出
            let parse_result = self.parser.parse(&response);

            // 发送思考完成事件
            self.send_event(ExecutionEvent::ThoughtComplete {
                iteration: state.iteration,
                thought: parse_result.thought.clone(),
                action: parse_result.action_name.clone(),
            });

            // 创建思考条目
            let mut thought_entry = ReactThoughtEntry::new(state.iteration, parse_result.thought.clone());
            thought_entry.action = parse_result.action_name.clone();
            thought_entry.action_input = parse_result.action_input.clone();
            thought_entry.confidence = parse_result.confidence;

            // 执行操作
            let observation = match parse_result.action_type {
                ActionType::UseTool => {
                    if let (Some(tool_name), Some(input)) = (
                        &parse_result.action_name,
                        &parse_result.action_input,
                    ) {
                        self.execute_tool(tool_name, input.clone()).await?
                    } else {
                        Observation::error("缺少工具名称或参数".to_string())
                    }
                }
                ActionType::Answer => {
                    state.mark_completed();
                    Observation::with_data(
                        "分析完成".to_string(),
                        parse_result.action_input.unwrap_or(serde_json::json!({})),
                    )
                }
                ActionType::Finish => {
                    state.mark_completed();
                    Observation::success("任务完成".to_string())
                }
                ActionType::Error => {
                    state.mark_failed("LLM 返回错误状态".to_string());
                    Observation::error("执行失败".to_string())
                }
                _ => Observation::success("继续思考".to_string()),
            };

            // 更新思考条目
            thought_entry.observation = Some(observation.clone());
            state.add_thought(thought_entry);

            // 更新状态
            state.set_observation(observation.clone());

            // 将观察结果添加到消息历史
            messages.push(LLMMessage::assistant(response));
            messages.push(LLMMessage::user(self.parser.format_observation(&observation)));

            // 追加上下文
            state.append_context(&format!(
                "迭代 {}: {} -> {}",
                state.iteration,
                parse_result.action_name.unwrap_or_else(|| "思考".to_string()),
                observation.summary
            ));

            // 检查是否完成
            if !parse_result.should_continue || state.completed {
                break;
            }
        }

        // 构建结果
        let tool_calls = state
            .thought_chain
            .iter()
            .filter_map(|t| t.action.clone())
            .collect();

        Ok(ReactExecutionResult {
            state,
            tool_calls,
        })
    }

    /// 调用 LLM（流式）
    async fn call_llm_streaming(&self, messages: &[LLMMessage]) -> Result<String, String> {
        use futures::StreamExt;

        let mut full_response = String::new();

        let stream = self
            .llm
            .generate_stream(messages.to_vec(), self.config.max_tokens, self.config.temperature)
            .await;

        futures::pin_mut!(stream);

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    if chunk.done {
                        break;
                    }
                    full_response.push_str(&chunk.delta);
                    self.send_event(ExecutionEvent::StreamToken(chunk.delta));
                }
                Err(e) => {
                    return Err(format!("流式输出错误: {}", e));
                }
            }
        }

        Ok(full_response)
    }

    /// 执行工具
    async fn execute_tool(
        &self,
        tool_name: &str,
        input: serde_json::Value,
    ) -> Result<Observation, String> {
        let start = Instant::now();

        self.send_event(ExecutionEvent::ToolCallStart {
            tool_name: tool_name.to_string(),
            input: input.clone(),
        });

        // 获取工具
        let tool = self
            .tool_registry
            .get_tool(tool_name)
            .ok_or_else(|| format!("工具不存在: {}", tool_name))?;

        // 执行工具
        let result = tool
            .execute(input)
            .await
            .map_err(|e| format!("工具执行失败: {}", e))?;

        let duration = start.elapsed().as_millis() as u64;

        // 构建观察结果
        let observation = if result.is_error {
            Observation::error(result.text.clone())
        } else {
            Observation::from_tool(tool_name.to_string(), result.text.clone(), duration)
        };

        self.send_event(ExecutionEvent::ToolCallComplete {
            tool_name: tool_name.to_string(),
            result: result.clone(),
            duration_ms: duration,
        });

        Ok(observation)
    }

    /// 构建提示词
    async fn build_prompt(&self, state: &ReactState, messages: &[LLMMessage]) -> String {
        let available_tools = self.tool_registry.list_tool_names().await;

        let context_summary = state.get_context_summary();

        // 更新系统提示
        let system_prompt = self.parser.format_prompt_template(&context_summary, &available_tools);

        // 组合历史
        let mut prompt = system_prompt;
        prompt.push_str("\n\n=== 对话历史 ===\n");

        for msg in messages.iter().skip(1) {
            // 跳过系统消息
            match msg.role {
                MessageRole::User => {
                    prompt.push_str(&format!("User: {}\n", msg.get_text()));
                }
                MessageRole::Assistant => {
                    prompt.push_str(&format!("Assistant: {}\n", msg.get_text()));
                }
                MessageRole::System => {}
            }
        }

        prompt
    }

    /// 发送事件
    fn send_event(&self, event: ExecutionEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event);
        }
    }
}

/// 执行结果
#[derive(Debug, Clone)]
pub struct ReactExecutionResult {
    /// 最终状态
    pub state: ReactState,

    /// 所有工具调用
    pub tool_calls: Vec<String>,
}

impl ReactExecutionResult {
    /// 获取工具调用记录
    pub fn get_tool_call_records(&self) -> Vec<ToolCallRecord> {
        self.state
            .thought_chain
            .iter()
            .filter_map(|thought| {
                if let (Some(tool_name), Some(ref input), Some(ref obs)) =
                    (&thought.action, &thought.action_input, &thought.observation)
                {
                    Some(ToolCallRecord {
                        tool_name: tool_name.clone(),
                        input: input.clone(),
                        output: obs.data.clone(),
                        duration_ms: obs.duration_ms,
                        success: obs.success,
                        error: obs.error.clone(),
                        timestamp: thought.timestamp,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// 获取漏洞发现
    pub fn get_findings(&self) -> Vec<ctx_audit_tools::FindingData> {
        let mut findings = Vec::new();

        for thought in &self.state.thought_chain {
            if let Some(ref obs) = thought.observation {
                if let Some(ref data) = obs.data {
                    if let Some(finding) = data.get("finding") {
                        if let Ok(f) = serde_json::from_value::<ctx_audit_tools::FindingData>(
                            finding.clone(),
                        ) {
                            findings.push(f);
                        }
                    }
                }
            }
        }

        findings
    }
}
