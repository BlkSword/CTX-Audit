// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct 循环执行器
//!
//! 执行 Thought -> Action -> Observation 循环

use super::parser::{ActionType, ParseResult, ReactParser};
use super::state::{Observation, ReactState, ThoughtEntry as ReactThoughtEntry};
use crate::base::{AgentContext, ToolCallRecord};
use crate::tool_recommender::ToolRecommender;
use ctx_audit_llm::{LLMClient, LLMMessage, MessageRole};
use ctx_audit_tools::{ToolRegistry, ToolResult};
use futures::stream::StreamExt;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// 执行配置
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// 最大迭代次数（None 表示无限制）
    pub max_iterations: Option<u32>,

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
            max_iterations: None,
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

    /// 工具推荐器
    tool_recommender: ToolRecommender,
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
            tool_recommender: ToolRecommender::new(),
        }
    }

    /// 设置事件发送器
    pub fn with_event_tx(mut self, tx: mpsc::UnboundedSender<ExecutionEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// 克隆执行器并设置新的事件发送器
    pub fn clone_with_event_tx(&self, tx: mpsc::UnboundedSender<ExecutionEvent>) -> Self {
        Self {
            llm: self.llm.clone(),
            tool_registry: self.tool_registry.clone(),
            parser: ReactParser::new(),
            config: self.config.clone(),
            event_tx: Some(tx),
            tool_recommender: ToolRecommender::new(),
        }
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

        // 获取工具 - 如果不存在，返回错误观察而不是失败
        let tool = match self.tool_registry.get_tool(tool_name) {
            Some(t) => t,
            None => {
                let error_msg = format!("工具不存在: {}", tool_name);
                self.send_event(ExecutionEvent::ToolCallFailed {
                    tool_name: tool_name.to_string(),
                    error: error_msg.clone(),
                });
                return Ok(Observation::error(error_msg));
            }
        };

        // 执行工具 - 如果失败，返回错误观察而不是传播错误
        let result = match tool.execute(input).await {
            Ok(r) => r,
            Err(e) => {
                let error_msg = format!("工具执行失败: {}", e);
                self.send_event(ExecutionEvent::ToolCallFailed {
                    tool_name: tool_name.to_string(),
                    error: error_msg.clone(),
                });
                return Ok(Observation::error(error_msg));
            }
        };

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

        // 添加工具使用建议（如果迭代次数较多但未使用专业分析工具）
        if let Some(suggestion) = self.suggest_next_tool(state) {
            prompt.push_str(&format!("\n\n=== 建议下一步操作 ===\n{}\n", suggestion));
        }

        prompt
    }

    /// 建议下一步工具使用
    ///
    /// 根据当前状态和已使用的工具，使用智能推荐系统建议最佳工具
    fn suggest_next_tool(&self, state: &ReactState) -> Option<String> {
        // 收集已使用的工具
        let used_tools: Vec<String> = state.thought_chain.iter()
            .filter_map(|t| t.action.clone())
            .collect();

        // 使用 ToolRecommender 进行智能推荐
        if let Some(recommendation) = self.tool_recommender.recommend_by_iteration(state.iteration, &used_tools) {
            let mut suggestion = format!("[建议] {}", recommendation.reason);

            if let Some(ref params) = recommendation.suggested_params {
                suggestion.push_str(&format!("\n建议参数: {}", serde_json::to_string(params).unwrap_or_default()));
            }

            suggestion.push_str(&format!("\n预期效果: {}", recommendation.expected_outcome));

            return Some(suggestion);
        }

        // 检查是否已使用专业分析工具
        let professional_tools = [
            "trace_taint",
            "detect_vulnerability_patterns",
            "global_taint_analysis",
            "batch_pattern_scan",
        ];

        let has_used_professional = used_tools.iter()
            .any(|t| professional_tools.contains(&t.as_str()));

        // 如果尚未使用专业工具，根据阶段提醒
        if !has_used_professional {
            match state.iteration {
                1..=2 => {
                    if !used_tools.contains(&"list_files".to_string()) {
                        return Some("[建议] 先使用 list_files 了解项目结构，然后使用专业分析工具".to_string());
                    }
                }
                3..=5 => {
                    return Some("[强烈建议] 使用专业安全分析工具:\n\
                        - trace_taint: 执行污点追踪，验证数据流\n\
                        - detect_vulnerability_patterns: 检测已知漏洞模式\n\
                        - global_taint_analysis: 跨文件污点分析".to_string());
                }
                _ => {
                    return Some("[提醒] 尚未使用确定性分析工具，建议使用 trace_taint 或 detect_vulnerability_patterns 提高检测准确性".to_string());
                }
            }
        }

        None
    }

    /// 获取工具推荐
    pub fn get_tool_recommendations(&self) -> Vec<crate::tool_recommender::ToolRecommendation> {
        // 返回通用推荐
        vec![
            crate::tool_recommender::ToolRecommendation {
                tool_name: "trace_taint".to_string(),
                priority: 9,
                reason: "执行确定性污点分析".to_string(),
                suggested_params: None,
                expected_outcome: "发现污点传播路径".to_string(),
            },
            crate::tool_recommender::ToolRecommendation {
                tool_name: "detect_vulnerability_patterns".to_string(),
                priority: 8,
                reason: "检测常见漏洞模式".to_string(),
                suggested_params: None,
                expected_outcome: "发现模式匹配的漏洞".to_string(),
            },
        ]
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
                    // 尝试从 "finding" 字段获取
                    if let Some(finding) = data.get("finding") {
                        if let Ok(f) = serde_json::from_value::<ctx_audit_tools::FindingData>(
                            finding.clone(),
                        ) {
                            findings.push(f);
                        }
                    }
                    // 尝试从 "result" 字段获取（因为工具返回的是 {"result": {...}}）
                    if let Some(result) = data.get("result") {
                        if let Ok(f) = serde_json::from_value::<ctx_audit_tools::FindingData>(
                            result.clone(),
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
