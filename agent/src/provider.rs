// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM provider 抽象与 OpenAI-compatible 实现
//!
//! 覆盖 deepseek / qwen / openrouter / anthropic(兼容端点) 等 OpenAI 兼容服务：
//! SSE 流式 chat/completions、tool_calls 增量聚合、429/5xx 指数退避重试
//! （2s×2^n 上限 30s，优先 retry-after 头）、usage 统计。
//!
//! 安全约定：api_key 只从环境变量读入（由调用方完成），本模块不写任何含 key 的日志。

use async_trait::async_trait;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::event::AgentEvent;

// ── 请求 / 响应模型 ─────────────────────────────────────

/// 一次工具调用（assistant 发起）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// 调用 ID（tool 消息回传时配对用）
    pub id: String,
    /// 工具名
    pub name: String,
    /// 参数（JSON 字符串，未解析）
    pub arguments: String,
}

/// token 用量
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Usage {
    /// prompt token 数
    pub prompt_tokens: u64,
    /// completion token 数
    pub completion_tokens: u64,
    /// 总 token 数
    pub total_tokens: u64,
}

impl Usage {
    /// 累加另一次调用的用量
    pub fn add(&mut self, other: &Usage) {
        self.prompt_tokens += other.prompt_tokens;
        self.completion_tokens += other.completion_tokens;
        self.total_tokens += other.total_tokens;
    }
}

/// 聊天消息
#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    /// 角色：system / user / assistant / tool
    pub role: String,

    /// 文本内容（assistant 纯 tool_call 消息可为空）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// assistant 发起的工具调用
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCallSer>>,

    /// tool 消息对应的调用 ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// ToolCall 的 OpenAI 序列化形式（带 type/function 包装）
#[derive(Debug, Clone, Serialize)]
pub struct ToolCallSer {
    /// 调用 ID
    pub id: String,
    /// 固定为 "function"
    #[serde(rename = "type")]
    pub kind: String,
    /// 函数体
    pub function: ToolCallFunction,
}

/// 函数调用体
#[derive(Debug, Clone, Serialize)]
pub struct ToolCallFunction {
    /// 函数名
    pub name: String,
    /// 参数 JSON 字符串
    pub arguments: String,
}

impl From<&ToolCall> for ToolCallSer {
    fn from(call: &ToolCall) -> Self {
        Self {
            id: call.id.clone(),
            kind: "function".to_string(),
            function: ToolCallFunction {
                name: call.name.clone(),
                arguments: call.arguments.clone(),
            },
        }
    }
}

impl ChatMessage {
    /// system 消息
    pub fn system(content: &str) -> Self {
        Self {
            role: "system".to_string(),
            content: Some(content.to_string()),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// user 消息
    pub fn user(content: &str) -> Self {
        Self {
            role: "user".to_string(),
            content: Some(content.to_string()),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// assistant 消息（可带工具调用）
    pub fn assistant(content: Option<String>, tool_calls: Vec<ToolCall>) -> Self {
        Self {
            role: "assistant".to_string(),
            content,
            tool_calls: if tool_calls.is_empty() {
                None
            } else {
                Some(tool_calls.iter().map(ToolCallSer::from).collect())
            },
            tool_call_id: None,
        }
    }

    /// tool 结果消息
    pub fn tool(tool_call_id: &str, content: &str) -> Self {
        Self {
            role: "tool".to_string(),
            content: Some(content.to_string()),
            tool_calls: None,
            tool_call_id: Some(tool_call_id.to_string()),
        }
    }
}

/// LLM 请求
#[derive(Debug, Clone)]
pub struct ChatRequest {
    /// 消息历史（含 system）
    pub messages: Vec<ChatMessage>,
    /// 工具 schema（OpenAI function-calling 格式）
    pub tools: Vec<serde_json::Value>,
    /// 单次调用 max_tokens 上限（预算第一层）
    pub max_tokens: usize,
}

/// LLM 响应（流式聚合后的最终结果）
#[derive(Debug, Clone, Default)]
pub struct ChatResponse {
    /// 聚合后的文本内容
    pub content: String,
    /// 聚合后的工具调用列表
    pub tool_calls: Vec<ToolCall>,
    /// token 用量
    pub usage: Option<Usage>,
    /// 结束原因（stop / tool_calls / length ...）
    pub finish_reason: Option<String>,
}

// ── 错误类型 ────────────────────────────────────────────

/// provider 错误
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// HTTP 状态错误（429/5xx 等）
    #[error("HTTP {status}: {body}")]
    Http {
        /// 状态码
        status: u16,
        /// 响应体（截断）
        body: String,
        /// 服务端要求的重试等待
        retry_after: Option<Duration>,
    },

    /// 网络层错误（连接失败、超时、流中断）
    #[error("网络错误: {0}")]
    Network(#[from] reqwest::Error),

    /// 服务端返回的业务错误（{"error": ...}）
    #[error("API 错误: {0}")]
    Api(String),

    /// SSE 数据解析失败
    #[error("响应解析失败: {0}")]
    Parse(String),
}

impl ProviderError {
    /// 是否可重试（429 / 5xx / 连接与超时类网络错误）
    fn is_retryable(&self) -> bool {
        match self {
            ProviderError::Http { status, .. } => *status == 429 || *status >= 500,
            ProviderError::Network(e) => e.is_connect() || e.is_timeout(),
            _ => false,
        }
    }

    /// 服务端指定的重试等待时间
    fn retry_after(&self) -> Option<Duration> {
        match self {
            ProviderError::Http { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// 指数退避：2s × 2^attempt，上限 30s（opencode 策略）
fn backoff_delay(attempt: u32) -> Duration {
    let secs = 2u64.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX));
    Duration::from_secs(secs.min(30))
}

// ── Provider trait ──────────────────────────────────────

/// LLM provider 抽象
///
/// `event_tx` 存在时，流式增量（Text/Thinking）实时推入事件通道；
/// 返回值为聚合后的完整响应。
#[async_trait]
pub trait LLMProvider: Send + Sync {
    /// 发起一轮聊天补全
    async fn chat(
        &self,
        request: &ChatRequest,
        event_tx: Option<mpsc::Sender<AgentEvent>>,
    ) -> Result<ChatResponse, ProviderError>;

    /// 模型名（用于会话 Meta 记录）
    fn model_name(&self) -> String {
        "unknown".to_string()
    }
}

// ── OpenAI-compatible 实现 ──────────────────────────────

/// OpenAI-compatible provider 配置
#[derive(Debug, Clone)]
pub struct OpenAIProviderConfig {
    /// API 基础地址（如 https://api.deepseek.com/v1）
    pub base_url: String,
    /// API 密钥（只从环境变量注入，绝不落盘/日志）
    pub api_key: String,
    /// 模型名
    pub model: String,
    /// 最大重试次数（默认 5）
    pub max_retries: u32,
}

/// OpenAI-compatible provider
pub struct OpenAIProvider {
    config: OpenAIProviderConfig,
    client: reqwest::Client,
}

impl OpenAIProvider {
    /// 创建 provider
    pub fn new(config: OpenAIProviderConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(600))
            .connect_timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { config, client }
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn chat(
        &self,
        request: &ChatRequest,
        event_tx: Option<mpsc::Sender<AgentEvent>>,
    ) -> Result<ChatResponse, ProviderError> {
        let mut attempt = 0u32;
        loop {
            match self.try_chat_once(request, &event_tx).await {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    if e.is_retryable() && attempt < self.config.max_retries {
                        let delay = e.retry_after().unwrap_or_else(|| backoff_delay(attempt));
                        // 注意：日志只含状态码/错误摘要，不含请求头与密钥
                        tracing::warn!(
                            "LLM 请求失败，第 {} 次重试前等待 {:?}: {}",
                            attempt + 1,
                            delay,
                            e
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    fn model_name(&self) -> String {
        self.config.model.clone()
    }
}

impl OpenAIProvider {
    /// 单次请求（重试只覆盖初始响应阶段；流式中途断流直接报错，
    /// 避免重试导致已推送的 Text delta 重复）
    async fn try_chat_once(
        &self,
        request: &ChatRequest,
        event_tx: &Option<mpsc::Sender<AgentEvent>>,
    ) -> Result<ChatResponse, ProviderError> {
        let url = format!(
            "{}/chat/completions",
            self.config.base_url.trim_end_matches('/')
        );

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": request.messages,
            "max_tokens": request.max_tokens,
            "stream": true,
            "stream_options": { "include_usage": true },
        });
        if !request.tools.is_empty() {
            body["tools"] = serde_json::Value::Array(request.tools.clone());
            body["tool_choice"] = serde_json::Value::String("auto".to_string());
        }

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.config.api_key)
            .header("Accept", "text/event-stream")
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs);
            let text = response.text().await.unwrap_or_default();
            let body_snippet: String = text.chars().take(500).collect();
            return Err(ProviderError::Http {
                status: status.as_u16(),
                body: body_snippet,
                retry_after,
            });
        }

        self.consume_sse(response, event_tx).await
    }

    /// 消费 SSE 流，聚合 content / tool_calls / usage
    async fn consume_sse(
        &self,
        response: reqwest::Response,
        event_tx: &Option<mpsc::Sender<AgentEvent>>,
    ) -> Result<ChatResponse, ProviderError> {
        let mut acc = StreamAccumulator::default();
        let mut buffer = String::new();
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            buffer.push_str(&String::from_utf8_lossy(&bytes));

            // 按行切分，保留不足一行的残余
            while let Some(pos) = buffer.find('\n') {
                let line: String = buffer[..pos].trim_end_matches('\r').to_string();
                buffer.drain(..=pos);
                for event in self.process_sse_line(&line, &mut acc)? {
                    if let Some(tx) = event_tx {
                        // 接收端已关闭时忽略（agent 已退出）
                        let _ = tx.send(event).await;
                    }
                }
            }
        }
        // 冲刷尾部残余行
        if !buffer.trim().is_empty() {
            for event in self.process_sse_line(buffer.trim(), &mut acc)? {
                if let Some(tx) = event_tx {
                    let _ = tx.send(event).await;
                }
            }
        }

        Ok(acc.into_response())
    }

    /// 处理一行 SSE 数据，返回本行产生的事件
    fn process_sse_line(
        &self,
        line: &str,
        acc: &mut StreamAccumulator,
    ) -> Result<Vec<AgentEvent>, ProviderError> {
        let line = line.trim();
        if line.is_empty() || line.starts_with(':') {
            return Ok(Vec::new());
        }
        let data = match line.strip_prefix("data:") {
            Some(d) => d.trim(),
            None => return Ok(Vec::new()),
        };
        if data == "[DONE]" {
            return Ok(Vec::new());
        }

        // 部分服务端会以 200 开头后在流内下发错误负载
        if let Ok(err) = serde_json::from_str::<StreamErrorPayload>(data) {
            return Err(ProviderError::Api(err.error.message));
        }

        let chunk: ChatChunk = serde_json::from_str(data)
            .map_err(|e| ProviderError::Parse(format!("{} (行: {})", e, truncate_str(data, 200))))?;
        Ok(acc.apply_chunk(&chunk))
    }
}

/// 截断辅助（按 char 安全截断）
fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let truncated: String = s.chars().take(max).collect();
    format!("{}...", truncated)
}

// ── SSE 数据结构（OpenAI 流式 chunk） ───────────────────

/// 流内错误负载
#[derive(Debug, Deserialize)]
struct StreamErrorPayload {
    error: StreamErrorBody,
}

/// 错误体
#[derive(Debug, Deserialize)]
struct StreamErrorBody {
    message: String,
}

/// 流式 chunk
#[derive(Debug, Deserialize)]
struct ChatChunk {
    #[serde(default)]
    choices: Vec<ChunkChoice>,
    usage: Option<Usage>,
}

/// chunk 中的 choice
#[derive(Debug, Deserialize)]
struct ChunkChoice {
    delta: ChunkDelta,
    finish_reason: Option<String>,
}

/// chunk 中的增量
#[derive(Debug, Deserialize)]
struct ChunkDelta {
    content: Option<String>,
    /// deepseek-reasoner 等模型的思考内容
    reasoning_content: Option<String>,
    tool_calls: Option<Vec<ChunkToolCall>>,
}

/// chunk 中的工具调用增量
#[derive(Debug, Deserialize)]
struct ChunkToolCall {
    index: usize,
    id: Option<String>,
    function: Option<ChunkToolCallFunction>,
}

/// 工具调用函数增量
#[derive(Debug, Deserialize)]
struct ChunkToolCallFunction {
    name: Option<String>,
    arguments: Option<String>,
}

// ── 流式聚合器 ──────────────────────────────────────────

/// tool_calls 增量聚合状态
#[derive(Default)]
struct ToolCallAcc {
    id: String,
    name: String,
    arguments: String,
}

/// SSE 聚合器：把 chunk 流聚合成完整响应
#[derive(Default)]
struct StreamAccumulator {
    content: String,
    tool_calls: Vec<ToolCallAcc>,
    usage: Option<Usage>,
    finish_reason: Option<String>,
}

impl StreamAccumulator {
    /// 应用一个 chunk，返回产生的事件
    fn apply_chunk(&mut self, chunk: &ChatChunk) -> Vec<AgentEvent> {
        let mut events = Vec::new();

        for choice in &chunk.choices {
            if let Some(ref text) = choice.delta.content {
                if !text.is_empty() {
                    self.content.push_str(text);
                    events.push(AgentEvent::Text {
                        delta: text.clone(),
                    });
                }
            }
            if let Some(ref thinking) = choice.delta.reasoning_content {
                if !thinking.is_empty() {
                    events.push(AgentEvent::Thinking {
                        delta: thinking.clone(),
                    });
                }
            }
            if let Some(ref calls) = choice.delta.tool_calls {
                for call in calls {
                    // 按 index 对齐聚合（OpenAI 流式 tool_calls 分片下发）
                    while self.tool_calls.len() <= call.index {
                        self.tool_calls.push(ToolCallAcc::default());
                    }
                    let slot = &mut self.tool_calls[call.index];
                    if let Some(ref id) = call.id {
                        slot.id.push_str(id);
                    }
                    if let Some(ref f) = call.function {
                        if let Some(ref name) = f.name {
                            slot.name.push_str(name);
                        }
                        if let Some(ref args) = f.arguments {
                            slot.arguments.push_str(args);
                        }
                    }
                }
            }
            if let Some(ref reason) = choice.finish_reason {
                self.finish_reason = Some(reason.clone());
            }
        }
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
        }

        events
    }

    /// 聚合为最终响应
    fn into_response(self) -> ChatResponse {
        ChatResponse {
            content: self.content,
            tool_calls: self
                .tool_calls
                .into_iter()
                .map(|acc| ToolCall {
                    id: acc.id,
                    name: acc.name,
                    arguments: acc.arguments,
                })
                .collect(),
            usage: self.usage,
            finish_reason: self.finish_reason,
        }
    }
}

// ── 测试 ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 指数退避：2/4/8/16/30(封顶)/30
    #[test]
    fn test_backoff_delay_cap() {
        assert_eq!(backoff_delay(0), Duration::from_secs(2));
        assert_eq!(backoff_delay(1), Duration::from_secs(4));
        assert_eq!(backoff_delay(2), Duration::from_secs(8));
        assert_eq!(backoff_delay(3), Duration::from_secs(16));
        assert_eq!(backoff_delay(4), Duration::from_secs(30));
        assert_eq!(backoff_delay(10), Duration::from_secs(30));
    }

    /// 错误可重试性判定
    #[test]
    fn test_retryable_classification() {
        let e429 = ProviderError::Http {
            status: 429,
            body: "rate limited".into(),
            retry_after: Some(Duration::from_secs(5)),
        };
        assert!(e429.is_retryable());
        assert_eq!(e429.retry_after(), Some(Duration::from_secs(5)));

        let e500 = ProviderError::Http {
            status: 503,
            body: "unavailable".into(),
            retry_after: None,
        };
        assert!(e500.is_retryable());

        let e400 = ProviderError::Http {
            status: 400,
            body: "bad request".into(),
            retry_after: None,
        };
        assert!(!e400.is_retryable());

        assert!(!ProviderError::Api("业务错误".into()).is_retryable());
    }

    /// 构造 chunk（测试辅助）
    fn make_chunk(json: &str) -> ChatChunk {
        serde_json::from_str(json).expect("chunk JSON 应可解析")
    }

    /// content 增量聚合 + Text 事件
    #[test]
    fn test_accumulate_content_deltas() {
        let mut acc = StreamAccumulator::default();
        let events1 = acc.apply_chunk(&make_chunk(
            r#"{"choices":[{"delta":{"content":"你好"},"finish_reason":null}]}"#,
        ));
        let events2 = acc.apply_chunk(&make_chunk(
            r#"{"choices":[{"delta":{"content":"，世界"},"finish_reason":"stop"}],
               "usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#,
        ));

        assert!(matches!(&events1[0], AgentEvent::Text { delta } if delta == "你好"));
        assert!(matches!(&events2[0], AgentEvent::Text { delta } if delta == "，世界"));

        let resp = acc.into_response();
        assert_eq!(resp.content, "你好，世界");
        assert_eq!(resp.finish_reason.as_deref(), Some("stop"));
        assert_eq!(resp.usage.unwrap().total_tokens, 15);
    }

    /// tool_calls 分片增量聚合（跨多个 chunk 的 id/name/arguments 拼接）
    #[test]
    fn test_accumulate_tool_call_deltas() {
        let mut acc = StreamAccumulator::default();

        // 第一片：id + name + 参数开头
        acc.apply_chunk(&make_chunk(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"read_file","arguments":"{\"path\":"}}]},"finish_reason":null}]}"#,
        ));
        // 第二片：参数续片
        acc.apply_chunk(&make_chunk(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"src/a.rs\"}"}}]},"finish_reason":null}]}"#,
        ));
        // 第三个工具调用（index=1）与结束
        acc.apply_chunk(&make_chunk(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_2","function":{"name":"list_files","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#,
        ));

        let resp = acc.into_response();
        assert_eq!(resp.tool_calls.len(), 2);
        assert_eq!(resp.tool_calls[0].id, "call_1");
        assert_eq!(resp.tool_calls[0].name, "read_file");
        assert_eq!(resp.tool_calls[0].arguments, r#"{"path":"src/a.rs"}"#);
        assert_eq!(resp.tool_calls[1].name, "list_files");
        assert_eq!(resp.finish_reason.as_deref(), Some("tool_calls"));
    }

    /// reasoning_content 增量产生 Thinking 事件
    #[test]
    fn test_thinking_deltas() {
        let mut acc = StreamAccumulator::default();
        let events = acc.apply_chunk(&make_chunk(
            r#"{"choices":[{"delta":{"reasoning_content":"先分析路径"},"finish_reason":null}]}"#,
        ));
        assert!(matches!(&events[0], AgentEvent::Thinking { delta } if delta == "先分析路径"));
    }
}
