// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 客户端 trait 定义

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;

use super::error::LLMError;
use super::stream::{LLMStreamChunk, ToolCallDelta, Usage};

// ============================================================================
// 模型定义
// ============================================================================

/// LLM 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMMessage {
    /// 消息角色
    pub role: MessageRole,

    /// 消息内容
    pub content: Vec<MessageContent>,

    /// 缓存控制
    pub cache_control: Option<String>,
}

impl LLMMessage {
    /// 创建系统消息
    pub fn system(content: String) -> Self {
        Self {
            role: MessageRole::System,
            content: vec![MessageContent::Text { text: content }],
            cache_control: None,
        }
    }

    /// 创建用户消息
    pub fn user(content: String) -> Self {
        Self {
            role: MessageRole::User,
            content: vec![MessageContent::Text { text: content }],
            cache_control: None,
        }
    }

    /// 创建助手消息
    pub fn assistant(content: String) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: vec![MessageContent::Text { text: content }],
            cache_control: None,
        }
    }

    /// 创建带工具结果的用户消息
    pub fn user_with_tool_result(tool_id: String, result: String, is_error: bool) -> Self {
        Self {
            role: MessageRole::User,
            content: vec![MessageContent::ToolResult {
                tool_use_id: tool_id,
                content: result,
                is_error,
            }],
            cache_control: None,
        }
    }

    /// 获取消息文本内容
    pub fn get_text(&self) -> String {
        self.content
            .iter()
            .filter_map(|c| match c {
                MessageContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// 消息角色
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MessageRole {
    System,
    User,
    Assistant,
}

/// 消息内容
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MessageContent {
    /// 文本内容
    Text { text: String },

    /// 工具结果
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

/// LLM 响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMResponse {
    /// 响应内容
    pub content: Vec<MessageContent>,

    /// 工具调用
    pub tool_calls: Vec<ToolUse>,

    /// 使用量统计
    pub usage: Usage,

    /// 模型名称
    pub model: String,
}

impl LLMResponse {
    /// 获取响应文本
    pub fn get_text(&self) -> String {
        self.content
            .iter()
            .filter_map(|c| match c {
                MessageContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 是否有工具调用
    pub fn has_tool_calls(&self) -> bool {
        !self.tool_calls.is_empty()
    }

    /// 获取工具调用列表
    pub fn get_tool_calls(&self) -> &[ToolUse] {
        &self.tool_calls
    }
}

/// 工具调用
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUse {
    /// 调用 ID
    pub id: String,

    /// 工具名称
    pub name: String,

    /// 工具输入
    pub input: serde_json::Value,
}

// ============================================================================
// LLM Client Trait
// ============================================================================

/// LLM 客户端 trait
///
/// 所有 LLM 提供商都需要实现此接口
#[async_trait]
pub trait LLMClient: Send + Sync {
    /// 生成文本
    async fn generate(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError>;

    /// 生成文本（支持工具调用）
    async fn generate_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError>;

    /// 流式生成
    async fn generate_stream(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>>;

    /// 流式生成（支持工具调用）
    async fn generate_stream_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>>;

    /// 获取模型名称
    fn model(&self) -> &str;

    /// 获取提供商名称
    fn provider(&self) -> &str;
}

/// 工具定义（简化版）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// 工具名称
    pub name: String,

    /// 工具描述
    pub description: String,

    /// 工具参数
    pub input_schema: serde_json::Value,
}

// ============================================================================
// Stream Handler
// ============================================================================

/// 流式响应处理器
pub struct StreamHandler {
    /// 完整的响应内容
    content: String,

    /// 是否完成
    done: bool,

    /// 工具调用增量（如果有）
    tool_calls: Vec<ToolCallDelta>,
}

impl StreamHandler {
    /// 创建新的处理器
    pub fn new() -> Self {
        Self {
            content: String::new(),
            done: false,
            tool_calls: Vec::new(),
        }
    }

    /// 处理流式块
    pub fn process(&mut self, chunk: LLMStreamChunk) -> Result<(), LLMError> {
        if chunk.done {
            self.done = true;
            return Ok(());
        }

        // 添加内容
        self.content.push_str(&chunk.delta);

        // 处理工具调用增量
        if let Some(tool_delta) = chunk.tool_call_delta {
            match &tool_delta.id {
                Some(id) => {
                    // 查找或创建工具调用
                    let pos = self
                        .tool_calls
                        .iter()
                        .position(|t| t.id.as_ref().map(|i| i == id).unwrap_or(false));

                    if let Some(idx) = pos {
                        // 更新现有工具调用
                        let tool = &mut self.tool_calls[idx];
                        if tool_delta.name.is_some() {
                            tool.name = tool_delta.name;
                        }
                        if let Some(input_delta) = &tool_delta.input_delta {
                            tool.input_delta = Some(
                                tool.input_delta
                                    .as_ref()
                                    .map(|s| format!("{}{}", s, input_delta))
                                    .unwrap_or_else(|| input_delta.clone()),
                            );
                        }
                    } else {
                        // 创建新的工具调用
                        self.tool_calls.push(ToolCallDelta {
                            id: tool_delta.id,
                            name: tool_delta.name,
                            input_delta: tool_delta.input_delta,
                        });
                    }
                }
                None => {
                    // 没有 ID，可能是增量更新
                    if let Some(last) = self.tool_calls.last_mut() {
                        if let Some(input_delta) = &tool_delta.input_delta {
                            last.input_delta = Some(
                                last.input_delta
                                    .as_ref()
                                    .map(|s| format!("{}{}", s, input_delta))
                                    .unwrap_or_else(|| input_delta.clone()),
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 获取累积的内容
    pub fn content(&self) -> &str {
        &self.content
    }

    /// 是否完成
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// 获取工具调用
    pub fn tool_calls(&self) -> &[ToolCallDelta] {
        &self.tool_calls
    }

    /// 构建完整的工具调用（尝试解析增量）
    pub fn build_tool_calls(&self) -> Result<Vec<ToolUse>, LLMError> {
        let mut result = Vec::new();

        for delta in &self.tool_calls {
            let id = delta
                .id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let name = delta
                .name
                .clone()
                .ok_or_else(|| LLMError::InvalidResponse("工具调用缺少名称".to_string()))?;

            let input = if let Some(input_delta) = &delta.input_delta {
                // 尝试解析 JSON
                serde_json::from_str(input_delta).map_err(|e| {
                    LLMError::InvalidResponse(format!("无效的工具输入 JSON: {}", e))
                })?
            } else {
                serde_json::json!({})
            };

            result.push(ToolUse { id, name, input });
        }

        Ok(result)
    }
}

impl Default for StreamHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Batch Request Handler
// ============================================================================

/// 批量请求处理器
///
/// 用于批量处理多个 LLM 请求
pub struct BatchRequestHandler<T>
where
    T: LLMClient + Send + Sync,
{
    client: Arc<T>,
    concurrent_limit: usize,
}

impl<T> BatchRequestHandler<T>
where
    T: LLMClient + Send + Sync,
{
    /// 创建新的批处理器
    pub fn new(client: Arc<T>, concurrent_limit: usize) -> Self {
        Self {
            client,
            concurrent_limit,
        }
    }

    /// 批量生成
    pub async fn generate_batch(
        &self,
        requests: Vec<BatchRequest>,
    ) -> Vec<Result<LLMResponse, LLMError>> {
        use futures::stream::{self, StreamExt};

        let client = self.client.clone();
        stream::iter(requests)
            .map(move |req| {
                let client = client.clone();
                async move {
                    client
                        .generate(req.messages, req.max_tokens, req.temperature)
                        .await
                }
            })
            .buffer_unordered(self.concurrent_limit)
            .collect()
            .await
    }
}

/// 批量请求
pub struct BatchRequest {
    /// 消息列表
    pub messages: Vec<LLMMessage>,

    /// 最大 tokens
    pub max_tokens: u32,

    /// 温度
    pub temperature: f32,
}
