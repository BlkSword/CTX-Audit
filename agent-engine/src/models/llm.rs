// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 模型定义

use serde::{Deserialize, Serialize};

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

/// 使用量统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// 输入 tokens
    pub input_tokens: u32,

    /// 输出 tokens
    pub output_tokens: u32,

    /// 总 tokens
    pub total_tokens: u32,
}

impl Usage {
    /// 获取总 tokens
    pub fn total_tokens(&self) -> u32 {
        self.total_tokens
    }
}

/// LLM 错误
#[derive(Debug, Clone, thiserror::Error)]
pub enum LLMError {
    #[error("请求失败: {0}")]
    RequestFailed(String),

    #[error("响应解析失败: {0}")]
    InvalidResponse(String),

    #[error("认证失败")]
    AuthenticationFailed,

    #[error("速率限制")]
    RateLimited,

    #[error("超时")]
    Timeout,

    #[error("未知错误: {0}")]
    Unknown(String),
}

/// 流式响应块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMStreamChunk {
    /// 内容增量
    pub delta: String,

    /// 是否完成
    pub done: bool,

    /// 工具调用增量
    pub tool_call_delta: Option<ToolCallDelta>,

    /// 使用量统计
    pub usage: Option<Usage>,
}

/// 工具调用增量
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallDelta {
    /// 调用 ID
    pub id: Option<String>,

    /// 工具名称
    pub name: Option<String>,

    /// 输入增量
    pub input_delta: Option<String>,
}
