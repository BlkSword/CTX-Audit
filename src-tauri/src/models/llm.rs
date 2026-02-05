//! LLM 相关的数据模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// LLM 消息角色
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    /// 系统消息
    System,
    /// 用户消息
    User,
    /// 助手消息
    Assistant,
}

impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageRole::System => write!(f, "system"),
            MessageRole::User => write!(f, "user"),
            MessageRole::Assistant => write!(f, "assistant"),
        }
    }
}

/// LLM 消息内容
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageContent {
    /// 文本内容
    Text { text: String },
    /// 图片内容（多模态）
    Image {
        /// 图片数据（base64 或 URL）
        source: ImageSource,
    },
    /// 工具使用（Anthropic 格式）
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// 工具结果（Anthropic 格式）
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: Option<bool>,
    },
}

/// 图片源
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ImageSource {
    /// Base64 编码的图片
    Base64 {
        media_type: String,
        data: String,
    },
    /// 图片 URL
    Url { url: String },
}

/// LLM 消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMMessage {
    /// 消息角色
    pub role: MessageRole,

    /// 消息内容
    pub content: Vec<MessageContent>,

    /// 缓存控制（用于提示词缓存）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

impl LLMMessage {
    /// 创建系统消息
    pub fn system(text: impl Into<String>) -> Self {
        Self {
            role: MessageRole::System,
            content: vec![MessageContent::Text {
                text: text.into(),
            }],
            cache_control: None,
        }
    }

    /// 创建用户消息
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: MessageRole::User,
            content: vec![MessageContent::Text {
                text: text.into(),
            }],
            cache_control: None,
        }
    }

    /// 创建助手消息
    pub fn assistant(text: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: vec![MessageContent::Text {
                text: text.into(),
            }],
            cache_control: None,
        }
    }

    /// 创建带工具使用的助手消息
    pub fn assistant_with_tool_use(tool_uses: Vec<ToolUse>) -> Self {
        let content = tool_uses
            .into_iter()
            .map(|tool_use| MessageContent::ToolUse {
                id: tool_use.id,
                name: tool_use.name,
                input: tool_use.input,
            })
            .collect();

        Self {
            role: MessageRole::Assistant,
            content,
            cache_control: None,
        }
    }

    /// 创建带工具结果的用户消息
    pub fn user_with_tool_result(tool_use_id: String, result: String, is_error: bool) -> Self {
        Self {
            role: MessageRole::User,
            content: vec![MessageContent::ToolResult {
                tool_use_id,
                content: result,
                is_error: Some(is_error),
            }],
            cache_control: None,
        }
    }

    /// 获取主要文本内容
    pub fn get_text(&self) -> String {
        self.content
            .iter()
            .filter_map(|c| match c {
                MessageContent::Text { text } => Some(text.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 添加缓存控制
    pub fn with_cache_control(mut self) -> Self {
        self.cache_control = Some(CacheControl::Breakpoint);
        self
    }
}

/// 缓存控制
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheControl {
    /// 缓存断点
    Breakpoint,
}

/// 工具调用
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUse {
    /// 工具调用 ID
    pub id: String,

    /// 工具名称
    pub name: String,

    /// 工具输入参数
    pub input: serde_json::Value,
}

impl ToolUse {
    /// 创建新的工具调用
    pub fn new(name: impl Into<String>, input: serde_json::Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.into(),
            input,
        }
    }
}

/// LLM 响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMResponse {
    /// 响应内容
    pub content: Vec<MessageContent>,

    /// 使用的模型
    pub model: String,

    /// Token 使用情况
    pub usage: Usage,

    /// 停止原因
    pub stop_reason: Option<String>,

    /// 工具调用（如果有）
    pub tool_calls: Option<Vec<ToolUse>>,

    /// 额外的响应元数据
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl LLMResponse {
    /// 获取响应文本
    pub fn get_text(&self) -> String {
        self.content
            .iter()
            .filter_map(|c| match c {
                MessageContent::Text { text } => Some(text.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 是否有工具调用
    pub fn has_tool_calls(&self) -> bool {
        self.content
            .iter()
            .any(|c| matches!(c, MessageContent::ToolUse { .. }))
    }

    /// 获取所有工具调用
    pub fn get_tool_calls(&self) -> Vec<ToolUse> {
        self.content
            .iter()
            .filter_map(|c| match c {
                MessageContent::ToolUse { id, name, input } => Some(ToolUse {
                    id: id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                }),
                _ => None,
            })
            .collect()
    }
}

/// Token 使用情况
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Usage {
    /// 输入 tokens
    pub input_tokens: u32,

    /// 输出 tokens
    pub output_tokens: u32,

    /// 缓存创建 tokens（缓存写入）
    pub cache_creation_tokens: Option<u32>,

    /// 缓存读取 tokens（缓存命中）
    pub cache_read_tokens: Option<u32>,
}

impl Usage {
    /// 总 tokens
    pub fn total_tokens(&self) -> u32 {
        self.input_tokens + self.output_tokens
    }

    /// 缓存节省的 tokens
    pub fn cache_saved_tokens(&self) -> u32 {
        self.cache_read_tokens.unwrap_or(0)
    }
}

/// 流式响应块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMStreamChunk {
    /// 增量内容
    pub delta: String,

    /// 是否完成
    pub done: bool,

    /// 工具调用增量（如果有）
    pub tool_call_delta: Option<ToolCallDelta>,

    /// 使用量（完成时提供）
    pub usage: Option<Usage>,
}

/// 工具调用增量（流式）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallDelta {
    /// 工具调用 ID
    pub id: Option<String>,

    /// 工具名称
    pub name: Option<String>,

    /// 工具输入增量（JSON 片段）
    pub input_delta: Option<String>,
}

/// LLM 错误类型
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum LLMError {
    /// 请求失败
    #[error("请求失败: {0}")]
    RequestFailed(String),

    /// 认证失败
    #[error("认证失败: {0}")]
    AuthenticationFailed(String),

    /// 速率限制
    #[error("速率限制: {0}")]
    RateLimited(String),

    /// 上下文过长
    #[error("上下文过长: 超过 {max_tokens} tokens")]
    ContextTooLong { max_tokens: u32 },

    /// 无效响应
    #[error("无效响应: {0}")]
    InvalidResponse(String),

    /// 超时
    #[error("请求超时")]
    Timeout,

    /// 提供商错误
    #[error("提供商错误: {code} - {message}")]
    ProviderError { code: String, message: String },

    /// 网络错误
    #[error("网络错误: {0}")]
    NetworkError(String),

    /// 配置错误
    #[error("配置错误: {0}")]
    ConfigurationError(String),

    /// 不支持的操作
    #[error("不支持的操作: {0}")]
    UnsupportedOperation(String),

    /// 其他错误
    #[error("未知错误: {0}")]
    Other(String),
}

impl LLMError {
    /// 从 HTTP 状态码和消息创建错误
    pub fn from_status(status: u16, message: String) -> Self {
        match status {
            401 | 403 => LLMError::AuthenticationFailed(message),
            429 => LLMError::RateLimited(message),
            400 => LLMError::ConfigurationError(message),
            408 => LLMError::Timeout,
            500..=599 => LLMError::ProviderError {
                code: status.to_string(),
                message,
            },
            _ => LLMError::RequestFailed(message),
        }
    }
}

/// LLM 提供商类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LLMProvider {
    /// Anthropic (Claude)
    Anthropic,
    /// OpenAI
    OpenAI,
    /// Ollama (本地)
    Ollama,
    /// 自定义提供商
    Custom,
}

impl std::fmt::Display for LLMProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LLMProvider::Anthropic => write!(f, "anthropic"),
            LLMProvider::OpenAI => write!(f, "openai"),
            LLMProvider::Ollama => write!(f, "ollama"),
            LLMProvider::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for LLMProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anthropic" => Ok(LLMProvider::Anthropic),
            "openai" => Ok(LLMProvider::OpenAI),
            "ollama" => Ok(LLMProvider::Ollama),
            _ => Ok(LLMProvider::Custom),
        }
    }
}

/// LLM 提供商配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMProviderConfig {
    /// 提供商类型 (anthropic, openai, ollama)
    pub provider: String,

    /// 模型名称
    pub model: String,

    /// API 基础 URL
    pub api_base: Option<String>,

    /// API 密钥
    pub api_key: Option<String>,

    /// 最大 tokens
    pub max_tokens: u32,

    /// 温度参数
    pub temperature: f32,

    /// 启用工具调用
    pub enable_tools: bool,
}

impl Default for LLMProviderConfig {
    fn default() -> Self {
        Self {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            api_base: None,
            api_key: None,
            max_tokens: 4096,
            temperature: 0.7,
            enable_tools: true,
        }
    }
}

// LLMProviderConfig 在此文件中已定义，无需从 agent 模块重新导出