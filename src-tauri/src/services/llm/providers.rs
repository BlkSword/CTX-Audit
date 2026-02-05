//! LLM 提供商实现
//!
//! 支持 Anthropic (Claude), OpenAI, Ollama

use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// HeaderMap 需要从 reqwest::header 导入
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};

use crate::models::llm::LLMProviderConfig;
use crate::models::llm::{LLMError, LLMMessage, LLMResponse, LLMStreamChunk, MessageContent, MessageRole, Usage};
use crate::models::tools::ToolDefinition;

use super::client::LLMClient;

/// Anthropic Claude 客户端
pub struct AnthropicClient {
    config: LLMProviderConfig,
    http_client: reqwest::Client,
}

impl AnthropicClient {
    /// 创建新的 Anthropic 客户端
    pub fn new(config: LLMProviderConfig) -> Result<Self, LLMError> {
        let api_key = config
            .api_key
            .as_ref()
            .ok_or_else(|| LLMError::ConfigurationError("API key is required".to_string()))?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| LLMError::ConfigurationError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            http_client,
        })
    }

    /// 获取 API 基础 URL
    fn api_base(&self) -> &str {
        self.config
            .api_base
            .as_deref()
            .unwrap_or("https://api.anthropic.com")
    }

    /// 构建请求头
    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            self.config
                .api_key
                .as_ref()
                .unwrap()
                .parse()
                .unwrap(),
        );
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers
    }

    /// 转换消息为 Anthropic 格式
    fn convert_messages(&self, messages: Vec<LLMMessage>) -> serde_json::Value {
        let anthropic_messages: Vec<serde_json::Value> = messages
            .into_iter()
            .filter(|m| m.role != MessageRole::System)
            .map(|m| {
                serde_json::json!({
                    "role": m.role.to_string(),
                    "content": m.content,
                })
            })
            .collect();
        serde_json::json!(anthropic_messages)
    }

    /// 提取系统消息
    fn extract_system_message(&self, messages: &[LLMMessage]) -> String {
        messages
            .iter()
            .filter(|m| m.role == MessageRole::System)
            .map(|m| m.get_text())
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

#[async_trait]
impl LLMClient for AnthropicClient {
    async fn generate(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        let system_prompt = self.extract_system_message(&messages);
        let anthropic_messages = self.convert_messages(messages);

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        });

        if !system_prompt.is_empty() {
            body["system"] = serde_json::json!(system_prompt);
        }

        let response = self
            .http_client
            .post(format!("{}/v1/messages", self.api_base()))
            .headers(self.headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        let status = response.status();
        let response_text = response
            .text()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(LLMError::from_status(status.as_u16(), response_text));
        }

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| LLMError::InvalidResponse(format!("Invalid JSON: {}", e)))?;

        Ok(LLMResponse {
            content: serde_json::from_value(json["content"].clone()).unwrap_or_default(),
            model: json["model"].as_str().unwrap_or(&self.config.model).to_string(),
            usage: Usage {
                input_tokens: json["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32,
                output_tokens: json["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32,
                cache_creation_tokens: json["usage"]["cache_creation_tokens"]
                    .as_u64()
                    .map(|v| v as u32),
                cache_read_tokens: json["usage"]["cache_read_tokens"].as_u64().map(|v| v as u32),
            },
            stop_reason: json["stop_reason"].as_str().map(|s| s.to_string()),
            tool_calls: None,
            extra: Default::default(),
        })
    }

    async fn generate_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        let system_prompt = self.extract_system_message(&messages);
        let anthropic_messages = self.convert_messages(messages);

        let tools_json: Vec<serde_json::Value> =
            tools.iter().map(|t| t.to_anthropic_format()).collect();

        let mut body = serde_json::json!({
            "model": self.config.model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "tools": tools_json,
        });

        if !system_prompt.is_empty() {
            body["system"] = serde_json::json!(system_prompt);
        }

        let response = self
            .http_client
            .post(format!("{}/v1/messages", self.api_base()))
            .headers(self.headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        let status = response.status();
        let response_text = response
            .text()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(LLMError::from_status(status.as_u16(), response_text));
        }

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| LLMError::InvalidResponse(format!("Invalid JSON: {}", e)))?;

        // 提取工具调用
        let tool_calls = crate::models::llm::LLMResponse::get_tool_calls;

        Ok(LLMResponse {
            content: serde_json::from_value(json["content"].clone()).unwrap_or_default(),
            model: json["model"].as_str().unwrap_or(&self.config.model).to_string(),
            usage: Usage {
                input_tokens: json["usage"]["input_tokens"].as_u64().unwrap_or(0) as u32,
                output_tokens: json["usage"]["output_tokens"].as_u64().unwrap_or(0) as u32,
                cache_creation_tokens: json["usage"]["cache_creation_tokens"]
                    .as_u64()
                    .map(|v| v as u32),
                cache_read_tokens: json["usage"]["cache_read_tokens"].as_u64().map(|v| v as u32),
            },
            stop_reason: json["stop_reason"].as_str().map(|s| s.to_string()),
            tool_calls: None, // TODO: 从响应中提取工具调用
            extra: Default::default(),
        })
    }

    async fn generate_stream(
        &self,
        _messages: Vec<LLMMessage>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        // TODO: 实现流式生成
        Box::pin(stream::empty())
    }

    async fn generate_stream_with_tools(
        &self,
        _messages: Vec<LLMMessage>,
        _tools: Vec<ToolDefinition>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        // TODO: 实现流式生成
        Box::pin(stream::empty())
    }

    fn model(&self) -> &str {
        &self.config.model
    }

    fn provider(&self) -> &str {
        "anthropic"
    }
}

/// OpenAI 客户端
pub struct OpenAIClient {
    config: LLMProviderConfig,
    http_client: reqwest::Client,
}

impl OpenAIClient {
    /// 创建新的 OpenAI 客户端
    pub fn new(config: LLMProviderConfig) -> Result<Self, LLMError> {
        let api_key = config
            .api_key
            .as_ref()
            .ok_or_else(|| LLMError::ConfigurationError("API key is required".to_string()))?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| LLMError::ConfigurationError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            http_client,
        })
    }

    /// 获取 API 基础 URL
    fn api_base(&self) -> &str {
        self.config
            .api_base
            .as_deref()
            .unwrap_or("https://api.openai.com")
    }

    /// 构建请求头
    fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", self.config.api_key.as_ref().unwrap())
                .parse()
                .unwrap(),
        );
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers
    }

    /// 转换消息为 OpenAI 格式
    fn convert_messages(&self, messages: Vec<LLMMessage>) -> Vec<serde_json::Value> {
        messages
            .into_iter()
            .map(|m| {
                let content: Vec<MessageContent> = m
                    .content
                    .into_iter()
                    .filter(|c| {
                        // 过滤掉工具相关的内容（OpenAI 使用不同的格式）
                        !matches!(c, MessageContent::ToolUse { .. } | MessageContent::ToolResult { .. })
                    })
                    .collect();

                serde_json::json!({
                    "role": m.role.to_string(),
                    "content": if content.is_empty() {
                        serde_json::Value::String("...".to_string())
                    } else if content.len() == 1 {
                        serde_json::to_value(&content[0]).unwrap_or(serde_json::json!(""))
                    } else {
                        serde_json::to_value(&content).unwrap_or(serde_json::json!(""))
                    }
                })
            })
            .collect()
    }
}

#[async_trait]
impl LLMClient for OpenAIClient {
    async fn generate(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        let openai_messages = self.convert_messages(messages);

        let body = serde_json::json!({
            "model": self.config.model,
            "messages": openai_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        });

        let response = self
            .http_client
            .post(format!("{}/v1/chat/completions", self.api_base()))
            .headers(self.headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        let status = response.status();
        let response_text = response
            .text()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(LLMError::from_status(status.as_u16(), response_text));
        }

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| LLMError::InvalidResponse(format!("Invalid JSON: {}", e)))?;

        let choice = &json["choices"][0];
        let message = &choice["message"];

        Ok(LLMResponse {
            content: vec![MessageContent::Text {
                text: message["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            }],
            model: json["model"].as_str().unwrap_or(&self.config.model).to_string(),
            usage: Usage {
                input_tokens: json["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
                output_tokens: json["usage"]["completion_tokens"].as_u64().unwrap_or(0) as u32,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            },
            stop_reason: choice["finish_reason"].as_str().map(|s| s.to_string()),
            tool_calls: None,
            extra: Default::default(),
        })
    }

    async fn generate_with_tools(
        &self,
        _messages: Vec<LLMMessage>,
        _tools: Vec<ToolDefinition>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        // TODO: 实现工具调用
        Err(LLMError::UnsupportedOperation(
            "Tool calling not implemented for OpenAI yet".to_string(),
        ))
    }

    async fn generate_stream(
        &self,
        _messages: Vec<LLMMessage>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        Box::pin(stream::empty())
    }

    async fn generate_stream_with_tools(
        &self,
        _messages: Vec<LLMMessage>,
        _tools: Vec<ToolDefinition>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        Box::pin(stream::empty())
    }

    fn model(&self) -> &str {
        &self.config.model
    }

    fn provider(&self) -> &str {
        "openai"
    }
}

/// Ollama 客户端（本地模型）
pub struct OllamaClient {
    config: LLMProviderConfig,
    http_client: reqwest::Client,
}

impl OllamaClient {
    /// 创建新的 Ollama 客户端
    pub fn new(config: LLMProviderConfig) -> Result<Self, LLMError> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300)) // Ollama 可能需要更长时间
            .build()
            .map_err(|e| LLMError::ConfigurationError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            http_client,
        })
    }

    /// 获取 API 基础 URL
    fn api_base(&self) -> &str {
        self.config
            .api_base
            .as_deref()
            .unwrap_or("http://localhost:11434")
    }

    /// 转换消息为 Ollama 格式
    fn convert_messages(&self, messages: Vec<LLMMessage>) -> Vec<serde_json::Value> {
        messages
            .into_iter()
            .map(|m| {
                serde_json::json!({
                    "role": m.role.to_string(),
                    "content": m.get_text(),
                })
            })
            .collect()
    }
}

#[async_trait]
impl LLMClient for OllamaClient {
    async fn generate(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        let ollama_messages = self.convert_messages(messages);

        let body = serde_json::json!({
            "model": self.config.model,
            "messages": ollama_messages,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            }
        });

        let response = self
            .http_client
            .post(format!("{}/api/chat", self.api_base()))
            .json(&body)
            .send()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        let status = response.status();
        let response_text = response
            .text()
            .await
            .map_err(|e| LLMError::NetworkError(e.to_string()))?;

        if !status.is_success() {
            return Err(LLMError::from_status(status.as_u16(), response_text));
        }

        let json: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| LLMError::InvalidResponse(format!("Invalid JSON: {}", e)))?;

        Ok(LLMResponse {
            content: vec![MessageContent::Text {
                text: json["message"]["content"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            }],
            model: json["model"].as_str().unwrap_or(&self.config.model).to_string(),
            usage: Usage {
                input_tokens: json["prompt_eval_count"].as_u64().unwrap_or(0) as u32,
                output_tokens: json["eval_count"].as_u64().unwrap_or(0) as u32,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            },
            stop_reason: json["done_reason"].as_str().map(|s| s.to_string()),
            tool_calls: None,
            extra: Default::default(),
        })
    }

    async fn generate_with_tools(
        &self,
        _messages: Vec<LLMMessage>,
        _tools: Vec<ToolDefinition>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        // Ollama 支持工具调用，但需要单独实现
        Err(LLMError::UnsupportedOperation(
            "Tool calling not implemented for Ollama yet".to_string(),
        ))
    }

    async fn generate_stream(
        &self,
        _messages: Vec<LLMMessage>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        Box::pin(stream::empty())
    }

    async fn generate_stream_with_tools(
        &self,
        _messages: Vec<LLMMessage>,
        _tools: Vec<ToolDefinition>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        Box::pin(stream::empty())
    }

    fn model(&self) -> &str {
        &self.config.model
    }

    fn provider(&self) -> &str {
        "ollama"
    }
}
