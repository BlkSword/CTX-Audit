// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 提供商实现

use async_trait::async_trait;
use futures::{stream, Stream, StreamExt};
use serde_json::json;
use std::pin::Pin;
use std::time::Duration;

use super::client::{LLMClient, LLMMessage, LLMResponse, MessageContent, ToolDefinition, Usage, ToolUse};
use super::error::LLMError;
use super::stream::{LLMStreamChunk, ToolCallDelta};

// ============================================================================
// Anthropic Claude 客户端
// ============================================================================

/// Anthropic Claude 客户端
pub struct AnthropicClient {
    api_key: String,
    model: String,
    base_url: String,
    client: reqwest::Client,
}

impl AnthropicClient {
    /// 创建新的 Anthropic 客户端
    pub fn new(api_key: String, model: Option<String>) -> Result<Self, LLMError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| LLMError::ConfigError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            api_key,
            model: model.unwrap_or_else(|| "claude-3-5-sonnet-20241022".to_string()),
            base_url: "https://api.anthropic.com/v1/messages".to_string(),
            client,
        })
    }

    /// 转换消息格式
    fn convert_messages(&self, messages: Vec<LLMMessage>) -> serde_json::Value {
        let converted: Vec<serde_json::Value> = messages
            .into_iter()
            .map(|msg| {
                let role = match msg.role {
                    super::client::MessageRole::System => "system",
                    super::client::MessageRole::User => "user",
                    super::client::MessageRole::Assistant => "assistant",
                };

                let content: Vec<serde_json::Value> = msg
                    .content
                    .into_iter()
                    .map(|c| match c {
                        MessageContent::Text { text } => json!({
                            "type": "text",
                            "text": text
                        }),
                        MessageContent::ToolResult { tool_use_id, content, is_error } => json!({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": content,
                            "is_error": is_error
                        }),
                    })
                    .collect();

                json!({
                    "role": role,
                    "content": content
                })
            })
            .collect();

        json!(converted)
    }

    /// 转换工具定义格式
    fn convert_tools(&self, tools: Vec<ToolDefinition>) -> Vec<serde_json::Value> {
        tools
            .into_iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema
                })
            })
            .collect()
    }

    /// 发送 API 请求
    async fn send_request(
        &self,
        messages: Vec<LLMMessage>,
        tools: Option<Vec<ToolDefinition>>,
        max_tokens: u32,
        temperature: f32,
        stream: bool,
    ) -> Result<reqwest::Response, LLMError> {
        let mut payload = json!({
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": self.convert_messages(messages),
            "stream": stream
        });

        if let Some(temp) = self.temperature_to_option(temperature) {
            payload["temperature"] = json!(temp);
        }

        if let Some(tool_list) = tools {
            payload["tools"] = json!(self.convert_tools(tool_list));
        }

        self.client
            .post(&self.base_url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| LLMError::RequestFailed(format!("HTTP request failed: {}", e)))
    }

    /// 温度参数转换
    fn temperature_to_option(&self, temp: f32) -> Option<f64> {
        if temp > 0.0 {
            Some(temp as f64)
        } else {
            None
        }
    }

    /// 解析响应
    fn parse_response(&self, response_text: &str, model: String) -> Result<LLMResponse, LLMError> {
        let json_response: serde_json::Value = serde_json::from_str(response_text)
            .map_err(|e| LLMError::InvalidResponse(format!("Failed to parse JSON: {}", e)))?;

        let mut content = Vec::new();
        let mut tool_calls = Vec::new();

        if let Some(content_array) = json_response.get("content").and_then(|c| c.as_array()) {
            for item in content_array {
                if let Some(item_type) = item.get("type").and_then(|t| t.as_str()) {
                    match item_type {
                        "text" => {
                            if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                                content.push(MessageContent::Text {
                                    text: text.to_string(),
                                });
                            }
                        }
                        "tool_use" => {
                            if let Some(id) = item.get("id").and_then(|i| i.as_str()) {
                                if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                                    if let Some(input) = item.get("input") {
                                        tool_calls.push(ToolUse {
                                            id: id.to_string(),
                                            name: name.to_string(),
                                            input: input.clone(),
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        let usage = if let Some(usage_obj) = json_response.get("usage") {
            Usage {
                input_tokens: usage_obj
                    .get("input_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0) as u32,
                output_tokens: usage_obj
                    .get("output_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0) as u32,
                total_tokens: usage_obj
                    .get("input_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0) as u32
                    + usage_obj
                        .get("output_tokens")
                        .and_then(|t| t.as_u64())
                        .unwrap_or(0) as u32,
            }
        } else {
            Usage {
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
            }
        };

        Ok(LLMResponse {
            content,
            tool_calls,
            usage,
            model,
        })
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
        let response = self
            .send_request(messages, None, max_tokens, temperature, false)
            .await?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            LLMError::RequestFailed(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            return Err(handle_anthropic_error(status, &response_text));
        }

        self.parse_response(&response_text, self.model.clone())
    }

    async fn generate_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        let response = self
            .send_request(messages, Some(tools), max_tokens, temperature, false)
            .await?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            LLMError::RequestFailed(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            return Err(handle_anthropic_error(status, &response_text));
        }

        self.parse_response(&response_text, self.model.clone())
    }

    async fn generate_stream(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        let client = self.client.clone();
        let api_key = self.api_key.clone();
        let base_url = self.base_url.clone();
        let model = self.model.clone();

        Box::pin(async_stream::stream! {
            let payload = match build_anthropic_payload(&messages, max_tokens, temperature, None, &model) {
                Ok(p) => p,
                Err(e) => {
                    yield Err(e);
                    return;
                }
            };

            let response = match client
                .post(&base_url)
                .header("x-api-key", &api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&payload)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    yield Err(LLMError::RequestFailed(format!("HTTP request failed: {}", e)));
                    return;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let response_text = match response.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Failed to read response: {}", e)));
                        return;
                    }
                };
                yield Err(handle_anthropic_error(status, &response_text));
                return;
            }

            let mut bytes = response.bytes_stream();
            let mut buffer = String::new();

            while let Some(chunk_result) = bytes.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Stream chunk error: {}", e)));
                        return;
                    }
                };

                buffer.push_str(&String::from_utf8_lossy(&chunk));

                while let Some(newline_pos) = buffer.find('\n') {
                    let line: String = buffer.drain(..=newline_pos).collect();

                    let line = line.trim();
                    if line.is_empty() || !line.starts_with("data:") {
                        continue;
                    }

                    let json_str = &line[5..].trim();
                    if *json_str == "[DONE]" {
                        yield Ok(LLMStreamChunk {
                            delta: String::new(),
                            done: true,
                            tool_call_delta: None,
                            usage: None,
                        });
                        return;
                    }

                    match serde_json::from_str::<serde_json::Value>(json_str) {
                        Ok(event) => {
                            if let Some(chunk_data) = parse_anthropic_stream_event(&event) {
                                yield Ok(chunk_data);
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        })
    }

    async fn generate_stream_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        let client = self.client.clone();
        let api_key = self.api_key.clone();
        let base_url = self.base_url.clone();
        let model = self.model.clone();

        Box::pin(async_stream::stream! {
            let payload = match build_anthropic_payload(&messages, max_tokens, temperature, Some(tools), &model) {
                Ok(p) => p,
                Err(e) => {
                    yield Err(e);
                    return;
                }
            };

            let response = match client
                .post(&base_url)
                .header("x-api-key", &api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&payload)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    yield Err(LLMError::RequestFailed(format!("HTTP request failed: {}", e)));
                    return;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let response_text = match response.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Failed to read response: {}", e)));
                        return;
                    }
                };
                yield Err(handle_anthropic_error(status, &response_text));
                return;
            }

            let mut bytes = response.bytes_stream();
            let mut buffer = String::new();

            while let Some(chunk_result) = bytes.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Stream chunk error: {}", e)));
                        return;
                    }
                };

                buffer.push_str(&String::from_utf8_lossy(&chunk));

                while let Some(newline_pos) = buffer.find('\n') {
                    let line: String = buffer.drain(..=newline_pos).collect();

                    let line = line.trim();
                    if line.is_empty() || !line.starts_with("data:") {
                        continue;
                    }

                    let json_str = &line[5..].trim();
                    if *json_str == "[DONE]" {
                        yield Ok(LLMStreamChunk {
                            delta: String::new(),
                            done: true,
                            tool_call_delta: None,
                            usage: None,
                        });
                        return;
                    }

                    match serde_json::from_str::<serde_json::Value>(json_str) {
                        Ok(event) => {
                            if let Some(chunk_data) = parse_anthropic_stream_event(&event) {
                                yield Ok(chunk_data);
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        })
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn provider(&self) -> &str {
        "anthropic"
    }
}

/// 构建 Anthropic 请求 payload
fn build_anthropic_payload(
    messages: &[LLMMessage],
    max_tokens: u32,
    temperature: f32,
    tools: Option<Vec<ToolDefinition>>,
    model: &str,
) -> Result<serde_json::Value, LLMError> {
    let converted_messages: Vec<serde_json::Value> = messages
        .iter()
        .map(|msg| {
            let role = match msg.role {
                super::client::MessageRole::System => "system",
                super::client::MessageRole::User => "user",
                super::client::MessageRole::Assistant => "assistant",
            };

            let content: Vec<serde_json::Value> = msg
                .content
                .iter()
                .map(|c| match c {
                    MessageContent::Text { text } => json!({
                        "type": "text",
                        "text": text
                    }),
                    MessageContent::ToolResult { tool_use_id, content, is_error } => json!({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": content,
                        "is_error": is_error
                    }),
                })
                .collect();

            json!({
                "role": role,
                "content": content
            })
        })
        .collect();

    let mut payload = json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": converted_messages,
        "stream": true
    });

    if temperature > 0.0 {
        payload["temperature"] = json!(temperature as f64);
    }

    if let Some(tool_list) = tools {
        let converted_tools: Vec<serde_json::Value> = tool_list
            .into_iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema
                })
            })
            .collect();
        payload["tools"] = json!(converted_tools);
    }

    Ok(payload)
}

/// 解析 Anthropic 流式事件
fn parse_anthropic_stream_event(event: &serde_json::Value) -> Option<LLMStreamChunk> {
    let event_type = event.get("type")?.as_str()?;

    match event_type {
        "content_block_start" => {
            if let Some(content_block) = event.get("content_block") {
                if content_block.get("type")?.as_str()? == "tool_use" {
                    Some(LLMStreamChunk {
                        delta: String::new(),
                        done: false,
                        tool_call_delta: Some(ToolCallDelta {
                            id: content_block.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()),
                            name: content_block.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()),
                            input_delta: None,
                        }),
                        usage: None,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        }
        "content_block_delta" => {
            let delta = event.get("delta")?;
            if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                Some(LLMStreamChunk {
                    delta: text.to_string(),
                    done: false,
                    tool_call_delta: None,
                    usage: None,
                })
            } else if let Some(partial_json) = delta.get("partial_json").and_then(|j| j.as_str()) {
                let index = event.get("index")?.as_u64()? as usize;
                Some(LLMStreamChunk {
                    delta: String::new(),
                    done: false,
                    tool_call_delta: Some(ToolCallDelta {
                        id: None,
                        name: None,
                        input_delta: if index == 0 { Some(partial_json.to_string()) } else { None },
                    }),
                    usage: None,
                })
            } else {
                None
            }
        }
        "message_delta" => {
            let usage = if let Some(usage_obj) = event.get("usage") {
                Some(super::stream::Usage {
                    input_tokens: usage_obj.get("input_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                    output_tokens: usage_obj.get("output_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                    total_tokens: usage_obj.get("input_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32
                        + usage_obj.get("output_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                })
            } else {
                None
            };

            Some(LLMStreamChunk {
                delta: String::new(),
                done: true,
                tool_call_delta: None,
                usage,
            })
        }
        _ => None,
    }
}

/// 处理 Anthropic 错误响应
fn handle_anthropic_error(status: reqwest::StatusCode, body: &str) -> LLMError {
    // 记录完整的错误响应以便调试
    eprintln!("=== LLM API Error ===");
    eprintln!("Status: {}", status);
    eprintln!("Response: {}", body);
    eprintln!("====================");

    if status.as_u16() == 401 {
        LLMError::AuthenticationFailed
    } else if status.as_u16() == 429 {
        LLMError::RateLimited
    } else if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(error_obj) = error_json.get("error") {
            let message = error_obj
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");

            let error_type = error_obj
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            match error_type {
                "authentication_error" => LLMError::AuthenticationFailed,
                "rate_limit_error" => LLMError::RateLimited,
                "invalid_request_error" => LLMError::ConfigError(message.to_string()),
                _ => LLMError::RequestFailed(message.to_string()),
            }
        } else {
            LLMError::RequestFailed(body.to_string())
        }
    } else {
        LLMError::RequestFailed(format!("HTTP {}: {}", status.as_u16(), body))
    }
}

// ============================================================================
// OpenAI 客户端
// ============================================================================

/// OpenAI 客户端
pub struct OpenAIClient {
    api_key: String,
    model: String,
    base_url: String,
    client: reqwest::Client,
}

impl OpenAIClient {
    /// 创建新的 OpenAI 客户端
    pub fn new(
        api_key: String,
        model: Option<String>,
        base_url: Option<String>,
    ) -> Result<Self, LLMError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| LLMError::ConfigError(format!("Failed to create HTTP client: {}", e)))?;

        // 智能 base_url 处理
        let final_url = match base_url {
            Some(url) => {
                // 如果已经包含 /chat/completions，直接使用
                if url.contains("/chat/completions") {
                    url
                }
                // 如果以 /v4 或 /v1 结尾（智谱、DeepSeek 等），追加 /chat/completions
                else if url.ends_with("/v4") || url.ends_with("/v1") {
                    url + "/chat/completions"
                }
                // 如果 URL 以 / 结尾，去掉后再追加
                else if url.ends_with('/') {
                    url.trim_end_matches('/').to_string() + "/chat/completions"
                }
                // 否则直接追加
                else {
                    url + "/chat/completions"
                }
            }
            None => "https://api.openai.com/v1/chat/completions".to_string(),
        };

        Ok(Self {
            api_key,
            model: model.unwrap_or_else(|| "gpt-4".to_string()),
            base_url: final_url,
            client,
        })
    }

    /// 转换消息格式
    fn convert_messages(&self, messages: Vec<LLMMessage>) -> Vec<serde_json::Value> {
        messages
            .into_iter()
            .map(|msg| {
                let role = match msg.role {
                    super::client::MessageRole::System => "system",
                    super::client::MessageRole::User => "user",
                    super::client::MessageRole::Assistant => "assistant",
                };

                // OpenAI 使用字符串内容
                let content: String = msg
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        MessageContent::Text { text } => Some(text.as_str()),
                        MessageContent::ToolResult { .. } => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                json!({
                    "role": role,
                    "content": content
                })
            })
            .collect()
    }

    /// 转换工具定义格式
    fn convert_tools(&self, tools: Vec<ToolDefinition>) -> Vec<serde_json::Value> {
        tools
            .into_iter()
            .map(|tool| {
                json!({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema
                    }
                })
            })
            .collect()
    }

    /// 发送 API 请求
    async fn send_request(
        &self,
        messages: Vec<LLMMessage>,
        tools: Option<Vec<ToolDefinition>>,
        max_tokens: u32,
        temperature: f32,
        stream: bool,
    ) -> Result<reqwest::Response, LLMError> {
        let mut payload = json!({
            "model": self.model,
            "messages": self.convert_messages(messages),
            "stream": stream
        });

        if max_tokens > 0 {
            payload["max_tokens"] = json!(max_tokens);
        }

        if temperature > 0.0 {
            payload["temperature"] = json!(temperature as f64);
        }

        if let Some(tool_list) = tools {
            payload["tools"] = json!(self.convert_tools(tool_list));
        }

        self.client
            .post(&self.base_url)
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| LLMError::RequestFailed(format!("HTTP request failed: {}", e)))
    }

    /// 解析响应
    fn parse_response(&self, response_text: &str) -> Result<LLMResponse, LLMError> {
        let json_response: serde_json::Value = serde_json::from_str(response_text)
            .map_err(|e| LLMError::InvalidResponse(format!("Failed to parse JSON: {}", e)))?;

        let content = if let Some(choices) = json_response.get("choices").and_then(|c| c.as_array()) {
            if let Some(choice) = choices.first() {
                if let Some(msg) = choice.get("message") {
                    if let Some(text) = msg.get("content").and_then(|c| c.as_str()) {
                        vec![MessageContent::Text {
                            text: text.to_string(),
                        }]
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let mut tool_calls = Vec::new();
        if let Some(choices) = json_response.get("choices").and_then(|c| c.as_array()) {
            if let Some(choice) = choices.first() {
                if let Some(msg) = choice.get("message") {
                    if let Some(calls) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                        for call in calls {
                            if let Some(function) = call.get("function") {
                                let id = call.get("id").and_then(|i| i.as_str()).unwrap_or("");
                                let name = function.get("name").and_then(|n| n.as_str()).unwrap_or("");
                                let arguments_str = function.get("arguments").and_then(|a| a.as_str()).unwrap_or("{}");

                                if let Ok(arguments) = serde_json::from_str::<serde_json::Value>(arguments_str) {
                                    tool_calls.push(ToolUse {
                                        id: id.to_string(),
                                        name: name.to_string(),
                                        input: arguments,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let usage = if let Some(usage_obj) = json_response.get("usage") {
            Usage {
                input_tokens: usage_obj
                    .get("prompt_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0) as u32,
                output_tokens: usage_obj
                    .get("completion_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0) as u32,
                total_tokens: usage_obj
                    .get("total_tokens")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0) as u32,
            }
        } else {
            Usage {
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
            }
        };

        Ok(LLMResponse {
            content,
            tool_calls,
            usage,
            model: self.model.clone(),
        })
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
        let response = self
            .send_request(messages, None, max_tokens, temperature, false)
            .await?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            LLMError::RequestFailed(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            return Err(handle_openai_error(status, &response_text));
        }

        self.parse_response(&response_text)
    }

    async fn generate_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        let response = self
            .send_request(messages, Some(tools), max_tokens, temperature, false)
            .await?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            LLMError::RequestFailed(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            return Err(handle_openai_error(status, &response_text));
        }

        self.parse_response(&response_text)
    }

    async fn generate_stream(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        let client = self.client.clone();
        let api_key = self.api_key.clone();
        let base_url = self.base_url.clone();
        let model = self.model.clone();
        let converted_messages = Self::convert_messages_static(messages);

        Box::pin(async_stream::stream! {
            let payload = json!({
                "model": model,
                "messages": converted_messages,
                "stream": true
            });

            let response = match client
                .post(&base_url)
                .header("authorization", format!("Bearer {}", api_key))
                .header("content-type", "application/json")
                .json(&payload)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    yield Err(LLMError::RequestFailed(format!("HTTP request failed: {}", e)));
                    return;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let response_text = match response.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Failed to read response: {}", e)));
                        return;
                    }
                };
                yield Err(handle_openai_error(status, &response_text));
                return;
            }

            let mut bytes = response.bytes_stream();
            let mut buffer = String::new();

            while let Some(chunk_result) = bytes.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Stream chunk error: {}", e)));
                        return;
                    }
                };

                buffer.push_str(&String::from_utf8_lossy(&chunk));

                while let Some(newline_pos) = buffer.find('\n') {
                    let line: String = buffer.drain(..=newline_pos).collect();

                    let line = line.trim();
                    if line.is_empty() || !line.starts_with("data:") {
                        continue;
                    }

                    let json_str = &line[5..].trim();
                    if *json_str == "[DONE]" {
                        yield Ok(LLMStreamChunk {
                            delta: String::new(),
                            done: true,
                            tool_call_delta: None,
                            usage: None,
                        });
                        return;
                    }

                    match serde_json::from_str::<serde_json::Value>(json_str) {
                        Ok(event) => {
                            if let Some(chunk_data) = parse_openai_stream_event(&event) {
                                yield Ok(chunk_data);
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        })
    }

    async fn generate_stream_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        let client = self.client.clone();
        let api_key = self.api_key.clone();
        let base_url = self.base_url.clone();
        let model = self.model.clone();
        let converted_messages = Self::convert_messages_static(messages);
        let converted_tools = Self::convert_tools_static(tools);

        Box::pin(async_stream::stream! {
            let mut payload = json!({
                "model": model,
                "messages": converted_messages,
                "stream": true,
                "tools": converted_tools
            });

            if max_tokens > 0 {
                payload["max_tokens"] = json!(max_tokens);
            }

            if temperature > 0.0 {
                payload["temperature"] = json!(temperature as f64);
            }

            let response = match client
                .post(&base_url)
                .header("authorization", format!("Bearer {}", api_key))
                .header("content-type", "application/json")
                .json(&payload)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    yield Err(LLMError::RequestFailed(format!("HTTP request failed: {}", e)));
                    return;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let response_text = match response.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Failed to read response: {}", e)));
                        return;
                    }
                };
                yield Err(handle_openai_error(status, &response_text));
                return;
            }

            let mut bytes = response.bytes_stream();
            let mut buffer = String::new();

            while let Some(chunk_result) = bytes.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Stream chunk error: {}", e)));
                        return;
                    }
                };

                buffer.push_str(&String::from_utf8_lossy(&chunk));

                while let Some(newline_pos) = buffer.find('\n') {
                    let line: String = buffer.drain(..=newline_pos).collect();

                    let line = line.trim();
                    if line.is_empty() || !line.starts_with("data:") {
                        continue;
                    }

                    let json_str = &line[5..].trim();
                    if *json_str == "[DONE]" {
                        yield Ok(LLMStreamChunk {
                            delta: String::new(),
                            done: true,
                            tool_call_delta: None,
                            usage: None,
                        });
                        return;
                    }

                    match serde_json::from_str::<serde_json::Value>(json_str) {
                        Ok(event) => {
                            if let Some(chunk_data) = parse_openai_stream_event(&event) {
                                yield Ok(chunk_data);
                            }
                        }
                        Err(_) => continue,
                    }
                }
            }
        })
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn provider(&self) -> &str {
        "openai"
    }
}

impl OpenAIClient {
    fn convert_messages_static(messages: Vec<LLMMessage>) -> Vec<serde_json::Value> {
        messages
            .into_iter()
            .map(|msg| {
                let role = match msg.role {
                    super::client::MessageRole::System => "system",
                    super::client::MessageRole::User => "user",
                    super::client::MessageRole::Assistant => "assistant",
                };

                let content: String = msg
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        MessageContent::Text { text } => Some(text.as_str()),
                        MessageContent::ToolResult { .. } => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                json!({
                    "role": role,
                    "content": content
                })
            })
            .collect()
    }

    fn convert_tools_static(tools: Vec<ToolDefinition>) -> Vec<serde_json::Value> {
        tools
            .into_iter()
            .map(|tool| {
                json!({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.input_schema
                    }
                })
            })
            .collect()
    }
}

/// 解析 OpenAI 流式事件
fn parse_openai_stream_event(event: &serde_json::Value) -> Option<LLMStreamChunk> {
    let choices = event.get("choices")?.as_array()?.first()?;

    if let Some(delta) = choices.get("delta") {
        if let Some(text) = delta.get("content").and_then(|c| c.as_str()) {
            return Some(LLMStreamChunk {
                delta: text.to_string(),
                done: false,
                tool_call_delta: None,
                usage: None,
            });
        }
    }

    if choices.get("finish_reason").is_some() {
        if let Some(usage_obj) = event.get("usage") {
            return Some(LLMStreamChunk {
                delta: String::new(),
                done: true,
                tool_call_delta: None,
                usage: Some(super::stream::Usage {
                    input_tokens: usage_obj.get("prompt_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                    output_tokens: usage_obj.get("completion_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                    total_tokens: usage_obj.get("total_tokens").and_then(|t| t.as_u64()).unwrap_or(0) as u32,
                }),
            });
        }
    }

    None
}

/// 处理 OpenAI 错误响应
fn handle_openai_error(status: reqwest::StatusCode, body: &str) -> LLMError {
    // 记录完整的错误响应以便调试
    eprintln!("=== LLM API Error ===");
    eprintln!("Status: {}", status);
    eprintln!("Response: {}", body);
    eprintln!("====================");

    if status.as_u16() == 401 {
        LLMError::AuthenticationFailed
    } else if status.as_u16() == 429 {
        LLMError::RateLimited
    } else if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(error_obj) = error_json.get("error") {
            let message = error_obj
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("Unknown error");

            let error_type = error_obj
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");

            // 构建详细的错误信息
            let error_detail = format!("{} (type: {})", message, error_type);

            match error_type {
                "invalid_request_error" => LLMError::ConfigError(error_detail),
                _ => LLMError::RequestFailed(error_detail),
            }
        } else {
            // 如果无法解析错误对象，返回完整的响应体
            LLMError::RequestFailed(format!("HTTP {}: {}", status.as_u16(), body))
        }
    } else {
        LLMError::RequestFailed(format!("HTTP {}: {}", status.as_u16(), body))
    }
}

// ============================================================================
// Ollama 客户端
// ============================================================================

/// Ollama 客户端
pub struct OllamaClient {
    model: String,
    base_url: String,
    client: reqwest::Client,
}

impl OllamaClient {
    /// 创建新的 Ollama 客户端
    pub fn new(model: Option<String>, base_url: String) -> Result<Self, LLMError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| LLMError::ConfigError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            model: model.unwrap_or_else(|| "llama2".to_string()),
            base_url: base_url.trim_end_matches('/').to_string() + "/api/generate",
            client,
        })
    }

    /// 构建提示词
    fn build_prompt(&self, messages: Vec<LLMMessage>) -> String {
        messages
            .into_iter()
            .map(|msg| {
                let role = match msg.role {
                    super::client::MessageRole::System => "System",
                    super::client::MessageRole::User => "User",
                    super::client::MessageRole::Assistant => "Assistant",
                };

                let content: String = msg
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        MessageContent::Text { text } => Some(text.as_str()),
                        MessageContent::ToolResult { content, .. } => Some(content.as_str()),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                format!("{}: {}", role, content)
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

#[async_trait]
impl LLMClient for OllamaClient {
    async fn generate(
        &self,
        messages: Vec<LLMMessage>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        let prompt = self.build_prompt(messages);

        let payload = json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });

        let response = self
            .client
            .post(&self.base_url)
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| LLMError::RequestFailed(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response.text().await.map_err(|e| {
            LLMError::RequestFailed(format!("Failed to read response body: {}", e))
        })?;

        if !status.is_success() {
            return Err(LLMError::RequestFailed(format!(
                "HTTP {}: {}",
                status.as_u16(),
                response_text
            )));
        }

        let json_response: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| LLMError::InvalidResponse(format!("Failed to parse JSON: {}", e)))?;

        let text = json_response
            .get("response")
            .and_then(|r| r.as_str())
            .unwrap_or("");

        Ok(LLMResponse {
            content: vec![MessageContent::Text {
                text: text.to_string(),
            }],
            tool_calls: Vec::new(),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
            },
            model: self.model.clone(),
        })
    }

    async fn generate_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        _tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        // Ollama 工具调用支持有限，暂时返回普通响应
        self.generate(messages, max_tokens, temperature).await
    }

    async fn generate_stream(
        &self,
        messages: Vec<LLMMessage>,
        _max_tokens: u32,
        _temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        let client = self.client.clone();
        let base_url = self.base_url.clone();
        let model = self.model.clone();
        let prompt = Self::build_prompt_static(messages);

        Box::pin(async_stream::stream! {
            let payload = json!({
                "model": model,
                "prompt": prompt,
                "stream": true
            });

            let response = match client
                .post(&base_url)
                .header("content-type", "application/json")
                .json(&payload)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    yield Err(LLMError::RequestFailed(format!("HTTP request failed: {}", e)));
                    return;
                }
            };

            let status = response.status();
            if !status.is_success() {
                let response_text = match response.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Failed to read response: {}", e)));
                        return;
                    }
                };
                yield Err(LLMError::RequestFailed(format!("HTTP {}: {}", status.as_u16(), response_text)));
                return;
            }

            let mut bytes = response.bytes_stream();

            while let Some(chunk_result) = bytes.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        yield Err(LLMError::RequestFailed(format!("Stream chunk error: {}", e)));
                        return;
                    }
                };

                let json_str = String::from_utf8_lossy(&chunk);
                if let Ok(json_response) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    if let Some(done) = json_response.get("done").and_then(|d| d.as_bool()) {
                        if done {
                            yield Ok(LLMStreamChunk {
                                delta: String::new(),
                                done: true,
                                tool_call_delta: None,
                                usage: None,
                            });
                            return;
                        }
                    }

                    if let Some(response) = json_response.get("response").and_then(|r| r.as_str()) {
                        yield Ok(LLMStreamChunk {
                            delta: response.to_string(),
                            done: false,
                            tool_call_delta: None,
                            usage: None,
                        });
                    }
                }
            }
        })
    }

    async fn generate_stream_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        // Ollama 工具调用支持有限
        self.generate_stream(messages, max_tokens, temperature).await
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn provider(&self) -> &str {
        "ollama"
    }
}

impl OllamaClient {
    fn build_prompt_static(messages: Vec<LLMMessage>) -> String {
        messages
            .into_iter()
            .map(|msg| {
                let role = match msg.role {
                    super::client::MessageRole::System => "System",
                    super::client::MessageRole::User => "User",
                    super::client::MessageRole::Assistant => "Assistant",
                };

                let content: String = msg
                    .content
                    .iter()
                    .filter_map(|c| match c {
                        MessageContent::Text { text } => Some(text.as_str()),
                        MessageContent::ToolResult { content, .. } => Some(content.as_str()),
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                format!("{}: {}", role, content)
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}
