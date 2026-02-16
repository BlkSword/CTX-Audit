// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 工具调用集成
//!
//! 处理 LLM 和工具系统之间的交互

use crate::base::{AgentContext, ToolCallRecord};
use ctx_audit_llm::{LLMClient, LLMMessage, MessageRole, ToolUse, Usage};
use ctx_audit_tools::{ToolRegistry, ToolResult, ToolDefinition};
use futures::StreamExt;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// 工具调用事件
#[derive(Debug, Clone)]
pub enum ToolCallEvent {
    /// 开始调用
    Start {
        tool_id: String,
        tool_name: String,
        input: serde_json::Value,
    },

    /// 流式 token
    Token {
        tool_id: String,
        delta: String,
    },

    /// 完成
    Complete {
        tool_id: String,
        tool_name: String,
        result: ToolResult,
        duration_ms: u64,
    },

    /// 失败
    Failed {
        tool_id: String,
        tool_name: String,
        error: String,
    },
}

/// LLM 工具调用管理器
pub struct LLMToolManager {
    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 工具注册表
    tool_registry: Arc<ToolRegistry>,

    /// 事件发送器
    event_tx: Option<mpsc::UnboundedSender<ToolCallEvent>>,
}

impl LLMToolManager {
    /// 创建新的管理器
    pub fn new(
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<ToolRegistry>,
    ) -> Self {
        Self {
            llm,
            tool_registry,
            event_tx: None,
        }
    }

    /// 设置事件发送器
    pub fn with_event_tx(mut self, tx: mpsc::UnboundedSender<ToolCallEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// 格式化工具定义为 LLM 格式
    pub async fn format_tools_for_llm(&self) -> Vec<ctx_audit_llm::ToolDefinition> {
        let tools = self.tool_registry.list_tools().await;

        tools
            .into_iter()
            .map(|tool| {
                let tool_def = tool.definition();
                ctx_audit_llm::ToolDefinition {
                    name: tool.name().to_string(),
                    description: tool.description().to_string(),
                    input_schema: self.build_input_schema(&tool_def),
                }
            })
            .collect()
    }

    /// 构建工具输入模式
    fn build_input_schema(
        &self,
        tool_def: &ctx_audit_tools::bridge::ToolDefinition,
    ) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for param in &tool_def.parameters {
            let param_schema = self.param_type_to_json_schema(&param);

            if param.required {
                required.push(param.name.clone());
            }

            properties.insert(param.name.clone(), param_schema);
        }

        json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }

    /// 将参数类型转换为 JSON Schema
    fn param_type_to_json_schema(
        &self,
        param: &ctx_audit_tools::bridge::ToolParameter,
    ) -> serde_json::Value {
        let (schema_type, schema_format) = match param.param_type {
            ctx_audit_tools::bridge::ToolParameterType::String => ("string", param.format.clone()),
            ctx_audit_tools::bridge::ToolParameterType::Number => ("number", None),
            ctx_audit_tools::bridge::ToolParameterType::Integer => ("integer", None),
            ctx_audit_tools::bridge::ToolParameterType::Boolean => ("boolean", None),
            ctx_audit_tools::bridge::ToolParameterType::Array => ("array", None),
            ctx_audit_tools::bridge::ToolParameterType::Object => ("object", None),
        };

        let mut schema = json!({
            "type": schema_type,
            "description": param.description,
        });

        if let Some(format) = schema_format {
            schema["format"] = json!(format);
        }

        if let Some(default) = &param.default {
            schema["default"] = default.clone();
        }

        if let Some(enum_values) = &param.enum_values {
            schema["enum"] = json!(enum_values);
        }

        schema
    }

    /// 执行工具调用（非流式）
    pub async fn execute_tool_call(
        &self,
        tool_use: &ToolUse,
    ) -> ToolCallRecord {
        let start = Instant::now();

        self.send_event(ToolCallEvent::Start {
            tool_id: tool_use.id.clone(),
            tool_name: tool_use.name.clone(),
            input: tool_use.input.clone(),
        });

        // 获取工具
        let tool = match self.tool_registry.get_tool(&tool_use.name) {
            Some(t) => t,
            None => {
                let error = format!("工具不存在: {}", tool_use.name);
                self.send_event(ToolCallEvent::Failed {
                    tool_id: tool_use.id.clone(),
                    tool_name: tool_use.name.clone(),
                    error: error.clone(),
                });

                return ToolCallRecord {
                    tool_name: tool_use.name.clone(),
                    input: tool_use.input.clone(),
                    output: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                    success: false,
                    error: Some(error),
                    timestamp: chrono::Utc::now(),
                };
            }
        };

        // 执行工具
        let result = tool.execute(tool_use.input.clone()).await;

        let duration = start.elapsed().as_millis() as u64;

        match result {
            Ok(res) => {
                self.send_event(ToolCallEvent::Complete {
                    tool_id: tool_use.id.clone(),
                    tool_name: tool_use.name.clone(),
                    result: res.clone(),
                    duration_ms: duration,
                });

                ToolCallRecord {
                    tool_name: tool_use.name.clone(),
                    input: tool_use.input.clone(),
                    output: Some(serde_json::json!({ "result": res.text })),
                    duration_ms: duration,
                    success: !res.is_error,
                    error: if res.is_error {
                        Some(res.text.clone())
                    } else {
                        None
                    },
                    timestamp: chrono::Utc::now(),
                }
            }
            Err(e) => {
                let error_msg = format!("工具执行失败: {}", e);
                self.send_event(ToolCallEvent::Failed {
                    tool_id: tool_use.id.clone(),
                    tool_name: tool_use.name.clone(),
                    error: error_msg.clone(),
                });

                ToolCallRecord {
                    tool_name: tool_use.name.clone(),
                    input: tool_use.input.clone(),
                    output: None,
                    duration_ms: duration,
                    success: false,
                    error: Some(error_msg),
                    timestamp: chrono::Utc::now(),
                }
            }
        }
    }

    /// 执行流式工具调用
    pub async fn execute_with_streaming(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMToolResponse, String> {
        let tools = self.format_tools_for_llm().await;

        // 调用 LLM（支持工具调用）
        let stream = self
            .llm
            .generate_stream_with_tools(messages, tools, max_tokens, temperature)
            .await;

        let mut full_content = String::new();
        let mut tool_calls = Vec::new();
        let mut current_tool: Option<(String, String, serde_json::Value)> = None;

        futures::pin_mut!(stream);

        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    if chunk.done {
                        break;
                    }

                    // 处理内容
                    if !chunk.delta.is_empty() {
                        full_content.push_str(&chunk.delta);

                        self.send_event(ToolCallEvent::Token {
                            tool_id: "llm".to_string(),
                            delta: chunk.delta,
                        });
                    }

                    // 处理工具调用增量
                    if let Some(tool_delta) = chunk.tool_call_delta {
                        match &tool_delta.id {
                            Some(id) => {
                                // 开始新的工具调用
                                if current_tool.is_none() {
                                    current_tool = Some((
                                        id.clone(),
                                        tool_delta.name.clone().unwrap_or_default(),
                                        serde_json::json!({}),
                                    ));
                                } else if current_tool.as_ref().map(|(i, _, _)| i) == Some(id) {
                                    // 更新现有工具调用
                                    if let Some((_, name, input)) = &mut current_tool {
                                        if let Some(n) = tool_delta.name {
                                            *name = n;
                                        }
                                        if let Some(input_delta) = &tool_delta.input_delta {
                                            // 尝试合并 JSON
                                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(input_delta) {
                                                *input = parsed;
                                            }
                                        }
                                    }
                                }
                            }
                            None => {
                                // 继续当前工具调用
                                if let Some((_, name, input)) = &mut current_tool {
                                    if let Some(n) = tool_delta.name {
                                        *name = n;
                                    }
                                    if let Some(input_delta) = &tool_delta.input_delta {
                                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(input_delta) {
                                            *input = parsed;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(format!("流式输出错误: {}", e));
                }
            }
        }

        // 完成工具调用
        if let Some((id, name, input)) = current_tool {
            tool_calls.push(ToolUse { id, name, input });
        }

        Ok(LLMToolResponse {
            content: full_content,
            tool_calls,
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
            },
        })
    }

    /// 发送事件
    fn send_event(&self, event: ToolCallEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event);
        }
    }
}

/// LLM 工具响应
#[derive(Debug, Clone)]
pub struct LLMToolResponse {
    /// 响应内容
    pub content: String,

    /// 工具调用
    pub tool_calls: Vec<ToolUse>,

    /// 使用量
    pub usage: Usage,
}
