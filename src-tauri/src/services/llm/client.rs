//! LLM 客户端 trait 定义

use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;

use crate::models::llm::{LLMError, LLMMessage, LLMResponse, LLMStreamChunk, Usage};
use crate::models::tools::ToolDefinition;

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

/// 流式响应处理器
pub struct StreamHandler {
    /// 完整的响应内容
    content: String,

    /// 是否完成
    done: bool,

    /// 工具调用增量（如果有）
    tool_calls: Vec<ToolCallDelta>,
}

/// 工具调用增量（流式）
#[derive(Debug, Clone)]
pub struct ToolCallDelta {
    /// 工具调用 ID
    pub id: Option<String>,

    /// 工具名称
    pub name: Option<String>,

    /// 工具输入增量（JSON 片段）
    pub input_delta: Option<String>,
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
                                tool.input_delta.as_ref().map(|s| format!("{}{}", s, input_delta)).unwrap_or_else(|| input_delta.clone()),
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
    pub fn build_tool_calls(&self) -> Result<Vec<crate::models::llm::ToolUse>, LLMError> {
        let mut result = Vec::new();

        for delta in &self.tool_calls {
            let id = delta.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let name = delta.name.clone().ok_or_else(|| {
                LLMError::InvalidResponse("工具调用缺少名称".to_string())
            })?;

            let input = if let Some(input_delta) = &delta.input_delta {
                // 尝试解析 JSON
                serde_json::from_str(input_delta).map_err(|e| {
                    LLMError::InvalidResponse(format!("无效的工具输入 JSON: {}", e))
                })?
            } else {
                serde_json::json!({})
            };

            result.push(crate::models::llm::ToolUse { id, name, input });
        }

        Ok(result)
    }
}

impl Default for StreamHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// 批量请求处理器
///
/// 用于批量处理多个 LLM 请求
pub struct BatchRequestHandler<T>
where
    T: LLMClient + Send + Sync,
{
    client: std::sync::Arc<T>,
    concurrent_limit: usize,
}

impl<T> BatchRequestHandler<T>
where
    T: LLMClient + Send + Sync,
{
    /// 创建新的批处理器
    pub fn new(client: std::sync::Arc<T>, concurrent_limit: usize) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_handler() {
        let mut handler = StreamHandler::new();

        // 处理多个块
        handler.process(LLMStreamChunk {
            delta: "Hello".to_string(),
            done: false,
            tool_call_delta: None,
            usage: None,
        })
        .unwrap();

        handler.process(LLMStreamChunk {
            delta: " World".to_string(),
            done: false,
            tool_call_delta: None,
            usage: None,
        })
        .unwrap();

        handler.process(LLMStreamChunk {
            delta: "".to_string(),
            done: true,
            tool_call_delta: None,
            usage: None,
        })
        .unwrap();

        assert_eq!(handler.content(), "Hello World");
        assert!(handler.is_done());
    }
}
