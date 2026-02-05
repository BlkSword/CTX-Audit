//! 流式响应处理

use crate::models::llm::{LLMStreamChunk, Usage};

/// 流式解析器
pub struct StreamParser {
    /// 累积的缓冲区
    buffer: String,

    /// 是否处理 SSE 格式
    sse_mode: bool,
}

impl StreamParser {
    /// 创建新的解析器
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            sse_mode: true,
        }
    }

    /// 创建非 SSE 模式的解析器
    pub fn new_plain() -> Self {
        Self {
            buffer: String::new(),
            sse_mode: false,
        }
    }

    /// 解析 SSE 格式的流式响应
    pub fn parse_sse(&mut self, data: &str) -> Result<Vec<LLMStreamChunk>, StreamParseError> {
        let mut chunks = Vec::new();

        // 添加到缓冲区
        self.buffer.push_str(data);

        // 处理 SSE 格式
        // 格式: "data: <json>\n\n"
        while let Some(pos) = self.buffer.find("\n\n") {
            // Split the buffer and clone the parts to avoid borrow issues
            let line = self.buffer[..pos].to_string();
            let rest = self.buffer[pos + 2..].to_string(); // Skip "\n\n"
            self.buffer = rest;

            // 跳过注释行
            if line.trim().starts_with(':') {
                continue;
            }

            // 解析 "data:" 前缀
            if let Some(data_start) = line.strip_prefix("data: ") {
                let data_str = data_start.trim();

                // 检查结束标记
                if data_str == "[DONE]" {
                    chunks.push(LLMStreamChunk {
                        delta: String::new(),
                        done: true,
                        tool_call_delta: None,
                        usage: None,
                    });
                    continue;
                }

                // 解析 JSON
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data_str) {
                    if let Some(chunk) = self.parse_sse_json(&json) {
                        chunks.push(chunk);
                    }
                }
            }
        }

        Ok(chunks)
    }

    /// 解析 SSE JSON 对象
    fn parse_sse_json(&self, json: &serde_json::Value) -> Option<LLMStreamChunk> {
        // OpenAI 格式
        if let Some(choices) = json.get("choices").and_then(|c| c.as_array()) {
            if let Some(choice) = choices.first() {
                let delta = &choice["delta"];

                // 检查完成
                let finish_reason = choice["finish_reason"].as_str();
                if let Some(reason) = finish_reason {
                    if reason != "null" {
                        return Some(LLMStreamChunk {
                            delta: String::new(),
                            done: true,
                            tool_call_delta: None,
                            usage: self.extract_usage(json),
                        });
                    }
                }

                // 提取文本增量
                let text_delta = delta["content"]
                    .as_str()
                    .or_else(|| delta["text"].as_str())
                    .unwrap_or("")
                    .to_string();

                // 提取工具调用增量
                let tool_call_delta = self.extract_tool_call_delta_openai(delta)
                    .map(|delta| crate::models::llm::ToolCallDelta {
                        id: delta.id,
                        name: delta.name,
                        input_delta: delta.input_delta,
                    });

                if !text_delta.is_empty() || tool_call_delta.is_some() {
                    return Some(LLMStreamChunk {
                        delta: text_delta,
                        done: false,
                        tool_call_delta,
                        usage: None,
                    });
                }
            }
        }

        None
    }

    /// 提取 OpenAI 格式的工具调用增量
    fn extract_tool_call_delta_openai(
        &self,
        delta: &serde_json::Value,
    ) -> Option<crate::services::llm::client::ToolCallDelta> {
        if let Some(tool_calls) = delta.get("tool_calls").and_then(|t| t.as_array()) {
            if let Some(tool_call) = tool_calls.first() {
                let index = tool_call["index"].as_u64().unwrap_or(0);

                let id = tool_call["id"].as_str().map(|s| s.to_string());
                let name = tool_call["function"]["name"].as_str().map(|s| s.to_string());
                let input_delta = tool_call["function"]["arguments"].as_str().map(|s| s.to_string());

                if id.is_some() || name.is_some() || input_delta.is_some() {
                    return Some(crate::services::llm::client::ToolCallDelta {
                        id,
                        name,
                        input_delta,
                    });
                }
            }
        }

        None
    }

    /// 提取使用量信息
    fn extract_usage(&self, json: &serde_json::Value) -> Option<Usage> {
        json.get("usage").and_then(|u| {
            Some(Usage {
                input_tokens: u["prompt_tokens"].as_u64().map(|v| v as u32)
                    .or_else(|| u["input_tokens"].as_u64().map(|v| v as u32))
                    .unwrap_or(0),
                output_tokens: u["completion_tokens"].as_u64().map(|v| v as u32)
                    .or_else(|| u["output_tokens"].as_u64().map(|v| v as u32))
                    .unwrap_or(0),
                cache_creation_tokens: u["cache_creation_tokens"].as_u64().map(|v| v as u32),
                cache_read_tokens: u["cache_read_tokens"].as_u64().map(|v| v as u32),
            })
        })
    }

    /// 解析普通文本流
    pub fn parse_plain(&mut self, data: &str) -> LLMStreamChunk {
        self.buffer.push_str(data);

        let chunk = LLMStreamChunk {
            delta: data.to_string(),
            done: false,
            tool_call_delta: None,
            usage: None,
        };

        chunk
    }

    /// 完成解析（返回最终状态）
    pub fn finish(&mut self) -> LLMStreamChunk {
        LLMStreamChunk {
            delta: String::new(),
            done: true,
            tool_call_delta: None,
            usage: None,
        }
    }

    /// 清空缓冲区
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// 获取缓冲区内容
    pub fn buffer(&self) -> &str {
        &self.buffer
    }
}

impl Default for StreamParser {
    fn default() -> Self {
        Self::new()
    }
}

/// 流式解析错误
#[derive(Debug, Clone, thiserror::Error)]
pub enum StreamParseError {
    #[error("无效的 JSON: {0}")]
    InvalidJson(String),

    #[error("无效的数据格式: {0}")]
    InvalidFormat(String),

    #[error("意外的数据: {0}")]
    UnexpectedData(String),
}

/// 流式聚合器
///
/// 将流式块聚合为完整的响应
pub struct StreamAggregator {
    /// 完整文本
    full_text: String,

    /// 工具调用
    tool_calls: Vec<serde_json::Value>,

    /// 使用量（从最后一个块获取）
    usage: Option<Usage>,

    /// 是否完成
    done: bool,
}

impl StreamAggregator {
    /// 创建新的聚合器
    pub fn new() -> Self {
        Self {
            full_text: String::new(),
            tool_calls: Vec::new(),
            usage: None,
            done: false,
        }
    }

    /// 添加流式块
    pub fn add(&mut self, chunk: LLMStreamChunk) {
        self.full_text.push_str(&chunk.delta);

        if chunk.done {
            self.done = true;
        }

        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
        }

        // 处理工具调用增量
        if let Some(tool_delta) = chunk.tool_call_delta {
            self.merge_tool_call_delta_from_model(tool_delta);
        }
    }

    /// 合并工具调用增量 (from models::llm::ToolCallDelta)
    fn merge_tool_call_delta_from_model(&mut self, delta: crate::models::llm::ToolCallDelta) {
        // 查找或创建工具调用
        if let Some(id) = &delta.id {
            let pos = self
                .tool_calls
                .iter()
                .position(|t| t["id"].as_str() == Some(id));

            if let Some(idx) = pos {
                // 更新现有工具调用
                let tool = &mut self.tool_calls[idx];
                if let Some(name) = &delta.name {
                    tool["name"] = serde_json::json!(name);
                }
                if let Some(input_delta) = &delta.input_delta {
                    let current = tool["input"].as_object().cloned().unwrap_or_default();
                    if let Ok(additional) = serde_json::from_str::<serde_json::Value>(input_delta) {
                        if let Some(additional_obj) = additional.as_object() {
                            let mut merged = current;
                            for (k, v) in additional_obj {
                                merged.insert(k.clone(), v.clone());
                            }
                            tool["input"] = serde_json::json!(merged);
                        }
                    }
                }
            } else {
                // 创建新的工具调用
                let mut new_tool = serde_json::json!({
                    "id": id,
                    "name": delta.name.unwrap_or_else(|| "unknown".to_string()),
                    "input": {}
                });
                if let Some(input_delta) = &delta.input_delta {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(input_delta) {
                        new_tool["input"] = parsed;
                    }
                }
                self.tool_calls.push(new_tool);
            }
        }
    }

    /// 合并工具调用增量 (from client::ToolCallDelta)
    fn merge_tool_call_delta(&mut self, delta: super::client::ToolCallDelta) {
        // 查找或创建工具调用
        if let Some(id) = &delta.id {
            let pos = self
                .tool_calls
                .iter()
                .position(|t| t["id"].as_str() == Some(id));

            if let Some(idx) = pos {
                // 更新现有工具调用
                let tool = &mut self.tool_calls[idx];
                if let Some(name) = &delta.name {
                    tool["name"] = serde_json::json!(name);
                }
                if let Some(input_delta) = &delta.input_delta {
                    let current = tool["input"].as_object().cloned().unwrap_or_default();
                    if let Ok(additional) = serde_json::from_str::<serde_json::Value>(input_delta) {
                        if let Some(additional_obj) = additional.as_object() {
                            let mut merged = current;
                            for (k, v) in additional_obj {
                                merged.insert(k.clone(), v.clone());
                            }
                            tool["input"] = serde_json::json!(merged);
                        }
                    }
                }
            } else {
                // 创建新的工具调用
                let mut new_tool = serde_json::json!({
                    "id": id,
                    "name": delta.name.unwrap_or_else(|| "unknown".to_string()),
                    "input": {}
                });
                if let Some(input_delta) = &delta.input_delta {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(input_delta) {
                        new_tool["input"] = parsed;
                    }
                }
                self.tool_calls.push(new_tool);
            }
        }
    }

    /// 获取完整文本
    pub fn text(&self) -> &str {
        &self.full_text
    }

    /// 获取工具调用
    pub fn tool_calls(&self) -> &[serde_json::Value] {
        &self.tool_calls
    }

    /// 获取使用量
    pub fn usage(&self) -> Option<&Usage> {
        self.usage.as_ref()
    }

    /// 是否完成
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// 重置聚合器
    pub fn reset(&mut self) {
        self.full_text.clear();
        self.tool_calls.clear();
        self.usage = None;
        self.done = false;
    }
}

impl Default for StreamAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_parser_sse() {
        let mut parser = StreamParser::new();

        let sse_data = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n";
        let chunks = parser.parse_sse(sse_data).unwrap();

        assert!(!chunks.is_empty());
        assert_eq!(chunks[0].delta, "Hello");
    }

    #[test]
    fn test_stream_aggregator() {
        let mut aggregator = StreamAggregator::new();

        aggregator.add(LLMStreamChunk {
            delta: "Hello".to_string(),
            done: false,
            tool_call_delta: None,
            usage: None,
        });

        aggregator.add(LLMStreamChunk {
            delta: " World".to_string(),
            done: true,
            tool_call_delta: None,
            usage: Some(Usage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_tokens: None,
                cache_read_tokens: None,
            }),
        });

        assert_eq!(aggregator.text(), "Hello World");
        assert!(aggregator.is_done());
        assert_eq!(aggregator.usage().unwrap().output_tokens, 5);
    }
}
