// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 流式响应处理

use anyhow::Result;
use ctx_audit_llm::{LLMClient, LLMMessage, MessageRole, LLMStreamChunk};
use futures::StreamExt;
use tokio::sync::mpsc;

use super::StreamEvent;

/// 流式响应配置
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// 是否启用打字机效果
    pub typewriter: bool,
    /// 打字机速度（每秒字符数）
    pub typewriter_speed: usize,
    /// 最大 Token 数
    pub max_tokens: Option<usize>,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            typewriter: true,
            typewriter_speed: 50,
            max_tokens: None,
        }
    }
}

/// 流式聊天处理器
pub struct StreamChatProcessor {
    /// LLM 客户端
    llm: Box<dyn LLMClient>,
    /// 配置
    config: StreamConfig,
    /// 是否运行中
    running: bool,
}

impl StreamChatProcessor {
    /// 创建新的处理器
    pub fn new(llm: Box<dyn LLMClient>) -> Self {
        Self {
            llm,
            config: StreamConfig::default(),
            running: false,
        }
    }

    /// 设置配置
    pub fn with_config(mut self, config: StreamConfig) -> Self {
        self.config = config;
        self
    }

    /// 发送聊天请求并流式处理响应
    pub async fn chat_stream(
        &mut self,
        messages: Vec<LLMMessage>,
        tx: mpsc::UnboundedSender<StreamEvent>,
    ) -> Result<String> {
        self.running = true;

        // 发送开始事件
        let _ = tx.send(StreamEvent::Start);

        // 调用 LLM 流式响应
        let max_tokens = self.config.max_tokens.unwrap_or(4096) as u32;
        let mut stream = self.llm.generate_stream(messages, max_tokens, 0.7).await;

        let mut full_content = String::new();

        // 处理流式响应
        while let Some(chunk_result) = stream.next().await {
            // 检查是否被中断
            if !self.running {
                break;
            }

            match chunk_result {
                Ok(chunk) => {
                    if chunk.done {
                        break;
                    }
                    full_content.push_str(&chunk.delta);

                    // 发送 Token 事件
                    let _ = tx.send(StreamEvent::Token(chunk.delta));

                    // 打字机效果延迟
                    if self.config.typewriter && self.config.typewriter_speed > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            (1000 / self.config.typewriter_speed as u64).max(10)
                        )).await;
                    }
                }
                Err(e) => {
                    let _ = tx.send(StreamEvent::Error(e.to_string()));
                    return Err(e.into());
                }
            }
        }

        // 发送完成事件
        let _ = tx.send(StreamEvent::Complete);

        Ok(full_content)
    }

    /// 中断流式传输
    pub fn interrupt(&mut self) {
        self.running = false;
    }

    /// 是否正在运行
    pub fn is_running(&self) -> bool {
        self.running
    }
}
