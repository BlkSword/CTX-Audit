// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 流式响应模块
//!
//! 处理 LLM 流式响应，实现打字机效果和实时显示

mod stream;
mod renderer;

pub use stream::*;
pub use renderer::*;

use tokio::sync::mpsc;

/// LLM 流式响应处理器
pub struct LLMStreamHandler {
    /// 响应内容
    content: String,
    /// 是否正在流式传输
    is_streaming: bool,
    /// Token 使用统计
    token_count: usize,
    /// 发送器
    tx: mpsc::UnboundedSender<StreamEvent>,
}

/// 流式事件
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Token 到达
    Token(String),
    /// 流式开始
    Start,
    /// 流式完成
    Complete,
    /// 错误
    Error(String),
}

impl LLMStreamHandler {
    /// 创建新的处理器
    pub fn new() -> (Self, mpsc::UnboundedReceiver<StreamEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();

        let handler = Self {
            content: String::new(),
            is_streaming: false,
            token_count: 0,
            tx,
        };

        (handler, rx)
    }

    /// 添加 Token
    pub fn add_token(&mut self, token: String) {
        self.content.push_str(&token);
        self.token_count += token.len();
        let _ = self.tx.send(StreamEvent::Token(token));
    }

    /// 开始流式传输
    pub fn start(&mut self) {
        self.is_streaming = true;
        self.content.clear();
        self.token_count = 0;
        let _ = self.tx.send(StreamEvent::Start);
    }

    /// 完成流式传输
    pub fn complete(&mut self) {
        self.is_streaming = false;
        let _ = self.tx.send(StreamEvent::Complete);
    }

    /// 发送错误
    pub fn error(&mut self, err: String) {
        self.is_streaming = false;
        let _ = self.tx.send(StreamEvent::Error(err));
    }

    /// 获取内容
    pub fn content(&self) -> &str {
        &self.content
    }

    /// 是否正在流式传输
    pub fn is_streaming(&self) -> bool {
        self.is_streaming
    }

    /// Token 数量
    pub fn token_count(&self) -> usize {
        self.token_count
    }
}

impl Default for LLMStreamHandler {
    fn default() -> Self {
        let (handler, _) = Self::new();
        handler
    }
}
