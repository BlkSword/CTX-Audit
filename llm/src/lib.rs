// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit LLM Client
//!
//! 支持 Anthropic Claude、OpenAI、Ollama 等 LLM 提供商

pub mod client;
pub mod error;
pub mod stream;
pub mod providers;
pub mod factory;

// 重新导出常用类型
pub use client::{LLMClient, StreamHandler, BatchRequestHandler, BatchRequest};
pub use client::{LLMMessage, MessageRole, MessageContent, LLMResponse, ToolUse, ToolDefinition};
pub use error::LLMError;
pub use stream::{LLMStreamChunk, ToolCallDelta, Usage};
pub use providers::{AnthropicClient, OpenAIClient, OllamaClient};
pub use factory::LLMFactory;

/// LLM 客户端版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
