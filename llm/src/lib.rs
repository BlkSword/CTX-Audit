// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit LLM Client
//!
//! 支持 Anthropic Claude、OpenAI、Ollama 等 LLM 提供商，以及文本嵌入生成

pub mod client;
pub mod error;
pub mod stream;
pub mod providers;
pub mod factory;
pub mod embedding;

// 重新导出常用类型
pub use client::{LLMClient, StreamHandler, BatchRequestHandler, BatchRequest};
pub use client::{LLMMessage, MessageRole, MessageContent, LLMResponse, ToolUse, ToolDefinition};
pub use error::LLMError;
pub use stream::{LLMStreamChunk, ToolCallDelta, Usage};
pub use providers::{AnthropicClient, OpenAIClient, OllamaClient};
pub use factory::{LLMFactory, LLMConfig};

// 嵌入生成
pub use embedding::{
    EmbeddingGenerator, EmbeddingError, EmbeddingConfig, EmbeddingProvider,
    OpenAIEmbedding, LocalEmbedding, FallbackEmbedding,
    create_embedding_generator, create_embedding_with_fallback,
};

/// LLM 客户端版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
