//! LLM 客户端模块
//!
//! 支持多个 LLM 提供商（Anthropic, OpenAI, Ollama）

pub mod client;
pub mod factory;
pub mod providers;
pub mod stream;

// 重新导出常用类型
pub use client::LLMClient;
pub use factory::{LLMFactory, LLMFactoryConfig};
pub use providers::{AnthropicClient, OllamaClient, OpenAIClient};
pub use stream::StreamParser;

// LLMStreamChunk 定义在 models::llm 中，不是在 stream.rs 中定义的
pub use crate::models::llm::LLMStreamChunk;
