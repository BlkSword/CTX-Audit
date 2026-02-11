// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 工厂
//!
//! 根据配置创建对应的 LLM 客户端实例

use std::sync::Arc;
use std::sync::Mutex;

use super::client::LLMClient;
use super::error::LLMError;
use super::providers::{AnthropicClient, OpenAIClient, OllamaClient};

/// LLM 配置
#[derive(Debug, Clone)]
pub struct LLMConfig {
    /// 提供商 (anthropic, openai, openai-compatible, ollama)
    pub provider: String,

    /// API 密钥
    pub api_key: Option<String>,

    /// 模型名称
    pub model: Option<String>,

    /// API 基础 URL
    pub base_url: Option<String>,

    /// 超时时间（秒）
    pub timeout_secs: Option<u64>,
}

/// LLM 工厂
pub struct LLMFactory {
    config: Mutex<LLMConfig>,
    client: Mutex<Option<Arc<dyn LLMClient>>>,
}

impl LLMFactory {
    /// 创建新的工厂
    pub fn new() -> Self {
        Self {
            config: Mutex::new(LLMConfig {
                provider: "anthropic".to_string(),
                api_key: None,
                model: None,
                base_url: None,
                timeout_secs: None,
            }),
            client: Mutex::new(None),
        }
    }

    /// 使用默认配置创建工厂
    pub fn with_default_config() -> Self {
        Self::new()
    }

    /// 设置配置
    pub fn set_config(&self, config: LLMConfig) {
        *self.config.lock().unwrap() = config;
        // 清除缓存的客户端
        *self.client.lock().unwrap() = None;
    }

    /// 获取客户端
    pub async fn get_client(&self) -> Result<Arc<dyn LLMClient>, LLMError> {
        // 检查是否有缓存的客户端
        {
            let client = self.client.lock().unwrap();
            if let Some(ref client) = *client {
                return Ok(client.clone());
            }
        }

        // 创建新客户端
        let config = self.config.lock().unwrap().clone();
        let client: Arc<dyn LLMClient> = match config.provider.as_str() {
            "anthropic" => Arc::new(AnthropicClient::new(
                config.api_key.ok_or_else(|| {
                    LLMError::ConfigError("Anthropic API key is required".to_string())
                })?,
                config.model,
            )?),
            "openai" | "openai-compatible" => {
                // 对于 openai-compatible，base_url 是必需的
                let base_url = if config.provider == "openai-compatible" {
                    Some(config.base_url.ok_or_else(|| {
                        LLMError::ConfigError(
                            "base_url is required for openai-compatible provider".to_string()
                        )
                    })?)
                } else {
                    config.base_url
                };
                Arc::new(OpenAIClient::new(
                    config.api_key.ok_or_else(|| {
                        LLMError::ConfigError("API key is required".to_string())
                    })?,
                    config.model,
                    base_url,
                )?)
            }
            "ollama" => Arc::new(OllamaClient::new(
                config.model,
                config.base_url.unwrap_or_else(|| "http://localhost:11434".to_string()),
            )?),
            _ => {
                return Err(LLMError::ConfigError(format!(
                    "Unknown provider: {}. Supported providers: anthropic, openai, openai-compatible, ollama",
                    config.provider
                )))
            }
        };

        // 缓存客户端
        *self.client.lock().unwrap() = Some(client.clone());

        Ok(client)
    }
}

impl Default for LLMFactory {
    fn default() -> Self {
        Self::new()
    }
}
