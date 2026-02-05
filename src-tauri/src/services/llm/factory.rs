//! LLM 客户端工厂
//!
//! 根据配置动态创建 LLM 客户端

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::llm::LLMProviderConfig;
use crate::models::llm::{LLMError, LLMProvider};

use super::client::LLMClient;
use super::providers::{AnthropicClient, OllamaClient, OpenAIClient};

/// LLM 工厂配置
#[derive(Debug, Clone)]
pub struct LLMFactoryConfig {
    /// 默认提供商
    pub default_provider: LLMProvider,

    /// 默认模型
    pub default_model: String,

    /// 默认 API 基础 URL
    pub default_api_base: Option<String>,

    /// 全局 API 密钥（按提供商）
    pub api_keys: HashMap<String, String>,

    /// 超时时间（秒）
    pub timeout_seconds: u64,
}

impl Default for LLMFactoryConfig {
    fn default() -> Self {
        let mut api_keys = HashMap::new();
        // 从环境变量读取默认密钥
        if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
            api_keys.insert("anthropic".to_string(), key);
        }
        if let Ok(key) = std::env::var("OPENAI_API_KEY") {
            api_keys.insert("openai".to_string(), key);
        }

        Self {
            default_provider: LLMProvider::Anthropic,
            default_model: "claude-sonnet-4-20250514".to_string(),
            default_api_base: None,
            api_keys,
            timeout_seconds: 120,
        }
    }
}

/// LLM 工厂
///
/// 负责创建和管理 LLM 客户端实例
pub struct LLMFactory {
    /// 工厂配置
    config: LLMFactoryConfig,

    /// 客户端缓存（按配置哈希）
    clients: Arc<RwLock<HashMap<String, Arc<dyn LLMClient>>>>,
}

impl LLMFactory {
    /// 创建新的工厂
    pub fn new(config: LLMFactoryConfig) -> Self {
        Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 使用默认配置创建工厂
    pub fn with_default_config() -> Self {
        Self::new(LLMFactoryConfig::default())
    }

    /// 创建 LLM 客户端
    pub async fn create_client(
        &self,
        config: &LLMProviderConfig,
    ) -> Result<Arc<dyn LLMClient>, LLMError> {
        // 生成缓存键
        let cache_key = self.cache_key(config);

        // 检查缓存
        {
            let clients = self.clients.read().await;
            if let Some(client) = clients.get(&cache_key) {
                return Ok(client.clone());
            }
        }

        // 创建新客户端
        let client = self.create_client_inner(config)?;

        // 缓存客户端
        let mut clients = self.clients.write().await;
        clients.insert(cache_key.clone(), client.clone());

        Ok(client)
    }

    /// 创建客户端（内部实现）
    fn create_client_inner(
        &self,
        config: &LLMProviderConfig,
    ) -> Result<Arc<dyn LLMClient>, LLMError> {
        // 解析提供商类型
        let provider: LLMProvider = config
            .provider
            .parse()
            .unwrap_or(self.config.default_provider);

        // 补充 API 密钥（如果配置中没有）
        let mut config = config.clone();
        if config.api_key.is_none() {
            if let Some(key) = self.config.api_keys.get(&config.provider) {
                config.api_key = Some(key.clone());
            }
        }

        match provider {
            LLMProvider::Anthropic => Ok(Arc::new(AnthropicClient::new(config)?)),
            LLMProvider::OpenAI => Ok(Arc::new(OpenAIClient::new(config)?)),
            LLMProvider::Ollama => Ok(Arc::new(OllamaClient::new(config)?)),
            LLMProvider::Custom => Err(LLMError::ConfigurationError(
                "Custom provider not supported".to_string(),
            )),
        }
    }

    /// 创建默认客户端
    pub async fn create_default_client(&self) -> Result<Arc<dyn LLMClient>, LLMError> {
        let config = LLMProviderConfig {
            provider: self.config.default_provider.to_string(),
            model: self.config.default_model.clone(),
            api_base: self.config.default_api_base.clone(),
            api_key: self
                .config
                .api_keys
                .get(&self.config.default_provider.to_string())
                .cloned(),
            max_tokens: 4096,
            temperature: 0.7,
            enable_tools: true,
        };

        self.create_client(&config).await
    }

    /// 清空客户端缓存
    pub async fn clear_cache(&self) {
        self.clients.write().await.clear();
    }

    /// 获取缓存大小
    pub async fn cache_size(&self) -> usize {
        self.clients.read().await.len()
    }

    /// 生成缓存键
    fn cache_key(&self, config: &LLMProviderConfig) -> String {
        format!(
            "{}::{}::{}",
            config.provider,
            config.model,
            config.api_base.as_deref().unwrap_or("default")
        )
    }

    /// 设置 API 密钥
    pub fn set_api_key(&mut self, provider: &str, key: String) {
        self.config.api_keys.insert(provider.to_string(), key);
    }

    /// 批量设置 API 密钥
    pub fn set_api_keys(&mut self, keys: HashMap<String, String>) {
        for (provider, key) in keys {
            self.config.api_keys.insert(provider, key);
        }
    }

    /// 获取支持的提供商列表
    pub fn supported_providers(&self) -> Vec<&'static str> {
        vec!["anthropic", "openai", "ollama"]
    }

    /// 测试连接
    pub async fn test_connection(&self, config: &LLMProviderConfig) -> Result<(), LLMError> {
        let client = self.create_client(config).await?;

        // 发送一个简单的测试请求
        use crate::models::llm::LLMMessage;

        let messages = vec![LLMMessage::user("Hello")];

        let _ = tokio::time::timeout(
            tokio::time::Duration::from_secs(30),
            client.generate(messages, 10, 0.7),
        )
        .await
        .map_err(|_| LLMError::Timeout)?
        .map_err(|e| LLMError::Other(format!("Connection test failed: {}", e)))?;

        Ok(())
    }
}

impl Default for LLMFactory {
    fn default() -> Self {
        Self::with_default_config()
    }
}

/// 全局 LLM 工厂单例
pub fn global_factory() -> &'static LLMFactory {
    use std::sync::OnceLock;
    static FACTORY: OnceLock<LLMFactory> = OnceLock::new();
    FACTORY.get_or_init(|| LLMFactory::with_default_config())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_factory_cache_key() {
        let factory = LLMFactory::with_default_config();

        let config1 = LLMProviderConfig {
            provider: "anthropic".to_string(),
            model: "claude-3-5-sonnet-20241022".to_string(),
            api_base: None,
            api_key: Some("key1".to_string()),
            max_tokens: 4096,
            temperature: 0.7,
            enable_tools: true,
        };

        let config2 = LLMProviderConfig {
            provider: "anthropic".to_string(),
            model: "claude-3-5-sonnet-20241022".to_string(),
            api_base: None,
            api_key: Some("key2".to_string()), // 不同的密钥
            max_tokens: 4096,
            temperature: 0.7,
            enable_tools: true,
        };

        // 相同的配置应该有相同的缓存键
        assert_eq!(factory.cache_key(&config1), factory.cache_key(&config1));

        // 不同密钥应该有相同的缓存键（我们只根据提供商和模型缓存）
        assert_eq!(factory.cache_key(&config1), factory.cache_key(&config2));
    }

    #[test]
    fn test_supported_providers() {
        let factory = LLMFactory::with_default_config();
        let providers = factory.supported_providers();

        assert!(providers.contains(&"anthropic"));
        assert!(providers.contains(&"openai"));
        assert!(providers.contains(&"ollama"));
    }
}
