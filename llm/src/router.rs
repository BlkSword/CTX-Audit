// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Multi-LLM Model Router
//!
//! 为不同分析任务选择最优模型，实现成本效益最大化。
//! 推理任务 → 大模型 (Opus)，分类/过滤 → 小模型 (Haiku/Sonnet)

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;

use super::client::{LLMClient, LLMMessage, LLMResponse, ToolDefinition};
use super::error::LLMError;
use super::factory::LLMFactory;
use super::stream::LLMStreamChunk;

/// 分析任务类型 — 决定使用哪个模型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskType {
    /// 深度推理（漏洞验证、业务逻辑分析、sanitizer 绕过判断）
    DeepReasoning,
    /// 分类/过滤（初步筛选、误报判断、严重程度分类）
    Classification,
    /// 摘要生成（代码摘要、文件摘要）
    Summarization,
    /// 代码生成（AutoFix、PoC 生成）
    CodeGeneration,
    /// 工具调用（ReAct 循环中的工具使用）
    ToolUse,
    /// 默认（未指定任务类型时的回退）
    Default,
}

/// 模型路由配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// 每种任务类型对应的 (provider, model) 映射
    /// 未配置的任务类型回退到 default
    pub task_models: HashMap<String, ModelSpec>,

    /// 默认模型规格
    pub default_model: ModelSpec,
}

/// 模型规格
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSpec {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

impl TaskType {
    fn config_key(&self) -> &'static str {
        match self {
            TaskType::DeepReasoning => "deep_reasoning",
            TaskType::Classification => "classification",
            TaskType::Summarization => "summarization",
            TaskType::CodeGeneration => "code_generation",
            TaskType::ToolUse => "tool_use",
            TaskType::Default => "default",
        }
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        let mut task_models = HashMap::new();

        // 深度推理: 使用最强模型
        task_models.insert(
            "deep_reasoning".to_string(),
            ModelSpec {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                api_key: None,
                base_url: None,
            },
        );

        // 分类: 使用快速模型
        task_models.insert(
            "classification".to_string(),
            ModelSpec {
                provider: "anthropic".to_string(),
                model: "claude-haiku-4-5-20251001".to_string(),
                api_key: None,
                base_url: None,
            },
        );

        // 摘要: 使用快速模型
        task_models.insert(
            "summarization".to_string(),
            ModelSpec {
                provider: "anthropic".to_string(),
                model: "claude-haiku-4-5-20251001".to_string(),
                api_key: None,
                base_url: None,
            },
        );

        // 代码生成: 使用强模型
        task_models.insert(
            "code_generation".to_string(),
            ModelSpec {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                api_key: None,
                base_url: None,
            },
        );

        // 工具调用: 使用默认模型
        task_models.insert(
            "tool_use".to_string(),
            ModelSpec {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                api_key: None,
                base_url: None,
            },
        );

        Self {
            task_models,
            default_model: ModelSpec {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
                api_key: None,
                base_url: None,
            },
        }
    }
}

/// Multi-LLM 模型路由器
///
/// 管理多个 LLM 客户端，按任务类型路由到最优模型。
/// 惰性初始化：只在首次使用某模型时创建客户端。
pub struct ModelRouter {
    config: RouterConfig,
    /// 主 API Key（用于未指定 api_key 的模型）
    primary_api_key: String,
    /// 缓存的客户端池
    clients: tokio::sync::Mutex<HashMap<String, Arc<dyn LLMClient>>>,
}

impl ModelRouter {
    /// 创建新的模型路由器
    pub fn new(config: RouterConfig, primary_api_key: String) -> Self {
        Self {
            config,
            primary_api_key,
            clients: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 从 LLMFactory 的配置推断路由器配置
    pub fn from_single_config(
        provider: &str,
        api_key: Option<&str>,
        model: Option<&str>,
        base_url: Option<&str>,
    ) -> Result<Self, LLMError> {
        let key = api_key
            .ok_or_else(|| LLMError::ConfigError("API key required for ModelRouter".into()))?
            .to_string();

        let model_name = model.unwrap_or("claude-sonnet-4-6");

        // 如果用户指定了一个具体模型，所有任务都用它（向后兼容）
        let default_spec = ModelSpec {
            provider: provider.to_string(),
            model: model_name.to_string(),
            api_key: Some(key.clone()),
            base_url: base_url.map(|s| s.to_string()),
        };

        let mut config = RouterConfig::default();

        // 用用户的 provider/api_key/base_url 覆盖所有任务模型
        let user_spec = ModelSpec {
            provider: provider.to_string(),
            model: model_name.to_string(),
            api_key: Some(key.clone()),
            base_url: base_url.map(|s| s.to_string()),
        };

        config.default_model = default_spec;

        // 用用户配置更新所有已有条目的 provider/api_key/base_url
        // 但保留各任务类型的 model 差异（如 classification 用 haiku）
        for spec in config.task_models.values_mut() {
            spec.provider = user_spec.provider.clone();
            spec.api_key = user_spec.api_key.clone();
            spec.base_url = user_spec.base_url.clone();
        }

        Ok(Self::new(config, key))
    }

    /// 获取指定任务类型的客户端
    pub async fn client_for(&self, task: TaskType) -> Result<Arc<dyn LLMClient>, LLMError> {
        let spec = self.spec_for(task);
        let cache_key = format!("{}:{}", spec.provider, spec.model);

        {
            let clients = self.clients.lock().await;
            if let Some(client) = clients.get(&cache_key) {
                return Ok(client.clone());
            }
        }

        let api_key = spec
            .api_key
            .as_deref()
            .unwrap_or(&self.primary_api_key);

        let factory = LLMFactory::new();
        let llm_config = super::factory::LLMConfig {
            provider: spec.provider.clone(),
            api_key: Some(api_key.to_string()),
            model: Some(spec.model.clone()),
            base_url: spec.base_url.clone(),
            timeout_secs: None,
        };
        factory.set_config(llm_config);
        let client = factory.get_client().await?;

        let mut clients = self.clients.lock().await;
        clients.insert(cache_key, client.clone());

        Ok(client)
    }

    /// 获取默认客户端（向后兼容）
    pub async fn default_client(&self) -> Result<Arc<dyn LLMClient>, LLMError> {
        self.client_for(TaskType::Default).await
    }

    fn spec_for(&self, task: TaskType) -> &ModelSpec {
        self.config
            .task_models
            .get(task.config_key())
            .unwrap_or(&self.config.default_model)
    }
}

/// 支持 per-task 模型选择的 LLM 客户端包装
pub struct TaskAwareClient {
    router: Arc<ModelRouter>,
    task: TaskType,
    fallback: Arc<dyn LLMClient>,
}

impl TaskAwareClient {
    pub fn new(router: Arc<ModelRouter>, task: TaskType, fallback: Arc<dyn LLMClient>) -> Self {
        Self {
            router,
            task,
            fallback,
        }
    }

    /// 获取当前任务的最优客户端
    pub async fn optimal_client(&self) -> Arc<dyn LLMClient> {
        self.router
            .client_for(self.task)
            .await
            .unwrap_or_else(|_| self.fallback.clone())
    }
}

#[async_trait]
impl LLMClient for TaskAwareClient {
    async fn generate(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        self.optimal_client()
            .await
            .generate(messages, max_tokens, temperature)
            .await
    }

    async fn generate_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Result<LLMResponse, LLMError> {
        self.optimal_client()
            .await
            .generate_with_tools(messages, tools, max_tokens, temperature)
            .await
    }

    async fn generate_stream(
        &self,
        messages: Vec<LLMMessage>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        self.optimal_client()
            .await
            .generate_stream(messages, max_tokens, temperature)
            .await
    }

    async fn generate_stream_with_tools(
        &self,
        messages: Vec<LLMMessage>,
        tools: Vec<ToolDefinition>,
        max_tokens: u32,
        temperature: f32,
    ) -> Pin<Box<dyn Stream<Item = Result<LLMStreamChunk, LLMError>> + Send>> {
        self.optimal_client()
            .await
            .generate_stream_with_tools(messages, tools, max_tokens, temperature)
            .await
    }

    fn model(&self) -> &str {
        // 返回 fallback 模型名（同步方法无法获取最优客户端）
        self.fallback.model()
    }

    fn provider(&self) -> &str {
        self.fallback.provider()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_config_default() {
        let config = RouterConfig::default();
        assert!(config.task_models.contains_key("deep_reasoning"));
        assert!(config.task_models.contains_key("classification"));
        assert!(config.task_models.contains_key("summarization"));
        assert!(config.task_models.contains_key("code_generation"));
    }

    #[test]
    fn test_task_type_config_key() {
        assert_eq!(TaskType::DeepReasoning.config_key(), "deep_reasoning");
        assert_eq!(TaskType::Classification.config_key(), "classification");
        assert_eq!(TaskType::CodeGeneration.config_key(), "code_generation");
    }

    #[test]
    fn test_from_single_config_backward_compat() {
        let router = ModelRouter::from_single_config(
            "anthropic",
            Some("test-key"),
            Some("claude-sonnet-4-6"),
            None,
        )
        .unwrap();

        let spec = router.spec_for(TaskType::DeepReasoning);
        assert_eq!(spec.provider, "anthropic");
        assert_eq!(spec.api_key.as_deref(), Some("test-key"));
    }
}
