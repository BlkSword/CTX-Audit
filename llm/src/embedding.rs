// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 嵌入生成模块
//!
//! 支持 OpenAI 和本地模型的文本嵌入生成

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 嵌入生成器 Trait
#[async_trait]
pub trait EmbeddingGenerator: Send + Sync {
    /// 生成单个文本的嵌入
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError>;

    /// 批量生成嵌入
    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError>;

    /// 获取嵌入维度
    fn dimension(&self) -> usize;

    /// 获取模型名称
    fn model_name(&self) -> &str;
}

/// 嵌入错误
#[derive(Debug, Clone, thiserror::Error)]
pub enum EmbeddingError {
    #[error("API 错误: {0}")]
    ApiError(String),

    #[error("网络错误: {0}")]
    NetworkError(String),

    #[error("无效的输入: {0}")]
    InvalidInput(String),

    #[error("模型错误: {0}")]
    ModelError(String),

    #[error("配置错误: {0}")]
    ConfigError(String),

    #[error("超过速率限制")]
    RateLimitExceeded,

    #[error("本地模型未初始化")]
    LocalModelNotInitialized,
}

/// 嵌入配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig {
    /// 提供商类型
    pub provider: EmbeddingProvider,

    /// OpenAI API 密钥
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// OpenAI API 基础 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,

    /// 模型名称
    pub model: String,

    /// 批量大小
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// 最大重试次数
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,

    /// 是否启用自动降级到本地模型
    #[serde(default)]
    pub fallback_to_local: bool,
}

fn default_batch_size() -> usize {
    100
}

fn default_max_retries() -> usize {
    3
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            provider: EmbeddingProvider::OpenAI,
            api_key: None,
            api_base: None,
            model: "text-embedding-3-small".to_string(),
            batch_size: 100,
            max_retries: 3,
            fallback_to_local: false,
        }
    }
}

/// 嵌入提供商
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EmbeddingProvider {
    /// OpenAI
    OpenAI,
    /// OpenAI 兼容 API
    OpenAICompatible,
    /// 本地模型
    Local,
}

// ============================================================================
// OpenAI 嵌入生成器
// ============================================================================

/// OpenAI 嵌入生成器
pub struct OpenAIEmbedding {
    client: reqwest::Client,
    config: EmbeddingConfig,
    dimension: usize,
}

impl OpenAIEmbedding {
    /// 创建新的 OpenAI 嵌入生成器
    pub fn new(config: EmbeddingConfig) -> Result<Self, EmbeddingError> {
        let api_key = config.api_key.clone().ok_or_else(|| {
            EmbeddingError::ConfigError("未设置 OpenAI API 密钥".to_string())
        })?;

        if api_key.is_empty() {
            return Err(EmbeddingError::ConfigError(
                "OpenAI API 密钥不能为空".to_string(),
            ));
        }

        let dimension = Self::get_dimension_for_model(&config.model);

        Ok(Self {
            client: reqwest::Client::new(),
            config,
            dimension,
        })
    }

    /// 获取模型的嵌入维度
    fn get_dimension_for_model(model: &str) -> usize {
        match model {
            "text-embedding-3-small" => 1536,
            "text-embedding-3-large" => 3072,
            "text-embedding-ada-002" => 1536,
            _ => 1536, // 默认维度
        }
    }

    /// 获取 API 基础 URL
    fn api_base(&self) -> &str {
        self.config
            .api_base
            .as_deref()
            .unwrap_or("https://api.openai.com/v1")
    }

    /// 发送嵌入请求
    async fn send_request(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        let api_key = self.config.api_key.as_ref().unwrap();

        let request_body = serde_json::json!({
            "model": self.config.model,
            "input": texts,
            "encoding_format": "float"
        });

        let url = format!("{}/embeddings", self.api_base());

        let mut retries = 0;
        loop {
            let response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&request_body)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let body: OpenAIEmbeddingResponse = resp
                            .json()
                            .await
                            .map_err(|e| EmbeddingError::ApiError(format!("解析响应失败: {}", e)))?;

                        // 按 index 排序
                        let mut data = body.data;
                        data.sort_by_key(|d| d.index);

                        return Ok(data.into_iter().map(|d| d.embedding).collect());
                    } else if resp.status().as_u16() == 429 {
                        if retries >= self.config.max_retries {
                            return Err(EmbeddingError::RateLimitExceeded);
                        }
                        retries += 1;
                        tokio::time::sleep(tokio::time::Duration::from_millis(500 * retries as u64))
                            .await;
                    } else {
                        let status = resp.status();
                        let error_text = resp.text().await.unwrap_or_default();
                        return Err(EmbeddingError::ApiError(format!(
                            "API 请求失败 ({}): {}",
                            status, error_text
                        )));
                    }
                }
                Err(e) => {
                    if retries >= self.config.max_retries {
                        return Err(EmbeddingError::NetworkError(format!(
                            "网络请求失败: {}",
                            e
                        )));
                    }
                    retries += 1;
                    tokio::time::sleep(tokio::time::Duration::from_millis(500 * retries as u64))
                        .await;
                }
            }
        }
    }
}

#[async_trait]
impl EmbeddingGenerator for OpenAIEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let embeddings = self.embed_batch(&[text]).await?;
        embeddings
            .into_iter()
            .next()
            .ok_or_else(|| EmbeddingError::ApiError("未返回嵌入结果".to_string()))
    }

    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        // 分批处理
        let mut all_embeddings = Vec::new();
        for chunk in texts.chunks(self.config.batch_size) {
            let embeddings = self.send_request(chunk).await?;
            all_embeddings.extend(embeddings);
        }

        Ok(all_embeddings)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    fn model_name(&self) -> &str {
        &self.config.model
    }
}

/// OpenAI 嵌入响应
#[derive(Debug, Deserialize)]
struct OpenAIEmbeddingResponse {
    data: Vec<OpenAIEmbeddingData>,
}

#[derive(Debug, Deserialize)]
struct OpenAIEmbeddingData {
    embedding: Vec<f32>,
    index: usize,
}

// ============================================================================
// 本地嵌入生成器（简化版）
// ============================================================================

/// 本地嵌入生成器（占位实现）
///
/// 注意：完整的本地嵌入支持需要 ONNX Runtime 或 candle
/// 这里提供一个接口，用户可以后续启用
pub struct LocalEmbedding {
    model_path: Option<String>,
    dimension: usize,
    initialized: bool,
}

impl LocalEmbedding {
    /// 创建新的本地嵌入生成器
    pub fn new(model_path: Option<String>) -> Self {
        Self {
            model_path,
            dimension: 384, // MiniLM-L6-v2 默认维度
            initialized: false,
        }
    }

    /// 尝试初始化模型
    pub async fn initialize(&mut self) -> Result<(), EmbeddingError> {
        // 这里应该加载 ONNX 模型
        // 目前返回未初始化错误
        Err(EmbeddingError::LocalModelNotInitialized)
    }
}

#[async_trait]
impl EmbeddingGenerator for LocalEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if !self.initialized {
            return Err(EmbeddingError::LocalModelNotInitialized);
        }
        // 占位实现
        Err(EmbeddingError::LocalModelNotInitialized)
    }

    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if !self.initialized {
            return Err(EmbeddingError::LocalModelNotInitialized);
        }
        // 占位实现
        Err(EmbeddingError::LocalModelNotInitialized)
    }

    fn dimension(&self) -> usize {
        self.dimension
    }

    fn model_name(&self) -> &str {
        "local-minilm"
    }
}

// ============================================================================
// 组合嵌入生成器（支持自动降级）
// ============================================================================

/// 组合嵌入生成器
///
/// 支持主生成器失败时自动降级到备用生成器
pub struct FallbackEmbedding {
    primary: Arc<dyn EmbeddingGenerator>,
    fallback: Option<Arc<dyn EmbeddingGenerator>>,
}

impl FallbackEmbedding {
    /// 创建新的组合嵌入生成器
    pub fn new(
        primary: Arc<dyn EmbeddingGenerator>,
        fallback: Option<Arc<dyn EmbeddingGenerator>>,
    ) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl EmbeddingGenerator for FallbackEmbedding {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        match self.primary.embed(text).await {
            Ok(embedding) => Ok(embedding),
            Err(e) => {
                if let Some(ref fallback) = self.fallback {
                    tracing::warn!("主嵌入生成器失败，使用备用: {}", e);
                    fallback.embed(text).await
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        match self.primary.embed_batch(texts).await {
            Ok(embeddings) => Ok(embeddings),
            Err(e) => {
                if let Some(ref fallback) = self.fallback {
                    tracing::warn!("主嵌入生成器失败，使用备用: {}", e);
                    fallback.embed_batch(texts).await
                } else {
                    Err(e)
                }
            }
        }
    }

    fn dimension(&self) -> usize {
        self.primary.dimension()
    }

    fn model_name(&self) -> &str {
        self.primary.model_name()
    }
}

// ============================================================================
// 工厂函数
// ============================================================================

/// 创建嵌入生成器
pub fn create_embedding_generator(
    config: EmbeddingConfig,
) -> Result<Arc<dyn EmbeddingGenerator>, EmbeddingError> {
    match config.provider {
        EmbeddingProvider::OpenAI | EmbeddingProvider::OpenAICompatible => {
            let generator = OpenAIEmbedding::new(config)?;
            Ok(Arc::new(generator))
        }
        EmbeddingProvider::Local => {
            let generator = LocalEmbedding::new(None);
            Ok(Arc::new(generator))
        }
    }
}

/// 创建带自动降级的嵌入生成器
pub fn create_embedding_with_fallback(
    primary_config: EmbeddingConfig,
    fallback_config: Option<EmbeddingConfig>,
) -> Result<Arc<dyn EmbeddingGenerator>, EmbeddingError> {
    let primary = create_embedding_generator(primary_config)?;

    let fallback = if let Some(config) = fallback_config {
        Some(create_embedding_generator(config)?)
    } else {
        None
    };

    Ok(Arc::new(FallbackEmbedding::new(primary, fallback)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedding_config_default() {
        let config = EmbeddingConfig::default();
        assert_eq!(config.provider, EmbeddingProvider::OpenAI);
        assert_eq!(config.model, "text-embedding-3-small");
        assert_eq!(config.batch_size, 100);
    }

    #[test]
    fn test_dimension_for_model() {
        assert_eq!(
            OpenAIEmbedding::get_dimension_for_model("text-embedding-3-small"),
            1536
        );
        assert_eq!(
            OpenAIEmbedding::get_dimension_for_model("text-embedding-3-large"),
            3072
        );
        assert_eq!(
            OpenAIEmbedding::get_dimension_for_model("text-embedding-ada-002"),
            1536
        );
    }

    #[test]
    fn test_local_embedding_creation() {
        let embedding = LocalEmbedding::new(None);
        assert_eq!(embedding.dimension(), 384);
        assert_eq!(embedding.model_name(), "local-minilm");
    }
}
