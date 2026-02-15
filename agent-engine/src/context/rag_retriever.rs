// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! RAG 检索器
//!
//! 整合向量存储和嵌入生成，实现项目索引和语义搜索

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

use ctx_audit_llm::{EmbeddingGenerator, EmbeddingError};
use deepaudit_core::{
    CodeChunk, CodeChunker, ChunkConfig, ChunkType,
    VectorStore, SearchResult as VectorSearchResult, VectorStoreError,
};

/// RAG 上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RAGContext {
    /// 查询文本
    pub query: String,

    /// 检索到的代码块
    pub chunks: Vec<RetrievedChunk>,

    /// 总检索时间（毫秒）
    pub retrieval_time_ms: u64,

    /// 搜索参数
    pub search_params: SearchParams,
}

/// 检索到的代码块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievedChunk {
    /// 代码块 ID
    pub id: String,

    /// 文件路径
    pub file_path: String,

    /// 符号名称
    pub name: String,

    /// 代码块类型
    pub chunk_type: ChunkType,

    /// 代码内容
    pub content: String,

    /// 起始行号
    pub start_line: usize,

    /// 结束行号
    pub end_line: usize,

    /// 相似度分数
    pub score: f32,

    /// 语言
    pub language: String,
}

impl RetrievedChunk {
    /// 从搜索结果和代码块创建
    fn from_search_result(result: &VectorSearchResult, chunk: &CodeChunk) -> Self {
        Self {
            id: chunk.id.clone(),
            file_path: chunk.relative_path.clone(),
            name: chunk.name.clone(),
            chunk_type: chunk.chunk_type,
            content: chunk.content.clone(),
            start_line: chunk.start_line,
            end_line: chunk.end_line,
            score: result.score,
            language: chunk.language.clone(),
        }
    }

    /// 格式化为上下文字符串
    pub fn to_context_string(&self) -> String {
        format!(
            "=== {} {} ({}) ===\nFile: {}:{}-{}\nScore: {:.3}\n\n{}\n",
            self.chunk_type,
            self.name,
            self.language,
            self.file_path,
            self.start_line,
            self.end_line,
            self.score,
            self.content
        )
    }
}

/// 搜索参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchParams {
    /// 返回结果数量
    pub top_k: usize,

    /// 最小相似度阈值
    pub min_score: f32,

    /// 是否按文件分组
    pub group_by_file: bool,

    /// 文件过滤（可选）
    pub file_filter: Option<String>,

    /// 语言过滤（可选）
    pub language_filter: Option<String>,
}

impl Default for SearchParams {
    fn default() -> Self {
        Self {
            top_k: 10,
            min_score: 0.5,
            group_by_file: false,
            file_filter: None,
            language_filter: None,
        }
    }
}

/// 索引统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    /// 总代码块数
    pub total_chunks: usize,

    /// 文件数
    pub file_count: usize,

    /// 按语言统计
    pub by_language: HashMap<String, usize>,

    /// 按类型统计
    pub by_type: HashMap<String, usize>,

    /// 索引大小（字节，估算）
    pub estimated_size_bytes: usize,

    /// 嵌入维度
    pub embedding_dimension: Option<usize>,
}

impl Default for IndexStats {
    fn default() -> Self {
        Self {
            total_chunks: 0,
            file_count: 0,
            by_language: HashMap::new(),
            by_type: HashMap::new(),
            estimated_size_bytes: 0,
            embedding_dimension: None,
        }
    }
}

/// RAG 检索器错误
#[derive(Debug, thiserror::Error)]
pub enum RAGError {
    #[error("嵌入生成错误: {0}")]
    Embedding(#[from] EmbeddingError),

    #[error("向量存储错误: {0}")]
    VectorStore(#[from] VectorStoreError),

    #[error("代码块提取错误: {0}")]
    Chunking(String),

    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("索引未初始化")]
    NotIndexed,

    #[error("无效的查询: {0}")]
    InvalidQuery(String),
}

/// RAG 检索器配置
#[derive(Debug, Clone)]
pub struct RAGConfig {
    /// 代码块配置
    pub chunk_config: ChunkConfig,

    /// 搜索参数
    pub search_params: SearchParams,

    /// 是否在索引时并行处理
    pub parallel_indexing: bool,

    /// 批量嵌入大小
    pub embedding_batch_size: usize,
}

impl Default for RAGConfig {
    fn default() -> Self {
        Self {
            chunk_config: ChunkConfig::default(),
            search_params: SearchParams::default(),
            parallel_indexing: true,
            embedding_batch_size: 50,
        }
    }
}

/// RAG 检索器
pub struct RAGRetriever {
    /// 嵌入生成器
    embedding: Arc<dyn EmbeddingGenerator>,

    /// 向量存储
    vector_store: Arc<RwLock<VectorStore>>,

    /// 代码块存储（ID -> CodeChunk）
    chunks: Arc<RwLock<HashMap<String, CodeChunk>>>,

    /// 代码块提取器
    chunker: CodeChunker,

    /// 配置
    config: RAGConfig,

    /// 索引统计
    stats: Arc<RwLock<IndexStats>>,
}

impl RAGRetriever {
    /// 创建新的 RAG 检索器
    pub fn new(embedding: Arc<dyn EmbeddingGenerator>, config: Option<RAGConfig>) -> Self {
        let config = config.unwrap_or_default();
        let chunker = CodeChunker::new(config.chunk_config.clone());

        Self {
            embedding,
            vector_store: Arc::new(RwLock::new(VectorStore::new())),
            chunks: Arc::new(RwLock::new(HashMap::new())),
            chunker,
            config,
            stats: Arc::new(RwLock::new(IndexStats::default())),
        }
    }

    /// 索引项目
    pub async fn index_project(&self, project_path: &Path) -> Result<IndexStats, RAGError> {
        let start = std::time::Instant::now();
        tracing::info!("开始索引项目: {:?}", project_path);

        // 清除现有索引
        {
            let mut store = self.vector_store.write().await;
            store.clear();
        }
        {
            let mut chunks = self.chunks.write().await;
            chunks.clear();
        }

        // 提取代码块
        let code_chunks = self
            .chunker
            .index_project(project_path)
            .await
            .map_err(|e| RAGError::Chunking(e.to_string()))?;

        tracing::info!("提取到 {} 个代码块", code_chunks.len());

        // 批量生成嵌入
        let mut indexed_count = 0;
        for batch in code_chunks.chunks(self.config.embedding_batch_size) {
            // 准备文本
            let texts: Vec<&str> = batch
                .iter()
                .map(|c| c.search_text.as_deref().unwrap_or(&c.content))
                .collect();

            // 生成嵌入
            let embeddings = self.embedding.embed_batch(&texts).await?;

            // 添加到向量存储
            let mut store = self.vector_store.write().await;
            let mut chunks = self.chunks.write().await;

            for (chunk, embedding) in batch.iter().zip(embeddings.iter()) {
                let mut metadata = HashMap::new();
                metadata.insert(
                    "file_path".to_string(),
                    serde_json::json!(chunk.relative_path),
                );
                metadata.insert("name".to_string(), serde_json::json!(chunk.name));
                metadata.insert(
                    "chunk_type".to_string(),
                    serde_json::json!(chunk.chunk_type.to_string()),
                );
                metadata.insert("language".to_string(), serde_json::json!(chunk.language));

                store.add_vector(
                    chunk.id.clone(),
                    embedding.clone(),
                    Some(metadata),
                )?;

                chunks.insert(chunk.id.clone(), chunk.clone());
                indexed_count += 1;
            }
        }

        // 更新统计
        let mut stats = self.stats.write().await;
        stats.total_chunks = indexed_count;
        stats.embedding_dimension = Some(self.embedding.dimension());

        // 计算文件数和按语言/类型统计
        let mut files = std::collections::HashSet::new();
        let chunks = self.chunks.read().await;
        for chunk in chunks.values() {
            files.insert(chunk.relative_path.clone());
            *stats.by_language.entry(chunk.language.clone()).or_insert(0) += 1;
            *stats.by_type.entry(chunk.chunk_type.to_string()).or_insert(0) += 1;
        }
        stats.file_count = files.len();

        // 估算大小
        stats.estimated_size_bytes = stats.total_chunks * self.embedding.dimension() * 4;

        let elapsed = start.elapsed();
        tracing::info!(
            "索引完成: {} 个代码块, {} 个文件, 耗时 {:?}",
            stats.total_chunks,
            stats.file_count,
            elapsed
        );

        Ok(stats.clone())
    }

    /// 语义搜索
    pub async fn retrieve(&self, query: &str) -> Result<RAGContext, RAGError> {
        self.retrieve_with_params(query, self.config.search_params.clone())
            .await
    }

    /// 使用自定义参数搜索
    pub async fn retrieve_with_params(
        &self,
        query: &str,
        params: SearchParams,
    ) -> Result<RAGContext, RAGError> {
        if query.trim().is_empty() {
            return Err(RAGError::InvalidQuery("查询不能为空".to_string()));
        }

        let start = std::time::Instant::now();

        // 生成查询嵌入
        let query_embedding = self.embedding.embed(query).await?;

        // 搜索向量存储
        let store = self.vector_store.read().await;
        let results = if let Some(ref file_filter) = params.file_filter {
            store.search_by_file(&query_embedding, params.top_k * 2, file_filter)?
        } else {
            store.search(&query_embedding, params.top_k * 2)?
        };
        drop(store);

        // 转换结果并过滤
        let chunks = self.chunks.read().await;
        let mut retrieved: Vec<RetrievedChunk> = results
            .iter()
            .filter_map(|r| {
                if r.score < params.min_score {
                    return None;
                }

                chunks.get(&r.id).map(|chunk| {
                    // 语言过滤
                    if let Some(ref lang) = params.language_filter {
                        if &chunk.language != lang {
                            return None;
                        }
                    }
                    Some(RetrievedChunk::from_search_result(r, chunk))
                })
            })
            .flatten()
            .take(params.top_k)
            .collect();

        // 按文件分组（如果需要）
        if params.group_by_file {
            retrieved.sort_by(|a, b| {
                a.file_path
                    .cmp(&b.file_path)
                    .then_with(|| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
            });
        } else {
            retrieved.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        let retrieval_time_ms = start.elapsed().as_millis() as u64;

        Ok(RAGContext {
            query: query.to_string(),
            chunks: retrieved,
            retrieval_time_ms,
            search_params: params,
        })
    }

    /// 获取相关代码上下文（用于 LLM 提示）
    pub async fn get_relevant_context(
        &self,
        query: &str,
        max_tokens: usize,
    ) -> Result<String, RAGError> {
        let params = SearchParams {
            top_k: 20,
            min_score: 0.3,
            ..Default::default()
        };

        let context = self.retrieve_with_params(query, params).await?;

        // 构建上下文字符串，控制在 token 限制内
        let mut result = String::new();
        result.push_str("# 相关代码上下文\n\n");

        let mut current_tokens = 0;
        let approx_chars_per_token = 4; // 粗略估计

        for chunk in &context.chunks {
            let chunk_str = chunk.to_context_string();
            let chunk_tokens = chunk_str.len() / approx_chars_per_token;

            if current_tokens + chunk_tokens > max_tokens {
                break;
            }

            result.push_str(&chunk_str);
            result.push_str("\n---\n\n");
            current_tokens += chunk_tokens;
        }

        Ok(result)
    }

    /// 获取索引统计
    pub async fn get_stats(&self) -> IndexStats {
        self.stats.read().await.clone()
    }

    /// 检查是否已索引
    pub async fn is_indexed(&self) -> bool {
        let chunks = self.chunks.read().await;
        !chunks.is_empty()
    }

    /// 清除索引
    pub async fn clear_index(&self) {
        let mut store = self.vector_store.write().await;
        store.clear();
        drop(store);

        let mut chunks = self.chunks.write().await;
        chunks.clear();
        drop(chunks);

        let mut stats = self.stats.write().await;
        *stats = IndexStats::default();
    }

    /// 按文件路径获取代码块
    pub async fn get_chunks_by_file(&self, file_path: &str) -> Vec<CodeChunk> {
        let chunks = self.chunks.read().await;
        chunks
            .values()
            .filter(|c| c.relative_path == file_path)
            .cloned()
            .collect()
    }

    /// 按 ID 获取代码块
    pub async fn get_chunk_by_id(&self, id: &str) -> Option<CodeChunk> {
        let chunks = self.chunks.read().await;
        chunks.get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_params_default() {
        let params = SearchParams::default();
        assert_eq!(params.top_k, 10);
        assert!((params.min_score - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_index_stats_default() {
        let stats = IndexStats::default();
        assert_eq!(stats.total_chunks, 0);
        assert_eq!(stats.file_count, 0);
    }

    #[test]
    fn test_retrieved_chunk_to_context_string() {
        let chunk = RetrievedChunk {
            id: "test".to_string(),
            file_path: "main.rs".to_string(),
            name: "main".to_string(),
            chunk_type: ChunkType::Function,
            content: "fn main() {}".to_string(),
            start_line: 1,
            end_line: 1,
            score: 0.95,
            language: "rust".to_string(),
        };

        let ctx = chunk.to_context_string();
        assert!(ctx.contains("main.rs"));
        assert!(ctx.contains("fn main()"));
        assert!(ctx.contains("0.95"));
    }
}
