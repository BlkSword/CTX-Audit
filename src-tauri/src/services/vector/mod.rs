//! 向量存储模块
//!
//! 提供向量存储接口和内存实现，用于 RAG 和代码相似搜索

use async_trait::async_trait;
use std::collections::HashMap;

/// 向量数据
#[derive(Debug, Clone)]
pub struct Vector {
    /// 向量 ID
    pub id: String,

    /// 嵌入向量
    pub embedding: Vec<f32>,

    /// 元数据
    pub metadata: HashMap<String, String>,
}

/// 向量存储 trait
#[async_trait]
pub trait VectorStore: Send + Sync {
    /// 插入向量
    async fn insert(&self, vectors: Vec<Vector>) -> Result<(), VectorError>;

    /// 搜索相似向量
    async fn search(
        &self,
        query_embedding: &[f32],
        limit: usize,
        filters: Option<HashMap<String, String>>,
    ) -> Result<Vec<VectorSearchResult>, VectorError>;

    /// 删除向量
    async fn delete(&self, ids: &[String]) -> Result<(), VectorError>;

    /// 清空所有向量
    async fn clear(&self) -> Result<(), VectorError>;
}

/// 向量搜索结果
#[derive(Debug, Clone)]
pub struct VectorSearchResult {
    /// 向量数据
    pub vector: Vector,

    /// 相似度分数
    pub score: f32,
}

/// 向量错误
#[derive(Debug, Clone, thiserror::Error)]
pub enum VectorError {
    #[error("维度不匹配: 期望 {expected}, 实际 {actual}")]
    DimensionMismatch { expected: usize, actual: usize },

    #[error("向量不存在: {0}")]
    NotFound(String),

    #[error("存储错误: {0}")]
    StorageError(String),

    #[error("索引错误: {0}")]
    IndexError(String),
}

/// 内存向量存储实现
pub struct MemoryVectorStore {
    /// 向量数据
    vectors: tokio::sync::RwLock<HashMap<String, Vector>>,

    /// 向量维度
    dimension: usize,
}

impl MemoryVectorStore {
    /// 创建新的内存存储
    pub fn new(dimension: usize) -> Self {
        Self {
            vectors: tokio::sync::RwLock::new(HashMap::new()),
            dimension,
        }
    }

    /// 计算余弦相似度
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }

        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            0.0
        } else {
            dot_product / (norm_a * norm_b)
        }
    }
}

#[async_trait]
impl VectorStore for MemoryVectorStore {
    async fn insert(&self, vectors: Vec<Vector>) -> Result<(), VectorError> {
        let mut store = self.vectors.write().await;

        for vector in vectors {
            if vector.embedding.len() != self.dimension {
                return Err(VectorError::DimensionMismatch {
                    expected: self.dimension,
                    actual: vector.embedding.len(),
                });
            }
            store.insert(vector.id.clone(), vector);
        }

        Ok(())
    }

    async fn search(
        &self,
        query_embedding: &[f32],
        limit: usize,
        filters: Option<HashMap<String, String>>,
    ) -> Result<Vec<VectorSearchResult>, VectorError> {
        if query_embedding.len() != self.dimension {
            return Err(VectorError::DimensionMismatch {
                expected: self.dimension,
                actual: query_embedding.len(),
            });
        }

        let store = self.vectors.read().await;

        let mut results = Vec::new();

        for vector in store.values() {
            // 应用过滤器
            if let Some(ref filters) = filters {
                let mut matches = true;
                for (key, value) in filters {
                    if vector.metadata.get(key) != Some(value) {
                        matches = false;
                        break;
                    }
                }
                if !matches {
                    continue;
                }
            }

            let score = Self::cosine_similarity(query_embedding, &vector.embedding);
            results.push(VectorSearchResult {
                vector: vector.clone(),
                score,
            });
        }

        // 按分数降序排序
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // 限制结果数量
        results.truncate(limit);

        Ok(results)
    }

    async fn delete(&self, ids: &[String]) -> Result<(), VectorError> {
        let mut store = self.vectors.write().await;

        for id in ids {
            store.remove(id).ok_or_else(|| VectorError::NotFound(id.clone()))?;
        }

        Ok(())
    }

    async fn clear(&self) -> Result<(), VectorError> {
        self.vectors.write().await.clear();
        Ok(())
    }
}

/// 代码块向量存储
///
/// 专门用于存储和搜索代码块
pub struct CodeVectorStore {
    inner: MemoryVectorStore,
}

impl CodeVectorStore {
    /// 创建新的代码向量存储
    pub fn new(embedding_dimension: usize) -> Self {
        Self {
            inner: MemoryVectorStore::new(embedding_dimension),
        }
    }

    /// 添加代码块
    pub async fn add_code_chunk(
        &self,
        audit_id: &str,
        file_path: &str,
        chunk_index: usize,
        content: &str,
        embedding: Vec<f32>,
        language: Option<&str>,
    ) -> Result<(), VectorError> {
        let mut metadata = HashMap::new();
        metadata.insert("audit_id".to_string(), audit_id.to_string());
        metadata.insert("file_path".to_string(), file_path.to_string());
        metadata.insert("chunk_index".to_string(), chunk_index.to_string());
        if let Some(lang) = language {
            metadata.insert("language".to_string(), lang.to_string());
        }

        let vector = Vector {
            id: format!("{}:{}:{}", file_path, chunk_index, audit_id),
            embedding,
            metadata,
        };

        self.inner.insert(vec![vector]).await
    }

    /// 搜索相似代码
    pub async fn search_similar_code(
        &self,
        query_embedding: &[f32],
        audit_id: &str,
        limit: usize,
    ) -> Result<Vec<SimilarCodeResult>, VectorError> {
        let mut filters = HashMap::new();
        filters.insert("audit_id".to_string(), audit_id.to_string());

        let results = self.inner.search(query_embedding, limit, Some(filters)).await?;

        Ok(results
            .into_iter()
            .map(|r| {
                let file_path = r.vector.metadata.get("file_path").cloned().unwrap_or_default();
                let chunk_index = r
                    .vector
                    .metadata
                    .get("chunk_index")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);

                SimilarCodeResult {
                    file_path,
                    chunk_index,
                    content: String::new(), // 需要从原始内容获取
                    similarity: r.score,
                }
            })
            .collect())
    }
}

/// 相似代码搜索结果
#[derive(Debug, Clone)]
pub struct SimilarCodeResult {
    /// 文件路径
    pub file_path: String,

    /// 块索引
    pub chunk_index: usize,

    /// 代码内容
    pub content: String,

    /// 相似度 (0-1)
    pub similarity: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_vector_store() {
        let store = MemoryVectorStore::new(3);

        // 插入向量
        store
            .insert(vec![Vector {
                id: "vec1".to_string(),
                embedding: vec![1.0, 0.0, 0.0],
                metadata: HashMap::new(),
            }])
            .await
            .unwrap();

        // 搜索
        let results = store
            .search(&[1.0, 0.0, 0.0], 5, None)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!((results[0].score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let c = vec![0.0, 1.0, 0.0];

        assert!((MemoryVectorStore::cosine_similarity(&a, &b) - 1.0).abs() < 0.001);
        assert!((MemoryVectorStore::cosine_similarity(&a, &c) - 0.0).abs() < 0.001);
    }
}
