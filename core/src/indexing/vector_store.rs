// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 向量存储
//!
//! 内存中的向量索引，支持余弦相似度搜索

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 向量存储错误
#[derive(Debug, Clone, thiserror::Error)]
pub enum VectorStoreError {
    #[error("向量维度不匹配: 期望 {expected}, 实际 {actual}")]
    DimensionMismatch { expected: usize, actual: usize },

    #[error("向量 ID 不存在: {0}")]
    NotFound(String),

    #[error("向量存储为空")]
    EmptyStore,

    #[error("无效的向量: {0}")]
    InvalidVector(String),

    #[error("序列化错误: {0}")]
    Serialization(String),
}

/// 搜索结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// 向量 ID
    pub id: String,

    /// 相似度分数（0-1，越高越相似）
    pub score: f32,

    /// 关联的元数据
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl SearchResult {
    /// 创建新的搜索结果
    pub fn new(id: String, score: f32) -> Self {
        Self {
            id,
            score,
            metadata: HashMap::new(),
        }
    }

    /// 添加元数据
    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }
}

/// 向量条目
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VectorEntry {
    /// 向量数据
    vector: Vec<f32>,

    /// 元数据
    metadata: HashMap<String, serde_json::Value>,
}

/// 内存向量存储
#[derive(Debug, Default)]
pub struct VectorStore {
    /// 向量维度
    dimension: Option<usize>,

    /// 向量条目（ID -> Entry）
    entries: HashMap<String, VectorEntry>,

    /// ID 列表（用于顺序访问）
    id_list: Vec<String>,
}

impl VectorStore {
    /// 创建新的向量存储
    pub fn new() -> Self {
        Self {
            dimension: None,
            entries: HashMap::new(),
            id_list: Vec::new(),
        }
    }

    /// 创建指定维度的向量存储
    pub fn with_dimension(dimension: usize) -> Self {
        Self {
            dimension: Some(dimension),
            entries: HashMap::new(),
            id_list: Vec::new(),
        }
    }

    /// 获取向量维度
    pub fn dimension(&self) -> Option<usize> {
        self.dimension
    }

    /// 获取向量数量
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 添加向量
    pub fn add_vector(
        &mut self,
        id: String,
        vector: Vec<f32>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<(), VectorStoreError> {
        // 验证向量
        if vector.is_empty() {
            return Err(VectorStoreError::InvalidVector("向量不能为空".to_string()));
        }

        // 检查维度
        if let Some(dim) = self.dimension {
            if vector.len() != dim {
                return Err(VectorStoreError::DimensionMismatch {
                    expected: dim,
                    actual: vector.len(),
                });
            }
        } else {
            self.dimension = Some(vector.len());
        }

        // 添加条目
        let entry = VectorEntry {
            vector,
            metadata: metadata.unwrap_or_default(),
        };

        // 如果 ID 已存在，更新而不是添加新 ID 到列表
        if !self.entries.contains_key(&id) {
            self.id_list.push(id.clone());
        }

        self.entries.insert(id, entry);

        Ok(())
    }

    /// 批量添加向量
    pub fn add_vectors(
        &mut self,
        vectors: Vec<(String, Vec<f32>, Option<HashMap<String, serde_json::Value>>)>,
    ) -> Result<usize, VectorStoreError> {
        let mut added = 0;
        for (id, vector, metadata) in vectors {
            self.add_vector(id, vector, metadata)?;
            added += 1;
        }
        Ok(added)
    }

    /// 获取向量
    pub fn get_vector(&self, id: &str) -> Option<&Vec<f32>> {
        self.entries.get(id).map(|e| &e.vector)
    }

    /// 获取元数据
    pub fn get_metadata(&self, id: &str) -> Option<&HashMap<String, serde_json::Value>> {
        self.entries.get(id).map(|e| &e.metadata)
    }

    /// 删除向量
    pub fn remove_vector(&mut self, id: &str) -> Option<VectorEntry> {
        self.id_list.retain(|i| i != id);
        self.entries.remove(id)
    }

    /// 清空存储
    pub fn clear(&mut self) {
        self.entries.clear();
        self.id_list.clear();
        self.dimension = None;
    }

    /// 获取所有 ID
    pub fn get_all_ids(&self) -> &[String] {
        &self.id_list
    }

    /// 余弦相似度搜索
    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<SearchResult>, VectorStoreError> {
        if self.entries.is_empty() {
            return Err(VectorStoreError::EmptyStore);
        }

        // 验证查询向量维度
        if let Some(dim) = self.dimension {
            if query.len() != dim {
                return Err(VectorStoreError::DimensionMismatch {
                    expected: dim,
                    actual: query.len(),
                });
            }
        }

        // 计算所有向量的相似度
        let mut results: Vec<SearchResult> = self
            .entries
            .iter()
            .map(|(id, entry)| {
                let score = cosine_similarity(query, &entry.vector);
                SearchResult {
                    id: id.clone(),
                    score,
                    metadata: entry.metadata.clone(),
                }
            })
            .collect();

        // 按相似度降序排序
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // 返回前 k 个结果
        Ok(results.into_iter().take(k).collect())
    }

    /// 带过滤条件的搜索
    pub fn search_with_filter<F>(
        &self,
        query: &[f32],
        k: usize,
        filter: F,
    ) -> Result<Vec<SearchResult>, VectorStoreError>
    where
        F: Fn(&HashMap<String, serde_json::Value>) -> bool,
    {
        if self.entries.is_empty() {
            return Err(VectorStoreError::EmptyStore);
        }

        // 验证查询向量维度
        if let Some(dim) = self.dimension {
            if query.len() != dim {
                return Err(VectorStoreError::DimensionMismatch {
                    expected: dim,
                    actual: query.len(),
                });
            }
        }

        // 计算满足过滤条件的向量的相似度
        let mut results: Vec<SearchResult> = self
            .entries
            .iter()
            .filter(|(_, entry)| filter(&entry.metadata))
            .map(|(id, entry)| {
                let score = cosine_similarity(query, &entry.vector);
                SearchResult {
                    id: id.clone(),
                    score,
                    metadata: entry.metadata.clone(),
                }
            })
            .collect();

        // 按相似度降序排序
        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // 返回前 k 个结果
        Ok(results.into_iter().take(k).collect())
    }

    /// 按文件路径搜索
    pub fn search_by_file(
        &self,
        query: &[f32],
        k: usize,
        file_path: &str,
    ) -> Result<Vec<SearchResult>, VectorStoreError> {
        self.search_with_filter(query, k, |metadata| {
            metadata
                .get("file_path")
                .and_then(|v| v.as_str())
                .map(|p| p == file_path)
                .unwrap_or(false)
        })
    }

    /// 序列化到字节
    pub fn to_bytes(&self) -> Result<Vec<u8>, VectorStoreError> {
        bincode::serialize(&(self.dimension, &self.entries, &self.id_list))
            .map_err(|e| VectorStoreError::Serialization(e.to_string()))
    }

    /// 从字节反序列化
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VectorStoreError> {
        let (dimension, entries, id_list): (
            Option<usize>,
            HashMap<String, VectorEntry>,
            Vec<String>,
        ) = bincode::deserialize(bytes)
            .map_err(|e| VectorStoreError::Serialization(e.to_string()))?;

        Ok(Self {
            dimension,
            entries,
            id_list,
        })
    }
}

/// 计算余弦相似度
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    dot_product / (norm_a * norm_b)
}

/// 归一化向量
pub fn normalize_vector(vector: &[f32]) -> Vec<f32> {
    let norm: f32 = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm == 0.0 {
        return vector.to_vec();
    }
    vector.iter().map(|x| x / norm).collect()
}

/// 线程安全的向量存储包装器
#[derive(Debug, Clone)]
pub struct ThreadSafeVectorStore {
    inner: Arc<RwLock<VectorStore>>,
}

impl ThreadSafeVectorStore {
    /// 创建新的线程安全向量存储
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(VectorStore::new())),
        }
    }

    /// 创建指定维度的线程安全向量存储
    pub fn with_dimension(dimension: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(VectorStore::with_dimension(dimension))),
        }
    }

    /// 添加向量
    pub async fn add_vector(
        &self,
        id: String,
        vector: Vec<f32>,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<(), VectorStoreError> {
        let mut store = self.inner.write().await;
        store.add_vector(id, vector, metadata)
    }

    /// 搜索
    pub async fn search(
        &self,
        query: &[f32],
        k: usize,
    ) -> Result<Vec<SearchResult>, VectorStoreError> {
        let store = self.inner.read().await;
        store.search(query, k)
    }

    /// 获取向量数量
    pub async fn len(&self) -> usize {
        let store = self.inner.read().await;
        store.len()
    }

    /// 清空存储
    pub async fn clear(&self) {
        let mut store = self.inner.write().await;
        store.clear();
    }
}

impl Default for ThreadSafeVectorStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-6);

        let c = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity(&a, &c).abs() < 1e-6);

        let d = vec![-1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &d) - (-1.0)).abs() < 1e-6);
    }

    #[test]
    fn test_normalize_vector() {
        let v = vec![3.0, 4.0];
        let normalized = normalize_vector(&v);
        assert!((normalized[0] - 0.6).abs() < 1e-6);
        assert!((normalized[1] - 0.8).abs() < 1e-6);
    }

    #[test]
    fn test_vector_store_add_and_search() {
        let mut store = VectorStore::new();

        // 添加向量
        store
            .add_vector("a".to_string(), vec![1.0, 0.0, 0.0], None)
            .unwrap();
        store
            .add_vector("b".to_string(), vec![0.0, 1.0, 0.0], None)
            .unwrap();
        store
            .add_vector("c".to_string(), vec![0.9, 0.1, 0.0], None)
            .unwrap();

        assert_eq!(store.len(), 3);
        assert_eq!(store.dimension(), Some(3));

        // 搜索
        let query = vec![1.0, 0.0, 0.0];
        let results = store.search(&query, 2).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].id, "a");
        assert!((results[0].score - 1.0).abs() < 1e-6);
        assert_eq!(results[1].id, "c"); // c 比 b 更接近查询向量
    }

    #[test]
    fn test_dimension_mismatch() {
        let mut store = VectorStore::with_dimension(3);
        store
            .add_vector("a".to_string(), vec![1.0, 0.0, 0.0], None)
            .unwrap();

        let result = store.add_vector("b".to_string(), vec![1.0, 0.0], None);
        assert!(matches!(
            result,
            Err(VectorStoreError::DimensionMismatch { .. })
        ));
    }

    #[test]
    fn test_search_with_filter() {
        let mut store = VectorStore::new();
        let mut meta_a = HashMap::new();
        meta_a.insert("type".to_string(), serde_json::json!("function"));

        let mut meta_b = HashMap::new();
        meta_b.insert("type".to_string(), serde_json::json!("class"));

        store
            .add_vector("a".to_string(), vec![1.0, 0.0], Some(meta_a))
            .unwrap();
        store
            .add_vector("b".to_string(), vec![0.0, 1.0], Some(meta_b))
            .unwrap();

        let query = vec![1.0, 0.0];
        let results = store
            .search_with_filter(&query, 10, |meta| {
                meta.get("type")
                    .and_then(|v| v.as_str())
                    .map(|t| t == "function")
                    .unwrap_or(false)
            })
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "a");
    }

    #[test]
    fn test_serialization() {
        let mut store = VectorStore::new();
        store
            .add_vector("a".to_string(), vec![1.0, 0.0, 0.0], None)
            .unwrap();

        let bytes = store.to_bytes().unwrap();
        let restored = VectorStore::from_bytes(&bytes).unwrap();

        assert_eq!(restored.len(), 1);
        assert_eq!(restored.dimension(), Some(3));
    }
}
