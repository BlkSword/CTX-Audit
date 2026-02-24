// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 分析缓存模块
//!
//! 提供 AST 解析缓存和分析结果缓存，提升性能

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// 缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    /// 缓存值
    pub value: T,
    /// 创建时间（毫秒时间戳）
    pub created_at: u64,
    /// 最后访问时间
    pub last_accessed: u64,
    /// 访问次数
    pub access_count: u64,
    /// 文件修改时间（用于验证缓存有效性）
    pub file_mtime: Option<u64>,
    /// 文件哈希（用于验证内容是否变化）
    pub file_hash: Option<String>,
}

impl<T> CacheEntry<T> {
    /// 创建新的缓存条目
    pub fn new(value: T, file_mtime: Option<u64>, file_hash: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            value,
            created_at: now,
            last_accessed: now,
            access_count: 1,
            file_mtime,
            file_hash,
        }
    }

    /// 记录访问
    pub fn record_access(&mut self) {
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.access_count += 1;
    }

    /// 检查缓存是否过期
    pub fn is_expired(&self, max_age_ms: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        now.saturating_sub(self.created_at) > max_age_ms
    }

    /// 检查文件是否已修改
    pub fn is_file_modified(&self, current_mtime: Option<u64>) -> bool {
        match (self.file_mtime, current_mtime) {
            (Some(cached), Some(current)) => cached != current,
            _ => false,
        }
    }
}

/// 缓存统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// 命中次数
    pub hits: u64,
    /// 未命中次数
    pub misses: u64,
    /// 总请求数
    pub total_requests: u64,
    /// 缓存大小
    pub size: usize,
    /// 内存使用估计（字节）
    pub estimated_memory: usize,
}

impl CacheStats {
    /// 获取命中率
    pub fn hit_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.hits as f64 / self.total_requests as f64
        }
    }
}

/// 通用内存缓存
#[derive(Debug)]
pub struct MemoryCache<T> {
    /// 缓存存储
    cache: Arc<RwLock<HashMap<String, CacheEntry<T>>>>,
    /// 最大条目数
    max_entries: usize,
    /// 最大存活时间（毫秒）
    max_age_ms: u64,
    /// 统计信息
    stats: Arc<RwLock<CacheStats>>,
}

impl<T: Clone + Send + Sync> MemoryCache<T> {
    /// 创建新的缓存
    pub fn new(max_entries: usize, max_age_ms: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            max_age_ms,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// 获取缓存值
    pub fn get(&self, key: &str) -> Option<T> {
        let mut stats = self.stats.write().unwrap();
        stats.total_requests += 1;

        let mut cache = self.cache.write().unwrap();
        if let Some(entry) = cache.get_mut(key) {
            if entry.is_expired(self.max_age_ms) {
                cache.remove(key);
                stats.misses += 1;
                return None;
            }
            entry.record_access();
            stats.hits += 1;
            Some(entry.value.clone())
        } else {
            stats.misses += 1;
            None
        }
    }

    /// 获取缓存值（带文件修改检查）
    pub fn get_with_mtime(&self, key: &str, current_mtime: Option<u64>) -> Option<T> {
        let mut stats = self.stats.write().unwrap();
        stats.total_requests += 1;

        let mut cache = self.cache.write().unwrap();
        if let Some(entry) = cache.get_mut(key) {
            if entry.is_expired(self.max_age_ms) || entry.is_file_modified(current_mtime) {
                cache.remove(key);
                stats.misses += 1;
                return None;
            }
            entry.record_access();
            stats.hits += 1;
            Some(entry.value.clone())
        } else {
            stats.misses += 1;
            None
        }
    }

    /// 设置缓存值
    pub fn set(&self, key: String, value: T) {
        self.set_with_meta(key, value, None, None);
    }

    /// 设置缓存值（带元数据）
    pub fn set_with_meta(
        &self,
        key: String,
        value: T,
        file_mtime: Option<u64>,
        file_hash: Option<String>,
    ) {
        let mut cache = self.cache.write().unwrap();

        // 如果超过最大条目数，删除最久未访问的条目
        if cache.len() >= self.max_entries {
            self.evict_lru(&mut cache);
        }

        let entry = CacheEntry::new(value, file_mtime, file_hash);
        cache.insert(key, entry);

        let mut stats = self.stats.write().unwrap();
        stats.size = cache.len();
    }

    /// 删除最久未访问的条目
    fn evict_lru(&self, cache: &mut HashMap<String, CacheEntry<T>>) {
        if cache.is_empty() {
            return;
        }

        let lru_key = cache
            .iter()
            .min_by_key(|(_, e)| e.last_accessed)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            cache.remove(&key);
        }
    }

    /// 删除缓存条目
    pub fn remove(&self, key: &str) -> Option<T> {
        let mut cache = self.cache.write().unwrap();
        let entry = cache.remove(key)?;
        let mut stats = self.stats.write().unwrap();
        stats.size = cache.len();
        Some(entry.value)
    }

    /// 清空缓存
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.clear();
        let mut stats = self.stats.write().unwrap();
        stats.size = 0;
    }

    /// 获取统计信息
    pub fn stats(&self) -> CacheStats {
        self.stats.read().unwrap().clone()
    }

    /// 获取缓存大小
    pub fn len(&self) -> usize {
        self.cache.read().unwrap().len()
    }

    /// 检查缓存是否为空
    pub fn is_empty(&self) -> bool {
        self.cache.read().unwrap().is_empty()
    }
}

impl<T: Clone + Send + Sync> Default for MemoryCache<T> {
    fn default() -> Self {
        Self::new(1000, 3600 * 1000) // 默认 1000 条，1 小时过期
    }
}

/// AST 解析缓存
pub type AstCache = MemoryCache<AstCacheEntry>;

/// AST 缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstCacheEntry {
    /// 文件路径
    pub file_path: String,
    /// 语言
    pub language: String,
    /// AST 节点（序列化后的 JSON）
    pub ast_json: String,
    /// 提取的符号
    pub symbols: Vec<CachedSymbol>,
    /// 解析耗时（毫秒）
    pub parse_time_ms: u64,
}

/// 缓存的符号
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSymbol {
    /// 符号名
    pub name: String,
    /// 符号类型
    pub kind: String,
    /// 行号
    pub line: usize,
    /// 列号
    pub column: usize,
}

/// 分析结果缓存
pub type AnalysisCache = MemoryCache<AnalysisCacheEntry>;

/// 分析缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCacheEntry {
    /// 分析类型
    pub analysis_type: String,
    /// 目标文件/路径
    pub target: String,
    /// 分析结果（JSON）
    pub result_json: String,
    /// 发现数量
    pub findings_count: usize,
    /// 分析耗时（毫秒）
    pub analysis_time_ms: u64,
}

/// 污点分析缓存
pub type TaintCache = MemoryCache<TaintCacheEntry>;

/// 污点分析缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintCacheEntry {
    /// 文件路径
    pub file_path: String,
    /// 语言
    pub language: String,
    /// 污点流（JSON）
    pub flows_json: String,
    /// 污点流数量
    pub flows_count: usize,
    /// 分析耗时（毫秒）
    pub analysis_time_ms: u64,
}

/// 全局缓存管理器
pub struct CacheManager {
    /// AST 缓存
    pub ast_cache: AstCache,
    /// 分析结果缓存
    pub analysis_cache: AnalysisCache,
    /// 污点分析缓存
    pub taint_cache: TaintCache,
}

impl CacheManager {
    /// 创建新的缓存管理器
    pub fn new() -> Self {
        Self {
            ast_cache: AstCache::new(500, 3600 * 1000),    // 500 条，1 小时
            analysis_cache: AnalysisCache::new(200, 1800 * 1000), // 200 条，30 分钟
            taint_cache: TaintCache::new(300, 1800 * 1000), // 300 条，30 分钟
        }
    }

    /// 获取总体统计
    pub fn total_stats(&self) -> TotalCacheStats {
        TotalCacheStats {
            ast_stats: self.ast_cache.stats(),
            analysis_stats: self.analysis_cache.stats(),
            taint_stats: self.taint_cache.stats(),
        }
    }

    /// 清空所有缓存
    pub fn clear_all(&self) {
        self.ast_cache.clear();
        self.analysis_cache.clear();
        self.taint_cache.clear();
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 总体缓存统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotalCacheStats {
    pub ast_stats: CacheStats,
    pub analysis_stats: CacheStats,
    pub taint_stats: CacheStats,
}

impl TotalCacheStats {
    /// 获取总命中率
    pub fn total_hit_rate(&self) -> f64 {
        let total_requests = self.ast_stats.total_requests
            + self.analysis_stats.total_requests
            + self.taint_stats.total_requests;
        let total_hits = self.ast_stats.hits
            + self.analysis_stats.hits
            + self.taint_stats.hits;

        if total_requests == 0 {
            0.0
        } else {
            total_hits as f64 / total_requests as f64
        }
    }
}

/// 获取文件修改时间
pub fn get_file_mtime(path: &std::path::Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
}

/// 计算文件内容哈希（简单实现）
pub fn compute_file_hash(content: &str) -> String {
    // 使用简单的哈希算法
    let mut hash: u64 = 0;
    for (i, c) in content.chars().enumerate() {
        hash = hash.wrapping_add((c as u64).wrapping_mul((i + 1) as u64));
    }
    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_creation() {
        let entry: CacheEntry<String> = CacheEntry::new("test".to_string(), Some(12345), None);
        assert_eq!(entry.value, "test");
        assert_eq!(entry.access_count, 1);
    }

    #[test]
    fn test_cache_entry_access() {
        let mut entry: CacheEntry<String> = CacheEntry::new("test".to_string(), None, None);
        entry.record_access();
        assert_eq!(entry.access_count, 2);
    }

    #[test]
    fn test_memory_cache_basic() {
        let cache: MemoryCache<String> = MemoryCache::new(10, 10000);

        cache.set("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
        assert_eq!(cache.get("key2"), None);
    }

    #[test]
    fn test_memory_cache_stats() {
        let cache: MemoryCache<String> = MemoryCache::new(10, 10000);

        cache.set("key1".to_string(), "value1".to_string());
        cache.get("key1"); // hit
        cache.get("key2"); // miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.total_requests, 2);
    }

    #[test]
    fn test_memory_cache_eviction() {
        let cache: MemoryCache<String> = MemoryCache::new(2, 10000);

        cache.set("key1".to_string(), "value1".to_string());
        cache.set("key2".to_string(), "value2".to_string());
        cache.set("key3".to_string(), "value3".to_string()); // 应该触发淘汰

        assert!(cache.len() <= 2);
    }

    #[test]
    fn test_cache_manager() {
        let manager = CacheManager::new();

        manager.ast_cache.set("file1.py".to_string(), AstCacheEntry {
            file_path: "file1.py".to_string(),
            language: "python".to_string(),
            ast_json: "{}".to_string(),
            symbols: vec![],
            parse_time_ms: 10,
        });

        assert!(!manager.ast_cache.is_empty());
    }

    #[test]
    fn test_compute_file_hash() {
        let hash1 = compute_file_hash("hello world");
        let hash2 = compute_file_hash("hello world");
        let hash3 = compute_file_hash("hello World");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
