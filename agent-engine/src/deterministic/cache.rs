// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 审计结果缓存

use crate::deterministic::config::CacheStrategy;
use crate::audit_state::SecurityAuditState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc};

/// 审计缓存
pub struct AuditCache {
    /// 缓存策略
    strategy: CacheStrategy,

    /// 内存缓存
    memory_cache: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,

    /// 缓存目录
    cache_dir: PathBuf,

    /// 统计信息
    stats: Arc<RwLock<CacheStats>>,
}

/// 缓存键
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct CacheKey {
    /// 代码库签名
    pub codebase_signature: String,

    /// 配置签名
    pub config_signature: String,

    /// 审计阶段
    pub phase: Option<String>,
}

/// 缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// 缓存的结果
    pub result: CachedResult,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 过期时间
    pub expires_at: Option<DateTime<Utc>>,

    /// 访问次数
    pub access_count: usize,

    /// 最后访问时间
    pub last_accessed: DateTime<Utc>,
}

/// 缓存结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CachedResult {
    /// 阶段结果
    PhaseResult(String),

    /// 漏洞候选列表
    VulnerabilityCandidates(Vec<serde_json::Value>),

    /// 分析报告
    AnalysisReport(String),

    /// 原始数据
    RawData(serde_json::Value),
}

/// 缓存统计
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheStats {
    /// 命中次数
    pub hits: usize,

    /// 未命中次数
    pub misses: usize,

    /// 存储的条目数
    pub entries: usize,

    /// 总字节数
    pub total_bytes: usize,

    /// 驱逐次数
    pub evictions: usize,
}

impl AuditCache {
    /// 创建新的审计缓存
    pub fn new(strategy: CacheStrategy, cache_dir: PathBuf) -> Self {
        Self {
            strategy,
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            cache_dir,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    /// 获取缓存
    pub fn get(&self, key: &CacheKey) -> Option<CachedResult> {
        if matches!(self.strategy, CacheStrategy::Disabled) {
            return None;
        }

        // 先检查内存缓存
        {
            let mut cache = self.memory_cache.write().expect("cache lock poisoned - another thread panicked");
            if let Some(entry) = cache.get_mut(key) {
                entry.access_count += 1;
                entry.last_accessed = Utc::now();

                // 检查是否过期
                if let Some(expires_at) = entry.expires_at {
                    if Utc::now() > expires_at {
                        cache.remove(key);
                        let mut stats = self.stats.write().expect("stats lock poisoned");
                        stats.misses += 1;
                        return None;
                    }
                }

                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.hits += 1;
                return Some(entry.result.clone());
            }
        }

        // 检查持久化缓存
        if matches!(self.strategy, CacheStrategy::Persistent | CacheStrategy::Smart) {
            if let Some(result) = self.load_from_disk(key) {
                let mut cache = self.memory_cache.write().expect("cache lock poisoned");
                cache.insert(key.clone(), CacheEntry {
                    result: result.clone(),
                    created_at: Utc::now(),
                    expires_at: None,
                    access_count: 1,
                    last_accessed: Utc::now(),
                });

                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.hits += 1;
                stats.entries += 1;
                return Some(result);
            }
        }

        let mut stats = self.stats.write().expect("stats lock poisoned");
        stats.misses += 1;
        None
    }

    /// 设置缓存
    pub fn set(&self, key: CacheKey, result: CachedResult, ttl_seconds: Option<u64>) {
        if matches!(self.strategy, CacheStrategy::Disabled) {
            return;
        }

        let expires_at = ttl_seconds.map(|secs| Utc::now() + chrono::Duration::seconds(secs as i64));

        let entry = CacheEntry {
            result: result.clone(),
            created_at: Utc::now(),
            expires_at,
            access_count: 1,
            last_accessed: Utc::now(),
        };

        // 写入内存缓存
        {
            let mut cache = self.memory_cache.write().expect("cache lock poisoned");
            cache.insert(key.clone(), entry);
        }

        // 写入持久化缓存
        if matches!(self.strategy, CacheStrategy::Persistent | CacheStrategy::Smart) {
            self.save_to_disk(&key, &result);
        }

        let mut stats = self.stats.write().expect("stats lock poisoned");
        stats.entries = self.memory_cache.read().expect("cache lock poisoned").len();
    }

    /// 清除缓存
    pub fn clear(&self) {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");
        cache.clear();

        if matches!(self.strategy, CacheStrategy::Persistent | CacheStrategy::Smart) {
            let _ = std::fs::remove_dir_all(&self.cache_dir);
            let _ = std::fs::create_dir_all(&self.cache_dir);
        }

        let mut stats = self.stats.write().expect("stats lock poisoned");
        *stats = CacheStats::default();
    }

    /// 清除过期缓存
    pub fn clear_expired(&self) {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");
        let now = Utc::now();
        let mut eviction_count = 0;

        // 收集过期的键
        let expired_keys: Vec<_> = cache.iter()
            .filter(|(_, entry)| {
                if let Some(expires_at) = entry.expires_at {
                    now >= expires_at
                } else {
                    false
                }
            })
            .map(|(k, _)| k.clone())
            .collect();

        // 移除过期的键
        for key in &expired_keys {
            cache.remove(key);
            eviction_count += 1;
        }

        // 更新统计信息
        let mut stats = self.stats.write().expect("stats lock poisoned");
        stats.evictions += eviction_count;
        stats.entries = cache.len();
    }

    /// 获取统计信息
    pub fn stats(&self) -> CacheStats {
        let stats = self.stats.read().expect("stats lock poisoned");
        stats.clone()
    }

    /// 计算缓存命中率
    pub fn hit_rate(&self) -> f32 {
        let stats = self.stats.read().expect("stats lock poisoned");
        let total = stats.hits + stats.misses;
        if total == 0 {
            0.0
        } else {
            stats.hits as f32 / total as f32
        }
    }

    /// 从磁盘加载
    fn load_from_disk(&self, key: &CacheKey) -> Option<CachedResult> {
        let file_path = self.cache_path_for_key(key);

        if let Ok(content) = std::fs::read_to_string(&file_path) {
            if let Ok(entry) = serde_json::from_str::<CacheEntry>(&content) {
                return Some(entry.result);
            }
        }

        None
    }

    /// 保存到磁盘
    fn save_to_disk(&self, key: &CacheKey, result: &CachedResult) {
        let _ = std::fs::create_dir_all(&self.cache_dir);

        let file_path = self.cache_path_for_key(key);
        let entry = CacheEntry {
            result: result.clone(),
            created_at: Utc::now(),
            expires_at: None,
            access_count: 1,
            last_accessed: Utc::now(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = std::fs::write(&file_path, json);
        }
    }

    /// 获取缓存文件路径
    fn cache_path_for_key(&self, key: &CacheKey) -> PathBuf {
        // 使用 SHA256 哈希缓存键作为文件名
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        self.cache_dir.join(format!("{:016x}.json", hash))
    }

    /// 清理旧缓存（LRU）
    pub fn evict_lru(&self, max_entries: usize) {
        let mut cache = self.memory_cache.write().expect("cache lock poisoned");

        if cache.len() <= max_entries {
            return;
        }

        // 按最后访问时间排序
        let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.last_accessed)).collect();
        entries.sort_by(|a, b| a.1.cmp(&b.1));

        // 移除最旧的条目
        let to_remove = entries.len() - max_entries;
        let mut eviction_count = 0;

        for (key, _) in entries.iter().take(to_remove) {
            cache.remove(key);
            eviction_count += 1;
        }

        // 更新统计信息
        let mut stats = self.stats.write().expect("stats lock poisoned");
        stats.evictions += eviction_count;
        stats.entries = cache.len();
    }

    /// 生成缓存键
    pub fn generate_key(
        codebase_signature: &str,
        config_signature: &str,
        phase: Option<&str>,
    ) -> CacheKey {
        CacheKey {
            codebase_signature: codebase_signature.to_string(),
            config_signature: config_signature.to_string(),
            phase: phase.map(|s| s.to_string()),
        }
    }

    /// 计算配置签名
    pub fn compute_config_signature(config: &crate::deterministic::config::DeterministicConfig) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        config.seed.hash(&mut hasher);
        config.decoding_mode.hash(&mut hasher);
        (config.temperature.to_bits()).hash(&mut hasher);
        config.cache_strategy.hash(&mut hasher);

        format!("{:016x}", hasher.finish())
    }
}

impl Default for AuditCache {
    fn default() -> Self {
        let cache_dir = std::env::temp_dir().join("ctx-audit-cache");
        Self::new(CacheStrategy::Smart, cache_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_generation() {
        let key = AuditCache::generate_key("sig1", "sig2", Some("scan"));
        assert_eq!(key.codebase_signature, "sig1");
        assert_eq!(key.config_signature, "sig2");
        assert_eq!(key.phase, Some("scan".to_string()));
    }

    #[test]
    fn test_cache_hit_rate() {
        let cache = AuditCache::default();

        // 初始命中率为 0
        assert_eq!(cache.hit_rate(), 0.0);

        let key = CacheKey {
            codebase_signature: "test".to_string(),
            config_signature: "test".to_string(),
            phase: None,
        };

        // 设置缓存
        cache.set(key.clone(), CachedResult::RawData(serde_json::json!({})), None);

        // 命中
        let _ = cache.get(&key);

        // 命中率应该是 100%
        assert_eq!(cache.hit_rate(), 1.0);
    }
}
