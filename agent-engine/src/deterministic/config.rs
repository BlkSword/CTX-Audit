// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 确定性审计配置

use serde::{Deserialize, Serialize};

/// 确定性审计配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterministicConfig {
    /// 随机种子
    pub seed: u64,

    /// 贪心解码模式
    pub decoding_mode: DecodingMode,

    /// 温度（贪心模式下应为 0）
    pub temperature: f32,

    /// 缓存策略
    pub cache_strategy: CacheStrategy,

    /// 种子策略
    pub seed_strategy: SeedStrategy,

    /// 最大重试次数
    pub max_retries: usize,

    /// 超时时间（秒）
    pub timeout_seconds: u64,
}

impl Default for DeterministicConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            decoding_mode: DecodingMode::Greedy,
            temperature: 0.0,
            cache_strategy: CacheStrategy::Smart,
            seed_strategy: SeedStrategy::Fixed,
            max_retries: 3,
            timeout_seconds: 300,
        }
    }
}

impl DeterministicConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置随机种子
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// 设置解码模式
    pub fn with_decoding_mode(mut self, mode: DecodingMode) -> Self {
        self.decoding_mode = mode;
        self
    }

    /// 设置温度
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }

    /// 设置缓存策略
    pub fn with_cache_strategy(mut self, strategy: CacheStrategy) -> Self {
        self.cache_strategy = strategy;
        self
    }

    /// 设置种子策略
    pub fn with_seed_strategy(mut self, strategy: SeedStrategy) -> Self {
        self.seed_strategy = strategy;
        self
    }

    /// 验证配置
    pub fn validate(&self) -> Result<(), String> {
        if self.decoding_mode == DecodingMode::Greedy && self.temperature != 0.0 {
            return Err("Greedy decoding requires temperature 0".to_string());
        }

        if self.temperature < 0.0 || self.temperature > 2.0 {
            return Err("Temperature must be between 0 and 2".to_string());
        }

        if self.timeout_seconds == 0 {
            return Err("Timeout must be greater than 0".to_string());
        }

        Ok(())
    }

    /// 获取实际使用的种子
    pub fn get_effective_seed(&self) -> u64 {
        match self.seed_strategy {
            SeedStrategy::Fixed => self.seed,
            SeedStrategy::TimeBased => {
                use std::time::{SystemTime, UNIX_EPOCH};
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(self.seed) as u64
            }
            SeedStrategy::ContentBased => {
                // 内容相关种子需要在运行时计算
                self.seed
            }
        }
    }

    /// 是否启用缓存
    pub fn is_cache_enabled(&self) -> bool {
        !matches!(self.cache_strategy, CacheStrategy::Disabled)
    }

    /// 是否使用贪心解码
    pub fn is_greedy_decoding(&self) -> bool {
        matches!(self.decoding_mode, DecodingMode::Greedy)
    }
}

/// 解码模式
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DecodingMode {
    /// 贪心解码（确定性，温度=0）
    Greedy,

    /// 采样解码（非确定性，温度>0）
    Sampling,

    /// 束搜索解码（相对确定性）
    BeamSearch { beam_size: usize },
}

/// 缓存策略
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CacheStrategy {
    /// 禁用缓存
    Disabled,

    /// 仅内存缓存
    MemoryOnly,

    /// 持久化缓存
    Persistent,

    /// 智能缓存（自动选择）
    Smart,
}

/// 种子策略
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SeedStrategy {
    /// 固定种子
    Fixed,

    /// 基于时间
    TimeBased,

    /// 基于内容哈希
    ContentBased,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DeterministicConfig::default();
        assert_eq!(config.seed, 42);
        assert_eq!(config.decoding_mode, DecodingMode::Greedy);
        assert_eq!(config.temperature, 0.0);
    }

    #[test]
    fn test_config_builder() {
        let config = DeterministicConfig::new()
            .with_seed(123)
            .with_temperature(0.5);

        assert_eq!(config.seed, 123);
        assert_eq!(config.temperature, 0.5);
    }

    #[test]
    fn test_config_validation() {
        // 有效配置
        let config = DeterministicConfig::default();
        assert!(config.validate().is_ok());

        // 贪心解码但温度不为 0
        let invalid_config = DeterministicConfig {
            decoding_mode: DecodingMode::Greedy,
            temperature: 0.5,
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_get_effective_seed() {
        let config = DeterministicConfig::new()
            .with_seed(42)
            .with_seed_strategy(SeedStrategy::Fixed);

        assert_eq!(config.get_effective_seed(), 42);
    }
}
