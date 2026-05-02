// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 配置管理
//!
//! 管理应用配置，包括扫描规则路径、输出格式等

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;

/// 应用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 扫描配置
    pub scan: ScanConfig,

    /// 输出配置
    pub output: OutputConfig,

    /// 高级配置
    pub advanced: AdvancedConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            output: OutputConfig::default(),
            advanced: AdvancedConfig::default(),
        }
    }
}

/// 扫描配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// 规则目录路径
    pub rules_dir: Option<PathBuf>,

    /// 并行线程数
    #[serde(default = "default_threads")]
    pub threads: usize,

    /// 是否包含测试文件
    #[serde(default)]
    pub include_tests: bool,

    /// 排除的目录模式
    #[serde(default = "default_exclude_patterns")]
    pub exclude_patterns: Vec<String>,
}

fn default_threads() -> usize { 4 }
fn default_exclude_patterns() -> Vec<String> {
    vec![
        "node_modules".to_string(),
        "target".to_string(),
        "vendor".to_string(),
        ".git".to_string(),
    ]
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            rules_dir: None,
            threads: 4,
            include_tests: false,
            exclude_patterns: vec![
                "node_modules".to_string(),
                "target".to_string(),
                "vendor".to_string(),
                ".git".to_string(),
            ],
        }
    }
}

/// 输出配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// 默认输出格式
    #[serde(default = "default_format")]
    pub format: String,

    /// 是否显示颜色
    #[serde(default = "default_color")]
    pub color: bool,

    /// 是否显示详细输出
    #[serde(default)]
    pub verbose: bool,
}

fn default_format() -> String { "text".to_string() }
fn default_color() -> bool { true }

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "text".to_string(),
            color: true,
            verbose: false,
        }
    }
}

/// 高级配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// 缓存目录
    pub cache_dir: Option<PathBuf>,

    /// 是否启用缓存
    #[serde(default = "default_enable_cache")]
    pub enable_cache: bool,

    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_enable_cache() -> bool { true }
fn default_log_level() -> String { "info".to_string() }

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            cache_dir: None,
            enable_cache: true,
            log_level: "info".to_string(),
        }
    }
}

/// 配置管理器
pub struct ConfigManager {
    /// 配置文件路径
    config_path: PathBuf,

    /// 当前配置
    config: Config,
}

impl ConfigManager {
    /// 创建新的配置管理器
    pub fn new(config_path: Option<PathBuf>) -> anyhow::Result<Self> {
        let config_path = config_path
            .or_else(|| {
                dirs::config_dir().map(|dir| dir.join("ctx-audit").join("config.toml"))
            })
            .context("无法确定配置文件路径")?;

        let config = Self::load_config(&config_path).unwrap_or_default();

        Ok(Self {
            config_path,
            config,
        })
    }

    /// 从文件加载配置
    fn load_config(path: &Path) -> Option<Config> {
        if !path.exists() {
            tracing::debug!("配置文件不存在: {:?}", path);
            return None;
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("读取配置文件失败: {:?}", e);
                return None;
            }
        };

        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(e) => e,
            None => {
                tracing::warn!("无法获取配置文件扩展名");
                return None;
            }
        };

        match ext {
            "toml" => {
                match toml::from_str(&content) {
                    Ok(config) => Some(config),
                    Err(e) => {
                        tracing::warn!("TOML 解析失败: {:?}", e);
                        None
                    }
                }
            }
            "yaml" | "yml" => serde_yaml::from_str(&content).ok(),
            "json" => serde_json::from_str(&content).ok(),
            _ => None,
        }
    }

    /// 获取当前配置
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 获取可变配置
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    /// 保存配置
    pub async fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let content = toml::to_string_pretty(&self.config)
            .context("序列化配置失败")?;

        fs::write(&self.config_path, content)
            .await
            .context("写入配置文件失败")?;

        Ok(())
    }

    /// 获取配置值
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "scan.threads" => Some(self.config.scan.threads.to_string()),
            "scan.include_tests" => Some(self.config.scan.include_tests.to_string()),
            "output.format" => Some(self.config.output.format.clone()),
            "output.color" => Some(self.config.output.color.to_string()),
            "output.verbose" => Some(self.config.output.verbose.to_string()),
            "cache.enabled" => Some(self.config.advanced.enable_cache.to_string()),
            "log.level" => Some(self.config.advanced.log_level.clone()),
            _ => None,
        }
    }

    /// 设置配置值
    pub fn set(&mut self, key: &str, value: String) -> anyhow::Result<()> {
        match key {
            "scan.threads" => {
                self.config.scan.threads = value
                    .parse()
                    .context("无效的线程数")?;
            }
            "scan.include_tests" => {
                self.config.scan.include_tests = value
                    .parse()
                    .context("无效的布尔值")?;
            }
            "output.format" => self.config.output.format = value,
            "output.color" => {
                self.config.output.color = value
                    .parse()
                    .context("无效的布尔值")?;
            }
            "output.verbose" => {
                self.config.output.verbose = value
                    .parse()
                    .context("无效的布尔值")?;
            }
            "cache.enabled" => {
                self.config.advanced.enable_cache = value
                    .parse()
                    .context("无效的布尔值")?;
            }
            "log.level" => self.config.advanced.log_level = value,
            _ => anyhow::bail!("未知的配置键: {}", key),
        }
        Ok(())
    }

    /// 删除配置值（恢复默认）
    pub fn remove(&mut self, key: &str) -> anyhow::Result<()> {
        match key {
            "scan.rules_dir" => self.config.scan.rules_dir = None,
            "advanced.cache_dir" => self.config.advanced.cache_dir = None,
            _ => anyhow::bail!("无法重置配置键: {}", key),
        }
        Ok(())
    }
}
