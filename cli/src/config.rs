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
    #[serde(default)]
    pub scan: ScanConfig,

    /// 输出配置
    #[serde(default)]
    pub output: OutputConfig,

    /// 高级配置
    #[serde(default)]
    pub advanced: AdvancedConfig,

    /// SCA 配置
    #[serde(default)]
    pub sca: ScaConfig,

    /// 守护进程配置
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// Agent 配置
    #[serde(default)]
    pub agent: AgentConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            output: OutputConfig::default(),
            advanced: AdvancedConfig::default(),
            sca: ScaConfig::default(),
            daemon: DaemonConfig::default(),
            agent: AgentConfig::default(),
        }
    }
}

// ── 扫描配置 ────────────────────────────────────────────

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

    /// 额外排除的目录（追加到默认列表）
    #[serde(default)]
    pub exclude_extra: Vec<String>,

    /// 单文件最大扫描大小（MB，默认 10）
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,

    /// 扫描内存预算（MB，默认 500）
    #[serde(default = "default_memory_budget_mb")]
    pub memory_budget_mb: usize,

    /// 并行扫描批次大小（默认 100）
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// 去重行容差（默认 3，即 ±3 行内合并）
    #[serde(default = "default_line_tolerance")]
    pub line_tolerance: usize,

    /// 默认严重程度过滤（可选 critical/high/medium/low/info）
    pub severity: Option<String>,

    /// 最低严重程度阈值（默认 medium，过滤 low/info）
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// 代码上下文行数（±N 行，默认 3）
    #[serde(default = "default_context_lines")]
    pub context_lines: usize,

    /// 是否默认启用深度扫描
    #[serde(default)]
    pub deep: bool,

    /// 深度扫描 AST 候选文件上限（默认 5000）
    #[serde(default = "default_taint_max_candidate_files")]
    pub taint_max_candidate_files: usize,

    /// 深度扫描单文件大小上限（KB，默认 500）
    #[serde(default = "default_taint_max_file_kb")]
    pub taint_max_file_kb: usize,

    /// 公开路由白名单（用于抑制公开端点被误报为未认证）
    #[serde(default = "default_public_route_patterns")]
    pub public_route_patterns: Vec<String>,

    /// 非生产代码路径模式（命中时标记 finding 为 non-production）
    #[serde(default = "default_non_production_path_patterns")]
    pub non_production_path_patterns: Vec<String>,
}

fn default_threads() -> usize {
    4
}
fn default_exclude_patterns() -> Vec<String> {
    vec![
        // VCS / 依赖 / 构建产物
        "node_modules",
        ".git",
        "target",
        "build",
        "dist",
        "vendor",
        "__pycache__",
        ".gradle",
        ".idea",
        ".vscode",
        ".cache",
        "bower_components",
        ".next",
        ".nuxt",
        "coverage",
        // 测试 / 示例 / 脚本
        "test",
        "tests",
        "__tests__",
        "spec",
        "fixtures",
        "e2e",
        "examples",
        "example",
        "scripts",
        // 文件模式
        "*.min.js",
        "*.min.css",
        "*.bundle.js",
        "*.chunk.js",
        "*.map",
        ".env.*",
        "*.test.*",
        "*.spec.*",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_max_file_size_mb() -> u64 {
    10
}
fn default_memory_budget_mb() -> usize {
    500
}
fn default_batch_size() -> usize {
    100
}
fn default_line_tolerance() -> usize {
    3
}
fn default_min_severity() -> String {
    "medium".to_string()
}
fn default_context_lines() -> usize {
    3
}
fn default_taint_max_candidate_files() -> usize {
    5000
}
fn default_taint_max_file_kb() -> usize {
    500
}
fn default_public_route_patterns() -> Vec<String> {
    deepaudit_core::analysis::attack_surface::default_public_route_patterns()
}
fn default_non_production_path_patterns() -> Vec<String> {
    deepaudit_core::analysis::attack_surface::default_non_production_path_patterns()
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            rules_dir: None,
            threads: 4,
            include_tests: false,
            exclude_patterns: default_exclude_patterns(),
            exclude_extra: Vec::new(),
            max_file_size_mb: 10,
            memory_budget_mb: 500,
            batch_size: 100,
            line_tolerance: 3,
            severity: None,
            min_severity: "medium".to_string(),
            context_lines: 3,
            deep: false,
            taint_max_candidate_files: 5000,
            taint_max_file_kb: 500,
            public_route_patterns: default_public_route_patterns(),
            non_production_path_patterns: default_non_production_path_patterns(),
        }
    }
}

// ── 输出配置 ────────────────────────────────────────────

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

fn default_format() -> String {
    "llm".to_string()
}
fn default_color() -> bool {
    true
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: "llm".to_string(),
            color: true,
            verbose: false,
        }
    }
}

// ── 高级配置 ────────────────────────────────────────────

/// 高级配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// 是否启用缓存
    #[serde(default = "default_true_val")]
    pub enable_cache: bool,

    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_true_val() -> bool {
    true
}
fn default_log_level() -> String {
    "info".to_string()
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            log_level: "info".to_string(),
        }
    }
}

// ── SCA 配置 ────────────────────────────────────────────

/// SCA（依赖漏洞）配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaConfig {
    /// 是否启用 SCA 扫描（默认 false）
    #[serde(default)]
    pub enabled: bool,

    /// 忽略的漏洞 ID（如 ["CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx"]）
    #[serde(default)]
    pub ignore_vulns: Vec<String>,

    /// 忽略的包（如 ["lodash@4.17.21", "express"]）
    #[serde(default)]
    pub ignore_packages: Vec<String>,

    /// 跳过的生态（如 ["Go"]，可选：npm, PyPI, crates.io, Go）
    #[serde(default)]
    pub ignore_ecosystems: Vec<String>,

    /// 是否包含 devDependencies（默认 true）
    #[serde(default = "default_true_val")]
    pub dev_dependencies: bool,

    /// 最低报告严重程度（默认 "low"）
    #[serde(default = "default_severity_threshold")]
    pub severity_threshold: String,

    /// 自定义 CVSS → severity 映射阈值
    #[serde(default)]
    pub severity_mapping: ScaSeverityMappingConfig,

    /// 缓存 TTL（小时，默认 24）
    #[serde(default = "default_cache_ttl_hours")]
    pub cache_ttl_hours: u64,

    /// OSV API 超时（秒，默认 30）
    #[serde(default = "default_osv_timeout_sec")]
    pub osv_timeout_sec: u64,

    /// 离线/网络失败时是否报错（默认 false，静默跳过）
    #[serde(default)]
    pub fail_offline: bool,
}

fn default_severity_threshold() -> String {
    "low".to_string()
}
fn default_cache_ttl_hours() -> u64 {
    24
}
fn default_osv_timeout_sec() -> u64 {
    30
}

impl Default for ScaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ignore_vulns: Vec::new(),
            ignore_packages: Vec::new(),
            ignore_ecosystems: Vec::new(),
            dev_dependencies: true,
            severity_threshold: "low".to_string(),
            severity_mapping: ScaSeverityMappingConfig::default(),
            cache_ttl_hours: 24,
            osv_timeout_sec: 30,
            fail_offline: false,
        }
    }
}

/// SCA 自定义 severity 映射配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaSeverityMappingConfig {
    /// ≥ 此值 → critical（默认 9.0）
    #[serde(default = "default_critical_threshold")]
    pub critical: f64,
    /// ≥ 此值 → high（默认 7.0）
    #[serde(default = "default_high_threshold")]
    pub high: f64,
    /// ≥ 此值 → medium（默认 4.0）
    pub medium: f64,
}

fn default_critical_threshold() -> f64 {
    9.0
}
fn default_high_threshold() -> f64 {
    7.0
}
fn default_medium_threshold() -> f64 {
    4.0
}

impl Default for ScaSeverityMappingConfig {
    fn default() -> Self {
        Self {
            critical: 9.0,
            high: 7.0,
            medium: 4.0,
        }
    }
}

// ── 守护进程配置 ────────────────────────────────────────

/// 守护进程配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// 监听地址（默认 "127.0.0.1:19527"）
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// 规则热重载间隔（秒，默认 30）
    #[serde(default = "default_rules_reload_secs")]
    pub rules_reload_interval_secs: u64,

    /// AST Engine 空闲超时（秒，默认 3600）
    #[serde(default = "default_ast_idle_secs")]
    pub ast_idle_secs: u64,

    /// AST Engine 最大总内存（MB，默认 512）
    #[serde(default = "default_ast_max_memory_mb")]
    pub ast_max_memory_mb: usize,

    /// Scan Cache 空闲超时（秒，默认 7200）
    #[serde(default = "default_scan_cache_idle_secs")]
    pub scan_cache_idle_secs: u64,

    /// 心跳间隔（秒，默认 5）
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_interval_secs: u64,

    /// 最大重连重试次数（默认 3）
    #[serde(default = "default_reconnect_retries")]
    pub reconnect_max_retries: u32,

    /// 重连基础延迟（毫秒，默认 200）
    #[serde(default = "default_reconnect_base_delay_ms")]
    pub reconnect_base_delay_ms: u64,
}

fn default_listen_addr() -> String {
    "127.0.0.1:19527".to_string()
}
fn default_rules_reload_secs() -> u64 {
    30
}
fn default_ast_idle_secs() -> u64 {
    3600
}
fn default_ast_max_memory_mb() -> usize {
    512
}
fn default_scan_cache_idle_secs() -> u64 {
    7200
}
fn default_heartbeat_secs() -> u64 {
    5
}
fn default_reconnect_retries() -> u32 {
    3
}
fn default_reconnect_base_delay_ms() -> u64 {
    200
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:19527".to_string(),
            rules_reload_interval_secs: 30,
            ast_idle_secs: 3600,
            ast_max_memory_mb: 512,
            scan_cache_idle_secs: 7200,
            heartbeat_interval_secs: 5,
            reconnect_max_retries: 3,
            reconnect_base_delay_ms: 200,
        }
    }
}

// ── Agent 配置 ──────────────────────────────────────────

/// Planner 策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlannerStrategy {
    Auto,
    Rule,
    Llm,
}

impl Default for PlannerStrategy {
    fn default() -> Self {
        PlannerStrategy::Auto
    }
}

/// Planner 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannerConfig {
    /// 策略模式：auto / rule / llm
    #[serde(default)]
    pub strategy: PlannerStrategy,

    /// 最大审计目标数
    #[serde(default = "default_max_goals")]
    pub max_goals: usize,

    /// 每个目标最大探索行动数
    #[serde(default = "default_max_exploration_actions")]
    pub max_exploration_actions: usize,

    /// 是否启用主动重扫描
    #[serde(default)]
    pub enable_proactive_scan: bool,

    /// 是否启用反思/重规划
    #[serde(default = "default_true_val")]
    pub enable_reflection: bool,

    /// 收敛阈值
    #[serde(default = "default_convergence_threshold")]
    pub convergence_threshold: f64,

    /// 公开路由白名单（与 scan 层保持一致）
    #[serde(default = "default_public_route_patterns")]
    pub public_route_patterns: Vec<String>,

    /// 非生产代码路径模式（与 scan 层保持一致）
    #[serde(default = "default_non_production_path_patterns")]
    pub non_production_path_patterns: Vec<String>,
}

fn default_max_goals() -> usize {
    10
}
fn default_max_exploration_actions() -> usize {
    5
}
fn default_convergence_threshold() -> f64 {
    5.0
}

impl Default for PlannerConfig {
    fn default() -> Self {
        Self {
            strategy: PlannerStrategy::Auto,
            max_goals: default_max_goals(),
            max_exploration_actions: default_max_exploration_actions(),
            enable_proactive_scan: false,
            enable_reflection: true,
            convergence_threshold: default_convergence_threshold(),
            public_route_patterns: default_public_route_patterns(),
            non_production_path_patterns: default_non_production_path_patterns(),
        }
    }
}

/// Agent 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// 是否启用 Agent（默认 true）
    #[serde(default = "default_true_val")]
    pub enabled: bool,

    /// 并发 triage 任务数（默认 4）
    #[serde(default = "default_triage_concurrency")]
    pub triage_concurrency: usize,

    /// LLM 模式：noop / http / mcp_relay（默认 noop）
    #[serde(default = "default_llm_mode")]
    pub llm_mode: String,

    /// 复核模式：off / debate / single（默认 off）
    #[serde(default = "default_review_mode")]
    pub review_mode: String,

    /// 最大 LLM 调用次数，0 表示不限制（默认 100）
    /// 作为全局总预算兜底
    #[serde(default = "default_max_llm_calls")]
    pub max_llm_calls: usize,

    /// 按严重度分级的 LLM 调用预算（例如 critical=50, high=30）。
    /// 键为 severity 小写字符串，0 表示该严重度不限制。
    #[serde(default = "default_max_llm_calls_by_severity")]
    pub max_llm_calls_by_severity: std::collections::HashMap<String, usize>,

    /// 是否启用 Specialist Agent（默认 false）
    #[serde(default)]
    pub specialist_enabled: bool,

    /// 是否启用 ReAct 调查器（默认 false）
    #[serde(default)]
    pub investigator_enabled: bool,

    /// 最大调查步数（默认 5）
    #[serde(default = "default_max_investigation_steps")]
    pub max_investigation_steps: usize,

    /// Planner 配置
    #[serde(default)]
    pub planner: PlannerConfig,

    /// LLM 详细配置
    #[serde(default)]
    pub llm: LlmConfig,
}

fn default_triage_concurrency() -> usize {
    4
}
fn default_llm_mode() -> String {
    "noop".to_string()
}
fn default_review_mode() -> String {
    "off".to_string()
}
fn default_max_investigation_steps() -> usize {
    5
}
fn default_max_llm_calls() -> usize {
    100
}
fn default_max_llm_calls_by_severity() -> std::collections::HashMap<String, usize> {
    std::collections::HashMap::new()
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            triage_concurrency: 4,
            llm_mode: "noop".to_string(),
            review_mode: "off".to_string(),
            max_llm_calls: default_max_llm_calls(),
            max_llm_calls_by_severity: default_max_llm_calls_by_severity(),
            specialist_enabled: false,
            investigator_enabled: false,
            max_investigation_steps: 5,
            planner: PlannerConfig::default(),
            llm: LlmConfig::default(),
        }
    }
}

/// LLM 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// 提供商：openai / anthropic / ollama（默认 openai）
    #[serde(default = "default_llm_provider")]
    pub provider: String,

    /// 模型名（默认 gpt-4o-mini）
    #[serde(default = "default_llm_model")]
    pub model: String,

    /// API 密钥
    #[serde(default)]
    pub api_key: String,

    /// 自定义 endpoint（可选）
    pub endpoint: Option<String>,

    /// 超时秒数（默认 60）
    #[serde(default = "default_llm_timeout_sec")]
    pub timeout_sec: u64,

    /// 最大 token 数（默认 2048）
    #[serde(default = "default_llm_max_tokens")]
    pub max_tokens: usize,
}

fn default_llm_provider() -> String {
    "openai".to_string()
}
fn default_llm_model() -> String {
    "gpt-4o-mini".to_string()
}
fn default_llm_timeout_sec() -> u64 {
    60
}
fn default_llm_max_tokens() -> usize {
    2048
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            api_key: String::new(),
            endpoint: None,
            timeout_sec: 60,
            max_tokens: 2048,
        }
    }
}

// ── 配置管理器 ──────────────────────────────────────────

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
            .or_else(|| dirs::config_dir().map(|dir| dir.join("ctx-audit").join("config.toml")))
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
            "toml" => match toml::from_str(&content) {
                Ok(config) => Some(config),
                Err(e) => {
                    tracing::warn!("TOML 解析失败: {:?}", e);
                    None
                }
            },
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

        let content = toml::to_string_pretty(&self.config).context("序列化配置失败")?;

        fs::write(&self.config_path, content)
            .await
            .context("写入配置文件失败")?;

        Ok(())
    }

    /// 获取配置值
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            // scan.*
            "scan.threads" => Some(self.config.scan.threads.to_string()),
            "scan.include_tests" => Some(self.config.scan.include_tests.to_string()),
            "scan.exclude_patterns" => {
                Some(serde_json::to_string(&self.config.scan.exclude_patterns).unwrap_or_default())
            }
            "scan.max_file_size_mb" => Some(self.config.scan.max_file_size_mb.to_string()),
            "scan.memory_budget_mb" => Some(self.config.scan.memory_budget_mb.to_string()),
            "scan.batch_size" => Some(self.config.scan.batch_size.to_string()),
            "scan.line_tolerance" => Some(self.config.scan.line_tolerance.to_string()),
            "scan.severity" => self.config.scan.severity.clone(),
            "scan.min_severity" => Some(self.config.scan.min_severity.clone()),
            "scan.context_lines" => Some(self.config.scan.context_lines.to_string()),
            "scan.exclude_extra" => {
                Some(serde_json::to_string(&self.config.scan.exclude_extra).unwrap_or_default())
            }
            "scan.deep" => Some(self.config.scan.deep.to_string()),
            "scan.taint_max_candidate_files" => {
                Some(self.config.scan.taint_max_candidate_files.to_string())
            }
            "scan.taint_max_file_kb" => Some(self.config.scan.taint_max_file_kb.to_string()),
            // output.*
            "output.format" => Some(self.config.output.format.clone()),
            "output.color" => Some(self.config.output.color.to_string()),
            "output.verbose" => Some(self.config.output.verbose.to_string()),
            // advanced.*
            "cache.enabled" => Some(self.config.advanced.enable_cache.to_string()),
            "log.level" => Some(self.config.advanced.log_level.clone()),
            // sca.*
            "sca.enabled" => Some(self.config.sca.enabled.to_string()),
            "sca.dev_dependencies" => Some(self.config.sca.dev_dependencies.to_string()),
            "sca.severity_threshold" => Some(self.config.sca.severity_threshold.clone()),
            "sca.cache_ttl_hours" => Some(self.config.sca.cache_ttl_hours.to_string()),
            "sca.osv_timeout_sec" => Some(self.config.sca.osv_timeout_sec.to_string()),
            "sca.fail_offline" => Some(self.config.sca.fail_offline.to_string()),
            "sca.ignore_vulns" => {
                Some(serde_json::to_string(&self.config.sca.ignore_vulns).unwrap_or_default())
            }
            "sca.ignore_packages" => {
                Some(serde_json::to_string(&self.config.sca.ignore_packages).unwrap_or_default())
            }
            "sca.ignore_ecosystems" => {
                Some(serde_json::to_string(&self.config.sca.ignore_ecosystems).unwrap_or_default())
            }
            "sca.severity_mapping" => {
                Some(serde_json::to_string(&self.config.sca.severity_mapping).unwrap_or_default())
            }
            // daemon.*
            "daemon.listen_addr" => Some(self.config.daemon.listen_addr.clone()),
            "daemon.rules_reload_interval_secs" => {
                Some(self.config.daemon.rules_reload_interval_secs.to_string())
            }
            "daemon.ast_idle_secs" => Some(self.config.daemon.ast_idle_secs.to_string()),
            "daemon.ast_max_memory_mb" => Some(self.config.daemon.ast_max_memory_mb.to_string()),
            "daemon.scan_cache_idle_secs" => {
                Some(self.config.daemon.scan_cache_idle_secs.to_string())
            }
            "daemon.heartbeat_interval_secs" => {
                Some(self.config.daemon.heartbeat_interval_secs.to_string())
            }
            "daemon.reconnect_max_retries" => {
                Some(self.config.daemon.reconnect_max_retries.to_string())
            }
            "daemon.reconnect_base_delay_ms" => {
                Some(self.config.daemon.reconnect_base_delay_ms.to_string())
            }
            // agent.*
            "agent.enabled" => Some(self.config.agent.enabled.to_string()),
            "agent.triage_concurrency" => Some(self.config.agent.triage_concurrency.to_string()),
            "agent.llm_mode" => Some(self.config.agent.llm_mode.clone()),
            "agent.review_mode" => Some(self.config.agent.review_mode.clone()),
            "agent.max_llm_calls" => Some(self.config.agent.max_llm_calls.to_string()),
            "agent.max_llm_calls_by_severity" => Some(
                serde_json::to_string(&self.config.agent.max_llm_calls_by_severity)
                    .unwrap_or_default(),
            ),
            "agent.specialist_enabled" => Some(self.config.agent.specialist_enabled.to_string()),
            "agent.investigator_enabled" => {
                Some(self.config.agent.investigator_enabled.to_string())
            }
            "agent.max_investigation_steps" => {
                Some(self.config.agent.max_investigation_steps.to_string())
            }
            "agent.planner.strategy" => {
                Some(format!("{:?}", self.config.agent.planner.strategy).to_lowercase())
            }
            "agent.planner.max_goals" => Some(self.config.agent.planner.max_goals.to_string()),
            "agent.planner.max_exploration_actions" => Some(
                self.config
                    .agent
                    .planner
                    .max_exploration_actions
                    .to_string(),
            ),
            "agent.planner.enable_proactive_scan" => {
                Some(self.config.agent.planner.enable_proactive_scan.to_string())
            }
            "agent.planner.enable_reflection" => {
                Some(self.config.agent.planner.enable_reflection.to_string())
            }
            "agent.planner.convergence_threshold" => {
                Some(self.config.agent.planner.convergence_threshold.to_string())
            }
            "agent.llm.provider" => Some(self.config.agent.llm.provider.clone()),
            "agent.llm.model" => Some(self.config.agent.llm.model.clone()),
            "agent.llm.api_key" => Some(self.config.agent.llm.api_key.clone()),
            "agent.llm.endpoint" => self.config.agent.llm.endpoint.clone(),
            "agent.llm.timeout_sec" => Some(self.config.agent.llm.timeout_sec.to_string()),
            "agent.llm.max_tokens" => Some(self.config.agent.llm.max_tokens.to_string()),
            _ => None,
        }
    }

    /// 设置配置值
    pub fn set(&mut self, key: &str, value: String) -> anyhow::Result<()> {
        match key {
            // scan.*
            "scan.threads" => {
                self.config.scan.threads = value.parse().context("无效的线程数")?;
            }
            "scan.include_tests" => {
                self.config.scan.include_tests = value.parse().context("无效的布尔值")?;
            }
            "scan.exclude_patterns" => {
                self.config.scan.exclude_patterns = serde_json::from_str(&value)
                    .context("无效的 JSON 数组，如 [\"node_modules\",\".git\"]")?;
            }
            "scan.max_file_size_mb" => {
                self.config.scan.max_file_size_mb = value.parse().context("无效的 MB 数")?;
            }
            "scan.memory_budget_mb" => {
                self.config.scan.memory_budget_mb = value.parse().context("无效的 MB 数")?;
            }
            "scan.batch_size" => {
                self.config.scan.batch_size = value.parse().context("无效的批次大小")?;
            }
            "scan.line_tolerance" => {
                self.config.scan.line_tolerance = value.parse().context("无效的行容差")?;
            }
            "scan.severity" => {
                let valid = ["critical", "high", "medium", "low", "info"];
                if !value.is_empty() && !valid.contains(&value.as_str()) {
                    anyhow::bail!("无效的严重程度，可选: {}", valid.join(", "));
                }
                self.config.scan.severity = if value.is_empty() { None } else { Some(value) };
            }
            "scan.deep" => {
                self.config.scan.deep = value.parse().context("无效的布尔值")?;
            }
            "scan.taint_max_candidate_files" => {
                self.config.scan.taint_max_candidate_files =
                    value.parse().context("无效的候选文件数")?;
            }
            "scan.taint_max_file_kb" => {
                self.config.scan.taint_max_file_kb = value.parse().context("无效的文件大小上限")?;
            }
            "scan.min_severity" => {
                let valid = ["critical", "high", "medium", "low"];
                if !valid.contains(&value.as_str()) {
                    anyhow::bail!("无效的最低严重程度，可选: {}", valid.join(", "));
                }
                self.config.scan.min_severity = value;
            }
            "scan.context_lines" => {
                self.config.scan.context_lines = value.parse().context("无效的上下文行数")?;
            }
            "scan.exclude_extra" => {
                self.config.scan.exclude_extra = serde_json::from_str(&value)
                    .context("无效的 JSON 数组，如 [\"scripts\",\"bench\"]")?;
            }
            // output.*
            "output.format" => self.config.output.format = value,
            "output.color" => {
                self.config.output.color = value.parse().context("无效的布尔值")?;
            }
            "output.verbose" => {
                self.config.output.verbose = value.parse().context("无效的布尔值")?;
            }
            // advanced.*
            "cache.enabled" => {
                self.config.advanced.enable_cache = value.parse().context("无效的布尔值")?;
            }
            "log.level" => self.config.advanced.log_level = value,
            // sca.*
            "sca.enabled" => {
                self.config.sca.enabled = value.parse().context("无效的布尔值 (true/false)")?;
            }
            "sca.dev_dependencies" => {
                self.config.sca.dev_dependencies =
                    value.parse().context("无效的布尔值 (true/false)")?;
            }
            "sca.severity_threshold" => {
                let valid = ["critical", "high", "medium", "low", "info"];
                if !valid.contains(&value.as_str()) {
                    anyhow::bail!("无效的严重程度阈值，可选: {}", valid.join(", "));
                }
                self.config.sca.severity_threshold = value;
            }
            "sca.cache_ttl_hours" => {
                self.config.sca.cache_ttl_hours = value.parse().context("无效的小时数")?;
            }
            "sca.osv_timeout_sec" => {
                self.config.sca.osv_timeout_sec = value.parse().context("无效的秒数")?;
            }
            "sca.fail_offline" => {
                self.config.sca.fail_offline =
                    value.parse().context("无效的布尔值 (true/false)")?;
            }
            "sca.ignore_vulns" => {
                self.config.sca.ignore_vulns = serde_json::from_str(&value)
                    .context("无效的 JSON 数组，如 [\"CVE-2024-1234\"]")?;
            }
            "sca.ignore_packages" => {
                self.config.sca.ignore_packages = serde_json::from_str(&value)
                    .context("无效的 JSON 数组，如 [\"lodash@4.17.21\"]")?;
            }
            "sca.ignore_ecosystems" => {
                self.config.sca.ignore_ecosystems =
                    serde_json::from_str(&value).context("无效的 JSON 数组，如 [\"Go\"]")?;
            }
            "sca.severity_mapping" => {
                self.config.sca.severity_mapping = serde_json::from_str(&value)
                    .context("无效的 JSON，如 {\"critical\":9.0,\"high\":7.0,\"medium\":4.0}")?;
            }
            // daemon.*
            "daemon.listen_addr" => self.config.daemon.listen_addr = value,
            "daemon.rules_reload_interval_secs" => {
                self.config.daemon.rules_reload_interval_secs =
                    value.parse().context("无效的秒数")?;
            }
            "daemon.ast_idle_secs" => {
                self.config.daemon.ast_idle_secs = value.parse().context("无效的秒数")?;
            }
            "daemon.ast_max_memory_mb" => {
                self.config.daemon.ast_max_memory_mb = value.parse().context("无效的 MB 数")?;
            }
            "daemon.scan_cache_idle_secs" => {
                self.config.daemon.scan_cache_idle_secs = value.parse().context("无效的秒数")?;
            }
            "daemon.heartbeat_interval_secs" => {
                self.config.daemon.heartbeat_interval_secs = value.parse().context("无效的秒数")?;
            }
            "daemon.reconnect_max_retries" => {
                self.config.daemon.reconnect_max_retries =
                    value.parse().context("无效的重试次数")?;
            }
            "daemon.reconnect_base_delay_ms" => {
                self.config.daemon.reconnect_base_delay_ms =
                    value.parse().context("无效的毫秒数")?;
            }
            // agent.*
            "agent.enabled" => {
                self.config.agent.enabled = value.parse().context("无效的布尔值")?;
            }
            "agent.triage_concurrency" => {
                self.config.agent.triage_concurrency = value.parse().context("无效的并发数")?;
            }
            "agent.llm_mode" => {
                let valid = ["noop", "http", "mcp_relay"];
                if !valid.contains(&value.as_str()) {
                    anyhow::bail!("无效的 LLM 模式，可选: {}", valid.join(", "));
                }
                self.config.agent.llm_mode = value;
            }
            "agent.review_mode" => {
                let valid = ["off", "debate", "single"];
                if !valid.contains(&value.as_str()) {
                    anyhow::bail!("无效的复核模式，可选: {}", valid.join(", "));
                }
                self.config.agent.review_mode = value;
            }
            "agent.max_llm_calls" => {
                self.config.agent.max_llm_calls = value.parse().context("无效的数字")?;
            }
            "agent.max_llm_calls_by_severity" => {
                self.config.agent.max_llm_calls_by_severity = serde_json::from_str(&value)
                    .context("无效的 JSON 对象，示例: {\"critical\":50,\"high\":30}")?;
            }
            "agent.specialist_enabled" => {
                self.config.agent.specialist_enabled = value.parse().context("无效的布尔值")?;
            }
            "agent.investigator_enabled" => {
                self.config.agent.investigator_enabled = value.parse().context("无效的布尔值")?;
            }
            "agent.max_investigation_steps" => {
                self.config.agent.max_investigation_steps = value.parse().context("无效的数字")?;
            }
            "agent.planner.strategy" => {
                let valid = ["auto", "rule", "llm"];
                if !valid.contains(&value.as_str()) {
                    anyhow::bail!("无效的策略模式，可选: {}", valid.join(", "));
                }
                self.config.agent.planner.strategy = match value.as_str() {
                    "rule" => PlannerStrategy::Rule,
                    "llm" => PlannerStrategy::Llm,
                    _ => PlannerStrategy::Auto,
                };
            }
            "agent.planner.max_goals" => {
                self.config.agent.planner.max_goals = value.parse().context("无效的数字")?;
            }
            "agent.planner.max_exploration_actions" => {
                self.config.agent.planner.max_exploration_actions =
                    value.parse().context("无效的数字")?;
            }
            "agent.planner.enable_proactive_scan" => {
                self.config.agent.planner.enable_proactive_scan =
                    value.parse().context("无效的布尔值")?;
            }
            "agent.planner.enable_reflection" => {
                self.config.agent.planner.enable_reflection =
                    value.parse().context("无效的布尔值")?;
            }
            "agent.planner.convergence_threshold" => {
                self.config.agent.planner.convergence_threshold =
                    value.parse().context("无效的数字")?;
            }
            "agent.llm.provider" => self.config.agent.llm.provider = value,
            "agent.llm.model" => self.config.agent.llm.model = value,
            "agent.llm.api_key" => self.config.agent.llm.api_key = value,
            "agent.llm.endpoint" => {
                self.config.agent.llm.endpoint = if value.is_empty() { None } else { Some(value) };
            }
            "agent.llm.timeout_sec" => {
                self.config.agent.llm.timeout_sec = value.parse().context("无效的秒数")?;
            }
            "agent.llm.max_tokens" => {
                self.config.agent.llm.max_tokens = value.parse().context("无效的数字")?;
            }
            _ => anyhow::bail!("未知的配置键: {}", key),
        }
        Ok(())
    }

    /// 删除配置值（恢复默认）
    pub fn remove(&mut self, key: &str) -> anyhow::Result<()> {
        match key {
            // scan.*
            "scan.rules_dir" => self.config.scan.rules_dir = None,
            "scan.severity" => self.config.scan.severity = None,
            "scan.max_file_size_mb" => self.config.scan.max_file_size_mb = 10,
            "scan.memory_budget_mb" => self.config.scan.memory_budget_mb = 500,
            "scan.batch_size" => self.config.scan.batch_size = 100,
            "scan.line_tolerance" => self.config.scan.line_tolerance = 3,
            "scan.threads" => self.config.scan.threads = 4,
            "scan.include_tests" => self.config.scan.include_tests = false,
            "scan.deep" => self.config.scan.deep = false,
            // advanced.*
            "cache.enabled" => self.config.advanced.enable_cache = true,
            "log.level" => self.config.advanced.log_level = "info".to_string(),
            // sca.*
            "sca.enabled" => self.config.sca.enabled = false,
            "sca.dev_dependencies" => self.config.sca.dev_dependencies = true,
            "sca.severity_threshold" => self.config.sca.severity_threshold = "low".to_string(),
            "sca.cache_ttl_hours" => self.config.sca.cache_ttl_hours = 24,
            "sca.osv_timeout_sec" => self.config.sca.osv_timeout_sec = 30,
            "sca.fail_offline" => self.config.sca.fail_offline = false,
            "sca.ignore_vulns" => self.config.sca.ignore_vulns.clear(),
            "sca.ignore_packages" => self.config.sca.ignore_packages.clear(),
            "sca.ignore_ecosystems" => self.config.sca.ignore_ecosystems.clear(),
            "sca.severity_mapping" => {
                self.config.sca.severity_mapping = ScaSeverityMappingConfig::default()
            }
            // daemon.*
            "daemon.listen_addr" => self.config.daemon.listen_addr = "127.0.0.1:19527".to_string(),
            "daemon.rules_reload_interval_secs" => {
                self.config.daemon.rules_reload_interval_secs = 30
            }
            "daemon.ast_idle_secs" => self.config.daemon.ast_idle_secs = 3600,
            "daemon.ast_max_memory_mb" => self.config.daemon.ast_max_memory_mb = 512,
            "daemon.scan_cache_idle_secs" => self.config.daemon.scan_cache_idle_secs = 7200,
            "daemon.heartbeat_interval_secs" => self.config.daemon.heartbeat_interval_secs = 5,
            "daemon.reconnect_max_retries" => self.config.daemon.reconnect_max_retries = 3,
            "daemon.reconnect_base_delay_ms" => self.config.daemon.reconnect_base_delay_ms = 200,
            // agent.*
            "agent.enabled" => self.config.agent.enabled = true,
            "agent.triage_concurrency" => self.config.agent.triage_concurrency = 4,
            "agent.llm_mode" => self.config.agent.llm_mode = "noop".to_string(),
            "agent.review_mode" => self.config.agent.review_mode = "off".to_string(),
            "agent.max_llm_calls" => self.config.agent.max_llm_calls = 100,
            "agent.specialist_enabled" => self.config.agent.specialist_enabled = false,
            "agent.investigator_enabled" => self.config.agent.investigator_enabled = false,
            "agent.max_investigation_steps" => self.config.agent.max_investigation_steps = 5,
            "agent.planner.strategy" => self.config.agent.planner.strategy = PlannerStrategy::Auto,
            "agent.planner.max_goals" => self.config.agent.planner.max_goals = 10,
            "agent.planner.max_exploration_actions" => {
                self.config.agent.planner.max_exploration_actions = 5
            }
            "agent.planner.enable_proactive_scan" => {
                self.config.agent.planner.enable_proactive_scan = false
            }
            "agent.planner.enable_reflection" => self.config.agent.planner.enable_reflection = true,
            "agent.planner.convergence_threshold" => {
                self.config.agent.planner.convergence_threshold = 5.0
            }
            "agent.llm.provider" => self.config.agent.llm.provider = "openai".to_string(),
            "agent.llm.model" => self.config.agent.llm.model = "gpt-4o-mini".to_string(),
            "agent.llm.api_key" => self.config.agent.llm.api_key.clear(),
            "agent.llm.endpoint" => self.config.agent.llm.endpoint = None,
            "agent.llm.timeout_sec" => self.config.agent.llm.timeout_sec = 60,
            "agent.llm.max_tokens" => self.config.agent.llm.max_tokens = 2048,
            _ => anyhow::bail!("无法重置配置键: {}", key),
        }
        Ok(())
    }
}
