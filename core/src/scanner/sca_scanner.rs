// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! SCA (Software Composition Analysis) 依赖扫描器
//!
//! 解析 package.json / requirements.txt / Cargo.lock / go.sum，
//! 通过 OSV API (osv.dev) 查询已知漏洞依赖。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{Finding, Scanner};

fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

// ── 配置 ──────────────────────────────────────────────

/// SCA 自定义 severity 映射（CVSS V3 分数阈值）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaSeverityMapping {
    /// ≥ 此值 → critical
    #[serde(default = "default_critical_threshold")]
    pub critical: f64,
    /// ≥ 此值 → high
    #[serde(default = "default_high_threshold")]
    pub high: f64,
    /// ≥ 此值 → medium
    #[serde(default = "default_medium_threshold")]
    pub medium: f64,
    // < medium → low
}

fn default_critical_threshold() -> f64 { 9.0 }
fn default_high_threshold() -> f64 { 7.0 }
fn default_medium_threshold() -> f64 { 4.0 }

impl Default for ScaSeverityMapping {
    fn default() -> Self {
        Self { critical: 9.0, high: 7.0, medium: 4.0 }
    }
}

/// SCA 扫描运行时选项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaScanOptions {
    /// 是否启用 SCA 扫描（默认 false）
    #[serde(default)]
    pub enabled: bool,

    /// 忽略的漏洞 ID 列表（如 ["CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx"]）
    #[serde(default)]
    pub ignore_vulns: Vec<String>,

    /// 忽略的包列表（如 ["lodash@4.17.21", "express"]）
    #[serde(default)]
    pub ignore_packages: Vec<String>,

    /// 跳过的生态列表（如 ["Go"]，可选值：npm, PyPI, crates.io, Go）
    #[serde(default)]
    pub ignore_ecosystems: Vec<String>,

    /// 是否包含 devDependencies（默认 true）
    #[serde(default = "default_true")]
    pub dev_dependencies: bool,

    /// 最低报告严重程度（默认 "low"，可选：critical/high/medium/low/info）
    #[serde(default = "default_severity_threshold")]
    pub severity_threshold: String,

    /// 自定义 CVSS → severity 映射阈值
    #[serde(default)]
    pub severity_mapping: ScaSeverityMapping,

    /// 缓存 TTL（小时，默认 24）
    #[serde(default = "default_cache_ttl_hours")]
    pub cache_ttl_hours: u64,

    /// OSV API 请求超时（秒，默认 30）
    #[serde(default = "default_osv_timeout_sec")]
    pub osv_timeout_sec: u64,

    /// 离线/网络失败时是否报错（默认 false，静默跳过）
    #[serde(default)]
    pub fail_offline: bool,
}

fn default_true() -> bool { true }
fn default_severity_threshold() -> String { "low".to_string() }
fn default_cache_ttl_hours() -> u64 { 24 }
fn default_osv_timeout_sec() -> u64 { 30 }

impl Default for ScaScanOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            ignore_vulns: Vec::new(),
            ignore_packages: Vec::new(),
            ignore_ecosystems: Vec::new(),
            dev_dependencies: true,
            severity_threshold: "low".to_string(),
            severity_mapping: ScaSeverityMapping::default(),
            cache_ttl_hours: 24,
            osv_timeout_sec: 30,
            fail_offline: false,
        }
    }
}

// ── 数据结构 ──────────────────────────────────────────────

/// 解析后的依赖项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String, // "npm", "PyPI", "crates.io", "Go"
}

// ── OSV API 请求/响应 ────────────────────────────────────

#[derive(Debug, Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    results: Vec<Option<OsvVulnResult>>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnResult {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

#[derive(Debug, Deserialize)]
struct OsvVulnerability {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    severity: Option<Vec<OsvSeverity>>,
    #[serde(default)]
    aliases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    score_type: String,
    score: String,
}

/// SCA 缓存条目
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedScaResult {
    /// 缓存时间（Unix timestamp）
    cached_at: i64,
    /// 漏洞列表（序列化的 JSON）
    vulns: Vec<CachedVuln>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedVuln {
    id: String,
    summary: String,
    severity: Option<String>,
    aliases: Vec<String>,
}

// ── SCA 扫描器 ──────────────────────────────────────────

/// SCA 依赖扫描器
pub struct ScaScanner {
    client: reqwest::Client,
    options: ScaScanOptions,
}

impl ScaScanner {
    pub fn new() -> Self {
        Self::with_options(ScaScanOptions::default())
    }

    pub fn with_options(options: ScaScanOptions) -> Self {
        let timeout = std::time::Duration::from_secs(options.osv_timeout_sec.max(5));
        Self {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            options,
        }
    }

    /// SCA 缓存文件路径
    fn cache_path() -> PathBuf {
        Path::new(".ctx-audit/cache/sca_cache.json").to_path_buf()
    }

    /// 缓存 TTL（秒）
    fn cache_ttl_secs(&self) -> u64 {
        self.options.cache_ttl_hours * 3600
    }

    /// 加载缓存
    fn load_cache() -> HashMap<String, CachedScaResult> {
        let path = Self::cache_path();
        if !path.exists() {
            return HashMap::new();
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return HashMap::new(),
        };
        serde_json::from_str(&content).unwrap_or_default()
    }

    /// 保存缓存
    fn save_cache(cache: &HashMap<String, CachedScaResult>) {
        let path = Self::cache_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(content) = serde_json::to_string_pretty(cache) {
            let _ = std::fs::write(&path, content);
        }
    }

    /// 生成缓存键
    fn cache_key(dep: &Dependency) -> String {
        format!("{}:{}:{}", dep.ecosystem, dep.name, dep.version)
    }

    /// 清理过期缓存
    fn prune_expired(&self, cache: &mut HashMap<String, CachedScaResult>) {
        let now = chrono::Utc::now().timestamp();
        let ttl = self.cache_ttl_secs() as i64;
        cache.retain(|_, v| now - v.cached_at < ttl);
    }

    /// 解析 package.json
    fn parse_package_json(&self, content: &str, include_dev: bool) -> Vec<Dependency> {
        let mut deps = Vec::new();

        #[derive(Deserialize)]
        struct PackageJson {
            #[serde(default)]
            dependencies: HashMap<String, String>,
            #[serde(default)]
            #[serde(rename = "devDependencies")]
            dev_dependencies: HashMap<String, String>,
        }

        let pkg: PackageJson = match serde_json::from_str(content) {
            Ok(p) => p,
            Err(_) => return deps,
        };

        let mut collect = |map: &HashMap<String, String>| {
            map.iter().for_each(|(name, ver)| {
                let clean_ver = Self::clean_npm_version(ver);
                if !clean_ver.is_empty() {
                    deps.push(Dependency {
                        name: name.clone(),
                        version: clean_ver,
                        ecosystem: "npm".to_string(),
                    });
                }
            });
        };

        collect(&pkg.dependencies);
        if include_dev {
            collect(&pkg.dev_dependencies);
        }
        deps
    }

    /// 解析 requirements.txt
    fn parse_requirements_txt(&self, content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            // 跳过注释、空行、选项行
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }

            // 解析 package==version, package>=version, package~=version 等
            let (name, version) = if let Some(pos) = line.find("==") {
                (&line[..pos], line[pos + 2..].split(',').next().unwrap_or("").to_string())
            } else if let Some(pos) = line.find(">=") {
                (&line[..pos], line[pos + 2..].split(',').next().unwrap_or("").to_string())
            } else if let Some(pos) = line.find("~=") {
                (&line[..pos], line[pos + 2..].split(',').next().unwrap_or("").to_string())
            } else if let Some(pos) = line.find("<=") {
                (&line[..pos], line[pos + 2..].split(',').next().unwrap_or("").to_string())
            } else if let Some(pos) = line.find('>') {
                (&line[..pos], line[pos + 1..].split(',').next().unwrap_or("").to_string())
            } else if let Some(pos) = line.find('<') {
                (&line[..pos], line[pos + 1..].split(',').next().unwrap_or("").to_string())
            } else if let Some(pos) = line.find('!') {
                (&line[..pos], "".to_string())
            } else {
                (line, "".to_string())
            };

            let name = name.trim().to_string();
            if name.is_empty() {
                continue;
            }

            // 只添加有版本号的依赖（版本为空表示无法精确查询）
            if !version.is_empty() {
                deps.push(Dependency {
                    name,
                    version,
                    ecosystem: "PyPI".to_string(),
                });
            }
        }

        deps
    }

    /// 解析 Cargo.lock（TOML 格式）
    fn parse_cargo_lock(&self, content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();

        #[derive(Deserialize)]
        struct CargoLock {
            #[serde(default)]
            package: Vec<CargoPackage>,
        }

        #[derive(Deserialize)]
        struct CargoPackage {
            name: String,
            version: String,
        }

        let lock: CargoLock = match toml::from_str(content) {
            Ok(l) => l,
            Err(_) => return deps,
        };

        for pkg in lock.package {
            deps.push(Dependency {
                name: pkg.name,
                version: pkg.version,
                ecosystem: "crates.io".to_string(),
            });
        }

        deps
    }

    /// 解析 go.sum
    fn parse_go_sum(&self, content: &str) -> Vec<Dependency> {
        let mut deps = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let module = parts[0].to_string();
            // go.sum 中版本格式为 "v1.2.3/go.mod" 或 "v1.2.3 h1:..."
            let version_raw = parts[1];
            let version = if version_raw.starts_with('v') {
                let v = version_raw.trim_start_matches('v');
                // Strip "/go.mod" suffix present in go.sum
                v.split('/').next().unwrap_or(v).to_string()
            } else {
                continue;
            };

            // 去重（go.sum 中同一模块可能出现多次）
            let key = format!("{}:{}", module, version);
            if seen.insert(key) {
                deps.push(Dependency {
                    name: module,
                    version,
                    ecosystem: "Go".to_string(),
                });
            }
        }

        deps
    }

    /// 清理 npm 版本字符串（去除 ^, ~, >= 等前缀）
    fn clean_npm_version(ver: &str) -> String {
        let ver = ver.trim();
        let ver = ver
            .strip_prefix('^')
            .or_else(|| ver.strip_prefix('~'))
            .or_else(|| ver.strip_prefix(">="))
            .or_else(|| ver.strip_prefix("<="))
            .or_else(|| ver.strip_prefix('>'))
            .or_else(|| ver.strip_prefix('<'))
            .unwrap_or(ver);

        // 如果版本中包含 - 或 x（如 "4.x"），取主版本号部分
        let ver = ver.split('-').next().unwrap_or(ver);
        let ver = ver.split(' ').next().unwrap_or(ver);
        ver.to_string()
    }

    /// 批量查询 OSV API
    async fn query_osv(
        &self,
        deps: &[Dependency],
    ) -> Result<Vec<(Dependency, Vec<OsvVulnerability>)>, String> {
        if deps.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();

        // OSV API 每批最多 1000 个查询
        for chunk in deps.chunks(1000) {
            let queries: Vec<OsvQuery> = chunk
                .iter()
                .map(|d| OsvQuery {
                    package: OsvPackage {
                        name: d.name.clone(),
                        ecosystem: d.ecosystem.clone(),
                    },
                    version: d.version.clone(),
                })
                .collect();

            let request = OsvBatchRequest { queries };

            match self
                .client
                .post("https://api.osv.dev/v1/querybatch")
                .json(&request)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        match resp.json::<OsvBatchResponse>().await {
                            Ok(batch_resp) => {
                                for (i, result) in batch_resp.results.into_iter().enumerate() {
                                    if i >= chunk.len() {
                                        break;
                                    }
                                    let vulns = result
                                        .map(|r| r.vulns)
                                        .unwrap_or_default();
                                    if !vulns.is_empty() {
                                        results.push((chunk[i].clone(), vulns));
                                    }
                                }
                            }
                            Err(e) => {
                                let msg = format!("OSV API response parse error: {}", e);
                                if self.options.fail_offline {
                                    return Err(msg);
                                }
                                tracing::warn!("{}", msg);
                            }
                        }
                    } else {
                        let msg = format!("OSV API returned status: {}", resp.status());
                        if self.options.fail_offline {
                            return Err(msg);
                        }
                        tracing::warn!("{}", msg);
                    }
                }
                Err(e) => {
                    let msg = format!("OSV API request failed: {}", e);
                    if self.options.fail_offline {
                        return Err(msg);
                    }
                    tracing::warn!("{}", msg);
                }
            }
        }

        Ok(results)
    }

    /// 将 OSV 漏洞转换为 Finding
    fn vuln_to_finding(
        &self,
        dep: &Dependency,
        vuln: &OsvVulnerability,
        file_path: &str,
    ) -> Finding {
        let mapping = &self.options.severity_mapping;
        let severity = vuln.severity.as_ref()
            .and_then(|s| s.first())
            .map(|s| {
                if s.score_type == "CVSS_V3" {
                    if let Ok(score) = s.score.parse::<f64>() {
                        if score >= mapping.critical { return "critical".to_string(); }
                        if score >= mapping.high { return "high".to_string(); }
                        if score >= mapping.medium { return "medium".to_string(); }
                        return "low".to_string();
                    }
                }
                "high".to_string()
            })
            .unwrap_or_else(|| "high".to_string());

        let aliases = vuln.aliases.join(", ");
        // 当 summary 为空时，用 vuln.id 作为替代描述
        let summary_text = if vuln.summary.is_empty() {
            format!("({})", vuln.id)
        } else {
            vuln.summary.clone()
        };
        let description = format!(
            "Vulnerable dependency: {}@{} — {}",
            dep.name,
            dep.version,
            summary_text,
        );

        let trail = vec![
            format!("Ecosystem: {}", dep.ecosystem),
            format!("Package: {}@{}", dep.name, dep.version),
            format!("Vulnerability: {}", vuln.id),
            if vuln.summary.is_empty() {
                format!("See: https://osv.dev/vulnerability/{}", vuln.id)
            } else {
                format!("Summary: {}", vuln.summary)
            },
        ];

        Finding {
            finding_id: uuid::Uuid::new_v4().to_string(),
            file_path: file_path.to_string(),
            line_start: 1,
            line_end: 1,
            detector: "SCAScanner".to_string(),
            vuln_type: format!("SCA:{}", vuln.id),
            severity,
            description,
            analysis_trail: Some(trail),
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: None,
            sink_snippet: None,
        }
    }
}

#[async_trait]
impl Scanner for ScaScanner {
    fn name(&self) -> String {
        "SCAScanner".to_string()
    }

    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let deps = match filename {
            "package.json" => self.parse_package_json(content, self.options.dev_dependencies),
            "requirements.txt" | "requirements-dev.txt" | "requirements-dev.in" => {
                self.parse_requirements_txt(content)
            }
            "Cargo.lock" => self.parse_cargo_lock(content),
            "go.sum" => self.parse_go_sum(content),
            _ => return Vec::new(),
        };

        // 过滤忽略的生态
        let deps: Vec<Dependency> = deps
            .into_iter()
            .filter(|d| !self.options.ignore_ecosystems.iter().any(|e| e.eq_ignore_ascii_case(&d.ecosystem)))
            .collect();

        // 过滤忽略的包
        let deps: Vec<Dependency> = deps
            .into_iter()
            .filter(|d| {
                let pkg_key = format!("{}@{}", d.name, d.version);
                !self.options.ignore_packages.iter().any(|p| {
                    p.eq_ignore_ascii_case(&d.name) || p.eq_ignore_ascii_case(&pkg_key)
                })
            })
            .collect();

        if deps.is_empty() {
            return Vec::new();
        }

        tracing::info!(
            "SCA: Found {} dependencies in {}",
            deps.len(),
            filename,
        );

        // 加载缓存，分离已缓存和未缓存的依赖
        let mut cache = Self::load_cache();
        self.prune_expired(&mut cache);
        let now = chrono::Utc::now().timestamp();

        let mut cached_results: Vec<(Dependency, Vec<OsvVulnerability>)> = Vec::new();
        let mut uncached_deps: Vec<Dependency> = Vec::new();

        for dep in &deps {
            let key = Self::cache_key(dep);
            if let Some(cached) = cache.get(&key) {
                let vulns: Vec<OsvVulnerability> = cached.vulns.iter().map(|cv| {
                    OsvVulnerability {
                        id: cv.id.clone(),
                        summary: cv.summary.clone(),
                        severity: cv.severity.as_ref().map(|s| {
                            vec![OsvSeverity { score_type: "CVSS_V3".into(), score: s.clone() }]
                        }),
                        aliases: cv.aliases.clone(),
                    }
                }).collect();
                cached_results.push((dep.clone(), vulns));
            } else {
                uncached_deps.push(dep.clone());
            }
        }

        // 查询未缓存的依赖
        let mut new_results = if !uncached_deps.is_empty() {
            tracing::info!("SCA: Querying OSV for {} uncached deps", uncached_deps.len());
            match self.query_osv(&uncached_deps).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("SCA: {}", e);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        // 缓存新结果
        for (dep, vulns) in &new_results {
            let key = Self::cache_key(dep);
            let cached_vulns: Vec<CachedVuln> = vulns.iter().map(|v| {
                let severity = v.severity.as_ref().and_then(|s| s.first()).map(|s| s.score.clone());
                CachedVuln {
                    id: v.id.clone(),
                    summary: v.summary.clone(),
                    severity,
                    aliases: v.aliases.clone(),
                }
            }).collect();
            cache.insert(key, CachedScaResult { cached_at: now, vulns: cached_vulns });
        }

        if !cache.is_empty() {
            Self::save_cache(&cache);
        }

        // 合并结果
        cached_results.append(&mut new_results);

        let threshold_rank = severity_rank(&self.options.severity_threshold);
        let file_path_str = path.to_string_lossy().to_string();
        let findings: Vec<Finding> = cached_results
            .iter()
            .flat_map(|(dep, vulns)| {
                vulns.iter().map(|v| self.vuln_to_finding(dep, v, &file_path_str))
            })
            .filter(|f| {
                // 过滤忽略的漏洞 ID
                if self.options.ignore_vulns.iter().any(|id| f.vuln_type.ends_with(id)) {
                    return false;
                }
                // 过滤低于阈值的严重程度
                severity_rank(&f.severity) >= threshold_rank
            })
            .collect();

        if !findings.is_empty() {
            tracing::info!(
                "SCA: Found {} vulnerabilities in {}",
                findings.len(),
                filename,
            );
        }

        findings
    }
}

/// 判断文件是否是依赖文件
pub fn is_dependency_file(path: &std::path::Path) -> bool {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        matches!(
            name,
            "package.json"
                | "requirements.txt"
                | "requirements-dev.txt"
                | "requirements-dev.in"
                | "Cargo.lock"
                | "go.sum"
        )
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_package_json() {
        let scanner = ScaScanner::new();
        let json = r#"{"dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"}, "devDependencies": {"jest": ">=29.0.0"}}"#;
        let deps = scanner.parse_package_json(json, true);
        assert_eq!(deps.len(), 3);

        // HashMap iteration order is non-deterministic, check by name
        let versions: HashMap<&str, &str> = deps.iter()
            .map(|d| (d.name.as_str(), d.version.as_str()))
            .collect();
        assert_eq!(versions.get("express"), Some(&"4.18.2"));
        assert_eq!(versions.get("lodash"), Some(&"4.17.21"));
        assert_eq!(versions.get("jest"), Some(&"29.0.0"));

        // All should be npm ecosystem
        assert!(deps.iter().all(|d| d.ecosystem == "npm"));
    }

    #[test]
    fn test_parse_requirements_txt() {
        let scanner = ScaScanner::new();
        let txt = "django==4.2\nrequests>=2.28\n# comment\nflask\nnumpy~=1.24\n";
        let deps = scanner.parse_requirements_txt(txt);
        assert_eq!(deps.len(), 3); // django, requests, numpy (flask 没有版本号)
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, "4.2");
        assert_eq!(deps[1].name, "requests");
        assert_eq!(deps[2].name, "numpy");
    }

    #[test]
    fn test_parse_cargo_lock() {
        let scanner = ScaScanner::new();
        let lock = r#"
[[package]]
name = "serde"
version = "1.0.160"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.28.0"
"#;
        let deps = scanner.parse_cargo_lock(lock);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.160");
        assert_eq!(deps[0].ecosystem, "crates.io");
    }

    #[test]
    fn test_parse_go_sum() {
        let scanner = ScaScanner::new();
        let content = "github.com/gin-gonic/gin v1.9.0 h1:abc123\ngithub.com/gin-gonic/gin v1.9.0/go.mod h1:def456\n";
        let deps = scanner.parse_go_sum(content);
        assert_eq!(deps.len(), 1); // 去重后只有 1 个
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, "1.9.0");
    }

    #[test]
    fn test_clean_npm_version() {
        assert_eq!(ScaScanner::clean_npm_version("^4.18.2"), "4.18.2");
        assert_eq!(ScaScanner::clean_npm_version("~4.17.21"), "4.17.21");
        assert_eq!(ScaScanner::clean_npm_version(">=29.0.0"), "29.0.0");
        assert_eq!(ScaScanner::clean_npm_version("1.2.3"), "1.2.3");
    }

    #[tokio::test]
    async fn test_scan_non_dependency_file_returns_empty() {
        let scanner = ScaScanner::new();
        let path = PathBuf::from("src/main.rs");
        let findings = scanner.scan_file(&path, "fn main() {}").await;
        assert!(findings.is_empty());
    }

    #[test]
    fn test_is_dependency_file() {
        assert!(is_dependency_file(std::path::Path::new("package.json")));
        assert!(is_dependency_file(std::path::Path::new("requirements.txt")));
        assert!(is_dependency_file(std::path::Path::new("Cargo.lock")));
        assert!(is_dependency_file(std::path::Path::new("go.sum")));
        assert!(!is_dependency_file(std::path::Path::new("main.rs")));
        assert!(!is_dependency_file(std::path::Path::new("index.js")));
    }
}
