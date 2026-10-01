// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 分析引擎协调
//!
//! 绑定 core 的各项分析能力，提供统一的分析接口。
//! 核心特性：基于 content hash 的增量扫描缓存。

macro_rules! json {
    ($($tt:tt)*) => {
        serde_json::json!($($tt)*)
    };
}

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::sync::RwLock;

use deepaudit_core::ast_api::{ASTEngine, ASTParser, QueryEngine, Symbol};
use deepaudit_core::scanning::{
    scan_directory_deep_with_rules, scan_directory_deep_with_rules_progress,
    scan_directory_with_rules, Finding, ScanResult,
};
use deepaudit_core::taint::{AstTaintAnalyzer, CrossFileTaintAnalyzer, TaintFlow};
use deepaudit_core::watcher::{DeltaResult, FileSnapshot};

// ────────────────────────────────────────────────────────
// 文件级 findings 缓存
// ────────────────────────────────────────────────────────

/// 单个文件的缓存 findings
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FileFindings {
    /// 文件相对路径
    relative_path: String,
    /// 该文件的 findings
    findings: Vec<Finding>,
    /// 缓存时的 content hash
    content_hash: u64,
}

/// 项目扫描缓存
struct ProjectScanCache {
    /// file_relative_path → FileFindings
    entries: HashMap<String, FileFindings>,
    /// FileSnapshot 用于变更检测
    snapshot: FileSnapshot,
    /// 上次全量扫描的 findings 总数
    total_findings: usize,
    /// 最近一次扫描的遥测（把"冷启动/局部重编译/缓存命中"变成可观测事实）
    last_scan: Option<ScanTelemetry>,
    /// 最近一次扫描使用的分析选项 `(enable_taint, enable_cross_file)`。
    /// 选项变化必须整表重建，否则会把浅扫结果当深扫结果复用。
    last_options: Option<(bool, bool)>,
}

/// 最近一次扫描的遥测。
#[derive(Debug, Clone)]
struct ScanTelemetry {
    /// 本次扫描耗时
    duration_ms: u64,
    /// 本次实际重扫的文件数
    files_scanned: usize,
    /// 走缓存未重扫的文件数（= 该文件此前有 findings 记录）
    files_cached: usize,
    /// 快照里的文件总数（本项目实际被跟踪的文件数）
    snapshot_files: usize,
    /// 是否走了增量路径
    was_incremental: bool,
    /// 变更文件数（无变更命中时为 0）
    changed_files: usize,
    /// 记录时刻（用于换算"多久之前"）
    at: std::time::Instant,
}

// ────────────────────────────────────────────────────────
// 带时间戳的包装（用于 LRU 淘汰）
// ────────────────────────────────────────────────────────

/// AST Engine 带访问时间戳和内存估算
struct TimestampedEngine {
    engine: Arc<ASTEngine>,
    last_accessed: std::sync::Mutex<std::time::Instant>,
    estimated_bytes: usize,
}

/// Scan Cache 带访问时间戳
struct TimestampedScanCache {
    cache: RwLock<ProjectScanCache>,
    last_accessed: std::sync::Mutex<std::time::Instant>,
}

/// 内存统计
pub struct MemoryStats {
    pub ast_count: usize,
    pub ast_bytes: usize,
    pub scan_count: usize,
}

// ────────────────────────────────────────────────────────
// 分析引擎
// ────────────────────────────────────────────────────────

pub struct AnalysisEngine {
    /// AST 索引引擎: project_path → TimestampedEngine
    ast_engines: RwLock<HashMap<String, TimestampedEngine>>,
    /// 扫描缓存: project_path → TimestampedScanCache
    scan_caches: RwLock<HashMap<String, TimestampedScanCache>>,
    /// 规则加载时间戳：rules_dir → (load_time, rule_count)
    rules_cache: RwLock<HashMap<String, (std::time::Instant, usize)>>,
    /// 可配置参数
    rules_reload_interval_secs: u64,
    ast_idle_secs: u64,
    ast_max_memory_bytes: usize,
    scan_cache_idle_secs: u64,
}

/// 增量扫描输出
pub struct ScanOutput {
    pub findings: Vec<Finding>,
    pub duration_ms: u64,
    pub files_scanned: usize,
    pub files_cached: usize,
    pub was_incremental: bool,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        let (rules_reload, ast_idle, ast_max_mem, scan_cache_idle) =
            if let Some(dirs) = dirs::config_dir() {
                let config_path = dirs.join("ctx-audit").join("config.toml");
                if let Ok(content) = std::fs::read_to_string(&config_path) {
                    if let Ok(val) = toml::from_str::<toml::Value>(&content) {
                        let daemon = val.get("daemon");
                        (
                            daemon
                                .and_then(|d| d.get("rules_reload_interval_secs"))
                                .and_then(|v| v.as_integer())
                                .unwrap_or(30) as u64,
                            daemon
                                .and_then(|d| d.get("ast_idle_secs"))
                                .and_then(|v| v.as_integer())
                                .unwrap_or(3600) as u64,
                            daemon
                                .and_then(|d| d.get("ast_max_memory_mb"))
                                .and_then(|v| v.as_integer())
                                .unwrap_or(512) as usize
                                * 1024
                                * 1024,
                            daemon
                                .and_then(|d| d.get("scan_cache_idle_secs"))
                                .and_then(|v| v.as_integer())
                                .unwrap_or(7200) as u64,
                        )
                    } else {
                        (30, 3600, 512 * 1024 * 1024, 7200)
                    }
                } else {
                    (30, 3600, 512 * 1024 * 1024, 7200)
                }
            } else {
                (30, 3600, 512 * 1024 * 1024, 7200)
            };

        Self {
            ast_engines: RwLock::new(HashMap::new()),
            scan_caches: RwLock::new(HashMap::new()),
            rules_cache: RwLock::new(HashMap::new()),
            rules_reload_interval_secs: rules_reload,
            ast_idle_secs: ast_idle,
            ast_max_memory_bytes: ast_max_mem,
            scan_cache_idle_secs: scan_cache_idle,
        }
    }

    // ── 增量扫描 ─────────────────────────────────────

    /// 扫描项目（自动增量）
    ///
    /// 首次调用：全量扫描，缓存结果。
    /// 后续调用：检测变更文件，只重新扫描变更部分，合并缓存。
    pub async fn scan(
        &self,
        path: &str,
        enable_taint: bool,
        enable_cross_file: bool,
    ) -> Result<ScanOutput> {
        let start = Instant::now();
        let project_path = Path::new(path);

        // 确保有缓存槽
        {
            let caches = self.scan_caches.read().await;
            if !caches.contains_key(path) {
                drop(caches);
                let mut caches = self.scan_caches.write().await;
                caches.entry(path.to_string()).or_insert_with(|| {
                    let ignore = vec![
                        "node_modules".into(),
                        ".git".into(),
                        "target".into(),
                        "build".into(),
                        "dist".into(),
                        "__pycache__".into(),
                        "vendor".into(),
                        ".next".into(),
                    ];
                    TimestampedScanCache {
                        cache: RwLock::new(ProjectScanCache {
                            entries: HashMap::new(),
                            snapshot: FileSnapshot::new(project_path, ignore),
                            total_findings: 0,
                            last_scan: None,
                            last_options: None,
                        }),
                        last_accessed: std::sync::Mutex::new(std::time::Instant::now()),
                    }
                });
            }
        }

        let caches = self.scan_caches.read().await;
        let ts_cache = match caches.get(path) {
            Some(c) => c,
            None => anyhow::bail!("扫描缓存初始化失败"),
        };
        if let Ok(mut t) = ts_cache.last_accessed.lock() {
            *t = std::time::Instant::now();
        }
        let mut cache = ts_cache.cache.write().await;

        // 检测变更
        let delta = cache
            .snapshot
            .detect_changes()
            .map_err(|e| anyhow::anyhow!("变更检测失败: {}", e))?;

        // 分析选项（污点/跨文件）变化时，缓存里已有的结果不可复用
        let options = (enable_taint, enable_cross_file);
        let options_changed = cache.last_options.is_some() && cache.last_options != Some(options);

        if !delta.has_changes() && cache.last_scan.is_some() && !options_changed {
            // 无变更且此前扫过（`entries` 是 **findings** 缓存，零 findings 项目会一直为空，
            // 所以不能用它当"扫过了"的判据）→ 直接返回缓存
            let all_findings: Vec<Finding> = cache
                .entries
                .values()
                .flat_map(|e| e.findings.clone())
                .collect();
            let duration = start.elapsed().as_millis() as u64;
            cache.last_scan = Some(ScanTelemetry {
                duration_ms: duration,
                files_scanned: 0,
                files_cached: cache.entries.len(),
                snapshot_files: cache.snapshot.file_count(),
                was_incremental: true,
                changed_files: 0,
                at: std::time::Instant::now(),
            });

            return Ok(ScanOutput {
                findings: all_findings,
                duration_ms: duration,
                files_scanned: 0,
                files_cached: cache.entries.len(),
                was_incremental: true,
            });
        }

        // 有变更：确定需要重新扫描的文件
        let changed_set: std::collections::HashSet<PathBuf> = delta
            .changed_files
            .iter()
            .chain(delta.added_files.iter())
            .cloned()
            .collect();

        // 移除已删除文件的缓存
        for deleted in &delta.deleted_files {
            let rel = path_relative_to(project_path, deleted);
            cache.entries.remove(&rel);
        }

        // 整表重建的三种情形：
        //  1. 从未扫过（`last_scan` 为空）；
        //  2. 分析选项变化——浅扫结果不能当深扫用，反之亦然；
        //  3. 启用污点 / 跨文件——这两层是项目级分析（跨文件图、全项目污点传播），
        //     无法按文件局部重算，必须整表重建。
        // 其余情形走增量路径：只重扫变更文件，且与全量结果按构造一致
        // （`scan_files` 复用 core 的同一条扫描管线）。
        if cache.last_scan.is_none() || options_changed || enable_taint || enable_cross_file {
            drop(cache);
            drop(caches);
            return self
                .full_scan(path, enable_taint, enable_cross_file, start)
                .await;
        }

        // 增量：只扫描变更文件
        tracing::info!(
            "[增量扫描] 变更: {} 个文件 (新增: {}, 修改: {}, 删除: {})",
            delta.total_changes(),
            delta.added_files.len(),
            delta.changed_files.len(),
            delta.deleted_files.len()
        );

        let (new_findings, file_hashes) = self.scan_files(path, &changed_set).await?;

        // 更新缓存：移除变更文件的旧 findings，加入新的
        for file_path in &changed_set {
            let rel = path_relative_to(project_path, file_path);
            cache.entries.remove(&rel);
        }

        // 按文件分组新 findings。
        // 键必须是**相对路径**（与缓存条目键一致）：finding.file_path 是绝对路径，
        // 直接拿它当键会让下面的 `by_file.get(&rel)` 永远查不中，
        // 结果是把变更文件的条目替换成"空 findings"——静默清空该文件的结论。
        let mut by_file: HashMap<String, Vec<Finding>> = HashMap::with_capacity(changed_set.len());
        for f in &new_findings {
            let rel = path_relative_to(project_path, Path::new(&f.file_path));
            by_file.entry(rel).or_default().push(f.clone());
        }

        // 计算变更文件的 content hash 并缓存（优先使用 scan_files 中已计算的 hash）
        for file_path in &changed_set {
            let rel = path_relative_to(project_path, file_path);
            let full = project_path.join(&rel);
            let full_str = full.to_string_lossy().to_string();
            let hash = file_hashes
                .get(&full_str)
                .copied()
                .unwrap_or_else(|| hash_file_content(&full));
            let findings = by_file.get(&rel).cloned().unwrap_or_default();
            cache.entries.insert(
                rel.clone(),
                FileFindings {
                    relative_path: rel,
                    findings,
                    content_hash: hash,
                },
            );
        }

        // 合并所有 findings
        let all_findings: Vec<Finding> = cache
            .entries
            .values()
            .flat_map(|e| e.findings.clone())
            .collect();

        cache.total_findings = all_findings.len();

        // 更新 snapshot baseline
        let _ = cache.snapshot.build_baseline();

        let duration = start.elapsed().as_millis() as u64;
        let files_cached = cache.entries.len().saturating_sub(changed_set.len());
        cache.last_scan = Some(ScanTelemetry {
            duration_ms: duration,
            files_scanned: changed_set.len(),
            files_cached,
            snapshot_files: cache.snapshot.file_count(),
            was_incremental: true,
            changed_files: changed_set.len(),
            at: std::time::Instant::now(),
        });
        cache.last_options = Some(options);
        Ok(ScanOutput {
            findings: all_findings,
            duration_ms: duration,
            files_scanned: changed_set.len(),
            files_cached,
            was_incremental: true,
        })
    }

    /// 全量扫描（首次或强制）
    async fn full_scan(
        &self,
        path: &str,
        enable_taint: bool,
        enable_cross_file: bool,
        start: Instant,
    ) -> Result<ScanOutput> {
        // 检测规则目录（项目级 > 内置）
        let rules_dir = Self::resolve_rules_dir(path);

        self.log_rules_status(path, rules_dir.as_deref()).await;

        let scan_result = if enable_taint || enable_cross_file {
            let mut opts = deepaudit_core::scanning::ScanOptions::default();
            opts.enable_taint = enable_taint;
            opts.enable_cross_file = enable_cross_file;
            scan_directory_deep_with_rules_progress(
                path,
                rules_dir.as_deref(),
                None,
                None,
                Some(opts),
                None,
            )
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?
        } else {
            ScanResult {
                findings: scan_directory_with_rules(path, rules_dir.as_deref(), None, None)
                    .await
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                attack_surface: Default::default(),
                cross_file_result: None,
                project_profile: Default::default(),
                encoding_fallback_files: Vec::new(),
            }
        };
        let findings = scan_result.findings;

        let project_path = Path::new(path);
        let total = findings.len();

        // 按 file_path 分组缓存
        let duration = start.elapsed().as_millis() as u64;
        let caches = self.scan_caches.read().await;
        if let Some(ts_cache) = caches.get(path) {
            if let Ok(mut t) = ts_cache.last_accessed.lock() {
                *t = std::time::Instant::now();
            }
            let mut cache = ts_cache.cache.write().await;

            let mut by_file: HashMap<String, Vec<Finding>> = HashMap::with_capacity(findings.len());
            for f in &findings {
                let rel = path_relative_to(project_path, Path::new(&f.file_path));
                by_file.entry(rel.clone()).or_default().push(f.clone());
            }

            cache.entries.clear();
            for (rel, file_findings) in by_file {
                let full = project_path.join(&rel);
                let hash = hash_file_content(&full);
                cache.entries.insert(
                    rel.clone(),
                    FileFindings {
                        relative_path: rel,
                        findings: file_findings,
                        content_hash: hash,
                    },
                );
            }

            cache.total_findings = total;
            let _ = cache.snapshot.build_baseline();
            cache.last_scan = Some(ScanTelemetry {
                duration_ms: duration,
                files_scanned: cache.entries.len(),
                files_cached: 0,
                snapshot_files: cache.snapshot.file_count(),
                was_incremental: false,
                changed_files: cache.entries.len(),
                at: std::time::Instant::now(),
            });
            cache.last_options = Some((enable_taint, enable_cross_file));
        }

        Ok(ScanOutput {
            findings,
            duration_ms: duration,
            files_scanned: cache_entries_count(&self.scan_caches, path).await,
            files_cached: 0,
            was_incremental: false,
        })
    }

    /// 只重扫给定文件集合（快速层：规则 + 攻击面），同时返回 content hash。
    ///
    /// 走的是 core 的**同一条扫描管线**（`scan_files_with_rules`），因此"局部重扫 N 个文件"
    /// 与"整目录扫描后取这 N 个文件的结果"逐条一致——这是增量结果可信的前提。
    /// 不含污点/跨文件层（项目级分析）：调用方 `scan()` 在启用它们时改为整表重建。
    async fn scan_files(
        &self,
        project_path: &str,
        files: &std::collections::HashSet<PathBuf>,
    ) -> Result<(Vec<Finding>, HashMap<String, u64>)> {
        if files.is_empty() {
            return Ok((vec![], HashMap::new()));
        }

        // 确定性：与目录扫描一致先排序（枚举顺序会影响并行切分与合并顺序）
        let mut ordered: Vec<PathBuf> = files.iter().cloned().collect();
        ordered.sort();

        let rules_dir = Self::resolve_rules_dir(project_path);
        let findings = deepaudit_core::scanning::scan_files_with_rules(
            project_path,
            &ordered,
            rules_dir.as_deref(),
            None,
        )
        .await
        .map_err(|e| anyhow::anyhow!("局部重扫失败: {}", e))?;

        // content hash：调用方据此更新 per-file 缓存
        let mut file_hashes: HashMap<String, u64> = HashMap::with_capacity(ordered.len());
        for path in &ordered {
            file_hashes.insert(path.to_string_lossy().to_string(), hash_file_content(path));
        }

        Ok((findings, file_hashes))
    }

    // ── 污点追踪 ──────────────────────────────────────

    pub fn trace_taint(&self, file_path: &str) -> Result<Vec<TaintFlow>> {
        let path = Path::new(file_path);
        let code = std::fs::read_to_string(path)?;
        let mut analyzer = AstTaintAnalyzer::new();
        let flows = analyzer.analyze_file(path, &code);
        Ok(flows)
    }

    // ── 文件分析 ──────────────────────────────────────

    pub fn analyze_file(
        &self,
        file_path: &str,
        start_line: Option<usize>,
        end_line: Option<usize>,
        show_ast: bool,
        show_symbols: bool,
    ) -> Result<serde_json::Value> {
        let path = Path::new(file_path);
        if !path.exists() {
            anyhow::bail!("文件不存在: {}", file_path);
        }

        let code = std::fs::read_to_string(path)?;
        let mut result = serde_json::Map::new();

        result.insert("file_path".to_string(), json!(file_path));

        let lines: Vec<&str> = code.lines().collect();
        result.insert("total_lines".to_string(), json!(lines.len()));

        let start = start_line.unwrap_or(1).max(1) - 1;
        let end = end_line.unwrap_or(lines.len()).min(lines.len());
        result.insert(
            "snippet".to_string(),
            json!(lines[start..end]
                .iter()
                .enumerate()
                .map(|(i, s)| { json!({ "line": start + i + 1, "content": s }) })
                .collect::<Vec<_>>()),
        );

        let language = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| match e {
                "py" => "python",
                "js" => "javascript",
                "ts" | "tsx" => "typescript",
                "java" => "java",
                "rs" => "rust",
                "go" => "go",
                "c" | "h" => "c",
                "cpp" | "cc" | "cxx" | "hpp" => "cpp",
                _ => e,
            })
            .unwrap_or("unknown")
            .to_string();
        result.insert("language".to_string(), json!(language));

        if show_symbols {
            let mut parser = ASTParser::new();
            match parser.parse_file(path, &code) {
                Ok(_tree) => {
                    let calls = parser.extract_calls(path, &code);
                    result.insert(
                        "calls".to_string(),
                        json!(calls
                            .iter()
                            .map(|c| json!({
                                "name": c.callee,
                                "line": c.line,
                            }))
                            .collect::<Vec<_>>()),
                    );
                }
                Err(e) => {
                    result.insert("parse_error".to_string(), json!(e));
                }
            }
        }

        if show_ast {
            let mut parser = ASTParser::new();
            match parser.parse_file(path, &code) {
                Ok(_) => result.insert("ast_parsed".to_string(), json!(true)),
                Err(e) => result.insert("ast_error".to_string(), json!(e)),
            };
        }

        let mut taint_analyzer = AstTaintAnalyzer::new();
        let taint_flows = taint_analyzer.analyze_file(path, &code);
        result.insert("taint_flow_count".to_string(), json!(taint_flows.len()));
        if !taint_flows.is_empty() {
            result.insert(
                "taint_flows".to_string(),
                json!(taint_flows
                    .iter()
                    .map(|f| json!({
                        "source": f.source.symbol,
                        "sink": f.sink.symbol,
                        "vulnerability_type": format!("{:?}", f.vulnerability_type),
                        "source_line": f.source.line,
                        "sink_line": f.sink.line,
                    }))
                    .collect::<Vec<_>>()),
            );
        }

        Ok(serde_json::Value::Object(result))
    }

    // ── AST 索引 ──────────────────────────────────────

    pub async fn ensure_indexed(&self, project_path: &str) -> Result<()> {
        {
            let engines = self.ast_engines.read().await;
            if let Some(ts_engine) = engines.get(project_path) {
                if let Ok(mut t) = ts_engine.last_accessed.lock() {
                    *t = std::time::Instant::now();
                }
                return Ok(());
            }
        }

        // 使用项目级缓存目录，而非 temp
        let cache_dir = std::path::Path::new(project_path).join(".ctx-audit/cache/ast");
        let _ = std::fs::create_dir_all(&cache_dir);
        let engine = Arc::new(ASTEngine::new(cache_dir.to_string_lossy().as_ref()));
        engine.use_repository(project_path);

        match engine.scan_project(project_path) {
            Ok(count) => tracing::info!("项目索引完成: {} 个文件", count),
            Err(e) => tracing::warn!("项目索引失败: {}", e),
        }

        let estimated_bytes = estimate_ast_bytes(&engine);
        let mut engines = self.ast_engines.write().await;
        engines.insert(
            project_path.to_string(),
            TimestampedEngine {
                engine,
                last_accessed: std::sync::Mutex::new(std::time::Instant::now()),
                estimated_bytes,
            },
        );
        Ok(())
    }

    // ── 符号查询 ──────────────────────────────────────

    pub async fn query_symbols(
        &self,
        project_path: &str,
        query: &str,
        limit: Option<usize>,
    ) -> Result<Vec<serde_json::Value>> {
        self.ensure_indexed(project_path).await?;

        let engines = self.ast_engines.read().await;
        if let Some(ts_engine) = engines.get(project_path) {
            if let Ok(mut t) = ts_engine.last_accessed.lock() {
                *t = std::time::Instant::now();
            }
            match ts_engine.engine.search_symbols(query) {
                Ok(results) => {
                    let limit = limit.unwrap_or(50);
                    Ok(results
                        .iter()
                        .take(limit)
                        .map(|s| {
                            json!({
                                "name": s.name,
                                "kind": format!("{:?}", s.kind),
                                "file": s.file_path,
                                "line": s.start_line,
                                "end_line": s.end_line,
                            })
                        })
                        .collect())
                }
                Err(e) => anyhow::bail!("符号查询失败: {}", e),
            }
        } else {
            Ok(vec![])
        }
    }

    // ── 调用图 ────────────────────────────────────────

    pub async fn get_call_graph(
        &self,
        project_path: &str,
        entry: &str,
        depth: Option<usize>,
    ) -> Result<serde_json::Value> {
        self.ensure_indexed(project_path).await?;

        let engines = self.ast_engines.read().await;
        if let Some(ts_engine) = engines.get(project_path) {
            if let Ok(mut t) = ts_engine.last_accessed.lock() {
                *t = std::time::Instant::now();
            }
            match ts_engine.engine.get_call_graph(entry, depth.unwrap_or(3)) {
                Ok(graph) => Ok(graph),
                Err(e) => anyhow::bail!("调用图查询失败: {}", e),
            }
        } else {
            Ok(json!({"error": "project not indexed"}))
        }
    }

    // ── 跨文件污点分析 ──────────────────────────────

    pub fn cross_file_analysis(&self, project_path: &str) -> Result<serde_json::Value> {
        let mut analyzer = CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(std::path::Path::new(project_path));

        let summaries = analyzer.compute_function_summaries(std::path::Path::new(project_path));

        let cross_file_flows: Vec<serde_json::Value> = result
            .taint_flows
            .iter()
            .filter(|f| f.source.file_path != f.sink.file_path)
            .map(|f| {
                json!({
                    "id": f.id,
                    "source": {
                        "file": f.source.file_path,
                        "line": f.source.line,
                        "symbol": f.source.symbol,
                    },
                    "sink": {
                        "file": f.sink.file_path,
                        "line": f.sink.line,
                        "symbol": f.sink.symbol,
                    },
                    "vulnerability_type": format!("{:?}", f.vulnerability_type),
                    "severity": format!("{:?}", f.severity),
                    "confidence": f.confidence,
                    "path_steps": f.interprocedural_path.iter().map(|s| json!({
                        "type": format!("{:?}", s.step_type),
                        "file": s.file_path,
                        "function": s.function_name,
                        "line": s.line,
                        "variable": s.variable,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();

        let summary_list: Vec<serde_json::Value> = summaries
            .values()
            .map(|s| {
                json!({
                    "func_id": s.func_id,
                    "func_name": s.func_name,
                    "file_path": s.file_path,
                    "taint_propagation": s.taint_propagation.iter().map(|(idx, affects_return)| {
                        json!({"param_index": idx, "affects_return": affects_return})
                    }).collect::<Vec<_>>(),
                    "direct_sinks": s.direct_sinks.iter().map(|sk| json!({
                        "sink_name": sk.sink_name,
                        "from_param": sk.from_param,
                        "sanitized": sk.sanitized,
                        "vuln_type": format!("{:?}", sk.vuln_type),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();

        Ok(json!({
            "project_path": result.project_path,
            "stats": {
                "files_analyzed": result.stats.files_analyzed,
                "total_functions": result.stats.total_functions,
                "taint_sources": result.stats.taint_sources,
                "taint_sinks": result.stats.taint_sinks,
                "total_flows": result.stats.taint_flows,
                "cross_file_flows": result.stats.cross_file_flows,
            },
            "cross_file_flows": cross_file_flows,
            "function_summaries": summary_list,
            "call_graph": {
                "nodes": result.call_graph.nodes.len(),
                "entry_points": result.call_graph.entry_points.len(),
            },
        }))
    }

    // ── 调用图查询 ──────────────────────────────────

    fn build_query_engine_for_project(
        &self,
        project_path: &str,
    ) -> anyhow::Result<deepaudit_core::CallGraphQueryEngine> {
        let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
        let result = analyzer.analyze_project(std::path::Path::new(project_path));
        Ok(deepaudit_core::CallGraphQueryEngine::from_result(&result))
    }

    pub fn graph_query_callers(
        &self,
        project_path: &str,
        file_path: &str,
        function_name: &str,
        recursive: bool,
    ) -> anyhow::Result<serde_json::Value> {
        let engine = self.build_query_engine_for_project(project_path)?;
        let callers = if recursive {
            engine.query_all_callers(file_path, function_name)
        } else {
            engine.query_callers(file_path, function_name)
        };
        Ok(serde_json::to_value(callers)?)
    }

    pub fn graph_query_callees(
        &self,
        project_path: &str,
        file_path: &str,
        function_name: &str,
        recursive: bool,
    ) -> anyhow::Result<serde_json::Value> {
        let engine = self.build_query_engine_for_project(project_path)?;
        let callees = if recursive {
            engine.query_all_callees(file_path, function_name)
        } else {
            engine.query_callees(file_path, function_name)
        };
        Ok(serde_json::to_value(callees)?)
    }

    pub fn graph_find_call_path(
        &self,
        project_path: &str,
        source_file: &str,
        source_function: &str,
        sink_file: &str,
        sink_function: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let engine = self.build_query_engine_for_project(project_path)?;
        let path = engine.find_call_path(source_file, source_function, sink_file, sink_function);
        Ok(serde_json::to_value(path)?)
    }

    pub fn graph_get_stats(&self, project_path: &str) -> anyhow::Result<serde_json::Value> {
        let engine = self.build_query_engine_for_project(project_path)?;
        let stats = engine.query_graph_stats();
        Ok(serde_json::to_value(stats)?)
    }

    pub fn graph_list_functions(
        &self,
        project_path: &str,
        file_path: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let engine = self.build_query_engine_for_project(project_path)?;
        let functions = engine.query_functions_in_file(file_path);
        Ok(serde_json::to_value(functions)?)
    }

    pub fn graph_trace_flow(
        &self,
        project_path: &str,
        file_path: &str,
        function_name: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let engine = self.build_query_engine_for_project(project_path)?;
        let flow = engine.trace_variable_flow(file_path, function_name);
        Ok(serde_json::to_value(flow)?)
    }

    // ── 增量索引状态 ─────────────────────────────────

    /// 规则目录解析（项目级 > 工作目录内置），扫描与状态上报共用同一口径。
    fn resolve_rules_dir(path: &str) -> Option<String> {
        let project_rules = Path::new(path).join(".ctx-audit/rules");
        let builtin_rules = Path::new("rules");
        if project_rules.exists() {
            Some(project_rules.to_string_lossy().to_string())
        } else if builtin_rules.exists() {
            Some(builtin_rules.to_string_lossy().to_string())
        } else {
            None
        }
    }

    /// 增量索引状态：冷启动 / 缓存命中 / 待重编译清单。
    ///
    /// **只读**：变更判定走 `FileSnapshot::peek_changes`，不会更新 baseline，
    /// 因此可以反复调用而不影响后续增量扫描的判定。
    pub async fn incremental_status(&self, path: &str) -> serde_json::Value {
        let caches = self.scan_caches.read().await;
        let ast_count = self.ast_engines.read().await.len();
        let scan_count = caches.len();

        let ts_cache = match caches.get(path) {
            Some(c) => c,
            None => {
                return serde_json::json!({
                    "project": path,
                    "mode": "cold",
                    "cold_start": true,
                    "reason": "no_scan_cache_slot",
                    "files_cached": 0,
                    "cached_findings": 0,
                    "snapshot_files": 0,
                    "pending_recompile": 0,
                    "pending": {"added": 0, "changed": 0, "deleted": 0, "sample": []},
                    "last_scan": null,
                    "rules_dir": Self::resolve_rules_dir(path),
                    "cache": {"ast_engines": ast_count, "scan_projects": scan_count},
                    "uncertainty": ["project_not_loaded"],
                });
            }
        };

        let cache = ts_cache.cache.read().await;
        let last_accessed_age_ms = ts_cache
            .last_accessed
            .lock()
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        // 只读变更预览：不更新 baseline
        let mut pending_added = 0usize;
        let mut pending_changed = 0usize;
        let mut pending_deleted = 0usize;
        let mut pending_sample: Vec<String> = Vec::new();
        let mut peek_error: Option<String> = None;
        match cache.snapshot.peek_changes() {
            Ok(delta) => {
                pending_added = delta.added_files.len();
                pending_changed = delta.changed_files.len();
                pending_deleted = delta.deleted_files.len();
                pending_sample = delta
                    .added_files
                    .iter()
                    .chain(delta.changed_files.iter())
                    .chain(delta.deleted_files.iter())
                    .take(20)
                    .map(|p| path_relative_to(Path::new(path), p))
                    .collect();
            }
            Err(e) => peek_error = Some(e.to_string()),
        }

        let last_scan = cache.last_scan.as_ref().map(|t| {
            serde_json::json!({
                "duration_ms": t.duration_ms,
                "files_scanned": t.files_scanned,
                "files_cached": t.files_cached,
                "snapshot_files": t.snapshot_files,
                "was_incremental": t.was_incremental,
                "changed_files": t.changed_files,
                "age_ms": t.at.elapsed().as_millis() as u64,
            })
        });

        let pending_total = pending_added + pending_changed + pending_deleted;
        // "冷" 的判据是"从未扫过"，不是"findings 缓存为空"——零 findings 项目扫完仍为空。
        let cold_start = cache.last_scan.is_none() && !cache.snapshot.has_baseline();
        let last_options = cache.last_options.map(|(taint, cross_file)| {
            serde_json::json!({"enable_taint": taint, "enable_cross_file": cross_file})
        });
        let mode = if cold_start {
            "cold"
        } else if pending_total == 0 {
            "warm-unchanged"
        } else {
            "warm-pending-recompile"
        };
        // 增量重扫只覆盖快速层（规则 + 攻击面）；污点/跨文件是项目级分析，
        // 上一次若以深扫选项执行，则本次变更只能整表重建——如实标注。
        let deep_options = matches!(cache.last_options, Some((true, _)) | Some((_, true)));
        let mut uncertainty: Vec<&str> = Vec::new();
        if peek_error.is_some() {
            uncertainty.push("change_peek_failed");
        }
        if !cache.snapshot.has_baseline() {
            uncertainty.push("baseline_not_built");
        }
        if pending_total > 0 && deep_options {
            uncertainty.push("partial_rescan_unavailable_for_deep_options");
        }

        serde_json::json!({
            "project": path,
            "mode": mode,
            "cold_start": cold_start,
            "files_cached": cache.entries.len(),
            "cached_findings": cache.total_findings,
            "snapshot_files": cache.snapshot.file_count(),
            "pending_recompile": pending_total,
            "pending": {
                "added": pending_added,
                "changed": pending_changed,
                "deleted": pending_deleted,
                "sample": pending_sample,
            },
            "last_scan": last_scan,
            "last_options": last_options,
            "last_accessed_age_ms": last_accessed_age_ms,
            "rules_dir": Self::resolve_rules_dir(path),
            "cache": {"ast_engines": ast_count, "scan_projects": scan_count},
            "peek_error": peek_error,
            "partial_rescan_supported": !deep_options,
            "uncertainty": uncertainty,
        })
    }

    // ── 缓存统计 ─────────────────────────────────────

    pub async fn cache_stats(&self) -> (usize, usize) {
        let caches = self.scan_caches.read().await;
        let ast_count = self.ast_engines.read().await.len();
        let scan_count = caches.len();
        (ast_count, scan_count)
    }

    /// taint cache 条目数（当前无独立 taint cache，taint 结果内嵌在 scan cache 中）
    pub async fn taint_cache_count(&self) -> usize {
        0
    }

    /// 内存统计（用于心跳上报）
    pub async fn memory_stats(&self) -> MemoryStats {
        let engines = self.ast_engines.read().await;
        let ast_bytes: usize = engines.values().map(|v| v.estimated_bytes).sum();
        let ast_count = engines.len();
        drop(engines);

        let caches = self.scan_caches.read().await;
        let scan_count = caches.len();

        MemoryStats {
            ast_count,
            ast_bytes,
            scan_count,
        }
    }

    // ── 内存淘汰 ─────────────────────────────────────

    /// 淘汰空闲超时的 AST Engine，或总量超限时淘汰最久未访问的
    pub fn evict_idle_ast_engines(&self) -> usize {
        let max_idle_secs = self.ast_idle_secs;
        let max_total_bytes = self.ast_max_memory_bytes;

        let mut engines = match self.ast_engines.try_write() {
            Ok(guard) => guard,
            Err(_) => return 0, // 正在被占用，跳过本次淘汰
        };

        let expired: Vec<String> = engines
            .iter()
            .filter_map(|(k, v)| {
                let last = v.last_accessed.lock().ok()?;
                if last.elapsed().as_secs() > max_idle_secs {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut evicted = expired.len();
        for key in &expired {
            engines.remove(key);
        }

        let total: usize = engines.values().map(|v| v.estimated_bytes).sum();
        if total > max_total_bytes {
            let mut entries: Vec<(String, std::time::Duration, usize)> = engines
                .iter()
                .filter_map(|(k, v)| {
                    let last = v.last_accessed.lock().ok()?;
                    Some((k.clone(), last.elapsed(), v.estimated_bytes))
                })
                .collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1));

            let mut freed = 0usize;
            for (key, _, bytes) in entries {
                if total - freed <= max_total_bytes {
                    break;
                }
                engines.remove(&key);
                freed += bytes;
                evicted += 1;
            }
        }

        if evicted > 0 {
            tracing::info!("[内存管理] 淘汰 {} 个空闲 AST Engine", evicted);
        }
        evicted
    }

    /// 淘汰空闲超时的 Scan Cache
    pub fn evict_idle_scan_caches(&self) -> usize {
        let max_idle_secs = self.scan_cache_idle_secs;

        let mut caches = match self.scan_caches.try_write() {
            Ok(guard) => guard,
            Err(_) => return 0,
        };

        let expired: Vec<String> = caches
            .iter()
            .filter_map(|(k, v)| {
                let last = v.last_accessed.lock().ok()?;
                if last.elapsed().as_secs() > max_idle_secs {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();

        let evicted = expired.len();
        for key in &expired {
            caches.remove(key.as_str());
        }

        if evicted > 0 {
            tracing::info!("[内存管理] 淘汰 {} 个空闲 Scan Cache", evicted);
        }
        evicted
    }

    /// 规则热重载状态日志（带缓存去重）
    async fn log_rules_status(&self, project_path: &str, rules_dir: Option<&str>) {
        let rules_cache = self.rules_cache.read().await;
        let key = rules_dir.unwrap_or("none");
        let now = std::time::Instant::now();
        let should_log = match rules_cache.get(key) {
            Some((last_time, _)) => {
                now.duration_since(*last_time).as_secs() > self.rules_reload_interval_secs
            }
            None => true,
        };
        drop(rules_cache);

        if should_log {
            if let Some(dir) = rules_dir {
                match deepaudit_core::rules::loader::load_rules_from_dir(dir) {
                    Ok(rules) => {
                        tracing::info!("规则加载: {} 条规则 from {}", rules.len(), dir);
                        let mut cache = self.rules_cache.write().await;
                        cache.insert(key.to_string(), (now, rules.len()));
                    }
                    Err(e) => tracing::warn!("规则加载失败: {}", e),
                }
            } else {
                tracing::info!("未找到规则目录，使用内置 RegexScanner");
            }
        }
    }
}

// ────────────────────────────────────────────────────────
// 辅助函数
// ────────────────────────────────────────────────────────

/// 计算文件的 content hash
fn hash_file_content(path: &Path) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    match std::fs::read_to_string(path) {
        Ok(content) => {
            let mut hasher = DefaultHasher::new();
            content.hash(&mut hasher);
            hasher.finish()
        }
        Err(_) => 0,
    }
}

/// 获取相对于项目根的路径
fn path_relative_to(root: &Path, full: &Path) -> String {
    full.strip_prefix(root)
        .unwrap_or(full)
        .to_string_lossy()
        .replace('\\', "/")
}

async fn cache_entries_count(
    caches: &RwLock<HashMap<String, TimestampedScanCache>>,
    path: &str,
) -> usize {
    let caches = caches.read().await;
    if let Some(ts_cache) = caches.get(path) {
        let cache = ts_cache.cache.read().await;
        cache.entries.len()
    } else {
        0
    }
}

/// 估算 AST Engine 的内存占用
fn estimate_ast_bytes(engine: &ASTEngine) -> usize {
    engine
        .get_statistics()
        .ok()
        .and_then(|s| s.get("total_nodes").and_then(|v| v.as_u64()))
        .map(|n| n as usize * 512)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_key(f: &Finding) -> (String, usize, String, String) {
        (
            f.file_path.clone(),
            f.line_start,
            f.detector.clone(),
            f.vuln_type.clone(),
        )
    }

    fn write_fixture(root: &Path, name: &str, content: &str) {
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, content).unwrap();
    }

    /// 增量重扫的不变量：**增量结果必须等于全量结果**。
    ///
    /// 夹具刻意包含一个无认证 HTTP 端点（`AttackSurfaceMapper` 会产出 finding），
    /// 这样"改动文件后走增量路径"与"全新引擎全量扫描"可以逐条对比。
    #[tokio::test]
    async fn test_incremental_rescan_matches_full_scan() {
        let root = std::env::temp_dir().join("ctx-audit-daemon-incremental-equiv");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_fixture(
            &root,
            "app.py",
            "@app.route(\"/admin\")\ndef admin():\n    return \"ok\"\n",
        );
        write_fixture(&root, "util.py", "def add(a, b):\n    return a + b\n");
        let root_str = root.to_string_lossy().to_string();

        let engine = AnalysisEngine::new();
        let first = engine.scan(&root_str, false, false).await.unwrap();
        assert!(
            !first.findings.is_empty(),
            "夹具应至少产出 1 个 finding（无认证端点）"
        );
        assert!(!first.was_incremental, "首次扫描应为全量");

        // 改一个文件 → 第二次走增量路径
        write_fixture(
            &root,
            "app.py",
            "@app.route(\"/admin2\")\ndef admin2():\n    return \"ok\"\n",
        );
        let second = engine.scan(&root_str, false, false).await.unwrap();
        assert!(second.was_incremental, "有变更时应走增量路径");
        assert_eq!(second.files_scanned, 1, "只应重扫变更的那 1 个文件");

        // 全新引擎（无缓存）全量扫描同一内容：必须逐条一致
        let fresh = AnalysisEngine::new();
        let full = fresh.scan(&root_str, false, false).await.unwrap();
        assert!(!full.was_incremental);

        let mut incremental_keys: Vec<_> = second.findings.iter().map(finding_key).collect();
        let mut full_keys: Vec<_> = full.findings.iter().map(finding_key).collect();
        incremental_keys.sort();
        full_keys.sort();
        assert_eq!(
            incremental_keys, full_keys,
            "增量重扫结果必须与全量扫描结果一致（增量 {:?} vs 全量 {:?}）",
            incremental_keys, full_keys
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 深扫选项必须整表重建：增量路径只覆盖快速层。
    #[tokio::test]
    async fn test_deep_options_force_full_rebuild() {
        let root = std::env::temp_dir().join("ctx-audit-daemon-deep-gate");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_fixture(&root, "app.py", "def handler(request):\n    return request.args\n");
        let root_str = root.to_string_lossy().to_string();

        let engine = AnalysisEngine::new();
        let _ = engine.scan(&root_str, false, false).await.unwrap();

        // 启用污点：即使只有一个文件变化，也必须整表重建（files_scanned != 1 或 was_incremental=false）
        write_fixture(
            &root,
            "app.py",
            "def handler(request):\n    return request.args.get('q')\n",
        );
        let deep = engine.scan(&root_str, true, false).await.unwrap();
        assert!(!deep.was_incremental, "深扫选项应整表重建");

        let _ = std::fs::remove_dir_all(&root);
    }
}
