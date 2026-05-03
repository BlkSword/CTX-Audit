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
use deepaudit_core::scanning::{Finding, Scanner, RegexScanner, scan_directory_deep_with_rules, scan_directory_with_rules};
use deepaudit_core::taint::{AstTaintAnalyzer, TaintFlow, CrossFileTaintAnalyzer};
use deepaudit_core::watcher::{FileSnapshot, DeltaResult};

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
}

// ────────────────────────────────────────────────────────
// 分析引擎
// ────────────────────────────────────────────────────────

pub struct AnalysisEngine {
    /// AST 索引引擎: project_path → ASTEngine
    ast_engines: RwLock<HashMap<String, Arc<ASTEngine>>>,
    /// 扫描缓存: project_path → ProjectScanCache
    scan_caches: RwLock<HashMap<String, RwLock<ProjectScanCache>>>,
    /// 规则加载时间戳：rules_dir → (load_time, rule_count)
    rules_cache: RwLock<HashMap<String, (std::time::Instant, usize)>>,
}

/// 规则热重载检查间隔
const RULES_RELOAD_INTERVAL_SECS: u64 = 30;

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
        Self {
            ast_engines: RwLock::new(HashMap::new()),
            scan_caches: RwLock::new(HashMap::new()),
            rules_cache: RwLock::new(HashMap::new()),
        }
    }

    // ── 增量扫描 ─────────────────────────────────────

    /// 扫描项目（自动增量）
    ///
    /// 首次调用：全量扫描，缓存结果。
    /// 后续调用：检测变更文件，只重新扫描变更部分，合并缓存。
    pub async fn scan(&self, path: &str, deep: bool) -> Result<ScanOutput> {
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
                        "node_modules".into(), ".git".into(), "target".into(),
                        "build".into(), "dist".into(), "__pycache__".into(),
                        "vendor".into(), ".next".into(),
                    ];
                    RwLock::new(ProjectScanCache {
                        entries: HashMap::new(),
                        snapshot: FileSnapshot::new(project_path, ignore),
                        total_findings: 0,
                    })
                });
            }
        }

        let caches = self.scan_caches.read().await;
        let cache = match caches.get(path) {
            Some(c) => c,
            None => anyhow::bail!("扫描缓存初始化失败"),
        };
        let mut cache = cache.write().await;

        // 检测变更
        let delta = cache.snapshot.detect_changes()
            .map_err(|e| anyhow::anyhow!("变更检测失败: {}", e))?;

        if !delta.has_changes() && !cache.entries.is_empty() {
            // 无变更，直接返回缓存
            let all_findings: Vec<Finding> = cache.entries.values()
                .flat_map(|e| e.findings.clone())
                .collect();
            let duration = start.elapsed().as_millis() as u64;

            return Ok(ScanOutput {
                findings: all_findings,
                duration_ms: duration,
                files_scanned: 0,
                files_cached: cache.entries.len(),
                was_incremental: true,
            });
        }

        // 有变更：确定需要重新扫描的文件
        let changed_set: std::collections::HashSet<PathBuf> = delta.changed_files.iter()
            .chain(delta.added_files.iter())
            .cloned()
            .collect();

        // 移除已删除文件的缓存
        for deleted in &delta.deleted_files {
            let rel = path_relative_to(project_path, deleted);
            cache.entries.remove(&rel);
        }

        // 如果是首次扫描（无缓存），执行全量扫描
        if cache.entries.is_empty() {
            drop(cache);
            drop(caches);
            return self.full_scan(path, deep, start).await;
        }

        // 增量：只扫描变更文件
        tracing::info!(
            "[增量扫描] 变更: {} 个文件 (新增: {}, 修改: {}, 删除: {})",
            delta.total_changes(), delta.added_files.len(),
            delta.changed_files.len(), delta.deleted_files.len()
        );

        let new_findings = self.scan_files(path, &changed_set, deep).await?;

        // 更新缓存：移除变更文件的旧 findings，加入新的
        for file_path in &changed_set {
            let rel = path_relative_to(project_path, file_path);
            cache.entries.remove(&rel);
        }

        // 按文件分组新 findings
        let mut by_file: HashMap<String, Vec<Finding>> = HashMap::new();
        for f in &new_findings {
            by_file.entry(f.file_path.clone()).or_default().push(f.clone());
        }

        // 计算变更文件的 content hash 并缓存
        for file_path in &changed_set {
            let rel = path_relative_to(project_path, file_path);
            let full = project_path.join(&rel);
            let hash = hash_file_content(&full);
            let findings = by_file.get(&rel).cloned().unwrap_or_default();
            cache.entries.insert(rel.clone(), FileFindings {
                relative_path: rel,
                findings,
                content_hash: hash,
            });
        }

        // 合并所有 findings
        let all_findings: Vec<Finding> = cache.entries.values()
            .flat_map(|e| e.findings.clone())
            .collect();

        cache.total_findings = all_findings.len();

        // 更新 snapshot baseline
        let _ = cache.snapshot.build_baseline();

        let duration = start.elapsed().as_millis() as u64;
        Ok(ScanOutput {
            findings: all_findings,
            duration_ms: duration,
            files_scanned: changed_set.len(),
            files_cached: cache.entries.len() - changed_set.len(),
            was_incremental: true,
        })
    }

    /// 全量扫描（首次或强制）
    async fn full_scan(&self, path: &str, deep: bool, start: Instant) -> Result<ScanOutput> {
        // 检测规则目录（项目级 > 内置）
        let project_rules = Path::new(path).join(".ctx-audit/rules");
        let builtin_rules = Path::new("rules");
        let rules_dir = if project_rules.exists() {
            Some(project_rules.to_string_lossy().to_string())
        } else if builtin_rules.exists() {
            Some(builtin_rules.to_string_lossy().to_string())
        } else {
            None
        };

        self.log_rules_status(path, rules_dir.as_deref()).await;

        let findings = if deep {
            scan_directory_deep_with_rules(path, rules_dir.as_deref(), None).await
                .map_err(|e| anyhow::anyhow!("{}", e))?
        } else {
            scan_directory_with_rules(path, rules_dir.as_deref(), None).await
                .map_err(|e| anyhow::anyhow!("{}", e))?
        };

        let project_path = Path::new(path);
        let total = findings.len();

        // 按 file_path 分组缓存
        let caches = self.scan_caches.read().await;
        if let Some(cache_rwlock) = caches.get(path) {
            let mut cache = cache_rwlock.write().await;

            let mut by_file: HashMap<String, Vec<Finding>> = HashMap::new();
            for f in &findings {
                let rel = path_relative_to(project_path, Path::new(&f.file_path));
                by_file.entry(rel.clone()).or_default().push(f.clone());
            }

            cache.entries.clear();
            for (rel, file_findings) in by_file {
                let full = project_path.join(&rel);
                let hash = hash_file_content(&full);
                cache.entries.insert(rel.clone(), FileFindings {
                    relative_path: rel,
                    findings: file_findings,
                    content_hash: hash,
                });
            }

            cache.total_findings = total;
            let _ = cache.snapshot.build_baseline();
        }

        let duration = start.elapsed().as_millis() as u64;
        Ok(ScanOutput {
            findings,
            duration_ms: duration,
            files_scanned: cache_entries_count(&self.scan_caches, path).await,
            files_cached: 0,
            was_incremental: false,
        })
    }

    /// 扫描指定文件集合
    async fn scan_files(
        &self,
        project_path: &str,
        files: &std::collections::HashSet<PathBuf>,
        deep: bool,
    ) -> Result<Vec<Finding>> {
        if files.is_empty() {
            return Ok(vec![]);
        }

        /// 最大文件大小 10MB，超过则跳过
        const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

        let regex_scanner = RegexScanner::new();
        let mut all_findings = Vec::new();

        for file_path in files {
            if !file_path.exists() {
                continue;
            }
            // 文件大小检查
            match std::fs::metadata(file_path) {
                Ok(meta) if meta.len() > MAX_FILE_SIZE => {
                    tracing::warn!("跳过大文件 ({}MB): {:?}", meta.len() / 1024 / 1024, file_path);
                    continue;
                }
                Err(_) => continue,
                _ => {}
            }
            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let file_path_buf = file_path.to_path_buf();
            let file_findings = regex_scanner.scan_file(&file_path_buf, &content).await;
            all_findings.extend(file_findings);
        }

        // 如果 deep 模式，对有 findings 的文件做 taint 分析
        if deep && !all_findings.is_empty() {
            let mut taint_analyzer = AstTaintAnalyzer::new();
            let files_with_findings: std::collections::HashSet<String> = all_findings.iter()
                .map(|f| f.file_path.clone())
                .collect();

            for file_path_str in &files_with_findings {
                let p = Path::new(file_path_str);
                if let Ok(code) = std::fs::read_to_string(p) {
                    let flows = taint_analyzer.analyze_file(p, &code);
                    for flow in flows {
                        all_findings.push(Finding {
                            finding_id: uuid::Uuid::new_v4().to_string(),
                            file_path: file_path_str.clone(),
                            line_start: flow.source.line,
                            line_end: flow.sink.line,
                            detector: "ast_taint".to_string(),
                            vuln_type: format!("{:?}", flow.vulnerability_type),
                            severity: format!("{:?}", flow.severity).to_lowercase(),
                            description: format!(
                                "Taint flow: {}:{} → {}:{}",
                                flow.source.symbol, flow.source.line,
                                flow.sink.symbol, flow.sink.line
                            ),
                            analysis_trail: None,
                            llm_output: None,
                            confidence: Some(flow.confidence),
                            corroboration_count: None,
                        });
                    }
                }
            }
        }

        Ok(all_findings)
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
        result.insert("snippet".to_string(), json!(
            lines[start..end].iter().enumerate().map(|(i, s)| {
                json!({ "line": start + i + 1, "content": s })
            }).collect::<Vec<_>>()
        ));

        let language = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| match e {
                "py" => "python", "js" => "javascript", "ts" | "tsx" => "typescript",
                "java" => "java", "rs" => "rust", "go" => "go",
                "c" | "h" => "c", "cpp" | "cc" | "cxx" | "hpp" => "cpp", _ => e,
            })
            .unwrap_or("unknown")
            .to_string();
        result.insert("language".to_string(), json!(language));

        if show_symbols {
            let mut parser = ASTParser::new();
            match parser.parse_file(path, &code) {
                Ok(_tree) => {
                    let calls = parser.extract_calls(path, &code);
                    result.insert("calls".to_string(), json!(
                        calls.iter().map(|c| json!({
                            "name": c.callee,
                            "line": c.line,
                        })).collect::<Vec<_>>()
                    ));
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
            result.insert("taint_flows".to_string(), json!(
                taint_flows.iter().map(|f| json!({
                    "source": f.source.symbol,
                    "sink": f.sink.symbol,
                    "vulnerability_type": format!("{:?}", f.vulnerability_type),
                    "source_line": f.source.line,
                    "sink_line": f.sink.line,
                })).collect::<Vec<_>>()
            ));
        }

        Ok(serde_json::Value::Object(result))
    }

    // ── AST 索引 ──────────────────────────────────────

    pub async fn ensure_indexed(&self, project_path: &str) -> Result<()> {
        {
            let engines = self.ast_engines.read().await;
            if engines.contains_key(project_path) {
                return Ok(());
            }
        }

        // 使用项目级缓存目录，而非 temp
        let cache_dir = std::path::Path::new(project_path).join(".ctx-audit/cache/ast");
        let _ = std::fs::create_dir_all(&cache_dir);
        let engine = Arc::new(ASTEngine::new(
            cache_dir.to_string_lossy().as_ref(),
        ));
        engine.use_repository(project_path);

        match engine.scan_project(project_path) {
            Ok(count) => tracing::info!("项目索引完成: {} 个文件", count),
            Err(e) => tracing::warn!("项目索引失败: {}", e),
        }

        let mut engines = self.ast_engines.write().await;
        engines.insert(project_path.to_string(), engine);
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
        if let Some(engine) = engines.get(project_path) {
            match engine.search_symbols(query) {
                Ok(results) => {
                    let limit = limit.unwrap_or(50);
                    Ok(results.iter().take(limit).map(|s| json!({
                        "name": s.name,
                        "kind": format!("{:?}", s.kind),
                        "file": s.file_path,
                        "line": s.start_line,
                        "end_line": s.end_line,
                    })).collect())
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
        if let Some(engine) = engines.get(project_path) {
            match engine.get_call_graph(entry, depth.unwrap_or(3)) {
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

        let cross_file_flows: Vec<serde_json::Value> = result.taint_flows.iter()
            .filter(|f| f.source.file_path != f.sink.file_path)
            .map(|f| json!({
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
            }))
            .collect();

        let summary_list: Vec<serde_json::Value> = summaries.values().map(|s| json!({
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
        })).collect();

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

    // ── 缓存统计 ─────────────────────────────────────

    pub async fn cache_stats(&self) -> (usize, usize) {
        let caches = self.scan_caches.read().await;
        let ast_count = self.ast_engines.read().await.len();
        let scan_count = caches.len();
        (ast_count, scan_count)
    }

    /// 规则热重载状态日志（带缓存去重）
    async fn log_rules_status(&self, project_path: &str, rules_dir: Option<&str>) {
        let rules_cache = self.rules_cache.read().await;
        let key = rules_dir.unwrap_or("none");
        let now = std::time::Instant::now();
        let should_log = match rules_cache.get(key) {
            Some((last_time, _)) => now.duration_since(*last_time).as_secs() > RULES_RELOAD_INTERVAL_SECS,
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
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

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
    caches: &RwLock<HashMap<String, RwLock<ProjectScanCache>>>,
    path: &str,
) -> usize {
    let caches = caches.read().await;
    if let Some(cache) = caches.get(path) {
        let cache = cache.read().await;
        cache.entries.len()
    } else {
        0
    }
}
