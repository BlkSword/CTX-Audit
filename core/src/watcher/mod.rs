// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 文件监听与增量扫描
//!
//! 轻量守护模式：监听文件变更 → 增量扫描 → 更新 SARIF 文件

mod delta;

pub use delta::{DeltaResult, FileSnapshot};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::analysis::taint::TaintFlow;
use crate::scanner::Finding;
use crate::AstTaintAnalyzer;

/// 守护模式配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherConfig {
    /// 项目路径
    pub project_path: String,

    /// SARIF 输出路径
    pub sarif_output_path: String,

    /// 忽略的目录模式
    pub ignore_patterns: Vec<String>,

    /// 防抖间隔（毫秒）
    pub debounce_ms: u64,

    /// 严重程度过滤
    pub severity_filter: Option<String>,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            project_path: ".".to_string(),
            sarif_output_path: ".ctx-audit.sarif".to_string(),
            ignore_patterns: vec![
                "node_modules".into(),
                ".git".into(),
                "target".into(),
                "build".into(),
                "dist".into(),
                "__pycache__".into(),
                ".next".into(),
                "vendor".into(),
            ],
            debounce_ms: 2000,
            severity_filter: None,
        }
    }
}

/// 增量扫描事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WatchEvent {
    /// 初始扫描完成
    InitialScanComplete {
        file_count: usize,
        finding_count: usize,
        duration_ms: u64,
    },

    /// 检测到文件变更
    FilesChanged { changed_files: Vec<String> },

    /// 增量扫描完成
    IncrementalScanComplete {
        scanned_files: usize,
        new_findings: usize,
        removed_findings: usize,
        duration_ms: u64,
    },

    /// SARIF 文件已更新
    SarifUpdated { path: String, total_findings: usize },

    /// 错误
    Error { message: String },
}

/// 文件变更事件（原始）
#[derive(Debug)]
pub struct RawFileEvent {
    pub path: PathBuf,
    pub kind: FileEventKind,
}

/// 文件事件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEventKind {
    Created,
    Modified,
    Deleted,
}

/// FileWatcher — 文件监听与增量扫描核心
pub struct FileWatcher {
    config: WatcherConfig,
    snapshot: delta::FileSnapshot,
    event_callback: Option<Box<dyn Fn(WatchEvent) + Send + Sync>>,
}

impl FileWatcher {
    /// 创建新的 FileWatcher
    pub fn new(config: WatcherConfig) -> Self {
        let snapshot = delta::FileSnapshot::new(
            Path::new(&config.project_path),
            config.ignore_patterns.clone(),
        );
        Self {
            config,
            snapshot,
            event_callback: None,
        }
    }

    /// 设置事件回调
    pub fn on_event(mut self, callback: impl Fn(WatchEvent) + Send + Sync + 'static) -> Self {
        self.event_callback = Some(Box::new(callback));
        self
    }

    /// 发出事件
    fn emit(&self, event: WatchEvent) {
        if let Some(ref cb) = self.event_callback {
            cb(event);
        }
    }

    /// 执行初始全量扫描，建立 baseline
    pub fn initial_scan(&mut self) -> Result<DeltaResult> {
        let start = Instant::now();
        tracing::info!("[Watcher] 开始初始扫描: {}", self.config.project_path);

        let result = self.snapshot.build_baseline()?;

        let duration = start.elapsed().as_millis() as u64;
        tracing::info!(
            "[Watcher] 初始扫描完成: {} 个文件, 耗时 {}ms",
            result.total_files,
            duration
        );

        self.emit(WatchEvent::InitialScanComplete {
            file_count: result.total_files,
            finding_count: 0, // finding_count 由外部扫描器提供
            duration_ms: duration,
        });

        Ok(result)
    }

    /// 检测自上次扫描以来的变更
    pub fn detect_changes(&mut self) -> Result<DeltaResult> {
        let start = Instant::now();

        let result = self.snapshot.detect_changes()?;

        let duration = start.elapsed().as_millis() as u64;

        if !result.changed_files.is_empty() || !result.deleted_files.is_empty() {
            let changed: Vec<String> = result
                .changed_files
                .iter()
                .chain(result.deleted_files.iter())
                .filter_map(|p| p.to_str().map(|s| s.to_string()))
                .collect();

            tracing::info!(
                "[Watcher] 检测到 {} 个文件变更, 耗时 {}ms",
                changed.len(),
                duration
            );

            self.emit(WatchEvent::FilesChanged {
                changed_files: changed,
            });
        }

        Ok(result)
    }

    /// 获取变更文件列表（用于增量扫描）
    pub fn get_changed_source_files(&self, delta: &DeltaResult) -> Vec<PathBuf> {
        let source_extensions = [
            ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".rs", ".go", ".php", ".rb", ".c",
            ".cpp", ".h", ".hpp", ".cs", ".kt", ".swift", ".scala", ".lua", ".r", ".sql", ".html",
            ".vue",
        ];

        delta
            .changed_files
            .iter()
            .filter(|p| {
                p.extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| source_extensions.contains(&ext))
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// 增量扫描：只分析变更的文件
    ///
    /// 使用 AstTaintAnalyzer 对变更文件进行污点分析，
    /// 返回新发现的漏洞（不会重新分析未变更的文件）。
    pub fn incremental_scan(&mut self, delta: &DeltaResult) -> IncrementalScanResult {
        let start = Instant::now();

        // 获取变更的源码文件
        let changed_source_files = self.get_changed_source_files(delta);

        if changed_source_files.is_empty() {
            return IncrementalScanResult {
                scanned_files: 0,
                taint_flows: Vec::new(),
                findings: Vec::new(),
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        let mut analyzer = AstTaintAnalyzer::new();
        let mut all_flows: Vec<TaintFlow> = Vec::new();
        let mut all_findings: Vec<Finding> = Vec::new();

        // 分析变更文件
        for file_path in &changed_source_files {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                let file_str = file_path.to_string_lossy().to_string();

                // AST 污点分析
                let flows = analyzer.analyze_file(file_path, &content);

                // 转换为 Finding 格式
                for flow in &flows {
                    all_findings.push(Finding {
                        finding_id: flow.id.clone(),
                        file_path: file_str.clone(),
                        line_start: flow.source.line,
                        line_end: flow.sink.line,
                        detector: "AstTaintAnalyzer".to_string(),
                        vuln_type: format!("{:?}", flow.vulnerability_type),
                        severity: format!("{:?}", flow.severity),
                        description: format!(
                            "{:?}: {} -> {}",
                            flow.vulnerability_type, flow.source.symbol, flow.sink.symbol,
                        ),
                        analysis_trail: Some(
                            flow.path
                                .iter()
                                .map(|n| {
                                    format!("{:?}:{} - {:?}", n.node_type, n.line, n.code_snippet)
                                })
                                .collect(),
                        ),
                        llm_output: None,
                        confidence: None,
                        corroboration_count: None,
                        code_snippet: None,
                        source_snippet: flow.source.code_snippet.clone(),
                        sink_snippet: flow.sink.code_snippet.clone(),
                        file_role: None,
                        barriers: None,
                        reasoning_hint: None,
                        evidence_refs: None,
                    });
                }

                all_flows.extend(flows);
            }
        }

        let duration = start.elapsed().as_millis() as u64;
        let scanned = changed_source_files.len();

        tracing::info!(
            "[Watcher] 增量扫描完成: {} 个文件, {} 条污点流, {} 个发现, 耗时 {}ms",
            scanned,
            all_flows.len(),
            all_findings.len(),
            duration,
        );

        self.emit(WatchEvent::IncrementalScanComplete {
            scanned_files: scanned,
            new_findings: all_findings.len(),
            removed_findings: delta.deleted_files.len(),
            duration_ms: duration,
        });

        IncrementalScanResult {
            scanned_files: scanned,
            taint_flows: all_flows,
            findings: all_findings,
            duration_ms: duration,
        }
    }

    /// 获取项目路径
    pub fn project_path(&self) -> &str {
        &self.config.project_path
    }

    /// 获取 SARIF 输出路径
    pub fn sarif_output_path(&self) -> &str {
        &self.config.sarif_output_path
    }

    /// 获取配置
    pub fn config(&self) -> &WatcherConfig {
        &self.config
    }
}

/// 判断文件是否是需要扫描的源码文件
pub fn is_source_file(path: &Path) -> bool {
    let source_extensions = [
        "py", "js", "ts", "tsx", "jsx", "java", "rs", "go", "php", "rb", "c", "cpp", "h", "hpp",
        "cs", "kt", "swift", "scala", "lua", "sql", "html", "vue",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| source_extensions.contains(&ext))
        .unwrap_or(false)
}

/// 增量扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalScanResult {
    /// 扫描的文件数
    pub scanned_files: usize,
    /// 污点流（AST 引擎）
    pub taint_flows: Vec<TaintFlow>,
    /// 发现的漏洞（Finding 格式）
    pub findings: Vec<Finding>,
    /// 耗时（毫秒）
    pub duration_ms: u64,
}
