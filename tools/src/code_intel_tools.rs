// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 高阶代码智能工具面
//!
//! 目标：把面向 LLM 的工具从细粒度几十个收敛到 9+1 个高阶语义能力，
//! 每个响应携带 `provenance`（来源）与 `uncertainty`（不确定度）。
//!
//! 本实现是**文件级确定性 fallback**（不依赖引擎内部 API）：
//! `resolver` 字段预留了接入 LSP/SCIP 或引擎调用图/污点的位置，
//! 调用方接口（工具名/参数/响应 envelope）保持不变。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::{Tool, ToolRegistry};

const MAX_FILES: usize = 2000;
const MAX_FILE_BYTES: usize = 512 * 1024;
const MAX_HITS: usize = 40;
/// 引用/定义结果上限（40 条在真实仓库上会按文件顺序截断，导致 recall 虚低且用户看不到截断）
const MAX_REFERENCE_HITS: usize = 200;
/// 定义结果上限（同引用：`index` 这类符号在真实仓库里可有上百处定义）
const MAX_DEFINITION_HITS: usize = 200;
/// 调用图结果上限（与定义/引用同一量级：真实 Go 仓库里 `Set`/`String` 这类方法可有数百个调用点，
/// 40 条上限会把 callers 的实测召回从 0.92 压到 0.12）
const MAX_CALL_GRAPH_HITS: usize = 200;
const SKIP_DIRS: [&str; 8] = [
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
];

/// 证据来源。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Provenance {
    pub file: Option<String>,
    pub line: Option<u32>,
    /// tree-sitter / file-heuristic / symbol-index / ...
    pub resolver: String,
    pub build_id: String,
    /// 该条证据的置信度（0–1）。按解析方式给固定档位，
    /// 供上层对照 ground truth 度量"标注准确率"（校准），而非拍脑袋写不确定度。
    #[serde(default = "default_evidence_confidence")]
    pub confidence: f64,
}

/// 置信度默认档（未知解析方式）
pub fn default_evidence_confidence() -> f64 {
    0.5
}

/// 解析方式 → 置信度档位（唯一事实源，改动需同步 ground truth 校准结果）
pub fn resolver_confidence(resolver: &str) -> f64 {
    match resolver {
        // 索引里的"被声明标识符"：标识符精确匹配声明行
        // （实测：真实仓库 ground truth 上 accuracy = 1.00）
        "symbol-index" => 0.95,
        // 索引 + 标识符边界（引用）：同名不同符号仍未消歧
        "symbol-index+identifier-boundary" => 0.9,
        // 函数体作用域内的调用名扫描（callees）/ 别名感知的调用点扫描（callers）
        "call-scan+body-scope" => 0.9,
        "call-scan+alias-aware" => 0.9,
        // 索引剪枝 + 旧逐行启发式（历史值；实测真实仓库 accuracy 0.48，已不再是引用主路径）
        "symbol-index+line-heuristic" => 0.5,
        // 纯文件/行启发式
        "file-heuristic" => 0.5,
        _ => default_evidence_confidence(),
    }
}

/// 不确定度：显式暴露"猜"和"未解析"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Uncertainty {
    pub level: String,
    pub reasons: Vec<String>,
    pub unresolved_edges: u32,
}

impl Uncertainty {
    pub fn new(level: &str, reasons: &[&str], unresolved: u32) -> Self {
        Self {
            level: level.to_string(),
            reasons: reasons.iter().map(|s| s.to_string()).collect(),
            unresolved_edges: unresolved,
        }
    }
}

/// 工具响应 envelope。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelEnvelope {
    pub data: Value,
    pub provenance: Vec<Provenance>,
    pub uncertainty: Uncertainty,
}

/// 高阶能力枚举（每个对应一个工具名）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntelKind {
    ProjectIndex,
    SymbolDefinition,
    SymbolReferences,
    CallHierarchy,
    SliceBackward,
    DataflowPath,
    SanitizerGuards,
    FrameworkContext,
    IncrementalStatus,
}

impl IntelKind {
    pub fn all() -> [IntelKind; 9] {
        [
            IntelKind::ProjectIndex,
            IntelKind::SymbolDefinition,
            IntelKind::SymbolReferences,
            IntelKind::CallHierarchy,
            IntelKind::SliceBackward,
            IntelKind::DataflowPath,
            IntelKind::SanitizerGuards,
            IntelKind::FrameworkContext,
            IntelKind::IncrementalStatus,
        ]
    }

    pub fn name(&self) -> &'static str {
        match self {
            IntelKind::ProjectIndex => "get_project_index",
            IntelKind::SymbolDefinition => "get_symbol_definition",
            IntelKind::SymbolReferences => "get_symbol_references",
            IntelKind::CallHierarchy => "get_call_hierarchy",
            IntelKind::SliceBackward => "slice_backward",
            IntelKind::DataflowPath => "get_dataflow_path",
            IntelKind::SanitizerGuards => "get_sanitizer_guards",
            IntelKind::FrameworkContext => "get_framework_context",
            IntelKind::IncrementalStatus => "get_incremental_status",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            IntelKind::ProjectIndex => "项目索引状态：文件数/语言分布/索引指纹",
            IntelKind::SymbolDefinition => "跨文件符号定义（启发式；未接 LSP/SCIP）",
            IntelKind::SymbolReferences => "跨文件符号引用（含 import alias 未解析提示）",
            IntelKind::CallHierarchy => "函数上下游调用拓扑（callers/callees，未解析边入 uncertainty）",
            IntelKind::SliceBackward => "从 file:line 向前切出相关代码片段",
            IntelKind::DataflowPath => "source→sink 路径（行区间启发式）",
            IntelKind::SanitizerGuards => "变量路径上的条件分支/校验逻辑",
            IntelKind::FrameworkContext => "路由 handler 的前置中间件/拦截器链",
            IntelKind::IncrementalStatus => "增量索引状态：冷启动/缓存命中/待重编译清单（stat 指纹 + TTL 缓存）",
        }
    }
}

/// "语言冻结"的一等公民表达：只有这些语言有针对性分析路线（跨文件/守卫/框架 resolver）。
/// 其余语言只做文本级启发式索引——必须在响应里如实标注，而不是假装所有语言一视同仁。
const PRIMARY_ANALYSIS_LANGUAGES: [&str; 6] = [
    "python",
    "go",
    "javascript",
    "typescript",
    "php",
    "rust",
];

/// 语言能力报告：哪些主语言在场、哪些只有启发式索引
fn language_capabilities(langs: &std::collections::BTreeMap<&'static str, usize>) -> Value {
    let mut present_primary: Vec<&str> = Vec::new();
    let mut heuristic_only: Vec<&str> = Vec::new();
    for (lang, count) in langs {
        if *count == 0 || *lang == "other" {
            continue;
        }
        if PRIMARY_ANALYSIS_LANGUAGES.contains(lang) {
            present_primary.push(lang);
        } else {
            heuristic_only.push(lang);
        }
    }
    json!({
        "primary_analysis_languages": PRIMARY_ANALYSIS_LANGUAGES,
        "present_primary": present_primary,
        "heuristic_only_present": heuristic_only,
        "analysis_backed": !present_primary.is_empty(),
    })
}

fn should_skip(dir_name: &str) -> bool {
    // 跳过清单 + 一切点号目录：`.ctx-audit` 是工具自己的状态目录
    // （mcp_metrics.jsonl 每次工具调用都会追加），索引它会让缓存指纹永远失效。
    SKIP_DIRS.contains(&dir_name) || dir_name.starts_with('.')
}

/// 内容索引的文件数上限：`CTX_AUDIT_INDEX_MAX_FILES` 可覆盖（0/非法值回落默认）。
///
/// 默认 2000 是"把文件内容全部读进内存"时代的产物；调大只影响内存，
/// 符号工具（`get_symbol_definition`/`references`）已不受该上限约束。
fn max_index_files() -> usize {
    std::env::var("CTX_AUDIT_INDEX_MAX_FILES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(MAX_FILES)
}

/// 显式点名单文件时的读取上限（8MB）。
///
/// `MAX_FILE_BYTES` 约束的是**批量索引**（把 2000 个文件读进内存的成本）。调用方点名一个
/// 文件时只读这一个，成本 O(1)。此前两者共用同一上限，于是被索引跳过的文件会被回答成
/// "文件不存在"——内容其实就在盘上（实测：542KB 的生成产物、以及超出 2000 文件上限的
/// 命中文件，都被误报为不存在）。批量上限与显式请求上限必须解耦。
const MAX_EXPLICIT_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// 按需读取调用方**点名**的单个文件。
///
/// 失败信息必须给出**真实原因**（路径不存在 / 不是常规文件 / 超过单文件读取上限），
/// 不得把"我没有索引它"说成"文件不存在"——对 LLM 消费者而言，后者是在陈述一个错误的世界。
fn read_requested_file(root: &Path, rel: &str) -> Result<String, ToolError> {
    let path = root.join(rel);
    let meta = std::fs::metadata(&path).map_err(|_| {
        ToolError::InvalidArgument(format!("文件不存在: {rel}（磁盘与索引中都没有该路径）"))
    })?;
    if !meta.is_file() {
        return Err(ToolError::InvalidArgument(format!("不是常规文件: {rel}")));
    }
    if meta.len() > MAX_EXPLICIT_FILE_BYTES {
        return Err(ToolError::InvalidArgument(format!(
            "文件过大: {rel} = {} 字节 > 单文件读取上限 {} 字节（批量索引上限为 {} 字节）",
            meta.len(),
            MAX_EXPLICIT_FILE_BYTES,
            MAX_FILE_BYTES
        )));
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(content),
        // 非 UTF-8 源码（latin-1/GBK 注释）：按字节尽力转换，不因编码拒绝一个存在的文件
        Err(_) => Ok(String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default()).to_string()),
    }
}

pub fn language_of(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "rs" => "rust",
        "py" => "python",
        "go" => "go",
        "js" | "jsx" => "javascript",
        "ts" | "tsx" => "typescript",
        "java" => "java",
        "php" => "php",
        "rb" => "ruby",
        "ex" | "exs" => "elixir",
        "c" => "c",
        "h" | "hpp" => "c-header",
        "cpp" | "cc" | "cxx" => "cpp",
        "cs" => "csharp",
        "kt" => "kotlin",
        "swift" => "swift",
        "scala" => "scala",
        "clj" => "clojure",
        "lua" => "lua",
        "sh" => "shell",
        "sql" => "sql",
        "yaml" | "yml" => "yaml",
        "json" => "json",
        "toml" => "toml",
        _ => "other",
    }
}

/// 索引加载结果：文件内容 + 可观测上限事实 + stat 指纹。
struct LoadedIndex {
    files: Vec<(String, String)>,
    /// 因超过单文件大小上限而跳过的文件数
    skipped_large: usize,
    /// 是否因达到文件数上限而提前停止遍历
    truncated_at_limit: bool,
    /// 已索引文件的 stat 指纹（缓存失效探测用）
    file_stamps: Vec<crate::index_cache::FileStamp>,
    /// 已遍历目录的 stat 指纹（目录内增删的兜底探测）
    dir_stamps: Vec<crate::index_cache::DirStamp>,
}

/// 遍历项目文件并采集 stat 指纹（跳过目录不采集，也不计入指纹）。
fn load_files(root: &Path) -> LoadedIndex {
    use crate::index_cache::{mtime_ms, DirStamp, FileStamp};

    let mut out: Vec<(String, String)> = Vec::new();
    let mut file_stamps: Vec<FileStamp> = Vec::new();
    let mut dir_stamps: Vec<DirStamp> = Vec::new();
    let mut skipped_large = 0usize;
    let mut truncated_at_limit = false;
    let max_files = max_index_files();
    // 遍历顺序必须**确定性**：`read_dir` 返回顺序随文件系统而异，而"达到文件数上限就停"
    // 意味着取舍结果在机器之间不同（同一仓库可能索引到不同的文件子集，实测命中文件因此
    // 被漏掉并报成"文件不存在"）。改为：目录项排序 + 广度优先（浅目录优先 ⇒ 顶层源码
    // 先于深层测试夹具进索引）。
    let mut queue: std::collections::VecDeque<(PathBuf, String)> =
        std::collections::VecDeque::from([(root.to_path_buf(), String::new())]);
    while let Some((dir, dir_rel)) = queue.pop_front() {
        if out.len() >= max_files {
            truncated_at_limit = true;
            break;
        }
        // 目录指纹：目录内新增/删除/改名会改变目录 mtime，是文件级指纹的兜底
        if let Ok(meta) = std::fs::metadata(&dir) {
            dir_stamps.push(DirStamp {
                path: dir_rel.clone(),
                mtime_ms: mtime_ms(&meta),
            });
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !should_skip(&name) {
                    let child_rel = if dir_rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{dir_rel}/{name}")
                    };
                    queue.push_back((path, child_rel));
                }
                continue;
            }
            if out.len() >= max_files {
                truncated_at_limit = true;
                break;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() as usize > MAX_FILE_BYTES {
                skipped_large += 1;
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or(name.clone());
            if let Ok(content) = std::fs::read_to_string(&path) {
                file_stamps.push(FileStamp {
                    path: rel.clone(),
                    mtime_ms: mtime_ms(&meta),
                    size: meta.len(),
                });
                out.push((rel, content));
            }
        }
    }
    // 输出顺序同样做成确定性：`build_id` 与"取前 N 条"的取舍都依赖它
    out.sort_by(|a, b| a.0.cmp(&b.0));
    file_stamps.sort_by(|a, b| a.path.cmp(&b.path));
    LoadedIndex {
        files: out,
        skipped_large,
        truncated_at_limit,
        file_stamps,
        dir_stamps,
    }
}

fn build_id(files: &[(String, String)]) -> String {
    let bytes: usize = files.iter().map(|(_, c)| c.len()).sum();
    format!("statv1:{}f:{}b", files.len(), bytes)
}

fn prov(file: &str, line: u32, id: &str) -> Provenance {
    let resolver = "file-heuristic";
    Provenance {
        file: Some(file.to_string()),
        line: Some(line),
        resolver: resolver.to_string(),
        build_id: id.to_string(),
        confidence: resolver_confidence(resolver),
    }
}

/// 指定 resolver 的 provenance（如 `symbol-index`）
fn prov_with(file: &str, line: u32, id: &str, resolver: &str) -> Provenance {
    Provenance {
        file: Some(file.to_string()),
        line: Some(line),
        resolver: resolver.to_string(),
        build_id: id.to_string(),
        confidence: resolver_confidence(resolver),
    }
}

/// 符号索引的可观测状态（供响应体如实上报）
/// 空结果的**可观测性分类**：把"索引里根本没有该符号"与"索引里有线索但没抽出结果"分开。
///
/// 动机：`total_hits = 0` 曾同时表示两件含义相反的事——"符号不存在"（正常答案）与
/// "定义抽取漏收"（**覆盖缺口**，既是索引排查的信号，也是"全项目联动"实验的仪器读数）。
fn empty_definition_kind(index: &crate::symbol_index::SymbolIndex, symbol: &str) -> &'static str {
    if index.identifier_occurrence_count(symbol) == 0 {
        "no_match"
    } else {
        "index_miss"
    }
}

/// 引用空结果的分类：`no_match`（索引里没有）/ `index_miss`（有出现但无定义）/
/// `definition_only`（只在定义处出现，确实没有引用）。
fn empty_reference_kind(index: &crate::symbol_index::SymbolIndex, symbol: &str) -> &'static str {
    if index.identifier_occurrence_count(symbol) == 0 {
        "no_match"
    } else if index.definitions(symbol, usize::MAX).is_empty() {
        "index_miss"
    } else {
        "definition_only"
    }
}

fn symbol_index_stats(
    index: &crate::symbol_index::SymbolIndex,
    hit: crate::symbol_index::HitSource,
    build_ms: u64,
) -> Value {
    json!({
        "files_indexed": index.file_count(),
        "symbols": index.symbol_count(),
        "identifiers": index.identifier_symbols(),
        "identifier_occurrences": index.identifier_count(),
        "parsed_files": index.parsed_files(),
        "hit_source": hit.as_str(),
        "build_ms": build_ms,
        "age_ms": index.build_age().as_millis() as u64,
        "skipped_large_files": index.skipped_large(),
        "skipped_non_code_files": index.skipped_non_code(),
        "truncated_at_limit": index.truncated(),
        "match": "identifier_exact",
    })
}

/// 纯函数：定义行启发式。
pub fn find_definitions(content: &str, symbol: &str) -> Vec<(u32, String)> {
    let keywords = [
        "fn ", "def ", "func ", "function ", "class ", "struct ", "enum ", "interface ",
        "trait ", "const ", "type ", "module ", "namespace ", "object ",
    ];
    let mut hits = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains(symbol) && keywords.iter().any(|k| trimmed.contains(*k)) {
            hits.push(((idx + 1) as u32, trimmed.chars().take(200).collect()));
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    hits
}

// 行级代码段工具（去注释/字符串 + 标识符边界）统一放在 `text_scan`，此处重导出保持调用点不变。
// 实测依据：整行子串匹配让 `App` 命中 `_AppCtxGlobals`、`copy` 命中 `deepcopy`（引用精度 0.48）；
// 字符串/行内注释里的同名 token 是剩余误报来源（oracle 只计 NAME token）。
pub use crate::text_scan::{call_site_match, code_lines, contains_identifier, hash_comment_language};

/// 纯函数：引用行扫描（标识符边界 + **精确**排除该符号的真实定义行）。
///
/// 与旧 `find_references` 的两点差别（都有实测依据）：
/// - 旧实现整行子串匹配 → 真实仓库 precision 0.48；
/// - 旧实现用"这行看起来像定义"来排除定义行 → 会把恰好含 def 关键字的真实引用行也排掉（recall 0.73）。
///   现在由符号索引给出该符号的真实定义行，精确排除。
pub fn find_references_exact(
    original: &[&str],
    code: &[String],
    symbol: &str,
    def_lines: &std::collections::HashSet<u32>,
) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, code_line) in code.iter().enumerate() {
        let lineno = (idx + 1) as u32;
        if def_lines.contains(&lineno) {
            continue;
        }
        if !contains_identifier(code_line.trim(), symbol) {
            continue;
        }
        let text = original
            .get(idx)
            .map(|l| l.trim().chars().take(200).collect::<String>())
            .unwrap_or_default();
        hits.push((lineno, text));
    }
    hits
}

/// 纯函数：调用点扫描（**代码段**判定 + 左边界），返回 `(行号, 原文行)`。
///
/// 用代码段而非原文，避免字符串/注释里的 `name(` 被当成调用点。
pub fn find_call_sites_in_code(
    original: &[&str],
    code: &[String],
    name: &str,
    limit: usize,
) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, code_line) in code.iter().enumerate() {
        let trimmed = code_line.trim();
        if !call_site_match(trimmed, name) {
            continue;
        }
        let def_like = ["fn ", "def ", "func ", "function "]
            .iter()
            .any(|k| trimmed.contains(*k));
        if def_like {
            continue;
        }
        let text = original
            .get(idx)
            .map(|l| l.trim().chars().take(200).collect::<String>())
            .unwrap_or_default();
        hits.push(((idx + 1) as u32, text));
        if hits.len() >= limit {
            break;
        }
    }
    hits
}

/// 纯函数：引用行启发式（排除定义行）。
pub fn find_references(content: &str, symbol: &str) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.contains(symbol) {
            continue;
        }
        let is_def = !find_definitions(trimmed, symbol).is_empty();
        if !is_def {
            hits.push(((idx + 1) as u32, trimmed.chars().take(200).collect()));
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    hits
}

/// 纯函数：调用点启发式（`name(`，排除定义行）。
pub fn find_call_sites(content: &str, name: &str) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        // 左边界校验：`myread(` 不算 `read(` 的调用点
        if !call_site_match(trimmed, name) {
            continue;
        }
        let def_like = ["fn ", "def ", "func ", "function "]
            .iter()
            .any(|k| trimmed.contains(*k));
        if !def_like {
            hits.push(((idx + 1) as u32, trimmed.chars().take(200).collect()));
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    hits
}

/// 该文件是否用花括号界定函数体（决定 body_span 用配对括号还是缩进）
pub fn is_brace_language(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    !matches!(ext.as_str(), "py" | "rb" | "ex" | "exs" | "clj" | "lua")
}

fn indent_width(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// 与最后一个 `)` 配对的 `(` 的位置（用于取出"名字("）。
fn matching_open_paren(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices().rev() {
        match ch {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// 判断一行是否像**函数头**，并尽力取出函数名（空串表示匿名）。
///
/// `next` 为**之后首个非空行**，用于识别 C/C++ 的多行签名
/// （`static ngx_int_t` / `ngx_http_foo(...)` / `{` 分三行，名字行不以 `{` 结尾）。
///
/// 为什么需要它：符号索引的 `declared_names()` 只能从**关键字**形态抽取声明，而
/// ① JS/TS 极常见的是匿名函数表达式/箭头函数赋给属性或变量；
/// ② C/C++ 定义**根本没有关键字**（`static int foo(int a) {`）——
/// 这两类在索引里都没有声明，切片会退化成"无函数头的前缀窗口"。
///
/// 只做**行级**判断，不解析作用域；取不到名字时返回空串，由调用方用属性/变量名回填。
pub fn function_header_name_ctx(text: &str, next: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() || t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
        return None;
    }
    // `name: …` / `name = …` 左侧的最后一个标识符
    let lhs_name = |s: &str| -> Option<String> {
        let sep = s.find(':').into_iter().chain(s.find('=')).min()?;
        let lhs = s[..sep].trim();
        let name: String = lhs
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if name
            .chars()
            .next()
            .map(|c| c.is_alphabetic() || c == '_')
            .unwrap_or(false)
        {
            Some(name)
        } else {
            None
        }
    };
    for kw in ["function", "def", "func", "fn"] {
        let mut from = 0usize;
        while let Some(pos) = t[from..].find(kw) {
            let abs = from + pos;
            from = abs + kw.len();
            // 关键字前后都必须是标识符边界：`define(` 里的 `def`、`myfn(` 里的 `fn` 都不算
            let before_ok = abs == 0
                || !t[..abs]
                    .chars()
                    .next_back()
                    .map(|c| c.is_alphanumeric() || c == '_' || c == '$')
                    .unwrap_or(false);
            let tail = &t[abs + kw.len()..];
            let boundary_ok = tail
                .chars()
                .next()
                .map(|c| !(c.is_alphanumeric() || c == '_' || c == '$'))
                .unwrap_or(true);
            if !before_ok || !boundary_ok {
                continue;
            }
            // 关键字与 `(` 之间**可以没有空格**：`function(then) {` 是 JS 匿名函数的常见写法
            //（旧实现的关键字表带尾空格，因此漏掉它并把 `function` 当成了函数名）。
            let rest = tail.trim_start();
            let rest = rest.strip_prefix('*').unwrap_or(rest).trim_start(); // function* gen
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            let after = rest[name.len()..].trim_start();
            if !name.is_empty() && after.starts_with('(') {
                return Some(name);
            }
            if rest.starts_with('(') {
                return Some(lhs_name(t).unwrap_or_default()); // 匿名：回填属性/变量名
            }
        }
    }
    if t.contains("=>") {
        return Some(lhs_name(t).unwrap_or_default());
    }
    // C/C++ 风格定义（无关键字）：`类型 名字(参数)` 且该行以 `{` 结尾、
    // 或名字行以 `)` 结尾而下一非空行以 `{` 开头。
    // 控制语句与调用因此都不会命中：`if (a) {` 的动作名在排除表里，`foo(bar);` 不以 `{` 结尾。
    // 已知近似：C++ 构造函数的初始化列表（`Foo::Foo() : a(1) {`）会取到 `a` 而非 `Foo::Foo`。
    c_style_header_name(t, next)
}

/// 只走 **C/C++ 无关键字定义** 这一条分支：`类型 名字(参数) {`（签名可跨行）。
///
/// 单独成函数，是因为"向下拼接多行"的调用点**只能**用这条分支：关键字分支一旦看到被拼接
/// 进来的后续行，就会把后面某个 `def`/`function` 当成本行的签名——实测模块级
/// `_is_image_dataurl = re.compile(` 拼到后面的 `def _is_javascript_scheme(s):`，
/// 把模块级代码误报成"有函数作用域"（假改善会计进度量）。
fn c_style_header_name(text: &str, next: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let starts_block =
        t.ends_with('{') || (t.ends_with(')') && next.trim_start().starts_with('{'));
    if starts_block {
        let head_src = t.trim_end_matches('{').trim_end();
        if head_src.ends_with(')') {
            if let Some(open) = matching_open_paren(head_src) {
                let head = head_src[..open].trim_end();
                let name: String = head
                    .chars()
                    .rev()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let ctrl = matches!(
                    name.as_str(),
                    "if" | "for" | "while" | "switch" | "catch" | "do" | "else" | "return"
                        | "sizeof" | "synchronized" | "finally" | "try" | "using" | "lock"
                        | "foreach" | "with" | "when" | "assert" | "new" | "delete" | "throw"
                        | "function" | "def" | "func" | "fn"
                );
                if !name.is_empty() && !ctrl {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// 多行签名版：`following` 为**之后最多 6 条非空代码行**（已 trim 前）。
///
/// 为什么需要它：C/C++ 的签名经常跨 **3 行以上**（实测
/// `static cmark_node *try_opening_table_header(` / `cmark_parser *parser,` /
/// `… unsigned char *input, int len) {`），而两行判定要求"名字行以 `)` 结尾、下一行以 `{` 开头"，
/// 于是这类函数一律被判成"找不到函数头"，长函数的作用域因此静默变成 unresolved。
pub fn function_header_name_multi(text: &str, following: &[&str]) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    // 先按原两行规则判（覆盖绝大多数形态，且行为与既有测试一致）
    if let Some(n) = function_header_name_ctx(t, following.first().copied().unwrap_or("")) {
        return Some(n);
    }
    // 只有"签名尚未闭合"（圆括号不配对）时才允许向下拼接。
    // 否则会**跨语句**把后面某个函数声明当成当前行的签名续行：实测
    // `var x = require('y')` 后跟 `function f() {` 被拼成一个"函数头"，
    // 于是模块级代码被误报成有函数作用域（把假改善算进度量）。
    let mut depth = 0i32;
    for ch in t.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    if depth <= 0 {
        return None;
    }
    // 再把后续行拼进来：拼到出现 `{` 为止，最多 6 行（拼完仍未闭合则判定自然不成立）
    let mut joined = t.to_string();
    for s in following.iter().take(6) {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        joined.push(' ');
        joined.push_str(s);
        if s.contains('{') {
            break;
        }
    }
    if joined != t {
        // 只认 C 风格：拼接结果必须形如 `类型 名字(…参数…) {`
        if let Some(n) = c_style_header_name(&joined, "") {
            return Some(n);
        }
    }
    None
}

/// 兼容无下一行信息的调用点。
pub fn function_header_name(text: &str) -> Option<String> {
    function_header_name_ctx(text, "")
}

/// 纯函数：估算某个定义所在函数的体范围（0-based，含首尾）。
///
/// - 花括号语言：从定义行的首个 `{` 起配对括号；
/// - 缩进语言（Python/Ruby/...）：取缩进大于定义行的后续行（空行不断开）；
/// - 找不到体时退化为定义行本身。
pub fn body_span(lines: &[&str], def_idx: usize, brace: bool) -> (usize, usize) {
    if def_idx >= lines.len() {
        return (def_idx, def_idx);
    }
    if brace {
        let mut depth: i32 = 0;
        let mut started = false;
        for (offset, line) in lines.iter().enumerate().skip(def_idx) {
            for ch in line.chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if started && depth <= 0 {
                return (def_idx, offset);
            }
            // 多行签名允许上溯若干行；超限则放弃
            if !started && offset > def_idx + 30 {
                break;
            }
        }
        (def_idx, def_idx)
    } else {
        // 先跳过"多行签名"：签名收尾行常从第 0 列开始（如 Python 的 `) -> T:`），
        // 若拿定义行缩进当基准会把函数体当 dedent 立即截断（实测导致切片漏函数头）。
        // 用括号平衡定位签名结束更稳。
        let mut depth: i32 = 0;
        let mut header_end = def_idx;
        for (offset, line) in lines.iter().enumerate().skip(def_idx) {
            for ch in line.chars() {
                match ch {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 {
                header_end = offset;
                break;
            }
        }
        let body_start = header_end + 1;
        // dedent 阈值仍取**定义行缩进**（外层缩进）；只是扫描从签名之后开始，
        // 这样多行签名的收尾行不会被误当成函数体结束。
        let outer = indent_width(lines[def_idx]);
        let mut end = header_end;
        for (idx, line) in lines.iter().enumerate().skip(body_start) {
            if line.trim().is_empty() {
                end = idx;
                continue;
            }
            if indent_width(line) <= outer {
                break;
            }
            end = idx;
        }
        (def_idx, end)
    }
}

/// 纯函数：抽取**命名导入**的别名对 `(被导入的符号名, 文件内本地名)`。
///
/// 只处理能被静态确定的形态：
/// - JS/TS：`import { a as b, c } from "..."`、`import Def, { a as b } from "..."`
/// - Python：`from x import a as b, c`
///
/// 默认导入（`import Store from ...`）与命名空间导入（`import * as ns`）不产生别名对
/// （本地名与导出名之间没有可静态推导的对应关系）。逐行解析，跨行的括号导入不支持。
pub fn import_aliases(content: &str) -> Vec<(String, String)> {
    fn is_ident(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    }

    let mut out: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        let clause: &str = if trimmed.starts_with("import") || trimmed.starts_with("export") {
            match (trimmed.find('{'), trimmed.find('}')) {
                (Some(s), Some(e)) if e > s => &trimmed[s + 1..e],
                _ => continue,
            }
        } else if trimmed.starts_with("from") {
            match trimmed.find("import") {
                Some(p) => trimmed[p + "import".len()..].trim(),
                None => continue,
            }
        } else {
            continue;
        };

        let clause = clause.trim().trim_start_matches('(').trim_end_matches(')');
        for item in clause.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (imported, local) = match item.split_once(" as ") {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (item, item),
            };
            if !is_ident(imported) || !is_ident(local) {
                continue;
            }
            out.push((imported.to_string(), local.to_string()));
        }
    }
    out
}

/// 纯函数：判断某行是否位于 `interface { ... }` 块内（Go/Java/TS 接口方法声明）。
///
/// 用于把"接口方法声明"从"调用点"里排除：`Read(p []byte) (int, error)` 会被
/// `name(` 匹配到，但它不是任何人的调用点（ground truth 上表现为 precision 0.5）。
pub fn in_interface_block(lines: &[&str], idx: usize) -> bool {
    if idx >= lines.len() {
        return false;
    }
    let mut depth: i32 = 0;
    let mut i = idx;
    loop {
        for ch in lines[i].chars().rev() {
            match ch {
                '}' => depth += 1,
                '{' => {
                    if depth == 0 {
                        return lines[i].contains("interface");
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        if i == 0 {
            return false;
        }
        i -= 1;
    }
}

/// 结构性关键词：它们后面跟 `(` 但不是调用点。
///
/// 真实 Go 仓库实测依据：匿名函数字面量 `func(c *Config) {`、`go func() {`、`defer func() {`
/// 会让 `callee_names` 产出名为 `func`/`go`/`defer` 的"callee"，直接污染调用图精度。
const NON_CALL_KEYWORDS: &[&str] = &[
    "func", "if", "for", "switch", "select", "go", "defer", "range", "case", "default",
    "return", "struct", "interface", "map", "chan", "type", "var", "const", "else", "package",
    "import", "break", "continue", "goto", "fallthrough", "while", "catch", "elif", "except",
    "with", "lambda", "yield", "match", "when", "do", "then", "begin", "ensure", "rescue",
    // C/C++ 的**运算符与内建形式**：`sizeof(x)`、`_Alignof(int)`、`offsetof(...)` 长得像调用，
    // 实测会被当成 callee 混进调用图（C 语言台阶：真值比对时在抽样里直接看到 `sizeof`）。
    "sizeof", "_Alignof", "__alignof__", "__alignof", "alignof", "typeof", "__typeof__",
    "__typeof", "offsetof", "defined", "va_arg", "va_start", "va_end", "va_copy",
    "_Generic", "static_assert", "_Static_assert",
];

/// 纯函数：从一行里提取 `(` 前的标识符（取最后一个点后的名字），过滤结构性关键词。
pub fn callee_names(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(pos) = rest.find('(') {
        let before = &rest[..pos];
        let raw: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let name = raw.rsplit('.').next().unwrap_or("").to_string();
        if name.len() >= 2
            && !NON_CALL_KEYWORDS.contains(&name.as_str())
            && !out.contains(&name)
        {
            out.push(name);
        }
        rest = &rest[pos + 1..];
    }
    out
}

fn str_param(name: &str, desc: &str, required: bool) -> ToolParameter {
    ToolParameter {
        name: name.to_string(),
        param_type: ToolParameterType::String,
        description: desc.to_string(),
        required,
        default: None,
        enum_values: None,
        format: None,
        items: None,
        properties: None,
    }
}

fn int_param(name: &str, desc: &str, default: i64) -> ToolParameter {
    ToolParameter {
        name: name.to_string(),
        param_type: ToolParameterType::Integer,
        description: desc.to_string(),
        required: false,
        default: Some(json!(default)),
        enum_values: None,
        format: None,
        items: None,
        properties: None,
    }
}

fn bool_param(name: &str, desc: &str) -> ToolParameter {
    ToolParameter {
        name: name.to_string(),
        param_type: ToolParameterType::Boolean,
        description: desc.to_string(),
        required: false,
        default: Some(json!(false)),
        enum_values: None,
        format: None,
        items: None,
        properties: None,
    }
}

/// 通用的高阶代码智能工具（按 kind 分派）。
pub struct CodeIntelTool {
    project_path: String,
    kind: IntelKind,
}

impl CodeIntelTool {
    pub fn new(project_path: String, kind: IntelKind) -> Self {
        Self { project_path, kind }
    }

    fn params(&self) -> Vec<ToolParameter> {
        let mut params = match self.kind {
            IntelKind::ProjectIndex | IntelKind::IncrementalStatus => vec![],
            IntelKind::SymbolDefinition | IntelKind::SymbolReferences => {
                vec![str_param("symbol", "符号名", true)]
            }
            IntelKind::CallHierarchy => vec![
                str_param("function", "函数名", true),
                str_param("direction", "callers|callees|both（默认 both）", false),
            ],
            IntelKind::SliceBackward => vec![
                str_param("file", "相对路径", true),
                int_param("line", "目标行号（可选）", 0),
                str_param("symbol", "目标符号（可选）", false),
                int_param("depth", "向前行数窗口（默认 40）", 40),
            ],
            IntelKind::DataflowPath => vec![
                str_param("source", "源符号/变量", true),
                str_param("sink", "汇符号/调用（可选）", false),
                str_param("file", "限定文件（可选）", false),
            ],
            IntelKind::SanitizerGuards => vec![
                str_param("file", "相对路径", true),
                int_param("line", "目标行号（可选）", 0),
            ],
            IntelKind::FrameworkContext => vec![
                str_param("file", "相对路径", true),
                str_param("handler", "handler 名（可选）", false),
            ],
        };
        // 索引缓存开关：所有能力都允许强制重建（索引底座）
        params.push(bool_param(
            "refresh",
            "强制重建索引缓存（默认 false；TTL 由 CTX_AUDIT_INDEX_TTL_MS 控制）",
        ));
        params
    }
}

#[async_trait]
impl Tool for CodeIntelTool {
    fn name(&self) -> &str {
        self.kind.name()
    }

    fn description(&self) -> &str {
        self.kind.description()
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        let mut def = ToolDefinition::new(self.name(), self.description(), ToolCategory::Analysis);
        for p in self.params() {
            def = def.add_parameter(p);
        }
        def
    }

    async fn execute(&self, input: Value) -> Result<ToolResult, ToolError> {
        let root = Path::new(&self.project_path);
        let refresh = input
            .get("refresh")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ttl = crate::index_cache::default_ttl();
        // 索引缓存：TTL 内复用同一份索引，避免每次调用重新遍历项目
        let (index, hit) = crate::index_cache::get_or_build(root, refresh, ttl, || {
            let loaded = load_files(root);
            let build_id = build_id(&loaded.files);
            crate::index_cache::ProjectIndex {
                root: root.to_string_lossy().to_string(),
                files: loaded.files,
                build_id,
                skipped_large: loaded.skipped_large,
                truncated_at_limit: loaded.truncated_at_limit,
                file_stamps: loaded.file_stamps,
                dir_stamps: loaded.dir_stamps,
                built_at: std::time::Instant::now(),
            }
        });
        let cache_hit = hit.is_hit();
        let files: &[(String, String)] = &index.files;
        let id = index.build_id.clone();
        let env: IntelEnvelope = match self.kind {
            IntelKind::ProjectIndex => {
                let mut langs: std::collections::BTreeMap<&'static str, usize> =
                    std::collections::BTreeMap::new();
                for (path, _) in files {
                    *langs.entry(language_of(path)).or_insert(0) += 1;
                }
                let freshness = if crate::index_cache::probe_enabled() {
                    "stat+mtime-probe + TTL cache (dir stamps cover add/remove)"
                } else {
                    "stat + TTL cache (probe disabled by CTX_AUDIT_INDEX_PROBE)"
                };
                let caps = language_capabilities(&langs);
                let analysis_backed = caps["analysis_backed"].as_bool().unwrap_or(false);
                let mut cap_reasons: Vec<&str> = vec!["index_is_stat_based"];
                if !analysis_backed {
                    cap_reasons.push("project_language_outside_primary_set");
                }
                IntelEnvelope {
                    data: json!({
                        "files": files.len(),
                        "languages": langs,
                        "build_id": id,
                        "index_freshness": freshness,
                        "capabilities": caps,
                        "limits": {
                            "max_files": max_index_files(),
                            "max_file_bytes": MAX_FILE_BYTES,
                            "skipped_large_files": index.skipped_large,
                            "truncated_at_limit": index.truncated_at_limit,
                        },
                        "cache": {
                            "hit": cache_hit,
                            "hit_source": hit.as_str(),
                            "age_ms": index.age().as_millis() as u64,
                            "ttl_ms": ttl.as_millis() as u64,
                            "refresh": refresh,
                        },
                    }),
                    provenance: vec![prov(".", 0, &id)],
                    uncertainty: Uncertainty::new(
                        if analysis_backed { "low" } else { "high" },
                        &cap_reasons,
                        0,
                    ),
                }
            }
            IntelKind::SymbolDefinition => {
                let symbol = input["symbol"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 symbol 参数".to_string()))?;
                // 走符号索引（反向表哈希查找），不再逐文件读盘 + 全量扫描
                let (sindex, s_hit, s_build_ms) =
                    crate::symbol_index::get_or_build(root, refresh, None);
                // 先取全量再截断：如实上报"总共多少处 / 是否被截断"（`index` 这类符号可上百处定义）
                let all_hits = sindex.definitions(symbol, usize::MAX);
                let total_hits = all_hits.len();
                let truncated_at_limit = total_hits > MAX_DEFINITION_HITS;
                let hits: Vec<_> = all_hits.into_iter().take(MAX_DEFINITION_HITS).collect();
                let provenance: Vec<Provenance> = hits
                    .iter()
                    .map(|h| prov_with(sindex.file_path(h.file), h.line, &id, "symbol-index"))
                    .collect();
                let defs: Vec<Value> = hits
                    .iter()
                    .map(|h| {
                        json!({
                            "file": sindex.file_path(h.file),
                            "line": h.line,
                            "text": h.text,
                        })
                    })
                    .collect();
                let level = if defs.is_empty() { "high" } else { "low" };
                let mut reasons: Vec<&str> = vec![
                    "definitions_are_identifier_exact",
                    "import_alias_not_resolved",
                    "not_lsp_resolved",
                    "index_covers_code_files_only",
                ];
                if defs.is_empty() {
                    reasons.push("no_definition_in_index");
                }
                // 空结果分类：`total_hits = 0` 曾同时表示"符号不存在"（正常答案）与
                // "定义抽取漏收"（覆盖缺口）。后者正是全项目联动实验的仪器读数。
                let identifier_lines = sindex.identifier_occurrence_count(symbol);
                let empty_kind: Option<&str> = if !defs.is_empty() {
                    None
                } else if identifier_lines == 0 {
                    reasons.push("symbol_absent_from_index");
                    Some("no_match")
                } else {
                    reasons.push("definition_missing_but_identifier_present");
                    Some("index_miss")
                };
                IntelEnvelope {
                    data: json!({
                        "symbol": symbol,
                        "definitions": defs,
                        "total_hits": total_hits,
                        "limit": MAX_DEFINITION_HITS,
                        "truncated_at_limit": truncated_at_limit,
                        "empty_kind": empty_kind,
                        "identifier_lines": identifier_lines,
                        "index": symbol_index_stats(&sindex, s_hit, s_build_ms),
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(level, &reasons, 0),
                }
            }
            IntelKind::SymbolReferences => {
                let symbol = input["symbol"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 symbol 参数".to_string()))?;
                // 引用：布隆过滤器先剪掉"不可能含该子串"的文件；命中的候选文件里
                // 再按**标识符边界**判定，并用符号索引给出的**真实定义行**精确排除定义行。
                // （真实仓库实测：旧子串+启发式排除的 F1 只有 0.58——`App` 命中 `_AppCtxGlobals`。）
                let (sindex, s_hit, s_build_ms) =
                    crate::symbol_index::get_or_build(root, refresh, None);

                // 该符号在各文件里的**真实定义行**（用于精确排除，替代"看起来像定义"的启发式）
                let mut def_lines_by_file: std::collections::HashMap<
                    String,
                    std::collections::HashSet<u32>,
                > = std::collections::HashMap::new();
                for hit in sindex.definitions(symbol, usize::MAX) {
                    def_lines_by_file
                        .entry(sindex.file_path(hit.file).to_string())
                        .or_default()
                        .insert(hit.line);
                }

                // 引用改为**倒排表查询**（不再逐文件扫描）：命中位置取自代码段
                // （注释/字符串已剥离），因此"字符串里的同名 token"天然不进结果。
                let mut by_file: std::collections::BTreeMap<usize, Vec<u32>> =
                    std::collections::BTreeMap::new();
                for (file_idx, line) in sindex.identifier_hits(symbol) {
                    let rel = sindex.file_path(file_idx);
                    if def_lines_by_file
                        .get(rel)
                        .map(|s| s.contains(&line))
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    by_file.entry(file_idx).or_default().push(line);
                }
                let candidate_count = by_file.len();

                let mut collected: Vec<(String, u32, String)> = Vec::new();
                let mut scanned_files = 0usize;
                for (file_idx, mut lines) in by_file {
                    let rel = sindex.file_path(file_idx);
                    let content = match std::fs::read_to_string(root.join(rel)) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    scanned_files += 1;
                    lines.sort_unstable();
                    let originals: Vec<&str> = content.lines().collect();
                    for line in lines {
                        let text = originals
                            .get((line as usize).saturating_sub(1))
                            .map(|l| l.trim().chars().take(200).collect::<String>())
                            .unwrap_or_default();
                        collected.push((rel.to_string(), line, text));
                    }
                }

                // 确定性：先排序再截断（旧实现按文件枚举顺序边扫边截，40 条上限会偏袒靠前文件）
                collected.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
                let total_hits = collected.len();
                let truncated_at_limit = total_hits > MAX_REFERENCE_HITS;
                collected.truncate(MAX_REFERENCE_HITS);

                let provenance: Vec<Provenance> = collected
                    .iter()
                    .map(|(file, line, _)| {
                        prov_with(file, *line, &id, "symbol-index+identifier-boundary")
                    })
                    .collect();
                let refs: Vec<Value> = collected
                    .iter()
                    .map(|(file, line, text)| json!({"file": file, "line": line, "text": text}))
                    .collect();
                // 空结果分类（与 get_symbol_definition 同口径）。
                let identifier_lines = sindex.identifier_occurrence_count(symbol);
                let empty_kind: Option<&str> = if refs.is_empty() {
                    Some(empty_reference_kind(&sindex, symbol))
                } else {
                    None
                };
                let mut reference_reasons: Vec<&str> = vec![
                    "same_name_not_disambiguated",
                    "not_lsp_resolved",
                    "index_covers_code_files_only",
                    "identifier_boundary_matching",
                    "strings_and_comments_excluded",
                ];
                if let Some(kind) = empty_kind {
                    reference_reasons.push(match kind {
                        "no_match" => "symbol_absent_from_index",
                        "index_miss" => "definition_missing_but_identifier_present",
                        _ => "symbol_defined_but_never_referenced",
                    });
                }
                IntelEnvelope {
                    data: json!({
                        "symbol": symbol,
                        "references": refs,
                        "total_hits": total_hits,
                        "limit": MAX_REFERENCE_HITS,
                        "truncated_at_limit": truncated_at_limit,
                        "empty_kind": empty_kind,
                        "identifier_lines": identifier_lines,
                        "index": symbol_index_stats(&sindex, s_hit, s_build_ms),
                        "candidate_files": candidate_count,
                        "scanned_files": scanned_files,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new("medium", &reference_reasons, 0),
                }
            }
            IntelKind::CallHierarchy => {
                let function = input["function"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 function 参数".to_string()))?;
                let direction = input["direction"].as_str().unwrap_or("both");
                let mut callers: Vec<Value> = Vec::new();
                let mut callees: Vec<Value> = Vec::new();
                let mut provenance: Vec<Provenance> = Vec::new();
                let mut unresolved = 0u32;
                let dynamic_markers =
                    ["getattr", "eval(", "apply(", "invoke(", "call_user_func", "Reflect."];
                // 符号索引：callees 必须用**标识符精确**的定义——子串式 `find_definitions` 会把
                // `TestConfig_ValidateAndSetDefaults(` 当成 `Validate` 的定义，再把它整个函数体
                // 当成 `Validate` 的体，收集出成批假 callee（真实 Go 仓库上 callees 精度≈0）。
                let (sindex, _s_hit, _s_build) =
                    crate::symbol_index::get_or_build(root, refresh, None);
                let mut matched_callers = 0usize;
                let mut matched_callees = 0usize;
                // 扫描上限比返回上限宽：用于如实统计"总共有多少"（上限纪律）
                let scan_cap = MAX_CALL_GRAPH_HITS * 4;
                for (path, content) in files {
                    // 调用图只在代码文件上做：内容索引包含 markdown/yaml/json，
                    // 其中的代码片段会伪装成调用点（真实 Go 仓库的 AGENTS.md 曾混进 callees）
                    if !crate::symbol_index::is_code_file(path) {
                        continue;
                    }
                    if direction != "callees" {
                        // 调用点匹配要覆盖**导入别名**（`import { put as save }` / `Loader as Ldr`），
                        // 否则真实调用点用本地名就没有（ground truth 上 recall=0）。
                        let lines: Vec<&str> = content.lines().collect();
                        // 调用点也在**代码段**上判定：字符串/注释里的 `name(` 不算调用
                        let code = code_lines(content, hash_comment_language(path));
                        let mut needles: Vec<String> = vec![function.to_string()];
                        for (imported, local) in import_aliases(content) {
                            if imported == function && !needles.contains(&local) {
                                needles.push(local);
                            }
                        }
                        let mut seen_callers: std::collections::HashSet<(String, u32)> =
                            std::collections::HashSet::new();
                        for needle in &needles {
                            for (line, text) in find_call_sites_in_code(&lines, &code, needle, scan_cap) {
                                let idx = (line as usize).saturating_sub(1);
                                // 接口/抽象方法**声明**不是调用点（Go/Java/TS 接口体）
                                if in_interface_block(&lines, idx) {
                                    continue;
                                }
                                if !seen_callers.insert((path.clone(), line)) {
                                    continue;
                                }
                                matched_callers += 1;
                                if callers.len() < scan_cap {
                                    provenance.push(prov_with(
                                        path,
                                        line,
                                        &id,
                                        "call-scan+alias-aware",
                                    ));
                                    callers.push(json!({"file": path, "line": line, "text": text}));
                                }
                            }
                        }
                    }
                    if direction != "callers" {
                        // callees 必须限定在**目标函数的函数体内**：
                        // 早先的实现把"文件里出现过的所有调用"都算成 callee，
                        // ground truth 基线上精度只有 0.53（把同文件无关函数也算进来）。
                        let lines: Vec<&str> = content.lines().collect();
                        // 体范围判定用**代码段**：函数体内的多行字符串若含顶格行，
                        // 用原始行做缩进判定会把函数提前截断。
                        let code = code_lines(content, hash_comment_language(path));
                        let code_refs: Vec<&str> = code.iter().map(|s| s.as_str()).collect();
                        let brace = is_brace_language(path);
                        let mut seen: std::collections::HashSet<(String, String)> =
                            std::collections::HashSet::new();
                        let def_lines: Vec<u32> = sindex
                            .file_index(path)
                            .map(|fi| {
                                sindex
                                    .definitions_in_file(fi)
                                    .into_iter()
                                    .filter(|(n, _, _)| n == function)
                                    .map(|(_, l, _)| l)
                                    .collect()
                            })
                            .unwrap_or_default();
                        for def_line in def_lines {
                            let def_idx = (def_line as usize).saturating_sub(1);
                            let (start, end) = body_span(&code_refs, def_idx, brace);
                            for idx in start..=end.min(code_refs.len().saturating_sub(1)) {
                                // 用**代码段**提取调用名：字符串/注释里的 `name(` 不算调用
                                let text = code_refs.get(idx).copied().unwrap_or("");
                                for name in callee_names(text) {
                                    if name.as_str() == function {
                                        continue;
                                    }
                                    if !seen.insert((name.clone(), path.clone())) {
                                        continue;
                                    }
                                    matched_callees += 1;
                                    if callees.len() < scan_cap {
                                        provenance.push(prov_with(
                                            path,
                                            (idx + 1) as u32,
                                            &id,
                                            "call-scan+body-scope",
                                        ));
                                        callees.push(json!({
                                            "name": name,
                                            "file": path,
                                            "line": idx + 1,
                                        }));
                                    }
                                }
                            }
                        }
                    }
                    if dynamic_markers.iter().any(|m| content.contains(*m)) {
                        unresolved += 1;
                    }
                    if callers.len() + callees.len() >= scan_cap {
                        break;
                    }
                }
                // 上限纪律：如实上报总数与是否被截断（调用图与定义/引用同一套约定）
                let truncated_at_limit = matched_callers > MAX_CALL_GRAPH_HITS || matched_callees > MAX_CALL_GRAPH_HITS;
                callers.truncate(MAX_CALL_GRAPH_HITS);
                callees.truncate(MAX_CALL_GRAPH_HITS);
                let level = if unresolved > 0 { "high" } else { "medium" };
                IntelEnvelope {
                    data: json!({
                        "function": function,
                        "callers": callers,
                        "callees": callees,
                        "total_hits": {
                            "callers": matched_callers,
                            "callees": matched_callees,
                        },
                        "limit": MAX_CALL_GRAPH_HITS,
                        "truncated_at_limit": truncated_at_limit,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(
                        level,
                        &[
                            "name_based_edges",
                            "dynamic_dispatch_not_resolved",
                            "callees_scoped_to_function_body",
                        ],
                        unresolved,
                    ),
                }
            }
            IntelKind::SliceBackward => {
                let file = input["file"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 file 参数".to_string()))?;
                let line = input["line"].as_i64().unwrap_or(0).max(0) as usize;
                let depth = input["depth"].as_i64().unwrap_or(40).clamp(1, 200) as usize;
                let symbol = input["symbol"].as_str().unwrap_or("");
                let mut snippets: Vec<Value> = Vec::new();
                let mut provenance: Vec<Provenance> = Vec::new();
                // 语义升级：定位目标行所在的**函数**，窗口必须覆盖函数头（否则切片读者看不到上下文）
                let (sindex, s_hit, s_build_ms) =
                    crate::symbol_index::get_or_build(root, refresh, None);
                let mut function_name: Option<String> = None;
                let mut function_def_line: Option<u32> = None;
                // 根因定向证据：函数头原文（可引用），以及无法解析时的最近声明锚点
                let mut function_signature: Option<String> = None;
                let mut nearest_declaration: Option<Value> = None;
                let mut includes_function_header = false;
                let mut window_start = 0usize;
                let mut window_end = 0usize;
                // 作用域锚点位置（在 match 之外读取，故在此声明）
                let mut scope_anchor: Value = Value::Null;
                // 点名文件解析：索引未收录时**按需从磁盘读取**（见 read_requested_file）。
                // 与批量索引的文件数/单文件大小上限解耦——否则"我没索引它"会被回答成
                // "文件不存在"，对 LLM 消费者就是在陈述一个错误的世界。
                let on_demand: Vec<(String, String)> =
                    match files.iter().find(|entry| entry.0.as_str() == file) {
                        Some(_) => Vec::new(),
                        None => vec![(file.to_string(), read_requested_file(root, file)?)],
                    };
                let content_source =
                    if on_demand.is_empty() { "project-index" } else { "on-demand-read" };
                let files: &[(String, String)] =
                    if on_demand.is_empty() { files } else { &on_demand };
                match files.iter().find(|entry| entry.0.as_str() == file) {
                    Some((path, content)) => {
                        let lines: Vec<&str> = content.lines().collect();
                        // 体范围判定用代码段（多行字符串里的顶格行不应被当成 dedent）
                        let code = code_lines(content, hash_comment_language(path));
                        let code_refs: Vec<&str> = code.iter().map(|s| s.as_str()).collect();
                        let center = if line > 0 { line.min(lines.len()) } else { lines.len() };
                        let brace = is_brace_language(path);
                        // 目标行之前最后一条声明，且其函数体覆盖目标行 ⇒ 它就是所在函数
                        let enclosing = sindex.file_index(path).and_then(|fi| {
                            sindex
                                .definitions_in_file(fi)
                                .into_iter()
                                .filter(|(_, def_line, _)| (*def_line as usize) <= center)
                                .filter(|(_, def_line, _)| {
                                    let (_, end) = body_span(
                                        &code_refs,
                                        (*def_line as usize).saturating_sub(1),
                                        brace,
                                    );
                                    end + 1 >= center
                                })
                                .max_by_key(|(_, def_line, _)| *def_line)
                        });
                        if let Some((name, def_line, _)) = &enclosing {
                            function_name = Some(name.clone());
                            function_def_line = Some(*def_line);
                            function_signature = lines
                                .get((*def_line as usize).saturating_sub(1))
                                .map(|s| s.trim().chars().take(200).collect::<String>());
                        } else {
                            // 两趟上溯：先找**体覆盖目标行**的函数头（含匿名函数表达式与箭头函数
                            // ——它们在符号索引里没有声明），找不到再退化为"最近声明锚点"。
                            //
                            // 两个坑（实测）：
                            // ① 必须校验函数体覆盖目标行，否则会把目标行上方"已经闭合的函数"当作用域
                            //    （utilities.js:30 位于字符串数组里，上方最近的函数已闭合 ⇒ 应保持 unresolved）；
                            // ② 不能与"最近声明"合并成一趟，否则中途遇到 `var indexEnd = …` 这类普通声明
                            //    会提前 break，反而漏掉更上面的真正函数头。
                            // 目标行本身可能就是函数头：ES6 类方法 `name() {`、对象字面量方法、
                            // 多行签名的匿名回调（实测 `addParseToken([...], function (`）。
                            // 上溯循环从目标行**上方**开始，结构上永远找不到目标行自己。
                            let self_idx = center.saturating_sub(1);
                            let self_code = code_refs.get(self_idx).copied().unwrap_or("");
                            let self_following: Vec<&str> = code_refs
                                .iter()
                                .skip(self_idx + 1)
                                .filter(|s| !s.trim().is_empty())
                                .take(6)
                                .copied()
                                .collect();
                            if let Some(name) =
                                function_header_name_multi(self_code, &self_following)
                            {
                                if !name.is_empty() {
                                    function_name = Some(name);
                                }
                                function_def_line = Some(center as u32);
                                function_signature = Some(
                                    lines
                                        .get(self_idx)
                                        .copied()
                                        .unwrap_or("")
                                        .trim()
                                        .chars()
                                        .take(200)
                                        .collect::<String>(),
                                );
                            }
                            // 上溯范围 = **整个文件**。旧实现只上溯 120 行，于是 C/Java/Go 的千行
                            // 长函数一律报 unresolved（实测：包含函数在目标行上方 60 行、933 行两例），
                            // 并退化成"最近声明"这种非函数锚点。每轮只做一次廉价的形态判定，
                            // 命中覆盖目标行的函数头即 break。
                            let upto = center.saturating_sub(1);
                            for back in 1..=upto {
                                if function_def_line.is_some() {
                                    break; // 目标行自身已判定为函数头（见上）
                                }
                                let idx = center.saturating_sub(back + 1);
                                let t = lines.get(idx).copied().unwrap_or("").trim();
                                if t.is_empty() {
                                    continue;
                                }
                                let code_line = code_refs.get(idx).copied().unwrap_or("");
                                // 之后最多 6 条非空代码行：C/C++ 签名常跨 3 行以上
                                let following: Vec<&str> = code_refs
                                    .iter()
                                    .skip(idx + 1)
                                    .filter(|s| !s.trim().is_empty())
                                    .take(6)
                                    .copied()
                                    .collect();
                                if let Some(name) = function_header_name_multi(code_line, &following) {
                                    let (_, end) = body_span(&code_refs, idx, brace);
                                    if end + 1 < center {
                                        continue; // 该函数体不覆盖目标行：继续上溯
                                    }
                                    if !name.is_empty() {
                                        function_name = Some(name);
                                    }
                                    function_def_line = Some((idx + 1) as u32);
                                    function_signature =
                                        Some(t.chars().take(200).collect::<String>());
                                    nearest_declaration = Some(json!({
                                        "line": idx + 1,
                                        "text": t.chars().take(160).collect::<String>(),
                                    }));
                                    break;
                                }
                            }
                            if function_def_line.is_none() {
                                for back in 1..=upto {
                                    let idx = center.saturating_sub(back + 1);
                                    let t = lines.get(idx).copied().unwrap_or("").trim();
                                    if t.is_empty() {
                                        continue;
                                    }
                                    let looks_decl = t.starts_with("class ")
                                        || t.starts_with("impl ")
                                        || t.starts_with("public ")
                                        || t.starts_with("private ")
                                        || t.starts_with("protected ")
                                        || t.starts_with("static ")
                                        || t.starts_with("var ")
                                        || t.starts_with("const ")
                                        || t.starts_with("let ");
                                    if looks_decl {
                                        nearest_declaration = Some(json!({
                                            "line": idx + 1,
                                            "text": t.chars().take(160).collect::<String>(),
                                        }));
                                        break;
                                    }
                                }
                            }
                        }
                        // 窗口起点：解析到函数头则锚定函数头（保证切片含函数头）
                        let start = match function_def_line {
                            Some(l) => center
                                .saturating_sub(depth)
                                .min((l as usize).saturating_sub(1)),
                            None => center.saturating_sub(depth),
                        };
                        window_start = start;
                        window_end = center;
                        // 作用域锚点的**位置事实**：函数头落在标称深度窗口内，还是因为函数太长
                        // 而必须把窗口向前扩展才装得下。注意窗口起点是 `min(center-depth, 头行-1)`
                        //（见上），所以解析成功时头**一定**在返回窗口里——这里区分的是"窗口被扩展过"，
                        // 消费者据此知道本次窗口比 `depth` 更宽。
                        scope_anchor = match function_def_line {
                            None => Value::Null,
                            Some(l) if (l as usize) + depth > center => json!("within_depth"),
                            Some(_) => json!("extended_for_long_function"),
                        };
                        for i in start..center {
                            let text = lines.get(i).copied().unwrap_or("");
                            let is_header = function_def_line.map(|l| l as usize == i + 1).unwrap_or(false);
                            let is_target = i + 1 == center;
                            if symbol.is_empty() || is_header || is_target || text.contains(symbol) {
                                if is_header {
                                    includes_function_header = true;
                                }
                                provenance.push(prov_with(
                                    path,
                                    (i + 1) as u32,
                                    &id,
                                    if is_header { "slice+function-header" } else { "slice+line-window" },
                                ));
                                snippets.push(json!({
                                    "line": i + 1,
                                    "text": text.trim().chars().take(200).collect::<String>(),
                                    "is_function_header": is_header,
                                    "is_target": is_target,
                                }));
                            }
                        }
                    }
                    None => {
                        return Err(ToolError::InvalidArgument(format!("文件不存在: {}", file)))
                    }
                }
                IntelEnvelope {
                    data: json!({
                        "file": file,
                        // 证据来源：索引收录 / 索引未收录时的按需读盘。后者本身即"索引漏收"的证据
                        "content_source": content_source,
                        "slice_kind": "function_scoped_prefix",
                        "function": function_name,
                        "function_def_line": function_def_line,
                        "function_signature": function_signature,
                        "function_scope": if function_def_line.is_some() { "resolved" } else { "unresolved" },
                        // `within_depth`：函数头落在标称深度窗口内；`extended_for_long_function`：
                        // 函数太长，窗口被向前扩展才装下头（此时 `window.start_line` 会明显早于
                        // `target_line - depth`）；`null`：未解析到作用域
                        "scope_anchor": scope_anchor,
                        "nearest_declaration": nearest_declaration,
                        "includes_function_header": includes_function_header,
                        "target_line": if line > 0 { json!(line) } else { Value::Null },
                        "window": {"start_line": window_start + 1, "end_line": window_end},
                        "depth": depth,
                        "lines_returned": snippets.len(),
                        "index": symbol_index_stats(&sindex, s_hit, s_build_ms),
                        "snippets": snippets,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(
                        "high",
                        &[
                            "backward_prefix_not_dataflow_slice",
                            "function_header_included_when_found",
                        ],
                        0,
                    ),
                }
            }
            IntelKind::DataflowPath => {
                let source = input["source"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 source 参数".to_string()))?;
                let sink = input["sink"].as_str().unwrap_or("");
                let only_file = input["file"].as_str();
                let mut steps: Vec<Value> = Vec::new();
                let mut provenance: Vec<Provenance> = Vec::new();
                for (path, content) in files {
                    // 数据流判定同样只在代码文件上做（文档里的示例代码不是数据流）
                    if !crate::symbol_index::is_code_file(path) {
                        continue;
                    }
                    if let Some(f) = only_file {
                        if path.as_str() != f {
                            continue;
                        }
                    }
                    let lines: Vec<&str> = content.lines().collect();
                    let src_line = lines.iter().position(|l| l.contains(source));
                    let Some(src_idx) = src_line else { continue };
                    let sink_idx = if sink.is_empty() {
                        None
                    } else {
                        lines.iter().position(|l| l.contains(sink))
                    };
                    let end = sink_idx.unwrap_or(src_idx + 10).min(lines.len().saturating_sub(1));
                    let (lo, hi) = if src_idx <= end { (src_idx, end) } else { (end, src_idx) };
                    for i in lo..=hi {
                        provenance.push(prov(path, (i + 1) as u32, &id));
                        steps.push(json!({"file": path, "line": i + 1, "text": lines[i].trim().chars().take(200).collect::<String>()}));
                    }
                    if steps.len() >= MAX_HITS * 4 {
                        break;
                    }
                }
                IntelEnvelope {
                    data: json!({"source": source, "sink": sink, "path": steps}),
                    provenance,
                    uncertainty: Uncertainty::new("high", &["statement_level_heuristic"], 0),
                }
            }
            IntelKind::SanitizerGuards => {
                let file = input["file"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 file 参数".to_string()))?;
                let line = input["line"].as_i64().unwrap_or(0).max(0);
                let markers = [
                    "if ", "guard", "match ", "switch ", "check", "validate", "sanitize",
                    "allow", "deny", "filter", "is_private", "is_loopback", "is_safe",
                    "allowlist", "whitelist", "blocked", "forbid",
                ];
                let mut guards: Vec<Value> = Vec::new();
                let mut guards_total = 0usize;
                let mut provenance: Vec<Provenance> = Vec::new();
                // 点名文件解析：索引未收录时按需读盘（见 read_requested_file）
                let on_demand: Vec<(String, String)> =
                    match files.iter().find(|entry| entry.0.as_str() == file) {
                        Some(_) => Vec::new(),
                        None => vec![(file.to_string(), read_requested_file(root, file)?)],
                    };
                let content_source =
                    if on_demand.is_empty() { "project-index" } else { "on-demand-read" };
                let files: &[(String, String)] =
                    if on_demand.is_empty() { files } else { &on_demand };
                match files.iter().find(|entry| entry.0.as_str() == file) {
                    Some((path, content)) => {
                        // 标记匹配走**代码段**：字符串/行内注释里的 "if "/"guard" 不算守卫
                        //（此前只跳过"以注释开头的行"，行尾注释与字符串内容仍会命中）
                        let code = code_lines(content, hash_comment_language(path));
                        let originals: Vec<&str> = content.lines().collect();
                        for (idx, code_line) in code.iter().enumerate() {
                            let ln = (idx + 1) as i64;
                            if line > 0 && (ln - line).abs() > 60 {
                                continue;
                            }
                            let text = originals.get(idx).copied().unwrap_or("");
                            let trimmed = text.trim();
                            let code_trimmed = code_line.trim();
                            if code_trimmed.is_empty() {
                                continue;
                            }
                            if markers.iter().any(|m| code_trimmed.contains(*m)) {
                                // 全量计数、只在超限时不入列表：让 `truncated_at_limit` 可信
                                //（此前在 40 条处 `break`，且 data 里没有任何上限字段——
                                //  与 README 承诺的"任何上限都显式上报、不静默截断"冲突）
                                guards_total += 1;
                                if guards.len() < MAX_HITS {
                                    provenance.push(prov(path, ln as u32, &id));
                                    guards.push(json!({"line": ln, "text": trimmed.chars().take(200).collect::<String>()}));
                                }
                            }
                        }
                    }
                    None => {
                        return Err(ToolError::InvalidArgument(format!("文件不存在: {}", file)))
                    }
                }
                IntelEnvelope {
                    data: json!({
                        "file": file,
                        "content_source": content_source,
                        "guards": guards,
                        "total_hits": guards_total,
                        "limit": MAX_HITS,
                        "truncated_at_limit": guards_total > MAX_HITS,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new("medium", &["guard_semantics_not_validated"], 0),
                }
            }
            IntelKind::FrameworkContext => {
                let file = input["file"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 file 参数".to_string()))?;
                let handler = input["handler"].as_str().unwrap_or("");
                let route_markers = [
                    "@app.route", "@router.", "@RequestMapping", "app.get(", "router.get(",
                    "r.GET(", "Route::", "#[get(", "#[post(",
                ];
                let middleware_markers = [
                    "middleware",
                    "before_action",
                    "@UseGuards",
                    "interceptor",
                    "filter_chain",
                    "login_required",
                    "permission_required",
                    "before_request",
                    "app.use(",
                    ".use(",
                ];
                let mut routes: Vec<Value> = Vec::new();
                let mut middleware: Vec<Value> = Vec::new();
                let mut routes_total = 0usize;
                let mut middleware_total = 0usize;
                let mut provenance: Vec<Provenance> = Vec::new();
                // 点名文件解析：索引未收录时按需读盘（见 read_requested_file）
                let on_demand: Vec<(String, String)> =
                    match files.iter().find(|entry| entry.0.as_str() == file) {
                        Some(_) => Vec::new(),
                        None => vec![(file.to_string(), read_requested_file(root, file)?)],
                    };
                let content_source =
                    if on_demand.is_empty() { "project-index" } else { "on-demand-read" };
                let files: &[(String, String)] =
                    if on_demand.is_empty() { files } else { &on_demand };
                match files.iter().find(|entry| entry.0.as_str() == file) {
                    Some((path, content)) => {
                        // 标记匹配走**代码段**：注释或字符串里出现的 `@app.route` / "middleware"
                        // 不是真实路由/中间件（YAML 配置里的 `#` 注释同样会被剥掉，值本身保留）
                        let code = code_lines(content, hash_comment_language(path));
                        let originals: Vec<&str> = content.lines().collect();
                        for (idx, code_line) in code.iter().enumerate() {
                            let ln = (idx + 1) as u32;
                            let text = originals.get(idx).copied().unwrap_or("");
                            let trimmed = text.trim();
                            let code_trimmed = code_line.trim();
                            if code_trimmed.is_empty() {
                                continue;
                            }
                            if route_markers.iter().any(|m| code_trimmed.contains(*m))
                                && (handler.is_empty() || trimmed.contains(handler))
                            {
                                routes_total += 1;
                                if routes.len() + middleware.len() < MAX_HITS {
                                    provenance.push(prov(path, ln, &id));
                                    routes.push(json!({"line": ln, "text": trimmed.chars().take(200).collect::<String>()}));
                                }
                            }
                            if middleware_markers.iter().any(|m| code_trimmed.contains(*m)) {
                                middleware_total += 1;
                                if routes.len() + middleware.len() < MAX_HITS {
                                    provenance.push(prov(path, ln, &id));
                                    middleware.push(json!({"line": ln, "text": trimmed.chars().take(200).collect::<String>()}));
                                }
                            }
                        }
                    }
                    None => {
                        return Err(ToolError::InvalidArgument(format!("文件不存在: {}", file)))
                    }
                }
                // 路由 → handler 绑定：用符号索引把 handler **标识符精确**解析到定义位置。
                // 这是"框架 resolver"的起点——先给出 route 与 handler 定义之间**可验证**的关联，
                // 而不是只报"这行看起来像路由"。
                let (sindex, s_hit, s_build_ms) =
                    crate::symbol_index::get_or_build(root, refresh, None);
                let mut handler_definitions: Vec<Value> = Vec::new();
                let mut handler_decorators: Vec<Value> = Vec::new();
                // 鉴权类装饰器标记：用于给出"链上是否有鉴权"这一可度量判据
                let auth_markers = [
                    "login_required",
                    "requires_auth",
                    "authenticated",
                    "permission_required",
                    "jwt_required",
                    "auth_required",
                    "authorize",
                    "is_admin",
                    "staff_member_required",
                    "user_passes_test",
                ];
                let mut auth_present = false;
                if !handler.is_empty() {
                    for hit in sindex.definitions(handler, 10) {
                        let hf = sindex.file_path(hit.file).to_string();
                        // 只接受**本次请求文件**里的同名定义：否则会把全仓库同名 handler 的
                        // 装饰器链混成一条（真实项目实测：`index` 的链里混进 11 个不同文件的装饰器行，
                        // 顺序正确率因此被压到 0.33）
                        if hf != file {
                            continue;
                        }
                        provenance.push(prov_with(&hf, hit.line, &id, "handler-definition"));
                        // 装饰器/中间件链：从定义行向上收集连续的 `@...` 行（保持自顶向下的顺序），
                        // 并按语义归类——auth / route / middleware / other。
                        let mut chain: Vec<Value> = Vec::new();
                        if let Ok(content) = std::fs::read_to_string(root.join(&hf)) {
                            let lines: Vec<&str> = content.lines().collect();
                            let mut cursor = (hit.line as usize).saturating_sub(1);
                            let mut steps = 0usize;
                            while cursor > 0 && steps < 10 && cursor <= lines.len() {
                                let prev = lines[cursor - 1].trim();
                                if !prev.starts_with('@') {
                                    break;
                                }
                                let kind = if auth_markers.iter().any(|m| prev.contains(*m)) {
                                    "auth"
                                } else if route_markers.iter().any(|m| prev.contains(*m)) {
                                    "route"
                                } else if middleware_markers.iter().any(|m| prev.contains(*m)) {
                                    "middleware"
                                } else {
                                    "other"
                                };
                                chain.push(json!({
                                    "file": hf,
                                    "line": cursor,
                                    "text": prev.chars().take(200).collect::<String>(),
                                    "kind": kind,
                                }));
                                cursor -= 1;
                                steps += 1;
                            }
                            chain.reverse();
                        }
                        if !chain.is_empty() {
                            for item in &chain {
                                if let (Some(f), Some(l)) =
                                    (item["file"].as_str(), item["line"].as_u64())
                                {
                                    provenance.push(prov_with(f, l as u32, &id, "handler-decorator"));
                                }
                            }
                            let chain_has_auth = chain.iter().any(|c| c["kind"] == "auth");
                            if chain_has_auth {
                                auth_present = true;
                            }
                            handler_decorators.push(json!({
                                "handler_line": hit.line,
                                "has_auth_decorator": chain_has_auth,
                                "chain": chain,
                            }));
                        }
                        handler_definitions.push(json!({
                            "file": hf,
                            "line": hit.line,
                            "text": hit.text,
                        }));
                    }
                }
                let resolved = !handler.is_empty() && !handler_definitions.is_empty();
                let mut reasons: Vec<&str> = vec!["framework_graph_not_resolved"];
                if !handler.is_empty() && !resolved {
                    reasons.push("handler_not_resolved");
                }
                // 有效顺序链：文件级中间件（全局注册）在前，handler 装饰器在后，各自按源码行序。
                // 这是"中间件实际生效顺序"的第一步近似——只表达**源码注册顺序**，
                // 不表达框架运行时语义（Django MIDDLEWARE 列表顺序相反、Express app.use 先注册先执行）。
                let mut effective_chain: Vec<Value> = Vec::new();
                // handler 自己的装饰器行号：文件级扫描会重复命中它们（如 `login_required`
                // 既在 middleware 标记里、又是 handler 装饰器），必须去重
                let handler_decor_lines: std::collections::HashSet<u64> = handler_decorators
                    .iter()
                    .filter_map(|hd| hd["chain"].as_array())
                    .flatten()
                    .filter_map(|c| c["line"].as_u64())
                    .collect();
                for m in &middleware {
                    if let (Some(l), Some(t)) = (m["line"].as_u64(), m["text"].as_str()) {
                        if handler_decor_lines.contains(&l) {
                            continue;
                        }
                        effective_chain.push(json!({
                            "scope": "file",
                            "line": l,
                            "text": t,
                            "kind": "middleware",
                        }));
                    }
                }
                for hd in &handler_decorators {
                    if let Some(chain) = hd["chain"].as_array() {
                        for c in chain {
                            effective_chain.push(json!({
                                "scope": "handler",
                                "line": c["line"],
                                "text": c["text"],
                                "kind": c["kind"],
                            }));
                        }
                    }
                }
                effective_chain.sort_by_key(|v| v["line"].as_u64().unwrap_or(0));
                // 每框架的**运行时**顺序（源码顺序 ≠ 运行时顺序）：
                // - 装饰器：`@outer` + `@inner` 等价于 `outer(inner(f))` ⇒ **前置执行顺序是自顶向下
                //   （最外层先）**；反序只描述"包裹应用顺序"，不是执行顺序；
                // - 文件级钩子/中间件（before_request、MIDDLEWARE、app.use）在 handler 之前；
                // - Express：`app.use` 先注册先执行 ⇒ 保持源码顺序。
                // Django 的 `MIDDLEWARE` 是**字符串列表**：代码段扫描会把字符串剥掉，
                // 因此这里对**原文**做一次列表字面量解析，按声明顺序给出中间件链。
                let mut django_middleware: Vec<Value> = Vec::new();
                if let Ok(raw) = std::fs::read_to_string(root.join(&file)) {
                    let mut in_list = false;
                    let mut order = 0usize;
                    for (idx, line) in raw.lines().enumerate() {
                        let t = line.trim();
                        if !in_list {
                            if t.starts_with("MIDDLEWARE") && t.contains('[') {
                                in_list = !t.contains(']');
                            }
                            continue;
                        }
                        if t.starts_with(']') {
                            break;
                        }
                        // 取该行**第一个字符串字面量**的内容：丢弃其后的逗号与行内注释
                        // （真实项目里条目常写成 `"a.b.M",  # 说明`，按 trim 处理会连带注释）
                        let entry = if let Some(start) = t.find(['"', '\'']) {
                            let quote = t.as_bytes()[start] as char;
                            let rest = &t[start + 1..];
                            match rest.find(quote) {
                                Some(end) => rest[..end].to_string(),
                                None => String::new(),
                            }
                        } else {
                            String::new()
                        };
                        if !entry.is_empty() {
                            order += 1;
                            django_middleware.push(json!({
                                "order": order,
                                "entry": entry,
                                "line": idx + 1,
                            }));
                        }
                    }
                }
                let is_django_settings = !django_middleware.is_empty();
                let fw: &str = if is_django_settings {
                    "django"
                } else if file.ends_with(".py") {
                    if file.ends_with("urls.py")
                        || middleware.iter().any(|m| {
                            m["text"].as_str().unwrap_or("").contains("MIDDLEWARE")
                        })
                    {
                        "django"
                    } else {
                        "flask"
                    }
                } else if file.ends_with(".js") || file.ends_with(".mjs") || file.ends_with(".ts") {
                    "express"
                } else {
                    "unknown"
                };
                // 运行时链 = 文件级钩子（按源码序）在前，handler 装饰器（自顶向下）在后
                let runtime_chain = effective_chain.clone();
                let ordering_rule = match fw {
                    "flask" => "file_scope_hooks_first_then_handler_decorators_top_down",
                    "django" => "middleware_list_source_order_then_handler_decorators_top_down",
                    _ => "source_registration_order",
                };
                // 诚实标注：顺序规则已由独立 oracle 验证过的框架不加警示——
                // Flask 12/12、Express 3/3（19 处 app.use 完全一致）、Django 1/1（真实项目 10 条 MIDDLEWARE 逐项一致）；
                // Django 与未知框架仍只是"按语义声明的规则"。
                if fw != "flask" && fw != "express" && fw != "django" {
                    reasons.push("ordering_rule_not_ground_truth_verified");
                }
                IntelEnvelope {
                    data: json!({
                        "file": file,
                        "content_source": content_source,
                        "handler": handler,
                        "handler_resolved": resolved,
                        "handler_definitions": handler_definitions,
                        "handler_decorators": handler_decorators,
                        "auth_decorators_present": auth_present,
                        "effective_chain": effective_chain,
                        "effective_chain_semantics": "source_registration_order_only",
                        "framework": fw,
                        "effective_chain_runtime": runtime_chain,
                        "ordering_rule": ordering_rule,
                        "django_middleware_order": django_middleware,
                        "decorator_application_order": "bottom_up_wrapping",
                        "routes": routes,
                        "middleware": middleware,
                        "total_hits": {
                            "routes": routes_total,
                            "middleware": middleware_total,
                        },
                        "limit": MAX_HITS,
                        "truncated_at_limit": routes_total + middleware_total > MAX_HITS,
                        "index": symbol_index_stats(&sindex, s_hit, s_build_ms),
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(
                        if resolved { "medium" } else { "high" },
                        &reasons,
                        0,
                    ),
                }
            }
            IntelKind::IncrementalStatus => {
                let bytes = index.total_bytes();
                let probe_on = crate::index_cache::probe_enabled();
                let timing = crate::index_cache::cache_timing(root);
                // 待局部重编译口径 = 相对上次构建已变化的文件/目录（stat 级，不重新遍历）
                let pending = crate::index_cache::changed_since_build(root).unwrap_or_default();
                let mut reasons: Vec<&str> = vec!["daemon_incremental_index_not_wired"];
                if probe_on {
                    reasons.push("new_directories_need_ttl_or_refresh");
                } else {
                    reasons.push("probe_disabled_by_env");
                }
                let mode = if probe_on {
                    "stat+mtime-probe+ttl-cache"
                } else {
                    "stat+ttl-cache"
                };
                IntelEnvelope {
                    data: json!({
                        "build_id": id,
                        "files_indexed": files.len(),
                        "bytes_indexed": bytes,
                        "mode": mode,
                        "pending_recompile": pending.len(),
                        "pending_sample": pending.iter().take(20).collect::<Vec<_>>(),
                        "fingerprint": {
                            "files": index.file_stamps.len(),
                            "dirs": index.dir_stamps.len(),
                            "probe_enabled": probe_on,
                        },
                        "skipped_large_files": index.skipped_large,
                        "truncated_at_limit": index.truncated_at_limit,
                        "cache": {
                            "hit": cache_hit,
                            "hit_source": hit.as_str(),
                            "age_ms": index.age().as_millis() as u64,
                            "ttl_ms": ttl.as_millis() as u64,
                            "refresh": refresh,
                            "entries": crate::index_cache::stats().0,
                            "ttl_hits": timing.map(|t| t.ttl_hits),
                            "probe_hits": timing.map(|t| t.probe_hits),
                        },
                        "slo": {
                            "symbol_jump_ms": null,
                            "slice_ms": null,
                            "index_build_ms": timing.map(|t| t.last_build_ms),
                            "validated_age_ms": timing.map(|t| t.validated_age_ms),
                        },
                    }),
                    provenance: vec![prov(".", 0, &id)],
                    uncertainty: Uncertainty::new("medium", &reasons, 0),
                }
            }
        };
        let text = format!("{}: {} files scanned", self.kind.name(), files.len());
        Ok(ToolResult::json(
            serde_json::to_value(env).unwrap_or(Value::Null),
            Some(text),
        ))
    }
}

/// 注册高阶代码智能工具（9 个；report_finding 由 built-in 提供）。
pub async fn register_code_intel_tools(registry: &Arc<ToolRegistry>, project_path: String) {
    for kind in IntelKind::all() {
        let tool: Arc<dyn Tool> = Arc::new(CodeIntelTool::new(project_path.clone(), kind));
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register code-intel tool: {}", e);
        }
    }
}

/// 工具面判定：MCP server 可据此只暴露高阶能力（legacy 工具另行 gate）。
pub fn is_code_intel_tool(name: &str) -> bool {
    CODE_INTEL_TOOL_SURFACE.contains(&name)
}

/// 目标工具面名单（9 + report_finding）。
pub const CODE_INTEL_TOOL_SURFACE: [&str; 10] = [
    "get_project_index",
    "get_symbol_definition",
    "get_symbol_references",
    "get_call_hierarchy",
    "slice_backward",
    "get_dataflow_path",
    "get_sanitizer_guards",
    "get_framework_context",
    "get_incremental_status",
    "report_finding",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(language_of("src/main.rs"), "rust");
        assert_eq!(language_of("app/models.py"), "python");
        assert_eq!(language_of("internal/x.go"), "go");
        assert_eq!(language_of("web/index.tsx"), "typescript");
        assert_eq!(language_of("a/b.cpp"), "cpp");
    }

    #[test]
    fn test_find_definitions() {
        let src = "class Foo:\n    pass\n\ndef bar():\n    pass\n";
        let defs = find_definitions(src, "bar");
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].0, 4);
    }

    #[test]
    fn test_find_call_sites_excludes_definition() {
        let src = "fn main() {\n    helper(1);\n}\nfn helper(x: i32) {}\n";
        let sites = find_call_sites(src, "helper");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].0, 2);
    }

    #[test]
    /// C 的运算符/内建形式不是被调用者（`sizeof`/`_Alignof`/`offsetof`）。
    #[test]
    fn test_callee_names_skips_c_operators() {
        for line in ["n = sizeof(ngx_str_t);", "x = _Alignof(int) + offsetof(S, f);"] {
            let names = callee_names(line);
            assert!(names.is_empty(), "{line} 不应产出 callee: {names:?}");
        }
        assert_eq!(callee_names("ngx_foo(a);"), vec!["ngx_foo".to_string()]);
    }

    fn test_callee_names() {
        let names = callee_names("let x = foo.bar(1) + baz(2);");
        assert!(names.contains(&"bar".to_string()));
        assert!(names.contains(&"baz".to_string()));
    }

    #[test]
    fn test_load_files_reports_limits() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-load-limits");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
        // 超过单文件上限的文件应计入 skipped_large
        std::fs::write(root.join("big.bin"), "x".repeat(MAX_FILE_BYTES + 1)).unwrap();
        // 跳过目录不应被索引
        std::fs::create_dir_all(root.join("node_modules")).unwrap();
        std::fs::write(root.join("node_modules/skip.js"), "var x = 1;").unwrap();

        let loaded = load_files(&root);
        assert_eq!(loaded.files.len(), 1, "只应索引 src/main.rs");
        assert_eq!(loaded.files[0].0, "src/main.rs");
        assert_eq!(loaded.skipped_large, 1, "超大文件应被计数");
        assert!(!loaded.truncated_at_limit, "未达文件数上限不应标记截断");
        assert_eq!(loaded.file_stamps.len(), 1, "每个已索引文件都应有指纹");
        assert_eq!(loaded.file_stamps[0].path, "src/main.rs");
        assert!(
            loaded.dir_stamps.iter().any(|d| d.path.is_empty()),
            "应记录项目根目录指纹"
        );
        assert!(
            loaded
                .dir_stamps
                .iter()
                .any(|d| d.path == "src" || d.path.ends_with("/src")),
            "应记录子目录指纹: {:?}",
            loaded.dir_stamps.iter().map(|d| &d.path).collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 点名文件解析必须与**批量索引**上限解耦：索引受文件数/单文件大小上限约束，
    /// 但调用方点名一个文件时只该回答"能不能读"。此前两者共用同一上限，于是被索引跳过的
    /// 文件被回答成"文件不存在"（实测 542KB 生成产物与超出 2000 文件上限的源码即此）。
    #[tokio::test]
    async fn test_file_skipped_by_index_is_read_on_demand() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-ondemand");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut src = String::new();
        while src.len() < MAX_FILE_BYTES + 64 * 1024 {
            src.push_str("// filler line to exceed the bulk index limit\n");
        }
        src.push_str("function target(a) {\n  var x = a + 1;\n  return x;\n}\n");
        let total = src.lines().count();
        std::fs::write(root.join("big.js"), &src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let loaded = load_files(&root);
        assert!(loaded.files.is_empty(), "超上限文件不应进批量索引");
        assert_eq!(loaded.skipped_large, 1);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let hit = tool
            .execute(json!({"file": "big.js", "line": total - 1}))
            .await
            .unwrap();
        let d = hit.data.expect("应有 envelope data");
        assert_eq!(d["data"]["content_source"], "on-demand-read", "{d}");
        assert_eq!(d["data"]["function"], "target", "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 读取失败必须给出**真实原因**：磁盘与索引都没有 / 不是常规文件 / 超过读取上限。
    #[tokio::test]
    async fn test_missing_and_non_file_requests_report_true_reason() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-missing");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn f() {}\n").unwrap();

        let missing = format!("{:?}", read_requested_file(&root, "src/nope.rs").unwrap_err());
        assert!(missing.contains("文件不存在"), "{missing}");
        assert!(missing.contains("磁盘与索引"), "{missing}");

        let dir = format!("{:?}", read_requested_file(&root, "src").unwrap_err());
        assert!(dir.contains("不是常规文件"), "{dir}");

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let err = format!(
            "{:?}",
            tool.execute(json!({"file": "src/nope.rs", "line": 1}))
                .await
                .unwrap_err()
        );
        assert!(err.contains("磁盘与索引"), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 索引遍历顺序必须确定性：`read_dir` 返回顺序随文件系统而异，而"达到文件数上限就停"
    /// 会让取舍结果在机器之间不同（实测同一仓库在两台机器上命中不同的文件子集）。
    #[test]
    fn test_load_files_order_is_deterministic() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-order");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("z/deep")).unwrap();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("z/deep/x.js"), "var x = 1;").unwrap();
        std::fs::write(root.join("a/y.js"), "var y = 1;").unwrap();
        std::fs::write(root.join("top.js"), "var t = 1;").unwrap();

        let loaded = load_files(&root);
        let paths: Vec<&str> = loaded.files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            vec!["a/y.js", "top.js", "z/deep/x.js"],
            "已索引文件应按路径排序（确定性）"
        );
        let stamps: Vec<&str> = loaded.file_stamps.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(stamps, paths, "指纹顺序应与文件顺序一致");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 多行签名：C/C++ 签名跨 3 行以上时也必须能取出函数名（实测
    /// `static cmark_node *try_opening_table_header(` + 2 行参数 + `… int len) {`）。
    #[test]
    fn test_function_header_name_multi_line_signature() {
        assert_eq!(
            function_header_name_multi("ngx_http_foo(ngx_http_request_t *r)", &["{"]).as_deref(),
            Some("ngx_http_foo")
        );
        let sig = [
            "cmark_parser *parser,",
            "cmark_node *parent_container,",
            "unsigned char *input, int len) {",
        ];
        assert_eq!(
            function_header_name_multi(
                "static cmark_node *try_opening_table_header(cmark_syntax_extension *self,",
                &sig
            )
            .as_deref(),
            Some("try_opening_table_header")
        );
        // 拼接不得制造误判：跨行的普通调用仍不是函数头；
        // 且**圆括号已闭合**的行（`var x = require('y')`）绝不允许被后面的函数声明拼成函数头
        assert_eq!(function_header_name_multi("foo(bar);", &["baz();"]).as_deref(), None);
        assert_eq!(
            function_header_name_multi("var isBuffer = require('is-buffer')", &["function keyIdentity (key) {"])
                .as_deref(),
            None
        );
        // 圆括号未闭合 ≠ 可以一路拼到后面的函数声明：模块级的 `x = re.compile(` 不得与
        // 后面的 `def f(s):` 拼成函数头（实测假阳性，关键字分支只许匹配**本行**）
        assert_eq!(
            function_header_name_multi(
                "_is_image_dataurl = re.compile(",
                &["    r'^data:image/.+;base64', re.I).search",
                  "_is_possibly_malicious_scheme = re.compile(",
                  "def _is_javascript_scheme(s):",
                  "    if _is_image_dataurl(s):"]
            )
            .as_deref(),
            None
        );
    }

    /// 目标行**自身**就是函数头（ES6 类方法）时也必须解析出作用域——上溯循环从目标行上方
    /// 开始，结构上找不到目标行自己。
    #[tokio::test]
    async fn test_slice_resolves_when_target_line_is_the_header() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-selfheader");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("m.js"),
            "var handlers = {};\nhandlers.getPublicInterface = function () {\n  var self = this;\n  return self.x;\n};\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        // 第 2 行就是函数头**本身**（符号索引里没有它的声明）
        let hit = tool.execute(json!({"file": "m.js", "line": 2})).await.unwrap();
        let d = hit.data.expect("应有 envelope data");
        assert_eq!(d["data"]["function"], "getPublicInterface", "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["scope_anchor"], "within_depth", "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 长函数：函数头在目标行**上方数百行**（远超切片窗口）时，仍需给出函数名与签名，
    /// 并如实标注 `scope_anchor=outside_window`（窗口里没有头就不许说 `includes_function_header`）。
    /// 用对象属性函数表达式构造，确保**符号索引里没有该声明**，只能靠上溯找到。
    #[tokio::test]
    async fn test_slice_resolves_enclosing_function_far_above_the_window() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-farabove");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut src = String::from("var obj = {\n  farAbove: function (a) {\n    var x = a;\n");
        for i in 0..300 {
            src.push_str(&format!("    x = x + {i};\n"));
        }
        src.push_str("    return x;\n  }\n};\n");
        std::fs::write(root.join("far.js"), &src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let hit = tool.execute(json!({"file": "far.js", "line": 304})).await.unwrap();
        let d = hit.data.expect("应有 envelope data");
        assert_eq!(d["data"]["function"], "farAbove", "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        // 函数太长 ⇒ 窗口被向前扩展才装下函数头，如实标注（消费者据此知道窗口比 depth 更宽）
        assert_eq!(d["data"]["scope_anchor"], "extended_for_long_function", "{d}");
        assert_eq!(d["data"]["window"]["start_line"], 2, "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 端到端回归：代码段里的**落单引号**（Rust 生命周期 `&'static str`、JS 正则 `/'/g`）
    /// 不得吞掉后续声明——否则定义进不了索引（表现为 `empty_kind=index_miss`）。
    /// 同时验证空结果分类：索引里完全没有的符号报 `no_match`。
    #[tokio::test]
    async fn test_definition_after_lifetime_is_indexed_and_empty_kind_is_reported() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-lifetime");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "fn f() -> Option<&'static str> {\n    None\n}\n\npub fn classify_file_role(p: &str) -> &'static str {\n    \"x\"\n}\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let project = root.to_string_lossy().to_string();
        let tool = CodeIntelTool::new(project, IntelKind::SymbolDefinition);

        let hit = tool
            .execute(json!({"symbol": "classify_file_role"}))
            .await
            .unwrap();
        let d = hit.data.clone().expect("应有 envelope data");
        assert!(
            d["data"]["total_hits"].as_u64().unwrap() >= 1,
            "生命周期之后的声明必须进索引: {d}"
        );
        assert_eq!(d["data"]["empty_kind"], Value::Null, "{d}");

        let miss = tool
            .execute(json!({"symbol": "definitely_absent_symbol_xyz"}))
            .await
            .unwrap();
        let m = miss.data.expect("应有 envelope data");
        assert_eq!(m["data"]["total_hits"], 0);
        assert_eq!(m["data"]["empty_kind"], "no_match", "{m}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 函数头识别：关键字形态 + **匿名函数表达式/箭头函数** + **C/C++ 无关键字定义**。
    #[test]
    fn test_function_header_name_forms() {
        assert_eq!(function_header_name("function foo(a) {").as_deref(), Some("foo"));
        assert_eq!(function_header_name("async function h(req) {").as_deref(), Some("h"));
        assert_eq!(function_header_name("def foo(x):").as_deref(), Some("foo"));
        // 匿名函数表达式：名字由属性/变量名回填
        assert_eq!(
            function_header_name("replacement: function (content) {").as_deref(),
            Some("replacement")
        );
        assert_eq!(function_header_name("const f = function (a) {").as_deref(), Some("f"));
        assert_eq!(function_header_name("handler: (req, res) => {").as_deref(), Some("handler"));
        assert_eq!(function_header_name("const g = (a) => a + 1").as_deref(), Some("g"));
        // 关键字与 `(` 之间**无空格**（JS 匿名函数常见）→ 名字回填自左侧属性/变量
        //（实测漏此形态会把 `function` 当成函数名）
        assert_eq!(
            function_header_name("Git.prototype.checkoutLatestTag = function(then) {").as_deref(),
            Some("checkoutLatestTag")
        );
        assert_eq!(function_header_name("function(a) {").as_deref(), Some(""));
        // 关键字边界：`define(` 的 `def`、`myfn(` 的 `fn` 都不得被当成关键字
        assert_eq!(function_header_name("myfn(x) {").as_deref(), Some("myfn"));
        assert_eq!(function_header_name("define(FOO, x)").as_deref(), None);
        // C/C++：无关键字定义（单词一行 + 多行签名两种）
        assert_eq!(function_header_name("static int foo(int a) {").as_deref(), Some("foo"));
        assert_eq!(function_header_name("void bar(void) {").as_deref(), Some("bar"));
        assert_eq!(
            function_header_name_ctx("ngx_http_foo(ngx_http_request_t *r)", "{").as_deref(),
            Some("ngx_http_foo")
        );
        // C/C++ 负例：控制语句、调用、结构体、else
        assert_eq!(function_header_name("if (a) {"), None);
        assert_eq!(function_header_name("for (i = 0; i < n; i++) {"), None);
        assert_eq!(function_header_name("while (x) {"), None);
        assert_eq!(function_header_name("synchronized (lock) {"), None);
        assert_eq!(function_header_name("foo(bar);"), None);
        assert_eq!(function_header_name("struct foo {"), None);
        assert_eq!(function_header_name("} else {"), None);
        // 非函数头
        assert_eq!(function_header_name("const x = 1;"), None);
        assert_eq!(function_header_name("// function notAHeader() {"), None);
    }

    /// `slice_backward` 必须锚定**函数头**，包括 `replacement: function (…) {` 这类
    /// 对象属性函数表达式——它在符号索引里没有声明，旧实现因此返回
    /// `function_scope="unresolved"`、窗口不含函数头（实测"函数头入镜 40.4%"的机制性原因）。
    #[tokio::test]
    async fn test_slice_anchors_object_property_function_expression() {
        let root = std::env::temp_dir().join("ctx-audit-slice-prop-fn");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "const rules = {}\n\nrules.blockquote = {\n  filter: 'blockquote',\n  replacement: function (content, node, options) {\n    content = content.replace(/^\\n+|\\n+$/g, '')\n    return content\n  }\n}\n";
        std::fs::write(root.join("src/rules.js"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/rules.js", "line": 6, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["function"], "replacement", "{d}");
        assert_eq!(d["data"]["function_def_line"], 5, "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 反向反例：目标行**不在任何函数体内**（文件级字符串数组），
    /// 即使上方 120 行内有已闭合的函数，也不得报 `resolved`——那是假作用域。
    #[tokio::test]
    async fn test_slice_does_not_falsely_anchor_closed_function() {
        let root = std::env::temp_dir().join("ctx-audit-slice-no-false-anchor");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "export function trim (s) {\n  return s\n}\n\nexport var list = [\n  'A', 'B',\n  'C', 'D'\n]\n";
        std::fs::write(root.join("src/u.js"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/u.js", "line": 7, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function_scope"], "unresolved", "{d}");
        assert_eq!(d["data"]["includes_function_header"], false, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C 风格定义（**无关键字**、多行签名）也要锚定函数头：
    /// `static ngx_int_t` / `ngx_http_foo(...)` / `{` 三行式——nginx、pppd 的实际形态。
    #[tokio::test]
    async fn test_slice_anchors_c_style_function_header() {
        let root = std::env::temp_dir().join("ctx-audit-slice-c-header");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "static ngx_int_t\nngx_http_foo(ngx_http_request_t *r)\n{\n    int n = r->n;\n    if (n == 0) {\n        return 1;\n    }\n    return 0;\n}\n";
        std::fs::write(root.join("src/a.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/a.c", "line": 5, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["function"], "ngx_http_foo", "{d}");
        assert_eq!(d["data"]["function_def_line"], 2, "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 上限纪律：`get_sanitizer_guards` 超限时必须**显式上报**
    /// `total_hits`/`limit`/`truncated_at_limit`，不得静默截断
    ///（README 契约；修复前 data 里只有 `{file, guards}`，第 40 条处静默 break）。
    #[tokio::test]
    async fn test_sanitizer_guards_reports_truncation() {
        let root = std::env::temp_dir().join("ctx-audit-guards-trunc");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let mut src = String::new();
        for i in 0..50 {
            src.push_str(&format!("if (guard_{}()) {{}}\n", i));
        }
        std::fs::write(root.join("src/g.js"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SanitizerGuards);

        let out = tool.execute(json!({"file": "src/g.js"})).await.unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["limit"], MAX_HITS, "{d}");
        assert_eq!(d["data"]["total_hits"], 50, "{d}");
        assert_eq!(d["data"]["truncated_at_limit"], true, "{d}");
        assert_eq!(
            d["data"]["guards"].as_array().map(|a| a.len()),
            Some(MAX_HITS),
            "{d}"
        );

        // 未超限：不得误报截断，且 total_hits == 返回条数
        std::fs::write(root.join("src/small.js"), "if (a) {}\nif (b) {}\n").unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let out2 = tool.execute(json!({"file": "src/small.js"})).await.unwrap();
        let d2 = out2.data.clone().expect("应有 envelope data");
        assert_eq!(d2["data"]["total_hits"], 2, "{d2}");
        assert_eq!(d2["data"]["truncated_at_limit"], false, "{d2}");
        assert_eq!(
            d2["data"]["guards"].as_array().map(|a| a.len()),
            Some(2),
            "{d2}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 工具级：`get_incremental_status` 的 pending 与命中来源必须来自真实状态。
    #[tokio::test]
    async fn test_incremental_status_reports_real_pending() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-incremental");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), "fn a() {}").unwrap();
        crate::index_cache::invalidate(&root);

        let project = root.to_string_lossy().to_string();
        let tool = CodeIntelTool::new(project.clone(), IntelKind::IncrementalStatus);

        let first = tool.execute(json!({})).await.unwrap();
        let first_env = first.data.clone().expect("应有 envelope data");
        let probe_on = crate::index_cache::probe_enabled();
        assert_eq!(
            first_env["data"]["mode"],
            if probe_on {
                "stat+mtime-probe+ttl-cache"
            } else {
                "stat+ttl-cache"
            }
        );
        assert_eq!(first_env["data"]["cache"]["hit"], false);
        assert_eq!(first_env["data"]["cache"]["hit_source"], "miss");
        assert_eq!(first_env["data"]["pending_recompile"], 0);
        assert!(
            first_env["data"]["fingerprint"]["files"].as_u64().unwrap() >= 1,
            "应记录文件指纹: {first_env}"
        );
        assert!(
            first_env["data"]["slo"]["index_build_ms"].as_u64().is_some(),
            "首次构建后应有构建耗时: {first_env}"
        );

        // 第二次调用：TTL 内应命中，并如实报告命中来源
        let second = tool.execute(json!({})).await.unwrap();
        let second_env = second.data.clone().expect("应有 envelope data");
        assert_eq!(second_env["data"]["cache"]["hit"], true);
        let second_source = second_env["data"]["cache"]["hit_source"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(
            second_source == "ttl" || second_source == "probe",
            "命中来源应为 ttl/probe（取决于 CTX_AUDIT_INDEX_TTL_MS）: {second_source}"
        );

        let status = crate::index_cache::changed_since_build(std::path::Path::new(&project))
            .expect("构建后应有缓存条目");
        assert!(status.is_empty(), "刚构建时不应有待重编译条目: {status:?}");

        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(root.join("src/a.rs"), "fn a() { longer_body(); }").unwrap();
        let status2 = crate::index_cache::changed_since_build(std::path::Path::new(&project))
            .expect("缓存条目仍在");
        assert!(
            status2.iter().any(|p| p == "src/a.rs"),
            "改动文件应进入待重编译: {status2:?}"
        );

        crate::index_cache::invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_envelope_serializes() {
        let env = IntelEnvelope {
            data: json!({"ok": true}),
            provenance: vec![prov("a.py", 1, "statv1:1f:1b")],
            uncertainty: Uncertainty::new("medium", &["x"], 0),
        };
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["data"]["ok"], true);
        assert_eq!(v["provenance"][0]["file"], "a.py");
        assert_eq!(v["uncertainty"]["level"], "medium");
    }

    #[test]
    fn test_tool_surface_is_ten() {
        assert_eq!(CODE_INTEL_TOOL_SURFACE.len(), 10);
        assert_eq!(IntelKind::all().len(), 9);
    }

    /// 缩进语言：callee 扫描必须止于函数体（同文件无关函数不得计入）
    #[test]
    fn test_body_span_indent_language() {
        let src = "def target(request):\n    a = helper_one(request)\n    return helper_two(a)\n\n\ndef unrelated():\n    return other_call()\n";
        let lines: Vec<&str> = src.lines().collect();
        let (start, end) = body_span(&lines, 0, false);
        assert_eq!(start, 0);
        let body = lines[start..=end].join("\n");
        assert!(body.contains("helper_one"), "{body}");
        assert!(body.contains("helper_two"), "{body}");
        assert!(
            !body.contains("other_call"),
            "函数体外的调用不应计入: {body}"
        );
    }

    /// 花括号语言：按配对花括号取体范围
    #[test]
    fn test_body_span_brace_language() {
        let src = "function target(req) {\n    const s = new Store();\n    return s.get(\"k\");\n}\n\nfunction unrelated() {\n    return other();\n}\n";
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(body_span(&lines, 0, true), (0, 3));
        assert!(is_brace_language("a.js") && is_brace_language("a.go"));
        assert!(!is_brace_language("a.py"));
    }

    /// Go 的匿名函数字面量不是调用点（真实仓库实测：callees 里混进名为 "func" 的条目）
    #[test]
    fn test_callee_names_skips_structural_keywords() {
        let names = callee_names("go func(c *Config) { Validate(c) }()");
        assert!(!names.contains(&"func".to_string()), "{names:?}");
        assert!(!names.contains(&"go".to_string()), "{names:?}");
        assert!(names.contains(&"Validate".to_string()), "{names:?}");

        let names = callee_names("defer func() { cleanup() }()");
        assert_eq!(names, vec!["cleanup".to_string()], "{names:?}");
    }

    /// 缩进语言：多行签名不得把函数体截断（签名收尾行 `) -> int:` 常从第 0 列开始）
    #[test]
    fn test_body_span_indent_multiline_signature() {
        let src = "def outer(\n    a: int,\n) -> int:\n    x = a + 1\n    return x\n\n\ndef other():\n    return 0\n";
        let lines: Vec<&str> = src.lines().collect();
        let (start, end) = body_span(&lines, 0, false);
        assert_eq!(start, 0);
        assert!(
            end >= 4 && end < 7,
            "函数体应覆盖 `return x`(idx 4) 且止于下一个顶层 def(idx 7)：实际 end={end}"
        );
    }

    /// 命名导入别名：JS/TS 花括号清单与 Python `from ... import`
    #[test]
    fn test_import_aliases() {
        let js = "import Store, { put as save, get } from \"./store.js\";\nconst x = 1;\n";
        let aliases = import_aliases(js);
        assert!(
            aliases.contains(&("put".to_string(), "save".to_string())),
            "{aliases:?}"
        );
        assert!(
            aliases.contains(&("get".to_string(), "get".to_string())),
            "{aliases:?}"
        );

        let py = "from pkg.util import Loader as Ldr\nimport os\n";
        let aliases = import_aliases(py);
        assert!(
            aliases.contains(&("Loader".to_string(), "Ldr".to_string())),
            "{aliases:?}"
        );

        // 默认导入 / 命名空间导入不产生别名对
        assert!(import_aliases("import Store from \"./store.js\";\n").is_empty());
        assert!(import_aliases("import * as ns from \"./m.js\";\n").is_empty());
    }

    /// 接口方法声明不是调用点
    #[test]
    fn test_in_interface_block() {
        let src = "type Reader interface {\n    Read(p []byte) (int, error)\n}\n\nfunc run(r Reader) int {\n    n, _ := r.Read(nil)\n    return n\n}\n";
        let lines: Vec<&str> = src.lines().collect();
        assert!(
            in_interface_block(&lines, 1),
            "接口方法声明应判为在 interface 块内"
        );
        assert!(
            !in_interface_block(&lines, 5),
            "函数体里的真实调用点不应被判为接口块"
        );
    }

    /// 标识符边界：`App` 不得命中 `_AppCtxGlobals`，`copy` 不得命中 `deepcopy`
    #[test]
    fn test_contains_identifier_boundaries() {
        assert!(contains_identifier("    const s = new Store();", "Store"));
        assert!(!contains_identifier("class _AppCtxGlobals:", "App"));
        assert!(!contains_identifier("import deepcopy", "copy"));
        assert!(contains_identifier("x = copy.copy(y)", "copy"));
        // 带点/其它符号的查询退化为子串匹配（保持旧语义）
        assert!(contains_identifier("a.b.c", "b.c"));
    }

    /// 调用点左边界：`myread(` 不算 `read(` 的调用点
    #[test]
    fn test_call_site_match_left_boundary() {
        assert!(call_site_match("    return loader.load(request)", "load"));
        assert!(!call_site_match("    return myread(buf)", "read"));
        assert!(call_site_match("n, _ := r.Read(buf)", "Read"));
    }
}
