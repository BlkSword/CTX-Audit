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
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, dir_rel)) = stack.pop() {
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
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !should_skip(&name) {
                    let child_rel = if dir_rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{dir_rel}/{name}")
                    };
                    stack.push((path, child_rel));
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
                IntelEnvelope {
                    data: json!({
                        "symbol": symbol,
                        "definitions": defs,
                        "total_hits": total_hits,
                        "limit": MAX_DEFINITION_HITS,
                        "truncated_at_limit": truncated_at_limit,
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
                IntelEnvelope {
                    data: json!({
                        "symbol": symbol,
                        "references": refs,
                        "total_hits": total_hits,
                        "limit": MAX_REFERENCE_HITS,
                        "truncated_at_limit": truncated_at_limit,
                        "index": symbol_index_stats(&sindex, s_hit, s_build_ms),
                        "candidate_files": candidate_count,
                        "scanned_files": scanned_files,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(
                        "medium",
                        &[
                            "same_name_not_disambiguated",
                            "not_lsp_resolved",
                            "index_covers_code_files_only",
                            "identifier_boundary_matching",
                            "strings_and_comments_excluded",
                        ],
                        0,
                    ),
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
                let mut includes_function_header = false;
                let mut window_start = 0usize;
                let mut window_end = 0usize;
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
                        let start = match &enclosing {
                            Some((_, def_line, _)) => {
                                center.saturating_sub(depth).min((*def_line as usize).saturating_sub(1))
                            }
                            None => center.saturating_sub(depth),
                        };
                        if let Some((name, def_line, _)) = &enclosing {
                            function_name = Some(name.clone());
                            function_def_line = Some(*def_line);
                        }
                        window_start = start;
                        window_end = center;
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
                        "slice_kind": "function_scoped_prefix",
                        "function": function_name,
                        "function_def_line": function_def_line,
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
                let mut provenance: Vec<Provenance> = Vec::new();
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
                                provenance.push(prov(path, ln as u32, &id));
                                guards.push(json!({"line": ln, "text": trimmed.chars().take(200).collect::<String>()}));
                            }
                            if guards.len() >= MAX_HITS {
                                break;
                            }
                        }
                    }
                    None => {
                        return Err(ToolError::InvalidArgument(format!("文件不存在: {}", file)))
                    }
                }
                IntelEnvelope {
                    data: json!({"file": file, "guards": guards}),
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
                    "middleware", "before_action", "@UseGuards", "interceptor", "filter_chain",
                    "login_required", "permission_required", "before_request",
                ];
                let mut routes: Vec<Value> = Vec::new();
                let mut middleware: Vec<Value> = Vec::new();
                let mut provenance: Vec<Provenance> = Vec::new();
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
                                provenance.push(prov(path, ln, &id));
                                routes.push(json!({"line": ln, "text": trimmed.chars().take(200).collect::<String>()}));
                            }
                            if middleware_markers.iter().any(|m| code_trimmed.contains(*m)) {
                                provenance.push(prov(path, ln, &id));
                                middleware.push(json!({"line": ln, "text": trimmed.chars().take(200).collect::<String>()}));
                            }
                            if routes.len() + middleware.len() >= MAX_HITS {
                                break;
                            }
                        }
                    }
                    None => {
                        return Err(ToolError::InvalidArgument(format!("文件不存在: {}", file)))
                    }
                }
                IntelEnvelope {
                    data: json!({"file": file, "handler": handler, "routes": routes, "middleware": middleware}),
                    provenance,
                    uncertainty: Uncertainty::new("high", &["framework_graph_not_resolved"], 0),
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
