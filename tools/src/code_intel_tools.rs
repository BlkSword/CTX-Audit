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
    /// tree-sitter / file-heuristic / lsp / engine
    pub resolver: String,
    pub build_id: String,
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

fn should_skip(dir_name: &str) -> bool {
    SKIP_DIRS.contains(&dir_name)
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
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, dir_rel)) = stack.pop() {
        if out.len() >= MAX_FILES {
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
            if out.len() >= MAX_FILES {
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
    Provenance {
        file: Some(file.to_string()),
        line: Some(line),
        resolver: "file-heuristic".to_string(),
        build_id: id.to_string(),
    }
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
    let needle = format!("{}(", name);
    let mut hits = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.contains(&needle) {
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

/// 纯函数：从一行里提取 `(` 前的标识符（取最后一个点后的名字）。
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
        if name.len() >= 2 && !out.contains(&name) {
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
                IntelEnvelope {
                    data: json!({
                        "files": files.len(),
                        "languages": langs,
                        "build_id": id,
                        "index_freshness": freshness,
                        "limits": {
                            "max_files": MAX_FILES,
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
                    uncertainty: Uncertainty::new("low", &["index_is_stat_based"], 0),
                }
            }
            IntelKind::SymbolDefinition => {
                let symbol = input["symbol"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 symbol 参数".to_string()))?;
                let mut defs: Vec<Value> = Vec::new();
                let mut provenance: Vec<Provenance> = Vec::new();
                for (path, content) in files {
                    for (line, text) in find_definitions(content, symbol) {
                        provenance.push(prov(path, line, &id));
                        defs.push(json!({"file": path, "line": line, "text": text}));
                        if defs.len() >= MAX_HITS {
                            break;
                        }
                    }
                    if defs.len() >= MAX_HITS {
                        break;
                    }
                }
                let level = if defs.is_empty() { "high" } else { "medium" };
                IntelEnvelope {
                    data: json!({"symbol": symbol, "definitions": defs}),
                    provenance,
                    uncertainty: Uncertainty::new(
                        level,
                        &["keyword_heuristic", "import_alias_not_resolved"],
                        0,
                    ),
                }
            }
            IntelKind::SymbolReferences => {
                let symbol = input["symbol"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 symbol 参数".to_string()))?;
                let mut refs: Vec<Value> = Vec::new();
                let mut provenance: Vec<Provenance> = Vec::new();
                for (path, content) in files {
                    for (line, text) in find_references(content, symbol) {
                        provenance.push(prov(path, line, &id));
                        refs.push(json!({"file": path, "line": line, "text": text}));
                        if refs.len() >= MAX_HITS {
                            break;
                        }
                    }
                    if refs.len() >= MAX_HITS {
                        break;
                    }
                }
                IntelEnvelope {
                    data: json!({"symbol": symbol, "references": refs}),
                    provenance,
                    uncertainty: Uncertainty::new(
                        "medium",
                        &["same_name_not_disambiguated"],
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
                for (path, content) in files {
                    if direction != "callees" {
                        for (line, text) in find_call_sites(content, function) {
                            provenance.push(prov(path, line, &id));
                            callers.push(json!({"file": path, "line": line, "text": text}));
                        }
                    }
                    if direction != "callers" && content.contains(function) {
                        for line in content.lines() {
                            for name in callee_names(line) {
                                if name.as_str() != function {
                                    callees.push(json!({"name": name, "file": path}));
                                }
                                if callees.len() >= MAX_HITS {
                                    break;
                                }
                            }
                        }
                    }
                    if dynamic_markers.iter().any(|m| content.contains(*m)) {
                        unresolved += 1;
                    }
                    if callers.len() + callees.len() >= MAX_HITS {
                        break;
                    }
                }
                let level = if unresolved > 0 { "high" } else { "medium" };
                IntelEnvelope {
                    data: json!({"function": function, "callers": callers, "callees": callees}),
                    provenance,
                    uncertainty: Uncertainty::new(
                        level,
                        &["name_based_edges", "dynamic_dispatch_not_resolved"],
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
                match files.iter().find(|entry| entry.0.as_str() == file) {
                    Some((path, content)) => {
                        let lines: Vec<&str> = content.lines().collect();
                        let center = if line > 0 { line.min(lines.len()) } else { lines.len() };
                        let start = center.saturating_sub(depth);
                        for i in start..center {
                            let text = lines.get(i).copied().unwrap_or("");
                            if symbol.is_empty() || text.contains(symbol) || i + 1 == center {
                                provenance.push(prov(path, (i + 1) as u32, &id));
                                snippets.push(json!({"line": i + 1, "text": text.trim().chars().take(200).collect::<String>()}));
                            }
                        }
                    }
                    None => {
                        return Err(ToolError::InvalidArgument(format!("文件不存在: {}", file)))
                    }
                }
                IntelEnvelope {
                    data: json!({"file": file, "snippets": snippets}),
                    provenance,
                    uncertainty: Uncertainty::new(
                        "high",
                        &["line_window_not_true_dataflow_slice"],
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
                        for (idx, text) in content.lines().enumerate() {
                            let ln = (idx + 1) as i64;
                            if line > 0 && (ln - line).abs() > 60 {
                                continue;
                            }
                            let trimmed = text.trim();
                            if trimmed.starts_with("//") || trimmed.starts_with('#') {
                                continue;
                            }
                            if markers.iter().any(|m| trimmed.contains(*m)) {
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
                        for (idx, text) in content.lines().enumerate() {
                            let ln = (idx + 1) as u32;
                            let trimmed = text.trim();
                            if route_markers.iter().any(|m| trimmed.contains(*m))
                                && (handler.is_empty() || trimmed.contains(handler))
                            {
                                provenance.push(prov(path, ln, &id));
                                routes.push(json!({"line": ln, "text": trimmed.chars().take(200).collect::<String>()}));
                            }
                            if middleware_markers.iter().any(|m| trimmed.contains(*m)) {
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
}
