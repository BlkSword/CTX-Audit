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

mod locus;
pub(crate) use locus::*;
mod framework;
pub(crate) use framework::*;
mod index;
pub use index::*;
mod symbols;
pub use symbols::*;
mod dispatch;
pub use dispatch::*;

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
/// 派发候选目标上限（C 的能力面 C3）：按签名近似匹配的候选最多交付这么多条
const MAX_DISPATCH_CANDIDATES: usize = 8;
/// 参与候选匹配的间接调用点上限（只在**目标函数体内**取，成本有界且可预期）
const MAX_DISPATCH_SITES: usize = 16;
/// 候选匹配时枚举的已索引 C/C++ 定义上限（超出即如实上报被截断）
const MAX_DISPATCH_SIGNATURE_SPACE: usize = 20000;
/// 跨行签名续行的最大行数（C 的 80 列风格：形参表多数在 2–6 行内闭合）
const MAX_SIGNATURE_JOIN_LINES: usize = 12;
/// 函数摘要上限（C 的能力面 C2）：一次响应最多给这么多函数出摘要
const MAX_FUNCTION_SUMMARIES: usize = 8;
/// **项目级**（全项目汇总，非单函数）候选派发采集的间接调用点上限。
///
/// 单函数口径用 `MAX_DISPATCH_SITES`；项目级口径的站点来源是"所有已索引 C 类函数的体"，
/// 数量不可预估，因此必须另设上限并如实上报截断（`sites_truncated_at_limit`）。
const MAX_PROJECT_DISPATCH_SITES: usize = 64;
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
            IntelKind::DataflowPath => "source→sink **行区间**（按行序，非 def-use/污点链）；响应会标注该语言是否受分析管线支持，可达性请配合调用层次/引用",
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
                // 本构建启用的宏/后端：只读解析构建产物（CMakeCache.txt / config.h），
                // 拿不到就如实报 unknown——用于让 C 的条件编译可判（此前只能人工读构建目录）。
                let build_context = probe_build_context(root);
                let analysis_backed = caps["analysis_backed"].as_bool().unwrap_or(false);
                let mut cap_reasons: Vec<&str> = vec!["index_is_stat_based"];
                if !analysis_backed {
                    cap_reasons.push("project_language_outside_primary_set");
                }
                if build_context["confidence"] == json!("unknown") {
                    cap_reasons.push("build_context_unavailable");
                }
                IntelEnvelope {
                    data: json!({
                        "files": files.len(),
                        "languages": langs,
                        "build_id": id,
                        "index_freshness": freshness,
                        "capabilities": caps,
                        "build_context": build_context,
                        // 索引期上报的源码侧条件编译宏（与 build_context 互补：后者读构建产物，
                        // 裸克隆时是 unknown；本字段只报源码事实）。
                        "source_conditionals": collect_source_conditionals(files),
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
                // C3：目标函数体内"解析不出目标"的调用点（与 `unresolved` 同一次扫描收集，
                // 站点数上限 MAX_DISPATCH_SITES，成本有界）
                let mut dispatch_sites: Vec<IndirectCallSite> = Vec::new();
                // 脚本语言的动态派发标记：**只作为非 C 类文件的兜底**。
                // C 类文件改走"逐调用点计数"（`count_indirect_call_sites`），见下方注释。
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
                        // C：调用点必须落在**某个函数体内部**——原型/声明行与**函数定义行本身**
                        // 都不是调用点。实测把它们算进 callers 使精确率只有 0.839
                        // （cscope 真值 172 条 / 引擎报 205 条）。
                        // 注意：**不能**用"顶格 + `;` 结尾"近似替代——那条规则会误杀 5 条真调用
                        // （实测召回 1.000 → 0.971 而精确率只到 0.865，已否决回退）。
                        // 显式条件编译过滤：此前 callers 侧**只**靠 `c_bodies` 间接生效
                        //（死函数没有体 ⇒ 死分支里的调用点被体过滤挡掉），非 C 语言没有这层兜底。
                        let (caller_pp, _caller_note) = preproc_view(path, content, true);
                        let c_bodies: Vec<(usize, usize)> = if is_c_like_path(path) {
                            sindex
                                .file_index(path)
                                .map(|fi| {
                                    sindex
                                        .definitions_in_file(fi)
                                        .into_iter()
                                        .map(|(_, def_line, _)| {
                                            let def_idx = (def_line as usize).saturating_sub(1);
                                            let (_, end) = body_span(&lines, def_idx, is_brace_language(path));
                                            (def_idx, end)
                                        })
                                        .collect()
                                })
                                .unwrap_or_default()
                        } else {
                            Vec::new()
                        };
                        // 目标函数**自己的定义行**不是调用点。C 由 `c_bodies`（调用点必须落在
                        // 某个函数体内）挡住；非 C 没有体过滤，于是 Java 的
                        // `public int handle(String s) {` 被当成 caller（实测 FP；Go/Rust/Python
                        // 无此问题——它们的定义行带 `func`/`fn`/`def` 关键字，已被调用点判据排除）。
                        // 这里统一用索引里的定义行下手，不去推广 C 的体过滤。
                        let own_def_lines: Vec<u32> = sindex
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
                        for needle in &needles {
                            for (line, text) in find_call_sites_in_code(&lines, &code, needle, scan_cap) {
                                let idx = (line as usize).saturating_sub(1);
                                // 接口/抽象方法**声明**不是调用点（Go/Java/TS 接口体）
                                if in_interface_block(&lines, idx) {
                                    continue;
                                }
                                if caller_pp.get(idx).map(|s| s.dead).unwrap_or(false) {
                                    continue; // 未激活分支里的调用点不是一条边
                                }
                                if own_def_lines.contains(&line) {
                                    continue; // 定义行本身（索引里认得出来时）
                                }
                                // 索引认不出该定义时（实测：Java 的 `public int handle(String s) {`
                                // 不在符号索引里）用形态判据兜底：整行只有"修饰/类型 + name(参数) {"
                                let next_is_brace = code
                                    .iter()
                                    .skip(idx + 1)
                                    .map(|s| s.trim())
                                    .find(|s| !s.is_empty())
                                    .map(|s| s.starts_with('{'))
                                    .unwrap_or(false);
                                if looks_like_definition_header(&text, function, next_is_brace) {
                                    continue;
                                }
                                if !c_bodies.is_empty()
                                    && !c_bodies.iter().any(|(s, e)| idx > *s && idx <= *e)
                                {
                                    continue; // 不在任何函数体内 ⇒ 原型/定义行
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
                    // ── 未解析边：从"每文件一次的子串探测"改为"逐调用点计数" ──
                    // 旧判据是"整个文件里出现过脚本语言的动态派发关键字就 +1"，于是 C 的
                    // `p->handler(...)` / `(*fp)(...)` / `table[i](...)` **一条都不计**，
                    // `unresolved_edges` 在 C 上结构性恒 0 —— 那等于向判定者宣称"调用图已闭合"。
                    // 口径与查询方向无关（它描述"这张图有多少条边解析不出来"）：始终统计
                    // **目标函数体内**的间接调用点。
                    if is_c_like_path(path) {
                        let code_u = code_lines(content, hash_comment_language(path));
                        let code_refs_u: Vec<&str> = code_u.iter().map(|s| s.as_str()).collect();
                        let brace_u = is_brace_language(path);
                        let def_lines_u: Vec<u32> = sindex
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
                        for def_line in def_lines_u {
                            let def_idx = (def_line as usize).saturating_sub(1);
                            let (s0, e0) = body_span(&code_refs_u, def_idx, brace_u);
                            // 数值语义不变：`unresolved_edges` 仍由这个已冻结的计数函数给出
                            unresolved += count_indirect_call_sites(&code_refs_u, s0, e0);
                            if dispatch_sites.len() < MAX_DISPATCH_SITES {
                                let mut found = indirect_call_sites(&code_refs_u, s0, e0);
                                let room = MAX_DISPATCH_SITES - dispatch_sites.len();
                                found.truncate(room);
                                dispatch_sites.extend(found);
                            }
                        }
                    } else if dynamic_markers.iter().any(|m| content.contains(*m)) {
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
                // C2 证据字段：对本次返回的函数（目标 + 去重后的 callee 名）给出**有界**摘要
                let mut summary_names: Vec<String> = vec![function.to_string()];
                for c in &callees {
                    if let Some(n) = c["name"].as_str() {
                        if !summary_names.iter().any(|s| s == n) {
                            summary_names.push(n.to_string());
                        }
                    }
                }
                let function_summaries =
                    function_summaries_evidence(root, &sindex, &summary_names);
                let summaries_available = function_summaries
                    .get("available_summaries")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                // C3 证据字段：解析不出目标的调用点 → 按签名匹配的候选目标集合。
                // 只加证据：不进 findings、不改 `unresolved_edges` 的数值语义。
                let dispatch_candidates = dispatch_candidates_evidence(
                    &sindex,
                    &dispatch_sites,
                    Some(function),
                    files,
                );
                let dispatch_has_candidates = dispatch_candidates
                    .get("candidates")
                    .and_then(|c| c.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false);
                let mut ch_reasons: Vec<&str> = vec![
                    "name_based_edges",
                    "dynamic_dispatch_not_resolved",
                    "callees_scoped_to_function_body",
                ];
                if dispatch_has_candidates {
                    // 字段级如实标注：这些候选是**签名启发式**，不是解析结果
                    ch_reasons.push("dispatch_candidates_are_signature_heuristic");
                } else if !dispatch_sites.is_empty() {
                    ch_reasons.push("dispatch_targets_unresolved_no_signature_match");
                }
                if summaries_available > 0 {
                    // 摘要是**单函数**范围内的（单文件污点流），不是完整过程间结论
                    ch_reasons.push("function_summaries_single_function_scope");
                }
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
                        "dispatch_candidates": dispatch_candidates,
                        "function_summaries": function_summaries,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(level, &ch_reasons, unresolved),
                }
            }
            IntelKind::SliceBackward => {
                let file = input["file"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 file 参数".to_string()))?;
                let line = input["line"].as_i64().unwrap_or(0).max(0) as usize;
                let depth = input["depth"].as_i64().unwrap_or(40).clamp(1, 200) as usize;
                // 前向窗口：危险点**之后**的谓词/危险操作常常才是决定性证据。
                // 默认 8 行、上限 40；`forward: 0` 可退回纯后向（用于与旧二进制做 A/B 对照）。
                let forward = input["forward"].as_i64().unwrap_or(8).clamp(0, 40) as usize;
                // 标识符驱动的前向扩展上限（默认 64）：目标行上的标识符（如 `len`）在标称窗口
                // 之外还有使用时，把窗口扩到**最后一处**使用——真实 CVE 的决定性使用常在
                // +20…+50 行（旧的 40 行上限够不着）。
                let forward_max = input["forward_max"].as_i64().unwrap_or(64).clamp(0, 200) as usize;
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
                let mut saw_conditional = false;
                let mut preproc_states: Vec<crate::text_scan::PreprocLine> = Vec::new();
                let mut preproc_note: Option<String> = None;
                let mut cpp_fallback = false;
                let mut forward_extended_for: Vec<String> = Vec::new();
                let mut decl_added = false;
                let mut window_start = 0usize;
                let mut window_end = 0usize;
                let mut forward_used = 0usize;
                let mut forward_bounded_by: &str = "requested";
                // 作用域锚点位置（在 match 之外读取，故在此声明）
                let mut scope_anchor: Value = Value::Null;
                // C3：所在函数体内"解析不出目标"的调用点 → 签名候选集合（同样在 match 之外读取）
                let mut dispatch_candidates: Value =
                    dispatch_candidates_evidence(&sindex, &[], None, files);
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
                        // 条件编译状态：`#if 0` 里的行**可证死**（不进切片）；`#ifdef` 一类无法
                        // 判定的，先由行级判据标 `conditional`，能起 `cpp -E` 时再按真实分支求值
                        // 升级为 dead；`cpp` 不可用则**如实降级并记录原因**。
                        let (pp_states, pp_note) = preproc_view(path, content, false);
                        preproc_states = pp_states;
                        cpp_fallback = pp_note.is_some();
                        preproc_note = pp_note;
                        // 体范围判定用代码段（多行字符串里的顶格行不应被当成 dedent）
                        let code = code_lines(content, hash_comment_language(path));
                        let code_refs: Vec<&str> = code.iter().map(|s| s.as_str()).collect();
                        let center = if line > 0 { line.min(lines.len()) } else { lines.len() };
                        let brace = is_brace_language(path);
                        // K&R 容忍只在 C 类文件生效（跨语言误召回的入口，必须门控）
                        let c_like = is_c_like_path(path);
                        // 目标行之前最后一条声明，且其函数体覆盖目标行 ⇒ 它就是所在函数。
                        //
                        // 归属选择**优先**取"自身能解析为函数头"的定义：函数体内的局部声明
                        // （`struct X *p = NULL;`）一旦进入索引，就会因 `body_span` 探到后续
                        // `{`（`} else if (…) {`）而通过覆盖测试，并靠"取最近"盖过真正的函数头
                        // ⇒ `function` 变成类型名/变量名。
                        //
                        // 兜底顺序保证不整片丢失归属：解析不出函数头的定义形态（无法用 C/JS
                        // 头部规则识别的定义）在没有可解析候选时仍按旧口径取最近一条。
                        let mut defs: Vec<(String, u32, String)> = sindex
                            .file_index(path)
                            .map(|fi| {
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
                                    .collect()
                            })
                            .unwrap_or_default();
                        defs.sort_by_key(|(_, def_line, _)| *def_line);
                        let parses_as_header = |def_line: u32| -> bool {
                            let idx = (def_line as usize).saturating_sub(1);
                            let code_line = code_refs.get(idx).copied().unwrap_or("");
                            let following: Vec<&str> = code_refs
                                .iter()
                                .skip(idx + 1)
                                .filter(|s| !s.trim().is_empty())
                                .take(6)
                                .copied()
                                .collect();
                            function_header_name_multi(code_line, &following, c_like).is_some()
                        };
                        let enclosing = defs
                            .iter()
                            .filter(|(_, def_line, _)| parses_as_header(*def_line))
                            .next_back()
                            .or_else(|| defs.last())
                            .cloned();
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
                            //    （某 JS 库里位于字符串数组中的一行：上方最近的函数已闭合
                            //     ⇒ 应保持 unresolved）；
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
                                function_header_name_multi(self_code, &self_following, c_like)
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
                                if let Some(name) = function_header_name_multi(code_line, &following, c_like) {
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
                        // 前向上界取三者最小：目标行 + forward、所在函数体末行、文件末行。
                        // 不越过函数体，避免把下一个函数的代码当成"后文证据"。
                        let body_end = function_def_line
                            .and_then(|l| {
                                let idx = (l as usize).saturating_sub(1);
                                code_refs.get(idx).map(|_| {
                                    let (_, end) = body_span(&code_refs, idx, brace);
                                    end + 1 // 0-based 闭区间 → 1-based 行号
                                })
                            })
                            .unwrap_or(lines.len());
                        let requested_end = center.saturating_add(forward);
                        let end_cap = body_end.min(lines.len());
                        window_end = requested_end.min(end_cap);
                        forward_used = window_end.saturating_sub(center);
                        forward_bounded_by = if window_end < requested_end {
                            if end_cap == body_end {
                                "function_body"
                            } else {
                                "file_end"
                            }
                        } else {
                            "requested"
                        };
                        // ── 标识符驱动扩展：目标行上的标识符在窗口之外还有使用时，扩到**最后一处** ──
                        // `forward: 0` 保持纯后向（A/B 对照口径），此时不做扩展。
                        if forward > 0 && forward_max > 0 {
                            let target_text =
                                lines.get(center.saturating_sub(1)).copied().unwrap_or("");
                            let hard_end = center.saturating_add(forward_max).min(end_cap);
                            let mut drivers: Vec<String> = Vec::new();
                            let mut last_use: Option<usize> = None;
                            for ident in crate::text_scan::identifiers_in_line(target_text) {
                                if ident.len() < 3 || is_stop_ident(&ident) {
                                    continue;
                                }
                                let mut hit = false;
                                for j in window_end..hard_end {
                                    if crate::text_scan::contains_identifier(
                                        lines.get(j).copied().unwrap_or(""),
                                        &ident,
                                    ) {
                                        hit = true;
                                        last_use = Some(last_use.map_or(j, |m: usize| m.max(j)));
                                    }
                                }
                                if hit {
                                    drivers.push(ident);
                                }
                            }
                            if let Some(j) = last_use {
                                window_end = (j + 1).min(end_cap);
                                forward_extended_for = drivers;
                                forward_bounded_by = "identifier_use";
                            }
                        }
                        // 作用域锚点的**位置事实**：函数头落在标称深度窗口内，还是因为函数太长
                        // 而必须把窗口向前扩展才装得下。注意窗口起点是 `min(center-depth, 头行-1)`
                        //（见上），所以解析成功时头**一定**在返回窗口里——这里区分的是"窗口被扩展过"，
                        // 消费者据此知道本次窗口比 `depth` 更宽。
                        scope_anchor = match function_def_line {
                            None => Value::Null,
                            Some(l) if (l as usize) + depth > center => json!("within_depth"),
                            Some(_) => json!("extended_for_long_function"),
                        };
                        for i in start..window_end {
                            let text = lines.get(i).copied().unwrap_or("");
                            let st = preproc_states.get(i).copied().unwrap_or_default();
                            if st.dead {
                                continue; // `#if 0` 里的行不进切片（活代码视图）
                            }
                            let is_header = function_def_line.map(|l| l as usize == i + 1).unwrap_or(false);
                            let is_target = i + 1 == center;
                            let is_after_target = i + 1 > center;
                            if is_after_target
                                || symbol.is_empty()
                                || is_header
                                || is_target
                                || text.contains(symbol)
                            {
                                if is_header {
                                    includes_function_header = true;
                                }
                                if st.conditional {
                                    saw_conditional = true;
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
                                    "is_after_target": is_after_target,
                                    "in_conditional_region": st.conditional,
                                }));
                            }
                        }
                        // ── 窗口内标识符的**声明行**：判定常要看类型/容量，而声明可能远在窗口
                        // 上方（真实 CVE：`uint16_t n_columns;` 在目标行上方约 170 行）。只交付
                        // 原文行并标注来源（`declaration_for`），**不做任何推断**。
                        {
                            let target_text =
                                lines.get(center.saturating_sub(1)).copied().unwrap_or("");
                            let mut seen: std::collections::HashMap<String, usize> =
                                std::collections::HashMap::new();
                            let mut order: Vec<String> = Vec::new();
                            for s in &snippets {
                                if let Some(t) = s.get("text").and_then(|v| v.as_str()) {
                                    for ident in crate::text_scan::identifiers_in_line(t) {
                                        if ident.len() < 3 || is_stop_ident(&ident) {
                                            continue;
                                        }
                                        *seen.entry(ident.clone()).or_insert(0) += 1;
                                        if !order.contains(&ident) {
                                            order.push(ident);
                                        }
                                    }
                                }
                            }
                            // 优先级：① **目标行上**的标识符（判定几乎总要它的类型/容量）；
                            // ② 在窗口里出现 ≥2 次的（一次性类型名多半与判定无关，先不取）。
                            let mut prio: Vec<String> = Vec::new();
                            for ident in crate::text_scan::identifiers_in_line(target_text) {
                                if ident.len() >= 3
                                    && !is_stop_ident(&ident)
                                    && !prio.contains(&ident)
                                {
                                    prio.push(ident);
                                }
                            }
                            for ident in &order {
                                if !prio.contains(ident)
                                    && seen.get(ident).copied().unwrap_or(0) >= 2
                                {
                                    prio.push(ident.clone());
                                }
                            }
                            let mut added = 0usize;
                            for ident in &prio {
                                for idx in find_declaration_lines(&lines, ident, 2) {
                                    if added >= 6 {
                                        break;
                                    }
                                    let in_window = idx >= window_start && idx < window_end;
                                    if in_window {
                                        continue;
                                    }
                                    let text = lines.get(idx).copied().unwrap_or("");
                                    provenance.push(prov_with(
                                        path,
                                        (idx + 1) as u32,
                                        &id,
                                        "slice+identifier-declaration",
                                    ));
                                    snippets.push(json!({
                                        "line": idx + 1,
                                        "text": text.trim().chars().take(200).collect::<String>(),
                                        "is_function_header": false,
                                        "is_target": false,
                                        "is_after_target": false,
                                        "in_conditional_region": preproc_states.get(idx).map(|s| s.conditional).unwrap_or(false),
                                        "declaration_for": ident,
                                    }));
                                    added += 1;
                                }
                            }
                            decl_added = added > 0;
                        }
                        // C3：所在函数体内解析不出目标的调用点（函数指针 / 成员指针 / 表下标派发）
                        // → 按签名匹配的候选目标集合。只对 C/C++ 生效（候选来源也是已索引的 C/C++ 定义），
                        // 且只在作用域解析成功时做（否则"函数体内"没有确定的边界）。
                        if c_like {
                            if let Some(def_line) = function_def_line {
                                let def_idx = (def_line as usize).saturating_sub(1);
                                let (b0, b1) = body_span(&code_refs, def_idx, brace);
                                let mut sites = indirect_call_sites(&code_refs, b0, b1);
                                sites.truncate(MAX_DISPATCH_SITES);
                                dispatch_candidates = dispatch_candidates_evidence(
                                    &sindex,
                                    &sites,
                                    function_name.as_deref(),
                                    files,
                                );
                            }
                        }
                    }
                    None => {
                        return Err(ToolError::InvalidArgument(format!("文件不存在: {}", file)))
                    }
                }
                // 判定要素：检查行 / 容量锚点 / 最小窗口；缺席即 no_check_found。
                // 可达性视图：签名字面参数 + 调用者（倒排索引），并明确不是污点证明。
                // 内容在这里自包含取回（Some 分支内的 lines/center/code_refs 已出作用域）。
                let fact_content: String = files
                    .iter()
                    .find(|(p, _)| p == file)
                    .map(|(_, c)| c.clone())
                    .or_else(|| std::fs::read_to_string(root.join(file)).ok())
                    .unwrap_or_default();
                let fact_code = code_lines(&fact_content, hash_comment_language(file));
                let fact_refs: Vec<&str> = fact_code.iter().map(|s| s.as_str()).collect();
                let fact_total = fact_content.lines().count().max(1);
                let fact_center = if line > 0 { line.min(fact_total) } else { fact_total };
                let fact_brace = is_brace_language(file);
                let fact_lines: Vec<&str> = fact_content.lines().collect();
                let fact_fn_idx = function_def_line
                    .map(|l| (l as usize).saturating_sub(1))
                    .unwrap_or(fact_center.saturating_sub(1));
                let (fn_start, fn_end) = body_span(&fact_refs, fact_fn_idx, fact_brace);
                let (decision_facts, reachability) = locus_facts(
                    root,
                    files,
                    &fact_refs,
                    &fact_lines,
                    fn_start,
                    fn_end,
                    fact_center.saturating_sub(1),
                    function_name.as_deref(),
                    function_signature.as_deref(),
                    PRIMARY_ANALYSIS_LANGUAGES.contains(&language_of(file)),
                    &sindex,
                );
                // 归属优先走 AST（core 的 tree-sitter，语言无关）；失败则保留启发式结果并如实标注来源。
                let (function_name, function_def_line, function_signature, scope_source) = {
                    let mut source = "index_heuristic";
                    let mut fname = function_name;
                    let mut fdef = function_def_line;
                    let mut fsig = function_signature;
                    if let Some((name, start_line, _end, body_start)) =
                        ast_enclosing_function(root, file, &fact_content, line as u32)
                    {
                        // 只有 AST 给出**实名**时才接管：匿名/占位名（`<anonymous@N>`）不得把
                        // 启发式得来的可用名字换掉（实测：JS 对象属性函数表达式上会退化）。
                        let named = !name.is_empty() && !name.starts_with('<');
                        if named {
                            source = "ast";
                            // `function_def_line` 语义 = **函数头（名字所在）行**：在
                            // [start_line, body_start] 内取首个含该名字的行（语言中立搜索，非语法正则）。
                            let header = (start_line..=body_start.max(start_line))
                                .find(|l| {
                                    fact_lines
                                        .get(l.saturating_sub(1))
                                        .map(|s| s.contains(&name))
                                        .unwrap_or(false)
                                })
                                .unwrap_or(start_line);
                            fname = Some(name.clone());
                            fdef = Some(header as u32);
                            fsig = fact_lines
                                .get(header.saturating_sub(1))
                                .map(|s| s.trim().chars().take(200).collect::<String>());
                        }
                    }
                    (fname, fdef, fsig, source)
                };

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
                    // 归属来源：ast = core 的 tree-sitter 命中；index_heuristic = 索引/文本启发式
                    "scope_source": scope_source,
                        // `within_depth`：函数头落在标称深度窗口内；`extended_for_long_function`：
                        // 函数太长，窗口被向前扩展才装下头（此时 `window.start_line` 会明显早于
                        // `target_line - depth`）；`null`：未解析到作用域
                        "scope_anchor": scope_anchor,
                        "nearest_declaration": nearest_declaration,
                        "includes_function_header": includes_function_header,
                        "target_line": if line > 0 { json!(line) } else { Value::Null },
                        "window": {"start_line": window_start + 1, "end_line": window_end},
                        "depth": depth,
                        "forward": forward,
                        "forward_max": forward_max,
                        "forward_lines_returned": forward_used,
                        "forward_extended_for": forward_extended_for.clone(),
                        "forward_bounded_by": forward_bounded_by,
                        "lines_returned": snippets.len(),
                        "index": symbol_index_stats(&sindex, s_hit, s_build_ms),
                        "preprocess_note": preproc_note,
                        "dispatch_candidates": dispatch_candidates,
                        "snippets": snippets,
                        "decision_facts": decision_facts,
                        "reachability": reachability,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(
                        "high",
                        &{
                            let mut reasons = vec![
                                "backward_prefix_not_dataflow_slice",
                                "function_header_included_when_found",
                            ];
                            if forward_used > 0 {
                                // 如实说明：目标行之后的这段是**固定下探**，不是数据流推导
                                reasons.push("forward_window_is_heuristic_lookahead");
                            }
                            if saw_conditional {
                                // 窗口里有**无法判定**的条件编译区（`#ifdef X` 之类）：
                                // 我们不知道编译配置，只能如实标注，不能假装这段一定参与编译
                                reasons.push("conditional_compilation_region_present");
                            }
                            if cpp_fallback {
                                // 想用 `cpp -E` 求真实分支但起不来（缺 cpp / 缺 include）：
                                // 如实说明"此刻只有行级判据，未激活分支可能仍被当成活代码"
                                reasons.push("cpp_preprocess_unavailable_line_level_fallback");
                            }
                            if !forward_extended_for.is_empty() {
                                // 窗口因"目标行上的标识符在更下面还有使用"而被扩展：
                                // 如实说明它比标称深度更宽，以及**为什么**宽
                                reasons.push("forward_window_extended_for_identifier_use");
                            }
                            if decl_added {
                                // 窗口内标识符的声明行（可能远在窗口上方）也被交付：
                                // 这些是**原文附加证据**，不是推断出来的结论
                                reasons.push("window_identifier_declarations_included");
                            }
                            if dispatch_candidates
                                .get("candidates")
                                .and_then(|c| c.as_array())
                                .map(|a| !a.is_empty())
                                .unwrap_or(false)
                            {
                                // 与 get_call_hierarchy 同一口径：这些候选是**签名启发式**，不是解析结果
                                reasons.push("dispatch_candidates_are_signature_heuristic");
                            }
                            reasons
                        },
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
                let mut df_note: Option<String> = None;
                let mut df_fallback = false;
                // source 侧命中的源码行（用于"来源是否像本地配置/命令行"的噪声标注）
                let mut df_source_line: Option<String> = None;
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
                    let (pp_states, pp_note) = preproc_view(path, content, true);
                    if pp_note.is_some() {
                        df_fallback = true;
                        if df_note.is_none() {
                            df_note = pp_note;
                        }
                    }
                    // 源点落在**未激活分支**里 ⇒ 这条"路径"在当前配置下不存在，不是证据
                    if pp_states.get(src_idx).map(|s| s.dead).unwrap_or(false) {
                        continue;
                    }
                    // 只有**真的会交付路径**的源点才参与来源噪声标注（未激活分支里的不算）
                    if df_source_line.is_none() {
                        df_source_line =
                            Some(lines[src_idx].trim().chars().take(200).collect::<String>());
                    }
                    let sink_idx = if sink.is_empty() {
                        None
                    } else {
                        lines.iter().position(|l| l.contains(sink))
                    };
                    let end = sink_idx.unwrap_or(src_idx + 10).min(lines.len().saturating_sub(1));
                    let (lo, hi) = if src_idx <= end { (src_idx, end) } else { (end, src_idx) };
                    for i in lo..=hi {
                        if pp_states.get(i).map(|s| s.dead).unwrap_or(false) {
                            continue; // 未激活分支里的行不进"路径"
                        }
                        provenance.push(prov(path, (i + 1) as u32, &id));
                        steps.push(json!({"file": path, "line": i + 1, "text": lines[i].trim().chars().take(200).collect::<String>()}));
                    }
                    if steps.len() >= MAX_HITS * 4 {
                        break;
                    }
                }
                // ── source 模型去噪（只加标注，不改路径）──
                // 来源若是本进程的 argv/getenv/配置文件/选项结构体，判定者不应把它当远端输入。
                // 标注口径：命中信号才追加 uncertainty 理由；未命中只报 `not_observed`。
                let origin_signals = local_configuration_signals(source, df_source_line.as_deref());
                let source_origin = json!({
                    "classification": if origin_signals.is_empty() {
                        "not_observed"
                    } else {
                        "local_configuration_like"
                    },
                    "signals": origin_signals,
                    "observed_source_line": df_source_line,
                    "note": "标注不等于结论：命中只表示该来源**可能**来自本地配置/命令行\
                             （argv/getenv/配置文件/选项结构体），需人工确认它是否真的可由远端输入控制；\
                             未命中也不代表一定是远端可控输入。",
                });
                // ── 如实标注"这不是数据流链" ──
                // `path` 的生成方式是"source 首次出现行 → sink 首次出现行之间的**行区间**（按行序）"，
                // 不是 def-use / 污点链。真实 C 文件里这段区间常被原型声明、无关语句填满
                // （实测：某解析器上 10 行里 9 行是函数原型）。字段名若被当作"路径"读，
                // 会把噪声当证据 ⇒ 这里显式给出 `path_kind` / `dataflow_verified`
                // 与"声明样行"计数，并追加 uncertainty 理由。
                let declaration_like = steps
                    .iter()
                    .filter(|s| {
                        let t = s["text"].as_str().unwrap_or("").trim();
                        t.ends_with(';')
                            && t.contains('(')
                            && !t.contains('=')
                            && !t.starts_with("if")
                            && !t.starts_with("for")
                            && !t.starts_with("while")
                            && !t.starts_with("return")
                            && !t.starts_with("switch")
                    })
                    .count();
                // **按语言区分**：本工具的实现对所有语言都是"行区间"，但只有**分析受支持的语言**
                // （见 PRIMARY_ANALYSIS_LANGUAGES）才有语义管线兜底；其余语言（如 C/C++）必须明确
                // 告知消费者"不要用它判可达性，请改用调用层次/引用"。
                let df_backed = only_file
                    .map(|f| PRIMARY_ANALYSIS_LANGUAGES.contains(&language_of(f)))
                    .unwrap_or(false);
                let df_scope = only_file.unwrap_or("<all indexed files>").to_string();
                IntelEnvelope {
                    data: json!({"source": source, "sink": sink, "path": steps,
                                 "path_kind": "source_sink_line_span",
                                 "dataflow_verified": false,
                                 "language_analysis_backed": df_backed,
                                 "language_scope": df_scope,
                                 "recommended_for_reachability": false,
                                 "recommendation": if df_backed {
                                     "本语言有分析管线：可达性请用引擎的污点/跨文件分析（CLI `--taint` / `--cross-file`）或 get_call_hierarchy；本工具只给行区间"
                                 } else {
                                     "本语言**不受分析管线支持**：可达性请用 get_call_hierarchy / get_symbol_references，不要依赖本工具"
                                 },
                                 "span_statistics": {
                                     "lines": steps.len(),
                                     "declaration_like_lines": declaration_like,
                                 },
                                 "path_note": "path 是 source 首次出现行到 sink 首次出现行之间的**行区间**（按行序），\
                                               不是 def-use / 污点链：区间内可能包含大量无关行（原型声明、无关语句）。\
                                               要判可达性请配合 get_call_hierarchy / get_symbol_references。",
                                 "preprocess_note": df_note,
                                 "source_origin": source_origin}),
                    provenance,
                    uncertainty: Uncertainty::new(
                        "high",
                        &{
                            let mut reasons = vec![
                                "statement_level_heuristic",
                                "path_is_line_span_not_dataflow_chain",
                            ];
                            if !df_backed {
                                reasons.push("language_not_analysis_backed_use_topology_tools");
                            }
                            if df_fallback {
                                reasons.push("cpp_preprocess_unavailable_line_level_fallback");
                            }
                            if !origin_signals.is_empty() {
                                reasons.push("source_may_be_local_configuration");
                            }
                            reasons
                        },
                        0,
                    ),
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
                let mut guard_scope = "line_window";
                let mut preproc_note: Option<String> = None;
                let mut cpp_fallback = false;
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
                        let code_refs: Vec<&str> = code.iter().map(|s| s.as_str()).collect();
                        let brace = is_brace_language(path);
                        let originals: Vec<&str> = content.lines().collect();
                        // 守卫也是"证据"：**未激活分支**里的条件分支不算守卫——
                        // 否则会把 `#if 0` 里的 `if` 交付给判定者（实测过）。
                        let (pp_states, pp_note) = preproc_view(path, content, false);
                        cpp_fallback = pp_note.is_some();
                        preproc_note = pp_note;
                        // ── 守卫的作用域必须限定在**目标行所在函数**内 ──
                        // 此前只用"目标行 ±60 行"窗口，会跨越函数边界，把**上一个函数**的守卫
                        // 交付给判定者（实测：某文件第 613 行返回了 555/557/562 行的守卫；
                        // 对 zip.c 的第 2313 行返回了 2257/2258/2270 行——都早于函数定义行）。
                        // 判定者据此会误以为"本处已被净化"，是**假阴性**的来源。复用切片同款
                        // `body_span` 做包含性判定，不引入新的解析口径；取不到函数边界时保持
                        // 原窗口并在 data 里如实标注 `guard_scope=line_window`。
                        let enclosing_span: Option<(usize, usize)> = {
                            let target_idx = (line.max(1) as usize).saturating_sub(1);
                            if brace && line > 0 && target_idx < code_refs.len() {
                                let mut d = target_idx;
                                let mut found = None;
                                while d > 0 {
                                    d -= 1;
                                    let l = code_refs.get(d).copied().unwrap_or("");
                                    if !l.contains('(') || l.trim_end().ends_with(';') {
                                        continue;
                                    }
                                    let (_, end) = body_span(&code_refs, d, brace);
                                    if end >= target_idx && end > d {
                                        found = Some((d, end));
                                        break;
                                    }
                                }
                                found
                            } else {
                                None
                            }
                        };
                        guard_scope = if enclosing_span.is_some() {
                            "enclosing_function"
                        } else {
                            "line_window"
                        };
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
                            if is_import_or_package_line(code_trimmed) {
                                continue;
                            }
                            if code_trimmed.starts_with('#') {
                                continue; // 预处理器指令行（`#if 0` 本身含 "if "）不是守卫
                            }
                            if pp_states.get(idx).map(|s| s.dead).unwrap_or(false) {
                                continue; // 未激活分支里的"守卫"不是证据
                            }
                            if let Some((fs, fe)) = enclosing_span {
                                if idx < fs || idx > fe {
                                    continue; // 跨函数的守卫不是本处的净化证据
                                }
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
                        "guard_scope": guard_scope,
                        "guards": guards,
                        "total_hits": guards_total,
                        "limit": MAX_HITS,
                        "truncated_at_limit": guards_total > MAX_HITS,
                        "preprocess_note": preproc_note,
                    }),
                    provenance,
                    uncertainty: Uncertainty::new(
                        "medium",
                        &{
                            let mut reasons = vec!["guard_semantics_not_validated"];
                            if guard_scope == "line_window" {
                                // 取不到函数边界 ⇒ 交付的守卫可能来自**别的函数**，如实标注
                                reasons.push("guard_scope_is_line_window");
                            }
                            if cpp_fallback {
                                reasons.push("cpp_preprocess_unavailable_line_level_fallback");
                            }
                            reasons
                        },
                        0,
                    ),
                }
            }
            IntelKind::FrameworkContext => {
                // 跨文件安全配置证据：此刻 `files` 仍是项目全量索引（下面会被按需单文件遮蔽）。
                let module_root = module_root_of(files, input["file"].as_str().unwrap_or(""));
                let scoped_evidence: Vec<(String, String)> = match &module_root {
                    Some(r) => files
                        .iter()
                        .filter(|(p, _)| p.replace('\\', "/").starts_with(r.as_str()))
                        .cloned()
                        .collect(),
                    None => Vec::new(),
                };
                let evidence_files: &[(String, String)] = if scoped_evidence.is_empty() {
                    files
                } else {
                    &scoped_evidence
                };
                let mut all_chains = security_config_chains(evidence_files);
                    all_chains.extend(reactive_security_chains(evidence_files));
                    all_chains.extend(spring_xml_security_chains(evidence_files));
                // 跨文件证据面必须在 `files` 被"按需单文件"遮蔽**之前**预取：
                // 否则只会扫描被请求的那个文件（实测：容器过滤器与拦截器注册因此整批漏掉）
                let container_filters = container_filter_registrations(evidence_files);
                let interceptor_regs = interceptor_registrations(evidence_files);
                // 反应式配置未建模：需要被发现才能如实标注（同样在"按需单文件"遮蔽之前取）
                let reactive_cfg = reactive_security_config(evidence_files);
                // 未建模保护栈信号（Sa-Token 等）：必须能在遮蔽前取到，才能如实标注
                let unmodeled_signals = unmodeled_protection_signals(evidence_files);
                all_chains.extend(shiro_filter_chains(evidence_files));
                let security_config_decls = security_config_declarations(evidence_files);
                let file = input["file"]
                    .as_str()
                    .ok_or_else(|| ToolError::InvalidArgument("缺少 file 参数".to_string()))?;
                let handler = input["handler"].as_str().unwrap_or("");
                let route_markers = [
                    "@app.route", "@router.", "@RequestMapping", "app.get(", "router.get(",
                    "r.GET(", "Route::", "#[get(", "#[post(",
                // Java：Spring MVC 注解式映射与 JAX-RS
                "@GetMapping", "@PostMapping", "@PutMapping", "@DeleteMapping", "@PatchMapping",
                "@Path(",
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
                // Java：Spring Security 方法级/全局配置与过滤器链接入
                "@PreAuthorize", "@PostAuthorize", "@Secured", "@RolesAllowed", "@PermitAll",
                "@DenyAll", "@EnableWebSecurity", "@EnableMethodSecurity", "SecurityFilterChain",
                "WebSecurityConfigurerAdapter", "authorizeHttpRequests", "authorizeRequests",
                "addFilterBefore", "addFilterAfter", "OncePerRequestFilter", "HttpSecurity",
                ];
                let mut routes: Vec<Value> = Vec::new();
                let mut middleware: Vec<Value> = Vec::new();
                let mut routes_total = 0usize;
                let mut middleware_total = 0usize;
                let mut frame_cpp_fallback = false;
                let mut frame_preproc_note: Option<String> = None;
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
                        // 路由/中间件同样是"证据"：未激活分支里的绑定不算
                        let (pp_states, pp_note) = preproc_view(path, content, false);
                        frame_cpp_fallback = pp_note.is_some();
                        frame_preproc_note = pp_note;
                        for (idx, code_line) in code.iter().enumerate() {
                            let ln = (idx + 1) as u32;
                            let text = originals.get(idx).copied().unwrap_or("");
                            let trimmed = text.trim();
                            let code_trimmed = code_line.trim();
                            if code_trimmed.is_empty() {
                                continue;
                            }
                            if is_import_or_package_line(code_trimmed) {
                                continue;
                            }
                            if pp_states.get(idx).map(|s| s.dead).unwrap_or(false) {
                                continue; // 未激活分支里的路由/中间件不是证据
                            }
                            if route_markers.iter().any(|m| code_trimmed.contains(*m))
                                && (handler.is_empty() || trimmed.contains(handler))
                            {
                                routes_total += 1;
                                if routes.len() + middleware.len() < MAX_HITS {
                                    provenance.push(prov(path, ln, &id));
                                    // 路由值：取注解实参里的首个字符串字面量（原文里取，避免被代码视图抹空）
                                    // HTTP 方法：由注解名给出（Spring 的 @GetMapping 等），取不到即 null
                                    let route_value = trimmed
                                        .split('"')
                                        .nth(1)
                                        .map(|s| s.to_string())
                                        .filter(|s| !s.is_empty());
                                    let http_method = [
                                        ("@GetMapping", "GET"),
                                        ("@PostMapping", "POST"),
                                        ("@PutMapping", "PUT"),
                                        ("@DeleteMapping", "DELETE"),
                                        ("@PatchMapping", "PATCH"),
                                        ("@RequestMapping", "ANY"),
                                        ("@Path(", "ANY"),
                                    ]
                                    .iter()
                                    .find(|(m, _)| code_trimmed.contains(*m))
                                    .map(|(_, v)| v.to_string());
                                    routes.push(json!({
                                        "line": ln,
                                        "text": trimmed.chars().take(200).collect::<String>(),
                                        // Spring 语义：类级前缀与方法级路径拼接（空实参的方法级映射继承类级路径）
                                        "route": annotate_route_with_prefix(
                                            content,
                                            ln,
                                            route_value.as_deref(),
                                        ),
                                        "route_raw": route_value,
                                        // 类级映射只提供前缀，不是端点
                                        "scope": route_scope(content, ln),
                                        "http_method": http_method,
                                    }));
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
                // 端点的全局覆盖判定（与安全配置的路径匹配器比对）。
                annotate_route_coverage(&mut routes, &all_chains);
                // 安全配置声明并入中间件链：**只上报与本文件相关者**——本文件自身（若它是配置）
                // 以及实际为端点提供覆盖判定的配置（来自 global_match.chain_file），
                // 按文件去重并封顶，避免把整个项目里所有配置都当成这个文件的证据。
                let mut relevant_cfg: Vec<String> = Vec::new();
                if security_config_decls.iter().any(|(f, _, _)| f == file) {
                    relevant_cfg.push(file.to_string());
                }
                for entry in routes.iter() {
                    if let Some(cf) = entry
                        .get("global_match")
                        .and_then(|m| m.get("chain_file"))
                        .and_then(|v| v.as_str())
                    {
                        if !relevant_cfg.iter().any(|x| x == cf) {
                            relevant_cfg.push(cf.to_string());
                        }
                    }
                }
                for cfg_file in relevant_cfg.iter().take(3) {
                    if let Some((_, cfg_line, cfg_text)) =
                        security_config_decls.iter().find(|(f, _, _)| f == cfg_file)
                    {
                        if middleware.len() >= MAX_HITS {
                            break;
                        }
                        provenance.push(prov_with(cfg_file, *cfg_line, &id, "security-config"));
                        middleware.push(json!({
                            "line": cfg_line,
                            "text": cfg_text,
                            "kind": "security_config",
                            "file": cfg_file,
                        }));
                    }
                }
                // 容器级过滤器注册（注解 / 注册 Bean / web.xml）：另一条保护证据面，独立陈述
                annotate_container_filters(&mut routes, &container_filters);
                // 拦截器注册（第三条保护面）：作为证据交付，不参与鉴权判定
                annotate_interceptors(&mut routes, &interceptor_regs);
                // 检测到但**未建模**的保护面：宁可如实说"未建模"，也绝不给出会被读成"没有保护"的结论。
                // 反应式安全配置排前（语义最明确），其余按信号表登记。
                let mut unmodeled: Vec<(String, String, u32)> = Vec::new();
                if let Some((rf, rline)) = reactive_cfg.as_ref() {
                    unmodeled.push(("spring_webflux".to_string(), rf.clone(), *rline));
                }
                unmodeled.extend(unmodeled_signals.iter().cloned());
                if !unmodeled.is_empty() {
                    let (first_fw, first_file, first_line) = unmodeled[0].clone();
                    let caveat = if first_fw == "spring_webflux" {
                        "reactive_security_not_modeled"
                    } else {
                        "unmodeled_protection_signal"
                    };
                    for entry in routes.iter_mut() {
                        if entry.get("scope").and_then(|v| v.as_str()) == Some("class") {
                            continue;
                        }
                        if entry.get("global_coverage").and_then(|v| v.as_str())
                            != Some("no_global_config_found")
                        {
                            continue;
                        }
                        if let Some(obj) = entry.as_object_mut() {
                            obj.insert("global_coverage".to_string(), json!("framework_not_modeled"));
                            obj.insert("coverage_caveat".to_string(), json!(caveat));
                            obj.insert("unmodeled_framework".to_string(), json!(first_fw));
                            obj.insert(
                                "unmodeled_source".to_string(),
                                json!({"file": first_file, "line": first_line}),
                            );
                            obj.insert(
                                "unmodeled_signals".to_string(),
                                json!(unmodeled
                                    .iter()
                                    .map(|(fw, f, l)| json!({"framework": fw, "file": f, "line": l}))
                                    .collect::<Vec<Value>>()),
                            );
                        }
                    }
                }
                // 如实标注跨文件证据的范围：module（按模块根收敛）/ project（保持全项目）
                for entry in routes.iter_mut() {
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert(
                            "evidence_scope".to_string(),
                            json!(evidence_scope_label(&module_root)),
                        );
                        obj.insert("evidence_root".to_string(), json!(module_root));
                    }
                }
                // 类级授权注解（打在类声明正上方，对整批方法生效）
                let class_auth = files
                    .iter()
                    .find(|(p, _)| p == file)
                    .map(|(_, c)| class_level_auth_annotations(c))
                    .unwrap_or_default();
                annotate_class_level_auth(&mut routes, &class_auth);
                // 方法级授权：用 AST 定位包含映射注解的方法起始行，再向上取连续注解 ⇒ 方法级覆盖类级
                let auth_src = files
                    .iter()
                    .find(|(p, _)| p == file)
                    .map(|(_, c)| c.clone())
                    .unwrap_or_default();
                if !auth_src.is_empty() {
                    for entry in routes.iter_mut() {
                        if entry.get("scope").and_then(|v| v.as_str()) == Some("class") {
                            continue;
                        }
                        let route_line = entry
                            .get("line")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32;
                        let method_auth = ast_enclosing_function(root, file, &auth_src, route_line)
                            .map(|(_, start, _, body_start)| {
                                method_level_auth_annotations(
                                    &auth_src,
                                    start as u32,
                                    body_start as u32,
                                    type_declaration_line(&auth_src),
                                )
                            })
                            .unwrap_or_default();
                        let class_count = entry
                            .get("class_level_auth_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as usize;
                        let effect = auth_effect(class_count, method_auth.len());
                        let items: Vec<Value> = method_auth
                            .iter()
                            .map(|(l, x)| json!({"line": l, "text": x}))
                            .collect();
                        if let Some(obj) = entry.as_object_mut() {
                            obj.insert("method_level_auth".to_string(), json!(items));
                            obj.insert(
                                "method_level_auth_count".to_string(),
                                json!(method_auth.len()),
                            );
                            obj.insert("auth_effect".to_string(), json!(effect));
                        }
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
                    // Java：Spring Security 的方法级授权与 SpEL 表达式
                    "@PreAuthorize",
                    "@PostAuthorize",
                    "@Secured",
                    "@RolesAllowed",
                    "isAuthenticated(",
                    "hasRole(",
                    "hasAuthority(",
                    // Shiro 注解式授权
                    "@RequiresPermissions",
                    "@RequiresRoles",
                    "@RequiresAuthentication",
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
                if frame_cpp_fallback {
                    // 想用 `cpp -E` 求真实分支但起不来 ⇒ 如实说明此刻只有行级判据
                    reasons.push("cpp_preprocess_unavailable_line_level_fallback");
                }
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
                        "preprocess_note": frame_preproc_note,
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
mod tests;
