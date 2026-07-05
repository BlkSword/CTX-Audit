// Scanner module - 扫描器模块
// 定义扫描器的核心接口和类型

pub mod manager;
pub mod regex_scanner;
pub mod sca_scanner;

// Re-export SCA types
pub use sca_scanner::{ScaScanOptions, ScaSeverityMapping};

use async_trait::async_trait;
use rayon::prelude::*;
use regex::RegexSet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

/// 扫描阶段
#[derive(Debug, Clone)]
pub enum ScanPhase {
    /// 收集文件
    FileWalking,
    /// SCA 依赖扫描
    ScaScanning,
    /// 规则 + 攻击面扫描
    RuleScanning,
    /// 深度扫描：候选文件选取
    CandidateSelection,
    /// 深度扫描：AST 污点分析
    TaintAnalysis,
    /// 深度扫描：跨文件分析
    CrossFileAnalysis,
}

/// 扫描进度
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// 当前阶段
    pub phase: ScanPhase,
    /// 当前处理数量
    pub current: usize,
    /// 当前阶段总量
    pub total: usize,
    /// 描述信息
    pub message: String,
}

/// 进度回调类型
pub type ProgressCallback = Arc<dyn Fn(ScanProgress) + Send + Sync>;

/// 扫描行为可配置参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// 并行线程数（默认 4，0 = rayon 自动检测）
    pub threads: usize,
    /// 单文件最大扫描大小（字节，默认 10MB）
    pub max_file_size: u64,
    /// 扫描内存预算（字节，默认 500MB）
    pub memory_budget: usize,
    /// 并行扫描批次大小（默认 100）
    pub batch_size: usize,
    /// 去重行容差（默认 3，即 ±3 行内合并）
    pub line_tolerance: usize,
    /// 是否包含测试文件（默认 false，测试目录中文件降低置信度但不排除）
    pub include_tests: bool,
    /// 启用 AST 污点分析（单文件 source→sink 追踪）
    pub enable_taint: bool,
    /// 启用跨文件污点追踪（需要 enable_taint）
    pub enable_cross_file: bool,
    /// 深度扫描时进入 AST 污点分析的候选文件上限（默认 5000）
    pub taint_max_candidate_files: usize,
    /// 深度扫描时单个 AST 候选文件大小上限（KB，默认 500）
    pub taint_max_file_kb: usize,
    /// 公开路由白名单（用于抑制公开端点被误报为未认证）
    pub public_route_patterns: Vec<String>,
    /// 非生产代码路径模式（命中时标记 finding 为 non-production）
    pub non_production_path_patterns: Vec<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            threads: 4,
            max_file_size: 10 * 1024 * 1024,
            memory_budget: 500 * 1024 * 1024,
            batch_size: 100,
            line_tolerance: 3,
            include_tests: false,
            enable_taint: false,
            enable_cross_file: false,
            taint_max_candidate_files: 5000,
            taint_max_file_kb: 500,
            public_route_patterns: crate::analysis::attack_surface::default_public_route_patterns(),
            non_production_path_patterns:
                crate::analysis::attack_surface::default_non_production_path_patterns(),
        }
    }
}

/// 测试目录标识（用于降低置信度，不排除扫描）
const TEST_DIR_MARKERS: &[&str] = &[
    "/test/",
    "/tests/",
    "/__tests__/",
    "/spec/",
    "\\test\\",
    "\\tests\\",
    "\\__tests__\\",
    "\\spec\\",
];

/// 基线文件结构：记录已忽略的 findings
#[derive(Debug, Deserialize)]
struct Baseline {
    /// key = "file_path:line_start:vuln_type" → value = reason
    #[serde(default)]
    ignored: std::collections::HashMap<String, String>,
}

/// 漏洞发现结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub detector: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_trail: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_output: Option<String>,
    /// 置信度评分 (0.0-1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// 多扫描器确认计数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corroboration_count: Option<usize>,
    /// 匹配行的代码上下文（±context_lines 行，带行号标记）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<String>,
    /// 污点源代码片段（仅 taint findings）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_snippet: Option<String>,
    /// 污点汇聚点代码片段（仅 taint findings）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_snippet: Option<String>,
    /// 文件角色标签: "production" | "test" | "build" | "vendor"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_role: Option<String>,
    /// 检测到的安全屏障 (如 "shell:false", "array_args", "safe_target")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub barriers: Option<Vec<String>>,
    /// 标记原因说明（为什么规则匹配了这段代码）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_hint: Option<String>,
    /// 调用图证据指针 — LLM 可据此用查询工具做深度验证
    /// 仅在跨文件分析（enable_cross_file=true）时填充
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<EvidenceRefs>,
}

// ── 证据引用类型 ──────────────────────────────────────────

/// 证据引用 — 指向调用图中的具体节点和路径
/// 为 LLM 提供可追踪、可查询的确定性证据入口
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRefs {
    /// source→sink 的调用路径证据
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_sink_path: Option<SourceSinkEvidence>,
    /// 沿途经过的 sanitizer（及有效性判定）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sanitizer_chain: Vec<SanitizerEvidence>,
    /// 中间件覆盖情况（路由是否被 auth middleware 覆盖）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub middleware_coverage: Vec<MiddlewareEvidence>,
    /// 调用图统计快照（用于 LLM 了解项目规模）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_snapshot: Option<GraphSnapshot>,
}

/// source→sink 调用的路径证据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceSinkEvidence {
    /// 源函数名
    pub source_function: String,
    /// 源函数所在文件
    pub source_file: String,
    /// 源函数行号
    pub source_line: usize,
    /// 源调用图节点 ID（优先用于精确路径查询）
    #[serde(default)]
    pub source_node_id: Option<String>,
    /// 汇函数名
    pub sink_function: String,
    /// 汇函数所在文件
    pub sink_file: String,
    /// 汇函数行号
    pub sink_line: usize,
    /// 汇调用图节点 ID（优先用于精确路径查询）
    #[serde(default)]
    pub sink_node_id: Option<String>,
    /// 路径跳数
    pub path_length: usize,
    /// 路径中的每一步
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_steps: Vec<PathStepRef>,
}

/// 路径中的单步引用（轻量，可据此调用 query_callers/query_callees）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStepRef {
    /// 函数名
    pub function: String,
    /// 文件路径
    pub file: String,
    /// 行号
    pub line: usize,
    /// 步骤类型：direct_call | callback | middleware | virtual_dispatch
    pub step_type: String,
}

/// Sanitizer 证据 — 路径中遇到的净化函数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerEvidence {
    /// 净化函数名
    pub function: String,
    /// 所在文件
    pub file: String,
    /// 行号
    pub line: usize,
    /// 对该漏洞类型是否有效
    pub effective: bool,
    /// 有效性判定理由
    pub reason: String,
}

/// 中间件覆盖证据 — 路由是否被安全中间件覆盖
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareEvidence {
    /// 中间件名/处理器名
    pub middleware_name: String,
    /// 中间件所在文件
    pub middleware_file: String,
    /// 是否适用于此路由
    pub applies_to_route: bool,
    /// 受影响的路由处理器
    pub route_handler: String,
}

/// 调用图统计快照
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    /// 总函数节点数
    pub total_nodes: usize,
    /// 总边数
    pub total_edges: usize,
    /// 跨文件边数
    pub cross_file_edges: usize,
    /// 污点源数量
    pub taint_sources_count: usize,
    /// 污点汇数量
    pub taint_sinks_count: usize,
}

/// 提取匹配行周围的代码上下文
pub fn extract_code_context(
    content: &str,
    line_start: usize,
    line_end: usize,
    context_lines: usize,
) -> String {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || line_start == 0 {
        return String::new();
    }

    let start = if line_start > context_lines + 1 {
        line_start - context_lines - 1
    } else {
        0
    };
    let end = (line_end + context_lines).min(lines.len());

    let width = format!("{}", end).len();
    let mut result = String::new();
    for i in start..end {
        let line_num = i + 1;
        let marker = if line_num >= line_start && line_num <= line_end {
            ">>"
        } else {
            "  "
        };
        result.push_str(&format!(
            "{} {:>width$} | {}\n",
            marker,
            line_num,
            lines[i],
            width = width
        ));
    }
    result.trim_end().to_string()
}

/// 文件角色分类
pub fn classify_file_role(path: &str) -> &'static str {
    let normalized = path.replace('\\', "/").to_lowercase();

    // 测试文件标识
    let test_markers = [
        "/__testfixtures__/",
        "/__tests__/",
        "/__mocks__/",
        "/test/",
        "/tests/",
        "/spec/",
        "/specs/",
        "/e2e/",
        "/evals/",
        "/benchmark/",
        "/bench/",
        "/fixtures/",
        "/snapshots/",
    ];
    let test_file_patterns = [
        ".test.",
        ".spec.",
        "_test.",
        "_spec.",
        ".bench.",
        ".benchmark.",
        ".snapshot",
        ".fixture",
    ];
    let test_file_names = [
        "run-tests.js",
        "run-tests.ts",
        "run-evals.js",
        "run-evals.ts",
        "jest.config",
        "vitest.config",
        "mocha",
        "karma.conf",
        "tsconfig-test",
        "test-runner",
    ];

    for marker in &test_markers {
        if normalized.contains(marker) {
            return "test";
        }
    }
    let file_name = normalized.rsplit('/').next().unwrap_or("");
    for pat in &test_file_patterns {
        if file_name.contains(pat) {
            return "test";
        }
    }
    for name in &test_file_names {
        if file_name.starts_with(name) {
            return "test";
        }
    }

    // 构建脚本标识
    let build_markers = [
        "/scripts/",
        "/build/",
        "/tooling/",
        "webpack.config",
        "rollup.config",
        "vite.config",
        "gulpfile",
        "gruntfile",
        "babel.config",
        "postcss.config",
        "tailwind.config",
        "taskfile.",
        "makefile",
        "rakefile",
    ];
    for marker in &build_markers {
        if normalized.contains(marker) {
            return "build";
        }
    }

    // 第三方/供应商标识
    let vendor_markers = [
        "/vendor/",
        "/third-party/",
        "/third_party/",
        "/external/",
        "/polyfill",
    ];
    for marker in &vendor_markers {
        if normalized.contains(marker) {
            return "vendor";
        }
    }

    "production"
}

/// 检测代码上下文中的安全屏障
///
/// 检查匹配位置周围的代码是否有安全防护措施：
/// - `shell: false` / `shell: false,` → 阻止 shell 注入
/// - 数组参数 `spawn(cmd, [...` → 参数化调用（非字符串拼接）
/// - `process.execPath` → 固定目标路径
/// - `require.resolve(` → 本地模块解析
/// - `new URL(` → URL 标准化
pub fn detect_barriers(
    content: &str,
    line_start: usize,
    line_end: usize,
    vuln_type: &str,
) -> Vec<String> {
    let mut barriers = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() {
        return barriers;
    }

    // 检查匹配行及附近上下文（向下扫描到函数结束或最多 20 行）
    let check_start = line_start.saturating_sub(1);
    let check_end = (line_end + 20).min(lines.len());

    let context_block: String = lines[check_start..check_end].join("\n").to_lowercase();

    // Command/Code Injection 相关屏障
    if vuln_type.contains("CWE-78")
        || vuln_type.contains("CWE-94")
        || vuln_type.contains("command")
        || vuln_type.contains("code")
        || vuln_type.contains("injection")
    {
        // shell: false 检查
        if context_block.contains("shell: false")
            || context_block.contains("shell:false")
            || context_block.contains("shell:!")
        {
            barriers.push("shell:false".to_string());
        }
        // spawn() 默认 shell:false — 如果没有 shell:true/shell: true，且使用数组参数
        let has_shell_true =
            context_block.contains("shell: true") || context_block.contains("shell:true");
        let has_spawn = context_block.contains("spawn(");
        let has_array_args = context_block.contains("[") && has_spawn;
        if has_spawn && !has_shell_true {
            barriers.push("spawn_default_no_shell".to_string());
        }
        if has_array_args {
            barriers.push("array_args".to_string());
        }
        // process.execPath — 固定目标
        if context_block.contains("process.execpath") {
            barriers.push("safe_target:process.execPath".to_string());
        }
        // require.resolve — 本地模块
        if context_block.contains("require.resolve") {
            barriers.push("safe_target:require.resolve".to_string());
        }
        // child_process 变量赋值检查 — `require('child_process')` 只是导入
        if context_block.contains("typeof import('child_process')")
            || context_block.contains("as typeof import")
        {
            barriers.push("type_import_only".to_string());
        }
        // windowsHide: true — 通常用于后台进程，非交互式
        if context_block.contains("windowshide: true") || context_block.contains("windowshide:true")
        {
            barriers.push("background_process".to_string());
        }
    }

    // Open Redirect / SSRF 相关屏障
    if vuln_type.contains("CWE-601")
        || vuln_type.contains("redirect")
        || vuln_type.contains("CWE-918")
        || vuln_type.contains("ssrf")
    {
        // new URL() 标准化
        if context_block.contains("new url(") {
            barriers.push("url_normalization".to_string());
        }
        // startsWith('/') 检查 — 相对路径校验
        if context_block.contains("startswith(\"/") || context_block.contains("startswith('/") {
            barriers.push("path_prefix_check".to_string());
        }
    }

    // XSS 相关屏障
    if vuln_type.contains("CWE-79") || vuln_type.contains("xss") {
        // dangerouslySetInnerHTML 中使用序列化函数
        if context_block.contains("json.stringify")
            || context_block.contains("serialize")
            || context_block.contains("escapehtml")
            || context_block.contains("sanitiz")
        {
            barriers.push("output_encoding".to_string());
        }
    }

    // Path Traversal 相关屏障
    if vuln_type.contains("CWE-22") || vuln_type.contains("path") {
        if context_block.contains("path.normalize")
            || context_block.contains("path.resolve")
            || context_block.contains("realpath")
            || context_block.contains("..")
                && (context_block.contains("replace") || context_block.contains("filter"))
        {
            barriers.push("path_normalization".to_string());
        }
    }

    barriers
}

/// 根据 file_role 和 barriers 调整严重程度
pub fn adjust_severity(severity: &str, file_role: &str, barriers: &[String]) -> String {
    // 有安全屏障时降级
    if !barriers.is_empty() {
        return match severity {
            "critical" => "medium".to_string(),
            "high" => "low".to_string(),
            s => s.to_string(),
        };
    }
    // 非生产代码降级
    if file_role != "production" {
        return match (severity, file_role) {
            ("critical", "test") => "medium".to_string(),
            ("critical", "build") => "medium".to_string(),
            ("critical", "vendor") => "high".to_string(),
            ("high", "test") => "low".to_string(),
            ("high", "build") => "low".to_string(),
            ("high", "vendor") => "medium".to_string(),
            (s, _) => s.to_string(),
        };
    }
    severity.to_string()
}

/// 扫描器 trait - 所有扫描器都需要实现此接口
#[async_trait]
pub trait Scanner: Send + Sync {
    /// 返回扫描器名称
    fn name(&self) -> String;

    /// 扫描单个文件
    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding>;
}

/// 规则目录搜索顺序：
/// 1. 用户指定目录（--rules 参数）
/// 2. 项目级目录 `<project>/.ctx-audit/rules/`
/// 3. 内置规则目录 `rules/`
fn resolve_rules_dir(project_path: &str, custom_dir: Option<&str>) -> Option<std::path::PathBuf> {
    // 1. 用户指定
    if let Some(dir) = custom_dir {
        let p = std::path::Path::new(dir);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    // 2. 项目级
    let project_rules = std::path::Path::new(project_path).join(".ctx-audit/rules");
    if project_rules.exists() {
        return Some(project_rules);
    }
    // 3. 内置
    let builtin = std::path::Path::new("rules");
    if builtin.exists() {
        return Some(builtin.to_path_buf());
    }
    None
}

/// 判断路径是否匹配排除规则
///
/// 排除规则支持两种形式：
/// - 目录名：`test`、`node_modules` → 匹配路径中包含 `/test/`、`/node_modules/`
/// - 文件模式：`*.test.ts`、`*.spec.js`、`*_test.go` → 匹配文件名后缀
/// - 后缀模式：`.json`、`.lock` → 匹配文件扩展名
fn is_excluded(path: &std::path::Path, exclude_patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy().replace('\\', "/");
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    for pattern in exclude_patterns {
        let pat = pattern.trim();
        if pat.is_empty() {
            continue;
        }

        // 文件模式：以 * 或 ? 开头，或包含通配符
        if pat.contains('*') || pat.contains('?') {
            // glob 模式匹配文件名
            if glob_match(pat, file_name) {
                return true;
            }
            // 也匹配完整路径中的模式如 test/**
            if glob_match(pat, &path_str) {
                return true;
            }
            continue;
        }

        // 后缀模式：以 . 开头（如 .json, .lock）
        if pat.starts_with('.') {
            if file_name.ends_with(pat) {
                return true;
            }
            continue;
        }

        // 目录名：匹配路径中的目录段
        let dir_pattern = format!("/{}/", pat.trim_matches('/'));
        if path_str.contains(&dir_pattern) {
            return true;
        }
        if path_str.starts_with(&format!("{}/", pat.trim_matches('/'))) {
            return true;
        }
    }
    false
}

/// 简易 glob 匹配（支持 * 和 ? 通配符）
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_impl(&p, &t, 0, 0)
}

fn glob_match_impl(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }
    match pattern[pi] {
        '*' => {
            // * 匹配 0 个或多个字符
            for i in ti..=text.len() {
                if glob_match_impl(pattern, text, pi + 1, i) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if ti < text.len() {
                glob_match_impl(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
        c => {
            if ti < text.len() && text[ti] == c {
                glob_match_impl(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
    }
}

/// 判断路径是否在测试目录中
fn is_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    for marker in TEST_DIR_MARKERS {
        if normalized.contains(marker) {
            return true;
        }
    }
    false
}

/// severity 排序值
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

/// 便捷的 scan_directory 函数（用于web-backend）
pub async fn scan_directory(path: &str) -> Result<Vec<Finding>, String> {
    scan_directory_with_rules_progress(path, None, None, None, None).await
}

/// 带自定义规则目录的扫描
pub async fn scan_directory_with_rules(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
    sca_options: Option<ScaScanOptions>,
) -> Result<Vec<Finding>, String> {
    scan_directory_with_rules_progress(path, rules_dir, exclude_dirs, sca_options, None).await
}

/// 带进度回调的扫描
pub async fn scan_directory_with_rules_progress(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
    sca_options: Option<ScaScanOptions>,
    progress: Option<ProgressCallback>,
) -> Result<Vec<Finding>, String> {
    scan_directory_with_opts(
        path,
        rules_dir,
        exclude_dirs,
        sca_options,
        ScanOptions::default(),
        progress,
    )
    .await
}

/// 带完整配置的扫描
pub async fn scan_directory_with_opts(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
    sca_options: Option<ScaScanOptions>,
    scan_opts: ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<Vec<Finding>, String> {
    let (findings, _) = scan_directory_with_rules_inner(
        path,
        rules_dir,
        exclude_dirs,
        true,
        sca_options,
        Some(scan_opts),
        progress,
    )
    .await?;
    Ok(findings)
}

/// 内部实现：返回 findings 和文件内容缓存（用于 deep scan 复用）
async fn scan_directory_with_rules_inner(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
    collect_content: bool,
    sca_options: Option<ScaScanOptions>,
    scan_opts: Option<ScanOptions>,
    progress: Option<ProgressCallback>,
) -> Result<(Vec<Finding>, HashMap<String, String>), String> {
    use ignore::Walk;

    // 排除列表完全由调用方（CLI 配置）提供，core 不硬编码任何排除项
    let mut excludes: Vec<String> = exclude_dirs.unwrap_or_default();
    // 若调用方未提供任何排除项，使用最小安全默认（防止扫描 .git 等）
    if excludes.is_empty() {
        excludes = vec![
            "node_modules".to_string(),
            ".git".to_string(),
            "target".to_string(),
            "vendor".to_string(),
        ];
    }

    let mut findings = Vec::new();
    let mut content_cache: HashMap<String, String> = HashMap::new();

    let rules = match resolve_rules_dir(path, rules_dir) {
        Some(rules_path) => {
            tracing::info!("加载规则: {}", rules_path.display());
            match crate::rules::loader::load_rules_from_dir(&rules_path) {
                Ok(r) => {
                    tracing::info!("加载了 {} 条规则", r.len());
                    r
                }
                Err(e) => {
                    tracing::warn!("规则加载失败: {}", e);
                    vec![]
                }
            }
        }
        None => {
            tracing::info!("未找到规则目录");
            vec![]
        }
    };

    // 创建规则扫描器
    let rule_scanner = if !rules.is_empty() {
        Some(crate::rules::scanner::RuleScanner::new(rules))
    } else {
        None
    };

    // 创建 SCA 依赖扫描器
    let sca_opts = sca_options.unwrap_or_default();
    let sca_scanner = sca_scanner::ScaScanner::with_options(sca_opts.clone());

    // 收集文件路径
    let opts = scan_opts.unwrap_or_default();

    let mut code_files: Vec<std::path::PathBuf> = Vec::new();
    let mut dep_files: Vec<std::path::PathBuf> = Vec::new();

    for entry in Walk::new(path) {
        if let Ok(entry) = entry {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // 排除目录过滤
            if is_excluded(path, &excludes) {
                continue;
            }

            // 文件大小检查
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.len() > opts.max_file_size {
                    continue;
                }
            }

            let path_buf = path.to_path_buf();

            if sca_scanner::is_dependency_file(path) {
                dep_files.push(path_buf);
            } else if is_supported_file(path) {
                code_files.push(path_buf);
            }
        }
    }

    // SCA 扫描（默认关闭，需通过配置或 --sca 启用）
    if sca_opts.enabled {
        let sca_total = dep_files.len();
        if let Some(ref cb) = progress {
            cb(ScanProgress {
                phase: ScanPhase::ScaScanning,
                current: 0,
                total: sca_total,
                message: format!("SCA 扫描: 0/{} 依赖文件", sca_total),
            });
        }
        for (i, path_buf) in dep_files.iter().enumerate() {
            if let Ok(content) = std::fs::read_to_string(path_buf) {
                let sca_findings = sca_scanner.scan_file(path_buf, &content).await;
                findings.extend(sca_findings);
            }
            if let Some(ref cb) = progress {
                cb(ScanProgress {
                    phase: ScanPhase::ScaScanning,
                    current: i + 1,
                    total: sca_total,
                    message: format!("SCA 扫描: {}/{} 依赖文件", i + 1, sca_total),
                });
            }
        }
    }

    // 代码文件并行扫描
    let rt_handle = tokio::runtime::Handle::current();

    let batch_size = opts.batch_size;
    let public_route_patterns = opts.public_route_patterns.clone();
    let non_production_path_patterns = opts.non_production_path_patterns.clone();
    let mut total_bytes_read: usize = 0;
    let total_code_files = code_files.len();
    tracing::debug!(
        "[ScanInner] {} code files, {} dep files",
        total_code_files,
        dep_files.len()
    );
    let mut scanned_files: usize = 0;

    if let Some(ref cb) = progress {
        cb(ScanProgress {
            phase: ScanPhase::RuleScanning,
            current: 0,
            total: total_code_files,
            message: format!("规则扫描: 0/{} 文件", total_code_files),
        });
    }

    for chunk in code_files.chunks(batch_size) {
        let code_results: Vec<(Vec<Finding>, Vec<Finding>, Option<(String, String)>, usize)> =
            chunk
                .par_iter()
                .map(|path_buf| {
                    let content = match std::fs::read_to_string(path_buf) {
                        Ok(c) => c,
                        Err(_) => return (Vec::new(), Vec::new(), None, 0),
                    };

                    let content_len = content.len();
                    let mut file_findings = Vec::new();
                    let file_str = path_buf.to_string_lossy().to_string();

                    // 规则扫描（同步调用，无需 async runtime）
                    if let Some(ref scanner) = rule_scanner {
                        let rule_results = scanner.scan_file_sync(path_buf, &content);
                        file_findings.extend(rule_results);
                    }

                    // 攻击面检测（合并到同一次文件读取中）
                    let mut attack_surface_findings = Vec::new();
                    let entry_points =
                        crate::analysis::attack_surface::AttackSurfaceMapper::map_file(
                            &file_str, &content,
                        );
                    for ep in &entry_points {
                        if !ep.auth_required
                            && ep.entry_type
                                == crate::analysis::attack_surface::EntryType::HttpEndpoint
                        {
                            // 公开端点（如 /login、/signup）不被报告为认证缺失漏洞
                            if ep
                                .route
                                .as_deref()
                                .map(|r| {
                                    crate::analysis::attack_surface::is_public_route_with_patterns(
                                        r,
                                        &public_route_patterns,
                                    )
                                })
                                .unwrap_or(false)
                            {
                                continue;
                            }
                            if !is_test_path(&ep.file_path) && !is_excluded(path_buf, &excludes) {
                                let is_non_production = crate::analysis::attack_surface::is_non_production_path_with_patterns(
                                    &ep.file_path,
                                    &non_production_path_patterns,
                                );
                                attack_surface_findings.push(Finding {
                                    finding_id: format!("attack-surface-unauth-{}", ep.line),
                                    file_path: ep.file_path.clone(),
                                    line_start: ep.line,
                                    line_end: ep.line,
                                    detector: "AttackSurfaceMapper".to_string(),
                                    vuln_type: "UnauthenticatedEndpoint".to_string(),
                                    severity: "high".to_string(),
                                    description: format!(
                                        "{} {} 端点未配置认证保护",
                                        ep.http_method.as_deref().unwrap_or("?"),
                                        ep.route.as_deref().unwrap_or("?")
                                    ),
                                    analysis_trail: None,
                                    llm_output: None,
                                    confidence: Some(ep.risk_score),
                                    corroboration_count: None,
                                    code_snippet: Some(extract_code_context(
                                        &content, ep.line, ep.line, 3,
                                    )),
                                    source_snippet: None,
                                    sink_snippet: None,
                                    file_role: if is_non_production {
                                        Some("non-production".to_string())
                                    } else {
                                        None
                                    },
                                    barriers: None,
                                    reasoning_hint: None,
                                    evidence_refs: None,
                                });
                            }
                        }
                    }

                    let has_findings =
                        !file_findings.is_empty() || !attack_surface_findings.is_empty();
                    let is_ast_supported = is_ast_supported_file(path_buf);
                    let cached = if collect_content && (has_findings || is_ast_supported) {
                        Some((file_str, content))
                    } else {
                        None
                    };

                    (file_findings, attack_surface_findings, cached, content_len)
                })
                .collect();

        total_bytes_read += code_results
            .iter()
            .map(|(_, _, _, len)| *len)
            .sum::<usize>();
        if total_bytes_read > opts.memory_budget {
            tracing::warn!(
                "内存预算接近上限 ({}MB)，停止扫描剩余文件",
                total_bytes_read / 1024 / 1024
            );
            break;
        }

        for (mut batch, mut as_batch, cached, _) in code_results {
            if let Some((path, content)) = cached {
                content_cache.insert(path, content);
            }
            findings.append(&mut batch);
            findings.append(&mut as_batch);
        }

        scanned_files += chunk.len();
        if let Some(ref cb) = progress {
            cb(ScanProgress {
                phase: ScanPhase::RuleScanning,
                current: scanned_files,
                total: total_code_files,
                message: format!("规则扫描: {}/{} 文件", scanned_files, total_code_files),
            });
        }
    }

    // 上下文感知过滤
    for finding in &mut findings {
        let fp = finding.file_path.to_lowercase().replace('\\', "/");
        let is_test = fp.contains("/test")
            || fp.contains("/tests/")
            || fp.contains("/__tests__/")
            || fp.contains("/spec/")
            || fp.ends_with("_test.go")
            || fp.ends_with("_test.rs")
            || fp.ends_with("_test.py")
            || fp.ends_with(".test.js")
            || fp.ends_with(".test.ts")
            || fp.ends_with(".spec.js")
            || fp.ends_with(".spec.ts");
        let is_example = fp.contains("/example") || fp.contains("/demo") || fp.contains("/sample");
        let is_non_production =
            crate::analysis::attack_surface::is_non_production_path_with_patterns(
                &finding.file_path,
                &opts.non_production_path_patterns,
            );

        if is_non_production {
            finding.file_role = Some("non-production".to_string());
        }

        if !opts.include_tests && (is_test || is_example) {
            finding.confidence = Some(finding.confidence.unwrap_or(0.7) * 0.3);
        }

        if finding.confidence.is_none() {
            finding.confidence = Some(match finding.detector.as_str() {
                "SCAScanner" => 0.9,
                "RuleScanner" => 0.7,
                "AttackSurfaceMapper" => 0.6,
                _ => 0.5,
            });
        }
    }

    // 基线抑制
    let baseline_path = std::path::Path::new(".ctx-audit/baseline.json");
    if baseline_path.exists() {
        if let Ok(content) = std::fs::read_to_string(baseline_path) {
            if let Ok(baseline) = serde_json::from_str::<Baseline>(&content) {
                findings.retain(|f| {
                    let key = format!("{}:{}:{}", f.file_path, f.line_start, f.vuln_type);
                    !baseline.ignored.contains_key(&key)
                });
            }
        }
    }

    // 去重
    findings = deduplicate_findings(findings, opts.line_tolerance);

    // 去重后清理缓存中不再需要的文件
    if !content_cache.is_empty() {
        let remaining_files: HashSet<String> =
            findings.iter().map(|f| f.file_path.clone()).collect();
        content_cache.retain(|path, _| remaining_files.contains(path));
    }

    Ok((findings, content_cache))
}

/// 带攻击面信息的扫描结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub attack_surface: crate::analysis::attack_surface::AttackSurface,
    /// 跨文件分析结果（仅当 enable_cross_file=true 时存在）
    /// 包含调用图、类型层次、中间件模型等确定性证据数据
    pub cross_file_result: Option<crate::analysis::cross_file::CrossFileTaintResult>,
}

/// 扫描目录并返回完整结果（含攻击面） — 使用无进度回调的默认扫描
pub async fn scan_directory_with_attack_surface(path: &str) -> Result<ScanResult, String> {
    let attack_surface = crate::analysis::attack_surface::AttackSurfaceMapper::map_project(
        std::path::Path::new(path),
    );

    let findings = scan_directory(path).await?;

    Ok(ScanResult {
        findings,
        attack_surface,
        cross_file_result: None,
    })
}

/// 深度扫描：在基础扫描后对候选文件运行 AST 污点分析
pub async fn scan_directory_deep(path: &str) -> Result<Vec<Finding>, String> {
    scan_directory_deep_with_rules(path, None, None, None).await
}

/// 带自定义规则目录的深度扫描
pub async fn scan_directory_deep_with_rules(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
    sca_options: Option<ScaScanOptions>,
) -> Result<Vec<Finding>, String> {
    let mut opts = ScanOptions::default();
    opts.enable_taint = true;
    opts.enable_cross_file = true;
    scan_directory_deep_with_rules_progress(
        path,
        rules_dir,
        exclude_dirs,
        sca_options,
        Some(opts),
        None,
    )
    .await
    .map(|r| r.findings)
}

/// 带进度回调的深度扫描
pub async fn scan_directory_deep_with_rules_progress(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
    sca_options: Option<ScaScanOptions>,
    scan_opts: Option<ScanOptions>,
    progress: Option<ProgressCallback>,
) -> Result<ScanResult, String> {
    // 引擎标志
    let enable_taint = scan_opts.as_ref().map(|o| o.enable_taint).unwrap_or(false);
    let enable_cross_file = scan_opts
        .as_ref()
        .map(|o| o.enable_cross_file)
        .unwrap_or(false);

    // 先执行基础扫描（收集文件内容缓存）
    let line_tol = scan_opts.as_ref().map(|o| o.line_tolerance).unwrap_or(3);
    let include_tests = scan_opts.as_ref().map(|o| o.include_tests).unwrap_or(false);
    let max_candidate_files = scan_opts
        .as_ref()
        .map(|o| o.taint_max_candidate_files)
        .unwrap_or(5000);
    let max_taint_file_kb = scan_opts
        .as_ref()
        .map(|o| o.taint_max_file_kb)
        .unwrap_or(500);

    // 保存排除列表副本用于二次收集
    let excludes_for_secondary = exclude_dirs.clone();
    let (mut findings, mut content_cache) = scan_directory_with_rules_inner(
        path,
        rules_dir,
        exclude_dirs,
        true,
        sca_options,
        scan_opts,
        progress.clone(),
    )
    .await?;

    // 无深度引擎启用时直接返回基础扫描结果
    if !enable_taint {
        findings = deduplicate_findings(findings, line_tol);
        return Ok(ScanResult {
            findings,
            attack_surface: crate::analysis::attack_surface::AttackSurface::default(),
            cross_file_result: None,
        });
    }

    // Stage B: AST 污点分析（enable_taint = true）
    // C1: 候选文件选择 — 基于 AST 支持的文件类型，不依赖 rule findings

    // 如果 content_cache 中 AST 文件不足，做第二轮收集
    // （内存预算可能提前终止了主扫描循环，导致 AST 文件未被缓存）
    let ast_in_cache = content_cache
        .keys()
        .filter(|fp| is_ast_supported_file(std::path::Path::new(fp)))
        .count();
    if ast_in_cache < max_candidate_files {
        let excludes = excludes_for_secondary.unwrap_or_else(|| {
            vec![
                "node_modules".to_string(),
                ".git".to_string(),
                "target".to_string(),
                "vendor".to_string(),
            ]
        });
        let mut extra_cached = 0;
        for entry in ignore::WalkBuilder::new(path).hidden(false).build() {
            if extra_cached >= max_candidate_files - ast_in_cache {
                break;
            }
            if let Ok(entry) = entry {
                let p = entry.path();
                if !p.is_file() || !is_ast_supported_file(p) {
                    continue;
                }
                let p_str = p.to_string_lossy().to_string();
                if content_cache.contains_key(&p_str) {
                    continue;
                }
                if is_excluded(p, &excludes) {
                    continue;
                }
                if let Ok(meta) = std::fs::metadata(p) {
                    if meta.len() as usize > max_taint_file_kb * 1024 {
                        continue;
                    }
                }
                if let Ok(content) = std::fs::read_to_string(p) {
                    if content.len() <= max_taint_file_kb * 1024 {
                        content_cache.insert(p_str, content);
                        extra_cached += 1;
                    }
                }
            }
        }
        tracing::debug!("[TaintAnalysis] 二次收集补充 {} 个 AST 文件", extra_cached);
    }

    let candidate_files: Vec<String> = content_cache
        .iter()
        .filter(|(fp, _)| is_ast_supported_file(std::path::Path::new(fp)))
        .filter(|(_, content)| content.len() <= max_taint_file_kb * 1024)
        .map(|(fp, _)| fp.clone())
        .take(max_candidate_files)
        .collect();

    tracing::debug!(
        "[TaintAnalysis] content_cache: {}, AST 候选: {}",
        content_cache.len(),
        candidate_files.len()
    );

    if let Some(ref cb) = progress {
        cb(ScanProgress {
            phase: ScanPhase::CandidateSelection,
            current: candidate_files.len(),
            total: max_candidate_files,
            message: format!("选取候选文件: {} 个文件进入深度分析", candidate_files.len()),
        });
    }

    // C2: 分批 AST 污点分析 + 并行处理
    let mut taint_findings: Vec<Finding> = Vec::with_capacity(candidate_files.len() * 4);
    let taint_total = candidate_files.len();
    let mut accumulated_cpg: HashMap<String, crate::analysis::cpg::FunctionCPG> = HashMap::new();
    let mut accumulated_flows: HashMap<String, Vec<crate::analysis::taint::TaintFlow>> =
        HashMap::new();
    let mut accumulated_parsed_ast: HashMap<
        String,
        (Vec<crate::ast::Symbol>, Vec<crate::ast::CallInfo>),
    > = HashMap::new();

    // 污点规则只加载一次，避免每个文件都重新读取 YAML
    let rules_dir = std::path::Path::new("rules/taint");
    let (taint_sources, taint_sinks, taint_sanitizers) =
        if let Ok(loaded) = crate::rules::taint_loader::load_taint_rules_from_dir(rules_dir) {
            if !loaded.sources.is_empty() || !loaded.sinks.is_empty() {
                tracing::info!(
                    "Loaded {} sources, {} sinks, {} sanitizers from {:?}",
                    loaded.sources.len(),
                    loaded.sinks.len(),
                    loaded.sanitizer_patterns.len(),
                    rules_dir,
                );
                (loaded.sources, loaded.sinks, loaded.sanitizer_patterns)
            } else {
                let analyzer = crate::analysis::ast_taint::AstTaintAnalyzer::new();
                (
                    analyzer.sources().to_vec(),
                    analyzer.sinks().to_vec(),
                    analyzer.sanitizer_patterns().to_vec(),
                )
            }
        } else {
            let analyzer = crate::analysis::ast_taint::AstTaintAnalyzer::new();
            (
                analyzer.sources().to_vec(),
                analyzer.sinks().to_vec(),
                analyzer.sanitizer_patterns().to_vec(),
            )
        };

    // 用 Arc 在 Stage B 的并行任务间共享规则，避免每个文件都克隆
    let taint_sources = std::sync::Arc::new(taint_sources);
    let taint_sinks = std::sync::Arc::new(taint_sinks);
    let taint_sanitizers = std::sync::Arc::new(taint_sanitizers);

    // 预编译 source/sink 关键词集合，用于 Stage B 快速跳过无关文件
    let taint_keyword_set = {
        let mut patterns = Vec::new();
        for src in taint_sources.iter() {
            for p in &src.patterns {
                if !p.is_empty() {
                    patterns.push(regex::escape(p));
                }
            }
        }
        for sink in taint_sinks.iter() {
            for p in &sink.patterns {
                if !p.is_empty() {
                    patterns.push(regex::escape(p));
                }
            }
        }
        if patterns.is_empty() {
            None
        } else {
            RegexSet::new(patterns).ok()
        }
    };

    if let Some(ref cb) = progress {
        cb(ScanProgress {
            phase: ScanPhase::TaintAnalysis,
            current: 0,
            total: taint_total,
            message: format!("AST 污点分析: 0/{} 文件", taint_total),
        });
    }

    // 一次性准备所有候选文件内容，然后整体并行分析，避免 batch 间串行等待
    let all_file_data: Vec<(String, String)> = candidate_files
        .iter()
        .filter_map(|file_path_str| {
            let file_path = std::path::Path::new(file_path_str);
            if !is_ast_supported_file(file_path) {
                return None;
            }
            let content = if let Some(cached) = content_cache.get(file_path_str) {
                cached.clone()
            } else if let Ok(c) = std::fs::read_to_string(file_path) {
                c
            } else {
                return None;
            };
            if content.len() > max_taint_file_kb * 1024 {
                return None;
            }
            Some((file_path_str.clone(), content))
        })
        .collect();

        // 并行分析 — 通过 CPG 构建后再做污点分析
        // 同时收集 CPG 缓存、taint_flows 和已解析 AST 产物供 Stage C 使用
    type FileAst = (Vec<crate::ast::Symbol>, Vec<crate::ast::CallInfo>);
    let all_results: Vec<(String, Vec<Finding>, HashMap<String, crate::analysis::cpg::FunctionCPG>, HashMap<String, Vec<crate::analysis::taint::TaintFlow>>, FileAst)> = all_file_data
        .into_par_iter()
        .map(|(ref file_path_str, ref content)| {
                use crate::analysis::cpg::CPGBuilder;

                let mut parsed_symbols: Vec<crate::ast::Symbol> = Vec::new();
                let mut parsed_calls: Vec<crate::ast::CallInfo> = Vec::new();

                // 快速过滤：文件内容不含任何 source/sink 关键词时，跳过 Stage B 的
                // CPG/污点分析（调用图仍由 Stage C 按需构建）。
                if let Some(ref set) = taint_keyword_set {
                    if !set.is_match(content) {
                        return (
                            file_path_str.clone(),
                            Vec::new(),
                            HashMap::new(),
                            HashMap::new(),
                            (parsed_symbols, parsed_calls),
                        );
                    }
                }

                let file_path = std::path::Path::new(file_path_str);

                // CPG 缓存（按函数 ID 存储）
                let mut cpg_cache: HashMap<String, crate::analysis::cpg::FunctionCPG> = HashMap::new();
                let mut cpg_flows: HashMap<String, Vec<crate::analysis::taint::TaintFlow>> = HashMap::new();

                // 每个文件任务创建一个只读分析器，函数级并行任务通过 Arc 共享，
                // 避免每个函数都新建 ASTParser。
                let analyzer = std::sync::Arc::new(
                    crate::analysis::ast_taint::AstTaintAnalyzer::from_rules_arc(
                        taint_sources.clone(),
                        taint_sinks.clone(),
                        taint_sanitizers.clone(),
                    ),
                );

                // 构建函数级 CPG，再运行污点分析（复用线程本地 parser）
                let flows = if let Some((_tree, symbols, functions, file_assignments, file_calls)) =
                    crate::ast::parser::with_thread_local_parser(|ast_parser| {
                        ast_parser.extract_all_for_taint_with_tree(
                            &std::path::PathBuf::from(file_path_str), content,
                        )
                    })
                {
                    parsed_symbols = symbols;
                    parsed_calls = file_calls.clone();

                    // 加载回调提示
                    let callback_hints = crate::analysis::async_flow::detect_callback_hints(content);

                    if functions.is_empty() {
                        // 无函数体：整个文件构建一个 CPG
                        let func_cpg = CPGBuilder::build_file_cpg(
                            content, file_path_str, &file_assignments, &file_calls,
                        );
                        let sig_id = func_cpg.signature.id();
                        let func_flows = analyzer.analyze_function_cpg(&func_cpg, content, &callback_hints);
                        cpg_flows.insert(sig_id.clone(), func_flows.clone());
                        cpg_cache.insert(sig_id, func_cpg);
                        func_flows
                    } else {
                        // 收集函数任务（顺序过滤，避免跨线程传递 tree-sitter Node）
                        let func_tasks: Vec<_> = functions
                            .iter()
                            .filter_map(|func| {
                                // 函数级快速过滤：函数体不含 source/sink 关键词时跳过 CPG 构建
                                if let Some(ref set) = taint_keyword_set {
                                    if !set.is_match(&func.body_text) {
                                        return None;
                                    }
                                }

                                let func_hints: Vec<_> = callback_hints.iter()
                                    .filter(|h| h.callback_start_line >= func.start_line
                                        && h.callback_start_line <= func.end_line)
                                    .cloned()
                                    .collect();

                                let func_assignments: Vec<_> = file_assignments.iter()
                                    .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
                                    .cloned()
                                    .collect();

                                let func_calls: Vec<_> = file_calls.iter()
                                    .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
                                    .cloned()
                                    .collect();

                                Some((func.clone(), func_assignments, func_calls, func_hints))
                            })
                            .collect();

                        // 函数级并行构建 CPG 并运行污点分析。
                        // tree-sitter Node 不是 Send，因此每个任务在本地用函数体文本重新解析出 AST，
                        // 优先使用 AST-based CPG；解析失败时回退到 text-based CPG。
                        let ext = std::path::Path::new(file_path_str)
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("");
                        let per_func_results: Vec<_> = func_tasks
                            .into_par_iter()
                            .map(|(func, func_assignments, func_calls, func_hints)| {
                                let func_cpg = crate::ast::parser::with_thread_local_parser(|ast_parser| {
                                    if let Some(tree) = ast_parser.parse_fragment(&func.body_text, ext) {
                                        let root = tree.root_node();
                                        let mut cursor = root.walk();
                                        let body_node = root.children(&mut cursor).find(|n| {
                                            matches!(
                                                n.kind(),
                                                "block" | "statement_block" | "body" | "suite" | "block_stmt"
                                            )
                                        });
                                        if let Some(body_node) = body_node {
                                            return CPGBuilder::build_function_cpg_from_fragment(
                                                &body_node, &func.body_text, file_path_str,
                                                &func, &func_assignments, &func_calls,
                                            );
                                        }
                                    }
                                    // 回退到 text-based CPG
                                    CPGBuilder::build_function_cpg_from_text(
                                        &func.body_text, file_path_str,
                                        &func, &func_assignments, &func_calls,
                                    )
                                });
                                let sig_id = func_cpg.signature.id();
                                let func_flows = analyzer.analyze_function_cpg(
                                    &func_cpg, &func.body_text, &func_hints,
                                );
                                (sig_id, func_cpg, func_flows)
                            })
                            .collect();

                        let mut all_flows = Vec::new();
                        for (sig_id, func_cpg, func_flows) in per_func_results {
                            cpg_flows.insert(sig_id.clone(), func_flows.clone());
                            cpg_cache.insert(sig_id, func_cpg);
                            all_flows.extend(func_flows);
                        }
                        all_flows
                    }
                } else {
                    // AST 解析失败，回退到原有路径
                    analyzer.analyze_file(file_path, content)
                };

                let findings_list: Vec<Finding> = flows.iter().map(|flow| {
                    let file_str = file_path.to_string_lossy().to_string();
                    let trail: Vec<String> = flow.path.iter().map(|n| {
                        format!("{:?}:{} - {:?}", n.node_type, n.line, n.code_snippet)
                    }).collect();
                    let vuln_name = format!("{}", flow.vulnerability_type);

                    Finding {
                        finding_id: flow.id.clone(),
                        file_path: file_str.clone(),
                        line_start: flow.source.line,
                        line_end: flow.sink.line,
                        detector: "AstTaintScanner".to_string(),
                        vuln_type: vuln_name.clone(),
                        severity: format!("{:?}", flow.severity).to_lowercase(),
                        description: format!(
                            "{}: {} → {} ({}→{})",
                            vuln_name,
                            flow.source.symbol,
                            flow.sink.symbol,
                            flow.source.line,
                            flow.sink.line,
                        ),
                        analysis_trail: Some(trail),
                        llm_output: None,
                        confidence: Some(0.85),
                        corroboration_count: None,
                        code_snippet: Some(extract_code_context(content, flow.source.line, flow.sink.line, 3)),
                        source_snippet: flow.source.code_snippet.clone(),
                        sink_snippet: flow.sink.code_snippet.clone(),
                        file_role: Some(classify_file_role(&file_str).to_string()),
                        barriers: None,
                        reasoning_hint: Some(format!("Taint flow: {} → {} via {} steps", flow.source.symbol, flow.sink.symbol, flow.path.len())),
                        evidence_refs: None,
                    }
                }).collect();

                (file_path_str.clone(), findings_list, cpg_cache, cpg_flows, (parsed_symbols, parsed_calls))
            })
            .collect();

    // 收集 findings + CPG 缓存 + Stage B 已解析 AST 产物
    for (fp, mut file_findings, file_cpgs, file_flows, file_ast) in all_results {
        taint_findings.append(&mut file_findings);
        accumulated_cpg.extend(file_cpgs);
        accumulated_flows.extend(file_flows);
        accumulated_parsed_ast.insert(fp, file_ast);
    }

    if let Some(ref cb) = progress {
        cb(ScanProgress {
            phase: ScanPhase::TaintAnalysis,
            current: taint_total,
            total: taint_total,
            message: format!("AST 污点分析: {}/{} 文件", taint_total, taint_total),
        });
    }

    // 为 regex/rule 发现设置置信度
    let taint_file_lines: std::collections::HashSet<(String, usize)> = taint_findings
        .iter()
        .map(|f| (f.file_path.clone(), f.line_start))
        .collect();

    for finding in &mut findings {
        let key = (finding.file_path.clone(), finding.line_start);
        if taint_file_lines.contains(&key) {
            finding.confidence = Some(0.9);
        } else {
            finding.confidence = Some(0.5);
        }
    }

    findings.extend(taint_findings);

    // Stage C: 跨文件污点分析（enable_cross_file = true）
    let mut cross_file_result_opt: Option<crate::analysis::cross_file::CrossFileTaintResult> = None;
    if enable_cross_file {
        if let Some(ref cb) = progress {
            cb(ScanProgress {
                phase: ScanPhase::CrossFileAnalysis,
                current: 0,
                total: 1,
                message: "跨文件污点分析中...".to_string(),
            });
        }

        // 跨文件分析需要完整调用图才能发现 L2 漏掉的跨文件漏洞（如 NoSQL 注入：
        // session.js handleLoginRequest → user-dao.js validateLogin → findOne）。
        // 之前只分析 AstTaintScanner 报过的文件——循环依赖：L3 靠 L2 选文件，
        // 而 L3 的价值恰恰是发现 L2 漏的。改为分析所有 AST 支持的源文件。
        let taint_files: Vec<std::path::PathBuf> = content_cache
            .keys()
            .filter(|fp| is_ast_supported_file(std::path::Path::new(fp)))
            .map(|fp| std::path::PathBuf::from(fp))
            .collect();

        // 加载与 Stage B 一致的 YAML 污点规则，注入跨文件分析器
        let rules_dir = std::path::PathBuf::from("rules/taint");
        let (taint_sources, taint_sinks) =
            crate::rules::taint_loader::load_taint_rules_from_dir(&rules_dir)
                .map(|loaded| (loaded.sources, loaded.sinks))
                .unwrap_or_default();

        let cross_file_result = if !taint_files.is_empty() {
            let mut analyzer = if !taint_sources.is_empty() || !taint_sinks.is_empty() {
                crate::analysis::cross_file::CrossFileTaintAnalyzer::with_rules(
                    taint_sources,
                    taint_sinks,
                )
            } else {
                crate::analysis::cross_file::CrossFileTaintAnalyzer::new()
            };
            // 注入 Stage B 的 CPG 缓存，使 compute_single_summary 使用精确摘要
            if !accumulated_cpg.is_empty() {
                analyzer.set_cpg_cache(accumulated_cpg, accumulated_flows);
            }
            // 注入 Stage B 已解析 AST 产物，避免 Stage C 二次 parse
            if !accumulated_parsed_ast.is_empty() {
                analyzer.set_parsed_ast_cache(accumulated_parsed_ast);
            }
            analyzer.analyze_files_with_content(
                std::path::Path::new(path),
                &taint_files,
                &content_cache,
            )
        } else {
            crate::analysis::cross_file::CrossFileTaintResult {
                project_path: path.to_string(),
                call_graph: Arc::new(crate::analysis::cross_file::CallGraph::new()),
                taint_flows: Vec::new(),
                stats: crate::analysis::cross_file::CrossFileAnalysisStats::default(),
                type_hierarchy: crate::analysis::type_hierarchy::TypeHierarchy::new(),
                middleware_model: crate::analysis::middleware::MiddlewareModel::new(),
                file_import_aliases: std::collections::HashMap::new(),
                variable_type_map: std::collections::HashMap::new(),
            }
        };

        if !cross_file_result.taint_flows.is_empty() {
            tracing::info!(
                "[CrossFileTaint] 发现 {} 个跨文件污点流",
                cross_file_result.taint_flows.len()
            );

            // 预计算图快照（所有 cross-file finding 共享）
            let total_edges: usize = cross_file_result
                .call_graph
                .nodes
                .values()
                .map(|n| n.calls.len())
                .sum();
            let graph_snapshot = GraphSnapshot {
                total_nodes: cross_file_result.call_graph.nodes.len(),
                total_edges,
                cross_file_edges: cross_file_result.stats.cross_file_flows,
                taint_sources_count: cross_file_result.stats.taint_sources,
                taint_sinks_count: cross_file_result.stats.taint_sinks,
            };

            for flow in &cross_file_result.taint_flows {
                let intermediate: Vec<String> = flow
                    .interprocedural_path
                    .iter()
                    .map(|s| format!("{}:{}", s.file_path, s.line))
                    .collect();

                let vuln_name = format!("{}", flow.vulnerability_type);

                // 构建证据引用 — 从跨文件分析结果提取确定性证据
                let path_steps: Vec<PathStepRef> = flow
                    .interprocedural_path
                    .iter()
                    .map(|step| PathStepRef {
                        function: step.function_name.clone(),
                        file: step.file_path.clone(),
                        line: step.line,
                        step_type: match step.step_type {
                            crate::analysis::cross_file::InterproceduralStepType::Source => {
                                "source".to_string()
                            }
                            crate::analysis::cross_file::InterproceduralStepType::Sink => {
                                "sink".to_string()
                            }
                            _ => "direct_call".to_string(),
                        },
                    })
                    .collect();

                let path_length = path_steps.len();

                // 中间件覆盖证据 — 检查中间件是否在源文件注册
                let middleware_coverage: Vec<MiddlewareEvidence> = cross_file_result
                    .middleware_model
                    .express_middleware
                    .iter()
                    .map(|mw| {
                        let applies = mw.handler_file == flow.source.file_path
                            || cross_file_result
                                .middleware_model
                                .express_routes
                                .get(&mw.handler_file)
                                .map(|routes| {
                                    routes.iter().any(|l| {
                                        *l >= flow.source.line.saturating_sub(5)
                                            && *l <= flow.sink.line.saturating_add(5)
                                    })
                                })
                                .unwrap_or(false);
                        // 获取该中间件文件的第一个路由行号作为参考
                        let route_ref = cross_file_result
                            .middleware_model
                            .get_express_route_lines(&mw.handler_file)
                            .first()
                            .map(|l| format!("{}:{}", mw.handler_file, l))
                            .unwrap_or_default();
                        MiddlewareEvidence {
                            middleware_name: mw.handler_name.clone(),
                            middleware_file: mw.handler_file.clone(),
                            applies_to_route: applies,
                            route_handler: route_ref,
                        }
                    })
                    .collect();

                let evidence = EvidenceRefs {
                    source_sink_path: Some(SourceSinkEvidence {
                        source_function: flow.source.symbol.clone(),
                        source_file: flow.source.file_path.clone(),
                        source_line: flow.source.line,
                        source_node_id: flow.source.node_id.clone(),
                        sink_function: flow.sink.symbol.clone(),
                        sink_file: flow.sink.file_path.clone(),
                        sink_line: flow.sink.line,
                        sink_node_id: flow.sink.node_id.clone(),
                        path_length,
                        path_steps,
                    }),
                    sanitizer_chain: Vec::new(),
                    middleware_coverage,
                    graph_snapshot: Some(graph_snapshot.clone()),
                };

                findings.push(Finding {
                    finding_id: flow.id.clone(),
                    file_path: flow.source.file_path.clone(),
                    line_start: flow.source.line,
                    line_end: flow.sink.line,
                    detector: "CrossFileTaintAnalyzer".to_string(),
                    vuln_type: vuln_name.clone(),
                    severity: format!("{:?}", flow.severity).to_lowercase(),
                    description: format!(
                        "{}: {}:{} → {}:{} (via {})",
                        vuln_name,
                        flow.source.symbol,
                        flow.source.line,
                        flow.sink.symbol,
                        flow.sink.line,
                        intermediate.join(" → ")
                    ),
                    analysis_trail: Some(intermediate),
                    llm_output: None,
                    confidence: Some(flow.confidence),
                    corroboration_count: None,
                    code_snippet: None,
                    source_snippet: flow.source.code_snippet.clone(),
                    sink_snippet: flow.sink.code_snippet.clone(),
                    file_role: Some(classify_file_role(&flow.source.file_path).to_string()),
                    barriers: None,
                    reasoning_hint: Some(format!(
                        "Cross-file taint: {} → {} via {} hops",
                        flow.source.symbol,
                        flow.sink.symbol,
                        flow.interprocedural_path.len()
                    )),
                    evidence_refs: Some(evidence),
                });
            }
        }
        cross_file_result_opt = Some(cross_file_result);
    } // end enable_cross_file

    // 去重
    findings = deduplicate_findings(findings, line_tol);

    Ok(ScanResult {
        findings,
        attack_surface: crate::analysis::attack_surface::AttackSurface::default(),
        cross_file_result: cross_file_result_opt,
    })
}

/// 判断文件是否支持 AST 分析
fn is_ast_supported_file(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("");
        matches!(
            ext,
            "js" | "jsx"
                | "ts"
                | "tsx"
                | "py"
                | "java"
                | "rs"
                | "go"
                | "c"
                | "h"
                | "cpp"
                | "hpp"
                | "cc"
        )
    } else {
        false
    }
}

/// 去重发现：按 (file_path, line_start) 精确分组，再按 (file_path, vuln_type) ±line_tolerance 行容差分组
fn deduplicate_findings(mut findings: Vec<Finding>, line_tolerance: usize) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    // Round 1: 精确匹配 (file_path, line_start)
    let mut groups: std::collections::HashMap<(String, usize), Vec<usize>> =
        std::collections::HashMap::with_capacity(findings.len());

    for (i, f) in findings.iter().enumerate() {
        let key = (f.file_path.clone(), f.line_start);
        groups.entry(key).or_default().push(i);
    }

    let mut result = Vec::with_capacity(groups.len());
    let mut deduped_indices = std::collections::HashSet::with_capacity(findings.len());

    for (_key, indices) in groups {
        if indices.len() == 1 {
            let idx = indices[0];
            if !deduped_indices.contains(&idx) {
                deduped_indices.insert(idx);
                result.push(findings[idx].clone());
            }
        } else {
            let merged = merge_findings_at_indices(&findings, &indices);
            for &idx in &indices {
                deduped_indices.insert(idx);
            }
            result.push(merged);
        }
    }

    // Round 2: 容差匹配 — 对 Round 1 的结果按 (file_path, vuln_type) 分组，±line_tolerance 行内合并
    result = deduplicate_with_tolerance(result, line_tolerance);

    result
}

/// 多引擎置信度融合（独立证据组合）
fn fuse_confidences(confidences: &[f32]) -> f32 {
    if confidences.is_empty() {
        return 0.0;
    }
    if confidences.len() == 1 {
        return confidences[0];
    }
    let disbelief: f32 = confidences.iter().map(|&c| 1.0 - c).product();
    (1.0 - disbelief).min(0.95)
}

/// 合并同一精确位置的多个 findings
fn merge_findings_at_indices(findings: &[Finding], indices: &[usize]) -> Finding {
    let mut best_severity = "info".to_string();
    let mut best_vuln_type = String::new();
    let mut detectors = Vec::new();
    let mut best_description = String::new();
    let mut best_trail: Option<Vec<String>> = None;
    let mut best_id = String::new();
    let mut best_end = 0usize;

    let mut confidences = Vec::new();

    for &idx in indices {
        let f = &findings[idx];
        detectors.push(f.detector.clone());
        confidences.push(f.confidence.unwrap_or(0.5));

        if severity_rank(&f.severity) > severity_rank(&best_severity) {
            best_severity = f.severity.clone();
        }

        let current_len = best_vuln_type.len();
        if f.vuln_type.starts_with("CWE-") && !best_vuln_type.starts_with("CWE-") {
            best_vuln_type = f.vuln_type.clone();
        } else if !f.vuln_type.starts_with("CWE-") && current_len == 0 {
            best_vuln_type = f.vuln_type.clone();
        } else if f.vuln_type.len() > current_len {
            best_vuln_type = f.vuln_type.clone();
        }

        if f.description.len() > best_description.len() {
            best_description = f.description.clone();
        }

        if f.analysis_trail.as_ref().map(|t| t.len()).unwrap_or(0)
            > best_trail.as_ref().map(|t| t.len()).unwrap_or(0)
        {
            best_trail = f.analysis_trail.clone();
        }

        if f.line_end > best_end {
            best_end = f.line_end;
            best_id = f.finding_id.clone();
        }
    }

    let fused = fuse_confidences(&confidences);

    detectors.sort();
    detectors.dedup();

    // 多引擎 corroboration 标注
    if indices.len() > 1 {
        let engine_list: Vec<&str> = indices
            .iter()
            .map(|&idx| findings[idx].detector.as_str())
            .collect();
        let unique_engines: Vec<&&str> = {
            let mut deduped = engine_list.iter().collect::<Vec<_>>();
            deduped.sort();
            deduped.dedup();
            deduped
        };
        best_description = format!(
            "{}\n[Corroborated by {} engine(s): {}]",
            best_description,
            unique_engines.len(),
            unique_engines
                .iter()
                .map(|s| **s)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Pick best code_snippet/source_snippet/sink_snippet (prefer taint findings)
    let best_code_snippet = indices
        .iter()
        .find_map(|&idx| findings[idx].code_snippet.clone());
    let best_source_snippet = indices
        .iter()
        .find_map(|&idx| findings[idx].source_snippet.clone());
    let best_sink_snippet = indices
        .iter()
        .find_map(|&idx| findings[idx].sink_snippet.clone());
    let best_file_role = indices
        .iter()
        .find_map(|&idx| findings[idx].file_role.clone());
    let best_barriers: Vec<String> = indices
        .iter()
        .flat_map(|&idx| findings[idx].barriers.clone().unwrap_or_default())
        .collect();
    let best_reasoning = indices
        .iter()
        .find_map(|&idx| findings[idx].reasoning_hint.clone());

    Finding {
        finding_id: best_id,
        file_path: findings[indices[0]].file_path.clone(),
        line_start: findings[indices[0]].line_start,
        line_end: best_end,
        detector: detectors.join("+"),
        vuln_type: best_vuln_type,
        severity: best_severity,
        description: best_description,
        analysis_trail: best_trail,
        llm_output: None,
        confidence: Some(fused),
        corroboration_count: Some(indices.len()),
        code_snippet: best_code_snippet,
        source_snippet: best_source_snippet,
        sink_snippet: best_sink_snippet,
        file_role: best_file_role,
        barriers: if best_barriers.is_empty() {
            None
        } else {
            Some(best_barriers)
        },
        reasoning_hint: best_reasoning,
        evidence_refs: None,
    }
}

/// 容差去重：按 (file_path, vuln_type) 分组，±line_tolerance 行内合并
fn deduplicate_with_tolerance(findings: Vec<Finding>, line_tolerance: usize) -> Vec<Finding> {
    // 按 (file_path, vuln_type) 分组
    let mut groups: std::collections::HashMap<(String, String), Vec<usize>> =
        std::collections::HashMap::with_capacity(findings.len());
    for (i, f) in findings.iter().enumerate() {
        groups
            .entry((f.file_path.clone(), f.vuln_type.clone()))
            .or_default()
            .push(i);
    }

    let mut merged_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut to_add: Vec<Finding> = Vec::new();

    for (_, indices) in &groups {
        if indices.len() < 2 {
            continue;
        }

        // 聚类：行号相近的分为同一 cluster
        let mut clusters: Vec<Vec<usize>> = Vec::new();
        for &idx in indices {
            let line = findings[idx].line_start;
            let mut found = false;
            for cluster in &mut clusters {
                if cluster
                    .iter()
                    .any(|&c_idx| findings[c_idx].line_start.abs_diff(line) <= line_tolerance)
                {
                    cluster.push(idx);
                    found = true;
                    break;
                }
            }
            if !found {
                clusters.push(vec![idx]);
            }
        }

        for cluster in clusters {
            if cluster.len() < 2 {
                continue;
            }
            let merged = merge_findings_at_indices(&findings, &cluster);
            for &idx in &cluster {
                merged_indices.insert(idx);
            }
            to_add.push(merged);
        }
    }

    let mut result: Vec<Finding> = findings
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !merged_indices.contains(i))
        .map(|(_, f)| f)
        .collect();
    result.extend(to_add);
    result
}

fn is_supported_file(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("");
        matches!(
            ext,
            "js" | "jsx"
                | "ts"
                | "tsx"
                | "py"
                | "java"
                | "rs"
                | "go"
                | "html"
                | "htm"
                | "vue"
                | "css"
                | "json"
                | "c"
                | "h"
                | "cpp"
                | "hpp"
                | "cc"
        )
    } else {
        false
    }
}
