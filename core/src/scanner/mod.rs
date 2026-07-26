// Scanner module - 扫描器模块
// 定义扫描器的核心接口和类型

pub mod manager;
pub mod regex_scanner;
pub mod sca_scanner;

mod source_sink_patterns;

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
    /// 跨文件污点流数量上限，防止大型项目内存爆炸（默认 50000）
    pub cross_file_max_flows: usize,
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
            cross_file_max_flows: 5000,
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    /// 命中行所在的包围函数名（LLM 可直接用此名调 query_callers/query_callees）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclosing_function: Option<String>,
    /// 包围函数的起始行号
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclosing_function_line: Option<usize>,
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

    // source 行号可能晚于 sink 行号（AST 污点分析中 source 参数在函数尾部），
    // 因此统一取最小/最大范围，保证上下文非空。
    let (lo, hi) = if line_start <= line_end {
        (line_start, line_end)
    } else {
        (line_end, line_start)
    };

    let start = if lo > context_lines + 1 {
        lo - context_lines - 1
    } else {
        0
    };
    let end = (hi + context_lines).min(lines.len());

    let width = format!("{}", end).len();
    let mut result = String::new();
    for i in start..end {
        let line_num = i + 1;
        let marker = if line_num >= lo && line_num <= hi {
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

/// 获取指定行的原始代码片段（去除首尾空白）
pub fn line_snippet(content: &str, line: usize) -> Option<String> {
    if line == 0 {
        return None;
    }
    content
        .lines()
        .nth(line.saturating_sub(1))
        .map(|s| s.trim().to_string())
}

/// 从赋值/调用代码片段中提取净化函数名（取第一个 `name(...)` 形式）
fn extract_sanitizer_function(code: &str) -> Option<String> {
    // 去掉常见的赋值前缀，如 "String safe = " 或 "safe = "
    let code = code
        .split('=')
        .nth(1)
        .unwrap_or(code)
        .trim()
        .trim_start_matches("new ")
        .trim();
    // 匹配 identifier(...)
    let re = regex::Regex::new(r"^([A-Za-z_][A-Za-z0-9_:\.]*)\s*\(").ok()?;
    re.captures(code)
        .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
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
        "/extra/",
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
        "/vendors/",
        "/third-party/",
        "/third_party/",
        "/external/",
        "/polyfill",
        "/node_modules/",
        "/plugins/",
        "/libs/",
        "/webjars/",
    ];
    for marker in &vendor_markers {
        if normalized.contains(marker) {
            return "vendor";
        }
    }
    // 压缩/打包产物文件名（minified 第三方库是调用图与污点分析的主要噪声源）
    let vendor_file_patterns = [".min.js", ".min.css", ".bundle.js", ".chunk.js", ".vendor.js"];
    for pat in &vendor_file_patterns {
        if file_name.ends_with(pat) {
            return "vendor";
        }
    }
    // 知名第三方库文件名前缀（jquery-1.10.2.min.js、bootstrap.js 等）
    let vendor_file_prefixes = [
        "jquery",
        "bootstrap",
        "lodash",
        "underscore",
        "zepto",
        "modernizr",
    ];
    for prefix in &vendor_file_prefixes {
        if file_name.starts_with(prefix) {
            return "vendor";
        }
    }

    "production"
}

/// 基于内容识别 minified 文件（未按 `.min.js` 命名的压缩第三方库，如 google-map.js）
///
/// 启发式：文件足够大，且存在超长单行（>1000 字符），
/// 或平均行长超过 400 字符（正常源码极少超过 120）。
pub fn is_minified_content(content: &str) -> bool {
    if content.len() < 1024 {
        return false;
    }
    let mut line_count = 0usize;
    let mut total_len = 0usize;
    for line in content.lines().take(50) {
        if line.len() > 1000 {
            return true;
        }
        line_count += 1;
        total_len += line.len();
    }
    line_count > 0 && total_len / line_count > 400
}

/// 结合路径与内容的文件角色分类。
/// 路径判定为 production 但内容是 minified 的 JS/CSS，归入 vendor。
pub fn classify_file_role_with_content(path: &str, content: &str) -> &'static str {
    let role = classify_file_role(path);
    if role != "production" {
        return role;
    }
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if matches!(ext.as_str(), "js" | "jsx" | "ts" | "tsx" | "css") && is_minified_content(content) {
        return "vendor";
    }
    role
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

        // shell: true 检测 — 标记为高风险（shell 解释器会执行注入的命令）
        if context_block.contains("shell: true")
            || context_block.contains("shell:true")
            || context_block.contains("shell=True")
            || context_block.contains("shell = True")
        {
            barriers.push("shell:true".to_string());
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

/// 判断文件名是否为测试文件（Stage B 污点分析跳过——测试文件不承载
/// 生产攻击面，只消耗分析量并产噪，方法论 10.12；规则层 Stage A 行为不变）
fn is_test_file_name(path: &str) -> bool {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_lowercase();
    name.contains(".spec.")
        || name.contains(".test.")
        || name.ends_with("_test.go")
        || name.ends_with("_test.py")
        || (name.starts_with("test_") && name.ends_with(".py"))
}

/// Stage B 进度与慢文件日志 guard：map 闭包内声明一次，
/// drop 时计数并按需输出（10.12 性能缺口的定位手段）
struct TaintProgressGuard<'a> {
    file: &'a str,
    start: std::time::Instant,
    done_counter: &'a std::sync::atomic::AtomicUsize,
    total: usize,
    scan_start: std::time::Instant,
    trace: bool,
}

impl Drop for TaintProgressGuard<'_> {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        let done = self
            .done_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if self.trace {
            tracing::info!("[TaintAnalysis] 完成分析: {}", self.file);
        }
        // 单文件超 10s 大概率是病态文件（超线性热点定位线索）
        if elapsed.as_secs() >= 10 {
            tracing::warn!(
                "[TaintAnalysis] 慢文件 {:.1}s: {}",
                elapsed.as_secs_f64(),
                self.file
            );
        }
        if done % 100 == 0 || done == self.total {
            tracing::info!(
                "[TaintAnalysis] Stage B 进度 {}/{}，累计 {:.1}s",
                done,
                self.total,
                self.scan_start.elapsed().as_secs_f64()
            );
        }
    }
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
            // 文件系统查找失败（如仓库外运行），回退到二进制内置嵌入规则
            let r = crate::rules::embedded::load_embedded_pattern_rules();
            tracing::info!("未找到规则目录，使用内置嵌入规则 ({} 条)", r.len());
            r
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

    let scan_root = std::path::Path::new(path);

    let mut code_files: Vec<std::path::PathBuf> = Vec::new();
    let mut dep_files: Vec<std::path::PathBuf> = Vec::new();

    for entry in Walk::new(path) {
        if let Ok(entry) = entry {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // 排除目录过滤：基于扫描根目录的相对路径，
            // 避免项目本身位于名为 target/build/test 的父目录时被整体排除。
            let rel_path = path.strip_prefix(scan_root).unwrap_or(path);
            if is_excluded(rel_path, &excludes) {
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

    // 全局认证守卫检测：Flask before_request / Express app.use(auth) / Django MIDDLEWARE
    // 在 per-file 循环外一次性计算，避免每个文件重复遍历项目
    let has_global_auth =
        crate::analysis::attack_surface::AttackSurfaceMapper::has_global_auth_middleware(scan_root);

    for chunk in code_files.chunks(batch_size) {
        let code_results: Vec<(Vec<Finding>, Vec<Finding>, Option<(String, String)>, usize)> =
            chunk
                .par_iter()
                .map(|path_buf| {
                    let rel_path = path_buf.strip_prefix(scan_root).unwrap_or(path_buf.as_path());

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
                            // 全局认证守卫（before_request / app.use(auth) / MIDDLEWARE）覆盖时
                            // 不报告 UnauthenticatedEndpoint——端点受全局门保护
                            if has_global_auth {
                                continue;
                            }
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
                            if !is_test_path(&ep.file_path) && !is_excluded(rel_path, &excludes) {
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
                                    ..Default::default()
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

    // MyBatis XML mapper 动态 SQL 检测 — 泛化扫描所有 mapper XML
    let xml_findings = scan_mybatis_mapper_xml(std::path::Path::new(path), &non_production_path_patterns);
    findings.extend(xml_findings);

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

    // RegexRule/ASTRule 单跳证据富化：在 sink 附近 ±35 行内找到 source 模式时，
    // 构造轻量 source→sink 结构化证据并写入 finding.evidence_refs。
    enrich_rule_findings_with_local_source_sink(&mut findings, &content_cache);

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
    /// 项目安全框架配置（从 pom.xml / build.gradle 中检测）
    pub project_profile: crate::analysis::ProjectProfile,
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
        project_profile: crate::analysis::framework_detector::detect_project_profile(
            std::path::Path::new(path),
        ),
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
    let cross_file_max_flows = scan_opts
        .as_ref()
        .map(|o| o.cross_file_max_flows)
        .unwrap_or(5000);

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
            project_profile: Default::default(),
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
                // 与 Stage A 一致：排除判断基于相对扫描根的路径，
                // 避免扫描根本身位于 target/ 等目录时 AST 文件被整体跳过
                let rel = p.strip_prefix(path).unwrap_or(p);
                if is_excluded(rel, &excludes) {
                    continue;
                }
                // 测试文件不进污点分析（10.12）
                if is_test_path(&p_str) || is_test_file_name(&p_str) {
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
        // vendor / minified 第三方库不进入污点分析（只产生噪声）
        .filter(|(fp, content)| classify_file_role_with_content(fp, content) != "vendor")
        // 测试文件不进入污点分析（10.12：约占分析量两成，纯浪费且只产噪；
        // Stage A 规则扫描对它们的行为不变）
        .filter(|(fp, _)| !is_test_path(fp) && !is_test_file_name(fp))
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
    let loaded_taint =
        crate::rules::taint_loader::load_taint_rules_with_embedded_fallback(rules_dir);
    let (taint_sources, taint_sinks, taint_sanitizers) =
        if !loaded_taint.sources.is_empty() || !loaded_taint.sinks.is_empty() {
            tracing::info!(
                "Loaded {} sources, {} sinks, {} sanitizers",
                loaded_taint.sources.len(),
                loaded_taint.sinks.len(),
                loaded_taint.sanitizer_patterns.len(),
            );
            (
                loaded_taint.sources,
                loaded_taint.sinks,
                loaded_taint.sanitizer_patterns,
            )
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
    let taint_scan_start = std::time::Instant::now();
    let taint_done_counter = std::sync::atomic::AtomicUsize::new(0);
    let taint_total_files = all_file_data.len();
    // 卡死文件定位手段：CTX_AUDIT_TRACE_FILES=1 时逐文件记录"开始分析"，
    // 日志里最后一个有开始无完成的文件即病态文件（慢文件告警只在完成后触发，抓不到卡死）
    let taint_trace_files = std::env::var_os("CTX_AUDIT_TRACE_FILES").is_some();
    type FileAst = (Vec<crate::ast::Symbol>, Vec<crate::ast::CallInfo>);
    let all_results: Vec<(
        String,
        Vec<Finding>,
        HashMap<String, crate::analysis::cpg::FunctionCPG>,
        HashMap<String, Vec<crate::analysis::taint::TaintFlow>>,
        FileAst,
    )> = all_file_data
        .into_par_iter()
        .map(|(ref file_path_str, ref content)| {
            use crate::analysis::cpg::CPGBuilder;

            let _progress = TaintProgressGuard {
                file: file_path_str,
                start: std::time::Instant::now(),
                done_counter: &taint_done_counter,
                total: taint_total_files,
                scan_start: taint_scan_start,
                trace: taint_trace_files,
            };
            if taint_trace_files {
                tracing::info!("[TaintAnalysis] 开始分析: {}", file_path_str);
            }

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
            let mut cpg_flows: HashMap<String, Vec<crate::analysis::taint::TaintFlow>> =
                HashMap::new();

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
                        &std::path::PathBuf::from(file_path_str),
                        content,
                    )
                }) {
                parsed_symbols = symbols;
                parsed_calls = file_calls.clone();

                // 加载回调提示
                let callback_hints = crate::analysis::async_flow::detect_callback_hints(content);

                // 10.14：纯数据文件快路径——无函数且无调用的 PHP 文件不存在可达 sink
                // （sink 均为函数调用；echo/print 本就不进 CallInfo，见 backlog 10.8），
                // 跳过整文件 CPG，避免巨型数组字面量（语言包/配置类）在路径敏感
                // 分析中的病态耗时（kanboard Locale 实测 ~240s/文件 → 0）
                let is_php_file = std::path::Path::new(file_path_str)
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|e| e.eq_ignore_ascii_case("php"))
                    .unwrap_or(false);
                if functions.is_empty() && file_calls.is_empty() && is_php_file {
                    return (
                        file_path_str.clone(),
                        Vec::new(),
                        cpg_cache,
                        cpg_flows,
                        (parsed_symbols, parsed_calls),
                    );
                }

                if functions.is_empty() {
                    // 无函数体：整个文件构建一个 CPG
                    let func_cpg = CPGBuilder::build_file_cpg(
                        content,
                        file_path_str,
                        &file_assignments,
                        &file_calls,
                    );
                    let sig_id = func_cpg.signature.id();
                    let func_flows =
                        analyzer.analyze_function_cpg(&func_cpg, content, &callback_hints);
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

                            let func_hints: Vec<_> = callback_hints
                                .iter()
                                .filter(|h| {
                                    h.callback_start_line >= func.start_line
                                        && h.callback_start_line <= func.end_line
                                })
                                .cloned()
                                .collect();

                            let func_assignments: Vec<_> = file_assignments
                                .iter()
                                .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
                                .cloned()
                                .collect();

                            let func_calls: Vec<_> = file_calls
                                .iter()
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
                    let per_func_results: Vec<_> =
                        func_tasks
                            .into_par_iter()
                            .map(|(func, func_assignments, func_calls, func_hints)| {
                                let func_cpg =
                                    crate::ast::parser::with_thread_local_parser(|ast_parser| {
                                        if let Some(tree) =
                                            ast_parser.parse_fragment(&func.body_text, ext)
                                        {
                                            let root = tree.root_node();
                                            let mut cursor = root.walk();
                                            let body_node = root.children(&mut cursor).find(|n| {
                                                matches!(
                                                    n.kind(),
                                                    "block"
                                                        | "statement_block"
                                                        | "body"
                                                        | "suite"
                                                        | "block_stmt"
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
                                            &func.body_text,
                                            file_path_str,
                                            &func,
                                            &func_assignments,
                                            &func_calls,
                                        )
                                    });
                                let sig_id = func_cpg.signature.id();
                                let func_flows = analyzer.analyze_function_cpg(
                                    &func_cpg,
                                    &func.body_text,
                                    &func_hints,
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

            let findings_list: Vec<Finding> = flows
                .iter()
                // 存储写入点不是漏洞：不产出 finding，flow 保留在 cpg_flows 中
                // 供扫描收尾的二阶流闸门统计
                .filter(|flow| {
                    flow.vulnerability_type
                        != crate::analysis::taint::VulnerabilityType::StorageWrite
                })
                .map(|flow| {
                    let file_str = file_path.to_string_lossy().to_string();
                    let trail: Vec<String> = flow
                        .path
                        .iter()
                        .map(|n| format!("{:?}:{} - {:?}", n.node_type, n.line, n.code_snippet))
                        .collect();
                    let vuln_name = format!("{}", flow.vulnerability_type);

                    let path_steps: Vec<PathStepRef> = flow
                        .path
                        .iter()
                        .map(|n| PathStepRef {
                            function: n.symbol.clone(),
                            file: n.file_path.clone(),
                            line: n.line,
                            step_type: match n.node_type {
                                crate::analysis::taint::FlowNodeType::Source => {
                                    "source".to_string()
                                }
                                crate::analysis::taint::FlowNodeType::Sink => "sink".to_string(),
                                crate::analysis::taint::FlowNodeType::Sanitized => {
                                    "sanitization".to_string()
                                }
                                crate::analysis::taint::FlowNodeType::Call => "call".to_string(),
                                crate::analysis::taint::FlowNodeType::Return => {
                                    "return".to_string()
                                }
                                _ => "propagation".to_string(),
                            },
                        })
                        .collect();

                    let sanitizer_chain: Vec<SanitizerEvidence> = flow
                        .path
                        .iter()
                        .filter(|n| n.node_type == crate::analysis::taint::FlowNodeType::Sanitized)
                        .map(|n| {
                            let function = n
                                .code_snippet
                                .as_deref()
                                .and_then(extract_sanitizer_function)
                                .unwrap_or_else(|| n.symbol.clone());
                            SanitizerEvidence {
                                function,
                                file: n.file_path.clone(),
                                line: n.line,
                                effective: true,
                                reason: "净化函数被识别并出现在污点路径中".to_string(),
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
                            path_length: path_steps.len(),
                            path_steps,
                        }),
                        sanitizer_chain,
                        middleware_coverage: Vec::new(),
                        graph_snapshot: None,
                    };

                    let role = classify_file_role(&file_str);
                    let flow_barriers: Vec<String> = if flow
                        .path
                        .iter()
                        .any(|n| n.node_type == crate::analysis::taint::FlowNodeType::Sanitized)
                    {
                        vec!["sanitization_detected".to_string()]
                    } else {
                        Vec::new()
                    };

                    Finding {
                        finding_id: flow.id.clone(),
                        file_path: file_str.clone(),
                        line_start: flow.source.line,
                        line_end: flow.sink.line,
                        detector: "AstTaintScanner".to_string(),
                        vuln_type: vuln_name.clone(),
                        // 与规则扫描一致：按文件角色与屏障调整严重度
                        severity: adjust_severity(
                            &format!("{:?}", flow.severity).to_lowercase(),
                            role,
                            &flow_barriers,
                        ),
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
                        // 二阶流（存储点读出）：数据流真实但来源是已存储数据，置信度 0.85→0.6
                        confidence: Some(if flow.source.symbol.contains("(second-order)") {
                            0.6
                        } else {
                            0.85
                        }),
                        corroboration_count: None,
                        code_snippet: Some(extract_code_context(
                            content,
                            flow.source.line,
                            flow.sink.line,
                            3,
                        )),
                        source_snippet: flow
                            .source
                            .code_snippet
                            .clone()
                            .or_else(|| line_snippet(content, flow.source.line)),
                        sink_snippet: flow
                            .sink
                            .code_snippet
                            .clone()
                            .or_else(|| line_snippet(content, flow.sink.line)),
                        file_role: Some(role.to_string()),
                        barriers: if flow_barriers.is_empty() {
                            None
                        } else {
                            Some(flow_barriers)
                        },
                        reasoning_hint: Some(format!(
                            "Taint flow: {} → {} via {} steps. {}{}{}",
                            flow.source.symbol,
                            flow.sink.symbol,
                            flow.path.len(),
                            sink_context_hint(&vuln_name),
                            if flow
                                .path
                                .iter()
                                .any(|n| n.node_type
                                    == crate::analysis::taint::FlowNodeType::Sanitized)
                            {
                                "；路径中检测到净化处理"
                            } else {
                                ""
                            },
                            if flow.source.symbol.contains("(second-order)") {
                                "；二阶流（存储点读出，需确认存在对应的污点写入路径）"
                            } else {
                                ""
                            }
                        )),
                        evidence_refs: Some(evidence),
                        ..Default::default()
                    }
                })
                .collect();

            (
                file_path_str.clone(),
                findings_list,
                cpg_cache,
                cpg_flows,
                (parsed_symbols, parsed_calls),
            )
        })
        .collect();

    tracing::info!(
        "[TaintAnalysis] Stage B 完成：{} 文件，耗时 {:.1}s，产出 {} findings",
        taint_total_files,
        taint_scan_start.elapsed().as_secs_f64(),
        all_results.iter().map(|(_, f, _, _, _)| f.len()).sum::<usize>()
    );

    // 收集 findings + CPG 缓存 + Stage B 已解析 AST 产物
    for (fp, mut file_findings, file_cpgs, file_flows, file_ast) in all_results {
        taint_findings.append(&mut file_findings);
        accumulated_cpg.extend(file_cpgs);
        accumulated_flows.extend(file_flows);
        accumulated_parsed_ast.insert(fp, file_ast);
    }

    // 从 Stage B 已解析符号提取每文件函数区间表（仅函数名+行号范围的轻量拷贝）。
    // accumulated_parsed_ast 随后会被 move 进跨文件分析器，因此必须先提取；
    // 该表用于扫描收尾时为 finding 填充 enclosing_function，避免为此二次解析文件。
    let file_function_ranges = build_file_function_ranges(&accumulated_parsed_ast);

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

    // 二阶流闸门事件计数：Stage B 各文件命中 storage_write sink 的 flow（跨文件部分在 Stage C 累加）
    let mut storage_write_events = accumulated_flows
        .values()
        .flatten()
        .filter(|f| f.vulnerability_type == crate::analysis::taint::VulnerabilityType::StorageWrite)
        .count();

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
            .iter()
            .filter(|(fp, _)| is_ast_supported_file(std::path::Path::new(fp)))
            // vendor / minified 第三方库不进入跨文件分析（只产生噪声边）
            .filter(|(fp, content)| classify_file_role_with_content(fp, content) != "vendor")
            .map(|(fp, _)| std::path::PathBuf::from(fp))
            .collect();

        // 加载与 Stage B 一致的 YAML 污点规则，注入跨文件分析器
        let rules_dir = std::path::PathBuf::from("rules/taint");
        let loaded_taint =
            crate::rules::taint_loader::load_taint_rules_with_embedded_fallback(&rules_dir);
        let (taint_sources, taint_sinks) = (loaded_taint.sources, loaded_taint.sinks);

        let mut cross_file_result = if !taint_files.is_empty() {
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

            // 对超大型项目，通过 drain + 精确容量分配截断流列表，
            // 立即释放旧 Vec 的内存。truncate() 不回收容量，在
            // 37K+ 流的大项目上会导致内存碎片。
            let flow_count = cross_file_result.taint_flows.len();
            let keep = flow_count.min(cross_file_max_flows);
            if flow_count > cross_file_max_flows {
                tracing::warn!(
                    "[CrossFileTaint] 跨文件污点流超过上限 {}，截断前 {} 个，保留 {} 个",
                    cross_file_max_flows, flow_count, keep
                );
            }
            let flows: Vec<_> = cross_file_result
                .taint_flows
                .drain(..)
                .take(keep)
                .collect();
            cross_file_result.taint_flows = flows;
            // 预分配 findings 容量，避免 Vec 增长时的多轮重新分配
            findings.reserve(keep);

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

            // 中间件覆盖证据在每个流中相同——只计算一次
            let shared_middleware_coverage: Vec<MiddlewareEvidence> =
                cross_file_result
                    .middleware_model
                    .express_middleware
                    .iter()
                    .map(|mw| {
                        let applies = mw.handler_file
                            == cross_file_result
                                .taint_flows
                                .first()
                                .map(|f| f.source.file_path.as_str())
                                .unwrap_or("");
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

            for flow in &cross_file_result.taint_flows {
                // 存储写入点不是漏洞：不产出 finding，但计入二阶流闸门事件
                if flow.vulnerability_type == crate::analysis::taint::VulnerabilityType::StorageWrite
                {
                    storage_write_events += 1;
                    continue;
                }
                let intermediate: Vec<String> = flow
                    .interprocedural_path
                    .iter()
                    .map(|s| format!("{}@{}:{}", s.function_name, s.file_path, s.line))
                    .collect();

                let vuln_name = format!("{}", flow.vulnerability_type);

                let evidence = build_evidence_refs_from_flow(
                    flow,
                    &graph_snapshot,
                    &shared_middleware_coverage,
                );

                // 为跨文件 finding 补充源码上下文：同文件取 source→sink，跨文件取 source 周围
                let code_snippet = content_cache.get(&flow.source.file_path).map(|content| {
                    if flow.source.file_path == flow.sink.file_path {
                        extract_code_context(content, flow.source.line, flow.sink.line, 3)
                    } else {
                        extract_code_context(content, flow.source.line, flow.source.line, 5)
                    }
                });

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
                    code_snippet,
                    source_snippet: flow.source.code_snippet.clone().or_else(|| {
                        content_cache
                            .get(&flow.source.file_path)
                            .and_then(|c| line_snippet(c, flow.source.line))
                    }),
                    sink_snippet: flow.sink.code_snippet.clone().or_else(|| {
                        content_cache
                            .get(&flow.sink.file_path)
                            .and_then(|c| line_snippet(c, flow.sink.line))
                    }),
                    file_role: Some(classify_file_role(&flow.source.file_path).to_string()),
                    barriers: None,
                    reasoning_hint: Some(format!(
                        "Cross-file taint: {} → {} via {} hops. {}",
                        flow.source.symbol,
                        flow.sink.symbol,
                        flow.interprocedural_path.len(),
                        sink_context_hint(&vuln_name)
                    )),
                    evidence_refs: Some(evidence),
                    ..Default::default()
                });
            }

            // 把跨文件污点证据回填到 Stage A 的 Rule/AttackSurface finding，
            // 让大量原本只有代码片段的 finding 获得 source→sink 路径。
            enrich_findings_with_cross_file_evidence(
                &mut findings,
                &cross_file_result,
                &graph_snapshot,
            );

            // 为每个 finding 填充 enclosing_function，让 LLM 可以直接用函数名查调用图
            let query_engine =
                crate::analysis::query::CallGraphQueryEngine::from_result(&cross_file_result);
            enrich_findings_with_enclosing_function(&mut findings, &query_engine);
        }
        cross_file_result_opt = Some(cross_file_result);
    } // end enable_cross_file

    // 去重
    findings = deduplicate_findings(findings, line_tol);

    // 去重后为仍未填充的 finding 用 Stage B 函数区间表补齐 enclosing_function。
    // 跨文件模式已由调用图引擎填充的 finding 在此处被跳过，行为保持不变；
    // 纯规则扫描（无 Stage B 数据）时该表为空，调用为 no-op。
    enrich_findings_with_enclosing_function_from_symbols(&mut findings, &file_function_ranges);

    // 二阶流闸门：项目内未检测到"污点写入存储点"（storage_write sink 命中）时，
    // 二阶 source（存储点读出）的 finding 降级为 info 参考——降权不丢弃。
    // 有污点写入事件时保持原严重度：存储型漏洞的写入路径已被证实存在。
    if storage_write_events == 0 {
        for finding in &mut findings {
            if finding.description.contains("(second-order)") {
                finding.severity = "info".to_string();
                if let Some(ref mut hint) = finding.reasoning_hint {
                    hint.push_str("；项目内未检测到污点写入存储点，降级为参考");
                }
            }
        }
    }

    Ok(ScanResult {
        findings,
        attack_surface: crate::analysis::attack_surface::AttackSurface::default(),
        cross_file_result: cross_file_result_opt,
        project_profile: Default::default(),
    })
}

/// 将跨文件污点流转换为结构化证据引用
fn build_evidence_refs_from_flow(
    flow: &crate::analysis::cross_file::InterproceduralTaintFlow,
    graph_snapshot: &GraphSnapshot,
    shared_middleware_coverage: &[MiddlewareEvidence],
) -> EvidenceRefs {
    let path_steps: Vec<PathStepRef> = flow
        .interprocedural_path
        .iter()
        .map(|step| PathStepRef {
            function: step.function_name.clone(),
            file: step.file_path.clone(),
            line: step.line,
            step_type: match step.step_type {
                crate::analysis::cross_file::InterproceduralStepType::Source => "source".to_string(),
                crate::analysis::cross_file::InterproceduralStepType::Sink => "sink".to_string(),
                crate::analysis::cross_file::InterproceduralStepType::ParameterIn => {
                    "parameter_in".to_string()
                }
                crate::analysis::cross_file::InterproceduralStepType::ParameterOut => {
                    "parameter_out".to_string()
                }
                crate::analysis::cross_file::InterproceduralStepType::ReturnValue => {
                    "return_value".to_string()
                }
                crate::analysis::cross_file::InterproceduralStepType::Assignment => {
                    "assignment".to_string()
                }
            },
        })
        .collect();

    let path_length = path_steps.len();

    EvidenceRefs {
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
        middleware_coverage: shared_middleware_coverage.to_vec(),
        graph_snapshot: Some(graph_snapshot.clone()),
    }
}

/// MyBatis XML mapper 动态 SQL 注入检测。
///
/// 扫描 `resources/mapper/**/*.xml` 文件，查找 `${...}` 动态 SQL 模式。
/// 泛化设计：不限项目、不限 MyBatis 版本、不限 SQL 方言。
fn scan_mybatis_mapper_xml(
    project_path: &std::path::Path,
    non_production_patterns: &[String],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    // 递归遍历项目目录，找 mapper/**/*.xml 文件。
    // 泛化：不限目录深度，不限模块结构。
    let mut dirs_to_scan: Vec<std::path::PathBuf> = vec![project_path.to_path_buf()];
    while let Some(dir) = dirs_to_scan.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
            if path.is_dir() {
                // 跳过非代码目录
                if name == "target" || name == "node_modules" || name == ".git" || name == ".ctx-audit" {
                    continue;
                }
                dirs_to_scan.push(path);
            } else if path.extension().map(|e| e == "xml").unwrap_or(false) {
                // 只处理 mapper 目录下的 XML 文件
                let parent = path.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                if !parent.contains("mapper") {
                    // Also check grandparent: .../resources/mapper/system/xxx.xml
                    let grandparent = path.parent().and_then(|p| p.parent()).and_then(|p| p.file_name()).map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                    if !grandparent.contains("mapper") {
                        continue;
                    }
                }
                process_mapper_xml(&path, project_path, non_production_patterns, &mut findings);
            }
        }
    }
    findings
}

fn process_mapper_xml(
    path: &std::path::Path,
    project_path: &std::path::Path,
    non_production_patterns: &[String],
    findings: &mut Vec<Finding>,
) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lower = content.to_lowercase();
    if !lower.contains("namespace") && !lower.contains("<select") && !lower.contains("<insert") {
        return;
    }
    let rel = path.strip_prefix(project_path).unwrap_or(path);
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    let is_non_prod = non_production_patterns.iter().any(|p| rel_str.contains(p));
    let file_role = if is_non_prod {
        Some("non-production".to_string())
    } else {
        Some("production".to_string())
    };
    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("<!--") || trimmed.contains("<![CDATA[") {
            continue;
        }
        if let Some(pos) = trimmed.find("${") {
            let end = trimmed[pos..].find('}').map(|e| pos + e).unwrap_or(trimmed.len());
            let snippet = &trimmed[pos..=end.min(pos + 60)];
            let stmt_id = extract_mybatis_statement_id(&content, line_no);
            findings.push(Finding {
                finding_id: uuid::Uuid::new_v4().to_string(),
                file_path: rel_str.clone(),
                line_start: line_no + 1,
                line_end: line_no + 1,
                detector: "MyBatisDynamicSQL".to_string(),
                vuln_type: "CWE-89".to_string(),
                severity: "critical".to_string(),
                description: format!(
                    "MyBatis ${} parameter in {}: {}",
                    snippet,
                    stmt_id.as_deref().unwrap_or("unknown statement"),
                    trimmed.trim()
                ),
                analysis_trail: None,
                llm_output: None,
                confidence: Some(0.9),
                corroboration_count: None,
                code_snippet: Some(trimmed.to_string()),
                source_snippet: None,
                sink_snippet: Some(snippet.to_string()),
                file_role: file_role.clone(),
                barriers: None,
                reasoning_hint: Some(format!(
                    "MyBatis ${} replaces text without parameterization in {}",
                    snippet,
                    stmt_id.as_deref().unwrap_or("?")
                )),
                evidence_refs: None,
                ..Default::default()
            });
        }
    }
}

/// 从 MyBatis XML mapper 中提取当前行所属的 SQL 语句 ID。
fn extract_mybatis_statement_id(content: &str, target_line: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    // 向上搜索最近的 <select>, <insert>, <update>, <delete> 标签
    for i in (0..target_line.min(lines.len())).rev() {
        let line = lines[i].trim();
        for tag in &["select", "insert", "update", "delete"] {
            if line.contains(&format!("<{}", tag)) && line.contains("id=\"") {
                if let Some(start) = line.find("id=\"") {
                    let rest = &line[start + 4..];
                    if let Some(end) = rest.find('"') {
                        return Some(format!("{}.{}", tag, &rest[..end]));
                    }
                }
            }
        }
    }
    None
}

/// 将漏洞类型字符串归一化为 CWE 编号（如 "CWE-22"）。
///
/// 支持直接 CWE 编号（"CWE-22"）、常见漏洞名称（"PathTraversal"）以及
/// 规则输出的描述性字符串（"RegexRule: path-traversal"）。
fn normalize_vuln_type_to_cwe(vuln: &str) -> Option<String> {
    let lower = vuln.to_lowercase();

    // 1. 直接包含 CWE 编号
    if let Some(cwe) = lower.split(|c: char| !c.is_ascii_digit()).find(|s| s.len() >= 2) {
        return Some(format!("CWE-{}", cwe));
    }

    // 2. 按常见别名映射到 CWE
    let aliases: &[(&str, &str)] = &[
        ("sqli", "CWE-89"),
        ("sql injection", "CWE-89"),
        ("sql-injection", "CWE-89"),
        ("sql", "CWE-89"),
        ("command injection", "CWE-78"),
        ("command-injection", "CWE-78"),
        ("os command", "CWE-78"),
        ("pathtraversal", "CWE-22"),
        ("path-traversal", "CWE-22"),
        ("path traversal", "CWE-22"),
        ("directory traversal", "CWE-22"),
        ("directory-traversal", "CWE-22"),
        ("crosssitescripting", "CWE-79"),
        ("cross-site scripting", "CWE-79"),
        ("xss", "CWE-79"),
        ("serversiderequestforgery", "CWE-918"),
        ("server-side request forgery", "CWE-918"),
        ("ssrf", "CWE-918"),
        ("insecuredeserialization", "CWE-502"),
        ("unsafe deserialization", "CWE-502"),
        ("deserialization", "CWE-502"),
        ("code injection", "CWE-94"),
        ("open redirect", "CWE-601"),
        ("ldap injection", "CWE-90"),
        ("xxe", "CWE-611"),
        ("xml external entity", "CWE-611"),
        ("xpath injection", "CWE-643"),
        ("cache poisoning", "CWE-444"),
        ("buffer overflow", "CWE-121"),
        ("format string", "CWE-134"),
        ("insecure random", "CWE-330"),
        ("weak random", "CWE-330"),
        ("insecure cookie", "CWE-614"),
        ("secure cookie", "CWE-614"),
        ("hardcoded password", "CWE-259"),
        ("hardcoded credential", "CWE-259"),
        ("sensitive info", "CWE-200"),
        ("sensitive data", "CWE-200"),
        ("debug info", "CWE-200"),
        ("log injection", "CWE-117"),
        ("log spoof", "CWE-117"),
    ];

    for (pattern, cwe) in aliases {
        if lower.contains(pattern) {
            return Some((*cwe).to_string());
        }
    }

    None
}

/// RegexRule / ASTRule 单跳证据富化。
///
/// 对 Stage A 中 detector 为 "RegexRule:*" 或 "ASTRule:*" 且尚无 evidence_refs 的 finding，
/// 在 sink 所在位置 ±35 行窗口内匹配语言相关的输入源模式。命中则在 finding 上写入
/// 一条轻量 source→sink 结构化证据，并把置信度提升到 0.85。
fn enrich_rule_findings_with_local_source_sink(
    findings: &mut [Finding],
    content_cache: &HashMap<String, String>,
) {
    for finding in findings {
        if finding.evidence_refs.is_some() {
            continue;
        }
        // 访问控制/攻击面类 finding 不依赖 source→sink 数据流，跳过
        if finding.vuln_type == "UnauthenticatedEndpoint" {
            continue;
        }
        let is_rule = finding.detector.starts_with("RegexRule:")
            || finding.detector.starts_with("ASTRule:");
        if !is_rule {
            continue;
        }
        let Some(content) = content_cache.get(&finding.file_path) else {
            continue;
        };

        let Some(matched) = source_sink_patterns::find_local_source_sink(
            &finding.file_path,
            &finding.vuln_type,
            &finding.description,
            content,
            finding.line_start,
        ) else {
            continue;
        };

        let path_steps = vec![
            PathStepRef {
                function: matched.source_pattern.clone(),
                file: finding.file_path.clone(),
                line: matched.source_line,
                step_type: "synthetic_source".to_string(),
            },
            PathStepRef {
                function: finding.detector.clone(),
                file: finding.file_path.clone(),
                line: finding.line_start,
                step_type: "synthetic_sink".to_string(),
            },
        ];

        finding.evidence_refs = Some(EvidenceRefs {
            source_sink_path: Some(SourceSinkEvidence {
                source_function: matched.source_pattern,
                source_file: finding.file_path.clone(),
                source_line: matched.source_line,
                source_node_id: None,
                sink_function: finding.detector.clone(),
                sink_file: finding.file_path.clone(),
                sink_line: finding.line_start,
                sink_node_id: None,
                path_length: 1,
                path_steps,
            }),
            sanitizer_chain: Vec::new(),
            middleware_coverage: Vec::new(),
            graph_snapshot: None,
        });

        finding.confidence = Some(finding.confidence.unwrap_or(0.5).max(0.85));
    }
}

/// 按漏洞类型名称判断跨文件流是否与已有 finding 兼容。
///
/// 用于回填 evidence 时避免把 SQLi 的污点路径贴到 PathTraversal finding 上。
fn is_compatible_vuln_type(finding_vuln: &str, flow_vuln: &crate::analysis::VulnerabilityType) -> bool {
    is_compatible_vuln_type_str(finding_vuln, &format!("{:?}", flow_vuln))
}

/// 扫描后证据富化：把跨文件污点流或同函数内其他 finding 的 evidence_refs
/// 回填到没有证据的 Stage A finding。
///
/// 回填条件：
/// 1. finding 当前没有 evidence_refs；
/// 2. finding 不是 UnauthenticatedEndpoint（访问控制类不依赖 source→sink）；
/// 3. finding 与证据 source/sink 位于同一文件同一函数内（按调用图函数范围匹配）；
/// 4. 漏洞类型兼容。
fn enrich_findings_with_cross_file_evidence(
    findings: &mut [Finding],
    cross_file_result: &crate::analysis::cross_file::CrossFileTaintResult,
    graph_snapshot: &GraphSnapshot,
) {
    let flows = &cross_file_result.taint_flows;
    if flows.is_empty() {
        return;
    }

    // 用跨文件结果构建调用图查询引擎，以确定 finding 与 flow source/sink 是否在同一函数
    let engine = crate::analysis::query::CallGraphQueryEngine::from_result(cross_file_result);

    // 建立无 evidence_refs 的 finding 索引（按首行精确匹配，用于快速精确回退）
    let mut index: HashMap<(String, usize), Vec<usize>> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if f.evidence_refs.is_some() {
            continue;
        }
        if f.vuln_type == "UnauthenticatedEndpoint" {
            continue;
        }
        let key = (
            crate::analysis::cross_file::normalize_path(&f.file_path),
            f.line_start,
        );
        index.entry(key).or_default().push(i);
    }

    // 收集要回填的 (target_idx, evidence) 列表，避免在遍历中可变借用 findings
    let mut backfills: Vec<(usize, EvidenceRefs)> = Vec::new();

    // 构建共享中间件证据（所有流复用，避免 N 次重复计算）
    let shared_mw_coverage: Vec<MiddlewareEvidence> = cross_file_result
        .middleware_model
        .express_middleware
        .iter()
        .map(|mw| MiddlewareEvidence {
            middleware_name: mw.handler_name.clone(),
            middleware_file: mw.handler_file.clone(),
            applies_to_route: false,
            route_handler: String::new(),
        })
        .collect();

    // ── Pass 1: 跨文件流 → 同函数 Rule finding ──
    for flow in flows {
        let evidence =
            build_evidence_refs_from_flow(flow, graph_snapshot, &shared_mw_coverage);
        let flow_sink_file = crate::analysis::cross_file::normalize_path(&flow.sink.file_path);
        let flow_source_file = crate::analysis::cross_file::normalize_path(&flow.source.file_path);

        let source_func = engine.query_enclosing_function(&flow.source.file_path, flow.source.line);
        let sink_func = engine.query_enclosing_function(&flow.sink.file_path, flow.sink.line);

        let mut matched_indices: Vec<usize> = Vec::new();

        // 1. sink/source 行精确匹配
        if let Some(idxs) = index.get(&(flow_sink_file.clone(), flow.sink.line)) {
            matched_indices.extend(idxs);
        }
        if let Some(idxs) = index.get(&(flow_source_file.clone(), flow.source.line)) {
            matched_indices.extend(idxs);
        }

        // 2. 按函数范围匹配
        for (i, f) in findings.iter().enumerate() {
            if f.evidence_refs.is_some() {
                continue;
            }
            if f.vuln_type == "UnauthenticatedEndpoint" {
                continue;
            }
            if !is_compatible_vuln_type(&f.vuln_type, &flow.vulnerability_type) {
                continue;
            }

            let f_file = crate::analysis::cross_file::normalize_path(&f.file_path);
            let f_func = engine.query_enclosing_function(&f.file_path, f.line_start);

            let same_func = |a: &crate::analysis::query::FunctionInfo,
                             b: &crate::analysis::query::FunctionInfo| {
                a.id == b.id
                    || (a.name == b.name && a.line == b.line && a.end_line == b.end_line)
            };

            let matches_source = f_file == flow_source_file
                && source_func
                    .as_ref()
                    .zip(f_func.as_ref())
                    .is_some_and(|(s, ff)| same_func(s, ff));
            let matches_sink = f_file == flow_sink_file
                && sink_func
                    .as_ref()
                    .zip(f_func.as_ref())
                    .is_some_and(|(sk, ff)| same_func(sk, ff));

            if matches_source || matches_sink {
                matched_indices.push(i);
            }
        }

        matched_indices.sort_unstable();
        matched_indices.dedup();

        for &idx in &matched_indices {
            backfills.push((idx, evidence.clone()));
        }
    }

    // ── Pass 2: 同函数内已有 evidence_refs 的 finding → 无证据 Rule finding ──
    // AstTaintScanner 等 Stage B finding 已携带精确证据，把它们共享给同一函数内
    // 漏洞类型兼容的规则 finding，可显著提升 evidence_refs 覆盖率。
    let mut evidence_by_func: HashMap<(String, String), Vec<(usize, String)>> = HashMap::new();
    for (i, f) in findings.iter().enumerate() {
        if f.evidence_refs.is_none() {
            continue;
        }
        if f.vuln_type == "UnauthenticatedEndpoint" {
            continue;
        }
        let f_file = crate::analysis::cross_file::normalize_path(&f.file_path);
        if let Some(func) = engine.query_enclosing_function(&f.file_path, f.line_start) {
            evidence_by_func
                .entry((f_file, func.id))
                .or_default()
                .push((i, f.vuln_type.clone()));
        }
    }

    for (i, f) in findings.iter().enumerate() {
        if f.evidence_refs.is_some() {
            continue;
        }
        if f.vuln_type == "UnauthenticatedEndpoint" {
            continue;
        }
        let f_file = crate::analysis::cross_file::normalize_path(&f.file_path);
        let f_func = engine.query_enclosing_function(&f.file_path, f.line_start);
        if let Some(func) = f_func {
            if let Some(sources) = evidence_by_func.get(&(f_file, func.id)) {
                for &(src_idx, ref src_vuln) in sources {
                    if is_compatible_vuln_type_str(&f.vuln_type, src_vuln) {
                        if let Some(ref src_evidence) = findings[src_idx].evidence_refs {
                            backfills.push((i, src_evidence.clone()));
                        }
                    }
                }
            }
        }
    }

    // 应用回填，同一 target 保留 path_steps 最长的证据
    backfills.sort_by_key(|(idx, _)| *idx);
    let mut best_for_idx: HashMap<usize, EvidenceRefs> = HashMap::new();
    for (idx, evidence) in backfills {
        let new_len = evidence
            .source_sink_path
            .as_ref()
            .map(|s| s.path_steps.len())
            .unwrap_or(0);
        let should = match best_for_idx.get(&idx) {
            None => true,
            Some(existing) => {
                let existing_len = existing
                    .source_sink_path
                    .as_ref()
                    .map(|s| s.path_steps.len())
                    .unwrap_or(0);
                new_len > existing_len
            }
        };
        if should {
            best_for_idx.insert(idx, evidence);
        }
    }

    for (idx, evidence) in best_for_idx {
        let f = &mut findings[idx];
        f.evidence_refs = Some(evidence);
        f.confidence = Some(f.confidence.unwrap_or(0.5).max(0.85));
    }
}

/// 为每个 finding 填充 enclosing_function 和 enclosing_function_line。
///
/// 利用调用图引擎查询包含 finding 命中行的最内层函数。
/// LLM 收到 finding 后可直接用函数名调 `query_callers`/`query_callees` 开始调查，
/// 无需先调 `enclosing_function_at_line` 查函数名。
fn enrich_findings_with_enclosing_function(
    findings: &mut [Finding],
    engine: &crate::analysis::query::CallGraphQueryEngine,
) {
    for f in findings.iter_mut() {
        if f.enclosing_function.is_some() {
            continue;
        }
        if let Some(func) = engine.query_enclosing_function(&f.file_path, f.line_start) {
            f.enclosing_function = Some(func.name);
            f.enclosing_function_line = Some(func.line);
        }
    }
}

/// 函数行号区间（仅保留填充 enclosing_function 所需的最小字段）
struct FunctionRange {
    name: String,
    start_line: usize,
    end_line: usize,
}

/// 从 Stage B 已解析的 AST 符号构建每文件函数区间表（按 start_line 升序）。
///
/// 只保留函数/方法符号的行号范围与名字，丢弃重量级的 Symbol 本体，
/// 供扫描收尾时按 (file_path, line) 做 O(log n) 的包围函数查询。
fn build_file_function_ranges(
    parsed_ast: &HashMap<String, (Vec<crate::ast::Symbol>, Vec<crate::ast::CallInfo>)>,
) -> HashMap<String, Vec<FunctionRange>> {
    parsed_ast
        .iter()
        .filter_map(|(fp, (symbols, _))| {
            let mut ranges: Vec<FunctionRange> = symbols
                .iter()
                .filter(|s| {
                    matches!(
                        s.kind,
                        crate::ast::SymbolKind::Function | crate::ast::SymbolKind::Method
                    )
                })
                .map(|s| FunctionRange {
                    name: s.name.clone(),
                    start_line: s.start_line as usize,
                    end_line: s.end_line as usize,
                })
                .collect();
            if ranges.is_empty() {
                return None;
            }
            ranges.sort_by_key(|r| r.start_line);
            Some((fp.clone(), ranges))
        })
        .collect()
}

/// 用 Stage B 函数区间表为 finding 填充 enclosing_function。
///
/// 与 `enrich_findings_with_enclosing_function`（调用图引擎路径）互补：
/// 已由调用图填充的 finding 直接跳过；调用图未覆盖的（如纯 --taint 模式下
/// 的 RuleScanner/AttackSurfaceMapper finding）按文件+行号匹配最内层包围函数。
/// 无 Stage B 符号数据的文件保持 None，不为此新建解析管线。
fn enrich_findings_with_enclosing_function_from_symbols(
    findings: &mut [Finding],
    file_function_ranges: &HashMap<String, Vec<FunctionRange>>,
) {
    if file_function_ranges.is_empty() {
        return;
    }
    for f in findings.iter_mut() {
        if f.enclosing_function.is_some() {
            continue;
        }
        let Some(ranges) = file_function_ranges.get(&f.file_path) else {
            continue;
        };
        // 二分定位 start_line <= line 的候选前缀，再从中取行号范围最小者，
        // 即最内层包围函数（与 CallGraphQueryEngine::query_enclosing_function 语义一致）。
        // 候选前缀内的线性扫描以嵌套深度为上界，整体为 O(log n + 嵌套深度)。
        let idx = ranges.partition_point(|r| r.start_line <= f.line_start);
        if let Some(best) = ranges[..idx]
            .iter()
            .filter(|r| r.end_line >= f.line_start)
            .min_by_key(|r| r.end_line - r.start_line)
        {
            f.enclosing_function = Some(best.name.clone());
            f.enclosing_function_line = Some(best.start_line);
        }
    }
}

/// 判断两个漏洞类型字符串是否兼容（都归一化为 CWE 后比较）。
fn is_compatible_vuln_type_str(a: &str, b: &str) -> bool {
    if let (Some(ca), Some(cb)) = (normalize_vuln_type_to_cwe(a), normalize_vuln_type_to_cwe(b)) {
        return ca == cb;
    }
    let a = a.to_lowercase();
    let b = b.to_lowercase();
    a.contains(&b) || b.contains(&a)
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
                | "php"
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
///
/// 选择一个“最佳” finding 作为代表（按严重等级、置信度排序），并沿用它的
/// vuln_type / description / trail / snippet 等全部字段，避免之前按字符串长度
/// 混拼不同 finding 的字段导致 vuln_type 与 description 不一致的问题。
fn merge_findings_at_indices(findings: &[Finding], indices: &[usize]) -> Finding {
    let mut detectors = Vec::new();
    let mut confidences = Vec::new();

    // 先收集所有引擎和置信度
    for &idx in indices {
        let f = &findings[idx];
        detectors.push(f.detector.clone());
        confidences.push(f.confidence.unwrap_or(0.5));
    }

    // 选择最佳代表：严重等级 > 置信度 > 漏洞类型更具体（非 CWE 通配）
    let mut best_idx = indices[0];
    for &idx in &indices[1..] {
        let best = &findings[best_idx];
        let current = &findings[idx];
        let current_rank = severity_rank(&current.severity);
        let best_rank = severity_rank(&best.severity);
        if current_rank > best_rank
            || (current_rank == best_rank
                && current.confidence.unwrap_or(0.5) > best.confidence.unwrap_or(0.5))
            || (current_rank == best_rank
                && (current.confidence.unwrap_or(0.5) - best.confidence.unwrap_or(0.5)).abs()
                    < f32::EPSILON
                && !current.vuln_type.starts_with("CWE-")
                && best.vuln_type.starts_with("CWE-"))
        {
            best_idx = idx;
        }
    }

    let fused = fuse_confidences(&confidences);

    detectors.sort();
    detectors.dedup();

    let mut best = findings[best_idx].clone();

    // 多引擎 corroboration 标注：保留原描述并追加引擎信息
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
        best.description = format!(
            "{}\n[Corroborated by {} engine(s): {}]",
            best.description,
            unique_engines.len(),
            unique_engines
                .iter()
                .map(|s| **s)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // 合并 barriers（去重）
    let best_barriers: Vec<String> = indices
        .iter()
        .flat_map(|&idx| findings[idx].barriers.clone().unwrap_or_default())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    best.detector = detectors.join("+");
    best.confidence = Some(fused);
    best.corroboration_count = Some(indices.len());
    best.barriers = if best_barriers.is_empty() {
        None
    } else {
        Some(best_barriers)
    };

    // 保留最佳 evidence_refs：若最佳自身没有，但同组其他 finding 有，则合并补充
    if best.evidence_refs.is_none() {
        if let Some(first_with_evidence) = indices
            .iter()
            .map(|&idx| &findings[idx].evidence_refs)
            .find(|e| e.is_some())
        {
            best.evidence_refs = first_with_evidence.clone();
        }
    }
    if let Some(ref mut evidence) = best.evidence_refs {
        // 合并同组所有 sanitizer / middleware 证据（按文件+行去重）
        let mut seen_sanitizers = std::collections::HashSet::new();
        let mut seen_middleware = std::collections::HashSet::new();
        for &idx in indices {
            if let Some(ref other) = findings[idx].evidence_refs {
                for s in &other.sanitizer_chain {
                    let key = (&s.file, s.line, &s.function);
                    if seen_sanitizers.insert(key) {
                        evidence.sanitizer_chain.push(s.clone());
                    }
                }
                for m in &other.middleware_coverage {
                    let key = (&m.middleware_file, &m.middleware_name, &m.route_handler);
                    if seen_middleware.insert(key) {
                        evidence.middleware_coverage.push(m.clone());
                    }
                }
            }
        }
    }

    best
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
                | "php"
        )
    } else {
        false
    }
}

/// 根据漏洞类型返回 sink 执行上下文描述，帮助 agent 快速判断漏洞真实性。
fn sink_context_hint(vuln_type: &str) -> &'static str {
    match vuln_type {
        "SqlInjection" => "Sink executes SQL against a database; verify whether user input is concatenated into the query",
        "CommandInjection" => "Sink executes OS commands; verify whether user input reaches Runtime.exec/ProcessBuilder",
        "ServerSideRequestForgery" => "Sink makes outbound network requests; verify whether the URL is user-controlled",
        "PathTraversal" => "Sink performs file system operations; verify whether the path is user-controlled",
        "Xss" | "CrossSiteScripting" => "Sink renders content in HTML/JS context; verify whether output is encoded",
        "InsecureDeserialization" => "Sink deserializes untrusted data; verify whether input is validated",
        "WeakCrypto" | "WeakHash" => "Sink uses a weak cryptographic algorithm; verify algorithm strength",
        "HardcodedSecret" => "Sink exposes hardcoded credentials; verify whether the value is truly sensitive",
        "CodeInjection" => "Sink evaluates/executes dynamic code; verify whether input reaches eval/Function",
        "OpenRedirect" => "Sink performs HTTP redirect; verify whether the target URL is user-controlled",
        "Xxe" => "Sink parses XML with external entities enabled",
        _ => "Sink performs a security-sensitive operation; verify data flow and validation",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_file_role_vendor() {
        // 目录标识
        assert_eq!(classify_file_role("app/node_modules/jquery/index.js"), "vendor");
        assert_eq!(classify_file_role("web/static/plugins/a.js"), "vendor");
        assert_eq!(classify_file_role("src/vendor/lib.py"), "vendor");
        // 压缩/打包产物文件名
        assert_eq!(classify_file_role("web/js/jquery-1.10.2.min.js"), "vendor");
        assert_eq!(classify_file_role("web/js/bootstrap.min.js"), "vendor");
        assert_eq!(classify_file_role("dist/app.bundle.js"), "vendor");
        // 知名第三方库文件名前缀
        assert_eq!(classify_file_role("web/js/jquery.js"), "vendor");
        assert_eq!(classify_file_role("web/js/bootstrap.js"), "vendor");
        // 业务文件不受影响
        assert_eq!(classify_file_role("src/main.py"), "production");
        assert_eq!(classify_file_role("web/js/serverstatus.js"), "production");
    }

    #[test]
    fn test_is_minified_content() {
        // 超长单行 → minified
        let minified = format!("var a=1;\n{}", "x".repeat(2000));
        assert!(is_minified_content(&minified));
        // 正常源码
        let normal = "function hello() {\n  return 42;\n}\n".repeat(100);
        assert!(!is_minified_content(&normal));
        // 小文件不判定
        assert!(!is_minified_content("var a=1;"));
    }

    #[test]
    fn test_classify_file_role_with_content_minified() {
        // 未按 .min.js 命名但内容是压缩代码 → vendor（google-map.js 场景）
        let minified = format!("(function(){{'use strict';{}}})();", "var a=1;".repeat(200));
        assert_eq!(
            classify_file_role_with_content("web/js/google-map.js", &minified),
            "vendor"
        );
        // 正常业务 JS → production
        let normal = "function update() {\n  fetch('/json/stats.json');\n}\n".repeat(50);
        assert_eq!(
            classify_file_role_with_content("web/js/serverstatus.js", &normal),
            "production"
        );
        // 路径已是 test 的保持 test，不被内容覆盖
        assert_eq!(
            classify_file_role_with_content("tests/min.test.js", &minified),
            "test"
        );
    }

    #[test]
    fn test_normalize_vuln_type_to_cwe_direct() {
        assert_eq!(
            normalize_vuln_type_to_cwe("CWE-22"),
            Some("CWE-22".to_string())
        );
        assert_eq!(
            normalize_vuln_type_to_cwe("cwe-89"),
            Some("CWE-89".to_string())
        );
    }

    #[test]
    fn test_normalize_vuln_type_to_cwe_by_name() {
        assert_eq!(
            normalize_vuln_type_to_cwe("PathTraversal"),
            Some("CWE-22".to_string())
        );
        assert_eq!(
            normalize_vuln_type_to_cwe("SqlInjection"),
            Some("CWE-89".to_string())
        );
        assert_eq!(
            normalize_vuln_type_to_cwe("CrossSiteScripting"),
            Some("CWE-79".to_string())
        );
        assert_eq!(
            normalize_vuln_type_to_cwe("InsecureDeserialization"),
            Some("CWE-502".to_string())
        );
    }

    #[test]
    fn test_normalize_vuln_type_to_cwe_from_detector() {
        assert_eq!(
            normalize_vuln_type_to_cwe("RegexRule: path-traversal"),
            Some("CWE-22".to_string())
        );
        assert_eq!(
            normalize_vuln_type_to_cwe("RegexRule: sql-injection"),
            Some("CWE-89".to_string())
        );
    }

    #[test]
    fn test_is_compatible_vuln_type_str_cwe_and_name() {
        assert!(is_compatible_vuln_type_str("CWE-22", "PathTraversal"));
        assert!(is_compatible_vuln_type_str("CWE-89", "SqlInjection"));
        assert!(!is_compatible_vuln_type_str("CWE-22", "SqlInjection"));
    }

    #[test]
    fn test_is_compatible_vuln_type_str_unknown() {
        // 无法归一化时退化为子串包含
        assert!(is_compatible_vuln_type_str("SomeVuln", "SomeVuln"));
        assert!(!is_compatible_vuln_type_str("Alpha", "Beta"));
    }

    // ── enclosing_function 符号填充 ─────────────────────────

    /// 构造带函数区间的测试符号表：
    /// - outer 函数 [10, 100]，内层嵌套 inner 函数 [40, 60]
    /// - 同级兄弟函数 sibling [70, 80]
    fn make_test_parsed_ast(
    ) -> HashMap<String, (Vec<crate::ast::Symbol>, Vec<crate::ast::CallInfo>)> {
        let fp = "src/Login.java".to_string();
        let mk = |name: &str, kind: crate::ast::SymbolKind, start: u32, end: u32| {
            crate::ast::Symbol::new(name.to_string(), kind, fp.clone(), start, String::new())
                .with_end_line(end)
        };
        let symbols = vec![
            mk("LoginController", crate::ast::SymbolKind::Class, 1, 120),
            mk("outer", crate::ast::SymbolKind::Method, 10, 100),
            mk("inner", crate::ast::SymbolKind::Function, 40, 60),
            mk("sibling", crate::ast::SymbolKind::Method, 70, 80),
        ];
        let mut map = HashMap::new();
        map.insert(fp, (symbols, Vec::new()));
        map
    }

    fn make_finding(file_path: &str, line: usize) -> Finding {
        Finding {
            file_path: file_path.to_string(),
            line_start: line,
            ..Default::default()
        }
    }

    #[test]
    fn test_enrich_from_symbols_fills_enclosing_function() {
        let parsed = make_test_parsed_ast();
        let ranges = build_file_function_ranges(&parsed);

        let mut findings = vec![
            make_finding("src/Login.java", 20), // 仅在 outer 内
            make_finding("src/Login.java", 45), // 在 inner 内（最内层优先）
            make_finding("src/Login.java", 75), // 在 sibling 内
        ];
        enrich_findings_with_enclosing_function_from_symbols(&mut findings, &ranges);

        assert_eq!(findings[0].enclosing_function.as_deref(), Some("outer"));
        assert_eq!(findings[0].enclosing_function_line, Some(10));
        // 嵌套场景应取最内层（范围最小）的函数，而不是外层 outer
        assert_eq!(findings[1].enclosing_function.as_deref(), Some("inner"));
        assert_eq!(findings[1].enclosing_function_line, Some(40));
        assert_eq!(findings[2].enclosing_function.as_deref(), Some("sibling"));
        assert_eq!(findings[2].enclosing_function_line, Some(70));
    }

    #[test]
    fn test_enrich_from_symbols_keeps_none_outside_functions() {
        let parsed = make_test_parsed_ast();
        let ranges = build_file_function_ranges(&parsed);

        let mut findings = vec![
            make_finding("src/Login.java", 5),   // 类体内、所有函数外
            make_finding("src/Login.java", 110), // 最后一个函数之后
            make_finding("src/Other.java", 20),  // 无符号数据的文件
        ];
        enrich_findings_with_enclosing_function_from_symbols(&mut findings, &ranges);

        assert!(findings[0].enclosing_function.is_none());
        assert!(findings[1].enclosing_function.is_none());
        assert!(findings[2].enclosing_function.is_none());
    }

    #[test]
    fn test_enrich_from_symbols_skips_already_filled() {
        let parsed = make_test_parsed_ast();
        let ranges = build_file_function_ranges(&parsed);

        // 模拟跨文件调用图引擎已填充的 finding，符号填充不得覆盖
        let mut filled = make_finding("src/Login.java", 45);
        filled.enclosing_function = Some("graph_func".to_string());
        filled.enclosing_function_line = Some(1);
        let mut findings = vec![filled];
        enrich_findings_with_enclosing_function_from_symbols(&mut findings, &ranges);

        assert_eq!(
            findings[0].enclosing_function.as_deref(),
            Some("graph_func")
        );
        assert_eq!(findings[0].enclosing_function_line, Some(1));
    }

    #[test]
    fn test_enrich_from_symbols_empty_table_is_noop() {
        let ranges: HashMap<String, Vec<FunctionRange>> = HashMap::new();
        let mut findings = vec![make_finding("src/Login.java", 20)];
        enrich_findings_with_enclosing_function_from_symbols(&mut findings, &ranges);
        assert!(findings[0].enclosing_function.is_none());
    }
}
