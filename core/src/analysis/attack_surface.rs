// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 攻击面映射引擎
//!
//! 识别项目中的入口点（HTTP endpoint、CLI handler 等），
//! 构建信任边界，计算风险评分，用于优先化安全分析。

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// ── 预编译正则（全局缓存，避免每次调用重新编译）──────────

static RE_SERVER_ACTION_FUNC: OnceLock<Regex> = OnceLock::new();
fn server_action_func_re() -> &'static Regex {
    RE_SERVER_ACTION_FUNC.get_or_init(|| Regex::new(r"(?:export\s+(?:async\s+)?function\s+(\w+)\s*\(|export\s+const\s+(\w+)\s*=\s*(?:async\s*)?\()").unwrap())
}

// 数据源检测
static RE_DS_FORMDATA: OnceLock<Regex> = OnceLock::new();
static RE_DS_COOKIES: OnceLock<Regex> = OnceLock::new();
static RE_DS_HEADERS: OnceLock<Regex> = OnceLock::new();
static RE_DS_SEARCH_PARAMS: OnceLock<Regex> = OnceLock::new();
static RE_DS_REQUEST: OnceLock<Regex> = OnceLock::new();
static RE_DS_REQ: OnceLock<Regex> = OnceLock::new();

fn ds_formdata_re() -> &'static Regex { RE_DS_FORMDATA.get_or_init(|| Regex::new(r"formData\.(get|getAll|entries|values|has)").unwrap()) }
fn ds_cookies_re() -> &'static Regex { RE_DS_COOKIES.get_or_init(|| Regex::new(r"cookies\(\)\.(get|getAll)").unwrap()) }
fn ds_headers_re() -> &'static Regex { RE_DS_HEADERS.get_or_init(|| Regex::new(r"headers\(\)\.(get)").unwrap()) }
fn ds_search_params_re() -> &'static Regex { RE_DS_SEARCH_PARAMS.get_or_init(|| Regex::new(r"searchParams\.(get|getAll)").unwrap()) }
fn ds_request_re() -> &'static Regex { RE_DS_REQUEST.get_or_init(|| Regex::new(r"request\.(json|text|formData)\s*\(").unwrap()) }
fn ds_req_re() -> &'static Regex { RE_DS_REQ.get_or_init(|| Regex::new(r"req\.(body|query|params)").unwrap()) }

// 上下文分析
static RE_SANITIZER: OnceLock<Regex> = OnceLock::new();
static RE_VALIDATION: OnceLock<Regex> = OnceLock::new();
static RE_DESERIALIZATION: OnceLock<Regex> = OnceLock::new();
static RE_PRIVILEGED_OP: OnceLock<Regex> = OnceLock::new();

fn sanitizer_re() -> &'static Regex { RE_SANITIZER.get_or_init(|| Regex::new(r"sanitize|escape|encode|DOMPurify|bleach|htmlspecialchars").unwrap()) }
fn validation_re() -> &'static Regex { RE_VALIDATION.get_or_init(|| Regex::new(r"(?i)(?:zod|joi|yup|ajv|\.safeParse|\.parse\(|validate\(|Schema|\.schema)").unwrap()) }
fn deserialization_re() -> &'static Regex { RE_DESERIALIZATION.get_or_init(|| Regex::new(r"(?:JSON\.parse|parseModel|resolveModel|deserialize|unserialize|objectMapper\.readValue|pickle\.loads)").unwrap()) }
fn privileged_op_re() -> &'static Regex { RE_PRIVILEGED_OP.get_or_init(|| Regex::new(r"(?:fs\.|writeFile|readFile|\.execute\s*\(|\.query\s*\(|exec\s*\(|eval\s*\(|system\s*\(|child_process|subprocess|DB::|database\.)").unwrap()) }

// 信任边界
static RE_TB_FORMDATA: OnceLock<Regex> = OnceLock::new();
static RE_TB_REQUEST_BODY: OnceLock<Regex> = OnceLock::new();
static RE_TB_SEARCH_PARAMS: OnceLock<Regex> = OnceLock::new();
static RE_TB_COOKIES: OnceLock<Regex> = OnceLock::new();
static RE_TB_HEADERS: OnceLock<Regex> = OnceLock::new();

fn tb_formdata_re() -> &'static Regex { RE_TB_FORMDATA.get_or_init(|| Regex::new(r"formData\.(get|getAll)\s*\(").unwrap()) }
fn tb_request_body_re() -> &'static Regex { RE_TB_REQUEST_BODY.get_or_init(|| Regex::new(r"request\.(json|text|formData)\s*\(").unwrap()) }
fn tb_search_params_re() -> &'static Regex { RE_TB_SEARCH_PARAMS.get_or_init(|| Regex::new(r"searchParams\.(get|getAll)\s*\(").unwrap()) }
fn tb_cookies_re() -> &'static Regex { RE_TB_COOKIES.get_or_init(|| Regex::new(r"cookies\(\)\.(get|getAll)\s*\(").unwrap()) }
fn tb_headers_re() -> &'static Regex { RE_TB_HEADERS.get_or_init(|| Regex::new(r"headers\(\)\.(get)\s*\(").unwrap()) }

/// 入口点类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntryType {
    /// HTTP API 端点（Spring @RequestMapping, Express app.get()）
    HttpEndpoint,
    /// CLI 入口（main(), argparse）
    CliHandler,
    /// 消息消费者（Kafka, RabbitMQ）
    MessageConsumer,
    /// 定时任务（@Scheduled, cron）
    ScheduledTask,
    /// 文件上传处理
    FileUpload,
    /// WebSocket 端点
    WebSocket,
    /// Next.js Server Action（'use server' 导出函数）
    ServerAction,
    /// Next.js App Router Route Handler（route.ts 导出函数）
    RscEndpoint,
}

/// 入口点上下文分析
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EntryContext {
    /// 数据源类型（如 "formData", "searchParams"）
    pub data_sources: Vec<String>,
    /// 是否检测到净化器
    pub has_sanitization: bool,
    /// 检测到的净化器函数名
    pub sanitizers: Vec<String>,
    /// 是否有输入校验（zod/joi/yup/ajv）
    pub has_input_validation: bool,
    /// 数据是否到达反序列化操作
    pub reaches_deserialization: bool,
    /// 数据是否到达特权操作（文件IO、数据库、命令执行）
    pub reaches_privileged_op: bool,
    /// 风险因子标签
    pub risk_factors: Vec<String>,
}

/// 入口点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    /// 文件路径
    pub file_path: String,
    /// 行号
    pub line: usize,
    /// 入口类型
    pub entry_type: EntryType,
    /// HTTP 路由（仅 HTTP 端点）
    pub route: Option<String>,
    /// HTTP 方法（GET/POST/PUT/DELETE）
    pub http_method: Option<String>,
    /// 是否需要认证
    pub auth_required: bool,
    /// 认证方式描述
    pub auth_mechanism: Option<String>,
    /// 风险评分 (0.0-1.0)
    pub risk_score: f32,
    /// 函数/方法名
    pub function_name: Option<String>,
    /// 上下文分析结果
    #[serde(default)]
    pub context: EntryContext,
}

/// 信任边界
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustBoundary {
    /// 文件路径
    pub file_path: String,
    /// 行号
    pub line: usize,
    /// 边界描述（如 "外部用户输入进入系统"）
    pub description: String,
    /// 输入来源
    pub source: String,
}

/// 攻击面映射结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    /// 识别的入口点
    pub entry_points: Vec<EntryPoint>,
    /// 信任边界
    pub trust_boundaries: Vec<TrustBoundary>,
    /// 高风险文件（包含高危入口点的文件）
    pub high_risk_files: Vec<String>,
    /// 统计
    pub stats: AttackSurfaceStats,
}

/// 映射统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackSurfaceStats {
    /// 扫描文件数
    pub files_scanned: usize,
    /// 入口点总数
    pub total_entry_points: usize,
    /// 未认证入口数
    pub unauthenticated_count: usize,
    /// 高风险文件数
    pub high_risk_file_count: usize,
    /// 检测到的框架
    #[serde(default)]
    pub detected_frameworks: Vec<String>,
}

/// 攻击面映射器
pub struct AttackSurfaceMapper;

impl AttackSurfaceMapper {
    /// 映射项目的攻击面
    pub fn map_project(project_path: &Path) -> AttackSurface {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();
        let mut files_scanned = 0;
        let mut detected_frameworks: HashSet<String> = HashSet::new();

        // 遍历项目文件
        if let Ok(entries) = walk_project(project_path) {
            for file_path in entries {
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    files_scanned += 1;

                    let ext = file_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");

                    let file_str = file_path.to_string_lossy().to_string();

                    match ext {
                        "java" => {
                            let (eps, tbs) = Self::analyze_java_file(&file_str, &content);
                            let has_endpoints = !eps.is_empty();
                            entry_points.extend(eps);
                            trust_boundaries.extend(tbs);
                            if has_endpoints {
                                detected_frameworks.insert("Spring".to_string());
                            }
                        }
                        "js" | "ts" | "jsx" | "tsx" => {
                            // 先检测 Next.js 模式
                            if Self::is_nextjs_file(&file_str, &content) {
                                let (eps, tbs) = Self::analyze_nextjs_file(&file_str, &content);
                                entry_points.extend(eps);
                                trust_boundaries.extend(tbs);
                                detected_frameworks.insert("Next.js".to_string());
                            } else {
                                let (eps, tbs) = Self::analyze_js_file(&file_str, &content);
                                let has_endpoints = !eps.is_empty();
                                entry_points.extend(eps);
                                trust_boundaries.extend(tbs);
                                if has_endpoints {
                                    detected_frameworks.insert("Express".to_string());
                                }
                            }
                        }
                        "py" => {
                            let (eps, tbs) = Self::analyze_python_file(&file_str, &content);
                            entry_points.extend(eps);
                            trust_boundaries.extend(tbs);
                            if content.contains("flask") || content.contains("Flask") {
                                detected_frameworks.insert("Flask".to_string());
                            }
                            if content.contains("django") || content.contains("Django") {
                                detected_frameworks.insert("Django".to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        // 计算风险评分
        for ep in &mut entry_points {
            ep.risk_score = Self::compute_risk_score(ep);
        }

        // 识别高风险文件
        let high_risk_files = Self::identify_high_risk_files(&entry_points);

        let unauthenticated_count = entry_points.iter().filter(|ep| !ep.auth_required).count();
        let total_entry_points = entry_points.len();
        let high_risk_file_count = high_risk_files.len();

        let mut frameworks: Vec<String> = detected_frameworks.into_iter().collect();
        frameworks.sort();

        AttackSurface {
            entry_points,
            trust_boundaries,
            high_risk_files,
            stats: AttackSurfaceStats {
                files_scanned,
                total_entry_points,
                unauthenticated_count,
                high_risk_file_count,
                detected_frameworks: frameworks,
            },
        }
    }

    /// 单文件攻击面检测（用于合并扫描，避免二次文件遍历）
    pub fn map_file(file_path: &str, content: &str) -> Vec<EntryPoint> {
        let path = std::path::Path::new(file_path);
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let mut entry_points = Vec::new();

        match ext {
            "java" => {
                let (eps, _) = Self::analyze_java_file(file_path, content);
                entry_points.extend(eps);
            }
            "js" | "ts" | "jsx" | "tsx" => {
                if Self::is_nextjs_file(file_path, content) {
                    let (eps, _) = Self::analyze_nextjs_file(file_path, content);
                    entry_points.extend(eps);
                } else {
                    let (eps, _) = Self::analyze_js_file(file_path, content);
                    entry_points.extend(eps);
                }
            }
            "py" => {
                let (eps, _) = Self::analyze_python_file(file_path, content);
                entry_points.extend(eps);
            }
            _ => {}
        }

        for ep in &mut entry_points {
            ep.risk_score = Self::compute_risk_score(ep);
        }

        entry_points
    }

    /// 分析 Java 文件中的入口点
    fn analyze_java_file(file_path: &str, content: &str) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // Spring 注解检测
        let spring_annotations = [
            ("@RequestMapping", None),
            ("@GetMapping", Some("GET")),
            ("@PostMapping", Some("POST")),
            ("@PutMapping", Some("PUT")),
            ("@DeleteMapping", Some("DELETE")),
            ("@PatchMapping", Some("PATCH")),
        ];

        for (annotation, method) in &spring_annotations {
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(annotation) {
                    // 提取路由
                    let route = Self::extract_spring_route(line);

                    // 检查认证
                    let context = Self::get_context_block(content, line_num, 20);
                    let auth_required = Self::check_java_auth(&context);

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::HttpEndpoint,
                        route: route.clone(),
                        http_method: method.map(|m| m.to_string()),
                        auth_required,
                        auth_mechanism: if auth_required {
                            Some("Spring Security".to_string())
                        } else {
                            None
                        },
                        risk_score: 0.0,
                        function_name: None,
                        context: EntryContext::default(),
                    });
                }
            }
        }

        // @Scheduled 定时任务
        for (line_num, line) in content.lines().enumerate() {
            if line.contains("@Scheduled") || line.contains("@Schedules") {
                entry_points.push(EntryPoint {
                    file_path: file_path.to_string(),
                    line: line_num + 1,
                    entry_type: EntryType::ScheduledTask,
                    route: None,
                    http_method: None,
                    auth_required: true,
                    auth_mechanism: None,
                    risk_score: 0.0,
                    function_name: None,
                    context: EntryContext::default(),
                });
            }
        }

        // 信任边界：外部输入点
        let input_patterns = [
            ("@RequestParam", "HTTP request parameter"),
            ("@PathVariable", "URL path variable"),
            ("@RequestBody", "HTTP request body"),
            ("@RequestHeader", "HTTP request header"),
            ("MultipartFile", "File upload"),
        ];
        for (pattern, desc) in &input_patterns {
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    trust_boundaries.push(TrustBoundary {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        description: desc.to_string(),
                        source: pattern.to_string(),
                    });
                }
            }
        }

        (entry_points, trust_boundaries)
    }

    /// 分析 JS/TS 文件中的入口点
    fn analyze_js_file(file_path: &str, content: &str) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // Express 路由检测
        let express_patterns = [
            ("app.get(", "GET"),
            ("app.post(", "POST"),
            ("app.put(", "PUT"),
            ("app.delete(", "DELETE"),
            ("app.patch(", "PATCH"),
            ("router.get(", "GET"),
            ("router.post(", "POST"),
            ("router.put(", "PUT"),
            ("router.delete(", "DELETE"),
            ("router.patch(", "PATCH"),
        ];

        for (pattern, method) in &express_patterns {
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    let route = Self::extract_express_route(line);
                    let context = Self::get_context_block(content, line_num, 10);
                    let auth_required = context.contains("auth") || context.contains("jwt")
                        || context.contains("token") || context.contains("passport");

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::HttpEndpoint,
                        route,
                        http_method: Some(method.to_string()),
                        auth_required,
                        auth_mechanism: if auth_required {
                            Some("Express middleware".to_string())
                        } else {
                            None
                        },
                        risk_score: 0.0,
                        function_name: None,
                        context: EntryContext::default(),
                    });
                }
            }
        }

        // 信任边界
        let input_patterns = [
            ("req.body", "HTTP request body"),
            ("req.query", "URL query parameters"),
            ("req.params", "URL path parameters"),
            ("req.headers", "HTTP request headers"),
            ("req.cookies", "HTTP cookies"),
            ("req.file", "File upload"),
        ];
        for (pattern, desc) in &input_patterns {
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    trust_boundaries.push(TrustBoundary {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        description: desc.to_string(),
                        source: pattern.to_string(),
                    });
                }
            }
        }

        (entry_points, trust_boundaries)
    }

    /// 分析 Python 文件中的入口点
    fn analyze_python_file(file_path: &str, content: &str) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // Flask/Django 路由
        let route_patterns = [
            ("@app.route(", "Flask"),
            ("@bp.route(", "Flask Blueprint"),
            ("path(", "Django URL"),
            ("re_path(", "Django URL"),
            ("@api_view(", "Django REST"),
        ];

        for (pattern, framework) in &route_patterns {
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    let route = Self::extract_python_route(line);
                    let context = Self::get_context_block(content, line_num, 10);
                    let auth_required = context.contains("@login_required")
                        || context.contains("@permission_required")
                        || context.contains("is_authenticated")
                        || context.contains("login_required");

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::HttpEndpoint,
                        route,
                        http_method: None,
                        auth_required,
                        auth_mechanism: if auth_required {
                            Some(framework.to_string())
                        } else {
                            None
                        },
                        risk_score: 0.0,
                        function_name: None,
                        context: EntryContext::default(),
                    });
                }
            }
        }

        // 信任边界
        let input_patterns = [
            ("request.GET", "HTTP GET parameters"),
            ("request.POST", "HTTP POST data"),
            ("request.body", "HTTP request body"),
            ("request.FILES", "File upload"),
            ("request.META", "HTTP headers"),
            ("request.data", "DRF request data"),
        ];
        for (pattern, desc) in &input_patterns {
            for (line_num, line) in content.lines().enumerate() {
                if line.contains(pattern) {
                    trust_boundaries.push(TrustBoundary {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        description: desc.to_string(),
                        source: pattern.to_string(),
                    });
                }
            }
        }

        (entry_points, trust_boundaries)
    }

    /// 计算入口点风险评分（增强版，使用 EntryContext）
    fn compute_risk_score(ep: &mut EntryPoint) -> f32 {
        let mut score: f32 = 0.2;

        // 未认证
        if !ep.auth_required {
            score += 0.35;
            ep.context.risk_factors.push("no_auth".to_string());
        }

        // 外部可达入口点
        if matches!(ep.entry_type, EntryType::HttpEndpoint | EntryType::ServerAction | EntryType::RscEndpoint) {
            score += 0.15;
        }

        // POST/PUT/DELETE/PATCH
        if let Some(ref method) = ep.http_method {
            if matches!(method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
                score += 0.1;
            }
        }

        // 无输入校验
        if !ep.context.has_input_validation && matches!(ep.entry_type,
            EntryType::HttpEndpoint | EntryType::ServerAction | EntryType::RscEndpoint) {
            score += 0.15;
            ep.context.risk_factors.push("no_input_validation".to_string());
        }

        // 数据到达反序列化
        if ep.context.reaches_deserialization {
            score += 0.15;
            ep.context.risk_factors.push("reaches_deserialization".to_string());
        }

        // 数据到达特权操作
        if ep.context.reaches_privileged_op {
            score += 0.1;
            ep.context.risk_factors.push("reaches_privileged_op".to_string());
        }

        // 定时任务 → 内部，降低
        if ep.entry_type == EntryType::ScheduledTask {
            score -= 0.2;
        }

        score.clamp(0.0, 1.0)
    }

    /// 识别高风险文件
    fn identify_high_risk_files(entry_points: &[EntryPoint]) -> Vec<String> {
        let mut file_scores: HashMap<String, f32> = HashMap::new();
        for ep in entry_points {
            let entry = file_scores.entry(ep.file_path.clone()).or_insert(0.0_f32);
            *entry = entry.max(ep.risk_score);
        }

        let mut high_risk: Vec<String> = file_scores
            .iter()
            .filter(|(_, score)| **score >= 0.6)
            .map(|(f, _)| f.clone())
            .collect();
        high_risk.sort();
        high_risk.dedup();
        high_risk
    }

    /// 检测文件是否为 Next.js 相关文件
    fn is_nextjs_file(file_path: &str, content: &str) -> bool {
        // 'use server' 指令
        let has_use_server = content.lines().take(5)
            .any(|l| l.trim() == "'use server'" || l.trim() == "\"use server\"");
        if has_use_server {
            return true;
        }

        // NextRequest / NextResponse 类型引用
        if content.contains("NextRequest") || content.contains("NextResponse") {
            return true;
        }

        // App Router 路径: app/ 目录下的 route.ts/js 或 page.tsx/jsx
        let normalized = file_path.replace('\\', "/");
        let is_app_route = normalized.contains("/app/") &&
            (normalized.ends_with("/route.ts") || normalized.ends_with("/route.js"));
        let is_app_page = normalized.contains("/app/") &&
            (normalized.ends_with("/page.tsx") || normalized.ends_with("/page.jsx") ||
             normalized.ends_with("/page.ts") || normalized.ends_with("/page.js"));

        is_app_route || is_app_page
    }

    /// 分析 Next.js 文件中的入口点
    fn analyze_nextjs_file(file_path: &str, content: &str) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // Server Actions: 'use server' 指令文件
        let has_use_server = content.lines().take(5)
            .any(|l| l.trim() == "'use server'" || l.trim() == "\"use server\"");

        if has_use_server {
            let (eps, tbs) = Self::detect_server_actions(file_path, content);
            entry_points.extend(eps);
            trust_boundaries.extend(tbs);
        }

        // Route Handlers: app/ 目录下的 route.ts/js
        let normalized = file_path.replace('\\', "/");
        let is_route_handler = normalized.contains("/app/") &&
            (normalized.ends_with("/route.ts") || normalized.ends_with("/route.js"));

        if is_route_handler {
            let route = Self::extract_nextjs_route(&normalized);
            let (eps, tbs) = Self::detect_route_handlers(file_path, content, route.as_deref());
            entry_points.extend(eps);
            trust_boundaries.extend(tbs);
        }

        (entry_points, trust_boundaries)
    }

    /// 检测 Server Action 函数
    fn detect_server_actions(file_path: &str, content: &str) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // 匹配 export async function X( 和 export function X(
        let func_re = server_action_func_re();

        for cap in func_re.captures_iter(content) {
            let func_name = cap.get(1)
                .or_else(|| cap.get(2))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let line_num = content[..cap.get(0).unwrap().start()].lines().count();

            // 获取函数上下文
            let ctx = Self::get_context_block(content, line_num, 30);
            let entry_ctx = Self::analyze_entry_context(&ctx);

            // 信任边界: Next.js 数据源
            Self::detect_nextjs_trust_boundaries(file_path, &ctx, line_num, &mut trust_boundaries);

            entry_points.push(EntryPoint {
                file_path: file_path.to_string(),
                line: line_num + 1,
                entry_type: EntryType::ServerAction,
                route: None,
                http_method: Some("POST".to_string()),
                auth_required: false,
                auth_mechanism: None,
                risk_score: 0.0,
                function_name: Some(func_name),
                context: entry_ctx,
            });
        }

        (entry_points, trust_boundaries)
    }

    /// 检测 Route Handler 函数
    fn detect_route_handlers(
        file_path: &str, content: &str, route: Option<&str>,
    ) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        let http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

        for (line_num, line) in content.lines().enumerate() {
            for method in &http_methods {
                // export async function GET(request: NextRequest)
                let pattern = format!("export async function {}(", method);
                let pattern_sync = format!("export function {}(", method);
                if line.contains(&pattern) || line.contains(&pattern_sync) {
                    let ctx = Self::get_context_block(content, line_num, 30);
                    let entry_ctx = Self::analyze_entry_context(&ctx);
                    let auth_required = ctx.contains("auth") || ctx.contains("jwt") || ctx.contains("token");

                    // 信任边界
                    Self::detect_nextjs_trust_boundaries(file_path, &ctx, line_num, &mut trust_boundaries);

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::RscEndpoint,
                        route: route.map(|r| r.to_string()),
                        http_method: Some(method.to_string()),
                        auth_required,
                        auth_mechanism: if auth_required { Some("Next.js middleware".to_string()) } else { None },
                        risk_score: 0.0,
                        function_name: Some(method.to_string()),
                        context: entry_ctx,
                    });
                }
            }
        }

        (entry_points, trust_boundaries)
    }

    /// 分析入口点上下文
    fn analyze_entry_context(context: &str) -> EntryContext {
        let mut ctx = EntryContext::default();

        // 数据源检测（使用预编译正则）
        let data_sources: &[(&str, &Regex)] = &[
            ("formData", ds_formdata_re()),
            ("cookies", ds_cookies_re()),
            ("headers", ds_headers_re()),
            ("searchParams", ds_search_params_re()),
            ("request", ds_request_re()),
            ("req", ds_req_re()),
        ];
        for (name, re) in data_sources {
            if re.is_match(context) && !ctx.data_sources.contains(&name.to_string()) {
                ctx.data_sources.push(name.to_string());
            }
        }

        // 净化器检测
        if let Some(cap) = sanitizer_re().find(context) {
            ctx.has_sanitization = true;
            ctx.sanitizers.push(cap.as_str().to_string());
        }

        // 输入校验检测
        ctx.has_input_validation = validation_re().is_match(context);

        // 反序列化检测
        ctx.reaches_deserialization = deserialization_re().is_match(context);

        // 特权操作检测
        ctx.reaches_privileged_op = privileged_op_re().is_match(context);

        ctx
    }

    /// 检测 Next.js 信任边界
    fn detect_nextjs_trust_boundaries(
        file_path: &str, context: &str, base_line: usize,
        trust_boundaries: &mut Vec<TrustBoundary>,
    ) {
        let patterns: &[(&str, &Regex)] = &[
            ("FormData input (Server Action)", tb_formdata_re()),
            ("Request body (Route Handler)", tb_request_body_re()),
            ("URL search parameters (RSC)", tb_search_params_re()),
            ("Cookies (Server Component)", tb_cookies_re()),
            ("HTTP headers (Server Component)", tb_headers_re()),
        ];

        for (line_offset, line) in context.lines().enumerate() {
            for (desc, re) in patterns {
                if re.is_match(line) {
                    trust_boundaries.push(TrustBoundary {
                        file_path: file_path.to_string(),
                        line: base_line + line_offset + 1,
                        description: desc.to_string(),
                        source: re.as_str().to_string(),
                    });
                }
            }
        }
    }

    /// 从文件路径推导 Next.js 路由
    fn extract_nextjs_route(file_path: &str) -> Option<String> {
        // app/api/users/[id]/route.ts → /api/users/:id
        // app/(dashboard)/settings/route.ts → /settings
        if let Some(app_idx) = file_path.find("/app/") {
            let after_app = &file_path[app_idx + 5..];
            // 移除 /route.ts 或 /route.js 后缀
            let path = after_app
                .trim_end_matches("/route.ts")
                .trim_end_matches("/route.js");

            let mut route = String::from("/");
            for segment in path.split('/') {
                if segment.is_empty() {
                    continue;
                }
                // 跳过 route groups: (dashboard)
                if segment.starts_with('(') && segment.ends_with(')') {
                    continue;
                }
                // 动态路由: [id] → :id, [...slug] → :slug*
                if segment.starts_with('[') && segment.ends_with(']') {
                    let inner = &segment[1..segment.len()-1];
                    if inner.starts_with("...") {
                        route.push_str(&inner[3..]);
                        route.push('*');
                    } else {
                        route.push(':');
                        route.push_str(inner);
                    }
                } else {
                    route.push_str(segment);
                }
                route.push('/');
            }
            // 移除末尾 /
            if route.len() > 1 {
                route.pop();
            }
            return Some(route);
        }
        None
    }

    // --- 辅助方法 ---

    fn extract_spring_route(line: &str) -> Option<String> {
        // @GetMapping("/api/users/{id}")
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        if let Some(start) = line.find("value") {
            if let Some(quote) = line[start..].find('"') {
                let rest = &line[start + quote + 1..];
                if let Some(end) = rest.find('"') {
                    return Some(rest[..end].to_string());
                }
            }
        }
        None
    }

    fn extract_express_route(line: &str) -> Option<String> {
        // app.get('/api/users/:id', ...)
        if let Some(start) = line.find('\'') {
            if let Some(end) = line[start + 1..].find('\'') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        None
    }

    fn extract_python_route(line: &str) -> Option<String> {
        // @app.route('/api/users/<id>')
        if let Some(start) = line.find('\'') {
            if let Some(end) = line[start + 1..].find('\'') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }
        None
    }

    fn check_java_auth(context: &str) -> bool {
        let auth_patterns = [
            "@PreAuthorize",
            "@Secured",
            "@RolesAllowed",
            "@WithMockUser",
            "SecurityContextHolder",
            "Authentication",
            "@Authenticated",
        ];
        auth_patterns.iter().any(|p| context.contains(p))
    }

    fn get_context_block(content: &str, center_line: usize, radius: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = center_line.saturating_sub(radius);
        let end = (center_line + radius).min(lines.len());
        lines[start..end].join("\n")
    }
}

/// 遍历项目文件
fn walk_project(project_path: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let ignore_dirs: HashSet<&str> = [
        "node_modules", ".git", "target", "build", "dist",
        "__pycache__", ".next", "vendor", ".gradle", ".idea",
        ".mvn", "bin", "obj",
    ].into_iter().collect();

    let source_extensions: HashSet<&str> = [
        "java", "js", "ts", "jsx", "tsx", "py", "go", "rs",
    ].into_iter().collect();

    let mut result = Vec::new();
    walk_dir_recursive(project_path, &ignore_dirs, &source_extensions, &mut result);
    Ok(result)
}

fn walk_dir_recursive(
    dir: &Path,
    ignore_dirs: &HashSet<&str>,
    source_extensions: &HashSet<&str>,
    result: &mut Vec<PathBuf>,
) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !ignore_dirs.contains(name) && !name.starts_with('.') {
                        walk_dir_recursive(&path, ignore_dirs, source_extensions, result);
                    }
                }
            } else if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if source_extensions.contains(ext) {
                        result.push(path);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_java_spring_endpoint() {
        let code = r#"
@RestController
@RequestMapping("/api/users")
public class UserController {
    @GetMapping("/{id}")
    public User getUser(@PathVariable String id) {
        return userService.findById(id);
    }

    @PostMapping
    public User createUser(@RequestBody UserCreateRequest request) {
        return userService.create(request);
    }
}
"#;
        let (eps, tbs) = AttackSurfaceMapper::analyze_java_file("UserController.java", code);
        assert!(eps.len() >= 2, "Should find at least 2 endpoints, found {}", eps.len());
        assert!(tbs.len() >= 2, "Should find at least 2 trust boundaries");

        let get_ep = eps.iter().find(|e| e.http_method.as_deref() == Some("GET"));
        assert!(get_ep.is_some());
        assert_eq!(get_ep.unwrap().route, Some("/{id}".to_string()));
    }

    #[test]
    fn test_analyze_express_endpoint() {
        let code = r#"
const express = require('express');
const app = express();

app.get('/api/users/:id', (req, res) => {
    const user = db.findUser(req.params.id);
    res.json(user);
});

app.post('/api/users', auth, (req, res) => {
    const user = db.createUser(req.body);
    res.json(user);
});
"#;
        let (eps, tbs) = AttackSurfaceMapper::analyze_js_file("app.js", code);
        assert!(eps.len() >= 2, "Should find at least 2 endpoints");
        assert!(tbs.len() >= 2, "Should find trust boundaries");

        let get_ep = eps.iter().find(|e| e.http_method.as_deref() == Some("GET"));
        assert!(get_ep.is_some());
        // GET /api/users/:id 不需要认证（代码中没有 auth middleware）
        let post_ep = eps.iter().find(|e| e.http_method.as_deref() == Some("POST"));
        assert!(post_ep.is_some());
        // POST /api/users 有 auth middleware
        assert!(post_ep.unwrap().auth_required);
    }

    #[test]
    fn test_risk_score_unauthenticated_http() {
        let mut ep = EntryPoint {
            file_path: "test.java".into(),
            line: 1,
            entry_type: EntryType::HttpEndpoint,
            route: Some("/api/admin".into()),
            http_method: Some("POST".into()),
            auth_required: false,
            auth_mechanism: None,
            risk_score: 0.0,
            function_name: None,
            context: EntryContext::default(),
        };
        let score = AttackSurfaceMapper::compute_risk_score(&mut ep);
        assert!(score >= 0.8, "Unauthenticated POST should score >= 0.8, got {}", score);
    }

    #[test]
    fn test_risk_score_scheduled_task() {
        let mut ep = EntryPoint {
            file_path: "test.java".into(),
            line: 1,
            entry_type: EntryType::ScheduledTask,
            route: None,
            http_method: None,
            auth_required: true,
            auth_mechanism: None,
            risk_score: 0.0,
            function_name: None,
            context: EntryContext::default(),
        };
        let score = AttackSurfaceMapper::compute_risk_score(&mut ep);
        assert!(score < 0.5, "Scheduled task should score < 0.5, got {}", score);
    }

    #[test]
    fn test_nextjs_server_action_detection() {
        let code = r#"'use server'

export async function createUser(formData: FormData) {
    const name = formData.get('name');
    const email = formData.get('email');
    await db.user.create({ data: { name, email } });
}

export async function deleteUser(formData: FormData) {
    const id = formData.get('id');
    await db.user.delete({ where: { id } });
}
"#;
        let (eps, tbs) = AttackSurfaceMapper::analyze_nextjs_file("app/actions/user.ts", code);
        assert!(eps.len() >= 2, "Should find at least 2 Server Actions, found {}", eps.len());
        assert!(tbs.len() >= 2, "Should find trust boundaries for formData");

        let create_ep = eps.iter().find(|e| e.function_name.as_deref() == Some("createUser"));
        assert!(create_ep.is_some());
        let ep = create_ep.unwrap();
        assert_eq!(ep.entry_type, EntryType::ServerAction);
        assert!(ep.context.data_sources.contains(&"formData".to_string()));
    }

    #[test]
    fn test_nextjs_route_handler_detection() {
        let code = r#"
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
    const data = await request.json();
    return NextResponse.json({ data });
}

export async function POST(request: NextRequest) {
    const body = await request.json();
    await db.query('INSERT INTO users VALUES (?)', [body.name]);
    return NextResponse.json({ success: true });
}
"#;
        let (eps, tbs) = AttackSurfaceMapper::analyze_nextjs_file(
            "src/app/api/users/route.ts", code,
        );
        assert!(eps.len() >= 2, "Should find at least 2 route handlers");
        assert_eq!(eps[0].entry_type, EntryType::RscEndpoint);

        let post_ep = eps.iter().find(|e| e.http_method.as_deref() == Some("POST"));
        assert!(post_ep.is_some());
        assert!(post_ep.unwrap().context.reaches_privileged_op);
    }

    #[test]
    fn test_nextjs_route_extraction() {
        assert_eq!(
            AttackSurfaceMapper::extract_nextjs_route("src/app/api/users/route.ts"),
            Some("/api/users".to_string())
        );
        assert_eq!(
            AttackSurfaceMapper::extract_nextjs_route("src/app/api/users/[id]/route.ts"),
            Some("/api/users/:id".to_string())
        );
        assert_eq!(
            AttackSurfaceMapper::extract_nextjs_route("src/app/(dashboard)/settings/route.ts"),
            Some("/settings".to_string())
        );
    }

    #[test]
    fn test_entry_context_validation_detection() {
        let code_with_validation = r#"
import { z } from 'zod';
const schema = z.object({ name: z.string() });
export async function action(formData: FormData) {
    const raw = { name: formData.get('name') };
    const data = schema.safeParse(raw);
}
"#;
        let ctx = AttackSurfaceMapper::analyze_entry_context(code_with_validation);
        assert!(ctx.has_input_validation, "Should detect zod validation");
        assert!(ctx.data_sources.contains(&"formData".to_string()));

        let code_without_validation = r#"
export async function action(formData: FormData) {
    const name = formData.get('name');
    eval(name);
}
"#;
        let ctx2 = AttackSurfaceMapper::analyze_entry_context(code_without_validation);
        assert!(!ctx2.has_input_validation, "Should NOT detect validation");
        assert!(ctx2.reaches_privileged_op, "Should detect eval as privileged op");
    }
}
