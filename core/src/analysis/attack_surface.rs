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

// ── 路由与路径过滤配置 ─────────────────────────────────────

/// 可配置的路由/路径过滤器。
/// 用于决定哪些 HTTP 端点属于设计上公开、哪些文件路径属于非生产代码。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteFilterConfig {
    /// 设计上公开访问的 HTTP 路由前缀/完整路径。
    #[serde(default = "default_public_route_patterns")]
    pub public_route_patterns: Vec<String>,

    /// 应被当作非生产代码的目录/路径片段。
    #[serde(default = "default_non_production_path_patterns")]
    pub non_production_path_patterns: Vec<String>,
}

impl Default for RouteFilterConfig {
    fn default() -> Self {
        Self {
            public_route_patterns: default_public_route_patterns(),
            non_production_path_patterns: default_non_production_path_patterns(),
        }
    }
}

/// 默认公开路由白名单。
/// 这些端点不应被直接报告为认证缺失漏洞。
pub fn default_public_route_patterns() -> Vec<String> {
    vec![
        "/signup".to_string(),
        "/sign-up".to_string(),
        "/register".to_string(),
        "/login".to_string(),
        "/signin".to_string(),
        "/sign-in".to_string(),
        "/logout".to_string(),
        "/signout".to_string(),
        "/sign-out".to_string(),
        "/health".to_string(),
        "/healthz".to_string(),
        "/status".to_string(),
        "/ping".to_string(),
        "/forgot-password".to_string(),
        "/reset-password".to_string(),
        "/oauth/".to_string(),
        "/auth/".to_string(),
        "/callback/".to_string(),
    ]
}

/// 默认非生产代码路径片段。
pub fn default_non_production_path_patterns() -> Vec<String> {
    vec![
        "/test/".to_string(),
        "/tests/".to_string(),
        "/__tests__/".to_string(),
        "/tutorial/".to_string(),
        "/tutorials/".to_string(),
        "/demo/".to_string(),
        "/demos/".to_string(),
        "/examples/".to_string(),
        "/fixtures/".to_string(),
        "/libs/".to_string(),
        "/plugins/".to_string(),
        "/jquery/".to_string(),
        "/vendor/".to_string(),
        "/vendors/".to_string(),
        "/.ctx-audit/".to_string(),
    ]
}

/// 判断路由是否在指定的公开路由列表中。
pub fn is_public_route_with_patterns(route: &str, patterns: &[String]) -> bool {
    let normalized = route.trim().replace('\\', "/");
    if normalized.is_empty() {
        return false;
    }
    for pat in patterns {
        if normalized == *pat || normalized.starts_with(pat) {
            return true;
        }
    }
    false
}

/// 判断路由是否属于默认的公开路由白名单。
pub fn is_public_route(route: &str) -> bool {
    is_public_route_with_patterns(route, &default_public_route_patterns())
}

/// 判断路径是否命中指定的非生产代码模式。
pub fn is_non_production_path_with_patterns(path: &str, patterns: &[String]) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    patterns
        .iter()
        .any(|p| normalized.contains(&p.to_lowercase()))
}

/// 判断路径是否属于默认的非生产代码目录。
pub fn is_non_production_path(path: &str) -> bool {
    is_non_production_path_with_patterns(path, &default_non_production_path_patterns())
}

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

fn ds_formdata_re() -> &'static Regex {
    RE_DS_FORMDATA.get_or_init(|| Regex::new(r"formData\.(get|getAll|entries|values|has)").unwrap())
}
fn ds_cookies_re() -> &'static Regex {
    RE_DS_COOKIES.get_or_init(|| Regex::new(r"cookies\(\)\.(get|getAll)").unwrap())
}
fn ds_headers_re() -> &'static Regex {
    RE_DS_HEADERS.get_or_init(|| Regex::new(r"headers\(\)\.(get)").unwrap())
}
fn ds_search_params_re() -> &'static Regex {
    RE_DS_SEARCH_PARAMS.get_or_init(|| Regex::new(r"searchParams\.(get|getAll)").unwrap())
}
fn ds_request_re() -> &'static Regex {
    RE_DS_REQUEST.get_or_init(|| Regex::new(r"request\.(json|text|formData)\s*\(").unwrap())
}
fn ds_req_re() -> &'static Regex {
    RE_DS_REQ.get_or_init(|| Regex::new(r"req\.(body|query|params)").unwrap())
}

// 上下文分析
static RE_SANITIZER: OnceLock<Regex> = OnceLock::new();
static RE_VALIDATION: OnceLock<Regex> = OnceLock::new();
static RE_DESERIALIZATION: OnceLock<Regex> = OnceLock::new();
static RE_PRIVILEGED_OP: OnceLock<Regex> = OnceLock::new();

fn sanitizer_re() -> &'static Regex {
    RE_SANITIZER.get_or_init(|| {
        Regex::new(r"sanitize|escape|encode|DOMPurify|bleach|htmlspecialchars").unwrap()
    })
}
fn validation_re() -> &'static Regex {
    RE_VALIDATION.get_or_init(|| {
        Regex::new(r"(?i)(?:zod|joi|yup|ajv|\.safeParse|\.parse\(|validate\(|Schema|\.schema)")
            .unwrap()
    })
}
fn deserialization_re() -> &'static Regex {
    RE_DESERIALIZATION.get_or_init(|| Regex::new(r"(?:JSON\.parse|parseModel|resolveModel|deserialize|unserialize|objectMapper\.readValue|pickle\.loads)").unwrap())
}
fn privileged_op_re() -> &'static Regex {
    RE_PRIVILEGED_OP.get_or_init(|| Regex::new(r"(?:fs\.|writeFile|readFile|\.execute\s*\(|\.query\s*\(|exec\s*\(|eval\s*\(|system\s*\(|child_process|subprocess|DB::|database\.)").unwrap())
}

// 信任边界
static RE_TB_FORMDATA: OnceLock<Regex> = OnceLock::new();
static RE_TB_REQUEST_BODY: OnceLock<Regex> = OnceLock::new();
static RE_TB_SEARCH_PARAMS: OnceLock<Regex> = OnceLock::new();
static RE_TB_COOKIES: OnceLock<Regex> = OnceLock::new();
static RE_TB_HEADERS: OnceLock<Regex> = OnceLock::new();

fn tb_formdata_re() -> &'static Regex {
    RE_TB_FORMDATA.get_or_init(|| Regex::new(r"formData\.(get|getAll)\s*\(").unwrap())
}
fn tb_request_body_re() -> &'static Regex {
    RE_TB_REQUEST_BODY.get_or_init(|| Regex::new(r"request\.(json|text|formData)\s*\(").unwrap())
}
fn tb_search_params_re() -> &'static Regex {
    RE_TB_SEARCH_PARAMS.get_or_init(|| Regex::new(r"searchParams\.(get|getAll)\s*\(").unwrap())
}
fn tb_cookies_re() -> &'static Regex {
    RE_TB_COOKIES.get_or_init(|| Regex::new(r"cookies\(\)\.(get|getAll)\s*\(").unwrap())
}
fn tb_headers_re() -> &'static Regex {
    RE_TB_HEADERS.get_or_init(|| Regex::new(r"headers\(\)\.(get)\s*\(").unwrap())
}

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

impl Default for AttackSurface {
    fn default() -> Self {
        Self {
            entry_points: Vec::new(),
            trust_boundaries: Vec::new(),
            high_risk_files: Vec::new(),
            stats: AttackSurfaceStats::default(),
        }
    }
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

                    let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

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
                        "go" => {
                            let (eps, tbs) = Self::analyze_go_file(&file_str, &content);
                            entry_points.extend(eps);
                            trust_boundaries.extend(tbs);
                            if content.contains("gin") || content.contains("gin-gonic") {
                                detected_frameworks.insert("Gin".to_string());
                            }
                            if content.contains("echo") || content.contains("labstack/echo") {
                                detected_frameworks.insert("Echo".to_string());
                            }
                            if content.contains("net/http") {
                                detected_frameworks.insert("net/http".to_string());
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

        // 如果项目有全局认证中间件，将未认证端点标记为已认证
        if Self::has_global_auth_middleware(project_path) {
            for ep in &mut entry_points {
                if !ep.auth_required {
                    ep.auth_required = true;
                    ep.auth_mechanism = Some("Global middleware".to_string());
                }
            }
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
            "go" => {
                let (eps, _) = Self::analyze_go_file(file_path, content);
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
                    let has_inline = Self::has_inline_middleware(line);
                    let auth_required = has_inline
                        || context.contains("auth")
                        || context.contains("jwt")
                        || context.contains("token")
                        || context.contains("passport");

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
    fn analyze_python_file(
        file_path: &str,
        content: &str,
    ) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // 文件级全局认证守卫预检查：Flask before_request + current_user / login_required
        // 若本文件定义了全局门，所有端点默认视为已认证（与 has_global_auth_middleware 同逻辑，
        // 但粒度为文件级，在 map_file 路径下也生效）
        let lower_content = content.to_lowercase();
        let file_has_global_guard = lower_content.contains("before_request")
            && (lower_content.contains("current_user")
                || lower_content.contains("is_authenticated")
                || lower_content.contains("login_required")
                || lower_content.contains("authenticate"));

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
                    let auth_required = file_has_global_guard
                        || context.contains("@login_required")
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

    /// 分析 Go 文件中的入口点（HTTP 端点）
    fn analyze_go_file(file_path: &str, content: &str) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        let content_lower = content.to_lowercase();

        // 检测框架导入
        let is_gin = content_lower.contains("github.com/gin-gonic/gin");
        let is_echo = content_lower.contains("github.com/labstack/echo");
        let is_net_http = content_lower.contains("\"net/http\"");

        let framework_detected = is_gin || is_echo || is_net_http;

        // 文件级全局认证中间件预检查：Gin r.Use(Auth...) / Echo e.Use(auth...) / net/http middleware
        let go_file_has_global_auth = (content_lower.contains(".use(")
            && (content_lower.contains("auth")
                || content_lower.contains("jwt")
                || content_lower.contains("token")
                || content_lower.contains("session")
                || content_lower.contains("login")
                || content_lower.contains("requireauth")
                || content_lower.contains("isauthenticated")));

        // 标准库路由: http.HandleFunc("/path", handler)
        if is_net_http {
            for (line_num, line) in content.lines().enumerate() {
                if line.contains("HandleFunc(") || line.contains("Handle(") {
                    let route = Self::extract_go_route(line);
                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::HttpEndpoint,
                        route,
                        http_method: None,
                        auth_required: false,
                        auth_mechanism: None,
                        risk_score: 0.0,
                        function_name: None,
                        context: EntryContext::default(),
                    });
                }
            }
        }

        // Gin 框架路由: r.GET("/path", handler), router.POST("/path", handler)
        if is_gin {
            let gin_methods: &[(&str, Option<&str>)] = &[
                ("GET", Some("GET")),
                ("POST", Some("POST")),
                ("PUT", Some("PUT")),
                ("DELETE", Some("DELETE")),
                ("PATCH", Some("PATCH")),
                ("HEAD", Some("HEAD")),
                ("OPTIONS", Some("OPTIONS")),
                ("Any", None),
                ("Handle", None),
                ("Static", None),
                ("StaticFile", None),
                ("StaticFS", None),
                ("StaticFileFS", None),
            ];

            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                for (method_func, method_verb) in gin_methods {
                    // 匹配 r.GET( 或 router.GET( 或 group.GET(
                    let func_call = format!(".{}(", method_func);
                    if !trimmed.contains(&func_call) {
                        continue;
                    }
                    let route = Self::extract_go_route(line);
                    // 检测认证中间件
                    let ctx = Self::get_context_block(content, line_num, 10);
                    let auth_required = go_file_has_global_auth
                        || ctx.contains("auth")
                        || ctx.contains("jwt")
                        || ctx.contains("token")
                        || ctx.contains("middleware")
                        || ctx.contains("login");

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::HttpEndpoint,
                        route,
                        http_method: method_verb.map(|m| m.to_string()),
                        auth_required,
                        auth_mechanism: if auth_required {
                            Some("Gin middleware".to_string())
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

        // Echo 框架路由: e.GET("/path", handler)
        if is_echo {
            let echo_methods: &[(&str, Option<&str>)] = &[
                ("GET", Some("GET")),
                ("POST", Some("POST")),
                ("PUT", Some("PUT")),
                ("DELETE", Some("DELETE")),
                ("PATCH", Some("PATCH")),
                ("HEAD", Some("HEAD")),
                ("OPTIONS", Some("OPTIONS")),
                ("Any", None),
                ("Match", None),
                ("Static", None),
                ("File", None),
            ];

            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                for (method_func, method_verb) in echo_methods {
                    let func_call = format!(".{}(", method_func);
                    if !trimmed.contains(&func_call) {
                        continue;
                    }
                    let route = Self::extract_go_route(line);
                    let ctx = Self::get_context_block(content, line_num, 10);
                    let auth_required = ctx.contains("auth")
                        || ctx.contains("jwt")
                        || ctx.contains("token")
                        || ctx.contains("middleware")
                        || ctx.contains("login");

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::HttpEndpoint,
                        route,
                        http_method: method_verb.map(|m| m.to_string()),
                        auth_required,
                        auth_mechanism: if auth_required {
                            Some("Echo middleware".to_string())
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

        // 信任边界: Go HTTP source 模式
        let input_patterns = [
            ("r.URL.Query()", "HTTP query parameters"),
            ("r.FormValue", "HTTP form value"),
            ("r.PostFormValue", "HTTP post form value"),
            ("r.Header.Get", "HTTP header"),
            ("r.Body", "HTTP request body"),
            ("r.Cookie", "HTTP cookie"),
            ("c.Query", "Gin query parameter"),
            ("c.Param", "Gin URL parameter"),
            ("c.PostForm", "Gin form value"),
            ("c.GetHeader", "Gin request header"),
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

        // 如果未检测到任何框架但有路由注册，仍报告入口点
        if !framework_detected && entry_points.is_empty() {
            // 通用检测: func 名称包含 handler/route/serve 且在 net/http 包下
            // 通过检测 http.Handler 接口实现来发现端点
            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("func")
                    && (trimmed.contains("http.ResponseWriter") || trimmed.contains("ResponseWriter"))
                    && (trimmed.contains("http.Request") || trimmed.contains("*Request"))
                {
                    let func_name = trimmed
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .to_string();

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::HttpEndpoint,
                        route: None,
                        http_method: None,
                        auth_required: false,
                        auth_mechanism: None,
                        risk_score: 0.0,
                        function_name: if func_name.is_empty() {
                            None
                        } else {
                            Some(func_name)
                        },
                        context: EntryContext::default(),
                    });
                }
            }
        }

        (entry_points, trust_boundaries)
    }

    /// 从 Go 路由注册行中提取路由路径
    fn compute_risk_score(ep: &mut EntryPoint) -> f32 {
        let mut score: f32 = 0.2;

        // 未认证
        if !ep.auth_required {
            score += 0.35;
            ep.context.risk_factors.push("no_auth".to_string());
        }

        // 外部可达入口点
        if matches!(
            ep.entry_type,
            EntryType::HttpEndpoint | EntryType::ServerAction | EntryType::RscEndpoint
        ) {
            score += 0.15;
        }

        // POST/PUT/DELETE/PATCH
        if let Some(ref method) = ep.http_method {
            if matches!(method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
                score += 0.1;
            }
        }

        // 无输入校验
        if !ep.context.has_input_validation
            && matches!(
                ep.entry_type,
                EntryType::HttpEndpoint | EntryType::ServerAction | EntryType::RscEndpoint
            )
        {
            score += 0.15;
            ep.context
                .risk_factors
                .push("no_input_validation".to_string());
        }

        // 数据到达反序列化
        if ep.context.reaches_deserialization {
            score += 0.15;
            ep.context
                .risk_factors
                .push("reaches_deserialization".to_string());
        }

        // 数据到达特权操作
        if ep.context.reaches_privileged_op {
            score += 0.1;
            ep.context
                .risk_factors
                .push("reaches_privileged_op".to_string());
        }

        // 定时任务 → 内部，降低
        if ep.entry_type == EntryType::ScheduledTask {
            score -= 0.2;
        }

        score.clamp(0.0, 1.0)
    }

    /// 检测项目是否有全局认证中间件（Flask before_request / Express app.use(auth) / Django MIDDLEWARE）
    pub fn has_global_auth_middleware(project_path: &Path) -> bool {
        if let Ok(entries) = walk_project(project_path) {
            for file_path in entries {
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                // 只检查 Python、JS 和 Go 文件
                if !matches!(ext, "py" | "js" | "ts" | "jsx" | "tsx" | "go") {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&file_path) {
                    let lower = content.to_lowercase();
                    // Flask: before_request + login_required / authenticate
                    if ext == "py" && lower.contains("before_request") {
                        if lower.contains("login_required")
                            || lower.contains("authenticate")
                            || lower.contains("is_authenticated")
                            || lower.contains("current_user")
                        {
                            return true;
                        }
                    }
                    // Express: app.use(auth) / app.use(jwt) / app.use(token)
                    if matches!(ext, "js" | "ts" | "jsx" | "tsx") {
                        if (lower.contains("app.use(") || lower.contains("router.use("))
                            && (lower.contains("auth")
                                || lower.contains("jwt")
                                || lower.contains("token")
                                || lower.contains("passport")
                                || lower.contains("session")
                                || lower.contains("isauthenticated")
                                || lower.contains("requireauth"))
                        {
                            return true;
                        }
                    }
                    // Go Gin/Echo: r.Use(AuthMiddleware()) / e.Use(auth.Middleware())
                    if ext == "go" {
                        if lower.contains(".use(")
                            && (lower.contains("auth")
                                || lower.contains("jwt")
                                || lower.contains("token")
                                || lower.contains("session")
                                || lower.contains("login")
                                || lower.contains("requireauth"))
                        {
                            return true;
                        }
                    }
                    // Django: MIDDLEWARE 配置
                    if ext == "py" && lower.contains("middleware") {
                        if lower.contains("authenticationmiddleware")
                            || lower.contains("loginrequiredmiddleware")
                        {
                            return true;
                        }
                    }
                }
            }
        }
        false
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
        let has_use_server = content
            .lines()
            .take(5)
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
        let is_app_route = normalized.contains("/app/")
            && (normalized.ends_with("/route.ts") || normalized.ends_with("/route.js"));
        let is_app_page = normalized.contains("/app/")
            && (normalized.ends_with("/page.tsx")
                || normalized.ends_with("/page.jsx")
                || normalized.ends_with("/page.ts")
                || normalized.ends_with("/page.js"));

        is_app_route || is_app_page
    }

    /// 分析 Next.js 文件中的入口点
    fn analyze_nextjs_file(
        file_path: &str,
        content: &str,
    ) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // Server Actions: 'use server' 指令文件
        let has_use_server = content
            .lines()
            .take(5)
            .any(|l| l.trim() == "'use server'" || l.trim() == "\"use server\"");

        if has_use_server {
            let (eps, tbs) = Self::detect_server_actions(file_path, content);
            entry_points.extend(eps);
            trust_boundaries.extend(tbs);
        }

        // Route Handlers: app/ 目录下的 route.ts/js
        let normalized = file_path.replace('\\', "/");
        let is_route_handler = normalized.contains("/app/")
            && (normalized.ends_with("/route.ts") || normalized.ends_with("/route.js"));

        if is_route_handler {
            let route = Self::extract_nextjs_route(&normalized);
            let (eps, tbs) = Self::detect_route_handlers(file_path, content, route.as_deref());
            entry_points.extend(eps);
            trust_boundaries.extend(tbs);
        }

        (entry_points, trust_boundaries)
    }

    /// 检测 Server Action 函数
    fn detect_server_actions(
        file_path: &str,
        content: &str,
    ) -> (Vec<EntryPoint>, Vec<TrustBoundary>) {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();

        // 匹配 export async function X( 和 export function X(
        let func_re = server_action_func_re();

        for cap in func_re.captures_iter(content) {
            let func_name = cap
                .get(1)
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
        file_path: &str,
        content: &str,
        route: Option<&str>,
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
                    let auth_required =
                        ctx.contains("auth") || ctx.contains("jwt") || ctx.contains("token");

                    // 信任边界
                    Self::detect_nextjs_trust_boundaries(
                        file_path,
                        &ctx,
                        line_num,
                        &mut trust_boundaries,
                    );

                    entry_points.push(EntryPoint {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        entry_type: EntryType::RscEndpoint,
                        route: route.map(|r| r.to_string()),
                        http_method: Some(method.to_string()),
                        auth_required,
                        auth_mechanism: if auth_required {
                            Some("Next.js middleware".to_string())
                        } else {
                            None
                        },
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
        file_path: &str,
        context: &str,
        base_line: usize,
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
                    let inner = &segment[1..segment.len() - 1];
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

    /// 检测 Express 路由注册行是否有内联 middleware
    ///
    /// Express 路由签名: app.METHOD(path, [middleware...], handler)
    /// 当逗号数量 ≥ 2 时（path, middleware, handler），认为有内联 middleware。
    /// 同时检查常见的 auth middleware 变量名。
    fn has_inline_middleware(line: &str) -> bool {
        // 路由路径后的逗号分隔参数数量
        // app.get("/path", mw, handler) → 至少 2 个逗号
        let comma_count = line.matches(',').count();
        if comma_count < 2 {
            return false;
        }

        // 检查常见的 auth middleware 变量名
        let auth_mw_patterns = [
            "isLoggedIn",
            "isAuthenticated",
            "isAdmin",
            "isAuthorized",
            "requireAuth",
            "requireLogin",
            "authenticate",
            "authenticateUser",
            "authMiddleware",
            "auth",
            "ensureLoggedIn",
            "ensureAuthenticated",
            "checkAuth",
            "verifyToken",
            "validateSession",
            "protect",
            "withAuth",
            "withUser",
        ];
        let lower = line.to_lowercase();
        for pat in &auth_mw_patterns {
            if lower.contains(&pat.to_lowercase()) {
                return true;
            }
        }

        // 通用检测：path 后的参数 ≥ 2 个（path, middleware, handler）
        // 不要求精确匹配 auth pattern，只要有额外参数就是潜在 middleware
        true
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

    fn extract_go_route(line: &str) -> Option<String> {
        // r.GET("/api/users/:id", handler)
        let trimmed = line.trim();
        // 查找 .GET( 或 .POST( 等之后的第一个字符串字面量
        if let Some(paren) = trimmed.find('(') {
            let after_paren = &trimmed[paren + 1..];
            // 跳过空白
            let start_idx = after_paren
                .find(|c: char| !c.is_whitespace())
                .unwrap_or(0);
            let after_ws = &after_paren[start_idx..];
            // 检查首字符是否为引号
            if let Some(quote_char) = after_ws.chars().next() {
                if quote_char == '"' || quote_char == '\'' {
                    if let Some(end) = after_ws[1..].find(quote_char) {
                        return Some(after_ws[1..1 + end].to_string());
                    }
                }
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
        "node_modules",
        ".git",
        "target",
        "build",
        "dist",
        "__pycache__",
        ".next",
        "vendor",
        ".gradle",
        ".idea",
        ".mvn",
        "bin",
        "obj",
    ]
    .into_iter()
    .collect();

    let source_extensions: HashSet<&str> = ["java", "js", "ts", "jsx", "tsx", "py", "go", "rs"]
        .into_iter()
        .collect();

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
        assert!(
            eps.len() >= 2,
            "Should find at least 2 endpoints, found {}",
            eps.len()
        );
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
        let post_ep = eps
            .iter()
            .find(|e| e.http_method.as_deref() == Some("POST"));
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
        assert!(
            score >= 0.8,
            "Unauthenticated POST should score >= 0.8, got {}",
            score
        );
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
        assert!(
            score < 0.5,
            "Scheduled task should score < 0.5, got {}",
            score
        );
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
        assert!(
            eps.len() >= 2,
            "Should find at least 2 Server Actions, found {}",
            eps.len()
        );
        assert!(tbs.len() >= 2, "Should find trust boundaries for formData");

        let create_ep = eps
            .iter()
            .find(|e| e.function_name.as_deref() == Some("createUser"));
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
        let (eps, tbs) =
            AttackSurfaceMapper::analyze_nextjs_file("src/app/api/users/route.ts", code);
        assert!(eps.len() >= 2, "Should find at least 2 route handlers");
        assert_eq!(eps[0].entry_type, EntryType::RscEndpoint);

        let post_ep = eps
            .iter()
            .find(|e| e.http_method.as_deref() == Some("POST"));
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
        assert!(
            ctx2.reaches_privileged_op,
            "Should detect eval as privileged op"
        );
    }

    #[test]
    fn test_has_global_auth_middleware_flask() {
        let dir = std::env::temp_dir().join("ctx_audit_test_flask_guard");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Flask 全局认证门：before_request + current_user.is_authenticated
        std::fs::write(
            dir.join("routes.py"),
            r#"
from flask import Flask, redirect, url_for
from flask_login import current_user

app = Flask(__name__)

@app.before_request
def check_perms():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))

@app.route("/api/data")
def get_data():
    return {"data": "secret"}
"#,
        )
        .unwrap();

        assert!(
            AttackSurfaceMapper::has_global_auth_middleware(&dir),
            "Should detect Flask before_request + current_user.is_authenticated"
        );

        // 无认证门的文件
        let dir2 = std::env::temp_dir().join("ctx_audit_test_no_guard");
        let _ = std::fs::remove_dir_all(&dir2);
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(
            dir2.join("app.py"),
            r#"
from flask import Flask
app = Flask(__name__)

@app.route("/public")
def public_page():
    return "hello"
"#,
        )
        .unwrap();

        assert!(
            !AttackSurfaceMapper::has_global_auth_middleware(&dir2),
            "Should NOT detect global auth when no before_request guard exists"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn test_flask_file_level_before_request_guard() {
        // 文件内有 before_request + current_user.is_authenticated → 端点应标为已认证
        let code = r#"
from flask import Flask, redirect, url_for
from flask_login import current_user

app = Flask(__name__)

@app.before_request
def check_perms():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))

@app.route("/api/data")
def get_data():
    return {"data": "secret"}

@app.route("/api/admin", methods=["POST"])
def admin_action():
    return {"status": "ok"}
"#;
        let (eps, _) = AttackSurfaceMapper::analyze_python_file("routes.py", code);
        assert!(eps.len() >= 2, "Should find at least 2 endpoints, found {}", eps.len());
        for ep in &eps {
            assert!(
                ep.auth_required,
                "Endpoint {:?} at line {} should be auth_required due to file-level before_request guard",
                ep.route, ep.line
            );
        }

        // 无 before_request 的文件 → 端点保持未认证
        let code_no_guard = r#"
from flask import Flask
app = Flask(__name__)

@app.route("/public")
def public_page():
    return "hello"
"#;
        let (eps2, _) = AttackSurfaceMapper::analyze_python_file("app.py", code_no_guard);
        assert!(!eps2.is_empty());
        assert!(
            !eps2[0].auth_required,
            "Endpoint without guard should NOT be auth_required"
        );
    }
}
