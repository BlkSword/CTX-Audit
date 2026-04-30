// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 攻击面映射引擎
//!
//! 识别项目中的入口点（HTTP endpoint、CLI handler 等），
//! 构建信任边界，计算风险评分，用于优先化安全分析。

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

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
}

/// 攻击面映射器
pub struct AttackSurfaceMapper;

impl AttackSurfaceMapper {
    /// 映射项目的攻击面
    pub fn map_project(project_path: &Path) -> AttackSurface {
        let mut entry_points = Vec::new();
        let mut trust_boundaries = Vec::new();
        let mut files_scanned = 0;

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
                            entry_points.extend(eps);
                            trust_boundaries.extend(tbs);
                        }
                        "js" | "ts" | "jsx" | "tsx" => {
                            let (eps, tbs) = Self::analyze_js_file(&file_str, &content);
                            entry_points.extend(eps);
                            trust_boundaries.extend(tbs);
                        }
                        "py" => {
                            let (eps, tbs) = Self::analyze_python_file(&file_str, &content);
                            entry_points.extend(eps);
                            trust_boundaries.extend(tbs);
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

        AttackSurface {
            entry_points,
            trust_boundaries,
            high_risk_files,
            stats: AttackSurfaceStats {
                files_scanned,
                total_entry_points,
                unauthenticated_count,
                high_risk_file_count,
            },
        }
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
                    auth_required: true, // 定时任务是内部的，不需要外部认证
                    auth_mechanism: None,
                    risk_score: 0.0,
                    function_name: None,
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

    /// 计算入口点风险评分
    fn compute_risk_score(ep: &EntryPoint) -> f32 {
        let mut score: f32 = 0.3; // 基础分

        // 未认证 → 大幅提升
        if !ep.auth_required {
            score += 0.4;
        }

        // HTTP 端点 → 外部可达
        if ep.entry_type == EntryType::HttpEndpoint {
            score += 0.2;
        }

        // POST/PUT/DELETE → 可修改数据
        if let Some(ref method) = ep.http_method {
            if matches!(method.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
                score += 0.1;
            }
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
        let ep = EntryPoint {
            file_path: "test.java".into(),
            line: 1,
            entry_type: EntryType::HttpEndpoint,
            route: Some("/api/admin".into()),
            http_method: Some("POST".into()),
            auth_required: false,
            auth_mechanism: None,
            risk_score: 0.0,
            function_name: None,
        };
        let score = AttackSurfaceMapper::compute_risk_score(&ep);
        assert!(score >= 0.8, "Unauthenticated POST should score >= 0.8, got {}", score);
    }

    #[test]
    fn test_risk_score_scheduled_task() {
        let ep = EntryPoint {
            file_path: "test.java".into(),
            line: 1,
            entry_type: EntryType::ScheduledTask,
            route: None,
            http_method: None,
            auth_required: true,
            auth_mechanism: None,
            risk_score: 0.0,
            function_name: None,
        };
        let score = AttackSurfaceMapper::compute_risk_score(&ep);
        assert!(score < 0.5, "Scheduled task should score < 0.5, got {}", score);
    }
}
