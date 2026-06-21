// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 框架中间件建模
//!
//! 检测 Express `app.use()` / Django `MIDDLEWARE` 等中间件模式，
//! 在调用图中注入虚拟边模拟隐式数据流。

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// 中间件注册信息
#[derive(Debug, Clone)]
pub struct MiddlewareRegistration {
    /// 中间件函数名
    pub handler_name: String,
    /// 中间件所在文件
    pub handler_file: String,
    /// 中间件注册行号
    pub line: usize,
}

/// 框架中间件模型 — 聚合所有检测到的中间件和路由关系
#[derive(Debug, Clone, Default)]
pub struct MiddlewareModel {
    /// Express `app.use()` 中间件注册
    pub express_middleware: Vec<MiddlewareRegistration>,
    /// Express app 实例的路由 handler 行号集合: file_path → set of handler lines
    pub express_routes: HashMap<String, Vec<usize>>,
    /// Django MIDDLEWARE 类名列表
    pub django_middleware: Vec<String>,
}

impl MiddlewareModel {
    pub fn new() -> Self {
        Self {
            express_middleware: Vec::new(),
            express_routes: HashMap::new(),
            django_middleware: Vec::new(),
        }
    }

    /// 扫描文件中的 Express 中间件和路由注册
    pub fn scan_express_file(&mut self, file_path: &str, content: &str) {
        let mut found_routes = Vec::new();
        let mut found_middleware = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // 检测 app.use(handler) — 中间件注册
            if trimmed.contains("app.use(") || trimmed.contains("router.use(") {
                if let Some(handler) = Self::extract_use_handler(trimmed) {
                    found_middleware.push(MiddlewareRegistration {
                        handler_name: handler,
                        handler_file: file_path.to_string(),
                        line: line_num + 1,
                    });
                }
            }

            // 检测 app.get/post/... — 路由注册
            if Self::is_express_route_line(trimmed) {
                found_routes.push(line_num + 1);
            }
        }

        if !found_routes.is_empty() {
            self.express_routes
                .insert(file_path.to_string(), found_routes);
        }
        if !found_middleware.is_empty() {
            self.express_middleware.extend(found_middleware);
        }
    }

    /// 扫描 Django settings.py 中的 MIDDLEWARE 列表
    pub fn scan_django_settings(&mut self, content: &str) {
        let mut in_middleware = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("MIDDLEWARE") && trimmed.contains('=') {
                in_middleware = true;
                continue;
            }
            if in_middleware {
                if trimmed == "]" || trimmed == "]" {
                    break;
                }
                // 提取 'django.middleware.X' 或 'myapp.middleware.X'
                if let Some(start) = trimmed.find('\'') {
                    let after = &trimmed[start + 1..];
                    if let Some(end) = after.find('\'') {
                        self.django_middleware.push(after[..end].to_string());
                    }
                }
            }
        }
    }

    /// 获取指定文件的所有 Express 路由行号
    pub fn get_express_route_lines(&self, file_path: &str) -> &[usize] {
        self.express_routes
            .get(file_path)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// 获取所有 Express 中间件注册
    pub fn get_express_middleware(&self) -> &[MiddlewareRegistration] {
        &self.express_middleware
    }

    /// 检测行是否为 Express 路由注册
    fn is_express_route_line(line: &str) -> bool {
        let patterns = [
            "app.get(",
            "app.post(",
            "app.put(",
            "app.delete(",
            "app.patch(",
            "router.get(",
            "router.post(",
            "router.put(",
            "router.delete(",
            "router.patch(",
        ];
        patterns.iter().any(|p| line.contains(p))
    }

    /// 从 app.use(handler) 行中提取 handler 名称
    fn extract_use_handler(line: &str) -> Option<String> {
        let start = line.find(".use(")?;
        let after = &line[start + 5..]; // skip ".use("
                                        // 情况1: app.use(express.json()) — 内置中间件，跳过
                                        // 情况2: app.use(authMiddleware) — 命名函数引用
                                        // 情况3: app.use('/path', handler) — 路径前缀 + handler

        let args_str = if let Some(end) = after.find(')') {
            &after[..end]
        } else {
            return None;
        };

        // 跳过内置中间件调用
        if args_str.contains('(') && !args_str.starts_with('\'') && !args_str.starts_with('"') {
            return None;
        }

        // 如果有路径前缀，提取第二个参数
        let parts: Vec<&str> = args_str.split(',').collect();
        let handler_part = if parts.len() >= 2 {
            parts.last()?.trim()
        } else {
            parts.first()?.trim()
        };

        // 只提取纯标识符（非字符串、非函数调用）
        if handler_part.is_empty()
            || handler_part.starts_with('\'')
            || handler_part.starts_with('"')
            || handler_part.contains('(')
        {
            return None;
        }

        Some(handler_part.to_string())
    }
}

/// 扫描项目中的中间件模式
pub fn scan_middleware(file_path: &Path, content: &str, model: &mut MiddlewareModel) {
    let path_str = file_path.to_string_lossy();
    let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Express/Node.js
    if matches!(
        file_path.extension().and_then(|e| e.to_str()),
        Some("js" | "jsx" | "ts" | "tsx")
    ) {
        model.scan_express_file(&path_str, content);
    }

    // Django settings
    if file_name == "settings.py" {
        model.scan_django_settings(content);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_use_named_handler() {
        let result = MiddlewareModel::extract_use_handler("app.use(authMiddleware)");
        assert_eq!(result, Some("authMiddleware".to_string()));
    }

    #[test]
    fn test_extract_use_builtin_skipped() {
        let result = MiddlewareModel::extract_use_handler("app.use(express.json())");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_use_with_path() {
        let result = MiddlewareModel::extract_use_handler("app.use('/api', authHandler)");
        assert_eq!(result, Some("authHandler".to_string()));
    }

    #[test]
    fn test_scan_express_file() {
        let code = r#"
const app = express();
app.use(authMiddleware);
app.use('/api', apiGuard);
app.get('/user', (req, res) => { res.send(req.user); });
app.post('/data', dataHandler);
"#;
        let mut model = MiddlewareModel::new();
        model.scan_express_file("app.js", code);

        assert_eq!(model.express_middleware.len(), 2);
        assert_eq!(model.express_middleware[0].handler_name, "authMiddleware");
        assert_eq!(model.express_middleware[1].handler_name, "apiGuard");
        assert_eq!(model.express_routes.get("app.js").unwrap().len(), 2);
    }

    #[test]
    fn test_scan_django_settings() {
        let code = r#"
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'myapp.middleware.AuthMiddleware',
]
"#;
        let mut model = MiddlewareModel::new();
        model.scan_django_settings(code);

        assert_eq!(model.django_middleware.len(), 3);
        assert!(model
            .django_middleware
            .iter()
            .any(|m| m.contains("SecurityMiddleware")));
    }

    #[test]
    fn test_is_express_route_line() {
        assert!(MiddlewareModel::is_express_route_line(
            "app.get('/x', handler)"
        ));
        assert!(MiddlewareModel::is_express_route_line(
            "router.post('/y', h)"
        ));
        assert!(!MiddlewareModel::is_express_route_line("app.use(auth)"));
        assert!(!MiddlewareModel::is_express_route_line("  const x = 1;"));
    }

    #[test]
    fn test_empty_model() {
        let model = MiddlewareModel::new();
        assert!(model.express_middleware.is_empty());
        assert!(model.express_routes.is_empty());
    }
}
