// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 上下文感知分析器
//!
//! 理解框架特定语义（如 Django 的 @login_required）和隐式安全机制

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 安全边界
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityBoundary {
    /// 无边界保护
    None,

    /// 隐式边界（框架提供但不明显）
    Implicit,

    /// 显式边界（明确的安全检查）
    Explicit,
}

/// 框架语义信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkSemantic {
    /// 框架名称
    pub name: String,

    /// 框架版本
    pub version: Option<String>,

    /// 框架提供的安全机制
    pub security_mechanisms: Vec<String>,

    /// 需要的特殊配置
    pub security_config: HashMap<String, String>,
}

/// 语义上下文
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SemanticContext {
    /// 文件路径
    pub file_path: Option<String>,

    /// 函数名
    pub function_name: Option<String>,

    /// 语言
    pub language: Option<String>,

    /// 框架信息
    pub framework: Option<String>,

    /// 导入的模块
    pub imports: Vec<String>,

    /// 装饰器
    pub decorators: Vec<String>,

    /// 额外上下文
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// 上下文感知分析器
pub struct ContextAwareAnalyzer {
    /// 框架语义库
    framework_semantics: HashMap<String, FrameworkSemantic>,
}

impl ContextAwareAnalyzer {
    /// 创建新的上下文分析器
    pub fn new() -> Self {
        let mut framework_semantics = HashMap::new();

        // Django 框架
        framework_semantics.insert(
            "django".to_string(),
            FrameworkSemantic {
                name: "Django".to_string(),
                version: None,
                security_mechanisms: vec![
                    "@login_required".to_string(),
                    "@permission_required".to_string(),
                    "@csrf_protect".to_string(),
                    "@require_http_methods".to_string(),
                    "CSRF middleware".to_string(),
                ],
                security_config: {
                    let mut config = std::collections::HashMap::new();
                    config.insert("CSRF_COOKIE_NAME".to_string(), "csrftoken".to_string());
                    config.insert("SESSION_COOKIE_HTTPONLY".to_string(), "True".to_string());
                    config
                },
            },
        );

        // Flask 框架
        framework_semantics.insert(
            "flask".to_string(),
            FrameworkSemantic {
                name: "Flask".to_string(),
                version: None,
                security_mechanisms: vec![
                    "@login_required".to_string(),
                    "before_request".to_string(),
                ],
                security_config: HashMap::new(),
            },
        );

        // Express.js 框架
        framework_semantics.insert(
            "express".to_string(),
            FrameworkSemantic {
                name: "Express".to_string(),
                version: None,
                security_mechanisms: vec![
                    "helmet".to_string(),
                    "cors".to_string(),
                    "express-session".to_string(),
                ],
                security_config: HashMap::new(),
            },
        );

        // Spring Boot 框架
        framework_semantics.insert(
            "spring".to_string(),
            FrameworkSemantic {
                name: "Spring Boot".to_string(),
                version: None,
                security_mechanisms: vec![
                    "@PreAuthorize".to_string(),
                    "@Secured".to_string(),
                    "@CrossOrigin".to_string(),
                ],
                security_config: HashMap::new(),
            },
        );

        Self {
            framework_semantics,
        }
    }

    /// 识别安全边界
    pub fn identify_security_boundaries(
        &self,
        code: &str,
        context: &SemanticContext,
    ) -> Vec<SecurityBoundary> {
        let mut boundaries = Vec::new();

        // 检查装饰器/注解
        for decorator in &context.decorators {
            if self.is_security_decorator(decorator) {
                boundaries.push(SecurityBoundary::Explicit);
            }
        }

        // 检查框架中间件
        if let Some(framework) = &context.framework {
            if let Some(fw_semantic) = self.framework_semantics.get(framework) {
                // 检查是否使用了框架安全机制
                for mechanism in &fw_semantic.security_mechanisms {
                    if code.contains(mechanism) {
                        boundaries.push(SecurityBoundary::Explicit);
                    }
                }
            }
        }

        // 检查显式安全检查
        if self.has_explicit_security_checks(code) {
            boundaries.push(SecurityBoundary::Explicit);
        }

        // 如果没有找到任何边界，返回无边界
        if boundaries.is_empty() {
            boundaries.push(SecurityBoundary::None);
        }

        boundaries
    }

    /// 检查是否有显式安全检查
    fn has_explicit_security_checks(&self, code: &str) -> bool {
        let security_patterns = [
            "if request.user",
            "if current_user",
            "if authenticated",
            "check_permission",
            "has_access",
            "require_permission",
            "@login_required",
            "@permission_required",
        ];

        security_patterns.iter().any(|&pattern| code.contains(pattern))
    }

    /// 推断框架
    pub fn infer_framework(&self, code: &str, imports: &[String]) -> Option<String> {
        // 从导入语句推断框架
        for import in imports {
            if import.contains("django") {
                return Some("django".to_string());
            }
            if import.contains("flask") {
                return Some("flask".to_string());
            }
            if import.contains("express") {
                return Some("express".to_string());
            }
            if import.contains("spring") || import.contains("org.springframework") {
                return Some("spring".to_string());
            }
        }

        // 从代码特征推断
        if code.contains("from django") || code.contains("import django") {
            return Some("django".to_string());
        }
        if code.contains("@login_required") && code.contains("django") {
            return Some("django".to_string());
        }
        if code.contains("from flask") || code.contains("import flask") {
            return Some("flask".to_string());
        }
        if code.contains("require('express')") {
            return Some("express".to_string());
        }

        None
    }

    /// 提取装饰器
    pub fn extract_decorators(&self, code: &str) -> Vec<String> {
        let mut decorators = Vec::new();

        // Python 装饰器 @xxx
        if code.contains('@') {
            for line in code.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('@') {
                    decorators.push(trimmed.to_string());
                }
            }
        }

        decorators
    }

    /// 判断装饰器是否是安全相关的
    pub fn is_security_decorator(&self, decorator: &str) -> bool {
        let security_decorators = [
            "@login_required",
            "@permission_required",
            "@auth_required",
            "@roles_required",
            "@requires_auth",
            "@authenticated",
            "@authorized",
            "@require_http_methods",
            "@csrf_protect",
            "@ensure_csrf_cookie",
            "@xframe_options_sameorigin",
            "@secure_page",
            "@jwt_required",
            "@require_admin",
        ];

        security_decorators.iter().any(|&sec| decorator.starts_with(sec))
    }

    /// 分析框架特定的安全问题
    pub fn analyze_framework_security_issues(
        &self,
        code: &str,
        framework: &str,
    ) -> Vec<String> {
        let mut issues = Vec::new();

        if let Some(fw_semantic) = self.framework_semantics.get(framework) {
            // 检查是否使用了推荐的安全机制
            for mechanism in &fw_semantic.security_mechanisms {
                if !code.contains(mechanism) {
                    issues.push(format!(
                        "缺少推荐的安全机制: {} ({})",
                        mechanism, fw_semantic.name
                    ));
                }
            }
        }

        issues
    }

    /// 获取框架语义
    pub fn get_framework_semantic(&self, framework: &str) -> Option<&FrameworkSemantic> {
        self.framework_semantics.get(framework)
    }

    /// 添加自定义框架语义
    pub fn add_framework_semantic(&mut self, semantic: FrameworkSemantic) {
        self.framework_semantics.insert(semantic.name.clone().to_lowercase(), semantic);
    }
}

impl Default for ContextAwareAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_decorator_detection() {
        let analyzer = ContextAwareAnalyzer::new();

        assert!(analyzer.is_security_decorator("@login_required"));
        assert!(analyzer.is_security_decorator("@permission_required"));
        assert!(!analyzer.is_security_decorator("@cache"));
    }

    #[test]
    fn test_extract_decorators() {
        let analyzer = ContextAwareAnalyzer::new();

        let code = r#"
        @login_required
        @permission_required('admin')
        def sensitive_view(request):
            pass
        "#;

        let decorators = analyzer.extract_decorators(code);
        assert_eq!(decorators.len(), 2);
    }

    #[test]
    fn test_infer_framework() {
        let analyzer = ContextAwareAnalyzer::new();

        // Django 检测
        let django_code = "from django.contrib.auth.decorators import login_required";
        let framework = analyzer.infer_framework(django_code, &[]);
        assert_eq!(framework, Some("django".to_string()));

        // Flask 检测
        let flask_code = "from flask import Flask";
        let framework = analyzer.infer_framework(flask_code, &[]);
        assert_eq!(framework, Some("flask".to_string()));
    }

    #[test]
    fn test_identify_security_boundaries() {
        let analyzer = ContextAwareAnalyzer::new();

        let code = r#"
        @login_required
        def view(request):
            if request.user.is_authenticated:
                return True
        "#;

        let context = SemanticContext {
            decorators: vec!["@login_required".to_string()],
            ..Default::default()
        };

        let boundaries = analyzer.identify_security_boundaries(code, &context);

        // 应该检测到显式边界（@login_required）
        assert!(boundaries.contains(&SecurityBoundary::Explicit));
    }
}
