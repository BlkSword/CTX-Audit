// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 自动修复生成器
//!
//! 根据漏洞类型生成修复建议和代码

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 修复建议
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairSuggestion {
    /// 建议唯一标识
    pub id: String,

    /// 漏洞类型
    pub vuln_type: String,

    /// 原始代码
    pub original_code: String,

    /// 修复后的代码
    pub fixed_code: String,

    /// 修复说明
    pub explanation: String,

    /// 置信度 (0.0 - 1.0)
    pub confidence: f32,

    /// 修复策略
    pub strategy: RepairStrategy,

    /// 相关 CWE
    pub cwe: Option<String>,

    /// 参考链接
    pub references: Vec<String>,
}

impl RepairSuggestion {
    /// 创建新的修复建议
    pub fn new(vuln_type: &str, original: &str, fixed: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            vuln_type: vuln_type.to_string(),
            original_code: original.to_string(),
            fixed_code: fixed.to_string(),
            explanation: String::new(),
            confidence: 0.5,
            strategy: RepairStrategy::Manual,
            cwe: None,
            references: Vec::new(),
        }
    }

    /// 设置解释
    pub fn with_explanation(mut self, explanation: &str) -> Self {
        self.explanation = explanation.to_string();
        self
    }

    /// 设置置信度
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// 设置策略
    pub fn with_strategy(mut self, strategy: RepairStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// 设置 CWE
    pub fn with_cwe(mut self, cwe: &str) -> Self {
        self.cwe = Some(cwe.to_string());
        self
    }

    /// 添加参考链接
    pub fn add_reference(mut self, url: &str) -> Self {
        self.references.push(url.to_string());
        self
    }
}

/// 修复策略
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RepairStrategy {
    /// 需要人工审查
    Manual,
    /// 参数化查询
    Parameterization,
    /// 输入验证
    InputValidation,
    /// 输出编码
    OutputEncoding,
    /// 路径规范化
    PathSanitization,
    /// 权限检查
    PermissionCheck,
    /// 加密处理
    Encryption,
    /// 错误处理
    ErrorHandling,
    /// 配置更改
    ConfigurationChange,
}

/// 修复模板
#[derive(Debug, Clone)]
pub struct RepairTemplate {
    /// 模板名称
    pub name: String,

    /// 漏洞类型
    pub vuln_type: String,

    /// 语言
    pub language: String,

    /// 原始代码模式 (正则)
    pub original_pattern: String,

    /// 修复代码模板
    pub fixed_template: String,

    /// 解释
    pub explanation: String,

    /// 策略
    pub strategy: RepairStrategy,

    /// CWE
    pub cwe: Option<String>,
}

impl RepairTemplate {
    /// 创建新的修复模板
    pub fn new(name: &str, vuln_type: &str, language: &str) -> Self {
        Self {
            name: name.to_string(),
            vuln_type: vuln_type.to_string(),
            language: language.to_string(),
            original_pattern: String::new(),
            fixed_template: String::new(),
            explanation: String::new(),
            strategy: RepairStrategy::Manual,
            cwe: None,
        }
    }
}

/// 修复模板库
pub struct RepairTemplateLibrary {
    /// 按漏洞类型索引的模板
    templates: HashMap<String, Vec<RepairTemplate>>,
}

impl RepairTemplateLibrary {
    /// 创建新的模板库
    pub fn new() -> Self {
        let mut library = Self {
            templates: HashMap::new(),
        };
        library.load_builtin_templates();
        library
    }

    /// 加载内置模板
    fn load_builtin_templates(&mut self) {
        // SQL 注入模板
        self.add_sql_injection_templates();

        // XSS 模板
        self.add_xss_templates();

        // 命令注入模板
        self.add_command_injection_templates();

        // 路径遍历模板
        self.add_path_traversal_templates();
    }

    /// 添加 SQL 注入模板
    fn add_sql_injection_templates(&mut self) {
        // Python SQL 注入
        let python_sql = RepairTemplate {
            name: "Python SQL Injection Fix".to_string(),
            vuln_type: "SQL_INJECTION".to_string(),
            language: "python".to_string(),
            original_pattern: r#"cursor\.execute\(["']SELECT.*\+.*["']"#.to_string(),
            fixed_template: r#"cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))"#.to_string(),
            explanation: "使用参数化查询代替字符串拼接，防止 SQL 注入攻击。".to_string(),
            strategy: RepairStrategy::Parameterization,
            cwe: Some("CWE-89".to_string()),
        };
        self.add_template(python_sql);

        // JavaScript SQL 注入
        let js_sql = RepairTemplate {
            name: "JavaScript SQL Injection Fix".to_string(),
            vuln_type: "SQL_INJECTION".to_string(),
            language: "javascript".to_string(),
            original_pattern: r#"query\(["']SELECT.*\$\{.*\}.*["']\)"#.to_string(),
            fixed_template: r#"db.query("SELECT * FROM users WHERE id = $1", [userId])"#.to_string(),
            explanation: "使用参数化查询或预处理语句，避免直接拼接用户输入到 SQL 查询中。".to_string(),
            strategy: RepairStrategy::Parameterization,
            cwe: Some("CWE-89".to_string()),
        };
        self.add_template(js_sql);

        // Rust SQL 注入
        let rust_sql = RepairTemplate {
            name: "Rust SQL Injection Fix".to_string(),
            vuln_type: "SQL_INJECTION".to_string(),
            language: "rust".to_string(),
            original_pattern: r#"format!\("SELECT.*\{.*\}.*""#.to_string(),
            fixed_template: r#"sqlx::query_as!("SELECT * FROM users WHERE id = $1", user_id)"#.to_string(),
            explanation: "使用 sqlx 的编译时检查查询或参数化查询，确保类型安全。".to_string(),
            strategy: RepairStrategy::Parameterization,
            cwe: Some("CWE-89".to_string()),
        };
        self.add_template(rust_sql);
    }

    /// 添加 XSS 模板
    fn add_xss_templates(&mut self) {
        // JavaScript XSS
        let js_xss = RepairTemplate {
            name: "JavaScript XSS Fix (innerHTML)".to_string(),
            vuln_type: "XSS".to_string(),
            language: "javascript".to_string(),
            original_pattern: r#"\.innerHTML\s*=\s*[^;]*\+"#.to_string(),
            fixed_template: r#"element.textContent = userInput; // 或使用 DOMPurify.sanitize()"#.to_string(),
            explanation: "避免使用 innerHTML 直接插入未经验证的用户输入。使用 textContent 或适当的 HTML 编码库。".to_string(),
            strategy: RepairStrategy::OutputEncoding,
            cwe: Some("CWE-79".to_string()),
        };
        self.add_template(js_xss);

        // Python XSS (Flask/Jinja2)
        let python_xss = RepairTemplate {
            name: "Python XSS Fix (Jinja2)".to_string(),
            vuln_type: "XSS".to_string(),
            language: "python".to_string(),
            original_pattern: r#"\{\{\s*.*\|safe\s*\}\}"#.to_string(),
            fixed_template: r#"{{ user_input }}  {# 移除 |safe 过滤器，让 Jinja2 自动转义 #}"#.to_string(),
            explanation: "移除 |safe 过滤器，让模板引擎自动对输出进行 HTML 实体编码。".to_string(),
            strategy: RepairStrategy::OutputEncoding,
            cwe: Some("CWE-79".to_string()),
        };
        self.add_template(python_xss);

        // React XSS
        let react_xss = RepairTemplate {
            name: "React XSS Fix (dangerouslySetInnerHTML)".to_string(),
            vuln_type: "XSS".to_string(),
            language: "typescript".to_string(),
            original_pattern: r#"dangerouslySetInnerHTML.*__html:.*\+"#.to_string(),
            fixed_template: r#"<div>{userInput}</div>  // 或使用 DOMPurify: <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}}"#.to_string(),
            explanation: "避免使用 dangerouslySetInnerHTML，或在使用前用 DOMPurify 清理输入。".to_string(),
            strategy: RepairStrategy::OutputEncoding,
            cwe: Some("CWE-79".to_string()),
        };
        self.add_template(react_xss);
    }

    /// 添加命令注入模板
    fn add_command_injection_templates(&mut self) {
        // Python 命令注入
        let python_cmd = RepairTemplate {
            name: "Python Command Injection Fix".to_string(),
            vuln_type: "COMMAND_INJECTION".to_string(),
            language: "python".to_string(),
            original_pattern: r#"subprocess\..*shell=True"#.to_string(),
            fixed_template: r#"subprocess.run(["ls", "-la", user_input], capture_output=True)"#.to_string(),
            explanation: "避免使用 shell=True，使用列表形式传递参数，防止 shell 元字符注入。".to_string(),
            strategy: RepairStrategy::InputValidation,
            cwe: Some("CWE-78".to_string()),
        };
        self.add_template(python_cmd);

        // Node.js 命令注入
        let node_cmd = RepairTemplate {
            name: "Node.js Command Injection Fix".to_string(),
            vuln_type: "COMMAND_INJECTION".to_string(),
            language: "javascript".to_string(),
            original_pattern: r#"exec\([^)]*\+[^)]*\)"#.to_string(),
            fixed_template: r#"execFile("ls", ["-la", userInput], (error, stdout, stderr) => { ... })"#.to_string(),
            explanation: "使用 execFile 或 spawn 代替 exec，以数组形式传递参数，避免 shell 解析。".to_string(),
            strategy: RepairStrategy::InputValidation,
            cwe: Some("CWE-78".to_string()),
        };
        self.add_template(node_cmd);

        // Rust 命令注入
        let rust_cmd = RepairTemplate {
            name: "Rust Command Injection Fix".to_string(),
            vuln_type: "COMMAND_INJECTION".to_string(),
            language: "rust".to_string(),
            original_pattern: r#"Command::new\("sh"\).arg\("-c"\).arg\(.*format!.*\)"#.to_string(),
            fixed_template: r#"Command::new("ls").arg("-la").arg(&user_input).output()"#.to_string(),
            explanation: "避免通过 shell 执行命令，直接使用 Command 并分别传递参数。".to_string(),
            strategy: RepairStrategy::InputValidation,
            cwe: Some("CWE-78".to_string()),
        };
        self.add_template(rust_cmd);
    }

    /// 添加路径遍历模板
    fn add_path_traversal_templates(&mut self) {
        // 通用路径遍历
        let path_traversal = RepairTemplate {
            name: "Path Traversal Fix".to_string(),
            vuln_type: "PATH_TRAVERSAL".to_string(),
            language: "generic".to_string(),
            original_pattern: r#"open\(.*\+.*filename.*\)"#.to_string(),
            fixed_template: r#"// 1. 规范化路径
let canonical = std::fs::canonicalize(&base_path.join(&user_input))?;
// 2. 检查是否在允许的目录内
if !canonical.starts_with(&base_path) {
    return Err("Path traversal detected");
}"#.to_string(),
            explanation: "使用路径规范化并验证结果路径是否在允许的基础目录内，防止目录遍历攻击。".to_string(),
            strategy: RepairStrategy::PathSanitization,
            cwe: Some("CWE-22".to_string()),
        };
        self.add_template(path_traversal);

        // Python 路径遍历
        let python_path = RepairTemplate {
            name: "Python Path Traversal Fix".to_string(),
            vuln_type: "PATH_TRAVERSAL".to_string(),
            language: "python".to_string(),
            original_pattern: r#"open\(os\.path\.join\(.*request.*\)\)"#.to_string(),
            fixed_template: r#"import os
from pathlib import Path

def safe_join(base_dir, user_path):
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    return target"#.to_string(),
            explanation: "使用 pathlib 进行路径解析和验证，确保目标路径在允许的目录内。".to_string(),
            strategy: RepairStrategy::PathSanitization,
            cwe: Some("CWE-22".to_string()),
        };
        self.add_template(python_path);
    }

    /// 添加模板
    pub fn add_template(&mut self, template: RepairTemplate) {
        self.templates
            .entry(template.vuln_type.clone())
            .or_insert_with(Vec::new)
            .push(template);
    }

    /// 获取漏洞类型的所有模板
    pub fn get_templates(&self, vuln_type: &str) -> Vec<&RepairTemplate> {
        self.templates
            .get(vuln_type)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// 获取漏洞类型和语言匹配的模板
    pub fn get_templates_for_language(&self, vuln_type: &str, language: &str) -> Vec<&RepairTemplate> {
        self.templates
            .get(vuln_type)
            .map(|v| {
                v.iter()
                    .filter(|t| t.language == language || t.language == "generic")
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for RepairTemplateLibrary {
    fn default() -> Self {
        Self::new()
    }
}

/// 修复生成器配置
#[derive(Debug, Clone)]
pub struct RepairConfig {
    /// 最小置信度阈值
    pub min_confidence: f32,

    /// 是否包含参考链接
    pub include_references: bool,

    /// 是否尝试自动匹配模板
    pub auto_match_templates: bool,
}

impl Default for RepairConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            include_references: true,
            auto_match_templates: true,
        }
    }
}

/// 修复生成器
pub struct RepairGenerator {
    /// 模板库
    templates: RepairTemplateLibrary,

    /// 配置
    config: RepairConfig,
}

impl RepairGenerator {
    /// 创建新的修复生成器
    pub fn new() -> Self {
        Self {
            templates: RepairTemplateLibrary::new(),
            config: RepairConfig::default(),
        }
    }

    /// 使用配置创建
    pub fn with_config(config: RepairConfig) -> Self {
        Self {
            templates: RepairTemplateLibrary::new(),
            config,
        }
    }

    /// 生成修复建议
    pub fn generate(
        &self,
        vuln_type: &str,
        original_code: &str,
        language: &str,
    ) -> Vec<RepairSuggestion> {
        let mut suggestions = Vec::new();

        // 从模板库获取匹配的模板
        let templates = self.templates.get_templates_for_language(vuln_type, language);

        for template in templates {
            // 尝试匹配模式
            if self.config.auto_match_templates {
                if let Ok(regex) = regex::Regex::new(&template.original_pattern) {
                    if regex.is_match(original_code) {
                        let suggestion = self.create_suggestion_from_template(
                            template,
                            original_code,
                        );
                        if suggestion.confidence >= self.config.min_confidence {
                            suggestions.push(suggestion);
                        }
                    }
                }
            }
        }

        // 如果没有匹配的模板，生成通用建议
        if suggestions.is_empty() {
            if let Some(generic) = self.generate_generic_suggestion(vuln_type, original_code) {
                suggestions.push(generic);
            }
        }

        // 按置信度排序
        suggestions.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        suggestions
    }

    /// 从模板创建修复建议
    fn create_suggestion_from_template(
        &self,
        template: &RepairTemplate,
        original_code: &str,
    ) -> RepairSuggestion {
        let mut suggestion = RepairSuggestion::new(
            &template.vuln_type,
            original_code,
            &template.fixed_template,
        );

        suggestion.explanation = template.explanation.clone();
        suggestion.strategy = template.strategy.clone();
        suggestion.cwe = template.cwe.clone();
        suggestion.confidence = 0.8; // 模板匹配的置信度较高

        if self.config.include_references {
            if let Some(ref cwe) = suggestion.cwe {
                suggestion.references.push(format!(
                    "https://cwe.mitre.org/data/definitions/{}.html",
                    cwe.replace("CWE-", "")
                ));
            }
        }

        suggestion
    }

    /// 生成通用修复建议
    fn generate_generic_suggestion(&self, vuln_type: &str, original_code: &str) -> Option<RepairSuggestion> {
        let (explanation, strategy, cwe) = match vuln_type {
            "SQL_INJECTION" => (
                "使用参数化查询或预处理语句，避免直接拼接用户输入到 SQL 查询中。",
                RepairStrategy::Parameterization,
                Some("CWE-89".to_string()),
            ),
            "XSS" => (
                "对用户输入进行适当的输出编码，避免直接插入未经验证的内容到 HTML 中。",
                RepairStrategy::OutputEncoding,
                Some("CWE-79".to_string()),
            ),
            "COMMAND_INJECTION" => (
                "避免通过 shell 执行命令，使用安全的 API 并验证用户输入。",
                RepairStrategy::InputValidation,
                Some("CWE-78".to_string()),
            ),
            "PATH_TRAVERSAL" => (
                "规范化路径并验证结果路径是否在允许的目录内。",
                RepairStrategy::PathSanitization,
                Some("CWE-22".to_string()),
            ),
            "SSRF" => (
                "验证和限制用户提供的 URL，使用允许列表而非禁止列表。",
                RepairStrategy::InputValidation,
                Some("CWE-918".to_string()),
            ),
            "XXE" => (
                "禁用 XML 外部实体处理，使用安全的 XML 解析器配置。",
                RepairStrategy::ConfigurationChange,
                Some("CWE-611".to_string()),
            ),
            "CRYPTO_WEAK" => (
                "使用强加密算法（如 AES-256-GCM、ChaCha20-Poly1305）和安全随机数生成器。",
                RepairStrategy::Encryption,
                Some("CWE-327".to_string()),
            ),
            _ => return None,
        };

        let mut suggestion = RepairSuggestion::new(vuln_type, original_code, "// 请参考修复说明进行手动修复");
        suggestion.explanation = explanation.to_string();
        suggestion.strategy = strategy;
        suggestion.cwe = cwe;
        suggestion.confidence = 0.5;

        if self.config.include_references {
            if let Some(ref cwe) = suggestion.cwe {
                suggestion.references.push(format!(
                    "https://cwe.mitre.org/data/definitions/{}.html",
                    cwe.replace("CWE-", "")
                ));
            }
        }

        Some(suggestion)
    }

    /// 获取模板库
    pub fn templates(&self) -> &RepairTemplateLibrary {
        &self.templates
    }

    /// 获取配置
    pub fn config(&self) -> &RepairConfig {
        &self.config
    }
}

impl Default for RepairGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repair_suggestion_creation() {
        let suggestion = RepairSuggestion::new("SQL_INJECTION", "original", "fixed")
            .with_explanation("test")
            .with_confidence(0.9);

        assert_eq!(suggestion.vuln_type, "SQL_INJECTION");
        assert_eq!(suggestion.confidence, 0.9);
    }

    #[test]
    fn test_repair_template_library() {
        let library = RepairTemplateLibrary::new();

        let templates = library.get_templates("SQL_INJECTION");
        assert!(!templates.is_empty());
    }

    #[test]
    fn test_repair_generator_sql_injection() {
        let generator = RepairGenerator::new();

        let vulnerable_code = r#"cursor.execute("SELECT * FROM users WHERE id = " + user_input)"#;
        let suggestions = generator.generate("SQL_INJECTION", vulnerable_code, "python");

        assert!(!suggestions.is_empty());
        let first = &suggestions[0];
        assert_eq!(first.strategy, RepairStrategy::Parameterization);
        assert!(first.cwe.is_some());
    }

    #[test]
    fn test_repair_generator_xss() {
        let generator = RepairGenerator::new();

        let vulnerable_code = r#"element.innerHTML = userInput"#;
        let suggestions = generator.generate("XSS", vulnerable_code, "javascript");

        assert!(!suggestions.is_empty());
    }

    #[test]
    fn test_repair_generator_generic() {
        let generator = RepairGenerator::new();

        let vulnerable_code = "some vulnerable code";
        let suggestions = generator.generate("SQL_INJECTION", vulnerable_code, "unknown_lang");

        assert!(!suggestions.is_empty());
        assert_eq!(suggestions[0].strategy, RepairStrategy::Parameterization);
    }

    #[test]
    fn test_repair_suggestion_confidence_clamp() {
        let suggestion = RepairSuggestion::new("TEST", "", "").with_confidence(1.5);
        assert_eq!(suggestion.confidence, 1.0);

        let suggestion = RepairSuggestion::new("TEST", "", "").with_confidence(-0.5);
        assert_eq!(suggestion.confidence, 0.0);
    }

    #[test]
    fn test_template_language_filtering() {
        let library = RepairTemplateLibrary::new();

        let python_templates = library.get_templates_for_language("SQL_INJECTION", "python");
        assert!(!python_templates.is_empty());

        // 应该包含 python 特定的模板或 generic 模板
        let has_python_or_generic = python_templates
            .iter()
            .any(|t| t.language == "python" || t.language == "generic");
        assert!(has_python_or_generic);
    }
}
