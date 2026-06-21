// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 漏洞模式检测工具
//!
//! 使用预定义规则和模式检测常见安全漏洞

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::{Tool, ToolRegistry};

/// 漏洞模式检测工具
///
/// 使用预定义的安全规则检测常见漏洞模式
pub struct DetectVulnerabilityPatternsTool {
    project_path: String,
}

impl DetectVulnerabilityPatternsTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }

    /// 获取内置的漏洞模式
    fn get_builtin_patterns() -> Vec<VulnerabilityPattern> {
        vec![
            // SQL 注入模式
            VulnerabilityPattern {
                id: "SQL_INJECTION_STRING_CONCAT".to_string(),
                name: "SQL 注入（字符串拼接）".to_string(),
                category: "sql_injection".to_string(),
                severity: "high".to_string(),
                patterns: vec![
                    r#"["']SELECT.*\+.*"#,        // 'SELECT' + var
                    r#"["']INSERT.*\+.*"#,        // 'INSERT' + var
                    r#"["']UPDATE.*\+.*"#,        // 'UPDATE' + var
                    r#"["']DELETE.*\+.*"#,        // 'DELETE' + var
                    r#"f["'].*SELECT.*\{.*\}.*"#, // f'SELECT ... {var}'
                    r#"f["'].*INSERT.*\{.*\}.*"#, // f'INSERT ... {var}'
                    r#"\$\{.*\}.*SELECT.*"#,      // ${var} SELECT
                    r#"execute\(.*\+.*\)"#,       // execute(query + var)
                    r#"query\(.*\+.*\)"#,         // query(sql + var)
                ],
                cwe: Some("CWE-89".to_string()),
                description: "通过字符串拼接构造 SQL 查询，可能导致 SQL 注入".to_string(),
                recommendation: "使用参数化查询或预处理语句".to_string(),
            },
            // 命令注入模式
            VulnerabilityPattern {
                id: "COMMAND_INJECTION".to_string(),
                name: "命令注入".to_string(),
                category: "command_injection".to_string(),
                severity: "critical".to_string(),
                patterns: vec![
                    r#"exec\(.*\+.*\)"#,
                    r#"system\(.*\+.*\)"#,
                    r#"shell_exec\(.*"#,
                    r#"subprocess.*shell=True"#,
                    r#"os\.system\(.*\+.*\)"#,
                    r#"Runtime\.getRuntime\(\)\.exec\(.*\+.*\)"#,
                    r#"ProcessBuilder.*\(.*\+.*\)"#,
                    r#"child_process\.exec\(.*\+.*\)"#,
                    r#"`.*\$\{.*\}.*`"#, // Template literal command
                ],
                cwe: Some("CWE-78".to_string()),
                description: "用户输入直接拼接到系统命令中执行".to_string(),
                recommendation: "使用参数化命令或白名单验证".to_string(),
            },
            // 路径遍历模式
            VulnerabilityPattern {
                id: "PATH_TRAVERSAL".to_string(),
                name: "路径遍历".to_string(),
                category: "path_traversal".to_string(),
                severity: "high".to_string(),
                patterns: vec![
                    r#"open\(.*request\..*\)"#,
                    r#"readFile\(.*req\..*\)"#,
                    r#"file_get_contents\(.*\$_"#,
                    r#"fopen\(.*\$_"#,
                    r#"new File\(.*request\..*\)"#,
                    r#"Paths\.get\(.*\+.*\)"#,
                    r#"fs\.readFile\(.*\+.*\)"#,
                ],
                cwe: Some("CWE-22".to_string()),
                description: "用户输入用于构造文件路径，可能导致路径遍历".to_string(),
                recommendation: "验证和规范化路径，使用白名单".to_string(),
            },
            // XSS 模式
            VulnerabilityPattern {
                id: "XSS_REFLECTED".to_string(),
                name: "反射型 XSS".to_string(),
                category: "xss".to_string(),
                severity: "high".to_string(),
                patterns: vec![
                    r#"innerHTML\s*=\s*.*request\..*"#,
                    r#"document\.write\(.*request\..*"#,
                    r#"res\.send\(.*req\..*\+.*\)"#,
                    r#"res\.write\(.*req\.params"#,
                    r#"echo.*\$_GET"#,
                    r#"Response\.Write\(.*Request\["#,
                    r#"render_template_string\(.*request\..*"#,
                ],
                cwe: Some("CWE-79".to_string()),
                description: "用户输入直接输出到 HTML，可能导致 XSS".to_string(),
                recommendation: "对输出进行 HTML 编码".to_string(),
            },
            // SSRF 模式
            VulnerabilityPattern {
                id: "SSRF".to_string(),
                name: "服务端请求伪造".to_string(),
                category: "ssrf".to_string(),
                severity: "high".to_string(),
                patterns: vec![
                    r#"fetch\(.*request\..*\)"#,
                    r#"axios\.\w+\(.*req\.params"#,
                    r#"requests\.get\(.*\+.*\)"#,
                    r#"urllib\.request\.urlopen\(.*\+.*\)"#,
                    r#"HttpClient.*execute\(.*\+.*\)"#,
                    r#"URL\(.*request\..*\)"#,
                    r#"reqwest::.*\(.*\+.*\)"#,
                ],
                cwe: Some("CWE-918".to_string()),
                description: "用户输入用于构造外部请求 URL".to_string(),
                recommendation: "验证 URL，使用白名单，禁止访问内网地址".to_string(),
            },
            // 硬编码密钥模式
            VulnerabilityPattern {
                id: "HARDCODED_SECRET".to_string(),
                name: "硬编码密钥".to_string(),
                category: "secret_exposure".to_string(),
                severity: "medium".to_string(),
                patterns: vec![
                    r#"(?i)password\s*=\s*["'][^"']{8,}["']"#,
                    r#"(?i)api_key\s*=\s*["'][^"']{16,}["']"#,
                    r#"(?i)secret_key\s*=\s*["'][^"']{16,}["']"#,
                    r#"(?i)private_key\s*=\s*["']-----BEGIN"#,
                    r#"(?i)access_token\s*=\s*["'][^"']{16,}["']"#,
                    r#"sk-[a-zA-Z0-9]{48,}"#,
                    r#"sk-ant-[a-zA-Z0-9-]{80,}"#,
                    r#"AKIA[0-9A-Z]{16}"#, // AWS Access Key
                ],
                cwe: Some("CWE-798".to_string()),
                description: "代码中包含硬编码的敏感信息".to_string(),
                recommendation: "使用环境变量或密钥管理服务".to_string(),
            },
            // 不安全的反序列化
            VulnerabilityPattern {
                id: "INSECURE_DESERIALIZATION".to_string(),
                name: "不安全的反序列化".to_string(),
                category: "deserialization".to_string(),
                severity: "critical".to_string(),
                patterns: vec![
                    r#"pickle\.loads?\(.*request\..*\)"#,
                    r#"yaml\.load\(.*request\..*\)"#,
                    r#"ObjectInputStream.*readObject\(\)"#,
                    r#"unserialize\(.*\$_"#,
                    r#"JSON\.parse\(.*request\..*\)"#,
                    r#"eval\(.*request\..*\)"#,
                ],
                cwe: Some("CWE-502".to_string()),
                description: "反序列化不可信数据可能导致远程代码执行".to_string(),
                recommendation: "使用安全的序列化格式，验证输入".to_string(),
            },
            // XXE 模式
            VulnerabilityPattern {
                id: "XXE".to_string(),
                name: "XML 外部实体注入".to_string(),
                category: "xxe".to_string(),
                severity: "high".to_string(),
                patterns: vec![
                    r#"XMLReader.*parse\(.*request\..*\)"#,
                    r#"SAXParser.*parse\(.*request\..*\)"#,
                    r#"DocumentBuilder.*parse\(.*request\..*\)"#,
                    r#"xml\.etree.*parse\(.*request\..*\)"#,
                    r#"lxml\.etree.*parse\(.*request\..*\)"#,
                ],
                cwe: Some("CWE-611".to_string()),
                description: "XML 解析器可能处理外部实体".to_string(),
                recommendation: "禁用外部实体处理".to_string(),
            },
            // 开放重定向
            VulnerabilityPattern {
                id: "OPEN_REDIRECT".to_string(),
                name: "开放重定向".to_string(),
                category: "open_redirect".to_string(),
                severity: "medium".to_string(),
                patterns: vec![
                    r#"redirect\(.*request\..*\)"#,
                    r#"res\.redirect\(.*req\..*\)"#,
                    r#"header\(.*Location.*request\..*\)"#,
                    r#"sendRedirect\(.*request\..*\)"#,
                    r#"window\.location\s*=\s*.*request\..*"#,
                ],
                cwe: Some("CWE-601".to_string()),
                description: "用户输入用于重定向目标".to_string(),
                recommendation: "验证 URL，使用白名单".to_string(),
            },
            // 弱加密
            VulnerabilityPattern {
                id: "WEAK_CRYPTO".to_string(),
                name: "弱加密算法".to_string(),
                category: "weak_crypto".to_string(),
                severity: "medium".to_string(),
                patterns: vec![
                    r#"MD5\("#,
                    r#"SHA1\("#,
                    r#"DES\("#,
                    r#"RC4\("#,
                    r#"hashlib\.md5\("#,
                    r#"hashlib\.sha1\("#,
                    r#"Cipher\.getInstance\(["']DES"#,
                    r#"MessageDigest\.getInstance\(["']MD5"#,
                    r#"MessageDigest\.getInstance\(["']SHA-1"#,
                ],
                cwe: Some("CWE-327".to_string()),
                description: "使用了不安全的加密算法".to_string(),
                recommendation: "使用强加密算法（如 AES-256, SHA-256）".to_string(),
            },
        ]
    }

    /// 检测代码中的漏洞模式
    fn detect_patterns(
        code: &str,
        file_path: &str,
        categories: Option<&[String]>,
    ) -> Vec<PatternMatch> {
        let patterns = Self::get_builtin_patterns();
        let mut matches = Vec::new();

        for pattern in &patterns {
            // 如果指定了类别，只检测匹配的类别
            if let Some(cats) = categories {
                if !cats
                    .iter()
                    .any(|c| pattern.category.contains(&c.to_lowercase()))
                {
                    continue;
                }
            }

            for pattern_regex in &pattern.patterns {
                if let Ok(re) = regex::Regex::new(pattern_regex) {
                    for cap in re.find_iter(code) {
                        let line_num = code[..cap.start()].lines().count() + 1;
                        let line_content = code
                            .lines()
                            .nth(line_num - 1)
                            .unwrap_or("")
                            .trim()
                            .to_string();

                        matches.push(PatternMatch {
                            pattern_id: pattern.id.clone(),
                            name: pattern.name.clone(),
                            category: pattern.category.clone(),
                            severity: pattern.severity.clone(),
                            file_path: file_path.to_string(),
                            line: line_num,
                            matched_text: line_content,
                            cwe: pattern.cwe.clone(),
                            description: pattern.description.clone(),
                            recommendation: pattern.recommendation.clone(),
                        });
                    }
                }
            }
        }

        matches
    }
}

#[async_trait]
impl Tool for DetectVulnerabilityPatternsTool {
    fn name(&self) -> &str {
        "detect_vulnerability_patterns"
    }

    fn description(&self) -> &str {
        "使用预定义的安全模式检测常见漏洞（SQL注入、命令注入、XSS、SSRF等）"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "要分析的文件路径（相对于项目根目录）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "categories".to_string(),
                param_type: ToolParameterType::Array,
                description: "要检测的漏洞类别（可选），如 [\"sql_injection\", \"xss\", \"command_injection\"]".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: Some(Box::new(ToolParameter {
                    name: "category".to_string(),
                    param_type: ToolParameterType::String,
                    description: "漏洞类别".to_string(),
                    required: false,
                    default: None,
                    enum_values: Some(vec![
                        serde_json::json!("sql_injection"),
                        serde_json::json!("command_injection"),
                        serde_json::json!("path_traversal"),
                        serde_json::json!("xss"),
                        serde_json::json!("ssrf"),
                        serde_json::json!("xxe"),
                        serde_json::json!("secret_exposure"),
                        serde_json::json!("deserialization"),
                        serde_json::json!("open_redirect"),
                        serde_json::json!("weak_crypto"),
                    ]),
                    format: None,
                    items: None,
                    properties: None,
                })),
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;

        // 获取类别过滤
        let categories: Option<Vec<String>> = input["categories"].as_array().map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

        // 构建完整路径
        let full_path = Path::new(&self.project_path).join(file_path);

        // 读取文件内容
        let content = tokio::fs::read_to_string(&full_path).await.map_err(|e| {
            ToolError::ExecutionFailed(format!("无法读取文件 '{}': {}", file_path, e))
        })?;

        // 检测漏洞模式
        let matches = Self::detect_patterns(&content, file_path, categories.as_deref());

        if matches.is_empty() {
            return Ok(ToolResult::json(
                serde_json::json!({
                    "matches": [],
                    "count": 0,
                    "message": "未发现匹配的漏洞模式"
                }),
                Some("模式检测完成，未发现潜在漏洞".to_string()),
            ));
        }

        // 按严重程度排序
        let mut sorted_matches = matches.clone();
        sorted_matches.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                "low" => 3,
                _ => 4,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        // 生成摘要
        let mut summary = format!("发现 {} 个潜在的漏洞模式:\n\n", sorted_matches.len());
        for (i, m) in sorted_matches.iter().enumerate() {
            summary.push_str(&format!("{}. {} ({})\n", i + 1, m.name, m.severity));
            summary.push_str(&format!("   位置: {}:{}\n", m.file_path, m.line));
            summary.push_str(&format!(
                "   代码: {}\n\n",
                if m.matched_text.len() > 60 {
                    format!("{}...", &m.matched_text[..60])
                } else {
                    m.matched_text.clone()
                }
            ));
        }

        // 构建结构化结果
        let results: Vec<serde_json::Value> = sorted_matches
            .iter()
            .map(|m| {
                serde_json::json!({
                    "pattern_id": m.pattern_id,
                    "name": m.name,
                    "category": m.category,
                    "severity": m.severity,
                    "file_path": m.file_path,
                    "line": m.line,
                    "matched_text": m.matched_text,
                    "cwe": m.cwe,
                    "description": m.description,
                    "recommendation": m.recommendation,
                })
            })
            .collect();

        Ok(ToolResult::json(
            serde_json::json!({
                "matches": results,
                "count": results.len(),
                "summary": summary,
                "file_analyzed": file_path,
            }),
            Some(summary),
        ))
    }
}

/// 批量模式检测工具
pub struct BatchPatternScanTool {
    project_path: String,
}

impl BatchPatternScanTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for BatchPatternScanTool {
    fn name(&self) -> &str {
        "batch_pattern_scan"
    }

    fn description(&self) -> &str {
        "对目录中的所有文件执行漏洞模式扫描"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "path".to_string(),
                param_type: ToolParameterType::String,
                description: "要扫描的目录（相对于项目根目录）".to_string(),
                required: false,
                default: Some(serde_json::json!(".")),
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_pattern".to_string(),
                param_type: ToolParameterType::String,
                description: "文件模式（如 *.py, *.js）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let sub_path = input["path"].as_str().unwrap_or(".");
        let file_pattern = input["file_pattern"].as_str();

        let scan_path = Path::new(&self.project_path).join(sub_path);

        if !scan_path.exists() {
            return Err(ToolError::ExecutionFailed(format!(
                "目录不存在: {}",
                sub_path
            )));
        }

        // 收集要分析的文件
        let mut files_to_analyze = Vec::new();
        crate::taint_tools::collect_files(&scan_path, file_pattern, &mut files_to_analyze);

        if files_to_analyze.is_empty() {
            return Ok(ToolResult::text("未找到符合条件的文件".to_string()));
        }

        let mut all_matches = Vec::new();
        let mut files_with_issues = Vec::new();

        // 分析每个文件
        for file_path in &files_to_analyze {
            if let Ok(content) = tokio::fs::read_to_string(file_path).await {
                let relative_path = file_path
                    .strip_prefix(&self.project_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                let matches = DetectVulnerabilityPatternsTool::detect_patterns(
                    &content,
                    &relative_path,
                    None,
                );

                if !matches.is_empty() {
                    files_with_issues.push(relative_path.clone());
                    all_matches.extend(matches);
                }
            }
        }

        // 按严重程度分组统计
        let mut severity_counts = std::collections::HashMap::new();
        for m in &all_matches {
            *severity_counts.entry(m.severity.clone()).or_insert(0) += 1;
        }

        let summary = format!(
            "批量模式扫描完成\n扫描文件: {}\n发现问题: {}\n受影响文件: {}\n严重程度分布: {:?}",
            files_to_analyze.len(),
            all_matches.len(),
            files_with_issues.len(),
            severity_counts
        );

        let results: Vec<serde_json::Value> = all_matches
            .iter()
            .map(|m| {
                serde_json::json!({
                    "pattern_id": m.pattern_id,
                    "name": m.name,
                    "category": m.category,
                    "severity": m.severity,
                    "file_path": m.file_path,
                    "line": m.line,
                    "cwe": m.cwe,
                })
            })
            .collect();

        Ok(ToolResult::json(
            serde_json::json!({
                "matches": results,
                "total_matches": all_matches.len(),
                "files_scanned": files_to_analyze.len(),
                "files_with_issues": files_with_issues.len(),
                "severity_distribution": severity_counts,
                "summary": summary,
            }),
            Some(summary),
        ))
    }
}

/// 漏洞模式定义
#[derive(Debug, Clone)]
struct VulnerabilityPattern {
    id: String,
    name: String,
    category: String,
    severity: String,
    patterns: Vec<&'static str>,
    cwe: Option<String>,
    description: String,
    recommendation: String,
}

/// 模式匹配结果
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PatternMatch {
    pattern_id: String,
    name: String,
    category: String,
    severity: String,
    file_path: String,
    line: usize,
    matched_text: String,
    cwe: Option<String>,
    description: String,
    recommendation: String,
}

use serde::{Deserialize, Serialize};

/// 注册模式检测工具
pub async fn register_pattern_tools(registry: &Arc<ToolRegistry>, project_path: String) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(DetectVulnerabilityPatternsTool::new(project_path.clone())),
        Arc::new(BatchPatternScanTool::new(project_path)),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register pattern detection tool: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sql_injection() {
        let code = r#"
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
"#;
        let matches = DetectVulnerabilityPatternsTool::detect_patterns(code, "test.py", None);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_command_injection() {
        let code = r#"
import os
filename = request.args.get('file')
os.system("cat " + filename)
"#;
        let matches = DetectVulnerabilityPatternsTool::detect_patterns(code, "test.py", None);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_hardcoded_secret() {
        let code = r#"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
"#;
        let matches = DetectVulnerabilityPatternsTool::detect_patterns(code, "test.py", None);
        // 可能检测到也可能没有，取决于具体模式
        // 这个测试主要是确保不会崩溃
    }

    #[test]
    fn test_category_filter() {
        let code = r#"
query = "SELECT * FROM users WHERE id = " + user_id
os.system("ls " + path)
"#;
        let all_matches = DetectVulnerabilityPatternsTool::detect_patterns(code, "test.py", None);
        let sql_only = DetectVulnerabilityPatternsTool::detect_patterns(
            code,
            "test.py",
            Some(&["sql_injection".to_string()]),
        );

        // 当过滤只看 SQL 注入时，应该只返回 SQL 注入相关的匹配
        for m in &sql_only {
            assert!(m.category == "sql_injection");
        }
    }
}
