// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 污点分析工具
//!
//! 提供基于 AST 的污点追踪能力，追踪用户输入到危险函数的数据流

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use crate::registry::{Tool, ToolRegistry};
use crate::bridge::{ToolCategory, ToolDefinition, ToolParameter, ToolParameterType, ToolResult, ToolError};

use deepaudit_core::{TaintAnalyzer, EnhancedTaintAnalyzer, AstTaintAnalyzer};

/// 污点追踪工具
///
/// 对指定文件执行污点分析，追踪用户输入到危险函数的数据流
pub struct TraceTaintTool {
    project_path: String,
}

impl TraceTaintTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }

    /// 从文件路径推断语言
    fn infer_language(file_path: &str) -> &str {
        let ext = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext {
            "py" => "python",
            "js" | "jsx" => "javascript",
            "ts" | "tsx" => "typescript",
            "java" => "java",
            "rs" => "rust",
            "go" => "go",
            "c" | "h" => "c",
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "cpp",
            "php" => "php",
            "rb" => "ruby",
            _ => "unknown",
        }
    }
}

#[async_trait]
impl Tool for TraceTaintTool {
    fn name(&self) -> &str {
        "trace_taint"
    }

    fn description(&self) -> &str {
        "执行污点分析，追踪用户输入到危险函数的数据流（如 SQL 注入、命令注入、路径遍历等）"
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
                name: "vulnerability_types".to_string(),
                param_type: ToolParameterType::Array,
                description: "要检测的漏洞类型（可选），如 [\"sql_injection\", \"command_injection\", \"path_traversal\", \"xss\", \"ssrf\"]".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: Some(Box::new(ToolParameter {
                    name: "type".to_string(),
                    param_type: ToolParameterType::String,
                    description: "漏洞类型".to_string(),
                    required: false,
                    default: None,
                    enum_values: Some(vec![
                        serde_json::json!("sql_injection"),
                        serde_json::json!("command_injection"),
                        serde_json::json!("path_traversal"),
                        serde_json::json!("xss"),
                        serde_json::json!("ssrf"),
                        serde_json::json!("code_injection"),
                    ]),
                    format: None,
                    items: None,
                    properties: None,
                })),
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "entry_point".to_string(),
                param_type: ToolParameterType::String,
                description: "入口函数名（可选，默认分析整个文件）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "engine".to_string(),
                param_type: ToolParameterType::String,
                description: "污点分析引擎: \"ast\" (基于AST,默认), \"enhanced\" (变量追踪), \"basic\" (基础文本)".to_string(),
                required: false,
                default: Some(serde_json::json!("ast")),
                enum_values: Some(vec![
                    serde_json::json!("ast"),
                    serde_json::json!("enhanced"),
                    serde_json::json!("basic"),
                ]),
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;

        // 选择分析引擎（默认 "ast"）
        let engine = input["engine"].as_str().unwrap_or("ast").to_lowercase();

        // 构建完整路径
        let full_path = Path::new(&self.project_path).join(file_path);

        // 读取文件内容
        let content = tokio::fs::read_to_string(&full_path)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("无法读取文件 '{}': {}", file_path, e)))?;

        // 推断语言
        let language = Self::infer_language(file_path);

        // 根据引擎类型执行污点分析
        let flows = match engine.as_str() {
            "ast" => {
                // 基于 AST 的污点分析（tree-sitter + CFG + worklist）
                let mut analyzer = AstTaintAnalyzer::new();
                analyzer.analyze_file(&full_path, &content)
            }
            "enhanced" => {
                // 增强的污点分析器（基于变量追踪）
                let analyzer = EnhancedTaintAnalyzer::new();
                analyzer.analyze(&content, file_path, language)
            }
            _ => {
                // 基础文本匹配污点分析器
                let analyzer = TaintAnalyzer::new();
                analyzer.analyze(&content, file_path, language)
            }
        };

        // 过滤漏洞类型
        let vuln_types: Option<Vec<String>> = input["vulnerability_types"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_lowercase())).collect());

        let filtered_flows = if let Some(ref types) = vuln_types {
            flows.into_iter()
                .filter(|flow| {
                    let flow_type = format!("{:?}", flow.vulnerability_type).to_lowercase();
                    types.iter().any(|t| flow_type.contains(&t.to_lowercase().replace("_", "")) ||
                                          t.to_lowercase().replace("_", "").contains(&flow_type.replace("_", "")))
                })
                .collect()
        } else {
            flows
        };

        // 格式化结果
        if filtered_flows.is_empty() {
            return Ok(ToolResult::json(
                serde_json::json!({
                    "flows": [],
                    "count": 0,
                    "message": "未发现污点流"
                }),
                Some("污点分析完成，未发现潜在漏洞".to_string()),
            ));
        }

        // 构建结构化结果
        let results: Vec<serde_json::Value> = filtered_flows.iter().map(|flow| {
            serde_json::json!({
                "id": flow.id,
                "vulnerability_type": format!("{}", flow.vulnerability_type),
                "severity": format!("{}", flow.severity),
                "confidence": flow.confidence,
                "source": {
                    "file": flow.source.file_path,
                    "line": flow.source.line,
                    "symbol": flow.source.symbol,
                    "code": flow.source.code_snippet,
                },
                "sink": {
                    "file": flow.sink.file_path,
                    "line": flow.sink.line,
                    "symbol": flow.sink.symbol,
                    "code": flow.sink.code_snippet,
                },
                "propagation_path": flow.path.iter().map(|node| {
                    serde_json::json!({
                        "type": format!("{:?}", node.node_type),
                        "line": node.line,
                        "symbol": node.symbol,
                        "code": node.code_snippet,
                    })
                }).collect::<Vec<_>>(),
            })
        }).collect();

        // 生成文本摘要
        let mut summary = format!("发现 {} 条污点流:\n\n", filtered_flows.len());
        for (i, flow) in filtered_flows.iter().enumerate() {
            summary.push_str(&format!(
                "{}. {} ({}) - 置信度: {:.0}%\n",
                i + 1,
                flow.vulnerability_type,
                flow.severity,
                flow.confidence * 100.0
            ));
            summary.push_str(&format!(
                "   源: {}:{} ({})\n",
                flow.source.file_path, flow.source.line, flow.source.symbol
            ));
            summary.push_str(&format!(
                "   汇: {}:{} ({})\n\n",
                flow.sink.file_path, flow.sink.line, flow.sink.symbol
            ));
        }

        Ok(ToolResult::json(
            serde_json::json!({
                "flows": results,
                "count": results.len(),
                "summary": summary,
                "file_analyzed": file_path,
                "language": language,
            }),
            Some(summary),
        ))
    }
}

/// 全局污点分析工具
///
/// 对整个项目执行污点分析
pub struct GlobalTaintAnalysisTool {
    project_path: String,
}

impl GlobalTaintAnalysisTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl Tool for GlobalTaintAnalysisTool {
    fn name(&self) -> &str {
        "global_taint_analysis"
    }

    fn description(&self) -> &str {
        "对整个项目执行污点分析，识别所有潜在的污点流"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "path".to_string(),
                param_type: ToolParameterType::String,
                description: "要扫描的目录（相对于项目根目录，默认为根目录）".to_string(),
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
            return Err(ToolError::ExecutionFailed(format!("目录不存在: {}", sub_path)));
        }

        // 收集要分析的文件
        let mut files_to_analyze = Vec::new();
        collect_files(&scan_path, file_pattern, &mut files_to_analyze);

        if files_to_analyze.is_empty() {
            return Ok(ToolResult::text("未找到符合条件的文件".to_string()));
        }

        // 创建基于 AST 的污点分析器
        let mut analyzer = AstTaintAnalyzer::new();
        let mut all_flows = Vec::new();

        // 分析每个文件
        for file_path in &files_to_analyze {
            if let Ok(content) = tokio::fs::read_to_string(file_path).await {
                let relative_path = file_path.strip_prefix(&self.project_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();

                let flows = analyzer.analyze_file(file_path, &content);
                all_flows.extend(flows);
            }
        }

        // 按严重程度排序
        all_flows.sort_by(|a, b| {
            let severity_order = |s: &deepaudit_core::analysis::taint::Severity| match s {
                deepaudit_core::analysis::taint::Severity::Critical => 0,
                deepaudit_core::analysis::taint::Severity::High => 1,
                deepaudit_core::analysis::taint::Severity::Medium => 2,
                deepaudit_core::analysis::taint::Severity::Low => 3,
                deepaudit_core::analysis::taint::Severity::Info => 4,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        // 构建结果
        let summary = format!(
            "全局污点分析完成\n扫描文件: {}\n发现污点流: {}",
            files_to_analyze.len(),
            all_flows.len()
        );

        let results: Vec<serde_json::Value> = all_flows.iter().map(|flow| {
            serde_json::json!({
                "id": flow.id,
                "vulnerability_type": format!("{}", flow.vulnerability_type),
                "severity": format!("{}", flow.severity),
                "confidence": flow.confidence,
                "source_file": flow.source.file_path,
                "source_line": flow.source.line,
                "sink_file": flow.sink.file_path,
                "sink_line": flow.sink.line,
            })
        }).collect();

        Ok(ToolResult::json(
            serde_json::json!({
                "flows": results,
                "total_flows": all_flows.len(),
                "files_scanned": files_to_analyze.len(),
                "summary": summary,
            }),
            Some(summary),
        ))
    }
}

/// 递归收集文件
pub fn collect_files(dir: &Path, pattern: Option<&str>, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // 跳过隐藏目录和常见的非代码目录
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') && !matches!(name, "node_modules" | "target" | "vendor" | "__pycache__" | "dist" | "build") {
                        collect_files(&path, pattern, files);
                    }
                }
            } else if path.is_file() {
                // 检查文件模式
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let matches_pattern = match pattern {
                    Some(p) => {
                        let p_lower = p.to_lowercase().trim_start_matches("*.").to_string();
                        ext.to_lowercase() == p_lower
                    }
                    None => is_code_file(ext),
                };

                if matches_pattern {
                    files.push(path);
                }
            }
        }
    }
}

/// 判断是否是代码文件
fn is_code_file(ext: &str) -> bool {
    matches!(
        ext.to_lowercase().as_str(),
        "py" | "js" | "jsx" | "ts" | "tsx" | "java" | "rs" | "go" | "c" | "cpp" | "h" | "hpp" | "php" | "rb"
    )
}

/// 注册污点分析工具
pub async fn register_taint_tools(
    registry: &Arc<ToolRegistry>,
    project_path: String,
) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(TraceTaintTool::new(project_path.clone())),
        Arc::new(GlobalTaintAnalysisTool::new(project_path)),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register taint analysis tool: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_language() {
        assert_eq!(TraceTaintTool::infer_language("test.py"), "python");
        assert_eq!(TraceTaintTool::infer_language("app.js"), "javascript");
        assert_eq!(TraceTaintTool::infer_language("main.ts"), "typescript");
        assert_eq!(TraceTaintTool::infer_language("App.java"), "java");
        assert_eq!(TraceTaintTool::infer_language("main.rs"), "rust");
        assert_eq!(TraceTaintTool::infer_language("main.go"), "go");
    }

    #[test]
    fn test_is_code_file() {
        assert!(is_code_file("py"));
        assert!(is_code_file("js"));
        assert!(is_code_file("java"));
        assert!(!is_code_file("txt"));
        assert!(!is_code_file("md"));
    }
}
