// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 污点分析工具
//!
//! 提供基于 AST 的污点追踪能力，追踪用户输入到危险函数的数据流

use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::{Tool, ToolRegistry};

use deepaudit_core::{AstTaintAnalyzer, EnhancedTaintAnalyzer, TaintAnalyzer};

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
        let content = tokio::fs::read_to_string(&full_path).await.map_err(|e| {
            ToolError::ExecutionFailed(format!("无法读取文件 '{}': {}", file_path, e))
        })?;

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
        let vuln_types: Option<Vec<String>> = input["vulnerability_types"].as_array().map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect()
        });

        let filtered_flows = if let Some(ref types) = vuln_types {
            flows
                .into_iter()
                .filter(|flow| {
                    let flow_type = format!("{:?}", flow.vulnerability_type).to_lowercase();
                    types.iter().any(|t| {
                        flow_type.contains(&t.to_lowercase().replace("_", ""))
                            || t.to_lowercase()
                                .replace("_", "")
                                .contains(&flow_type.replace("_", ""))
                    })
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
        let results: Vec<serde_json::Value> = filtered_flows
            .iter()
            .map(|flow| {
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
            })
            .collect();

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
            return Err(ToolError::ExecutionFailed(format!(
                "目录不存在: {}",
                sub_path
            )));
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
                let relative_path = file_path
                    .strip_prefix(&self.project_path)
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

        let results: Vec<serde_json::Value> = all_flows
            .iter()
            .map(|flow| {
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
            })
            .collect();

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

/// 污点状态查询工具（探索向）
///
/// 让 LLM 在链式深审中反向查询引擎污点状态，三种模式：
/// - 模式 A（storage_writes=true）：列出目录下所有"写入持久层"的闸门事件
/// - 模式 B（file_path + variable）：查询变量是否被污染、被谁污染、来源行
/// - 模式 C（仅 file_path）：文件全部污点流 + 污染变量摘要
pub struct QueryTaintTool {
    project_path: String,
}

impl QueryTaintTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }

    /// 与生产扫描一致的分析器（加载 YAML 污点规则，含嵌入回退）
    fn production_analyzer() -> AstTaintAnalyzer {
        AstTaintAnalyzer::new()
    }

    /// 将一条污点流格式化为 JSON
    fn flow_to_json(flow: &deepaudit_core::TaintFlow) -> serde_json::Value {
        serde_json::json!({
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
            "path": flow.path.iter().map(|n| serde_json::json!({
                "line": n.line,
                "symbol": n.symbol,
            })).collect::<Vec<_>>(),
        })
    }

    /// 模式 A：收集目录下全部 StorageWrite 闸门事件
    async fn list_storage_writes(&self, sub_path: &str) -> Result<ToolResult, ToolError> {
        let scan_path = Path::new(&self.project_path).join(sub_path);
        if !scan_path.exists() {
            return Err(ToolError::ExecutionFailed(format!(
                "路径不存在: {}",
                sub_path
            )));
        }

        let mut files = Vec::new();
        collect_files(&scan_path, None, &mut files);

        let analyzer = Self::production_analyzer();
        let mut events = Vec::new();

        for file_path in &files {
            if let Ok(content) = tokio::fs::read_to_string(file_path).await {
                let relative = file_path
                    .strip_prefix(&self.project_path)
                    .unwrap_or(file_path)
                    .to_string_lossy()
                    .to_string();
                let report = analyzer.analyze_file_cpg(file_path, &content);
                for flow in &report.flows {
                    if matches!(
                        flow.vulnerability_type,
                        deepaudit_core::analysis::taint::VulnerabilityType::StorageWrite
                    ) {
                        events.push(serde_json::json!({
                            "file": relative,
                            "line": flow.sink.line,
                            "sink": flow.sink.symbol,
                            "code": flow.sink.code_snippet,
                            "source": flow.source.symbol,
                            "source_line": flow.source.line,
                            "confidence": flow.confidence,
                        }));
                    }
                }
            }
        }

        let summary = format!(
            "扫描 {} 个文件，发现 {} 个持久层写入事件（StorageWrite 闸门）",
            files.len(),
            events.len()
        );
        Ok(ToolResult::json(
            serde_json::json!({
                "storage_writes": events,
                "count": events.len(),
                "files_scanned": files.len(),
            }),
            Some(summary),
        ))
    }

    /// 模式 B/C：单文件污点状态查询
    async fn query_file(
        &self,
        file_path: &str,
        variable: Option<&str>,
    ) -> Result<ToolResult, ToolError> {
        let full_path = Path::new(&self.project_path).join(file_path);
        let content = tokio::fs::read_to_string(&full_path).await.map_err(|e| {
            ToolError::ExecutionFailed(format!("无法读取文件 '{}': {}", file_path, e))
        })?;

        let analyzer = Self::production_analyzer();
        let report = analyzer.analyze_file_cpg(&full_path, &content);

        if let Some(var) = variable {
            // 模式 B：变量反查
            let matches: Vec<serde_json::Value> = report
                .tainted_vars
                .iter()
                .filter(|(k, _)| {
                    k.as_str() == var
                        || k.starts_with(&format!("{}.", var))
                        || k.trim_start_matches('$') == var.trim_start_matches('$')
                })
                .map(|(k, (src, line))| {
                    serde_json::json!({
                        "variable": k,
                        "source_var": src,
                        "source_line": line,
                    })
                })
                .collect();

            // 经过该变量的污点流（路径任一节点符号匹配）
            let related_flows: Vec<serde_json::Value> = report
                .flows
                .iter()
                .filter(|f| {
                    f.source.symbol.contains(var)
                        || f.sink.symbol.contains(var)
                        || f.path.iter().any(|n| n.symbol.contains(var))
                })
                .map(Self::flow_to_json)
                .collect();

            let tainted = !matches.is_empty();
            let summary = if tainted {
                let (src, line) = &report.tainted_vars[matches[0]["variable"].as_str().unwrap_or(var)];
                format!(
                    "变量 '{}' 已被污染（来源: {}，第 {} 行），经过它的污点流: {} 条",
                    var,
                    src,
                    line,
                    related_flows.len()
                )
            } else {
                format!("变量 '{}' 未被污染（分析覆盖的函数体内无污点来源）", var)
            };

            Ok(ToolResult::json(
                serde_json::json!({
                    "file": file_path,
                    "variable": var,
                    "tainted": tainted,
                    "taint_entries": matches,
                    "related_flows": related_flows,
                    "related_flow_count": related_flows.len(),
                }),
                Some(summary),
            ))
        } else {
            // 模式 C：文件级摘要
            let tainted_list: Vec<serde_json::Value> = report
                .tainted_vars
                .iter()
                .map(|(k, (src, line))| {
                    serde_json::json!({
                        "variable": k,
                        "source_var": src,
                        "source_line": line,
                    })
                })
                .collect();
            let flows: Vec<serde_json::Value> =
                report.flows.iter().map(Self::flow_to_json).collect();

            let summary = format!(
                "文件 {}: {} 个被污染变量，{} 条污点流",
                file_path,
                tainted_list.len(),
                flows.len()
            );
            Ok(ToolResult::json(
                serde_json::json!({
                    "file": file_path,
                    "tainted_vars": tainted_list,
                    "flows": flows,
                    "flow_count": flows.len(),
                }),
                Some(summary),
            ))
        }
    }
}

#[async_trait]
impl Tool for QueryTaintTool {
    fn name(&self) -> &str {
        "query_taint"
    }

    fn description(&self) -> &str {
        "查询污点状态：变量是否被污染（被谁污染、来源行）、列出项目内所有持久层写入事件。用于链式深审中反向确认引擎污点结论"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "要查询的文件路径（相对于项目根目录）。与 variable 配合做变量反查；单独使用返回文件污点摘要".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "variable".to_string(),
                param_type: ToolParameterType::String,
                description: "要反查的变量名（如 \"name\"、\"$commentId\"），需配合 file_path".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "storage_writes".to_string(),
                param_type: ToolParameterType::Boolean,
                description: "为 true 时列出 path 目录下所有持久层写入事件（StorageWrite 闸门），用于寻找二阶漏洞的存储点".to_string(),
                required: false,
                default: Some(serde_json::json!(false)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "path".to_string(),
                param_type: ToolParameterType::String,
                description: "storage_writes 模式下要扫描的目录（相对于项目根目录，默认为根目录）".to_string(),
                required: false,
                default: Some(serde_json::json!(".")),
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let storage_writes = input["storage_writes"].as_bool().unwrap_or(false);
        let file_path = input["file_path"].as_str();
        let variable = input["variable"].as_str();

        if storage_writes {
            let sub_path = input["path"].as_str().unwrap_or(".");
            return self.list_storage_writes(sub_path).await;
        }

        match file_path {
            Some(fp) => self.query_file(fp, variable).await,
            None => Err(ToolError::InvalidArgument(
                "缺少 file_path 参数（或将 storage_writes 设为 true 列出持久层写入事件）".to_string(),
            )),
        }
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
                    if !name.starts_with('.')
                        && !matches!(
                            name,
                            "node_modules" | "target" | "vendor" | "__pycache__" | "dist" | "build"
                        )
                    {
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
        "py" | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "java"
            | "rs"
            | "go"
            | "c"
            | "cpp"
            | "h"
            | "hpp"
            | "php"
            | "rb"
    )
}

/// 注册污点分析工具
pub async fn register_taint_tools(registry: &Arc<ToolRegistry>, project_path: String) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(TraceTaintTool::new(project_path.clone())),
        Arc::new(GlobalTaintAnalysisTool::new(project_path.clone())),
        Arc::new(QueryTaintTool::new(project_path)),
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
