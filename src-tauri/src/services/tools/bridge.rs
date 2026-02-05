//! 内置工具桥接
//!
//! 实现所有内置的 MCP 工具

use async_trait::async_trait;
use std::path::Path;

use crate::models::tools::{ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult};

/// 读取文件工具
pub struct ReadFileTool {
    project_path: String,
}

impl ReadFileTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl super::registry::Tool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }

    fn description(&self) -> &str {
        "读取文件内容，支持指定行范围"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::File
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "文件路径（相对于项目根目录）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "start_line".to_string(),
                param_type: ToolParameterType::Integer,
                description: "起始行号（从1开始，可选）".to_string(),
                required: false,
                default: Some(serde_json::json!(1)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "end_line".to_string(),
                param_type: ToolParameterType::Integer,
                description: "结束行号（可选）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let file_path = input["file_path"]
            .as_str()
            .ok_or_else(|| ToolError::invalid_argument("缺少 file_path 参数"))?;

        let start_line = input["start_line"].as_u64().map(|v| v as usize).unwrap_or(1);
        let end_line = input["end_line"].as_u64().map(|v| v as usize);

        let full_path = Path::new(&self.project_path).join(file_path);

        // 读取文件
        let content = tokio::fs::read_to_string(&full_path)
            .await
            .map_err(|e| ToolError::internal(format!("无法读取文件: {}", e)))?;

        // 处理行范围
        let lines: Vec<&str> = content.lines().collect();
        let selected_lines = if let Some(end) = end_line {
            if start_line <= end && end <= lines.len() {
                &lines[(start_line - 1)..end]
            } else if start_line <= lines.len() {
                &lines[(start_line - 1)..]
            } else {
                return Err(ToolError::invalid_argument("行号超出范围"));
            }
        } else {
            &lines[(start_line - 1)..]
        };

        let result = selected_lines.join("\n");
        let line_info = if end_line.is_some() {
            format!("行 {}-{}", start_line, end_line.unwrap())
        } else {
            format!("行 {} 到文件末尾", start_line)
        };

        Ok(ToolResult::text(format!(
            "文件: {}\n{}\n\n内容:\n{}",
            file_path, line_info, result
        )))
    }
}

/// 列出文件工具
pub struct ListFilesTool {
    project_path: String,
}

impl ListFilesTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl super::registry::Tool for ListFilesTool {
    fn name(&self) -> &str {
        "list_files"
    }

    fn description(&self) -> &str {
        "列出目录中的文件和子目录"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::File
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "path".to_string(),
                param_type: ToolParameterType::String,
                description: "目录路径（相对于项目根目录，默认为根目录）".to_string(),
                required: false,
                default: Some(serde_json::json!(".")),
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "pattern".to_string(),
                param_type: ToolParameterType::String,
                description: "文件模式过滤器（如 *.rs）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        use futures::stream::{self, StreamExt};

        let path = input["path"].as_str().unwrap_or(".");
        let pattern = input["pattern"].as_str();

        let full_path = Path::new(&self.project_path).join(path);

        let mut entries = Vec::new();
        let mut read_dir = tokio::fs::read_dir(&full_path)
            .await
            .map_err(|e| ToolError::internal(format!("无法读取目录: {}", e)))?;

        while let Some(entry) = read_dir.next_entry().await
            .map_err(|e| ToolError::internal(format!("读取目录失败: {}", e)))? {
            entries.push(Ok::<tokio::fs::DirEntry, std::io::Error>(entry));
        }

        // 排序
        entries.sort_by_key(|e| {
            e.as_ref()
                .map(|e| e.path())
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        });

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ToolError::internal(format!("读取条目失败: {}", e)))?;
            let entry_path = entry.path();

            // 应用模式过滤
            if let Some(pat) = pattern {
                if let Some(file_name) = entry_path.file_name() {
                    if !glob_match(pat, &file_name.to_string_lossy()) {
                        continue;
                    }
                }
            }

            let file_type = if entry_path.is_dir() {
                "DIR"
            } else if entry_path.is_file() {
                "FILE"
            } else {
                "OTHER"
            };

            let name = entry_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?");

            result.push(format!("[{}] {}", file_type, name));
        }

        Ok(ToolResult::text(result.join("\n")))
    }
}

/// 简单的 glob 匹配
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.replace('*', ".*").replace('?', ".");
    let regex = match regex::Regex::new(&format!("^{}$", pattern)) {
        Ok(re) => re,
        Err(_) => return false,
    };
    regex.is_match(text)
}

/// 搜索符号工具
pub struct SearchSymbolTool {
    project_path: String,
}

impl SearchSymbolTool {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl super::registry::Tool for SearchSymbolTool {
    fn name(&self) -> &str {
        "search_symbol"
    }

    fn description(&self) -> &str {
        "在项目中搜索符号定义（函数、类、变量等）"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Search
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "symbol".to_string(),
                param_type: ToolParameterType::String,
                description: "要搜索的符号名称".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let symbol = input["symbol"]
            .as_str()
            .ok_or_else(|| ToolError::invalid_argument("缺少 symbol 参数"))?;

        // TODO: 实现实际的符号搜索
        // 暂时返回占位符
        Ok(ToolResult::text(format!(
            "符号搜索功能待实现: {}",
            symbol
        )))
    }
}

/// 报告漏洞工具
pub struct ReportFindingTool;

#[async_trait]
impl super::registry::Tool for ReportFindingTool {
    fn name(&self) -> &str {
        "report_finding"
    }

    fn description(&self) -> &str {
        "报告发现的安全漏洞"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Reporting
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "title".to_string(),
                param_type: ToolParameterType::String,
                description: "漏洞标题".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "description".to_string(),
                param_type: ToolParameterType::String,
                description: "漏洞描述".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "severity".to_string(),
                param_type: ToolParameterType::String,
                description: "严重程度".to_string(),
                required: true,
                default: Some(serde_json::json!("medium")),
                enum_values: Some(vec![
                    serde_json::json!("critical"),
                    serde_json::json!("high"),
                    serde_json::json!("medium"),
                    serde_json::json!("low"),
                    serde_json::json!("info"),
                ]),
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_path".to_string(),
                param_type: ToolParameterType::String,
                description: "受影响的文件路径".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "line_number".to_string(),
                param_type: ToolParameterType::Integer,
                description: "行号".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        // 验证必需参数
        let title = input["title"]
            .as_str()
            .ok_or_else(|| ToolError::invalid_argument("缺少 title 参数"))?;
        let description = input["description"]
            .as_str()
            .ok_or_else(|| ToolError::invalid_argument("缺少 description 参数"))?;
        let severity = input["severity"]
            .as_str()
            .unwrap_or("medium");
        let file_path = input["file_path"]
            .as_str()
            .ok_or_else(|| ToolError::invalid_argument("缺少 file_path 参数"))?;
        let line_number = input["line_number"]
            .as_u64()
            .ok_or_else(|| ToolError::invalid_argument("缺少或无效的 line_number 参数"))?;

        // 创建漏洞数据
        let finding = crate::models::events::FindingData {
            id: Some(uuid::Uuid::new_v4().to_string()),
            title: Some(title.to_string()),
            description: description.to_string(),
            severity: severity.to_string(),
            category: "other".to_string(),
            cwe_id: None,
            file_path: file_path.to_string(),
            start_line: line_number as u32,
            end_line: None,
            code_snippet: None,
            recommendation: None,
            status: "open".to_string(),
            verification_status: None,
            discovered_by: None,
            extra: Default::default(),
        };

        Ok(ToolResult::json(
            serde_json::to_value(finding).unwrap_or_default(),
            Some(format!("漏洞已报告: {}", title)),
        ))
    }
}

/// 完成分析工具
pub struct FinishAnalysisTool;

#[async_trait]
impl super::registry::Tool for FinishAnalysisTool {
    fn name(&self) -> &str {
        "finish_analysis"
    }

    fn description(&self) -> &str {
        "完成代码分析任务"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Reporting
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "summary".to_string(),
                param_type: ToolParameterType::String,
                description: "分析总结".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "findings_count".to_string(),
                param_type: ToolParameterType::Integer,
                description: "发现的漏洞数量".to_string(),
                required: true,
                default: Some(serde_json::json!(0)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let summary = input["summary"]
            .as_str()
            .ok_or_else(|| ToolError::invalid_argument("缺少 summary 参数"))?;
        let findings_count = input["findings_count"]
            .as_u64()
            .unwrap_or(0);

        Ok(ToolResult::text(format!(
            "分析完成！\n\n总结: {}\n\n共发现 {} 个漏洞",
            summary, findings_count
        )))
    }
}

/// 注册所有内置工具
pub async fn register_built_in_tools(
    registry: &std::sync::Arc<super::registry::ToolRegistry>,
    project_path: String,
) {
    let tools: Vec<std::sync::Arc<dyn super::registry::Tool>> = vec![
        std::sync::Arc::new(ReadFileTool::new(project_path.clone())),
        std::sync::Arc::new(ListFilesTool::new(project_path.clone())),
        std::sync::Arc::new(SearchSymbolTool::new(project_path)),
        std::sync::Arc::new(ReportFindingTool),
        std::sync::Arc::new(FinishAnalysisTool),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register built-in tool: {}", e);
        }
    }
}
