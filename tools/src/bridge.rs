// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 内置工具桥接
//!
//! 实现所有内置的工具

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use crate::registry::{Tool, ToolRegistry};

// 工具模型定义（避免循环依赖）

/// 工具类别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolCategory {
    File,
    Search,
    Analysis,
    Reporting,
    Custom,
}

/// 工具参数类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolParameterType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
}

/// 工具定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// 工具名称
    pub name: String,

    /// 工具描述
    pub description: String,

    /// 工具类别
    pub category: ToolCategory,

    /// 参数定义
    pub parameters: Vec<ToolParameter>,
}

impl ToolDefinition {
    /// 创建新的工具定义
    pub fn new(name: &str, description: &str, category: ToolCategory) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            category,
            parameters: Vec::new(),
        }
    }

    /// 添加参数
    pub fn add_parameter(mut self, param: ToolParameter) -> Self {
        self.parameters.push(param);
        self
    }
}

/// 工具参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameter {
    /// 参数名称
    pub name: String,

    /// 参数类型
    pub param_type: ToolParameterType,

    /// 参数描述
    pub description: String,

    /// 是否必需
    pub required: bool,

    /// 默认值
    pub default: Option<serde_json::Value>,

    /// 枚举值
    pub enum_values: Option<Vec<serde_json::Value>>,

    /// 格式
    pub format: Option<String>,

    /// 数组项类型
    pub items: Option<Box<ToolParameter>>,

    /// 对象属性
    pub properties: Option<HashMap<String, ToolParameter>>,
}

/// 工具执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// 结果文本
    pub text: String,

    /// 是否是错误
    pub is_error: bool,

    /// 错误代码
    pub error_code: Option<String>,

    /// 执行时长（毫秒）
    pub duration_ms: Option<u64>,

    /// 结果数据
    pub data: Option<serde_json::Value>,
}

impl ToolResult {
    /// 创建文本结果
    pub fn text(text: String) -> Self {
        Self {
            text,
            is_error: false,
            error_code: None,
            duration_ms: None,
            data: None,
        }
    }

    /// 创建 JSON 结果
    pub fn json(data: serde_json::Value, message: Option<String>) -> Self {
        let text = message.unwrap_or_else(|| serde_json::to_string(&data).unwrap_or_default());
        Self {
            text,
            is_error: false,
            error_code: None,
            duration_ms: None,
            data: Some(data),
        }
    }

    /// 创建错误结果
    pub fn error(text: String, code: Option<String>) -> Self {
        Self {
            text,
            is_error: true,
            error_code: code,
            duration_ms: None,
            data: None,
        }
    }

    /// 获取结果文本
    pub fn get_text(&self) -> &str {
        &self.text
    }
}

/// 工具错误
#[derive(Debug, Clone, thiserror::Error)]
pub enum ToolError {
    #[error("参数错误: {0}")]
    InvalidArgument(String),

    #[error("执行失败: {0}")]
    ExecutionFailed(String),

    #[error("未找到工具: {0}")]
    ToolNotFound(String),

    #[error("代码: {0:?}")]
    Code(ToolErrorCode),
}

/// 工具错误代码
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolErrorCode {
    InvalidInput,
    NotFound,
    PermissionDenied,
    Timeout,
    Internal,
}

/// 漏洞数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingData {
    /// 漏洞 ID
    pub id: Option<String>,

    /// 漏洞标题
    pub title: Option<String>,

    /// 漏洞描述
    pub description: String,

    /// 严重程度
    pub severity: String,

    /// 类别
    pub category: String,

    /// CWE ID
    pub cwe_id: Option<String>,

    /// 文件路径
    pub file_path: String,

    /// 起始行号
    pub start_line: u32,

    /// 结束行号
    pub end_line: Option<u32>,

    /// 代码片段
    pub code_snippet: Option<String>,

    /// 修复建议
    pub recommendation: Option<String>,

    /// 状态
    pub status: String,

    /// 验证状态
    pub verification_status: Option<String>,

    /// 发现者
    pub discovered_by: Option<String>,

    /// 额外信息
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

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
impl Tool for ReadFileTool {
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
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;

        let start_line = input["start_line"].as_u64().map(|v| v as usize).unwrap_or(1);
        let end_line = input["end_line"].as_u64().map(|v| v as usize);

        let full_path = Path::new(&self.project_path).join(file_path);

        // 读取文件
        let content = tokio::fs::read_to_string(&full_path)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("无法读取文件: {}", e)))?;

        // 处理行范围
        let lines: Vec<&str> = content.lines().collect();
        let selected_lines = if let Some(end) = end_line {
            if start_line <= end && end <= lines.len() {
                &lines[(start_line - 1)..end]
            } else if start_line <= lines.len() {
                &lines[(start_line - 1)..]
            } else {
                return Err(ToolError::InvalidArgument("行号超出范围".to_string()));
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
impl Tool for ListFilesTool {
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
        let path = input["path"].as_str().unwrap_or(".");
        let pattern = input["pattern"].as_str();

        let full_path = Path::new(&self.project_path).join(path);

        let mut entries = tokio::fs::read_dir(&full_path)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("无法读取目录: {}", e)))?;

        let mut result = Vec::new();
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| ToolError::ExecutionFailed(format!("读取目录失败: {}", e)))? {
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

        // 排序
        result.sort();

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

/// 报告漏洞工具
pub struct ReportFindingTool;

#[async_trait]
impl Tool for ReportFindingTool {
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
        use std::collections::HashMap;

        // 验证必需参数
        let title = input["title"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 title 参数".to_string()))?;
        let description = input["description"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 description 参数".to_string()))?;
        let severity = input["severity"]
            .as_str()
            .unwrap_or("medium");
        let file_path = input["file_path"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 file_path 参数".to_string()))?;
        let line_number = input["line_number"]
            .as_u64()
            .ok_or_else(|| ToolError::InvalidArgument("缺少或无效的 line_number 参数".to_string()))?;

        // 创建漏洞数据
        let finding = FindingData {
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
            extra: HashMap::new(),
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
impl Tool for FinishAnalysisTool {
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
            .ok_or_else(|| ToolError::InvalidArgument("缺少 summary 参数".to_string()))?;
        let findings_count = input["findings_count"].as_u64().unwrap_or(0);

        Ok(ToolResult::text(format!(
            "分析完成！\n\n总结: {}\n\n共发现 {} 个漏洞",
            summary, findings_count
        )))
    }
}

/// 注册所有内置工具
pub async fn register_built_in_tools(
    registry: &Arc<ToolRegistry>,
    project_path: String,
) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(ReadFileTool::new(project_path.clone())),
        Arc::new(ListFilesTool::new(project_path.clone())),
        Arc::new(ReportFindingTool),
        Arc::new(FinishAnalysisTool),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register built-in tool: {}", e);
        }
    }
}

/// 注册所有内置工具（包括 AST 工具）
pub async fn register_all_tools(
    registry: &Arc<ToolRegistry>,
    project_path: String,
    ast_engine: Option<std::sync::Arc<deepaudit_core::ASTEngine>>,
) {
    // 先注册基础工具
    register_built_in_tools(registry, project_path.clone()).await;

    // 如果提供了 AST 引擎，注册 AST 工具
    if let Some(engine) = ast_engine {
        crate::ast_tools::register_ast_tools(registry, project_path, engine).await;
    }
}
