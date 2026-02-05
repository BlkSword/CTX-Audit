//! 工具系统数据模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 工具参数类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolParameterType {
    /// 字符串
    String,
    /// 数字
    Number,
    /// 整数
    Integer,
    /// 布尔值
    Boolean,
    /// 数组
    Array,
    /// 对象
    Object,
    /// 空值
    Null,
}

impl std::fmt::Display for ToolParameterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolParameterType::String => write!(f, "string"),
            ToolParameterType::Number => write!(f, "number"),
            ToolParameterType::Integer => write!(f, "integer"),
            ToolParameterType::Boolean => write!(f, "boolean"),
            ToolParameterType::Array => write!(f, "array"),
            ToolParameterType::Object => write!(f, "object"),
            ToolParameterType::Null => write!(f, "null"),
        }
    }
}

/// 工具参数定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolParameter {
    /// 参数名称
    pub name: String,

    /// 参数类型
    #[serde(rename = "type")]
    pub param_type: ToolParameterType,

    /// 参数描述
    pub description: String,

    /// 是否必需
    pub required: bool,

    /// 默认值
    pub default: Option<serde_json::Value>,

    /// 枚举值（可选）
    pub enum_values: Option<Vec<serde_json::Value>>,

    /// 格式说明（可选）
    pub format: Option<String>,

    /// 数组元素类型（当类型为数组时）
    pub items: Option<Box<ToolParameter>>,

    /// 对象属性（当类型为对象时）
    pub properties: Option<HashMap<String, ToolParameter>>,
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

    /// 输入参数
    pub input_schema: ToolInputSchema,

    /// 是否异步执行
    pub async_exec: bool,

    /// 超时时间（秒）
    pub timeout_seconds: Option<u64>,

    /// 额外元数据
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

/// 工具输入 Schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInputSchema {
    /// 参数类型
    #[serde(rename = "type")]
    pub schema_type: String,

    /// 参数定义
    pub properties: HashMap<String, ToolParameter>,

    /// 必需参数列表
    pub required: Vec<String>,
}

impl Default for ToolInputSchema {
    fn default() -> Self {
        Self {
            schema_type: "object".to_string(),
            properties: HashMap::new(),
            required: Vec::new(),
        }
    }
}

impl ToolDefinition {
    /// 创建简单的工具定义
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        category: ToolCategory,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            category,
            input_schema: ToolInputSchema::default(),
            async_exec: true,
            timeout_seconds: Some(60),
            metadata: None,
        }
    }

    /// 添加参数
    pub fn add_parameter(mut self, param: ToolParameter) -> Self {
        if param.required {
            self.input_schema.required.push(param.name.clone());
        }
        self.input_schema
            .properties
            .insert(param.name.clone(), param);
        self
    }

    /// 转换为 OpenAI 函数调用格式
    pub fn to_openai_format(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": self.input_schema.schema_type,
                    "properties": self.input_schema.properties,
                    "required": self.input_schema.required
                }
            }
        })
    }

    /// 转换为 Anthropic 工具格式
    pub fn to_anthropic_format(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": self.input_schema.schema_type,
                "properties": self.input_schema.properties,
                "required": self.input_schema.required
            }
        })
    }
}

/// 工具类别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// 文件操作
    File,
    /// 代码分析
    CodeAnalysis,
    /// AST 操作
    Ast,
    /// 搜索
    Search,
    /// 外部工具
    External,
    /// 漏洞报告
    Reporting,
    /// 系统操作
    System,
    /// 向量搜索
    VectorSearch,
    /// 自定义
    Custom,
}

impl std::fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolCategory::File => write!(f, "file"),
            ToolCategory::CodeAnalysis => write!(f, "code_analysis"),
            ToolCategory::Ast => write!(f, "ast"),
            ToolCategory::Search => write!(f, "search"),
            ToolCategory::External => write!(f, "external"),
            ToolCategory::Reporting => write!(f, "reporting"),
            ToolCategory::System => write!(f, "system"),
            ToolCategory::VectorSearch => write!(f, "vector_search"),
            ToolCategory::Custom => write!(f, "custom"),
        }
    }
}

/// 工具执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// 结果内容
    pub content: Vec<ToolContent>,

    /// 是否是错误
    pub is_error: bool,

    /// 执行时长（毫秒）
    pub duration_ms: Option<u64>,

    /// 元数据
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl ToolResult {
    /// 创建文本结果
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ToolContent::Text {
                text: text.into(),
            }],
            is_error: false,
            duration_ms: None,
            metadata: None,
        }
    }

    /// 检查结果是否成功（非错误）
    pub fn is_ok(&self) -> bool {
        !self.is_error
    }

    /// 创建 JSON 结果
    pub fn json(data: serde_json::Value, description: Option<String>) -> Self {
        let mut content = vec![ToolContent::Data { data }];
        if let Some(desc) = description {
            content.insert(0, ToolContent::Text { text: desc });
        }
        Self {
            content,
            is_error: false,
            duration_ms: None,
            metadata: None,
        }
    }

    /// 创建错误结果
    pub fn error(message: impl Into<String>, code: Option<String>) -> Self {
        let mut msg = message.into();
        if let Some(c) = code {
            msg = format!("[{}] {}", c, msg);
        }
        Self {
            content: vec![ToolContent::Text { text: msg }],
            is_error: true,
            duration_ms: None,
            metadata: None,
        }
    }

    /// 获取主要文本
    pub fn get_text(&self) -> String {
        self.content
            .iter()
            .filter_map(|c| match c {
                ToolContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 设置执行时长
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    /// 设置元数据
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// 工具内容类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolContent {
    /// 文本内容
    Text { text: String },
    /// JSON 数据
    Data { data: serde_json::Value },
    /// 文件路径
    File { path: String },
    /// 图片
    Image {
        /// 图片格式
        format: String,
        /// Base64 数据
        data: String,
    },
}

/// 工具错误码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolErrorCode {
    /// 无效参数
    InvalidArgument,
    /// 未找到
    NotFound,
    /// 权限拒绝
    PermissionDenied,
    /// 内部错误
    InternalError,
    /// 网络错误
    NetworkError,
    /// 超时
    Timeout,
    /// 不支持的操作
    UnsupportedOperation,
}

impl std::fmt::Display for ToolErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolErrorCode::InvalidArgument => write!(f, "INVALID_ARGUMENT"),
            ToolErrorCode::NotFound => write!(f, "NOT_FOUND"),
            ToolErrorCode::PermissionDenied => write!(f, "PERMISSION_DENIED"),
            ToolErrorCode::InternalError => write!(f, "INTERNAL_ERROR"),
            ToolErrorCode::NetworkError => write!(f, "NETWORK_ERROR"),
            ToolErrorCode::Timeout => write!(f, "TIMEOUT"),
            ToolErrorCode::UnsupportedOperation => write!(f, "UNSUPPORTED_OPERATION"),
        }
    }
}

/// 工具执行错误
#[derive(Debug, Serialize, Deserialize, thiserror::Error)]
#[error("工具错误 [{code}]: {message}")]
pub struct ToolError {
    /// 错误码
    pub code: ToolErrorCode,

    /// 错误消息
    pub message: String,

    /// 工具名称
    pub tool_name: Option<String>,

    /// 源错误
    #[serde(skip)]
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Clone for ToolError {
    fn clone(&self) -> Self {
        Self {
            code: self.code,
            message: self.message.clone(),
            tool_name: self.tool_name.clone(),
            source: None, // Cannot clone Error trait object
        }
    }
}

impl ToolError {
    /// 创建新错误
    pub fn new(code: ToolErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            tool_name: None,
            source: None,
        }
    }

    /// 设置工具名称
    pub fn with_tool_name(mut self, name: impl Into<String>) -> Self {
        self.tool_name = Some(name.into());
        self
    }

    /// 无效参数错误
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::InvalidArgument, message)
    }

    /// 未找到错误
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::NotFound, message)
    }

    /// 权限拒绝错误
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::PermissionDenied, message)
    }

    /// 内部错误
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::InternalError, message)
    }

    /// 超时错误
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(ToolErrorCode::Timeout, message)
    }
}

/// 外部工具适配器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalToolConfig {
    /// 工具名称
    pub tool_name: String,

    /// 可执行文件路径
    pub executable_path: String,

    /// 参数模板
    pub args_template: Vec<String>,

    /// 工作目录
    pub working_dir: Option<String>,

    /// 环境变量
    pub env_vars: Option<HashMap<String, String>>,

    /// 超时时间（秒）
    pub timeout_seconds: u64,

    /// 是否启用
    pub enabled: bool,
}

impl Default for ExternalToolConfig {
    fn default() -> Self {
        Self {
            tool_name: String::new(),
            executable_path: String::new(),
            args_template: Vec::new(),
            working_dir: None,
            env_vars: None,
            timeout_seconds: 300,
            enabled: true,
        }
    }
}
