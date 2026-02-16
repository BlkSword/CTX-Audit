// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 工具模型

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 工具类别
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolCategory {
    File,
    Search,
    Analysis,
    Reporting,
    Custom,
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

    /// 设置执行时长
    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
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
