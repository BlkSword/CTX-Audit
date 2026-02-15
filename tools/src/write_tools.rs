// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 写入工具实现
//!
//! 提供 write_file 和 edit_file 工具，用于创建和编辑文件
//! 包含路径规范化和项目目录限制的安全措施

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::Tool;

/// 路径安全验证器
pub struct PathValidator {
    /// 项目根目录的规范化路径
    project_root: PathBuf,
}

impl PathValidator {
    /// 创建新的路径验证器
    pub fn new(project_path: &str) -> Self {
        let project_root = PathBuf::from(project_path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(project_path));

        Self { project_root }
    }

    /// 验证并规范化路径
    ///
    /// # 安全措施
    /// - 路径规范化（解析 .. 和 .）
    /// - 防止目录遍历攻击
    /// - 确保路径在项目目录内
    pub fn validate_path(&self, relative_path: &str) -> Result<PathBuf, ToolError> {
        // 构建完整路径
        let full_path = self.project_root.join(relative_path);

        // 规范化路径（解析 .. 和 .）
        let canonical_path = full_path
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .map(|p| p.join(full_path.file_name().unwrap_or_default()))
            .unwrap_or(full_path.clone());

        // 对于新文件，父目录可能不存在，所以只检查父目录
        let path_to_check = if canonical_path.exists() {
            canonical_path.clone()
        } else {
            canonical_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| canonical_path.clone())
        };

        // 确保路径在项目目录内（防止目录遍历）
        let canonical_to_check = path_to_check
            .canonicalize()
            .map_err(|e| ToolError::InvalidArgument(format!("路径无效: {}", e)))?;

        if !canonical_to_check.starts_with(&self.project_root) {
            return Err(ToolError::InvalidArgument(
                "路径必须在项目目录内".to_string(),
            ));
        }

        Ok(canonical_path)
    }

    /// 检查文件是否存在
    pub fn file_exists(&self, path: &Path) -> bool {
        path.exists() && path.is_file()
    }

    /// 获取项目根目录
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }
}

// ============================================================================
// WriteFile Tool
// ============================================================================

/// 写入文件工具
pub struct WriteFileTool {
    project_path: String,
    validator: PathValidator,
}

impl WriteFileTool {
    /// 创建新的写入文件工具
    pub fn new(project_path: String) -> Self {
        let validator = PathValidator::new(&project_path);
        Self {
            project_path,
            validator,
        }
    }

    /// 确保父目录存在
    async fn ensure_parent_dir(&self, path: &Path) -> Result<(), ToolError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("无法创建目录: {}", e)))?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Tool for WriteFileTool {
    fn name(&self) -> &str {
        "write_file"
    }

    fn description(&self) -> &str {
        "创建或修改文件内容。支持 overwrite（覆盖）、append（追加）、prepend（前置）三种模式。注意：路径必须在项目目录内。"
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
                name: "content".to_string(),
                param_type: ToolParameterType::String,
                description: "要写入的内容".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "mode".to_string(),
                param_type: ToolParameterType::String,
                description: "写入模式: overwrite(覆盖), append(追加), prepend(前置)".to_string(),
                required: false,
                default: Some(serde_json::json!("overwrite")),
                enum_values: Some(vec![
                    serde_json::json!("overwrite"),
                    serde_json::json!("append"),
                    serde_json::json!("prepend"),
                ]),
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "create_dirs".to_string(),
                param_type: ToolParameterType::Boolean,
                description: "是否自动创建父目录".to_string(),
                required: false,
                default: Some(serde_json::json!(true)),
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

        let content = input["content"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 content 参数".to_string()))?;

        let mode = input["mode"].as_str().unwrap_or("overwrite");
        let create_dirs = input["create_dirs"].as_bool().unwrap_or(true);

        // 验证路径
        let full_path = self.validator.validate_path(file_path)?;

        // 检查文件是否存在
        let file_exists = self.validator.file_exists(&full_path);

        // 对于 append 和 prepend 模式，文件必须存在
        if (mode == "append" || mode == "prepend") && !file_exists {
            return Err(ToolError::InvalidArgument(format!(
                "文件不存在，无法使用 {} 模式: {}",
                mode, file_path
            )));
        }

        // 创建父目录
        if create_dirs {
            self.ensure_parent_dir(&full_path).await?;
        }

        // 根据模式写入内容
        let final_content = match mode {
            "overwrite" => content.to_string(),
            "append" => {
                let existing = tokio::fs::read_to_string(&full_path)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("无法读取文件: {}", e)))?;
                format!("{}{}", existing, content)
            }
            "prepend" => {
                let existing = tokio::fs::read_to_string(&full_path)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("无法读取文件: {}", e)))?;
                format!("{}{}", content, existing)
            }
            _ => {
                return Err(ToolError::InvalidArgument(format!(
                    "无效的写入模式: {}",
                    mode
                )))
            }
        };

        // 写入文件
        tokio::fs::write(&full_path, &final_content)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("无法写入文件: {}", e)))?;

        let action_desc = match mode {
            "overwrite" => if file_exists { "覆盖" } else { "创建" },
            "append" => "追加内容到",
            "prepend" => "在开头插入内容到",
            _ => "写入",
        };

        Ok(ToolResult::json(
            serde_json::json!({
                "file_path": file_path,
                "mode": mode,
                "bytes_written": final_content.len(),
                "created": !file_exists,
            }),
            Some(format!(
                "成功{}文件: {} ({} 字节)",
                action_desc,
                file_path,
                final_content.len()
            )),
        ))
    }
}

// ============================================================================
// EditFile Tool
// ============================================================================

/// 编辑文件工具
pub struct EditFileTool {
    project_path: String,
    validator: PathValidator,
}

impl EditFileTool {
    /// 创建新的编辑文件工具
    pub fn new(project_path: String) -> Self {
        let validator = PathValidator::new(&project_path);
        Self {
            project_path,
            validator,
        }
    }
}

#[async_trait]
impl Tool for EditFileTool {
    fn name(&self) -> &str {
        "edit_file"
    }

    fn description(&self) -> &str {
        "基于字符串替换编辑文件。查找文件中的 old_text 并替换为 new_text。可指定替换所有匹配或仅第一个匹配。"
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
                name: "old_text".to_string(),
                param_type: ToolParameterType::String,
                description: "要查找的文本（必须精确匹配）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "new_text".to_string(),
                param_type: ToolParameterType::String,
                description: "替换后的文本".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "replace_all".to_string(),
                param_type: ToolParameterType::Boolean,
                description: "是否替换所有匹配（true）或仅第一个匹配（false）".to_string(),
                required: false,
                default: Some(serde_json::json!(false)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "create_backup".to_string(),
                param_type: ToolParameterType::Boolean,
                description: "是否创建备份文件（.bak 后缀）".to_string(),
                required: false,
                default: Some(serde_json::json!(true)),
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

        let old_text = input["old_text"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 old_text 参数".to_string()))?;

        let new_text = input["new_text"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 new_text 参数".to_string()))?;

        let replace_all = input["replace_all"].as_bool().unwrap_or(false);
        let create_backup = input["create_backup"].as_bool().unwrap_or(true);

        // 验证路径
        let full_path = self.validator.validate_path(file_path)?;

        // 检查文件是否存在
        if !self.validator.file_exists(&full_path) {
            return Err(ToolError::InvalidArgument(format!(
                "文件不存在: {}",
                file_path
            )));
        }

        // 读取文件内容
        let content = tokio::fs::read_to_string(&full_path)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("无法读取文件: {}", e)))?;

        // 检查是否找到匹配
        if !content.contains(old_text) {
            return Err(ToolError::ExecutionFailed(format!(
                "未找到要替换的文本: {}",
                if old_text.len() > 50 {
                    &old_text[..50]
                } else {
                    old_text
                }
            )));
        }

        // 计算替换次数
        let occurrences = content.matches(old_text).count();

        // 创建备份
        if create_backup {
            let backup_path = format!("{}.bak", full_path.display());
            tokio::fs::copy(&full_path, &backup_path)
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("无法创建备份: {}", e)))?;
        }

        // 执行替换
        let new_content = if replace_all {
            content.replace(old_text, new_text)
        } else {
            // 只替换第一个匹配
            if let Some(pos) = content.find(old_text) {
                let mut result = String::with_capacity(content.len() - old_text.len() + new_text.len());
                result.push_str(&content[..pos]);
                result.push_str(new_text);
                result.push_str(&content[pos + old_text.len()..]);
                result
            } else {
                content
            }
        };

        // 写入文件
        tokio::fs::write(&full_path, &new_content)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("无法写入文件: {}", e)))?;

        let replacements_made = if replace_all { occurrences } else { 1 };

        Ok(ToolResult::json(
            serde_json::json!({
                "file_path": file_path,
                "replacements_made": replacements_made,
                "total_occurrences": occurrences,
                "backup_created": create_backup,
            }),
            Some(format!(
                "成功编辑文件: {}，替换了 {} 处",
                file_path, replacements_made
            )),
        ))
    }
}

// ============================================================================
// 注册函数
// ============================================================================

/// 注册写入工具
pub async fn register_write_tools(registry: &Arc<crate::registry::ToolRegistry>, project_path: String) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(WriteFileTool::new(project_path.clone())),
        Arc::new(EditFileTool::new(project_path)),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register write tool: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_path_validator_valid_path() {
        let validator = PathValidator::new(".");
        let result = validator.validate_path("src/main.rs");
        // 可能文件不存在，但路径应该被规范化
        assert!(result.is_ok() || result.err().unwrap().to_string().contains("路径无效"));
    }

    #[test]
    fn test_path_validator_traversal_attack() {
        let validator = PathValidator::new(".");
        let result = validator.validate_path("../../../etc/passwd");
        // 应该拒绝目录遍历攻击
        assert!(result.is_err());
    }

    #[test]
    fn test_path_validator_absolute_path() {
        let validator = PathValidator::new(".");
        // 绝对路径应该被拒绝（除非它在项目目录内）
        let result = validator.validate_path("/etc/passwd");
        assert!(result.is_err());
    }
}
