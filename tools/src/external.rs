// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 外部工具适配器
//!
//! 支持集成外部工具如 Semgrep、Bandit、Gitleaks 等

use async_trait::async_trait;
use std::sync::Arc;
use tokio::process::Command;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::{Tool, ToolRegistry};

/// 外部工具配置
#[derive(Debug, Clone)]
pub struct ExternalToolConfig {
    /// 工具名称
    pub name: String,

    /// 命令路径
    pub command: String,

    /// 参数模板
    pub args_template: Vec<String>,

    /// 工作目录
    pub working_dir: Option<String>,
}

/// 外部工具
pub struct ExternalTool {
    config: ExternalToolConfig,
}

impl ExternalTool {
    /// 创建新的外部工具
    pub fn new(config: ExternalToolConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Tool for ExternalTool {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn description(&self) -> &str {
        "外部扫描工具"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "target".to_string(),
                param_type: ToolParameterType::String,
                description: "扫描目标".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "args".to_string(),
                param_type: ToolParameterType::Object,
                description: "额外参数".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let target = input["target"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 target 参数".to_string()))?;

        // 验证 target 路径（防止路径遍历）
        if target.contains("..") || target.starts_with('/') || target.starts_with('\\') {
            return Err(ToolError::ExecutionFailed(
                "Invalid target path: path traversal detected".to_string(),
            ));
        }

        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args_template);
        cmd.kill_on_drop(true);

        // 添加目标
        cmd.arg(target);

        // 添加额外参数（验证参数名）
        if let Some(args) = input["args"].as_object() {
            for (key, value) in args {
                // 验证参数名只包含安全字符
                if !key
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                    || key.is_empty()
                {
                    return Err(ToolError::ExecutionFailed(format!(
                        "Invalid argument key: {}",
                        key
                    )));
                }
                if let Some(s) = value.as_str() {
                    cmd.arg(format!("--{}", key));
                    cmd.arg(s);
                }
            }
        }

        // 设置工作目录
        if let Some(dir) = &self.config.working_dir {
            cmd.current_dir(dir);
        }

        // 执行命令（带超时）
        let output = tokio::time::timeout(std::time::Duration::from_secs(60), cmd.output())
            .await
            .map_err(|_| ToolError::ExecutionFailed("Command timed out (60s)".to_string()))?
            .map_err(|e| ToolError::ExecutionFailed(format!("执行失败: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(ToolResult::text(stdout))
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            Err(ToolError::ExecutionFailed(stderr))
        }
    }
}

/// 注册常见的外部工具
pub async fn register_common_tools(registry: &Arc<ToolRegistry>, project_path: &str) {
    // Semgrep
    if let Ok(semgrep) = which::which("semgrep") {
        let config = ExternalToolConfig {
            name: "semgrep".to_string(),
            command: semgrep.to_string_lossy().to_string(),
            args_template: vec![
                "--config".to_string(),
                "auto".to_string(),
                "--json".to_string(),
            ],
            working_dir: Some(project_path.to_string()),
        };
        if let Err(e) = registry.register(Arc::new(ExternalTool::new(config))).await {
            tracing::warn!("Failed to register semgrep: {}", e);
        }
    }

    // Bandit (Python)
    if let Ok(bandit) = which::which("bandit") {
        let config = ExternalToolConfig {
            name: "bandit".to_string(),
            command: bandit.to_string_lossy().to_string(),
            args_template: vec!["-f".to_string(), "json".to_string()],
            working_dir: Some(project_path.to_string()),
        };
        if let Err(e) = registry.register(Arc::new(ExternalTool::new(config))).await {
            tracing::warn!("Failed to register bandit: {}", e);
        }
    }

    // Gitleaks
    if let Ok(gitleaks) = which::which("gitleaks") {
        let config = ExternalToolConfig {
            name: "gitleaks".to_string(),
            command: gitleaks.to_string_lossy().to_string(),
            args_template: vec!["detect".to_string(), "--source".to_string()],
            working_dir: Some(project_path.to_string()),
        };
        if let Err(e) = registry.register(Arc::new(ExternalTool::new(config))).await {
            tracing::warn!("Failed to register gitleaks: {}", e);
        }
    }
}
