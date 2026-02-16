// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Shell 执行工具实现
//!
//! 提供安全的 Shell 命令执行能力，采用白名单模式
//! 只允许预定义的安全命令，并有超时和输出大小限制

use async_trait::async_trait;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::Tool;

/// Shell 工具配置
#[derive(Debug, Clone)]
pub struct ShellConfig {
    /// 允许的命令白名单
    pub allowed_commands: HashSet<String>,

    /// 命令执行超时（秒）
    pub timeout_secs: u64,

    /// 最大输出大小（字节）
    pub max_output_bytes: usize,

    /// 是否允许参数
    pub allow_arguments: bool,

    /// 是否允许环境变量
    pub allow_env_vars: bool,

    /// 额外的允许环境变量
    pub allowed_env_vars: HashSet<String>,
}

impl Default for ShellConfig {
    fn default() -> Self {
        // 默认允许的安全命令
        let allowed_commands: HashSet<String> = [
            // 包管理器
            "npm".to_string(),
            "yarn".to_string(),
            "pnpm".to_string(),
            "pip".to_string(),
            "pip3".to_string(),
            "cargo".to_string(),
            // 版本控制
            "git".to_string(),
            // 构建工具
            "make".to_string(),
            "cmake".to_string(),
            // 代码分析工具
            "semgrep".to_string(),
            "bandit".to_string(),
            "gitleaks".to_string(),
            // 其他安全工具
            "trivy".to_string(),
            "safety".to_string(),
            "npm-audit".to_string(),
            "yarn-audit".to_string(),
        ]
        .into_iter()
        .collect();

        let allowed_env_vars: HashSet<String> = [
            "PATH".to_string(),
            "HOME".to_string(),
            "USER".to_string(),
            "TEMP".to_string(),
            "TMP".to_string(),
            "LANG".to_string(),
            "LC_ALL".to_string(),
            // Node.js 相关
            "NODE_PATH".to_string(),
            "NPM_CONFIG_CACHE".to_string(),
            // Python 相关
            "PYTHONPATH".to_string(),
            "VIRTUAL_ENV".to_string(),
            // Rust 相关
            "CARGO_HOME".to_string(),
            "RUSTUP_HOME".to_string(),
        ]
        .into_iter()
        .collect();

        Self {
            allowed_commands,
            timeout_secs: 60,
            max_output_bytes: 1024 * 1024, // 1MB
            allow_arguments: true,
            allow_env_vars: false,
            allowed_env_vars,
        }
    }
}

impl ShellConfig {
    /// 创建新的 Shell 配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加允许的命令
    pub fn with_allowed_command(mut self, command: &str) -> Self {
        self.allowed_commands.insert(command.to_lowercase());
        self
    }

    /// 设置超时
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// 设置最大输出大小
    pub fn with_max_output(mut self, bytes: usize) -> Self {
        self.max_output_bytes = bytes;
        self
    }

    /// 检查命令是否被允许
    pub fn is_command_allowed(&self, command: &str) -> bool {
        // 提取命令名（不含路径）
        let command_name = Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command)
            .to_lowercase();

        self.allowed_commands.contains(&command_name)
    }
}

/// Shell 执行工具
pub struct ShellTool {
    project_path: String,
    config: Arc<RwLock<ShellConfig>>,
}

impl ShellTool {
    /// 创建新的 Shell 工具
    pub fn new(project_path: String) -> Self {
        Self {
            project_path,
            config: Arc::new(RwLock::new(ShellConfig::default())),
        }
    }

    /// 使用自定义配置创建 Shell 工具
    pub fn with_config(project_path: String, config: ShellConfig) -> Self {
        Self {
            project_path,
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// 执行命令
    async fn execute_command(
        &self,
        command: &str,
        args: &[String],
        working_dir: Option<&str>,
        env_vars: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<(String, String, bool), ToolError> {
        let config = self.config.read().await;

        // 验证命令是否被允许
        if !config.is_command_allowed(command) {
            let allowed: Vec<_> = config.allowed_commands.iter().cloned().collect();
            return Err(ToolError::InvalidArgument(format!(
                "命令 '{}' 不在允许列表中。允许的命令: {}",
                command,
                allowed.join(", ")
            )));
        }

        // 构建工作目录
        let work_dir = if let Some(dir) = working_dir {
            let full_path = Path::new(&self.project_path).join(dir);
            // 验证路径在项目目录内
            let canonical = full_path
                .canonicalize()
                .map_err(|e| ToolError::InvalidArgument(format!("无效的工作目录: {}", e)))?;
            let project_canonical = Path::new(&self.project_path)
                .canonicalize()
                .unwrap_or_else(|_| Path::new(&self.project_path).to_path_buf());
            if !canonical.starts_with(&project_canonical) {
                return Err(ToolError::InvalidArgument(
                    "工作目录必须在项目目录内".to_string(),
                ));
            }
            canonical
        } else {
            Path::new(&self.project_path).to_path_buf()
        };

        // 构建命令
        let mut cmd = Command::new(command);
        cmd.args(args)
            .current_dir(&work_dir)
            .kill_on_drop(true); // 确保超时时杀死进程

        // 添加环境变量（如果允许）
        if config.allow_env_vars {
            if let Some(vars) = env_vars {
                for (key, value) in vars {
                    if config.allowed_env_vars.contains(key) {
                        cmd.env(key, value);
                    }
                }
            }
        }

        // 执行命令并捕获输出
        let timeout_duration = Duration::from_secs(config.timeout_secs);
        let max_output = config.max_output_bytes;

        let result = timeout(timeout_duration, async {
            // 启动进程
            let mut child = cmd
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| ToolError::ExecutionFailed(format!("无法启动命令: {}", e)))?;

            // 读取输出
            let mut stdout = String::new();
            let mut stderr = String::new();

            if let Some(mut stdout_handle) = child.stdout.take() {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stdout_handle.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stdout.len() + n > max_output {
                                stdout.push_str("\n... [输出被截断，超过大小限制]");
                                break;
                            }
                            if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                                stdout.push_str(s);
                            }
                        }
                        Err(e) => {
                            stderr.push_str(&format!("\n读取输出错误: {}", e));
                            break;
                        }
                    }
                }
            }

            if let Some(mut stderr_handle) = child.stderr.take() {
                let mut buf = vec![0u8; 8192];
                loop {
                    match stderr_handle.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stderr.len() + n > max_output {
                                stderr.push_str("\n... [错误输出被截断，超过大小限制]");
                                break;
                            }
                            if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                                stderr.push_str(s);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }

            // 等待进程完成
            let status = child
                .wait()
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("等待进程失败: {}", e)))?;

            Ok((stdout, stderr, status.success()))
        })
        .await;

        match result {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(ToolError::ExecutionFailed(format!(
                "命令执行超时（超过 {} 秒）",
                config.timeout_secs
            ))),
        }
    }
}

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell_execute"
    }

    fn description(&self) -> &str {
        "执行安全的 Shell 命令。只允许预定义的白名单命令（npm, yarn, git, cargo, semgrep 等）。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Custom
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "command".to_string(),
                param_type: ToolParameterType::String,
                description: "要执行的命令（必须在白名单中）".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "args".to_string(),
                param_type: ToolParameterType::Array,
                description: "命令参数数组".to_string(),
                required: false,
                default: Some(serde_json::json!([])),
                enum_values: None,
                format: None,
                items: Some(Box::new(ToolParameter {
                    name: "arg".to_string(),
                    param_type: ToolParameterType::String,
                    description: "参数值".to_string(),
                    required: false,
                    default: None,
                    enum_values: None,
                    format: None,
                    items: None,
                    properties: None,
                })),
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "working_dir".to_string(),
                param_type: ToolParameterType::String,
                description: "工作目录（相对于项目根目录）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "timeout".to_string(),
                param_type: ToolParameterType::Integer,
                description: "超时时间（秒，最大 300）".to_string(),
                required: false,
                default: Some(serde_json::json!(60)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let command = input["command"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 command 参数".to_string()))?;

        let args: Vec<String> = input["args"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let working_dir = input["working_dir"].as_str();

        let custom_timeout = input["timeout"].as_u64();

        // 如果指定了自定义超时，临时更新配置
        if let Some(secs) = custom_timeout {
            let max_timeout = 300u64;
            let actual_timeout = secs.min(max_timeout);
            let mut config = self.config.write().await;
            config.timeout_secs = actual_timeout;
        }

        // 执行命令
        let (stdout, stderr, success) =
            self.execute_command(command, &args, working_dir, None).await?;

        // 构建结果
        let mut result_text = format!("命令: {} {}\n", command, args.join(" "));
        result_text.push_str(&format!("状态: {}\n", if success { "成功" } else { "失败" }));

        if !stdout.is_empty() {
            result_text.push_str("\n=== 标准输出 ===\n");
            result_text.push_str(&stdout);
        }

        if !stderr.is_empty() {
            result_text.push_str("\n=== 标准错误 ===\n");
            result_text.push_str(&stderr);
        }

        if success {
            Ok(ToolResult::json(
                serde_json::json!({
                    "command": command,
                    "args": args,
                    "success": true,
                    "stdout": stdout,
                    "stderr": stderr,
                }),
                Some(result_text),
            ))
        } else {
            Ok(ToolResult {
                text: result_text,
                is_error: true,
                error_code: Some("COMMAND_FAILED".to_string()),
                duration_ms: None,
                data: Some(serde_json::json!({
                    "command": command,
                    "args": args,
                    "success": false,
                    "stdout": stdout,
                    "stderr": stderr,
                })),
            })
        }
    }
}

/// 获取允许的命令列表
pub fn get_allowed_commands() -> Vec<&'static str> {
    vec![
        "npm",
        "yarn",
        "pnpm",
        "pip",
        "pip3",
        "cargo",
        "git",
        "make",
        "cmake",
        "semgrep",
        "bandit",
        "gitleaks",
        "trivy",
        "safety",
    ]
}

/// 注册 Shell 工具
pub async fn register_shell_tools(registry: &Arc<crate::registry::ToolRegistry>, project_path: String) {
    let tool: Arc<dyn Tool> = Arc::new(ShellTool::new(project_path));

    if let Err(e) = registry.register(tool).await {
        tracing::warn!("Failed to register shell tool: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_config_default() {
        let config = ShellConfig::default();

        assert!(config.is_command_allowed("npm"));
        assert!(config.is_command_allowed("git"));
        assert!(config.is_command_allowed("cargo"));
        assert!(config.is_command_allowed("NPM")); // 大小写不敏感
        assert!(!config.is_command_allowed("rm"));
        assert!(!config.is_command_allowed("chmod"));
    }

    #[test]
    fn test_shell_config_custom() {
        let config = ShellConfig::new()
            .with_allowed_command("my-tool")
            .with_timeout(120)
            .with_max_output(2 * 1024 * 1024);

        assert!(config.is_command_allowed("my-tool"));
        assert_eq!(config.timeout_secs, 120);
        assert_eq!(config.max_output_bytes, 2 * 1024 * 1024);
    }

    #[test]
    fn test_get_allowed_commands() {
        let commands = get_allowed_commands();
        assert!(commands.contains(&"npm"));
        assert!(commands.contains(&"git"));
        assert!(!commands.contains(&"rm"));
    }
}
