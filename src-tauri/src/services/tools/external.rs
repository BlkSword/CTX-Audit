//! 外部工具适配器
//!
//! 适配外部安全扫描工具（Semgrep, Bandit, Gitleaks 等）

use async_trait::async_trait;
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;

use crate::models::tools::{ToolCategory, ToolError, ToolResult};

/// 外部工具 trait
#[async_trait]
pub trait ExternalTool: Send + Sync {
    /// 工具名称
    fn name(&self) -> &str;

    /// 检查工具是否可用
    async fn is_available(&self) -> bool;

    /// 运行工具
    async fn run(&self, target_path: &Path) -> Result<ExternalToolOutput, ToolError>;
}

/// 外部工具输出
#[derive(Debug, Clone)]
pub struct ExternalToolOutput {
    /// 标准输出
    pub stdout: String,

    /// 标准错误
    pub stderr: String,

    /// 退出代码
    pub exit_code: i32,

    /// 执行时长（毫秒）
    pub duration_ms: u64,
}

/// 外部工具适配器
pub struct ExternalToolAdapter {
    /// 工具配置
    config: ExternalToolConfig,
}

/// 外部工具配置
#[derive(Debug, Clone)]
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
    pub env_vars: Option<Vec<(String, String)>>,

    /// 超时时间（秒）
    pub timeout_seconds: u64,
}

impl ExternalToolAdapter {
    /// 创建新的适配器
    pub fn new(config: ExternalToolConfig) -> Self {
        Self { config }
    }

    /// 检查工具是否可用
    pub async fn is_available(&self) -> bool {
        Command::new(&self.config.executable_path)
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// 运行工具
    pub async fn run(&self, target_path: &Path) -> Result<ExternalToolOutput, ToolError> {
        let start_time = std::time::Instant::now();

        // 构建命令
        let mut cmd = Command::new(&self.config.executable_path);

        // 添加参数
        for arg_template in &self.config.args_template {
            let arg = arg_template.replace("{target}", &target_path.to_string_lossy());
            cmd.arg(arg);
        }

        // 设置工作目录
        if let Some(ref work_dir) = self.config.working_dir {
            cmd.current_dir(work_dir);
        }

        // 设置环境变量
        if let Some(ref env_vars) = self.config.env_vars {
            for (key, value) in env_vars {
                cmd.env(key, value);
            }
        }

        // 执行命令（带超时）
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_seconds),
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output(),
        )
        .await
        .map_err(|_| ToolError::timeout(format!("{} 执行超时", self.config.tool_name)))?
        .map_err(|e| ToolError::internal(format!("执行 {} 失败: {}", self.config.tool_name, e)))?;

        let duration = start_time.elapsed().as_millis() as u64;

        Ok(ExternalToolOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            duration_ms: duration,
        })
    }
}

/// Semgrep 工具适配器
pub struct SemgrepAdapter {
    project_path: String,
}

impl SemgrepAdapter {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl ExternalTool for SemgrepAdapter {
    fn name(&self) -> &str {
        "semgrep"
    }

    async fn is_available(&self) -> bool {
        Command::new("semgrep")
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    async fn run(&self, target_path: &Path) -> Result<ExternalToolOutput, ToolError> {
        let adapter = ExternalToolAdapter::new(ExternalToolConfig {
            tool_name: "semgrep".to_string(),
            executable_path: "semgrep".to_string(),
            args_template: vec![
                "scan".to_string(),
                "{target}".to_string(),
                "--json".to_string(),
                "--no-git-ignore".to_string(),
            ],
            working_dir: Some(self.project_path.clone()),
            env_vars: None,
            timeout_seconds: 300,
        });

        adapter.run(target_path).await
    }
}

/// Bandit 工具适配器（Python 安全扫描）
pub struct BanditAdapter {
    project_path: String,
}

impl BanditAdapter {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl ExternalTool for BanditAdapter {
    fn name(&self) -> &str {
        "bandit"
    }

    async fn is_available(&self) -> bool {
        Command::new("bandit")
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    async fn run(&self, target_path: &Path) -> Result<ExternalToolOutput, ToolError> {
        let adapter = ExternalToolAdapter::new(ExternalToolConfig {
            tool_name: "bandit".to_string(),
            executable_path: "bandit".to_string(),
            args_template: vec![
                "-r".to_string(),
                "{target}".to_string(),
                "-f".to_string(),
                "json".to_string(),
            ],
            working_dir: Some(self.project_path.clone()),
            env_vars: None,
            timeout_seconds: 300,
        });

        adapter.run(target_path).await
    }
}

/// Gitleaks 工具适配器（密钥泄露检测）
pub struct GitleaksAdapter {
    project_path: String,
}

impl GitleaksAdapter {
    pub fn new(project_path: String) -> Self {
        Self { project_path }
    }
}

#[async_trait]
impl ExternalTool for GitleaksAdapter {
    fn name(&self) -> &str {
        "gitleaks"
    }

    async fn is_available(&self) -> bool {
        Command::new("gitleaks")
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    async fn run(&self, target_path: &Path) -> Result<ExternalToolOutput, ToolError> {
        let adapter = ExternalToolAdapter::new(ExternalToolConfig {
            tool_name: "gitleaks".to_string(),
            executable_path: "gitleaks".to_string(),
            args_template: vec![
                "detect".to_string(),
                "--source".to_string(),
                "{target}".to_string(),
                "--report-format".to_string(),
                "json".to_string(),
            ],
            working_dir: Some(self.project_path.clone()),
            env_vars: None,
            timeout_seconds: 300,
        });

        adapter.run(target_path).await
    }
}

/// 外部工具管理器
pub struct ExternalToolManager {
    /// 项目路径
    project_path: String,

    /// 可用的外部工具
    tools: Vec<std::sync::Arc<dyn ExternalTool>>,
}

impl ExternalToolManager {
    /// 创建新的管理器
    pub fn new(project_path: String) -> Self {
        Self {
            project_path,
            tools: Vec::new(),
        }
    }

    /// 添加外部工具
    pub fn add_tool(&mut self, tool: std::sync::Arc<dyn ExternalTool>) {
        self.tools.push(tool);
    }

    /// 检查所有工具的可用性
    pub async fn check_availability(&self) -> Vec<String> {
        let mut available = Vec::new();

        for tool in &self.tools {
            if tool.is_available().await {
                available.push(tool.name().to_string());
            }
        }

        available
    }

    /// 运行指定的工具
    pub async fn run_tool(
        &self,
        tool_name: &str,
        target_path: &Path,
    ) -> Result<ExternalToolOutput, ToolError> {
        let tool = self
            .tools
            .iter()
            .find(|t| t.name() == tool_name)
            .ok_or_else(|| ToolError::not_found(format!("外部工具不存在: {}", tool_name)))?;

        if !tool.is_available().await {
            return Err(ToolError::internal(format!(
                "外部工具不可用: {} (请确保已安装)",
                tool_name
            )));
        }

        tool.run(target_path).await
    }

    /// 运行所有可用的工具
    pub async fn run_all_available(&self, target_path: &Path) -> Vec<(String, Result<ExternalToolOutput, ToolError>)> {
        let mut results = Vec::new();

        for tool in &self.tools {
            if tool.is_available().await {
                let name = tool.name().to_string();
                let result = tool.run(target_path).await;
                results.push((name, result));
            }
        }

        results
    }
}

impl Default for ExternalToolManager {
    fn default() -> Self {
        Self {
            project_path: ".".to_string(),
            tools: Vec::new(),
        }
    }
}

/// 创建默认的外部工具管理器（包含所有内置工具）
pub fn create_default_manager(project_path: String) -> ExternalToolManager {
    let mut manager = ExternalToolManager::new(project_path);

    manager.add_tool(std::sync::Arc::new(SemgrepAdapter::new(
        manager.project_path.clone(),
    )));
    manager.add_tool(std::sync::Arc::new(BanditAdapter::new(
        manager.project_path.clone(),
    )));
    manager.add_tool(std::sync::Arc::new(GitleaksAdapter::new(
        manager.project_path.clone(),
    )));

    manager
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_external_tool_adapter() {
        let config = ExternalToolConfig {
            tool_name: "echo".to_string(),
            executable_path: "echo".to_string(),
            args_template: vec!["hello".to_string()],
            working_dir: None,
            env_vars: None,
            timeout_seconds: 5,
        };

        let adapter = ExternalToolAdapter::new(config);
        let output = adapter.run(Path::new(".")).await.unwrap();

        assert_eq!(output.stdout.trim(), "hello");
        assert_eq!(output.exit_code, 0);
    }
}
