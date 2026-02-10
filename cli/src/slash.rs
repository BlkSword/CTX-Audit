// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 斜杠命令系统
//!
//! 支持 TUI 和 CLI 模式的斜杠命令

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::ConfigManager;
use crate::database::Database;
use ctx_audit_agent_engine::{AgentRegistry, AgentType, AgentConfig, LLMConfig, AgentContext};
use ctx_audit_tools::ToolRegistry;

/// 斜杠命令
#[derive(Debug, Clone, PartialEq)]
pub enum SlashCommand {
    /// 帮助
    Help,

    /// 退出
    Quit,

    /// 清屏
    Clear,

    /// 审计
    Audit {
        path: Option<String>,
    },

    /// 扫描
    Scan {
        path: String,
        output: Option<String>,
    },

    /// 搜索
    Search {
        query: String,
        in_file: Option<String>,
    },

    /// 查找符号
    Find {
        symbol: String,
    },

    /// 查找引用
    Refs {
        symbol: String,
    },

    /// 调用图
    CallGraph {
        entry: String,
        depth: Option<usize>,
    },

    /// 解释代码
    Explain {
        file: Option<String>,
        line: Option<usize>,
    },

    /// 修复漏洞
    Fix {
        finding_id: Option<String>,
    },

    /// 差异对比
    Diff {
        file1: String,
        file2: Option<String>,
    },

    /// 切换目录
    Cd {
        path: String,
    },

    /// 列出漏洞
    Findings,

    /// 导出
    Export {
        format: String,
        output: Option<String>,
    },

    /// 配置
    Config {
        key: Option<String>,
        value: Option<String>,
    },

    /// 历史记录
    History,

    /// 继续对话
    Continue,

    /// 索引项目
    Index {
        path: Option<String>,
    },

    /// 自定义命令
    Custom {
        name: String,
        args: Vec<String>,
    },
}

/// 斜杠命令解析器
pub struct SlashCommandParser {
    /// 别名映射
    aliases: HashMap<String, String>,
}

impl SlashCommandParser {
    /// 创建新的解析器
    pub fn new() -> Self {
        let mut aliases = HashMap::new();

        // 设置别名
        aliases.insert("h".to_string(), "help".to_string());
        aliases.insert("q".to_string(), "quit".to_string());
        aliases.insert("exit".to_string(), "quit".to_string());
        aliases.insert("cls".to_string(), "clear".to_string());
        aliases.insert("s".to_string(), "search".to_string());
        aliases.insert("f".to_string(), "find".to_string());
        aliases.insert("cg".to_string(), "callgraph".to_string());
        aliases.insert("x".to_string(), "explain".to_string());
        aliases.insert("cfg".to_string(), "config".to_string());
        aliases.insert("pwd".to_string(), "cd".to_string());

        Self { aliases }
    }

    /// 解析命令
    pub fn parse(&self, input: &str) -> Result<SlashCommand, String> {
        let input = input.trim();

        if !input.starts_with('/') {
            return Err("命令必须以 / 开头".to_string());
        }

        let parts: Vec<&str> = input[1..].split_whitespace().collect();
        if parts.is_empty() {
            return Err("缺少命令".to_string());
        }

        // 解析别名
        let command = self.aliases.get(parts[0])
            .map(|s| s.as_str())
            .unwrap_or(parts[0]);

        match command {
            "help" => Ok(SlashCommand::Help),
            "quit" | "exit" | "q" => Ok(SlashCommand::Quit),
            "clear" | "cls" => Ok(SlashCommand::Clear),
            "audit" => {
                let path = parts.get(1).map(|s| s.to_string());
                Ok(SlashCommand::Audit { path })
            }
            "scan" => {
                let path = parts.get(1).map(|s| s.to_string())
                    .unwrap_or_else(|| ".".to_string());
                let output = parts.get(2).map(|s| s.to_string());
                Ok(SlashCommand::Scan { path, output })
            }
            "search" | "s" => {
                let query = parts.get(1).map(|s| s.to_string())
                    .ok_or_else(|| "缺少搜索查询".to_string())?;
                let in_file = parts.get(2).map(|s| s.to_string());
                Ok(SlashCommand::Search { query, in_file })
            }
            "find" | "f" => {
                let symbol = parts.get(1).map(|s| s.to_string())
                    .ok_or_else(|| "缺少符号名".to_string())?;
                Ok(SlashCommand::Find { symbol })
            }
            "refs" => {
                let symbol = parts.get(1).map(|s| s.to_string())
                    .ok_or_else(|| "缺少符号名".to_string())?;
                Ok(SlashCommand::Refs { symbol })
            }
            "callgraph" | "cg" => {
                let entry = parts.get(1).map(|s| s.to_string())
                    .ok_or_else(|| "缺少入口函数".to_string())?;
                let depth = parts.get(2).and_then(|s| s.parse().ok());
                Ok(SlashCommand::CallGraph { entry, depth })
            }
            "explain" | "x" => {
                let file = parts.get(1).map(|s| s.to_string());
                let line = parts.get(2).and_then(|s| s.parse().ok());
                Ok(SlashCommand::Explain { file, line })
            }
            "fix" => {
                let finding_id = parts.get(1).map(|s| s.to_string());
                Ok(SlashCommand::Fix { finding_id })
            }
            "diff" => {
                let file1 = parts.get(1).map(|s| s.to_string())
                    .ok_or_else(|| "缺少文件路径".to_string())?;
                let file2 = parts.get(2).map(|s| s.to_string());
                Ok(SlashCommand::Diff { file1, file2 })
            }
            "cd" | "pwd" => {
                let path = parts.get(1).map(|s| s.to_string())
                    .unwrap_or_else(|| ".".to_string());
                Ok(SlashCommand::Cd { path })
            }
            "findings" => Ok(SlashCommand::Findings),
            "export" => {
                let format = parts.get(1).map(|s| s.to_string())
                    .unwrap_or_else(|| "json".to_string());
                let output = parts.get(2).map(|s| s.to_string());
                Ok(SlashCommand::Export { format, output })
            }
            "config" | "cfg" => {
                let key = parts.get(1).map(|s| s.to_string());
                let value = parts.get(2).map(|s| s.to_string());
                Ok(SlashCommand::Config { key, value })
            }
            "history" => Ok(SlashCommand::History),
            "continue" => Ok(SlashCommand::Continue),
            "index" => {
                let path = parts.get(1).map(|s| s.to_string());
                Ok(SlashCommand::Index { path })
            }
            _ => Ok(SlashCommand::Custom {
                name: command.to_string(),
                args: parts[1..].iter().map(|s| s.to_string()).collect(),
            }),
        }
    }

    /// 获取命令建议
    pub fn get_suggestions(&self, partial: &str) -> Vec<String> {
        let partial = partial.trim_start_matches('/').to_lowercase();

        let mut suggestions = Vec::new();

        let commands = vec![
            "help", "quit", "clear", "audit", "scan", "search",
            "find", "refs", "callgraph", "explain", "fix", "diff",
            "cd", "findings", "export", "config", "history", "continue",
            "index",
        ];

        for cmd in commands {
            if cmd.starts_with(&partial) {
                suggestions.push(format!("/{}", cmd));
            }
        }

        suggestions
    }
}

impl Default for SlashCommandParser {
    fn default() -> Self {
        Self::new()
    }
}

/// 斜杠命令执行器
pub struct SlashCommandExecutor {
    /// 数据库
    db: Arc<Database>,

    /// Agent 注册表
    agent_registry: Option<Arc<AgentRegistry>>,

    /// 工具注册表
    tool_registry: Option<Arc<ToolRegistry>>,

    /// 当前项目路径
    current_project: Option<String>,
}

impl SlashCommandExecutor {
    /// 创建新的执行器
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            agent_registry: None,
            tool_registry: None,
            current_project: None,
        }
    }

    /// 设置 Agent 注册表
    pub fn with_agent_registry(mut self, registry: Arc<AgentRegistry>) -> Self {
        self.agent_registry = Some(registry);
        self
    }

    /// 设置工具注册表
    pub fn with_tool_registry(mut self, registry: Arc<ToolRegistry>) -> Self {
        self.tool_registry = Some(registry);
        self
    }

    /// 设置当前项目
    pub fn with_current_project(mut self, path: String) -> Self {
        self.current_project = Some(path);
        self
    }

    /// 执行命令
    pub async fn execute(&self, command: &SlashCommand) -> Result<String, String> {
        match command {
            SlashCommand::Help => {
                Ok(self.get_help_text())
            }
            SlashCommand::Quit => {
                Ok("再见！".to_string())
            }
            SlashCommand::Clear => {
                // 在 TUI 中会由调用者处理
                Ok("屏幕已清除".to_string())
            }
            SlashCommand::Audit { path } => {
                let project_path = path.clone()
                    .or(self.current_project.clone())
                    .ok_or_else(|| "未指定项目路径".to_string())?;

                // 启动审计
                if let Some(ref agent_registry) = self.agent_registry {
                    self.run_audit(agent_registry, project_path).await
                } else {
                    Err("Agent 系统未初始化".to_string())
                }
            }
            SlashCommand::Scan { path, output } => {
                self.run_scan(path.clone(), output.clone()).await
            }
            SlashCommand::Search { query, in_file } => {
                self.search_code(query.clone(), in_file.clone()).await
            }
            SlashCommand::Find { symbol } => {
                self.find_symbol(symbol.clone()).await
            }
            SlashCommand::Refs { symbol } => {
                self.find_references(symbol.clone()).await
            }
            SlashCommand::CallGraph { entry, depth } => {
                self.get_call_graph(entry.clone(), *depth).await
            }
            SlashCommand::Explain { file, line } => {
                self.explain_code(file.clone(), *line).await
            }
            SlashCommand::Fix { finding_id } => {
                self.fix_finding(finding_id.clone()).await
            }
            SlashCommand::Diff { file1, file2 } => {
                self.show_diff(file1.clone(), file2.clone()).await
            }
            SlashCommand::Cd { path } => {
                Ok(format!("切换到: {}", path))
            }
            SlashCommand::Findings => {
                self.list_findings().await
            }
            SlashCommand::Export { format, output } => {
                self.export_findings(&format, output.clone()).await
            }
            SlashCommand::Config { key, value } => {
                self.handle_config(key.clone(), value.clone()).await
            }
            SlashCommand::History => {
                Ok("历史记录功能待实现".to_string())
            }
            SlashCommand::Continue => {
                Ok("继续对话功能待实现".to_string())
            }
            SlashCommand::Index { path } => {
                let project_path = path.clone()
                    .or(self.current_project.clone())
                    .ok_or_else(|| "未指定项目路径".to_string())?;

                self.index_project(project_path).await
            }
            SlashCommand::Custom { name, args } => {
                Err(format!("未知命令: {}", name))
            }
        }
    }

    /// 获取帮助文本
    fn get_help_text(&self) -> String {
        r#"
可用命令:

审计相关:
  /audit [path]        - 启动 AI 审计
  /scan <path>         - 快速规则扫描
  /index [path]        - 索引项目符号

代码搜索:
  /search <query>      - 搜索代码
  /find <symbol>       - 查找符号定义
  /refs <symbol>       - 查找符号引用
  /callgraph <entry>   - 显示调用图

分析工具:
  /explain [file:line] - 解释代码
  /diff <file1> [file2]- 对比文件差异
  /fix [finding_id]    - 修复漏洞

项目管理:
  /cd <path>           - 切换项目目录
  /findings            - 列出所有漏洞
  /export <format>     - 导出报告

系统:
  /config [key] [val]  - 查看/设置配置
  /help                - 显示此帮助
  /clear               - 清屏
  /quit, /q            - 退出

示例:
  /audit ./src
  /search "login"
  /find authenticate
  /explain auth.rs:42
  /diff file1.rs file2.rs

LLM 配置:
  /config llm.provider anthropic
  /config llm.api_key sk-ant-xxx...
  /config llm.model claude-3-5-sonnet-20241022

支持提供商:
  - Anthropic: claude-3-5-sonnet, claude-3-5-haiku
  - OpenAI: gpt-4, gpt-3.5-turbo
  - Ollama: llama2, codellama, mistral
"#.trim().to_string()
    }

    /// 运行审计
    async fn run_audit(&self, agent_registry: &AgentRegistry, path: String) -> Result<String, String> {
        // 创建审计上下文
        let context = AgentContext {
            project_id: uuid::Uuid::new_v4().to_string(),
            project_path: path.to_string(),
            session_id: uuid::Uuid::new_v4().to_string(),
            inherited_context: Default::default(),
            user_context: Default::default(),
        };

        // 创建 Analysis Agent
        let agent = agent_registry.create_agent(
            AgentType::Analysis,
            AgentConfig {
                agent_type: AgentType::Analysis,
                name: "Analysis Agent".to_string(),
                description: Some("代码安全审计".to_string()),
                llm_config: LLMConfig::default(),
                max_iterations: 50,
                timeout_secs: Some(600),
                extra: Default::default(),
            },
        ).map_err(|e| format!("创建 Agent 失败: {}", e))?;

        // 执行审计
        let result = agent.execute(context).await;

        match result.status {
            ctx_audit_agent_engine::AgentStatus::Completed => {
                Ok(format!(
                    "审计完成！\n\n消息: {}\n发现漏洞: {}",
                    result.message.unwrap_or_default(),
                    result.findings.len()
                ))
            }
            ctx_audit_agent_engine::AgentStatus::Failed => {
                Err(format!("审计失败: {}", result.error.unwrap_or_default()))
            }
            _ => {
                Err("审计未正常完成".to_string())
            }
        }
    }

    /// 运行扫描
    async fn run_scan(&self, path: String, output: Option<String>) -> Result<String, String> {
        // 使用规则扫描器
        Ok(format!("扫描 {} (输出: {:?})", path, output))
    }

    /// 搜索代码
    async fn search_code(&self, query: String, in_file: Option<String>) -> Result<String, String> {
        Ok(format!("搜索: {} (文件: {:?})", query, in_file))
    }

    /// 查找符号
    async fn find_symbol(&self, symbol: String) -> Result<String, String> {
        // TODO: 实现符号查询
        Ok(format!("符号搜索功能开发中: {}", symbol))
    }

    /// 查找引用
    async fn find_references(&self, symbol: String) -> Result<String, String> {
        Ok(format!("查找 {} 的引用...", symbol))
    }

    /// 获取调用图
    async fn get_call_graph(&self, entry: String, depth: Option<usize>) -> Result<String, String> {
        Ok(format!("获取 {} 的调用图 (深度: {:?})", entry, depth))
    }

    /// 解释代码
    async fn explain_code(&self, file: Option<String>, line: Option<usize>) -> Result<String, String> {
        Ok(format!("解释代码: {:?}:{:?}", file, line))
    }

    /// 修复漏洞
    async fn fix_finding(&self, finding_id: Option<String>) -> Result<String, String> {
        Ok(format!("修复漏洞: {:?}", finding_id))
    }

    /// 显示差异
    async fn show_diff(&self, file1: String, file2: Option<String>) -> Result<String, String> {
        Ok(format!("对比: {} 和 {:?}", file1, file2))
    }

    /// 列出漏洞
    async fn list_findings(&self) -> Result<String, String> {
        // TODO: 实现漏洞列表查询
        Ok("漏洞列表功能开发中...".to_string())
    }

    /// 导出漏洞
    async fn export_findings(&self, format: &str, output: Option<String>) -> Result<String, String> {
        Ok(format!("导出为 {} 到 {:?}", format, output))
    }

    /// 处理配置
    async fn handle_config(&self, key: Option<String>, value: Option<String>) -> Result<String, String> {
        let mut config_manager = ConfigManager::new(None)
            .map_err(|e| format!("加载配置失败: {}", e))?;

        match (key, value) {
            (None, None) => {
                // 显示所有配置
                let mut result = "当前配置:\n\n".to_string();

                result.push_str("LLM 配置:\n");
                if let Some(provider) = config_manager.get("llm.provider") {
                    result.push_str(&format!("  提供商: {}\n", provider));
                }
                if let Some(model) = config_manager.get("llm.model") {
                    result.push_str(&format!("  模型: {}\n", model));
                }
                if config_manager.get("llm.api_key").is_some() {
                    result.push_str("  API 密钥: ***已配置***\n");
                } else {
                    result.push_str("  API 密钥: ***未配置***\n");
                }

                result.push_str("\n使用 /config <key> 查看具体配置\n");
                result.push_str("使用 /config <key> <value> 设置配置\n");
                result.push_str("\n常用配置键:\n");
                result.push_str("  llm.provider      - LLM 提供商 (anthropic, openai, ollama)\n");
                result.push_str("  llm.api_key       - API 密钥\n");
                result.push_str("  llm.model         - 模型名称\n");

                Ok(result)
            }
            (None, Some(_)) => {
                // 没有键但有值，这是错误的情况
                Err("配置键不能为空，请使用 /config <key> <value>".to_string())
            }
            (Some(key), None) => {
                // 显示特定配置
                match config_manager.get(&key) {
                    Some(value) => {
                        if key.contains("api_key") {
                            Ok(format!("{}: ***已配置***", key))
                        } else {
                            Ok(format!("{}: {}", key, value))
                        }
                    }
                    None => Ok(format!("{}: (未设置)", key))
                }
            }
            (Some(key), Some(value)) => {
                // 设置配置
                config_manager.set(&key, value.clone())
                    .map_err(|e| format!("设置失败: {}", e))?;

                config_manager.save().await
                    .map_err(|e| format!("保存配置失败: {}", e))?;

                Ok(format!("配置已更新: {} = {}", key,
                    if key.contains("api_key") { "***" } else { &value }))
            }
        }
    }

    /// 索引项目
    async fn index_project(&self, path: String) -> Result<String, String> {
        Ok(format!("索引项目: {}", path))
    }
}
