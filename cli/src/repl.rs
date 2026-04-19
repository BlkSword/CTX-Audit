// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! REPL (Read-Eval-Print Loop) 模块
//!
//! 实现交互式命令行界面

use anyhow::Result;
use rustyline::{DefaultEditor, Helper};
use std::sync::Arc;

use crate::config::ConfigManager;
use crate::database::Database;
use crate::terminal::TerminalRenderer;
use ctx_audit_llm::{LLMFactory, LLMConfig, LLMMessage, MessageRole, MessageContent};

/// REPL 会话
pub struct ReplSession {
    editor: DefaultEditor,

    renderer: TerminalRenderer,

    config: Arc<ConfigManager>,

    /// 当前项目路径
    pub current_project: Option<String>,

    /// 会话历史
    history: Vec<String>,

    /// 数据库
    db: Option<Arc<Database>>,

    /// LLM 工厂
    llm_factory: Arc<LLMFactory>,
}

impl ReplSession {
    /// 创建新的 REPL 会话
    pub fn new(config: Arc<ConfigManager>) -> Result<Self> {
        let mut editor = DefaultEditor::new()?;

        // 设置历史文件
        if let Some(history_path) = dirs::config_dir()
            .map(|dir| dir.join("ctx-audit").join("history.txt"))
        {
            let _ = std::fs::create_dir_all(history_path.parent().unwrap_or_else(|| std::path::Path::new("")));
            let _ = editor.load_history(&history_path);
        }

        // 初始化 LLM 工厂 - 使用用户配置
        let llm_factory = Arc::new(LLMFactory::new());
        let llm_config = config.config();
        llm_factory.set_config(LLMConfig {
            provider: llm_config.llm.provider.clone(),
            api_key: llm_config.llm.api_key.clone(),
            model: llm_config.llm.model.clone(),
            base_url: llm_config.llm.base_url.clone(),
            timeout_secs: Some(llm_config.llm.timeout_secs),
        });

        Ok(Self {
            editor,
            renderer: TerminalRenderer::new(),
            config,
            current_project: None,
            history: Vec::new(),
            db: None,
            llm_factory,
        })
    }

    /// 启动 REPL 循环
    pub async fn run(&mut self) -> Result<()> {
        self.renderer.print("CTX-Audit 交互式审计工具");
        self.renderer.print("输入 /help 查看帮助，/exit 退出");
        self.renderer.print("");

        loop {
            let prompt = if let Some(project) = &self.current_project {
                format!("ctx-audit:{}> ", project)
            } else {
                "ctx-audit> ".to_string()
            };

            match self.editor.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();

                    // 跳过空行
                    if line.is_empty() {
                        continue;
                    }

                    // 添加到历史
                    let _ = self.editor.add_history_entry(line);
                    self.history.push(line.to_string());

                    // 处理命令
                    if let Err(e) = self.handle_command(line).await {
                        self.renderer.error(&format!("错误: {}", e));
                    }
                }
                Err(rustyline::error::ReadlineError::Interrupted) => {
                    // Ctrl-C
                    self.renderer.info("使用 /exit 退出");
                }
                Err(rustyline::error::ReadlineError::Eof) => {
                    // Ctrl-D
                    self.renderer.info("再见！");
                    break;
                }
                Err(e) => {
                    self.renderer.error(&format!("读取错误: {}", e));
                    break;
                }
            }
        }

        // 保存历史
        if let Some(history_path) = dirs::config_dir()
            .map(|dir| dir.join("ctx-audit").join("history.txt"))
        {
            let _ = self.editor.save_history(&history_path);
        }

        Ok(())
    }

    /// 处理命令
    async fn handle_command(&mut self, cmd: &str) -> Result<()> {
        // 检查是否是斜杠命令
        if cmd.starts_with('/') {
            self.handle_slash_command(cmd).await
        } else {
            // 普通对话命令（转发给 LLM）
            self.handle_chat_command(cmd).await
        }
    }

    /// 处理斜杠命令
    async fn handle_slash_command(&mut self, cmd: &str) -> Result<()> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        let command = parts.first().copied().unwrap_or("");

        match command {
            "/help" | "/h" => {
                self.show_help();
            }
            "/exit" | "/quit" | "/q" => {
                self.renderer.info("再见！");
                return Ok(()); // 返回 Ok，允许 run() 中的历史保存和资源清理
            }
            "/project" | "/pwd" => {
                if let Some(project) = &self.current_project {
                    self.renderer.print(project);
                } else {
                    self.renderer.info("未设置项目路径");
                }
            }
            "/cd" => {
                if let Some(path) = parts.get(1) {
                    let project_path = std::path::Path::new(path);
                    if project_path.exists() {
                        self.current_project = Some(path.to_string());
                        self.renderer.success(&format!("项目路径设置为: {}", path));
                    } else {
                        self.renderer.error(&format!("路径不存在: {}", path));
                    }
                } else {
                    self.renderer.error("用法: /cd <path>");
                }
            }
            "/audit" => {
                let path = parts.get(1).unwrap_or(&".");
                self.run_audit(path).await?;
            }
            "/scan" => {
                let path = parts.get(1).unwrap_or(&".");
                self.run_scan(path).await?;
            }
            "/findings" => {
                self.list_findings().await?;
            }
            "/config" | "/cfg" => {
                if let Some(key) = parts.get(1) {
                    if let Some(value) = parts.get(2) {
                        self.set_config(key, value).await?;
                    } else {
                        self.get_config(key)?;
                    }
                } else {
                    self.list_config()?;
                }
            }
            "/clear" => {
                let _ = self.editor.clear_screen();
            }
            "/history" => {
                for (i, cmd) in self.history.iter().enumerate() {
                    self.renderer.print(&format!("{}  {}", i + 1, cmd));
                }
            }
            _ => {
                self.renderer.error(&format!("未知命令: {}", command));
                self.renderer.info("输入 /help 查看帮助");
            }
        }

        Ok(())
    }

    /// 显示帮助
    fn show_help(&mut self) {
        self.renderer.print("可用命令:");
        self.renderer.print("");
        self.renderer.print("斜杠命令:");
        self.renderer.print("  /help, /h              显示此帮助");
        self.renderer.print("  /exit, /quit, /q       退出程序");
        self.renderer.print("  /project, /pwd         显示当前项目路径");
        self.renderer.print("  /cd <path>             设置项目路径");
        self.renderer.print("  /audit [path]          启动 AI 审计");
        self.renderer.print("  /scan [path]           启动快速扫描");
        self.renderer.print("  /findings              列出漏洞发现");
        self.renderer.print("  /config <key> [value]  查看/设置配置");
        self.renderer.print("  /clear                 清屏");
        self.renderer.print("  /history               显示命令历史");
        self.renderer.print("");
        self.renderer.print("聊天模式:");
        self.renderer.print("  直接输入问题，将使用 LLM 回答");
        self.renderer.print("");
    }

    /// 运行审计
    async fn run_audit(&mut self, path: &str) -> Result<()> {
        // 确保数据库已初始化
        if self.db.is_none() {
            self.db = Some(Arc::new(Database::with_default_path().await?));
        }

        self.renderer.info(&format!("启动审计: {}", path));

        // 检查 LLM 配置
        let provider = self.config.get("llm.provider").unwrap_or_else(|| "anthropic".to_string());
        let api_key = self.config.get("llm.api_key");

        if api_key.is_none() {
            self.renderer.error("LLM API 密钥未配置");
            self.renderer.info("请使用以下命令配置：");
            self.renderer.info("  /config llm.api_key <your-api-key>");
            return Ok(());
        }

        // 配置 LLM
        let llm_config = LLMConfig {
            provider,
            api_key,
            model: self.config.get("llm.model"),
            base_url: self.config.get("llm.base_url"),
            timeout_secs: Some(120),
        };
        self.llm_factory.set_config(llm_config);

        // TODO: 实现完整的审计逻辑
        self.renderer.info("审计功能正在开发中...");
        self.renderer.info("当前可以使用以下功能：");
        self.renderer.info("  /scan - 快速规则扫描");
        self.renderer.info("  /findings - 查看已发现的漏洞");

        Ok(())
    }

    /// 运行扫描
    async fn run_scan(&mut self, path: &str) -> Result<()> {
        // 确保数据库已初始化
        if self.db.is_none() {
            self.db = Some(Arc::new(Database::with_default_path().await?));
        }

        self.renderer.info(&format!("启动扫描: {}", path));

        // 使用 deepaudit_core 扫描
        match deepaudit_core::scan_directory(path).await {
            Ok(findings) => {
                self.renderer.success(&format!("扫描完成！发现 {} 个漏洞", findings.len()));

                // 保存到数据库
                if let Some(ref db) = self.db {
                    // 创建或获取项目
                    let project_name = std::path::Path::new(path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("Unknown");

                    let uuid = uuid::Uuid::new_v4().to_string();

                    let project = match crate::database::ProjectQueries::get_by_path(db.pool(), path).await? {
                        Some(p) => p,
                        None => {
                            crate::database::ProjectQueries::create(db.pool(), &crate::database::CreateProject {
                                uuid,
                                name: project_name.to_string(),
                                path: path.to_string(),
                                description: None,
                            }).await?
                        }
                    };

                    // 保存漏洞
                    for finding in &findings {
                        let _ = crate::database::FindingQueries::create(db.pool(), &crate::database::CreateFinding {
                            finding_id: uuid::Uuid::new_v4().to_string(),
                            project_id: project.id,
                            session_id: None,
                            scan_id: Some(format!("scan_{}", chrono::Utc::now().timestamp())),
                            file_path: finding.file_path.clone(),
                            severity: finding.severity.clone(),
                            category: Some("scan".to_string()),
                            title: finding.vuln_type.clone(),
                            description: Some(finding.description.clone()),
                            start_line: Some(finding.line_start as i32),
                            end_line: Some(finding.line_end as i32),
                            code_snippet: None,
                            confidence: Some("high".to_string()),
                        }).await;
                    }

                    self.renderer.info(&format!("已保存 {} 个漏洞到数据库", findings.len()));
                }
            }
            Err(e) => {
                self.renderer.error(&format!("扫描失败: {}", e));
            }
        }

        Ok(())
    }

    /// 列出漏洞
    async fn list_findings(&mut self) -> Result<()> {
        if let Some(ref db) = self.db {
            let findings = crate::database::FindingQueries::list(
                db.pool(),
                None,
                None,
                Some("open"),
                None,
            ).await?;

            if findings.is_empty() {
                self.renderer.info("暂无漏洞记录");
            } else {
                self.renderer.print(&format!("发现 {} 个漏洞:\n", findings.len()));
                for finding in findings {
                    let title = finding.title.as_str();
                    self.renderer.finding(
                        &finding.severity,
                        title,
                        &finding.file_path,
                        finding.start_line.unwrap_or(0) as u32,
                    );
                }
            }
        } else {
            self.renderer.info("请先运行 /scan 或 /audit");
        }

        Ok(())
    }

    /// 获取配置
    fn get_config(&mut self, key: &str) -> Result<()> {
        match self.config.get(key) {
            Some(value) => {
                self.renderer.print(&value);
                Ok(())
            }
            None => {
                self.renderer.error(&format!("未找到配置: {}", key));
                Ok(())
            }
        }
    }

    /// 设置配置
    async fn set_config(&mut self, key: &str, value: &str) -> Result<()> {
        // ConfigManager 在 Arc 后面无法 &mut，创建新实例来修改并保存
        let mut config_manager = ConfigManager::new(None)
            .map_err(|e| anyhow::anyhow!("加载配置失败: {}", e))?;

        config_manager.set(key, value.to_string())
            .map_err(|e| anyhow::anyhow!("设置配置失败: {}", e))?;

        config_manager.save().await
            .map_err(|e| anyhow::anyhow!("保存配置失败: {}", e))?;

        self.renderer.success(&format!("配置已更新: {} = {}", key,
            if key.contains("api_key") { "***" } else { value }));
        self.renderer.info("配置已保存。重启 REPL 以加载新配置。");

        Ok(())
    }

    /// 列出配置
    fn list_config(&mut self) -> Result<()> {
        self.renderer.print("当前配置:");
        // 从实际配置中读取常用配置项
        let keys = [
            "llm.provider",
            "llm.model",
            "llm.api_key",
            "llm.timeout_secs",
            "scan.threads",
        ];
        for key in &keys {
            if let Some(value) = self.config.get(key) {
                let display_value = if key.contains("api_key") && value.len() > 8 {
                    format!("{}***", &value[..8])
                } else {
                    value
                };
                self.renderer.print(&format!("  {} = {}", key, display_value));
            }
        }
        Ok(())
    }

    /// 处理聊天命令
    async fn handle_chat_command(&mut self, cmd: &str) -> Result<()> {
        // 检查 LLM 配置
        let provider = self.config.get("llm.provider").unwrap_or_else(|| "anthropic".to_string());
        let api_key = self.config.get("llm.api_key");

        if api_key.is_none() {
            self.renderer.error("LLM API 密钥未配置");
            self.renderer.info("请使用以下命令配置：");
            self.renderer.info("  /config llm.api_key <your-api-key>");
            return Ok(());
        }

        // 配置 LLM
        let llm_config = LLMConfig {
            provider,
            api_key,
            model: self.config.get("llm.model"),
            base_url: self.config.get("llm.base_url"),
            timeout_secs: Some(60),
        };
        self.llm_factory.set_config(llm_config);

        self.renderer.info("AI 正在思考...");

        // 创建消息
        let message = LLMMessage {
            role: MessageRole::User,
            content: vec![MessageContent::Text {
                text: cmd.to_string()
            }],
            cache_control: None,
        };

        // 调用 LLM
        match self.llm_factory.get_client().await {
            Ok(client) => {
                match client.generate(vec![message], 1024, 0.7).await {
                    Ok(response) => {
                        let text = response.get_text();
                        self.renderer.print(&text);
                    }
                    Err(e) => {
                        self.renderer.error(&format!("LLM 请求失败: {}", e));
                    }
                }
            }
            Err(e) => {
                self.renderer.error(&format!("获取 LLM 客户端失败: {}", e));
            }
        }

        Ok(())
    }
}
