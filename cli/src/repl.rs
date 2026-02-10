// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! REPL (Read-Eval-Print Loop) 模块
//!
//! 实现交互式命令行界面

use anyhow::Result;
use rustyline::{DefaultEditor, Helper};
use std::sync::Arc;

use crate::config::ConfigManager;
use crate::terminal::TerminalRenderer;

/// REPL 会话
pub struct ReplSession {
    editor: DefaultEditor,

    renderer: TerminalRenderer,

    config: Arc<ConfigManager>,

    /// 当前项目路径
    current_project: Option<String>,

    /// 会话历史
    history: Vec<String>,
}

impl ReplSession {
    /// 创建新的 REPL 会话
    pub fn new(config: Arc<ConfigManager>) -> Result<Self> {
        let mut editor = DefaultEditor::new()?;

        // 设置历史文件
        if let Some(history_path) = dirs::config_dir()
            .map(|dir| dir.join("ctx-audit").join("history.txt"))
        {
            let _ = std::fs::create_dir_all(history_path.parent().unwrap());
            let _ = editor.load_history(&history_path);
        }

        Ok(Self {
            editor,
            renderer: TerminalRenderer::new(),
            config,
            current_project: None,
            history: Vec::new(),
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
                std::process::exit(0);
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
                    self.current_project = Some(path.to_string());
                    self.renderer.success(&format!("项目路径设置为: {}", path));
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
                        self.set_config(key, value)?;
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
        // TODO: 实现审计逻辑
        self.renderer.info(&format!("启动审计: {}", path));
        Ok(())
    }

    /// 运行扫描
    async fn run_scan(&mut self, path: &str) -> Result<()> {
        // TODO: 实现扫描逻辑
        self.renderer.info(&format!("启动扫描: {}", path));
        Ok(())
    }

    /// 列出漏洞
    async fn list_findings(&mut self) -> Result<()> {
        // TODO: 实现列出漏洞逻辑
        self.renderer.info("暂无漏洞记录");
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
    fn set_config(&mut self, key: &str, value: &str) -> Result<()> {
        // 需要通过 Arc 获取可变引用，这里简化处理
        self.renderer.info(&format!("配置 {} = {}", key, value));
        Ok(())
    }

    /// 列出配置
    fn list_config(&mut self) -> Result<()> {
        self.renderer.print("当前配置:");
        self.renderer.print("  llm.provider = anthropic");
        self.renderer.print("  scan.threads = 4");
        Ok(())
    }

    /// 处理聊天命令
    async fn handle_chat_command(&mut self, _cmd: &str) -> Result<()> {
        // TODO: 实现 LLM 聊天逻辑
        self.renderer.info("LLM 聊天功能待实现");
        Ok(())
    }
}
