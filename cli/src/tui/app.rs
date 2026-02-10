// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! TUI 应用主循环

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::Backend, Frame, Terminal};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::layout::{Layout, PanelType};
use super::panels::*;
use super::llm::{StreamChatProcessor, StreamConfig, StreamEvent};
use super::audit::AuditManager;
use crate::slash::{SlashCommandParser, SlashCommandExecutor, SlashCommand};
use crate::config::ConfigManager;
use crate::database::Database;
use std::sync::Arc;

/// 应用事件
#[derive(Debug, Clone, PartialEq)]
pub enum AppEvent {
    /// 键盘事件
    Key(KeyEvent),
    /// 鼠标事件
    Mouse(crossterm::event::MouseEvent),
    /// 粘贴事件
    Paste(String),
    /// 审计进度更新
    AuditProgress(u8, String),
    /// 新漏洞发现
    NewFinding(FindingEvent),
    /// Agent 事件
    Agent(AgentEvent),
    /// 系统消息
    System(String),
    /// 错误
    Error(String),
    /// 退出
    Quit,
}

/// 审计事件
#[derive(Debug, Clone, PartialEq)]
pub struct FindingEvent {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub file_path: String,
    pub line: Option<u32>,
}

/// Agent 事件
#[derive(Debug, Clone, PartialEq)]
pub enum AgentEvent {
    Start(String),
    Thinking(String),
    ToolCall(String, String),
    Complete(String),
    Error(String),
}

/// 应用状态
pub struct App {
    /// 是否运行中
    running: bool,
    /// 当前布局
    layout: Layout,
    /// 活动面板
    active_panel: PanelType,
    /// 事件接收器
    event_rx: mpsc::UnboundedReceiver<AppEvent>,
    /// 事件发送器
    event_tx: mpsc::UnboundedSender<AppEvent>,
    /// 审计状态
    audit_status: AuditStatus,
    /// 漏洞列表
    findings: Vec<FindingEvent>,
    /// 对话历史
    chat_history: Vec<ChatMessage>,
    /// 当前输入
    input_buffer: String,
    /// 流式响应接收器
    stream_rx: Option<mpsc::UnboundedReceiver<StreamEvent>>,
    /// 当前流式响应内容
    current_response: String,
    /// 是否正在生成响应
    is_generating: bool,
    /// LLM 处理器（可选）
    llm_processor: Option<StreamChatProcessor>,
    /// 审计管理器
    audit_manager: Arc<AuditManager>,
    /// 项目路径
    project_path: Option<String>,
    /// 斜杠命令解析器
    slash_parser: SlashCommandParser,
    /// 斜杠命令执行器（可选，稍后初始化）
    slash_executor: Option<Arc<SlashCommandExecutor>>,
    /// 配置管理器
    config_manager: Arc<std::sync::RwLock<ConfigManager>>,
    /// Ctrl+C 按下次数（用于双重退出）
    ctrl_c_count: u8,
    /// 上次 Ctrl+C 按下时间
    last_ctrl_c_time: Option<std::time::Instant>,
}

/// 审计状态
#[derive(Debug, Clone, PartialEq, Default)]
pub enum AuditStatus {
    #[default]
    Idle,
    Initializing,
    Running,
    Paused,
    Completed,
    Failed(String),
}

/// 聊天消息
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChatRole {
    User,
    Assistant,
    System,
}

impl App {
    /// 创建新的应用
    pub fn new() -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let layout = Layout::default();

        // 初始化配置管理器（同步）
        let config_manager = Arc::new(std::sync::RwLock::new(
            ConfigManager::new(None).map_err(|e| anyhow::anyhow!("{}", e))?
        ));

        // 初始化斜杠命令解析器
        let slash_parser = SlashCommandParser::new();

        Ok(Self {
            running: true,
            layout,
            active_panel: PanelType::ChatInput,
            event_rx,
            event_tx,
            audit_status: AuditStatus::default(),
            findings: Vec::new(),
            chat_history: Vec::new(),
            input_buffer: String::new(),
            stream_rx: None,
            current_response: String::new(),
            is_generating: false,
            llm_processor: None,
            audit_manager: Arc::new(AuditManager::new()),
            project_path: None,
            slash_parser,
            slash_executor: None,
            config_manager,
            ctrl_c_count: 0,
            last_ctrl_c_time: None,
        })
    }

    /// 异步初始化（数据库等）
    pub async fn initialize(&mut self) -> Result<()> {
        // 初始化数据库
        let db = Arc::new(Database::with_default_path().await?);
        db.initialize().await?;

        // 初始化斜杠命令执行器
        self.slash_executor = Some(Arc::new(SlashCommandExecutor::new(db)));

        info!("App initialization complete");
        Ok(())
    }

    /// 运行应用主循环
    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        info!("Starting TUI main loop");

        let mut loop_count: u64 = 0;
        let mut last_key_time = None;

        while self.running {
            loop_count += 1;

            // 绘制界面
            terminal.draw(|f| self.draw(f))?;

            // 处理流式响应事件
            if self.stream_rx.is_some() {
                let mut events = Vec::new();
                if let Some(ref mut rx) = self.stream_rx {
                    while let Ok(event) = rx.try_recv() {
                        events.push(event);
                    }
                }
                for event in events {
                    self.handle_stream_event(event);
                }
            }

            // 处理应用事件
            let mut app_events = Vec::new();
            while let Ok(event) = self.event_rx.try_recv() {
                app_events.push(event);
            }
            for event in app_events {
                self.handle_app_event(event);
            }

            // 处理输入
            if event::poll(std::time::Duration::from_millis(5))? {
                let now = std::time::Instant::now();

                // 检查是否有过快的重复输入（防抖）
                if let Some(last_time) = last_key_time {
                    if now.duration_since(last_time).as_millis() < 10 {
                        debug!("Debouncing fast input, ignoring");
                        continue;
                    }
                }

                let evt = event::read()?;
                match evt {
                    Event::Key(key) => {
                        debug!("Loop {}: Key event received: {:?}", loop_count, key);
                        self.handle_key_event(key);
                        last_key_time = Some(now);
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// 绘制界面
    fn draw(&self, f: &mut Frame) {
        self.layout.render_with_input(f, self.active_panel, &self.input_buffer);
    }

    /// 处理键盘事件
    fn handle_key_event(&mut self, key: KeyEvent) {
        debug!("handle_key_event called: {:?}, buffer length: {}", key, self.input_buffer.len());

        // 重置 Ctrl+C 计数器（按下非 Ctrl+C 键时）
        let is_ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
        if !is_ctrl_c && self.ctrl_c_count > 0 {
            self.ctrl_c_count = 0;
            self.last_ctrl_c_time = None;
        }

        // 处理 Ctrl+C (双重退出)
        if is_ctrl_c {
            let now = std::time::Instant::now();

            // 检查是否在 2 秒内按下第二次 Ctrl+C
            if let Some(last_time) = self.last_ctrl_c_time {
                if now.duration_since(last_time).as_secs() < 2 {
                    // 第二次 Ctrl+C，退出
                    self.running = false;
                    return;
                }
            }

            // 第一次 Ctrl+C
            self.ctrl_c_count += 1;
            self.last_ctrl_c_time = Some(now);

            // 显示提示
            self.layout.add_system_message("再按一次 Ctrl+C 退出程序".to_string());
            return;
        }

        match key.code {
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.running = false;
            }
            KeyCode::Char('q') => {
                if self.chat_history.is_empty() || self.audit_status == AuditStatus::Idle {
                    self.running = false;
                }
            }
            KeyCode::Tab => {
                self.active_panel = self.layout.next_panel(self.active_panel);
            }
            KeyCode::BackTab => {
                self.active_panel = self.layout.prev_panel(self.active_panel);
            }
            KeyCode::Char(c) => {
                if self.active_panel == PanelType::ChatInput {
                    debug!("Char '{}' added to buffer", c);
                    self.input_buffer.push(c);
                    debug!("Buffer is now: '{}', len: {}", self.input_buffer, self.input_buffer.len());
                }
            }
            KeyCode::Enter => {
                if self.active_panel == PanelType::ChatInput && !self.input_buffer.is_empty() {
                    self.handle_chat_input();
                }
            }
            KeyCode::Backspace => {
                if self.active_panel == PanelType::ChatInput {
                    debug!("Backspace, buffer before pop: '{}'", self.input_buffer);
                    self.input_buffer.pop();
                }
            }
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right => {
                self.layout.handle_navigation(key.code);
            }
            _ => {}
        }

        debug!("handle_key_event completed, buffer: '{}'", self.input_buffer);
    }

    /// 处理应用事件
    fn handle_app_event(&mut self, event: AppEvent) {
        debug!("App event: {:?}", event);

        match event {
            // 注意：键盘事件已在主循环中直接处理，这里不再处理避免重复
            // AppEvent::Key(key) => self.handle_key_event(key),
            AppEvent::AuditProgress(progress, message) => {
                self.layout.update_progress(progress, message);
            }
            AppEvent::NewFinding(finding) => {
                self.findings.push(finding);
                self.layout.update_findings_count(self.findings.len());
            }
            AppEvent::Agent(agent_event) => {
                match agent_event {
                    AgentEvent::Thinking(msg) => {
                        self.layout.add_thought(msg);
                    }
                    AgentEvent::ToolCall(tool, input) => {
                        self.layout.add_tool_call(tool, input);
                    }
                    AgentEvent::Complete(msg) => {
                        self.audit_status = AuditStatus::Completed;
                        self.layout.add_assistant_message(msg);
                    }
                    AgentEvent::Error(err) => {
                        self.audit_status = AuditStatus::Failed(err);
                    }
                    _ => {}
                }
            }
            AppEvent::Error(err) => {
                self.layout.add_error(err);
            }
            AppEvent::System(msg) => {
                self.layout.add_system_message(msg);
            }
            AppEvent::Quit => {
                self.running = false;
            }
            _ => {}
        }
    }

    /// 处理聊天输入
    fn handle_chat_input(&mut self) {
        let input = self.input_buffer.clone();
        self.input_buffer.clear();

        // 添加用户消息
        self.chat_history.push(ChatMessage {
            role: ChatRole::User,
            content: input.clone(),
            timestamp: chrono::Utc::now(),
        });

        // 处理斜杠命令
        if input.starts_with('/') {
            self.handle_slash_command(&input);
        } else {
            // 发送到 LLM
            self.layout.add_user_message(input.clone());
            self.send_to_llm(input);
        }
    }

    /// 处理斜杠命令
    fn handle_slash_command(&mut self, input: &str) {
        // 使用斜杠命令解析器
        match self.slash_parser.parse(input) {
            Ok(SlashCommand::Quit) => {
                self.running = false;
            }
            Ok(SlashCommand::Help) => {
                self.show_help();
            }
            Ok(SlashCommand::Clear) => {
                self.chat_history.clear();
                self.layout.clear_chat();
                self.layout.add_system_message("屏幕已清除".to_string());
            }
            Ok(SlashCommand::Audit { path }) => {
                // 检查 LLM 配置
                if !self.check_llm_config() {
                    self.layout.add_error("LLM 未配置。请使用 /config llm.api_key <your-api-key> 配置 API 密钥。".to_string());
                    self.layout.add_system_message(
                        "\n配置示例:\n  /config llm.provider anthropic\n  /config llm.api_key sk-ant-xxx...\n  /config llm.model claude-3-5-sonnet-20241022\n".to_string()
                    );
                    return;
                }

                let project_path = path.unwrap_or_else(|| {
                    self.project_path.clone().unwrap_or_else(|| ".".to_string())
                });
                self.start_audit(project_path);
            }
            Ok(SlashCommand::Config { key, value }) => {
                let key_clone = key.clone();
                let value_clone = value.clone();
                let config_manager = Arc::clone(&self.config_manager);

                // 异步处理配置命令
                let event_tx = self.event_tx.clone();

                // 处理读操作（不需要 await）
                let read_result = match (&key_clone, &value_clone) {
                    (None, None) => {
                        // 显示所有配置
                        if let Some(manager) = config_manager.read().ok() {
                            let mut msg = "当前配置:\n\n".to_string();
                            if let Some(provider) = manager.get("llm.provider") {
                                msg.push_str(&format!("  LLM 提供商: {}\n", provider));
                            }
                            if let Some(model) = manager.get("llm.model") {
                                msg.push_str(&format!("  模型: {}\n", model));
                            }
                            if manager.get("llm.api_key").is_some() {
                                msg.push_str("  API 密钥: ***已配置***\n");
                            } else {
                                msg.push_str("  API 密钥: ***未配置***\n");
                            }
                            Some(msg)
                        } else {
                            Some("配置管理器错误".to_string())
                        }
                    }
                    (None, Some(_)) => {
                        Some("配置键不能为空".to_string())
                    }
                    (Some(k), None) => {
                        if let Some(manager) = config_manager.read().ok() {
                            if let Some(v) = manager.get(k) {
                                Some(if k.contains("api_key") {
                                    format!("{}: ***已配置***", k)
                                } else {
                                    format!("{}: {}", k, v)
                                })
                            } else {
                                Some(format!("{}: (未设置)", k))
                            }
                        } else {
                            Some("配置管理器错误".to_string())
                        }
                    }
                    (Some(_), Some(_)) => None, // 需要写操作，在异步任务中处理
                };

                // 如果是读操作，直接发送结果
                if let Some(msg) = read_result {
                    let _ = event_tx.send(AppEvent::System(msg));
                } else {
                    // 写操作需要异步任务
                    let k = key_clone.clone().unwrap();
                    let v = value_clone.clone().unwrap();
                    let config_manager_clone = Arc::clone(&config_manager);

                    // 写操作 - 立即设置值并发送响应，然后在后台保存
                    let k = key_clone.clone().unwrap();
                    let v = value_clone.clone().unwrap();
                    let config_manager_clone = Arc::clone(&config_manager);

                    // 设置值并准备响应
                    let (set_result, response) = if let Some(mut manager) = config_manager.write().ok() {
                        let set_result = manager.set(&k, v.clone());
                        let response = match &set_result {
                            Ok(_) => format!("配置已更新: {} = {}",
                                if k.contains("api_key") { "***" } else { &k },
                                if k.contains("api_key") { "***" } else { &v }),
                            Err(e) => format!("设置失败: {}", e),
                        };
                        (set_result, response)
                    } else {
                        (Err(anyhow::anyhow!("无法获取配置锁")), "配置管理器错误".to_string())
                    };

                    // 立即发送响应
                    let _ = event_tx.send(AppEvent::System(response));

                    // 如果设置成功，在后台异步保存（不需要返回结果）
                    if set_result.is_ok() {
                        let _ = std::thread::spawn(move || {
                            // 使用 tokio runtime 来运行异步保存
                            let rt = tokio::runtime::Handle::try_current();
                            if let Ok(rt) = rt {
                                rt.block_on(async {
                                    if let Some(mut manager) = config_manager_clone.write().ok() {
                                        if let Err(e) = manager.save().await {
                                            tracing::error!("配置保存失败: {}", e);
                                        }
                                    }
                                });
                            }
                        });
                    }
                }
            }
            Ok(SlashCommand::Cd { path }) => {
                self.project_path = Some(path.clone());
                self.layout.add_system_message(format!("切换到: {}", path));
            }
            Ok(SlashCommand::Findings) => {
                // 显示漏洞列表
                self.layout.add_system_message("漏洞列表功能开发中...".to_string());
            }
            Ok(cmd) => {
                // 对于其他命令，使用执行器
                if let Some(executor) = &self.slash_executor {
                    let executor = Arc::clone(executor);
                    let event_tx = self.event_tx.clone();

                    tokio::spawn(async move {
                        match executor.execute(&cmd).await {
                            Ok(msg) => {
                                let _ = event_tx.send(AppEvent::System(msg));
                            }
                            Err(err) => {
                                let _ = event_tx.send(AppEvent::Error(err));
                            }
                        }
                    });
                } else {
                    self.layout.add_error("数据库未初始化".to_string());
                }
            }
            Err(err) => {
                self.layout.add_error(format!("命令错误: {}", err));
            }
        }
    }

    /// 检查 LLM 配置
    fn check_llm_config(&self) -> bool {
        if let Ok(manager) = self.config_manager.read() {
            manager.get("llm.api_key").is_some()
        } else {
            false
        }
    }

    /// 开始审计
    fn start_audit(&mut self, path: String) {
        self.audit_status = AuditStatus::Initializing;
        self.project_path = Some(path.clone());
        self.layout.add_system_message(format!("开始审计: {}", path));

        // 使用审计管理器启动审计
        let event_tx = self.event_tx.clone();
        let audit_manager = Arc::clone(&self.audit_manager);

        tokio::spawn(async move {
            if let Err(e) = audit_manager.start_audit(path, event_tx).await {
                tracing::error!("Failed to start audit: {:?}", e);
            }
        });
    }

    /// 显示帮助
    fn show_help(&mut self) {
        let help = r#"
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

快捷键:
  Tab            - 切换面板
  Shift+Tab      - 反向切换面板
  Ctrl+Q         - 强制退出
  方向键         - 导航列表

LLM 配置:
  /config llm.provider anthropic
  /config llm.api_key sk-ant-xxx...
  /config llm.model claude-3-5-sonnet-20241022
"#;
        self.layout.add_system_message(help.to_string());
    }

    /// 发送事件
    pub fn send_event(&self, event: AppEvent) -> Result<()> {
        // TODO: 实现事件发送
        Ok(())
    }

    /// 处理流式响应事件
    fn handle_stream_event(&mut self, event: StreamEvent) {
        match event {
            StreamEvent::Start => {
                self.is_generating = true;
                self.current_response.clear();
                self.layout.add_system_message("AI 正在思考...".to_string());
            }
            StreamEvent::Token(token) => {
                self.current_response.push_str(&token);
                // 实时更新显示
                self.layout.add_assistant_message(token);
            }
            StreamEvent::Complete => {
                self.is_generating = false;
                // 保存完整的响应到历史
                if !self.current_response.is_empty() {
                    self.chat_history.push(ChatMessage {
                        role: ChatRole::Assistant,
                        content: self.current_response.clone(),
                        timestamp: chrono::Utc::now(),
                    });
                }
                self.stream_rx = None;
            }
            StreamEvent::Error(err) => {
                self.is_generating = false;
                self.layout.add_error(format!("AI 响应错误: {}", err));
                self.stream_rx = None;
            }
        }
    }

    /// 发送消息到 LLM
    fn send_to_llm(&mut self, message: String) {
        use ctx_audit_llm::{LLMMessage, MessageRole, MessageContent};

        // 构建消息历史
        let messages: Vec<LLMMessage> = self.chat_history
            .iter()
            .map(|msg| LLMMessage {
                role: match msg.role {
                    ChatRole::User => MessageRole::User,
                    ChatRole::Assistant => MessageRole::Assistant,
                    ChatRole::System => MessageRole::System,
                },
                content: vec![MessageContent::Text { text: msg.content.clone() }],
                cache_control: None,
            })
            .collect();

        // 添加当前消息
        let mut all_messages = messages;
        all_messages.push(LLMMessage {
            role: MessageRole::User,
            content: vec![MessageContent::Text { text: message }],
            cache_control: None,
        });

        // 创建流式响应通道
        let (tx, rx) = mpsc::unbounded_channel();
        self.stream_rx = Some(rx);

        // TODO: 实际调用 LLM
        // 这里需要异步任务来处理 LLM 调用
        // 暂时模拟响应
        self.layout.add_system_message("LLM 集成待实现...".to_string());
    }
}
