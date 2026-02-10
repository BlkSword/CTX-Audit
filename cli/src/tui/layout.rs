// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! TUI 布局系统

use crossterm::event::KeyCode;
use ratatui::{
    backend::Backend,
    Frame,
    layout::{Alignment, Constraint, Direction, Layout as RatatuiLayout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use super::app::{AuditStatus, FindingEvent};

/// 面板类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PanelType {
    /// 文件浏览器
    Explorer,
    /// 主面板（聊天/代码）
    Main,
    /// 侧边栏（漏洞/事件）
    Side,
    /// 输入面板
    ChatInput,
    /// 状态栏
    Status,
}

/// 布局配置
#[derive(Debug, Clone)]
pub struct AppLayout {
    /// 主分割比例
    main_split: [Constraint; 3],
    /// 当前活动面板
    active_panel: PanelType,
    /// 进度百分比
    progress: u8,
    /// 进度消息
    progress_message: String,
    /// 漏洞数量
    findings_count: usize,
    /// 聊天消息
    chat_messages: Vec<ChatMessageData>,
    /// 思考过程
    thoughts: Vec<String>,
    /// 工具调用
    tool_calls: Vec<ToolCallData>,
    /// 错误消息
    errors: Vec<String>,
}

/// 聊天消息数据
#[derive(Debug, Clone)]
struct ChatMessageData {
    role: ChatRole,
    content: String,
}

/// 工具调用数据
#[derive(Debug, Clone)]
struct ToolCallData {
    tool: String,
    input: String,
}

#[derive(Debug, Clone, PartialEq)]
enum ChatRole {
    User,
    Assistant,
    System,
}

impl Default for AppLayout {
    fn default() -> Self {
        Self {
            main_split: [
                Constraint::Percentage(25),
                Constraint::Percentage(50),
                Constraint::Percentage(25),
            ],
            active_panel: PanelType::Main,
            progress: 0,
            progress_message: String::new(),
            findings_count: 0,
            chat_messages: Vec::new(),
            thoughts: Vec::new(),
            tool_calls: Vec::new(),
            errors: Vec::new(),
        }
    }
}

impl AppLayout {
    /// 创建新布局
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取下一个面板
    pub fn next_panel(&self, current: PanelType) -> PanelType {
        match current {
            PanelType::Explorer => PanelType::Main,
            PanelType::Main => PanelType::Side,
            PanelType::Side => PanelType::ChatInput,
            PanelType::ChatInput => PanelType::Explorer,
            PanelType::Status => PanelType::Explorer,
        }
    }

    /// 获取上一个面板
    pub fn prev_panel(&self, current: PanelType) -> PanelType {
        match current {
            PanelType::Explorer => PanelType::ChatInput,
            PanelType::Main => PanelType::Explorer,
            PanelType::Side => PanelType::Main,
            PanelType::ChatInput => PanelType::Side,
            PanelType::Status => PanelType::Side,
        }
    }

    /// 渲染布局
    pub fn render(&self, f: &mut Frame, active: PanelType) {
        self.render_with_input(f, active, "")
    }

    /// 渲染布局（带输入）
    pub fn render_with_input(&self, f: &mut Frame, active: PanelType, input: &str) {
        let size = f.area();

        // 顶部状态栏
        let status_height = 3;
        let status_rect = Rect {
            x: size.x,
            y: size.y,
            width: size.width,
            height: status_height,
        };
        self.render_status_bar(f, status_rect, active);

        // 主内容区域
        let main_rect = Rect {
            x: size.x,
            y: size.y + status_height,
            width: size.width,
            height: size.height - status_height - 3, // -3 for input area
        };

        // 三栏布局
        let chunks = RatatuiLayout::default()
            .direction(Direction::Horizontal)
            .constraints(self.main_split.as_ref())
            .split(main_rect);

        // 左侧面板 - 文件浏览器
        self.render_explorer(f, chunks[0], active == PanelType::Explorer);

        // 中间面板 - 主内容
        self.render_main_panel(f, chunks[1], active == PanelType::Main);

        // 右侧面板 - 漏洞列表
        self.render_findings(f, chunks[2], active == PanelType::Side);

        // 底部输入区域
        let input_rect = Rect {
            x: size.x,
            y: size.y + size.height - 3,
            width: size.width,
            height: 3,
        };
        self.render_input(f, input_rect, active == PanelType::ChatInput, input);
    }

    /// 渲染状态栏
    fn render_status_bar(&self, f: &mut Frame, rect: Rect, active: PanelType) {
        let chunks = RatatuiLayout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(25),
                Constraint::Percentage(50),
                Constraint::Percentage(25),
            ])
            .split(rect);

        // 左侧 - 项目信息
        let left_text = vec![
            Line::from(vec![
                Span::styled("CTX-Audit", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(" | "),
                Span::styled("v2.0.0", Style::default().fg(Color::DarkGray)),
            ])
        ];
        let left_paragraph = Paragraph::new(left_text)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(left_paragraph, chunks[0]);

        // 中间 - 进度
        let progress_text = if self.progress > 0 {
            format!("{}% - {}", self.progress, self.progress_message)
        } else {
            "就绪".to_string()
        };
        let center_text = vec![Line::from(progress_text)];
        let center_paragraph = Paragraph::new(center_text)
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(center_paragraph, chunks[1]);

        // 右侧 - 统计
        let right_text = vec![
            Line::from(vec![
                Span::raw(format!("漏洞: {} | ", self.findings_count)),
                Span::styled(
                    format!("活动: {:?}", active),
                    Style::default().fg(Color::Yellow)
                ),
            ])
        ];
        let right_paragraph = Paragraph::new(right_text)
            .alignment(Alignment::Right)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(right_paragraph, chunks[2]);
    }

    /// 渲染文件浏览器
    fn render_explorer(&self, f: &mut Frame, rect: Rect, active: bool) {
        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let text = vec![
            Line::from("📁 项目文件"),
            Line::from(""),
            Line::from("  📂 src/"),
            Line::from("  📂 tests/"),
            Line::from("  📄 README.md"),
            Line::from("  📄 Cargo.toml"),
        ];

        let paragraph = Paragraph::new(text)
            .block(Block::default()
                .title(" 文件浏览器 ")
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, rect);
    }

    /// 渲染主面板（聊天/代码）
    fn render_main_panel(&self, f: &mut Frame, rect: Rect, active: bool) {
        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let mut lines = Vec::new();

        // 渲染聊天消息
        for msg in &self.chat_messages {
            let (prefix, style) = match msg.role {
                ChatRole::User => ("You", Style::default().fg(Color::Green)),
                ChatRole::Assistant => ("AI", Style::default().fg(Color::Cyan)),
                ChatRole::System => ("System", Style::default().fg(Color::Yellow)),
            };

            lines.push(Line::from(vec![
                Span::styled(format!("[{}]", prefix), style.add_modifier(Modifier::BOLD)),
                Span::raw(" "),
                Span::raw(&msg.content),
            ]));
            lines.push(Line::from(""));
        }

        // 渲染思考过程
        if !self.thoughts.is_empty() {
            lines.push(Line::from(Span::styled(
                "💭 思考中...",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::ITALIC)
            )));
            for thought in &self.thoughts {
                lines.push(Line::from(vec![
                    Span::styled("  → ", Style::default().fg(Color::DarkGray)),
                    Span::styled(thought, Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)),
                ]));
            }
            lines.push(Line::from(""));
        }

        // 渲染工具调用
        if !self.tool_calls.is_empty() {
            lines.push(Line::from(Span::styled(
                "🔧 工具调用",
                Style::default().fg(Color::Magenta)
            )));
            for tc in &self.tool_calls {
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(Color::Magenta)),
                    Span::styled(&tc.tool, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
                    Span::raw(format!(": {}", &tc.input.chars().take(50).collect::<String>())),
                ]));
            }
        }

        // 渲染错误
        for error in &self.errors {
            lines.push(Line::from(vec![
                Span::styled("✗ ", Style::default().fg(Color::Red)),
                Span::styled(error, Style::default().fg(Color::Red)),
            ]));
        }

        if lines.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("欢迎使用 CTX-Audit", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("快速开始:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("1. 配置 LLM: ", Style::default().fg(Color::DarkGray)),
                Span::styled("/config llm.api_key <your-key>", Style::default().fg(Color::Green)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("2. 开始审计: ", Style::default().fg(Color::DarkGray)),
                Span::styled("/audit <项目路径>", Style::default().fg(Color::Yellow)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("输入 ", Style::default().fg(Color::DarkGray)),
                Span::styled("/help", Style::default().fg(Color::Cyan)),
                Span::styled(" 查看所有可用命令", Style::default().fg(Color::DarkGray)),
            ]));
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(" 主面板 ")
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, rect);
    }

    /// 渲染漏洞列表
    fn render_findings(&self, f: &mut Frame, rect: Rect, active: bool) {
        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled(" 漏洞列表 ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
                Span::styled(format!("({})", self.findings_count), Style::default().fg(Color::DarkGray)),
            ]),
            Line::from(""),
        ];

        if self.findings_count == 0 {
            lines.push(Line::from(Span::styled(
                "暂无漏洞发现",
                Style::default().fg(Color::DarkGray)
            )));
        } else {
            // TODO: 显示实际漏洞列表
            lines.push(Line::from(Span::styled(
                "等待审计完成...",
                Style::default().fg(Color::DarkGray)
            )));
        }

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(" 漏洞 ")
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, rect);
    }

    /// 渲染输入区域
    fn render_input(&self, f: &mut Frame, rect: Rect, active: bool, input: &str) {
        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        // 显示实际输入内容，如果为空则显示提示符
        let display_input = if input.is_empty() {
            ""
        } else {
            input
        };

        let input_text = vec![Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Green)),
            Span::raw(display_input),
            Span::raw("█"), // 光标
        ])];

        let paragraph = Paragraph::new(input_text)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
            );

        f.render_widget(paragraph, rect);
    }

    /// 处理导航
    pub fn handle_navigation(&mut self, _key: KeyCode) {
        // TODO: 实现列表导航
    }

    /// 更新进度
    pub fn update_progress(&mut self, progress: u8, message: String) {
        self.progress = progress;
        self.progress_message = message;
    }

    /// 更新漏洞数量
    pub fn update_findings_count(&mut self, count: usize) {
        self.findings_count = count;
    }

    /// 添加用户消息
    pub fn add_user_message(&mut self, content: String) {
        self.chat_messages.push(ChatMessageData {
            role: ChatRole::User,
            content,
        });
    }

    /// 添加助手消息
    pub fn add_assistant_message(&mut self, content: String) {
        self.chat_messages.push(ChatMessageData {
            role: ChatRole::Assistant,
            content,
        });
    }

    /// 添加系统消息
    pub fn add_system_message(&mut self, content: String) {
        self.chat_messages.push(ChatMessageData {
            role: ChatRole::System,
            content,
        });
    }

    /// 清空聊天
    pub fn clear_chat(&mut self) {
        self.chat_messages.clear();
    }

    /// 添加思考过程
    pub fn add_thought(&mut self, thought: String) {
        self.thoughts.push(thought);
    }

    /// 添加工具调用
    pub fn add_tool_call(&mut self, tool: String, input: String) {
        self.tool_calls.push(ToolCallData { tool, input });
    }

    /// 添加错误
    pub fn add_error(&mut self, error: String) {
        self.errors.push(error);
    }
}

// 导出为 Layout 以保持接口兼容
pub type Layout = AppLayout;
