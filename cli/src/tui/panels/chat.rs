// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 聊天面板

use ratatui::{Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap}};

/// 聊天面板
pub struct ChatPanel {
    /// 消息列表
    messages: Vec<ChatMessage>,
    /// 滚动位置
    scroll: usize,
}

/// 聊天消息
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// 聊天角色
#[derive(Debug, Clone, PartialEq)]
pub enum ChatRole {
    User,
    Assistant,
    System,
    Tool,
}

impl ChatPanel {
    /// 创建新的聊天面板
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            scroll: 0,
        }
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let mut lines = Vec::new();

        for msg in &self.messages {
            let (prefix, style) = match msg.role {
                ChatRole::User => ("You", Style::default().fg(Color::Green)),
                ChatRole::Assistant => ("AI", Style::default().fg(Color::Cyan)),
                ChatRole::System => ("System", Style::default().fg(Color::Yellow)),
                ChatRole::Tool => ("Tool", Style::default().fg(Color::Magenta)),
            };

            lines.push(Line::from(vec![
                Span::styled(format!("[{}]", prefix), style.add_modifier(Modifier::BOLD)),
                Span::raw(" "),
                Span::raw(&msg.content),
            ]));
            lines.push(Line::from(""));
        }

        if lines.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("欢迎使用 CTX-Audit", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("输入命令开始审计", Style::default().fg(Color::DarkGray)),
            ]));
        }

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(" 主面板 ")
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: true })
            .scroll((self.scroll as u16, 0));

        f.render_widget(paragraph, rect);
    }

    /// 添加消息
    pub fn add_message(&mut self, role: ChatRole, content: String) {
        self.messages.push(ChatMessage {
            role,
            content,
            timestamp: chrono::Utc::now(),
        });
    }

    /// 添加用户消息
    pub fn add_user_message(&mut self, content: String) {
        self.add_message(ChatRole::User, content);
    }

    /// 添加助手消息
    pub fn add_assistant_message(&mut self, content: String) {
        self.add_message(ChatRole::Assistant, content);
    }

    /// 添加系统消息
    pub fn add_system_message(&mut self, content: String) {
        self.add_message(ChatRole::System, content);
    }

    /// 清空消息
    pub fn clear(&mut self) {
        self.messages.clear();
        self.scroll = 0;
    }

    /// 向下滚动
    pub fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    /// 向上滚动
    pub fn scroll_up(&mut self) {
        self.scroll += 1;
    }
}

impl Default for ChatPanel {
    fn default() -> Self {
        Self::new()
    }
}
