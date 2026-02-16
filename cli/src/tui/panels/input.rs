// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 输入面板

use ratatui::{Frame, layout::Rect, style::{Color, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap}};

/// 输入面板
pub struct InputPanel {
    /// 输入缓冲区
    buffer: String,
    /// 历史记录
    history: Vec<String>,
    /// 历史索引
    history_index: usize,
    /// 提示信息
    placeholder: String,
}

impl InputPanel {
    /// 创建新的输入面板
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            history: Vec::new(),
            history_index: 0,
            placeholder: "输入命令或消息...".to_string(),
        }
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let display = if self.buffer.is_empty() {
            Span::styled(
                &self.placeholder,
                Style::default().fg(Color::DarkGray)
            )
        } else {
            Span::raw(&self.buffer)
        };

        let line = Line::from(vec![
            Span::styled("> ", Style::default().fg(Color::Green)),
            display,
            Span::styled("_", Style::default().fg(Color::White)),
        ]);

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(line)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, rect);
    }

    /// 添加字符
    pub fn insert_char(&mut self, c: char) {
        self.buffer.push(c);
    }

    /// 删除字符
    pub fn remove_char(&mut self) {
        self.buffer.pop();
    }

    /// 提交输入
    pub fn submit(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }

        let input = self.buffer.clone();
        self.history.push(input.clone());
        self.history_index = self.history.len();
        self.buffer.clear();
        Some(input)
    }

    /// 清空输入
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// 上一个历史记录
    pub fn history_prev(&mut self) {
        if !self.history.is_empty() && self.history_index > 0 {
            self.history_index -= 1;
            self.buffer = self.history[self.history_index].clone();
        }
    }

    /// 下一个历史记录
    pub fn history_next(&mut self) {
        if self.history_index < self.history.len() {
            self.history_index += 1;
            if self.history_index < self.history.len() {
                self.buffer = self.history[self.history_index].clone();
            } else {
                self.buffer.clear();
            }
        }
    }

    /// 获取输入内容
    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    /// 设置输入内容
    pub fn set_buffer(&mut self, buffer: String) {
        self.buffer = buffer;
    }
}

impl Default for InputPanel {
    fn default() -> Self {
        Self::new()
    }
}
