// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 状态栏组件

use ratatui::{Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap}};

/// 状态栏组件
pub struct StatusBar {
    /// 左侧文本
    left: String,
    /// 中间文本
    center: String,
    /// 右侧文本
    right: String,
}

impl StatusBar {
    /// 创建新的状态栏
    pub fn new() -> Self {
        Self {
            left: String::new(),
            center: String::new(),
            right: String::new(),
        }
    }

    /// 设置左侧文本
    pub fn left(mut self, text: impl Into<String>) -> Self {
        self.left = text.into();
        self
    }

    /// 设置中间文本
    pub fn center(mut self, text: impl Into<String>) -> Self {
        self.center = text.into();
        self
    }

    /// 设置右侧文本
    pub fn right(mut self, text: impl Into<String>) -> Self {
        self.right = text.into();
        self
    }

    /// 渲染状态栏
    pub fn render(&self, f: &mut Frame, rect: Rect) {
        let line = Line::from(vec![
            Span::styled(&self.left, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::styled(&self.center, Style::default()),
            Span::raw(" "),
            Span::styled(&self.right, Style::default().fg(Color::Yellow)),
        ]);

        let paragraph = Paragraph::new(line)
            .block(Block::default().borders(Borders::ALL));

        f.render_widget(paragraph, rect);
    }
}

impl Default for StatusBar {
    fn default() -> Self {
        Self::new()
    }
}
