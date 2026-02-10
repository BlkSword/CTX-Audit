// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码块组件

use ratatui::{Frame, layout::Rect, style::{Color, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap}};

/// 代码块组件
pub struct CodeBlock<'a> {
    /// 代码内容
    code: &'a str,
    /// 语言
    language: Option<String>,
    /// 起始行号
    start_line: usize,
    /// 是否显示行号
    show_line_numbers: bool,
    /// 高亮行
    highlight_lines: Vec<usize>,
}

impl<'a> CodeBlock<'a> {
    /// 创建新的代码块
    pub fn new(code: &'a str) -> Self {
        Self {
            code,
            language: None,
            start_line: 1,
            show_line_numbers: true,
            highlight_lines: Vec::new(),
        }
    }

    /// 设置语言
    pub fn language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }

    /// 设置起始行号
    pub fn start_line(mut self, line: usize) -> Self {
        self.start_line = line;
        self
    }

    /// 是否显示行号
    pub fn show_line_numbers(mut self, show: bool) -> Self {
        self.show_line_numbers = show;
        self
    }

    /// 添加高亮行
    pub fn highlight_line(mut self, line: usize) -> Self {
        self.highlight_lines.push(line);
        self
    }

    /// 渲染代码块
    pub fn render(&self, f: &mut Frame, rect: Rect) {
        let mut lines = Vec::new();

        for (i, line) in self.code.lines().enumerate() {
            let line_num = i + self.start_line;
            let is_highlighted = self.highlight_lines.contains(&line_num);

            let mut spans = Vec::new();

            if self.show_line_numbers {
                spans.push(Span::styled(
                    format!("{:4} │ ", line_num),
                    Style::default().fg(Color::DarkGray)
                ));
            }

            let style = if is_highlighted {
                Style::default().fg(Color::Yellow).add_modifier(ratatui::style::Modifier::BOLD)
            } else {
                Style::default()
            };

            spans.push(Span::styled(line, style));
            lines.push(Line::from(spans));
        }

        let title = if let Some(lang) = &self.language {
            format!(" {} ", lang)
        } else {
            " Code ".to_string()
        };

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(title)
                .borders(Borders::ALL)
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, rect);
    }
}
