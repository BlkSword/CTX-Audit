// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 流式响应渲染器

use ratatui::{Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap}};

/// 流式响应渲染器
pub struct StreamRenderer {
    /// 当前内容
    content: String,
    /// 显示的内容（用于打字机效果）
    displayed_content: String,
    /// 光标可见性
    cursor_visible: bool,
    /// 是否正在流式传输
    is_streaming: bool,
    /// 代码块检测
    in_code_block: bool,
    /// 代码块语言
    code_block_lang: Option<String>,
}

impl StreamRenderer {
    /// 创建新的渲染器
    pub fn new() -> Self {
        Self {
            content: String::new(),
            displayed_content: String::new(),
            cursor_visible: true,
            is_streaming: false,
            in_code_block: false,
            code_block_lang: None,
        }
    }

    /// 添加内容
    pub fn add_content(&mut self, text: &str) {
        self.content.push_str(text);
        self.update_displayed_content();
    }

    /// 设置完整内容
    pub fn set_content(&mut self, content: String) {
        self.content = content;
        self.update_displayed_content();
    }

    /// 设置流式状态
    pub fn set_streaming(&mut self, streaming: bool) {
        self.is_streaming = streaming;
    }

    /// 更新光标状态（用于闪烁效果）
    pub fn toggle_cursor(&mut self) {
        self.cursor_visible = !self.cursor_visible;
    }

    /// 获取内容
    pub fn content(&self) -> &str {
        &self.content
    }

    /// 渲染到 Frame
    pub fn render(&self, f: &mut Frame, rect: Rect) {
        let lines = self.format_content();

        let border_style = if self.is_streaming {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let title = if self.is_streaming {
            " AI 响应中... "
        } else {
            " AI 响应 "
        };

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, rect);
    }

    /// 格式化内容
    fn format_content(&self) -> Vec<Line> {
        let mut lines = Vec::new();
        let text = &self.displayed_content;

        for line in text.lines() {
            if let Some(code_start) = line.trim_start().strip_prefix("```") {
                // 代码块标记
                if self.in_code_block {
                    // 结束代码块
                    lines.push(Line::from(Span::styled(
                        "```",
                        Style::default().fg(Color::DarkGray)
                    )));
                } else {
                    // 开始代码块
                    let lang = code_start.trim();
                    let lang_span = if lang.is_empty() {
                        Span::styled("代码块", Style::default().fg(Color::Magenta))
                    } else {
                        Span::styled(
                            format!("{} 代码块", lang),
                            Style::default().fg(Color::Magenta)
                        )
                    };
                    lines.push(Line::from(vec![
                        Span::styled("▸ ", Style::default().fg(Color::Magenta)),
                        lang_span,
                    ]));
                }
            } else if line.starts_with("# ") {
                // 标题
                lines.push(Line::from(Span::styled(
                    line,
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                )));
            } else if line.starts_with("- ") || line.starts_with("* ") {
                // 列表项
                lines.push(Line::from(vec![
                    Span::styled("• ", Style::default().fg(Color::Yellow)),
                    Span::styled(&line[2..], Style::default()),
                ]));
            } else if line.starts_with("> ") {
                // 引用
                lines.push(Line::from(Span::styled(
                    line,
                    Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)
                )));
            } else if line.starts_with("**") && line.ends_with("**") {
                // 粗体
                let content = &line[2..line.len()-2];
                lines.push(Line::from(Span::styled(
                    content,
                    Style::default().add_modifier(Modifier::BOLD)
                )));
            } else {
                // 普通文本
                lines.push(Line::from(Span::styled(line, Style::default())));
            }
        }

        // 添加闪烁光标
        if self.is_streaming && self.cursor_visible {
            if let Some(last_line) = lines.last_mut() {
                last_line.spans.push(Span::styled("▊", Style::default().fg(Color::Cyan)));
            }
        }

        lines
    }

    /// 更新显示的内容（打字机效果）
    fn update_displayed_content(&mut self) {
        // 简单实现：显示全部内容
        // TODO: 实现渐进式显示
        self.displayed_content = self.content.clone();
    }

    /// 清空内容
    pub fn clear(&mut self) {
        self.content.clear();
        self.displayed_content.clear();
        self.in_code_block = false;
        self.code_block_lang = None;
    }
}

impl Default for StreamRenderer {
    fn default() -> Self {
        Self::new()
    }
}
