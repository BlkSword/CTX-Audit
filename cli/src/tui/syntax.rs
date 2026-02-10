// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码语法高亮

use ratatui::{Frame, layout::Rect, style::{Color, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap}};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::{SyntaxSet, SyntaxReference};

/// 语法高亮渲染器
pub struct CodeHighlighter {
    /// 语法集合
    syntax_set: SyntaxSet,
    /// 主题集合
    theme_set: ThemeSet,
    /// 当前主题
    theme: Theme,
}

impl CodeHighlighter {
    /// 创建新的高亮器
    pub fn new() -> Self {
        let syntax_set = SyntaxSet::load_defaults_newlines();
        let theme_set = ThemeSet::load_defaults();

        // 使用 base16-ocean.dark 主题
        let theme = theme_set.themes.get("base16-ocean.dark")
            .or_else(|| theme_set.themes.get("Solarized (dark)"))
            .unwrap_or_else(|| theme_set.themes.values().next().unwrap())
            .clone();

        Self {
            syntax_set,
            theme_set,
            theme,
        }
    }

    /// 渲染代码块
    pub fn render_code(&self, f: &mut Frame, rect: Rect, code: &str, language: Option<&str>) {
        let syntax = self.get_syntax(language);
        let mut highlighter = HighlightLines::new(syntax, &self.theme);

        let mut lines = Vec::new();

        for (i, line) in code.lines().enumerate() {
            let ranges = highlighter.highlight_line(line, &self.syntax_set).unwrap_or_default();

            let spans: Vec<Span> = ranges
                .iter()
                .map(|(style, text)| {
                    let color = self.syntect_color_to_ratatui(&style.foreground);
                    Span::styled(*text, Style::default().fg(color))
                })
                .collect();

            if !spans.is_empty() {
                // 添加行号
                let line_num = Span::styled(
                    format!("{:4} │ ", i + 1),
                    Style::default().fg(Color::DarkGray)
                );

                let mut all_spans = vec![line_num];
                all_spans.extend(spans);
                lines.push(Line::from(all_spans));
            } else {
                lines.push(Line::from(""));
            }
        }

        let border_style = Style::default().fg(Color::Cyan);

        let title = if let Some(lang) = language {
            format!(" {} ", lang)
        } else {
            " Code ".to_string()
        };

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, rect);
    }

    /// 获取语言对应的语法
    fn get_syntax(&self, language: Option<&str>) -> &SyntaxReference {
        let lang = language.unwrap_or("");

        self.syntax_set
            .find_syntax_by_token(lang)
            .or_else(|| self.syntax_set.find_syntax_by_extension(lang))
            .or_else(|| self.syntax_set.find_syntax_by_name(lang))
            .unwrap_or_else(|| self.syntax_set.find_syntax_plain_text())
    }

    /// 将 syntect 颜色转换为 ratatui 颜色
    fn syntect_color_to_ratatui(&self, color: &syntect::highlighting::Color) -> Color {
        let (r, g, b, a) = (color.r, color.g, color.b, color.a);
        if a == 0 {
            return Color::Reset;
        }

        // 简单转换：将 RGB 转换为最接近的 ANSI 颜色
        self.rgb_to_ansi(r, g, b)
    }

    /// RGB 转 ANSI 颜色
    fn rgb_to_ansi(&self, r: u8, g: u8, b: u8) -> Color {
        // 使用固定的颜色映射
        match (r, g, b) {
            // 灰色系
            (128..=138, 128..=138, 128..=138) => Color::Gray,
            (200..=255, 200..=255, 200..=255) => Color::White,
            (0..=50, 0..=50, 0..=50) => Color::Black,
            (100..=150, 100..=150, 100..=150) => Color::DarkGray,

            // 红色系
            (200..=255, 0..=100, 0..=100) => Color::Red,
            (255, 100..=150, 100..=150) => Color::LightRed,
            (150..=200, 50..=100, 50..=100) => Color::Red,

            // 绿色系
            (0..=100, 200..=255, 0..=100) => Color::Green,
            (100..=150, 255, 100..=150) => Color::LightGreen,

            // 蓝色系
            (0..=100, 0..=100, 200..=255) => Color::Blue,
            (100..=150, 100..=150, 255) => Color::LightBlue,
            (50..=100, 100..=150, 200..=255) => Color::Blue,

            // 青色系
            (0..=100, 200..=255, 200..=255) => Color::Cyan,
            (0..=50, 150..=200, 200..=255) => Color::Cyan,

            // 黄色系
            (200..=255, 200..=255, 0..=100) => Color::Yellow,
            (255, 255, 150..=200) => Color::LightYellow,

            // 品红/紫色系
            (200..=255, 0..=100, 200..=255) => Color::Magenta,

            // 橙色系
            (255, 150..=200, 0..=100) => Color::LightMagenta,

            _ => Color::White,
        }
    }
}

impl Default for CodeHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

/// 代码块组件（带语法高亮）
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
    /// 语法高亮器
    highlighter: CodeHighlighter,
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
            highlighter: CodeHighlighter::new(),
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
        self.highlighter.render_code(
            f,
            rect,
            self.code,
            self.language.as_deref()
        );
    }
}
