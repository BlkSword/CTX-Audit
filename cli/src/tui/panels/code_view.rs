// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码查看面板
//!
//! 显示文件内容，支持语法高亮、搜索、跳转、漏洞高亮

use ratatui::{Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap, List, ListItem, ListState}};
use std::path::PathBuf;
use std::collections::HashMap;

use crate::tui::syntax::{CodeBlock, CodeHighlighter};

/// 漏洞严重程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VulnerabilitySeverity {
    /// 严重
    Critical,
    /// 高危
    High,
    /// 中危
    Medium,
    /// 低危
    Low,
    /// 信息
    Info,
}

impl VulnerabilitySeverity {
    /// 获取严重程度对应的颜色
    pub fn color(&self) -> Color {
        match self {
            VulnerabilitySeverity::Critical => Color::Red,
            VulnerabilitySeverity::High => Color::LightRed,
            VulnerabilitySeverity::Medium => Color::Yellow,
            VulnerabilitySeverity::Low => Color::Blue,
            VulnerabilitySeverity::Info => Color::DarkGray,
        }
    }

    /// 获取严重程度背景色
    pub fn bg_color(&self) -> Color {
        match self {
            VulnerabilitySeverity::Critical => Color::Indexed(52),  // 深红
            VulnerabilitySeverity::High => Color::Indexed(88),      // 红
            VulnerabilitySeverity::Medium => Color::Indexed(58),    // 橙
            VulnerabilitySeverity::Low => Color::Indexed(24),       // 蓝
            VulnerabilitySeverity::Info => Color::Indexed(238),     // 灰
        }
    }

    /// 获取图标
    pub fn icon(&self) -> &str {
        match self {
            VulnerabilitySeverity::Critical => "[!!!]",
            VulnerabilitySeverity::High => "[!!]",
            VulnerabilitySeverity::Medium => "[!]",
            VulnerabilitySeverity::Low => "[*]",
            VulnerabilitySeverity::Info => "[i]",
        }
    }
}

/// 漏洞位置标记
#[derive(Debug, Clone)]
pub struct VulnerabilityMarker {
    /// 起始行 (0-indexed)
    pub start_line: usize,

    /// 结束行 (0-indexed)
    pub end_line: usize,

    /// 起始列
    pub start_col: usize,

    /// 结束列
    pub end_col: usize,

    /// 严重程度
    pub severity: VulnerabilitySeverity,

    /// 漏洞类型
    pub vuln_type: String,

    /// 漏洞描述
    pub description: String,

    /// 唯一标识
    pub id: String,
}

impl VulnerabilityMarker {
    /// 创建新的漏洞标记
    pub fn new(start_line: usize, severity: VulnerabilitySeverity, vuln_type: &str) -> Self {
        Self {
            start_line,
            end_line: start_line,
            start_col: 0,
            end_col: usize::MAX,
            severity,
            vuln_type: vuln_type.to_string(),
            description: String::new(),
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        }
    }

    /// 设置结束行
    pub fn with_end_line(mut self, end_line: usize) -> Self {
        self.end_line = end_line;
        self
    }

    /// 设置列范围
    pub fn with_cols(mut self, start_col: usize, end_col: usize) -> Self {
        self.start_col = start_col;
        self.end_col = end_col;
        self
    }

    /// 设置描述
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    /// 检查行是否在漏洞范围内
    pub fn contains_line(&self, line: usize) -> bool {
        line >= self.start_line && line <= self.end_line
    }
}

/// 代码查看面板
pub struct CodeViewPanel {
    /// 当前文件
    current_file: Option<PathBuf>,

    /// 文件内容
    content: String,

    /// 高亮器
    highlighter: CodeHighlighter,

    /// 滚动位置
    scroll: usize,

    /// 搜索字符串
    search_query: Option<String>,

    /// 搜索结果
    search_results: Vec<usize>,

    /// 当前搜索索引
    current_search_index: usize,

    /// 光标位置
    cursor_line: usize,
    cursor_col: usize,

    /// 是否显示行号
    show_line_numbers: bool,

    /// 书签
    bookmarks: Vec<(PathBuf, usize, String)>,

    /// 历史记录
    history: Vec<PathBuf>,
    history_index: usize,

    /// 漏洞标记 (按行索引)
    vulnerability_markers: Vec<VulnerabilityMarker>,

    /// 当前行高亮的漏洞
    highlighted_vulnerability: Option<String>,

    /// 显示漏洞指示器
    show_vulnerability_indicators: bool,

    /// 上下文行数 (显示漏洞时前后显示多少行)
    context_lines: usize,
}

impl CodeViewPanel {
    /// 创建新的代码查看面板
    pub fn new() -> Self {
        Self {
            current_file: None,
            content: String::new(),
            highlighter: CodeHighlighter::new(),
            scroll: 0,
            search_query: None,
            search_results: Vec::new(),
            current_search_index: 0,
            cursor_line: 0,
            cursor_col: 0,
            show_line_numbers: true,
            bookmarks: Vec::new(),
            history: Vec::new(),
            history_index: 0,
            vulnerability_markers: Vec::new(),
            highlighted_vulnerability: None,
            show_vulnerability_indicators: true,
            context_lines: 3,
        }
    }

    /// 添加漏洞标记
    pub fn add_vulnerability(&mut self, marker: VulnerabilityMarker) {
        self.vulnerability_markers.push(marker);
    }

    /// 批量添加漏洞标记
    pub fn add_vulnerabilities(&mut self, markers: Vec<VulnerabilityMarker>) {
        self.vulnerability_markers.extend(markers);
    }

    /// 清除所有漏洞标记
    pub fn clear_vulnerabilities(&mut self) {
        self.vulnerability_markers.clear();
        self.highlighted_vulnerability = None;
    }

    /// 获取指定行的漏洞标记
    pub fn get_vulnerabilities_at_line(&self, line: usize) -> Vec<&VulnerabilityMarker> {
        self.vulnerability_markers
            .iter()
            .filter(|m| m.contains_line(line))
            .collect()
    }

    /// 跳转到漏洞位置
    pub fn goto_vulnerability(&mut self, id: &str) -> bool {
        if let Some(marker) = self.vulnerability_markers.iter().find(|m| m.id == id) {
            self.goto_line(marker.start_line);
            self.highlighted_vulnerability = Some(id.to_string());
            return true;
        }
        false
    }

    /// 跳转到下一个漏洞
    pub fn next_vulnerability(&mut self) -> bool {
        let current_line = self.cursor_line;

        // 先找到目标漏洞信息
        let target = self.vulnerability_markers
            .iter()
            .filter(|m| m.start_line > current_line)
            .min_by_key(|m| m.start_line)
            .map(|m| (m.start_line, m.id.clone()))
            .or_else(|| {
                self.vulnerability_markers
                    .iter()
                    .min_by_key(|m| m.start_line)
                    .map(|m| (m.start_line, m.id.clone()))
            });

        if let Some((line, id)) = target {
            self.goto_line(line);
            self.highlighted_vulnerability = Some(id);
            return true;
        }

        false
    }

    /// 跳转到上一个漏洞
    pub fn prev_vulnerability(&mut self) -> bool {
        let current_line = self.cursor_line;

        // 先找到目标漏洞信息
        let target = self.vulnerability_markers
            .iter()
            .filter(|m| m.start_line < current_line)
            .max_by_key(|m| m.start_line)
            .map(|m| (m.start_line, m.id.clone()))
            .or_else(|| {
                self.vulnerability_markers
                    .iter()
                    .max_by_key(|m| m.start_line)
                    .map(|m| (m.start_line, m.id.clone()))
            });

        if let Some((line, id)) = target {
            self.goto_line(line);
            self.highlighted_vulnerability = Some(id);
            return true;
        }

        false
    }

    /// 获取漏洞统计
    pub fn get_vulnerability_stats(&self) -> HashMap<VulnerabilitySeverity, usize> {
        let mut stats = HashMap::new();
        for marker in &self.vulnerability_markers {
            *stats.entry(marker.severity).or_insert(0) += 1;
        }
        stats
    }

    /// 设置上下文行数
    pub fn set_context_lines(&mut self, lines: usize) {
        self.context_lines = lines;
    }

    /// 切换漏洞指示器显示
    pub fn toggle_vulnerability_indicators(&mut self) {
        self.show_vulnerability_indicators = !self.show_vulnerability_indicators;
    }

    /// 加载文件
    pub fn load_file(&mut self, path: PathBuf) -> Result<(), String> {
        use std::fs;

        // 读取文件
        let content = fs::read_to_string(&path)
            .map_err(|e| format!("无法读取文件: {}", e))?;

        // 检测语言
        let language = self.detect_language(&path);

        // 更新内容
        self.current_file = Some(path.clone());
        self.content = content;
        self.scroll = 0;
        self.cursor_line = 0;
        self.cursor_col = 0;

        // 添加到历史
        if let Some(last) = self.history.last() {
            if last != &path {
                self.history.push(path);
                self.history_index = self.history.len() - 1;
            }
        } else {
            self.history.push(path);
        }

        Ok(())
    }

    /// 检测语言
    fn detect_language(&self, path: &PathBuf) -> Option<&'static str> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| match ext {
                "rs" => "rust",
                "py" => "python",
                "js" => "javascript",
                "jsx" => "jsx",
                "ts" => "typescript",
                "tsx" => "tsx",
                "go" => "go",
                "java" => "java",
                "c" => "c",
                "h" => "c",
                "cpp" | "cc" | "cxx" => "cpp",
                "hpp" | "hh" | "hxx" => "cpp",
                "html" | "htm" => "html",
                "css" => "css",
                "json" => "json",
                "yaml" | "yml" => "yaml",
                "toml" => "toml",
                "md" => "markdown",
                _ => "text",
            })
    }

    /// 搜索
    pub fn search(&mut self, query: String) {
        self.search_query = Some(query.clone());
        self.search_results.clear();
        self.current_search_index = 0;

        if query.is_empty() {
            return;
        }

        // 在内容中搜索
        for (i, line) in self.content.lines().enumerate() {
            if line.contains(&query) {
                self.search_results.push(i);
            }
        }

        // 跳转到第一个结果
        if !self.search_results.is_empty() {
            self.goto_line(self.search_results[0]);
        }
    }

    /// 下一个搜索结果
    pub fn next_search_result(&mut self) {
        if self.search_results.is_empty() {
            return;
        }

        self.current_search_index = (self.current_search_index + 1) % self.search_results.len();
        self.goto_line(self.search_results[self.current_search_index]);
    }

    /// 上一个搜索结果
    pub fn prev_search_result(&mut self) {
        if self.search_results.is_empty() {
            return;
        }

        self.current_search_index = if self.current_search_index == 0 {
            self.search_results.len() - 1
        } else {
            self.current_search_index - 1
        };
        self.goto_line(self.search_results[self.current_search_index]);
    }

    /// 跳转到行
    pub fn goto_line(&mut self, line: usize) {
        self.cursor_line = line.min(self.content.lines().count().saturating_sub(1));
        self.scroll = self.cursor_line.saturating_sub(5);
    }

    /// 添加书签
    pub fn add_bookmark(&mut self, name: String) {
        if let Some(ref file) = self.current_file {
            self.bookmarks.push((file.clone(), self.cursor_line, name));
        }
    }

    /// 跳转到书签
    pub fn goto_bookmark(&mut self, index: usize) -> Result<(), String> {
        let (file, line) = self.bookmarks
            .get(index)
            .map(|(f, l, _)| (f.clone(), *l))
            .ok_or_else(|| format!("书签不存在: {}", index))?;

        if self.current_file.as_ref() != Some(&file) {
            self.load_file(file)?;
        }

        self.goto_line(line);
        Ok(())
    }

    /// 历史后退
    pub fn history_back(&mut self) -> Result<(), String> {
        if self.history_index > 0 {
            self.history_index -= 1;
            let path = self.history[self.history_index].clone();
            self.load_file(path)?;
        }
        Ok(())
    }

    /// 历史前进
    pub fn history_forward(&mut self) -> Result<(), String> {
        if self.history_index + 1 < self.history.len() {
            self.history_index += 1;
            let path = self.history[self.history_index].clone();
            self.load_file(path)?;
        }
        Ok(())
    }

    /// 滚动
    pub fn scroll(&mut self, delta: isize) {
        let line_count = self.content.lines().count();
        let new_scroll = if delta >= 0 {
            self.scroll + delta as usize
        } else {
            self.scroll.saturating_sub((-delta) as usize)
        };
        self.scroll = new_scroll.min(line_count.saturating_sub(1));
    }

    /// 移动光标
    pub fn move_cursor(&mut self, line_delta: isize, col_delta: isize) {
        let line_count = self.content.lines().count();

        // 更新行
        let new_line = if line_delta >= 0 {
            self.cursor_line + line_delta as usize
        } else {
            self.cursor_line.saturating_sub((-line_delta) as usize)
        };
        self.cursor_line = new_line.min(line_count.saturating_sub(1));

        // 获取当前行长度
        if let Some(line) = self.content.lines().nth(self.cursor_line) {
            let col_count = line.chars().count();

            // 更新列
            let new_col = if col_delta >= 0 {
                self.cursor_col + col_delta as usize
            } else {
                self.cursor_col.saturating_sub((-col_delta) as usize)
            };
            self.cursor_col = new_col.min(col_count);
        }
    }

    /// 获取当前状态文本
    pub fn get_status_text(&self) -> String {
        let mut status = String::new();

        // 文件名
        if let Some(ref file) = self.current_file {
            if let Some(name) = file.file_name() {
                status.push_str(&name.to_string_lossy());
            }
        }

        // 行号
        let line_count = self.content.lines().count();
        status.push_str(&format!("  行 {}/{}", self.cursor_line + 1, line_count));

        // 列号
        status.push_str(&format!(":{}", self.cursor_col + 1));

        // 搜索结果
        if let Some(ref query) = self.search_query {
            if !self.search_results.is_empty() {
                status.push_str(&format!(
                    "  搜索: {}/{} ({})",
                    self.current_search_index + 1,
                    self.search_results.len(),
                    query
                ));
            }
        }

        status
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        if self.content.is_empty() {
            // 空状态
            let text = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("未打开文件", Style::default().fg(Color::DarkGray)),
                ]),
                Line::from(vec![
                    Span::styled("按 Enter 打开选中的文件", Style::default().fg(Color::DarkGray)),
                ]),
            ];

            let paragraph = Paragraph::new(text)
                .block(Block::default()
                    .title(" 代码查看 ")
                    .borders(Borders::ALL)
                    .border_style(if active {
                        Style::default().fg(Color::Cyan)
                    } else {
                        Style::default()
                    })
                )
                .wrap(Wrap { trim: true })
                .alignment(ratatui::layout::Alignment::Center);

            f.render_widget(paragraph, rect);
            return;
        }

        // 计算可见区域
        let visible_height = rect.height.saturating_sub(2) as usize; // 减去边框
        let visible_lines: Vec<Line> = self.render_code_lines(self.scroll, visible_height);

        // 构建标题
        let title = self.build_title();

        let paragraph = Paragraph::new(visible_lines)
            .block(Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(if active {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                })
            )
            .wrap(Wrap { trim: false });

        f.render_widget(paragraph, rect);
    }

    /// 渲染代码行 (带语法高亮和漏洞标记)
    fn render_code_lines(&self, start_line: usize, count: usize) -> Vec<Line<'static>> {
        let lines: Vec<&str> = self.content.lines().collect();
        let total_lines = lines.len();
        let line_num_width = (total_lines.to_string().len() + 1).max(4);

        let mut result = Vec::new();

        for i in 0..count {
            let line_idx = start_line + i;
            if line_idx >= total_lines {
                break;
            }

            let line_content = lines[line_idx];
            let line_number = line_idx + 1; // 1-indexed for display

            // 获取当前行的漏洞标记
            let vulns = self.get_vulnerabilities_at_line(line_idx);
            let is_highlighted = self.highlighted_vulnerability.as_ref()
                .map(|id| vulns.iter().any(|v| &v.id == id))
                .unwrap_or(false);

            // 构建行
            let mut spans = Vec::new();

            // 行号
            if self.show_line_numbers {
                let (num_style, num_bg) = if !vulns.is_empty() && self.show_vulnerability_indicators {
                    let severity = vulns.iter()
                        .max_by_key(|v| v.severity)
                        .map(|v| v.severity)
                        .unwrap_or(VulnerabilitySeverity::Info);
                    (Style::default().fg(Color::Black).bg(severity.color()), true)
                } else if line_idx == self.cursor_line {
                    (Style::default().fg(Color::Black).bg(Color::DarkGray), true)
                } else {
                    (Style::default().fg(Color::DarkGray), false)
                };

                let num_str = format!("{:>width$} ", line_number, width = line_num_width);
                spans.push(Span::styled(num_str, num_style));
            }

            // 漏洞指示器
            if self.show_vulnerability_indicators && !vulns.is_empty() {
                let severity = vulns.iter()
                    .max_by_key(|v| v.severity)
                    .map(|v| v.severity)
                    .unwrap_or(VulnerabilitySeverity::Info);
                spans.push(Span::styled(
                    format!("{} ", severity.icon()),
                    Style::default().fg(severity.color()),
                ));
            }

            // 代码内容
            let code_style = if is_highlighted {
                Style::default()
                    .fg(Color::White)
                    .bg(vulns.first().map(|v| v.severity.bg_color()).unwrap_or(Color::DarkGray))
                    .add_modifier(Modifier::BOLD)
            } else if !vulns.is_empty() && self.show_vulnerability_indicators {
                Style::default()
                    .fg(Color::White)
                    .bg(vulns.first().map(|v| v.severity.bg_color()).unwrap_or(Color::DarkGray))
            } else {
                Style::default().fg(Color::White)
            };

            // 应用语法高亮 (简化版本)
            let highlighted_spans = self.highlight_line(line_content, line_idx);
            if highlighted_spans.is_empty() {
                spans.push(Span::styled(line_content.to_string(), code_style));
            } else {
                spans.extend(highlighted_spans.into_iter().map(|s| {
                    // 如果有漏洞，添加背景色
                    if is_highlighted || (!vulns.is_empty() && self.show_vulnerability_indicators) {
                        let bg = vulns.first().map(|v| v.severity.bg_color()).unwrap_or(Color::DarkGray);
                        Span::styled(s.content, s.style.bg(bg))
                    } else {
                        s
                    }
                }));
            }

            result.push(Line::from(spans));
        }

        result
    }

    /// 高亮单行代码 (简单语法高亮)
    fn highlight_line(&self, line: &str, _line_idx: usize) -> Vec<Span<'static>> {
        // 简单的关键字高亮
        let keywords = ["fn", "let", "mut", "const", "if", "else", "for", "while", "loop",
                        "match", "return", "struct", "enum", "impl", "trait", "pub", "mod",
                        "use", "self", "Self", "true", "false", "None", "Some", "Ok", "Err",
                        "async", "await", "move", "ref", "static", "type", "where"];

        let types = ["String", "Vec", "Option", "Result", "Box", "Rc", "Arc",
                     "i32", "i64", "u32", "u64", "usize", "isize", "f32", "f64",
                     "bool", "char", "str"];

        // 简单实现：检查是否以关键字开头
        let trimmed = line.trim_start();

        for kw in &keywords {
            if trimmed.starts_with(kw) && trimmed.len() > kw.len() {
                let after = &trimmed[kw.len()..];
                if after.starts_with(' ') || after.starts_with('(') || after.starts_with(':') {
                    // 找到关键字，高亮它
                    let leading_ws = line.len() - trimmed.len();
                    let mut spans = Vec::new();

                    if leading_ws > 0 {
                        spans.push(Span::raw(line[..leading_ws].to_string()));
                    }

                    spans.push(Span::styled(
                        kw.to_string(),
                        Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                    ));

                    spans.push(Span::styled(
                        line[leading_ws + kw.len()..].to_string(),
                        Style::default().fg(Color::White),
                    ));

                    return spans;
                }
            }
        }

        // 检查类型
        for t in &types {
            if line.contains(t) {
                // 简单的类型高亮
                let parts: Vec<&str> = line.split(t).collect();
                if parts.len() > 1 {
                    let mut spans = Vec::new();
                    let mut remaining = line;

                    for (i, part) in parts.iter().enumerate() {
                        if !part.is_empty() {
                            spans.push(Span::styled(part.to_string(), Style::default().fg(Color::White)));
                        }
                        if i < parts.len() - 1 {
                            spans.push(Span::styled(
                                t.to_string(),
                                Style::default().fg(Color::Cyan),
                            ));
                            remaining = &remaining[part.len() + t.len()..];
                        }
                    }

                    return spans;
                }
            }
        }

        // 字符串高亮
        if line.contains('"') {
            let mut in_string = false;
            let mut spans = Vec::new();
            let mut current = String::new();

            for ch in line.chars() {
                if ch == '"' {
                    if !in_string {
                        if !current.is_empty() {
                            spans.push(Span::styled(current.clone(), Style::default().fg(Color::White)));
                            current.clear();
                        }
                        current.push(ch);
                        in_string = true;
                    } else {
                        current.push(ch);
                        spans.push(Span::styled(current.clone(), Style::default().fg(Color::Green)));
                        current.clear();
                        in_string = false;
                    }
                } else {
                    current.push(ch);
                }
            }

            if !current.is_empty() {
                let style = if in_string {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::White)
                };
                spans.push(Span::styled(current, style));
            }

            if !spans.is_empty() {
                return spans;
            }
        }

        // 注释高亮
        if line.trim_start().starts_with("//") || line.trim_start().starts_with("#") {
            return vec![Span::styled(line.to_string(), Style::default().fg(Color::DarkGray))];
        }

        // 默认：无高亮
        vec![]
    }

    /// 构建标题栏
    fn build_title(&self) -> String {
        let filename = self.current_file
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "未命名".to_string());

        let mut title = format!(" {} ", filename);

        // 添加漏洞统计
        if !self.vulnerability_markers.is_empty() {
            let stats = self.get_vulnerability_stats();
            let critical = stats.get(&VulnerabilitySeverity::Critical).unwrap_or(&0);
            let high = stats.get(&VulnerabilitySeverity::High).unwrap_or(&0);
            let medium = stats.get(&VulnerabilitySeverity::Medium).unwrap_or(&0);

            title.push_str(&format!(
                " | [!!!]{} [!!]{} [!]{} ",
                critical, high, medium
            ));
        }

        // 添加位置信息
        let line_count = self.content.lines().count();
        title.push_str(&format!(
            " | 行 {}/{}:{} ",
            self.cursor_line + 1, line_count, self.cursor_col + 1
        ));

        title
    }

    /// 处理输入
    pub fn handle_input(&mut self, input: CodeViewInput) -> Result<(), String> {
        match input {
            CodeViewInput::Scroll(delta) => {
                self.scroll(delta);
            }
            CodeViewInput::GotoLine(line) => {
                self.goto_line(line);
            }
            CodeViewInput::Search(query) => {
                self.search(query);
            }
            CodeViewInput::NextSearch => {
                self.next_search_result();
            }
            CodeViewInput::PrevSearch => {
                self.prev_search_result();
            }
            CodeViewInput::MoveCursor(line_delta, col_delta) => {
                self.move_cursor(line_delta, col_delta);
            }
            CodeViewInput::AddBookmark(name) => {
                self.add_bookmark(name);
            }
            CodeViewInput::GotoBookmark(index) => {
                self.goto_bookmark(index)?;
            }
            CodeViewInput::HistoryBack => {
                self.history_back()?;
            }
            CodeViewInput::HistoryForward => {
                self.history_forward()?;
            }
            CodeViewInput::ToggleLineNumbers => {
                self.show_line_numbers = !self.show_line_numbers;
            }
            CodeViewInput::NextVulnerability => {
                self.next_vulnerability();
            }
            CodeViewInput::PrevVulnerability => {
                self.prev_vulnerability();
            }
            CodeViewInput::GotoVulnerability(id) => {
                if !self.goto_vulnerability(&id) {
                    return Err(format!("漏洞不存在: {}", id));
                }
            }
            CodeViewInput::ClearVulnerabilities => {
                self.clear_vulnerabilities();
            }
            CodeViewInput::ToggleVulnerabilityIndicators => {
                self.toggle_vulnerability_indicators();
            }
            CodeViewInput::SetContextLines(lines) => {
                self.set_context_lines(lines);
            }
        }
        Ok(())
    }

    /// 获取当前行内容
    pub fn get_current_line(&self) -> Option<&str> {
        self.content.lines().nth(self.cursor_line)
    }

    /// 获取选中内容
    pub fn get_selection(&self) -> String {
        self.get_current_line().unwrap_or("").to_string()
    }

    /// 获取漏洞标记数量
    pub fn vulnerability_count(&self) -> usize {
        self.vulnerability_markers.len()
    }

    /// 获取所有漏洞标记
    pub fn get_vulnerabilities(&self) -> &[VulnerabilityMarker] {
        &self.vulnerability_markers
    }
}

impl Default for CodeViewPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// 代码查看输入事件
#[derive(Debug, Clone)]
pub enum CodeViewInput {
    /// 滚动
    Scroll(isize),

    /// 跳转到行
    GotoLine(usize),

    /// 搜索
    Search(String),

    /// 下一个搜索结果
    NextSearch,

    /// 上一个搜索结果
    PrevSearch,

    /// 移动光标
    MoveCursor(isize, isize),

    /// 添加书签
    AddBookmark(String),

    /// 跳转到书签
    GotoBookmark(usize),

    /// 历史后退
    HistoryBack,

    /// 历史前进
    HistoryForward,

    /// 切换行号显示
    ToggleLineNumbers,

    /// 下一个漏洞
    NextVulnerability,

    /// 上一个漏洞
    PrevVulnerability,

    /// 跳转到漏洞
    GotoVulnerability(String),

    /// 清除漏洞标记
    ClearVulnerabilities,

    /// 切换漏洞指示器
    ToggleVulnerabilityIndicators,

    /// 设置上下文行数
    SetContextLines(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_severity_colors() {
        assert_eq!(VulnerabilitySeverity::Critical.color(), Color::Red);
        assert_eq!(VulnerabilitySeverity::High.color(), Color::LightRed);
        assert_eq!(VulnerabilitySeverity::Medium.color(), Color::Yellow);
    }

    #[test]
    fn test_vulnerability_marker() {
        let marker = VulnerabilityMarker::new(10, VulnerabilitySeverity::High, "SQL Injection")
            .with_end_line(12)
            .with_description("Unsafe SQL query");

        assert!(marker.contains_line(10));
        assert!(marker.contains_line(11));
        assert!(marker.contains_line(12));
        assert!(!marker.contains_line(9));
        assert!(!marker.contains_line(13));
    }

    #[test]
    fn test_code_view_vulnerability_navigation() {
        let mut panel = CodeViewPanel::new();
        panel.content = "line1\nline2\nline3\nline4\nline5".to_string();

        panel.add_vulnerability(VulnerabilityMarker::new(1, VulnerabilitySeverity::High, "Vuln1"));
        panel.add_vulnerability(VulnerabilityMarker::new(3, VulnerabilitySeverity::Critical, "Vuln2"));

        assert_eq!(panel.vulnerability_count(), 2);

        // 导航到下一个漏洞
        panel.next_vulnerability();
        assert_eq!(panel.cursor_line, 1);

        // 导航到下一个漏洞
        panel.next_vulnerability();
        assert_eq!(panel.cursor_line, 3);
    }

    #[test]
    fn test_vulnerability_stats() {
        let mut panel = CodeViewPanel::new();

        panel.add_vulnerability(VulnerabilityMarker::new(1, VulnerabilitySeverity::Critical, "V1"));
        panel.add_vulnerability(VulnerabilityMarker::new(2, VulnerabilitySeverity::Critical, "V2"));
        panel.add_vulnerability(VulnerabilityMarker::new(3, VulnerabilitySeverity::High, "V3"));

        let stats = panel.get_vulnerability_stats();
        assert_eq!(*stats.get(&VulnerabilitySeverity::Critical).unwrap(), 2);
        assert_eq!(*stats.get(&VulnerabilitySeverity::High).unwrap(), 1);
    }

    #[test]
    fn test_code_view_input_handling() {
        let mut panel = CodeViewPanel::new();
        panel.content = "line1\nline2\nline3".to_string();

        panel.handle_input(CodeViewInput::GotoLine(2)).unwrap();
        assert_eq!(panel.cursor_line, 2);

        panel.handle_input(CodeViewInput::MoveCursor(-1, 0)).unwrap();
        assert_eq!(panel.cursor_line, 1);

        panel.handle_input(CodeViewInput::ToggleLineNumbers).unwrap();
        assert!(!panel.show_line_numbers);
    }
}
