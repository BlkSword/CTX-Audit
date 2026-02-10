// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码查看面板
//!
//! 显示文件内容，支持语法高亮、搜索、跳转

use ratatui::{Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap, List, ListItem, ListState}};
use std::path::PathBuf;

use crate::tui::syntax::{CodeBlock, CodeHighlighter};

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
        }
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

        // 获取语言
        let language = self.current_file
            .as_ref()
            .and_then(|p| self.detect_language(p));

        // 渲染代码
        let code_block = CodeBlock::new(&self.content)
            .language(language.unwrap_or("text"))
            .show_line_numbers(self.show_line_numbers)
            .start_line(self.scroll + 1);

        // 创建临时 frame 来渲染代码块
        let lines: Vec<Line> = self.content.lines().map(Line::from).collect();
        let mut paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(format!(" {} | {} ",
                    self.current_file
                        .as_ref()
                        .and_then(|p| p.file_name())
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "未命名".to_string()),
                    self.get_status_text()
                ))
                .borders(Borders::ALL)
                .border_style(if active {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                })
            )
            .wrap(Wrap { trim: false })
            .scroll((self.scroll as u16, 0));

        f.render_widget(paragraph, rect);
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
}
