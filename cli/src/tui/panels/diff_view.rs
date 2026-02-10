// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码差异视图面板
//!
//! 显示两个文件/版本之间的差异

use ratatui::{Frame, layout::Rect, style::{Color, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap}};

/// 差视图面板
pub struct DiffViewPanel {
    /// 原始内容
    old_content: String,

    /// 新内容
    new_content: String,

    /// 滚动位置
    scroll: usize,

    /// 是否显示行号
    show_line_numbers: bool,
}

impl DiffViewPanel {
    /// 创建新的差异视图面板
    pub fn new() -> Self {
        Self {
            old_content: String::new(),
            new_content: String::new(),
            scroll: 0,
            show_line_numbers: true,
        }
    }

    /// 设置内容
    pub fn set_content(&mut self, old_content: String, new_content: String) {
        self.old_content = old_content;
        self.new_content = new_content;
        self.scroll = 0;
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let mut lines = Vec::new();

        // 简单的行差异比较
        let old_lines: Vec<&str> = self.old_content.lines().collect();
        let new_lines: Vec<&str> = self.new_content.lines().collect();

        // 使用简单的 LCS (最长公共子序列) 算法来计算差异
        let diff = compute_line_diff(&old_lines, &new_lines);

        for (i, change) in diff.iter().enumerate() {
            match change {
                DiffChange::Equal(old_line, new_line) => {
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("{:4} ", i + 1),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("{:4} ", i + 1),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::raw("  "),
                        Span::raw(*old_line),
                    ]));
                }
                DiffChange::Delete(line) => {
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!("{:4} ", i + 1),
                            Style::default().fg(Color::Red),
                        ),
                        Span::raw("     "),
                        Span::styled("-", Style::default().fg(Color::Red).bg(Color::Rgb(50, 0, 0))),
                        Span::styled(
                            *line,
                            Style::default().fg(Color::LightRed).bg(Color::Rgb(50, 0, 0)),
                        ),
                    ]));
                }
                DiffChange::Insert(line) => {
                    lines.push(Line::from(vec![
                        Span::raw("     "),
                        Span::styled(
                            format!("{:4} ", i + 1),
                            Style::default().fg(Color::Green),
                        ),
                        Span::styled("+", Style::default().fg(Color::Green)),
                        Span::styled(
                            *line,
                            Style::default().fg(Color::LightGreen).bg(Color::Rgb(0, 50, 0)),
                        ),
                    ]));
                }
            }
        }

        if lines.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("无差异", Style::default().fg(Color::DarkGray)),
            ]));
        }

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(" 差异查看 ")
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: false })
            .scroll((self.scroll as u16, 0));

        f.render_widget(paragraph, rect);
    }

    /// 滚动
    pub fn scroll(&mut self, delta: isize) {
        let line_count = self.old_content.lines().count() + self.new_content.lines().count();
        let new_scroll = if delta >= 0 {
            self.scroll + delta as usize
        } else {
            self.scroll.saturating_sub((-delta) as usize)
        };
        self.scroll = new_scroll.min(line_count.saturating_sub(1));
    }

    /// 切换行号显示
    pub fn toggle_line_numbers(&mut self) {
        self.show_line_numbers = !self.show_line_numbers;
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> DiffStats {
        let mut additions = 0;
        let mut deletions = 0;
        let mut modifications = 0;

        let old_lines: Vec<&str> = self.old_content.lines().collect();
        let new_lines: Vec<&str> = self.new_content.lines().collect();
        let diff = compute_line_diff(&old_lines, &new_lines);

        for change in diff {
            match change {
                DiffChange::Delete(_) => deletions += 1,
                DiffChange::Insert(_) => additions += 1,
                DiffChange::Equal(_, _) => {}
            }
        }

        DiffStats {
            additions,
            deletions,
            modifications,
        }
    }
}

impl Default for DiffViewPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// 差异统计
#[derive(Debug, Clone)]
pub struct DiffStats {
    /// 新增行数
    pub additions: usize,

    /// 删除行数
    pub deletions: usize,

    /// 修改行数
    pub modifications: usize,
}

/// 差异变更类型
#[derive(Debug)]
enum DiffChange<'a> {
    /// 相同
    Equal(&'a str, &'a str),
    /// 删除
    Delete(&'a str),
    /// 插入
    Insert(&'a str),
}

/// 计算行差异（简单版本）
fn compute_line_diff<'a>(old_lines: &'a [&'a str], new_lines: &'a [&'a str]) -> Vec<DiffChange<'a>> {
    let mut result = Vec::new();
    let mut i = 0;
    let mut j = 0;

    while i < old_lines.len() || j < new_lines.len() {
        if i < old_lines.len() && j < new_lines.len() {
            let old_line = old_lines[i];
            let new_line = new_lines[j];

            if old_line == new_line {
                result.push(DiffChange::Equal(old_line, new_line));
                i += 1;
                j += 1;
            } else {
                // 检查是否是新行插入
                let found_in_old = old_lines.iter().skip(i).any(|l| *l == new_line);
                let found_in_new = new_lines.iter().skip(j).any(|l| *l == old_line);

                if found_in_new && !found_in_old {
                    result.push(DiffChange::Delete(old_line));
                    i += 1;
                } else if found_in_old && !found_in_new {
                    result.push(DiffChange::Insert(new_line));
                    j += 1;
                } else {
                    // 都不相同，标记为删除+插入
                    result.push(DiffChange::Delete(old_line));
                    result.push(DiffChange::Insert(new_line));
                    i += 1;
                    j += 1;
                }
            }
        } else if i < old_lines.len() {
            result.push(DiffChange::Delete(old_lines[i]));
            i += 1;
        } else {
            result.push(DiffChange::Insert(new_lines[j]));
            j += 1;
        }
    }

    result
}
