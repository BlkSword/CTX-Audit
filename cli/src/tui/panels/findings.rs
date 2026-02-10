// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 漏洞列表面板

use ratatui::{Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, List, ListItem, Wrap}};

/// 漏洞列表面板
pub struct FindingsPanel {
    /// 漏洞列表
    findings: Vec<FindingItem>,
    /// 选中索引
    selected: usize,
    /// 过滤器
    filter: FindingsFilter,
}

/// 漏洞项
#[derive(Debug, Clone)]
pub struct FindingItem {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub file_path: String,
    pub line: Option<u32>,
    pub status: FindingStatus,
}

/// 漏洞状态
#[derive(Debug, Clone, PartialEq)]
pub enum FindingStatus {
    Open,
    Fixed,
    Ignored,
}

/// 漏洞过滤器
#[derive(Debug, Clone, Default)]
pub struct FindingsFilter {
    pub severity: Option<String>,
    pub status: Option<FindingStatus>,
    pub file_pattern: Option<String>,
}

impl FindingsPanel {
    /// 创建新的漏洞列表面板
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            selected: 0,
            filter: FindingsFilter::default(),
        }
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let mut lines = Vec::new();

        // 标题
        lines.push(Line::from(vec![
            Span::styled(" 漏洞列表 ", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(format!("({})", self.findings.len()), Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::from(""));

        if self.findings.is_empty() {
            lines.push(Line::from(Span::styled(
                "暂无漏洞发现",
                Style::default().fg(Color::DarkGray)
            )));
        } else {
            for (i, finding) in self.findings.iter().enumerate() {
                let is_selected = i == self.selected;
                let color = match finding.severity.to_lowercase().as_str() {
                    "critical" => Color::Red,
                    "high" => Color::LightRed,
                    "medium" => Color::Yellow,
                    "low" => Color::Blue,
                    _ => Color::Gray,
                };

                let style = if is_selected {
                    Style::default().bg(Color::DarkGray).add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };

                lines.push(Line::from(vec![
                    Span::styled(
                        format!("[{}] ", match finding.status {
                            FindingStatus::Open => "○",
                            FindingStatus::Fixed => "✓",
                            FindingStatus::Ignored => "⊘",
                        }),
                        Style::default().fg(Color::DarkGray)
                    ),
                    Span::styled(
                        format!("{} ", match finding.severity.to_lowercase().as_str() {
                            "critical" => "⚠⚠",
                            "high" => "⚠",
                            "medium" => "⚠",
                            "low" => "ℹ",
                            _ => "?",
                        }),
                        Style::default().fg(color)
                    ),
                    Span::raw(&finding.title),
                ]));

                if is_selected {
                    lines.push(Line::from(vec![
                        Span::styled("  → ", Style::default().fg(Color::DarkGray)),
                        Span::styled(&finding.file_path, Style::default().fg(Color::Blue)),
                        Span::styled(
                            format!(":{}", finding.line.map(|l| l.to_string()).unwrap_or_default()),
                            Style::default().fg(Color::Blue)
                        ),
                    ]));
                }
            }
        }

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let items: Vec<ListItem> = lines.into_iter().map(ListItem::new).collect();

        let list = List::new(items)
            .block(Block::default()
                .title(" 漏洞 ")
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .highlight_style(Style::default().bg(Color::DarkGray));

        f.render_widget(list, rect);
    }

    /// 设置漏洞列表
    pub fn set_findings(&mut self, findings: Vec<FindingItem>) {
        self.findings = findings;
        self.selected = 0;
    }

    /// 选择下一个
    pub fn select_next(&mut self) {
        if !self.findings.is_empty() {
            self.selected = (self.selected + 1).min(self.findings.len() - 1);
        }
    }

    /// 选择上一个
    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// 获取选中项
    pub fn selected(&self) -> Option<&FindingItem> {
        self.findings.get(self.selected)
    }

    /// 应用过滤器
    pub fn apply_filter(&mut self, filter: FindingsFilter) {
        self.filter = filter;
        // TODO: 实现过滤逻辑
    }
}

impl Default for FindingsPanel {
    fn default() -> Self {
        Self::new()
    }
}
