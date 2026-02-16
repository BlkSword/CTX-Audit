// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 进度条组件

use ratatui::{Frame, layout::Rect, style::{Color, Style}, widgets::{Block, Borders, Gauge, Wrap}};

/// 进度条组件
pub struct ProgressBar {
    /// 进度百分比 (0-100)
    progress: u16,
    /// 标签
    label: String,
    /// 宽度
    width: u16,
}

impl ProgressBar {
    /// 创建新的进度条
    pub fn new(progress: u16) -> Self {
        Self {
            progress: progress.min(100),
            label: String::new(),
            width: 50,
        }
    }

    /// 设置标签
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// 设置宽度
    pub fn width(mut self, width: u16) -> Self {
        self.width = width;
        self
    }

    /// 渲染进度条
    pub fn render(&self, f: &mut Frame, rect: Rect) {
        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::ALL))
            .gauge_style(
                Style::default()
                    .fg(Color::Cyan)
                    .bg(Color::DarkGray)
            )
            .percent(self.progress)
            .label(&self.label);

        f.render_widget(gauge, rect);
    }

    /// 更新进度
    pub fn update(&mut self, progress: u16) {
        self.progress = progress.min(100);
    }
}

impl Default for ProgressBar {
    fn default() -> Self {
        Self::new(0)
    }
}
