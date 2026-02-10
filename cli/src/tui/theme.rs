// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! TUI 主题系统

use ratatui::style::{Color, Modifier, Style};

/// 主题配置
#[derive(Debug, Clone)]
pub struct Theme {
    /// 主色调
    pub primary: Color,
    /// 次要色调
    pub secondary: Color,
    /// 成功色
    pub success: Color,
    /// 警告色
    pub warning: Color,
    /// 错误色
    pub error: Color,
    /// 信息色
    pub info: Color,
    /// 背景色
    pub background: Color,
    /// 前景色
    pub foreground: Color,
    /// 边框样式
    pub border_style: Style,
    /// 活动面板样式
    pub active_style: Style,
    /// 高亮样式
    pub highlight_style: Style,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

impl Theme {
    /// 深色主题（默认）
    pub fn dark() -> Self {
        Self {
            primary: Color::Cyan,
            secondary: Color::Blue,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            info: Color::Blue,
            background: Color::Black,
            foreground: Color::White,
            border_style: Style::default().fg(Color::DarkGray),
            active_style: Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            highlight_style: Style::default().bg(Color::DarkGray).add_modifier(Modifier::REVERSED),
        }
    }

    /// 浅色主题
    pub fn light() -> Self {
        Self {
            primary: Color::Blue,
            secondary: Color::Cyan,
            success: Color::Green,
            warning: Color::Yellow,
            error: Color::Red,
            info: Color::Blue,
            background: Color::White,
            foreground: Color::Black,
            border_style: Style::default().fg(Color::Gray),
            active_style: Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            highlight_style: Style::default().bg(Color::LightBlue).add_modifier(Modifier::REVERSED),
        }
    }

    /// 获取严重程度对应的颜色
    pub fn severity_color(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "critical" => Color::Red,
            "high" => Color::LightRed,
            "medium" => Color::Yellow,
            "low" => Color::Blue,
            _ => Color::Gray,
        }
    }
}
