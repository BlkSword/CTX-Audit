// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 工具执行进度面板
//!
//! 显示当前执行的工具和执行历史

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::tui::app::AppEvent;

/// 工具执行状态
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolExecutionStatus {
    /// 等待中
    Pending,
    /// 执行中
    Running,
    /// 已成功
    Success,
    /// 已失败
    Failed,
    /// 已超时
    Timeout,
}

impl ToolExecutionStatus {
    /// 获取状态图标
    pub fn icon(&self) -> &str {
        match self {
            ToolExecutionStatus::Pending => "[...]",
            ToolExecutionStatus::Running => "[*]",
            ToolExecutionStatus::Success => "[OK]",
            ToolExecutionStatus::Failed => "[ERR]",
            ToolExecutionStatus::Timeout => "[TIME]",
        }
    }

    /// 获取状态颜色
    pub fn color(&self) -> Color {
        match self {
            ToolExecutionStatus::Pending => Color::DarkGray,
            ToolExecutionStatus::Running => Color::Yellow,
            ToolExecutionStatus::Success => Color::Green,
            ToolExecutionStatus::Failed => Color::Red,
            ToolExecutionStatus::Timeout => Color::Magenta,
        }
    }
}

/// 单个工具执行记录
#[derive(Debug, Clone)]
pub struct ToolExecution {
    /// 工具名称
    pub tool_name: String,

    /// 工具输入摘要
    pub input_summary: String,

    /// 执行状态
    pub status: ToolExecutionStatus,

    /// 开始时间
    pub started_at: Instant,

    /// 结束时间
    pub finished_at: Option<Instant>,

    /// 输出摘要
    pub output_summary: Option<String>,

    /// 错误信息
    pub error: Option<String>,

    /// 关联的 Agent ID
    pub agent_id: Option<String>,
}

impl ToolExecution {
    /// 创建新的工具执行记录
    pub fn new(tool_name: &str, input_summary: &str) -> Self {
        Self {
            tool_name: tool_name.to_string(),
            input_summary: truncate(input_summary, 50),
            status: ToolExecutionStatus::Pending,
            started_at: Instant::now(),
            finished_at: None,
            output_summary: None,
            error: None,
            agent_id: None,
        }
    }

    /// 设置 Agent ID
    pub fn with_agent(mut self, agent_id: &str) -> Self {
        self.agent_id = Some(agent_id.to_string());
        self
    }

    /// 标记为运行中
    pub fn start(&mut self) {
        self.status = ToolExecutionStatus::Running;
        self.started_at = Instant::now();
    }

    /// 标记为成功
    pub fn succeed(&mut self, output_summary: &str) {
        self.status = ToolExecutionStatus::Success;
        self.finished_at = Some(Instant::now());
        self.output_summary = Some(truncate(output_summary, 100));
    }

    /// 标记为失败
    pub fn fail(&mut self, error: &str) {
        self.status = ToolExecutionStatus::Failed;
        self.finished_at = Some(Instant::now());
        self.error = Some(truncate(error, 100));
    }

    /// 标记为超时
    pub fn timeout(&mut self) {
        self.status = ToolExecutionStatus::Timeout;
        self.finished_at = Some(Instant::now());
    }

    /// 获取执行时长
    pub fn duration(&self) -> Duration {
        match self.finished_at {
            Some(end) => end.duration_since(self.started_at),
            None => self.started_at.elapsed(),
        }
    }

    /// 格式化执行时长
    pub fn format_duration(&self) -> String {
        let duration = self.duration();
        let ms = duration.as_millis();
        if ms < 1000 {
            format!("{}ms", ms)
        } else {
            format!("{:.1}s", duration.as_secs_f64())
        }
    }
}

/// 工具统计信息
#[derive(Debug, Clone, Default)]
pub struct ToolStats {
    /// 总执行次数
    pub total: usize,

    /// 成功次数
    pub successes: usize,

    /// 失败次数
    pub failures: usize,

    /// 超时次数
    pub timeouts: usize,

    /// 总执行时间 (毫秒)
    pub total_duration_ms: u128,

    /// 平均执行时间 (毫秒)
    pub avg_duration_ms: f64,
}

impl ToolStats {
    /// 计算成功率
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.successes as f64 / self.total as f64) * 100.0
        }
    }
}

/// 工具进度面板
pub struct ToolProgressPanel {
    /// 当前执行的工具
    current: Option<ToolExecution>,

    /// 执行历史 (最近 20 条)
    history: VecDeque<ToolExecution>,

    /// 历史最大长度
    max_history: usize,

    /// 各工具的统计信息
    tool_stats: std::collections::HashMap<String, ToolStats>,

    /// 总体统计
    overall_stats: ToolStats,
}

impl ToolProgressPanel {
    /// 创建新的工具进度面板
    pub fn new() -> Self {
        Self {
            current: None,
            history: VecDeque::with_capacity(20),
            max_history: 20,
            tool_stats: std::collections::HashMap::new(),
            overall_stats: ToolStats::default(),
        }
    }

    /// 开始执行工具
    pub fn start_tool(&mut self, tool_name: &str, input_summary: &str) {
        let mut execution = ToolExecution::new(tool_name, input_summary);
        execution.start();
        self.current = Some(execution);
    }

    /// 开始执行工具 (带 Agent ID)
    pub fn start_tool_with_agent(&mut self, tool_name: &str, input_summary: &str, agent_id: &str) {
        let mut execution = ToolExecution::new(tool_name, input_summary).with_agent(agent_id);
        execution.start();
        self.current = Some(execution);
    }

    /// 完成当前工具执行 (成功)
    pub fn finish_tool(&mut self, output_summary: &str) {
        if let Some(mut execution) = self.current.take() {
            execution.succeed(output_summary);
            self.add_to_history(execution);
        }
    }

    /// 完成当前工具执行 (失败)
    pub fn fail_tool(&mut self, error: &str) {
        if let Some(mut execution) = self.current.take() {
            execution.fail(error);
            self.add_to_history(execution);
        }
    }

    /// 超时当前工具执行
    pub fn timeout_tool(&mut self) {
        if let Some(mut execution) = self.current.take() {
            execution.timeout();
            self.add_to_history(execution);
        }
    }

    /// 添加到历史记录
    fn add_to_history(&mut self, execution: ToolExecution) {
        // 更新统计
        self.update_stats(&execution);

        // 添加到历史
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(execution);
    }

    /// 更新统计信息
    fn update_stats(&mut self, execution: &ToolExecution) {
        // 更新工具特定统计
        let stats = self.tool_stats.entry(execution.tool_name.clone()).or_default();
        stats.total += 1;
        stats.total_duration_ms += execution.duration().as_millis();
        stats.avg_duration_ms = stats.total_duration_ms as f64 / stats.total as f64;

        match execution.status {
            ToolExecutionStatus::Success => stats.successes += 1,
            ToolExecutionStatus::Failed => stats.failures += 1,
            ToolExecutionStatus::Timeout => stats.timeouts += 1,
            _ => {}
        }

        // 更新总体统计
        self.overall_stats.total += 1;
        self.overall_stats.total_duration_ms += execution.duration().as_millis();
        self.overall_stats.avg_duration_ms =
            self.overall_stats.total_duration_ms as f64 / self.overall_stats.total as f64;

        match execution.status {
            ToolExecutionStatus::Success => self.overall_stats.successes += 1,
            ToolExecutionStatus::Failed => self.overall_stats.failures += 1,
            ToolExecutionStatus::Timeout => self.overall_stats.timeouts += 1,
            _ => {}
        }
    }

    /// 获取当前执行的工具
    pub fn current(&self) -> Option<&ToolExecution> {
        self.current.as_ref()
    }

    /// 获取历史记录
    pub fn history(&self) -> &VecDeque<ToolExecution> {
        &self.history
    }

    /// 获取总体统计
    pub fn overall_stats(&self) -> &ToolStats {
        &self.overall_stats
    }

    /// 获取工具特定统计
    pub fn tool_stats(&self, tool_name: &str) -> Option<&ToolStats> {
        self.tool_stats.get(tool_name)
    }

    /// 是否有正在执行的工具
    pub fn is_running(&self) -> bool {
        self.current.is_some()
    }

    /// 重置面板
    pub fn reset(&mut self) {
        self.current = None;
        self.history.clear();
        self.tool_stats.clear();
        self.overall_stats = ToolStats::default();
    }

    /// 处理事件
    pub fn handle_event(&mut self, _event: &AppEvent) {
        // 事件处理由外部通过 start_tool 等方法完成
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let mut lines = Vec::new();

        // 总体统计
        lines.push(self.render_stats_line());

        // 当前执行的工具
        if let Some(ref current) = self.current {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("当前执行: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    &current.tool_name,
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]));

            // 输入摘要
            lines.push(Line::from(vec![
                Span::styled("  输入: ", Style::default().fg(Color::DarkGray)),
                Span::styled(&current.input_summary, Style::default().fg(Color::White)),
            ]));

            // 执行时长 (动态)
            let elapsed = current.format_duration();
            lines.push(Line::from(vec![
                Span::styled("  耗时: ", Style::default().fg(Color::DarkGray)),
                Span::styled(elapsed, Style::default().fg(Color::Cyan)),
                Span::styled(" (执行中...)", Style::default().fg(Color::Yellow)),
            ]));
        }

        // 最近执行历史
        if !self.history.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("最近执行 (", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{}", self.history.len()),
                    Style::default().fg(Color::White),
                ),
                Span::styled(")", Style::default().fg(Color::DarkGray)),
            ]));

            // 显示最近 5 条
            let recent: Vec<_> = self.history.iter().rev().take(5).collect();
            for execution in recent {
                lines.push(self.render_history_item(execution));
            }
        }

        // 如果没有活动，显示提示
        if self.current.is_none() && self.history.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "等待工具执行...",
                Style::default().fg(Color::DarkGray),
            )]));
        }

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" 工具进度 ")
                    .borders(Borders::ALL)
                    .border_style(border_style),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, rect);
    }

    /// 渲染统计行
    fn render_stats_line(&self) -> Line<'static> {
        let success_rate = self.overall_stats.success_rate();

        Line::from(vec![
            Span::styled("总计: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", self.overall_stats.total),
                Style::default().fg(Color::White),
            ),
            Span::raw("  "),
            Span::styled("成功: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", self.overall_stats.successes),
                Style::default().fg(Color::Green),
            ),
            Span::raw("  "),
            Span::styled("失败: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}", self.overall_stats.failures),
                Style::default().fg(Color::Red),
            ),
            Span::raw("  "),
            Span::styled("成功率: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.0}%", success_rate),
                Style::default().fg(if success_rate >= 80.0 {
                    Color::Green
                } else if success_rate >= 50.0 {
                    Color::Yellow
                } else {
                    Color::Red
                }),
            ),
            Span::raw("  "),
            Span::styled("平均: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.0}ms", self.overall_stats.avg_duration_ms),
                Style::default().fg(Color::Cyan),
            ),
        ])
    }

    /// 渲染历史记录项
    fn render_history_item(&self, execution: &ToolExecution) -> Line<'static> {
        let status_icon = execution.status.icon().to_string();
        let status_color = execution.status.color();
        let tool_name = format!("{:15}", execution.tool_name);
        let duration = execution.format_duration();

        let mut spans = vec![
            Span::raw("  "),
            Span::styled(status_icon, Style::default().fg(status_color)),
            Span::raw(" "),
            Span::styled(
                tool_name,
                Style::default().fg(Color::White),
            ),
            Span::raw(" "),
            Span::styled(
                duration,
                Style::default().fg(Color::DarkGray),
            ),
        ];

        // 如果有错误，显示错误
        if let Some(ref error) = execution.error {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                truncate(error, 30),
                Style::default().fg(Color::Red),
            ));
        }

        Line::from(spans)
    }

    /// 获取所有工具名称
    pub fn get_tool_names(&self) -> Vec<String> {
        self.tool_stats.keys().cloned().collect()
    }
}

impl Default for ToolProgressPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// 截断文本
fn truncate(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{}...", &text[..max_len.saturating_sub(3)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_execution_creation() {
        let execution = ToolExecution::new("read_file", "src/main.rs");
        assert_eq!(execution.tool_name, "read_file");
        assert_eq!(execution.status, ToolExecutionStatus::Pending);
    }

    #[test]
    fn test_tool_execution_lifecycle() {
        let mut execution = ToolExecution::new("read_file", "test.rs");
        execution.start();
        assert_eq!(execution.status, ToolExecutionStatus::Running);

        execution.succeed("file contents");
        assert_eq!(execution.status, ToolExecutionStatus::Success);
        assert!(execution.finished_at.is_some());
    }

    #[test]
    fn test_tool_progress_panel() {
        let mut panel = ToolProgressPanel::new();

        panel.start_tool("read_file", "test.rs");
        assert!(panel.is_running());

        panel.finish_tool("contents");
        assert!(!panel.is_running());
        assert_eq!(panel.history().len(), 1);
    }

    #[test]
    fn test_tool_stats() {
        let mut panel = ToolProgressPanel::new();

        panel.start_tool("read_file", "test.rs");
        panel.finish_tool("ok");

        panel.start_tool("write_file", "test.rs");
        panel.fail_tool("error");

        let stats = panel.overall_stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.successes, 1);
        assert_eq!(stats.failures, 1);
    }

    #[test]
    fn test_success_rate() {
        let mut panel = ToolProgressPanel::new();

        // 3 成功, 1 失败 = 75%
        for _ in 0..3 {
            panel.start_tool("test", "");
            panel.finish_tool("ok");
        }
        panel.start_tool("test", "");
        panel.fail_tool("err");

        assert_eq!(panel.overall_stats().success_rate(), 75.0);
    }

    #[test]
    fn test_status_icon_color() {
        assert_eq!(ToolExecutionStatus::Running.icon(), "[*]");
        assert_eq!(ToolExecutionStatus::Running.color(), Color::Yellow);
        assert_eq!(ToolExecutionStatus::Success.icon(), "[OK]");
        assert_eq!(ToolExecutionStatus::Success.color(), Color::Green);
    }
}
