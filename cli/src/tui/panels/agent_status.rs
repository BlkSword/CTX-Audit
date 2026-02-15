// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 多 Agent 状态面板
//!
//! 显示多个 Agent 的并行执行状态

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Wrap},
    Frame,
};
use std::collections::HashMap;

use crate::tui::app::AppEvent;

/// Agent 执行状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentExecutionStatus {
    /// 空闲
    Idle,
    /// 初始化中
    Initializing,
    /// 运行中
    Running,
    /// 思考中
    Thinking,
    /// 执行工具
    ExecutingTool,
    /// 已完成
    Completed,
    /// 已失败
    Failed,
}

impl AgentExecutionStatus {
    /// 获取状态图标
    pub fn icon(&self) -> &str {
        match self {
            AgentExecutionStatus::Idle => "○",
            AgentExecutionStatus::Initializing => "◐",
            AgentExecutionStatus::Running => "●",
            AgentExecutionStatus::Thinking => "💭",
            AgentExecutionStatus::ExecutingTool => "⚙",
            AgentExecutionStatus::Completed => "✓",
            AgentExecutionStatus::Failed => "✗",
        }
    }

    /// 获取状态颜色
    pub fn color(&self) -> Color {
        match self {
            AgentExecutionStatus::Idle => Color::DarkGray,
            AgentExecutionStatus::Initializing => Color::Yellow,
            AgentExecutionStatus::Running => Color::Cyan,
            AgentExecutionStatus::Thinking => Color::Magenta,
            AgentExecutionStatus::ExecutingTool => Color::Blue,
            AgentExecutionStatus::Completed => Color::Green,
            AgentExecutionStatus::Failed => Color::Red,
        }
    }
}

/// Agent 类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AgentType {
    Orchestrator,
    Recon,
    Analysis,
    Verification,
}

impl AgentType {
    /// 获取显示名称
    pub fn display_name(&self) -> &str {
        match self {
            AgentType::Orchestrator => "Orchestrator",
            AgentType::Recon => "Recon",
            AgentType::Analysis => "Analysis",
            AgentType::Verification => "Verification",
        }
    }

    /// 获取图标
    pub fn icon(&self) -> &str {
        match self {
            AgentType::Orchestrator => "🎯",
            AgentType::Recon => "🔍",
            AgentType::Analysis => "🔬",
            AgentType::Verification => "✅",
        }
    }
}

/// 单个 Agent 的状态
#[derive(Debug, Clone)]
pub struct AgentStatus {
    /// Agent 类型
    pub agent_type: AgentType,

    /// Agent ID
    pub agent_id: String,

    /// 执行状态
    pub status: AgentExecutionStatus,

    /// 进度 (0-100)
    pub progress: u8,

    /// 当前任务描述
    pub current_task: String,

    /// 已执行的工具数量
    pub tools_executed: usize,

    /// 发现的漏洞数量
    pub findings_count: usize,

    /// 开始时间
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,

    /// 完成时间
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// 错误信息
    pub error: Option<String>,
}

impl AgentStatus {
    /// 创建新的 Agent 状态
    pub fn new(agent_type: AgentType) -> Self {
        Self {
            agent_type,
            agent_id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            status: AgentExecutionStatus::Idle,
            progress: 0,
            current_task: String::new(),
            tools_executed: 0,
            findings_count: 0,
            started_at: None,
            completed_at: None,
            error: None,
        }
    }

    /// 获取执行时长
    pub fn duration(&self) -> Option<std::time::Duration> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => {
                Some(end.signed_duration_since(start).to_std().unwrap_or_default())
            }
            (Some(start), None) => {
                let now = chrono::Utc::now();
                Some(now.signed_duration_since(start).to_std().unwrap_or_default())
            }
            _ => None,
        }
    }

    /// 格式化执行时长
    pub fn format_duration(&self) -> String {
        if let Some(duration) = self.duration() {
            let secs = duration.as_secs();
            if secs < 60 {
                format!("{}s", secs)
            } else {
                format!("{}m {}s", secs / 60, secs % 60)
            }
        } else {
            "-".to_string()
        }
    }
}

/// 多 Agent 状态面板
pub struct AgentStatusPanel {
    /// Agent 状态列表
    agents: HashMap<AgentType, AgentStatus>,

    /// 总体进度
    overall_progress: u8,

    /// 总体状态
    overall_status: String,

    /// 活动的 Agent 数量
    active_agents: usize,

    /// 完成的 Agent 数量
    completed_agents: usize,
}

impl AgentStatusPanel {
    /// 创建新的 Agent 状态面板
    pub fn new() -> Self {
        let mut agents = HashMap::new();
        agents.insert(AgentType::Orchestrator, AgentStatus::new(AgentType::Orchestrator));
        agents.insert(AgentType::Recon, AgentStatus::new(AgentType::Recon));
        agents.insert(AgentType::Analysis, AgentStatus::new(AgentType::Analysis));
        agents.insert(AgentType::Verification, AgentStatus::new(AgentType::Verification));

        Self {
            agents,
            overall_progress: 0,
            overall_status: "就绪".to_string(),
            active_agents: 0,
            completed_agents: 0,
        }
    }

    /// 更新 Agent 状态
    pub fn update_agent(&mut self, agent_type: AgentType, status: AgentStatus) {
        self.agents.insert(agent_type.clone(), status);
        self.recalculate_overall();
    }

    /// 设置 Agent 执行状态
    pub fn set_agent_status(&mut self, agent_type: &AgentType, status: AgentExecutionStatus) {
        if let Some(agent) = self.agents.get_mut(agent_type) {
            agent.status = status;
            if status == AgentExecutionStatus::Running && agent.started_at.is_none() {
                agent.started_at = Some(chrono::Utc::now());
            }
            if status == AgentExecutionStatus::Completed || status == AgentExecutionStatus::Failed {
                agent.completed_at = Some(chrono::Utc::now());
            }
        }
        self.recalculate_overall();
    }

    /// 设置 Agent 进度
    pub fn set_agent_progress(&mut self, agent_type: &AgentType, progress: u8, task: &str) {
        if let Some(agent) = self.agents.get_mut(agent_type) {
            agent.progress = progress;
            agent.current_task = task.to_string();
        }
        self.recalculate_overall();
    }

    /// 增加 Agent 工具执行计数
    pub fn increment_tools(&mut self, agent_type: &AgentType) {
        if let Some(agent) = self.agents.get_mut(agent_type) {
            agent.tools_executed += 1;
        }
    }

    /// 增加 Agent 发现计数
    pub fn increment_findings(&mut self, agent_type: &AgentType) {
        if let Some(agent) = self.agents.get_mut(agent_type) {
            agent.findings_count += 1;
        }
    }

    /// 设置 Agent 错误
    pub fn set_agent_error(&mut self, agent_type: &AgentType, error: &str) {
        if let Some(agent) = self.agents.get_mut(agent_type) {
            agent.status = AgentExecutionStatus::Failed;
            agent.error = Some(error.to_string());
        }
        self.recalculate_overall();
    }

    /// 重新计算总体状态
    fn recalculate_overall(&mut self) {
        let mut total_progress = 0u32;
        let mut active = 0usize;
        let mut completed = 0usize;

        for agent in self.agents.values() {
            total_progress += agent.progress as u32;

            match agent.status {
                AgentExecutionStatus::Running
                | AgentExecutionStatus::Thinking
                | AgentExecutionStatus::ExecutingTool
                | AgentExecutionStatus::Initializing => {
                    active += 1;
                }
                AgentExecutionStatus::Completed | AgentExecutionStatus::Failed => {
                    completed += 1;
                }
                AgentExecutionStatus::Idle => {}
            }
        }

        self.overall_progress = (total_progress / self.agents.len() as u32) as u8;
        self.active_agents = active;
        self.completed_agents = completed;

        // 更新总体状态
        if active > 0 {
            self.overall_status = format!("{} 个 Agent 运行中", active);
        } else if completed == self.agents.len() {
            self.overall_status = "所有 Agent 已完成".to_string();
        } else {
            self.overall_status = "就绪".to_string();
        }
    }

    /// 重置所有状态
    pub fn reset(&mut self) {
        for (_, agent) in self.agents.iter_mut() {
            agent.status = AgentExecutionStatus::Idle;
            agent.progress = 0;
            agent.current_task.clear();
            agent.tools_executed = 0;
            agent.findings_count = 0;
            agent.started_at = None;
            agent.completed_at = None;
            agent.error = None;
        }
        self.overall_progress = 0;
        self.overall_status = "就绪".to_string();
        self.active_agents = 0;
        self.completed_agents = 0;
    }

    /// 处理事件
    pub fn handle_event(&mut self, _event: &AppEvent) {
        // 事件处理由外部通过 update_agent 等方法完成
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let mut lines = Vec::new();

        // 总体状态
        lines.push(Line::from(vec![
            Span::styled("状态: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &self.overall_status,
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled(
                format!("完成: {}/{}", self.completed_agents, self.agents.len()),
                Style::default().fg(Color::Green),
            ),
        ]));
        lines.push(Line::from(""));

        // Agent 列表
        let agent_order = [
            AgentType::Orchestrator,
            AgentType::Recon,
            AgentType::Analysis,
            AgentType::Verification,
        ];

        for agent_type in &agent_order {
            if let Some(agent) = self.agents.get(agent_type) {
                lines.push(self.render_agent_line(agent));
                lines.push(self.render_agent_progress(agent));

                // 如果有错误，显示错误
                if let Some(ref error) = agent.error {
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled(
                            format!("❌ {}", truncate(error, 50)),
                            Style::default().fg(Color::Red),
                        ),
                    ]));
                }

                lines.push(Line::from(""));
            }
        }

        // 如果没有活动，显示提示
        if self.active_agents == 0 && self.completed_agents == 0 {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "等待审计开始...",
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" Agent 状态 ")
                    .borders(Borders::ALL)
                    .border_style(border_style),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, rect);
    }

    /// 渲染单个 Agent 状态行
    fn render_agent_line(&self, agent: &AgentStatus) -> Line<'static> {
        let status_color = agent.status.color();
        let status_icon = agent.status.icon().to_string();
        let type_icon = agent.agent_type.icon().to_string();
        let display_name = format!("{:12}", agent.agent_type.display_name());
        let status_text = format!("{:12}", format!("{:?}", agent.status));
        let tools = format!("🔧{}", agent.tools_executed);
        let findings = format!("🔍{}", agent.findings_count);
        let duration = agent.format_duration();

        Line::from(vec![
            Span::styled(type_icon, Style::default().fg(Color::Yellow)),
            Span::raw(" "),
            Span::styled(
                display_name,
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(status_icon, Style::default().fg(status_color)),
            Span::raw(" "),
            Span::styled(
                status_text,
                Style::default().fg(status_color),
            ),
            Span::raw("  "),
            Span::styled(
                tools,
                Style::default().fg(Color::Blue),
            ),
            Span::raw(" "),
            Span::styled(
                findings,
                Style::default().fg(Color::Green),
            ),
            Span::raw("  "),
            Span::styled(
                duration,
                Style::default().fg(Color::DarkGray),
            ),
        ])
    }

    /// 渲染 Agent 进度条
    fn render_agent_progress(&self, agent: &AgentStatus) -> Line<'static> {
        let progress_width = 20;
        let filled = (agent.progress as usize * progress_width) / 100;
        let empty = progress_width - filled;

        let bar: String = if agent.progress > 0 {
            format!(
                "[{}{}] {:3}%",
                "█".repeat(filled),
                "░".repeat(empty),
                agent.progress
            )
        } else {
            format!("[{}]   -%", "░".repeat(progress_width))
        };

        let bar_color = if agent.progress == 100 {
            Color::Green
        } else if agent.progress > 0 {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let mut spans = vec![
            Span::raw("    "),
            Span::styled(bar, Style::default().fg(bar_color)),
        ];

        // 当前任务
        if !agent.current_task.is_empty() {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(
                truncate(&agent.current_task, 30),
                Style::default().fg(Color::DarkGray),
            ));
        }

        Line::from(spans)
    }

    /// 获取 Agent 状态
    pub fn get_agent(&self, agent_type: &AgentType) -> Option<&AgentStatus> {
        self.agents.get(agent_type)
    }

    /// 获取总体进度
    pub fn get_overall_progress(&self) -> u8 {
        self.overall_progress
    }

    /// 是否有活动的 Agent
    pub fn has_active_agents(&self) -> bool {
        self.active_agents > 0
    }
}

impl Default for AgentStatusPanel {
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
    fn test_agent_status_creation() {
        let status = AgentStatus::new(AgentType::Analysis);
        assert_eq!(status.agent_type, AgentType::Analysis);
        assert_eq!(status.status, AgentExecutionStatus::Idle);
        assert_eq!(status.progress, 0);
    }

    #[test]
    fn test_agent_status_panel_creation() {
        let panel = AgentStatusPanel::new();
        assert_eq!(panel.agents.len(), 4);
        assert_eq!(panel.overall_progress, 0);
    }

    #[test]
    fn test_set_agent_status() {
        let mut panel = AgentStatusPanel::new();
        panel.set_agent_status(&AgentType::Analysis, AgentExecutionStatus::Running);
        let agent = panel.get_agent(&AgentType::Analysis).unwrap();
        assert_eq!(agent.status, AgentExecutionStatus::Running);
        assert!(agent.started_at.is_some());
    }

    #[test]
    fn test_agent_execution_status_icon() {
        assert_eq!(AgentExecutionStatus::Running.icon(), "●");
        assert_eq!(AgentExecutionStatus::Completed.icon(), "✓");
        assert_eq!(AgentExecutionStatus::Failed.icon(), "✗");
    }
}
