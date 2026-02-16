// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 思考过程可视化面板
//!
//! 显示 Agent 的 ReAct 循环思考链

use ratatui::{Frame, layout::Rect, style::{Color, Modifier, Style}, text::{Line, Span}, widgets::{Block, Borders, Paragraph, Wrap, List, ListItem, ListState}};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::tui::app::{AppEvent, AgentEvent};

/// Agent 思考面板
pub struct ThinkingPanel {
    /// 思考历史
    thoughts: Vec<ThoughtItem>,

    /// 滚动位置
    scroll: usize,

    /// 选中的思考
    selected: usize,

    /// 是否展开详情
    expanded: bool,

    /// 当前状态
    current_status: String,

    /// 进度
    progress: u8,
}

/// 思考条目
#[derive(Debug, Clone)]
pub struct ThoughtItem {
    /// 迭代次数
    pub iteration: u32,

    /// 思考内容
    pub thought: String,

    /// 操作
    pub action: Option<String>,

    /// 操作输入
    pub action_input: Option<serde_json::Value>,

    /// 观察结果
    pub observation: Option<String>,

    /// 时间戳
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// 是否正在执行
    pub executing: bool,

    /// 是否完成
    pub completed: bool,
}

impl ThinkingPanel {
    /// 创建新的思考面板
    pub fn new() -> Self {
        Self {
            thoughts: Vec::new(),
            scroll: 0,
            selected: 0,
            expanded: false,
            current_status: "就绪".to_string(),
            progress: 0,
        }
    }

    /// 添加思考
    pub fn add_thought(&mut self, thought: ThoughtItem) {
        self.thoughts.push(thought);
        // 自动滚动到最新
        if self.thoughts.len() > 1 {
            self.selected = self.thoughts.len() - 1;
        }
    }

    /// 更新当前状态
    pub fn update_status(&mut self, status: String, progress: u8) {
        self.current_status = status;
        self.progress = progress;
    }

    /// 清空历史
    pub fn clear(&mut self) {
        self.thoughts.clear();
        self.scroll = 0;
        self.selected = 0;
    }

    /// 切换展开状态
    pub fn toggle_expanded(&mut self) {
        self.expanded = !self.expanded;
    }

    /// 滚动
    pub fn scroll(&mut self, delta: isize) {
        let new_scroll = if delta >= 0 {
            self.scroll + delta as usize
        } else {
            self.scroll.saturating_sub((-delta) as usize)
        };
        self.scroll = new_scroll.min(self.thoughts.len().saturating_sub(1));
    }

    /// 选择上一个
    pub fn select_prev(&mut self) {
        if !self.thoughts.is_empty() {
            self.selected = self.selected.saturating_sub(1);
        }
    }

    /// 选择下一个
    pub fn select_next(&mut self) {
        if !self.thoughts.is_empty() {
            self.selected = (self.selected + 1).min(self.thoughts.len() - 1);
        }
    }

    /// 处理事件
    pub fn handle_event(&mut self, event: &AppEvent) {
        match event {
            AppEvent::Agent(agent_event) => {
                match agent_event {
                    AgentEvent::Thinking(msg) => {
                        // 添加思考条目
                        let thought = ThoughtItem {
                            iteration: self.thoughts.len() as u32 + 1,
                            thought: msg.clone(),
                            action: None,
                            action_input: None,
                            observation: None,
                            timestamp: chrono::Utc::now(),
                            executing: true,
                            completed: false,
                        };
                        self.add_thought(thought);
                        self.update_status("思考中...".to_string(), self.progress);
                    }
                    AgentEvent::ToolCall(tool, input) => {
                        // 更新最后一个思考条目
                        if let Some(last) = self.thoughts.last_mut() {
                            last.action = Some(tool.clone());
                            last.action_input = Some(serde_json::from_str(input).unwrap_or(serde_json::json!(input)));
                            last.executing = false;
                        }
                        self.update_status(format!("执行: {}", tool), self.progress);
                    }
                    AgentEvent::Complete(msg) => {
                        // 标记完成
                        if let Some(last) = self.thoughts.last_mut() {
                            last.observation = Some(msg.clone());
                            last.completed = true;
                        }
                        self.update_status("完成".to_string(), 100);
                    }
                    AgentEvent::Error(err) => {
                        // 标记错误
                        if let Some(last) = self.thoughts.last_mut() {
                            last.observation = Some(format!("错误: {}", err));
                            last.completed = true;
                        }
                        self.update_status(format!("错误: {}", err), self.progress);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let mut lines = Vec::new();

        // 状态栏
        lines.push(Line::from(vec![
            Span::styled("状态: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &self.current_status,
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("进度: {}%", self.progress),
                Style::default().fg(Color::Yellow),
            ),
        ]));
        lines.push(Line::from(""));

        // 思考链
        for (i, thought) in self.thoughts.iter().enumerate() {
            let is_selected = i == self.selected;

            // 迭代标题
            let icon = if thought.executing {
                "[...]"
            } else if thought.completed {
                "[OK]"
            } else {
                "[?]"
            };

            let iteration_style = if is_selected {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };

            lines.push(Line::from(vec![
                Span::styled(icon, Style::default().fg(Color::Yellow)),
                Span::raw(" "),
                Span::styled(
                    format!("迭代 {} | {}", thought.iteration, thought.timestamp.format("%H:%M:%S")),
                    iteration_style,
                ),
            ]));

            // 思考内容
            let thought_style = if is_selected {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };

            for line in word_wrap(&thought.thought, 60) {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(line, thought_style),
                ]));
            }

            // 操作（如果有）
            if let Some(ref action) = thought.action {
                let action_style = Style::default().fg(Color::Cyan);

                if self.expanded || is_selected {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled("> ", action_style),
                        Span::styled(action, action_style),
                    ]));

                    // 操作输入
                    if let Some(ref input) = thought.action_input {
                        if let Ok(input_str) = serde_json::to_string_pretty(input) {
                            for line in word_wrap(&input_str, 56) {
                                lines.push(Line::from(vec![
                                    Span::raw("      "),
                                    Span::styled(line, Style::default().fg(Color::DarkGray)),
                                ]));
                            }
                        }
                    }
                }
            }

            // 观察结果（如果有）
            if let Some(ref obs) = thought.observation {
                let obs_style = if obs.contains("错误") {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                };

                if self.expanded || is_selected {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled("→ ", obs_style),
                        Span::styled(truncate(&obs, 70), obs_style),
                    ]));
                }
            }

            lines.push(Line::from(""));
        }

        // 如果没有思考，显示提示
        if lines.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Agent 思考过程", Style::default().fg(Color::Cyan)),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("等待审计开始...", Style::default().fg(Color::DarkGray)),
            ]));
        }

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(lines)
            .block(Block::default()
                .title(" Agent 思考 ")
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .wrap(Wrap { trim: true })
            .scroll((self.scroll as u16, 0));

        f.render_widget(paragraph, rect);
    }

    /// 获取选中的思考
    pub fn get_selected(&self) -> Option<&ThoughtItem> {
        self.thoughts.get(self.selected)
    }
}

impl Default for ThinkingPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// 文本换行
fn word_wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_length = 0;

    for word in text.split_whitespace() {
        if current_length + word.len() + 1 > width {
            if !current_line.is_empty() {
                lines.push(current_line.clone());
            }
            current_line = word.to_string();
            current_length = word.len();
        } else {
            if !current_line.is_empty() {
                current_line.push(' ');
                current_length += 1;
            }
            current_line.push_str(word);
            current_length += word.len();
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(text.to_string());
    }

    lines
}

/// 截断文本
fn truncate(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{}...", &text[..max_len.saturating_sub(3)])
    }
}
