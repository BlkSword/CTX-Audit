// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 终端渲染器
//!
//! 提供跨平台的终端 UI 功能

use console::{Style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::Write;
use std::time::Duration;

use ctx_audit_agent_engine::{AgentType, AgentStatus};
use crate::database::Finding;

/// 终端渲染器
pub struct TerminalRenderer {
    term: Term,
    use_colors: bool,
}

impl TerminalRenderer {
    /// 创建新的渲染器
    pub fn new() -> Self {
        let term = Term::stdout();
        let use_colors = term.is_term();

        Self { term, use_colors }
    }

    /// 检查是否支持颜色
    pub fn supports_color(&self) -> bool {
        self.use_colors
    }

    /// 打印普通文本
    pub fn print(&mut self, text: &str) {
        let _ = writeln!(self.term, "{}", text);
    }

    /// 打印带时间戳的日志
    pub fn log(&mut self, level: LogLevel, text: &str) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        let level_str = level.as_str();
        let msg = format!("[{}] {} {}", timestamp, level_str, text);

        if self.use_colors {
            let style = level.style();
            let styled = style.apply_to(msg);
            let _ = writeln!(self.term, "{}", styled);
        } else {
            let _ = writeln!(self.term, "{}", msg);
        }
    }

    /// 打印成功消息
    pub fn success(&mut self, text: &str) {
        self.log(LogLevel::Success, text);
    }

    /// 打印错误消息
    pub fn error(&mut self, text: &str) {
        self.log(LogLevel::Error, text);
    }

    /// 打印警告消息
    pub fn warning(&mut self, text: &str) {
        self.log(LogLevel::Warning, text);
    }

    /// 打印信息消息
    pub fn info(&mut self, text: &str) {
        self.log(LogLevel::Info, text);
    }

    /// 打印调试消息
    pub fn debug(&mut self, text: &str) {
        self.log(LogLevel::Debug, text);
    }

    /// 打印 Agent 状态
    pub fn agent_status(&mut self, agent_type: &AgentType, status: &AgentStatus) {
        let icon = match status {
            AgentStatus::Initializing => "⚙",
            AgentStatus::Running => "▶",
            AgentStatus::Completed => "✓",
            AgentStatus::Paused => "⏸",
            AgentStatus::Failed => "✗",
            AgentStatus::Cancelled => "⏹",
        };

        let status_str = match status {
            AgentStatus::Initializing => "初始化中",
            AgentStatus::Running => "运行中",
            AgentStatus::Completed => "已完成",
            AgentStatus::Paused => "已暂停",
            AgentStatus::Failed => "失败",
            AgentStatus::Cancelled => "已取消",
        };

        self.info(&format!("{} {}: {}", icon, agent_type, status_str));
    }

    /// 打印思考过程
    pub fn thinking(&mut self, _agent_type: &AgentType, thought: &str) {
        if self.use_colors {
            let style = Style::new().dim();
            let _ = writeln!(
                &mut self.term,
                "  {} {}",
                style.apply_to("Thinking:"),
                style.apply_to(thought)
            );
        } else {
            let _ = writeln!(&mut self.term, "  Thinking: {}", thought);
        }
    }

    /// 打印工具调用
    pub fn tool_call(&mut self, tool_name: &str, input: &serde_json::Value) {
        let input_str = serde_json::to_string(input).unwrap_or_default();
        self.info(&format!("  → {} with: {}", tool_name, input_str));
    }

    /// 打印漏洞发现
    pub fn finding(&mut self, severity: &str, title: &str, file_path: &str, line: u32) {
        let (icon, style) = match severity.to_lowercase().as_str() {
            "critical" => ("⚠", Style::new().red().bold()),
            "high" => ("⚠", Style::new().red()),
            "medium" => ("⚠", Style::new().yellow()),
            "low" => ("ℹ", Style::new().blue()),
            _ => ("ℹ", Style::new().dim()),
        };

        let msg = format!(
            "{} [{}] {} at {}:{}",
            icon, severity, title, file_path, line
        );

        if self.use_colors {
            let _ = writeln!(&mut self.term, "{}", style.apply_to(msg));
        } else {
            let _ = writeln!(&mut self.term, "{}", msg);
        }
    }

    /// 打印漏洞（数据库模型）
    pub fn print_finding(&mut self, finding: &Finding) {
        let (icon, style) = match finding.severity.to_lowercase().as_str() {
            "critical" => ("⚠", Style::new().red().bold()),
            "high" => ("⚠", Style::new().red()),
            "medium" => ("⚠", Style::new().yellow()),
            "low" => ("ℹ", Style::new().blue()),
            _ => ("ℹ", Style::new().dim()),
        };

        let location = if let Some(line) = finding.start_line {
            format!("{}:{}", finding.file_path, line)
        } else {
            finding.file_path.clone()
        };

        let msg = format!(
            "{} [{}] {} - {}",
            icon, finding.severity, finding.finding_id, finding.title
        );

        if self.use_colors {
            let _ = writeln!(&mut self.term, "{}", style.apply_to(msg));
        } else {
            let _ = writeln!(&mut self.term, "{}", msg);
        }
        let _ = writeln!(&mut self.term, "  → {}", location);

        if let Some(desc) = &finding.description {
            if self.use_colors {
                let desc_style = Style::new().dim();
                let _ = writeln!(&mut self.term, "  {}", desc_style.apply_to(desc));
            } else {
                let _ = writeln!(&mut self.term, "  {}", desc);
            }
        }
    }

    /// 打印漏洞详情
    pub fn print_finding_detail(&mut self, finding: &Finding) {
        self.info(&format!("漏洞详情: {}", finding.finding_id));

        println!();
        println!("标题: {}", finding.title);
        println!("严重程度: {}", finding.severity);
        println!("状态: {}", finding.status);
        println!("文件: {}", finding.file_path);

        if let Some(start) = finding.start_line {
            if let Some(end) = finding.end_line {
                println!("行号: {}-{}", start, end);
            } else {
                println!("行号: {}", start);
            }
        }

        if let Some(category) = &finding.category {
            println!("分类: {}", category);
        }

        if let Some(confidence) = &finding.confidence {
            println!("置信度: {}", confidence);
        }

        if finding.false_positive {
            println!("误报: 是");
        }

        if let Some(desc) = &finding.description {
            println!();
            println!("描述:");
            println!("  {}", desc);
        }

        if let Some(snippet) = &finding.code_snippet {
            println!();
            println!("代码片段:");
            for line in snippet.lines() {
                println!("  {}", line);
            }
        }

        if let Some(note) = &finding.note {
            println!();
            println!("备注: {}", note);
        }

        println!();
        println!("创建时间: {}", finding.created_at);
        println!("更新时间: {}", finding.updated_at);
    }

    /// 创建进度条
    pub fn progress_bar(&self, total: u64) -> ProgressBar {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("##>-"),
        );
        pb
    }

    /// 创建 spinner
    pub fn spinner(&self, msg: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg}")
                .unwrap()
        );
        pb.set_message(msg.to_string());
        pb.enable_steady_tick(Duration::from_millis(100));
        pb
    }

    /// 清空行
    pub fn clear_line(&mut self) {
        let _ = self.term.clear_line();
    }
}

impl Default for TerminalRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// 日志级别
pub enum LogLevel {
    Debug,
    Info,
    Success,
    Warning,
    Error,
}

impl LogLevel {
    /// 获取级别字符串
    fn as_str(&self) -> &str {
        match self {
            LogLevel::Debug => "D",
            LogLevel::Info => "ℹ",
            LogLevel::Success => "✓",
            LogLevel::Warning => "⚠",
            LogLevel::Error => "✗",
        }
    }

    /// 获取样式
    fn style(&self) -> Style {
        match self {
            LogLevel::Debug => Style::new().dim(),
            LogLevel::Info => Style::new().blue(),
            LogLevel::Success => Style::new().green(),
            LogLevel::Warning => Style::new().yellow(),
            LogLevel::Error => Style::new().red().bold(),
        }
    }
}

/// 流式输出器
///
/// 用于实时输出 Agent 执行过程
pub struct StreamOutput {
    renderer: TerminalRenderer,
}

impl StreamOutput {
    /// 创建新的流式输出器
    pub fn new() -> Self {
        Self {
            renderer: TerminalRenderer::new(),
        }
    }

    /// 输出事件
    pub fn emit(&mut self, event: &StreamEvent) {
        match event {
            StreamEvent::AgentStart(agent_type) => {
                self.renderer.info(&format!("启动 {} Agent", agent_type));
            }
            StreamEvent::AgentComplete(agent_type, message) => {
                self.renderer.success(&format!("{} Agent 完成: {}", agent_type, message));
            }
            StreamEvent::AgentError(agent_type, error) => {
                self.renderer.error(&format!("{} Agent 失败: {}", agent_type, error));
            }
            StreamEvent::Thinking(agent_type, thought) => {
                self.renderer.thinking(agent_type, thought);
            }
            StreamEvent::ToolCall(tool_name, input) => {
                self.renderer.tool_call(tool_name, input);
            }
            StreamEvent::Finding(severity, title, file_path, line) => {
                self.renderer.finding(severity, title, file_path, *line);
            }
            StreamEvent::Progress(agent_type, progress, message) => {
                self.renderer
                    .info(&format!("{}: {}% - {}", agent_type, progress, message));
            }
        }
    }
}

impl Default for StreamOutput {
    fn default() -> Self {
        Self::new()
    }
}

/// 流式事件
#[derive(Debug)]
pub enum StreamEvent {
    /// Agent 开始
    AgentStart(AgentType),

    /// Agent 完成
    AgentComplete(AgentType, String),

    /// Agent 错误
    AgentError(AgentType, String),

    /// 思考过程
    Thinking(AgentType, String),

    /// 工具调用
    ToolCall(String, serde_json::Value),

    /// 漏洞发现
    Finding(String, String, String, u32),

    /// 进度更新
    Progress(AgentType, u8, String),
}
