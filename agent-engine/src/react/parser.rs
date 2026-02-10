// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct 循环解析器
//!
//! 解析 LLM 输出中的 Thought, Action, Action Input

use regex::Regex;
use serde::{Deserialize, Serialize};

/// 解析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseResult {
    /// 思考内容
    pub thought: String,

    /// 操作类型
    pub action_type: ActionType,

    /// 操作名称（如工具名）
    pub action_name: Option<String>,

    /// 操作输入（JSON 格式）
    pub action_input: Option<serde_json::Value>,

    /// 推理链
    pub reasoning: Vec<String>,

    /// 置信度
    pub confidence: f32,

    /// 是否需要继续
    pub should_continue: bool,
}

/// 操作类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionType {
    /// 思考（无操作）
    Thought,

    /// 使用工具
    UseTool,

    /// 回答用户
    Answer,

    /// 请求更多信息
    AskClarification,

    /// 完成任务
    Finish,

    /// 报告错误
    Error,
}

/// ReAct 解析器
pub struct ReactParser {
    /// 思考关键词正则
    thought_regex: Regex,

    /// 操作关键词正则
    action_regex: Regex,

    /// 工具调用正则
    tool_regex: Regex,

    /// JSON 提取正则
    json_regex: Regex,
}

impl ReactParser {
    /// 创建新的解析器
    pub fn new() -> Self {
        Self {
            thought_regex: Regex::new(r"(?i)thought:|thinking:|思考:|分析:").unwrap(),
            action_regex: Regex::new(r"(?i)action:|操作:|工具:").unwrap(),
            tool_regex: Regex::new(r"(?i)([a-z_]+)\(").unwrap(),
            json_regex: Regex::new(r"\{[^{}]*\}").unwrap(),
        }
    }

    /// 解析 LLM 输出
    pub fn parse(&self, output: &str) -> ParseResult {
        let mut thought = String::new();
        let mut action_type = ActionType::Thought;
        let mut action_name = None;
        let mut action_input = None;
        let mut reasoning = Vec::new();
        let mut should_continue = true;

        // 分割输出为行
        let lines: Vec<&str> = output.lines().collect();

        let mut current_section = "thought";
        let mut action_buffer = String::new();

        for line in &lines {
            let line = line.trim();

            // 检测章节切换
            if self.thought_regex.is_match(line) {
                current_section = "thought";
                reasoning.push(line.to_string());
                continue;
            } else if self.action_regex.is_match(line) {
                current_section = "action";
                reasoning.push(line.to_string());
                continue;
            }

            match current_section {
                "thought" => {
                    if !line.is_empty() {
                        thought.push_str(line);
                        thought.push(' ');
                    }
                }
                "action" => {
                    action_buffer.push_str(line);
                    action_buffer.push(' ');
                }
                _ => {}
            }
        }

        // 解析操作
        if !action_buffer.is_empty() {
            if let Some(caps) = self.tool_regex.captures(&action_buffer) {
                action_name = Some(caps.get(1).unwrap().as_str().to_string());
                action_type = ActionType::UseTool;

                // 尝试提取 JSON 参数
                if let Some(json_caps) = self.json_regex.captures(&action_buffer) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_caps.get(0).unwrap().as_str()) {
                        action_input = Some(json);
                    }
                }
            } else if action_buffer.contains("完成") || action_buffer.contains("finish") {
                action_type = ActionType::Finish;
                should_continue = false;
            } else if action_buffer.contains("回答") || action_buffer.contains("answer") {
                action_type = ActionType::Answer;
                should_continue = false;
            } else if action_buffer.contains("错误") || action_buffer.contains("error") {
                action_type = ActionType::Error;
                should_continue = false;
            }
        }

        // 提取推理步骤
        for line in &lines {
            if line.contains("1.") || line.contains("2.") || line.contains("3.") ||
               line.contains("首先") || line.contains("然后") || line.contains("最后") {
                reasoning.push(line.to_string());
            }
        }

        // 检测置信度
        let confidence = self.extract_confidence(output);

        ParseResult {
            thought: thought.trim().to_string(),
            action_type,
            action_name,
            action_input,
            reasoning,
            confidence,
            should_continue,
        }
    }

    /// 从输出中提取置信度
    fn extract_confidence(&self, output: &str) -> f32 {
        let output_lower = output.to_lowercase();

        if output_lower.contains("确定") || output_lower.contains("certain") {
            0.9
        } else if output_lower.contains("可能") || output_lower.contains("probably") {
            0.7
        } else if output_lower.contains("不确定") || output_lower.contains("uncertain") {
            0.3
        } else {
            0.5
        }
    }

    /// 格式化提示词模板
    pub fn format_prompt_template(&self, context: &str, available_tools: &[String]) -> String {
        format!(
            r#"你是一个代码安全审计专家。请按照以下格式进行推理：

当前上下文:
{}

可用工具:
{}

请使用以下格式回答：

Thought: [你的思考过程]
Action: [工具名称] 或 "Answer" (回答用户) 或 "Finish" (完成任务)
Action Input: [工具参数，JSON 格式]

例如：
Thought: 我需要检查认证相关的代码，先搜索登录函数
Action: search_symbol
Action Input: {{"symbol": "login", "limit": 10}}

或者：
Thought: 我已经找到了所有相关问题，现在给出分析结果
Action: Answer
Action Input: {{"summary": "发现 3 个安全问题...", "findings": [...]}}
"#,
            context,
            available_tools.join(", ")
        )
    }

    /// 格式化观察结果为提示
    pub fn format_observation(&self, observation: &super::state::Observation) -> String {
        if observation.success {
            format!(
                "观察: 执行成功\n工具: {}\n结果: {}\n耗时: {}ms",
                observation.tool_name.as_deref().unwrap_or("N/A"),
                observation.summary,
                observation.duration_ms
            )
        } else {
            format!(
                "观察: 执行失败\n错误: {}",
                observation.error.as_deref().unwrap_or("Unknown error")
            )
        }
    }
}

impl Default for ReactParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tool_action() {
        let parser = ReactParser::new();

        let output = r#"
Thought: 我需要检查登录相关的代码
Action: search_symbol
Action Input: {"symbol": "login"}
"#;

        let result = parser.parse(output);

        assert_eq!(result.action_type, ActionType::UseTool);
        assert_eq!(result.action_name, Some("search_symbol".to_string()));
        assert!(result.action_input.is_some());
    }

    #[test]
    fn test_parse_answer_action() {
        let parser = ReactParser::new();

        let output = r#"
Thought: 我已经完成分析
Action: Answer
Action Input: {"summary": "发现 3 个漏洞"}
"#;

        let result = parser.parse(output);

        assert_eq!(result.action_type, ActionType::Answer);
        assert!(!result.should_continue);
    }
}
