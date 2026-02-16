// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct 循环解析器（旧版）
//!
//! 解析 LLM 输出中的 Thought、Action、Action Input
//!
//! 注意：建议使用 react/parser.rs 中的新版 ReactParser

use regex::Regex;
use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;

lazy_static! {
    /// 匹配 Thought: 后的内容（到行尾）
    static ref THOUGHT_REGEX: Regex = Regex::new(r"(?im)^\s*Thought\s*:?\s*(.+)$").unwrap();

    /// 匹配 Action: 后的内容（到行尾）
    static ref ACTION_REGEX: Regex = Regex::new(r"(?im)^\s*Action\s*:?\s*(.+)$").unwrap();

    /// 匹配 Action Input: 后的内容（到行尾或整个 JSON）
    static ref ACTION_INPUT_REGEX: Regex = Regex::new(r"(?im)^\s*Action Input\s*:?\s*(.+)$").unwrap();

    /// 匹配 JSON 格式的 Action Input
    static ref JSON_REGEX: Regex = Regex::new(r"\{[^{}]*\}").unwrap();
}

/// ReAct 解析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactParseResult {
    /// 思考内容
    pub thought: String,

    /// 操作名称
    pub action: Option<String>,

    /// 操作输入（JSON 格式）
    pub action_input: Option<serde_json::Value>,

    /// 原始输出
    pub raw_output: String,
}

/// ReAct 解析错误
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReactParseError {
    /// 无效的 Action Input JSON
    InvalidJson(String),

    /// 缺少必需的字段
    MissingField(String),

    /// 格式不正确
    InvalidFormat(String),
}

impl std::fmt::Display for ReactParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReactParseError::InvalidJson(msg) => write!(f, "Invalid JSON: {}", msg),
            ReactParseError::MissingField(field) => write!(f, "Missing field: {}", field),
            ReactParseError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for ReactParseError {}

/// 解析 LLM 输出为 ReAct 格式
pub fn parse_react_output(output: &str) -> Result<ReactParseResult, ReactParseError> {
    let mut thought = String::new();
    let mut action = None;
    let mut action_input = None;

    // 提取 Thought
    if let Some(caps) = THOUGHT_REGEX.captures(output) {
        if let Some(thought_match) = caps.get(1) {
            thought = thought_match.as_str().trim().to_string();
        }
    }

    // 如果没有找到 Thought，检查是否整个输出都是思考内容
    if thought.is_empty() && !output.contains("Action:") {
        thought = output.trim().to_string();
    }

    // 提取 Action
    if let Some(caps) = ACTION_REGEX.captures(output) {
        if let Some(action_match) = caps.get(1) {
            action = Some(action_match.as_str().trim().to_string());
        }
    }

    // 提取 Action Input
    if let Some(caps) = ACTION_INPUT_REGEX.captures(output) {
        if let Some(input_match) = caps.get(1) {
            let input_str = input_match.as_str().trim();

            // 尝试解析为 JSON
            if let Ok(json) = parse_action_input(input_str) {
                action_input = Some(json);
            } else {
                // 如果不是标准 JSON，尝试查找其中的 JSON 对象
                if let Some(json_match) = JSON_REGEX.find(input_str) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_match.as_str()) {
                        action_input = Some(json);
                    } else {
                        return Err(ReactParseError::InvalidJson(
                            format!("Could not parse JSON from: {}", input_str)
                        ));
                    }
                }
            }
        }
    }

    Ok(ReactParseResult {
        thought,
        action,
        action_input,
        raw_output: output.to_string(),
    })
}

/// 解析 Action Input
fn parse_action_input(input: &str) -> Result<serde_json::Value, String> {
    // 尝试直接解析为 JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(input) {
        return Ok(json);
    }

    // 尝试提取花括号内的内容
    let trimmed = input.trim();
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            let json_str = &trimmed[start..=end];
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
                return Ok(json);
            }
        }
    }

    // 尝试解析键值对格式
    if let Some(json) = parse_key_value_format(input) {
        return Ok(json);
    }

    Err("Invalid Action Input format".to_string())
}

/// 解析键值对格式
fn parse_key_value_format(input: &str) -> Option<serde_json::Value> {
    let mut obj = serde_json::Map::new();

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(colon_pos) = line.find(':') {
            let key = line[..colon_pos].trim().trim_matches('"').trim_matches('\'');
            let value = line[colon_pos + 1..].trim().trim_matches('"').trim_matches('\'');
            obj.insert(key.to_string(), serde_json::Value::String(value.to_string()));
        }
    }

    if obj.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(obj))
    }
}

/// 构建 ReAct 格式的提示词
pub fn build_react_prompt(system_prompt: &str, tools: &[&str]) -> String {
    let tools_list = if tools.is_empty() {
        "No tools available".to_string()
    } else {
        tools.iter()
            .map(|t| format!("- {}", t))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"{}

你可以使用以下工具:

{}

请按照以下格式回答:

Thought: 你的思考过程
Action: 工具名称
Action Input: {{"参数": "值"}}

或者如果不需要使用工具:

Thought: 你的思考过程
Action: finish
Action Input: {{"result": "最终答案"}}

Observation: 将被工具结果替换
"#,
        system_prompt, tools_list
    )
}

/// 检查是否完成了任务
pub fn is_finish_action(result: &ReactParseResult) -> bool {
    result.action.as_deref() == Some("finish") ||
    result.action.as_deref() == Some("Finish") ||
    result.action.as_deref() == Some("Final Answer")
}

/// 提取最终答案
pub fn extract_final_answer(result: &ReactParseResult) -> Option<String> {
    if is_finish_action(result) {
        if let Some(input) = &result.action_input {
            if let Some(result_val) = input.get("result") {
                if let Some(s) = result_val.as_str() {
                    return Some(s.to_string());
                }
                return Some(result_val.to_string());
            }
            if let Some(answer_val) = input.get("answer") {
                if let Some(s) = answer_val.as_str() {
                    return Some(s.to_string());
                }
                return Some(answer_val.to_string());
            }
            return Some(input.to_string());
        }
        Some(result.thought.clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_react_output_with_thought() {
        let output = r#"Thought: I need to search for the function definition
Action: search_code
Action Input: {"query": "def my_function"}"#;

        let result = parse_react_output(output).unwrap();
        assert_eq!(result.thought, "I need to search for the function definition");
        assert_eq!(result.action, Some("search_code".to_string()));
        assert!(result.action_input.is_some());
    }

    #[test]
    fn test_parse_react_output_simple() {
        let output = "This is my thinking about the problem";
        let result = parse_react_output(output).unwrap();
        assert_eq!(result.thought, "This is my thinking about the problem");
        assert!(result.action.is_none());
    }

    #[test]
    fn test_is_finish_action() {
        let result = ReactParseResult {
            thought: "I'm done".to_string(),
            action: Some("finish".to_string()),
            action_input: Some(serde_json::json!({"result": "Task completed"})),
            raw_output: String::new(),
        };
        assert!(is_finish_action(&result));
    }

    #[test]
    fn test_extract_final_answer() {
        let result = ReactParseResult {
            thought: "Task complete".to_string(),
            action: Some("finish".to_string()),
            action_input: Some(serde_json::json!({"result": "The answer is 42"})),
            raw_output: String::new(),
        };
        assert_eq!(extract_final_answer(&result), Some("The answer is 42".to_string()));
    }
}
