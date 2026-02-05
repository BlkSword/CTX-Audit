//! ReAct 解析器
//!
//! 解析 LLM 输出的 ReAct 格式（推理-行动循环）

use regex::Regex;
use serde::{Deserialize, Serialize};

/// ReAct 解析错误
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseError {
    /// 缺少 Thought
    #[error("缺少 Thought 字段")]
    MissingThought,

    /// 缺少 Action
    #[error("缺少 Action 字段")]
    MissingAction,

    /// 无效的 JSON 格式
    #[error("无效的 JSON 格式: {0}")]
    InvalidJson(String),

    /// 不支持的 Action
    #[error("不支持的 Action: {0}")]
    UnsupportedAction(String),

    /// 解析失败
    #[error("解析失败: {0}")]
    ParseFailed(String),
}

/// ReAct 步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactStep {
    /// 思考内容
    pub thought: String,

    /// 累计思考
    pub accumulated_thought: Option<String>,

    /// 行动名称
    pub action: String,

    /// 行动输入参数
    pub action_input: serde_json::Value,
}

impl ReactStep {
    /// 创建新步骤
    pub fn new(thought: String, action: String, action_input: serde_json::Value) -> Self {
        Self {
            thought,
            accumulated_thought: None,
            action,
            action_input,
        }
    }

    /// 设置累计思考
    pub fn with_accumulated(mut self, accumulated: String) -> Self {
        self.accumulated_thought = Some(accumulated);
        self
    }

    /// 是否是完成动作
    pub fn is_finish(&self) -> bool {
        self.action.to_lowercase() == "finish" || self.action.to_lowercase() == "final_answer"
    }

    /// 是否是工具调用
    pub fn is_tool_call(&self) -> bool {
        !self.is_finish()
    }

    /// 获取显示文本
    pub fn display(&self) -> String {
        format!(
            "Thought: {}\nAction: {}\nAction Input: {}",
            self.thought,
            self.action,
            serde_json::to_string_pretty(&self.action_input).unwrap_or_default()
        )
    }
}

/// ReAct 解析器
pub struct ReactParser;

impl ReactParser {
    /// 解析 LLM 响应为 ReAct 步骤
    ///
    /// 支持的格式：
    /// ```text
    /// Thought: <思考内容>
    /// Action: <动作名称>
    /// Action Input: <JSON 格式的输入参数>
    /// ```
    pub fn parse(response: &str) -> Result<ReactStep, ParseError> {
        // 1. 提取 Thought
        let thought = Self::extract_thought(response)?;

        // 2. 提取 Action
        let action = Self::extract_action(response)?;

        // 3. 提取 Action Input
        let action_input = Self::extract_action_input(response)?;

        Ok(ReactStep {
            thought,
            accumulated_thought: None,
            action,
            action_input,
        })
    }

    /// 使用累计思考解析
    pub fn parse_with_accumulated(
        response: &str,
        accumulated: &str,
    ) -> Result<ReactStep, ParseError> {
        let mut step = Self::parse(response)?;
        step.accumulated_thought = Some(format!("{}\n{}", accumulated, step.thought));
        Ok(step)
    }

    /// 提取 Thought
    fn extract_thought(text: &str) -> Result<String, ParseError> {
        // 尝试多种格式的正则
        let patterns = [
            r"Thought:\s*(.*?)(?=\n(?:Action|Observation|Final Answer)|$)",
            r"thought:\s*(.*?)(?=\n(?:action|observation|final)|$)",
            r"思考:\s*(.*?)(?=\n(?:行动|动作|观察)|$)",
        ];

        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(text) {
                    if let Some(thought) = caps.get(1) {
                        return Ok(thought.as_str().trim().to_string());
                    }
                }
            }
        }

        // 如果没有找到，尝试提取第一段非空文本
        let lines: Vec<&str> = text.lines().collect();
        for line in lines {
            let trimmed = line.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with("Action")
                && !trimmed.starts_with("action")
                && !trimmed.starts_with("Action Input")
                && !trimmed.starts_with("Final Answer")
            {
                return Ok(trimmed.to_string());
            }
        }

        Err(ParseError::MissingThought)
    }

    /// 提取 Action
    fn extract_action(text: &str) -> Result<String, ParseError> {
        let patterns = [
            r"Action:\s*([A-Za-z_][A-Za-z0-9_]*)",
            r"action:\s*([A-Za-z_][A-Za-z0-9_]*)",
            r"Action:\s*(.+?)(?:\n|$)",
            r"行动:\s*([A-Za-z_][A-Za-z0-9_]*)",
        ];

        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(text) {
                    if let Some(action) = caps.get(1) {
                        let action_str = action.as_str().trim().to_string();
                        if !action_str.is_empty() {
                            return Ok(action_str);
                        }
                    }
                }
            }
        }

        // 尝试查找 "Final Answer" 格式
        if text.contains("Final Answer:") || text.contains("final_answer:") {
            return Ok("finish".to_string());
        }

        Err(ParseError::MissingAction)
    }

    /// 提取 Action Input
    fn extract_action_input(text: &str) -> Result<serde_json::Value, ParseError> {
        let patterns = [
            r"Action Input:\s*(\{.*?\})(?=\n\n|\nThought|$)",
            r"action input:\s*(\{.*?\})(?=\n\n|\nThought|$)",
            r"Action Input:\s*(\[.*?\])(?=\n\n|\nThought|$)",
        ];

        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(caps) = re.captures(text) {
                    if let Some(input) = caps.get(1) {
                        let input_str = input.as_str();
                        // 尝试解析 JSON
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(input_str) {
                            return Ok(value);
                        }
                    }
                }
            }
        }

        // 如果是 finish 动作，没有参数也是可以的
        if text.contains("Final Answer:") || text.contains("final_answer:") {
            let patterns = [
                r"Final Answer:\s*(.+?)(?=\n\n|$)",
                r"final_answer:\s*(.+?)(?=\n\n|$)",
            ];
            for pattern in &patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if let Some(caps) = re.captures(text) {
                        if let Some(answer) = caps.get(1) {
                            return Ok(serde_json::json!({"answer": answer.as_str().trim()}));
                        }
                    }
                }
            }
            return Ok(serde_json::json!({}));
        }

        // 默认返回空对象
        Ok(serde_json::json!({}))
    }

    /// 检查响应是否包含完整的 ReAct 格式
    pub fn is_complete_react_format(text: &str) -> bool {
        Self::extract_thought(text).is_ok() && Self::extract_action(text).is_ok()
    }

    /// 从部分响应中提取可用的部分信息
    pub fn parse_partial(text: &str) -> Result<ReactStep, ParseError> {
        let thought = Self::extract_thought(text).unwrap_or_else(|_| "思考中...".to_string());

        let action = Self::extract_action(text)
            .unwrap_or_else(|_| "thinking".to_string());

        let action_input = Self::extract_action_input(text)
            .unwrap_or_else(|_| serde_json::json!({}));

        Ok(ReactStep {
            thought,
            accumulated_thought: None,
            action,
            action_input,
        })
    }

    /// 构建系统提示词
    pub fn build_system_prompt(available_tools: &[String]) -> String {
        let tools_list = available_tools
            .iter()
            .map(|t| format!("- {}", t))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"你是一个安全代码审计专家。使用 ReAct (推理-行动) 框架来分析代码并发现潜在的安全漏洞。

## 可用工具

{}

## ReAct 格式

请按以下格式回复：

```
Thought: <你的思考过程，分析当前情况和下一步计划>
Action: <工具名称或 "finish">
Action Input: <JSON 格式的工具输入参数>
```

## 指导原则

1. **Thought**: 详细说明你的推理过程
2. **Action**: 从可用工具中选择，或使用 "finish" 完成分析
3. **Action Input**: 严格的 JSON 格式

## 完成分析

当你完成分析后，使用：

```
Thought: <总结你的发现>
Action: finish
Action Input: {{"findings_count": <数量>, "summary": "<总结>"}}
```

## 安全漏洞类别

- SQL 注入
- XSS (跨站脚本)
- CSRF (跨站请求伪造)
- 命令注入
- 路径遍历
- 不安全的反序列化
- 敏感信息泄露
- 不安全的随机数
- 加密问题
- 访问控制问题
"#,
            tools_list
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_react_step() {
        let response = r#"Thought: 我需要先查看项目结构
Action: list_files
Action Input: {"path": "/src"}"#;

        let step = ReactParser::parse(response).unwrap();
        assert_eq!(step.action, "list_files");
        assert!(step.thought.contains("项目结构"));
    }

    #[test]
    fn test_parse_finish_action() {
        let response = r#"Thought: 我已经完成了分析
Action: finish
Action Input: {"findings_count": 3, "summary": "发现3个漏洞"}"#;

        let step = ReactParser::parse(response).unwrap();
        assert!(step.is_finish());
        assert_eq!(step.action, "finish");
    }

    #[test]
    fn test_extract_thought() {
        let text = "Thought: 这是一个思考内容\nAction: some_action";
        let thought = ReactParser::extract_thought(text).unwrap();
        assert_eq!(thought, "这是一个思考内容");
    }

    #[test]
    fn test_extract_action() {
        let text = "Thought: thinking\nAction: read_file";
        let action = ReactParser::extract_action(text).unwrap();
        assert_eq!(action, "read_file");
    }

    #[test]
    fn test_build_system_prompt() {
        let tools = vec!["read_file".to_string(), "search_code".to_string()];
        let prompt = ReactParser::build_system_prompt(&tools);
        assert!(prompt.contains("read_file"));
        assert!(prompt.contains("search_code"));
        assert!(prompt.contains("ReAct"));
    }
}
