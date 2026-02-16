// Copyright 2026 CTX-Audit
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

    /// 操作输入关键词正则
    action_input_regex: Regex,

    /// 工具调用正则
    tool_regex: Regex,

    /// JSON 提取正则（支持嵌套）
    json_regex: Regex,
}

/// 参数名映射 - 将常见变体映射到正确的参数名
fn normalize_action_input(tool_name: &str, input: &mut serde_json::Value) {
    if let Some(obj) = input.as_object_mut() {
        match tool_name {
            "search_symbol" | "text_search" => {
                // symbol -> query
                if let Some(symbol) = obj.remove("symbol") {
                    obj.entry("query".to_string()).or_insert(symbol);
                }
                // search -> query
                if let Some(search) = obj.remove("search") {
                    obj.entry("query".to_string()).or_insert(search);
                }
                // text -> query
                if let Some(text) = obj.remove("text") {
                    obj.entry("query".to_string()).or_insert(text);
                }
                // q -> query
                if let Some(q) = obj.remove("q") {
                    obj.entry("query".to_string()).or_insert(q);
                }
            }
            "read_file" | "get_file_structure" | "trace_taint" | "detect_vulnerability_patterns" => {
                // path -> file_path
                if let Some(path) = obj.remove("path") {
                    obj.entry("file_path".to_string()).or_insert(path);
                }
                // file -> file_path
                if let Some(file) = obj.remove("file") {
                    obj.entry("file_path".to_string()).or_insert(file);
                }
                // filename -> file_path
                if let Some(filename) = obj.remove("filename") {
                    obj.entry("file_path".to_string()).or_insert(filename);
                }
            }
            "find_references" => {
                // symbol -> symbol_name
                if let Some(symbol) = obj.remove("symbol") {
                    obj.entry("symbol_name".to_string()).or_insert(symbol);
                }
                // name -> symbol_name
                if let Some(name) = obj.remove("name") {
                    obj.entry("symbol_name".to_string()).or_insert(name);
                }
            }
            "get_call_graph" => {
                // function -> entry
                if let Some(func) = obj.remove("function") {
                    obj.entry("entry".to_string()).or_insert(func);
                }
                // func -> entry
                if let Some(func) = obj.remove("func") {
                    obj.entry("entry".to_string()).or_insert(func);
                }
                // name -> entry
                if let Some(name) = obj.remove("name") {
                    obj.entry("entry".to_string()).or_insert(name);
                }
            }
            "get_class_hierarchy" => {
                // class -> class_name
                if let Some(class) = obj.remove("class") {
                    obj.entry("class_name".to_string()).or_insert(class);
                }
                // name -> class_name
                if let Some(name) = obj.remove("name") {
                    obj.entry("class_name".to_string()).or_insert(name);
                }
            }
            "report_finding" => {
                // line -> line_number
                if let Some(line) = obj.remove("line") {
                    obj.entry("line_number".to_string()).or_insert(line);
                }
                // file -> file_path
                if let Some(file) = obj.remove("file") {
                    obj.entry("file_path".to_string()).or_insert(file);
                }
            }
            _ => {}
        }
    }
}

impl ReactParser {
    /// 创建新的解析器
    pub fn new() -> Self {
        Self {
            thought_regex: Regex::new(r"(?i)thought:|thinking:|思考:|分析:").unwrap(),
            action_regex: Regex::new(r"(?i)^action:|^操作:|^工具:").unwrap(),
            action_input_regex: Regex::new(r"(?i)^action\s*input:|^操作输入:|^参数:").unwrap(),
            tool_regex: Regex::new(r"(?i)([a-z_]+)\(").unwrap(),
            // 改进的 JSON 正则，支持多层嵌套
            json_regex: Regex::new(r"\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}").unwrap(),
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
        let mut action_input_buffer = String::new();

        for line in &lines {
            let trimmed_line = line.trim();

            // 检测章节切换
            if self.thought_regex.is_match(trimmed_line) {
                current_section = "thought";
                reasoning.push(trimmed_line.to_string());
                // 提取 thought 后的内容
                if let Some(pos) = trimmed_line.find(':') {
                    let content = trimmed_line[pos + 1..].trim();
                    if !content.is_empty() {
                        thought.push_str(content);
                        thought.push(' ');
                    }
                }
                continue;
            } else if self.action_input_regex.is_match(trimmed_line) {
                // 检测 Action Input 行
                current_section = "action_input";
                reasoning.push(trimmed_line.to_string());
                // 提取 Action Input 后的 JSON
                if let Some(pos) = trimmed_line.find(':') {
                    let content = trimmed_line[pos + 1..].trim();
                    if !content.is_empty() {
                        action_input_buffer.push_str(content);
                    }
                }
                continue;
            } else if self.action_regex.is_match(trimmed_line) {
                current_section = "action";
                reasoning.push(trimmed_line.to_string());
                // 提取 action 后的内容（如 "Action: search_symbol" 中的 "search_symbol"）
                if let Some(pos) = trimmed_line.find(':') {
                    let content = trimmed_line[pos + 1..].trim();
                    if !content.is_empty() {
                        action_buffer.push_str(content);
                        action_buffer.push(' ');
                    }
                }
                continue;
            }

            match current_section {
                "thought" => {
                    if !trimmed_line.is_empty() {
                        thought.push_str(trimmed_line);
                        thought.push(' ');
                    }
                }
                "action" => {
                    action_buffer.push_str(trimmed_line);
                    action_buffer.push(' ');
                }
                "action_input" => {
                    action_input_buffer.push_str(trimmed_line);
                }
                _ => {}
            }
        }

        // 首先尝试从 action_input_buffer 解析 JSON
        if !action_input_buffer.is_empty() {
            if let Some(json_caps) = self.json_regex.captures(&action_input_buffer) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_caps.get(0).unwrap().as_str()) {
                    action_input = Some(json);
                }
            }
        }

        // 如果 action_input_buffer 中没有找到 JSON，尝试从 action_buffer 中找
        if action_input.is_none() && !action_buffer.is_empty() {
            if let Some(json_caps) = self.json_regex.captures(&action_buffer) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_caps.get(0).unwrap().as_str()) {
                    action_input = Some(json);
                }
            }
        }

        // 解析操作
        if !action_buffer.is_empty() {
            let action_lower = action_buffer.to_lowercase();

            // 先检查特殊操作类型
            if action_lower.contains("answer") || action_lower.contains("回答") {
                action_type = ActionType::Answer;
                should_continue = false;
            } else if action_lower.contains("finish") || action_lower.contains("完成") {
                action_type = ActionType::Finish;
                should_continue = false;
            } else if action_lower.contains("error") || action_lower.contains("错误") {
                action_type = ActionType::Error;
                should_continue = false;
            } else {
                // 尝试提取工具名
                // 支持两种格式：
                // 1. tool_name(args) - 带括号的格式
                // 2. tool_name - 不带括号的格式
                if let Some(caps) = self.tool_regex.captures(&action_buffer) {
                    // 带括号的格式
                    action_name = Some(caps.get(1).unwrap().as_str().to_string());
                    action_type = ActionType::UseTool;
                } else {
                    // 尝试匹配不带括号的工具名（仅包含字母、下划线和连字符）
                    let tool_name_regex = Regex::new(r"(?i)\b([a-z][a-z0-9_-]*)\b").unwrap();
                    if let Some(caps) = tool_name_regex.captures(&action_buffer) {
                        let name = caps.get(1).unwrap().as_str().to_string();
                        // 排除常见的非工具关键词
                        let exclude_words = ["the", "a", "an", "is", "are", "was", "were", "be", "been",
                            "being", "have", "has", "had", "do", "does", "did", "will", "would",
                            "could", "should", "may", "might", "must", "shall", "can", "need",
                            "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
                            "into", "through", "during", "before", "after", "above", "below",
                            "between", "under", "again", "further", "then", "once", "here",
                            "there", "when", "where", "why", "how", "all", "each", "few",
                            "more", "most", "other", "some", "such", "no", "nor", "not",
                            "only", "own", "same", "so", "than", "too", "very", "just",
                            "and", "but", "if", "or", "because", "until", "while", "this",
                            "that", "these", "those", "it", "its", "they", "them", "their",
                            "we", "us", "our", "you", "your", "he", "him", "his", "she",
                            "her", "i", "me", "my"];
                        if !exclude_words.contains(&name.to_lowercase().as_str()) {
                            action_name = Some(name);
                            action_type = ActionType::UseTool;
                        }
                    }
                }
            }
        }

        // 在工具名确定后，再次对 action_input 应用参数名规范化
        if let (Some(ref tool_name), Some(ref mut input)) = (&action_name, &mut action_input) {
            normalize_action_input(tool_name, input);
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

    /// 格式化提示词模板（专业化安全审计版本）
    pub fn format_prompt_template(&self, context: &str, available_tools: &[String]) -> String {
        // 构建详细的工具列表，包含参数说明
        let tools_help = self.build_tools_help(available_tools);

        format!(
            r#"你是一个专业的代码安全审计系统。请按照以下方法论进行安全审计：

## 审计方法论

### 阶段 1: 信息收集
1. 使用 `list_files` 了解项目结构
2. 使用 `text_search` 搜索敏感关键词（password, token, api_key, secret 等）
3. 使用 `get_file_structure` 分析关键文件的结构

### 阶段 2: 污点分析（关键！）
**优先使用确定性分析工具**：
1. 使用 `trace_taint` 对用户输入进行污点追踪
   - 识别污点源：HTTP 参数、文件输入、环境变量、命令行参数
   - 识别污点汇：SQL 执行、命令执行、文件操作、网络请求
2. 使用 `detect_vulnerability_patterns` 进行模式匹配
3. 验证漏洞时必须提供完整的污点传播路径

### 阶段 3: 深度分析
1. 使用 `read_file` 读取可疑代码
2. 使用 `find_references` 追踪函数调用链
3. 使用 `get_call_graph` 分析调用关系

### 阶段 4: 报告
1. 使用 `report_finding` 报告漏洞，必须包含：
   - 完整的污点传播路径（source → propagation → sink）
   - 置信度评估
   - CWE 编号
2. 使用 `finish_analysis` 完成审计

## 重要原则

- **优先使用确定性工具**: 先用 trace_taint 和 detect_vulnerability_patterns，再用 LLM 推理
- **提供证据**: 每个漏洞报告必须包含传播路径和代码位置
- **避免误报**: 只有污点流明确存在时才报告漏洞
- **标注置信度**: 根据分析深度标注置信度（高/中/低）

当前上下文:
{}
{}

请使用以下格式回答：

Thought: [你的思考过程，说明你正在哪个阶段，分析目标是什么]
Action: [工具名称] 或 "Answer" (回答用户) 或 "Finish" (完成任务)
Action Input: {{"参数名": "参数值"}}

重要提示：
- 必须严格按照工具定义的参数名传递参数
- 参数名和值都必须使用双引号
- JSON 必须是有效的格式
- 文件路径必须是相对路径（相对于项目根目录），不要使用绝对路径
- 优先使用 trace_taint 和 detect_vulnerability_patterns 进行确定性分析

例如：
Thought: 阶段2 - 污点分析。我需要检查这个文件中的用户输入是否安全到达敏感函数
Action: trace_taint
Action Input: {{"file_path": "src/handlers/user.py", "vulnerability_types": ["sql_injection", "command_injection"]}}

或者：
Thought: 阶段2 - 模式检测。快速扫描文件中的常见漏洞模式
Action: detect_vulnerability_patterns
Action Input: {{"file_path": "src/api/auth.js"}}

或者：
Thought: 阶段4 - 报告。发现了一个 SQL 注入漏洞，需要报告
Action: report_finding
Action Input: {{"title": "SQL注入漏洞", "description": "用户输入直接拼接到SQL查询中，可通过id参数注入恶意SQL", "severity": "high", "file_path": "src/handlers/user.py", "line_number": 42, "category": "sql_injection"}}
"#,
            context,
            tools_help
        )
    }

    /// 构建工具帮助信息（包含新的专业分析工具）
    fn build_tools_help(&self, available_tools: &[String]) -> String {
        let mut help = String::from("可用工具:\n");

        for tool in available_tools {
            let tool_help = match tool.as_str() {
                // 专业分析工具（优先级最高）
                "trace_taint" => {
                    "  - trace_taint: [推荐] 执行污点分析，追踪用户输入到危险函数的数据流\n    参数: file_path (必需, 相对路径), vulnerability_types (可选, 漏洞类型数组)\n    示例: {\"file_path\": \"src/api.py\", \"vulnerability_types\": [\"sql_injection\", \"command_injection\"]}"
                }
                "detect_vulnerability_patterns" => {
                    "  - detect_vulnerability_patterns: [推荐] 使用预定义模式检测常见漏洞\n    参数: file_path (必需, 相对路径), categories (可选, 漏洞类别数组)\n    示例: {\"file_path\": \"src/auth.js\"}"
                }
                "global_taint_analysis" => {
                    "  - global_taint_analysis: 对整个项目执行污点分析\n    参数: path (可选, 目录路径), file_pattern (可选, 文件模式)\n    示例: {\"path\": \"src\", \"file_pattern\": \"*.py\"}"
                }
                "batch_pattern_scan" => {
                    "  - batch_pattern_scan: 批量模式扫描\n    参数: path (可选, 目录路径), file_pattern (可选, 文件模式)\n    示例: {\"path\": \"src\"}"
                }
                // 文件操作工具
                "read_file" => {
                    "  - read_file: 读取文件内容\n    参数: file_path (必需, 相对路径如 \"src/main.rs\"), start_line (可选), end_line (可选)\n    示例: {\"file_path\": \"src/main.rs\"}"
                }
                "list_files" => {
                    "  - list_files: 列出目录文件\n    参数: path (可选, 相对路径如 \"src\"), pattern (可选)\n    示例: {\"path\": \"src\"}"
                }
                // 搜索工具
                "search_symbol" => {
                    "  - search_symbol: 搜索符号定义（需要项目已索引）\n    参数: query (必需, 搜索词), limit (可选)\n    示例: {\"query\": \"login\"}"
                }
                "text_search" => {
                    "  - text_search: 文本搜索（推荐使用）\n    参数: query (必需, 搜索文本), path (可选), file_pattern (可选)\n    示例: {\"query\": \"password\"}"
                }
                "regex_search" => {
                    "  - regex_search: 正则搜索\n    参数: pattern (必需, 正则表达式), path (可选)\n    示例: {\"pattern\": \"func.*login\"}"
                }
                // AST 工具
                "get_file_structure" => {
                    "  - get_file_structure: 获取文件结构\n    参数: file_path (必需, 相对路径)\n    示例: {\"file_path\": \"src/main.rs\"}"
                }
                "find_references" => {
                    "  - find_references: 查找引用\n    参数: symbol_name (必需)\n    示例: {\"symbol_name\": \"login\"}"
                }
                "get_call_graph" => {
                    "  - get_call_graph: 获取调用图\n    参数: entry (必需), max_depth (可选)\n    示例: {\"entry\": \"main\"}"
                }
                "get_class_hierarchy" => {
                    "  - get_class_hierarchy: 获取类层次\n    参数: class_name (必需)\n    示例: {\"class_name\": \"User\"}"
                }
                // 报告工具
                "report_finding" => {
                    "  - report_finding: 报告漏洞发现\n    参数: title (必需), description (必需), severity (critical/high/medium/low), file_path (相对路径), line_number (行号), category (可选, 漏洞类型)\n    示例: {\"title\": \"SQL注入漏洞\", \"description\": \"用户输入直接拼接到SQL查询\", \"severity\": \"high\", \"file_path\": \"src/db.py\", \"line_number\": 42, \"category\": \"sql_injection\"}"
                }
                "finish_analysis" => {
                    "  - finish_analysis: 完成分析\n    参数: summary (必需), findings_count (可选)\n    示例: {\"summary\": \"分析完成\"}"
                }
                "index_project" => {
                    "  - index_project: 索引项目（自动执行，通常无需手动调用）\n    参数: 无\n    示例: {}"
                }
                _ => {
                    &format!("  - {}", tool)
                }
            };
            help.push_str(tool_help);
            help.push('\n');
        }

        help
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
        // 验证参数名规范化: symbol -> query
        let input = result.action_input.unwrap();
        assert_eq!(input.get("query").and_then(|v| v.as_str()), Some("login"));
        assert!(input.get("symbol").is_none(), "symbol should be normalized to query");
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

    #[test]
    fn test_normalize_search_symbol_params() {
        let parser = ReactParser::new();

        // 测试 symbol -> query
        let output = r#"
Thought: 搜索函数
Action: search_symbol
Action Input: {"symbol": "login"}
"#;
        let result = parser.parse(output);
        assert_eq!(result.action_input.unwrap().get("query").unwrap().as_str().unwrap(), "login");

        // 测试 text -> query
        let output = r#"
Thought: 搜索文本
Action: text_search
Action Input: {"text": "password"}
"#;
        let result = parser.parse(output);
        assert_eq!(result.action_input.unwrap().get("query").unwrap().as_str().unwrap(), "password");
    }

    #[test]
    fn test_normalize_read_file_params() {
        let parser = ReactParser::new();

        // 测试 file -> file_path
        let output = r#"
Thought: 读取文件
Action: read_file
Action Input: {"file": "src/main.rs"}
"#;
        let result = parser.parse(output);
        assert_eq!(result.action_input.unwrap().get("file_path").unwrap().as_str().unwrap(), "src/main.rs");

        // 测试 path -> file_path
        let output = r#"
Thought: 读取文件
Action: read_file
Action Input: {"path": "src/lib.rs"}
"#;
        let result = parser.parse(output);
        assert_eq!(result.action_input.unwrap().get("file_path").unwrap().as_str().unwrap(), "src/lib.rs");
    }

    #[test]
    fn test_normalize_find_references_params() {
        let parser = ReactParser::new();

        let output = r#"
Thought: 查找引用
Action: find_references
Action Input: {"symbol": "login"}
"#;
        let result = parser.parse(output);
        assert_eq!(result.action_input.unwrap().get("symbol_name").unwrap().as_str().unwrap(), "login");
    }

    #[test]
    fn test_normalize_trace_taint_params() {
        let parser = ReactParser::new();

        // 测试 trace_taint 工具的 path -> file_path 规范化
        let output = r#"
Thought: 污点分析
Action: trace_taint
Action Input: {"path": "src/api.py"}
"#;
        let result = parser.parse(output);
        assert_eq!(result.action_input.unwrap().get("file_path").unwrap().as_str().unwrap(), "src/api.py");
    }
}
