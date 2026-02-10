// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct 循环解析器
//!
//! 解析 LLM 输出中的 Thought、Action、Action Input

use serde::{Deserialize, Serialize};

/// ReAct 解析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactParseResult {
    /// 思考内容
    pub thought: String,

    /// 操作名称
    pub action: Option<String>,

    /// 操作输入（JSON 格式）
    pub action_input: Option<serde_json::Value>,
}

/// 解析 LLM 输出为 ReAct 格式
pub fn parse_react_output(output: &str) -> ReactParseResult {
    let mut thought = String::new();
    let mut action = None;
    let mut action_input = None;

    // 简单解析实现
    // TODO: 实现完整的 ReAct 格式解析
    thought = output.to_string();

    ReactParseResult {
        thought,
        action,
        action_input,
    }
}
