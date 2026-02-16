// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 流式响应模型

use serde::{Deserialize, Serialize};

/// 流式响应块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMStreamChunk {
    /// 内容增量
    pub delta: String,

    /// 是否完成
    pub done: bool,

    /// 工具调用增量
    pub tool_call_delta: Option<ToolCallDelta>,

    /// 使用量统计
    pub usage: Option<Usage>,
}

/// 工具调用增量
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallDelta {
    /// 调用 ID
    pub id: Option<String>,

    /// 工具名称
    pub name: Option<String>,

    /// 输入增量
    pub input_delta: Option<String>,
}

/// 使用量统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// 输入 tokens
    pub input_tokens: u32,

    /// 输出 tokens
    pub output_tokens: u32,

    /// 总 tokens
    pub total_tokens: u32,
}

impl Usage {
    /// 获取总 tokens
    pub fn total_tokens(&self) -> u32 {
        self.total_tokens
    }
}
