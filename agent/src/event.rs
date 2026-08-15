// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 事件流
//!
//! 主循环产出的统一事件枚举，CLI 人性化渲染 / NDJSON / 日志等 sink 共用。

use serde::{Deserialize, Serialize};

/// Agent 事件
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    /// 文本增量（assistant content delta）
    Text {
        /// 增量文本
        delta: String,
    },

    /// 思考过程增量（reasoning_content，如 deepseek-reasoner）
    Thinking {
        /// 增量文本
        delta: String,
    },

    /// 工具调用请求（模型发起）
    ToolCallRequest {
        /// 调用 ID
        id: String,
        /// 工具名
        name: String,
        /// 参数（JSON 字符串）
        arguments: String,
    },

    /// 工具执行结果
    ToolResult {
        /// 调用 ID
        id: String,
        /// 工具名
        name: String,
        /// 输出文本（已截断）
        output: String,
        /// 是否错误
        is_error: bool,
    },

    /// 一轮结束（一轮 = 一次 LLM 调用 + 其工具调用执行）
    RoundFinish {
        /// 轮次号（从 1 开始）
        round: usize,
        /// 本轮 token 用量
        prompt_tokens: u64,
        /// 本轮 completion token 数
        completion_tokens: u64,
        /// 累计 token 数
        total_tokens: u64,
    },

    /// 错误事件
    Error {
        /// 错误信息
        message: String,
    },

    /// 检测到 doom loop（连续重复同名同参工具调用）
    LoopDetected {
        /// 重复调用的工具名
        tool_name: String,
        /// 重复次数
        count: usize,
    },

    /// 预算耗尽熔断
    BudgetExceeded {
        /// 触发原因
        reason: String,
    },
}
