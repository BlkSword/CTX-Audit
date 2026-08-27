// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit 原生 Agent（M1 最小闭环）
//!
//! 消息驱动主循环 + OpenAI-compatible provider + 工具适配 + JSONL 会话。
//! 分层导出：按消费者角色分组，同时保留顶层 re-export 兼容。

pub use pipeline::{ExtraJudgePhase, JudgeConfig, OutputContract, PipelineConfig, PipelineError, RegistrationConfig, ScanConfig};
pub mod agent;
pub mod confirm;
pub mod cron;
pub mod event;
pub mod feedback;
pub mod gate;
pub mod pipeline;
pub mod provider;
pub mod runner;
pub mod session;
pub mod subagent;
pub mod tool_adapter;

/// 主循环层：Agent、预算、错误类型
pub mod agent_loop {
    pub use crate::agent::{Agent, AgentBudget, AgentError, AgentRunResult};
    pub use crate::confirm::{ApprovalMode, ToolGate};
    pub use crate::event::AgentEvent;
}

/// provider 层：LLM 抽象与 OpenAI-compatible 实现
pub mod providers {
    pub use crate::provider::{
        ChatMessage, ChatRequest, ChatResponse, LLMProvider, OpenAIProvider, OpenAIProviderConfig,
        ProviderError, ToolCall, Usage,
    };
}

/// 工具适配层：ToolDefinition → function-calling schema + 执行
pub mod tooling {
    pub use crate::tool_adapter::{to_openai_tool, tools_schema, ToolAdapter, ToolOutput};
}

/// 会话层：append-only JSONL 存储与重放
pub mod sessions {
    pub use crate::session::{Session, SessionInfo, SessionRecord};
}

/// 轮状态机层（M2）：runner 六阶段 + human gate
pub mod rounds {
    pub use crate::gate::{extract_tp_candidates, GateDecision, GateNotice, TpCandidate};
    pub use crate::runner::{
        EligibilityReport, RoundPhase, Runner, RunnerConfig, RunnerError, RunnerState, TargetInfo,
    };
}

/// 定时调度层（M3）：cron 表达式、任务存储、调度器
pub mod scheduling {
    pub use crate::cron::{
        CronJob, CronParseError, CronSchedule, CronScheduler, CronStore, RoundLauncher,
    };
}

/// 子 agent 层（M4）：spawn 工厂、delegate 工具
pub mod delegation {
    pub use crate::subagent::{
        register_delegate_tool, DelegateTool, SubAgentConfig, SubAgentSpawner, DELEGATE_TOOL_NAME,
    };
}

/// 反哺机械层（M4）：CVE 回放任务与报告
pub mod replay {
    pub use crate::feedback::{
        report_path, run_replay, ExpectedHit, FeedbackError, FeedbackTask, RefScanSummary,
        RegressionStats, ReplayReport, SimpleFinding, Verdict,
    };
}

// 顶层 re-export，兼容扁平使用
pub use agent::{Agent, AgentBudget, AgentError, AgentRunResult};
pub use confirm::{ApprovalMode, ToolGate};
pub use event::AgentEvent;
pub use feedback::{FeedbackError, FeedbackTask, ReplayReport};
pub use gate::{GateDecision, GateNotice, TpCandidate};
pub use provider::{
    ChatMessage, ChatRequest, ChatResponse, LLMProvider, OpenAIProvider, OpenAIProviderConfig,
    ProviderError, ToolCall, Usage,
};
pub use runner::{RoundPhase, Runner, RunnerConfig, RunnerError, RunnerState};
pub use session::{Session, SessionInfo, SessionRecord};
pub use subagent::{SubAgentConfig, SubAgentSpawner};
pub use tool_adapter::{to_openai_tool, tools_schema, ToolAdapter, ToolOutput};
