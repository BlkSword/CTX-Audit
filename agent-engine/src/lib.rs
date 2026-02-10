// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit Agent Engine
//!
//! Multi-agent 系统实现，支持 Orchestrator、Recon、Analysis、Verification Agent

pub mod agents;
pub mod base;
pub mod graph_controller;
pub mod llm_integration;
pub mod message_bus;
pub mod mod_file;
pub mod react;
pub mod react_parser;
pub mod registry;
pub mod state;

// 重新导出常用类型
pub use base::{Agent, AgentContext, AgentConfig, AgentResult, AgentType, AgentStatus};
pub use base::{ExecutionStats, ThoughtEntry, ToolCallRecord, LLMConfig};
pub use state::AgentState;
pub use registry::AgentRegistry;

/// Agent 引擎版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
