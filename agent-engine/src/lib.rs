// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit Agent Engine
//!
//! Multi-agent 系统实现，支持 Orchestrator、Recon、Analysis、Verification Agent

pub mod agents;
pub mod base;
pub mod fix;
pub mod graph_controller;
pub mod llm_integration;
pub mod message_bus;
pub mod mod_file;
pub mod poc;
pub mod react;
pub mod react_agent;
pub mod react_parser;
pub mod registry;
pub mod state;
pub mod context;

// 重新导出常用类型
pub use base::{Agent, AgentContext, AgentConfig, AgentResult, AgentType, AgentStatus};
pub use base::{ExecutionStats, ThoughtEntry, ToolCallRecord, LLMConfig};
pub use state::AgentState;
pub use registry::AgentRegistry;
pub use react::executor::{ExecutionEvent, ExecutionConfig, ReactExecutor};
pub use react_agent::{
    ReactAgentWrapper, AgentPrompts,
    create_orchestrator_agent, create_recon_agent,
    create_analysis_agent, create_verification_agent,
};

// 上下文管理
pub use context::{RAGRetriever, RAGContext, IndexStats};

// 修复生成
pub use fix::{RepairGenerator, RepairSuggestion, RepairStrategy, RepairTemplateLibrary};

// PoC 生成
pub use poc::{PoCGenerator, PoCResult, PoCTemplateLibrary, PoCContext};

/// Agent 引擎版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
