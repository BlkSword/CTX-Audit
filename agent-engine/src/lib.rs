// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit Agent Engine
//!
//! 专业安全审计框架，实现阶段化、目标导向的审计流程

pub mod base;
pub mod fix;
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

// 新模块
pub mod audit_state;
pub mod prescan;
pub mod phase_executor;
pub mod task_scheduler;
pub mod audit_prompts;
pub mod audit_chain;
pub mod tool_recommender;

// 多 Agent 系统
pub mod multi_agent;

// 语义理解引擎
pub mod semantic;

// 业务逻辑分析
pub mod analysis;

// 双重验证系统
pub mod verification;

// 确定性审计
pub mod deterministic;

// 重新导出常用类型
pub use base::{Agent, AgentContext, AgentConfig, AgentResult, AgentType, AgentStatus};
pub use base::{ExecutionStats, ThoughtEntry, ToolCallRecord, LLMConfig};
pub use state::AgentState;
pub use registry::AgentRegistry;
pub use react::executor::{ExecutionEvent, ExecutionConfig, ReactExecutor};
pub use react_agent::{
    ReactAgentWrapper, AgentPrompts,
    create_agent_with_type, create_agent_with_custom_prompt,
};

// 新模块导出
pub use audit_state::{
    SecurityAuditState, AuditPhase, AnalysisTarget, TargetPriority, TargetType,
    TargetStatus, VulnerabilityCandidate, VerificationStatus, ProjectInfo,
};
pub use prescan::{DeterministicPrescanner, PrescanConfig, PrescanResult, ProjectInfoCollector};
pub use phase_executor::{PhaseAwareExecutor, PhaseResult};
pub use task_scheduler::{TaskScheduler, ScheduledTask, TaskStatus};
pub use audit_prompts::AuditPrompts;

// 上下文管理
pub use context::{RAGRetriever, RAGContext, IndexStats};

// 修复生成
pub use fix::{RepairGenerator, RepairSuggestion, RepairStrategy, RepairTemplateLibrary};

// PoC 生成
pub use poc::{PoCGenerator, PoCResult, PoCTemplateLibrary, PoCContext};

// 审计思维链
pub use audit_chain::{
    SecurityAuditChain, AuditThinkingPhase, VulnerabilityHypothesis, HypothesisStatus,
    Evidence, EvidenceType, VerificationResult, VulnerabilityType, Severity,
    CodeLocation, DataFlowStep, DataFlowStepType,
};

// 工具推荐
pub use tool_recommender::{ToolRecommender, ToolRecommendation, ToolCombo};

/// Agent 引擎版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
