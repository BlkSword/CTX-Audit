// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 注册表
//!
//! 管理所有可用的 Agent 类型

use crate::base::{Agent, AgentType, AgentConfig};
use std::sync::Arc;
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::ToolRegistry;

/// Agent 注册表
pub struct AgentRegistry {
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
}

impl AgentRegistry {
    /// 创建新的注册表
    pub fn new(llm: Arc<dyn LLMClient>, tool_registry: Arc<ToolRegistry>) -> Self {
        Self { llm, tool_registry }
    }

    /// 创建 Agent 实例
    pub fn create_agent(
        &self,
        agent_type: AgentType,
        config: AgentConfig,
    ) -> anyhow::Result<Arc<dyn Agent>> {
        match agent_type {
            AgentType::Orchestrator => Ok(Arc::new(crate::agents::OrchestratorAgent::new(
                config,
                self.llm.clone(),
                self.tool_registry.clone(),
            ))),
            AgentType::Recon => Ok(Arc::new(crate::agents::ReconAgent::new(
                config,
                self.llm.clone(),
                self.tool_registry.clone(),
            ))),
            AgentType::Analysis => Ok(Arc::new(crate::agents::AnalysisAgent::new(
                config,
                self.llm.clone(),
                self.tool_registry.clone(),
            ))),
            AgentType::Verification => Ok(Arc::new(crate::agents::VerificationAgent::new(
                config,
                self.llm.clone(),
                self.tool_registry.clone(),
            ))),
        }
    }
}
