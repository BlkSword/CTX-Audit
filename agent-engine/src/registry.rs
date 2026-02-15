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

    /// 创建 Agent 实例（使用 ReAct 执行器）
    pub fn create_agent(
        &self,
        agent_type: AgentType,
        config: AgentConfig,
    ) -> anyhow::Result<Arc<dyn Agent>> {
        // 使用 ReactAgentWrapper 创建真正执行 ReAct 循环的 Agent
        Ok(crate::react_agent::create_agent_with_type(
            agent_type,
            config,
            self.llm.clone(),
            self.tool_registry.clone(),
        ))
    }

    /// 创建带自定义提示词的 Agent
    pub fn create_agent_with_prompt(
        &self,
        agent_type: AgentType,
        config: AgentConfig,
        custom_prompt: String,
    ) -> anyhow::Result<Arc<dyn Agent>> {
        Ok(crate::react_agent::create_agent_with_custom_prompt(
            agent_type,
            config,
            self.llm.clone(),
            self.tool_registry.clone(),
            custom_prompt,
        ))
    }
}
