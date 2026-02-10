// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 图控制器
//!
//! 管理 Agent 之间的依赖关系和执行顺序

use std::collections::HashMap;
use std::sync::Arc;

use crate::base::{Agent, AgentContext, AgentResult};

/// Agent 图控制器
pub struct AgentGraphController {
    agents: HashMap<String, Arc<dyn Agent>>,
}

impl AgentGraphController {
    /// 创建新的控制器
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    /// 添加 Agent
    pub fn add_agent(&mut self, agent: Arc<dyn Agent>) {
        let id = agent.agent_id().to_string();
        self.agents.insert(id, agent);
    }

    /// 获取 Agent
    pub fn get_agent(&self, id: &str) -> Option<Arc<dyn Agent>> {
        self.agents.get(id).cloned()
    }

    /// 执行 Agent
    pub async fn execute_agent(&self, id: &str, context: AgentContext) -> anyhow::Result<AgentResult> {
        let agent = self.get_agent(id)
            .ok_or_else(|| anyhow::anyhow!("Agent not found: {}", id))?;

        Ok(agent.execute(context).await)
    }
}

impl Default for AgentGraphController {
    fn default() -> Self {
        Self::new()
    }
}
