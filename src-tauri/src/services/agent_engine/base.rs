//! Agent trait 定义

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::{
    agent::{AgentConfig, AgentContext, AgentResult, AgentType, AgentStatus},
    events::{AgentEvent, EventType},
};

use crate::services::llm::LLMClient;

/// Agent 基础 trait
#[async_trait]
pub trait Agent: Send + Sync {
    /// 获取 Agent 类型
    fn agent_type(&self) -> AgentType;

    /// 获取 Agent ID
    fn agent_id(&self) -> &str;

    /// 获取 Agent 配置
    fn config(&self) -> &AgentConfig;

    /// 标准执行流程
    async fn run(&self, context: AgentContext) -> AgentResult {
        // 发射开始事件
        self.emit_event(
            &context.audit_id,
            EventType::AgentStarted,
            Some(format!("Agent {} 开始执行", self.agent_id())),
        )
        .await;

        // 执行核心逻辑
        let result = self.execute(context.clone()).await;

        // 根据结果发射完成或失败事件
        match result.status {
            AgentStatus::Completed => {
                self.emit_event(
                    &context.audit_id,
                    EventType::AgentCompleted,
                    Some(format!("Agent {} 执行完成", self.agent_id())),
                )
                .await;
            }
            AgentStatus::Failed => {
                self.emit_event(
                    &context.audit_id,
                    EventType::AgentFailed,
                    Some(format!(
                        "Agent {} 执行失败: {}",
                        self.agent_id(),
                        result.error.as_deref().unwrap_or("未知错误")
                    )),
                )
                .await;
            }
            _ => {}
        }

        result
    }

    /// 核心执行逻辑（由具体 Agent 实现）
    async fn execute(&self, context: AgentContext) -> AgentResult;

    /// 发射事件
    async fn emit_event(
        &self,
        audit_id: &str,
        event_type: EventType,
        message: Option<String>,
    ) {
        // 这里会通过事件总线发射
        // 暂时使用日志输出
        tracing::info!(
            "[{}] {:?}: {}",
            audit_id,
            event_type,
            message.unwrap_or_default()
        );
    }
}

/// ReAct Agent trait
///
/// 实现推理-行动循环的 Agent
#[async_trait]
pub trait ReactAgent: Agent {
    /// 执行 ReAct 循环
    async fn react_loop(
        &self,
        context: AgentContext,
        system_prompt: &str,
        max_iterations: usize,
    ) -> AgentResult {
        let agent_id = self.agent_id().to_string();
        let start_time = chrono::Utc::now();
        let mut findings = Vec::new();
        let mut thought_chain = Vec::new();
        let mut tool_calls = Vec::new();
        let mut total_tokens = 0;
        let mut llm_calls = 0;

        // 初始消息
        let initial_message = format!(
            "开始审计项目: {}\n项目路径: {}\n请使用 ReAct 方法进行分析。",
            context.project_id, context.project_path
        );

        // 这里需要 LLM 客户端和工具执行器
        // 暂时返回基本结果
        let result = AgentResult {
            agent_id: agent_id.clone(),
            agent_type: self.agent_type(),
            status: AgentStatus::Completed,
            message: Some("ReAct 循环执行完成".to_string()),
            findings,
            thought_chain,
            tool_calls,
            stats: crate::models::agent::ExecutionStats {
                total_iterations: 0,
                total_tool_calls: 0,
                total_tokens,
                total_duration_ms: (chrono::Utc::now() - start_time).num_milliseconds() as u64,
                llm_calls,
            },
            error: None,
            completed_at: chrono::Utc::now(),
        };

        result
    }
}

/// Agent 执行器
///
/// 负责管理 Agent 的生命周期和执行
pub struct AgentExecutor {
    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 配置
    config: AgentConfig,
}

impl AgentExecutor {
    /// 创建新的执行器
    pub fn new(llm: Arc<dyn LLMClient>, config: AgentConfig) -> Self {
        Self { llm, config }
    }

    /// 执行 Agent
    pub async fn execute(&self, agent: Arc<dyn Agent>, context: AgentContext) -> AgentResult {
        agent.run(context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 测试用实现
    struct TestAgent {
        id: String,
        config: AgentConfig,
    }

    #[async_trait]
    impl Agent for TestAgent {
        fn agent_type(&self) -> AgentType {
            AgentType::Analysis
        }

        fn agent_id(&self) -> &str {
            &self.id
        }

        fn config(&self) -> &AgentConfig {
            &self.config
        }

        async fn execute(&self, _context: AgentContext) -> AgentResult {
            AgentResult {
                agent_id: self.id.clone(),
                agent_type: AgentType::Analysis,
                status: AgentStatus::Completed,
                message: Some("Test complete".to_string()),
                findings: Vec::new(),
                thought_chain: Vec::new(),
                tool_calls: Vec::new(),
                stats: crate::models::agent::ExecutionStats::default(),
                error: None,
                completed_at: chrono::Utc::now(),
            }
        }
    }
}
