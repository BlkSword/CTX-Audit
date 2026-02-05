//! 具体 Agent 实现
//!
//! 实现 Orchestrator, Recon, Analysis, Verification Agent

use async_trait::async_trait;
use std::sync::Arc;

use crate::models::agent::{AgentConfig, AgentContext, AgentResult, AgentType};
use crate::services::agent_engine::{Agent, ReactAgent};
use crate::services::agent_engine::state::{AgentState, AgentStateHandle, IterationController};
use crate::services::llm::LLMClient;
use crate::services::agent_engine::ReactParser;

/// Orchestrator Agent - 编排器
///
/// 负责协调整个审计流程，管理子 Agent，汇总结果
pub struct OrchestratorAgent {
    agent_id: String,
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    state: AgentStateHandle,
}

impl OrchestratorAgent {
    /// 创建新的 Orchestrator Agent
    pub fn new(
        config: AgentConfig,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    ) -> Self {
        let agent_id = format!("orchestrator-{}", uuid::Uuid::new_v4());
        let state = AgentStateHandle::new(crate::services::agent_engine::AgentState::new(
            agent_id.clone(),
            "Orchestrator".to_string(),
            AgentType::Orchestrator,
        ));

        Self {
            agent_id,
            config,
            llm,
            tool_registry,
            state,
        }
    }
}

#[async_trait]
impl Agent for OrchestratorAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Orchestrator
    }

    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        self.state.start().await;

        let start_time = chrono::Utc::now();
        let mut findings = Vec::new();
        let mut thought_chain = Vec::new();
        let mut tool_calls = Vec::new();
        let mut total_tokens = 0;

        // 加载系统提示词
        let loader = crate::services::prompts::global_loader();
        let template = match loader.load("orchestrator").await {
            Ok(t) => t,
            Err(_) => {
                // 使用默认提示词
                crate::services::prompts::PromptTemplate {
                    system_prompt: "你是代码审计编排器，负责协调审计流程。".to_string(),
                    prompts: Default::default(),
                    variables: Default::default(),
                }
            }
        };

        // 构建初始 Prompt
        let prompt_vars = crate::services::prompts::PromptContext::from_agent_context(&context)
            .to_variables();

        let system_prompt = loader.render(&template.system_prompt, &prompt_vars);

        // 执行 ReAct 循环
        let iteration_controller =
            IterationController::new(self.state.clone(), self.config.iteration_timeout_seconds);

        let messages = vec![crate::models::llm::LLMMessage::system(&system_prompt)];

        let mut current_messages = messages;

        while iteration_controller.can_continue().await {
            let iteration = iteration_controller.current_iteration().await;

            // 调用 LLM
            let llm_result = match self
                .llm
                .generate_with_tools(
                    current_messages.clone(),
                    self.tool_registry.get_definitions().await,
                    self.config.llm_config.max_tokens,
                    self.config.llm_config.temperature,
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    self.state.mark_failed(e.to_string()).await;
                    break;
                }
            };

            total_tokens += llm_result.usage.total_tokens();

            // 添加助手消息到历史
            let assistant_content = llm_result.content.clone();
            current_messages.push(crate::models::llm::LLMMessage {
                role: crate::models::llm::MessageRole::Assistant,
                content: assistant_content,
                cache_control: None,
            });

            // 检查是否有工具调用
            if llm_result.has_tool_calls() {
                let tool_calls_list = llm_result.get_tool_calls();

                for tool_call in tool_calls_list {
                    // 记录思考
                    thought_chain.push(crate::models::agent::ThoughtEntry {
                        iteration,
                        thought: format!("执行工具: {}", tool_call.name),
                        accumulated_thought: String::new(),
                        planned_action: Some(tool_call.name.clone()),
                        timestamp: chrono::Utc::now(),
                    });

                    // 执行工具
                    let tool_result = match self
                        .tool_registry
                        .execute(&tool_call.name, tool_call.input.clone())
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            crate::models::tools::ToolResult::error(e.to_string(), Some(e.code.to_string()))
                        }
                    };

                    // 记录工具调用
                    tool_calls.push(crate::models::agent::ToolCallRecord {
                        tool_name: tool_call.name.clone(),
                        input: tool_call.input.clone(),
                        output: Some(tool_result.clone()),
                        duration_ms: tool_result.duration_ms.unwrap_or(0),
                        success: !tool_result.is_error,
                        error: if tool_result.is_error {
                            Some(tool_result.get_text())
                        } else {
                            None
                        },
                        timestamp: chrono::Utc::now(),
                    });

                    // 添加工具结果到历史
                    current_messages.push(crate::models::llm::LLMMessage::user_with_tool_result(
                        tool_call.id,
                        tool_result.get_text(),
                        tool_result.is_error,
                    ));

                    // 检查是否是 finish 工具
                    if tool_call.name == "finish_analysis" || tool_call.name == "finish" {
                        self.state.mark_completed().await;
                        break;
                    }

                    // 检查是否是 report_finding
                    if tool_call.name == "report_finding" {
                        if let Ok(finding) = serde_json::from_value::<crate::models::events::FindingData>(
                            tool_call.input,
                        ) {
                            findings.push(finding);
                        }
                    }
                }
            } else {
                // 没有工具调用，记录思考
                let response_text = llm_result.get_text();
                thought_chain.push(crate::models::agent::ThoughtEntry {
                    iteration,
                    thought: response_text.clone(),
                    accumulated_thought: String::new(),
                    planned_action: None,
                    timestamp: chrono::Utc::now(),
                });
            }

            // 检查是否完成
            if self.state.get().await.is_completed() {
                break;
            }
        }

        let duration = (chrono::Utc::now() - start_time).num_milliseconds() as u64;
        let tool_calls_count = tool_calls.len();

        AgentResult {
            agent_id: self.agent_id().to_string(),
            agent_type: AgentType::Orchestrator,
            status: self.state.status().await,
            message: Some("编排器执行完成".to_string()),
            findings,
            thought_chain,
            tool_calls,
            stats: crate::models::agent::ExecutionStats {
                total_iterations: iteration_controller.current_iteration().await,
                total_tool_calls: tool_calls_count,
                total_tokens: total_tokens as u64,
                total_duration_ms: duration,
                llm_calls: iteration_controller.current_iteration().await,
            },
            error: None,
            completed_at: chrono::Utc::now(),
        }
    }
}

/// Recon Agent - 侦察 Agent
///
/// 负责项目结构分析、技术栈识别、攻击面分析
pub struct ReconAgent {
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
}

impl ReconAgent {
    pub fn new(config: AgentConfig, llm: Arc<dyn LLMClient>) -> Self {
        Self { config, llm }
    }
}

#[async_trait]
impl Agent for ReconAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Recon
    }

    fn agent_id(&self) -> &str {
        "recon"
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        // TODO: 实现侦察逻辑
        AgentResult {
            agent_id: "recon".to_string(),
            agent_type: AgentType::Recon,
            status: crate::models::agent::AgentStatus::Completed,
            message: Some("侦察完成".to_string()),
            findings: Vec::new(),
            thought_chain: Vec::new(),
            tool_calls: Vec::new(),
            stats: Default::default(),
            error: None,
            completed_at: chrono::Utc::now(),
        }
    }
}

/// Analysis Agent - 分析 Agent
///
/// 负责使用 ReAct 循环进行代码漏洞分析
pub struct AnalysisAgent {
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
}

impl AnalysisAgent {
    pub fn new(
        config: AgentConfig,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    ) -> Self {
        Self {
            config,
            llm,
            tool_registry,
        }
    }
}

#[async_trait]
impl Agent for AnalysisAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Analysis
    }

    fn agent_id(&self) -> &str {
        "analysis"
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        // TODO: 实现分析逻辑
        AgentResult {
            agent_id: "analysis".to_string(),
            agent_type: AgentType::Analysis,
            status: crate::models::agent::AgentStatus::Completed,
            message: Some("分析完成".to_string()),
            findings: Vec::new(),
            thought_chain: Vec::new(),
            tool_calls: Vec::new(),
            stats: Default::default(),
            error: None,
            completed_at: chrono::Utc::now(),
        }
    }
}

/// Verification Agent - 验证 Agent
///
/// 负责验证漏洞的可利用性（可选）
pub struct VerificationAgent {
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
}

impl VerificationAgent {
    pub fn new(config: AgentConfig, llm: Arc<dyn LLMClient>) -> Self {
        Self { config, llm }
    }
}

#[async_trait]
impl Agent for VerificationAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Verification
    }

    fn agent_id(&self) -> &str {
        "verification"
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        // TODO: 实现验证逻辑
        AgentResult {
            agent_id: "verification".to_string(),
            agent_type: AgentType::Verification,
            status: crate::models::agent::AgentStatus::Completed,
            message: Some("验证完成".to_string()),
            findings: Vec::new(),
            thought_chain: Vec::new(),
            tool_calls: Vec::new(),
            stats: Default::default(),
            error: None,
            completed_at: chrono::Utc::now(),
        }
    }
}
