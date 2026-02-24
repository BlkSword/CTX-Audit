// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! ReAct Agent 包装器
//!
//! 将 Agent 与 ReAct 执行器连接起来，实现真正的思考-行动-观察循环

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::base::{
    Agent, AgentConfig, AgentContext, AgentResult, AgentStatus, AgentType, ExecutionStats,
    ThoughtEntry, ToolCallRecord,
};
use crate::react::{ExecutionConfig, ExecutionEvent, ReactExecutor, ReactExecutionResult};
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::ToolRegistry;

/// Agent 系统提示词配置
pub struct AgentPrompts {
    /// Orchestrator 系统提示词
    pub orchestrator: String,
    /// Recon 系统提示词
    pub recon: String,
    /// Analysis 系统提示词
    pub analysis: String,
    /// Verification 系统提示词
    pub verification: String,
}

impl Default for AgentPrompts {
    fn default() -> Self {
        Self {
            orchestrator: ORCHESTRATOR_PROMPT.to_string(),
            recon: RECON_PROMPT.to_string(),
            analysis: ANALYSIS_PROMPT.to_string(),
            verification: VERIFICATION_PROMPT.to_string(),
        }
    }
}

impl AgentPrompts {
    /// 获取指定类型 Agent 的系统提示词
    pub fn get_prompt(&self, agent_type: &AgentType) -> &str {
        match agent_type {
            AgentType::Orchestrator => &self.orchestrator,
            AgentType::Recon => &self.recon,
            AgentType::Analysis => &self.analysis,
            AgentType::Verification => &self.verification,
        }
    }
}

// ============================================================================
// 系统提示词定义
// ============================================================================

/// Orchestrator Agent 系统提示词
const ORCHESTRATOR_PROMPT: &str = r#"你是一个代码安全审计编排器（Orchestrator）。

你的职责是：
1. 协调整个审计流程
2. 分配任务给专业的子 Agent（Recon、Analysis、Verification）
3. 汇总和整合所有审计结果
4. 生成最终的审计报告

工作流程：
1. 首先调用 Recon Agent 了解项目结构和技术栈
2. 然后调用 Analysis Agent 进行深度漏洞分析
3. 如果需要，调用 Verification Agent 验证关键漏洞
4. 最后整合所有发现，生成报告

你需要使用 report_finding 工具报告每个发现的安全问题。
完成所有任务后，使用 finish_analysis 工具结束审计。

请使用以下格式进行推理：
Thought: [你的思考过程]
Action: [工具名称]
Action Input: {"参数名": "参数值"}

可用工具将动态提供。"#;

/// Recon Agent 系统提示词
const RECON_PROMPT: &str = r#"你是一个代码安全侦察 Agent（Recon）。

你的职责是：
1. 分析项目结构（目录布局、文件组织）
2. 识别技术栈（框架、库、语言版本）
3. 识别潜在的攻击面（API 端点、外部输入点）
4. 发现敏感配置文件和依赖关系

分析方法：
1. 使用 list_files 获取项目目录结构
2. 读取关键配置文件（package.json, requirements.txt, Cargo.toml 等）
3. 搜索入口文件和路由定义
4. 识别认证、授权、数据库相关的代码

输出格式：
完成侦察后，使用 finish_analysis 报告你的发现：
{
    "project_type": "Web Application / API / CLI / ...",
    "tech_stack": ["框架", "语言", "数据库"],
    "entry_points": ["入口文件列表"],
    "attack_surface": ["潜在攻击面"],
    "recommendations": ["建议优先分析的模块"]
}

请使用以下格式进行推理：
Thought: [你的思考过程]
Action: [工具名称]
Action Input: {"参数名": "参数值"}"#;

/// Analysis Agent 系统提示词
const ANALYSIS_PROMPT: &str = r#"你是一个专业的代码安全分析 Agent（Analysis）。

你的职责是：
1. 深度分析代码中的安全漏洞
2. 追踪数据流，识别污点传播
3. 验证漏洞的可利用性
4. 生成详细的漏洞报告

你能够检测的漏洞类型：
- SQL 注入（SQL Injection）
- 跨站脚本（XSS）
- 命令注入（Command Injection）
- 路径遍历（Path Traversal）
- 不安全的反序列化（Insecure Deserialization）
- 硬编码凭证（Hardcoded Credentials）
- 敏感数据泄露（Sensitive Data Exposure）
- 认证和授权缺陷（Authentication/Authorization Issues）
- 加密问题（Cryptographic Issues）
- SSRF（Server-Side Request Forgery）
- XXE（XML External Entity）

分析方法：
1. 使用 search_symbol 搜索关键函数
2. 使用 read_file 读取可疑代码
3. 使用 get_ast_context 获取 AST 上下文
4. 追踪用户输入到危险函数的数据流

报告漏洞：
发现漏洞后，立即使用 report_finding 工具：
{
    "title": "漏洞标题",
    "description": "详细描述",
    "severity": "Critical/High/Medium/Low",
    "category": "漏洞类别",
    "file_path": "文件路径",
    "start_line": 行号,
    "code_snippet": "相关代码",
    "recommendation": "修复建议"
}

请使用以下格式进行推理：
Thought: [你的思考过程]
Action: [工具名称]
Action Input: {"参数名": "参数值"}"#;

/// Verification Agent 系统提示词
const VERIFICATION_PROMPT: &str = r#"你是一个安全漏洞验证 Agent（Verification）。

你的职责是：
1. 验证 Analysis Agent 发现的漏洞
2. 评估漏洞的实际可利用性
3. 生成安全的概念验证代码（PoC）
4. 提供更精确的风险评估

验证方法：
1. 深入分析漏洞触发条件
2. 检查是否存在有效的安全控制
3. 评估攻击者利用漏洞的难度
4. 考虑实际环境中的限制因素

输出格式：
验证完成后，更新漏洞的状态：
{
    "finding_id": "漏洞ID",
    "verification_status": "Confirmed/Unlikely/False Positive",
    "exploitability": "Easy/Medium/Hard/Unlikely",
    "poc_code": "安全的概念验证代码（如果适用）",
    "additional_notes": "额外说明"
}

安全原则：
- PoC 代码必须是安全的、无害的
- 不要生成可被直接滥用的攻击代码
- PoC 应仅用于证明漏洞存在

请使用以下格式进行推理：
Thought: [你的思考过程]
Action: [工具名称]
Action Input: {"参数名": "参数值"}"#;

// ============================================================================
// ReactAgentWrapper 实现
// ============================================================================

/// ReAct Agent 包装器
///
/// 将 Agent 与 ReAct 执行器连接，实现真正的思考-行动-观察循环
pub struct ReactAgentWrapper {
    /// Agent ID
    agent_id: String,
    /// Agent 配置
    config: AgentConfig,
    /// ReAct 执行器
    executor: ReactExecutor,
    /// 系统提示词
    system_prompt: String,
    /// 事件接收器（可选）
    event_rx: Option<mpsc::UnboundedReceiver<ExecutionEvent>>,
}

impl ReactAgentWrapper {
    /// 创建新的 ReAct Agent 包装器
    pub fn new(
        config: AgentConfig,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<ToolRegistry>,
        prompts: Option<AgentPrompts>,
    ) -> Self {
        let agent_id = format!(
            "{}-{}",
            config.agent_type.to_string().to_lowercase(),
            uuid::Uuid::new_v4()
        );

        let prompts = prompts.unwrap_or_default();
        let system_prompt = prompts.get_prompt(&config.agent_type).to_string();

        // 创建执行配置
        let exec_config = ExecutionConfig {
            max_iterations: config.max_iterations,
            timeout_secs: config.timeout_secs,
            enable_streaming: config.llm_config.stream,
            temperature: config.llm_config.temperature,
            max_tokens: config.llm_config.max_tokens,
        };

        // 创建事件通道
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // 创建执行器
        let executor = ReactExecutor::new(llm, tool_registry, exec_config).with_event_tx(event_tx);

        Self {
            agent_id,
            config,
            executor,
            system_prompt,
            event_rx: Some(event_rx),
        }
    }

    /// 创建带自定义系统提示词的包装器
    pub fn with_custom_prompt(mut self, prompt: String) -> Self {
        self.system_prompt = prompt;
        self
    }

    /// 获取事件接收器
    pub fn take_event_rx(&mut self) -> Option<mpsc::UnboundedReceiver<ExecutionEvent>> {
        self.event_rx.take()
    }

    /// 将 ReactExecutionResult 转换为 AgentResult
    fn convert_result(&self, exec_result: ReactExecutionResult) -> AgentResult {
        let state = &exec_result.state;

        // 转换思考链
        let thought_chain: Vec<ThoughtEntry> = state
            .thought_chain
            .iter()
            .map(|t| ThoughtEntry {
                iteration: t.iteration,
                thought: t.thought.clone(),
                accumulated_thought: String::new(),
                planned_action: None,
                action: t.action.clone(),
                action_input: t.action_input.clone(),
                observation: t.observation.as_ref().map(|o| {
                    serde_json::json!({
                        "summary": &o.summary,
                        "success": o.success,
                        "data": &o.data,
                    })
                }),
                confidence: Some(t.confidence),
                timestamp: t.timestamp,
            })
            .collect();

        // 获取工具调用记录
        let tool_calls = exec_result.get_tool_call_records();

        // 获取漏洞发现
        let findings = exec_result.get_findings();

        // 计算统计信息
        let stats = ExecutionStats {
            total_iterations: state.iteration,
            total_tool_calls: tool_calls.len(),
            total_tokens: 0,
            total_duration_ms: 0,
            llm_calls: state.iteration,
        };

        // 确定状态
        let status = if state.failed {
            AgentStatus::Failed
        } else if state.completed {
            AgentStatus::Completed
        } else {
            AgentStatus::Running
        };

        AgentResult {
            agent_id: self.agent_id.clone(),
            agent_type: self.config.agent_type.clone(),
            status,
            message: if state.completed {
                Some("分析完成".to_string())
            } else if state.failed {
                Some(format!("分析失败: {:?}", state.error))
            } else {
                Some("分析中断".to_string())
            },
            findings,
            thought_chain,
            tool_calls,
            stats,
            error: state.error.clone(),
            completed_at: chrono::Utc::now(),
        }
    }
}

#[async_trait]
impl Agent for ReactAgentWrapper {
    fn agent_type(&self) -> AgentType {
        self.config.agent_type.clone()
    }

    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        let start_time = chrono::Utc::now();

        // 构建用户消息
        let user_message = if let Some(user_ctx) = context.user_context.get("task") {
            user_ctx.as_str().unwrap_or("执行代码安全审计").to_string()
        } else {
            "执行代码安全审计".to_string()
        };

        // 执行 ReAct 循环
        match self
            .executor
            .execute(&context, &self.system_prompt, &user_message)
            .await
        {
            Ok(exec_result) => {
                let mut result = self.convert_result(exec_result);
                result.stats.total_duration_ms =
                    (chrono::Utc::now() - start_time).num_milliseconds() as u64;
                result
            }
            Err(error) => AgentResult {
                agent_id: self.agent_id.clone(),
                agent_type: self.config.agent_type.clone(),
                status: AgentStatus::Failed,
                message: Some(format!("执行失败: {}", error)),
                findings: Vec::new(),
                thought_chain: Vec::new(),
                tool_calls: Vec::new(),
                stats: ExecutionStats {
                    total_iterations: 0,
                    total_tool_calls: 0,
                    total_tokens: 0,
                    total_duration_ms: (chrono::Utc::now() - start_time).num_milliseconds() as u64,
                    llm_calls: 0,
                },
                error: Some(error),
                completed_at: chrono::Utc::now(),
            },
        }
    }

    /// 执行 Agent 任务（带外部事件回调）
    async fn execute_with_events(
        &self,
        context: AgentContext,
        event_tx: Option<mpsc::UnboundedSender<ExecutionEvent>>,
    ) -> AgentResult {
        let start_time = chrono::Utc::now();

        // 构建用户消息
        let user_message = if let Some(user_ctx) = context.user_context.get("task") {
            user_ctx.as_str().unwrap_or("执行代码安全审计").to_string()
        } else {
            "执行代码安全审计".to_string()
        };

        // 如果提供了外部事件发送器，创建一个带外部发送器的执行器
        if let Some(tx) = event_tx {
            // 创建新的执行配置
            let exec_config = ExecutionConfig {
                max_iterations: self.config.max_iterations,
                timeout_secs: self.config.timeout_secs,
                enable_streaming: self.config.llm_config.stream,
                temperature: self.config.llm_config.temperature,
                max_tokens: self.config.llm_config.max_tokens,
            };

            // 创建带外部事件发送器的执行器
            let executor = self.executor.clone_with_event_tx(tx);

            // 执行 ReAct 循环
            match executor.execute(&context, &self.system_prompt, &user_message).await {
                Ok(exec_result) => {
                    let mut result = self.convert_result(exec_result);
                    result.stats.total_duration_ms =
                        (chrono::Utc::now() - start_time).num_milliseconds() as u64;
                    result
                }
                Err(error) => AgentResult {
                    agent_id: self.agent_id.clone(),
                    agent_type: self.config.agent_type.clone(),
                    status: AgentStatus::Failed,
                    message: Some(format!("执行失败: {}", error)),
                    findings: Vec::new(),
                    thought_chain: Vec::new(),
                    tool_calls: Vec::new(),
                    stats: ExecutionStats {
                        total_iterations: 0,
                        total_tool_calls: 0,
                        total_tokens: 0,
                        total_duration_ms: (chrono::Utc::now() - start_time).num_milliseconds() as u64,
                        llm_calls: 0,
                    },
                    error: Some(error),
                    completed_at: chrono::Utc::now(),
                },
            }
        } else {
            // 没有外部事件发送器，使用默认 execute
            self.execute(context).await
        }
    }
}

// ============================================================================
// 工厂函数
// ============================================================================

/// 创建 Orchestrator Agent
pub fn create_orchestrator_agent(
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
) -> Arc<dyn Agent> {
    Arc::new(ReactAgentWrapper::new(
        config,
        llm,
        tool_registry,
        None,
    ))
}

/// 创建 Recon Agent
pub fn create_recon_agent(
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
) -> Arc<dyn Agent> {
    Arc::new(ReactAgentWrapper::new(config, llm, tool_registry, None))
}

/// 创建 Analysis Agent
pub fn create_analysis_agent(
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
) -> Arc<dyn Agent> {
    Arc::new(ReactAgentWrapper::new(config, llm, tool_registry, None))
}

/// 创建 Verification Agent
pub fn create_verification_agent(
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
) -> Arc<dyn Agent> {
    Arc::new(ReactAgentWrapper::new(config, llm, tool_registry, None))
}

/// 根据类型创建 Agent
pub fn create_agent_with_type(
    agent_type: AgentType,
    mut config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
) -> Arc<dyn Agent> {
    // 确保 config 中的 agent_type 与请求的类型一致
    config.agent_type = agent_type.clone();

    match agent_type {
        AgentType::Orchestrator => create_orchestrator_agent(config, llm, tool_registry),
        AgentType::Recon => create_recon_agent(config, llm, tool_registry),
        AgentType::Analysis => create_analysis_agent(config, llm, tool_registry),
        AgentType::Verification => create_verification_agent(config, llm, tool_registry),
    }
}

/// 创建带自定义提示词的 Agent
pub fn create_agent_with_custom_prompt(
    agent_type: AgentType,
    mut config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
    custom_prompt: String,
) -> Arc<dyn Agent> {
    config.agent_type = agent_type.clone();

    let wrapper = ReactAgentWrapper::new(config, llm, tool_registry, None)
        .with_custom_prompt(custom_prompt);

    Arc::new(wrapper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_prompts() {
        let prompts = AgentPrompts::default();

        assert!(!prompts.orchestrator.is_empty());
        assert!(!prompts.recon.is_empty());
        assert!(!prompts.analysis.is_empty());
        assert!(!prompts.verification.is_empty());

        assert_eq!(
            prompts.get_prompt(&AgentType::Analysis),
            prompts.analysis
        );
    }
}
