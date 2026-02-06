//! 具体 Agent 实现
//!
//! 实现 Orchestrator, Recon, Analysis, Verification Agent

use async_trait::async_trait;
use std::sync::Arc;

use crate::models::agent::{
    AgentConfig, AgentContext, AgentResult, AgentType, AgentStatus, ExecutionStats,
    ThoughtEntry, ToolCallRecord,
};
use crate::models::events::FindingData;
use crate::models::llm::{LLMMessage, MessageRole};
use crate::services::agent_engine::{Agent, ReactAgent};
use crate::services::llm::LLMClient;
use crate::services::prompts::global_loader;

/// ReAct 循环执行器
///
/// 共享的 ReAct 循环逻辑，供所有 Agent 使用
struct ReactLoopExecutor {
    agent_id: String,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    config: AgentConfig,
}

impl ReactLoopExecutor {
    /// 创建新的执行器
    fn new(
        agent_id: String,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
        config: AgentConfig,
    ) -> Self {
        Self {
            agent_id,
            llm,
            tool_registry,
            config,
        }
    }

    /// 执行 ReAct 循环
    async fn execute(
        &self,
        context: &AgentContext,
        system_prompt: &str,
        initial_message: &str,
    ) -> AgentResult {
        let start_time = chrono::Utc::now();
        let mut findings = Vec::new();
        let mut thought_chain = Vec::new();
        let mut tool_calls = Vec::new();
        let mut total_tokens = 0;
        let max_iterations = self.config.max_iterations;

        // 构建初始消息
        let mut messages = vec![
            LLMMessage::system(system_prompt),
            LLMMessage::user(initial_message),
        ];

        // ReAct 循环
        for iteration in 0..max_iterations {
            tracing::info!("[{}] ReAct 迭代 {}/{}", self.agent_id, iteration + 1, max_iterations);

            // 调用 LLM
            let llm_result = match self
                .llm
                .generate_with_tools(
                    messages.clone(),
                    self.tool_registry.get_definitions().await,
                    self.config.llm_config.max_tokens,
                    self.config.llm_config.temperature,
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("[{}] LLM 调用失败: {}", self.agent_id, e);
                    let tool_calls_count = tool_calls.len();
                    return AgentResult {
                        agent_id: self.agent_id.clone(),
                        agent_type: self.config.agent_type.clone(),
                        status: AgentStatus::Failed,
                        message: Some(format!("LLM 调用失败: {}", e)),
                        findings,
                        thought_chain,
                        tool_calls,
                        stats: ExecutionStats {
                            total_iterations: iteration,
                            total_tool_calls: tool_calls_count,
                            total_tokens,
                            total_duration_ms: (chrono::Utc::now() - start_time).num_milliseconds() as u64,
                            llm_calls: iteration + 1,
                        },
                        error: Some(e.to_string()),
                        completed_at: chrono::Utc::now(),
                    };
                }
            };

            total_tokens += llm_result.usage.total_tokens() as u64;

            // 获取响应文本
            let response_text = llm_result.get_text();

            // 记录思考
            thought_chain.push(ThoughtEntry {
                iteration: iteration + 1,
                thought: response_text.clone(),
                accumulated_thought: String::new(),
                planned_action: None,
                timestamp: chrono::Utc::now(),
            });

            // 添加助手消息到历史
            messages.push(LLMMessage {
                role: MessageRole::Assistant,
                content: vec![crate::models::llm::MessageContent::Text {
                    text: response_text.clone(),
                }],
                cache_control: None,
            });

            // 检查是否有工具调用
            if llm_result.has_tool_calls() {
                let tool_calls_list = llm_result.get_tool_calls();

                for tool_call in tool_calls_list {
                    tracing::info!(
                        "[{}] 执行工具: {} with input: {}",
                        self.agent_id,
                        tool_call.name,
                        serde_json::to_string(&tool_call.input).unwrap_or_default()
                    );

                    // 执行工具
                    let tool_result = match self
                        .tool_registry
                        .execute(&tool_call.name, tool_call.input.clone())
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::error!("[{}] 工具执行失败: {}", self.agent_id, e);
                            crate::models::tools::ToolResult::error(
                                e.to_string(),
                                Some(e.code.to_string()),
                            )
                        }
                    };

                    // 记录工具调用
                    tool_calls.push(ToolCallRecord {
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
                    messages.push(LLMMessage::user_with_tool_result(
                        tool_call.id,
                        tool_result.get_text(),
                        tool_result.is_error,
                    ));

                    // 检查是否是 finish 工具
                    if tool_call.name == "finish_analysis" || tool_call.name == "finish" {
                        tracing::info!("[{}] 收到 finish 信号", self.agent_id);
                        let tool_calls_count = tool_calls.len();
                        return AgentResult {
                            agent_id: self.agent_id.clone(),
                            agent_type: self.config.agent_type.clone(),
                            status: AgentStatus::Completed,
                            message: Some("分析完成".to_string()),
                            findings,
                            thought_chain,
                            tool_calls,
                            stats: ExecutionStats {
                                total_iterations: iteration + 1,
                                total_tool_calls: tool_calls_count,
                                total_tokens,
                                total_duration_ms: (chrono::Utc::now() - start_time).num_milliseconds() as u64,
                                llm_calls: iteration + 1,
                            },
                            error: None,
                            completed_at: chrono::Utc::now(),
                        };
                    }

                    // 检查是否是 report_finding
                    if tool_call.name == "report_finding" {
                        if let Ok(finding) = serde_json::from_value::<FindingData>(tool_call.input) {
                            tracing::info!("[{}] 报告漏洞: {:?}", self.agent_id, finding.title);
                            findings.push(finding);
                        }
                    }
                }
            } else {
                // 没有工具调用，检查是否是完成信号
                if response_text.to_lowercase().contains("finish")
                    || response_text.to_lowercase().contains("完成")
                {
                    tracing::info!("[{}] 检测到完成信号", self.agent_id);
                    break;
                }
            }
        }

        // 达到最大迭代次数
        let tool_calls_count = tool_calls.len();
        AgentResult {
            agent_id: self.agent_id.clone(),
            agent_type: self.config.agent_type.clone(),
            status: AgentStatus::Completed,
            message: Some(format!("完成 {} 次迭代", max_iterations)),
            findings,
            thought_chain,
            tool_calls,
            stats: ExecutionStats {
                total_iterations: max_iterations,
                total_tool_calls: tool_calls_count,
                total_tokens,
                total_duration_ms: (chrono::Utc::now() - start_time).num_milliseconds() as u64,
                llm_calls: max_iterations,
            },
            error: None,
            completed_at: chrono::Utc::now(),
        }
    }
}

// ============================================================================
// Orchestrator Agent - 编排器
// ============================================================================

/// Orchestrator Agent - 编排器
///
/// 负责协调整个审计流程，管理子 Agent，汇总结果
pub struct OrchestratorAgent {
    agent_id: String,
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
}

impl OrchestratorAgent {
    /// 创建新的 Orchestrator Agent
    pub fn new(
        config: AgentConfig,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    ) -> Self {
        let agent_id = format!("orchestrator-{}", uuid::Uuid::new_v4());

        Self {
            agent_id,
            config,
            llm,
            tool_registry,
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
        // 加载系统提示词
        let loader = global_loader();
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

        let executor = ReactLoopExecutor::new(
            self.agent_id.clone(),
            self.llm.clone(),
            self.tool_registry.clone(),
            self.config.clone(),
        );

        let initial_message = format!(
            "开始审计项目: {}\n项目路径: {}\n\n请协调审计流程，依次执行：
            1. 侦察阶段 - 分析项目结构和技术栈
            2. 分析阶段 - 深度代码分析，发现漏洞
            3. 验证阶段 - 验证漏洞真实性（可选）

            请使用 ReAct 方法进行编排。",
            context.project_id, context.project_path
        );

        executor
            .execute(&context, &template.system_prompt, &initial_message)
            .await
    }
}

// ============================================================================
// Recon Agent - 侦察 Agent
// ============================================================================

/// Recon Agent - 侦察 Agent
///
/// 负责项目结构分析、技术栈识别、攻击面分析
pub struct ReconAgent {
    agent_id: String,
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
}

impl ReconAgent {
    /// 创建新的 Recon Agent
    pub fn new(
        config: AgentConfig,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    ) -> Self {
        let agent_id = format!("recon-{}", uuid::Uuid::new_v4());

        Self {
            agent_id,
            config,
            llm,
            tool_registry,
        }
    }
}

#[async_trait]
impl Agent for ReconAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Recon
    }

    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        // 加载系统提示词
        let loader = global_loader();
        let template = match loader.load("recon").await {
            Ok(t) => t,
            Err(_) => {
                // 使用默认提示词
                crate::services::prompts::PromptTemplate {
                    system_prompt: r#"你是一个代码安全审计侦察专家（Recon Agent）。

## 职责
- 分析项目结构和架构
- 识别使用的技术栈和框架
- 检测潜在的攻击面
- 识别第三方依赖和安全风险

## 工作流程
1. 扫描项目目录结构
2. 分析配置文件（package.json, requirements.txt, Cargo.toml 等）
3. 识别入口点和关键文件
4. 检测外部依赖和已知漏洞组件
5. 分析代码复杂度和热点区域

## 可用工具
- `list_files`: 列出目录中的文件
- `read_file`: 读取文件内容
- `finish_analysis`: 完成分析

## 关注重点
- 身份认证和授权机制
- 数据处理和存储
- 网络通信和 API 端点
- 加密和敏感数据处理
- 第三方依赖和已知漏洞"#
                        .to_string(),
                    prompts: Default::default(),
                    variables: Default::default(),
                }
            }
        };

        let executor = ReactLoopExecutor::new(
            self.agent_id.clone(),
            self.llm.clone(),
            self.tool_registry.clone(),
            self.config.clone(),
        );

        let initial_message = format!(
            "请对项目 {} 进行侦察分析。

目标：
1. 识别项目技术栈
2. 分析项目结构
3. 检测攻击面
4. 识别关键风险点

项目路径: {}

开始你的侦察工作。",
            context.project_id, context.project_path
        );

        executor
            .execute(&context, &template.system_prompt, &initial_message)
            .await
    }
}

// ============================================================================
// Analysis Agent - 分析 Agent
// ============================================================================

/// Analysis Agent - 分析 Agent
///
/// 负责使用 ReAct 循环进行代码漏洞分析
pub struct AnalysisAgent {
    agent_id: String,
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
}

impl AnalysisAgent {
    /// 创建新的 Analysis Agent
    pub fn new(
        config: AgentConfig,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    ) -> Self {
        let agent_id = format!("analysis-{}", uuid::Uuid::new_v4());

        Self {
            agent_id,
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
        &self.agent_id
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        // 加载系统提示词
        let loader = global_loader();
        let template = match loader.load("analysis").await {
            Ok(t) => t,
            Err(_) => {
                // 使用默认提示词
                crate::services::prompts::PromptTemplate {
                    system_prompt: r#"你是一个专业的代码安全漏洞分析专家（Analysis Agent）。

## 职责
- 使用 ReAct 循环进行深度代码分析
- 检测各类安全漏洞（OWASP Top 10、CWE 等）
- 分析数据流和控制流
- 验证潜在漏洞的可利用性
- 过滤误报和低风险问题

## 工作流程 (ReAct 循环)
对于每个分析任务：
1. **Thought**: 思考当前代码片段可能存在的安全问题
2. **Action**: 选择合适的工具进行深入分析
3. **Observation**: 观察工具返回的结果
4. **Thought**: 基于结果更新你的理解
5. **Repeat**: 继续分析或报告发现

## 可用工具
- `read_file`: 读取文件内容
- `list_files`: 列出目录文件
- `get_ast_context`: 获取函数/类的 AST 信息
- `search_symbol`: 搜索符号定义和引用
- `report_finding`: 报告确认的漏洞
- `finish_analysis`: 完成当前文件的分析

## 漏洞类别
### 注入类
- SQL 注入
- NoSQL 注入
- 命令注入
- LDAP 注入
- 模板注入

### 认证授权
- 弱密码策略
- 硬编码凭证
- 会话管理缺陷
- 权限提升
- JWT 问题

### 数据安全
- 敏感数据泄露
- 不安全的加密
- 明文存储密码
- 缺少数据验证

### 业务逻辑
- 价格篡改
- 参数篡改
- 竞态条件
- 越权访问

### 配置安全
- 不安全的默认配置
- 错误信息泄露
- 安全头缺失
- CORS 配置错误"#
                        .to_string(),
                    prompts: Default::default(),
                    variables: Default::default(),
                }
            }
        };

        let executor = ReactLoopExecutor::new(
            self.agent_id.clone(),
            self.llm.clone(),
            self.tool_registry.clone(),
            self.config.clone(),
        );

        // 获取扫描目标（如果有）
        let scan_targets = context
            .inherited_context
            .get("scan_targets")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "整个项目".to_string());

        let initial_message = format!(
            "请对项目进行深度安全分析。

项目: {}
路径: {}

扫描目标: {}

请使用 ReAct 循环进行分析：
1. Thought: [你的思考]
2. Action: [工具名称]
3. Action Input: [工具输入参数]

对于每个发现的潜在漏洞：
- 使用代码分析工具查看相关代码
- 使用 report_finding 报告确认的漏洞
- 使用 finish_analysis 完成分析",
            context.project_id, context.project_path, scan_targets
        );

        executor
            .execute(&context, &template.system_prompt, &initial_message)
            .await
    }
}

// ============================================================================
// Verification Agent - 验证 Agent
// ============================================================================

/// Verification Agent - 验证 Agent
///
/// 负责验证漏洞的可利用性（可选）
pub struct VerificationAgent {
    agent_id: String,
    config: AgentConfig,
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
}

impl VerificationAgent {
    /// 创建新的 Verification Agent
    pub fn new(
        config: AgentConfig,
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<crate::services::tools::registry::ToolRegistry>,
    ) -> Self {
        let agent_id = format!("verification-{}", uuid::Uuid::new_v4());

        Self {
            agent_id,
            config,
            llm,
            tool_registry,
        }
    }
}

#[async_trait]
impl Agent for VerificationAgent {
    fn agent_type(&self) -> AgentType {
        AgentType::Verification
    }

    fn agent_id(&self) -> &str {
        &self.agent_id
    }

    fn config(&self) -> &AgentConfig {
        &self.config
    }

    async fn execute(&self, context: AgentContext) -> AgentResult {
        // 加载系统提示词
        let loader = global_loader();
        let template = match loader.load("verification").await {
            Ok(t) => t,
            Err(_) => {
                // 使用默认提示词
                crate::services::prompts::PromptTemplate {
                    system_prompt: r#"你是一个安全漏洞验证专家（Verification Agent）。

## 职责
- 验证报告的漏洞是否真实存在
- 评估漏洞的可利用性和影响范围
- 确定漏洞的严重程度评级
- 过滤误报和低风险问题

## 验证标准
### 确认漏洞的条件
1. 代码路径可达（用户可触发）
2. 污点数据可以流向敏感操作
3. 没有适当的防护措施
4. 可导致实际的安全影响

### 严重程度评级
- **Critical (严重)**: 可直接导致 RCE、数据泄露、权限提升
- **High (高危)**: 需要特定条件但影响严重
- **Medium (中危)**: 影响有限或利用难度较高
- **Low (低危)**: 安全最佳实践问题
- **Info (信息)**: 非安全问题，仅作提醒

## 工作流程
1. 审查原始发现
2. 追踪数据流和控制流
3. 检查防护机制
4. 评估实际影响
5. 给出验证结论

## 可用工具
- `read_file`: 读取文件内容
- `get_ast_context`: 获取详细的 AST 信息
- `search_symbol`: 追踪数据流
- `finish_analysis`: 完成验证"#
                        .to_string(),
                    prompts: Default::default(),
                    variables: Default::default(),
                }
            }
        };

        let executor = ReactLoopExecutor::new(
            self.agent_id.clone(),
            self.llm.clone(),
            self.tool_registry.clone(),
            self.config.clone(),
        );

        // 获取待验证的漏洞列表
        let findings = context
            .inherited_context
            .get("findings")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| serde_json::to_string(v).ok())
                    .collect::<Vec<_>>()
                    .join("\n\n")
            })
            .unwrap_or_else(|| "没有待验证的漏洞".to_string());

        let initial_message = format!(
            "请验证以下发现的漏洞：

## 待验证的漏洞
{}

## 验证任务
1. 代码路径是否可达？
2. 数据流是否完整？
3. 是否有防护措施？
4. 实际影响是什么？

请使用工具进行深入验证，然后给出结论。",
            findings
        );

        executor
            .execute(&context, &template.system_prompt, &initial_message)
            .await
    }
}
