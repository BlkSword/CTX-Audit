// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 阶段感知执行器
//!
//! 根据审计阶段使用不同的执行策略和工具集

use std::sync::Arc;
use tokio::sync::mpsc;

use crate::audit_state::{
    SecurityAuditState, AuditPhase, AnalysisTarget, VulnerabilityCandidate, VerificationStatus,
};
use crate::prescan::{DeterministicPrescanner, PrescanConfig, ProjectInfoCollector};
use crate::audit_prompts::AuditPrompts;
use crate::audit_chain::{
    SecurityAuditChain, AuditThinkingPhase, VulnerabilityHypothesis, HypothesisStatus,
    Evidence, EvidenceType, CodeLocation, DataFlowStep, DataFlowStepType,
    VulnerabilityType, Severity,
};
use crate::tool_recommender::ToolRecommender;
use crate::react::executor::{ExecutionConfig, ExecutionEvent, ReactExecutor};
use crate::base::AgentContext;
use ctx_audit_llm::LLMClient;
use ctx_audit_tools::ToolRegistry;

// 新模块导入
use crate::multi_agent::UnifiedMultiAgentSystem;
use crate::multi_agent::MultiAgentConfig;
use crate::semantic::SemanticUnderstandingEngine;
use crate::analysis::{
    BusinessLogicAnalyzer, GlobalFlowGraph, GitHistoryAnalyzer
};
use crate::verification::DualVerificationSystem;
use crate::deterministic::{DeterministicExecutor, DeterministicConfig};

/// 阶段执行结果
#[derive(Debug, Clone)]
pub struct PhaseResult {
    /// 阶段
    pub phase: AuditPhase,

    /// 是否成功
    pub success: bool,

    /// 消息
    pub message: String,

    /// 处理的目标数
    pub targets_processed: usize,

    /// 发现的漏洞数
    pub findings_count: usize,

    /// 耗时（毫秒）
    pub duration_ms: u64,
}

/// 阶段感知执行器
pub struct PhaseAwareExecutor {
    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 工具注册表
    tool_registry: Arc<ToolRegistry>,

    /// 执行配置
    config: ExecutionConfig,

    /// 审计提示词
    prompts: AuditPrompts,

    /// 事件发送器
    event_tx: Option<mpsc::UnboundedSender<ExecutionEvent>>,

    /// 审计思维链
    audit_chain: SecurityAuditChain,

    /// 工具推荐器
    tool_recommender: ToolRecommender,

    // ========== 新模块集成 ==========

    /// 多 Agent 系统
    multi_agent_system: Option<UnifiedMultiAgentSystem>,

    /// 语义理解引擎
    semantic_engine: SemanticUnderstandingEngine,

    /// 业务逻辑分析器
    business_logic_analyzer: BusinessLogicAnalyzer,

    /// 全局数据流图谱
    global_flow_graph: Option<GlobalFlowGraph>,

    /// Git 历史分析器
    git_analyzer: Option<GitHistoryAnalyzer>,

    /// 双重验证系统
    dual_verification: Option<DualVerificationSystem>,

    /// 确定性执行器
    deterministic_executor: Option<DeterministicExecutor>,

    /// 是否启用多 Agent 模式
    enable_multi_agent: bool,

    /// 是否启用确定性审计
    enable_deterministic: bool,
}

impl PhaseAwareExecutor {
    /// 创建新的阶段感知执行器
    pub fn new(
        llm: Arc<dyn LLMClient>,
        tool_registry: Arc<ToolRegistry>,
        config: ExecutionConfig,
    ) -> Self {
        Self {
            llm: llm.clone(),
            tool_registry,
            config,
            prompts: AuditPrompts::default(),
            event_tx: None,
            audit_chain: SecurityAuditChain::new(),
            tool_recommender: ToolRecommender::new(),
            // 新模块初始化
            multi_agent_system: None,
            semantic_engine: SemanticUnderstandingEngine::new(),
            business_logic_analyzer: BusinessLogicAnalyzer::new(),
            global_flow_graph: None,
            git_analyzer: None,
            dual_verification: None,
            deterministic_executor: None,
            enable_multi_agent: false,
            enable_deterministic: false,
        }
    }

    /// 启用多 Agent 模式
    pub async fn with_multi_agent(mut self, config: MultiAgentConfig) -> Result<Self, String> {
        let multi_agent = crate::multi_agent::create_multi_agent_system(
            self.llm.clone(),
            self.tool_registry.clone(),
            config,
        ).await?;
        self.multi_agent_system = Some(multi_agent);
        self.enable_multi_agent = true;
        Ok(self)
    }

    /// 启用确定性审计
    pub fn with_deterministic(mut self, config: DeterministicConfig) -> Self {
        self.deterministic_executor = Some(DeterministicExecutor::new(
            self.llm.clone(),
            config,
        ));
        self.enable_deterministic = true;
        self
    }

    /// 启用全局数据流追踪
    pub fn with_global_flow(mut self, project_path: String) -> Self {
        self.global_flow_graph = Some(GlobalFlowGraph::new(project_path));
        self
    }

    /// 启用 Git 历史分析
    pub fn with_git_analysis(mut self, repo_path: String) -> Self {
        self.git_analyzer = Some(GitHistoryAnalyzer::new(repo_path));
        self
    }

    /// 启用双重验证
    pub fn with_dual_verification(mut self) -> Self {
        self.dual_verification = Some(DualVerificationSystem::new(
            self.llm.clone()
        ));
        self
    }

    /// 设置事件发送器
    pub fn with_event_tx(mut self, tx: mpsc::UnboundedSender<ExecutionEvent>) -> Self {
        self.event_tx = Some(tx);
        self
    }

    /// 获取审计思维链的引用
    pub fn get_audit_chain(&self) -> &SecurityAuditChain {
        &self.audit_chain
    }

    /// 获取审计思维链的可变引用
    pub fn get_audit_chain_mut(&mut self) -> &mut SecurityAuditChain {
        &mut self.audit_chain
    }

    /// 获取工具推荐器的引用
    pub fn get_tool_recommender(&self) -> &ToolRecommender {
        &self.tool_recommender
    }

    /// 执行完整的审计流程
    pub async fn execute_full_audit(&mut self, state: &mut SecurityAuditState) -> Result<Vec<PhaseResult>, String> {
        let mut results = Vec::new();

        // 阶段 1: 初始化
        let init_result = self.execute_initialization(state).await;
        results.push(init_result);

        // 阶段 2: 确定性扫描
        let scan_result = self.execute_deterministic_scan(state).await;
        results.push(scan_result);

        // 阶段 3: 深度分析
        let analysis_result = self.execute_deep_analysis(state).await;
        results.push(analysis_result);

        // 阶段 4: 验证
        let verification_result = self.execute_verification(state).await;
        results.push(verification_result);

        // 阶段 5: 报告
        let report_result = self.execute_reporting(state).await;
        results.push(report_result);

        Ok(results)
    }

    /// 执行初始化阶段
    pub async fn execute_initialization(&mut self, state: &mut SecurityAuditState) -> PhaseResult {
        let start = std::time::Instant::now();
        state.transition_to(AuditPhase::Initialization);

        // 记录思维链开始
        self.audit_chain.record_thought(
            "开始安全审计".to_string(),
            "识别项目技术栈和入口点".to_string(),
            Some("收集项目信息".to_string()),
        );

        self.send_event(ExecutionEvent::IterationStart(0));

        // 收集项目信息
        let project_info = ProjectInfoCollector::collect(&state.project_path);
        state.project_info = project_info;

        // 识别入口点
        let entry_count = state.project_info.entry_points.len();

        // 更新审计链上下文
        for tech in &state.project_info.tech_stack {
            self.audit_chain.context.project_info.insert(tech.clone(), "detected".to_string());
        }
        for entry in &state.project_info.entry_points {
            self.audit_chain.context.analyzed_entry_points.push(entry.clone());
        }

        let message = format!(
            "项目初始化完成\n技术栈: {:?}\n框架: {:?}\n入口点: {}",
            state.project_info.tech_stack,
            state.project_info.frameworks,
            entry_count
        );

        // 推进思维链阶段
        self.audit_chain.advance_phase();

        self.send_event(ExecutionEvent::ThoughtComplete {
            iteration: 0,
            thought: message.clone(),
            action: None,
        });

        state.transition_to(AuditPhase::DeterministicScan);

        PhaseResult {
            phase: AuditPhase::Initialization,
            success: true,
            message,
            targets_processed: entry_count,
            findings_count: 0,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// 执行确定性扫描阶段
    pub async fn execute_deterministic_scan(&mut self, state: &mut SecurityAuditState) -> PhaseResult {
        let start = std::time::Instant::now();
        state.transition_to(AuditPhase::DeterministicScan);

        // 推进思维链到假设生成阶段
        self.audit_chain.advance_phase();
        self.audit_chain.record_thought(
            "开始确定性扫描".to_string(),
            "使用污点分析和模式检测识别候选漏洞".to_string(),
            Some("执行全局污点分析和模式扫描".to_string()),
        );

        self.send_event(ExecutionEvent::IterationStart(1));

        // 执行预扫描
        let prescanner = DeterministicPrescanner::new(PrescanConfig::default());
        let scan_result = prescanner.scan(state).await;

        // 从候选漏洞生成假设
        for candidate in &state.vulnerability_candidates {
            // 解析漏洞类型
            let vuln_type = self.parse_vulnerability_type(&candidate.vulnerability_type);

            // 创建代码位置
            let entry_point = CodeLocation::new(candidate.file_path.clone(), candidate.line);
            let sink_point = CodeLocation::new(candidate.file_path.clone(), candidate.line);

            // 创建假设
            let mut hypothesis = VulnerabilityHypothesis::new(vuln_type, entry_point, sink_point);
            hypothesis.initial_confidence = candidate.confidence;
            hypothesis.current_confidence = candidate.confidence;

            // 如果有传播路径，添加数据流步骤
            if let Some(ref path) = candidate.propagation_path {
                for step in path {
                    let flow_step = DataFlowStep {
                        step_type: DataFlowStepType::Assignment,
                        location: CodeLocation::new(candidate.file_path.clone(), step.line),
                        variable: step.symbol.clone(),
                        code: step.code.clone(),
                        description: format!("变量 {} 传播", step.symbol),
                    };
                    hypothesis.add_data_flow_step(flow_step);
                }
            }

            self.audit_chain.add_hypothesis(hypothesis);
        }

        let message = format!(
            "确定性扫描完成\n扫描文件: {}\n候选漏洞: {}\n用户输入点: {}\n敏感调用: {}\n分析目标: {}\n生成假设: {}",
            scan_result.files_scanned,
            scan_result.candidates_found,
            scan_result.input_points_found,
            scan_result.sensitive_calls_found,
            state.pending_targets.len(),
            self.audit_chain.hypotheses.len()
        );

        // 推进思维链到证据收集阶段
        self.audit_chain.advance_phase();

        self.send_event(ExecutionEvent::ThoughtComplete {
            iteration: 1,
            thought: message.clone(),
            action: Some("deterministic_scan".to_string()),
        });

        state.stats.tool_calls += scan_result.files_scanned as u32;
        state.transition_to(AuditPhase::DeepAnalysis);

        PhaseResult {
            phase: AuditPhase::DeterministicScan,
            success: true,
            message,
            targets_processed: scan_result.files_scanned,
            findings_count: scan_result.candidates_found,
            duration_ms: scan_result.duration_ms,
        }
    }

    /// 解析漏洞类型字符串
    fn parse_vulnerability_type(&self, type_str: &str) -> VulnerabilityType {
        let lower = type_str.to_lowercase();
        if lower.contains("sql") {
            VulnerabilityType::SqlInjection
        } else if lower.contains("command") || lower.contains("cmd") || lower.contains("exec") {
            VulnerabilityType::CommandInjection
        } else if lower.contains("xss") || lower.contains("script") {
            VulnerabilityType::Xss
        } else if lower.contains("path") || lower.contains("traversal") || lower.contains("directory") {
            VulnerabilityType::PathTraversal
        } else if lower.contains("ssrf") || lower.contains("request") {
            VulnerabilityType::Ssrf
        } else if lower.contains("xxe") || lower.contains("xml") {
            VulnerabilityType::Xxe
        } else if lower.contains("deserialize") || lower.contains("pickle") {
            VulnerabilityType::InsecureDeserialization
        } else if lower.contains("redirect") {
            VulnerabilityType::OpenRedirect
        } else if lower.contains("auth") && lower.contains("bypass") {
            VulnerabilityType::AuthBypass
        } else if lower.contains("hardcoded") || lower.contains("secret") || lower.contains("password") || lower.contains("key") {
            VulnerabilityType::HardcodedSecret
        } else {
            VulnerabilityType::Custom
        }
    }

    /// 执行深度分析阶段
    pub async fn execute_deep_analysis(&mut self, state: &mut SecurityAuditState) -> PhaseResult {
        let start = std::time::Instant::now();
        state.transition_to(AuditPhase::DeepAnalysis);

        // 记录思维链
        self.audit_chain.record_thought(
            "开始深度分析".to_string(),
            format!("验证 {} 个候选漏洞假设", self.audit_chain.hypotheses.len()),
            Some("使用 LLM 和专业工具验证假设".to_string()),
        );

        let mut targets_processed = 0;
        let mut total_findings = 0;
        let max_iterations = self.config.max_iterations.unwrap_or(50);
        let mut iteration = 2;

        // 构建初始上下文
        let system_prompt = self.prompts.get_deep_analysis_prompt(state);
        let initial_context = self.build_initial_context(state);

        // 获取工具推荐
        let recommendations = self.tool_recommender.recommend(state);
        let recommendations_text = recommendations.iter()
            .map(|r| format!("- {} (优先级: {}): {}", r.tool_name, r.priority, r.reason))
            .collect::<Vec<_>>()
            .join("\n");

        // 构建假设上下文
        let hypotheses_context = self.build_hypotheses_context();

        // 创建 ReAct 执行器
        let executor = ReactExecutor::new(
            self.llm.clone(),
            self.tool_registry.clone(),
            self.config.clone(),
        );

        // 构建代理上下文
        let agent_context = AgentContext {
            project_id: state.session_id.clone(),
            project_path: state.project_path.clone(),
            session_id: state.session_id.clone(),
            inherited_context: state.working_memory.clone(),
            user_context: {
                let mut ctx = std::collections::HashMap::new();
                ctx.insert("initial_context".to_string(), serde_json::json!(initial_context));
                ctx.insert("candidates".to_string(), serde_json::json!(state.vulnerability_candidates));
                ctx.insert("hypotheses".to_string(), serde_json::json!(self.audit_chain.hypotheses));
                ctx.insert("tool_recommendations".to_string(), serde_json::json!(recommendations_text));
                ctx
            },
        };

        // 执行 LLM 分析
        let user_message = self.build_analysis_user_message_with_hypotheses(state);

        self.send_event(ExecutionEvent::IterationStart(iteration));

        match executor.execute(&agent_context, &system_prompt, &user_message).await {
            Ok(exec_result) => {
                targets_processed = exec_result.tool_calls.len() as usize;

                // 收集需要添加的证据和更新的假设
                let mut evidences_to_add: Vec<(String, Evidence)> = Vec::new();
                let mut hypotheses_to_verify: Vec<(String, f32)> = Vec::new();

                // 处理发现并收集更新信息
                for finding in exec_result.get_findings() {
                    // 查找匹配的假设
                    for hypothesis in &self.audit_chain.hypotheses {
                        if hypothesis.entry_point.file_path == finding.file_path &&
                           hypothesis.entry_point.start_line == finding.start_line as usize {
                            // 收集证据
                            let evidence = Evidence::new(
                                &hypothesis.id,
                                EvidenceType::LLMAnalysis,
                                CodeLocation::new(finding.file_path.clone(), finding.start_line as usize),
                                finding.description.clone(),
                            ).with_support(0.8).with_source("llm_analysis");

                            evidences_to_add.push((hypothesis.id.clone(), evidence));
                            hypotheses_to_verify.push((hypothesis.id.clone(), 0.8));

                            // 同时更新候选漏洞状态
                            for candidate in &mut state.vulnerability_candidates {
                                if candidate.file_path == finding.file_path &&
                                   candidate.line == finding.start_line as usize {
                                    candidate.verification_status = VerificationStatus::Confirmed;
                                    state.confirmed_vulnerabilities.push(candidate.clone());
                                    total_findings += 1;
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }

                // 应用收集的更新
                for (_, evidence) in evidences_to_add {
                    self.audit_chain.add_evidence(evidence);
                }

                for (hyp_id, confidence) in hypotheses_to_verify {
                    for hypothesis in &mut self.audit_chain.hypotheses {
                        if hypothesis.id == hyp_id {
                            hypothesis.mark_verified(confidence);
                            self.audit_chain.stats.confirmed_vulnerabilities += 1;
                            break;
                        }
                    }
                }

                // 更新统计
                state.stats.llm_calls += exec_result.state.iteration;
                state.stats.tool_calls += exec_result.tool_calls.len() as u32;

                // 推进思维链
                self.audit_chain.advance_phase();

                self.send_event(ExecutionEvent::Complete {
                    iterations: exec_result.state.iteration,
                    tool_calls: exec_result.tool_calls.len(),
                });

                iteration += exec_result.state.iteration;
            }
            Err(e) => {
                self.send_event(ExecutionEvent::Failed(e.clone()));
            }
        }

        // 检查是否达到最大迭代
        if iteration >= max_iterations {
            state.transition_to(AuditPhase::Verification);
        }

        let message = format!(
            "深度分析完成\n处理目标: {}\n确认漏洞: {}\nLLM 调用: {}\n活跃假设: {}",
            targets_processed,
            total_findings,
            state.stats.llm_calls,
            self.audit_chain.get_active_hypotheses().len()
        );

        PhaseResult {
            phase: AuditPhase::DeepAnalysis,
            success: true,
            message,
            targets_processed,
            findings_count: total_findings,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// 构建假设上下文
    fn build_hypotheses_context(&self) -> String {
        let mut context = String::from("## 当前漏洞假设\n\n");

        for (i, hypothesis) in self.audit_chain.hypotheses.iter().enumerate() {
            context.push_str(&format!(
                "### 假设 {}: {} (ID: {})\n",
                i + 1,
                hypothesis.vuln_type.display_name(),
                hypothesis.id
            ));
            context.push_str(&format!("- 位置: {}:{}\n", hypothesis.entry_point.file_path, hypothesis.entry_point.start_line));
            context.push_str(&format!("- 置信度: {:.0}%\n", hypothesis.current_confidence * 100.0));
            context.push_str(&format!("- 状态: {:?}\n", hypothesis.status));

            if !hypothesis.data_flow.is_empty() {
                context.push_str("- 数据流:\n");
                for step in &hypothesis.data_flow {
                    context.push_str(&format!("  - L{}: {} ({})\n", step.location.start_line, step.variable, step.description));
                }
            }
            context.push_str("\n");
        }

        context
    }

    /// 构建包含假设的分析用户消息
    fn build_analysis_user_message_with_hypotheses(&self, state: &SecurityAuditState) -> String {
        let mut message = String::from("请执行以下安全审计任务:\n\n");

        // 任务描述
        message.push_str("## 主要任务\n");
        message.push_str("1. 验证确定性扫描发现的候选漏洞\n");
        message.push_str("2. 深入分析高风险代码区域\n");
        message.push_str("3. 使用专业工具（trace_taint, detect_vulnerability_patterns）确认漏洞\n");
        message.push_str("4. 排除误报\n\n");

        // 假设列表
        let active_hypotheses = self.audit_chain.get_active_hypotheses();
        if !active_hypotheses.is_empty() {
            message.push_str("## 待验证的漏洞假设\n");
            for (i, hypothesis) in active_hypotheses.iter().enumerate() {
                message.push_str(&format!(
                    "{}. [{}] {} ({}:{}) - 置信度: {:.0}%\n",
                    i + 1,
                    hypothesis.vuln_type.base_severity().as_str().to_uppercase(),
                    hypothesis.vuln_type.display_name(),
                    hypothesis.entry_point.file_path,
                    hypothesis.entry_point.start_line,
                    hypothesis.current_confidence * 100.0
                ));
            }
            message.push_str("\n");
        }

        // 待验证的候选
        let high_confidence: Vec<_> = state.vulnerability_candidates
            .iter()
            .filter(|c| c.confidence >= 0.5)
            .take(10)
            .collect();

        if !high_confidence.is_empty() {
            message.push_str("## 高优先级候选漏洞\n");
            for (i, candidate) in high_confidence.iter().enumerate() {
                message.push_str(&format!(
                    "{}. [{}] {} ({}:{}) - 置信度: {:.0}%\n",
                    i + 1,
                    candidate.severity.to_uppercase(),
                    candidate.vulnerability_type,
                    candidate.file_path,
                    candidate.line,
                    candidate.confidence * 100.0
                ));
            }
            message.push_str("\n");
        }

        // 优先分析的目标
        message.push_str("## 优先分析文件\n");
        for (i, target) in state.pending_targets.iter().take(5).enumerate() {
            message.push_str(&format!("{}. {} - {}\n", i + 1, target.file_path, target.reason));
        }

        // 工具推荐
        let recommendations = self.tool_recommender.recommend(state);
        if !recommendations.is_empty() {
            message.push_str("\n## 推荐使用的工具\n");
            for rec in recommendations.iter().take(3) {
                message.push_str(&format!("- {} (优先级: {}): {}\n", rec.tool_name, rec.priority, rec.reason));
            }
        }

        message
    }

    /// 执行验证阶段 - 使用 LLM 做最终判断
    pub async fn execute_verification(&mut self, state: &mut SecurityAuditState) -> PhaseResult {
        let start = std::time::Instant::now();
        state.transition_to(AuditPhase::Verification);

        // 推进思维链到假设验证阶段
        self.audit_chain.record_thought(
            "开始 LLM 漏洞验证".to_string(),
            format!("使用 LLM 验证 {} 个候选漏洞", state.vulnerability_candidates.len()),
            Some("置信值作为辅助参考，LLM 做最终判断".to_string()),
        );

        // 收集所有待验证的候选漏洞（不再按置信值过滤）
        let pending_candidates: Vec<_> = state.vulnerability_candidates
            .iter()
            .filter(|c| c.verification_status == VerificationStatus::Pending)
            .cloned()
            .collect();

        let total_pending = pending_candidates.len();
        let mut confirmed = 0;
        let mut false_positives = 0;
        let mut needs_review = 0;

        if pending_candidates.is_empty() {
            // 没有待验证的候选漏洞
            self.audit_chain.advance_phase();
            state.transition_to(AuditPhase::Reporting);
            return PhaseResult {
                phase: AuditPhase::Verification,
                success: true,
                message: "没有待验证的候选漏洞".to_string(),
                targets_processed: 0,
                findings_count: 0,
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        self.send_event(ExecutionEvent::IterationStart(3));

        // 构建 LLM 验证请求
        let system_prompt = self.prompts.get_llm_verification_prompt().to_string();
        let user_message = self.prompts.build_llm_verification_message(
            &pending_candidates,
            &self.audit_chain.hypotheses,
            &self.audit_chain.evidence,
        );

        // 创建 ReAct 执行器
        let executor = ReactExecutor::new(
            self.llm.clone(),
            self.tool_registry.clone(),
            self.config.clone(),
        );

        // 构建代理上下文
        let agent_context = AgentContext {
            project_id: state.session_id.clone(),
            project_path: state.project_path.clone(),
            session_id: state.session_id.clone(),
            inherited_context: state.working_memory.clone(),
            user_context: std::collections::HashMap::new(),
        };

        // 执行 LLM 验证
        match executor.execute(&agent_context, &system_prompt, &user_message).await {
            Ok(exec_result) => {
                // 从 thought_chain 获取最后一个思考的输出
                let llm_output = exec_result.state.thought_chain
                    .last()
                    .map(|t| {
                        // 尝试获取 action_input 中的 JSON，否则使用 thought
                        if let Some(ref input) = t.action_input {
                            serde_json::to_string(input).unwrap_or_else(|_| t.thought.clone())
                        } else {
                            t.thought.clone()
                        }
                    })
                    .unwrap_or_default();

                // 解析 LLM 返回的验证结果
                let verification_results = self.parse_verification_results(&llm_output);

                if verification_results.is_empty() {
                    tracing::warn!("LLM 未返回有效的验证结果，候选漏洞保持待验证状态");
                    needs_review = total_pending;
                } else {
                    // 根据 LLM 判断更新状态
                    for result in verification_results {
                        match result.status {
                            VerificationStatus::Confirmed => {
                                state.confirm_vulnerability(&result.candidate_id);
                                self.update_hypothesis_status(&result.candidate_id, HypothesisStatus::Confirmed);
                                confirmed += 1;
                                tracing::info!(
                                    "LLM 确认漏洞 {}: {}",
                                    result.candidate_id,
                                    result.reason
                                );
                            }
                            VerificationStatus::FalsePositive => {
                                state.mark_false_positive(
                                    &result.candidate_id,
                                    Some(result.reason.clone())
                                );
                                self.update_hypothesis_status(&result.candidate_id, HypothesisStatus::FalsePositive);
                                false_positives += 1;
                                self.audit_chain.stats.false_positives_excluded += 1;
                                tracing::info!(
                                    "LLM 标记误报 {}: {}",
                                    result.candidate_id,
                                    result.reason
                                );
                            }
                            VerificationStatus::LikelyFalsePositive => {
                                // 可能误报，保留但标记
                                if let Some(candidate) = state.vulnerability_candidates
                                    .iter_mut()
                                    .find(|c| c.id == result.candidate_id)
                                {
                                    candidate.verification_status = VerificationStatus::LikelyFalsePositive;
                                    candidate.verification_result = Some(result.reason.clone());
                                }
                                needs_review += 1;
                                tracing::info!(
                                    "LLM 标记可能误报 {}: {}",
                                    result.candidate_id,
                                    result.reason
                                );
                            }
                            VerificationStatus::NeedsMoreInfo | VerificationStatus::Pending => {
                                // 需要更多信息，保持 Pending 状态
                                needs_review += 1;
                                tracing::info!(
                                    "候选漏洞 {} 需要更多信息: {}",
                                    result.candidate_id,
                                    result.reason
                                );
                            }
                        }
                    }
                }

                // 更新统计
                state.stats.llm_calls += 1;

                self.send_event(ExecutionEvent::ThoughtComplete {
                    iteration: 3,
                    thought: format!(
                        "LLM 验证完成: {} 确认, {} 误报, {} 待审核",
                        confirmed, false_positives, needs_review
                    ),
                    action: Some("llm_verification".to_string()),
                });

                self.send_event(ExecutionEvent::Complete {
                    iterations: 1,
                    tool_calls: 0,
                });
            }
            Err(e) => {
                // LLM 验证失败：保留为待验证状态，不做判断
                tracing::warn!("LLM 验证失败，候选漏洞保持待验证状态: {}", e);
                needs_review = total_pending;

                self.send_event(ExecutionEvent::Failed(format!("LLM verification failed: {}", e)));
            }
        }

        // 推进到结论阶段
        self.audit_chain.advance_phase();
        state.transition_to(AuditPhase::Reporting);

        PhaseResult {
            phase: AuditPhase::Verification,
            success: true,
            message: format!(
                "LLM 验证完成: {} 确认, {} 误报, {} 待人工审核",
                confirmed, false_positives, needs_review
            ),
            targets_processed: confirmed + false_positives,
            findings_count: confirmed,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// 解析 LLM 验证结果
    fn parse_verification_results(&self, llm_output: &str) -> Vec<crate::audit_state::LLMVerificationResult> {
        use crate::audit_state::LLMVerificationResult;

        let mut results = Vec::new();

        // 尝试从 LLM 输出中提取 JSON
        if let Ok(json_values) = self.extract_json_results(llm_output) {
            for json in json_values {
                match serde_json::from_value::<LLMVerificationResult>(json) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        tracing::debug!("解析验证结果失败: {}", e);
                    }
                }
            }
        }

        results
    }

    /// 从 LLM 输出中提取 JSON 结果
    fn extract_json_results(&self, output: &str) -> Result<Vec<serde_json::Value>, String> {
        let mut results = Vec::new();

        // 方法 1: 尝试提取 ```json ``` 代码块
        if let Some(json_blocks) = self.extract_json_code_blocks(output) {
            for block in json_blocks {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&block) {
                    self.collect_json_values(value, &mut results);
                }
            }
        }

        // 方法 2: 尝试解析 Action Input 中的 JSON
        if results.is_empty() {
            if let Some(action_input) = self.extract_action_input(output) {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&action_input) {
                    self.collect_json_values(value, &mut results);
                }
            }
        }

        // 方法 3: 尝试直接在整个输出中查找 JSON 对象
        if results.is_empty() {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(output) {
                self.collect_json_values(value, &mut results);
            }
        }

        if results.is_empty() {
            Err("未找到有效的 JSON 验证结果".to_string())
        } else {
            Ok(results)
        }
    }

    /// 提取 ```json ``` 代码块
    fn extract_json_code_blocks(&self, output: &str) -> Option<Vec<String>> {
        let mut blocks = Vec::new();
        let mut in_block = false;
        let mut current_block = String::new();

        for line in output.lines() {
            if line.trim().starts_with("```json") {
                in_block = true;
                current_block.clear();
            } else if line.trim() == "```" && in_block {
                in_block = false;
                if !current_block.trim().is_empty() {
                    blocks.push(current_block.clone());
                }
            } else if in_block {
                current_block.push_str(line);
                current_block.push('\n');
            }
        }

        if blocks.is_empty() {
            None
        } else {
            Some(blocks)
        }
    }

    /// 提取 Action Input 中的 JSON
    fn extract_action_input(&self, output: &str) -> Option<String> {
        // 查找 Action Input: 后面的内容
        if let Some(start) = output.find("Action Input:") {
            let remaining = &output[start + 12..];

            // 查找 JSON 开始位置
            if let Some(json_start) = remaining.find('{') {
                // 简单的括号匹配
                let mut depth = 0;
                let mut json_end = json_start;

                for (i, c) in remaining[json_start..].char_indices() {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                json_end = json_start + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                return Some(remaining[json_start..json_end].to_string());
            }
        }

        None
    }

    /// 从 JSON 值中收集验证结果
    fn collect_json_values(&self, value: serde_json::Value, results: &mut Vec<serde_json::Value>) {
        match value {
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.collect_json_values(item, results);
                }
            }
            serde_json::Value::Object(ref map) if map.contains_key("candidate_id") => {
                results.push(value);
            }
            _ => {}
        }
    }

    /// 更新假设状态
    fn update_hypothesis_status(&mut self, candidate_id: &str, status: HypothesisStatus) {
        // 查找对应的假设
        for hypothesis in &mut self.audit_chain.hypotheses {
            // 尝试通过 ID 或位置匹配
            if hypothesis.id == candidate_id {
                match status {
                    HypothesisStatus::Confirmed => {
                        hypothesis.mark_verified(1.0);
                        self.audit_chain.stats.confirmed_vulnerabilities += 1;
                    }
                    HypothesisStatus::FalsePositive => {
                        hypothesis.mark_false_positive("LLM 判断为误报");
                    }
                    _ => {}
                }
                break;
            }
        }
    }

    /// 执行报告阶段
    pub async fn execute_reporting(&mut self, state: &mut SecurityAuditState) -> PhaseResult {
        let start = std::time::Instant::now();
        state.transition_to(AuditPhase::Reporting);

        // 推进思维链到结论阶段
        self.audit_chain.record_thought(
            "生成审计报告".to_string(),
            format!("确认 {} 个漏洞，排除 {} 个误报",
                self.audit_chain.stats.confirmed_vulnerabilities,
                self.audit_chain.stats.false_positives_excluded),
            None,
        );

        let summary = state.generate_summary();

        // 获取思维链摘要
        let chain_summary = self.audit_chain.generate_summary();

        // 生成报告数据
        let report = serde_json::json!({
            "session_id": state.session_id,
            "project_path": state.project_path,
            "started_at": state.started_at.to_rfc3339(),
            "completed_at": chrono::Utc::now().to_rfc3339(),
            "project_info": state.project_info,
            "statistics": {
                "files_analyzed": state.stats.files_analyzed,
                "llm_calls": state.stats.llm_calls,
                "tool_calls": state.stats.tool_calls,
                "total_findings": state.confirmed_vulnerabilities.len(),
                "candidates": state.vulnerability_candidates.len(),
                "false_positives": state.false_positives.len(),
            },
            "audit_chain": {
                "phase": self.audit_chain.phase.display_name(),
                "hypotheses_generated": self.audit_chain.stats.hypotheses_generated,
                "confirmed_vulnerabilities": self.audit_chain.stats.confirmed_vulnerabilities,
                "false_positives_excluded": self.audit_chain.stats.false_positives_excluded,
                "evidence_collected": self.audit_chain.stats.evidence_collected,
                "thought_iterations": self.audit_chain.stats.thought_iterations,
            },
            "confirmed_vulnerabilities": state.confirmed_vulnerabilities,
            "hypotheses": self.audit_chain.hypotheses.iter()
                .filter(|h| h.status == HypothesisStatus::Confirmed)
                .map(|h| serde_json::json!({
                    "id": h.id,
                    "type": h.vuln_type.display_name(),
                    "cwe": h.vuln_type.cwe_id(),
                    "file": h.entry_point.file_path,
                    "line": h.entry_point.start_line,
                    "confidence": h.current_confidence,
                    "data_flow_steps": h.data_flow.len(),
                }))
                .collect::<Vec<_>>(),
            "by_severity": {
                "critical": state.confirmed_vulnerabilities.iter().filter(|v| v.severity == "critical").count(),
                "high": state.confirmed_vulnerabilities.iter().filter(|v| v.severity == "high").count(),
                "medium": state.confirmed_vulnerabilities.iter().filter(|v| v.severity == "medium").count(),
                "low": state.confirmed_vulnerabilities.iter().filter(|v| v.severity == "low").count(),
            },
        });

        state.set_memory("final_report", report);
        state.set_memory("chain_summary", serde_json::json!(chain_summary));

        state.transition_to(AuditPhase::Completed);

        PhaseResult {
            phase: AuditPhase::Reporting,
            success: true,
            message: format!("{}\n\n{}", summary, chain_summary),
            targets_processed: state.stats.files_analyzed,
            findings_count: state.confirmed_vulnerabilities.len(),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// 构建初始上下文
    fn build_initial_context(&self, state: &SecurityAuditState) -> String {
        let mut context = String::new();

        // 项目信息
        context.push_str(&format!(
            "项目类型: {}\n",
            state.project_info.project_type.as_deref().unwrap_or("未知")
        ));
        context.push_str(&format!(
            "技术栈: {}\n",
            state.project_info.tech_stack.join(", ")
        ));
        context.push_str(&format!(
            "框架: {}\n",
            state.project_info.frameworks.join(", ")
        ));
        context.push_str(&format!(
            "入口点: {}\n",
            state.project_info.entry_points.join(", ")
        ));

        // 候选漏洞摘要
        context.push_str(&format!(
            "\n候选漏洞数: {}\n",
            state.vulnerability_candidates.len()
        ));

        // 按类型统计
        let mut by_type = std::collections::HashMap::new();
        for candidate in &state.vulnerability_candidates {
            *by_type.entry(&candidate.vulnerability_type).or_insert(0) += 1;
        }
        context.push_str("漏洞类型分布:\n");
        for (vtype, count) in by_type {
            context.push_str(&format!("  - {}: {}\n", vtype, count));
        }

        context
    }

    /// 构建分析用户消息
    fn build_analysis_user_message(&self, state: &SecurityAuditState) -> String {
        let mut message = String::from("请执行以下安全审计任务:\n\n");

        // 任务描述
        message.push_str("## 主要任务\n");
        message.push_str("1. 验证确定性扫描发现的候选漏洞\n");
        message.push_str("2. 深入分析高风险代码区域\n");
        message.push_str("3. 使用专业工具（trace_taint, detect_vulnerability_patterns）确认漏洞\n");
        message.push_str("4. 排除误报\n\n");

        // 待验证的候选
        let high_confidence: Vec<_> = state.vulnerability_candidates
            .iter()
            .filter(|c| c.confidence >= 0.5)
            .take(10)
            .collect();

        if !high_confidence.is_empty() {
            message.push_str("## 高优先级候选漏洞\n");
            for (i, candidate) in high_confidence.iter().enumerate() {
                message.push_str(&format!(
                    "{}. [{}] {} ({}:{}) - 置信度: {:.0}%\n",
                    i + 1,
                    candidate.severity.to_uppercase(),
                    candidate.vulnerability_type,
                    candidate.file_path,
                    candidate.line,
                    candidate.confidence * 100.0
                ));
            }
            message.push_str("\n");
        }

        // 优先分析的目标
        message.push_str("## 优先分析文件\n");
        for (i, target) in state.pending_targets.iter().take(5).enumerate() {
            message.push_str(&format!("{}. {} - {}\n", i + 1, target.file_path, target.reason));
        }

        message
    }

    /// 发送事件
    fn send_event(&self, event: ExecutionEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event);
        }
    }

    // ========== 新模块集成方法 ==========

    /// 使用多 Agent 系统执行审计
    pub async fn execute_multi_agent_audit(&mut self, state: &mut SecurityAuditState) -> Result<PhaseResult, String> {
        if let Some(ref mut multi_agent) = self.multi_agent_system {
            tracing::info!("使用多 Agent 系统执行审计");

            let start = std::time::Instant::now();

            // 运行多 Agent 审计
            let audit_report = multi_agent.audit(state.project_path.clone(), state.clone()).await?;

            // 使用新的 API 获取发现数量
            let findings = audit_report.get_all_findings();
            let finding_count = findings.len();

            let duration = start.elapsed();

            Ok(PhaseResult {
                phase: AuditPhase::DeepAnalysis,
                success: true,
                message: format!("多 Agent 审计完成，发现 {} 个漏洞候选", finding_count),
                targets_processed: finding_count, // 使用 finding 数量作为目标处理数
                findings_count: finding_count,
                duration_ms: duration.as_millis() as u64,
            })
        } else {
            Err("多 Agent 系统未初始化".to_string())
        }
    }

    /// 使用语义理解引擎分析代码
    pub async fn execute_semantic_analysis(&self, code: &str, file_path: &str) -> Result<crate::semantic::SemanticUnderstanding, String> {
        use crate::semantic::SemanticContext;

        let context = SemanticContext {
            file_path: Some(file_path.to_string()),
            function_name: None,
            language: Some(self.detect_language(file_path)),
            framework: self.detect_framework(code),
            imports: vec![],
            decorators: vec![],
            extra: std::collections::HashMap::new(),
        };

        Ok(self.semantic_engine.understand_code(code, &context).await)
    }

    /// 执行业务逻辑分析
    pub async fn execute_business_logic_analysis(&self, code: &str, file_path: &str) -> Vec<crate::analysis::BusinessLogicFinding> {
        use crate::semantic::SemanticContext;

        // 提取 API 端点
        let endpoints = self.extract_api_endpoints(code, file_path);

        // 创建语义上下文
        let context = SemanticContext {
            file_path: Some(file_path.to_string()),
            function_name: None,
            language: Some(self.detect_language(file_path)),
            framework: self.detect_framework(code),
            imports: vec![],
            decorators: vec![],
            extra: std::collections::HashMap::new(),
        };

        // 运行业务逻辑分析器（async）
        let result = self.business_logic_analyzer.analyze(code, &context).await;

        result.findings
    }

    /// 执行全局数据流分析
    pub fn execute_global_flow_analysis(&mut self, project_path: &str) -> Result<crate::analysis::GlobalTaintResult, String> {
        if let Some(ref mut graph) = self.global_flow_graph {
            Ok(graph.build_taint_result())
        } else {
            Err("全局数据流图未初始化".to_string())
        }
    }

    /// 执行 Git 历史"举一反三"分析
    pub fn execute_git_learning_analysis(&self) -> Result<Vec<crate::analysis::SimilarVulnerabilityCandidate>, String> {
        if let Some(ref analyzer) = self.git_analyzer {
            // 提取漏洞修复记录
            let fixes = analyzer.extract_vulnerability_fixes();

            // 获取代码库文件
            let files = self.collect_project_files()?;

            // 查找相似未修复漏洞
            let similar = analyzer.find_similar_unfixed_vulnerabilities(&fixes, &files);

            Ok(similar)
        } else {
            Err("Git 分析器未初始化".to_string())
        }
    }

    /// 使用双重验证系统验证漏洞
    pub async fn execute_dual_verification(&self, candidate: &VulnerabilityCandidate) -> Result<crate::verification::EnhancedVerificationResult, String> {
        if let Some(ref verifier) = self.dual_verification {
            let context = crate::verification::VerificationContext {
                language: self.detect_language(&candidate.file_path),
                call_chain: vec![],
                data_flow: vec![],
                related_files: vec![],
                framework_info: None,
            };

            Ok(verifier.verify(candidate, &context).await)
        } else {
            Err("双重验证系统未初始化".to_string())
        }
    }

    /// 执行确定性审计
    pub async fn execute_deterministic_audit(&mut self, state: &mut SecurityAuditState) -> Result<crate::deterministic::AuditReproducibility, String> {
        if let Some(ref executor) = self.deterministic_executor {
            Ok(executor.execute_deterministic_audit(state).await?)
        } else {
            Err("确定性执行器未初始化".to_string())
        }
    }

    // ========== 辅助方法 ==========

    /// 检测编程语言
    fn detect_language(&self, file_path: &str) -> String {
        if file_path.ends_with(".rs") {
            "rust".to_string()
        } else if file_path.ends_with(".py") {
            "python".to_string()
        } else if file_path.ends_with(".js") {
            "javascript".to_string()
        } else if file_path.ends_with(".ts") {
            "typescript".to_string()
        } else if file_path.ends_with(".java") {
            "java".to_string()
        } else if file_path.ends_with(".go") {
            "go".to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// 检测框架
    fn detect_framework(&self, code: &str) -> Option<String> {
        if code.contains("from django") || code.contains("django.") {
            Some("Django".to_string())
        } else if code.contains("from flask") || code.contains("Flask") {
            Some("Flask".to_string())
        } else if code.contains("express") || code.contains("require('express')") {
            Some("Express".to_string())
        } else if code.contains("@SpringBootApplication") || code.contains("org.springframework") {
            Some("Spring".to_string())
        } else {
            None
        }
    }

    /// 提取 API 端点
    fn extract_api_endpoints(&self, code: &str, file_path: &str) -> Vec<crate::analysis::ApiEndpointInfo> {
        // 简化实现：返回空列表
        // 实际实现应该使用 AST 解析来提取端点信息
        vec![]
    }

    /// 收集项目文件
    fn collect_project_files(&self) -> Result<Vec<String>, String> {
        // 简化实现：返回空列表
        Ok(vec![])
    }
}

/// 执行器构建器
pub struct ExecutorBuilder {
    llm: Arc<dyn LLMClient>,
    tool_registry: Arc<ToolRegistry>,
    config: ExecutionConfig,
}

impl ExecutorBuilder {
    pub fn new(llm: Arc<dyn LLMClient>, tool_registry: Arc<ToolRegistry>) -> Self {
        Self {
            llm,
            tool_registry,
            config: ExecutionConfig::default(),
        }
    }

    pub fn with_max_iterations(mut self, max: u32) -> Self {
        self.config.max_iterations = Some(max);
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.config.timeout_secs = Some(secs);
        self
    }

    pub fn with_streaming(mut self, enable: bool) -> Self {
        self.config.enable_streaming = enable;
        self
    }

    pub fn build(self) -> PhaseAwareExecutor {
        PhaseAwareExecutor::new(self.llm, self.tool_registry, self.config)
    }
}
