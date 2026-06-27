// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM Client 抽象层
//!
//! 定义 `LlmClient` trait，统一 noop / http / mcp_relay 三种调用模式。
//! Phase 1 仅实现 NoopLlmClient，后续再接入真实 LLM API。

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::{judge_finding, Verdict};

/// LLM triage 结果
#[derive(Debug, Clone)]
pub struct LlmTriageResult {
    /// 判定结果
    pub verdict: Verdict,
    /// 置信度 0.0-1.0
    pub confidence: f64,
    /// 判定理由
    pub reasoning: String,
    /// 建议转发的 specialist（None 表示不转发）
    pub suggested_specialist: Option<String>,
}

/// LLM Client trait
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// 对单个 finding 做 LLM triage
    async fn triage(&self, finding: &Finding, evidence: &Evidence) -> Result<LlmTriageResult>;
}

/// 默认 Noop 实现：退化为规则判定器
pub struct NoopLlmClient;

#[async_trait]
impl LlmClient for NoopLlmClient {
    async fn triage(&self, finding: &Finding, evidence: &Evidence) -> Result<LlmTriageResult> {
        let verdict = judge_finding(finding, evidence);
        let confidence = match verdict {
            Verdict::NeedsReview => 0.5,
            _ => 0.9,
        };
        Ok(LlmTriageResult {
            verdict,
            confidence,
            reasoning: format!("Noop LLM 退化为规则判定: {}", verdict.as_str()),
            suggested_specialist: None,
        })
    }
}

/// HTTP LLM Client 占位（后续接入 OpenAI / Anthropic / Ollama）
pub struct HttpLlmClient {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub endpoint: Option<String>,
    pub timeout_sec: u64,
    pub max_tokens: usize,
}

#[async_trait]
impl LlmClient for HttpLlmClient {
    async fn triage(&self, _finding: &Finding, _evidence: &Evidence) -> Result<LlmTriageResult> {
        anyhow::bail!(
            "HTTP LLM client is not implemented yet (provider: {}, model: {})",
            self.provider,
            self.model
        )
    }
}

/// MCP Relay LLM Client 占位（通过 MCP 协议将 prompt 转发给外部 LLM）
pub struct McpRelayLlmClient;

#[async_trait]
impl LlmClient for McpRelayLlmClient {
    async fn triage(&self, _finding: &Finding, _evidence: &Evidence) -> Result<LlmTriageResult> {
        anyhow::bail!("MCP relay LLM client is not implemented yet")
    }
}

/// 根据配置构造 LlmClient
pub fn create_llm_client(agent_config: &crate::config::AgentConfig) -> Arc<dyn LlmClient> {
    match agent_config.llm_mode.as_str() {
        "http" => Arc::new(HttpLlmClient {
            provider: agent_config.llm.provider.clone(),
            model: agent_config.llm.model.clone(),
            api_key: agent_config.llm.api_key.clone(),
            endpoint: agent_config.llm.endpoint.clone(),
            timeout_sec: agent_config.llm.timeout_sec,
            max_tokens: agent_config.llm.max_tokens,
        }),
        "mcp_relay" => Arc::new(McpRelayLlmClient),
        _ => Arc::new(NoopLlmClient),
    }
}
