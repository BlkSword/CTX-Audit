// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM Client 抽象层
//!
//! 定义 `LlmClient` trait，统一 noop / http / mcp_relay 三种调用模式。
//! Phase 1 仅实现 NoopLlmClient；Phase 2 增加 HttpLlmClient 与受控触发逻辑。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::{judge_finding, Verdict};
use crate::agent::prompts::build_triage_prompt;

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

impl LlmTriageResult {
    /// 从 LLM 返回的 JSON 字符串解析
    fn parse_from_json(text: &str) -> Result<Self> {
        // 尝试提取 JSON 代码块
        let json_text = if let Some(start) = text.find('{') {
            if let Some(end) = text.rfind('}') {
                &text[start..=end]
            } else {
                text
            }
        } else {
            text
        };

        let value: serde_json::Value =
            serde_json::from_str(json_text).context("LLM 返回不是合法 JSON")?;

        let verdict_str = value
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("needs_review");
        let verdict = match verdict_str {
            "true_positive" => Verdict::TruePositive,
            "false_positive" => Verdict::FalsePositive,
            _ => Verdict::NeedsReview,
        };

        let confidence = value
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5)
            .clamp(0.0, 1.0);

        let reasoning = value
            .get("reasoning")
            .and_then(|v| v.as_str())
            .unwrap_or("LLM 未提供理由")
            .to_string();

        let suggested_specialist = value
            .get("suggested_specialist")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && *s != "null")
            .map(String::from);

        Ok(LlmTriageResult {
            verdict,
            confidence,
            reasoning,
            suggested_specialist,
        })
    }
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

/// 受控 LLM Client：仅在满足触发条件时调用真实 LLM，否则退化为 Noop
pub struct ControlledLlmClient {
    inner: Arc<dyn LlmClient>,
    mode: String,
    max_calls: usize,
    calls_made: AtomicUsize,
}

impl ControlledLlmClient {
    pub fn new(inner: Arc<dyn LlmClient>, mode: String, max_calls: usize) -> Self {
        Self {
            inner,
            mode,
            max_calls,
            calls_made: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl LlmClient for ControlledLlmClient {
    async fn triage(&self, finding: &Finding, evidence: &Evidence) -> Result<LlmTriageResult> {
        // noop 模式直接退化为规则判定
        if self.mode == "noop" {
            return NoopLlmClient.triage(finding, evidence).await;
        }

        // 明显可判定的情况直接用规则，不浪费 LLM
        if evidence.has_effective_sanitizer {
            return NoopLlmClient.triage(finding, evidence).await;
        }
        if evidence.call_path.is_some()
            && evidence.barriers.is_empty()
            && !evidence.has_effective_sanitizer
        {
            return NoopLlmClient.triage(finding, evidence).await;
        }
        if evidence.call_path.is_none()
            && (!evidence.barriers.is_empty() || evidence.has_effective_sanitizer)
        {
            return NoopLlmClient.triage(finding, evidence).await;
        }

        // 只有证据冲突或不足时才调用 LLM
        if !should_call_llm(finding, evidence) {
            return NoopLlmClient.triage(finding, evidence).await;
        }

        // max_llm_calls 限制（0 表示不限制）
        if self.max_calls > 0 {
            let made = self.calls_made.fetch_add(1, Ordering::SeqCst);
            if made >= self.max_calls {
                self.calls_made.fetch_sub(1, Ordering::SeqCst);
                return NoopLlmClient.triage(finding, evidence).await;
            }
        }

        self.inner.triage(finding, evidence).await
    }
}

/// 判断是否值得调用 LLM
fn should_call_llm(finding: &Finding, evidence: &Evidence) -> bool {
    // NeedsReview 且 severity 较高
    let preliminary = judge_finding(finding, evidence);
    if preliminary == Verdict::NeedsReview {
        return matches!(
            finding.severity.to_lowercase().as_str(),
            "critical" | "high"
        );
    }

    // 高严重度且证据存在冲突
    let is_high = matches!(
        finding.severity.to_lowercase().as_str(),
        "critical" | "high"
    );
    let has_conflict = evidence.call_path.is_some()
        && (evidence.has_effective_sanitizer || !evidence.barriers.is_empty());

    is_high && has_conflict
}

/// HTTP LLM Client：支持 OpenAI / Anthropic / Ollama
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
    async fn triage(&self, finding: &Finding, evidence: &Evidence) -> Result<LlmTriageResult> {
        let prompt = build_triage_prompt(finding, evidence);
        let text = match self.provider.as_str() {
            "anthropic" => self.call_anthropic(&prompt).await?,
            _ => self.call_openai_compatible(&prompt).await?,
        };
        LlmTriageResult::parse_from_json(&text)
    }
}

impl HttpLlmClient {
    async fn call_openai_compatible(&self, prompt: &str) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_sec))
            .build()?;

        let url = self
            .endpoint
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1/chat/completions".to_string());

        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "user", "content": prompt }
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.1,
        });

        let mut req = client.post(&url).json(&body);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }

        let resp = req.send().await.context("LLM HTTP 请求失败")?;
        let status = resp.status();
        let resp_text = resp.text().await.context("读取 LLM 响应失败")?;
        if !status.is_success() {
            anyhow::bail!("LLM API 错误 ({}): {}", status, resp_text);
        }

        let value: serde_json::Value =
            serde_json::from_str(&resp_text).context("解析 LLM 响应 JSON 失败")?;
        value
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|msg| msg.get("content"))
            .and_then(|content| content.as_str())
            .map(|s| s.to_string())
            .context("LLM 响应中未找到 content")
    }

    async fn call_anthropic(&self, prompt: &str) -> Result<String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_sec))
            .build()?;

        let url = self
            .endpoint
            .clone()
            .unwrap_or_else(|| "https://api.anthropic.com/v1/messages".to_string());

        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                { "role": "user", "content": prompt }
            ],
        });

        let resp = client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
            .context("Anthropic HTTP 请求失败")?;

        let status = resp.status();
        let resp_text = resp.text().await.context("读取 Anthropic 响应失败")?;
        if !status.is_success() {
            anyhow::bail!("Anthropic API 错误 ({}): {}", status, resp_text);
        }

        let value: serde_json::Value =
            serde_json::from_str(&resp_text).context("解析 Anthropic 响应 JSON 失败")?;
        value
            .get("content")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|block| block.get("text"))
            .and_then(|text| text.as_str())
            .map(|s| s.to_string())
            .context("Anthropic 响应中未找到 text")
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

/// 根据配置构造受控 LlmClient
pub fn create_llm_client(agent_config: &crate::config::AgentConfig) -> Arc<dyn LlmClient> {
    let inner: Arc<dyn LlmClient> = match agent_config.llm_mode.as_str() {
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
    };

    Arc::new(ControlledLlmClient::new(
        inner,
        agent_config.llm_mode.clone(),
        agent_config.max_llm_calls,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::evidence::Evidence;
    use deepaudit_core::scanning::Finding;

    struct MockLlmClient {
        verdict: Verdict,
    }

    #[async_trait]
    impl LlmClient for MockLlmClient {
        async fn triage(
            &self,
            _finding: &Finding,
            _evidence: &Evidence,
        ) -> Result<LlmTriageResult> {
            Ok(LlmTriageResult {
                verdict: self.verdict,
                confidence: 0.8,
                reasoning: "mock llm".to_string(),
                suggested_specialist: None,
            })
        }
    }

    fn dummy_finding(severity: &str) -> Finding {
        Finding {
            finding_id: "test-1".to_string(),
            file_path: "app.js".to_string(),
            line_start: 10,
            line_end: 10,
            detector: "test".to_string(),
            vuln_type: "CWE-89".to_string(),
            severity: severity.to_string(),
            description: "test finding".to_string(),
            analysis_trail: None,
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: None,
            sink_snippet: None,
            file_role: Some("production".to_string()),
            barriers: None,
            reasoning_hint: None,
            evidence_refs: None,
        }
    }

    #[tokio::test]
    async fn test_controlled_client_respects_max_calls() {
        let inner = Arc::new(MockLlmClient {
            verdict: Verdict::TruePositive,
        });
        let controlled = ControlledLlmClient::new(inner, "http".to_string(), 1);

        // 构造一个会触发 LLM 的 finding：高严重度 + 证据冲突
        let mut evidence = Evidence::default();
        evidence.call_path = Some(deepaudit_core::CallPath {
            steps: vec![],
            total_hops: 1,
            crosses_files: false,
            files_in_path: vec![],
        });
        evidence.barriers = vec!["unknown".to_string()];

        let finding = dummy_finding("high");

        // 第一次调用真实 LLM
        let r1 = controlled.triage(&finding, &evidence).await.unwrap();
        assert_eq!(r1.verdict, Verdict::TruePositive);
        assert_eq!(r1.reasoning, "mock llm");

        // 第二次超过 max_calls，退化为 Noop
        let r2 = controlled.triage(&finding, &evidence).await.unwrap();
        assert!(r2.reasoning.starts_with("Noop LLM"));
    }

    #[tokio::test]
    async fn test_noop_mode_never_calls_inner() {
        let inner = Arc::new(MockLlmClient {
            verdict: Verdict::TruePositive,
        });
        let controlled = ControlledLlmClient::new(inner, "noop".to_string(), 10);

        let mut evidence = Evidence::default();
        evidence.call_path = Some(deepaudit_core::CallPath {
            steps: vec![],
            total_hops: 1,
            crosses_files: false,
            files_in_path: vec![],
        });
        evidence.barriers = vec!["unknown".to_string()];

        let finding = dummy_finding("critical");
        let r = controlled.triage(&finding, &evidence).await.unwrap();
        assert!(r.reasoning.starts_with("Noop LLM"));
    }

    #[test]
    fn test_parse_llm_json() {
        let text = r#"{"verdict":"false_positive","confidence":0.85,"reasoning":"有 sanitizer","suggested_specialist":null}"#;
        let r = LlmTriageResult::parse_from_json(text).unwrap();
        assert_eq!(r.verdict, Verdict::FalsePositive);
        assert!((r.confidence - 0.85).abs() < f64::EPSILON);
        assert_eq!(r.reasoning, "有 sanitizer");
        assert!(r.suggested_specialist.is_none());
    }
}
