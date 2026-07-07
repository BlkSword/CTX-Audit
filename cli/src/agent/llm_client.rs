// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM Client 抽象层
//!
//! 定义 `LlmClient` trait，统一 noop / http / mcp_relay 三种调用模式。
//! Phase 1 仅实现 NoopLlmClient；Phase 2 增加 HttpLlmClient 与受控触发逻辑。

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;

use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::{judge_finding, Verdict};
use crate::agent::investigator::{
    parse_investigation_decision, InvestigationDecision, InvestigationMemory, ToolDescription,
};
use crate::agent::prompts::{build_investigation_prompt, build_triage_prompt};

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

/// 从文本中按平衡大括号提取 JSON Value
///
/// 优先从 `{"actions"` 等已知关键字处开始解析，以跳过模型可能在 JSON 前附加的自然语言前缀。
pub fn extract_json_value(text: &str) -> Result<serde_json::Value> {
    // 1. 优先尝试包含 actions 的对象（规划/调查场景）
    if let Some(idx) = text.find("{\"actions\"") {
        if let Ok(v) = extract_balanced_json(&text[idx..]) {
            return Ok(v);
        }
    }

    // 2. 通用大括号提取
    extract_balanced_json(text)
}

fn extract_balanced_json(text: &str) -> Result<serde_json::Value> {
    let start = text.find('{').or_else(|| text.find('['));
    let start = start.context("LLM 响应中未找到 JSON")?;

    let mut depth = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut end = None;

    for (i, c) in text[start..].char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if c == '\\' {
                escape = true;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i + c.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }

    let end = end.context("LLM 响应中 JSON 括号不平衡")?;
    let json_text = &text[start..start + end];
    serde_json::from_str(json_text).context("LLM 响应 JSON 解析失败")
}

/// LLM Client trait
#[async_trait]
pub trait LlmClient: Send + Sync {
    /// 对单个 finding 做 LLM triage
    async fn triage(&self, finding: &Finding, evidence: &Evidence) -> Result<LlmTriageResult>;

    /// 通用对话接口，用于非 triage/调查场景（如启动引导中的目录分类）。
    /// 默认返回空字符串，表示不调用真实 LLM。
    async fn chat(&self, _prompt: &str) -> Result<String> {
        Ok(String::new())
    }

    /// JSON 模式对话接口。默认实现调用 chat 后按平衡大括号提取 JSON。
    /// 真实 LLM 实现应优先使用 provider 原生 JSON 模式（如 OpenAI response_format）。
    async fn chat_json(&self, prompt: &str) -> Result<serde_json::Value> {
        let text = self.chat(prompt).await?;
        extract_json_value(&text)
    }

    /// 调查阶段：LLM 决定下一步工具或结束调查
    ///
    /// 默认实现退化为基于证据的确定性决策，不调用真实 LLM。
    async fn investigate_decision(
        &self,
        finding: &Finding,
        evidence: &Evidence,
        _memory: &InvestigationMemory,
        _available_tools: &[ToolDescription],
    ) -> Result<InvestigationDecision> {
        Ok(default_investigation_decision(finding, evidence))
    }
}

/// 默认调查决策：证据充分则直接结束，否则返回 needs_review
fn default_investigation_decision(finding: &Finding, evidence: &Evidence) -> InvestigationDecision {
    let verdict = judge_finding(finding, evidence);
    let confidence = match verdict {
        Verdict::NeedsReview => 0.5,
        _ => 0.85,
    };
    InvestigationDecision::Finish {
        verdict,
        confidence,
        reasoning: format!(
            "Noop 调查模式：基于确定性证据直接判定为 {}",
            verdict.as_str()
        ),
    }
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
    /// 激进模式：跳过证据清晰度短接，对高严重度 finding 强制调用 LLM
    llm_aggressive: bool,
    max_calls: usize,
    calls_made: AtomicUsize,
    /// 按严重度分级的 LLM 调用预算
    max_calls_by_severity: HashMap<String, usize>,
    calls_made_by_severity: Mutex<HashMap<String, usize>>,
}

impl ControlledLlmClient {
    pub fn new(
        inner: Arc<dyn LlmClient>,
        mode: String,
        max_calls: usize,
        max_calls_by_severity: HashMap<String, usize>,
    ) -> Self {
        Self {
            inner,
            mode,
            llm_aggressive: false,
            max_calls,
            calls_made: AtomicUsize::new(0),
            max_calls_by_severity,
            calls_made_by_severity: Mutex::new(HashMap::new()),
        }
    }

    /// 设置激进模式
    pub fn with_aggressive(mut self, aggressive: bool) -> Self {
        self.llm_aggressive = aggressive;
        self
    }

    /// 检查并扣减 LLM 预算。
    /// 返回 true 表示预算充足，可以继续调用真实 LLM。
    fn try_consume_budget(&self, severity: &str) -> bool {
        let severity = severity.to_lowercase();

        // 1. 总预算检查与扣减
        if self.max_calls > 0 {
            let made = self.calls_made.fetch_add(1, Ordering::SeqCst);
            if made >= self.max_calls {
                self.calls_made.fetch_sub(1, Ordering::SeqCst);
                return false;
            }
        }

        // 2. 按严重度分级预算检查
        if let Some(&limit) = self.max_calls_by_severity.get(&severity) {
            if limit == 0 {
                // 0 表示该严重度不限制，只受总预算约束
                return true;
            }
            let mut map = self.calls_made_by_severity.lock().unwrap();
            let made = map.entry(severity).or_insert(0);
            if *made >= limit {
                // 该严重度预算耗尽，恢复总预算计数
                drop(map);
                self.calls_made.fetch_sub(1, Ordering::SeqCst);
                return false;
            }
            *made += 1;
        }

        true
    }
}

#[async_trait]
impl LlmClient for ControlledLlmClient {
    async fn chat(&self, prompt: &str) -> Result<String> {
        self.inner.chat(prompt).await
    }

    async fn chat_json(&self, prompt: &str) -> Result<serde_json::Value> {
        self.inner.chat_json(prompt).await
    }

    async fn triage(&self, finding: &Finding, evidence: &Evidence) -> Result<LlmTriageResult> {
        // noop 模式直接退化为规则判定
        if self.mode == "noop" {
            return NoopLlmClient.triage(finding, evidence).await;
        }

        // 非激进模式下，明显可判定的情况直接用规则，不浪费 LLM
        if !self.llm_aggressive {
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
        }

        // LLM 预算检查（总预算 + 按严重度分级预算）
        if !self.try_consume_budget(&finding.severity) {
            return NoopLlmClient.triage(finding, evidence).await;
        }

        self.inner.triage(finding, evidence).await
    }

    async fn investigate_decision(
        &self,
        finding: &Finding,
        evidence: &Evidence,
        memory: &InvestigationMemory,
        available_tools: &[ToolDescription],
    ) -> Result<InvestigationDecision> {
        // noop 模式直接退化为规则判定
        if self.mode == "noop" {
            return Ok(default_investigation_decision(finding, evidence));
        }

        // 非激进模式下，明显可判定的情况直接用规则，不浪费 LLM
        if !self.llm_aggressive {
            if evidence.has_effective_sanitizer {
                return Ok(default_investigation_decision(finding, evidence));
            }
            if evidence.call_path.is_some()
                && evidence.barriers.is_empty()
                && !evidence.has_effective_sanitizer
            {
                return Ok(default_investigation_decision(finding, evidence));
            }
            if evidence.call_path.is_none()
                && (!evidence.barriers.is_empty() || evidence.has_effective_sanitizer)
            {
                return Ok(default_investigation_decision(finding, evidence));
            }

            // 只有证据冲突或不足时才调用 LLM
            if !should_call_llm(finding, evidence) {
                return Ok(default_investigation_decision(finding, evidence));
            }
        }

        // LLM 预算检查（总预算 + 按严重度分级预算）
        if !self.try_consume_budget(&finding.severity) {
            return Ok(default_investigation_decision(finding, evidence));
        }

        self.inner
            .investigate_decision(finding, evidence, memory, available_tools)
            .await
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
    async fn chat(&self, prompt: &str) -> Result<String> {
        match self.provider.as_str() {
            "anthropic" => self.call_anthropic(prompt).await,
            _ => self.call_openai_compatible(prompt).await,
        }
    }

    async fn chat_json(&self, prompt: &str) -> Result<serde_json::Value> {
        match self.provider.as_str() {
            "anthropic" => {
                let text = self.call_anthropic(prompt).await?;
                extract_json_value(&text)
            }
            _ => self.call_openai_compatible_json(prompt).await,
        }
    }

    async fn triage(&self, finding: &Finding, evidence: &Evidence) -> Result<LlmTriageResult> {
        let prompt = build_triage_prompt(finding, evidence);
        let text = match self.provider.as_str() {
            "anthropic" => self.call_anthropic(&prompt).await?,
            _ => self.call_openai_compatible(&prompt).await?,
        };
        LlmTriageResult::parse_from_json(&text)
    }

    async fn investigate_decision(
        &self,
        finding: &Finding,
        evidence: &Evidence,
        memory: &InvestigationMemory,
        available_tools: &[ToolDescription],
    ) -> Result<InvestigationDecision> {
        let prompt = build_investigation_prompt(finding, evidence, memory, available_tools);
        let text = match self.provider.as_str() {
            "anthropic" => self.call_anthropic(&prompt).await?,
            _ => self.call_openai_compatible(&prompt).await?,
        };
        parse_investigation_decision(&text)
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
        let message = value
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"));

        let content = message
            .and_then(|msg| msg.get("content"))
            .and_then(|content| content.as_str())
            .unwrap_or("");

        if !content.is_empty() {
            return Ok(content.to_string());
        }

        // 兼容 DeepSeek 等 reasoning 模型：content 为空时读取 reasoning_content
        message
            .and_then(|msg| msg.get("reasoning_content"))
            .and_then(|r| r.as_str())
            .map(|s| s.to_string())
            .context("LLM 响应中未找到 content 或 reasoning_content")
    }

    /// OpenAI 兼容 JSON 模式调用
    async fn call_openai_compatible_json(&self, prompt: &str) -> Result<serde_json::Value> {
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
                { "role": "system", "content": "You are a helpful coding audit assistant. Always respond with valid JSON only." },
                { "role": "user", "content": prompt }
            ],
            "max_tokens": self.max_tokens,
            "temperature": 0.1,
            "response_format": { "type": "json_object" },
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
        let message = value
            .get("choices")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"));

        let content = message
            .and_then(|msg| msg.get("content"))
            .and_then(|content| content.as_str())
            .unwrap_or("");

        if !content.is_empty() {
            return serde_json::from_str(content)
                .or_else(|_| extract_json_value(content))
                .with_context(|| {
                    format!(
                        "无法从 content 解析 JSON: {}",
                        content.chars().take(500).collect::<String>()
                    )
                });
        }

        message
            .and_then(|msg| msg.get("reasoning_content"))
            .and_then(|r| r.as_str())
            .map(|s| {
                serde_json::from_str(s)
                    .or_else(|_| extract_json_value(s))
                    .with_context(|| {
                        format!(
                            "无法从 reasoning_content 解析 JSON: {}",
                            s.chars().take(500).collect::<String>()
                        )
                    })
            })
            .transpose()
            .and_then(|v| v.context("LLM 响应中未找到 content 或 reasoning_content"))
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
///
/// 当 `llm_mode=http` 但未配置 API key（且不是本地 Ollama endpoint）时，
/// 自动回退到 NoopLlmClient，避免无 key 时直接报错。
pub fn create_llm_client(agent_config: &crate::config::AgentConfig) -> Arc<dyn LlmClient> {
    let mode = agent_config.llm_mode.as_str();

    let (inner, effective_mode): (Arc<dyn LlmClient>, String) = match mode {
        "http" => {
            let mut api_key = agent_config.llm.api_key.clone();
            if api_key.is_empty() {
                if let Ok(key) = std::env::var("CTX_AUDIT_LLM_API_KEY") {
                    api_key = key;
                }
            }

            let endpoint = agent_config.llm.endpoint.as_deref().unwrap_or("");
            let is_local_endpoint = endpoint.contains("127.0.0.1")
                || endpoint.contains("localhost")
                || endpoint.contains(":11434");
            let is_ollama = agent_config.llm.provider.eq_ignore_ascii_case("ollama");

            if api_key.is_empty() && !(is_ollama || is_local_endpoint) {
                tracing::warn!(
                    "agent.llm_mode=http 但未配置 API key（也未设置 CTX_AUDIT_LLM_API_KEY），\
                     回退到 noop LLM 客户端。请在配置文件中设置 agent.llm.api_key 或环境变量。"
                );
                (Arc::new(NoopLlmClient), "noop".to_string())
            } else {
                (
                    Arc::new(HttpLlmClient {
                        provider: agent_config.llm.provider.clone(),
                        model: agent_config.llm.model.clone(),
                        api_key,
                        endpoint: agent_config.llm.endpoint.clone(),
                        timeout_sec: agent_config.llm.timeout_sec,
                        max_tokens: agent_config.llm.max_tokens,
                    }),
                    "http".to_string(),
                )
            }
        }
        "mcp_relay" => (Arc::new(McpRelayLlmClient), "mcp_relay".to_string()),
        _ => (Arc::new(NoopLlmClient), "noop".to_string()),
    };

    Arc::new(
        ControlledLlmClient::new(
            inner,
            effective_mode,
            agent_config.max_llm_calls,
            agent_config.max_llm_calls_by_severity.clone(),
        )
        .with_aggressive(agent_config.llm_aggressive),
    )
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
        let controlled = ControlledLlmClient::new(inner, "http".to_string(), 1, HashMap::new());

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
        let controlled = ControlledLlmClient::new(inner, "noop".to_string(), 10, HashMap::new());

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

    #[tokio::test]
    async fn test_controlled_client_respects_severity_budget() {
        let inner = Arc::new(MockLlmClient {
            verdict: Verdict::TruePositive,
        });
        let mut budget = HashMap::new();
        budget.insert("high".to_string(), 1usize);
        // critical 不限制，只受总预算约束
        let controlled = ControlledLlmClient::new(inner, "http".to_string(), 2, budget);

        let mut evidence = Evidence::default();
        evidence.call_path = Some(deepaudit_core::CallPath {
            steps: vec![],
            total_hops: 1,
            crosses_files: false,
            files_in_path: vec![],
        });
        evidence.barriers = vec!["unknown".to_string()];

        let finding_high = dummy_finding("high");
        let r1 = controlled.triage(&finding_high, &evidence).await.unwrap();
        assert_eq!(r1.reasoning, "mock llm");

        // high 严重度预算已耗尽，第二次退化为 Noop
        let r2 = controlled.triage(&finding_high, &evidence).await.unwrap();
        assert!(r2.reasoning.starts_with("Noop LLM"));
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
