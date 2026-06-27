// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 判定抽象层（占位）
//!
//! 当前默认实现退化为规则判定器，避免引入外部网络依赖。
//! 未来可实现 `OpenAiJudge` / `AnthropicJudge` 等真实 LLM 调用器。

use anyhow::Result;

use deepaudit_core::scanning::Finding;

use crate::agent::evidence::Evidence;
use crate::agent::heuristics::{judge_finding, Judge, Verdict};

/// 规则判定器 —— 默认实现
pub struct RuleBasedJudge;

impl Judge for RuleBasedJudge {
    fn judge(&self, finding: &Finding, evidence: &Evidence) -> Result<Verdict> {
        Ok(judge_finding(finding, evidence))
    }
}

// TODO: 实现 LLM 判定器
// pub struct OpenAiJudge { client: ..., model: String }
// impl Judge for OpenAiJudge { ... }
