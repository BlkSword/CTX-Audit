// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 错误定义

use thiserror::Error;

/// LLM 错误
#[derive(Debug, Error)]
pub enum LLMError {
    #[error("请求失败: {0}")]
    RequestFailed(String),

    #[error("响应解析失败: {0}")]
    InvalidResponse(String),

    #[error("认证失败")]
    AuthenticationFailed,

    #[error("速率限制")]
    RateLimited,

    #[error("超时")]
    Timeout,

    #[error("配置错误: {0}")]
    ConfigError(String),

    #[error("未知错误: {0}")]
    Unknown(String),
}

impl LLMError {
    /// 获取错误代码
    pub fn code(&self) -> &str {
        match self {
            LLMError::RequestFailed(_) => "request_failed",
            LLMError::InvalidResponse(_) => "invalid_response",
            LLMError::AuthenticationFailed => "authentication_failed",
            LLMError::RateLimited => "rate_limited",
            LLMError::Timeout => "timeout",
            LLMError::ConfigError(_) => "config_error",
            LLMError::Unknown(_) => "unknown",
        }
    }
}
