// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CTX-Audit Security Analysis Daemon
//!
//! 常驻后台的安全分析引擎，提供 AST 解析、污点分析、模式匹配等能力

pub mod agent_host;
pub mod client;
pub mod engine;
pub mod protocol;
pub mod server;
pub mod state;

/// 守护进程版本
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
