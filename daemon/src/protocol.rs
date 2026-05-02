// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! IPC 协议定义
//!
//! 定义守护进程与客户端之间的通信协议

use serde::{Deserialize, Serialize};

/// IPC 请求
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Request {
    /// 心跳检测
    Ping,

    /// 查询状态
    Status,

    /// 关闭守护进程
    Shutdown,

    /// 加载项目
    LoadProject { path: String },

    /// 扫描项目
    Scan {
        path: String,
        deep: bool,
        severity_filter: Option<String>,
        pattern_filter: Option<String>,
    },

    /// 分析单个文件
    Analyze {
        file_path: String,
        start_line: Option<usize>,
        end_line: Option<usize>,
        show_ast: bool,
        show_symbols: bool,
    },

    /// 污点追踪
    TraceTaint { file_path: String },

    /// 查询符号
    QuerySymbols { query: String, limit: Option<usize> },

    /// 获取调用图
    GetCallGraph { entry: String, depth: Option<usize> },

    /// 启动文件监控
    WatchStart { path: String, ignore_patterns: Vec<String> },

    /// 停止文件监控
    WatchStop { path: String },
}

/// IPC 响应
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Response {
    /// 心跳响应
    Pong { version: String, uptime_secs: u64 },

    /// 状态信息
    StatusInfo {
        pid: u32,
        uptime_secs: u64,
        loaded_projects: Vec<String>,
        cache_stats: CacheStats,
    },

    /// 确认
    Ack { message: String },

    /// 扫描结果
    ScanResult {
        findings: Vec<serde_json::Value>,
        duration_ms: u64,
        files_scanned: usize,
    },

    /// 分析结果
    AnalysisResult { content: serde_json::Value },

    /// 污点分析结果
    TaintResult { flows: Vec<serde_json::Value> },

    /// 符号查询结果
    SymbolResults { symbols: Vec<serde_json::Value> },

    /// 调用图结果
    CallGraphResult { graph: serde_json::Value },

    /// 监控已启动
    WatchStarted { path: String },

    /// 监控已停止
    WatchStopped { path: String },

    /// 错误
    Error { code: String, message: String },
}

/// 缓存统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub ast_cache_entries: usize,
    pub taint_cache_entries: usize,
    pub scan_cache_entries: usize,
}

/// 消息信封（用于 NDJSON 传输）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    #[serde(flatten)]
    pub payload: Response,
}

impl Envelope {
    pub fn new(id: impl Into<String>, payload: Response) -> Self {
        Self { id: id.into(), payload }
    }
}
