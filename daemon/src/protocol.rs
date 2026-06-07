// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! IPC 协议定义
//!
//! 定义守护进程与客户端之间的通信协议

use serde::{Deserialize, Serialize};

/// IPC 请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// 认证令牌（Ping 请求可选，其他必须）
    #[serde(default)]
    pub auth_token: Option<String>,

    #[serde(flatten)]
    pub command: RequestCommand,
}

/// IPC 请求命令
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RequestCommand {
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
        #[serde(default)]
        deep: bool,
        #[serde(default)]
        enable_taint: bool,
        #[serde(default)]
        enable_cross_file: bool,
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

    /// 跨文件污点分析
    CrossFileAnalysis { path: String },

    /// 启动文件监控
    WatchStart { path: String, ignore_patterns: Vec<String> },

    /// 停止文件监控
    WatchStop { path: String },

    /// 查询调用图：谁调用了指定函数
    QueryCallers { project_path: String, file_path: String, function_name: String, recursive: Option<bool> },

    /// 查询调用图：指定函数调用了谁
    QueryCallees { project_path: String, file_path: String, function_name: String, recursive: Option<bool> },

    /// 查找 source→sink 调用路径
    FindCallPath { project_path: String, source_file: String, source_function: String, sink_file: String, sink_function: String },

    /// 获取调用图统计
    GetGraphStats { project_path: String },

    /// 列出文件中被索引的函数
    ListFileFunctions { project_path: String, file_path: String },

    /// 追踪变量流
    TraceVariableFlow { project_path: String, file_path: String, function_name: String },
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

    /// 跨文件污点分析结果
    CrossFileTaintResult { result: serde_json::Value },

    /// 监控已启动
    WatchStarted { path: String },

    /// 监控已停止
    WatchStopped { path: String },

    /// 错误
    Error { code: String, message: String },

    /// 调用图查询结果
    GraphQueryResult { result: serde_json::Value },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization_roundtrip() {
        // Test that Request with auth_token serializes/deserializes correctly
        let req = Request {
            auth_token: Some("test-token-123".into()),
            command: RequestCommand::Ping,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auth_token.unwrap(), "test-token-123");
        assert!(matches!(parsed.command, RequestCommand::Ping));
    }

    #[test]
    fn test_request_without_token() {
        let json = r#"{"type":"Ping"}"#;
        let parsed: Request = serde_json::from_str(json).unwrap();
        assert!(parsed.auth_token.is_none());
        assert!(matches!(parsed.command, RequestCommand::Ping));
    }

    #[test]
    fn test_scan_request_serialization() {
        let req = Request {
            auth_token: Some("tok".into()),
            command: RequestCommand::Scan {
                path: "/test/project".into(),
                deep: true,
                enable_taint: false,
                enable_cross_file: false,
                severity_filter: Some("high".into()),
                pattern_filter: None,
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.auth_token.unwrap(), "tok");
        match parsed.command {
            RequestCommand::Scan { path, deep, severity_filter, .. } => {
                assert_eq!(path, "/test/project");
                assert!(deep);
                assert_eq!(severity_filter.unwrap(), "high");
            }
            _ => panic!("Expected Scan command"),
        }
    }

    #[test]
    fn test_response_pong_serialization() {
        let resp = Response::Pong {
            version: "2.0.0".into(),
            uptime_secs: 42,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "Pong");
        assert_eq!(parsed["data"]["version"], "2.0.0");
        assert_eq!(parsed["data"]["uptime_secs"], 42);
    }

    #[test]
    fn test_response_error_serialization() {
        let resp = Response::Error {
            code: "auth_failed".into(),
            message: "Invalid token".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "Error");
        assert_eq!(parsed["data"]["code"], "auth_failed");
    }

    #[test]
    fn test_envelope_wraps_response() {
        let env = Envelope::new("msg-1", Response::Ack {
            message: "ok".into(),
        });
        let json = serde_json::to_string(&env).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "msg-1");
        assert_eq!(parsed["type"], "Ack");
        assert_eq!(parsed["data"]["message"], "ok");
    }

    #[test]
    fn test_all_request_commands_deserialize() {
        let commands = vec![
            r#"{"type":"Ping"}"#,
            r#"{"type":"Status"}"#,
            r#"{"type":"Shutdown"}"#,
            r#"{"type":"LoadProject","data":{"path":"/tmp/test"}}"#,
            r#"{"type":"Scan","data":{"path":"/tmp","deep":false,"enable_taint":true,"enable_cross_file":false,"severity_filter":null,"pattern_filter":null}}"#,
            r#"{"type":"Analyze","data":{"file_path":"src/main.rs","start_line":null,"end_line":null,"show_ast":true,"show_symbols":false}}"#,
            r#"{"type":"TraceTaint","data":{"file_path":"src/main.rs"}}"#,
            r#"{"type":"QuerySymbols","data":{"query":"main","limit":10}}"#,
            r#"{"type":"GetCallGraph","data":{"entry":"main","depth":3}}"#,
            r#"{"type":"CrossFileAnalysis","data":{"path":"/tmp"}}"#,
            r#"{"type":"WatchStart","data":{"path":"/tmp","ignore_patterns":[]}}"#,
            r#"{"type":"WatchStop","data":{"path":"/tmp"}}"#,
        ];

        for cmd_json in commands {
            let req: Request = serde_json::from_str(cmd_json).unwrap();
            assert!(req.auth_token.is_none());
        }
    }

    #[test]
    fn test_cache_stats_serialization() {
        let stats = CacheStats {
            ast_cache_entries: 5,
            taint_cache_entries: 10,
            scan_cache_entries: 3,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["ast_cache_entries"], 5);
        assert_eq!(parsed["taint_cache_entries"], 10);
    }
}
