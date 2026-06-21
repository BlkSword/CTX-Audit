// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! IPC 客户端
//!
//! 供 CLI 连接守护进程，支持指数退避重连

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::Duration;

use crate::protocol::{Envelope, Request, RequestCommand, Response};
use crate::server::{heartbeat_file_path, read_token_file};

/// 默认地址
const DEFAULT_ADDR: &str = "127.0.0.1:19527";

/// 心跳过期阈值（秒）
const HEARTBEAT_STALE_SECS: i64 = 30;

/// 重连参数
const RECONNECT_MAX_RETRIES: u32 = 3;
const RECONNECT_BASE_DELAY_MS: u64 = 200;
const RECONNECT_MAX_DELAY_MS: u64 = 3000;

/// 守护进程 IPC 客户端
pub struct DaemonClient {
    stream: tokio::net::TcpStream,
    auth_token: Option<String>,
}

/// 心跳检测结果
#[derive(Debug, Clone)]
pub enum HeartbeatStatus {
    Alive {
        pid: u32,
        timestamp: String,
        uptime_secs: u64,
        version: String,
        age_secs: i64,
    },
    Stale {
        pid: u32,
        timestamp: String,
        age_secs: i64,
    },
    NoHeartbeat,
    ShuttingDown,
}

impl DaemonClient {
    /// 连接到守护进程（单次尝试）
    pub async fn connect() -> Result<Self> {
        let addr = Self::detect_addr()?;
        let stream = tokio::net::TcpStream::connect(&addr).await?;
        let auth_token = read_token_file();
        Ok(Self { stream, auth_token })
    }

    /// 带重试的连接（指数退避）
    pub async fn connect_with_retry() -> Result<Self> {
        let mut delay_ms = RECONNECT_BASE_DELAY_MS;
        let mut last_err = None;

        for attempt in 0..=RECONNECT_MAX_RETRIES {
            if attempt > 0 {
                tracing::debug!("重连尝试 {}/{}", attempt, RECONNECT_MAX_RETRIES);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                delay_ms = (delay_ms * 2).min(RECONNECT_MAX_DELAY_MS);
            }

            match Self::connect().await {
                Ok(client) => return Ok(client),
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("连接守护进程失败")))
    }

    /// 通过心跳文件快速检测 daemon 是否存活
    pub fn check_heartbeat() -> HeartbeatStatus {
        let path = heartbeat_file_path();
        if !path.exists() {
            return HeartbeatStatus::NoHeartbeat;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return HeartbeatStatus::NoHeartbeat,
        };

        let hb: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return HeartbeatStatus::NoHeartbeat,
        };

        let pid = hb.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let timestamp = hb
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if hb.get("status").and_then(|v| v.as_str()) == Some("shutting_down") {
            return HeartbeatStatus::ShuttingDown;
        }

        let age_secs = match chrono::DateTime::parse_from_rfc3339(&timestamp) {
            Ok(ts) => chrono::Utc::now()
                .signed_duration_since(ts.with_timezone(&chrono::Utc))
                .num_seconds(),
            Err(_) => {
                return HeartbeatStatus::Stale {
                    pid,
                    timestamp,
                    age_secs: i64::MAX,
                }
            }
        };

        if age_secs > HEARTBEAT_STALE_SECS {
            return HeartbeatStatus::Stale {
                pid,
                timestamp,
                age_secs,
            };
        }

        let version = hb
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let uptime_secs = hb.get("uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0);

        HeartbeatStatus::Alive {
            pid,
            timestamp,
            uptime_secs,
            version,
            age_secs,
        }
    }

    /// 综合检测存活
    pub async fn is_running() -> bool {
        match Self::check_heartbeat() {
            HeartbeatStatus::Alive { .. } | HeartbeatStatus::Stale { .. } => {
                Self::connect().await.is_ok()
            }
            HeartbeatStatus::ShuttingDown | HeartbeatStatus::NoHeartbeat => false,
        }
    }

    /// 清理残留文件
    pub fn cleanup_stale_files() {
        let hb_path = heartbeat_file_path();
        let pid_path = std::path::Path::new(".ctx-audit/daemon.pid");

        if hb_path.exists() {
            let _ = std::fs::remove_file(&hb_path);
        }
        if pid_path.exists() {
            let _ = std::fs::remove_file(pid_path);
        }
    }

    /// 发送请求（带自动重连）
    pub async fn send_request(&mut self, command: RequestCommand) -> Result<Response> {
        // 先尝试发送
        match self.try_send_request(&command).await {
            Ok(resp) => return Ok(resp),
            Err(e) if is_connection_error(&e) => {
                tracing::debug!("连接断开，尝试重连: {}", e);
            }
            Err(e) => return Err(e),
        }

        // 重连并重试
        let addr = Self::detect_addr()?;
        let mut delay_ms = RECONNECT_BASE_DELAY_MS;

        for attempt in 1..=RECONNECT_MAX_RETRIES {
            tracing::debug!("重连尝试 {}/{}", attempt, RECONNECT_MAX_RETRIES);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 2).min(RECONNECT_MAX_DELAY_MS);

            match tokio::net::TcpStream::connect(&addr).await {
                Ok(stream) => {
                    self.stream = stream;
                    tracing::debug!("重连成功");
                    return self.try_send_request(&command).await;
                }
                Err(_) => continue,
            }
        }

        anyhow::bail!("守护进程连接失败，已重试 {} 次", RECONNECT_MAX_RETRIES)
    }

    /// 单次发送请求（不重试）
    async fn try_send_request(&mut self, command: &RequestCommand) -> Result<Response> {
        let request = Request {
            auth_token: self.auth_token.clone(),
            command: command.clone(),
        };
        let json = serde_json::to_string(&request)?;
        self.stream
            .write_all(format!("{}\n", json).as_bytes())
            .await?;
        self.stream.flush().await?;

        let mut reader = BufReader::new(&mut self.stream);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            anyhow::bail!("守护进程关闭了连接");
        }

        let envelope: Envelope = serde_json::from_str(&line)?;
        Ok(envelope.payload)
    }

    pub async fn ping(&mut self) -> Result<Response> {
        self.send_request(RequestCommand::Ping).await
    }

    pub async fn status(&mut self) -> Result<Response> {
        self.send_request(RequestCommand::Status).await
    }

    pub async fn shutdown(&mut self) -> Result<Response> {
        self.send_request(RequestCommand::Shutdown).await
    }

    pub async fn load_project(&mut self, path: String) -> Result<Response> {
        self.send_request(RequestCommand::LoadProject { path })
            .await
    }

    pub async fn scan(
        &mut self,
        path: String,
        deep: bool,
        enable_taint: bool,
        enable_cross_file: bool,
        severity_filter: Option<String>,
        pattern_filter: Option<String>,
    ) -> Result<Response> {
        self.send_request(RequestCommand::Scan {
            path,
            deep,
            enable_taint,
            enable_cross_file,
            severity_filter,
            pattern_filter,
        })
        .await
    }

    pub async fn trace_taint(&mut self, file_path: String) -> Result<Response> {
        self.send_request(RequestCommand::TraceTaint { file_path })
            .await
    }

    fn detect_addr() -> Result<String> {
        let path = std::path::Path::new(".ctx-audit/daemon.pid");
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(addr) = val.get("addr").and_then(|v| v.as_str()) {
                        return Ok(addr.to_string());
                    }
                }
            }
        }
        Ok(DEFAULT_ADDR.to_string())
    }
}

/// 判断是否为连接类错误（需要重连）
fn is_connection_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("关闭了连接")
        || msg.contains("connection reset")
        || msg.contains("broken pipe")
        || msg.contains("connection refused")
        || msg.contains("unexpected eof")
}
