// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! IPC 客户端
//!
//! 供 CLI 连接守护进程

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::protocol::{Envelope, Request, Response};

/// 默认地址
const DEFAULT_ADDR: &str = "127.0.0.1:19527";

/// 守护进程 IPC 客户端
pub struct DaemonClient {
    stream: tokio::net::TcpStream,
}

impl DaemonClient {
    /// 连接到守护进程
    pub async fn connect() -> Result<Self> {
        let addr = Self::detect_addr()?;
        let stream = tokio::net::TcpStream::connect(&addr).await?;
        Ok(Self { stream })
    }

    /// 检测守护进程是否在运行
    pub async fn is_running() -> bool {
        Self::connect().await.is_ok()
    }

    /// 发送 ping 并等待 pong
    pub async fn ping(&mut self) -> Result<Response> {
        self.send_request(Request::Ping).await
    }

    /// 查询状态
    pub async fn status(&mut self) -> Result<Response> {
        self.send_request(Request::Status).await
    }

    /// 关闭守护进程
    pub async fn shutdown(&mut self) -> Result<Response> {
        self.send_request(Request::Shutdown).await
    }

    /// 加载项目
    pub async fn load_project(&mut self, path: String) -> Result<Response> {
        self.send_request(Request::LoadProject { path }).await
    }

    /// 扫描
    pub async fn scan(
        &mut self,
        path: String,
        deep: bool,
        severity_filter: Option<String>,
        pattern_filter: Option<String>,
    ) -> Result<Response> {
        self.send_request(Request::Scan {
            path,
            deep,
            severity_filter,
            pattern_filter,
        }).await
    }

    /// 污点追踪
    pub async fn trace_taint(&mut self, file_path: String) -> Result<Response> {
        self.send_request(Request::TraceTaint { file_path }).await
    }

    /// 发送请求并读取响应
    pub async fn send_request(&mut self, request: Request) -> Result<Response> {
        let json = serde_json::to_string(&request)?;
        self.stream.write_all(format!("{}\n", json).as_bytes()).await?;
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

    /// 自动检测守护进程地址（从 PID 文件或默认值）
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
