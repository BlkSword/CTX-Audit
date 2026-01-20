// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use crate::commands::agent::AgentStatus;
use std::process::{Child, Command};
use std::time::{SystemTime, UNIX_EPOCH};

/// Agent 服务管理器
pub struct AgentService {
    process: Option<Child>,
    port: u16,
    start_time: Option<SystemTime>,
}

impl AgentService {
    /// 创建新的 Agent 服务
    pub fn new(port: u16) -> Self {
        Self {
            process: None,
            port,
            start_time: None,
        }
    }

    /// 启动 Agent 服务
    pub fn start(&mut self) -> Result<(), String> {
        if self.process.is_some() {
            return Err("Agent service is already running".to_string());
        }

        // 检查 Python 是否可用
        let python_check = Command::new("python")
            .args(["--version"])
            .output();

        match python_check {
            Ok(_) => {
                // 启动 Python Agent 服务
                let child = Command::new("python")
                    .args(["-m", "app.main"])
                    .current_dir("./agent-service")
                    .env("AGENT_PORT", self.port.to_string())
                    .spawn()
                    .map_err(|e| format!("Failed to start agent service: {}", e))?;

                self.process = Some(child);
                self.start_time = Some(SystemTime::now());

                tracing::info!("Agent service started on port {}", self.port);
                Ok(())
            }
            Err(e) => {
                Err(format!("Python not found: {}. Please ensure Python is installed.", e))
            }
        }
    }

    /// 停止 Agent 服务
    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(mut child) = self.process.take() {
            child.kill()
                .map_err(|e| format!("Failed to stop agent service: {}", e))?;
            self.start_time = None;
            tracing::info!("Agent service stopped");
            Ok(())
        } else {
            Err("Agent service is not running".to_string())
        }
    }

    /// 获取服务状态
    pub fn get_status(&self) -> AgentStatus {
        let uptime = self.start_time
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        AgentStatus {
            running: self.process.is_some(),
            port: self.port,
            pid: self.process.as_ref().map(|p| p.id()),
            uptime_secs: uptime,
        }
    }

    /// 检查服务是否运行中
    pub fn is_running(&mut self) -> bool {
        if let Some(child) = &mut self.process {
            child.try_wait().ok().flatten().is_none()
        } else {
            false
        }
    }
}

impl Drop for AgentService {
    fn drop(&mut self) {
        // 自动停止服务
        if self.process.is_some() {
            let _ = self.stop();
        }
    }
}
