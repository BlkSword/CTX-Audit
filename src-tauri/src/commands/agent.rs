// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::services::agent_service::AgentService;

/// Agent 服务状态
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentStatus {
    pub running: bool,
    pub port: u16,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
}

/// 启动 Agent 服务
#[tauri::command]
pub async fn start_agent_service(
    agent_service: tauri::State<'_, Arc<Mutex<AgentService>>>,
) -> Result<AgentStatus, String> {
    let service = agent_service.inner().clone();
    let mut service = service.lock().await;

    service.start()
        .map_err(|e| format!("Failed to start agent service: {}", e))?;

    Ok(service.get_status())
}

/// 停止 Agent 服务
#[tauri::command]
pub async fn stop_agent_service(
    agent_service: tauri::State<'_, Arc<Mutex<AgentService>>>,
) -> Result<(), String> {
    let service = agent_service.inner().clone();
    let mut service = service.lock().await;

    service.stop()
        .map_err(|e| format!("Failed to stop agent service: {}", e))
}

/// 获取 Agent 服务状态
#[tauri::command]
pub async fn get_agent_status(
    agent_service: tauri::State<'_, Arc<Mutex<AgentService>>>,
) -> Result<AgentStatus, String> {
    let service = agent_service.inner().clone();
    let service = service.lock().await;

    Ok(service.get_status())
}
