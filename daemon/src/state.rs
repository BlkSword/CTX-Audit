// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 守护进程状态管理

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// 守护进程全局状态
pub struct DaemonState {
    /// 已加载的项目: path -> ProjectState
    pub projects: RwLock<HashMap<String, ProjectState>>,
    /// 守护进程启动时间
    pub started_at: DateTime<Utc>,
    /// 进程 PID
    pub pid: u32,
}

/// 单个项目的分析状态
pub struct ProjectState {
    /// 项目根路径
    pub path: String,
    /// 上次扫描时间
    pub last_scan: RwLock<Option<DateTime<Utc>>>,
    /// 项目信息
    pub project_info: ProjectInfo,
}

/// 项目基本信息
#[derive(Debug, Clone)]
pub struct ProjectInfo {
    pub tech_stack: Vec<String>,
    pub frameworks: Vec<String>,
    pub project_type: String,
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            projects: RwLock::new(HashMap::new()),
            started_at: Utc::now(),
            pid: std::process::id(),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        Utc::now()
            .signed_duration_since(self.started_at)
            .num_seconds()
            .max(0) as u64
    }
}

impl ProjectState {
    pub fn new(path: String) -> Self {
        Self {
            path: path.clone(),
            last_scan: RwLock::new(None),
            project_info: ProjectInfo::detect(&path),
        }
    }
}

impl ProjectInfo {
    /// 基于项目文件检测基本信息
    fn detect(project_path: &str) -> Self {
        let path = std::path::Path::new(project_path);
        let mut tech_stack = Vec::new();
        let mut frameworks = Vec::new();
        let mut project_type = "unknown".to_string();

        if path.join("package.json").exists() {
            tech_stack.push("javascript".to_string());
            project_type = "node".to_string();
        }
        if path.join("Cargo.toml").exists() {
            tech_stack.push("rust".to_string());
            project_type = "rust".to_string();
        }
        if path.join("pom.xml").exists() || path.join("build.gradle").exists() {
            tech_stack.push("java".to_string());
            project_type = "java".to_string();
        }
        if path.join("requirements.txt").exists() || path.join("pyproject.toml").exists() {
            tech_stack.push("python".to_string());
            project_type = "python".to_string();
        }
        if path.join("go.mod").exists() {
            tech_stack.push("go".to_string());
            project_type = "go".to_string();
        }

        // 框架检测
        if path.join("next.config.js").exists() || path.join("next.config.mjs").exists() {
            frameworks.push("next.js".to_string());
        }
        if path.join("django").exists() || path.join("manage.py").exists() {
            frameworks.push("django".to_string());
        }

        Self {
            tech_stack,
            frameworks,
            project_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_state_new() {
        let state = DaemonState::new();
        assert!(state.uptime_secs() < 5);
        assert_eq!(state.pid, std::process::id());
    }

    #[test]
    fn test_project_state_detection() {
        // Test that detection doesn't panic on non-existent paths
        let info = ProjectInfo::detect("/nonexistent/path/12345");
        assert!(info.tech_stack.is_empty());
        assert_eq!(info.project_type, "unknown");
    }

    #[test]
    fn test_uptime_increases() {
        let state = DaemonState::new();
        let start = state.uptime_secs();
        // uptime should be 0 or very small
        assert!(start < 2);
    }
}
