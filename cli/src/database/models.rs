// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 数据库模型

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// 项目模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Project {
    pub id: i64,
    pub uuid: String,
    pub name: String,
    pub path: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_scanned_at: Option<String>,
    pub is_active: bool,
}

/// 创建项目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProject {
    pub uuid: String,
    pub name: String,
    pub path: String,
    pub description: Option<String>,
}

/// 审计会话模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditSession {
    pub id: i64,
    pub uuid: String,
    pub project_id: i64,
    pub session_type: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_iterations: Option<i32>,
    pub tokens_used: Option<i32>,
    pub error_message: Option<String>,
    pub metadata: Option<String>,
}

/// 漏洞发现模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Finding {
    pub id: i64,
    pub finding_id: String,
    pub project_id: i64,
    pub session_id: Option<i64>,
    pub scan_id: Option<String>,
    pub file_path: String,
    pub severity: String,
    pub category: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub start_line: Option<i32>,
    pub end_line: Option<i32>,
    pub code_snippet: Option<String>,
    pub status: String,
    pub confidence: Option<String>,
    pub false_positive: bool,
    pub created_at: String,
    pub updated_at: String,
    pub note: Option<String>,
    pub metadata: Option<String>,
}

/// 创建漏洞
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFinding {
    pub finding_id: String,
    pub project_id: i64,
    pub session_id: Option<i64>,
    pub scan_id: Option<String>,
    pub file_path: String,
    pub severity: String,
    pub category: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub start_line: Option<i32>,
    pub end_line: Option<i32>,
    pub code_snippet: Option<String>,
    pub confidence: Option<String>,
}

/// 更新漏洞
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateFinding {
    pub status: Option<String>,
    pub note: Option<String>,
    pub false_positive: Option<bool>,
}

/// Agent 事件模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentEvent {
    pub id: i64,
    pub session_id: i64,
    pub event_type: String,
    pub agent_type: Option<String>,
    pub timestamp: String,
    pub data: Option<String>,
}

/// 项目文件模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProjectFile {
    pub id: i64,
    pub project_id: i64,
    pub file_path: String,
    pub language: Option<String>,
    pub size: Option<i64>,
    pub last_modified: Option<String>,
    pub findings_count: i32,
    pub indexed_at: Option<String>,
}

/// 符号模型
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Symbol {
    pub id: i64,
    pub project_id: i64,
    pub file_path: String,
    pub symbol_name: String,
    pub symbol_type: String,
    pub line_number: i32,
    pub parent_name: Option<String>,
    pub signature: Option<String>,
    pub documentation: Option<String>,
    pub indexed_at: String,
}

/// 审计状态枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl std::fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditStatus::Pending => write!(f, "pending"),
            AuditStatus::Running => write!(f, "running"),
            AuditStatus::Paused => write!(f, "paused"),
            AuditStatus::Completed => write!(f, "completed"),
            AuditStatus::Failed => write!(f, "failed"),
            AuditStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for AuditStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(AuditStatus::Pending),
            "running" => Ok(AuditStatus::Running),
            "paused" => Ok(AuditStatus::Paused),
            "completed" => Ok(AuditStatus::Completed),
            "failed" => Ok(AuditStatus::Failed),
            "cancelled" => Ok(AuditStatus::Cancelled),
            _ => Err(anyhow::anyhow!("Invalid audit status: {}", s)),
        }
    }
}

/// 漏洞严重程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(anyhow::anyhow!("Invalid severity: {}", s)),
        }
    }
}

/// 漏洞状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Open,
    Fixed,
    Ignored,
}

impl std::fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingStatus::Open => write!(f, "open"),
            FindingStatus::Fixed => write!(f, "fixed"),
            FindingStatus::Ignored => write!(f, "ignored"),
        }
    }
}

impl std::str::FromStr for FindingStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "open" => Ok(FindingStatus::Open),
            "fixed" => Ok(FindingStatus::Fixed),
            "ignored" => Ok(FindingStatus::Ignored),
            _ => Err(anyhow::anyhow!("Invalid finding status: {}", s)),
        }
    }
}
