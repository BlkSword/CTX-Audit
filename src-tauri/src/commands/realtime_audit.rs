// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 实时审计命令
//!
//! 提供文件级实时审计功能，包括：
//! - 获取文件的所有漏洞
//! - 更新漏洞状态
//! - 增量扫描单个文件

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::services::database::{Database, ProjectStats, ProjectFile};

// ==================== 类型定义 ====================

/// 漏洞状态
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    New,
    Fixed,
    FalsePositive,
    Ignored,
    Verified,
}

/// 扫描结果
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub findings: Vec<Finding>,
    pub content_hash: String,
    pub cached: bool,
}

// 重新导出 Finding 类型
pub use crate::commands::scanner::Finding;

// ==================== Tauri Commands ====================

/// 获取文件的所有漏洞
#[tauri::command]
pub async fn get_file_findings(
    file_path: String,
    project_id: i64,
    db: State<'_, Database>,
) -> Result<Vec<Finding>, String> {
    db.get_file_findings(&file_path, project_id)
        .await
        .map_err(|e| e.to_string())
}

/// 更新漏洞状态
#[tauri::command]
pub async fn update_finding_status(
    finding_id: String,
    status: String,
    user_note: Option<String>,
    db: State<'_, Database>,
) -> Result<(), String> {
    // 解析状态
    let finding_status = match status.as_str() {
        "new" => FindingStatus::New,
        "fixed" => FindingStatus::Fixed,
        "false_positive" => FindingStatus::FalsePositive,
        "ignored" => FindingStatus::Ignored,
        "verified" => FindingStatus::Verified,
        _ => return Err("Invalid status".to_string()),
    };

    db.update_finding_status(&finding_id, finding_status, user_note)
        .await
        .map_err(|e| e.to_string())
}

/// 增量扫描单个文件
#[tauri::command]
pub async fn scan_file(
    file_path: String,
    project_id: i64,
    content: String,
    db: State<'_, Database>,
) -> Result<ScanResult, String> {
    // 1. 计算内容哈希
    let content_hash = calculate_content_hash(&content);

    // 2. 检查缓存
    if let Some(cache) = db
        .get_file_scan_cache(&file_path)
        .await
        .map_err(|e| e.to_string())?
    {
        if cache.content_hash == content_hash {
            // 缓存命中，返回缓存结果
            let findings: Vec<Finding> =
                serde_json::from_str(&cache.findings_json).map_err(|e| e.to_string())?;
            return Ok(ScanResult {
                file_path,
                findings,
                content_hash,
                cached: true,
            });
        }
    }

    // 3. 执行扫描（TODO: 调用核心库扫描）
    let findings = scan_file_content(&file_path, &content).await?;

    // 4. 保存到数据库
    db.save_scan_results(project_id, &file_path, &findings, &content_hash)
        .await
        .map_err(|e| e.to_string())?;

    // 5. 更新缓存
    let findings_json = serde_json::to_string(&findings).map_err(|e| e.to_string())?;
    db.update_file_scan_cache(&file_path, &content_hash, &findings_json)
        .await
        .map_err(|e| e.to_string())?;

    Ok(ScanResult {
        file_path,
        findings,
        content_hash,
        cached: false,
    })
}

/// 获取项目统计信息
#[tauri::command]
pub async fn get_project_stats(
    project_id: i64,
    db: State<'_, Database>,
) -> Result<ProjectStats, String> {
    db.get_project_stats(project_id)
        .await
        .map_err(|e| e.to_string())
}

/// 获取文件列表
#[tauri::command]
pub async fn get_project_files(
    project_id: i64,
    db: State<'_, Database>,
) -> Result<Vec<ProjectFile>, String> {
    db.get_project_files(project_id)
        .await
        .map_err(|e| e.to_string())
}

// ==================== 辅助函数 ====================

/// 计算内容哈希
fn calculate_content_hash(content: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 扫描文件内容（TODO: 实现真正的扫描逻辑）
async fn scan_file_content(_file_path: &str, _content: &str) -> Result<Vec<Finding>, String> {
    // TODO: 调用核心库扫描
    // 暂时返回空列表
    Ok(vec![])
}
