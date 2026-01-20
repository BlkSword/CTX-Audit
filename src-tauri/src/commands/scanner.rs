// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::services::database::Database;

/// 漏洞发现结果
#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Finding {
    pub id: String,
    pub file_path: String,
    pub line_start: i64,
    pub line_end: i64,
    pub detector: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    pub code_snippet: Option<String>,
    pub status: String,
    pub created_at: String,
}

/// 扫描结果
#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: i64,
    pub project_id: i64,
    pub status: String,
    pub files_scanned: i64,
    pub findings_found: i64,
    pub findings: Vec<Finding>,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// 扫描请求
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub project_path: String,
    pub project_id: Option<i64>,
    pub rules: Option<Vec<String>>,
}

/// 运行扫描
#[tauri::command]
pub async fn run_scan(
    req: ScanRequest,
    db: State<'_, Database>,
) -> Result<ScanResult, String> {
    use deepaudit_core::scan_directory;

    let project_id = req.project_id.unwrap_or(0);

    // 创建扫描记录
    let scan_id = db.create_scan(project_id).await
        .map_err(|e| format!("Failed to create scan record: {}", e))?;

    // 执行扫描 (core 库的 scan_directory 是 async 函数)
    let core_findings = scan_directory(&req.project_path).await
        .map_err(|e| format!("Scan failed: {}", e))?;

    // 转换发现结果
    let converted_findings: Vec<Finding> = core_findings
        .into_iter()
        .map(|f| Finding {
            id: f.finding_id,
            file_path: f.file_path,
            line_start: f.line_start as i64,
            line_end: f.line_end as i64,
            detector: f.detector,
            vuln_type: f.vuln_type,
            severity: f.severity,
            description: f.description,
            code_snippet: None,
            status: "new".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        })
        .collect();

    let files_scanned = converted_findings.len() as i64;
    let findings_found = converted_findings.len() as i64;

    // 保存发现结果到数据库
    for finding in &converted_findings {
        db.save_finding(scan_id, finding).await
            .map_err(|e| format!("Failed to save finding: {}", e))?;
    }

    // 更新扫描记录
    let result = ScanResult {
        id: scan_id,
        project_id,
        status: "completed".to_string(),
        files_scanned,
        findings_found,
        findings: converted_findings,
        started_at: chrono::Utc::now().to_rfc3339(),
        completed_at: Some(chrono::Utc::now().to_rfc3339()),
    };

    db.update_scan(scan_id, "completed", files_scanned as usize, findings_found as usize).await
        .map_err(|e| format!("Failed to update scan: {}", e))?;

    Ok(result)
}

/// 获取扫描结果
#[tauri::command]
pub async fn get_findings(
    project_id: i64,
    db: State<'_, Database>,
) -> Result<Vec<Finding>, String> {
    db.get_findings(project_id)
        .await
        .map_err(|e| format!("Failed to get findings: {}", e))
}
