use actix_multipart::Multipart;
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::tempdir;
use futures_util::TryStreamExt;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Serialize, Deserialize)]
pub struct ScanRequest {
    pub project_path: String,
    #[serde(default)]
    pub project_id: Option<i64>,
    pub rules: Option<Vec<String>>,
}

#[derive(Serialize)]
pub struct Finding {
    pub id: String,
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub detector: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<String>,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub scan_time: String,
    pub scan_id: Option<i64>,
}

pub fn configure_scanner_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/scan", web::post().to(run_scan))
        .route("/upload", web::post().to(upload_and_scan))
        .route("/findings/{project_id}", web::get().to(get_findings))
        .route("/scans/{project_id}", web::get().to(get_scans));  // 新增：获取扫描历史
}

#[derive(Serialize)]
pub struct ScanRecord {
    pub id: i64,
    pub status: String,
    pub files_scanned: i64,
    pub findings_found: i64,
    pub started_at: String,
    pub completed_at: Option<String>,
}

/// 获取项目的扫描历史
pub async fn get_scans(
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> impl Responder {
    let project_id = path.into_inner();

    let scans = match sqlx::query_as::<_, (i64, String, i64, i64, String, Option<String>)>(
        "SELECT id, status, files_scanned, findings_found,
                datetime(started_at) as started_at,
                CASE WHEN completed_at IS NOT NULL
                     THEN datetime(completed_at)
                     ELSE NULL
                END as completed_at
         FROM scans
         WHERE project_id = ?
         ORDER BY started_at DESC"
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(scans) => scans,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch scans: {}", e)
            }));
        }
    };

    let scans: Vec<ScanRecord> = scans
        .into_iter()
        .map(|(id, status, files_scanned, findings_found, started_at, completed_at)| ScanRecord {
            id,
            status,
            files_scanned,
            findings_found,
            started_at,
            completed_at,
        })
        .collect();

    HttpResponse::Ok().json(scans)
}

/// 将扫描结果存储到数据库
async fn store_scan_results(
    state: &AppState,
    project_id: i64,
    findings: &[Finding],
    files_scanned: usize,
) -> Result<i64, Box<dyn std::error::Error>> {
    // 开始事务
    let mut tx = state.db.begin().await?;

    // 1. 创建扫描记录
    let scan_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO scans (project_id, status, files_scanned, findings_found)
         VALUES (?, 'running', 0, 0)
         RETURNING id"
    )
    .bind(project_id)
    .fetch_one(&mut *tx)
    .await?;

    // 2. 批量插入漏洞发现
    for finding in findings {
        // 检查是否已存在（基于 finding_id）
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM findings WHERE finding_id = ?"
        )
        .bind(&finding.id)
        .fetch_one(&mut *tx)
        .await?;

        if exists == 0 {
            // 插入新记录
            sqlx::query(
                "INSERT INTO findings (project_id, finding_id, file_path, line_start, line_end, detector, vuln_type, severity, description)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(project_id)
            .bind(&finding.id)
            .bind(&finding.file_path)
            .bind(finding.line_start as i64)
            .bind(finding.line_end as i64)
            .bind(&finding.detector)
            .bind(&finding.vuln_type)
            .bind(&finding.severity)
            .bind(&finding.description)
            .execute(&mut *tx)
            .await?;
        }
    }

    // 3. 更新扫描记录状态
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    sqlx::query(
        "UPDATE scans
         SET status = 'completed',
             files_scanned = ?,
             findings_found = ?,
             completed_at = ?
         WHERE id = ?"
    )
    .bind(files_scanned as i64)
    .bind(findings.len() as i64)
    .bind(&now)
    .bind(scan_id)
    .execute(&mut *tx)
    .await?;

    // 提交事务
    tx.commit().await?;

    Ok(scan_id)
}

pub async fn run_scan(
    state: web::Data<AppState>,
    req: web::Json<ScanRequest>,
) -> impl Responder {
    // 运行扫描
    let start = std::time::Instant::now();

    // 调用 core 库的扫描函数
    let core_findings = match deepaudit_core::scan_directory(&req.project_path).await {
        Ok(findings) => findings,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Scan failed: {}", e)
            }));
        }
    };

    let scan_time = format!("{:?}", start.elapsed());

    // 转换结果格式
    let findings: Vec<Finding> = core_findings
        .into_iter()
        .map(|f| Finding {
            id: f.finding_id,
            file_path: f.file_path,
            line_start: f.line_start,
            line_end: f.line_end,
            detector: f.detector,
            vuln_type: f.vuln_type,
            severity: f.severity,
            description: f.description,
            code_snippet: None,
        })
        .collect();

    let files_scanned = findings.len();
    let mut scan_id = None;

    // 如果提供了 project_id，将结果存入数据库
    if let Some(project_id) = req.project_id {
        match store_scan_results(&state, project_id, &findings, files_scanned).await {
            Ok(id) => {
                scan_id = Some(id);
                tracing::info!("Stored {} findings for project {}", findings.len(), project_id);
            }
            Err(e) => {
                tracing::error!("Failed to store scan results: {}", e);
                // 继续返回结果，即使存储失败
            }
        }
    } else {
        tracing::warn!("No project_id provided, scan results not stored to database");
    }

    HttpResponse::Ok().json(ScanResult {
        findings,
        files_scanned,
        scan_time,
        scan_id,
    })
}

pub async fn upload_and_scan(
    _state: web::Data<AppState>,
    mut payload: Multipart,
) -> impl Responder {
    // 创建临时目录
    let temp_dir_obj = match tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create temp dir: {}", e)
            }));
        }
    };
    let project_path = temp_dir_obj.path().to_string_lossy().to_string();

    // 处理上传的文件
    loop {
        match payload.try_next().await {
            Ok(Some(mut field)) => {
                let _name = field.name().unwrap_or("file").to_string();
                let filename = field.content_disposition()
                    .and_then(|cd| cd.get_filename())
                    .unwrap_or("unknown")
                    .to_string();

                let limit = 1024 * 1024 * 1024; // 1GB limit
                let data = match field.bytes(limit).await {
                    Ok(Ok(bytes)) => Vec::from(bytes.as_ref()),
                    Ok(Err(e)) => {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": format!("Failed to read field: {}", e)
                        }));
                    }
                    Err(_) => {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "File size limit exceeded"
                        }));
                    }
                };

                // 保存文件
                let file_path = std::path::PathBuf::from(&project_path).join(&filename);
                match std::fs::File::create(&file_path) {
                    Ok(mut file) => {
                        if let Err(e) = file.write_all(&data) {
                            return HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": format!("Failed to write file: {}", e)
                            }));
                        }
                    }
                    Err(e) => {
                        return HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": format!("Failed to create file: {}", e)
                        }));
                    }
                }
            }
            Ok(None) => {
                // 没有更多字段了，退出循环
                break;
            }
            Err(_) => {
                break;
            }
        }
    }

    // 运行扫描
    let findings = match deepaudit_core::scan_directory(&project_path).await {
        Ok(findings) => findings,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Scan failed: {}", e)
            }));
        }
    };

    let findings: Vec<Finding> = findings
        .into_iter()
        .map(|f| Finding {
            id: f.finding_id,
            file_path: f.file_path,
            line_start: f.line_start,
            line_end: f.line_end,
            detector: f.detector,
            vuln_type: f.vuln_type,
            severity: f.severity,
            description: f.description,
            code_snippet: None,
        })
        .collect();

    let files_scanned = findings.len();

    HttpResponse::Ok().json(ScanResult {
        findings,
        files_scanned,
        scan_time: "upload scan".to_string(),
        scan_id: None,
    })
}

pub async fn get_findings(
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> impl Responder {
    let project_id = path.into_inner();

    let findings = match sqlx::query_as::<_, (String, String, i64, i64, String, String, String, String, Option<String>)>(
        "SELECT finding_id, file_path, line_start, line_end, detector, vuln_type, severity, description, code_snippet
         FROM findings
         WHERE project_id = ?
         ORDER BY created_at DESC"
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(findings) => findings,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch findings: {}", e)
            }));
        }
    };

    let findings: Vec<Finding> = findings
        .into_iter()
        .map(|(id, file_path, line_start, line_end, detector, vuln_type, severity, description, code_snippet)| Finding {
            id,
            file_path,
            line_start: line_start as usize,
            line_end: line_end as usize,
            detector,
            vuln_type,
            severity,
            description,
            code_snippet,
        })
        .collect();

    HttpResponse::Ok().json(findings)
}
