use actix_multipart::Multipart;
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::io::Write;
use tempfile::tempdir;
use futures_util::TryStreamExt;

use crate::state::AppState;

#[derive(Serialize, Deserialize)]
pub struct ScanRequest {
    pub project_path: String,
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
}

pub fn configure_scanner_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/scan", web::post().to(run_scan))
        .route("/upload", web::post().to(upload_and_scan))
        .route("/findings/{project_id}", web::get().to(get_findings));
}

pub async fn run_scan(
    _state: web::Data<AppState>,
    req: web::Json<ScanRequest>,
) -> impl Responder {
    // 运行扫描
    let start = std::time::Instant::now();

    // 调用 core 库的扫描函数
    let findings = match deepaudit_core::scan_directory(&req.project_path).await {
        Ok(findings) => findings,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Scan failed: {}", e)
            }));
        }
    };

    let scan_time = format!("{:?}", start.elapsed());

    // 转换结果格式
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
        scan_time,
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
