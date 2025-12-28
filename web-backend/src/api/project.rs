use actix_multipart::Multipart;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use futures_util::TryStreamExt;

use crate::state::AppState;

#[derive(Serialize, Deserialize, FromRow)]
pub struct Project {
    pub id: i64,
    pub uuid: String,
    pub name: String,
    pub path: String,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub path: String,
}

#[derive(Deserialize)]
pub struct UploadProjectRequest {
    pub name: String,
}

pub fn configure_project_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // RESTful 风格路由
        .route("", web::post().to(create_project))           // POST /api/projects
        .route("/upload", web::post().to(upload_project))    // POST /api/projects/upload
        .route("", web::get().to(list_projects))             // GET /api/projects
        .route("/{uuid}", web::get().to(get_project))        // GET /api/projects/{uuid}
        .route("/{uuid}", web::delete().to(delete_project)); // DELETE /api/projects/{uuid}
}

async fn create_project(
    state: web::Data<AppState>,
    req: web::Json<CreateProjectRequest>,
) -> impl Responder {
    let uuid = Uuid::new_v4().to_string();
    let result = sqlx::query("INSERT INTO projects (uuid, name, path) VALUES (?, ?, ?)")
        .bind(&uuid)
        .bind(&req.name)
        .bind(&req.path)
        .execute(&state.db)
        .await;

    match result {
        Ok(result) => {
            let id = result.last_insert_rowid();
            match sqlx::query_as::<_, Project>(
                "SELECT id, uuid, name, path, datetime(created_at) as created_at FROM projects WHERE id = ?"
            )
            .bind(id)
            .fetch_one(&state.db)
            .await
            {
                Ok(project) => HttpResponse::Ok().json(project),
                Err(e) => {
                    tracing::error!("Failed to fetch project: {}", e);
                    HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Failed to fetch project: {}", e)
                    }))
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to create project: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create project: {}", e)
            }))
        }
    }
}

async fn upload_project(
    state: web::Data<AppState>,
    mut payload: Multipart,
    _req: HttpRequest,
) -> impl Responder {
    tracing::info!("Starting project upload...");

    let mut name = String::new();
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename = String::new();

    // 解析 multipart 表单 - 使用循环处理所有字段
    loop {
        match payload.try_next().await {
            Ok(Some(mut field)) => {
                let field_name = field.name().unwrap_or("").to_string();
                tracing::debug!("Processing field: {}", field_name);

                if field_name == "name" {
                    // bytes 方法需要 limit 参数
                    let limit = 1024 * 1024; // 1MB limit for name
                    match field.bytes(limit).await {
                        Ok(Ok(data)) => {
                            name = String::from_utf8(Vec::from(data.as_ref())).unwrap_or_default();
                            tracing::info!("Project name: {}", name);
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Failed to read name field: {}", e);
                            return HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": format!("Failed to read name: {}", e)
                            }));
                        }
                        Err(_) => {
                            return HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Limit exceeded for name field"
                            }));
                        }
                    }
                } else if field_name == "file" {
                    let content_type = field.content_type()
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "application/octet-stream".to_string());

                    // 获取文件名 - 尝试从 content_disposition 获取
                    let file_name = field.content_disposition()
                        .and_then(|cd| cd.get_filename())
                        .unwrap_or("unknown.zip")
                        .to_string();
                    filename = file_name.clone();

                    tracing::info!("Receiving file: {} (content-type: {})", filename, content_type);

                    // 验证是 ZIP 文件
                    if !file_name.ends_with(".zip") {
                        tracing::error!("Invalid file format: {}", file_name);
                        return HttpResponse::BadRequest().json(serde_json::json!({
                            "error": "Only ZIP files are allowed"
                        }));
                    }

                    // 读取文件数据
                    let limit = 1024 * 1024 * 1024; // 1GB limit for file
                    match field.bytes(limit).await {
                        Ok(Ok(data)) => {
                            file_data = Some(Vec::from(data.as_ref()));
                            tracing::info!("File data received: {} bytes", file_data.as_ref().map(|d| d.len()).unwrap_or(0));
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Failed to read file data: {}", e);
                            return HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": format!("Failed to read file: {}", e)
                            }));
                        }
                        Err(_) => {
                            return HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "File size limit exceeded"
                            }));
                        }
                    }
                }
                // 继续处理下一个字段
            }
            Ok(None) => {
                // 没有更多字段了，退出循环
                tracing::info!("All fields processed");
                break;
            }
            Err(e) => {
                tracing::error!("Failed to read multipart field: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to read multipart: {}", e)
                }));
            }
        }
    }

    if name.is_empty() {
        tracing::error!("Project name is empty");
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Project name is required"
        }));
    }

    let file_data = match file_data {
        Some(data) => data,
        None => {
            tracing::error!("No file data received");
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No file uploaded"
            }));
        }
    };

    tracing::info!("Uploading project: {} from file: {}", name, filename);

    // 创建项目目录
    let projects_dir = std::path::PathBuf::from("./data/projects");
    if let Err(e) = std::fs::create_dir_all(&projects_dir) {
        tracing::error!("Failed to create projects directory: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create projects directory: {}", e)
        }));
    }

    let project_id = Uuid::new_v4();
    let project_dir = projects_dir.join(format!("{}_{}", name.replace(" ", "_"), project_id));
    if let Err(e) = std::fs::create_dir_all(&project_dir) {
        tracing::error!("Failed to create project directory: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create project directory: {}", e)
        }));
    }

    tracing::info!("Created project directory: {:?}", project_dir);

    // 保存上传的 ZIP 文件
    let zip_path = project_dir.join("upload.zip");
    match std::fs::File::create(&zip_path) {
        Ok(mut file) => {
            if let Err(e) = std::io::Write::write_all(&mut file, &file_data) {
                tracing::error!("Failed to write zip file: {}", e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to write zip file: {}", e)
                }));
            }
        }
        Err(e) => {
            tracing::error!("Failed to create zip file: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create zip file: {}", e)
            }));
        }
    }

    tracing::info!("Saved ZIP file: {}, size: {} bytes", zip_path.display(), file_data.len());

    // 解压 ZIP 文件
    let extract_dir = project_dir.join("code");
    if let Err(e) = std::fs::create_dir_all(&extract_dir) {
        tracing::error!("Failed to create extract directory: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create extract directory: {}", e)
        }));
    }

    // 使用 zip 解压
    let zip_file = match std::fs::File::open(&zip_path) {
        Ok(file) => file,
        Err(e) => {
            tracing::error!("Failed to open zip file: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to open zip: {}", e)
            }));
        }
    };

    let mut archive = match zip::ZipArchive::new(zip_file) {
        Ok(archive) => archive,
        Err(e) => {
            tracing::error!("Failed to create zip archive: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create zip archive: {}", e)
            }));
        }
    };

    tracing::info!("Extracting ZIP archive with {} files...", archive.len());

    // 手动解压每个文件（zip 2.x 兼容方式）
    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(file) => file,
            Err(e) => {
                tracing::error!("Failed to get file at index {}: {}", i, e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to get file at index {}: {}", i, e)
                }));
            }
        };

        let enclosed_name = file.enclosed_name()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("unknown"));

        let file_path = extract_dir.join(enclosed_name);

        // 创建目录
        if let Some(parent) = file_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!("Failed to create directory {:?}: {}", parent, e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to create directory {:?}: {}", parent, e)
                }));
            }
        }

        if file.is_dir() {
            if let Err(e) = std::fs::create_dir_all(&file_path) {
                tracing::error!("Failed to create directory {:?}: {}", file_path, e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to create directory {:?}: {}", file_path, e)
                }));
            }
            tracing::debug!("Created directory: {:?}", file_path);
        } else {
            let mut outfile = match std::fs::File::create(&file_path) {
                Ok(file) => file,
                Err(e) => {
                    tracing::error!("Failed to create file {:?}: {}", file_path, e);
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": format!("Failed to create file {:?}: {}", file_path, e)
                    }));
                }
            };

            if let Err(e) = std::io::copy(&mut file, &mut outfile) {
                tracing::error!("Failed to write file {:?}: {}", file_path, e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Failed to write file {:?}: {}", file_path, e)
                }));
            }

            tracing::debug!("Extracted file: {:?}", file_path);
        }
    }

    tracing::info!("Successfully extracted to: {:?}", extract_dir);

    // 保存到数据库
    let project_path_str = project_dir.to_string_lossy().to_string();
    let project_uuid = project_id.to_string();

    tracing::info!("Saving project to database: {} at {}", name, project_path_str);

    let result = match sqlx::query("INSERT INTO projects (uuid, name, path) VALUES (?, ?, ?)")
        .bind(&project_uuid)
        .bind(&name)
        .bind(&project_path_str)
        .execute(&state.db)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to insert project into database: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create project: {}", e)
            }));
        }
    };

    let id = result.last_insert_rowid();
    tracing::info!("Project inserted with ID: {}, UUID: {}", id, project_uuid);

    let project = match sqlx::query_as::<_, Project>(
        "SELECT id, uuid, name, path, datetime(created_at) as created_at FROM projects WHERE id = ?"
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    {
        Ok(project) => project,
        Err(e) => {
            tracing::error!("Failed to fetch project from database: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch project: {}", e)
            }));
        }
    };

    tracing::info!("Project created successfully: {}", project.name);

    HttpResponse::Ok().json(project)
}

async fn list_projects(state: web::Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, Project>(
        "SELECT id, uuid, name, path, datetime(created_at) as created_at FROM projects ORDER BY created_at DESC"
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(projects) => HttpResponse::Ok().json(projects),
        Err(e) => {
            tracing::error!("Failed to list projects: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to list projects: {}", e)
            }))
        }
    }
}

async fn get_project(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let uuid = path.into_inner();
    match sqlx::query_as::<_, Project>(
        "SELECT id, uuid, name, path, datetime(created_at) as created_at FROM projects WHERE uuid = ?"
    )
    .bind(&uuid)
    .fetch_one(&state.db)
    .await
    {
        Ok(project) => HttpResponse::Ok().json(project),
        Err(e) => {
            tracing::error!("Failed to fetch project: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Project not found: {}", e)
            }))
        }
    }
}

async fn delete_project(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let uuid = path.into_inner();

    // 首先获取项目信息（需要 project_id 用于级联删除）
    let project = match sqlx::query_as::<_, (i64, String, String, String, String)>(
        "SELECT id, uuid, name, path, datetime(created_at) as created_at FROM projects WHERE uuid = ?"
    )
    .bind(&uuid)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(proj)) => proj,
        Ok(None) => {
            tracing::warn!("Project {} not found, nothing to delete", uuid);
            return HttpResponse::Ok().json(serde_json::json!({
                "message": "Project not found"
            }));
        }
        Err(e) => {
            tracing::error!("Failed to fetch project: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch project: {}", e)
            }));
        }
    };

    let (project_id, _project_uuid, _project_name, project_path, _created_at) = project;

    tracing::info!("Deleting project {} (ID: {}), cleanup scheduled for: {}", uuid, project_id, project_path);

    // 使用事务删除所有关联数据
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to begin transaction: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to begin transaction: {}", e)
            }));
        }
    };

    // 1. 删除 findings 表中的关联记录
    match sqlx::query("DELETE FROM findings WHERE project_id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) => {
            tracing::info!("Deleted {} findings for project {}", result.rows_affected(), project_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete findings: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete findings: {}", e)
            }));
        }
    }

    // 2. 删除 scans 表中的关联记录
    match sqlx::query("DELETE FROM scans WHERE project_id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) => {
            tracing::info!("Deleted {} scan records for project {}", result.rows_affected(), project_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete scans: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete scans: {}", e)
            }));
        }
    }

    // 3. 删除 AST 相关数据（依赖关系：call_relations -> code_graphs -> symbols -> ast_indices）
    match sqlx::query("DELETE FROM call_relations WHERE project_id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) => {
            tracing::info!("Deleted {} call relations for project {}", result.rows_affected(), project_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete call relations: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete call relations: {}", e)
            }));
        }
    }

    match sqlx::query("DELETE FROM code_graphs WHERE project_id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) => {
            tracing::info!("Deleted {} code graphs for project {}", result.rows_affected(), project_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete code graphs: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete code graphs: {}", e)
            }));
        }
    }

    match sqlx::query("DELETE FROM symbols WHERE project_id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) => {
            tracing::info!("Deleted {} symbols for project {}", result.rows_affected(), project_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete symbols: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete symbols: {}", e)
            }));
        }
    }

    match sqlx::query("DELETE FROM ast_indices WHERE project_id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        Ok(result) => {
            tracing::info!("Deleted {} AST indices for project {}", result.rows_affected(), project_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete AST indices: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete AST indices: {}", e)
            }));
        }
    }

    // 4. 删除项目记录
    match sqlx::query("DELETE FROM projects WHERE id = ?")
        .bind(project_id)
        .execute(&mut *tx)
        .await
    {
        Ok(_) => {
            tracing::info!("Deleted project {}", project_id);
        }
        Err(e) => {
            tracing::error!("Failed to delete project: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete project: {}", e)
            }));
        }
    }

    // 提交事务
    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit transaction: {}", e);
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to commit transaction: {}", e)
        }));
    }

    // 异步清理文件系统
    let project_path_clone = project_path.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::fs::remove_dir_all(&project_path_clone).await {
            tracing::error!("Failed to cleanup project directory {:?}: {}", project_path_clone, e);
        } else {
            tracing::info!("Successfully cleaned up project directory: {:?}", project_path_clone);
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Project deleted successfully"
    }))
}
