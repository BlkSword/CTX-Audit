use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::path::{Path as StdPath, PathBuf};

#[derive(Serialize, Deserialize)]
pub struct ReadFileRequest {
    pub path: String,
}

#[derive(Serialize, Deserialize)]
pub struct ListFilesRequest {
    pub directory: String,
    #[serde(default)]
    pub recursive: bool,
}

#[derive(Serialize, Deserialize)]
pub struct SearchFilesRequest {
    pub query: String,
    pub path: String,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub name: String,
}

pub fn configure_files_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/read", web::get().to(read_file))
        .route("/list", web::get().to(list_files))
        .route("/search", web::get().to(search_files));
}

pub async fn read_file(query: web::Query<ReadFileRequest>) -> impl Responder {
    let path = PathBuf::from(&query.path);

    if !path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("文件不存在: {}", query.path)
        }));
    }

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => HttpResponse::Ok().json(content),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("读取文件失败: {}", e)
        }))
    }
}

pub async fn list_files(query: web::Query<ListFilesRequest>) -> impl Responder {
    let path = PathBuf::from(&query.directory);

    if !path.exists() {
        return HttpResponse::Ok().json(vec![] as Vec<String>);
    }

    // 默认递归列出所有文件
    let mut entries = vec![];
    match _list_files_recursive(&path, &mut entries).await {
        Ok(_) => {
            entries.sort();
            HttpResponse::Ok().json(entries)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("读取目录失败: {}", e)
        }))
    }
}

// 递归列出所有文件
async fn _list_files_recursive(dir: &StdPath, entries: &mut Vec<String>) -> Result<(), anyhow::Error> {
    let mut rd = tokio::fs::read_dir(dir).await?;

    while let Some(entry) = rd.next_entry().await? {
        let path = entry.path();

        // 过滤隐藏目录和特定目录
        if let Some(name) = path.file_name() {
            if let Some(name_str) = name.to_str() {
                if name_str.starts_with('.') ||
                   name_str == "node_modules" ||
                   name_str == "target" ||
                   name_str == "__pycache__" ||
                   name_str == ".git" ||
                   name_str == "dist" {
                    continue;
                }
            }
        }

        if path.is_dir() {
            Box::pin(_list_files_recursive(&path, entries)).await?;
        } else if let Some(path_str) = path.to_str() {
            entries.push(path_str.to_string());
        }
    }

    Ok(())
}

pub async fn search_files(query: web::Query<SearchFilesRequest>) -> impl Responder {
    let path = PathBuf::from(&query.path);
    let query_str = &query.query;

    if !path.exists() {
        return HttpResponse::Ok().json(vec![] as Vec<FileInfo>);
    }

    match _search_files_recursive(&path, query_str).await {
        Ok(results) => HttpResponse::Ok().json(results),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("搜索文件失败: {}", e)
        }))
    }
}

async fn _search_files_recursive(
    dir: &StdPath,
    query: &str,
) -> Result<Vec<FileInfo>, anyhow::Error> {
    let mut results = vec![];
    let mut entries = tokio::fs::read_dir(dir).await?;

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();

        if let Some(os_name) = path.file_name() {
            if let Some(name) = os_name.to_str() {
                if name.starts_with('.') ||
                   name == "node_modules" ||
                   name == "target" ||
                   name == "__pycache__" ||
                   name == ".git" ||
                   name == "dist" {
                    continue;
                }
            }
        }

        if path.is_dir() {
            match Box::pin(_search_files_recursive(&path, query)).await {
                Ok(mut sub_results) => results.append(&mut sub_results),
                Err(_) => continue,
            }
        } else if let Some(os_name) = path.file_name() {
            if let Some(name) = os_name.to_str() {
                if name.to_lowercase().contains(&query.to_lowercase()) {
                    results.push(FileInfo {
                        path: path.to_string_lossy().to_string(),
                        name: name.to_string(),
                    });
                }
            }
        }
    }

    Ok(results)
}
