// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;
use std::path::{Path, PathBuf};

use crate::services::database::Database;

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Project {
    pub id: i64,
    pub uuid: String,
    pub name: String,
    pub path: String,
    pub created_at: String,
}

/// 列出所有项目
#[tauri::command]
pub async fn list_projects(
    db: State<'_, Database>,
) -> Result<Vec<Project>, String> {
    db.list_projects()
        .await
        .map_err(|e| format!("Failed to list projects: {}", e))
}

/// 获取单个项目
#[tauri::command]
pub async fn get_project_by_id(
    id: i64,
    db: State<'_, Database>,
) -> Result<Option<Project>, String> {
    let project = db.get_project_by_id(id)
        .await
        .map_err(|e| format!("Failed to get project: {}", e))?;
    Ok(Some(project))
}

/// 通过路径查找项目
#[tauri::command]
pub async fn get_project_by_path(
    path: String,
    db: State<'_, Database>,
) -> Result<Option<Project>, String> {
    let projects = db.list_projects()
        .await
        .map_err(|e| format!("Failed to list projects: {}", e))?;

    // 标准化路径进行比较
    let path_normalized = Path::new(&path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&path))
        .to_string_lossy()
        .to_string();

    for project in projects {
        let project_path_normalized = Path::new(&project.path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(&project.path))
            .to_string_lossy()
            .to_string();

        if project_path_normalized == path_normalized {
            return Ok(Some(project));
        }
    }

    Ok(None)
}

/// 创建新项目
#[tauri::command]
pub async fn create_project(
    name: String,
    path: String,
    db: State<'_, Database>,
) -> Result<Project, String> {
    let uuid = Uuid::new_v4().to_string();
    db.create_project(&uuid, &name, &path)
        .await
        .map_err(|e| format!("Failed to create project: {}", e))
}

/// 打开目录并创建/获取项目
///
/// 这个命令会：
/// 1. 选择目录
/// 2. 检查该目录是否已有项目
/// 3. 如果有，返回现有项目
/// 4. 如果没有，从目录名提取项目名并创建新项目
#[tauri::command]
pub async fn open_directory(
    db: State<'_, Database>,
) -> Result<Project, String> {
    use rfd::AsyncFileDialog;
    use std::path::PathBuf;

    // 1. 选择目录
    let folder = AsyncFileDialog::new()
        .pick_folder()
        .await
        .ok_or_else(|| "No directory selected".to_string())?;

    let path = folder.path();
    let path_str = path.to_string_lossy().to_string();

    // 2. 检查是否已存在项目
    let existing_project = get_project_by_path(path_str.clone(), db.clone()).await?;
    if let Some(project) = existing_project {
        return Ok(project);
    }

    // 3. 从目录名提取项目名
    let project_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Untitled")
        .to_string();

    // 4. 创建新项目
    let uuid = Uuid::new_v4().to_string();
    db.create_project(&uuid, &project_name, &path_str)
        .await
        .map_err(|e| format!("Failed to create project: {}", e))
}

/// 删除项目
#[tauri::command]
pub async fn delete_project(
    uuid: String,
    db: State<'_, Database>,
) -> Result<(), String> {
    db.delete_project(&uuid)
        .await
        .map_err(|e| format!("Failed to delete project: {}", e))
}
