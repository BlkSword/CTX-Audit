// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::services::database::Database;

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Project {
    pub id: i64,
    pub uuid: String,
    pub name: String,
    pub path: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub path: String,
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

/// 创建新项目
#[tauri::command]
pub async fn create_project(
    req: CreateProjectRequest,
    db: State<'_, Database>,
) -> Result<Project, String> {
    let uuid = Uuid::new_v4().to_string();
    db.create_project(&uuid, &req.name, &req.path)
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
