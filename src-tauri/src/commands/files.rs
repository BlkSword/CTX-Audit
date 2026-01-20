// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: Option<u64>,
}

/// 读取文件内容
#[tauri::command]
pub async fn read_file(path: String) -> Result<String, String> {
    fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read file: {}", e))
}

/// 列出目录内容
#[tauri::command]
pub async fn list_directory(path: String) -> Result<Vec<FileInfo>, String> {
    let path_obj = Path::new(&path);
    if !path_obj.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    let entries = fs::read_dir(&path)
        .map_err(|e| format!("Failed to read directory: {}", e))?;

    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let metadata = entry.metadata().ok();

        files.push(FileInfo {
            name: entry.file_name().to_string_lossy().to_string(),
            path: entry.path().to_string_lossy().to_string(),
            is_dir: metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false),
            size: metadata.map(|m| m.len()),
        });
    }

    // 排序：目录在前，然后按名称排序
    files.sort_by(|a, b| {
        match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.name.cmp(&b.name),
        }
    });

    Ok(files)
}

/// 选择目录（使用系统文件选择对话框）
#[tauri::command]
pub async fn select_directory() -> Result<Option<String>, String> {
    use rfd::AsyncFileDialog;

    let folder = AsyncFileDialog::new()
        .pick_folder()
        .await;

    // 转换路径为字符串
    Ok(folder.map(|p| p.path().to_string_lossy().to_string()))
}
