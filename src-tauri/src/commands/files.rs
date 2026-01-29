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
    // 验证路径
    let path_obj = Path::new(&path);

    // 检查文件是否存在
    if !path_obj.exists() {
        return Err(format!("文件不存在: {}", path));
    }

    // 检查是否是文件
    if !path_obj.is_file() {
        return Err(format!("路径不是文件: {}", path));
    }

    // 检查文件扩展名，跳过二进制文件
    if let Some(ext) = path_obj.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        let binary_extensions = [
            "exe", "dll", "so", "dylib", "bin", "o", "a", "lib",
            "png", "jpg", "jpeg", "gif", "ico", "bmp", "webp",
            "mp3", "mp4", "wav", "avi", "mov", "mkv",
            "zip", "tar", "gz", "7z", "rar",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        ];
        if binary_extensions.contains(&ext.as_str()) {
            return Err(format!("不支持读取二进制文件: {}", path));
        }
    }

    // 尝试读取文件
    fs::read_to_string(&path)
        .map_err(|e| {
            // 提供更友好的错误信息
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                format!("权限不足，无法读取文件: {}", path)
            } else {
                format!("读取文件失败: {} ({})", path, e)
            }
        })
}

/// 列出目录内容
#[tauri::command]
pub async fn list_directory(path: String) -> Result<Vec<FileInfo>, String> {
    let path_obj = Path::new(&path);

    if !path_obj.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    if !path_obj.is_dir() {
        return Err(format!("Path is not a directory: {}", path));
    }

    let entries = fs::read_dir(&path)
        .map_err(|e| format!("Failed to read directory: {}", e))?;

    let mut files = Vec::new();

    // 应该跳过的文件/目录名称
    let skip_names = [
        "node_modules",
        "target",
        "dist",
        "build",
        ".git",
        ".vscode",
        ".idea",
        "venv",
        "__pycache__",
        ".DS_Store",
        "Thumbs.db",
    ];

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        let file_name = entry.file_name().to_string_lossy().to_string();

        // 跳过隐藏文件和特定目录
        if file_name.starts_with('.') || skip_names.contains(&file_name.as_str()) {
            continue;
        }

        let metadata = entry.metadata().ok();

        // 跳过没有权限访问的文件
        if let Some(ref meta) = metadata {
            if meta.permissions().readonly() && !meta.is_dir() {
                // 只读文件可能无法读取，但仍然显示
            }
        }

        files.push(FileInfo {
            name: file_name,
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
