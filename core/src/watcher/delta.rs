// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 文件快照与变更检测
//!
//! 通过 content hash 对比检测文件变更，支持增量扫描

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// 文件快照 — 记录每个文件的 content hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    /// 项目根路径
    project_path: PathBuf,

    /// 忽略的目录模式
    ignore_patterns: Vec<String>,

    /// 文件 hash 映射: 相对路径 → content hash
    file_hashes: HashMap<String, u64>,

    /// 是否已建立 baseline
    has_baseline: bool,
}

/// 变更检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaResult {
    /// 新增的文件
    pub added_files: Vec<PathBuf>,

    /// 修改的文件
    pub changed_files: Vec<PathBuf>,

    /// 删除的文件
    pub deleted_files: Vec<PathBuf>,

    /// 未变更的文件数
    pub unchanged_count: usize,

    /// 总文件数
    pub total_files: usize,
}

impl DeltaResult {
    /// 是否有任何变更
    pub fn has_changes(&self) -> bool {
        !self.added_files.is_empty()
            || !self.changed_files.is_empty()
            || !self.deleted_files.is_empty()
    }

    /// 所有变更文件的总数
    pub fn total_changes(&self) -> usize {
        self.added_files.len() + self.changed_files.len() + self.deleted_files.len()
    }
}

impl FileSnapshot {
    /// 创建新的文件快照
    pub fn new(project_path: &Path, ignore_patterns: Vec<String>) -> Self {
        Self {
            project_path: project_path.to_path_buf(),
            ignore_patterns,
            file_hashes: HashMap::new(),
            has_baseline: false,
        }
    }

    /// 建立 baseline — 扫描项目并记录所有文件的 hash
    pub fn build_baseline(&mut self) -> Result<DeltaResult> {
        let current_files = self.scan_project_files()?;
        let mut file_hashes = HashMap::new();

        for file_path in &current_files {
            if let Ok(hash) = self.hash_file(file_path) {
                let relative = self.relative_path(file_path);
                file_hashes.insert(relative, hash);
            }
        }

        let total = file_hashes.len();
        self.file_hashes = file_hashes;
        self.has_baseline = true;

        Ok(DeltaResult {
            added_files: current_files,
            changed_files: vec![],
            deleted_files: vec![],
            unchanged_count: 0,
            total_files: total,
        })
    }

    /// 检测变更 — 对比当前文件系统与 baseline
    pub fn detect_changes(&mut self) -> Result<DeltaResult> {
        if !self.has_baseline {
            return self.build_baseline();
        }

        let current_files = self.scan_project_files()?;
        let mut added = Vec::new();
        let mut changed = Vec::new();
        let mut unchanged = 0usize;

        let mut current_keys: HashSet<String> = HashSet::new();

        for file_path in &current_files {
            let relative = self.relative_path(file_path);
            current_keys.insert(relative.clone());

            if let Ok(hash) = self.hash_file(file_path) {
                match self.file_hashes.get(&relative) {
                    Some(&old_hash) if old_hash == hash => {
                        unchanged += 1;
                    }
                    Some(_) => {
                        changed.push(file_path.clone());
                    }
                    None => {
                        added.push(file_path.clone());
                    }
                }
            }
        }

        // 找出已删除的文件
        let deleted: Vec<PathBuf> = self
            .file_hashes
            .keys()
            .filter(|k| !current_keys.contains(*k))
            .map(|k| self.project_path.join(k))
            .collect();

        // 更新 snapshot
        for file_path in &current_files {
            let relative = self.relative_path(file_path);
            if let Ok(hash) = self.hash_file(file_path) {
                self.file_hashes.insert(relative, hash);
            }
        }
        for key in &current_keys {
            // already updated above
        }
        // 删除已不存在的文件
        self.file_hashes.retain(|k, _| current_keys.contains(k));

        Ok(DeltaResult {
            added_files: added,
            changed_files: changed,
            deleted_files: deleted,
            unchanged_count: unchanged,
            total_files: current_files.len(),
        })
    }

    /// 获取当前快照的文件数
    pub fn file_count(&self) -> usize {
        self.file_hashes.len()
    }

    /// 扫描项目文件（排除忽略目录）
    fn scan_project_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        self.walk_dir(&self.project_path, &mut files)?;

        Ok(files)
    }

    /// 递归遍历目录
    fn walk_dir(&self, dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        let entries = std::fs::read_dir(dir)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // 检查是否应该忽略
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.should_ignore_directory(name) {
                        continue;
                    }
                }
                self.walk_dir(&path, files)?;
            } else if path.is_file() {
                files.push(path);
            }
        }

        Ok(())
    }

    /// 检查目录是否应该忽略
    fn should_ignore_directory(&self, name: &str) -> bool {
        self.ignore_patterns
            .iter()
            .any(|pattern| name == pattern || name.starts_with('.') && pattern == ".*")
            || name.starts_with('.')
    }

    /// 计算文件的 content hash（使用简单快速的 hash）
    fn hash_file(&self, path: &Path) -> Result<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let content = std::fs::read(path)?;
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        Ok(hasher.finish())
    }

    /// 获取相对路径
    fn relative_path(&self, path: &Path) -> String {
        path.strip_prefix(&self.project_path)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_delta_result_has_changes() {
        let empty = DeltaResult {
            added_files: vec![],
            changed_files: vec![],
            deleted_files: vec![],
            unchanged_count: 0,
            total_files: 0,
        };
        assert!(!empty.has_changes());

        let with_changes = DeltaResult {
            added_files: vec![PathBuf::from("a.py")],
            changed_files: vec![],
            deleted_files: vec![],
            unchanged_count: 0,
            total_files: 1,
        };
        assert!(with_changes.has_changes());
    }
}
