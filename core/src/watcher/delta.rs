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

    /// 只读变更预览：判定口径与 [`FileSnapshot::detect_changes`] 一致，但**不更新** baseline。
    ///
    /// 用途：状态上报（"待重编译"清单）等只读观测场景——可以反复调用而不影响后续增量扫描。
    /// 未建立 baseline 时，把当前所有文件视为"新增"，同样不落库。
    pub fn peek_changes(&self) -> Result<DeltaResult> {
        let current_files = self.scan_project_files()?;

        if !self.has_baseline {
            let total = current_files.len();
            return Ok(DeltaResult {
                added_files: current_files,
                changed_files: vec![],
                deleted_files: vec![],
                unchanged_count: 0,
                total_files: total,
            });
        }

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

        let deleted: Vec<PathBuf> = self
            .file_hashes
            .keys()
            .filter(|k| !current_keys.contains(*k))
            .map(|k| self.project_path.join(k))
            .collect();

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

    /// 是否已建立 baseline（未建立时变更判定退化为"全部新增"）
    pub fn has_baseline(&self) -> bool {
        self.has_baseline
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

    fn temp_project(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ctx-audit-delta-peek-{tag}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn test_peek_changes_does_not_mutate_snapshot() {
        let root = temp_project("noroot");
        fs::write(root.join("a.py"), "x = 1\n").unwrap();

        let mut snapshot = FileSnapshot::new(&root, vec!["node_modules".to_string()]);
        // 未建立 baseline：peek 把现有文件全部视为新增，且不落库
        let first = snapshot.peek_changes().unwrap();
        assert_eq!(first.added_files.len(), 1);
        assert!(!snapshot.has_baseline(), "peek 不应建立 baseline");
        let second = snapshot.peek_changes().unwrap();
        assert_eq!(second.added_files.len(), 1, "peek 结果必须可重复");

        // 建立 baseline 后：无变化 → 全部未变
        let baseline = snapshot.build_baseline().unwrap();
        assert_eq!(baseline.total_files, 1);
        let clean = snapshot.peek_changes().unwrap();
        assert!(!clean.has_changes(), "无变化时不应报告变更: {clean:?}");
        assert_eq!(clean.unchanged_count, 1);

        // 改内容：peek 报"修改"，重复调用结果稳定，且后续 detect_changes 仍能识别
        fs::write(root.join("a.py"), "x = 2\ny = 3\n").unwrap();
        let changed = snapshot.peek_changes().unwrap();
        assert_eq!(changed.changed_files.len(), 1, "应报修改: {changed:?}");
        let changed_again = snapshot.peek_changes().unwrap();
        assert_eq!(
            changed_again.changed_files.len(),
            1,
            "peek 之后 detect 仍须能识别（说明 peek 没更新 baseline）"
        );
        let detected = snapshot.detect_changes().unwrap();
        assert_eq!(detected.changed_files.len(), 1);
        assert!(!snapshot.peek_changes().unwrap().has_changes(), "detect 后应已收敛");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_peek_changes_reports_added_and_deleted() {
        let root = temp_project("adddel");
        fs::write(root.join("keep.py"), "keep\n").unwrap();
        fs::write(root.join("gone.py"), "gone\n").unwrap();

        let mut snapshot = FileSnapshot::new(&root, vec![]);
        snapshot.build_baseline().unwrap();

        fs::write(root.join("new.py"), "new\n").unwrap();
        fs::remove_file(root.join("gone.py")).unwrap();

        let delta = snapshot.peek_changes().unwrap();
        assert!(
            delta
                .added_files
                .iter()
                .any(|p| p.file_name().unwrap().to_string_lossy() == "new.py"),
            "应识别新增文件: {delta:?}"
        );
        assert!(
            delta
                .deleted_files
                .iter()
                .any(|p| p.file_name().unwrap().to_string_lossy() == "gone.py"),
            "应识别删除文件: {delta:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
