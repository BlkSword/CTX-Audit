use crate::diff::git_integration::GitIntegration;
use crate::diff::types::*;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 高性能差异比较引擎
pub struct DiffEngine {
    config: ComparisonConfig,
}

impl DiffEngine {
    /// 创建新的差异引擎实例
    pub fn new(config: ComparisonConfig) -> Self {
        Self { config }
    }

    /// 执行完整的比较
    pub fn compare(&self, request: ComparisonRequest) -> Result<ComparisonResult> {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let file_diffs = if request.is_git_comparison {
            self.git_compare(&request)?
        } else {
            self.file_system_compare(&request)?
        };

        let summary = self.calculate_summary(&file_diffs);

        Ok(ComparisonResult {
            source_a: request.source_a,
            source_b: request.source_b,
            comparison_time: start_time as i64,
            file_diffs,
            summary,
        })
    }

    /// 文件系统比较（比较两个文件或目录）
    fn file_system_compare(&self, request: &ComparisonRequest) -> Result<Vec<FileDiff>> {
        let path_a = Path::new(&request.source_a);
        let path_b = Path::new(&request.source_b);

        if path_a.is_file() && path_b.is_file() {
            // 单文件比较
            let file_diff = self.compare_files(path_a, path_b)?;
            Ok(vec![file_diff])
        } else if path_a.is_dir() && path_b.is_dir() {
            // 目录比较
            self.compare_directories(path_a, path_b)
        } else {
            Err(anyhow::anyhow!(
                "Cannot compare different types: {} and {}",
                if path_a.is_file() {
                    "file"
                } else {
                    "directory"
                },
                if path_b.is_file() {
                    "file"
                } else {
                    "directory"
                }
            ))
        }
    }

    /// 比较两个文件
    fn compare_files(&self, path_a: &Path, path_b: &Path) -> Result<FileDiff> {
        // 检查文件是否为二进制文件
        let is_binary_a = self.is_binary_file(path_a)?;
        let is_binary_b = self.is_binary_file(path_b)?;

        // 如果任一文件是二进制文件，进行二进制比较
        if is_binary_a || is_binary_b {
            return self.compare_binary_files(path_a, path_b, is_binary_a, is_binary_b);
        }

        // 文本文件比较
        let content_a = match self.read_text_file(path_a) {
            Ok(content) => content,
            Err(e) => {
                // 如果读取失败，创建错误记录并返回
                return self.create_error_file_diff(path_a, path_b, &e);
            }
        };

        let content_b = match self.read_text_file(path_b) {
            Ok(content) => content,
            Err(e) => {
                // 如果读取失败，创建错误记录并返回
                return self.create_error_file_diff(path_a, path_b, &e);
            }
        };

        let lines_a: Vec<String> = if self.config.ignore_whitespace {
            content_a
                .lines()
                .map(|line| line.trim().to_string())
                .collect()
        } else {
            content_a.lines().map(|line| line.to_string()).collect()
        };

        let lines_b: Vec<String> = if self.config.ignore_whitespace {
            content_b
                .lines()
                .map(|line| line.trim().to_string())
                .collect()
        } else {
            content_b.lines().map(|line| line.to_string()).collect()
        };

        let diff_lines = self.compute_line_diff(&lines_a, &lines_b);

        let metadata_a = fs::metadata(path_a)?;
        let metadata_b = fs::metadata(path_b)?;

        let left_stats = FileStats {
            size: metadata_a.len(),
            line_count: lines_a.len() as u32,
            modified_time: metadata_a
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
        };

        let right_stats = FileStats {
            size: metadata_b.len(),
            line_count: lines_b.len() as u32,
            modified_time: metadata_b
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
        };

        // 只有当文件不是太大时才包含原始内容，避免内存溢出
        // 限制为 1MB
        let include_content = metadata_a.len() < 1024 * 1024 && metadata_b.len() < 1024 * 1024;

        Ok(FileDiff {
            path: path_b.to_string_lossy().to_string(),
            status: if diff_lines
                .iter()
                .all(|line| line.diff_type == DiffType::Equal)
            {
                FileStatus::Unchanged
            } else {
                FileStatus::Modified
            },
            lines: diff_lines,
            original_content: if include_content {
                Some(content_a)
            } else {
                None
            },
            modified_content: if include_content {
                Some(content_b)
            } else {
                None
            },
            left_stats,
            right_stats,
        })
    }

    /// 比较两个目录
    fn compare_directories(&self, dir_a: &Path, dir_b: &Path) -> Result<Vec<FileDiff>> {
        let mut file_diffs = Vec::new();

        // 获取两个目录中的所有文件
        let files_a = self.get_files_recursive(dir_a)?;
        let files_b = self.get_files_recursive(dir_b)?;

        let files_a_set: HashMap<String, PathBuf> = files_a
            .into_iter()
            .map(|p| {
                let relative_path = p.strip_prefix(dir_a).unwrap().to_string_lossy().to_string();
                (relative_path, p)
            })
            .collect();

        let files_b_set: HashMap<String, PathBuf> = files_b
            .into_iter()
            .map(|p| {
                let relative_path = p.strip_prefix(dir_b).unwrap().to_string_lossy().to_string();
                (relative_path, p)
            })
            .collect();

        let all_paths: Vec<String> = files_a_set
            .keys()
            .chain(files_b_set.keys())
            .cloned()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // 并行处理所有文件
        let results: Vec<Result<FileDiff>> = all_paths
            .into_par_iter()
            .map(|relative_path| {
                match (
                    files_a_set.get(&relative_path),
                    files_b_set.get(&relative_path),
                ) {
                    (Some(path_a), Some(path_b)) => {
                        // 两个目录都有的文件，比较内容
                        self.compare_files(path_a, path_b)
                    }
                    (Some(path_a), None) => {
                        // 只在左侧存在的文件（删除）
                        self.create_deleted_file_diff(&relative_path, path_a)
                    }
                    (None, Some(path_b)) => {
                        // 只在右侧存在的文件（新增）
                        self.create_added_file_diff(&relative_path, path_b)
                    }
                    (None, None) => {
                        unreachable!("File path not found in either directory")
                    }
                }
            })
            .collect();

        // 分离成功的结果和错误
        let mut diffs = Vec::new();
        // let mut skipped_files = Vec::new();

        for result in results {
            match result {
                Ok(diff) => diffs.push(diff),
                Err(_e) => {
                    // skipped_files.push(format!("跳过文件: {}", e));
                }
            }
        }

        // 如果启用了重命名检测
        if self.config.detect_renames {
            self.detect_renames(&mut diffs);
        }

        file_diffs.extend(diffs);
        Ok(file_diffs)
    }

    /// 计算行级别的差异 (使用 similar crate 优化)
    fn compute_line_diff(&self, lines_a: &[String], lines_b: &[String]) -> Vec<DiffLine> {
        use similar::{Algorithm, ChangeTag, TextDiff};

        let text_a = lines_a.join("\n");
        let text_b = lines_b.join("\n");

        let diff = TextDiff::configure()
            .algorithm(Algorithm::Myers) // Myers is standard, Patience is cleaner but slower
            .diff_lines(&text_a, &text_b);

        let mut result = Vec::new();
        let mut left_line_num = 1u32;
        let mut right_line_num = 1u32;

        for change in diff.iter_all_changes() {
            let content = change.value().trim_end_matches('\n').to_string();

            match change.tag() {
                ChangeTag::Equal => {
                    result.push(DiffLine {
                        left_line_number: Some(left_line_num),
                        right_line_number: Some(right_line_num),
                        diff_type: DiffType::Equal,
                        content,
                        is_placeholder: false,
                    });
                    left_line_num += 1;
                    right_line_num += 1;
                }
                ChangeTag::Delete => {
                    result.push(DiffLine {
                        left_line_number: Some(left_line_num),
                        right_line_number: None,
                        diff_type: DiffType::Delete,
                        content,
                        is_placeholder: false,
                    });
                    left_line_num += 1;
                }
                ChangeTag::Insert => {
                    result.push(DiffLine {
                        left_line_number: None,
                        right_line_number: Some(right_line_num),
                        diff_type: DiffType::Insert,
                        content,
                        is_placeholder: false,
                    });
                    right_line_num += 1;
                }
            }
        }

        result
    }

    /// 递归获取目录中的所有文件
    fn get_files_recursive(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                files.push(entry.path().to_path_buf());
            }
        }

        Ok(files)
    }

    /// 创建删除文件的差异记录
    fn create_deleted_file_diff(&self, relative_path: &str, path: &Path) -> Result<FileDiff> {
        let metadata = fs::metadata(path)?;
        let is_binary = self.is_binary_file(path)?;

        if is_binary {
            // 二进制文件的删除记录
            Ok(FileDiff {
                path: relative_path.to_string(),
                status: FileStatus::Deleted,
                lines: vec![DiffLine {
                    left_line_number: Some(1),
                    right_line_number: None,
                    diff_type: DiffType::Delete,
                    content: format!("[二进制文件] 大小: {} 字节", metadata.len()),
                    is_placeholder: false,
                }],
                original_content: None,
                modified_content: None,
                left_stats: FileStats {
                    size: metadata.len(),
                    line_count: 1,
                    modified_time: metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64),
                },
                right_stats: FileStats {
                    size: 0,
                    line_count: 0,
                    modified_time: None,
                },
            })
        } else {
            // 文本文件的删除记录
            let content = self.read_text_file(path)?;
            let lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();
            let line_count = lines.len();

            let diff_lines: Vec<DiffLine> = lines
                .into_iter()
                .enumerate()
                .map(|(i, line)| DiffLine {
                    left_line_number: Some(i as u32 + 1),
                    right_line_number: None,
                    diff_type: DiffType::Delete,
                    content: line,
                    is_placeholder: false,
                })
                .collect();

            Ok(FileDiff {
                path: relative_path.to_string(),
                status: FileStatus::Deleted,
                lines: diff_lines,
                original_content: Some(content),
                modified_content: None,
                left_stats: FileStats {
                    size: metadata.len(),
                    line_count: line_count as u32,
                    modified_time: metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64),
                },
                right_stats: FileStats {
                    size: 0,
                    line_count: 0,
                    modified_time: None,
                },
            })
        }
    }

    /// 创建新增文件的差异记录
    fn create_added_file_diff(&self, relative_path: &str, path: &Path) -> Result<FileDiff> {
        let metadata = fs::metadata(path)?;
        let is_binary = self.is_binary_file(path)?;

        if is_binary {
            // 二进制文件的新增记录
            Ok(FileDiff {
                path: relative_path.to_string(),
                status: FileStatus::Added,
                lines: vec![DiffLine {
                    left_line_number: None,
                    right_line_number: Some(1),
                    diff_type: DiffType::Insert,
                    content: format!("[二进制文件] 大小: {} 字节", metadata.len()),
                    is_placeholder: false,
                }],
                original_content: None,
                modified_content: None,
                left_stats: FileStats {
                    size: 0,
                    line_count: 0,
                    modified_time: None,
                },
                right_stats: FileStats {
                    size: metadata.len(),
                    line_count: 1,
                    modified_time: metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64),
                },
            })
        } else {
            // 文本文件的新增记录
            let content = self.read_text_file(path)?;
            let lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();
            let line_count = lines.len();

            let diff_lines: Vec<DiffLine> = lines
                .into_iter()
                .enumerate()
                .map(|(i, line)| DiffLine {
                    left_line_number: None,
                    right_line_number: Some(i as u32 + 1),
                    diff_type: DiffType::Insert,
                    content: line,
                    is_placeholder: false,
                })
                .collect();

            Ok(FileDiff {
                path: relative_path.to_string(),
                status: FileStatus::Added,
                lines: diff_lines,
                original_content: None,
                modified_content: Some(content),
                left_stats: FileStats {
                    size: 0,
                    line_count: 0,
                    modified_time: None,
                },
                right_stats: FileStats {
                    size: metadata.len(),
                    line_count: line_count as u32,
                    modified_time: metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64),
                },
            })
        }
    }

    /// 检测文件重命名 (优化版)
    fn detect_renames(&self, diffs: &mut Vec<FileDiff>) {
        // 先收集所有的信息
        // 使用索引来避免借用问题
        let mut added_indices: Vec<usize> = Vec::new();
        let mut deleted_indices: Vec<usize> = Vec::new();

        for (i, diff) in diffs.iter().enumerate() {
            if matches!(diff.status, FileStatus::Added) {
                added_indices.push(i);
            } else if matches!(diff.status, FileStatus::Deleted) {
                deleted_indices.push(i);
            }
        }

        let mut rename_mappings: Vec<(usize, String)> = Vec::new();

        // 检查重命名
        // 优化：首先检查文件大小是否相近
        for &add_idx in &added_indices {
            let added_size = diffs[add_idx].right_stats.size;

            for &del_idx in &deleted_indices {
                let deleted_size = diffs[del_idx].left_stats.size;

                // 如果大小差异超过 20%，则认为不太可能是重命名（快速过滤）
                let size_diff = (added_size as i64 - deleted_size as i64).abs();
                let max_size = std::cmp::max(added_size, deleted_size);

                if max_size > 0 && (size_diff as f32 / max_size as f32) > 0.2 {
                    continue;
                }

                // 计算内容相似度
                // 注意：这里需要访问 lines，但 lines 已经被借用了
                // 由于 Rust 的借用规则，我们需要小心
                // 这里我们通过索引访问
                let similarity =
                    self.calculate_similarity(&diffs[del_idx].lines, &diffs[add_idx].lines);

                if similarity >= self.config.rename_similarity_threshold {
                    rename_mappings.push((add_idx, diffs[del_idx].path.clone()));
                    break; // 找到一个匹配后就跳过当前 added 文件
                }
            }
        }

        // 应用重命名标记
        for (new_idx, old_path) in &rename_mappings {
            if let Some(diff) = diffs.get_mut(*new_idx) {
                diff.status = FileStatus::Renamed {
                    old_path: old_path.clone(),
                };
            }
        }

        // 收集要删除的文件路径（被重命名的文件）
        let paths_to_remove: std::collections::HashSet<String> = rename_mappings
            .iter()
            .map(|(_, old_path)| old_path.clone())
            .collect();

        // 移除被重命名的删除文件
        diffs.retain(|diff| {
            if matches!(diff.status, FileStatus::Deleted) {
                !paths_to_remove.contains(&diff.path)
            } else {
                true
            }
        });
    }

    /// 计算两个文件行序列的相似度
    fn calculate_similarity(&self, lines_a: &[DiffLine], lines_b: &[DiffLine]) -> f32 {
        if lines_a.is_empty() || lines_b.is_empty() {
            return 0.0;
        }

        // 跳过二进制文件的相似度比较
        if lines_a
            .iter()
            .any(|line| line.content.starts_with("[二进制文件]"))
            || lines_b
                .iter()
                .any(|line| line.content.starts_with("[二进制文件]"))
        {
            return 0.0;
        }

        let set_a: std::collections::HashSet<&str> = lines_a
            .iter()
            .filter(|line| !line.content.starts_with("[二进制文件]"))
            .map(|line| line.content.trim())
            .collect();

        let set_b: std::collections::HashSet<&str> = lines_b
            .iter()
            .filter(|line| !line.content.starts_with("[二进制文件]"))
            .map(|line| line.content.trim())
            .collect();

        let intersection = set_a.intersection(&set_b).count();
        let union = set_a.union(&set_b).count();

        if union == 0 {
            1.0
        } else {
            intersection as f32 / union as f32
        }
    }

    /// Git比较实现
    fn git_compare(&self, request: &ComparisonRequest) -> Result<Vec<FileDiff>> {
        if let Some(git_params) = &request.git_params {
            let git_integration = GitIntegration::new();
            git_integration.compare(git_params, &self.config)
        } else {
            Err(anyhow::anyhow!("Git parameters not provided"))
        }
    }

    /// 检查文件是否为二进制文件
    fn is_binary_file(&self, path: &Path) -> Result<bool> {
        // 基于扩展名的快速检查
        if let Some(ext) = path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            let binary_extensions = [
                "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "pdf", "doc", "docx", "xls",
                "xlsx", "ppt", "pptx", "zip", "rar", "7z", "tar", "gz", "bz2", "exe", "dll", "so",
                "dylib", "class", "jar", "war", "ear", "pyc", "pyo", "pyd", "db", "sqlite",
                "sqlite3", "mp3", "mp4", "avi", "mov", "wmv", "flv", "wav", "flac", "ogg",
            ];

            if binary_extensions.contains(&ext_lower.as_str()) {
                return Ok(true);
            }
        }

        // 简单的内容检查（读取前 1024 字节）
        if let Ok(mut file) = fs::File::open(path) {
            use std::io::Read;
            let mut buffer = [0; 1024];
            let n = file.read(&mut buffer)?;
            if n > 0 {
                // 检查是否有 null 字节
                if buffer[..n].iter().any(|&b| b == 0) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// 读取文本文件内容
    fn read_text_file(&self, path: &Path) -> Result<String> {
        fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read file {}: {}", path.display(), e))
    }

    /// 创建错误记录
    fn create_error_file_diff(
        &self,
        _path_a: &Path,
        path_b: &Path,
        error: &anyhow::Error,
    ) -> Result<FileDiff> {
        Ok(FileDiff {
            path: path_b.to_string_lossy().to_string(),
            status: FileStatus::Modified,
            lines: vec![DiffLine {
                left_line_number: None,
                right_line_number: None,
                diff_type: DiffType::Equal,
                content: format!("Error reading file: {}", error),
                is_placeholder: false,
            }],
            original_content: None,
            modified_content: None,
            left_stats: FileStats {
                size: 0,
                line_count: 0,
                modified_time: None,
            },
            right_stats: FileStats {
                size: 0,
                line_count: 0,
                modified_time: None,
            },
        })
    }

    /// 计算汇总信息
    fn calculate_summary(&self, diffs: &[FileDiff]) -> ComparisonSummary {
        let mut summary = ComparisonSummary {
            files_added: 0,
            files_deleted: 0,
            files_modified: 0,
            files_renamed: 0,
            lines_added: 0,
            lines_deleted: 0,
        };

        for diff in diffs {
            match diff.status {
                FileStatus::Added => summary.files_added += 1,
                FileStatus::Deleted => summary.files_deleted += 1,
                FileStatus::Modified => summary.files_modified += 1,
                FileStatus::Renamed { .. } => summary.files_renamed += 1,
                FileStatus::Unchanged => {}
            }

            for line in &diff.lines {
                match line.diff_type {
                    DiffType::Insert => summary.lines_added += 1,
                    DiffType::Delete => summary.lines_deleted += 1,
                    _ => {}
                }
            }
        }

        summary
    }

    /// 比较二进制文件
    fn compare_binary_files(
        &self,
        _path_a: &Path,
        path_b: &Path,
        is_binary_a: bool,
        is_binary_b: bool,
    ) -> Result<FileDiff> {
        let metadata_a = fs::metadata(_path_a)?;
        let metadata_b = fs::metadata(path_b)?;

        // TODO: 比较二进制内容 (MD5 or SHA256)
        // 这里简单比较大小
        let modified = metadata_a.len() != metadata_b.len();

        Ok(FileDiff {
            path: path_b.to_string_lossy().to_string(),
            status: if modified {
                FileStatus::Modified
            } else {
                FileStatus::Unchanged
            },
            lines: vec![DiffLine {
                left_line_number: None,
                right_line_number: None,
                diff_type: DiffType::Equal,
                content: format!(
                    "[二进制文件比较] {} vs {}",
                    if is_binary_a { "Binary" } else { "Text" },
                    if is_binary_b { "Binary" } else { "Text" }
                ),
                is_placeholder: false,
            }],
            original_content: None,
            modified_content: None,
            left_stats: FileStats {
                size: metadata_a.len(),
                line_count: 0,
                modified_time: None,
            },
            right_stats: FileStats {
                size: metadata_b.len(),
                line_count: 0,
                modified_time: None,
            },
        })
    }
}
