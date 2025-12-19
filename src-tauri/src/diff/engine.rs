use crate::diff::types::*;
use crate::diff::git_integration::GitIntegration;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::Read;

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
                if path_a.is_file() { "file" } else { "directory" },
                if path_b.is_file() { "file" } else { "directory" }
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
            content_a.lines().map(|line| line.trim().to_string()).collect()
        } else {
            content_a.lines().map(|line| line.to_string()).collect()
        };

        let lines_b: Vec<String> = if self.config.ignore_whitespace {
            content_b.lines().map(|line| line.trim().to_string()).collect()
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

        Ok(FileDiff {
            path: path_b.to_string_lossy().to_string(),
            status: if diff_lines.iter().all(|line| line.diff_type == DiffType::Equal) {
                FileStatus::Unchanged
            } else {
                FileStatus::Modified
            },
            lines: diff_lines,
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

        // 并行处理所有文件，收集成功的结果和跳过的文件
        let results: Vec<Result<FileDiff>> = all_paths
            .into_par_iter()
            .map(|relative_path| {
                match (files_a_set.get(&relative_path), files_b_set.get(&relative_path)) {
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
                        // 这种情况理论上不应该发生，但为了完整性
                        unreachable!("File path not found in either directory")
                    }
                }
            })
            .collect();

        // 分离成功的结果和错误
        let mut diffs = Vec::new();
        let mut skipped_files = Vec::new();

        for result in results {
            match result {
                Ok(diff) => diffs.push(diff),
                Err(e) => {
                    // 记录跳过的文件，但继续处理其他文件
                    skipped_files.push(format!("跳过文件: {}", e));
                }
            }
        }

        // 如果有跳过的文件，可以在日志中记录（这里暂时不记录，避免干扰用户）
        if !skipped_files.is_empty() {
            // 可以选择在结果中包含跳过的文件信息
        }

        // 如果启用了重命名检测
        if self.config.detect_renames {
            self.detect_renames(&mut diffs);
        }

        file_diffs.extend(diffs);
        Ok(file_diffs)
    }

    /// 计算行级别的差异
    fn compute_line_diff(&self, lines_a: &[String], lines_b: &[String]) -> Vec<DiffLine> {
        use dissimilar::{Chunk, diff};

        let text_a = lines_a.join("\n");
        let text_b = lines_b.join("\n");

        let chunks = diff(&text_a, &text_b);
        let mut result = Vec::new();
        let mut left_line_num = 1u32;
        let mut right_line_num = 1u32;

        for chunk in chunks {
            match chunk {
                Chunk::Equal(text) => {
                    for line in text.lines() {
                        result.push(DiffLine {
                            left_line_number: Some(left_line_num),
                            right_line_number: Some(right_line_num),
                            diff_type: DiffType::Equal,
                            content: line.to_string(),
                            is_placeholder: false,
                        });
                        left_line_num += 1;
                        right_line_num += 1;
                    }
                }
                Chunk::Delete(text) => {
                    for line in text.lines() {
                        result.push(DiffLine {
                            left_line_number: Some(left_line_num),
                            right_line_number: None,
                            diff_type: DiffType::Delete,
                            content: line.to_string(),
                            is_placeholder: false,
                        });
                        left_line_num += 1;
                    }
                }
                Chunk::Insert(text) => {
                    for line in text.lines() {
                        result.push(DiffLine {
                            left_line_number: None,
                            right_line_number: Some(right_line_num),
                            diff_type: DiffType::Insert,
                            content: line.to_string(),
                            is_placeholder: false,
                        });
                        right_line_num += 1;
                    }
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
                lines: vec![
                    DiffLine {
                        left_line_number: Some(1),
                        right_line_number: None,
                        diff_type: DiffType::Delete,
                        content: format!("[二进制文件] 大小: {} 字节", metadata.len()),
                        is_placeholder: false,
                    }
                ],
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
                lines: vec![
                    DiffLine {
                        left_line_number: None,
                        right_line_number: Some(1),
                        diff_type: DiffType::Insert,
                        content: format!("[二进制文件] 大小: {} 字节", metadata.len()),
                        is_placeholder: false,
                    }
                ],
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

    /// 检测文件重命名
    fn detect_renames(&self, diffs: &mut Vec<FileDiff>) {
        // 先收集所有的信息，避免借用问题
        let added_files: Vec<(usize, &FileDiff)> = diffs.iter()
            .enumerate()
            .filter(|(_, diff)| matches!(diff.status, FileStatus::Added) && !diff.lines.is_empty())
            .collect();

        let deleted_files: Vec<&FileDiff> = diffs.iter()
            .filter(|diff| matches!(diff.status, FileStatus::Deleted))
            .collect();

        let mut rename_mappings: Vec<(usize, String)> = Vec::new();

        // 检查重命名
        for (add_idx, added) in added_files {
            for deleted in &deleted_files {
                let similarity = self.calculate_similarity(&deleted.lines, &added.lines);
                if similarity >= self.config.rename_similarity_threshold {
                    rename_mappings.push((add_idx, deleted.path.clone()));
                    break;
                }
            }
        }

        // 应用重命名标记
        for (new_idx, old_path) in &rename_mappings {
            if let Some(diff) = diffs.get_mut(*new_idx) {
                diff.status = FileStatus::Renamed { old_path: old_path.clone() };
            }
        }

        // 收集要删除的文件路径（被重命名的文件）
        let mut paths_to_remove: Vec<String> = Vec::new();
        for (_, old_path) in &rename_mappings {
            paths_to_remove.push(old_path.clone());
        }

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
        if lines_a.iter().any(|line| line.content.starts_with("[二进制文件]")) ||
           lines_b.iter().any(|line| line.content.starts_with("[二进制文件]")) {
            return 0.0; // 二进制文件不参与重命名检测
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
                "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg",
                "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
                "zip", "rar", "7z", "tar", "gz", "bz2",
                "exe", "dll", "so", "dylib",
                "jar", "war", "ear", "class",
                "mp3", "mp4", "avi", "mov", "wmv",
                "ttf", "otf", "woff", "woff2",
            ];

            if binary_extensions.contains(&ext_lower.as_str()) {
                return Ok(true);
            }
        }

        // 读取文件头部检查是否包含null字节
        const BUFFER_SIZE: usize = 1024;
        let mut file = std::fs::File::open(path)?;
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let bytes_read = file.read(&mut buffer)?;

        // 如果文件为空，视为文本文件
        if bytes_read == 0 {
            return Ok(false);
        }

        // 检查是否包含null字节（通常表示二进制文件）
        if buffer[..bytes_read].contains(&0) {
            return Ok(true);
        }

        // 检查UTF-8有效性，如果无效则认为是二进制文件
        match std::str::from_utf8(&buffer[..bytes_read]) {
            Ok(_) => Ok(false),
            Err(_) => Ok(true),
        }
    }

    /// 安全地读取文本文件
    fn read_text_file(&self, path: &Path) -> Result<String> {
        use std::io::Read;

        // 限制文件大小以避免内存问题
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return Err(anyhow::anyhow!("无法访问文件 {}: {}", path.display(), e));
            }
        };

        if metadata.len() > 10 * 1024 * 1024 { // 10MB限制
            return Err(anyhow::anyhow!("文件过大，跳过文本比较"));
        }

        // 尝试以UTF-8编码读取文件
        match fs::read_to_string(path) {
            Ok(content) => Ok(content),
            Err(e) => {
                // 如果UTF-8读取失败，尝试以二进制方式读取并转换
                match fs::read(path) {
                    Ok(bytes) => {
                        // 尝试不同的编码
                        if let Ok(utf8_content) = String::from_utf8(bytes.clone()) {
                            Ok(utf8_content)
                        } else {
                            let (windows1252_content, _, _) = encoding_rs::WINDOWS_1252.decode(&bytes);
                            if !windows1252_content.is_empty() {
                                Ok(windows1252_content.to_string())
                            } else {
                                let (gbk_content, _, _) = encoding_rs::GBK.decode(&bytes);
                                if !gbk_content.is_empty() {
                                    Ok(gbk_content.to_string())
                                } else {
                                    // 如果都无法解码，返回错误信息
                                    Err(anyhow::anyhow!(
                                        "无法解码文件 {}，可能包含非文本二进制数据。错误: {}",
                                        path.display(),
                                        e
                                    ))
                                }
                            }
                        }
                    }
                    Err(io_err) => {
                        Err(anyhow::anyhow!(
                            "无法读取文件 {}: {}。原因: {}",
                            path.display(),
                            e,
                            io_err
                        ))
                    }
                }
            }
        }
    }

    /// 比较二进制文件
    fn compare_binary_files(&self, path_a: &Path, path_b: &Path, is_binary_a: bool, is_binary_b: bool) -> Result<FileDiff> {
        let metadata_a = fs::metadata(path_a)?;
        let metadata_b = fs::metadata(path_b)?;

        let mut status = FileStatus::Modified;
        let mut lines = Vec::new();

        // 如果两个文件都是二进制且大小相同，检查哈希值
        if is_binary_a && is_binary_b {
            let hash_a = self.calculate_file_hash(path_a)?;
            let hash_b = self.calculate_file_hash(path_b)?;

            if hash_a == hash_b {
                status = FileStatus::Unchanged;
            } else {
                // 添加二进制文件差异标记
                lines.push(DiffLine {
                    left_line_number: Some(1),
                    right_line_number: Some(1),
                    diff_type: DiffType::Delete,
                    content: format!("[二进制文件] 大小: {} 字节", metadata_a.len()),
                    is_placeholder: false,
                });

                lines.push(DiffLine {
                    left_line_number: Some(2),
                    right_line_number: Some(2),
                    diff_type: DiffType::Insert,
                    content: format!("[二进制文件] 大小: {} 字节", metadata_b.len()),
                    is_placeholder: false,
                });
            }
        } else {
            // 一个是二进制，一个是文本
            let binary_status = if is_binary_a { "二进制" } else { "文本" };
            let text_status = if is_binary_b { "二进制" } else { "文本" };

            lines.push(DiffLine {
                left_line_number: Some(1),
                right_line_number: Some(1),
                diff_type: DiffType::Delete,
                content: format!("[{}文件] {}", binary_status, metadata_a.len()),
                is_placeholder: false,
            });

            lines.push(DiffLine {
                left_line_number: Some(2),
                right_line_number: Some(2),
                diff_type: DiffType::Insert,
                content: format!("[{}文件] {}", text_status, metadata_b.len()),
                is_placeholder: false,
            });
        }

        let left_stats = FileStats {
            size: metadata_a.len(),
            line_count: if lines.is_empty() { 0 } else { 1 },
            modified_time: metadata_a
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
        };

        let right_stats = FileStats {
            size: metadata_b.len(),
            line_count: if lines.is_empty() { 0 } else { 1 },
            modified_time: metadata_b
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
        };

        Ok(FileDiff {
            path: path_b.to_string_lossy().to_string(),
            status,
            lines,
            left_stats,
            right_stats,
        })
    }

    /// 创建文件读取错误的差异记录
    fn create_error_file_diff(&self, path_a: &Path, path_b: &Path, error: &anyhow::Error) -> Result<FileDiff> {
        let metadata_a = fs::metadata(path_a).unwrap_or_else(|_| {
            // 如果无法获取元数据，创建默认值
            std::fs::metadata(".").unwrap().into()
        });
        let metadata_b = fs::metadata(path_b).unwrap_or_else(|_| {
            // 如果无法获取元数据，创建默认值
            std::fs::metadata(".").unwrap().into()
        });

        let lines = vec![
            DiffLine {
                left_line_number: Some(1),
                right_line_number: Some(1),
                diff_type: DiffType::Equal,
                content: format!("[文件读取错误] {}", error),
                is_placeholder: false,
            }
        ];

        let left_stats = FileStats {
            size: metadata_a.len(),
            line_count: 1,
            modified_time: metadata_a
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
        };

        let right_stats = FileStats {
            size: metadata_b.len(),
            line_count: 1,
            modified_time: metadata_b
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64),
        };

        Ok(FileDiff {
            path: path_b.to_string_lossy().to_string(),
            status: FileStatus::Modified,
            lines,
            left_stats,
            right_stats,
        })
    }

    /// 计算文件哈希值
    fn calculate_file_hash(&self, path: &Path) -> Result<u64> {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let content = std::fs::read(path)?;
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        Ok(hasher.finish())
    }

    /// 计算比较结果的总体统计
    fn calculate_summary(&self, file_diffs: &[FileDiff]) -> ComparisonSummary {
        let mut summary = ComparisonSummary {
            files_added: 0,
            files_deleted: 0,
            files_modified: 0,
            files_renamed: 0,
            lines_added: 0,
            lines_deleted: 0,
        };

        for diff in file_diffs {
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
}