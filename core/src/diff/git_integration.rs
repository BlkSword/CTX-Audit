use crate::diff::types::*;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Git集成处理器
pub struct GitIntegration;

impl GitIntegration {
    /// 创建新的Git集成实例
    pub fn new() -> Self {
        Self
    }

    /// 执行Git比较
    pub fn compare(
        &self,
        params: &GitComparisonParams,
        config: &ComparisonConfig,
    ) -> Result<Vec<FileDiff>> {
        let repo_path = Path::new(&params.repository_path);

        // 验证是否为Git仓库
        if !self.is_git_repository(repo_path)? {
            return Err(anyhow::anyhow!(
                "Not a git repository: {}",
                params.repository_path
            ));
        }

        // 获取两个版本之间的文件变更列表
        let changed_files = self.get_changed_files(params)?;

        // 如果指定了特定文件路径，则过滤
        let files_to_compare: Vec<String> = if params.file_paths.is_empty() {
            changed_files
        } else {
            changed_files
                .into_iter()
                .filter(|file| {
                    params.file_paths.iter().any(|pattern| {
                        file.contains(pattern) || self.matches_pattern(file, pattern)
                    })
                })
                .collect()
        };

        // 并行处理文件比较
        use rayon::prelude::*;
        let file_diffs: Result<Vec<FileDiff>> = files_to_compare
            .into_par_iter()
            .map(|file_path| self.compare_git_file(repo_path, &file_path, params, config))
            .collect();

        file_diffs
    }

    /// 检查是否为Git仓库
    fn is_git_repository(&self, path: &Path) -> Result<bool> {
        let git_dir = path.join(".git");
        Ok(git_dir.exists() || git_dir.is_dir())
    }

    /// 获取两个版本之间的变更文件列表
    fn get_changed_files(&self, params: &GitComparisonParams) -> Result<Vec<String>> {
        let output = Command::new("git")
            .args([
                "-C",
                &params.repository_path,
                "diff",
                "--name-status",
                &params.left_ref,
                &params.right_ref,
            ])
            .output()
            .with_context(|| "Failed to execute git diff --name-status")?;

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Git diff command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut changed_files = Vec::new();

        for line in output_str.lines() {
            if let Some((status, file_path)) = line.split_once('\t') {
                match status {
                    "A" => changed_files.push(file_path.to_string()), // Added
                    "D" => changed_files.push(file_path.to_string()), // Deleted
                    "M" => changed_files.push(file_path.to_string()), // Modified
                    "R" => {
                        // Renamed - git shows "R100\told_path\tnew_path"
                        if let Some((_, new_path)) = file_path.split_once('\t') {
                            changed_files.push(new_path.to_string());
                        } else {
                            changed_files.push(file_path.to_string());
                        }
                    }
                    "C" => {
                        // Copied - git shows "C100\tsource\tdestination"
                        if let Some((_, new_path)) = file_path.split_once('\t') {
                            changed_files.push(new_path.to_string());
                        } else {
                            changed_files.push(file_path.to_string());
                        }
                    }
                    _ => changed_files.push(file_path.to_string()),
                }
            }
        }

        Ok(changed_files)
    }

    /// 比较Git中的单个文件
    fn compare_git_file(
        &self,
        repo_path: &Path,
        file_path: &str,
        params: &GitComparisonParams,
        config: &ComparisonConfig,
    ) -> Result<FileDiff> {
        // 获取文件在左侧版本的内容
        let left_content =
            self.get_file_content_at_commit(repo_path, file_path, &params.left_ref)?;

        // 获取文件在右侧版本的内容
        let right_content =
            self.get_file_content_at_commit(repo_path, file_path, &params.right_ref)?;

        // 获取文件状态
        let file_status = self.get_file_status(repo_path, file_path, params)?;

        // 处理内容
        let left_lines: Vec<String> = if config.ignore_whitespace {
            left_content
                .lines()
                .map(|line| line.trim().to_string())
                .collect()
        } else {
            left_content.lines().map(|line| line.to_string()).collect()
        };

        let right_lines: Vec<String> = if config.ignore_whitespace {
            right_content
                .lines()
                .map(|line| line.trim().to_string())
                .collect()
        } else {
            right_content.lines().map(|line| line.to_string()).collect()
        };

        // 计算差异
        let diff_lines = self.compute_git_line_diff(&left_lines, &right_lines);

        // 获取文件统计信息
        let (left_stats, right_stats) = self.get_git_file_stats(repo_path, file_path, params)?;

        // 限制内容大小为 1MB
        let include_content = left_stats.size < 1024 * 1024 && right_stats.size < 1024 * 1024;

        Ok(FileDiff {
            path: file_path.to_string(),
            status: file_status,
            lines: diff_lines,
            original_content: if include_content {
                Some(left_content)
            } else {
                None
            },
            modified_content: if include_content {
                Some(right_content)
            } else {
                None
            },
            left_stats,
            right_stats,
        })
    }

    /// 获取文件在特定commit的内容
    fn get_file_content_at_commit(
        &self,
        repo_path: &Path,
        file_path: &str,
        commit_ref: &str,
    ) -> Result<String> {
        let output = Command::new("git")
            .args([
                "-C",
                &repo_path.to_string_lossy(),
                "show",
                &format!("{}:{}", commit_ref, file_path),
            ])
            .output()
            .with_context(|| format!("Failed to get file content at commit {}", commit_ref))?;

        if !output.status.success() {
            // 文件可能在指定commit中不存在，返回空字符串
            Ok(String::new())
        } else {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        }
    }

    /// 获取文件在两个版本之间的状态
    fn get_file_status(
        &self,
        repo_path: &Path,
        file_path: &str,
        params: &GitComparisonParams,
    ) -> Result<FileStatus> {
        let output = Command::new("git")
            .args([
                "-C",
                &repo_path.to_string_lossy(),
                "diff",
                "--name-status",
                &params.left_ref,
                &params.right_ref,
                "--",
                file_path,
            ])
            .output()
            .with_context(|| "Failed to get file status")?;

        if !output.status.success() {
            return Ok(FileStatus::Unchanged);
        }

        let output_str = String::from_utf8_lossy(&output.stdout);

        for line in output_str.lines() {
            if let Some((status, path)) = line.split_once('\t') {
                if path == file_path {
                    match status {
                        "A" => return Ok(FileStatus::Added),
                        "D" => return Ok(FileStatus::Deleted),
                        "M" => return Ok(FileStatus::Modified),
                        "R" => {
                            // 对于重命名，我们需要获取旧路径
                            if let Some(old_path) =
                                self.get_renamed_from_path(repo_path, file_path, params)?
                            {
                                return Ok(FileStatus::Renamed { old_path });
                            }
                        }
                        "C" => return Ok(FileStatus::Added), // Copy treated as add
                        _ => {}
                    }
                }
            }
        }

        Ok(FileStatus::Unchanged)
    }

    /// 获取重命名文件的原始路径
    fn get_renamed_from_path(
        &self,
        repo_path: &Path,
        new_path: &str,
        params: &GitComparisonParams,
    ) -> Result<Option<String>> {
        let output = Command::new("git")
            .args([
                "-C",
                &repo_path.to_string_lossy(),
                "log",
                "--follow",
                "--name-status",
                "--pretty=format:",
                &format!("{}..{}", params.left_ref, params.right_ref),
                "--",
                new_path,
            ])
            .output()
            .with_context(|| "Failed to follow file renames")?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        for line in output_str.lines() {
            if let Some((status, path)) = line.split_once('\t') {
                if status == "R" && path != new_path {
                    return Ok(Some(path.to_string()));
                }
            }
        }

        Ok(None)
    }

    /// 计算Git文件行级别的差异
    fn compute_git_line_diff(&self, lines_a: &[String], lines_b: &[String]) -> Vec<DiffLine> {
        use similar::{Algorithm, ChangeTag, TextDiff};

        let text_a = lines_a.join("\n");
        let text_b = lines_b.join("\n");

        let diff = TextDiff::configure()
            .algorithm(Algorithm::Myers)
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

    /// 获取Git文件的统计信息
    fn get_git_file_stats(
        &self,
        repo_path: &Path,
        file_path: &str,
        params: &GitComparisonParams,
    ) -> Result<(FileStats, FileStats)> {
        // 左侧版本统计
        let left_content =
            self.get_file_content_at_commit(repo_path, file_path, &params.left_ref)?;
        let left_size = left_content.len() as u64;
        let left_line_count = left_content.lines().count() as u32;

        // 右侧版本统计
        let right_content =
            self.get_file_content_at_commit(repo_path, file_path, &params.right_ref)?;
        let right_size = right_content.len() as u64;
        let right_line_count = right_content.lines().count() as u32;

        // 获取修改时间（获取commit时间）
        let left_time = self.get_commit_time(repo_path, &params.left_ref)?;
        let right_time = self.get_commit_time(repo_path, &params.right_ref)?;

        let left_stats = FileStats {
            size: left_size,
            line_count: left_line_count,
            modified_time: Some(left_time),
        };

        let right_stats = FileStats {
            size: right_size,
            line_count: right_line_count,
            modified_time: Some(right_time),
        };

        Ok((left_stats, right_stats))
    }

    /// 获取commit的Unix时间戳
    fn get_commit_time(&self, repo_path: &Path, commit_ref: &str) -> Result<i64> {
        let output = Command::new("git")
            .args([
                "-C",
                &repo_path.to_string_lossy(),
                "show",
                "-s",
                "--format=%ct",
                commit_ref,
            ])
            .output()
            .with_context(|| format!("Failed to get commit time for {}", commit_ref))?;

        if !output.status.success() {
            return Ok(0);
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let timestamp_str = output_str.trim();
        timestamp_str
            .parse::<i64>()
            .with_context(|| "Invalid timestamp format")
    }

    /// 检查文件路径是否匹配模式
    fn matches_pattern(&self, file_path: &str, pattern: &str) -> bool {
        // 简单的通配符匹配实现
        if pattern.contains('*') {
            // 转换为正则表达式
            let regex_pattern = pattern.replace('.', r"\.").replace('*', ".*");

            if let Ok(regex) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
                regex.is_match(file_path)
            } else {
                file_path == pattern
            }
        } else {
            file_path.contains(pattern)
        }
    }

    /// 获取分支和标签列表
    pub fn get_refs(&self, repo_path: &str) -> Result<Vec<(String, String)>> {
        let repo_path = Path::new(repo_path);

        if !self.is_git_repository(repo_path)? {
            return Err(anyhow::anyhow!("Not a git repository"));
        }

        // 获取分支
        let branches_output = Command::new("git")
            .args(["-C", repo_path.to_string_lossy().as_ref(), "branch", "-a"])
            .output()
            .with_context(|| "Failed to get branches")?;

        // 获取标签
        let tags_output = Command::new("git")
            .args(["-C", repo_path.to_string_lossy().as_ref(), "tag"])
            .output()
            .with_context(|| "Failed to get tags")?;

        let mut refs = Vec::new();

        // 处理分支
        if branches_output.status.success() {
            let branches_str = String::from_utf8_lossy(&branches_output.stdout);
            for line in branches_str.lines() {
                let line_trim = line.trim().replace('*', "");
                let branch = line_trim.trim();
                if !branch.is_empty() {
                    refs.push((branch.to_string(), "branch".to_string()));
                }
            }
        }

        // 处理标签
        if tags_output.status.success() {
            let tags_str = String::from_utf8_lossy(&tags_output.stdout);
            for tag in tags_str.lines() {
                let tag_trim = tag.trim();
                if !tag_trim.is_empty() {
                    refs.push((tag_trim.to_string(), "tag".to_string()));
                }
            }
        }

        Ok(refs)
    }
}
