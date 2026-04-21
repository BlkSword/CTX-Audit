// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Git 历史分析器
//!
//! 分析 Git 提交历史，追踪漏洞引入，"举一反三"发现相似未修复漏洞

use crate::audit_state::VulnerabilityCandidate;
use crate::audit_state::VerificationStatus;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

/// Git 历史分析器
pub struct GitHistoryAnalyzer {
    /// 仓库路径
    repo_path: String,
}

/// 漏洞修复记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFix {
    /// 提交 SHA
    pub commit: String,

    /// 修改的文件
    pub files: Vec<String>,

    /// 漏洞类型
    pub vuln_type: String,

    /// 修复模式
    pub fix_pattern: FixPattern,

    /// 修复前代码
    pub before_code: String,

    /// 修复后代码
    pub after_code: String,

    /// 提交信息
    pub commit_message: String,

    /// 作者
    pub author: String,

    /// 时间戳
    pub timestamp: i64,
}

/// 修复模式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FixPattern {
    /// 添加验证
    AddValidation,

    /// 参数化查询
    ParameterizedQuery,

    /// 输入转义
    InputEscaping,

    /// 权限检查
    PermissionCheck,

    /// CSRF 保护
    CsrfProtection,

    /// 其他
    Other(String),
}

/// 相似漏洞候选
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarVulnerabilityCandidate {
    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 代码片段
    pub code_snippet: String,

    /// 相似的修复
    pub similar_fix: String,

    /// 相似度分数
    pub similarity_score: f32,

    /// 漏洞类型
    pub vuln_type: String,
}

/// 提交差异
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitDiff {
    /// 提交 SHA
    pub commit: String,

    /// 文件路径
    pub file_path: String,

    /// 删除的行
    pub removed_lines: Vec<LineChange>,

    /// 添加的行
    pub added_lines: Vec<LineChange>,
}

/// 行变更
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineChange {
    /// 行号
    pub line_number: usize,

    /// 内容
    pub content: String,

    /// 上下文
    pub context: Vec<String>,
}

impl GitHistoryAnalyzer {
    /// 创建新的 Git 历史分析器
    pub fn new(repo_path: String) -> Self {
        Self { repo_path }
    }

    /// 检查是否是 Git 仓库
    pub fn is_git_repository(&self) -> bool {
        let git_dir = Path::new(&self.repo_path).join(".git");
        git_dir.exists() || Command::new("git")
            .args(["-C", &self.repo_path, "rev-parse", "--is-inside-work-tree"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// 提取漏洞修复记录
    pub fn extract_vulnerability_fixes(&self) -> Vec<VulnerabilityFix> {
        let mut fixes = Vec::new();

        if !self.is_git_repository() {
            tracing::warn!("{} 不是 Git 仓库", self.repo_path);
            return fixes;
        }

        // 获取最近的提交历史
        let commits = self.get_recent_commits(100);

        for commit in commits {
            if let Some(fix) = self.analyze_commit_for_fix(&commit) {
                fixes.push(fix);
            }
        }

        fixes
    }

    /// "举一反三" - 查找相似的未修复漏洞
    pub fn find_similar_unfixed_vulnerabilities(
        &self,
        fixes: &[VulnerabilityFix],
        codebase_files: &[String],
    ) -> Vec<SimilarVulnerabilityCandidate> {
        let mut candidates = Vec::new();

        for fix in fixes {
            let vuln_pattern = self.extract_vulnerability_pattern(&fix.before_code);

            for file_path in codebase_files {
                // 跳过已修复的文件
                if fix.files.contains(file_path) {
                    continue;
                }

                if let Ok(content) = std::fs::read_to_string(file_path) {
                    for (line_num, line) in content.lines().enumerate() {
                        if self.matches_vulnerability_pattern(line, &vuln_pattern)
                            && !self.matches_fix_pattern(line, &fix.fix_pattern)
                        {
                            let similarity = self.calculate_similarity(line, &fix.before_code);

                            if similarity > 0.5 {
                                candidates.push(SimilarVulnerabilityCandidate {
                                    file_path: file_path.clone(),
                                    line: line_num + 1,
                                    code_snippet: line.to_string(),
                                    similar_fix: fix.commit.clone(),
                                    similarity_score: similarity,
                                    vuln_type: fix.vuln_type.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // 按相似度排序
        candidates.sort_by(|a, b| {
            b.similarity_score
                .partial_cmp(&a.similarity_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        candidates
    }

    /// 获取最近的提交
    fn get_recent_commits(&self, limit: usize) -> Vec<GitCommit> {
        let mut commits = Vec::new();

        let output = Command::new("git")
            .args([
                "-C", &self.repo_path,
                "log",
                &format!("-{}", limit),
                "--format=%H|%an|%ai|%s",
            ])
            .output();

        if let Ok(result) = output {
            if result.status.success() {
                for line in String::from_utf8_lossy(&result.stdout).lines() {
                    if let Some(commit) = self.parse_commit_line(line) {
                        commits.push(commit);
                    }
                }
            }
        }

        commits
    }

    /// 解析提交行
    fn parse_commit_line(&self, line: &str) -> Option<GitCommit> {
        let parts: Vec<&str> = line.splitn(4, '|').collect();
        if parts.len() >= 4 {
            Some(GitCommit {
                sha: parts[0].to_string(),
                author: parts[1].to_string(),
                timestamp: parts[2].to_string(),
                message: parts[3].to_string(),
            })
        } else {
            None
        }
    }

    /// 分析提交是否包含漏洞修复
    fn analyze_commit_for_fix(&self, commit: &GitCommit) -> Option<VulnerabilityFix> {
        // 检查提交信息是否包含安全相关关键词
        let security_keywords = [
            "fix", "security", "vulnerability", "xss", "sqli",
            "injection", "csrf", "sanitize", "validate", "escape",
        ];

        let message_lower = commit.message.to_lowercase();
        if !security_keywords.iter().any(|kw| message_lower.contains(kw)) {
            return None;
        }

        // 获取提交的文件变更
        let files = self.get_commit_files(&commit.sha);
        if files.is_empty() {
            return None;
        }

        // 获取差异
        let diffs = self.get_commit_diff(&commit.sha);

        // 分析修复模式
        let fix_pattern = self.detect_fix_pattern(&commit.message, &diffs);

        // 提取修复前后的代码
        let (before_code, after_code) = self.extract_before_after_code(&diffs);

        // 推断漏洞类型
        let vuln_type = self.infer_vulnerability_type(&commit.message, &fix_pattern);

        Some(VulnerabilityFix {
            commit: commit.sha.clone(),
            files,
            vuln_type,
            fix_pattern,
            before_code,
            after_code,
            commit_message: commit.message.clone(),
            author: commit.author.clone(),
            timestamp: self.parse_timestamp(&commit.timestamp),
        })
    }

    /// 获取提交修改的文件
    fn get_commit_files(&self, commit_sha: &str) -> Vec<String> {
        let mut files = Vec::new();

        let output = Command::new("git")
            .args(["-C", &self.repo_path, "diff-tree", "--no-commit-id", "--name-only", "-r", commit_sha])
            .output();

        if let Ok(result) = output {
            if result.status.success() {
                for line in String::from_utf8_lossy(&result.stdout).lines() {
                    if !line.is_empty() {
                        files.push(line.to_string());
                    }
                }
            }
        }

        files
    }

    /// 获取提交差异
    fn get_commit_diff(&self, commit_sha: &str) -> Vec<CommitDiff> {
        let mut diffs = Vec::new();

        let files = self.get_commit_files(commit_sha);

        for file_path in files {
            let output = Command::new("git")
                .args(["-C", &self.repo_path, "diff", &format!("{}^..{}", commit_sha, commit_sha), "--", &file_path])
                .output();

            if let Ok(result) = output {
                if result.status.success() {
                    let diff_content = String::from_utf8_lossy(&result.stdout);
                    let parsed = self.parse_diff(&diff_content, &file_path);
                    diffs.push(parsed);
                }
            }
        }

        diffs
    }

    /// 解析差异
    fn parse_diff(&self, diff_content: &str, file_path: &str) -> CommitDiff {
        let mut removed_lines = Vec::new();
        let mut added_lines = Vec::new();
        let mut current_line = 0;

        for line in diff_content.lines() {
            if line.starts_with("@@") {
                // 解析行号信息
                if let Some(pos) = line.find('+') {
                    let after_plus = &line[pos..];
                    if let Some(end) = after_plus.find(',') {
                        if let Ok(line_num) = after_plus[1..end].parse::<usize>() {
                            current_line = line_num;
                        }
                    }
                }
            } else if line.starts_with('-') && !line.starts_with("---") {
                removed_lines.push(LineChange {
                    line_number: current_line,
                    content: line[1..].to_string(),
                    context: Vec::new(),
                });
            } else if line.starts_with('+') && !line.starts_with("+++") {
                added_lines.push(LineChange {
                    line_number: current_line,
                    content: line[1..].to_string(),
                    context: Vec::new(),
                });
                current_line += 1;
            } else if !line.starts_with('\\') && !line.starts_with('+') && !line.starts_with('-') {
                current_line += 1;
            }
        }

        CommitDiff {
            commit: String::new(),
            file_path: file_path.to_string(),
            removed_lines,
            added_lines,
        }
    }

    /// 检测修复模式
    fn detect_fix_pattern(&self, commit_message: &str, diffs: &[CommitDiff]) -> FixPattern {
        let message_lower = commit_message.to_lowercase();

        // 基于提交信息判断
        if message_lower.contains("parameterized") || message_lower.contains("prepared statement") {
            return FixPattern::ParameterizedQuery;
        }

        if message_lower.contains("sanitize") || message_lower.contains("escape") {
            return FixPattern::InputEscaping;
        }

        if message_lower.contains("permission") || message_lower.contains("authorization") {
            return FixPattern::PermissionCheck;
        }

        if message_lower.contains("csrf") {
            return FixPattern::CsrfProtection;
        }

        // 基于代码变更判断
        for diff in diffs {
            for added in &diff.added_lines {
                let added_lower = added.content.to_lowercase();
                if added_lower.contains("validate")
                    || added_lower.contains("check")
                    || added_lower.contains("sanitize")
                {
                    return FixPattern::AddValidation;
                }
            }
        }

        FixPattern::Other("unknown".to_string())
    }

    /// 提取修复前后的代码
    fn extract_before_after_code(&self, diffs: &[CommitDiff]) -> (String, String) {
        let mut before_code = String::new();
        let mut after_code = String::new();

        for diff in diffs {
            for removed in &diff.removed_lines {
                before_code.push_str(&removed.content);
                before_code.push('\n');
            }
            for added in &diff.added_lines {
                after_code.push_str(&added.content);
                after_code.push('\n');
            }
        }

        (before_code, after_code)
    }

    /// 推断漏洞类型
    fn infer_vulnerability_type(&self, commit_message: &str, fix_pattern: &FixPattern) -> String {
        let message_lower = commit_message.to_lowercase();

        if message_lower.contains("sql") || message_lower.contains("query") {
            return "SQL Injection".to_string();
        }

        if message_lower.contains("xss") || message_lower.contains("cross-site") {
            return "XSS".to_string();
        }

        if message_lower.contains("csrf") {
            return "CSRF".to_string();
        }

        if message_lower.contains("injection") {
            return "Code Injection".to_string();
        }

        match fix_pattern {
            FixPattern::ParameterizedQuery => "SQL Injection".to_string(),
            FixPattern::InputEscaping => "XSS".to_string(),
            FixPattern::PermissionCheck => "Authorization Bypass".to_string(),
            FixPattern::CsrfProtection => "CSRF".to_string(),
            _ => "General Vulnerability".to_string(),
        }
    }

    /// 提取漏洞模式
    fn extract_vulnerability_pattern(&self, code: &str) -> String {
        // 简化实现：提取危险函数调用
        let dangerous_patterns = [
            "execute(", "exec(", "eval(", "system(",
            "query(", "render(", "innerHTML", "document.write",
        ];

        for pattern in &dangerous_patterns {
            if code.contains(pattern) {
                return pattern.to_string();
            }
        }

        // 返回代码的前几个字符作为模式
        code.chars().take(50).collect()
    }

    /// 匹配漏洞模式
    fn matches_vulnerability_pattern(&self, line: &str, pattern: &str) -> bool {
        // 简化实现：检查是否包含危险模式
        let dangerous_keywords = [
            "execute", "exec", "eval", "system", "query",
            "innerHTML", "document.write", "serialize",
        ];

        dangerous_keywords.iter().any(|kw| line.to_lowercase().contains(kw))
    }

    /// 匹配修复模式
    fn matches_fix_pattern(&self, line: &str, fix_pattern: &FixPattern) -> bool {
        let line_lower = line.to_lowercase();

        match fix_pattern {
            FixPattern::AddValidation => {
                line_lower.contains("validate")
                    || line_lower.contains("sanitize")
                    || line_lower.contains("check")
            }
            FixPattern::ParameterizedQuery => {
                line_lower.contains("?")
                    || line_lower.contains("$1")
                    || line_lower.contains("prepared")
            }
            FixPattern::InputEscaping => {
                line_lower.contains("escape")
                    || line_lower.contains("encode")
                    || line_lower.contains("htmlentities")
            }
            FixPattern::PermissionCheck => {
                line_lower.contains("permission")
                    || line_lower.contains("authorize")
                    || line_lower.contains("can(")
            }
            FixPattern::CsrfProtection => {
                line_lower.contains("csrf")
                    || line_lower.contains("token")
            }
            FixPattern::Other(_) => false,
        }
    }

    /// 计算相似度
    fn calculate_similarity(&self, code1: &str, code2: &str) -> f32 {
        // 简化实现：基于词袋余弦相似度
        let words1 = self.extract_words(code1);
        let words2 = self.extract_words(code2);

        if words1.is_empty() || words2.is_empty() {
            return 0.0;
        }

        let intersection: HashSet<_> = words1.iter().collect::<HashSet<_>>()
            .intersection(&words2.iter().collect()).cloned().collect();

        let union: HashSet<_> = words1.iter().chain(words2.iter()).cloned().collect();

        if union.is_empty() {
            0.0
        } else {
            intersection.len() as f32 / union.len() as f32
        }
    }

    /// 提取单词
    fn extract_words(&self, code: &str) -> Vec<String> {
        code.split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
            .collect()
    }

    /// 解析时间戳
    fn parse_timestamp(&self, timestamp: &str) -> i64 {
        // Git log --format="%ai" 输出格式: "2024-01-15 10:30:00 +0800"
        let ts = timestamp.trim();

        // 尝试解析 git 日期格式: "YYYY-MM-DD HH:MM:SS +ZZZZ"
        if let Ok(dt) = chrono::DateTime::parse_from_str(
            &format!("{} +0000", ts),
            "%Y-%m-%d %H:%M:%S %z"
        ) {
            return dt.timestamp();
        }

        // 直接尝试原始格式（带时区）
        if let Ok(dt) = chrono::DateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S %z") {
            return dt.timestamp();
        }

        // 尝试 RFC 3339 格式
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
            return dt.timestamp();
        }

        // 所有解析都失败时返回 0
        tracing::warn!("无法解析时间戳: {}", timestamp);
        0
    }

    /// 将相似漏洞候选转换为 VulnerabilityCandidate
    pub fn convert_to_candidates(
        &self,
        similar: &[SimilarVulnerabilityCandidate],
    ) -> Vec<VulnerabilityCandidate> {
        similar.iter().map(|s| {
            VulnerabilityCandidate {
                id: format!("git_similar_{}", s.file_path.replace("/", "_")),
                vulnerability_type: s.vuln_type.clone(),
                severity: "Medium".to_string(),
                confidence: s.similarity_score,
                source: "git_history_analysis".to_string(),
                file_path: s.file_path.clone(),
                line: s.line,
                code_snippet: Some(s.code_snippet.clone()),
                propagation_path: None,
                verification_status: VerificationStatus::Pending,
                verification_result: None,
            }
        }).collect()
    }

    /// 获取漏洞引入时间线
    pub fn get_vulnerability_timeline(&self, file_path: &str, line: usize) -> Vec<GitCommit> {
        let mut commits = Vec::new();

        let output = Command::new("git")
            .args([
                "-C", &self.repo_path,
                "log",
                "-p",
                "-S", &format!("{}:{}", file_path, line),
                "--format=%H|%an|%ai|%s",
                "--", file_path,
            ])
            .output();

        if let Ok(result) = output {
            if result.status.success() {
                for line in String::from_utf8_lossy(&result.stdout).lines() {
                    if let Some(commit) = self.parse_commit_line(line) {
                        commits.push(commit);
                    }
                }
            }
        }

        commits
    }
}

/// Git 提交
#[derive(Debug, Clone)]
struct GitCommit {
    /// 提交 SHA
    sha: String,

    /// 作者
    author: String,

    /// 时间戳
    timestamp: String,

    /// 提交信息
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_analyzer_creation() {
        let analyzer = GitHistoryAnalyzer::new(".".to_string());
        assert_eq!(analyzer.repo_path, ".");
    }

    #[test]
    fn test_extract_vulnerability_pattern() {
        let analyzer = GitHistoryAnalyzer::new(".".to_string());
        let code = "user_input = request.args.get('input')\nexecute(query)";
        let pattern = analyzer.extract_vulnerability_pattern(code);
        assert_eq!(pattern, "execute(");
    }

    #[test]
    fn test_calculate_similarity() {
        let analyzer = GitHistoryAnalyzer::new(".".to_string());
        let similarity = analyzer.calculate_similarity("execute(user_input)", "execute(query)");
        assert!(similarity > 0.0);
    }
}
