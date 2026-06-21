// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码搜索工具实现
//!
//! 提供 text_search 和 regex_search 工具，用于在代码库中搜索内容

use async_trait::async_trait;
use regex::Regex;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;

use crate::bridge::{
    ToolCategory, ToolDefinition, ToolError, ToolParameter, ToolParameterType, ToolResult,
};
use crate::registry::Tool;

/// 搜索结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchResult {
    /// 文件路径
    pub file_path: String,
    /// 行号
    pub line_number: usize,
    /// 匹配的行内容
    pub line_content: String,
    /// 匹配的上下文（前后几行）
    pub context: Option<Vec<(usize, String)>>,
}

/// 搜索配置
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// 最大结果数量
    pub max_results: usize,
    /// 是否忽略大小写
    pub case_insensitive: bool,
    /// 包含的文件模式
    pub include_patterns: Vec<String>,
    /// 排除的文件模式
    pub exclude_patterns: Vec<String>,
    /// 上下文行数（前后各多少行）
    pub context_lines: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            max_results: 100,
            case_insensitive: false,
            include_patterns: vec![
                "*.rs".to_string(),
                "*.js".to_string(),
                "*.ts".to_string(),
                "*.jsx".to_string(),
                "*.tsx".to_string(),
                "*.py".to_string(),
                "*.java".to_string(),
                "*.go".to_string(),
                "*.c".to_string(),
                "*.cpp".to_string(),
                "*.h".to_string(),
                "*.hpp".to_string(),
                "*.html".to_string(),
                "*.css".to_string(),
                "*.json".to_string(),
                "*.yaml".to_string(),
                "*.yml".to_string(),
                "*.toml".to_string(),
                "*.md".to_string(),
            ],
            exclude_patterns: vec![
                "node_modules/*".to_string(),
                "target/*".to_string(),
                ".git/*".to_string(),
                "dist/*".to_string(),
                "build/*".to_string(),
                "*.min.js".to_string(),
                "*.min.css".to_string(),
                "*.lock".to_string(),
            ],
            context_lines: 2,
        }
    }
}

/// 检查文件是否匹配模式
fn matches_patterns(path: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

    let path_lower = path.to_lowercase();
    for pattern in patterns {
        let pattern_lower = pattern.to_lowercase();

        // 简单的 glob 匹配
        if pattern_lower.contains('*') {
            let parts: Vec<&str> = pattern_lower.split('*').collect();
            if parts.len() == 2 {
                let prefix = parts[0];
                let suffix = parts[1];
                if (prefix.is_empty() || path_lower.starts_with(prefix))
                    && (suffix.is_empty() || path_lower.ends_with(suffix))
                {
                    return true;
                }
            } else if parts.len() == 1 {
                if pattern_lower.starts_with('*') && path_lower.ends_with(parts[0]) {
                    return true;
                }
                if pattern_lower.ends_with('*') && path_lower.starts_with(parts[0]) {
                    return true;
                }
            }
        } else if path_lower.contains(&pattern_lower) {
            return true;
        }
    }
    false
}

/// 检查路径是否应该被排除
fn should_exclude(path: &str, exclude_patterns: &[String]) -> bool {
    let path_lower = path.to_lowercase();
    for pattern in exclude_patterns {
        let pattern_lower = pattern.to_lowercase();

        // 检查目录排除
        if pattern_lower.ends_with("/*") {
            let dir = &pattern_lower[..pattern_lower.len() - 2];
            if path_lower.starts_with(&format!("{}/", dir)) || path_lower == dir {
                return true;
            }
        }

        // 检查文件扩展名排除
        if pattern_lower.starts_with("*.") {
            let ext = &pattern_lower[1..]; // 包含点
            if path_lower.ends_with(ext) {
                return true;
            }
        }

        // 精确匹配
        if path_lower.contains(&pattern_lower) {
            return true;
        }
    }
    false
}

/// 文本搜索工具
pub struct TextSearchTool {
    project_path: String,
    config: SearchConfig,
}

impl TextSearchTool {
    /// 创建新的文本搜索工具
    pub fn new(project_path: String) -> Self {
        Self {
            project_path,
            config: SearchConfig::default(),
        }
    }

    /// 使用自定义配置创建
    pub fn with_config(project_path: String, config: SearchConfig) -> Self {
        Self {
            project_path,
            config,
        }
    }

    /// 在单个文件中搜索
    async fn search_in_file(
        &self,
        file_path: &Path,
        query: &str,
        case_insensitive: bool,
    ) -> Result<Vec<SearchResult>, std::io::Error> {
        let file = fs::File::open(file_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut results = Vec::new();
        let mut all_lines: Vec<(usize, String)> = Vec::new();

        // 读取所有行
        while let Some(line) = lines.next_line().await? {
            all_lines.push((all_lines.len() + 1, line));
        }

        let query_cmp = if case_insensitive {
            query.to_lowercase()
        } else {
            query.to_string()
        };

        // 搜索匹配
        for (idx, (line_num, line)) in all_lines.iter().enumerate() {
            let line_cmp = if case_insensitive {
                line.to_lowercase()
            } else {
                line.clone()
            };

            if line_cmp.contains(&query_cmp) {
                // 获取上下文
                let context = if self.config.context_lines > 0 {
                    let start = idx.saturating_sub(self.config.context_lines);
                    let end = (idx + self.config.context_lines + 1).min(all_lines.len());
                    Some(all_lines[start..end].to_vec())
                } else {
                    None
                };

                results.push(SearchResult {
                    file_path: file_path.to_string_lossy().to_string(),
                    line_number: *line_num,
                    line_content: line.clone(),
                    context,
                });

                if results.len() >= self.config.max_results {
                    break;
                }
            }
        }

        Ok(results)
    }

    /// 递归搜索目录
    fn search_directory<'a>(
        &'a self,
        dir_path: &'a Path,
        query: &'a str,
        case_insensitive: bool,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<SearchResult>, std::io::Error>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let mut all_results = Vec::new();
            let mut entries = fs::read_dir(dir_path).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();

                // 获取相对路径
                let relative_path = path
                    .strip_prefix(&self.project_path)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                // 检查是否应该排除
                if should_exclude(&relative_path, &self.config.exclude_patterns) {
                    continue;
                }

                if path.is_dir() {
                    // 递归搜索子目录
                    let subdir_results = self
                        .search_directory(&path, query, case_insensitive)
                        .await?;
                    all_results.extend(subdir_results);
                } else if path.is_file() {
                    // 检查文件是否匹配包含模式
                    if !matches_patterns(&relative_path, &self.config.include_patterns) {
                        continue;
                    }

                    // 在文件中搜索
                    if let Ok(file_results) =
                        self.search_in_file(&path, query, case_insensitive).await
                    {
                        all_results.extend(file_results);
                    }
                }

                // 检查是否达到最大结果数
                if all_results.len() >= self.config.max_results {
                    all_results.truncate(self.config.max_results);
                    break;
                }
            }

            Ok(all_results)
        })
    }
}

#[async_trait]
impl Tool for TextSearchTool {
    fn name(&self) -> &str {
        "text_search"
    }

    fn description(&self) -> &str {
        "在代码库中搜索文本。支持大小写敏感/不敏感搜索，可以指定文件模式过滤。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Search
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "query".to_string(),
                param_type: ToolParameterType::String,
                description: "要搜索的文本".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "path".to_string(),
                param_type: ToolParameterType::String,
                description: "搜索路径（相对于项目根目录，默认为整个项目）".to_string(),
                required: false,
                default: Some(serde_json::json!(".")),
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "case_sensitive".to_string(),
                param_type: ToolParameterType::Boolean,
                description: "是否区分大小写".to_string(),
                required: false,
                default: Some(serde_json::json!(false)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_pattern".to_string(),
                param_type: ToolParameterType::String,
                description: "文件模式过滤（如 *.rs）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "max_results".to_string(),
                param_type: ToolParameterType::Integer,
                description: "最大结果数量".to_string(),
                required: false,
                default: Some(serde_json::json!(50)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let query = input["query"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 query 参数".to_string()))?;

        let search_path = input["path"].as_str().unwrap_or(".");
        let case_sensitive = input["case_sensitive"].as_bool().unwrap_or(false);
        let file_pattern = input["file_pattern"].as_str();
        let max_results = input["max_results"].as_u64().unwrap_or(50) as usize;

        // 更新配置
        let mut config = self.config.clone();
        config.max_results = max_results;
        config.case_insensitive = !case_sensitive;

        if let Some(pattern) = file_pattern {
            config.include_patterns = vec![pattern.to_string()];
        }

        let tool = Self::with_config(self.project_path.clone(), config);

        // 构建搜索路径
        let full_path = Path::new(&self.project_path).join(search_path);

        if !full_path.exists() {
            return Err(ToolError::InvalidArgument(format!(
                "路径不存在: {}",
                search_path
            )));
        }

        // 执行搜索
        let results = if full_path.is_file() {
            tool.search_in_file(&full_path, query, !case_sensitive)
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("搜索失败: {}", e)))?
        } else {
            tool.search_directory(&full_path, query, !case_sensitive)
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("搜索失败: {}", e)))?
        };

        // 构建结果文本
        let mut result_text = format!("搜索 '{}' 找到 {} 个结果:\n\n", query, results.len());

        for result in &results {
            result_text.push_str(&format!(
                "{}:{}: {}\n",
                result.file_path, result.line_number, result.line_content
            ));
        }

        // 转换为相对路径
        let relative_results: Vec<_> = results
            .iter()
            .map(|r| {
                let relative_path = Path::new(&r.file_path)
                    .strip_prefix(&self.project_path)
                    .unwrap_or(Path::new(&r.file_path))
                    .to_string_lossy()
                    .to_string();

                SearchResult {
                    file_path: relative_path,
                    line_number: r.line_number,
                    line_content: r.line_content.clone(),
                    context: r.context.clone(),
                }
            })
            .collect();

        Ok(ToolResult::json(
            serde_json::json!({
                "query": query,
                "total_results": relative_results.len(),
                "results": relative_results,
            }),
            Some(result_text),
        ))
    }
}

/// 正则搜索工具
pub struct RegexSearchTool {
    project_path: String,
    config: SearchConfig,
}

impl RegexSearchTool {
    /// 创建新的正则搜索工具
    pub fn new(project_path: String) -> Self {
        Self {
            project_path,
            config: SearchConfig::default(),
        }
    }

    /// 使用自定义配置创建
    pub fn with_config(project_path: String, config: SearchConfig) -> Self {
        Self {
            project_path,
            config,
        }
    }

    /// 在单个文件中搜索
    async fn search_in_file(
        &self,
        file_path: &Path,
        pattern: &Regex,
    ) -> Result<Vec<SearchResult>, std::io::Error> {
        let file = fs::File::open(file_path).await?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        let mut results = Vec::new();
        let mut all_lines: Vec<(usize, String)> = Vec::new();

        // 读取所有行
        while let Some(line) = lines.next_line().await? {
            all_lines.push((all_lines.len() + 1, line));
        }

        // 搜索匹配
        for (idx, (line_num, line)) in all_lines.iter().enumerate() {
            if pattern.is_match(line) {
                // 获取上下文
                let context = if self.config.context_lines > 0 {
                    let start = idx.saturating_sub(self.config.context_lines);
                    let end = (idx + self.config.context_lines + 1).min(all_lines.len());
                    Some(all_lines[start..end].to_vec())
                } else {
                    None
                };

                results.push(SearchResult {
                    file_path: file_path.to_string_lossy().to_string(),
                    line_number: *line_num,
                    line_content: line.clone(),
                    context,
                });

                if results.len() >= self.config.max_results {
                    break;
                }
            }
        }

        Ok(results)
    }

    /// 递归搜索目录
    fn search_directory<'a>(
        &'a self,
        dir_path: &'a Path,
        pattern: &'a Regex,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<SearchResult>, std::io::Error>> + Send + 'a,
        >,
    > {
        Box::pin(async move {
            let mut all_results = Vec::new();
            let mut entries = fs::read_dir(dir_path).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();

                // 获取相对路径
                let relative_path = path
                    .strip_prefix(&self.project_path)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();

                // 检查是否应该排除
                if should_exclude(&relative_path, &self.config.exclude_patterns) {
                    continue;
                }

                if path.is_dir() {
                    // 递归搜索子目录
                    let subdir_results = self.search_directory(&path, pattern).await?;
                    all_results.extend(subdir_results);
                } else if path.is_file() {
                    // 检查文件是否匹配包含模式
                    if !matches_patterns(&relative_path, &self.config.include_patterns) {
                        continue;
                    }

                    // 在文件中搜索
                    if let Ok(file_results) = self.search_in_file(&path, pattern).await {
                        all_results.extend(file_results);
                    }
                }

                // 检查是否达到最大结果数
                if all_results.len() >= self.config.max_results {
                    all_results.truncate(self.config.max_results);
                    break;
                }
            }

            Ok(all_results)
        })
    }
}

#[async_trait]
impl Tool for RegexSearchTool {
    fn name(&self) -> &str {
        "regex_search"
    }

    fn description(&self) -> &str {
        "使用正则表达式在代码库中搜索。支持标准正则表达式语法。"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Search
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::new(self.name(), self.description(), self.category())
            .add_parameter(ToolParameter {
                name: "pattern".to_string(),
                param_type: ToolParameterType::String,
                description: "正则表达式模式".to_string(),
                required: true,
                default: None,
                enum_values: None,
                format: Some("regex".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "path".to_string(),
                param_type: ToolParameterType::String,
                description: "搜索路径（相对于项目根目录，默认为整个项目）".to_string(),
                required: false,
                default: Some(serde_json::json!(".")),
                enum_values: None,
                format: Some("path".to_string()),
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "file_pattern".to_string(),
                param_type: ToolParameterType::String,
                description: "文件模式过滤（如 *.py）".to_string(),
                required: false,
                default: None,
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
            .add_parameter(ToolParameter {
                name: "max_results".to_string(),
                param_type: ToolParameterType::Integer,
                description: "最大结果数量".to_string(),
                required: false,
                default: Some(serde_json::json!(50)),
                enum_values: None,
                format: None,
                items: None,
                properties: None,
            })
    }

    async fn execute(&self, input: serde_json::Value) -> Result<ToolResult, ToolError> {
        let pattern_str = input["pattern"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgument("缺少 pattern 参数".to_string()))?;

        let search_path = input["path"].as_str().unwrap_or(".");
        let file_pattern = input["file_pattern"].as_str();
        let max_results = input["max_results"].as_u64().unwrap_or(50) as usize;

        // 编译正则表达式
        let pattern = Regex::new(pattern_str)
            .map_err(|e| ToolError::InvalidArgument(format!("无效的正则表达式: {}", e)))?;

        // 更新配置
        let mut config = self.config.clone();
        config.max_results = max_results;

        if let Some(pattern) = file_pattern {
            config.include_patterns = vec![pattern.to_string()];
        }

        let tool = Self::with_config(self.project_path.clone(), config);

        // 构建搜索路径
        let full_path = Path::new(&self.project_path).join(search_path);

        if !full_path.exists() {
            return Err(ToolError::InvalidArgument(format!(
                "路径不存在: {}",
                search_path
            )));
        }

        // 执行搜索
        let results = if full_path.is_file() {
            tool.search_in_file(&full_path, &pattern)
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("搜索失败: {}", e)))?
        } else {
            tool.search_directory(&full_path, &pattern)
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("搜索失败: {}", e)))?
        };

        // 构建结果文本
        let mut result_text = format!(
            "正则搜索 '{}' 找到 {} 个结果:\n\n",
            pattern_str,
            results.len()
        );

        for result in &results {
            result_text.push_str(&format!(
                "{}:{}: {}\n",
                result.file_path, result.line_number, result.line_content
            ));
        }

        // 转换为相对路径
        let relative_results: Vec<_> = results
            .iter()
            .map(|r| {
                let relative_path = Path::new(&r.file_path)
                    .strip_prefix(&self.project_path)
                    .unwrap_or(Path::new(&r.file_path))
                    .to_string_lossy()
                    .to_string();

                SearchResult {
                    file_path: relative_path,
                    line_number: r.line_number,
                    line_content: r.line_content.clone(),
                    context: r.context.clone(),
                }
            })
            .collect();

        Ok(ToolResult::json(
            serde_json::json!({
                "pattern": pattern_str,
                "total_results": relative_results.len(),
                "results": relative_results,
            }),
            Some(result_text),
        ))
    }
}

/// 注册搜索工具
pub async fn register_search_tools(
    registry: &Arc<crate::registry::ToolRegistry>,
    project_path: String,
) {
    let tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(TextSearchTool::new(project_path.clone())),
        Arc::new(RegexSearchTool::new(project_path)),
    ];

    for tool in tools {
        if let Err(e) = registry.register(tool).await {
            tracing::warn!("Failed to register search tool: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_patterns() {
        assert!(matches_patterns("main.rs", &["*.rs".to_string()]));
        assert!(matches_patterns("src/main.rs", &["*.rs".to_string()]));
        assert!(!matches_patterns("main.py", &["*.rs".to_string()]));
        assert!(matches_patterns("test.txt", &["*.txt".to_string()]));
    }

    #[test]
    fn test_should_exclude() {
        assert!(should_exclude(
            "node_modules/package/index.js",
            &["node_modules/*".to_string()]
        ));
        assert!(should_exclude(
            "target/debug/main",
            &["target/*".to_string()]
        ));
        assert!(should_exclude("app.min.js", &["*.min.js".to_string()]));
        assert!(!should_exclude(
            "src/main.rs",
            &["node_modules/*".to_string()]
        ));
    }
}
