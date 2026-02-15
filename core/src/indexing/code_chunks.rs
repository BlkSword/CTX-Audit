// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码块索引系统
//!
//! 将代码分割成语义单元（函数、类、方法等）用于嵌入和检索

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::collections::HashMap;

/// 代码块类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkType {
    /// 函数
    Function,
    /// 方法
    Method,
    /// 类
    Class,
    /// 接口
    Interface,
    /// 结构体
    Struct,
    /// 模块
    Module,
    /// 代码片段（通用）
    Snippet,
    /// 文件级别
    File,
}

impl std::fmt::Display for ChunkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkType::Function => write!(f, "Function"),
            ChunkType::Method => write!(f, "Method"),
            ChunkType::Class => write!(f, "Class"),
            ChunkType::Interface => write!(f, "Interface"),
            ChunkType::Struct => write!(f, "Struct"),
            ChunkType::Module => write!(f, "Module"),
            ChunkType::Snippet => write!(f, "Snippet"),
            ChunkType::File => write!(f, "File"),
        }
    }
}

/// 代码块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeChunk {
    /// 唯一标识符
    pub id: String,

    /// 文件路径
    pub file_path: PathBuf,

    /// 相对路径（相对于项目根目录）
    pub relative_path: String,

    /// 代码块类型
    pub chunk_type: ChunkType,

    /// 符号名称（函数名、类名等）
    pub name: String,

    /// 代码内容
    pub content: String,

    /// 起始行号
    pub start_line: usize,

    /// 结束行号
    pub end_line: usize,

    /// 语言
    pub language: String,

    /// 嵌入向量（可选，后续填充）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,

    /// 元数据
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,

    /// 用于搜索的文本表示
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_text: Option<String>,
}

impl CodeChunk {
    /// 创建新的代码块
    pub fn new(
        file_path: PathBuf,
        relative_path: String,
        chunk_type: ChunkType,
        name: String,
        content: String,
        start_line: usize,
        end_line: usize,
        language: String,
    ) -> Self {
        let id = Self::generate_id(&file_path, start_line, &name);

        // 生成搜索文本（包含上下文信息）
        let search_text = Some(Self::build_search_text(
            &name,
            &chunk_type,
            &content,
            &language,
        ));

        Self {
            id,
            file_path,
            relative_path,
            chunk_type,
            name,
            content,
            start_line,
            end_line,
            language,
            embedding: None,
            metadata: HashMap::new(),
            search_text,
        }
    }

    /// 生成唯一 ID
    fn generate_id(file_path: &Path, start_line: usize, name: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(file_path.to_string_lossy().as_bytes());
        hasher.update(start_line.to_string().as_bytes());
        hasher.update(name.as_bytes());
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    /// 构建搜索文本
    fn build_search_text(
        name: &str,
        chunk_type: &ChunkType,
        content: &str,
        language: &str,
    ) -> String {
        // 包含符号名、类型和代码内容的简化版本
        let content_preview = if content.len() > 500 {
            &content[..500]
        } else {
            content
        };

        format!(
            "{} {} in {}: {}",
            chunk_type, name, language, content_preview
        )
    }

    /// 添加元数据
    pub fn with_metadata(mut self, key: &str, value: serde_json::Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    /// 设置嵌入向量
    pub fn with_embedding(mut self, embedding: Vec<f32>) -> Self {
        self.embedding = Some(embedding);
        self
    }

    /// 获取代码行数
    pub fn line_count(&self) -> usize {
        self.end_line - self.start_line + 1
    }

    /// 获取内容字符数
    pub fn char_count(&self) -> usize {
        self.content.len()
    }
}

/// 代码块提取配置
#[derive(Debug, Clone)]
pub struct ChunkConfig {
    /// 最大块大小（字符数）
    pub max_chunk_size: usize,

    /// 最小块大小（字符数）
    pub min_chunk_size: usize,

    /// 最大重叠（字符数）
    pub max_overlap: usize,

    /// 是否包含导入语句
    pub include_imports: bool,

    /// 是否包含注释
    pub include_comments: bool,

    /// 是否分割大函数
    pub split_large_functions: bool,

    /// 要处理的文件扩展名
    pub file_extensions: Vec<String>,

    /// 要排除的目录
    pub exclude_dirs: Vec<String>,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: 2000,
            min_chunk_size: 50,
            max_overlap: 200,
            include_imports: false,
            include_comments: false,
            split_large_functions: true,
            file_extensions: vec![
                "rs".to_string(), "js".to_string(), "ts".to_string(),
                "jsx".to_string(), "tsx".to_string(), "py".to_string(),
                "java".to_string(), "go".to_string(), "c".to_string(),
                "cpp".to_string(), "h".to_string(), "hpp".to_string(),
            ],
            exclude_dirs: vec![
                "node_modules".to_string(), "target".to_string(),
                ".git".to_string(), "dist".to_string(),
                "build".to_string(), "vendor".to_string(),
            ],
        }
    }
}

impl ChunkConfig {
    /// 创建新配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置最大块大小
    pub fn with_max_chunk_size(mut self, size: usize) -> Self {
        self.max_chunk_size = size;
        self
    }

    /// 添加文件扩展名
    pub fn with_extension(mut self, ext: &str) -> Self {
        self.file_extensions.push(ext.to_string());
        self
    }

    /// 添加排除目录
    pub fn with_exclude_dir(mut self, dir: &str) -> Self {
        self.exclude_dirs.push(dir.to_string());
        self
    }
}

/// 代码块提取器
pub struct CodeChunker {
    config: ChunkConfig,
}

impl CodeChunker {
    /// 创建新的代码块提取器
    pub fn new(config: ChunkConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建
    pub fn with_defaults() -> Self {
        Self::new(ChunkConfig::default())
    }

    /// 检查文件是否应该被处理
    pub fn should_process(&self, path: &Path) -> bool {
        // 检查扩展名
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if !self.config.file_extensions.contains(&ext.to_lowercase()) {
                return false;
            }
        } else {
            return false;
        }

        // 检查排除目录
        let path_str = path.to_string_lossy();
        for exclude in &self.config.exclude_dirs {
            if path_str.contains(&format!("/{}", exclude)) ||
               path_str.contains(&format!("\\{}", exclude)) {
                return false;
            }
        }

        true
    }

    /// 从文件提取代码块
    pub async fn chunk_file(
        &self,
        file_path: &Path,
        project_root: &Path,
    ) -> Result<Vec<CodeChunk>, std::io::Error> {
        if !self.should_process(file_path) {
            return Ok(Vec::new());
        }

        let content = tokio::fs::read_to_string(file_path).await?;

        // 获取相对路径
        let relative_path = file_path
            .strip_prefix(project_root)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        // 获取语言
        let language = Self::detect_language(file_path);

        // 基于语言提取代码块
        let chunks = self.extract_chunks(&content, file_path, &relative_path, &language);

        Ok(chunks)
    }

    /// 从内容中提取代码块
    fn extract_chunks(
        &self,
        content: &str,
        file_path: &Path,
        relative_path: &str,
        language: &str,
    ) -> Vec<CodeChunk> {
        let lines: Vec<&str> = content.lines().collect();
        let mut chunks = Vec::new();

        // 基于缩进和关键字检测代码块
        let block_starts = self.detect_block_starts(&lines, language);

        if block_starts.is_empty() {
            // 如果没有检测到结构化代码块，将整个文件作为一个块
            if content.len() >= self.config.min_chunk_size {
                chunks.push(CodeChunk::new(
                    file_path.to_path_buf(),
                    relative_path.to_string(),
                    ChunkType::File,
                    file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    content.to_string(),
                    1,
                    lines.len(),
                    language.to_string(),
                ));
            }
        } else {
            // 提取每个检测到的代码块
            for (i, (name, chunk_type, start_line)) in block_starts.iter().enumerate() {
                let end_line = if i + 1 < block_starts.len() {
                    block_starts[i + 1].2 - 1
                } else {
                    lines.len()
                };

                // 计算实际的结束行（基于缩进）
                let actual_end = self.find_block_end(&lines, *start_line, language);
                let final_end = actual_end.min(end_line);

                if final_end >= *start_line {
                    let block_content: String =
                        lines[start_line.saturating_sub(1)..final_end.min(lines.len())]
                            .iter()
                            .cloned()
                            .collect::<Vec<&str>>()
                            .join("\n");

                    // 检查大小限制
                    if block_content.len() >= self.config.min_chunk_size {
                        let mut chunk = CodeChunk::new(
                            file_path.to_path_buf(),
                            relative_path.to_string(),
                            *chunk_type,
                            name.clone(),
                            block_content,
                            *start_line,
                            final_end,
                            language.to_string(),
                        );

                        // 如果块太大，分割它
                        if chunk.content.len() > self.config.max_chunk_size
                            && self.config.split_large_functions
                        {
                            let sub_chunks = self.split_large_chunk(
                                chunk,
                                &lines,
                                *start_line,
                                final_end,
                            );
                            chunks.extend(sub_chunks);
                        } else {
                            chunks.push(chunk);
                        }
                    }
                }
            }
        }

        chunks
    }

    /// 检测代码块起始位置
    fn detect_block_starts(
        &self,
        lines: &[&str],
        language: &str,
    ) -> Vec<(String, ChunkType, usize)> {
        let mut blocks = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // 根据语言检测不同的代码块
            match language {
                "rust" => {
                    if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
                        let name = self.extract_function_name(trimmed, "fn");
                        let chunk_type = if trimmed.contains("impl") {
                            ChunkType::Method
                        } else {
                            ChunkType::Function
                        };
                        blocks.push((name, chunk_type, i + 1));
                    } else if trimmed.starts_with("struct ") || trimmed.starts_with("pub struct ") {
                        let name = self.extract_struct_name(trimmed);
                        blocks.push((name, ChunkType::Struct, i + 1));
                    } else if trimmed.starts_with("impl ") {
                        let name = self.extract_impl_name(trimmed);
                        blocks.push((name, ChunkType::Class, i + 1));
                    } else if trimmed.starts_with("trait ") || trimmed.starts_with("pub trait ") {
                        let name = self.extract_trait_name(trimmed);
                        blocks.push((name, ChunkType::Interface, i + 1));
                    }
                }
                "python" => {
                    if trimmed.starts_with("def ") || trimmed.starts_with("async def ") {
                        let name = self.extract_python_function_name(trimmed);
                        let chunk_type = if self.is_method(&lines[..i]) {
                            ChunkType::Method
                        } else {
                            ChunkType::Function
                        };
                        blocks.push((name, chunk_type, i + 1));
                    } else if trimmed.starts_with("class ") {
                        let name = self.extract_python_class_name(trimmed);
                        blocks.push((name, ChunkType::Class, i + 1));
                    }
                }
                "javascript" | "typescript" | "jsx" | "tsx" => {
                    if trimmed.starts_with("function ")
                        || trimmed.starts_with("async function ")
                        || trimmed.starts_with("export function ")
                        || trimmed.starts_with("const ")
                        || trimmed.starts_with("export const ")
                    {
                        if trimmed.contains("=>") || trimmed.contains("function") {
                            let name = self.extract_js_function_name(trimmed);
                            blocks.push((name, ChunkType::Function, i + 1));
                        }
                    } else if trimmed.starts_with("class ") || trimmed.starts_with("export class ") {
                        let name = self.extract_js_class_name(trimmed);
                        blocks.push((name, ChunkType::Class, i + 1));
                    }
                }
                "java" => {
                    if trimmed.contains("class ") && trimmed.contains("{") {
                        let name = self.extract_java_class_name(trimmed);
                        blocks.push((name, ChunkType::Class, i + 1));
                    } else if (trimmed.starts_with("public ")
                        || trimmed.starts_with("private ")
                        || trimmed.starts_with("protected ")
                        || trimmed.starts_with("static "))
                        && (trimmed.contains("(") && trimmed.contains(")"))
                        && !trimmed.contains("class ")
                    {
                        let name = self.extract_java_method_name(trimmed);
                        blocks.push((name, ChunkType::Method, i + 1));
                    }
                }
                "go" => {
                    if trimmed.starts_with("func ") {
                        let name = self.extract_go_function_name(trimmed);
                        let chunk_type = if trimmed.contains(")") && trimmed[trimmed.find(")").unwrap_or(0)..].contains("(") {
                            ChunkType::Method
                        } else {
                            ChunkType::Function
                        };
                        blocks.push((name, chunk_type, i + 1));
                    } else if trimmed.starts_with("type ") && trimmed.contains("struct") {
                        let name = self.extract_go_struct_name(trimmed);
                        blocks.push((name, ChunkType::Struct, i + 1));
                    } else if trimmed.starts_with("type ") && trimmed.contains("interface") {
                        let name = self.extract_go_interface_name(trimmed);
                        blocks.push((name, ChunkType::Interface, i + 1));
                    }
                }
                "c" | "cpp" | "h" | "hpp" => {
                    if trimmed.contains("(") && trimmed.contains(")")
                        && (trimmed.ends_with("{") || lines.get(i + 1).map(|l| l.trim() == "{").unwrap_or(false))
                    {
                        let name = self.extract_c_function_name(trimmed);
                        let chunk_type = if trimmed.contains("::") {
                            ChunkType::Method
                        } else {
                            ChunkType::Function
                        };
                        blocks.push((name, chunk_type, i + 1));
                    }
                }
                _ => {}
            }
        }

        blocks
    }

    /// 找到代码块的结束位置
    fn find_block_end(&self, lines: &[&str], start_line: usize, _language: &str) -> usize {
        if start_line == 0 || start_line > lines.len() {
            return lines.len();
        }

        let start_idx = start_line - 1;
        let first_line = lines[start_idx];
        let base_indent = first_line.len() - first_line.trim_start().len();

        let mut brace_count = 0;
        let mut found_open_brace = false;

        for (i, line) in lines.iter().enumerate().skip(start_idx) {
            let trimmed = line.trim();

            // 计算大括号
            for ch in trimmed.chars() {
                match ch {
                    '{' => {
                        brace_count += 1;
                        found_open_brace = true;
                    }
                    '}' => {
                        brace_count -= 1;
                        if found_open_brace && brace_count == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
            }

            // Python 风格的缩进块
            if !line.is_empty() {
                let current_indent = line.len() - line.trim_start().len();
                if i > start_idx && current_indent <= base_indent && !trimmed.is_empty() {
                    return i;
                }
            }
        }

        lines.len()
    }

    /// 分割大代码块
    fn split_large_chunk(
        &self,
        chunk: CodeChunk,
        lines: &[&str],
        start_line: usize,
        end_line: usize,
    ) -> Vec<CodeChunk> {
        let mut result = Vec::new();
        let lines_slice = &lines[start_line.saturating_sub(1)..end_line.min(lines.len())];

        let mut current_content = String::new();
        let mut current_start = start_line;
        let mut part_num = 1;

        for (i, line) in lines_slice.iter().enumerate() {
            current_content.push_str(line);
            current_content.push('\n');

            if current_content.len() >= self.config.max_chunk_size - self.config.max_overlap {
                let mut new_chunk = CodeChunk::new(
                    chunk.file_path.clone(),
                    chunk.relative_path.clone(),
                    chunk.chunk_type,
                    format!("{} (part {})", chunk.name, part_num),
                    current_content.clone(),
                    current_start,
                    start_line + i,
                    chunk.language.clone(),
                );
                new_chunk.metadata = chunk.metadata.clone();
                result.push(new_chunk);

                current_content.clear();
                current_start = start_line + i + 1;
                part_num += 1;
            }
        }

        if !current_content.trim().is_empty() {
            let mut new_chunk = CodeChunk::new(
                chunk.file_path.clone(),
                chunk.relative_path.clone(),
                chunk.chunk_type,
                format!("{} (part {})", chunk.name, part_num),
                current_content,
                current_start,
                end_line,
                chunk.language.clone(),
            );
            new_chunk.metadata = chunk.metadata.clone();
            result.push(new_chunk);
        }

        result
    }

    // 各种语言的名字提取方法
    fn extract_function_name(&self, line: &str, keyword: &str) -> String {
        let after_keyword = line.split(keyword).nth(1).unwrap_or("");
        let name_part = after_keyword.split('(').next().unwrap_or("");
        name_part
            .trim()
            .split('<')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_struct_name(&self, line: &str) -> String {
        let after_struct = line.split("struct").nth(1).unwrap_or("");
        after_struct
            .trim()
            .split('{')
            .next()
            .unwrap_or("")
            .trim()
            .split('<')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_impl_name(&self, line: &str) -> String {
        let after_impl = line.split("impl").nth(1).unwrap_or("");
        after_impl
            .trim()
            .split('{')
            .next()
            .unwrap_or("")
            .trim()
            .split("for")
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_trait_name(&self, line: &str) -> String {
        let after_trait = line.split("trait").nth(1).unwrap_or("");
        after_trait
            .trim()
            .split('{')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_python_function_name(&self, line: &str) -> String {
        let after_def = line.split("def ").nth(1).unwrap_or("");
        after_def
            .split('(')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_python_class_name(&self, line: &str) -> String {
        let after_class = line.split("class ").nth(1).unwrap_or("");
        after_class
            .split('(')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn is_method(&self, _lines_before: &[&str]) -> bool {
        // 简单实现：检查前面是否有 class 定义（需要更复杂的实现）
        false
    }

    fn extract_js_function_name(&self, line: &str) -> String {
        // 处理各种 JS 函数定义格式
        if line.contains("=>") {
            // 箭头函数: const name = () =>
            let parts: Vec<&str> = line.split('=').collect();
            if let Some(first) = parts.first() {
                return first
                    .trim()
                    .split_whitespace()
                    .last()
                    .unwrap_or("anonymous")
                    .to_string();
            }
        } else if line.contains("function") {
            // 普通函数: function name() 或 export function name()
            let after_fn = line.split("function").nth(1).unwrap_or("");
            return after_fn
                .trim()
                .split('(')
                .next()
                .unwrap_or("anonymous")
                .trim()
                .to_string();
        }
        "anonymous".to_string()
    }

    fn extract_js_class_name(&self, line: &str) -> String {
        let after_class = line.split("class ").nth(1).unwrap_or("");
        after_class
            .split('{')
            .next()
            .unwrap_or("")
            .split("extends")
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_java_class_name(&self, line: &str) -> String {
        let after_class = line.split("class ").nth(1).unwrap_or("");
        after_class
            .split('{')
            .next()
            .unwrap_or("")
            .trim()
            .split_whitespace()
            .next()
            .unwrap_or("Unknown")
            .to_string()
    }

    fn extract_java_method_name(&self, line: &str) -> String {
        let parts: Vec<&str> = line.split('(').collect();
        if let Some(first) = parts.first() {
            return first
                .split_whitespace()
                .last()
                .unwrap_or("unknown")
                .to_string();
        }
        "unknown".to_string()
    }

    fn extract_go_function_name(&self, line: &str) -> String {
        let after_func = line.split("func ").nth(1).unwrap_or("");
        after_func
            .split('{')
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_go_struct_name(&self, line: &str) -> String {
        let after_type = line.split("type ").nth(1).unwrap_or("");
        after_type
            .split("struct")
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_go_interface_name(&self, line: &str) -> String {
        let after_type = line.split("type ").nth(1).unwrap_or("");
        after_type
            .split("interface")
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    }

    fn extract_c_function_name(&self, line: &str) -> String {
        let parts: Vec<&str> = line.split('(').collect();
        if let Some(first) = parts.first() {
            return first
                .split_whitespace()
                .last()
                .unwrap_or("unknown")
                .to_string();
        }
        "unknown".to_string()
    }

    /// 检测编程语言
    pub fn detect_language(path: &Path) -> String {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let ext_lower = ext.to_lowercase();

        match ext_lower.as_str() {
            "rs" => "rust",
            "py" => "python",
            "js" => "javascript",
            "ts" => "typescript",
            "jsx" => "jsx",
            "tsx" => "tsx",
            "java" => "java",
            "go" => "go",
            "c" => "c",
            "cpp" | "cc" => "cpp",
            "h" => "h",
            "hpp" => "hpp",
            _ => ext, // 返回原始扩展名
        }
        .to_string()
    }

    /// 索引整个项目目录
    pub async fn index_project(
        &self,
        project_root: &Path,
    ) -> Result<Vec<CodeChunk>, std::io::Error> {
        let mut all_chunks = Vec::new();
        let mut entries = Vec::new();

        // 收集所有文件
        for entry in walkdir::WalkDir::new(project_root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() && self.should_process(path) {
                entries.push(path.to_path_buf());
            }
        }

        // 处理每个文件
        for file_path in entries {
            match self.chunk_file(&file_path, project_root).await {
                Ok(chunks) => all_chunks.extend(chunks),
                Err(e) => {
                    tracing::warn!("Failed to chunk file {:?}: {}", file_path, e);
                }
            }
        }

        Ok(all_chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_type_display() {
        assert_eq!(ChunkType::Function.to_string(), "Function");
        assert_eq!(ChunkType::Class.to_string(), "Class");
    }

    #[test]
    fn test_chunk_config_default() {
        let config = ChunkConfig::default();
        assert_eq!(config.max_chunk_size, 2000);
        assert_eq!(config.min_chunk_size, 50);
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(
            CodeChunker::detect_language(Path::new("main.rs")),
            "rust"
        );
        assert_eq!(
            CodeChunker::detect_language(Path::new("app.py")),
            "python"
        );
        assert_eq!(
            CodeChunker::detect_language(Path::new("index.js")),
            "javascript"
        );
    }

    #[test]
    fn test_code_chunk_creation() {
        let chunk = CodeChunk::new(
            PathBuf::from("/test/main.rs"),
            "main.rs".to_string(),
            ChunkType::Function,
            "main".to_string(),
            "fn main() {}".to_string(),
            1,
            1,
            "rust".to_string(),
        );

        assert!(!chunk.id.is_empty());
        assert_eq!(chunk.name, "main");
        assert_eq!(chunk.line_count(), 1);
    }
}
