// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 跨文件分析
//!
//! 实现导入解析、符号解析和跨文件引用追踪

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 导入解析器
pub struct ImportResolver {
    /// 已解析的模块
    modules: HashMap<String, ResolvedModule>,

    /// 符号表
    symbol_table: HashMap<String, Vec<SymbolInfo>>,

    /// 文件到模块的映射
    file_to_module: HashMap<String, String>,
}

/// 解析后的模块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedModule {
    /// 模块名
    pub name: String,

    /// 文件路径
    pub file_path: PathBuf,

    /// 导出的符号
    pub exports: Vec<ExportInfo>,

    /// 导入的符号
    pub imports: Vec<ImportInfo>,

    /// 语言
    pub language: String,
}

/// 导出信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    /// 符号名称
    pub name: String,

    /// 符号类型
    pub symbol_type: SymbolType,

    /// 行号
    pub line: usize,

    /// 是否为默认导出
    pub is_default: bool,
}

/// 导入信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    /// 原始导入语句
    pub raw: String,

    /// 导入的符号
    pub symbols: Vec<ImportedSymbol>,

    /// 来源模块
    pub source: String,

    /// 行号
    pub line: usize,
}

/// 导入的符号
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedSymbol {
    /// 原始名称
    pub original_name: String,

    /// 别名
    pub alias: Option<String>,

    /// 是否为默认导入
    pub is_default: bool,
}

/// 符号类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SymbolType {
    Function,
    Class,
    Variable,
    Constant,
    Type,
    Interface,
    Module,
}

/// 符号信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    /// 符号名称
    pub name: String,

    /// 定义位置
    pub location: SymbolLocation,

    /// 符号类型
    pub symbol_type: SymbolType,

    /// 可见性
    pub visibility: Visibility,
}

/// 符号位置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolLocation {
    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 列号
    pub column: Option<usize>,
}

/// 可见性
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Private,
    Protected,
    Internal,
}

/// 符号引用
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolReference {
    /// 引用的符号名称
    pub symbol_name: String,

    /// 引用位置
    pub location: SymbolLocation,

    /// 定义位置（如果找到）
    pub definition: Option<SymbolLocation>,

    /// 引用类型
    pub reference_type: ReferenceType,
}

/// 引用类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReferenceType {
    /// 函数调用
    Call,
    /// 变量读取
    Read,
    /// 变量写入
    Write,
    /// 类型使用
    TypeUse,
    /// 导入
    Import,
}

/// 跨文件引用
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileReference {
    /// 源文件
    pub source_file: String,

    /// 目标文件
    pub target_file: String,

    /// 引用的符号
    pub symbol: String,

    /// 源位置
    pub source_location: SymbolLocation,

    /// 目标位置（如果找到）
    pub target_location: Option<SymbolLocation>,
}

impl ImportResolver {
    /// 创建新的导入解析器
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            symbol_table: HashMap::new(),
            file_to_module: HashMap::new(),
        }
    }

    /// 解析文件的导入和导出
    pub fn parse_file(&mut self, file_path: &Path, content: &str) -> ResolvedModule {
        let language = Self::detect_language(file_path);
        let (imports, exports) = self.parse_imports_exports(content, &language);

        let module = ResolvedModule {
            name: file_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string(),
            file_path: file_path.to_path_buf(),
            exports,
            imports,
            language,
        };

        // 更新符号表
        for export in &module.exports {
            let info = SymbolInfo {
                name: export.name.clone(),
                location: SymbolLocation {
                    file_path: file_path.to_string_lossy().to_string(),
                    line: export.line,
                    column: None,
                },
                symbol_type: export.symbol_type.clone(),
                visibility: Visibility::Public,
            };
            self.symbol_table
                .entry(export.name.clone())
                .or_insert_with(Vec::new)
                .push(info);
        }

        // 记录文件到模块的映射
        self.file_to_module.insert(
            file_path.to_string_lossy().to_string(),
            module.name.clone(),
        );

        // 存储模块
        let module_name = module.name.clone();
        self.modules.insert(module_name, module.clone());

        module
    }

    /// 解析导入和导出
    fn parse_imports_exports(
        &self,
        content: &str,
        language: &str,
    ) -> (Vec<ImportInfo>, Vec<ExportInfo>) {
        let mut imports = Vec::new();
        let mut exports = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            match language {
                "python" => {
                    if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
                        if let Some(import) = self.parse_python_import(trimmed, line_idx + 1) {
                            imports.push(import);
                        }
                    }
                    // Python 导出通常是函数和类定义
                    if trimmed.starts_with("def ") {
                        if let Some(name) = trimmed.strip_prefix("def ") {
                            let name = name.split('(').next().unwrap_or("").trim();
                            exports.push(ExportInfo {
                                name: name.to_string(),
                                symbol_type: SymbolType::Function,
                                line: line_idx + 1,
                                is_default: false,
                            });
                        }
                    }
                    if trimmed.starts_with("class ") {
                        if let Some(name) = trimmed.strip_prefix("class ") {
                            let name = name.split('(').next().unwrap_or("").trim();
                            let name = name.split(':').next().unwrap_or("").trim();
                            exports.push(ExportInfo {
                                name: name.to_string(),
                                symbol_type: SymbolType::Class,
                                line: line_idx + 1,
                                is_default: false,
                            });
                        }
                    }
                }
                "javascript" | "typescript" => {
                    // ES6 导入
                    if trimmed.starts_with("import ") {
                        if let Some(import) = self.parse_js_import(trimmed, line_idx + 1) {
                            imports.push(import);
                        }
                    }
                    // ES6 导出
                    if trimmed.starts_with("export ") {
                        if let Some(export) = self.parse_js_export(trimmed, line_idx + 1) {
                            exports.push(export);
                        }
                    }
                    // CommonJS require (single-line only; skip multi-line closing brackets)
                    if trimmed.contains("require(") && !trimmed.starts_with('}') {
                        if let Some(import) = self.parse_commonjs_require(trimmed, line_idx + 1) {
                            imports.push(import);
                        }
                    }
                    // 多行 CommonJS require: const {\n  Foo\n} = require('...')
                    if (trimmed.starts_with("const {") || trimmed.starts_with("let {") || trimmed.starts_with("var {"))
                        && !trimmed.contains("require(") && !trimmed.contains("=")
                    {
                        if let Some(merged) = self.try_merge_multiline_require(content, line_idx) {
                            if let Some(import) = self.parse_commonjs_require(&merged, line_idx + 1) {
                                imports.push(import);
                            }
                        }
                    }
                    // CommonJS exports
                    exports.extend(self.parse_commonjs_exports(trimmed, line_idx + 1));
                }
                "rust" => {
                    if trimmed.starts_with("use ") {
                        if let Some(import) = self.parse_rust_use(trimmed, line_idx + 1) {
                            imports.push(import);
                        }
                    }
                    // Rust pub 导出
                    if trimmed.contains("pub fn ") || trimmed.contains("pub struct ")
                        || trimmed.contains("pub enum ") || trimmed.contains("pub trait ")
                    {
                        if let Some(export) = self.parse_rust_export(trimmed, line_idx + 1) {
                            exports.push(export);
                        }
                    }
                }
                "go" => {
                    if trimmed.starts_with("import ") {
                        if let Some(import) = self.parse_go_import(trimmed, line_idx + 1) {
                            imports.push(import);
                        }
                    }
                    // Go 导出的函数（首字母大写）
                    if trimmed.starts_with("func ") {
                        if let Some(name) = trimmed.strip_prefix("func ") {
                            let name = name.split('(').next().unwrap_or("").trim();
                            if name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                                exports.push(ExportInfo {
                                    name: name.to_string(),
                                    symbol_type: SymbolType::Function,
                                    line: line_idx + 1,
                                    is_default: false,
                                });
                            }
                        }
                    }
                }
                "java" => {
                    if trimmed.starts_with("import ") {
                        if let Some(import) = self.parse_java_import(trimmed, line_idx + 1) {
                            imports.push(import);
                        }
                    }
                    // Java public 类/方法
                    if trimmed.contains("public class ") {
                        if let Some(name) = trimmed.split("class ").nth(1) {
                            let name = name.split('{').next().unwrap_or("").trim();
                            exports.push(ExportInfo {
                                name: name.to_string(),
                                symbol_type: SymbolType::Class,
                                line: line_idx + 1,
                                is_default: false,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        (imports, exports)
    }

    /// 解析 Python 导入
    fn parse_python_import(&self, line: &str, line_num: usize) -> Option<ImportInfo> {
        let raw = line.to_string();

        if line.starts_with("from ") {
            // from module import symbol
            let parts: Vec<&str> = line.split(" import ").collect();
            if parts.len() == 2 {
                let source = parts[0].strip_prefix("from ")?.trim().to_string();
                let symbols_str = parts[1].trim();

                let symbols = symbols_str
                    .split(',')
                    .filter_map(|s| {
                        let s = s.trim();
                        if s.is_empty() {
                            return None;
                        }
                        // 处理 as 别名
                        let parts: Vec<&str> = s.split(" as ").collect();
                        Some(ImportedSymbol {
                            original_name: parts[0].trim().to_string(),
                            alias: parts.get(1).map(|a| a.trim().to_string()),
                            is_default: false,
                        })
                    })
                    .collect();

                return Some(ImportInfo {
                    raw,
                    symbols,
                    source,
                    line: line_num,
                });
            }
        } else if line.starts_with("import ") {
            // import module
            let source = line.strip_prefix("import ")?.trim().to_string();
            return Some(ImportInfo {
                raw,
                symbols: vec![ImportedSymbol {
                    original_name: source.clone(),
                    alias: None,
                    is_default: false,
                }],
                source,
                line: line_num,
            });
        }

        None
    }

    /// 解析 JavaScript/TypeScript 导入
    fn parse_js_import(&self, line: &str, line_num: usize) -> Option<ImportInfo> {
        let raw = line.to_string();

        // 提取模块路径
        let source = if let Some(start) = line.find("from '") {
            let rest = &line[start + 6..];
            if let Some(end) = rest.find('\'') {
                rest[..end].to_string()
            } else {
                return None;
            }
        } else if let Some(start) = line.find("from \"") {
            let rest = &line[start + 6..];
            if let Some(end) = rest.find('"') {
                rest[..end].to_string()
            } else {
                return None;
            }
        } else {
            return None;
        };

        let mut symbols = Vec::new();

        // 解析导入的符号
        if line.contains("import {") {
            // 命名导入
            if let Some(start) = line.find('{') {
                if let Some(end) = line.find('}') {
                    let inner = &line[start + 1..end];
                    for part in inner.split(',') {
                        let part = part.trim();
                        if part.is_empty() {
                            continue;
                        }
                        // 处理 as 别名
                        let parts: Vec<&str> = part.split(" as ").collect();
                        symbols.push(ImportedSymbol {
                            original_name: parts[0].trim().to_string(),
                            alias: parts.get(1).map(|a| a.trim().to_string()),
                            is_default: false,
                        });
                    }
                }
            }
        } else if line.contains("import * as ") {
            // 全部导入
            if let Some(start) = line.find("import * as ") {
                let rest = &line[start + 12..];
                let name = rest.split_whitespace().next()?;
                symbols.push(ImportedSymbol {
                    original_name: "*".to_string(),
                    alias: Some(name.to_string()),
                    is_default: false,
                });
            }
        } else if let Some(start) = line.find("import ") {
            // 默认导入
            let rest = &line[start + 7..];
            if let Some(end) = rest.find(" from") {
                let name = rest[..end].trim();
                if !name.starts_with('{') && !name.starts_with('*') {
                    symbols.push(ImportedSymbol {
                        original_name: name.to_string(),
                        alias: None,
                        is_default: true,
                    });
                }
            }
        }

        Some(ImportInfo {
            raw,
            symbols,
            source,
            line: line_num,
        })
    }

    /// 合并多行 CommonJS require 语句为单行
    ///
    /// 处理模式:
    ///   const {
    ///     BenefitsDAO
    ///   } = require("../data/benefits-dao");
    fn try_merge_multiline_require(&self, content: &str, start_line: usize) -> Option<String> {
        let lines: Vec<&str> = content.lines().collect();
        let mut merged = String::new();
        for i in start_line..lines.len() {
            let line = lines[i].trim();
            merged.push_str(line);
            merged.push(' ');
            // 找到 require( 且包含 }=
            if line.contains("require(") && (line.contains("}") || merged.contains("}")) {
                return Some(merged.trim().to_string());
            }
            // 防止无限缓冲：最多合并 10 行
            if i - start_line > 10 {
                return None;
            }
        }
        None
    }

    /// 解析 CommonJS require（支持解构）
    fn parse_commonjs_require(&self, line: &str, line_num: usize) -> Option<ImportInfo> {
        let raw = line.to_string();

        // 提取模块路径
        let source = if let Some(start) = line.find("require('") {
            let rest = &line[start + 9..];
            let end = rest.find('\'')?;
            rest[..end].to_string()
        } else if let Some(start) = line.find("require(\"") {
            let rest = &line[start + 9..];
            let end = rest.find('"')?;
            rest[..end].to_string()
        } else {
            return None;
        };

        // 检测解构: const { body, query } = require('module')
        let symbols = if line.contains('{') && line.contains('}') && line.contains("require(") {
            self.parse_commonjs_destructuring(line)
        } else if let Some(eq_pos) = line.find('=') {
            let lhs = line[..eq_pos].trim();
            let lhs = lhs
                .strip_prefix("const ")
                .or_else(|| lhs.strip_prefix("let "))
                .or_else(|| lhs.strip_prefix("var "))
                .unwrap_or(lhs)
                .trim();

            if lhs.is_empty() {
                vec![ImportedSymbol {
                    original_name: "default".to_string(),
                    alias: None,
                    is_default: true,
                }]
            } else {
                vec![ImportedSymbol {
                    original_name: lhs.to_string(),
                    alias: None,
                    is_default: true,
                }]
            }
        } else {
            vec![ImportedSymbol {
                original_name: "default".to_string(),
                alias: None,
                is_default: true,
            }]
        };

        Some(ImportInfo {
            raw,
            symbols,
            source,
            line: line_num,
        })
    }

    /// 解析 CommonJS 解构: const { body, query } = require('module')
    fn parse_commonjs_destructuring(&self, line: &str) -> Vec<ImportedSymbol> {
        let mut symbols = Vec::new();
        if let Some(start) = line.find('{') {
            if let Some(end) = line.find('}') {
                let inner = &line[start + 1..end];
                for part in inner.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if part.contains(':') {
                        // 重命名: { body: data }
                        let pieces: Vec<&str> = part.split(':').collect();
                        symbols.push(ImportedSymbol {
                            original_name: pieces[0].trim().to_string(),
                            alias: Some(pieces[1].trim().to_string()),
                            is_default: false,
                        });
                    } else {
                        symbols.push(ImportedSymbol {
                            original_name: part.to_string(),
                            alias: None,
                            is_default: false,
                        });
                    }
                }
            }
        }
        symbols
    }

    /// 解析 CommonJS 导出: module.exports.X 和 exports.X
    fn parse_commonjs_exports(&self, line: &str, line_num: usize) -> Vec<ExportInfo> {
        let mut exports = Vec::new();
        let trimmed = line.trim();

        // module.exports.funcName = ...
        if trimmed.starts_with("module.exports.") {
            if let Some(rest) = trimmed.strip_prefix("module.exports.") {
                if let Some(eq_pos) = rest.find('=') {
                    let name = rest[..eq_pos].trim().to_string();
                    if !name.is_empty() && name != "exports" {
                        exports.push(ExportInfo {
                            name,
                            symbol_type: SymbolType::Function,
                            line: line_num,
                            is_default: false,
                        });
                    }
                }
            }
        }

        // exports.funcName = ...
        if trimmed.starts_with("exports.") && !trimmed.starts_with("module.exports") {
            if let Some(rest) = trimmed.strip_prefix("exports.") {
                if let Some(eq_pos) = rest.find('=') {
                    let name = rest[..eq_pos].trim().to_string();
                    if !name.is_empty() {
                        exports.push(ExportInfo {
                            name,
                            symbol_type: SymbolType::Function,
                            line: line_num,
                            is_default: false,
                        });
                    }
                }
            }
        }

        exports
    }

    /// 解析 Rust use
    fn parse_rust_use(&self, line: &str, line_num: usize) -> Option<ImportInfo> {
        let raw = line.to_string();
        let content = line.strip_prefix("use ")?.trim();
        let content = content.trim_end_matches(';');

        // 简单处理：将整个路径作为源
        let (source, symbols) = if content.contains("::{") {
            // use module::{item1, item2}
            let parts: Vec<&str> = content.split("::{").collect();
            let source = parts[0].to_string();
            let items = parts.get(1)?.trim_end_matches('}');
            let symbols = items
                .split(',')
                .filter_map(|s| {
                    let s = s.trim();
                    if s.is_empty() {
                        return None;
                    }
                    // 处理 as 别名
                    let parts: Vec<&str> = s.split(" as ").collect();
                    Some(ImportedSymbol {
                        original_name: parts[0].trim().to_string(),
                        alias: parts.get(1).map(|a| a.trim().to_string()),
                        is_default: false,
                    })
                })
                .collect();
            (source, symbols)
        } else if content.contains(" as ") {
            // use module as alias
            let parts: Vec<&str> = content.split(" as ").collect();
            (
                parts[0].trim().to_string(),
                vec![ImportedSymbol {
                    original_name: parts[0].trim().to_string(),
                    alias: Some(parts[1].trim().to_string()),
                    is_default: false,
                }],
            )
        } else {
            // use module::item
            let mut parts: Vec<&str> = content.split("::").collect();
            let item = parts.pop()?;
            let source = parts.join("::");
            (
                source,
                vec![ImportedSymbol {
                    original_name: item.to_string(),
                    alias: None,
                    is_default: false,
                }],
            )
        };

        Some(ImportInfo {
            raw,
            symbols,
            source,
            line: line_num,
        })
    }

    /// 解析 Rust 导出
    fn parse_rust_export(&self, line: &str, line_num: usize) -> Option<ExportInfo> {
        let (name, symbol_type) = if line.contains("pub fn ") {
            let rest = line.split("pub fn ").nth(1)?;
            let name = rest.split('(').next()?.trim();
            (name.to_string(), SymbolType::Function)
        } else if line.contains("pub struct ") {
            let rest = line.split("pub struct ").nth(1)?;
            let name = rest.split('{').next()?.split('<').next()?.trim();
            (name.to_string(), SymbolType::Class)
        } else if line.contains("pub enum ") {
            let rest = line.split("pub enum ").nth(1)?;
            let name = rest.split('{').next()?.split('<').next()?.trim();
            (name.to_string(), SymbolType::Type)
        } else if line.contains("pub trait ") {
            let rest = line.split("pub trait ").nth(1)?;
            let name = rest.split('{').next()?.trim();
            (name.to_string(), SymbolType::Interface)
        } else {
            return None;
        };

        Some(ExportInfo {
            name,
            symbol_type,
            line: line_num,
            is_default: false,
        })
    }

    /// 解析 Go 导入
    fn parse_go_import(&self, line: &str, line_num: usize) -> Option<ImportInfo> {
        let raw = line.to_string();
        let content = line.strip_prefix("import ")?.trim();
        let content = content.trim_matches('"');

        // 处理别名
        let (alias, source) = if content.contains(' ') {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() == 2 {
                (Some(parts[0].to_string()), parts[1].to_string())
            } else {
                (None, content.to_string())
            }
        } else {
            (None, content.to_string())
        };

        Some(ImportInfo {
            raw,
            symbols: vec![ImportedSymbol {
                original_name: source.clone(),
                alias,
                is_default: false,
            }],
            source,
            line: line_num,
        })
    }

    /// 解析 Java 导入
    fn parse_java_import(&self, line: &str, line_num: usize) -> Option<ImportInfo> {
        let raw = line.to_string();
        let content = line.strip_prefix("import ")?.trim_end_matches(';');

        let (source, name) = if content.ends_with(".*") {
            (content.to_string(), "*".to_string())
        } else {
            let parts: Vec<&str> = content.rsplit('.').collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                let source = parts[1..].iter().rev().cloned().collect::<Vec<_>>().join(".");
                (source, name)
            } else {
                (content.to_string(), "*".to_string())
            }
        };

        Some(ImportInfo {
            raw,
            symbols: vec![ImportedSymbol {
                original_name: name,
                alias: None,
                is_default: false,
            }],
            source,
            line: line_num,
        })
    }

    /// 解析 JS 导出
    fn parse_js_export(&self, line: &str, line_num: usize) -> Option<ExportInfo> {
        let content = line.strip_prefix("export ")?.trim();

        let (name, symbol_type, is_default) = if content.starts_with("default ") {
            let rest = content.strip_prefix("default ")?;
            let name = if rest.starts_with("function ") {
                rest.split("function ").nth(1)?.split('(').next()?.trim()
            } else if rest.starts_with("class ") {
                rest.split("class ").nth(1)?.split('{').next()?.trim()
            } else {
                "default"
            };
            (name.to_string(), SymbolType::Function, true)
        } else if content.starts_with("function ") {
            let name = content
                .split("function ")
                .nth(1)?
                .split('(')
                .next()?
                .trim();
            (name.to_string(), SymbolType::Function, false)
        } else if content.starts_with("class ") {
            let name = content.split("class ").nth(1)?.split('{').next()?.trim();
            (name.to_string(), SymbolType::Class, false)
        } else if content.starts_with("const ") || content.starts_with("let ") || content.starts_with("var ") {
            let rest = content.split_whitespace().nth(1)?;
            let name = rest.split('=').next()?.trim();
            (name.to_string(), SymbolType::Constant, false)
        } else if content.starts_with("{") || content.starts_with("*") {
            // 重导出，跳过
            return None;
        } else {
            return None;
        };

        Some(ExportInfo {
            name,
            symbol_type,
            line: line_num,
            is_default,
        })
    }

    /// 查找符号定义
    pub fn find_symbol_definition(&self, symbol_name: &str) -> Option<&SymbolInfo> {
        self.symbol_table
            .get(symbol_name)
            .and_then(|v| v.first())
    }

    /// 获取模块的所有导出
    pub fn get_module_exports(&self, module_name: &str) -> Option<&Vec<ExportInfo>> {
        self.modules.get(module_name).map(|m| &m.exports)
    }

    /// 获取模块的所有导入
    pub fn get_module_imports(&self, module_name: &str) -> Option<&Vec<ImportInfo>> {
        self.modules.get(module_name).map(|m| &m.imports)
    }

    /// 查找跨文件引用
    pub fn find_cross_file_references(&self) -> Vec<CrossFileReference> {
        let mut references = Vec::new();

        for (module_name, module) in &self.modules {
            for import in &module.imports {
                for symbol in &import.symbols {
                    let target_symbol = symbol.alias.as_ref().unwrap_or(&symbol.original_name);

                    // 查找符号定义
                    let target_location = self
                        .find_symbol_definition(target_symbol)
                        .map(|s| s.location.clone());

                    references.push(CrossFileReference {
                        source_file: module.file_path.to_string_lossy().to_string(),
                        target_file: import.source.clone(),
                        symbol: target_symbol.clone(),
                        source_location: SymbolLocation {
                            file_path: module.file_path.to_string_lossy().to_string(),
                            line: import.line,
                            column: None,
                        },
                        target_location,
                    });
                }
            }
        }

        references
    }

    /// 检测语言
    fn detect_language(path: &Path) -> String {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|ext| match ext.to_lowercase().as_str() {
                "py" => "python",
                "js" => "javascript",
                "ts" => "typescript",
                "jsx" => "javascript",
                "tsx" => "typescript",
                "rs" => "rust",
                "go" => "go",
                "java" => "java",
                _ => "unknown",
            })
            .unwrap_or("unknown")
            .to_string()
    }

    /// 获取所有模块
    pub fn get_modules(&self) -> &HashMap<String, ResolvedModule> {
        &self.modules
    }

    /// 获取符号表
    pub fn get_symbol_table(&self) -> &HashMap<String, Vec<SymbolInfo>> {
        &self.symbol_table
    }
}

impl Default for ImportResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_resolver_creation() {
        let resolver = ImportResolver::new();
        assert!(resolver.modules.is_empty());
        assert!(resolver.symbol_table.is_empty());
    }

    #[test]
    fn test_parse_python_import() {
        let resolver = ImportResolver::new();
        let import = resolver.parse_python_import("from flask import Flask, request", 1);
        assert!(import.is_some());
        let import = import.unwrap();
        assert_eq!(import.source, "flask");
        assert_eq!(import.symbols.len(), 2);
    }

    #[test]
    fn test_parse_js_import() {
        let resolver = ImportResolver::new();
        let import = resolver.parse_js_import("import { useState, useEffect } from 'react'", 1);
        assert!(import.is_some());
        let import = import.unwrap();
        assert_eq!(import.source, "react");
        assert_eq!(import.symbols.len(), 2);
    }

    #[test]
    fn test_parse_rust_use() {
        let resolver = ImportResolver::new();
        let import = resolver.parse_rust_use("use std::collections::HashMap;", 1);
        assert!(import.is_some());
        let import = import.unwrap();
        assert_eq!(import.source, "std::collections");
        assert_eq!(import.symbols[0].original_name, "HashMap");
    }

    #[test]
    fn test_parse_file() {
        let mut resolver = ImportResolver::new();
        let code = r#"
import os
import sys
from typing import List

def main():
    pass

class MyClass:
    pass
"#;
        let module = resolver.parse_file(Path::new("test.py"), code);
        assert!(!module.imports.is_empty());
        assert!(!module.exports.is_empty());
    }
}
