// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! AST 索引命令
//!
//! 使用 tree-sitter 实现代码分析和符号提取功能

use crate::services::database::Database;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use tauri::State;

// ==================== 类型定义 ====================

/// 符号信息
#[derive(Debug, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub kind: String,  // "function", "class", "method", "interface", "struct", etc.
    pub file_path: String,
    pub line: u32,
    pub column: u32,
    pub parent: Option<String>,
    pub code_snippet: Option<String>,
    pub start_line: u32,
    pub end_line: u32,
}

/// 文件索引
#[derive(Debug, Serialize, Deserialize)]
pub struct FileIndex {
    pub path: String,
    pub name: String,
    pub language: String,
    pub symbols: Vec<SymbolInfo>,
    pub updated_at: String,
}

/// 调用图节点
#[derive(Debug, Serialize, Deserialize)]
pub struct CallNode {
    pub name: String,
    pub file_path: String,
    pub line: u32,
    pub children: Vec<CallNode>,
}

/// 符号搜索结果
#[derive(Debug, Serialize, Deserialize)]
pub struct SymbolSearchResult {
    pub name: String,
    pub kind: String,
    pub file_path: String,
    pub line: u32,
    pub definition: String,
}

// ==================== Tauri Commands ====================

/// 索引项目中的所有文件
#[tauri::command]
pub async fn index_project(project_path: String) -> Result<usize, String> {
    use deepaudit_core::ASTParser;
    use ignore::Walk;
    use tokio::fs;

    let path_obj = Path::new(&project_path);

    if !path_obj.exists() {
        return Err("项目路径不存在".to_string());
    }

    // 创建 AST 解析器
    let mut parser = ASTParser::new();

    let mut file_count = 0;
    let mut symbol_count = 0;

    // 使用 ignore 库遍历目录
    for entry in Walk::new(path_obj) {
        if let Ok(entry) = entry {
            let path = entry.path();

            // 只扫描支持的文件类型
            if path.is_file() && is_supported_file(path) {
                if let Ok(content) = fs::read_to_string(path).await {
                    // 解析文件获取符号
                    match parser.parse_file(path, &content) {
                        Ok(symbols) => {
                            file_count += 1;
                            symbol_count += symbols.len();
                            // TODO: 将符号保存到数据库
                            tracing::debug!(
                                "Indexed {}: {} symbols",
                                path.display(),
                                symbols.len()
                            );
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }

    tracing::info!(
        "Project indexing complete: {} files, {} symbols",
        file_count,
        symbol_count
    );

    Ok(file_count)
}

/// 根据语言获取文件中的符号
#[tauri::command]
pub fn get_file_symbols(file_path: String) -> Result<Vec<SymbolInfo>, String> {
    use deepaudit_core::ASTParser;

    let path = Path::new(&file_path);

    if !path.exists() {
        return Err("文件不存在".to_string());
    }

    // 读取文件内容
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("读取文件失败: {}", e))?;

    // 创建 AST 解析器
    let mut parser = ASTParser::new();

    // 解析文件获取符号
    let core_symbols = parser
        .parse_file(path, &content)
        .map_err(|e| format!("解析文件失败: {}", e))?;

    // 转换为前端 SymbolInfo 格式
    let symbols: Vec<SymbolInfo> = core_symbols
        .into_iter()
        .map(|s| SymbolInfo {
            name: s.name.clone(),
            kind: s.kind_to_string(),
            file_path: s.file_path,
            line: s.start_line,
            column: 0,
            parent: if s.parent_classes.is_empty() {
                None
            } else {
                Some(s.parent_classes.join(", "))
            },
            code_snippet: Some(s.code),
            start_line: s.start_line,
            end_line: s.end_line,
        })
        .collect();

    Ok(symbols)
}

/// 搜索符号
///
/// 根据符号名称和项目 ID 搜索符号定义
/// 支持模糊匹配，返回所有包含搜索词的符号
#[tauri::command]
pub async fn search_symbol(
    symbol_name: String,
    project_id: i64,
    db: State<'_, Database>,
) -> Result<Vec<SymbolSearchResult>, String> {
    // 使用 LIKE 进行模糊匹配
    let pattern = format!("%{}%", symbol_name);

    #[derive(sqlx::FromRow)]
    struct SymbolRow {
        symbol_name: String,
        symbol_type: String,
        file_path: String,
        line_number: Option<i64>,
        metadata: Option<String>,
    }

    let pool = db.get_pool();

    let rows = sqlx::query_as::<_, SymbolRow>(
        r#"
        SELECT
            symbol_name,
            symbol_type,
            file_path,
            line_number,
            metadata
        FROM symbols
        WHERE project_id = ? AND symbol_name LIKE ?
        ORDER BY
            CASE
                WHEN symbol_name = ? THEN 1
                WHEN symbol_name LIKE ? THEN 2
                ELSE 3
            END,
            symbol_name ASC,
            line_number ASC
        LIMIT 100
        "#
    )
    .bind(project_id)
    .bind(&pattern)
    .bind(&symbol_name)          // 精确匹配优先
    .bind(format!("{}%", symbol_name))  // 前缀匹配次之
    .fetch_all(pool)
    .await
    .map_err(|e| format!("数据库查询失败: {}", e))?;

    // 转换为 SymbolSearchResult
    let results: Vec<SymbolSearchResult> = rows
        .into_iter()
        .map(|row| {
            // 尝试从 metadata 中提取定义代码
            let definition = if let Some(metadata) = row.metadata {
                // 尝试解析 JSON metadata
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&metadata) {
                    json.get("definition")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            SymbolSearchResult {
                name: row.symbol_name,
                kind: row.symbol_type,
                file_path: row.file_path,
                line: row.line_number.unwrap_or(0) as u32,
                definition,
            }
        })
        .collect();

    Ok(results)
}

/// 获取调用图
///
/// 根据入口函数名构建函数调用关系图
/// 注意: 当前实现是简化版本，完整的调用图分析需要 AST 解析和符号引用分析
#[tauri::command]
pub async fn get_call_graph(
    entry_function: String,
    max_depth: u32,
    project_id: i64,
    db: State<'_, Database>,
) -> Result<CallNode, String> {
    use std::collections::HashSet;

    let pool = db.get_pool();

    // 查找入口函数的定义
    #[derive(sqlx::FromRow)]
    struct SymbolRow {
        symbol_name: String,
        symbol_type: String,
        file_path: String,
        line_number: Option<i64>,
    }

    let entry_symbol = sqlx::query_as::<_, SymbolRow>(
        r#"
        SELECT symbol_name, symbol_type, file_path, line_number
        FROM symbols
        WHERE project_id = ? AND symbol_name = ? AND symbol_type IN ('function', 'method')
        LIMIT 1
        "#
    )
    .bind(project_id)
    .bind(&entry_function)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("查询入口函数失败: {}", e))?;

    let (file_path, line) = if let Some(sym) = entry_symbol {
        (sym.file_path, sym.line_number.unwrap_or(0) as u32)
    } else {
        // 如果找不到函数定义，返回占位节点
        return Ok(CallNode {
            name: entry_function,
            file_path: "unknown".to_string(),
            line: 0,
            children: vec![],
        });
    };

    // 使用迭代方式构建调用图（避免异步递归）
    let children = build_call_graph_iterative(&entry_function, project_id, max_depth, pool).await?;

    Ok(CallNode {
        name: entry_function,
        file_path,
        line,
        children,
    })
}

/// 迭代方式构建调用图
///
/// 使用栈来避免异步递归的限制
async fn build_call_graph_iterative(
    entry_function: &str,
    project_id: i64,
    max_depth: u32,
    pool: &sqlx::Pool<sqlx::Sqlite>,
) -> Result<Vec<CallNode>, String> {
    use std::collections::{HashMap, HashSet, VecDeque};

    #[derive(sqlx::FromRow)]
    struct CallRefRow {
        symbol_name: String,
        symbol_type: String,
        file_path: String,
        line_number: Option<i64>,
    }

    // 用于跟踪节点及其深度
    #[derive(Clone)]
    struct StackFrame {
        function_name: String,
        file_path: String,
        line: u32,
        depth: u32,
        parent_index: Option<usize>,
    }

    let mut visited = HashSet::new();
    let mut nodes: Vec<(StackFrame, Vec<usize>)> = Vec::new(); // (frame, children_indices)
    let mut stack = VecDeque::new();

    // 初始化栈
    stack.push_back(StackFrame {
        function_name: entry_function.to_string(),
        file_path: String::new(),
        line: 0,
        depth: 0,
        parent_index: None,
    });
    visited.insert(entry_function.to_string());

    while let Some(frame) = stack.pop_front() {
        if frame.depth >= max_depth {
            continue;
        }

        // 查找当前函数可以调用的其他函数
        let rows = sqlx::query_as::<_, CallRefRow>(
            r#"
            SELECT DISTINCT symbol_name, symbol_type, file_path, line_number
            FROM symbols
            WHERE project_id = ?
                AND symbol_type IN ('function', 'method')
                AND symbol_name != ?
            LIMIT 20
            "#
        )
        .bind(project_id)
        .bind(&frame.function_name)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("查询函数调用失败: {}", e))?;

        let current_index = nodes.len();
        let mut child_indices = Vec::new();

        for row in rows {
            if visited.contains(&row.symbol_name) {
                continue;
            }
            visited.insert(row.symbol_name.clone());

            let child_frame = StackFrame {
                function_name: row.symbol_name.clone(),
                file_path: row.file_path.clone(),
                line: row.line_number.unwrap_or(0) as u32,
                depth: frame.depth + 1,
                parent_index: Some(current_index),
            };

            child_indices.push(nodes.len());
            nodes.push((child_frame, vec![]));

            // 将子节点加入栈以继续处理
            stack.push_back(StackFrame {
                function_name: row.symbol_name,
                file_path: row.file_path,
                line: row.line_number.unwrap_or(0) as u32,
                depth: frame.depth + 1,
                parent_index: Some(nodes.len() - 1),
            });

            // 限制子节点数量
            if child_indices.len() >= 10 {
                break;
            }
        }

        // 更新当前节点的子节点索引
        if let Some(node) = nodes.get_mut(current_index) {
            node.1 = child_indices;
        }
    }

    // 构建最终的 CallNode 树
    fn build_tree(index: usize, nodes: &[(StackFrame, Vec<usize>)]) -> CallNode {
        let (frame, children_indices) = &nodes[index];
        CallNode {
            name: frame.function_name.clone(),
            file_path: frame.file_path.clone(),
            line: frame.line,
            children: children_indices
                .iter()
                .map(|&child_idx| build_tree(child_idx, nodes))
                .collect(),
        }
    }

    // 如果没有找到任何节点，返回空列表
    if nodes.is_empty() {
        // 获取入口函数的基本信息
        let entry_info = sqlx::query_as::<_, CallRefRow>(
            r#"
            SELECT symbol_name, symbol_type, file_path, line_number
            FROM symbols
            WHERE project_id = ? AND symbol_name = ? AND symbol_type IN ('function', 'method')
            LIMIT 1
            "#
        )
        .bind(project_id)
        .bind(entry_function)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("查询入口函数失败: {}", e))?;

        if let Some(info) = entry_info {
            return Ok(vec![CallNode {
                name: info.symbol_name,
                file_path: info.file_path,
                line: info.line_number.unwrap_or(0) as u32,
                children: vec![],
            }]);
        }

        return Ok(vec![]);
    }

    // 构建并返回子节点树
    let result = nodes[0].1
        .iter()
        .map(|&child_idx| build_tree(child_idx, &nodes))
        .collect();

    Ok(result)
}

// ==================== 辅助函数 ====================

/// 检查文件是否被支持
fn is_supported_file(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("");
        matches!(
            ext,
            "js" | "jsx" | "ts" | "tsx" | "py" | "java" | "rs" | "go"
                | "html" | "htm" | "vue" | "css" | "json"
                | "c" | "h" | "cpp" | "hpp" | "cc"
        )
    } else {
        false
    }
}
