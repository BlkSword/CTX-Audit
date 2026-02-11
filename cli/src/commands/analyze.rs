// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! analyze 命令实现
//!
//! 深度分析单个文件

use miette::Result;

use crate::terminal::TerminalRenderer;

/// 执行 analyze 命令
pub async fn execute(
    file: String,
    start_line: usize,
    end_line: Option<usize>,
    show_ast: bool,
    show_symbols: bool,
    output_format: &str,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 验证文件路径
    let file_path = std::path::Path::new(&file);
    if !file_path.exists() {
        renderer.error(&format!("文件不存在: {}", file));
        return Err(miette::miette!("文件不存在"));
    }

    renderer.info(&format!("分析文件: {}", file));

    // 读取文件内容
    let content = tokio::fs::read_to_string(&file).await.map_err(|e| miette::miette!("{}", e))?;
    let lines: Vec<&str> = content.lines().collect();

    // 确定行范围
    let end = end_line.unwrap_or(lines.len());
    let selected_lines = if start_line <= end && end <= lines.len() {
        &lines[(start_line - 1)..end]
    } else {
        renderer.error("行号超出范围");
        return Err(miette::miette!("行号超出范围"));
    };

    // 显示文件内容
    renderer.print("文件内容:");
    for (i, line) in selected_lines.iter().enumerate() {
        renderer.print(&format!("{}: {}", start_line + i, line));
    }

    // 显示 AST 信息
    if show_ast {
        renderer.print("\nAST 信息:");
        renderer.print("提示: AST 解析功能需要使用完整的项目索引");
        renderer.print("建议: 先使用 'ctx-audit scan <path>' 扫描项目");
    }

    // 显示符号信息
    if show_symbols {
        renderer.print("\n符号信息:");
        renderer.print("提示: 符号提取功能需要使用完整的项目索引");
        renderer.print("建议: 先使用 'ctx-audit scan <path>' 扫描项目");

        // 显示基本统计信息
        let total_lines = lines.len();
        let total_chars = content.chars().count();
        renderer.print(&format!("\n文件统计:"));
        renderer.print(&format!("  总行数: {}", total_lines));
        renderer.print(&format!("  总字符数: {}", total_chars));

        // 简单检测函数/类定义
        let mut functions = Vec::new();
        let mut classes = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();

            // 检测函数定义
            if trimmed.contains("fn ") || trimmed.contains("function ") || trimmed.contains("def ") {
                functions.push(i + 1);
            }

            // 检测类定义
            if trimmed.contains("class ") || trimmed.contains("struct ") || trimmed.contains("interface ") {
                classes.push(i + 1);
            }
        }

        if !functions.is_empty() {
            renderer.print(&format!("  检测到 {} 个可能的函数定义", functions.len()));
        }
        if !classes.is_empty() {
            renderer.print(&format!("  检测到 {} 个可能的类/结构体定义", classes.len()));
        }
    }

    Ok(())
}
