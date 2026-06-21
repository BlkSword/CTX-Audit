// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! analyze 命令实现
//!
//! 深度分析单个文件

use miette::Result;

use crate::terminal::TerminalRenderer;
use ctx_audit_daemon::client::DaemonClient;
use ctx_audit_daemon::protocol::{RequestCommand, Response};

/// 执行 analyze 命令
pub async fn execute(
    file: String,
    start_line: usize,
    end_line: Option<usize>,
    show_ast: bool,
    show_symbols: bool,
    output_format: &str,
    daemon: bool,
) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    // 验证文件路径
    let file_path = std::path::Path::new(&file);
    if !file_path.exists() {
        renderer.error(&format!("文件不存在: {}", file));
        return Err(miette::miette!("文件不存在"));
    }

    if daemon {
        return analyze_via_daemon(
            file,
            start_line,
            end_line,
            show_ast,
            show_symbols,
            output_format,
            &mut renderer,
        )
        .await;
    }

    renderer.info(&format!("分析文件: {}", file));

    // 读取文件内容
    let content = tokio::fs::read_to_string(&file)
        .await
        .map_err(|e| miette::miette!("{}", e))?;
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
        renderer.print("提示: 使用 --daemon 获取完整 AST 分析结果");
    }

    // 显示符号信息
    if show_symbols {
        renderer.print("\n符号信息:");
        let total_lines = lines.len();
        renderer.print(&format!("  总行数: {}", total_lines));

        let mut functions = Vec::new();
        let mut classes = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains("fn ") || trimmed.contains("function ") || trimmed.contains("def ")
            {
                functions.push(i + 1);
            }
            if trimmed.contains("class ")
                || trimmed.contains("struct ")
                || trimmed.contains("interface ")
            {
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

/// 通过守护进程分析文件
async fn analyze_via_daemon(
    file: String,
    start_line: usize,
    end_line: Option<usize>,
    show_ast: bool,
    show_symbols: bool,
    output_format: &str,
    renderer: &mut TerminalRenderer,
) -> Result<()> {
    let mut client = DaemonClient::connect().await.map_err(|e| {
        miette::miette!(
            "连接守护进程失败: {} (使用 'ctx-audit daemon start' 启动)",
            e
        )
    })?;

    renderer.info(&format!("通过守护进程分析: {}", file));

    let response = client
        .send_request(RequestCommand::Analyze {
            file_path: file.clone(),
            start_line: Some(start_line),
            end_line,
            show_ast,
            show_symbols,
        })
        .await
        .map_err(|e| miette::miette!("分析请求失败: {}", e))?;

    match response {
        Response::AnalysisResult { content } => {
            match output_format {
                "json" => {
                    let json = serde_json::to_string_pretty(&content)
                        .map_err(|e| miette::miette!("JSON 格式化失败: {}", e))?;
                    println!("{}", json);
                }
                _ => {
                    // 格式化输出
                    if let Some(lang) = content.get("language").and_then(|v| v.as_str()) {
                        renderer.info(&format!("语言: {}", lang));
                    }
                    if let Some(total) = content.get("total_lines").and_then(|v| v.as_u64()) {
                        renderer.info(&format!("总行数: {}", total));
                    }

                    // 代码片段
                    if let Some(snippet) = content.get("snippet").and_then(|v| v.as_array()) {
                        renderer.print("\n代码片段:");
                        for line in snippet {
                            let line_num = line.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
                            let line_content =
                                line.get("content").and_then(|v| v.as_str()).unwrap_or("");
                            println!("  {}: {}", line_num, line_content);
                        }
                    }

                    // 符号
                    if let Some(symbols) = content.get("symbols").and_then(|v| v.as_array()) {
                        if !symbols.is_empty() {
                            renderer.print(&format!("\n符号 ({}):", symbols.len()));
                            for sym in symbols {
                                let name = sym.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                let kind = sym.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
                                let line = sym.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
                                println!("  {} [{}] :{}", name, kind, line);
                            }
                        }
                    }

                    // 污点流
                    if let Some(flows) = content.get("taint_flows").and_then(|v| v.as_array()) {
                        if !flows.is_empty() {
                            renderer.print(&format!("\n污点流 ({}):", flows.len()));
                            for flow in flows {
                                let source =
                                    flow.get("source").and_then(|v| v.as_str()).unwrap_or("?");
                                let sink = flow.get("sink").and_then(|v| v.as_str()).unwrap_or("?");
                                let src_line = flow
                                    .get("source_line")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(0);
                                let snk_line =
                                    flow.get("sink_line").and_then(|v| v.as_u64()).unwrap_or(0);
                                println!("  {}:{} → {}:{}", source, src_line, sink, snk_line);
                            }
                        }
                    }
                }
            }
        }
        Response::Error { message, .. } => {
            renderer.error(&format!("分析失败: {}", message));
            return Err(miette::miette!("分析失败: {}", message));
        }
        _ => {
            renderer.error("意外的响应类型");
        }
    }

    Ok(())
}
