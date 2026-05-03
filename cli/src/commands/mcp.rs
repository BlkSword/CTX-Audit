// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! MCP Server 命令实现
//!
//! 通过 stdio JSON-RPC 暴露 daemon 的安全分析能力给 AI agent
//! 提供粗粒度（security_scan）和细粒度（get_taint_path, check_sanitizer 等）工具

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use ctx_audit_daemon::client::DaemonClient;
use ctx_audit_daemon::protocol::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── MCP Protocol Types ──────────────────────────────────

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    result: Value,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
}

// ── Tool Definitions ────────────────────────────────────

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        // ── 粗粒度工具 ────────────────────────────
        ToolDefinition {
            name: "security_scan",
            description: "Scan a project or directory for security vulnerabilities. Returns a list of findings with severity, file path, line number, and description. Supports quick scan and deep scan (AST taint analysis).",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Project or directory path to scan"
                    },
                    "deep": {
                        "type": "boolean",
                        "description": "Enable deep scan with AST taint analysis (default: false)",
                        "default": false
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: critical, high, medium, low, info",
                        "enum": ["critical", "high", "medium", "low", "info"]
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Filter by file pattern (e.g. '*.py')"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "scan_file",
            description: "Analyze a single source file for security issues. Returns detailed analysis including language, code snippet, function calls, and taint flows.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the source file to analyze"
                    },
                    "show_symbols": {
                        "type": "boolean",
                        "description": "Include symbol and call information (default: true)",
                        "default": true
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Start line for analysis (default: 1)"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "End line for analysis"
                    }
                },
                "required": ["file_path"]
            }),
        },
        ToolDefinition {
            name: "daemon_status",
            description: "Check if the CTX-Audit security analysis daemon is running and get its status including uptime, loaded projects, and cache statistics.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
        },
        // ── 细粒度工具：污点追踪 ──────────────────
        ToolDefinition {
            name: "get_taint_path",
            description: "Get detailed taint propagation path from source to sink in a file. Returns each propagation step with variable name, line number, code snippet, and step type (assignment, call, sanitization, etc.). Use this to trace exactly how user input flows to a dangerous operation.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the source file to analyze for taint paths"
                    },
                    "source": {
                        "type": "string",
                        "description": "Filter: only return flows starting from this source variable or pattern (e.g. 'request.args')"
                    },
                    "sink": {
                        "type": "string",
                        "description": "Filter: only return flows reaching this sink function (e.g. 'execute')"
                    }
                },
                "required": ["file_path"]
            }),
        },
        ToolDefinition {
            name: "get_data_flow",
            description: "Trace how a specific variable flows through the code. Returns all definitions (where it's assigned), uses (where it's referenced), and whether it's affected by taint. Use this to understand how data moves through a function.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the source file"
                    },
                    "variable": {
                        "type": "string",
                        "description": "Variable name to trace (e.g. 'user_input', 'query')"
                    }
                },
                "required": ["file_path", "variable"]
            }),
        },
        ToolDefinition {
            name: "check_sanitizer",
            description: "Check if a function name matches any known sanitizer pattern. Returns matching patterns with descriptions. Use this to verify if a filtering/validation function is recognized as a sanitizer by the analysis engine.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "func_name": {
                        "type": "string",
                        "description": "Function name to check (e.g. 'htmlspecialchars', 'escape', 'DOMPurify.sanitize')"
                    }
                },
                "required": ["func_name"]
            }),
        },
        ToolDefinition {
            name: "list_sources",
            description: "List all taint sources (user input points) detected in a file. Returns source ID, name, matching pattern, and line number for each detected source. Use this to find all entry points for user-controlled data.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the source file to scan for taint sources"
                    }
                },
                "required": ["file_path"]
            }),
        },
        ToolDefinition {
            name: "list_sinks",
            description: "List all taint sinks (dangerous operations) detected in a file. Returns sink ID, name, vulnerability type, CWE, and line number for each detected sink. Use this to find all potentially dangerous function calls.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the source file to scan for taint sinks"
                    }
                },
                "required": ["file_path"]
            }),
        },
        ToolDefinition {
            name: "cross_file_analysis",
            description: "Run cross-file taint analysis on a project. Builds call graph, resolves cross-file function calls, computes function summaries, and finds interprocedural taint flows. Returns cross-file flows with full path steps, function summaries, and call graph statistics.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the project root directory"
                    }
                },
                "required": ["project_path"]
            }),
        },
        ToolDefinition {
            name: "get_call_graph",
            description: "Get the function call graph for a project. Returns nodes (functions) and their call relationships. Use this to understand how functions call each other across files.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the project root directory"
                    },
                    "entry": {
                        "type": "string",
                        "description": "Entry function name to start from (optional)"
                    },
                    "depth": {
                        "type": "integer",
                        "description": "Maximum depth to traverse (default: 3)",
                        "default": 3
                    }
                },
                "required": ["project_path"]
            }),
        },
    ]
}

/// Handle a tool call
async fn handle_tool_call(name: &str, arguments: &Value) -> Value {
    match name {
        // 粗粒度
        "security_scan" => tool_security_scan(arguments).await,
        "scan_file" => tool_scan_file(arguments).await,
        "daemon_status" => tool_daemon_status().await,
        // 细粒度
        "get_taint_path" => tool_get_taint_path(arguments).await,
        "get_data_flow" => tool_get_data_flow(arguments).await,
        "check_sanitizer" => tool_check_sanitizer(arguments).await,
        "list_sources" => tool_list_sources(arguments).await,
        "list_sinks" => tool_list_sinks(arguments).await,
        "cross_file_analysis" => tool_cross_file_analysis(arguments).await,
        "get_call_graph" => tool_get_call_graph(arguments).await,
        _ => serde_json::json!({
            "content": [{"type": "text", "text": format!("Unknown tool: {}", name)}],
            "isError": true
        }),
    }
}

// ── 粗粒度工具实现 ──────────────────────────────────────

async fn tool_security_scan(args: &Value) -> Value {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let deep = args.get("deep").and_then(|v| v.as_bool()).unwrap_or(false);
    let severity = args.get("severity").and_then(|v| v.as_str()).map(String::from);
    let pattern = args.get("pattern").and_then(|v| v.as_str()).map(String::from);

    let result = if deep {
        deepaudit_core::scan_directory_deep(path).await
    } else {
        deepaudit_core::scan_directory(path).await
    };

    match result {
        Ok(findings) => {
            let mut filtered = findings;
            if let Some(sev) = &severity {
                let sev_lower = sev.to_lowercase();
                filtered.retain(|f| f.severity.to_lowercase() == sev_lower);
            }
            if let Some(pat) = &pattern {
                filtered.retain(|f| f.file_path.contains(pat.as_str()));
            }

            let summary = format_security_findings(&filtered);
            let details: Vec<Value> = filtered.iter().map(|f| serde_json::json!({
                "id": f.finding_id,
                "severity": f.severity,
                "type": f.vuln_type,
                "file": f.file_path,
                "line": f.line_start,
                "description": f.description,
                "confidence": f.confidence,
                "detector": f.detector,
            })).collect();

            serde_json::json!({
                "content": [
                    {"type": "text", "text": summary},
                    {"type": "text", "text": serde_json::to_string_pretty(&details).unwrap_or_default()}
                ]
            })
        }
        Err(e) => serde_json::json!({
            "content": [{"type": "text", "text": format!("Scan failed: {}", e)}],
            "isError": true
        }),
    }
}

async fn tool_scan_file(args: &Value) -> Value {
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return serde_json::json!({
            "content": [{"type": "text", "text": "Missing required parameter: file_path"}],
            "isError": true
        }),
    };

    let show_symbols = args.get("show_symbols").and_then(|v| v.as_bool()).unwrap_or(true);
    let start_line = args.get("start_line").and_then(|v| v.as_u64()).map(|n| n as usize);
    let end_line = args.get("end_line").and_then(|v| v.as_u64()).map(|n| n as usize);

    // Try daemon first, fallback to local
    let result = try_daemon_analyze(file_path, start_line, end_line, show_symbols).await;

    match result {
        Some(content) => serde_json::json!({
            "content": [{"type": "text", "text": serde_json::to_string_pretty(&content).unwrap_or_default()}]
        }),
        None => {
            // Local fallback
            let path = std::path::Path::new(file_path);
            if !path.exists() {
                return serde_json::json!({
                    "content": [{"type": "text", "text": format!("File not found: {}", file_path)}],
                    "isError": true
                });
            }

            let code = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => return serde_json::json!({
                    "content": [{"type": "text", "text": format!("Failed to read file: {}", e)}],
                    "isError": true
                }),
            };

            let mut result = serde_json::Map::new();
            result.insert("file_path".into(), serde_json::json!(file_path));
            result.insert("language".into(), serde_json::json!(
                path.extension().and_then(|e| e.to_str()).unwrap_or("unknown")
            ));
            result.insert("total_lines".into(), serde_json::json!(code.lines().count()));

            // Taint analysis
            let mut taint_analyzer = deepaudit_core::AstTaintAnalyzer::new();
            let flows = taint_analyzer.analyze_file(path, &code);
            if !flows.is_empty() {
                result.insert("taint_flows".into(), serde_json::json!(
                    flows.iter().map(|f| serde_json::json!({
                        "source": f.source.symbol,
                        "source_line": f.source.line,
                        "sink": f.sink.symbol,
                        "sink_line": f.sink.line,
                        "type": format!("{:?}", f.vulnerability_type),
                    })).collect::<Vec<_>>()
                ));
            }

            serde_json::json!({
                "content": [{"type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default()}]
            })
        }
    }
}

async fn tool_daemon_status() -> Value {
    match DaemonClient::connect().await {
        Ok(mut client) => {
            let ping_resp = client.ping().await;
            let status_resp = client.status().await;

            let mut info = serde_json::Map::new();
            info.insert("running".into(), serde_json::json!(true));

            if let Ok(Response::Pong { version, uptime_secs }) = ping_resp {
                info.insert("version".into(), serde_json::json!(version));
                info.insert("uptime_secs".into(), serde_json::json!(uptime_secs));
            }
            if let Ok(Response::StatusInfo { pid, loaded_projects, cache_stats, .. }) = status_resp {
                info.insert("pid".into(), serde_json::json!(pid));
                info.insert("projects".into(), serde_json::json!(loaded_projects));
                info.insert("cache".into(), serde_json::json!({
                    "ast": cache_stats.ast_cache_entries,
                    "scan": cache_stats.scan_cache_entries,
                }));
            }

            serde_json::json!({
                "content": [{"type": "text", "text": serde_json::to_string_pretty(&info).unwrap_or_default()}]
            })
        }
        Err(_) => serde_json::json!({
            "content": [{"type": "text", "text": "Daemon is not running. Start it with 'ctx-audit daemon start' for better performance with incremental caching."}]
        }),
    }
}

// ── 细粒度工具实现 ──────────────────────────────────────

async fn tool_get_taint_path(args: &Value) -> Value {
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: file_path"),
    };
    let source_filter = args.get("source").and_then(|v| v.as_str());
    let sink_filter = args.get("sink").and_then(|v| v.as_str());

    let path = std::path::Path::new(file_path);
    if !path.exists() {
        return error_response(&format!("File not found: {}", file_path));
    }

    let code = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("Failed to read file: {}", e)),
    };

    let mut analyzer = deepaudit_core::AstTaintAnalyzer::new();
    let mut flows = analyzer.analyze_file(path, &code);

    // Apply filters
    if let Some(src) = source_filter {
        flows.retain(|f| f.source.symbol.contains(src) || f.source.symbol.to_lowercase().contains(&src.to_lowercase()));
    }
    if let Some(snk) = sink_filter {
        flows.retain(|f| f.sink.symbol.contains(snk) || f.sink.symbol.to_lowercase().contains(&snk.to_lowercase()));
    }

    if flows.is_empty() {
        return text_response("No taint flows found matching the criteria.");
    }

    let details: Vec<Value> = flows.iter().map(|f| {
        let path_steps: Vec<Value> = f.path.iter().map(|node| serde_json::json!({
            "type": format!("{:?}", node.node_type),
            "line": node.line,
            "symbol": node.symbol,
            "code_snippet": node.code_snippet,
        })).collect();

        serde_json::json!({
            "vulnerability_type": format!("{:?}", f.vulnerability_type),
            "severity": format!("{:?}", f.severity).to_lowercase(),
            "confidence": f.confidence,
            "source": {
                "symbol": f.source.symbol,
                "line": f.source.line,
                "code_snippet": f.source.code_snippet,
            },
            "sink": {
                "symbol": f.sink.symbol,
                "line": f.sink.line,
                "code_snippet": f.sink.code_snippet,
            },
            "propagation_path": path_steps,
        })
    }).collect();

    let summary = format!("Found {} taint flow(s):\n", flows.len());
    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&details).unwrap_or_default()}
        ]
    })
}

async fn tool_get_data_flow(args: &Value) -> Value {
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: file_path"),
    };
    let variable = match args.get("variable").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return error_response("Missing required parameter: variable"),
    };

    let path = std::path::Path::new(file_path);
    if !path.exists() {
        return error_response(&format!("File not found: {}", file_path));
    }

    let code = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("Failed to read file: {}", e)),
    };

    let mut parser = deepaudit_core::ASTParser::new();
    let path_buf = std::path::PathBuf::from(file_path);

    // Extract assignments and calls
    let assignments = parser.extract_assignments(&path_buf, &code);
    let calls = parser.extract_calls(&path_buf, &code);

    // Find definitions (where the variable is assigned)
    let definitions: Vec<Value> = assignments.iter()
        .filter(|a| a.target == variable || a.target.contains(variable))
        .map(|a| serde_json::json!({
            "line": a.line,
            "target": a.target,
            "source_expr": a.source_expr,
            "source_vars": a.source_vars,
        }))
        .collect();

    // Find uses (where the variable is referenced in calls)
    let uses: Vec<Value> = calls.iter()
        .filter(|c| c.arguments.iter().any(|arg| arg.referenced_vars.contains(&variable.to_string())))
        .map(|c| serde_json::json!({
            "line": c.line,
            "callee": c.callee,
            "arguments": c.arguments.iter().map(|a| &a.text).collect::<Vec<_>>(),
        }))
        .collect();

    // Find uses in assignments (where variable is in source_vars)
    let propagated_to: Vec<Value> = assignments.iter()
        .filter(|a| a.source_vars.contains(&variable.to_string()) && a.target != variable)
        .map(|a| serde_json::json!({
            "line": a.line,
            "target": a.target,
            "source_expr": a.source_expr,
        }))
        .collect();

    // Check if variable is tainted
    let mut taint_analyzer = deepaudit_core::AstTaintAnalyzer::new();
    let flows = taint_analyzer.analyze_file(path, &code);
    let taint_status: Vec<Value> = flows.iter()
        .filter(|f| f.source.symbol == variable || f.path.iter().any(|n| n.symbol == variable))
        .map(|f| serde_json::json!({
            "is_tainted": true,
            "source": f.source.symbol,
            "sink": f.sink.symbol,
            "vulnerability_type": format!("{:?}", f.vulnerability_type),
            "confidence": f.confidence,
        }))
        .collect();

    let result = serde_json::json!({
        "variable": variable,
        "file_path": file_path,
        "definitions": definitions,
        "uses": uses,
        "propagated_to": propagated_to,
        "taint_status": if taint_status.is_empty() {
            serde_json::json!([{"is_tainted": false}])
        } else {
            serde_json::json!(taint_status)
        },
    });

    text_response(&serde_json::to_string_pretty(&result).unwrap_or_default())
}

async fn tool_check_sanitizer(args: &Value) -> Value {
    let func_name = match args.get("func_name").and_then(|v| v.as_str()) {
        Some(f) => f,
        None => return error_response("Missing required parameter: func_name"),
    };

    let analyzer = deepaudit_core::AstTaintAnalyzer::new();

    // Check against sanitizer patterns
    let matches: Vec<Value> = analyzer.sanitizer_patterns().iter()
        .filter(|p| func_name.contains(p.as_str()))
        .map(|p| serde_json::json!({
            "matched_pattern": p,
            "function_name": func_name,
        }))
        .collect();

    // Also check YAML taint rules for sanitizer descriptions
    let descriptions = get_sanitizer_descriptions();

    let result = serde_json::json!({
        "function_name": func_name,
        "is_sanitizer": !matches.is_empty(),
        "matched_patterns": matches,
        "descriptions": matches.iter().filter_map(|m| {
            let pattern = m.get("matched_pattern")?.as_str()?;
            descriptions.iter().find(|(p, _)| p == pattern).map(|(_, desc)| {
                serde_json::json!({"pattern": pattern, "description": desc})
            })
        }).collect::<Vec<_>>(),
    });

    text_response(&serde_json::to_string_pretty(&result).unwrap_or_default())
}

async fn tool_list_sources(args: &Value) -> Value {
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: file_path"),
    };

    let path = std::path::Path::new(file_path);
    if !path.exists() {
        return error_response(&format!("File not found: {}", file_path));
    }

    let code = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("Failed to read file: {}", e)),
    };

    let analyzer = deepaudit_core::AstTaintAnalyzer::new();
    let mut detected_sources: Vec<Value> = Vec::new();

    for (line_idx, line) in code.lines().enumerate() {
        let line_num = line_idx + 1;
        for source in analyzer.sources() {
            if source.matches(line, "") {
                detected_sources.push(serde_json::json!({
                    "line": line_num,
                    "source_id": source.id,
                    "source_name": source.name,
                    "matched_by": source.patterns.iter()
                        .filter(|p| line.contains(p.as_str()))
                        .cloned()
                        .collect::<Vec<_>>(),
                    "code": line.trim(),
                }));
            }
        }
    }

    if detected_sources.is_empty() {
        return text_response("No taint sources detected in this file.");
    }

    let summary = format!("Found {} taint source(s):\n", detected_sources.len());
    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&detected_sources).unwrap_or_default()}
        ]
    })
}

async fn tool_list_sinks(args: &Value) -> Value {
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: file_path"),
    };

    let path = std::path::Path::new(file_path);
    if !path.exists() {
        return error_response(&format!("File not found: {}", file_path));
    }

    let code = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("Failed to read file: {}", e)),
    };

    let analyzer = deepaudit_core::AstTaintAnalyzer::new();
    let mut detected_sinks: Vec<Value> = Vec::new();

    for (line_idx, line) in code.lines().enumerate() {
        let line_num = line_idx + 1;
        for sink in analyzer.sinks() {
            if sink.matches(line, "") {
                detected_sinks.push(serde_json::json!({
                    "line": line_num,
                    "sink_id": sink.id,
                    "sink_name": sink.name,
                    "vulnerability_type": format!("{:?}", sink.vulnerability_type),
                    "cwe": sink.cwe_id,
                    "matched_by": sink.patterns.iter()
                        .filter(|p| line.contains(p.as_str()))
                        .cloned()
                        .collect::<Vec<_>>(),
                    "code": line.trim(),
                }));
            }
        }
    }

    if detected_sinks.is_empty() {
        return text_response("No taint sinks detected in this file.");
    }

    let summary = format!("Found {} taint sink(s):\n", detected_sinks.len());
    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&detected_sinks).unwrap_or_default()}
        ]
    })
}

async fn tool_cross_file_analysis(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: project_path"),
    };

    // Try daemon first
    if let Some(response) = try_daemon_cross_file(project_path).await {
        return response;
    }

    // Local fallback
    let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
    let result = analyzer.analyze_project(std::path::Path::new(project_path));

    let cross_file_flows: Vec<Value> = result.taint_flows.iter()
        .filter(|f| f.source.file_path != f.sink.file_path)
        .map(|f| {
            let steps: Vec<Value> = f.interprocedural_path.iter().map(|s| serde_json::json!({
                "step_type": format!("{:?}", s.step_type),
                "file": s.file_path,
                "function": s.function_name,
                "line": s.line,
                "variable": s.variable,
            })).collect();

            serde_json::json!({
                "source": {"file": f.source.file_path, "line": f.source.line, "symbol": f.source.symbol},
                "sink": {"file": f.sink.file_path, "line": f.sink.line, "symbol": f.sink.symbol},
                "vulnerability_type": format!("{:?}", f.vulnerability_type),
                "confidence": f.confidence,
                "path_steps": steps,
            })
        })
        .collect();

    let output = serde_json::json!({
        "project_path": project_path,
        "stats": {
            "files_analyzed": result.stats.files_analyzed,
            "total_functions": result.stats.total_functions,
            "taint_sources": result.stats.taint_sources,
            "taint_sinks": result.stats.taint_sinks,
            "total_flows": result.stats.taint_flows,
            "cross_file_flows": result.stats.cross_file_flows,
        },
        "cross_file_flows": cross_file_flows,
    });

    text_response(&serde_json::to_string_pretty(&output).unwrap_or_default())
}

async fn tool_get_call_graph(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: project_path"),
    };
    let entry = args.get("entry").and_then(|v| v.as_str()).unwrap_or("");
    let depth = args.get("depth").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

    // Try daemon first
    if let Some(response) = try_daemon_call_graph(project_path, entry, depth).await {
        return response;
    }

    // Local fallback: build call graph from CrossFileTaintAnalyzer
    let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
    let result = analyzer.analyze_project(std::path::Path::new(project_path));

    let nodes: Vec<Value> = result.call_graph.nodes.values()
        .take(100) // Limit output
        .map(|n| serde_json::json!({
            "id": n.id,
            "name": n.name,
            "file": n.file_path,
            "line": n.start_line,
            "calls_count": n.calls.len(),
            "called_by_count": n.called_by.len(),
            "is_taint_source": n.is_taint_source,
            "is_taint_sink": n.is_taint_sink,
        }))
        .collect();

    let edges: Vec<Value> = result.call_graph.nodes.values()
        .flat_map(|n| n.calls.iter().map(move |c| serde_json::json!({
            "caller": n.id,
            "callee": c,
        })))
        .take(200)
        .collect();

    let output = serde_json::json!({
        "project_path": project_path,
        "total_nodes": result.call_graph.nodes.len(),
        "total_edges": edges.len(),
        "nodes": nodes,
        "edges": edges,
    });

    text_response(&serde_json::to_string_pretty(&output).unwrap_or_default())
}

// ── Daemon helpers ──────────────────────────────────────

async fn try_daemon_analyze(
    file_path: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
    show_symbols: bool,
) -> Option<serde_json::Map<String, Value>> {
    let mut client = DaemonClient::connect().await.ok()?;
    let response = client.send_request(Request::Analyze {
        file_path: file_path.to_string(),
        start_line,
        end_line,
        show_ast: false,
        show_symbols,
    }).await.ok()?;

    match response {
        Response::AnalysisResult { content } => {
            if let Value::Object(map) = content { Some(map) } else { None }
        }
        _ => None,
    }
}

async fn try_daemon_cross_file(project_path: &str) -> Option<Value> {
    let mut client = DaemonClient::connect().await.ok()?;
    let response = client.send_request(Request::CrossFileAnalysis {
        path: project_path.to_string(),
    }).await.ok()?;

    match response {
        Response::CrossFileTaintResult { result } => {
            Some(text_response(&serde_json::to_string_pretty(&result).unwrap_or_default()))
        }
        _ => None,
    }
}

async fn try_daemon_call_graph(project_path: &str, entry: &str, depth: usize) -> Option<Value> {
    let mut client = DaemonClient::connect().await.ok()?;

    // Try to load project first
    let _ = client.send_request(Request::LoadProject {
        path: project_path.to_string(),
    }).await;

    let response = client.send_request(Request::GetCallGraph {
        entry: entry.to_string(),
        depth: Some(depth),
    }).await.ok()?;

    match response {
        Response::CallGraphResult { graph } => {
            Some(text_response(&serde_json::to_string_pretty(&graph).unwrap_or_default()))
        }
        _ => None,
    }
}

/// Load sanitizer descriptions from YAML taint rules
fn get_sanitizer_descriptions() -> Vec<(String, String)> {
    let yaml_dir = std::path::Path::new("rules/taint");
    if !yaml_dir.exists() {
        return Vec::new();
    }

    let mut descriptions = Vec::new();

    fn visit_yaml(dir: &std::path::Path, result: &mut Vec<(String, String)>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit_yaml(&path, result);
                } else if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext != "yaml" && ext != "yml" {
                        continue;
                    }
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(rule_set) = serde_yaml::from_str::<deepaudit_core::TaintRuleSet>(&content) {
                            for san in &rule_set.sanitizers {
                                result.push((san.pattern.clone(), san.description.clone()));
                            }
                        }
                    }
                }
            }
        }
    }

    visit_yaml(yaml_dir, &mut descriptions);
    descriptions
}

// ── Response helpers ─────────────────────────────────────

fn error_response(msg: &str) -> Value {
    serde_json::json!({
        "content": [{"type": "text", "text": msg}],
        "isError": true
    })
}

fn text_response(text: &str) -> Value {
    serde_json::json!({
        "content": [{"type": "text", "text": text}]
    })
}

// ── Formatting ──────────────────────────────────────────

fn format_security_findings(findings: &[deepaudit_core::Finding]) -> String {
    if findings.is_empty() {
        return "No security vulnerabilities found.".to_string();
    }

    let mut counts: HashMap<String, usize> = HashMap::new();
    for f in findings {
        *counts.entry(f.severity.clone()).or_insert(0) += 1;
    }

    let mut summary = format!(
        "Found {} security findings:\n",
        findings.len()
    );

    for sev in &["critical", "high", "medium", "low", "info"] {
        if let Some(count) = counts.get(*sev) {
            summary.push_str(&format!("  - {}: {}\n", sev.to_uppercase(), count));
        }
    }

    summary.push_str("\nTop findings:\n");
    for f in findings.iter().take(20) {
        summary.push_str(&format!(
            "  [{}] {} — {}:{} — {}\n",
            f.severity.to_uppercase(),
            f.vuln_type,
            f.file_path,
            f.line_start,
            f.description.chars().take(120).collect::<String>()
        ));
    }

    if findings.len() > 20 {
        summary.push_str(&format!("  ... and {} more\n", findings.len() - 20));
    }

    summary
}

// ── MCP Server Main Loop ────────────────────────────────

pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = line?;

        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err_response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32700, "message": format!("Parse error: {}", e)}
                });
                writeln!(stdout, "{}", serde_json::to_string(&err_response)?)?;
                stdout.flush()?;
                continue;
            }
        };

        let id = request.id.unwrap_or(Value::Null);
        let result = handle_request(request.method.clone(), &request.params).await;

        let response = JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result,
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}

async fn handle_request(method: String, params: &Value) -> Value {
    match method.as_str() {
        "initialize" => {
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "ctx-audit",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })
        }
        "notifications/initialized" => {
            // No response needed for notifications
            serde_json::json!(null)
        }
        "tools/list" => {
            let tools: Vec<Value> = tool_definitions().iter().map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                })
            }).collect();
            serde_json::json!({"tools": tools})
        }
        "tools/call" => {
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));

            handle_tool_call(tool_name, &arguments).await
        }
        "ping" => {
            serde_json::json!({})
        }
        _ => {
            serde_json::json!({
                "content": [{"type": "text", "text": format!("Unknown method: {}", method)}],
                "isError": true
            })
        }
    }
}
