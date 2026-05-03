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

use deepaudit_core::scanning::{Finding, scan_directory, scan_directory_deep};
use deepaudit_core::ast_api::ASTParser;
use deepaudit_core::taint::{AstTaintAnalyzer, CrossFileTaintAnalyzer};
use deepaudit_core::attack_surface::{AttackSurfaceMapper, AttackSurface, RiskPatternScanner, RiskPatternMatch};
use deepaudit_core::rules::model::Rule;
use deepaudit_core::rules::taint_model::TaintRuleSet;
use deepaudit_core::rules::model::RuleSet;

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
        // ── 攻击面 + 风险模式 + 动态规则 ────────────
        ToolDefinition {
            name: "get_attack_surface",
            description: "Map the attack surface of a project. Returns entry points with risk scores, trust boundaries, high-risk files, per-entry-point risk factors (validation status, data sources, deserialization reach), and detected frameworks (Spring, Express, Next.js, Flask, Django). Essential for understanding attack vectors and prioritizing security analysis.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the project root directory"
                    },
                    "min_risk_score": {
                        "type": "number",
                        "description": "Minimum risk score to include (0.0-1.0, default: 0.3)",
                        "default": 0.3
                    },
                    "include_details": {
                        "type": "boolean",
                        "description": "Include detailed risk factors per entry point (default: true)",
                        "default": true
                    }
                },
                "required": ["project_path"]
            }),
        },
        ToolDefinition {
            name: "analyze_risk_patterns",
            description: "Analyze a project for high-level architectural risk patterns that may indicate 0-day vulnerability candidates. Combines entry point detection with data flow heuristics (source → sink + missing validation). Returns matched risk patterns with evidence, affected entry points, and confidence scores. Patterns include: unvalidated input to deserialization, unauthenticated privileged operations, external data to code execution, prototype pollution vectors, and missing input validation.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {
                        "type": "string",
                        "description": "Path to the project root directory"
                    },
                    "pattern_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Specific risk pattern IDs to check (optional, checks all by default)"
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Minimum severity filter: critical, high, medium, low, info",
                        "enum": ["critical", "high", "medium", "low", "info"]
                    }
                },
                "required": ["project_path"]
            }),
        },
        ToolDefinition {
            name: "add_custom_rule",
            description: "Add a custom security rule (pattern or taint) at runtime. Validates the YAML content against the rule schema and, if valid, writes it to the project's .ctx-audit/rules/ directory. The rule becomes effective on the next scan or daemon reload (30s). Use this to create targeted rules for investigating potential 0-day vulnerabilities discovered during analysis.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "rule_content": {
                        "type": "string",
                        "description": "YAML content of the rule to add"
                    },
                    "rule_type": {
                        "type": "string",
                        "description": "Type of rule",
                        "enum": ["pattern", "taint"]
                    },
                    "validate_only": {
                        "type": "boolean",
                        "description": "Validate without writing to disk (default: false)",
                        "default": false
                    }
                },
                "required": ["rule_content", "rule_type"]
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
        // 攻击面 + 风险模式 + 动态规则
        "get_attack_surface" => tool_get_attack_surface(arguments).await,
        "analyze_risk_patterns" => tool_analyze_risk_patterns(arguments).await,
        "add_custom_rule" => tool_add_custom_rule(arguments).await,
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
        scan_directory_deep(path).await
    } else {
        scan_directory(path).await
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
            let mut taint_analyzer = AstTaintAnalyzer::new();
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

    let mut analyzer = AstTaintAnalyzer::new();
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

    let mut parser = ASTParser::new();
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
    let mut taint_analyzer = AstTaintAnalyzer::new();
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

    let analyzer = AstTaintAnalyzer::new();

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

    let analyzer = AstTaintAnalyzer::new();
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

    let analyzer = AstTaintAnalyzer::new();
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
    let mut analyzer = CrossFileTaintAnalyzer::new();
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
    let mut analyzer = CrossFileTaintAnalyzer::new();
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
                        if let Ok(rule_set) = serde_yaml::from_str::<TaintRuleSet>(&content) {
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

fn format_security_findings(findings: &[Finding]) -> String {
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

// ── 攻击面 + 风险模式 + 动态规则工具 ──────────────────────

async fn tool_get_attack_surface(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: project_path"),
    };
    let min_risk_score = args.get("min_risk_score").and_then(|v| v.as_f64()).unwrap_or(0.3) as f32;
    let include_details = args.get("include_details").and_then(|v| v.as_bool()).unwrap_or(true);

    let path = std::path::Path::new(project_path);
    if !path.exists() {
        return error_response(&format!("Project path not found: {}", project_path));
    }

    let surface = AttackSurfaceMapper::map_project(path);

    // 过滤低风险入口点
    let filtered_entries: Vec<Value> = surface.entry_points.iter()
        .filter(|ep| ep.risk_score >= min_risk_score)
        .map(|ep| {
            let mut entry = serde_json::json!({
                "file_path": ep.file_path,
                "line": ep.line,
                "entry_type": format!("{:?}", ep.entry_type),
                "route": ep.route,
                "http_method": ep.http_method,
                "auth_required": ep.auth_required,
                "risk_score": (ep.risk_score * 100.0).round() / 100.0,
                "function_name": ep.function_name,
            });
            if include_details {
                entry["context"] = serde_json::json!({
                    "data_sources": ep.context.data_sources,
                    "has_sanitization": ep.context.has_sanitization,
                    "has_input_validation": ep.context.has_input_validation,
                    "reaches_deserialization": ep.context.reaches_deserialization,
                    "reaches_privileged_op": ep.context.reaches_privileged_op,
                    "risk_factors": ep.context.risk_factors,
                });
            }
            entry
        })
        .collect();

    let trust_bounds: Vec<Value> = surface.trust_boundaries.iter()
        .map(|tb| serde_json::json!({
            "file_path": tb.file_path,
            "line": tb.line,
            "description": tb.description,
            "source": tb.source,
        }))
        .collect();

    let summary = format!(
        "Attack Surface: {} entry points ({} filtered ≥{:.1}), {} trust boundaries, {} high-risk files. Frameworks: {}",
        surface.stats.total_entry_points,
        filtered_entries.len(),
        min_risk_score,
        surface.trust_boundaries.len(),
        surface.high_risk_files.len(),
        surface.stats.detected_frameworks.join(", "),
    );

    let details = serde_json::json!({
        "entry_points": filtered_entries,
        "trust_boundaries": trust_bounds,
        "high_risk_files": surface.high_risk_files,
        "stats": {
            "files_scanned": surface.stats.files_scanned,
            "total_entry_points": surface.stats.total_entry_points,
            "unauthenticated_count": surface.stats.unauthenticated_count,
            "high_risk_file_count": surface.stats.high_risk_file_count,
            "detected_frameworks": surface.stats.detected_frameworks,
        },
    });

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&details).unwrap_or_default()},
        ]
    })
}

async fn tool_analyze_risk_patterns(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: project_path"),
    };

    let path = std::path::Path::new(project_path);
    if !path.exists() {
        return error_response(&format!("Project path not found: {}", project_path));
    }

    // 获取攻击面
    let surface = AttackSurfaceMapper::map_project(path);

    // 创建风险模式扫描器
    let mut scanner = RiskPatternScanner::new(path);

    // 可选: 过滤特定 pattern IDs
    let requested_ids: Option<Vec<String>> = args.get("pattern_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect());

    // 扫描
    let mut matches = scanner.scan(&surface, path);

    // 过滤
    if let Some(ref ids) = requested_ids {
        matches.retain(|m| ids.contains(&m.pattern_id));
    }

    let severity_order = |s: &str| match s {
        "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, "info" => 4, _ => 5,
    };
    if let Some(min_sev) = args.get("min_severity").and_then(|v| v.as_str()) {
        let min_rank = severity_order(min_sev);
        matches.retain(|m| {
            let sev = format!("{:?}", m.severity).to_lowercase();
            severity_order(&sev) <= min_rank
        });
    }

    let summary = format!(
        "Risk Pattern Analysis: {} matches found across {} entry points. Patterns checked: {}.",
        matches.len(),
        surface.stats.total_entry_points,
        scanner.pattern_count(),
    );

    let match_details: Vec<Value> = matches.iter().map(|m| {
        let evidence: Vec<Value> = m.evidence.iter().take(5).map(|e| serde_json::json!({
            "file": e.file_path,
            "line": e.line,
            "matched": e.matched_pattern,
            "code": e.code_snippet,
            "type": e.context_type,
        })).collect();

        let affected: Vec<Value> = m.affected_entries.iter().map(|a| serde_json::json!({
            "file": a.file_path,
            "line": a.line,
            "type": a.entry_type,
            "function": a.function_name,
            "route": a.route,
        })).collect();

        serde_json::json!({
            "pattern_id": m.pattern_id,
            "pattern_name": m.pattern_name,
            "severity": format!("{:?}", m.severity).to_lowercase(),
            "confidence": m.confidence,
            "cwe": m.cwe,
            "risk_factors": m.risk_factors,
            "affected_entries": affected,
            "evidence": evidence,
        })
    }).collect();

    let output = serde_json::json!({
        "total_matches": matches.len(),
        "patterns_checked": scanner.pattern_count(),
        "available_pattern_ids": scanner.pattern_ids(),
        "matches": match_details,
    });

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&output).unwrap_or_default()},
        ]
    })
}

async fn tool_add_custom_rule(args: &Value) -> Value {
    let rule_content = match args.get("rule_content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return error_response("Missing required parameter: rule_content"),
    };
    let rule_type = match args.get("rule_type").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return error_response("Missing required parameter: rule_type"),
    };
    let validate_only = args.get("validate_only").and_then(|v| v.as_bool()).unwrap_or(false);

    // 大小限制
    if rule_content.len() > 65536 {
        return error_response("Rule content too large (max 64KB)");
    }

    // 安全检查: 拒绝 YAML merge keys
    if rule_content.contains("<<:") {
        return error_response("Rule content contains forbidden YAML merge key (<<:)");
    }

    // 解析 YAML
    let yaml_value: serde_yaml::Value = match serde_yaml::from_str(rule_content) {
        Ok(v) => v,
        Err(e) => return error_response(&format!("Invalid YAML: {}", e)),
    };

    // 按类型验证
    match rule_type {
        "pattern" => {
            // 尝试解析为 RuleSet 或单个 Rule
            let validation_result = if let Ok(rs) = serde_yaml::from_value::<RuleSet>(yaml_value.clone()) {
                Ok((rs.name.clone(), rs.rules.len(), "ruleset"))
            } else if let Ok(rule) = serde_yaml::from_value::<Rule>(yaml_value.clone()) {
                // 验证必填字段
                if rule.id.is_empty() {
                    return error_response("Pattern rule missing required field: id");
                }
                if rule.name.is_empty() {
                    return error_response("Pattern rule missing required field: name");
                }
                if rule.pattern.is_none() && rule.patterns.is_none() && rule.query.is_none() {
                    return error_response("Pattern rule must have at least one of: pattern, patterns, query");
                }
                Ok((rule.name.clone(), 1, "rule"))
            } else {
                Err("Could not parse as RuleSet or Rule. Check YAML structure.".to_string())
            };

            match validation_result {
                Ok((name, count, kind)) => {
                    if validate_only {
                        return text_response(&format!(
                            "Validation OK: {} '{}' with {} rule(s)", kind, name, count
                        ));
                    }
                    write_rule_file(rule_content, rule_type, &extract_rule_id(&yaml_value))
                }
                Err(e) => error_response(&format!("Validation failed: {}", e)),
            }
        }
        "taint" => {
            match serde_yaml::from_value::<TaintRuleSet>(yaml_value.clone()) {
                Ok(ts) => {
                    if ts.kind != "taint-rules" {
                        return error_response(&format!(
                            "Taint rule must have kind='taint-rules', got '{}'", ts.kind
                        ));
                    }
                    if ts.sources.is_empty() && ts.sinks.is_empty() {
                        return error_response("Taint rule must have at least one source or sink");
                    }
                    if validate_only {
                        return text_response(&format!(
                            "Validation OK: taint rule '{}' with {} sources, {} sinks, {} sanitizers",
                            ts.name, ts.sources.len(), ts.sinks.len(), ts.sanitizers.len()
                        ));
                    }
                    write_rule_file(rule_content, rule_type, &slugify(&ts.name))
                }
                Err(e) => error_response(&format!("Failed to parse taint rule: {}", e)),
            }
        }
        _ => error_response(&format!("Unknown rule_type: '{}'. Must be 'pattern' or 'taint'", rule_type)),
    }
}

fn write_rule_file(content: &str, rule_type: &str, id_base: &str) -> Value {
    let rules_dir = std::path::Path::new(".ctx-audit/rules");
    if let Err(e) = std::fs::create_dir_all(rules_dir) {
        return error_response(&format!("Failed to create rules directory: {}", e));
    }

    let filename = format!("llm-generated-{}.yaml", id_base);
    let filepath = rules_dir.join(&filename);

    if let Err(e) = std::fs::write(&filepath, content) {
        return error_response(&format!("Failed to write rule file: {}", e));
    }

    text_response(&format!(
        "Rule written to {} (type: {}). Daemon will hot-reload within 30s.",
        filepath.display(), rule_type
    ))
}

fn extract_rule_id(yaml: &serde_yaml::Value) -> String {
    yaml.get("id")
        .and_then(|v| v.as_str())
        .map(slugify)
        .unwrap_or_else(|| "unnamed".to_string())
}

fn slugify(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
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
