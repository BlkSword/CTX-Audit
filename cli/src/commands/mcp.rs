// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! MCP Server 命令实现
//!
//! 通过 stdio JSON-RPC 暴露 daemon 的安全分析能力给 AI agent
//! 提供粗粒度（security_scan）和细粒度（get_taint_path, check_sanitizer 等）工具

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use ctx_audit_daemon::client::DaemonClient;
use ctx_audit_daemon::protocol::{RequestCommand, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use deepaudit_core::ast_api::ASTParser;
use deepaudit_core::attack_surface::{AttackSurfaceMapper, RiskPatternScanner};
use deepaudit_core::rules::audit_pack::{find_pack, generic_pack, load_audit_packs};
use deepaudit_core::rules::model::Rule;
use deepaudit_core::rules::model::RuleSet;
use deepaudit_core::rules::taint_model::TaintRuleSet;
use deepaudit_core::scanning::{
    scan_directory, scan_directory_deep_with_rules_progress, scan_directory_with_opts, Finding,
    ScanOptions,
};
use deepaudit_core::taint::{AstTaintAnalyzer, CrossFileTaintAnalyzer};

use crate::config::ConfigManager;

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
            description: "Scan a project or directory for security vulnerabilities. Returns a list of findings with full metadata: severity, file role (production/test/build/vendor), detected security barriers, code context, taint chains, and reasoning hints. Supports quick scan and deep scan (AST taint analysis + cross-file tracking). Use file_role_filter to focus on production code.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Project or directory path to scan"
                    },
                    "deep": {
                        "type": "boolean",
                        "description": "Shorthand for enable_taint + enable_cross_file (default: false)",
                        "default": false
                    },
                    "enable_taint": {
                        "type": "boolean",
                        "description": "Enable AST taint analysis (single-file source-to-sink tracking)",
                        "default": false
                    },
                    "enable_cross_file": {
                        "type": "boolean",
                        "description": "Enable cross-file taint tracking (implies enable_taint)",
                        "default": false
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: critical, high, medium, low, info",
                        "enum": ["critical", "high", "medium", "low", "info"]
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Filter by file path pattern (e.g. '*.py')"
                    },
                    "file_role_filter": {
                        "type": "string",
                        "description": "Filter by file role: production, test, build, vendor",
                        "enum": ["production", "test", "build", "vendor"]
                    },
                    "min_severity": {
                        "type": "string",
                        "description": "Minimum severity threshold (e.g. 'high' returns critical+high)",
                        "enum": ["critical", "high", "medium", "low", "info"]
                    },
                    "include_details": {
                        "type": "boolean",
                        "description": "Include full finding details: code_context, taint_chain, barriers, source/sink snippets (default: true)",
                        "default": true
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
        // ── LLM 自主审计工具 ──────────────────────────
        ToolDefinition {
            name: "get_code_context",
            description: "Read source code around a specific file and line number. Returns the code with line numbers, highlighting the target line. Use this to read the actual source code when auditing a finding — you need to see the surrounding context to judge if a finding is a true positive or false positive.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the source file"
                    },
                    "line": {
                        "type": "integer",
                        "description": "Center line number to read around"
                    },
                    "context_lines": {
                        "type": "integer",
                        "description": "Number of context lines above and below (default: 10)",
                        "default": 10
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "Start line (overrides line - context_lines)"
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "End line (overrides line + context_lines)"
                    }
                },
                "required": ["file_path"]
            }),
        },
        ToolDefinition {
            name: "get_project_info",
            description: "Get project overview: detected languages, frameworks, file counts, directory structure, and entry points. Call this first to understand what you're auditing before running scans. Returns top-level directory structure, language distribution, and detected frameworks.",
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
            name: "validate_finding",
            description: "Record your audit decision for a finding. Marks it as true positive (TP) or false positive (FP) with your reasoning. Writes to .ctx-audit/baseline.json for FP suppression or .ctx-audit/audit_log.json for confirmed findings. This creates the feedback loop for LLM-driven auditing.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The finding ID to validate"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "File path of the finding"
                    },
                    "line": {
                        "type": "integer",
                        "description": "Line number of the finding"
                    },
                    "vulnerability_type": {
                        "type": "string",
                        "description": "Vulnerability type (e.g. 'CWE-79')"
                    },
                    "verdict": {
                        "type": "string",
                        "description": "Your audit verdict",
                        "enum": ["true_positive", "false_positive", "needs_review"]
                    },
                    "reasoning": {
                        "type": "string",
                        "description": "Your detailed reasoning for this verdict"
                    },
                    "severity_override": {
                        "type": "string",
                        "description": "Override severity if different from original (optional)",
                        "enum": ["critical", "high", "medium", "low", "info"]
                    }
                },
                "required": ["finding_id", "verdict", "reasoning"]
            }),
        },
        ToolDefinition {
            name: "list_rules",
            description: "List all active security rules currently loaded. Shows rule ID, name, severity, language, and category for each rule. Use this to understand what vulnerability patterns the scanner checks for, and to identify gaps where custom rules may be needed.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "description": "Filter by category (e.g. 'injection', 'xss')"
                    },
                    "language": {
                        "type": "string",
                        "description": "Filter by language (e.g. 'javascript', 'python')"
                    }
                }
            }),
        },
        // ── 审计会话工具（调查式协作）──────────────
        ToolDefinition {
            name: "start_audit_session",
            description: "Start a new audit session for a project. Creates a session context that tracks all investigations. Call this FIRST before auditing findings. Returns a session_uuid to use in subsequent investigation calls.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "session_type": {"type": "string", "description": "Session type: full, targeted, or incremental", "enum": ["full", "targeted", "incremental"], "default": "targeted"}
                },
                "required": ["project_path"]
            }),
        },
        ToolDefinition {
            name: "start_investigation",
            description: "Start a deep investigation of a specific finding. Matches the finding's vuln_type to a CWE-specific evidence pack (rules/audit-packs/) and returns structured evidence steps (suggested_tools with pre-filled params), TP/FP criteria, and a confidence calibration guide. Use the steps to gather evidence, then conclude_investigation with your verdict.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "session_uuid": {"type": "string", "description": "Session UUID from start_audit_session"},
                    "finding_id": {"type": "string", "description": "The finding ID to investigate"},
                    "finding_file": {"type": "string", "description": "File path of the finding"},
                    "finding_line": {"type": "integer", "description": "Line number of the finding"},
                    "vuln_type": {"type": "string", "description": "Vulnerability type or CWE (e.g. 'xss', 'SqlInjection', 'CWE-79'). Optional — used to match the evidence pack when the finding is not in a session group"},
                    "hypothesis": {"type": "string", "description": "Your initial hypothesis about this finding (e.g., 'likely TP because no sanitizer', 'suspicious FP because of array args')"}
                },
                "required": ["session_uuid", "finding_id"]
            }),
        },
        ToolDefinition {
            name: "log_investigation_step",
            description: "Record a step in your investigation. Call this after using other tools (query_callers, get_code_context, etc.) to document what you found and your reasoning. Builds a complete audit trail for each finding.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "investigation_id": {"type": "string", "description": "Investigation ID from start_investigation"},
                    "tool_used": {"type": "string", "description": "Name of the tool you just used (e.g., 'query_callers', 'get_code_context')"},
                    "finding": {"type": "string", "description": "What you discovered from this tool call"},
                    "reasoning": {"type": "string", "description": "Your reasoning about how this affects the verdict"}
                },
                "required": ["investigation_id", "tool_used", "finding", "reasoning"]
            }),
        },
        ToolDefinition {
            name: "conclude_investigation",
            description: "Conclude an investigation with your final verdict. Records the complete investigation trail (all steps) and the final decision. For FP verdicts, automatically updates .ctx-audit/baseline.json for future suppression. Also logs to .ctx-audit/audit_log.json.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "investigation_id": {"type": "string", "description": "Investigation ID from start_investigation"},
                    "verdict": {"type": "string", "description": "Your final verdict", "enum": ["true_positive", "false_positive", "needs_review"]},
                    "reasoning": {"type": "string", "description": "Complete reasoning for your verdict, summarizing all investigation steps"},
                    "confidence": {"type": "number", "description": "Your confidence in this verdict (0.0-1.0)"},
                    "severity_override": {"type": "string", "description": "Override severity if different from original", "enum": ["critical", "high", "medium", "low", "info"]}
                },
                "required": ["investigation_id", "verdict", "reasoning"]
            }),
        },
        ToolDefinition {
            name: "conclude_audit_session",
            description: "Conclude the entire audit session. Returns a summary of all investigations with counts of TP/FP/needs_review findings. This finalizes the session and provides an audit summary.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "session_uuid": {"type": "string", "description": "Session UUID from start_audit_session"},
                    "summary": {"type": "string", "description": "Optional free-text summary of the audit"}
                },
                "required": ["session_uuid"]
            }),
        },
        ToolDefinition {
            name: "audit_plan",
            description: "Create a full audit plan for a project: runs a deep scan (taint + cross-file), groups findings by (vuln_type, file), matches each group to a CWE-specific evidence pack, and persists an audit session to <project>/.ctx-audit/audit_sessions/. Returns the session_uuid and the group list with each group's full evidence pack. Workflow: for each group, call start_investigation on the representative finding and follow the pack's evidence_steps to gather evidence; call conclude_investigation with your verdict (TP/FP/needs_review per the pack's criteria); when all groups are done, call audit_finalize_report to generate the Markdown report.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "min_severity": {"type": "string", "description": "Minimum severity threshold for findings to include (default: high)", "enum": ["critical", "high", "medium", "low", "info"], "default": "high"}
                },
                "required": ["project_path"]
            }),
        },
        ToolDefinition {
            name: "audit_finalize_report",
            description: "Generate the final Markdown audit report for a session. Reads the persisted session and its verdicts from .ctx-audit/audit_log.json, then writes a report with project fingerprint, verdict statistics (TP/FP/needs_review), TP details (attack chain, evidence references, confidence), and FP summaries grouped by vuln_type with exclusion reasons. Call this after concluding all investigations in the session.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "session_uuid": {"type": "string", "description": "Session UUID from audit_plan or start_audit_session"},
                    "output_path": {"type": "string", "description": "Report output path (default: <project>/.ctx-audit/audit_report_<uuid>.md)"}
                },
                "required": ["session_uuid"]
            }),
        },
        // ── 调用图查询工具（Cross-File Call Graph）────
        ToolDefinition {
            name: "query_callers",
            description: "Query the cross-file call graph: find all functions that call a given function. Returns deterministic evidence: caller function name, file, line number, and receiver info. Use this to trace backward from a sink to find entry points.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "file_path": {"type": "string", "description": "File path containing the target function (relative to project)"},
                    "function_name": {"type": "string", "description": "Name of the target function"},
                    "recursive": {"type": "boolean", "description": "Recursively find all transitive callers (default: false)"}
                },
                "required": ["project_path", "file_path", "function_name"]
            }),
        },
        ToolDefinition {
            name: "query_callees",
            description: "Query the cross-file call graph: find all functions called by a given function. Returns each callee with file, line, receiver, and resolution status. Use this to trace forward from an entry point to find sinks.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "file_path": {"type": "string", "description": "File path containing the target function"},
                    "function_name": {"type": "string", "description": "Name of the target function"},
                    "recursive": {"type": "boolean", "description": "Recursively find all transitive callees (default: false)"}
                },
                "required": ["project_path", "file_path", "function_name"]
            }),
        },
        ToolDefinition {
            name: "find_call_path",
            description: "Find the exact call path from a source function to a sink function in the cross-file call graph. Returns each step with file, function, line number. If a path exists, this is DETERMINISTIC evidence that the source can reach the sink — use this to confirm or refute potential vulnerabilities.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "source_file": {"type": "string", "description": "File containing the source function"},
                    "source_function": {"type": "string", "description": "Source function name (taint entry point)"},
                    "sink_file": {"type": "string", "description": "File containing the sink function"},
                    "sink_function": {"type": "string", "description": "Sink function name (dangerous operation)"}
                },
                "required": ["project_path", "source_file", "source_function", "sink_file", "sink_function"]
            }),
        },
        ToolDefinition {
            name: "resolve_method_call",
            description: "Resolve a method call like db.query(x) to its actual implementation. Uses import aliases, receiver tracking, and type hierarchy. Returns candidate implementations with resolution method and confidence. Essential for distinguishing db.query() from logger.query().",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "file_path": {"type": "string", "description": "File containing the method call"},
                    "line": {"type": "integer", "description": "Line number of the method call"},
                    "receiver": {"type": "string", "description": "Receiver variable name (e.g., 'db' in db.query())"},
                    "method": {"type": "string", "description": "Method name (e.g., 'query' in db.query())"}
                },
                "required": ["project_path", "file_path", "line", "receiver", "method"]
            }),
        },
        ToolDefinition {
            name: "query_type_hierarchy",
            description: "Get the full class inheritance hierarchy from the cross-file analysis. Returns parent classes, child classes, interface implementations, and all methods (including inherited). Use this to understand virtual method dispatch for object-oriented code.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "class_name": {"type": "string", "description": "Class name to query"}
                },
                "required": ["project_path", "class_name"]
            }),
        },
        ToolDefinition {
            name: "query_middleware_chain",
            description: "Get Express app.use() / Django MIDDLEWARE registrations detected by the framework-aware scanner. Shows which middleware functions affect which routes. Use this to find authentication bypass vulnerabilities — if a route is NOT covered by auth middleware, it may be unauthenticated.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "file_path": {"type": "string", "description": "File path to query middleware for (optional — omit for all middleware)"}
                },
                "required": ["project_path"]
            }),
        },
        ToolDefinition {
            name: "trace_variable_flow",
            description: "Trace a tainted source function through the cross-file call graph to find all reachable sinks. Returns each sink with its complete call path, hop count, and vulnerability type. Use this to quickly assess whether an entry point poses a real security risk.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "file_path": {"type": "string", "description": "File containing the source function"},
                    "function_name": {"type": "string", "description": "Source function name (e.g., handleRequest, getUserInput)"}
                },
                "required": ["project_path", "file_path", "function_name"]
            }),
        },
        ToolDefinition {
            name: "get_graph_stats",
            description: "Get cross-file call graph statistics: total function nodes, callback nodes, edges, cross-file edges, taint sources/sinks, file count, type count, and middleware count. Use this first to understand project scale and what the analysis engine has discovered.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"}
                },
                "required": ["project_path"]
            }),
        },
        ToolDefinition {
            name: "list_file_functions",
            description: "List all functions in a file that are indexed in the cross-file call graph. Shows function name, line range, whether it's a taint source/sink/callback, call count, and caller count. Use this to browse file structure and identify analysis targets.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "file_path": {"type": "string", "description": "File path to list functions for"}
                },
                "required": ["project_path", "file_path"]
            }),
        },
        ToolDefinition {
            name: "enclosing_function_at_line",
            description: "Find the innermost function that encloses a given line in a file. Returns function name, line range, node id, and whether it's a taint source/sink/callback. Use this when a finding only has a file and line but no function name — it lets the agent query the call graph with the correct function identifier.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "file_path": {"type": "string", "description": "File path containing the line"},
                    "line": {"type": "integer", "description": "Line number to look up (1-based)"}
                },
                "required": ["project_path", "file_path", "line"]
            }),
        },
        ToolDefinition {
            name: "search_code",
            description: "Search code content across the project using regex patterns. Returns matching files, line numbers, and code snippets. Use this to find where a variable is assigned, who imports a module, or where a function is defined. Prefer this over list_files+read_file when you have a specific pattern to search for.",
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "project_path": {"type": "string", "description": "Project root directory path"},
                    "pattern": {"type": "string", "description": "Regex pattern to search for (e.g. 'password\\\\s*=' or 'import.*axios')"},
                    "file_glob": {"type": "string", "description": "Optional file pattern filter (e.g. '*.java' or '*.{js,ts}')"},
                    "max_results": {"type": "integer", "description": "Maximum results to return (default 50)"}
                },
                "required": ["project_path", "pattern"]
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
        // LLM 自主审计工具
        "get_code_context" => tool_get_code_context(arguments).await,
        "get_project_info" => tool_get_project_info(arguments).await,
        "validate_finding" => tool_validate_finding(arguments).await,
        "list_rules" => tool_list_rules(arguments).await,
        // 审计会话工具（在 handle_request_with_state 中处理）
        // 调用图查询工具
        "query_callers" => tool_query_callers(arguments).await,
        "query_callees" => tool_query_callees(arguments).await,
        "find_call_path" => tool_find_call_path(arguments).await,
        "resolve_method_call" => tool_resolve_method_call(arguments).await,
        "query_type_hierarchy" => tool_query_type_hierarchy(arguments).await,
        "query_middleware_chain" => tool_query_middleware_chain(arguments).await,
        "trace_variable_flow" => tool_trace_variable_flow(arguments).await,
        "get_graph_stats" => tool_get_graph_stats_handler(arguments).await,
        "list_file_functions" => tool_list_file_functions(arguments).await,
        "enclosing_function_at_line" => tool_enclosing_function_at_line(arguments).await,
        "search_code" => tool_search_code(arguments).await,
        _ => serde_json::json!({
            "content": [{"type": "text", "text": format!("Unknown tool: {}", name)}],
            "isError": true
        }),
    }
}

// ── 粗粒度工具实现 ──────────────────────────────────────

/// 严重度排序（数值越小越严重），供 min_severity 过滤复用
fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// 按 CLI scan 同款配置执行扫描（供 security_scan / audit_plan 复用）
///
/// 与 CLI scan 命令使用同一套配置（排除模式、线程、内存预算等），
/// 避免 MCP 使用 core 的保守默认值把 target/ 等目录误排。
async fn run_configured_scan(
    path: &str,
    enable_taint: bool,
    enable_cross_file: bool,
) -> Result<Vec<Finding>, String> {
    let config = ConfigManager::new(None).ok();
    let mut scan_opts = config
        .as_ref()
        .map(|cm| {
            let scan = &cm.config().scan;
            ScanOptions {
                threads: scan.threads,
                max_file_size: scan.max_file_size_mb * 1024 * 1024,
                memory_budget: scan.memory_budget_mb * 1024 * 1024,
                batch_size: scan.batch_size,
                line_tolerance: scan.line_tolerance,
                include_tests: scan.include_tests,
                enable_taint,
                enable_cross_file,
                taint_max_candidate_files: scan.taint_max_candidate_files,
                taint_max_file_kb: scan.taint_max_file_kb,
                cross_file_max_flows: 50000,
                public_route_patterns: scan.public_route_patterns.clone(),
                non_production_path_patterns: scan.non_production_path_patterns.clone(),
            }
        })
        .unwrap_or_else(|| {
            let mut opts = ScanOptions::default();
            opts.enable_taint = enable_taint;
            opts.enable_cross_file = enable_cross_file;
            opts
        });
    scan_opts.enable_taint = enable_taint;
    scan_opts.enable_cross_file = enable_cross_file;

    let exclude_dirs = config
        .as_ref()
        .map(|cm| cm.config().scan.exclude_patterns.clone())
        .filter(|v| !v.is_empty());

    if enable_taint || enable_cross_file {
        scan_directory_deep_with_rules_progress(path, None, exclude_dirs, None, Some(scan_opts), None)
            .await
            .map(|r| r.findings)
    } else {
        scan_directory_with_opts(path, None, exclude_dirs, None, scan_opts, None).await
    }
}

async fn tool_security_scan(args: &Value) -> Value {
    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or(".");
    let deep = args.get("deep").and_then(|v| v.as_bool()).unwrap_or(false);
    let taint_arg = args
        .get("enable_taint")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cross_file_arg = args
        .get("enable_cross_file")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let severity = args
        .get("severity")
        .and_then(|v| v.as_str())
        .map(String::from);
    let pattern = args
        .get("pattern")
        .and_then(|v| v.as_str())
        .map(String::from);
    let file_role_filter = args
        .get("file_role_filter")
        .and_then(|v| v.as_str())
        .map(String::from);
    let min_severity = args
        .get("min_severity")
        .and_then(|v| v.as_str())
        .map(String::from);
    let include_details = args
        .get("include_details")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let enable_taint = taint_arg || deep || cross_file_arg;
    let enable_cross_file = cross_file_arg || deep;

    let result = run_configured_scan(path, enable_taint, enable_cross_file).await;

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
            if let Some(role) = &file_role_filter {
                let role_lower = role.to_lowercase();
                filtered.retain(|f| {
                    f.file_role
                        .as_deref()
                        .unwrap_or("production")
                        .to_lowercase()
                        == role_lower
                });
            }
            if let Some(min_sev) = &min_severity {
                let rank = |s: &str| match s {
                    "critical" => 0,
                    "high" => 1,
                    "medium" => 2,
                    "low" => 3,
                    "info" => 4,
                    _ => 5,
                };
                let min_rank = rank(min_sev);
                filtered.retain(|f| rank(&f.severity.to_lowercase()) <= min_rank);
            }

            let summary = format_security_findings(&filtered);
            let details: Vec<Value> = filtered
                .iter()
                .map(|f| {
                    let mut obj = serde_json::json!({
                        "id": f.finding_id,
                        "severity": f.severity,
                        "vulnerability_type": f.vuln_type,
                        "detector": f.detector,
                        "file": f.file_path,
                        "line": f.line_start,
                        "end_line": f.line_end,
                        "description": f.description,
                    });

                    if let Some(ref role) = f.file_role {
                        obj.as_object_mut()
                            .unwrap()
                            .insert("file_role".into(), serde_json::json!(role));
                    }
                    if let Some(ref barriers) = f.barriers {
                        if !barriers.is_empty() {
                            obj.as_object_mut()
                                .unwrap()
                                .insert("barriers".into(), serde_json::json!(barriers));
                        }
                    }
                    if let Some(ref hint) = f.reasoning_hint {
                        obj.as_object_mut()
                            .unwrap()
                            .insert("reasoning_hint".into(), serde_json::json!(hint));
                    }

                    if include_details {
                        if let Some(ref ctx) = f.code_snippet {
                            obj.as_object_mut()
                                .unwrap()
                                .insert("code_context".into(), serde_json::json!(ctx));
                        }
                        if let Some(ref trail) = f.analysis_trail {
                            if !trail.is_empty() {
                                obj.as_object_mut()
                                    .unwrap()
                                    .insert("taint_chain".into(), serde_json::json!(trail));
                            }
                        }
                        if let Some(ref src) = f.source_snippet {
                            obj.as_object_mut()
                                .unwrap()
                                .insert("source_snippet".into(), serde_json::json!(src));
                        }
                        if let Some(ref snk) = f.sink_snippet {
                            obj.as_object_mut()
                                .unwrap()
                                .insert("sink_snippet".into(), serde_json::json!(snk));
                        }
                        if let Some(conf) = f.confidence {
                            obj.as_object_mut().unwrap().insert(
                                "confidence".into(),
                                serde_json::json!(format!("{:.2}", conf)),
                            );
                        }
                        if let Some(count) = f.corroboration_count {
                            obj.as_object_mut()
                                .unwrap()
                                .insert("corroboration_count".into(), serde_json::json!(count));
                        }
                        if let Some(ref evidence) = f.evidence_refs {
                            obj.as_object_mut().unwrap().insert(
                                "evidence_refs".into(),
                                serde_json::to_value(evidence).unwrap_or_default(),
                            );
                        }
                    }

                    obj
                })
                .collect();

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
        None => {
            return serde_json::json!({
                "content": [{"type": "text", "text": "Missing required parameter: file_path"}],
                "isError": true
            })
        }
    };

    let show_symbols = args
        .get("show_symbols")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let start_line = args
        .get("start_line")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);
    let end_line = args
        .get("end_line")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);

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
                Err(e) => {
                    return serde_json::json!({
                        "content": [{"type": "text", "text": format!("Failed to read file: {}", e)}],
                        "isError": true
                    })
                }
            };

            let mut result = serde_json::Map::new();
            result.insert("file_path".into(), serde_json::json!(file_path));
            result.insert(
                "language".into(),
                serde_json::json!(path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")),
            );
            result.insert(
                "total_lines".into(),
                serde_json::json!(code.lines().count()),
            );

            // Taint analysis
            let mut taint_analyzer = AstTaintAnalyzer::new();
            let flows = taint_analyzer.analyze_file(path, &code);
            if !flows.is_empty() {
                result.insert(
                    "taint_flows".into(),
                    serde_json::json!(flows
                        .iter()
                        .map(|f| serde_json::json!({
                            "id": f.id,
                            "type": format!("{:?}", f.vulnerability_type),
                            "severity": format!("{:?}", f.severity).to_lowercase(),
                            "confidence": f.confidence,
                            "source": {
                                "file": f.source.file_path,
                                "line": f.source.line,
                                "column": f.source.column,
                                "symbol": f.source.symbol,
                                "code": f.source.code_snippet,
                            },
                            "sink": {
                                "file": f.sink.file_path,
                                "line": f.sink.line,
                                "column": f.sink.column,
                                "symbol": f.sink.symbol,
                                "code": f.sink.code_snippet,
                            },
                            "propagation_path": f.path.iter().map(|n| serde_json::json!({
                                "step_type": format!("{:?}", n.node_type).to_lowercase(),
                                "file": n.file_path,
                                "line": n.line,
                                "symbol": n.symbol,
                                "code": n.code_snippet,
                            })).collect::<Vec<_>>(),
                        }))
                        .collect::<Vec<_>>()),
                );
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

            if let Ok(Response::Pong {
                version,
                uptime_secs,
            }) = ping_resp
            {
                info.insert("version".into(), serde_json::json!(version));
                info.insert("uptime_secs".into(), serde_json::json!(uptime_secs));
            }
            if let Ok(Response::StatusInfo {
                pid,
                loaded_projects,
                cache_stats,
                ..
            }) = status_resp
            {
                info.insert("pid".into(), serde_json::json!(pid));
                info.insert("projects".into(), serde_json::json!(loaded_projects));
                info.insert(
                    "cache".into(),
                    serde_json::json!({
                        "ast": cache_stats.ast_cache_entries,
                        "scan": cache_stats.scan_cache_entries,
                    }),
                );
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
        flows.retain(|f| {
            f.source.symbol.contains(src)
                || f.source.symbol.to_lowercase().contains(&src.to_lowercase())
        });
    }
    if let Some(snk) = sink_filter {
        flows.retain(|f| {
            f.sink.symbol.contains(snk)
                || f.sink.symbol.to_lowercase().contains(&snk.to_lowercase())
        });
    }

    if flows.is_empty() {
        return text_response("No taint flows found matching the criteria.");
    }

    let details: Vec<Value> = flows
        .iter()
        .map(|f| {
            let path_steps: Vec<Value> = f
                .path
                .iter()
                .map(|node| {
                    serde_json::json!({
                        "type": format!("{:?}", node.node_type),
                        "line": node.line,
                        "symbol": node.symbol,
                        "code_snippet": node.code_snippet,
                    })
                })
                .collect();

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
        })
        .collect();

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
    let definitions: Vec<Value> = assignments
        .iter()
        .filter(|a| a.target == variable || a.target.contains(variable))
        .map(|a| {
            serde_json::json!({
                "line": a.line,
                "target": a.target,
                "source_expr": a.source_expr,
                "source_vars": a.source_vars,
            })
        })
        .collect();

    // Find uses (where the variable is referenced in calls)
    let uses: Vec<Value> = calls
        .iter()
        .filter(|c| {
            c.arguments
                .iter()
                .any(|arg| arg.referenced_vars.contains(&variable.to_string()))
        })
        .map(|c| {
            serde_json::json!({
                "line": c.line,
                "callee": c.callee,
                "arguments": c.arguments.iter().map(|a| &a.text).collect::<Vec<_>>(),
            })
        })
        .collect();

    // Find uses in assignments (where variable is in source_vars)
    let propagated_to: Vec<Value> = assignments
        .iter()
        .filter(|a| a.source_vars.contains(&variable.to_string()) && a.target != variable)
        .map(|a| {
            serde_json::json!({
                "line": a.line,
                "target": a.target,
                "source_expr": a.source_expr,
            })
        })
        .collect();

    // Check if variable is tainted
    let mut taint_analyzer = AstTaintAnalyzer::new();
    let flows = taint_analyzer.analyze_file(path, &code);
    let taint_status: Vec<Value> = flows
        .iter()
        .filter(|f| f.source.symbol == variable || f.path.iter().any(|n| n.symbol == variable))
        .map(|f| {
            serde_json::json!({
                "is_tainted": true,
                "source": f.source.symbol,
                "sink": f.sink.symbol,
                "vulnerability_type": format!("{:?}", f.vulnerability_type),
                "confidence": f.confidence,
            })
        })
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
    let matches: Vec<Value> = analyzer
        .sanitizer_patterns()
        .iter()
        .filter(|p| func_name.contains(p.as_str()))
        .map(|p| {
            serde_json::json!({
                "matched_pattern": p,
                "function_name": func_name,
            })
        })
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

    let nodes: Vec<Value> = result
        .call_graph
        .nodes
        .values()
        .take(100) // Limit output
        .map(|n| {
            serde_json::json!({
                "id": n.id,
                "name": n.name,
                "file": n.file_path,
                "line": n.start_line,
                "calls_count": n.calls.len(),
                "called_by_count": n.called_by.len(),
                "is_taint_source": n.is_taint_source,
                "is_taint_sink": n.is_taint_sink,
            })
        })
        .collect();

    let edges: Vec<Value> = result
        .call_graph
        .nodes
        .values()
        .flat_map(|n| {
            n.calls.iter().map(move |c| {
                serde_json::json!({
                    "caller": n.id,
                    "callee": c,
                })
            })
        })
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

// ── LLM 自主审计工具实现 ────────────────────────────────

async fn tool_get_code_context(args: &Value) -> Value {
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

    let lines: Vec<&str> = code.lines().collect();
    let total_lines = lines.len();

    let (start, end) = if let (Some(s), Some(e)) = (
        args.get("start_line").and_then(|v| v.as_u64()),
        args.get("end_line").and_then(|v| v.as_u64()),
    ) {
        (s as usize, e as usize)
    } else {
        let center = args.get("line").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
        let ctx = args
            .get("context_lines")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;
        (center.saturating_sub(ctx), (center + ctx).min(total_lines))
    };

    let start = start.max(1);
    let end = end.min(total_lines);
    let center_line = args
        .get("line")
        .and_then(|v| v.as_u64())
        .map(|l| l as usize);

    let mut code_output = String::new();
    for i in start..=end {
        let marker = if center_line == Some(i) { ">> " } else { "   " };
        code_output.push_str(&format!("{}{:>4} | {}\n", marker, i, lines[i - 1]));
    }

    let result = serde_json::json!({
        "file_path": file_path,
        "total_lines": total_lines,
        "shown_range": format!("{}-{}", start, end),
        "center_line": center_line,
        "language": path.extension().and_then(|e| e.to_str()).unwrap_or("unknown"),
        "code": code_output,
    });

    text_response(&serde_json::to_string_pretty(&result).unwrap_or_default())
}

async fn tool_get_project_info(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing required parameter: project_path"),
    };

    let path = std::path::Path::new(project_path);
    if !path.exists() {
        return error_response(&format!("Project path not found: {}", project_path));
    }

    // 语言检测
    let lang_extensions: HashMap<&str, &str> = [
        (".py", "Python"),
        (".js", "JavaScript"),
        (".ts", "TypeScript"),
        (".tsx", "TypeScript (JSX)"),
        (".jsx", "JavaScript (JSX)"),
        (".java", "Java"),
        (".rs", "Rust"),
        (".go", "Go"),
        (".c", "C"),
        (".cpp", "C++"),
        (".h", "C/C++ Header"),
        (".php", "PHP"),
        (".rb", "Ruby"),
        (".cs", "C#"),
        (".kt", "Kotlin"),
        (".swift", "Swift"),
        (".scala", "Scala"),
        (".vue", "Vue"),
        (".html", "HTML"),
    ]
    .iter()
    .cloned()
    .collect();

    let mut language_counts: HashMap<String, usize> = HashMap::new();
    let mut total_source_files = 0usize;
    let mut top_dirs: HashMap<String, usize> = HashMap::new();

    let ignore_dirs = [
        "node_modules",
        ".git",
        "target",
        "build",
        "dist",
        "vendor",
        "__pycache__",
        ".gradle",
        ".idea",
        ".vscode",
        ".cache",
        ".next",
    ];

    for entry in ignore::WalkBuilder::new(path).hidden(false).build() {
        if let Ok(entry) = entry {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    let ext_with_dot = format!(".{}", ext);
                    if let Some(&lang) = lang_extensions.get(ext_with_dot.as_str()) {
                        *language_counts.entry(lang.to_string()).or_insert(0) += 1;
                        total_source_files += 1;
                    }
                }
                // Top-level directory tracking
                if let Ok(relative) = p.strip_prefix(path) {
                    if let Some(comp) = relative.components().next() {
                        let dir = comp.as_os_str().to_string_lossy().to_string();
                        if !ignore_dirs.contains(&dir.as_str()) {
                            *top_dirs.entry(dir).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    // 排序语言
    let mut languages: Vec<(String, usize)> = language_counts.into_iter().collect();
    languages.sort_by(|a, b| b.1.cmp(&a.1));

    // 排序目录
    let mut dirs: Vec<(String, usize)> = top_dirs.into_iter().collect();
    dirs.sort_by(|a, b| b.1.cmp(&a.1));
    dirs.truncate(15);

    // 框架检测
    let surface = AttackSurfaceMapper::map_project(path);
    let frameworks = surface.stats.detected_frameworks;

    // 包管理器检测
    let mut package_managers = Vec::new();
    if path.join("package.json").exists() {
        package_managers.push("npm".to_string());
    }
    if path.join("yarn.lock").exists() {
        package_managers.push("yarn".to_string());
    }
    if path.join("pnpm-lock.yaml").exists() {
        package_managers.push("pnpm".to_string());
    }
    if path.join("requirements.txt").exists() || path.join("Pipfile").exists() {
        package_managers.push("pip".to_string());
    }
    if path.join("Cargo.toml").exists() {
        package_managers.push("cargo".to_string());
    }
    if path.join("go.sum").exists() {
        package_managers.push("go modules".to_string());
    }
    if path.join("pom.xml").exists() {
        package_managers.push("maven".to_string());
    }
    if path.join("build.gradle").exists() {
        package_managers.push("gradle".to_string());
    }

    let top_langs = languages
        .iter()
        .take(3)
        .map(|(l, _)| l.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let frameworks_str = if frameworks.is_empty() {
        "none detected".to_string()
    } else {
        frameworks.join(", ")
    };

    let result = serde_json::json!({
        "project_path": project_path,
        "total_source_files": total_source_files,
        "languages": languages.into_iter().map(|(lang, count)| serde_json::json!({
            "language": lang,
            "file_count": count,
        })).collect::<Vec<_>>(),
        "frameworks": frameworks,
        "package_managers": package_managers,
        "directory_structure": dirs.into_iter().map(|(dir, count)| serde_json::json!({
            "directory": dir,
            "file_count": count,
        })).collect::<Vec<_>>(),
        "entry_points": {
            "total": surface.stats.total_entry_points,
            "unauthenticated": surface.stats.unauthenticated_count,
        },
    });

    let summary = format!(
        "Project: {} | {} source files | Languages: {} | Frameworks: {} | Entry points: {} ({} unauthenticated)",
        project_path,
        total_source_files,
        top_langs,
        frameworks_str,
        surface.stats.total_entry_points,
        surface.stats.unauthenticated_count,
    );

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default()}
        ]
    })
}

async fn tool_validate_finding(args: &Value) -> Value {
    let finding_id = match args.get("finding_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return error_response("Missing required parameter: finding_id"),
    };
    let verdict = match args.get("verdict").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return error_response("Missing required parameter: verdict"),
    };
    let reasoning = match args.get("reasoning").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => return error_response("Missing required parameter: reasoning"),
    };

    // 验证 verdict
    if !["true_positive", "false_positive", "needs_review"].contains(&verdict) {
        return error_response(&format!(
            "Invalid verdict: '{}'. Must be true_positive, false_positive, or needs_review",
            verdict
        ));
    }

    let file_path = args
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let line = args.get("line").and_then(|v| v.as_u64()).unwrap_or(0);
    let vuln_type = args
        .get("vulnerability_type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let severity_override = args.get("severity_override").and_then(|v| v.as_str());

    // 写入审计日志
    let audit_dir = std::path::Path::new(".ctx-audit");
    if let Err(e) = std::fs::create_dir_all(audit_dir) {
        return error_response(&format!("Failed to create .ctx-audit directory: {}", e));
    }

    // 审计日志
    let audit_log_path = audit_dir.join("audit_log.json");
    let mut audit_log: Vec<Value> = if audit_log_path.exists() {
        std::fs::read_to_string(&audit_log_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let entry = serde_json::json!({
        "finding_id": finding_id,
        "file_path": file_path,
        "line": line,
        "vulnerability_type": vuln_type,
        "verdict": verdict,
        "reasoning": reasoning,
        "severity_override": severity_override,
        "audited_at": chrono::Utc::now().to_rfc3339(),
    });

    audit_log.push(entry);

    if let Err(e) = std::fs::write(
        &audit_log_path,
        serde_json::to_string_pretty(&audit_log).unwrap_or_default(),
    ) {
        return error_response(&format!("Failed to write audit log: {}", e));
    }

    // 如果是 false_positive，同时写入 baseline.json 用于后续扫描抑制
    if verdict == "false_positive" {
        let baseline_path = audit_dir.join("baseline.json");
        let mut baseline: serde_json::Map<String, Value> = if baseline_path.exists() {
            std::fs::read_to_string(&baseline_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            let mut map = serde_json::Map::new();
            map.insert("ignored".into(), serde_json::json!({}));
            map
        };

        let key = format!("{}:{}:{}", file_path, line, vuln_type);
        if let Some(ignored) = baseline.get_mut("ignored").and_then(|v| v.as_object_mut()) {
            ignored.insert(key, serde_json::json!(reasoning));
        }

        if let Err(e) = std::fs::write(
            &baseline_path,
            serde_json::to_string_pretty(&baseline).unwrap_or_default(),
        ) {
            return error_response(&format!("Failed to write baseline: {}", e));
        }
    }

    let verdict_label = match verdict {
        "true_positive" => "TRUE POSITIVE",
        "false_positive" => "FALSE POSITIVE",
        "needs_review" => "NEEDS REVIEW",
        _ => verdict,
    };

    text_response(&format!(
        "Finding {} recorded as {}. {}Entry written to .ctx-audit/audit_log.json{}",
        finding_id,
        verdict_label,
        if severity_override.is_some() {
            format!("Severity overridden to {}. ", severity_override.unwrap())
        } else {
            String::new()
        },
        if verdict == "false_positive" {
            " and .ctx-audit/baseline.json (future scans will suppress this finding)"
        } else {
            ""
        }
    ))
}

async fn tool_list_rules(args: &Value) -> Value {
    let category_filter = args.get("category").and_then(|v| v.as_str());
    let language_filter = args.get("language").and_then(|v| v.as_str());

    let mut all_rules: Vec<Value> = Vec::new();

    // 加载内置规则
    let rules_dirs = [
        std::path::Path::new("rules"),
        std::path::Path::new(".ctx-audit/rules"),
    ];

    for rules_dir in &rules_dirs {
        if !rules_dir.exists() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(rules_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext != "yaml" && ext != "yml" {
                        continue;
                    }
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        // 尝试解析为 RuleSet
                        if let Ok(rs) = serde_yaml::from_str::<RuleSet>(&content) {
                            for rule in &rs.rules {
                                let matches_filter = {
                                    let cat_ok = category_filter.map_or(true, |cf| {
                                        rule.category.as_deref().map_or(false, |c| {
                                            c.to_lowercase().contains(&cf.to_lowercase())
                                        })
                                    });
                                    let lang_ok = language_filter.map_or(true, |lf| {
                                        rule.language.to_lowercase().contains(&lf.to_lowercase())
                                            || rule.language == "all"
                                    });
                                    cat_ok && lang_ok
                                };
                                if matches_filter {
                                    all_rules.push(serde_json::json!({
                                        "id": rule.id,
                                        "name": rule.name,
                                        "severity": format!("{:?}", rule.severity).to_lowercase(),
                                        "language": rule.language,
                                        "category": rule.category,
                                        "cwe": rule.cwe,
                                        "owasp": rule.owasp,
                                        "source": format!("{} ({})", p.display(), rs.name),
                                    }));
                                }
                            }
                        }
                        // 尝试解析为单个 Rule
                        else if let Ok(rule) = serde_yaml::from_str::<Rule>(&content) {
                            let matches_filter = {
                                let cat_ok = category_filter.map_or(true, |cf| {
                                    rule.category.as_deref().map_or(false, |c| {
                                        c.to_lowercase().contains(&cf.to_lowercase())
                                    })
                                });
                                let lang_ok = language_filter.map_or(true, |lf| {
                                    rule.language.to_lowercase().contains(&lf.to_lowercase())
                                        || rule.language == "all"
                                });
                                cat_ok && lang_ok
                            };
                            if matches_filter {
                                all_rules.push(serde_json::json!({
                                    "id": rule.id,
                                    "name": rule.name,
                                    "severity": format!("{:?}", rule.severity).to_lowercase(),
                                    "language": rule.language,
                                    "category": rule.category,
                                    "cwe": rule.cwe,
                                    "owasp": rule.owasp,
                                    "source": p.display().to_string(),
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // 加载 taint 规则（简要信息）
    let taint_dir = std::path::Path::new("rules/taint");
    if taint_dir.exists() {
        fn visit_taint_yaml(
            dir: &std::path::Path,
            rules: &mut Vec<Value>,
            cat_filter: Option<&str>,
            lang_filter: Option<&str>,
        ) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        visit_taint_yaml(&p, rules, cat_filter, lang_filter);
                    } else if p.is_file() {
                        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                        if ext != "yaml" && ext != "yml" {
                            continue;
                        }
                        if let Ok(content) = std::fs::read_to_string(&p) {
                            if let Ok(ts) = serde_yaml::from_str::<TaintRuleSet>(&content) {
                                rules.push(serde_json::json!({
                                    "id": format!("taint:{}", ts.name.to_lowercase().replace(' ', "-")),
                                    "name": ts.name,
                                    "severity": "variable",
                                    "language": "multi",
                                    "category": "taint-rules",
                                    "type": "taint",
                                    "sources_count": ts.sources.len(),
                                    "sinks_count": ts.sinks.len(),
                                    "sanitizers_count": ts.sanitizers.len(),
                                    "source": p.display().to_string(),
                                }));
                            }
                        }
                    }
                }
            }
        }
        visit_taint_yaml(taint_dir, &mut all_rules, category_filter, language_filter);
    } else {
        // 文件系统目录缺失（如在仓库外运行），回退到内置嵌入规则
        for content in deepaudit_core::rules::embedded::embedded_taint_yaml_contents() {
            if let Ok(ts) = serde_yaml::from_str::<TaintRuleSet>(&content) {
                all_rules.push(serde_json::json!({
                    "id": format!("taint:{}", ts.name.to_lowercase().replace(' ', "-")),
                    "name": ts.name,
                    "severity": "variable",
                    "language": "multi",
                    "category": "taint-rules",
                    "type": "taint",
                    "sources_count": ts.sources.len(),
                    "sinks_count": ts.sinks.len(),
                    "sanitizers_count": ts.sanitizers.len(),
                    "source": "embedded",
                }));
            }
        }
    }

    let summary = format!(
        "Loaded {} rule(s){}{}.",
        all_rules.len(),
        category_filter
            .map(|c| format!(" (category: {})", c))
            .unwrap_or_default(),
        language_filter
            .map(|l| format!(" (language: {})", l))
            .unwrap_or_default(),
    );

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&all_rules).unwrap_or_default()}
        ]
    })
}

// ── Daemon helpers ──────────────────────────────────────

async fn try_daemon_analyze(
    file_path: &str,
    start_line: Option<usize>,
    end_line: Option<usize>,
    show_symbols: bool,
) -> Option<serde_json::Map<String, Value>> {
    let mut client = DaemonClient::connect().await.ok()?;
    let response = client
        .send_request(RequestCommand::Analyze {
            file_path: file_path.to_string(),
            start_line,
            end_line,
            show_ast: false,
            show_symbols,
        })
        .await
        .ok()?;

    match response {
        Response::AnalysisResult { content } => {
            if let Value::Object(map) = content {
                Some(map)
            } else {
                None
            }
        }
        _ => None,
    }
}

async fn try_daemon_cross_file(project_path: &str) -> Option<Value> {
    let mut client = DaemonClient::connect().await.ok()?;
    let response = client
        .send_request(RequestCommand::CrossFileAnalysis {
            path: project_path.to_string(),
        })
        .await
        .ok()?;

    match response {
        Response::CrossFileTaintResult { result } => Some(text_response(
            &serde_json::to_string_pretty(&result).unwrap_or_default(),
        )),
        _ => None,
    }
}

async fn try_daemon_call_graph(project_path: &str, entry: &str, depth: usize) -> Option<Value> {
    let mut client = DaemonClient::connect().await.ok()?;

    // Try to load project first
    let _ = client
        .send_request(RequestCommand::LoadProject {
            path: project_path.to_string(),
        })
        .await;

    let response = client
        .send_request(RequestCommand::GetCallGraph {
            entry: entry.to_string(),
            depth: Some(depth),
        })
        .await
        .ok()?;

    match response {
        Response::CallGraphResult { graph } => Some(text_response(
            &serde_json::to_string_pretty(&graph).unwrap_or_default(),
        )),
        _ => None,
    }
}

/// Load sanitizer descriptions from YAML taint rules
fn get_sanitizer_descriptions() -> Vec<(String, String)> {
    let yaml_dir = std::path::Path::new("rules/taint");
    if !yaml_dir.exists() {
        // 文件系统目录缺失（如在仓库外运行），回退到内置嵌入规则
        let mut descriptions = Vec::new();
        for content in deepaudit_core::rules::embedded::embedded_taint_yaml_contents() {
            if let Ok(rule_set) = serde_yaml::from_str::<TaintRuleSet>(&content) {
                for san in &rule_set.sanitizers {
                    descriptions.push((san.pattern.clone(), san.description.clone()));
                }
            }
        }
        return descriptions;
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

// ── 调用图查询工具实现 ──────────────────────────────────

fn build_query_engine_for_mcp(
    project_path: &str,
) -> Result<deepaudit_core::CallGraphQueryEngine, String> {
    let path = std::path::Path::new(project_path);
    if !path.exists() {
        return Err(format!("Project path not found: {}", project_path));
    }
    let mut analyzer = deepaudit_core::CrossFileTaintAnalyzer::new();
    let result = analyzer.analyze_project(path);
    Ok(deepaudit_core::CallGraphQueryEngine::from_result(&result))
}

async fn tool_query_callers(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing file_path"),
    };
    let function_name = match args.get("function_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return error_response("Missing function_name"),
    };
    let recursive = args
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    let callers = if recursive {
        engine.query_all_callers(file_path, function_name)
    } else {
        engine.query_callers(file_path, function_name)
    };

    let text = if callers.is_empty() {
        format!("No callers found for '{}' in {}", function_name, file_path)
    } else {
        format!(
            "Found {} caller(s) for '{}'{}",
            callers.len(),
            function_name,
            if recursive { " (recursive)" } else { "" }
        )
    };

    serde_json::json!({
        "content": [
            {"type": "text", "text": text},
            {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                "target": {"file": file_path, "function": function_name},
                "count": callers.len(),
                "recursive": recursive,
                "callers": callers,
            })).unwrap_or_default()}
        ]
    })
}

async fn tool_query_callees(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing file_path"),
    };
    let function_name = match args.get("function_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return error_response("Missing function_name"),
    };
    let recursive = args
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    let callees = if recursive {
        engine.query_all_callees(file_path, function_name)
    } else {
        engine.query_callees(file_path, function_name)
    };

    let text = if callees.is_empty() {
        format!(
            "'{}' in {} calls no known functions",
            function_name, file_path
        )
    } else {
        format!(
            "'{}' calls {} function(s){}",
            function_name,
            callees.len(),
            if recursive { " (recursive)" } else { "" }
        )
    };

    serde_json::json!({
        "content": [
            {"type": "text", "text": text},
            {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                "source": {"file": file_path, "function": function_name},
                "count": callees.len(),
                "recursive": recursive,
                "callees": callees,
            })).unwrap_or_default()}
        ]
    })
}

async fn tool_find_call_path(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let source_file = match args.get("source_file").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing source_file"),
    };
    let source_function = match args.get("source_function").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return error_response("Missing source_function"),
    };
    let sink_file = match args.get("sink_file").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing sink_file"),
    };
    let sink_function = match args.get("sink_function").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return error_response("Missing sink_function"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    let result = engine.find_call_path(source_file, source_function, sink_file, sink_function);

    match result {
        Some(path) => {
            let text = if path.crosses_files {
                format!(
                    "PATH FOUND: {} hops across {} files",
                    path.total_hops,
                    path.files_in_path.len()
                )
            } else {
                format!("PATH FOUND: {} hops (same file)", path.total_hops)
            };

            serde_json::json!({
                "content": [
                    {"type": "text", "text": text},
                    {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                        "path_exists": true,
                        "total_hops": path.total_hops,
                        "crosses_files": path.crosses_files,
                        "files_in_path": path.files_in_path,
                        "steps": path.steps,
                    })).unwrap_or_default()}
                ]
            })
        }
        None => {
            serde_json::json!({
                "content": [{"type": "text", "text": format!(
                    "NO PATH: '{}' ({}) cannot reach '{}' ({})",
                    source_function, source_file, sink_function, sink_file
                )}]
            })
        }
    }
}

async fn tool_resolve_method_call(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing file_path"),
    };
    let line = match args.get("line").and_then(|v| v.as_u64()) {
        Some(l) => l as usize,
        None => return error_response("Missing line"),
    };
    let receiver = match args.get("receiver").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => return error_response("Missing receiver"),
    };
    let method = match args.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => return error_response("Missing method"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    let targets = engine.resolve_method_call(file_path, line, receiver, method);

    if targets.is_empty() {
        text_response(&format!(
            "No resolved targets for {}.{}() at {}:{}",
            receiver, method, file_path, line
        ))
    } else {
        let best = &targets[0];
        let text = format!(
            "Found {} candidate(s) for {}.{}() — best: {} ({}:{} confidence {:.0}%) via {}",
            targets.len(),
            receiver,
            method,
            best.function_name,
            best.file_path,
            best.line,
            best.confidence * 100.0,
            best.resolution_method
        );

        serde_json::json!({
            "content": [
                {"type": "text", "text": text},
                {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                    "call": {"receiver": receiver, "method": method, "file": file_path, "line": line},
                    "candidates": targets,
                    "best_match": targets.first(),
                })).unwrap_or_default()}
            ]
        })
    }
}

async fn tool_query_type_hierarchy(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let class_name = match args.get("class_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return error_response("Missing class_name"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    match engine.query_type_chain(class_name) {
        Some(chain) => {
            let text = format!(
                "{} ({}) — {} parents, {} children, {} methods",
                chain.class_name,
                chain.kind,
                chain.parent_classes.len(),
                chain.child_classes.len(),
                chain.methods.len(),
            );
            serde_json::json!({
                "content": [
                    {"type": "text", "text": text},
                    {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!(chain)).unwrap_or_default()}
                ]
            })
        }
        None => text_response(&format!("Type '{}' not found in hierarchy", class_name)),
    }
}

async fn tool_query_middleware_chain(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    if let Some(file_path) = args.get("file_path").and_then(|v| v.as_str()) {
        let mw = engine.query_middleware_for_file(file_path);
        let routes = engine.query_routes_in_file(file_path);
        let text = format!(
            "File '{}': {} middleware, {} routes",
            file_path,
            mw.len(),
            routes.len()
        );
        serde_json::json!({
            "content": [
                {"type": "text", "text": text},
                {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                    "file_path": file_path, "middleware": mw, "routes": routes,
                })).unwrap_or_default()}
            ]
        })
    } else {
        let all = engine.query_all_middleware();
        let text = format!("Total: {} middleware registrations", all.len());
        serde_json::json!({
            "content": [
                {"type": "text", "text": text},
                {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                    "all_middleware": all, "count": all.len(),
                })).unwrap_or_default()}
            ]
        })
    }
}

async fn tool_trace_variable_flow(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing file_path"),
    };
    let function_name = match args.get("function_name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return error_response("Missing function_name"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    let flow = engine.trace_variable_flow(file_path, function_name);

    let text = if flow.total_sinks_reached > 0 {
        format!(
            "'{}' reaches {} sink(s): {}",
            function_name,
            flow.total_sinks_reached,
            flow.flows_to_sinks
                .iter()
                .map(|f| format!("{}({})", f.sink_function, f.vulnerability_type))
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!("'{}' reaches no sinks", function_name)
    };

    serde_json::json!({
        "content": [
            {"type": "text", "text": text},
            {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                "source": {"function": flow.source_function, "file": flow.source_file, "line": flow.source_line},
                "total_sinks_reached": flow.total_sinks_reached,
                "flows_to_sinks": flow.flows_to_sinks,
            })).unwrap_or_default()}
        ]
    })
}

async fn tool_get_graph_stats_handler(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    let stats = engine.query_graph_stats();
    let text = format!(
        "Call Graph: {} nodes ({} callbacks), {} edges ({} cross-file), {} sources, {} sinks, {} files, {} types, {} middleware",
        stats.total_nodes, stats.callback_nodes, stats.total_edges, stats.cross_file_edges,
        stats.taint_sources, stats.taint_sinks, stats.total_files, stats.type_count, stats.middleware_count,
    );

    text_response(&serde_json::to_string_pretty(&serde_json::json!(stats)).unwrap_or_default())
}

async fn tool_list_file_functions(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing file_path"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    let functions = engine.query_functions_in_file(file_path);

    if functions.is_empty() {
        return text_response(&format!("No indexed functions in '{}'", file_path));
    }

    let sources: Vec<_> = functions.iter().filter(|f| f.is_source).collect();
    let sinks: Vec<_> = functions.iter().filter(|f| f.is_sink).collect();
    let cbs: Vec<_> = functions.iter().filter(|f| f.is_callback).collect();

    let text = format!(
        "{} functions in '{}': {} sources, {} sinks, {} callbacks",
        functions.len(),
        file_path,
        sources.len(),
        sinks.len(),
        cbs.len(),
    );

    serde_json::json!({
        "content": [
            {"type": "text", "text": text},
            {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                "file_path": file_path,
                "total": functions.len(),
                "functions": functions,
            })).unwrap_or_default()}
        ]
    })
}

async fn tool_search_code(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let pattern = match args.get("pattern").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing pattern"),
    };
    let file_glob = args.get("file_glob").and_then(|v| v.as_str());
    let max_results = args
        .get("max_results")
        .and_then(|v| v.as_u64())
        .unwrap_or(50) as usize;

    let re = match regex::Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => return error_response(&format!("Invalid regex: {}", e)),
    };

    let mut results: Vec<serde_json::Value> = Vec::new();
    let project = std::path::Path::new(project_path);

    // Walk project directory, respecting common exclusions
    let exclude_dirs: &[&str] = &[
        ".git", "target", "node_modules", "build", "dist", ".ctx-audit",
        "__pycache__", ".gradle", ".idea", ".vscode", "vendor",
    ];

    fn walk(
        dir: &std::path::Path,
        project: &std::path::Path,
        re: &regex::Regex,
        file_glob: Option<&str>,
        exclude_dirs: &[&str],
        results: &mut Vec<serde_json::Value>,
        max_results: usize,
    ) {
        if results.len() >= max_results {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            if results.len() >= max_results {
                return;
            }
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if name.starts_with('.') || exclude_dirs.contains(&name) {
                    continue;
                }
                walk(&path, project, re, file_glob, exclude_dirs, results, max_results);
            } else if path.is_file() {
                if let Some(glob) = file_glob {
                    if !glob_match_simple(glob, name) {
                        continue;
                    }
                }
                // Skip binary/large files
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let skip_exts = &[
                    "png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2",
                    "ttf", "eot", "pdf", "zip", "tar", "gz", "jar", "class",
                    "exe", "dll", "so", "dylib", "bin", "mp4", "mp3", "wav",
                ];
                if skip_exts.contains(&ext) {
                    continue;
                }
                let content = match std::fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                for (line_no, line) in content.lines().enumerate() {
                    if results.len() >= max_results {
                        return;
                    }
                    if re.is_match(line) {
                        let rel = path
                            .strip_prefix(project)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .to_string();
                        results.push(serde_json::json!({
                            "file": rel,
                            "line": line_no + 1,
                            "content": line.trim(),
                        }));
                    }
                }
            }
        }
    }

    walk(
        project,
        project,
        &re,
        file_glob,
        exclude_dirs,
        &mut results,
        max_results,
    );

    if results.is_empty() {
        text_response(&format!(
            "No matches found for pattern '{}' in {}",
            pattern, project_path
        ))
    } else {
        let count = results.len();
        let output = results
            .iter()
            .map(|r| {
                format!(
                    "{}:{}: {}",
                    r["file"].as_str().unwrap_or(""),
                    r["line"].as_u64().unwrap_or(0),
                    r["content"].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        serde_json::json!({
            "content": [
                {"type": "text", "text": format!("{} matches (showing up to {}):\n{}", count, max_results, output)},
                {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                    "total_matches": count,
                    "results": results,
                })).unwrap_or_default()}
            ]
        })
    }
}

/// Simple glob match for file names (supports *.ext and *.{ext1,ext2} patterns)
fn glob_match_simple(pattern: &str, name: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let name = name.to_lowercase();
    // Handle *.{ext1,ext2} pattern
    if let Some(braces) = pattern.strip_prefix("*.{") {
        if let Some(inner) = braces.strip_suffix('}') {
            let exts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
            return exts.iter().any(|e| name.ends_with(&format!(".{}", e)));
        }
    }
    // Handle *.ext pattern
    if let Some(ext) = pattern.strip_prefix("*.") {
        return name.ends_with(&format!(".{}", ext));
    }
    // Fallback: substring match
    name.contains(&pattern)
}

async fn tool_enclosing_function_at_line(args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing project_path"),
    };
    let file_path = match args.get("file_path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return error_response("Missing file_path"),
    };
    let line = match args.get("line").and_then(|v| v.as_u64()) {
        Some(n) if n >= 1 => n as usize,
        _ => return error_response("Missing or invalid line (must be >= 1)"),
    };

    let engine = match build_query_engine_for_mcp(project_path) {
        Ok(e) => e,
        Err(e) => return error_response(&e),
    };

    match engine.query_enclosing_function(file_path, line) {
        Some(func) => serde_json::json!({
            "content": [
                {"type": "text", "text": format!(
                    "Function enclosing {}:{} is '{}' (lines {}-{})",
                    file_path, line, func.name, func.line, func.end_line
                )},
                {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                    "file_path": file_path,
                    "line": line,
                    "function": func,
                })).unwrap_or_default()}
            ]
        }),
        None => text_response(&format!(
            "No indexed function encloses {}:{}. The file may not be parsed or the line is outside any function.",
            file_path, line
        )),
    }
}

// ── 审计会话工具实现 ──────────────────────────────────────

async fn tool_start_audit_session_with_state(state: &McpServerState, args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return error_response("Missing required parameter: project_path"),
    };
    let session_type = args
        .get("session_type")
        .and_then(|v| v.as_str())
        .unwrap_or("targeted")
        .to_string();

    let session_uuid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let ctx = SessionContext {
        session_uuid: session_uuid.clone(),
        project_path: project_path.clone(),
        session_type: session_type.clone(),
        started_at: now.clone(),
        groups: Vec::new(),
    };

    // 持久化到磁盘，进程重启后可恢复
    persist_session(&ctx);

    state
        .audit
        .active_sessions
        .borrow_mut()
        .insert(session_uuid.clone(), ctx);

    let summary = format!(
        "🔍 Audit session started\n  Session: {}\n  Project: {}\n  Type: {}\n  Time: {}\n\nNext: run security_scan or cross_file_analysis to get findings, then use start_investigation to drill down.",
        session_uuid, project_path, session_type, now
    );

    serde_json::json!({
        "content": [{"type": "text", "text": summary}],
        "data": {
            "session_uuid": session_uuid,
            "project_path": project_path,
            "session_type": session_type,
            "started_at": now,
        }
    })
}

async fn tool_start_investigation_with_state(state: &McpServerState, args: &Value) -> Value {
    let session_uuid = match args.get("session_uuid").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: session_uuid"),
    };
    let finding_id = match args.get("finding_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: finding_id"),
    };
    let finding_file = args.get("finding_file").and_then(|v| v.as_str());
    let finding_line = args
        .get("finding_line")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);
    let hypothesis = args
        .get("hypothesis")
        .and_then(|v| v.as_str())
        .map(String::from);
    let vuln_type_arg = args.get("vuln_type").and_then(|v| v.as_str());

    // 检查会话是否存在（内存未命中时从磁盘加载）
    let session = match get_or_load_session(state, &session_uuid) {
        Some(s) => s,
        None => {
            return error_response(&format!(
                "Session not found: {}. Use start_audit_session first.",
                session_uuid
            ))
        }
    };
    let project_path = session.project_path.clone();

    // 确定漏洞类型：优先显式参数，其次从会话分组中按 finding_id 反查
    let vuln_type = vuln_type_arg
        .map(String::from)
        .or_else(|| vuln_type_of_finding(&session, &finding_id).map(String::from));

    // 匹配证据包（匹配不到回退 generic 兜底包）
    let packs = load_audit_packs();
    let pack = vuln_type
        .as_deref()
        .and_then(|vt| find_pack(&packs, vt, None))
        .or_else(|| generic_pack(&packs));

    // 用证据包的取证步骤构建建议工具调用，注入 finding 的 file/line
    let suggested_tools: Vec<serde_json::Value> = match pack {
        Some(p) => p
            .evidence_steps
            .iter()
            .map(|step| {
                serde_json::json!({
                    "tool": step.tool,
                    "params": evidence_step_params(&step.tool, &project_path, finding_file, finding_line),
                    "purpose": step.purpose,
                })
            })
            .collect(),
        None => Vec::new(),
    };

    let investigation_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let ctx = InvestigationContext {
        investigation_id: investigation_id.clone(),
        session_uuid: session_uuid.clone(),
        finding_id: finding_id.clone(),
        hypothesis,
        steps: Vec::new(),
        started_at: now.clone(),
    };

    state
        .audit
        .active_investigations
        .borrow_mut()
        .insert(investigation_id.clone(), ctx.clone());
    // 持久化调查，MCP 进程重启后 log/conclude 仍可继续
    persist_investigation(&ctx);

    let pack_summary = match pack {
        Some(p) => format!("  Evidence pack: {} ({})\n", p.id, p.name),
        None => String::new(),
    };
    let summary = format!(
        "🕵️ Investigation started\n  ID: {}\n  Finding: {}\n  Session: {}\n{}  Time: {}\n\nFollow the evidence steps below, then conclude_investigation with your verdict.",
        investigation_id, finding_id, session_uuid, pack_summary, now
    );

    let mut detail = serde_json::json!({
        "investigation_id": investigation_id,
        "finding_id": finding_id,
        "vuln_type": vuln_type,
        "suggested_tools": suggested_tools,
    });
    if let Some(p) = pack {
        detail.as_object_mut().unwrap().insert(
            "evidence_pack".to_string(),
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "tp_criteria": p.tp_criteria,
                "fp_criteria": p.fp_criteria,
                "confidence_guide": p.confidence_guide,
            }),
        );
    }

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&detail).unwrap_or_default()}
        ]
    })
}

async fn tool_log_investigation_step_with_state(state: &McpServerState, args: &Value) -> Value {
    let investigation_id = match args.get("investigation_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: investigation_id"),
    };
    let tool_used = match args.get("tool_used").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: tool_used"),
    };
    let finding = match args.get("finding").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: finding"),
    };
    let reasoning = match args.get("reasoning").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: reasoning"),
    };

    let step = InvestigationStep {
        tool_used: tool_used.clone(),
        finding,
        reasoning,
    };

    // 先查内存，未命中则从磁盘恢复（MCP 进程重启场景）
    let step_count = match get_or_load_investigation(state, &investigation_id) {
        Some(mut inv) => {
            inv.steps.push(step);
            let count = inv.steps.len();
            persist_investigation(&inv);
            state
                .audit
                .active_investigations
                .borrow_mut()
                .insert(investigation_id.clone(), inv);
            count
        }
        None => {
            return error_response(&format!(
                "Investigation not found: {}. Use start_investigation first.",
                investigation_id
            ))
        }
    };

    serde_json::json!({
        "content": [{"type": "text", "text": format!("📝 Step {} recorded for investigation {}\n  Tool: {}\n  Total steps so far: {}", step_count, investigation_id, tool_used, step_count)}]
    })
}

async fn tool_conclude_investigation_with_state(state: &McpServerState, args: &Value) -> Value {
    let investigation_id = match args.get("investigation_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: investigation_id"),
    };
    let verdict = match args.get("verdict").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: verdict"),
    };
    let reasoning = match args.get("reasoning").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: reasoning"),
    };
    let confidence = args.get("confidence").and_then(|v| v.as_f64());
    let severity_override = args
        .get("severity_override")
        .and_then(|v| v.as_str())
        .map(String::from);

    // 获取调查上下文（内存优先，磁盘回退；判定后从内存移除，磁盘留档最终状态）
    let inv = match get_or_load_investigation(state, &investigation_id) {
        Some(inv) => {
            persist_investigation(&inv);
            state
                .audit
                .active_investigations
                .borrow_mut()
                .remove(&investigation_id)
                .unwrap_or(inv)
        }
        None => return error_response(&format!("Investigation not found: {}", investigation_id)),
    };

    // 构建完整的审计日志条目
    let audit_entry = serde_json::json!({
        "investigation_id": investigation_id,
        "session_uuid": inv.session_uuid,
        "finding_id": inv.finding_id,
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "severity_override": severity_override,
        "hypothesis": inv.hypothesis,
        "investigation_steps": inv.steps.iter().map(|s| serde_json::json!({
            "tool_used": s.tool_used,
            "finding": s.finding,
            "reasoning": s.reasoning,
        })).collect::<Vec<_>>(),
        "total_steps": inv.steps.len(),
        "started_at": inv.started_at,
        "concluded_at": chrono::Utc::now().to_rfc3339(),
    });

    // 写入 audit_log.json
    // (复用现有的 validate_finding 逻辑)
    let log_path = std::path::Path::new(".ctx-audit").join("audit_log.json");
    let mut log_entries: Vec<serde_json::Value> = if log_path.exists() {
        std::fs::read_to_string(&log_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    log_entries.push(audit_entry.clone());
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        &log_path,
        serde_json::to_string_pretty(&log_entries).unwrap_or_default(),
    );

    // 如果是 FP，同时更新 baseline.json
    if verdict == "false_positive" {
        let baseline_path = std::path::Path::new(".ctx-audit").join("baseline.json");
        let mut baseline: serde_json::Value = if baseline_path.exists() {
            std::fs::read_to_string(&baseline_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::json!({"ignored": {}}))
        } else {
            serde_json::json!({"ignored": {}})
        };
        // 使用 finding_id 作为基线键
        if let Some(obj) = baseline.as_object_mut() {
            if let Some(ignored) = obj.get_mut("ignored").and_then(|v| v.as_object_mut()) {
                ignored.insert(inv.finding_id.clone(), serde_json::json!(reasoning));
            }
        }
        let _ = std::fs::write(
            &baseline_path,
            serde_json::to_string_pretty(&baseline).unwrap_or_default(),
        );
    }

    // 更新会话分组状态（finding 所属组标记为 concluded）并持久化
    if let Some(mut session) = get_or_load_session(state, &inv.session_uuid) {
        let mut changed = false;
        for group in session.groups.iter_mut() {
            if group.findings.iter().any(|f| f.finding_id == inv.finding_id) {
                group.status = "concluded".to_string();
                changed = true;
            }
        }
        if changed {
            persist_session(&session);
            state
                .audit
                .active_sessions
                .borrow_mut()
                .insert(session.session_uuid.clone(), session);
        }
    }

    let verdict_label = match verdict.as_str() {
        "true_positive" => "✅ TRUE POSITIVE",
        "false_positive" => "❌ FALSE POSITIVE",
        _ => "⚠️ NEEDS REVIEW",
    };

    let summary = format!(
        "{} Investigation concluded\n  Finding: {}\n  Verdict: {}\n  Steps: {}\n  Confidence: {}\n\nReasoning: {}\n\nAudit log → .ctx-audit/audit_log.json",
        verdict_label,
        inv.finding_id,
        verdict,
        inv.steps.len(),
        confidence.map(|c| format!("{:.0}%", c * 100.0)).unwrap_or_else(|| "N/A".to_string()),
        reasoning
    );

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&audit_entry).unwrap_or_default()}
        ]
    })
}

async fn tool_conclude_audit_session_with_state(state: &McpServerState, args: &Value) -> Value {
    let session_uuid = match args.get("session_uuid").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: session_uuid"),
    };
    let user_summary = args.get("summary").and_then(|v| v.as_str());

    // 统计所有调查结果
    let investigations: Vec<InvestigationContext> = {
        let invs = state.audit.active_investigations.borrow();
        invs.values()
            .filter(|i| i.session_uuid == session_uuid)
            .cloned()
            .collect()
    };

    let total = investigations.len();

    // 收集已下结论的调查（从 audit_log.json，仅统计本会话）
    let session = get_or_load_session(state, &session_uuid);
    let log_entries = read_audit_log(session.as_ref().map(|s| s.project_path.as_str()));
    let session_entries: Vec<&serde_json::Value> = log_entries
        .iter()
        .filter(|e| e["session_uuid"].as_str() == Some(session_uuid.as_str()))
        .collect();

    let tp_count = session_entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("true_positive"))
        .count();
    let fp_count = session_entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("false_positive"))
        .count();
    let review_count = session_entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("needs_review"))
        .count();

    // 从内存移除会话（磁盘文件保留留档）
    let session_info = state
        .audit
        .active_sessions
        .borrow_mut()
        .remove(&session_uuid)
        .or(session);

    let summary = format!(
        "📋 Audit session concluded\n  Session: {}\n  Project: {}\n  Investigations: {} total\n  ✅ True Positives: {}\n  ❌ False Positives: {}\n  ⚠️ Needs Review: {}\n  Active investigations at close: {}\n\n{}",
        session_uuid,
        session_info.as_ref().map(|s| s.project_path.as_str()).unwrap_or("unknown"),
        tp_count + fp_count + review_count,
        tp_count,
        fp_count,
        review_count,
        total,
        user_summary.unwrap_or("Audit complete.")
    );

    serde_json::json!({
        "content": [{"type": "text", "text": summary}],
        "data": {
            "session_uuid": session_uuid,
            "total_investigations": tp_count + fp_count + review_count,
            "true_positives": tp_count,
            "false_positives": fp_count,
            "needs_review": review_count,
        }
    })
}

/// 编排审计计划：deep 扫描 → 分组 → 匹配证据包 → 持久化会话
async fn tool_audit_plan_with_state(state: &McpServerState, args: &Value) -> Value {
    let project_path = match args.get("project_path").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return error_response("Missing required parameter: project_path"),
    };
    let min_severity = args
        .get("min_severity")
        .and_then(|v| v.as_str())
        .unwrap_or("high")
        .to_string();

    if !std::path::Path::new(&project_path).exists() {
        return error_response(&format!("Project path not found: {}", project_path));
    }

    // 内部复用 security_scan 的 deep 扫描逻辑（taint + cross-file）
    let findings = match run_configured_scan(&project_path, true, true).await {
        Ok(f) => f,
        Err(e) => return error_response(&format!("Scan failed: {}", e)),
    };

    // min_severity 过滤
    let min_rank = severity_rank(&min_severity);
    let filtered: Vec<&Finding> = findings
        .iter()
        .filter(|f| severity_rank(&f.severity.to_lowercase()) <= min_rank)
        .collect();

    // 按 (vuln_type, file) 分组，保持出现顺序
    let packs = load_audit_packs();
    let mut groups: Vec<SessionGroup> = Vec::new();
    let mut group_index: HashMap<(String, String), usize> = HashMap::new();
    for f in &filtered {
        let key = (f.vuln_type.clone(), f.file_path.clone());
        let idx = match group_index.get(&key) {
            Some(&i) => i,
            None => {
                let pack = find_pack(&packs, &f.vuln_type, None)
                    .or_else(|| generic_pack(&packs));
                groups.push(SessionGroup {
                    vuln_type: f.vuln_type.clone(),
                    pack_id: pack.map(|p| p.id.clone()).unwrap_or_default(),
                    status: "pending".to_string(),
                    findings: Vec::new(),
                });
                group_index.insert(key, groups.len() - 1);
                groups.len() - 1
            }
        };
        groups[idx].findings.push(GroupFinding {
            finding_id: f.finding_id.clone(),
            file: f.file_path.clone(),
            line: f.line_start,
            severity: f.severity.clone(),
            description: f.description.chars().take(200).collect(),
        });
    }

    // 创建并持久化审计会话
    let session_uuid = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let ctx = SessionContext {
        session_uuid: session_uuid.clone(),
        project_path: project_path.clone(),
        session_type: "full".to_string(),
        started_at: now.clone(),
        groups: groups.clone(),
    };
    persist_session(&ctx);
    state
        .audit
        .active_sessions
        .borrow_mut()
        .insert(session_uuid.clone(), ctx);

    // 组装分组响应（含每组完整证据包内容）
    let group_details: Vec<Value> = groups
        .iter()
        .map(|g| {
            let pack = packs.iter().find(|p| p.id == g.pack_id);
            let representative = g.findings.first();
            serde_json::json!({
                "vuln_type": g.vuln_type,
                "file": representative.map(|r| r.file.as_str()).unwrap_or(""),
                "finding_count": g.findings.len(),
                "representative_finding": representative.map(|r| serde_json::json!({
                    "finding_id": r.finding_id,
                    "file": r.file,
                    "line": r.line,
                    "severity": r.severity,
                })),
                "pack_id": g.pack_id,
                "status": g.status,
                "findings": g.findings.iter().map(|f| serde_json::json!({
                    "finding_id": f.finding_id,
                    "file": f.file,
                    "line": f.line,
                    "severity": f.severity,
                })).collect::<Vec<_>>(),
                "pack": pack.map(|p| serde_json::to_value(p).unwrap_or_default()),
            })
        })
        .collect();

    let summary = format!(
        "🗂️ Audit plan created\n  Session: {}\n  Project: {}\n  Findings (≥{}): {} in {} groups\n  Session file: {}\n\nWorkflow: for each group, follow its evidence pack — call start_investigation on the representative finding, gather evidence with the suggested tools, then conclude_investigation with your verdict. When all groups are done, call audit_finalize_report.",
        session_uuid,
        project_path,
        min_severity,
        filtered.len(),
        groups.len(),
        session_file_path(&project_path, &session_uuid).display(),
    );

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                "session_uuid": session_uuid,
                "project_path": project_path,
                "min_severity": min_severity,
                "total_findings": filtered.len(),
                "group_count": groups.len(),
                "groups": group_details,
            })).unwrap_or_default()}
        ]
    })
}

/// 生成 Markdown 审计报告（纯函数，便于单测）
///
/// 结构：项目指纹 / 判定统计表 / TP 详情（攻击链、证据、置信度）/ FP 分组摘要
fn render_audit_report(session: &SessionContext, entries: &[Value]) -> String {
    let tp: Vec<&Value> = entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("true_positive"))
        .collect();
    let fp: Vec<&Value> = entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("false_positive"))
        .collect();
    let nr: Vec<&Value> = entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("needs_review"))
        .collect();
    let pending_groups = session
        .groups
        .iter()
        .filter(|g| g.status != "concluded")
        .count();

    let mut out = String::new();
    out.push_str("# 安全审计报告\n\n");

    // ── 项目指纹 ──
    out.push_str("## 项目指纹\n\n");
    out.push_str(&format!("- 项目路径: `{}`\n", session.project_path));
    out.push_str(&format!(
        "- 会话: `{}`（类型: {}）\n",
        session.session_uuid, session.session_type
    ));
    out.push_str(&format!("- 开始时间: {}\n", session.started_at));
    out.push_str(&format!(
        "- 报告生成时间: {}\n",
        chrono::Utc::now().to_rfc3339()
    ));
    out.push_str(&format!(
        "- 计划分组: {} 组 / 已判定: {} 条 / 未完结分组: {}\n\n",
        session.groups.len(),
        entries.len(),
        pending_groups
    ));

    // ── 判定统计 ──
    out.push_str("## 判定统计\n\n");
    out.push_str("| 判定 | 数量 |\n| --- | --- |\n");
    out.push_str(&format!("| ✅ True Positive | {} |\n", tp.len()));
    out.push_str(&format!("| ❌ False Positive | {} |\n", fp.len()));
    out.push_str(&format!("| ⚠️ Needs Review | {} |\n\n", nr.len()));

    // ── TP 详情 ──
    out.push_str("## 确认漏洞（True Positives）\n\n");
    if tp.is_empty() {
        out.push_str("无。\n\n");
    }
    for (i, e) in tp.iter().enumerate() {
        let finding_id = e["finding_id"].as_str().unwrap_or("unknown");
        let vuln_type = vuln_type_of_finding(session, finding_id).unwrap_or("unknown");
        out.push_str(&format!("### {}. {} — `{}`\n\n", i + 1, vuln_type, finding_id));
        if let Some(c) = e["confidence"].as_f64() {
            out.push_str(&format!("- 置信度: {:.0}%\n", c * 100.0));
        }
        if let Some(sev) = e["severity_override"].as_str() {
            out.push_str(&format!("- 严重度修正: {}\n", sev));
        }
        out.push_str(&format!(
            "- 判定理由: {}\n",
            e["reasoning"].as_str().unwrap_or("")
        ));
        // 攻击链与证据引用（调查步骤）
        if let Some(steps) = e["investigation_steps"].as_array() {
            if !steps.is_empty() {
                out.push_str("- 攻击链与证据:\n");
                for (j, s) in steps.iter().enumerate() {
                    out.push_str(&format!(
                        "  {}. `{}`: {}\n",
                        j + 1,
                        s["tool_used"].as_str().unwrap_or("?"),
                        s["finding"].as_str().unwrap_or("")
                    ));
                }
            }
        }
        out.push('\n');
    }

    // ── FP 分组摘要（按 vuln_type 聚类）──
    out.push_str("## 误报分组摘要\n\n");
    if fp.is_empty() {
        out.push_str("无。\n\n");
    } else {
        let mut fp_by_type: HashMap<String, Vec<&Value>> = HashMap::new();
        for e in &fp {
            let vt = vuln_type_of_finding(session, e["finding_id"].as_str().unwrap_or(""))
                .unwrap_or("unknown")
                .to_string();
            fp_by_type.entry(vt).or_default().push(e);
        }
        let mut types: Vec<&String> = fp_by_type.keys().collect();
        types.sort();
        for vt in types {
            let group = &fp_by_type[vt];
            out.push_str(&format!("### {}（{} 条）\n\n", vt, group.len()));
            for e in group {
                out.push_str(&format!(
                    "- `{}`: {}\n",
                    e["finding_id"].as_str().unwrap_or("unknown"),
                    e["reasoning"].as_str().unwrap_or("")
                ));
            }
            out.push('\n');
        }
    }

    // ── 待人工复核 ──
    if !nr.is_empty() {
        out.push_str("## 待人工复核（Needs Review）\n\n");
        for e in &nr {
            let finding_id = e["finding_id"].as_str().unwrap_or("unknown");
            let vuln_type = vuln_type_of_finding(session, finding_id).unwrap_or("unknown");
            out.push_str(&format!(
                "- {} — `{}`: {}\n",
                vuln_type,
                finding_id,
                e["reasoning"].as_str().unwrap_or("")
            ));
        }
        out.push('\n');
    }

    out
}

/// 汇总会话判定并生成 Markdown 审计报告
async fn tool_audit_finalize_report_with_state(state: &McpServerState, args: &Value) -> Value {
    let session_uuid = match args.get("session_uuid").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return error_response("Missing required parameter: session_uuid"),
    };

    // 读取会话（内存未命中时从磁盘加载）
    let session = match get_or_load_session(state, &session_uuid) {
        Some(s) => s,
        None => {
            return error_response(&format!(
                "Session not found: {}. Provide a valid session_uuid from audit_plan/start_audit_session.",
                session_uuid
            ))
        }
    };

    // 收集本会话的判定记录
    let log_entries = read_audit_log(Some(&session.project_path));
    let session_entries: Vec<Value> = log_entries
        .into_iter()
        .filter(|e| e["session_uuid"].as_str() == Some(session_uuid.as_str()))
        .collect();

    let report = render_audit_report(&session, &session_entries);

    // 默认输出路径：<project>/.ctx-audit/audit_report_<uuid>.md
    let output_path = args
        .get("output_path")
        .and_then(|v| v.as_str())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(&session.project_path)
                .join(".ctx-audit")
                .join(format!("audit_report_{}.md", session_uuid))
        });

    if let Some(parent) = output_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return error_response(&format!("Failed to create report directory: {}", e));
        }
    }
    if let Err(e) = std::fs::write(&output_path, &report) {
        return error_response(&format!("Failed to write report: {}", e));
    }

    let tp = session_entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("true_positive"))
        .count();
    let fp = session_entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("false_positive"))
        .count();
    let nr = session_entries
        .iter()
        .filter(|e| e["verdict"].as_str() == Some("needs_review"))
        .count();

    let summary = format!(
        "📄 Audit report generated\n  Session: {}\n  Report: {}\n  ✅ TP: {}  ❌ FP: {}  ⚠️ NR: {}",
        session_uuid,
        output_path.display(),
        tp,
        fp,
        nr
    );

    serde_json::json!({
        "content": [
            {"type": "text", "text": summary},
            {"type": "text", "text": serde_json::to_string_pretty(&serde_json::json!({
                "report_path": output_path.display().to_string(),
                "session_uuid": session_uuid,
                "true_positives": tp,
                "false_positives": fp,
                "needs_review": nr,
                "total_verdicts": session_entries.len(),
            })).unwrap_or_default()}
        ]
    })
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

    let has_evidence = findings.iter().any(|f| f.evidence_refs.is_some());

    let mut summary = format!("Found {} security findings:\n", findings.len());

    for sev in &["critical", "high", "medium", "low", "info"] {
        if let Some(count) = counts.get(*sev) {
            summary.push_str(&format!("  - {}: {}\n", sev.to_uppercase(), count));
        }
    }

    if has_evidence {
        summary.push_str("\n📎 Cross-file findings include 'evidence_refs' with call graph pointers. Use query_callers/query_callees/find_call_path with the evidence data to verify each finding deterministically.\n");
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

// ── MCP Server State ──────────────────────────────────────

/// MCP 服务器运行时状态
struct McpServerState {
    /// 统一的工具注册表（来自 tools/ crate）
    tool_registry: std::sync::Arc<ctx_audit_tools::ToolRegistry>,
    /// 审计会话状态（内存存储，进程生命周期内有效）
    audit: McpAuditState,
}

/// 审计会话管理（纯内存，无数据库依赖）
/// 使用 RefCell 实现内部可变性（MCP 服务器单线程运行，无需 Mutex）
struct McpAuditState {
    /// 活跃审计会话: session_uuid → SessionContext
    active_sessions: std::cell::RefCell<HashMap<String, SessionContext>>,
    /// 活跃调查: investigation_id → InvestigationContext
    active_investigations: std::cell::RefCell<HashMap<String, InvestigationContext>>,
}

impl McpAuditState {
    fn new() -> Self {
        Self {
            active_sessions: std::cell::RefCell::new(HashMap::new()),
            active_investigations: std::cell::RefCell::new(HashMap::new()),
        }
    }
}

/// 审计会话上下文
///
/// 创建时持久化到 `<project>/.ctx-audit/audit_sessions/<uuid>.json`，
/// MCP 进程重启后可从磁盘恢复。
#[derive(Clone, Serialize, Deserialize)]
struct SessionContext {
    session_uuid: String,
    project_path: String,
    session_type: String,
    started_at: String,
    /// 审计分组（audit_plan 生成；start_audit_session 创建时为空）
    #[serde(default)]
    groups: Vec<SessionGroup>,
}

/// 审计分组 —— 同一 (vuln_type, file) 的 findings 归为一组，
/// 整组共用一个证据包，逐组完成取证与判定
#[derive(Clone, Serialize, Deserialize)]
struct SessionGroup {
    /// 漏洞类型（finding 的 vuln_type）
    vuln_type: String,
    /// 匹配到的证据包 id
    pack_id: String,
    /// 组状态：pending / concluded
    status: String,
    /// 组内 finding 摘要
    findings: Vec<GroupFinding>,
}

/// 分组内的 finding 摘要
#[derive(Clone, Serialize, Deserialize)]
struct GroupFinding {
    finding_id: String,
    file: String,
    line: usize,
    severity: String,
    description: String,
}

/// 调查上下文 — 对单个 finding 的深度调查
#[derive(Clone, Serialize, Deserialize)]
struct InvestigationContext {
    investigation_id: String,
    session_uuid: String,
    finding_id: String,
    hypothesis: Option<String>,
    steps: Vec<InvestigationStep>,
    started_at: String,
}

/// 调查步骤记录
#[derive(Clone, Serialize, Deserialize)]
struct InvestigationStep {
    tool_used: String,
    finding: String,
    reasoning: String,
}

/// 调查磁盘文件路径：`.ctx-audit/audit_sessions/inv_<iid>.json`（CWD 相对，与会话加载语义一致）
fn investigation_file_path(investigation_id: &str) -> std::path::PathBuf {
    std::path::Path::new(".ctx-audit")
        .join("audit_sessions")
        .join(format!("inv_{}.json", investigation_id))
}

/// 将调查持久化到磁盘（失败仅记录日志，不阻断主流程）
fn persist_investigation(ctx: &InvestigationContext) {
    let path = investigation_file_path(&ctx.investigation_id);
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("创建调查目录失败 {:?}: {}", parent, e);
            return;
        }
    }
    match serde_json::to_string_pretty(ctx) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!("调查持久化失败 {:?}: {}", path, e);
            }
        }
        Err(e) => tracing::warn!("调查序列化失败: {}", e),
    }
}

/// 从磁盘加载调查
fn load_investigation_from_disk(investigation_id: &str) -> Option<InvestigationContext> {
    let path = investigation_file_path(investigation_id);
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<InvestigationContext>(&content) {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            tracing::warn!("调查文件解析失败 {:?}: {}", path, e);
            None
        }
    }
}

/// 查询调查：先查内存，未命中则从磁盘加载并回填内存（MCP 进程重启后可恢复）
fn get_or_load_investigation(
    state: &McpServerState,
    investigation_id: &str,
) -> Option<InvestigationContext> {
    if let Some(ctx) = state
        .audit
        .active_investigations
        .borrow()
        .get(investigation_id)
    {
        return Some(ctx.clone());
    }
    let ctx = load_investigation_from_disk(investigation_id)?;
    state
        .audit
        .active_investigations
        .borrow_mut()
        .insert(investigation_id.to_string(), ctx.clone());
    Some(ctx)
}

// ── 会话磁盘持久化 ──────────────────────────────────────

/// 会话磁盘文件路径：`<project>/.ctx-audit/audit_sessions/<uuid>.json`
fn session_file_path(project_path: &str, session_uuid: &str) -> std::path::PathBuf {
    std::path::Path::new(project_path)
        .join(".ctx-audit")
        .join("audit_sessions")
        .join(format!("{}.json", session_uuid))
}

/// 将会话持久化到磁盘（失败仅记录日志，不阻断主流程）
fn persist_session(ctx: &SessionContext) {
    let path = session_file_path(&ctx.project_path, &ctx.session_uuid);
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("创建会话目录失败 {:?}: {}", parent, e);
            return;
        }
    }
    match serde_json::to_string_pretty(ctx) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!("会话持久化失败 {:?}: {}", path, e);
            }
        }
        Err(e) => tracing::warn!("会话序列化失败: {}", e),
    }
}

/// 从磁盘加载会话（按 CWD 相对路径 `.ctx-audit/audit_sessions/<uuid>.json` 查找）
fn load_session_from_disk(session_uuid: &str) -> Option<SessionContext> {
    let path = session_file_path(".", session_uuid);
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<SessionContext>(&content) {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            tracing::warn!("会话文件解析失败 {:?}: {}", path, e);
            None
        }
    }
}

/// 查询会话：先查内存，未命中则从磁盘加载并回填内存
fn get_or_load_session(state: &McpServerState, session_uuid: &str) -> Option<SessionContext> {
    if let Some(ctx) = state.audit.active_sessions.borrow().get(session_uuid) {
        return Some(ctx.clone());
    }
    let ctx = load_session_from_disk(session_uuid)?;
    state
        .audit
        .active_sessions
        .borrow_mut()
        .insert(session_uuid.to_string(), ctx.clone());
    Some(ctx)
}

/// 读取审计日志条目：优先 `<project>/.ctx-audit/audit_log.json`，
/// 不存在时回退 CWD 下的 `.ctx-audit/audit_log.json`（历史行为）
fn read_audit_log(project_path: Option<&str>) -> Vec<serde_json::Value> {
    let candidates: Vec<std::path::PathBuf> = match project_path {
        Some(p) => vec![
            std::path::Path::new(p).join(".ctx-audit").join("audit_log.json"),
            std::path::Path::new(".ctx-audit").join("audit_log.json"),
        ],
        None => vec![std::path::Path::new(".ctx-audit").join("audit_log.json")],
    };
    for path in candidates {
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                    return entries;
                }
            }
        }
    }
    Vec::new()
}

/// 在会话分组中查找 finding 对应的漏洞类型
fn vuln_type_of_finding<'a>(session: &'a SessionContext, finding_id: &str) -> Option<&'a str> {
    session
        .groups
        .iter()
        .find(|g| g.findings.iter().any(|f| f.finding_id == finding_id))
        .map(|g| g.vuln_type.as_str())
}

/// 按工具名为取证步骤填充调用参数（finding 的 file/line 注入到合适位置）
fn evidence_step_params(
    tool: &str,
    project_path: &str,
    finding_file: Option<&str>,
    finding_line: Option<usize>,
) -> Value {
    let file = finding_file.unwrap_or("");
    let line = finding_line.unwrap_or(1);
    match tool {
        "get_code_context" => serde_json::json!({"file_path": file, "line": line}),
        "search_code" => serde_json::json!({
            "project_path": project_path,
            "pattern": "<根据本步 purpose 自行构造正则，如变量名/函数名/净化函数名>"
        }),
        "query_callers" | "query_callees" => serde_json::json!({
            "project_path": project_path,
            "file_path": file,
            "function_name": "<sink 所在函数名，可先用 enclosing_function_at_line 确认>"
        }),
        "query_middleware_chain" | "list_file_functions" => {
            serde_json::json!({"project_path": project_path, "file_path": file})
        }
        "check_sanitizer" => {
            serde_json::json!({"func_name": "<待查证的净化/解析函数名>"})
        }
        "get_graph_stats" => serde_json::json!({"project_path": project_path}),
        _ => serde_json::json!({"project_path": project_path, "file_path": file, "line": line}),
    }
}

impl McpServerState {
    async fn new() -> Self {
        let registry = std::sync::Arc::new(ctx_audit_tools::ToolRegistry::new());
        // 注册所有内置工具（搜索、污点、模式、调用图）
        ctx_audit_tools::register_all_tools(&registry, ".".to_string(), None, None).await;
        Self {
            tool_registry: registry,
            audit: McpAuditState::new(),
        }
    }
}

// ── MCP Server Main Loop ────────────────────────────────

pub async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = stdin.lock();

    let state = McpServerState::new().await;

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
        let result =
            handle_request_with_state(&state, request.method.clone(), &request.params).await;

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
    let min_risk_score = args
        .get("min_risk_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.3) as f32;
    let include_details = args
        .get("include_details")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let path = std::path::Path::new(project_path);
    if !path.exists() {
        return error_response(&format!("Project path not found: {}", project_path));
    }

    let surface = AttackSurfaceMapper::map_project(path);

    // 过滤低风险入口点
    let filtered_entries: Vec<Value> = surface
        .entry_points
        .iter()
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

    let trust_bounds: Vec<Value> = surface
        .trust_boundaries
        .iter()
        .map(|tb| {
            serde_json::json!({
                "file_path": tb.file_path,
                "line": tb.line,
                "description": tb.description,
                "source": tb.source,
            })
        })
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
    let requested_ids: Option<Vec<String>> = args
        .get("pattern_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });

    // 扫描
    let mut matches = scanner.scan(&surface, path);

    // 过滤
    if let Some(ref ids) = requested_ids {
        matches.retain(|m| ids.contains(&m.pattern_id));
    }

    let severity_order = |s: &str| match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
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

    let match_details: Vec<Value> = matches
        .iter()
        .map(|m| {
            let evidence: Vec<Value> = m
                .evidence
                .iter()
                .take(5)
                .map(|e| {
                    serde_json::json!({
                        "file": e.file_path,
                        "line": e.line,
                        "matched": e.matched_pattern,
                        "code": e.code_snippet,
                        "type": e.context_type,
                    })
                })
                .collect();

            let affected: Vec<Value> = m
                .affected_entries
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "file": a.file_path,
                        "line": a.line,
                        "type": a.entry_type,
                        "function": a.function_name,
                        "route": a.route,
                    })
                })
                .collect();

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
        })
        .collect();

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
    let validate_only = args
        .get("validate_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

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
            let validation_result =
                if let Ok(rs) = serde_yaml::from_value::<RuleSet>(yaml_value.clone()) {
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
                        return error_response(
                            "Pattern rule must have at least one of: pattern, patterns, query",
                        );
                    }
                    Ok((rule.name.clone(), 1, "rule"))
                } else {
                    Err("Could not parse as RuleSet or Rule. Check YAML structure.".to_string())
                };

            match validation_result {
                Ok((name, count, kind)) => {
                    if validate_only {
                        return text_response(&format!(
                            "Validation OK: {} '{}' with {} rule(s)",
                            kind, name, count
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
                            "Taint rule must have kind='taint-rules', got '{}'",
                            ts.kind
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
        _ => error_response(&format!(
            "Unknown rule_type: '{}'. Must be 'pattern' or 'taint'",
            rule_type
        )),
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
        filepath.display(),
        rule_type
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
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

async fn handle_request_with_state(
    state: &McpServerState,
    method: String,
    params: &Value,
) -> Value {
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
            // 合并 ToolRegistry 工具 + MCP 独有工具
            let mut tools: Vec<Value> = Vec::new();

            // 1. 来自 tools/ crate 的工具（通过 ToolRegistry）
            for def in state.tool_registry.get_definitions().await {
                tools.push(serde_json::json!({
                    "name": def.name,
                    "description": def.description,
                    "inputSchema": def.to_mcp_schema(),
                }));
            }

            // 2. MCP 独有的工具（security_scan, scan_file, get_attack_surface 等）
            for t in tool_definitions() {
                // 避免与 ToolRegistry 中的同名工具重复
                let name = t.name;
                if tools
                    .iter()
                    .any(|existing| existing["name"].as_str() == Some(name))
                {
                    continue;
                }
                tools.push(serde_json::json!({
                    "name": name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                }));
            }

            serde_json::json!({"tools": tools})
        }
        "tools/call" => {
            let tool_name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            // 先尝试 ToolRegistry
            if let Some(tool) = state.tool_registry.get_tool(tool_name) {
                match tool.execute(arguments).await {
                    Ok(result) => result.to_mcp_response(),
                    Err(e) => serde_json::json!({
                        "content": [{"type": "text", "text": format!("Tool error: {}", e)}],
                        "isError": true
                    }),
                }
            } else {
                // 审计会话工具（需要 state 访问）
                match tool_name {
                    "start_audit_session" => {
                        tool_start_audit_session_with_state(state, &arguments).await
                    }
                    "start_investigation" => {
                        tool_start_investigation_with_state(state, &arguments).await
                    }
                    "log_investigation_step" => {
                        tool_log_investigation_step_with_state(state, &arguments).await
                    }
                    "conclude_investigation" => {
                        tool_conclude_investigation_with_state(state, &arguments).await
                    }
                    "conclude_audit_session" => {
                        tool_conclude_audit_session_with_state(state, &arguments).await
                    }
                    "audit_plan" => tool_audit_plan_with_state(state, &arguments).await,
                    "audit_finalize_report" => {
                        tool_audit_finalize_report_with_state(state, &arguments).await
                    }
                    // 回退到 MCP 独有工具（不需要 state）
                    _ => handle_tool_call(tool_name, &arguments).await,
                }
            }
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

// ── 单元测试 ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造带两个分组的测试会话
    fn sample_session() -> SessionContext {
        SessionContext {
            session_uuid: "test-uuid-1234".to_string(),
            project_path: "/tmp/demo-project".to_string(),
            session_type: "full".to_string(),
            started_at: "2026-07-22T00:00:00Z".to_string(),
            groups: vec![
                SessionGroup {
                    vuln_type: "CrossSiteScripting".to_string(),
                    pack_id: "cwe-79-xss".to_string(),
                    status: "concluded".to_string(),
                    findings: vec![GroupFinding {
                        finding_id: "f-xss-1".to_string(),
                        file: "src/views.rs".to_string(),
                        line: 42,
                        severity: "high".to_string(),
                        description: "innerHTML assignment".to_string(),
                    }],
                },
                SessionGroup {
                    vuln_type: "SqlInjection".to_string(),
                    pack_id: "cwe-89-sqli".to_string(),
                    status: "pending".to_string(),
                    findings: vec![GroupFinding {
                        finding_id: "f-sqli-1".to_string(),
                        file: "src/db.rs".to_string(),
                        line: 10,
                        severity: "critical".to_string(),
                        description: "string concat in query".to_string(),
                    }],
                },
            ],
        }
    }

    /// 构造各类型判定各一条的审计日志
    fn sample_entries() -> Vec<Value> {
        vec![
            serde_json::json!({
                "investigation_id": "inv-1",
                "session_uuid": "test-uuid-1234",
                "finding_id": "f-xss-1",
                "verdict": "true_positive",
                "confidence": 0.95,
                "reasoning": "外部输入未转义直达 innerHTML",
                "investigation_steps": [
                    {"tool_used": "get_code_context", "finding": "sink 为 innerHTML 赋值", "reasoning": "r"},
                    {"tool_used": "query_callers", "finding": "来源为 HTTP 参数", "reasoning": "r"}
                ],
            }),
            serde_json::json!({
                "investigation_id": "inv-2",
                "session_uuid": "test-uuid-1234",
                "finding_id": "f-sqli-1",
                "verdict": "false_positive",
                "confidence": 0.9,
                "reasoning": "实际为参数化查询",
                "investigation_steps": [],
            }),
            serde_json::json!({
                "investigation_id": "inv-3",
                "session_uuid": "test-uuid-1234",
                "finding_id": "f-other",
                "verdict": "needs_review",
                "reasoning": "证据矛盾",
                "investigation_steps": [],
            }),
        ]
    }

    #[test]
    fn test_render_audit_report_structure() {
        let session = sample_session();
        let entries = sample_entries();
        let report = render_audit_report(&session, &entries);

        // 结构完整性
        assert!(report.contains("# 安全审计报告"));
        assert!(report.contains("## 项目指纹"));
        assert!(report.contains("## 判定统计"));
        assert!(report.contains("## 确认漏洞（True Positives）"));
        assert!(report.contains("## 误报分组摘要"));
        assert!(report.contains("## 待人工复核（Needs Review）"));

        // 项目指纹
        assert!(report.contains("/tmp/demo-project"));
        assert!(report.contains("test-uuid-1234"));
        // 未完结分组 = 1（sqli 组仍 pending）
        assert!(report.contains("未完结分组: 1"));

        // 统计数字
        assert!(report.contains("| ✅ True Positive | 1 |"));
        assert!(report.contains("| ❌ False Positive | 1 |"));
        assert!(report.contains("| ⚠️ Needs Review | 1 |"));

        // TP 详情：vuln_type 从分组反查、置信度、攻击链证据
        assert!(report.contains("CrossSiteScripting — `f-xss-1`"));
        assert!(report.contains("置信度: 95%"));
        assert!(report.contains("`get_code_context`: sink 为 innerHTML 赋值"));
        assert!(report.contains("`query_callers`: 来源为 HTTP 参数"));

        // FP 按 vuln_type 聚类
        assert!(report.contains("### SqlInjection（1 条）"));
        assert!(report.contains("`f-sqli-1`: 实际为参数化查询"));
    }

    #[test]
    fn test_render_audit_report_empty() {
        let mut session = sample_session();
        session.groups.clear();
        let report = render_audit_report(&session, &[]);
        assert!(report.contains("| ✅ True Positive | 0 |"));
        assert!(report.contains("无。"));
        // 空报告不应有待复核段
        assert!(!report.contains("## 待人工复核"));
    }

    #[test]
    fn test_vuln_type_of_finding() {
        let session = sample_session();
        assert_eq!(
            vuln_type_of_finding(&session, "f-xss-1"),
            Some("CrossSiteScripting")
        );
        assert_eq!(vuln_type_of_finding(&session, "f-sqli-1"), Some("SqlInjection"));
        assert_eq!(vuln_type_of_finding(&session, "nonexistent"), None);
    }

    #[test]
    fn test_evidence_step_params() {
        // get_code_context 注入 file/line
        let params = evidence_step_params("get_code_context", "/proj", Some("a.rs"), Some(7));
        assert_eq!(params["file_path"], "a.rs");
        assert_eq!(params["line"], 7);
        assert!(params.get("project_path").is_none());

        // search_code 注入 project_path
        let params = evidence_step_params("search_code", "/proj", Some("a.rs"), Some(7));
        assert_eq!(params["project_path"], "/proj");
        assert!(params["pattern"].as_str().unwrap().contains("purpose"));

        // query_callers 注入 project_path + file
        let params = evidence_step_params("query_callers", "/proj", Some("a.rs"), None);
        assert_eq!(params["file_path"], "a.rs");
        assert_eq!(params["project_path"], "/proj");

        // 未知工具走通用兜底
        let params = evidence_step_params("some_other_tool", "/proj", Some("a.rs"), Some(3));
        assert_eq!(params["line"], 3);

        // 无 file 时为空串而非 panic
        let params = evidence_step_params("get_code_context", "/proj", None, None);
        assert_eq!(params["file_path"], "");
        assert_eq!(params["line"], 1);
    }

    #[test]
    fn test_session_serialization_roundtrip() {
        let session = sample_session();
        let json = serde_json::to_string_pretty(&session).unwrap();
        let restored: SessionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.session_uuid, session.session_uuid);
        assert_eq!(restored.groups.len(), 2);
        assert_eq!(restored.groups[0].pack_id, "cwe-79-xss");
        assert_eq!(restored.groups[0].findings[0].line, 42);
    }

    #[test]
    fn test_session_file_path_layout() {
        let path = session_file_path("/proj", "abc-123");
        let s = path.to_string_lossy().replace('\\', "/");
        assert_eq!(s, "/proj/.ctx-audit/audit_sessions/abc-123.json");
    }

    #[test]
    fn test_audit_plan_tool_registered() {
        // 新工具必须在工具列表中可见且 schema 完整
        let defs = tool_definitions();
        let plan = defs.iter().find(|t| t.name == "audit_plan").unwrap();
        assert_eq!(plan.input_schema["required"][0], "project_path");
        assert!(plan.input_schema["properties"]["min_severity"].is_object());
        assert!(plan.description.contains("audit_finalize_report"));

        let fin = defs
            .iter()
            .find(|t| t.name == "audit_finalize_report")
            .unwrap();
        assert_eq!(fin.input_schema["required"][0], "session_uuid");
        assert!(fin.input_schema["properties"]["output_path"].is_object());

        // start_investigation 接受可选 vuln_type
        let inv = defs.iter().find(|t| t.name == "start_investigation").unwrap();
        assert!(inv.input_schema["properties"]["vuln_type"].is_object());
    }
}
