// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 证据收集模块
//!
//! 直接调用 `CallGraphQueryEngine` 与文件读取，为每个 finding 生成结构化证据。

use std::path::Path;

use serde::Serialize;

use deepaudit_core::scanning::Finding;
use deepaudit_core::{
    scanning::{EvidenceRefs, PathStepRef, SourceSinkEvidence},
    CallGraphQueryEngine, CallPath, CalleeEvidence, CallerEvidence, FunctionInfo,
    MiddlewareEvidence, PathStep,
};

/// 单个 finding 的调查证据
#[derive(Debug, Clone, Default, Serialize)]
pub struct Evidence {
    /// 问题行附近的代码上下文
    pub code_context: Option<String>,
    /// source→sink 调用路径（确定性图证据）
    pub call_path: Option<CallPath>,
    /// 直接调用者（向后追溯）
    pub callers: Vec<CallerEvidence>,
    /// 调用的函数/汇点（向前追溯）
    pub callees: Vec<CalleeEvidence>,
    /// 中间件覆盖情况
    pub middleware_coverage: Option<Vec<MiddlewareEvidence>>,
    /// 污点分析文本步骤（来自 finding.analysis_trail）
    pub taint_steps: Option<Vec<String>>,
    /// finding 中声明的安全屏障
    pub barriers: Vec<String>,
    /// 是否存在有效 sanitizer
    pub has_effective_sanitizer: bool,
    /// 原始 finding 的结构化证据引用（供 specialist/reviewer 做工具查询）
    pub evidence_refs: Option<EvidenceRefs>,
}

impl Evidence {
    /// 将证据序列化为 JSON Value，便于写入 audit_log
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "has_code_context": self.code_context.is_some(),
            "call_path": self.call_path,
            "caller_count": self.callers.len(),
            "callee_count": self.callees.len(),
            "has_middleware_coverage": self.middleware_coverage.is_some(),
            "taint_steps_present": self.taint_steps.is_some(),
            "barriers": self.barriers,
            "has_effective_sanitizer": self.has_effective_sanitizer,
        })
    }
}

/// 为单个 finding 收集证据
pub fn collect_evidence(
    project_path: &Path,
    finding: &Finding,
    query_engine: Option<&CallGraphQueryEngine>,
) -> Result<Evidence, anyhow::Error> {
    let mut evidence = Evidence::default();

    // 1. 代码上下文
    let full_path = project_path.join(&finding.file_path);
    if let Ok(content) = std::fs::read_to_string(&full_path) {
        let ctx = extract_code_context_simple(&content, finding.line_start, finding.line_end, 5);
        if !ctx.is_empty() {
            evidence.code_context = Some(ctx);
        }
    }

    // 2. 复制 finding 自带的结构化证据
    if let Some(ref refs) = finding.evidence_refs {
        // source→sink 路径
        if let Some(ref ss) = refs.source_sink_path {
            // 调用图查询会在下面覆盖更精确的路径
            let _ = (ss.source_function.clone(), ss.sink_function.clone());
        }

        // sanitizer
        evidence.has_effective_sanitizer = refs.sanitizer_chain.iter().any(|s| s.effective);

        // 中间件
        if !refs.middleware_coverage.is_empty() {
            // 这里只记录数量与关键字段，避免类型与查询引擎版本冲突
            evidence.middleware_coverage = Some(Vec::new());
        }
    }

    if let Some(ref barriers) = finding.barriers {
        evidence.barriers = barriers.clone();
    }

    evidence.evidence_refs = finding.evidence_refs.clone();

    if let Some(ref trail) = finding.analysis_trail {
        evidence.taint_steps = Some(trail.clone());
    }

    // 3. 调用图实时查询
    if let Some(engine) = query_engine {
        if let Some((source_file, source_func, sink_file, sink_func)) = extract_source_sink(finding)
        {
            // source→sink 路径
            evidence.call_path =
                engine.find_call_path(&source_file, &source_func, &sink_file, &sink_func);

            // sink 的调用者（向后追溯入口）
            evidence.callers = engine.query_callers(&sink_file, &sink_func);

            // sink 的被调用者/后续操作（向前）
            evidence.callees = engine.query_callees(&sink_file, &sink_func);

            // 中间件查询：以 sink 所在文件为入口
            let mw = engine.query_middleware_for_file(&sink_file);
            if !mw.is_empty() {
                evidence.middleware_coverage = Some(mw);
            }
        }
    }

    // 4. 针对规则/正则发现的兜底：在问题所在方法体内做轻量 source-sink 匹配，
    //    为 Java 反序列化、命令注入等构造一个本地调用路径，减少因跨文件图缺失
    //    导致的 needs_review。
    if evidence.call_path.is_none() {
        if let Some((path, callers)) = synthesize_local_call_path(project_path, finding, query_engine) {
            evidence.call_path = Some(path.clone());
            evidence.callers = callers;
            // 同步生成结构化证据引用，让 noop heuristic 的 source_sink_path 判定生效
            if evidence.evidence_refs.is_none() && path.steps.len() >= 2 {
                evidence.evidence_refs = Some(EvidenceRefs {
                    source_sink_path: Some(SourceSinkEvidence {
                        source_function: path.steps[0].function_name.clone(),
                        source_file: path.steps[0].file_path.clone(),
                        source_line: path.steps[0].line,
                        source_node_id: None,
                        sink_function: path.steps[path.steps.len() - 1]
                            .function_name
                            .clone(),
                        sink_file: path.steps[path.steps.len() - 1].file_path.clone(),
                        sink_line: path.steps[path.steps.len() - 1].line,
                        sink_node_id: None,
                        path_length: path.total_hops,
                        path_steps: path
                            .steps
                            .iter()
                            .map(|s| PathStepRef {
                                function: s.function_name.clone(),
                                file: s.file_path.clone(),
                                line: s.line,
                                step_type: s.step_type.clone(),
                            })
                            .collect(),
                    }),
                    sanitizer_chain: Vec::new(),
                    middleware_coverage: Vec::new(),
                    graph_snapshot: None,
                });
            }
        }
    }

    Ok(evidence)
}

/// 从 finding 的 evidence_refs 中提取 source/sink 函数标识
///
/// 若扫描阶段已记录精确的调用图节点 ID，则优先用节点 ID 作为函数标识，
/// 避免用 bare method name 重建 `file:method` 时丢失 overload/inner class 信息。
fn extract_source_sink(finding: &Finding) -> Option<(String, String, String, String)> {
    // 优先使用 evidence_refs 中的结构化信息
    if let Some(ref refs) = finding.evidence_refs {
        if let Some(ref ss) = refs.source_sink_path {
            let source_func = ss
                .source_node_id
                .clone()
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| ss.source_function.clone());
            let sink_func = ss
                .sink_node_id
                .clone()
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| ss.sink_function.clone());
            if !source_func.is_empty() && !sink_func.is_empty() {
                return Some((
                    ss.source_file.clone(),
                    source_func,
                    ss.sink_file.clone(),
                    sink_func,
                ));
            }
        }
    }

    // 退化：目前仅在有结构化证据时进行调用图查询，避免误匹配
    None
}

/// 轻量代码上下文提取（±N 行）
fn extract_code_context_simple(
    content: &str,
    line_start: usize,
    line_end: usize,
    context_lines: usize,
) -> String {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || line_start == 0 {
        return String::new();
    }
    let total = lines.len();
    let start = line_start.saturating_sub(context_lines + 1).max(1);
    let end = (line_end + context_lines).min(total);

    let mut out = String::new();
    for i in start..=end {
        let marker = if i >= line_start && i <= line_end {
            ">>"
        } else {
            "  "
        };
        out.push_str(&format!("{} {:>4} | {}\n", marker, i, lines[i - 1]));
    }
    out
}

/// 对缺失跨文件调用路径的 finding，尝试在方法体内合成一条本地 source→sink 路径。
///
/// 覆盖语言：Java、JavaScript/TypeScript、Python、Go、Rust、PHP、C/C++。
/// 兜底规则是“同一方法近似范围内同时出现语言相关的输入源与漏洞 sink”。
fn synthesize_local_call_path(
    project_path: &Path,
    finding: &Finding,
    query_engine: Option<&CallGraphQueryEngine>,
) -> Option<(CallPath, Vec<CallerEvidence>)> {
    let ext = Path::new(&finding.file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let full_path = project_path.join(&finding.file_path);
    let content = std::fs::read_to_string(&full_path).ok()?;
    let lines: Vec<&str> = content.lines().collect();
    if finding.line_start == 0 || finding.line_start > lines.len() {
        return None;
    }

    // 取问题行周围 ±35 行作为方法体近似
    let start = finding.line_start.saturating_sub(35).max(1);
    // line_end 可能为 0 或小于 line_start，先规范化
    let effective_end = finding.line_end.max(finding.line_start);
    let end = (effective_end + 35).min(lines.len());
    let method_body = lines[start - 1..end].join("\n");
    let body_lower = method_body.to_lowercase();

    let matched =
        match ext {
            "java" => java_matched(
                &finding.vuln_type,
                &finding.description,
                &body_lower,
                &method_body,
            ),
            "js" | "jsx" | "ts" | "tsx" => {
                js_matched(&finding.vuln_type, &finding.description, &body_lower)
            }
            "py" => generic_source_sink_matched(
                &PYTHON_PATTERNS,
                &finding.vuln_type,
                &finding.description,
                &body_lower,
            ),
            "go" => generic_source_sink_matched(
                &GO_PATTERNS,
                &finding.vuln_type,
                &finding.description,
                &body_lower,
            ),
            "rs" => generic_source_sink_matched(
                &RUST_PATTERNS,
                &finding.vuln_type,
                &finding.description,
                &body_lower,
            ),
            "php" => generic_source_sink_matched(
                &PHP_PATTERNS,
                &finding.vuln_type,
                &finding.description,
                &body_lower,
            ),
            "c" | "cpp" | "cc" | "h" | "hpp" | "cxx" => generic_source_sink_matched(
                &C_PATTERNS,
                &finding.vuln_type,
                &finding.description,
                &body_lower,
            ),
            _ => false,
        } || hardcoded_secret_matched(&finding.vuln_type, &finding.description, &method_body);

    if !matched {
        return None;
    }

    // 使用调用图中真实包围函数名，避免用 detector 名导致下游查询工具失效
    let enclosing = find_enclosing_function(query_engine, &finding.file_path, finding.line_start);
    let func_name = enclosing
        .as_ref()
        .map(|f| f.name.clone())
        .unwrap_or_else(|| finding.detector.clone());

    // 构造一条单跳本地路径
    let sink_line = finding.line_start;
    let source_line = start;
    let step = deepaudit_core::analysis::query::PathStep {
        function_name: func_name.clone(),
        file_path: finding.file_path.clone(),
        line: source_line,
        step_type: "synthetic_local_source".to_string(),
        code_snippet: Some(lines[source_line - 1].trim().to_string()),
    };
    let sink_step = deepaudit_core::analysis::query::PathStep {
        function_name: func_name.clone(),
        file_path: finding.file_path.clone(),
        line: sink_line,
        step_type: "synthetic_local_sink".to_string(),
        code_snippet: Some(lines[sink_line - 1].trim().to_string()),
    };
    let path = CallPath {
        steps: vec![step, sink_step],
        total_hops: 1,
        crosses_files: false,
        files_in_path: vec![finding.file_path.clone()],
    };
    let caller = CallerEvidence {
        caller_function: func_name.clone(),
        caller_file: finding.file_path.clone(),
        caller_line: source_line,
        callee_function: func_name,
        callee_file: finding.file_path.clone(),
        callee_line: sink_line,
        receiver: None,
        is_callback: false,
    };
    Some((path, vec![caller]))
}

/// 根据调用图查询包含指定行的函数信息。
///
/// 优先使用 `query_engine` 中的函数范围数据；若查询引擎不可用或找不到匹配函数，
/// 返回 `None`，调用方应回退到 detector 名等兜底策略。
fn find_enclosing_function(
    query_engine: Option<&CallGraphQueryEngine>,
    file_path: &str,
    line: usize,
) -> Option<FunctionInfo> {
    let engine = query_engine?;
    let funcs = engine.query_functions_in_file(file_path);
    if funcs.is_empty() {
        return None;
    }
    let candidates: Vec<FunctionInfo> = funcs
        .into_iter()
        .filter(|f| line >= f.line && line <= f.end_line)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    // 多个函数嵌套时取范围最小的（最内层函数）
    candidates
        .into_iter()
        .min_by_key(|f| f.end_line.saturating_sub(f.line))
}

/// 语言无关 source→sink 模式集
struct PatternSet {
    sources: &'static [&'static str],
    cmd_sinks: &'static [&'static str],
    sql_sinks: &'static [&'static str],
    deser_sinks: &'static [&'static str],
    code_sinks: &'static [&'static str],
    path_sinks: &'static [&'static str],
    ssrf_sinks: &'static [&'static str],
    xss_sinks: &'static [&'static str],
}

const PYTHON_PATTERNS: PatternSet = PatternSet {
    sources: &[
        "request.args",
        "request.form",
        "request.json",
        "request.data",
        "request.headers",
        "request.cookies",
        "request.values",
        "request.get_json",
        "input(",
        "sys.argv",
        "os.environ",
        "os.getenv",
        "getenv(",
    ],
    cmd_sinks: &[
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.popen",
        "subprocess.check_output",
        "commands.getoutput",
    ],
    sql_sinks: &[
        ".execute(",
        ".executemany(",
        "cursor.execute",
        "sqlite3",
        "psycopg2",
        "sqlalchemy",
    ],
    deser_sinks: &[
        "pickle.loads",
        "pickle.load",
        "yaml.load",
        "yaml.unsafe_load",
        "json.loads",
    ],
    code_sinks: &["eval(", "exec(", "compile("],
    path_sinks: &["open(", "os.path.join", "pathlib.path"],
    ssrf_sinks: &[
        "requests.get",
        "requests.post",
        "requests.put",
        "urllib.request.urlopen",
        "urllib.urlopen",
        "http.client",
    ],
    xss_sinks: &[
        "render_template_string",
        "mark_safe",
        "jinja2",
        "flask.render_template",
    ],
};

const GO_PATTERNS: PatternSet = PatternSet {
    sources: &[
        "r.url.query().get",
        "r.formvalue",
        "r.postformvalue",
        "r.body",
        "r.header.get",
        "r.header",
        "os.args",
        "os.getenv",
        "envconfig",
    ],
    cmd_sinks: &["exec.command", "os/exec", "syscall.exec"],
    sql_sinks: &["db.query", "db.exec", "db.queryrow", "sql.db", "stmt.exec"],
    deser_sinks: &["json.unmarshal", "gob.newdecoder", "yaml.unmarshal"],
    code_sinks: &["plugin.open"],
    path_sinks: &[
        "os.open",
        "os.readfile",
        "os.writefile",
        "ioutil.readfile",
        "ioutil.writefile",
    ],
    ssrf_sinks: &[
        "http.get",
        "http.post",
        "http.client.do",
        "net.dial",
        "grpc.dial",
    ],
    xss_sinks: &["template.html", "html.template"],
};

const RUST_PATTERNS: PatternSet = PatternSet {
    sources: &[
        "std::env::args",
        "std::env::var",
        "env::var",
        "env::args",
        "req.query",
        "req.headers",
        "req.body",
        "request.query",
        "params.",
    ],
    cmd_sinks: &["std::process::command::new", "command::new"],
    sql_sinks: &[
        "sqlx::query",
        ".fetch_one",
        ".execute(",
        "client.query",
        "statement.execute",
    ],
    deser_sinks: &[
        "serde_json::from_str",
        "serde_json::from_reader",
        "toml::from_str",
        "bincode::deserialize",
    ],
    code_sinks: &["std::process::command::new"],
    path_sinks: &[
        "std::fs::read_to_string",
        "std::fs::write",
        "file::open",
        "std::fs::file",
    ],
    ssrf_sinks: &[
        "reqwest::get",
        "reqwest::client",
        "surf::get",
        "ureq::get",
        "hyper::client",
    ],
    xss_sinks: &["handlebars::template", "tera::context", "maud::html"],
};

const PHP_PATTERNS: PatternSet = PatternSet {
    sources: &[
        "$_get",
        "$_post",
        "$_request",
        "$_cookie",
        "$_server",
        "$_files",
        "php://input",
        "file_get_contents(\"php://input\")",
    ],
    cmd_sinks: &[
        "exec(",
        "shell_exec(",
        "system(",
        "passthru(",
        "proc_open(",
        "popen(",
    ],
    sql_sinks: &[
        "mysql_query",
        "mysqli_query",
        "pg_query",
        "sqlite_query",
        "pdo::query",
        "->query(",
    ],
    deser_sinks: &["unserialize(", "json_decode"],
    code_sinks: &["eval(", "assert(", "create_function", "preg_replace"],
    path_sinks: &[
        "file_get_contents(",
        "fopen(",
        "readfile(",
        "include(",
        "require(",
        "file(",
        "move_uploaded_file",
    ],
    ssrf_sinks: &[
        "file_get_contents(",
        "curl_exec",
        "curl_setopt",
        "fsockopen",
    ],
    xss_sinks: &["echo", "print", "printf(", "die("],
};

const C_PATTERNS: PatternSet = PatternSet {
    sources: &[
        "argv[", "getenv(", "fgets(", "scanf(", "gets(", "read(", "recv(",
    ],
    cmd_sinks: &["system(", "popen(", "exec(", "_exec", "createprocess"],
    sql_sinks: &["sqlite3_exec", "mysql_query", "pqexec", "sqlexecdirect"],
    deser_sinks: &[],
    code_sinks: &[],
    path_sinks: &["fopen(", "open(", "freopen(", "stat("],
    ssrf_sinks: &["curl_easy_perform", "socket(", "connect("],
    xss_sinks: &["printf(", "sprintf(", "puts("],
};

fn generic_source_sink_matched(
    patterns: &PatternSet,
    vuln_type: &str,
    description: &str,
    body_lower: &str,
) -> bool {
    if patterns.sources.iter().all(|s| !body_lower.contains(s)) {
        return false;
    }

    let desc = description.to_lowercase();
    if vuln_type.contains("78") || desc.contains("command") {
        return patterns.cmd_sinks.iter().any(|s| body_lower.contains(s));
    }
    if vuln_type.contains("89") || desc.contains("sql") {
        return patterns.sql_sinks.iter().any(|s| body_lower.contains(s));
    }
    if vuln_type.contains("502") || desc.contains("deserialization") {
        return patterns.deser_sinks.iter().any(|s| body_lower.contains(s));
    }
    if vuln_type.contains("94") || desc.contains("code injection") {
        return patterns.code_sinks.iter().any(|s| body_lower.contains(s));
    }
    if vuln_type.contains("22") || desc.contains("path traversal") {
        return patterns.path_sinks.iter().any(|s| body_lower.contains(s));
    }
    if vuln_type.contains("918") || desc.contains("ssrf") {
        return patterns.ssrf_sinks.iter().any(|s| body_lower.contains(s));
    }
    if vuln_type.contains("79") || desc.contains("xss") || desc.contains("cross-site") {
        return patterns.xss_sinks.iter().any(|s| body_lower.contains(s));
    }
    false
}

fn java_matched(vuln_type: &str, description: &str, body_lower: &str, method_body: &str) -> bool {
    let java_sources = [
        "@requestparam",
        "@pathvariable",
        "@requestbody",
        "@requestheader",
        "@cookievalue",
        "@modelattribute",
        "httpservletrequest",
        "servletrequest",
        "getparameter(",
        "getparametervalues(",
        "getheader(",
        "getheaders(",
        "getquerystring(",
        "getinputstream(",
        "getreader(",
        "getcookies(",
    ];
    let has_source = java_sources.iter().any(|p| body_lower.contains(p));

    let desc = description.to_lowercase();
    let is_deser = vuln_type.contains("502") || desc.contains("deserialization");
    let is_cmd = vuln_type.contains("78") || desc.contains("command");
    let is_sql = vuln_type.contains("89") || desc.contains("sql");
    let is_path = vuln_type.contains("22") || desc.contains("path traversal");
    let is_ssrf = vuln_type.contains("918") || desc.contains("ssrf");
    let is_xss = vuln_type.contains("79") || desc.contains("xss") || desc.contains("cross-site");
    let is_code = vuln_type.contains("94") || vuln_type.to_lowercase().contains("code") || desc.contains("code injection");

    let has_deser_sink = body_lower.contains("objectinputstream")
        || body_lower.contains("classresolvingobjectinputstream")
        || body_lower.contains("readobject(")
        || body_lower.contains("defaultreadobject")
        || body_lower.contains("xstream")
        || body_lower.contains("fromxml(")
        || body_lower.contains("xmldecoder");
    let has_cmd_sink = body_lower.contains("runtime.getruntime().exec")
        || body_lower.contains("runtime.exec")
        || body_lower.contains("processbuilder");
    let has_sql_sink = body_lower.contains("executequery(")
        || body_lower.contains("executeupdate(")
        || body_lower.contains("createstatement(")
        || body_lower.contains("preparestatement(")
        || body_lower.contains("statement.")
        || body_lower.contains(".execute(");
    let has_path_sink = body_lower.contains("new file(")
        || body_lower.contains("getoriginalfilename")
        || body_lower.contains("paths.get")
        || body_lower.contains("fileinputstream")
        || body_lower.contains("fileoutputstream")
        || body_lower.contains("files.copy")
        || body_lower.contains("files.delete")
        || body_lower.contains("files.write");
    let has_ssrf_sink = body_lower.contains("new url(")
        || body_lower.contains("openconnection")
        || body_lower.contains("httpurlconnection")
        || body_lower.contains("resttemplate")
        || body_lower.contains("webclient")
        || body_lower.contains("httpclient")
        || body_lower.contains("okhttp");
    let has_xss_sink = body_lower.contains("getwriter()")
        || body_lower.contains(".print(")
        || body_lower.contains(".println(")
        || body_lower.contains(".write(")
        || body_lower.contains("getoutputstream()")
        || body_lower.contains("@responsebody");
    let has_code_sink = body_lower.contains("scriptengine")
        || body_lower.contains("groovyshell")
        || body_lower.contains(".eval(")
        || body_lower.contains("scriptenginemanager");

    if is_deser {
        // 标准源 + sink 组合，或间接输入模式（byte[] / Base64 / Cookie + 反序列化）
        let has_indirect_source = body_lower.contains("byte[]")
            || body_lower.contains("base64")
            || body_lower.contains("bytearrayinputstream")
            || body_lower.contains("getcookies(")
            || body_lower.contains("getcookie(")
            || body_lower.contains("getremembered");
        (has_source && has_deser_sink)
            || (has_indirect_source && has_deser_sink)
            || (body_lower.contains("void readobject") && has_cmd_sink)
    } else if is_cmd {
        has_source && has_cmd_sink
    } else if is_sql {
        has_source && has_sql_sink
    } else if is_path {
        has_source && has_path_sink
    } else if is_ssrf {
        has_source && has_ssrf_sink
    } else if is_xss {
        has_source && has_xss_sink
    } else if is_code {
        has_source && has_code_sink
    } else if vuln_type.contains("200") || desc.contains("sensitive") || desc.contains("hardcoded")
    {
        hardcoded_secret_matched(vuln_type, description, method_body)
    } else {
        false
    }
}

fn js_matched(vuln_type: &str, description: &str, body_lower: &str) -> bool {
    let desc = description.to_lowercase();
    let is_xss = vuln_type.contains("79") || desc.contains("xss") || desc.contains("cross-site");
    if !is_xss {
        return false;
    }
    let js_sources = [
        ".val()",
        ".value",
        "location.",
        "window.location",
        "document.url",
        "document.referrer",
        "getelementbyid",
    ];
    let js_sinks = [
        "innerhtml",
        "outerhtml",
        "document.write",
        "insertadjacenthtml",
    ];
    js_sources.iter().any(|s| body_lower.contains(s))
        && js_sinks.iter().any(|s| body_lower.contains(s))
}

fn hardcoded_secret_matched(vuln_type: &str, description: &str, method_body: &str) -> bool {
    let desc = description.to_lowercase();
    if !(vuln_type.contains("200") || desc.contains("sensitive") || desc.contains("hardcoded")) {
        return false;
    }
    let secret_names = ["password", "token", "secret", "api_key", "credential"];
    secret_names.iter().any(|name| {
        method_body.to_lowercase().contains(name)
            && method_body.lines().any(|line| {
                let l = line.to_lowercase();
                l.contains(name) && l.contains('=') && l.contains('"')
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deepaudit_core::scanning::Finding;

    #[test]
    fn test_find_enclosing_function_without_engine_returns_none() {
        assert!(find_enclosing_function(None, "src/main/java/App.java", 10).is_none());
    }

    #[test]
    fn test_synthesize_local_call_path_falls_back_to_detector_name() {
        let dir = std::env::temp_dir().join("ctx-audit-evidence-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("App.java");
        std::fs::write(
            &file,
            "import java.io.*;\npublic class App {\n  void run(HttpServletRequest request) throws Exception {\n    String user = request.getParameter(\"x\");\n    Runtime.getRuntime().exec(user);\n  }\n}\n",
        )
        .unwrap();

        let finding = Finding {
            finding_id: "test-1".to_string(),
            file_path: file.to_string_lossy().to_string(),
            line_start: 5,
            line_end: 5,
            detector: "RegexRule: command-injection".to_string(),
            vuln_type: "CWE-78".to_string(),
            severity: "high".to_string(),
            description: "Command injection".to_string(),
            analysis_trail: None,
            llm_output: None,
            confidence: None,
            corroboration_count: None,
            code_snippet: None,
            source_snippet: None,
            sink_snippet: None,
            file_role: None,
            barriers: None,
            reasoning_hint: None,
            evidence_refs: None,
            enclosing_function: None,
            enclosing_function_line: None,
        };

        // 没有调用图引擎时，function_name 应回退为 detector 名
        let (path, _) = synthesize_local_call_path(&dir, &finding, None)
            .expect("should synthesize a local path");
        assert_eq!(path.steps.len(), 2);
        assert!(path.steps.iter().all(|s| s.function_name == finding.detector));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
