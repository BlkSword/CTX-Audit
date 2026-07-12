// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 本地 source→sink 模式匹配
//!
//! 用于在扫描阶段为 RegexRule/ASTRule 命中补充轻量结构化证据：
//! 在 sink 所在位置 ±35 行窗口内检测语言相关的输入源与漏洞 sink 共现，
//! 生成 `SourceSinkEvidence` 所需的 source 位置信息。

use std::path::Path;

/// 本地 source→sink 匹配结果
#[derive(Debug, Clone)]
pub struct LocalSourceSinkMatch {
    /// 检测到的输入源模式（如 "@RequestParam"）
    pub source_pattern: String,
    /// 输入源所在行号（1-based）
    pub source_line: usize,
}

/// 在指定文件内容中，以 sink_line 为中心 ±35 行窗口内检测 source→sink 共现。
///
/// 仅覆盖有明确 source/sink 语义的语言与漏洞类型：
/// Java（反序列化、命令注入）、JS/TS（XSS）、Python/Go/Rust/PHP/C（多种注入）。
pub fn find_local_source_sink(
    file_path: &str,
    vuln_type: &str,
    description: &str,
    content: &str,
    sink_line: usize,
) -> Option<LocalSourceSinkMatch> {
    let ext = Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let lines: Vec<&str> = content.lines().collect();
    if sink_line == 0 || sink_line > lines.len() {
        return None;
    }

    let start = sink_line.saturating_sub(35).max(1);
    let end = (sink_line + 35).min(lines.len());
    let window_lines = &lines[start - 1..end];
    let window_lower = window_lines.join("\n").to_lowercase();

    let matched_sources: Vec<&'static str> = match ext {
        "java" => java_match_sources(vuln_type, description, &window_lower),
        "js" | "jsx" | "ts" | "tsx" => js_match_sources(vuln_type, description, &window_lower),
        "py" => generic_match_sources(&PYTHON_PATTERNS, vuln_type, description, &window_lower),
        "go" => generic_match_sources(&GO_PATTERNS, vuln_type, description, &window_lower),
        "rs" => generic_match_sources(&RUST_PATTERNS, vuln_type, description, &window_lower),
        "php" => generic_match_sources(&PHP_PATTERNS, vuln_type, description, &window_lower),
        "c" | "cpp" | "cc" | "h" | "hpp" | "cxx" => {
            generic_match_sources(&C_PATTERNS, vuln_type, description, &window_lower)
        }
        _ => Vec::new(),
    };

    if matched_sources.is_empty() {
        return None;
    }

    // 在所有命中 source 模式里，取离 sink 最近的那一行作为证据源，
    // 这样更可能对应实际流入 sink 的入口参数。
    let mut best: Option<(usize, usize, &str)> = None; // (distance, line, pattern)
    for source in matched_sources {
        let pattern_lower = source.to_lowercase();
        for (idx, line) in window_lines.iter().enumerate() {
            if line.to_lowercase().contains(&pattern_lower) {
                let actual_line = start + idx;
                let dist = actual_line.abs_diff(sink_line);
                let should_replace = match best {
                    None => true,
                    Some((best_dist, _, _)) => dist < best_dist,
                };
                if should_replace {
                    best = Some((dist, actual_line, source));
                }
            }
        }
    }

    best.map(|(_, source_line, source_pattern)| LocalSourceSinkMatch {
        source_pattern: source_pattern.to_string(),
        source_line,
    })
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

fn source_patterns_in_window(
    haystack_lower: &str,
    patterns: &[&'static str],
) -> Vec<&'static str> {
    patterns
        .iter()
        .filter(|p: &&&str| haystack_lower.contains(&p.to_lowercase()))
        .copied()
        .collect()
}

fn generic_match_sources(
    patterns: &PatternSet,
    vuln_type: &str,
    description: &str,
    body_lower: &str,
) -> Vec<&'static str> {
    let desc = description.to_lowercase();
    let sinks = if vuln_type.contains("78") || desc.contains("command") {
        patterns.cmd_sinks
    } else if vuln_type.contains("89") || desc.contains("sql") {
        patterns.sql_sinks
    } else if vuln_type.contains("502") || desc.contains("deserialization") {
        patterns.deser_sinks
    } else if vuln_type.contains("94") || desc.contains("code injection") {
        patterns.code_sinks
    } else if vuln_type.contains("22") || desc.contains("path traversal") {
        patterns.path_sinks
    } else if vuln_type.contains("918") || desc.contains("ssrf") {
        patterns.ssrf_sinks
    } else if vuln_type.contains("79") || desc.contains("xss") || desc.contains("cross-site") {
        patterns.xss_sinks
    } else {
        return Vec::new();
    };

    let sink_hit = sinks.iter().any(|s| body_lower.contains(&s.to_lowercase()));
    if !sink_hit {
        return Vec::new();
    }

    source_patterns_in_window(body_lower, patterns.sources)
}

const JAVA_SOURCES: &[&str] = &[
    "@RequestParam",
    "@PathVariable",
    "@RequestBody",
    "@RequestHeader",
    "@CookieValue",
    "@ModelAttribute",
    "HttpServletRequest",
    "ServletRequest",
    "getParameter(",
    "getParameterValues(",
    "getHeader(",
    "getHeaders(",
    "getQueryString(",
    "getInputStream(",
    "getReader(",
    "getCookies(",
];

fn java_match_sources(
    vuln_type: &str,
    description: &str,
    body_lower: &str,
) -> Vec<&'static str> {
    let desc = description.to_lowercase();
    let is_deser = vuln_type.contains("502") || desc.contains("deserialization");
    let is_cmd = vuln_type.contains("78") || desc.contains("command");
    let is_sql = vuln_type.contains("89") || desc.contains("sql");
    let is_path = vuln_type.contains("22") || desc.contains("path traversal");
    let is_ssrf = vuln_type.contains("918") || desc.contains("ssrf");
    let is_xss = vuln_type.contains("79") || desc.contains("xss") || desc.contains("cross-site");
    let is_code = vuln_type.contains("94") || desc.contains("code injection");

    let sink_matches = if is_deser {
        body_lower.contains("objectinputstream")
            || body_lower.contains("readobject(")
            || body_lower.contains("defaultreadobject")
            || body_lower.contains("xstream")
            || body_lower.contains("fromxml(")
            || body_lower.contains("xmldecoder")
            || body_lower.contains("classresolvingobjectinputstream")
            || (body_lower.contains("void readobject")
                && (body_lower.contains("runtime.getruntime().exec")
                    || body_lower.contains("runtime.exec")
                    || body_lower.contains("processbuilder")))
    } else if is_cmd {
        body_lower.contains("runtime.getruntime().exec")
            || body_lower.contains("runtime.exec")
            || body_lower.contains("processbuilder")
    } else if is_sql {
        body_lower.contains("executequery(")
            || body_lower.contains("executeupdate(")
            || body_lower.contains("createstatement(")
            || body_lower.contains("preparestatement(")
            || body_lower.contains("statement.")
            || body_lower.contains(".execute(")
    } else if is_path {
        body_lower.contains("new file(")
            || body_lower.contains("getoriginalfilename")
            || body_lower.contains("paths.get")
            || body_lower.contains("fileinputstream")
            || body_lower.contains("fileoutputstream")
            || body_lower.contains("files.copy")
            || body_lower.contains("files.delete")
            || body_lower.contains("files.write")
    } else if is_ssrf {
        body_lower.contains("new url(")
            || body_lower.contains("openconnection")
            || body_lower.contains("httpurlconnection")
            || body_lower.contains("resttemplate")
            || body_lower.contains("webclient")
            || body_lower.contains("httpclient")
            || body_lower.contains("okhttp")
    } else if is_xss {
        body_lower.contains("getwriter()")
            || body_lower.contains(".print(")
            || body_lower.contains(".println(")
            || body_lower.contains(".write(")
            || body_lower.contains("getoutputstream()")
            || body_lower.contains("@responsebody")
    } else if is_code {
        body_lower.contains("scriptengine")
            || body_lower.contains("groovyshell")
            || body_lower.contains(".eval(")
            || body_lower.contains("scriptenginemanager")
    } else {
        false
    };

    if !sink_matches {
        return Vec::new();
    }

    let sources = source_patterns_in_window(body_lower, JAVA_SOURCES);

    // 反序列化: 如果标准 HTTP source 未命中，尝试间接输入模式 —
    // byte[] 参数、Base64 解码、ByteArrayInputStream、Cookie 读取等。
    if is_deser && sources.is_empty() {
        const DESER_INDIRECT: &[&str] = &[
            "base64.getdecoder().decode",
            "base64.decode",
            "bytearrayinputstream",
            "getcookies(",
            "getcookie(",
            "getremembered",
            "getinputstream(",
            "getreader(",
            "serialized",
            "deserialize(",
        ];
        return source_patterns_in_window(body_lower, DESER_INDIRECT);
    }

    sources
}

fn js_match_sources(
    vuln_type: &str,
    description: &str,
    body_lower: &str,
) -> Vec<&'static str> {
    let desc = description.to_lowercase();
    let is_xss = vuln_type.contains("79") || desc.contains("xss") || desc.contains("cross-site");
    if !is_xss {
        return Vec::new();
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

    let sink_hit = js_sinks.iter().any(|s| body_lower.contains(*s));
    if !sink_hit {
        return Vec::new();
    }

    source_patterns_in_window(body_lower, &js_sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_local_source_sink_java_command_injection() {
        let content = r#"public class App {
  void run(HttpServletRequest request) throws Exception {
    String user = request.getParameter("x");
    Runtime.getRuntime().exec(user);
  }
}
"#;
        // 离 sink（line 4，Runtime.getRuntime().exec）最近的 source 是 line 3 的 getParameter
        let m = find_local_source_sink("App.java", "CWE-78", "Command injection", content, 4)
            .expect("should match");
        assert_eq!(m.source_pattern, "getParameter(");
        assert_eq!(m.source_line, 3);
    }

    #[test]
    fn test_find_local_source_sink_java_deserialization() {
        let content = r#"public class App {
  void process(@RequestBody String body) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body.getBytes()));
    ois.readObject();
  }
}
"#;
        let m = find_local_source_sink("App.java", "CWE-502", "Unsafe deserialization", content, 4)
            .expect("should match");
        assert_eq!(m.source_pattern, "@RequestBody");
        assert_eq!(m.source_line, 2);
    }

    #[test]
    fn test_find_local_source_sink_no_match() {
        let content = r#"public class App {
  void run() {
    System.out.println("hello");
  }
}
"#;
        assert!(find_local_source_sink("App.java", "CWE-78", "Command injection", content, 4).is_none());
    }
}
