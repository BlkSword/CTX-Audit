//! 验签顺序分析器（VerificationOrderAnalyzer）
//!
//! 机制类：**入站 handler 在完成签名验证之前，就对"请求可控 URL"发起出站抓取**
//! （verify-before-dereference 违例，CWE-918 + CWE-306）。
//!
//! 这是控制流时序问题：规则/污点的 source→sink 模型表达不了"抓取早于验签"，
//! 差分 oracle 的实测也证实引擎对 5 个已知正例 0 命中（期望行 ±20 内 0 条）。
//! 因此单列一个按函数体行序判定的分析器，接在 Stage B（enable_taint）里。
//!
//! 判定（v1.1，两段式收紧）：
//!   1. handler 判定分强/弱：函数名命中 inbox/webhook/signature/federation/activitypub/verify
//!      为强信号；命中 handle/handler/receive/callback/controller/endpoint 或文件路径命中
//!      views/handlers/routes/controllers/api/functions/inbox 为弱信号，弱信号必须同时满足
//!      "文件内存在验签调用"且"函数体出现请求对象"（req/request/ctx/event/...）；
//!   2. 函数体内存在出站抓取调用行，且该行含强输入标识（keyId/actor/signature/remote_id/...）；
//!      弱输入标识（url/uri/instance/object/...）仅在文件内有验签代码时接受；
//!   3. 最早的抓取行早于最早的验签行（或无验签行）。
//! 产物：`detector=VerificationOrderAnalyzer`，`vuln_type=SSRF`，`severity=medium`。
//!
//! 明确局限（v1）：只做同函数行序，不做跨函数调用序；marker 表是人工维护的
//! 常见形态（与 pilot 的 ordering oracle 同源），通过不同的语言/框架可继续扩展。
//! v1.1 的收紧用于压低"项目根本不用 HTTP 签名"时的误报（如内部监控抓取、
//! Express 元数据代理、单例 getInstance 等），代价是可能漏掉弱命名但真实的 handler。

use crate::ast::symbol::FunctionBody;
use crate::scanner::{stable_finding_id, EvidenceRefs, Finding};
use regex::RegexSet;
use std::sync::OnceLock;

/// 出站抓取调用形态（小写子串匹配）
const FETCH_MARKERS: &[&str] = &[
    // Python
    "requests.get",
    "requests.post",
    "requests.head",
    "requests.request",
    "session.get",
    "session.post",
    "httpx.",
    "aiohttp",
    "urlopen",
    // JS/TS
    "axios(",
    "axios.get",
    "axios.post",
    "fetch(",
    // Go
    "http.get(",
    "http.post(",
    "http.newrequest",
    "httpclient",
    "http_client",
    "client.do(",
    // Rust
    "reqwest",
    "hyper::",
    "ureq",
    "isahc",
    // Elixir / Erlang
    "tesla.",
    "httpoison.",
    "finch.",
    "mint.http",
    ":httpc.request",
    // PHP
    "curl_init",
    "file_get_contents",
    // 领域包装器（联邦/社交/通用抓取）
    "getactor(",
    "get_actor(",
    "getnodeinfo(",
    "get_node_info(",
    "getpersonpubkey(",
    "resolve_remote_id(",
    "actor_request(",
    "xs_http_request(",
    "activityrequest",
    "actoridresolver",
    "federationagent",
    "apclient",
    "fetch_object",
    "fetch_json",
    "fetch_remote_object",
    "fetch_remote_actor",
    "fetch_remote_activity",
    "get_remote_object",
    "get_remote_actor",
    "get_remote_activity",
    "perform_request(",
];

/// 签名验证调用形态（小写子串匹配）
const VERIFY_MARKERS: &[&str] = &[
    "verifysignature",
    "verify_signature",
    "verify_http_signature",
    "verifypostheaders",
    "verify_post_headers",
    "verifypostheader",
    "has_valid_signature",
    "checksignature",
    "check_signature",
    "validatesignature",
    "validate_signature",
    "signature.verify",
    ".verified(",
    "verify_request",
    "verify_signed_request",
    "xs_evp_verify",
    "httpsig.verify",
    "crypto.verify",
    ":public_key.verify",
    "http_signature.verify",
    "ldsignature.verify",
];

/// handler 强形态：函数名本身表明这是入站联邦/签名处理面（直接成立）
const STRONG_HANDLER_MARKERS: &[&str] = &[
    "inbox",
    "webhook",
    "signature",
    "federation",
    "fediverse",
    "activitypub",
    "verify",
];

/// handler 弱形态：必须同时满足"文件内有验签调用 + 函数体出现请求对象"才成立
const WEAK_HANDLER_MARKERS: &[&str] = &[
    "handle",
    "handler",
    "receive",
    "callback",
    "controller",
    "endpoint",
];

/// 仅凭文件路径命中 handler 目录时，排除明显是内部 helper 的函数名（否则 inbox.py 里的
/// getActor / fetch_remote_object 等工具函数会被当成 handler 误报）。名字本身命中
/// HANDLER_MARKERS 时不受此限制（如 has_valid_signature 就是受害函数本身）。
const PATH_ONLY_HELPER_PREFIXES: &[&str] = &[
    "get",
    "fetch",
    "resolve",
    "load",
    "read",
    "parse",
    "build",
    "create",
    "make",
    "send",
    "sign",
    "verify",
    "check",
    "validate",
    "find",
    "extract",
    "format",
    "cache",
    "refresh",
    "update",
    "store",
    "save",
    "request",
    "client",
    "upload",
    "register",
    "init",
    "start",
    "list",
    "search",
    "query",
];

/// 文件路径里的 handler 目录
const HANDLER_PATH_MARKERS: &[&str] = &[
    "/views/",
    "/handlers/",
    "/handler/",
    "/routes/",
    "/controllers/",
    "/controller/",
    "/api/",
    "/functions/",
    "inbox",
];

/// 强输入标识：请求可控且带身份/签名语义（抓取行命中即成立）
const STRONG_INPUT_MARKERS: &[&str] = &[
    "keyid",
    "key_id",
    "actor",
    "signature",
    "remote_id",
    "signer",
    "webfinger",
    "publickey",
    "public_key",
    "inbox",
];

/// 弱输入标识：仅在"文件内有验签代码"时接受（url/uri 等过于宽泛，单独出现多为内部抓取）
const WEAK_INPUT_MARKERS: &[&str] = &[
    "url",
    "uri",
    "href",
    "instance",
    "object",
    "document",
    "activity",
];

/// 请求对象证据：弱 handler 必须真的在函数体里拿到入站请求对象
const REQUEST_EVIDENCE: &[&str] = &[
    "(req",
    "req.",
    "req,",
    "req)",
    "req;",
    "req ",
    "(request",
    "request.",
    "request,",
    "request)",
    "request;",
    "$request",
    "http.request",
    "httpservletrequest",
    "incomingmessage",
    "ctx.",
    "event.",
    "event,",
    "requestbody",
];

fn has_request_evidence_lower(lower: &str) -> bool {
    REQUEST_EVIDENCE.iter().any(|m| lower.contains(m))
}

/// 标记表 → 大小写不敏感的 RegexSet：预过滤一次扫描替代逐 marker 的 contains，
/// 且无需为整文件分配小写副本（RegexSet 只构建一次）。
fn marker_set(patterns: &[&str]) -> RegexSet {
    let pats: Vec<String> = patterns
        .iter()
        .map(|p| format!("(?i){}", regex::escape(p)))
        .collect();
    RegexSet::new(pats).expect("verification_order marker set")
}

fn fetch_marker_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| marker_set(FETCH_MARKERS))
}

fn verify_marker_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| marker_set(VERIFY_MARKERS))
}

fn strong_handler_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| marker_set(STRONG_HANDLER_MARKERS))
}

fn weak_handler_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| marker_set(WEAK_HANDLER_MARKERS))
}

fn request_evidence_set() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| marker_set(REQUEST_EVIDENCE))
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("/test")
        || lower.contains("/spec")
        || lower.contains(".spec.")
        || lower.contains(".test.")
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.go")
        || lower.ends_with("_test.rs")
}

/// 预过滤：文件是否具备命中本机制的"必要条件"。
///
/// 都是 finding 的必要条件，供调用方决定是否值得为它付出解析成本：
///   1) 路径命中 handler 目录；或内容含强 handler 标记（inbox/signature/...）；
///   2) 弱 handler（handle/handler/controller/...）+ 文件内有验签代码 + 内容有请求对象；
///   3) 内容含抓取标记。
pub fn is_candidate_file(file_path: &str, content: &str) -> bool {
    let path = std::path::Path::new(file_path);
    if !crate::scanner::is_ast_supported_file(path) {
        return false;
    }
    if is_test_path(file_path) {
        return false;
    }
    let path_lower = file_path.to_ascii_lowercase();
    let file_has_verify = verify_marker_set().is_match(content);
    let path_handler_possible = HANDLER_PATH_MARKERS.iter().any(|m| path_lower.contains(m));
    let strong_handler_possible = strong_handler_set().is_match(content);
    let weak_handler_possible = weak_handler_set().is_match(content)
        && file_has_verify
        && request_evidence_set().is_match(content);
    (path_handler_possible || strong_handler_possible || weak_handler_possible)
        && fetch_marker_set().is_match(content)
}

/// 对**已解析**的函数体做判定（Stage B 复用它同一次 AST 解析的结果，避免二次解析）。
pub fn analyze_bodies(
    file_path: &str,
    content: &str,
    bodies: &[FunctionBody],
) -> Vec<Finding> {
    if !is_candidate_file(file_path, content) {
        return Vec::new();
    }
    let file_has_verify = verify_marker_set().is_match(content);
    let mut out = Vec::new();
    for body in bodies {
        if let Some(finding) = analyze_function(file_path, body, file_has_verify) {
            out.push(finding);
        }
    }
    out
}

/// 分析单个文件：自行解析后返回 verify-before-dereference 违例 findings。
/// 已有函数体时优先用 [`analyze_bodies`] 复用解析结果。
pub fn analyze_file(file_path: &str, content: &str) -> Vec<Finding> {
    if !is_candidate_file(file_path, content) {
        return Vec::new();
    }
    let path = std::path::Path::new(file_path);
    let bodies = crate::ast::parser::with_thread_local_parser(|parser| {
        parser.extract_function_bodies(path, content)
    });
    analyze_bodies(file_path, content, &bodies)
}

fn analyze_function(
    file_path: &str,
    body: &FunctionBody,
    file_has_verify: bool,
) -> Option<Finding> {
    let name_lower = body.name.to_ascii_lowercase();
    let path_lower = file_path.to_ascii_lowercase();
    let strong_handler = STRONG_HANDLER_MARKERS.iter().any(|m| name_lower.contains(m));
    let helper_name = PATH_ONLY_HELPER_PREFIXES
        .iter()
        .any(|p| name_lower.starts_with(p));
    let weak_handler = !helper_name
        && (WEAK_HANDLER_MARKERS.iter().any(|m| name_lower.contains(m))
            || HANDLER_PATH_MARKERS.iter().any(|m| path_lower.contains(m)));
    let handler_like = strong_handler
        || (weak_handler
            && file_has_verify
            && has_request_evidence_lower(&body.body_text.to_ascii_lowercase()));
    if !handler_like {
        return None;
    }

    let mut first_fetch: Option<(usize, String)> = None;
    let mut first_verify: Option<(usize, String)> = None;
    for (idx, raw_line) in body.body_text.lines().enumerate() {
        let line_no = body.body_start_line + idx;
        let line_lower = raw_line.to_ascii_lowercase();
        if first_verify.is_none() && VERIFY_MARKERS.iter().any(|m| line_lower.contains(m)) {
            first_verify = Some((line_no, raw_line.trim().to_string()));
        }
        if first_fetch.is_none()
            && FETCH_MARKERS.iter().any(|m| line_lower.contains(m))
            && (STRONG_INPUT_MARKERS.iter().any(|m| line_lower.contains(m))
                || (file_has_verify
                    && WEAK_INPUT_MARKERS.iter().any(|m| line_lower.contains(m))))
        {
            first_fetch = Some((line_no, raw_line.trim().to_string()));
        }
    }

    let (fetch_line, fetch_text) = first_fetch?;
    let verify_line = first_verify.as_ref().map(|(l, _)| *l);
    let order_violation = match verify_line {
        Some(v) => fetch_line < v,
        None => true,
    };
    if !order_violation {
        return None;
    }

    let line_end = match verify_line {
        Some(v) if v >= fetch_line => v,
        _ => fetch_line,
    };
    let description = match verify_line {
        Some(v) => format!(
            "Signature verification ordering: outbound fetch at line {} precedes signature \
             verification at line {} in function '{}' — an unauthenticated request can trigger \
             an attacker-controlled outbound request (SSRF) before the signature is verified.",
            fetch_line, v, body.name
        ),
        None => format!(
            "Signature verification missing: outbound fetch at line {} in function '{}' has no \
             signature verification in the same function — an unauthenticated request can trigger \
             an attacker-controlled outbound request (SSRF).",
            fetch_line, body.name
        ),
    };

    let snippet_key = format!(
        "VerificationOrderAnalyzer:{}:{}:{}",
        body.name,
        fetch_line,
        verify_line.unwrap_or(0)
    );
    Some(Finding {
        finding_id: stable_finding_id(file_path, fetch_line, 0, "SSRF", &snippet_key),
        file_path: file_path.to_string(),
        line_start: fetch_line,
        line_end,
        detector: "VerificationOrderAnalyzer".to_string(),
        vuln_type: "SSRF".to_string(),
        severity: "medium".to_string(),
        description,
        analysis_trail: Some(vec![
            format!("fetch@{}: {}", fetch_line, fetch_text),
            match verify_line {
                Some(v) => format!("verify@{} (after fetch)", v),
                None => "verify: missing in function".to_string(),
            },
        ]),
        llm_output: None,
        confidence: Some(0.6),
        corroboration_count: None,
        code_snippet: None,
        source_snippet: Some(fetch_text),
        sink_snippet: first_verify.as_ref().map(|(_, t)| t.clone()),
        file_role: None,
        barriers: None,
        reasoning_hint: Some(
            "fetch-before-verify ordering (CWE-918/CWE-306); 由 VerificationOrderAnalyzer \
             按函数体行序判定（同函数，v1 不做跨函数调用序）"
                .to_string(),
        ),
        evidence_refs: Some(EvidenceRefs {
            matched_pattern: Some(format!(
                "verification-order: fetch@{} {} verify@{}",
                fetch_line,
                if verify_line.is_some() { "<" } else { "missing" },
                verify_line.unwrap_or(0)
            )),
            ..Default::default()
        }),
        enclosing_function: Some(body.name.clone()),
        enclosing_function_line: Some(body.start_line),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PY_VULN: &str = r#"
def verifySignature(req):
    return signature.verify(req)

def getActor(url):
    return requests.get(url).json()

def handle_inbox(req):
    actor_url = req.get("actor")
    getActor(actor_url)
    verifySignature(req)
    return "ok"
"#;

    const PY_SAFE: &str = r#"
def verifySignature(req):
    return signature.verify(req)

def getActor(url):
    return requests.get(url).json()

def handle_inbox(req):
    actor_url = req.get("actor")
    verifySignature(req)
    getActor(actor_url)
    return "ok"
"#;

    const NON_HANDLER: &str = r#"
def refresh_caches(url):
    return requests.get(url).json()
"#;

    #[test]
    fn detects_fetch_before_verify() {
        let findings = analyze_file("app/inbox.py", PY_VULN);
        assert_eq!(findings.len(), 1, "应命中 1 条时序违例");
        let f = &findings[0];
        assert_eq!(f.detector, "VerificationOrderAnalyzer");
        assert_eq!(f.enclosing_function.as_deref(), Some("handle_inbox"));
        assert!(f.description.contains("precedes signature verification"));
        assert!(f.line_start < f.line_end, "finding 应覆盖 fetch→verify 区间");
    }

    #[test]
    fn ignores_verify_before_fetch() {
        assert!(analyze_file("app/inbox.py", PY_SAFE).is_empty());
    }

    #[test]
    fn ignores_non_handler_fetch() {
        assert!(analyze_file("app/cache.py", NON_HANDLER).is_empty());
    }

    #[test]
    fn ignores_test_paths() {
        assert!(analyze_file("app/tests/test_inbox.py", PY_VULN).is_empty());
    }

    #[test]
    fn stable_ids_across_runs() {
        let a = analyze_file("app/inbox.py", PY_VULN);
        let b = analyze_file("app/inbox.py", PY_VULN);
        assert_eq!(a[0].finding_id, b[0].finding_id);
    }

    #[test]
    fn ignores_weak_handler_without_signature_context() {
        // 文件内无验签调用、函数体无请求对象：弱 handler（handle/api 路径）不成立
        const SRC: &str = r#"
def handle_remote_fetch(url):
    return requests.get(url).json()
"#;
        assert!(analyze_file("app/api/proxy.py", SRC).is_empty());
    }

    #[test]
    fn ignores_singleton_getter_as_fetch() {
        // getInstance() 单例获取不是出站抓取（联邦包装器 getInstance 已从 marker 移除）
        const SRC: &str = r#"
def verifySignature(req):
    return signature.verify(req)

def handle_inbox(req):
    provider = Tvdb.getInstance()
    return provider
"#;
        assert!(analyze_file("app/inbox.py", SRC).is_empty());
    }

    #[test]
    fn detects_weak_handler_with_request_and_verify_context() {
        // 弱 handler + 函数体请求对象 + 文件内验签调用：成立
        const SRC: &str = r#"
def verifySignature(req):
    return signature.verify(req)

def handle_callback(req):
    return requests.get(req.get("url")).json()
"#;
        let findings = analyze_file("app/handlers/webhook.py", SRC);
        assert_eq!(findings.len(), 1, "弱 handler 在有签名上下文时应命中");
        assert_eq!(
            findings[0].enclosing_function.as_deref(),
            Some("handle_callback")
        );
    }
}
