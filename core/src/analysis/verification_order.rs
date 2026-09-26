//! 验签顺序分析器（VerificationOrderAnalyzer）与机制模板接入。
//!
//! 机制类：**入站 handler 在完成签名验证之前，就对"请求可控 URL"发起出站抓取**
//! （verify-before-dereference 违例，CWE-918 + CWE-306）。
//!
//! 判定（v1.2，两段式收紧 + 抓取包装器降级）：
//!   1. handler 判定分强/弱：函数名命中 inbox/webhook/signature/verify 为强信号；
//!      命中 handle/handler/receive/callback/controller/endpoint 或文件路径命中
//!      views/handlers/routes/controllers/api/functions/inbox 为弱信号，弱信号必须同时满足
//!      "文件内存在验签调用"且"函数体出现请求对象"（req/request/ctx/event/...）；
//!   2. 以 get/fetch/resolve/load/read 开头但含强 marker 的名字（get_actor_inbox 等）
//!      视为"被调用的取数工具"，降级为弱信号——时序违例应报在调用方 handler；
//!      出站抓取行必须含强输入标识（keyId/actor/signature/remote_id/...），
//!      弱输入标识（url/uri/instance/object/...）仅在文件内有验签代码时接受；
//!   3. 最早的抓取行早于最早的验签行（或无验签行）。
//!
//! 通用逻辑在 `crate::analysis::ordering_template`；本文件只维护 VO 机制的 marker 与元信息，
//! 新机制 = 一份 `OrderingMechanismConfig` + 单测。

use crate::analysis::ordering_template::{OrderingMechanism, OrderingMechanismConfig};
use crate::ast::symbol::FunctionBody;
use crate::scanner::Finding;
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

/// handler 强形态：函数名本身表明这是入站签名/inbox 处理面（直接成立）。
/// 不收录 federation/fediverse/activitypub：这些是**模块/领域名**，出站抓取包装器
/// （如 activitypub_request）也会命中，属噪声；真正的入站面由 inbox/signature 覆盖。
const STRONG_HANDLER_MARKERS: &[&str] = &[
    "inbox",
    "webhook",
    "signature",
    "verify",
];

/// 抓取包装器前缀：名字命中强 marker 但以这些前缀开头（get_actor_inbox 等）时降级为弱，
/// 因为它们是"被调用的取数工具"，时序违例应报在调用方（入站 handler）。
const FETCH_WRAPPER_PREFIXES: &[&str] = &["get", "fetch", "resolve", "load", "read"];

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

/// VO 机制配置（默认机制；新机制可复制此结构换成自己的 marker/元信息）。
pub const VERIFICATION_ORDER_CONFIG: OrderingMechanismConfig<'static> =
    OrderingMechanismConfig {
        name: "VerificationOrderAnalyzer",
        vuln_type: "SSRF",
        severity: "medium",
        confidence: 0.6,
        description_subject: "Signature verification",
        verify_label: "signature verification",
        strong_handler_markers: STRONG_HANDLER_MARKERS,
        weak_handler_markers: WEAK_HANDLER_MARKERS,
        handler_path_markers: HANDLER_PATH_MARKERS,
        helper_prefixes: PATH_ONLY_HELPER_PREFIXES,
        fetch_wrapper_prefixes: FETCH_WRAPPER_PREFIXES,
        fetch_markers: FETCH_MARKERS,
        verify_markers: VERIFY_MARKERS,
        strong_input_markers: STRONG_INPUT_MARKERS,
        weak_input_markers: WEAK_INPUT_MARKERS,
        request_evidence: REQUEST_EVIDENCE,
    };

/// 默认机制编译一次（RegexSet 构建成本只付一次）。
pub fn default_mechanism() -> &'static OrderingMechanism {
    static MECHANISM: OnceLock<OrderingMechanism> = OnceLock::new();
    MECHANISM.get_or_init(|| OrderingMechanism::compile(VERIFICATION_ORDER_CONFIG))
}

/// 预过滤：文件是否具备命中本机制的必要条件（供 scanner 决定是否解析）。
pub fn is_candidate_file(file_path: &str, content: &str) -> bool {
    default_mechanism().is_candidate_file(file_path, content)
}

/// 对已解析的函数体做判定（复用 Stage B 解析结果，避免二次解析）。
pub fn analyze_bodies(
    file_path: &str,
    content: &str,
    bodies: &[FunctionBody],
) -> Vec<Finding> {
    default_mechanism().analyze_bodies(file_path, content, bodies)
}

/// 自行解析后判定（无 Stage B 函数体时使用）。
pub fn analyze_file(file_path: &str, content: &str) -> Vec<Finding> {
    default_mechanism().analyze_file(file_path, content)
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

    #[test]
    fn template_supports_second_mechanism() {
        const CFG: OrderingMechanismConfig<'static> = OrderingMechanismConfig {
            name: "TestOrderingMechanism",
            vuln_type: "SSRF",
            severity: "low",
            confidence: 0.5,
            description_subject: "Token check",
            verify_label: "token check",
            strong_handler_markers: &["process_upload"],
            weak_handler_markers: &[],
            handler_path_markers: &[],
            helper_prefixes: &[],
            fetch_wrapper_prefixes: &[],
            fetch_markers: &["http.get("],
            verify_markers: &["check_token"],
            strong_input_markers: &["url"],
            weak_input_markers: &[],
            request_evidence: &[],
        };
        let m = OrderingMechanism::compile(CFG);
        const SRC: &str = r#"
def process_upload(payload):
    url = payload.get("url")
    http.get(url)
    check_token(payload)
"#;
        let findings = m.analyze_file("app/handlers/upload.py", SRC);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "TestOrderingMechanism");
        assert_eq!(findings[0].severity, "low");
        assert!(findings[0].description.contains("precedes token check"));
    }
}
