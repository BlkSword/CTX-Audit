//! 时序机制检测器的通用模板（OrderingMechanism）。
//!
//! 把 `verification_order.rs` 里"函数体行序判定 + 两段式 handler 门槛 + 必要性预过滤"
//! 的通用逻辑抽出来，用 [`OrderingMechanismConfig`] 参数化：
//!
//! - 新机制 = 一组 marker + finding 元信息（name/vuln_type/severity/confidence/描述短语），
//!   不需要复制分析逻辑；
//! - 默认机制（VerificationOrderAnalyzer）在 `verification_order.rs` 里用 `OnceLock` 编译一次，
//!   调用方 API 保持不变；
//! - 机制专属的 marker 仍由各机制模块维护（模板不内置任何目标指纹）。

use crate::ast::symbol::FunctionBody;
use crate::scanner::{stable_finding_id, EvidenceRefs, Finding};
use regex::RegexSet;

/// 机制配置：所有 marker 都是小写子串/正则（大小写不敏感编译）。
pub struct OrderingMechanismConfig<'a> {
    /// finding.detector 名称，也是 finding_id snippet key 的命名空间
    pub name: &'static str,
    /// finding.vuln_type
    pub vuln_type: &'static str,
    /// finding.severity
    pub severity: &'static str,
    /// finding.confidence
    pub confidence: f32,
    /// 描述主体（如 "Signature verification"）
    pub description_subject: &'static str,
    /// 描述里的验签动作短语（如 "signature verification"）
    pub verify_label: &'static str,
    /// handler 强信号（函数名命中即成立）
    pub strong_handler_markers: &'a [&'a str],
    /// handler 弱信号（需文件内有验签调用 + 函数体有请求对象证据）
    pub weak_handler_markers: &'a [&'a str],
    /// 文件路径里的 handler 目录
    pub handler_path_markers: &'a [&'a str],
    /// 弱 handler 匹配时排除的 helper 前缀
    pub helper_prefixes: &'a [&'a str],
    /// 抓取包装器前缀（含强 marker 时降级为弱）
    pub fetch_wrapper_prefixes: &'a [&'a str],
    /// 出站抓取形态
    pub fetch_markers: &'a [&'a str],
    /// 验签/校验形态
    pub verify_markers: &'a [&'a str],
    /// 强输入标识（请求可控且带身份/签名语义）
    pub strong_input_markers: &'a [&'a str],
    /// 弱输入标识（仅在文件内有验签代码时接受）
    pub weak_input_markers: &'a [&'a str],
    /// 请求对象证据（req/request/ctx/event/...）
    pub request_evidence: &'a [&'a str],
}

/// 编译后的机制：marker 表编译成大小写不敏感的 RegexSet，预过滤一次扫描。
pub struct OrderingMechanism {
    cfg: OrderingMechanismConfig<'static>,
    fetch: RegexSet,
    verify: RegexSet,
    strong_handler: RegexSet,
    weak_handler: RegexSet,
    request_evidence: RegexSet,
    strong_input: RegexSet,
    weak_input: RegexSet,
}

fn marker_set(patterns: &[&str]) -> RegexSet {
    let pats: Vec<String> = patterns
        .iter()
        .map(|p| format!("(?i){}", regex::escape(p)))
        .collect();
    RegexSet::new(pats).expect("ordering mechanism marker set")
}

impl OrderingMechanism {
    pub fn compile(cfg: OrderingMechanismConfig<'static>) -> Self {
        Self {
            fetch: marker_set(cfg.fetch_markers),
            verify: marker_set(cfg.verify_markers),
            strong_handler: marker_set(cfg.strong_handler_markers),
            weak_handler: marker_set(cfg.weak_handler_markers),
            request_evidence: marker_set(cfg.request_evidence),
            strong_input: marker_set(cfg.strong_input_markers),
            weak_input: marker_set(cfg.weak_input_markers),
            cfg,
        }
    }

    pub fn name(&self) -> &'static str {
        self.cfg.name
    }

    /// 必要性预过滤：文件是否值得解析/分析。
    pub fn is_candidate_file(&self, file_path: &str, content: &str) -> bool {
        let path = std::path::Path::new(file_path);
        if !crate::scanner::is_ast_supported_file(path) {
            return false;
        }
        if is_test_path(file_path) {
            return false;
        }
        let path_lower = file_path.to_ascii_lowercase();
        let file_has_verify = self.verify.is_match(content);
        let path_handler_possible = self
            .cfg
            .handler_path_markers
            .iter()
            .any(|m| path_lower.contains(m));
        let strong_handler_possible = self.strong_handler.is_match(content);
        let weak_handler_possible = self.weak_handler.is_match(content)
            && file_has_verify
            && self.request_evidence.is_match(content);
        (path_handler_possible || strong_handler_possible || weak_handler_possible)
            && self.fetch.is_match(content)
    }

    /// 对已解析的函数体做判定（复用 Stage B 解析结果，避免二次解析）。
    pub fn analyze_bodies(
        &self,
        file_path: &str,
        content: &str,
        bodies: &[FunctionBody],
    ) -> Vec<Finding> {
        if !self.is_candidate_file(file_path, content) {
            return Vec::new();
        }
        let file_has_verify = self.verify.is_match(content);
        let mut out = Vec::new();
        for body in bodies {
            if let Some(finding) = self.analyze_function(file_path, body, file_has_verify) {
                out.push(finding);
            }
        }
        out
    }

    /// 自行解析后判定（无 Stage B 函数体时使用）。
    pub fn analyze_file(&self, file_path: &str, content: &str) -> Vec<Finding> {
        if !self.is_candidate_file(file_path, content) {
            return Vec::new();
        }
        let path = std::path::Path::new(file_path);
        let bodies = crate::ast::parser::with_thread_local_parser(|parser| {
            parser.extract_function_bodies(path, content)
        });
        self.analyze_bodies(file_path, content, &bodies)
    }

    fn analyze_function(
        &self,
        file_path: &str,
        body: &FunctionBody,
        file_has_verify: bool,
    ) -> Option<Finding> {
        let name_lower = body.name.to_ascii_lowercase();
        let path_lower = file_path.to_ascii_lowercase();
        let helper_name = self
            .cfg
            .helper_prefixes
            .iter()
            .any(|p| name_lower.starts_with(p));
        let fetch_wrapper = self
            .cfg
            .fetch_wrapper_prefixes
            .iter()
            .any(|p| name_lower.starts_with(p));
        let strong_handler = !fetch_wrapper && self.strong_handler.is_match(&name_lower);
        let weak_handler = !helper_name
            && (self.weak_handler.is_match(&name_lower)
                || self
                    .cfg
                    .handler_path_markers
                    .iter()
                    .any(|m| path_lower.contains(m)));
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
            if first_verify.is_none() && self.verify.is_match(&line_lower) {
                first_verify = Some((line_no, raw_line.trim().to_string()));
            }
            if first_fetch.is_none()
                && self.fetch.is_match(&line_lower)
                && (self.strong_input.is_match(&line_lower)
                    || (file_has_verify && self.weak_input.is_match(&line_lower)))
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
                "{}: outbound fetch at line {} precedes {} at line {} in function '{}' — an \
                 unauthenticated request can trigger an attacker-controlled outbound request \
                 (SSRF) before the {}.",
                self.cfg.description_subject, fetch_line, self.cfg.verify_label, v, body.name,
                self.cfg.verify_label
            ),
            None => format!(
                "{}: outbound fetch at line {} in function '{}' has no {} in the same function — \
                 an unauthenticated request can trigger an attacker-controlled outbound request \
                 (SSRF).",
                self.cfg.description_subject, fetch_line, body.name, self.cfg.verify_label
            ),
        };

        let snippet_key = format!(
            "{}:{}:{}:{}",
            self.cfg.name,
            body.name,
            fetch_line,
            verify_line.unwrap_or(0)
        );
        Some(Finding {
            finding_id: stable_finding_id(
                file_path,
                fetch_line,
                0,
                self.cfg.vuln_type,
                &snippet_key,
            ),
            file_path: file_path.to_string(),
            line_start: fetch_line,
            line_end,
            detector: self.cfg.name.to_string(),
            vuln_type: self.cfg.vuln_type.to_string(),
            severity: self.cfg.severity.to_string(),
            description,
            analysis_trail: Some(vec![
                format!("fetch@{}: {}", fetch_line, fetch_text),
                match verify_line {
                    Some(v) => format!("verify@{} (after fetch)", v),
                    None => "verify: missing in function".to_string(),
                },
            ]),
            llm_output: None,
            confidence: Some(self.cfg.confidence),
            corroboration_count: None,
            code_snippet: None,
            source_snippet: Some(fetch_text),
            sink_snippet: first_verify.as_ref().map(|(_, t)| t.clone()),
            file_role: None,
            barriers: None,
            reasoning_hint: Some(format!(
                "fetch-before-verify ordering (CWE-918/CWE-306); 由 {} 按函数体行序判定\
                 （同函数，v1 不做跨函数调用序）",
                self.cfg.name
            )),
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
}

pub fn is_test_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("/test")
        || lower.contains("/spec")
        || lower.contains(".spec.")
        || lower.contains(".test.")
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.go")
        || lower.ends_with("_test.rs")
}

fn has_request_evidence_lower(lower: &str) -> bool {
    lower.contains("(req")
        || lower.contains("req.")
        || lower.contains("req,")
        || lower.contains("req)")
        || lower.contains("req;")
        || lower.contains("req ")
        || lower.contains("(request")
        || lower.contains("request.")
        || lower.contains("request,")
        || lower.contains("request)")
        || lower.contains("request;")
        || lower.contains("$request")
        || lower.contains("http.request")
        || lower.contains("httpservletrequest")
        || lower.contains("incomingmessage")
        || lower.contains("ctx.")
        || lower.contains("event.")
        || lower.contains("event,")
        || lower.contains("requestbody")
}
