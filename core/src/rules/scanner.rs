use crate::rules::model::Rule;
use crate::scanner::{Finding, Scanner};
use async_trait::async_trait;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use tree_sitter::{Language, Parser, Query, QueryCursor};
use uuid::Uuid;

pub enum RuleMatcher {
    Regex(Regex),
    TreeSitter(Query),
}

pub struct CompiledRule {
    pub rule: Rule,
    pub matcher: RuleMatcher,
    pub language: Option<Language>,
}

pub struct RuleScanner {
    compiled_rules: Vec<CompiledRule>,
    context_lines: usize,
}

impl RuleScanner {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self::with_context_lines(rules, 3)
    }

    pub fn with_context_lines(rules: Vec<Rule>, context_lines: usize) -> Self {
        let mut compiled_rules = Vec::new();
        for rule in rules {
            // Priority: Query (AST) > patterns (multi-lang) > Pattern (Regex)
            if let Some(query_str) = &rule.query {
                if let Some(lang) = get_language_for_rule(&rule.language) {
                    match Query::new(&lang, query_str) {
                        Ok(query) => {
                            compiled_rules.push(CompiledRule {
                                rule: rule.clone(),
                                matcher: RuleMatcher::TreeSitter(query),
                                language: Some(lang),
                            });
                        }
                        Err(e) => {
                            eprintln!("Invalid Tree-sitter query for rule {}: {}", rule.id, e);
                        }
                    }
                } else {
                    eprintln!(
                        "Unsupported language for Tree-sitter rule {}: {}",
                        rule.id, rule.language
                    );
                }
            } else if let Some(patterns) = &rule.patterns {
                // 多语言模式：为每个 LanguagePattern 创建独立的编译规则
                for lp in patterns {
                    if let Ok(regex) = Regex::new(&lp.pattern) {
                        // 创建一条带特定语言的副本
                        let mut lang_rule = rule.clone();
                        lang_rule.language = lp.language.clone();
                        lang_rule.pattern = Some(lp.pattern.clone());
                        lang_rule.patterns = None; // 避免重复展开
                        compiled_rules.push(CompiledRule {
                            rule: lang_rule,
                            matcher: RuleMatcher::Regex(regex),
                            language: None,
                        });
                    } else {
                        eprintln!(
                            "Invalid regex pattern for rule {} ({}): {}",
                            rule.id, lp.language, lp.pattern
                        );
                    }
                }
            } else if let Some(pattern) = &rule.pattern {
                if let Ok(regex) = Regex::new(pattern) {
                    compiled_rules.push(CompiledRule {
                        rule: rule.clone(),
                        matcher: RuleMatcher::Regex(regex),
                        language: None,
                    });
                } else {
                    eprintln!("Invalid regex pattern for rule {}: {}", rule.id, pattern);
                }
            }
        }
        Self {
            compiled_rules,
            context_lines,
        }
    }

    /// 同步扫描文件（可在任意线程调用，不需要 async runtime）
    pub fn scan_file_sync(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 注释范围惰性计算：仅在首个命中时解析一次。
        // 命中点位于注释内则丢弃——注释中的代码不会执行，必为误报。
        let mut comment_ranges_cache: Option<Vec<(usize, usize)>> = None;

        for compiled in &self.compiled_rules {
            // Simple language check based on extension
            if !rule_matches_extension(&compiled.rule.language, &extension) {
                continue;
            }

            match &compiled.matcher {
                RuleMatcher::Regex(regex) => {
                    for cap in regex.captures_iter(content) {
                        if let Some(m) = cap.get(0) {
                            let start_pos = m.start();
                            if is_sanitized_before(content, start_pos, &compiled.rule.sanitizers) {
                                continue;
                            }
                            let ranges = comment_ranges_cache
                                .get_or_insert_with(|| collect_comment_ranges(content, &extension));
                            if position_in_ranges(ranges, start_pos) {
                                continue;
                            }
                            let end_pos = m.end();

                            // Convert byte offset to line number
                            let line_start = content[..start_pos].matches('\n').count() + 1;
                            let line_end = content[..end_pos].matches('\n').count() + 1;

                            // 常量参数 / 安全格式串检测：sink 的参数攻击者不可控时
                            // 标记 likely_fp 并降为 info（不丢弃，交由上层/LLM 最终判定）。
                            // 凭证/密钥类规则除外——硬编码常量正是此类规则要发现的问题。
                            let matched_text = &content[start_pos..end_pos];
                            let likely_fp = if is_credential_related(&compiled.rule, matched_text)
                            {
                                if is_placeholder_secret(&compiled.rule, matched_text) {
                                    Some("值为占位符/示例，非真实凭证")
                                } else if is_config_key_value(matched_text) {
                                    Some("引号内值为配置 key 名称，非真实凭证")
                                } else {
                                    None
                                }
                            } else {
                                evaluate_likely_fp_args(content, start_pos, end_pos).or_else(
                                    || {
                                        if is_placeholder_secret(&compiled.rule, matched_text) {
                                            Some("值为占位符/示例，非真实凭证")
                                        } else {
                                            None
                                        }
                                    },
                                )
                            };

                            findings.push(create_finding(
                                &compiled.rule,
                                path,
                                line_start,
                                line_end,
                                format!("RegexRule: {}", compiled.rule.id),
                                content,
                                3,
                                likely_fp,
                            ));
                        }
                    }
                }
                RuleMatcher::TreeSitter(query) => {
                    if let Some(lang) = &compiled.language {
                        thread_local! {
                            static PARSER_CACHE: std::cell::RefCell<HashMap<String, Parser>> =
                                std::cell::RefCell::new(HashMap::new());
                        }
                        let tree = PARSER_CACHE.with(|cache| {
                            let mut cache = cache.borrow_mut();
                            let lang_key = format!("{:?}", lang);
                            let parser = cache.entry(lang_key).or_insert_with(|| {
                                let mut p = Parser::new();
                                let _ = p.set_language(lang);
                                p
                            });
                            parser.parse(content, None)
                        });
                        if let Some(tree) = tree {
                            let mut cursor = QueryCursor::new();
                            let matches =
                                cursor.matches(query, tree.root_node(), content.as_bytes());

                            for m in matches {
                                if let Some(capture) = m.captures.first() {
                                    let node = capture.node;
                                    let start_byte = node.start_byte();
                                    if is_sanitized_before(
                                        content,
                                        start_byte,
                                        &compiled.rule.sanitizers,
                                    ) {
                                        continue;
                                    }
                                    let start_pos = node.start_position();
                                    let end_pos = node.end_position();

                                    findings.push(create_finding(
                                        &compiled.rule,
                                        path,
                                        start_pos.row + 1,
                                        end_pos.row + 1,
                                        format!("ASTRule: {}", compiled.rule.id),
                                        content,
                                        3,
                                        None,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

#[async_trait]
impl Scanner for RuleScanner {
    fn name(&self) -> String {
        "RuleBasedScanner".to_string()
    }

    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
        self.scan_file_sync(path, content)
    }
}

/// 检查匹配位置之前是否出现任一 sanitizer 模式。
/// 用于规则级去误报：命中点之前存在净化代码，则跳过该发现。
fn is_sanitized_before(content: &str, pos: usize, sanitizers: &[String]) -> bool {
    if sanitizers.is_empty() || pos == 0 {
        return false;
    }
    let prefix = &content[..pos.min(content.len())];
    let prefix_lower = prefix.to_lowercase();
    sanitizers
        .iter()
        .any(|s| prefix_lower.contains(&s.to_lowercase()))
}

/// printf 族函数：格式串为字面量且不含 %s/%[ 时，输出长度有界，
/// 攻击者无法控制写入内容，可判 likely_fp。
const PRINTF_FAMILY: &[&str] = &[
    "sprintf", "vsprintf", "snprintf", "vsnprintf", "fprintf", "printf", "swprintf", "fwprintf",
];

/// 从匹配位置提取调用的参数文本（字符串感知的括号配平）。
/// match_start/match_end 为规则命中区间（通常以 `(` 结尾）。
/// 返回 (函数名, 参数文本)。提取失败返回 None。
fn extract_call_args(content: &str, match_start: usize, match_end: usize) -> Option<(String, String)> {
    let matched = content.get(match_start..match_end)?;
    let paren_rel = matched.rfind('(')?;
    let func_name = matched[..paren_rel]
        .trim_end()
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_' && c != ':' && c != '.')
        .next()?
        .to_string();
    if func_name.is_empty() {
        return None;
    }

    let bytes = content.as_bytes();
    let mut i = match_start + paren_rel;
    let mut depth = 0usize;
    let mut args = String::new();
    let mut in_str: Option<u8> = None;
    let mut prev = 0u8;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            args.push(c as char);
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = Some(c);
            args.push(c as char);
        } else if c == b'(' {
            depth += 1;
            if depth > 1 {
                args.push(c as char);
            }
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                return Some((func_name, args));
            }
            args.push(c as char);
        } else if depth >= 1 {
            args.push(c as char);
        }
        prev = c;
        i += 1;
    }
    None
}

/// 判断参数文本是否全为字面量/常量（字符串、字符、数字、布尔、None/null）。
/// 字符串字面量内的内容不参与标识符判定。
fn args_all_literals(args: &str) -> bool {
    let mut cleaned = String::with_capacity(args.len());
    let bytes = args.as_bytes();
    let mut i = 0;
    let mut in_str: Option<u8> = None;
    let mut prev = 0u8;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = Some(c);
        } else {
            cleaned.push(c as char);
        }
        prev = c;
        i += 1;
    }
    // 清理后不允许出现任何标识符（函数调用、变量、关键字 true/false/null/None 除外）
    !cleaned
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
        .filter(|tok| !tok.is_empty())
        .any(|tok| {
            let t = tok.trim_matches('.');
            !t.is_empty()
                && t.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
                && !matches!(t, "true" | "false" | "null" | "None" | "TRUE" | "FALSE" | "NULL")
        })
}

/// 提取参数文本中的字符串字面量列表
fn extract_string_literals(args: &str) -> Vec<String> {
    let mut lits = Vec::new();
    let bytes = args.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            let mut j = i + 1;
            let mut lit = String::new();
            while j < bytes.len() && (bytes[j] != q || bytes[j - 1] == b'\\') {
                lit.push(bytes[j] as char);
                j += 1;
            }
            if j < bytes.len() {
                lits.push(lit);
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    lits
}

/// 拷贝族函数：源参数为字符串字面量时，拷贝长度有界（如 strcpy(dst, "literal")）
const COPY_FAMILY: &[&str] = &["strcpy", "strcat", "wcscpy", "wcscat", "lstrcpy", "lstrcat"];

/// 取顶层逗号分隔的最后一个参数（不深入嵌套括号）
fn last_top_level_arg(args: &str) -> &str {
    let mut depth = 0i32;
    let mut last_split = 0usize;
    let bytes = args.as_bytes();
    let mut in_str: Option<u8> = None;
    let mut prev = 0u8;
    for (i, &c) in bytes.iter().enumerate() {
        if let Some(q) = in_str {
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' {
            in_str = Some(c);
        } else if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
        } else if c == b',' && depth == 0 {
            last_split = i + 1;
        }
        prev = c;
    }
    args[last_split..].trim()
}

/// 判断文本是否为单个字符串字面量（允许空白包裹）
fn is_string_literal(s: &str) -> bool {
    let s = s.trim();
    s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
}

/// 评估 sink 调用的参数是否攻击者不可控（likely_fp）。
/// 返回 Some(原因) 表示可降级为 info：
/// - 参数全部为字面量（如 os.popen("netstat ...")）
/// - printf 族格式串为字面量且不含 %s/%[（输出长度有界）
/// - strcpy/strcat 族源参数为字符串字面量（拷贝长度有界）
fn evaluate_likely_fp_args(content: &str, match_start: usize, match_end: usize) -> Option<&'static str> {
    let (func_name, args) = extract_call_args(content, match_start, match_end)?;
    if args.trim().is_empty() {
        return None;
    }

    // shell=true 是高风险信号 — 不降权，保持高置信度
    let context_start = match_start.saturating_sub(200);
    let context_end = (match_end + 200).min(content.len());
    let context = &content[context_start..context_end].to_lowercase();
    if context.contains("shell=true") || context.contains("shell = true") {
        return None;
    }

    if args_all_literals(&args) {
        return Some("参数全部为字面量，攻击者不可控");
    }
    let short_name = func_name.rsplit(|c| c == ':' || c == '.').next().unwrap_or(&func_name);
    if PRINTF_FAMILY.contains(&short_name) {
        let lits = extract_string_literals(&args);
        // printf 族：第一个字符串字面量即格式串（可能跳过 dst/stream 参数，取首个字面量近似）
        if let Some(fmt) = lits.first() {
            if !fmt.contains("%s") && !fmt.contains("%[") && !fmt.is_empty() {
                return Some("printf 族格式串为字面量且无 %s，输出有界");
            }
        }
    }
    if COPY_FAMILY.contains(&short_name) && is_string_literal(last_top_level_arg(&args)) {
        return Some("拷贝源为字符串字面量，长度有界");
    }
    None
}

/// 明显的占位符/示例口令值（模板配置），非真实凭证
const PLACEHOLDER_SECRETS: &[&str] = &[
    "user_password",
    "your_password",
    "your-password",
    "yourpassword",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "replace_me",
    "insert_password",
    "password_here",
    "your_secret",
    "your-secret",
    "example_password",
    "******",
];

/// 判断是否为凭证/密钥类规则（此类规则的"常量"正是问题本身，不做参数字面量降权）
fn is_credential_related(rule: &Rule, matched_text: &str) -> bool {
    rule.cwe
        .as_deref()
        .map(|c| c == "CWE-259" || c == "CWE-798")
        .unwrap_or(false)
        || rule.id.contains("password")
        || rule.id.contains("secret")
        || rule.id.contains("credential")
        || rule.id.contains("crypto-key")
        || matched_text.to_lowercase().contains("password")
}

/// 凭证类规则命中明显的占位符值时判 likely_fp
fn is_placeholder_secret(rule: &Rule, matched_text: &str) -> bool {
    if !is_credential_related(rule, matched_text) {
        return false;
    }
    let lower = matched_text.to_lowercase();
    PLACEHOLDER_SECRETS.iter().any(|p| lower.contains(p))
}

/// 判断引号内的值是否为配置 key 名称（仅含标识符字符），而非真实凭证
/// 例如 Go const: const SSOClientSecret = "sso_client_secret" 中的值是 key 名称
fn is_config_key_value(matched_text: &str) -> bool {
    // 提取引号内的值
    let extract_quoted = |quote: char| -> Option<&str> {
        let start = matched_text.rfind(quote)?;
        if start > 0 && matched_text.as_bytes().get(start - 1) == Some(&(b'\\')) {
            return None;
        }
        let before = &matched_text[..start];
        let eq_pos = before.rfind('=')?;
        // 确保等号后在引号前没有其他内容（除了空白）
        let between = before[eq_pos + 1..].trim();
        if !between.is_empty() && between != ":" {
            return None;
        }
        // 找到结束引号
        let after = &matched_text[start + 1..];
        let end = after.find(quote)?;
        Some(&after[..end])
    };

    let value = match extract_quoted('"') {
        Some(v) => v,
        None => match extract_quoted('\'') {
            Some(v) => v,
            None => return false,
        },
    };
    if value.len() < 4 {
        return false;
    }

    // 配置 key 名称特征：只含标识符字符（字母、数字、下划线、点、连字符）
    let is_identifier = value
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-');
    if !is_identifier {
        return false;
    }

    // 排除明显是真实密钥的情况：包含 Base64 特征或高熵片段
    let has_base64_pattern = value.len() >= 12
        && (value.contains("+/") || value.contains("==") || value.contains("AAAA"));
    if has_base64_pattern {
        return false;
    }

    // 排除明显的 hash 值（连续长十六进制串）
    let has_hash_pattern = value.len() >= 16
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && !value.contains('_');
    if has_hash_pattern {
        return false;
    }

    true
}

fn create_finding(
    rule: &Rule,
    path: &PathBuf,
    line_start: usize,
    line_end: usize,
    detector: String,
    content: &str,
    context_lines: usize,
    likely_fp: Option<&'static str>,
) -> Finding {
    let code_snippet = Some(crate::scanner::extract_code_context(
        content,
        line_start,
        line_end,
        context_lines,
    ));
    let file_path = path.to_string_lossy().to_string();
    let vuln_type = rule.cwe.clone().unwrap_or_else(|| "Unknown".to_string());

    // 文件角色分类（含 minified 内容识别）
    let file_role = Some(crate::scanner::classify_file_role_with_content(&file_path, content).to_string());

    // 安全屏障检测
    let barriers = {
        let b = crate::scanner::detect_barriers(content, line_start, line_end, &vuln_type);
        if b.is_empty() {
            None
        } else {
            Some(b)
        }
    };

    // 根据角色和屏障调整严重程度
    let raw_severity = format!("{:?}", rule.severity).to_lowercase();
    let adjusted = crate::scanner::adjust_severity(
        &raw_severity,
        file_role.as_deref().unwrap_or("production"),
        barriers.as_deref().unwrap_or(&[]),
    );
    // likely_fp：参数攻击者不可控（全字面量 / 安全格式串），降为 info
    let severity = if likely_fp.is_some() {
        "info".to_string()
    } else {
        adjusted
    };

    // 生成标记原因
    let reasoning_hint = Some(match likely_fp {
        Some(reason) => format!(
            "Matched {} pattern in {} context; likely_fp: {}",
            rule.id,
            file_role.as_deref().unwrap_or("unknown"),
            reason
        ),
        None => format!(
            "Matched {} pattern in {} context",
            rule.id,
            file_role.as_deref().unwrap_or("unknown")
        ),
    });

    Finding {
        finding_id: Uuid::new_v4().to_string(),
        file_path,
        line_start,
        line_end,
        detector,
        vuln_type,
        severity,
        description: rule.description.clone(),
        analysis_trail: None,
        llm_output: None,
        confidence: None,
        corroboration_count: None,
        code_snippet,
        source_snippet: None,
        sink_snippet: None,
        file_role,
        barriers,
        reasoning_hint,
        evidence_refs: None,
        ..Default::default()
    }
}

fn get_language_for_rule(language: &str) -> Option<Language> {
    match language.to_lowercase().as_str() {
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "json" => Some(tree_sitter_json::LANGUAGE.into()),
        "html" => Some(tree_sitter_html::LANGUAGE.into()),
        _ => None,
    }
}

/// 按文件扩展名选择 tree-sitter 语言（用于注释范围检测）
fn get_language_for_extension(extension: &str) -> Option<Language> {
    match extension {
        "py" => Some(tree_sitter_python::LANGUAGE.into()),
        "js" | "jsx" | "mjs" | "cjs" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "c" | "h" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" | "hpp" | "cc" | "cxx" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "html" | "htm" => Some(tree_sitter_html::LANGUAGE.into()),
        "css" => Some(tree_sitter_css::LANGUAGE.into()),
        _ => None,
    }
}

/// 收集内容中所有注释节点的字节范围（按扩展名选语言）。
/// 不支持的语言返回空表（即不做注释过滤，行为与旧版一致）。
fn collect_comment_ranges(content: &str, extension: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let lang = match get_language_for_extension(extension) {
        Some(l) => l,
        None => return ranges,
    };

    thread_local! {
        static COMMENT_PARSER_CACHE: RefCell<HashMap<String, Parser>> =
            RefCell::new(HashMap::new());
    }
    let tree = COMMENT_PARSER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let lang_key = format!("{:?}", lang);
        let parser = cache.entry(lang_key).or_insert_with(|| {
            let mut p = Parser::new();
            let _ = p.set_language(&lang);
            p
        });
        parser.parse(content, None)
    });
    let tree = match tree {
        Some(t) => t,
        None => return ranges,
    };

    // 迭代遍历（避免深递归），收集所有 comment 节点的字节范围
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind().contains("comment") {
            ranges.push((node.start_byte(), node.end_byte()));
            continue; // 注释节点不会再嵌套代码
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    ranges.sort_unstable();
    ranges
}

/// 判断字节偏移是否落在任一注释范围内（ranges 已排序）
fn position_in_ranges(ranges: &[(usize, usize)], pos: usize) -> bool {
    ranges
        .binary_search_by(|&(start, end)| {
            if pos < start {
                std::cmp::Ordering::Greater
            } else if pos >= end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sanitized_before_skips_when_sanitizer_precedes() {
        let content = "cookie.setSecure(true);\nresponse.addCookie(cookie);";
        let sanitizers = vec!["setSecure".to_string()];
        assert!(is_sanitized_before(content, content.len(), &sanitizers));
    }

    #[test]
    fn test_is_sanitized_before_no_skip_when_sanitizer_absent() {
        let content = "response.addCookie(cookie);";
        let sanitizers = vec!["setSecure".to_string()];
        assert!(!is_sanitized_before(content, content.len(), &sanitizers));
    }

    #[test]
    fn test_collect_comment_ranges_js() {
        let content = "var a = eval(x); // eval(y) 注释\n/* eval(z) 块注释 */\nvar b = eval(w);";
        let ranges = collect_comment_ranges(content, "js");
        // 行注释与块注释都被收集
        assert_eq!(ranges.len(), 2, "ranges: {:?}", ranges);
        // 代码位置的 eval 不在注释内
        let code_pos = content.find("eval(x)").unwrap();
        assert!(!position_in_ranges(&ranges, code_pos));
        let tail_pos = content.find("eval(w)").unwrap();
        assert!(!position_in_ranges(&ranges, tail_pos));
        // 注释内的 eval 在注释内
        let line_comment_pos = content.find("eval(y)").unwrap();
        assert!(position_in_ranges(&ranges, line_comment_pos));
        let block_comment_pos = content.find("eval(z)").unwrap();
        assert!(position_in_ranges(&ranges, block_comment_pos));
    }

    #[test]
    fn test_collect_comment_ranges_python() {
        let content = "exec(cmd)  # exec(other) 注释\n# 整行注释 exec(x)\nexec(cmd2)";
        let ranges = collect_comment_ranges(content, "py");
        assert_eq!(ranges.len(), 2, "ranges: {:?}", ranges);
        assert!(!position_in_ranges(&ranges, content.find("exec(cmd)").unwrap()));
        assert!(position_in_ranges(&ranges, content.find("exec(other)").unwrap()));
        assert!(position_in_ranges(&ranges, content.find("exec(x)").unwrap()));
        assert!(!position_in_ranges(&ranges, content.find("exec(cmd2)").unwrap()));
    }

    #[test]
    fn test_comment_ranges_unsupported_language() {
        let ranges = collect_comment_ranges("eval(x) // eval(y)", "txt");
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_likely_fp_const_args() {
        // 全字面量参数 → likely_fp（os.popen 硬编码命令场景）
        let content = r#"tmp = os.popen("netstat -anp |grep tcp").read()"#;
        let start = content.find("os.popen(").unwrap();
        let end = start + "os.popen(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_some());
    }

    #[test]
    fn test_likely_fp_printf_bounded_format() {
        // printf 族字面量格式串无 %s → likely_fp（json.c sprintf 场景）
        let content = r#"{  sprintf (error, "%d:%d: Expected , before %c", cur_line, e_off, b);"#;
        let start = content.find("sprintf (").unwrap();
        // 模拟规则命中区间（包含空格与左括号）
        let end = start + "sprintf (".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_some());
    }

    #[test]
    fn test_likely_fp_printf_percent_s_not_downgraded() {
        // 格式串含 %s → 不降权（可能写入任意长字符串）
        let content = r#"sprintf(dst, "%s", user)"#;
        let start = content.find("sprintf(").unwrap();
        let end = start + "sprintf(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_none());
    }

    #[test]
    fn test_likely_fp_variable_args_not_downgraded() {
        // 参数含变量 → 不降权（真实污点场景）
        let content = "result = exec(userInput)";
        let start = content.find("exec(").unwrap();
        let end = start + "exec(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_none());
    }

    #[test]
    fn test_placeholder_secret_detected() {
        // 占位符口令 → likely_fp（status-client.py USER_PASSWORD 场景）
        let content = r#"PASSWORD = "USER_PASSWORD""#;
        let rule = Rule {
            id: "no-hardcoded-passwords".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "all".to_string(),
            pattern: Some(r"(?i)password\s*=\s*\S+".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-259".to_string()),
            sanitizers: vec![],
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.py"), content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "info");
        assert!(findings[0]
            .reasoning_hint
            .as_deref()
            .unwrap_or("")
            .contains("likely_fp"));
    }

    #[test]
    fn test_real_password_not_downgraded() {
        // 真实弱口令保持原严重度（不降为 info）
        let content = r#"PASSWORD = "Xq9#kLz2$mP""#;
        let rule = Rule {
            id: "no-hardcoded-passwords".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "all".to_string(),
            pattern: Some(r"(?i)password\s*=\s*\S+".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-259".to_string()),
            sanitizers: vec![],
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.py"), content);
        assert_eq!(findings.len(), 1);
        assert_ne!(findings[0].severity, "info");
    }

    #[test]
    fn test_likely_fp_strcpy_literal_source() {
        // strcpy 源为字面量 → likely_fp（json.c e_alloc_failure 场景）
        let content = r#"strcpy (error, "Memory allocation failure");"#;
        let start = content.find("strcpy (").unwrap();
        let end = start + "strcpy (".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_some());
    }

    #[test]
    fn test_likely_fp_strcpy_variable_source_not_downgraded() {
        // strcpy 源为变量 → 不降权（可能溢出）
        let content = "strcpy(dst, user_input);";
        let start = content.find("strcpy(").unwrap();
        let end = start + "strcpy(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_none());
    }

    #[test]
    fn test_regex_rule_skips_commented_code() {        let rule = Rule {
            id: "test-eval".to_string(),
            name: "test".to_string(),
            description: "test".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "javascript".to_string(),
            pattern: Some(r"eval\s*\(".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-94".to_string()),
            sanitizers: vec![],
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let content = "// eval(commented)\nvar x = eval(active);\n/* eval(blocked) */";
        let findings = scanner.scan_file_sync(&PathBuf::from("a.js"), content);
        assert_eq!(findings.len(), 1, "只应命中未注释的 eval: {:?}", findings.iter().map(|f| f.line_start).collect::<Vec<_>>());
        assert_eq!(findings[0].line_start, 2);
    }
}

fn rule_matches_extension(language: &str, extension: &str) -> bool {
    match language.to_lowercase().as_str() {
        "python" => extension == "py",
        "javascript" | "typescript" => {
            ["js", "jsx", "ts", "tsx", "mjs", "cjs", "vue"].contains(&extension)
        }
        "rust" => extension == "rs",
        "go" => extension == "go",
        "java" => extension == "java",
        "c" => extension == "c" || extension == "h",
        "cpp" => ["cpp", "hpp", "cc", "cxx"].contains(&extension),
        "all" | "*" => true,
        _ => language.eq_ignore_ascii_case(extension),
    }
}
