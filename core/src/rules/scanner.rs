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
                            let end_pos = m.end();

                            // Convert byte offset to line number
                            let line_start = content[..start_pos].matches('\n').count() + 1;
                            let line_end = content[..end_pos].matches('\n').count() + 1;

                            findings.push(create_finding(
                                &compiled.rule,
                                path,
                                line_start,
                                line_end,
                                format!("RegexRule: {}", compiled.rule.id),
                                content,
                                3,
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

fn create_finding(
    rule: &Rule,
    path: &PathBuf,
    line_start: usize,
    line_end: usize,
    detector: String,
    content: &str,
    context_lines: usize,
) -> Finding {
    let code_snippet = Some(crate::scanner::extract_code_context(
        content,
        line_start,
        line_end,
        context_lines,
    ));
    let file_path = path.to_string_lossy().to_string();
    let vuln_type = rule.cwe.clone().unwrap_or_else(|| "Unknown".to_string());

    // 文件角色分类
    let file_role = Some(crate::scanner::classify_file_role(&file_path).to_string());

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
    let severity = crate::scanner::adjust_severity(
        &raw_severity,
        file_role.as_deref().unwrap_or("production"),
        barriers.as_deref().unwrap_or(&[]),
    );

    // 生成标记原因
    let reasoning_hint = Some(format!(
        "Matched {} pattern in {} context",
        rule.id,
        file_role.as_deref().unwrap_or("unknown")
    ));

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
