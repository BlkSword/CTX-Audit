use crate::rules::model::Rule;
use crate::scanners::{Finding, Scanner};
use async_trait::async_trait;
use regex::Regex;
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
}

impl RuleScanner {
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut compiled_rules = Vec::new();
        for rule in rules {
            // Priority: Query (AST) > Pattern (Regex)
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
        Self { compiled_rules }
    }
}

#[async_trait]
impl Scanner for RuleScanner {
    fn name(&self) -> String {
        "RuleBasedScanner".to_string()
    }

    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
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
                            ));
                        }
                    }
                }
                RuleMatcher::TreeSitter(query) => {
                    if let Some(lang) = &compiled.language {
                        let mut parser = Parser::new();
                        if parser.set_language(lang).is_ok() {
                            if let Some(tree) = parser.parse(content, None) {
                                let mut cursor = QueryCursor::new();
                                let matches =
                                    cursor.matches(query, tree.root_node(), content.as_bytes());

                                for m in matches {
                                    // Use the first capture for location
                                    if let Some(capture) = m.captures.first() {
                                        let node = capture.node;
                                        let start_pos = node.start_position();
                                        let end_pos = node.end_position();

                                        findings.push(create_finding(
                                            &compiled.rule,
                                            path,
                                            start_pos.row + 1,
                                            end_pos.row + 1,
                                            format!("ASTRule: {}", compiled.rule.id),
                                        ));
                                    }
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

fn create_finding(
    rule: &Rule,
    path: &PathBuf,
    line_start: usize,
    line_end: usize,
    detector: String,
) -> Finding {
    Finding {
        finding_id: Uuid::new_v4().to_string(),
        file_path: path.to_string_lossy().to_string(),
        line_start,
        line_end,
        detector,
        vuln_type: rule.cwe.clone().unwrap_or_else(|| "Unknown".to_string()),
        severity: format!("{:?}", rule.severity),
        description: rule.description.clone(),
        analysis_trail: None,
        llm_output: None,
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

fn rule_matches_extension(language: &str, extension: &str) -> bool {
    match language.to_lowercase().as_str() {
        "python" => extension == "py",
        "javascript" | "typescript" => {
            ["js", "jsx", "ts", "tsx", "mjs", "cjs"].contains(&extension)
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
