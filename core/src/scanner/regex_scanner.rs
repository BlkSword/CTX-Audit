use super::{Finding, Scanner};
use async_trait::async_trait;
use regex::Regex;
use std::path::PathBuf;
use uuid::Uuid;

pub struct RegexScanner {
    patterns: Vec<(Regex, String, String)>, // Regex, VulnType, Severity
}

impl RegexScanner {
    pub fn new() -> Self {
        let patterns = vec![
            (
                Regex::new(r#"(?i)password\s*=\s*['"][^'"]+['"]"#).unwrap(),
                "Hardcoded Password".to_string(),
                "high".to_string(),
            ),
            (
                Regex::new(r#"(?i)api_key\s*=\s*['"][^'"]+['"]"#).unwrap(),
                "Hardcoded API Key".to_string(),
                "high".to_string(),
            ),
            (
                Regex::new(r"(?i)TODO:").unwrap(),
                "TODO Comment".to_string(),
                "low".to_string(),
            ),
        ];
        Self { patterns }
    }
}

#[async_trait]
impl Scanner for RegexScanner {
    fn name(&self) -> String {
        "RegexScanner".to_string()
    }

    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            for (regex, vuln_type, severity) in &self.patterns {
                if regex.is_match(line) {
                    findings.push(Finding {
                        finding_id: Uuid::new_v4().to_string(),
                        file_path: path.to_string_lossy().to_string(),
                        line_start: i + 1,
                        line_end: i + 1,
                        detector: self.name(),
                        vuln_type: vuln_type.clone(),
                        severity: severity.clone(),
                        description: format!("Found potential {} at line {}", vuln_type, i + 1),
                        analysis_trail: None,
                        llm_output: None,
                    });
                }
            }
        }
        findings
    }
}
