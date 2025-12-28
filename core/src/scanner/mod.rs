// Scanner module - 扫描器模块
// 定义扫描器的核心接口和类型

pub mod manager;
pub mod regex_scanner;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 漏洞发现结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub finding_id: String,
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub detector: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis_trail: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_output: Option<String>,
}

/// 扫描器 trait - 所有扫描器都需要实现此接口
#[async_trait]
pub trait Scanner: Send + Sync {
    /// 返回扫描器名称
    fn name(&self) -> String;

    /// 扫描单个文件
    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding>;
}

/// 便捷的 scan_directory 函数（用于web-backend）
pub async fn scan_directory(path: &str) -> Result<Vec<Finding>, String> {
    use ignore::Walk;
    use tokio::fs;

    let mut findings = Vec::new();

    // 加载规则
    let rules_path = std::path::Path::new("rules");
    let rules = if rules_path.exists() {
        match crate::rules::loader::load_rules_from_dir(rules_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Failed to load rules: {}, using only RegexScanner", e);
                vec![]
            }
        }
    } else {
        eprintln!("Rules directory not found, using only RegexScanner");
        vec![]
    };

    // 创建规则扫描器
    let rule_scanner = if !rules.is_empty() {
        Some(crate::rules::scanner::RuleScanner::new(rules))
    } else {
        None
    };

    // 创建正则扫描器
    let regex_scanner = regex_scanner::RegexScanner::new();

    // 使用 ignore 库遍历目录
    for entry in Walk::new(path) {
        if let Ok(entry) = entry {
            let path = entry.path();

            // 只扫描支持的文件类型
            if path.is_file() && is_supported_file(path) {
                if let Ok(content) = fs::read_to_string(path).await {
                    let path_buf = path.to_path_buf();

                    // 使用 RegexScanner 进行简单扫描
                    let mut file_findings = regex_scanner.scan_file(&path_buf, &content).await;

                    // 如果有规则扫描器，也使用规则扫描
                    if let Some(ref scanner) = rule_scanner {
                        let mut rule_findings = scanner.scan_file(&path_buf, &content).await;
                        findings.append(&mut rule_findings);
                    }

                    findings.append(&mut file_findings);
                }
            }
        }
    }

    Ok(findings)
}

fn is_supported_file(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("");
        matches!(
            ext,
            "js" | "jsx" | "ts" | "tsx" | "py" | "java" | "rs" | "go"
                | "html" | "htm" | "vue" | "css" | "json"
                | "c" | "h" | "cpp" | "hpp" | "cc"
        )
    } else {
        false
    }
}
