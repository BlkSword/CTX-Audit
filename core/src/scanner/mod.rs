// Scanner module - 扫描器模块
// 定义扫描器的核心接口和类型

pub mod manager;
pub mod regex_scanner;
pub mod sca_scanner;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use rayon::prelude::*;

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
    /// 置信度评分 (0.0-1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// 多扫描器确认计数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corroboration_count: Option<usize>,
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

    // 创建 SCA 依赖扫描器
    let sca_scanner = sca_scanner::ScaScanner::new();

    // 收集所有文件路径（用于并行处理）
    let mut code_files: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut dep_files: Vec<(std::path::PathBuf, String)> = Vec::new();

    // 使用 ignore 库遍历目录，收集文件
    for entry in Walk::new(path) {
        if let Ok(entry) = entry {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(path) {
                let path_buf = path.to_path_buf();

                if sca_scanner::is_dependency_file(path) {
                    dep_files.push((path_buf, content));
                } else if is_supported_file(path) {
                    code_files.push((path_buf, content));
                }
            }
        }
    }

    // SCA 扫描（异步，按顺序处理依赖文件）
    for (path_buf, content) in &dep_files {
        let sca_findings = sca_scanner.scan_file(path_buf, content).await;
        findings.extend(sca_findings);
    }

    // 代码文件并行扫描（使用 rayon）
    // 在进入 rayon 之前捕获 Tokio Handle（rayon 线程没有 runtime 上下文）
    let rt_handle = tokio::runtime::Handle::current();

    let code_findings: Vec<Vec<Finding>> = code_files
        .par_iter()
        .map(|(path_buf, content)| {
            let mut file_findings = Vec::new();

            // 正则扫描（通过捕获的 Handle 调用）
            let regex_results = rt_handle.block_on(regex_scanner.scan_file(path_buf, content));
            file_findings.extend(regex_results);

            file_findings
        })
        .collect();

    for mut batch in code_findings {
        findings.append(&mut batch);
    }

    // 规则扫描（如果存在规则）— 同样使用捕获的 Handle
    if let Some(ref scanner) = rule_scanner {
        let rule_findings: Vec<Vec<Finding>> = code_files
            .par_iter()
            .map(|(path_buf, content)| {
                rt_handle.block_on(scanner.scan_file(path_buf, content))
            })
            .collect();

        for mut batch in rule_findings {
            findings.append(&mut batch);
        }
    }

    Ok(findings)
}

/// 深度扫描：在基础扫描后对候选文件运行 AST 污点分析
///
/// 仅对有候选发现的文件运行 AstTaintAnalyzer，用于验证和提升置信度。
pub async fn scan_directory_deep(path: &str) -> Result<Vec<Finding>, String> {
    // 先执行基础扫描
    let mut findings = scan_directory(path).await?;

    if findings.is_empty() {
        return Ok(findings);
    }

    // 收集有候选发现的文件
    let candidate_files: std::collections::HashSet<String> = findings
        .iter()
        .map(|f| f.file_path.clone())
        .collect();

    // AST 污点分析（仅处理候选文件）
    let mut analyzer = crate::analysis::ast_taint::AstTaintAnalyzer::new();
    let mut taint_findings: Vec<Finding> = Vec::new();

    for file_path_str in &candidate_files {
        let file_path = std::path::Path::new(file_path_str);

        // 仅分析 tree-sitter 支持的语言
        if !is_ast_supported_file(file_path) {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(file_path) {
            let flows = analyzer.analyze_file(file_path, &content);

            for flow in &flows {
                let file_str = file_path.to_string_lossy().to_string();
                let trail: Vec<String> = flow.path.iter().map(|n| {
                    format!("{:?}:{} - {:?}", n.node_type, n.line, n.code_snippet)
                }).collect();

                taint_findings.push(Finding {
                    finding_id: flow.id.clone(),
                    file_path: file_str,
                    line_start: flow.source.line,
                    line_end: flow.sink.line,
                    detector: "AstTaintScanner".to_string(),
                    vuln_type: format!("{:?}", flow.vulnerability_type),
                    severity: format!("{:?}", flow.severity).to_lowercase(),
                    description: format!(
                        "AST taint flow: {:?} {} -> {}",
                        flow.vulnerability_type,
                        flow.source.symbol,
                        flow.sink.symbol,
                    ),
                    analysis_trail: Some(trail),
                    llm_output: None,
                    confidence: Some(0.85),
                    corroboration_count: None,
                });
            }
        }
    }

    // 为 regex/rule 发现设置置信度
    let taint_file_lines: std::collections::HashSet<(String, usize)> = taint_findings
        .iter()
        .map(|f| (f.file_path.clone(), f.line_start))
        .collect();

    for finding in &mut findings {
        let key = (finding.file_path.clone(), finding.line_start);
        if taint_file_lines.contains(&key) {
            // Regex + AST 同时确认
            finding.confidence = Some(0.9);
        } else {
            // 仅 Regex
            finding.confidence = Some(0.5);
        }
    }

    findings.extend(taint_findings);

    // 去重
    findings = deduplicate_findings(findings);

    Ok(findings)
}

/// 判断文件是否支持 AST 分析（tree-sitter 支持的语言）
fn is_ast_supported_file(path: &std::path::Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_str().unwrap_or("");
        matches!(
            ext,
            "js" | "jsx" | "ts" | "tsx" | "py" | "java" | "rs" | "go"
                | "c" | "h" | "cpp" | "hpp" | "cc"
        )
    } else {
        false
    }
}

/// 去重发现：按 (file_path, line_start, vuln_type) 分组
fn deduplicate_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    // 按 (file_path, line_start, vuln_type) 分组
    let mut groups: std::collections::HashMap<(String, usize, String), Vec<usize>> =
        std::collections::HashMap::new();

    for (i, f) in findings.iter().enumerate() {
        let key = (f.file_path.clone(), f.line_start, f.vuln_type.clone());
        groups.entry(key).or_default().push(i);
    }

    let mut result = Vec::new();
    let mut deduped_indices = std::collections::HashSet::new();

    for (_key, indices) in groups {
        if indices.len() == 1 {
            // 唯一发现，直接保留
            let idx = indices[0];
            if !deduped_indices.contains(&idx) {
                deduped_indices.insert(idx);
                result.push(findings[idx].clone());
            }
        } else {
            // 多个发现合并：保留信息最丰富的
            let best_idx = *indices.iter().max_by_key(|&&idx| {
                let f = &findings[idx];
                let trail_len = f.analysis_trail.as_ref().map(|t| t.len()).unwrap_or(0);
                trail_len
            }).unwrap();

            let mut merged = findings[best_idx].clone();
            merged.corroboration_count = Some(indices.len());
            merged.confidence = Some(
                merged.confidence.unwrap_or(0.5).min(0.5 + 0.1 * indices.len() as f32).min(1.0)
            );

            for &idx in &indices {
                deduped_indices.insert(idx);
            }
            result.push(merged);
        }
    }

    result
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
