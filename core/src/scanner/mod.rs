// Scanner module - 扫描器模块
// 定义扫描器的核心接口和类型

pub mod manager;
pub mod regex_scanner;
pub mod sca_scanner;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use rayon::prelude::*;

/// 基线文件结构：记录已忽略的 findings
#[derive(Debug, Deserialize)]
struct Baseline {
    /// key = "file_path:line_start:vuln_type" → value = reason
    #[serde(default)]
    ignored: std::collections::HashMap<String, String>,
}

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

    // 先运行攻击面映射
    let attack_surface = crate::analysis::attack_surface::AttackSurfaceMapper::map_project(
        std::path::Path::new(path)
    );
    tracing::info!(
        "[AttackSurface] 发现 {} 个入口点, {} 个高风险文件, {} 个未认证入口",
        attack_surface.stats.total_entry_points,
        attack_surface.stats.high_risk_file_count,
        attack_surface.stats.unauthenticated_count,
    );

    let mut findings = Vec::new();

    // 从攻击面生成未认证端点发现
    for ep in &attack_surface.entry_points {
        if !ep.auth_required && ep.entry_type == crate::analysis::attack_surface::EntryType::HttpEndpoint {
            findings.push(Finding {
                finding_id: format!("attack-surface-unauth-{}", ep.line),
                file_path: ep.file_path.clone(),
                line_start: ep.line,
                line_end: ep.line,
                detector: "AttackSurfaceMapper".to_string(),
                vuln_type: "UnauthenticatedEndpoint".to_string(),
                severity: "high".to_string(),
                description: format!(
                    "{} {} 端点未配置认证保护",
                    ep.http_method.as_deref().unwrap_or("?"),
                    ep.route.as_deref().unwrap_or("?")
                ),
                analysis_trail: None,
                llm_output: None,
                confidence: Some(ep.risk_score),
                corroboration_count: None,
            });
        }
    }
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

    // 收集文件路径（不预读内容，按需读取）
    /// 最大文件大小 10MB
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
    /// 内存预算：所有文件内容总量上限 500MB
    const MEMORY_BUDGET_BYTES: usize = 500 * 1024 * 1024;

    let mut code_files: Vec<std::path::PathBuf> = Vec::new();
    let mut dep_files: Vec<std::path::PathBuf> = Vec::new();

    // 使用 ignore 库遍历目录，收集文件路径
    for entry in Walk::new(path) {
        if let Ok(entry) = entry {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // 文件大小检查
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.len() > MAX_FILE_SIZE {
                    continue;
                }
            }

            let path_buf = path.to_path_buf();

            if sca_scanner::is_dependency_file(path) {
                dep_files.push(path_buf);
            } else if is_supported_file(path) {
                code_files.push(path_buf);
            }
        }
    }

    // SCA 扫描（按需读取依赖文件）
    for path_buf in &dep_files {
        if let Ok(content) = std::fs::read_to_string(path_buf) {
            let sca_findings = sca_scanner.scan_file(path_buf, &content).await;
            findings.extend(sca_findings);
        }
    }

    // 代码文件并行扫描（使用 rayon，按需读取 + 内存预算控制）
    let rt_handle = tokio::runtime::Handle::current();

    // 分批处理以控制内存
    let batch_size = 100; // 每批最多 100 个文件
    let mut total_bytes_read: usize = 0;

    for chunk in code_files.chunks(batch_size) {
        let code_findings: Vec<Vec<Finding>> = chunk
            .par_iter()
            .map(|path_buf| {
                let content = match std::fs::read_to_string(path_buf) {
                    Ok(c) => c,
                    Err(_) => return Vec::new(),
                };

                let mut file_findings = Vec::new();

                // 正则扫描
                let regex_results = rt_handle.block_on(regex_scanner.scan_file(path_buf, &content));
                file_findings.extend(regex_results);

                // 规则扫描（同一文件，内容已加载，不重复读）
                if let Some(ref scanner) = rule_scanner {
                    let rule_results = rt_handle.block_on(scanner.scan_file(path_buf, &content));
                    file_findings.extend(rule_results);
                }

                file_findings
            })
            .collect();

        // 更新内存计数（近似）
        total_bytes_read += chunk.len() * 10_000; // 估算
        if total_bytes_read > MEMORY_BUDGET_BYTES {
            tracing::warn!(
                "内存预算接近上限 ({}MB)，停止扫描剩余文件",
                total_bytes_read / 1024 / 1024
            );
            break;
        }

        for mut batch in code_findings {
            findings.append(&mut batch);
        }
    }

    // 上下文感知过滤：降低测试文件和配置目录中 findings 的置信度
    for finding in &mut findings {
        let fp = finding.file_path.to_lowercase().replace('\\', "/");
        let is_test = fp.contains("/test") || fp.contains("/tests/") || fp.contains("/__tests__/")
            || fp.contains("/spec/") || fp.ends_with("_test.go") || fp.ends_with("_test.rs")
            || fp.ends_with("_test.py") || fp.ends_with(".test.js") || fp.ends_with(".test.ts")
            || fp.ends_with(".spec.js") || fp.ends_with(".spec.ts");
        let is_config = fp.contains("/config/") || fp.contains("/.env") || fp.contains("/migrations/")
            || fp.ends_with("dockerfile") || fp.ends_with(".toml") || fp.ends_with(".yaml")
            || fp.ends_with(".yml") || fp.ends_with(".json");
        let is_example = fp.contains("/example") || fp.contains("/demo") || fp.contains("/sample");

        if is_test || is_example {
            // 测试/示例文件中的发现降低严重程度
            finding.confidence = Some(finding.confidence.unwrap_or(0.7) * 0.3);
        } else if is_config {
            // 配置文件中的发现降低置信度（配置中硬编码密码可能是预期的）
            if finding.vuln_type.contains("Password") || finding.vuln_type.contains("password") {
                finding.confidence = Some(finding.confidence.unwrap_or(0.7) * 0.5);
            }
        }

        // 为没有置信度的 findings 设置默认值
        if finding.confidence.is_none() {
            finding.confidence = Some(match finding.detector.as_str() {
                "SCAScanner" => 0.9,
                "RuleScanner" => 0.7,
                "RegexScanner" => 0.5,
                "AttackSurfaceMapper" => 0.6,
                _ => 0.5,
            });
        }
    }

    // 基线抑制：加载已确认/忽略的 findings
    let baseline_path = std::path::Path::new(".ctx-audit/baseline.json");
    if baseline_path.exists() {
        if let Ok(content) = std::fs::read_to_string(baseline_path) {
            if let Ok(baseline) = serde_json::from_str::<Baseline>(&content) {
                findings.retain(|f| {
                    let key = format!("{}:{}:{}", f.file_path, f.line_start, f.vuln_type);
                    !baseline.ignored.contains_key(&key)
                });
            }
        }
    }

    Ok(findings)
}

/// 带攻击面信息的扫描结果
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub attack_surface: crate::analysis::attack_surface::AttackSurface,
}

/// 扫描目录并返回完整结果（含攻击面）
pub async fn scan_directory_with_attack_surface(path: &str) -> Result<ScanResult, String> {
    let attack_surface = crate::analysis::attack_surface::AttackSurfaceMapper::map_project(
        std::path::Path::new(path)
    );

    let findings = scan_directory(path).await?;

    Ok(ScanResult { findings, attack_surface })
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

    // 跨文件污点分析
    let cross_file_result = crate::analysis::cross_file::CrossFileTaintAnalyzer::new()
        .analyze_project(std::path::Path::new(path));

    if !cross_file_result.taint_flows.is_empty() {
        tracing::info!(
            "[CrossFileTaint] 发现 {} 个跨文件污点流",
            cross_file_result.taint_flows.len()
        );
        for flow in &cross_file_result.taint_flows {
            let intermediate: Vec<String> = flow.interprocedural_path.iter()
                .map(|s| format!("{}:{}", s.file_path, s.line))
                .collect();
            findings.push(Finding {
                finding_id: flow.id.clone(),
                file_path: flow.source.file_path.clone(),
                line_start: flow.source.line,
                line_end: flow.sink.line,
                detector: "CrossFileTaintAnalyzer".to_string(),
                vuln_type: format!("{:?}", flow.vulnerability_type),
                severity: format!("{:?}", flow.severity).to_lowercase(),
                description: format!(
                    "Cross-file taint: {}:{} → {}:{} (via {})",
                    flow.source.symbol, flow.source.line,
                    flow.sink.symbol, flow.sink.line,
                    intermediate.join(" → ")
                ),
                analysis_trail: Some(intermediate),
                llm_output: None,
                confidence: Some(flow.confidence),
                corroboration_count: None,
            });
        }
    }

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
