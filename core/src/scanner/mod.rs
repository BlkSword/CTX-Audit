// Scanner module - 扫描器模块
// 定义扫描器的核心接口和类型

pub mod manager;
pub mod regex_scanner;
pub mod sca_scanner;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use rayon::prelude::*;

/// 默认排除列表（目录 + 文件模式）
const DEFAULT_EXCLUDE_PATTERNS: &[&str] = &[
    // 目录
    "node_modules", ".git", "target", "build", "dist", "vendor",
    "__pycache__", ".gradle", ".idea", ".vscode", ".cache",
    "bower_components", ".next", ".nuxt", "coverage", ".cache",
    // 文件
    "*.min.js", "*.min.css", "*.bundle.js", "*.chunk.js",
    "*.map", ".env.*",
];

/// 测试目录标识（用于降低置信度，不排除扫描）
const TEST_DIR_MARKERS: &[&str] = &[
    "/test/", "/tests/", "/__tests__/", "/spec/",
    "\\test\\", "\\tests\\", "\\__tests__\\", "\\spec\\",
];

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

/// 规则目录搜索顺序：
/// 1. 用户指定目录（--rules 参数）
/// 2. 项目级目录 `<project>/.ctx-audit/rules/`
/// 3. 内置规则目录 `rules/`
fn resolve_rules_dir(project_path: &str, custom_dir: Option<&str>) -> Option<std::path::PathBuf> {
    // 1. 用户指定
    if let Some(dir) = custom_dir {
        let p = std::path::Path::new(dir);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    // 2. 项目级
    let project_rules = std::path::Path::new(project_path).join(".ctx-audit/rules");
    if project_rules.exists() {
        return Some(project_rules);
    }
    // 3. 内置
    let builtin = std::path::Path::new("rules");
    if builtin.exists() {
        return Some(builtin.to_path_buf());
    }
    None
}

/// 判断路径是否匹配排除规则
///
/// 排除规则支持两种形式：
/// - 目录名：`test`、`node_modules` → 匹配路径中包含 `/test/`、`/node_modules/`
/// - 文件模式：`*.test.ts`、`*.spec.js`、`*_test.go` → 匹配文件名后缀
/// - 后缀模式：`.json`、`.lock` → 匹配文件扩展名
fn is_excluded(path: &std::path::Path, exclude_patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy().replace('\\', "/");
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    for pattern in exclude_patterns {
        let pat = pattern.trim();
        if pat.is_empty() {
            continue;
        }

        // 文件模式：以 * 或 ? 开头，或包含通配符
        if pat.contains('*') || pat.contains('?') {
            // glob 模式匹配文件名
            if glob_match(pat, file_name) {
                return true;
            }
            // 也匹配完整路径中的模式如 test/**
            if glob_match(pat, &path_str) {
                return true;
            }
            continue;
        }

        // 后缀模式：以 . 开头（如 .json, .lock）
        if pat.starts_with('.') {
            if file_name.ends_with(pat) {
                return true;
            }
            continue;
        }

        // 目录名：匹配路径中的目录段
        let dir_pattern = format!("/{}/", pat.trim_matches('/'));
        if path_str.contains(&dir_pattern) {
            return true;
        }
        if path_str.starts_with(&format!("{}/", pat.trim_matches('/'))) {
            return true;
        }
    }
    false
}

/// 简易 glob 匹配（支持 * 和 ? 通配符）
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_match_impl(&p, &t, 0, 0)
}

fn glob_match_impl(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }
    match pattern[pi] {
        '*' => {
            // * 匹配 0 个或多个字符
            for i in ti..=text.len() {
                if glob_match_impl(pattern, text, pi + 1, i) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if ti < text.len() {
                glob_match_impl(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
        c => {
            if ti < text.len() && text[ti] == c {
                glob_match_impl(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
    }
}

/// 判断路径是否在测试目录中
fn is_test_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    for marker in TEST_DIR_MARKERS {
        if normalized.contains(marker) {
            return true;
        }
    }
    false
}

/// severity 排序值
fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

/// 便捷的 scan_directory 函数（用于web-backend）
pub async fn scan_directory(path: &str) -> Result<Vec<Finding>, String> {
    scan_directory_with_rules(path, None, None).await
}

/// 带自定义规则目录的扫描
pub async fn scan_directory_with_rules(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
) -> Result<Vec<Finding>, String> {
    use ignore::Walk;

    // 合并默认排除 + 用户排除
    let mut excludes: Vec<String> = DEFAULT_EXCLUDE_PATTERNS.iter().map(|s| s.to_string()).collect();
    if let Some(user_excludes) = exclude_dirs {
        for dir in user_excludes {
            let trimmed = dir.trim();
            if !trimmed.is_empty() && !excludes.contains(&trimmed.to_string()) {
                excludes.push(trimmed.to_string());
            }
        }
    }

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

    // 从攻击面生成未认证端点发现（过滤 test 目录）
    for ep in &attack_surface.entry_points {
        if !ep.auth_required && ep.entry_type == crate::analysis::attack_surface::EntryType::HttpEndpoint {
            // 跳过测试目录中的端点
            if is_test_path(&ep.file_path) {
                continue;
            }
            // 跳过排除目录中的端点
            if is_excluded(std::path::Path::new(&ep.file_path), &excludes) {
                continue;
            }
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
    let rules = match resolve_rules_dir(path, rules_dir) {
        Some(rules_path) => {
            tracing::info!("加载规则: {}", rules_path.display());
            match crate::rules::loader::load_rules_from_dir(&rules_path) {
                Ok(r) => {
                    tracing::info!("加载了 {} 条规则", r.len());
                    r
                }
                Err(e) => {
                    tracing::warn!("规则加载失败: {}", e);
                    vec![]
                }
            }
        }
        None => {
            tracing::info!("未找到规则目录");
            vec![]
        }
    };

    // 创建规则扫描器
    let rule_scanner = if !rules.is_empty() {
        Some(crate::rules::scanner::RuleScanner::new(rules))
    } else {
        None
    };

    // 创建 SCA 依赖扫描器
    let sca_scanner = sca_scanner::ScaScanner::new();

    // 收集文件路径
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
    const MEMORY_BUDGET_BYTES: usize = 500 * 1024 * 1024;

    let mut code_files: Vec<std::path::PathBuf> = Vec::new();
    let mut dep_files: Vec<std::path::PathBuf> = Vec::new();

    for entry in Walk::new(path) {
        if let Ok(entry) = entry {
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            // 排除目录过滤
            if is_excluded(path, &excludes) {
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

    // SCA 扫描
    for path_buf in &dep_files {
        if let Ok(content) = std::fs::read_to_string(path_buf) {
            let sca_findings = sca_scanner.scan_file(path_buf, &content).await;
            findings.extend(sca_findings);
        }
    }

    // 代码文件并行扫描
    let rt_handle = tokio::runtime::Handle::current();

    let batch_size = 100;
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

                // 规则扫描
                if let Some(ref scanner) = rule_scanner {
                    let rule_results = rt_handle.block_on(scanner.scan_file(path_buf, &content));
                    file_findings.extend(rule_results);
                }

                file_findings
            })
            .collect();

        total_bytes_read += chunk.len() * 10_000;
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

    // 上下文感知过滤
    for finding in &mut findings {
        let fp = finding.file_path.to_lowercase().replace('\\', "/");
        let is_test = fp.contains("/test") || fp.contains("/tests/") || fp.contains("/__tests__/")
            || fp.contains("/spec/") || fp.ends_with("_test.go") || fp.ends_with("_test.rs")
            || fp.ends_with("_test.py") || fp.ends_with(".test.js") || fp.ends_with(".test.ts")
            || fp.ends_with(".spec.js") || fp.ends_with(".spec.ts");
        let is_example = fp.contains("/example") || fp.contains("/demo") || fp.contains("/sample");

        if is_test || is_example {
            finding.confidence = Some(finding.confidence.unwrap_or(0.7) * 0.3);
        }

        if finding.confidence.is_none() {
            finding.confidence = Some(match finding.detector.as_str() {
                "SCAScanner" => 0.9,
                "RuleScanner" => 0.7,
                "AttackSurfaceMapper" => 0.6,
                _ => 0.5,
            });
        }
    }

    // 基线抑制
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

    // 去重
    findings = deduplicate_findings(findings);

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
pub async fn scan_directory_deep(path: &str) -> Result<Vec<Finding>, String> {
    scan_directory_deep_with_rules(path, None, None).await
}

/// 带自定义规则目录的深度扫描
pub async fn scan_directory_deep_with_rules(
    path: &str,
    rules_dir: Option<&str>,
    exclude_dirs: Option<Vec<String>>,
) -> Result<Vec<Finding>, String> {
    // 先执行基础扫描
    let mut findings = scan_directory_with_rules(path, rules_dir, exclude_dirs).await?;

    if findings.is_empty() {
        return Ok(findings);
    }

    // 收集有候选发现的文件
    let candidate_files: std::collections::HashSet<String> = findings
        .iter()
        .map(|f| f.file_path.clone())
        .collect();

    // AST 污点分析
    let mut analyzer = crate::analysis::ast_taint::AstTaintAnalyzer::new();
    let mut taint_findings: Vec<Finding> = Vec::new();

    for file_path_str in &candidate_files {
        let file_path = std::path::Path::new(file_path_str);

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

                let vuln_name = format!("{}", flow.vulnerability_type);

                taint_findings.push(Finding {
                    finding_id: flow.id.clone(),
                    file_path: file_str,
                    line_start: flow.source.line,
                    line_end: flow.sink.line,
                    detector: "AstTaintScanner".to_string(),
                    vuln_type: vuln_name.clone(),
                    severity: format!("{:?}", flow.severity).to_lowercase(),
                    description: format!(
                        "{}: {} → {} ({}→{})",
                        vuln_name,
                        flow.source.symbol,
                        flow.sink.symbol,
                        flow.source.line,
                        flow.sink.line,
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
            finding.confidence = Some(0.9);
        } else {
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

            let vuln_name = format!("{}", flow.vulnerability_type);

            findings.push(Finding {
                finding_id: flow.id.clone(),
                file_path: flow.source.file_path.clone(),
                line_start: flow.source.line,
                line_end: flow.sink.line,
                detector: "CrossFileTaintAnalyzer".to_string(),
                vuln_type: vuln_name.clone(),
                severity: format!("{:?}", flow.severity).to_lowercase(),
                description: format!(
                    "{}: {}:{} → {}:{} (via {})",
                    vuln_name,
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

/// 判断文件是否支持 AST 分析
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

/// 去重发现：按 (file_path, line_start) 分组，同一行合并为一条
fn deduplicate_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }

    // 按 (file_path, line_start) 分组
    let mut groups: std::collections::HashMap<(String, usize), Vec<usize>> =
        std::collections::HashMap::new();

    for (i, f) in findings.iter().enumerate() {
        let key = (f.file_path.clone(), f.line_start);
        groups.entry(key).or_default().push(i);
    }

    let mut result = Vec::new();
    let mut deduped_indices = std::collections::HashSet::new();

    for (_key, indices) in groups {
        if indices.len() == 1 {
            let idx = indices[0];
            if !deduped_indices.contains(&idx) {
                deduped_indices.insert(idx);
                result.push(findings[idx].clone());
            }
        } else {
            // 多个发现合并：取最高 severity，合并 detector，最长的 description
            let mut best_severity = "info".to_string();
            let mut best_vuln_type = String::new();
            let mut detectors = Vec::new();
            let mut best_confidence: f32 = 0.0;
            let mut best_description = String::new();
            let mut best_trail: Option<Vec<String>> = None;
            let mut best_id = String::new();
            let mut best_end = 0usize;

            for &idx in &indices {
                let f = &findings[idx];
                detectors.push(f.detector.clone());

                if severity_rank(&f.severity) > severity_rank(&best_severity) {
                    best_severity = f.severity.clone();
                }

                // 优先选择 CWE 编号（更具体）而非通用名称
                let current_len = best_vuln_type.len();
                if f.vuln_type.starts_with("CWE-") && !best_vuln_type.starts_with("CWE-") {
                    best_vuln_type = f.vuln_type.clone();
                } else if !f.vuln_type.starts_with("CWE-") && current_len == 0 {
                    best_vuln_type = f.vuln_type.clone();
                } else if f.vuln_type.len() > current_len {
                    best_vuln_type = f.vuln_type.clone();
                }

                if f.confidence.unwrap_or(0.0) > best_confidence {
                    best_confidence = f.confidence.unwrap_or(0.0);
                }

                if f.description.len() > best_description.len() {
                    best_description = f.description.clone();
                }

                if f.analysis_trail.as_ref().map(|t| t.len()).unwrap_or(0)
                    > best_trail.as_ref().map(|t| t.len()).unwrap_or(0)
                {
                    best_trail = f.analysis_trail.clone();
                }

                if f.line_end > best_end {
                    best_end = f.line_end;
                    best_id = f.finding_id.clone();
                }

                deduped_indices.insert(idx);
            }

            // 去重 detector 列表
            detectors.sort();
            detectors.dedup();

            result.push(Finding {
                finding_id: best_id,
                file_path: findings[indices[0]].file_path.clone(),
                line_start: findings[indices[0]].line_start,
                line_end: best_end,
                detector: detectors.join("+"),
                vuln_type: best_vuln_type,
                severity: best_severity,
                description: best_description,
                analysis_trail: best_trail,
                llm_output: None,
                confidence: Some(best_confidence.min(0.5 + 0.1 * indices.len() as f32).min(1.0)),
                corroboration_count: Some(indices.len()),
            });
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
