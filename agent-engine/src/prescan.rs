// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 确定性预扫描模块
//!
//! 在 LLM 分析前执行污点分析和模式检测，收集候选漏洞

use std::path::Path;
use std::sync::Arc;

use crate::audit_state::{
    SecurityAuditState, AnalysisTarget, TargetPriority, TargetType,
    VulnerabilityCandidate, PropagationStepInfo, ProjectInfo, UserInputPoint,
    SensitiveFunctionCall, AnalysisContext,
};
use deepaudit_core::TaintAnalyzer;

/// 预扫描配置
#[derive(Debug, Clone)]
pub struct PrescanConfig {
    /// 是否执行污点分析
    pub enable_taint_analysis: bool,

    /// 是否执行模式检测
    pub enable_pattern_detection: bool,

    /// 最大扫描文件数
    pub max_files: usize,

    /// 文件大小限制（字节）
    pub max_file_size: usize,

    /// 并发扫描数
    pub concurrency: usize,
}

impl Default for PrescanConfig {
    fn default() -> Self {
        Self {
            enable_taint_analysis: true,
            enable_pattern_detection: true,
            max_files: 1000,
            max_file_size: 1024 * 1024, // 1MB
            concurrency: 4,
        }
    }
}

/// 预扫描结果
#[derive(Debug, Clone)]
pub struct PrescanResult {
    /// 扫描的文件数
    pub files_scanned: usize,

    /// 发现的候选漏洞数
    pub candidates_found: usize,

    /// 发现的用户输入点数
    pub input_points_found: usize,

    /// 发现的敏感函数调用数
    pub sensitive_calls_found: usize,

    /// 耗时（毫秒）
    pub duration_ms: u64,
}

/// 确定性预扫描器
pub struct DeterministicPrescanner {
    config: PrescanConfig,
    taint_analyzer: TaintAnalyzer,
}

impl DeterministicPrescanner {
    /// 创建新的预扫描器
    pub fn new(config: PrescanConfig) -> Self {
        Self {
            config,
            taint_analyzer: TaintAnalyzer::new(),
        }
    }

    /// 使用默认配置创建
    pub fn with_defaults() -> Self {
        Self::new(PrescanConfig::default())
    }

    /// 执行预扫描
    pub async fn scan(&self, state: &mut SecurityAuditState) -> PrescanResult {
        let start = std::time::Instant::now();
        let mut result = PrescanResult {
            files_scanned: 0,
            candidates_found: 0,
            input_points_found: 0,
            sensitive_calls_found: 0,
            duration_ms: 0,
        };

        // 收集要扫描的文件
        let files = self.collect_files(&state.project_path);
        result.files_scanned = files.len().min(self.config.max_files);

        // 对每个文件执行扫描
        for file_path in files.into_iter().take(self.config.max_files) {
            self.scan_file(file_path, state, &mut result);
        }

        // 确定性过滤：移除明显的误报（第三方库、配置占位符、TODO）
        let before = state.vulnerability_candidates.len();
        let filter = crate::verification::dual_verification::DeterministicFilter::new();
        state.vulnerability_candidates = filter.filter(std::mem::take(&mut state.vulnerability_candidates));
        let filtered = before - state.vulnerability_candidates.len();
        if filtered > 0 {
            tracing::info!("[DeterministicFilter] 过滤掉 {} 个明显误报，保留 {} 个候选", filtered, state.vulnerability_candidates.len());
        }

        // 根据扫描结果生成分析目标
        self.generate_analysis_targets(state);

        result.duration_ms = start.elapsed().as_millis() as u64;
        result.candidates_found = state.vulnerability_candidates.len();
        result.input_points_found = state.analysis_context.user_input_points.len();
        result.sensitive_calls_found = state.analysis_context.sensitive_functions.len();

        result
    }

    /// 收集项目文件
    fn collect_files(&self, project_path: &str) -> Vec<String> {
        let mut files = Vec::new();
        let path = Path::new(project_path);

        if path.exists() {
            self.collect_files_recursive(path, project_path, &mut files);
        }

        // 按优先级排序（先扫描入口文件和关键目录）
        files.sort_by(|a, b| {
            let priority = |f: &str| {
                if f.contains("main") || f.contains("index") || f.contains("app") {
                    0
                } else if f.contains("route") || f.contains("handler") || f.contains("controller") {
                    1
                } else if f.contains("api") || f.contains("service") {
                    2
                } else {
                    3
                }
            };
            priority(a).cmp(&priority(b))
        });

        files
    }

    /// 递归收集文件
    fn collect_files_recursive(&self, dir: &Path, base_path: &str, files: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                // 跳过隐藏目录和非代码目录
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if !name.starts_with('.') && !Self::should_skip_dir(name) {
                            self.collect_files_recursive(&path, base_path, files);
                        }
                    }
                } else if path.is_file() {
                    // 检查文件扩展名和大小
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        if Self::is_code_file(ext) {
                            // 检查文件大小
                            if let Ok(metadata) = std::fs::metadata(&path) {
                                if metadata.len() <= self.config.max_file_size as u64 {
                                    if let Ok(relative) = path.strip_prefix(base_path) {
                                        files.push(relative.to_string_lossy().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// 是否应该跳过目录
    fn should_skip_dir(name: &str) -> bool {
        matches!(
            name,
            "node_modules" | "target" | "vendor" | "__pycache__" |
            "dist" | "build" | ".git" | ".svn" | ".hg" |
            "venv" | "env" | ".venv" | "cache" | "tmp"
        )
    }

    /// 是否是代码文件
    fn is_code_file(ext: &str) -> bool {
        matches!(
            ext.to_lowercase().as_str(),
            "py" | "js" | "jsx" | "ts" | "tsx" | "java" | "rs" | "go" |
            "c" | "cpp" | "cc" | "cxx" | "h" | "hpp" | "php" | "rb" |
            "cs" | "swift" | "kt" | "scala"
        )
    }

    /// 从路径推断语言
    fn infer_language(file_path: &str) -> &str {
        let ext = Path::new(file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext {
            "py" => "python",
            "js" | "jsx" => "javascript",
            "ts" | "tsx" => "typescript",
            "java" => "java",
            "rs" => "rust",
            "go" => "go",
            "c" | "h" => "c",
            "cpp" | "cc" | "cxx" | "hpp" => "cpp",
            "php" => "php",
            "rb" => "ruby",
            _ => "unknown",
        }
    }

    /// 扫描单个文件
    fn scan_file(&self, file_path: String, state: &mut SecurityAuditState, result: &mut PrescanResult) {
        let full_path = Path::new(&state.project_path).join(&file_path);

        // 读取文件内容
        let content = match std::fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let language = Self::infer_language(&file_path);
        let lines: Vec<&str> = content.lines().collect();

        // 1. 污点分析
        if self.config.enable_taint_analysis {
            self.run_taint_analysis(&file_path, &content, language, state);
        }

        // 2. 模式检测
        if self.config.enable_pattern_detection {
            self.run_pattern_detection(&file_path, &lines, state);
        }

        // 3. 提取用户输入点
        self.extract_user_input_points(&file_path, &lines, language, state);

        // 4. 提取敏感函数调用
        self.extract_sensitive_calls(&file_path, &lines, language, state);
    }

    /// 执行污点分析
    fn run_taint_analysis(&self, file_path: &str, content: &str, language: &str, state: &mut SecurityAuditState) {
        let flows = self.taint_analyzer.analyze(content, file_path, language);

        for flow in flows {
            // 构建传播路径
            let propagation_path: Vec<PropagationStepInfo> = flow.path.iter().map(|node| {
                PropagationStepInfo {
                    line: node.line,
                    symbol: node.symbol.clone(),
                    code: node.code_snippet.clone(),
                }
            }).collect();

            let candidate = VulnerabilityCandidate::new(
                format!("{:?}", flow.vulnerability_type),
                format!("{:?}", flow.severity).to_lowercase(),
                flow.confidence,
                "taint_analysis".to_string(),
                file_path.to_string(),
                flow.sink.line,
            )
            .with_code(flow.sink.code_snippet.clone().unwrap_or_default())
            .with_propagation_path(propagation_path);

            state.add_vulnerability_candidate(candidate);
        }
    }

    /// 执行模式检测
    fn run_pattern_detection(&self, file_path: &str, lines: &[&str], state: &mut SecurityAuditState) {
        // 使用内置的漏洞模式
        let patterns = self.get_vulnerability_patterns();

        for (line_idx, line) in lines.iter().enumerate() {
            for pattern in &patterns {
                if let Ok(re) = regex::Regex::new(&pattern.pattern) {
                    if re.is_match(line) {
                        let candidate = VulnerabilityCandidate::new(
                            pattern.vulnerability_type.clone(),
                            pattern.severity.clone(),
                            pattern.confidence,
                            "pattern_detection".to_string(),
                            file_path.to_string(),
                            line_idx + 1,
                        )
                        .with_code(line.trim().to_string());

                        state.add_vulnerability_candidate(candidate);
                    }
                }
            }
        }
    }

    /// 获取漏洞模式
    fn get_vulnerability_patterns(&self) -> Vec<VulnerabilityPattern> {
        vec![
            // SQL 注入
            VulnerabilityPattern {
                pattern: r#"["']SELECT.*\+.*"#.to_string(),
                vulnerability_type: "SQL Injection".to_string(),
                severity: "high".to_string(),
                confidence: 0.7,
            },
            VulnerabilityPattern {
                pattern: r#"execute\(.*\+.*\)"#.to_string(),
                vulnerability_type: "SQL Injection".to_string(),
                severity: "high".to_string(),
                confidence: 0.8,
            },
            VulnerabilityPattern {
                pattern: r#"f["'].*SELECT.*\{.*\}"#.to_string(),
                vulnerability_type: "SQL Injection".to_string(),
                severity: "high".to_string(),
                confidence: 0.9,
            },

            // 命令注入
            VulnerabilityPattern {
                pattern: r#"exec\(.*\+.*\)"#.to_string(),
                vulnerability_type: "Command Injection".to_string(),
                severity: "critical".to_string(),
                confidence: 0.85,
            },
            VulnerabilityPattern {
                pattern: r#"os\.system\(.*\+.*\)"#.to_string(),
                vulnerability_type: "Command Injection".to_string(),
                severity: "critical".to_string(),
                confidence: 0.9,
            },
            VulnerabilityPattern {
                pattern: r#"subprocess.*shell=True"#.to_string(),
                vulnerability_type: "Command Injection".to_string(),
                severity: "high".to_string(),
                confidence: 0.8,
            },

            // XSS
            VulnerabilityPattern {
                pattern: r#"innerHTML\s*=\s*.*request\."#.to_string(),
                vulnerability_type: "Cross-Site Scripting".to_string(),
                severity: "high".to_string(),
                confidence: 0.8,
            },
            VulnerabilityPattern {
                pattern: r#"document\.write\(.*request\."#.to_string(),
                vulnerability_type: "Cross-Site Scripting".to_string(),
                severity: "high".to_string(),
                confidence: 0.8,
            },

            // 路径遍历
            VulnerabilityPattern {
                pattern: r#"open\(.*request\."#.to_string(),
                vulnerability_type: "Path Traversal".to_string(),
                severity: "high".to_string(),
                confidence: 0.75,
            },
            VulnerabilityPattern {
                pattern: r#"readFile\(.*req\."#.to_string(),
                vulnerability_type: "Path Traversal".to_string(),
                severity: "high".to_string(),
                confidence: 0.75,
            },

            // 硬编码密钥
            VulnerabilityPattern {
                pattern: r#"(?i)password\s*=\s*["'][^"']{8,}["']"#.to_string(),
                vulnerability_type: "Hardcoded Credential".to_string(),
                severity: "medium".to_string(),
                confidence: 0.7,
            },
            VulnerabilityPattern {
                pattern: r#"(?i)api_key\s*=\s*["'][^"']{16,}["']"#.to_string(),
                vulnerability_type: "Hardcoded Credential".to_string(),
                severity: "medium".to_string(),
                confidence: 0.7,
            },

            // SSRF
            VulnerabilityPattern {
                pattern: r#"fetch\(.*request\."#.to_string(),
                vulnerability_type: "SSRF".to_string(),
                severity: "high".to_string(),
                confidence: 0.6,
            },
            VulnerabilityPattern {
                pattern: r#"requests\.get\(.*\+.*\)"#.to_string(),
                vulnerability_type: "SSRF".to_string(),
                severity: "high".to_string(),
                confidence: 0.65,
            },
        ]
    }

    /// 提取用户输入点
    fn extract_user_input_points(&self, file_path: &str, lines: &[&str], language: &str, state: &mut SecurityAuditState) {
        let input_patterns = match language {
            "python" => vec![
                (r#"request\.args\.get"#, "HTTP GET Parameter"),
                (r#"request\.form"#, "HTTP POST Form"),
                (r#"request\.json"#, "HTTP JSON Body"),
                (r#"request\.data"#, "HTTP Request Body"),
                (r#"input\("#, "Console Input"),
                (r#"sys\.argv"#, "Command Line Argument"),
                (r#"os\.environ"#, "Environment Variable"),
            ],
            "javascript" | "typescript" => vec![
                (r#"req\.params"#, "HTTP Route Parameter"),
                (r#"req\.query"#, "HTTP Query Parameter"),
                (r#"req\.body"#, "HTTP Request Body"),
                (r#"req\.headers"#, "HTTP Headers"),
                (r#"process\.env"#, "Environment Variable"),
            ],
            "java" => vec![
                (r#"request\.getParameter"#, "HTTP Parameter"),
                (r#"HttpServletRequest"#, "HTTP Request"),
                (r#"System\.getenv"#, "Environment Variable"),
            ],
            _ => vec![],
        };

        for (line_idx, line) in lines.iter().enumerate() {
            for (pattern, source_type) in &input_patterns {
                if line.contains(pattern) {
                    // 尝试提取变量名
                    let var_name = self.extract_variable_name(line, pattern);

                    state.analysis_context.user_input_points.push(UserInputPoint {
                        source_type: source_type.to_string(),
                        file_path: file_path.to_string(),
                        line: line_idx + 1,
                        variable_name: var_name,
                    });
                }
            }
        }
    }

    /// 提取变量名
    fn extract_variable_name(&self, line: &str, _pattern: &str) -> String {
        // 简单提取：找到 = 前面的变量名
        if let Some(eq_pos) = line.find('=') {
            let before_eq = &line[..eq_pos];
            let words: Vec<&str> = before_eq.split_whitespace().collect();
            if let Some(last) = words.last() {
                return last.to_string();
            }
        }
        "unknown".to_string()
    }

    /// 提取敏感函数调用
    fn extract_sensitive_calls(&self, file_path: &str, lines: &[&str], _language: &str, state: &mut SecurityAuditState) {
        let sensitive_functions = [
            ("execute", "SQL Execution"),
            ("query", "SQL Query"),
            ("exec", "Command Execution"),
            ("system", "System Command"),
            ("eval", "Code Evaluation"),
            ("popen", "Process Open"),
            ("subprocess", "Subprocess"),
            ("spawn", "Process Spawn"),
            ("open", "File Operation"),
            ("readFile", "File Read"),
            ("writeFile", "File Write"),
            ("unlink", "File Delete"),
            ("fetch", "HTTP Request"),
            ("axios", "HTTP Request"),
            ("requests", "HTTP Request"),
        ];

        for (line_idx, line) in lines.iter().enumerate() {
            for (func_name, risk_category) in &sensitive_functions {
                // 检查是否是函数调用（包含括号）
                if line.contains(&format!("{}(", func_name)) || line.contains(&format!("{} (", func_name)) {
                    state.analysis_context.sensitive_functions.push(SensitiveFunctionCall {
                        function_name: func_name.to_string(),
                        file_path: file_path.to_string(),
                        line: line_idx + 1,
                        risk_category: risk_category.to_string(),
                    });
                }
            }
        }
    }

    /// 根据扫描结果生成分析目标
    fn generate_analysis_targets(&self, state: &mut SecurityAuditState) {
        // 1. 为有候选漏洞的文件创建高优先级目标
        let mut files_with_candidates: std::collections::HashSet<String> = std::collections::HashSet::new();

        for candidate in &state.vulnerability_candidates {
            files_with_candidates.insert(candidate.file_path.clone());
        }

        // 先收集所有需要创建的目标
        let mut targets_to_add = Vec::new();

        for file_path in &files_with_candidates {
            let priority = if candidate_count_for_file(&state.vulnerability_candidates, file_path) > 3 {
                TargetPriority::Critical
            } else {
                TargetPriority::High
            };

            let mut target = AnalysisTarget::file(
                file_path.clone(),
                priority,
                "包含候选漏洞".to_string(),
            );

            // 关联候选漏洞
            for candidate in &state.vulnerability_candidates {
                if &candidate.file_path == file_path {
                    target.add_candidate(candidate.id.clone());
                }
            }

            targets_to_add.push(target);
        }

        // 2. 为有用户输入点的文件创建中等优先级目标
        for input_point in &state.analysis_context.user_input_points {
            if !state.analyzed_files.contains(&input_point.file_path) && !files_with_candidates.contains(&input_point.file_path) {
                let target = AnalysisTarget::file(
                    input_point.file_path.clone(),
                    TargetPriority::Medium,
                    format!("包含用户输入点: {}", input_point.source_type),
                );
                targets_to_add.push(target);
            }
        }

        // 3. 为有敏感函数调用的文件创建目标
        for sensitive_call in &state.analysis_context.sensitive_functions {
            if !state.analyzed_files.contains(&sensitive_call.file_path) && !files_with_candidates.contains(&sensitive_call.file_path) {
                let target = AnalysisTarget::file(
                    sensitive_call.file_path.clone(),
                    TargetPriority::Medium,
                    format!("包含敏感函数: {}", sensitive_call.function_name),
                );
                targets_to_add.push(target);
            }
        }

        // 批量添加目标
        for target in targets_to_add {
            state.add_target(target);
        }
    }
}

/// 统计文件的候选漏洞数量
fn candidate_count_for_file(candidates: &[VulnerabilityCandidate], file_path: &str) -> usize {
    candidates.iter().filter(|c| c.file_path == file_path).count()
}

/// 漏洞模式
struct VulnerabilityPattern {
    pattern: String,
    vulnerability_type: String,
    severity: String,
    confidence: f32,
}

/// 项目信息收集器
pub struct ProjectInfoCollector;

impl ProjectInfoCollector {
    /// 收集项目信息
    pub fn collect(project_path: &str) -> ProjectInfo {
        let mut info = ProjectInfo::default();

        // 检测项目类型和技术栈
        Self::detect_project_type(project_path, &mut info);

        // 查找入口点
        Self::find_entry_points(project_path, &mut info);

        // 检测框架
        Self::detect_frameworks(project_path, &mut info);

        info
    }

    /// 检测项目类型
    fn detect_project_type(project_path: &str, info: &mut ProjectInfo) {
        let path = Path::new(project_path);

        // Python
        if path.join("requirements.txt").exists() || path.join("setup.py").exists() || path.join("pyproject.toml").exists() {
            info.tech_stack.push("Python".to_string());
            info.project_type = Some("Python Application".to_string());
        }

        // Node.js
        if path.join("package.json").exists() {
            info.tech_stack.push("Node.js".to_string());
            info.project_type = Some("Node.js Application".to_string());

            // 尝试读取 package.json 获取更多信息
            if let Ok(content) = std::fs::read_to_string(path.join("package.json")) {
                if content.contains("express") {
                    info.frameworks.push("Express".to_string());
                }
                if content.contains("next") {
                    info.frameworks.push("Next.js".to_string());
                }
                if content.contains("react") {
                    info.tech_stack.push("React".to_string());
                }
                if content.contains("vue") {
                    info.tech_stack.push("Vue".to_string());
                }
            }
        }

        // Rust
        if path.join("Cargo.toml").exists() {
            info.tech_stack.push("Rust".to_string());
            info.project_type = Some("Rust Application".to_string());
        }

        // Go
        if path.join("go.mod").exists() {
            info.tech_stack.push("Go".to_string());
            info.project_type = Some("Go Application".to_string());
        }

        // Java
        if path.join("pom.xml").exists() {
            info.tech_stack.push("Java".to_string());
            info.frameworks.push("Maven".to_string());
            info.project_type = Some("Java Application".to_string());
        }
        // Gradle: 检测 build.gradle 或 settings.gradle (多模块项目)
        if path.join("build.gradle").exists() || path.join("build.gradle.kts").exists() ||
           path.join("settings.gradle").exists() || path.join("settings.gradle.kts").exists() {
            info.tech_stack.push("Java".to_string());
            info.frameworks.push("Gradle".to_string());
            info.project_type = Some("Java Application".to_string());
        }
    }

    /// 查找入口点
    fn find_entry_points(project_path: &str, info: &mut ProjectInfo) {
        let entry_files = [
            "main.py", "app.py", "wsgi.py", "asgi.py",
            "index.js", "app.js", "server.js", "main.js",
            "main.rs", "lib.rs",
            "main.go",
            "Main.java", "Application.java",
            "index.ts", "main.ts", "app.ts",
        ];

        let path = Path::new(project_path);
        for entry in &entry_files {
            if path.join(entry).exists() {
                info.entry_points.push(entry.to_string());
            }
        }

        // 搜索路由文件
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains("route") || name.contains("controller") || name.contains("handler") {
                    info.entry_points.push(name);
                }
            }
        }
    }

    /// 检测框架
    fn detect_frameworks(project_path: &str, info: &mut ProjectInfo) {
        let path = Path::new(project_path);

        // Django
        if path.join("manage.py").exists() {
            info.frameworks.push("Django".to_string());
        }

        // Flask
        if path.join("app.py").exists() {
            if let Ok(content) = std::fs::read_to_string(path.join("app.py")) {
                if content.contains("Flask") {
                    info.frameworks.push("Flask".to_string());
                }
            }
        }

        // Spring Boot
        if let Ok(content) = std::fs::read_to_string(path.join("pom.xml")) {
            if content.contains("spring-boot") {
                info.frameworks.push("Spring Boot".to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prescan_config_default() {
        let config = PrescanConfig::default();
        assert!(config.enable_taint_analysis);
        assert!(config.enable_pattern_detection);
    }

    #[test]
    fn test_project_info_collector() {
        // 测试当前项目
        let info = ProjectInfoCollector::collect(".");
        assert!(info.tech_stack.contains(&"Rust".to_string()));
    }

    #[test]
    fn test_is_code_file() {
        assert!(DeterministicPrescanner::with_defaults().config.enable_taint_analysis);
        assert!(DeterministicPrescanner::is_code_file("py"));
        assert!(DeterministicPrescanner::is_code_file("js"));
        assert!(!DeterministicPrescanner::is_code_file("txt"));
    }
}
