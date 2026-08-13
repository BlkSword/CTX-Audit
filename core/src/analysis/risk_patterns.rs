// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 风险模式扫描引擎
//!
//! 检测架构级安全风险模式，结合入口点分析、数据流启发式和防护缺失检测。
//! 用于发现 0-day 漏洞候选项，辅助 LLM 进行深度安全推理。

use crate::analysis::attack_surface::{AttackSurface, EntryPoint, EntryType};
use crate::rules::model::Severity;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── 数据模型 ──────────────────────────────────────────────

/// 风险模式定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub source_conditions: Vec<PatternCondition>,
    #[serde(default)]
    pub sink_conditions: Vec<PatternCondition>,
    #[serde(default)]
    pub missing_patterns: Vec<PatternCondition>,
    #[serde(default)]
    pub risk_factors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
}

/// 模式匹配条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCondition {
    pub pattern: String,
    #[serde(default = "default_languages")]
    pub languages: Vec<String>,
    #[serde(default = "default_context")]
    pub context: String,
}

fn default_languages() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_context() -> String {
    "file".to_string()
}

/// 风险模式文件容器
#[derive(Debug, Deserialize)]
struct RiskPatternFile {
    patterns: Vec<RiskPattern>,
}

/// 编译后的条件（regex 预编译）
struct CompiledCondition {
    original: PatternCondition,
    regex: Regex,
}

/// 编译后的风险模式
struct CompiledPattern {
    pattern: RiskPattern,
    source_conditions: Vec<CompiledCondition>,
    sink_conditions: Vec<CompiledCondition>,
    missing_conditions: Vec<CompiledCondition>,
}

/// 风险模式匹配结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskPatternMatch {
    pub pattern_id: String,
    pub pattern_name: String,
    pub severity: Severity,
    pub confidence: f32,
    pub affected_entries: Vec<AffectedEntry>,
    pub evidence: Vec<EvidenceSnippet>,
    pub risk_factors: Vec<String>,
    pub cwe: Option<String>,
}

/// 受影响的入口点
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedEntry {
    pub file_path: String,
    pub line: usize,
    pub entry_type: String,
    pub function_name: Option<String>,
    pub route: Option<String>,
}

/// 证据片段
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSnippet {
    pub file_path: String,
    pub line: usize,
    pub matched_pattern: String,
    pub code_snippet: String,
    pub context_type: String,
}

// ── 风险模式扫描器 ────────────────────────────────────────

/// 风险模式扫描器
pub struct RiskPatternScanner {
    patterns: Vec<CompiledPattern>,
}

impl RiskPatternScanner {
    /// 创建扫描器并加载风险模式
    pub fn new(project_path: &Path) -> Self {
        let mut all_patterns = Vec::new();

        // 加载内置模式
        if let Ok(built_in) = Self::load_yaml(include_str!("../../../rules/risk-patterns.yaml")) {
            all_patterns.extend(built_in);
        }

        // 加载项目级自定义模式
        let custom_path = project_path.join(".ctx-audit/rules/risk-patterns.yaml");
        if custom_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&custom_path) {
                if let Ok(custom) = Self::load_yaml(&content) {
                    // 项目级覆盖内置（按 ID）
                    let custom_ids: Vec<&str> = custom.iter().map(|p| p.id.as_str()).collect();
                    all_patterns.retain(|p| !custom_ids.contains(&p.id.as_str()));
                    all_patterns.extend(custom);
                }
            }
        }

        // 编译正则
        let compiled: Vec<CompiledPattern> = all_patterns
            .into_iter()
            .filter_map(|p| Self::compile_pattern(p))
            .collect();

        RiskPatternScanner { patterns: compiled }
    }

    /// 扫描攻击面匹配风险模式
    pub fn scan(&self, surface: &AttackSurface, _project_path: &Path) -> Vec<RiskPatternMatch> {
        // 一次性读取所有涉及的文件
        let file_cache = Self::load_file_cache(surface);

        let mut matches = Vec::new();

        for compiled in &self.patterns {
            let pattern_matches = self.scan_pattern(compiled, surface, &file_cache);
            matches.extend(pattern_matches);
        }

        matches
    }

    /// 获取已加载的模式数量
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// 获取模式 ID 列表
    pub fn pattern_ids(&self) -> Vec<&str> {
        self.patterns
            .iter()
            .map(|p| p.pattern.id.as_str())
            .collect()
    }

    // ── 内部方法 ──

    fn load_yaml(content: &str) -> Result<Vec<RiskPattern>, String> {
        let file: RiskPatternFile =
            serde_yaml::from_str(content).map_err(|e| format!("YAML parse error: {}", e))?;
        Ok(file.patterns)
    }

    fn compile_pattern(pattern: RiskPattern) -> Option<CompiledPattern> {
        let compile = |conditions: &[PatternCondition]| -> Vec<CompiledCondition> {
            conditions
                .iter()
                .filter_map(|c| {
                    Regex::new(&c.pattern).ok().map(|regex| CompiledCondition {
                        original: c.clone(),
                        regex,
                    })
                })
                .collect()
        };

        let source_conditions = compile(&pattern.source_conditions);
        let sink_conditions = compile(&pattern.sink_conditions);
        let missing_conditions = compile(&pattern.missing_patterns);

        Some(CompiledPattern {
            pattern,
            source_conditions,
            sink_conditions,
            missing_conditions,
        })
    }

    fn load_file_cache(surface: &AttackSurface) -> HashMap<String, String> {
        let mut cache = HashMap::new();
        for ep in &surface.entry_points {
            if !cache.contains_key(&ep.file_path) {
                if let Ok(content) = std::fs::read_to_string(&ep.file_path) {
                    cache.insert(ep.file_path.clone(), content);
                }
            }
        }
        cache
    }

    fn scan_pattern(
        &self,
        compiled: &CompiledPattern,
        surface: &AttackSurface,
        file_cache: &HashMap<String, String>,
    ) -> Vec<RiskPatternMatch> {
        let mut matches = Vec::new();

        for ep in &surface.entry_points {
            let file_content = match file_cache.get(&ep.file_path) {
                Some(c) => c.as_str(),
                None => continue,
            };

            // 获取入口点附近的上下文块
            let context_block = Self::get_context_block(file_content, ep.line, 40);

            // 检查 source conditions（在入口点上下文中）
            let source_matched = Self::check_conditions(
                &compiled.source_conditions,
                &context_block,
                &ep.file_path,
                file_content,
            );
            let has_source = !compiled.source_conditions.is_empty();

            // 检查 sink conditions（在文件内容中）
            let sink_matched = Self::check_conditions(
                &compiled.sink_conditions,
                file_content,
                &ep.file_path,
                file_content,
            );
            let has_sink = !compiled.sink_conditions.is_empty();

            // 检查 missing patterns（防护模式应该存在但不存在）
            let missing_detected =
                Self::check_missing(&compiled.missing_conditions, &context_block, file_content);
            let has_missing = !compiled.missing_conditions.is_empty();

            // 计算 confidence
            let confidence = Self::compute_confidence(
                has_source && !source_matched.is_empty(),
                has_sink && !sink_matched.is_empty(),
                has_missing && missing_detected,
                has_source,
                has_sink,
                has_missing,
            );

            if confidence < 0.4 {
                continue;
            }

            // 收集受影响的入口点
            let affected = AffectedEntry {
                file_path: ep.file_path.clone(),
                line: ep.line,
                entry_type: format!("{:?}", ep.entry_type),
                function_name: ep.function_name.clone(),
                route: ep.route.clone(),
            };

            // 收集证据
            let mut evidence = Vec::new();
            evidence.extend(source_matched);
            evidence.extend(sink_matched);

            matches.push(RiskPatternMatch {
                pattern_id: compiled.pattern.id.clone(),
                pattern_name: compiled.pattern.name.clone(),
                severity: compiled.pattern.severity.clone(),
                confidence,
                affected_entries: vec![affected],
                evidence,
                risk_factors: compiled.pattern.risk_factors.clone(),
                cwe: compiled.pattern.cwe.clone(),
            });
        }

        // 合并同一模式的多个匹配
        Self::merge_matches(matches)
    }

    fn check_conditions(
        conditions: &[CompiledCondition],
        context: &str,
        file_path: &str,
        file_content: &str,
    ) -> Vec<EvidenceSnippet> {
        let mut evidence = Vec::new();

        for cc in conditions {
            let search_text = if cc.original.context == "function" {
                context
            } else {
                file_content
            };

            for (line_num, line) in search_text.lines().enumerate() {
                if cc.regex.is_match(line) {
                    evidence.push(EvidenceSnippet {
                        file_path: file_path.to_string(),
                        line: line_num + 1,
                        matched_pattern: cc.original.pattern.clone(),
                        code_snippet: line.trim().chars().take(120).collect(),
                        context_type: "source".to_string(),
                    });
                    break; // 每个条件只取第一个匹配
                }
            }
        }

        evidence
    }

    fn check_missing(conditions: &[CompiledCondition], context: &str, file_content: &str) -> bool {
        // "missing" 意味着防护模式**不**存在 → 所有条件都不匹配时为 true
        if conditions.is_empty() {
            return true; // 无 missing 条件视为匹配
        }

        for cc in conditions {
            let search_text = if cc.original.context == "function" {
                context
            } else {
                file_content
            };
            if cc.regex.is_match(search_text) {
                return false; // 找到了防护模式 → 不是缺失
            }
        }
        true // 所有防护模式都不存在 → 缺失
    }

    fn compute_confidence(
        source_ok: bool,
        sink_ok: bool,
        missing_ok: bool,
        has_source: bool,
        has_sink: bool,
        has_missing: bool,
    ) -> f32 {
        // 只检查有定义的条件
        let (s, k, m) = (
            if has_source { source_ok } else { true },
            if has_sink { sink_ok } else { true },
            if has_missing { missing_ok } else { true },
        );

        let defined_count = has_source as u8 + has_sink as u8 + has_missing as u8;
        if defined_count == 0 {
            return 0.0;
        }

        let matched = s as u8 + k as u8 + m as u8;
        match matched {
            3 => 0.9,
            2 => 0.7,
            1 => 0.5,
            _ => 0.0,
        }
    }

    fn merge_matches(matches: Vec<RiskPatternMatch>) -> Vec<RiskPatternMatch> {
        let mut merged: HashMap<String, RiskPatternMatch> = HashMap::new();
        for m in matches {
            let key = format!(
                "{}-{}",
                m.pattern_id,
                m.affected_entries
                    .first()
                    .map(|e| &e.file_path)
                    .unwrap_or(&String::new())
            );
            match merged.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    let existing = e.get_mut();
                    existing.affected_entries.extend(m.affected_entries);
                    existing.evidence.extend(m.evidence);
                    existing.confidence = existing.confidence.max(m.confidence);
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(m);
                }
            }
        }
        merged.into_values().collect()
    }

    fn get_context_block(content: &str, center_line: usize, radius: usize) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let start = center_line.saturating_sub(radius);
        let end = (center_line + radius).min(lines.len());
        lines[start..end].join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_builtin_patterns() {
        let scanner = RiskPatternScanner::new(Path::new("."));
        assert!(
            scanner.pattern_count() >= 5,
            "Should load at least 5 built-in patterns"
        );
        let ids = scanner.pattern_ids();
        assert!(ids.contains(&"unvalidated-input-to-deserialization"));
        assert!(ids.contains(&"prototype-pollution-vector"));
    }

    #[test]
    fn test_pattern_matching_full_confidence() {
        let mut scanner = RiskPatternScanner::new(Path::new("."));

        // 构造一个测试用的 AttackSurface
        let surface = AttackSurface {
            entry_points: vec![EntryPoint {
                file_path: "test.ts".to_string(),
                line: 1,
                entry_type: EntryType::ServerAction,
                route: None,
                http_method: Some("POST".to_string()),
                auth_required: false,
                auth_mechanism: None,
                risk_score: 0.9,
                function_name: Some("createUser".to_string()),
                context: Default::default(),
            }],
            trust_boundaries: vec![],
            high_risk_files: vec!["test.ts".to_string()],
            stats: Default::default(),
        };

        // 临时写一个测试文件
        let test_code = r#"
'use server'
export async function createUser(formData: FormData) {
    const name = formData.get('name');
    const data = JSON.parse(name);
    eval(data.command);
}
"#;
        std::fs::write("test.ts", test_code).unwrap();

        let matches = scanner.scan(&surface, Path::new("."));
        assert!(
            !matches.is_empty(),
            "Should find at least one risk pattern match"
        );

        // 清理
        let _ = std::fs::remove_file("test.ts");
    }

    #[test]
    fn test_eval_sink_excludes_angular_dollar_eval() {
        // R76 登记：AngularJS 的 $$eval(/$eval( 不得命中 eval sink 条件；
        // 同时守护含 eval 的条件正则必须真实编译进扫描器
        // （compile 失败会被 filter_map 静默丢弃）
        let scanner = RiskPatternScanner::new(Path::new("."));
        let mut checked = 0;
        for compiled in &scanner.patterns {
            for cond in compiled
                .sink_conditions
                .iter()
                .chain(compiled.source_conditions.iter())
            {
                if cond.original.pattern.contains("eval") {
                    checked += 1;
                    assert!(
                        !cond.regex.is_match("scope.$$eval('a + b');"),
                        "$$eval( 不应命中: {}",
                        cond.original.pattern
                    );
                    assert!(
                        !cond.regex.is_match("scope.$eval('a + b');"),
                        "$eval( 不应命中: {}",
                        cond.original.pattern
                    );
                    assert!(
                        cond.regex.is_match("eval(userInput);"),
                        "原生 eval( 应命中: {}",
                        cond.original.pattern
                    );
                }
            }
        }
        assert!(checked >= 2, "应至少覆盖两处 eval sink 条件，实际 {}", checked);
    }

    #[test]
    fn test_empty_attack_surface() {
        let scanner = RiskPatternScanner::new(Path::new("."));
        let surface = AttackSurface {
            entry_points: vec![],
            trust_boundaries: vec![],
            high_risk_files: vec![],
            stats: Default::default(),
        };
        let matches = scanner.scan(&surface, Path::new("."));
        assert!(
            matches.is_empty(),
            "Empty surface should produce no matches"
        );
    }
}
