// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 内置嵌入规则
//!
//! 将仓库根目录的 `rules/` 通过 `include_dir` 打包进二进制。
//! 当文件系统上的规则目录查找失败（例如在仓库外运行、
//! `cargo install` 安装后的任意目录）时，回退到这些嵌入规则，
//! 保证规则扫描与污点分析在任何工作目录下都可用。

use include_dir::{include_dir, Dir, DirEntry};

use crate::rules::audit_pack::AuditPack;
use crate::rules::model::{Rule, RuleSet};
use crate::rules::taint_loader::LoadedTaintRules;
use crate::rules::taint_model::TaintRuleSet;

/// 嵌入的规则目录（仓库根 `rules/`）
static EMBEDDED_RULES: Dir = include_dir!("$CARGO_MANIFEST_DIR/../rules");

/// 递归收集目录下所有 YAML 文件的 (相对路径, 内容)
fn collect_yaml_files(dir: &'static Dir<'static>, out: &mut Vec<(String, String)>) {
    for entry in dir.entries() {
        match entry {
            DirEntry::File(file) => {
                let path = file.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    if let Some(content) = file.contents_utf8() {
                        out.push((path.to_string_lossy().replace('\\', "/"), content.to_string()));
                    }
                }
            }
            DirEntry::Dir(subdir) => collect_yaml_files(subdir, out),
        }
    }
}

/// 嵌入的模式规则 YAML（顶层 + 子目录，语义同 `load_rules_from_dir("rules")`）
fn embedded_pattern_yaml_files() -> Vec<(String, String)> {
    let mut files = Vec::new();
    collect_yaml_files(&EMBEDDED_RULES, &mut files);
    files
}

/// 嵌入的污点规则 YAML（仅 `taint/` 子目录）
fn embedded_taint_yaml_files() -> Vec<(String, String)> {
    let mut files = Vec::new();
    if let Some(taint_dir) = EMBEDDED_RULES.get_dir("taint") {
        collect_yaml_files(taint_dir, &mut files);
    }
    files
}

/// 加载嵌入的模式规则（与 `loader::load_rules_from_dir` 相同的解析与跳过语义）
pub fn load_embedded_pattern_rules() -> Vec<Rule> {
    let mut rules = Vec::new();
    for (path, content) in embedded_pattern_yaml_files() {
        if let Ok(rule_set) = serde_yaml::from_str::<RuleSet>(&content) {
            rules.extend(rule_set.rules);
        } else if let Ok(rule) = serde_yaml::from_str::<Rule>(&content) {
            rules.push(rule);
        } else {
            tracing::debug!("Skipping non-pattern-rule embedded file: {}", path);
        }
    }
    rules
}

/// 加载嵌入的污点规则（与 `taint_loader::load_taint_rules_from_dir` 相同的聚合语义）
pub fn load_embedded_taint_rules() -> LoadedTaintRules {
    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    let mut sanitizer_patterns = Vec::new();

    for (path, content) in embedded_taint_yaml_files() {
        match serde_yaml::from_str::<TaintRuleSet>(&content) {
            Ok(rule_set) => {
                tracing::debug!(
                    "Loaded embedded taint rules: {} ({} sources, {} sinks, {} sanitizers)",
                    rule_set.name,
                    rule_set.sources.len(),
                    rule_set.sinks.len(),
                    rule_set.sanitizers.len(),
                );
                sources.extend(rule_set.sources);
                sinks.extend(rule_set.sinks);
                for san in rule_set.sanitizers {
                    sanitizer_patterns.push(san.pattern);
                }
            }
            Err(e) => {
                tracing::debug!("Skipped non-taint embedded YAML {}: {}", path, e);
            }
        }
    }

    LoadedTaintRules {
        sources,
        sinks,
        sanitizer_patterns,
    }
}

/// 嵌入污点规则 YAML 的原始内容（供 CLI/MCP 侧在文件系统目录缺失时兜底解析）
pub fn embedded_taint_yaml_contents() -> Vec<String> {
    embedded_taint_yaml_files()
        .into_iter()
        .map(|(_, content)| content)
        .collect()
}

/// 嵌入的审计证据包（仅 `audit-packs/` 子目录）
///
/// audit-packs 的 YAML 不是模式规则/污点规则格式，
/// 会被 `load_embedded_pattern_rules` 的 RuleSet/Rule 解析自然跳过，无副作用。
pub fn load_embedded_audit_packs() -> Vec<AuditPack> {
    let mut packs = Vec::new();
    if let Some(dir) = EMBEDDED_RULES.get_dir("audit-packs") {
        let mut files = Vec::new();
        collect_yaml_files(dir, &mut files);
        for (path, content) in files {
            match serde_yaml::from_str::<AuditPack>(&content) {
                Ok(pack) => packs.push(pack),
                Err(e) => {
                    tracing::debug!("Skipped non-audit-pack embedded YAML {}: {}", path, e);
                }
            }
        }
    }
    packs.sort_by(|a, b| a.id.cmp(&b.id));
    packs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_pattern_rules_loaded() {
        let rules = load_embedded_pattern_rules();
        assert!(
            rules.len() >= 30,
            "嵌入的模式规则数量异常: {}",
            rules.len()
        );
    }

    #[test]
    fn test_embedded_taint_rules_loaded() {
        let loaded = load_embedded_taint_rules();
        assert!(!loaded.sources.is_empty(), "嵌入污点规则应包含 sources");
        assert!(!loaded.sinks.is_empty(), "嵌入污点规则应包含 sinks");
        assert!(
            !loaded.sanitizer_patterns.is_empty(),
            "嵌入污点规则应包含 sanitizers"
        );
        // 框架规则包（frameworks/ 子目录）也应被递归收集
        let sink_ids: Vec<&str> = loaded.sinks.iter().map(|s| s.id.as_str()).collect();
        assert!(
            sink_ids.iter().any(|id| id.starts_with("java_")),
            "应包含 Java 框架 sink: {:?}",
            &sink_ids[..sink_ids.len().min(10)]
        );
    }

    #[test]
    fn test_embedded_audit_packs_loaded() {
        let packs = load_embedded_audit_packs();
        assert!(packs.len() >= 8, "嵌入的证据包数量异常: {}", packs.len());
        assert!(
            packs.iter().any(|p| p.id == "generic"),
            "应包含 generic 兜底包"
        );
        for pack in &packs {
            assert!(
                !pack.evidence_steps.is_empty(),
                "嵌入包 {} 缺少 evidence_steps",
                pack.id
            );
        }
    }

    #[test]
    fn test_audit_packs_not_parsed_as_pattern_rules() {
        // audit-packs 的 YAML 不应被误解析为模式规则（缺 severity/language 等必填字段）
        let yaml = r#"
kind: audit-pack
id: "test-pack"
name: "Test Pack"
vuln_types: ["xss"]
cwe: ["CWE-79"]
evidence_steps:
  - tool: get_code_context
    purpose: "test"
"#;
        assert!(serde_yaml::from_str::<RuleSet>(yaml).is_err());
        assert!(serde_yaml::from_str::<Rule>(yaml).is_err());
    }

    #[test]
    fn test_embedded_xxe_rules_hardening_fields() {
        // CVE-2021-23901 回放反哺（R85）：xxe 两条规则必须携带 setFeature 加固
        // sanitizers 与有界窗口字段——YAML 新增字段静默解析失败会直接导致
        // 修复版豁免腿失效（R21 教训：加字段必查反序列化兼容）。
        let rules = load_embedded_pattern_rules();
        let xxe_detection = rules
            .iter()
            .find(|r| r.id == "xxe-detection")
            .expect("应嵌入 xxe-detection 规则");
        assert!(
            xxe_detection.sanitizers.iter().any(|s| s.contains("disallow-doctype-decl")),
            "xxe-detection 应识别 disallow-doctype-decl 加固"
        );
        assert!(
            xxe_detection.sanitizer_after_lines >= 4,
            "xxe-detection 应有后向加固窗口（工厂创建后紧跟 setFeature 形态）"
        );
        assert!(
            !xxe_detection
                .pattern
                .as_deref()
                .unwrap_or("")
                .contains("javax\\.xml\\.parsers\\.SAXParser|"),
            "xxe-detection 不应再以无词边界的 FQN 匹配 import 行"
        );
        let xxe_injection = rules
            .iter()
            .find(|r| r.id == "xxe-injection")
            .expect("应嵌入 xxe-injection 规则");
        assert!(
            xxe_injection.sanitizers.iter().any(|s| s.contains("disallow-doctype-decl")),
            "xxe-injection 应识别 disallow-doctype-decl 加固"
        );
        assert!(
            xxe_injection.sanitizer_before_lines >= 4,
            "xxe-injection 应有前向加固窗口（解析前配置工厂形态）"
        );
    }
}
