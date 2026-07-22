// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 审计证据包（Audit Pack）schema 与加载器
//!
//! 证据包把"按 CWE 分类的取证方法论"固化为 YAML 数据：
//! 每类漏洞对应一组取证步骤（用哪个 MCP 工具、回答什么问题）、
//! TP/FP 判据与置信度校准指南，供 MCP 工具（audit_plan /
//! start_investigation）向外部 LLM 下发结构化的判定流程。
//!
//! 加载优先级：文件系统 `rules/audit-packs/`（相对 CWD）→ 内置嵌入内容。

use serde::{Deserialize, Serialize};
use std::path::Path;
use walkdir::WalkDir;

/// 审计证据包 —— 一类漏洞的完整取证与判定指南
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPack {
    /// 包标识（如 "cwe-79-xss"）
    pub id: String,
    /// 包名称
    pub name: String,
    /// 包类型标记，固定为 "audit-pack"，便于识别
    #[serde(default)]
    pub kind: Option<String>,
    /// 匹配的漏洞类型别名（finding 的 vuln_type，大小写/分隔符不敏感）
    #[serde(default)]
    pub vuln_types: Vec<String>,
    /// 匹配的 CWE 编号（如 "CWE-79"）
    #[serde(default)]
    pub cwe: Vec<String>,
    /// 取证步骤：按顺序执行，每步回答一个关键问题
    #[serde(default)]
    pub evidence_steps: Vec<EvidenceStep>,
    /// 判定为真实漏洞（TP）的判据
    #[serde(default)]
    pub tp_criteria: Vec<String>,
    /// 判定为误报（FP）的判据
    #[serde(default)]
    pub fp_criteria: Vec<String>,
    /// 置信度校准指南
    #[serde(default)]
    pub confidence_guide: String,
}

/// 单个取证步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceStep {
    /// 建议使用的 MCP 工具名（如 query_callers、search_code）
    pub tool: String,
    /// 这一步要回答的问题
    pub purpose: String,
}

/// 从目录递归加载所有证据包 YAML
///
/// 目录不存在或文件无法解析为 AuditPack 时跳过（不报错），
/// 与普通规则/污点规则的容错语义一致。结果按 id 排序保证确定性。
pub fn load_audit_packs_from_dir<P: AsRef<Path>>(path: P) -> Vec<AuditPack> {
    let mut packs = Vec::new();

    let path = path.as_ref();
    if !path.exists() {
        return packs;
    }

    for entry in WalkDir::new(path) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let file_path = entry.path();
        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        let content = match std::fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match serde_yaml::from_str::<AuditPack>(&content) {
            Ok(pack) => {
                tracing::debug!(
                    "Loaded audit pack: {} ({} steps)",
                    pack.id,
                    pack.evidence_steps.len()
                );
                packs.push(pack);
            }
            Err(e) => {
                // 非 audit-pack 格式的 YAML（如普通规则），跳过不报错
                tracing::debug!("Skipped non-audit-pack YAML {:?}: {}", file_path, e);
            }
        }
    }

    packs.sort_by(|a, b| a.id.cmp(&b.id));
    packs
}

/// 加载证据包：优先文件系统 `rules/audit-packs/`（相对 CWD），
/// 读不到或为空时回退到内置嵌入内容
pub fn load_audit_packs() -> Vec<AuditPack> {
    let from_dir = load_audit_packs_from_dir("rules/audit-packs");
    if !from_dir.is_empty() {
        return from_dir;
    }
    let embedded = crate::rules::embedded::load_embedded_audit_packs();
    if !embedded.is_empty() {
        tracing::info!(
            "证据包目录 rules/audit-packs 不可用，使用内置嵌入证据包 ({} packs)",
            embedded.len()
        );
    }
    embedded
}

/// 规范化标识符：小写并去除所有非字母数字字符，
/// 使 "CWE-79"/"cwe_79"、 "CrossSiteScripting"/"xss-detection" 等写法可比较
fn normalize_id(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// 规范化 CWE 编号：提取数字部分，使 "CWE-79"、"79"、"cwe-79" 等价
fn normalize_cwe(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// 按漏洞类型 / CWE 匹配证据包
///
/// 匹配规则（任一命中即返回）：
/// - `cwe` 与 pack 的 cwe 列表数字部分相等；
/// - `vuln_type` 规范化后与 pack 的 vuln_types 任一条目相等或互相包含。
///
/// id 为 "generic" 的兜底包不参与匹配（由 `generic_pack` 显式获取）。
/// 多个命中时返回切片中第一个（`load_audit_packs_from_dir` 已按 id 排序）。
pub fn find_pack<'a>(
    packs: &'a [AuditPack],
    vuln_type: &str,
    cwe: Option<&str>,
) -> Option<&'a AuditPack> {
    let vt_norm = normalize_id(vuln_type);
    let cwe_norm = cwe.map(normalize_cwe).unwrap_or_default();
    // vuln_type 本身可能就是 CWE 编号（如 RegexRule 的 vuln_type="CWE-79"），
    // 此时应与 pack 的 cwe 列表做数字等价匹配
    let vt_cwe_norm = normalize_cwe(vuln_type);

    packs
        .iter()
        .filter(|p| p.id != "generic")
        .find(|p| {
            let pack_cwe_hit = |want: &str| {
                !want.is_empty()
                    && p.cwe
                        .iter()
                        .any(|c| !normalize_cwe(c).is_empty() && normalize_cwe(c) == want)
            };
            if pack_cwe_hit(&cwe_norm) || pack_cwe_hit(&vt_cwe_norm) {
                return true;
            }
            !vt_norm.is_empty()
                && p.vuln_types.iter().any(|t| {
                    let t_norm = normalize_id(t);
                    !t_norm.is_empty()
                        && (t_norm == vt_norm
                            || vt_norm.contains(&t_norm)
                            || t_norm.contains(&vt_norm))
                })
        })
}

/// 获取兜底证据包（id == "generic"）
pub fn generic_pack(packs: &[AuditPack]) -> Option<&AuditPack> {
    packs.iter().find(|p| p.id == "generic")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小证据包用于测试
    fn sample_pack(id: &str, vuln_types: &[&str], cwe: &[&str]) -> AuditPack {
        AuditPack {
            id: id.to_string(),
            name: format!("{} pack", id),
            kind: Some("audit-pack".to_string()),
            vuln_types: vuln_types.iter().map(|s| s.to_string()).collect(),
            cwe: cwe.iter().map(|s| s.to_string()).collect(),
            evidence_steps: vec![EvidenceStep {
                tool: "get_code_context".to_string(),
                purpose: "查看上下文".to_string(),
            }],
            tp_criteria: vec!["tp".to_string()],
            fp_criteria: vec!["fp".to_string()],
            confidence_guide: "guide".to_string(),
        }
    }

    #[test]
    fn test_deserialize_audit_pack() {
        let yaml = r#"
kind: audit-pack
id: "cwe-79-xss"
name: "XSS 取证包"
vuln_types: ["xss", "CrossSiteScripting"]
cwe: ["CWE-79"]
evidence_steps:
  - tool: get_code_context
    purpose: "确认 sink 赋值内容来源"
tp_criteria:
  - "外部可控 + 无转义"
fp_criteria:
  - "字面量 HTML"
confidence_guide: "多证据交叉 0.9+"
"#;
        let pack: AuditPack = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(pack.id, "cwe-79-xss");
        assert_eq!(pack.kind.as_deref(), Some("audit-pack"));
        assert_eq!(pack.evidence_steps.len(), 1);
        assert_eq!(pack.evidence_steps[0].tool, "get_code_context");
        assert_eq!(pack.tp_criteria.len(), 1);
    }

    #[test]
    fn test_find_pack_by_vuln_type_as_cwe() {
        // RegexRule 的 vuln_type 就是 CWE 编号（如 "CWE-79"），
        // 应能与 pack 的 cwe 列表做数字等价匹配
        let packs = vec![
            sample_pack("cwe-79-xss", &["xss"], &["CWE-79"]),
            sample_pack("cwe-89-sqli", &["sql injection"], &["CWE-89"]),
            sample_pack("generic", &[], &[]),
        ];
        let found = find_pack(&packs, "CWE-79", None).expect("CWE-79 应命中 xss pack");
        assert_eq!(found.id, "cwe-79-xss");
        let found = find_pack(&packs, "CWE-89", None).expect("CWE-89 应命中 sqli pack");
        assert_eq!(found.id, "cwe-89-sqli");
        // 无对应 pack 的 CWE 编号返回 None（由调用方回退 generic）
        assert!(find_pack(&packs, "CWE-120", None).is_none());
    }

    #[test]
    fn test_find_pack_by_cwe() {        let packs = vec![
            sample_pack("cwe-79-xss", &["xss"], &["CWE-79"]),
            sample_pack("generic", &[], &[]),
        ];
        let found = find_pack(&packs, "anything", Some("CWE-79")).unwrap();
        assert_eq!(found.id, "cwe-79-xss");
        // 纯数字写法也等价
        let found = find_pack(&packs, "anything", Some("79")).unwrap();
        assert_eq!(found.id, "cwe-79-xss");
    }

    #[test]
    fn test_find_pack_by_vuln_type_aliases() {
        let packs = vec![
            sample_pack("cwe-79-xss", &["xss", "CrossSiteScripting"], &["CWE-79"]),
            sample_pack("generic", &[], &[]),
        ];
        // 污点引擎的 Debug 格式 vuln_type
        let found = find_pack(&packs, "CrossSiteScripting", None).unwrap();
        assert_eq!(found.id, "cwe-79-xss");
        // 规则 id 形式
        let found = find_pack(&packs, "xss-detection", None).unwrap();
        assert_eq!(found.id, "cwe-79-xss");
    }

    #[test]
    fn test_find_pack_skips_generic_and_misses() {
        let packs = vec![
            sample_pack("cwe-79-xss", &["xss"], &["CWE-79"]),
            sample_pack("generic", &["xss"], &["CWE-79"]),
        ];
        // generic 不参与匹配
        let found = find_pack(&packs, "xss", None).unwrap();
        assert_eq!(found.id, "cwe-79-xss");
        // 匹配不到时返回 None，由调用方回退 generic
        assert!(find_pack(&packs, "path-traversal", None).is_none());
        assert_eq!(generic_pack(&packs).unwrap().id, "generic");
    }

    #[test]
    fn test_nonexistent_dir_returns_empty() {
        let packs = load_audit_packs_from_dir("/nonexistent/path/that/does/not/exist");
        assert!(packs.is_empty());
    }

    #[test]
    fn test_load_real_audit_packs() {
        // 加载仓库内置证据包（相对仓库根）
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let packs_dir = std::path::Path::new(&manifest_dir)
            .parent()
            .unwrap()
            .join("rules")
            .join("audit-packs");

        if !packs_dir.exists() {
            eprintln!("Skipping audit packs test: {:?} not found", packs_dir);
            return;
        }

        let packs = load_audit_packs_from_dir(&packs_dir);
        assert!(packs.len() >= 8, "内置证据包数量异常: {}", packs.len());

        // 每个 pack 都应有取证步骤与判据
        for pack in &packs {
            assert!(
                !pack.evidence_steps.is_empty(),
                "pack {} 缺少 evidence_steps",
                pack.id
            );
            assert!(
                !pack.tp_criteria.is_empty() && !pack.fp_criteria.is_empty(),
                "pack {} 缺少 TP/FP 判据",
                pack.id
            );
            assert!(
                !pack.confidence_guide.is_empty(),
                "pack {} 缺少 confidence_guide",
                pack.id
            );
            assert!(
                pack.evidence_steps.len() >= 3 && pack.evidence_steps.len() <= 6,
                "pack {} 的 evidence_steps 应为 3-6 步，实际 {}",
                pack.id,
                pack.evidence_steps.len()
            );
        }

        // 必备的核心包
        assert!(packs.iter().any(|p| p.id == "cwe-79-xss"));
        assert!(packs.iter().any(|p| p.id == "cwe-89-sqli"));
        assert!(packs.iter().any(|p| p.id == "generic"));

        // 匹配实战：污点引擎 vuln_type → 正确 pack
        let found = find_pack(&packs, "SqlInjection", None).unwrap();
        assert_eq!(found.id, "cwe-89-sqli");
        let found = find_pack(&packs, "command-injection", None).unwrap();
        assert_eq!(found.id, "cwe-78-cmdi");
        // 未知类型回退 generic
        assert!(find_pack(&packs, "some-unknown-type", None).is_none());
        assert!(generic_pack(&packs).is_some());
    }
}
