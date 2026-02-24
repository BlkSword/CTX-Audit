// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 辅助函数 - 处理 FindingData 兼容性

use ctx_audit_tools::FindingData;

/// 从 FindingData 中提取置信度
pub fn get_confidence(finding: &FindingData) -> f32 {
    finding
        .extra
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.7) as f32
}

/// 设置 FindingData 的置信度
pub fn set_confidence(finding: &mut FindingData, confidence: f32) {
    finding
        .extra
        .insert("confidence".to_string(), serde_json::json!(confidence));
}

/// 获取 FindingData 的行号
pub fn get_line_number(finding: &FindingData) -> usize {
    finding.start_line as usize
}

/// 获取 FindingData 的严重程度（转换为枚举）
pub fn get_severity_enum(finding: &FindingData) -> FindingSeverity {
    match finding.severity.to_lowercase().as_str() {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        "low" => FindingSeverity::Low,
        "info" => FindingSeverity::Info,
        _ => FindingSeverity::Medium,
    }
}

/// 获取 FindingData 的类别（转换为枚举）
pub fn get_category_enum(finding: &FindingData) -> FindingCategory {
    match finding.category.to_lowercase().as_str() {
        "injection" | "sql_injection" => FindingCategory::Injection,
        "xss" => FindingCategory::Xss,
        "auth" | "authorization" => FindingCategory::Auth,
        "crypto" => FindingCategory::Crypto,
        "config" => FindingCategory::Config,
        _ => FindingCategory::Other,
    }
}

/// 严重程度枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// 类别枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    Injection,
    Xss,
    Auth,
    Crypto,
    Config,
    Other,
}
