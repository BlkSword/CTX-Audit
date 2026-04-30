// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 智能 Token 管理
//!
//! 从代码中提取最小上下文，控制 LLM 输入 token 消耗。
//! 策略：污点切片 > 函数级上下文 > 文件摘要 > 跳过。

use std::collections::HashSet;

/// Token 预算配置
#[derive(Debug, Clone)]
pub struct TokenBudget {
    /// 验证阶段每个候选的最大上下文 token（约 4 字符/token）
    pub max_context_chars_per_candidate: usize,
    /// 深度分析阶段每个文件的最大上下文
    pub max_context_chars_per_file: usize,
    /// 摘要的最大长度
    pub max_summary_chars: usize,
}

impl Default for TokenBudget {
    fn default() -> Self {
        Self {
            // ~3K tokens per candidate (12K chars ≈ 3K tokens)
            max_context_chars_per_candidate: 12_000,
            // ~6K tokens per file (24K chars)
            max_context_chars_per_file: 24_000,
            // ~500 tokens for summaries
            max_summary_chars: 2_000,
        }
    }
}

/// 从源代码中提取围绕目标行的最小上下文窗口
///
/// 返回以 `center_line` 为中心、向上下扩展到函数边界或 `max_lines` 的代码片段。
pub fn extract_context_slice(
    code: &str,
    center_line: usize,
    max_lines: usize,
) -> String {
    let lines: Vec<&str> = code.lines().collect();
    if lines.is_empty() || center_line == 0 {
        return String::new();
    }

    let target = center_line.saturating_sub(1); // 0-indexed
    let half = max_lines / 2;

    // 查找函数边界（简化：用大括号计数）
    let mut start = target.saturating_sub(half);
    let mut end = (target + half).min(lines.len());

    // 向上扩展到最近的函数开头
    for i in (0..target).rev() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with("fn ")
            || trimmed.starts_with("def ")
            || trimmed.starts_with("function ")
            || trimmed.starts_with("public ")
            || trimmed.starts_with("private ")
            || trimmed.starts_with("protected ")
            || trimmed.starts_with("static ")
            || trimmed.starts_with("async ")
            || trimmed.starts_with("@GetMapping")
            || trimmed.starts_with("@PostMapping")
            || trimmed.starts_with("@RequestMapping")
            || trimmed.starts_with("app.get(")
            || trimmed.starts_with("app.post(")
            || trimmed.starts_with("router.get(")
            || trimmed.starts_with("router.post(")
        {
            start = i;
            break;
        }
        if i <= target.saturating_sub(half * 3) {
            break;
        }
    }

    lines[start..end].join("\n")
}

/// 从污点传播路径中提取相关代码行
///
/// 收集路径中每个步骤的行号及其上下文，合并重叠区域。
pub fn extract_taint_slice(
    code: &str,
    taint_lines: &[usize],
    context_radius: usize,
) -> String {
    if taint_lines.is_empty() {
        return String::new();
    }

    let lines: Vec<&str> = code.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    // 收集所有需要的行号
    let mut needed: HashSet<usize> = HashSet::new();
    for &line in taint_lines {
        let center = line.saturating_sub(1);
        for i in center.saturating_sub(context_radius)..=center + context_radius {
            if i < lines.len() {
                needed.insert(i);
            }
        }
    }

    // 按行号排序，合并连续区间
    let mut sorted: Vec<usize> = needed.into_iter().collect();
    sorted.sort();

    let mut result = String::new();
    let mut prev: Option<usize> = None;

    for line_idx in sorted {
        match prev {
            Some(p) if line_idx == p + 1 => {
                result.push_str(lines[line_idx]);
                result.push('\n');
            }
            Some(_) => {
                result.push_str("  ...\n");
                result.push_str(lines[line_idx]);
                result.push('\n');
            }
            None => {
                result.push_str(lines[line_idx]);
                result.push('\n');
            }
        }
        prev = Some(line_idx);
    }

    result
}

/// 为文件生成简短摘要（用于跨文件上下文）
///
/// 提取 import/require 语句、函数签名、类声明等骨架信息。
pub fn generate_file_skeleton(code: &str, max_chars: usize) -> String {
    let mut skeleton = String::new();

    for line in code.lines() {
        let trimmed = line.trim();

        // 保留 import/require/use 语句
        if trimmed.starts_with("import ")
            || trimmed.starts_with("from ")
            || trimmed.starts_with("require(")
            || trimmed.starts_with("use ")
            || trimmed.starts_with("#include")
        {
            skeleton.push_str(trimmed);
            skeleton.push('\n');
            continue;
        }

        // 保留函数/方法签名
        if trimmed.starts_with("fn ")
            || trimmed.starts_with("def ")
            || trimmed.starts_with("function ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("public ")
            || trimmed.starts_with("private ")
            || trimmed.starts_with("class ")
            || trimmed.starts_with("struct ")
            || trimmed.starts_with("interface ")
            || trimmed.starts_with("impl ")
            || trimmed.starts_with("@")
        {
            // 只取第一行（签名行）
            skeleton.push_str(trimmed);
            skeleton.push('\n');
            continue;
        }

        if skeleton.len() >= max_chars {
            skeleton.push_str("... (truncated)\n");
            break;
        }
    }

    skeleton
}

/// 根据置信度和优先级排序候选漏洞，截断到 token 预算
///
/// 高置信度 + 有 taint 证据的候选优先，低置信度的只发送摘要。
pub fn prioritize_candidates<C>(
    candidates: &[C],
    budget: &TokenBudget,
    get_confidence: impl Fn(&C) -> f32,
    has_taint_evidence: impl Fn(&C) -> bool,
) -> Vec<PrioritizedCandidate> {
    let mut indexed: Vec<(usize, f32, bool)> = candidates
        .iter()
        .enumerate()
        .map(|(i, c)| (i, get_confidence(c), has_taint_evidence(c)))
        .collect();

    // 排序：有 taint 证据 > 高置信度
    indexed.sort_by(|a, b| {
        b.2.cmp(&a.2) // taint evidence first
            .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
    });

    let mut results = Vec::new();
    let mut chars_used = 0usize;

    for (original_idx, confidence, has_taint) in indexed {
        let remaining = budget.max_context_chars_per_candidate.saturating_sub(chars_used);
        let detail_level = if !has_taint && confidence < 0.5 {
            DetailLevel::SummaryOnly
        } else if remaining < budget.max_summary_chars {
            DetailLevel::SummaryOnly
        } else if confidence >= 0.7 || has_taint {
            DetailLevel::FullContext
        } else {
            DetailLevel::Standard
        };

        chars_used += match detail_level {
            DetailLevel::FullContext => budget.max_context_chars_per_candidate,
            DetailLevel::Standard => budget.max_context_chars_per_candidate / 2,
            DetailLevel::SummaryOnly => budget.max_summary_chars,
        };

        results.push(PrioritizedCandidate {
            original_idx,
            confidence,
            has_taint_evidence: has_taint,
            detail_level,
        });
    }

    results
}

/// 优先级排序结果
#[derive(Debug, Clone)]
pub struct PrioritizedCandidate {
    pub original_idx: usize,
    pub confidence: f32,
    pub has_taint_evidence: bool,
    pub detail_level: DetailLevel,
}

/// 上下文详细程度
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailLevel {
    /// 完整上下文（高优先级候选）
    FullContext,
    /// 标准上下文
    Standard,
    /// 仅摘要（低优先级）
    SummaryOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_context_slice() {
        let code = "line1\nline2\nfn foo() {\n  vuln_line\n}\nline6";
        let result = extract_context_slice(code, 4, 10);
        assert!(result.contains("fn foo()"));
        assert!(result.contains("vuln_line"));
    }

    #[test]
    fn test_extract_taint_slice() {
        let code = "line1\nline2\nline3\nsource\nline5\nsink\nline7";
        let result = extract_taint_slice(code, &[4, 6], 1);
        assert!(result.contains("source"));
        assert!(result.contains("sink"));
    }

    #[test]
    fn test_generate_file_skeleton() {
        let code = "import os\nimport sys\n\ndef foo():\n    x = 1\n\ndef bar(a, b):\n    return a + b";
        let skeleton = generate_file_skeleton(code, 1000);
        assert!(skeleton.contains("import os"));
        assert!(skeleton.contains("def foo():"));
        assert!(skeleton.contains("def bar(a, b):"));
        assert!(!skeleton.contains("x = 1"));
    }
}
