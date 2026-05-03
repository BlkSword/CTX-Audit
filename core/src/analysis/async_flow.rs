// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 异步流追踪 — Promise 链和回调参数污点提示
//!
//! 检测 .then(param => ...)、.catch(param => ...)、await 等异步模式，
//! 为回调参数提供污点提示，使函数级分析能正确传播异步数据流中的污点。

use serde::{Deserialize, Serialize};

/// 回调参数的污点提示
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackTaintHint {
    /// 回调参数名
    pub param_name: String,
    /// 回调在源代码中的起始行（1-based）
    pub callback_start_line: usize,
    /// 提示来源类型
    pub hint_type: CallbackHintType,
}

/// 回调提示类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallbackHintType {
    /// .then() 回调 — 参数是 Promise 的 resolve 值
    PromiseThen,
    /// .catch() 回调 — 参数是 rejection reason
    PromiseCatch,
    /// .forEach()/.map()/.filter() 回调 — 参数是数组元素
    ArrayCallback,
}

/// 检测源代码中的 Promise 链和回调模式，返回污点提示
pub fn detect_callback_hints(code: &str) -> Vec<CallbackTaintHint> {
    let mut hints = Vec::new();

    for (line_idx, line) in code.lines().enumerate() {
        let line_num = line_idx + 1;
        let trimmed = line.trim();

        // .then(param => ...)
        if let Some(hint) = extract_callback_hint(trimmed, ".then(", line_num, CallbackHintType::PromiseThen) {
            hints.push(hint);
        }

        // .catch(param => ...)
        if let Some(hint) = extract_callback_hint(trimmed, ".catch(", line_num, CallbackHintType::PromiseCatch) {
            hints.push(hint);
        }

        // .forEach(param => ...) 和 .map(param => ...)
        if let Some(hint) = extract_callback_hint(trimmed, ".forEach(", line_num, CallbackHintType::ArrayCallback) {
            hints.push(hint);
        }
        if let Some(hint) = extract_callback_hint(trimmed, ".map(", line_num, CallbackHintType::ArrayCallback) {
            hints.push(hint);
        }
        if let Some(hint) = extract_callback_hint(trimmed, ".filter(", line_num, CallbackHintType::ArrayCallback) {
            hints.push(hint);
        }
    }

    hints
}

/// 从一行代码中提取回调参数提示
fn extract_callback_hint(line: &str, method: &str, line_num: usize, hint_type: CallbackHintType) -> Option<CallbackTaintHint> {
    let pos = line.find(method)?;
    let rest = &line[pos + method.len()..];

    // 模式 1: arrow function — .then(param => ...) 或 .then((param) => ...)
    if let Some(param) = extract_arrow_param(rest) {
        return Some(CallbackTaintHint {
            param_name: param,
            callback_start_line: line_num,
            hint_type,
        });
    }

    // 模式 2: function expression — .then(function(param) { ... })
    if let Some(param) = extract_function_expr_param(rest) {
        return Some(CallbackTaintHint {
            param_name: param,
            callback_start_line: line_num,
            hint_type,
        });
    }

    None
}

/// 提取箭头函数参数: "param => ..." 或 "(param) => ..." 或 "(a, b) => ..."
fn extract_arrow_param(rest: &str) -> Option<String> {
    let rest = rest.trim();

    // (param) => ...
    if rest.starts_with('(') {
        if let Some(end) = rest.find(')') {
            let inner = rest[1..end].trim();
            // 只取第一个参数（多参数场景中第一个通常是数据）
            let first = inner.split(',').next().unwrap_or(inner).trim();
            if is_valid_param_name(first) {
                return Some(first.to_string());
            }
        }
    }

    // param => ...
    if let Some(arrow_pos) = rest.find("=>") {
        let param = rest[..arrow_pos].trim();
        if is_valid_param_name(param) {
            return Some(param.to_string());
        }
    }

    None
}

/// 提取 function 表达式参数: "function(param) { ... }"
fn extract_function_expr_param(rest: &str) -> Option<String> {
    let rest = rest.trim();
    if !rest.starts_with("function") {
        return None;
    }

    if let Some(start) = rest.find('(') {
        if let Some(end) = rest.find(')') {
            let inner = rest[start + 1..end].trim();
            let first = inner.split(',').next().unwrap_or(inner).trim();
            if is_valid_param_name(first) {
                return Some(first.to_string());
            }
        }
    }

    None
}

fn is_valid_param_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_then_arrow() {
        let code = "fetch(url).then(data => eval(data))";
        let hints = detect_callback_hints(code);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].param_name, "data");
        assert_eq!(hints[0].hint_type, CallbackHintType::PromiseThen);
    }

    #[test]
    fn test_detect_then_paren_arrow() {
        let code = ".then((res) => res.json())";
        let hints = detect_callback_hints(code);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].param_name, "res");
    }

    #[test]
    fn test_detect_catch_arrow() {
        let code = ".catch(err => console.log(err))";
        let hints = detect_callback_hints(code);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].param_name, "err");
        assert_eq!(hints[0].hint_type, CallbackHintType::PromiseCatch);
    }

    #[test]
    fn test_detect_foreach_callback() {
        let code = "items.forEach(item => process(item))";
        let hints = detect_callback_hints(code);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].param_name, "item");
        assert_eq!(hints[0].hint_type, CallbackHintType::ArrayCallback);
    }

    #[test]
    fn test_detect_function_expr() {
        let code = ".then(function(data) { return data; })";
        let hints = detect_callback_hints(code);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].param_name, "data");
    }

    #[test]
    fn test_detect_multi_param_arrow() {
        let code = ".then((res, rej) => res.json())";
        let hints = detect_callback_hints(code);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].param_name, "res"); // 第一个参数
    }

    #[test]
    fn test_no_hint_for_no_callback() {
        let code = "const x = 1\nconst y = x + 2";
        let hints = detect_callback_hints(code);
        assert!(hints.is_empty());
    }

    #[test]
    fn test_detect_chain_multiline() {
        let code = r#"
fetch(url)
  .then(res => res.json())
  .then(data => eval(data))
  .catch(err => log(err))
"#;
        let hints = detect_callback_hints(code);
        assert_eq!(hints.len(), 3);
        assert_eq!(hints[0].param_name, "res");
        assert_eq!(hints[1].param_name, "data");
        assert_eq!(hints[2].param_name, "err");
    }
}
