// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! CPG 构建器
//!
//! 从 tree-sitter AST 节点 + 解析器提取的元数据构建 FunctionCPG。
//! 复用现有 EnhancedFlowGraph::from_ast_node 构建 CFG，通过行号匹配附加元数据。

use std::collections::HashMap;

use crate::analysis::alias::{detect_all_aliases, AliasMap};
use crate::analysis::enhanced_dataflow::{EnhancedFlowGraph, EnhancedNodeType};
use crate::ast::symbol::{Assignment, CallInfo, FunctionBody, TypedParam};

use super::{CPGNodeMeta, ConditionInfo, FunctionCPG, FunctionSignature};

/// CPG 构建器
pub struct CPGBuilder;

/// 净化器函数名模式 — 用于检测条件中的净化检查
const SANITIZER_CALL_PATTERNS: &[&str] = &[
    "isSafe",
    "validate",
    "sanitize",
    "isValid",
    "check",
    "verify",
    "isAuthorized",
    "isAuthenticated",
    "isAllowed",
    "isPermitted",
    "checkPermission",
    "escape",
    "encode",
    "DOMPurify",
    "htmlspecialchars",
    "bleach",
];

impl CPGBuilder {
    /// 从 AST 节点 + 解析器元数据构建单函数 CPG
    ///
    /// - `func_body_node`: tree-sitter 函数体节点（block / statement_block 等）
    /// - `content`: 文件完整内容（供 CFG 构建使用）
    /// - `file_path`: 文件路径
    /// - `func`: 函数体信息
    /// - `assignments`: 该函数行范围内的赋值
    /// - `calls`: 该函数行范围内的调用
    pub fn build_function_cpg(
        func_body_node: &tree_sitter::Node,
        content: &str,
        file_path: &str,
        func: &FunctionBody,
        assignments: &[Assignment],
        calls: &[CallInfo],
    ) -> FunctionCPG {
        // 1. 构建 CFG（复用现有实现）
        let cfg = EnhancedFlowGraph::from_ast_node(func_body_node, content, file_path, &func.name);

        // 2. 按行号索引赋值和调用
        let assign_by_line: HashMap<usize, &Assignment> = assignments
            .iter()
            .filter(|a| a.line >= func.start_line && a.line <= func.end_line)
            .map(|a| (a.line, a))
            .collect();
        let call_by_line: HashMap<usize, &CallInfo> = calls
            .iter()
            .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
            .map(|c| (c.line, c))
            .collect();

        // 3. 为每个 CFG 节点附加元数据
        let mut node_meta = HashMap::new();
        for node in &cfg.nodes {
            let line = node.start_line;
            let ast_kind = node
                .code
                .split('(')
                .next()
                .unwrap_or(&node.code)
                .trim()
                .to_string();

            let assignment = assign_by_line.get(&line).map(|a| (*a).clone());
            let call_info = call_by_line.get(&line).map(|c| (*c).clone());

            // 4. 对 ConditionHeader 节点提取条件信息
            let condition = if node.node_type == EnhancedNodeType::ConditionHeader {
                Self::extract_condition_info(&node.code)
            } else {
                None
            };

            node_meta.insert(
                node.id,
                CPGNodeMeta {
                    ast_kind,
                    assignment,
                    call_info,
                    condition,
                },
            );
        }

        // 5. 构建别名映射（复用现有 detect_all_aliases）
        let alias_map = Self::build_alias_map(assignments);

        // 6. 构建函数签名
        let signature = FunctionSignature {
            name: func.name.clone(),
            file_path: file_path.to_string(),
            start_line: func.start_line,
            end_line: func.end_line,
            params: func.typed_params.clone(),
        };

        FunctionCPG {
            cfg,
            node_meta,
            alias_map,
            signature,
        }
    }

    /// 从函数体 AST 片段构建单函数 CPG（用于跨线程并行）
    ///
    /// 与 `build_function_cpg` 的区别：
    /// - `func_body_node` 是从函数体文本片段解析出来的局部 AST 节点，
    ///   其行号是相对于片段的；
    /// - `assignments`/`calls` 仍使用文件绝对行号，方法内部会转换为相对行号。
    pub fn build_function_cpg_from_fragment(
        func_body_node: &tree_sitter::Node,
        content: &str,
        file_path: &str,
        func: &FunctionBody,
        assignments: &[Assignment],
        calls: &[CallInfo],
    ) -> FunctionCPG {
        let cfg = EnhancedFlowGraph::from_ast_node(func_body_node, content, file_path, &func.name);

        // CFG 节点行号是相对于函数体文本的，需要把 assignments/calls 也转为相对行号
        let line_offset = func.start_line.saturating_sub(1);
        let relative_assignments: Vec<Assignment> = assignments
            .iter()
            .map(|a| {
                let mut a = a.clone();
                a.line = a.line.saturating_sub(line_offset);
                a.target_node.line = a.target_node.line.saturating_sub(line_offset);
                a
            })
            .collect();
        let relative_calls: Vec<CallInfo> = calls
            .iter()
            .map(|c| {
                let mut c = c.clone();
                c.line = c.line.saturating_sub(line_offset);
                c
            })
            .collect();

        let assign_by_line: HashMap<usize, &Assignment> =
            relative_assignments.iter().map(|a| (a.line, a)).collect();
        let call_by_line: HashMap<usize, &CallInfo> =
            relative_calls.iter().map(|c| (c.line, c)).collect();

        let mut node_meta = HashMap::new();
        for node in &cfg.nodes {
            let line = node.start_line;
            let ast_kind = node
                .code
                .split('(')
                .next()
                .unwrap_or(&node.code)
                .trim()
                .to_string();

            let assignment = assign_by_line.get(&line).map(|a| (*a).clone());
            let call_info = call_by_line.get(&line).map(|c| (*c).clone());
            let condition = if node.node_type == EnhancedNodeType::ConditionHeader {
                Self::extract_condition_info(&node.code)
            } else {
                None
            };

            node_meta.insert(
                node.id,
                CPGNodeMeta {
                    ast_kind,
                    assignment,
                    call_info,
                    condition,
                },
            );
        }

        let alias_map = Self::build_alias_map(&relative_assignments);

        let signature = FunctionSignature {
            name: func.name.clone(),
            file_path: file_path.to_string(),
            start_line: func.start_line,
            end_line: func.end_line,
            params: func.typed_params.clone(),
        };

        FunctionCPG {
            cfg,
            node_meta,
            alias_map,
            signature,
        }
    }

    /// 从函数体文本构建单函数 CPG（不依赖 tree-sitter Node，用于跨线程并行）
    ///
    /// 与 `build_function_cpg` 行为类似，但基于文本构建 CFG，signature 仍使用 func 元数据，
    /// 确保同一文件内不同函数仍拥有唯一的 signature id。
    pub fn build_function_cpg_from_text(
        content: &str,
        file_path: &str,
        func: &FunctionBody,
        assignments: &[Assignment],
        calls: &[CallInfo],
    ) -> FunctionCPG {
        let cfg = EnhancedFlowGraph::from_code(content, file_path, &func.name);

        // from_code 生成的 CFG 节点行号是相对于函数体文本的（从 1 开始），
        // 而传入的 assignments/calls 仍使用文件绝对行号。需要统一为相对行号，
        // 才能使 node_meta 正确附加 assignment/call_info。
        let line_offset = func.start_line.saturating_sub(1);
        let relative_assignments: Vec<Assignment> = assignments
            .iter()
            .map(|a| {
                let mut a = a.clone();
                a.line = a.line.saturating_sub(line_offset);
                a.target_node.line = a.target_node.line.saturating_sub(line_offset);
                a
            })
            .collect();
        let relative_calls: Vec<CallInfo> = calls
            .iter()
            .map(|c| {
                let mut c = c.clone();
                c.line = c.line.saturating_sub(line_offset);
                c
            })
            .collect();

        let assign_by_line: HashMap<usize, &Assignment> =
            relative_assignments.iter().map(|a| (a.line, a)).collect();
        let call_by_line: HashMap<usize, &CallInfo> =
            relative_calls.iter().map(|c| (c.line, c)).collect();

        let mut node_meta = HashMap::new();
        for node in &cfg.nodes {
            let line = node.start_line;
            let ast_kind = node
                .code
                .split('(')
                .next()
                .unwrap_or(&node.code)
                .trim()
                .to_string();

            let assignment = assign_by_line.get(&line).map(|a| (*a).clone());
            let call_info = call_by_line.get(&line).map(|c| (*c).clone());
            let condition = if node.node_type == EnhancedNodeType::ConditionHeader {
                Self::extract_condition_info(&node.code)
            } else {
                None
            };

            node_meta.insert(
                node.id,
                CPGNodeMeta {
                    ast_kind,
                    assignment,
                    call_info,
                    condition,
                },
            );
        }

        let alias_map = Self::build_alias_map(&relative_assignments);

        let signature = FunctionSignature {
            name: func.name.clone(),
            file_path: file_path.to_string(),
            start_line: func.start_line,
            end_line: func.end_line,
            params: func.typed_params.clone(),
        };

        FunctionCPG {
            cfg,
            node_meta,
            alias_map,
            signature,
        }
    }

    /// 从整个文件的 AST 构建单函数 CPG（无函数体节点时使用 text-based CFG）
    pub fn build_file_cpg(
        content: &str,
        file_path: &str,
        assignments: &[Assignment],
        calls: &[CallInfo],
    ) -> FunctionCPG {
        let cfg = EnhancedFlowGraph::from_code(content, file_path, "");

        let assign_by_line: HashMap<usize, &Assignment> =
            assignments.iter().map(|a| (a.line, a)).collect();
        let call_by_line: HashMap<usize, &CallInfo> = calls.iter().map(|c| (c.line, c)).collect();

        let mut node_meta = HashMap::new();
        for node in &cfg.nodes {
            let line = node.start_line;
            let ast_kind = node
                .code
                .split('(')
                .next()
                .unwrap_or(&node.code)
                .trim()
                .to_string();

            let assignment = assign_by_line.get(&line).map(|a| (*a).clone());
            let call_info = call_by_line.get(&line).map(|c| (*c).clone());
            let condition = if node.node_type == EnhancedNodeType::ConditionHeader {
                Self::extract_condition_info(&node.code)
            } else {
                None
            };

            node_meta.insert(
                node.id,
                CPGNodeMeta {
                    ast_kind,
                    assignment,
                    call_info,
                    condition,
                },
            );
        }

        let alias_map = Self::build_alias_map(assignments);
        let signature = FunctionSignature {
            name: String::new(),
            file_path: file_path.to_string(),
            start_line: 1,
            end_line: content.lines().count(),
            params: vec![],
        };

        FunctionCPG {
            cfg,
            node_meta,
            alias_map,
            signature,
        }
    }

    /// 从条件表达式文本中提取 ConditionInfo
    fn extract_condition_info(code: &str) -> Option<ConditionInfo> {
        // 提取条件部分：去掉 "if " / "elif " / "else if " 前缀
        let expr = code
            .trim_start_matches(|c: char| c.is_alphabetic() || c == ' ')
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim_start_matches('{')
            .trim()
            .to_string();

        if expr.is_empty() || expr == "[merge]" || expr.starts_with('[') {
            return None;
        }

        // 提取使用的变量（简化：按常见分隔符分词）
        let used_vars = Self::extract_variables(&expr);
        // 提取函数调用（匹配 word( 模式）
        let calls = Self::extract_calls_from_expr(&expr);

        // 判断是否包含净化器检查
        let is_sanitizer_check = calls.iter().any(|c| {
            SANITIZER_CALL_PATTERNS
                .iter()
                .any(|p| c.eq_ignore_ascii_case(p))
        });

        Some(ConditionInfo {
            expr,
            used_vars,
            calls,
            is_sanitizer_check,
        })
    }

    /// 从表达式中提取标识符（排除关键字）
    fn extract_variables(expr: &str) -> Vec<String> {
        let keywords = [
            "if",
            "else",
            "for",
            "while",
            "return",
            "let",
            "const",
            "var",
            "fn",
            "func",
            "function",
            "def",
            "class",
            "import",
            "from",
            "true",
            "false",
            "null",
            "none",
            "undefined",
            "and",
            "or",
            "not",
            "typeof",
            "instanceof",
            "in",
            "of",
            "new",
            "async",
            "await",
        ];

        let mut vars = Vec::new();
        for word in expr.split(
            &[
                ' ', '(', ')', '+', '-', '*', '/', ',', ';', '[', ']', '{', '}', '<', '>', '=',
                '!', '&', '|', ':', '.', '?',
            ][..],
        ) {
            let word = word.trim();
            if !word.is_empty()
                && word
                    .chars()
                    .next()
                    .map_or(false, |c| c.is_alphabetic() || c == '_')
                && !keywords.contains(&word)
                && !vars.iter().any(|v| v == word)
            {
                vars.push(word.to_string());
            }
        }
        vars
    }

    /// 从表达式中提取函数调用名（word( 模式）
    fn extract_calls_from_expr(expr: &str) -> Vec<String> {
        let mut calls = Vec::new();
        let chars: Vec<char> = expr.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '(' && i > 0 {
                // 回溯找到函数名
                let mut end = i;
                while end > 0
                    && (chars[end - 1] == '.'
                        || chars[end - 1].is_alphanumeric()
                        || chars[end - 1] == '_')
                {
                    end -= 1;
                }
                if end < i {
                    let name: String = chars[end..i].iter().collect();
                    // 只取最后一段（如 obj.method → method）
                    let short_name = name.rsplit('.').next().unwrap_or(&name);
                    if !short_name.is_empty()
                        && short_name
                            .chars()
                            .next()
                            .map_or(false, |c| c.is_alphabetic())
                        && !calls.iter().any(|c| c == short_name)
                    {
                        calls.push(short_name.to_string());
                    }
                }
            }
            i += 1;
        }
        calls
    }

    /// 从赋值列表构建别名映射
    fn build_alias_map(assignments: &[Assignment]) -> AliasMap {
        let mut map = AliasMap::new();
        for assign in assignments {
            let detection = detect_all_aliases(assign);
            for (var, path) in detection.new_aliases {
                map.add_alias(&var, path);
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_condition_info_if_statement() {
        let info = CPGBuilder::extract_condition_info("if (isSafe(input))").unwrap();
        assert!(info.is_sanitizer_check);
        assert!(info.calls.contains(&"isSafe".to_string()));
        assert!(info.used_vars.contains(&"input".to_string()));
    }

    #[test]
    fn test_extract_condition_info_plain_condition() {
        let info = CPGBuilder::extract_condition_info("if (x > 0)").unwrap();
        assert!(!info.is_sanitizer_check);
        assert!(info.used_vars.contains(&"x".to_string()));
    }

    #[test]
    fn test_extract_condition_info_merge_node() {
        let result = CPGBuilder::extract_condition_info("[merge]");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_calls_from_expr() {
        let calls =
            CPGBuilder::extract_calls_from_expr("validate(req.body) && checkPermission(user)");
        assert!(calls.contains(&"validate".to_string()));
        assert!(calls.contains(&"checkPermission".to_string()));
    }

    #[test]
    fn test_extract_variables() {
        let vars = CPGBuilder::extract_variables("req.body.name !== undefined");
        assert!(vars.contains(&"req".to_string()));
    }
}
