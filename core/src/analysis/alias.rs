// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! AccessPath + AliasMap — 动态语言变量别名追踪
//!
//! 通过 AccessPath 表示属性链路径（如 "req.body.name"），
//! 通过 AliasMap 追踪解构、属性访问、简单别名等模式，
//! 解决动态语言中因变量重命名/解构导致的"污点断链"问题。

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::ast::symbol::Assignment;

/// 属性链路径，表示一个变量或属性访问链。
/// 例如: AccessPath { segments: ["req", "body", "name"] } 表示 req.body.name
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessPath {
    segments: Vec<String>,
}

impl AccessPath {
    /// 从点分字符串解析: "req.body" → ["req", "body"]
    pub fn from_dotted(s: &str) -> Self {
        let segments = s
            .split('.')
            .map(|seg| seg.trim().to_string())
            .filter(|seg| !seg.is_empty())
            .collect();
        Self { segments }
    }

    /// 从单个变量名创建: "req" → ["req"]
    pub fn simple(name: &str) -> Self {
        Self {
            segments: vec![name.to_string()],
        }
    }

    /// 根变量名（第一段）
    pub fn root(&self) -> &str {
        self.segments.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// 重新组合为点分字符串
    pub fn as_dotted(&self) -> String {
        self.segments.join(".")
    }

    /// 追加一个字段，返回新的 AccessPath
    pub fn extend(&self, field: &str) -> Self {
        let mut segments = self.segments.clone();
        segments.push(field.to_string());
        Self { segments }
    }

    /// 是否以 other 为前缀
    pub fn starts_with(&self, other: &AccessPath) -> bool {
        if other.segments.len() > self.segments.len() {
            return false;
        }
        self.segments[..other.segments.len()] == other.segments
    }

    /// other 是否以 self 为前缀
    pub fn is_prefix_of(&self, other: &AccessPath) -> bool {
        other.starts_with(self)
    }

    /// 路径深度（段数）
    pub fn depth(&self) -> usize {
        self.segments.len()
    }

    /// 是否是简单变量名（无属性访问）
    pub fn is_simple(&self) -> bool {
        self.segments.len() == 1
    }
}

/// 最大传递解析深度，防止循环别名导致无限递归
const MAX_TRANSITIVE_DEPTH: usize = 3;

/// 别名映射表: 局部变量名 → 其别名的一组 AccessPath
///
/// 支持传递解析: 如果 y→x 且 x→obj.prop，则 resolve("y") 返回 {obj.prop}
#[derive(Debug, Clone, Default)]
pub struct AliasMap {
    /// var_name → set of aliased AccessPaths
    aliases: HashMap<String, HashSet<AccessPath>>,
}

impl AliasMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// 记录 local_var 别名了 access_path
    pub fn add_alias(&mut self, local_var: &str, path: AccessPath) {
        self.aliases
            .entry(local_var.to_string())
            .or_default()
            .insert(path);
    }

    /// 解析 local_var 到所有传递可达的 AccessPath
    pub fn resolve(&self, local_var: &str) -> HashSet<AccessPath> {
        let mut result = HashSet::new();
        let mut visited = HashSet::new();
        self.resolve_recursive(local_var, &mut result, &mut visited, 0);
        result
    }

    /// 返回所有别名映射的迭代器
    pub fn all_aliases(&self) -> impl Iterator<Item = (&String, &HashSet<AccessPath>)> {
        self.aliases.iter()
    }

    fn resolve_recursive(
        &self,
        var: &str,
        result: &mut HashSet<AccessPath>,
        visited: &mut HashSet<String>,
        depth: usize,
    ) {
        if depth >= MAX_TRANSITIVE_DEPTH || visited.contains(var) {
            return;
        }
        visited.insert(var.to_string());

        if let Some(paths) = self.aliases.get(var) {
            for path in paths {
                result.insert(path.clone());
                if path.is_simple() {
                    self.resolve_recursive(path.root(), result, visited, depth + 1);
                }
            }
        }
    }

    /// 检查 local_var 的任何别名路径是否匹配（以 pattern 为前缀或等于 pattern）
    pub fn matches_pattern(&self, local_var: &str, pattern: &AccessPath) -> bool {
        for path in self.resolve(local_var) {
            if path.starts_with(pattern) || pattern.starts_with(&path) {
                return true;
            }
        }
        false
    }

    /// 对于给定的 AccessPath，找到所有别名了该路径（或其前缀）的局部变量
    pub fn find_variables_for_path(&self, path: &AccessPath) -> Vec<String> {
        let mut result = Vec::new();
        for (var, paths) in &self.aliases {
            for alias_path in paths {
                if alias_path.starts_with(path) || path.starts_with(alias_path) {
                    result.push(var.clone());
                    break;
                }
            }
        }
        result
    }

    /// 返回所有已解析的路径字符串（用于 source pattern 匹配）
    pub fn all_resolved_paths(&self) -> HashSet<String> {
        let mut paths = HashSet::new();
        for (_, alias_set) in &self.aliases {
            for p in alias_set {
                paths.insert(p.as_dotted());
            }
        }
        paths
    }

    /// 返回所有别名条目（用于迭代）
    pub fn entries(&self) -> impl Iterator<Item = (&String, &HashSet<AccessPath>)> {
        self.aliases.iter()
    }
}

/// 别名检测结果
#[derive(Debug, Default)]
pub struct AliasDetection {
    /// (local_var, access_path) 对
    pub new_aliases: Vec<(String, AccessPath)>,
}

/// 检测对象解构模式
///
/// ```js
/// const { body, query } = req       → body→req.body, query→req.query
/// const { body: data } = req        → data→req.body
/// ```
pub fn detect_destructuring(assign: &Assignment) -> AliasDetection {
    let mut detection = AliasDetection::default();
    let target = assign.target.trim();
    let source = assign.source_expr.trim();

    // 对象解构: { a, b } 或 { a: c }
    if target.starts_with('{') && target.ends_with('}') {
        let inner = &target[1..target.len() - 1];
        let source_path = AccessPath::from_dotted(source);

        for part in inner.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if part.contains(':') {
                // 重命名: { body: data }
                let pieces: Vec<&str> = part.split(':').collect();
                let original = pieces[0].trim();
                let alias_name = pieces[1].trim();
                if !original.is_empty() && !alias_name.is_empty() {
                    detection
                        .new_aliases
                        .push((alias_name.to_string(), source_path.extend(original)));
                }
            } else {
                // 简单: { body }
                let name = part.trim();
                if !name.is_empty() && is_valid_identifier(name) {
                    detection
                        .new_aliases
                        .push((name.to_string(), source_path.extend(name)));
                }
            }
        }
        return detection;
    }

    // 数组解构: [a, b]
    if target.starts_with('[') && target.ends_with(']') {
        let inner = &target[1..target.len() - 1];
        let source_path = AccessPath::from_dotted(source);

        for (idx, part) in inner.split(',').enumerate() {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if is_valid_identifier(part) {
                detection
                    .new_aliases
                    .push((part.to_string(), source_path.extend(&format!("[{}]", idx))));
            }
        }
    }

    detection
}

/// 检测属性访问赋值模式
///
/// ```js
/// const x = obj.prop          → x→obj.prop
/// const y = req.body.name     → y→req.body.name
/// ```
pub fn detect_property_access(assign: &Assignment) -> AliasDetection {
    let mut detection = AliasDetection::default();
    let target = clean_target_name(&assign.target);
    let source = assign.source_expr.trim();

    if target.is_empty() {
        return detection;
    }

    // source_expr 是纯属性链: a.b.c (不含运算符、函数调用、括号等)
    if is_pure_member_expression(source) {
        let path = AccessPath::from_dotted(source);
        if path.depth() > 1 {
            detection.new_aliases.push((target.to_string(), path));
        }
    }

    detection
}

/// 检测简单变量别名
///
/// ```js
/// const y = x     → y 继承 x 的所有别名
/// let data = body → data 继承 body 的所有别名
/// ```
pub fn detect_simple_alias(assign: &Assignment) -> AliasDetection {
    let mut detection = AliasDetection::default();
    let target = clean_target_name(&assign.target);
    let source = assign.source_expr.trim();

    if target.is_empty() || source.is_empty() {
        return detection;
    }
    // 目标必须是裸标识符；`char *p` / `self.attr` 交给 C 指针或属性路径逻辑
    if !is_valid_identifier(target) {
        return detection;
    }

    // 条件: source_vars 恰好一个，且 source_expr 等于该变量名（无运算符）
    if assign.source_vars.len() == 1
        && source == assign.source_vars[0]
        && is_valid_identifier(source)
    {
        detection
            .new_aliases
            .push((target.to_string(), AccessPath::simple(source)));
    }

    detection
}

/// 检测 await 表达式别名
///
/// ```js
/// const data = await expr → data 别名 expr (去掉 await 前缀)
/// const resp = await fetch(url) → resp 别名 fetch(url)
/// ```
pub fn detect_await_alias(assign: &Assignment) -> AliasDetection {
    let mut detection = AliasDetection::default();
    let target = clean_target_name(&assign.target);
    let source = assign.source_expr.trim();

    if target.is_empty() || !source.starts_with("await ") {
        return detection;
    }

    let inner = source.strip_prefix("await ").unwrap().trim();
    if inner.is_empty() {
        return detection;
    }

    // 对于简单的 member_expression（如 await response.json()），用表达式作为路径
    // 对于纯标识符（如 await promise），直接别名
    if is_valid_identifier(inner) {
        detection
            .new_aliases
            .push((target.to_string(), AccessPath::simple(inner)));
    } else if let Some(first_ident) = inner.split('.').next() {
        if is_valid_identifier(first_ident) {
            detection
                .new_aliases
                .push((target.to_string(), AccessPath::simple(first_ident)));
        }
    }

    detection
}

/// 运行所有别名检测
pub fn detect_all_aliases(assign: &Assignment) -> AliasDetection {
    let mut result = AliasDetection::default();

    // 属性访问优先级最高（最精确）
    let prop = detect_property_access(assign);
    if !prop.new_aliases.is_empty() {
        result.new_aliases.extend(prop.new_aliases);
        return result;
    }

    // await 表达式（在简单别名之前，因为 await x 也是单变量）
    let await_alias = detect_await_alias(assign);
    if !await_alias.new_aliases.is_empty() {
        result.new_aliases.extend(await_alias.new_aliases);
        return result;
    }

    // 解构
    let destr = detect_destructuring(assign);
    result.new_aliases.extend(destr.new_aliases);

    // 简单别名（仅在非解构时）
    if result.new_aliases.is_empty() {
        let simple = detect_simple_alias(assign);
        result.new_aliases.extend(simple.new_aliases);
    }

    // C 指针简单别名（10.3 近似）：`char *p = &x` / `int *p = q`。
    // 只处理“取地址 + 裸变量”与“同变量赋值”，遇指针算术保守不处理。
    if result.new_aliases.is_empty() {
        let c_alias = detect_c_pointer_assignment(assign);
        result.new_aliases.extend(c_alias.new_aliases);
    }

    result
}

/// 10.3 最低成本近似：C 指针简单别名。
///
/// 目标形如 `char *p = ...`、`FILE *fp = ...` 时提取最后一个标识符作为别名目标；
/// 右值形如 `&x` 或裸标识符时建立 target → x/q 的别名边。
fn detect_c_pointer_assignment(assign: &Assignment) -> AliasDetection {
    let mut detection = AliasDetection::default();
    let target = assign.target.trim();
    let source = assign.source_expr.trim();

    // 提取 `type *name` 中的 name（仅常见标量/指针类型前缀，避免误伤 JS）
    let target_name = if let Some(idx) = target.rfind('*') {
        let candidate = target[idx + 1..].trim();
        if is_valid_identifier(candidate) {
            candidate.to_string()
        } else {
            return detection;
        }
    } else {
        clean_target_name(target).to_string()
    };
    if !is_valid_identifier(&target_name) {
        return detection;
    }

    // p = &x
    if let Some(stripped) = source.strip_prefix('&') {
        let stripped = stripped.trim();
        if is_valid_identifier(stripped) {
            detection
                .new_aliases
                .push((target_name, AccessPath::simple(stripped)));
            return detection;
        }
    }

    // p = q（纯变量，不带 * / 算术）
    if assign.source_vars.len() == 1 && is_valid_identifier(source) {
        detection
            .new_aliases
            .push((target_name, AccessPath::simple(source)));
    }
    detection
}

/// 清理 target 名称：去掉 const/let/var 前缀
fn clean_target_name(target: &str) -> &str {
    let t = target.trim();
    t.strip_prefix("const ")
        .or_else(|| t.strip_prefix("let "))
        .or_else(|| t.strip_prefix("var "))
        .unwrap_or(t)
        .trim()
}

/// 检查是否是有效的标识符
fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
}

/// 检查是否是纯属性链表达式（a.b.c，不含运算符/函数调用等）
fn is_pure_member_expression(expr: &str) -> bool {
    if expr.is_empty() {
        return false;
    }
    // 不应包含: 运算符、括号、分号、空格(除了属性链内的)
    let forbidden = [
        '+', '-', '*', '/', '%', '(', ')', ';', '=', '<', '>', '!', '&', '|', '?', ':', ',', '[',
        ']', '{', '}',
    ];
    if expr.chars().any(|c| forbidden.contains(&c)) {
        return false;
    }
    // 必须至少包含一个 '.' 且所有段都是有效标识符
    let parts: Vec<&str> = expr.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|p| is_valid_identifier(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::symbol::NodeInfo;

    fn make_assign(target: &str, source_expr: &str, source_vars: Vec<&str>) -> Assignment {
        Assignment {
            target: target.to_string(),
            target_node: NodeInfo {
                line: 1,
                column: 0,
                byte_start: 0,
                byte_end: target.len(),
            },
            source_expr: source_expr.to_string(),
            source_vars: source_vars.iter().map(|s| s.to_string()).collect(),
            line: 1,
            column: 0,
        }
    }

    // ===== AccessPath Tests =====

    #[test]
    fn test_access_path_from_dotted() {
        let path = AccessPath::from_dotted("req.body.name");
        assert_eq!(path.segments, vec!["req", "body", "name"]);
        assert_eq!(path.root(), "req");
        assert_eq!(path.as_dotted(), "req.body.name");
    }

    #[test]
    fn test_access_path_simple() {
        let path = AccessPath::simple("req");
        assert_eq!(path.segments, vec!["req"]);
        assert!(path.is_simple());
    }

    #[test]
    fn test_access_path_extend() {
        let path = AccessPath::from_dotted("req").extend("body");
        assert_eq!(path.as_dotted(), "req.body");
    }

    #[test]
    fn test_access_path_starts_with() {
        let path = AccessPath::from_dotted("req.body.name");
        let prefix = AccessPath::from_dotted("req.body");
        assert!(path.starts_with(&prefix));
        assert!(!prefix.starts_with(&path));
    }

    // ===== AliasMap Tests =====

    #[test]
    fn test_alias_map_basic() {
        let mut map = AliasMap::new();
        map.add_alias("body", AccessPath::from_dotted("req.body"));
        let resolved = map.resolve("body");
        assert!(resolved.contains(&AccessPath::from_dotted("req.body")));
    }

    #[test]
    fn test_alias_map_transitive() {
        let mut map = AliasMap::new();
        map.add_alias("y", AccessPath::simple("x"));
        map.add_alias("x", AccessPath::from_dotted("obj.prop"));
        let resolved = map.resolve("y");
        assert!(resolved.contains(&AccessPath::from_dotted("obj.prop")));
    }

    #[test]
    fn test_alias_map_circular_safe() {
        let mut map = AliasMap::new();
        map.add_alias("a", AccessPath::simple("b"));
        map.add_alias("b", AccessPath::simple("a"));
        // 不应死循环
        let resolved = map.resolve("a");
        assert!(!resolved.is_empty());
    }

    #[test]
    fn test_alias_map_matches_pattern() {
        let mut map = AliasMap::new();
        map.add_alias("body", AccessPath::from_dotted("req.body"));
        assert!(map.matches_pattern("body", &AccessPath::from_dotted("req.body")));
        assert!(map.matches_pattern("body", &AccessPath::from_dotted("req")));
    }

    #[test]
    fn test_alias_map_find_variables_for_path() {
        let mut map = AliasMap::new();
        map.add_alias("body", AccessPath::from_dotted("req.body"));
        map.add_alias("query", AccessPath::from_dotted("req.query"));
        let vars = map.find_variables_for_path(&AccessPath::from_dotted("req.body"));
        assert!(vars.contains(&"body".to_string()));
        assert!(!vars.contains(&"query".to_string()));
    }

    // ===== Pattern Detection Tests =====

    #[test]
    fn test_detect_destructuring_object() {
        let assign = make_assign("{ body, query }", "req", vec!["req"]);
        let detection = detect_destructuring(&assign);
        assert_eq!(detection.new_aliases.len(), 2);

        let aliases: HashMap<&str, &AccessPath> = detection
            .new_aliases
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect();
        assert_eq!(aliases["body"].as_dotted(), "req.body");
        assert_eq!(aliases["query"].as_dotted(), "req.query");
    }

    #[test]
    fn test_detect_destructuring_rename() {
        let assign = make_assign("{ body: data }", "req", vec!["req"]);
        let detection = detect_destructuring(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].0, "data");
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "req.body");
    }

    #[test]
    fn test_detect_property_access() {
        let assign = make_assign("x", "obj.prop", vec!["obj"]);
        let detection = detect_property_access(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].0, "x");
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "obj.prop");
    }

    #[test]
    fn test_detect_property_access_chain() {
        let assign = make_assign("y", "req.body.name", vec!["req"]);
        let detection = detect_property_access(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "req.body.name");
    }

    #[test]
    fn test_detect_simple_alias() {
        let assign = make_assign("y", "x", vec!["x"]);
        let detection = detect_simple_alias(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].0, "y");
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "x");
    }

    #[test]
    fn test_detect_not_concat() {
        let assign = make_assign("y", "x + z", vec!["x", "z"]);
        let detection = detect_simple_alias(&assign);
        assert!(detection.new_aliases.is_empty());
    }

    #[test]
    fn test_detect_not_function_call() {
        let assign = make_assign("y", "process(x)", vec!["x", "process"]);
        let detection = detect_simple_alias(&assign);
        assert!(detection.new_aliases.is_empty());
    }

    #[test]
    fn test_detect_all_aliases_property_priority() {
        // 属性访问应优先于简单别名
        let assign = make_assign("x", "req.body", vec!["req"]);
        let detection = detect_all_aliases(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "req.body");
    }

    #[test]
    fn test_detect_await_simple() {
        let assign = make_assign("data", "await promise", vec!["promise"]);
        let detection = detect_await_alias(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].0, "data");
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "promise");
    }

    #[test]
    fn test_detect_await_member_expr() {
        let assign = make_assign("data", "await response.json()", vec!["response"]);
        let detection = detect_await_alias(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "response");
    }

    #[test]
    fn test_detect_not_await() {
        let assign = make_assign("data", "promise", vec!["promise"]);
        let detection = detect_await_alias(&assign);
        assert!(detection.new_aliases.is_empty());
    }

    #[test]
    fn test_detect_all_aliases_await_priority() {
        // await 应优先于简单别名
        let assign = make_assign("data", "await promise", vec!["promise"]);
        let detection = detect_all_aliases(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "promise");
    }

    #[test]
    fn test_detect_c_pointer_assignment_address_of() {
        let assign = make_assign("char *p", "&x", vec!["x"]);
        let detection = detect_all_aliases(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].0, "p");
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "x");
    }

    #[test]
    fn test_detect_c_pointer_assignment_simple() {
        let assign = make_assign("FILE *fp", "q", vec!["q"]);
        let detection = detect_all_aliases(&assign);
        assert_eq!(detection.new_aliases.len(), 1);
        assert_eq!(detection.new_aliases[0].0, "fp");
        assert_eq!(detection.new_aliases[0].1.as_dotted(), "q");
    }
}
