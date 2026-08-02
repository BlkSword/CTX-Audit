use crate::rules::model::{Rule, SanitizerMatch};
use crate::scanner::{Finding, Scanner};
use async_trait::async_trait;
use regex::Regex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use tree_sitter::{Language, Parser, Query, QueryCursor};
use uuid::Uuid;

pub enum RuleMatcher {
    Regex(Regex),
    TreeSitter(Query),
}

pub struct CompiledRule {
    pub rule: Rule,
    pub matcher: RuleMatcher,
    pub language: Option<Language>,
}

pub struct RuleScanner {
    compiled_rules: Vec<CompiledRule>,
    context_lines: usize,
}

impl RuleScanner {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self::with_context_lines(rules, 3)
    }

    pub fn with_context_lines(rules: Vec<Rule>, context_lines: usize) -> Self {
        let mut compiled_rules = Vec::new();
        for rule in rules {
            // Priority: Query (AST) > patterns (multi-lang) > Pattern (Regex)
            if let Some(query_str) = &rule.query {
                if let Some(lang) = get_language_for_rule(&rule.language) {
                    match Query::new(&lang, query_str) {
                        Ok(query) => {
                            compiled_rules.push(CompiledRule {
                                rule: rule.clone(),
                                matcher: RuleMatcher::TreeSitter(query),
                                language: Some(lang),
                            });
                        }
                        Err(e) => {
                            eprintln!("Invalid Tree-sitter query for rule {}: {}", rule.id, e);
                        }
                    }
                } else {
                    eprintln!(
                        "Unsupported language for Tree-sitter rule {}: {}",
                        rule.id, rule.language
                    );
                }
            } else if let Some(patterns) = &rule.patterns {
                // 多语言模式：为每个 LanguagePattern 创建独立的编译规则
                for lp in patterns {
                    if let Ok(regex) = compile_rule_regex(&lp.pattern) {
                        // 创建一条带特定语言的副本
                        let mut lang_rule = rule.clone();
                        lang_rule.language = lp.language.clone();
                        lang_rule.pattern = Some(lp.pattern.clone());
                        lang_rule.patterns = None; // 避免重复展开
                        compiled_rules.push(CompiledRule {
                            rule: lang_rule,
                            matcher: RuleMatcher::Regex(regex),
                            language: None,
                        });
                    } else {
                        eprintln!(
                            "Invalid regex pattern for rule {} ({}): {}",
                            rule.id, lp.language, lp.pattern
                        );
                    }
                }
            } else if let Some(pattern) = &rule.pattern {
                if let Ok(regex) = compile_rule_regex(pattern) {
                    compiled_rules.push(CompiledRule {
                        rule: rule.clone(),
                        matcher: RuleMatcher::Regex(regex),
                        language: None,
                    });
                } else {
                    eprintln!("Invalid regex pattern for rule {}: {}", rule.id, pattern);
                }
            }
        }
        Self {
            compiled_rules,
            context_lines,
        }
    }

    /// 同步扫描文件（可在任意线程调用，不需要 async runtime）
    pub fn scan_file_sync(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 注释范围惰性计算：仅在首个命中时解析一次。
        // 命中点位于注释内则丢弃——注释中的代码不会执行，必为误报。
        let mut comment_ranges_cache: Option<Vec<(usize, usize)>> = None;
        // 字符串字面量范围同理，仅对 exclude_string_literals 的规则生效
        let mut string_ranges_cache: Option<Vec<(usize, usize)>> = None;
        // 条件编译块范围（仅 C 家族）：块内命中降 info——如 #ifdef MPE 平台分支
        // 的死代码（thttpd gets() 场景），不丢弃交由判定层
        let mut preproc_ranges_cache: Option<Vec<(usize, usize)>> = None;
        // PHP include 链守卫内容（10.13）：仅在带 sanitizer_include_chain 的
        // 规则首次做 sanitizer 检查时解析一次
        let mut guard_content_cache: Option<Option<String>> = None;
        // PHP 非裸调用形态的名字范围（php_bare_call_only 规则）：->method(、
        // ::method(、new Foo(、function foo( 的命中不是内建函数裸调用
        let mut php_bare_call_ranges_cache: Option<Vec<(usize, usize)>> = None;

        for compiled in &self.compiled_rules {
            // Simple language check based on extension
            if !rule_matches_extension(&compiled.rule.language, &extension) {
                continue;
            }

            match &compiled.matcher {
                RuleMatcher::Regex(regex) => {
                    let mut emitted = false;
                    for cap in regex.captures_iter(content) {
                        if emitted && compiled.rule.once_per_file {
                            break;
                        }
                        if let Some(m) = cap.get(0) {
                            let start_pos = m.start();
                            let guard = guard_for_rule(
                                &compiled.rule,
                                path,
                                &extension,
                                &mut guard_content_cache,
                            );
                            if is_rule_sanitized(content, start_pos, &compiled.rule, guard) {
                                continue;
                            }
                            // 函数级授权检查（backlog 10.27）：资源操作函数体内
                            // 无身份/属主校验即"缺失授权"候选。函数级语义——
                            // 同文件远处 import 的 auth 模块不豁免本函数。
                            if compiled.rule.auth_check_in_func
                                && enclosing_func_has_auth_check(
                                    content,
                                    start_pos,
                                    &extension,
                                    &compiled.rule.sanitizers,
                                )
                            {
                                continue;
                            }
                            let ranges = comment_ranges_cache
                                .get_or_insert_with(|| collect_comment_ranges(content, &extension));
                            if position_in_ranges(ranges, start_pos) {
                                continue;
                            }
                            if compiled.rule.exclude_string_literals {
                                let sranges = string_ranges_cache.get_or_insert_with(|| {
                                    collect_string_ranges(content, &extension)
                                });
                                if position_in_ranges(sranges, start_pos) {
                                    continue;
                                }
                            }
                            if compiled.rule.php_bare_call_only {
                                // 命中文本与"非裸调用名"范围有交叠即丢弃——
                                // $pdo->exec( 的命中带前缀字符 `>`，用区间
                                // 交叠而非点位判断
                                let branges = php_bare_call_ranges_cache.get_or_insert_with(|| {
                                    collect_php_non_bare_call_ranges(content, &extension)
                                });
                                if range_overlaps_ranges(branges, start_pos, m.end()) {
                                    continue;
                                }
                            }
                            let end_pos = m.end();

                            // Convert byte offset to line number
                            let line_start = content[..start_pos].matches('\n').count() + 1;
                            let line_end = content[..end_pos].matches('\n').count() + 1;

                            // 常量参数 / 安全格式串检测：sink 的参数攻击者不可控时
                            // 标记 likely_fp 并降为 info（不丢弃，交由上层/LLM 最终判定）。
                            // 凭证/密钥类规则除外——硬编码常量正是此类规则要发现的问题。
                            // 缺失检查类规则（missing/unprotected）同样除外——问题在
                            // "没有调用某校验"，与命中点参数是否字面量无关。
                            let matched_text = &content[start_pos..end_pos];
                            // `io.Copy(` 共现检查（backlog 10.19）：io.Copy 的参数是
                            // io.Reader/io.Writer 接口，流拷贝目标（HTTP 响应/管道/
                            // zip writer/临时文件）不是文件路径写入。仅当同一函数内
                            // 存在文件打开调用（os.Create/os.OpenFile）才保留——
                            // 那才是"用户可控路径 → 打开 → 拷贝"的危险形态。
                            if compiled.rule.go_io_copy_requires_open_file
                                && extension == "go"
                                && matched_text.to_lowercase().contains("io.copy(")
                                && !go_enclosing_func_has_file_open(content, start_pos)
                            {
                                continue;
                            }
                            // `sizeof *p`（无括号解引用形式）被分配器乘法 pattern 误读为
                            // 乘法（redis setproctitle.c 场景），必为误报，直接丢弃。
                            // 带括号的 sizeof(int) 不受影响——那才是真的乘法。
                            if is_c_family_ext(&extension) && contains_sizeof_deref(matched_text)
                            {
                                continue;
                            }
                            let likely_fp = if is_credential_related(&compiled.rule, matched_text)
                            {
                                if is_placeholder_secret(&compiled.rule, matched_text) {
                                    Some("值为占位符/示例，非真实凭证")
                                } else if is_config_key_value(matched_text) {
                                    Some("引号内值为配置 key 名称，非真实凭证")
                                } else {
                                    None
                                }
                            } else if is_missing_check_related(&compiled.rule) {
                                None
                            } else {
                                evaluate_likely_fp_args(content, start_pos, end_pos)
                                    .or_else(|| {
                                        // 条件编译块内（平台分支）的命中降 info：
                                        // 可能是非目标平台死代码（thttpd #ifdef MPE 场景）
                                        if is_c_family_ext(&extension) {
                                            let pranges = preproc_ranges_cache
                                                .get_or_insert_with(|| {
                                                    collect_preproc_ranges(content, &extension)
                                                });
                                            if position_in_ranges(pranges, start_pos) {
                                                return Some("位于条件编译块内，可能不适用于目标平台");
                                            }
                                        }
                                        None
                                    })
                                    .or_else(|| {
                                        if is_placeholder_secret(&compiled.rule, matched_text) {
                                            Some("值为占位符/示例，非真实凭证")
                                        } else {
                                            None
                                        }
                                    })
                            };

                            findings.push(create_finding(
                                &compiled.rule,
                                path,
                                line_start,
                                line_end,
                                format!("RegexRule: {}", compiled.rule.id),
                                content,
                                3,
                                likely_fp,
                            ));
                            emitted = true;
                        }
                    }
                }
                RuleMatcher::TreeSitter(query) => {
                    if let Some(lang) = &compiled.language {
                        thread_local! {
                            static PARSER_CACHE: std::cell::RefCell<HashMap<String, Parser>> =
                                std::cell::RefCell::new(HashMap::new());
                        }
                        let tree = PARSER_CACHE.with(|cache| {
                            let mut cache = cache.borrow_mut();
                            let lang_key = format!("{:?}", lang);
                            let parser = cache.entry(lang_key).or_insert_with(|| {
                                let mut p = Parser::new();
                                let _ = p.set_language(lang);
                                p
                            });
                            parser.parse(content, None)
                        });
                        if let Some(tree) = tree {
                            let mut cursor = QueryCursor::new();
                            let matches =
                                cursor.matches(query, tree.root_node(), content.as_bytes());

                            let mut emitted = false;
                            for m in matches {
                                if emitted && compiled.rule.once_per_file {
                                    break;
                                }
                                if let Some(capture) = m.captures.first() {
                                    let node = capture.node;
                                    let start_byte = node.start_byte();
                                    let guard = guard_for_rule(
                                        &compiled.rule,
                                        path,
                                        &extension,
                                        &mut guard_content_cache,
                                    );
                                    if is_rule_sanitized(content, start_byte, &compiled.rule, guard) {
                                        continue;
                                    }
                                    let start_pos = node.start_position();
                                    let end_pos = node.end_position();

                                    findings.push(create_finding(
                                        &compiled.rule,
                                        path,
                                        start_pos.row + 1,
                                        end_pos.row + 1,
                                        format!("ASTRule: {}", compiled.rule.id),
                                        content,
                                        3,
                                        None,
                                    ));
                                    emitted = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

#[async_trait]
impl Scanner for RuleScanner {
    fn name(&self) -> String {
        "RuleBasedScanner".to_string()
    }

    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
        self.scan_file_sync(path, content)
    }
}

/// 编译规则正则。Rust regex crate 不支持 `(?m)`/`(?s)`/`(?i)` 等 inline flag
/// （`Regex::new("(?m)...")` 直接报错导致规则静默跳过——规则作者常踩的坑）。
/// 这里把行首 inline flag 组（(?m)(?s)(?i)(?im)... 形态）转换为等价语义：
///   `(?m)` -> RegexBuilder::multi_line(true)（^/$ 按行匹配）
///   `(?s)` -> RegexBuilder::dot_matches_new_line(true)
///   `(?i)` -> RegexBuilder::case_insensitive(true)
/// 组合（如 `(?im)`）按字符逐个解析。非 flag 前缀（命名组 `(?P<name>`、
/// `(?<name>`）不匹配"全 m/s/i 字符"条件，原样保留由 RegexBuilder 处理。
fn compile_rule_regex(pattern: &str) -> Result<regex::Regex, regex::Error> {
    // 解析行首 inline flag 组并从 pattern 中剥除
    let mut flags = String::new();
    let mut rest = pattern;
    if let Some(inner) = pattern.strip_prefix("(?") {
        if let Some(end) = inner.find(')') {
            let flag_part = &inner[..end];
            // 仅当全部是 m/s/i 字符时才视为 flag 组（排除命名组 (?P<...>、(?<...>)
            if !flag_part.is_empty()
                && flag_part.chars().all(|c| matches!(c, 'm' | 's' | 'i'))
            {
                flags.push_str(flag_part);
                rest = &inner[end + 1..];
            }
        }
    }
    let mut builder = regex::RegexBuilder::new(rest);
    for c in flags.chars() {
        match c {
            'm' => {
                builder.multi_line(true);
            }
            's' => {
                builder.dot_matches_new_line(true);
            }
            'i' => {
                builder.case_insensitive(true);
            }
            _ => {}
        }
    }
    builder.build()
}

/// 带 sanitizer_include_chain 的规则：惰性解析当前文件的 PHP include 链，
/// 返回守卫文件合并内容（无链或非 PHP 返回 None）。
fn guard_for_rule<'a>(
    rule: &Rule,
    path: &PathBuf,
    extension: &str,
    cache: &'a mut Option<Option<String>>,
) -> Option<&'a str> {
    if !rule.sanitizer_include_chain {
        return None;
    }
    cache
        .get_or_insert_with(|| collect_php_guard_content(path, extension))
        .as_deref()
}

/// PHP include/require 链解析（backlog 10.13）：从被扫描文件出发，提取
/// include/require 语句中的路径字面量，best-effort 解析为磁盘文件并递归，
/// 收集守卫文件内容（深度≤3、文件≤16、仅 .php，环路去重）。
///
/// 解析启发式：`__DIR__`/`dirname(__FILE__)` → 当前文件目录；
/// 其余常量前缀（如 ROOT_DIR）同样回落到当前文件目录；
/// 字符串里的 `..`/`./` 手工归一。解析失败的路径直接跳过——
/// 这是去误报辅助，宁可漏豁免也不引入异常。
fn collect_php_guard_content(path: &PathBuf, extension: &str) -> Option<String> {
    if extension != "php" {
        return None;
    }
    let mut visited = std::collections::HashSet::new();
    let mut out = String::new();
    let mut budget = 16usize;
    collect_php_guard_recursive(path, 0, &mut visited, &mut budget, &mut out);
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn collect_php_guard_recursive(
    path: &PathBuf,
    depth: usize,
    visited: &mut std::collections::HashSet<PathBuf>,
    budget: &mut usize,
    out: &mut String,
) {
    if depth > 3 || *budget == 0 {
        return;
    }
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Some(dir) = path.parent().map(|p| p.to_path_buf()) else {
        return;
    };
    for inc in extract_php_include_literals(&content) {
        if *budget == 0 {
            return;
        }
        let Some(resolved) = resolve_php_include(&dir, &inc) else {
            continue;
        };
        if resolved.extension().and_then(|e| e.to_str()) != Some("php") {
            continue;
        }
        if !visited.insert(resolved.clone()) {
            continue;
        }
        if let Ok(guard) = std::fs::read_to_string(&resolved) {
            *budget -= 1;
            out.push_str(&guard);
            out.push('\n');
            collect_php_guard_recursive(&resolved, depth + 1, visited, budget, out);
        }
    }
}

/// 提取 include/require 语句中的字符串字面量路径。
fn extract_php_include_literals(content: &str) -> Vec<String> {
    let stmt_re = regex::Regex::new(r"(?i)(?:require|include)(?:_once)?\s*\(?\s*([^;\n]{1,200})")
        .expect("include stmt regex");
    let str_re = regex::Regex::new(r#"['"]([^'"]{1,200})['"]"#).expect("string lit regex");
    let mut lits = Vec::new();
    for cap in stmt_re.captures_iter(content) {
        let expr = &cap[1];
        // 表达式中不得有函数调用（动态路径不解析），变量拼接按字面量部分尝试
        for scap in str_re.captures_iter(expr) {
            lits.push(scap[1].to_string());
        }
    }
    lits
}

/// 把 include 字面量解析为磁盘路径：优先相对当前文件目录；
/// 归一化 `./`、`../` 与前导 `/`（ROOT_DIR.'/x.php' 场景）。
fn resolve_php_include(dir: &PathBuf, lit: &str) -> Option<PathBuf> {
    let cleaned = lit.trim_start_matches('/').replace('\\', "/");
    let mut candidate = dir.clone();
    for part in cleaned.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                candidate.pop();
            }
            p => candidate.push(p),
        }
    }
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// 检查规则命中是否被 sanitizer 豁免。
/// 默认前缀语义（命中点之前出现即豁免）；规则声明 `sanitizer_file_scope: true` 时
/// 全文件任一处出现即豁免（"缺失检查"类规则：校验在文件任意位置都算已接入防护）。
/// `sanitizer_match: all` 时要求全部 sanitizer 都出现才豁免（防护完整性检查）。
/// `guard` 为 include 链守卫内容（10.13），命中即豁免——全局校验无"位置"语义。
fn is_rule_sanitized(content: &str, pos: usize, rule: &Rule, guard: Option<&str>) -> bool {
    let match_all = rule.sanitizer_match == SanitizerMatch::All;
    if rule.sanitizer_after_lines > 0 {
        // 后向窗口语义：仅看命中点之后 N 行（替代前缀语义），
        // 避免同文件 import/其他守卫造成的前缀误豁免
        if is_sanitized_within_lines_after(content, pos, &rule.sanitizers, match_all, rule.sanitizer_after_lines) {
            return true;
        }
        // 前向窗口语义（有界，10.25）：仅看命中点之前 N 行，
        // 覆盖"先净化后使用"形态（sanitize 在 sink 上一两行），远处 import/守卫不吃
        if rule.sanitizer_before_lines > 0
            && is_sanitized_within_lines_before(content, pos, &rule.sanitizers, match_all, rule.sanitizer_before_lines)
        {
            return true;
        }
    } else {
        let effective_pos = if rule.sanitizer_file_scope {
            content.len()
        } else {
            pos
        };
        if is_sanitized_before(content, effective_pos, &rule.sanitizers, match_all) {
            return true;
        }
    }
    if let Some(guard) = guard {
        return is_sanitized_before(guard, guard.len(), &rule.sanitizers, match_all);
    }
    false
}

/// 检查命中点之后 N 行内（含命中行剩余部分）是否出现 sanitizer 模式。
/// 检查匹配位置之后 N 行内是否出现 sanitizer（后向窗口语义）。
/// 用于"先取路径后校验"形态：校验调用紧跟 sink 之后。
fn is_sanitized_within_lines_after(
    content: &str,
    pos: usize,
    sanitizers: &[String],
    match_all: bool,
    lines: usize,
) -> bool {
    if sanitizers.is_empty() || pos >= content.len() {
        return false;
    }
    let mut end = content.len();
    let mut seen = 0;
    for (i, b) in content[pos..].bytes().enumerate() {
        if b == b'\n' {
            seen += 1;
            if seen >= lines {
                end = pos + i;
                break;
            }
        }
    }
    let window = content[pos..end].to_lowercase();
    let contains = |s: &String| window.contains(&s.to_lowercase());
    if match_all {
        sanitizers.iter().all(contains)
    } else {
        sanitizers.iter().any(contains)
    }
}

/// 检查匹配位置之前 N 行内是否出现 sanitizer（前向窗口语义，10.25）。
/// 用于"先净化后使用"形态（`const safe = sanitize(x); sink(dir, safe)`），
/// 窗口有界以避免同文件远处 import/无关守卫误豁免。
fn is_sanitized_within_lines_before(
    content: &str,
    pos: usize,
    sanitizers: &[String],
    match_all: bool,
    lines: usize,
) -> bool {
    if sanitizers.is_empty() || pos == 0 {
        return false;
    }
    let mut start = 0;
    let mut seen = 0;
    for (i, b) in content[..pos].bytes().enumerate().rev() {
        if b == b'\n' {
            seen += 1;
            if seen >= lines {
                start = i + 1;
                break;
            }
        }
    }
    let window = content[start..pos].to_lowercase();
    let contains = |s: &String| window.contains(&s.to_lowercase());
    if match_all {
        sanitizers.iter().all(contains)
    } else {
        sanitizers.iter().any(contains)
    }
}

/// 检查匹配位置之前是否出现 sanitizer 模式。
/// 用于规则级去误报：命中点之前存在净化代码，则跳过该发现。
/// `match_all` 为 true 时要求所有 sanitizer 都出现（任一缺失即不豁免）。
fn is_sanitized_before(content: &str, pos: usize, sanitizers: &[String], match_all: bool) -> bool {
    if sanitizers.is_empty() || pos == 0 {
        return false;
    }
    let prefix = &content[..pos.min(content.len())];
    let prefix_lower = prefix.to_lowercase();
    let contains = |s: &String| prefix_lower.contains(&s.to_lowercase());
    if match_all {
        sanitizers.iter().all(contains)
    } else {
        sanitizers.iter().any(contains)
    }
}

/// printf 族函数：格式串为字面量且不含 %s/%[ 时，输出长度有界，
/// 攻击者无法控制写入内容，可判 likely_fp。
const PRINTF_FAMILY: &[&str] = &[
    "sprintf", "vsprintf", "snprintf", "vsnprintf", "fprintf", "printf", "swprintf", "fwprintf",
];

/// 从匹配位置提取调用的参数文本（字符串感知的括号配平）。
/// match_start/match_end 为规则命中区间（通常以 `(` 结尾）。
/// 返回 (函数名, 参数文本)。提取失败返回 None。
fn extract_call_args(content: &str, match_start: usize, match_end: usize) -> Option<(String, String)> {
    let matched = content.get(match_start..match_end)?;
    let paren_rel = matched.rfind('(')?;
    let func_name = matched[..paren_rel]
        .trim_end()
        .rsplit(|c: char| !c.is_alphanumeric() && c != '_' && c != ':' && c != '.')
        .next()?
        .to_string();
    if func_name.is_empty() {
        return None;
    }

    let bytes = content.as_bytes();
    let mut i = match_start + paren_rel;
    let mut depth = 0usize;
    let mut args = String::new();
    let mut in_str: Option<u8> = None;
    let mut prev = 0u8;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            args.push(c as char);
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = Some(c);
            args.push(c as char);
        } else if c == b'(' {
            depth += 1;
            if depth > 1 {
                args.push(c as char);
            }
        } else if c == b')' {
            depth -= 1;
            if depth == 0 {
                return Some((func_name, args));
            }
            args.push(c as char);
        } else if depth >= 1 {
            args.push(c as char);
        }
        prev = c;
        i += 1;
    }
    None
}

/// 判断参数文本是否全为字面量/常量（字符串、字符、数字、布尔、None/null）。
/// 字符串字面量内的内容不参与标识符判定。
fn args_all_literals(args: &str) -> bool {
    let mut cleaned = String::with_capacity(args.len());
    let bytes = args.as_bytes();
    let mut i = 0;
    let mut in_str: Option<u8> = None;
    let mut prev = 0u8;
    while i < bytes.len() {
        let c = bytes[i];
        if let Some(q) = in_str {
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = Some(c);
        } else {
            cleaned.push(c as char);
        }
        prev = c;
        i += 1;
    }
    // 清理后不允许出现任何标识符（函数调用、变量、关键字 true/false/null/None 除外）
    !cleaned
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
        .filter(|tok| !tok.is_empty())
        .any(|tok| {
            let t = tok.trim_matches('.');
            !t.is_empty()
                && t.chars().next().map(|c| c.is_alphabetic() || c == '_').unwrap_or(false)
                && !matches!(t, "true" | "false" | "null" | "None" | "TRUE" | "FALSE" | "NULL")
        })
}

/// 提取参数文本中的字符串字面量列表
fn extract_string_literals(args: &str) -> Vec<String> {
    let mut lits = Vec::new();
    let bytes = args.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            let q = c;
            let mut j = i + 1;
            let mut lit = String::new();
            while j < bytes.len() && (bytes[j] != q || bytes[j - 1] == b'\\') {
                lit.push(bytes[j] as char);
                j += 1;
            }
            if j < bytes.len() {
                lits.push(lit);
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    lits
}

/// 拷贝族函数：源参数为字符串字面量时，拷贝长度有界（如 strcpy(dst, "literal")）
const COPY_FAMILY: &[&str] = &["strcpy", "strcat", "wcscpy", "wcscat", "lstrcpy", "lstrcat"];

/// 取顶层逗号分隔的最后一个参数（不深入嵌套括号）
fn last_top_level_arg(args: &str) -> &str {
    let mut depth = 0i32;
    let mut last_split = 0usize;
    let bytes = args.as_bytes();
    let mut in_str: Option<u8> = None;
    let mut prev = 0u8;
    for (i, &c) in bytes.iter().enumerate() {
        if let Some(q) = in_str {
            if c == q && prev != b'\\' {
                in_str = None;
            }
        } else if c == b'"' || c == b'\'' {
            in_str = Some(c);
        } else if c == b'(' {
            depth += 1;
        } else if c == b')' {
            depth -= 1;
        } else if c == b',' && depth == 0 {
            last_split = i + 1;
        }
        prev = c;
    }
    args[last_split..].trim()
}

/// 判断文本是否为单个字符串字面量（允许空白包裹）
fn is_string_literal(s: &str) -> bool {
    let s = s.trim();
    s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
}

/// 向下钳制到最近的 char 边界（字节索引可能落在多字节字符内部）
fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    let mut i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// 向上钳制到最近的 char 边界
fn ceil_char_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// 评估 sink 调用的参数是否攻击者不可控（likely_fp）。
/// 返回 Some(原因) 表示可降级为 info：
/// - 参数全部为字面量（如 os.popen("netstat ...")）
/// - printf 族格式串为字面量且不含 %s/%[（输出长度有界）
/// - strcpy/strcat 族源参数为字符串字面量（拷贝长度有界）
fn evaluate_likely_fp_args(content: &str, match_start: usize, match_end: usize) -> Option<&'static str> {
    let (func_name, args) = extract_call_args(content, match_start, match_end)?;
    if args.trim().is_empty() {
        return None;
    }

    // shell=true 是高风险信号 — 不降权，保持高置信度
    // 注意：±200 字节的窗口可能落在多字节字符内部，必须钳制到 char 边界，
    // 否则按字节切片会 panic（emlog 实测：中文注释触发 end byte index 非边界）
    let context_start = floor_char_boundary(content, match_start.saturating_sub(200));
    let context_end = ceil_char_boundary(content, (match_end + 200).min(content.len()));
    let context = &content[context_start..context_end].to_lowercase();
    if context.contains("shell=true") || context.contains("shell = true") {
        return None;
    }

    if args_all_literals(&args) {
        return Some("参数全部为字面量，攻击者不可控");
    }
    let short_name = func_name.rsplit(|c| c == ':' || c == '.').next().unwrap_or(&func_name);
    if PRINTF_FAMILY.contains(&short_name) {
        let lits = extract_string_literals(&args);
        // printf 族：第一个字符串字面量即格式串（可能跳过 dst/stream 参数，取首个字面量近似）
        if let Some(fmt) = lits.first() {
            if !fmt.contains("%s") && !fmt.contains("%[") && !fmt.is_empty() {
                return Some("printf 族格式串为字面量且无 %s，输出有界");
            }
        }
    }
    if COPY_FAMILY.contains(&short_name) && is_string_literal(last_top_level_arg(&args)) {
        return Some("拷贝源为字符串字面量，长度有界");
    }
    None
}

/// 明显的占位符/示例口令值（模板配置），非真实凭证
const PLACEHOLDER_SECRETS: &[&str] = &[
    "user_password",
    "your_password",
    "your-password",
    "yourpassword",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "replace_me",
    "insert_password",
    "password_here",
    "your_secret",
    "your-secret",
    "example_password",
    "******",
];

/// 缺失检查类规则（id 含 missing/unprotected）：问题是"没有调用某校验"，
/// 命中点参数是否字面量与可利用性无关，不做参数字面量降权
fn is_missing_check_related(rule: &Rule) -> bool {
    rule.id.contains("missing") || rule.id.contains("unprotected")
}

/// 判断是否为凭证/密钥类规则（此类规则的"常量"正是问题本身，不做参数字面量降权）
fn is_credential_related(rule: &Rule, matched_text: &str) -> bool {    rule.cwe
        .as_deref()
        .map(|c| c == "CWE-259" || c == "CWE-798")
        .unwrap_or(false)
        || rule.id.contains("password")
        || rule.id.contains("secret")
        || rule.id.contains("credential")
        || rule.id.contains("crypto-key")
        || matched_text.to_lowercase().contains("password")
}

/// 凭证类规则命中明显的占位符值时判 likely_fp
fn is_placeholder_secret(rule: &Rule, matched_text: &str) -> bool {
    if !is_credential_related(rule, matched_text) {
        return false;
    }
    let lower = matched_text.to_lowercase();
    PLACEHOLDER_SECRETS.iter().any(|p| lower.contains(p))
}

/// 判断引号内的值是否为配置 key 名称（仅含标识符字符），而非真实凭证
/// 例如 Go const: const SSOClientSecret = "sso_client_secret" 中的值是 key 名称
fn is_config_key_value(matched_text: &str) -> bool {
    // 提取引号内的值
    let extract_quoted = |quote: char| -> Option<&str> {
        let start = matched_text.rfind(quote)?;
        if start > 0 && matched_text.as_bytes().get(start - 1) == Some(&(b'\\')) {
            return None;
        }
        let before = &matched_text[..start];
        let eq_pos = before.rfind('=')?;
        // 确保等号后在引号前没有其他内容（除了空白）
        let between = before[eq_pos + 1..].trim();
        if !between.is_empty() && between != ":" {
            return None;
        }
        // 找到结束引号
        let after = &matched_text[start + 1..];
        let end = after.find(quote)?;
        Some(&after[..end])
    };

    let value = match extract_quoted('"') {
        Some(v) => v,
        None => match extract_quoted('\'') {
            Some(v) => v,
            None => return false,
        },
    };
    if value.len() < 4 {
        return false;
    }

    // 配置 key 名称特征：只含标识符字符（字母、数字、下划线、点、连字符）
    let is_identifier = value
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-');
    if !is_identifier {
        return false;
    }

    // 排除明显是真实密钥的情况：包含 Base64 特征或高熵片段
    let has_base64_pattern = value.len() >= 12
        && (value.contains("+/") || value.contains("==") || value.contains("AAAA"));
    if has_base64_pattern {
        return false;
    }

    // 排除明显的 hash 值（连续长十六进制串）
    let has_hash_pattern = value.len() >= 16
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && !value.contains('_');
    if has_hash_pattern {
        return false;
    }

    true
}

fn create_finding(
    rule: &Rule,
    path: &PathBuf,
    line_start: usize,
    line_end: usize,
    detector: String,
    content: &str,
    context_lines: usize,
    likely_fp: Option<&'static str>,
) -> Finding {
    let code_snippet = Some(crate::scanner::extract_code_context(
        content,
        line_start,
        line_end,
        context_lines,
    ));
    let file_path = path.to_string_lossy().to_string();
    let vuln_type = rule.cwe.clone().unwrap_or_else(|| "Unknown".to_string());

    // 文件角色分类（含 minified 内容识别）
    let file_role = Some(crate::scanner::classify_file_role_with_content(&file_path, content).to_string());

    // 安全屏障检测
    let barriers = {
        let b = crate::scanner::detect_barriers(content, line_start, line_end, &vuln_type);
        if b.is_empty() {
            None
        } else {
            Some(b)
        }
    };

    // 根据角色和屏障调整严重程度
    let raw_severity = format!("{:?}", rule.severity).to_lowercase();
    let adjusted = crate::scanner::adjust_severity(
        &raw_severity,
        file_role.as_deref().unwrap_or("production"),
        barriers.as_deref().unwrap_or(&[]),
    );
    // likely_fp：参数攻击者不可控（全字面量 / 安全格式串），降为 info
    let severity = if likely_fp.is_some() {
        "info".to_string()
    } else {
        adjusted
    };

    // 生成标记原因
    let reasoning_hint = Some(match likely_fp {
        Some(reason) => format!(
            "Matched {} pattern in {} context; likely_fp: {}",
            rule.id,
            file_role.as_deref().unwrap_or("unknown"),
            reason
        ),
        None => format!(
            "Matched {} pattern in {} context",
            rule.id,
            file_role.as_deref().unwrap_or("unknown")
        ),
    });

    Finding {
        finding_id: Uuid::new_v4().to_string(),
        file_path,
        line_start,
        line_end,
        detector,
        vuln_type,
        severity,
        description: rule.description.clone(),
        analysis_trail: None,
        llm_output: None,
        confidence: None,
        corroboration_count: None,
        code_snippet,
        source_snippet: None,
        sink_snippet: None,
        file_role,
        barriers,
        reasoning_hint,
        evidence_refs: None,
        ..Default::default()
    }
}

fn get_language_for_rule(language: &str) -> Option<Language> {
    match language.to_lowercase().as_str() {
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "c" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "json" => Some(tree_sitter_json::LANGUAGE.into()),
        "html" => Some(tree_sitter_html::LANGUAGE.into()),
        _ => None,
    }
}

/// 按文件扩展名选择 tree-sitter 语言（用于注释范围检测）
fn get_language_for_extension(extension: &str) -> Option<Language> {
    match extension {
        "py" => Some(tree_sitter_python::LANGUAGE.into()),
        "php" | "phtml" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        "js" | "jsx" | "mjs" | "cjs" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "c" | "h" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" | "hpp" | "cc" | "cxx" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "html" | "htm" => Some(tree_sitter_html::LANGUAGE.into()),
        "css" => Some(tree_sitter_css::LANGUAGE.into()),
        _ => None,
    }
}

/// 收集内容中所有注释节点的字节范围（按扩展名选语言）。
/// 不支持的语言返回空表（即不做注释过滤，行为与旧版一致）。
fn collect_comment_ranges(content: &str, extension: &str) -> Vec<(usize, usize)> {
    collect_node_ranges(content, extension, |kind| kind.contains("comment"))
}

/// 收集内容中所有字符串字面量节点的字节范围（按扩展名选语言）。
/// 用于 sink 调用类规则排除字符串内的误报（如错误消息里的 "system()"）。
fn collect_string_ranges(content: &str, extension: &str) -> Vec<(usize, usize)> {
    collect_node_ranges(content, extension, |kind| {
        kind.contains("string") && !kind.contains("escape")
    })
}

/// C 家族扩展名判定（C/C++ 源与头文件）
fn is_c_family_ext(extension: &str) -> bool {
    matches!(extension, "c" | "h" | "cpp" | "cc" | "cxx" | "hpp")
}

/// 判断文本是否包含无括号 sizeof 解引用形式 `sizeof *p`。
/// 分配器乘法 pattern（`\w+\s*\*\s*\w+`）会把它误读为乘法。
fn contains_sizeof_deref(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut idx = 0;
    while let Some(pos) = text[idx..].find("sizeof") {
        let abs = idx + pos + "sizeof".len();
        // sizeof 后跳过空白，若紧跟 `*` 即为无括号解引用形式
        let mut i = abs;
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'*' {
            return true;
        }
        idx = abs;
    }
    false
}

/// 收集条件编译块（#if/#ifdef/#ifndef/#elif/#else）的字节范围。
/// 排除接近覆盖全文件的范围——那是头文件 include guard，不是平台分支。
fn collect_preproc_ranges(content: &str, extension: &str) -> Vec<(usize, usize)> {
    let total = content.len();
    let mut ranges = collect_node_ranges(content, extension, |kind| {
        kind.starts_with("preproc_if") || kind == "preproc_elif" || kind == "preproc_else"
    });
    ranges.retain(|&(start, end)| (end - start) * 10 < total * 9);
    ranges
}

/// 用 tree-sitter 解析内容并收集谓词命中的节点字节范围。
/// 不支持的语言返回空表（即不做过滤，行为与旧版一致）。
fn collect_node_ranges(
    content: &str,
    extension: &str,
    pred: impl Fn(&str) -> bool,
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let lang = match get_language_for_extension(extension) {
        Some(l) => l,
        None => return ranges,
    };

    thread_local! {
        static COMMENT_PARSER_CACHE: RefCell<HashMap<String, Parser>> =
            RefCell::new(HashMap::new());
    }
    let tree = COMMENT_PARSER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let lang_key = format!("{:?}", lang);
        let parser = cache.entry(lang_key).or_insert_with(|| {
            let mut p = Parser::new();
            let _ = p.set_language(&lang);
            p
        });
        parser.parse(content, None)
    });
    let tree = match tree {
        Some(t) => t,
        None => return ranges,
    };

    // 迭代遍历（避免深递归），收集谓词命中节点的字节范围
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if pred(node.kind()) {
            ranges.push((node.start_byte(), node.end_byte()));
            continue; // 该类节点不会再嵌套代码
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    ranges.sort_unstable();
    ranges
}

/// 判断字节区间 [start, end) 是否与任一已排序范围有交叠
fn range_overlaps_ranges(ranges: &[(usize, usize)], start: usize, end: usize) -> bool {
    if start >= end {
        return false;
    }
    // 二分找到第一个 end > start 的范围，若其 start < end 则交叠
    let idx = ranges.partition_point(|&(_, e)| e <= start);
    match ranges.get(idx) {
        Some(&(s, _)) => s < end,
        None => false,
    }
}

/// 文件打开调用正则（io.Copy 共现检查用，backlog 10.19）：
/// `os.Create(`/`os.OpenFile(`（排除 `os.CreateTemp(`——临时文件良性）以及
/// `*Os*Create/OpenFile` 命名包装（如 `SafeOsOpenFile(`——打开语义同 os.OpenFile，
/// 清洗与否属判定层职责）。编译失败时返回 None（不豁免，保守保留）。
fn go_file_open_call_regex() -> Option<&'static Regex> {
    use std::sync::OnceLock;
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:\bos\.(?:Create|OpenFile)\s*\(|[A-Z][A-Za-z]*Os(?:Create|OpenFile)\s*\()"#)
            .ok()
    })
    .as_ref()
}

/// Go：`io.Copy(` 命中点的共现检查（backlog 10.19）——查找命中点所在的最深
/// 函数/方法/函数字面量节点，判断其函数体是否包含文件打开调用
/// （os.Create / os.OpenFile 及包装）。无函数包裹（顶层裸调用）保守返回 false
/// （不豁免）；无法解析时不豁免。已知限制：注释/字符串内的打开调用也会计数。
fn go_enclosing_func_has_file_open(content: &str, pos: usize) -> bool {
    thread_local! {
        static GO_PARSER_CACHE: RefCell<HashMap<String, Parser>> = RefCell::new(HashMap::new());
    }
    let tree = GO_PARSER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let parser = cache.entry("go".to_string()).or_insert_with(|| {
            let mut p = Parser::new();
            let _ = p.set_language(&tree_sitter_go::LANGUAGE.into());
            p
        });
        parser.parse(content, None)
    });
    let tree = match tree {
        Some(t) => t,
        None => return false,
    };
    // 递归查找包含 pos 的最深函数类节点（function_declaration /
    // method_declaration / func_literal）
    fn find_func<'a>(node: tree_sitter::Node<'a>, pos: usize) -> Option<tree_sitter::Node<'a>> {
        if node.start_byte() > pos || node.end_byte() <= pos {
            return None;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_func(child, pos) {
                return Some(found);
            }
        }
        if matches!(
            node.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            Some(node)
        } else {
            None
        }
    }
    let Some(func) = find_func(tree.root_node(), pos) else {
        return false;
    };
    let body = &content[func.start_byte()..func.end_byte()];
    go_file_open_call_regex()
        .map(|re| re.is_match(body))
        .unwrap_or(false)
}

/// 授权检查语义（missing-authorization 家族，backlog 10.27）：
/// 命中点所在函数/方法体内是否出现任一授权关键字。
/// 资源操作（按 id/name 的 get/delete/update/remove 等）的函数体内
/// 没有身份/属主校验（currentUser/owner/isAdmin/hasRole 等）即为
/// "缺失授权"候选（CWE-862）。函数作用域语义：同文件远处 import 的
/// auth 模块不豁免本函数（区别于 sanitizer_file_scope 的文件级语义）。
/// 授权关键字由调用方提供（规则 sanitizers 列表）。
/// 支持语言：go/java/python/javascript/typescript/php/rust/c/cpp。
/// 解析失败或无法确定函数范围时返回 false（保守：不豁免，交由判定层）。
fn enclosing_func_has_auth_check(
    content: &str,
    pos: usize,
    extension: &str,
    auth_keywords: &[String],
) -> bool {
    if auth_keywords.is_empty() || pos >= content.len() {
        return false;
    }
    let lang = match get_language_for_extension(extension) {
        Some(l) => l,
        None => return false,
    };
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return false;
    }
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return false,
    };
    // 递归查找包含 pos 的最深函数类节点——函数/方法定义体是授权检查的
    // 作用域边界。按语言映射函数节点类型：
    //   go:    function_declaration / method_declaration / func_literal
    //   java:  method_declaration / constructor_declaration
    //   python:function_definition
    //   js/ts: function_declaration / method_definition / arrow_function /
    //          function_expression / generator_function_declaration
    //   php:   function_definition / method_declaration
    //   rust:  function_item / closure_expression
    //   c/cpp: function_definition
    fn find_func<'a>(node: tree_sitter::Node<'a>, pos: usize) -> Option<tree_sitter::Node<'a>> {
        if node.start_byte() > pos || node.end_byte() <= pos {
            return None;
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_func(child, pos) {
                return Some(found);
            }
        }
        match node.kind() {
            "function_declaration"
            | "method_declaration"
            | "func_literal"
            | "constructor_declaration"
            | "function_definition"
            | "method_definition"
            | "arrow_function"
            | "function_expression"
            | "generator_function_declaration"
            | "function_item"
            | "closure_expression" => Some(node),
            _ => None,
        }
    }
    let Some(func) = find_func(tree.root_node(), pos) else {
        return false;
    };
    let body = &content[func.start_byte()..func.end_byte()];
    let body_lower = body.to_lowercase();
    auth_keywords
        .iter()
        .any(|kw| body_lower.contains(&kw.to_lowercase()))
}

/// 收集 PHP 文件中"非裸调用"形态的被调用名/定义名字节范围：
/// 方法调用（member_call_expression）、静态调用（scoped_call_expression）、
/// 构造调用（object_creation_expression）、函数/方法定义（function_definition /
/// method_declaration）。命中点落在这些名字范围内即不是内建函数裸调用
/// （`$pdo->exec(`、`Foo::exec(`、`new System()`、`function exec(`）。
/// 非 PHP 文件返回空表（即不做过滤）。
fn collect_php_non_bare_call_ranges(content: &str, extension: &str) -> Vec<(usize, usize)> {
    if extension != "php" && extension != "phtml" {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let lang: Language = tree_sitter_php::LANGUAGE_PHP.into();
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return ranges;
    }
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => return ranges,
    };
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        let name_node = match node.kind() {
            // $obj->method(：被调用方法名
            "member_call_expression" => node.child_by_field_name("name"),
            // Foo::method(：被调用方法名
            "scoped_call_expression" => node.child_by_field_name("name"),
            // new Foo(：类名（0.23 无 name 字段，取首个命名子节点）
            "object_creation_expression" => node.named_child(0),
            // function foo(/方法定义：定义名
            "function_definition" | "method_declaration" => node.child_by_field_name("name"),
            _ => None,
        };
        if let Some(n) = name_node {
            ranges.push((n.start_byte(), n.end_byte()));
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    ranges.sort_unstable();
    ranges
}

/// 判断字节偏移是否落在任一注释范围内（ranges 已排序）
fn position_in_ranges(ranges: &[(usize, usize)], pos: usize) -> bool {
    ranges
        .binary_search_by(|&(start, end)| {
            if pos < start {
                std::cmp::Ordering::Greater
            } else if pos >= end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sanitized_before_skips_when_sanitizer_precedes() {
        let content = "cookie.setSecure(true);\nresponse.addCookie(cookie);";
        let sanitizers = vec!["setSecure".to_string()];
        assert!(is_sanitized_before(content, content.len(), &sanitizers, false));
    }

    #[test]
    fn test_is_sanitized_before_no_skip_when_sanitizer_absent() {
        let content = "response.addCookie(cookie);";
        let sanitizers = vec!["setSecure".to_string()];
        assert!(!is_sanitized_before(content, content.len(), &sanitizers, false));
    }

    #[test]
    fn test_is_sanitized_before_match_all_requires_full_set() {
        // sanitizer_match=all：危险集合必须完整覆盖，缺任一即不豁免。
        // 场景：CVE-2021-42342——只过滤 LD_ 而缺 DYLD_/LDR_/_RLD/=() 视为防护不完整。
        let sanitizers: Vec<String> = ["LD_", "DYLD_", "LDR_", "_RLD", "=()"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let partial = "if (sstarts(vp, \"LD_\")) continue;  envp[n++] = sfmt(...);";
        assert!(
            !is_sanitized_before(partial, partial.len(), &sanitizers, true),
            "只覆盖 LD_ 子集：all 语义下不豁免"
        );
        let full = "sstarts(vp, \"LD_\"); sstarts(vp, \"LDR_\"); sstarts(vp, \"_RLD\"); sstarts(vp, \"DYLD_\"); strstr(vp, \"=()\");";
        assert!(
            is_sanitized_before(full, full.len(), &sanitizers, true),
            "全集覆盖：all 语义下豁免"
        );
        // any 语义保持旧行为：任一出现即豁免
        assert!(is_sanitized_before(partial, partial.len(), &sanitizers, false));
    }

    #[test]
    fn test_collect_comment_ranges_js() {
        let content = "var a = eval(x); // eval(y) 注释\n/* eval(z) 块注释 */\nvar b = eval(w);";
        let ranges = collect_comment_ranges(content, "js");
        // 行注释与块注释都被收集
        assert_eq!(ranges.len(), 2, "ranges: {:?}", ranges);
        // 代码位置的 eval 不在注释内
        let code_pos = content.find("eval(x)").unwrap();
        assert!(!position_in_ranges(&ranges, code_pos));
        let tail_pos = content.find("eval(w)").unwrap();
        assert!(!position_in_ranges(&ranges, tail_pos));
        // 注释内的 eval 在注释内
        let line_comment_pos = content.find("eval(y)").unwrap();
        assert!(position_in_ranges(&ranges, line_comment_pos));
        let block_comment_pos = content.find("eval(z)").unwrap();
        assert!(position_in_ranges(&ranges, block_comment_pos));
    }

    #[test]
    fn test_collect_comment_ranges_python() {
        let content = "exec(cmd)  # exec(other) 注释\n# 整行注释 exec(x)\nexec(cmd2)";
        let ranges = collect_comment_ranges(content, "py");
        assert_eq!(ranges.len(), 2, "ranges: {:?}", ranges);
        assert!(!position_in_ranges(&ranges, content.find("exec(cmd)").unwrap()));
        assert!(position_in_ranges(&ranges, content.find("exec(other)").unwrap()));
        assert!(position_in_ranges(&ranges, content.find("exec(x)").unwrap()));
        assert!(!position_in_ranges(&ranges, content.find("exec(cmd2)").unwrap()));
    }

    #[test]
    fn test_comment_ranges_unsupported_language() {
        let ranges = collect_comment_ranges("eval(x) // eval(y)", "txt");
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_likely_fp_const_args() {
        // 全字面量参数 → likely_fp（os.popen 硬编码命令场景）
        let content = r#"tmp = os.popen("netstat -anp |grep tcp").read()"#;
        let start = content.find("os.popen(").unwrap();
        let end = start + "os.popen(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_some());
    }

    #[test]
    fn test_likely_fp_printf_bounded_format() {
        // printf 族字面量格式串无 %s → likely_fp（json.c sprintf 场景）
        let content = r#"{  sprintf (error, "%d:%d: Expected , before %c", cur_line, e_off, b);"#;
        let start = content.find("sprintf (").unwrap();
        // 模拟规则命中区间（包含空格与左括号）
        let end = start + "sprintf (".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_some());
    }

    #[test]
    fn test_likely_fp_printf_percent_s_not_downgraded() {
        // 格式串含 %s → 不降权（可能写入任意长字符串）
        let content = r#"sprintf(dst, "%s", user)"#;
        let start = content.find("sprintf(").unwrap();
        let end = start + "sprintf(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_none());
    }

    #[test]
    fn test_likely_fp_variable_args_not_downgraded() {
        // 参数含变量 → 不降权（真实污点场景）
        let content = "result = exec(userInput)";
        let start = content.find("exec(").unwrap();
        let end = start + "exec(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_none());
    }

    #[test]
    fn test_placeholder_secret_detected() {
        // 占位符口令 → likely_fp（status-client.py USER_PASSWORD 场景）
        let content = r#"PASSWORD = "USER_PASSWORD""#;
        let rule = Rule {
            id: "no-hardcoded-passwords".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "all".to_string(),
            pattern: Some(r"(?i)password\s*=\s*\S+".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-259".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.py"), content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "info");
        assert!(findings[0]
            .reasoning_hint
            .as_deref()
            .unwrap_or("")
            .contains("likely_fp"));
    }

    #[test]
    fn test_real_password_not_downgraded() {
        // 真实弱口令保持原严重度（不降为 info）
        let content = r#"PASSWORD = "Xq9#kLz2$mP""#;
        let rule = Rule {
            id: "no-hardcoded-passwords".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "all".to_string(),
            pattern: Some(r"(?i)password\s*=\s*\S+".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-259".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.py"), content);
        assert_eq!(findings.len(), 1);
        assert_ne!(findings[0].severity, "info");
    }

    #[test]
    fn test_missing_check_rule_not_downgraded_by_literal_args() {
        // 缺失检查类规则（php-missing-csrf-token 场景）：命中点参数为字面量
        // 与可利用性无关——漏洞是"没有调用 token 校验"，不得降权为 info
        let content = r#"<?php
$source = Input::postStrVar('source', '');
$upsql = Input::postStrVar('upsql', '');
"#;
        let rule = Rule {
            id: "php-missing-csrf-token".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::Medium,
            language: "php".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "php".to_string(),
                pattern: r"\bInput::post[A-Za-z]*\s*\(".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-352".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let findings = scanner.scan_file_sync(&PathBuf::from("upgrade.php"), content);
        assert_eq!(findings.len(), 2);
        assert!(
            findings.iter().all(|f| f.severity != "info"),
            "缺失检查类规则不得因字面量参数降权为 info"
        );
    }

    #[test]
    fn test_sanitizer_file_scope_covers_whole_file() {
        // sanitizer_file_scope=true：校验调用在命中点之后（文件任意位置）也豁免；
        // 默认前缀语义则不豁免——emlog widgets.php（:139 才有 checkToken）场景
        let content = "<?php\n$a = $_POST['title'];\n// ...\nLoginAuth::checkToken();\n";
        let mk_rule = |file_scope: bool| Rule {
            id: "php-missing-csrf-token".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::Medium,
            language: "php".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "php".to_string(),
                pattern: r"\$_POST\s*\[".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-352".to_string()),
            sanitizers: vec!["checktoken(".to_string()],
            sanitizer_file_scope: file_scope,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let prefix_findings =
            RuleScanner::new(vec![mk_rule(false)]).scan_file_sync(&PathBuf::from("w.php"), content);
        assert_eq!(prefix_findings.len(), 1, "前缀语义下命中点在 checkToken 之前，不豁免");
        let file_findings =
            RuleScanner::new(vec![mk_rule(true)]).scan_file_sync(&PathBuf::from("w.php"), content);
        assert_eq!(file_findings.len(), 0, "文件级语义下全文件任一处 checkToken 即豁免");
    }

    #[test]
    fn test_sanitizer_after_lines_window() {
        // sanitizer_after_lines=N：命中点之后 N 行内出现 sanitizer 即豁免，
        // 且不受命中点之前文本影响（import/其他守卫不造成误豁免）。
        // CVE-2026-16088 场景：resolve 后紧跟 checkDirectoryTraversal 校验
        let guarded = "import static x.FileUtils.checkDirectoryTraversal;\nclass T {\n  void f() {\n    var p = root.resolve(name);\n    checkDirectoryTraversal(root, p);\n  }\n}\n";
        let unguarded = "import static x.FileUtils.checkDirectoryTraversal;\nclass T {\n  void f() {\n    var p = root.resolve(name);\n    return new FileSystemResource(p);\n  }\n}\n";
        let mk_rule = |after: usize| Rule {
            id: "path-traversal".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "java".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "java".to_string(),
                pattern: r"\.resolve\s*\(".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-22".to_string()),
            sanitizers: vec!["checkDirectoryTraversal(".to_string()],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: after,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        // 前缀语义：校验在命中点之后 → 守卫版也无法豁免（正是本字段要解决的问题）
        let prefix_guarded =
            RuleScanner::new(vec![mk_rule(0)]).scan_file_sync(&PathBuf::from("T.java"), guarded);
        assert_eq!(prefix_guarded.len(), 1, "前缀语义看不到命中点之后的校验");
        let prefix_unguarded =
            RuleScanner::new(vec![mk_rule(0)]).scan_file_sync(&PathBuf::from("T.java"), unguarded);
        assert_eq!(prefix_unguarded.len(), 1);
        // 后向窗口：守卫版豁免（校验在窗口内），未守卫版保留
        let win_guarded =
            RuleScanner::new(vec![mk_rule(2)]).scan_file_sync(&PathBuf::from("T.java"), guarded);
        assert_eq!(win_guarded.len(), 0, "校验在命中后 2 行内，豁免");
        let win_unguarded =
            RuleScanner::new(vec![mk_rule(2)]).scan_file_sync(&PathBuf::from("T.java"), unguarded);
        assert_eq!(win_unguarded.len(), 1, "窗口内无校验，保留命中");
    }

    #[test]
    fn test_sanitizer_before_lines_window() {
        // sanitizer_before_lines=N：命中点之前 N 行内出现 sanitizer 即豁免，
        // 覆盖"先净化后使用"形态（sanitize 在 sink 上一两行），
        // 且不受同文件远处文本影响（无界前缀语义会把远处 import/守卫误当净化）。
        // 真实修复形态：const sanitized = sanitize(name); path.join(dir, sanitized);
        let guarded = "const sanitize = require('x');\nfunction f(dir, name) {\n  const sanitized = sanitize(name);\n  return path.join(dir, sanitized);\n}\n";
        let unguarded = "const sanitize = require('x');\nfunction f(dir, name) {\n  return path.join(dir, name);\n}\n";
        let distant = "const y = sanitize(q);\n\n\n\n\n\n\nfunction f(dir, name) {\n  return path.join(dir, name);\n}\n";
        let mk_rule = |after: usize, before: usize| Rule {
            id: "path-traversal".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "javascript".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "javascript".to_string(),
                pattern: r"path\.join\s*\(".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-22".to_string()),
            sanitizers: vec!["sanitize(".to_string()],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: after,
            sanitizer_before_lines: before,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        // 仅后向窗口（现有语义）：净化在命中点之前 → 守卫版也不豁免
        let after_only =
            RuleScanner::new(vec![mk_rule(2, 0)]).scan_file_sync(&PathBuf::from("f.js"), guarded);
        assert_eq!(after_only.len(), 1, "后向窗口看不到命中点之前的净化");
        // 前向窗口：守卫版豁免（净化在窗口内），未守卫版保留
        let win_guarded =
            RuleScanner::new(vec![mk_rule(2, 2)]).scan_file_sync(&PathBuf::from("f.js"), guarded);
        assert_eq!(win_guarded.len(), 0, "净化在命中前 2 行内，豁免");
        let win_unguarded =
            RuleScanner::new(vec![mk_rule(2, 2)]).scan_file_sync(&PathBuf::from("f.js"), unguarded);
        assert_eq!(win_unguarded.len(), 1, "窗口内无净化，保留命中");
        // 远处净化（超出窗口）不误豁免——与无界前缀语义的关键区别
        let win_distant =
            RuleScanner::new(vec![mk_rule(2, 2)]).scan_file_sync(&PathBuf::from("f.js"), distant);
        assert_eq!(win_distant.len(), 1, "净化超出前向窗口，不误豁免");
    }

    #[test]
    fn test_deserialization_self_write_exempt() {
        // unsafe-deserialization 内外源区分：同文件命中点之前出现
        // ObjectOutputStream/writeObject（自产自销回环，如 Lucene 索引自写自读）
        // → 内部可信源，豁免；无自写逻辑 → 保留
        let guarded = "class T {\n  void save() { var o = new ObjectOutputStream(fos); o.writeObject(idx); }\n  Object load() { return new ObjectInputStream(fis).readObject(); }\n}\n";
        let unguarded = "class T {\n  Object load() { return new ObjectInputStream(req.getInputStream()).readObject(); }\n}\n";
        let rule = Rule {
            id: "unsafe-deserialization".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::Critical,
            language: "java".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "java".to_string(),
                pattern: r"ObjectInputStream\s*\(".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-502".to_string()),
            sanitizers: vec!["ObjectOutputStream".to_string(), "writeObject".to_string()],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let g = RuleScanner::new(vec![rule.clone()])
            .scan_file_sync(&PathBuf::from("T.java"), guarded);
        assert_eq!(g.len(), 0, "自写自读回环应豁免");
        let u = RuleScanner::new(vec![rule]).scan_file_sync(&PathBuf::from("T.java"), unguarded);
        assert_eq!(u.len(), 1, "外部输入反序列化应保留");
    }

    #[test]
    fn test_likely_fp_strcpy_literal_source() {
        // strcpy 源为字面量 → likely_fp（json.c e_alloc_failure 场景）
        let content = r#"strcpy (error, "Memory allocation failure");"#;
        let start = content.find("strcpy (").unwrap();
        let end = start + "strcpy (".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_some());
    }

    #[test]
    fn test_likely_fp_strcpy_variable_source_not_downgraded() {
        // strcpy 源为变量 → 不降权（可能溢出）
        let content = "strcpy(dst, user_input);";
        let start = content.find("strcpy(").unwrap();
        let end = start + "strcpy(".len();
        assert!(evaluate_likely_fp_args(content, start, end).is_none());
    }

    #[test]
    fn test_exclude_string_literals_skips_string_content() {
        // exclude_string_literals=true：字符串字面量内的 sink 名（如错误消息里的
        // "system()"）不报，真实调用仍报——sqlite3_rsync.c "popen() failed" 场景
        let mk_rule = |exclude: bool| Rule {
            id: "c-command-execution".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "c".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "c".to_string(),
                pattern: r"\b(system|popen)\s*\(".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-78".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: exclude,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let content = "if( (p=popen(cmd,\"r\"))==0 ){\n  fprintf(stderr,\"popen() failed\");\n}\n";
        let off_findings =
            RuleScanner::new(vec![mk_rule(false)]).scan_file_sync(&PathBuf::from("a.c"), content);
        assert_eq!(off_findings.len(), 2, "默认不排除字符串：真实调用 + 字符串内各 1 条");
        let on_findings =
            RuleScanner::new(vec![mk_rule(true)]).scan_file_sync(&PathBuf::from("a.c"), content);
        assert_eq!(on_findings.len(), 1, "开启后只保留真实调用");
        assert_eq!(on_findings[0].line_start, 1);
    }

    #[test]
    fn test_php_bare_call_only_drops_non_bare_call_forms() {
        // php_bare_call_only=true：$pdo->exec(、Foo::exec(、new System()、
        // function exec( 定义点全部丢弃；裸 exec( 调用保留——kanboard Schema
        // $pdo->exec 与 pagekit Connection::exec 定义点场景
        let mk_rule = |bare_only: bool| Rule {
            id: "command-injection".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::Critical,
            language: "php".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "php".to_string(),
                pattern: r"(?i)(?:^|[^\w])(?:system|exec)\s*\(".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-78".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: bare_only,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let content = concat!(
            "<?php\n",
            "class C { public function exec($s) { return parent::exec($s); } }\n",
            "$pdo->exec($sql);\n",
            "Foo::exec($cmd);\n",
            "$d = new System();\n",
            "exec($user_input);\n",
        );
        let off = RuleScanner::new(vec![mk_rule(false)])
            .scan_file_sync(&PathBuf::from("a.php"), content);
        assert!(off.len() >= 5, "默认不消歧：方法/静态/构造/定义/裸调用全报，实际 {}", off.len());
        let on = RuleScanner::new(vec![mk_rule(true)])
            .scan_file_sync(&PathBuf::from("a.php"), content);
        assert_eq!(on.len(), 1, "开启后只保留裸调用，实际 {:?}", on.iter().map(|f| f.line_start).collect::<Vec<_>>());
        // 行号为 5 的原因：命中含前缀换行符（(?:^|[^\w]) 消费了 \n），
        // 行号按命中起点计算——与生产 pattern 行为一致
        assert_eq!(on[0].line_start, 5, "保留的应是裸 exec($user_input)");
    }

    #[test]
    fn test_sizeof_deref_not_misread_as_multiplication() {
        // `sizeof *tmp`（无括号解引用）不得被分配器乘法 pattern 误报；
        // `n * sizeof(int)` 真实乘法仍应报——redis setproctitle.c 场景
        let rule = Rule {
            id: "cpp-integer-overflow".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "c".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "c".to_string(),
                pattern: r"(?i)(\bmalloc\s*\(\s*\w+\s*\*\s*\w+|\brealloc\s*\(\s*[^,]+,\s*\w+\s*\*\s*\w+)"
                    .to_string(),
            }]),
            query: None,
            cwe: Some("CWE-120".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let fp = scanner.scan_file_sync(
            &PathBuf::from("a.c"),
            "if (!(tmp = malloc(sizeof *tmp)))\n",
        );
        assert_eq!(fp.len(), 0, "sizeof *tmp 不得误报");
        let tp = scanner.scan_file_sync(&PathBuf::from("b.c"), "p = malloc(n * sizeof(int));\n");
        assert_eq!(tp.len(), 1, "n * sizeof(int) 真实乘法仍应报");
    }

    #[test]
    fn test_preproc_branch_downgraded_to_info() {
        // 条件编译平台分支内的命中降 info（thttpd #ifdef MPE gets() 场景），
        // 块外命中保持原级别
        let rule = Rule {
            id: "c-command-execution".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "c".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "c".to_string(),
                pattern: r"\b(system|popen)\s*\(".to_string(),
            }]),
            query: None,
            cwe: Some("CWE-78".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let content = "#ifdef MPE\nsystem(cmd1);\n#endif\nsystem(cmd2);\n";
        let findings = RuleScanner::new(vec![rule]).scan_file_sync(&PathBuf::from("a.c"), content);
        assert_eq!(findings.len(), 2);
        let inside = findings.iter().find(|f| f.line_start == 2).unwrap();
        let outside = findings.iter().find(|f| f.line_start == 4).unwrap();
        assert_eq!(inside.severity, "info", "条件编译块内应降 info");
        assert_eq!(outside.severity, "high", "块外保持原级别");
    }

    #[test]
    fn test_regex_rule_skips_commented_code() {        let rule = Rule {
            id: "test-eval".to_string(),
            name: "test".to_string(),
            description: "test".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "javascript".to_string(),
            pattern: Some(r"eval\s*\(".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-94".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let content = "// eval(commented)\nvar x = eval(active);\n/* eval(blocked) */";
        let findings = scanner.scan_file_sync(&PathBuf::from("a.js"), content);
        assert_eq!(findings.len(), 1, "只应命中未注释的 eval: {:?}", findings.iter().map(|f| f.line_start).collect::<Vec<_>>());
        assert_eq!(findings[0].line_start, 2);
    }

    /// 规则静默失败防线：所有嵌入规则的 pattern 必须能被 Rust regex 编译。
    /// Rust regex 不支持 lookaround（`(?<=`/`(?!`/`(?=`），历史上有 5 条规则
    /// 因此静默失效（eval/subprocess/yaml.load/硬编码密钥/CSRF），扫描照常进行
    /// 但召回缺失无任何告警。此测试把"pattern 无效"从启动日志升级为编译期失败。
    #[test]
    fn test_all_embedded_rule_patterns_compile() {
        let rules = crate::rules::embedded::load_embedded_pattern_rules();
        assert!(!rules.is_empty(), "嵌入规则加载为空");
        let mut invalid = Vec::new();
        for rule in &rules {
            if let Some(patterns) = &rule.patterns {
                for lp in patterns {
                    if regex::Regex::new(&lp.pattern).is_err() {
                        invalid.push(format!("{}({}): {}", rule.id, lp.language, lp.pattern));
                    }
                }
            }
            if let Some(pattern) = &rule.pattern {
                if regex::Regex::new(pattern).is_err() {
                    invalid.push(format!("{}: {}", rule.id, pattern));
                }
            }
        }
        assert!(invalid.is_empty(), "以下规则 pattern 无法编译:\n{}", invalid.join("\n"));
    }

    /// yaml.load 危险/安全形态判别（unsafe-deserialization 规则，archivy SafeLoader 场景回归）
    #[test]
    fn test_yaml_load_pattern_safeloader_excluded() {
        let rules = crate::rules::embedded::load_embedded_pattern_rules();
        let rule = rules
            .iter()
            .find(|r| r.id == "unsafe-deserialization")
            .expect("unsafe-deserialization 规则应存在");
        let py_pattern = rule
            .patterns
            .as_ref()
            .unwrap()
            .iter()
            .find(|lp| lp.language == "python")
            .unwrap();
        let re = regex::Regex::new(&py_pattern.pattern).unwrap();

        // 危险形态应命中
        assert!(re.is_match("data = yaml.load(user_input)"));
        assert!(re.is_match("yaml.load(stream, Loader=yaml.Loader)"));
        assert!(re.is_match("yaml.load(stream, Loader=UnsafeLoader)"));
        assert!(re.is_match("yaml.unsafe_load(payload)"));
        // 安全形态不命中（SafeLoader/CSafeLoader/BaseLoader + 显式 Loader 参数）
        assert!(!re.is_match("yaml.load(f.read(), Loader=yaml.SafeLoader)"));
        assert!(!re.is_match("yaml.load(text, Loader=yaml.CSafeLoader)"));
        assert!(!re.is_match("yaml.load(text, Loader=BaseLoader)"));
    }

    /// backlog 10.13：sanitizer_include_chain=true 时，bootstrap include 链中的
    /// 全局守卫文件（如统一校验 CSRF 的 security/csrf.php）参与豁免判定——
    /// projectsend 形态：页面 → bootstrap.php → includes/security/csrf.php。
    #[test]
    fn test_sanitizer_include_chain_global_guard() {
        let dir = std::env::temp_dir().join(format!("ctx_audit_1013_{}", std::process::id()));
        let sec = dir.join("includes").join("security");
        std::fs::create_dir_all(&sec).unwrap();
        std::fs::write(
            dir.join("bootstrap.php"),
            "<?php\nrequire_once ROOT_DIR . '/includes/security/csrf.php';\n",
        )
        .unwrap();
        std::fs::write(
            sec.join("csrf.php"),
            "<?php\nif (!defined('IS_INSTALL') && $_POST && !validateCsrfToken()) { exit; }\n",
        )
        .unwrap();
        let page = dir.join("users-add.php");
        let page_content = "<?php\nrequire_once 'bootstrap.php';\n$name = $_POST['name'];\n";
        std::fs::write(&page, page_content).unwrap();

        let mut rule = Rule {
            id: "php-missing-csrf-token".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::Medium,
            language: "php".to_string(),
            pattern: Some(r"\$_POST\s*\[".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-352".to_string()),
            sanitizers: vec!["validatecsrftoken(".to_string()],
            sanitizer_file_scope: true,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: true,
            exclude_string_literals: false,
            sanitizer_include_chain: true,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        };
        let scanner = RuleScanner::new(vec![rule.clone()]);
        let findings = scanner.scan_file_sync(&page, page_content);
        assert!(
            findings.is_empty(),
            "全局守卫文件含校验调用，页面应被豁免: {:?}",
            findings.len()
        );

        // 对照：同一文件不开 include_chain → 仍报告（证明豁免来自守卫链）
        rule.sanitizer_include_chain = false;
        let scanner = RuleScanner::new(vec![rule]);
        let findings = scanner.scan_file_sync(&page, page_content);
        assert_eq!(findings.len(), 1, "不开 include_chain 时应报告缺失校验");

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn mk_go_io_copy_rule(require_open: bool) -> Rule {
        Rule {
            id: "arbitrary-file-write".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "all".to_string(),
            pattern: None,
            patterns: Some(vec![crate::rules::model::LanguagePattern {
                language: "go".to_string(),
                pattern: r"(?i)(os\.Rename\s*\(|os\.WriteFile\s*\(|io\.Copy\s*\(|ioutil\.WriteFile\s*\()"
                    .to_string(),
            }]),
            query: None,
            cwe: Some("CWE-22".to_string()),
            sanitizers: vec![],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: require_open,
            auth_check_in_func: false,
            category: None,
            owasp: None,
            remediation: None,
            references: None,
        }
    }

    #[test]
    fn test_go_io_copy_kept_when_same_func_opens_user_file() {
        // 正例：同函数 os.Create(用户路径) + io.Copy —— 任意文件写入危险形态
        let content = r#"package main

func save(path string, r io.Reader) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	f.Close()
	return err
}
"#;
        let scanner = RuleScanner::new(vec![mk_go_io_copy_rule(true)]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.go"), content);
        assert_eq!(findings.len(), 1, "同函数文件打开+io.Copy 应保留");
        assert_eq!(findings[0].line_start, 8);
    }

    #[test]
    fn test_go_io_copy_kept_with_os_openfile_wrapper() {
        // 正例：*Os*OpenFile 命名包装（SafeOsOpenFile 形态）同样计入共现
        let content = r#"package main

func store(path string, r io.Reader) error {
	f, err := SafeOsOpenFile(path, os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		return err
	}
	if _, err = io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
"#;
        let scanner = RuleScanner::new(vec![mk_go_io_copy_rule(true)]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.go"), content);
        assert_eq!(findings.len(), 1, "包装打开调用也应计入共现");
    }

    #[test]
    fn test_go_io_copy_exempted_for_stream_copy() {
        // 负例：HTTP 响应流拷贝（无文件打开）——R46 filestash 误标主形态
        let content = r#"package main

func handler(w http.ResponseWriter, f *os.File) {
	io.Copy(w, f)
}
"#;
        let scanner = RuleScanner::new(vec![mk_go_io_copy_rule(true)]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.go"), content);
        assert!(
            findings.is_empty(),
            "流拷贝（无文件打开）应豁免，got {}",
            findings.len()
        );
    }

    #[test]
    fn test_go_io_copy_exempted_for_create_temp() {
        // 负例：os.CreateTemp 是良性临时文件，不计入共现
        let content = r#"package main

func extract(zipFile io.Reader) error {
	f, err := os.CreateTemp("", "tmpzip.*.zip")
	if err != nil {
		return err
	}
	_, err = io.Copy(f, zipFile)
	return err
}
"#;
        let scanner = RuleScanner::new(vec![mk_go_io_copy_rule(true)]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.go"), content);
        assert!(
            findings.is_empty(),
            "CreateTemp+io.Copy 应豁免，got {}",
            findings.len()
        );
    }

    #[test]
    fn test_go_io_copy_exempted_when_open_in_other_func() {
        // 负例：文件打开在另一函数（跨函数链），共现式不做函数间关联
        let content = r#"package main

func open(path string) (*os.File, error) {
	return os.Create(path)
}

func copyTo(f *os.File, r io.Reader) error {
	_, err := io.Copy(f, r)
	return err
}
"#;
        let scanner = RuleScanner::new(vec![mk_go_io_copy_rule(true)]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.go"), content);
        assert!(
            findings.is_empty(),
            "跨函数文件打开不应计入共现，got {}",
            findings.len()
        );
    }

    #[test]
    fn test_go_io_copy_flag_off_keeps_finding() {
        // 对照：规则字段关闭时保持旧行为（向后兼容）
        let content = r#"package main

func handler(w http.ResponseWriter, f *os.File) {
	io.Copy(w, f)
}
"#;
        let scanner = RuleScanner::new(vec![mk_go_io_copy_rule(false)]);
        let findings = scanner.scan_file_sync(&PathBuf::from("a.go"), content);
        assert_eq!(findings.len(), 1, "字段关闭时保持旧行为");
    }

    #[test]
    fn test_compile_rule_regex_inline_flags() {
        // Rust regex 支持 (?i)/(?m)/(?s) inline flag——compile_rule_regex 不应破坏它们
        let re = compile_rule_regex(r"(?m)^foo").expect("compile (?m)");
        assert!(re.is_match("abc\nfoo"));
        let re2 = compile_rule_regex(r"(?i)FOO").expect("compile (?i)");
        assert!(re2.is_match("foo"));
        let re3 = compile_rule_regex(r"(?s)a.b").expect("compile (?s)");
        assert!(re3.is_match("a\nb"));
        let re4 = compile_rule_regex(r"^func\s+").expect("compile plain");
        assert!(re4.is_match("func bar"));
    }

    #[test]
    fn test_missing_authorization_func_scope() {
        // 漏洞版：资源操作函数体内无授权关键字 → 应命中
        let vuln = r#"package main
func (s *Server) UpdateAccount(w http.ResponseWriter, r *http.Request) {
    var req accountRequest
    json.NewDecoder(r.Body).Decode(&req)
    s.db.UpdateAccount(req)
    w.WriteHeader(200)
}
"#;
        let rule = Rule {
            id: "go-missing-authorization".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "go".to_string(),
            pattern: Some(r"(?m)^\s*func\s+(?:\([^)]*\)\s+)?\w*(?:Get|Delete|Update|Remove|Find|Edit|Modify|GetById|DeleteById|UpdateById)\w*\s*\([^)]*\)\s*\{".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-862".to_string()),
            sanitizers: vec!["user_id".to_string(), "currentuser".to_string()],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: true,
            category: None,
            owasp: None,
            references: None,
            remediation: None,
        };
        let scanner = RuleScanner::new(vec![rule]);
        let findings = scanner.scan_file_sync(&PathBuf::from("vuln.go"), vuln);
        assert!(!findings.is_empty(), "vuln.go 应命中 missing-authorization");

        // 修复版：函数体内有 user_id 校验 → 应豁免
        let fixed = r#"package main
func (s *Server) UpdateAccountFixed(w http.ResponseWriter, r *http.Request) {
    userID := c.GetString("user_id")
    if userID == "" {
        http.Error(w, "unauthorized", 401)
        return
    }
    s.db.UpdateAccount(req)
    w.WriteHeader(200)
}
"#;
        let rule2 = Rule {
            id: "go-missing-authorization".to_string(),
            name: "t".to_string(),
            description: "t".to_string(),
            severity: crate::rules::model::Severity::High,
            language: "go".to_string(),
            pattern: Some(r"(?m)^\s*func\s+(?:\([^)]*\)\s+)?\w*(?:Get|Delete|Update|Remove|Find|Edit|Modify|GetById|DeleteById|UpdateById)\w*\s*\([^)]*\)\s*\{".to_string()),
            patterns: None,
            query: None,
            cwe: Some("CWE-862".to_string()),
            sanitizers: vec!["user_id".to_string(), "currentuser".to_string()],
            sanitizer_file_scope: false,
            sanitizer_match: SanitizerMatch::Any,
            once_per_file: false,
            exclude_string_literals: false,
            sanitizer_include_chain: false,
            php_bare_call_only: false,
            sanitizer_after_lines: 0,
            sanitizer_before_lines: 0,
            go_io_copy_requires_open_file: false,
            auth_check_in_func: true,
            category: None,
            owasp: None,
            references: None,
            remediation: None,
        };
        let scanner2 = RuleScanner::new(vec![rule2]);
        let findings2 = scanner2.scan_file_sync(&PathBuf::from("fixed.go"), fixed);
        assert!(findings2.is_empty(), "fixed.go 应豁免 missing-authorization");
    }
}

fn rule_matches_extension(language: &str, extension: &str) -> bool {
    match language.to_lowercase().as_str() {
        "python" => extension == "py",
        "javascript" | "typescript" => {
            ["js", "jsx", "ts", "tsx", "mjs", "cjs", "vue"].contains(&extension)
        }
        "rust" => extension == "rs",
        "go" => extension == "go",
        "java" => extension == "java",
        "c" => extension == "c" || extension == "h",
        "cpp" => ["cpp", "hpp", "cc", "cxx"].contains(&extension),
        "all" | "*" => true,
        _ => language.eq_ignore_ascii_case(extension),
    }
}
