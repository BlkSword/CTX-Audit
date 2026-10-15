// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 符号与代码事实查询：定义/引用/调用点、函数头与函数体边界、预处理与声明行、
//! dispatch 候选评分、函数摘要、标量参数与 callee 名提取。

use super::*;
/// 纯函数：定义行启发式。
pub fn find_definitions(content: &str, symbol: &str) -> Vec<(u32, String)> {
    let keywords = [
        "fn ", "def ", "func ", "function ", "class ", "struct ", "enum ", "interface ",
        "trait ", "const ", "type ", "module ", "namespace ", "object ",
    ];
    let mut hits = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains(symbol) && keywords.iter().any(|k| trimmed.contains(*k)) {
            hits.push(((idx + 1) as u32, trimmed.chars().take(200).collect()));
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    hits
}

// 行级代码段工具（去注释/字符串 + 标识符边界）统一放在 `text_scan`，此处重导出保持调用点不变。
// 实测依据：整行子串匹配让 `App` 命中 `_AppCtxGlobals`、`copy` 命中 `deepcopy`（引用精度 0.48）；
// 字符串/行内注释里的同名 token 是剩余误报来源（oracle 只计 NAME token）。
pub use crate::text_scan::{call_site_match, code_lines, contains_identifier, hash_comment_language};

/// 纯函数：引用行扫描（标识符边界 + **精确**排除该符号的真实定义行）。
///
/// 与旧 `find_references` 的两点差别（都有实测依据）：
/// - 旧实现整行子串匹配 → 真实仓库 precision 0.48；
/// - 旧实现用"这行看起来像定义"来排除定义行 → 会把恰好含 def 关键字的真实引用行也排掉（recall 0.73）。
///   现在由符号索引给出该符号的真实定义行，精确排除。
pub fn find_references_exact(
    original: &[&str],
    code: &[String],
    symbol: &str,
    def_lines: &std::collections::HashSet<u32>,
) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, code_line) in code.iter().enumerate() {
        let lineno = (idx + 1) as u32;
        if def_lines.contains(&lineno) {
            continue;
        }
        if !contains_identifier(code_line.trim(), symbol) {
            continue;
        }
        let text = original
            .get(idx)
            .map(|l| l.trim().chars().take(200).collect::<String>())
            .unwrap_or_default();
        hits.push((lineno, text));
    }
    hits
}

/// 纯函数：调用点扫描（**代码段**判定 + 左边界），返回 `(行号, 原文行)`。
///
/// 用代码段而非原文，避免字符串/注释里的 `name(` 被当成调用点。
pub fn find_call_sites_in_code(
    original: &[&str],
    code: &[String],
    name: &str,
    limit: usize,
) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, code_line) in code.iter().enumerate() {
        let trimmed = code_line.trim();
        if !call_site_match(trimmed, name) {
            continue;
        }
        let def_like = ["fn ", "def ", "func ", "function "]
            .iter()
            .any(|k| trimmed.contains(*k));
        if def_like {
            continue;
        }
        let text = original
            .get(idx)
            .map(|l| l.trim().chars().take(200).collect::<String>())
            .unwrap_or_default();
        hits.push(((idx + 1) as u32, text));
        if hits.len() >= limit {
            break;
        }
    }
    hits
}

/// 纯函数：引用行启发式（排除定义行）。
pub fn find_references(content: &str, symbol: &str) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.contains(symbol) {
            continue;
        }
        let is_def = !find_definitions(trimmed, symbol).is_empty();
        if !is_def {
            hits.push(((idx + 1) as u32, trimmed.chars().take(200).collect()));
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    hits
}

/// 纯函数：调用点启发式（`name(`，排除定义行）。
pub fn find_call_sites(content: &str, name: &str) -> Vec<(u32, String)> {
    let mut hits = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        // 左边界校验：`myread(` 不算 `read(` 的调用点
        if !call_site_match(trimmed, name) {
            continue;
        }
        let def_like = ["fn ", "def ", "func ", "function "]
            .iter()
            .any(|k| trimmed.contains(*k));
        if !def_like {
            hits.push(((idx + 1) as u32, trimmed.chars().take(200).collect()));
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    hits
}

/// 该文件是否用花括号界定函数体（决定 body_span 用配对括号还是缩进）
pub fn is_brace_language(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    !matches!(ext.as_str(), "py" | "rb" | "ex" | "exs" | "clj" | "lua")
}

pub(crate) fn indent_width(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').count()
}

/// 与最后一个 `)` 配对的 `(` 的位置（用于取出"名字("）。
pub(crate) fn matching_open_paren(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, ch) in s.char_indices().rev() {
        match ch {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// 判断一行是否像**函数头**，并尽力取出函数名（空串表示匿名）。
///
/// `next` 为**之后首个非空行**，用于识别 C/C++ 的多行签名
/// （`static ret_t` / `http_handler(...)` / `{` 分三行，名字行不以 `{` 结尾）。
///
/// 为什么需要它：符号索引的 `declared_names()` 只能从**关键字**形态抽取声明，而
/// ① JS/TS 极常见的是匿名函数表达式/箭头函数赋给属性或变量；
/// ② C/C++ 定义**根本没有关键字**（`static int foo(int a) {`）——
/// 这两类在索引里都没有声明，切片会退化成"无函数头的前缀窗口"。
///
/// 只做**行级**判断，不解析作用域；取不到名字时返回空串，由调用方用属性/变量名回填。
pub fn function_header_name_ctx(text: &str, next: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() || t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') {
        return None;
    }
    // `name: …` / `name = …` 左侧的最后一个标识符
    let lhs_name = |s: &str| -> Option<String> {
        let sep = s.find(':').into_iter().chain(s.find('=')).min()?;
        let lhs = s[..sep].trim();
        let name: String = lhs
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if name
            .chars()
            .next()
            .map(|c| c.is_alphabetic() || c == '_')
            .unwrap_or(false)
        {
            Some(name)
        } else {
            None
        }
    };
    for kw in ["function", "def", "func", "fn"] {
        let mut from = 0usize;
        while let Some(pos) = t[from..].find(kw) {
            let abs = from + pos;
            from = abs + kw.len();
            // 关键字前后都必须是标识符边界：`define(` 里的 `def`、`myfn(` 里的 `fn` 都不算
            let before_ok = abs == 0
                || !t[..abs]
                    .chars()
                    .next_back()
                    .map(|c| c.is_alphanumeric() || c == '_' || c == '$')
                    .unwrap_or(false);
            let tail = &t[abs + kw.len()..];
            let boundary_ok = tail
                .chars()
                .next()
                .map(|c| !(c.is_alphanumeric() || c == '_' || c == '$'))
                .unwrap_or(true);
            if !before_ok || !boundary_ok {
                continue;
            }
            // 关键字与 `(` 之间**可以没有空格**：`function(then) {` 是 JS 匿名函数的常见写法
            //（旧实现的关键字表带尾空格，因此漏掉它并把 `function` 当成了函数名）。
            let rest = tail.trim_start();
            let rest = rest.strip_prefix('*').unwrap_or(rest).trim_start(); // function* gen
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            let after = rest[name.len()..].trim_start();
            if !name.is_empty() && after.starts_with('(') {
                return Some(name);
            }
            if rest.starts_with('(') {
                return Some(lhs_name(t).unwrap_or_default()); // 匿名：回填属性/变量名
            }
        }
    }
    if t.contains("=>") {
        return Some(lhs_name(t).unwrap_or_default());
    }
    // C/C++ 风格定义（无关键字）：`类型 名字(参数)` 且该行以 `{` 结尾、
    // 或名字行以 `)` 结尾而下一非空行以 `{` 开头。
    // 控制语句与调用因此都不会命中：`if (a) {` 的动作名在排除表里，`foo(bar);` 不以 `{` 结尾。
    // 已知近似：C++ 构造函数的初始化列表（`Foo::Foo() : a(1) {`）会取到 `a` 而非 `Foo::Foo`。
    c_style_header_name(t, next)
}

/// 只走 **C/C++ 无关键字定义** 这一条分支：`类型 名字(参数) {`（签名可跨行）。
///
/// 单独成函数，是因为"向下拼接多行"的调用点**只能**用这条分支：关键字分支一旦看到被拼接
/// 进来的后续行，就会把后面某个 `def`/`function` 当成本行的签名——实测模块级
/// `_is_image_dataurl = re.compile(` 拼到后面的 `def _is_javascript_scheme(s):`，
/// 把模块级代码误报成"有函数作用域"（假改善会计进度量）。
pub(crate) fn c_style_header_name(text: &str, next: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let starts_block =
        t.ends_with('{') || (t.ends_with(')') && next.trim_start().starts_with('{'));
    if starts_block {
        let head_src = t.trim_end_matches('{').trim_end();
        if head_src.ends_with(')') {
            if let Some(open) = matching_open_paren(head_src) {
                let head = head_src[..open].trim_end();
                let name: String = head
                    .chars()
                    .rev()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let ctrl = matches!(
                    name.as_str(),
                    "if" | "for" | "while" | "switch" | "catch" | "do" | "else" | "return"
                        | "sizeof" | "synchronized" | "finally" | "try" | "using" | "lock"
                        | "foreach" | "with" | "when" | "assert" | "new" | "delete" | "throw"
                        | "function" | "def" | "func" | "fn"
                );
                if !name.is_empty() && !ctrl {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// 多行签名版：`following` 为**之后最多 6 条非空代码行**（已 trim 前）。
///
/// 为什么需要它：C/C++ 的签名经常跨 **3 行以上**（实测
/// 三行式定义：`static node_t *build_table(` / `parser_t *parser,` /
/// `… unsigned char *input, int len) {`），而两行判定要求"名字行以 `)` 结尾、下一行以 `{` 开头"，
/// 于是这类函数一律被判成"找不到函数头"，长函数的作用域因此静默变成 unresolved。
pub fn function_header_name_multi(text: &str, following: &[&str], c_like: bool) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    // 先按原两行规则判（覆盖绝大多数形态，且行为与既有测试一致）
    if let Some(n) = function_header_name_ctx(t, following.first().copied().unwrap_or("")) {
        return Some(n);
    }
    // 只有"签名尚未闭合"（圆括号不配对）时才允许向下拼接。
    // 否则会**跨语句**把后面某个函数声明当成当前行的签名续行：实测
    // `var x = require('y')` 后跟 `function f() {` 被拼成一个"函数头"，
    // 于是模块级代码被误报成有函数作用域（把假改善算进度量）。
    let mut depth = 0i32;
    for ch in t.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    if depth <= 0 {
        // K&R 风格：签名**已闭合**，但参数类型声明行在其后、`{` 更后：
        //     opt_request(esp, id, typenum, len, inp)
        //     OPT_STATE *esp;
        //     {
        // 只认"后续若干行是参数类型声明行、且其中出现 `{`"这一种情况，
        // 以免退回"跨语句拼接"的老毛病（那会把模块级代码误报成有函数作用域）。
        // 实测：真实 C 代码库里的边界检查省略正是这种风格。
        let mut kr = false;
        for s in following.iter().take(8) {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            if s.starts_with('{') {
                kr = true;
                break;
            }
            if crate::symbol_index::kr_param_line(s) {
                continue;
            }
            break;
        }
        if !kr || !c_like {
            return None;
        }
        return c_style_header_name(&format!("{t} {{"), "");
    }
    // 再把后续行拼进来：拼到出现 `{` 为止，最多 6 行（拼完仍未闭合则判定自然不成立）
    let mut joined = t.to_string();
    for s in following.iter().take(6) {
        let s = s.trim();
        if s.is_empty() {
            continue;
        }
        joined.push(' ');
        joined.push_str(s);
        if s.contains('{') {
            break;
        }
    }
    if joined != t {
        // 只认 C 风格：拼接结果必须形如 `类型 名字(…参数…) {`
        if let Some(n) = c_style_header_name(&joined, "") {
            return Some(n);
        }
    }
    None
}

/// 兼容无下一行信息的调用点。
pub fn function_header_name(text: &str) -> Option<String> {
    function_header_name_ctx(text, "")
}

/// 纯函数：估算某个定义所在函数的体范围（0-based，含首尾）。
///
/// - 花括号语言：从定义行的首个 `{` 起配对括号；
/// - 缩进语言（Python/Ruby/...）：取缩进大于定义行的后续行（空行不断开）；
/// - 找不到体时退化为定义行本身。
pub fn body_span(lines: &[&str], def_idx: usize, brace: bool) -> (usize, usize) {
    if def_idx >= lines.len() {
        return (def_idx, def_idx);
    }
    if brace {
        let mut depth: i32 = 0;
        let mut started = false;
        for (offset, line) in lines.iter().enumerate().skip(def_idx) {
            for ch in line.chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        started = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if started && depth <= 0 {
                return (def_idx, offset);
            }
            // 多行签名允许上溯若干行；超限则放弃
            if !started && offset > def_idx + 30 {
                break;
            }
        }
        (def_idx, def_idx)
    } else {
        // 先跳过"多行签名"：签名收尾行常从第 0 列开始（如 Python 的 `) -> T:`），
        // 若拿定义行缩进当基准会把函数体当 dedent 立即截断（实测导致切片漏函数头）。
        // 用括号平衡定位签名结束更稳。
        let mut depth: i32 = 0;
        let mut header_end = def_idx;
        for (offset, line) in lines.iter().enumerate().skip(def_idx) {
            for ch in line.chars() {
                match ch {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 {
                header_end = offset;
                break;
            }
        }
        let body_start = header_end + 1;
        // dedent 阈值仍取**定义行缩进**（外层缩进）；只是扫描从签名之后开始，
        // 这样多行签名的收尾行不会被误当成函数体结束。
        let outer = indent_width(lines[def_idx]);
        let mut end = header_end;
        for (idx, line) in lines.iter().enumerate().skip(body_start) {
            if line.trim().is_empty() {
                end = idx;
                continue;
            }
            if indent_width(line) <= outer {
                break;
            }
            end = idx;
        }
        (def_idx, end)
    }
}

/// 纯函数：抽取**命名导入**的别名对 `(被导入的符号名, 文件内本地名)`。
///
/// 只处理能被静态确定的形态：
/// - JS/TS：`import { a as b, c } from "..."`、`import Def, { a as b } from "..."`
/// - Python：`from x import a as b, c`
///
/// 默认导入（`import Store from ...`）与命名空间导入（`import * as ns`）不产生别名对
/// （本地名与导出名之间没有可静态推导的对应关系）。逐行解析，跨行的括号导入不支持。
pub fn import_aliases(content: &str) -> Vec<(String, String)> {
    fn is_ident(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    }

    let mut out: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        let clause: &str = if trimmed.starts_with("import") || trimmed.starts_with("export") {
            match (trimmed.find('{'), trimmed.find('}')) {
                (Some(s), Some(e)) if e > s => &trimmed[s + 1..e],
                _ => continue,
            }
        } else if trimmed.starts_with("from") {
            match trimmed.find("import") {
                Some(p) => trimmed[p + "import".len()..].trim(),
                None => continue,
            }
        } else {
            continue;
        };

        let clause = clause.trim().trim_start_matches('(').trim_end_matches(')');
        for item in clause.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let (imported, local) = match item.split_once(" as ") {
                Some((a, b)) => (a.trim(), b.trim()),
                None => (item, item),
            };
            if !is_ident(imported) || !is_ident(local) {
                continue;
            }
            out.push((imported.to_string(), local.to_string()));
        }
    }
    out
}

/// 纯函数：判断某行是否位于 `interface { ... }` 块内（Go/Java/TS 接口方法声明）。
///
/// 用于把"接口方法声明"从"调用点"里排除：`Read(p []byte) (int, error)` 会被
/// `name(` 匹配到，但它不是任何人的调用点（ground truth 上表现为 precision 0.5）。
pub fn in_interface_block(lines: &[&str], idx: usize) -> bool {
    if idx >= lines.len() {
        return false;
    }
    let mut depth: i32 = 0;
    let mut i = idx;
    loop {
        for ch in lines[i].chars().rev() {
            match ch {
                '}' => depth += 1,
                '{' => {
                    if depth == 0 {
                        return lines[i].contains("interface");
                    }
                    depth -= 1;
                }
                _ => {}
            }
        }
        if i == 0 {
            return false;
        }
        i -= 1;
    }
}

/// 文件的预处理视图：行级状态 + 可选的 `cpp -E` 真实分支求值。
///
/// `multi_file`（`get_dataflow_path` / `get_call_hierarchy` 这类要遍历整个项目的路径）默认**不**
/// 起子进程；单文件路径（切片、守卫）默认开。开关：`CTX_AUDIT_PREPROCESS=1` 全局开、`=0` 全局关。
/// 返回的 `Option<String>` 是**降级原因**（`cpp` 不可用/失败），必须带进响应，不得静默。
pub(crate) fn preproc_view(
    path: &str,
    content: &str,
    multi_file: bool,
) -> (Vec<crate::text_scan::PreprocLine>, Option<String>) {
    let mode = std::env::var("CTX_AUDIT_PREPROCESS").unwrap_or_default();
    let enable = match mode.trim() {
        "0" => false,
        "1" => true,
        _ => !multi_file,
    };
    crate::text_scan::preproc_line_states_with_cpp(path, content, enable)
}

/// 不该驱动"前向扩展 / 声明交付"的标识符：C/C++ 关键字与类型名。
/// （不把 `len`/`buf`/`src` 这类常见变量名放进来——它们恰恰是有用的驱动器；
/// 极短名如 `i`/`n` 由调用方的长度阈值过滤。）
pub(crate) fn is_stop_ident(ident: &str) -> bool {
    matches!(
        ident,
        "int" | "char"
            | "long"
            | "short"
            | "float"
            | "double"
            | "void"
            | "unsigned"
            | "signed"
            | "struct"
            | "union"
            | "enum"
            | "const"
            | "static"
            | "extern"
            | "return"
            | "sizeof"
            | "case"
            | "switch"
            | "while"
            | "for"
            | "else"
            | "goto"
            | "break"
            | "continue"
            | "default"
            | "typedef"
            | "register"
            | "volatile"
            | "inline"
            | "auto"
            | "if"
            | "do"
            | "new"
            | "delete"
            | "class"
            | "public"
            | "private"
            | "protected"
            | "namespace"
            | "template"
            | "typename"
            | "using"
            | "true"
            | "false"
            | "null"
            | "nullptr"
            | "defined"
            | "include"
            | "define"
    )
}

/// 找 `ident` 的**声明行**（最多 `max` 条，按文件顺序）。
///
/// 只认"类型… 名字[可选数组] ;"形态，避免把赋值/调用语句当成声明
/// （`row->n_columns = 0;` 不匹配：`-`/`>` 不在类型片段的字符集里）。
/// 同一字段名可能在多个结构体里声明（实测某 C 解析库的同名字段有 18/24 两处），
/// 因此返回多条，让判定者按上下文取舍——引擎只交付原文，不做推断。
pub(crate) fn find_declaration_lines(lines: &[&str], ident: &str, max: usize) -> Vec<usize> {
    let pattern = format!(
        r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)+[*\s]*{}\s*(?:\[[^\]]*\])?\s*;",
        regex::escape(ident)
    );
    let Ok(re) = regex::Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        if re.is_match(l) {
            out.push(i);
            if out.len() >= max {
                break;
            }
        }
    }
    out
}

/// C/C++ 源文件判定（调用图的 C 专用规则用）。
pub(crate) fn is_c_like_path(path: &str) -> bool {
    matches!(language_of(path), "c" | "c-header" | "cpp")
}

/// 结构性关键词：它们后面跟 `(` 但不是调用点。
///
/// 真实 Go 仓库实测依据：匿名函数字面量 `func(c *Config) {`、`go func() {`、`defer func() {`
/// 会让 `callee_names` 产出名为 `func`/`go`/`defer` 的"callee"，直接污染调用图精度。
pub(crate) const NON_CALL_KEYWORDS: &[&str] = &[
    "func", "if", "for", "switch", "select", "go", "defer", "range", "case", "default",
    "return", "struct", "interface", "map", "chan", "type", "var", "const", "else", "package",
    "import", "break", "continue", "goto", "fallthrough", "while", "catch", "elif", "except",
    "with", "lambda", "yield", "match", "when", "do", "then", "begin", "ensure", "rescue",
    // C/C++ 的**运算符与内建形式**：`sizeof(x)`、`_Alignof(int)`、`offsetof(...)` 长得像调用，
    // 实测会被当成 callee 混进调用图（C 语言台阶：真值比对时在抽样里直接看到 `sizeof`）。
    "sizeof", "_Alignof", "__alignof__", "__alignof", "alignof", "typeof", "__typeof__",
    "__typeof", "offsetof", "defined", "va_arg", "va_start", "va_end", "va_copy",
    "_Generic", "static_assert", "_Static_assert",
];

/// 纯函数：从一行里提取 `(` 前的标识符（取最后一个点后的名字），过滤结构性关键词。
/// 该行是否是**目标函数的定义头**（`… name(参数) {`）——用于非 C 语言的 callers 过滤。
///
/// 判据：名字后面的参数表闭合之后，本行只剩 `{`（Java/Go/Rust 的定义头），或本行到此为止
/// 且**下一非空行**以 `{` 开头（返回类型另一行的 C 风格）。像 `if (h.handle("x")) {` 这种
/// "调用出现在条件里"的行闭合括号之后还有内容 ⇒ 不算定义头；`h.handle("x")` 这种纯调用
/// 语句后面没有 `{` ⇒ 也不算。
pub(crate) fn looks_like_definition_header(text: &str, name: &str, next_is_brace: bool) -> bool {
    let t = text.trim();
    let t = match t.find("//") {
        Some(i) => t[..i].trim(),
        None => t,
    };
    if name.is_empty() || t.starts_with("if") || t.starts_with("for") || t.starts_with("while")
        || t.starts_with("switch") || t.starts_with("return") || t.starts_with("case")
    {
        return false;
    }
    let with_paren = format!("{}(", name);
    let open = match t.find(&with_paren) {
        Some(p) => p + with_paren.len() - 1,
        None => return false,
    };
    let mut depth = 0i32;
    for (i, ch) in t[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let rest = t[open + i + 1..].trim();
                    return rest == "{" || (rest.is_empty() && next_is_brace);
                }
            }
            _ => {}
        }
    }
    false
}

/// "看起来像本地配置/命令行来源"的标识符（token 精确匹配，或 `<head>_…` 前缀形态）。
pub(crate) const LOCAL_CONFIGURATION_IDENTIFIER_HEADS: [&str; 14] = [
    "argv", "argc", "getenv", "environ", "optarg", "optind", "getopt", "cfg", "conf", "config",
    "opts", "options", "settings", "prefs",
];

/// 同上，但按**子串**匹配的多词形态（这些词被标识符切分后仍是完整片段，但整串更明确）。
pub(crate) const LOCAL_CONFIGURATION_SUBSTRINGS: [&str; 10] = [
    "read_config",
    "load_config",
    "config_manager",
    "configmanager",
    "inifile",
    "parse_args",
    "parseargs",
    "command_line",
    "cmdline",
    "program_options",
];

/// 判断 source 侧文本是否**看起来**来自本地配置/命令行；返回命中的信号（空 = 未观测到）。
///
/// 文本同时取 `source` 参数本身与它命中的源码行（行文本信息量更大，例如 `char *p = argv[1];`）。
/// 这是**噪声标注而非结论**：命中只表示"该来源需要人工确认是否真的可由远端控制"；
/// 未命中**不代表**一定是远端可控输入。
pub fn local_configuration_signals(source: &str, source_line: Option<&str>) -> Vec<&'static str> {
    let mut texts: Vec<String> = vec![source.to_lowercase()];
    if let Some(line) = source_line {
        texts.push(line.to_lowercase());
    }
    let mut out: Vec<&'static str> = Vec::new();
    for text in &texts {
        let tokens = ident_tokens(text);
        for head in LOCAL_CONFIGURATION_IDENTIFIER_HEADS {
            let hit = tokens
                .iter()
                .any(|t| t == head || t.strip_prefix(head).map(|r| r.starts_with('_')).unwrap_or(false));
            if hit && !out.contains(&head) {
                out.push(head);
            }
        }
        for pat in LOCAL_CONFIGURATION_SUBSTRINGS {
            if text.contains(pat) && !out.contains(&pat) {
                out.push(pat);
            }
        }
    }
    out
}

pub fn callee_names(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(pos) = rest.find('(') {
        let before = &rest[..pos];
        let raw: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let name = raw.rsplit('.').next().unwrap_or("").to_string();
        if name.len() >= 2
            && !NON_CALL_KEYWORDS.contains(&name.as_str())
            && !out.contains(&name)
        {
            out.push(name);
        }
        rest = &rest[pos + 1..];
    }
    out
}

pub(crate) fn str_param(name: &str, desc: &str, required: bool) -> ToolParameter {
    ToolParameter {
        name: name.to_string(),
        param_type: ToolParameterType::String,
        description: desc.to_string(),
        required,
        default: None,
        enum_values: None,
        format: None,
        items: None,
        properties: None,
    }
}

pub(crate) fn int_param(name: &str, desc: &str, default: i64) -> ToolParameter {
    ToolParameter {
        name: name.to_string(),
        param_type: ToolParameterType::Integer,
        description: desc.to_string(),
        required: false,
        default: Some(json!(default)),
        enum_values: None,
        format: None,
        items: None,
        properties: None,
    }
}

pub(crate) fn bool_param(name: &str, desc: &str) -> ToolParameter {
    ToolParameter {
        name: name.to_string(),
        param_type: ToolParameterType::Boolean,
        description: desc.to_string(),
        required: false,
        default: Some(json!(false)),
        enum_values: None,
        format: None,
        items: None,
        properties: None,
    }
}

