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

/// 目标函数体内**解析不出目标**的调用点数量：函数指针派发 / 成员指针 / 表下标调用。
///
/// 这是 `unresolved_edges` 的 C 口径。旧的"整文件子串探测"只认脚本语言的动态派发关键字，
/// 于是 C 的 `p->handler(...)`、`(*fp)(...)`、`table[i](...)` 一条都不计，该字段在 C 上
/// 结构性恒 0 —— 等于对外宣称"调用图已闭合"。
///
/// 计数口径：逐行取三类模式出现次数的**最大值**，避免 `(*table[i])(x)` 这类重叠形态
/// 被重复计数。
pub fn count_indirect_call_sites(code_refs: &[&str], start: usize, end: usize) -> u32 {
    use std::sync::OnceLock;
    static MEMBER: OnceLock<regex::Regex> = OnceLock::new();
    static DEREF: OnceLock<regex::Regex> = OnceLock::new();
    static INDEX: OnceLock<regex::Regex> = OnceLock::new();
    static PAREN: OnceLock<regex::Regex> = OnceLock::new();

    let member = MEMBER.get_or_init(|| {
        regex::Regex::new(r"->\s*[A-Za-z_][A-Za-z0-9_]*\s*\(").unwrap()
    });
    let deref = DEREF.get_or_init(|| {
        regex::Regex::new(r"\(\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\(").unwrap()
    });
    let index = INDEX.get_or_init(|| {
        regex::Regex::new(r"[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]\n]*\]\s*\(").unwrap()
    });
    let paren = PAREN.get_or_init(|| {
        // 经函数指针成员的调用，形如 (a->ops.run)(a)：括号内以标识符或成员链结尾、
        // 无前导星号，也不呈现为 ->name( 的形态。此前三种模式都漏掉它，使大量使用该
        // 写法的 C 项目 unresolved_edges 结构性恒 0。
        regex::Regex::new(r"\(\s*[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)*\s*\)\s*\(").unwrap()
    });

    if code_refs.is_empty() || end < start {
        return 0;
    }
    let mut n = 0u32;
    for idx in start..=end.min(code_refs.len().saturating_sub(1)) {
        let text = code_refs.get(idx).copied().unwrap_or("");
        let per_line = member
            .find_iter(text)
            .count()
            .max(deref.find_iter(text).count())
            .max(index.find_iter(text).count())
            .max(paren.find_iter(text).count());
        n += per_line as u32;
    }
    n
}

// ─────────────────────────────────────────────────────────────────────────────
// C3 证据：按签名匹配的**派发候选目标集合**
//
// 当调用点解析不出目标（函数指针 / 成员指针 / 表下标派发）时，引擎能确定的事实只有
// "这里有一条解析不出的边 + 该调用点的实参形态"。本段把这份事实交付成一份**启发式候选
// 集合**：候选来自**已被索引的 C/C++ 定义**，按 `参数个数相等` 为前提、再用
// `实参表达式标识符 ↔ 形参名字` 与 `形参类型词 ↔ 实参文本` 的重叠度打分。
//
// 边界（必须守住）：
// - 只产出**证据**，不产出调用边：`unresolved_edges` 仍由 `count_indirect_call_sites`
//   独立计算，两者的口径互不影响；
// - 候选只是"签名像"，不是解析结果，字段级 `heuristic: true` + `reason` + `score` 如实标注；
// - 不做全量分析：站点只取目标函数体内（上限 `MAX_DISPATCH_SITES`），定义只枚举已索引的
//   C/C++ 定义（上限 `MAX_DISPATCH_SIGNATURE_SPACE`），成本可预期。
// ─────────────────────────────────────────────────────────────────────────────

/// 一个"解析不出目标"的调用点（与 `count_indirect_call_sites` 同源形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndirectCallSite {
    /// 1-based 行号
    pub line: u32,
    /// `member`（`p->f(`）/ `deref`（`(*fp)(`）/ `index`（`t[i](`）
    pub kind: &'static str,
    /// 调用形态原文（如 `table[idx]`、`o->run`、`(*fp)`）
    pub callee_text: String,
    /// 实参表达式列表；**参数表未在同一行闭合**时为 `None`（= 实参个数不可判定）
    pub args: Option<Vec<String>>,
}

/// 三类派发形态的正则（与 `count_indirect_call_sites` 保持同一套字面量；
/// 刻意各留一份 statics，避免动到已冻结的计数实现）。
pub(crate) fn dispatch_regex(kind: &str) -> &'static regex::Regex {
    use std::sync::OnceLock;
    static MEMBER: OnceLock<regex::Regex> = OnceLock::new();
    static DEREF: OnceLock<regex::Regex> = OnceLock::new();
    static INDEX: OnceLock<regex::Regex> = OnceLock::new();
    static PAREN: OnceLock<regex::Regex> = OnceLock::new();
    match kind {
        "member" => MEMBER.get_or_init(|| {
            regex::Regex::new(r"->\s*[A-Za-z_][A-Za-z0-9_]*\s*\(").unwrap()
        }),
        "deref" => DEREF.get_or_init(|| {
            regex::Regex::new(r"\(\s*\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\(").unwrap()
        }),
        _ => INDEX.get_or_init(|| {
            regex::Regex::new(r"[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]\n]*\]\s*\(").unwrap()
        }),
    }
}

/// 目标函数体内**解析不出目标**的调用点（含实参文本，供候选匹配）。
///
/// 行的取值口径与 `count_indirect_call_sites` 对齐：每行只取三类模式中**匹配最多的那一类**，
/// 因此站点数不超过该行对 `unresolved_edges` 的贡献；`unresolved_edges` 本身仍是那个已冻结的
/// 函数算出来的，两者独立。
pub fn indirect_call_sites(code_refs: &[&str], start: usize, end: usize) -> Vec<IndirectCallSite> {
    let mut out: Vec<IndirectCallSite> = Vec::new();
    if code_refs.is_empty() || end < start {
        return out;
    }
    for idx in start..=end.min(code_refs.len().saturating_sub(1)) {
        let text = code_refs.get(idx).copied().unwrap_or("");
        let member = dispatch_regex("member").find_iter(text).count();
        let deref = dispatch_regex("deref").find_iter(text).count();
        let index = dispatch_regex("index").find_iter(text).count();
        let best = member.max(deref).max(index);
        if best == 0 {
            continue;
        }
        let kind = if best == member {
            "member"
        } else if best == deref {
            "deref"
        } else {
            "index"
        };
        for m in dispatch_regex(kind).find_iter(text) {
            // 三类模式的匹配都以**调用参数表的左括号**结尾
            let open = m.end().saturating_sub(1);
            if !text.is_char_boundary(m.start()) || !text.is_char_boundary(open) {
                continue;
            }
            out.push(IndirectCallSite {
                line: (idx + 1) as u32,
                kind,
                callee_text: text[m.start()..open].trim().to_string(),
                args: call_args_at(text, open),
            });
        }
    }
    out
}

/// 从 `(` 的字节下标开始解析实参表；参数表未在本行闭合时返回 `None`。
pub(crate) fn call_args_at(text: &str, open: usize) -> Option<Vec<String>> {
    if !text.is_char_boundary(open) || !text[open..].starts_with('(') {
        return None;
    }
    let mut depth = 0i32;
    let mut start = open + 1;
    let mut args: Vec<String> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (off, ch) in text[open..].char_indices() {
        let i = open + off;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' => {
                depth -= 1;
                if depth <= 0 {
                    let seg = text[start..i].trim();
                    if !seg.is_empty() {
                        args.push(seg.to_string());
                    }
                    return Some(args);
                }
            }
            // 方括号/花括号只用于维持深度平衡；能闭合实参表的只有 `)`
            ']' | '}' => depth -= 1,
            ',' if depth == 1 => {
                args.push(text[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    None // 跨行实参表：实参个数不可判定
}

/// 表达式里的标识符 token（按出现顺序去重；纯数字与字面量天然被切开丢弃）。
pub(crate) fn ident_tokens(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in s.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
        if raw.is_empty() {
            continue;
        }
        if raw.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) {
            continue;
        }
        let t = raw.to_string();
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// source 模型去噪（只作用于 MCP 只读证据面）
//
// 背景：source→sink 路径里的 `source` 若其实来自**本进程的本地配置/命令行**
//（argv/getenv/配置文件/选项结构体），把它当作"远端可控输入"会让判定者高估可利用性。
// 这里只**加噪声标注**：在 `uncertainty.reasons` 里追加 `source_may_be_local_configuration`，
// 并在 `data.source_origin` 里给出命中的信号。不改变路径本身、不产出 findings。
// ─────────────────────────────────────────────────────────────────────────────

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

/// 一段声明文本里最后一个标识符（= 参数名 / 函数名）。
pub(crate) fn last_ident(s: &str) -> Option<String> {
    let mut cur = String::new();
    let mut last: Option<String> = None;
    for ch in s.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else {
            if !cur.is_empty() {
                last = Some(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        last = Some(cur);
    }
    last
}

/// 与 `open` 处的 `(` 配对的 `)` 的字节下标。
pub(crate) fn matching_close(s: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (off, ch) in s[open..].char_indices() {
        let i = open + off;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
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

/// 按顶层逗号切分参数表（括号/方括号/花括号内的逗号不算分隔符）。
pub(crate) fn split_top_level(inner: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, ch) in inner.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(inner[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(inner[start..].to_string());
    out
}

/// 从索引里的一条定义行文本解析 C/C++ 签名 → `(函数名, 形参文本, 是否变参)`。
///
/// 解析不出（无参数表 / 参数表跨行 / 函数指针声明 `(*fp)(…)` / `typedef` / 控制关键字）返回 `None`：
/// 这些形态的目标不是"可被索引到的函数定义"，列进候选只会污染证据。
pub(crate) fn parse_c_signature(text: &str) -> Option<(String, Vec<String>, bool)> {
    let s = text.trim();
    if s.is_empty() || s.starts_with("typedef") || s.starts_with('#') {
        return None;
    }
    let open = s.find('(')?;
    let close = matching_close(s, open)?;
    // `(*name)(params)`：函数指针**变量声明**，不是可调用定义
    if s[close..].trim_start().starts_with('(') {
        return None;
    }
    let name = last_ident(&s[..open])?;
    if NON_CALL_KEYWORDS.contains(&name.as_str()) {
        return None;
    }
    let inner = &s[open + 1..close];
    let mut params: Vec<String> = Vec::new();
    let mut variadic = false;
    for seg in split_top_level(inner) {
        let p = seg.trim();
        if p.is_empty() || (p == "void" && inner.trim() == "void") {
            continue;
        }
        if p == "..." {
            variadic = true;
            continue;
        }
        params.push(p.to_string());
    }
    Some((name, params, variadic))
}

/// 括号是否已闭合（`(`/`)` 计数；签名文本里出现字符串右括号的形态不影响判据的保守性）。
pub(crate) fn paren_balanced(s: &str) -> bool {
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth <= 0
}

/// 把**跨行签名**的定义行续成完整签名（返回 `(文本, 是否续过行)`）。
///
/// 索引里只存"定义行"原文；C 的 80 列风格常把形参表折到下一行（真实 C 代码库常见），
/// 只拿这一行就因括号不闭合而解析失败 ⇒ 候选空间被系统性偏向"单行签名"的函数
/// （实测：真实 C 代码库里真正的 writer 实现整批缺席，候选里只剩巧合同参数个数的无关函数）。
/// 这里用**已在内存里**的内容索引把后续行拼上（上限 `MAX_SIGNATURE_JOIN_LINES`），
/// 不额外读盘、不做全量分析；拼到上限仍不闭合就按解析失败处理（不猜）。
pub(crate) fn signature_with_continuation(
    text: &str,
    file: &str,
    line: u32,
    contents: &std::collections::HashMap<&str, &str>,
) -> (String, bool) {
    if paren_balanced(text) {
        return (text.to_string(), false);
    }
    let Some(content) = contents.get(file) else {
        return (text.to_string(), false);
    };
    let mut joined = text.to_string();
    for next in content
        .lines()
        .skip(line as usize)
        .take(MAX_SIGNATURE_JOIN_LINES)
    {
        joined.push(' ');
        joined.push_str(next.trim());
        if paren_balanced(&joined) {
            return (joined, true);
        }
    }
    (text.to_string(), false)
}

/// 已索引的 C/C++ 定义（签名解析成功的那部分）。
pub(crate) struct ParsedCDef {
    pub(crate) name: String,
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) text: String,
    pub(crate) params: Vec<String>,
    pub(crate) variadic: bool,
}

/// 调用点实参个数能否匹配形参表（变参函数只要实参数 ≥ 固定形参数）。
pub(crate) fn arity_matches(argc: usize, params: usize, variadic: bool) -> bool {
    if variadic {
        argc >= params
    } else {
        argc == params
    }
}

/// 签名近似打分（0.5 = 参数个数相等即得的基础分）：
/// `0.5 + 0.4 * 实参名↔形参名重叠率 + 0.1 * 形参类型词↔实参文本重叠率`。
pub(crate) fn score_signature_match(
    args: &[String],
    arg_tokens: &[String],
    def: &ParsedCDef,
) -> (f64, String, Vec<String>) {
    let param_names: Vec<String> = def
        .params
        .iter()
        .filter_map(|p| last_ident(p))
        .collect();
    let mut matched_names: Vec<String> = Vec::new();
    for tok in arg_tokens {
        if param_names.iter().any(|p| p == tok) && !matched_names.contains(tok) {
            matched_names.push(tok.clone());
        }
    }
    // 形参类型词（去掉形参名本身）+ 实参文本（只有显式转型之类才可能命中类型词）
    let arg_text = args.join(", ");
    let arg_text_tokens = ident_tokens(&arg_text);
    let mut type_tokens: Vec<String> = Vec::new();
    for p in &def.params {
        let pname = last_ident(p).unwrap_or_default();
        for tok in ident_tokens(p) {
            if tok == pname || type_tokens.contains(&tok) {
                continue;
            }
            type_tokens.push(tok);
        }
    }
    let type_hits = type_tokens
        .iter()
        .filter(|t| arg_text_tokens.iter().any(|a| a == *t))
        .count();
    let name_sim = if arg_tokens.is_empty() {
        0.0
    } else {
        matched_names.len() as f64 / arg_tokens.len() as f64
    };
    let type_sim = if type_tokens.is_empty() {
        0.0
    } else {
        type_hits as f64 / type_tokens.len() as f64
    };
    let score = ((0.5 + 0.4 * name_sim + 0.1 * type_sim) * 1000.0).round() / 1000.0;
    let reason = format!(
        "arity_match={}/{};argument_name_overlap={}/{};param_type_token_overlap={}/{}",
        args.len(),
        def.params.len(),
        matched_names.len(),
        arg_tokens.len(),
        type_hits,
        type_tokens.len()
    );
    (score, reason, matched_names)
}

/// C3 交付物：把"解析不出目标的调用点"变成**按签名匹配的候选目标集合**。
///
/// 候选必须来自**已被索引的 C/C++ 定义**（不重扫磁盘、不做 CPG/污点分析）。
/// `exclude` = 所在函数（派发的目标按定义是**别的**函数；含自身的候选只有一个固定假线索，
/// 且会占掉有界名额），命中失败时不影响其余候选。
/// `contents` = 本轮**已经在内存里**的内容索引，只用于把跨行签名的定义行续上
/// （见 `signature_with_continuation`）；不产生任何额外读盘。
pub fn dispatch_candidates_evidence(
    sindex: &crate::symbol_index::SymbolIndex,
    sites: &[IndirectCallSite],
    exclude: Option<&str>,
    contents: &[(String, String)],
) -> Value {
    let site_json: Vec<Value> = sites
        .iter()
        .map(|s| {
            json!({
                "line": s.line,
                "kind": s.kind,
                "callee_text": s.callee_text,
                "arity": s.args.as_ref().map(|a| a.len()),
            })
        })
        .collect();

    // 只有"实参个数可判定"的调用点能做签名匹配
    let usable: Vec<&IndirectCallSite> = sites.iter().filter(|s| s.args.is_some()).collect();

    let mut parsed: Vec<ParsedCDef> = Vec::new();
    let mut scanned = 0usize;
    let mut space_truncated = false;
    let mut joined_signatures = 0usize;
    if !usable.is_empty() {
        // 路径 → 文件文本：只服务"定义行签名跨行"的续行，不额外读盘
        let by_path: std::collections::HashMap<&str, &str> = contents
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        'scan: for file_idx in 0..sindex.file_count() {
            let rel = sindex.file_path(file_idx);
            if !is_c_like_path(rel) {
                continue;
            }
            for (name, line, text) in sindex.definitions_in_file(file_idx) {
                if scanned >= MAX_DISPATCH_SIGNATURE_SPACE {
                    space_truncated = true;
                    break 'scan;
                }
                scanned += 1;
                if Some(name.as_str()) == exclude {
                    continue; // 所在函数自身不是"派发目标"候选
                }
                let (sig_text, joined) = signature_with_continuation(&text, rel, line, &by_path);
                if joined {
                    joined_signatures += 1;
                }
                if let Some((pname, params, variadic)) = parse_c_signature(&sig_text) {
                    // 索引里的声明名与签名解析出的名字必须一致（避免把 `Type name(...)` 之类错认）
                    if pname == name {
                        parsed.push(ParsedCDef {
                            name,
                            file: rel.to_string(),
                            line,
                            text: sig_text,
                            params,
                            variadic,
                        });
                    }
                }
            }
        }
    }

    // 站点 × 候选：参数个数相等为前提，取每个候选名的最高分
    let mut best: std::collections::BTreeMap<String, (f64, u32, Vec<String>, usize, String)> =
        std::collections::BTreeMap::new();
    for site in &usable {
        let args = site.args.as_deref().unwrap_or(&[]);
        let arg_tokens = ident_tokens(&args.join(", "));
        for (idx, def) in parsed.iter().enumerate() {
            if !arity_matches(args.len(), def.params.len(), def.variadic) {
                continue;
            }
            let (score, reason, matched) = score_signature_match(args, &arg_tokens, def);
            let slot = best
                .entry(def.name.clone())
                .or_insert((score, site.line, matched.clone(), idx, reason.clone()));
            if score > slot.0 {
                *slot = (score, site.line, matched, idx, reason);
            }
        }
    }

    let mut ranked: Vec<(String, f64, u32, Vec<String>, usize, String)> = best
        .into_iter()
        .map(|(name, (score, line, matched, idx, reason))| (name, score, line, matched, idx, reason))
        .collect();
    ranked.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    let total_hits = ranked.len();
    let truncated_at_limit = total_hits > MAX_DISPATCH_CANDIDATES;
    let candidates: Vec<Value> = ranked
        .iter()
        .take(MAX_DISPATCH_CANDIDATES)
        .map(|(name, score, site_line, matched, idx, reason)| {
            let def = &parsed[*idx];
            json!({
                "name": name,
                "file": def.file,
                "line": def.line,
                "signature": def.text.trim().chars().take(200).collect::<String>(),
                "arity": def.params.len(),
                "variadic": def.variadic,
                "score": score,
                "reason": reason,
                "matched_argument_names": matched,
                "from_call_site_line": site_line,
            })
        })
        .collect();

    json!({
        "heuristic": true,
        "basis": "signature_match_over_indexed_c_definitions",
        "note": "signature-matched candidate targets for call sites whose target is unresolved \
                 (function-pointer / member-pointer / indexed-table dispatch); these are heuristic \
                 candidates, not resolved call edges, and they do not change unresolved_edges; the \
                 containing function itself is excluded",
        "call_sites": site_json,
        "call_sites_with_arity": usable.len(),
        "signature_space": {
            "scanned_indexed_c_definitions": scanned,
            "signatures_joined_from_continuation_lines": joined_signatures,
            "join_line_limit": MAX_SIGNATURE_JOIN_LINES,
            "limit": MAX_DISPATCH_SIGNATURE_SPACE,
            "truncated_at_limit": space_truncated,
        },
        "candidates": candidates,
        "limit": MAX_DISPATCH_CANDIDATES,
        "total_hits": total_hits,
        "truncated_at_limit": truncated_at_limit,
    })
}

/// **项目级**候选派发证据：把全项目 C/C++ 函数体里"解析不出目标"的调用点汇总后，
/// 复用 [`dispatch_candidates_evidence`]（与 MCP 证据面同一实现）产出签名候选集合。
///
/// 与 MCP 单函数口径的差异（必须如实标注，不能混为一谈）：
/// - 站点来源是**全项目已索引的 C 类函数体**，不是某一个目标函数，因此没有"所在函数"
///   可排除（`containing_function_excluded: false`）——某个站点可能把**自己所在的函数**
///   也列为候选之一，这是该口径的已知噪声；
/// - 站点数上限 [`MAX_PROJECT_DISPATCH_SITES`]，超出即截断并如实上报；
/// - 只读：不产出 findings、不写除 TTL 缓存以外的任何状态、不改变 `unresolved_edges`
///   的数值语义（与 MCP 面同一约定）。
///
/// 调用方（CLI）必须用 flag 门控——默认关闭时不调用本函数，历史输出因此逐字节不变。
pub fn project_dispatch_candidates(root: &Path, refresh: bool) -> Value {
    let ttl = crate::index_cache::default_ttl();
    let (index, hit) = crate::index_cache::get_or_build(root, refresh, ttl, || {
        let loaded = load_files(root);
        let build_id = build_id(&loaded.files);
        crate::index_cache::ProjectIndex {
            root: root.to_string_lossy().to_string(),
            files: loaded.files,
            build_id,
            skipped_large: loaded.skipped_large,
            truncated_at_limit: loaded.truncated_at_limit,
            file_stamps: loaded.file_stamps,
            dir_stamps: loaded.dir_stamps,
            built_at: std::time::Instant::now(),
        }
    });
    let files: &[(String, String)] = &index.files;
    let (sindex, s_hit, s_build_ms) = crate::symbol_index::get_or_build(root, refresh, None);

    // 站点采集：与调用图同一判据——只取 C 类文件**函数体内**的间接调用点。
    let mut sites: Vec<IndirectCallSite> = Vec::new();
    let mut site_files: Vec<String> = Vec::new();
    let mut files_with_sites = 0usize;
    let mut sites_truncated = false;
    'files: for (path, content) in files {
        if !is_c_like_path(path) {
            continue;
        }
        let Some(file_idx) = sindex.file_index(path) else {
            continue;
        };
        let code = code_lines(content, hash_comment_language(path));
        let refs: Vec<&str> = code.iter().map(|s| s.as_str()).collect();
        let brace = is_brace_language(path);
        let mut file_has_site = false;
        for (_, def_line, _) in sindex.definitions_in_file(file_idx) {
            let def_idx = (def_line as usize).saturating_sub(1);
            let (start, end) = body_span(&refs, def_idx, brace);
            for site in indirect_call_sites(&refs, start, end) {
                if sites.len() >= MAX_PROJECT_DISPATCH_SITES {
                    sites_truncated = true;
                    break 'files;
                }
                file_has_site = true;
                site_files.push(path.clone());
                sites.push(site);
            }
        }
        if file_has_site {
            files_with_sites += 1;
        }
    }

    let mut evidence = dispatch_candidates_evidence(&sindex, &sites, None, files);
    // 项目级口径必须带文件归属：`IndirectCallSite` 只带行号，而 `call_sites` 是按输入
    // 顺序 1:1 映射出来的，因此按序补 `file` 即可对齐（不改任何评分/候选逻辑）。
    if let Some(arr) = evidence
        .get_mut("call_sites")
        .and_then(|v| v.as_array_mut())
    {
        for (i, item) in arr.iter_mut().enumerate() {
            if let (Some(obj), Some(file)) = (item.as_object_mut(), site_files.get(i)) {
                obj.insert("file".to_string(), Value::String(file.clone()));
            }
        }
    }

    json!({
        "scope": "project",
        "containing_function_excluded": false,
        "root": root.to_string_lossy(),
        "files_indexed": files.len(),
        "files_with_indirect_sites": files_with_sites,
        "sites_collected": sites.len(),
        "sites_limit": MAX_PROJECT_DISPATCH_SITES,
        "sites_truncated_at_limit": sites_truncated,
        "index": {
            "hit": hit.as_str(),
            "truncated_at_limit": index.truncated_at_limit,
            "skipped_large_files": index.skipped_large,
        },
        "symbol_index": symbol_index_stats(&sindex, s_hit, s_build_ms),
        "evidence": evidence,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// C2 证据：轻量过程间摘要（`function_summaries`）
//
// **复用** CPG 侧已有的 `compute_summary_from_cpg`（不另写一套摘要逻辑）。原料与引擎扫描
// 管线同源：单函数 CPG（文本 CFG）+ 该函数体内的污点流 + 函数体文本 + sink 规则。
// 范围被钉死在**本次响应里出现的函数**上（目标函数 + 去重后的 callee 名），上限
// `MAX_FUNCTION_SUMMARIES`；每个文件只解析一次；单函数沿用扫描管线的函数级预算
// （`CTX_AUDIT_MAX_FUNC_NODES` / `CTX_AUDIT_MAX_FUNC_BRANCHES`，超预算直接标 skipped，
// 不做分析）。任何一环不可用都如实降级为 `available: false` + `reason`，
// **不为了填字段去做全量分析**——成本必须可预期。
// ─────────────────────────────────────────────────────────────────────────────

/// 函数级预算（与扫描管线同一套环境变量口径；0 = 关闭预算）。
pub(crate) fn function_budget() -> (usize, usize) {
    let read = |key: &str, default: usize| {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(default)
    };
    (
        read("CTX_AUDIT_MAX_FUNC_NODES", 180),
        read("CTX_AUDIT_MAX_FUNC_BRANCHES", 60),
    )
}

/// C2 交付物：对给定函数名列表（本次响应里出现的函数）产出有界的轻量摘要。
///
/// `param_to_return` = 参数是否（保守地）影响返回值；`param_to_sink` = 参数是否到达 sink；
/// 两者都带置信度与**作用域说明**：摘要只覆盖单函数体，缺席 ≠ 证明不存在。
/// 同步函数（内部不 await），因此 tree-sitter parser 这类非 Send 资源不会跨 await 存活。
pub(crate) fn function_summaries_evidence(
    root: &Path,
    sindex: &crate::symbol_index::SymbolIndex,
    names: &[String],
) -> Value {
    use deepaudit_core::analysis::{compute_summary_from_cpg, AstTaintAnalyzer, CPGBuilder};
    use deepaudit_core::ast_api::ASTParser;

    // 去重，保持传入顺序（目标函数在前、callee 依响应顺序在后）
    let mut ordered: Vec<String> = Vec::new();
    for n in names {
        let t = n.trim();
        if t.is_empty() || ordered.iter().any(|o| o == t) {
            continue;
        }
        ordered.push(t.to_string());
    }
    let total_hits = ordered.len();

    // 解析到**已索引的定义**（`definitions()` 已按路径排序 ⇒ 确定性）
    let resolved: Vec<Option<(String, u32)>> = ordered
        .iter()
        .map(|n| {
            sindex
                .definitions(n, 8)
                .into_iter()
                .next()
                .map(|h| (sindex.file_path(h.file).to_string(), h.line))
        })
        .collect();
    let resolved_in_index = resolved.iter().filter(|r| r.is_some()).count();

    let (max_nodes, max_branches) = function_budget();
    // 每个文件只解析一次
    let mut parsed_files: std::collections::HashMap<
        String,
        Option<(
            Vec<deepaudit_core::ast_api::FunctionBody>,
            Vec<deepaudit_core::ast_api::Assignment>,
            Vec<deepaudit_core::ast_api::CallInfo>,
        )>,
    > = std::collections::HashMap::new();
    // 污点规则只加载一次（进程内），不在每次调用里重读规则文件
    static ANALYZER: std::sync::OnceLock<AstTaintAnalyzer> = std::sync::OnceLock::new();

    let mut entries: Vec<Value> = Vec::new();
    let mut available_summaries = 0usize;

    for (idx, name) in ordered.iter().enumerate().take(MAX_FUNCTION_SUMMARIES) {
        let Some((file, line)) = resolved.get(idx).cloned().flatten() else {
            entries.push(json!({
                "func": name,
                "available": false,
                "reason": "no_definition_in_index",
            }));
            continue;
        };
        let parsed = parsed_files.entry(file.clone()).or_insert_with(|| {
            let content = std::fs::read_to_string(root.join(&file)).ok()?;
            let mut parser = ASTParser::new();
            let (bodies, assignments, calls) =
                parser.extract_all_for_taint(&root.join(&file), &content);
            Some((bodies, assignments, calls))
        });
        let Some((bodies, assignments, calls)) = parsed else {
            entries.push(json!({
                "func": name,
                "file": file,
                "line": line,
                "available": false,
                "reason": "file_unreadable_or_unparsable",
            }));
            continue;
        };
        // 定义行落在函数体范围内优先；否则退化为同名函数
        let body = bodies
            .iter()
            .find(|b| {
                &b.name == name && (b.start_line as u32) <= line && line <= b.end_line as u32
            })
            .or_else(|| bodies.iter().find(|b| &b.name == name));
        let Some(body) = body else {
            entries.push(json!({
                "func": name,
                "file": file,
                "line": line,
                "available": false,
                "reason": "function_body_not_extracted",
            }));
            continue;
        };

        let func_assignments: Vec<_> = assignments
            .iter()
            .filter(|a| a.line >= body.start_line && a.line <= body.end_line)
            .cloned()
            .collect();
        let func_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.line >= body.start_line && c.line <= body.end_line)
            .cloned()
            .collect();
        let cpg = CPGBuilder::build_function_cpg_from_text(
            &body.body_text,
            &file,
            body,
            &func_assignments,
            &func_calls,
        );
        // 函数级预算：超预算不做污点分析（与扫描管线同一口径，成本可预期）
        let cfg_nodes = cpg.cfg.nodes.len();
        let branches = cpg
            .cfg
            .nodes
            .iter()
            .filter(|n| n.successors.len() >= 2)
            .count();
        if (max_nodes > 0 && cfg_nodes > max_nodes) || (max_branches > 0 && branches > max_branches)
        {
            entries.push(json!({
                "func": name,
                "file": file,
                "line": line,
                "available": false,
                "reason": "over_function_budget",
                "cfg_nodes": cfg_nodes,
                "branches": branches,
                "budget": {"max_nodes": max_nodes, "max_branches": max_branches},
            }));
            continue;
        }

        let analyzer = ANALYZER.get_or_init(AstTaintAnalyzer::new);
        let flows = analyzer.analyze_function_cpg(&cpg, &body.body_text, &[]);
        let summary = compute_summary_from_cpg(&cpg, &flows, &body.body_text, analyzer.sinks());

        // 参数下标 → 参数名。CPG 的 `signature.params` 就是 `body.typed_params`（下标一一对应），
        // 退化时用 `body.params`；两者都没有就如实给 null（不编名字）。
        let param_name_at = |idx: usize| -> Value {
            body.typed_params
                .get(idx)
                .map(|p| p.name.clone())
                .or_else(|| body.params.get(idx).cloned())
                .map(Value::String)
                .unwrap_or(Value::Null)
        };
        let param_to_return: Vec<Value> = summary
            .taint_propagation
            .iter()
            .map(|(param, reaches)| {
                json!({
                    "param": param,
                    "param_name": param_name_at(*param),
                    "reaches_return": reaches,
                    // 「参数存在单文件污点流 ⇒ 可能影响返回值」是**保守上界**，不是精确定论
                    "confidence": 0.4,
                })
            })
            .collect();
        let param_to_sink: Vec<Value> = summary
            .direct_sinks
            .iter()
            .map(|ds| {
                json!({
                    "param": ds.from_param,
                    "param_name": param_name_at(ds.from_param),
                    "sink": ds.sink_name,
                    "sink_line": ds.sink_line,
                    "sanitized": ds.sanitized,
                    "sanitizer": ds.sanitizer,
                    "vuln_type": serde_json::to_value(&ds.vuln_type).unwrap_or(Value::Null),
                    "confidence": if ds.sanitized { 0.3 } else { 0.6 },
                })
            })
            .collect();
        let param_to_calls: Vec<Value> = summary
            .param_to_calls
            .iter()
            .take(MAX_FUNCTION_SUMMARIES)
            .map(|p| {
                json!({
                    "param": p.param_idx,
                    "callee": p.callee,
                    "arg_idx": p.arg_idx,
                    "line": p.call_line,
                })
            })
            .collect();
        available_summaries += 1;
        entries.push(json!({
            "func": name,
            "file": file,
            "line": line,
            "params": body.typed_params.len().max(body.params.len()),
            "available": true,
            "param_to_return": param_to_return,
            "param_to_sink": param_to_sink,
            "param_to_calls": param_to_calls,
            "taint_flows": flows.len(),
            "basis": "compute_summary_from_cpg(cpg + single-function taint flows)",
            "scope": "single function body only; absence means no flow found in this scope, not proof of absence",
        }));
    }

    // 依赖（CPG / 单函数污点）不可用时**不填假摘要**：字段仍在，但 `available: false` + `reason`。
    // `available_summaries == 0` 的三种真实成因都写在 reason 里（无索引定义 / 函数体抽不出 /
    // 超函数级预算），逐条原因在 `summaries[]` 的 `reason` 上，这里给的是字段级汇总。
    let field_level_reason: Value = if available_summaries > 0 {
        Value::Null
    } else {
        json!(
            "no_function_summary_computed: no indexed definition in scope, or the function body \
             could not be extracted, or it exceeded the function-level budget"
        )
    };
    json!({
        "method": "compute_summary_from_cpg",
        "scope": "queried function + distinct returned callee names, in response order",
        "available": available_summaries > 0,
        "reason": field_level_reason,
        "considered": total_hits,
        "resolved_in_index": resolved_in_index,
        "available_summaries": available_summaries,
        "budget": {"max_cfg_nodes": max_nodes, "max_branches": max_branches},
        "limit": MAX_FUNCTION_SUMMARIES,
        "total_hits": total_hits,
        "truncated_at_limit": total_hits > MAX_FUNCTION_SUMMARIES,
        "summaries": entries,
    })
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

