// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 行级"代码段"扫描工具：去掉注释与字符串字面量后再做符号判定。
//!
//! 实测依据（真实仓库 + CPython `ast`/`tokenize` 独立 oracle）：引用误报里剩下的那一成
//! 来自**字符串字面量与行内注释里的同名标识符**——oracle 只计 NAME token，按行匹配会命中它们。

/// 一行在条件编译里的处境。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PreprocLine {
    /// **可证死**：位于 `#if 0` 分支（且之前的兄弟分支都没有可证为真的条件）里。
    pub dead: bool,
    /// 位于任意条件编译区内（含**无法判定**的 `#ifdef X` / `#if defined(X)` / `#if VERSION >= N`）。
    pub conditional: bool,
}

#[derive(Debug, Clone, Copy)]
struct PreprocFrame {
    /// 该层是否已有可证为真的兄弟分支
    seen_live: bool,
    /// 当前分支是否可证死
    cur_dead: bool,
}

/// 逐行的条件编译状态（**行级、保守**，不依赖树解析）。
///
/// 只把**能证明为假**的分支标成 `dead`：`#if 0`，以及 `#elif 0`（当上面没有可证为真的分支时）。
/// `#ifdef X`／`#if defined(X)`／版本比较一律**不判死**，只标 `conditional` ——
/// 我们不知道编译配置，就不能假装这段代码不存在。`#else` 视为活跃（保守）。
///
/// 用途：C4 的"活代码视图"缺口在**证据层**（符号索引 / 切片），不在规则扫描层——
/// 规则层早已用 tree-sitter 收集条件编译区间做严重度降权，而索引/切片此前完全没有感知，
/// 于是 `#if 0` 里的函数会被当成真实定义。
pub fn preproc_line_states(content: &str) -> Vec<PreprocLine> {
    let mut out: Vec<PreprocLine> = Vec::with_capacity(content.lines().count());
    let mut stack: Vec<PreprocFrame> = Vec::new();

    for line in content.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix('#') {
            let rest = rest.trim_start();
            let word: String = rest.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            let arg = rest[word.len()..].trim();
            match word.as_str() {
                "if" | "ifdef" | "ifndef" => {
                    let dead = word == "if" && arg == "0";
                    stack.push(PreprocFrame { seen_live: !dead, cur_dead: dead });
                }
                "elif" => {
                    if let Some(top) = stack.last_mut() {
                        let dead = arg == "0";
                        if !top.cur_dead {
                            top.seen_live = true;
                        }
                        top.cur_dead = dead && !top.seen_live;
                    }
                }
                "else" => {
                    // 保守：`#else` 分支一律**视为可编译**（`#if 0 / #else` 时它确实就是活的那支；
                    // `#if 1 / #else` 时我们只是不敢判死，方向安全）。
                    if let Some(top) = stack.last_mut() {
                        top.cur_dead = false;
                        top.seen_live = true;
                    }
                }
                "endif" => {
                    stack.pop();
                }
                _ => {}
            }
        }
        out.push(PreprocLine {
            dead: stack.iter().any(|f| f.cur_dead),
            conditional: !stack.is_empty(),
        });
    }
    out
}

/// 该语言的 `#` 是否为行注释（Python/Ruby/Shell/Perl/YAML 家族）
pub fn hash_comment_language(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "py" | "rb" | "sh" | "bash" | "pl" | "pm" | "yaml" | "yml" | "toml" | "r" | "ex" | "exs"
    )
}

/// 逐行抽出"代码段"：去掉注释与字符串字面量内容，保留其余字符，**行数不变**。
///
/// 粗粒度但方向正确。覆盖：
/// - 行注释：`#`（`hash_comment` 语言）/ `//`；
/// - 块注释：`/* ... */`（可跨行）；
/// - 字符串：`'`、`"`、`` ` ``（可跨行，含 JS 模板串/Go 原串）；Python 三引号 `"""`/`'''`；
/// - `\` 转义跳过下一个字符。
pub fn code_lines(content: &str, hash_comment: bool) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(content.lines().count());
    let mut block = false;
    let mut triple: Option<&'static str> = None;
    let mut quote: Option<char> = None;

    for line in content.lines() {
        let mut kept = String::new();
        let mut i = 0usize;
        while i < line.len() {
            let rest = &line[i..];

            if block {
                match rest.find("*/") {
                    Some(p) => {
                        i += p + 2;
                        block = false;
                    }
                    None => i = line.len(),
                }
                continue;
            }
            if let Some(t) = triple {
                match rest.find(t) {
                    Some(p) => {
                        i += p + t.len();
                        triple = None;
                    }
                    None => i = line.len(),
                }
                continue;
            }
            if let Some(q) = quote {
                if rest.starts_with('\\') {
                    let step = rest[1..].chars().next().map(|c| c.len_utf8()).unwrap_or(0);
                    i += 1 + step;
                    continue;
                }
                if rest.starts_with(q) {
                    i += q.len_utf8();
                    quote = None;
                    continue;
                }
                i += rest.chars().next().map(|c| c.len_utf8()).unwrap_or(1);
                continue;
            }

            if rest.starts_with("/*") {
                block = true;
                i += 2;
                continue;
            }
            if hash_comment && rest.starts_with('#') {
                break;
            }
            if !hash_comment && rest.starts_with("//") {
                break;
            }
            if rest.starts_with("\"\"\"") {
                triple = Some("\"\"\"");
                i += 3;
                continue;
            }
            if rest.starts_with("'''") {
                triple = Some("'''");
                i += 3;
                continue;
            }
            let ch = rest.chars().next().unwrap_or(' ');
            if ch == '"' || ch == '\'' {
                // 单/双引号必须**在本行内闭合**，否则按普通字符处理。
                //
                // 依据：本引擎支持的语言里 `'…'` 与 `"…"` 都不能跨原始换行；而 Rust 的
                // 生命周期（`&'static str`）是**单个未配对**的 `'`。旧实现把后者当成
                // 字符串开引号，且 `quote` 状态跨行存活 → 后续整行被当作字符串内容清空，
                // 声明、引用与调用点成片丢失（实测 `core/src/scanner/mod.rs` 的函数定义
                // 因此进不了符号索引，见下方回归测试）。
                //
                // 同类触发形态：JS 正则字面量里的单个引号（`/'/g`）、任何来源的落单撇号。
                //
                // 取舍（如实记录）：PHP/Ruby 的多行 `'…'` 与 `\` 续行字符串会因此把串体
                // 当代码（少数语言、少数形态）；换来的是"落单引号不再污染整个文件"——
                // 实测本仓符号定义 2567→3323（+29%）、标识符出现 187038→247919（+33%）。
                let mut it = rest.chars();
                it.next(); // 跳过开引号本身
                let mut closes_here = false;
                while let Some(c) = it.next() {
                    if c == '\\' {
                        it.next();
                        continue;
                    }
                    if c == ch {
                        closes_here = true;
                        break;
                    }
                }
                if closes_here {
                    quote = Some(ch);
                } else {
                    kept.push(ch);
                }
                i += ch.len_utf8();
                continue;
            }
            // 反引号（JS/TS 模板串）允许跨行，保持旧语义
            if ch == '`' {
                quote = Some(ch);
                i += ch.len_utf8();
                continue;
            }
            kept.push(ch);
            i += ch.len_utf8();
        }
        // 防御：`'`/`"` 不跨行（反引号模板串与 Python 三引号允许跨行）
        if matches!(quote, Some('\'') | Some('"')) {
            quote = None;
        }
        out.push(kept);
    }
    out
}

/// 该行里出现的标识符（`[A-Za-z0-9_$]` 连续段；纯数字段丢弃）
pub fn identifiers_in_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in line.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '$' {
            cur.push(ch);
        } else if !cur.is_empty() {
            if !cur.chars().all(|c| c.is_ascii_digit()) {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if !cur.is_empty() && !cur.chars().all(|c| c.is_ascii_digit()) {
        out.push(cur);
    }
    out
}

/// `symbol` 是否作为**独立标识符**出现在该行（两侧不是标识符字符）。
///
/// 真实仓库实测依据：整行子串匹配让 `App` 命中 `_AppCtxGlobals`、`copy` 命中 `deepcopy`。
/// 带点/其它符号的查询退化为子串匹配（保持旧语义）。
pub fn contains_identifier(line: &str, symbol: &str) -> bool {
    if symbol.is_empty() {
        return false;
    }
    if !symbol
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    {
        return line.contains(symbol);
    }
    let chars: Vec<char> = line.chars().collect();
    let sym: Vec<char> = symbol.chars().collect();
    let is_ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    if sym.len() > chars.len() {
        return false;
    }
    for i in 0..=(chars.len() - sym.len()) {
        if chars[i..i + sym.len()] == sym[..] {
            let before_ok = i == 0 || !is_ident(chars[i - 1]);
            let after_ok = i + sym.len() == chars.len() || !is_ident(chars[i + sym.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// 该行是否有 `name(` 形态的调用点，且 `name` 左侧不是标识符字符
///（否则 `myread(` 会被当成 `read(` 的调用点）。
pub fn call_site_match(line: &str, name: &str) -> bool {
    let needle = format!("{name}(");
    let is_ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    let mut from = 0usize;
    while let Some(pos) = line[from..].find(&needle) {
        let abs = from + pos;
        let before_ok = abs == 0
            || !line[..abs]
                .chars()
                .next_back()
                .map(is_ident)
                .unwrap_or(false);
        if before_ok {
            return true;
        }
        from = abs + needle.len();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preproc_line_states_dead_and_conditional() {
        let src = "#if 0\nint dead_only (void) { return 1; }\n#else\nint live_in_else (void) { return 2; }\n#endif\n\n#ifdef FEATURE_X\nint maybe (void) { return 3; }\n#endif\n\nint always (void) { return 4; }\n";
        let st = preproc_line_states(src);
        assert!(st[1].dead, "`#if 0` 分支必须判死: {:?}", st[1]);
        assert!(st[1].conditional);
        assert!(!st[2].dead, "`#else` 行本身是活的: {:?}", st[2]);
        assert!(!st[3].dead, "`#else` 之后的分支是活的: {:?}", st[3]);
        assert!(
            !st[4].dead && !st[4].conditional,
            "`#endif` 之后不在条件区内: {:?}",
            st[4]
        );
        // `#ifdef X` 无法判定 ⇒ 只标 conditional，绝不判死
        assert!(!st[6].dead && st[6].conditional, "{:?}", st[6]);
        assert!(!st[7].dead && st[7].conditional, "`#ifdef X` 不能判死: {:?}", st[7]);
        assert!(!st[10].dead && !st[10].conditional, "{:?}", st[10]);
    }

    #[test]
    fn test_preproc_line_states_elif_after_dead_branch() {
        // `#if 0 / #elif 1` ⇒ elif 分支是活的；`#if 0 / #elif 0` ⇒ 仍判死
        let live = preproc_line_states("#if 0\nA\n#elif 1\nB\n#endif\n");
        assert!(live[1].dead);
        assert!(!live[3].dead, "`#elif 1` 分支必须判活: {:?}", live[3]);
        let dead = preproc_line_states("#if 0\nA\n#elif 0\nB\n#endif\n");
        assert!(dead[3].dead, "`#elif 0` 分支必须判死: {:?}", dead[3]);
    }

    #[test]
    fn test_hash_comment_language() {
        assert!(hash_comment_language("a.py") && hash_comment_language("a.rb"));
        assert!(!hash_comment_language("a.js") && !hash_comment_language("a.go"));
    }

    #[test]
    fn test_code_lines_strips_strings_and_comments() {
        let py = "x = \"copy\"  # deepcopy\ny = copy.copy(z)\n";
        let code = code_lines(py, true);
        assert!(!code[0].contains("copy"), "字符串与注释应被去掉: {:?}", code[0]);
        assert!(code[1].contains("copy"), "{:?}", code[1]);

        let js = "const a = `App`; // _AppCtxGlobals\nconst b = new App();\n/* App */\n";
        let code = code_lines(js, false);
        assert!(!code[0].contains("App"), "{:?}", code[0]);
        assert!(code[1].contains("App"), "{:?}", code[1]);
        assert!(!code[2].contains("App"), "块注释应被去掉: {:?}", code[2]);
    }

    #[test]
    fn test_code_lines_cross_line_string_and_triple_quote() {
        let js = "const t = `line1\nApp\nline2`;\nconst u = new App();\n";
        let code = code_lines(js, false);
        assert_eq!(code.len(), 4, "行数必须保持不变");
        assert!(!code[1].contains("App"), "跨行模板串内应被去掉: {:?}", code[1]);
        assert!(code[3].contains("App"), "{:?}", code[3]);

        let py = "s = \"\"\"\nApp\n\"\"\"\nx = App()\n";
        let code = code_lines(py, true);
        assert!(!code[1].contains("App"), "三引号串内应被去掉: {:?}", code[1]);
        assert!(code[3].contains("App"), "{:?}", code[3]);
    }

    #[test]
    fn test_identifiers_in_line() {
        let ids = identifiers_in_line("foo.bar(42, baz_1)");
        assert!(ids.contains(&"foo".to_string()), "{ids:?}");
        assert!(ids.contains(&"bar".to_string()), "{ids:?}");
        assert!(ids.contains(&"baz_1".to_string()), "{ids:?}");
        assert!(!ids.contains(&"42".to_string()), "纯数字不是标识符: {ids:?}");
    }

    #[test]
    fn test_contains_identifier_boundaries() {
        assert!(contains_identifier("    const s = new Store();", "Store"));
        assert!(!contains_identifier("class _AppCtxGlobals:", "App"));
        assert!(!contains_identifier("import deepcopy", "copy"));
        assert!(contains_identifier("x = copy.copy(y)", "copy"));
        assert!(contains_identifier("a.b.c", "b.c"));
    }

    #[test]
    fn test_call_site_match_left_boundary() {
        assert!(call_site_match("    return loader.load(request)", "load"));
        assert!(!call_site_match("    return myread(buf)", "read"));
        assert!(call_site_match("n, _ := r.Read(buf)", "Read"));
    }

    /// Rust 生命周期是**单个未配对**的 `'`（`&'static str`）。旧实现把它当成字符串
    /// 开引号，且 `quote` 状态跨行存活 → 后续整行被当作字符串内容清空，声明、引用与
    /// 调用点成片丢失。真实复现：`core/src/scanner/mod.rs` 的函数定义因此进不了符号索引。
    #[test]
    fn test_code_lines_rust_lifetime_does_not_swallow_following_lines() {
        let rs = "fn f() -> Option<&'static str> {\n    let mut out = Vec::new();\n}\n\npub fn classify_file_role(path: &str) -> &'static str {\n    \"code\"\n}\n";
        let code = code_lines(rs, false);
        assert_eq!(code.len(), rs.lines().count(), "行数必须保持不变");
        assert!(code[1].contains("Vec"), "存活行不应被清空: {:?}", code[1]);
        assert!(
            code[4].contains("classify_file_role"),
            "生命周期不得吞掉后续声明行: {:?}",
            code[4]
        );
        // 同行闭合的字符串仍按旧语义剥离
        assert!(!code[5].contains("code"), "同行字符串应被剥离: {:?}", code[5]);
    }
}
