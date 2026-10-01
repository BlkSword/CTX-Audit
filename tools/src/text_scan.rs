// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 行级"代码段"扫描工具：去掉注释与字符串字面量后再做符号判定。
//!
//! 实测依据（真实仓库 + CPython `ast`/`tokenize` 独立 oracle）：引用误报里剩下的那一成
//! 来自**字符串字面量与行内注释里的同名标识符**——oracle 只计 NAME token，按行匹配会命中它们。

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
            if ch == '"' || ch == '\'' || ch == '`' {
                quote = Some(ch);
                i += ch.len_utf8();
                continue;
            }
            kept.push(ch);
            i += ch.len_utf8();
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
}
