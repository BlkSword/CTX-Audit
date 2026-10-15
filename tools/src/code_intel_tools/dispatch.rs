// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 间接调用与分发：C 风格调用点计数、候选签名解析与打分、项目级候选、函数摘要与预算。

use super::*;
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

