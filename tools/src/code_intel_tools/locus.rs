// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! C 线 locus 事实：单个代码点上下文的确定性事实抽取（归属、能力锚点、最小窗口判据）。

use super::*;
/// 从一行里取标识符（长度 ≥2、非数字开头），用于"这一行涉及哪些名字"。
pub(crate) fn locus_identifiers(line: &str) -> Vec<String> {
    locus_identifiers_min(line, 2)
}

/// 取**源码顺序**的最后一个标识符（**不排序**）：参数形如"类型 + 名字"，
/// 用排序后的列表取末尾会把名字挤掉（实测：`unsigned int n` 得到 `unsigned`）。
pub(crate) fn locus_last_identifier(line: &str) -> String {
    let mut last = String::new();
    let mut cur = String::new();
    for c in line.chars() {
        if c.is_alphanumeric() || c == '_' {
            cur.push(c);
        } else {
            if !cur.is_empty() {
                last = cur.clone();
            }
            cur.clear();
        }
    }
    if !cur.is_empty() {
        last = cur;
    }
    last
}

/// 同上，但可放宽最小长度：**参数名**用 `min_len=1`——C 里 `n`/`i`/`p` 这类单字符名很常见，
/// 用 ≥2 会把它们整批滤掉（实测：`unsigned int n` 的 `n` 被漏）。
pub(crate) fn locus_identifiers_min(line: &str, min_len: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in line.chars() {
        if c.is_alphanumeric() || c == '_' {
            cur.push(c);
        } else {
            if cur.len() >= min_len && !cur.starts_with(|c: char| c.is_ascii_digit()) {
                out.push(cur.clone());
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len && !cur.starts_with(|c: char| c.is_ascii_digit()) {
        out.push(cur);
    }
    out.sort();
    out.dedup();
    out
}

/// 定长数组声明（容量锚点）：方括号里是**常量**（数字或全大写宏）且行内有类型关键字。
/// 生成物 `name[len++] = c;` 这类下标写入不得被当锚点。
pub(crate) fn locus_capacity_anchor(t: &str) -> bool {
    if !t.contains('[') || !t.contains(']') {
        return false;
    }
    let inner = t
        .split('[')
        .nth(1)
        .unwrap_or("")
        .split(']')
        .next()
        .unwrap_or("")
        .trim();
    if inner.is_empty() {
        return false;
    }
    let const_like = inner.chars().all(|c| c.is_ascii_digit())
        || (inner.len() >= 3 && inner.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
    let typed = ["char ", "int ", "u_char", "uint", "size_t", "unsigned ", "long ", "wchar"]
        .iter()
        .any(|k| t.contains(k));
    const_kind_check(t) && const_like && typed
}

/// 排除"下标写入/赋值"（`x[i] = ...`）—— 那不是容量锚点。
pub(crate) fn const_kind_check(t: &str) -> bool {
    !t.contains("] =") && !t.contains("]=") && !t.contains("] +=") && !t.contains("] -=")
}

/// 判定要素与可达性视图。
///
/// 只产**字面事实与显式缺失**：检查行按"标记 + 目标行标识符命中"给出，未命中即
/// `no_check_found`（缺席本身就是可归因的事实）；容量锚点是定长数组声明与 `sizeof`；
/// 最小窗口只覆盖"目标行 + 检查行 + 锚点"；可达性给的是**签名字面参数**与**调用者**，
/// 并明确标注这不是污点/可达性证明。
#[allow(clippy::too_many_arguments)]
// `code` 是**代码视图**（注释与字符串已被抹空、行号对齐）。判定只用它、输出仍用原文，
// 一次覆盖 C/Java/JS/Go/Rust 的行/块注释与 Java 文档注释、Python docstring（S3 上提）。
#[allow(clippy::too_many_arguments)]
pub(crate) fn locus_facts(
    root: &std::path::Path,
    files: &[(String, String)],
    code: &[&str],
    lines: &[&str],
    scope_start: usize,
    scope_end: usize,
    center: usize,
    function: Option<&str>,
    signature: Option<&str>,
    language_backed: bool,
    sindex: &crate::symbol_index::SymbolIndex,
) -> (Value, Value) {
    let target_line = lines.get(center).copied().unwrap_or("");
    let idents = locus_identifiers(target_line);
    // 参数相关性判定用放宽版：C 里参数常是单字符名（`n`/`i`），用 ≥2 会整批漏掉
    let idents_any = locus_identifiers_min(target_line, 1);
    // **区域变量**：目标行 ±3 行内出现过的标识符。locus 常落在空白/指针行上，而真正的变量在
    // 紧邻几行（实测：某解析器的目标行是空行，决定性的长度变量在下一行）⇒ 只看目标行会漏。
    let region_lo = center.saturating_sub(3);
    let region_hi = (center + 3).min(lines.len().saturating_sub(1));
    let mut region_idents: Vec<String> = Vec::new();
    for i in region_lo..=region_hi {
        for id in locus_identifiers(lines.get(i).copied().unwrap_or("")) {
            region_idents.push(id);
        }
    }
    region_idents.sort();
    region_idents.dedup();
    let mut guards: Vec<Value> = Vec::new();
    let mut anchors: Vec<Value> = Vec::new();
    let end = scope_end.min(lines.len());
    for i in scope_start..end {
        let raw = lines.get(i).copied().unwrap_or("");
        // 判定读**代码视图**（注释/字符串为空白），显示仍用原文 ⇒ 文档注释不再被当成检查行。
        let scanned = code.get(i).copied().unwrap_or(raw);
        let t = scanned.trim();
        if t.is_empty()
            || t.starts_with("//")
            || t.starts_with('*')
            || t.starts_with('#')
            || t.starts_with("/*")
        {
            continue;
        }
        let brief: String = raw.trim().chars().take(160).collect();
        if locus_capacity_anchor(t) {
            anchors.push(json!({"line": i + 1, "text": brief, "kind": "fixed_array_capacity"}));
        } else if t.contains("sizeof") && idents.iter().any(|id| t.contains(id.as_str())) {
            anchors.push(json!({"line": i + 1, "text": brief, "kind": "sizeof_bound"}));
        }
        // 相关性分两层，避免"密集函数里所有守卫都算相关"（实测某函数 54 条守卫 ⇒ 最小窗口
        // 反而比交付窗口大）：
        //   direct  —— 提到**区域变量**（目标行 ±3 行里的名字）⇒ 参与最小窗口；
        //   nearby  —— 仅在 ±10 行内、与区域变量无关 ⇒ 列出但不撑大窗口。
        let is_check = LOCUS_CHECK_TOKENS.iter().any(|m| t.contains(m));
        if !is_check || i == center {
            continue;
        }
        let direct = region_idents.iter().any(|id| t.contains(id.as_str()));
        let nearby = i.abs_diff(center) <= 10;
        if direct || nearby {
            guards.push(json!({
                "line": i + 1,
                "text": brief,
                "scope": "enclosing_function",
                "relevance": if direct { "direct" } else { "nearby" },
            }));
        }
    }
    // 最小窗口 = 目标行所在区域 + **最近的上方/下方 direct 检查** + **最近的上方/下方锚点**。
    // 把所有 direct 检查都收进来会让窗口随函数规模增长（实测 p90 仍达 49 行）；只取最近邻
    // 可以让窗口紧贴"判定够用"的范围（纳入半径 ±20 行，更远的只登记不纳入）。其余检查行**仍在 guards 里逐条列出并标 in_window=false**，
    // 信息不丢，只是不撑大交付窗口。
    let anchor_center = center + 1;
    let mut points: Vec<usize> = vec![region_lo + 1, anchor_center, region_hi + 1];
    let direct_lines: Vec<usize> = guards
        .iter()
        .filter(|g| g.get("relevance").map(|r| r == "direct").unwrap_or(false))
        .filter_map(|g| g["line"].as_u64().map(|l| l as usize))
        .collect();
    let anchor_lines_all: Vec<usize> = anchors
        .iter()
        .filter_map(|a| a["line"].as_u64().map(|l| l as usize))
        .collect();
    let nearest_below = |xs: &[usize]| xs.iter().copied().filter(|l| *l < anchor_center).max();
    let nearest_above = |xs: &[usize]| xs.iter().copied().filter(|l| *l > anchor_center).min();
    let candidates = [
        nearest_below(&direct_lines),
        nearest_above(&direct_lines),
        nearest_below(&anchor_lines_all),
        nearest_above(&anchor_lines_all),
    ];
    let mut far_points = 0usize;
    for c in candidates.into_iter().flatten() {
        if c.abs_diff(anchor_center) <= 20 {
            points.push(c);
        } else {
            far_points += 1;
        }
    }
    // 未能进入窗口的 direct 检查行数（供消费者判断"窗口外还有几条相关检查"）
    far_points += direct_lines
        .iter()
        .filter(|l| !points.contains(l))
        .count();
    points.sort_unstable();
    points.dedup();
    let mut guards: Vec<Value> = guards;
    for g in guards.iter_mut() {
        if let (Some(l), Some(obj)) = (g["line"].as_u64(), g.as_object_mut()) {
            let inw = points.contains(&(l as usize));
            obj.insert("in_window".to_string(), json!(inw));
        }
    }
    let lo = points.iter().copied().min().unwrap_or(center + 1);
    let hi = points.iter().copied().max().unwrap_or(center + 1);
    let span = hi.saturating_sub(lo) + 1;
    let minimal_window = json!({
        "start_line": lo,
        "end_line": hi,
        "lines": span,
        "spread": if span > 40 { "wide" } else { "tight" },
        "covers": ["target_line", "guards", "capacity_anchors"],
        "far_points_outside_window": far_points,
        "note": "只覆盖目标行所在区域与**最近的上/下方检查行、最近的上/下方容量锚点**（纳入半径 ±20 行）——可直接作为交付单元；far_points_outside_window 是未进入窗口的 direct 检查行数（它们在 guards 里仍逐条列出）",
    });
    // **目标行自身的检查状态**：locus 所在行常常就是那条检查（修复改的往往正是这一行）。
    // 之前这行被排除在 guards 之外且没有任何标注 ⇒ 当"决定性行就是目标行"时它凭空消失，
    // 判定者只能看到"作用域里别处没有检查"，这是**归属**错误而不是覆盖缺失（行在窗口里）。
    let target_matched: Vec<&str> = LOCUS_CHECK_TOKENS
        .iter()
        .filter(|m| target_line.contains(**m))
        .copied()
        .collect();
    let target_is_check = !target_matched.is_empty();
    let target_brief: String = target_line.trim().chars().take(160).collect();
    // `no_check_found` 只在**目标行与作用域都没有检查**时才为真（口径显式写在响应里）。
    let no_check_found = guards.is_empty() && !target_is_check;
    let decision_facts = json!({
        "guards": {
            "lines": guards,
            "count": guards.len(),
            "target_line_check": {
                "line": center + 1,
                "is_check": target_is_check,
                "tokens_matched": target_matched,
                "text": target_brief,
            },
            "no_check_found": no_check_found,
            "no_check_found_meaning": "目标行与作用域内都没有检出检查标记",
            "searched_scope": "enclosing_function",
            "markers": LOCUS_CHECK_TOKENS,
        },
        "capacity_anchors": anchors,
        "minimal_window": minimal_window,
        "semantics": {
            "evidence_kind": "textual+structural",
            "pointer_or_bounds_reasoning": false,
            "language_analysis_backed": language_backed,
            "note": "字面事实 + 显式缺失：检查行按标记与目标行标识符命中给出，未命中即 no_check_found；不做尺寸或可达性推理",
        },
    });

    // ── 可达性视图 ──
    let mut origins: Vec<Value> = Vec::new();
    if let Some(sig) = signature {
        if let (Some(open), Some(close)) = (sig.find('('), sig.rfind(')')) {
            if open < close {
                for param in sig[open + 1..close].split(',') {
                    let p = param.trim();
                    if p.is_empty() || p == "void" {
                        continue;
                    }
                    let name = locus_last_identifier(p);
                    if name.is_empty() {
                        continue;
                    }
                    if idents_any.iter().any(|id| id == &name) {
                        origins.push(json!({
                            "kind": "parameter",
                            "name": name,
                            "text": p.chars().take(120).collect::<String>(),
                        }));
                    }
                }
            }
        }
    }
    // 局部赋值：目标表达式里的名字在本函数内被赋过值 ⇒ 来源候选（**只报字面行，不追链**）。
    for i in scope_start..end {
        let t = lines.get(i).copied().unwrap_or("").trim();
        if t.starts_with("//") || !t.contains('=') || t.contains("==") {
            continue;
        }
        let Some(eq) = t.find('=') else { continue };
        let lhs = t[..eq].trim();
        if lhs.contains('(') || lhs.contains(')') {
            continue; // 调用/条件式，不是赋值目标
        }
        let lhs_no_index: String = lhs.chars().take_while(|c| *c != '[').collect();
        let name = locus_last_identifier(&lhs_no_index);
        if name.is_empty() || !region_idents.iter().any(|id| id == &name) {
            continue;
        }
        // 同一个名字可能被赋多次：只保留**离目标行最近**的一条，避免来源候选被同一变量刷屏。
        if let Some(existing) = origins
            .iter_mut()
            .find(|o| o["kind"] == "local_assignment" && o["name"] == name.as_str())
        {
            let existing_gap = (existing["line"].as_u64().unwrap_or(0) as usize)
                .abs_diff(anchor_center);
            if (i + 1).abs_diff(anchor_center) < existing_gap {
                *existing = json!({
                    "kind": "local_assignment",
                    "name": name,
                    "line": i + 1,
                    "text": t.chars().take(120).collect::<String>(),
                });
            }
        } else {
            origins.push(json!({
                "kind": "local_assignment",
                "name": name,
                "line": i + 1,
                "text": t.chars().take(120).collect::<String>(),
            }));
        }
    }

    let mut entry_candidates: Vec<Value> = Vec::new();
    if let Some(fname) = function {
        if !fname.is_empty() && fname != "<unknown>" {
            let mut def_lines: std::collections::HashMap<String, std::collections::HashSet<u32>> =
                std::collections::HashMap::new();
            for hit in sindex.definitions(fname, 64) {
                def_lines
                    .entry(sindex.file_path(hit.file).to_string())
                    .or_default()
                    .insert(hit.line);
            }
            for (file_idx, line) in sindex.identifier_hits(fname) {
                if entry_candidates.len() >= 5 {
                    break;
                }
                let rel = sindex.file_path(file_idx).to_string();
                if def_lines.get(&rel).map(|s| s.contains(&line)).unwrap_or(false) {
                    continue;
                }
                let text = files
                    .iter()
                    .find(|(p, _)| p == &rel)
                    .and_then(|(_, content)| {
                        content
                            .lines()
                            .nth((line as usize).saturating_sub(1))
                            .map(|s| s.trim().chars().take(160).collect::<String>())
                    })
                    .unwrap_or_default();
                entry_candidates.push(json!({"file": rel, "line": line, "text": text}));
            }
        }
    }
    // 索引没给到调用者时的**文件内字面兜底**：同文件里的 `fn(` 调用点（排除定义行）。
    // 仍然只报字面事实；命中不到就是空列表 + confidence=low，不编造。
    if entry_candidates.is_empty() {
        if let Some(fname) = function {
            let needle = format!("{}(", fname);
            for (rel, content) in files {
                for (idx, raw) in content.lines().enumerate() {
                    if entry_candidates.len() >= 5 {
                        break;
                    }
                    let t = raw.trim();
                    if t.starts_with("//") || !raw.contains(&needle) {
                        continue;
                    }
                    if ["void ", "int ", "char ", "unsigned ", "static ", "long ", "size_t "]
                        .iter()
                        .any(|k| t.starts_with(k))
                    {
                        continue; // 定义行/声明行
                    }
                    entry_candidates.push(json!({
                        "file": rel,
                        "line": (idx + 1) as u32,
                        "text": t.chars().take(160).collect::<String>(),
                    }));
                }
            }
        }
    }

    let _ = root;
    let reachability = json!({
        "function": function,
        "origin_candidates": origins,
        "entry_candidates": entry_candidates,
        "entry_count": entry_candidates.len(),
        "guard_summary": if no_check_found { "no_check_found" } else { "check_present" },
        "target_line_is_check": target_is_check,
        "confidence": if entry_candidates.is_empty() { "low" } else { "medium" },
        "semantics": {
            "analysis_backed": language_backed,
            "evidence_kind": "textual+structural",
            "no_pointer_or_bounds_reasoning": true,
        },
        "note": "origin_candidates 来自函数签名的参数（字面）；entry_candidates 是调用者（倒排索引，排除定义行，最多 5 条）。**这不是污点或可达性证明**，只是判定所需的入口/来源候选。",
    });
    (decision_facts, reachability)
}

