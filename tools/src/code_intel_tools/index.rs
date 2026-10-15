// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 项目索引与出处：构建上下文探测、文件加载与上限、语言判定、provenance 构造、符号索引统计。

use super::*;
/// 语言能力报告：哪些主语言在场、哪些只有启发式索引
/// 只读探测"本构建启用的宏/后端"。
///
/// 来源优先级：`<root>/build*/CMakeCache.txt`（`ENABLE_*:BOOL=ON` 与
/// `*_LIBRARY_*:FILEPATH=...-NOTFOUND`）→ `<root>/build*/config.h`（`#define HAVE_*`）。
/// 裸 clone 通常拿不到（config.h 由构建期生成）⇒ 如实报 `confidence=unknown`，**不得猜**。
pub(crate) fn probe_build_context(root: &std::path::Path) -> Value {
    let mut cache_files: Vec<std::path::PathBuf> = Vec::new();
    let mut config_files: Vec<std::path::PathBuf> = Vec::new();
    let mut push_pair = |dir: &std::path::Path| {
        let c = dir.join("CMakeCache.txt");
        if c.is_file() {
            cache_files.push(c);
        }
        let h = dir.join("config.h");
        if h.is_file() {
            config_files.push(h);
        }
    };
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if name.starts_with("build") || name == "out" {
                    push_pair(&p);
                }
            }
        }
    }
    push_pair(root);

    let mut switches: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut defines: Vec<String> = Vec::new();
    let mut sources: Vec<String> = Vec::new();

    for f in cache_files.iter().take(2) {
        if let Ok(text) = std::fs::read_to_string(f) {
            for line in text.lines().take(20_000) {
                if let Some(rest) = line.strip_prefix("ENABLE_") {
                    if let Some((k, v)) = rest.split_once(":BOOL=") {
                        if v.trim() == "ON" {
                            switches.push(k.to_string());
                        }
                    }
                }
                if let Some((k, v)) = line.split_once("_LIBRARY_") {
                    if v.contains("NOTFOUND") {
                        missing.push(k.to_string());
                    }
                }
            }
            sources.push(f.display().to_string());
        }
    }
    for f in config_files.iter().take(2) {
        if let Ok(text) = std::fs::read_to_string(f) {
            for line in text.lines().take(20_000) {
                let t = line.trim_start();
                if t.starts_with("#define HAVE_") || t.starts_with("#define ARCHIVE_") {
                    if let Some(name) = t.split_whitespace().nth(1) {
                        defines.push(name.to_string());
                    }
                }
            }
            sources.push(f.display().to_string());
        }
    }
    let known = !sources.is_empty();
    for v in [&mut switches, &mut missing, &mut defines] {
        v.sort();
        v.dedup();
        v.truncate(40);
    }
    json!({
        "source": sources.first().cloned(),
        "sources_scanned": sources,
        "enabled_switches": switches,
        "unavailable_libraries": missing,
        "config_defines": defines,
        "confidence": if known { "derived_from_build_artifacts" } else { "unknown" },
        "note": if known {
            "只读解析构建产物；不保证与当前编译命令逐字一致"
        } else {
            "未找到构建产物（CMakeCache.txt / config.h）：本构建启用了哪些宏/后端未知"
        },
    })
}

/// 标识符判据：C 宏名的形态（字母/下划线开头，字母数字下划线组成，长度 ≥ 2）。
pub(crate) fn is_macro_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    s.len() >= 2 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// 从 `#if` / `#elif` 的表达式里取被检验的宏名：`defined(X)`、`defined X`，以及前导的全大写标识符
/// （`#if HAVE_ZLIB`、`#if ENABLE_A && …`）。只做**字面**提取，不求值表达式。
pub(crate) fn defined_names(expr: &str) -> Vec<String> {
    let chars: Vec<char> = expr.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let word = ['d', 'e', 'f', 'i', 'n', 'e', 'd'];
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut i = 0usize;
    while i + word.len() <= chars.len() {
        if chars[i..i + word.len()] == word {
            let before_ok = i == 0 || !ident(chars[i - 1]);
            let after_ok = i + word.len() == chars.len() || !ident(chars[i + word.len()]);
            if before_ok && after_ok {
                let mut j = i + word.len();
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if j < chars.len() && chars[j] == '(' {
                    j += 1;
                    while j < chars.len() && chars[j].is_whitespace() {
                        j += 1;
                    }
                }
                let start = j;
                while j < chars.len() && ident(chars[j]) {
                    j += 1;
                }
                let name: String = chars[start..j].iter().collect();
                if is_macro_ident(&name) {
                    out.push(name);
                }
                i = j.max(i + word.len());
                continue;
            }
        }
        i += 1;
    }
    // `defined(...)` 之外的条件项（`&& HAVE_ZLIB`、`|| ENABLE_X`、`!DEBUG_MODE`）：
    // 按 C 的惯例取**含大写字母的标识符**；`0`/`1` 这类常量与全小写关键字自然被排除。
    for token in expr.split(|c: char| !ident(c)) {
        if token == "defined" || !is_macro_ident(token) {
            continue;
        }
        if token.chars().any(|c| c.is_ascii_uppercase()) {
            out.push(token.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// **索引期**上报：源码里出现过的条件编译宏（`#if`/`#elif` 的 `defined(...)`、`#ifdef`/`#ifndef`），
/// 以及该宏是否由源码自身 `#define`。
///
/// 与 `probe_build_context` 互补：后者读构建产物（裸克隆拿不到 ⇒ `unknown`），本字段只报**源码事实**，
/// 因此"这个项目对外部后端/特性有没有条件编译开关"在没有构建目录时也可判。只报字面事实：
/// 宏出现过几次、是否在源码里被定义；**不代表构建时的取值**。
pub(crate) fn collect_source_conditionals(files: &[(String, String)]) -> Value {
    use std::collections::{BTreeMap, BTreeSet};
    let mut branches: BTreeMap<String, usize> = BTreeMap::new();
    let mut defines: BTreeSet<String> = BTreeSet::new();
    let mut scanned_files = 0usize;
    for (path, content) in files {
        if !is_c_like_path(path) {
            continue;
        }
        scanned_files += 1;
        for line in content.lines().take(20_000) {
            let t = line.trim_start();
            let Some(rest) = t.strip_prefix('#') else {
                continue;
            };
            let rest = rest.trim_start();
            let (kw, tail) = match rest.split_once(char::is_whitespace) {
                Some((k, v)) => (k, v.trim()),
                None => (rest, ""),
            };
            match kw {
                "if" | "elif" => {
                    for name in defined_names(tail) {
                        *branches.entry(name).or_insert(0) += 1;
                    }
                }
                "ifdef" | "ifndef" => {
                    let name = tail.split_whitespace().next().unwrap_or("");
                    if is_macro_ident(name) {
                        *branches.entry(name.to_string()).or_insert(0) += 1;
                    }
                }
                "define" => {
                    let name = tail
                        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .next()
                        .unwrap_or("");
                    if is_macro_ident(name) {
                        defines.insert(name.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let distinct = branches.len();
    let mut list: Vec<(String, usize, bool)> = branches
        .into_iter()
        .map(|(macro_name, count)| {
            let defined_in_source = defines.contains(&macro_name);
            (macro_name, count, defined_in_source)
        })
        .collect();
    // 频次降序，再按宏名稳定排序；只保留前 40 个，避免大仓把响应撑大。
    list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    list.truncate(40);
    json!({
        "scanned_files": scanned_files,
        "distinct_macros": distinct,
        "branches": list
            .iter()
            .map(|(macro_name, count, defined_in_source)| json!({
                "macro": macro_name,
                "if_lines": count,
                "defined_in_source": defined_in_source,
            }))
            .collect::<Vec<_>>(),
        "note": "只统计源码里出现过的条件编译宏；是否为真取决于构建配置，不代表实际取值",
    })
}

/// 归属优先走 core 的 tree-sitter（语言无关，替代文本启发式）。
///
/// 只做一件事：问 AST"哪个体（函数/方法）包含目标行"，取**最近包含者**（最内层）。
/// 返回 (名字, 体起始行, 体结束行, 体开始行)。**解析不到就返回 None**，由调用方保留既有
/// 启发式结果并如实标注来源——**不在这里写任何语言专属正则**（R6）。
pub(crate) fn ast_enclosing_function(
    root: &std::path::Path,
    rel: &str,
    content: &str,
    line: u32,
) -> Option<(String, usize, usize, usize)> {
    if line == 0 || content.is_empty() {
        return None;
    }
    let mut parser = deepaudit_core::ast_api::ASTParser::new();
    let abs = root.join(rel);
    let bodies = parser.extract_function_bodies(&abs, content);
    let target = line as usize;
    // 由内向外取**最近的实名包含体**：嵌套匿名回调（`<anonymous@N>`）不应让归属整体落空，
    // 但若整条链上只有匿名体，则返回 None，交由启发式命名（避免把可用名换成占位名）。
    let mut containing: Vec<&deepaudit_core::ast_api::FunctionBody> = bodies
        .iter()
        .filter(|b| b.start_line <= target && target <= b.end_line)
        .collect();
    containing.sort_by_key(|b| b.end_line.saturating_sub(b.start_line));
    for b in containing {
        let named = !b.name.is_empty() && !b.name.starts_with('<');
        if named {
            return Some((
                b.name.clone(),
                b.start_line,
                b.end_line,
                b.body_start_line,
            ));
        }
    }
    None
}

pub(crate) fn language_capabilities(langs: &std::collections::BTreeMap<&'static str, usize>) -> Value {
    let mut present_primary: Vec<&str> = Vec::new();
    let mut heuristic_only: Vec<&str> = Vec::new();
    for (lang, count) in langs {
        if *count == 0 || *lang == "other" {
            continue;
        }
        if PRIMARY_ANALYSIS_LANGUAGES.contains(lang) {
            present_primary.push(lang);
        } else {
            heuristic_only.push(lang);
        }
    }
    json!({
        "primary_analysis_languages": PRIMARY_ANALYSIS_LANGUAGES,
        "present_primary": present_primary,
        "heuristic_only_present": heuristic_only,
        "analysis_backed": !present_primary.is_empty(),
    })
}

pub(crate) fn should_skip(dir_name: &str) -> bool {
    // 跳过清单 + 一切点号目录：`.ctx-audit` 是工具自己的状态目录
    // （mcp_metrics.jsonl 每次工具调用都会追加），索引它会让缓存指纹永远失效。
    SKIP_DIRS.contains(&dir_name) || dir_name.starts_with('.')
}

/// 内容索引的文件数上限：`CTX_AUDIT_INDEX_MAX_FILES` 可覆盖（0/非法值回落默认）。
///
/// 默认 2000 是"把文件内容全部读进内存"时代的产物；调大只影响内存，
/// 符号工具（`get_symbol_definition`/`references`）已不受该上限约束。
pub(crate) fn max_index_files() -> usize {
    std::env::var("CTX_AUDIT_INDEX_MAX_FILES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(MAX_FILES)
}

/// 显式点名单文件时的读取上限（8MB）。
///
/// `MAX_FILE_BYTES` 约束的是**批量索引**（把 2000 个文件读进内存的成本）。调用方点名一个
/// 文件时只读这一个，成本 O(1)。此前两者共用同一上限，于是被索引跳过的文件会被回答成
/// "文件不存在"——内容其实就在盘上（实测：542KB 的生成产物、以及超出 2000 文件上限的
/// 命中文件，都被误报为不存在）。批量上限与显式请求上限必须解耦。
pub(crate) const MAX_EXPLICIT_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// 按需读取调用方**点名**的单个文件。
///
/// 失败信息必须给出**真实原因**（路径不存在 / 不是常规文件 / 超过单文件读取上限），
/// 不得把"我没有索引它"说成"文件不存在"——对 LLM 消费者而言，后者是在陈述一个错误的世界。
pub(crate) fn read_requested_file(root: &Path, rel: &str) -> Result<String, ToolError> {
    let path = root.join(rel);
    let meta = std::fs::metadata(&path).map_err(|_| {
        ToolError::InvalidArgument(format!("文件不存在: {rel}（磁盘与索引中都没有该路径）"))
    })?;
    if !meta.is_file() {
        return Err(ToolError::InvalidArgument(format!("不是常规文件: {rel}")));
    }
    if meta.len() > MAX_EXPLICIT_FILE_BYTES {
        return Err(ToolError::InvalidArgument(format!(
            "文件过大: {rel} = {} 字节 > 单文件读取上限 {} 字节（批量索引上限为 {} 字节）",
            meta.len(),
            MAX_EXPLICIT_FILE_BYTES,
            MAX_FILE_BYTES
        )));
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(content),
        // 非 UTF-8 源码（latin-1/GBK 注释）：按字节尽力转换，不因编码拒绝一个存在的文件
        Err(_) => Ok(String::from_utf8_lossy(&std::fs::read(&path).unwrap_or_default()).to_string()),
    }
}

pub fn language_of(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "rs" => "rust",
        "py" => "python",
        "go" => "go",
        "js" | "jsx" => "javascript",
        "ts" | "tsx" => "typescript",
        "java" => "java",
        "php" => "php",
        "rb" => "ruby",
        "ex" | "exs" => "elixir",
        "c" => "c",
        "h" | "hpp" => "c-header",
        "cpp" | "cc" | "cxx" => "cpp",
        "cs" => "csharp",
        "kt" => "kotlin",
        "swift" => "swift",
        "scala" => "scala",
        "clj" => "clojure",
        "lua" => "lua",
        "sh" => "shell",
        "sql" => "sql",
        "yaml" | "yml" => "yaml",
        "json" => "json",
        "toml" => "toml",
        _ => "other",
    }
}

/// 索引加载结果：文件内容 + 可观测上限事实 + stat 指纹。
pub(crate) struct LoadedIndex {
    pub(crate) files: Vec<(String, String)>,
    /// 因超过单文件大小上限而跳过的文件数
    pub(crate) skipped_large: usize,
    /// 是否因达到文件数上限而提前停止遍历
    pub(crate) truncated_at_limit: bool,
    /// 已索引文件的 stat 指纹（缓存失效探测用）
    pub(crate) file_stamps: Vec<crate::index_cache::FileStamp>,
    /// 已遍历目录的 stat 指纹（目录内增删的兜底探测）
    pub(crate) dir_stamps: Vec<crate::index_cache::DirStamp>,
}

/// 遍历项目文件并采集 stat 指纹（跳过目录不采集，也不计入指纹）。
pub(crate) fn load_files(root: &Path) -> LoadedIndex {
    use crate::index_cache::{mtime_ms, DirStamp, FileStamp};

    let mut out: Vec<(String, String)> = Vec::new();
    let mut file_stamps: Vec<FileStamp> = Vec::new();
    let mut dir_stamps: Vec<DirStamp> = Vec::new();
    let mut skipped_large = 0usize;
    let mut truncated_at_limit = false;
    let max_files = max_index_files();
    // 遍历顺序必须**确定性**：`read_dir` 返回顺序随文件系统而异，而"达到文件数上限就停"
    // 意味着取舍结果在机器之间不同（同一仓库可能索引到不同的文件子集，实测命中文件因此
    // 被漏掉并报成"文件不存在"）。改为：目录项排序 + 广度优先（浅目录优先 ⇒ 顶层源码
    // 先于深层测试夹具进索引）。
    let mut queue: std::collections::VecDeque<(PathBuf, String)> =
        std::collections::VecDeque::from([(root.to_path_buf(), String::new())]);
    while let Some((dir, dir_rel)) = queue.pop_front() {
        if out.len() >= max_files {
            truncated_at_limit = true;
            break;
        }
        // 目录指纹：目录内新增/删除/改名会改变目录 mtime，是文件级指纹的兜底
        if let Ok(meta) = std::fs::metadata(&dir) {
            dir_stamps.push(DirStamp {
                path: dir_rel.clone(),
                mtime_ms: mtime_ms(&meta),
            });
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if !should_skip(&name) {
                    let child_rel = if dir_rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{dir_rel}/{name}")
                    };
                    queue.push_back((path, child_rel));
                }
                continue;
            }
            if out.len() >= max_files {
                truncated_at_limit = true;
                break;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() as usize > MAX_FILE_BYTES {
                skipped_large += 1;
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or(name.clone());
            if let Ok(content) = std::fs::read_to_string(&path) {
                file_stamps.push(FileStamp {
                    path: rel.clone(),
                    mtime_ms: mtime_ms(&meta),
                    size: meta.len(),
                });
                out.push((rel, content));
            }
        }
    }
    // 输出顺序同样做成确定性：`build_id` 与"取前 N 条"的取舍都依赖它
    out.sort_by(|a, b| a.0.cmp(&b.0));
    file_stamps.sort_by(|a, b| a.path.cmp(&b.path));
    LoadedIndex {
        files: out,
        skipped_large,
        truncated_at_limit,
        file_stamps,
        dir_stamps,
    }
}

pub(crate) fn build_id(files: &[(String, String)]) -> String {
    let bytes: usize = files.iter().map(|(_, c)| c.len()).sum();
    format!("statv1:{}f:{}b", files.len(), bytes)
}

pub(crate) fn prov(file: &str, line: u32, id: &str) -> Provenance {
    let resolver = "file-heuristic";
    Provenance {
        file: Some(file.to_string()),
        line: Some(line),
        resolver: resolver.to_string(),
        build_id: id.to_string(),
        confidence: resolver_confidence(resolver),
    }
}

/// 指定 resolver 的 provenance（如 `symbol-index`）
pub(crate) fn prov_with(file: &str, line: u32, id: &str, resolver: &str) -> Provenance {
    Provenance {
        file: Some(file.to_string()),
        line: Some(line),
        resolver: resolver.to_string(),
        build_id: id.to_string(),
        confidence: resolver_confidence(resolver),
    }
}

/// 符号索引的可观测状态（供响应体如实上报）
/// 空结果的**可观测性分类**：把"索引里根本没有该符号"与"索引里有线索但没抽出结果"分开。
///
/// 动机：`total_hits = 0` 曾同时表示两件含义相反的事——"符号不存在"（正常答案）与
/// "定义抽取漏收"（**覆盖缺口**，既是索引排查的信号，也是"全项目联动"实验的仪器读数）。
pub(crate) fn empty_definition_kind(index: &crate::symbol_index::SymbolIndex, symbol: &str) -> &'static str {
    if index.identifier_occurrence_count(symbol) == 0 {
        "no_match"
    } else {
        "index_miss"
    }
}

/// 引用空结果的分类：`no_match`（索引里没有）/ `index_miss`（有出现但无定义）/
/// `definition_only`（只在定义处出现，确实没有引用）。
pub(crate) fn empty_reference_kind(index: &crate::symbol_index::SymbolIndex, symbol: &str) -> &'static str {
    if index.identifier_occurrence_count(symbol) == 0 {
        "no_match"
    } else if index.definitions(symbol, usize::MAX).is_empty() {
        "index_miss"
    } else {
        "definition_only"
    }
}

pub(crate) fn symbol_index_stats(
    index: &crate::symbol_index::SymbolIndex,
    hit: crate::symbol_index::HitSource,
    build_ms: u64,
) -> Value {
    json!({
        "files_indexed": index.file_count(),
        "symbols": index.symbol_count(),
        "identifiers": index.identifier_symbols(),
        "identifier_occurrences": index.identifier_count(),
        "parsed_files": index.parsed_files(),
        "hit_source": hit.as_str(),
        "build_ms": build_ms,
        "age_ms": index.build_age().as_millis() as u64,
        "skipped_large_files": index.skipped_large(),
        "skipped_non_code_files": index.skipped_non_code(),
        "truncated_at_limit": index.truncated(),
        "match": "identifier_exact",
    })
}

