// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 链档（Chain Dossier）—— 法医台核心：把"入口 → 危险汇"的可疑路径装配成有界、确定性、
//! 带断点与不确定性的证据档。
//!
//! 取舍（依据 R247–R257 实测）：
//! - 候选生成用**调用图可达性**而非全污点：污点自动发现实测弱（0/17），先保召回；
//! - **断点显式**：解不开的地方（深度上限/扇出超限/无调用者）一律进 `breakpoints`；
//! - **有界**：步骤 ≤40、单档 ≤12KB、确定性排序、内容哈希 ID；
//! - **不做判定**：只给 `verdict_candidates`。

use super::*;
use super::chain_vocab;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub(crate) const DOSSIER_SCHEMA: &str = "chain-dossier/v1";
pub(crate) const MAX_STEPS: usize = 40;
pub(crate) const MAX_DOSSIER_BYTES: usize = 12 * 1024;
const MAX_DEPTH: usize = 12;
const MAX_FANOUT: usize = 6;

/// FNV-1a：确定性链 ID（不依赖 std 随机化 hasher）。
pub(crate) fn stable_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    format!("{h:016x}")
}

pub(crate) fn chain_language_of(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "js" | "mjs" | "cjs" | "jsx" => "js",
        "ts" | "tsx" => "ts",
        "java" => "java",
        "py" => "py",
        "go" => "go",
        _ => "other",
    }
}

fn is_code_line(line: &str) -> bool {
    let t = line.trim_start();
    !(t.is_empty()
        || t.starts_with("//")
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.starts_with('#')
        || t.starts_with("--"))
}

fn ident_before_paren(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let paren = trimmed.find('(')?;
    let head = &trimmed[..paren];
    let name: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if name.is_empty() || name.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(true) {
        None
    } else {
        Some(name)
    }
}

const KEYWORDS: [&str; 30] = [
    "if", "for", "while", "switch", "catch", "return", "function", "new", "typeof", "await",
    "async", "else", "do", "try", "throw", "delete", "void", "in", "size", "length", "toString",
    "println", "print", "log", "require", "import", "assert", "super", "this", "yield",
];

pub(crate) fn definitions(content: &str, lang: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        if !is_code_line(raw) {
            continue;
        }
        let t = raw.trim();
        let ln = (idx + 1) as u32;
        match lang {
            "js" | "ts" => {
                if let Some(pos) = t.find("function ") {
                    let rest = &t[pos + 9..];
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                        .collect();
                    if !name.is_empty() {
                        out.push((name, ln));
                        continue;
                    }
                }
                if t.contains("=>") || t.contains("= function") || t.contains("= async") {
                    if let Some(eq) = t.find('=') {
                        let head = t[..eq].trim_end();
                        let name: String = head
                            .chars()
                            .rev()
                            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect();
                        if !name.is_empty() {
                            out.push((name, ln));
                            continue;
                        }
                    }
                }
                if t.ends_with('{') && !t.contains('=') {
                    if let Some(name) = ident_before_paren(t) {
                        if !KEYWORDS.contains(&name.as_str()) {
                            out.push((name, ln));
                        }
                    }
                }
            }
            "java" => {
                if t.contains('(')
                    && t.contains(')')
                    && t.contains('{')
                    && !t.contains('=')
                    && !["if", "for", "while", "switch", "return", "new "]
                        .iter()
                        .any(|k| t.starts_with(k))
                {
                    if let Some(name) = ident_before_paren(t) {
                        out.push((name, ln));
                    }
                }
            }
            "py" => {
                if let Some(rest) = t.strip_prefix("def ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        out.push((name, ln));
                    }
                }
            }
            "go" => {
                if t.starts_with("func ") {
                    if let Some(name) = ident_before_paren(t) {
                        out.push((name, ln));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

pub(crate) fn calls(content: &str) -> Vec<(String, u32, bool, bool, bool)> {
    calls_ext(content)
        .into_iter()
        .map(|(n, l, m, i, c, _r)| (n, l, m, i, c))
        .collect()
}

/// 带接收者的调用扫描：`receiver.method()` 额外返回 `Some("receiver")`。
pub(crate) fn calls_ext(content: &str) -> Vec<(String, u32, bool, bool, bool, Option<String>)> {
    let mut out = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        if !is_code_line(raw) {
            continue;
        }
        let ln = (idx + 1) as u32;
        if raw.is_ascii() {
            // ASCII 快路径：按字节扫描，零分配
            let b = raw.as_bytes();
            let n = b.len();
            let mut i = 0usize;
            while i < n {
                let c = b[i];
                if c.is_ascii_alphabetic() || c == b'_' || c == b'$' {
                    let start = i;
                    while i < n && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                        i += 1;
                    }
                    let name = &raw[start..i];
                    let mut j = i;
                    while j < n && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < n && b[j] == b'(' && !KEYWORDS.contains(&name) && !declaration_like(raw, start) {
                        let member = start > 0 && b[start - 1] == b'.';
                        let receiver = receiver_before(raw, start);
                        let before = raw[..start].trim_end();
                        let install = before.ends_with("this.") || before.ends_with("this._");
                        let ctor = name.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false)
                            || before.ends_with("new");
                        out.push((name.to_string(), ln, member, install, ctor, receiver));
                    }
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // 非 ASCII：保底 char 扫描
        let chars: Vec<(usize, char)> = raw.char_indices().collect();
        let n = chars.len();
        let mut k = 0usize;
        while k < n {
            let (start_byte, ch) = chars[k];
            if ch.is_alphabetic() || ch == '_' || ch == '$' {
                let mut end_k = k;
                while end_k + 1 < n {
                    let c2 = chars[end_k + 1].1;
                    if c2.is_alphanumeric() || c2 == '_' || c2 == '$' {
                        end_k += 1;
                    } else {
                        break;
                    }
                }
                let end_byte = if end_k + 1 < n { chars[end_k + 1].0 } else { raw.len() };
                let name = &raw[start_byte..end_byte];
                let mut j = end_k + 1;
                while j < n && chars[j].1.is_whitespace() {
                    j += 1;
                }
                if j < n && chars[j].1 == '(' && !KEYWORDS.contains(&name) && !declaration_like(raw, start_byte) {
                    let member = start_byte > 0 && raw.as_bytes()[start_byte - 1] == b'.';
                    let receiver = receiver_before(raw, start_byte);
                    let before = raw[..start_byte].trim_end();
                    let install = before.ends_with("this.") || before.ends_with("this._");
                    let ctor = name.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false)
                        || before.ends_with("new");
                    out.push((name.to_string(), ln, member, install, ctor, receiver));
                }
                k = end_k + 1;
            } else {
                k += 1;
            }
        }
    }
    out
}

/// 判断 `name(` 所在行是否是"函数/方法声明"而不是调用。
///
/// 名字级扫描会把 `public static <T> T parseObject(...)` 这类重载声明行当成调用，
/// 进而把同文件重载误连成路径。规则：名字前有类型/修饰符 token、无 `=`、`.`、`(`，
/// 且名字后存在 `{` / `;` / `throws` / `,`。
fn declaration_like(raw: &str, start: usize) -> bool {
    let before = raw[..start].trim_end();
    if before.is_empty() {
        return false;
    }
    let last = before.chars().last().unwrap_or(' ');
    if !(last.is_alphanumeric() || last == '>' || last == '?' || last == ']') {
        return false;
    }
    let last_word = before
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .last()
        .unwrap_or("");
    const KEYWORDS: [&str; 14] = [
        "return", "new", "if", "for", "while", "switch", "catch", "throw", "case",
        "else", "yield", "await", "typeof", "instanceof",
    ];
    if KEYWORDS.contains(&last_word) {
        return false;
    }
    if before.contains('=') || before.contains('.') || before.contains('(') {
        return false;
    }
    let rest = &raw[start..];
    rest.contains('{') || rest.contains(';') || rest.contains("throws") || rest.contains(',')
}

/// 取 `receiver.method(` 中 `.` 之前的接收者变量名（支持 `this.` 与简单标识符）。
fn receiver_before(raw: &str, start: usize) -> Option<String> {
    let bytes = raw.as_bytes();
    if start == 0 || bytes[start - 1] != b'.' {
        return None;
    }
    let mut k = start - 1;
    while k > 0 && bytes[k - 1].is_ascii_whitespace() {
        k -= 1;
    }
    if k == 0 {
        return None;
    }
    let mut end = k;
    while end > 0 {
        let c = bytes[end - 1];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
            end -= 1;
        } else {
            break;
        }
    }
    if end == k {
        return None;
    }
    let word = &raw[end..k];
    if word == "this" || word == "new" || word.is_empty() {
        None
    } else {
        Some(word.to_string())
    }
}

/// 在文件内按函数名找最近的、位于 line 之前的定义行；找不到则退化到最近定义。
fn def_line_for_name(
    defs: &BTreeMap<String, Vec<(String, u32)>>,
    file: &str,
    name: &str,
    line: u32,
) -> Option<u32> {
    let ds = defs.get(file)?;
    if let Some((_, l)) = ds
        .iter()
        .filter(|(n, l)| n == name && *l <= line)
        .max_by_key(|(_, l)| *l)
    {
        return Some(*l);
    }
    ds.iter()
        .filter(|(_, l)| *l <= line)
        .map(|(_, l)| *l)
        .max()
}

/// 候选链前向边校验（caller 函数体内是否有对下一节点的真实调用）。
/// 解析 `name(` 调用或声明括号内的参数个数；返回 (参数个数, 是否 varargs)。
fn paren_params(raw: &str, name: &str) -> Option<(usize, bool)> {
    let needle = format!("{name}(");
    let pos = raw.find(&needle)?;
    let start = pos + needle.len();
    let bytes = raw.as_bytes();
    let mut depth = 1i32;
    let mut i = start;
    let mut commas = 0usize;
    let mut any = false;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        match ch {
            '(' | '<' if depth == 1 => {}
            '(' => {}
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let inner = &raw[start..i];
                    let varargs = inner.contains("...");
                    if inner.trim().is_empty() {
                        return Some((0, varargs));
                    }
                    return Some((commas + 1, varargs));
                }
            }
            ',' if depth == 1 => {
                commas += 1;
                any = true;
            }
            _ => {}
        }
        i += 1;
    }
    let _ = any;
    None
}

fn path_forward_connected(
    path: &[(String, u32, String)],
    defs: &BTreeMap<String, Vec<(String, u32)>>,
    file_calls: &BTreeMap<String, Vec<(String, u32)>>,
    contents: &BTreeMap<String, String>,
    scope_imports: &BTreeMap<String, std::collections::BTreeSet<String>>,
    scope_unresolved: &std::collections::BTreeSet<String>,
) -> bool {
    if path.len() < 2 {
        return true;
    }
    for w in path.windows(2) {
        let (af, al, an) = (&w[0].0, w[0].1, w[0].2.clone());
        let bn = w[1].2.clone();
        if af == &w[1].0 && al == w[1].1 {
            continue;
        }
        let Some(def_line) = def_line_for_name(defs, af, &an, al) else {
            return false;
        };
        let total = contents.get(af).map(|c| c.lines().count() as u32).unwrap_or(def_line);
        let end = defs
            .get(af)
            .and_then(|ds| ds.iter().filter(|(_, l)| *l > def_line).map(|(_, l)| *l).min())
            .map(|n| n.saturating_sub(1))
            .unwrap_or(total)
            .max(def_line);
        let Some(calls) = file_calls.get(af) else {
            return false;
        };
        let call_line = calls
            .iter()
            .filter(|(n, l)| n == &bn && *l > def_line && *l <= end)
            .map(|(_, l)| *l)
            .min();
        let Some(call_line) = call_line else {
            return false;
        };
        // 参数个数校验（重载区分）：调用实参个数必须与被调定义的形参个数匹配
        // （varargs 允许 >= 形参-1），否则是名字冲突伪边。
        let caller_line_text = contents
            .get(af)
            .and_then(|c| c.lines().nth(call_line.saturating_sub(1) as usize));
        let bf = &w[1].0;
        let target_def_line = def_line_for_name(defs, bf, &bn, w[1].1);
        let target_line_text = target_def_line.and_then(|dl| {
            contents
                .get(bf)
                .and_then(|c| c.lines().nth(dl.saturating_sub(1) as usize))
        });
        if let (Some(call_text), Some(def_text)) = (caller_line_text, target_line_text) {
            if let (Some((call_args, _)), Some((def_params, varargs))) =
                (paren_params(call_text, &bn), paren_params(def_text, &bn))
            {
                let ok = if varargs {
                    call_args + 1 >= def_params
                } else {
                    call_args == def_params
                };
                if !ok {
                    return false;
                }
            }
        }
        // 目标文件必须在作用域内（同文件/同目录/被 caller import），否则是名字冲突伪边；
        // import 解析不完整的文件不做此项限制（避免误删真实跨包调用）。
        if af != &w[1].0 && !scope_unresolved.contains(af) {
            let same_dir = af.rsplit_once('/').map(|(d, _)| d) == w[1].0.rsplit_once('/').map(|(d, _)| d);
            let imported = scope_imports
                .get(af)
                .map(|s| s.contains(&w[1].0))
                .unwrap_or(false);
            if !same_dir && !imported {
                return false;
            }
        }
    }
    true
}

fn enclosing_def(defs: &[(String, u32)], line: u32) -> Option<(String, u32)> {
    let mut best: Option<(String, u32)> = None;
    for (name, ln) in defs {
        if *ln <= line && best.as_ref().map(|(_, b)| *ln > *b).unwrap_or(true) {
            best = Some((name.clone(), *ln));
        }
    }
    best
}

/// 危险汇清单（首版：JS/TS/Java/Python）。
pub(crate) fn scan_sinks(files: &[(String, String)]) -> Vec<Value> {
    scan_sinks_with(files, &[], true)
}

/// 附加词汇扫描：`extra` 来自 `chain learn` 的派生结果；`include_builtin=false` 时只用派生词汇
/// （用于验证"换靶不加内置 pattern 也能找到"，即泛化性）。
pub(crate) fn scan_sinks_with(
    files: &[(String, String)],
    extra: &[(String, String)],
    include_builtin: bool,
) -> Vec<Value> {
    const PATTERNS: [(&str, &[&str]); 10] = [
        (
            "exec",
            &[
                "child_process.exec",
                "execSync(",
                "spawnSync(",
                "execFile(",
                "Runtime.getRuntime",
                "ProcessBuilder",
                "exec.Command(",
                "os.system(",
                "subprocess.",
            ],
        ),
        (
            "eval",
            &[
                "eval(",
                "new Function(",
                "Function(\"",
                "ScriptEngine",
                "vm.runInNewContext",
                "vm.runInThisContext",
            ],
        ),
        (
            "deserialize",
            &[
                "ObjectInputStream",
                "readObject(",
                "JSON.parse(",
                "yaml.load(",
                "pickle.loads(",
                "unserialize(",
                "readValue(",
                "parseObject(",
                "decodeReply(",
                "decodeAction(",
            ],
        ),
        (
            "reflect",
            &[
                "Class.forName(",
                "getDeclaredMethod(",
                "getMethod(",
                "newInstance(",
                "Module._load(",
                "process.binding(",
            ],
        ),
        (
            "file_write",
            &[
                "writeFile(",
                "writeFileSync(",
                "createWriteStream(",
                "Files.write(",
                "FileOutputStream",
                "os.WriteFile",
                "write_text(",
            ],
        ),
        (
            "sql",
            &["executeQuery(", "createNativeQuery(", "rawQuery(", "knex.raw(", "db.query("],
        ),
        (
            "template",
            &[
                "render_template_string(",
                "compileTemplate(",
                "Handlebars.compile(",
                "nunjucks.renderString(",
                "ScriptEngine",
                "velocity.evaluate",
            ],
        ),
        (
            "ssrf",
            &[
                "axios.get(",
                "axios.post(",
                "fetch(",
                "http.get(",
                "https.get(",
                "requests.get(",
                "requests.post(",
                "HttpClient.newHttpClient(",
                "OkHttpClient",
            ],
        ),
        (
            "module_access",
            &["moduleExports[", "serverManifest[", "metadata[NAME]", "clientManifest["],
        ),
        (
            "jndi",
            &["InitialContext(", "new InitialDirContext(", "InitialDirContext("],
        ),
    ];
    use rayon::prelude::*;
    let indexed: Vec<(String, String)> = files.iter().take(max_index_files()).cloned().collect();
    let extra_owned: Vec<(String, String)> = extra.to_vec();
    let mut out: Vec<Value> = indexed
        .par_iter()
        .flat_map(|(path, content)| {
            let mut local: Vec<Value> = Vec::new();
            let lang = chain_language_of(path);
            if !matches!(lang, "js" | "ts" | "java" | "py" | "go") {
                return local;
            }
            for (idx, raw) in content.lines().enumerate() {
                if !is_code_line(raw) {
                    continue;
                }
                let expr: String = raw.trim().chars().take(160).collect();
                let is_compare = raw.contains("===")
                    || raw.contains("!==")
                    || raw.contains("==")
                    || raw.contains("!=");
                let mut hit = false;
                if include_builtin && !is_compare {
                    for (kind, pats) in PATTERNS.iter() {
                        if pats.iter().any(|p| raw.contains(p)) {
                            // module_access 只收动态键：`moduleExports['*']` 常量键、
                            // `name = metadata[NAME]` 纯赋值都不是动态取值
                            if *kind == "module_access" {
                                let is_const = raw.contains("moduleExports['")
                                    || raw.contains("moduleExports[\"")
                                    || raw.contains("clientManifest['")
                                    || raw.contains("serverManifest['");
                                let assign_before = raw
                                    .find("moduleExports[")
                                    .map(|pos| raw[..pos].contains('=') && !raw[..pos].contains("=="))
                                    .unwrap_or(false);
                                if is_const || assign_before {
                                    continue;
                                }
                            }
                            local.push(json!({
                                "kind": kind,
                                "file": path,
                                "line": (idx + 1) as u32,
                                "expr": expr,
                                "language": lang,
                            }));
                            hit = true;
                            break;
                        }
                    }
                }
                // `metadata[NAME] === '*'` 这类比较不是动态取值，不能当 module_access 汇
                let is_compare = raw.contains("===")
                    || raw.contains("!==")
                    || raw.contains("==")
                    || raw.contains("!=");
                if !hit && !is_compare {
                    for (kind, pat) in extra_owned.iter() {
                        if raw.contains(pat.as_str()) {
                            local.push(json!({
                                "kind": kind,
                                "file": path,
                                "line": (idx + 1) as u32,
                                "expr": expr,
                                "language": lang,
                                "derived_from": "learned_vocab",
                            }));
                            break;
                        }
                    }
                }
            }
            local
        })
        .collect();
    out.sort_by(|a, b| {
        (
            a["file"].as_str().unwrap_or(""),
            a["line"].as_u64().unwrap_or(0),
            a["kind"].as_str().unwrap_or(""),
        )
            .cmp(&(
                b["file"].as_str().unwrap_or(""),
                b["line"].as_u64().unwrap_or(0),
                b["kind"].as_str().unwrap_or(""),
            ))
    });
    out
}

/// 库级入口：框架内部"请求可达"的导出函数（框架 CVE 取证用）。
pub(crate) const LIB_ENTRY_NAMES: [&str; 8] = [
    "decodeReply",
    "decodeReplyFromBusboy",
    "decodeAction",
    "decodeFormState",
    "createRequest",
    "renderToReadableStream",
    "createFromFetch",
    "createFromReadableStream",
];

/// 入口清单：method 级路由（文件/行）+ 覆盖判定（来自端点表）。
pub(crate) fn collect_entries(files: &[(String, String)], id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (path, content) in files.iter().take(max_index_files()) {
        let lang = chain_language_of(path);
        if !(path.ends_with(".java") || matches!(lang, "js" | "ts")) {
            continue;
        }
        let scan = scan_routes_in_file_prefixed(path, content, "", id, "");
        for r in scan.routes {
            if r.get("scope").and_then(|v| v.as_str()) != Some("method") {
                continue;
            }
            out.push(json!({
                "file": path,
                "line": r.get("line").and_then(|v| v.as_u64()).unwrap_or(0),
                "method": r.get("http_method").and_then(|v| v.as_str()).unwrap_or("ANY"),
                "route": r.get("route").and_then(|v| v.as_str()).unwrap_or(""),
                "entry_kind": "http",
            }));
        }
        // 库级入口：request-facing 导出函数
        for (name, line) in definitions(content, lang) {
            if LIB_ENTRY_NAMES.contains(&name.as_str()) {
                out.push(json!({
                    "file": path,
                    "line": line,
                    "method": "LIB",
                    "route": name,
                    "entry_kind": "library_entry",
                }));
            }
        }
    }
    out
}

/// 入口鉴权映射：(文件, 映射行) → verdict（来自端点表，保证与 `explain_route` 同源）。
pub(crate) fn auth_map(root: &Path, files: &[(String, String)], id: &str) -> BTreeMap<(String, u32), String> {
    let table = compute_routes(root, files, id, false, &RouteFilter::default(), false);
    let mut out = BTreeMap::new();
    if let Some(routes) = table.data.get("routes").and_then(|v| v.as_array()) {
        for r in routes {
            if r.get("scope").and_then(|v| v.as_str()) != Some("method") {
                continue;
            }
            let file = r.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let line = r.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let verdict = r
                .get("global_coverage")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            out.insert((file, line), verdict);
        }
    }
    out
}

/// 按行区间扫描守卫（入口装饰器行 → handler 定义行），避免扫到相邻函数的装饰器。
pub(crate) fn guards_range(content: &str, start: u32, end: u32, file: &str) -> Vec<Value> {
    const GUARDS: [(&str, &[&str]); 9] = [
        ("auth_check", &["@SaCheckLogin", "@PreAuthorize", "@RequiresPermissions", "@RequiresRoles", "isAuthenticated(", "checkLogin(", "getLoginId(", "requireAuth", "login_required", "jwt_required", "permission_required", "requires_auth", "get_current_user", "@requires_login", "Depends(get_current_user", "Depends(current_user", "current_user.is_authenticated"]),
        ("permission_check", &["@CheckPassword", "@StoragePermissionCheck", "checkRole(", "hasRole(", "hasPermission(", "isAdmin"]),
        ("allowlist", &["allowlist", "whitelist", "ALLOWED_", "startsWith(", "matchesPattern", "Pattern.compile", "hasOwnProperty", "checkAutoType", "ObjectInputFilter", "allowTypes", "denyList", "acceptList", "autoTypeSupport"]),
        ("sanitize", &["sanitize", "escapeHtml", "escape(", "encodeURI", "HtmlUtils", "StringEscapeUtils"]),
        ("signature", &["validSignature", "hmac", "HmacSHA", "constantTimeEqual"]),
        ("bounds", &["maxLength", "Preconditions", "assertNotNull"]),
        ("path_check", &["filepath.Clean", "path.Clean", ".normalize(", "getCanonicalPath", "secureJoin"]),
        ("ssrf_check", &["isAllowedHost", "hostAllowlist", "ALLOWED_HOSTS", "validateUrl", "isInternalAddress", "InetAddress", "getByName("]),
        ("template_escape", &["autoescape", "escapeHtml", "html.EscapeString"]),
    ];
    let lines: Vec<&str> = content.lines().collect();
    let lo = start.saturating_sub(2) as usize;
    let hi = (end as usize + 2).min(lines.len());
    let mut out = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for i in lo..hi {
        let Some(raw) = lines.get(i) else { continue };
        if !is_code_line(raw) {
            continue;
        }
        for (kind, pats) in GUARDS.iter() {
            if pats.iter().any(|p| raw.contains(p)) && !seen.contains(kind) {
                seen.insert(kind);
                out.push(json!({
                    "kind": kind,
                    "file": file,
                    "line": (i + 1) as u32,
                    "verdict": "partial",
                    "evidence": raw.trim().chars().take(120).collect::<String>(),
                }));
            }
        }
    }
    out
}

pub(crate) fn guards_in(content: &str, center: u32, file: &str) -> Vec<Value> {
    const GUARDS: [(&str, &[&str]); 9] = [
        ("auth_check", &["@SaCheckLogin", "@PreAuthorize", "@RequiresPermissions", "@RequiresRoles", "isAuthenticated(", "checkLogin(", "getLoginId(", "requireAuth", "login_required", "jwt_required", "permission_required", "requires_auth", "get_current_user", "@requires_login", "Depends(get_current_user", "Depends(current_user", "current_user.is_authenticated"]),
        ("permission_check", &["@CheckPassword", "@StoragePermissionCheck", "checkRole(", "hasRole(", "hasPermission(", "isAdmin"]),
        ("allowlist", &["allowlist", "whitelist", "ALLOWED_", "startsWith(", "matchesPattern", "Pattern.compile", "hasOwnProperty", "checkAutoType", "ObjectInputFilter", "allowTypes", "denyList", "acceptList", "autoTypeSupport"]),
        ("sanitize", &["sanitize", "escapeHtml", "escape(", "encodeURI", "HtmlUtils", "StringEscapeUtils"]),
        ("signature", &["validSignature", "hmac", "HmacSHA", "constantTimeEqual"]),
        ("bounds", &["maxLength", "Preconditions", "assertNotNull"]),
        ("path_check", &["filepath.Clean", "path.Clean", ".normalize(", "getCanonicalPath", "secureJoin"]),
        ("ssrf_check", &["isAllowedHost", "hostAllowlist", "ALLOWED_HOSTS", "validateUrl", "isInternalAddress", "InetAddress", "getByName("]),
        ("template_escape", &["autoescape", "escapeHtml", "html.EscapeString"]),
    ];
    let lines: Vec<&str> = content.lines().collect();
    let start = center.saturating_sub(4) as usize;
    let end = ((center + 30) as usize).min(lines.len());
    let mut out = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for i in start..end {
        let Some(raw) = lines.get(i) else { continue };
        if !is_code_line(raw) {
            continue;
        }
        for (kind, pats) in GUARDS.iter() {
            if pats.iter().any(|p| raw.contains(p)) && !seen.contains(kind) {
                seen.insert(kind);
                out.push(json!({
                    "kind": kind,
                    "file": file,
                    "line": (i + 1) as u32,
                    "verdict": "partial",
                    "evidence": raw.trim().chars().take(120).collect::<String>(),
                }));
            }
        }
    }
    out
}

pub(crate) fn fnv_chain_id(sink_file: &str, sink_line: u32, steps: &[Value]) -> String {
    let src = format!(
        "{}|{}|{}",
        sink_file,
        sink_line,
        steps
            .iter()
            .map(|s| format!(
                "{}:{}",
                s.get("file").and_then(|v| v.as_str()).unwrap_or(""),
                s.get("line").and_then(|v| v.as_u64()).unwrap_or(0)
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    format!("CH-{}", &stable_hash(&src)[..8])
}

/// 生成候选链（只保留"能到入口"的链）。
#[allow(dead_code)]
pub(crate) fn candidates_legacy(
    files: &[(String, String)],
    entries: &[Value],
    auth: &BTreeMap<(String, u32), String>,
    sink_kind: Option<&str>,
    entry_filter: Option<&str>,
    vocab: Option<&Value>,
    include_builtin_sinks: bool,
    limit: usize,
) -> (Vec<Value>, BTreeMap<String, usize>) {
    // 入口扩展：Next.js 隐式入口（'use server' / route.ts）+ 词表派生入口
    let mut entries: Vec<Value> = entries.to_vec();
    entries.extend(chain_vocab::nextjs_entries(files));
    if let Some(v) = vocab {
        if let Some(names) = v.get("entry_names").and_then(|x| x.as_array()) {
            for n in names.iter().take(200) {
                let name = n.get("name").and_then(|x| x.as_str()).unwrap_or("");
                let file = n.get("file").and_then(|x| x.as_str()).unwrap_or("");
                let line = n.get("line").and_then(|x| x.as_u64()).unwrap_or(0);
                if name.is_empty() || file.is_empty() {
                    continue;
                }
                const REQUEST_STEMS: [&str; 12] = [
                    "decode", "action", "request", "handler", "route", "render", "create",
                    "fetch", "stream", "dispatch", "endpoint", "invoke",
                ];
                let lower = name.to_ascii_lowercase();
                if !REQUEST_STEMS.iter().any(|s| lower.contains(s)) {
                    continue;
                }
                entries.push(json!({
                    "file": file,
                    "line": line,
                    "method": "LIB",
                    "route": name,
                    "entry_kind": "library_entry",
                }));
            }
        }
    }
    // 附加汇模式（来自派生词表）
    let extra_sinks: Vec<(String, String)> = vocab
        .and_then(|v| v.get("sink_patterns").and_then(|x| x.as_array()))
        .map(|arr| {
            arr.iter()
                .filter_map(|p| {
                    let kind = p.get("kind").and_then(|x| x.as_str())?;
                    let pat = p.get("pattern").and_then(|x| x.as_str())?;
                    Some((kind.to_string(), pat.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let imports = chain_vocab::import_graph(files);
    let (scope_imports, scope_unresolved) = super::probe::build_imports(files);
    let mut defs: BTreeMap<String, Vec<(String, u32)>> = BTreeMap::new();
    let mut call_sites: BTreeMap<String, Vec<(String, u32, bool)>> = BTreeMap::new();
    let mut file_calls: BTreeMap<String, Vec<(String, u32)>> = BTreeMap::new();
    let mut contents: BTreeMap<String, String> = BTreeMap::new();
    for (path, content) in files.iter().take(max_index_files()) {
        let lang = chain_language_of(path);
        if !matches!(lang, "js" | "ts" | "java" | "py" | "go") {
            continue;
        }
        let file_defs = definitions(content, lang);
        for (name, line, member, _install, _ctor) in calls(content) {
            // 跳过"函数声明行被当成同名调用"的伪边（与探针口径一致）
            if file_defs.iter().any(|(n, l)| n == &name && *l == line) {
                continue;
            }
            file_calls.entry(path.clone()).or_default().push((name.clone(), line));
            call_sites.entry(name).or_default().push((path.clone(), line, member));
        }
        defs.insert(path.clone(), file_defs);
        contents.insert(path.clone(), content.clone());
    }

    // entry 映射行 → handler 定义（同文件下方最近定义）
    let mut handler_of: BTreeMap<(String, u32), (String, u32, String, Value)> = BTreeMap::new();
    for e in entries.iter() {
        let file = e.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let line = e.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let Some(ds) = defs.get(&file) else { continue };
        // 优先按**入口名**在文件里找定义（词表/框架入口给的是函数名，行号可能是导出语句行）；
        // 找不到再退化为"映射注解下方最近的函数定义"。
        let route_name = e.get("route").and_then(|v| v.as_str()).unwrap_or("");
        let by_name: Option<(String, u32)> = if route_name.is_empty() {
            None
        } else {
            ds.iter()
                .find(|(n, _)| n == route_name)
                .map(|(n, l)| (n.clone(), *l))
        };
        let mut best: Option<(String, u32)> = by_name;
        if best.is_none() {
            for (name, ln) in ds {
                if *ln >= line && best.as_ref().map(|(_, b)| *ln < *b).unwrap_or(true) {
                    best = Some((name.clone(), *ln));
                }
            }
        }
        if let Some((name, ln)) = best {
            let entry_kind = e.get("entry_kind").and_then(|v| v.as_str()).unwrap_or("http");
            let auth_v = if entry_kind == "library_entry" {
                "unknown".to_string()
            } else {
                auth.get(&(file.clone(), line)).cloned().unwrap_or_default()
            };
            handler_of.insert(
                (file.clone(), line),
                (file.clone(), ln, name, json!({
                    "kind": "http",
                    "method": e.get("method").cloned().unwrap_or(Value::Null),
                    "route": e.get("route").cloned().unwrap_or(Value::Null),
                    "file": file,
                    "mapping_line": line,
                    "handler_line": ln,
                    "entry_kind": e.get("entry_kind").cloned().unwrap_or(Value::Null),
                    "auth": auth_v,
                })),
            );
        }
    }
    // handler 定义 → entry 信息（用于 BFS 命中判断）
    let mut entry_by_handler: BTreeMap<(String, u32), Value> = BTreeMap::new();
    for (_k, (hf, hl, _name, info)) in handler_of.iter() {
        entry_by_handler.insert((hf.clone(), *hl), info.clone());
    }

    let mut stats: BTreeMap<String, usize> = BTreeMap::new();
    let sinks = scan_sinks_with(files, &extra_sinks, include_builtin_sinks);
    stats.insert("sinks_scanned".to_string(), sinks.len());
    let mut chains: Vec<Value> = Vec::new();
    let mut reached = 0usize;

    for sink in sinks.iter() {
        if let Some(k) = sink_kind {
            if sink.get("kind").and_then(|v| v.as_str()) != Some(k) {
                continue;
            }
        }
        let file = sink.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let line = sink.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let Some(ds) = defs.get(&file) else { continue };
        let Some((sink_def, sink_def_line)) = enclosing_def(ds, line) else { continue };

        // 汇所在函数本身即入口（Spring Controller 方法直接调 exec、Next Server Action 直接执行命令）
        let direct_entry: Option<Vec<(String, u32, String)>> =
            if entry_by_handler.contains_key(&(file.clone(), sink_def_line)) {
                Some(vec![
                    (file.clone(), sink_def_line, sink_def.clone()),
                    (file.clone(), sink_def_line, sink_def.clone()),
                ])
            } else {
                None
            };

        let mut visited: BTreeSet<(String, u32)> = BTreeSet::new();
        let mut queue: VecDeque<(String, u32, String, Vec<(String, u32, String)>)> = VecDeque::new();
        queue.push_back((
            file.clone(),
            sink_def_line,
            sink_def.clone(),
            vec![(file.clone(), sink_def_line, sink_def.clone())],
        ));
        let mut found: Vec<(Vec<(String, u32, String)>, Vec<Value>, Value)> = Vec::new();

        if let Some(p) = direct_entry {
            let entry_info = entry_by_handler
                .get(&(file.clone(), sink_def_line))
                .cloned()
                .unwrap_or(Value::Null);
            found.push((p, Vec::new(), entry_info));
        }
        if found.is_empty() {
        while let Some((cur_file, cur_line, cur_name, path)) = queue.pop_front() {
            if visited.contains(&(cur_file.clone(), cur_line)) {
                continue;
            }
            visited.insert((cur_file.clone(), cur_line));
            let is_sink_self = cur_file == sink.get("file").and_then(|v| v.as_str()).unwrap_or("")
                && cur_line == sink.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let is_sink_def = cur_file == file && cur_line == sink_def_line;
            if !is_sink_self
                && !is_sink_def
                && entry_by_handler.contains_key(&(cur_file.clone(), cur_line))
                && found.len() < 12
            {
                let entry_info = entry_by_handler
                    .get(&(cur_file.clone(), cur_line))
                    .cloned()
                    .unwrap_or(Value::Null);
                found.push((path.clone(), Vec::new(), entry_info));
                // 继续搜索：同一 sink 可能同时可达客户端与服务端入口（框架 CVE 取证需要后者）
                continue;
            }
            if path.len() >= MAX_DEPTH {
                if found.is_empty() {
                    found.push((
                        path.clone(),
                        vec![json!({
                            "kind": "ambiguous_chain",
                            "at": format!("{}:{}", cur_file, cur_line),
                            "candidates": [],
                            "confidence": "low",
                        })],
                        Value::Null,
                    ));
                }
                continue;
            }
            let mut next: Vec<(String, u32, bool)> = call_sites
                .get(&cur_name)
                .map(|v| v.clone())
                .unwrap_or_default();
            next.retain(|(f, l, _)| !(f == &cur_file && *l == cur_line));
            next.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));
            next.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
            let truncated = next.len() > MAX_FANOUT;
            if truncated {
                next.truncate(MAX_FANOUT);
            }
            if next.is_empty() {
                continue;
            }
            for (site_file, site_line, _member) in next {
                let Some(site_defs) = defs.get(&site_file) else { continue };
                let Some((caller_name, caller_line)) = enclosing_def(site_defs, site_line) else {
                    continue;
                };
                let mut p = path.clone();
                p.push((site_file.clone(), site_line, caller_name.clone()));
                queue.push_back((site_file, caller_line, caller_name, p));
            }
            if truncated {
                // 记录扇出截断（不影响继续搜索，但要在最终档里标注）
                let _ = cur_name;
            }
        }
        }

        // 前向边校验：候选链的相邻步骤必须在 caller 函数体内存在对该函数的真实调用，
        // 否则只是名字级伪边（同文件重载/声明行伪调用），直接丢弃。
        let before = found.len();
        found.retain(|(path, _, _)| {
            path_forward_connected(path, &defs, &file_calls, &contents, &scope_imports, &scope_unresolved)
        });
        let dropped = before.saturating_sub(found.len());
        *stats.entry("dropped_unverifiable".to_string()).or_default() += dropped;

        if found.is_empty() {
            // 无法把汇连到入口：输出"汇级链档"，断点显式（framework_magic / ambiguous_chain）。
            // 框架回调/异步调度（如 RSC 的 createResponse→requireModule）本身不在静态调用图上，
            // 诚实做法是给出候选入口并标注断点，而不是静默丢弃或假装可达。
            let cand_entries: Vec<Value> = entries
                .iter()
                .filter(|e| {
                    matches!(
                        e.get("entry_kind").and_then(|v| v.as_str()),
                        Some("library_entry") | Some("server_action") | Some("route_handler")
                    )
                })
                .take(3)
                .map(|e| {
                    json!({
                        "route": e.get("route").cloned().unwrap_or(Value::Null),
                        "file": e.get("file").cloned().unwrap_or(Value::Null),
                        "line": e.get("line").cloned().unwrap_or(Value::Null),
                        "entry_kind": e.get("entry_kind").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            let cands: Vec<String> = cand_entries
                .iter()
                .filter_map(|c| c.get("route").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
                .collect();
            let kind = if cands.is_empty() { "ambiguous_chain" } else { "framework_magic" };
            let mut guards: Vec<Value> = Vec::new();
            if let Some(c) = contents.get(&file) {
                guards.extend(guards_in(c, line, &file));
            }
            let reasons: Vec<String> = vec![kind.to_string(), "unmodelled_framework".to_string()];
            chains.push(json!({
                "schema": DOSSIER_SCHEMA,
                "chain_id": fnv_chain_id(&file, line, &[json!({"file": file, "line": line})]),
                "entry": Value::Null,
                "sink": {
                    "kind": sink.get("kind").cloned().unwrap_or(Value::Null),
                    "file": sink.get("file").cloned().unwrap_or(Value::Null),
                    "line": sink.get("line").cloned().unwrap_or(Value::Null),
                    "expr": sink.get("expr").cloned().unwrap_or(Value::Null),
                },
                "steps": [{
                    "file": file,
                    "line": line,
                    "symbol": sink_def,
                    "role": "sink",
                    "certainty": "certain",
                }],
                "guards": guards,
                "breakpoints": [{
                    "kind": kind,
                    "at": format!("{}:{}", file, line),
                    "candidates": cands,
                    "candidate_entries": cand_entries,
                    "confidence": "low",
                }],
                "uncertainty": {"level": "high", "reasons": reasons},
                "verdict_candidates": ["reachable_unauthenticated", "reachable_authenticated", "unreachable"],
                "falsify": [format!("ctx-audit chain <ROOT> --id {}", fnv_chain_id(&file, line, &[]))],
                "steps_total": 1,
            }));
            continue;
        }
        let found_paths = found;
        for (path, mut breakpoints, entry_info) in found_paths {
        reached += 1;
        let mut rev = path;
        rev.reverse();
        let mut steps: Vec<Value> = Vec::new();
        for (i, (f, l, name)) in rev.iter().enumerate() {
            let role = if i == 0 {
                "source"
            } else if i + 1 == rev.len() {
                "sink"
            } else {
                "propagation"
            };
            let certainty = if i == 0 { "certain" } else { "inferred" };
            steps.push(json!({
                "file": f,
                "line": l,
                "symbol": name,
                "role": role,
                "certainty": certainty,
            }));
        }
        // 用 import 图重估每一步的确定性：同文件/被 import ⇒ certain；同名唯一定义 ⇒ inferred；否则 ambiguous
        for i in 1..steps.len() {
            let caller_file = steps[i - 1]["file"].as_str().unwrap_or("").to_string();
            let callee_file = steps[i]["file"].as_str().unwrap_or("").to_string();
            let symbol = steps[i]["symbol"].as_str().unwrap_or("").to_string();
            let same_file = caller_file == callee_file;
            let imported = imports
                .get(&caller_file)
                .map(|t| t.contains(&callee_file))
                .unwrap_or(false);
            let def_count = defs
                .values()
                .filter(|v| v.iter().any(|(n, _)| n == &symbol))
                .count();
            let conf = if same_file || imported {
                "certain"
            } else if def_count <= 1 {
                "inferred"
            } else {
                "ambiguous"
            };
            if let Some(obj) = steps[i].as_object_mut() {
                obj.insert("certainty".to_string(), json!(conf));
            }
        }
        if steps.len() > MAX_STEPS {
            steps.truncate(MAX_STEPS);
            breakpoints.push(json!({
                "kind": "ambiguous_chain",
                "at": format!("{}:{}", file, line),
                "candidates": [],
                "confidence": "low",
            }));
        }
        // sink 步用真实汇行替换（若最后一步不是汇行）
        if let Some(last) = steps.last_mut() {
            if let Some(obj) = last.as_object_mut() {
                obj.insert("line".to_string(), json!(line));
                obj.insert("expr".to_string(), sink.get("expr").cloned().unwrap_or(Value::Null));
            }
        }

        // 入口信息与守卫
        let entry = entry_info;
        let mut guards: Vec<Value> = Vec::new();
        if let Some(c) = contents.get(&rev[0].0) {
            guards.extend(guards_in(c, rev[0].1, &rev[0].0));
        }
        if let Some(c) = contents.get(&file) {
            guards.extend(guards_in(c, line, &file));
        }

        let mut reasons: Vec<String> = Vec::new();
        for b in breakpoints.iter() {
            if let Some(k) = b.get("kind").and_then(|v| v.as_str()) {
                if !reasons.iter().any(|r| r == k) {
                    reasons.push(k.to_string());
                }
            }
        }
        // 入口鉴权未知也算不确定性来源
        let entry_auth = entry
            .get("auth")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if entry_auth == "unknown" && !reasons.iter().any(|r| r == "unmodelled_framework") {
            reasons.push("unmodelled_framework".to_string());
        }
        let level = if breakpoints.is_empty() { "medium" } else { "high" };

        chains.push(json!({
            "schema": DOSSIER_SCHEMA,
            "chain_id": fnv_chain_id(&file, line, &steps),
            "entry": entry,
            "sink": {
                "kind": sink.get("kind").cloned().unwrap_or(Value::Null),
                "file": sink.get("file").cloned().unwrap_or(Value::Null),
                "line": sink.get("line").cloned().unwrap_or(Value::Null),
                "expr": sink.get("expr").cloned().unwrap_or(Value::Null),
            },
            "steps": steps,
            "guards": guards,
            "breakpoints": breakpoints,
            "uncertainty": {"level": level, "reasons": reasons},
            "verdict_candidates": ["reachable_unauthenticated", "reachable_authenticated", "unreachable"],
            "falsify": [
                format!("ctx-audit chain <ROOT> --id {}", fnv_chain_id(&file, line, &steps)),
                "ctx-audit chain <ROOT> --list --sink <kind>".to_string()
            ],
            "steps_total": rev_len(&entry),
        }));
    }

    }
    // 可选：按入口过滤（如 `decodeReply` 只看服务端入口）
    if let Some(filter) = entry_filter {
        chains.retain(|c| {
            let e = &c["entry"];
            e["route"].as_str().map(|r| r.contains(filter)).unwrap_or(false)
                || e["file"].as_str().map(|f| f.contains(filter)).unwrap_or(false)
        });
    }

    // 排序：已连到入口的链优先（兜底档最后），再按入口鉴权/步数/位置
    chains.sort_by(|a, b| {
        let reached_a = !a["entry"].is_null() as u8;
        let reached_b = !b["entry"].is_null() as u8;
        let ua = a["entry"]["auth"].as_str().unwrap_or("unknown");
        let ub = b["entry"]["auth"].as_str().unwrap_or("unknown");
        let wa = if matches!(ua, "uncovered" | "no_global_match_found" | "unknown") { 0 } else { 1 };
        let wb = if matches!(ub, "uncovered" | "no_global_match_found" | "unknown") { 0 } else { 1 };
        reached_b.cmp(&reached_a).then_with(|| wa.cmp(&wb))
            .then_with(|| {
                a["steps"].as_array().map(|v| v.len()).unwrap_or(0)
                    .cmp(&b["steps"].as_array().map(|v| v.len()).unwrap_or(0))
            })
            .then_with(|| {
                a["sink"]["file"].as_str().unwrap_or("").cmp(b["sink"]["file"].as_str().unwrap_or(""))
            })
            .then_with(|| {
                a["sink"]["line"].as_u64().unwrap_or(0).cmp(&b["sink"]["line"].as_u64().unwrap_or(0))
            })
    });
    stats.insert("chains_found".to_string(), chains.len());
    stats.insert("sinks_reached".to_string(), reached);
    // 兜底档（entry=null）限量，避免淹没真实链
    let mut kept: Vec<Value> = Vec::new();
    let mut fallback = 0usize;
    for c in chains.into_iter() {
        if c["entry"].is_null() {
            if fallback >= 20 {
                continue;
            }
            fallback += 1;
        }
        kept.push(c);
    }
    let take = if limit == 0 { kept.len() } else { limit.min(kept.len()) };
    kept.truncate(take);
    (kept, stats)
}

fn rev_len(entry: &Value) -> usize {
    if entry.is_null() {
        0
    } else {
        1
    }
}

/// 链档 JSON 体积（用于预算检查）。
pub(crate) fn dossier_bytes(v: &Value) -> usize {
    serde_json::to_string(v).map(|s| s.len()).unwrap_or(0)
}

/// Markdown 渲染（人读）。
pub(crate) fn dossier_markdown(d: &Value) -> String {
    let mut s = String::new();
    let id = d["chain_id"].as_str().unwrap_or("");
    s.push_str(&format!("# 链档 {id}\n\n"));
    s.push_str(&format!("- schema: `{}`\n", d["schema"].as_str().unwrap_or("")));
    let e = &d["entry"];
    s.push_str(&format!(
        "- 入口: `{} {}` ({}:{}) auth={}\n",
        e["method"].as_str().unwrap_or("ANY"),
        e["route"].as_str().unwrap_or(""),
        e["file"].as_str().unwrap_or(""),
        e["handler_line"].as_u64().unwrap_or(0),
        e["auth"].as_str().unwrap_or("unknown"),
    ));
    let k = &d["sink"];
    s.push_str(&format!(
        "- 汇: `{}` ({}:{})\n",
        k["kind"].as_str().unwrap_or(""),
        k["file"].as_str().unwrap_or(""),
        k["line"].as_u64().unwrap_or(0),
    ));
    s.push_str(&format!("- 不确定度: {}\n", d["uncertainty"]["level"].as_str().unwrap_or("")));
    if let Some(rs) = d["uncertainty"]["reasons"].as_array() {
        let list: Vec<&str> = rs.iter().filter_map(|v| v.as_str()).collect();
        if !list.is_empty() {
            s.push_str(&format!("- 原因: {}\n", list.join(", ")));
        }
    }
    s.push_str("\n## 步骤\n\n| # | 角色 | 位置 | 符号 | 确定性 |\n|---|---|---|---|---|\n");
    if let Some(steps) = d["steps"].as_array() {
        for (i, st) in steps.iter().enumerate() {
            s.push_str(&format!(
                "| {} | {} | {}:{} | `{}` | {} |\n",
                i + 1,
                st["role"].as_str().unwrap_or(""),
                st["file"].as_str().unwrap_or(""),
                st["line"].as_u64().unwrap_or(0),
                st["symbol"].as_str().unwrap_or(""),
                st["certainty"].as_str().unwrap_or(""),
            ));
        }
    }
    s.push_str("\n## 守卫（启发式，需人工复核）\n\n");
    if let Some(gs) = d["guards"].as_array() {
        if gs.is_empty() {
            s.push_str("- （未读到校验形态）\n");
        }
        for g in gs {
            s.push_str(&format!(
                "- `{}` {}:{} — {}\n",
                g["kind"].as_str().unwrap_or(""),
                g["file"].as_str().unwrap_or(""),
                g["line"].as_u64().unwrap_or(0),
                g["evidence"].as_str().unwrap_or(""),
            ));
        }
    }
    s.push_str("\n## 断点（必须人工确认）\n\n");
    if let Some(bs) = d["breakpoints"].as_array() {
        if bs.is_empty() {
            s.push_str("- （无）\n");
        }
        for b in bs {
            s.push_str(&format!(
                "- `{}` @ {} confidence={}\n",
                b["kind"].as_str().unwrap_or(""),
                b["at"].as_str().unwrap_or(""),
                b["confidence"].as_str().unwrap_or(""),
            ));
        }
    }
    s.push_str("\n## 反证\n\n");
    if let Some(fs) = d["falsify"].as_array() {
        for f in fs {
            if let Some(cmd) = f.as_str() {
                s.push_str(&format!("```\n{cmd}\n```\n"));
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_skip_declaration_lines() {
        let src = "public class A {\n  public static <T> T parseObject(String s) { return null; }\n  public void run(String s) {\n    parseObject(s);\n    Object x = parseObject(s);\n    JSON.parseObject(s);\n  }\n}\n";
        let names: Vec<String> = calls(src).into_iter().map(|(n, _, _, _, _)| n).collect();
        assert!(!names.is_empty());
        // 声明行（第 2 行）不应产生 parseObject 调用
        let decl_line_calls = calls(src)
            .into_iter()
            .filter(|(n, l, _, _, _)| n == "parseObject" && *l == 2)
            .count();
        assert_eq!(decl_line_calls, 0, "names={names:?}");
        // 真实调用仍被保留（第 4/5/6 行）
        let real = calls(src)
            .into_iter()
            .filter(|(n, l, _, _, _)| n == "parseObject" && *l > 2)
            .count();
        assert!(real >= 2, "real={real}");
    }
}
