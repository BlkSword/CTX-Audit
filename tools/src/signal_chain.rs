// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 三角色信号链候选（trigger → path → effect）。
//!
//! 本模块只产**候选与证据**：不读规则/YAML、不产出 findings、不改 `scan` 的任何输出路径。
//! 它回答的问题是"这条写入路径是否具备三角色信号链形态"：
//!
//! 1. **触发点（trigger）** —— 循环界（或长度实参）必须是**数据来源**：
//!    结构体成员（`data.x` / `p->x`）、小写标识符、调用结果。
//!    **排除**纯数字表达式与纯大写宏（`8`、`PARAM_DEGREE` 不是"可被攻击者左右的量"），
//!    以及 `sizeof(...)` 这类编译期常量。触发点是常量 ⇒ 三角色不齐备。
//! 2. **路径（path）** —— 守卫检索**只能作用于本构造**：
//!    ① 本循环 / 本调用自身的条件式（含 `&&` 追加项、以及"守卫式提前返回"的 `if`）；
//!    ② 紧邻前 **3** 行；③ **绑定标识符本身**（本构造的长度变量不能被兄弟构造的守卫顶替）。
//!    **禁止大窗口**（如 ±80 行）：大窗口会让兄弟构造的守卫顶替本构造的守卫，
//!    从而漏掉真候选。
//! 3. **起效点（effect）** —— 写 sink 在循环内是否**累积**：
//!    `p += sprintf(p, …)` / 指针推进 ⇒ 累积，需要 `Σ每轮上界 ≤ 剩余容量`；
//!    每轮写回**同一基址**（`sprintf(buf, "item%i", i)`）⇒ 不累积，
//!    单轮有界即可。
//!    **保守口径**：格式串里的宽度/精度是最小值**不是上界**，因此只有
//!    "字面量格式 **且** 非累积 **且** 单轮"才判为"输出有界"，不升级。
//!
//! 三角色齐备 ⇒ `candidate`；缺任一 ⇒ `not_upgraded` 并给出 `cause`。
//!
//! ## 构造族与已验证原型
//!
//! * [`Construct::Loop`] —— 循环界构造。这是**已用已知答案验证过的原型规则集的忠实移植**：
//!   含 sink 首匹配语义、12 行 sink 窗口、`base = bound.rsplit('.')` 的守卫绑定口径。
//!   用于复现已验证的量级（某服务端实现的配置长度循环 → 9 条候选）。
//!   移植刻意使用**行/正则**而非 AST —— 判据是在该规则集上验证的，换机制会改变候选集合。
//! * [`Construct::LenArg`] —— 长度实参构造（判据本身要求"循环界**或**长度实参"）。
//!   同一套三角色判据作用在 sink 的长度实参上；因为单轮写入没有"累积"可判，
//!   起效点改用**目的地容量锚点**：目的地必须是本函数内可见的定长数组
//!   （`char dst[64]`），否则不升级（宁少勿滥）。
//!
//! 两个构造族都**只登记、不判定漏洞真值**：最终判定由人/LLM 依据证据做。

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// 候选/证据的来源标签（写进 `provenance`）。
pub const SIGNAL_CHAIN_PROVENANCE: &[&str] = &[
    "fix-pattern/signal-chain",
    "heuristic/line-regex",
    "roles/trigger+path+effect",
];

/// 三角色信号链的 schema 版本。
pub const SIGNAL_CHAIN_SCHEMA: &str = "ctx-audit/signal-chain/v1";

/// 构造族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Construct {
    /// 循环界构造（原型已验证路径）。
    Loop,
    /// 长度实参构造。
    LenArg,
}

impl Construct {
    pub fn as_str(&self) -> &'static str {
        match self {
            Construct::Loop => "loop",
            Construct::LenArg => "lenarg",
        }
    }
}

/// 要扫描哪些构造族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstructSet {
    All,
    Loop,
    LenArg,
}

impl ConstructSet {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" | "both" => Some(ConstructSet::All),
            "loop" | "loops" => Some(ConstructSet::Loop),
            "lenarg" | "len-arg" | "lenarg-only" => Some(ConstructSet::LenArg),
            _ => None,
        }
    }

    pub fn includes(&self, c: Construct) -> bool {
        match self {
            ConstructSet::All => true,
            ConstructSet::Loop => c == Construct::Loop,
            ConstructSet::LenArg => c == Construct::LenArg,
        }
    }
}

/// 扫描选项。
#[derive(Debug, Clone)]
pub struct SignalChainOptions {
    pub constructs: ConstructSet,
    /// 最多扫描多少个源文件（0 = 不限）。用于大仓快速取样。
    pub max_files: usize,
}

impl Default for SignalChainOptions {
    fn default() -> Self {
        Self {
            constructs: ConstructSet::All,
            max_files: 0,
        }
    }
}

/// 触发点角色。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    /// 被检验的量（循环界表达式或长度实参表达式）。
    pub expr: String,
    /// `constant` | `struct-member` | `call-result` | `param` | `identifier`
    pub origin: String,
    /// `none`（攻击者不可左右）| `possible`（数据来源，可达性**未证明**）
    pub attacker_influence: String,
}

/// 路径角色：守卫证据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRole {
    pub guard_seen: bool,
    /// `none` | `own-condition` | `prev-3-lines` | `bound-identifier`
    pub guard_scope: String,
    /// 命中的守卫所在行（1-based）。
    pub guard_line: Option<usize>,
    /// 实际检索过的范围（证据：证明没有用大窗口）。
    pub searched: Vec<String>,
}

/// 起效点前置条件。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Precondition {
    pub expr: String,
    /// `unproven` | `satisfied` | `inconclusive`
    pub verdict: String,
}

/// 起效点角色。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Effect {
    pub sink: String,
    /// `oob_write` | `bounded_write` | `unknown_write`
    pub kind: String,
    /// 写指针是否在循环内推进（累积）。
    pub accumulating: bool,
    pub precondition: Precondition,
}

/// 一条信号链构造的候选与证据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalChainCandidate {
    pub file: String,
    pub line: usize,
    pub function: String,
    /// `loop` | `lenarg`
    pub construct: String,
    pub trigger: Trigger,
    pub path: PathRole,
    pub effect: Effect,
    /// `candidate` | `not_upgraded`
    pub verdict: String,
    /// 未升级原因：`trigger_constant` | `guard_in_scope` | `bounded_nonaccumulating` | `no_fixed_destination`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    /// 证据原文（该构造所在行，已去首尾空白）。
    pub evidence_line: String,
    pub provenance: Vec<String>,
    pub uncertainty: Vec<String>,
}

impl SignalChainCandidate {
    pub fn is_candidate(&self) -> bool {
        self.verdict == "candidate"
    }
}

/// 一次信号链扫描的报告。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalChainReport {
    pub schema: String,
    pub root: String,
    pub files_scanned: usize,
    pub constructs_scanned: usize,
    pub candidate_count: usize,
    pub not_upgraded_count: usize,
    /// 候选数按构造族拆分（与原型对齐时看 `loop` 一档）。
    pub candidate_count_by_construct: std::collections::BTreeMap<String, usize>,
    pub candidates: Vec<SignalChainCandidate>,
    pub not_upgraded: Vec<SignalChainCandidate>,
    pub provenance: Vec<String>,
    pub uncertainty: Vec<String>,
}

// ── 正则（编译期一次）────────────────────────────────────────────────

fn re_loop() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"for\s*\(([^;]*);\s*([^;]*);\s*([^)]*)\)").expect("loop regex")
    })
}

fn re_cond_cmp() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"([A-Za-z_]\w*)\s*(<=|<|>=|>)\s*([^&|)]+)").expect("cond regex"))
}

fn re_cmp_op() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:<=|<|>=|>)").expect("cmp op regex"))
}

/// 循环构造的 sink 集合 —— 与已验证原型完全一致（首匹配语义参与判定，不得增删）。
fn re_sink_loop() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\b(sprintf|vsprintf|strcpy|strcat|memcpy|memmove|snprintf)\s*\(")
            .expect("loop sink regex")
    })
}

/// 长度实参构造的 sink 集合（额外含 `__builtin_` 前缀与带长度实参的写法）。
fn re_sink_lenarg() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"\b(?:__builtin_)?(memcpy|memmove|memset|strncpy|strncat|bcopy|snprintf|vsnprintf)\s*\(",
        )
        .expect("lenarg sink regex")
    })
}

fn re_const_only() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[\s\d()+*\-]*$").expect("const regex"))
}

fn re_macro_only() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Z][A-Z0-9_]*$").expect("macro regex"))
}

fn re_upper_run() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Z][A-Z0-9_]{2,}").expect("upper regex"))
}

fn re_lower_or_underscore() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[a-z_]").expect("lower regex"))
}

fn re_sizeof_word() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bsizeof\b").expect("sizeof regex"))
}

/// 触发点判据里出现的"常量味道"记号（`sizeof` / 数字 / 大写宏）。
fn re_num_hit() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:sizeof\b|\b\d+\b|[A-Z][A-Z0-9_]{2,})").expect("num regex"))
}

fn re_ident() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"([A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*|\s*\.\s*[A-Za-z_]\w*)?)")
            .expect("ident regex")
    })
}

/// 定长数组声明：`char dst[64];`
fn re_array_decl() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"^\s*(?:static\s+)?(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:char|u_char|uint8_t|u8|wchar_t)\s+([A-Za-z_]\w*)\s*\[\s*([^\]\r\n]+?)\s*\]",
        )
        .expect("array decl regex")
    })
}

/// 同一行内的守卫式条件：`if (…) <sink>(…)`
fn re_same_line_if() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"if\s*\(([^)]*)\)[^;]*$").expect("same line if regex"))
}

fn re_any_if() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"if\s*\(([^)]*)\)").expect("any if regex"))
}

fn re_bailout_kw() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b(return|continue|goto|break)\b").expect("bailout regex"))
}

/// 每轮写入是否累积：`p += sprintf(p, …)`。
///
/// 注意：Rust `regex` crate **不支持反向引用**（`\1`），所以原型里的
/// `([A-Za-z_]\w*)\s*\+=\s*sink\s*\(\s*\1\b` 在这里拆成
/// "捕获两侧标识符再在代码里比较相等"，语义与原型等价。
fn accumulating_re(sink: &str) -> Option<Regex> {
    static CACHE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        KNOWN_SINKS
            .iter()
            .map(|s| {
                (
                    *s,
                    Regex::new(&format!(
                        r"([A-Za-z_]\w*)\s*\+=\s*{}\s*\(\s*([A-Za-z_]\w*)",
                        regex::escape(s)
                    ))
                    .expect("accumulating regex"),
                )
            })
            .collect()
    });
    cache
        .iter()
        .find(|(name, _)| *name == sink)
        .map(|(_, r)| r.clone())
}

/// 写指针是否在"同一基址"上推进（累积）。
fn is_accumulating(body: &str, sink: &str) -> bool {
    match accumulating_re(sink) {
        Some(re) => re.captures_iter(body).any(|c| {
            let lhs = c.get(1).map(|m| m.as_str()).unwrap_or("");
            let first_arg = c.get(2).map(|m| m.as_str()).unwrap_or("");
            !lhs.is_empty() && lhs == first_arg
        }),
        None => false,
    }
}

/// 是否"字面量格式串"：`sprintf(p, "` —— 用于保守口径的"输出有界"判定。
fn literal_format_re(sink: &str) -> Option<Regex> {
    static CACHE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| {
        KNOWN_SINKS
            .iter()
            .map(|s| {
                (
                    *s,
                    Regex::new(&format!(r#"{}\s*\(\s*[^,]+,\s*""#, regex::escape(s)))
                        .expect("literal format regex"),
                )
            })
            .collect()
    });
    cache
        .iter()
        .find(|(name, _)| *name == sink)
        .map(|(_, r)| r.clone())
}

/// 全部已知 sink 名（累积性/字面量格式两个判据都按名字取正则）。
const KNOWN_SINKS: &[&str] = &[
    "sprintf", "vsprintf", "strcpy", "strcat", "memcpy", "memmove", "snprintf", "vsnprintf",
    "memset", "strncpy", "strncat", "bcopy",
];

/// sink 的"长度实参"序号（1-based）。
fn length_arg_index(sink: &str) -> Option<usize> {
    match sink {
        "memcpy" | "memmove" | "memset" | "strncpy" | "strncat" | "bcopy" => Some(3),
        "snprintf" | "vsnprintf" => Some(2),
        _ => None,
    }
}

// ── 判据实现 ────────────────────────────────────────────────────────

/// 触发点角色：这个量是"可被攻击者左右的量"还是编译期常量？
///
/// 常量口径（与原型一致）：`sizeof(...)`、纯数字/运算符表达式、纯大写宏、纯宏表达式、
/// 字符串字面量 ⇒ `constant`。
fn trigger_origin(expr: &str) -> &'static str {
    let e = expr.trim();
    if e.is_empty() {
        return "constant";
    }
    if re_sizeof_word().is_match(e) || e.starts_with("sizeof") {
        return "constant";
    }
    if re_const_only().is_match(e) {
        return "constant";
    }
    if re_macro_only().is_match(e) {
        return "constant";
    }
    if re_upper_run().is_match(e) && !re_lower_or_underscore().is_match(e) {
        return "constant";
    }
    if e.starts_with('"') || e.starts_with('\'') {
        return "constant";
    }
    if e.contains("->") || e.contains('.') {
        "struct-member"
    } else if e.contains('(') {
        "call-result"
    } else if is_plain_identifier(e) {
        "identifier"
    } else {
        "identifier"
    }
}

fn is_plain_identifier(s: &str) -> bool {
    static R: OnceLock<Regex> = OnceLock::new();
    let r = R.get_or_init(|| Regex::new(r"^[A-Za-z_]\w*$").expect("plain ident regex"));
    r.is_match(s)
}

/// 绑定标识符：路径角色只能被**绑定标识符本身**的守卫顶替。
fn binding_ident(expr: &str) -> Option<String> {
    re_ident()
        .captures(expr)
        .map(|c| c.get(1).unwrap().as_str().replace(' ', "").replace('\t', ""))
}

/// 守卫判据（与原型一致）：标识符后跟比较，右值是 `sizeof`/数字/大写宏。
fn guard_hit(text: &str, ident: &str) -> bool {
    build_guard_regex(ident)
        .map(|r| r.is_match(text))
        .unwrap_or(false)
}

fn build_guard_regex(ident: &str) -> Option<Regex> {
    if ident.is_empty() {
        return None;
    }
    let needle = format!(
        r"\b{}\b[^\n]*?(?:<=|>=|<|>)\s*(?:sizeof|\d+|[A-Z_]{{3,}})",
        regex::escape(ident)
    );
    Regex::new(&needle).ok()
}

/// 带行号的守卫命中：返回命中的行在 `lines` 中的 1-based 相对位置。
fn guard_hit_line(lines: &[&str], ident: &str) -> Option<usize> {
    let r = build_guard_regex(ident)?;
    lines.iter().position(|l| r.is_match(l)).map(|i| i + 1)
}

/// 不要超过 N 行的"小窗口"：紧邻前 3 行。
const GUARD_PREV_LINES: usize = 3;

/// 在字符数组里做一个括号平衡的实参切分（从 `(` 的下标开始）。
/// 与原型同构：最外层 `(` 不计入实参，字符串字面量整体折叠成 `""`。
fn split_args(chars: &[char], start: usize) -> Vec<String> {
    let mut depth: i32 = 0;
    let mut cur = String::new();
    let mut args: Vec<String> = Vec::new();
    let mut i = start;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            cur.push_str("\"\"");
            i += 1;
            continue;
        }
        if c == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            cur.push_str("''");
            i += 1;
            continue;
        }
        if c == '(' || c == '[' || c == '{' {
            depth += 1;
            if depth == 1 {
                i += 1;
                continue;
            }
            cur.push(c);
            i += 1;
            continue;
        }
        if c == ')' || c == ']' || c == '}' {
            depth -= 1;
            if depth == 0 {
                args.push(cur);
                return args;
            }
            cur.push(c);
            i += 1;
            continue;
        }
        if c == ',' && depth == 1 {
            args.push(cur);
            cur = String::new();
            i += 1;
            continue;
        }
        if depth >= 1 {
            cur.push(c);
        }
        i += 1;
    }
    args.push(cur);
    args
}

/// 取 `text` 中 `from` 之后第一个 `(` 的实参列表。
fn args_after(text: &str, from_byte: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let Some(rel) = text[from_byte..].find('(') else {
        return Vec::new();
    };
    let open_byte = from_byte + rel;
    // 字节下标 → 字符下标（`(` 之前只可能有 ASCII 与多字节 UTF-8 注释）
    let mut char_idx = 0usize;
    for (b, _) in text.char_indices() {
        if b == open_byte {
            break;
        }
        char_idx += 1;
    }
    split_args(&chars, char_idx)
}

/// 注释行 / 预处理行：既不是函数定义头，也不该作为"函数起点"。
fn is_comment_or_preproc(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with('#')
}

/// 类型关键字（从形参里剔除，剩下的标识符视为形参名）。
const TYPE_KEYWORDS: &[&str] = &[
    "const", "volatile", "restrict", "static", "register", "extern", "inline", "unsigned",
    "signed", "void", "char", "short", "int", "long", "float", "double", "struct", "union",
    "enum", "bool", "_Bool", "size_t", "ssize_t", "wchar_t", "u_char", "u_short", "u_int",
    "u_long", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t",
    "int64_t", "u8", "u16", "u32", "u64", "FILE",
];

/// 函数上下文：所在函数名与该函数的形参名集合（仅作证据/来源标注，不参与判定）。
fn enclosing_function(lines: &[&str], idx: usize) -> (String, Vec<String>) {
    static HDR: OnceLock<Regex> = OnceLock::new();
    let hdr = HDR.get_or_init(|| {
        Regex::new(r"^([A-Za-z_][A-Za-z0-9_ \t\*]*?)\b([A-Za-z_]\w*)\s*\(([^;]*)\)\s*\{?\s*$")
            .expect("func hdr regex")
    });
    static WORD: OnceLock<Regex> = OnceLock::new();
    let word = WORD.get_or_init(|| Regex::new(r"[A-Za-z_]\w*").expect("word regex"));
    const CTRL: &[&str] = &[
        "if", "for", "while", "switch", "return", "sizeof", "do", "else", "defined",
    ];
    let lo = idx.saturating_sub(400);
    for j in (lo..idx).rev() {
        let line = lines[j];
        if line.trim().is_empty() || is_comment_or_preproc(line) {
            continue;
        }
        // 只认列 0 起的函数定义头（C 源码惯例；也避免把控制语句认成函数）
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(c) = hdr.captures(line) {
            let name = c.get(2).unwrap().as_str().to_string();
            if CTRL.contains(&name.as_str()) {
                continue;
            }
            let params = c
                .get(3)
                .map(|m| {
                    m.as_str()
                        .split(',')
                        .flat_map(|p| {
                            word.find_iter(p)
                                .map(|w| w.as_str().to_string())
                                .filter(|w| !TYPE_KEYWORDS.contains(&w.as_str()))
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return (name, params);
        }
    }
    ("<unknown>".to_string(), Vec::new())
}

/// 本函数内可见的定长数组声明：名字 → (行号, 容量表达式)。
fn fixed_arrays_in_function(
    lines: &[&str],
    idx: usize,
) -> std::collections::BTreeMap<String, (usize, String)> {
    let (start, _) = function_span(lines, idx);
    // 扫描范围＝**整个所在函数体**（而不是到 idx 为止）。构造锚点有时落在函数头那一行，
    // 此时 `take(idx)` 会让函数体内的定长数组声明全部落在范围外 ⇒ `dest_anchor=None`
    // ⇒ 误判 `no_fixed_destination` ⇒ 该升级的被漏掉（实测夹具 `expect_upgrade_tainted_len.c`
    // 的 `char dst[64]; memcpy(dst, src, n);` 就是这样被漏的）。
    let end = function_body_end(lines, start);
    let mut out = std::collections::BTreeMap::new();
    for (i, line) in lines.iter().enumerate().take(end).skip(start) {
        if let Some(c) = re_array_decl().captures(line) {
            let name = c.get(1).unwrap().as_str().to_string();
            let cap = c.get(2).unwrap().as_str().to_string();
            out.entry(name).or_insert((i + 1, cap));
        }
    }
    out
}

/// 从 `start`（函数头行）起做花括号配对，返回函数体结束后的行下标（配不上时回退到文件末）。
/// 用于把"目的地容量解析"的扫描范围限定在整个函数体内——见 `fixed_arrays_in_function` 的注释。
fn function_body_end(lines: &[&str], start: usize) -> usize {
    let mut depth: i32 = 0;
    let mut seen = false;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
                seen = true;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if seen && depth <= 0 {
            return (i + 1).min(lines.len());
        }
    }
    lines.len()
}

/// 粗略估出包含 `idx` 的函数的起始行。
fn function_span(lines: &[&str], idx: usize) -> (usize, usize) {    let lo = idx.saturating_sub(400);
    let mut start = lo;
    for j in (lo..idx).rev() {
        let line = lines[j];
        if line.is_empty() || is_comment_or_preproc(line) {
            continue;
        }
        if !line.starts_with(char::is_whitespace) && line.contains('(') {
            start = j;
            break;
        }
    }
    (start, idx)
}

fn provenance_for(construct: Construct) -> Vec<String> {
    let mut v: Vec<String> = SIGNAL_CHAIN_PROVENANCE.iter().map(|s| s.to_string()).collect();
    v.push(format!("construct/{}", construct.as_str()));
    v
}

fn base_uncertainty(construct: Construct) -> Vec<String> {
    let mut u = vec![
        "触发点的攻击者可达性未证明：本模块只判形态（数据来源 vs 编译期常量），不做污点/可达性证明"
            .to_string(),
        format!(
            "守卫检索被刻意裁剪为本构造（自身条件式 + 紧邻前 {} 行 + 绑定标识符）；范围之外的守卫未被采信",
            GUARD_PREV_LINES
        ),
    ];
    match construct {
        Construct::Loop => u.push(
            "循环构造的目的地容量未解析：只判'是否累积'，累积量上界需人工/LLM 复核".to_string(),
        ),
        Construct::LenArg => u.push(
            "长度实参构造要求目的地是本函数内可见的定长数组；单轮写入的容量关系仍需复核"
                .to_string(),
        ),
    }
    u
}

/// 扫描一个目录/文件，产出三角色信号链候选与证据。
pub fn scan_path(root: &Path, options: &SignalChainOptions) -> std::io::Result<SignalChainReport> {
    let mut files: Vec<PathBuf> = Vec::new();
    let start = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        collect_sources(root, &mut files)?;
        files.sort();
        files
    };
    let mut files_scanned = 0usize;
    let mut all: Vec<SignalChainCandidate> = Vec::new();
    for f in &start {
        if options.max_files > 0 && files_scanned >= options.max_files {
            break;
        }
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        files_scanned += 1;
        let rel = {
            let stripped = f.strip_prefix(root).unwrap_or(f).to_string_lossy().replace('\\', "/");
            if stripped.is_empty() {
                f.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| stripped.clone())
            } else {
                stripped
            }
        };
        let res = scan_source(&rel, &text, options);
        all.extend(res);
    }
    // 排序：文件 + 行 + 构造族，便于 diff 与人工复核
    all.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.construct.cmp(&b.construct))
    });
    let mut candidates = Vec::new();
    let mut not_upgraded = Vec::new();
    let mut by_construct: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for c in all {
        if c.is_candidate() {
            *by_construct.entry(c.construct.clone()).or_insert(0) += 1;
            candidates.push(c);
        } else {
            not_upgraded.push(c);
        }
    }
    let constructs_scanned = candidates.len() + not_upgraded.len();
    Ok(SignalChainReport {
        schema: SIGNAL_CHAIN_SCHEMA.to_string(),
        root: root.to_string_lossy().replace('\\', "/"),
        files_scanned,
        constructs_scanned,
        candidate_count: candidates.len(),
        not_upgraded_count: not_upgraded.len(),
        candidate_count_by_construct: by_construct,
        candidates,
        not_upgraded,
        provenance: SIGNAL_CHAIN_PROVENANCE.iter().map(|s| s.to_string()).collect(),
        uncertainty: vec![
            "本模块只产候选与证据，不改任何检测路径，不产出 findings".to_string(),
            "未升级项（not_upgraded）同样落盘：它们是'三角色不齐备'的证据，便于判定者复核判据本身"
                .to_string(),
        ],
    })
}

/// 原型口径的目录遍历：只收 `.c` / `.h`，跳过 `test/`、`tests/`、`contrib/` 与 `test_*`。
/// 刻意**不**做 gitignore 过滤 —— 与已验证原型的文件集合保持一致。
fn collect_sources(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            if matches!(name.as_str(), "test" | "tests" | "contrib") {
                continue;
            }
            collect_sources(&p, out)?;
        } else if ft.is_file()
            && (name.ends_with(".c") || name.ends_with(".h"))
            && !name.starts_with("test_")
        {
            out.push(p);
        }
    }
    Ok(())
}

/// 扫描单个源文件的文本。
pub fn scan_source(rel: &str, text: &str, options: &SignalChainOptions) -> Vec<SignalChainCandidate> {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::new();
    if options.constructs.includes(Construct::Loop) {
        scan_loops(rel, &lines, &mut out);
    }
    if options.constructs.includes(Construct::LenArg) {
        scan_lenargs(rel, &lines, &mut out);
    }
    out
}

fn scan_loops(rel: &str, lines: &[&str], out: &mut Vec<SignalChainCandidate>) {
    for (i, ln) in lines.iter().enumerate() {
        let Some(m) = re_loop().captures(ln) else {
            continue;
        };
        let cond = m.get(2).map(|x| x.as_str()).unwrap_or("");
        let Some(cm) = re_cond_cmp().captures(cond) else {
            continue;
        };
        let bound = cm.get(3).map(|x| x.as_str()).unwrap_or("").trim().to_string();
        if bound == "0" || bound == "1" {
            continue;
        }
        // sink 窗口：本行起 12 行（与原型一致，含首匹配语义）
        let body = lines[i..(i + 12).min(lines.len())].join("\n");
        let Some(sk) = re_sink_loop().captures(&body) else {
            continue;
        };
        let sink = sk.get(1).unwrap().as_str().to_string();
        let prev_lo = i.saturating_sub(GUARD_PREV_LINES);
        let prev: Vec<&str> = lines[prev_lo..i].to_vec();
        // 绑定口径与原型一致：取 `.` 之后的最后一段
        let base = bound.rsplit('.').next().unwrap_or(&bound).to_string();
        // ① 本构造自身条件式：比较项 ≥ 2 且含 sizeof/数字/大写宏 ⇒ 自带 clamp
        let loop_guard = re_cmp_op().find_iter(cond).count() >= 2 && re_num_hit().is_match(cond);
        let prev_hit_line = guard_hit_line(&prev, &base);
        let searched = vec![
            "own-condition".to_string(),
            format!("prev-{}lines", GUARD_PREV_LINES),
            "bound-identifier".to_string(),
        ];
        let (guard_seen, guard_scope, guard_line) = if loop_guard {
            (true, "own-condition".to_string(), Some(i + 1))
        } else if let Some(l) = prev_hit_line {
            (true, "prev-3-lines".to_string(), Some(prev_lo + l))
        } else {
            (false, "none".to_string(), None)
        };

        let (function, params) = enclosing_function(lines, i);
        let origin = trigger_origin(&bound);
        let accumulating = is_accumulating(&body, &sink);
        let literal_fmt = literal_format_re(&sink)
            .map(|r| r.is_match(&body))
            .unwrap_or(false);
        let dest = args_after(&body, sk.get(0).unwrap().end().saturating_sub(1))
            .first()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let (kind, pre_expr, pre_verdict) = if accumulating {
            (
                "oob_write".to_string(),
                format!(
                    "Σ(每轮写入上界) <= {} 的剩余容量",
                    dest.clone().unwrap_or_else(|| "<destination>".to_string())
                ),
                "unproven".to_string(),
            )
        } else if literal_fmt {
            (
                "bounded_write".to_string(),
                "字面量格式串 + 每轮写回同一基址（单轮有界）".to_string(),
                "satisfied".to_string(),
            )
        } else {
            (
                "unknown_write".to_string(),
                "写入量上界未解析".to_string(),
                "inconclusive".to_string(),
            )
        };

        let (verdict, cause) = if origin == "constant" {
            ("not_upgraded", Some("trigger_constant".to_string()))
        } else if guard_seen {
            ("not_upgraded", Some("guard_in_scope".to_string()))
        } else if !accumulating && literal_fmt {
            ("not_upgraded", Some("bounded_nonaccumulating".to_string()))
        } else {
            ("candidate", None)
        };

        let origin_label = if origin == "identifier" && params.contains(&bound) {
            "param"
        } else {
            origin
        };

        out.push(SignalChainCandidate {
            file: rel.to_string(),
            line: i + 1,
            function: function.clone(),
            construct: Construct::Loop.as_str().to_string(),
            trigger: Trigger {
                expr: bound.clone(),
                origin: origin_label.to_string(),
                attacker_influence: if origin == "constant" {
                    "none".to_string()
                } else {
                    "possible".to_string()
                },
            },
            path: PathRole {
                guard_seen,
                guard_scope,
                guard_line,
                searched,
            },
            effect: Effect {
                sink: sink.clone(),
                kind,
                accumulating,
                precondition: Precondition {
                    expr: pre_expr,
                    verdict: pre_verdict,
                },
            },
            verdict: verdict.to_string(),
            cause,
            evidence_line: ln.trim().to_string(),
            provenance: provenance_for(Construct::Loop),
            uncertainty: base_uncertainty(Construct::Loop),
        });
    }
}

fn scan_lenargs(rel: &str, lines: &[&str], out: &mut Vec<SignalChainCandidate>) {
    for (i, ln) in lines.iter().enumerate() {
        // 逐 sink 匹配：同一行可能有多个调用
        let mut ms: Vec<(usize, usize, String)> = Vec::new();
        for c in re_sink_lenarg().captures_iter(ln) {
            let m = c.get(0).unwrap();
            ms.push((m.start(), m.end(), c.get(1).unwrap().as_str().to_string()));
        }
        for (start, end, sink) in ms {
            let Some(li) = length_arg_index(&sink) else {
                continue;
            };
            let args = args_after(ln, end.saturating_sub(1));
            if args.len() < li {
                continue;
            }
            let expr = args[li - 1].trim().to_string();
            if expr.is_empty() {
                continue;
            }
            let ident = binding_ident(&expr).unwrap_or_default();
            // 路径：本调用自身条件式（同行 if + 守卫式提前返回）+ 紧邻前 3 行 + 绑定标识符
            let prev_lo = i.saturating_sub(GUARD_PREV_LINES);
            let prev: Vec<&str> = lines[prev_lo..i].to_vec();
            let mut own_cond_lines: Vec<String> = Vec::new();
            if let Some(c) = re_same_line_if().captures(&ln[..start]) {
                own_cond_lines.push(c.get(1).unwrap().as_str().to_string());
            }
            // 守卫式提前返回：`if (…) return/continue/goto/break;`（最多回看 4 行）
            for j in i.saturating_sub(4)..i {
                if let Some(c) = re_any_if().captures(lines[j]) {
                    let seg = lines[j..(j + 2).min(lines.len())].join("\n");
                    if re_bailout_kw().is_match(&seg) {
                        own_cond_lines.push(c.get(1).unwrap().as_str().to_string());
                    }
                }
            }
            let own_text = own_cond_lines.join("\n");
            let mut win = prev.join("\n");
            if !own_text.is_empty() {
                win.push('\n');
                win.push_str(&own_text);
            }
            let own_hit = guard_hit(&own_text, &ident);
            let prev_hit_line = guard_hit_line(&prev, &ident);
            let (guard_seen, guard_scope, guard_line) = if own_hit {
                (true, "own-condition".to_string(), Some(i + 1))
            } else if let Some(l) = prev_hit_line {
                (true, "prev-3-lines".to_string(), Some(prev_lo + l))
            } else {
                (false, "none".to_string(), None)
            };

            let (function, params) = enclosing_function(lines, i);
            let origin = trigger_origin(&expr);
            let origin_label = if origin == "identifier" && params.contains(&ident) {
                "param"
            } else {
                origin
            };
            // 起效点：单轮写入 ⇒ 需要目的地容量锚点（本函数内可见的定长数组）
            let arrays = fixed_arrays_in_function(lines, i);
            let dest_raw = args.first().map(|s| s.trim().to_string()).unwrap_or_default();
            // 目的地实参可能是带 C 强制转换的表达式（memcpy ((char *) passbuf, ...)）：
            // 必须在切分基名前剥掉前导的 ( ... ) 组，否则基名会变成 (char，容量锚点永远解析不到。
            let mut dest_expr = dest_raw.as_str();
            while dest_expr.starts_with('(') {
                match dest_expr.find(')') {
                    Some(close) => {
                        let rest = dest_expr[close + 1..].trim_start();
                        if rest.is_empty() { break; }
                        dest_expr = rest;
                    }
                    None => break,
                }
            }
            let dest_base = dest_expr
                .split(|c: char| c == '[' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string();
            let dest_anchor = arrays.get(&dest_base).cloned();
            let cap_expr = dest_anchor
                .as_ref()
                .map(|(_decl_line, cap)| {
                    if cap.chars().all(|c| c.is_ascii_digit()) {
                        format!("sizeof({}) /* = {} */", dest_base, cap)
                    } else {
                        format!("sizeof({})", dest_base)
                    }
                })
                .unwrap_or_else(|| format!("capacity({})", dest_raw));

            let (verdict, cause) = if origin == "constant" {
                ("not_upgraded", Some("trigger_constant".to_string()))
            } else if guard_seen {
                ("not_upgraded", Some("guard_in_scope".to_string()))
            } else if dest_anchor.is_none() {
                ("not_upgraded", Some("no_fixed_destination".to_string()))
            } else {
                ("candidate", None)
            };

            out.push(SignalChainCandidate {
                file: rel.to_string(),
                line: i + 1,
                function: function.clone(),
                construct: Construct::LenArg.as_str().to_string(),
                trigger: Trigger {
                    expr: expr.clone(),
                    origin: origin_label.to_string(),
                    attacker_influence: if origin == "constant" {
                        "none".to_string()
                    } else {
                        "possible".to_string()
                    },
                },
                path: PathRole {
                    guard_seen,
                    guard_scope,
                    guard_line,
                    searched: vec![
                        "own-condition".to_string(),
                        format!("prev-{}lines", GUARD_PREV_LINES),
                        "bound-identifier".to_string(),
                    ],
                },
                effect: Effect {
                    sink: sink.clone(),
                    kind: if dest_anchor.is_some() {
                        "oob_write".to_string()
                    } else {
                        "unknown_write".to_string()
                    },
                    accumulating: false,
                    precondition: Precondition {
                        expr: format!("{} <= {}", expr, cap_expr),
                        verdict: "unproven".to_string(),
                    },
                },
                verdict: verdict.to_string(),
                cause,
                evidence_line: ln.trim().to_string(),
                provenance: provenance_for(Construct::LenArg),
                uncertainty: base_uncertainty(Construct::LenArg),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_text(text: &str) -> Vec<SignalChainCandidate> {
        scan_source("fixture.c", text, &SignalChainOptions::default())
    }

    fn find<'a>(
        v: &'a [SignalChainCandidate],
        f: &str,
    ) -> Option<&'a SignalChainCandidate> {
        v.iter().find(|c| c.function == f)
    }

    // 内联夹具：语义等价于私有回归尺子的四个 *.c。私有夹具不入库，公开源码只保留
    // 通用技术事实，因此夹具里的标识符与注释做了中性化改写（判据与形态完全一致）。
    const FIX_UPGRADE_TAINTED_LEN: &str = r#"// 夹具：期望升级为候选（触发点=参数长度、路径=无守卫、起效点=oob_write）
// 期望：升级；三角色齐备（trigger=param/length、path 无 guard、effect=oob_write）
#include <string.h>

void tainted_copy(char *src, unsigned int n)
{
    char dst[64];
    memcpy(dst, src, n);          /* n 来自参数，窗口内无 n <= sizeof(dst) 类比较 */
}
"#;

    const FIX_NO_UPGRADE_SIZEOF: &str = r#"// 夹具：期望不升级（触发点=编译期常量）
// 这是引擎真实误判过的形态：memcpy(p, &server, sizeof(server)) 被判 critical。
// 期望：不升级；trigger.origin=constant ⇒ 三角色不齐备。
#include <string.h>

struct server_info {
    unsigned int addr;
    unsigned short port;
};

void copy_fixed(struct server_info *si)
{
    char packet[548];
    memcpy(packet, si, sizeof(*si));   /* 长度是编译期常量，不构成可被攻击者左右的量 */
}
"#;

    const FIX_NO_UPGRADE_GUARDED: &str = r#"// 夹具：期望不升级（路径角色=已有有效守卫）
// 期望：不升级；path.guard_seen=true（窗口内存在 n > sizeof(dst) 类比较/返回）

void sanitized_copy(char *src, unsigned int n)
{
    char dst[64];
    if (n > sizeof(dst))
        return;
    __builtin_memcpy(dst, src, n);
}
"#;

    /// 已知答案的等价形态：展开循环把数据写进 548 字节的结构体缓冲，
    /// 循环界来自配置且无上限；紧邻的兄弟循环带 `&& i < 100` 这类 clamp。
    const FIX_UPGRADE_OOB_SHAPE: &str = r#"// 夹具：期望升级（复刻已确认的堆溢出形态）
// 真身形态：展开循环写进 548 字节的结构体缓冲，循环界来自配置且无上限；
// 紧邻的兄弟循环带 i < 100 这类 clamp（那是给兄弟加的守卫）。
// 期望：升级；trigger.origin=config/param 且 attacker_influence 至少 unknown→按配置面标注；
//       effect.kind=oob_write，sink=sprintf。

#include <stdio.h>

struct holder {
    unsigned char buf[548];
};

static struct holder data;

void expand_raw(const unsigned char *raw, unsigned int raw_len)
{
    char *p = (char *)data.buf;
    unsigned int i;

    for (i = 0; i < raw_len; i++) {          /* 无 i < LIMIT 类 clamp */
        p += sprintf(p, "%.2x", raw[i]);
        if (i != raw_len - 1)
            p += sprintf(p, ":");
    }
}
"#;

    #[test]
    fn fixture_upgrade_tainted_len() {
        let v = scan_text(FIX_UPGRADE_TAINTED_LEN);
        let c = find(&v, "tainted_copy").expect("tainted_copy 应被登记");
        assert_eq!(c.verdict, "candidate", "参数长度 + 无守卫 ⇒ 必须升级");
        assert_eq!(c.construct, "lenarg");
        assert_eq!(c.effect.sink, "memcpy");
        assert_eq!(c.effect.kind, "oob_write");
        assert_eq!(c.trigger.expr, "n");
        assert_eq!(c.trigger.origin, "param");
        assert!(!c.path.guard_seen);
    }

    #[test]
    fn fixture_no_upgrade_sizeof() {
        // 已知 FP 形态：sizeof 常量绝不能被判成候选
        let v = scan_text(FIX_NO_UPGRADE_SIZEOF);
        let c = find(&v, "copy_fixed").expect("copy_fixed 应被登记");
        assert_eq!(c.verdict, "not_upgraded", "sizeof 常量不得升级");
        assert_eq!(c.cause.as_deref(), Some("trigger_constant"));
        assert_eq!(c.trigger.origin, "constant");
        assert_eq!(c.trigger.attacker_influence, "none");
    }

    #[test]
    fn fixture_no_upgrade_guarded() {
        let v = scan_text(FIX_NO_UPGRADE_GUARDED);
        let c = find(&v, "sanitized_copy").expect("sanitized_copy 应被登记");
        assert_eq!(c.verdict, "not_upgraded", "已有守卫不得升级");
        assert_eq!(c.cause.as_deref(), Some("guard_in_scope"));
        assert!(c.path.guard_seen);
        // `if (n > sizeof(dst)) return;` 就是本调用的守卫 ⇒ 归入"本调用自身条件式"
        assert_eq!(c.path.guard_scope, "own-condition");
        assert!(c.path.guard_line.is_some());
        // 守卫检索范围必须被暴露且不含大窗口
        assert!(c.path.searched.iter().all(|s| !s.contains("80")));
    }

    #[test]
    fn fixture_upgrade_oob_accumulating_shape() {
        // 已知答案的等价形态：循环界来自参数且无 clamp，写指针在循环内推进
        let v = scan_text(FIX_UPGRADE_OOB_SHAPE);
        let c = find(&v, "expand_raw").expect("expand_raw 应被登记");
        assert_eq!(c.verdict, "candidate", "该形态必须升级");
        assert_eq!(c.construct, "loop");
        assert_eq!(c.effect.sink, "sprintf");
        assert_eq!(c.effect.kind, "oob_write");
        assert!(c.effect.accumulating, "p += sprintf(p, …) 必须判为累积");
        assert_eq!(c.trigger.expr, "raw_len");
        assert!(!c.path.guard_seen);
    }

    /// 兄弟构造的守卫绝不能顶替本构造的守卫（大窗口会漏掉本构造的真候选）。
    #[test]
    fn sibling_guard_must_not_mask_own_construct() {
        let text = r#"
struct d { unsigned char buf[548]; };
static struct d data;

void expand(unsigned char *raw, unsigned int own_len, unsigned int sib_len)
{
    char *p = (char *)data.buf;
    unsigned int i;

    /* 兄弟构造：自带 i < 100 这类 clamp */
    for (i = 0; i < sib_len && i < 100; i++)
        p += sprintf(p, "%.2x", raw[i]);

    /* 本构造：无 clamp —— 不能被上面兄弟的守卫顶替 */
    p = (char *)data.buf;
    for (i = 0; i < own_len; i++)
        p += sprintf(p, "%.2x", raw[i]);
    return;
}
"#;
        let v = scan_text(text);
        let loops: Vec<&SignalChainCandidate> =
            v.iter().filter(|c| c.construct == "loop").collect();
        assert_eq!(loops.len(), 2, "两个循环都应被登记: {loops:#?}");
        // 兄弟循环：自身条件式含 i < 100 ⇒ own-condition 守卫
        let sib = loops
            .iter()
            .find(|c| c.trigger.expr == "sib_len")
            .expect("兄弟循环");
        assert!(sib.path.guard_seen, "兄弟循环应命中自身条件式守卫");
        assert_eq!(sib.path.guard_scope, "own-condition");
        // 本构造：必须仍然是候选（守卫检索只作用于本构造）
        let own = loops
            .iter()
            .find(|c| c.trigger.expr == "own_len")
            .expect("本构造");
        assert_eq!(
            own.verdict, "candidate",
            "本构造不得被兄弟构造的守卫顶替: {own:#?}"
        );
        assert!(!own.path.guard_seen);
    }

    /// 保守口径：字面量格式 + 非累积 + 单轮 ⇒ 判"输出有界"，不升级。
    #[test]
    fn literal_format_single_round_is_bounded() {
        let text = r#"
void tag(char *out, unsigned int n)
{
    unsigned int i;
    for (i = 0; i < n; i++)
        sprintf(out, "item%i", i);
}
"#;
        let v = scan_text(text);
        let c = v.first().expect("应被登记");
        assert!(!c.effect.accumulating, "写回同一基址 ⇒ 不累积");
        assert_eq!(c.verdict, "not_upgraded");
        assert_eq!(c.cause.as_deref(), Some("bounded_nonaccumulating"));
        assert_eq!(c.effect.kind, "bounded_write");
    }

    /// 纯大写宏界不是"可被攻击者左右的量"。
    #[test]
    fn macro_bound_is_constant() {
        let text = r#"
void f(int *src, int *dst)
{
    int i;
    for (i = 0; i < PARALLELISM_DEGREE; i++)
        memcpy(dst, src, 8);
}
"#;
        let v = scan_text(text);
        let c = v.first().expect("应被登记");
        assert_eq!(c.trigger.origin, "constant");
        assert_eq!(c.verdict, "not_upgraded");
    }

    /// 触发点是纯数字表达式 ⇒ 不升级。
    #[test]
    fn numeric_bound_is_constant() {
        let text = r#"
void f(int *src, int *dst)
{
    int i;
    for (i = 0; i < 8; i++)
        memcpy(dst, src, 4);
}
"#;
        let v = scan_text(text);
        assert!(v.iter().all(|c| c.verdict == "not_upgraded"));
    }

    /// 私有大仓已知答案：仅当显式给出检出路径与期望时才跑（CI 上不存在该仓库）。
    ///
    /// 环境变量（三者都给出才生效）：
    ///   `CTX_AUDIT_SIGNAL_CHAIN_KNOWN_ANSWER_ROOT`   项目根目录
    ///   `CTX_AUDIT_SIGNAL_CHAIN_EXPECT_FILE_SUFFIX`  期望候选所在文件的后缀
    ///   `CTX_AUDIT_SIGNAL_CHAIN_EXPECT_LINE`         期望候选所在行号
    #[test]
    fn known_answer_env_gated() {
        let (Some(root), Some(suffix), Some(line)) = (
            std::env::var_os("CTX_AUDIT_SIGNAL_CHAIN_KNOWN_ANSWER_ROOT"),
            std::env::var_os("CTX_AUDIT_SIGNAL_CHAIN_EXPECT_FILE_SUFFIX"),
            std::env::var_os("CTX_AUDIT_SIGNAL_CHAIN_EXPECT_LINE"),
        ) else {
            return;
        };
        let Some(line) = line.to_string_lossy().parse::<usize>().ok() else {
            return;
        };
        let suffix = suffix.to_string_lossy().to_string();
        let root = PathBuf::from(root);
        if !root.is_dir() {
            return;
        }
        let rep = scan_path(&root, &SignalChainOptions::default()).expect("scan");
        let hit = rep
            .candidates
            .iter()
            .find(|c| c.file.ends_with(suffix.as_str()) && c.line == line);
        let hit = hit.unwrap_or_else(|| {
            panic!(
                "已知答案未被列为候选（{}:{}）。候选 {} 条: {:?}",
                suffix,
                line,
                rep.candidate_count,
                rep.candidates
                    .iter()
                    .map(|c| format!("{}:{}", c.file, c.line))
                    .collect::<Vec<_>>()
            )
        });
        assert_eq!(hit.construct, "loop");
        assert!(hit.effect.accumulating, "已知答案的写指针必须在循环内推进");
    }
}
