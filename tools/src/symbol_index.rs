// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 符号索引（代码智能面的索引底座）。
//!
//! 问题（实测）：`get_symbol_definition` / `get_symbol_references` 原先按调用逐个读取并
//! 正则扫描项目里**所有**文件内容——同一台空闲机器上，flask（83 文件）p95 ≈ 6.9ms，
//! 而 1556 文件的项目 p95 ≈ 189ms（是"符号跳转 < 10ms"目标的 19 倍），且随文件数线性增长；
//! 内容索引另有 2000 文件的静默截断。
//!
//! 做法：
//! - **定义索引**：索引期从声明行抽取"被声明的标识符"，建 `symbol → 位置` 反向表；
//!   查询是哈希查找。语义比原先的"整行子串命中"更精确（新结果集是旧结果集的子集：
//!   只保留真正声明该符号的行），这一变化如实写进 `uncertainty`。
//! - **引用剪枝**：每个文件一份 4096 位 trigram 布隆过滤器。布隆过滤器**无假阴性**，
//!   所以候选文件集是"内容包含该子串的文件"的超集；再对候选文件逐行跑原有启发式，
//!   因此引用的判定语义与原先一致（只是不再全量读盘）。
//! - **增量**：文件级 `(mtime_ms, size)` 指纹 + 目录指纹；只有变化的文件重新解析，
//!   未变文件的定义与布隆位图直接复用。
//! - 只保留元数据（路径 + 指纹 + 布隆位图 + 声明），不驻留文件内容，因此不再有
//!   "读满 2000 个文件就截断"的问题。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 单文件大小上限（与内容索引保持一致）
const MAX_FILE_BYTES: u64 = 512 * 1024;
/// 索引文件数上限（仅用于兜底，避免异常目录把内存吃光；远超内容索引的 2000）
const MAX_INDEXED_FILES: usize = 100_000;
/// 布隆过滤器位宽（64 × 64 = 4096 位/文件 ≈ 512B）
const BLOOM_WORDS: usize = 64;
/// 默认 TTL（毫秒），与内容索引共用 `CTX_AUDIT_INDEX_TTL_MS`
const DEFAULT_TTL_MS: u64 = 5_000;
/// 单个符号最多保留的定义条数
const MAX_DEFS_PER_SYMBOL: usize = 200;

/// 声明关键字（与既有 `find_definitions` 保持同一清单）
const DEF_KEYWORDS: [&str; 14] = [
    "fn ",
    "def ",
    "func ",
    "function ",
    "class ",
    "struct ",
    "enum ",
    "interface ",
    "trait ",
    "const ",
    "type ",
    "module ",
    "namespace ",
    "object ",
];

/// 声明关键字之后可能出现的修饰符，抽取标识符时跳过
const MODIFIERS: [&str; 16] = [
    "pub", "async", "unsafe", "extern", "static", "public", "private", "protected", "final",
    "abstract", "sealed", "partial", "export", "default", "virtual", "inline",
];

/// 目录跳过清单（与内容索引保持一致）
const SKIP_DIRS: [&str; 8] = [
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
];

/// 一条定义命中
#[derive(Debug, Clone)]
pub struct DefHit {
    /// files 下标
    pub file: usize,
    pub line: u32,
    pub text: String,
}

#[derive(Debug, Clone)]
struct FileEntry {
    /// 相对路径（分隔符统一为 `/`）
    path: String,
    mtime_ms: u64,
    size: u64,
    /// trigram 布隆位图
    bloom: Vec<u64>,
}

#[derive(Debug, Clone)]
struct DirEntry {
    path: String,
    mtime_ms: u64,
}

/// 符号索引
#[derive(Debug)]
pub struct SymbolIndex {
    root: String,
    files: Vec<FileEntry>,
    dirs: Vec<DirEntry>,
    /// files 下标 → 该文件的声明（symbol, line, text）
    file_defs: Vec<Vec<(String, u32, String)>>,
    /// symbol → 定义位置（由 file_defs 派生）
    defs: HashMap<String, Vec<DefHit>>,
    built_at: Instant,
    /// 累计解析过的文件数（增量时只解析变化的）
    parsed_files: u64,
    skipped_large: usize,
    /// 因不是代码文件（json/yaml/md 等）而跳过的文件数
    skipped_non_code: usize,
    truncated: bool,
}

/// 命中来源（与内容索引同构）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitSource {
    Ttl,
    Probe,
    Miss,
}

impl HitSource {
    pub fn is_hit(self) -> bool {
        !matches!(self, HitSource::Miss)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            HitSource::Ttl => "ttl",
            HitSource::Probe => "probe",
            HitSource::Miss => "miss",
        }
    }
}

impl SymbolIndex {
    pub fn root(&self) -> &str {
        &self.root
    }

    /// 已索引文件数
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// 不同符号数（有定义的）
    pub fn symbol_count(&self) -> usize {
        self.defs.len()
    }

    /// 累计解析文件数（用于验证"增量只重解析变化的文件"）
    pub fn parsed_files(&self) -> u64 {
        self.parsed_files
    }

    pub fn skipped_large(&self) -> usize {
        self.skipped_large
    }

    /// 因不是代码文件而跳过的文件数
    pub fn skipped_non_code(&self) -> usize {
        self.skipped_non_code
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn build_age(&self) -> Duration {
        self.built_at.elapsed()
    }

    /// 符号定义查询（标识符精确，按路径排序稳定）
    pub fn definitions(&self, symbol: &str, limit: usize) -> Vec<DefHit> {
        let mut hits = self.defs.get(symbol).cloned().unwrap_or_default();
        hits.sort_by(|a, b| {
            self.files[a.file]
                .path
                .cmp(&self.files[b.file].path)
                .then(a.line.cmp(&b.line))
        });
        hits.truncate(limit.min(MAX_DEFS_PER_SYMBOL));
        hits
    }

    /// 引用候选文件下标（布隆过滤器无假阴性 ⇒ 候选集是"内容包含该子串"的超集）
    pub fn reference_candidates(&self, symbol: &str) -> Vec<usize> {
        self.files
            .iter()
            .enumerate()
            .filter(|(_, f)| bloom_might_contain(&f.bloom, symbol))
            .map(|(i, _)| i)
            .collect()
    }

    /// 文件相对路径
    pub fn file_path(&self, idx: usize) -> &str {
        &self.files[idx].path
    }

    /// 只读新鲜度判定（不重新解析）：已知文件逐个 stat + 目录指纹比对
    pub fn freshness(&self, root: &Path) -> bool {
        if self.dirs.is_empty() && self.files.is_empty() {
            return false;
        }
        for dir in &self.dirs {
            if dir.mtime_ms == 0 {
                continue;
            }
            let path = if dir.path.is_empty() {
                root.to_path_buf()
            } else {
                root.join(&dir.path)
            };
            match stat_mtime_ms(&path) {
                Some(ms) if ms == dir.mtime_ms => {}
                _ => return false,
            }
        }
        for file in &self.files {
            match std::fs::metadata(root.join(&file.path)) {
                Ok(meta) => {
                    if meta.len() != file.size || mtime_ms(&meta) != file.mtime_ms {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        true
    }

    /// 增量重建：复用未变文件的声明与布隆位图，只解析新增/变化的文件。
    fn rebuild_incremental(&self, root: &Path) -> SymbolIndex {
        let (paths, dirs, skipped_large, skipped_non_code, truncated) = collect_paths(root);
        let mut old_by_path: HashMap<&str, usize> = HashMap::with_capacity(self.files.len());
        for (i, f) in self.files.iter().enumerate() {
            old_by_path.insert(f.path.as_str(), i);
        }

        let mut files: Vec<FileEntry> = Vec::with_capacity(paths.len());
        let mut file_defs: Vec<Vec<(String, u32, String)>> = Vec::with_capacity(paths.len());
        let mut parsed_files = self.parsed_files;

        for (rel, full, meta) in paths {
            let mtime = mtime_ms(&meta);
            let size = meta.len();
            if let Some(&old_idx) = old_by_path.get(rel.as_str()) {
                let old = &self.files[old_idx];
                if old.mtime_ms == mtime && old.size == size {
                    // 未变：直接复用
                    files.push(old.clone());
                    file_defs.push(self.file_defs[old_idx].clone());
                    continue;
                }
            }
            // 新增或变化：解析
            if let Ok(content) = std::fs::read_to_string(&full) {
                let (defs, bloom) = index_content(&content);
                parsed_files += 1;
                files.push(FileEntry {
                    path: rel,
                    mtime_ms: mtime,
                    size,
                    bloom,
                });
                file_defs.push(defs);
            }
        }

        let defs = build_def_map(&file_defs);
        SymbolIndex {
            root: self.root.clone(),
            files,
            dirs,
            file_defs,
            defs,
            built_at: Instant::now(),
            parsed_files,
            skipped_large,
            skipped_non_code,
            truncated,
        }
    }

    /// 从零构建
    fn build(root: &Path) -> SymbolIndex {
        let empty = SymbolIndex {
            root: root.to_string_lossy().to_string(),
            files: Vec::new(),
            dirs: Vec::new(),
            file_defs: Vec::new(),
            defs: HashMap::new(),
            built_at: Instant::now(),
            parsed_files: 0,
            skipped_large: 0,
            skipped_non_code: 0,
            truncated: false,
        };
        empty.rebuild_incremental(root)
    }
}

// ────────────────────────────────────────────────────────
// 进程内缓存
// ────────────────────────────────────────────────────────

struct Entry {
    index: Arc<SymbolIndex>,
    validated_at: Instant,
    last_build_ms: u64,
}

fn registry() -> &'static Mutex<HashMap<String, Entry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ttl() -> Duration {
    let ms = std::env::var("CTX_AUDIT_INDEX_TTL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_MS);
    Duration::from_millis(ms)
}

fn probe_enabled() -> bool {
    crate::index_cache::probe_enabled()
}

fn cache_key(root: &Path) -> String {
    crate::index_cache::cache_key(root)
}

/// 取符号索引：TTL 内复用；TTL 过后用指纹探测，未变则复用，变了则**增量**重建。
///
/// 返回 `(索引, 命中来源, 最近一次构建耗时毫秒)`。
pub fn get_or_build(root: &Path, refresh: bool, ttl_override: Option<Duration>) -> (Arc<SymbolIndex>, HitSource, u64) {
    let key = cache_key(root);
    let ttl = ttl_override.unwrap_or_else(ttl);

    match registry().lock() {
        Ok(mut reg) => {
            if !refresh && !ttl.is_zero() {
                if let Some(entry) = reg.get_mut(&key) {
                    if entry.validated_at.elapsed() < ttl {
                        return (entry.index.clone(), HitSource::Ttl, entry.last_build_ms);
                    }
                    if probe_enabled() && entry.index.freshness(root) {
                        entry.validated_at = Instant::now();
                        return (entry.index.clone(), HitSource::Probe, entry.last_build_ms);
                    }
                    // 变化：增量重建（只解析变化的文件）
                    let started = Instant::now();
                    let rebuilt = Arc::new(entry.index.rebuild_incremental(root));
                    let build_ms = started.elapsed().as_millis() as u64;
                    entry.index = rebuilt.clone();
                    entry.validated_at = Instant::now();
                    entry.last_build_ms = build_ms;
                    return (rebuilt, HitSource::Miss, build_ms);
                }
            }

            let started = Instant::now();
            let index = Arc::new(SymbolIndex::build(root));
            let build_ms = started.elapsed().as_millis() as u64;
            reg.insert(
                key,
                Entry {
                    index: index.clone(),
                    validated_at: Instant::now(),
                    last_build_ms: build_ms,
                },
            );
            (index, HitSource::Miss, build_ms)
        }
        Err(_) => {
            let started = Instant::now();
            let index = Arc::new(SymbolIndex::build(root));
            (
                index,
                HitSource::Miss,
                started.elapsed().as_millis() as u64,
            )
        }
    }
}

/// 丢弃某个项目根的符号索引
pub fn invalidate(root: &Path) -> bool {
    let key = cache_key(root);
    match registry().lock() {
        Ok(mut reg) => reg.remove(&key).is_some(),
        Err(_) => false,
    }
}

/// 缓存概览：`(条目数, 条目内文件总数)`
pub fn stats() -> (usize, usize) {
    match registry().lock() {
        Ok(reg) => (
            reg.len(),
            reg.values().map(|e| e.index.file_count()).sum(),
        ),
        Err(_) => (0, 0),
    }
}

// ────────────────────────────────────────────────────────
// 索引构建
// ────────────────────────────────────────────────────────

fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    crate::index_cache::mtime_ms(meta)
}

fn stat_mtime_ms(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| mtime_ms(&m))
}

/// 只有"代码文件"参与符号索引：JSON/YAML/锁文件等数据文件不含声明，
/// 却会因为同名子串污染引用结果（实测夹具里 expected.json 贡献了全部误报）。
fn is_code_file(rel: &str) -> bool {
    let ext = rel.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "rs" | "py"
            | "go"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "java"
            | "php"
            | "rb"
            | "ex"
            | "exs"
            | "c"
            | "h"
            | "hpp"
            | "cpp"
            | "cc"
            | "cxx"
            | "cs"
            | "kt"
            | "swift"
            | "scala"
            | "clj"
            | "lua"
            | "vue"
    )
}

/// 收集候选文件 `(相对路径, 绝对路径, 元数据)` 与目录指纹
fn collect_paths(
    root: &Path,
) -> (
    Vec<(String, PathBuf, std::fs::Metadata)>,
    Vec<DirEntry>,
    usize,
    usize,
    bool,
) {
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut skipped_large = 0usize;
    let mut skipped_non_code = 0usize;
    let mut truncated = false;
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];

    while let Some((dir, dir_rel)) = stack.pop() {
        if files.len() >= MAX_INDEXED_FILES {
            truncated = true;
            break;
        }
        if let Ok(meta) = std::fs::metadata(&dir) {
            dirs.push(DirEntry {
                path: dir_rel.clone(),
                mtime_ms: mtime_ms(&meta),
            });
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                // 跳过清单 + 一切点号目录：`.ctx-audit` 里是工具自己的状态
                // （如 mcp_metrics.jsonl 每次调用都会变），把它当源码索引会让
                // "无变化就不重解析"永远不成立。
                if !SKIP_DIRS.contains(&name.as_str()) && !name.starts_with('.') {
                    let child_rel = if dir_rel.is_empty() {
                        name.clone()
                    } else {
                        format!("{dir_rel}/{name}")
                    };
                    stack.push((path, child_rel));
                }
                continue;
            }
            if files.len() >= MAX_INDEXED_FILES {
                truncated = true;
                break;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > MAX_FILE_BYTES {
                skipped_large += 1;
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or(name);
            if !is_code_file(&rel) {
                skipped_non_code += 1;
                continue;
            }
            files.push((rel, path, meta));
        }
    }

    // 确定性：路径排序（避免枚举顺序影响 40 条上限的取舍）
    files.sort_by(|a, b| a.0.cmp(&b.0));
    dirs.sort_by(|a, b| a.path.cmp(&b.path));
    (files, dirs, skipped_large, skipped_non_code, truncated)
}

/// 解析一个文件：返回 `(声明列表, trigram 布隆位图)`
fn index_content(content: &str) -> (Vec<(String, u32, String)>, Vec<u64>) {
    let mut bloom = vec![0u64; BLOOM_WORDS];
    add_trigrams(&mut bloom, content);

    let mut defs: Vec<(String, u32, String)> = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        if !DEF_KEYWORDS.iter().any(|k| trimmed.contains(*k)) {
            continue;
        }
        let text: String = trimmed.chars().take(200).collect();
        for name in declared_names(trimmed) {
            defs.push((name, (idx + 1) as u32, text.clone()));
        }
    }
    (defs, bloom)
}

/// 从声明行抽取被声明的标识符（跳过修饰符；语言无关的保守启发式）
pub fn declared_names(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for kw in DEF_KEYWORDS {
        let mut from = 0usize;
        while let Some(pos) = line[from..].find(kw) {
            let abs = from + pos;
            let mut rest = line[abs + kw.len()..].trim_start();
            // Go/Rust 形态 `func (recv Type) Name(`：先跳过接收者/泛型括号，否则取不到方法名
            if rest.starts_with('(') {
                if let Some(close) = rest.find(')') {
                    rest = rest[close + 1..].trim_start();
                }
            }
            // 跳过修饰符（pub/async/public/...）与噪声
            loop {
                let end = rest
                    .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                    .unwrap_or(rest.len());
                if end == 0 {
                    break;
                }
                let token = &rest[..end];
                if MODIFIERS.contains(&token) {
                    rest = rest[end..].trim_start();
                    continue;
                }
                if !out.iter().any(|n| n == token) {
                    out.push(token.to_string());
                }
                break;
            }
            from = abs + kw.len();
            if out.len() >= 8 {
                return out;
            }
        }
    }
    out
}

fn build_def_map(file_defs: &[Vec<(String, u32, String)>]) -> HashMap<String, Vec<DefHit>> {
    let mut map: HashMap<String, Vec<DefHit>> = HashMap::new();
    for (file, defs) in file_defs.iter().enumerate() {
        for (symbol, line, text) in defs {
            map.entry(symbol.clone()).or_default().push(DefHit {
                file,
                line: *line,
                text: text.clone(),
            });
        }
    }
    map
}

fn hash3(a: u8, b: u8, c: u8) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in [a, b, c] {
        h ^= byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn add_trigrams(bloom: &mut [u64], content: &str) {
    let bytes = content.as_bytes();
    if bytes.len() < 3 {
        return;
    }
    for w in bytes.windows(3) {
        let h = hash3(w[0], w[1], w[2]);
        let idx = (h & (BLOOM_WORDS as u64 - 1)) as usize;
        let bit = ((h >> 6) & 63) as u32;
        bloom[idx] |= 1u64 << bit;
    }
}

/// 布隆判定：短查询（< 3 字符）不剪枝
fn bloom_might_contain(bloom: &[u64], symbol: &str) -> bool {
    let bytes = symbol.as_bytes();
    if bytes.len() < 3 {
        return true;
    }
    for w in bytes.windows(3) {
        let h = hash3(w[0], w[1], w[2]);
        let idx = (h & (BLOOM_WORDS as u64 - 1)) as usize;
        let bit = ((h >> 6) & 63) as u32;
        if bloom[idx] & (1u64 << bit) == 0 {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ctx-audit-symbol-index-{tag}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/app.py"),
            "@app.route(\"/a\")\ndef handler(request):\n    return helper(request)\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/util.py"),
            "class Helper:\n    def helper(self, value):\n        return value\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn test_declared_names_extraction() {
        assert_eq!(declared_names("def handler(request):"), vec!["handler"]);
        assert_eq!(declared_names("class Helper(Base):"), vec!["Helper"]);
        assert_eq!(declared_names("pub async fn run(x: u32) {"), vec!["run"]);
        assert_eq!(declared_names("struct Foo<T> {"), vec!["Foo"]);
        assert_eq!(declared_names("const MAX_LEN: usize = 4;"), vec!["MAX_LEN"]);
        // Go/Rust 接收者形态：必须先跳过 (recv Type)
        assert_eq!(
            declared_names("func (f fileReader) Read(p []byte) (int, error) {"),
            vec!["Read"]
        );
        assert_eq!(
            declared_names("func (s *Server) handle(c *gin.Context) {"),
            vec!["handle"]
        );
        assert!(declared_names("let x = 1;").is_empty());
    }

    /// 数据文件（json/yaml/md 等）不参与符号索引
    #[test]
    fn test_non_code_files_are_not_indexed() {
        let root = fixture("noncode");
        std::fs::write(
            root.join("config.json"),
            "{\n  \"handler\": \"app.handler\",\n  \"put\": \"x\"\n}\n",
        )
        .unwrap();

        let (index, _, _) = get_or_build(&root, true, None);
        let indexed: Vec<&str> = (0..index.file_count())
            .map(|i| index.file_path(i))
            .collect();
        assert!(
            indexed.iter().all(|p| !p.ends_with(".json")),
            "数据文件不应进符号索引: {indexed:?}"
        );
        assert!(index.skipped_non_code() >= 1);

        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_definitions_are_identifier_exact() {
        let root = fixture("exact");
        let (index, hit, _) = get_or_build(&root, true, None);
        assert_eq!(hit, HitSource::Miss);

        let defs = index.definitions("handler", 10);
        assert_eq!(defs.len(), 1, "应命中 1 处定义: {defs:?}");
        assert_eq!(index.file_path(defs[0].file), "src/app.py");
        assert_eq!(defs[0].line, 2);

        // 子串查询不再误报（旧实现按整行子串命中）
        assert!(
            index.definitions("and", 10).is_empty(),
            "子串不应再被当成定义"
        );
        assert!(index.definitions("Helper", 10).len() == 1);

        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_reference_candidates_have_no_false_negatives() {
        let root = fixture("refs");
        let (index, _, _) = get_or_build(&root, true, None);

        for symbol in ["helper", "handler", "Helper", "request"] {
            let candidates: Vec<&str> = index
                .reference_candidates(symbol)
                .iter()
                .map(|i| index.file_path(*i))
                .collect();
            // 逐文件核实：内容里真的含该符号的文件必须出现在候选里
            for (rel, content) in [
                ("src/app.py", std::fs::read_to_string(root.join("src/app.py")).unwrap()),
                ("src/util.py", std::fs::read_to_string(root.join("src/util.py")).unwrap()),
            ] {
                if content.contains(symbol) {
                    assert!(
                        candidates.contains(&rel),
                        "{symbol} 出现在 {rel}，但没进候选: {candidates:?}"
                    );
                }
            }
        }

        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_incremental_rebuild_only_reparses_changed_files() {
        let root = fixture("incremental");
        let (first, _, _) = get_or_build(&root, true, None);
        let parsed_after_full = first.parsed_files();
        assert!(parsed_after_full >= 2, "首次应解析全部文件");

        // 只改一个文件；TTL 置 0 强制走探测 + 增量重建
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(
            root.join("src/new.py"),
            "def brand_new_thing():\n    pass\n",
        )
        .unwrap();

        let (second, hit, _) = get_or_build(&root, false, Some(Duration::from_millis(1)));
        assert_eq!(hit, HitSource::Miss, "有新文件必须重建");
        assert_eq!(
            second.parsed_files(),
            parsed_after_full + 1,
            "增量重建只应解析新增/变化的文件"
        );
        assert_eq!(second.definitions("brand_new_thing", 5).len(), 1);
        // 未变文件的定义仍在
        assert_eq!(second.definitions("handler", 5).len(), 1);

        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_probe_hit_avoids_rescan() {
        let root = fixture("probe");
        let (first, _, _) = get_or_build(&root, true, None);
        let parsed = first.parsed_files();

        std::thread::sleep(Duration::from_millis(10));
        let (second, hit, _) = get_or_build(&root, false, Some(Duration::from_millis(1)));
        assert_eq!(hit, HitSource::Probe, "文件未变应走探测命中");
        assert_eq!(second.parsed_files(), parsed, "探测命中不应重新解析任何文件");

        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 工具自己的状态目录（`.ctx-audit`，MCP 每次调用都会追加指标）不得进入索引：
    /// 否则"无变化 ⇒ 不重解析"永远不成立。
    #[test]
    fn test_tool_state_dir_is_not_indexed() {
        let root = fixture("toolstate");
        std::fs::create_dir_all(root.join(".ctx-audit")).unwrap();
        std::fs::write(root.join(".ctx-audit/mcp_metrics.jsonl"), "{}\n").unwrap();

        let (first, _, _) = get_or_build(&root, true, None);
        let indexed: Vec<&str> = (0..first.file_count())
            .map(|i| first.file_path(i))
            .collect();
        assert!(
            indexed.iter().all(|p| !p.starts_with(".ctx-audit")),
            "点号目录不应被索引: {indexed:?}"
        );
        let parsed = first.parsed_files();

        // 模拟工具调用追加指标：不在索引里，因此不应触发重建
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(root.join(".ctx-audit/mcp_metrics.jsonl"), "{}\n{}\n").unwrap();
        let (second, hit, _) = get_or_build(&root, false, Some(Duration::from_millis(1)));
        assert_eq!(hit, HitSource::Probe, "只有工具状态变化时应是探测命中");
        assert_eq!(second.parsed_files(), parsed, "不应重新解析任何文件");

        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }
}
