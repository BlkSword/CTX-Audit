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

use crate::text_scan::{code_lines, hash_comment_language, identifiers_in_line};

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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FileEntry {
    /// 相对路径（分隔符统一为 `/`）
    path: String,
    mtime_ms: u64,
    size: u64,
    /// trigram 布隆位图
    bloom: Vec<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    /// files 下标 → 该文件的标识符倒排（identifier → 行号）
    file_idents: Vec<HashMap<String, Vec<u32>>>,
    /// symbol → 定义位置（由 file_defs 派生）
    defs: HashMap<String, Vec<DefHit>>,
    /// identifier → 引用位置 `(文件下标, 行号)`（由 file_idents 派生）
    idents: HashMap<String, Vec<(u32, u32)>>,
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

    /// 标识符引用位置 `(文件下标, 行号)`，按 路径 → 行号 稳定排序。
    ///
    /// 与定义同源：都来自**代码段**（注释/字符串已剥离），因此"字符串里的同名 token"
    /// 不会被当成引用（真实仓库 oracle 上这正是剩余误报的来源）。
    pub fn identifier_hits(&self, symbol: &str) -> Vec<(usize, u32)> {
        let Some(raw) = self.idents.get(symbol) else {
            return Vec::new();
        };
        let mut hits: Vec<(usize, u32)> = raw.iter().map(|(f, l)| (*f as usize, *l)).collect();
        hits.sort_by(|a, b| {
            self.files[a.0]
                .path
                .cmp(&self.files[b.0].path)
                .then(a.1.cmp(&b.1))
        });
        hits
    }

    /// 该符号在倒排表里的 `(文件, 行)` 条目数——**不分配**，用于空结果分类与埋点。
    pub fn identifier_occurrence_count(&self, symbol: &str) -> usize {
        self.idents.get(symbol).map(|v| v.len()).unwrap_or(0)
    }

    /// 倒排表覆盖的标识符出现次数（可观测性）
    pub fn identifier_count(&self) -> usize {
        self.idents.values().map(|v| v.len()).sum()
    }

    /// 倒排表里的不同标识符数
    pub fn identifier_symbols(&self) -> usize {
        self.idents.len()
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

    /// 相对路径 → 文件下标（用于按文件查定义）
    pub fn file_index(&self, rel: &str) -> Option<usize> {
        self.files.iter().position(|f| f.path == rel)
    }

    /// 某文件里的全部声明 `(名字, 行号, 原文)`，按行号升序
    pub fn definitions_in_file(&self, file_idx: usize) -> Vec<(String, u32, String)> {
        let mut out = self
            .file_defs
            .get(file_idx)
            .cloned()
            .unwrap_or_default();
        out.sort_by(|a, b| a.1.cmp(&b.1));
        out
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
        let mut file_idents: Vec<HashMap<String, Vec<u32>>> = Vec::with_capacity(paths.len());
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
                    file_idents.push(self.file_idents[old_idx].clone());
                    continue;
                }
            }
            // 新增或变化：解析
            if let Ok(content) = std::fs::read_to_string(&full) {
                let (defs, bloom, idents) = index_content(&rel, &content);
                parsed_files += 1;
                files.push(FileEntry {
                    path: rel,
                    mtime_ms: mtime,
                    size,
                    bloom,
                });
                file_defs.push(defs);
                file_idents.push(idents);
            }
        }

        let defs = build_def_map(&file_defs);
        let idents = build_ident_map(&file_idents);
        SymbolIndex {
            root: self.root.clone(),
            files,
            dirs,
            file_defs,
            file_idents,
            defs,
            idents,
            built_at: Instant::now(),
            parsed_files,
            skipped_large,
            skipped_non_code,
            truncated,
        }
    }

    /// 从零构建
    fn build(root: &Path) -> SymbolIndex {
        // 先试磁盘缓存：命中则只按指纹增量补齐（变化的文件才重新解析）
        if persist_enabled() {
            if let Some(mut loaded) = load_persisted(root) {
                if !loaded.freshness(root) {
                    loaded = loaded.rebuild_incremental(root);
                }
                return loaded;
            }
        }
        let empty = SymbolIndex {
            root: root.to_string_lossy().to_string(),
            files: Vec::new(),
            dirs: Vec::new(),
            file_defs: Vec::new(),
            file_idents: Vec::new(),
            defs: HashMap::new(),
            idents: HashMap::new(),
            built_at: Instant::now(),
            parsed_files: 0,
            skipped_large: 0,
            skipped_non_code: 0,
            truncated: false,
        };
        let index = empty.rebuild_incremental(root);
        if persist_enabled() {
            let _ = save_persisted(&index, root);
        }
        index
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
// 磁盘缓存（冷启动：建表 117ms–2.1s → 亚秒）
// ────────────────────────────────────────────────────────

/// 磁盘缓存格式版本（字段变化时递增，旧缓存自动失效）
const PERSIST_VERSION: u32 = 1;
/// 磁盘缓存体积上限（MB），超过则不落盘
const PERSIST_MAX_MB: u64 = 64;

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedIndex {
    version: u32,
    root: String,
    files: Vec<FileEntry>,
    dirs: Vec<DirEntry>,
    file_defs: Vec<Vec<(String, u32, String)>>,
    file_idents: Vec<HashMap<String, Vec<u32>>>,
}

/// 是否启用磁盘缓存：`CTX_AUDIT_INDEX_PERSIST=0` 关闭
fn persist_enabled() -> bool {
    !matches!(
        std::env::var("CTX_AUDIT_INDEX_PERSIST")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// 索引构建逻辑版本：**任何影响定义/标识符抽取的改动都必须 +1**。
///
/// 磁盘缓存键（见 `persist_path`）原先只由"规范化根路径"决定，于是引擎换了抽取规则、
/// 缓存却照旧命中——缓存里存的是**旧二进制**解析出的 `file_defs`，新规则一次都不会跑。
/// 实测代价：改完 C 的定义抽取规则后，nginx 的 `symbols` 仍恒为 **391**、定义召回仍
/// **0/60**，而同一份代码在单元测试里是通过的（夹具目录没有旧缓存）。
/// 把逻辑版本与 crate 版本并进缓存键，才能保证"你看到的索引来自你正在运行的引擎"。
const INDEX_LOGIC_VERSION: u32 = 2;

/// 磁盘缓存路径：**不写进项目目录**——否则创建 `.ctx-audit/index/` 会改变项目根目录的
/// mtime，把工具自己的指纹探测打失效（与 `mcp_metrics.jsonl` 同一类自污染）。
/// 放在系统临时目录，按规范化根路径 + **索引逻辑版本** + crate 版本命名。
fn persist_path(root: &Path) -> PathBuf {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    cache_key(root).hash(&mut hasher);
    INDEX_LOGIC_VERSION.hash(&mut hasher);
    env!("CARGO_PKG_VERSION").hash(&mut hasher);
    std::env::temp_dir()
        .join("ctx-audit-index")
        .join(format!("{:016x}.json", hasher.finish()))
}

fn load_persisted(root: &Path) -> Option<SymbolIndex> {
    let path = persist_path(root);
    let text = std::fs::read_to_string(&path).ok()?;
    let data: PersistedIndex = serde_json::from_str(&text).ok()?;
    if data.version != PERSIST_VERSION {
        return None;
    }
    // 根路径必须一致（防止把别的项目的缓存当自己的）
    if cache_key(Path::new(&data.root)) != cache_key(root) {
        return None;
    }
    let defs = build_def_map(&data.file_defs);
    let idents = build_ident_map(&data.file_idents);
    Some(SymbolIndex {
        root: root.to_string_lossy().to_string(),
        files: data.files,
        dirs: data.dirs,
        file_defs: data.file_defs,
        file_idents: data.file_idents,
        defs,
        idents,
        built_at: Instant::now(),
        parsed_files: 0,
        skipped_large: 0,
        skipped_non_code: 0,
        truncated: false,
    })
}

/// 落盘（原子写：先写临时文件再改名）；返回写入字节数
fn save_persisted(index: &SymbolIndex, root: &Path) -> Option<u64> {
    let data = PersistedIndex {
        version: PERSIST_VERSION,
        root: index.root.clone(),
        files: index.files.clone(),
        dirs: index.dirs.clone(),
        file_defs: index.file_defs.clone(),
        file_idents: index.file_idents.clone(),
    };
    let text = serde_json::to_string(&data).ok()?;
    let bytes = text.len() as u64;
    if bytes > PERSIST_MAX_MB * 1024 * 1024 {
        return None;
    }
    let path = persist_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).ok()?;
    std::fs::rename(&tmp, &path).ok()?;
    Some(bytes)
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
/// 是否为代码文件（符号/调用图/数据流只在代码文件上有意义：
/// 内容索引含 markdown/yaml/json 等，其中的代码片段会伪装成调用点——
/// 实测真实 Go 仓库的 `AGENTS.md` 混进了 `callees`）。
pub fn is_code_file(rel: &str) -> bool {
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

/// 解析一个文件：返回 `(声明列表, trigram 布隆位图, 标识符倒排)`
fn index_content(
    path: &str,
    content: &str,
) -> (
    Vec<(String, u32, String)>,
    Vec<u64>,
    HashMap<String, Vec<u32>>,
) {
    /// 单文件标识符条目上限（防御异常大文件把内存吃光）
    const MAX_IDENTS_PER_FILE: usize = 20_000;

    let mut bloom = vec![0u64; BLOOM_WORDS];
    add_trigrams(&mut bloom, content);

    let hash_comment = hash_comment_language(path);
    let code = code_lines(content, hash_comment);

    let mut defs: Vec<(String, u32, String)> = Vec::new();
    let mut idents: HashMap<String, Vec<u32>> = HashMap::new();
    // 是否位于括号块声明内（`var (` / `const (` / `type (`）
    let mut block_decl = false;
    // 条件编译状态：**可证死**的行（`#if 0`）不进索引——死代码里的函数不是真实定义，
    // 死分支里的引用也不该计入（C4 的"活代码视图"缺口在证据层，不在规则扫描层）。
    let preproc = crate::text_scan::preproc_line_states(content);

    for (idx, raw) in content.lines().enumerate() {
        let lineno = (idx + 1) as u32;
        let code_line = code.get(idx).map(|s| s.as_str()).unwrap_or("");

        if preproc.get(idx).map(|s| s.dead).unwrap_or(false) {
            continue;
        }

        // 标识符倒排：只在**代码段**里取（字符串/注释里的同名 token 不算引用）
        if idents.len() < MAX_IDENTS_PER_FILE {
            for name in identifiers_in_line(code_line) {
                let entry = idents.entry(name).or_default();
                if entry.last() != Some(&lineno) {
                    entry.push(lineno);
                }
            }
        }

        // ── 括号块声明（Go/C/C++ 常见）──
        // `var (` / `const (` / `type (` 之后的每一行**没有关键字**，只有 `名字 = ...`
        // 或 `名字 类型`；旧实现只看带关键字的行，整块声明因此进不了索引。
        let ctrim = code_line.trim();
        if !block_decl
            && (ctrim.starts_with("var (")
                || ctrim.starts_with("const (")
                || ctrim.starts_with("type ("))
        {
            block_decl = true;
            continue;
        }
        if block_decl {
            if ctrim.starts_with(')') {
                block_decl = false;
                continue;
            }
            let text: String = raw.trim().chars().take(200).collect();
            for name in block_declared_names(code_line) {
                defs.push((name, lineno, text.clone()));
            }
            continue;
        }

        // ── C/C++ 语言特有的定义形态 ──
        // C 的规范写法是"返回类型一行、函数名顶格另一行、`{` 再一行"：
        //     static ngx_int_t
        //     ngx_resolver_copy(ngx_resolver_t *r, …)
        //     {
        // 行内没有任何 `fn/def/class/struct` 关键字，旧实现因此直接 `continue` 掉——
        // 实测 nginx `src/core` 的函数定义召回 **0/60**（ctags 真值 416），
        // 整个 C 侧的调用图/作用域/引用都建立在这个缺失之上。
        if is_c_like(path) {
            if let Some(name) = c_define_name(code_line) {
                let text: String = raw.trim().chars().take(200).collect();
                defs.push((name, lineno, text));
                continue;
            }
            if let Some(name) = c_function_name(&code, idx) {
                let text: String = raw.trim().chars().take(200).collect();
                defs.push((name, lineno, text));
                continue;
            }
        }

        // 声明：同样用代码段判定，避免字符串里的 "def foo" 被当成定义
        let trimmed = code_line.trim();
        if trimmed.is_empty() || !DEF_KEYWORDS.iter().any(|k| trimmed.contains(*k)) {
            continue;
        }
        let text: String = raw.trim().chars().take(200).collect();
        for name in declared_names(trimmed) {
            defs.push((name, lineno, text.clone()));
        }
    }
    (defs, bloom, idents)
}

/// 从声明行抽取被声明的标识符（跳过修饰符；语言无关的保守启发式）
/// 括号块声明内的一行：取 `=` 左侧（或 `type` 块里的首个）标识符。
///
/// 支持 `A = expr`、`A, B = expr`、`A Type`（type 块）三种形态；注释行与结束行返回空。
fn block_declared_names(code_line: &str) -> Vec<String> {
    let t = code_line.trim();
    if t.is_empty() || t.starts_with("//") || t.starts_with(')') {
        return Vec::new();
    }
    let lhs = t.split('=').next().unwrap_or(t);
    let mut out = Vec::new();
    for part in lhs.split(',') {
        let name: String = part
            .trim()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name
            .chars()
            .next()
            .map(|c| c.is_alphabetic() || c == '_')
            .unwrap_or(false)
        {
            out.push(name);
        }
    }
    out
}

/// C/C++ 源文件判定（含头文件——声明与定义分离是 C 的常态）。
fn is_c_like(path: &str) -> bool {
    matches!(
        path.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str(),
        "c" | "h" | "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx"
    )
}

/// C 的控制语句关键字：它们也长得像 `名字(`，但显然不是函数定义。
const C_CTRL: [&str; 12] = [
    "if", "for", "while", "switch", "catch", "do", "else", "return", "sizeof", "case",
    "goto", "defined",
];

/// `#define NAME` / `#define NAME(args)` 的宏名。
///
/// C 的预处理器是**语言的一部分**：sink/source 藏在宏里时，看不到宏定义就等于看不到它
/// （实测 nginx `src/core` 有 452 个宏定义）。宏名进索引后，调用方问 `NGX_OK` 这类
/// 标识符时能拿到 `#define` 行本身——文本自带 `#define` 前缀，消费者一眼能分辨。
fn c_define_name(code_line: &str) -> Option<String> {
    let t = code_line.trim_start();
    let rest = t.strip_prefix('#')?.trim_start();
    let rest = rest.strip_prefix("define")?;
    // `#defineX` 不是合法指令：`define` 后必须是空白或行尾
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
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
}

/// 该行是否像 C 的**类型行**（`static ngx_int_t`、`void *`、`struct foo *`）：
/// 不含 `(`/`;`/`=`/`{}`/`,`，且至少有一个标识符 token。
fn c_type_line(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty()
        || t.starts_with('#')
        || t.contains('(')
        || t.contains(';')
        || t.contains('=')
        || t.contains('{')
        || t.contains('}')
        || t.contains(',')
    {
        return false;
    }
    let mut saw = false;
    for tok in t.split_whitespace() {
        let bare = tok.trim_matches(|c| c == '*' || c == '&');
        if bare.is_empty() {
            continue; // 纯 `*` / `&`
        }
        if !bare.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return false;
        }
        saw = true;
    }
    saw
}

fn next_code_line(code: &[String], idx: usize) -> Option<String> {
    code.iter()
        .skip(idx + 1)
        .take(4)
        .find(|s| !s.trim().is_empty())
        .cloned()
}

fn prev_code_line(code: &[String], idx: usize) -> Option<String> {
    (0..idx)
        .rev()
        .take(4)
        .map(|i| code[i].clone())
        .find(|s| !s.trim().is_empty())
}

/// 从定义行起，签名闭合之后是否紧跟函数体的 `{`。
///
/// 必须支持**参数表跨行**——nginx/Linux 的规范写法是
///     static ngx_int_t
///     ngx_resolver_copy(ngx_resolver_t *r, … u_char *src,
///         u_char *last)
///     {
/// 只看"紧邻下一行是不是 `{`"会把这类定义全部漏掉（实测 nginx src/core 召回 0/60）。
/// K&R 风格函数定义的**参数类型声明行**：`EAP_STATE *esp;` / `int id;` / `char *inp;`。
///
/// 老式 C 把参数类型写在参数表**之后**、函数体之前：
///     eap_request(esp, id, typenum, len, inp)
///     EAP_STATE *esp;
///     int id;
///     {
/// 旧实现遇到这种行里的 `;` 就判定"这不是函数定义"，于是整个 `eap_request` 进不了索引——
/// 实测 CVE-2020-8597 的漏洞点（`pppd/eap.c`）因此 `function_scope=unresolved`，判定者
/// 连"这是哪个函数"都拿不到。
pub(crate) fn kr_param_line(line: &str) -> bool {
    let t = line.trim();
    if !t.ends_with(';')
        || t.contains('(')
        || t.contains('=')
        || t.contains('{')
        || t.contains('}')
    {
        return false;
    }
    let body = t.trim_end_matches(';').trim_end();
    if body.is_empty() {
        return false;
    }
    // 语句关键字开头的行不是参数类型声明：`return x;` 也是"两 token + 无括号 + 无 =`"，
    // 不设这道闸就会被当成 K&R 参数行（跨语言误召回的入口）。
    const STMT: [&str; 12] = [
        "return", "goto", "break", "continue", "case", "default", "else", "do", "throw",
        "sizeof", "defined", "static_assert",
    ];
    if let Some(first) = body.split_whitespace().next() {
        if STMT.contains(&first) {
            return false;
        }
    }
    let mut toks = 0usize;
    for tok in body.split_whitespace() {
        let bare = tok.trim_matches(|c| c == '*' || c == '&' || c == '[' || c == ']');
        if bare.is_empty() {
            continue;
        }
        if !bare.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return false;
        }
        toks += 1;
    }
    toks >= 2 // 至少"类型 + 名字"：`int id;` 通过，`return;` 不通过
}

fn c_opens_block(code: &[String], idx: usize) -> bool {
    let mut depth = 0i32;
    let mut closed = false;
    for (k, line) in code.iter().enumerate().skip(idx).take(24) {
        let t = line.trim();
        // 预处理器指令**不是代码**：`#if/#else/#endif` 对签名与函数体是透明的。
        // 实测 nginx 把同一签名写在两个条件分支里、函数体放在 `#endif` 之后
        // （`ngx_log_error_core`），不跳过 `#` 行就会漏掉它。
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if closed {
            if t.starts_with('{') {
                return true;
            }
            // K&R：签名闭合后可能是**参数类型声明行**，之后才轮到 `{`
            if kr_param_line(t) {
                continue;
            }
            // 另一分支里重复的签名/声明：继续往下找体；遇到语句或块结束则放弃
            if t.starts_with('}') || t.contains(';') {
                return false;
            }
            continue;
        }
        for ch in t.chars() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
        }
        if depth <= 0 {
            closed = true;
            if t.ends_with('{') {
                return true; // 单行式 `void f(void) {`
            }
        }
    }
    false
}

/// C/C++ 顶层函数定义的函数名（顶格 `名字(` + 签名闭合后的 `{`）。
///
/// 只认**顶格**（列 0）：C 的函数定义在列 0，而函数体内的续行/表达式都带缩进，
/// 这条约束把"函数体内以标识符开头的行、宏调用、K&R 续行"全部挡在外面。
/// 另两种形态也覆盖：① 名字独占一行时要求**上一行是类型行**（`static ngx_int_t`）；
/// ② 单行式 `void foo(void) {` 直接取 `(` 前最后一个标识符。
fn c_function_name(code: &[String], idx: usize) -> Option<String> {
    let raw_line = code.get(idx)?;
    if raw_line.trim_start().len() != raw_line.trim_end().len() {
        return None; // 有缩进 ⇒ 不是顶层定义
    }
    let t = raw_line.trim_end();
    if t.is_empty() || t.starts_with('#') || t.starts_with("//") || t.starts_with("/*") {
        return None;
    }
    // 以 `;` 结尾 ⇒ 是调用/声明语句，不是定义头（`foo(bar);`）
    if t.ends_with(';') {
        return None;
    }
    let open = t.find('(')?;
    let head = t[..open].trim_end();
    let name: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if name.is_empty() || C_CTRL.contains(&name.as_str()) {
        return None;
    }
    let opens = c_opens_block(code, idx);
    if !opens {
        return None;
    }
    // 名字独占一行（head 只有 `*`/`&`）：必须有类型行在前
    let head_bare = head.trim_matches(|c| c == '*' || c == '&').trim();
    if head_bare.is_empty() {
        if !prev_code_line(code, idx).map(|s| c_type_line(&s)).unwrap_or(false) {
            return None;
        }
    }
    Some(name)
}

pub fn declared_names(line: &str) -> Vec<String> {    let mut out: Vec<String> = Vec::new();
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

/// 由 per-file 倒排派生全局倒排：`identifier → [(文件下标, 行号)]`
fn build_ident_map(
    file_idents: &[HashMap<String, Vec<u32>>],
) -> HashMap<String, Vec<(u32, u32)>> {
    let mut map: HashMap<String, Vec<(u32, u32)>> = HashMap::new();
    for (file, idents) in file_idents.iter().enumerate() {
        for (name, lines) in idents {
            let entry = map.entry(name.clone()).or_default();
            for line in lines {
                entry.push((file as u32, *line));
            }
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

    /// 磁盘缓存：新进程（仅清进程内缓存）应零解析载入；改一个文件只重解析一个
    #[test]
    fn test_disk_cache_avoids_reparse() {
        let root = fixture("persist");
        // 磁盘缓存按根路径哈希命名，会跨测试进程残留：先清掉再跑，保证断言确定性
        let _ = std::fs::remove_file(persist_path(&root));
        invalidate(&root);
        let (first, _, _) = get_or_build(&root, true, None);
        let full = first.parsed_files();
        assert!(full >= 2, "首次应解析全部文件: {full}");
        assert!(persist_path(&root).exists(), "应写出磁盘缓存");

        // 模拟新进程：只清进程内缓存，磁盘缓存仍在
        invalidate(&root);
        let (second, _, _) = get_or_build(&root, true, None);
        assert_eq!(
            second.parsed_files(),
            0,
            "磁盘缓存命中时不应重新解析任何文件"
        );
        assert_eq!(second.definitions("handler", 5).len(), 1, "载入后定义仍可查");
        assert!(
            !second.identifier_hits("request").is_empty(),
            "载入后引用仍可查"
        );

        // 新增一个文件 → 只重解析该文件
        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(
            root.join("src/changed.py"),
            "def changed_symbol():\n    pass\n",
        )
        .unwrap();
        invalidate(&root);
        let (third, _, _) = get_or_build(&root, true, None);
        assert_eq!(
            third.parsed_files(),
            1,
            "磁盘缓存 + 增量：只应重解析变化的文件"
        );
        assert_eq!(third.definitions("changed_symbol", 5).len(), 1);

        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(persist_path(&root));
    }

    /// 括号块声明（`var (` / `const (` / `type (`）内的行没有关键字，也必须进索引
    /// K&R 风格定义：签名之后是**参数类型声明行**（带 `;`），再 `{`。
    /// 实测 CVE-2020-8597 的 `pppd/eap.c` 因为这种风格整函数进不了索引，
    /// 漏洞点的切片因此 `function_scope=unresolved`。
    #[test]
    fn test_kr_style_definition_is_indexed() {
        let root = fixture("krdefs");
        std::fs::write(
            root.join("src/kr.c"),
            "static void\neap_request(esp, id, typenum, len, inp)\nEAP_STATE *esp;\nint id;\nint typenum;\nint len;\nunsigned char *inp;\n{\n    return;\n}\n",
        )
        .unwrap();
        invalidate(&root);
        let (index, _, _) = get_or_build(&root, true, None);
        assert!(
            !index.definitions("eap_request", 5).is_empty(),
            "K&R 风格定义应被索引"
        );
        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(persist_path(&root));
    }

    /// K&R 参数行判据本身：只认"类型 + 名字 + `;`"。
    #[test]
    fn test_kr_param_line() {
        for ok in ["EAP_STATE *esp;", "int id;", "char *inp;", "struct foo *p;"] {
            assert!(kr_param_line(ok), "{ok} 应判为参数类型声明行");
        }
        for bad in ["return;", "x = y;", "foo(bar);", "{", "int x = 1;"] {
            assert!(!kr_param_line(bad), "{bad} 不应判为参数类型声明行");
        }
    }

    /// 缓存必须与"索引构建逻辑"绑定：否则引擎改了抽取规则、旧缓存照旧命中，
    /// 新规则一次都不会跑（实测踩过：C 抽取规则改了而 nginx 的 symbols 恒为 391）。
    /// 刻意**不碰文件系统**：先前用 `fixture()` 建临时目录，同一测试会一过一败。
    #[test]
    fn test_persist_path_is_version_scoped() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let root = std::path::Path::new("/nonexistent-ctx-audit-cache-key-probe");
        let mut h = DefaultHasher::new();
        cache_key(root).hash(&mut h);
        let legacy = std::env::temp_dir()
            .join("ctx-audit-index")
            .join(format!("{:016x}.json", h.finish()));
        assert_ne!(
            persist_path(root),
            legacy,
            "缓存键必须包含索引逻辑版本与 crate 版本"
        );
    }

    /// 直接命中抽取路径：`index_content` 是索引的唯一入口，先在这里定位问题，
    /// 避免把"规则错"和"索引层/缓存没生效"混在一起（上一轮就吃了这个亏）。
    #[test]
    fn test_c_decl_extraction_direct() {
        let src = "static ngx_int_t\nngx_resolver_copy(ngx_resolver_t *r, u_char *src)\n{\n    return NGX_OK;\n}\n";
        let (defs, _, idents) = index_content("src/a.c", src);
        assert!(
            defs.iter().any(|(n, _, _)| n == "ngx_resolver_copy"),
            "index_content 应抽出 C 定义，实际 defs={defs:?}"
        );
        assert!(idents.contains_key("ngx_resolver_copy"), "标识符应同时在倒排里");
        // 参数表跨行（nginx 规范写法）
        let src2 = "static ngx_int_t\nngx_resolver_multi(ngx_resolver_t *r, u_char *src,\n    u_char *last)\n{\n    return NGX_OK;\n}\n";
        let (defs2, _, _) = index_content("src/b.c", src2);
        assert!(
            defs2.iter().any(|(n, _, _)| n == "ngx_resolver_multi"),
            "跨行参数表应被抽出，实际 defs={defs2:?}"
        );
        // 条件编译：签名写在 `#if/#else` 两分支、体在 `#endif` 之后（nginx 实际写法）
        let src3 = "#if (NGX_HAVE_VARIADIC_MACROS)\n\nvoid\nngx_log_error_core(ngx_uint_t level, ngx_log_t *log,\n    ngx_err_t err, const char *fmt, ...)\n\n#else\n\nvoid\nngx_log_error_core(ngx_uint_t level, ngx_log_t *log,\n    ngx_err_t err, const char *fmt, ...)\n\n#endif\n{\n    return;\n}\n";
        let (defs3, _, _) = index_content("src/c.c", src3);
        assert!(
            defs3.iter().any(|(n, _, _)| n == "ngx_log_error_core"),
            "跨条件编译分支的签名应被抽出，实际 defs={defs3:?}"
        );
        // 纯函数级
        let code: Vec<String> = ["static ngx_int_t",
                                 "ngx_resolver_copy(ngx_resolver_t *r, u_char *src)",
                                 "{", "    return NGX_OK;", "}"]
            .iter().map(|s| s.to_string()).collect();
        assert_eq!(
            c_function_name(&code, 1).as_deref(),
            Some("ngx_resolver_copy")
        );
        assert!(c_opens_block(&code, 1));
    }

    /// C 的规范定义风格：返回类型一行、函数名**顶格**一行、`{` 再一行。
    /// 行内没有任何 `fn/def/class/struct` 关键字，旧实现直接跳过 ⇒ 这类函数
    /// **一个都抽不出来**（实测 nginx `src/core` 定义召回 0/60，ctags 真值 416）。
    /// 同时覆盖单行式 `void f(void) {` 与 `#define` 宏（C 的 sink 常藏在宏里）。
    #[test]
    fn test_c_style_function_definitions_are_indexed() {
        let root = fixture("cdefs");
        std::fs::write(
            root.join("src/ngx_resolver.c"),
            "static ngx_int_t\nngx_resolver_copy(ngx_resolver_t *r, u_char *src)\n{\n    return NGX_OK;\n}\n\nstatic ngx_int_t\nngx_resolver_multi(ngx_resolver_t *r, ngx_str_t *name, u_char *buf,\n    u_char *src, u_char *last)\n{\n    return NGX_OK;\n}\n\nint ngx_cdecl\nmain(int argc, char *const *argv)\n{\n    return 0;\n}\n\nvoid ngx_single(void) {\n}\n\n#define NGX_RESOLVER_MAX 16\n#define NGX_CLAMP(x) ((x) > 0 ? (x) : 0)\n",
        )
        .unwrap();
        invalidate(&root);
        let (index, _, _) = get_or_build(&root, true, None);
        for name in [
            "ngx_resolver_copy",
            "ngx_resolver_multi",
            "main",
            "ngx_single",
            "NGX_RESOLVER_MAX",
            "NGX_CLAMP",
        ] {
            assert!(
                !index.definitions(name, 5).is_empty(),
                "{name} 应被 C 规则索引"
            );
        }
        // 反例：控制语句不得被当成定义
        for name in ["if", "return", "sizeof"] {
            assert!(
                index.definitions(name, 5).is_empty(),
                "{name} 不应被当成函数定义"
            );
        }
        // 缩进的行不是顶层定义（函数体内的续行/表达式）
        std::fs::write(
            root.join("src/indented.c"),
            "int outer(void)\n{\n    inner_call(1);\n    return 0;\n}\n",
        )
        .unwrap();
        invalidate(&root);
        // 该夹具出现过一次间歇失败（同一轮里"刷新"后的第二个 build 看不到刚写入的文件）：
        // 先把磁盘缓存也清掉，让 refresh 路径不依赖上一次运行留下的 persist 文件。
        let _ = std::fs::remove_file(persist_path(&root));
        let (index2, _, _) = get_or_build(&root, true, None);
        assert!(
            !index2.definitions("outer", 5).is_empty(),
            "outer 应被索引"
        );
        assert!(
            index2.definitions("inner_call", 5).is_empty(),
            "缩进的调用不得被当成定义"
        );
        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(persist_path(&root));
    }

    #[test]
    fn test_bracket_block_declarations_are_indexed() {        let root = fixture("blockdecl");
        std::fs::write(
            root.join("src/block.go"),
            "package main\n\nvar (\n\tErrA = errors.New(\"a\")\n\tErrB = errors.New(\"b\")\n)\n\nconst (\n\tMaxN = 10\n)\n\ntype (\n\tWidget struct{}\n)\n",
        )
        .unwrap();
        invalidate(&root);
        let (index, _, _) = get_or_build(&root, true, None);
        for name in ["ErrA", "ErrB", "MaxN", "Widget"] {
            assert!(
                !index.definitions(name, 5).is_empty(),
                "{name} 应在括号块声明里被索引"
            );
        }
        invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_file(persist_path(&root));
    }
}
