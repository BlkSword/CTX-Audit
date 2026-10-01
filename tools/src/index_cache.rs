// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 进程内项目索引缓存（索引底座）。
//!
//! 目的：把"每次工具调用都重新遍历项目"降级为"TTL 内或 stat 探测确认未变时复用同一份索引"，
//! 让符号跳转 / 单函数切片在缓存命中时达到延迟目标
//! （符号跳转 p95 < 10ms、单函数切片 p95 < 50ms，均为缓存命中口径）。
//!
//! 三级新鲜度判定：
//! 1. `refresh=true` → 无条件重建；
//! 2. 距上次确认在 TTL 内 → 直接复用（[`HitSource::Ttl`]）；
//! 3. TTL 已过，但文件/目录 stat 指纹未变 → 复用（[`HitSource::Probe`]）。
//!
//! TTL 由 `CTX_AUDIT_INDEX_TTL_MS` 覆盖（默认 5s，**0 表示完全关闭缓存，含探测**）；
//! 探测由 `CTX_AUDIT_INDEX_PROBE=0` 关闭（退化为纯 TTL）。
//!
//! 显式局限（不假装健全）：
//! - 探测基于 mtime + size，mtime 精度不足（同一时间戳内改写且长度不变）时识别不出；
//! - 只有**已索引目录**内的增删会被目录指纹捕获；新目录的出现需要 TTL 兜底或显式 `refresh`；
//! - 达到文件数上限被截断时，只对已索引部分负责（截断事实本身在 `truncated_at_limit` 暴露）。
//!
//! 约定：
//! - 缓存键是规范化后的项目根路径（Windows 下大小写不敏感）；
//! - 缓存是进程内全局状态，长驻进程（daemon / mcp）受益最大；
//! - 构建在锁内完成，避免同一 key 的并发重复遍历。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 默认 TTL（毫秒）。`CTX_AUDIT_INDEX_TTL_MS=0` 表示完全关闭缓存。
pub const DEFAULT_TTL_MS: u64 = 5_000;

// ────────────────────────────────────────────────────────
// 新鲜度指纹
// ────────────────────────────────────────────────────────

/// 文件级新鲜度指纹（stat 级，不读内容）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStamp {
    /// 相对路径（分隔符统一为 `/`）
    pub path: String,
    /// 修改时间（epoch 毫秒；平台不提供时为 0）
    pub mtime_ms: u64,
    /// 字节数
    pub size: u64,
}

/// 目录级新鲜度指纹：目录内新增/删除/改名文件会改变目录 mtime。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirStamp {
    /// 相对路径；项目根为空字符串
    pub path: String,
    /// 修改时间（epoch 毫秒）
    pub mtime_ms: u64,
}

/// stat 级新鲜度判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// 所有文件与目录指纹未变
    Unchanged,
    /// 至少一个文件/目录变了或消失
    Changed,
    /// 没有可用指纹，无法判断
    Unknown,
}

impl Freshness {
    /// 是否可安全复用缓存。
    pub fn is_unchanged(self) -> bool {
        matches!(self, Freshness::Unchanged)
    }
}

/// 一次索引构建的产物（不含缓存判定信息）。
#[derive(Debug)]
pub struct ProjectIndex {
    /// 展示用的项目根（未规范化）
    pub root: String,
    /// 相对路径 -> 文件内容
    pub files: Vec<(String, String)>,
    /// 确定性构建标识：同一份文件集合与内容得到同一 id
    pub build_id: String,
    /// 因超过单文件大小上限而跳过的文件数
    pub skipped_large: usize,
    /// 是否因达到文件数上限而提前停止遍历
    pub truncated_at_limit: bool,
    /// 已索引文件的 stat 指纹
    pub file_stamps: Vec<FileStamp>,
    /// 已遍历目录的 stat 指纹
    pub dir_stamps: Vec<DirStamp>,
    /// 构建时刻
    pub built_at: Instant,
}

impl ProjectIndex {
    /// 距今多久构建的。
    pub fn age(&self) -> Duration {
        self.built_at.elapsed()
    }

    /// 已索引内容总字节数。
    pub fn total_bytes(&self) -> usize {
        self.files.iter().map(|(_, c)| c.len()).sum()
    }

    /// stat 级新鲜度判定：不重新遍历目录、不读文件内容。
    ///
    /// 任一枚举文件的时间戳为 0（平台不支持）时返回 [`Freshness::Unknown`]——宁可不命中。
    pub fn freshness(&self, root: &Path) -> Freshness {
        if self.file_stamps.is_empty() {
            return Freshness::Unknown;
        }
        if self.file_stamps.iter().any(|f| f.mtime_ms == 0) {
            return Freshness::Unknown;
        }
        for dir in &self.dir_stamps {
            if dir.mtime_ms == 0 {
                continue;
            }
            if stat_mtime_ms(&dir_real_path(root, &dir.path)) != Some(dir.mtime_ms) {
                return Freshness::Changed;
            }
        }
        for file in &self.file_stamps {
            let same = match std::fs::metadata(root.join(&file.path)) {
                Ok(meta) => meta.len() == file.size && mtime_ms(&meta) == file.mtime_ms,
                Err(_) => false,
            };
            if !same {
                return Freshness::Changed;
            }
        }
        Freshness::Unchanged
    }

    /// 与构建时相比发生变化的条目（文件相对路径；目录以 `dir/` 形式列出，上限 200 条）。
    ///
    /// 目录条目表示"该目录内有增删"，具体增删的文件名需要重新遍历才能确定。
    pub fn changed_stamps(&self, root: &Path) -> Vec<String> {
        const MAX: usize = 200;
        let mut out: Vec<String> = Vec::new();
        for dir in &self.dir_stamps {
            if dir.mtime_ms == 0 {
                continue;
            }
            if stat_mtime_ms(&dir_real_path(root, &dir.path)) != Some(dir.mtime_ms) {
                out.push(if dir.path.is_empty() {
                    "<root>/".to_string()
                } else {
                    format!("{}/", dir.path)
                });
                if out.len() >= MAX {
                    return out;
                }
            }
        }
        for file in &self.file_stamps {
            let same = match std::fs::metadata(root.join(&file.path)) {
                Ok(meta) => meta.len() == file.size && mtime_ms(&meta) == file.mtime_ms,
                Err(_) => false,
            };
            if !same {
                out.push(file.path.clone());
                if out.len() >= MAX {
                    return out;
                }
            }
        }
        out
    }
}

/// 目录相对路径 → 实际路径（根目录表示为空字符串）。
fn dir_real_path(root: &Path, rel: &str) -> PathBuf {
    if rel.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    }
}

/// 取文件修改时间的 epoch 毫秒；平台不支持时返回 0。
pub fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn stat_mtime_ms(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| mtime_ms(&m))
}

// ────────────────────────────────────────────────────────
// 缓存
// ────────────────────────────────────────────────────────

/// 命中来源，供调用方如实报告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitSource {
    /// TTL 内直接复用
    Ttl,
    /// TTL 已过，但 stat 探测确认未变
    Probe,
    /// 缓存未命中（首次构建 / 过期 / refresh / 探测失败 / 缓存关闭）
    Miss,
}

impl HitSource {
    /// 是否命中（TTL 或探测）。
    pub fn is_hit(self) -> bool {
        !matches!(self, HitSource::Miss)
    }

    /// 简短标签，用于 JSON 报告。
    pub fn as_str(self) -> &'static str {
        match self {
            HitSource::Ttl => "ttl",
            HitSource::Probe => "probe",
            HitSource::Miss => "miss",
        }
    }
}

/// 解析探测开关字符串：`0`/`false`/`no`/`off` 视为关闭。
pub fn probe_flag_enabled(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// 是否启用 stat 探测：`CTX_AUDIT_INDEX_PROBE=0` 关闭（退化为纯 TTL）。
pub fn probe_enabled() -> bool {
    match std::env::var("CTX_AUDIT_INDEX_PROBE") {
        Ok(v) => probe_flag_enabled(&v),
        Err(_) => true,
    }
}

/// 缓存时序与命中计数（增量状态上报用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTiming {
    /// 最近一次构建耗时（毫秒）
    pub last_build_ms: u64,
    /// 距上次新鲜度确认的时间（毫秒）
    pub validated_age_ms: u64,
    /// 累计 TTL 命中次数
    pub ttl_hits: u64,
    /// 累计 stat 探测命中次数
    pub probe_hits: u64,
}

struct Entry {
    index: Arc<ProjectIndex>,
    /// 上次确认仍然新鲜的时刻（构建或命中）
    validated_at: Instant,
    /// 最近一次构建耗时
    last_build_ms: u64,
    /// 累计 TTL 命中
    ttl_hits: u64,
    /// 累计探测命中
    probe_hits: u64,
}

fn registry() -> &'static Mutex<HashMap<String, Entry>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// TTL 解析：`CTX_AUDIT_INDEX_TTL_MS` 覆盖默认值，非法值回落到默认。
pub fn default_ttl() -> Duration {
    let ms = std::env::var("CTX_AUDIT_INDEX_TTL_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_MS);
    Duration::from_millis(ms)
}

/// 规范化缓存键：能 canonicalize 就用绝对路径，统一分隔符并做平台大小写折叠。
pub fn cache_key(root: &Path) -> String {
    let resolved: PathBuf = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let s = resolved.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        s.to_ascii_lowercase()
    } else {
        s
    }
}

/// 取索引：TTL 内或 stat 探测确认未变时复用，否则调用 `build` 重建。
///
/// `ttl` 为 [`Duration::ZERO`] 时完全关闭缓存（含探测），每次调用都重建。
/// 返回 `(索引, 命中来源)`。
pub fn get_or_build<F>(
    root: &Path,
    refresh: bool,
    ttl: Duration,
    build: F,
) -> (Arc<ProjectIndex>, HitSource)
where
    F: FnOnce() -> ProjectIndex,
{
    let key = cache_key(root);
    let probe = probe_enabled();

    match registry().lock() {
        Ok(mut reg) => {
            if !refresh && !ttl.is_zero() {
                if let Some(entry) = reg.get_mut(&key) {
                    // TTL 命中：只计数，**不**延长 validated_at——
                    // 否则探测关闭时缓存会被无限续期而永不失效。
                    if entry.validated_at.elapsed() < ttl {
                        entry.ttl_hits += 1;
                        return (entry.index.clone(), HitSource::Ttl);
                    }
                    // 探测命中 = 真正重新确认了新鲜度，可以续期
                    if probe && entry.index.freshness(root).is_unchanged() {
                        entry.validated_at = Instant::now();
                        entry.probe_hits += 1;
                        return (entry.index.clone(), HitSource::Probe);
                    }
                }
            }
            let started = Instant::now();
            let index = Arc::new(build());
            let last_build_ms = started.elapsed().as_millis() as u64;
            reg.insert(
                key,
                Entry {
                    index: index.clone(),
                    validated_at: Instant::now(),
                    last_build_ms,
                    ttl_hits: 0,
                    probe_hits: 0,
                },
            );
            (index, HitSource::Miss)
        }
        // 锁中毒只影响缓存效果，不影响功能：退化为不缓存
        Err(_) => (Arc::new(build()), HitSource::Miss),
    }
}

/// 缓存时序；没有该项目的缓存条目时为 `None`。
pub fn cache_timing(root: &Path) -> Option<CacheTiming> {
    let key = cache_key(root);
    match registry().lock() {
        Ok(reg) => reg.get(&key).map(|e| CacheTiming {
            last_build_ms: e.last_build_ms,
            validated_age_ms: e.validated_at.elapsed().as_millis() as u64,
            ttl_hits: e.ttl_hits,
            probe_hits: e.probe_hits,
        }),
        Err(_) => None,
    }
}

/// 相对缓存构建时刻已变化的条目（stat 级）；没有缓存条目时为 `None`。
///
/// 这是"待局部重编译"的观测口径：目录条目表示该目录内有增删。
pub fn changed_since_build(root: &Path) -> Option<Vec<String>> {
    let key = cache_key(root);
    match registry().lock() {
        Ok(reg) => reg.get(&key).map(|e| e.index.changed_stamps(root)),
        Err(_) => None,
    }
}

/// 丢弃某个项目的缓存条目，返回是否命中过。
pub fn invalidate(root: &Path) -> bool {
    let key = cache_key(root);
    match registry().lock() {
        Ok(mut reg) => reg.remove(&key).is_some(),
        Err(_) => false,
    }
}

/// 清空全部缓存（测试与维护用）。
pub fn clear() {
    if let Ok(mut reg) = registry().lock() {
        reg.clear();
    }
}

/// 缓存概览：`(条目数, 缓存内文件总数)`。
pub fn stats() -> (usize, usize) {
    match registry().lock() {
        Ok(reg) => (reg.len(), reg.values().map(|e| e.index.files.len()).sum()),
        Err(_) => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // 注意：缓存是进程内全局状态，测试并行运行。
    // 这里**不使用全局 `clear()`**（会互相清掉条目导致抖动），而是让每个用例
    // 使用自己独立的 `temp_root(tag)`（互不相同的 tag ⇒ 互不相同的缓存键），
    // 结束时只 `invalidate(&root)` 自己的条目。

    fn temp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ctx-audit-index-cache-{tag}"));
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::create_dir_all(&p);
        p
    }

    fn synthetic(root: &str, build_id: &str) -> ProjectIndex {
        ProjectIndex {
            root: root.to_string(),
            files: vec![(
                "src/main.rs".to_string(),
                "fn main() { helper(); }".to_string(),
            )],
            build_id: build_id.to_string(),
            skipped_large: 0,
            truncated_at_limit: false,
            file_stamps: Vec::new(),
            dir_stamps: Vec::new(),
            built_at: Instant::now(),
        }
    }

    /// 按磁盘真实状态生成指纹（本模块测试自洽用，不依赖上层 load_files）。
    fn stamps_from_disk(root: &Path) -> (Vec<FileStamp>, Vec<DirStamp>) {
        let mut files = Vec::new();
        let mut dirs = Vec::new();
        let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
        while let Some((dir, rel)) = stack.pop() {
            if let Ok(meta) = std::fs::metadata(&dir) {
                dirs.push(DirStamp {
                    path: rel.clone(),
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
                let child_rel = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                if path.is_dir() {
                    stack.push((path, child_rel));
                } else if let Ok(meta) = entry.metadata() {
                    files.push(FileStamp {
                        path: child_rel,
                        mtime_ms: mtime_ms(&meta),
                        size: meta.len(),
                    });
                }
            }
        }
        (files, dirs)
    }

    fn disk_index(root: &Path, build_id: &str) -> ProjectIndex {
        let (file_stamps, dir_stamps) = stamps_from_disk(root);
        ProjectIndex {
            root: root.to_string_lossy().to_string(),
            files: Vec::new(),
            build_id: build_id.to_string(),
            skipped_large: 0,
            truncated_at_limit: false,
            file_stamps,
            dir_stamps,
            built_at: Instant::now(),
        }
    }

    #[test]
    fn test_cache_hit_within_ttl() {
        let root = temp_root("hit");
        let calls = AtomicUsize::new(0);
        let ttl = Duration::from_secs(30);

        let (first, hit1) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            synthetic("root", "id-first")
        });
        let (second, hit2) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            synthetic("root", "id-second")
        });

        assert_eq!(hit1, HitSource::Miss, "首次调用不应命中缓存");
        assert_eq!(hit2, HitSource::Ttl, "TTL 内第二次调用应命中 TTL");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "构建只应发生一次");
        assert_eq!(first.build_id, "id-first");
        assert_eq!(second.build_id, "id-first", "命中时应复用首次构建结果");
        assert!(Arc::ptr_eq(&first, &second), "命中时应共享同一份索引");

        invalidate(&root);
    }

    #[test]
    fn test_refresh_forces_rebuild() {
        let root = temp_root("refresh");
        let calls = AtomicUsize::new(0);
        let ttl = Duration::from_secs(30);

        let (_, hit1) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            synthetic("root", "id-1")
        });
        let (second, hit2) = get_or_build(&root, true, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            synthetic("root", "id-2")
        });

        assert_eq!(hit1, HitSource::Miss);
        assert_eq!(hit2, HitSource::Miss, "refresh=true 必须绕过缓存");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(second.build_id, "id-2");

        // refresh 之后的新结果应重新进入缓存
        let (third, hit3) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            synthetic("root", "id-3")
        });
        assert_eq!(hit3, HitSource::Ttl);
        assert_eq!(third.build_id, "id-2");

        invalidate(&root);
    }

    #[test]
    fn test_zero_ttl_never_caches() {
        let root = temp_root("zero-ttl");
        let calls = AtomicUsize::new(0);

        for _ in 0..2 {
            let (_, hit) = get_or_build(&root, false, Duration::ZERO, || {
                calls.fetch_add(1, Ordering::SeqCst);
                synthetic("root", "id")
            });
            assert_eq!(hit, HitSource::Miss, "TTL=0 应关闭缓存（含探测）");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        invalidate(&root);
    }

    #[test]
    fn test_invalidate_and_stats() {
        let root = temp_root("invalidate");
        let (_, _) = get_or_build(&root, false, Duration::from_secs(30), || {
            synthetic("root", "id")
        });
        assert!(stats().0 >= 1);
        assert!(invalidate(&root));
        assert!(!invalidate(&root), "重复失效应返回 false");
    }

    #[test]
    fn test_cache_key_normalizes_separators() {
        let root = temp_root("key");
        let key = cache_key(&root);
        assert!(!key.contains('\\'), "缓存键不应含反斜杠: {key}");
        assert_eq!(key, cache_key(&root), "同一路径的键必须稳定");
    }

    #[test]
    fn test_probe_hit_after_ttl_expiry() {
        let root = temp_root("probe-hit");
        std::fs::write(root.join("a.txt"), "one").unwrap();
        let calls = AtomicUsize::new(0);
        let ttl = Duration::from_millis(1);

        let (_, hit1) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            disk_index(&root, "id-probe")
        });
        assert_eq!(hit1, HitSource::Miss);

        std::thread::sleep(Duration::from_millis(10));
        let (second, hit2) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            disk_index(&root, "id-rebuild")
        });
        assert_eq!(hit2, HitSource::Probe, "TTL 过期但文件未变应走探测命中");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "探测命中不应重建");
        assert_eq!(second.build_id, "id-probe");

        invalidate(&root);
    }

    #[test]
    fn test_probe_detects_content_change() {
        let root = temp_root("probe-changed");
        std::fs::write(root.join("a.txt"), "one").unwrap();
        let calls = AtomicUsize::new(0);
        let ttl = Duration::from_millis(1);

        let (_, _) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            disk_index(&root, "id-1")
        });
        std::thread::sleep(Duration::from_millis(10));
        // 追加内容：长度与 mtime 至少一项必变
        std::fs::write(root.join("a.txt"), "one-plus-more").unwrap();

        let (second, hit) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            disk_index(&root, "id-2")
        });
        assert_eq!(hit, HitSource::Miss, "文件变化后必须重建");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(second.build_id, "id-2");

        invalidate(&root);
    }

    #[test]
    fn test_probe_detects_new_file_in_indexed_dir() {
        let root = temp_root("probe-new-file");
        std::fs::write(root.join("a.txt"), "one").unwrap();
        let calls = AtomicUsize::new(0);
        let ttl = Duration::from_millis(1);

        let (_, _) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            disk_index(&root, "id-1")
        });
        std::thread::sleep(Duration::from_millis(10));
        // 目录指纹兜底：新增文件不改变已索引文件的 stat，但会改变目录 mtime
        std::fs::write(root.join("b.txt"), "two").unwrap();

        let (_, hit) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            disk_index(&root, "id-2")
        });
        assert_eq!(hit, HitSource::Miss, "目录内新增文件应使缓存失效");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        invalidate(&root);
    }

    #[test]
    fn test_changed_since_build_reports_paths() {
        let root = temp_root("changed-list");
        std::fs::write(root.join("a.txt"), "one").unwrap();
        let ttl = Duration::from_secs(30);
        let (_, _) = get_or_build(&root, false, ttl, || disk_index(&root, "id"));

        assert_eq!(
            changed_since_build(&root).unwrap().len(),
            0,
            "刚构建时不应有变化条目"
        );

        std::thread::sleep(Duration::from_millis(10));
        std::fs::write(root.join("a.txt"), "one-changed").unwrap();
        let changed = changed_since_build(&root).unwrap();
        assert!(
            changed.iter().any(|p| p == "a.txt"),
            "应报告变化文件: {changed:?}"
        );

        invalidate(&root);
    }

    #[test]
    fn test_freshness_unknown_without_stamps() {
        let root = temp_root("freshness-unknown");
        let index = synthetic("root", "id");
        assert_eq!(index.freshness(&root), Freshness::Unknown);
    }

    #[test]
    fn test_cache_timing_reports_last_build() {
        let root = temp_root("timing");
        std::fs::write(root.join("a.txt"), "one").unwrap();
        let ttl = Duration::from_secs(30);
        assert!(cache_timing(&root).is_none(), "未构建时不应有时序");

        let (_, hit) = get_or_build(&root, false, ttl, || disk_index(&root, "id"));
        assert_eq!(hit, HitSource::Miss);
        let timing = cache_timing(&root).expect("构建后应有时序");
        assert_eq!(timing.ttl_hits, 0);
        assert_eq!(timing.probe_hits, 0);

        let (_, hit2) = get_or_build(&root, false, ttl, || disk_index(&root, "id2"));
        assert_eq!(hit2, HitSource::Ttl);
        let timing2 = cache_timing(&root).expect("命中后应有时序");
        assert_eq!(timing2.ttl_hits, 1, "TTL 命中应计数");

        invalidate(&root);
    }

    #[test]
    fn test_probe_flag_parsing() {
        assert!(!probe_flag_enabled("0"));
        assert!(!probe_flag_enabled("false"));
        assert!(!probe_flag_enabled(" OFF "));
        assert!(!probe_flag_enabled("No"));
        assert!(probe_flag_enabled("1"));
        assert!(probe_flag_enabled(""));
        assert!(probe_flag_enabled("true"));
    }
}
