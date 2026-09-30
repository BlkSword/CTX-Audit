// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 进程内项目索引缓存（索引底座）。
//!
//! 目的：把"每次工具调用都重新遍历项目"降级为"TTL 内复用同一份索引"，
//! 让符号跳转 / 单函数切片在缓存命中时达到延迟目标
//! （符号跳转 p95 < 10ms、单函数切片 p95 < 50ms，均为缓存命中口径）。
//!
//! 当前用 TTL + 显式 `refresh` 失效；后续由 daemon 增量索引提供
//! 文件级 mtime 失效与局部重编译，本模块对外接口保持不变。
//!
//! 约定：
//! - 缓存键是规范化后的项目根路径（Windows 下大小写不敏感）；
//! - 缓存是进程内全局状态，长驻进程（daemon / mcp）受益最大；
//! - 构建在锁内完成，避免同一 key 的并发重复遍历；构建期间不持锁做别的判断。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 默认 TTL（毫秒）。`CTX_AUDIT_INDEX_TTL_MS=0` 表示不缓存。
pub const DEFAULT_TTL_MS: u64 = 5_000;

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
}

struct Entry {
    index: Arc<ProjectIndex>,
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

/// 取索引：TTL 内算命中并复用，否则调用 `build` 重建。
///
/// 返回 `(索引, 是否命中缓存)`。
pub fn get_or_build<F>(
    root: &Path,
    refresh: bool,
    ttl: Duration,
    build: F,
) -> (Arc<ProjectIndex>, bool)
where
    F: FnOnce() -> ProjectIndex,
{
    let key = cache_key(root);

    match registry().lock() {
        Ok(mut reg) => {
            if !refresh && !ttl.is_zero() {
                if let Some(entry) = reg.get(&key) {
                    if entry.index.age() < ttl {
                        return (entry.index.clone(), true);
                    }
                }
            }
            let index = Arc::new(build());
            reg.insert(
                key,
                Entry {
                    index: index.clone(),
                },
            );
            (index, false)
        }
        // 锁中毒只影响缓存效果，不影响功能：退化为不缓存
        Err(_) => (Arc::new(build()), false),
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

    fn temp_root(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ctx-audit-index-cache-{tag}"));
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
            built_at: Instant::now(),
        }
    }

    #[test]
    fn test_cache_hit_within_ttl() {
        clear();
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

        assert!(!hit1, "首次调用不应命中缓存");
        assert!(hit2, "TTL 内第二次调用应命中缓存");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "构建只应发生一次");
        assert_eq!(first.build_id, "id-first");
        assert_eq!(second.build_id, "id-first", "命中时应复用首次构建结果");
        assert!(Arc::ptr_eq(&first, &second), "命中时应共享同一份索引");

        invalidate(&root);
    }

    #[test]
    fn test_refresh_forces_rebuild() {
        clear();
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

        assert!(!hit1);
        assert!(!hit2, "refresh=true 必须绕过缓存");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(second.build_id, "id-2");

        // refresh 之后的新结果应重新进入缓存
        let (third, hit3) = get_or_build(&root, false, ttl, || {
            calls.fetch_add(1, Ordering::SeqCst);
            synthetic("root", "id-3")
        });
        assert!(hit3);
        assert_eq!(third.build_id, "id-2");

        invalidate(&root);
    }

    #[test]
    fn test_zero_ttl_never_caches() {
        clear();
        let root = temp_root("zero-ttl");
        let calls = AtomicUsize::new(0);

        for _ in 0..2 {
            let (_, hit) = get_or_build(&root, false, Duration::ZERO, || {
                calls.fetch_add(1, Ordering::SeqCst);
                synthetic("root", "id")
            });
            assert!(!hit, "TTL=0 时不应命中");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        invalidate(&root);
    }

    #[test]
    fn test_invalidate_and_stats() {
        clear();
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
}
