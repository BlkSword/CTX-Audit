// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 项目文件表进程内缓存（Phase 2：图缓存第一步）。
//!
//! 探针 / mini-SSA / 载荷蚂蚁每次查询都重建整份文件表；MCP server 常驻时
//! 重复调用会浪费同一份索引。这里做最小缓存：按 canonical 项目根缓存文件表，
//! TTL 60s；同一输入在 TTL 内输出保持逐字节一致（确定性红线不受影响）。
//! 文件改动后最迟 TTL 生效——交互式 agent 场景可接受，gate/CLI 单次进程不受影响。

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::chain;
use super::di;
use super::index;
use super::probe;

type FileTable = Arc<Vec<(String, String)>>;
type Entry = (Instant, FileTable);

static CACHE: OnceLock<Mutex<HashMap<PathBuf, Entry>>> = OnceLock::new();
const TTL: Duration = Duration::from_secs(60);

/// 单文件解析结果（定义/调用），按内容哈希缓存。
pub(crate) struct ParsedFile {
    pub defs: Arc<Vec<(String, u32)>>,
    pub calls: Arc<Vec<(String, u32, bool)>>,
}

static PARSED: OnceLock<Mutex<HashMap<u64, Arc<ParsedFile>>>> = OnceLock::new();
static DI_CACHE: OnceLock<Mutex<HashMap<PathBuf, (Instant, Arc<di::DiIndex>)>>> = OnceLock::new();
const PARSED_CAP: usize = 50_000;

/// 解析单文件（定义/调用）；同一内容重复查询直接命中缓存。
pub(crate) fn parsed_file(path: &str, content: &str) -> Arc<ParsedFile> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    content.hash(&mut h);
    let key = h.finish();
    let cache = PARSED.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut m) = cache.lock() {
        if let Some(p) = m.get(&key) {
            return p.clone();
        }
        let lang = chain::chain_language_of(path);
        let defs = probe::definitions_multi(content, lang);
        let calls: Vec<(String, u32, bool)> = chain::calls(content)
            .into_iter()
            .map(|(name, line, member, _install, _ctor)| (name, line, member))
            .collect();
        let parsed = Arc::new(ParsedFile {
            defs: Arc::new(defs),
            calls: Arc::new(calls),
        });
        if m.len() >= PARSED_CAP {
            m.clear();
        }
        m.insert(key, parsed.clone());
        return parsed;
    }
    Arc::new(ParsedFile {
        defs: Arc::new(Vec::new()),
        calls: Arc::new(Vec::new()),
    })
}

/// 取项目文件表（缓存命中直接返回 Arc；未命中加载并写入）。
pub(crate) fn project_files(root: &Path) -> FileTable {
    let key = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    if let Ok(mut m) = cache.lock() {
        if let Some((t, files)) = m.get(&key) {
            if now.duration_since(*t) < TTL {
                return files.clone();
            }
        }
        let loaded = index::load_files(root);
        let files: FileTable = Arc::new(loaded.files);
        m.insert(key, (now, files.clone()));
        return files;
    }
    Arc::new(index::load_files(root).files)
}

/// 取项目级 Spring DI 索引（按 canonical 根缓存，TTL 与文件表一致）。
pub(crate) fn project_di(root: &Path) -> Arc<di::DiIndex> {
    let key = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let files = project_files(root);
    let cache = DI_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    if let Ok(mut m) = cache.lock() {
        if let Some((t, idx)) = m.get(&key) {
            if now.duration_since(*t) < TTL {
                return idx.clone();
            }
        }
        let idx = Arc::new(di::parse(&files));
        m.insert(key, (now, idx.clone()));
        return idx;
    }
    Arc::new(di::parse(&files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ctx-fc-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn repeated_parse_of_same_content_is_cached() {
        let a = parsed_file("A.java", "class A { void a() {} }\n");
        let b = parsed_file("A.java", "class A { void a() {} }\n");
        assert!(Arc::ptr_eq(&a, &b), "同内容应命中解析缓存");
    }

    #[test]
    fn repeated_loads_share_one_snapshot() {
        let dir = tmp("a");
        let mut f = std::fs::File::create(dir.join("A.java")).unwrap();
        f.write_all(b"class A { void a() {} }\n").unwrap();
        let a = project_files(&dir);
        let b = project_files(&dir);
        assert!(Arc::ptr_eq(&a, &b), "同根目录应命中同一份文件表");
    }
}
