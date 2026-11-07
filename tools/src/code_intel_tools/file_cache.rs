// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 项目文件表进程内缓存（Phase 2：图缓存第一步）。
//!
//! 探针 / mini-SSA / 载荷蚂蚁每次查询都重建整份文件表；MCP server 常驻时
//! 重复调用会浪费同一份索引。这里做最小缓存：按 canonical 项目根缓存文件表，
//! TTL 60s；同一输入在 TTL 内输出保持逐字节一致（确定性红线不受影响）。
//! 文件改动后最迟 TTL 生效——交互式 agent 场景可接受，gate/CLI 单次进程不受影响。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use super::index;

type FileTable = Arc<Vec<(String, String)>>;
type Entry = (Instant, FileTable);

static CACHE: OnceLock<Mutex<HashMap<PathBuf, Entry>>> = OnceLock::new();
const TTL: Duration = Duration::from_secs(60);

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
    fn repeated_loads_share_one_snapshot() {
        let dir = tmp("a");
        let mut f = std::fs::File::create(dir.join("A.java")).unwrap();
        f.write_all(b"class A { void a() {} }\n").unwrap();
        let a = project_files(&dir);
        let b = project_files(&dir);
        assert!(Arc::ptr_eq(&a, &b), "同根目录应命中同一份文件表");
    }
}
