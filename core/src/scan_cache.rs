// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 扫描结果缓存
//!
//! 将 `ScanResult`（含 findings 与跨文件调用图）持久化到项目本地目录，
//! 在项目文件、规则、扫描选项未发生变化时直接复用，跳过昂贵的扫描阶段。

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::scanning::ScanResult;

/// 缓存文件常量
pub const SCAN_CACHE_FILE: &str = "scan_cache.bin";
pub const SCAN_CACHE_MANIFEST: &str = "scan_cache_manifest.json";

/// 单个文件在缓存清单中的元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    /// 相对于项目根目录的路径
    pub relative_path: String,
    /// 文件修改时间（秒级）
    pub mtime_secs: u64,
    /// 文件大小（字节）
    pub size: u64,
}

/// 扫描缓存清单
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCacheManifest {
    /// 项目绝对路径（仅作信息记录）
    pub project_path: String,
    /// 缓存生成时间戳（毫秒）
    pub created_at_ms: u64,
    /// rules 目录内容哈希
    pub rules_hash: String,
    /// 扫描选项哈希
    pub options_hash: String,
    /// 被扫描的文件清单
    pub files: Vec<FileManifest>,
}

/// 尝试加载已缓存的扫描结果
///
/// 若缓存不存在、清单解析失败或项目文件/规则/选项发生变化，返回 None。
pub fn load_scan_result(
    cache_dir: &Path,
    project_path: &Path,
    rules_hash: &str,
    options_hash: &str,
) -> Option<ScanResult> {
    let manifest_path = cache_dir.join(SCAN_CACHE_MANIFEST);
    let cache_path = cache_dir.join(SCAN_CACHE_FILE);

    if !manifest_path.exists() || !cache_path.exists() {
        return None;
    }

    let manifest: ScanCacheManifest = match fs::read_to_string(&manifest_path) {
        Ok(text) => serde_json::from_str(&text).ok()?,
        Err(_) => return None,
    };

    if manifest.rules_hash != rules_hash || manifest.options_hash != options_hash {
        log::debug!(
            "[ScanCache] rules/options 变化，rules {} -> {}, options {} -> {}",
            manifest.rules_hash,
            rules_hash,
            manifest.options_hash,
            options_hash
        );
        return None;
    }

    if !is_manifest_valid(project_path, &manifest.files) {
        log::debug!("[ScanCache] 项目文件发生变化，缓存失效");
        return None;
    }

    let compressed = fs::read(&cache_path).ok()?;
    let data = match zstd::decode_all(compressed.as_slice()) {
        Ok(d) => d,
        Err(e) => {
            log::warn!("[ScanCache] 解压缓存失败：{}，将重新扫描", e);
            return None;
        }
    };
    let text = match String::from_utf8(data) {
        Ok(t) => t,
        Err(e) => {
            log::warn!("[ScanCache] 缓存不是有效 UTF-8：{}，将重新扫描", e);
            return None;
        }
    };
    match serde_json::from_str::<ScanResult>(&text) {
        Ok(result) => {
            log::info!("[ScanCache] 命中缓存：{} 个 finding", result.findings.len());
            Some(result)
        }
        Err(e) => {
            log::warn!("[ScanCache] 反序列化失败：{}，将重新扫描", e);
            None
        }
    }
}

/// 保存扫描结果到缓存
pub fn save_scan_result(
    cache_dir: &Path,
    project_path: &Path,
    scan_result: &ScanResult,
    rules_hash: &str,
    options_hash: &str,
) -> Result<(), String> {
    if let Err(e) = fs::create_dir_all(cache_dir) {
        return Err(format!("创建缓存目录失败: {}", e));
    }

    let files = build_project_manifest(project_path)?;
    let manifest = ScanCacheManifest {
        project_path: project_path.to_string_lossy().to_string(),
        created_at_ms: current_time_ms(),
        rules_hash: rules_hash.to_string(),
        options_hash: options_hash.to_string(),
        files,
    };

    let manifest_path = cache_dir.join(SCAN_CACHE_MANIFEST);
    let cache_path = cache_dir.join(SCAN_CACHE_FILE);

    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("序列化缓存清单失败: {}", e))?;
    fs::write(&manifest_path, manifest_json)
        .map_err(|e| format!("写入缓存清单失败: {}", e))?;

    let json = serde_json::to_string(scan_result)
        .map_err(|e| format!("序列化扫描结果失败: {}", e))?;
    let compressed = zstd::encode_all(json.as_bytes(), 0)
        .map_err(|e| format!("压缩缓存失败: {}", e))?;
    fs::write(&cache_path, compressed).map_err(|e| format!("写入缓存文件失败: {}", e))?;

    log::info!(
        "[ScanCache] 已保存缓存：{} findings，缓存目录: {}",
        scan_result.findings.len(),
        cache_dir.display()
    );
    Ok(())
}

/// 清除项目缓存
pub fn clear_scan_cache(cache_dir: &Path) -> Result<(), String> {
    let manifest_path = cache_dir.join(SCAN_CACHE_MANIFEST);
    let cache_path = cache_dir.join(SCAN_CACHE_FILE);
    if manifest_path.exists() {
        fs::remove_file(&manifest_path).map_err(|e| e.to_string())?;
    }
    if cache_path.exists() {
        fs::remove_file(&cache_path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// 计算 rules 目录的内容哈希
pub fn compute_rules_hash(rules_dir: &Path) -> String {
    if !rules_dir.exists() {
        return hash_bytes(b"");
    }

    let mut entries: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for entry in walkdir::WalkDir::new(rules_dir).sort_by_file_name() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let content = match fs::read(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        entries.push((entry.path().to_path_buf(), content));
    }

    // 稳定排序后做摘要，确保哈希与文件系统遍历顺序无关
    let mut hasher = sha2::Sha256::new();
    for (path, content) in &entries {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update(content);
    }
    format!("{:x}", hasher.finalize())[..16].to_string()
}

/// 计算扫描选项的哈希
pub fn compute_options_hash<T: Serialize>(opts: &T) -> String {
    let json = match serde_json::to_string(opts) {
        Ok(s) => s,
        Err(_) => return hash_bytes(b""),
    };
    hash_bytes(json.as_bytes())
}

/// 构建项目文件清单
fn build_project_manifest(project_path: &Path) -> Result<Vec<FileManifest>, String> {
    let mut files = Vec::new();
    let exclude_dirs: HashSet<&str> = [
        ".git",
        "node_modules",
        "target",
        "vendor",
        ".ctx-audit",
    ]
    .iter()
    .cloned()
    .collect();

    for entry in ignore::WalkBuilder::new(project_path).hidden(false).build() {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // 跳过常见排除目录
        if path.components().any(|c| {
            if let std::path::Component::Normal(name) = c {
                exclude_dirs.contains(name.to_string_lossy().as_ref())
            } else {
                false
            }
        }) {
            continue;
        }

        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let relative_path = match path.strip_prefix(project_path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => path.to_string_lossy().to_string(),
        };

        let mtime = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        files.push(FileManifest {
            relative_path,
            mtime_secs: mtime,
            size: metadata.len(),
        });
    }

    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(files)
}

/// 验证缓存清单是否与当前项目文件一致
fn is_manifest_valid(project_path: &Path, manifest_files: &[FileManifest]) -> bool {
    let current = match build_project_manifest(project_path) {
        Ok(v) => v,
        Err(_) => return false,
    };

    if current.len() != manifest_files.len() {
        return false;
    }

    for (a, b) in current.iter().zip(manifest_files.iter()) {
        if a.relative_path != b.relative_path
            || a.mtime_secs != b.mtime_secs
            || a.size != b.size
        {
            return false;
        }
    }

    true
}

fn hash_bytes(data: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(data))[..16].to_string()
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_rules_hash_changes_with_content() {
        let tmp = std::env::temp_dir().join("ctx-rules-hash-test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let rule = tmp.join("rule.yaml");
        fs::write(&rule, "pattern: abc").unwrap();

        let h1 = compute_rules_hash(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&rule)
            .unwrap();
        writeln!(f, "pattern: xyz").unwrap();
        drop(f);

        let h2 = compute_rules_hash(&tmp);
        assert_ne!(h1, h2);
        let _ = fs::remove_dir_all(&tmp);
    }
}
