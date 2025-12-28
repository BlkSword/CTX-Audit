use crate::ast::symbol::Symbol;
use serde::{Deserialize, Serialize};
use sha1::Digest;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndex {
    pub mtime: u64,
    pub symbols: Vec<Symbol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub index: HashMap<String, FileIndex>,
    pub class_map: HashMap<String, String>, // class_name -> file_path
    pub build_time: String,
}

pub struct CacheManager {
    base_cache_dir: PathBuf,
    cache_dir: PathBuf,
    repository_path: Option<PathBuf>,
}

impl CacheManager {
    pub fn new(base_cache_dir: &str) -> Self {
        let base_cache_dir = PathBuf::from(base_cache_dir);
        Self {
            base_cache_dir: base_cache_dir.clone(),
            cache_dir: base_cache_dir,
            repository_path: None,
        }
    }

    pub fn use_repository(&mut self, repo_path: &str) {
        let abs_path = fs::canonicalize(repo_path).unwrap_or_else(|_| PathBuf::from(repo_path));
        let mut hasher = sha1::Sha1::new();
        hasher.update(abs_path.to_string_lossy().as_bytes());
        let key = format!("{:x}", hasher.finalize());
        let key = key.chars().take(16).collect::<String>();

        self.repository_path = Some(abs_path.clone());
        self.cache_dir = self.base_cache_dir.join(&key);
    }

    pub fn load_cache(&self) -> Option<CacheData> {
        if !self.cache_dir.exists() {
            return None;
        }

        let cache_file = self.cache_dir.join("ast_index.bin");
        if !cache_file.exists() {
            return None;
        }

        match fs::read(&cache_file) {
            Ok(data) => match bincode::deserialize::<CacheData>(&data) {
                Ok(cache) => Some(cache),
                Err(e) => {
                    log::error!("Failed to deserialize cache: {}", e);
                    None
                }
            },
            Err(e) => {
                log::error!("Failed to read cache file: {}", e);
                None
            }
        }
    }

    pub fn save_cache(&self, cache_data: &CacheData) -> Result<(), String> {
        if !self.cache_dir.exists() {
            if let Err(e) = fs::create_dir_all(&self.cache_dir) {
                return Err(format!("Failed to create cache directory: {}", e));
            }
        }

        let cache_file = self.cache_dir.join("ast_index.bin");
        let serialized = bincode::serialize(cache_data)
            .map_err(|e| format!("Failed to serialize cache: {}", e))?;

        fs::write(&cache_file, serialized)
            .map_err(|e| format!("Failed to write cache file: {}", e))?;

        Ok(())
    }

    pub fn save_analysis_report(&self, report: &serde_json::Value) -> Result<(), String> {
        if !self.cache_dir.exists() {
            if let Err(e) = fs::create_dir_all(&self.cache_dir) {
                return Err(format!("Failed to create cache directory: {}", e));
            }
        }

        let report_file = self.cache_dir.join("analysis_report.json");
        let json_str = serde_json::to_string_pretty(report)
            .map_err(|e| format!("Failed to serialize report: {}", e))?;

        fs::write(&report_file, json_str)
            .map_err(|e| format!("Failed to write report file: {}", e))?;

        Ok(())
    }

    pub fn load_analysis_report(&self) -> Option<serde_json::Value> {
        let report_file = self.cache_dir.join("analysis_report.json");
        if !report_file.exists() {
            return None;
        }

        match fs::read_to_string(&report_file) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(report) => Some(report),
                Err(e) => {
                    log::error!("Failed to parse analysis report: {}", e);
                    None
                }
            },
            Err(e) => {
                log::error!("Failed to read analysis report: {}", e);
                None
            }
        }
    }

    pub fn get_file_mtime(&self, file_path: &Path) -> Result<u64, String> {
        let metadata =
            fs::metadata(file_path).map_err(|e| format!("Failed to get file metadata: {}", e))?;

        let mtime = metadata
            .modified()
            .map_err(|e| format!("Failed to get file modification time: {}", e))?;

        let duration = mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| format!("Failed to convert system time: {}", e))?;

        Ok(duration.as_secs())
    }

    pub fn is_file_changed(&self, file_path: &Path, cached_mtime: u64) -> Result<bool, String> {
        let current_mtime = self.get_file_mtime(file_path)?;
        Ok(current_mtime != cached_mtime)
    }

    pub fn get_cache_dir(&self) -> &Path {
        &self.cache_dir
    }
}
