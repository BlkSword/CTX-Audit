use crate::ast::cache::{CacheData, FileIndex};
use crate::ast::{ASTParser, CacheManager, QueryEngine};
use ignore::Walk;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

pub struct ASTEngine {
    parser: Arc<Mutex<ASTParser>>,
    cache_manager: Arc<Mutex<CacheManager>>,
    query_engine: Arc<Mutex<Option<QueryEngine>>>,
}

impl ASTEngine {
    pub fn new(cache_dir: &str) -> Self {
        Self {
            parser: Arc::new(Mutex::new(ASTParser::new())),
            cache_manager: Arc::new(Mutex::new(CacheManager::new(cache_dir))),
            query_engine: Arc::new(Mutex::new(None)),
        }
    }

    pub fn use_repository(&self, repo_path: &str) {
        let mut cache_manager = self.cache_manager.lock().unwrap();
        cache_manager.use_repository(repo_path);

        // Load existing cache if available
        if let Some(cache_data) = cache_manager.load_cache() {
            let mut query_engine = self.query_engine.lock().unwrap();
            *query_engine = Some(QueryEngine::new(cache_data));
        } else {
            // Initialize empty cache
            let cache_data = CacheData {
                index: std::collections::HashMap::new(),
                class_map: std::collections::HashMap::new(),
                build_time: chrono::Utc::now().to_rfc3339(),
            };
            let mut query_engine = self.query_engine.lock().unwrap();
            *query_engine = Some(QueryEngine::new(cache_data));
        }
    }

    pub fn scan_project(&self, root_path: &str) -> Result<usize, String> {
        let root_path = PathBuf::from(root_path);
        if !root_path.exists() {
            return Err(format!("Path '{}' does not exist", root_path.display()));
        }

        // Collect all files to process
        let mut files_to_process = Vec::new();

        for entry in Walk::new(&root_path) {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() && self.is_supported_file(path) {
                    files_to_process.push(path.to_path_buf());
                }
            }
        }

        let total_files = files_to_process.len();
        log::info!(
            "Found {} files to scan in {}",
            total_files,
            root_path.display()
        );

        // Process files in parallel
        let processed_files: Vec<_> = files_to_process
            .par_iter()
            .filter_map(|file_path| {
                if let Err(e) = self.update_file(file_path) {
                    log::error!("Error updating file {}: {}", file_path.display(), e);
                    None
                } else {
                    Some(file_path.clone())
                }
            })
            .collect();

        // Save cache
        if let Err(e) = self.save_cache() {
            log::error!("Failed to save cache: {}", e);
        }

        log::info!(
            "Successfully processed {} out of {} files",
            processed_files.len(),
            total_files
        );
        Ok(processed_files.len())
    }

    pub fn update_file(&self, file_path: &Path) -> Result<(), String> {
        if !file_path.exists() {
            // Remove from cache if file was deleted
            self.remove_file_from_cache(file_path);
            return Ok(());
        }

        let cache_manager = self.cache_manager.lock().unwrap();

        // Check if file needs updating
        let file_path_str = file_path.to_string_lossy().to_string();
        let needs_update = if let Some(query_engine) = self.query_engine.lock().unwrap().as_ref() {
            if let Some(file_index) = query_engine.cache.index.get(&file_path_str) {
                cache_manager.is_file_changed(file_path, file_index.mtime)?
            } else {
                true
            }
        } else {
            true
        };

        if !needs_update {
            return Ok(());
        }

        // Read and parse file
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        let symbols = {
            let mut parser = self.parser.lock().unwrap();
            parser.parse_file(file_path, &content)?
        };

        // Update cache
        let mtime = cache_manager.get_file_mtime(file_path)?;
        let file_index = FileIndex { mtime, symbols };

        let mut query_engine = self.query_engine.lock().unwrap();
        if let Some(ref mut engine) = *query_engine {
            engine.cache.index.insert(file_path_str.clone(), file_index);

            // Update class map
            for symbol in &engine.cache.index[&file_path_str].symbols {
                if matches!(symbol.kind, crate::ast::symbol::SymbolKind::Class) {
                    engine
                        .cache
                        .class_map
                        .insert(symbol.name.clone(), file_path_str.clone());
                }
            }
        }

        Ok(())
    }

    pub fn save_cache(&self) -> Result<(), String> {
        let cache_manager = self.cache_manager.lock().unwrap();
        if let Some(query_engine) = self.query_engine.lock().unwrap().as_ref() {
            cache_manager.save_cache(&query_engine.cache)?;
        }
        Ok(())
    }

    pub fn get_statistics(&self) -> Result<serde_json::Value, String> {
        let query_engine = self.query_engine.lock().unwrap();
        if let Some(ref engine) = *query_engine {
            Ok(engine.get_statistics())
        } else {
            Err("No cache loaded".to_string())
        }
    }

    pub fn generate_report(&self, repository_path: &str) -> Result<serde_json::Value, String> {
        let query_engine = self.query_engine.lock().unwrap();
        if let Some(ref engine) = *query_engine {
            let report = engine.generate_report(repository_path);

            // Save report to cache
            let cache_manager = self.cache_manager.lock().unwrap();
            cache_manager.save_analysis_report(&report)?;

            Ok(report)
        } else {
            Err("No cache loaded".to_string())
        }
    }

    pub fn search_symbols(&self, query: &str) -> Result<Vec<String>, String> {
        let query_engine = self.query_engine.lock().unwrap();
        if let Some(ref engine) = *query_engine {
            let results = engine.search_symbols(query);
            Ok(results.iter().map(|s| s.to_dict().to_string()).collect())
        } else {
            Err("No cache loaded".to_string())
        }
    }

    pub fn find_call_sites(&self, callee_name: &str) -> Result<Vec<String>, String> {
        let query_engine = self.query_engine.lock().unwrap();
        if let Some(ref engine) = *query_engine {
            let results = engine.find_call_sites(callee_name);
            Ok(results.iter().map(|s| s.to_dict().to_string()).collect())
        } else {
            Err("No cache loaded".to_string())
        }
    }

    pub fn get_call_graph(
        &self,
        entry: &str,
        max_depth: usize,
    ) -> Result<serde_json::Value, String> {
        let query_engine = self.query_engine.lock().unwrap();
        if let Some(ref engine) = *query_engine {
            Ok(engine.get_call_graph(entry, max_depth))
        } else {
            Err("No cache loaded".to_string())
        }
    }

    pub fn get_file_structure(&self, file_path: &str) -> Result<Vec<String>, String> {
        let query_engine = self.query_engine.lock().unwrap();
        if let Some(ref engine) = *query_engine {
            let results = engine.get_file_structure(file_path);
            Ok(results.iter().map(|s| s.to_dict().to_string()).collect())
        } else {
            Err("No cache loaded".to_string())
        }
    }

    pub fn get_class_hierarchy(&self, class_name: &str) -> Result<serde_json::Value, String> {
        let query_engine = self.query_engine.lock().unwrap();
        if let Some(ref engine) = *query_engine {
            Ok(engine.get_class_hierarchy(class_name))
        } else {
            Err("No cache loaded".to_string())
        }
    }

    pub fn get_analysis_report(&self) -> Result<Option<serde_json::Value>, String> {
        let cache_manager = self.cache_manager.lock().unwrap();
        Ok(cache_manager.load_analysis_report())
    }

    fn is_supported_file(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext = ext.to_str().unwrap_or("");
            matches!(
                ext,
                "js" | "jsx"
                    | "py"
                    | "java"
                    | "rs"
                    | "go"
                    | "ts"
                    | "tsx"
                    | "html"
                    | "htm"
                    | "vue"
                    | "css"
                    | "json"
                    | "c"
                    | "h"
                    | "cpp"
                    | "hpp"
                    | "cc"
            )
        } else {
            false
        }
    }

    fn remove_file_from_cache(&self, file_path: &Path) {
        let file_path_str = file_path.to_string_lossy().to_string();
        let mut query_engine = self.query_engine.lock().unwrap();
        if let Some(ref mut engine) = *query_engine {
            // Remove from index
            if let Some(file_index) = engine.cache.index.remove(&file_path_str) {
                // Remove from class map
                for symbol in &file_index.symbols {
                    if matches!(symbol.kind, crate::ast::symbol::SymbolKind::Class) {
                        engine.cache.class_map.remove(&symbol.name);
                    }
                }
            }
        }
    }
}

// Security scanner functionality
pub struct SecurityScanner;

impl SecurityScanner {
    pub fn scan_file(
        file_path: &Path,
        custom_rules: &std::collections::HashMap<String, Vec<CustomRule>>,
    ) -> Result<Vec<SecurityFinding>, String> {
        let mut findings = Vec::new();

        if let Some(ext) = file_path.extension() {
            let ext = format!(".{}", ext.to_str().unwrap_or(""));

            if let Some(rules) = custom_rules.get(&ext) {
                let content = std::fs::read_to_string(file_path)
                    .map_err(|e| format!("Failed to read file: {}", e))?;

                for (line_num, line) in content.lines().enumerate() {
                    for rule in rules {
                        if let Ok(re) = regex::Regex::new(&rule.pattern) {
                            if re.is_match(line) {
                                findings.push(SecurityFinding {
                                    file: file_path.to_string_lossy().to_string(),
                                    line: line_num + 1,
                                    severity: rule.severity.clone(),
                                    message: rule.message.clone(),
                                    code: line.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    pub fn scan_directory(
        path: &Path,
        custom_rules: &std::collections::HashMap<String, Vec<CustomRule>>,
        include_dirs: &[String],
        exclude_dirs: &[String],
    ) -> Result<Vec<SecurityFinding>, String> {
        let mut files_to_scan = Vec::new();

        // Default exclude patterns
        let default_excludes = vec![
            "node_modules".to_string(),
            ".git".to_string(),
            "target".to_string(),
            "__pycache__".to_string(),
            ".venv".to_string(),
            "dist".to_string(),
            "build".to_string(),
        ];

        // Combine exclude directories
        let excludes: Vec<String> = default_excludes
            .into_iter()
            .chain(exclude_dirs.iter().cloned())
            .collect();

        // Collect files with filtering
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            // Check if directory should be excluded
            if let Some(path_str) = path.to_str() {
                if excludes.iter().any(|exclude| path_str.contains(exclude)) {
                    continue;
                }
            }

            // Check if we should include this directory
            if !include_dirs.is_empty() {
                if let Ok(rel_path) = path.strip_prefix(path) {
                    let rel_path_str = rel_path.to_string_lossy();
                    if !include_dirs
                        .iter()
                        .any(|include| rel_path_str.contains(include))
                    {
                        continue;
                    }
                }
            }

            if path.is_file() {
                files_to_scan.push(path.to_path_buf());
            }
        }

        log::info!(
            "Found {} files to scan in {}",
            files_to_scan.len(),
            path.display()
        );

        // Scan files in parallel
        let results = files_to_scan
            .par_iter()
            .filter_map(|file_path| Self::scan_file(file_path, custom_rules).ok())
            .flatten()
            .collect();

        Ok(results)
    }
}

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub pattern: String,
    pub message: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub file: String,
    pub line: usize,
    pub severity: String,
    pub message: String,
    pub code: String,
}
