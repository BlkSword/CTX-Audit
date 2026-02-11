// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 项目索引和缓存系统
//!
//! 管理 AST 索引、符号缓存、文件监控

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::fs;
use chrono::{DateTime, Utc};

use deepaudit_core::{ASTEngine, CacheData};
use crate::database::Database;

/// 项目索引状态
#[derive(Debug, Clone, PartialEq)]
pub enum IndexStatus {
    /// 未索引
    NotIndexed,

    /// 索引中
    Indexing { progress: u8 },

    /// 已索引
    Indexed {
        file_count: usize,
        symbol_count: usize,
        indexed_at: DateTime<Utc>,
    },

    /// 索引失败
    Failed { error: String },
}

/// 项目索引信息
#[derive(Debug, Clone)]
pub struct ProjectIndex {
    /// 项目路径
    pub project_path: String,

    /// 索引状态
    pub status: IndexStatus,

    /// 最后修改时间
    pub last_modified: DateTime<Utc>,

    /// 索引版本
    pub index_version: String,

    /// 需要重新索引
    pub needs_reindex: bool,
}

/// 索引管理器
pub struct IndexManager {
    /// 数据库
    db: Arc<Database>,

    /// AST 引擎
    ast_engine: Arc<ASTEngine>,

    /// 项目索引缓存
    indexes: Arc<RwLock<HashMap<String, ProjectIndex>>>,

    /// 配置
    config: IndexConfig,
}

/// 索引配置
#[derive(Debug, Clone)]
pub struct IndexConfig {
    /// 是否启用自动索引
    pub enable_auto_index: bool,

    /// 索引超时（秒）
    pub index_timeout_secs: u64,

    /// 最大索引文件数
    pub max_files: usize,

    /// 索引缓存目录
    pub cache_dir: PathBuf,

    /// 是否监控文件变化
    pub enable_watch: bool,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            enable_auto_index: true,
            index_timeout_secs: 300,
            max_files: 10000,
            cache_dir: dirs::cache_dir()
                .unwrap_or_else(|| PathBuf::from(".cache"))
                .join("ctx-audit")
                .join("index"),
            enable_watch: false,
        }
    }
}

impl IndexManager {
    /// 创建新的索引管理器
    pub fn new(db: Arc<Database>, ast_engine: Arc<ASTEngine>) -> Self {
        let config = IndexConfig::default();

        // 确保缓存目录存在
        let _ = std::fs::create_dir_all(&config.cache_dir);

        Self {
            db,
            ast_engine,
            indexes: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// 设置配置
    pub fn with_config(mut self, config: IndexConfig) -> Self {
        self.config = config;
        self
    }

    /// 获取项目索引状态
    pub async fn get_index_status(&self, project_path: &str) -> IndexStatus {
        let indexes = self.indexes.read().await;

        if let Some(index) = indexes.get(project_path) {
            return index.status.clone();
        }

        IndexStatus::NotIndexed
    }

    /// 索引项目
    pub async fn index_project(
        &self,
        project_path: &str,
    ) -> Result<ProjectIndex, String> {
        // 检查路径是否存在
        let path = Path::new(project_path);
        if !path.exists() {
            return Err(format!("项目路径不存在: {}", project_path));
        }

        // 更新状态为索引中
        self.update_index_status(project_path, IndexStatus::Indexing { progress: 0 }).await;

        // 执行索引
        let file_count = self.ast_engine.scan_project(project_path)
            .map_err(|e| format!("索引失败: {}", e))?;

        // 获取统计信息
        let stats = self.ast_engine.get_statistics()
            .map_err(|e| format!("获取统计失败: {}", e))?;

        let symbol_count = stats["total_nodes"]
            .as_u64()
            .unwrap_or(0) as usize;

        // 更新状态为已索引
        let index = ProjectIndex {
            project_path: project_path.to_string(),
            status: IndexStatus::Indexed {
                file_count,
                symbol_count,
                indexed_at: Utc::now(),
            },
            last_modified: self.get_last_modified(project_path).await,
            index_version: "1.0".to_string(),
            needs_reindex: false,
        };

        // 保存到缓存
        let mut indexes = self.indexes.write().await;
        indexes.insert(project_path.to_string(), index.clone());

        Ok(index)
    }

    /// 检查是否需要重新索引
    pub async fn needs_reindex(&self, project_path: &str) -> bool {
        let indexes = self.indexes.read().await;

        if let Some(index) = indexes.get(project_path) {
            if index.needs_reindex {
                return true;
            }

            // 检查最后修改时间
            let last_modified = self.get_last_modified(project_path).await;
            last_modified > index.last_modified
        } else {
            true
        }
    }

    /// 增量更新索引
    pub async fn update_index(
        &self,
        project_path: &str,
    ) -> Result<usize, String> {
        let indexes = self.indexes.read().await;

        // 获取当前状态
        let current_status = indexes
            .get(project_path)
            .map(|i| i.status.clone())
            .unwrap_or(IndexStatus::NotIndexed);

        match current_status {
            IndexStatus::Indexed { file_count, .. } => {
                // 扫描变化
                let modified_files = self.scan_modified_files(project_path).await?;

                let mut updated_count = 0;
                for file in &modified_files {
                    if let Err(e) = self.ast_engine.update_file(file) {
                        tracing::warn!("更新文件 {} 失败: {}", file.display(), e);
                    } else {
                        updated_count += 1;
                    }
                }

                Ok(updated_count)
            }
            _ => {
                // 需要完全重新索引
                let index = self.index_project(project_path).await?;
                if let IndexStatus::Indexed { file_count, .. } = index.status {
                    Ok(file_count)
                } else {
                    Ok(0)
                }
            }
        }
    }

    /// 获取项目符号
    pub async fn get_symbols(&self, project_path: &str, query: &str) -> Vec<SymbolInfo> {
        // 从 AST 引擎搜索
        match self.ast_engine.search_symbols(query) {
            Ok(symbols) => {
                symbols.into_iter()
                    .filter(|s| s.file_path.starts_with(project_path))
                    .map(|s| SymbolInfo {
                        name: s.name.clone(),
                        kind: s.kind_to_string(),
                        file_path: s.file_path.clone(),
                        line: s.start_line,
                        code: s.code.clone(),
                    })
                    .collect()
            }
            Err(_) => Vec::new(),
        }
    }

    /// 获取文件结构
    pub async fn get_file_structure(&self, file_path: &str) -> Result<FileStructure, String> {
        let symbols = self.ast_engine.get_file_structure(file_path)
            .map_err(|e| format!("获取文件结构失败: {}", e))?;

        let mut classes = Vec::new();
        let mut functions = Vec::new();
        let mut imports = Vec::new();

        for symbol in symbols {
            match symbol.kind {
                deepaudit_core::SymbolKind::Class | deepaudit_core::SymbolKind::Interface => {
                    classes.push(SymbolItem {
                        name: symbol.name.clone(),
                        line: symbol.start_line,
                        end_line: symbol.end_line,
                        doc: symbol.code.chars().take(100).collect(),
                    });
                }
                deepaudit_core::SymbolKind::Function | deepaudit_core::SymbolKind::Method => {
                    functions.push(SymbolItem {
                        name: symbol.name.clone(),
                        line: symbol.start_line,
                        end_line: symbol.end_line,
                        doc: symbol.code.chars().take(100).collect(),
                    });
                }
                _ => {}
            }
        }

        Ok(FileStructure {
            file_path: file_path.to_string(),
            classes,
            functions,
            imports,
        })
    }

    /// 扫描修改的文件
    async fn scan_modified_files(&self, project_path: &str) -> Result<Vec<PathBuf>, String> {
        let mut modified_files = Vec::new();
        let indexes = self.indexes.read().await;

        // 获取上次索引时间
        let index_time = indexes
            .get(project_path)
            .and_then(|i| {
                if let IndexStatus::Indexed { indexed_at, .. } = i.status {
                    Some(indexed_at)
                } else {
                    None
                }
            });

        let path = Path::new(project_path);

        // 遍历项目目录
        let mut entries = fs::read_dir(path)
            .await
            .map_err(|e| format!("读取目录失败: {}", e))?;

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| format!("遍历目录失败: {}", e))?
        {
            let entry_path = entry.path();

            if entry_path.is_file() && self.is_source_file(&entry_path) {
                // 检查修改时间
                if let Ok(metadata) = entry.metadata().await {
                    if let Ok(modified) = metadata.modified() {
                        if let Some(index_time) = index_time {
                            if modified > index_time {
                                modified_files.push(entry_path);
                            }
                        } else {
                            modified_files.push(entry_path);
                        }
                    }
                }
            }
        }

        Ok(modified_files)
    }

    /// 判断是否是源代码文件
    fn is_source_file(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            matches!(
                ext.to_str(),
                Some("rs") | Some("py") | Some("js") | Some("jsx") |
                Some("ts") | Some("tsx") | Some("go") | Some("java") |
                Some("c") | Some("h") | Some("cpp") | Some("hpp") |
                Some("cc") | Some("cxx") | Some("html") | Some("css")
            )
        } else {
            false
        }
    }

    /// 获取项目最后修改时间
    async fn get_last_modified(&self, project_path: &str) -> DateTime<Utc> {
        let path = Path::new(project_path);

        // 递归获取最新修改时间
        match self.recursive_last_modified(path).await {
            Ok(time) => time,
            Err(_) => Utc::now(),
        }
    }

    /// 递归获取最后修改时间
    async fn recursive_last_modified(&self, path: &Path) -> Result<DateTime<Utc>, std::io::Error> {
        let mut latest = fs::metadata(path)
            .await?
            .modified()?
            .into();

        if path.is_dir() {
            let mut entries = fs::read_dir(path).await?;

            while let Some(entry) = entries.next_entry().await? {
                let entry_path = entry.path();
                if let Ok(time) = self.recursive_last_modified(&entry_path).await {
                    if time > latest {
                        latest = time;
                    }
                }
            }
        }

        Ok(latest)
    }

    /// 更新索引状态
    async fn update_index_status(&self, project_path: &str, status: IndexStatus) {
        let mut indexes = self.indexes.write().await;

        let index = indexes.entry(project_path.to_string())
            .or_insert_with(|| ProjectIndex {
                project_path: project_path.to_string(),
                status: IndexStatus::NotIndexed,
                last_modified: Utc::now(),
                index_version: "1.0".to_string(),
                needs_reindex: false,
            });

        index.status = status;
    }

    /// 清除索引
    pub async fn clear_index(&self, project_path: &str) -> Result<(), String> {
        // 从内存中移除
        let mut indexes = self.indexes.write().await;
        indexes.remove(project_path);
        drop(indexes);

        // 清除磁盘缓存
        self.clear_disk_cache(project_path).await?;

        // 从数据库中删除相关符号
        if let Ok(db) = Database::with_default_path().await {
            // 获取项目 ID
            let pool = db.pool();
            if let Ok(Some(project)) = crate::database::ProjectQueries::get_by_path(pool, project_path).await {
                // 删除符号
                let _ = sqlx::query("DELETE FROM symbols WHERE project_id = ?")
                    .bind(project.id)
                    .execute(pool)
                    .await;

                // 删除项目文件
                let _ = sqlx::query("DELETE FROM project_files WHERE project_id = ?")
                    .bind(project.id)
                    .execute(pool)
                    .await;

                tracing::info!("已清除数据库中的索引数据: {}", project_path);
            }
        }

        Ok(())
    }

    /// 清除磁盘缓存
    async fn clear_disk_cache(&self, project_path: &str) -> Result<(), String> {
        // 获取缓存目录
        let cache_dir = self.get_cache_dir(project_path)?;

        // 如果缓存目录存在，删除它
        if cache_dir.exists() {
            fs::remove_dir_all(&cache_dir)
                .await
                .map_err(|e| format!("删除缓存目录失败: {}", e))?;

            tracing::info!("已清除磁盘缓存: {}", cache_dir.display());
        }

        Ok(())
    }

    /// 获取缓存目录
    fn get_cache_dir(&self, project_path: &str) -> Result<PathBuf, String> {
        // 获取系统缓存目录
        let cache_base = dirs::cache_dir()
            .ok_or_else(|| "无法获取缓存目录".to_string())?;

        // 创建项目特定的缓存目录
        let project_hash = self.hash_path(project_path);
        let cache_dir = cache_base
            .join("ctx-audit")
            .join("projects")
            .join(project_hash);

        Ok(cache_dir)
    }

    /// 生成路径哈希
    fn hash_path(&self, path: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// 获取所有索引
    pub async fn list_indexes(&self) -> Vec<ProjectIndex> {
        let indexes = self.indexes.read().await;
        indexes.values().cloned().collect()
    }
}

/// 符号信息
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// 符号名称
    pub name: String,

    /// 符号类型
    pub kind: String,

    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: u32,

    /// 代码片段
    pub code: String,
}

/// 文件结构
#[derive(Debug, Clone)]
pub struct FileStructure {
    /// 文件路径
    pub file_path: String,

    /// 类列表
    pub classes: Vec<SymbolItem>,

    /// 函数列表
    pub functions: Vec<SymbolItem>,

    /// 导入列表
    pub imports: Vec<SymbolItem>,
}

/// 符号项
#[derive(Debug, Clone)]
pub struct SymbolItem {
    /// 名称
    pub name: String,

    /// 起始行
    pub line: u32,

    /// 结束行
    pub end_line: u32,

    /// 文档字符串
    pub doc: String,
}
