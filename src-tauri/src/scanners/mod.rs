pub mod manager;
pub mod regex_scanner;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Finding {
    pub finding_id: String,
    pub file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub detector: String,
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    pub analysis_trail: Option<String>,
    pub llm_output: Option<String>,
}

#[async_trait]
pub trait Scanner: Send + Sync {
    fn name(&self) -> String;
    async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding>;
}
