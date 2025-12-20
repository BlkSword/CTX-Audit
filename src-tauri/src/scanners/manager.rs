use super::{Finding, Scanner};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct ScannerManager {
    scanners: Vec<Arc<dyn Scanner>>,
}

impl ScannerManager {
    pub fn new() -> Self {
        Self {
            scanners: Vec::new(),
        }
    }

    pub fn register_scanner<S: Scanner + 'static>(&mut self, scanner: S) {
        self.scanners.push(Arc::new(scanner));
    }

    pub async fn scan_file(&self, path: &PathBuf, content: &str) -> Vec<Finding> {
        let mut all_findings = Vec::new();
        for scanner in &self.scanners {
            let findings = scanner.scan_file(path, content).await;
            all_findings.extend(findings);
        }
        all_findings
    }

    pub async fn scan_directory(&self, root_path: &str) -> Vec<Finding> {
        let walker = ignore::WalkBuilder::new(root_path).build();
        let mut set = tokio::task::JoinSet::new();

        for result in walker {
            if let Ok(entry) = result {
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    let path = entry.path().to_path_buf();
                    let manager = self.clone();

                    set.spawn(async move {
                        if let Ok(content) = tokio::fs::read_to_string(&path).await {
                            manager.scan_file(&path, &content).await
                        } else {
                            Vec::new()
                        }
                    });
                }
            }
        }

        let mut all_findings = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok(findings) = res {
                all_findings.extend(findings);
            }
        }
        all_findings
    }
}
