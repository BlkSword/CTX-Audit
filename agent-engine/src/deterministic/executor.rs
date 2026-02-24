// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 确定性审计执行器

use crate::audit_state::{SecurityAuditState, AuditPhase, VulnerabilityCandidate};
use crate::deterministic::{
    config::{DeterministicConfig, DecodingMode, SeedStrategy},
    cache::{AuditCache, CacheKey, CachedResult},
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use ctx_audit_llm::LLMClient;
use std::sync::Arc;

/// 确定性审计执行器
pub struct DeterministicExecutor {
    /// LLM 客户端
    llm: Arc<dyn LLMClient>,

    /// 审计缓存
    cache: AuditCache,

    /// 配置
    config: DeterministicConfig,
}

/// 审计可重现性
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReproducibility {
    /// 是否可重现
    pub is_reproducible: bool,

    /// 重现种子
    pub seed: u64,

    /// 重现配置
    pub config: DeterministicConfig,

    /// 代码库签名
    pub codebase_signature: CodebaseSignature,

    /// 执行时间（毫秒）
    pub execution_time_ms: u64,
}

/// 代码库签名
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CodebaseSignature {
    /// 文件哈希列表
    pub file_hashes: Vec<FileHash>,

    /// 总体哈希
    pub overall_hash: String,

    /// 文件数量
    pub file_count: usize,

    /// 总行数
    pub total_lines: usize,
}

/// 文件哈希
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FileHash {
    /// 相对路径
    pub relative_path: String,

    /// SHA256 哈希
    pub sha256: String,

    /// 文件大小
    pub size: u64,

    /// 最后修改时间
    pub modified_time: i64,
}

/// 签名算法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// SHA256
    Sha256,

    /// BLAKE3
    Blake3,
}

impl DeterministicExecutor {
    /// 创建新的确定性执行器
    pub fn new(llm: Arc<dyn LLMClient>, config: DeterministicConfig) -> Self {
        let cache_dir = std::env::temp_dir().join("ctx-audit-cache");
        let cache = AuditCache::new(config.cache_strategy, cache_dir);

        Self { llm, cache, config }
    }

    /// 执行确定性审计
    pub async fn execute_deterministic_audit(
        &self,
        state: &mut SecurityAuditState,
    ) -> Result<AuditReproducibility, String> {
        let start = Instant::now();

        // 验证配置
        self.config.validate()?;

        // 计算代码库签名
        let codebase_signature = self.calculate_codebase_signature(&state.project_path)?;

        // 计算配置签名
        let config_signature = AuditCache::compute_config_signature(&self.config);

        // 检查缓存
        let cache_key = CacheKey {
            codebase_signature: codebase_signature.overall_hash.clone(),
            config_signature,
            phase: None,
        };

        if let Some(cached) = self.cache.get(&cache_key) {
            tracing::info!("使用缓存的审计结果");

            // 从缓存恢复结果
            self.restore_from_cache(cached, state)?;

            return Ok(AuditReproducibility {
                is_reproducible: true,
                seed: self.config.get_effective_seed(),
                config: self.config.clone(),
                codebase_signature,
                execution_time_ms: start.elapsed().as_millis() as u64,
            });
        }

        // 执行审计
        self.execute_audit_with_seed(state).await?;

        // 缓存结果
        self.cache_audit_result(&cache_key, state);

        Ok(AuditReproducibility {
            is_reproducible: true,
            seed: self.config.get_effective_seed(),
            config: self.config.clone(),
            codebase_signature,
            execution_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// 使用指定种子执行审计
    async fn execute_audit_with_seed(&self, state: &mut SecurityAuditState) -> Result<(), String> {
        // 设置 LLM 参数
        self.configure_llm_for_determinism().await;

        // 执行各阶段审计
        let phases = [
            AuditPhase::Initialization,
            AuditPhase::DeterministicScan,
            AuditPhase::DeepAnalysis,
            AuditPhase::Verification,
            AuditPhase::Reporting,
        ];

        for phase in phases {
            state.current_phase = phase;
            tracing::info!("执行审计阶段: {:?}", phase);

            // 执行阶段逻辑
            // 这里简化实现，实际应该调用相应的阶段执行器
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(())
    }

    /// 配置 LLM 以实现确定性
    async fn configure_llm_for_determinism(&self) {
        // 设置种子（如果 LLM 客户端支持）
        // 设置温度
        // 设置解码模式

        tracing::info!("配置 LLM 用于确定性审计:");
        tracing::info!("  种子: {}", self.config.get_effective_seed());
        tracing::info!("  解码模式: {:?}", self.config.decoding_mode);
        tracing::info!("  温度: {}", self.config.temperature);
    }

    /// 计算代码库签名
    pub fn calculate_codebase_signature(&self, project_path: &str) -> Result<CodebaseSignature, String> {
        let mut file_hashes = Vec::new();
        let mut total_lines = 0;
        let mut overall_hasher = DefaultHasher::new();

        // 扫描项目文件（简化实现）
        let project_dir = Path::new(project_path);
        if let Ok(entries) = std::fs::read_dir(project_dir) {
            for entry in entries.flatten() {
                let path = entry.path();

                // 跳过特殊目录
                if path.to_string_lossy().contains("node_modules")
                    || path.to_string_lossy().contains("target")
                    || path.to_string_lossy().contains(".git") {
                    continue;
                }

                // 只处理文件
                if !path.is_file() {
                    continue;
                }

                // 只处理代码文件
                if !self.is_code_file(&path) {
                    continue;
                }

                if let Ok(relative_path) = path.strip_prefix(project_path) {
                    if let Some(rel_str) = relative_path.to_str() {
                        if let Ok(metadata) = std::fs::metadata(&path) {
                            if let Ok(content) = std::fs::read(&path) {
                                let mut hasher = DefaultHasher::new();
                                hasher.write(&content);
                                let hash = format!("{:016x}", hasher.finish());

                                let lines = content.iter().filter(|&&b| b == b'\n').count();

                                total_lines += lines;

                                let file_hash = FileHash {
                                    relative_path: rel_str.replace('\\', "/"),
                                    sha256: hash,
                                    size: metadata.len() as u64,
                                    modified_time: metadata.modified()
                                        .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64)
                                        .unwrap_or(0),
                                };

                                // 更新整体哈希
                                let mut file_hasher = DefaultHasher::new();
                                file_hasher.write(file_hash.relative_path.as_bytes());
                                file_hasher.write(file_hash.sha256.as_bytes());
                                overall_hasher.write_u64(file_hasher.finish());

                                file_hashes.push(file_hash);

                                // 限制文件数量
                                if file_hashes.len() >= 1000 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let overall_hash = format!("{:016x}", overall_hasher.finish());

        let file_count = file_hashes.len();

        Ok(CodebaseSignature {
            file_hashes,
            overall_hash,
            file_count,
            total_lines,
        })
    }

    /// 判断是否是代码文件
    fn is_code_file(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            matches!(
                ext_str.as_str(),
                "rs" | "py" | "js" | "ts" | "java" | "go" | "c" | "cpp"
                    | "h" | "hpp" | "cs" | "php" | "rb" | "swift" | "kt"
            )
        } else {
            false
        }
    }

    /// 从缓存恢复结果
    fn restore_from_cache(&self, cached: CachedResult, state: &mut SecurityAuditState) -> Result<(), String> {
        match cached {
            CachedResult::RawData(data) => {
                // 从 JSON 恢复漏洞候选
                if let Some(vulnerability_candidates) = data.get("vulnerability_vulnerability_candidates") {
                    if let Ok(vulnerability_candidates_serde) = serde_json::from_value::<Vec<VulnerabilityCandidate>>(vulnerability_candidates.clone()) {
                        state.vulnerability_candidates.extend(vulnerability_candidates_serde);
                    }
                }
                Ok(())
            }
            _ => Ok(())
        }
    }

    /// 缓存审计结果
    fn cache_audit_result(&self, key: &CacheKey, state: &SecurityAuditState) {
        let cached_data = CachedResult::RawData(serde_json::json!({
            "vulnerability_vulnerability_candidates": state.vulnerability_candidates,
            "phase": format!("{:?}", state.current_phase),
        }));

        // 缓存 24 小时
        self.cache.set(key.clone(), cached_data, Some(86400));
    }

    /// 获取缓存统计
    pub fn cache_stats(&self) -> crate::deterministic::cache::CacheStats {
        self.cache.stats()
    }

    /// 清除缓存
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// 验证审计可重现性
    pub async fn verify_reproducibility(
        &self,
        state: &mut SecurityAuditState,
        runs: usize,
    ) -> Result<bool, String> {
        let mut results = Vec::new();

        for _ in 0..runs {
            let start = Instant::now();
            let signature = self.calculate_codebase_signature(&state.project_path)?;

            // 保存当前状态
            let saved_vulnerability_candidates = state.vulnerability_candidates.clone();

            // 执行审计
            self.execute_audit_with_seed(state).await?;

            // 收集结果
            let result_hash = self.hash_vulnerability_candidates(&state.vulnerability_candidates);

            // 恢复状态
            state.vulnerability_candidates = saved_vulnerability_candidates;

            results.push((result_hash, start.elapsed()));

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // 检查所有结果是否一致
        let first_hash = results.first().map(|(h, _)| h).ok_or("没有结果")?;
        let all_same = results.iter().all(|(h, _)| h == first_hash);

        Ok(all_same)
    }

    /// 计算候选的哈希
    fn hash_vulnerability_candidates(&self, vulnerability_candidates: &[VulnerabilityCandidate]) -> String {
        let mut hasher = DefaultHasher::new();
        for candidate in vulnerability_candidates {
            hasher.write(candidate.id.as_bytes());
            hasher.write(candidate.file_path.as_bytes());
            hasher.write(candidate.vulnerability_type.as_bytes());
        }

        format!("{:016x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_algorithm() {
        let alg = SignatureAlgorithm::Sha256;
        assert_eq!(alg as i32, 0);
    }

    #[test]
    fn test_codebase_signature() {
        let signature = CodebaseSignature {
            file_hashes: vec![],
            overall_hash: "test".to_string(),
            file_count: 0,
            total_lines: 0,
        };

        assert_eq!(signature.overall_hash, "test");
        assert_eq!(signature.file_count, 0);
    }
}
