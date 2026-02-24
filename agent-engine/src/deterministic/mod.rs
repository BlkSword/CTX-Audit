// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 确定性审计模块
//!
//! 提供可重现的审计结果，使用固定种子、贪心解码和结果缓存

pub mod config;
pub mod cache;
pub mod executor;

pub use config::{
    DeterministicConfig, CacheStrategy,
    DecodingMode, SeedStrategy,
};
pub use cache::{
    AuditCache, CacheKey, CachedResult,
    CacheEntry, CacheStats,
};
pub use executor::{
    DeterministicExecutor, AuditReproducibility,
    CodebaseSignature, SignatureAlgorithm,
};
