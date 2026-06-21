// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 索引系统
//!
//! 提供代码块索引、向量存储和语义搜索能力

pub mod code_chunks;
pub mod vector_store;

pub use code_chunks::{ChunkConfig, ChunkType, CodeChunk, CodeChunker};
pub use vector_store::{SearchResult, VectorStore, VectorStoreError};
