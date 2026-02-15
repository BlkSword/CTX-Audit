// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! PoC (Proof of Concept) 生成模块
//!
//! 为安全漏洞生成验证代码

mod generator;

pub use generator::{
    PoCGenerator, PoCResult, PoCTemplate, PoCTemplateLibrary, PoCContext, PoCGeneratorConfig,
};
