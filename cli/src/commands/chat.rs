// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! chat 命令实现
//!
//! 进入 REPL 对话模式

use miette::Result;
use std::sync::Arc;

use crate::config::ConfigManager;
use crate::repl::ReplSession;

/// 执行 chat 命令
pub async fn execute(path: Option<String>) -> Result<()> {
    // 初始化配置
    let config = Arc::new(ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?);

    // 创建 REPL 会话
    let mut session = ReplSession::new(config).map_err(|e| miette::miette!("{}", e))?;

    // 设置项目路径（如果提供）
    if let Some(p) = path {
        // 验证路径
        let project_path = std::path::Path::new(&p);
        if !project_path.exists() {
            return Err(miette::miette!("项目路径不存在: {}", p));
        }
    }

    // 启动 REPL 循环
    session.run().await.map_err(|e| miette::miette!("{}", e))?;

    Ok(())
}
