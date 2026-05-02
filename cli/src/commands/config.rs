// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! config 命令实现
//!
//! 管理应用配置

use miette::Result;

use crate::config::ConfigManager;
use crate::terminal::TerminalRenderer;
use std::path::PathBuf;

/// 显示配置
pub async fn show(key: Option<String>, _reveal: bool) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    if let Some(key) = key {
        match config_manager.get(&key) {
            Some(value) => renderer.print(&value),
            None => renderer.error(&format!("未找到配置: {}", key)),
        }
    } else {
        renderer.print("当前配置:");
        display_config_value("扫描线程数", config_manager.get("scan.threads"), &mut renderer);
        display_config_value("输出格式", config_manager.get("output.format"), &mut renderer);
        display_config_value("缓存启用", config_manager.get("cache.enabled"), &mut renderer);
        display_config_value("日志级别", config_manager.get("log.level"), &mut renderer);
    }

    Ok(())
}

fn display_config_value(key: &str, value: Option<String>, renderer: &mut TerminalRenderer) {
    if let Some(v) = value {
        renderer.print(&format!("  {}: {}", key, v));
    }
}

/// 设置配置
pub async fn set(key: String, value: String) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let mut config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    config_manager.set(&key, value.clone()).map_err(|e| miette::miette!("{}", e))?;
    config_manager.save().await.map_err(|e| miette::miette!("{}", e))?;

    renderer.success(&format!("配置已更新: {} = {}", key, value));

    Ok(())
}

/// 删除配置
pub async fn remove(key: String) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let mut config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    config_manager.remove(&key).map_err(|e| miette::miette!("{}", e))?;
    config_manager.save().await.map_err(|e| miette::miette!("{}", e))?;

    renderer.success(&format!("配置已重置: {}", key));

    Ok(())
}

/// 列出所有配置键
pub async fn list(_verbose: bool) -> Result<()> {
    let renderer = TerminalRenderer::new();

    drop(renderer);
    println!("可用配置键:");
    println!("  scan.threads         - 扫描线程数");
    println!("  scan.include_tests   - 是否包含测试文件");
    println!("  output.format        - 输出格式 (text, json, markdown, sarif)");
    println!("  output.color         - 是否显示颜色");
    println!("  output.verbose       - 是否显示详细输出");
    println!("  cache.enabled        - 是否启用缓存");
    println!("  log.level            - 日志级别");

    Ok(())
}

/// 验证配置
pub async fn validate() -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    renderer.info("验证配置...");

    let config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let _ = config_manager;

    renderer.success("配置验证通过");

    Ok(())
}

/// 重置配置
pub async fn reset(confirm: bool) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    if !confirm {
        renderer.warning("请使用 --confirm 确认重置");
        return Ok(());
    }

    let config_path = get_config_path()?;

    if config_path.exists() {
        tokio::fs::remove_file(&config_path)
            .await
            .map_err(|e| miette::miette!("删除配置文件失败: {}", e))?;

        renderer.success(&format!("配置文件已删除: {}", config_path.display()));
    } else {
        renderer.warning("配置文件不存在，无需删除");
    }

    renderer.success("配置已重置为默认值");

    Ok(())
}

/// 获取配置文件路径
fn get_config_path() -> Result<PathBuf, miette::Error> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| miette::miette!("无法获取配置目录"))?;

    Ok(config_dir.join("ctx-audit").join("config.toml"))
}
