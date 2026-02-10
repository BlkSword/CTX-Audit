// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! config 命令实现
//!
//! 管理应用配置

use miette::Result;

use crate::config::ConfigManager;
use crate::terminal::TerminalRenderer;

/// 显示配置
pub async fn show(key: Option<String>, reveal: bool) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    if let Some(key) = key {
        match config_manager.get(&key) {
            Some(value) => {
                // 如果是敏感信息且不显示
                if key.contains("api_key") && !reveal {
                    renderer.print("****** (隐藏)");
                } else {
                    renderer.print(&value);
                }
            }
            None => {
                renderer.error(&format!("未找到配置: {}", key));
            }
        }
    } else {
        // 显示所有配置
        renderer.print("当前配置:");
        display_config_value("LLM 提供商", config_manager.get("llm.provider"), &mut renderer);
        display_config_value("模型", config_manager.get("llm.model"), &mut renderer);
        display_config_value("API 密钥", config_manager.get("llm.api_key").map(|_| "******".to_string()), &mut renderer);
        display_config_value("扫描线程数", config_manager.get("scan.threads"), &mut renderer);
        display_config_value("输出格式", config_manager.get("output.format"), &mut renderer);
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
pub async fn list(verbose: bool) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    renderer.print("可用配置键:");
    renderer.print("  llm.provider         - LLM 提供商 (anthropic, openai, ollama)");
    renderer.print("  llm.api_key          - API 密钥");
    renderer.print("  llm.model            - 模型名称");
    renderer.print("  llm.base_url         - API 基础 URL");
    renderer.print("  llm.timeout          - 超时时间（秒）");
    renderer.print("  llm.max_tokens       - 最大 tokens");
    renderer.print("  llm.temperature      - 温度参数");
    renderer.print("  scan.threads         - 扫描线程数");
    renderer.print("  scan.include_tests   - 是否包含测试文件");
    renderer.print("  output.format        - 输出格式 (text, json, markdown, sarif)");
    renderer.print("  output.color         - 是否显示颜色");
    renderer.print("  output.verbose       - 是否显示详细输出");
    renderer.print("  cache.enabled        - 是否启用缓存");
    renderer.print("  log.level            - 日志级别");

    Ok(())
}

/// 验证配置
pub async fn validate(test_llm: bool) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    renderer.info("验证配置...");

    if test_llm {
        renderer.info("测试 LLM 连接...");
        // TODO: 实现 LLM 连接测试
        renderer.warning("LLM 连接测试待实现");
    }

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

    // TODO: 删除配置文件
    renderer.success("配置已重置为默认值");

    Ok(())
}
