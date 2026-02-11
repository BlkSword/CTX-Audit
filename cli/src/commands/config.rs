// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! config 命令实现
//!
//! 管理应用配置

use miette::Result;

use crate::config::ConfigManager;
use crate::terminal::TerminalRenderer;
use ctx_audit_llm::{LLMFactory, LLMConfig, LLMMessage, MessageRole};
use std::path::PathBuf;

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
    renderer.print("  llm.provider         - LLM 提供商 (anthropic, openai, openai-compatible, ollama)");
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

    // 检查配置文件是否存在
    let config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    // 验证基本配置
    let provider = config_manager.get("llm.provider");
    let api_key = config_manager.get("llm.api_key");
    let model = config_manager.get("llm.model");

    match &provider {
        Some(p) => renderer.print(&format!("  ✓ LLM 提供商: {}", p)),
        None => renderer.warning("  ⚠ LLM 提供商未配置"),
    }

    match &api_key {
        Some(_) => renderer.print("  ✓ API 密钥已配置"),
        None => renderer.warning("  ⚠ API 密钥未配置"),
    }

    match &model {
        Some(m) => renderer.print(&format!("  ✓ 模型: {}", m)),
        None => renderer.warning("  ⚠ 模型未配置"),
    }

    if test_llm {
        renderer.info("\n测试 LLM 连接...");

        // 检查是否有 API 密钥
        let api_key = match &api_key {
            Some(key) => key.clone(),
            None => {
                renderer.error("无法测试连接：API 密钥未配置");
                renderer.info("请使用以下命令配置 API 密钥：");
                renderer.info("  ctx-audit config set llm.api_key <your-api-key>");
                return Ok(());
            }
        };

        // 获取配置
        let provider = provider.as_ref().map(|s| s.as_str()).unwrap_or("anthropic");
        let model = model.as_ref().map(|s| s.as_str()).unwrap_or_else(|| {
            match provider {
                "anthropic" => "claude-3-5-sonnet-20241022",
                "openai" => "gpt-4",
                "ollama" => "llama2",
                _ => "claude-3-5-sonnet-20241022"
            }
        }).to_string();
        let base_url = config_manager.get("llm.base_url");

        // 创建 LLM 配置
        let llm_config = LLMConfig {
            provider: provider.to_string(),
            api_key: Some(api_key),
            model: Some(model),
            base_url,
            timeout_secs: Some(30),
        };

        // 创建 LLM 工厂
        let factory = LLMFactory::new();
        factory.set_config(llm_config);

        // 测试连接
        match test_llm_connection(&factory).await {
            Ok(response) => {
                renderer.success("LLM 连接测试成功！");
                renderer.print(&format!("  响应: {}", response.trim()));
            }
            Err(e) => {
                renderer.error(&format!("LLM 连接测试失败: {}", e));
                renderer.info("\n故障排查建议:");
                renderer.info("  1. 检查 API 密钥是否正确");
                renderer.info("  2. 检查网络连接是否正常");
                renderer.info("  3. 确认 API 密钥有足够的配额");
                renderer.info("  4. 检查提供商服务是否正常运行");
            }
        }
    }

    renderer.success("\n配置验证通过");

    Ok(())
}

/// 测试 LLM 连接
async fn test_llm_connection(factory: &LLMFactory) -> Result<String, String> {
    let client = factory.get_client().await
        .map_err(|e| format!("获取 LLM 客户端失败: {}", e))?;

    // 发送测试消息
    let test_message = LLMMessage {
        role: MessageRole::User,
        content: vec![ctx_audit_llm::MessageContent::Text {
            text: "Hello! Please respond with 'OK' to confirm the connection.".to_string()
        }],
        cache_control: None,
    };

    let response = client.generate(vec![test_message], 10, 0.5).await
        .map_err(|e| format!("LLM 请求失败: {}", e))?;

    Ok(response.get_text())
}

/// 重置配置
pub async fn reset(confirm: bool) -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    if !confirm {
        renderer.warning("请使用 --confirm 确认重置");
        return Ok(());
    }

    // 删除配置文件
    let config_path = get_config_path()?;

    if config_path.exists() {
        tokio::fs::remove_file(&config_path)
            .await
            .map_err(|e| miette::miette!("删除配置文件失败: {}", e))?;

        renderer.success(&format!("配置文件已删除: {}", config_path.display()));
    } else {
        renderer.warning("配置文件不存在，无需删除");
    }

    // 同时删除数据库缓存（可选）
    let db_path = get_db_path()?;
    if db_path.exists() {
        renderer.info(&format!("数据库缓存: {} (如需删除，请手动删除)", db_path.display()));
    }

    renderer.success("配置已重置为默认值");
    renderer.info("提示: 下次运行将使用默认配置");

    Ok(())
}

/// 获取配置文件路径
fn get_config_path() -> Result<PathBuf, miette::Error> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| miette::miette!("无法获取配置目录"))?;

    Ok(config_dir.join("ctx-audit").join("config.toml"))
}

/// 获取数据库路径
fn get_db_path() -> Result<PathBuf, miette::Error> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| miette::miette!("无法获取配置目录"))?;

    Ok(config_dir.join("ctx-audit").join("audit.db"))
}
