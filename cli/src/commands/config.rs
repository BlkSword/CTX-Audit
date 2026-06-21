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
        let cfg = config_manager.config();
        renderer.print("当前配置:");
        renderer.print(&format!("  扫描线程数:       {}", cfg.scan.threads));
        renderer.print(&format!("  包含测试文件:     {}", cfg.scan.include_tests));
        renderer.print(&format!(
            "  最大文件大小:     {} MB",
            cfg.scan.max_file_size_mb
        ));
        renderer.print(&format!(
            "  内存预算:         {} MB",
            cfg.scan.memory_budget_mb
        ));
        renderer.print(&format!("  批次大小:         {}", cfg.scan.batch_size));
        renderer.print(&format!("  去重行容差:       {}", cfg.scan.line_tolerance));
        renderer.print(&format!("  默认深度扫描:     {}", cfg.scan.deep));
        renderer.print(&format!("  输出格式:         {}", cfg.output.format));
        renderer.print(&format!(
            "  缓存启用:         {}",
            cfg.advanced.enable_cache
        ));
        renderer.print(&format!("  日志级别:         {}", cfg.advanced.log_level));
        renderer.print(&format!("  SCA 启用:         {}", cfg.sca.enabled));
        renderer.print(&format!(
            "  SCA 最低严重程度: {}",
            cfg.sca.severity_threshold
        ));
        renderer.print(&format!("  守护进程地址:     {}", cfg.daemon.listen_addr));
    }

    Ok(())
}

/// 设置配置
pub async fn set(key: String, value: String) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let mut config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    config_manager
        .set(&key, value.clone())
        .map_err(|e| miette::miette!("{}", e))?;
    config_manager
        .save()
        .await
        .map_err(|e| miette::miette!("{}", e))?;

    renderer.success(&format!("配置已更新: {} = {}", key, value));

    Ok(())
}

/// 删除配置
pub async fn remove(key: String) -> Result<()> {
    let mut renderer = TerminalRenderer::new();
    let mut config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;

    config_manager
        .remove(&key)
        .map_err(|e| miette::miette!("{}", e))?;
    config_manager
        .save()
        .await
        .map_err(|e| miette::miette!("{}", e))?;

    renderer.success(&format!("配置已重置: {}", key));

    Ok(())
}

/// 列出所有配置键
pub async fn list(_verbose: bool) -> Result<()> {
    let renderer = TerminalRenderer::new();

    drop(renderer);
    println!("扫描配置:");
    println!("  scan.threads                  - 并行线程数 (默认 4)");
    println!("  scan.include_tests            - 是否包含测试文件 (默认 false)");
    println!(
        "  scan.exclude_patterns         - 排除模式 (JSON 数组, 如 [\"node_modules\",\".git\"])"
    );
    println!("  scan.max_file_size_mb         - 单文件最大扫描大小 MB (默认 10)");
    println!("  scan.memory_budget_mb         - 扫描内存预算 MB (默认 500)");
    println!("  scan.batch_size               - 并行批次大小 (默认 100)");
    println!("  scan.line_tolerance           - 去重行容差 (默认 3)");
    println!("  scan.severity                 - 默认严重程度过滤 (critical/high/medium/low/info)");
    println!("  scan.deep                     - 默认启用深度扫描 (默认 false)");
    println!();
    println!("输出配置:");
    println!("  output.format                 - 输出格式 (text, json, markdown, sarif)");
    println!("  output.color                  - 是否显示颜色 (默认 true)");
    println!("  output.verbose                - 是否显示详细输出 (默认 false)");
    println!();
    println!("高级配置:");
    println!("  cache.enabled                 - 是否启用缓存 (默认 true)");
    println!("  log.level                     - 日志级别 (trace/debug/info/warn/error, 默认 info)");
    println!();
    println!("SCA 配置:");
    println!("  sca.enabled                   - 是否启用 SCA 依赖扫描 (默认 false)");
    println!("  sca.dev_dependencies          - 是否包含 devDependencies (默认 true)");
    println!("  sca.severity_threshold        - 最低报告严重程度 (默认 low)");
    println!("  sca.cache_ttl_hours           - SCA 缓存 TTL 小时数 (默认 24)");
    println!("  sca.osv_timeout_sec           - OSV API 超时秒数 (默认 30)");
    println!("  sca.fail_offline              - 离线时是否报错 (默认 false)");
    println!("  sca.ignore_vulns              - 忽略的漏洞 ID (JSON 数组)");
    println!("  sca.ignore_packages           - 忽略的包 (JSON 数组)");
    println!("  sca.ignore_ecosystems         - 跳过的生态 (JSON 数组, 如 [\"Go\"])");
    println!("  sca.severity_mapping          - CVSS 阈值映射 (JSON)");
    println!();
    println!("守护进程配置:");
    println!("  daemon.listen_addr            - 监听地址 (默认 127.0.0.1:19527)");
    println!("  daemon.rules_reload_interval_secs - 规则热重载间隔秒数 (默认 30)");
    println!("  daemon.ast_idle_secs          - AST Engine 空闲超时秒数 (默认 3600)");
    println!("  daemon.ast_max_memory_mb      - AST Engine 最大总内存 MB (默认 512)");
    println!("  daemon.scan_cache_idle_secs   - Scan Cache 空闲超时秒数 (默认 7200)");
    println!("  daemon.heartbeat_interval_secs - 心跳间隔秒数 (默认 5)");
    println!("  daemon.reconnect_max_retries  - 最大重连重试次数 (默认 3)");
    println!("  daemon.reconnect_base_delay_ms - 重连基础延迟毫秒 (默认 200)");

    Ok(())
}

/// 验证配置
pub async fn validate() -> Result<()> {
    let mut renderer = TerminalRenderer::new();

    renderer.info("验证配置...");

    let config_manager = ConfigManager::new(None).map_err(|e| miette::miette!("{}", e))?;
    let cfg = config_manager.config();

    let mut errors = Vec::new();

    if cfg.scan.threads == 0 {
        errors.push("scan.threads 不能为 0".to_string());
    }
    if cfg.scan.max_file_size_mb == 0 {
        errors.push("scan.max_file_size_mb 不能为 0".to_string());
    }
    if cfg.scan.memory_budget_mb == 0 {
        errors.push("scan.memory_budget_mb 不能为 0".to_string());
    }
    if let Some(ref sev) = cfg.scan.severity {
        let valid = ["critical", "high", "medium", "low", "info"];
        if !valid.contains(&sev.as_str()) {
            errors.push(format!("scan.severity 无效: {}", sev));
        }
    }

    if errors.is_empty() {
        renderer.success("配置验证通过");
    } else {
        for e in &errors {
            renderer.error(e);
        }
        return Err(miette::miette!("配置验证失败: {} 个错误", errors.len()));
    }

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
    let config_dir = dirs::config_dir().ok_or_else(|| miette::miette!("无法获取配置目录"))?;

    Ok(config_dir.join("ctx-audit").join("config.toml"))
}
