// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

// CLI 工具需要控制台输出，不要使用 windows 子系统
// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config;
mod database;
mod output;
mod report;
mod repl;
mod slash;
mod terminal;
mod tui;

use clap::{CommandFactory, Parser, Subcommand};
use miette::{Result, IntoDiagnostic};
use miette::Context;

/// CTX-Audit - AI 驱动的代码安全审计工具
///
/// 一个强大的代码安全审计 CLI 工具，支持 AI 辅助分析和规则扫描。
#[derive(Parser, Debug)]
#[command(name = "ctx-audit")]
#[command(author = "CTX-Audit Contributors")]
#[command(version = VERSION)]
#[command(about = "AI-powered code security audit tool", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// 启用详细输出
    #[arg(short, long)]
    verbose: bool,

    /// 启用调试输出
    #[arg(short, long)]
    debug: bool,

    /// 设置日志级别 (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// 输出格式 (text, json, markdown, sarif)
    #[arg(short, long, default_value = "text")]
    output: String,

    /// 配置文件路径
    #[arg(short, long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

/// CLI 子命令
#[derive(Subcommand, Debug)]
enum Commands {
    /// 启动 AI 审计（交互式）
    ///
    /// 使用 AI Agent 进行深度代码安全分析
    Audit {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 审计类型 (full, quick, incremental)
        #[arg(short, long, default_value = "full")]
        audit_type: String,

        /// 最大迭代次数（不指定则无限制）
        #[arg(short, long)]
        max_iterations: Option<u32>,

        /// 跳过验证阶段
        #[arg(long)]
        skip_verification: bool,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<String>,

        /// 显示详细的 LLM 过程（思考、工具调用、观察结果）
        #[arg(short, long)]
        verbose: bool,
    },

    /// 快速规则扫描（批处理）
    ///
    /// 使用预定义规则快速扫描代码
    Scan {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 规则目录路径
        #[arg(short, long)]
        rules: Option<String>,

        /// 严重程度过滤 (critical, high, medium, low, info)
        #[arg(short, long)]
        severity: Option<String>,

        /// 文件模式过滤（如 *.rs）
        #[arg(short, long)]
        pattern: Option<String>,

        /// 输出文件路径
        #[arg(short, long)]
        output: Option<String>,

        /// 并行扫描线程数
        #[arg(short, long, default_value = "4")]
        threads: usize,
    },

    /// REPL 对话模式
    ///
    /// 进入交互式对话界面
    Chat {
        /// 项目路径（可选）
        #[arg(value_name = "PATH")]
        path: Option<String>,
    },

    /// 深度分析单个文件
    ///
    /// 对单个文件进行详细的 AI 分析
    Analyze {
        /// 文件路径
        #[arg(value_name = "FILE")]
        file: String,

        /// 起始行号
        #[arg(short, long, default_value = "1")]
        start_line: usize,

        /// 结束行号
        #[arg(short, long)]
        end_line: Option<usize>,

        /// 显示 AST 信息
        #[arg(long)]
        ast: bool,

        /// 显示符号信息
        #[arg(long)]
        symbols: bool,
    },

    /// 管理漏洞发现
    ///
    /// 查看、更新或删除漏洞记录
    Findings {
        #[command(subcommand)]
        action: FindingsAction,
    },

    /// 配置管理
    ///
    /// 管理应用配置
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// 生成 Shell 自动补全脚本
    ///
    /// 生成 bash/zsh/fish/powershell 补全脚本
    Completion {
        /// Shell 类型
        #[arg(value_name = "SHELL")]
        shell: String,
    },

    /// 启动 TUI（终端用户界面）
    ///
    /// 进入交互式 TUI 界面
    Ui {
        /// 项目路径（可选）
        #[arg(value_name = "PATH")]
        path: Option<String>,

        /// 自动开始审计
        #[arg(short, long)]
        audit: bool,
    },

    /// 守护模式：监听文件变更并增量扫描
    ///
    /// 持续监听项目文件变更，自动增量扫描并更新 SARIF 报告
    Watch {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 严重程度过滤 (critical, high, medium, low)
        #[arg(short, long)]
        severity: Option<String>,

        /// 输出格式
        #[arg(short, long, default_value = "sarif")]
        output: String,

        /// SARIF 输出路径
        #[arg(long, default_value = ".ctx-audit.sarif")]
        output_path: String,

        /// 忽略的目录（逗号分隔）
        #[arg(long, default_value = "node_modules,.git,target,build,dist,__pycache__,vendor")]
        ignore: String,
    },
}

/// 漏洞管理子命令
#[derive(Subcommand, Debug)]
enum FindingsAction {
    /// 列出所有漏洞
    List {
        /// 严重程度过滤
        #[arg(short, long)]
        severity: Option<String>,

        /// 状态过滤 (open, fixed, ignored)
        #[arg(short, long)]
        status: Option<String>,

        /// 文件路径过滤
        #[arg(short, long)]
        file: Option<String>,

        /// JSON 格式输出
        #[arg(long)]
        json: bool,
    },

    /// 查看单个漏洞详情
    View {
        /// 漏洞 ID
        #[arg(value_name = "ID")]
        id: String,
    },

    /// 更新漏洞状态
    Update {
        /// 漏洞 ID
        #[arg(value_name = "ID")]
        id: String,

        /// 新状态 (open, fixed, ignored)
        #[arg(short, long)]
        status: String,

        /// 添加备注
        #[arg(short, long)]
        note: Option<String>,
    },

    /// 删除漏洞
    Delete {
        /// 漏洞 ID
        #[arg(value_name = "ID")]
        id: String,

        /// 确认删除（跳过确认提示）
        #[arg(long)]
        confirm: bool,
    },

    /// 导出漏洞报告
    Export {
        /// 输出文件路径
        #[arg(value_name = "FILE")]
        output: String,

        /// 导出格式 (json, markdown, sarif)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
}

/// 配置管理子命令
#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// 显示当前配置
    Show {
        /// 配置键（可选，显示所有配置）
        #[arg(value_name = "KEY")]
        key: Option<String>,

        /// 显示敏感信息（如 API 密钥）
        #[arg(long)]
        reveal: bool,
    },

    /// 设置配置值
    Set {
        /// 配置键
        #[arg(value_name = "KEY")]
        key: String,

        /// 配置值
        #[arg(value_name = "VALUE")]
        value: String,
    },

    /// 删除配置值
    Remove {
        /// 配置键
        #[arg(value_name = "KEY")]
        key: String,
    },

    /// 列出所有配置键
    List {
        /// 显示详细信息
        #[arg(long)]
        verbose: bool,
    },

    /// 验证配置
    Validate {
        /// 测试 LLM 连接
        #[arg(long)]
        test_llm: bool,
    },

    /// 重置为默认配置
    Reset {
        /// 确认重置
        #[arg(long)]
        confirm: bool,
    },
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 检查命令类型以决定日志策略
    let is_tui_command = matches!(cli.command, Commands::Ui { .. });
    let is_chat_command = matches!(cli.command, Commands::Chat { .. });

    // 初始化日志
    // - TUI 模式: 完全禁用日志（避免干扰界面渲染）
    // - Chat 模式: 只显示 warn 和 error 级别（避免干扰交互）
    // - 其他模式: 正常初始化日志
    if !is_tui_command {
        if is_chat_command {
            init_logging_chat_only();
        } else {
            init_logging(&cli);
        }
    }

    // 执行命令
    match cli.command {
        Commands::Audit {
            path,
            audit_type,
            max_iterations,
            skip_verification,
            output,
            verbose,
        } => {
            commands::audit::execute(
                path,
                audit_type,
                max_iterations,
                skip_verification,
                output,
                cli.output.as_str(),
                verbose,
            )
            .await
        }

        Commands::Scan {
            path,
            rules,
            severity,
            pattern,
            output,
            threads,
        } => {
            commands::scan::execute(
                path,
                rules,
                severity,
                pattern,
                output,
                threads,
                cli.output.as_str(),
            )
            .await
        }

        Commands::Chat { path } => commands::chat::execute(path).await,

        Commands::Analyze {
            file,
            start_line,
            end_line,
            ast,
            symbols,
        } => {
            commands::analyze::execute(file, start_line, end_line, ast, symbols, cli.output.as_str())
                .await
        }

        Commands::Findings { action } => match action {
            FindingsAction::List {
                severity,
                status,
                file,
                json,
            } => commands::findings::list(severity, status, file, json, cli.output.as_str()).await,

            FindingsAction::View { id } => commands::findings::view(id, cli.output.as_str()).await,

            FindingsAction::Update { id, status, note } => {
                commands::findings::update(id, status, note).await
            }

            FindingsAction::Delete { id, confirm } => commands::findings::delete(id, confirm).await,

            FindingsAction::Export { output, format } => {
                commands::findings::export(output, format).await
            }
        },

        Commands::Config { action } => match action {
            ConfigAction::Show { key, reveal } => commands::config::show(key, reveal).await,
            ConfigAction::Set { key, value } => commands::config::set(key, value).await,
            ConfigAction::Remove { key } => commands::config::remove(key).await,
            ConfigAction::List { verbose } => commands::config::list(verbose).await,
            ConfigAction::Validate { test_llm } => commands::config::validate(test_llm).await,
            ConfigAction::Reset { confirm } => commands::config::reset(confirm).await,
        },

        Commands::Completion { shell } => {
            generate_completion(&shell);
            Ok(())
        }

        Commands::Ui { path, audit: _ } => {
            if let Some(p) = path {
                tui::run_tui_audit(p).await.map_err(|e| miette::miette!("{}", e))
            } else {
                tui::run_tui().await.map_err(|e| miette::miette!("{}", e))
            }
        }

        Commands::Watch {
            path,
            severity,
            output: _,
            output_path,
            ignore,
        } => commands::watch::execute(path, severity, "sarif", output_path, ignore).await,
    }
}

/// 初始化日志系统
fn init_logging(cli: &Cli) {
    let level = if cli.debug {
        "debug"
    } else if cli.verbose {
        "info"
    } else {
        &cli.log_level
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}

/// 初始化日志系统（仅用于 Chat/REPL 模式）
/// 只显示警告和错误，避免干扰用户交互
fn init_logging_chat_only() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}

/// 生成 Shell 自动补全脚本
fn generate_completion(shell: &str) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();

    match shell {
        "bash" => {
            println!(
                "# Bash completion for {}",
                name
            );
            println!("# Add to ~/.bashrc or ~/.bash_completion");
            println!();
            println!("eval \"$({} --completion bash)\"", name);
            // 实际生成由 clap 自动处理
        }
        "zsh" => {
            println!(
                "# Zsh completion for {}",
                name
            );
            println!("# Add to ~/.zshrc");
            println!();
            println!("eval \"$({} --completion zsh)\"", name);
        }
        "fish" => {
            println!(
                "# Fish completion for {}",
                name
            );
            println!("# Add to ~/.config/fish/completions/{}.fish", name);
            println!();
            println!("{} --completion fish | source", name);
        }
        "powershell" | "pwsh" => {
            println!(
                "# PowerShell completion for {}",
                name
            );
            println!("# Add to PowerShell profile");
            println!();
            println!("Invoke-Expression -Command (& '{}' --completion powershell) | Out-String", name);
        }
        _ => {
            eprintln!("Unknown shell: {}", shell);
            eprintln!("Supported shells: bash, zsh, fish, powershell");
            std::process::exit(1);
        }
    }
}
