// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

mod commands;
mod config;
mod database;
mod output;
mod report;
mod terminal;

use clap::{CommandFactory, Parser, Subcommand};
use miette::{Result, IntoDiagnostic};

/// CTX-Audit - 安全分析守护进程工具包
///
/// 基于确定性分析引擎的代码安全分析工具
#[derive(Parser, Debug)]
#[command(name = "ctx-audit")]
#[command(author = "CTX-Audit Contributors")]
#[command(version = VERSION)]
#[command(about = "Security analysis daemon toolkit", long_about = None)]
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

        /// 排除的目录（逗号分隔，如 test,node_modules,dist）
        #[arg(short, long, default_value = "")]
        exclude: String,

        /// 启用深度扫描（AST 污点分析）
        #[arg(long)]
        deep: bool,

        /// 通过守护进程执行
        #[arg(long)]
        daemon: bool,

        /// 启用 SCA 依赖漏洞扫描
        #[arg(long)]
        sca: bool,
    },

    /// 深度分析单个文件
    ///
    /// 对单个文件进行详细的 AST 分析和污点追踪
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

        /// 通过守护进程执行
        #[arg(long)]
        daemon: bool,
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

    /// 守护进程管理
    ///
    /// 启动、查询或停止安全分析守护进程
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
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

        /// 通过守护进程执行
        #[arg(long)]
        daemon: bool,
    },

    /// MCP Server 模式（AI agent 集成）
    ///
    /// 启动 MCP 协议服务器，通过 stdio 暴露安全分析能力给 AI agent（如 Claude Code）
    Mcp,

    /// 规则管理
    ///
    /// 列出、验证自定义检测规则
    Rules {
        #[command(subcommand)]
        action: RulesAction,
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

        /// 显示敏感信息
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
    Validate,

    /// 重置为默认配置
    Reset {
        /// 确认重置
        #[arg(long)]
        confirm: bool,
    },
}

/// 守护进程管理子命令
#[derive(Subcommand, Debug)]
enum DaemonAction {
    /// 启动守护进程
    Start {
        /// 预加载的项目路径
        #[arg(short, long)]
        project: Option<String>,
    },

    /// 查询守护进程状态
    Status,

    /// 停止守护进程
    Stop,
}

/// 规则管理子命令
#[derive(Subcommand, Debug)]
enum RulesAction {
    /// 列出所有规则
    List {
        /// 自定义规则目录
        #[arg(short, long)]
        rules: Option<String>,
    },

    /// 验证规则文件
    Validate {
        /// 规则目录
        #[arg(short, long)]
        rules: Option<String>,
    },
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // 初始化日志
    init_logging(&cli);

    // 执行命令
    match cli.command {
        Commands::Scan {
            path,
            rules,
            severity,
            pattern,
            output,
            threads,
            exclude,
            deep,
            daemon,
            sca,
        } => {
            commands::scan::execute(
                path,
                rules,
                severity,
                pattern,
                output,
                threads,
                cli.output.as_str(),
                deep,
                daemon,
                exclude,
                sca,
            )
            .await
        }

        Commands::Analyze {
            file,
            start_line,
            end_line,
            ast,
            symbols,
            daemon,
        } => {
            commands::analyze::execute(file, start_line, end_line, ast, symbols, cli.output.as_str(), daemon)
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
            ConfigAction::Validate => commands::config::validate().await,
            ConfigAction::Reset { confirm } => commands::config::reset(confirm).await,
        },

        Commands::Completion { shell } => {
            generate_completion(&shell);
            Ok(())
        }

        Commands::Daemon { action } => match action {
            DaemonAction::Start { project } => commands::daemon::start(project).await,
            DaemonAction::Status => commands::daemon::status().await,
            DaemonAction::Stop => commands::daemon::stop().await,
        },

        Commands::Watch {
            path,
            severity,
            output: _,
            output_path,
            ignore,
            daemon,
        } => commands::watch::execute(path, severity, "sarif", output_path, ignore, daemon).await,

        Commands::Mcp => {
            commands::mcp::run_mcp_server().await
                .map_err(|e| miette::miette!("MCP server error: {}", e))
        }

        Commands::Rules { action } => match action {
            RulesAction::List { rules } => commands::rules::list(rules).await,
            RulesAction::Validate { rules } => commands::rules::validate(rules).await,
        },
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

    // MCP 模式：日志只写 stderr，不能写 stdout（stdout 用于 JSON-RPC）
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

/// 生成 Shell 自动补全脚本
fn generate_completion(shell: &str) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();

    match shell {
        "bash" => {
            println!("# Bash completion for {}", name);
            println!("# Add to ~/.bashrc or ~/.bash_completion");
            println!();
            println!("eval \"$({} --completion bash)\"", name);
        }
        "zsh" => {
            println!("# Zsh completion for {}", name);
            println!("# Add to ~/.zshrc");
            println!();
            println!("eval \"$({} --completion zsh)\"", name);
        }
        "fish" => {
            println!("# Fish completion for {}", name);
            println!("# Add to ~/.config/fish/completions/{}.fish", name);
            println!();
            println!("{} --completion fish | source", name);
        }
        "powershell" | "pwsh" => {
            println!("# PowerShell completion for {}", name);
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
