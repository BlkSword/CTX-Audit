// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

mod commands;
mod config;
mod database;
mod output;
mod report;
mod terminal;

use clap::{CommandFactory, Parser, Subcommand};
use miette::{IntoDiagnostic, Result};

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

const XFILE_ENV_HELP: &str = "\
跨文件（--deep / --cross-file）上限可用环境变量按 run 覆盖（默认值即历史行为）：
  CTX_AUDIT_XFILE_MAX_FLOWS                  跨文件流总数上限（默认 5000）
  CTX_AUDIT_XFILE_MAX_FLOWS_PER_SOURCE       单 source 保留流数（默认 3）
  CTX_AUDIT_XFILE_MAX_STRUCTURAL_PER_SOURCE  单 source 结构可达链上限（默认 1；0=只留数据流证据链，并跳过结构链搜索）
  CTX_AUDIT_XFILE_MIN_CONFIDENCE             保留流的最低置信度（默认 0.35）
  CTX_AUDIT_XFILE_MAX_SINKS_PER_SOURCE       每 source 的候选 sink 池（默认 8，按跳数取最近）
  CTX_AUDIT_XFILE_MAX_HOPS                   调用图 BFS 深度上限（默认 5）

MAX_FLOWS 是主要的“覆盖 vs 成本”旋钮：结构链按 source 均摊，≈ 覆盖的 source 数
（实测 18k 文件 JS 仓 --deep：500→753 findings/5.3s，1000→1249/6.1s，2000→1693/7.1s，
默认 5000→1755/7.3s；可达 source 约 1560 个，超过后不再增长）。
注：这些旋钮主要影响候选量与结构链覆盖，对总耗时影响通常在 10-30%（跨文件搜索约占 deep 的 1/4）。";

/// CLI 子命令
#[derive(Subcommand, Debug)]
enum Commands {
    /// 快速规则扫描（批处理）
    ///
    /// 使用预定义规则快速扫描代码
    #[command(after_help = XFILE_ENV_HELP)]
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

        /// 最低严重程度阈值（覆盖配置文件，默认使用配置文件中的 scan.min_severity）
        #[arg(long)]
        min_severity: Option<String>,

        /// 最低置信度阈值（0.0-1.0，过滤低置信度发现。CrossFileTaintAnalyzer 的 name/body based 发现默认被降权）
        #[arg(long)]
        min_confidence: Option<f32>,
        /// 是否保留跨文件“结构可达链”的原始严重度（默认降为 info 并被默认阈值过滤）
        #[arg(long)]
        include_structural: bool,

        /// 跨文件精度优先：关闭“结构可达链”(=0)、最低置信度提至 0.5（切片/取证面）
        #[arg(long, conflicts_with = "recall_first")]
        precision_first: bool,

        /// 跨文件召回优先：结构链每 source 放宽至 3 条、最低置信度回到 0.35（候选面）
        #[arg(long)]
        recall_first: bool,

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

        /// 启用深度扫描（等同于 --taint --cross-file）
        #[arg(long)]
        deep: bool,

        /// 启用 AST 污点分析（单文件 source→sink 追踪）
        #[arg(long)]
        taint: bool,

        /// 启用跨文件污点追踪（隐含 --taint）
        #[arg(long)]
        cross_file: bool,

        /// 通过守护进程执行
        #[arg(long)]
        daemon: bool,

        /// 启用 SCA 依赖漏洞扫描
        #[arg(long)]
        sca: bool,

        /// 保存调用图到指定路径（用于 LLM 查询）
        #[arg(long)]
        graph_output: Option<String>,

        /// 查询模式：构建调用图但不运行规则扫描（与 MCP 工具配合使用）
        #[arg(long)]
        query_mode: bool,

        /// 输出中附加**候选派发**证据（默认关闭）。
        ///
        /// 对"解析不出目标"的间接调用点（函数指针/成员指针/表派发）给出按签名匹配的
        /// 候选目标集合（启发式，非解析结果）。只在 `-o json` 时生效：把 findings 数组
        /// 包进 `{"dispatch_candidates": …, "findings": […]}`；不加该 flag 时输出与历史
        /// 逐字节一致。
        #[arg(long)]
        dispatch_candidates: bool,
    },

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
        #[arg(
            long,
            default_value = "node_modules,.git,target,build,dist,__pycache__,vendor"
        )]
        ignore: String,

        /// 通过守护进程执行
        #[arg(long)]
        daemon: bool,
    },

    /// MCP Server 模式（AI agent 集成）
    ///
    /// 启动 MCP 协议服务器，通过 stdio 暴露安全分析能力给 AI agent（如 Claude Code）
    Mcp {
        /// 注册遗留细粒度工具面（默认只暴露高阶能力与基础工具）
        #[arg(long)]
        legacy_tools: bool,
    },

    /// 三角色信号链候选（只读证据，不改检测）
    ///
    /// 扫描"循环界 / 长度实参 → 守卫检索（按构造裁剪）→ 写 sink 累积性"三步，
    /// 输出三角色（trigger / path / effect）齐备的候选及其证据。
    /// 只产候选与证据：不产出 findings，不影响 scan 的任何输出。
    #[command(after_help = "输出 JSON 时候选与未升级项都会落盘（未升级项是判据本身的证据）。")]
    SignalChain {
        /// 项目路径或单个源文件
        #[arg(value_name = "PATH")]
        path: String,

        /// 输出格式 (text, json)
        #[arg(short = 'o', long = "output", default_value = "text")]
        output: String,

        /// 构造族: all | loop | lenarg | sprintf-unbounded | macro-class | signed-init | charcopy-loop
        #[arg(long, default_value = "all")]
        constructs: String,

        /// 只列出升级候选（影响 text 输出）
        #[arg(long)]
        candidates_only: bool,

        /// 最多扫描的源文件数（0 = 不限）
        #[arg(long, default_value_t = 0)]
        max_files: usize,

        /// 从 git diff 取 locus（如 `HEAD~1..HEAD`）：删除行取漏洞侧原文，纯新增 hunk 取新行号
        #[arg(long, value_name = "REVSPEC")]
        from_diff: Option<String>,

        /// 从公告/清单文件取 locus（每行 `文件:行号`）
        #[arg(long, value_name = "FILE")]
        from_advisory: Option<String>,
    },

    /// 鉴权基线卡（链/规则/过滤器/注解消费者/被关闭的钩子）
    ///
    /// 把"这个项目的'受保护'是什么意思"压成一屏可复核的事实，
    /// 替代审计员重新读一遍安全配置的固定成本。
    Baseline {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 输出格式 (text, json)
        #[arg(short = 'o', long = "output", default_value = "text")]
        output: String,
    },

    /// 法医台：候选链 / 链档 / 步骤证伪
    #[command(after_help = "链 ID 来自 --list；--format md 输出人读链档。")]
    Chain {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 列出候选链（入口→危险汇）
        #[arg(long)]
        list: bool,

        /// 链 ID（输出该链档）
        #[arg(long)]
        id: Option<String>,

        /// 只保留某类危险汇（exec|eval|deserialize|reflect|file_write|sql|template|ssrf|module_access）
        #[arg(long)]
        sink: Option<String>,

        /// 只保留某类入口（如 decodeReply / 文件名子串）
        #[arg(long)]
        entry: Option<String>,

        /// 从"漏洞版 → 修复版"的 diff 自动派生词表（需配合 --before/--after）
        #[arg(long)]
        learn: bool,

        /// 漏洞版目录（--learn 用）
        #[arg(long)]
        before: Option<String>,

        /// 修复版目录（--learn 用）
        #[arg(long)]
        after: Option<String>,

        /// 外部词表 JSON（默认读 <PATH>/.ctx-audit/chain-vocab.json 或 CTX_AUDIT_CHAIN_VOCAB）
        #[arg(long)]
        vocab: Option<String>,

        /// 词表落盘路径（--learn 用；默认打印到 stdout）
        #[arg(long)]
        out: Option<String>,

        /// 只用派生词表，不使用内置汇模式（验证泛化性）
        #[arg(long)]
        no_builtin_vocab: bool,

        /// 条数上限（0=全部）
        #[arg(long, default_value_t = 20)]
        limit: usize,

        /// 输出格式 (json, md)
        #[arg(short = 'o', long = "output", default_value = "json")]
        output: String,
    },

    /// 审计驾驶舱：覆盖率摘要 + 排序待审清单 + 证据包（人用加速器）
    Audit {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 输出目录
        #[arg(short = 'O', long = "out", default_value = "report")]
        out: String,

        /// 待审/证据条数上限（0 = 全部）
        #[arg(long, default_value_t = 100)]
        limit: usize,

        /// 输出格式 (text, json)
        #[arg(short = 'o', long = "output", default_value = "text")]
        output: String,
    },

    /// 单条路由判定（verbatim 证据 + 可机械证伪的 --assert 退出码）
    #[command(after_help = "退出码：--assert 不匹配时返回 1，可用于 CI/脚本化复核。")]
    ExplainRoute {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 路由（含类级前缀，如 /data/export）
        #[arg(value_name = "ROUTE")]
        route: Option<String>,

        /// 相对文件路径（与 ROUTE 二选一或并用）
        #[arg(long)]
        file: Option<String>,

        /// handler 方法名（需配合 --file）
        #[arg(long)]
        handler: Option<String>,

        /// 断言：covered | uncovered | permitted | any（不匹配则退出码 1）
        #[arg(long, value_name = "EXPECT")]
        assert: Option<String>,

        /// 输出格式 (text, json)
        #[arg(short = 'o', long = "output", default_value = "text")]
        output: String,
    },

    /// 端点与覆盖判定的基线 diff（CI 门禁）
    ///
    /// 重复审计里真正昂贵的不是"再看一遍"，而是"判断哪些是新变的"。
    #[command(after_help = "退出码：--fail-on-new-uncovered 且存在新增未覆盖端点时返回 1。")]
    DiffRoutes {
        /// 项目路径
        #[arg(value_name = "PATH")]
        path: String,

        /// 基线文件（默认 <PATH>/.ctx-audit/routes-baseline.json）
        #[arg(long, value_name = "FILE")]
        since: Option<String>,

        /// 把当前端点表写成基线
        #[arg(long)]
        write_baseline: bool,

        /// 新增且未覆盖的端点存在时返回退出码 1
        #[arg(long)]
        fail_on_new_uncovered: bool,

        /// 输出格式 (text, json)
        #[arg(short = 'o', long = "output", default_value = "text")]
        output: String,
    },

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

    /// 查询增量索引状态（冷启动 / 缓存命中 / 待重编译清单）
    Incremental {
        /// 项目路径（省略时取守护进程已加载的第一个项目）
        #[arg(short, long)]
        project: Option<String>,
    },

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
    // 全局 rayon 池：**先于任何并行分析**建立并给足线程栈。
    // 真实仓库（压缩产物 dist/*.js）的 AST 递归深度足以打穿默认 2MB 线程栈并直接崩溃；
    // 这里统一 64MB，与遍历器的深度上界构成纵深防御。
    let _ = rayon::ThreadPoolBuilder::new()
        .stack_size(64 * 1024 * 1024)
        .build_global();

    init_logging(&cli);

    // 执行命令
    match cli.command {
        Commands::Scan {
            path,
            rules,
            severity,
            min_severity,
            pattern,
            output,
            threads,
            exclude,
            deep,
            taint,
            cross_file,
            daemon,
            sca,
            graph_output,
            query_mode,
            min_confidence,
            include_structural,
            precision_first,
            recall_first,
            dispatch_candidates,
        } => {
            commands::scan::execute(
                path,
                rules,
                severity,
                min_severity,
                pattern,
                output,
                threads,
                cli.output.as_str(),
                deep,
                taint,
                cross_file,
                daemon,
                exclude,
                sca,
                graph_output,
                query_mode,
                min_confidence,
                include_structural,
                precision_first,
                recall_first,
                dispatch_candidates,
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
            commands::analyze::execute(
                file,
                start_line,
                end_line,
                ast,
                symbols,
                cli.output.as_str(),
                daemon,
            )
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
            DaemonAction::Incremental { project } => {
                commands::daemon::incremental(project).await
            }
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

        Commands::Mcp { legacy_tools } => commands::mcp::run_mcp_server(legacy_tools)
            .await
            .map_err(|e| miette::miette!("MCP server error: {}", e)),

        Commands::SignalChain {
            from_diff,
            from_advisory,
            path,
            output,
            constructs,
            candidates_only,
            max_files,
        } => {
            commands::signal_chain::execute(
                path,
                output,
                constructs,
                candidates_only,
                max_files,
                from_diff,
                from_advisory,
            )
                .await
        }

        Commands::Baseline { path, output } => commands::baseline::execute(path, output).await,
        Commands::Audit {
            path,
            out,
            limit,
            output,
        } => commands::audit::execute(path, out, limit, output).await,
        Commands::Chain {
            path,
            list,
            id,
            sink,
            entry,
            learn,
            before,
            after,
            vocab,
            out,
            no_builtin_vocab,
            limit,
            output,
        } => {
            commands::chain::execute(
                path,
                list,
                id,
                sink,
                entry,
                learn,
                before,
                after,
                vocab,
                out,
                no_builtin_vocab,
                limit,
                output,
            )
            .await
        }

        Commands::ExplainRoute {
            path,
            route,
            file,
            handler,
            assert,
            output,
        } => {
            commands::explain_route::execute(path, route, file, handler, assert, output).await
        }

        Commands::DiffRoutes {
            path,
            since,
            write_baseline,
            fail_on_new_uncovered,
            output,
        } => {
            commands::diff_routes::execute(
                path,
                since,
                write_baseline,
                fail_on_new_uncovered,
                output,
            )
            .await
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
            println!(
                "Invoke-Expression -Command (& '{}' --completion powershell) | Out-String",
                name
            );
        }
        _ => {
            eprintln!("Unknown shell: {}", shell);
            eprintln!("Supported shells: bash, zsh, fish, powershell");
            std::process::exit(1);
        }
    }
}
