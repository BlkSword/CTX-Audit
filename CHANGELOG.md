# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Agent 架构搁置，推荐 MCP 协作模式**：经 WebGoat 基准测试验证，内部 Agent（Supervisor/Specialist/Investigator/TaintWalk/Reviewer）实际效果未达预期（TaintWalk 0% source 发现率，Specialist 28/28 返回"无法判定"）。`audit --agent` 默认改为 noop 模式，推荐使用 MCP 协议让外部 LLM 驱动调查。详见 `LLM-AUDIT-SKILL.md`。
- **Finding 自动填充 enclosing_function**：扫描阶段为每个 finding 查询包围函数名，覆盖率 97%。MCP LLM 可直接用函数名调 `query_callers`/`query_callees`，无需额外步骤。
- **MCP 新增 `search_code` 工具**：跨项目正则搜索代码内容，支持文件类型过滤，补全了"查调用图但看不到赋值/导入"的信息缺口。
- **TaintWalk 关键词协议**：TaintWalk 通信从脆弱的 JSON 文本解析改为 `KEY: value` 关键词协议，兼容任意 LLM，消除了解析失败导致的全部 TaintWalk 中断。
- **路径处理修复**：`tools/src/bridge.rs` 的 `extract_relative_path` 新增 case 2b——剥离完整 project_path 前缀，修复 finding file_path 与 project_path 重复导致的 `Invalid path` 错误。
- **栈溢出缓解**：TaintWalk 改为 `tokio::spawn` 隔离执行，打断 triage→specialist→investigator→taint_walk 10+ 层嵌套调用链。
- **Java YAML 规则扩展**：新增 `java_template_injection`（SSTI）、`java_log_injection`、`java_xxe_parser`、`java_open_redirect` 4 个 sink 规则，sanitizer 从 85 扩至 101 个。Spring source 补 `@RequestPart`/`@MatrixVariable`/`MultipartFile`。

### Removed

- **内部 Agent 默认关闭**：`agent.llm_mode` 默认值从 `http` 改为 `noop`。

### Added

- **OWASP BenchmarkJava v1.2 可回归基线**：新增 `BASELINE.md` 记录 `--taint` / `--deep` 模式下的 precision / recall / F1（taint: P=0.344 R=0.514 F1=0.412；deep: P=0.336 R=0.514 F1=0.406）。
- **主次模型搭配（Dual-Model Routing）**：
  - `LlmConfig` 新增 `model_pro` 字段，用于配置强模型（如 `deepseek-v4-pro`）。
  - `ControlledLlmClient` 同时持有 fast 模型（`model`）与 pro 模型（`model_pro`）。
  - `triage` 按案件复杂度路由：非激进模式下复杂案件走强模型；激进模式下低严重度/证据清晰案件走 fast 模型，高严重度/证据冲突/needs_review 走强模型。
  - `investigate_decision` / `chat` / `chat_json`（Reviewer / Planner）始终走强模型；未配置 `model_pro` 时自动回退到单模型。
- **Agent LLM 默认激活**：
  - `agent.llm_mode` 默认从 `noop` 改为 `http`，`agent.review_mode` 默认从 `off` 改为 `debate`。
  - `agent.specialist_enabled` 与 `agent.investigator_enabled` 默认开启。
  - 支持通过 `CTX_AUDIT_LLM_API_KEY` 环境变量读取 API key。
  - 未配置 API key（且非本地 Ollama endpoint）时自动回退到 `noop` LLM 客户端，避免无 key 时直接失败。
- **`config show` / `config list` 补充 Agent 配置项展示**。
- **Agent `--llm-aggressive` 模式**：新增 CLI 参数 `--llm-aggressive` 与配置项 `agent.llm_aggressive`。启用后 `ControlledLlmClient` 跳过证据清晰度规则短接，对高严重度 finding 强制调用真实 LLM（仍受预算控制），用于评估 LLM 在清晰 source→sink 场景下的判定价值。
- **LLM 调用计数器**：`ControlledLlmClient` 按模型与用途（triage / investigate / review）统计 LLM 调用次数，审计结束后写入 `<project>/.ctx-audit/llm_usage.json`。
- **扩展 Specialist 覆盖**：新增命令注入（CWE-78）、不安全反序列化（CWE-502）、路径遍历（CWE-22）、SSRF（CWE-918）四个基于规则的 PatternBasedSpecialist，规则文件位于 `rules/specialists/`。
- **可回归基线脚本**：新增 `benchmarks/run-baseline.sh`，一键跑 `--taint` / `--deep` / `agent_noop_100` / `agent_dual_100` 并生成评估报告。

### Changed

- `agent.triage_concurrency` 默认值从 4 提升到 32，提高 Agent 在高并发 LLM endpoint 下的吞吐。
- `agent.max_llm_calls` 默认值从 100 提升到 500，并新增按严重度默认预算（critical=100, high=200, medium=200）。
- `agent.max_investigation_steps` 默认值从 5 提升到 10。

### Fixed

- **Agent 扫描排除目录与 CLI 不一致**：`run_security_scan` 现在读取配置文件中的 `scan.exclude_patterns` / `exclude_extra` 并传给 core 扫描器；修复了当项目位于 `target/` 等默认排除目录下时 Agent 扫描返回 0 finding 的问题。
- **跨文件污点流内存崩溃**：在 `ScanOptions` 新增 `cross_file_max_flows`（默认 50000），超过上限时截断并告警，防止 full BenchmarkJava `--deep` 扫描直接内存分配失败。
- **MCP `security_scan` 排除目录与 CLI 不一致**：`tool_security_scan` 现在读取 CLI 配置中的 `scan.exclude_patterns`、线程数、内存预算等参数，避免 `target/` 等目录在 MCP 路径下被 core 默认值误排除。
- **Finding `code_context` 为空**：`extract_code_context` 在 `source` 行号晚于 `sink` 行号时自动取最小/最大范围，确保上下文非空。
- **`source_snippet` / `sink_snippet` 缺失**：AST 污点 findings 在 source/sink 节点缺少代码片段时，自动回退到对应行的原始代码。
- **净化器证据精确化**：`evidence_refs.sanitizer_chain` 现在会收集污点路径中 `Sanitized` 节点，包含净化函数名、文件、行号及有效性判定。
- **匿名类 / 内部类调用图支持**：Java AST 符号提取时把匿名类（`new X() { ... }`）压入类作用域；跨文件调用图为 Java 方法使用 `ownerClass.method` 限定 ID，避免同名方法冲突；`CallGraph::file_functions` 使用规范化路径作为 key。
- **Agent Investigator / Reviewer 中文日志截断 panic**：修复 `&text[..text.len().min(N)]` 在多字节 UTF-8 字符边界处 panic 的问题，改用 `text.chars().take(N)`，避免 LLM 返回中文时进程崩溃。
- **Agent Investigator JSON 容错**：LLM 返回非 JSON 或解析失败时回退到 `needs_review`，不再导致单个 finding 调查失败。
- **HTTP LLM 调用重试**：`HttpLlmClient` 对 OpenAI/Anthropic 兼容接口增加 3 次指数退避重试，降低瞬态网络/API 错误导致的调查失败。
- **Reviewer 误报抑制**：`RuleBasedReviewer` 仅在 specialist 置信度不低于初审时才覆盖原判定；`LlmBasedReviewer` 与 debate 阶段正确计算 `agrees_with_primary`，避免 LLM 默认被当作"不同意初审"。
- **LLM-based Planner 激活**：移除 `CTX_AUDIT_LLM_AVAILABLE` 环境变量门控，`Auto` 模式根据实际 LLM 客户端类型（noop/http）决定是否启用 LLM 战略规划；实现 `plan_goals_with_llm`，支持从 `EnvironmentModel` 生成审计目标。

## [2.1.0] - 2026-07-05

### Added

- **AST 片段解析 `ASTParser::parse_fragment`**：支持对函数体文本单独解析局部 AST，为函数级并行 CPG 构建提供 AST 节点。
- **CPG 构建器新方法**：
  - `CPGBuilder::build_function_cpg_from_text`：纯文本回退构建单函数 CPG。
  - `CPGBuilder::build_function_cpg_from_fragment`：基于 AST 片段构建单函数 CPG，自动处理函数体相对行号与文件绝对行号的转换。
- **项目级性能基准**：README 新增 WebGoat-new 真实项目扫描基准（~52s / 249 findings）。

### Changed

- **Stage B 并行化重构**（`core/src/scanner/mod.rs`）：
  - 移除候选文件 batching，所有 AST 文件一次性进入 `rayon` 并行处理。
  - 文件内部按**函数粒度**并行构建 CPG 并执行污点分析。
  - 污点规则（sources / sinks / sanitizers）通过 `Arc` 在 Stage B 所有并行任务间共享。
- **`AstTaintAnalyzer` 去 parser 化**（`core/src/analysis/ast_taint.rs`）：
  - 不再持有 `tree-sitter::Parser`（非 Send/Sync），分析器本身变为可 `Arc` 共享。
  - `analyze_file` / `analyze_code` 改为使用线程本地 parser。
  - `analyze_function_cpg` 等核心路径不受线程安全限制，可在 rayon 任务中共享只读分析器。
- **README 性能章节**：补充 v2.1.0 Stage B 并行化说明与 WebGoat-new 基准数据；统一 AST 支持语言数量为 12 种。

### Fixed

- 修复函数体文本构建 CPG 时 assignments / calls 行号与 CFG 节点行号不一致的问题，确保 `node_meta` 正确附加 assignment / call_info。

### Performance

- WebGoat-new（`--agent --deep --no-auto-goal --max-findings 10 --min-severity high`）：
  - 总耗时从约 **58s**（上一稳定状态）→ 中间 text-only 回退版约 **282s** → v2.1.0 优化后约 **52s**。
  - findings 数量保持 **~249**（与优化前 250 基本一致）。
  - Stage B 函数级并行 + AST fragment 解析使 text-only 回退造成的性能回退被完全修复，并略快于原基线。

### Verification

- `cargo test -p ctx-audit`：65 项测试全部通过（54 单元 + 6 audit agent 集成 + 5 CLI 集成）。
- WebGoat-new 深度扫描验证：检出 CWE-78、CWE-502、CWE-94 等真实漏洞，调用图 source→sink 路径证据完整。
