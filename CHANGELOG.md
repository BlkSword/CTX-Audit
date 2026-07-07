# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **OWASP BenchmarkJava v1.2 可回归基线**：新增 `BASELINE.md` 记录 `--taint` / `--deep` 模式下的 precision / recall / F1（taint: P=0.344 R=0.514 F1=0.412；deep: P=0.336 R=0.514 F1=0.406）。
- **Agent LLM 默认激活**：
  - `agent.llm_mode` 默认从 `noop` 改为 `http`，`agent.review_mode` 默认从 `off` 改为 `debate`。
  - `agent.specialist_enabled` 与 `agent.investigator_enabled` 默认开启。
  - 支持通过 `CTX_AUDIT_LLM_API_KEY` 环境变量读取 API key。
  - 未配置 API key（且非本地 Ollama endpoint）时自动回退到 `noop` LLM 客户端，避免无 key 时直接失败。
- **`config show` / `config list` 补充 Agent 配置项展示**。

### Changed

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
