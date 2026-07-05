# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
