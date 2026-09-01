# CTX-Audit 3.0.0 Release Notes

## Overview

CTX-Audit 3.0.0 是一次大规模里程碑升级。自 v2.2.0 以来，项目累计包含 163 个提交、242 个文件变更，新增约 4.1 万行、清理/重构约 2.3 万行。本版本的核心变化是：将审计判定层从内部实验模块重构为 **通用、可配置、可私有化 overlay 的 Agent / Pipeline 框架**，同时把确定性安全分析引擎的能力大幅外放——新增大量规则、污点模型、证据链字段、MCP 工具、公共 DSH harness，以及面向大型代码库的性能与稳定性治理。

本版本继续坚持“确定性引擎负责证据供给，LLM 负责语义判定”的产品定位：

- 引擎先构建调用图、跨文件污点链和结构化证据；
- 再通过 MCP 协议把可验证上下文交给 LLM；
- 同时提供可编程 audit pipeline，让团队可以按需编排扫描、判定、gate 与报告流程。

## Highlights

- 新增可配置审计 Pipeline（`PipelineConfig`），支持完全数据驱动的 phase 阶段序列
- 新增 Agent CLI：`pipeline show` / `pipeline validate` / `round run --pipeline`
- 支持无 LLM provider 的纯确定性 pipeline，适合自动化门禁
- 公共 DSH harness 独立为 `harness/`，支持私有 overlay 注入
- 规则系统全面扩展：新增 60+ 规则/框架污点文件，审计包 audit-packs 达到 14 个
- 污点引擎新增二阶存储型漏洞建模、Python/PHP 生产链路修复、sanitizer 窗口语义
- MCP 工具链新增 `query_taint` 等能力；scan artifact 携带完整证据链
- 新增 Laravel/PHP 攻击面识别、C/C++ 内存安全规则、Go SSRF/上传/授权规则、LLM 应用污点源
- 大规模性能治理：跨文件流上限、TS 声明文件快路径、纯数据 PHP 快路径、bincode+zstd 缓存
- 全量 workspace 测试通过

## New Features

### Configurable Agent / Pipeline Framework

- `agent/src/pipeline.rs` 新增 Pipeline 配置模型：
  - scan 开关（taint / cross-file / rules_dir / min_severity）
  - judge prompt 与 system_prompt
  - 输出契约（TP 候选路径、verdict 字段、接受值）
  - gate 开关、registration 草稿润色
  - extra_phases（自定义 LLM 审计阶段）
- Runner 支持完全数据驱动的 `phases` 顺序：
  - 可跳过内置阶段
  - 可插入 `extra_phases`
  - `phases: null` 时保留默认推荐顺序
- CLI 支持：
  - `ctx-audit agent pipeline show`
  - `ctx-audit agent pipeline validate`
  - `ctx-audit agent round run --pipeline <file>`
- `daemon/src/agent_host.rs` 新增 daemon 内托管 Agent 轮次 runner，支持流式事件转发
- `agent` crate 全面入库：LLM provider、会话、runner、subagent、tool adapter、cron、gate、feedback

### Public DSH Harness

- `harness/` 作为公共 DSH 编排框架独立发布
- 包含 installable profile / skill / settings / launcher：
  - `harness/install.sh`
  - `harness/bin/ctx-audit-dsh`
  - `harness/bin/run-round.sh` / `run-scout.sh` / `run-sniper.sh`
  - `harness/profiles/audit`、`audit-scout`、`audit-sniper`
  - `harness/skills/ctx-audit-auditor/SKILL.md`
- 支持私有 overlay 注入：
  - `CTX_AUDIT_PRIVATE_DIR`
  - `AUDIT_LOG_DIR`
  - `DSH_SCOUT_PROMPT_FILE`
  - `DSH_SNIPER_PROMPT_FILE`
  - `CTX_AUDIT_PIPELINE_FILE`
- 公共 harness 默认使用极简模式；审计专用 preset 通过本地私有 overlay 提供
- `templates/` 提供 pipeline 示例与 private-overlay 初始化脚本

### Rule Engine & Detection Coverage

- 新增/补齐多语言规则，覆盖 CWE 家族包括：
  - C/C++：CWE-77/78 命令执行、CWE-88 参数注入、CWE-120/134/787 内存安全、缓冲区/格式化字符串/整数溢出降噪
  - Go：CWE-434 上传类型守卫、CWE-290 IP 校验、CWE-89 `fmt.Sprintf` SQL、SSRF source/sink/sanitizer 扩展
  - Java：XML 实体扩展限制、SpEL sanitizer、类字面量豁免、path-traversal `resolve()` 形态扩展
  - PHP：SQLite JSON extract 注入、动态 include、chmod 权限、CSRF missing-check、unserialize 分级、assert 误标收窄
  - Python：SQLAlchemy `text()` 拼接 SQLi、XPath unsafe parser、模板渲染路径 source
  - JS/TS：Prisma `$queryRawUnsafe`、inline 服务 XSS、stored XSS inline serve、response header injection、客户端模板裸插
  - 通用：默认关闭安全开关、installer config write、unsafe redirect、unprotected installer、weak encryption、XXE injection
- 审计包 audit-packs 新增至 14 个，沉淀 CWE 家族 TP/FP 判据：
  - cwe-78-cmdi、cwe-79-xss、cwe-89-sqli、cwe-22-pathtraversal、cwe-918-ssrf、cwe-502-deser、cwe-352-csrf、cwe-1321-prototype-pollution、cwe-1333-redos、cwe-367-race、cwe-613-672-session、cwe-862-863-authorization、cwe-259-798-secrets、cwe-120-134-c-memory、cwe-601-open-redirect、cwe-94-codei、generic 等
- 规则加载与校验体系加固：
  - 运行时规则加载器跳过 non-rule YAML 目录
  - `rules validate` 跳过 audit-packs / specialists / taint / risk-patterns 等非规则目录
  - 修复多份 YAML 非法引号、缺 RuleSet metadata、schema 失败告警
  - 内置规则嵌入二进制，仓库外运行时自动回退加载
  - 新增 63 个规则文件，含 33 个规则文件修改；当前规则 YAML 总数 118

### Taint Engine & Dataflow

- 二阶存储型漏洞建模 MVP：
  - `second-order.yaml` 定义存储点读出 source 与 storage_write sink 闸门
  - 项目级写入闸门统计，无写入事件时二阶 finding 降权
  - 支持 PHP fetch/row、Python fetchone/session、JS 前端响应回调等二阶形态
- Python/PHP 污点生产链路修复：
  - 修复 CPG 行号偏移导致 Python 系 AstTaint 生产全哑
  - 修复 PHP 调用节点提取、`$` 变量名被拒绝等致命断点
  - Python fragment 重解析恒失败修复（dedent_fragment）
- sanitizer 语义扩展：
  - `sanitizer_before_lines` 有界前向窗口
  - `sanitizer_after_lines` 后向窗口
  - `sanitizer_include_chain` PHP include 全局守卫收集
  - `sanitizer_match: all|any` 多守卫组合
  - sink 参数内联净化识别（如 `HtmlUtils.htmlEscape(...)`）
- sink/source 匹配修复：
  - `sensitive_params` 参数位置感知，参数化 SQL 不再误报
  - receiver 缩写/长名边界匹配，避免 `clientConfigs` 误伤 `client`
  - 类字面量参数豁免、SSRF 同源相对 URL 豁免、路径数字插值豁免
  - 赋值右值同步判定、赋值目标 sink 匹配（`innerHTML = ...`）
  - sink 级 FP 豁免（SSRF 字面量 host、path 语义等）
- 跨文件分析增强：
  - cross-file 语言参数化，YAML 规则 `languages` 生效
  - 语言域隔离修复跨语言假边
  - 全局中间件/守卫识别扩展（Go 全局 auth、PHP include guard）
  - C 宏展开近似、C 指针简单别名、死过滤模式检测
  - Python 实例属性污点传播近似实现

### MCP / LLM Collaboration

- 新增 MCP 工具 `query_taint`：支持存储点查询、变量反查、文件级污点摘要
- scan 产物新增完整证据链字段：
  - `evidence_refs`
  - `source_snippet` / `sink_snippet`
  - `barriers`
  - `file_role`
  - `enclosing_function_line`
  - `reasoning_hint`
- MCP `list_sources` / `list_sinks` 按文件语言过滤
- MCP 全局工具超时保护，`trace_variable_flow` 查询缓存
- 新增 `scripts/mcp_metrics.py` 与 `scripts/evidence_completeness.py`
- LLM-AUDIT-SKILL 新增 Phase 2.5 链式深审流程
- 内置规则嵌入二进制后，MCP 在仓库外也能加载完整规则与 sanitizer 描述

### Attack Surface & Language Modeling

- PHP：完整 pipeline AST 支持（parser / symbols / attack surface），Laravel `Route::group` middleware 绑定、`before => 'auth'` 过滤器、collection 组级守卫识别
- Python：Django `|safe` 审计判据、模板渲染输出作为路径 source、Flask 污点规则、AIOHTTP 框架污点规则
- Go：SSRF 大字典扩展、上传 filename source、archive entry sink、验证类规则
- C/C++：宏展开近似、回调注册显式建边、指针简单别名
- JS/TS：事件回调参数二阶 source、前端赋值目标 sink、Remix/React Router `request.*` source、Handlebars/EJS 模板裸插提示

## Performance & Reliability

- 跨文件流最大条数配置 `scan.cross_file_max_flows`，默认 5000，防止大项目 OOM
- 递归调用图遍历改为迭代 BFS，避免栈溢出
- flow-to-finding 转换改为流式处理，共享 middleware evidence
- TS declaration 文件 Stage B 快路径（`.d.ts` 跳过），大仓库性能提升显著
- 纯数据 PHP 文件 Stage B 快路径，避免巨型数组字面量状态爆炸
- 路径敏感污点传播增加分支点预算，超大函数降级为规则层覆盖
- 可达性查询缓存、扫描缓存改 bincode+zstd、analyze_project 并行构建路径
- vendor / venv / node_modules / minified 文件识别，减少图噪声
- 测试文件在 Stage B 污点候选排除，减少无效分析量
- UTF-8 非编码源文件 lossy 降级扫描，不再静默跳过

## Bug Fixes

- 修复多份 YAML 规则非法引号、RuleSet metadata 缺失、风险模式 YAML 非法
- 修复规则加载器把 audit-packs / specialists / taint 当规则解析
- 修复 MCP source/sink 语言过滤缺失
- 修复 `rules validate` 误解析 `risk-patterns.yaml`
- 修复 innerHTML/outerHTML/document.write 常量右值误报
- 修复字符串字面量 RHS helper 字节字面量处理
- 修复 C/C++ 规则空白回溯、分配器名字缺失 `\b`、calloc 噪声、`gets` 大小写误伤、memcpy 死 pattern
- 修复 Java/Go 反序列化误标、serde/toml/bincode 等数据格式误报 CWE-502
- 修复 Python path-traversal 过度召回：重新要求用户输入标记，`os.path.join` 降为 medium
- 修复 SSRF 误报：同源相对 URL、字面量 host、固定常量 URL、重定向语义
- 修复跨文件调用图跨语言假边
- 修复 CPG 行号偏移、变量解析 unwrap panic、分支合并净化误判
- 修复 UTF-8 多字节切片 panic、非 UTF-8 文件静默跳过
- 修复可执行 lookaround 不支持的 regex pattern 静默失效（5 条规则）
- 修复 PHP 认证守卫识别、CSRF 全局 include 守卫、路由过滤器守卫
- 修复 audit-pack CWE 前缀误匹配（CWE-78 与 CWE-787）
- 修复去重聚类与输出顺序确定性、容差去重首行锚定窗口
- 修复 launcher 路径与 profile 使用问题，harness 公共化清理

## Validation

在干净环境中完成以下验证：

- `cargo build --release` ✅
- `cargo test --workspace` ✅
- `ctx-audit rules validate`：规则全部有效 ✅
- 公共 DSH harness 可安装、launcher 可启动 ✅
- 确定性 pipeline / LLM pipeline 冒烟验证 ✅
- 多语言规则回放：CVE 漏洞版命中、修复版豁免闭环 ✅
- CI：GitHub Actions 构建、测试、clippy、安全扫描 ✅

## Installation

```bash
# DSH 是外部可选依赖，如需公共 harness 再安装
npm install -g @deepseek-ai/dsh@0.1.1-rc.2

# 构建
cargo build --release

# 公共 harness 安装
DSH_HOME="$HOME/.dsh" ./harness/install.sh

# 使用 pipeline 模板
ctx-audit agent pipeline validate --pipeline templates/pipelines/ctx-audit-default.yaml
ctx-audit agent round run --pipeline templates/pipelines/ctx-audit-default.yaml --target ./project
```

## Upgrade Notes from v2.2.0

- 推荐审计方式保持 MCP 协作：`ctx-audit mcp`
- `audit --agent` 旧命令已移除，统一使用新的 `agent pipeline` / `agent round` 命令
- 公共 DSH harness 已从 `templates/dsh` 迁移到 `harness/`
- `CHANGELOG.md` 不再纳入 Git 版本管理，保留为本地工作文档
- 新增 `scan.cross_file_max_flows` 配置，默认 5000；大型项目可自行调整
- YAML 规则目录现在会跳过非规则目录，自定义规则仍通过 `--rules` / `CTX_AUDIT_RULES_DIR` 注入

## Acknowledgements

感谢所有贡献者、开源安全社区与真实项目审计反馈。