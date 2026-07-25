# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **PHP AST 支持（全链路）**：`tree-sitter-php` 接入 AST 引擎——`core/src/ast/parser.rs` 注册 `.php` 并新增 `extract_php_symbols`（class_declaration / function_definition / method_declaration，方法携带 ownerClass 元数据），三处符号分发（`extract_symbols` / `parse_full` / `parse_and_extract_calls`）全部接通；`attack_surface.rs` 新增 `analyze_php_file`（Laravel `Route::get/post/...` 与 Symfony `#[Route]` 路由识别、路由组 `Route::middleware('auth')` 文件级守卫、原生 PHP 超全局变量脚本入口识别、13 种 PHP 输入源信任边界）。同步打通 5 处扩展名门槛（`scanner/mod.rs` ×2、`ast/engine.rs`、`attack_surface.rs` walk_project、`cli/src/index.rs`、`indexing/code_chunks.rs`）——此前 PHP 文件虽早有 php 污点框架规则与 php-* 模式规则，但被这些门槛挡在 AST/攻击面管线之外（R23 laravel 扫描 0 findings 的根因）。测试机实测：laravel 0→1（UnauthenticatedEndpoint）、typecho 43→53（新增 CWE-89/78/94 等 AST 管线产出，零回归）。
- **判定层产品化（证据包 + 编排 + 会话持久化）**：新增 `rules/audit-packs/` 证据包机制（9 个 YAML，覆盖 CWE-79/89/78/94/502/918/22/259+798 及 generic 兜底），每个包定义按 CWE 的取证步骤（evidence_steps，MCP 工具 + 要回答的问题）、TP/FP 判据与置信度校准指南；`core/src/rules/audit_pack.rs` 提供 schema、文件系统/嵌入双路加载与 `find_pack` 匹配（vuln_type 别名 + CWE 编号规范化）。MCP 新增两个工具：`audit_plan`（deep 扫描 → 按 (vuln_type, file) 分组 → 匹配证据包 → 持久化会话到 `<project>/.ctx-audit/audit_sessions/<uuid>.json`，返回分组清单与各组完整证据包）与 `audit_finalize_report`（汇总会话判定，生成含项目指纹/判定统计/TP 攻击链详情/FP 分组摘要的 Markdown 报告）；`start_investigation` 升级：`suggested_tools` 改为证据包取证步骤（自动注入 finding 的 file/line），并附 TP/FP 判据与置信度指南，支持可选 `vuln_type` 参数直接匹配证据包。审计会话增加磁盘持久化：创建即写盘，查询时内存未命中自动从磁盘恢复，`conclude_audit_session` 不再删除磁盘留档，`conclude_investigation` 会自动更新分组状态。调查上下文（investigation）同样持久化到 `.ctx-audit/audit_sessions/inv_<iid>.json`，`log_investigation_step`/`conclude_investigation` 在 MCP 进程重启后仍可继续；`find_pack` 支持 vuln_type 本身即 CWE 编号（如 RegexRule 的 `CWE-79`）时与 pack 的 cwe 列表做数字等价匹配。
- **Flask 污点规则**：新增 `rules/taint/frameworks/flask.yaml`，定义 Flask 专属 sources（`request.args`、`request.form`、`request.json`、`request.headers`、`request.cookies`、`request.view_args` 等 8 个 source）和 sinks（SSTI `render_template_string`、命令注入 `subprocess.Popen`/`os.system`、SQL 注入 `cursor.execute`、代码注入 `eval`/`exec`、路径穿越 `flask.send_file`、SSRF `requests.get`、反序列化 `pickle.loads`/`yaml.load`、XSS `Markup` 等 10 个 sink），以及 11 个 sanitizer（`html.escape`、`shlex.quote`、`secure_filename`、`yaml.SafeLoader`、`is_safe_redirect_url` 等）。此前 Python 项目扫描完全依赖通用规则和 Django YAML，Flask 专属模式完全缺失。

### Fixed

- **`php-sql-injection` 规则缺词边界误报**：pattern 中 `(WHERE|VALUES|SET)` 无 `\b`，误命中 `isset(...$_COOKIE...)`（"isset" 含 "set"）与 `setCookie(...)`，typecho 实测产生 2 个 CWE-89 误报。两个 SQL 关键词组均补 `\b` 词边界（与此前 `cpp-format-string` 修复同法）。
- **证据包 `find_pack` CWE 前缀误匹配**：`vuln_type="CWE-78"` 规范化后为 `"cwe78"`，是 `"cwe787"` 的子串，包含式匹配使 CWE-78 命令注入 finding 挂上 C 内存安全证据包（c-memory 按 id 排序先于 cmdi）。修复：双方都含 CWE 数字且数字不同（如 78 vs 787）时禁止包含式匹配，附回归测试。typecho 审计实测发现并验证。
- **`command-injection` PHP pattern 子串误报**：裸 `exec\s*\(` 误命中 `curl_exec(` 与 JS `RegExp.prototype.exec()`，裸 `system\s*\(` 可误命中 `filesystem(`。`system|exec` 补 `(?:^|[^\w.])` 前缀边界（与 code-injection `compile` 修复同法），typecho 复扫 2 个 CWE-78 误报消除。
- **`php-unsafe-deserialization` CWE 归类修正与拆档**：PHP `unserialize` 对象注入正确 CWE 为 CWE-502（原标 CWE-94 导致挂错证据包）；裸 `unserialize($var)` 任意变量 pattern 拆分为独立规则 `php-unserialize-variable`（medium），直接超全局输入保持 critical——数据库内容等二阶来源不再以 critical 噪声进入 high+ 审计范围。
- **多字节字符按字节切片崩溃（2 处）**：`rules/scanner.rs` likely_fp 上下文窗口（±200 字节）与 `ast/parser.rs` 回调函数体 500 字节截断，窗口端点落在多字节字符内部时按字节切片 panic，扫描含中文注释的文件直接 core dump（emlog 实测两处各崩一次）。修复：窗口端点钳制到 char 边界（新增 `floor/ceil_char_boundary`）、截断统一走 `truncate_string_safe`。
- **5 条规则 pattern 使用 Rust regex 不支持的 lookaround，静默失效**：`code-injection`（python eval/exec 后顾）、`command-injection`（python subprocess `(?!\[)` 前瞻）、`csrf-exemption`（javascript `(?!.*csrf)`）、`hardcoded-crypto-key`（`(?=...)` 前瞻）、`unsafe-deserialization`（python yaml.load SafeLoader 前瞻）——Rust regex 不支持 lookaround，这些 pattern 自引入起从未生效（启动时仅一行 eprintln 警告）。全部改写为合法等价形式：后顾改 `(?:^|[^...])` 前缀边界；subprocess 改匹配字符串首参（`["']`）排除列表形式；yaml.load 改"单变量参数 / 显式危险 Loader"两种可表达形态（SafeLoader/CSafeLoader/BaseLoader 借 `\b` 排除，附判别测试）；crypto-key 去掉非本质前瞻；csurf 保留可表达分支。`unsafe-deserialization` 的 PHP 裸 `unserialize(` 同步对齐为超全局直通（与 `php-unserialize-variable` 分级一致）。新增防线测试 `test_all_embedded_rule_patterns_compile`：任何嵌入规则 pattern 无法编译即测试失败，"规则静默死亡"从日志升级为 CI 门禁。
- **攻击面原生 PHP 入口未识别 include 式认证守卫**：emlog `admin/*.php` 统一 `require_once 'globals.php'`，由被包含文件执行 `loginAuth::checkLogin()`，攻击面分析将 14 个后台脚本全部误报为 UnauthenticatedEndpoint。修复：`analyze_php_file` 原生分支识别守卫调用（`checkLogin(`/`is_user_logged_in(`/`Auth::check(` 等）与守卫 include（`globals.php`/`auth.php`/`guard.php`），命中即标记 `auth_required`。emlog 复测：UnauthenticatedEndpoint 14→5（剩余 5 个为库类/视图/插件页误判，另议），archivy CWE-502 回归保持 0。

- **CWE-502 误报 `yaml.SafeLoader`**：`unsafe-deserialization.yaml` 的 Python pattern 对 `yaml.load(...)` 无 SafeLoader 排除意识，在显式使用 `Loader=yaml.SafeLoader` 时仍报 CRITICAL。pattern 新增 negative lookahead `(?!.*yaml\.SafeLoader)`；`specialists/deserialization.yaml` safe_patterns 补 `yaml\.SafeLoader`。archivy 复测：CWE-502 1→0。
- **CrossFileTaintAnalyzer `infer_vuln_type` getter 函数误分类**：`get_db`、`get_items`、`get_config` 等常见 getter/helper 函数被 name fallback 误归为安全 sink（database→SQLi、file read→PathTraversal）。新增 getter prefix 白名单（`get_db`、`get_database`、`get_items`、`get_config` 等 14 个）和 safe prefix（`build_`、`list_`、`load_config`、`init_` 等），命中直接返回 `Generic`。`open_file`/`openfile` 本地工具函数排除 PathTraversal。

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

- **内置规则嵌入二进制**：`core/src/rules/embedded.rs` 通过 `include_dir` 将仓库根 `rules/`（模式规则 + `taint/` 污点规则）打包进二进制。此前规则目录解析依赖相对 CWD 的 `rules/` 路径，在仓库外运行（如 `cargo install` 后、MCP 以项目目录为 CWD）时所有 YAML 规则静默失效（日志仅一行"未找到规则目录"）。现在文件系统三级查找失败时自动回退到嵌入规则；`AstTaintAnalyzer::new`、Stage B/C 污点规则加载、MCP 规则列表与 sanitizer 描述均走 `load_taint_rules_with_embedded_fallback`。
- **Vendor / minified 第三方库识别**：`classify_file_role` 扩展 vendor 判定（`/node_modules/`、`/plugins/`、`/libs/` 目录，`*.min.js`/`*.bundle.js` 等文件名，jquery/bootstrap 等知名库前缀）；新增 `is_minified_content` 内容级识别（超长单行/平均行长启发式）与 `classify_file_role_with_content`。vendor 文件不再进入 Stage B 污点候选、Stage C 跨文件分析与跨文件调用图建图（ServerStatus 实测可消除 96% 的图噪声节点）；规则扫描的 vendor finding 仍保留但按既有 `adjust_severity` 降权。
- **likely_fp 参数评估**：`RuleScanner` 对 regex 命中的 sink 调用做参数分析（字符串感知的括号配平提取实参）：参数全部为字面量（如 `os.popen("netstat ...")`）、printf 族格式串为字面量且不含 `%s/%[`（输出有界）、凭证类规则命中占位符值（`USER_PASSWORD`/`changeme` 等）时，finding 标记 `likely_fp` 原因并降为 info（不丢弃，交由 LLM/上层最终判定）。

### Fixed

- **跨文件调用图跨语言假边**：`cross_file.rs` Phase 2 裸名全局回退连边不做语言校验，导致 Python 方法被连到 jQuery 同名函数（ServerStatus 实测一个 `get` 产生 366 个"调用者"，`find_call_path` 会"确认"Python→JS 的不可能路径）。新增 `language_domain` / `same_language_domain`：双方均为已知语言时必须同域（JS/TS 同域、C/C++ 同域），未知语言放行避免误杀。import 精确匹配与 receiver 解析路径不受影响。
- **`extract_relative_path` 跨平台解析失败**：`tools/src/bridge.rs` 提取项目目录名时直接用 `Path::file_name()` 解析 `project_path`，Windows 风格路径（`D:\project\myproject`）在 Linux 下反斜杠不被识别为分隔符，导致项目名解析失败、相对路径剥离失效（Linux 下 `cargo test --workspace` 中 `test_extract_relative_path_with_project_prefix` 失败）。修复为先将 `project_path` 的 `\` 统一替换为 `/` 再提取目录名。
- **规则命中注释中的代码**：正则规则对注释行与代码行无差别命中（注释掉的 `innerHTML`、`DOCTODO`/`HACK` 注释关键词等）。`RuleScanner` 新增注释感知过滤：首个命中时用 tree-sitter AST 惰性收集全文件注释字节范围，命中点落在注释节点内直接丢弃（注释中的代码不会执行，必为误报）。ServerStatus 复测消除约 25% 的规则层误报。
- **格式串规则误伤有界变体**：`cpp-format-string` 的 pattern 以 `printf\s*\(` 子串匹配，误命中 `snprintf`/`vsnprintf` 等长度受控调用。pattern 增加 `\b` 词边界，有界变体不再命中。
- **code-injection 误命中正则编译**：Python pattern 中 `compile\s*\(` 误命中 `re.compile`/`Pattern.compile`。改为 `(?:^|[^\w.])compile\s*\(`，排除成员调用形态。
- **JS 污点字典误报治理**（Uptime Kuma 真实项目驱动，55 → 39 findings，CRITICAL 8 → 1）：
  - `JSON.parse` 移出反序列化 sink（JS 语境下 `JSON.parse` 不是 Java `readObject`，此前产生 4 个 CRITICAL 误报）。
  - `process.argv`/`sys.argv` 等 CLI 参数从 `http_request` source 拆出为独立的低严重度 `cli_args` source（`TaintCategory` 新增 `CliInput` 变体），CLI 入参不再被当作远程攻击面。
  - 跨文件 `is_taint_sink` 函数体匹配对 Semantic 模式 sink 增加语义锚点要求（namespace / receiver_pattern / exact_match 必须出现在函数体中），消除 `.exec`/`.run` 短 pattern 把 `connection.exec`、`log()` 等任意函数误判为命令注入 sink 的问题。
  - 推测性参数 source（callback param / tainted param）产生的 finding 降一级严重度并降低置信度（SSRF 通知配置等"设计内"流量自动降权）。
  - 污点 finding 与规则扫描一致应用 `adjust_severity`（build 角色的 dev 脚本如 `extra/` 自动降级）；`/extra/` 目录归入 build 角色；占位符清单补 `"******"`（密码脱敏代码不再被误报为硬编码密码）。

### Added

- **`hardcoded-crypto-key` 规则**（`rules/hardcoded-crypto-key.yaml`）：检测密钥类变量（cipherKey/secretKey/aesKey 等）被赋予长常量字面量（CWE-798）。由 Apache Shiro CVE-2016-4437 双向验证驱动：1.2.4（漏洞版）在 `AbstractRememberMeManager.java:80` 命中硬编码 AES 密钥，1.2.5（修复版，`generateNewKey()`）零命中。配套调整：likely_fp 参数字面量降权不再应用于凭证/密钥类规则（硬编码常量正是此类规则要发现的问题）。
- **OWASP BenchmarkJava v1.2 可回归基线**：新增 `BASELINE.md` 记录 `--taint` / `--deep` 模式下的 precision / recall / F1（taint: P=0.344 R=0.514 F1=0.412；deep: P=0.336 R=0.514 F1=0.406）。

### Added
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

- **Agent 测试编译失败**：`Finding` 新增 `enclosing_function` / `enclosing_function_line` 字段后，`cli/src/agent` 各测试模块的构造函数未同步，导致 `cargo test --workspace` 编译失败（10 处 E0063）。已全部补齐，`cargo test --workspace` 恢复可用。
- **Stage B 污点分析在 `target/` 等目录下被整体跳过**：`core/src/scanner/mod.rs` 二次收集循环用带扫描根前缀的路径调用 `is_excluded`，扫描根本身位于 `target/` 时所有 AST 文件被排除（Stage A 已用根相对路径，此处不一致）。修复为根相对判断；修复后 `run-baseline.sh` 的 `--deep` 扫描才真正包含污点分析。
- **Java 污点传播断流（if 体注释）**：`AstCFGBuilder::process_if` 处理 consequence/alternative 子节点时始终从 `cond_id` 重新出发，注释等不产生 CFG 节点的子节点会把 `end` 重置回条件节点，导致 if 体内最后一条真实语句到 merge 的边丢失。改为链式连接（`end` 作为前驱），修复 `headers.nextElement()` 等 receiver 传播链断流（BenchmarkTest00012 LDAP 注入检出）。
- **净化器误判切断传播**：sanitizer 匹配从普通子串改为标识符边界感知（`expr_mentions_sanitizer`），`Base64.encodeBase64` 不再被误判为 `encode` 净化器，Base64 编码往返表达式不再切断污点传播（BenchmarkTest00207 XPath 注入检出）。
- **去重吞 finding**：传播覆盖入口行扫描直接标记的 source 标注时，多条 finding 会共享同一 source 行并在 `(file, line_start)` 去重时被错误合并。现在保留原始 source 标注（如 00012 的 XSS 不再被吞进 LDAP finding）。
- **Java 污点字典缺口**：`java_ldap` 的 `sensitive_params` 从 `[0]` 改为 `[0,1]`（原配置只检查 `search(base, ...)` 的 arg0，漏掉真正可被注入的 arg1 filter），receiver_patterns 补充 `idc`/`ldap`/`naming`；`java_xpath` receiver_patterns 补充 `xp`（`xp.evaluate(...)` 形态）。BenchmarkJava CWE-90 召回从 0 提升到 0.889。
- **TaintWalk 测试与解析修复**：测试 mock 未实现关键词协议切换后使用的 `chat` 接口（`LlmClient::chat` 默认返回空串），导致 3 个 taint_walk 测试失败；同时 `parse_taint_walk_decision_from_text` 在文本明显是 JSON（`{` 开头）时优先走 JSON 解析，避免关键词解析器把单行 JSON 误当键值对并用默认值静默吞掉。
- **Agent 集成测试环境隔离**：`cli/tests/audit_agent_test.rs` 6 个端到端测试继承全局配置，当用户配置 `agent.llm_mode=http` 但 API key 失效时 triage 全部失败、audit_log 为空。测试统一显式传 `--llm-mode noop`，不再受全局配置影响。
- **evaluate.py 归一化映射补全**：补充 `xpath injection`→643、`insecure cookie`→614、`trust boundary violation`→501、`weak hash (algorithm)`→328，修复此前对应 CWE 的真阳性被统计为误报的问题（CWE-643 召回从账面 0 修正为实际 1.0）。

### Changed

- **`rules/insecure-random.yaml` Java 模式收窄**：仅匹配 `new Random(` 实例化与 `Math.random()`，不再匹配 `java.util.Random` 类型引用（实际声明为 SecureRandom 的安全用法）。BenchmarkJava CWE-330 真阳性 193 → 218（召回 1.0），该规则在 false 文件上的误报 104 → 0。
- **`rules/command-injection.yaml` Java 模式收窄**：要求 `new ProcessBuilder(` 构造形式，避免命中异常消息字符串字面量中的 `ProcessBuilder(...)`。CWE-78 真阳性持平（33），规则误报 60 → 30。

### Added

- **`enclosing_function` 全模式覆盖**：Stage B 结束后用已解析的 per-file 符号构建函数区间表（`build_file_function_ranges` + `enrich_findings_with_enclosing_function_from_symbols`），`--taint` / `--deep` 模式下所有 finding（含 RuleScanner / AttackSurfaceMapper 产出）自动填充包围函数名与起始行，WebGoat 覆盖率从 0% 提升到 90%；跨文件 query_engine 路径行为不变，纯规则扫描保持零开销。

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
