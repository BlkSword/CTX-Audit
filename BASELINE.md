# CTX-Audit 引擎基线

本文件记录 CTX-Audit 确定性引擎在 OWASP BenchmarkJava v1.2 上的可回归指标，用于后续 Agent LLM 激活与引擎优化的效果对比。

## 环境

- 日期：2026-07-07
- 版本：v2.1.0
- 数据集：OWASP BenchmarkJava v1.2
  - Ground truth：`target/benchmarks/BenchmarkJava/expectedresults-1.2.csv`
  - 测试用例总数：约 1415 个真实漏洞 + 对应误报用例
- 运行命令：

```bash
# Taint 模式（单文件 AST 污点）
./target/release/ctx-audit.exe scan target/benchmarks/BenchmarkJava \
  --taint --min-severity info \
  --output target/benchmarks/benchmarkjava_taint.json

python benchmarks/evaluate.py --dataset owasp-java \
  --ground-truth target/benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --findings target/benchmarks/benchmarkjava_taint.json \
  --mode taint \
  --output target/benchmarks/benchmarkjava_taint_report.md

# Deep 模式（跨文件 CPG 污点，含 50000 流上限）
./target/release/ctx-audit.exe scan target/benchmarks/BenchmarkJava \
  --deep --min-severity info \
  --output target/benchmarks/benchmarkjava_deep.json

python benchmarks/evaluate.py --dataset owasp-java \
  --ground-truth target/benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --findings target/benchmarks/benchmarkjava_deep.json \
  --mode deep \
  --output target/benchmarks/benchmarkjava_deep_report.md
```

## 关键改动

- 在 `core/src/scanner/mod.rs` 的 `ScanOptions` 中新增 `cross_file_max_flows: usize`，默认 `50000`。
- 当跨文件污点流超过上限时截断并告警，防止 full BenchmarkJava `--deep` 扫描直接内存分配失败崩溃。
- 同步在 CLI 与 MCP 的扫描入口构造 `ScanOptions` 时传入该字段。

## 指标汇总

### 2026-07-18 误报治理回归（当前版本）

跨文件语言域隔离、vendor 过滤、嵌入规则、likely_fp 参数评估、注释感知过滤后的回归结果（门禁：TP 不允许下降）：

| 模式 | Findings | TP | FP | FN | Precision | Recall | F1 |
|------|----------|----|----|----|-----------|--------|----|
| `--taint` | 2686 | 858 | 1828 | 557 | 0.319 | 0.606 | 0.418 |
| `--deep` | 3061 | 871 | 2190 | 544 | 0.285 | 0.616 | 0.389 |

与 2026-07-18 前基线对比：

- **TP 无回归**：taint 858 → 858（持平），deep 864 → 871（+7，recall +0.5pt），门禁通过。
- **BenchmarkJava 上 FP 基本持平**（taint −6，deep +82）：该数据集的 FP 主要是与 TP 代码形状一致的 Java 常量条件死代码，不是本轮治理的目标形态（注释命中、有界 printf、常量参数调用）。
- **真实项目收益**：ServerStatus（C++/Python/JS 混合）全严重度 finding 79 → 30（−62%），CRITICAL 28 → 1，且唯一真阳性（存储型 XSS）保留。

### 2026-07-17 重测（存档）

修复 Stage B 排除 bug、Java 字典、传播链断流、规则误报并补全 evaluate.py 映射后的结果：

| 模式 | Findings | TP | FP | FN | Precision | Recall | F1 |
|------|----------|----|----|----|-----------|--------|----|
| `--taint` | 2663 | 858 | 1834 | 557 | 0.319 | 0.606 | 0.418 |
| `--deep` | 2943 | 864 | 2108 | 551 | 0.291 | 0.611 | 0.394 |

按 CWE 拆分（Taint 模式）：

| CWE | TP | FP | FN | Precision | Recall | F1 |
|-----|----|----|----|-----------|--------|----|
| CWE-22 | 105 | 216 | 28 | 0.327 | 0.789 | 0.463 |
| CWE-78 | 33 | 192 | 93 | 0.147 | 0.262 | 0.188 |
| CWE-79 | 124 | 134 | 122 | 0.481 | 0.504 | 0.492 |
| CWE-89 | 194 | 167 | 78 | 0.537 | 0.713 | 0.613 |
| CWE-90 | 25 | 59 | 2 | 0.298 | 0.926 | 0.450 |
| CWE-327 | 130 | 102 | 0 | 0.560 | 1.000 | 0.718 |
| CWE-328 | 0 | 257 | 129 | 0.000 | 0.000 | 0.000 |
| CWE-330 | 218 | 566 | 0 | 0.278 | 1.000 | 0.435 |
| CWE-501 | 11 | 48 | 72 | 0.186 | 0.133 | 0.155 |
| CWE-614 | 3 | 31 | 33 | 0.088 | 0.083 | 0.086 |
| CWE-643 | 15 | 62 | 0 | 0.195 | 1.000 | 0.326 |

与旧基线相比的变化及原因：

- **CWE-90 召回 0 → 0.926**：`java_ldap` sink 字典修复（receiver 补 `idc` 等、`sensitive_params` 改 `[0,1]`）+ Stage B 排除修复 + if 分支 CFG 链式连接修复（`headers.nextElement()` receiver 传播）。
- **CWE-643 召回 0 → 1.000**：`java_xpath` 补 receiver `xp` + 净化器标识符边界匹配（`encodeBase64` 不再误判为 `encode` 净化器）+ evaluate.py 补 `xpath injection` 映射（此前 TP 被统计为 FP）。
- **CWE-330 召回 0.885 → 1.000 且规则 FP 104 → 0**：`insecure-random` Java 模式收窄为 `new Random(`/`Math.random(`。桶内剩余 566 FP 主要是 false 文件上的 debug-info-leak（275）与 TrustBoundary（274）输出，非 random 规则。
- **CWE-78 规则 FP 60 → 30**：`command-injection` 要求 `new ProcessBuilder(` 构造形式。剩余 FP 与 TP 代码形状一致（基准靠常量条件死代码区分），需污点引擎层治理。
- **CWE-501 / CWE-614 从 0 变为非零**：主要是 evaluate.py 补映射（`trust boundary violation` / `insecure cookie`）后显形，召回仍低（0.133 / 0.083），是后续字典方向。
- **CWE-328 仍为 0**：BenchmarkJava 的 hash 用例从 `benchmark.properties` 读算法名（`MessageDigest.getInstance(algorithm)`），属配置驱动弱点，静态污点本质上难覆盖，暂不投入。
- **Precision 略降（0.344 → 0.319）**：Stage B 排除修复后更多文件真正进入污点分析，总 findings 2113 → 2663，FP 绝对值随之上升；召回 +9.2pt 是主要收益。
- **`--deep` vs `--taint`**：TP +6（858 → 864）、FP +274，recall +0.5pt、precision −2.8pt。单文件主导数据集上跨文件增量价值仍有限，不建议作为默认模式。

### 2026-07-07 旧基线（v2.1.0，存档）

> 注意：旧基线测量时 Stage B 二次收集存在绝对路径排除 bug（target/ 下文件被跳过 AST 污点分析），且 evaluate.py 缺少 xpath/cookie/trustbound 映射，以下数字低估实际检出。

| 模式 | Findings | TP | FP | FN | Precision | Recall | F1 |
|------|----------|----|----|----|-----------|--------|----|
| `--taint` | 2113 | 727 | 1386 | 688 | 0.344 | 0.514 | 0.412 |
| `--deep` | 2163 | 727 | 1436 | 688 | 0.336 | 0.514 | 0.406 |

<details>
<summary>旧基线按 CWE 拆分（Deep 模式）</summary>

| CWE | TP | FP | FN | Precision | Recall | F1 |
|-----|----|----|----|-----------|--------|----|
| CWE-22 | 83 | 180 | 50 | 0.316 | 0.624 | 0.419 |
| CWE-78 | 33 | 210 | 93 | 0.136 | 0.262 | 0.179 |
| CWE-79 | 102 | 94 | 144 | 0.520 | 0.415 | 0.462 |
| CWE-89 | 186 | 133 | 86 | 0.583 | 0.684 | 0.629 |
| CWE-90 | 0 | 33 | 27 | 0.000 | 0.000 | 0.000 |
| CWE-327 | 130 | 72 | 0 | 0.644 | 1.000 | 0.783 |
| CWE-328 | 0 | 235 | 129 | 0.000 | 0.000 | 0.000 |
| CWE-330 | 193 | 385 | 25 | 0.334 | 0.885 | 0.485 |
| CWE-501 | 0 | 30 | 83 | 0.000 | 0.000 | 0.000 |
| CWE-614 | 0 | 23 | 36 | 0.000 | 0.000 | 0.000 |
| CWE-643 | 0 | 41 | 15 | 0.000 | 0.000 | 0.000 |

</details>

## Agent 审计基线

Agent 默认启用 Specialist、Investigator、Debate Reviewer，并在配置 API key 后调用真实 LLM。以下基线使用 `--min-severity high --no-auto-goal`，仅审计高严重度 finding 子集，因此 recall 以全量 ground truth 计算会显著低于引擎全量扫描。

```bash
# Noop Agent（规则判定）200 findings
./target/release/ctx-audit.exe config set agent.llm_mode noop
./target/release/ctx-audit.exe audit target/benchmarks/BenchmarkJava --agent --deep \
  --min-severity high --max-findings 200 --no-auto-goal \
  --output target/benchmarks/benchmarkjava_agent_noop_200.json

python benchmarks/evaluate.py --dataset owasp-java \
  --ground-truth target/benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --audit-log target/benchmarks/benchmarkjava_agent_noop_200_audit_log.json \
  --verdict-mode true_positive --mode agent_noop_200 \
  --output target/benchmarks/benchmarkjava_agent_noop_200_report.md

# LLM Agent（DeepSeek）100 findings
./target/release/ctx-audit.exe config set agent.llm_mode http
./target/release/ctx-audit.exe audit target/benchmarks/BenchmarkJava --agent --deep \
  --min-severity high --max-findings 100 --no-auto-goal \
  --output target/benchmarks/benchmarkjava_agent_llm_100.json

python benchmarks/evaluate.py --dataset owasp-java \
  --ground-truth target/benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --audit-log target/benchmarks/benchmarkjava_agent_llm_100_audit_log.json \
  --verdict-mode true_positive --mode agent_llm_100 \
  --output target/benchmarks/benchmarkjava_agent_llm_100_report.md

# LLM aggressive 模式（强制 LLM 判定高严重度 finding）
./target/release/ctx-audit.exe config set agent.llm_aggressive true
./target/release/ctx-audit.exe audit target/benchmarks/BenchmarkJava --agent --deep \
  --min-severity high --max-findings 100 --no-auto-goal --llm-aggressive \
  --output target/benchmarks/benchmarkjava_agent_llm_aggressive_v2_100.json

python benchmarks/evaluate.py --dataset owasp-java \
  --ground-truth target/benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --audit-log target/benchmarks/benchmarkjava_agent_llm_aggressive_v2_100_audit_log.json \
  --verdict-mode true_positive --mode agent_llm_aggressive_v2_100 \
  --output target/benchmarks/benchmarkjava_agent_llm_aggressive_v2_100_report.md

# Dual-Model Agent：fast 初筛 + pro 深度（30 findings 短验证）
./target/release/ctx-audit.exe config set agent.llm.model deepseek-v4-flash
./target/release/ctx-audit.exe config set agent.llm.model_pro deepseek-v4-pro
./target/release/ctx-audit.exe config set agent.triage_concurrency 32
rm -f target/benchmarks/BenchmarkJava/.ctx-audit/audit_log.json
./target/release/ctx-audit.exe audit target/benchmarks/BenchmarkJava --agent --deep \
  --min-severity high --max-findings 30 --no-auto-goal --llm-aggressive \
  --output target/benchmarks/benchmarkjava_agent_llm_dual_30.json

python benchmarks/evaluate.py --dataset owasp-java \
  --ground-truth target/benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --findings target/benchmarks/benchmarkjava_agent_llm_dual_30.json \
  --audit-log target/benchmarks/BenchmarkJava/.ctx-audit/audit_log.json \
  --verdict-mode true_positive --mode agent_llm_dual_30 \
  --output target/benchmarks/benchmarkjava_agent_llm_dual_30_report.md
```

### 指标对比

| 模式 | 调查数 | TP | FP | FN | Precision | Recall | F1 |
|------|--------|----|----|----|-----------|--------|----|
| `--taint`（全量引擎） | 2113 | 727 | 1386 | 688 | 0.344 | 0.514 | 0.412 |
| `--deep`（全量引擎） | 2163 | 727 | 1436 | 688 | 0.336 | 0.514 | 0.406 |
| Agent noop 200 | 200 | 131 | 67 | 1284 | **0.662** | 0.093 | 0.162 |
| Agent noop 100 | 100 | 68 | 30 | 1347 | **0.694** | 0.048 | 0.090 |
| Agent LLM 100 | 100 | 68 | 30 | 1347 | **0.694** | 0.048 | 0.090 |
| Agent LLM aggressive 100 | 100 | 67 | 42 | 1348 | **0.615** | 0.047 | 0.088 |
| Agent Dual-Model 30 | 30 | 21 | 2 | 1394 | **0.913** | 0.015 | 0.029 |

### 观察

- Agent 在高严重度子集上的 precision（~0.66-0.69）显著高于原始引擎（~0.34），说明 Specialist/Reviewer/Investigator 的过滤与证据校验有效抑制了误报。
- 由于只调查前 N 个高严重度 finding，recall 随 N 增加而上升（noop 200 的 recall 是 noop 100 的近 2 倍）。
- 在 100 finding 子集上，默认 LLM 判定结果与 noop 完全一致。原因是 `ControlledLlmClient` 对证据充分的高严重度 SQLi 直接走规则判定，未触发 LLM 调用；该子集以清晰 source→sink 路径为主，LLM 介入空间有限。
- 启用 `--llm-aggressive` 并提升调用预算（`max_llm_calls=5000`、`high=2000`）、限制调查步数（`max_investigation_steps=5`）后，真实 LLM 被强制调用（audit_log 中 100/100 出现 LLM 推理，无 Noop 回退）。但结果反而下降：precision 从 0.694 降至 **0.615**，FP 从 30 升至 42，TP 从 68 降至 67。说明当前 LLM prompt/调查工具链在该数据集上不仅未提升判定质量，还引入了额外误报。
- 主要失败点：Investigator 的 tool-use JSON 输出不稳定（大量 "LLM 响应未找到 JSON / JSON 解析失败" 回退到 `needs_review`），导致 LLM 无法有效利用工具收集证据；Reviewer debate 模式在证据不足时仍倾向于维持 `true_positive` 初审结论，未能有效抑制误报。
- 下一步若要真正释放 LLM 价值，应优先修复 Investigator 的 tool-use 输出格式与 tool 结果解析，而非单纯扩大调用预算或强制触发。
- **Dual-Model 短验证（30 findings）**：启用 `deepseek-v4-flash` 做 fast 初筛、`deepseek-v4-pro` 做深度判定，`triage_concurrency=32`。30 个高严重度 finding 中 audit_log 给出 24 TP / 1 FP / 5 needs_review，输出 JSON 经 ground truth 验证为 21 TP / 2 FP，precision 达到 **0.913**。由于样本量小且仅覆盖高严重度子集，recall 仍低；该结果主要说明主次模型路由可用，且在高严重度 SQLi 子集上保持较高 precision。要度量 cost/quality  trade-off，需后续补充 per-call 模型使用日志与更大规模（≥100 findings）的对比实验。

## 通用观察

- SQLi（CWE-89）与弱加密（CWE-327）召回率最高，是引擎当前最稳定的类别。
- 命令注入（CWE-78）、LDAP 注入（CWE-90）、哈希误用（CWE-328）、会话管理（CWE-614）、XPath 注入（CWE-643）等类别召回率为 0，主要因为当前 source/sink/sanitizer 字典未覆盖这些 Java 场景。
- Deep 模式相比 Taint 模式总 findings 略多，但 precision 略低，说明跨文件分析引入了额外误报，同时未显著提升召回（受上限截断与字典覆盖度双重限制）。
- `cross_file_max_flows = 50000` 的截断主要影响长尾高流用例，对整体 recall 未造成可观测下降（与 Taint 模式 recall 相同）。
