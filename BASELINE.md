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

| 模式 | Findings | TP | FP | FN | Precision | Recall | F1 |
|------|----------|----|----|----|-----------|--------|----|
| `--taint` | 2113 | 727 | 1386 | 688 | 0.344 | 0.514 | 0.412 |
| `--deep` | 2163 | 727 | 1436 | 688 | 0.336 | 0.514 | 0.406 |

## 按 CWE 拆分（Deep 模式）

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

### 观察

- Agent 在高严重度子集上的 precision（~0.66-0.69）显著高于原始引擎（~0.34），说明 Specialist/Reviewer/Investigator 的过滤与证据校验有效抑制了误报。
- 由于只调查前 N 个高严重度 finding，recall 随 N 增加而上升（noop 200 的 recall 是 noop 100 的近 2 倍）。
- 在 100 finding 子集上，默认 LLM 判定结果与 noop 完全一致。原因是 `ControlledLlmClient` 对证据充分的高严重度 SQLi 直接走规则判定，未触发 LLM 调用；该子集以清晰 source→sink 路径为主，LLM 介入空间有限。
- 启用 `--llm-aggressive` 并提升调用预算（`max_llm_calls=5000`、`high=2000`）、限制调查步数（`max_investigation_steps=5`）后，真实 LLM 被强制调用（audit_log 中 100/100 出现 LLM 推理，无 Noop 回退）。但结果反而下降：precision 从 0.694 降至 **0.615**，FP 从 30 升至 42，TP 从 68 降至 67。说明当前 LLM prompt/调查工具链在该数据集上不仅未提升判定质量，还引入了额外误报。
- 主要失败点：Investigator 的 tool-use JSON 输出不稳定（大量 "LLM 响应未找到 JSON / JSON 解析失败" 回退到 `needs_review`），导致 LLM 无法有效利用工具收集证据；Reviewer debate 模式在证据不足时仍倾向于维持 `true_positive` 初审结论，未能有效抑制误报。
- 下一步若要真正释放 LLM 价值，应优先修复 Investigator 的 tool-use 输出格式与 tool 结果解析，而非单纯扩大调用预算或强制触发。

## 通用观察

- SQLi（CWE-89）与弱加密（CWE-327）召回率最高，是引擎当前最稳定的类别。
- 命令注入（CWE-78）、LDAP 注入（CWE-90）、哈希误用（CWE-328）、会话管理（CWE-614）、XPath 注入（CWE-643）等类别召回率为 0，主要因为当前 source/sink/sanitizer 字典未覆盖这些 Java 场景。
- Deep 模式相比 Taint 模式总 findings 略多，但 precision 略低，说明跨文件分析引入了额外误报，同时未显著提升召回（受上限截断与字典覆盖度双重限制）。
- `cross_file_max_flows = 50000` 的截断主要影响长尾高流用例，对整体 recall 未造成可观测下降（与 Taint 模式 recall 相同）。
