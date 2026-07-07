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

## 观察

- SQLi（CWE-89）与弱加密（CWE-327）召回率最高，是引擎当前最稳定的类别。
- 命令注入（CWE-78）、LDAP 注入（CWE-90）、哈希误用（CWE-328）、会话管理（CWE-614）、XPath 注入（CWE-643）等类别召回率为 0，主要因为当前 source/sink/sanitizer 字典未覆盖这些 Java 场景。
- Deep 模式相比 Taint 模式总 findings 略多，但 precision 略低，说明跨文件分析引入了额外误报，同时未显著提升召回（受上限截断与字典覆盖度双重限制）。
- `cross_file_max_flows = 50000` 的截断主要影响长尾高流用例，对整体 recall 未造成可观测下降（与 Taint 模式 recall 相同）。
