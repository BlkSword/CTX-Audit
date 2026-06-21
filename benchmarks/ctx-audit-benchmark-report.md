# CTX-Audit 客观基准测试报告

> 生成时间：2026-06-21  
> 测试版本：`ctx-audit` release build（commit 基于当前工作区）  
> 测试原则：不对结果做人为挑选，真实反映工具在当前代码/规则下的检测能力。

## 1. 测试环境

| 配置项 | 值 |
|--------|-----|
| CLI | `target/release/ctx-audit.exe` |
| 规则目录 | `rules/`（含 `rules/taint/generic-taint.yaml` 与 `rules/taint/frameworks/*.yaml`） |
| 最低严重程度 | `low` |
| 包含测试文件 | `true` |
| 排除目录 | `node_modules,.git,build,dist`（注意：默认的 `target` 被移除，否则数据集在 `target/` 下会被整体跳过） |
| Taint 候选文件上限 | 5000（原硬编码 200 已放宽，否则无法覆盖 OWASP Java 全部 2740 个文件） |
| Taint 单文件大小上限 | 500 KB（原 100 KB） |

关键配置命令：

```bash
ctx-audit config set scan.include_tests true
ctx-audit config set scan.min_severity low
ctx-audit config set scan.exclude_patterns '["node_modules",".git","build","dist"]'
```

## 2. 数据集

### 2.1 OWASP Benchmark Java v1.2

- 路径：`target/benchmarks/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode`
- 文件数：2740 个 `.java`
- 真值：`expectedresults-1.2.csv`，按文件粒度标记 `category / real vulnerability / CWE`
- 类别分布（部分）：sqli(504)、weakrand(493)、xss(455)、pathtraver(268)、cmdi(251)、crypto(246)、hash(236)、trustbound(126)、securecookie(67)、ldapi(59)、xpathi(35)

### 2.2 NIST Juliet C/C++ v1.3（抽样）

Juliet C/C++ 全集约 10.1 万个文件，完整跑完不可行，因此抽取与当前规则覆盖最相关的三类进行客观评估：

| 类别 | 子目录 | 文件数 |
|------|--------|--------|
| CWE-121 Stack Based Buffer Overflow | `s01`, `s02` | ~1811 |
| CWE-122 Heap Based Buffer Overflow | `s01`, `s02` | ~1894 |
| CWE-134 Uncontrolled Format String | `s01`, `s02` | ~1772 |
| **合计** | | **5477** |

- 真值：`target/benchmarks/JulietCpp/C/manifest.xml`，按 `<flaw line=... name="CWE-xxx"/>` 标记
- 评估时行号容差 `line_tol = 3`
- 报告中的整体指标已按 CWE-121/122/134 过滤，避免未抽样类别的巨大 FN 拉低整体 recall

## 3. 扫描命令

```bash
# OWASP Java - 三种模式
ctx-audit scan --min-severity low \
  target/benchmarks/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
  -o target/tmp/bench_java_default.json

ctx-audit scan --min-severity low --taint --threads 8 \
  target/benchmarks/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
  -o target/tmp/bench_java_taint.json

ctx-audit scan --min-severity low --deep --threads 8 \
  target/benchmarks/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
  -o target/tmp/bench_java_deep.json

# Juliet C/C++ - 三种模式（在 target/tmp/juliet_sample 抽样目录上）
ctx-audit scan --min-severity low target/tmp/juliet_sample -o target/tmp/bench_juliet_default.json
ctx-audit scan --min-severity low --taint --threads 8 target/tmp/juliet_sample -o target/tmp/bench_juliet_taint.json
ctx-audit scan --min-severity low --deep --threads 8 target/tmp/juliet_sample -o target/tmp/bench_juliet_deep.json
```

评估脚本：

```bash
python benchmarks/evaluate.py --dataset owasp-java \
  --ground-truth target/benchmarks/BenchmarkJava/expectedresults-1.2.csv \
  --findings target/tmp/bench_java_<mode>.json --mode <mode>

python benchmarks/evaluate.py --dataset juliet-cpp \
  --ground-truth target/benchmarks/JulietCpp/C/manifest.xml \
  --findings target/tmp/bench_juliet_<mode>.json --mode <mode> \
  --line-tol 3 --cwe-filter 121,122,134
```

## 4. OWASP Java 结果

### 4.1 整体指标

| 模式 | 检出数 | TP | FP | FN | Precision | Recall | F1 |
|------|--------|----|----|----|-----------|--------|-----|
| default | 1483 | 199 | 672 | 1216 | 0.228 | 0.141 | 0.174 |
| taint | 1632 | 269 | 734 | 1146 | 0.268 | 0.190 | 0.222 |
| deep | 1632 | 269 | 734 | 1146 | 0.268 | 0.190 | 0.222 |

### 4.2 分 CWE 指标（taint 模式，最具代表性的模式）

| CWE | 类别 | TP | FP | FN | Precision | Recall | F1 |
|-----|------|----|----|----|-----------|--------|-----|
| CWE-22 | Path Traversal | 18 | 34 | 115 | 0.346 | 0.135 | 0.195 |
| CWE-78 | Command Injection | 33 | 85 | 93 | 0.280 | 0.262 | 0.270 |
| CWE-79 | XSS | 0 | 0 | 246 | 0.000 | 0.000 | 0.000 |
| CWE-89 | SQL Injection | 52 | 64 | 220 | 0.448 | 0.191 | 0.268 |
| CWE-90 | LDAP Injection | 0 | 2 | 27 | 0.000 | 0.000 | 0.000 |
| CWE-327 | Weak Crypto | 130 | 22 | 0 | 0.855 | 1.000 | 0.922 |
| CWE-328 | Weak Hash | 0 | 24 | 129 | 0.000 | 0.000 | 0.000 |
| CWE-330 | Insecure Random | 0 | 411 | 218 | 0.000 | 0.000 | 0.000 |
| CWE-501 | Trust Boundary | 0 | 10 | 83 | 0.000 | 0.000 | 0.000 |
| CWE-614 | Secure Cookie | 36 | 39 | 0 | 0.480 | 1.000 | 0.649 |
| CWE-643 | XPath Injection | 0 | 43 | 15 | 0.000 | 0.000 | 0.000 |

### 4.3 主要观察

- **检测能力较强的类别**：`crypto`（CWE-327）和 `securecookie`（CWE-614）召回率达到 1.0，说明规则/AST 规则对固定模式（如弱算法、缺少 `Secure`/`HttpOnly` 标志）识别较好。
- **污点分析带来的提升**：`taint`/`deep` 相比 `default` 在 `CWE-89`（SQLi）和 `CWE-22`（Path Traversal）上新增了 TP，但 F1 仍偏低。
- **召回率极低的类别**：`XSS`（CWE-79）、`Weak Hash`（CWE-328）、`Insecure Random`（CWE-330）、`LDAP`（CWE-90）、`XPath`（CWE-643）几乎没有真正命中。
- **误报集中点**：`CWE-330` 产生 411 个 FP，工具把大量非漏洞的随机数使用误判为不安全；`CWE-78` 也有较高 FP。
- **deep 模式无额外收益**：与 taint 模式结果完全相同，跨文件分析在本次单文件主导的数据集上没有带来新发现。

## 5. Juliet C/C++ 抽样结果

### 5.1 整体指标（限制在 CWE-121/122/134）

| 模式 | 检出数 | TP | FP | FN | Precision | Recall | F1 |
|------|--------|----|----|----|-----------|--------|-----|
| default | 6586 | 1288 | 1117 | 22307 | 0.536 | 0.055 | 0.099 |
| taint | 6586 | 1285 | 1117 | 22310 | 0.535 | 0.054 | 0.099 |
| deep | 6586 | 1286 | 1117 | 22309 | 0.535 | 0.055 | 0.099 |

### 5.2 分 CWE 指标（default 模式）

| CWE | TP | FP | FN | Precision | Recall | F1 |
|-----|----|----|----|-----------|--------|-----|
| CWE-121 | 105 | 0 | 8072 | 1.000 | 0.013 | 0.025 |
| CWE-122 | 64 | 0 | 10194 | 1.000 | 0.006 | 0.012 |
| CWE-134 | 1119 | 1117 | 4041 | 0.500 | 0.217 | 0.303 |

### 5.3 主要观察

- **Buffer Overflow（CWE-121/122）**：精度极高（1.0），但召回率极低（~0.01）。工具只在少数文件上触发了与真值行号对齐的检测，绝大多数 flaw 行未被报告。
- **Format String（CWE-134）**：召回率 0.217，但精度仅 0.5，大量 good 文件上的 `printf`/`fprintf`/`vsnprintf` 等被误报。
- **Taint/Deep 没有显著改善**：与 default 模式几乎一致，说明当前 C/C++ 的检测仍以规则/AST 模式匹配为主，污点传播路径尚未有效提升覆盖。

## 6. 关键发现与建议

1. **默认排除 `target` 目录会误伤放在 `target/` 下的基准数据集**  
   这是本次测试最初得到 0 检出的根因之一。已在配置中显式移除 `target`，建议在后续测试/CI 中注意此默认行为。

2. **Taint 候选文件/大小限制过严**  
   原 `MAX_CANDIDATE_FILES=200`、`MAX_TAINT_FILE_KB=100` 会导致全量 OWASP Java 只能进入 200 个文件分析。已临时放宽到 5000/500 KB，若作为产品默认值需谨慎评估内存/性能。

3. **规则覆盖不平衡**  
   - Java：`crypto`、`securecookie` 表现好；`XSS`、`weak hash`、`insecure random`、`LDAP`、`XPath` 几乎无法检出。
   - C/C++：`printf` 家族规则过于宽泛，导致 Format String 误报高；Buffer Overflow 规则覆盖不足，召回率低。

4. **跨文件分析未生效**  
   `deep` 模式与 `taint` 模式在两类数据集上结果一致，说明当前 cross-file 组件对这类单文件测试用例没有额外贡献。

5. **建议后续优化方向**  
   - 为 Java 补充 `XSS`、`LDAP`、`XPath`、`weak hash/random` 的专用 sink/source 规则。
   - 细化 C/C++ Buffer Overflow 的触发条件（如结合数组大小与源长度），减少漏报。
   - 细化 Format String 规则，区分可控格式字符串与硬编码格式字符串，降低 FP。
   - 评估 `deep` 模式在真实多文件项目上的价值，并修复其在本基准中零额外发现的问题。

## 7. 数据产物

所有原始结果保存在 `target/tmp/`：

```
target/tmp/bench_java_default.json
target/tmp/bench_java_taint.json
target/tmp/bench_java_deep.json
target/tmp/bench_juliet_default.json
target/tmp/bench_juliet_taint.json
target/tmp/bench_juliet_deep.json
target/tmp/report_java_*.md
target/tmp/report_juliet_*.md
```

## 8. 限制说明

- Juliet 评估基于抽样（CWE-121/122/134 的 s01/s02），不能代表整个 Juliet 全集。
- 评估按“文件+行号+CWE”对齐，对跨多行的复杂 flaw 可能存在容差内匹配偏差。
- 工具输出中部分发现的 `vuln_type` 为通用名称，已按 `benchmarks/evaluate.py` 中的映射表归一化到 CWE；若映射不全，可能导致 TP 被计入 FP/FN。
- 本次测试未对规则做针对性调优，结果反映的是当前代码与规则状态。
