# CTX-Audit 3.1.1 Release Notes

## Overview

本版本聚焦 **C/C++ 语言支持与证据交付的完整性**。自 v3.1.0 以来，共 18 个文件变更、新增约 0.36 万行、删除约 0.02 万行。

核心变化：

- **C/C++ 符号索引补齐**：无关键字的"返回类型一行、函数名一行"定义形态、K&R 风格定义、`#define` 宏名；
- **切片交付"能支撑判定"的原文**：目标行之后的下探窗口、按标识符扩展到其使用处、附加窗口内标识符的声明行；
- **未解析的间接调用改为逐调用点计数**（此前按文件探测动态派发关键字，在 C 上恒为 0）；
- **条件编译进入证据层**：可证死的分支不再进入索引与证据；无法判定者如实标注；可选接入系统预处理器做真实分支求值，失败即降级并标注；
- **严重度降级开始留痕**（`severity_original` / `severity_downgraded_by`），并修正一条会把真阳性降级的假阳性判据。

## Highlights

- C/C++ 定义抽取：以 `universal-ctags` 为真值，在真实 C 代码库的 60 个定义抽样上由 **0.000 提升到 0.983**
- 声明与定义区分 **0.960**；调用点（去掉声明噪声后）精确率 **0.976** / 召回 **0.994**；callee **1.000 / 1.000**
- 切片新增字段：`forward`、`forward_max`、`forward_lines_returned`、`forward_bounded_by`、`forward_extended_for`、
  `is_after_target`、`declaration_for`
- 索引与切片统一跳过**可证死**的预处理分支；条件编译区逐行标注 `in_conditional_region`
- 可选预处理求值：`CTX_AUDIT_PREPROCESS`（默认单文件证据路径开启、整项目路径关闭），失败写 `preprocess_note`
- 文档：README / README_EN 改为**证据优先**主线，新增入库的 `rules/CUSTOM-RULES.md`，本仓库的 LLM 审计 Skill 指南同步重写
- 工程：CI 仓库元数据收口、测试矩阵扩展与安全扫描工作流修复；发布名称与说明改为由 tag 推导

## New Features

### C/C++ 语言支持

- 支持"返回类型一行、函数名顶格一行、`{` 再一行"的**无关键字**定义形态（旧实现依赖关键字门控，这类定义召回为 0）
- 支持 **K&R 风格**定义（参数类型声明在参数表之后），并**按语言门控**：仅在 C/C++ 类文件上容忍该形态
- `#define` 对象宏/函数宏名纳入索引
- 声明与定义分离：`.h` 原型与 `.c` 定义不再互相冒充

### 切片与证据交付

- **前向窗口**：在目标行之后下探（`forward`，默认 8），上界取"目标行 + 下探、所在函数体末行、文件末行"三者最小值，不越过函数体
- **标识符驱动扩展**：目标行上的标识符在窗口之外还有使用时，窗口扩展到**最后一处**使用（`forward_max`，默认 64）；`forward: 0` 保持纯后向
- **窗口内标识符的声明行**一并交付并标注 `declaration_for`（目标行标识符优先，其次窗口内重复出现者）——只交付原文，不做推断
- 切片响应新增 `scope_anchor`、`content_source` 与上述字段，并在 `uncertainty` 中说明窗口为何变宽

### 条件编译视图

- 行级判据：`#if 0`（及 `#elif 0` 且前面没有可证为真的分支）判为**可证死**；`#else` 保守视为活；`#ifdef` / `#if defined(...)` 一律不判死，只标 `conditional`
- 索引跳过可证死行（死代码既不定义符号也不计引用）；切片、守卫、框架上下文、数据流路径与调用点扫描一律过滤未激活分支
- 可选真实分支求值：以探针宏标记条件编译区内的代码行，再在系统预处理器的输出中查找对应标记；
  失败（无 `cpp`、include 解析不了）时降级为行级判据，并在 `preprocess_note` 与 `uncertainty` 中如实标注

## Performance & Efficiency

### 索引与缓存

- 显式点名的文件按需读盘，不再受批量索引的文件大小/数量上限连坐
- 目录遍历排序（广度优先 + 输出按路径排序），消除跨机器不确定的文件子集
- 索引磁盘缓存键纳入**索引逻辑版本**与 crate 版本：升级后不会命中旧规则生成的缓存
- 空结果分类：`empty_kind`（`no_match` / `index_miss` / `definition_only`）替代裸的 0
- 结果上限统一上报：守卫与框架上下文补齐 `total_hits` / `limit` / `truncated_at_limit`

## Reliability & Stability

### 严重度与假阳性控制

- 修正 `printf` 族"格式串为字面量且无 `%s` ⇒ 输出有界"的降级判据：宽度说明符与整数精度都是**最小值**，
  只有"每个转换都有编译期上界"（纯字面量、`%%`、`%c`、带显式精度的 `%s`）才判有界
- 降级留痕：finding 新增 `severity_original` 与 `severity_downgraded_by`（空值不输出），调用方按严重度过滤时
  可看出"曾有一条更高级别的候选被降下来、以及为什么"

### 调用点与未解析边

- 调用点判定：非 C 语言的调用点不再把目标函数自身的定义行算作调用者；C 语言调用点限定在函数体内
- 未解析间接调用：由"按文件探测动态派发关键字"改为**按调用点**统计（`p->member(`、`(*fp)(`、`table[i](`），与查询方向无关

## Bug Fixes

- 修复未配对引号导致其后整段代码被清空（定义与引用随之漏收）
- 修复长函数与"目标行本身是函数头"的作用域解析失败，退化为非声明锚点
- 修复匿名函数表达式（对象属性函数/箭头函数）解析不出所属函数
- 修复 C 运算符被当成被调函数（`sizeof` / `_Alignof` / `offsetof` / `typeof` / `va_*`）
- 修复 C 风格定义与未加空格的 `function(` 形态未识别
- 修复"函数指针 typedef"被兜底正则当成函数定义，导致 finding 的函数归属错误
- 修复切片缺失函数头、函数体范围在跨行签名处截断
- 修复符号遍历与赋值遍历在深层嵌套输入上的栈溢出
- 修复超大匹配下 finding 结束行被写成字节偏移
- 修复调用图与切片因结果上限缺省而静默丢结果
- 修复同一轮内"先写文件再刷新索引"看不到新文件的间歇失败

## Validation

- `cargo build --workspace` ✅
- `cargo test --workspace` ✅（core 419 / tools 88 / agent 71 / daemon 20 / cli 22 + 集成 5，0 失败）
- ground-truth 夹具回归门：相对基线无回退 ✅
- C 语言基线（ctags / cscope / `gcc -M` 真值口径）：定义、调用点、声明-定义分离、TU 闭包等轴不回退 ✅
- 受控对照（同一脚本、同一样本、新旧二进制）覆盖：切片契约、调用点过滤、未解析边计数、条件编译视图 ✅

## Installation

```bash
# 构建
cargo build --release

# 或安装到本机
cargo install --path cli --locked

# LLM 协作审计（推荐）：启动 MCP Server
ctx-audit mcp

# 需要遗留细粒度工具面时
ctx-audit mcp --legacy-tools
```

## Upgrade Notes from v3.1.0

- 版本号统一升至 3.1.1（`cli` / `tools` / `daemon` / `agent` / `deepaudit-core` 均继承 workspace 版本）
- 新增环境变量 `CTX_AUDIT_PREPROCESS`：`1` 全局启用预处理求值、`0` 全局关闭；不设置时仅单文件证据路径启用
- finding 新增 `severity_original` 与 `severity_downgraded_by`；空值不序列化，消费方可忽略未知字段
- `slice_backward` 响应新增 `forward` / `forward_max` / `forward_lines_returned` / `forward_bounded_by` /
  `forward_extended_for` / `declaration_for` / `in_conditional_region` / `preprocess_note`
- `get_symbol_definition` 的空结果现在带 `empty_kind`；`unresolved_edges` 在 C 语言上不再是恒 0
- 索引缓存键包含逻辑版本，升级后首次查询会重建索引（属预期行为）
