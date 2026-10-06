# CTX-Audit 自定义规则编写指南

本指南面向规则作者与使用者，说明两类自定义 YAML 规则的写法、放置位置与校验方式。

> 规则语料在引擎里的定位是**候选种子与回归基线**，不是漏洞结论：命中只代表"这里值得看一眼"，
> 判定由 LLM/人工在证据之上完成。语料定位与冻结约定见 [README.md](README.md)。

---

## 1. 两类规则

| 类型 | 作用 | 放置位置 |
|---|---|---|
| **Pattern Rules（模式规则）** | 正则 / tree-sitter query 匹配，快速召回固定风险模式 | `rules/*.yaml` 或 `<项目>/.ctx-audit/rules/*.yaml` |
| **Taint Rules（污点规则）** | 定义 source / sink / sanitizer，驱动 AST 污点分析与跨文件追踪 | `rules/taint/` 或 `<项目>/.ctx-audit/rules/taint/` |

## 2. 放置位置与优先级

```text
--rules 参数  >  <项目>/.ctx-audit/rules/  >  内置 rules/
```

项目级规则目录适合放"只对本项目有意义"的判据；同目录下所有 `.yaml` / `.yml` 都会被加载。
守护进程模式下规则目录每 30 秒自动检测变更并热加载。

---

## 3. Pattern Rules

### 3.1 单条规则

```yaml
id: my-custom-rule
name: My Custom Rule
description: 检测某个特定的代码模式
severity: high
language: python
pattern: "(?i)(dangerous_function\\s*\\()"
category: injection
cwe: CWE-123
owasp: "A03:2021-Injection"
remediation: "使用安全的替代函数 xxx"
references:
  - "https://example.com/docs"
```

### 3.2 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | 规则唯一标识（kebab-case，如 `sql-injection`） |
| `name` | string | 是 | 规则显示名称 |
| `description` | string | 是 | 规则描述（中文或英文） |
| `severity` | enum | 是 | `critical` / `high` / `medium` / `low` / `info` |
| `language` | string | 是 | `python` / `javascript` / `typescript` / `java` / `rust` / `go` / `php` / `ruby` / `c` / `cpp` / `all` |
| `pattern` | string | 否* | 单一正则表达式（所有语言通用） |
| `patterns` | array | 否* | 多语言模式列表（优先于 `pattern`） |
| `query` | string | 否 | tree-sitter 查询语句（优先级最高） |
| `category` | string | 否 | 漏洞类别（如 `injection`、`xss`、`auth`） |
| `cwe` | string | 否 | CWE 编号（如 `CWE-89`） |
| `owasp` | string | 否 | OWASP Top 10 映射（如 `"A03:2021-Injection"`） |
| `remediation` | string | 否 | 修复建议 |
| `references` | array | 否 | 参考链接列表 |

> *`pattern` 与 `patterns` 至少提供一个。

### 3.3 多语言模式

不同语言模式不同时，用 `patterns` 替代 `pattern`：

```yaml
id: command-injection
name: Command Injection Detection
description: 检测命令注入风险
severity: critical
language: all
category: injection
cwe: CWE-78
owasp: "A03:2021-Injection"
patterns:
  - language: python
    pattern: "(?i)(subprocess\\.(call|run|Popen)\\s*\\(|os\\.system\\s*\\()"
  - language: javascript
    pattern: "(?i)(child_process\\.exec\\s*\\(|child_process\\.spawn\\s*\\()"
  - language: java
    pattern: "(?i)(Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(|ProcessBuilder\\s*\\()"
  - language: php
    pattern: "(?i)(shell_exec\\s*\\(|passthru\\s*\\(|system\\s*\\()"
  - language: ruby
    pattern: "(?i)(system\\s*\\(|exec\\s*\\(|`[^`]+`)"
```

### 3.4 规则集（一个文件多条规则）

```yaml
name: My Security Rules
version: "1.0"
rules:
  - id: rule-1
    name: First Rule
    description: ...
    severity: high
    language: python
    pattern: "..."

  - id: rule-2
    name: Second Rule
    description: ...
    severity: medium
    language: javascript
    pattern: "..."
```

---

## 4. Taint Rules

### 4.1 格式

```yaml
kind: taint-rules
name: "My Taint Rules"
version: "1.0"

sources:
  - id: "my_http_source"
    name: "HTTP Request"
    description: "HTTP 请求参数"
    patterns:
      - "request.args"
      - "req.query"
      - "$_GET"
    languages: ["*"]
    severity: "High"
    category: "UserInput"

sinks:
  - id: "my_sql_sink"
    name: "SQL Execution"
    description: "SQL 查询执行"
    patterns:
      - ".execute("
      - "cursor.execute"
      - "db.query"
    languages: ["*"]
    vulnerability_type: "SqlInjection"
    severity: "Critical"
    cwe_id: "CWE-89"

sanitizers:
  - pattern: "escape"
    description: "通用转义函数"
  - pattern: "sanitize"
    description: "通用净化函数"
  - pattern: "htmlspecialchars"
    description: "HTML 实体编码"
```

### 4.2 Source 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | 唯一标识 |
| `name` | string | 是 | 显示名称 |
| `description` | string | 否 | 描述 |
| `patterns` | string[] | 是 | 匹配模式列表（包含匹配） |
| `languages` | string[] | 否 | 语言列表（`["*"]` 表示所有语言） |
| `severity` | enum | 否 | `Critical` / `High` / `Medium` / `Low` / `Info` |
| `category` | string | 否 | 类别标签 |

### 4.3 Sink 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | 唯一标识 |
| `name` | string | 是 | 显示名称 |
| `description` | string | 否 | 描述 |
| `patterns` | string[] | 是 | 匹配模式列表 |
| `languages` | string[] | 否 | 语言列表 |
| `vulnerability_type` | enum | 是 | 漏洞类型（见下） |
| `severity` | enum | 否 | 严重程度 |
| `cwe_id` | string | 否 | CWE 编号 |

**`vulnerability_type` 枚举**：

- `SqlInjection` — SQL 注入
- `CommandInjection` — 命令注入
- `CrossSiteScripting` — 跨站脚本（XSS）
- `PathTraversal` — 路径遍历
- `ServerSideRequestForgery` — 服务端请求伪造（SSRF）
- `CodeInjection` — 代码注入
- `InsecureDeserialization` — 不安全反序列化
- `Generic` — 通用

### 4.4 Sanitizer 字段

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `pattern` | string | 是 | 匹配模式（函数名片段，包含匹配） |
| `description` | string | 否 | 描述 |

---

## 5. 校验与运行

```bash
# 列出已加载规则（含自定义目录）
ctx-audit rules list -r .ctx-audit/rules

# 校验规则目录下的 YAML
ctx-audit rules validate -r .ctx-audit/rules

# 用自定义规则扫描
ctx-audit scan ./myproject --rules .ctx-audit/rules

# 连污点/跨文件一起跑
ctx-audit scan ./myproject --rules .ctx-audit/rules --deep
```

内置规则位于 `rules/`，可直接作为编写参考。

---

## 6. 注意事项

- **匹配方式**：`patterns` 使用包含匹配（`str.contains()`），不必写完整匹配的正则。
- **Source 匹配**：对代码行中出现的字符串做包含匹配。
- **Sink 匹配**：匹配函数调用表达式中的函数名。
- **Sanitizer 匹配**：匹配函数名中包含的片段。
- **多规则文件**：同目录下所有 `.yaml` / `.yml` 均被加载，同名规则会合并。
- **热加载**：守护进程模式下规则目录每 30 秒检测变更。
- **描述文案面向使用者**：写清"为什么存在这条判据"，不要写内部编号、里程碑代号、被审计项目名或机器信息。
- **优先固化机制而非堆规则**：一次真实误报/漏报更适合先变成回归用例，再由测试驱动修改既有规则；
  能沉到引擎机制层的判据，不要继续以规则形式叠加（见 [README.md](README.md) 的冻结约定）。
