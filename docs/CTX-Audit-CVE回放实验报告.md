# CTX-Audit CVE 回放实验报告

> 2026-07-19，基于 Uptime Kuma 5 个 CVE 的回放实验 + 24 项目大规模扫描的交叉分析

---

## 1. 实验背景

**问题**：24 个活跃项目全量扫描 = 0 TP。引擎有问题还是项目选错了？

**实验设计**：回放活跃项目的历史 CVE——在漏洞版本上扫描，观察引擎能否检出。如果能，说明 0 TP 是因为扫了最新版而非引擎能力不足；如果不能，归因到具体引擎层。

**被试**：Uptime Kuma（活跃项目，JS 技术栈，有 10+ 公开安全公告，已有 R2 字典基础）

---

## 2. 实验结果

| # | CVE / GHSA | 类型 | 检出 | 归因 |
|---|-----------|------|------|------|
| 1 | GHSA-vffh-c9pq-4crh | SSTI (Liquid template injection) | ✅ | 字典缺失→补后检出 |
| 2 | GHSA-v832-4r73-wx5j | SSTI (同根因变体) | ✅ | 同上 |
| 3 | GHSA-5px6-fx2w-459r | Path Traversal (socket) | ❌ | Socket 内联回调数据流追踪限制 |
| 4 | GHSA-2qgm-m29m-cj2h | LFI (Puppeteer) | ❌ | 运行时浏览器行为，非代码 pattern |
| 5 | GHSA-qjxc-h5jf-c7rj | SSRF (cloud metadata) | ❌ | 设计级 SSRF，监控功能本身就是发 HTTP 请求 |

**检出率：40%（2/5）。**

---

## 3. 不可检出的三类 CVE

继续在 NVD/GitHub Advisory 中翻活跃项目的 CVE 会陷入循环，因为大部分属于以下三类，不在静态 pattern 匹配的能力域：

### 3.1 框架内部 bug

Express `res.redirect()` XSS (CVE-2024-43796)——Express 自身没对 Location 头做 HTML 编码。修复在 Express 源码一行 `encodeURI()`。应用代码里 `res.redirect(userUrl)` 的调用模式完全正确，没有任何可检测的 pattern 错误。

**类比**：门锁设计有缺陷，但安装正确、使用正确。问题在锁厂。

### 3.2 运行时问题

Redis Lua sandbox escape (CVE-2022-0543)——`EVAL` 是合法 Redis 命令，静态分析无法区分正常 Lua 脚本和恶意 payload。防御靠运行时 sandbox，不是代码 shape。

**类比**：刀可以切菜也可以伤人，静态分析只能看到"使用了刀"。

### 3.3 设计级缺陷

Uptime Kuma cloud metadata SSRF (GHSA-qjxc-h5jf-c7rj)——监控功能设计上就要发 HTTP 请求。攻击者设 URL 为 `169.254.169.254` 读云 metadata，代码和执行 `https://google.com` 完全一样——都是 `axios.get(url)`。区别在设计意图，不在代码形状。

**类比**：GPS 只能看到"车辆行驶"，分不清去超市还是抢银行。

### 3.4 架构限制

Socket/WebSocket 事件回调中的 inline 匿名函数——参数来自网络事件（非 HTTP request），CTX-Audit 的 taint tracker 无法追踪内联箭头函数的数据流。这是引擎架构层面的限制，不是字典问题。

---

## 4. 引擎真实能力域

| 能力层 | 可检测 | 不可检测 |
|--------|--------|---------|
| **Regex 规则** | 危险函数调用（eval/exec/system/open/sprintf） | 函数调用的**上下文是否安全** |
| **AST 污点** | HTTP request → 变量 → sink 的单文件数据流 | 跨文件、内联回调、WebSocket 参数 |
| **跨文件分析** | 有名函数的跨文件调用链 | 内联匿名函数、动态 import、运行时沙箱 |
| **字典/规则** | 已知 sink 的 pattern 匹配 | 新 sink 类型（字典未覆盖 → 可补），设计级/运行时漏洞（字典无法覆盖） |

**架构结论**：引擎能覆盖约 50-60% 的 CWE 类别（与业界静态工具同量级）。差异化不在覆盖率，在于判定质量（证据链 + LLM 压低 FP 率）。架构方向正确，不需要换架构。

---

## 5. 字典 vs LLM 的关系

```
召回（字典） → 决定 LLM 能看到什么
判定（LLM） → 决定候选变成什么交付物
```

- **字典补了才有素材**：Uptime Kuma SSTI 的 `engine.parse()` 最初不检测，补了字典后立刻检出。
- **LLM 判了才有 TP**：同样 52 个候选，纯静态交付 52 条"漏洞"（51 条噪声）；LLM 协作交付 1 个完整攻击链 TP + 51 条有据可查的排除记录。
- **LLM 独有判定域**："这是脱敏代码不是密码"、"这个 webhook 是管理员设计内行为"——语义判断，不是模式匹配。

---

## 6. 累计字典（本阶段产出）

| 规则 | 覆盖 | 来源 |
|------|------|------|
| `code-injection.yaml` 增强 | `engine.parse`, `ejs.compile`, `Handlebars.compile` | Uptime Kuma SSTI CVE |
| `express-node.yaml` 增强 | `socket.on` WebSocket taint source | Uptime Kuma Path Traversal CVE |
| `nosql-injection.yaml` | MongoDB `$gt/$ne/$where` 操作符注入 | 字典补充 |
| `orm-field-injection.yaml` | Django `order_by(request.)` / JPA CriteriaBuilder | 字典补充 |
| `xxe-injection.yaml` | etree/DocumentBuilder 不安全 XML 解析 | 字典补充 |
| `sql-orderby-injection.yaml` | 5 语言 ORDER BY 标识符注入 | 字典补充 |
| `sql-second-order-injection.yaml` | DB 读出的数据拼入新 SQL | 字典补充 |

---

## 7. 建议

1. **停止在 NVD 里翻 CVE 做回放**——大部分是框架 bug / 运行时 / 设计缺陷，对字典反哺效率递减
2. **用现有字典扫"活但弱"项目**——字典已经 7 项增强，需要在实际项目上验证能否产出新 TP
3. **LLM 判定流程产品化需更多素材**——当前 4 个 TP 不够支撑系统化，先攒证据再产品化
