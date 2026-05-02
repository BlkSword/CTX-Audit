# CTX-Audit 开发路线图

> 当前版本：v0.2.0-stable | 更新时间：2026-05-02

---

## 当前状态评估

| 维度 | 状态 | 评分 |
|------|------|------|
| AST 污点分析 | 基础可用，支持 12 语言 | ★★★☆☆ |
| 模式匹配规则 | 28 条规则，覆盖主流注入类型 | ★★★☆☆ |
| SCA 扫描 | OSV API 集成，4 个生态 | ★★★☆☆ |
| 守护进程 | 增量缓存 + TCP IPC | ★★★★☆ |
| 测试覆盖 | 93 个单元测试，无集成测试 | ★★☆☆☆ |
| 文档 | README 仅覆盖使用说明 | ★★☆☆☆ |

---

## P0：稳定性与质量（1-2 周）

> 目标：让 daemon 达到生产可用级别

### 0.1 守护进程健壮性

- [x] **自动重连**：client.rs 添加指数退避重连逻辑，daemon 崩溃后 CLI 自动恢复
- [x] **心跳检测**：daemon 定期写心跳文件，CLI 检测 daemon 存活状态
- [x] **优雅降级**：`--daemon` 模式连接失败时，自动 fallback 到本地扫描
- [x] **进程锁**：防止多个 daemon 实例同时启动（PID 文件 + 端口探测）
- [x] **日志持久化**：daemon 日志写入 `.ctx-audit/daemon.log`，支持 `--verbose`

### 0.2 错误处理加固

- [x] 消除 daemon 中的 `expect()` / `unwrap()` 调用，替换为 `map_err` + 日志
- [x] daemon panic 时自动重启（panic hook + 自动 spawn 新进程）
- [x] 大文件/二进制文件扫描时的内存保护（文件大小限制）

### 0.3 集成测试

- [x] 创建 `tests/` 目录，添加端到端测试
- [x] 测试场景：scan、JSON/SARIF 输出、config、analyze

### 0.4 CI/CD 流水线

- [x] GitHub Actions：`cargo build` + `cargo test` + `cargo clippy`
- [x] Release workflow：自动构建 Linux/macOS/Windows 二进制
- [x] SARIF 上传到 GitHub Security tab

---

## P1：检测能力增强（2-4 周）

> 目标：从"能用"到"好用"，提高检测准确率和覆盖率

### 1.1 规则扩展

**新增检测类型**：

| 漏洞类型 | CWE | 优先级 | 说明 |
|----------|-----|--------|------|
| XSS（反射型/存储型） | CWE-79 | 高 | ✅ 前端框架感知规则 |
| SSRF | CWE-918 | 高 | ✅ URL 参数 → HTTP 请求追踪 |
| IDOR / 越权访问 | CWE-639 | 中 | 需框架感知（路由 + 数据库查询） |
| 开放重定向 | CWE-601 | 中 | ✅ 已有 unsafe-redirect.yaml |
| 不安全 XML 处理 | CWE-611 | 中 | ✅ 已有 xxe-detection.yaml |
| JWT 安全问题 | — | 中 | ✅ 算法 none、弱密钥 |
| 正则 DoS (ReDoS) | CWE-1333 | 低 | ✅ 危险正则模式检测 |

**新增语言规则**：
- [x] PHP 规则集（SQL 注入、命令注入、反序列化、Laravel 安全）
- [x] C/C++ 规则集（缓冲区溢出、格式化字符串、整数溢出）
- [x] Ruby 规则集（Rails SQL 注入、XSS、路径遍历）

### 1.2 污点分析增强

- [x] **跨文件污点传播**：完善 `CrossFileTaintAnalyzer`，集成到 deep scan 流程
- [x] ** sanitizer 识别**：识别常见净化函数（`htmlspecialchars`、`parameterized query`等），降低误报
- [x] **数据类型推断**：区分字符串拼接 SQL vs 参数化查询（is_parameterized_query 检测）
- [x] **上下文感知**：识别框架请求对象变量名（req/request/ctx 等）作为 source

### 1.3 SCA 增强

- [x] **SCA 结果缓存**：本地缓存 OSV 查询结果（TTL 24h），避免重复网络请求
- [ ] **离线模式**：预下载 OSV 数据库快照，支持无网络环境
- [ ] **许可证合规检测**：扫描依赖许可证（GPL 风险等）

### 1.4 误报控制

- [x] **置信度评分系统**：每条 finding 附带置信度（高/中/低），基于多个信号综合判断
- [x] **基线抑制机制**：`.ctx-audit/baseline.json` 记录已确认/已忽略的 finding
- [x] **上下文感知过滤**：在测试文件中的硬编码密码不算漏洞；在 `config/` 中的配置项不算敏感信息泄露

---

## P2：性能与规模（4-6 周）

> 目标：支持大型项目（100k+ 文件）的高效扫描

### 2.1 扫描性能

- [x] **并行 AST 解析**：rayon 并行解析多文件，利用多核 CPU
- [x] **流式文件遍历**：大项目不一次性加载文件内容，按需读取
- [x] **扫描器流水线**：多个 scanner 组成 pipeline，文件只需读一次
- [x] **内存预算控制**：限制 AST 缓存大小（500MB 预算），防止 OOM

### 2.2 索引优化

- [x] **增量 AST 索引**：scan_project 检查 mtime，跳过未变更文件
- [x] **索引持久化**：AST 索引持久化到项目 `.ctx-audit/cache/ast/` 目录
- [x] **符号表缓存**：QueryEngine 直接查询缓存符号，跨查询复用

---

## P3：生态与集成（6-8 周）

> 目标：融入开发者工作流，提供多入口接入

### 3.1 IDE 集成

- [ ] **VS Code 扩展**：通过 TCP 连接 daemon，实时显示 findings
- [ ] **LSP 协议**：将 findings 作为 Diagnostics 推送
- [ ] **代码内联提示**：在编辑器中标记 source→sink 流

### 3.2 AI Agent 集成

- [ ] **MCP Server**：将 daemon 暴露为 MCP 工具服务器
  - `security_scan` 工具：扫描指定文件或项目
  - `trace_taint` 工具：追踪污点流
  - `get_findings` 工具：获取当前 findings
- [ ] 让 AI agent（如 Claude Code）能直接调用 daemon 的分析能力
- [ ] 不依赖 LLM 做 analysis，但让 LLM 能消费 analysis 结果

### 3.3 Git Hooks 集成

- [ ] `pre-commit` hook：仅扫描暂存文件
- [ ] `pre-push` hook：扫描变更文件，阻断高危漏洞推送
- [ ] `ctx-audit hooks install` 一键安装

### 3.4 其他集成

- [ ] **GitHub Action**：发布官方 Action（`uses: blksword/ctx-audit-action@v1`）
- [ ] **GitLab CI 模板**：提供 `.gitlab-ci.yml` 模板
- [ ] **SARIF 集成**：确保输出兼容 GitHub Code Scanning、SonarQube 等平台

---

## P4：高级特性（8+ 周）

> 目标：差异化竞争力

### 4.1 自定义规则支持

- [ ] 用户可编写自定义 YAML 规则
- [ ] 规则热加载：daemon 运行时更新规则无需重启
- [ ] 规则市场/共享机制

### 4.2 修复建议

- [ ] 基于规则的自动修复建议（规则中定义 fix 模板）
- [ ] 生成修复 diff（类似 `git diff` 格式）
- [ ] 交互式修复确认（`ctx-audit fix <ID>`）

### 4.3 报告与可视化

- [ ] HTML 报告（交互式，可筛选/排序）
- [ ] 趋势分析：漏洞数量随时间变化
- [ ] 团队仪表板：按开发者/模块统计

### 4.4 多项目管理

- [ ] monorepo 支持：单 daemon 管理多个子项目
- [ ] 项目配置文件（`.ctx-audit.toml`）：忽略规则、自定义 severity 映射等
- [ ] 项目模板：预设规则集（前端项目、后端 API、移动端等）

---

## 里程碑

| 里程碑 | 目标日期 | 交付物 |
|--------|----------|--------|
| v0.2.0 — 稳定版 | +2 周 | P0 全部完成，daemon 生产可用 |
| v0.3.0 — 增强版 | +4 周 | P1 完成，检测能力显著提升 |
| v0.4.0 — 高性能版 | +6 周 | P2 完成，支持大型项目 |
| v0.5.0 — 集成版 | +8 周 | P3 完成，VS Code + MCP + CI |
| v1.0.0 — 正式版 | +10 周 | P4 完成，差异化特性就绪 |

---

## 贡献指南

优先级最高的贡献方向：
1. **新增检测规则** — 参照 `core/src/rules/` 现有规则格式编写 YAML
2. **集成测试** — 帮助建立 `tests/` 目录下的端到端测试
3. **新语言支持** — 添加 tree-sitter 语法 + 语言规则集
4. **文档完善** — 开发者指南、架构文档、API 参考
