# CTX-Audit Console

工作区中心化的审计控制台。Vue 3 + Element Plus + Vite，零依赖 Node API。

## 运行

```bash
cd console
npm install
npm run build
npm run serve          # http://127.0.0.1:4317
```

或由 DSH 插件挂到 Web 面的 `/console`（见 `dsh-profile/`）。

## 结构

```
src/
  main.ts                 应用入口（Element Plus + Router）
  router.ts               路由：工作区选择 → 工作区外壳（9 视图）
  store.ts                工作区状态（总览/台账/会话）
  api.ts                  API 客户端与类型（含 snake_case → camelCase 映射）
  styles.css              设计系统（token + 共享原语 + Element Plus 主题覆盖）
  views/
    WorkspacePicker.vue   工作区选择 / 添加 / 移除
    WorkspaceShell.vue    侧栏 + 顶栏 KPI + 状态栏 + 子路由出口
    OverviewView.vue      KPI、一键审计、覆盖分布、载荷档位、头部链
    SessionsView.vue      审计台账、会话列表、阶段耗时、证据表
    CoverageView.vue      端点覆盖与待审队列
    ChainsView.vue        候选链列表 + 链档抽屉
    PayloadView.vue       载荷档位分布 + 逐链重跑判定
    ActionsView.vue       14 个受校验动作
    GateView.vue          PR 漂移闸门
    ReportView.vue        报告生成
    AssistantView.vue     审计助手（简报 → Agent → 回复与工具轨迹）
server/
  index.mjs               独立 HTTP 服务
  api.mjs                 共享 API（独立服务与 DSH 插件共用）
  sessions.mjs            审计会话持久化与台账
  actions.mjs             14 个动作定义与参数校验
scripts/
  browser-smoke.mjs       无头浏览器冒烟（CDP，零依赖）
  e2e.mjs                 端到端 API 检查
tests/
  sessions.test.mjs       会话存储单测
```

## 设计语言

参考 DSH 的克制风格，但不照搬：

- **表面**：暖中性灰阶（`#151517` → `#353638`），按亮度分层，不用纯黑；
- **分隔**：白色 alpha 细线（`rgba(255,255,255,0.06)`），读起来是"光"而不是"框"；
- **强调**：白色是品牌色（主按钮白底黑字），蓝色只用于链接与信息态；
- **状态**：胶囊 chip 用填充色表达，不用描边；
- **表格**：无斑马纹，只有 hover 与发丝分隔线；
- **圆角**：4 / 8 / 12 / 16px 四档，比常见后台更圆但不夸张；
- **数字**：等宽数字（`font-variant-numeric: tabular-nums`）。

## 验证

```bash
npm run typecheck              # vue-tsc
npm test                       # 会话存储 13/13
node scripts/e2e.mjs           # 端到端 API
node scripts/browser-smoke.mjs # 无头浏览器 9/9
```
