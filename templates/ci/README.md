# CTX-Audit 门禁模板

这个目录放"可直接复制到别的仓库"的 CI 片段。当前只有一项：**端点覆盖门禁**。

## 为什么是门禁，而不是"审计加速器"

实测（见私有报告 §13–§16）表明：把引擎给出的端点清单/证据交给审计员，**并不会**缩短审计时间
（三臂实验里裸读最快）。真正站得住的价值是**确定性 + 可机械比对**：
同一份引擎输出在两个提交上的差异，不需要任何人"信任"引擎就能用来拦回退。

## 它拦什么

- **新增端点没有任何声明式鉴权覆盖**（`no_global_config_found` / `no_global_match_found` / `coverage_unknown`）
- 判定翻转（`verdict_changed`：上次受保护、这次变成未覆盖/放行）也出现在报告里，供人工确认

## 它不拦什么（必须知道）

- 它不判断"这个端点真的能被利用"——那需要人或 LLM 判。
- 它不覆盖动态注册（`@Bean RouterFunction` 拼接、网关路由表）、`@Profile` 条件装配。
- 它默认只覆盖 Java/Express/Flask/Gin/WebFlux 这些已建模的栈；未建模的栈会在输出里如实标注。
- `permitted_by_global_config`（显式放行）当前**不会**让门禁失败——如果你的策略是"放行也必须显式评审"，
  请把 `new_uncovered` 之外再对 `added[].verdict == permitted_by_global_config` 加一条自己的判断。

## 用法

```bash
# 1) 建立基线（提交到仓库）
ctx-audit diff-routes . --write-baseline --since .github/ctx-audit/routes-baseline.json
git add .github/ctx-audit/routes-baseline.json

# 2) 本地先跑一遍（与 CI 相同）
CTX_AUDIT_INDEX_MAX_FILES=20000 \
  ctx-audit diff-routes . --since .github/ctx-audit/routes-baseline.json --fail-on-new-uncovered

# 3) 单条证伪（复核门禁报出来的路由）
ctx-audit explain-route . /data/export --assert uncovered   # 断言不匹配 → 退出码 1
ctx-audit baseline .                                        # 一屏看清项目鉴权基线
```

CI 片段见 `route-coverage-gate.yml`。

## 已知边界

- **索引上限**：默认 2000 文件；超过会截断。截断时引擎**不会**给"未覆盖"结论，而是降级为
  `coverage_unknown` 并提高 `uncertainty`——所以大仓库必须设置 `CTX_AUDIT_INDEX_MAX_FILES`，
  否则门禁会因"结论未知"而无法判定（报告里会显示 `unknown`）。
- 实测口径（1,383 个 Java 文件的仓库，索引上限放到 2 万）：端点 recall **0.853**、precision **0.914**；
  默认 2000 上限时 recall 只有 **0.014**（因此必须调大）。
- 基线文件是快照：**引擎升级后应重建基线**（同一提交、新版本引擎的输出可能不同，会表现为大量
  `verdict_changed`）。
