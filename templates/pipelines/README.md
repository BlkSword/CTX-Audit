# Pipeline 配置说明

Pipeline YAML 用于定制 Agent Runner 的审计流程。支持以下字段：

```yaml
name: 配置名
description: 说明

scan:
  enable_taint: true        # 是否启用 AST 污点
  enable_cross_file: true   # 是否启用跨文件追踪
  min_severity: high        # null / critical / high / medium / low
  rules_dir: null           # 自定义规则目录

triage:
  prompt_path: null         # 初审 prompt 文件（相对 Pipeline 文件路径解析）
  system_prompt: null       # 直接覆盖 system prompt 文本
  shard_threshold: null     # 初审分片阈值；null 用默认 50，0 禁用分片
  enabled: true             # false 则跳过初审 LLM 阶段

deep_review:
  prompt_path: null
  system_prompt: null
  shard_threshold: null
  enabled: true

output:
  tp_candidates_path: ["tp_candidates"]     # TP 候选数组的 JSON 路径
  verdict_findings_path: ["findings"]       # verdict 形态的 findings 路径
  verdict_field: "verdict"                  # findings 中判定字段名
  accepted_verdicts: ["TP", "TP_CANDIDATE"] # 视为 TP 的判定值

gate_enabled: true          # false 则 TP 候选不触发人工闸门
registration:
  polish_draft: false       # true 则用 LLM 润色登记草稿

# 可选：完全自定义阶段顺序；不写则使用内置默认
# phases:
#   - type: select_target
#   - type: eligibility
#   - type: scan
#   - type: triage
#   - type: extra
#     id: logic_audit
#   - type: registration
#   - type: feedback

extra_phases:               # 额外的 LLM 审计阶段，深审后按顺序执行
  - id: logic_audit
    prompt_path: ./private/prompts/logic-audit.md
    system_prompt: null
    enabled: true
    output:
      tp_candidates_path: ["candidates"]
      verdict_findings_path: ["results"]
      verdict_field: "decision"
      accepted_verdicts: ["CONFIRMED", "TP"]
```

所有字段都可省略；省略时使用与内置默认一致的值。