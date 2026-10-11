#!/usr/bin/env bash
# CTX-Audit DSH 公共模板安装脚本。
# 非破坏性：已存在的 profile/skill 不会被覆盖，确保你的私有覆盖优先。
# 用法：DSH_HOME="$HOME/.dsh" ./install.sh
#      FORCE=1 DSH_HOME=... ./install.sh    # 覆盖本仓库自带的 profile 与 web bundle
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOME_DIR="${DSH_HOME:-$HOME/.dsh}"

for profile in audit audit-scout audit-sniper; do
  target="$HOME_DIR/profiles/$profile"
  mkdir -p "$target"
  for f in package.json cordis.yml cordis.patch.yml; do
    if [[ -f "$SCRIPT_DIR/profiles/$profile/$f" && ! -f "$target/$f" ]]; then
      cp "$SCRIPT_DIR/profiles/$profile/$f" "$target/$f"
      echo "installed $profile/$f"
    fi
  done
done

# ── Web 定制面：profile + 本地 bundle ────────────────────────────────────────
# bundle 必须放在 profile 目录自身的 node_modules 下：bundle 名按
# 「安装锚点优先、其次 profile 目录」解析，@local/* 只可能来自 profile 目录。
web_profile="ctx-audit-web"
web_target="$HOME_DIR/profiles/$web_profile"
web_bundle="$web_target/node_modules/@local/ctx-audit-web"
mkdir -p "$web_target" "$web_bundle/locale"

if [[ "${FORCE:-0}" == "1" ]]; then
  # 复制【内容】而不是目录本身：目标已存在时 `cp -R src dst` 会把 src 嵌进去。
  cp -R "$SCRIPT_DIR/profiles/$web_profile/." "$web_target/"
  cp -R "$SCRIPT_DIR/plugins/ctx-audit-web/." "$web_bundle/"
  echo "installed $web_profile + bundle (forced)"
else
  for f in package.json cordis.yml cordis.patch.yml pnpm-workspace.yaml; do
    if [[ -f "$SCRIPT_DIR/profiles/$web_profile/$f" && ! -f "$web_target/$f" ]]; then
      cp "$SCRIPT_DIR/profiles/$web_profile/$f" "$web_target/$f"
      echo "installed $web_profile/$f"
    fi
  done
  for f in package.json index.js client.js cordis.patch.yml roadmap.json README.md; do
    if [[ -f "$SCRIPT_DIR/plugins/ctx-audit-web/$f" && ! -f "$web_bundle/$f" ]]; then
      cp "$SCRIPT_DIR/plugins/ctx-audit-web/$f" "$web_bundle/$f"
      echo "installed $web_profile bundle/$f"
    fi
  done
  for f in en.json zh.json; do
    if [[ -f "$SCRIPT_DIR/plugins/ctx-audit-web/locale/$f" && ! -f "$web_bundle/locale/$f" ]]; then
      cp "$SCRIPT_DIR/plugins/ctx-audit-web/locale/$f" "$web_bundle/locale/$f"
      echo "installed $web_profile bundle/locale/$f"
    fi
  done
  # The preset is a separate patch file listed by the bundle manifest; a fixed
  # filename list would silently omit it.
  mkdir -p "$web_bundle/presets"
  for f in ctx-audit.patch.yml; do
    if [[ -f "$SCRIPT_DIR/plugins/ctx-audit-web/presets/$f" && ! -f "$web_bundle/presets/$f" ]]; then
      cp "$SCRIPT_DIR/plugins/ctx-audit-web/presets/$f" "$web_bundle/presets/$f"
      echo "installed $web_profile bundle/presets/$f"
    fi
  done
fi

skill_target="$HOME_DIR/skills/ctx-audit-auditor"
mkdir -p "$skill_target"
if [[ ! -f "$skill_target/SKILL.md" ]]; then
  cp "$SCRIPT_DIR/skills/ctx-audit-auditor/SKILL.md" "$skill_target/SKILL.md"
  echo "installed skills/ctx-audit-auditor/SKILL.md"
else
  echo "skip skills/ctx-audit-auditor/SKILL.md (already exists)"
fi

if [[ ! -f "$HOME_DIR/settings.yaml" ]]; then
  cp "$SCRIPT_DIR/settings.yaml" "$HOME_DIR/settings.yaml"
  echo "installed settings.yaml (公共 provider 模板，无密钥)"
else
  echo "skip settings.yaml (already exists)"
fi

# ── 校验：不要只假设复制成功 ────────────────────────────────────────────────
# 客户端半区只有在 Loader 里存在「指向本包」的启用条目时才会进入浏览器 boot
# graph，所以这里直接检查组合树里两行是否都在。
if command -v dsh >/dev/null 2>&1; then
  if composition="$(dsh --profile "$web_profile" --dump-config 2>/dev/null)"; then
    missing=""
    for row in "id: $web_profile" "id: ctx-audit-mcp" "id: preset-ctx-audit"; do
      grep -q -- "$row" <<<"$composition" || missing="$missing [$row]"
    done
    if [[ -z "$missing" ]]; then
      echo "verified: $web_profile composes with both rows"
    else
      echo "WARN: $web_profile composition is missing:$missing" >&2
    fi
  else
    echo "WARN: could not compose $web_profile; run 'dsh --profile $web_profile --dump-config' to see why" >&2
  fi
else
  echo "note: dsh not on PATH; skipped the composition check"
fi

echo "DSH 公共模板安装完成：$HOME_DIR"
echo "接下来把私有 provider 配置、secrets.env、方法论覆盖到对应目录。"
echo "Web 定制面：CTX_AUDIT_MCP_CMD=<abs>/ctx-audit dsh --profile $web_profile --port 3081 --no-open"
