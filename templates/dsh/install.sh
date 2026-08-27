#!/usr/bin/env bash
# CTX-Audit DSH 公共模板安装脚本。
# 非破坏性：已存在的 profile/skill 不会被覆盖，确保你的私有覆盖优先。
# 用法：DSH_HOME="$HOME/.dsh" ./install.sh
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

skill_target="$HOME_DIR/skills/ctx-audit-auditor"
mkdir -p "$skill_target"
if [[ ! -f "$skill_target/SKILL.md" ]]; then
  cp "$SCRIPT_DIR/skills/ctx-audit-auditor/SKILL.md" "$skill_target/SKILL.md"
  echo "installed skills/ctx-audit-auditor/SKILL.md"
else
  echo "skip skills/ctx-audit-auditor/SKILL.md (already exists)"
fi

echo "DSH 公共模板安装完成：$HOME_DIR"
echo "接下来把私有 provider 配置、secrets.env、方法论覆盖到对应目录。"