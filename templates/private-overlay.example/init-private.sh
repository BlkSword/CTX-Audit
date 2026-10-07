#!/usr/bin/env bash
# 初始化本地私有 overlay 骨架（不提交到公共仓库）。
# 用法：./init-private.sh
# 可用环境变量：CTX_AUDIT_PRIVATE_DIR（默认 ~/.ctx-audit/private）
set -euo pipefail

PRIVATE_DIR="${CTX_AUDIT_PRIVATE_DIR:-$HOME/.ctx-audit/private}"

mkdir -p "$PRIVATE_DIR"/{prompts,dsh/profiles,dsh/skills,logs}

# 私有方法论/台账占位
for name in methodology.md registry.md; do
  if [[ ! -f "$PRIVATE_DIR/$name" ]]; then
    : > "$PRIVATE_DIR/$name"
    echo "created $PRIVATE_DIR/$name"
  fi
done

# 密钥文件占位
if [[ ! -f "$PRIVATE_DIR/secrets.env" ]]; then
  cat > "$PRIVATE_DIR/secrets.env" <<'EOF'
# 在这里填入你的 API key，例如：
# export LONGCAT_API_KEY=...
# export OPENCODE_API_KEY=...
EOF
  echo "created $PRIVATE_DIR/secrets.env"
fi

echo "私有 overlay 已初始化：$PRIVATE_DIR"
echo "记得把该目录加入公共仓库 .gitignore（已默认忽略 /.ctx-audit-private/）。"