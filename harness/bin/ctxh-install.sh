#!/usr/bin/env bash
# ctxh — 安装 CTX-Audit 的最小 agent 运行时。
#
# 为什么需要它：`npm i -g @deepseek-ai/dsh` 装的是**全部能力**（1.1 GB，其中
# LibreOffice 339 MB、Web 前端、语音、图像等审计用不到的东西）。审计 agent 实际
# 只需要 base + headless 两个 bundle + 我们自己的三件（preset / MCP 行 / skill），
# 实测 254 MB。
#
# 这个脚本把"最小组合"装成一个可运行的 profile，并处理四个已踩过的坑：
#
#   1. 先普通 `npm install` base+headless，让 npm 自动装 peer。用
#      `--legacy-peer-deps` 会跳过 peer，直到运行时 import 才报
#      ERR_MODULE_NOT_FOUND。
#   2. `@mars-sea/dsh-commandcode-provider` 的 peer 写的是 `^0.2.0-rc.1`，而
#      semver 对 prerelease 要求同 patch——0.2.2-rc.5 不满足，普通 install 会
#      ERESOLVE。用 `--force` 单独补装（不是 --legacy-peer-deps，那会拆掉 peer 树）。
#   3. 我们的 bundle 声明的三个插件（agent-preset / agent-preset-registry /
#      mcp-client）不是 base 的依赖，必须显式装，否则组合树能 dump 但运行时
#      "did not activate"。
#   4. 每次 npm install 都会**删掉**手工放进 node_modules 的 `@local/*` 目录，
#      所以 bundle 必须在**最后一次** npm 之后复制。
#
# 用法：
#   ./ctxh-install.sh                      # 装到 ~/.ctxh
#   CTXH_HOME=/opt/ctxh ./ctxh-install.sh
#   CTX_AUDIT_BIN=/path/to/ctx-audit ./ctxh-install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CTXH_HOME="${CTXH_HOME:-$HOME/.ctxh}"
PROFILE_DIR="$CTXH_HOME/profiles/ctxh"

DSH_BASE_VERSION="${DSH_BASE_VERSION:-0.2.2-rc.5}"
PROVIDER_VERSION="${PROVIDER_VERSION:-0.12.0}"

say() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ── 前置检查 ────────────────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || die "需要 Node.js >= 24.9（DSH 0.2.2 的下限）"
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
NODE_MINOR="$(node -p 'process.versions.node.split(".")[1]')"
if [ "$NODE_MAJOR" -lt 24 ] || { [ "$NODE_MAJOR" -eq 24 ] && [ "$NODE_MINOR" -lt 9 ]; }; then
  die "Node.js 版本过低：$(node -v)，需要 >= 24.9"
fi
command -v npm >/dev/null 2>&1 || die "需要 npm"

if [ -z "${DSH_BIN:-}" ]; then
  if command -v dsh >/dev/null 2>&1; then DSH_BIN="$(command -v dsh)"; else DSH_BIN=""; fi
fi

mkdir -p "$PROFILE_DIR"

# ── 1) 模板文件 ─────────────────────────────────────────────────────────────
say "写入 profile 模板到 $PROFILE_DIR"
cp "$SCRIPT_DIR/../profiles/ctxh/package.json"      "$PROFILE_DIR/package.json"
cp "$SCRIPT_DIR/../profiles/ctxh/cordis.patch.yml"  "$PROFILE_DIR/cordis.patch.yml"
cp "$SCRIPT_DIR/../profiles/ctxh/cordis.yml"        "$PROFILE_DIR/cordis.yml"

cd "$PROFILE_DIR"

# ── 2) 基础树（普通 install，让 npm 装 peer）─────────────────────────────────
say "安装 base + headless（含 peer，约 213 MB）"
npm install --no-audit --no-fund --loglevel=error \
  "@deepseek-ai/dsh-base@$DSH_BASE_VERSION" \
  "@deepseek-ai/dsh-headless@$DSH_BASE_VERSION"

# ── 3) provider 与 bundle 需要的插件 ────────────────────────────────────────
#
# 两条命令必须分开，而且都用 --force：
#   - 与 base+headless 同一次 install 时，npm 会按 provider 的 peer 范围
#     （^0.2.0-rc.1）挑一个 0.2.0-rc.x，与已装的 0.2.2-rc.5 冲突并 ERESOLVE；
#   - 三个插件不是 base 的依赖，但不装会在运行时 "did not activate"。
say "安装 commandcode provider"
npm install --no-audit --no-fund --loglevel=error --force \
  "@mars-sea/dsh-commandcode-provider@$PROVIDER_VERSION"

say "安装 preset / MCP client 插件"
npm install --no-audit --no-fund --loglevel=error --force \
  "@deepseek-ai/dsh-agent-preset@$DSH_BASE_VERSION" \
  "@deepseek-ai/dsh-agent-preset-registry@$DSH_BASE_VERSION" \
  "@deepseek-ai/dsh-mcp-client@$DSH_BASE_VERSION"

# ── 4) CLI：复制全局 dsh 的 lib（约 65 KB，不复制它的 91 个依赖）─────────────
CLI_READY=""
if [ -n "$DSH_BIN" ]; then
  GLOBAL_ROOT="$(npm root -g 2>/dev/null || true)"
  for candidate in "$GLOBAL_ROOT/@deepseek-ai/dsh" "$(cd "$(dirname "$DSH_BIN")/.." 2>/dev/null && pwd)"; do
    if [ -n "$candidate" ] && [ -f "$candidate/package.json" ] && [ -d "$candidate/lib" ]; then
      say "复制瘦 CLI 到 profile（不复制其依赖）"
      mkdir -p "$PROFILE_DIR/node_modules/@deepseek-ai/dsh"
      cp -R "$candidate/lib" "$PROFILE_DIR/node_modules/@deepseek-ai/dsh/"
      cp "$candidate/package.json" "$PROFILE_DIR/node_modules/@deepseek-ai/dsh/"
      CLI_READY=1
      break
    fi
  done
fi
[ -n "$CLI_READY" ] || say "未找到可复制的 dsh CLI；运行时将使用 PATH 上的 dsh"

# ── 5) 我们的 bundle（必须在所有 npm install 之后）──────────────────────────
say "复制 @local/ctx-audit-web 到 profile"
mkdir -p "$PROFILE_DIR/node_modules/@local"
rm -rf "$PROFILE_DIR/node_modules/@local/ctx-audit-web"
cp -R "$REPO_ROOT/harness/plugins/ctx-audit-web" \
      "$PROFILE_DIR/node_modules/@local/ctx-audit-web"

# ── 6) skill ────────────────────────────────────────────────────────────────
say "安装审计 skill"
mkdir -p "$CTXH_HOME/skills/ctx-audit-auditor"
cp "$REPO_ROOT/harness/skills/ctx-audit-auditor/SKILL.md" \
   "$CTXH_HOME/skills/ctx-audit-auditor/SKILL.md"

# ── 7) 自检 ─────────────────────────────────────────────────────────────────
say "自检：组合树"
DUMP="$(mktemp)"
if ! CTXH_HOME="$CTXH_HOME" CTX_AUDIT_MCP_CMD="${CTX_AUDIT_BIN:-ctx-audit}" \
     "$SCRIPT_DIR/ctxh" --dump-config >"$DUMP" 2>&1; then
  printf 'error: 组合失败：\n' >&2
  tail -20 "$DUMP" >&2
  rm -f "$DUMP"
  exit 1
fi
for row in preset-ctx-audit ctx-audit-mcp llm-commandcode; do
  grep -q -- "$row" "$DUMP" || { rm -f "$DUMP"; die "组合树缺少 $row"; }
done
rm -f "$DUMP"
say "自检通过：preset-ctx-audit / ctx-audit-mcp / llm-commandcode 均在组合树中"

SIZE_MB="$(du -sm "$PROFILE_DIR/node_modules" 2>/dev/null | cut -f1 || echo '?')"
cat >&2 <<EOF

安装完成：$CTXH_HOME  （profile 约 $SIZE_MB MB）

下一步——模型凭据（二选一）：
  a) export COMMANDCODE_API_KEY=...        # 实测最可靠，直接读环境变量
  b) 复制已有的 ~/.dsh/.credentials.yaml 到 $CTXH_HOME/

然后运行：
  $SCRIPT_DIR/ctxh "把 /path/to/target 审一遍"

已知限制：把凭据文件复制到新 home 后实测**未被识别**（只有环境变量生效），
所以优先用 a)。
EOF
