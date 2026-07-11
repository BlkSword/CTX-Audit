#!/bin/bash
# CTX-Audit 真实项目基线脚本
#
# 目的：在真实项目上观察污点链、调用图、source→sink 路径是否被引擎发现和标注，
#       不调用 LLM（agent.llm_mode=noop），避免成本和不稳定性。
#
# 用法：bash benchmarks/run-baseline.sh [project_dir...]
#   不指定项目时，默认跑 target/benchmarks/webgoat
#
# 每个项目会输出：
#   - ${OUT_DIR}/${name}_findings.json        scan --deep 结果
#   - ${OUT_DIR}/${name}_audit_log.json       Agent noop 审计日志
#   - ${OUT_DIR}/${name}_report.md            评估报告
#   - ${OUT_DIR}/${name}_details.json         结构化明细

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${PROJECT_DIR}/target/benchmarks/real-projects"
BIN="${PROJECT_DIR}/target/release/ctx-audit"

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    BIN="${BIN}.exe"
fi

mkdir -p "$OUT_DIR"

if [[ ! -x "$BIN" ]]; then
    echo "错误：未找到可执行文件 $BIN，请先运行 cargo build --release"
    exit 1
fi

# 默认项目列表
PROJECTS=("$@")
if [[ ${#PROJECTS[@]} -eq 0 ]]; then
    PROJECTS=("${PROJECT_DIR}/target/benchmarks/webgoat")
fi

# 强制使用 noop 模式，避免 LLM 调用成本和不确定性
"$BIN" config set agent.llm_mode noop
"$BIN" config set agent.taint_walk_enabled false
"$BIN" config set agent.investigator_enabled true
"$BIN" config set agent.review_mode off
"$BIN" config set agent.specialist_enabled true
"$BIN" config set agent.planner.strategy rule
"$BIN" config set scan.min_severity low

# 强制使用统一的排除列表，避免本地旧配置文件导致基线不可复现
"$BIN" config set scan.exclude_patterns '["node_modules",".git","target","build","dist","vendor","__pycache__",".gradle",".idea",".vscode",".cache","bower_components",".next",".nuxt","coverage","test","tests","__tests__","spec","fixtures","e2e","examples","example","scripts","*.min.js","*.min.css","*.bundle.js","*.chunk.js","*.map",".env.*","*.test.*","*.spec.*","static/plugins","static/js/libs","static/webjars","webjars","src/main/resources/static","resources/static","static/**/libs","static/**/plugins","**/static/plugins/**","**/static/js/libs/**","**/webjars/**","*.vendor.js"]'

run_project() {
    local project_path="$1"
    local name
    name="$(basename "$project_path")"

    echo ""
    echo "=============================================="
    echo "项目: $name"
    echo "路径: $project_path"
    echo "=============================================="

    # 清理上次审计产物，避免旧结果干扰
    rm -rf "${project_path}/.ctx-audit"

    local findings_json="${OUT_DIR}/${name}_findings.json"
    local audit_log="${project_path}/.ctx-audit/audit_log.json"
    local report_md="${OUT_DIR}/${name}_report.md"
    local details_json="${OUT_DIR}/${name}_details.json"

    # 1. 引擎深度扫描
    echo ""
    echo "--- scan --deep ---"
    "$BIN" scan "$project_path" --deep --min-severity low \
        --output "$findings_json"

    # 2. Agent noop 审计：主要观察证据链和标注
    echo ""
    echo "--- audit --agent (noop, no-auto-goal) ---"
    "$BIN" audit "$project_path" --agent --deep --no-auto-goal \
        --min-severity low \
        --output "${OUT_DIR}/${name}_audit.json" || true

    # 拷贝 audit log 到输出目录，方便归档
    if [[ -f "$audit_log" ]]; then
        cp "$audit_log" "${OUT_DIR}/${name}_audit_log.json"
    fi

    # 3. 评估：污点链 / 调用图 / source-sink / Agent 判定分布
    echo ""
    echo "--- evaluate ---"
    python "$SCRIPT_DIR/evaluate_real_project.py" \
        --findings "$findings_json" \
        --audit-log "${OUT_DIR}/${name}_audit_log.json" \
        --output "$report_md" \
        --details "$details_json"

    echo ""
    echo "$name 完成，报告: $report_md"
}

for project in "${PROJECTS[@]}"; do
    if [[ ! -d "$project" ]]; then
        echo "跳过不存在的项目目录: $project"
        continue
    fi
    run_project "$project"
done

echo ""
echo "=============================================="
echo "所有项目基线运行完成，结果位于 $OUT_DIR"
echo "=============================================="
