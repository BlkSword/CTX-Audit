<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useWorkspaceStore } from '../store'

const store = useWorkspaceStore()
const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const budget = ref(3)
const running = ref(false)

const overview = computed(() => store.overview.value)
const ledger = computed(() => store.ledger.value)
const sessions = computed(() => store.sessions.value)

const coverage = computed(() => overview.value?.coverage ?? null)
const chains = computed(() => overview.value?.chains ?? null)

const verdictRows = computed(() => {
  const by = coverage.value?.byVerdict ?? {}
  return Object.entries(by)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ verdict: k, count: v }))
})

const tierRows = computed(() => {
  const tiers = chains.value?.tiers ?? {}
  return Object.entries(tiers)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ tier: k, count: v }))
})

const topChains = computed(() => chains.value?.top ?? [])

function toneFor(verdict: string): string {
  if (verdict.includes('uncovered') || verdict.includes('no_global')) return 'danger'
  if (verdict.includes('covered')) return 'ok'
  if (verdict.includes('permitted')) return 'info'
  return 'warn'
}

function tierTone(tier: string): string {
  if (tier === 'payload_may_survive') return 'danger'
  if (tier === 'guard_ineffective_token') return 'warn'
  if (tier === 'payload_killed') return 'ok'
  return 'info'
}

async function runAudit() {
  running.value = true
  try {
    const s = await store.runAudit(workspaceId.value, budget.value)
    if (s) ElMessage.success(`审计完成：${s.evidence.length} 条证据`)
    else ElMessage.error(store.error.value ?? '审计失败')
  } finally {
    running.value = false
  }
}

onMounted(async () => {
  await Promise.all([store.loadOverview(workspaceId.value), store.loadSessions(workspaceId.value)])
})
</script>

<template>
  <div class="stack">
    <el-skeleton v-if="store.loadingOverview.value && !overview" :rows="6" animated />

    <template v-else-if="overview">
      <!-- KPI strip -->
      <div class="kpi-grid">
        <div class="kpi">
          <div class="kpi-label">端点总数</div>
          <div class="kpi-value num">{{ coverage?.methodRoutes ?? 0 }}</div>
          <div class="kpi-hint">{{ coverage?.filesIndexed ?? 0 }} 个文件 · 置信 {{ coverage?.confidence }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">未覆盖端点</div>
          <div class="kpi-value num" :class="(coverage?.uncovered ?? 0) > 0 ? 'danger' : 'ok'">
            {{ coverage?.uncovered ?? 0 }}
          </div>
          <div class="kpi-hint">注解覆盖 {{ coverage?.annotationCovered ?? 0 }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">候选链</div>
          <div class="kpi-value num">{{ chains?.total ?? 0 }}</div>
          <div class="kpi-hint">载荷可能存活 {{ chains?.tiers['payload_may_survive'] ?? 0 }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">审计会话</div>
          <div class="kpi-value num">{{ ledger?.sessions ?? 0 }}</div>
          <div class="kpi-hint">证据 {{ ledger?.evidenceTotal ?? 0 }} · 发现 {{ ledger?.findingsTotal ?? 0 }}</div>
        </div>
      </div>

      <!-- one-click audit -->
      <div class="panel">
        <div class="panel-head">
          <div>
            <div class="panel-title">一键审计</div>
            <div class="panel-sub">跑完整 SOP：覆盖率 → 待审 → 候选链 → 链档 → 载荷判定，结果落为审计会话</div>
          </div>
          <div class="row">
            <el-select v-model="budget" size="small" style="width: 108px">
              <el-option v-for="n in [1, 2, 3, 5, 8]" :key="n" :label="`预算 ${n}`" :value="n" />
            </el-select>
            <el-button type="primary" size="small" :loading="running" @click="runAudit">
              一键审计
            </el-button>
          </div>
        </div>
        <div class="panel-body">
          <div v-if="sessions.length === 0" class="empty">
            <div class="empty-title">还没有审计会话</div>
            <div class="hint">点右上角「一键审计」跑一轮完整 SOP。</div>
          </div>
          <div v-else class="session-strip">
            <div v-for="s in sessions.slice(0, 6)" :key="s.id" class="session-pill">
              <span class="chip" :class="s.status === 'done' ? 'ok' : s.status === 'failed' ? 'danger' : 'warn'">
                {{ s.status }}
              </span>
              <span class="session-pill-label">{{ s.label }}</span>
              <span class="muted num">{{ s.evidence.length }} 证据</span>
              <span v-if="s.durationMs" class="muted num">{{ Math.round(s.durationMs / 1000) }}s</span>
            </div>
          </div>
        </div>
      </div>

      <div class="two-col">
        <!-- coverage distribution -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">鉴权覆盖分布</div>
              <div class="panel-sub">按判定标签统计的端点数量</div>
            </div>
          </div>
          <div class="panel-body flush">
            <table class="data-table">
              <thead>
                <tr>
                  <th>判定</th>
                  <th style="text-align: right">数量</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="r in verdictRows" :key="r.verdict">
                  <td><span class="chip" :class="toneFor(r.verdict)">{{ r.verdict }}</span></td>
                  <td class="num strong" style="text-align: right">{{ r.count }}</td>
                </tr>
                <tr v-if="verdictRows.length === 0">
                  <td colspan="2" class="muted">暂无数据</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- payload tiers -->
        <div class="panel">
          <div class="panel-head">
            <div>
              <div class="panel-title">载荷档位</div>
              <div class="panel-sub">候选链的载荷存活判定分布</div>
            </div>
          </div>
          <div class="panel-body flush">
            <table class="data-table">
              <thead>
                <tr>
                  <th>档位</th>
                  <th style="text-align: right">数量</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="r in tierRows" :key="r.tier">
                  <td><span class="chip" :class="tierTone(r.tier)">{{ r.tier }}</span></td>
                  <td class="num strong" style="text-align: right">{{ r.count }}</td>
                </tr>
                <tr v-if="tierRows.length === 0">
                  <td colspan="2" class="muted">暂无数据</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- top chains -->
      <div class="panel">
        <div class="panel-head">
          <div>
            <div class="panel-title">头部候选链</div>
            <div class="panel-sub">按分数排序的入口 → 危险汇路径</div>
          </div>
          <RouterLink :to="{ name: 'chains', params: { id: workspaceId } }">
            <el-button size="small" text>查看全部</el-button>
          </RouterLink>
        </div>
        <div class="panel-body flush">
          <table class="data-table">
            <thead>
              <tr>
                <th>链 ID</th>
                <th>档位</th>
                <th>入口</th>
                <th>汇</th>
                <th style="text-align: right">分数</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="c in topChains" :key="c.chainId">
                <td class="mono">{{ c.chainId }}</td>
                <td><span class="chip" :class="tierTone(c.tier)">{{ c.tier }}</span></td>
                <td>{{ c.entryRoute ?? '-' }}</td>
                <td>{{ c.sinkKind }} · {{ c.sinkFile.split('/').pop() }}:{{ c.sinkLine }}</td>
                <td class="num strong" style="text-align: right">{{ c.score }}</td>
              </tr>
              <tr v-if="topChains.length === 0">
                <td colspan="5" class="muted">暂无候选链</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <div v-else class="empty">
      <div class="empty-title">暂无总览数据</div>
      <div class="hint">点右上角「重新分析」生成总览。</div>
    </div>
  </div>
</template>

<style scoped>
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.two-col {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.session-strip {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.session-pill {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 6px 10px;
  border: 1px solid var(--rule);
  border-radius: var(--r-md);
  background: var(--bg-elevated);
  font-size: var(--fs-xs);
}
.session-pill-label {
  color: var(--text-2);
}
@media (max-width: 1100px) {
  .kpi-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .two-col {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
