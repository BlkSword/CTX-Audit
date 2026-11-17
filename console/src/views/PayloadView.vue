<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import { useWorkspaceStore } from '../store'
import type { ChainRow } from '../api'

const store = useWorkspaceStore()
const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const rows = ref<ChainRow[]>([])
const loading = ref(false)
const selected = ref<ChainRow | null>(null)
const verdict = ref<Record<string, unknown> | null>(null)
const verdictLoading = ref(false)

const overview = computed(() => store.overview.value)

const tiers = computed(() => {
  const t = overview.value?.chains.tiers ?? {}
  return Object.entries(t)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ tier: k, count: v }))
})

function tierTone(tier: string): string {
  if (tier === 'payload_may_survive') return 'danger'
  if (tier === 'guard_ineffective_token') return 'warn'
  if (tier === 'payload_killed') return 'ok'
  return 'info'
}

async function runVerdict(row: ChainRow) {
  selected.value = row
  verdictLoading.value = true
  verdict.value = null
  try {
    const r = await api.runAction(workspaceId.value, 'payload', {
      entryFile: row.sinkFile ? row.entryRoute ?? '' : '',
      entryLine: '1',
      sinkFile: row.sinkFile,
      sinkLine: String(row.sinkLine),
      archetype: row.sinkKind,
    })
    if (r.ok) verdict.value = (r.data ?? {}) as Record<string, unknown>
    else verdict.value = { error: r.error ?? r.stderr ?? '判定失败' }
  } finally {
    verdictLoading.value = false
  }
}

onMounted(async () => {
  loading.value = true
  try {
    const r = await api.chains(workspaceId.value, 50)
    if (r.ok) rows.value = r.chains ?? []
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="stack">
    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">载荷档位分布</div>
          <div class="panel-sub">候选链按载荷存活判定分档</div>
        </div>
      </div>
      <div class="panel-body">
        <div class="tier-grid">
          <div v-for="t in tiers" :key="t.tier" class="tier-card">
            <span class="chip" :class="tierTone(t.tier)">{{ t.tier }}</span>
            <div class="tier-count num">{{ t.count }}</div>
          </div>
          <div v-if="tiers.length === 0" class="muted">暂无数据</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">逐链载荷判定</div>
          <div class="panel-sub">对单条链重跑载荷存活推演，查看逐跳证据</div>
        </div>
      </div>
      <div class="panel-body flush">
        <el-table :data="rows" v-loading="loading" size="small" max-height="420" stripe>
          <el-table-column prop="chainId" label="链 ID" width="140">
            <template #default="{ row }">
              <span class="mono" style="color: var(--accent)">{{ row.chainId }}</span>
            </template>
          </el-table-column>
          <el-table-column label="档位" width="190">
            <template #default="{ row }">
              <span class="chip" :class="tierTone(row.tier)">{{ row.tier }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="sinkKind" label="汇类型" width="120" />
          <el-table-column label="汇位置" min-width="240" show-overflow-tooltip>
            <template #default="{ row }">
              <span class="mono" style="font-size: 10.5px">{{ row.sinkFile }}:{{ row.sinkLine }}</span>
            </template>
          </el-table-column>
          <el-table-column width="110" align="right">
            <template #default="{ row }">
              <el-button size="small" text type="primary" @click="runVerdict(row)">重跑判定</el-button>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>

    <div v-if="selected" class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">判定结果 · {{ selected.chainId }}</div>
          <div class="panel-sub">{{ selected.sinkKind }} · {{ selected.sinkFile }}:{{ selected.sinkLine }}</div>
        </div>
      </div>
      <div class="panel-body">
        <el-skeleton v-if="verdictLoading" :rows="4" animated />
        <pre v-else class="verdict-json mono">{{ JSON.stringify(verdict, null, 2) }}</pre>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tier-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 10px;
}
.tier-card {
  padding: 12px;
  border: 1px solid var(--rule);
  border-radius: var(--r-md);
  background: var(--bg-elevated);
}
.tier-count {
  font-size: var(--fs-2xl);
  font-weight: 600;
  margin-top: 6px;
}
.verdict-json {
  font-size: 10.5px;
  line-height: 1.6;
  color: var(--text-2);
  background: var(--bg-elevated);
  border: 1px solid var(--rule-faint);
  border-radius: var(--r-md);
  padding: 12px;
  max-height: 420px;
  overflow: auto;
  margin: 0;
}
</style>
