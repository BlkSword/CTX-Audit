<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import { useWorkspaceStore } from '../store'
import type { ChainRow, ChainDossier } from '../api'

const store = useWorkspaceStore()
const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const rows = ref<ChainRow[]>([])
const loading = ref(false)
const dossier = ref<ChainDossier | null>(null)
const dossierLoading = ref(false)
const drawer = ref(false)

const overview = computed(() => store.overview.value)

function tierTone(tier: string): string {
  if (tier === 'payload_may_survive') return 'danger'
  if (tier === 'guard_ineffective_token') return 'warn'
  if (tier === 'payload_killed') return 'ok'
  return 'info'
}

async function openDossier(chainId: string) {
  drawer.value = true
  dossierLoading.value = true
  dossier.value = null
  try {
    const r = await api.chain(workspaceId.value, chainId)
    if (r.ok && r.dossier) dossier.value = r.dossier
  } finally {
    dossierLoading.value = false
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
    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-label">候选链</div>
        <div class="kpi-value num">{{ overview?.chains.total ?? rows.length }}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">载荷可能存活</div>
        <div class="kpi-value num danger">{{ overview?.chains.tiers['payload_may_survive'] ?? 0 }}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">守卫无效</div>
        <div class="kpi-value num warn">{{ overview?.chains.tiers['guard_ineffective_token'] ?? 0 }}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">载荷被杀</div>
        <div class="kpi-value num ok">{{ overview?.chains.tiers['payload_killed'] ?? 0 }}</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">候选链</div>
          <div class="panel-sub">入口 → 危险汇的可达路径，点击查看链档</div>
        </div>
      </div>
      <div class="panel-body flush">
        <el-table :data="rows" v-loading="loading" size="small" max-height="640" stripe @row-click="(r: ChainRow) => openDossier(r.chainId)">
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
          <el-table-column label="汇位置" min-width="220" show-overflow-tooltip>
            <template #default="{ row }">
              <span class="mono" style="font-size: 10.5px">{{ row.sinkFile }}:{{ row.sinkLine }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="entryRoute" label="入口" min-width="160" show-overflow-tooltip />
          <el-table-column prop="steps" label="步数" width="70" align="right" />
          <el-table-column prop="guards" label="守卫" width="70" align="right" />
          <el-table-column prop="score" label="分数" width="70" align="right">
            <template #default="{ row }">
              <span class="num strong">{{ row.score }}</span>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>

    <el-drawer v-model="drawer" :title="dossier ? `链档 ${dossier.chain_id}` : '链档'" size="620px">
      <el-skeleton v-if="dossierLoading" :rows="8" animated />
      <div v-else-if="dossier" class="stack">
        <div class="row wrap">
          <span class="chip" :class="tierTone(dossier.tier)">{{ dossier.tier }}</span>
          <span class="chip">分数 {{ dossier.score }}</span>
          <span class="chip">可控性 {{ dossier.controllability }}</span>
        </div>

        <div>
          <div class="section-title">入口</div>
          <div class="mono" style="font-size: 11px">
            {{ dossier.entry?.file }}:{{ dossier.entry?.line }}
            <span v-if="dossier.entry?.route"> · {{ dossier.entry.route }}</span>
          </div>
        </div>

        <div>
          <div class="section-title">汇</div>
          <div class="mono" style="font-size: 11px">
            {{ dossier.sink.kind }} · {{ dossier.sink.file }}:{{ dossier.sink.line }}
          </div>
          <div v-if="dossier.sink.expr" class="hint mono" style="margin-top: 4px">{{ dossier.sink.expr }}</div>
        </div>

        <div>
          <div class="section-title">步骤 · {{ dossier.steps.length }}</div>
          <div v-for="(st, i) in dossier.steps" :key="i" class="step-row">
            <span class="step-idx num">{{ i + 1 }}</span>
            <div>
              <div class="mono" style="font-size: 11px">{{ st.symbol }}</div>
              <div class="hint">{{ st.file }}:{{ st.line }} · {{ st.role }}</div>
            </div>
          </div>
        </div>

        <div v-if="dossier.guards.length">
          <div class="section-title">守卫 · {{ dossier.guards.length }}</div>
          <div v-for="(g, i) in dossier.guards" :key="i" class="guard-row">
            <span class="chip" :class="g.verdict === 'partial' ? 'warn' : 'ok'">{{ g.verdict ?? 'unknown' }}</span>
            <span class="mono" style="font-size: 10.5px">{{ g.kind }} @L{{ g.line }}</span>
            <div class="hint mono">{{ g.evidence }}</div>
          </div>
        </div>

        <div v-if="dossier.breakpoints.length">
          <div class="section-title">断点 · {{ dossier.breakpoints.length }}</div>
          <div v-for="(b, i) in dossier.breakpoints" :key="i" class="hint">
            {{ b.kind }} @ {{ b.at }} · 置信 {{ b.confidence }}
          </div>
        </div>
      </div>
    </el-drawer>
  </div>
</template>

<style scoped>
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.step-row {
  display: flex;
  gap: 10px;
  padding: 7px 0;
  border-bottom: 1px solid var(--rule-faint);
}
.step-idx {
  width: 20px;
  height: 20px;
  display: grid;
  place-items: center;
  border-radius: var(--r-sm);
  background: var(--surface-3);
  font-size: var(--fs-xs);
  color: var(--text-3);
  flex-shrink: 0;
}
.guard-row {
  padding: 7px 0;
  border-bottom: 1px solid var(--rule-faint);
}
@media (max-width: 1100px) {
  .kpi-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
