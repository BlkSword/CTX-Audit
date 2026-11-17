<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '../api'
import { useWorkspaceStore } from '../store'
import type { WorklistItem } from '../api'

const store = useWorkspaceStore()
const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const items = ref<WorklistItem[]>([])
const loading = ref(false)
const filter = ref('')

const overview = computed(() => store.overview.value)

const filtered = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return items.value
  return items.value.filter(
    (i) =>
      (i.route ?? '').toLowerCase().includes(q) ||
      (i.file ?? '').toLowerCase().includes(q) ||
      i.verdict.toLowerCase().includes(q),
  )
})

function tone(verdict: string): string {
  if (verdict.includes('uncovered') || verdict.includes('no_global')) return 'danger'
  if (verdict.includes('covered')) return 'ok'
  if (verdict.includes('permitted')) return 'info'
  return 'warn'
}

onMounted(async () => {
  loading.value = true
  try {
    const r = await api.worklist(workspaceId.value, 200)
    if (r.ok) items.value = r.worklist ?? []
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="stack">
    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-label">端点总数</div>
        <div class="kpi-value num">{{ overview?.coverage.methodRoutes ?? 0 }}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">未覆盖</div>
        <div class="kpi-value num danger">{{ overview?.coverage.uncovered ?? 0 }}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">注解覆盖</div>
        <div class="kpi-value num">{{ overview?.coverage.annotationCovered ?? 0 }}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">待审队列</div>
        <div class="kpi-value num">{{ items.length }}</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">待审队列</div>
          <div class="panel-sub">按风险分数排序的端点，逐条给出判定与信号</div>
        </div>
        <el-input v-model="filter" size="small" placeholder="过滤路由 / 文件 / 判定" style="width: 240px" clearable />
      </div>
      <div class="panel-body flush">
        <el-table :data="filtered" v-loading="loading" size="small" max-height="640" stripe>
          <el-table-column prop="score" label="分数" width="72" align="right">
            <template #default="{ row }">
              <span class="num strong">{{ row.score }}</span>
            </template>
          </el-table-column>
          <el-table-column label="判定" width="200">
            <template #default="{ row }">
              <span class="chip" :class="tone(row.verdict)">{{ row.verdict }}</span>
            </template>
          </el-table-column>
          <el-table-column label="方法" width="80">
            <template #default="{ row }">
              <span class="mono">{{ row.method ?? 'ANY' }}</span>
            </template>
          </el-table-column>
          <el-table-column prop="route" label="路由" min-width="180" show-overflow-tooltip />
          <el-table-column label="位置" min-width="240" show-overflow-tooltip>
            <template #default="{ row }">
              <span class="mono" style="font-size: 10.5px">{{ row.file }}:{{ row.line }}</span>
            </template>
          </el-table-column>
          <el-table-column label="信号" min-width="200">
            <template #default="{ row }">
              <span class="hint">{{ (row.signals ?? []).join(' · ') }}</span>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>
  </div>
</template>

<style scoped>
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
@media (max-width: 1100px) {
  .kpi-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
