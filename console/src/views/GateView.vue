<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import type { GateReport } from '../api'

const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const base = ref('')
const head = ref('')
const strict = ref(false)
const busy = ref(false)
const report = ref<GateReport | null>(null)

async function run() {
  if (!base.value.trim() || !head.value.trim()) {
    ElMessage.warning('需要 base 与 head 两个目录')
    return
  }
  busy.value = true
  report.value = null
  try {
    const r = await api.gate(workspaceId.value, base.value.trim(), head.value.trim(), strict.value)
    if (r.ok && r.report) report.value = r.report
    else ElMessage.error(r.error ?? '闸门执行失败')
  } finally {
    busy.value = false
  }
}

function verdictTone(severity: string): string {
  return severity === 'block' ? 'danger' : 'info'
}
</script>

<template>
  <div class="stack">
    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">PR 漂移闸门</div>
          <div class="panel-sub">对比 base / head 两个目录，判断本次改动是否引入安全漂移</div>
        </div>
        <el-button type="primary" size="small" :loading="busy" @click="run">执行闸门</el-button>
      </div>
      <div class="panel-body">
        <el-form label-position="top">
          <div class="two-col">
            <el-form-item label="base 目录">
              <el-input v-model="base" size="small" placeholder="C:\\path\\to\\base-tree" />
            </el-form-item>
            <el-form-item label="head 目录">
              <el-input v-model="head" size="small" placeholder="C:\\path\\to\\head-tree" />
            </el-form-item>
          </div>
          <el-checkbox v-model="strict">严格模式（受保护接口新增危险汇也阻断）</el-checkbox>
        </el-form>
      </div>
    </div>

    <template v-if="report">
      <div class="kpi-grid">
        <div class="kpi">
          <div class="kpi-label">判决</div>
          <div class="kpi-value" :class="(report.summary?.blocks ?? 0) > 0 ? 'danger' : 'ok'">
            {{ (report.summary?.blocks ?? 0) > 0 ? 'BLOCK' : 'PASS' }}
          </div>
        </div>
        <div class="kpi">
          <div class="kpi-label">阻断项</div>
          <div class="kpi-value num danger">{{ report.summary?.blocks ?? 0 }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">信息项</div>
          <div class="kpi-value num">{{ (report.verdicts ?? []).filter((v) => v.severity === 'info').length }}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">豁免</div>
          <div class="kpi-value num">{{ report.summary?.waived ?? 0 }}</div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">判决明细 · {{ (report.verdicts ?? []).length }}</div>
        </div>
        <div class="panel-body flush">
          <table class="data-table">
            <thead>
              <tr>
                <th>严重度</th>
                <th>类型</th>
                <th>路由</th>
                <th>原因</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(v, i) in report.verdicts ?? []" :key="i">
                <td><span class="chip" :class="verdictTone(v.severity)">{{ v.severity }}</span></td>
                <td class="mono">{{ v.kind }}</td>
                <td class="mono">{{ v.route ?? '-' }}</td>
                <td>{{ v.reason }}</td>
              </tr>
              <tr v-if="(report.verdicts ?? []).length === 0">
                <td colspan="4" class="muted">无判决项</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <div v-else class="empty">
      <div class="empty-title">尚未执行闸门</div>
      <div class="hint">填入 base / head 目录后点「执行闸门」。</div>
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
  gap: 12px;
}
@media (max-width: 1100px) {
  .kpi-grid,
  .two-col {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}
</style>
