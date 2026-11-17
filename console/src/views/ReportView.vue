<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { useWorkspaceStore } from '../store'

const store = useWorkspaceStore()
const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const busy = ref(false)
const markdown = ref('')

const overview = computed(() => store.overview.value)
const ledger = computed(() => store.ledger.value)

async function generate() {
  busy.value = true
  try {
    const r = await api.runAction(workspaceId.value, 'report', {})
    if (r.ok) {
      markdown.value = String(r.stdout ?? r.data ?? '')
      ElMessage.success('报告已生成')
    } else {
      ElMessage.error(r.error ?? r.stderr ?? '生成失败')
    }
  } finally {
    busy.value = false
  }
}

function copy() {
  void navigator.clipboard?.writeText(markdown.value)
  ElMessage.success('已复制到剪贴板')
}

onMounted(async () => {
  await store.loadSessions(workspaceId.value)
})
</script>

<template>
  <div class="stack">
    <div class="panel">
      <div class="panel-head">
        <div>
          <div class="panel-title">审计报告</div>
          <div class="panel-sub">汇总当前工作区的覆盖、链、载荷与会话台账</div>
        </div>
        <div class="row">
          <el-button size="small" :disabled="!markdown" @click="copy">复制</el-button>
          <el-button type="primary" size="small" :loading="busy" @click="generate">生成报告</el-button>
        </div>
      </div>
      <div class="panel-body">
        <div class="summary-grid">
          <div class="summary-item">
            <div class="summary-label">端点</div>
            <div class="summary-value num">{{ overview?.coverage.methodRoutes ?? 0 }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">未覆盖</div>
            <div class="summary-value num danger">{{ overview?.coverage.uncovered ?? 0 }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">候选链</div>
            <div class="summary-value num">{{ overview?.chains.total ?? 0 }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">审计会话</div>
            <div class="summary-value num">{{ ledger?.sessions ?? 0 }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">证据</div>
            <div class="summary-value num">{{ ledger?.evidenceTotal ?? 0 }}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">发现</div>
            <div class="summary-value num">{{ ledger?.findingsTotal ?? 0 }}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel" v-if="markdown">
      <div class="panel-head">
        <div class="panel-title">报告内容</div>
      </div>
      <div class="panel-body">
        <pre class="report-md mono">{{ markdown }}</pre>
      </div>
    </div>

    <div v-else class="empty">
      <div class="empty-title">尚未生成报告</div>
      <div class="hint">点右上角「生成报告」汇总当前工作区。</div>
    </div>
  </div>
</template>

<style scoped>
.summary-grid {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 10px;
}
.summary-item {
  padding: 10px 12px;
  border: 1px solid var(--rule);
  border-radius: var(--r-md);
  background: var(--bg-elevated);
}
.summary-label {
  font-size: var(--fs-xs);
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-3);
}
.summary-value {
  font-size: var(--fs-xl);
  font-weight: 600;
  margin-top: 3px;
}
.summary-value.danger {
  color: var(--danger);
}
.report-md {
  font-size: 11px;
  line-height: 1.7;
  color: var(--text-2);
  background: var(--bg-elevated);
  border: 1px solid var(--rule-faint);
  border-radius: var(--r-md);
  padding: 14px;
  max-height: 620px;
  overflow: auto;
  margin: 0;
  white-space: pre-wrap;
}
@media (max-width: 1100px) {
  .summary-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
}
</style>
