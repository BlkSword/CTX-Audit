<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useWorkspaceStore } from '../store'
import type { AuditSession } from '../api'

const store = useWorkspaceStore()
const route = useRoute()
const workspaceId = computed(() => String(route.params.id ?? ''))
const selectedId = ref<string | null>(null)
const budget = ref(3)
const running = ref(false)

const sessions = computed(() => store.sessions.value)
const ledger = computed(() => store.ledger.value)
const current = computed<AuditSession | null>(
  () => sessions.value.find((s) => s.id === selectedId.value) ?? sessions.value[0] ?? null,
)

const stageRows = computed(() => current.value?.workflow?.stages ?? [])
const evidence = computed(() => current.value?.evidence ?? [])

async function runAudit() {
  running.value = true
  try {
    const s = await store.runAudit(workspaceId.value, budget.value)
    if (s) selectedId.value = s.id
  } finally {
    running.value = false
  }
}

function statusTone(status: string): string {
  return status === 'done' ? 'ok' : status === 'failed' ? 'danger' : 'warn'
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
          <div class="panel-title">审计台账</div>
          <div class="panel-sub">
            {{ ledger?.sessions ?? 0 }} 次会话 · 证据 {{ ledger?.evidenceTotal ?? 0 }} 条 · 发现
            {{ ledger?.findingsTotal ?? 0 }} 条 · 完成 {{ ledger?.byStatus.done ?? 0 }} / 失败
            {{ ledger?.byStatus.failed ?? 0 }}
          </div>
        </div>
        <div class="row">
          <el-select v-model="budget" size="small" style="width: 108px">
            <el-option v-for="n in [1, 2, 3, 5, 8]" :key="n" :label="`预算 ${n}`" :value="n" />
          </el-select>
          <el-button type="primary" size="small" :loading="running" @click="runAudit">一键审计</el-button>
        </div>
      </div>
    </div>

    <div v-if="sessions.length === 0" class="empty">
      <div class="empty-title">还没有审计会话</div>
      <div class="hint">点右上角「一键审计」跑一轮完整 SOP。</div>
    </div>

    <div v-else class="split">
      <div class="panel session-list">
        <div class="panel-head">
          <div class="panel-title">会话列表</div>
        </div>
        <div class="panel-body flush">
          <button
            v-for="s in sessions"
            :key="s.id"
            class="session-item"
            :class="{ active: current?.id === s.id }"
            @click="selectedId = s.id"
          >
            <div class="session-item-top">
              <span class="chip" :class="statusTone(s.status)">{{ s.status }}</span>
              <span class="session-item-label">{{ s.label }}</span>
            </div>
            <div class="session-item-meta">
              <span class="mono">{{ s.id }}</span>
            </div>
            <div class="session-item-meta">
              <span>{{ s.evidence.length }} 证据</span>
              <span v-if="s.durationMs">· {{ (s.durationMs / 1000).toFixed(1) }}s</span>
              <span>· {{ new Date(s.createdAt).toLocaleString() }}</span>
            </div>
          </button>
        </div>
      </div>

      <div class="panel" v-if="current">
        <div class="panel-head">
          <div>
            <div class="panel-title">会话 {{ current.id }}</div>
            <div class="panel-sub">
              {{ current.label }} · 创建 {{ new Date(current.createdAt).toLocaleString() }}
              <span v-if="current.finishedAt"> · 完成 {{ new Date(current.finishedAt).toLocaleString() }}</span>
            </div>
          </div>
          <span class="chip" :class="statusTone(current.status)">{{ current.status }}</span>
        </div>

        <div class="panel-body">
          <el-alert
            v-if="current.error"
            :title="current.error"
            type="error"
            :closable="false"
            show-icon
            style="margin-bottom: 12px"
          />

          <div v-if="stageRows.length" class="section-title">阶段</div>
          <div v-if="stageRows.length" class="stage-row">
            <div v-for="st in stageRows" :key="st.stage" class="stage-card">
              <div class="stage-name">{{ st.stage }}</div>
              <div class="stage-ms num">{{ st.ms }}ms</div>
              <div class="stage-ev num">{{ st.evidence_ids?.length ?? 0 }} 证据</div>
            </div>
          </div>

          <div class="section-title" style="margin-top: 16px">
            证据 · {{ evidence.length }}
          </div>
          <el-table :data="evidence" size="small" max-height="420" stripe>
            <el-table-column prop="id" label="证据 ID" width="150">
              <template #default="{ row }">
                <span class="mono" style="color: var(--accent)">{{ row.id }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="stage" label="阶段" width="100" />
            <el-table-column prop="kind" label="类型" width="150" />
            <el-table-column prop="summary" label="摘要" show-overflow-tooltip />
          </el-table>

          <div v-if="current.workflow?.nextActions?.length" style="margin-top: 14px">
            <div class="section-title">下一步动作</div>
            <div class="row wrap">
              <span
                v-for="(a, i) in current.workflow.nextActions"
                :key="i"
                class="chip accent"
              >
                {{ a.tool }} · {{ a.evidence_id ?? '-' }}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.split {
  display: grid;
  grid-template-columns: 300px minmax(0, 1fr);
  gap: 14px;
  align-items: start;
}
.session-list {
  max-height: 640px;
  overflow: auto;
}
.session-item {
  display: block;
  width: 100%;
  text-align: left;
  padding: 10px 12px;
  background: transparent;
  border: none;
  border-bottom: 1px solid var(--rule-faint);
  border-left: 2px solid transparent;
  color: var(--text-2);
  font: inherit;
  cursor: pointer;
}
.session-item:hover {
  background: var(--surface-2);
}
.session-item.active {
  background: rgba(255, 255, 255, 0.07);
  border-left-color: var(--text-3);
}
.session-item-top {
  display: flex;
  align-items: center;
  gap: 7px;
}
.session-item-label {
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--text);
}
.session-item-meta {
  display: flex;
  gap: 5px;
  font-size: var(--fs-xs);
  color: var(--text-3);
  margin-top: 3px;
}
.stage-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.stage-card {
  padding: 8px 12px;
  border: 1px solid var(--rule);
  border-radius: var(--r-md);
  background: var(--bg-elevated);
  min-width: 108px;
}
.stage-name {
  font-size: var(--fs-xs);
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-3);
}
.stage-ms {
  font-size: var(--fs-lg);
  font-weight: 600;
  margin-top: 2px;
}
.stage-ev {
  font-size: var(--fs-xs);
  color: var(--text-3);
}
@media (max-width: 1100px) {
  .split {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
