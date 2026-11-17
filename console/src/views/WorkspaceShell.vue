<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useWorkspaceStore } from '../store'

const store = useWorkspaceStore()
const route = useRoute()
const router = useRouter()

const nav = [
  { name: 'overview', label: '总览', icon: 'DataBoard' },
  { name: 'sessions', label: '审计会话', icon: 'Tickets' },
  { name: 'coverage', label: '覆盖与待审', icon: 'Aim' },
  { name: 'chains', label: '候选链', icon: 'Share' },
  { name: 'payload', label: '载荷档位', icon: 'Histogram' },
  { name: 'actions', label: '能力动作', icon: 'SetUp' },
  { name: 'gate', label: '漂移闸门', icon: 'Lock' },
  { name: 'report', label: '报告', icon: 'Document' },
  { name: 'assistant', label: '审计助手', icon: 'ChatDotRound' },
]

const workspaceId = computed(() => String(route.params.id ?? ''))
const workspace = computed(() => store.workspaces.value.find((w) => w.id === workspaceId.value) ?? null)
const overview = computed(() => store.overview.value)
const ledger = computed(() => store.ledger.value)

const kpis = computed(() => {
  const o = overview.value
  if (!o) return []
  return [
    { label: '端点', value: String(o.coverage.methodRoutes), hint: `${o.coverage.filesIndexed} 文件` },
    {
      label: '未覆盖',
      value: String(o.coverage.uncovered),
      hint: `置信 ${o.coverage.confidence}`,
      tone: o.coverage.uncovered > 0 ? 'danger' : 'ok',
    },
    { label: '候选链', value: String(o.chains.total), hint: `载荷存活 ${o.chains.tiers['payload_may_survive'] ?? 0}` },
    {
      label: '会话',
      value: String(ledger.value?.sessions ?? 0),
      hint: `证据 ${ledger.value?.evidenceTotal ?? 0}`,
    },
  ]
})

onMounted(async () => {
  if (store.workspaces.value.length === 0) await store.loadWorkspaces()
  if (workspaceId.value) {
    await Promise.all([store.loadOverview(workspaceId.value), store.loadSessions(workspaceId.value)])
  }
})
</script>

<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand" @click="router.push('/workspaces')">
        <div class="brand-mark">CTX</div>
        <div class="brand-text">
          <div class="brand-name">CTX-Audit</div>
          <div class="brand-sub">审计控制台</div>
        </div>
      </div>

      <div class="ws-switch" @click="router.push('/workspaces')">
        <div class="ws-label">当前工作区</div>
        <div class="ws-name">{{ workspace?.name ?? '未选择' }}</div>
        <div class="ws-path mono">{{ workspace?.path ?? '点击选择工作区' }}</div>
      </div>

      <nav class="nav">
        <RouterLink
          v-for="item in nav"
          :key="item.name"
          :to="{ name: item.name, params: { id: workspaceId } }"
          class="nav-item"
          active-class="active"
        >
          <el-icon class="nav-icon"><component :is="item.icon" /></el-icon>
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar-foot">
        <el-button size="small" text @click="router.push('/workspaces')">切换工作区</el-button>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="topbar-title">{{ route.meta.title ?? '' }}</div>
        <div class="topbar-divider" />
        <div class="kpis">
          <div v-for="k in kpis" :key="k.label" class="topbar-kpi">
            <span class="topbar-kpi-label">{{ k.label }}</span>
            <span class="topbar-kpi-value num" :class="k.tone">{{ k.value }}</span>
          </div>
        </div>
        <div class="spacer" />
        <el-button
          size="small"
          :loading="store.loadingOverview.value"
          @click="store.loadOverview(workspaceId, true)"
        >
          重新分析
        </el-button>
      </header>

      <main class="content">
        <el-alert
          v-if="store.error.value"
          :title="store.error.value"
          type="error"
          show-icon
          :closable="false"
          class="content-alert"
        />
        <RouterView />
      </main>

      <footer class="statusbar">
        <span class="status-dot" />
        <span>ENGINE READY</span>
        <span class="sep">·</span>
        <span class="mono">{{ workspace?.path ?? '-' }}</span>
        <div class="spacer" />
        <span v-if="overview">
          覆盖 {{ overview.timings.auditMs }}ms · 链 {{ overview.timings.chainsMs }}ms
        </span>
        <span v-else>等待分析</span>
      </footer>
    </div>
  </div>
</template>

<style scoped>
.shell {
  display: grid;
  grid-template-columns: var(--sidebar-w) minmax(0, 1fr);
  height: 100%;
}

.sidebar {
  display: flex;
  flex-direction: column;
  background: var(--bg-elevated);
  border-right: 1px solid var(--rule-faint);
  min-height: 0;
}

.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 16px 16px 14px;
  cursor: pointer;
}
.brand-mark {
  width: 32px;
  height: 32px;
  display: grid;
  place-items: center;
  border-radius: var(--r-sm);
  background: rgba(255, 255, 255, 0.08);
  color: var(--text);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.04em;
}
.brand-name {
  font-size: var(--fs-md);
  font-weight: 600;
  letter-spacing: -0.01em;
}
.brand-sub {
  font-size: var(--fs-xs);
  color: var(--text-4);
  margin-top: 1px;
}

.ws-switch {
  margin: 0 12px 12px;
  padding: 10px 12px;
  border-radius: var(--r-sm);
  background: rgba(255, 255, 255, 0.04);
  cursor: pointer;
  transition: background var(--dur-fast) var(--ease);
}
.ws-switch:hover {
  background: rgba(255, 255, 255, 0.07);
}
.ws-label {
  font-size: var(--fs-xs);
  color: var(--text-4);
  letter-spacing: 0.03em;
}
.ws-name {
  font-size: var(--fs-sm);
  font-weight: 600;
  margin-top: 3px;
}
.ws-path {
  font-size: 10px;
  color: var(--text-4);
  margin-top: 2px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 4px 10px;
  overflow: auto;
  flex: 1;
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: var(--r-sm);
  color: var(--text-3);
  font-size: var(--fs-sm);
  transition: background var(--dur-fast) var(--ease), color var(--dur-fast) var(--ease);
}
.nav-item:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--text);
}
.nav-item.active {
  background: rgba(255, 255, 255, 0.09);
  color: var(--text);
  font-weight: 500;
}
.nav-icon {
  font-size: 15px;
  opacity: 0.85;
}

.sidebar-foot {
  padding: 10px 12px 14px;
}

.main {
  display: grid;
  grid-template-rows: var(--topbar-h) minmax(0, 1fr) var(--statusbar-h);
  min-width: 0;
  min-height: 0;
}

.topbar {
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 0 20px;
  border-bottom: 1px solid var(--rule-faint);
  background: var(--bg);
}
.topbar-title {
  font-size: var(--fs-lg);
  font-weight: 600;
  letter-spacing: -0.015em;
}
.topbar-divider {
  width: 1px;
  height: 18px;
  background: var(--rule-strong);
}
.kpis {
  display: flex;
  gap: 22px;
}
.topbar-kpi {
  display: flex;
  align-items: baseline;
  gap: 6px;
}
.topbar-kpi-label {
  font-size: var(--fs-xs);
  color: var(--text-4);
  letter-spacing: 0.03em;
}
.topbar-kpi-value {
  font-size: var(--fs-md);
  font-weight: 600;
}
.topbar-kpi-value.ok {
  color: var(--ok);
}
.topbar-kpi-value.danger {
  color: var(--danger);
}

.content {
  padding: 20px;
  overflow: auto;
  min-height: 0;
}
.content-alert {
  margin-bottom: 14px;
}

.statusbar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 20px;
  border-top: 1px solid var(--rule-faint);
  background: var(--bg);
  font-size: var(--fs-xs);
  color: var(--text-4);
}
.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--ok);
}
.sep {
  color: var(--rule-strong);
}
</style>
