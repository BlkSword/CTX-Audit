import { computed, ref } from 'vue'
import { api } from './api'
import type { Workspace, Overview, WorkspaceLedger, AuditSession } from './api'

/**
 * Workspace-scoped state shared by the shell and its views.
 *
 * The overview is expensive (it shells out to the CLI), so it is cached per
 * workspace and only refreshed on demand or when the workspace changes.
 * A plain module-level singleton is enough here — the console has one store.
 */
const workspaces = ref<Workspace[]>([])
const activeId = ref<string | null>(null)
const overview = ref<Overview | null>(null)
const ledger = ref<WorkspaceLedger | null>(null)
const sessions = ref<AuditSession[]>([])
const loadingOverview = ref(false)
const loadingSessions = ref(false)
const error = ref<string | null>(null)

const active = computed(() => workspaces.value.find((w) => w.id === activeId.value) ?? null)

async function loadWorkspaces(): Promise<void> {
  try {
    const r = await api.listWorkspaces()
    workspaces.value = r.workspaces ?? []
    if (!activeId.value && workspaces.value.length > 0) {
      activeId.value = workspaces.value[0].id
    }
  } catch (e) {
    error.value = String(e)
  }
}

async function addWorkspace(path: string, name?: string): Promise<Workspace | null> {
  try {
    const r = await api.addWorkspace(path, name)
    await loadWorkspaces()
    if (r.workspace) activeId.value = r.workspace.id
    return r.workspace ?? null
  } catch (e) {
    error.value = String(e)
    return null
  }
}

async function removeWorkspace(id: string): Promise<void> {
  try {
    await api.removeWorkspace(id)
    if (activeId.value === id) {
      activeId.value = null
      overview.value = null
      ledger.value = null
      sessions.value = []
    }
    await loadWorkspaces()
  } catch (e) {
    error.value = String(e)
  }
}

async function loadOverview(id: string, force = false): Promise<void> {
  if (!force && overview.value?.workspace.id === id) return
  loadingOverview.value = true
  error.value = null
  try {
    const r = await api.overview(id)
    if (r.ok && r.overview) overview.value = r.overview
    else error.value = r.error ?? '总览加载失败'
  } catch (e) {
    error.value = String(e)
  } finally {
    loadingOverview.value = false
  }
}

async function loadSessions(id: string): Promise<void> {
  loadingSessions.value = true
  try {
    const [l, s] = await Promise.all([api.ledger(id), api.sessions(id)])
    if (l.ok) ledger.value = l.ledger
    if (s.ok) sessions.value = s.sessions
  } catch (e) {
    error.value = String(e)
  } finally {
    loadingSessions.value = false
  }
}

async function runAudit(id: string, budget: number): Promise<AuditSession | null> {
  const r = await api.auditRun(id, {
    triageLimit: 20,
    chainLimit: 20,
    deepLimit: budget,
    label: `一键审计 · 预算 ${budget}`,
  })
  await loadSessions(id)
  if (!r.ok) {
    error.value = r.error ?? '审计失败'
    return null
  }
  return r.session ?? null
}

export function useWorkspaceStore() {
  return {
    workspaces,
    activeId,
    active,
    overview,
    ledger,
    sessions,
    loadingOverview,
    loadingSessions,
    error,
    loadWorkspaces,
    addWorkspace,
    removeWorkspace,
    loadOverview,
    loadSessions,
    runAudit,
  }
}
