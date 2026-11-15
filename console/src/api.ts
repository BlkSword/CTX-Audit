/** Typed client for the console API. */

export interface Workspace {
  id: string
  name: string
  path: string
  addedAt: string
}

export interface Coverage {
  methodRoutes: number
  filesIndexed: number
  uncovered: number
  annotationCovered: number
  notAnEndpoint: number
  chainCount: number
  ruleCount: number
  containerFilters: number
  hasPathLevelPolicy: boolean
  confidence: string
  reasons: string[]
  byVerdict: Record<string, number>
  boundaries: {
    dynamicRegistrations: number
    unmodelledRouteFiles: number
    indexTruncated: boolean
    unmodelledStacks: unknown
  }
}

export interface WorklistItem {
  score: number
  signals: string[]
  method: string | null
  route: string | null
  file: string | null
  line: number | null
  verdict: string
  global_match: unknown
  coverage_caveat: string | null
  annotation_covered_by: string | null
  unmodelled_stack: string | null
}

export interface ChainRow {
  chainId: string
  tier: string
  controllability: string
  score: number
  sinkKind: string
  sinkFile: string
  sinkLine: number
  entryRoute: string | null
  entryMethod: string | null
  steps: number
  guards: number
}

export interface Overview {
  workspace: Workspace
  generatedAt: string
  timings: { auditMs: number; chainsMs: number }
  coverage: Coverage
  worklist: { total: number; top: WorklistItem[] }
  chains: { total: number; tiers: Record<string, number>; top: ChainRow[]; stats: Record<string, number> }
}

export interface ChainStep {
  file: string
  line: number
  symbol: string
  role: string
  edge?: string
  certainty?: string
  expr?: string
}

export interface ChainDossier {
  chain_id: string
  tier: string
  score: number
  controllability: string
  controllability_basis?: unknown
  entry: { file?: string; line?: number; route?: string; method?: string } | null
  sink: { file?: string; line?: number; kind?: string; expr?: string }
  steps: ChainStep[]
  guards: Array<{ kind?: string; line?: number; verdict?: string; evidence?: string; file?: string }>
  breakpoints: Array<{ kind?: string; at?: string; confidence?: string }>
  falsify?: unknown
  uncertainty?: unknown
  verdict_candidates?: unknown
}

export interface ActionArgSpec {
  name: string
  required: boolean
  hint: string
}

export interface ActionSpec {
  id: string
  label: string
  description: string
  args: ActionArgSpec[]
}

export interface ActionResult {
  ok: boolean
  action?: string
  argv?: string[]
  exitCode?: number | null
  timedOut?: boolean
  durationMs?: number
  data?: unknown
  stdout?: string
  stderr?: string
  error?: string
}

export interface AuditEvidence {
  id: string
  stage: string
  kind: string
  summary?: string
  data?: unknown
}

export interface AuditFinding {
  id: string
  title: string
  severity: string
  evidenceIds: string[]
  note: string
  createdAt: string
}

export interface AuditSession {
  id: string
  workspaceId: string
  kind: string
  label: string
  status: 'running' | 'done' | 'failed'
  createdAt: string
  finishedAt: string | null
  durationMs?: number
  agentSessionId: string | null
  workflow: {
    stages: Array<{ stage: string; status: string; ms: number; evidence_ids?: string[] }>
    evidenceCounts: Record<string, number>
    nextActions: Array<{ kind: string; tool: string; hint: string; evidence_id?: string }>
    limits: unknown[]
    stoppedAfter: string | null
  } | null
  evidence: AuditEvidence[]
  findings: AuditFinding[]
  notes: string[]
  error: string | null
}

export interface WorkspaceLedger {
  workspaceId: string
  sessions: number
  byStatus: Record<string, number>
  byKind: Record<string, number>
  evidenceTotal: number
  findingsTotal: number
  latest: Array<{
    id: string
    kind: string
    label: string
    status: string
    createdAt: string
    finishedAt: string | null
    evidence: number
    findings: number
  }>
}

export interface GateVerdict {
  severity: string
  kind: string
  reason: string
  evidence?: unknown
}

export interface GateReport {
  schema?: string
  summary?: { blocks?: number; waived?: number; exit_code?: number }
  verdicts?: GateVerdict[]
  duration_ms?: number
}

/**
 * API base: the console runs standalone at `/` (API at `/api`) and embedded in
 * the DSH web surface at `/console` (API at `/api/console`).
 */
export const API_BASE = window.location.pathname.startsWith('/console') ? '/api/console' : '/api'

async function json<T>(res: Response): Promise<T> {
  const body = await res.json()
  if (!res.ok) throw new Error((body as { error?: string })?.error ?? `HTTP ${res.status}`)
  return body as T
}

export const api = {
  health: () => fetch(`${API_BASE}/health`).then((r) => json<{ ok: boolean; binary: string; version: string; workspaces: number }>(r)),

  listWorkspaces: () => fetch(`${API_BASE}/workspaces`).then((r) => json<{ ok: boolean; workspaces: Workspace[] }>(r)),

  addWorkspace: (path: string, name?: string) =>
    fetch(`${API_BASE}/workspaces`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path, name }),
    }).then((r) => json<{ ok: boolean; workspace: Workspace }>(r)),

  removeWorkspace: (id: string) =>
    fetch(`${API_BASE}/workspaces/${id}`, { method: 'DELETE' }).then((r) => json<{ ok: boolean; workspaces: Workspace[] }>(r)),

  overview: (id: string) =>
    fetch(`${API_BASE}/workspaces/${id}/overview`).then((r) =>
      json<{ ok: boolean; overview?: Overview; error?: string; durationMs?: number }>(r),
    ),

  worklist: (id: string, limit = 200) =>
    fetch(`${API_BASE}/workspaces/${id}/worklist?limit=${limit}`).then((r) =>
      json<{ ok: boolean; coverage: Coverage | null; worklist: WorklistItem[]; error?: string }>(r),
    ),

  chains: (id: string, limit = 20) =>
    fetch(`${API_BASE}/workspaces/${id}/chains?limit=${limit}`).then((r) =>
      json<{ ok: boolean; chains: ChainRow[]; stats: Record<string, number>; error?: string }>(r),
    ),

  chain: (id: string, chainId: string) =>
    fetch(`${API_BASE}/workspaces/${id}/chain?id=${encodeURIComponent(chainId)}`).then((r) =>
      json<{ ok: boolean; dossier?: ChainDossier; error?: string; durationMs?: number }>(r),
    ),

  gate: (id: string, base: string, head: string, strict: boolean) =>
    fetch(`${API_BASE}/workspaces/${id}/gate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ base, head, strict }),
    }).then((r) => json<{ ok: boolean; report?: GateReport; error?: string; durationMs?: number }>(r)),

  actions: () => fetch(`${API_BASE}/actions`).then((r) => json<{ ok: boolean; actions: ActionSpec[] }>(r)),

  runAction: (id: string, actionId: string, args: Record<string, string>) =>
    fetch(`${API_BASE}/workspaces/${id}/action/${actionId}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ args }),
    }).then((r) => json<ActionResult>(r)),

  agentStatus: (cwd: string, replies = false) =>
    fetch(`${API_BASE}/agent?cwd=${encodeURIComponent(cwd)}${replies ? '&replies=1' : ''}`).then((r) =>
      json<{
        ok: boolean
        sessionId: string | null
        available?: boolean
        replies?: Array<{ at?: number; text: string; kind?: 'assistant' | 'tool'; tool?: string }>
        error?: string
      }>(r),
    ),

  agentPrompt: (cwd: string, text: string) =>
    fetch(`${API_BASE}/agent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ cwd, text }),
    }).then((r) => json<{ ok: boolean; sessionId?: string; created?: boolean; accepted?: boolean; error?: string }>(r)),

  addActionEvidence: (
    id: string,
    payload: { action: string; summary: string; data?: unknown; id?: string },
  ) =>
    fetch(`${API_BASE}/workspaces/${id}/evidence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    }).then((r) =>
      json<{ ok: boolean; sessionId: string; evidenceId: string; error?: string }>(r),
    ),

  sessions: (id: string) =>
    fetch(`${API_BASE}/workspaces/${id}/sessions`).then((r) =>
      json<{ ok: boolean; sessions: AuditSession[] }>(r),
    ),

  session: (id: string, sessionId: string) =>
    fetch(`${API_BASE}/workspaces/${id}/sessions/${sessionId}`).then((r) =>
      json<{ ok: boolean; session: AuditSession }>(r),
    ),

  ledger: (id: string) =>
    fetch(`${API_BASE}/workspaces/${id}/ledger`).then((r) =>
      json<{ ok: boolean; ledger: WorkspaceLedger }>(r),
    ),

  auditRun: (id: string, opts: { triageLimit?: number; chainLimit?: number; deepLimit?: number; label?: string }) =>
    fetch(`${API_BASE}/workspaces/${id}/audit-run`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(opts),
    }).then((r) =>
      json<{ ok: boolean; session?: AuditSession; evidenceCount?: number; durationMs?: number; error?: string }>(r),
    ),

  addEvidence: (id: string, sessionId: string, evidence: AuditEvidence[]) =>
    fetch(`${API_BASE}/workspaces/${id}/sessions/${sessionId}/evidence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ evidence }),
    }).then((r) => json<{ ok: boolean; session: AuditSession }>(r)),

  addFinding: (
    id: string,
    sessionId: string,
    finding: { title: string; severity: string; evidenceIds: string[]; note: string },
  ) =>
    fetch(`${API_BASE}/workspaces/${id}/sessions/${sessionId}/findings`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(finding),
    }).then((r) => json<{ ok: boolean; session: AuditSession; finding: AuditFinding }>(r)),

  /** Subscribe to the audit stream; returns an unsubscribe function. */
  stream(id: string, onEvent: (event: string, data: unknown) => void): () => void {
    const es = new EventSource(`${API_BASE}/workspaces/${id}/stream`)
    const names = ['open', 'step', 'done']
    for (const name of names) {
      es.addEventListener(name, (ev) => {
        try {
          onEvent(name, JSON.parse((ev as MessageEvent).data))
        } catch {
          onEvent(name, (ev as MessageEvent).data)
        }
      })
    }
    es.onerror = () => onEvent('error', { message: 'stream disconnected' })
    return () => es.close()
  },
}
