/**
 * Audit session store: durable per-workspace audit records.
 *
 * One workspace can hold several audit sessions (e.g. routine sweep, PR review,
 * deep dive). Each session records the workflow run, its evidence entries, the
 * agent conversation id, and any findings the operator promoted.
 *
 * Storage: `<stateDir>/sessions/<workspaceId>.json`, one file per workspace so a
 * corrupt record cannot take down the whole registry.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const MAX_SESSIONS_PER_WORKSPACE = 50
const MAX_EVIDENCE_PER_SESSION = 400

export function createSessionStore(stateDir) {
  const dir = join(stateDir, 'sessions')

  function fileFor(workspaceId) {
    return join(dir, `${workspaceId}.json`)
  }

  function load(workspaceId) {
    try {
      const parsed = JSON.parse(readFileSync(fileFor(workspaceId), 'utf8'))
      if (Array.isArray(parsed)) return parsed
    } catch {
      /* first run or unreadable */
    }
    return []
  }

  function save(workspaceId, sessions) {
    mkdirSync(dir, { recursive: true })
    writeFileSync(fileFor(workspaceId), JSON.stringify(sessions, null, 2), 'utf8')
  }

  function newId() {
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14)
    return `AS-${stamp}-${Math.random().toString(36).slice(2, 6)}`
  }

  /** Create a session record (status starts as `running`). */
  function create(workspaceId, input) {
    const sessions = load(workspaceId)
    const session = {
      id: newId(),
      workspaceId,
      kind: input.kind ?? 'workflow',
      label: input.label ?? '一键审计',
      status: 'running',
      createdAt: new Date().toISOString(),
      finishedAt: null,
      agentSessionId: input.agentSessionId ?? null,
      workflow: null,
      evidence: [],
      findings: [],
      notes: [],
      error: null,
    }
    sessions.unshift(session)
    save(workspaceId, sessions.slice(0, MAX_SESSIONS_PER_WORKSPACE))
    return session
  }

  /** Patch one session; returns the updated record or null when missing. */
  function update(workspaceId, sessionId, patch) {
    const sessions = load(workspaceId)
    const idx = sessions.findIndex((s) => s.id === sessionId)
    if (idx < 0) return null
    const next = { ...sessions[idx], ...patch }
    if (Array.isArray(next.evidence) && next.evidence.length > MAX_EVIDENCE_PER_SESSION) {
      next.evidence = next.evidence.slice(0, MAX_EVIDENCE_PER_SESSION)
      next.evidenceTruncated = true
    }
    sessions[idx] = next
    save(workspaceId, sessions)
    return next
  }

  /** Append evidence entries (idempotent by evidence id). */
  function appendEvidence(workspaceId, sessionId, entries) {
    const sessions = load(workspaceId)
    const idx = sessions.findIndex((s) => s.id === sessionId)
    if (idx < 0) return null
    const session = sessions[idx]
    const seen = new Set(session.evidence.map((e) => e.id))
    for (const entry of entries) {
      if (!entry || typeof entry.id !== 'string' || seen.has(entry.id)) continue
      seen.add(entry.id)
      session.evidence.push(entry)
    }
    if (session.evidence.length > MAX_EVIDENCE_PER_SESSION) {
      session.evidence = session.evidence.slice(0, MAX_EVIDENCE_PER_SESSION)
      session.evidenceTruncated = true
    }
    sessions[idx] = session
    save(workspaceId, sessions)
    return session
  }

  function list(workspaceId) {
    return load(workspaceId)
  }

  function get(workspaceId, sessionId) {
    return load(workspaceId).find((s) => s.id === sessionId) ?? null
  }

  function remove(workspaceId, sessionId) {
    const sessions = load(workspaceId)
    const next = sessions.filter((s) => s.id !== sessionId)
    if (next.length === sessions.length) return false
    save(workspaceId, next)
    return true
  }

  /** Workspace-level ledger: counts and the latest session per kind. */
  function ledger(workspaceId) {
    const sessions = load(workspaceId)
    const byStatus = {}
    const byKind = {}
    let evidenceTotal = 0
    let findingsTotal = 0
    for (const s of sessions) {
      byStatus[s.status] = (byStatus[s.status] ?? 0) + 1
      byKind[s.kind] = (byKind[s.kind] ?? 0) + 1
      evidenceTotal += Array.isArray(s.evidence) ? s.evidence.length : 0
      findingsTotal += Array.isArray(s.findings) ? s.findings.length : 0
    }
    return {
      workspaceId,
      sessions: sessions.length,
      byStatus,
      byKind,
      evidenceTotal,
      findingsTotal,
      latest: sessions.slice(0, 5).map((s) => ({
        id: s.id,
        kind: s.kind,
        label: s.label,
        status: s.status,
        createdAt: s.createdAt,
        finishedAt: s.finishedAt,
        evidence: Array.isArray(s.evidence) ? s.evidence.length : 0,
        findings: Array.isArray(s.findings) ? s.findings.length : 0,
      })),
    }
  }

  return { create, update, appendEvidence, list, get, remove, ledger }
}
