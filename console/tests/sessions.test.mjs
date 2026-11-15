import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createSessionStore } from '../server/sessions.mjs'

function withStore(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'ctx-sessions-'))
  try {
    return fn(createSessionStore(dir), dir)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('creates a session with a stable id and running status', () => {
  withStore((store) => {
    const s = store.create('ws-1', { kind: 'workflow', label: 'routine' })
    assert.match(s.id, /^AS-\d{14}-[a-z0-9]{4}$/)
    assert.equal(s.status, 'running')
    assert.equal(s.kind, 'workflow')
    assert.equal(s.label, 'routine')
    assert.deepEqual(s.evidence, [])
    assert.equal(store.list('ws-1').length, 1)
  })
})

test('updates a session and persists it across store instances', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ctx-sessions-'))
  try {
    const store = createSessionStore(dir)
    const s = store.create('ws-1', {})
    store.update('ws-1', s.id, { status: 'done', durationMs: 1234 })
    const reopened = createSessionStore(dir)
    const loaded = reopened.get('ws-1', s.id)
    assert.equal(loaded.status, 'done')
    assert.equal(loaded.durationMs, 1234)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('appends evidence idempotently by id', () => {
  withStore((store) => {
    const s = store.create('ws-1', {})
    store.appendEvidence('ws-1', s.id, [
      { id: 'EV-a', stage: 'coverage', kind: 'coverage_summary' },
      { id: 'EV-b', stage: 'triage', kind: 'route_triage' },
    ])
    store.appendEvidence('ws-1', s.id, [
      { id: 'EV-a', stage: 'coverage', kind: 'coverage_summary' },
      { id: 'EV-c', stage: 'chains', kind: 'candidate_chain' },
    ])
    const loaded = store.get('ws-1', s.id)
    assert.deepEqual(
      loaded.evidence.map((e) => e.id),
      ['EV-a', 'EV-b', 'EV-c'],
    )
  })
})

test('rejects evidence entries without a string id', () => {
  withStore((store) => {
    const s = store.create('ws-1', {})
    store.appendEvidence('ws-1', s.id, [{ stage: 'x' }, { id: 42 }, null])
    assert.equal(store.get('ws-1', s.id).evidence.length, 0)
  })
})

test('ledger aggregates counts and latest sessions', () => {
  withStore((store) => {
    const a = store.create('ws-1', { kind: 'workflow', label: 'a' })
    store.update('ws-1', a.id, { status: 'done' })
    store.appendEvidence('ws-1', a.id, [{ id: 'EV-1' }, { id: 'EV-2' }])
    const b = store.create('ws-1', { kind: 'pr-review', label: 'b' })
    store.update('ws-1', b.id, { status: 'failed' })
    const ledger = store.ledger('ws-1')
    assert.equal(ledger.sessions, 2)
    assert.equal(ledger.byStatus.done, 1)
    assert.equal(ledger.byStatus.failed, 1)
    assert.equal(ledger.byKind.workflow, 1)
    assert.equal(ledger.byKind['pr-review'], 1)
    assert.equal(ledger.evidenceTotal, 2)
    assert.equal(ledger.latest.length, 2)
    assert.equal(ledger.latest[0].id, b.id)
  })
})

test('removes a session and reports missing ids', () => {
  withStore((store) => {
    const s = store.create('ws-1', {})
    assert.equal(store.remove('ws-1', s.id), true)
    assert.equal(store.remove('ws-1', s.id), false)
    assert.equal(store.list('ws-1').length, 0)
    assert.equal(store.update('ws-1', 'AS-missing', { status: 'done' }), null)
  })
})

test('workspaces are isolated from each other', () => {
  withStore((store) => {
    const a = store.create('ws-a', { label: 'a' })
    store.create('ws-b', { label: 'b' })
    assert.equal(store.list('ws-a').length, 1)
    assert.equal(store.list('ws-b').length, 1)
    assert.equal(store.get('ws-b', a.id), null)
  })
})
