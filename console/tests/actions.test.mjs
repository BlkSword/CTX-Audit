import test from 'node:test'
import assert from 'node:assert/strict'
import { actionCatalogue, findAction, validateActionArgs } from '../server/actions.mjs'

const ws = { path: 'C:/project/demo' }

test('catalogue exposes every action with typed arguments', () => {
  const catalogue = actionCatalogue()
  assert.ok(catalogue.length >= 10)
  const byId = new Map(catalogue.map((a) => [a.id, a]))
  for (const id of ['audit', 'chains', 'chain-dossier', 'explain-route', 'payload', 'baseline', 'signal-chain', 'diff-routes', 'gate', 'scan', 'report']) {
    assert.ok(byId.has(id), `missing action ${id}`)
  }
  // catalogue must not leak the argv builder
  for (const action of catalogue) {
    assert.equal(action.build, undefined)
    for (const arg of action.args) assert.equal(typeof arg.name, 'string')
  }
})

test('valid arguments build the expected argv', () => {
  const audit = findAction('audit')
  const checked = validateActionArgs(audit, { limit: '50' })
  assert.equal(checked.ok, true)
  assert.deepEqual(audit.build(ws, checked.args), ['audit', ws.path, '-o', 'json', '--limit', '50'])

  const gate = findAction('gate')
  const gateArgs = validateActionArgs(gate, { base: 'HEAD~1', head: 'HEAD', strict: '1' })
  assert.equal(gateArgs.ok, true)
  assert.deepEqual(gate.build(ws, gateArgs.args), [
    'gate',
    '--git',
    ws.path,
    '--base',
    'HEAD~1',
    '--head',
    'HEAD',
    '-o',
    'json',
    '--no-fail-on-block',
    '--strict-sinks',
  ])
})

test('required arguments are enforced', () => {
  const checked = validateActionArgs(findAction('chain-dossier'), {})
  assert.equal(checked.ok, false)
  assert.match(String(checked.error), /missing required argument: id/)
})

test('shape patterns reject traversal and shell-ish values', () => {
  const dossier = findAction('chain-dossier')
  for (const bad of ['../../etc/passwd', 'CH-zzz', '$(rm -rf /)', 'CH-12345;rm']) {
    const checked = validateActionArgs(dossier, { id: bad })
    assert.equal(checked.ok, false, `expected rejection for ${bad}`)
  }
  const route = findAction('explain-route')
  assert.equal(validateActionArgs(route, { route: 'admin' }).ok, false)
  assert.equal(validateActionArgs(route, { route: '/admin' }).ok, true)
})

test('over-long and non-string arguments are rejected', () => {
  const audit = findAction('audit')
  assert.equal(validateActionArgs(audit, { limit: 'x'.repeat(500) }).ok, false)
  assert.equal(validateActionArgs(audit, { limit: 7 }).ok, false)
  assert.equal(validateActionArgs(audit, undefined).ok, true)
})

test('report action requires a directory-shaped source', () => {
  const report = findAction('report')
  assert.equal(validateActionArgs(report, {}).ok, false)
  assert.equal(validateActionArgs(report, { from: 'C:/tmp/artifacts' }).ok, true)
})
