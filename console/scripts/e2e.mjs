/**
 * End-to-end verification: boots the console server on an ephemeral port,
 * registers a workspace, and asserts the key surfaces return real data.
 *
 *   node scripts/e2e.mjs                 # uses ../target/release/ctx-audit.exe
 *   node scripts/e2e.mjs --target <dir>  # explicit audit workspace
 */
import http from 'node:http'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const ROOT = resolve(HERE, '..')
const argTarget = process.argv.indexOf('--target')
const WORKSPACE = argTarget > 0 ? resolve(process.argv[argTarget + 1]) : resolve(ROOT, '..')
const BIN = process.env['CTX_AUDIT_BIN'] ?? resolve(ROOT, '..', 'target', 'release', 'ctx-audit.exe')

const checks = []
function check(name, condition, detail) {
  checks.push({ name, ok: Boolean(condition), detail })
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
}

function readBody(req) {
  return new Promise((ok) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim()
      ok(text ? JSON.parse(text) : {})
    })
  })
}

function sendJson(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

const { createConsoleApi } = await import(pathToFileURL(resolve(ROOT, 'server/api.mjs')).href)
const api = createConsoleApi({
  bin: BIN,
  stateDir: resolve(ROOT, '.state-e2e'),
  timeoutMs: 120000,
  cwd: ROOT,
  logger: { warn: () => {} },
})
const server = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost')
  void api.handle(req, res, url.pathname, url, readBody, sendJson)
})

await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
const port = server.address().port
const base = `http://127.0.0.1:${port}`
console.log(`[e2e] server ${base} · workspace ${WORKSPACE}`)

try {
  check('binary exists', existsSync(BIN), BIN)

  const health = await (await fetch(`${base}/health`)).json()
  check('health ok', health.ok === true, health.version)

  const actions = await (await fetch(`${base}/actions`)).json()
  check('action catalogue', Array.isArray(actions.actions) && actions.actions.length >= 11, `${actions.actions.length} actions`)

  const added = await (
    await fetch(`${base}/workspaces`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: WORKSPACE, name: 'e2e' }),
    })
  ).json()
  check('workspace added', Boolean(added.workspace?.id), added.workspace?.id)

  const id = added.workspace.id
  const overview = await (await fetch(`${base}/workspaces/${id}/overview`)).json()
  check('overview ok', overview.ok === true)
  if (overview.ok) {
    const o = overview.overview
    check('endpoints counted', o.coverage.methodRoutes > 0, `${o.coverage.methodRoutes} endpoints`)
    check('worklist present', Array.isArray(o.worklist.top), `${o.worklist.total} rows`)
    check('chains present', Array.isArray(o.chains.top), `${o.chains.total} chains`)
    check('timings reported', o.timings.auditMs > 0, `audit ${o.timings.auditMs}ms + chains ${o.timings.chainsMs}ms`)
  }

  const baseline = await (
    await fetch(`${base}/workspaces/${id}/action/baseline`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ args: {} }),
    })
  ).json()
  check('baseline action', baseline.ok === true && baseline.exitCode === 0, `${baseline.durationMs}ms`)
  check('baseline payload shape', Boolean(baseline.data && 'chains_total' in baseline.data))

  const rejected = await fetch(`${base}/workspaces/${id}/action/chain-dossier`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ args: { id: '../../etc/passwd' } }),
  })
  check('invalid action arg rejected', rejected.status === 400, `status ${rejected.status}`)

  const badWorkspace = await fetch(`${base}/workspaces`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ path: resolve(ROOT, 'no-such-dir') }),
  })
  check('missing workspace rejected', badWorkspace.status === 400, `status ${badWorkspace.status}`)
} finally {
  server.close()
}

const failed = checks.filter((c) => !c.ok)
console.log(`\n[e2e] ${checks.length - failed.length}/${checks.length} checks passed`)
if (failed.length > 0) {
  for (const f of failed) console.error(`  FAILED: ${f.name}`)
  process.exit(1)
}
