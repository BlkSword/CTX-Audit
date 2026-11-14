/**
 * CTX-Audit Console API server.
 *
 * Serves the built SPA and a JSON API over the ctx-audit CLI:
 *   GET  /api/health
 *   GET  /api/workspaces
 *   POST /api/workspaces                  { path, name? }
 *   DELETE /api/workspaces/:id
 *   GET  /api/workspaces/:id/overview     coverage + worklist + chains (one audit run)
 *   GET  /api/workspaces/:id/worklist
 *   GET  /api/workspaces/:id/chains?limit=20
 *   POST /api/workspaces/:id/gate         { base, head, strict? }
 *   GET  /api/workspaces/:id/stream       SSE audit stream
 *
 * Security: loopback only, no shell (argv spawn), workspace paths must exist and
 * be directories, every CLI call is time-bounded and output-capped.
 */
import http from 'node:http'
import { spawn } from 'node:child_process'
import {
  createReadStream,
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { extname, join, normalize, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const ROOT = resolve(HERE, '..')
const DIST = join(ROOT, 'dist')
const STATE_DIR = join(ROOT, '.state')
const STATE_FILE = join(STATE_DIR, 'workspaces.json')
const PORT = Number(process.env['CTX_CONSOLE_PORT'] ?? 4317)
const HOST = process.env['CTX_CONSOLE_HOST'] ?? '127.0.0.1'
const BIN =
  process.env['CTX_AUDIT_BIN'] ?? resolve(ROOT, '..', 'target', 'release', 'ctx-audit.exe')
const CLI_TIMEOUT_MS = Number(process.env['CTX_CONSOLE_CLI_TIMEOUT_MS'] ?? 90000)

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
}

function loadWorkspaces() {
  try {
    const parsed = JSON.parse(readFileSync(STATE_FILE, 'utf8'))
    if (Array.isArray(parsed)) return parsed
  } catch {
    /* first run */
  }
  return []
}

function saveWorkspaces(list) {
  mkdirSync(STATE_DIR, { recursive: true })
  writeFileSync(STATE_FILE, JSON.stringify(list, null, 2), 'utf8')
}

let workspaces = loadWorkspaces()

function slug(p) {
  return (
    p
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 40) || 'workspace'
  )
}

function addWorkspace(inputPath, name) {
  if (!inputPath) throw new Error('path is required')
  const abs = resolve(inputPath)
  if (!existsSync(abs)) throw new Error('path does not exist')
  if (!statSync(abs).isDirectory()) throw new Error('path is not a directory')
  const real = realpathSync(abs)
  const existing = workspaces.find((w) => w.path === real)
  if (existing) return existing
  const ws = {
    id: `${slug(real.split(sep).pop() ?? 'workspace')}-${Math.random().toString(36).slice(2, 7)}`,
    name: name || real.split(sep).pop() || real,
    path: real,
    addedAt: new Date().toISOString(),
  }
  workspaces = [...workspaces, ws]
  saveWorkspaces(workspaces)
  return ws
}

function findWorkspace(id) {
  return workspaces.find((w) => w.id === id)
}

/** Run one ctx-audit CLI command; resolves parsed JSON when possible. */
function runCli(cwd, args) {
  return new Promise((resolvePromise) => {
    const started = Date.now()
    const child = spawn(BIN, args, { cwd, windowsHide: true })
    let stdout = ''
    let stderr = ''
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, CLI_TIMEOUT_MS)
    child.stdout.on('data', (b) => {
      stdout += b.toString('utf8')
      if (stdout.length > 16 * 1024 * 1024) child.kill('SIGKILL')
    })
    child.stderr.on('data', (b) => {
      stderr += b.toString('utf8')
    })
    child.on('error', (err) => {
      clearTimeout(timer)
      resolvePromise({ ok: false, error: String(err), durationMs: Date.now() - started })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      let json
      try {
        json = JSON.parse(stdout)
      } catch {
        json = undefined
      }
      const data = json && typeof json === 'object' && 'data' in json ? json.data : json
      resolvePromise({
        ok: code === 0 && !timedOut,
        exitCode: code,
        timedOut,
        durationMs: Date.now() - started,
        data,
        stdout: json === undefined ? stdout.slice(0, 20000) : undefined,
        stderr: stderr.slice(0, 4000) || undefined,
      })
    })
  })
}

function sendJson(res, status, body) {
  const text = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(text)
}

function readBody(req) {
  return new Promise((resolvePromise, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (c) => {
      size += c.length
      if (size > 256 * 1024) {
        reject(new Error('body too large'))
        req.destroy()
        return
      }
      chunks.push(c)
    })
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim()
      if (!text) return resolvePromise({})
      try {
        resolvePromise(JSON.parse(text))
      } catch {
        reject(new Error('invalid JSON body'))
      }
    })
    req.on('error', reject)
  })
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? '/index.html' : pathname
  const target = normalize(join(DIST, rel))
  if (!target.startsWith(DIST)) {
    res.writeHead(403).end('forbidden')
    return
  }
  const file = existsSync(target) && statSync(target).isFile() ? target : join(DIST, 'index.html')
  if (!existsSync(file)) {
    res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
    res.end('console bundle not built yet — run `npm run build` in console/')
    return
  }
  res.writeHead(200, { 'content-type': MIME[extname(file)] ?? 'application/octet-stream' })
  createReadStream(file).pipe(res)
}

/** One audit run → the console's overview payload. */
function buildOverview(ws, bundle, chainsData, timings) {
  const cov = bundle?.coverage ?? {}
  const worklist = bundle?.worklist ?? []
  const chains = chainsData?.chains ?? []
  const tiers = {}
  for (const c of chains) {
    const t = c?.tier ?? 'unknown'
    tiers[t] = (tiers[t] ?? 0) + 1
  }
  const byVerdict = cov.by_verdict ?? {}
  return {
    workspace: ws,
    generatedAt: new Date().toISOString(),
    timings,
    coverage: {
      methodRoutes: cov.method_routes ?? 0,
      filesIndexed: bundle?.files_indexed ?? 0,
      uncovered: cov.uncovered ?? 0,
      annotationCovered: cov.annotation_covered ?? 0,
      notAnEndpoint: cov.not_an_endpoint ?? 0,
      chainCount: cov.chain_count ?? 0,
      ruleCount: cov.rule_count ?? 0,
      containerFilters: cov.container_filters ?? 0,
      hasPathLevelPolicy: cov.has_path_level_policy ?? false,
      confidence: cov.confidence ?? 'unknown',
      reasons: cov.reasons ?? [],
      byVerdict,
      boundaries: {
        dynamicRegistrations: cov.dynamic_endpoint_registrations ?? 0,
        unmodelledRouteFiles: cov.unmodelled_route_files ?? 0,
        indexTruncated: cov.index_truncated_at_limit ?? false,
        unmodelledStacks: cov.unmodelled_route_stacks ?? null,
      },
    },
    worklist: {
      total: worklist.length,
      top: worklist.slice(0, 40),
    },
    chains: {
      total: chains.length,
      tiers,
      top: chains.slice(0, 20).map((c) => ({
        chainId: c?.chain_id,
        tier: c?.tier,
        controllability: c?.controllability,
        score: c?.score,
        sinkKind: c?.sink?.kind,
        sinkFile: c?.sink?.file,
        sinkLine: c?.sink?.line,
        entryRoute: c?.entry?.route,
        entryMethod: c?.entry?.method,
        steps: Array.isArray(c?.steps) ? c.steps.length : 0,
        guards: Array.isArray(c?.guards) ? c.guards.length : 0,
      })),
      stats: chainsData?.stats ?? {},
    },
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const path = url.pathname

    if (!path.startsWith('/api/')) {
      serveStatic(req, res, path)
      return
    }

    if (path === '/api/health') {
      const probe = await runCli(ROOT, ['--version'])
      return sendJson(res, 200, {
        ok: probe.ok,
        binary: BIN,
        version: (probe.stdout ?? '').trim(),
        workspaces: workspaces.length,
      })
    }

    if (path === '/api/workspaces' && req.method === 'GET') {
      return sendJson(res, 200, { ok: true, workspaces })
    }

    if (path === '/api/workspaces' && req.method === 'POST') {
      const body = await readBody(req)
      try {
        const ws = addWorkspace(String(body.path ?? ''), body.name ? String(body.name) : undefined)
        return sendJson(res, 200, { ok: true, workspace: ws })
      } catch (e) {
        return sendJson(res, 400, { ok: false, error: String(e?.message ?? e) })
      }
    }

    const del = path.match(/^\/api\/workspaces\/([^/]+)$/)
    if (del && req.method === 'DELETE') {
      const before = workspaces.length
      workspaces = workspaces.filter((w) => w.id !== del[1])
      if (workspaces.length !== before) saveWorkspaces(workspaces)
      return sendJson(res, 200, { ok: true, workspaces })
    }

    const m = path.match(/^\/api\/workspaces\/([^/]+)\/([a-z-]+)$/)
    if (m) {
      const ws = findWorkspace(m[1])
      if (!ws) return sendJson(res, 404, { ok: false, error: 'workspace not found' })
      const action = m[2]

      if (action === 'overview' && req.method === 'GET') {
        const audit = await runCli(ws.path, ['audit', ws.path, '-o', 'json', '--limit', '200'])
        if (!audit.ok) {
          return sendJson(res, 200, {
            ok: false,
            error: audit.stderr ?? audit.error ?? 'audit failed',
            durationMs: audit.durationMs,
          })
        }
        const chains = await runCli(ws.path, ['chain', ws.path, '--list', '--limit', '40', '-o', 'json'])
        return sendJson(res, 200, {
          ok: true,
          overview: buildOverview(ws, audit.data, chains.data, {
            auditMs: audit.durationMs,
            chainsMs: chains.durationMs,
          }),
        })
      }

      if (action === 'worklist' && req.method === 'GET') {
        const limit = url.searchParams.get('limit') ?? '200'
        const audit = await runCli(ws.path, ['audit', ws.path, '-o', 'json', '--limit', limit])
        return sendJson(res, 200, {
          ok: audit.ok,
          coverage: audit.data?.coverage ?? null,
          worklist: audit.data?.worklist ?? [],
          durationMs: audit.durationMs,
          error: audit.ok ? undefined : (audit.stderr ?? audit.error),
        })
      }

      if (action === 'chains' && req.method === 'GET') {
        const limit = url.searchParams.get('limit') ?? '20'
        const result = await runCli(ws.path, ['chain', ws.path, '--list', '--limit', limit, '-o', 'json'])
        return sendJson(res, 200, {
          ok: result.ok,
          chains: result.data?.chains ?? [],
          stats: result.data?.stats ?? {},
          durationMs: result.durationMs,
          error: result.ok ? undefined : (result.stderr ?? result.error),
        })
      }

      if (action === 'chain' && req.method === 'GET') {
        const chainId = url.searchParams.get('id') ?? ''
        if (!/^CH-[0-9a-f]{6,}$/i.test(chainId)) {
          return sendJson(res, 400, { ok: false, error: 'invalid chain id' })
        }
        const result = await runCli(ws.path, ['chain', ws.path, '--id', chainId, '-o', 'json'])
        return sendJson(res, 200, {
          ok: result.ok,
          dossier: result.data,
          durationMs: result.durationMs,
          error: result.ok ? undefined : (result.stderr ?? result.error),
        })
      }

      if (action === 'gate' && req.method === 'POST') {
        const body = await readBody(req)
        const args = [
          'gate',
          '--git',
          ws.path,
          '--base',
          String(body.base ?? 'HEAD~1'),
          '--head',
          String(body.head ?? 'HEAD'),
          '-o',
          'json',
          '--no-fail-on-block',
        ]
        if (body.strict) args.push('--strict-sinks')
        const result = await runCli(ws.path, args)
        return sendJson(res, 200, {
          ok: result.ok,
          report: result.data,
          durationMs: result.durationMs,
          error: result.ok ? undefined : (result.stderr ?? result.error),
        })
      }

      if (action === 'stream' && req.method === 'GET') {
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          connection: 'keep-alive',
        })
        const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        send('open', { workspace: ws.id, at: new Date().toISOString() })
        const steps = [
          ['coverage', ['audit', ws.path, '-o', 'json', '--limit', '200']],
          ['chains', ['chain', ws.path, '--list', '--limit', '40', '-o', 'json']],
        ]
        for (const [name, args] of steps) {
          send('step', { name, status: 'running' })
          const r = await runCli(ws.path, args)
          send('step', {
            name,
            status: r.ok ? 'done' : 'failed',
            durationMs: r.durationMs,
            error: r.ok ? undefined : (r.stderr ?? r.error),
          })
        }
        send('done', { at: new Date().toISOString() })
        res.end()
        return
      }

      return sendJson(res, 404, { ok: false, error: 'unknown action' })
    }

    sendJson(res, 404, { ok: false, error: 'not found' })
  } catch (err) {
    try {
      sendJson(res, 500, { ok: false, error: String(err?.message ?? err) })
    } catch {
      /* response already closed */
    }
  }
})

server.listen(PORT, HOST, () => {
  console.log(`[ctx-audit-console] http://${HOST}:${PORT}`)
  console.log(`[ctx-audit-console] binary: ${BIN}`)
  console.log(`[ctx-audit-console] workspaces: ${workspaces.length}`)
})
