/**
 * Shared console API: workspace registry + ctx-audit CLI bridge.
 *
 * Used by both the standalone server (`server/index.mjs`) and the DSH host
 * plugin (`dsh-host/index.js`), so the two surfaces cannot drift.
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from 'node:fs'
import { join, resolve, sep } from 'node:path'

const DEFAULT_TIMEOUT_MS = 90000

export function createConsoleApi(options) {
  const bin = options.bin
  const stateDir = options.stateDir
  const stateFile = join(stateDir, 'workspaces.json')
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const logger = options.logger ?? { warn: () => {} }

  function loadWorkspaces() {
    try {
      const parsed = JSON.parse(readFileSync(stateFile, 'utf8'))
      if (Array.isArray(parsed)) return parsed
    } catch {
      /* first run */
    }
    return []
  }

  function saveWorkspaces(list) {
    mkdirSync(stateDir, { recursive: true })
    writeFileSync(stateFile, JSON.stringify(list, null, 2), 'utf8')
  }

  let workspaces = loadWorkspaces()

  const slug = (p) =>
    p
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 40) || 'workspace'

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

  const findWorkspace = (id) => workspaces.find((w) => w.id === id)

  function runCli(cwd, args) {
    return new Promise((resolvePromise) => {
      const started = Date.now()
      const child = spawn(bin, args, { cwd, windowsHide: true })
      let stdout = ''
      let stderr = ''
      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        child.kill('SIGKILL')
      }, timeoutMs)
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

  function buildOverview(ws, bundle, chainsData, timings) {
    const cov = bundle?.coverage ?? {}
    const worklist = bundle?.worklist ?? []
    const chains = chainsData?.chains ?? []
    const tiers = {}
    for (const c of chains) {
      const t = c?.tier ?? 'unknown'
      tiers[t] = (tiers[t] ?? 0) + 1
    }
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
        byVerdict: cov.by_verdict ?? {},
        boundaries: {
          dynamicRegistrations: cov.dynamic_endpoint_registrations ?? 0,
          unmodelledRouteFiles: cov.unmodelled_route_files ?? 0,
          indexTruncated: cov.index_truncated_at_limit ?? false,
          unmodelledStacks: cov.unmodelled_route_stacks ?? null,
        },
      },
      worklist: { total: worklist.length, top: worklist.slice(0, 40) },
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

  /**
   * Handle one API request. `path` is the path *after* the mount prefix
   * (e.g. `/health`), so the same handler serves `/api/*` standalone and
   * `/api/console/*` inside DSH.
   */
  async function handle(req, res, path, url, readBody, sendJson) {
    if (path === '/health') {
      const probe = await runCli(options.cwd ?? process.cwd(), ['--version'])
      return sendJson(res, 200, {
        ok: probe.ok,
        binary: bin,
        version: (probe.stdout ?? '').trim(),
        workspaces: workspaces.length,
      })
    }

    if (path === '/workspaces' && req.method === 'GET') {
      return sendJson(res, 200, { ok: true, workspaces })
    }

    if (path === '/workspaces' && req.method === 'POST') {
      const body = await readBody(req)
      try {
        const ws = addWorkspace(String(body.path ?? ''), body.name ? String(body.name) : undefined)
        return sendJson(res, 200, { ok: true, workspace: ws })
      } catch (e) {
        return sendJson(res, 400, { ok: false, error: String(e?.message ?? e) })
      }
    }

    const del = path.match(/^\/workspaces\/([^/]+)$/)
    if (del && req.method === 'DELETE') {
      const before = workspaces.length
      workspaces = workspaces.filter((w) => w.id !== del[1])
      if (workspaces.length !== before) saveWorkspaces(workspaces)
      return sendJson(res, 200, { ok: true, workspaces })
    }

    const m = path.match(/^\/workspaces\/([^/]+)\/([a-z-]+)$/)
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
  }

  return { handle, runCli, listWorkspaces: () => workspaces, logger }
}
