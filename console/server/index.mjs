/**
 * CTX-Audit Console standalone server: serves the built SPA and the console API.
 *
 * The API implementation lives in ./api.mjs so the DSH host plugin can mount the
 * exact same surface under /api/console/*.
 */
import http from 'node:http'
import { createReadStream, existsSync, statSync } from 'node:fs'
import { extname, join, normalize, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createConsoleApi } from './api.mjs'

const HERE = fileURLToPath(new URL('.', import.meta.url))
const ROOT = resolve(HERE, '..')
const DIST = join(ROOT, 'dist')
const PORT = Number(process.env['CTX_CONSOLE_PORT'] ?? 4317)
const HOST = process.env['CTX_CONSOLE_HOST'] ?? '127.0.0.1'
const BIN = process.env['CTX_AUDIT_BIN'] ?? resolve(ROOT, '..', 'target', 'release', 'ctx-audit.exe')

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

const api = createConsoleApi({
  bin: BIN,
  stateDir: join(ROOT, '.state'),
  timeoutMs: Number(process.env['CTX_CONSOLE_CLI_TIMEOUT_MS'] ?? 90000),
  cwd: ROOT,
  logger: console,
})

function sendJson(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(JSON.stringify(body))
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

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const path = url.pathname
    if (!path.startsWith('/api/')) {
      serveStatic(req, res, path)
      return
    }
    await api.handle(req, res, path.slice('/api'.length), url, readBody, sendJson)
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
  console.log(`[ctx-audit-console] workspaces: ${api.listWorkspaces().length}`)
})
