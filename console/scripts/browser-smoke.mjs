/**
 * Headless browser smoke test for the console (Vue 3 rewrite).
 *
 * Drives the installed Chrome over the DevTools protocol (no extra dependency):
 * loads the console, walks the workspace picker into a workspace, checks the
 * overview KPIs, runs a one-click audit, visits each view, and asserts the DOM
 * reflects every step.
 */
import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const CHROME_CANDIDATES = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
]

const argUrl = process.argv.indexOf('--url')
const URL_UNDER_TEST = argUrl > 0 ? process.argv[argUrl + 1] : 'http://127.0.0.1:4317/'
const PORT = 9333

const chromePath = CHROME_CANDIDATES.find((p) => existsSync(p))
if (!chromePath) {
  console.error('[smoke] no Chrome/Edge found')
  process.exit(2)
}

const profileDir = mkdtempSync(join(tmpdir(), 'ctx-console-smoke-'))
const chrome = spawn(
  chromePath,
  [
    '--headless=new',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-gpu',
    '--window-size=1600,1000',
    'about:blank',
  ],
  { stdio: 'ignore' },
)

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function cdpTargets() {
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/list`)
      const list = await res.json()
      const page = list.find((t) => t.type === 'page')
      if (page) return page
    } catch {
      /* not up yet */
    }
    await sleep(250)
  }
  throw new Error('devtools endpoint never came up')
}

function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl)
    let id = 0
    const pending = new Map()
    ws.addEventListener('open', () => resolve({ send, close: () => ws.close() }))
    ws.addEventListener('error', reject)
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data)
      if (msg.id && pending.has(msg.id)) {
        const { resolve: ok, reject: fail } = pending.get(msg.id)
        pending.delete(msg.id)
        if (msg.error) fail(new Error(msg.error.message))
        else ok(msg.result)
      }
    })
    function send(method, params = {}) {
      const mid = ++id
      return new Promise((ok, fail) => {
        pending.set(mid, { resolve: ok, reject: fail })
        ws.send(JSON.stringify({ id: mid, method, params }))
      })
    }
  })
}

const checks = []
function check(name, ok, detail) {
  checks.push({ name, ok: Boolean(ok), detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
}

let client
try {
  const target = await cdpTargets()
  client = await connect(target.webSocketDebuggerUrl)
  await client.send('Page.enable')
  await client.send('Runtime.enable')

  const evaluate = async (expression) => {
    const res = await client.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true,
    })
    if (res.exceptionDetails) throw new Error(res.exceptionDetails.text ?? 'eval failed')
    return res.result.value
  }

  await client.send('Page.navigate', { url: URL_UNDER_TEST })
  await sleep(2500)

  const title = await evaluate('document.title')
  check('page loads', title.includes('CTX-Audit'), title)

  const picker = await evaluate(`(() => {
    const cards = document.querySelectorAll('.ws-card').length
    const empty = Boolean(document.querySelector('.empty-title'))
    const heading = document.querySelector('.picker-title')?.textContent ?? ''
    return { cards, empty, heading }
  })()`)
  check('workspace picker renders', picker.cards > 0 || picker.empty, JSON.stringify(picker))

  const entered = await evaluate(`(() => {
    const card = document.querySelector('.ws-card')
    if (!card) return false
    card.click()
    return true
  })()`)
  await sleep(2500)
  const shell = await evaluate(`(() => ({
    hasSidebar: Boolean(document.querySelector('.sidebar')),
    hasTopbar: Boolean(document.querySelector('.topbar')),
    hasStatusbar: Boolean(document.querySelector('.statusbar')),
    navItems: document.querySelectorAll('.nav-item').length,
    hash: location.hash,
  }))()`)
  check(
    'workspace shell renders',
    entered && shell.hasSidebar && shell.hasTopbar && shell.hasStatusbar && shell.navItems >= 9,
    JSON.stringify(shell),
  )

  let kpis = null
  for (let i = 0; i < 40; i++) {
    kpis = await evaluate(`[...document.querySelectorAll('.kpi-value')].map(e => e.textContent.trim())`)
    if (kpis && kpis.length >= 4) break
    await sleep(1000)
  }
  check('overview KPIs render', Array.isArray(kpis) && kpis.length >= 4, JSON.stringify(kpis))

  const topbarKpis = await evaluate(
    `[...document.querySelectorAll('.topbar-kpi-value')].map(e => e.textContent.trim())`,
  )
  check('topbar KPI strip renders', Array.isArray(topbarKpis) && topbarKpis.length >= 4, JSON.stringify(topbarKpis))

  // The session KPI is the ledger count; the pill strip is capped, so compare the
  // KPI rather than the number of rendered pills.
  const sessionKpi = () =>
    evaluate(`(() => {
      const kpis = [...document.querySelectorAll('.kpi')]
      const k = kpis.find(el => el.textContent.includes('审计会话'))
      return k ? Number(k.querySelector('.kpi-value')?.textContent.trim() ?? '0') : -1
    })()`)
  const before = await sessionKpi()
  await evaluate(`(() => {
    const btn = [...document.querySelectorAll('.el-button')].find(b => b.textContent.includes('一键审计'))
    btn?.click()
    return true
  })()`)
  let auditDone = false
  let after = before
  for (let i = 0; i < 150; i++) {
    const state = await evaluate(`(() => ({
      busy: [...document.querySelectorAll('.el-button')].some(b => b.classList.contains('is-loading')),
    }))()`)
    after = await sessionKpi()
    if (!state.busy && after > before) {
      auditDone = true
      break
    }
    await sleep(1000)
  }
  check('one-click audit runs and stores a session', auditDone, `sessions ${before} -> ${after}`)

  const views = ['审计会话', '覆盖与待审', '候选链', '载荷档位', '能力动作', '漂移闸门', '报告', '审计助手']
  const visited = []
  for (const label of views) {
    const ok = await evaluate(`(() => {
      const item = [...document.querySelectorAll('.nav-item')].find(a => a.textContent.includes(${JSON.stringify(label)}))
      if (!item) return false
      item.click()
      return true
    })()`)
    await sleep(1400)
    const rendered = await evaluate(`(() => ({
      panels: document.querySelectorAll('.panel').length,
      hash: location.hash,
    }))()`)
    visited.push({ label, ok, panels: rendered.panels, hash: rendered.hash })
  }
  const allVisited = visited.every((v) => v.ok && v.panels > 0)
  check('all views navigate and render', allVisited, JSON.stringify(visited.map((v) => `${v.label}:${v.panels}`)))

  await evaluate(`(() => {
    const item = [...document.querySelectorAll('.nav-item')].find(a => a.textContent.includes('审计会话'))
    item?.click()
    return true
  })()`)
  await sleep(1600)
  const sessionView = await evaluate(`(() => ({
    items: document.querySelectorAll('.session-item').length,
    evidenceRows: document.querySelectorAll('.el-table__row').length,
  }))()`)
  check(
    'session view lists sessions and evidence',
    sessionView.items > 0 && sessionView.evidenceRows > 0,
    JSON.stringify(sessionView),
  )

  const errors = await evaluate(`window.__smokeErrors ?? []`)
  check('no uncaught page errors', !Array.isArray(errors) || errors.length === 0, JSON.stringify(errors))
} finally {
  try {
    client?.close()
  } catch {
    /* ignore */
  }
  chrome.kill()
  await sleep(500)
  try {
    rmSync(profileDir, { recursive: true, force: true })
  } catch {
    /* ignore */
  }
}

const failed = checks.filter((c) => !c.ok)
console.log(`\n[smoke] ${checks.length - failed.length}/${checks.length} checks passed`)
if (failed.length > 0) process.exit(1)
