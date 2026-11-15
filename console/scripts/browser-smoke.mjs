/**
 * Headless browser smoke test for the console.
 *
 * Drives the installed Chrome over the DevTools protocol (no extra dependency):
 * loads the console, waits for the overview to render real numbers, switches
 * views, runs a validated action, and asserts the DOM reflects each step.
 *
 *   node scripts/browser-smoke.mjs                       # standalone :4317
 *   node scripts/browser-smoke.mjs --url http://127.0.0.1:4321/console/
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
    '--window-size=1440,900',
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

  // Wait for the overview to finish loading (metrics render real numbers).
  let metrics = null
  for (let i = 0; i < 40; i++) {
    metrics = await evaluate(`(() => {
      const els = [...document.querySelectorAll('.metric-value')].map(e => e.textContent.trim())
      return els.length ? els : null
    })()`)
    if (metrics && metrics.length >= 4) break
    await sleep(1000)
  }
  check('overview metrics render', Array.isArray(metrics) && metrics.length >= 4, JSON.stringify(metrics))

  const kpis = await evaluate(`[...document.querySelectorAll('.kpi .v')].map(e => e.textContent.trim())`)
  check('top bar KPIs render', Array.isArray(kpis) && kpis.length >= 4, JSON.stringify(kpis))

  const statusbar = await evaluate(`document.querySelector('.statusbar')?.textContent ?? ''`)
  check('status bar shows engine state', /ENGINE (READY|OFFLINE)/.test(statusbar), statusbar.slice(0, 80))

  // Switch to the chains view and confirm rows appear.
  await evaluate(`(() => {
    const btn = [...document.querySelectorAll('.nav-item')].find(b => b.textContent.includes('候选链'))
    btn?.click()
    return true
  })()`)
  await sleep(1200)
  const chainRows = await evaluate(`document.querySelectorAll('table.data tbody tr').length`)
  check('chains view lists rows', chainRows > 0, `${chainRows} rows`)

  // Switch to the actions view and run the baseline action.
  await evaluate(`(() => {
    const btn = [...document.querySelectorAll('.nav-item')].find(b => b.textContent.includes('能力动作'))
    btn?.click()
    return true
  })()`)
  await sleep(1200)
  const actionButtons = await evaluate(`[...document.querySelectorAll('.btn')].map(b => b.textContent.trim()).filter(Boolean)`)
  check('action catalogue renders', actionButtons.some((t) => t.includes('鉴权基线卡')), `${actionButtons.length} buttons`)

  await evaluate(`(() => {
    const btn = [...document.querySelectorAll('.btn')].find(b => b.textContent.trim() === '鉴权基线卡')
    btn?.click()
    return true
  })()`)
  await sleep(600)
  await evaluate(`(() => {
    const btn = [...document.querySelectorAll('.btn')].find(b => b.textContent.includes('执行'))
    btn?.click()
    return true
  })()`)

  let resultText = ''
  for (let i = 0; i < 40; i++) {
    resultText = await evaluate(`document.querySelector('.logpane')?.textContent ?? ''`)
    if (resultText.includes('chains_total') || resultText.includes('summary')) break
    await sleep(1000)
  }
  check('action executes and returns data', resultText.length > 100, `${resultText.length} chars`)

  // Assistant view must render the brief and the send control.
  await evaluate(`(() => {
    const btn = [...document.querySelectorAll('.nav-item')].find(b => b.textContent.includes('审计助手'))
    btn?.click()
    return true
  })()`)
  await sleep(1500)
  const assistant = await evaluate(`(() => ({
    hasTextarea: Boolean(document.querySelector('textarea.input')),
    hasSend: [...document.querySelectorAll('.btn')].some(b => b.textContent.includes('发送给 Agent')),
    brief: (document.querySelector('textarea.input')?.value ?? '').slice(0, 40),
  }))()`)
  check('assistant view renders brief', assistant.hasTextarea && assistant.hasSend, assistant.brief)

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
