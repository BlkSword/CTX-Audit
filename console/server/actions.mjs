/**
 * Action registry: maps CTX-Audit capabilities to console page actions.
 *
 * Every action is a whitelisted CLI invocation with typed arguments; the server
 * validates the action id and argument shapes before spawning, so the browser
 * can never compose an arbitrary command line.
 */

/** @typedef {{ id: string, label: string, description: string, args: Array<{name: string, required?: boolean, pattern?: RegExp, hint?: string}>, build: (ws: {path: string}, args: Record<string, string>) => string[] }} Action */

/** @type {Action[]} */
export const ACTIONS = [
  {
    id: 'audit',
    label: '审计驾驶舱',
    description: '覆盖率摘要 + 排序待审清单 + 证据包',
    args: [{ name: 'limit', pattern: /^\d{1,4}$/, hint: '待审条数上限' }],
    build: (ws, a) => ['audit', ws.path, '-o', 'json', '--limit', a.limit ?? '200'],
  },
  {
    id: 'chains',
    label: '候选链',
    description: '入口 → 危险汇的可达链',
    args: [{ name: 'limit', pattern: /^\d{1,3}$/, hint: '返回条数' }],
    build: (ws, a) => ['chain', ws.path, '--list', '--limit', a.limit ?? '40', '-o', 'json'],
  },
  {
    id: 'chain-dossier',
    label: '链档',
    description: '单条链的步骤 / 守卫 / 断点 / 证伪',
    args: [{ name: 'id', required: true, pattern: /^CH-[0-9a-f]{6,}$/i, hint: '链 ID' }],
    build: (ws, a) => ['chain', ws.path, '--id', a.id, '-o', 'json'],
  },
  {
    id: 'explain-route',
    label: '单路由判定',
    description: 'verbatim 证据 + 可机械证伪的断言',
    args: [
      { name: 'route', required: true, pattern: /^\/[A-Za-z0-9_\-./{}]*$/, hint: '路由路径' },
      { name: 'assert', pattern: /^(covered|uncovered|permitted|any)$/, hint: '断言' },
    ],
    build: (ws, a) => {
      const out = ['explain-route', ws.path, a.route, '-o', 'json']
      if (a.assert) out.push('--assert', a.assert)
      return out
    },
  },
  {
    id: 'payload',
    label: '载荷存活判定',
    description: '入口 → 汇的载荷是否被现有守卫杀死（ant 档位）',
    args: [
      { name: 'entryFile', required: true, pattern: /^[A-Za-z0-9_\-./\\]{1,300}$/, hint: '入口文件（相对路径）' },
      { name: 'entryLine', required: true, pattern: /^\d{1,6}$/, hint: '入口行号' },
      { name: 'sinkFile', required: true, pattern: /^[A-Za-z0-9_\-./\\]{1,300}$/, hint: '汇文件（相对路径）' },
      { name: 'sinkLine', required: true, pattern: /^\d{1,6}$/, hint: '汇行号' },
      { name: 'archetype', pattern: /^(sql|path|command|deser|jndi|template|ssrf|xss|xxe|redirect|header)$/, hint: '载荷类型' },
    ],
    build: (ws, a) => [
      'payload',
      'viability',
      ws.path,
      '--entry-file',
      a.entryFile,
      '--entry-line',
      a.entryLine,
      '--sink-file',
      a.sinkFile,
      '--sink-line',
      a.sinkLine,
      '--archetype',
      a.archetype ?? 'command',
      '-o',
      'json',
    ],
  },
  {
    id: 'baseline',
    label: '鉴权基线卡',
    description: '链 / 规则 / 过滤器 / 注解消费者 / 被关闭的钩子',
    args: [],
    build: (ws) => ['baseline', ws.path, '-o', 'json'],
  },
  {
    id: 'probe-reach',
    label: '可达性探针',
    description: '两点之间是否存在调用路径（probe reach）',
    args: [
      { name: 'fromFile', required: true, pattern: /^[A-Za-z0-9_\-./\\]{1,300}$/, hint: '源文件（相对路径）' },
      { name: 'fromLine', pattern: /^\d{1,6}$/, hint: '源行号' },
      { name: 'toFile', required: true, pattern: /^[A-Za-z0-9_\-./\\]{1,300}$/, hint: '目标文件（相对路径）' },
      { name: 'toLine', pattern: /^\d{1,6}$/, hint: '目标行号' },
    ],
    build: (ws, a) => [
      'probe',
      'reach',
      ws.path,
      '--from-file',
      a.fromFile,
      '--from-line',
      a.fromLine ?? '1',
      '--to-file',
      a.toFile,
      '--to-line',
      a.toLine ?? '1',
      '-o',
      'json',
    ],
  },
  {
    id: 'probe-slice',
    label: '路径切片',
    description: '沿可达路径切出每步代码窗口',
    args: [
      { name: 'fromFile', required: true, pattern: /^[A-Za-z0-9_\-./\\]{1,300}$/, hint: '源文件（相对路径）' },
      { name: 'fromLine', pattern: /^\d{1,6}$/, hint: '源行号' },
      { name: 'toFile', required: true, pattern: /^[A-Za-z0-9_\-./\\]{1,300}$/, hint: '目标文件（相对路径）' },
      { name: 'toLine', pattern: /^\d{1,6}$/, hint: '目标行号' },
      { name: 'radius', pattern: /^\d{1,3}$/, hint: '每步窗口半径' },
    ],
    build: (ws, a) => {
      const out = [
        'probe',
        'slice',
        ws.path,
        '--from-file',
        a.fromFile,
        '--from-line',
        a.fromLine ?? '1',
        '--to-file',
        a.toFile,
        '--to-line',
        a.toLine ?? '1',
        '-o',
        'json',
      ]
      if (a.radius) out.push('--radius', a.radius)
      return out
    },
  },
  {
    id: 'analyze',
    label: '单文件分析',
    description: 'AST / 符号信息（analyze）',
    args: [
      { name: 'file', required: true, pattern: /^[A-Za-z0-9_\-./\\]{1,300}$/, hint: '文件（相对路径）' },
      { name: 'symbols', pattern: /^(1|0)$/, hint: '显示符号信息' },
    ],
    build: (ws, a) => {
      const out = ['analyze', a.file, '-o', 'json']
      if (a.symbols === '1') out.push('--symbols')
      return out
    },
  },
  {
    id: 'signal-chain',
    label: '三角色信号链',
    description: '循环界 / 守卫检索 / 写 sink 累积性候选',
    args: [],
    build: (ws) => ['signal-chain', ws.path, '-o', 'json'],
  },
  {
    id: 'diff-routes',
    label: '端点基线 diff',
    description: '端点与覆盖判定的基线差异（CI 门禁用）',
    args: [{ name: 'since', pattern: /^[A-Za-z0-9_\-./]{1,200}$/, hint: '基线文件' }],
    build: (ws, a) => {
      const out = ['diff-routes', ws.path, '-o', 'json']
      if (a.since) out.push('--since', a.since)
      return out
    },
  },
  {
    id: 'gate',
    label: 'PR 漂移闸门',
    description: '对比 base/head 输出漂移判决',
    args: [
      { name: 'base', required: true, pattern: /^[A-Za-z0-9_\-./~^]{1,120}$/, hint: '基线 ref' },
      { name: 'head', required: true, pattern: /^[A-Za-z0-9_\-./~^]{1,120}$/, hint: '变更 ref' },
      { name: 'strict', pattern: /^(1|0)$/, hint: '严格模式' },
    ],
    build: (ws, a) => {
      const out = ['gate', '--git', ws.path, '--base', a.base, '--head', a.head, '-o', 'json', '--no-fail-on-block']
      if (a.strict === '1') out.push('--strict-sinks')
      return out
    },
  },
  {
    id: 'scan',
    label: '规则扫描',
    description: 'YAML 规则快速扫描',
    args: [{ name: 'taint', pattern: /^(1|0)$/, hint: '启用污点分析' }],
    build: (ws, a) => {
      const out = ['scan', ws.path, '-o', 'json']
      if (a.taint === '1') out.push('--taint')
      return out
    },
  },
  {
    id: 'report',
    label: '闸门汇总报告',
    description: '汇总多份 gate JSON artifact',
    args: [{ name: 'from', required: true, pattern: /^[A-Za-z0-9_\-./:]{1,300}$/, hint: 'artifact 目录' }],
    build: (_ws, a) => ['report', '--from', a.from, '-o', 'json'],
  },
]

/** Look up an action by id. */
export function findAction(id) {
  return ACTIONS.find((a) => a.id === id)
}

/**
 * Validate action arguments against the declared patterns.
 * @returns {{ ok: true, args: Record<string,string> } | { ok: false, error: string }}
 */
export function validateActionArgs(action, raw) {
  const args = {}
  const input = raw && typeof raw === 'object' ? raw : {}
  for (const spec of action.args) {
    const value = input[spec.name]
    if (value === undefined || value === null || value === '') {
      if (spec.required) return { ok: false, error: `missing required argument: ${spec.name}` }
      continue
    }
    if (typeof value !== 'string') return { ok: false, error: `argument ${spec.name} must be a string` }
    if (value.length > 300) return { ok: false, error: `argument ${spec.name} too long` }
    if (spec.pattern && !spec.pattern.test(value)) {
      return { ok: false, error: `argument ${spec.name} has an invalid shape` }
    }
    args[spec.name] = value
  }
  return { ok: true, args }
}

/** Public action catalogue (no build functions) for the UI. */
export function actionCatalogue() {
  return ACTIONS.map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
    args: a.args.map((s) => ({ name: s.name, required: Boolean(s.required), hint: s.hint ?? '' })),
  }))
}
