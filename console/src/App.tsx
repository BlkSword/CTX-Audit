import { createElement as h, useCallback, useEffect, useMemo, useState } from 'react'
import { api } from './api'
import type { ActionSpec, ChainDossier, Overview, Workspace } from './api'
import { Icon } from './icons'
import { Badge, Bar, Card, Empty, Loading, Metric, SkeletonRows, Table, fmtMs, shortPath, tierTone, verdictTone } from './ui'

type Page = 'overview' | 'stream' | 'coverage' | 'chains' | 'actions' | 'gate' | 'report'

const PAGES: Array<{ id: Page; label: string; icon: string }> = [
  { id: 'overview', label: '总览', icon: 'overview' },
  { id: 'stream', label: '审计流', icon: 'stream' },
  { id: 'coverage', label: '覆盖与待审', icon: 'coverage' },
  { id: 'chains', label: '候选链', icon: 'chains' },
  { id: 'actions', label: '能力动作', icon: 'stream' },
  { id: 'gate', label: '漂移闸门', icon: 'gate' },
  { id: 'report', label: '报告', icon: 'report' },
]

export default function App() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [page, setPage] = useState<Page>('overview')
  const [overview, setOverview] = useState<Overview | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [health, setHealth] = useState<{ ok: boolean; version: string; binary: string } | null>(null)
  const [adding, setAdding] = useState(false)
  const [pathInput, setPathInput] = useState('')
  const [nameInput, setNameInput] = useState('')
  const [addError, setAddError] = useState<string | null>(null)

  const active = useMemo(() => workspaces.find((w) => w.id === activeId) ?? null, [workspaces, activeId])

  const refreshWorkspaces = useCallback(async () => {
    const res = await api.listWorkspaces()
    setWorkspaces(res.workspaces)
    if (!activeId && res.workspaces.length > 0) setActiveId(res.workspaces[0].id)
  }, [activeId])

  useEffect(() => {
    void refreshWorkspaces().catch((e: Error) => setError(e.message))
    void api
      .health()
      .then((r) => setHealth({ ok: r.ok, version: r.version, binary: r.binary }))
      .catch(() => setHealth(null))
  }, [refreshWorkspaces])

  const loadOverview = useCallback(async (id: string) => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.overview(id)
      if (!res.ok || !res.overview) throw new Error(res.error ?? '分析失败')
      setOverview(res.overview)
    } catch (e) {
      setError((e as Error).message)
      setOverview(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (activeId) void loadOverview(activeId)
  }, [activeId, loadOverview])

  const addWorkspace = async () => {
    setAddError(null)
    try {
      const res = await api.addWorkspace(pathInput.trim(), nameInput.trim() || undefined)
      setAdding(false)
      setPathInput('')
      setNameInput('')
      await refreshWorkspaces()
      setActiveId(res.workspace.id)
    } catch (e) {
      setAddError((e as Error).message)
    }
  }

  return h(
    'div',
    { className: 'app' },
    h(
      'aside',
      { className: 'sidebar' },
      h(
        'div',
        { className: 'brand' },
        h('div', { className: 'brand-mark' }, 'C'),
        h('div', { className: 'brand-text' }, h('div', { className: 'brand-title' }, 'CTX-Audit'), h('div', { className: 'brand-sub' }, 'Console')),
      ),
      h(
        'nav',
        { className: 'nav' },
        h('div', { className: 'nav-label' }, '工作区'),
        ...workspaces.map((w) =>
          h(
            'button',
            {
              key: w.id,
              className: `nav-item${w.id === activeId ? ' active' : ''}`,
              onClick: () => setActiveId(w.id),
              title: w.path,
            },
            h(Icon, { name: 'coverage' }),
            h('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, w.name),
          ),
        ),
        h(
          'button',
          { className: 'nav-item', onClick: () => setAdding(true) },
          h(Icon, { name: 'plus' }),
          h('span', null, '添加工作区'),
        ),
        h('div', { className: 'nav-label', style: { marginTop: 8 } }, '视图'),
        ...PAGES.map((p) =>
          h(
            'button',
            {
              key: p.id,
              className: `nav-item${page === p.id ? ' active' : ''}`,
              onClick: () => setPage(p.id),
            },
            h(Icon, { name: p.icon }),
            h('span', null, p.label),
            p.id === 'coverage' && overview ? h('span', { className: 'count' }, overview.coverage.uncovered) : null,
            p.id === 'chains' && overview ? h('span', { className: 'count' }, overview.chains.total) : null,
          ),
        ),
      ),
      h(
        'div',
        { className: 'sidebar-foot' },
        h('div', null, h('span', { className: `dot ${health?.ok ? 'ok' : 'bad'}` }), health?.ok ? '引擎在线' : '引擎离线'),
        h('div', { className: 'mono', style: { fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis' } }, health?.version || '—'),
      ),
    ),
    h(
      'main',
      { className: 'main' },
      h(
        'header',
        { className: 'topbar' },
        h(
          'div',
          { className: 'crumbs' },
          h('span', null, '工作区'),
          h('span', { className: 'sep' }, '/'),
          h('span', { className: 'here' }, active?.name ?? '未选择'),
          h('span', { className: 'sep' }, '/'),
          h('span', null, PAGES.find((p) => p.id === page)?.label ?? ''),
        ),
        h('div', { className: 'topbar-spacer' }),
        active
          ? h(
              'button',
              { className: 'btn', onClick: () => void loadOverview(active.id), disabled: loading },
              loading ? h('span', { className: 'spinner' }) : h(Icon, { name: 'refresh' }),
              '重新分析',
            )
          : null,
      ),
      h(
        'div',
        { className: 'content' },
        !active
          ? h(Empty, {
              title: '还没有工作区',
              hint: '添加一个代码仓库目录作为审计工作区，Console 会为它建立总览、审计流、覆盖与链档视图。',
              action: h('button', { className: 'btn primary', onClick: () => setAdding(true) }, '添加工作区'),
            })
          : error
            ? h(Empty, { title: '分析失败', hint: error, action: h('button', { className: 'btn', onClick: () => void loadOverview(active.id) }, '重试') })
            : page === 'overview'
              ? h(OverviewPage, { overview, loading, onGoto: setPage })
              : page === 'stream'
                ? h(StreamPage, { workspace: active, onDone: () => void loadOverview(active.id) })
                : page === 'coverage'
                  ? h(CoveragePage, { overview, loading })
                  : page === 'chains'
                    ? h(ChainsPage, { overview, loading, workspace: active })
                    : page === 'actions'
                      ? h(ActionsPage, { workspace: active })
                      : page === 'gate'
                      ? h(GatePage, { workspace: active })
                      : h(ReportPage, { overview }),
      ),
    ),
    adding
      ? h(
          'div',
          { className: 'overlay', onClick: () => setAdding(false) },
          h(
            'div',
            { className: 'modal', onClick: (e: { stopPropagation: () => void }) => e.stopPropagation() },
            h('div', { className: 'modal-head' }, '添加审计工作区'),
            h(
              'div',
              { className: 'modal-body' },
              h(
                'div',
                null,
                h('label', { className: 'field-label' }, '仓库目录（绝对路径）'),
                h('input', {
                  className: 'input',
                  value: pathInput,
                  placeholder: 'C:\\project\\CTX-Audit',
                  onChange: (e: { target: { value: string } }) => setPathInput(e.target.value),
                  autoFocus: true,
                }),
              ),
              h(
                'div',
                null,
                h('label', { className: 'field-label' }, '显示名称（可选）'),
                h('input', {
                  className: 'input',
                  value: nameInput,
                  placeholder: '例如 zfile / mall',
                  onChange: (e: { target: { value: string } }) => setNameInput(e.target.value),
                }),
              ),
              addError ? h('div', { className: 'error-text' }, addError) : null,
            ),
            h(
              'div',
              { className: 'modal-foot' },
              h('button', { className: 'btn ghost', onClick: () => setAdding(false) }, '取消'),
              h('button', { className: 'btn primary', onClick: () => void addWorkspace(), disabled: !pathInput.trim() }, '添加'),
            ),
          ),
        )
      : null,
  )
}

/* ── Overview ─────────────────────────────────────────────────────────── */

function OverviewPage(props: { overview: Overview | null; loading: boolean; onGoto: (p: Page) => void }) {
  if (props.loading && !props.overview) return h(Loading, { label: '正在建立工作区总览…' })
  if (!props.overview) return h(Empty, { title: '暂无数据', hint: '点击右上角“重新分析”生成总览。' })
  const o = props.overview
  const cov = o.coverage
  const total = Math.max(1, cov.methodRoutes)
  const covered = Math.max(0, cov.methodRoutes - cov.uncovered)
  const risky = o.chains.tiers['payload_may_survive'] ?? 0

  return h(
    'div',
    { className: 'stack' },
    h(
      'div',
      { className: 'grid k4' },
      h(Metric, {
        label: '端点总数',
        value: cov.methodRoutes,
        hint: `${cov.filesIndexed} 个文件 · 置信 ${cov.confidence}`,
      }),
      h(Metric, {
        label: '未覆盖端点',
        value: cov.uncovered,
        tone: cov.uncovered > 0 ? 'danger' : 'ok',
        hint: `注解覆盖 ${cov.annotationCovered} · 待判 ${cov.byVerdict['coverage_unknown'] ?? 0}`,
      }),
      h(Metric, {
        label: '候选链',
        value: o.chains.total,
        hint: `载荷可能存活 ${risky} · 守卫无效 ${o.chains.tiers['guard_ineffective_token'] ?? 0}`,
      }),
      h(Metric, {
        label: '分析耗时',
        value: fmtMs(o.timings.auditMs + o.timings.chainsMs),
        hint: `覆盖 ${fmtMs(o.timings.auditMs)} · 链 ${fmtMs(o.timings.chainsMs)}`,
      }),
    ),
    h(
      'div',
      { className: 'grid k2' },
      h(Card, {
        title: '鉴权覆盖分布',
        sub: `${covered}/${total} 端点有明确覆盖证据`,
        actions: h('button', { className: 'btn sm ghost', onClick: () => props.onGoto('coverage') }, '查看待审'),
        children: h(
          'div',
          { className: 'stack' },
          h(Bar, { value: covered, max: total, tone: cov.uncovered > 0 ? 'warn' : 'ok' }),
          h(
            'div',
            { className: 'legend' },
            ...Object.entries(cov.byVerdict)
              .sort((a, b) => b[1] - a[1])
              .map(([k, v]) =>
                h('span', { key: k }, h('span', { className: 'swatch', style: { background: verdictColor(k) } }), `${k} · ${v}`),
              ),
          ),
          h(
            'dl',
            { className: 'kv mt2' },
            h('dt', null, '动态注册'),
            h('dd', null, String(cov.boundaries.dynamicRegistrations)),
            h('dt', null, '未建模路由文件'),
            h('dd', null, String(cov.boundaries.unmodelledRouteFiles)),
            h('dt', null, '索引截断'),
            h('dd', null, cov.boundaries.indexTruncated ? '是（结论不可信）' : '否'),
            h('dt', null, '路径级策略'),
            h('dd', null, cov.hasPathLevelPolicy ? '已建模' : '未发现'),
          ),
        ),
      }),
      h(Card, {
        title: '链档分布',
        sub: '按载荷存活档位统计',
        actions: h('button', { className: 'btn sm ghost', onClick: () => props.onGoto('chains') }, '查看链'),
        children: h(
          'div',
          { className: 'stack' },
          ...Object.entries(o.chains.tiers)
            .sort((a, b) => b[1] - a[1])
            .map(([tier, n]) =>
              h(
                'div',
                { key: tier },
                h(
                  'div',
                  { className: 'row between', style: { marginBottom: 4 } },
                  h(Badge, { tone: tierTone(tier) }, tier),
                  h('span', { className: 'num dim' }, n),
                ),
                h(Bar, { value: n, max: Math.max(1, o.chains.total), tone: tier === 'payload_may_survive' ? 'danger' : undefined }),
              ),
            ),
        ),
      }),
    ),
    h(Card, {
      title: '高风险待审端点',
      sub: `共 ${o.worklist.total} 条待审，按风险分排序`,
      flush: true,
      children:
        o.worklist.top.length === 0
          ? h(Empty, { title: '没有待审端点', hint: '当前工作区的端点都有明确覆盖证据。' })
          : h(Table, {
              columns: [
                { key: 'score', label: '分', width: '56px', render: (r) => h('span', { className: 'num' }, r.score) },
                { key: 'method', label: '方法', width: '72px', render: (r) => h('span', { className: 'mono' }, r.method ?? 'ANY') },
                { key: 'route', label: '路由', render: (r) => h('span', { className: 'mono' }, r.route ?? '—') },
                {
                  key: 'verdict',
                  label: '判定',
                  width: '210px',
                  render: (r) => h(Badge, { tone: verdictTone(r.verdict) }, r.verdict),
                },
                { key: 'file', label: '位置', render: (r) => h('span', { className: 'faint mono' }, `${shortPath(r.file)}:${r.line ?? 0}`) },
              ],
              rows: o.worklist.top.slice(0, 12),
              rowKey: (r, i) => `${r.file}:${r.line}:${i}`,
            }),
    }),
  )
}

function verdictColor(v: string): string {
  if (v.startsWith('covered')) return 'var(--ok)'
  if (v.startsWith('no_global')) return 'var(--danger)'
  if (v === 'permitted_by_global_config') return 'var(--info)'
  if (v === 'coverage_unknown' || v === 'ambiguous_across_chains') return 'var(--warn)'
  return 'var(--text-faint)'
}

/* ── Stream ───────────────────────────────────────────────────────────── */

interface StreamRow {
  at: string
  name: string
  status: string
  durationMs?: number
  error?: string
}

function StreamPage(props: { workspace: Workspace; onDone: () => void }) {
  const [rows, setRows] = useState<StreamRow[]>([])
  const [running, setRunning] = useState(false)

  const start = useCallback(() => {
    setRows([])
    setRunning(true)
    const off = api.stream(props.workspace.id, (event, data) => {
      const d = data as Record<string, unknown>
      if (event === 'step') {
        setRows((prev) => {
          const next = [...prev]
          const name = String(d['name'] ?? '')
          const idx = next.findIndex((r) => r.name === name)
          const row: StreamRow = {
            at: new Date().toLocaleTimeString(),
            name,
            status: String(d['status'] ?? ''),
            durationMs: d['durationMs'] as number | undefined,
            error: d['error'] as string | undefined,
          }
          if (idx >= 0) next[idx] = row
          else next.push(row)
          return next
        })
      }
      if (event === 'done' || event === 'error') {
        setRunning(false)
        off()
        props.onDone()
      }
    })
  }, [props])

  useEffect(() => {
    start()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.workspace.id])

  return h(
    'div',
    { className: 'stack' },
    h(Card, {
      title: '审计流',
      sub: '按步骤执行覆盖分析与链扫描，实时回传状态',
      actions: h(
        'button',
        { className: 'btn sm', onClick: start, disabled: running },
        running ? h('span', { className: 'spinner' }) : h(Icon, { name: 'refresh' }),
        '重新运行',
      ),
      children:
        rows.length === 0
          ? h(Loading, { label: '正在启动审计流…' })
          : h(
              'div',
              { className: 'stream' },
              ...rows.map((r) =>
                h(
                  'div',
                  { key: r.name, className: `stream-row ${r.status}` },
                  h('span', { className: 't' }, r.at),
                  h('span', { className: 'msg' }, `${r.name} · ${r.status}${r.error ? ` · ${r.error}` : ''}`),
                  h('span', { className: 'faint num' }, r.durationMs !== undefined ? fmtMs(r.durationMs) : ''),
                ),
              ),
            ),
    }),
    h(Card, {
      title: '说明',
      children: h(
        'div',
        { className: 'dim', style: { fontSize: 12 } },
        '审计流按顺序执行：覆盖分析（audit）→ 候选链扫描（chain）。每一步都会记录耗时与错误；失败时保留上一步结果。',
      ),
    }),
  )
}

/* ── Coverage ─────────────────────────────────────────────────────────── */

function CoveragePage(props: { overview: Overview | null; loading: boolean }) {
  if (props.loading && !props.overview) return h(Loading, { label: '正在分析覆盖…' })
  if (!props.overview) return h(Empty, { title: '暂无数据' })
  const o = props.overview
  const items = o.worklist.top
  return h(
    'div',
    { className: 'stack' },
    h(
      'div',
      { className: 'grid k3' },
      h(Metric, { label: '待审总数', value: o.worklist.total, tone: o.worklist.total > 0 ? 'warn' : 'ok' }),
      h(Metric, { label: '未覆盖', value: o.coverage.uncovered, tone: o.coverage.uncovered > 0 ? 'danger' : 'ok' }),
      h(Metric, { label: '未知/歧义', value: (o.coverage.byVerdict['coverage_unknown'] ?? 0) + (o.coverage.byVerdict['ambiguous_across_chains'] ?? 0) }),
    ),
    h(Card, {
      title: '待审端点',
      sub: '风险分 = 写方法 + 高危路径 + 未覆盖 + 未建模栈',
      flush: true,
      children:
        items.length === 0
          ? h(Empty, { title: '没有待审端点' })
          : h(Table, {
              columns: [
                { key: 'score', label: '分', width: '56px', render: (r) => h('span', { className: 'num' }, r.score) },
                { key: 'method', label: '方法', width: '72px', render: (r) => h('span', { className: 'mono' }, r.method ?? 'ANY') },
                { key: 'route', label: '路由', render: (r) => h('span', { className: 'mono' }, r.route ?? '—') },
                { key: 'verdict', label: '判定', width: '220px', render: (r) => h(Badge, { tone: verdictTone(r.verdict) }, r.verdict) },
                {
                  key: 'signals',
                  label: '信号',
                  render: (r) =>
                    h(
                      'div',
                      { className: 'row', style: { flexWrap: 'wrap', gap: 4 } },
                      ...(r.signals ?? []).slice(0, 4).map((sig: string) => h(Badge, { key: sig, tone: 'muted' }, sig)),
                    ),
                },
                { key: 'file', label: '位置', render: (r) => h('span', { className: 'faint mono' }, `${shortPath(r.file)}:${r.line ?? 0}`) },
              ],
              rows: items,
              rowKey: (r, i) => `${r.file}:${r.line}:${i}`,
            }),
    }),
  )
}

/* ── Chains ───────────────────────────────────────────────────────────── */

function ChainsPage(props: { overview: Overview | null; loading: boolean; workspace: Workspace }) {
  const [selected, setSelected] = useState<string | null>(null)
  const [dossier, setDossier] = useState<ChainDossier | null>(null)
  const [detailBusy, setDetailBusy] = useState(false)
  const [detailErr, setDetailErr] = useState<string | null>(null)

  const openChain = async (chainId: string) => {
    setSelected(chainId)
    setDetailBusy(true)
    setDetailErr(null)
    try {
      const res = await api.chain(props.workspace.id, chainId)
      if (!res.ok || !res.dossier) throw new Error(res.error ?? '链档读取失败')
      setDossier(res.dossier)
    } catch (e) {
      setDetailErr((e as Error).message)
      setDossier(null)
    } finally {
      setDetailBusy(false)
    }
  }

  if (props.loading && !props.overview) return h(Loading, { label: '正在扫描候选链…' })
  if (!props.overview) return h(Empty, { title: '暂无数据' })
  const o = props.overview
  return h(
    'div',
    { className: 'stack' },
    h(
      'div',
      { className: 'grid k4' },
      h(Metric, { label: '候选链', value: o.chains.total }),
      h(Metric, { label: '载荷可能存活', value: o.chains.tiers['payload_may_survive'] ?? 0, tone: 'danger' }),
      h(Metric, { label: '守卫无效', value: o.chains.tiers['guard_ineffective_token'] ?? 0, tone: 'warn' }),
      h(Metric, { label: '污点丢失', value: o.chains.tiers['taint_lost'] ?? 0 }),
    ),
    h(Card, {
      title: '候选链',
      sub: '入口 → 危险汇；tier 表示载荷存活档位',
      flush: true,
      children:
        o.chains.top.length === 0
          ? h(Empty, { title: '没有候选链', hint: '该工作区未发现入口到危险汇的可达路径。' })
          : h(Table, {
              columns: [
                { key: 'chainId', label: '链', width: '120px', render: (r) => h('span', { className: 'mono' }, r.chainId) },
                { key: 'tier', label: '档位', width: '190px', render: (r) => h(Badge, { tone: tierTone(r.tier) }, r.tier) },
                { key: 'sinkKind', label: '汇', width: '110px', render: (r) => h('span', { className: 'mono' }, r.sinkKind) },
                { key: 'entryRoute', label: '入口', render: (r) => h('span', { className: 'mono' }, r.entryRoute ?? '—') },
                { key: 'steps', label: '步', width: '56px', render: (r) => h('span', { className: 'num' }, r.steps) },
                { key: 'guards', label: '守卫', width: '64px', render: (r) => h('span', { className: 'num' }, r.guards) },
                { key: 'sinkFile', label: '汇位置', render: (r) => h('span', { className: 'faint mono' }, `${shortPath(r.sinkFile)}:${r.sinkLine}`) },
              ],
              rows: o.chains.top,
              rowKey: (r) => r.chainId,
              onRowClick: (r: { chainId: string }) => void openChain(r.chainId),
            }),
    }),
    selected
      ? h(Card, {
          title: `链档 ${selected}`,
          sub: '步骤 / 守卫 / 断点 / 证伪命令',
          actions: h(
            'button',
            {
              className: 'btn sm ghost',
              onClick: () => {
                setSelected(null)
                setDossier(null)
              },
            },
            '关闭',
          ),
          children: detailBusy
            ? h(Loading, { label: '正在读取链档…' })
            : detailErr
              ? h(Empty, { title: '读取失败', hint: detailErr })
              : dossier
                ? h(
                    'div',
                    { className: 'stack' },
                    h(
                      'div',
                      { className: 'row', style: { flexWrap: 'wrap', gap: 8 } },
                      h(Badge, { tone: tierTone(dossier.tier) }, dossier.tier),
                      h(Badge, { tone: 'muted' }, `score ${dossier.score}`),
                      h(Badge, { tone: 'muted' }, `controllability ${dossier.controllability}`),
                      h(Badge, { tone: 'info' }, `sink ${dossier.sink?.kind ?? '—'}`),
                    ),
                    h(
                      'dl',
                      { className: 'kv' },
                      h('dt', null, '入口'),
                      h(
                        'dd',
                        { className: 'mono' },
                        dossier.entry
                          ? `${dossier.entry.method ?? 'ANY'} ${dossier.entry.route ?? ''} (${shortPath(dossier.entry.file)}:${dossier.entry.line ?? 0})`
                          : '—',
                      ),
                      h('dt', null, '汇'),
                      h('dd', { className: 'mono' }, `${shortPath(dossier.sink?.file)}:${dossier.sink?.line ?? 0}`),
                      h('dt', null, '步骤'),
                      h('dd', null, String(dossier.steps?.length ?? 0)),
                      h('dt', null, '守卫'),
                      h('dd', null, String(dossier.guards?.length ?? 0)),
                    ),
                    h(
                      'div',
                      null,
                      h('div', { className: 'section-title' }, '路径'),
                      h(Table, {
                        columns: [
                          {
                            key: 'role',
                            label: '角色',
                            width: '96px',
                            render: (r: { role: string }) =>
                              h(Badge, { tone: r.role === 'sink' ? 'danger' : r.role === 'source' ? 'info' : 'muted' }, r.role),
                          },
                          { key: 'symbol', label: '符号', width: '180px', render: (r: { symbol: string }) => h('span', { className: 'mono' }, r.symbol) },
                          {
                            key: 'file',
                            label: '位置',
                            render: (r: { file: string; line: number }) => h('span', { className: 'faint mono' }, `${shortPath(r.file)}:${r.line}`),
                          },
                          {
                            key: 'expr',
                            label: '表达式',
                            render: (r: { expr?: string }) => h('span', { className: 'mono dim ellipsis' }, r.expr ?? ''),
                          },
                        ],
                        rows: dossier.steps ?? [],
                        rowKey: (_r: unknown, i: number) => String(i),
                      }),
                    ),
                    (dossier.guards ?? []).length > 0
                      ? h(
                          'div',
                          null,
                          h('div', { className: 'section-title' }, '守卫'),
                          h(Table, {
                            columns: [
                              { key: 'kind', label: '类型', width: '160px', render: (r: { kind?: string }) => h('span', { className: 'mono' }, r.kind ?? '') },
                              {
                                key: 'verdict',
                                label: '判定',
                                width: '110px',
                                render: (r: { verdict?: string }) => h(Badge, { tone: r.verdict === 'blocking' ? 'ok' : 'warn' }, r.verdict ?? '—'),
                              },
                              {
                                key: 'evidence',
                                label: '证据',
                                render: (r: { evidence?: string }) => h('span', { className: 'mono dim ellipsis' }, r.evidence ?? ''),
                              },
                            ],
                            rows: dossier.guards ?? [],
                            rowKey: (_r: unknown, i: number) => String(i),
                          }),
                        )
                      : null,
                  )
                : null,
        })
      : null,
  )
}

/* ── Gate ─────────────────────────────────────────────────────────────── */

function GatePage(props: { workspace: Workspace }) {
  const [base, setBase] = useState('HEAD~1')
  const [head, setHead] = useState('HEAD')
  const [strict, setStrict] = useState(false)
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState<{ summary?: { blocks?: number; waived?: number }; verdicts?: Array<{ severity: string; kind: string; reason: string }> } | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setErr(null)
    try {
      const res = await api.gate(props.workspace.id, base, head, strict)
      if (!res.ok) throw new Error(res.error ?? '闸门执行失败')
      setReport((res.report ?? null) as typeof report)
    } catch (e) {
      setErr((e as Error).message)
      setReport(null)
    } finally {
      setBusy(false)
    }
  }

  const blocks = report?.summary?.blocks ?? 0
  return h(
    'div',
    { className: 'stack' },
    h(Card, {
      title: 'PR 漂移闸门',
      sub: '对比 base/head，输出新增未鉴权路由、鉴权回退、守卫丢失、新增危险汇',
      children: h(
        'div',
        { className: 'stack' },
        h(
          'div',
          { className: 'grid k3' },
          h('div', null, h('label', { className: 'field-label' }, '基线 ref'), h('input', { className: 'input', value: base, onChange: (e: { target: { value: string } }) => setBase(e.target.value) })),
          h('div', null, h('label', { className: 'field-label' }, '变更 ref'), h('input', { className: 'input', value: head, onChange: (e: { target: { value: string } }) => setHead(e.target.value) })),
          h(
            'div',
            null,
            h('label', { className: 'field-label' }, '严格模式'),
            h(
              'label',
              { className: 'row', style: { paddingTop: 8, cursor: 'pointer' } },
              h('input', { type: 'checkbox', checked: strict, onChange: (e: { target: { checked: boolean } }) => setStrict(e.target.checked) }),
              h('span', { className: 'dim' }, '受保护接口新增危险汇也阻断'),
            ),
          ),
        ),
        h(
          'div',
          { className: 'row' },
          h('button', { className: 'btn primary', onClick: () => void run(), disabled: busy }, busy ? h('span', { className: 'spinner' }) : h(Icon, { name: 'gate' }), '运行闸门'),
          err ? h('span', { className: 'error-text' }, err) : null,
        ),
      ),
    }),
    report
      ? h(Card, {
          title: '判决',
          sub: blocks > 0 ? '存在阻断项' : '无阻断项',
          flush: true,
          children: h(
            'div',
            { className: 'stack', style: { padding: 16 } },
            h(
              'div',
              { className: 'row' },
              h(Badge, { tone: blocks > 0 ? 'danger' : 'ok' }, blocks > 0 ? `BLOCK · ${blocks}` : 'PASS'),
              h('span', { className: 'dim' }, `豁免 ${report.summary?.waived ?? 0}`),
            ),
            (report.verdicts ?? []).length === 0
              ? h(Empty, { title: '没有判决项' })
              : h(Table, {
                  columns: [
                    { key: 'severity', label: '严重度', width: '90px', render: (r) => h(Badge, { tone: r.severity === 'block' ? 'danger' : 'info' }, r.severity) },
                    { key: 'kind', label: '类型', width: '240px', render: (r) => h('span', { className: 'mono' }, r.kind) },
                    { key: 'reason', label: '原因' },
                  ],
                  rows: report.verdicts ?? [],
                  rowKey: (_r, i) => String(i),
                }),
          ),
        })
      : null,
  )
}

/* ── Actions ──────────────────────────────────────────────────────────── */

function ActionsPage(props: { workspace: Workspace }) {
  const [specs, setSpecs] = useState<ActionSpec[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<{ ok: boolean; argv?: string[]; durationMs?: number; data?: unknown; stdout?: string; stderr?: string; error?: string } | null>(null)

  useEffect(() => {
    void api
      .actions()
      .then((r) => setSpecs(r.actions))
      .catch(() => setSpecs([]))
  }, [])

  const active = specs.find((s) => s.id === activeId) ?? null

  const run = async () => {
    if (!active) return
    setBusy(true)
    setResult(null)
    try {
      const res = await api.runAction(props.workspace.id, active.id, values)
      setResult(res)
    } catch (e) {
      setResult({ ok: false, error: (e as Error).message })
    } finally {
      setBusy(false)
    }
  }

  return h(
    'div',
    { className: 'stack' },
    h(Card, {
      title: '能力动作',
      sub: '把 CLI / 工具面映射为可执行动作；参数在服务端按白名单校验',
      children: h(
        'div',
        { className: 'stack' },
        h(
          'div',
          { className: 'row', style: { flexWrap: 'wrap', gap: 6 } },
          ...specs.map((spec) =>
            h(
              'button',
              {
                key: spec.id,
                className: `btn sm${spec.id === activeId ? ' primary' : ''}`,
                onClick: () => {
                  setActiveId(spec.id)
                  setValues({})
                  setResult(null)
                },
                title: spec.description,
              },
              spec.label,
            ),
          ),
        ),
        active
          ? h(
              'div',
              { className: 'stack', style: { marginTop: 8 } },
              h('div', { className: 'dim', style: { fontSize: 12 } }, active.description),
              ...active.args.map((arg) =>
                h(
                  'div',
                  { key: arg.name },
                  h('label', { className: 'field-label' }, `${arg.name}${arg.required ? ' *' : ''}${arg.hint ? ` — ${arg.hint}` : ''}`),
                  h('input', {
                    className: 'input',
                    value: values[arg.name] ?? '',
                    placeholder: arg.hint,
                    onChange: (e: { target: { value: string } }) => setValues((v) => ({ ...v, [arg.name]: e.target.value })),
                  }),
                ),
              ),
              h(
                'div',
                { className: 'row' },
                h('button', { className: 'btn primary', onClick: () => void run(), disabled: busy }, busy ? h('span', { className: 'spinner' }) : h(Icon, { name: 'stream' }), '执行'),
              ),
            )
          : h(Empty, { title: '选择一个动作', hint: '动作覆盖审计驾驶舱、候选链、链档、单路由判定、基线卡、信号链、端点 diff、闸门、规则扫描与报告汇总。' }),
      ),
    }),
    result
      ? h(Card, {
          title: '执行结果',
          sub: result.argv ? result.argv.join(' ') : undefined,
          actions: h(Badge, { tone: result.ok ? 'ok' : 'danger' }, result.ok ? 'OK' : 'FAILED'),
          children: h(
            'div',
            { className: 'stack' },
            h('div', { className: 'row' }, h('span', { className: 'dim' }, `耗时 ${fmtMs(result.durationMs)}`)),
            result.error ? h('div', { className: 'error-text' }, result.error) : null,
            h(
              'pre',
              { className: 'mono', style: { whiteSpace: 'pre-wrap', margin: 0, maxHeight: '46vh', overflow: 'auto', fontSize: 11.5, color: 'var(--text-dim)' } },
              result.data !== undefined ? JSON.stringify(result.data, null, 2) : (result.stdout ?? result.stderr ?? ''),
            ),
          ),
        })
      : null,
  )
}

/* ── Report ───────────────────────────────────────────────────────────── */

function ReportPage(props: { overview: Overview | null }) {
  if (!props.overview) return h(Empty, { title: '暂无数据' })
  const o = props.overview
  const md = [
    `# 审计报告 — ${o.workspace.name}`,
    '',
    `- 生成时间：${new Date(o.generatedAt).toLocaleString()}`,
    `- 工作区：\`${o.workspace.path}\``,
    '',
    '## 覆盖',
    '',
    `- 端点总数：${o.coverage.methodRoutes}`,
    `- 未覆盖：${o.coverage.uncovered}`,
    `- 注解覆盖：${o.coverage.annotationCovered}`,
    `- 置信：${o.coverage.confidence}`,
    '',
    '## 待审（前 10）',
    '',
    ...o.worklist.top.slice(0, 10).map((w) => `- [${w.score}] ${w.method ?? 'ANY'} ${w.route ?? ''} — ${w.verdict} (${w.file}:${w.line})`),
    '',
    '## 候选链（前 10）',
    '',
    ...o.chains.top.slice(0, 10).map((c) => `- ${c.chainId} · ${c.tier} · ${c.sinkKind} · ${c.entryRoute ?? '—'}`),
  ].join('\n')

  return h(
    'div',
    { className: 'stack' },
    h(Card, {
      title: '报告预览',
      sub: 'Markdown，可直接复制到工单或 PR',
      actions: h(
        'button',
        {
          className: 'btn sm',
          onClick: () => void navigator.clipboard?.writeText(md),
        },
        '复制',
      ),
      children: h('pre', { className: 'mono', style: { whiteSpace: 'pre-wrap', margin: 0, fontSize: 11.5, color: 'var(--text-dim)' } }, md),
    }),
  )
}
