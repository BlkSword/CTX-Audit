import { createElement as h } from 'react'
import type { ReactNode } from 'react'

/** Small presentational primitives shared by every page. */

export function Card(props: { title?: string; sub?: string; actions?: ReactNode; flush?: boolean; children: ReactNode }) {
  return h(
    'section',
    { className: `card${props.flush ? ' flush' : ''}` },
    props.title
      ? h(
          'header',
          { className: 'card-head' },
          h('div', null, h('div', { className: 'card-title' }, props.title), props.sub ? h('div', { className: 'card-sub' }, props.sub) : null),
          h('div', { style: { flex: 1 } }),
          props.actions ?? null,
        )
      : null,
    props.flush ? props.children : h('div', { className: 'card-body' }, props.children),
  )
}

export function Metric(props: { label: string; value: ReactNode; hint?: ReactNode; tone?: 'ok' | 'warn' | 'danger' }) {
  return h(
    'div',
    { className: `card metric${props.tone ? ` ${props.tone}` : ''}` },
    h('div', { className: 'metric-label' }, props.label),
    h('div', { className: 'metric-value' }, props.value),
    props.hint ? h('div', { className: 'metric-hint' }, props.hint) : null,
  )
}

export function Badge(props: { tone?: 'ok' | 'warn' | 'danger' | 'info' | 'violet' | 'muted'; children?: ReactNode }) {
  return h('span', { className: `badge ${props.tone ?? 'muted'}` }, props.children)
}

export function Bar(props: { value: number; max: number; tone?: 'ok' | 'warn' | 'danger' }) {
  const pct = props.max > 0 ? Math.min(100, Math.round((props.value / props.max) * 100)) : 0
  return h('div', { className: `bar${props.tone ? ` ${props.tone}` : ''}` }, h('span', { style: { width: `${pct}%` } }))
}

export function Empty(props: { title: string; hint?: string; action?: ReactNode }) {
  return h(
    'div',
    { className: 'empty' },
    h('div', { className: 'title' }, props.title),
    props.hint ? h('div', { className: 'hint' }, props.hint) : null,
    props.action ?? null,
  )
}

export function Loading(props: { label?: string }) {
  return h(
    'div',
    { className: 'empty' },
    h('span', { className: 'spinner' }),
    h('div', { className: 'hint' }, props.label ?? '正在分析…'),
  )
}

export function SkeletonRows(props: { rows?: number }) {
  const rows = props.rows ?? 6
  return h(
    'div',
    { className: 'stack', style: { padding: 16 } },
    ...Array.from({ length: rows }, (_, i) =>
      h('div', { key: i, className: 'skeleton', style: { width: `${92 - i * 7}%` } }),
    ),
  )
}

export function Table(props: {
  columns: Array<{ key: string; label: string; width?: string; render?: (row: any) => ReactNode }>
  rows: any[]
  rowKey: (row: any, i: number) => string
  onRowClick?: (row: any) => void
}) {
  return h(
    'div',
    { className: 'table-wrap' },
    h(
      'table',
      { className: 'data' },
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          ...props.columns.map((c) => h('th', { key: c.key, style: c.width ? { width: c.width } : undefined }, c.label)),
        ),
      ),
      h(
        'tbody',
        null,
        ...props.rows.map((row, i) =>
          h(
            'tr',
            {
              key: props.rowKey(row, i),
              onClick: props.onRowClick ? () => props.onRowClick?.(row) : undefined,
              style: props.onRowClick ? { cursor: 'pointer' } : undefined,
            },
            ...props.columns.map((c) =>
              h('td', { key: c.key }, c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? '')),
            ),
          ),
        ),
      ),
    ),
  )
}

export function verdictTone(verdict: string): 'ok' | 'warn' | 'danger' | 'info' | 'violet' | 'muted' {
  if (verdict.startsWith('covered')) return 'ok'
  if (verdict === 'permitted_by_global_config') return 'info'
  if (verdict.startsWith('no_global')) return 'danger'
  if (verdict === 'coverage_unknown' || verdict === 'ambiguous_across_chains') return 'warn'
  if (verdict === 'framework_not_modeled') return 'violet'
  return 'muted'
}

export function tierTone(tier: string): 'ok' | 'warn' | 'danger' | 'info' | 'violet' | 'muted' {
  if (tier === 'payload_may_survive') return 'danger'
  if (tier === 'guard_ineffective_token') return 'warn'
  if (tier === 'taint_lost') return 'info'
  if (tier === 'payload_killed') return 'ok'
  if (tier === 'unreachable') return 'muted'
  return 'violet'
}

export function fmtMs(ms: number | undefined): string {
  if (ms === undefined || ms === null) return '—'
  if (ms < 1000) return Math.round(ms) + 'ms'
  return (ms / 1000).toFixed(2) + 's'
}

export function shortPath(p: string | null | undefined, keep = 2): string {
  if (!p) return '—'
  const parts = p.split(/[\\/]/)
  return parts.length <= keep ? p : '…/' + parts.slice(-keep).join('/')
}
