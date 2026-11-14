import { createElement as h } from 'react'
import type { ReactElement } from 'react'

/** Lightweight SVG charts — no chart library, deterministic rendering. */

export function Donut(props: {
  segments: Array<{ label: string; value: number; color: string }>
  size?: number
  thickness?: number
  centerLabel?: string
  centerValue?: string
}): ReactElement {
  const size = props.size ?? 148
  const thickness = props.thickness ?? 14
  const radius = (size - thickness) / 2
  const circumference = 2 * Math.PI * radius
  const total = props.segments.reduce((sum, s) => sum + s.value, 0) || 1
  let offset = 0
  const arcs = props.segments
    .filter((s) => s.value > 0)
    .map((s, i) => {
      const length = (s.value / total) * circumference
      const arc = h('circle', {
        key: i,
        cx: size / 2,
        cy: size / 2,
        r: radius,
        fill: 'none',
        stroke: s.color,
        strokeWidth: thickness,
        strokeDasharray: `${length} ${circumference - length}`,
        strokeDashoffset: -offset,
        strokeLinecap: 'butt',
        transform: `rotate(-90 ${size / 2} ${size / 2})`,
      })
      offset += length
      return arc
    })

  return h(
    'div',
    { style: { display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' } },
    h(
      'svg',
      { width: size, height: size, viewBox: `0 0 ${size} ${size}`, role: 'img' },
      h('circle', {
        cx: size / 2,
        cy: size / 2,
        r: radius,
        fill: 'none',
        stroke: '#1a2230',
        strokeWidth: thickness,
      }),
      ...arcs,
      props.centerValue
        ? h(
            'text',
            {
              x: '50%',
              y: '47%',
              textAnchor: 'middle',
              fill: '#e6ebf4',
              fontSize: 22,
              fontWeight: 680,
              fontFamily: 'ui-monospace, monospace',
            },
            props.centerValue,
          )
        : null,
      props.centerLabel
        ? h(
            'text',
            {
              x: '50%',
              y: '62%',
              textAnchor: 'middle',
              fill: '#66748c',
              fontSize: 10,
              letterSpacing: 0.8,
            },
            props.centerLabel,
          )
        : null,
    ),
    h(
      'div',
      { style: { display: 'flex', flexDirection: 'column', gap: 6, minWidth: 160 } },
      ...props.segments.map((s) =>
        h(
          'div',
          { key: s.label, style: { display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5 } },
          h('span', { style: { width: 8, height: 8, borderRadius: 2, background: s.color, flex: 'none' } }),
          h('span', { style: { color: '#9aa7bd', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, s.label),
          h('span', { style: { color: '#e6ebf4', fontVariantNumeric: 'tabular-nums' } }, String(s.value)),
        ),
      ),
    ),
  )
}

/** Horizontal stacked bar for a single ratio split. */
export function StackedBar(props: {
  segments: Array<{ label: string; value: number; color: string }>
  height?: number
}): ReactElement {
  const total = props.segments.reduce((sum, s) => sum + s.value, 0) || 1
  return h(
    'div',
    null,
    h(
      'div',
      {
        style: {
          display: 'flex',
          height: props.height ?? 10,
          borderRadius: 999,
          overflow: 'hidden',
          background: '#1a2230',
        },
      },
      ...props.segments
        .filter((s) => s.value > 0)
        .map((s) =>
          h('div', {
            key: s.label,
            title: `${s.label}: ${s.value}`,
            style: { width: `${(s.value / total) * 100}%`, background: s.color },
          }),
        ),
    ),
  )
}

/** Chain path visualisation: entry → steps → sink as a horizontal flow. */
export function ChainFlow(props: {
  steps: Array<{ role: string; symbol: string; file: string; line: number }>
  guards?: number
}): ReactElement {
  const color = (role: string): string =>
    role === 'source' ? '#58b8e8' : role === 'sink' ? '#f2555a' : '#4f8cff'
  return h(
    'div',
    { style: { display: 'flex', alignItems: 'stretch', gap: 0, overflowX: 'auto', padding: '4px 0' } },
    ...props.steps.flatMap((step, i) => {
      const node = h(
        'div',
        {
          key: `n${i}`,
          style: {
            minWidth: 132,
            maxWidth: 200,
            padding: '8px 10px',
            borderRadius: 8,
            border: `1px solid ${color(step.role)}44`,
            background: `${color(step.role)}12`,
            flex: 'none',
          },
        },
        h('div', { style: { fontSize: 9.5, letterSpacing: 0.8, textTransform: 'uppercase', color: color(step.role) } }, step.role),
        h(
          'div',
          { style: { fontSize: 12, fontWeight: 600, margin: '2px 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } },
          step.symbol || '—',
        ),
        h(
          'div',
          { style: { fontSize: 10, color: '#66748c', fontFamily: 'ui-monospace, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } },
          `${step.file.split(/[\\/]/).pop()}:${step.line}`,
        ),
      )
      const arrow =
        i < props.steps.length - 1
          ? h(
              'div',
              {
                key: `a${i}`,
                style: { display: 'flex', alignItems: 'center', color: '#2a3648', padding: '0 2px', flex: 'none' },
              },
              h(
                'svg',
                { width: 22, height: 12, viewBox: '0 0 22 12' },
                h('path', { d: 'M0 6h16M13 2l4 4-4 4', stroke: 'currentColor', strokeWidth: 1.4, fill: 'none', strokeLinecap: 'round' }),
              ),
            )
          : null
      return arrow ? [node, arrow] : [node]
    }),
  )
}
