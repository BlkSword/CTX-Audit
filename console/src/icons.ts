import { createElement as h } from 'react'
import type { ReactNode } from 'react'

/** Inline SVG icon set (16px grid, currentColor). */

const paths: Record<string, ReactNode> = {
  overview: h('path', { d: 'M3 3h7v7H3zM12 3h5v4h-5zM12 10h5v7h-5zM3 13h7v4H3z' }),
  stream: h('path', { d: 'M2 8h3l2-4 3 8 2-4h4' }),
  coverage: h('path', { d: 'M8 2l6 3v4c0 3-2.5 5-6 6-3.5-1-6-3-6-6V5z' }),
  chains: h('path', { d: 'M5 3v4a2 2 0 002 2h2a2 2 0 012 2v2M11 13a2 2 0 100 4 2 2 0 000-4zM5 1a2 2 0 100 4 2 2 0 000-4z' }),
  gate: h('path', { d: 'M2 4h12M2 8h12M2 12h7' }),
  report: h('path', { d: 'M4 2h6l3 3v9H4zM10 2v3h3' }),
  settings: h('path', { d: 'M8 5.5A2.5 2.5 0 108 10.5 2.5 2.5 0 008 5.5zM8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.5 1.5M11.5 11.5L13 13M13 3l-1.5 1.5M4.5 11.5L3 13' }),
  plus: h('path', { d: 'M8 3v10M3 8h10' }),
  refresh: h('path', { d: 'M13 8a5 5 0 11-1.5-3.5M13 2v3h-3' }),
  chevron: h('path', { d: 'M6 4l4 4-4 4' }),
  search: h('path', { d: 'M7 2a5 5 0 103.5 8.5L14 14M7 2a5 5 0 013.5 8.5' }),
  alert: h('path', { d: 'M8 2l6 11H2zM8 6v3M8 11v.5' }),
  check: h('path', { d: 'M3 8l3 3 7-7' }),
  clock: h('path', { d: 'M8 2a6 6 0 100 12A6 6 0 008 2zM8 5v3l2 2' }),
}

export function Icon(props: { name: keyof typeof paths | string; size?: number; className?: string }) {
  return h(
    'svg',
    {
      className: props.className ?? 'ico',
      width: props.size ?? 15,
      height: props.size ?? 15,
      viewBox: '0 0 16 16',
      fill: 'none',
      stroke: 'currentColor',
      strokeWidth: 1.6,
      strokeLinecap: 'round',
      strokeLinejoin: 'round',
      'aria-hidden': true,
    },
    paths[props.name] ?? paths['overview'],
  )
}
