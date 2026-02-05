/**
 * FlexLayout - 纯 CSS Flexbox 布局系统
 *
 * 不依赖 react-resizable-panels，使用原生 CSS + 自定义拖拽
 * 更简单、更可靠、更易调试
 */

import { type ReactNode, useState, useRef, useCallback, useEffect } from 'react'
import { cn } from '@/lib/utils'

// 可拖拽的分隔条组件
interface ResizableHandleProps {
  direction: 'horizontal' | 'vertical'
  onDrag: (delta: number) => void
  className?: string
  withHandle?: boolean
}

function ResizableHandle({ direction, onDrag, className, withHandle }: ResizableHandleProps) {
  const [isDragging, setIsDragging] = useState(false)
  const startPosRef = useRef<number>(0)

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    setIsDragging(true)
    startPosRef.current = direction === 'horizontal' ? e.clientX : e.clientY

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const currentPos = direction === 'horizontal' ? moveEvent.clientX : moveEvent.clientY
      const delta = currentPos - startPosRef.current
      onDrag(delta)
    }

    const handleMouseUp = () => {
      setIsDragging(false)
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
    }

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)
  }, [direction, onDrag])

  return (
    <div
      className={cn(
        'relative shrink-0 bg-border hover:bg-primary/20 transition-colors',
        'select-none',
        direction === 'horizontal' ? 'w-1.5 cursor-col-resize' : 'h-1.5 cursor-row-resize',
        isDragging && 'bg-primary/40',
        className
      )}
      onMouseDown={handleMouseDown}
    >
      {withHandle && (
        <div
          className={cn(
            'absolute bg-border rounded-sm flex items-center justify-center',
            direction === 'horizontal'
              ? 'top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-3 h-4'
              : 'left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 h-3 w-4'
          )}
        >
          <div className="flex gap-0.5">
            <div className={cn('w-0.5 h-3 bg-current rounded-full', direction === 'vertical' && 'rotate-90')} />
            <div className={cn('w-0.5 h-3 bg-current rounded-full', direction === 'vertical' && 'rotate-90')} />
          </div>
        </div>
      )}
    </div>
  )
}

// 水平面板组
interface HorizontalGroupProps {
  children: ReactNode
  className?: string
}

export function HorizontalGroup({ children, className }: HorizontalGroupProps) {
  return (
    <div className={cn('flex flex-row h-full overflow-hidden', className)}>
      {children}
    </div>
  )
}

// 垂直面板组
interface VerticalGroupProps {
  children: ReactNode
  className?: string
}

export function VerticalGroup({ children, className }: VerticalGroupProps) {
  return (
    <div className={cn('flex flex-col w-full overflow-hidden', className)}>
      {children}
    </div>
  )
}

// 可调整大小的面板（水平方向）
interface HPanelProps {
  children: ReactNode
  defaultSize: number // 百分比 0-100
  minSize?: number
  maxSize?: number
  onResize?: (size: number) => void
  className?: string
  resizable?: boolean
}

export function HPanel({
  children,
  defaultSize,
  minSize = 10,
  maxSize = 90,
  onResize,
  className,
  resizable = false,  // 默认不可调整大小
}: HPanelProps) {
  const [size, setSize] = useState(defaultSize)
  const panelRef = useRef<HTMLDivElement>(null)
  const groupRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setSize(defaultSize)
  }, [defaultSize])

  const handleDrag = useCallback((delta: number) => {
    if (!resizable || !groupRef.current) return

    const groupWidth = groupRef.current.offsetWidth
    const deltaPercent = (delta / groupWidth) * 100
    const newSize = Math.max(minSize, Math.min(maxSize, size + deltaPercent))

    setSize(newSize)
    onResize?.(newSize)
  }, [size, minSize, maxSize, resizable, onResize])

  return (
    <>
      <div
        ref={panelRef}
        className={cn('overflow-hidden', className)}
        style={{ flex: `0 0 ${size}%` }}
      >
        {children}
      </div>
      {resizable && <ResizableHandle direction="horizontal" onDrag={handleDrag} />}
    </>
  )
}

// 可调整大小的面板（垂直方向）
interface VPanelProps {
  children: ReactNode
  defaultSize: number // 百分比 0-100
  minSize?: number
  maxSize?: number
  onResize?: (size: number) => void
  className?: string
  resizable?: boolean
  showHandle?: boolean
}

export function VPanel({
  children,
  defaultSize,
  minSize = 10,
  maxSize = 90,
  onResize,
  className,
  resizable = false,  // 默认不可调整大小
  showHandle = false,
}: VPanelProps) {
  const [size, setSize] = useState(defaultSize)
  const panelRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setSize(defaultSize)
  }, [defaultSize])

  const handleDrag = useCallback((delta: number) => {
    if (!resizable || !panelRef.current?.parentElement) return

    const groupHeight = panelRef.current.parentElement.offsetHeight
    const deltaPercent = (delta / groupHeight) * 100
    const newSize = Math.max(minSize, Math.min(maxSize, size + deltaPercent))

    setSize(newSize)
    onResize?.(newSize)
  }, [size, minSize, maxSize, resizable, onResize])

  return (
    <>
      <div
        ref={panelRef}
        className={cn('overflow-hidden', className)}
        style={{ flex: `0 0 ${size}%` }}
      >
        {children}
      </div>
      {resizable && showHandle && <ResizableHandle direction="vertical" onDrag={handleDrag} />}
    </>
  )
}

// 固定大小的面板（使用 flex-basis）
interface FixedPanelProps {
  children: ReactNode
  basis: string // CSS width/height 值，如 '48px', '300px'
  className?: string
}

export function FixedPanel({ children, basis, className }: FixedPanelProps) {
  return (
    <div
      className={cn('shrink-0', className)}
      style={{ flexBasis: basis }}
    >
      {children}
    </div>
  )
}

// 弹性面板（占据剩余空间）
interface FlexPanelProps {
  children: ReactNode
  className?: string
}

export function FlexPanel({ children, className }: FlexPanelProps) {
  return (
    <div className={cn('flex-1 min-w-0 min-h-0 overflow-hidden', className)}>
      {children}
    </div>
  )
}
