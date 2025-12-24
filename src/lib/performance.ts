import { useState, useRef } from 'react'

/**
 * 性能优化工具函数
 * 提供防抖、节流、批量更新等功能
 */

/**
 * 防抖函数 - 延迟执行，适用于搜索等场景
 */
export function debounce<T extends (...args: any[]) => void>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: number | null = null

  return function executedFunction(...args: Parameters<T>) {
    const later = () => {
      timeout = null
      func(...args)
    }

    if (timeout !== null) {
      clearTimeout(timeout)
    }
    timeout = setTimeout(later, wait)
  }
}

/**
 * 节流函数 - 限制执行频率
 */
export function throttle<T extends (...args: any[]) => void>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle = false

  return function executedFunction(...args: Parameters<T>) {
    if (!inThrottle) {
      func(...args)
      inThrottle = true
      setTimeout(() => inThrottle = false, limit)
    }
  }
}

/**
 * 批量更新状态 - 合并多次 setState
 */
export function createBatchedUpdater<T>(
  setState: React.Dispatch<React.SetStateAction<T[]>>,
  maxBatchSize = 100,
  timeoutMs = 100
) {
  const pendingRef: { current: T[] } = { current: [] }
  let timer: number | null = null

  const flush = () => {
    if (timer) {
      clearTimeout(timer)
      timer = null
    }
    if (pendingRef.current.length > 0) {
      setState(prev => {
        const merged = [...prev, ...pendingRef.current]
        pendingRef.current = []
        return merged
      })
    }
  }

  const add = (item: T) => {
    pendingRef.current.push(item)

    if (pendingRef.current.length >= maxBatchSize) {
      flush()
    } else if (!timer) {
      timer = setTimeout(flush, timeoutMs)
    }
  }

  const getPending = () => pendingRef.current

  return { add, flush, getPending }
}

/**
 * 性能监控钩子
 */
export function usePerformanceMark(name: string) {
  const startTimeRef = useRef<number>(0)

  const start = () => {
    startTimeRef.current = performance.now()
    performance.mark(`${name}-start`)
  }

  const end = () => {
    performance.mark(`${name}-end`)
    performance.measure(name, `${name}-start`, `${name}-end`)
    const duration = performance.now() - startTimeRef.current
    console.log(`${name}: ${duration.toFixed(2)}ms`)
    return duration
  }

  return { start, end }
}

/**
 * 虚拟化列表的简单实现
 */
export function useVirtualList<T>(
  items: T[],
  itemHeight: number,
  containerHeight: number
) {
  const [scrollTop, setScrollTop] = useState(0)
  const startIndex = Math.floor(scrollTop / itemHeight)
  const endIndex = Math.min(
    items.length - 1,
    Math.floor((scrollTop + containerHeight) / itemHeight)
  )
  const visibleItems = items.slice(startIndex, endIndex + 1)

  const handleScroll = (e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop)
  }

  return {
    visibleItems,
    startIndex,
    endIndex,
    handleScroll,
    contentHeight: items.length * itemHeight,
    offset: startIndex * itemHeight
  }
}
