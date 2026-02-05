/**
 * useKeyboard - 全局快捷键管理
 *
 * 提供常用的编辑器快捷键支持
 */

import { useEffect } from 'react'
import { useLayoutStore, toggleSidebar } from '@/stores/layoutStore'

interface KeyboardShortcut {
  key: string
  ctrl?: boolean
  shift?: boolean
  alt?: boolean
  meta?: boolean
  description: string
  action: () => void
}

export function useKeyboard(shortcuts: KeyboardShortcut[]) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // 如果用户正在输入（在 input、textarea 中），不触发快捷键
      const target = e.target as HTMLElement
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        return
      }

      // 检查快捷键
      for (const shortcut of shortcuts) {
        const keyMatch = e.key.toLowerCase() === shortcut.key.toLowerCase() ||
          (shortcut.key.length === 1 && e.key === shortcut.key)

        const ctrlMatch = shortcut.ctrl ? e.ctrlKey || e.metaKey : !e.ctrlKey && !e.metaKey
        const shiftMatch = shortcut.shift ? e.shiftKey : !e.shiftKey
        const altMatch = shortcut.alt ? e.altKey : !e.altKey
        const metaMatch = shortcut.meta ? e.metaKey : !e.metaKey

        if (keyMatch && ctrlMatch && shiftMatch && altMatch && metaMatch) {
          e.preventDefault()
          shortcut.action()
          return
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [shortcuts])
}

// 编辑器默认快捷键
export function useEditorShortcuts() {
  useKeyboard([
    {
      key: 'p',
      ctrl: true,
      description: '快速打开文件',
      action: () => useLayoutStore.getState().setActiveActivity('search')
    },
    {
      key: 'f',
      ctrl: true,
      shift: true,
      description: '在文件中搜索',
      action: () => useLayoutStore.getState().setActiveActivity('search')
    },
    {
      key: 'b',
      ctrl: true,
      description: '切换侧边栏',
      action: () => toggleSidebar()
    },
    {
      key: 'Escape',
      description: '关闭面板',
      action: () => {
        const { activeActivity } = useLayoutStore.getState()
        // 当搜索打开时，关闭它（settings 不再是 activity，由路由处理）
        if (activeActivity === 'search') {
          useLayoutStore.getState().setActiveActivity('explorer')
        }
      }
    }
  ])
}
