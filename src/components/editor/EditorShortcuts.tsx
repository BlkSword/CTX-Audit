/**
 * EditorShortcuts - 编辑器快捷键支持
 *
 * 提供 VSCode 风格的编辑器快捷键
 */

import { useEffect, useCallback } from 'react'
import { useEditorStore } from '@/stores/editorStore'
import { useFindingMarkerStore } from '@/stores/findingMarkerStore'
import { useLayoutStore, setActiveBottomTab } from '@/stores/layoutStore'
import { useRealtimeAuditStore } from '@/stores/realTimeAuditStore'

export interface EditorShortcutsProps {
  enabled?: boolean
}

/**
 * 快捷键处理器
 */
export function EditorShortcuts({ enabled = true }: EditorShortcutsProps) {
  const {
    closeFile,
    editorGroups,
    activeGroupId,
    splitGroup,
  } = useEditorStore()
  const { jumpToFinding } = useFindingMarkerStore()
  const toggleBottomPanel = useLayoutStore(state => state.toggleBottomPanel)
  const { autoMode, setAutoMode } = useRealtimeAuditStore()

  /**
   * 处理快捷键
   */
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!enabled) return

      const isCtrl = event.ctrlKey || event.metaKey
      const isShift = event.shiftKey
      const key = event.key.toLowerCase()

      // Ctrl+\: 水平拆分编辑器
      if (isCtrl && !isShift && key === '\\' && activeGroupId) {
        event.preventDefault()
        splitGroup(activeGroupId, 'horizontal')
        return
      }

      // Ctrl+Shift+\: 垂直拆分编辑器
      if (isCtrl && isShift && key === '\\' && activeGroupId) {
        event.preventDefault()
        splitGroup(activeGroupId, 'vertical')
        return
      }

      // Ctrl+W: 关闭当前文件
      if (isCtrl && !isShift && key === 'w' && activeGroupId) {
        event.preventDefault()
        const activeGroup = editorGroups.find((g) => g.id === activeGroupId)
        if (activeGroup?.activeFile) {
          closeFile(activeGroupId, activeGroup.activeFile.path)
        }
        return
      }

      // F8: 跳转到下一个问题
      if (!isCtrl && !isShift && key === 'f8') {
        event.preventDefault()
        // TODO: 实现跳转到下一个问题
        console.log('Next problem')
        return
      }

      // Shift+F8: 跳转到上一个问题
      if (!isCtrl && isShift && key === 'f8') {
        event.preventDefault()
        // TODO: 实现跳转到上一个问题
        console.log('Previous problem')
        return
      }

      // Ctrl+Shift+M: 打开/关闭问题面板
      if (isCtrl && isShift && key === 'm') {
        event.preventDefault()
        setActiveBottomTab('problems')
        toggleBottomPanel()
        return
      }

      // Ctrl+Shift+A: 切换审计模式
      if (isCtrl && isShift && key === 'a') {
        event.preventDefault()
        setAutoMode(!autoMode)
        return
      }

      // Ctrl+Shift+S: 触发扫描
      if (isCtrl && isShift && key === 's') {
        event.preventDefault()
        // TODO: 触发当前文件扫描
        console.log('Trigger scan')
        return
      }
    },
    [
      enabled,
      activeGroupId,
      editorGroups,
      splitGroup,
      closeFile,
      jumpToFinding,
      toggleBottomPanel,
      setActiveBottomTab,
      autoMode,
      setAutoMode,
    ]
  )

  /**
   * 注册快捷键监听
   */
  useEffect(() => {
    if (enabled) {
      window.addEventListener('keydown', handleKeyDown)
      return () => {
        window.removeEventListener('keydown', handleKeyDown)
      }
    }
  }, [enabled, handleKeyDown])

  return null // 这是一个管理组件，不渲染任何 UI
}

/**
 * 快捷键帮助信息
 */
export const SHORTCUT_HELP = [
  {
    category: '编辑器操作',
    shortcuts: [
      { key: 'Ctrl+\\', description: '水平拆分编辑器' },
      { key: 'Ctrl+Shift+\\', description: '垂直拆分编辑器' },
      { key: 'Ctrl+W', description: '关闭当前文件' },
      { key: 'Ctrl+Tab', description: '切换到下一个文件' },
      { key: 'Ctrl+Shift+Tab', description: '切换到上一个文件' },
    ],
  },
  {
    category: '问题导航',
    shortcuts: [
      { key: 'F8', description: '跳转到下一个问题' },
      { key: 'Shift+F8', description: '跳转到上一个问题' },
      { key: 'Ctrl+Shift+M', description: '打开/关闭问题面板' },
    ],
  },
  {
    category: '审计操作',
    shortcuts: [
      { key: 'Ctrl+Shift+A', description: '切换审计模式' },
      { key: 'Ctrl+Shift+S', description: '触发扫描' },
    ],
  },
  {
    category: '面板操作',
    shortcuts: [
      { key: 'Ctrl+B', description: '切换侧边栏' },
      { key: 'Ctrl+J', description: '切换底部面板' },
      { key: 'Ctrl+1', description: '聚焦编辑器' },
    ],
  },
]

/**
 * 快捷键帮助面板组件
 */
export function ShortcutHelpPanel() {
  return (
    <div className="p-4 bg-[#252526] text-white">
      <h3 className="text-sm font-semibold mb-3">键盘快捷键</h3>
      <div className="space-y-4">
        {SHORTCUT_HELP.map((category) => (
          <div key={category.category}>
            <h4 className="text-xs text-muted-foreground mb-2">
              {category.category}
            </h4>
            <div className="space-y-1">
              {category.shortcuts.map((shortcut) => (
                <div
                  key={shortcut.key}
                  className="flex items-center justify-between text-xs"
                >
                  <span className="text-muted-foreground">
                    {shortcut.description}
                  </span>
                  <kbd className="px-2 py-0.5 bg-[#1e1e1e] border border-border/40 rounded text-[10px]">
                    {shortcut.key}
                  </kbd>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
