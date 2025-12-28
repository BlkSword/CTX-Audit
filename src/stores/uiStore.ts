/**
 * UI 状态管理
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'

interface UIState {
  // 侧边栏状态
  activeSidebar: 'explorer' | 'search' | 'tools' | 'none'
  sidebarWidth: number

  // 底部面板状态
  activeBottomTab: 'output' | 'problems' | 'terminal'
  bottomPanelHeight: number
  bottomPanelVisible: boolean

  // 主内容区
  activeView: 'editor' | 'graph' | 'scan' | 'analysis' | 'agent'

  // 日志 - 使用本地的 LogEntry 类型
  logs: {
    id: string
    timestamp: string
    message: string
    source: 'system' | 'rust' | 'python'
  }[]

  // 菜单
  activeMenu: string | null

  // Actions
  setActiveSidebar: (sidebar: UIState['activeSidebar']) => void
  setSidebarWidth: (width: number) => void
  setActiveBottomTab: (tab: UIState['activeBottomTab']) => void
  setBottomPanelHeight: (height: number) => void
  setBottomPanelVisible: (visible: boolean) => void
  setActiveView: (view: UIState['activeView']) => void
  addLog: (message: string, source: 'system' | 'rust' | 'python') => void
  clearLogs: () => void
  setActiveMenu: (menu: string | null) => void
}

export const useUIStore = create<UIState>()(
  devtools(
    persist(
      (set) => ({
        activeSidebar: 'explorer',
        sidebarWidth: 250,

        activeBottomTab: 'output',
        bottomPanelHeight: 200,
        bottomPanelVisible: true,

        activeView: 'editor',

        logs: [],

        activeMenu: null,

        setActiveSidebar: (sidebar) => set({ activeSidebar: sidebar }),

        setSidebarWidth: (width) => set({ sidebarWidth: width }),

        setActiveBottomTab: (tab) => set({ activeBottomTab: tab }),

        setBottomPanelHeight: (height) => set({ bottomPanelHeight: height }),

        setBottomPanelVisible: (visible) => set({ bottomPanelVisible: visible }),

        setActiveView: (view) => set({ activeView: view }),

        addLog: (message, source = 'system') => {
          const log = {
            id: Date.now().toString() + Math.random(),
            timestamp: new Date().toLocaleTimeString(),
            message,
            source
          }

          set(state => {
            const MAX_LOGS = 2000
            const logs = [...state.logs, log]
            if (logs.length > MAX_LOGS) {
              return { logs: logs.slice(logs.length - MAX_LOGS) }
            }
            return { logs }
          })
        },

        clearLogs: () => set({ logs: [] }),

        setActiveMenu: (menu) => set({ activeMenu: menu }),
      }),
      {
        name: 'ui-storage',
        partialize: (state) => ({
          sidebarWidth: state.sidebarWidth,
          bottomPanelHeight: state.bottomPanelHeight,
        }),
      }
    ),
    { name: 'ui-store' }
  )
)
