/**
 * layoutStore - VSCode 风格布局状态管理
 *
 * 管理布局面板的显示/隐藏状态、大小配置等
 */

import { create } from 'zustand'
import { persist } from 'zustand/middleware'

// 活动栏图标类型
export type ActivityBarItem = 'explorer' | 'search' | 'findings' | 'settings'

// 底部面板标签类型
export type BottomPanelTab = 'output' | 'terminal' | 'problems' | 'debug-console' | 'logs'

// 侧边栏视图类型
export type SidebarView = 'explorer' | 'search' | 'findings' | 'settings'

// 布局状态接口
interface LayoutState {
  // 活动栏
  activeActivity: ActivityBarItem | null

  // 侧边栏
  sidebarVisible: boolean
  sidebarSize: number // 百分比 0-100

  // Agent 面板（右侧）
  agentPanelVisible: boolean
  agentPanelSize: number // 百分比 0-100

  // 底部面板
  bottomPanelVisible: boolean
  bottomPanelSize: number // 百分比 0-100
  activeBottomTab: BottomPanelTab

  // 编辑器组
  editorGroupVisible: boolean

  // 操作方法
  setActiveActivity: (item: ActivityBarItem | null) => void
  toggleSidebar: () => void
  setSidebarSize: (size: number) => void
  toggleAgentPanel: () => void
  setAgentPanelSize: (size: number) => void
  toggleBottomPanel: () => void
  setBottomPanelSize: (size: number) => void
  setActiveBottomTab: (tab: BottomPanelTab) => void
  toggleEditorGroup: () => void

  // 重置布局
  resetLayout: () => void
}

// 默认布局配置
const defaultLayout = {
  activeActivity: 'explorer' as ActivityBarItem | null,
  sidebarVisible: true,
  sidebarSize: 20, // 20%
  agentPanelVisible: true,
  agentPanelSize: 35, // 35%
  bottomPanelVisible: false,
  bottomPanelSize: 25, // 25%
  activeBottomTab: 'output' as BottomPanelTab,
  editorGroupVisible: true,
}

// 创建布局 store
export const useLayoutStore = create<LayoutState>()(
  persist(
    (set) => ({
      // 初始状态
      ...defaultLayout,

      // 设置活动栏项
      setActiveActivity: (item) =>
        set((state) => ({
          activeActivity: item,
          // 如果选择了活动项，自动显示侧边栏
          sidebarVisible: item !== null,
        })),

      // 切换侧边栏显示/隐藏
      toggleSidebar: () =>
        set((state) => ({
          sidebarVisible: !state.sidebarVisible,
        })),

      // 设置侧边栏大小
      setSidebarSize: (size) =>
        set(() => ({
          sidebarSize: Math.max(10, Math.min(50, size)),
        })),

      // 切换 Agent 面板显示/隐藏
      toggleAgentPanel: () =>
        set((state) => ({
          agentPanelVisible: !state.agentPanelVisible,
        })),

      // 设置 Agent 面板大小
      setAgentPanelSize: (size) =>
        set(() => ({
          agentPanelSize: Math.max(20, Math.min(50, size)),
        })),

      // 切换底部面板显示/隐藏
      toggleBottomPanel: () =>
        set((state) => ({
          bottomPanelVisible: !state.bottomPanelVisible,
        })),

      // 设置底部面板大小
      setBottomPanelSize: (size) =>
        set({
          bottomPanelSize: Math.max(10, Math.min(60, size)), // 限制在 10%-60% 之间
        }),

      // 设置底部面板激活标签
      setActiveBottomTab: (tab) =>
        set({
          activeBottomTab: tab,
          bottomPanelVisible: true,
        }),

      // 切换编辑器组
      toggleEditorGroup: () =>
        set((state) => ({
          editorGroupVisible: !state.editorGroupVisible,
        })),

      // 重置布局
      resetLayout: () =>
        set(defaultLayout),
    }),
    {
      name: 'ctx-audit-layout', // localStorage key
      version: 2,
    }
  )
)

// 便捷 hooks
export const useActiveActivity = () => useLayoutStore((state) => state.activeActivity)
export const useSidebarVisible = () => useLayoutStore((state) => state.sidebarVisible)
export const useAgentPanelVisible = () => useLayoutStore((state) => state.agentPanelVisible)
export const useBottomPanelVisible = () => useLayoutStore((state) => state.bottomPanelVisible)
export const useActiveBottomTab = () => useLayoutStore((state) => state.activeBottomTab)
