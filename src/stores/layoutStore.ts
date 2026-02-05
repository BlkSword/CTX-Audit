/**
 * LayoutStore - 布局状态管理
 *
 * 简化版：只管理必要的布局状态
 * 页面级导航由各自页面管理
 */

import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { NavItem, ToolPanel } from '@/config/navigation'
import { ACTIVITY_BAR_ITEMS, getNavItemById } from '@/config/navigation'

// ==================== 类型定义 ====================

export type ActivityId = 'explorer' | 'search' | 'ast-tools' | 'scan-results' | 'terminal' | null

// 兼容旧代码的类型别名（待移除）
export type ActivityBarItem = ActivityId extends null ? 'explorer' : ActivityId
export type BottomPanelTab = 'output' | 'terminal' | 'problems' | 'debug-console' | 'logs'
export type SidebarView = 'explorer' | 'search' | 'findings' | 'settings'

export interface LayoutState {
  // 当前活动区域
  activeActivity: ActivityId
  setActiveActivity: (activityId: ActivityId) => void

  // 左侧边栏状态
  leftSidebarVisible: boolean
  setLeftSidebarVisible: (visible: boolean) => void
  toggleLeftSidebar: () => void

  // 右侧边栏状态
  rightSidebarVisible: boolean
  setRightSidebarVisible: (visible: boolean) => void
  toggleRightSidebar: () => void

  // 底部面板状态
  bottomPanelVisible: boolean
  setBottomPanelVisible: (visible: boolean) => void
  toggleBottomPanel: () => void

  // 底部面板高度（百分比）
  bottomPanelSize: number
  setBottomPanelSize: (size: number) => void

  // 侧边栏宽度（百分比）
  leftSidebarSize: number
  setLeftSidebarSize: (size: number) => void

  rightSidebarSize: number
  setRightSidebarSize: (size: number) => void

  // 工具面板状态（按位置分组）
  visibleToolPanels: {
    left: string[]
    right: string[]
    bottom: string[]
  }
  toggleToolPanel: (panelId: string, position: 'left' | 'right' | 'bottom') => void
  isToolPanelVisible: (panelId: string, position: 'left' | 'right' | 'bottom') => boolean

  // 重置所有状态
  resetLayout: () => void
}

// ==================== Store ====================

export const useLayoutStore = create<LayoutState>()(
  persist(
    (set, get) => ({
      // 初始状态
      activeActivity: 'explorer',
      leftSidebarVisible: true,
      rightSidebarVisible: false,
      bottomPanelVisible: false,
      bottomPanelSize: 25,
      leftSidebarSize: 20,
      rightSidebarSize: 20,
      visibleToolPanels: {
        left: [],
        right: [],
        bottom: ['problems'],
      },

      // 设置活动区域
      setActiveActivity: (activityId) => {
        set({ activeActivity: activityId })

        // 根据活动区域自动显示/隐藏侧边栏
        if (activityId === 'terminal') {
          set({ bottomPanelVisible: true })
        } else if (activityId === 'explorer') {
          set({ leftSidebarVisible: true })
        }
      },

      // 左侧边栏
      setLeftSidebarVisible: (visible) => set({ leftSidebarVisible: visible }),
      toggleLeftSidebar: () => set((state) => ({ leftSidebarVisible: !state.leftSidebarVisible })),

      // 右侧边栏
      setRightSidebarVisible: (visible) => set({ rightSidebarVisible: visible }),
      toggleRightSidebar: () => set((state) => ({ rightSidebarVisible: !state.rightSidebarVisible })),

      // 底部面板
      setBottomPanelVisible: (visible) => set({ bottomPanelVisible: visible }),
      toggleBottomPanel: () => set((state) => ({ bottomPanelVisible: !state.bottomPanelVisible })),
      setBottomPanelSize: (size) => set({ bottomPanelSize: Math.max(15, Math.min(50, size)) }),

      // 侧边栏大小
      setLeftSidebarSize: (size) => set({ leftSidebarSize: Math.max(15, Math.min(40, size)) }),
      setRightSidebarSize: (size) => set({ rightSidebarSize: Math.max(15, Math.min(40, size)) }),

      // 工具面板切换
      toggleToolPanel: (panelId, position) => set((state) => {
        const panels = state.visibleToolPanels[position]
        const index = panels.indexOf(panelId)

        if (index >= 0) {
          // 移除面板
          return {
            visibleToolPanels: {
              ...state.visibleToolPanels,
              [position]: panels.filter(p => p !== panelId)
            }
          }
        } else {
          // 添加面板
          return {
            visibleToolPanels: {
              ...state.visibleToolPanels,
              [position]: [...panels, panelId]
            },
            // 自动显示对应的边栏/底部面板
            ...(position === 'bottom' && !state.bottomPanelVisible && { bottomPanelVisible: true }),
            ...(position === 'left' && !state.leftSidebarVisible && { leftSidebarVisible: true }),
            ...(position === 'right' && !state.rightSidebarVisible && { rightSidebarVisible: true }),
          }
        }
      }),

      isToolPanelVisible: (panelId, position) => {
        return get().visibleToolPanels[position].includes(panelId)
      },

      // 重置布局
      resetLayout: () => set({
        activeActivity: 'explorer',
        leftSidebarVisible: true,
        rightSidebarVisible: false,
        bottomPanelVisible: false,
        bottomPanelSize: 25,
        leftSidebarSize: 20,
        rightSidebarSize: 20,
        visibleToolPanels: {
          left: [],
          right: [],
          bottom: ['problems'],
        },
      }),
    }),
    {
      name: 'ctx-audit-layout',
      partialize: (state) => ({
        activeActivity: state.activeActivity,
        leftSidebarSize: state.leftSidebarSize,
        rightSidebarSize: state.rightSidebarSize,
        bottomPanelSize: state.bottomPanelSize,
      }),
    }
  )
)

// ==================== 辅助函数 ====================

/**
 * 获取当前活动区域的导航项
 */
export function getActiveNavItem(): NavItem | undefined {
  const { activeActivity } = useLayoutStore.getState()
  if (!activeActivity) return undefined
  return getNavItemById(activeActivity, ACTIVITY_BAR_ITEMS)
}

// ==================== 兼容旧代码的导出 ====================

/**
 * 获取当前活动区域（旧组件使用）
 */
export function useActiveActivity() {
  return useLayoutStore(state => state.activeActivity)
}

/**
 * 获取侧边栏可见性（旧组件使用）
 */
export function useSidebarVisible() {
  return useLayoutStore(state => state.leftSidebarVisible)
}

/**
 * 获取 Agent 面板可见性（旧组件使用）
 */
export function useAgentPanelVisible() {
  // 旧组件的 Agent 面板现在对应右侧边栏
  return useLayoutStore(state => state.rightSidebarVisible)
}

/**
 * 获取底部面板可见性（旧组件使用）
 */
export function useBottomPanelVisible() {
  return useLayoutStore(state => state.bottomPanelVisible)
}

/**
 * 获取激活的底部面板标签（旧组件使用）
 */
export function useActiveBottomTab() {
  // 简化：返回固定的标签
  return useLayoutStore(state => state.visibleToolPanels.bottom[0] || 'problems' as BottomPanelTab)
}

/**
 * 旧组件使用的 toggleSidebar 方法
 */
export function toggleSidebar() {
  useLayoutStore.getState().toggleLeftSidebar()
}

/**
 * 旧组件使用的 toggleAgentPanel 方法
 */
export function toggleAgentPanel() {
  useLayoutStore.getState().toggleRightSidebar()
}

/**
 * 旧组件使用的 toggleBottomPanel 方法
 */
export function toggleBottomPanel() {
  useLayoutStore.getState().toggleBottomPanel()
}

/**
 * 旧组件使用的 setActiveBottomTab 方法
 */
export function setActiveBottomTab(tab: BottomPanelTab) {
  // 更新工具面板列表
  useLayoutStore.getState().toggleToolPanel(tab, 'bottom')
}

// ==================== 额外的向后兼容选择器 ====================

/**
 * 获取侧边栏尺寸（旧组件使用）
 */
export function useSidebarSize() {
  return useLayoutStore(state => state.leftSidebarSize)
}

/**
 * 获取 Agent 面板尺寸（旧组件使用）
 */
export function useAgentPanelSize() {
  return useLayoutStore(state => state.rightSidebarSize)
}

/**
 * 设置侧边栏尺寸（旧组件使用）
 */
export function setSidebarSize(size: number) {
  useLayoutStore.getState().setLeftSidebarSize(size)
}

/**
 * 设置 Agent 面板尺寸（旧组件使用）
 */
export function setAgentPanelSize(size: number) {
  useLayoutStore.getState().setRightSidebarSize(size)
}
