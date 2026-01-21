/**
 * Layout 组件导出
 */

// 新的编辑器布局
export { EditorLayout } from './EditorLayout'
export { AgentPanel } from './AgentPanel'
export { CodeEditorPanel } from './CodeEditorPanel'

// 旧的 VSCode 布局（保留用于兼容）
export { VSCodeLayout } from './VSCodeLayout'
export { ActivityBar } from './ActivityBar'
export { Sidebar } from './Sidebar'
export { BottomPanel } from './BottomPanel'
export { ProjectTabsBar } from './ProjectTabsBar'

// 导出类型
export type { ActivityBarItem, BottomPanelTab, SidebarView } from '@/stores/layoutStore'

// 导出 hooks
export {
  useLayoutStore,
  useActiveActivity,
  useSidebarVisible,
  useAgentPanelVisible,
  useBottomPanelVisible,
  useActiveBottomTab,
} from '@/stores/layoutStore'

// 导出多项目相关
export {
  useMultiProjectStore,
  useOpenProjects,
  useActiveProjectId,
  useActiveProjectState,
} from '@/stores/multiProjectStore'

export type { ProjectAuditState } from '@/stores/multiProjectStore'
export type { EditorLayoutProps } from './EditorLayout'
