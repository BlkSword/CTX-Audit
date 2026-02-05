/**
 * 导航配置系统
 *
 * 统一管理所有导航项，作为单一数据源
 *
 * 注意：路径需要项目 ID，在使用时需要动态拼接
 * 例如：`/editor/${projectId}` 或 `/editor/${projectId}?panel=search`
 */

import type { LucideProps } from 'lucide-react'
import {
  Home,
  FileCode,
  Search,
  BarChart3,
  Settings,
  Terminal,
  Zap,
  GitGraph,
  Database,
  Layers,
} from 'lucide-react'

// ==================== 类型定义 ====================

export interface NavItem {
  id: string
  label: string
  icon: React.ComponentType<LucideProps>
  // 路径模板，使用 {id} 作为项目 ID 占位符
  pathTemplate: string
  description?: string
  shortcut?: string
  disabled?: boolean
  separator?: boolean
}

export interface ToolPanel {
  id: string
  label: string
  icon: React.ComponentType<LucideProps>
  description?: string
  defaultShortcut?: string
  position: 'left' | 'right' | 'bottom'
}

// ==================== 全局导航配置 ====================

/**
 * ActivityBar 导航项（左侧活动栏）
 * 这些是主要的功能区域切换
 * 注意：路径需要动态拼接项目 ID
 */
export const ACTIVITY_BAR_ITEMS: NavItem[] = [
  {
    id: 'explorer',
    label: '资源管理器',
    icon: FileCode,
    pathTemplate: '/editor/{id}',
    description: '浏览和管理项目文件',
    shortcut: 'Ctrl+Shift+E',
  },
  {
    id: 'search',
    label: '搜索',
    icon: Search,
    pathTemplate: '/editor/{id}?panel=search',
    description: '在项目中搜索',
    shortcut: 'Ctrl+Shift+F',
  },
  {
    id: 'ast-tools',
    label: 'AST 工具',
    icon: GitGraph,
    pathTemplate: '/editor/{id}?panel=ast',
    description: '代码分析和符号工具',
    shortcut: 'Ctrl+Shift+A',
  },
  {
    id: 'scan-results',
    label: '扫描结果',
    icon: BarChart3,
    pathTemplate: '/editor/{id}?panel=scan',
    description: '查看安全扫描结果',
    shortcut: 'Ctrl+Shift+R',
  },
  {
    id: 'terminal',
    label: '终端',
    icon: Terminal,
    pathTemplate: '/editor/{id}?panel=terminal',
    description: '打开集成终端',
    shortcut: 'Ctrl+`',
  },
]

/**
 * 根据项目 ID 生成完整路径
 */
export function getPathWithId(item: NavItem, projectId: number): string {
  return item.pathTemplate.replace('{id}', String(projectId))
}

/**
 * 工具面板配置
 * 这些是可以展开/收起的辅助面板
 */
export const TOOL_PANELS: ToolPanel[] = [
  // 左侧工具面板
  {
    id: 'file-scanner',
    label: '文件扫描',
    icon: Zap,
    description: '实时扫描当前文件的安全问题',
    defaultShortcut: 'Ctrl+Shift+S',
    position: 'left',
  },

  // 右侧工具面板
  {
    id: 'ast-outline',
    label: '大纲',
    icon: Layers,
    description: '查看当前文件的符号大纲',
    position: 'right',
  },
  {
    id: 'call-graph',
    label: '调用图',
    icon: GitGraph,
    description: '查看函数调用关系图',
    position: 'right',
  },

  // 底部工具面板
  {
    id: 'problems',
    label: '问题',
    icon: Zap,
    description: '查看当前项目的问题列表',
    position: 'bottom',
  },
  {
    id: 'output',
    label: '输出',
    icon: Terminal,
    description: '查看应用输出信息',
    position: 'bottom',
  },
  {
    id: 'debug-console',
    label: '调试控制台',
    icon: Terminal,
    description: '调试时的控制台输出',
    position: 'bottom',
  },
]

// ==================== 设置导航配置 ====================

/**
 * 设置页面导航项（仅顶部导航，不与 ActivityBar 混合）
 * 注意：设置页面不需要项目 ID
 */
export const SETTINGS_NAV_ITEMS: NavItem[] = [
  {
    id: 'llm',
    label: 'LLM 配置',
    icon: Database,
    pathTemplate: '/settings/llm',
    description: '配置语言模型和 API 密钥',
  },
  {
    id: 'prompts',
    label: '提示词模板',
    icon: FileCode,
    pathTemplate: '/settings/prompts',
    description: '管理 Agent 提示词模板',
  },
  {
    id: 'rules',
    label: '审计规则',
    icon: Zap,
    pathTemplate: '/settings/rules',
    description: '配置安全审计规则',
  },
  {
    id: 'system',
    label: '系统设置',
    icon: Settings,
    pathTemplate: '/settings/system',
    description: '应用程序首选项',
  },
]

// ==================== 辅助函数 ====================

/**
 * 根据 ID 获取导航项
 */
export function getNavItemById(id: string, items: NavItem[]): NavItem | undefined {
  return items.find(item => item.id === id)
}

/**
 * 根据路径获取导航项
 */
export function getNavItemByPath(path: string, items: NavItem[]): NavItem | undefined {
  return items.find(item => {
    const itemPath = item.pathTemplate.replace('{id}', '\\d+')
    const regex = new RegExp(`^${itemPath}(/|$)`)
    return regex.test(path)
  })
}

/**
 * 根据 ID 获取工具面板
 */
export function getToolPanelById(id: string): ToolPanel | undefined {
  return TOOL_PANELS.find(panel => panel.id === id)
}

/**
 * 获取指定位置的工具面板列表
 */
export function getToolPanelsByPosition(position: 'left' | 'right' | 'bottom'): ToolPanel[] {
  return TOOL_PANELS.filter(panel => panel.position === position)
}

/**
 * 判断路径是否是设置页面
 */
export function isSettingsPath(path: string): boolean {
  return path.startsWith('/settings')
}

/**
 * 判断路径是否是编辑器页面
 */
export function isEditorPath(path: string): boolean {
  return path.startsWith('/editor') || path.startsWith('/project/')
}
