/**
 * ActivityBar - 左侧活动栏
 *
 * 只负责主要功能区域的切换
 * 不处理页面内的子导航（如设置的子页面）
 */

import { useLayoutStore, type ActivityId } from '@/stores/layoutStore'
import { ACTIVITY_BAR_ITEMS, getPathWithId } from '@/config/navigation'
import { useNavigate, useLocation } from 'react-router-dom'
import { Settings, Home } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useProjectStore } from '@/stores/projectStore'

// ==================== 类型定义 ====================

interface ActivityButtonProps {
  id: string
  icon: React.ComponentType<{ className?: string }>
  label: string
  isActive: boolean
  isDisabled?: boolean
  onClick: () => void
  shortcut?: string
}

// ==================== 子组件 ====================

/**
 * 单个活动按钮
 */
function ActivityButton({ id, icon: Icon, label, isActive, isDisabled, onClick, shortcut }: ActivityButtonProps) {
  return (
    <button
      onClick={onClick}
      disabled={isDisabled}
      className={cn(
        "relative w-12 h-12 flex items-center justify-center",
        "transition-all duration-150",
        "group",
        isActive && "before:absolute before:left-0 before:top-0 before:bottom-0 before:w-0.5 before:bg-[var(--vscode-activityBar-foreground)]",
        !isActive && !isDisabled && "opacity-60 hover:opacity-100",
        isDisabled && "opacity-30 cursor-not-allowed"
      )}
      title={`${label}${shortcut ? ` (${shortcut})` : ''}${isDisabled ? ' (请先打开项目)' : ''}`}
    >
      <Icon className={cn(
        "w-5 h-5",
        isActive
          ? "text-[var(--vscode-activityBar-foreground)]"
          : "text-[var(--vscode-activityBar-inactiveForeground)]",
        !isDisabled && "group-hover:text-[var(--vscode-activityBar-foreground)]"
      )} />
    </button>
  )
}

/**
 * 分隔线
 */
function Separator() {
  return (
    <div className="w-8 h-0.5 mx-auto my-1 bg-[var(--vscode-activityBar-inactiveForeground)]/20" />
  )
}

// ==================== 主组件 ====================

export function ActivityBar() {
  const navigate = useNavigate()
  const location = useLocation()
  const { activeActivity, setActiveActivity } = useLayoutStore()
  const { currentProject } = useProjectStore()

  // 处理活动项点击
  const handleActivityClick = (itemId: string, itemPathTemplate: string) => {
    // 如果没有项目，提示用户先打开项目
    if (!currentProject) {
      // 不做任何操作，按钮已经被禁用
      return
    }

    // 如果点击当前活动项，则不切换
    if (activeActivity === itemId) {
      return
    }

    // 设置新的活动项
    setActiveActivity(itemId as ActivityId)
    // 使用项目 ID 生成完整路径
    const fullPath = itemPathTemplate.replace('{id}', String(currentProject.id))
    navigate(fullPath)
  }

  // 判断是否是设置页面
  const isSettingsPage = location.pathname.startsWith('/settings')
  // 判断是否是首页
  const isHomePage = location.pathname === '/'

  // 判断是否在编辑器页面
  const isEditorPage = location.pathname.startsWith('/editor')

  return (
    <div className="w-12 h-full bg-[var(--vscode-activityBar-background)] flex flex-col items-center py-2 select-none">
      {/* Logo/首页按钮 */}
      <button
        onClick={() => navigate('/')}
        className={cn(
          "w-12 h-12 flex items-center justify-center mb-2",
          "transition-opacity duration-150",
          isHomePage ? "opacity-100" : "opacity-50 hover:opacity-100"
        )}
        title="主页"
      >
        <Home className={cn(
          "w-5 h-5",
          isHomePage
            ? "text-[var(--vscode-activityBar-foreground)]"
            : "text-[var(--vscode-activityBar-inactiveForeground)]"
        )} />
      </button>

      <Separator />

      {/* 主要活动项 */}
      {ACTIVITY_BAR_ITEMS.map((item) => {
        const isActive = isEditorPage && activeActivity === item.id
        const isDisabled = !currentProject
        return (
          <ActivityButton
            key={item.id}
            id={item.id}
            icon={item.icon}
            label={item.label}
            isActive={isActive}
            isDisabled={isDisabled}
            shortcut={item.shortcut}
            onClick={() => handleActivityClick(item.id, item.pathTemplate)}
          />
        )
      })}

      <Separator />

      {/* 设置按钮 */}
      <ActivityButton
        id="settings"
        icon={Settings}
        label="设置"
        isActive={isSettingsPage}
        onClick={() => navigate('/settings/llm')}
      />
    </div>
  )
}
