/**
 * ActivityBar - VSCode 风格左侧活动栏
 *
 * 显示用于切换不同侧边栏视图的图标按钮
 */

import { FileText, Search, AlertTriangle, Settings, X, PanelRightClose, PanelRight } from 'lucide-react'
import { useLayoutStore } from '@/stores/layoutStore'
import type { ActivityBarItem } from '@/stores/layoutStore'
import { cn } from '@/lib/utils'

// 活动栏项配置
const activityBarItems: Array<{
  id: ActivityBarItem
  icon: typeof FileText
  label: string
}> = [
  { id: 'explorer', icon: FileText, label: '资源管理器' },
  { id: 'search', icon: Search, label: '搜索' },
  { id: 'findings', icon: AlertTriangle, label: '扫描结果' },
  { id: 'settings', icon: Settings, label: '设置' },
]

export function ActivityBar() {
  const { activeActivity, setActiveActivity, sidebarVisible, agentPanelVisible, toggleAgentPanel } = useLayoutStore()

  const handleItemClick = (itemId: ActivityBarItem) => {
    // 如果点击的是当前活动项，则切换侧边栏显示/隐藏
    if (activeActivity === itemId) {
      if (sidebarVisible) {
        setActiveActivity(null)
      }
    } else {
      // 切换到新的活动项
      setActiveActivity(itemId)
    }
  }

  return (
    <div className="flex flex-col items-center py-2 gap-1 w-12 h-full bg-[#3c3c3c] border-r border-border/40 select-none">
      {/* 应用图标 */}
      <div className="w-full flex items-center justify-center py-3 mb-2">
        <div className="w-8 h-8 rounded bg-gradient-to-br from-primary to-primary/60 flex items-center justify-center">
          <span className="text-white font-bold text-sm">C</span>
        </div>
      </div>

      {/* 分隔线 */}
      <div className="w-8 h-[1px] bg-border/40 mb-2" />

      {/* 活动项 */}
      {activityBarItems.map((item) => {
        const Icon = item.icon
        const isActive = activeActivity === item.id

        return (
          <button
            key={item.id}
            onClick={() => handleItemClick(item.id)}
            className={cn(
              'relative w-full py-3 flex items-center justify-center text-muted-foreground hover:text-white transition-colors group',
              isActive && 'text-white before:absolute before:left-0 before:top-0 before:bottom-0 before:w-0.5 before:bg-white'
            )}
            title={item.label}
          >
            <Icon className="w-6 h-6" />
          </button>
        )
      })}

      {/* 底部空间占位 */}
      <div className="flex-1" />

      {/* Agent 面板切换按钮 */}
      <button
        onClick={toggleAgentPanel}
        className={cn(
          'w-full py-3 flex items-center justify-center transition-colors relative',
          agentPanelVisible
            ? 'text-white before:absolute before:left-0 before:top-0 before:bottom-0 before:w-0.5 before:bg-white'
            : 'text-muted-foreground hover:text-white'
        )}
        title={agentPanelVisible ? '隐藏 Agent 面板' : '显示 Agent 面板'}
      >
        {agentPanelVisible ? <PanelRightClose className="w-5 h-5" /> : <PanelRight className="w-5 h-5" />}
      </button>

      {/* 关闭侧边栏按钮 */}
      {sidebarVisible && (
        <button
          onClick={() => {
            setActiveActivity(null)
          }}
          className="w-full py-3 flex items-center justify-center text-muted-foreground hover:text-white transition-colors"
          title="隐藏侧边栏"
        >
          <X className="w-5 h-5" />
        </button>
      )}
    </div>
  )
}
