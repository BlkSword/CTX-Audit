/**
 * 设置页面布局 (VSCode 风格)
 */

import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  ArrowLeft,
  Settings,
  Server,
  Sliders,
  FileText,
  Shield,
} from 'lucide-react'
import { VSCodeLayout } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const settingsNavItems = [
  {
    id: 'llm',
    label: 'LLM 配置',
    icon: Server,
    path: '/settings/llm',
  },
  {
    id: 'system',
    label: '系统设置',
    icon: Sliders,
    path: '/settings/system',
  },
  {
    id: 'prompts',
    label: '提示词模板',
    icon: FileText,
    path: '/settings/prompts',
  },
  {
    id: 'rules',
    label: '安全规则',
    icon: Shield,
    path: '/settings/rules',
  },
]

export function SettingsLayout() {
  const navigate = useNavigate()
  const location = useLocation()

  // VSCode 风格的 Header
  const header = (
    <header className="h-9 flex items-center justify-between px-3 bg-[#3c3c3c] border-b border-border/40 select-none">
      <div className="flex items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="h-6 w-6 text-muted-foreground hover:text-white hover:bg-white/10"
          onClick={() => navigate('/')}
          title="返回仪表板"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
        </Button>
        <div className="flex items-center gap-2">
          <Settings className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium text-white">设置</span>
        </div>
      </div>

      {/* Settings Navigation Tabs */}
      <div className="flex items-center gap-1 bg-[#252526] rounded p-0.5">
        {settingsNavItems.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.path

          return (
            <button
              key={item.id}
              onClick={() => navigate(item.path)}
              className={cn(
                'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium transition-all',
                isActive
                  ? 'bg-[#1e1e1e] text-white'
                  : 'text-muted-foreground hover:text-white hover:bg-white/5'
              )}
              title={item.label}
            >
              <Icon className="w-3 h-3" />
              {item.label}
            </button>
          )
        })}
      </div>

      <div className="w-20"></div>
    </header>
  )

  return (
    <VSCodeLayout
      header={header}
      editorContent={<Outlet />}
      showActivityBar={true}
      showProjectTabs={false}
    />
  )
}
