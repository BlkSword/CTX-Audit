/**
 * Sidebar - VSCode 风格侧边栏
 *
 * 根据活动栏显示不同的侧边栏内容：
 * - explorer: 文件资源管理器
 * - search: 搜索
 * - findings: 扫描结果
 * - settings: 设置
 */

import { useState } from 'react'
import { FileText, Search, AlertTriangle, Settings } from 'lucide-react'
import { useLayoutStore } from '@/stores/layoutStore'
import type { ActivityBarItem } from '@/stores/layoutStore'
import { FileTree } from '@/components/file-explorer/FileTree'
import type { FileNode } from '@/components/file-explorer/FileTree'
import { useFileStore } from '@/stores/fileStore'
import { useScanStore } from '@/stores/scanStore'
import { ResizablePanel } from '@/components/ui/resizable'
import { cn } from '@/lib/utils'

// 侧边栏标题映射
const sidebarTitles: Record<ActivityBarItem, string> = {
  explorer: '资源管理器',
  search: '搜索',
  findings: '扫描结果',
  settings: '设置',
}

const sidebarIcons: Record<ActivityBarItem, React.ElementType> = {
  explorer: FileText,
  search: Search,
  findings: AlertTriangle,
  settings: Settings,
}

interface SidebarProps {
  className?: string
}

export function Sidebar({ className }: SidebarProps) {
  const { activeActivity } = useLayoutStore()

  // 如果没有活动项，不渲染侧边栏内容
  if (!activeActivity) {
    return null
  }

  const Icon = sidebarIcons[activeActivity]
  const title = sidebarTitles[activeActivity]

  return (
    <ResizablePanel
      defaultSize={20}
      minSize={10}
      maxSize={50}
      className={cn(
        'bg-[#252526] border-r border-border/40 flex flex-col overflow-hidden',
        className
      )}
    >
      {/* 侧边栏标题 */}
      <div className="h-9 flex items-center px-4 text-xs font-semibold text-muted-foreground uppercase tracking-wide select-none">
        <Icon className="w-4 h-4 mr-2" />
        {title}
      </div>

      {/* 侧边栏内容 */}
      <div className="flex-1 overflow-auto">
        {activeActivity === 'explorer' && <ExplorerContent />}
        {activeActivity === 'search' && <SearchContent />}
        {activeActivity === 'findings' && <FindingsContent />}
        {activeActivity === 'settings' && <SettingsContent />}
      </div>
    </ResizablePanel>
  )
}

// 资源管理器内容
function ExplorerContent() {
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const { files } = useFileStore()

  // 将文件列表转换为 FileTree 格式
  const buildFileTree = (files: any[]): FileNode[] => {
    const root: FileNode[] = []
    const map = new Map<string, FileNode>()

    files.forEach((file) => {
      const pathParts = file.path.split('/')
      let currentLevel = root
      let currentPath = ''

      pathParts.forEach((part: string, index: number) => {
        currentPath = currentPath ? `${currentPath}/${part}` : part
        const isFile = index === pathParts.length - 1 && !file.is_dir

        let node = map.get(currentPath)
        if (!node) {
          node = {
            name: part,
            path: currentPath,
            type: isFile ? 'file' : 'folder',
            children: isFile ? undefined : [],
          }
          map.set(currentPath, node)
          currentLevel.push(node)
        }

        if (node.children) {
          currentLevel = node.children
        }
      })
    })

    return root
  }

  const fileTree = buildFileTree(files || [])

  return (
    <div className="p-2">
      {fileTree.length > 0 ? (
        <FileTree
          nodes={fileTree}
          selectedPath={selectedPath}
          onSelect={setSelectedPath}
        />
      ) : (
        <div className="text-sm text-muted-foreground p-4 text-center">
          无文件
        </div>
      )}
    </div>
  )
}

// 搜索内容
function SearchContent() {
  return (
    <div className="p-4 text-sm text-muted-foreground">
      <p>搜索功能</p>
      <p className="mt-2 text-xs">在项目中搜索文件和内容</p>
    </div>
  )
}

// 扫描结果内容
function FindingsContent() {
  const { vulnerabilities } = useScanStore()

  // 按严重程度分组
  const groupedFindings = {
    critical: vulnerabilities.filter((f: any) => f.severity === 'critical'),
    high: vulnerabilities.filter((f: any) => f.severity === 'high'),
    medium: vulnerabilities.filter((f: any) => f.severity === 'medium'),
    low: vulnerabilities.filter((f: any) => f.severity === 'low'),
    info: vulnerabilities.filter((f: any) => f.severity === 'info'),
  }

  const severityColors = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-yellow-400',
    low: 'text-blue-400',
    info: 'text-gray-400',
  }

  const severityLabels = {
    critical: '严重',
    high: '高危',
    medium: '中危',
    low: '低危',
    info: '信息',
  }

  return (
    <div className="p-2">
      {vulnerabilities.length === 0 ? (
        <div className="text-sm text-muted-foreground p-4 text-center">
          暂无扫描结果
        </div>
      ) : (
        <div className="space-y-1">
          {Object.entries(groupedFindings).map(([severity, items]) =>
            items.length > 0 ? (
              <div key={severity} className="mb-2">
                <div className={cn('text-xs font-semibold mb-1', severityColors[severity as keyof typeof severityColors])}>
                  {severityLabels[severity as keyof typeof severityLabels]} ({items.length})
                </div>
                {items.slice(0, 10).map((finding: any) => (
                  <div
                    key={finding.id}
                    className="text-xs p-2 rounded bg-[#1e1e1e] hover:bg-[#2a2a2a] cursor-pointer transition-colors"
                  >
                    <div className="font-medium text-white truncate">{finding.title || finding.vuln_type}</div>
                    <div className="text-muted-foreground truncate mt-1">{finding.file_path}</div>
                  </div>
                ))}
                {items.length > 10 && (
                  <div className="text-xs text-muted-foreground p-1 text-center">
                    还有 {items.length - 10} 条...
                  </div>
                )}
              </div>
            ) : null
          )}
        </div>
      )}
    </div>
  )
}

// 设置内容
function SettingsContent() {
  return (
    <div className="p-4 text-sm text-muted-foreground">
      <p>设置</p>
      <p className="mt-2 text-xs">配置应用程序设置</p>
    </div>
  )
}
