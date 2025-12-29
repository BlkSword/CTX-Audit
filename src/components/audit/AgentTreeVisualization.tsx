/**
 * Agent 树可视化组件
 *
 * 使用 CSS 绘制 Agent 树结构，显示 Agent 层次和状态
 */

import React, { useEffect, useState } from 'react'
import {
  Brain,
  FileSearch,
  Bug,
  Shield,
  ChevronDown,
  ChevronRight,
  Clock,
  CheckCircle,
  XCircle,
  Loader2,
  Info,
  Power,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

// Agent 类型定义
export interface AgentNode {
  agent_id: string
  agent_name: string
  agent_type: string
  task: string
  status: 'running' | 'completed' | 'stopped' | 'error'
  created_at: string
  parent_id?: string
  children?: AgentNode[]
}

// Agent 图标映射
const AGENT_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  orchestrator: Brain,
  recon: FileSearch,
  analysis: Bug,
  verification: Shield,
}

// Agent 颜色映射
const AGENT_COLORS: Record<string, { bg: string; border: string; icon: string }> = {
  orchestrator: { bg: 'bg-purple-500/10', border: 'border-purple-500/30', icon: 'text-purple-500' },
  recon: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', icon: 'text-blue-500' },
  analysis: { bg: 'bg-orange-500/10', border: 'border-orange-500/30', icon: 'text-orange-500' },
  verification: { bg: 'bg-green-500/10', border: 'border-green-500/30', icon: 'text-green-500' },
}

// 状态颜色映射
const STATUS_COLORS: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
  running: { bg: 'bg-blue-500/10', text: 'text-blue-500', icon: <Loader2 className="w-3 h-3 animate-spin" /> },
  completed: { bg: 'bg-green-500/10', text: 'text-green-500', icon: <CheckCircle className="w-3 h-3" /> },
  stopped: { bg: 'bg-gray-500/10', text: 'text-gray-500', icon: <XCircle className="w-3 h-3" /> },
  error: { bg: 'bg-red-500/10', text: 'text-red-500', icon: <XCircle className="w-3 h-3" /> },
}

// 单个 Agent 节点组件
interface TreeNodeProps {
  node: AgentNode
  level: number
  isExpanded: boolean
  onToggle: () => void
  onViewDetails: (node: AgentNode) => void
  onStopAgent?: (nodeId: string) => void
}

function TreeNode({ node, level, isExpanded, onToggle, onViewDetails, onStopAgent }: TreeNodeProps) {
  const colors = AGENT_COLORS[node.agent_type] || AGENT_COLORS.analysis
  const statusConfig = STATUS_COLORS[node.status] || STATUS_COLORS.running
  const AgentIcon = AGENT_ICONS[node.agent_type] || Bug
  const hasChildren = node.children && node.children.length > 0

  return (
    <div className="relative">
      {/* 节点内容 */}
      <div
        className={`
          flex items-center gap-2 p-2 rounded-lg border-2 transition-all
          ${colors.bg} ${colors.border}
          hover:bg-opacity-20 cursor-pointer group
        `}
        style={{ marginLeft: `${level * 16}px` }}
        onClick={() => hasChildren && onToggle()}
      >
        {/* 展开/收起按钮 */}
        {hasChildren ? (
          <Button
            variant="ghost"
            size="icon"
            className="h-5 w-5 flex-shrink-0"
            onClick={(e) => {
              e.stopPropagation()
              onToggle()
            }}
          >
            {isExpanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </Button>
        ) : (
          <div className="w-5 h-5 flex-shrink-0" />
        )}

        {/* Agent 图标 */}
        <div className={`p-1.5 rounded ${colors.icon} ${colors.bg} flex-shrink-0`}>
          <AgentIcon className="w-4 h-4" />
        </div>

        {/* Agent 信息 */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium truncate">{node.agent_name}</span>
            <Badge variant="outline" className={`text-[9px] h-4 px-1 ${statusConfig.bg} ${statusConfig.text}`}>
              {node.status}
            </Badge>
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-muted-foreground font-mono">
              {node.agent_id}
            </span>
            {hasChildren && (
              <span className="text-[10px] text-muted-foreground">
                ({node.children?.length} 个子节点)
              </span>
            )}
          </div>
        </div>

        {/* 状态图标 */}
        <div className={`flex-shrink-0 ${statusConfig.text}`}>
          {statusConfig.icon}
        </div>

        {/* 操作按钮 */}
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={(e) => {
              e.stopPropagation()
              onViewDetails(node)
            }}
            title="查看详情"
          >
            <Info className="w-3 h-3" />
          </Button>
          {node.status === 'running' && onStopAgent && (
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 text-red-500 hover:text-red-600 hover:bg-red-500/10"
              onClick={(e) => {
                e.stopPropagation()
                onStopAgent(node.agent_id)
              }}
              title="停止 Agent"
            >
              <Power className="w-3 h-3" />
            </Button>
          )}
        </div>
      </div>

      {/* 子节点 */}
      {isExpanded && hasChildren && (
        <div className="mt-1 space-y-1">
          {node.children!.map((child) => (
            <TreeNode
              key={child.agent_id}
              node={child}
              level={level + 1}
              isExpanded={true}
              onToggle={() => {}}
              onViewDetails={onViewDetails}
              onStopAgent={onStopAgent}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// Agent 详情对话框
interface AgentDetailDialogProps {
  node: AgentNode | null
  open: boolean
  onClose: () => void
}

function AgentDetailDialog({ node, open, onClose }: AgentDetailDialogProps) {
  if (!node) return null

  const colors = AGENT_COLORS[node.agent_type] || AGENT_COLORS.analysis
  const statusConfig = STATUS_COLORS[node.status] || STATUS_COLORS.running
  const AgentIcon = AGENT_ICONS[node.agent_type] || Bug

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className={`p-3 rounded-lg ${colors.bg} ${colors.icon}`}>
              <AgentIcon className="w-6 h-6" />
            </div>
            <div>
              <DialogTitle className="text-lg">{node.agent_name}</DialogTitle>
              <DialogDescription className="font-mono text-xs">
                {node.agent_id}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-4 mt-4">
          {/* 状态 */}
          <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
            <span className="text-sm font-medium">状态</span>
            <Badge variant="outline" className={`${statusConfig.bg} ${statusConfig.text}`}>
              {statusConfig.icon}
              <span className="ml-1">{node.status}</span>
            </Badge>
          </div>

          {/* Agent 类型 */}
          <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
            <span className="text-sm font-medium">Agent 类型</span>
            <span className="text-sm font-mono uppercase">{node.agent_type}</span>
          </div>

          {/* 当前任务 */}
          <div className="p-3 bg-muted/30 rounded-lg">
            <span className="text-sm font-medium block mb-2">当前任务</span>
            <p className="text-xs text-muted-foreground">{node.task || '无'}</p>
          </div>

          {/* 创建时间 */}
          <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
            <span className="text-sm font-medium">创建时间</span>
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {new Date(node.created_at).toLocaleString('zh-CN')}
            </span>
          </div>

          {/* 父节点信息 */}
          {node.parent_id && (
            <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
              <span className="text-sm font-medium">父 Agent</span>
              <span className="text-xs font-mono">{node.parent_id}</span>
            </div>
          )}

          {/* 子节点数量 */}
          {node.children && node.children.length > 0 && (
            <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
              <span className="text-sm font-medium">子 Agent 数量</span>
              <span className="text-sm">{node.children.length}</span>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}

// 主组件
interface AgentTreeVisualizationProps {
  treeData?: AgentNode | null
  loading?: boolean
  error?: string | null
  onStopAgent?: (nodeId: string) => void
  onRefresh?: () => void
}

export function AgentTreeVisualization({
  treeData,
  loading = false,
  error = null,
  onStopAgent,
  onRefresh,
}: AgentTreeVisualizationProps) {
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set())
  const [selectedNode, setSelectedNode] = useState<AgentNode | null>(null)
  const [detailDialogOpen, setDetailDialogOpen] = useState(false)

  // 初始化时展开根节点
  useEffect(() => {
    if (treeData) {
      setExpandedNodes(new Set([treeData.agent_id]))
    }
  }, [treeData])

  // 切换节点展开状态
  const toggleNodeExpanded = (nodeId: string) => {
    setExpandedNodes(prev => {
      const newSet = new Set(prev)
      if (newSet.has(nodeId)) {
        newSet.delete(nodeId)
      } else {
        newSet.add(nodeId)
      }
      return newSet
    })
  }

  // 递归检查节点是否展开
  const isNodeExpanded = (node: AgentNode): boolean => {
    return expandedNodes.has(node.agent_id)
  }

  // 查看节点详情
  const handleViewDetails = (node: AgentNode) => {
    setSelectedNode(node)
    setDetailDialogOpen(true)
  }

  // 空状态
  if (!treeData && !loading && !error) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-muted-foreground p-8">
        <Brain className="w-16 h-16 mb-4 opacity-20" />
        <p className="text-sm">暂无 Agent 树数据</p>
        <p className="text-xs mt-2">启动审计后将显示 Agent 执行树</p>
        {onRefresh && (
          <Button variant="outline" size="sm" className="mt-4" onClick={onRefresh}>
            刷新
          </Button>
        )}
      </div>
    )
  }

  // 加载状态
  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
        <p className="text-sm text-muted-foreground mt-4">加载 Agent 树中...</p>
      </div>
    )
  }

  // 错误状态
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8">
        <XCircle className="w-12 h-12 text-red-500 mb-4" />
        <p className="text-sm text-red-500 mb-2">加载失败</p>
        <p className="text-xs text-muted-foreground mb-4">{error}</p>
        {onRefresh && (
          <Button variant="outline" size="sm" onClick={onRefresh}>
            重试
          </Button>
        )}
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* 顶部工具栏 */}
      <div className="flex items-center justify-between p-3 border-b bg-muted/10">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium">Agent 执行树</span>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onRefresh}>
            <Loader2 className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </Button>
        </div>
      </div>

      {/* 树结构 */}
      <ScrollArea className="flex-1 p-4">
        {treeData && (
          <div className="space-y-2">
            <TreeNode
              node={treeData}
              level={0}
              isExpanded={isNodeExpanded(treeData)}
              onToggle={() => toggleNodeExpanded(treeData.agent_id)}
              onViewDetails={handleViewDetails}
              onStopAgent={onStopAgent}
            />
          </div>
        )}
      </ScrollArea>

      {/* 详情对话框 */}
      <AgentDetailDialog
        node={selectedNode}
        open={detailDialogOpen}
        onClose={() => {
          setDetailDialogOpen(false)
          setSelectedNode(null)
        }}
      />
    </div>
  )
}
