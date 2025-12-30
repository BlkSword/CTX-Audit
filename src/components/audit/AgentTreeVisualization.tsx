/**
 * Agent 树可视化组件 - 动态版
 *
 * 特性：
 * - 动态连接线动画
 * - 节点脉动效果
 * - 流光边框
 * - 实时状态更新
 * - 平滑展开/收起动画
 */

import React, { useEffect, useState, useMemo } from 'react'
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
  Zap,
  MoreVertical,
  MinusCircle,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import type { AgentNode } from '@/shared/types'
import { cn } from '@/lib/utils'

// ==================== 类型定义 ====================

interface AgentTreeVisualizationProps {
  treeData?: AgentNode | null
  loading?: boolean
  error?: string | null
  onStopAgent?: (nodeId: string) => void
  onRefresh?: () => void
}

// ==================== 常量配置 ====================

const AGENT_CONFIG: Record<string, {
  icon: React.ComponentType<{ className?: string }>
  name: string
  color: string
  gradient: string
  bgGradient: string
  glowColor: string
}> = {
  ORCHESTRATOR: {
    icon: Brain,
    name: '编排者',
    color: 'text-violet-500',
    gradient: 'from-violet-500 to-purple-600',
    bgGradient: 'bg-gradient-to-br from-violet-500/10 to-purple-600/10',
    glowColor: 'shadow-violet-500/50',
  },
  orchestrator: {
    icon: Brain,
    name: '编排者',
    color: 'text-violet-500',
    gradient: 'from-violet-500 to-purple-600',
    bgGradient: 'bg-gradient-to-br from-violet-500/10 to-purple-600/10',
    glowColor: 'shadow-violet-500/50',
  },
  RECON: {
    icon: FileSearch,
    name: '侦察者',
    color: 'text-blue-500',
    gradient: 'from-blue-500 to-cyan-600',
    bgGradient: 'bg-gradient-to-br from-blue-500/10 to-cyan-600/10',
    glowColor: 'shadow-blue-500/50',
  },
  recon: {
    icon: FileSearch,
    name: '侦察者',
    color: 'text-blue-500',
    gradient: 'from-blue-500 to-cyan-600',
    bgGradient: 'bg-gradient-to-br from-blue-500/10 to-cyan-600/10',
    glowColor: 'shadow-blue-500/50',
  },
  ANALYSIS: {
    icon: Bug,
    name: '分析者',
    color: 'text-orange-500',
    gradient: 'from-orange-500 to-amber-600',
    bgGradient: 'bg-gradient-to-br from-orange-500/10 to-amber-600/10',
    glowColor: 'shadow-orange-500/50',
  },
  analysis: {
    icon: Bug,
    name: '分析者',
    color: 'text-orange-500',
    gradient: 'from-orange-500 to-amber-600',
    bgGradient: 'bg-gradient-to-br from-orange-500/10 to-amber-600/10',
    glowColor: 'shadow-orange-500/50',
  },
  VERIFICATION: {
    icon: Shield,
    name: '验证者',
    color: 'text-emerald-500',
    gradient: 'from-emerald-500 to-green-600',
    bgGradient: 'bg-gradient-to-br from-emerald-500/10 to-green-600/10',
    glowColor: 'shadow-emerald-500/50',
  },
  verification: {
    icon: Shield,
    name: '验证者',
    color: 'text-emerald-500',
    gradient: 'from-emerald-500 to-green-600',
    bgGradient: 'bg-gradient-to-br from-emerald-500/10 to-green-600/10',
    glowColor: 'shadow-emerald-500/50',
  },
}

const STATUS_CONFIG: Record<string, {
  icon: React.ReactNode
  color: string
  bgGradient: string
  animation: string
}> = {
  running: {
    icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />,
    color: 'text-blue-500',
    bgGradient: 'bg-gradient-to-r from-blue-500/20 to-cyan-500/20',
    animation: 'animate-pulse',
  },
  completed: {
    icon: <CheckCircle className="w-3.5 h-3.5" />,
    color: 'text-emerald-500',
    bgGradient: 'bg-gradient-to-r from-emerald-500/20 to-green-500/20',
    animation: '',
  },
  stopped: {
    icon: <MinusCircle className="w-3.5 h-3.5" />,
    color: 'text-gray-500',
    bgGradient: 'bg-gradient-to-r from-gray-500/20 to-slate-500/20',
    animation: '',
  },
  error: {
    icon: <XCircle className="w-3.5 h-3.5" />,
    color: 'text-rose-500',
    bgGradient: 'bg-gradient-to-r from-rose-500/20 to-red-500/20',
    animation: 'animate-pulse',
  },
  idle: {
    icon: <Clock className="w-3.5 h-3.5" />,
    color: 'text-amber-500',
    bgGradient: 'bg-gradient-to-r from-amber-500/20 to-yellow-500/20',
    animation: '',
  },
}

// ==================== 树节点组件 ====================

interface TreeNodeProps {
  node: AgentNode
  level: number
  isExpanded: boolean
  onToggle: () => void
  onViewDetails: (node: AgentNode) => void
  onStopAgent?: (nodeId: string) => void
}

function TreeNode({ node, level, isExpanded, onToggle, onViewDetails, onStopAgent }: TreeNodeProps) {
  const config = AGENT_CONFIG[node.agent_type] || AGENT_CONFIG.analysis
  const statusConfig = STATUS_CONFIG[node.status] || STATUS_CONFIG.idle
  const AgentIcon = config.icon
  const hasChildren = node.children && node.children.length > 0
  const isRunning = node.status === 'running'

  return (
    <div className="relative">
      {/* 连接线 */}
      {level > 0 && (
        <div
          className="absolute left-0 top-0 w-8 h-6 border-l-2 border-b-2 border-dashed border-primary/30"
          style={{ marginLeft: `${(level - 1) * 24}px` }}
        />
      )}

      {/* 节点卡片 */}
      <div
        className={cn(
          "relative group transition-all duration-300",
          isExpanded && "mb-2"
        )}
        style={{ marginLeft: `${level * 24}px` }}
      >
        {/* 主卡片 */}
        <div
          className={cn(
            "relative overflow-hidden rounded-xl border-2 transition-all duration-300",
            config.bgGradient,
            isRunning
              ? "border-current shadow-lg shadow-current/20"
              : "border-border/50 hover:border-border",
            "hover:shadow-md hover:scale-[1.01]"
          )}
        >
          {/* 运行时的流光效果 */}
          {isRunning && (
            <>
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full animate-[shimmer_2s_infinite]" />
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-current/5 to-transparent translate-x-full animate-[shimmer-reverse_2s_infinite]" />
            </>
          )}

          {/* 内容 */}
          <div className="relative p-3">
            <div className="flex items-center gap-3">
              {/* 展开/收起按钮 */}
              {hasChildren ? (
                <Button
                  variant="ghost"
                  size="icon"
                  className={cn(
                    "h-7 w-7 shrink-0 transition-all",
                    isExpanded && "rotate-90"
                  )}
                  onClick={(e) => {
                    e.stopPropagation()
                    onToggle()
                  }}
                >
                  <ChevronRight className="w-4 h-4" />
                </Button>
              ) : (
                <div className="w-7 h-7 shrink-0 flex items-center justify-center">
                  <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground/30" />
                </div>
              )}

              {/* Agent 图标 */}
              <div
                className={cn(
                  "relative p-2.5 rounded-xl shrink-0",
                  config.bgGradient,
                  isRunning && "animate-pulse"
                )}
              >
                {isRunning && (
                  <div className={cn(
                    "absolute inset-0 rounded-xl blur-md opacity-50",
                    config.glowColor,
                    "animate-pulse"
                  )} />
                )}
                <AgentIcon className={cn("w-5 h-5 relative z-10", config.color)} />
              </div>

              {/* Agent 信息 */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-semibold truncate">{node.agent_name}</span>
                  <Badge
                    variant="outline"
                    className={cn(
                      "text-[9px] h-5 px-2 font-medium shrink-0",
                      statusConfig.color,
                      statusConfig.bgGradient,
                      "border-current/50"
                    )}
                  >
                    {statusConfig.icon}
                    <span className="ml-1">{node.status}</span>
                  </Badge>
                </div>
                <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-mono">
                  <span className="truncate">{node.agent_id.slice(0, 12)}...</span>
                  {hasChildren && (
                    <span className="shrink-0">
                      {node.children?.length} 子节点
                    </span>
                  )}
                  {node.created_at && (
                    <span className="shrink-0">
                      {new Date(node.created_at).toLocaleTimeString()}
                    </span>
                  )}
                </div>
              </div>

              {/* 操作按钮 */}
              <div className="flex items-center gap-1 shrink-0">
                {isRunning && onStopAgent && (
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-rose-500 hover:text-rose-600 hover:bg-rose-500/10"
                    onClick={(e) => {
                      e.stopPropagation()
                      onStopAgent(node.agent_id)
                    }}
                    title="停止 Agent"
                  >
                    <Power className="w-3.5 h-3.5" />
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                  onClick={(e) => {
                    e.stopPropagation()
                    onViewDetails(node)
                  }}
                  title="查看详情"
                >
                  <Info className="w-3.5 h-3.5" />
                </Button>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <MoreVertical className="w-3.5 h-3.5" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={(e) => {
                      e.stopPropagation()
                      onViewDetails(node)
                    }}>
                      <Info className="w-4 h-4 mr-2" />
                      查看详情
                    </DropdownMenuItem>
                    {isRunning && onStopAgent && (
                      <DropdownMenuItem
                        className="text-rose-600"
                        onClick={(e) => {
                          e.stopPropagation()
                          onStopAgent(node.agent_id)
                        }}
                      >
                        <Power className="w-4 h-4 mr-2" />
                        停止 Agent
                      </DropdownMenuItem>
                    )}
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>

            {/* 任务描述 */}
            {node.task && isExpanded && (
              <div className="mt-2 pt-2 border-t border-border/50">
                <p className="text-xs text-muted-foreground line-clamp-2">
                  {node.task}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 子节点 */}
      {isExpanded && hasChildren && (
        <div
          className={cn(
            "mt-2 space-y-2 relative transition-all duration-300",
            "before:absolute before:left-0 before:top-0 before:bottom-0 before:w-px before:bg-gradient-to-b before:from-primary/30 before:to-transparent before:opacity-50"
          )}
          style={{ marginLeft: `${level * 24}px` }}
        >
          {node.children!.map((child, index) => (
            <div
              key={child.agent_id}
              className="relative"
              style={{
                animation: `slideIn 0.3s ease-out ${index * 0.05}s both`,
              }}
            >
              {/* 水平连接线 */}
              <div
                className="absolute left-0 top-6 w-3 h-px border-t border-dashed border-primary/30"
                style={{ marginLeft: `${(level - 1) * 24}px` }}
              />
              <TreeNode
                node={child}
                level={level + 1}
                isExpanded={true}
                onToggle={() => {}}
                onViewDetails={onViewDetails}
                onStopAgent={onStopAgent}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ==================== Agent 详情对话框 ====================

interface AgentDetailDialogProps {
  node: AgentNode | null
  open: boolean
  onClose: () => void
}

function AgentDetailDialog({ node, open, onClose }: AgentDetailDialogProps) {
  if (!node) return null

  const config = AGENT_CONFIG[node.agent_type] || AGENT_CONFIG.analysis
  const statusConfig = STATUS_CONFIG[node.status] || STATUS_CONFIG.idle
  const AgentIcon = config.icon

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <div className="flex items-center gap-4">
            <div className={cn(
              "relative p-4 rounded-2xl",
              config.bgGradient
            )}>
              <div className={cn(
                "absolute inset-0 rounded-2xl blur-xl opacity-50",
                config.glowColor
              )} />
              <AgentIcon className={cn("w-8 h-8 relative z-10", config.color)} />
            </div>
            <div className="flex-1">
              <DialogTitle className="text-xl">{node.agent_name}</DialogTitle>
              <DialogDescription className="font-mono text-xs mt-1">
                {node.agent_id}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-4 mt-6">
          {/* 状态卡片 */}
          <div className={cn(
            "flex items-center justify-between p-4 rounded-xl border-2 transition-all",
            statusConfig.bgGradient,
            "border-current/30"
          )}>
            <span className="text-sm font-semibold">状态</span>
            <Badge
              variant="outline"
              className={cn(
                "text-sm px-3 py-1 font-semibold",
                statusConfig.color,
                "border-current/50",
                statusConfig.animation
              )}
            >
              {statusConfig.icon}
              <span className="ml-2 uppercase">{node.status}</span>
            </Badge>
          </div>

          {/* Agent 类型 */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-muted/30 rounded-xl">
              <p className="text-xs text-muted-foreground mb-1">Agent 类型</p>
              <p className="text-sm font-semibold uppercase">{node.agent_type}</p>
            </div>
            <div className="p-3 bg-muted/30 rounded-xl">
              <p className="text-xs text-muted-foreground mb-1">子节点数量</p>
              <p className="text-sm font-semibold">{node.children?.length || 0}</p>
            </div>
          </div>

          {/* 当前任务 */}
          {node.task && (
            <div className="p-4 bg-muted/30 rounded-xl">
              <p className="text-sm font-semibold mb-2 flex items-center gap-2">
                <Zap className="w-4 h-4 text-primary" />
                当前任务
              </p>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {node.task}
              </p>
            </div>
          )}

          {/* 时间信息 */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-muted/30 rounded-xl">
              <p className="text-xs text-muted-foreground mb-1 flex items-center gap-1">
                <Clock className="w-3 h-3" />
                创建时间
              </p>
              <p className="text-xs font-mono">
                {new Date(node.created_at).toLocaleString('zh-CN')}
              </p>
            </div>
            {node.parent_id && (
              <div className="p-3 bg-muted/30 rounded-xl">
                <p className="text-xs text-muted-foreground mb-1">父 Agent ID</p>
                <p className="text-xs font-mono truncate">
                  {node.parent_id}
                </p>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ==================== 主组件 ====================

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

  // 查看节点详情
  const handleViewDetails = (node: AgentNode) => {
    setSelectedNode(node)
    setDetailDialogOpen(true)
  }

  // 统计信息
  const stats = useMemo(() => {
    if (!treeData) return { total: 0, running: 0, completed: 0, error: 0 }

    const count = (node: AgentNode) => {
      let total = 1
      let running = node.status === 'running' ? 1 : 0
      let completed = node.status === 'completed' ? 1 : 0
      let error = node.status === 'error' ? 1 : 0

      if (node.children) {
        node.children.forEach(child => {
          const childStats = count(child)
          total += childStats.total
          running += childStats.running
          completed += childStats.completed
          error += childStats.error
        })
      }

      return { total, running, completed, error }
    }

    return count(treeData)
  }, [treeData])

  // 空状态
  if (!treeData && !loading && !error) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8">
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-r from-violet-500/20 to-purple-500/20 blur-3xl rounded-full" />
          <Brain className="relative w-20 h-20 text-muted-foreground/30" />
        </div>
        <p className="text-sm font-medium text-muted-foreground mt-6">暂无 Agent 树</p>
        <p className="text-xs text-muted-foreground/70 mt-2">启动审计后将显示 Agent 执行树</p>
        {onRefresh && (
          <Button variant="outline" size="sm" className="mt-6" onClick={onRefresh}>
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
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-r from-primary/20 to-primary/10 blur-xl rounded-full" />
          <Loader2 className="relative w-12 h-12 animate-spin text-primary" />
        </div>
        <p className="text-sm text-muted-foreground mt-6">加载 Agent 树中...</p>
      </div>
    )
  }

  // 错误状态
  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8">
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-r from-rose-500/20 to-red-500/20 blur-2xl rounded-full" />
          <XCircle className="relative w-16 h-16 text-rose-500" />
        </div>
        <p className="text-sm font-semibold text-rose-500 mt-6">加载失败</p>
        <p className="text-xs text-muted-foreground mt-2 mb-6">{error}</p>
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
      <div className="flex items-center justify-between p-4 border-b bg-muted/10">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-gradient-to-br from-primary/20 to-primary/10">
            <Brain className="w-4 h-4 text-primary" />
          </div>
          <div>
            <span className="text-sm font-semibold">Agent 执行树</span>
            <div className="flex items-center gap-3 mt-1">
              <span className="text-[10px] text-muted-foreground">
                总计: {stats.total}
              </span>
              <span className="text-[10px] text-blue-500">
                运行: {stats.running}
              </span>
              <span className="text-[10px] text-emerald-500">
                完成: {stats.completed}
              </span>
              {stats.error > 0 && (
                <span className="text-[10px] text-rose-500">
                  错误: {stats.error}
                </span>
              )}
            </div>
          </div>
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={onRefresh}
          title="刷新"
        >
          <Loader2 className={cn("w-4 h-4", loading && "animate-spin")} />
        </Button>
      </div>

      {/* 树结构 */}
      <ScrollArea className="flex-1 p-6">
        {treeData && (
          <div className="space-y-3">
            <TreeNode
              node={treeData}
              level={0}
              isExpanded={expandedNodes.has(treeData.agent_id)}
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
