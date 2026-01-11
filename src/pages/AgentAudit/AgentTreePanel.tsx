/**
 * Agent 树组件
 * 参考 DeepAudit-3.0.0 实现
 *
 * 特性：
 * - 树形结构展示
 * - 展开/收起节点
 * - 状态指示器
 * - 连接线可视化
 * - 点击选择 Agent
 */

import { useState } from 'react'
import { ChevronDown, ChevronRight, Brain, FileSearch, Bug, Shield, Loader2, CheckCircle2, XCircle, Clock } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AgentTreeNode, AgentNodeStatus, AgentType } from './types'

interface AgentTreePanelProps {
  treeData: { roots: AgentTreeNode[] } | null
  loading?: boolean
  selectedAgentId: string | null
  onSelectAgent?: (agentId: string | null) => void
}

// Agent 类型配置
const AGENT_TYPE_CONFIG: Record<AgentType, {
  icon: React.ComponentType<{ className?: string }>
  name: string
  color: string
  bgColor: string
  iconBg: string
}> = {
  ORCHESTRATOR: {
    icon: Brain,
    name: '编排者',
    color: 'text-violet-400',
    bgColor: 'bg-violet-950/30',
    iconBg: 'bg-violet-900/50',
  },
  RECON: {
    icon: FileSearch,
    name: '侦察者',
    color: 'text-blue-400',
    bgColor: 'bg-blue-950/30',
    iconBg: 'bg-blue-900/50',
  },
  ANALYSIS: {
    icon: Bug,
    name: '分析者',
    color: 'text-amber-400',
    bgColor: 'bg-amber-950/30',
    iconBg: 'bg-amber-900/50',
  },
  VERIFICATION: {
    icon: Shield,
    name: '验证者',
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-950/30',
    iconBg: 'bg-emerald-900/50',
  },
  SYSTEM: {
    icon: Shield,
    name: '系统',
    color: 'text-slate-400',
    bgColor: 'bg-slate-950/30',
    iconBg: 'bg-slate-900/50',
  },
}

// 状态配置
const STATUS_CONFIG: Record<AgentNodeStatus, {
  icon: React.ComponentType<{ className?: string }>
  color: string
  label: string
  animate?: string
  bg?: string
}> = {
  running: {
    icon: Loader2,
    color: 'text-blue-400',
    label: '运行中',
    animate: 'animate-spin',
    bg: 'bg-blue-950/30',
  },
  completed: {
    icon: CheckCircle2,
    color: 'text-emerald-400',
    label: '完成',
    bg: 'bg-emerald-950/30',
  },
  failed: {
    icon: XCircle,
    color: 'text-rose-400',
    label: '失败',
    bg: 'bg-rose-950/30',
  },
  waiting: {
    icon: Clock,
    color: 'text-amber-400',
    label: '等待',
    bg: 'bg-amber-950/30',
  },
  created: {
    icon: Clock,
    color: 'text-slate-400',
    label: '创建',
    bg: 'bg-slate-950/30',
  },
  stopped: {
    icon: XCircle,
    color: 'text-slate-400',
    label: '停止',
    bg: 'bg-slate-950/30',
  },
  idle: {
    icon: Clock,
    color: 'text-slate-500',
    label: '空闲',
    bg: 'bg-slate-950/30',
  },
}

// 节点组件
interface TreeNodeProps {
  node: AgentTreeNode
  level?: number
  isSelected?: boolean
  onSelect?: (node: AgentTreeNode) => void
}

function TreeNode({ node, level = 0, isSelected, onSelect }: TreeNodeProps) {
  const [isExpanded, setIsExpanded] = useState(level < 1) // 默认展开第一层

  const hasChildren = node.children && node.children.length > 0
  const typeConfig = AGENT_TYPE_CONFIG[node.agent_type] || AGENT_TYPE_CONFIG.SYSTEM
  const statusConfig = STATUS_CONFIG[node.status] || STATUS_CONFIG.idle
  const TypeIcon = typeConfig.icon
  const StatusIcon = statusConfig.icon

  const handleClick = () => {
    if (onSelect) {
      onSelect(node)
    }
  }

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation()
    if (hasChildren) {
      setIsExpanded(!isExpanded)
    }
  }

  return (
    <div className="relative">
      {/* 节点内容 */}
      <div
        onClick={handleClick}
        className={cn(
          "flex items-center gap-2 py-2 px-3 rounded-lg transition-all cursor-pointer",
          "hover:bg-white/5 border border-transparent hover:border-white/10",
          typeConfig.bgColor,
          isSelected && "border-violet-500/50 bg-violet-950/20",
          node.status === 'running' && "border-current/30 shadow-lg shadow-current/10 animate-pulse"
        )}
      >
        {/* 展开/收起图标 */}
        <div
          className="w-4 h-4 flex items-center justify-center shrink-0"
          onClick={handleToggle}
        >
          {hasChildren ? (
            isExpanded ? (
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
            )
          ) : (
            <div className="w-1.5 h-1.5 rounded-full bg-slate-600" />
          )}
        </div>

        {/* Agent 类型图标 */}
        <div className={cn(
          "p-1.5 rounded-lg shrink-0",
          typeConfig.iconBg,
          node.status === 'running' && "animate-pulse"
        )}>
          <TypeIcon className={cn("w-4 h-4", typeConfig.color)} />
        </div>

        {/* 节点信息 */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={cn("text-sm font-medium", typeConfig.color)}>
              {typeConfig.name}
            </span>
            <span className="text-xs text-slate-500 truncate max-w-[80px]">
              #{node.agent_id.slice(-6)}
            </span>
          </div>
          {node.task && (
            <div className="text-xs text-slate-400 truncate mt-0.5" title={node.task}>
              {node.task}
            </div>
          )}
        </div>

        {/* 状态指示器 */}
        <div className="flex items-center gap-1.5 shrink-0">
          <StatusIcon className={cn(
            "w-3.5 h-3.5",
            statusConfig.color,
            statusConfig.animate
          )} />
          <span className={cn(
            "text-[10px] font-medium px-1.5 py-0.5 rounded",
            statusConfig.color,
            statusConfig.bg
          )}>
            {statusConfig.label}
          </span>
        </div>
      </div>

      {/* 子节点 */}
      {isExpanded && hasChildren && (
        <div className="ml-4 pl-2 border-l border-slate-700/50 mt-0.5 space-y-0.5">
          {node.children!.map((child: AgentTreeNode) => (
            <TreeNode
              key={child.agent_id}
              node={child}
              level={level + 1}
              isSelected={isSelected}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  )
}

export function AgentTreePanel({
  treeData,
  loading = false,
  selectedAgentId,
  onSelectAgent
}: AgentTreePanelProps) {
  const handleSelectNode = (node: AgentTreeNode) => {
    if (onSelectAgent) {
      // 如果点击的是已选中的，取消选择
      if (selectedAgentId === node.agent_id) {
        onSelectAgent(null)
      } else {
        onSelectAgent(node.agent_id)
      }
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500">
        <Loader2 className="w-8 h-8 animate-spin mb-3 text-slate-600" />
        <p className="text-sm">加载 Agent 树...</p>
      </div>
    )
  }

  if (!treeData || !treeData.roots || treeData.roots.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-600 py-8">
        <Brain className="w-12 h-12 mb-3 opacity-20" />
        <p className="text-sm">暂无 Agent 运行</p>
        <p className="text-xs text-slate-500 mt-1">启动审计以查看 Agent 树</p>
      </div>
    )
  }

  return (
    <div className="h-full overflow-y-auto custom-scrollbar p-2">
      {treeData.roots.map((root: AgentTreeNode) => (
        <TreeNode
          key={root.agent_id}
          node={root}
          isSelected={selectedAgentId === root.agent_id}
          onSelect={handleSelectNode}
        />
      ))}
    </div>
  )
}
