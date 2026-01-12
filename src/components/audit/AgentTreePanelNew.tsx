/**
 * Agent Tree Panel Component - 新设计版本
 *
 * 新设计的Agent树面板，匹配紫色主题：
 * - 紫色主题色 #8B5CF6
 * - 居中的加载动画
 * - 文件夹图标
 * - 深色背景 #121212
 * - 边框 #333333
 */

import { useState } from 'react'
import { ChevronDown, ChevronRight, Brain, FileSearch, Bug, Shield, Loader2, CheckCircle2, XCircle, Clock, Folder } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AgentTreeNode, AgentNodeStatus, AgentType } from '@/pages/AgentAudit/types'

interface AgentTreePanelNewProps {
  treeData: { roots: AgentTreeNode[] } | null
  loading?: boolean
  selectedAgentId: string | null
  onSelectAgent?: (agentId: string | null) => void
}

// Agent 类型配置 - 更新为紫色主题
const AGENT_TYPE_CONFIG: Record<AgentType, {
  icon: React.ComponentType<{ className?: string }>
  name: string
  color: string
  bgColor: string
  iconBg: string
}> = {
  ORCHESTRATOR: {
    icon: Brain,
    name: 'Orchestrator',
    color: 'text-[#A78BFA]',
    bgColor: 'bg-purple-950/20',
    iconBg: 'bg-purple-900/40',
  },
  RECON: {
    icon: FileSearch,
    name: 'Reconnaissance',
    color: 'text-[#60A5FA]',
    bgColor: 'bg-blue-950/20',
    iconBg: 'bg-blue-900/40',
  },
  ANALYSIS: {
    icon: Bug,
    name: 'Analysis',
    color: 'text-[#FBBF24]',
    bgColor: 'bg-amber-950/20',
    iconBg: 'bg-amber-900/40',
  },
  VERIFICATION: {
    icon: Shield,
    name: 'Verification',
    color: 'text-[#34D399]',
    bgColor: 'bg-emerald-950/20',
    iconBg: 'bg-emerald-900/40',
  },
  SYSTEM: {
    icon: Shield,
    name: 'System',
    color: 'text-[#888888]',
    bgColor: 'bg-slate-950/20',
    iconBg: 'bg-slate-900/40',
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
    color: 'text-[#10B981]',
    label: '运行中',
    animate: 'animate-spin',
    bg: 'bg-emerald-950/20',
  },
  completed: {
    icon: CheckCircle2,
    color: 'text-[#10B981]',
    label: '完成',
    bg: 'bg-emerald-950/20',
  },
  failed: {
    icon: XCircle,
    color: 'text-[#EF4444]',
    label: '失败',
    bg: 'bg-red-950/20',
  },
  waiting: {
    icon: Clock,
    color: 'text-[#F97316]',
    label: '等待',
    bg: 'bg-orange-950/20',
  },
  created: {
    icon: Clock,
    color: 'text-[#888888]',
    label: '创建',
    bg: 'bg-slate-950/20',
  },
  stopped: {
    icon: XCircle,
    color: 'text-[#888888]',
    label: '停止',
    bg: 'bg-slate-950/20',
  },
  idle: {
    icon: Clock,
    color: 'text-[#666666]',
    label: '空闲',
    bg: 'bg-slate-950/20',
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
  const [isExpanded, setIsExpanded] = useState(level < 1)

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
          "flex items-center gap-2 py-2 px-3 rounded transition-all cursor-pointer",
          "hover:bg-white/5 border border-transparent",
          isSelected && "bg-purple-950/30 border-purple-500/50"
        )}
      >
        {/* 展开/收起图标 */}
        <div
          className="w-4 h-4 flex items-center justify-center shrink-0"
          onClick={handleToggle}
        >
          {hasChildren ? (
            isExpanded ? (
              <ChevronDown className="w-3 h-3 text-[#888888]" />
            ) : (
              <ChevronRight className="w-3 h-3 text-[#888888]" />
            )
          ) : (
            <div className="w-1 h-1 rounded-full bg-[#666666]" />
          )}
        </div>

        {/* Agent 类型图标 */}
        <div className={cn("p-1 rounded shrink-0", typeConfig.iconBg)}>
          <TypeIcon className={cn("w-3.5 h-3.5", typeConfig.color)} />
        </div>

        {/* 节点信息 */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={cn("text-xs font-medium text-white")}>
              {typeConfig.name}
            </span>
            <span className="text-[10px] text-[#888888] truncate">
              #{node.agent_id.slice(-6)}
            </span>
          </div>
          {node.task && (
            <div className="text-[10px] text-[#666666] truncate mt-0.5" title={node.task}>
              {node.task}
            </div>
          )}
        </div>

        {/* 状态指示器 */}
        <StatusIcon className={cn(
          "w-3 h-3 shrink-0",
          statusConfig.color,
          statusConfig.animate
        )} />
      </div>

      {/* 子节点 */}
      {isExpanded && hasChildren && (
        <div className="ml-5 pl-2 border-l border-[#333333] mt-0.5 space-y-0.5">
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

// 加载状态 - 居中紫色加载动画
function LoadingState() {
  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="w-10 h-10 border-2 border-[#333333] border-t-[#8B5CF6] rounded-full animate-spin mb-3" />
      <p className="text-xs text-[#888888]">INITIALIZING AGENTS...</p>
    </div>
  )
}

// 空状态
function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-full py-8">
      <Folder className="w-10 h-10 text-[#666666] mb-3" />
      <p className="text-xs text-[#888888]">暂无 Agent 运行</p>
      <p className="text-[10px] text-[#666666] mt-1">启动审计以查看 Agent 树</p>
    </div>
  )
}

export function AgentTreePanelNew({
  treeData,
  loading = false,
  selectedAgentId,
  onSelectAgent
}: AgentTreePanelNewProps) {
  const handleSelectNode = (node: AgentTreeNode) => {
    if (onSelectAgent) {
      if (selectedAgentId === node.agent_id) {
        onSelectAgent(null)
      } else {
        onSelectAgent(node.agent_id)
      }
    }
  }

  if (loading) {
    return <LoadingState />
  }

  if (!treeData || !treeData.roots || treeData.roots.length === 0) {
    return <EmptyState />
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
