/**
 * Agent 详情面板组件
 *
 * 显示选中 Agent 的详细信息：
 * - 基本信息和状态
 * - 统计数据（发现数、迭代次数、Token 使用、工具调用）
 * - 当前任务描述
 * - 执行时间线
 * - 相关日志
 */

import { useMemo } from 'react'
import {
  Bug,
  RefreshCw,
  Zap,
  Wrench,
  Clock,
  FileText,
  ChevronRight,
  XCircle,
  Loader2,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type { AgentTreeNode, LogItem, AgentFinding } from './types'

// 扩展 AgentTreeNode 类型以包含统计数据
export interface AgentDetailNode extends AgentTreeNode {
  findings_count?: number
  iterations?: number
  total_tokens?: number
  tool_calls?: number
  started_at?: string
  completed_at?: string
  error?: string
}

interface AgentDetailPanelProps {
  agent: AgentDetailNode | null
  logs?: LogItem[]
  findings?: AgentFinding[]
}

// Agent 类型配置
const AGENT_TYPE_CONFIG = {
  ORCHESTRATOR: {
    icon: '🎯',
    name: '编排者',
    color: 'text-violet-400',
    bgColor: 'bg-violet-950/30',
    borderColor: 'border-violet-500/30',
  },
  RECON: {
    icon: '🔍',
    name: '侦察者',
    color: 'text-blue-400',
    bgColor: 'bg-blue-950/30',
    borderColor: 'border-blue-500/30',
  },
  ANALYSIS: {
    icon: '🔬',
    name: '分析者',
    color: 'text-amber-400',
    bgColor: 'bg-amber-950/30',
    borderColor: 'border-amber-500/30',
  },
  VERIFICATION: {
    icon: '✅',
    name: '验证者',
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-950/30',
    borderColor: 'border-emerald-500/30',
  },
  SYSTEM: {
    icon: '⚙️',
    name: '系统',
    color: 'text-slate-400',
    bgColor: 'bg-slate-950/30',
    borderColor: 'border-slate-500/30',
  },
}

// 状态配置
const STATUS_CONFIG: Record<string, {
  icon: any
  label: string
  color: string
  bgColor: string
  animate?: string
}> = {
  running: {
    icon: Loader2,
    label: '运行中',
    color: 'text-blue-400',
    bgColor: 'bg-blue-950/30',
    animate: 'animate-spin',
  },
  completed: {
    icon: CheckCircle2,
    label: '完成',
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-950/30',
    animate: '',
  },
  failed: {
    icon: XCircle,
    label: '失败',
    color: 'text-rose-400',
    bgColor: 'bg-rose-950/30',
    animate: '',
  },
  waiting: {
    icon: Clock,
    label: '等待中',
    color: 'text-amber-400',
    bgColor: 'bg-amber-950/30',
    animate: '',
  },
  created: {
    icon: Clock,
    label: '已创建',
    color: 'text-slate-400',
    bgColor: 'bg-slate-950/30',
    animate: '',
  },
  stopped: {
    icon: XCircle,
    label: '已停止',
    color: 'text-slate-400',
    bgColor: 'bg-slate-950/30',
    animate: '',
  },
  idle: {
    icon: Clock,
    label: '空闲',
    color: 'text-slate-500',
    bgColor: 'bg-slate-950/30',
    animate: '',
  },
}

// 统计卡片组件
function StatCard({
  icon: Icon,
  label,
  value,
  color,
  bgColor,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: number | string
  color: string
  bgColor: string
}) {
  return (
    <div className={cn('flex items-center gap-3 p-3 rounded-lg border', bgColor, 'border-white/10')}>
      <div className={cn('p-2 rounded-lg', bgColor)}>
        <Icon className={cn('w-4 h-4', color)} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[10px] text-slate-500 uppercase tracking-wide">{label}</div>
        <div className={cn('text-lg font-semibold', color, 'truncate')}>{value}</div>
      </div>
    </div>
  )
}

// 时间线组件
function TimelineItem({ type, message, timestamp }: { type: string; message: string; timestamp: string }) {
  const getTypeConfig = () => {
    switch (type) {
      case 'start':
        return { icon: '🚀', color: 'text-blue-400', bg: 'bg-blue-950/30' }
      case 'complete':
        return { icon: '✅', color: 'text-emerald-400', bg: 'bg-emerald-950/30' }
      case 'error':
        return { icon: '❌', color: 'text-rose-400', bg: 'bg-rose-950/30' }
      case 'thinking':
        return { icon: '🤔', color: 'text-violet-400', bg: 'bg-violet-950/30' }
      case 'tool':
        return { icon: '🔧', color: 'text-amber-400', bg: 'bg-amber-950/30' }
      case 'finding':
        return { icon: '🐛', color: 'text-rose-400', bg: 'bg-rose-950/30' }
      default:
        return { icon: '📝', color: 'text-slate-400', bg: 'bg-slate-950/30' }
    }
  }

  const config = getTypeConfig()

  return (
    <div className="flex gap-3 items-start">
      <div className={cn('flex items-center justify-center w-6 h-6 rounded-full text-sm shrink-0', config.bg)}>
        {config.icon}
      </div>
      <div className="flex-1 min-w-0">
        <div className={cn('text-sm', config.color)}>{message}</div>
        <div className="text-[10px] text-slate-600">{timestamp}</div>
      </div>
    </div>
  )
}

export function AgentDetailPanel({ agent, logs = [], findings = [] }: AgentDetailPanelProps) {
  // 计算统计数据
  const stats = useMemo(() => {
    if (!agent) return null

    // 筛选与该 Agent 相关的日志
    const agentLogs = logs.filter((log) => log.agent_type === agent.agent_type)

    // 筛选与该 Agent 相关的发现
    const agentFindings = findings.slice(0, 3)

    // 计算工具调用次数
    const toolCalls = agentLogs.filter((log) => log.type === 'tool').length

    // 计算 Token 使用量
    const totalTokens = agentLogs.reduce((sum, log) => {
      return sum + (log.data?.tokens as number) || 0
    }, 0)

    // 计算迭代次数（thinking 事件）
    const iterations = agentLogs.filter((log) => log.type === 'thinking').length

    return {
      findingsCount: agent.findings_count ?? agentFindings.length,
      iterations: agent.iterations ?? iterations,
      totalTokens: agent.total_tokens ?? totalTokens,
      toolCalls: agent.tool_calls ?? toolCalls,
      relatedLogs: agentLogs.slice(-10), // 最近 10 条日志
    }
  }, [agent, logs, findings])

  if (!agent) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-600 py-8">
        <FileText className="w-12 h-12 mb-3 opacity-20" />
        <p className="text-sm">选择一个 Agent 查看详情</p>
      </div>
    )
  }

  const typeConfig = AGENT_TYPE_CONFIG[agent.agent_type] || AGENT_TYPE_CONFIG.SYSTEM
  const statusConfig = STATUS_CONFIG[agent.status] || STATUS_CONFIG.idle
  const StatusIcon = statusConfig.icon

  // 格式化时间
  const formatTime = (timestamp?: string) => {
    if (!timestamp) return '-'
    return new Date(timestamp).toLocaleTimeString('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  // 计算执行时长
  const getDuration = () => {
    if (!agent.started_at) return '-'
    const start = new Date(agent.started_at)
    const end = agent.completed_at ? new Date(agent.completed_at) : new Date()
    const duration = Math.floor((end.getTime() - start.getTime()) / 1000)
    if (duration < 60) return `${duration}秒`
    return `${Math.floor(duration / 60)}分${duration % 60}秒`
  }

  return (
    <div className="h-full flex flex-col bg-slate-950/50">
      {/* Header */}
      <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/50 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="text-2xl">{typeConfig.icon}</span>
            <div>
              <h3 className={cn('text-sm font-semibold', typeConfig.color)}>{typeConfig.name}</h3>
              <div className="text-[10px] text-slate-500 font-mono">#{agent.agent_id.slice(-6)}</div>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <StatusIcon className={cn('w-3.5 h-3.5', statusConfig.color, statusConfig.animate)} />
            <span className={cn('text-[10px] font-medium px-2 py-0.5 rounded', statusConfig.color, statusConfig.bgColor)}>
              {statusConfig.label}
            </span>
          </div>
        </div>

        {/* 时间信息 */}
        <div className="flex items-center gap-3 text-[10px] text-slate-500">
          <div className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            <span>开始: {formatTime(agent.started_at)}</span>
          </div>
          {agent.completed_at && (
            <div className="flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3" />
              <span>完成: {formatTime(agent.completed_at)}</span>
            </div>
          )}
          <div className="flex items-center gap-1">
            <Zap className="w-3 h-3" />
            <span>耗时: {getDuration()}</span>
          </div>
        </div>
      </div>

      {/* Scrollable Content */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">
        {/* 统计网格 */}
        {stats && (
          <div className="grid grid-cols-2 gap-2">
            <StatCard
              icon={Bug}
              label="发现漏洞"
              value={stats.findingsCount}
              color="text-rose-400"
              bgColor="bg-rose-950/20"
            />
            <StatCard
              icon={RefreshCw}
              label="迭代次数"
              value={stats.iterations}
              color="text-blue-400"
              bgColor="bg-blue-950/20"
            />
            <StatCard
              icon={Zap}
              label="Token 使用"
              value={stats.totalTokens}
              color="text-amber-400"
              bgColor="bg-amber-950/20"
            />
            <StatCard
              icon={Wrench}
              label="工具调用"
              value={stats.toolCalls}
              color="text-violet-400"
              bgColor="bg-violet-950/20"
            />
          </div>
        )}

        {/* 当前任务 */}
        {agent.task && (
          <div className={cn('p-3 rounded-lg border', typeConfig.bgColor, typeConfig.borderColor)}>
            <div className="flex items-center gap-2 mb-2">
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              <span className="text-xs font-medium text-slate-300">当前任务</span>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed">{agent.task}</p>
          </div>
        )}

        {/* 错误信息 */}
        {agent.error && (
          <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-950/30">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              <span className="text-xs font-medium text-rose-400">错误信息</span>
            </div>
            <p className="text-sm text-rose-300">{agent.error}</p>
          </div>
        )}

        {/* 执行时间线 */}
        {stats && stats.relatedLogs.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-xs font-medium text-slate-400">执行时间线</span>
            </div>
            <div className="space-y-2">
              {stats.relatedLogs.map((log) => (
                <TimelineItem
                  key={log.id}
                  type={log.type}
                  message={log.content || log.type}
                  timestamp={new Date(log.timestamp).toLocaleTimeString('zh-CN')}
                />
              ))}
            </div>
          </div>
        )}

        {/* 相关发现 */}
        {stats && stats.findingsCount > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Bug className="w-3.5 h-3.5 text-rose-400" />
              <span className="text-xs font-medium text-slate-400">相关漏洞发现</span>
            </div>
            <div className="space-y-2">
              {findings.slice(0, 3).map((finding) => (
                <div
                  key={finding.id}
                  className={cn(
                    'p-2 rounded border text-xs',
                    finding.severity === 'critical'
                      ? 'bg-rose-950/30 border-rose-500/30'
                      : finding.severity === 'high'
                        ? 'bg-orange-950/30 border-orange-500/30'
                        : finding.severity === 'medium'
                          ? 'bg-amber-950/30 border-amber-500/30'
                          : 'bg-slate-900/50 border-slate-700'
                  )}
                >
                  <div className="font-medium text-slate-300">{finding.title}</div>
                  {finding.file_path && (
                    <div className="text-[10px] text-slate-500 font-mono mt-1">
                      {finding.file_path}:{finding.line_start}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
