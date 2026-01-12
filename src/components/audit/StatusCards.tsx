/**
 * Status Cards Component
 *
 * 新设计的右侧状态卡片组件，包含：
 * - Progress卡片（带进度条）
 * - Files Scanned卡片
 * - 2x2状态网格（Iteration、Tool Calls、Tokens、Findings）
 * - Security Score卡片
 *
 * 颜色方案：
 * - Progress橙色: #F97316
 * - Files扫描青色: #14B8A6
 * - Iteration青绿色: #10B981
 * - Tool Calls橙色: #F97316
 * - Tokens紫色: #8B5CF6
 * - Findings灰色: #888888
 * - Security红色: #EF4444
 */

import { Activity, FileText, RefreshCcw, Zap, Bug, Shield } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface StatusCardsProps {
  // 进度百分比
  progress?: number
  // 已扫描文件数
  scannedFiles?: number
  // 总文件数
  totalFiles?: number
  // 迭代次数
  iterations?: number
  // 工具调用次数
  toolCalls?: number
  // Token数量（k为单位）
  tokens?: number
  // 发现数
  findings?: number
  // 安全评分
  securityScore?: number
  // 是否加载中
  isLoading?: boolean
}

// 进度卡片
function ProgressCard({ progress = 0 }: { progress?: number }) {
  return (
    <div className="p-3 rounded-lg bg-[#121212] border border-[#333333]">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#F97316]" />
          <span className="text-xs font-semibold text-[#888888]">PROGRESS</span>
        </div>
        <span className="text-sm font-bold text-white">{progress}%</span>
      </div>
      {/* 进度条 */}
      <div className="h-1.5 bg-[#333333] rounded-full overflow-hidden">
        <div
          className="h-full bg-[#F97316] transition-all duration-300"
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  )
}

// 文件扫描卡片
function FilesScannedCard({ scanned = 0, total = 0 }: { scanned?: number; total?: number }) {
  return (
    <div className="p-3 rounded-lg bg-[#121212] border border-[#333333]">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-[#14B8A6]" />
          <span className="text-xs font-semibold text-[#888888]">Files scanned</span>
        </div>
        <span className="text-sm font-bold text-white">
          {scanned} / {total}
        </span>
      </div>
    </div>
  )
}

// 小状态卡片（用于2x2网格）
interface StatusCardProps {
  icon: React.ReactNode
  label: string
  value: string | number
  colorClass: string
}

function StatusCard({ icon, label, value, colorClass }: StatusCardProps) {
  return (
    <div className="p-3 rounded-lg bg-[#121212] border border-[#333333]">
      <div className="flex flex-col gap-1">
        <div className={cn("flex items-center gap-1.5", colorClass)}>
          {icon}
          <span className="text-[10px] font-semibold truncate">{label}</span>
        </div>
        <span className="text-lg font-bold text-white">{value}</span>
      </div>
    </div>
  )
}

// 安全评分卡片
function SecurityScoreCard({ score = 0 }: { score?: number }) {
  const getScoreStatus = (score: number) => {
    if (score >= 80) return { label: 'Good', color: 'text-emerald-400' }
    if (score >= 60) return { label: 'Fair', color: 'text-amber-400' }
    return { label: 'Needs Attention', color: 'text-rose-400' }
  }

  const status = getScoreStatus(score)

  return (
    <div className="p-3 rounded-lg bg-[#121212] border border-[#333333]">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-white" />
          <span className="text-xs font-semibold text-white">SECURITY SCORE</span>
        </div>
        <span className={cn("text-sm font-bold", status.color)}>
          {status.label}
        </span>
      </div>
      {/* 评分显示 */}
      <div className="mt-2 flex items-center justify-center">
        <div className={cn(
          "text-3xl font-bold",
          score >= 80 && "text-emerald-400",
          score >= 60 && score < 80 && "text-amber-400",
          score < 60 && "text-rose-400"
        )}>
          {score}
        </div>
      </div>
    </div>
  )
}

// 加载状态
function LoadingState() {
  return (
    <div className="flex flex-col items-center justify-center py-8 text-[#888888]">
      <div className="w-10 h-10 border-2 border-[#333333] border-t-purple-500 rounded-full animate-spin mb-3" />
      <p className="text-xs">INITIALIZING AGENTS...</p>
    </div>
  )
}

export function StatusCards({
  progress = 0,
  scannedFiles = 0,
  totalFiles = 0,
  iterations = 0,
  toolCalls = 0,
  tokens = 0,
  findings = 0,
  securityScore = 0,
  isLoading = false,
}: StatusCardsProps) {
  return (
    <div className="flex flex-col gap-3 p-4 bg-[#121212]">
      {/* Progress卡片 */}
      <ProgressCard progress={progress} />

      {/* Files Scanned卡片 */}
      <FilesScannedCard scanned={scannedFiles} total={totalFiles} />

      {/* 2x2状态网格 */}
      <div className="grid grid-cols-2 gap-3">
        <StatusCard
          icon={<RefreshCcw className="w-3.5 h-3.5" />}
          label="ITERATION"
          value={iterations}
          colorClass="text-[#10B981]"
        />
        <StatusCard
          icon={<Zap className="w-3.5 h-3.5" />}
          label="TOOL CALLS"
          value={toolCalls}
          colorClass="text-[#F97316]"
        />
        <StatusCard
          icon={<Activity className="w-3.5 h-3.5" />}
          label="TOKENS"
          value={`${(tokens / 1000).toFixed(1)}k`}
          colorClass="text-[#8B5CF6]"
        />
        <StatusCard
          icon={<Bug className="w-3.5 h-3.5" />}
          label="FINDINGS"
          value={findings}
          colorClass="text-[#888888]"
        />
      </div>

      {/* Security Score卡片 */}
      <SecurityScoreCard score={securityScore} />

      {/* 加载状态覆盖 */}
      {isLoading && (
        <div className="absolute inset-0 bg-[#121212]/80 flex items-center justify-center rounded-lg">
          <LoadingState />
        </div>
      )}
    </div>
  )
}
