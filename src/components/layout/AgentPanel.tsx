/**
 * AgentPanel - 右侧 Agent 审计面板
 *
 * 显示 AI 审计 Agent 的功能：
 * - 审计控制（开始/暂停/终止）
 * - 审计状态和进度
 * - Agent 树结构
 * - 审计日志
 * - 发现的漏洞
 */

import { useState } from 'react'
import { Play, Pause, Square, Zap, Sparkles, Loader2, Bot, Activity, FileText, X } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import { useToast } from '@/hooks/use-toast'

// 组件
import { ChatLogPanel } from '@/components/audit/ChatLogPanel'
import { FindingsPanel } from '@/components/audit/FindingsPanel'
import { AuditStatusIndicator } from '@/components/audit/AuditStatusIndicator'

// Hook 和 API
import { useAgentAuditState } from '@/pages/AgentAudit/useAgentAuditState'
import {
  createAuditTask,
  pauseAuditTask,
  cancelAuditTask,
  getAuditTask,
  getAuditFindings,
  getAuditAgentTree,
  healthCheck,
  eventToLogItem,
} from '@/pages/AgentAudit/api'

export function AgentPanel() {
  const { currentProject } = useProjectStore()
  const toast = useToast()

  // 状态管理
  const {
    state,
    filteredLogs,
    setTask,
    setFindings,
    addLog,
    addFinding,
    setAgentTree,
    setLoading,
    setError,
    reset,
  } = useAgentAuditState()

  // UI 状态
  const [auditType, setAuditType] = useState<'quick' | 'full'>('full')
  const [isServiceHealthy, setIsServiceHealthy] = useState(false)
  const [isCheckingHealth, setIsCheckingHealth] = useState(true)
  const [activeTab, setActiveTab] = useState<'status' | 'tree' | 'logs' | 'findings'>('status')

  // 获取当前项目的 auditId（如果有）
  const auditId = state.task?.id || null

  // ==================== 渲染 ====================

  return (
    <div className="flex flex-col h-full bg-[#252526]">
      {/* 头部 */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-border/40 shrink-0">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-primary" />
          <span className="text-sm font-semibold text-white">Agent 审计</span>
        </div>
        {state.isLoading && (
          <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
        )}
      </div>

      {/* 审计控制栏 */}
      <div className="px-3 py-2 border-b border-border/40 shrink-0 space-y-2">
        {/* 审计模式选择 */}
        <div className="flex items-center gap-2">
          <label className="text-xs font-semibold text-muted-foreground">模式</label>
          <div className="flex rounded-lg bg-[#1e1e1e] p-0.5 border border-border/40 flex-1">
            <button
              onClick={() => setAuditType('quick')}
              className={cn(
                "flex-1 px-2 py-1 rounded text-xs font-medium transition-all flex items-center justify-center gap-1",
                auditType === 'quick'
                  ? "bg-amber-500/20 text-amber-300"
                  : "text-muted-foreground hover:text-white hover:bg-white/5"
              )}
            >
              <Zap className="w-3 h-3" />
              快速
            </button>
            <button
              onClick={() => setAuditType('full')}
              className={cn(
                "flex-1 px-2 py-1 rounded text-xs font-medium transition-all flex items-center justify-center gap-1",
                auditType === 'full'
                  ? "bg-violet-500/20 text-violet-300"
                  : "text-muted-foreground hover:text-white hover:bg-white/5"
              )}
            >
              <Sparkles className="w-3 h-3" />
              深度
            </button>
          </div>
        </div>

        {/* 服务状态 */}
        <div className={cn(
          "flex items-center gap-1.5 px-2 py-1 rounded-full border transition-all",
          isServiceHealthy ? "bg-green-950/30 border-green-800/50" : "bg-red-950/30 border-red-800/50"
        )}>
          <div className={cn(
            "w-1.5 h-1.5 rounded-full transition-colors",
            isCheckingHealth ? "bg-yellow-400 animate-pulse" : isServiceHealthy ? "bg-green-400 animate-pulse" : "bg-red-400"
          )} />
          <span className={cn(
            "text-[10px] font-medium",
            isCheckingHealth ? "text-yellow-400" : isServiceHealthy ? "text-green-400" : "text-red-400"
          )}>
            {isCheckingHealth ? '检查中' : isServiceHealthy ? '在线' : '离线'}
          </span>
        </div>

        {/* 控制按钮 */}
        <div className="flex gap-1">
          {(!state.task || state.task.status === 'pending' || state.task.status === 'completed' || state.task.status === 'failed' || state.task.status === 'cancelled') ? (
            <Button
              size="sm"
              onClick={() => handleStartAudit()}
              disabled={!isServiceHealthy || state.isLoading || !currentProject}
              className="h-7 flex-1 text-xs"
            >
              {state.isLoading ? (
                <Loader2 className="w-3 h-3 mr-1 animate-spin" />
              ) : (
                <Play className="w-3 h-3 mr-1" />
              )}
              开始
            </Button>
          ) : state.task.status === 'running' ? (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handlePauseAudit()}
                className="h-7 bg-[#1e1e1e] border-border/40 text-muted-foreground hover:text-white flex-1 text-xs"
              >
                <Pause className="w-3 h-3 mr-1" />
                暂停
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => handleCancelAudit()}
                className="h-7 flex-1 text-xs"
              >
                <Square className="w-3 h-3 mr-1" />
                终止
              </Button>
            </>
          ) : state.task.status === 'paused' ? (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleStartAudit()}
                className="h-7 bg-[#1e1e1e] border-border/40 text-muted-foreground hover:text-white flex-1 text-xs"
              >
                <Play className="w-3 h-3 mr-1" />
                恢复
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => handleCancelAudit()}
                className="h-7 flex-1 text-xs"
              >
                <Square className="w-3 h-3 mr-1" />
                终止
              </Button>
            </>
          ) : null}
        </div>
      </div>

      {/* 内容区域 - 标签页 */}
      <Tabs value={activeTab} onValueChange={(v: any) => setActiveTab(v)} className="flex-1 flex flex-col min-h-0">
        <div className="px-3 pt-2 shrink-0">
          <TabsList className="w-full bg-[#1e1e1e] border border-border/40 rounded-md p-0.5 h-7">
            <TabsTrigger value="status" className="flex-1 h-6 data-[state=active]:bg-[#252526] text-xs">
              状态
            </TabsTrigger>
            <TabsTrigger value="tree" className="flex-1 h-6 data-[state=active]:bg-[#252526] text-xs">
              Agent树
            </TabsTrigger>
            <TabsTrigger value="logs" className="flex-1 h-6 data-[state=active]:bg-[#252526] text-xs flex items-center gap-1">
              <Activity className="w-3 h-3" />
              日志
              {state.logs.length > 0 && (
                <Badge variant="secondary" className="ml-auto text-[10px] bg-[#3c3c3c] text-muted-foreground border-border/40 px-1 h-4">
                  {state.logs.length}
                </Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="findings" className="flex-1 h-6 data-[state=active]:bg-[#252526] text-xs flex items-center gap-1">
              <FileText className="w-3 h-3" />
              结果
              {state.findings.length > 0 && (
                <Badge variant="secondary" className="ml-auto text-[10px] bg-red-900/50 text-red-400 border-border/40 px-1 h-4">
                  {state.findings.length}
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>
        </div>

        {/* 标签页内容 */}
        <div className="flex-1 min-h-0 overflow-hidden">
          <TabsContent value="status" className="h-full m-0 p-0 overflow-auto">
            <div className="p-3 space-y-3">
              {state.task ? (
                <>
                  <AuditStatusIndicator
                    status={state.task.status}
                    progress={state.task.progress_percentage}
                    currentPhase={state.task.current_phase}
                    error={state.error}
                  />
                  {/* 统计信息 */}
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="bg-[#1e1e1e] rounded p-2">
                      <div className="text-muted-foreground">已扫描文件</div>
                      <div className="text-white font-semibold">{state.task.analyzed_files || 0}</div>
                    </div>
                    <div className="bg-[#1e1e1e] rounded p-2">
                      <div className="text-muted-foreground">发现漏洞</div>
                      <div className="text-red-400 font-semibold">{state.findings.length}</div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="text-center text-sm text-muted-foreground py-8">
                  {state.isLoading ? (
                    <>
                      <Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />
                      <p>加载中...</p>
                    </>
                  ) : (
                    <>
                      <Bot className="w-8 h-8 mx-auto mb-2 opacity-50" />
                      <p>点击"开始"启动审计</p>
                    </>
                  )}
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="tree" className="h-full m-0 p-0 overflow-hidden">
            <div className="h-full flex items-center justify-center text-muted-foreground">
              {state.isLoading ? (
                <Loader2 className="w-6 h-6 animate-spin" />
              ) : state.agentTree?.roots?.length ? (
                <div className="p-4 w-full">
                  <div className="text-xs text-muted-foreground mb-2">
                    Agent Tree ({state.agentTree.roots.length} 个根节点)
                  </div>
                  {state.agentTree.roots.map((agent: any) => (
                    <div key={agent.agent_id} className="bg-[#1e1e1e] rounded p-2 mb-2">
                      <div className="text-sm font-medium">{agent.agent_type}</div>
                      <div className="text-xs text-muted-foreground">{agent.agent_id}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-sm">暂无 Agent 数据</div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="logs" className="h-full m-0 p-0 overflow-hidden">
            <ChatLogPanel
              logs={filteredLogs}
              autoScroll={state.isAutoScroll}
              expandedLogIds={state.expandedLogIds}
              onToggleExpand={() => {}}
            />
          </TabsContent>

          <TabsContent value="findings" className="h-full m-0 p-0 overflow-hidden">
            <FindingsPanel
              findings={state.findings}
              loading={state.isLoading}
              onRefresh={() => {}}
            />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  )

  // ==================== 处理函数 ====================

  async function handleStartAudit() {
    if (!currentProject) {
      toast.error('请先打开一个项目')
      return
    }
    if (!isServiceHealthy) {
      toast.error('Agent 服务未连接')
      return
    }

    setLoading(true)
    toast.info('正在启动审计...')

    try {
      const result = await createAuditTask({
        project_id: currentProject.uuid,
        audit_type: auditType,
      })

      toast.success('审计任务已启动')
      // 加载任务信息
      const task = await getAuditTask(result.audit_id)
      setTask(task)
      setActiveTab('logs')
    } catch (err) {
      const message = err instanceof Error ? err.message : '启动审计失败'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  async function handlePauseAudit() {
    if (!auditId) return

    try {
      await pauseAuditTask(auditId)
      toast.success('审计已暂停')
      const task = await getAuditTask(auditId)
      setTask(task)
    } catch (err) {
      toast.error('暂停审计失败')
    }
  }

  async function handleCancelAudit() {
    if (!auditId) return

    try {
      await cancelAuditTask(auditId)
      toast.success('审计已终止')
      const task = await getAuditTask(auditId)
      setTask(task)
    } catch (err) {
      toast.error('终止审计失败')
    }
  }
}
