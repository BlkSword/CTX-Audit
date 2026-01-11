/**
 * Agent 审计状态管理 Hook
 * 参考 DeepAudit-3.0.0 实现
 */

import { useReducer, useCallback, useMemo } from 'react'
import {
  agentAuditReducer,
  initialState,
  type AgentAuditState,
  selectFilteredLogs,
  selectIsTaskRunning,
  selectIsTaskComplete,
  selectSeverityStats,
  selectTokenCount,
  selectToolCallCount,
} from './reducer'

export function useAgentAuditState() {
  const [state, dispatch] = useReducer(agentAuditReducer, initialState)

  // ==================== 数据设置 ====================

  const setTask = useCallback((task: AgentAuditState['task']) => {
    dispatch({ type: 'SET_TASK', payload: task })
  }, [])

  const setFindings = useCallback((findings: AgentAuditState['findings']) => {
    dispatch({ type: 'SET_FINDINGS', payload: findings })
  }, [])

  const addFinding = useCallback((finding: AgentFinding) => {
    dispatch({ type: 'ADD_FINDING', payload: finding })
  }, [])

  const updateFinding = useCallback((id: string, updates: Partial<AgentFinding>) => {
    dispatch({ type: 'UPDATE_FINDING', payload: { id, updates } })
  }, [])

  const setAgentTree = useCallback((tree: AgentAuditState['agentTree']) => {
    dispatch({ type: 'SET_AGENT_TREE', payload: tree })
  }, [])

  // ==================== 日志操作 ====================

  const addLog = useCallback((log: LogItem | null) => {
    if (log) {
      dispatch({ type: 'ADD_LOG', payload: log })
    }
  }, [])

  const updateLog = useCallback((id: string, updates: Partial<LogItem>) => {
    dispatch({ type: 'UPDATE_LOG', payload: { id, updates } })
  }, [])

  const removeLog = useCallback((id: string) => {
    dispatch({ type: 'REMOVE_LOG', payload: id })
  }, [])

  const completeToolLog = useCallback((id: string, output: unknown, duration: number) => {
    dispatch({ type: 'COMPLETE_TOOL_LOG', payload: { id, output, duration } })
  }, [])

  const updateOrAddProgressLog = useCallback(
    (progressKey: string, title: string, agentName: string, content?: string) => {
      dispatch({
        type: 'UPDATE_OR_ADD_PROGRESS_LOG',
        payload: { progressKey, title, agentName, content },
      })
    },
    []
  )

  // ==================== UI 状态 ====================

  const selectAgent = useCallback((agentId: string | null) => {
    dispatch({ type: 'SELECT_AGENT', payload: agentId })
  }, [])

  const toggleShowAllLogs = useCallback(() => {
    dispatch({ type: 'TOGGLE_SHOW_ALL_LOGS' })
  }, [])

  const toggleLogExpanded = useCallback((id: string) => {
    dispatch({ type: 'TOGGLE_LOG_EXPANDED', payload: id })
  }, [])

  const setAutoScroll = useCallback((enabled: boolean) => {
    dispatch({ type: 'SET_AUTO_SCROLL', payload: enabled })
  }, [])

  const setLoading = useCallback((loading: boolean) => {
    dispatch({ type: 'SET_LOADING', payload: loading })
  }, [])

  const setError = useCallback((error: string | null) => {
    dispatch({ type: 'SET_ERROR', payload: error })
  }, [])

  const setConnectionStatus = useCallback((status: ConnectionStatus) => {
    dispatch({ type: 'SET_CONNECTION_STATUS', payload: status })
  }, [])

  const setHistoricalEventsLoaded = useCallback((loaded: boolean) => {
    dispatch({ type: 'SET_HISTORICAL_EVENTS_LOADED', payload: loaded })
  }, [])

  const setAfterSequence = useCallback((sequence: number) => {
    dispatch({ type: 'SET_AFTER_SEQUENCE', payload: sequence })
  }, [])

  const reset = useCallback(() => {
    dispatch({ type: 'RESET' })
  }, [])

  // ==================== 计算属性 ====================

  const filteredLogs = useMemo(() => selectFilteredLogs(state), [state])
  const isTaskRunning = useMemo(() => selectIsTaskRunning(state), [state])
  const isTaskComplete = useMemo(() => selectIsTaskComplete(state), [state])
  const severityStats = useMemo(() => selectSeverityStats(state), [state])
  const tokenCount = useMemo(() => selectTokenCount(state), [state])
  const toolCallCount = useMemo(() => selectToolCallCount(state), [state])

  return {
    // 状态
    state,

    // 数据设置
    setTask,
    setFindings,
    addFinding,
    updateFinding,
    setAgentTree,

    // 日志操作
    addLog,
    updateLog,
    removeLog,
    completeToolLog,
    updateOrAddProgressLog,

    // UI 状态
    selectAgent,
    toggleShowAllLogs,
    toggleLogExpanded,
    setAutoScroll,
    setLoading,
    setError,
    setConnectionStatus,
    setHistoricalEventsLoaded,
    setAfterSequence,
    reset,

    // 计算属性
    filteredLogs,
    isTaskRunning,
    isTaskComplete,
    severityStats,
    tokenCount,
    toolCallCount,
  }
}

// 类型导入
import type { LogItem, AgentFinding, ConnectionStatus } from './types'
