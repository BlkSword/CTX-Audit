/**
 * Agent 审计状态管理 Reducer
 * 参考 DeepAudit-3.0.0 实现
 * 使用 useReducer 管理复杂的审计状态
 */

import type { LogItem, AgentTask, AgentFinding, AgentTreeResponse, ConnectionStatus, AgentType } from './types'

// ==================== State ====================

export interface AgentAuditState {
  // 数据
  task: AgentTask | null
  findings: AgentFinding[]
  agentTree: AgentTreeResponse | null
  logs: LogItem[]

  // UI 状态
  selectedAgentId: string | null
  showAllLogs: boolean
  isAutoScroll: boolean
  expandedLogIds: Set<string>
  isLoading: boolean
  error: string | null
  connectionStatus: ConnectionStatus

  // 流控制
  historicalEventsLoaded: boolean
  afterSequence: number
}

export const initialState: AgentAuditState = {
  task: null,
  findings: [],
  agentTree: null,
  logs: [],
  selectedAgentId: null,
  showAllLogs: true,
  isAutoScroll: true,
  expandedLogIds: new Set<string>(),
  isLoading: false,
  error: null,
  connectionStatus: 'disconnected',
  historicalEventsLoaded: false,
  afterSequence: 0,
}

// ==================== Actions ====================

export type AgentAuditAction =
  | { type: 'SET_TASK'; payload: AgentTask | null }
  | { type: 'SET_FINDINGS'; payload: AgentFinding[] }
  | { type: 'ADD_FINDING'; payload: AgentFinding }
  | { type: 'UPDATE_FINDING'; payload: { id: string; updates: Partial<AgentFinding> } }
  | { type: 'SET_AGENT_TREE'; payload: AgentTreeResponse | null }
  | { type: 'ADD_LOG'; payload: LogItem }
  | { type: 'UPDATE_LOG'; payload: { id: string; updates: Partial<LogItem> } }
  | { type: 'REMOVE_LOG'; payload: string }
  | { type: 'COMPLETE_TOOL_LOG'; payload: { id: string; output: unknown; duration: number } }
  | { type: 'UPDATE_OR_ADD_PROGRESS_LOG'; payload: { progressKey: string; title: string; agentName: string; content?: string } }
  | { type: 'SELECT_AGENT'; payload: string | null }
  | { type: 'TOGGLE_SHOW_ALL_LOGS' }
  | { type: 'TOGGLE_LOG_EXPANDED'; payload: string }
  | { type: 'SET_AUTO_SCROLL'; payload: boolean }
  | { type: 'SET_LOADING'; payload: boolean }
  | { type: 'SET_ERROR'; payload: string | null }
  | { type: 'SET_CONNECTION_STATUS'; payload: ConnectionStatus }
  | { type: 'SET_HISTORICAL_EVENTS_LOADED'; payload: boolean }
  | { type: 'SET_AFTER_SEQUENCE'; payload: number }
  | { type: 'RESET' }

// ==================== Reducer ====================

export function agentAuditReducer(state: AgentAuditState, action: AgentAuditAction): AgentAuditState {
  switch (action.type) {
    // ==================== 数据设置 ====================

    case 'SET_TASK':
      return { ...state, task: action.payload }

    case 'SET_FINDINGS':
      return { ...state, findings: action.payload }

    case 'ADD_FINDING': {
      const exists = state.findings.some(f => f.id === action.payload.id)
      if (exists) return state
      return { ...state, findings: [...state.findings, action.payload] }
    }

    case 'UPDATE_FINDING': {
      return {
        ...state,
        findings: state.findings.map(f =>
          f.id === action.payload.id ? { ...f, ...action.payload.updates } : f
        ),
      }
    }

    case 'SET_AGENT_TREE':
      return { ...state, agentTree: action.payload }

    // ==================== 日志操作 ====================

    case 'ADD_LOG': {
      const maxLogs = 1000
      const newLogs = [...state.logs, action.payload]
      if (newLogs.length > maxLogs) {
        return { ...state, logs: newLogs.slice(-maxLogs) }
      }
      return { ...state, logs: newLogs }
    }

    case 'UPDATE_LOG': {
      return {
        ...state,
        logs: state.logs.map(log =>
          log.id === action.payload.id ? { ...log, ...action.payload.updates } : log
        ),
      }
    }

    case 'REMOVE_LOG': {
      return {
        ...state,
        logs: state.logs.filter(log => log.id !== action.payload),
      }
    }

    case 'COMPLETE_TOOL_LOG': {
      const { id, output, duration } = action.payload
      return {
        ...state,
        logs: state.logs.map(log => {
          if (log.id === id && log.type === 'tool') {
            return {
              ...log,
              isComplete: true,
              toolOutput: output,
              data: {
                ...log.data,
                result: output,
                duration_ms: duration,
              },
            }
          }
          return log
        }),
      }
    }

    case 'UPDATE_OR_ADD_PROGRESS_LOG': {
      const { progressKey, title, agentName, content } = action.payload
      const existingLog = state.logs.find(
        log => log.type === 'progress' && log.progressKey === progressKey
      )

      if (existingLog) {
        return {
          ...state,
          logs: state.logs.map(log =>
            log.id === existingLog.id
              ? {
                  ...log,
                  content: content || log.content,
                  timestamp: Date.now(),
                  data: {
                    ...log.data,
                    message: content || log.content,
                  },
                }
              : log
          ),
        }
      } else {
        const newLog: LogItem = {
          id: `progress_${progressKey}_${Date.now()}`,
          type: 'progress',
          agent_type: agentName as AgentType,
          timestamp: Date.now(),
          content: title,
          progressKey,
          data: {
            message: content || title,
            stage: progressKey,
          },
        }
        return { ...state, logs: [...state.logs, newLog] }
      }
    }

    // ==================== UI 状态 ====================

    case 'SELECT_AGENT':
      return { ...state, selectedAgentId: action.payload }

    case 'TOGGLE_SHOW_ALL_LOGS':
      return { ...state, showAllLogs: !state.showAllLogs }

    case 'TOGGLE_LOG_EXPANDED': {
      const newExpanded = new Set(state.expandedLogIds)
      if (newExpanded.has(action.payload)) {
        newExpanded.delete(action.payload)
      } else {
        newExpanded.add(action.payload)
      }
      return { ...state, expandedLogIds: newExpanded }
    }

    case 'SET_AUTO_SCROLL':
      return { ...state, isAutoScroll: action.payload }

    case 'SET_LOADING':
      return { ...state, isLoading: action.payload }

    case 'SET_ERROR':
      return { ...state, error: action.payload }

    case 'SET_CONNECTION_STATUS':
      return { ...state, connectionStatus: action.payload }

    case 'SET_HISTORICAL_EVENTS_LOADED':
      return { ...state, historicalEventsLoaded: action.payload }

    case 'SET_AFTER_SEQUENCE':
      return { ...state, afterSequence: action.payload }

    case 'RESET':
      return { ...initialState, expandedLogIds: new Set() }

    default:
      return state
  }
}

// ==================== Selectors ====================

export const selectFilteredLogs = (state: AgentAuditState): LogItem[] => {
  if (state.showAllLogs || !state.selectedAgentId) {
    return state.logs
  }
  return state.logs.filter(log => log.agent_type === state.selectedAgentId)
}

export const selectIsTaskRunning = (state: AgentAuditState): boolean => {
  return state.task?.status === 'running'
}

export const selectIsTaskComplete = (state: AgentAuditState): boolean => {
  return state.task?.status === 'completed' || state.task?.status === 'failed' || state.task?.status === 'cancelled'
}

export const selectSeverityStats = (state: AgentAuditState) => {
  return {
    critical: state.findings.filter(f => f.severity === 'critical').length,
    high: state.findings.filter(f => f.severity === 'high').length,
    medium: state.findings.filter(f => f.severity === 'medium').length,
    low: state.findings.filter(f => f.severity === 'low').length,
    info: state.findings.filter(f => f.severity === 'info').length,
  }
}

export const selectTokenCount = (state: AgentAuditState): number => {
  return state.logs.reduce((sum, log) => {
    if (log.data?.tokens_used) {
      return sum + (log.data.tokens_used as number)
    }
    return sum
  }, 0)
}

export const selectToolCallCount = (state: AgentAuditState): number => {
  return state.logs.filter(log => log.type === 'tool').length
}
