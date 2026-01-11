/**
 * Agent SSE 流式连接 Hook
 *
 * 处理与后端Agent服务的SSE连接，实时接收事件
 */

import { useEffect, useRef, useState, useCallback } from 'react'
import { useToast } from '@/hooks/use-toast'
import type { LogItem, LogType } from '@/shared/types'

// 后端事件类型（与后端一致）
export interface BackendAgentEvent {
  id: string
  audit_id: string
  agent_type: string
  event_type: string
  sequence: number
  timestamp: string
  data: Record<string, any>
  message?: string
}

export interface UseAgentStreamOptions {
  auditId?: string
  onEvent?: (event: BackendAgentEvent) => void
  onLog?: (log: LogItem) => void
  onComplete?: () => void
  onError?: (error: Error) => void
  enabled?: boolean
}

export interface UseAgentStreamReturn {
  isConnected: boolean
  isConnecting: boolean
  error: Error | null
  logs: LogItem[]
  connectionStatus: 'disconnected' | 'connecting' | 'connected' | 'error'
  reconnect: () => void
  disconnect: () => void
  clearLogs: () => void
}

// 后端API地址
const AGENT_SERVICE_URL = import.meta.env.VITE_AGENT_SERVICE_URL || 'http://localhost:8001'

export function useAgentStream(options: UseAgentStreamOptions = {}): UseAgentStreamReturn {
  const {
    auditId,
    onEvent,
    onLog,
    onComplete,
    onError,
    enabled = true,
  } = options

  const [isConnected, setIsConnected] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const [logs, setLogs] = useState<LogItem[]>([])
  const [connectionStatus, setConnectionStatus] = useState<'disconnected' | 'connecting' | 'connected' | 'error'>('disconnected')

  const eventSourceRef = useRef<EventSource | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const retryCountRef = useRef(0)
  const toast = useToast()

  // 转换后端事件为日志条目
  const convertEventToLog = useCallback((event: BackendAgentEvent): LogItem => {
    const eventType = event.event_type.toLowerCase()

    // 映射后端事件类型到前端日志类型
    const logTypeMap: Record<string, LogType> = {
      'thinking': 'thinking',
      'action': 'tool',
      'tool_call': 'tool',
      'observation': 'observation',
      'finding': 'finding',
      'info': 'info',
      'error': 'error',
      'progress': 'progress',
      'complete': 'complete',
      'status': 'info',
      'phase_start': 'info',
      'phase_complete': 'complete',
      'dispatch': 'dispatch',
      'system': 'system',
    }

    const logType = logTypeMap[eventType] || 'info'

    return {
      id: event.id,
      type: logType,
      agent_type: event.agent_type as any, // TODO: fix type mapping
      timestamp: new Date(event.timestamp).getTime(),
      content: event.message || event.data?.message || '',
      data: event.data,
      expanded: false,
    }
  }, [])

  // 连接SSE
  const connect = useCallback(() => {
    if (!auditId || !enabled) {
      return
    }

    // 清理现有连接
    disconnect()

    setIsConnecting(true)
    setConnectionStatus('connecting')
    setError(null)

    try {
      const url = `${AGENT_SERVICE_URL}/api/audit/${auditId}/stream`
      const eventSource = new EventSource(url)

      eventSourceRef.current = eventSource

      // 连接成功
      eventSource.onopen = () => {
        console.log('[SSE] 连接成功')
        setIsConnected(true)
        setIsConnecting(false)
        setConnectionStatus('connected')
        setError(null)
        retryCountRef.current = 0
      }

      // 接收消息
      eventSource.onmessage = (event) => {
        try {
          const data: BackendAgentEvent = JSON.parse(event.data)

          // 触发事件回调
          if (onEvent) {
            onEvent(data)
          }

          // 转换为日志并添加
          const log = convertEventToLog(data)
          setLogs(prev => {
            // 避免重复（通过sequence检查）
            if (prev.some(l => l.id === log.id)) {
              return prev
            }
            // 限制日志数量
            const newLogs = [...prev, log]
            if (newLogs.length > 500) {
              return newLogs.slice(-500)
            }
            return newLogs
          })

          // 触发日志回调
          if (onLog) {
            onLog(log)
          }

          // 检查完成状态
          if (data.event_type === 'complete' || data.event_type === 'cancelled' || data.event_type === 'error') {
            setIsConnected(false)
            if (onComplete) {
              onComplete()
            }
          }
        } catch (err) {
          console.error('[SSE] 解析消息失败:', err)
        }
      }

      // 错误处理
      eventSource.onerror = (err) => {
        console.error('[SSE] 连接错误:', err)

        const error = new Error('SSE连接失败')
        setError(error)
        setIsConnected(false)
        setIsConnecting(false)
        setConnectionStatus('error')

        if (onError) {
          onError(error)
        }

        // 自动重连（最多5次）
        if (retryCountRef.current < 5) {
          retryCountRef.current++
          const delay = Math.min(1000 * Math.pow(2, retryCountRef.current), 30000)
          console.log(`[SSE] ${delay}ms后重连 (${retryCountRef.current}/5)`)

          reconnectTimeoutRef.current = setTimeout(() => {
            connect()
          }, delay)
        } else {
          toast.error('Agent服务连接失败，请检查服务是否启动')
          disconnect()
        }
      }
    } catch (err) {
      const error = err instanceof Error ? err : new Error('创建SSE连接失败')
      setError(error)
      setIsConnecting(false)
      setConnectionStatus('error')

      if (onError) {
        onError(error)
      }
    }
  }, [auditId, enabled, onEvent, onLog, onComplete, onError, convertEventToLog, toast])

  // 断开连接
  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    setIsConnected(false)
    setConnectionStatus('disconnected')
  }, [])

  // 手动重连
  const reconnect = useCallback(() => {
    retryCountRef.current = 0
    connect()
  }, [connect])

  // 清空日志
  const clearLogs = useCallback(() => {
    setLogs([])
  }, [])

  // 当auditId或enabled变化时，重新连接
  useEffect(() => {
    if (auditId && enabled) {
      connect()
    } else {
      disconnect()
    }

    return () => {
      disconnect()
    }
  }, [auditId, enabled, connect, disconnect])

  return {
    isConnected,
    isConnecting,
    error,
    logs,
    connectionStatus,
    reconnect,
    disconnect,
    clearLogs,
  }
}
