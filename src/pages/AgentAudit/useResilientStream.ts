/**
 * Resilient SSE Stream Hook
 * 参考 DeepAudit-3.0.0 实现
 *
 * 特性：
 * - 指数退避重连
 * - 心跳检测
 * - 自动序列号管理
 * - 事件类型分发
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import type { AgentEvent, ConnectionStatus } from './types'
import { createSSEUrl, transformBackendEvent, parseSSEEvent } from './api'

export interface UseResilientStreamOptions {
  enabled?: boolean
  onEvent?: (event: AgentEvent) => void
  onError?: (error: Error) => void
  onConnectionChange?: (status: ConnectionStatus) => void
  reconnectMaxAttempts?: number
  reconnectBaseDelay?: number
  reconnectMaxDelay?: number
  heartbeatTimeout?: number
}

export interface UseResilientStreamReturn {
  isConnected: boolean
  isConnecting: boolean
  connectionStatus: ConnectionStatus
  connectionAttempt: number
  connect: () => void
  disconnect: () => void
  resetConnection: () => void
}

/**
 * 计算重连延迟（指数退避 + 抖动）
 */
function calculateReconnectDelay(
  attempt: number,
  baseDelay: number,
  maxDelay: number
): number {
  const exponentialDelay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay)
  // 添加抖动（±25%）
  const jitter = exponentialDelay * 0.25 * (Math.random() * 2 - 1)
  return Math.max(exponentialDelay + jitter, baseDelay)
}

/**
 * Resilient SSE Stream Hook
 */
export function useResilientStream(
  auditId: string | null,
  afterSequence: number,
  options: UseResilientStreamOptions = {}
): UseResilientStreamReturn {
  const {
    enabled = true,
    onEvent,
    onError,
    onConnectionChange,
    reconnectMaxAttempts = 5,
    reconnectBaseDelay = 1000,
    reconnectMaxDelay = 30000,
    heartbeatTimeout = 45000,
  } = options

  // 连接状态
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('disconnected')
  const [connectionAttempt, setConnectionAttempt] = useState(0)

  // Refs
  const abortControllerRef = useRef<AbortController | null>(null)
  const heartbeatTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const readerRef = useRef<ReadableStreamDefaultReader<Uint8Array> | null>(null)
  const isCleanedUpRef = useRef(false)

  // 重置心跳定时器
  const resetHeartbeat = useCallback(() => {
    if (heartbeatTimeoutRef.current) {
      clearTimeout(heartbeatTimeoutRef.current)
    }
    heartbeatTimeoutRef.current = setTimeout(() => {
      if (!isCleanedUpRef.current && connectionStatus === 'connected') {
        console.warn('[ResilientStream] Heartbeat timeout, reconnecting...')
        disconnect()
        connect()
      }
    }, heartbeatTimeout)
  }, [connectionStatus, heartbeatTimeout])

  // 处理单个事件
  const handleEvent = useCallback(
    (event: AgentEvent) => {
      // 重置心跳
      resetHeartbeat()

      // 触发回调
      if (onEvent) {
        onEvent(event)
      }
    },
    [onEvent, resetHeartbeat]
  )

  // 连接流
  const connect = useCallback(async () => {
    if (!auditId || !enabled || isCleanedUpRef.current) {
      return
    }

    // 防止重复连接
    if (connectionStatus === 'connected' || connectionStatus === 'connecting') {
      return
    }

    setConnectionStatus('connecting')
    onConnectionChange?.('connecting')

    try {
      const url = createSSEUrl(auditId, afterSequence)
      console.log(`[ResilientStream] Connecting to: ${url}`)

      abortControllerRef.current = new AbortController()

      const response = await fetch(url, {
        headers: {
          Accept: 'text/event-stream',
        },
        signal: abortControllerRef.current.signal,
      })

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      const reader = response.body?.getReader()
      if (!reader) {
        throw new Error('No response body reader')
      }

      readerRef.current = reader

      setConnectionStatus('connected')
      setConnectionAttempt(0)
      onConnectionChange?.('connected')
      resetHeartbeat()

      // 读取流
      const decoder = new TextDecoder()
      let buffer = ''
      let currentEvent: { eventType: string; data: any } | null = null

      while (!isCleanedUpRef.current) {
        const { done, value } = await reader.read()

        if (done) {
          console.log('[ResilientStream] Stream ended')
          break
        }

        // 解码并追加到缓冲区
        buffer += decoder.decode(value, { stream: true })

        // 处理缓冲区中的 SSE 消息
        const lines = buffer.split('\n')
        buffer = lines.pop() || '' // 保留最后一个不完整的行

        for (const line of lines) {
          if (!line.trim()) {
            // 空行表示一个事件结束
            if (currentEvent) {
              try {
                const backendEvent = transformBackendEvent(currentEvent.data)
                handleEvent(backendEvent)
              } catch (error) {
                console.error('[ResilientStream] Failed to transform event:', error)
              }
              currentEvent = null
            }
            continue
          }

          const parsed = parseSSEEvent(line)
          if (parsed) {
            if (parsed.eventType) {
              // 事件类型行
              if (!currentEvent) {
                currentEvent = { eventType: parsed.eventType, data: null }
              } else {
                currentEvent.eventType = parsed.eventType
              }
            } else if (parsed.data !== null) {
              // 数据行
              if (!currentEvent) {
                currentEvent = { eventType: '', data: parsed.data }
              } else {
                currentEvent.data = { ...currentEvent.data, ...parsed.data }
              }
            }
          }
        }
      }

      // 流正常结束
      if (!isCleanedUpRef.current) {
        setConnectionStatus('disconnected')
        onConnectionChange?.('disconnected')
      }
    } catch (error) {
      if (isCleanedUpRef.current || abortControllerRef.current?.signal.aborted) {
        // 用户主动断开，不是错误
        return
      }

      console.error('[ResilientStream] Connection error:', error)
      setConnectionStatus('disconnected')

      const err = error instanceof Error ? error : new Error('Connection failed')
      onError?.(err)

      // 尝试重连
      if (connectionAttempt < reconnectMaxAttempts) {
        const newAttempt = connectionAttempt + 1
        setConnectionAttempt(newAttempt)
        setConnectionStatus('reconnecting')
        onConnectionChange?.('reconnecting')

        const delay = calculateReconnectDelay(newAttempt - 1, reconnectBaseDelay, reconnectMaxDelay)
        console.log(`[ResilientStream] Reconnecting in ${delay}ms (attempt ${newAttempt}/${reconnectMaxAttempts})`)

        reconnectTimeoutRef.current = setTimeout(() => {
          connect()
        }, delay)
      } else {
        console.error('[ResilientStream] Max reconnection attempts reached')
        setConnectionStatus('failed')
        onConnectionChange?.('failed')
      }
    }
  }, [
    auditId,
    afterSequence,
    enabled,
    connectionStatus,
    connectionAttempt,
    onConnectionChange,
    onError,
    onEvent,
    reconnectMaxAttempts,
    reconnectBaseDelay,
    reconnectMaxDelay,
    resetHeartbeat,
    handleEvent,
  ])

  // 断开连接
  const disconnect = useCallback(() => {
    console.log('[ResilientStream] Disconnecting...')

    isCleanedUpRef.current = true

    // 取消请求
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
      abortControllerRef.current = null
    }

    // 取消读取器
    if (readerRef.current) {
      try {
        readerRef.current.cancel()
      } catch {
        // 忽略
      }
      readerRef.current = null
    }

    // 清除定时器
    if (heartbeatTimeoutRef.current) {
      clearTimeout(heartbeatTimeoutRef.current)
      heartbeatTimeoutRef.current = null
    }

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    setConnectionStatus('disconnected')
    onConnectionChange?.('disconnected')
  }, [onConnectionChange])

  // 重置连接（重置重连次数）
  const resetConnection = useCallback(() => {
    setConnectionAttempt(0)
    setConnectionStatus('disconnected')
  }, [])

  // 清理
  useEffect(() => {
    isCleanedUpRef.current = false

    return () => {
      disconnect()
    }
  }, [disconnect])

  // 自动连接
  useEffect(() => {
    if (auditId && enabled && connectionStatus === 'disconnected') {
      connect()
    }
  }, [auditId, enabled, connect])

  return {
    isConnected: connectionStatus === 'connected',
    isConnecting: connectionStatus === 'connecting' || connectionStatus === 'reconnecting',
    connectionStatus,
    connectionAttempt,
    connect,
    disconnect,
    resetConnection,
  }
}
