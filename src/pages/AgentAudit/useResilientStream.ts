/**
 * Tauri Events Stream Hook
 *
 * 使用 Tauri Events 替代 SSE 进行实时事件流处理
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { listen } from '@tauri-apps/api/event'
import type { UnlistenFn } from '@tauri-apps/api/event'
import type { AgentEvent } from './api'
import type { ConnectionStatus } from './types'

export interface UseResilientStreamOptions {
  enabled?: boolean
  onEvent?: (event: AgentEvent) => void
  onError?: (error: Error) => void
  onConnectionChange?: (status: ConnectionStatus) => void
}

export interface UseResilientStreamReturn {
  isConnected: boolean
  isConnecting: boolean
  connectionStatus: ConnectionStatus
  connect: () => void
  disconnect: () => void
  resetConnection: () => void
}

/**
 * Tauri Events Stream Hook
 *
 * 使用 Tauri 的事件系统替代 SSE
 */
export function useResilientStream(
  auditId: string | null,
  _afterSequence: number,
  options: UseResilientStreamOptions = {}
): UseResilientStreamReturn {
  const {
    enabled = true,
    onEvent,
    onError,
    onConnectionChange,
  } = options

  // 连接状态
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('disconnected')

  // Refs
  const unlistenRef = useRef<UnlistenFn | null>(null)
  const isCleanedUpRef = useRef(false)

  // 处理单个事件
  const handleEvent = useCallback(
    (event: AgentEvent) => {
      // 触发回调
      if (onEvent) {
        onEvent(event)
      }
    },
    [onEvent]
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
      console.log(`[ResilientStream] Connecting to audit: ${auditId}`)

      // 使用 Tauri Events 监听 audit-event
      const unlisten = await listen<any>('audit-event', (event) => {
        const payload = event.payload as any
        // 过滤属于当前审计的事件
        if (payload.audit_id === auditId) {
          handleEvent(payload as AgentEvent)

          // 检查是否完成
          const eventType = (payload.event_type || '') as string
          const isComplete = eventType === 'complete' ||
                           eventType === 'agent_completed' ||
                           eventType === 'task_complete' ||
                           payload.data?.status === 'completed'

          if (isComplete) {
            console.log('[ResilientStream] Audit completed')
            setConnectionStatus('disconnected')
            onConnectionChange?.('disconnected')
          }
        }
      })

      unlistenRef.current = unlisten
      setConnectionStatus('connected')
      onConnectionChange?.('connected')

      console.log('[ResilientStream] Connected to Tauri events')
    } catch (error) {
      console.error('[ResilientStream] Connection error:', error)
      setConnectionStatus('failed')

      const err = error instanceof Error ? error : new Error('Connection failed')
      onError?.(err)
      onConnectionChange?.('failed')
    }
  }, [
    auditId,
    enabled,
    connectionStatus,
    onConnectionChange,
    onError,
    onEvent,
    handleEvent,
  ])

  // 断开连接
  const disconnect = useCallback(() => {
    console.log('[ResilientStream] Disconnecting...')

    isCleanedUpRef.current = true

    // 取消事件监听
    if (unlistenRef.current) {
      unlistenRef.current()
      unlistenRef.current = null
    }

    setConnectionStatus('disconnected')
    onConnectionChange?.('disconnected')
  }, [onConnectionChange])

  // 重置连接
  const resetConnection = useCallback(() => {
    setConnectionStatus('disconnected')
    isCleanedUpRef.current = false
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
  }, [auditId, enabled, connectionStatus, connect])

  return {
    isConnected: connectionStatus === 'connected',
    isConnecting: connectionStatus === 'connecting',
    connectionStatus,
    connect,
    disconnect,
    resetConnection,
  }
}
