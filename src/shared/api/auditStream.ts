/**
 * Agent 审计流式事件处理
 *
 * 使用 SSE (Server-Sent Events) 实时接收审计事件
 */

export type StreamEventType =
  // LLM 相关
  | 'llm_start'
  | 'llm_thought'
  | 'llm_decision'
  | 'llm_action'
  | 'llm_complete'
  | 'thinking'
  // 工具调用相关
  | 'tool_call_start'
  | 'tool_call_end'
  | 'tool_call'
  | 'tool_result'
  // 阶段相关
  | 'phase_start'
  | 'phase_complete'
  // 发现相关
  | 'finding_new'
  | 'finding_verified'
  // 状态相关
  | 'info'
  | 'warning'
  | 'error'
  | 'status'
  // 任务相关
  | 'task_start'
  | 'task_complete'
  | 'task_error'
  | 'task_cancel'
  // 心跳
  | 'heartbeat'
  // 连接状态
  | 'connected'

export interface StreamEventData {
  id?: string
  type: StreamEventType
  timestamp: string
  sequence: number
  task_id?: string
  phase?: string
  message?: string
  agent_type?: string
  tool_name?: string
  tool_input?: Record<string, unknown>
  tool_output?: Record<string, unknown>
  tool_duration_ms?: number
  finding_id?: string
  tokens_used?: number
  metadata?: Record<string, unknown>
  // 附加字段
  data?: Record<string, unknown>
  status?: string
  error?: string
}

export type StreamEventCallback = (event: StreamEventData) => void

export interface StreamOptions {
  onThinking?: (message: string) => void
  onToolCall?: (toolName: string, input: Record<string, unknown>) => void
  onToolResult?: (toolName: string, output: unknown, duration: number) => void
  onFinding?: (finding: Record<string, unknown>) => void
  onStatus?: (status: string) => void
  onError?: (error: string) => void
  onComplete?: () => void
  onEvent?: StreamEventCallback
}

/**
 * Agent 流式事件处理器
 * 支持事件节流和批处理优化
 */
export class AuditStreamHandler {
  private auditId: string
  private eventSource: EventSource | null = null
  private options: StreamOptions
  private reconnectAttempts = 0
  private maxReconnectAttempts = 5
  private reconnectDelay = 1000
  private isConnected = false
  private isDisconnecting = false
  private lastSequence = 0

  // 节流优化
  private throttleTimers: Map<string, ReturnType<typeof setTimeout>> = new Map()
  private readonly throttleIntervals: Record<string, number> = {
    thinking: 50,   // thinking 事件节流 50ms
    llm_thought: 50,
    tool_call: 100,  // 工具调用节流 100ms
    tool_result: 100,
  }

  constructor(auditId: string, options: StreamOptions = {}) {
    this.auditId = auditId
    this.options = options
  }

  /**
   * 节流包装函数
   */
  private throttle<T extends (...args: any[]) => void>(
    key: string,
    fn: T,
    delay: number
  ): T {
    return ((...args: Parameters<T>) => {
      const existingTimer = this.throttleTimers.get(key)
      if (existingTimer) {
        clearTimeout(existingTimer)
      }

      const timer = setTimeout(() => {
        fn(...args)
        this.throttleTimers.delete(key)
      }, delay)

      this.throttleTimers.set(key, timer)
    }) as T
  }

  /**
   * 清理所有节流定时器
   */
  private clearThrottleTimers(): void {
    this.throttleTimers.forEach(timer => clearTimeout(timer))
    this.throttleTimers.clear()
  }

  /**
   * 开始监听事件流
   */
  connect(afterSequence = 0): void {
    this.isDisconnecting = false
    this.lastSequence = afterSequence

    if (this.isConnected) {
      return
    }

    const token = localStorage.getItem('access_token')
    if (!token) {
      this.options.onError?.('未登录')
      return
    }

    const url = `/api/audit/${this.auditId}/stream?after_sequence=${afterSequence}`
    this.eventSource = new EventSource(url, {
      withCredentials: true,
    })

    this.eventSource.onopen = () => {
      console.log(`[AuditStream] Connected to audit ${this.auditId}`)
      this.isConnected = true
      this.reconnectAttempts = 0
    }

    this.eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        this.handleEvent(data)
      } catch (e) {
        console.error('[AuditStream] Failed to parse event:', e)
      }
    }

    this.eventSource.onerror = (error) => {
      console.error('[AuditStream] Connection error:', error)
      this.isConnected = false

      if (!this.isDisconnecting && this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++
        console.log(`[AuditStream] Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`)
        setTimeout(() => {
          if (!this.isDisconnecting) {
            this.connect(this.lastSequence)
          }
        }, this.reconnectDelay * this.reconnectAttempts)
      } else {
        this.options.onError?.('连接失败')
      }
    }

    // 监听特定事件类型
    this.setupEventListeners()
  }

  /**
   * 设置特定事件监听器（带节流优化）
   */
  private setupEventListeners(): void {
    if (!this.eventSource) return

    // LLM 思考事件 - 使用节流
    const throttledThinking = this.throttle('thinking', (message: string) => {
      this.options.onThinking?.(message)
    }, this.throttleIntervals.thinking)

    this.eventSource.addEventListener('thinking', (evt: MessageEvent) => {
      const data = JSON.parse(evt.data)
      throttledThinking(data.message || '')
    })

    this.eventSource.addEventListener('llm_thought', (event: MessageEvent) => {
      const data = JSON.parse(event.data)
      throttledThinking(data.message || '')
    })

    // 工具调用事件
    this.eventSource.addEventListener('tool_call', (event: MessageEvent) => {
      const data = JSON.parse(event.data)
      this.options.onToolCall?.(
        data.tool_name || 'unknown',
        data.tool_input || {}
      )
      this.lastSequence = data.sequence
    })

    this.eventSource.addEventListener('tool_result', (event: MessageEvent) => {
      const data = JSON.parse(event.data)
      this.options.onToolResult?.(
        data.tool_name || 'unknown',
        data.tool_output,
        data.tool_duration_ms || 0
      )
      this.lastSequence = data.sequence
    })

    // 发现事件
    this.eventSource.addEventListener('finding_new', (event: MessageEvent) => {
      const data = JSON.parse(event.data)
      this.options.onFinding?.(data.metadata || {})
      this.lastSequence = data.sequence
    })

    this.eventSource.addEventListener('finding_verified', (event: MessageEvent) => {
      const data = JSON.parse(event.data)
      this.options.onFinding?.({ ...(data.metadata || {}), is_verified: true })
      this.lastSequence = data.sequence
    })

    // 状态事件
    this.eventSource.addEventListener('status', (event: MessageEvent) => {
      const data = JSON.parse(event.data)
      const status = data.metadata?.status || data.status
      if (status === 'completed') {
        this.options.onComplete?.()
      } else {
        this.options.onStatus?.(status)
      }
      this.lastSequence = data.sequence
    })

    this.eventSource.addEventListener('task_complete', (_evt: MessageEvent) => {
      this.options.onComplete?.()
    })

    // 错误事件
    this.eventSource.addEventListener('error', (event: MessageEvent) => {
      const data = JSON.parse(event.data)
      this.options.onError?.(data.error || data.message || '未知错误')
    })
  }

  /**
   * 处理通用事件
   */
  private handleEvent(data: StreamEventData): void {
    this.lastSequence = data.sequence || this.lastSequence
    this.options.onEvent?.(data)
  }

  /**
   * 断开连接
   */
  disconnect(): void {
    this.isDisconnecting = true
    this.isConnected = false

    // 清理节流定时器
    this.clearThrottleTimers()

    if (this.eventSource) {
      this.eventSource.close()
      this.eventSource = null
    }

    this.reconnectAttempts = 0
  }

  /**
   * 检查是否已连接
   */
  get connected(): boolean {
    return this.isConnected
  }

  /**
   * 获取最新序列号
   */
  getLatestSequence(): number {
    return this.lastSequence
  }
}

/**
 * 创建审计流式处理器
 */
export function createAuditStream(
  auditId: string,
  options: StreamOptions = {}
): AuditStreamHandler {
  return new AuditStreamHandler(auditId, options)
}
