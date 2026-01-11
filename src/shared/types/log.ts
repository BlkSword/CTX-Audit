
import type { AgentFinding, AgentType } from './index'

export type LogType =
  | 'thinking'
  | 'tool'
  | 'observation'
  | 'finding'
  | 'dispatch'
  | 'phase'
  | 'info'
  | 'error'
  | 'progress'
  | 'complete'
  | 'system' // New type for system logs

export interface LogItem {
  id: string
  type: LogType
  agent_type: AgentType | 'SYSTEM'
  timestamp: number
  content: string
  data?: Record<string, unknown>
  expanded?: boolean
  sequence?: number
  // 日志特有字段
  title?: string
  progressKey?: string
  isComplete?: boolean
  accumulatedContent?: string
  toolName?: string
  toolInput?: Record<string, unknown>
  toolOutput?: unknown
  finding?: Partial<AgentFinding>
}
