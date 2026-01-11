/**
 * Agent 相关类型定义
 */

// ==================== 基础类型 ====================

// 审计类型
export type AuditType = 'full' | 'quick' | 'targeted'

// 漏洞类型
export type VulnerabilityType =
  | 'sql_injection'
  | 'xss'
  | 'command_injection'
  | 'path_traversal'
  | 'ssrf'
  | 'xxe'
  | 'insecure_deserialization'
  | 'hardcoded_secret'
  | 'weak_crypto'
  | 'authentication_bypass'
  | 'authorization_bypass'
  | 'idor'

// 严重程度
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

// 审计状态
export type AuditStatus = 'pending' | 'running' | 'completed' | 'failed' | 'paused'

// Agent 类型
export type AgentType = 'ORCHESTRATOR' | 'RECON' | 'ANALYSIS' | 'VERIFICATION' | 'SYSTEM'

// Agent 状态（扩展版 - 支持 ReAct 模式）
export type AgentStatus = 'idle' | 'running' | 'completed' | 'failed' | 'waiting' | 'paused' | 'stopped' | 'stopping'

// Agent 执行状态（详细版）
export type AgentExecutionStatus = 'created' | 'running' | 'waiting' | 'paused' | 'completed' | 'failed' | 'stopped' | 'stopping'

// ==================== Agent 任务相关 ====================

export interface AuditStartRequest {
  project_id: string
  audit_type?: AuditType
  target_types?: VulnerabilityType[]
  config?: AuditConfig
}

export interface AuditConfig {
  llm_provider?: string
  llm_model?: string
  max_concurrent?: number
  enable_rag?: boolean
  enable_verification?: boolean
  max_iterations?: number
  timeout_seconds?: number
  // 新增配置项
  llm_max_retries?: number
  llm_timeout_seconds?: number
  tool_timeout_seconds?: number
  enable_circuit_breaker?: boolean
  enable_checkpoint?: boolean
  continue_on_tool_failure?: boolean
  checkpoint_interval?: number
}

export interface AuditStartResponse {
  audit_id: string
  status: AuditStatus
  estimated_time: number
}

export interface AuditProgress {
  current_stage: string
  completed_steps: number
  total_steps: number
  percentage: number
}

export interface AgentStatusMap {
  orchestrator: AgentStatus
  recon: AgentStatus
  analysis: AgentStatus
  verification: AgentStatus
}

export interface AuditStats {
  files_scanned: number
  findings_detected: number
  verified_vulnerabilities: number
}

export interface AuditStatusResponse {
  audit_id: string
  status: AuditStatus
  progress: AuditProgress
  agent_status: AgentStatusMap
  stats: AuditStats
  current_agent?: AgentType
  error?: string
}

// ==================== 漏洞相关 ====================

export interface Vulnerability {
  id: string
  vulnerability_type: VulnerabilityType
  severity: Severity
  confidence: number
  title: string
  description: string
  file_path: string
  line_number: number
  line_end?: number
  code_snippet: string
  remediation: string
  exploit_condition?: string
  agent_found: string
  verified: boolean
  is_false_positive?: boolean
  verification_method?: string
  poc?: string
  cwe?: string[]
  references?: string[]
  category?: string
  recommendation?: string
}

export interface VulnerabilityStats {
  total_vulnerabilities: number
  by_severity: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
}

export interface AuditResult {
  audit_id: string
  status: AuditStatus
  summary: VulnerabilityStats
  vulnerabilities: Vulnerability[]
}

// ==================== Agent 事件系统 ====================

export type AgentEventType =
  | 'thinking'       // Agent 思考过程
  | 'action'         // Agent 执行工具
  | 'observation'    // 工具执行结果
  | 'finding'        // 发现漏洞
  | 'decision'       // 决策（如切换 Agent）
  | 'error'          // 错误
  | 'complete'       // 任务完成
  | 'progress'       // 进度更新
  | 'agent_start'    // Agent 开始执行
  | 'agent_complete' // Agent 完成执行
  | 'tool_call'      // 工具调用
  | 'rag_retrieval'  // RAG 检索
  | 'status'         // 状态更新
  | 'connected'      // SSE 连接成功

export interface AgentEvent {
  id: string
  audit_id: string
  type: AgentEventType
  agent_type: AgentType
  timestamp: number
  data: EventData
}

export type EventData =
  | ThinkingData
  | ActionData
  | ObservationData
  | FindingData
  | DecisionData
  | ErrorData
  | CompleteData
  | ProgressData
  | AgentStartData
  | AgentCompleteData
  | ToolCallData
  | RagRetrievalData

export interface ThinkingData {
  thought: string
  reasoning?: string
  context?: Record<string, unknown>
}

export interface ActionData {
  action: string
  tool_name?: string
  parameters?: Record<string, unknown>
}

export interface ObservationData {
  observation: string
  result?: unknown
  summary?: string
}

export interface FindingData {
  finding: Vulnerability
  confidence: 'confirmed' | 'likely' | 'uncertain' | 'false_positive'
}

export interface DecisionData {
  decision: string
  reasoning: string
  next_agent?: AgentType
  next_action?: string
}

export interface ErrorData {
  error: string
  recoverable: boolean
  recovery_action?: string
}

export interface CompleteData {
  success: boolean
  summary: string
  findings_count: number
}

export interface ProgressData {
  stage: string
  percentage: number
  message: string
}

export interface AgentStartData {
  agent: AgentType
  stage: string
}

export interface AgentCompleteData {
  agent: AgentType
  success: boolean
  duration: number
  findings_count?: number
}

export interface ToolCallData {
  tool_name: string
  input: Record<string, unknown>
  status: 'started' | 'completed' | 'failed'
  output?: unknown
  error?: string
  duration?: number
}

export interface RagRetrievalData {
  query: string
  context_count: number
  relevant_info: string[]
}

// ==================== Agent 思考链 ====================

export interface AgentThought {
  timestamp: number
  thought: string
  agent?: AgentType
}

export interface AgentExecutionResult {
  agent: AgentType
  status: 'success' | 'error'
  result?: unknown
  thinking_chain: AgentThought[]
  duration_ms: number
  error?: string
}

// ==================== 审计流事件 ====================

export type AuditStreamEventType =
  | 'agent_thinking'
  | 'finding'
  | 'rag_retrieval'
  | 'progress'
  | 'verification'
  | 'complete'
  | 'error'
  | 'agent_start'
  | 'agent_complete'
  | 'tool_call'

export interface AuditStreamEvent {
  type: AuditStreamEventType
  timestamp: number
  audit_id?: string
  agent_type?: AgentType
  data?: unknown
}

// ==================== LLM 配置相关 ====================
// 从 settings.ts 导入，保持类型统一

export type { LLMConfig } from './settings'

// ==================== 提示词模板相关 ====================

export interface PromptTemplate {
  id: string
  name: string
  description: string
  category: 'system' | 'agent' | 'tool' | 'custom'
  language: 'zh' | 'en'
  agentType?: AgentType
  template: string
  variables: PromptVariable[]
  isSystem: boolean
  isActive: boolean
  createdAt: string
  updatedAt: string
}

export interface PromptVariable {
  name: string
  description: string
  type: 'string' | 'number' | 'boolean' | 'object' | 'array'
  required: boolean
  defaultValue?: unknown
}

// ==================== Agent 工具相关 ====================

export interface AgentTool {
  name: string
  description: string
  category: 'analysis' | 'external' | 'file' | 'verification' | 'collaboration' | 'rag'
  parameters: Record<string, ToolParameter>
  enabled: boolean
}

export interface ToolParameter {
  type: string
  description: string
  required: boolean
  default?: unknown
}

export interface ToolExecution {
  id: string
  toolName: string
  agentType: AgentType
  input: Record<string, unknown>
  output?: unknown
  status: 'pending' | 'running' | 'completed' | 'failed'
  duration?: number
  timestamp: string
}

// Agent 工具列表
export const AGENT_TOOLS: AgentTool[] = [
  // 文件操作工具
  {
    name: 'read_file',
    description: '读取文件内容',
    category: 'file',
    parameters: {
      file_path: { type: 'string', description: '文件路径', required: true },
    },
    enabled: true,
  },
  {
    name: 'list_files',
    description: '列出目录中的文件',
    category: 'file',
    parameters: {
      directory: { type: 'string', description: '目录路径', required: true },
      pattern: { type: 'string', description: '文件匹配模式', required: false },
    },
    enabled: true,
  },
  {
    name: 'search_files',
    description: '在文件中搜索内容',
    category: 'file',
    parameters: {
      query: { type: 'string', description: '搜索内容', required: true },
      directory: { type: 'string', description: '搜索目录', required: false },
    },
    enabled: true,
  },

  // 外部安全工具
  {
    name: 'run_semgrep',
    description: '运行 Semgrep 语义分析',
    category: 'external',
    parameters: {
      target: { type: 'string', description: '目标目录或文件', required: true },
      rules: { type: 'array', description: '规则集', required: false },
    },
    enabled: true,
  },
  {
    name: 'run_bandit',
    description: '运行 Bandit Python 安全扫描',
    category: 'external',
    parameters: {
      target: { type: 'string', description: '目标目录或文件', required: true },
    },
    enabled: true,
  },
  {
    name: 'run_gitleaks',
    description: '运行 Gitleaks 密钥检测',
    category: 'external',
    parameters: {
      target: { type: 'string', description: '目标目录', required: true },
    },
    enabled: true,
  },

  // 代码分析工具
  {
    name: 'analyze_code_structure',
    description: '分析代码结构',
    category: 'analysis',
    parameters: {
      file_path: { type: 'string', description: '文件路径', required: true },
    },
    enabled: true,
  },
  {
    name: 'get_call_graph',
    description: '获取函数调用图',
    category: 'analysis',
    parameters: {
      entry_function: { type: 'string', description: '入口函数', required: true },
      max_depth: { type: 'number', description: '最大深度', required: false },
    },
    enabled: true,
  },

  // 验证工具
  {
    name: 'verify_finding',
    description: '验证漏洞发现',
    category: 'verification',
    parameters: {
      file_path: { type: 'string', description: '文件路径', required: true },
      line_number: { type: 'number', description: '行号', required: true },
      vulnerability_type: { type: 'string', description: '漏洞类型', required: true },
    },
    enabled: true,
  },
  {
    name: 'run_code_in_sandbox',
    description: '在沙箱中运行代码',
    category: 'verification',
    parameters: {
      code: { type: 'string', description: '代码', required: true },
      language: { type: 'string', description: '语言', required: true },
    },
    enabled: true,
  },

  // RAG 工具
  {
    name: 'rag_search',
    description: 'RAG 语义搜索漏洞知识',
    category: 'rag',
    parameters: {
      query: { type: 'string', description: '搜索查询', required: true },
      top_k: { type: 'number', description: '返回结果数', required: false },
    },
    enabled: true,
  },

  // 协作工具
  {
    name: 'delegate_to_agent',
    description: '委托任务给其他 Agent',
    category: 'collaboration',
    parameters: {
      agent_type: { type: 'string', description: '目标 Agent 类型', required: true },
      task: { type: 'string', description: '任务描述', required: true },
    },
    enabled: true,
  },
  {
    name: 'finish',
    description: '完成任务',
    category: 'collaboration',
    parameters: {
      summary: { type: 'string', description: '总结', required: true },
      findings: { type: 'array', description: '发现的漏洞', required: false },
    },
    enabled: true,
  },
]

// ==================== Agent 树相关 ====================

export interface AgentNode {
  agent_id: string
  agent_name: string
  agent_type: string
  task: string
  status: 'running' | 'completed' | 'stopped' | 'error'
  created_at: string
  parent_id?: string
  children?: AgentNode[]
}

// ==================== Agent 状态详情（增强版） ====================

export interface AgentStateInfo {
  agent_id: string
  agent_name: string
  agent_type: string
  parent_id?: string
  task: string
  status: AgentExecutionStatus
  iteration: number
  max_iterations: number
  total_tokens: number
  tool_calls: number
  findings_count: number
  errors_count: number
  created_at: string
  started_at?: string
  finished_at?: string
  duration_seconds?: number
}

// ==================== ReAct 步骤 ====================

export interface ReActStep {
  iteration: number
  thought: string
  action: string
  action_input: Record<string, unknown>
  observation?: string
  success: boolean
  error?: string
  timestamp: string
}

export interface ReActLoopResult {
  steps: ReActStep[]
  total_iterations: number
  total_tokens: number
  total_tool_calls: number
  findings_count: number
  duration_seconds: number
  success: boolean
  error?: string
}

// ==================== 容错相关 ====================

export interface CircuitBreakerState {
  name: string
  state: 'closed' | 'open' | 'half_open'
  stats: {
    total_calls: number
    successful_calls: number
    failed_calls: number
    rejected_calls: number
    failure_rate: number
  }
  time_in_state: number
}

export interface RetryStats {
  attempts: number
  total_delay: number
  last_error?: string
}

export interface ResilienceConfig {
  enable_retry: boolean
  enable_circuit_breaker: boolean
  max_retries: number
  base_delay: number
  max_delay: number
  failure_threshold: number
  recovery_timeout: number
}

// ==================== 取消相关 ====================

export type CancelReason =
  | 'user_request'
  | 'timeout'
  | 'error'
  | 'parent_cancelled'
  | 'resource_limit'

export interface CancellationToken {
  is_cancelled: boolean
  reason?: CancelReason
  message?: string
}

export interface CancelTreeNode {
  agent_id: string
  agent_name: string
  is_cancelled: boolean
  cancel_reason?: CancelReason
  children: CancelTreeNode[]
}

// ==================== 智能去重相关 ====================

export type SimilarityLevel = 'identical' | 'very_high' | 'high' | 'medium' | 'low'

export interface FindingMatch {
  finding1: Vulnerability
  finding2: Vulnerability
  similarity: number
  similarity_type: SimilarityLevel
  match_reasons: string[]
}

export interface DedupResult {
  unique_findings: Vulnerability[]
  duplicate_count: number
  merged_count: number
  matches: FindingMatch[]
}

export interface DedupConfig {
  similarity_threshold: number
  enable_position_match: boolean
  enable_description_match: boolean
  enable_type_match: boolean
}

// ==================== Agent 执行统计 ====================

export interface AgentExecutionStats {
  agent_id: string
  agent_name: string
  agent_type: AgentType
  iterations: number
  tool_calls: number
  tokens_used: number
  duration_ms: number
  findings_count: number
  errors_count: number
  success: boolean
  error?: string
}

// ==================== 检查点相关 ====================

export interface AgentCheckpoint {
  checkpoint_id: string
  agent_id: string
  iteration: number
  timestamp: string
  state: Record<string, unknown>
  findings: Vulnerability[]
  metadata?: Record<string, unknown>
}

export interface CheckpointConfig {
  enabled: boolean
  interval_iterations: number
  on_tool_complete: boolean
  on_phase_complete: boolean
  max_checkpoints: number
}

// ==================== 任务交接（TaskHandoff） ====================

export interface TaskHandoff {
  from_agent: string
  to_agent: string
  summary: string
  work_completed: string[]
  key_findings: Vulnerability[]
  insights: string[]
  suggested_actions: SuggestedAction[]
  attention_points: string[]
  priority_areas: string[]
  context_data: Record<string, unknown>
  confidence: number
  timestamp: string
}

export interface SuggestedAction {
  type: string
  description: string
  priority: 'critical' | 'high' | 'medium' | 'low'
  target_files?: string[]
}

// ==================== Agent 事件（扩展版） ====================

export type ExtendedAgentEventType =
  | AgentEventType
  | 'llm_start'
  | 'llm_thought'
  | 'llm_decision'
  | 'llm_complete'
  | 'llm_action'
  | 'llm_observation'
  | 'thinking_start'
  | 'thinking_token'
  | 'thinking_end'
  | 'dispatch'
  | 'dispatch_complete'
  | 'finding_new'
  | 'finding_verified'
  | 'retry_attempt'
  | 'circuit_open'
  | 'checkpoint_created'

export interface ExtendedAgentEvent extends Omit<AgentEvent, 'type'> {
  type: ExtendedAgentEventType
  metadata?: {
    iteration?: number
    thought?: string
    decision?: string
    reason?: string
    action?: string
    action_input?: Record<string, unknown>
    observation?: string
    tokens_used?: number
    duration_ms?: number
    tool_name?: string
    tool_input?: Record<string, unknown>
    tool_output?: Record<string, unknown>
    tool_duration_ms?: number
    finding_id?: string
    confidence?: number
  }
}

