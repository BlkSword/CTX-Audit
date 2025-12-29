/**
 * 系统设置类型定义
 * 后端API对应：agent-service/app/api/settings.py
 */

// ==================== LLM 配置 ====================

export interface LLMConfig {
  id: string
  provider: string  // 自定义名称/标识
  model: string
  apiKey: string
  apiEndpoint?: string
  temperature?: number
  maxTokens?: number
  enabled: boolean
  isDefault: boolean
  createdAt?: string
  updatedAt?: string
}

// ==================== 嵌入模型配置 ====================

export interface EmbeddingConfig {
  provider: string
  model: string
  apiKey?: string
  baseUrl?: string
  dimension: number
}

// ==================== 分析参数配置 ====================

export interface AnalysisConfig {
  maxAnalyzeFiles: number
  maxFileSize: number
  llmConcurrency: number
  llmGapMs: number
  outputLanguage: string
  enableRAG: boolean
  enableVerification: boolean
  maxIterations: number
  timeoutSeconds: number
}

// ==================== Git 集成配置 ====================

export interface GitConfig {
  githubToken?: string
  gitlabToken?: string
  giteaToken?: string
  defaultBranch?: string
}

// ==================== Agent 配置 ====================

export interface AgentConfig {
  maxConcurrentAgents: number
  agentTimeout: number
  enableSandbox: boolean
  sandboxImage?: string
}

// ==================== 界面配置 ====================

export interface UIConfig {
  theme: string
  language: string
  fontSize: string
  showThinking: boolean
  autoScroll: boolean
  compactMode: boolean
}

// ==================== 完整系统配置 ====================

export interface SystemSettings {
  // 嵌入模型配置
  embedding?: EmbeddingConfig

  // 分析参数
  analysis?: AnalysisConfig

  // Git 集成
  git?: GitConfig

  // Agent 配置
  agent?: AgentConfig

  // 界面配置
  ui?: UIConfig
}

// ==================== 默认配置 ====================

export const DEFAULT_ANALYSIS_CONFIG: AnalysisConfig = {
  maxAnalyzeFiles: 0,
  maxFileSize: 204800,
  llmConcurrency: 3,
  llmGapMs: 2000,
  outputLanguage: 'zh-CN',
  enableRAG: true,
  enableVerification: false,
  maxIterations: 20,
  timeoutSeconds: 300,
}

export const DEFAULT_GIT_CONFIG: GitConfig = {
  defaultBranch: 'main',
}

export const DEFAULT_AGENT_CONFIG: AgentConfig = {
  maxConcurrentAgents: 3,
  agentTimeout: 300,
  enableSandbox: false,
  sandboxImage: 'python:3.11-slim',
}

export const DEFAULT_UI_CONFIG: UIConfig = {
  theme: 'auto',
  language: 'zh-CN',
  fontSize: 'medium',
  showThinking: true,
  autoScroll: true,
  compactMode: false,
}

export const DEFAULT_SYSTEM_SETTINGS: SystemSettings = {
  analysis: DEFAULT_ANALYSIS_CONFIG,
  git: DEFAULT_GIT_CONFIG,
  agent: DEFAULT_AGENT_CONFIG,
  ui: DEFAULT_UI_CONFIG,
}
