/**
 * 提示词模板状态管理 (localStorage 持久化)
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import type { PromptTemplate, AgentType } from '@/shared/types'

// localStorage key
const TEMPLATES_KEY = 'ctx-audit-prompt-templates'

interface PromptTemplateState {
  // 状态
  templates: PromptTemplate[]
  isLoading: boolean

  // 操作方法
  loadTemplates: () => Promise<void>
  createTemplate: (template: Omit<PromptTemplate, 'id' | 'createdAt' | 'updatedAt'>) => Promise<void>
  updateTemplate: (id: string, template: Partial<PromptTemplate>) => Promise<void>
  deleteTemplate: (id: string) => Promise<void>
  getTemplateById: (id: string) => PromptTemplate | undefined
  getTemplatesByAgentType: (agentType: AgentType) => PromptTemplate[]
  getTemplatesByCategory: (category: 'system' | 'agent' | 'tool' | 'custom') => PromptTemplate[]

  // 清理
  reset: () => void
}

// LocalStorage 辅助函数
const loadFromStorage = <T>(key: string, defaultValue: T): T => {
  try {
    const item = localStorage.getItem(key)
    if (!item) return defaultValue
    return JSON.parse(item) as T
  } catch {
    return defaultValue
  }
}

const saveToStorage = <T>(key: string, value: T): void => {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch (error) {
    console.error(`Failed to save ${key}:`, error)
  }
}

// 系统默认模板
const SYSTEM_TEMPLATES: PromptTemplate[] = [
  {
    id: 'sys_orchestrator_zh',
    name: '编排者提示词（中文）',
    description: '用于 Orchestrator Agent 的中文提示词',
    category: 'system',
    language: 'zh',
    agentType: 'ORCHESTRATOR',
    template: `你是一个安全审计编排专家，负责协调整个代码安全审计流程。

## 任务
根据以下信息，制定审计计划并协调各个 Agent 工作：

## 项目信息
项目路径：{{project_path}}
项目类型：{{project_type}}

## 审计配置
审计类型：{{audit_type}}
最大迭代次数：{{max_iterations}}

## 你的职责
1. 分析项目结构，识别需要重点关注的安全区域
2. 将审计任务分解为子任务
3. 协调 Recon、Analysis、Verification 等 Agent
4. 汇总审计结果，生成最终报告

## 输出格式
请以 JSON 格式输出你的分析和计划。`,
    variables: [
      { name: 'project_path', description: '项目路径', type: 'string', required: true },
      { name: 'project_type', description: '项目类型', type: 'string', required: true },
      { name: 'audit_type', description: '审计类型', type: 'string', required: true },
      { name: 'max_iterations', description: '最大迭代次数', type: 'number', required: false },
    ],
    isSystem: true,
    isActive: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'sys_recon_zh',
    name: '侦察者提示词（中文）',
    description: '用于 Recon Agent 的中文提示词',
    category: 'system',
    language: 'zh',
    agentType: 'RECON',
    template: `你是一个代码侦察专家，负责收集项目的基本信息。

## 任务
分析项目结构，识别潜在的安全风险点。

## 项目信息
项目路径：{{project_path}}
目标文件：{{target_files}}

## 你需要收集
1. 项目结构和文件组织
2. 使用的框架和库
3. 用户输入处理点
4. 数据库交互点
5. API 端点
6. 认证/授权机制

## 输出格式
请以结构化的方式输出你的发现。`,
    variables: [
      { name: 'project_path', description: '项目路径', type: 'string', required: true },
      { name: 'target_files', description: '目标文件列表', type: 'array', required: false },
    ],
    isSystem: true,
    isActive: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  {
    id: 'sys_analysis_zh',
    name: '分析者提示词（中文）',
    description: '用于 Analysis Agent 的中文提示词',
    category: 'system',
    language: 'zh',
    agentType: 'ANALYSIS',
    template: `你是一个安全分析专家，负责检测代码中的安全漏洞。

## 任务
分析以下代码，检测潜在的安全漏洞。

## 代码信息
文件路径：{{file_path}}
代码内容：
\`\`\`
{{code_content}}
\`\`\`

## 重点关注
1. SQL 注入
2. XSS 跨站脚本
3. 命令注入
4. 路径遍历
5. SSRF
6. 硬编码密钥
7. 弱加密算法
8. 认证绕过
9. 权限绕过
10. IDOR

## 输出格式
对于每个发现的漏洞，请提供：
- 漏洞类型
- 严重程度（critical/high/medium/low）
- 位置（行号）
- 描述
- 修复建议`,
    variables: [
      { name: 'file_path', description: '文件路径', type: 'string', required: true },
      { name: 'code_content', description: '代码内容', type: 'string', required: true },
    ],
    isSystem: true,
    isActive: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
]

const initialState = {
  templates: [],
  isLoading: false,
}

export const usePromptTemplateStore = create<PromptTemplateState>()(
  devtools(
    (set, get) => ({
      ...initialState,

      // 加载模板
      loadTemplates: async () => {
        set({ isLoading: true })

        // 加载用户自定义模板
        const stored: PromptTemplate[] = loadFromStorage(TEMPLATES_KEY, [])

        // 合并系统模板（系统模板不存储在 localStorage 中）
        const allTemplates = [...SYSTEM_TEMPLATES, ...stored]

        set({ templates: allTemplates, isLoading: false })
      },

      // 创建模板
      createTemplate: async (template) => {
        const newTemplate: PromptTemplate = {
          ...template,
          id: `tpl_${Date.now()}`,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }

        // 只保存用户模板到 localStorage
        const current = get().templates.filter(t => !t.isSystem)
        const updated = [...current, newTemplate]
        saveToStorage(TEMPLATES_KEY, updated)

        // 更新状态
        set({ templates: [...SYSTEM_TEMPLATES, ...updated] })
      },

      // 更新模板
      updateTemplate: async (id, template) => {
        const currentTemplates = get().templates

        // 系统模板不允许更新
        const target = currentTemplates.find(t => t.id === id)
        if (target?.isSystem) {
          throw new Error('系统模板不允许修改')
        }

        // 更新用户模板
        const userTemplates = currentTemplates.filter(t => !t.isSystem)
        const updated = userTemplates.map(t =>
          t.id === id
            ? { ...t, ...template, updatedAt: new Date().toISOString() }
            : t
        )
        saveToStorage(TEMPLATES_KEY, updated)

        // 更新状态
        set({ templates: [...SYSTEM_TEMPLATES, ...updated] })
      },

      // 删除模板
      deleteTemplate: async (id) => {
        const currentTemplates = get().templates

        // 系统模板不允许删除
        const target = currentTemplates.find(t => t.id === id)
        if (target?.isSystem) {
          throw new Error('系统模板不允许删除')
        }

        // 删除用户模板
        const userTemplates = currentTemplates.filter(t => !t.isSystem && t.id !== id)
        saveToStorage(TEMPLATES_KEY, userTemplates)

        // 更新状态
        set({ templates: [...SYSTEM_TEMPLATES, ...userTemplates] })
      },

      // 获取单个模板
      getTemplateById: (id) => {
        return get().templates.find(t => t.id === id)
      },

      // 按 Agent 类型获取模板
      getTemplatesByAgentType: (agentType) => {
        return get().templates.filter(t => t.agentType === agentType && t.isActive)
      },

      // 按类别获取模板
      getTemplatesByCategory: (category) => {
        return get().templates.filter(t => t.category === category && t.isActive)
      },

      // 重置
      reset: () => {
        set(initialState)
      },
    }),
    {
      name: 'prompt-template-storage',
      partialize: (state: PromptTemplateState) => ({
        templates: state.templates.filter(t => !t.isSystem),
      }),
    }
  )
)
