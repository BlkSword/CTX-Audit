/**
 * multiProjectStore - 多项目并行审计状态管理
 *
 * 支持同时打开多个项目，并行进行审计
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import type { Project } from '@/shared/types'

// 本地类型定义（避免依赖后端类型）
export interface AuditTask {
  id: string
  project_id: string
  audit_type: string
  status: 'idle' | 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
  progress_percentage: number
  current_phase?: string
  created_at: string
  completed_at?: string
}

export interface AuditFinding {
  id: string
  task_id: string
  vulnerability_type: string
  severity: string
  title?: string
  description: string
  file_path?: string
  line_start?: number
  line_end?: number
  is_verified: boolean
  created_at: string
}

export interface AgentEvent {
  id: string
  audit_id: string
  type: string
  agent_type: string
  timestamp: number
  data: Record<string, unknown>
}

// 单个项目审计状态
export interface ProjectAuditState {
  project: Project
  currentAuditId: string | null
  auditTask: AuditTask | null
  findings: AuditFinding[]
  events: AgentEvent[]
  auditStatus: 'idle' | 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled'
  progress: number
  error: string | null
  isLoading: boolean
}

// 多项目状态接口
interface MultiProjectState {
  // 所有打开的项目 (使用数组而不是 Map 以便序列化)
  openProjects: ProjectAuditState[]

  // 当前激活的项目
  activeProjectId: string | null

  // 最大并行项目数
  maxConcurrentProjects: number

  // 操作方法
  openProject: (project: Project) => void
  closeProject: (projectId: string) => void
  setActiveProject: (projectId: string | null) => void

  // 获取项目状态
  getProjectState: (projectId: string) => ProjectAuditState | undefined
  getActiveProjectState: () => ProjectAuditState | undefined

  // 更新项目状态
  updateProjectState: (projectId: string, updates: Partial<Omit<ProjectAuditState, 'project'>>) => void

  // 批量操作
  closeAllProjects: () => void
  closeInactiveProjects: () => void

  // 统计信息
  getRunningAuditsCount: () => number
}

// 初始化多项目 store
export const useMultiProjectStore = create<MultiProjectState>()(
  devtools(
    persist(
      (set, get) => ({
        // 初始状态
        openProjects: [],
        activeProjectId: null,
        maxConcurrentProjects: 3,

        // 打开项目
        openProject: (project) => {
          set((state) => {
            // 检查是否已打开
            const existingIndex = state.openProjects.findIndex(p => p.project.uuid === project.uuid)

            if (existingIndex >= 0) {
              // 已打开，激活它
              return {
                activeProjectId: project.uuid,
              }
            }

            // 检查是否超过最大并行数
            if (state.openProjects.length >= state.maxConcurrentProjects) {
              // 找到最早的非运行项目并关闭
              const projectToCloseIndex = state.openProjects.findIndex(p => p.auditStatus !== 'running')

              if (projectToCloseIndex >= 0) {
                const newProjects = [...state.openProjects]
                newProjects.splice(projectToCloseIndex, 1)
                newProjects.push({
                  project,
                  currentAuditId: null,
                  auditTask: null,
                  findings: [],
                  events: [],
                  auditStatus: 'idle',
                  progress: 0,
                  error: null,
                  isLoading: false,
                })
                return {
                  openProjects: newProjects,
                  activeProjectId: project.uuid,
                }
              }
              // 所有项目都在运行，不打开新项目
              return state
            }

            // 添加新项目
            return {
              openProjects: [
                ...state.openProjects,
                {
                  project,
                  currentAuditId: null,
                  auditTask: null,
                  findings: [],
                  events: [],
                  auditStatus: 'idle',
                  progress: 0,
                  error: null,
                  isLoading: false,
                },
              ],
              activeProjectId: project.uuid,
            }
          })
        },

        // 关闭项目
        closeProject: (projectId) => {
          set((state) => {
            const newProjects = state.openProjects.filter(p => p.project.uuid !== projectId)

            // 如果关闭的是当前激活项目，切换到其他项目
            let newActiveProjectId = state.activeProjectId
            if (state.activeProjectId === projectId) {
              newActiveProjectId = newProjects.length > 0 ? newProjects[0].project.uuid : null
            }

            return {
              openProjects: newProjects,
              activeProjectId: newActiveProjectId,
            }
          })
        },

        // 设置激活项目
        setActiveProject: (projectId) => {
          set({ activeProjectId: projectId })
        },

        // 获取项目状态
        getProjectState: (projectId) => {
          return get().openProjects.find(p => p.project.uuid === projectId)
        },

        // 获取激活项目状态
        getActiveProjectState: () => {
          const { activeProjectId, openProjects } = get()
          if (!activeProjectId) return undefined
          return openProjects.find(p => p.project.uuid === activeProjectId)
        },

        // 更新项目状态
        updateProjectState: (projectId, updates) => {
          set((state) => ({
            openProjects: state.openProjects.map(p =>
              p.project.uuid === projectId ? { ...p, ...updates } : p
            ),
          }))
        },

        // 关闭所有项目
        closeAllProjects: () => {
          set({
            openProjects: [],
            activeProjectId: null,
          })
        },

        // 关闭非运行中的项目
        closeInactiveProjects: () => {
          set((state) => {
            const newProjects = state.openProjects.filter(p => p.auditStatus === 'running')

            let newActiveProjectId = state.activeProjectId
            if (state.activeProjectId && !newProjects.find(p => p.project.uuid === state.activeProjectId)) {
              newActiveProjectId = newProjects.length > 0 ? newProjects[0].project.uuid : null
            }

            return {
              openProjects: newProjects,
              activeProjectId: newActiveProjectId,
            }
          })
        },

        // 获取运行中的审计数量
        getRunningAuditsCount: () => {
          return get().openProjects.filter(p => p.auditStatus === 'running').length
        },
      }),
      {
        name: 'multi-project-storage',
        // 只持久化激活项目 ID
        partialize: (state) => ({
          activeProjectId: state.activeProjectId,
          maxConcurrentProjects: state.maxConcurrentProjects,
        }),
      }
    ),
    { name: 'multi-project-store' }
  )
)

// 便捷 hooks
export const useOpenProjects = () => useMultiProjectStore((state) => state.openProjects)
export const useActiveProjectId = () => useMultiProjectStore((state) => state.activeProjectId)
export const useActiveProjectState = () => useMultiProjectStore((state) => state.getActiveProjectState())
