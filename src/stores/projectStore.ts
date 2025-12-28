/**
 * 项目状态管理
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import type { Project } from '@/shared/types'
import { projectService } from '@/shared/api/services'

interface ProjectState {
  projects: Project[]
  currentProject: Project | null
  isLoading: boolean
  isInitiallyLoaded: boolean  // 是否已执行过初始加载
  error: string | null

  // Actions
  loadProjects: () => Promise<void>
  createProject: (name: string, zipFile: File, onProgress?: (progress: number) => void) => Promise<Project>
  deleteProject: (id: number) => Promise<void>
  setCurrentProject: (project: Project | null) => void
  clearError: () => void
}

export const useProjectStore = create<ProjectState>()(
  devtools(
    persist(
      (set) => ({
        projects: [],
        currentProject: null,
        isLoading: false,
        isInitiallyLoaded: false,
        error: null,

        loadProjects: async () => {
          set({ isLoading: true, error: null })
          try {
            const projects = await projectService.listProjects()
            set({ projects, isLoading: false, isInitiallyLoaded: true })
          } catch (error) {
            const message = error instanceof Error ? error.message : '加载项目失败'
            set({ error: message, isLoading: false, isInitiallyLoaded: true })
          }
        },

        createProject: async (name, zipFile, onProgress) => {
          set({ isLoading: true, error: null })
          try {
            const project = await projectService.uploadProject(name, zipFile, onProgress)
            set(state => ({
              projects: [project, ...state.projects],
              isLoading: false
            }))
            return project
          } catch (error) {
            const message = error instanceof Error ? error.message : '创建项目失败'
            set({ error: message, isLoading: false })
            throw error
          }
        },

        deleteProject: async (id) => {
          set({ isLoading: true, error: null })
          try {
            // 先获取当前项目列表，找到对应的 uuid
            let projectUuid: string | null = null
            set(state => {
              const project = state.projects.find(p => p.id === id)
              if (project) {
                projectUuid = project.uuid
              }
              return state
            })

            if (!projectUuid) {
              throw new Error('项目不存在')
            }

            await projectService.deleteProject(projectUuid)
            set(state => ({
              projects: state.projects.filter(p => p.id !== id),
              currentProject: state.currentProject?.id === id ? null : state.currentProject,
              isLoading: false
            }))
          } catch (error) {
            const message = error instanceof Error ? error.message : '删除项目失败'
            set({ error: message, isLoading: false })
            throw error
          }
        },

        setCurrentProject: (project) => {
          set({ currentProject: project })
        },

        clearError: () => {
          set({ error: null })
        },
      }),
      {
        name: 'project-storage',
        partialize: (state) => ({
          currentProject: state.currentProject,
        }),
      }
    ),
    { name: 'project-store' }
  )
)
