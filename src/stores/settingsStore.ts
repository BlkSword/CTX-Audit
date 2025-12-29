/**
 * 系统设置状态管理
 * 基于 Zustand
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import type {
  SystemSettings,
  LLMConfig,
} from '@/shared/types'
import {
  getLLMConfigs,
  createLLMConfig,
  updateLLMConfig,
  deleteLLMConfig,
  setDefaultLLMConfig,
  testLLMConfig,
  testLLMConnection,
  getSystemSettings,
  updateSystemSettings as updateSystemSettingsAPI,
  resetSystemSettings,
  getDefaultSettings,
} from '@/shared/api/settings-client'
import { DEFAULT_SYSTEM_SETTINGS as DEFAULTS } from '@/shared/types'

interface SettingsState {
  // LLM 配置
  llmConfigs: LLMConfig[]
  defaultLLMConfigId: string | null
  llmConfigsLoading: boolean
  llmConfigsError: string | null

  // 系统设置
  systemSettings: SystemSettings
  systemSettingsLoading: boolean
  systemSettingsError: string | null

  // 操作方法
  // LLM 配置
  loadLLMConfigs: () => Promise<void>
  createLLMConfig: (config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>) => Promise<void>
  updateLLMConfig: (id: string, config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>) => Promise<void>
  deleteLLMConfig: (id: string) => Promise<void>
  setDefaultLLMConfig: (id: string) => Promise<void>
  testLLMConfig: (id: string) => Promise<{ success: boolean; message?: string }>
  testLLMConnection: (config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>) => Promise<{ success: boolean; message?: string }>

  // 系统设置
  loadSystemSettings: () => Promise<void>
  updateSystemSettings: (settings: Partial<SystemSettings>) => Promise<void>
  resetSystemSettings: () => Promise<void>
  loadDefaultSettings: () => Promise<void>

  // 清理
  clearError: () => void
  reset: () => void
}

const initialState = {
  llmConfigs: [],
  defaultLLMConfigId: null,
  llmConfigsLoading: false,
  llmConfigsError: null,

  systemSettings: DEFAULTS,
  systemSettingsLoading: false,
  systemSettingsError: null,
}

export const useSettingsStore = create<SettingsState>()(
  devtools(
    persist(
      (set, get) => ({
        ...initialState,

        // ==================== LLM 配置操作 ====================

        loadLLMConfigs: async () => {
          set({ llmConfigsLoading: true, llmConfigsError: null })
          try {
            const response = await getLLMConfigs()
            set({
              llmConfigs: response.configs,
              defaultLLMConfigId: response.configs.find(c => c.isDefault)?.id || null,
              llmConfigsLoading: false,
            })
          } catch (error) {
            const message = error instanceof Error ? error.message : '加载 LLM 配置失败'
            set({ llmConfigsError: message, llmConfigsLoading: false })
            throw error
          }
        },

        createLLMConfig: async (config) => {
          try {
            await createLLMConfig(config)
            // 重新加载配置列表
            await get().loadLLMConfigs()
          } catch (error) {
            const message = error instanceof Error ? error.message : '创建 LLM 配置失败'
            set({ llmConfigsError: message })
            throw error
          }
        },

        updateLLMConfig: async (id, config) => {
          try {
            await updateLLMConfig(id, config)
            // 重新加载配置列表
            await get().loadLLMConfigs()
          } catch (error) {
            const message = error instanceof Error ? error.message : '更新 LLM 配置失败'
            set({ llmConfigsError: message })
            throw error
          }
        },

        deleteLLMConfig: async (id) => {
          try {
            await deleteLLMConfig(id)
            // 重新加载配置列表
            await get().loadLLMConfigs()
          } catch (error) {
            const message = error instanceof Error ? error.message : '删除 LLM 配置失败'
            set({ llmConfigsError: message })
            throw error
          }
        },

        setDefaultLLMConfig: async (id) => {
          try {
            await setDefaultLLMConfig(id)
            // 重新加载配置列表
            await get().loadLLMConfigs()
          } catch (error) {
            const message = error instanceof Error ? error.message : '设置默认配置失败'
            set({ llmConfigsError: message })
            throw error
          }
        },

        testLLMConfig: async (id) => {
          try {
            const result = await testLLMConfig(id)
            return result
          } catch (error) {
            return {
              success: false,
              message: error instanceof Error ? error.message : '测试连接失败',
            }
          }
        },

        testLLMConnection: async (config) => {
          try {
            const result = await testLLMConnection(config)
            return result
          } catch (error) {
            return {
              success: false,
              message: error instanceof Error ? error.message : '测试连接失败',
            }
          }
        },

        // ==================== 系统设置操作 ====================

        loadSystemSettings: async () => {
          set({ systemSettingsLoading: true, systemSettingsError: null })
          try {
            const settings = await getSystemSettings()
            set({
              systemSettings: { ...DEFAULTS, ...settings },
              systemSettingsLoading: false,
            })
          } catch (error) {
            const message = error instanceof Error ? error.message : '加载系统设置失败'
            set({ systemSettingsError: message, systemSettingsLoading: false })
            // 使用默认设置
            set({ systemSettings: DEFAULTS, systemSettingsLoading: false })
          }
        },

        updateSystemSettings: async (settings) => {
          try {
            await updateSystemSettingsAPI(settings)
            set((state) => ({
              systemSettings: { ...state.systemSettings, ...settings },
            }))
          } catch (error) {
            const message = error instanceof Error ? error.message : '更新系统设置失败'
            set({ systemSettingsError: message })
            throw error
          }
        },

        resetSystemSettings: async () => {
          try {
            await resetSystemSettings()
            set({ systemSettings: DEFAULTS })
          } catch (error) {
            const message = error instanceof Error ? error.message : '重置系统设置失败'
            set({ systemSettingsError: message })
            throw error
          }
        },

        loadDefaultSettings: async () => {
          try {
            const defaults = await getDefaultSettings()
            set({ systemSettings: defaults })
          } catch (error) {
            console.error('加载默认设置失败:', error)
          }
        },

        // ==================== 清理 ====================

        clearError: () => {
          set({
            llmConfigsError: null,
            systemSettingsError: null,
          })
        },

        reset: () => {
          set(initialState)
        },
      }),
      {
        name: 'settings-storage',
        // 只持久化部分设置（不包括敏感信息）
        partialize: (state) => ({
          systemSettings: {
            ...state.systemSettings,
            // 不持久化敏感字段
            git: {
              defaultBranch: state.systemSettings.git?.defaultBranch,
            },
          },
        }),
      }
    )
  )
)
