/**
 * 系统设置状态管理 (纯本地版本)
 *
 * 使用 localStorage 存储设置，LLM 测试通过 Tauri 后端
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import type {
  SystemSettings,
  LLMConfig,
} from '@/shared/types'
import { DEFAULT_SYSTEM_SETTINGS as DEFAULTS } from '@/shared/types'
import { tauriApi } from '@/shared/api/tauri-client'

// localStorage keys
const LLM_CONFIGS_KEY = 'ctx-audit-llm-configs'
const SYSTEM_SETTINGS_KEY = 'ctx-audit-system-settings'

interface SettingsState {
  // LLM 配置
  llmConfigs: LLMConfig[]
  defaultLLMConfigId: string | null

  // 系统设置
  systemSettings: SystemSettings

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

  // 清理
  clearError: () => void
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

const initialState = {
  llmConfigs: [],
  defaultLLMConfigId: null,
  systemSettings: DEFAULTS,
}

export const useSettingsStore = create<SettingsState>()(
  devtools(
    (set, get) => ({
      ...initialState,

      // ==================== LLM 配置操作 ====================

      loadLLMConfigs: async () => {
        const stored: LLMConfig[] = loadFromStorage(LLM_CONFIGS_KEY, [])
        set({
          llmConfigs: stored,
          defaultLLMConfigId: stored.find((c: LLMConfig) => c.isDefault)?.id || null,
        })
      },

      createLLMConfig: async (config) => {
        const newConfig: LLMConfig = {
          ...config,
          id: `llm_${Date.now()}`,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }
        const current = get().llmConfigs
        const updated = [...current, newConfig]
        saveToStorage(LLM_CONFIGS_KEY, updated)
        set({ llmConfigs: updated })
      },

      updateLLMConfig: async (id, config) => {
        const current = get().llmConfigs
        const updated = current.map(c =>
          c.id === id
            ? { ...c, ...config, updatedAt: new Date().toISOString() }
            : c
        )
        saveToStorage(LLM_CONFIGS_KEY, updated)
        set({ llmConfigs: updated })
      },

      deleteLLMConfig: async (id) => {
        const current = get().llmConfigs
        const updated = current.filter(c => c.id !== id)
        saveToStorage(LLM_CONFIGS_KEY, updated)

        // 如果删除的是默认配置，清除默认设置
        const defaultId = get().defaultLLMConfigId
        if (defaultId === id) {
          set({ llmConfigs: updated, defaultLLMConfigId: null })
        } else {
          set({ llmConfigs: updated })
        }
      },

      setDefaultLLMConfig: async (id) => {
        const current = get().llmConfigs
        const updated = current.map(c =>
          c.id === id ? { ...c, isDefault: true } : { ...c, isDefault: false }
        )
        saveToStorage(LLM_CONFIGS_KEY, updated)
        set({ llmConfigs: updated, defaultLLMConfigId: id })
      },

      testLLMConfig: async (id) => {
        try {
          return await tauriApi.testLLMConfig(id)
        } catch (error) {
          console.error('LLM config test failed:', error)
          return {
            success: false,
            message: error instanceof Error ? error.message : '测试失败'
          }
        }
      },

      testLLMConnection: async (config) => {
        try {
          return await tauriApi.testLLMConnection(config)
        } catch (error) {
          console.error('LLM connection test failed:', error)
          return {
            success: false,
            message: error instanceof Error ? error.message : '测试失败'
          }
        }
      },

      // ==================== 系统设置操作 ====================

      loadSystemSettings: async () => {
        const stored = loadFromStorage(SYSTEM_SETTINGS_KEY, DEFAULTS)
        set({ systemSettings: { ...DEFAULTS, ...stored } })
      },

      updateSystemSettings: async (settings) => {
        const current = get().systemSettings
        const updated = { ...current, ...settings }
        saveToStorage(SYSTEM_SETTINGS_KEY, updated)
        set({ systemSettings: updated })
      },

      resetSystemSettings: async () => {
        saveToStorage(SYSTEM_SETTINGS_KEY, DEFAULTS)
        set({ systemSettings: DEFAULTS })
      },

      // ==================== 清理 ====================

      clearError: () => {
        // No errors in localStorage-only mode
      },

      reset: () => {
        set(initialState)
      },
    }),
    {
      name: 'settings-storage',
      partialize: (state: SettingsState) => ({
        systemSettings: state.systemSettings,
      }),
    }
  )
)
