/**
 * 设置 API 客户端
 */

import type { SystemSettings, LLMConfig } from '@/shared/types'

export interface SettingsAPIConfig {
  baseURL: string
  timeout?: number
}

export class SettingsAPIClient {
  private config: SettingsAPIConfig

  constructor(config?: Partial<SettingsAPIConfig>) {
    this.config = {
      baseURL: config?.baseURL || import.meta.env.VITE_AGENT_API_BASE_URL || 'http://localhost:8001',
      timeout: config?.timeout || 30000,
    }
  }

  private async request<T>(
    method: string,
    path: string,
    data?: unknown
  ): Promise<T> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout)

    try {
      const response = await fetch(`${this.config.baseURL}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: data !== undefined ? JSON.stringify(data) : undefined,
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        const error = await response.json().catch(() => ({ message: '请求失败' }))
        throw new Error(error.message || '请求失败')
      }

      return response.json()
    } catch (error) {
      clearTimeout(timeoutId)
      throw error
    }
  }

  private get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path)
  }

  private post<T>(path: string, data?: unknown): Promise<T> {
    return this.request<T>('POST', path, data)
  }

  private put<T>(path: string, data?: unknown): Promise<T> {
    return this.request<T>('PUT', path, data)
  }

  private delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path)
  }

  // ==================== LLM 配置 ====================

  async getLLMConfigs(): Promise<{ configs: LLMConfig[] }> {
    return this.get<{ configs: LLMConfig[] }>('/api/settings/llm/configs')
  }

  // 将驼峰命名转换为下划线命名（匹配后端API）
  private toSnakeCase(config: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(config)) {
      const snakeKey = key.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`)
      result[snakeKey] = value
    }
    return result
  }

  async createLLMConfig(config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<{ id: string; status: string }> {
    return this.post('/api/settings/llm/configs', this.toSnakeCase(config))
  }

  async updateLLMConfig(configId: string, config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<{ id: string; status: string }> {
    return this.put(`/api/settings/llm/configs/${configId}`, this.toSnakeCase(config))
  }

  async deleteLLMConfig(configId: string): Promise<{ status: string }> {
    return this.delete(`/api/settings/llm/configs/${configId}`)
  }

  async setDefaultLLMConfig(configId: string): Promise<{ status: string }> {
    return this.post(`/api/settings/llm/configs/${configId}/default`)
  }

  async testLLMConfig(configId: string): Promise<{ success: boolean; message?: string }> {
    return this.post(`/api/settings/llm/configs/${configId}/test`)
  }

  async testLLMConnection(config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<{ success: boolean; message?: string }> {
    return this.post('/api/settings/llm/configs/test-connection', this.toSnakeCase(config))
  }

  // ==================== 系统设置 ====================

  async getSystemSettings(): Promise<SystemSettings> {
    return this.get<SystemSettings>('/api/settings/system')
  }

  async updateSystemSettings(settings: Partial<SystemSettings>): Promise<{ status: string }> {
    return this.put('/api/settings/system', settings)
  }

  async resetSystemSettings(): Promise<{ status: string }> {
    return this.post('/api/settings/system/reset')
  }

  // ==================== 默认配置 ====================

  async getDefaultSettings(): Promise<SystemSettings> {
    return this.get<SystemSettings>('/api/settings/defaults')
  }
}

// 单例实例
let settingsClientInstance: SettingsAPIClient | null = null

export function getSettingsClient(): SettingsAPIClient {
  if (!settingsClientInstance) {
    settingsClientInstance = new SettingsAPIClient()
  }
  return settingsClientInstance
}

// 导出便捷函数
const settingsApi = getSettingsClient()

export async function getLLMConfigs() {
  return settingsApi.getLLMConfigs()
}

export async function createLLMConfig(config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>) {
  return settingsApi.createLLMConfig(config)
}

export async function updateLLMConfig(configId: string, config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>) {
  return settingsApi.updateLLMConfig(configId, config)
}

export async function deleteLLMConfig(configId: string) {
  return settingsApi.deleteLLMConfig(configId)
}

export async function setDefaultLLMConfig(configId: string) {
  return settingsApi.setDefaultLLMConfig(configId)
}

export async function testLLMConfig(configId: string) {
  return settingsApi.testLLMConfig(configId)
}

export async function testLLMConnection(config: Omit<LLMConfig, 'id' | 'createdAt' | 'updatedAt'>) {
  return settingsApi.testLLMConnection(config)
}

export async function getSystemSettings() {
  return settingsApi.getSystemSettings()
}

export async function updateSystemSettings(settings: Partial<SystemSettings>) {
  return settingsApi.updateSystemSettings(settings)
}

export async function resetSystemSettings() {
  return settingsApi.resetSystemSettings()
}

export async function getDefaultSettings() {
  return settingsApi.getDefaultSettings()
}
