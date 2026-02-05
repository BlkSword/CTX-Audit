/**
 * 规则状态管理 (纯本地版本)
 *
 * 使用 localStorage 存储规则，不需要后端 API
 */

import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import type { Rule } from '@/shared/types'

interface RuleStats {
  total: number
  by_severity: Record<string, number>
  by_language: Record<string, number>
  by_category: Record<string, number>
}

interface RuleState {
  rules: Rule[]
  selectedRule: Rule | null
  stats: RuleStats | null

  // Actions
  loadRules: () => Promise<void>
  loadRuleById: (ruleId: string) => Promise<void>
  loadStats: () => Promise<void>
  createRule: (rule: Omit<Rule, 'enabled'>) => Promise<Rule>
  updateRule: (ruleId: string, rule: Omit<Rule, 'enabled'>) => Promise<Rule>
  deleteRule: (ruleId: string) => Promise<void>
  setSelectedRule: (rule: Rule | null) => void
  clearError: () => void
}

const RULES_KEY = 'ctx-audit-rules'

const defaultStats: RuleStats = {
  total: 0,
  by_severity: {},
  by_language: {},
  by_category: {},
}

// LocalStorage 辅助函数
const loadFromStorage = <T>(key: string, defaultValue: T): T => {
  try {
    const item = localStorage.getItem(key)
    return item ? JSON.parse(item) : defaultValue
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

// 计算规则统计
const calculateStats = (rules: Rule[]): RuleStats => {
  const stats: RuleStats = {
    total: rules.length,
    by_severity: {},
    by_language: {},
    by_category: {},
  }

  rules.forEach(rule => {
    stats.by_severity[rule.severity] = (stats.by_severity[rule.severity] || 0) + 1
    stats.by_language[rule.language] = (stats.by_language[rule.language] || 0) + 1
    if (rule.category) {
      stats.by_category[rule.category] = (stats.by_category[rule.category] || 0) + 1
    }
  })

  return stats
}

export const useRuleStore = create<RuleState>()(
  devtools(
    (set, get) => ({
      rules: [],
      selectedRule: null,
      stats: null,

      loadRules: async () => {
        const stored = loadFromStorage<Rule[]>(RULES_KEY, [])
        set({ rules: stored, stats: calculateStats(stored) })
      },

      loadRuleById: async (ruleId) => {
        const stored = loadFromStorage<Rule[]>(RULES_KEY, [])
        const rule = stored.find(r => r.id === ruleId)
        if (rule) {
          set({ selectedRule: rule })
        }
      },

      loadStats: async () => {
        const stored = loadFromStorage<Rule[]>(RULES_KEY, [])
        set({ stats: calculateStats(stored) })
      },

      createRule: async (rule) => {
        const newRule: Rule = {
          ...rule,
          id: `rule_${Date.now()}`,
          enabled: true,
        }
        const current = get().rules
        const updated = [...current, newRule]
        saveToStorage(RULES_KEY, updated)
        set({ rules: updated, stats: calculateStats(updated) })
        return newRule
      },

      updateRule: async (ruleId, rule) => {
        const current = get().rules
        const updated = current.map(r =>
          r.id === ruleId ? { ...r, ...rule } : r
        )
        saveToStorage(RULES_KEY, updated)
        set(state => ({
          rules: updated,
          selectedRule: state.selectedRule?.id === ruleId
            ? { ...state.selectedRule, ...rule }
            : state.selectedRule,
          stats: calculateStats(updated),
        }))
        return updated.find(r => r.id === ruleId)!
      },

      deleteRule: async (ruleId) => {
        const current = get().rules
        const updated = current.filter(r => r.id !== ruleId)
        saveToStorage(RULES_KEY, updated)
        set(state => ({
          rules: updated,
          selectedRule: state.selectedRule?.id === ruleId ? null : state.selectedRule,
          stats: calculateStats(updated),
        }))
      },

      setSelectedRule: (rule) => {
        set({ selectedRule: rule })
      },

      clearError: () => {
        // No errors in localStorage-only mode
      },
    }),
    {
      name: 'rule-store',
      partialize: (state: RuleState) => ({
        rules: state.rules,
      }),
    }
  )
)
