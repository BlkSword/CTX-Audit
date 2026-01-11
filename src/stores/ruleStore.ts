/**
 * 规则状态管理
 */

import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import type { Rule } from '@/shared/types'
import { rulesService } from '@/shared/api/services'
import type { RuleStats } from '@/shared/api/services/rules'

interface RuleState {
  rules: Rule[]
  selectedRule: Rule | null
  stats: RuleStats | null
  isLoading: boolean
  isSaving: boolean
  isDeleting: boolean
  error: string | null

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

export const useRuleStore = create<RuleState>()(
  devtools(
    (set) => ({
      rules: [],
      selectedRule: null,
      stats: null,
      isLoading: false,
      isSaving: false,
      isDeleting: false,
      error: null,

      loadRules: async () => {
        set({ isLoading: true, error: null })
        try {
          const rules = await rulesService.getRules()
          set({ rules, isLoading: false })
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载规则失败'
          set({ error: message, isLoading: false, rules: [] })
        }
      },

      loadRuleById: async (ruleId) => {
        set({ isLoading: true, error: null })
        try {
          const rule = await rulesService.getRuleById(ruleId)
          set({ selectedRule: rule, isLoading: false })
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载规则详情失败'
          set({ error: message, isLoading: false })
        }
      },

      loadStats: async () => {
        set({ isLoading: true, error: null })
        try {
          const stats = await rulesService.getRuleStats()
          set({ stats, isLoading: false })
        } catch (error) {
          const message = error instanceof Error ? error.message : '加载规则统计失败'
          set({ error: message, isLoading: false })
        }
      },

      createRule: async (rule) => {
        set({ isSaving: true, error: null })
        try {
          const newRule = await rulesService.createRule(rule)
          set(state => ({
            rules: [...state.rules, newRule],
            isSaving: false
          }))
          return newRule
        } catch (error) {
          const message = error instanceof Error ? error.message : '创建规则失败'
          set({ error: message, isSaving: false })
          throw error
        }
      },

      updateRule: async (ruleId, rule) => {
        set({ isSaving: true, error: null })
        try {
          const updatedRule = await rulesService.updateRule(ruleId, rule)
          set(state => ({
            rules: state.rules.map(r => r.id === ruleId ? updatedRule : r),
            selectedRule: state.selectedRule?.id === ruleId ? updatedRule : state.selectedRule,
            isSaving: false
          }))
          return updatedRule
        } catch (error) {
          const message = error instanceof Error ? error.message : '更新规则失败'
          set({ error: message, isSaving: false })
          throw error
        }
      },

      deleteRule: async (ruleId) => {
        set({ isDeleting: true, error: null })
        try {
          await rulesService.deleteRule(ruleId)
          set(state => ({
            rules: state.rules.filter(r => r.id !== ruleId),
            selectedRule: state.selectedRule?.id === ruleId ? null : state.selectedRule,
            isDeleting: false
          }))
        } catch (error) {
          const message = error instanceof Error ? error.message : '删除规则失败'
          set({ error: message, isDeleting: false })
          throw error
        }
      },

      setSelectedRule: (rule) => {
        set({ selectedRule: rule })
      },

      clearError: () => {
        set({ error: null })
      },
    }),
    { name: 'rule-store' }
  )
)
