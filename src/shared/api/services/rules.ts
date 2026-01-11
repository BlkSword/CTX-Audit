/**
 * 规则服务 API
 */

import { api } from '../client'
import type { Rule } from '@/shared/types'

export interface RuleStats {
  total: number
  by_severity: Record<string, number>
  by_language: Record<string, number>
  by_category: Record<string, number>
}

export class RulesService {
  /**
   * 获取所有规则列表
   */
  async getRules(): Promise<Rule[]> {
    return api.get<Rule[]>('/api/rules')
  }

  /**
   * 根据ID获取单个规则详情
   */
  async getRuleById(ruleId: string): Promise<Rule> {
    return api.get<Rule>(`/api/rules/${ruleId}`)
  }

  /**
   * 获取规则统计信息
   */
  async getRuleStats(): Promise<RuleStats> {
    return api.get<RuleStats>('/api/rules/stats')
  }

  /**
   * 创建新规则
   */
  async createRule(rule: Omit<Rule, 'enabled'>): Promise<Rule> {
    return api.post<Rule>('/api/rules', rule)
  }

  /**
   * 更新规则
   */
  async updateRule(ruleId: string, rule: Omit<Rule, 'enabled'>): Promise<Rule> {
    return api.post<Rule>(`/api/rules/${ruleId}`, rule)
  }

  /**
   * 删除规则
   */
  async deleteRule(ruleId: string): Promise<{ success: boolean; message: string }> {
    return api.delete<{ success: boolean; message: string }>(`/api/rules/${ruleId}`)
  }
}

export const rulesService = new RulesService()
