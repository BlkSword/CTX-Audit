/**
 * 规则管理页面
 */

import { useEffect, useState } from 'react'
import {
  Shield,
  Search,
  AlertTriangle,
  RefreshCw,
  Filter,
  Code,
  FileText,
  Plus,
  Edit,
  Trash2,
  Save,
  X,
} from 'lucide-react'
import { useRuleStore } from '@/stores/ruleStore'
import { useToast } from '@/hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import type { Rule } from '@/shared/types'

type RuleFormData = Omit<Rule, 'enabled'>

const emptyRule: RuleFormData = {
  id: '',
  name: '',
  description: '',
  severity: 'medium',
  language: 'all',
  category: '',
  cwe: '',
  pattern: '',
  query: '',
}

export function RulesPage() {
  const { rules, stats, isLoading, error, isSaving, isDeleting, loadRules, loadStats, createRule, updateRule, deleteRule, setSelectedRule } = useRuleStore()
  const toast = useToast()

  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [selectedRule, setSelectedRuleState] = useState<Rule | null>(null)
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [formData, setFormData] = useState<RuleFormData>(emptyRule)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      await Promise.all([loadRules(), loadStats()])
    } catch (err) {
      toast.error(`加载失败: ${err instanceof Error ? err.message : '未知错误'}`)
    }
  }

  const handleCreate = async () => {
    if (!formData.id || !formData.name || !formData.description) {
      toast.error('请填写必填字段（ID、名称、描述）')
      return
    }

    try {
      await createRule(formData)
      toast.success('规则创建成功')
      setIsCreateDialogOpen(false)
      setFormData(emptyRule)
      loadData()
    } catch (err) {
      toast.error(`创建失败: ${err instanceof Error ? err.message : '未知错误'}`)
    }
  }

  const handleUpdate = async () => {
    if (!selectedRule) return

    try {
      await updateRule(selectedRule.id, formData)
      toast.success('规则更新成功')
      setIsEditDialogOpen(false)
      setSelectedRuleState(null)
      setFormData(emptyRule)
      loadData()
    } catch (err) {
      toast.error(`更新失败: ${err instanceof Error ? err.message : '未知错误'}`)
    }
  }

  const handleDelete = async (ruleId: string, ruleName: string) => {
    if (!confirm(`确定要删除规则 "${ruleName}" 吗？此操作不可恢复！`)) return

    try {
      await deleteRule(ruleId)
      toast.success('规则删除成功')
      if (selectedRule?.id === ruleId) {
        setSelectedRuleState(null)
      }
      loadData()
    } catch (err) {
      toast.error(`删除失败: ${err instanceof Error ? err.message : '未知错误'}`)
    }
  }

  const openCreateDialog = () => {
    setFormData(emptyRule)
    setIsCreateDialogOpen(true)
  }

  const openEditDialog = (rule: Rule) => {
    setSelectedRuleState(rule)
    setFormData({
      id: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      language: rule.language,
      category: rule.category || '',
      cwe: rule.cwe || '',
      pattern: rule.pattern || '',
      query: rule.query || '',
    })
    setIsEditDialogOpen(true)
  }

  // 获取所有类别
  const categories = Array.from(new Set(rules.map((r) => r.category).filter(Boolean))) as string[]

  // 筛选规则
  const filteredRules = rules.filter((rule) => {
    const matchesSearch =
      searchQuery === '' ||
      rule.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.id.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesSeverity = severityFilter === 'all' || rule.severity === severityFilter
    const matchesCategory = categoryFilter === 'all' || rule.category === categoryFilter

    return matchesSearch && matchesSeverity && matchesCategory
  })

  const getSeverityBadgeVariant = (severity: string): "destructive" | "default" | "secondary" | "outline" => {
    switch (severity) {
      case 'critical':
      case 'high':
        return 'destructive'
      case 'medium':
        return 'default'
      default:
        return 'secondary'
    }
  }

  return (
    <div className="p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Shield className="w-6 h-6 text-primary" />
              安全规则管理
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              查看和管理代码安全扫描规则
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button onClick={loadData} disabled={isLoading} variant="outline" size="sm">
              {isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  加载中...
                </>
              ) : (
                <>
                  <RefreshCw className="w-4 h-4 mr-2" />
                  刷新
                </>
              )}
            </Button>
            <Button onClick={openCreateDialog} size="sm">
              <Plus className="w-4 h-4 mr-2" />
              新建规则
            </Button>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-4 bg-destructive/10 text-destructive rounded-lg">
            {error}
          </div>
        )}

        {/* 统计信息 */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">总规则数</p>
                  <p className="text-2xl font-bold mt-1">{stats.total}</p>
                </div>
                <Shield className="w-8 h-8 text-primary/20" />
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">严重/高危</p>
                  <p className="text-2xl font-bold text-red-600 mt-1">
                    {(stats.by_severity.critical || 0) + (stats.by_severity.high || 0)}
                  </p>
                </div>
                <AlertTriangle className="w-8 h-8 text-red-600/20" />
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">支持语言</p>
                  <p className="text-2xl font-bold mt-1">{Object.keys(stats.by_language).length}</p>
                </div>
                <Code className="w-8 h-8 text-blue-600/20" />
              </div>
            </Card>
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">类别数</p>
                  <p className="text-2xl font-bold mt-1">{Object.keys(stats.by_category).length}</p>
                </div>
                <FileText className="w-8 h-8 text-green-600/20" />
              </div>
            </Card>
          </div>
        )}

        {/* 筛选器 */}
        <div className="flex items-center gap-4 mb-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="搜索规则名称、描述或ID..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 max-w-md"
              />
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground">严重级别:</span>
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((level) => (
              <Button
                key={level}
                variant={severityFilter === level ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSeverityFilter(level)}
                className="text-xs"
              >
                {level === 'all' ? '全部' : level.charAt(0).toUpperCase() + level.slice(1)}
              </Button>
            ))}
          </div>

          {categories.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">类别:</span>
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="text-xs px-2 py-1 rounded border border-border bg-background"
              >
                <option value="all">全部</option>
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="text-sm text-muted-foreground ml-auto">
            显示 <span className="font-semibold">{filteredRules.length}</span> /
            <span className="font-semibold"> {rules.length}</span> 个规则
          </div>
        </div>

        {/* 规则列表 */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* 左侧规则列表 */}
          <div className="lg:col-span-1">
            <Card className="overflow-hidden">
              <ScrollArea className="h-[calc(100vh-420px)]">
                <div className="divide-y divide-border/40">
                  {filteredRules.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                      <Shield className="w-12 h-12 mb-3 opacity-20" />
                      <p className="text-sm">未找到匹配的规则</p>
                    </div>
                  ) : (
                    filteredRules.map((rule) => (
                      <div
                        key={rule.id}
                        className="p-4 hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div
                            className="flex-1 min-w-0 cursor-pointer"
                            onClick={() => setSelectedRuleState(rule)}
                          >
                            <div className="flex items-center gap-2 mb-1">
                              <Badge
                                variant={getSeverityBadgeVariant(rule.severity)}
                                className="text-[10px] uppercase"
                              >
                                {rule.severity}
                              </Badge>
                              <span className="text-xs text-muted-foreground font-mono">
                                {rule.id}
                              </span>
                            </div>
                            <h3 className="font-medium text-sm mb-1 truncate">{rule.name}</h3>
                            <p className="text-xs text-muted-foreground line-clamp-2">
                              {rule.description}
                            </p>
                            <div className="flex items-center gap-2 mt-2">
                              <Badge variant="outline" className="text-[10px]">
                                {rule.language}
                              </Badge>
                              {rule.category && (
                                <Badge variant="outline" className="text-[10px]">
                                  {rule.category}
                                </Badge>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => openEditDialog(rule)}
                            >
                              <Edit className="w-3 h-3" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-destructive"
                              onClick={() => handleDelete(rule.id, rule.name)}
                              disabled={isDeleting}
                            >
                              <Trash2 className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </Card>
          </div>

          {/* 右侧规则详情 */}
          <div className="lg:col-span-2">
            <Card className="p-6 h-[calc(100vh-420px)] overflow-auto no-scrollbar">
              {!selectedRule ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                  <Shield className="w-16 h-16 mb-4 opacity-20" />
                  <p className="text-lg font-medium">选择一个规则查看详情</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* 规则头部 */}
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <Badge
                          variant={getSeverityBadgeVariant(selectedRule.severity)}
                          className="text-sm uppercase"
                        >
                          {selectedRule.severity}
                        </Badge>
                        <Badge variant="outline" className="text-sm">
                          {selectedRule.language}
                        </Badge>
                        {selectedRule.category && (
                          <Badge variant="outline" className="text-sm">
                            {selectedRule.category}
                          </Badge>
                        )}
                      </div>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => openEditDialog(selectedRule)}
                      >
                        <Edit className="w-4 h-4 mr-2" />
                        编辑
                      </Button>
                    </div>
                    <h2 className="text-2xl font-bold mb-2">{selectedRule.name}</h2>
                    <p className="text-sm text-muted-foreground font-mono">
                      ID: {selectedRule.id}
                    </p>
                    {selectedRule.cwe && (
                      <p className="text-sm text-muted-foreground mt-1">
                        CWE: {selectedRule.cwe}
                      </p>
                    )}
                  </div>

                  {/* 描述 */}
                  <div>
                    <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                      <FileText className="w-4 h-4" />
                      描述
                    </h3>
                    <p className="text-sm text-muted-foreground">{selectedRule.description}</p>
                  </div>

                  {/* 检测模式 */}
                  {selectedRule.pattern && (
                    <div>
                      <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                        <Code className="w-4 h-4" />
                        检测模式
                      </h3>
                      <pre className="p-3 bg-muted rounded-lg text-xs font-mono overflow-x-auto no-scrollbar">
                        <code>{selectedRule.pattern}</code>
                      </pre>
                    </div>
                  )}

                  {/* AST 查询 */}
                  {selectedRule.query && (
                    <div>
                      <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                        <Code className="w-4 h-4" />
                        AST 查询
                      </h3>
                      <pre className="p-3 bg-muted rounded-lg text-xs font-mono overflow-x-auto no-scrollbar">
                        <code>{selectedRule.query}</code>
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>

      {/* 新建规则对话框 */}
      {isCreateDialogOpen && (
        <RuleDialog
          title="新建规则"
          formData={formData}
          setFormData={setFormData}
          onSave={handleCreate}
          onCancel={() => {
            setIsCreateDialogOpen(false)
            setFormData(emptyRule)
          }}
          isSaving={isSaving}
        />
      )}

      {/* 编辑规则对话框 */}
      {isEditDialogOpen && (
        <RuleDialog
          title="编辑规则"
          formData={formData}
          setFormData={setFormData}
          onSave={handleUpdate}
          onCancel={() => {
            setIsEditDialogOpen(false)
            setSelectedRuleState(null)
            setFormData(emptyRule)
          }}
          isSaving={isSaving}
          isEdit={true}
        />
      )}
    </div>
  )
}

function RuleDialog({
  title,
  formData,
  setFormData,
  onSave,
  onCancel,
  isSaving,
  isEdit = false,
}: {
  title: string
  formData: RuleFormData
  setFormData: (data: RuleFormData) => void
  onSave: () => void
  onCancel: () => void
  isSaving: boolean
  isEdit?: boolean
}) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-background rounded-lg shadow-lg max-w-2xl w-full max-h-[90vh] overflow-auto no-scrollbar">
        <div className="p-6 border-b border-border/40">
          <h2 className="text-xl font-bold">{title}</h2>
        </div>

        <div className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="id">规则 ID *</Label>
              <Input
                id="id"
                value={formData.id}
                onChange={(e) => setFormData({ ...formData, id: e.target.value })}
                placeholder="例如: my-custom-rule"
                disabled={isEdit}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="severity">严重级别 *</Label>
              <select
                id="severity"
                value={formData.severity}
                onChange={(e) => setFormData({ ...formData, severity: e.target.value as any })}
                className="w-full px-3 py-2 rounded border border-border bg-background"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="name">规则名称 *</Label>
            <Input
              id="name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="例如: My Custom Security Rule"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="description">描述 *</Label>
            <Textarea
              id="description"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="描述这个规则的用途..."
              rows={2}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="language">语言 *</Label>
              <select
                id="language"
                value={formData.language}
                onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                className="w-full px-3 py-2 rounded border border-border bg-background"
              >
                <option value="all">All</option>
                <option value="javascript">JavaScript</option>
                <option value="typescript">TypeScript</option>
                <option value="python">Python</option>
                <option value="java">Java</option>
                <option value="go">Go</option>
                <option value="rust">Rust</option>
                <option value="c">C</option>
                <option value="cpp">C++</option>
              </select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="category">类别</Label>
              <Input
                id="category"
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                placeholder="例如: injection"
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="cwe">CWE 编号</Label>
            <Input
              id="cwe"
              value={formData.cwe}
              onChange={(e) => setFormData({ ...formData, cwe: e.target.value })}
              placeholder="例如: CWE-78"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="pattern">检测模式 (正则表达式)</Label>
            <Textarea
              id="pattern"
              value={formData.pattern}
              onChange={(e) => setFormData({ ...formData, pattern: e.target.value })}
              placeholder="例如: (?i)eval\\s*\\("
              rows={3}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">输入正则表达式模式用于检测安全问题</p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="query">AST 查询 (可选)</Label>
            <Textarea
              id="query"
              value={formData.query}
              onChange={(e) => setFormData({ ...formData, query: e.target.value })}
              placeholder="(function_definition name: @name) @name"
              rows={3}
              className="font-mono text-xs"
            />
            <p className="text-xs text-muted-foreground">Tree-sitter 查询语言 (可选，优先于正则表达式)</p>
          </div>
        </div>

        <div className="p-6 border-t border-border/40 flex justify-end gap-2">
          <Button variant="outline" onClick={onCancel} disabled={isSaving}>
            取消
          </Button>
          <Button onClick={onSave} disabled={isSaving || !formData.id || !formData.name || !formData.description}>
            {isSaving ? (
              <>
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                保存中...
              </>
            ) : (
              <>
                <Save className="w-4 h-4 mr-2" />
                保存
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  )
}
