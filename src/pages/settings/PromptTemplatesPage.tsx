/**
 * 提示词模板管理页面
 */

import { useEffect, useState } from 'react'
import {
  Plus,
  Trash2,
  Search,
  Code,
  FileText,
  Bot,
  Wrench,
  Eye,
} from 'lucide-react'
import { useAgentStore } from '@/stores/agentStore'
import { useUIStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { ScrollArea } from '@/components/ui/scroll-area'
import type { PromptTemplate, AgentType } from '@/shared/types'

const CATEGORIES = [
  { value: 'all', label: '全部' },
  { value: 'system', label: '系统' },
  { value: 'agent', label: 'Agent' },
  { value: 'tool', label: '工具' },
  { value: 'custom', label: '自定义' },
]

const AGENT_TYPES: { value: AgentType | null; label: string }[] = [
  { value: null, label: '全部' },
  { value: 'ORCHESTRATOR', label: '编排者' },
  { value: 'RECON', label: '侦察者' },
  { value: 'ANALYSIS', label: '分析者' },
  { value: 'VERIFICATION', label: '验证者' },
]

export function PromptTemplatesPage() {
  const { addLog } = useUIStore()

  const {
    promptTemplates,
    loadPromptTemplates,
    createPromptTemplate,
    deletePromptTemplate,
  } = useAgentStore()

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isViewDialogOpen, setIsViewDialogOpen] = useState(false)
  const [viewingTemplate, setViewingTemplate] = useState<PromptTemplate | null>(null)

  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [agentTypeFilter, setAgentTypeFilter] = useState<AgentType | null>(null)

  // 新建模板表单状态
  const [newTemplate, setNewTemplate] = useState<{
    name: string
    description: string
    category: 'system' | 'agent' | 'tool' | 'custom'
    language: 'zh' | 'en'
    agentType?: AgentType
    template: string
    isActive: boolean
  }>({
    name: '',
    description: '',
    category: 'custom',
    language: 'zh',
    agentType: undefined,
    template: '',
    isActive: true,
  })

  useEffect(() => {
    loadPromptTemplates(categoryFilter === 'all' ? undefined : categoryFilter)
  }, [categoryFilter, loadPromptTemplates])

  // 过滤模板
  const filteredTemplates = promptTemplates.filter((template) => {
    const matchesSearch =
      searchQuery === '' ||
      template.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.description.toLowerCase().includes(searchQuery.toLowerCase())

    const matchesAgentType =
      !agentTypeFilter || template.agentType === agentTypeFilter

    return matchesSearch && matchesAgentType
  })

  // 创建新模板
  const handleCreateTemplate = async () => {
    try {
      await createPromptTemplate({
        ...newTemplate,
        variables: [],
        isSystem: false,
      })
      addLog(`提示词模板已创建: ${newTemplate.name}`, 'system')
      setIsCreateDialogOpen(false)
      setNewTemplate({
        name: '',
        description: '',
        category: 'custom',
        language: 'zh',
        agentType: undefined,
        template: '',
        isActive: true,
      } as typeof newTemplate)
      loadPromptTemplates()
    } catch (err) {
      addLog(`创建提示词模板失败: ${err}`, 'system')
    }
  }

  // 删除模板
  const handleDeleteTemplate = async (id: string, name: string) => {
    if (!confirm(`确定要删除提示词模板 "${name}" 吗？`)) return

    try {
      await deletePromptTemplate(id)
      addLog(`提示词模板已删除: ${name}`, 'system')
      loadPromptTemplates()
    } catch (err) {
      addLog(`删除提示词模板失败: ${err}`, 'system')
    }
  }

  // 查看模板
  const handleViewTemplate = (template: PromptTemplate) => {
    setViewingTemplate(template)
    setIsViewDialogOpen(true)
  }

  // 获取类别图标
  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'system':
        return <Code className="w-4 h-4" />
      case 'agent':
        return <Bot className="w-4 h-4" />
      case 'tool':
        return <Wrench className="w-4 h-4" />
      default:
        return <FileText className="w-4 h-4" />
    }
  }

  // 获取 Agent 类型标签
  const getAgentTypeLabel = (agentType?: AgentType) => {
    if (!agentType) return null
    const labels: Record<AgentType, string> = {
      ORCHESTRATOR: '编排者',
      RECON: '侦察者',
      ANALYSIS: '分析者',
      VERIFICATION: '验证者',
      SYSTEM: '系统',
    }
    return labels[agentType]
  }

  // 格式化变量显示
  const formatVariableName = (name: string) => {
    return `{{${name}}}`
  }

  return (
    <div className="h-full flex flex-col">
      {/* Page Header */}
      <div className="border-b border-border/40 px-6 py-4 flex items-center justify-between bg-muted/20">
        <div className="flex items-center gap-3">
          <FileText className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-semibold">提示词模板</h2>
        </div>

        <div className="flex-1" />

        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              新建模板
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-2xl max-h-[80vh]">
            <DialogHeader>
              <DialogTitle>新建提示词模板</DialogTitle>
              <DialogDescription>
                创建一个自定义的提示词模板用于 Agent
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-4 py-4 overflow-y-auto max-h-[50vh] no-scrollbar">
              {/* 基本信息 */}
              <div className="grid grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label>名称 *</Label>
                  <Input
                    value={newTemplate.name}
                    onChange={(e) => setNewTemplate({ ...newTemplate, name: e.target.value })}
                    placeholder="例如: SQL注入检测提示词"
                  />
                </div>
                <div className="grid gap-2">
                  <Label>类别</Label>
                  <Select
                    value={newTemplate.category}
                    onValueChange={(category: any) => setNewTemplate({ ...newTemplate, category })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="custom">自定义</SelectItem>
                      <SelectItem value="agent">Agent</SelectItem>
                      <SelectItem value="tool">工具</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* 描述 */}
              <div className="grid gap-2">
                <Label>描述</Label>
                <Input
                  value={newTemplate.description}
                  onChange={(e) => setNewTemplate({ ...newTemplate, description: e.target.value })}
                  placeholder="简要描述此模板的用途"
                />
              </div>

              {/* Agent 类型 */}
              {newTemplate.category === 'agent' && (
                <div className="grid gap-2">
                  <Label>Agent 类型</Label>
                  <Select
                    value={newTemplate.agentType}
                    onValueChange={(agentType: AgentType) => setNewTemplate({ ...newTemplate, agentType })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="选择 Agent 类型" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ORCHESTRATOR">编排者</SelectItem>
                      <SelectItem value="RECON">侦察者</SelectItem>
                      <SelectItem value="ANALYSIS">分析者</SelectItem>
                      <SelectItem value="VERIFICATION">验证者</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}

              {/* 语言 */}
              <div className="grid gap-2">
                <Label>语言</Label>
                <Select
                  value={newTemplate.language}
                  onValueChange={(language: 'zh' | 'en') => setNewTemplate({ ...newTemplate, language })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="zh">中文</SelectItem>
                    <SelectItem value="en">English</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* 模板内容 */}
              <div className="grid gap-2">
                <Label>模板内容 *</Label>
                <Textarea
                  value={newTemplate.template}
                  onChange={(e) => setNewTemplate({ ...newTemplate, template: e.target.value })}
                  placeholder="输入提示词模板，使用 {{variable_name}} 作为变量占位符"
                  rows={10}
                  className="font-mono text-xs"
                />
                <p className="text-[10px] text-muted-foreground">
                  使用 {formatVariableName('variable_name')} 语法定义变量
                </p>
              </div>
            </div>

            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setIsCreateDialogOpen(false)}
              >
                取消
              </Button>
              <Button
                onClick={handleCreateTemplate}
                disabled={!newTemplate.name || !newTemplate.template}
              >
                创建
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-6 no-scrollbar">
        <div className="max-w-6xl mx-auto">
          {/* 过滤器 */}
          <div className="flex items-center gap-4 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="搜索模板..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>

            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CATEGORIES.map((cat) => (
                  <SelectItem key={cat.value} value={cat.value}>{cat.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={agentTypeFilter || 'all'} onValueChange={(v) => setAgentTypeFilter(v === 'all' ? null : v as AgentType)}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {AGENT_TYPES.map((type) => (
                  <SelectItem key={type.value || 'all'} value={type.value || 'all'}>
                    {type.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* 模板列表 */}
          {filteredTemplates.length === 0 ? (
            <Card className="p-12 text-center">
              <FileText className="w-16 h-16 mx-auto mb-4 text-muted-foreground/30" />
              <h3 className="text-lg font-semibold mb-2">没有找到提示词模板</h3>
              <p className="text-sm text-muted-foreground mb-6">
                {searchQuery || categoryFilter !== 'all' || agentTypeFilter
                  ? '尝试调整搜索或筛选条件'
                  : '创建自定义提示词模板以扩展 Agent 能力'}
              </p>
              {!searchQuery && categoryFilter === 'all' && !agentTypeFilter && (
                <Button onClick={() => setIsCreateDialogOpen(true)}>
                  <Plus className="w-4 h-4 mr-2" />
                  新建模板
                </Button>
              )}
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredTemplates.map((template) => (
                <Card key={template.id} className="p-4 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <div className="p-1.5 rounded bg-primary/10">
                        {getCategoryIcon(template.category)}
                      </div>
                      <div>
                        <h3 className="font-medium text-sm">{template.name}</h3>
                        <p className="text-xs text-muted-foreground">{template.description}</p>
                      </div>
                    </div>

                    <Badge variant={template.isActive ? 'default' : 'secondary'} className="text-[10px]">
                      {template.language === 'zh' ? '中文' : 'English'}
                    </Badge>
                  </div>

                  <div className="flex flex-wrap gap-1 mb-3">
                    <Badge variant="outline" className="text-[10px]">
                      {template.category}
                    </Badge>
                    {template.agentType && (
                      <Badge variant="outline" className="text-[10px]">
                        {getAgentTypeLabel(template.agentType)}
                      </Badge>
                    )}
                    {template.isSystem && (
                      <Badge variant="secondary" className="text-[10px]">系统</Badge>
                    )}
                  </div>

                  <div className="mb-3">
                    <pre className="text-xs bg-muted p-2 rounded max-h-20 overflow-hidden text-muted-foreground font-mono">
                      {template.template.slice(0, 150)}
                      {template.template.length > 150 && '...'}
                    </pre>
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleViewTemplate(template)}
                        className="h-7 text-xs"
                      >
                        <Eye className="w-3 h-3 mr-1" />
                        查看
                      </Button>
                      {!template.isSystem && (
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-7 text-xs text-destructive"
                          onClick={() => handleDeleteTemplate(template.id, template.name)}
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      )}
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 查看模板对话框 */}
      <Dialog open={isViewDialogOpen} onOpenChange={setIsViewDialogOpen}>
        <DialogContent className="sm:max-w-3xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle>{viewingTemplate?.name}</DialogTitle>
            <DialogDescription>{viewingTemplate?.description}</DialogDescription>
          </DialogHeader>

          {viewingTemplate && (
            <div className="space-y-4">
              {/* 元数据 */}
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline">{viewingTemplate.category}</Badge>
                {viewingTemplate.agentType && (
                  <Badge variant="outline">{getAgentTypeLabel(viewingTemplate.agentType)}</Badge>
                )}
                <Badge variant="secondary">{viewingTemplate.language}</Badge>
                {viewingTemplate.isSystem && (
                  <Badge variant="secondary">系统模板</Badge>
                )}
                <Badge variant={viewingTemplate.isActive ? 'default' : 'secondary'}>
                  {viewingTemplate.isActive ? '已启用' : '已禁用'}
                </Badge>
              </div>

              {/* 变量列表 */}
              {viewingTemplate.variables && viewingTemplate.variables.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold mb-2">变量</h4>
                  <div className="flex flex-wrap gap-2">
                    {viewingTemplate.variables.map((variable) => (
                      <Badge key={variable.name} variant="outline" className="text-xs">
                        {formatVariableName(variable.name)}
                        {variable.required && '*'}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* 模板内容 */}
              <div>
                <h4 className="text-sm font-semibold mb-2">模板内容</h4>
                <ScrollArea className="h-[300px] p-4 bg-muted rounded">
                  <pre className="text-xs font-mono whitespace-pre-wrap">{viewingTemplate.template}</pre>
                </ScrollArea>
              </div>
            </div>
          )}

          <DialogFooter>
            <Button onClick={() => setIsViewDialogOpen(false)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
