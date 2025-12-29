/**
 * 系统设置页面
 * 对应后端API: agent-service/app/api/settings.py
 */

import { useEffect, useState } from 'react'
import {
  Save,
  RotateCcw,
  Settings as SettingsIcon,
  GitBranch,
  Bot,
  Palette,
  Scan,
  Loader2,
  Database,
} from 'lucide-react'
import { useSettingsStore } from '@/stores/settingsStore'
import { useUIStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Slider } from '@/components/ui/slider'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { SystemSettings } from '@/shared/types'

export function SystemSettingsPage() {
  const { addLog } = useUIStore()

  const {
    systemSettings,
    systemSettingsLoading,
    systemSettingsError,
    loadSystemSettings,
    updateSystemSettings,
    resetSystemSettings,
  } = useSettingsStore()

  const [isSaving, setIsSaving] = useState(false)
  const [hasChanges, setHasChanges] = useState(false)
  const [localSettings, setLocalSettings] = useState<SystemSettings>(systemSettings)

  useEffect(() => {
    loadSystemSettings()
  }, [loadSystemSettings])

  // 当系统设置加载完成后，同步到本地状态
  useEffect(() => {
    if (!systemSettingsLoading) {
      setLocalSettings(systemSettings)
    }
  }, [systemSettings, systemSettingsLoading])

  // 检查是否有变更
  useEffect(() => {
    const changed = JSON.stringify(localSettings) !== JSON.stringify(systemSettings)
    setHasChanges(changed)
  }, [localSettings, systemSettings])

  // 保存设置
  const handleSave = async () => {
    setIsSaving(true)
    try {
      await updateSystemSettings(localSettings)
      addLog('系统设置已保存', 'system')
      setHasChanges(false)
    } catch (err) {
      addLog(`保存设置失败: ${err}`, 'system')
    } finally {
      setIsSaving(false)
    }
  }

  // 重置设置
  const handleReset = async () => {
    if (!confirm('确定要重置所有设置为默认值吗？')) return

    setIsSaving(true)
    try {
      await resetSystemSettings()
      addLog('系统设置已重置为默认值', 'system')
    } catch (err) {
      addLog(`重置设置失败: ${err}`, 'system')
    } finally {
      setIsSaving(false)
    }
  }

  // 更新本地设置
  const updateLocalSettings = (section: keyof SystemSettings, updates: Partial<any>) => {
    const currentSection = localSettings[section]
    setLocalSettings({
      ...localSettings,
      [section]: {
        ...(currentSection && typeof currentSection === 'object' ? currentSection : {}),
        ...updates,
      },
    })
  }

  if (systemSettingsLoading) {
    return (
      <div className="h-full flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (systemSettingsError) {
    return (
      <div className="h-full flex items-center justify-center">
        <Card className="p-8 text-center border-destructive">
          <p className="text-destructive mb-4">{systemSettingsError}</p>
          <Button onClick={loadSystemSettings} variant="outline">
            <RotateCcw className="w-4 h-4 mr-2" />
            重试
          </Button>
        </Card>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="border-b border-border/40 px-6 py-4 flex items-center justify-between bg-muted/20">
        <div className="flex items-center gap-3">
          <SettingsIcon className="w-5 h-5 text-primary" />
          <div>
            <h2 className="text-lg font-semibold">系统设置</h2>
            <p className="text-xs text-muted-foreground">
              配置分析参数、Git 集成、Agent 行为和界面偏好
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleReset}
            disabled={isSaving}
          >
            <RotateCcw className="w-4 h-4 mr-2" />
            重置默认
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={!hasChanges || isSaving}
          >
            {isSaving ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Save className="w-4 h-4 mr-2" />
            )}
            保存设置
          </Button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-6 no-scrollbar">
        <Tabs defaultValue="analysis" className="max-w-3xl mx-auto">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="analysis" className="gap-2">
              <Scan className="w-4 h-4" />
              分析
            </TabsTrigger>
            <TabsTrigger value="git" className="gap-2">
              <GitBranch className="w-4 h-4" />
              Git
            </TabsTrigger>
            <TabsTrigger value="agent" className="gap-2">
              <Bot className="w-4 h-4" />
              Agent
            </TabsTrigger>
            <TabsTrigger value="ui" className="gap-2">
              <Palette className="w-4 h-4" />
              界面
            </TabsTrigger>
            <TabsTrigger value="embedding" className="gap-2">
              <Database className="w-4 h-4" />
              嵌入
            </TabsTrigger>
          </TabsList>

          {/* 分析参数设置 */}
          <TabsContent value="analysis" className="mt-6 space-y-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">扫描分析参数</h3>
              <div className="space-y-6">

                {/* 最大分析文件数 */}
                <div className="grid gap-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium">最大分析文件数</Label>
                    <span className="text-sm text-muted-foreground">
                      {localSettings.analysis?.maxAnalyzeFiles === 0 ? '无限制' : localSettings.analysis?.maxAnalyzeFiles}
                    </span>
                  </div>
                  <Slider
                    value={[localSettings.analysis?.maxAnalyzeFiles ?? 0]}
                    onValueChange={([value]) => updateLocalSettings('analysis', { maxAnalyzeFiles: value })}
                    min={0}
                    max={500}
                    step={10}
                  />
                  <p className="text-xs text-muted-foreground">
                    设置为 0 表示不限制文件数量
                  </p>
                </div>

                {/* 单文件最大大小 */}
                <div className="grid gap-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium">单文件最大大小</Label>
                    <span className="text-sm text-muted-foreground">
                      {((localSettings.analysis?.maxFileSize ?? 204800) / 1024).toFixed(0)} KB
                    </span>
                  </div>
                  <Slider
                    value={[localSettings.analysis?.maxFileSize ?? 204800]}
                    onValueChange={([value]) => updateLocalSettings('analysis', { maxFileSize: value })}
                    min={10 * 1024}
                    max={1024 * 1024}
                    step={10 * 1024}
                  />
                  <p className="text-xs text-muted-foreground">
                    超过此大小的文件将被跳过分析
                  </p>
                </div>

                {/* LLM 并发数 */}
                <div className="grid gap-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium">LLM 并发请求数</Label>
                    <span className="text-sm text-muted-foreground">{localSettings.analysis?.llmConcurrency ?? 3}</span>
                  </div>
                  <Slider
                    value={[localSettings.analysis?.llmConcurrency ?? 3]}
                    onValueChange={([value]) => updateLocalSettings('analysis', { llmConcurrency: value })}
                    min={1}
                    max={10}
                    step={1}
                  />
                  <p className="text-xs text-muted-foreground">
                    同时发送给 LLM 的最大请求数
                  </p>
                </div>

                {/* LLM 请求间隔 */}
                <div className="grid gap-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium">LLM 请求间隔 (毫秒)</Label>
                    <span className="text-sm text-muted-foreground">{localSettings.analysis?.llmGapMs ?? 2000} ms</span>
                  </div>
                  <Slider
                    value={[localSettings.analysis?.llmGapMs ?? 2000]}
                    onValueChange={([value]) => updateLocalSettings('analysis', { llmGapMs: value })}
                    min={0}
                    max={5000}
                    step={100}
                  />
                  <p className="text-xs text-muted-foreground">
                    连续 LLM 请求之间的间隔时间
                  </p>
                </div>

                {/* 输出语言 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">输出语言</Label>
                  <Select
                    value={localSettings.analysis?.outputLanguage ?? 'zh-CN'}
                    onValueChange={(value: string) =>
                      updateLocalSettings('analysis', { outputLanguage: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="zh-CN">简体中文</SelectItem>
                      <SelectItem value="en-US">English</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* 开关选项 */}
                <div className="space-y-4 pt-4 border-t">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-sm">启用 RAG 知识检索</Label>
                      <p className="text-xs text-muted-foreground">
                        使用向量数据库检索相关漏洞知识
                      </p>
                    </div>
                    <Switch
                      checked={localSettings.analysis?.enableRAG ?? true}
                      onCheckedChange={(checked) => updateLocalSettings('analysis', { enableRAG: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-sm">启用 LLM 验证</Label>
                      <p className="text-xs text-muted-foreground">
                        使用 LLM 验证扫描发现的漏洞
                      </p>
                    </div>
                    <Switch
                      checked={localSettings.analysis?.enableVerification ?? false}
                      onCheckedChange={(checked) => updateLocalSettings('analysis', { enableVerification: checked })}
                    />
                  </div>
                </div>

                {/* 高级选项 */}
                <div className="space-y-4 pt-4 border-t">
                  <h4 className="text-sm font-medium">高级选项</h4>

                  <div className="grid gap-3">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs">最大迭代次数</Label>
                      <span className="text-xs text-muted-foreground">{localSettings.analysis?.maxIterations ?? 20}</span>
                    </div>
                    <Slider
                      value={[localSettings.analysis?.maxIterations ?? 20]}
                      onValueChange={([value]) => updateLocalSettings('analysis', { maxIterations: value })}
                      min={5}
                      max={50}
                      step={5}
                    />
                  </div>

                  <div className="grid gap-3">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs">超时时间 (秒)</Label>
                      <span className="text-xs text-muted-foreground">{localSettings.analysis?.timeoutSeconds ?? 300}s</span>
                    </div>
                    <Slider
                      value={[localSettings.analysis?.timeoutSeconds ?? 300]}
                      onValueChange={([value]) => updateLocalSettings('analysis', { timeoutSeconds: value })}
                      min={60}
                      max={600}
                      step={30}
                    />
                  </div>
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* Git 集成设置 */}
          <TabsContent value="git" className="mt-6 space-y-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Git 仓库集成</h3>
              <p className="text-sm text-muted-foreground mb-6">
                配置 Git 托管平台的访问令牌
              </p>
              <div className="space-y-6">

                {/* 默认分支 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">默认分支</Label>
                  <Input
                    value={localSettings.git?.defaultBranch ?? 'main'}
                    onChange={(e) => updateLocalSettings('git', { defaultBranch: e.target.value })}
                    placeholder="main"
                  />
                </div>

                <div className="pt-4 border-t">
                  <h4 className="text-sm font-medium mb-4">访问令牌 (可选)</h4>

                  {/* GitHub Token */}
                  <div className="grid gap-2 mb-4">
                    <Label className="text-sm">GitHub 令牌</Label>
                    <Input
                      type="password"
                      value={localSettings.git?.githubToken ?? ''}
                      onChange={(e) => updateLocalSettings('git', { githubToken: e.target.value })}
                      placeholder="ghp_..."
                    />
                  </div>

                  {/* GitLab Token */}
                  <div className="grid gap-2 mb-4">
                    <Label className="text-sm">GitLab 令牌</Label>
                    <Input
                      type="password"
                      value={localSettings.git?.gitlabToken ?? ''}
                      onChange={(e) => updateLocalSettings('git', { gitlabToken: e.target.value })}
                      placeholder="glpat-..."
                    />
                  </div>

                  {/* Gitea Token */}
                  <div className="grid gap-2">
                    <Label className="text-sm">Gitea 令牌</Label>
                    <Input
                      type="password"
                      value={localSettings.git?.giteaToken ?? ''}
                      onChange={(e) => updateLocalSettings('git', { giteaToken: e.target.value })}
                      placeholder="..."
                    />
                  </div>
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* Agent 配置 */}
          <TabsContent value="agent" className="mt-6 space-y-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Agent 行为配置</h3>
              <div className="space-y-6">

                {/* 最大并发 Agent 数 */}
                <div className="grid gap-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium">最大并发 Agent 数</Label>
                    <span className="text-sm text-muted-foreground">{localSettings.agent?.maxConcurrentAgents ?? 3}</span>
                  </div>
                  <Slider
                    value={[localSettings.agent?.maxConcurrentAgents ?? 3]}
                    onValueChange={([value]) => updateLocalSettings('agent', { maxConcurrentAgents: value })}
                    min={1}
                    max={10}
                    step={1}
                  />
                  <p className="text-xs text-muted-foreground">
                    同时运行的最大 Agent 实例数
                  </p>
                </div>

                {/* Agent 超时 */}
                <div className="grid gap-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium">Agent 超时时间 (秒)</Label>
                    <span className="text-sm text-muted-foreground">{localSettings.agent?.agentTimeout ?? 300}s</span>
                  </div>
                  <Slider
                    value={[localSettings.agent?.agentTimeout ?? 300]}
                    onValueChange={([value]) => updateLocalSettings('agent', { agentTimeout: value })}
                    min={60}
                    max={600}
                    step={30}
                  />
                  <p className="text-xs text-muted-foreground">
                    单个 Agent 任务的最大执行时间
                  </p>
                </div>

                {/* 沙箱设置 */}
                <div className="pt-4 border-t space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-sm">启用沙箱隔离</Label>
                      <p className="text-xs text-muted-foreground">
                        在 Docker 容器中运行验证代码
                      </p>
                    </div>
                    <Switch
                      checked={localSettings.agent?.enableSandbox ?? false}
                      onCheckedChange={(checked) => updateLocalSettings('agent', { enableSandbox: checked })}
                    />
                  </div>

                  {(localSettings.agent?.enableSandbox ?? false) && (
                    <div className="grid gap-2 pl-4">
                      <Label className="text-sm">沙箱镜像</Label>
                      <Input
                        value={localSettings.agent?.sandboxImage ?? 'python:3.11-slim'}
                        onChange={(e) => updateLocalSettings('agent', { sandboxImage: e.target.value })}
                        placeholder="python:3.11-slim"
                      />
                    </div>
                  )}
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* 界面偏好设置 */}
          <TabsContent value="ui" className="mt-6 space-y-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">界面偏好</h3>
              <div className="space-y-6">

                {/* 主题 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">主题</Label>
                  <Select
                    value={localSettings.ui?.theme ?? 'auto'}
                    onValueChange={(value: string) =>
                      updateLocalSettings('ui', { theme: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="light">浅色</SelectItem>
                      <SelectItem value="dark">深色</SelectItem>
                      <SelectItem value="auto">跟随系统</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* 语言 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">语言</Label>
                  <Select
                    value={localSettings.ui?.language ?? 'zh-CN'}
                    onValueChange={(value: string) =>
                      updateLocalSettings('ui', { language: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="zh-CN">简体中文</SelectItem>
                      <SelectItem value="en-US">English</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* 字体大小 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">字体大小</Label>
                  <Select
                    value={localSettings.ui?.fontSize ?? 'medium'}
                    onValueChange={(value: string) =>
                      updateLocalSettings('ui', { fontSize: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="small">小</SelectItem>
                      <SelectItem value="medium">中</SelectItem>
                      <SelectItem value="large">大</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* 开关选项 */}
                <div className="space-y-4 pt-4 border-t">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-sm">显示思考过程</Label>
                      <p className="text-xs text-muted-foreground">
                        在审计过程中显示 Agent 的思考链
                      </p>
                    </div>
                    <Switch
                      checked={localSettings.ui?.showThinking ?? true}
                      onCheckedChange={(checked) => updateLocalSettings('ui', { showThinking: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-sm">自动滚动</Label>
                      <p className="text-xs text-muted-foreground">
                        审计过程中自动滚动到最新事件
                      </p>
                    </div>
                    <Switch
                      checked={localSettings.ui?.autoScroll ?? true}
                      onCheckedChange={(checked) => updateLocalSettings('ui', { autoScroll: checked })}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-sm">紧凑模式</Label>
                      <p className="text-xs text-muted-foreground">
                        减少卡片和列表的内边距
                      </p>
                    </div>
                    <Switch
                      checked={localSettings.ui?.compactMode ?? false}
                      onCheckedChange={(checked) => updateLocalSettings('ui', { compactMode: checked })}
                    />
                  </div>
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* 嵌入模型配置 */}
          <TabsContent value="embedding" className="mt-6 space-y-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">嵌入模型配置</h3>
              <p className="text-sm text-muted-foreground mb-6">
                配置向量嵌入模型用于 RAG 知识检索
              </p>
              <div className="space-y-6">

                {/* 提供商 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">提供商</Label>
                  <Input
                    value={localSettings.embedding?.provider ?? 'openai'}
                    onChange={(e) => updateLocalSettings('embedding', { provider: e.target.value })}
                    placeholder="openai"
                  />
                  <p className="text-xs text-muted-foreground">
                    嵌入模型提供商标识
                  </p>
                </div>

                {/* 模型 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">模型名称</Label>
                  <Input
                    value={localSettings.embedding?.model ?? 'text-embedding-3-small'}
                    onChange={(e) => updateLocalSettings('embedding', { model: e.target.value })}
                    placeholder="text-embedding-3-small"
                  />
                  <p className="text-xs text-muted-foreground">
                    嵌入模型标识符
                  </p>
                </div>

                {/* API 密钥 */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">API 密钥</Label>
                  <Input
                    type="password"
                    value={localSettings.embedding?.apiKey ?? ''}
                    onChange={(e) => updateLocalSettings('embedding', { apiKey: e.target.value })}
                    placeholder="sk-..."
                  />
                </div>

                {/* Base URL */}
                <div className="grid gap-2">
                  <Label className="text-sm font-medium">API 端点</Label>
                  <Input
                    value={localSettings.embedding?.baseUrl ?? ''}
                    onChange={(e) => updateLocalSettings('embedding', { baseUrl: e.target.value })}
                    placeholder="https://api.openai.com/v1"
                  />
                </div>

                {/* 维度 */}
                <div className="grid gap-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-sm font-medium">向量维度</Label>
                    <span className="text-sm text-muted-foreground">{localSettings.embedding?.dimension ?? 1536}</span>
                  </div>
                  <Slider
                    value={[localSettings.embedding?.dimension ?? 1536]}
                    onValueChange={([value]) => updateLocalSettings('embedding', { dimension: value })}
                    min={256}
                    max={4096}
                    step={128}
                  />
                  <p className="text-xs text-muted-foreground">
                    嵌入向量的维度大小
                  </p>
                </div>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Footer - 提示有未保存的更改 */}
      {hasChanges && (
        <div className="border-t border-border/40 px-6 py-3 bg-muted/30">
          <div className="flex items-center justify-center gap-2 text-sm text-amber-600 dark:text-amber-400">
            <span>您有未保存的更改</span>
            <Button size="sm" variant="ghost" onClick={handleSave} disabled={isSaving}>
              {isSaving ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  <Save className="w-4 h-4 mr-1" />
                  立即保存
                </>
              )}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
