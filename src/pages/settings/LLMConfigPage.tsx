/**
 * LLM 配置页面
 */

import { useEffect, useState } from 'react'
import {
  Plus,
  Trash2,
  Check,
  X,
  Key,
  Server,
  Loader2,
} from 'lucide-react'
import { useAgentStore } from '@/stores/agentStore'
import { useUIStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import { Switch } from '@/components/ui/switch'
import type { LLMProvider, LLMConfig } from '@/shared/types'
import { LLM_PROVIDERS } from '@/shared/types'

export function LLMConfigPage() {
  const { addLog } = useUIStore()

  const {
    llmConfigs,
    loadLLMConfigs,
    createLLMConfig,
    deleteLLMConfig,
    setDefaultLLMConfig,
    testLLMConfig,
  } = useAgentStore()

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [testingConfigId, setTestingConfigId] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; error?: string }>>({})

  useEffect(() => {
    loadLLMConfigs()
  }, [loadLLMConfigs])

  // 新建配置表单状态
  const [newConfig, setNewConfig] = useState({
    provider: 'openai' as LLMProvider,
    model: '',
    apiKey: '',
    apiEndpoint: '',
    temperature: 0.7,
    maxTokens: 4096,
    enabled: true,
    isDefault: false,
  })

  // 获取提供商的可用模型
  const getProviderModels = (provider: LLMProvider) => {
    return LLM_PROVIDERS[provider]?.models || []
  }

  // 处理提供商变更
  const handleProviderChange = (provider: LLMProvider) => {
    setNewConfig({
      ...newConfig,
      provider,
      model: getProviderModels(provider)[0] || '',
      apiEndpoint: provider === 'custom' ? '' : newConfig.apiEndpoint,
    })
  }

  // 创建新配置
  const handleCreateConfig = async () => {
    try {
      await createLLMConfig(newConfig)
      addLog(`LLM 配置已创建: ${newConfig.provider}/${newConfig.model}`, 'system')
      setIsCreateDialogOpen(false)
      setNewConfig({
        provider: 'openai',
        model: '',
        apiKey: '',
        apiEndpoint: '',
        temperature: 0.7,
        maxTokens: 4096,
        enabled: true,
        isDefault: false,
      })
    } catch (err) {
      addLog(`创建 LLM 配置失败: ${err}`, 'system')
    }
  }

  // 删除配置
  const handleDeleteConfig = async (id: string, name: string) => {
    if (!confirm(`确定要删除 LLM 配置 "${name}" 吗？`)) return

    try {
      await deleteLLMConfig(id)
      addLog(`LLM 配置已删除: ${name}`, 'system')
    } catch (err) {
      addLog(`删除 LLM 配置失败: ${err}`, 'system')
    }
  }

  // 设置默认配置
  const handleSetDefault = async (id: string) => {
    try {
      await setDefaultLLMConfig(id)
      addLog(`已设置默认 LLM 配置`, 'system')
    } catch (err) {
      addLog(`设置默认配置失败: ${err}`, 'system')
    }
  }

  // 测试配置
  const handleTestConfig = async (config: LLMConfig) => {
    setTestingConfigId(config.id)
    try {
      const result = await testLLMConfig(config.id)
      setTestResults({ ...testResults, [config.id]: result })
      if (result.success) {
        addLog(`LLM 配置测试成功: ${config.model}`, 'system')
      } else {
        addLog(`LLM 配置测试失败: ${result.error}`, 'system')
      }
    } catch (err) {
      setTestResults({ ...testResults, [config.id]: { success: false, error: String(err) } })
    } finally {
      setTestingConfigId(null)
    }
  }

  return (
    <div className="h-full flex flex-col">
      {/* Page Header */}
      <div className="border-b border-border/40 px-6 py-4 flex items-center justify-between bg-muted/20">
        <div className="flex items-center gap-3">
          <Server className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-semibold">LLM 配置</h2>
        </div>

        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm">
              <Plus className="w-4 h-4 mr-2" />
              添加配置
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>添加 LLM 配置</DialogTitle>
              <DialogDescription>
                配置一个新的 LLM 提供商用于 Agent 审计
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-4 py-4">
              {/* 提供商选择 */}
              <div className="grid gap-2">
                <Label>提供商</Label>
                <Select value={newConfig.provider} onValueChange={handleProviderChange}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.entries(LLM_PROVIDERS).map(([id, info]) => (
                      <SelectItem key={id} value={id}>
                        <div className="flex items-center gap-2">
                          <span>{info.name}</span>
                          <span className="text-muted-foreground text-xs">{info.description}</span>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* 模型选择 */}
              <div className="grid gap-2">
                <Label>模型</Label>
                <Select
                  value={newConfig.model}
                  onValueChange={(model) => setNewConfig({ ...newConfig, model })}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="选择模型" />
                  </SelectTrigger>
                  <SelectContent>
                    {getProviderModels(newConfig.provider).map((model) => (
                      <SelectItem key={model} value={model}>{model}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* API 密钥 */}
              <div className="grid gap-2">
                <Label>API 密钥</Label>
                <div className="relative">
                  <Input
                    type="password"
                    value={newConfig.apiKey}
                    onChange={(e) => setNewConfig({ ...newConfig, apiKey: e.target.value })}
                    placeholder="sk-..."
                  />
                  <Key className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                </div>
              </div>

              {/* API 端点（仅自定义） */}
              {newConfig.provider === 'custom' && (
                <div className="grid gap-2">
                  <Label>API 端点</Label>
                  <Input
                    value={newConfig.apiEndpoint}
                    onChange={(e) => setNewConfig({ ...newConfig, apiEndpoint: e.target.value })}
                    placeholder="https://api.example.com/v1"
                  />
                </div>
              )}

              {/* 高级选项 */}
              <div className="grid grid-cols-2 gap-4">
                <div className="grid gap-2">
                  <Label>温度 (0-2)</Label>
                  <Input
                    type="number"
                    min={0}
                    max={2}
                    step={0.1}
                    value={newConfig.temperature}
                    onChange={(e) => setNewConfig({ ...newConfig, temperature: parseFloat(e.target.value) })}
                  />
                </div>
                <div className="grid gap-2">
                  <Label>最大令牌</Label>
                  <Input
                    type="number"
                    min={1}
                    value={newConfig.maxTokens}
                    onChange={(e) => setNewConfig({ ...newConfig, maxTokens: parseInt(e.target.value) })}
                  />
                </div>
              </div>

              {/* 启用和默认 */}
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Switch
                    checked={newConfig.enabled}
                    onCheckedChange={(enabled: boolean) => setNewConfig({ ...newConfig, enabled })}
                  />
                  <Label>启用此配置</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch
                    checked={newConfig.isDefault}
                    onCheckedChange={(isDefault: boolean) => setNewConfig({ ...newConfig, isDefault })}
                  />
                  <Label>设为默认</Label>
                </div>
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
                onClick={handleCreateConfig}
                disabled={!newConfig.model || !newConfig.apiKey}
              >
                创建
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl mx-auto">
          {/* 配置列表 */}
          <div className="space-y-4">
            {llmConfigs.length === 0 ? (
              <Card className="p-12 text-center">
                <Server className="w-16 h-16 mx-auto mb-4 text-muted-foreground/30" />
                <h3 className="text-lg font-semibold mb-2">还没有 LLM 配置</h3>
                <p className="text-sm text-muted-foreground mb-6 max-w-md mx-auto">
                  添加 LLM 配置以启用 AI Agent 审计功能。支持 OpenAI、Anthropic、Azure、Ollama 等多种提供商。
                </p>
                <Button onClick={() => setIsCreateDialogOpen(true)}>
                  <Plus className="w-4 h-4 mr-2" />
                  添加第一个配置
                </Button>
              </Card>
            ) : (
              llmConfigs.map((config) => {
                const providerInfo = LLM_PROVIDERS[config.provider]
                const testResult = testResults[config.id]

                return (
                  <Card key={config.id} className="p-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-4">
                        {/* 图标 */}
                        <div className="p-2 rounded-lg bg-primary/10">
                          <Server className="w-5 h-5 text-primary" />
                        </div>

                        {/* 信息 */}
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <h3 className="font-semibold">{providerInfo?.name || config.provider}</h3>
                            {config.isDefault && (
                              <Badge variant="secondary" className="text-[10px]">默认</Badge>
                            )}
                            {!config.enabled && (
                              <Badge variant="outline" className="text-[10px]">已禁用</Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground mb-2">
                            {config.model}
                          </p>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>温度: {config.temperature}</span>
                            <span>最大令牌: {config.maxTokens}</span>
                            {config.apiEndpoint && (
                              <span className="font-mono max-w-[200px] truncate">{config.apiEndpoint}</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* 操作按钮 */}
                      <div className="flex items-center gap-2">
                        {/* 测试结果 */}
                        {testResult && (
                          <div className={`flex items-center gap-1 text-xs ${
                            testResult.success ? 'text-green-500' : 'text-red-500'
                          }`}>
                            {testResult.success ? (
                              <Check className="w-3 h-3" />
                            ) : (
                              <X className="w-3 h-3" />
                            )}
                            {testResult.error && (
                              <span className="max-w-[150px] truncate">{testResult.error}</span>
                            )}
                          </div>
                        )}

                        {/* 测试按钮 */}
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleTestConfig(config)}
                          disabled={testingConfigId === config.id || !config.enabled}
                        >
                          {testingConfigId === config.id ? (
                            <Loader2 className="w-3 h-3 animate-spin" />
                          ) : (
                            <Check className="w-3 h-3" />
                          )}
                        </Button>

                        {/* 设为默认 */}
                        {!config.isDefault && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleSetDefault(config.id)}
                          >
                            默认
                          </Button>
                        )}

                        {/* 删除 */}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-destructive"
                          onClick={() => handleDeleteConfig(config.id, config.model)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </div>
                  </Card>
                )
              })
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
