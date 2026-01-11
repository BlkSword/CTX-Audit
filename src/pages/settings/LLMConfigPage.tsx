/**
 * LLM 配置页面
 * 自定义配置版本 - 无预置厂商
 * 创建前自动验证连接
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
  Save,
  RotateCcw,
  Sparkles,
} from 'lucide-react'
import { useSettingsStore } from '@/stores/settingsStore'
import { useToast } from '@/hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
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
import { Slider } from '@/components/ui/slider'
import type { LLMConfig } from '@/shared/types'

export function LLMConfigPage() {
  const toast = useToast()
  
  const {
    llmConfigs,
    defaultLLMConfigId,
    llmConfigsLoading,
    llmConfigsError,
    loadLLMConfigs,
    createLLMConfig,
    deleteLLMConfig,
    setDefaultLLMConfig,
    testLLMConfig,
  } = useSettingsStore()

  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [testingConfigId, setTestingConfigId] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message?: string }>>({})
  const [isCreating, setIsCreating] = useState(false)

  useEffect(() => {
    loadLLMConfigs()
  }, [loadLLMConfigs])

  // 新建配置表单状态
  const [newConfig, setNewConfig] = useState({
    name: '',  // 自定义名称
    model: '',
    apiKey: '',
    apiEndpoint: '',
    temperature: 0.7,
    maxTokens: 4096,
    enabled: true,
    isDefault: false,
  })

  // 验证表单是否填写完整
  const isFormValid = () => {
    return newConfig.name && newConfig.model && newConfig.apiEndpoint && newConfig.apiKey
  }

  // 创建新配置
  const handleCreateConfig = async () => {
    if (!isFormValid()) {
      toast.warning('请填写所有必填字段')
      return
    }

    setIsCreating(true)

    try {
      // 直接创建配置，不再验证连接
      await createLLMConfig({
        provider: newConfig.name,
        model: newConfig.model,
        apiKey: newConfig.apiKey,
        apiEndpoint: newConfig.apiEndpoint,
        temperature: newConfig.temperature,
        maxTokens: newConfig.maxTokens,
        enabled: newConfig.enabled,
        isDefault: newConfig.isDefault,
      })

      toast.success(`LLM 配置已创建: ${newConfig.name}`)
      setIsCreateDialogOpen(false)

      // 重置表单
      setNewConfig({
        name: '',
        model: '',
        apiKey: '',
        apiEndpoint: '',
        temperature: 0.7,
        maxTokens: 4096,
        enabled: true,
        isDefault: false,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      toast.error(`操作失败: ${message}`)
    } finally {
      setIsCreating(false)
    }
  }

  // 删除配置
  const handleDeleteConfig = async (id: string, name: string) => {
    if (!confirm(`确定要删除 LLM 配置 "${name}" 吗？`)) return

    try {
      await deleteLLMConfig(id)
      toast.success(`LLM 配置已删除: ${name}`)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      toast.error(`删除 LLM 配置失败: ${message}`)
    }
  }

  // 设置默认配置
  const handleSetDefault = async (id: string) => {
    try {
      await setDefaultLLMConfig(id)
      toast.success('已设置默认 LLM 配置')
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      toast.error(`设置默认配置失败: ${message}`)
    }
  }

  // 测试已保存的配置
  const handleTestConfig = async (config: LLMConfig) => {
    setTestingConfigId(config.id)
    try {
      const result = await testLLMConfig(config.id)
      setTestResults({ ...testResults, [config.id]: result })
      if (result.success) {
        toast.success(`LLM 配置测试成功: ${config.provider}`)
      } else {
        toast.error(`LLM 配置测试失败: ${result.message}`)
      }
    } catch (err) {
      setTestResults({ ...testResults, [config.id]: { success: false, message: String(err) } })
    } finally {
      setTestingConfigId(null)
    }
  }

  // 关闭对话框时重置状态
  const handleDialogOpenChange = (open: boolean) => {
    if (!open && !isCreating) {
      setIsCreateDialogOpen(open)
      // 重置表单
      setNewConfig({
        name: '',
        model: '',
        apiKey: '',
        apiEndpoint: '',
        temperature: 0.7,
        maxTokens: 4096,
        enabled: true,
        isDefault: false,
      })
    } else {
      setIsCreateDialogOpen(open)
    }
  }

  return (
    <div className="h-full flex flex-col">
      {/* Page Header */}
      <div className="border-b border-border/40 px-6 py-4 flex items-center justify-between bg-muted/20">
        <div className="flex items-center gap-3">
          <Server className="w-5 h-5 text-primary" />
          <div>
            <h2 className="text-lg font-semibold">LLM 配置</h2>
            <p className="text-xs text-muted-foreground">
              配置自定义 LLM API 用于 AI Agent 审计分析
            </p>
          </div>
        </div>

        <Dialog open={isCreateDialogOpen} onOpenChange={handleDialogOpenChange}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2">
              <Plus className="w-4 h-4" />
              添加配置
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto no-scrollbar">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Sparkles className="w-5 h-5" />
                添加 LLM 配置
              </DialogTitle>
              <DialogDescription>
                配置自定义 LLM API。支持任何兼容 OpenAI API 格式的服务。
                <span className="text-amber-600 dark:text-amber-400"> 点击创建时会自动验证连接。</span>
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-5 py-4">
              {/* 配置名称 */}
              <div className="grid gap-2">
                <Label className="text-sm font-medium">配置名称 <span className="text-destructive">*</span></Label>
                <Input
                  value={newConfig.name}
                  onChange={(e) => setNewConfig({ ...newConfig, name: e.target.value })}
                  placeholder="例如: OpenAI GPT-4"
                  disabled={isCreating}
                />
                <p className="text-xs text-muted-foreground">
                  为此配置输入一个便于识别的名称
                </p>
              </div>

              {/* 模型名称 */}
              <div className="grid gap-2">
                <Label className="text-sm font-medium">模型名称 <span className="text-destructive">*</span></Label>
                <Input
                  value={newConfig.model}
                  onChange={(e) => setNewConfig({ ...newConfig, model: e.target.value })}
                  placeholder="例如: gpt-4o"
                  disabled={isCreating}
                />
                <p className="text-xs text-muted-foreground">
                  API 请求中使用的模型标识符
                </p>
              </div>

              {/* API 端点 */}
              <div className="grid gap-2">
                <Label className="text-sm font-medium">API 端点 <span className="text-destructive">*</span></Label>
                <Input
                  value={newConfig.apiEndpoint}
                  onChange={(e) => setNewConfig({ ...newConfig, apiEndpoint: e.target.value })}
                  placeholder="https://api.openai.com/v1"
                  disabled={isCreating}
                />
                <p className="text-xs text-muted-foreground">
                  OpenAI 兼容 API 的基础 URL
                </p>
              </div>

              {/* API 密钥 */}
              <div className="grid gap-2">
                <Label className="text-sm font-medium">
                  API 密钥 <span className="text-destructive">*</span>
                </Label>
                <div className="relative">
                  <Key className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    type="password"
                    value={newConfig.apiKey}
                    onChange={(e) => setNewConfig({ ...newConfig, apiKey: e.target.value })}
                    placeholder="sk-..."
                    className="pl-10"
                    disabled={isCreating}
                  />
                </div>
                <p className="text-xs text-muted-foreground">
                  密钥将被加密存储在本地数据库中
                </p>
              </div>

              {/* 高级选项 */}
              <div className="space-y-4">
                <Label className="text-sm font-medium">高级选项</Label>

                {/* 温度 */}
                <div className="grid gap-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs">温度</Label>
                    <span className="text-xs text-muted-foreground">{newConfig.temperature.toFixed(1)}</span>
                  </div>
                  <Slider
                    value={[newConfig.temperature]}
                    onValueChange={([value]) => setNewConfig({ ...newConfig, temperature: value })}
                    min={0}
                    max={2}
                    step={0.1}
                    disabled={isCreating}
                  />
                  <p className="text-xs text-muted-foreground">
                    控制模型输出的随机性。较低值使输出更确定性。
                  </p>
                </div>

                {/* 最大令牌 */}
                <div className="grid gap-2">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs">最大令牌数</Label>
                    <span className="text-xs text-muted-foreground">{newConfig.maxTokens}</span>
                  </div>
                  <Slider
                    value={[newConfig.maxTokens]}
                    onValueChange={([value]) => setNewConfig({ ...newConfig, maxTokens: value })}
                    min={256}
                    max={32000}
                    step={256}
                    disabled={isCreating}
                  />
                  <p className="text-xs text-muted-foreground">
                    单次请求的最大输出令牌数。
                  </p>
                </div>
              </div>

              {/* 启用和默认 */}
              <div className="flex items-center justify-between py-2">
                <div className="flex items-center gap-2">
                  <Switch
                    checked={newConfig.enabled}
                    onCheckedChange={(enabled: boolean) => setNewConfig({ ...newConfig, enabled })}
                    disabled={isCreating}
                  />
                  <Label className="text-sm cursor-pointer">启用此配置</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch
                    checked={newConfig.isDefault}
                    onCheckedChange={(isDefault: boolean) => setNewConfig({ ...newConfig, isDefault })}
                    disabled={isCreating}
                  />
                  <Label className="text-sm cursor-pointer">设为默认</Label>
                </div>
              </div>

              {/* 创建中提示 */}
              {isCreating && (
                <div className="flex items-center justify-center gap-2 p-4 bg-muted rounded-lg">
                  <Loader2 className="w-5 h-5 animate-spin text-primary" />
                  <span className="text-sm text-muted-foreground">
                    正在验证 API 连接并创建配置...
                  </span>
                </div>
              )}
            </div>

            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => handleDialogOpenChange(false)}
                disabled={isCreating}
              >
                取消
              </Button>
              <Button
                onClick={handleCreateConfig}
                disabled={isCreating || !isFormValid()}
              >
                {isCreating ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    验证中...
                  </>
                ) : (
                  <>
                    <Save className="w-4 h-4 mr-2" />
                    创建配置
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-6 no-scrollbar">
        {llmConfigsLoading ? (
          <div className="flex items-center justify-center h-64">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : llmConfigsError ? (
          <Card className="p-12 text-center border-destructive">
            <X className="w-16 h-16 mx-auto mb-4 text-destructive" />
            <h3 className="text-lg font-semibold mb-2">加载失败</h3>
            <p className="text-sm text-muted-foreground mb-6">{llmConfigsError}</p>
            <Button onClick={loadLLMConfigs} variant="outline">
              <RotateCcw className="w-4 h-4 mr-2" />
              重试
            </Button>
          </Card>
        ) : llmConfigs.length === 0 ? (
          <Card className="p-12 text-center">
            <Server className="w-16 h-16 mx-auto mb-4 text-muted-foreground/30" />
            <h3 className="text-lg font-semibold mb-2">还没有 LLM 配置</h3>
            <p className="text-sm text-muted-foreground mb-6 max-w-md mx-auto">
              添加 LLM 配置以启用 AI Agent 审计功能。支持任何兼容 OpenAI API 格式的服务。
            </p>
            <Button onClick={() => setIsCreateDialogOpen(true)}>
              <Plus className="w-4 h-4 mr-2" />
              添加第一个配置
            </Button>
          </Card>
        ) : (
          <div className="max-w-4xl mx-auto space-y-4">
            {llmConfigs.map((config) => {
              const testResult = testResults[config.id]

              return (
                <Card key={config.id} className="p-5">
                  <div className="flex items-start justify-between gap-4">
                    {/* 左侧：图标和信息 */}
                    <div className="flex items-start gap-4 flex-1">
                      <div className="p-3 rounded-lg bg-primary/10">
                        <Server className="w-6 h-6 text-primary" />
                      </div>

                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <h3 className="font-semibold text-base">{config.provider}</h3>
                          {config.id === defaultLLMConfigId && (
                            <Badge variant="default" className="text-[10px]">
                              <Sparkles className="w-3 h-3 mr-1" />
                              默认
                            </Badge>
                          )}
                          {!config.enabled && (
                            <Badge variant="outline" className="text-[10px]">已禁用</Badge>
                          )}
                          {testResult?.success ? (
                            <Badge variant="outline" className="text-[10px] text-green-500 border-green-500">
                              <Check className="w-3 h-3 mr-1" />
                              连接成功
                            </Badge>
                          ) : testResult && !testResult.success ? (
                            <Badge variant="outline" className="text-[10px] text-red-500 border-red-500">
                              <X className="w-3 h-3 mr-1" />
                              连接失败
                            </Badge>
                          ) : null}
                        </div>

                        <p className="text-sm font-medium mb-1">{config.model}</p>

                        <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-muted-foreground mb-3">
                          <div>温度: <span className="text-foreground">{config.temperature?.toFixed(1) ?? 'N/A'}</span></div>
                          <div>最大令牌: <span className="text-foreground">{config.maxTokens ?? 'N/A'}</span></div>
                          <div className="col-span-2">
                            端点: <span className="font-mono text-foreground">{config.apiEndpoint}</span>
                          </div>
                          <div>密钥: <span className="font-mono text-foreground">{config.apiKey}</span></div>
                          <div>状态: <span className={config.enabled ? "text-green-500" : "text-muted-foreground"}>
                            {config.enabled ? "已启用" : "已禁用"}
                          </span></div>
                        </div>

                        {/* 错误信息 */}
                        {testResult && !testResult.success && (
                          <div className="mt-2 p-2 bg-destructive/10 border border-destructive/20 rounded text-xs text-destructive">
                            {testResult.message}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 右侧：操作按钮 */}
                    <div className="flex items-center gap-2">
                      {/* 测试按钮 */}
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleTestConfig(config)}
                        disabled={testingConfigId === config.id || !config.enabled}
                        title="测试连接"
                      >
                        {testingConfigId === config.id ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          <Check className="w-4 h-4" />
                        )}
                      </Button>

                      {/* 设为默认 */}
                      {config.id !== defaultLLMConfigId && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleSetDefault(config.id)}
                          title="设为默认"
                        >
                          <Sparkles className="w-4 h-4" />
                        </Button>
                      )}

                      {/* 删除 */}
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-destructive hover:text-destructive"
                        onClick={() => handleDeleteConfig(config.id, config.provider)}
                        title="删除配置"
                      >
                        <Trash2 className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </Card>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
