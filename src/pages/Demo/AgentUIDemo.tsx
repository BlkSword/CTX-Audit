/**
 * UI 组件展示 Demo 页面
 *
 * 展示项目中所有UI组件的使用方法和样式
 */

import { useState, useEffect, useCallback } from 'react'
import {
  Play, Square, RotateCcw, Sparkles, Palette, Layout,
  Eye, CheckCircle, XCircle, AlertTriangle, Info, Settings,
  Trash2, Edit, Plus, Minus, Search, Filter, Download,
  Upload, Save, RefreshCw, ChevronDown, ExternalLink,
  Mail, Phone, User, Lock, Key, Bell, Zap, Shield, Code,
  FileText, FolderOpen, Globe, Github, Twitter, Linkedin,
  LogOut as LogoutIcon,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Switch } from '@/components/ui/switch'
import { Slider } from '@/components/ui/slider'
import { Checkbox } from '@/components/ui/checkbox'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Progress } from '@/components/ui/progress'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useToast } from '@/hooks/use-toast'
import { alertDialog, confirmDialog } from '@/components/ui/confirm-dialog'
import { AuditHeader } from '@/components/audit/AuditHeader'
import { ActivityLogPanel } from '@/components/audit/ActivityLogPanel'
import { StatusCards } from '@/components/audit/StatusCards'
import { AgentTreePanelNew } from '@/components/audit/AgentTreePanelNew'
import type { LogItem } from '@/shared/types'
import type { AgentTreeNode } from '@/pages/AgentAudit/types'

// 模拟日志数据
const mockLogs: LogItem[] = [
  {
    id: '1',
    type: 'info',
    agent_type: 'SYSTEM',
    content: '初始化审计任务...',
    timestamp: Date.now() - 100000,
    data: {},
  },
  {
    id: '2',
    type: 'thinking',
    agent_type: 'ORCHESTRATOR',
    content: '开始分析项目结构',
    timestamp: Date.now() - 90000,
    data: {},
  },
  {
    id: '3',
    type: 'tool',
    agent_type: 'RECON',
    content: '执行文件扫描: src/**/*.ts',
    timestamp: Date.now() - 80000,
    data: {},
  },
]

// 模拟Agent树数据
const mockAgentTree: { roots: AgentTreeNode[] } = {
  roots: [
    {
      agent_id: 'orch-001',
      agent_type: 'ORCHESTRATOR',
      status: 'running',
      task: '协调所有Agent进行安全审计',
      parent_id: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      children: [],
    },
  ],
}

export function AgentUIDemo() {
  const toast = useToast()
  const [activeTab, setActiveTab] = useState('audit')
  const [inputValue, setInputValue] = useState('')
  const [textareaValue, setTextareaValue] = useState('')
  const [switchValue, setSwitchValue] = useState(true)
  const [sliderValue, setSliderValue] = useState([50])
  const [checkboxValue, setCheckboxValue] = useState(true)
  const [selectValue, setSelectValue] = useState('option1')
  const [progress, setProgress] = useState(33)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [isSimulating, setIsSimulating] = useState(false)
  const [currentTheme, setCurrentTheme] = useState(0)

  const themes = [
    { name: '默认', bg: '#121212', border: '#333333', primary: '#F97316' },
    { name: '深蓝', bg: '#0a1628', border: '#1e3a5f', primary: '#3b82f6' },
    { name: '深紫', bg: '#1a0a2e', border: '#4a1a6b', primary: '#a855f7' },
  ]

  // 模拟进度动画
  useEffect(() => {
    if (isSimulating && progress < 100) {
      const timer = setTimeout(() => setProgress(p => Math.min(100, p + 1)), 100)
      return () => clearTimeout(timer)
    }
  }, [progress, isSimulating])

  // Toast演示函数
  const showToast = (type: 'success' | 'error' | 'info' | 'warning') => {
    const messages = {
      success: '操作成功完成！',
      error: '操作失败，请重试。',
      info: '这是一条信息提示。',
      warning: '请注意潜在风险。',
    }
    toast[type](messages[type])
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <div className="border-b px-6 py-4 bg-muted/20">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Sparkles className="w-6 h-6 text-primary" />
            <div>
              <h1 className="text-2xl font-bold">UI 组件展示</h1>
              <p className="text-sm text-muted-foreground">
                完整的 shadcn/ui 组件库演示
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline">v1.0.0</Badge>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCurrentTheme((c) => (c + 1) % themes.length)}
            >
              <Palette className="w-4 h-4 mr-2" />
              {themes[currentTheme].name}主题
            </Button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="max-w-7xl mx-auto">
          <TabsList className="grid w-full grid-cols-5 lg:w-auto">
            <TabsTrigger value="audit">审计组件</TabsTrigger>
            <TabsTrigger value="buttons">按钮</TabsTrigger>
            <TabsTrigger value="forms">表单</TabsTrigger>
            <TabsTrigger value="feedback">反馈</TabsTrigger>
            <TabsTrigger value="navigation">导航</TabsTrigger>
          </TabsList>

          {/* 审计组件 */}
          <TabsContent value="audit" className="space-y-6 mt-6">
            <section>
              <h2 className="text-xl font-semibold mb-4">完整审计界面</h2>
              <div className="rounded-lg border overflow-hidden" style={{ height: '700px' }}>
                <AuditHeader
                  taskName="UI组件演示"
                  status="running"
                  progress={progress}
                  isServiceHealthy={true}
                  logCount={mockLogs.length}
                  onStart={() => setIsSimulating(true)}
                  onCancel={() => setIsSimulating(false)}
                  onExport={async () => {
                    await alertDialog({
                      title: '导出报告',
                      description: '导出报告功能演示',
                      confirmText: '确定',
                      type: 'info',
                    })
                  }}
                  onNewAudit={() => setProgress(0)}
                />
                <div className="flex-1 flex overflow-hidden">
                  <div className="w-[60%] border-r">
                    <ActivityLogPanel logs={mockLogs} autoScroll={true} isLoading={false} />
                  </div>
                  <div className="w-[40%] flex flex-col">
                    <div className="flex-1 border-b overflow-hidden">
                      <AgentTreePanelNew
                        treeData={mockAgentTree}
                        loading={false}
                        selectedAgentId={null}
                        onSelectAgent={() => {}}
                      />
                    </div>
                    <StatusCards
                      progress={progress}
                      scannedFiles={Math.floor(1000 * (progress / 100))}
                      totalFiles={1000}
                      iterations={10}
                      toolCalls={50}
                      tokens={20000}
                      findings={3}
                      securityScore={70}
                    />
                  </div>
                </div>
              </div>
            </section>
          </TabsContent>

          {/* 按钮 */}
          <TabsContent value="buttons" className="space-y-6 mt-6">
            <section>
              <h2 className="text-xl font-semibold mb-4">按钮变体</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-wrap gap-4">
                    <Button>默认按钮</Button>
                    <Button variant="secondary">次要按钮</Button>
                    <Button variant="destructive">危险按钮</Button>
                    <Button variant="outline">边框按钮</Button>
                    <Button variant="ghost">幽灵按钮</Button>
                    <Button variant="link">链接按钮</Button>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">按钮尺寸</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-4">
                    <Button size="sm">小按钮</Button>
                    <Button size="default">默认</Button>
                    <Button size="lg">大按钮</Button>
                    <Button size="icon">
                      <Settings className="w-4 h-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">按钮状态</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-wrap gap-4">
                    <Button>正常</Button>
                    <Button disabled>禁用</Button>
                    <Button>
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      加载中
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">带图标的按钮</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-wrap gap-4">
                    <Button><Plus className="w-4 h-4 mr-2" />新建</Button>
                    <Button><Edit className="w-4 h-4 mr-2" />编辑</Button>
                    <Button variant="destructive"><Trash2 className="w-4 h-4 mr-2" />删除</Button>
                    <Button variant="outline"><Download className="w-4 h-4 mr-2" />下载</Button>
                    <Button variant="outline"><Upload className="w-4 h-4 mr-2" />上传</Button>
                    <Button><Save className="w-4 h-4 mr-2" />保存</Button>
                    <Button variant="secondary"><RefreshCw className="w-4 h-4 mr-2" />刷新</Button>
                  </div>
                </CardContent>
              </Card>
            </section>
          </TabsContent>

          {/* 表单 */}
          <TabsContent value="forms" className="space-y-6 mt-6">
            <section>
              <h2 className="text-xl font-semibold mb-4">输入框</h2>
              <div className="grid gap-6 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>基础输入框</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label>用户名</Label>
                      <Input
                        value={inputValue}
                        onChange={(e) => setInputValue(e.target.value)}
                        placeholder="输入用户名..."
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>带图标</Label>
                      <div className="relative">
                        <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input className="pl-10" placeholder="带图标的输入框..." />
                      </div>
                    </div>
                    <div className="space-y-2">
                      <Label>禁用状态</Label>
                      <Input disabled placeholder="禁用的输入框..." />
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>文本域</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label>描述</Label>
                      <Textarea
                        value={textareaValue}
                        onChange={(e) => setTextareaValue(e.target.value)}
                        placeholder="输入多行文本..."
                        rows={4}
                      />
                    </div>
                    <div className="text-sm text-muted-foreground">
                      字符数: {textareaValue.length}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">选择器</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="grid gap-6 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label>单选</Label>
                      <Select value={selectValue} onValueChange={setSelectValue}>
                        <SelectTrigger>
                          <SelectValue placeholder="选择一个选项" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="option1">选项 1</SelectItem>
                          <SelectItem value="option2">选项 2</SelectItem>
                          <SelectItem value="option3">选项 3</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">开关与滑块</h2>
              <div className="grid gap-6 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>开关</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between">
                      <Label>启用通知</Label>
                      <Switch checked={switchValue} onCheckedChange={setSwitchValue} />
                    </div>
                    <div className="flex items-center justify-between">
                      <Label>自动保存</Label>
                      <Switch />
                    </div>
                    <div className="flex items-center justify-between">
                      <Label>启用调试模式</Label>
                      <Switch disabled />
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>滑块</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label>音量: {sliderValue[0]}%</Label>
                      <Slider value={sliderValue} onValueChange={setSliderValue} />
                    </div>
                    <div className="space-y-2">
                      <Label>步进</Label>
                      <Slider value={[33]} max={100} step={25} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">复选框</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2">
                      <Checkbox checked={checkboxValue} onCheckedChange={setCheckboxValue} />
                      <Label>我同意服务条款和隐私政策</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox />
                      <Label>订阅邮件通知</Label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox disabled />
                      <Label className="text-muted-foreground">禁用的选项</Label>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </section>
          </TabsContent>

          {/* 反馈 */}
          <TabsContent value="feedback" className="space-y-6 mt-6">
            <section>
              <h2 className="text-xl font-semibold mb-4">徽章 (Badge)</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-wrap gap-3">
                    <Badge>默认</Badge>
                    <Badge variant="secondary">次要</Badge>
                    <Badge variant="destructive">危险</Badge>
                    <Badge variant="outline">边框</Badge>
                    <Badge className="bg-emerald-500">成功</Badge>
                    <Badge className="bg-amber-500">警告</Badge>
                    <Badge className="bg-blue-500">信息</Badge>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">Toast 通知</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-wrap gap-3">
                    <Button onClick={() => showToast('success')}>
                      <CheckCircle className="w-4 h-4 mr-2" />
                      成功
                    </Button>
                    <Button variant="destructive" onClick={() => showToast('error')}>
                      <XCircle className="w-4 h-4 mr-2" />
                      错误
                    </Button>
                    <Button variant="secondary" onClick={() => showToast('info')}>
                      <Info className="w-4 h-4 mr-2" />
                      信息
                    </Button>
                    <Button variant="outline" onClick={() => showToast('warning')}>
                      <AlertTriangle className="w-4 h-4 mr-2" />
                      警告
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">进度条</h2>
              <Card>
                <CardContent className="pt-6 space-y-4">
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>默认进度</span>
                      <span>{progress}%</span>
                    </div>
                    <Progress value={progress} />
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>不确定进度</span>
                    </div>
                    <Progress />
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>已完成</span>
                      <span>100%</span>
                    </div>
                    <Progress value={100} />
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">确认对话框</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="grid gap-4 md:grid-cols-2">
                    <Button
                      variant="destructive"
                      onClick={async () => {
                        const confirmed = await confirmDialog({
                          title: '删除项目',
                          description: '确定要删除此项目吗？此操作不可恢复。',
                          confirmText: '删除',
                          cancelText: '取消',
                          type: 'destructive',
                        })
                        toast.success(confirmed ? '已删除' : '已取消')
                      }}
                    >
                      <Trash2 className="w-4 h-4 mr-2" />
                      删除确认
                    </Button>
                    <Button
                      variant="outline"
                      onClick={async () => {
                        await alertDialog({
                          title: '系统通知',
                          description: '这是一条重要通知信息。',
                          confirmText: '知道了',
                          type: 'info',
                        })
                      }}
                    >
                      <Info className="w-4 h-4 mr-2" />
                      信息提示
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">对话框</h2>
              <Card>
                <CardContent className="pt-6">
                  <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
                    <DialogTrigger asChild>
                      <Button>打开对话框</Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>对话框标题</DialogTitle>
                        <DialogDescription>
                          这是对话框的描述内容，可以包含更多信息说明。
                        </DialogDescription>
                      </DialogHeader>
                      <div className="py-4">
                        <p>这是对话框的主要内容区域。</p>
                      </div>
                      <DialogFooter>
                        <Button variant="outline" onClick={() => setDialogOpen(false)}>
                          取消
                        </Button>
                        <Button onClick={() => {
                          setDialogOpen(false)
                          toast.success('已确认')
                        }}>
                          确认
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </CardContent>
              </Card>
            </section>
          </TabsContent>

          {/* 导航 */}
          <TabsContent value="navigation" className="space-y-6 mt-6">
            <section>
              <h2 className="text-xl font-semibold mb-4">卡片</h2>
              <div className="grid gap-6 md:grid-cols-3">
                <Card>
                  <CardHeader>
                    <CardTitle>卡片标题</CardTitle>
                    <CardDescription>卡片描述信息</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      这是卡片的主要内容区域，可以放置任何组件或信息。
                    </p>
                  </CardContent>
                  <CardFooter>
                    <Button className="w-full">操作</Button>
                  </CardFooter>
                </Card>

                <Card className="border-primary">
                  <CardHeader>
                    <CardTitle>高亮卡片</CardTitle>
                    <CardDescription>使用主题色边框</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      强调显示的卡片样式。
                    </p>
                  </CardContent>
                </Card>

                <Card className="bg-muted">
                  <CardHeader>
                    <CardTitle>背景卡片</CardTitle>
                    <CardDescription>使用背景色</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm">
                      使用背景色的卡片样式。
                    </p>
                  </CardContent>
                </Card>
              </div>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">下拉菜单</h2>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex flex-wrap gap-4">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline">
                          <Settings className="w-4 h-4 mr-2" />
                          设置
                          <ChevronDown className="w-4 h-4 ml-2" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent>
                        <DropdownMenuLabel>我的账户</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem>
                          <User className="w-4 h-4 mr-2" />
                          个人资料
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Key className="w-4 h-4 mr-2" />
                          API 密钥
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Bell className="w-4 h-4 mr-2" />
                          通知设置
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem>
                          <LogoutIcon className="w-4 h-4 mr-2" />
                          退出登录
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>

                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline">
                          <ExternalLink className="w-4 h-4 mr-2" />
                          链接
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent>
                        <DropdownMenuItem>
                          <Globe className="w-4 h-4 mr-2" />
                          官网
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Github className="w-4 h-4 mr-2" />
                          GitHub
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Twitter className="w-4 h-4 mr-2" />
                          Twitter
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Linkedin className="w-4 h-4 mr-2" />
                          LinkedIn
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">标签页</h2>
              <Card>
                <CardContent className="pt-6">
                  <Tabs defaultValue="tab1">
                    <TabsList>
                      <TabsTrigger value="tab1">标签 1</TabsTrigger>
                      <TabsTrigger value="tab2">标签 2</TabsTrigger>
                      <TabsTrigger value="tab3">标签 3</TabsTrigger>
                    </TabsList>
                    <TabsContent value="tab1" className="mt-4">
                      <p className="text-sm text-muted-foreground">标签 1 的内容</p>
                    </TabsContent>
                    <TabsContent value="tab2" className="mt-4">
                      <p className="text-sm text-muted-foreground">标签 2 的内容</p>
                    </TabsContent>
                    <TabsContent value="tab3" className="mt-4">
                      <p className="text-sm text-muted-foreground">标签 3 的内容</p>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            </section>

            <section>
              <h2 className="text-xl font-semibold mb-4">滚动区域</h2>
              <Card>
                <CardHeader>
                  <CardTitle>长内容滚动</CardTitle>
                  <CardDescription>使用自定义滚动条</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-40 w-full rounded border p-4">
                    <div className="space-y-2">
                      {Array.from({ length: 20 }).map((_, i) => (
                        <div key={i} className="text-sm">
                          滚动内容行 {i + 1} - 这是一段示例文本，用于演示滚动效果。
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </section>
          </TabsContent>
        </Tabs>
      </div>

      {/* Footer */}
      <footer className="border-t px-6 py-4 text-center text-sm text-muted-foreground">
        <p>CTX-Audit UI 组件展示 v1.0.0</p>
        <p className="text-xs mt-1">基于 shadcn/ui 和 Tailwind CSS 构建</p>
      </footer>
    </div>
  )
}

export default AgentUIDemo
