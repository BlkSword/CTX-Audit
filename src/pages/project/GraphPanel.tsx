/**
 * GraphPanel - 代码图谱面板
 */

import { useState, useEffect, useMemo } from 'react'
import ReactFlow, { Background, Controls, useNodesState, useEdgesState } from 'reactflow'
import 'reactflow/dist/style.css'
import { Network, Search, RefreshCw, LayoutGrid, Database } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import CodeGraphNode from '@/components/graph/CodeGraphNode'
import { api } from '@/shared/api/client'
import { useProjectStore } from '@/stores/projectStore'
import { useUIStore } from '@/stores/uiStore'
import { calculateGraphLayout, assignEdgeHandles } from '@/lib/graphLayout'

export function GraphPanel() {
  const { currentProject } = useProjectStore()
  const { addLog } = useUIStore()

  const [graphNodes, setGraphNodes, onNodesChange] = useNodesState([])
  const [graphEdges, setGraphEdges, onEdgesChange] = useEdgesState([])
  const [rfInstance, setRfInstance] = useState<any>(null)
  const [graphSearchQuery, setGraphSearchQuery] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [needsIndex, setNeedsIndex] = useState(false)

  const nodeTypes = useMemo(() => ({
    codeNode: CodeGraphNode,
  }), [])

  const buildIndex = async () => {
    if (!currentProject) return

    try {
      addLog('正在构建 AST 索引...', 'system')
      // 传递 project_id 以支持从数据库恢复缓存
      const result = await api.invoke('build_ast_index', {
        project_path: currentProject.path,
        project_id: currentProject.id,
      }) as { message: string }
      addLog(`AST 索引构建完成: ${result.message}`, 'system')
      setNeedsIndex(false)

      // 构建完成后自动加载图谱
      await loadGraph()
    } catch (err) {
      addLog(`构建索引失败: ${err}`, 'system')
    }
  }

  const loadGraph = async () => {
    if (!currentProject) {
      addLog('请先打开一个项目', 'system')
      return
    }

    setIsLoading(true)
    setGraphNodes([])
    setGraphEdges([])

    try {
      addLog('正在获取图谱数据...', 'system')
      // 传递项目信息以支持从数据库加载缓存
      const resultJson = await api.invoke('get_knowledge_graph', {
        limit: 100,
        project_id: currentProject.id,
        project_path: currentProject.path,
      })

      let data
      if (typeof resultJson === 'string') {
        data = JSON.parse(resultJson)
      } else {
        data = resultJson
      }

      if (data.graph) {
        addLog(`成功获取图谱数据: ${data.graph.nodes.length} 个节点, ${data.graph.edges.length} 条边`, 'system')

        const rawNodes = data.graph.nodes.map((node: any) => ({
          ...node,
          type: 'codeNode',
          data: {
            label: `${node.label} (${node.type})`,
            type: node.type,
            originalLabel: node.label
          }
        }))

        const rawEdges = data.graph.edges.map((edge: any) => ({
          ...edge,
          animated: true,
          style: { stroke: '#64748b' }
        }))

        const layoutedNodes = calculateGraphLayout(rawNodes, rawEdges)
        const layoutedEdges = assignEdgeHandles(layoutedNodes, rawEdges)

        setGraphNodes(layoutedNodes)
        setGraphEdges(layoutedEdges)
        setNeedsIndex(false)
      }
    } catch (e: any) {
      console.error('Failed to fetch graph', e)
      // 检查是否是缓存未加载的错误
      if (e.message?.includes('No cache loaded') || String(e).includes('No cache loaded')) {
        addLog('需要先构建 AST 索引', 'system')
        setNeedsIndex(true)
      } else {
        addLog(`获取图谱失败: ${e}`, 'system')
      }
    } finally {
      setIsLoading(false)
    }
  }

  const refreshGraph = async () => {
    await loadGraph()
  }

  useEffect(() => {
    if (currentProject) {
      loadGraph()
    }
  }, [currentProject])

  const handleGraphSearch = (query: string) => {
    setGraphSearchQuery(query)
    if (!query.trim()) {
      setGraphNodes((nds) =>
        nds.map((node) => ({
          ...node,
          data: {
            ...node.data,
            style: {
              ...node.data?.style,
              border: '1px solid #94a3b8',
              boxShadow: 'none',
            }
          }
        }))
      )
      return
    }

    const lowerQuery = query.toLowerCase()
    const matchingNodes: any[] = []

    setGraphNodes((nds) =>
      nds.map((node) => {
        const label = node.data?.label || ''
        const originalLabel = node.data?.originalLabel || ''
        const isMatch = label.toLowerCase().includes(lowerQuery) ||
          originalLabel.toLowerCase().includes(lowerQuery)

        if (isMatch) {
          matchingNodes.push(node)
        }

        return {
          ...node,
          data: {
            ...node.data,
            style: {
              ...node.data?.style,
              border: isMatch ? '2px solid #ef4444' : '1px solid #94a3b8',
              boxShadow: isMatch ? '0 0 10px rgba(239, 68, 68, 0.5)' : 'none',
            }
          }
        }
      })
    )

    if (matchingNodes.length > 0 && rfInstance) {
      rfInstance.fitView({ nodes: matchingNodes, duration: 800, padding: 0.2 })
    }
  }

  return (
    <div className="h-full w-full bg-background text-foreground flex flex-col">
      {/* Header */}
      <div className="h-12 border-b border-border/40 flex items-center justify-between px-4 bg-muted/10">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-primary" />
          <span className="text-sm font-semibold">代码知识图谱</span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="搜索节点..."
              className="h-8 w-56 pl-8 text-xs bg-background border-border/50"
              value={graphSearchQuery}
              onChange={(e) => handleGraphSearch(e.target.value)}
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            className="h-8 text-xs"
            onClick={refreshGraph}
            disabled={isLoading}
          >
            {isLoading ? (
              <RefreshCw className="w-3.5 h-3.5 mr-1.5 animate-spin" />
            ) : (
              <LayoutGrid className="w-3.5 h-3.5 mr-1.5" />
            )}
            刷新
          </Button>
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1">
        {needsIndex ? (
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
            <Database className="w-16 h-16 mb-4 opacity-20" />
            <p className="text-lg font-medium">需要构建 AST 索引</p>
            <p className="text-sm mt-2 mb-4">首次使用需要分析项目代码结构</p>
            <Button onClick={buildIndex} disabled={isLoading}>
              {isLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  构建中...
                </>
              ) : (
                <>
                  <Database className="w-4 h-4 mr-2" />
                  构建索引
                </>
              )}
            </Button>
          </div>
        ) : graphNodes.length === 0 && !isLoading ? (
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
            <Network className="w-16 h-16 mb-4 opacity-20" />
            <p className="text-lg font-medium">图谱数据为空</p>
            <p className="text-sm mt-2">点击刷新按钮重新加载图谱</p>
          </div>
        ) : (
          <ReactFlow
            nodes={graphNodes}
            edges={graphEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            onInit={setRfInstance}
          >
            <Background />
            <Controls />
          </ReactFlow>
        )}
      </div>
    </div>
  )
}
