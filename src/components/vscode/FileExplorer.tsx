/**
 * VSCode 风格文件浏览器
 * 侧边栏中的资源管理器面板
 */

import { useState } from 'react'
import { VSCodeIcon } from './ActivityBar'

// ==================== 类型定义 ====================

interface FileNode {
  id: string
  name: string
  type: 'file' | 'folder'
  children?: FileNode[]
  collapsed?: boolean
}

// ==================== 示例数据 ====================

const SAMPLE_TREE: FileNode[] = [
  {
    id: 'src',
    name: 'src',
    type: 'folder',
    collapsed: false,
    children: [
      {
        id: 'src/components',
        name: 'components',
        type: 'folder',
        collapsed: false,
        children: [
          { id: 'src/App.tsx', name: 'App.tsx', type: 'file' },
          { id: 'src/main.tsx', name: 'main.tsx', type: 'file' },
        ],
      },
      {
        id: 'src/pages',
        name: 'pages',
        type: 'folder',
        collapsed: true,
        children: [
          { id: 'src/pages/Home.tsx', name: 'Home.tsx', type: 'file' },
          { id: 'src/pages/About.tsx', name: 'About.tsx', type: 'file' },
        ],
      },
      { id: 'src/index.css', name: 'index.css', type: 'file' },
      { id: 'src/vite-env.d.ts', name: 'vite-env.d.ts', type: 'file' },
    ],
  },
  {
    id: 'package.json',
    name: 'package.json',
    type: 'file',
  },
  {
    id: 'tsconfig.json',
    name: 'tsconfig.json',
    type: 'file',
  },
  {
    id: 'vite.config.ts',
    name: 'vite.config.ts',
    type: 'file',
  },
]

// ==================== 文件树节点组件 ====================

interface TreeNodeProps {
  node: FileNode
  level: number
  onToggle?: (nodeId: string) => void
  onSelect?: (node: FileNode) => void
  selectedId?: string
}

function TreeNode({ node, level, onToggle, onSelect, selectedId }: TreeNodeProps) {
  const paddingLeft = level * 12 + 8
  const isFolder = node.type === 'folder'
  const hasChildren = isFolder && node.children && node.children.length > 0
  const isCollapsed = node.collapsed
  const isSelected = selectedId === node.id

  const handleClick = () => {
    if (isFolder && hasChildren) {
      onToggle?.(node.id)
    }
    onSelect?.(node)
  }

  const getIconName = () => {
    if (isFolder) {
      return isCollapsed ? 'folder-open' : 'chevron-down'
    }
    // 根据文件扩展名返回图标
    const ext = node.name.split('.').pop()
    if (ext === 'tsx' || ext === 'ts') return 'file-code'
    if (ext === 'json') return 'chevron-right'
    return 'chevron-right'
  }

  return (
    <div>
      {/* 节点行 */}
      <div
        className={`
          flex items-center gap-1 py-0.5 pr-2 cursor-pointer
          hover:bg-[var(--vscode-list-hoverBackground)]
          ${isSelected ? 'bg-[var(--vscode-list-activeSelectionBackground)] text-[var(--vscode-list-activeSelectionForeground)]' : ''}
        `}
        style={{ paddingLeft: `${paddingLeft}px` }}
        onClick={handleClick}
      >
        {/* 展开/折叠图标 */}
        {hasChildren && (
          <VSCodeIcon
            name={isCollapsed ? 'chevron-right' : 'chevron-down'}
            className="w-4 h-4 text-[var(--vscode-foreground)] opacity-70"
          />
        )}
        {!hasChildren && <span className="w-4 h-4" />}

        {/* 文件/文件夹图标 */}
        <VSCodeIcon
          name={getIconName()}
          className={`w-4 h-4 ${isFolder ? 'text-[var(--vscode-textLink-foreground)]' : ''}`}
        />

        {/* 文件名 */}
        <span className="text-sm truncate flex-1">{node.name}</span>
      </div>

      {/* 子节点 */}
      {isFolder && !isCollapsed && hasChildren && (
        <div>
          {node.children!.map((child) => (
            <TreeNode
              key={child.id}
              node={child}
              level={level + 1}
              onToggle={onToggle}
              onSelect={onSelect}
              selectedId={selectedId}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ==================== 文件浏览器组件 ====================

interface FileExplorerProps {
  projectPath?: string
  onFileSelect?: (filePath: string) => void
}

export function FileExplorer({ projectPath, onFileSelect }: FileExplorerProps) {
  const [tree, setTree] = useState<FileNode[]>(SAMPLE_TREE)
  const [selectedId, setSelectedId] = useState<string>()

  const handleToggle = (nodeId: string) => {
    const updateNode = (nodes: FileNode[]): FileNode[] => {
      return nodes.map((node) => {
        if (node.id === nodeId && node.type === 'folder') {
          return { ...node, collapsed: !node.collapsed }
        }
        if (node.children) {
          return { ...node, children: updateNode(node.children) }
        }
        return node
      })
    }
    setTree(updateNode(tree))
  }

  const handleSelect = (node: FileNode) => {
    setSelectedId(node.id)
    if (node.type === 'file') {
      onFileSelect?.(node.id)
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* 标题栏 */}
      <div className="flex items-center justify-between px-3 py-1.5 text-xs font-semibold text-[var(--vscode-sideBarSectionHeader-foreground)] uppercase tracking-wider">
        <span>资源管理器</span>
        <div className="flex items-center gap-1">
          <button className="p-1 hover:bg-[var(--vscode-toolbar-hoverBackground)] rounded">
            <VSCodeIcon name="horizontal-more" className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* 项目名称 */}
      {projectPath && (
        <div className="px-3 py-1">
          <div className="flex items-center gap-1 text-sm text-[var(--vscode-sideBar-foreground)]">
            <VSCodeIcon name="folder-open" className="w-4 h-4" />
            <span className="font-semibold">{projectPath.split('/').pop()}</span>
          </div>
        </div>
      )}

      {/* 文件树 */}
      <div className="flex-1 overflow-auto vs-scrollbar">
        {tree.map((node) => (
          <TreeNode
            key={node.id}
            node={node}
            level={0}
            onToggle={handleToggle}
            onSelect={handleSelect}
            selectedId={selectedId}
          />
        ))}
      </div>
    </div>
  )
}

export default FileExplorer
