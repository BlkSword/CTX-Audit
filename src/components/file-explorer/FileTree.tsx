import { useState, useCallback, memo, useEffect } from 'react'
import {
  ChevronRight,
  ChevronDown,
  Folder,
  FolderOpen,
  FileCode,
  FileJson,
  FileText,
  FileType,
  FileType2,
  Image,
  Music,
  Video,
  Archive,
  GitBranch,
} from 'lucide-react'
import { tauriApi } from '@/shared/api/tauri-client'

export interface FileNode {
  name: string
  path: string
  type: 'file' | 'folder'
  children?: FileNode[]
  // 懒加载相关
  loaded?: boolean
  hasChildren?: boolean
}

interface FileTreeProps {
  nodes: FileNode[]
  selectedPath: string | null
  onSelect: (path: string | null) => void
}

// 根据文件扩展名获取图标
function getFileIcon(filename: string) {
  const ext = filename.split('.').pop()?.toLowerCase() || ''

  // 代码文件
  const codeExts = ['js', 'jsx', 'ts', 'tsx', 'vue', 'svelte', 'astro']
  if (codeExts.includes(ext)) return <FileType className="w-3.5 h-3.5 text-blue-400" />

  // 样式文件
  const styleExts = ['css', 'scss', 'sass', 'less', 'styl']
  if (styleExts.includes(ext)) return <FileType2 className="w-3.5 h-3.5 text-pink-400" />

  // JSON/YAML
  if (['json', 'yaml', 'yml', 'toml'].includes(ext)) {
    return <FileJson className="w-3.5 h-3.5 text-yellow-400" />
  }

  // Markdown/文本
  if (['md', 'markdown', 'txt', 'rst'].includes(ext)) {
    return <FileText className="w-3.5 h-3.5 text-blue-300" />
  }

  // 图片
  if (['png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp'].includes(ext)) {
    return <Image className="w-3.5 h-3.5 text-purple-400" />
  }

  // 音频
  if (['mp3', 'wav', 'ogg', 'flac'].includes(ext)) {
    return <Music className="w-3.5 h-3.5 text-green-400" />
  }

  // 视频
  if (['mp4', 'avi', 'mkv', 'mov', 'webm'].includes(ext)) {
    return <Video className="w-3.5 h-3.5 text-red-400" />
  }

  // 压缩文件
  if (['zip', 'tar', 'gz', '7z', 'rar'].includes(ext)) {
    return <Archive className="w-3.5 h-3.5 text-orange-400" />
  }

  // Git
  if (filename === '.git') {
    return <GitBranch className="w-3.5 h-3.5 text-orange-500" />
  }

  // 默认代码图标
  return <FileCode className="w-3.5 h-3.5 opacity-70" />
}

// 构建扁平文件树
function buildFileTree(files: any[]): FileNode[] {
  const root: FileNode[] = []

  files.forEach((file: any) => {
    const fileName = file.name
    const filePath = file.path
    const isDir = file.is_dir

    if (isDir) {
      // 文件夹节点
      const node: FileNode = {
        name: fileName,
        path: filePath,
        type: 'folder',
        children: [],
        loaded: false,
      }
      root.push(node)
    } else {
      // 文件节点
      const node: FileNode = {
        name: fileName,
        path: filePath,
        type: 'file',
      }
      root.push(node)
    }
  })

  // 排序：文件夹在前，然后按名称排序
  root.sort((a, b) => {
    if (a.type === 'folder' && b.type === 'folder') {
      return a.name.localeCompare(b.name)
    }
    if (a.type === 'folder') return -1
    if (b.type === 'folder') return 1
    return a.name.localeCompare(b.name)
  })

  return root
}

const FileTreeNode = memo(({
  node,
  level,
  selectedPath,
  onSelect,
  onDataChange,
}: {
  node: FileNode
  level: number
  selectedPath: string | null
  onSelect: (path: string | null) => void
  onDataChange?: () => void
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [children, setChildren] = useState<FileNode[]>(node.children || [])
  const isSelected = selectedPath === node.path
  const isFolder = node.type === 'folder'

  const handleClick = useCallback(async () => {
    if (!isFolder) {
      // 文件：选择文件
      onSelect(node.path)
      return
    }

    // 文件夹：切换展开/折叠
    if (isOpen) {
      setIsOpen(false)
      return
    }

    // 如果已经加载过子内容，直接展开
    if (node.loaded && children.length > 0) {
      setIsOpen(true)
      return
    }

    // 懒加载子内容
    setIsLoading(true)
    try {
      const files = await tauriApi.listDirectory(node.path)
      const newChildren = buildFileTree(files)

      setChildren(newChildren)
      setIsOpen(true)
      setIsLoading(false)

      // 通知父组件更新
      onDataChange?.()
    } catch (error) {
      console.error('Failed to load directory:', error)
      setIsLoading(false)
      // 设置为已加载，但子项为空
      setChildren([])
      node.loaded = true
    }
  }, [node, isFolder, isOpen, children, onSelect, onDataChange])

  // 文件节点
  if (!isFolder) {
    return (
      <button
        className={`w-full text-left px-2 py-1 rounded-sm text-xs font-mono truncate flex items-center gap-1 transition-colors ${
          isSelected
            ? 'bg-primary/15 text-primary'
            : 'text-muted-foreground hover:text-foreground hover:bg-muted/30'
        }`}
        style={{ paddingLeft: `${level * 12 + 4}px` }}
        onClick={handleClick}
        title={node.path}
      >
        {getFileIcon(node.name)}
        <span className="truncate">{node.name}</span>
      </button>
    )
  }

  // 文件夹节点
  return (
    <div>
      <button
        className={`w-full text-left px-2 py-1 rounded-sm text-xs font-mono truncate transition-colors ${
          isOpen ? 'text-foreground' : 'text-muted-foreground'
        } hover:text-foreground hover:bg-muted/30 flex items-center gap-1`}
        style={{ paddingLeft: `${level * 12 + 4}px` }}
        onClick={handleClick}
        title={node.path}
      >
        {isLoading ? (
          <div className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin" />
        ) : isOpen ? (
          <ChevronDown className="w-3 h-3 opacity-70" />
        ) : (
          <ChevronRight className="w-3 h-3 opacity-70" />
        )}
        {isOpen ? (
          <FolderOpen className="w-3.5 h-3.5 text-yellow-400" />
        ) : (
          <Folder className="w-3.5 h-3.5 text-yellow-400/70" />
        )}
        <span className="truncate">{node.name}</span>
      </button>
      {isOpen && children.length > 0 && (
        <div>
          {children.map(child => (
            <FileTreeNode
              key={child.path}
              node={child}
              level={level + 1}
              selectedPath={selectedPath}
              onSelect={onSelect}
              onDataChange={onDataChange}
            />
          ))}
        </div>
      )}
      {isOpen && children.length === 0 && !isLoading && (
        <div
          className="text-xs text-muted-foreground px-2 py-1"
          style={{ paddingLeft: `${(level + 1) * 12 + 4}px` }}
        >
          空文件夹
        </div>
      )}
    </div>
  )
})

FileTreeNode.displayName = 'FileTreeNode'

export const FileTree = memo(({ nodes, selectedPath, onSelect }: FileTreeProps) => {
  // 当顶层 nodes 变化时，重新渲染
  const [localNodes, setLocalNodes] = useState<FileNode[]>(nodes)

  useEffect(() => {
    setLocalNodes(nodes)
  }, [nodes])

  return (
    <div className="h-full overflow-y-auto no-scrollbar">
      {localNodes.map(node => (
        <FileTreeNode
          key={node.path}
          node={node}
          level={0}
          selectedPath={selectedPath}
          onSelect={onSelect}
          onDataChange={() => {
            // 可以在这里触发其他更新
          }}
        />
      ))}
    </div>
  )
})

FileTree.displayName = 'FileTree'
