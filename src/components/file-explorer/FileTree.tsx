import { useState, useCallback, memo } from 'react'
import { ChevronRight, ChevronDown, Folder, FileCode } from 'lucide-react'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'

interface FileNode {
  name: string
  path: string
  type: 'file' | 'folder'
  children?: FileNode[]
}

interface FileTreeProps {
  nodes: FileNode[]
  selectedPath: string | null
  onSelect: (path: string) => void
}

const FileTreeNode = memo(({ node, level, selectedPath, onSelect }: {
  node: FileNode
  level: number
  selectedPath: string | null
  onSelect: (path: string) => void
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const isSelected = selectedPath === node.path

  const handleClick = useCallback(() => {
    if (node.type === 'file') {
      onSelect(node.path)
    } else {
      setIsOpen(prev => !prev)
    }
  }, [node, onSelect])

  if (node.type === 'file') {
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
        <FileCode className="w-3 h-3 opacity-70" />
        <span className="truncate">{node.name}</span>
      </button>
    )
  }

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger
        className={`w-full text-left px-2 py-1 rounded-sm text-xs font-mono truncate transition-colors ${
          isOpen ? 'text-foreground' : 'text-muted-foreground'
        } hover:text-foreground hover:bg-muted/30 flex items-center gap-1`}
        style={{ paddingLeft: `${level * 12 + 4}px` }}
        asChild
      >
        <button onClick={handleClick}>
          {isOpen ? <ChevronDown className="w-3 h-3 opacity-70" /> : <ChevronRight className="w-3 h-3 opacity-70" />}
          <Folder className={`w-3.5 h-3.5 ${isOpen ? 'text-foreground' : 'text-muted-foreground/70'}`} />
          <span className="truncate">{node.name}</span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        {node.children?.map(child => (
          <FileTreeNode
            key={child.path}
            node={child}
            level={level + 1}
            selectedPath={selectedPath}
            onSelect={onSelect}
          />
        ))}
      </CollapsibleContent>
    </Collapsible>
  )
})

FileTreeNode.displayName = 'FileTreeNode'

export const FileTree = memo(({ nodes, selectedPath, onSelect }: FileTreeProps) => {
  return (
    <div className="h-full overflow-y-auto no-scrollbar">
      {nodes.map(node => (
        <FileTreeNode
          key={node.path}
          node={node}
          level={0}
          selectedPath={selectedPath}
          onSelect={onSelect}
        />
      ))}
    </div>
  )
})

FileTree.displayName = 'FileTree'
