import { useCallback, memo } from 'react'
import { Search, Loader2, FileCode } from 'lucide-react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { ScrollArea } from '@/components/ui/scroll-area'

interface SearchResult {
  file: string
  line: number
  content: string
}

// 根据文件扩展名获取语言类型
function getLanguageFromPath(filePath: string): string {
  if (!filePath) return 'text'
  const ext = filePath.split('.').pop()?.toLowerCase()
  switch (ext) {
    case 'ts': return 'typescript'
    case 'tsx': return 'typescript'
    case 'js': return 'javascript'
    case 'jsx': return 'javascript'
    case 'vue': return 'vue'
    case 'rs': return 'rust'
    case 'py': return 'python'
    case 'java': return 'java'
    case 'c': return 'c'
    case 'cpp': return 'cpp'
    case 'cc': return 'cpp'
    case 'h': return 'c'
    case 'hpp': return 'cpp'
    case 'cs': return 'csharp'
    case 'go': return 'go'
    case 'php': return 'php'
    case 'rb': return 'ruby'
    case 'sh': return 'bash'
    case 'json': return 'json'
    case 'xml': return 'xml'
    case 'yaml': return 'yaml'
    case 'yml': return 'yaml'
    case 'sql': return 'sql'
    case 'css': return 'css'
    case 'scss': return 'scss'
    case 'sass': return 'sass'
    case 'less': return 'less'
    case 'html': return 'html'
    case 'htm': return 'html'
    case 'md': return 'markdown'
    case 'mdx': return 'markdown'
    case 'toml': return 'toml'
    case 'ini': return 'ini'
    case 'conf': return 'ini'
    case 'dockerfile': return 'docker'
    case 'docker': return 'docker'
    case 'txt': return 'text'
    default: return 'text'
  }
}

interface SearchPanelProps {
  searchQuery: string
  isSearching: boolean
  searchResults: SearchResult[]
  onSearchQueryChange: (value: string) => void
  onSearchSubmit: (e: React.FormEvent) => void
  onResultClick: (result: SearchResult) => void
}

export const SearchResultItem = memo(({ result, onClick }: {
  result: SearchResult
  onClick: () => void
}) => {
  return (
    <button
      className="w-full text-left p-3 hover:bg-muted/40 transition-colors rounded-md mb-2"
      onClick={onClick}
    >
      <div className="flex items-center gap-2 text-xs text-muted-foreground mb-2">
        <FileCode className="w-3.5 h-3.5" />
        <span className="truncate">{result.file}</span>
        <span className="text-primary font-bold">:{result.line}</span>
      </div>
      <div className="rounded overflow-hidden text-xs">
        <SyntaxHighlighter
          language={getLanguageFromPath(result.file)}
          style={vscDarkPlus}
          customStyle={{
            margin: 0,
            borderRadius: '0.375rem',
            fontSize: '0.75rem',
            lineHeight: '1.4',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}
          wrapLongLines={true}
        >
          {result.content}
        </SyntaxHighlighter>
      </div>
    </button>
  )
})

SearchResultItem.displayName = 'SearchResultItem'

export const SearchPanel = memo(({
  searchQuery,
  isSearching,
  searchResults,
  onSearchQueryChange,
  onSearchSubmit,
  onResultClick
}: SearchPanelProps) => {
  const handleQueryChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    onSearchQueryChange(e.target.value)
  }, [onSearchQueryChange])

  return (
    <div className="h-full">
      <form onSubmit={onSearchSubmit} className="p-4 border-b border-border/40">
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="搜索文件内容..."
            value={searchQuery}
            onChange={handleQueryChange}
            className="flex-1 px-3 py-2 text-sm bg-background border border-input rounded-md outline-none focus:ring-2 focus:ring-ring focus:border-ring text-foreground"
          />
          <button
            type="submit"
            disabled={isSearching}
            className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isSearching ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                搜索中
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                搜索
              </>
            )}
          </button>
        </div>
      </form>

      <ScrollArea className="h-[calc(100%-80px)] p-2">
        {!searchResults.length && searchQuery.trim() ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            没有匹配的结果
          </div>
        ) : null}

        {searchResults.length > 0 && (
          <div className="space-y-2">
            {searchResults.map((result, idx) => (
              <SearchResultItem
                key={`${result.file}-${result.line}-${idx}`}
                result={result}
                onClick={() => onResultClick(result)}
              />
            ))}
          </div>
        )}
      </ScrollArea>
    </div>
  )
})

SearchPanel.displayName = 'SearchPanel'
