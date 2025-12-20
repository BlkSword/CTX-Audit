import { useCallback, memo } from 'react'
import { Search, Loader2, ChevronRight, ChevronDown, FileCode } from 'lucide-react'
import { ScrollArea } from '@/components/ui/scroll-area'

interface SearchResult {
  file: string
  line: number
  content: string
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
  const fileName = result.file.split('/').pop() || result.file

  return (
    <button
      className="w-full text-left p-3 hover:bg-muted/40 transition-colors rounded-md mb-2"
      onClick={onClick}
    >
      <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
        <FileCode className="w-3.5 h-3.5" />
        <span className="truncate">{result.file}</span>
      </div>
      <div className="text-sm font-mono">
        <span className="text-primary font-bold">{result.line}:</span>
        <span className="ml-2">{result.content}</span>
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
