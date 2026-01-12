/**
 * File Upload Component - 拖拽上传组件
 * 支持拖拽上传和点击选择文件
 */

import { useCallback, useState } from 'react'
import { Upload, FileArchive, X, Check } from 'lucide-react'
import { cn } from '@/lib/utils'

export interface FileUploadProps {
  /** 接受的文件类型 (MIME type 或扩展名) */
  accept?: string
  /** 是否禁用 */
  disabled?: boolean
  /** 当前选中的文件 */
  value: File | null
  /** 文件变化回调 */
  onChange: (file: File | null) => void
  /** 最大文件大小 (MB) */
  maxSize?: number
  /** 自定义类名 */
  className?: string
}

export function FileUpload({
  accept = '.zip',
  disabled = false,
  value,
  onChange,
  maxSize = 500,
  className,
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const validateFile = useCallback((file: File): string | null => {
    // 检查文件扩展名
    if (accept && !file.name.endsWith(accept.replace('*', ''))) {
      return `请上传 ${accept} 格式的文件`
    }

    // 检查文件大小
    const maxSizeBytes = maxSize * 1024 * 1024
    if (file.size > maxSizeBytes) {
      return `文件大小不能超过 ${maxSize} MB`
    }

    return null
  }, [accept, maxSize])

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (!disabled) {
      setIsDragging(true)
    }
  }, [disabled])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    if (disabled) return

    const file = e.dataTransfer.files[0]
    if (!file) return

    const validationError = validateFile(file)
    if (validationError) {
      setError(validationError)
      return
    }

    setError(null)
    onChange(file)
  }, [disabled, validateFile, onChange])

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const validationError = validateFile(file)
    if (validationError) {
      setError(validationError)
      return
    }

    setError(null)
    onChange(file)
  }, [validateFile, onChange])

  const handleRemove = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    onChange(null)
    setError(null)
  }, [onChange])

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
  }

  return (
    <div className={cn('w-full', className)}>
      <input
        id="file-upload"
        type="file"
        accept={accept}
        onChange={handleFileSelect}
        disabled={disabled}
        className="hidden"
      />

      {!value ? (
        // 上传区域
        <label
          htmlFor="file-upload"
          className={cn(
            'relative flex flex-col items-center justify-center gap-3 p-6 rounded-lg border-2 border-dashed transition-all cursor-pointer',
            'min-h-[140px]',
            isDragging && !disabled
              ? 'border-primary bg-primary/5 scale-[1.02]'
              : 'border-border/40 hover:border-primary/50 hover:bg-muted/30',
            disabled && 'opacity-50 cursor-not-allowed'
          )}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {/* 上传图标 */}
          <div className={cn(
            'w-12 h-12 rounded-full flex items-center justify-center transition-colors',
            isDragging ? 'bg-primary/20' : 'bg-muted/50'
          )}>
            <Upload className={cn(
              'w-6 h-6 transition-colors',
              isDragging ? 'text-primary' : 'text-muted-foreground'
            )} />
          </div>

          {/* 提示文字 */}
          <div className="text-center space-y-1">
            <p className="text-sm font-medium text-foreground">
              {isDragging ? '释放以上传文件' : '拖拽文件到此处'}
            </p>
            <p className="text-xs text-muted-foreground">
              或点击选择文件
            </p>
            <p className="text-xs text-muted-foreground/60">
              支持 {accept} 格式，最大 {maxSize} MB
            </p>
          </div>
        </label>
      ) : (
        // 已选择文件显示
        <div className="relative group">
          <div className="flex items-center gap-3 p-4 rounded-lg border border-border/40 bg-muted/20 transition-colors hover:border-primary/30">
            {/* 文件图标 */}
            <div className="shrink-0 w-10 h-10 rounded-lg bg-gradient-to-br from-orange-500/20 to-orange-600/20 flex items-center justify-center border border-orange-500/30">
              <FileArchive className="w-5 h-5 text-orange-500" />
            </div>

            {/* 文件信息 */}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-foreground truncate">
                {value.name}
              </p>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xs text-muted-foreground">
                  {formatFileSize(value.size)}
                </span>
                <span className="text-xs text-green-500 flex items-center gap-1">
                  <Check className="w-3 h-3" />
                  已选择
                </span>
              </div>
            </div>

            {/* 删除按钮 */}
            <button
              type="button"
              onClick={handleRemove}
              disabled={disabled}
              className={cn(
                'shrink-0 w-8 h-8 rounded-lg flex items-center justify-center transition-all',
                'text-muted-foreground hover:text-destructive hover:bg-destructive/10',
                'opacity-0 group-hover:opacity-100 focus:opacity-100',
                disabled && 'opacity-30 cursor-not-allowed'
              )}
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* 进度条装饰 */}
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-muted overflow-hidden rounded-b-lg">
            <div className="h-full w-full bg-gradient-to-r from-orange-500 to-orange-600 animate-pulse" />
          </div>
        </div>
      )}

      {/* 错误提示 */}
      {error && (
        <div className="mt-2 p-2 bg-destructive/10 border border-destructive/20 rounded text-xs text-destructive flex items-center gap-2">
          <span className="shrink-0">⚠</span>
          <span>{error}</span>
        </div>
      )}
    </div>
  )
}
