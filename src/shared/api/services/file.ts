/**
 * 文件服务 API
 */

import { api } from '../client'
import type { FileNode, SearchResult } from '@/shared/types'

export class FileService {
  /**
   * 列出目录文件
   */
  async listFiles(directory: string): Promise<string[]> {
    return api.get<string[]>('/api/files/list', { directory })
  }

  /**
   * 读取文件内容
   */
  async readFile(filePath: string): Promise<string> {
    return api.readFile(filePath)
  }

  /**
   * 搜索文件
   */
  async searchFiles(query: string, path: string): Promise<SearchResult[]> {
    return api.get<SearchResult[]>('/api/files/search', { query, path })
  }

  /**
   * 构建文件树
   */
  async buildFileTree(rootPath: string): Promise<FileNode[]> {
    const files = await this.listFiles(rootPath)
    return this.buildTreeFromList(files, rootPath)
  }

  /**
   * 递归构建文件树
   */
  private buildTreeFromList(files: string[], rootPath: string): FileNode[] {
    const root: FileNode[] = []

    for (const file of files) {
      const fullPath = `${rootPath}/${file}`.replace(/\/+/g, '/')
      root.push({
        name: file,
        path: fullPath,
        type: 'file', // 简化处理，实际应该判断是文件还是目录
        children: [],
      })
    }

    return root
  }
}

export const fileService = new FileService()
