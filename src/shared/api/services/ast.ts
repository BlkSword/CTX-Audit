/**
 * AST 服务 API (Tauri 版本)
 *
 * 使用 Tauri Commands 与 Rust 后端通信
 */

import type { Symbol, CallNode, GraphData } from '@/shared/types'
import { tauriApi } from '@/shared/api/tauri-client'

/**
 * AST 服务 - 使用 Tauri 后端
 */
export class ASTService {
  /**
   * 构建 AST 索引
   */
  async buildIndex(projectPath: string, _projectId?: number): Promise<{ files_processed: number; message: string }> {
    try {
      const fileCount = await tauriApi.indexProject(projectPath)
      return {
        files_processed: fileCount,
        message: `已索引 ${fileCount} 个文件`
      }
    } catch (error) {
      return {
        files_processed: 0,
        message: `索引失败: ${error instanceof Error ? error.message : '未知错误'}`
      }
    }
  }

  /**
   * 搜索符号
   */
  async searchSymbol(symbolName: string, projectId?: number, _projectPath?: string): Promise<Symbol[]> {
    try {
      if (!projectId) {
        return []
      }
      const results = await tauriApi.searchSymbol(symbolName, projectId)
      // 转换为前端 Symbol 类型
      return results.map(r => ({
        name: r.name,
        kind: r.kind,
        file_path: r.file_path,
        line: r.line,
        column: 0
      }))
    } catch (error) {
      console.error('搜索符号失败:', error)
      return []
    }
  }

  /**
   * 获取调用图
   */
  async getCallGraph(entryFunction: string, maxDepth: number = 3, projectId?: number): Promise<CallNode | GraphData> {
    try {
      if (!projectId) {
        return { nodes: [], edges: [] }
      }
      return await tauriApi.getCallGraph(entryFunction, maxDepth, projectId)
    } catch (error) {
      console.error('获取调用图失败:', error)
      return { nodes: [], edges: [] }
    }
  }

  /**
   * 获取文件结构
   */
  async getCodeStructure(filePath: string, _projectId?: number, _projectPath?: string): Promise<Symbol[]> {
    try {
      const symbols = await tauriApi.getFileSymbols(filePath)
      // 转换为前端 Symbol 类型
      return symbols.map(s => ({
        name: s.name,
        kind: s.kind,
        file_path: s.file_path,
        line: s.line,
        column: s.column
      }))
    } catch (error) {
      console.error('获取代码结构失败:', error)
      return []
    }
  }

  /**
   * 查找调用点
   * TODO: 需要添加对应的 Tauri Command
   */
  async findCallSites(_functionName: string): Promise<Symbol[]> {
    // 待实现：需要 Rust 后端支持
    return []
  }

  /**
   * 获取类层次结构
   * TODO: 需要添加对应的 Tauri Command
   */
  async getClassHierarchy(_className: string): Promise<{
    parent?: string
    children?: string[]
    interfaces?: string[]
  }> {
    // 待实现：需要 Rust 后端支持
    return {}
  }

  /**
   * 获取知识图谱
   * TODO: 需要添加对应的 Tauri Command
   */
  async getKnowledgeGraph(_projectId?: number, _projectPath?: string): Promise<GraphData> {
    // 待实现：需要 Rust 后端支持
    return { nodes: [], edges: [] }
  }
}

export const astService = new ASTService()
