/**
 * AST 服务 API
 */

import { api } from '../client'
import type { Symbol, CallNode, GraphData } from '@/shared/types'

export class ASTService {
  /**
   * 构建 AST 索引
   */
  async buildIndex(projectPath: string): Promise<{ files_processed: number; message: string }> {
    return api.invoke('build_ast_index', { project_path: projectPath })
  }

  /**
   * 搜索符号
   */
  async searchSymbol(symbolName: string): Promise<Symbol[]> {
    return api.invoke('search_symbol', { symbol_name: symbolName })
  }

  /**
   * 获取调用图
   */
  async getCallGraph(
    entryFunction: string,
    maxDepth: number = 3
  ): Promise<CallNode | GraphData> {
    return api.invoke('get_call_graph', {
      entry_function: entryFunction,
      max_depth: maxDepth,
    })
  }

  /**
   * 获取文件结构
   */
  async getCodeStructure(filePath: string): Promise<Symbol[]> {
    return api.invoke('get_code_structure', { file_path: filePath })
  }

  /**
   * 查找调用点
   */
  async findCallSites(functionName: string): Promise<Symbol[]> {
    return api.invoke('find_call_sites', { function_name: functionName })
  }

  /**
   * 获取类层次结构
   */
  async getClassHierarchy(className: string): Promise<{
    parent?: string
    children?: string[]
    interfaces?: string[]
  }> {
    return api.invoke('get_class_hierarchy', { class_name: className })
  }

  /**
   * 获取知识图谱
   */
  async getKnowledgeGraph(): Promise<GraphData> {
    return api.invoke('get_knowledge_graph', {})
  }
}

export const astService = new ASTService()
