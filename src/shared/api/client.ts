/**
 * API 客户端 - Web 版专用
 *
 * 纯 HTTP API 客户端，用于与 Rust 后端通信
 */

export interface APIConfig {
  baseURL: string
  timeout?: number
  headers?: Record<string, string>
}

export class APIClient {
  private config: APIConfig

  constructor(config?: Partial<APIConfig>) {
    this.config = {
      baseURL: config?.baseURL || import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
      timeout: config?.timeout || 30000,
      headers: config?.headers || {},
    }
  }

  /**
   * 调用 API
   */
  async invoke<T>(command: string, args?: any): Promise<T> {
    const path = this.commandToPath(command)

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout)

    try {
      const response = await fetch(`${this.config.baseURL}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.config.headers,
        },
        body: args ? JSON.stringify(args) : undefined,
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        const error = await response.text()
        throw new Error(`API error (${response.status}): ${error}`)
      }

      // 处理 204 No Content
      if (response.status === 204) {
        return undefined as T
      }

      return response.json()
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('API request timeout')
      }
      throw error
    }
  }

  /**
   * GET 请求
   */
  async get<T>(path: string, params?: Record<string, any>): Promise<T> {
    let url = `${this.config.baseURL}${path}`

    if (params) {
      const searchParams = new URLSearchParams()
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          searchParams.append(key, String(value))
        }
      })
      url += `?${searchParams.toString()}`
    }

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers,
      },
    })

    if (!response.ok) {
      throw new Error(`GET ${path} failed: ${response.statusText}`)
    }

    return response.json()
  }

  /**
   * POST 请求
   */
  async post<T>(path: string, data?: any): Promise<T> {
    const response = await fetch(`${this.config.baseURL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers,
      },
      body: data ? JSON.stringify(data) : undefined,
    })

    if (!response.ok) {
      throw new Error(`POST ${path} failed: ${response.statusText}`)
    }

    return response.json()
  }

  /**
   * DELETE 请求
   */
  async delete<T>(path: string): Promise<T> {
    const response = await fetch(`${this.config.baseURL}${path}`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers,
      },
    })

    if (!response.ok) {
      throw new Error(`DELETE ${path} failed: ${response.statusText}`)
    }

    return response.json()
  }

  /**
   * 上传文件
   */
  async uploadFiles(
    files: FileList | File[],
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    _onProgress?: (progress: number) => void
  ): Promise<any> {
    const formData = new FormData()

    const fileArray = files instanceof FileList
      ? Array.from(files)
      : files

    fileArray.forEach((file) => {
      formData.append('files', file)
    })

    const response = await fetch(`${this.config.baseURL}/api/scanner/upload`, {
      method: 'POST',
      body: formData,
    })

    if (!response.ok) {
      throw new Error(`Upload failed: ${response.statusText}`)
    }

    return response.json()
  }

  /**
   * 读取文件内容
   */
  async readFile(filePath: string): Promise<string> {
    const response = await fetch(`${this.config.baseURL}/api/files/read?path=${encodeURIComponent(filePath)}`)

    if (!response.ok) {
      throw new Error(`Read file failed: ${response.statusText}`)
    }

    const text = await response.text()
    
    // 尝试判断是否为 JSON 格式的字符串（后端可能将内容序列化为 JSON 字符串返回）
    // 如果首尾是引号，并且看起来像是 JSON 字符串，尝试解析
    try {
      if (text.startsWith('"') && text.endsWith('"')) {
        const parsed = JSON.parse(text)
        if (typeof parsed === 'string') {
          return parsed
        }
      }
    } catch (e) {
      // 解析失败，说明不是 JSON 字符串，直接返回原始内容
    }

    return text
  }

  /**
   * 搜索文件内容
   */
  async searchFiles(query: string, path: string): Promise<any[]> {
    const response = await fetch(
      `${this.config.baseURL}/api/files/search?query=${encodeURIComponent(query)}&path=${encodeURIComponent(path)}`
    )
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    return response.json()
  }

  /**
   * 列出目录文件
   */
  async listFiles(directory: string): Promise<string[]> {
    const response = await fetch(
      `${this.config.baseURL}/api/files/list?directory=${encodeURIComponent(directory)}`
    )
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    return response.json()
  }

  /**
   * 将命令名转换为 API 路径
   */
  private commandToPath(command: string): string {
    // 命令名到路径的映射
    const pathMap: Record<string, string> = {
      // AST 相关
      'build_ast_index': '/api/ast/build_index',
      'search_symbol': '/api/ast/search_symbol',
      'get_call_graph': '/api/ast/get_call_graph',
      'get_code_structure': '/api/ast/get_code_structure',
      'find_call_sites': '/api/ast/find_call_sites',
      'get_class_hierarchy': '/api/ast/get_class_hierarchy',
      'get_knowledge_graph': '/api/ast/get_knowledge_graph',

      // 扫描相关
      'run_scan': '/api/scanner/scan',

      // 注意：以下命令不使用 invoke，而是直接使用 GET/POST/DELETE 方法
      // - create_project: 使用 projectService.uploadProject()
      // - list_projects: 使用 api.get('/api/projects')
      // - get_project: 使用 api.get('/api/projects/:uuid')
      // - delete_project: 使用 api.delete('/api/projects/:uuid')
      // - list_files: 使用 fileService.listFiles()
      // - read_file: 使用 api.readFile()
      // - search_files: 使用 fileService.searchFiles()
    }

    return pathMap[command] || `/api/${command}`
  }

  /**
   * 设置基础 URL
   */
  setBaseURL(url: string): void {
    this.config.baseURL = url
  }

  /**
   * 获取基础 URL
   */
  getBaseURL(): string {
    return this.config.baseURL
  }
}

// 单例实例
let apiClientInstance: APIClient | null = null

export function getAPIClient(config?: Partial<APIConfig>): APIClient {
  if (!apiClientInstance) {
    apiClientInstance = new APIClient(config)
  }
  return apiClientInstance
}

// 默认导出
export const api = getAPIClient()

// 便捷函数
export function setAPIBaseURL(url: string): void {
  getAPIClient().setBaseURL(url)
}
