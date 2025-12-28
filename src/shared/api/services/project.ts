/**
 * 项目服务 API
 */

import { api } from '../client'
import type { Project } from '@/shared/types'

export class ProjectService {
  /**
   * 创建项目
   */
  async createProject(name: string, path: string): Promise<Project> {
    return api.post<Project>('/api/projects', { name, path })
  }

  /**
   * 上传项目 ZIP 文件
   */
  async uploadProject(
    name: string,
    zipFile: File,
    onProgress?: (progress: number) => void
  ): Promise<Project> {
    const formData = new FormData()
    formData.append('name', name)
    formData.append('file', zipFile)

    const response = await fetch(`${api.getBaseURL()}/api/projects/upload`, {
      method: 'POST',
      body: formData,
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`Upload failed: ${error}`)
    }

    return response.json()
  }

  /**
   * 列出所有项目
   */
  async listProjects(): Promise<Project[]> {
    return api.get<Project[]>('/api/projects')
  }

  /**
   * 获取项目详情
   */
  async getProject(projectId: number): Promise<Project> {
    return api.get<Project>(`/api/projects/${projectId}`)
  }

  /**
   * 删除项目（使用 uuid）
   */
  async deleteProject(projectUuid: string): Promise<{ message: string }> {
    return api.delete<{ message: string }>(`/api/projects/${projectUuid}`)
  }
}

export const projectService = new ProjectService()
