"""
Rust 后端客户端

负责与 CTX-Audit Rust 后端通信，获取 AST 分析、扫描结果等
"""
import httpx
from typing import Optional, Dict, Any, List
from loguru import logger

from app.config import settings


class RustBackendClient:
    """
    Rust 后端 HTTP 客户端

    提供与 Rust 后端通信的方法，包括：
    - 项目管理
    - AST 查询
    - 扫描器接口
    """

    def __init__(self):
        self.base_url = settings.RUST_BACKEND_URL
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """获取 HTTP 客户端实例"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
            )
        return self._client

    async def close(self):
        """关闭客户端连接"""
        if self._client:
            await self._client.aclose()
            self._client = None

    # ========== 项目管理 ==========

    async def get_project(self, project_id: str) -> Dict[str, Any]:
        """
        获取项目信息

        Args:
            project_id: 项目 UUID

        Returns:
            项目信息字典
        """
        client = await self._get_client()
        try:
            # 使用 /api/projects/{uuid} 路径（复数形式）
            response = await client.get(f"/api/projects/{project_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取项目失败: {e}")
            raise

    async def list_projects(self) -> List[Dict[str, Any]]:
        """列出所有项目"""
        client = await self._get_client()
        try:
            response = await client.get("/api/project/list")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"列出项目失败: {e}")
            raise

    async def list_files(self, directory: str) -> List[str]:
        """
        列出目录下的文件
        
        Args:
            directory: 目录路径
            
        Returns:
            文件列表
        """
        client = await self._get_client()
        try:
            response = await client.get("/api/files/list", params={"directory": directory})
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"列出文件失败: {e}")
            return []

    async def read_file(self, path: str) -> str:
        """读取文件内容"""
        client = await self._get_client()
        try:
            response = await client.get("/api/files/read", params={"path": path})
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"读取文件失败: {e}")
            return ""

    # ========== AST 查询 ==========

    async def build_ast_index(
        self,
        project_path: str,
        project_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        构建 AST 索引

        Args:
            project_path: 项目路径
            project_id: 项目 ID（可选，用于将索引保存到数据库）

        Returns:
            索引构建结果
        """
        client = await self._get_client()
        try:
            payload = {"project_path": project_path}
            if project_id is not None:
                payload["project_id"] = project_id

            response = await client.post(
                "/api/ast/build_index",
                json=payload
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"构建 AST 索引失败: {e}")
            raise

    async def get_ast_context(
        self,
        file_path: str,
        line_range: List[int],
        include_callers: bool = True,
        include_callees: bool = True,
        project_id: Optional[int] = None,
        project_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        获取 AST 上下文

        Args:
            file_path: 文件路径
            line_range: 行范围 [start, end]
            include_callers: 是否包含调用者
            include_callees: 是否包含被调用者
            project_id: 项目ID（可选）
            project_path: 项目路径（可选）

        Returns:
            AST 上下文信息
        """
        client = await self._get_client()
        try:
            payload = {
                "file_path": file_path,
                "line_range": line_range,
                "include_callers": include_callers,
                "include_callees": include_callees,
            }
            # 添加可选的项目信息
            if project_id is not None:
                payload["project_id"] = project_id
            if project_path is not None:
                payload["project_path"] = project_path

            response = await client.post(
                "/api/ast/context",
                json=payload
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取 AST 上下文失败: {e}")
            raise

    async def search_symbol(
        self,
        symbol_name: str,
        project_id: Optional[int] = None,
        project_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        搜索符号

        Args:
            symbol_name: 符号名称
            project_id: 项目 ID（可选）
            project_path: 项目路径（可选）

        Returns:
            符号搜索结果列表
        """
        client = await self._get_client()
        try:
            params = {}
            if project_id is not None:
                params["project_id"] = str(project_id)
            if project_path is not None:
                params["project_path"] = project_path

            response = await client.get(
                f"/api/ast/search_symbol/{symbol_name}",
                params=params if params else None
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"搜索符号失败: {e}")
            raise

    async def batch_query(self, queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        批量代码查询

        Args:
            queries: 查询列表

        Returns:
            查询结果
        """
        client = await self._get_client()
        try:
            response = await client.post("/api/ast/batch_query", json={"queries": queries})
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"批量查询失败: {e}")
            raise

    # ========== 扫描器接口 ==========

    async def run_scan(self, project_path: str) -> Dict[str, Any]:
        """
        运行扫描器

        Args:
            project_path: 项目路径

        Returns:
            扫描结果
        """
        client = await self._get_client()
        try:
            response = await client.post(
                "/api/scanner/scan",
                json={"project_path": project_path}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"运行扫描失败: {e}")
            raise

    async def upload_and_scan(self, file_content: str, filename: str) -> Dict[str, Any]:
        """
        上传并扫描文件

        Args:
            file_content: 文件内容
            filename: 文件名

        Returns:
            扫描结果
        """
        client = await self._get_client()
        try:
            response = await client.post(
                "/api/scanner/upload",
                files={"file": (filename, file_content)}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"上传扫描失败: {e}")
            raise

    async def get_scan_findings(self, project_id: str) -> List[Dict[str, Any]]:
        """
        获取扫描结果

        Args:
            project_id: 项目 ID

        Returns:
            漏洞发现列表
        """
        client = await self._get_client()
        try:
            response = await client.get(f"/api/scanner/findings/{project_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取扫描结果失败: {e}")
            raise

    # ========== 代码图谱查询 ==========

    async def get_call_graph(
        self,
        entry_function: str,
        max_depth: int = 3,
        project_id: Optional[int] = None,
        save_graph: bool = False,
    ) -> Dict[str, Any]:
        """
        获取函数调用图

        Args:
            entry_function: 入口函数名
            max_depth: 最大深度
            project_id: 项目 ID（可选，用于保存图谱）
            save_graph: 是否保存图谱到数据库

        Returns:
            调用图数据，包含 nodes 和 edges
        """
        client = await self._get_client()
        try:
            payload = {
                "entry_function": entry_function,
                "max_depth": max_depth,
            }
            if project_id is not None:
                payload["project_id"] = project_id
            if save_graph:
                payload["save_graph"] = True

            response = await client.post("/api/ast/get_call_graph", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取调用图失败: {e}")
            raise

    async def get_knowledge_graph(
        self,
        limit: int = 500,
        project_id: Optional[int] = None,
        project_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        获取代码知识图谱

        Args:
            limit: 节点数量限制
            project_id: 项目 ID
            project_path: 项目路径

        Returns:
            知识图谱数据，包含 nodes 和 edges
        """
        client = await self._get_client()
        try:
            payload = {"limit": limit}
            if project_id is not None:
                payload["project_id"] = project_id
            if project_path is not None:
                payload["project_path"] = project_path

            response = await client.post("/api/ast/get_knowledge_graph", json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取知识图谱失败: {e}")
            raise

    async def get_code_structure(
        self,
        file_path: str,
        project_id: Optional[int] = None,
        project_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        获取文件的代码结构

        Args:
            file_path: 文件路径
            project_id: 项目 ID（可选）
            project_path: 项目路径（可选）

        Returns:
            符号列表
        """
        client = await self._get_client()
        try:
            # URL encode the file path
            import urllib.parse
            encoded_path = urllib.parse.quote(file_path, safe='')

            params = {}
            if project_id is not None:
                params["project_id"] = str(project_id)
            if project_path is not None:
                params["project_path"] = project_path

            response = await client.get(
                f"/api/ast/get_code_structure/{encoded_path}",
                params=params if params else None
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取代码结构失败: {e}")
            return []

    async def get_ast_index_history(
        self,
        project_id: int,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        获取项目的 AST 索引历史

        Args:
            project_id: 项目 ID
            limit: 返回数量限制

        Returns:
            历史记录列表
        """
        client = await self._get_client()
        try:
            response = await client.get(
                f"/api/ast/history/indices/{project_id}",
                params={"limit": limit}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取 AST 索引历史失败: {e}")
            return []

    async def get_graph_history(
        self,
        project_id: int,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        获取项目的代码图谱历史

        Args:
            project_id: 项目 ID
            limit: 返回数量限制

        Returns:
            历史记录列表
        """
        client = await self._get_client()
        try:
            response = await client.get(
                f"/api/ast/history/graphs/{project_id}",
                params={"limit": limit}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"获取图谱历史失败: {e}")
            return []


# 全局客户端实例
rust_client = RustBackendClient()
