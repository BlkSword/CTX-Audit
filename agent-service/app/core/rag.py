"""
RAG (检索增强生成) 引擎

提供向量检索和上下文增强功能
"""
from typing import List, Dict, Any, Optional
from loguru import logger

from app.config import settings


class RAGEngine:
    """
    RAG 引擎

    功能：
    - 代码语义搜索
    - 漏洞知识库检索
    - 上下文构建
    """

    def __init__(self):
        self.enabled = settings.RAG_ENABLED
        self.top_k = settings.TOP_K_RETRIEVAL

    async def retrieve_relevant_context(
        self,
        query: str,
        context_type: str = "code",
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        检索相关上下文

        Args:
            query: 查询文本
            context_type: 上下文类型 (code | vulnerability)
            project_id: 项目 ID（用于代码检索）

        Returns:
            相关上下文列表
        """
        if not self.enabled:
            logger.debug("RAG 未启用")
            return []

        try:
            if context_type == "code":
                return await self._retrieve_code_context(query, project_id)
            elif context_type == "vulnerability":
                return await self._retrieve_vulnerability_context(query)
            else:
                logger.warning(f"未知的上下文类型: {context_type}")
                return []

        except Exception as e:
            logger.error(f"RAG 检索失败: {e}")
            return []

    async def _retrieve_code_context(
        self,
        query: str,
        project_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        检索代码上下文

        Args:
            query: 查询文本
            project_id: 项目 ID

        Returns:
            相关代码片段列表
        """
        from app.services.vector_store import search_similar_code

        filter_dict = {"project_id": project_id} if project_id else None
        results = await search_similar_code(
            query=query,
            top_k=self.top_k,
            filter=filter_dict,
        )

        return [
            {
                "type": "code",
                "text": r["text"],
                "metadata": r["metadata"],
                "score": 1 - r.get("distance", 1),  # 转换为相似度分数
            }
            for r in results
        ]

    async def _retrieve_vulnerability_context(
        self,
        query: str,
    ) -> List[Dict[str, Any]]:
        """
        检索漏洞知识库上下文

        Args:
            query: 查询文本

        Returns:
            相关漏洞模式列表
        """
        from app.services.vector_store import search_vulnerability_patterns

        results = await search_vulnerability_patterns(
            query=query,
            top_k=self.top_k,
        )

        return [
            {
                "type": "vulnerability",
                "text": r["text"],
                "metadata": r["metadata"],
                "score": 1 - r.get("distance", 1),
            }
            for r in results
        ]

    async def build_analysis_prompt(
        self,
        code_snippet: str,
        file_path: str,
        rule_finding: Dict[str, Any],
    ) -> str:
        """
        构建增强的分析提示词

        Args:
            code_snippet: 代码片段
            file_path: 文件路径
            rule_finding: 规则扫描结果

        Returns:
            增强后的提示词
        """
        # 检索相关上下文
        vuln_contexts = await self.retrieve_relevant_context(
            query=f"{code_snippet} {rule_finding.get('description', '')}",
            context_type="vulnerability",
        )

        # 构建提示词
        prompt_parts = [
            f"请分析以下代码是否存在安全漏洞：\n",
            f"文件: {file_path}\n",
            f"代码:\n```\n{code_snippet}\n```\n",
            f"\n规则扫描结果: {rule_finding.get('description', '')}\n",
        ]

        # 添加相关上下文
        if vuln_contexts:
            prompt_parts.append("\n参考信息:\n")
            for ctx in vuln_contexts[:3]:  # 最多取 3 个相关结果
                prompt_parts.append(f"- {ctx['text'][:200]}...\n")

        prompt_parts.append("\n请基于以上信息分析：")
        prompt_parts.append("1. 这是否为真实的安全漏洞？")
        prompt_parts.append("2. 漏洞类型和严重程度")
        prompt_parts.append("3. 利用条件")
        prompt_parts.append("4. 修复建议")

        return "".join(prompt_parts)

    async def index_project_code(
        self,
        project_id: str,
        files: List[Dict[str, Any]],
    ) -> None:
        """
        索引项目代码到向量库

        Args:
            project_id: 项目 ID
            files: 文件列表，每个文件包含:
                - path: 文件路径
                - content: 文件内容
                - language: 编程语言
        """
        if not self.enabled:
            logger.debug("RAG 未启用，跳过代码索引")
            return

        logger.info(f"开始索引项目 {project_id} 的代码...")

        # 切分代码
        chunks = []
        for file in files:
            file_chunks = self._chunk_code(
                content=file["content"],
                file_path=file["path"],
                language=file.get("language", "unknown"),
            )
            chunks.extend(file_chunks)

        # 添加到向量库
        from app.services.vector_store import add_code_chunks
        await add_code_chunks(project_id, chunks)

        logger.info(f"已索引 {len(chunks)} 个代码片段")

    def _chunk_code(
        self,
        content: str,
        file_path: str,
        language: str,
    ) -> List[Dict[str, Any]]:
        """
        切分代码为小块

        Args:
            content: 代码内容
            file_path: 文件路径
            language: 编程语言

        Returns:
            代码块列表
        """
        chunk_size = settings.CHUNK_SIZE
        overlap = settings.CHUNK_OVERLAP

        lines = content.split("\n")
        chunks = []

        for i in range(0, len(lines), chunk_size - overlap):
            chunk_lines = lines[i : i + chunk_size]
            chunk_text = "\n".join(chunk_lines)

            chunks.append({
                "id": f"{file_path}_{i}_{i + len(chunk_lines)}",
                "text": chunk_text,
                "metadata": {
                    "file": file_path,
                    "start_line": i + 1,
                    "end_line": i + len(chunk_lines),
                    "language": language,
                },
            })

        return chunks


# 全局 RAG 引擎实例
rag_engine = RAGEngine()
