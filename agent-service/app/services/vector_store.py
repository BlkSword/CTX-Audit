"""
向量存储服务

ChromaDB 向量数据库连接和操作
"""
from typing import Optional, List, Dict, Any
from loguru import logger
import chromadb
from chromadb.config import Settings as ChromaSettings

from app.config import settings

# 全局 ChromaDB 客户端
_chroma_client: Optional[chromadb.HttpClient] = None


async def init_vector_store():
    """初始化 ChromaDB 连接"""
    global _chroma_client

    if _chroma_client is not None:
        return

    try:
        _chroma_client = chromadb.HttpClient(
            host=settings.CHROMADB_HOST,
            port=settings.CHROMADB_PORT,
        )

        # 创建必要的集合
        _create_collections()

        logger.info("ChromaDB 连接初始化成功")
    except Exception as e:
        logger.error(f"ChromaDB 连接失败: {e}")
        # 不抛出异常，允许在没有 ChromaDB 的情况下运行
        _chroma_client = None


def _create_collections():
    """创建向量集合"""
    if not _chroma_client:
        return

    # 代码片段集合
    try:
        _chroma_client.get_or_create_collection(
            name="code_chunks",
            metadata={"hnsw:space": "cosine"}
        )
    except Exception as e:
        logger.warning(f"创建 code_chunks 集合失败: {e}")

    # 漏洞知识库集合
    try:
        _chroma_client.get_or_create_collection(
            name="vulnerability_kb"
        )
    except Exception as e:
        logger.warning(f"创建 vulnerability_kb 集合失败: {e}")

    # 历史审计结果集合
    try:
        _chroma_client.get_or_create_collection(
            name="historical_findings"
        )
    except Exception as e:
        logger.warning(f"创建 historical_findings 集合失败: {e}")


async def check_vector_store() -> bool:
    """检查向量数据库连接状态"""
    if not _chroma_client:
        return False

    try:
        _chroma_client.heartbeat()
        return True
    except Exception:
        return False


def get_client() -> Optional[chromadb.HttpClient]:
    """获取 ChromaDB 客户端"""
    return _chroma_client


# ========== 向量操作函数 ==========

async def add_code_chunks(
    project_id: str,
    chunks: List[Dict[str, Any]],
) -> None:
    """
    添加代码切片到向量库

    Args:
        project_id: 项目 ID
        chunks: 代码切片列表，每个切片包含:
            - id: 唯一标识
            - text: 代码文本
            - metadata: 元数据 (file, line_range, language, etc.)
            - embedding: 向量嵌入 (可选，如果没有会自动生成)
    """
    client = get_client()
    if not client:
        logger.warning("ChromaDB 未连接，跳过代码切片存储")
        return

    try:
        collection = client.get_collection("code_chunks")

        ids = [f"{project_id}_{c['id']}" for c in chunks]
        texts = [c["text"] for c in chunks]
        metadatas = [
            {
                "project_id": project_id,
                **c.get("metadata", {})
            }
            for c in chunks
        ]

        # 如果提供了 embedding，使用它；否则 ChromaDB 会自动生成
        embeddings = [c.get("embedding") for c in chunks] if chunks[0].get("embedding") else None

        collection.add(
            ids=ids,
            documents=texts,
            metadatas=metadatas,
            embeddings=embeddings,
        )

        logger.info(f"添加 {len(chunks)} 个代码切片到向量库")
    except Exception as e:
        logger.error(f"添加代码切片失败: {e}")


async def search_similar_code(
    query: str,
    top_k: int = 5,
    filter: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    搜索相似代码片段

    Args:
        query: 查询文本
        top_k: 返回结果数量
        filter: 元数据过滤条件

    Returns:
        相似代码片段列表
    """
    client = get_client()
    if not client:
        return []

    try:
        collection = client.get_collection("code_chunks")

        results = collection.query(
            query_texts=[query],
            n_results=top_k,
            where=filter,
        )

        # 格式化结果
        formatted_results = []
        if results["documents"] and results["documents"][0]:
            for i, doc in enumerate(results["documents"][0]):
                formatted_results.append({
                    "text": doc,
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else 0,
                })

        return formatted_results
    except Exception as e:
        logger.error(f"搜索相似代码失败: {e}")
        return []


async def add_vulnerability_knowledge(
    vuln_data: List[Dict[str, Any]],
) -> None:
    """
    添加漏洞知识到向量库

    Args:
        vuln_data: 漏洞数据列表，包含:
            - cwe_id: CWE ID
            - title: 标题
            - description: 描述
            - patterns: 漏洞模式列表
    """
    client = get_client()
    if not client:
        return

    try:
        collection = client.get_collection("vulnerability_kb")

        ids = [v["cwe_id"] for v in vuln_data]
        texts = [f"{v['title']}\n\n{v['description']}" for v in vuln_data]
        metadatas = [
            {
                "cwe_id": v["cwe_id"],
                "patterns": ",".join(v.get("patterns", [])),
            }
            for v in vuln_data
        ]

        collection.add(
            ids=ids,
            documents=texts,
            metadatas=metadatas,
        )

        logger.info(f"添加 {len(vuln_data)} 条漏洞知识")
    except Exception as e:
        logger.error(f"添加漏洞知识失败: {e}")


async def search_vulnerability_patterns(
    query: str,
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    """
    搜索相似漏洞模式

    Args:
        query: 查询文本（代码片段或描述）
        top_k: 返回结果数量

    Returns:
        相似漏洞模式列表
    """
    client = get_client()
    if not client:
        return []

    try:
        collection = client.get_collection("vulnerability_kb")

        results = collection.query(
            query_texts=[query],
            n_results=top_k,
        )

        formatted_results = []
        if results["documents"] and results["documents"][0]:
            for i, doc in enumerate(results["documents"][0]):
                formatted_results.append({
                    "text": doc,
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else 0,
                })

        return formatted_results
    except Exception as e:
        logger.error(f"搜索漏洞模式失败: {e}")
        return []
