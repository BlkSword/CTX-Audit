"""
向量存储服务

使用 Qdrant 向量数据库进行 RAG 功能
"""
from typing import Optional, List, Dict, Any
from loguru import logger
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter

# 尝试导入 qdrant_client
try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct, Filter
    QDRANT_AVAILABLE = True
except ImportError:
    logger.warning("Qdrant 客户端未安装，请运行: pip install qdrant-client")
    QDRANT_AVAILABLE = False
    QdrantClient = None  # type: ignore

from app.config import settings

# 全局 Qdrant 客户端
_qdrant_client: Optional[QdrantClient] = None

# 集合名称
COLLECTION_CODE_CHUNKS = "code_chunks"
COLLECTION_VULNERABILITY_KB = "vulnerability_kb"
COLLECTION_HISTORICAL_FINDINGS = "historical_findings"

# 向量维度（使用 fastembed 的默认维度）
VECTOR_SIZE = 384  # sentence-transformers/all-MiniLM-L6-v2 的维度


async def init_vector_store():
    """初始化 Qdrant 连接"""
    global _qdrant_client

    if not QDRANT_AVAILABLE:
        logger.warning("Qdrant 客户端不可用，RAG 功能将被禁用")
        return

    if _qdrant_client is not None:
        return

    try:
        # 连接到 Qdrant（使用 HTTP）
        _qdrant_client = QdrantClient(
            host=settings.QDRANT_HOST,
            port=settings.QDRANT_PORT,
        )

        # 测试连接
        try:
            collections = _qdrant_client.get_collections()
            logger.info(f"Qdrant 连接成功，已有 {len(collections.collections)} 个集合")
        except Exception as e:
            logger.warning(f"Qdrant 服务未启动或不可达: {e}")
            logger.info("请先启动 Qdrant: docker run -p 6333:6333 qdrant/qdrant")
            _qdrant_client = None
            return

        # 创建必要的集合
        _create_collections()

        logger.info("✅ Qdrant 初始化完成（RAG 功能已启用）")

    except Exception as e:
        logger.error(f"Qdrant 初始化失败: {e}")
        logger.info("请确保 Qdrant 服务正在运行: docker run -p 6333:6333 qdrant/qdrant")
        _qdrant_client = None


def _create_collections():
    """创建向量集合"""
    if not _qdrant_client:
        return

    collections = [
        (COLLECTION_CODE_CHUNKS, "代码片段集合"),
        (COLLECTION_VULNERABILITY_KB, "漏洞知识库集合"),
        (COLLECTION_HISTORICAL_FINDINGS, "历史审计结果集合"),
    ]

    for collection_name, description in collections:
        try:
            # 检查集合是否存在
            _qdrant_client.get_collection(collection_name)
            logger.info(f"集合 '{collection_name}' 已存在")
        except Exception:
            # 集合不存在，创建它
            try:
                _qdrant_client.create_collection(
                    collection_name=collection_name,
                    vectors_config=VectorParams(
                        size=VECTOR_SIZE,
                        distance=Distance.COSINE,
                    ),
                )
                logger.info(f"✅ 创建集合: {collection_name}")
            except Exception as e:
                logger.warning(f"创建集合 '{collection_name}' 失败: {e}")


async def check_vector_store() -> bool:
    """检查向量数据库连接状态"""
    if not QDRANT_AVAILABLE:
        return False

    if not _qdrant_client:
        return False

    try:
        _qdrant_client.get_collections()
        return True
    except Exception:
        return False


def get_client() -> Optional[QdrantClient]:
    """获取 Qdrant 客户端"""
    return _qdrant_client


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
    """
    client = get_client()
    if not client:
        logger.warning("Qdrant 未连接，跳过代码切片存储")
        return

    try:
        # 生成向量嵌入
        from fastembed import TextEmbedding
        embedding_model = TextEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")

        texts = [c["text"] for c in chunks]
        embeddings = list(embedding_model.embed(texts))

        # 准备点数据
        points = []
        for i, chunk in enumerate(chunks):
            point_id = f"{project_id}_{chunk['id']}"
            points.append(
                PointStruct(
                    id=point_id,
                    vector=embeddings[i].tolist(),
                    payload={
                        "project_id": project_id,
                        "text": chunk["text"],
                        **chunk.get("metadata", {})
                    }
                )
            )

        # 批量插入
        client.upsert(
            collection_name=COLLECTION_CODE_CHUNKS,
            points=points,
        )

        logger.info(f"✅ 添加 {len(chunks)} 个代码切片到向量库")

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
        # 生成查询向量
        from fastembed import TextEmbedding
        embedding_model = TextEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")
        query_embedding = list(embedding_model.embed([query]))[0].tolist()

        # 构建过滤条件
        query_filter = None
        if filter:
            # 这里可以添加更复杂的过滤逻辑
            pass

        # 搜索
        search_result = client.search(
            collection_name=COLLECTION_CODE_CHUNKS,
            query_vector=query_embedding,
            limit=top_k,
            query_filter=query_filter,
        )

        # 格式化结果
        formatted_results = []
        for hit in search_result:
            payload = hit.payload or {}
            formatted_results.append({
                "text": payload.get("text", ""),
                "metadata": {
                    "file": payload.get("file", "unknown"),
                    "line_range": payload.get("line_range", "unknown"),
                    "project_id": payload.get("project_id", ""),
                },
                "distance": 1 - hit.score,  # 转换为距离（余弦相似度）
                "score": hit.score,
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
        from fastembed import TextEmbedding
        embedding_model = TextEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")

        # 准备文本和嵌入
        texts = [f"{v['cwe_id']}: {v['title']}\n\n{v['description']}" for v in vuln_data]
        embeddings = list(embedding_model.embed(texts))

        # 准备点数据
        points = []
        for i, vuln in enumerate(vuln_data):
            points.append(
                PointStruct(
                    id=vuln["cwe_id"],
                    vector=embeddings[i].tolist(),
                    payload={
                        "cwe_id": vuln["cwe_id"],
                        "title": vuln["title"],
                        "description": vuln["description"],
                        "patterns": ",".join(vuln.get("patterns", [])),
                    }
                )
            )

        # 批量插入
        client.upsert(
            collection_name=COLLECTION_VULNERABILITY_KB,
            points=points,
        )

        logger.info(f"✅ 添加 {len(vuln_data)} 条漏洞知识")

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
        from fastembed import TextEmbedding
        embedding_model = TextEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")
        query_embedding = list(embedding_model.embed([query]))[0].tolist()

        # 搜索
        search_result = client.search(
            collection_name=COLLECTION_VULNERABILITY_KB,
            query_vector=query_embedding,
            limit=top_k,
        )

        # 格式化结果
        formatted_results = []
        for hit in search_result:
            payload = hit.payload or {}
            formatted_results.append({
                "text": f"{payload.get('cwe_id', '')}: {payload.get('title', '')}\n\n{payload.get('description', '')}",
                "metadata": {
                    "cwe_id": payload.get("cwe_id", "unknown"),
                    "patterns": payload.get("patterns", ""),
                },
                "distance": 1 - hit.score,
                "score": hit.score,
            })

        return formatted_results

    except Exception as e:
        logger.error(f"搜索漏洞模式失败: {e}")
        return []


async def add_historical_findings(
    project_id: str,
    findings: List[Dict[str, Any]],
) -> None:
    """
    添加历史审计结果到向量库

    Args:
        project_id: 项目 ID
        findings: 审计结果列表
    """
    client = get_client()
    if not client:
        return

    try:
        from fastembed import TextEmbedding
        embedding_model = TextEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")

        # 准备文本
        texts = [
            f"{f.get('title', '')}: {f.get('description', '')}\n文件: {f.get('file_path', '')}"
            for f in findings
        ]
        embeddings = list(embedding_model.embed(texts))

        # 准备点数据
        points = []
        for i, finding in enumerate(findings):
            finding_id = f"{project_id}_{finding.get('id', i)}"
            points.append(
                PointStruct(
                    id=finding_id,
                    vector=embeddings[i].tolist(),
                    payload={
                        "project_id": project_id,
                        **finding
                    }
                )
            )

        # 批量插入
        client.upsert(
            collection_name=COLLECTION_HISTORICAL_FINDINGS,
            points=points,
        )

        logger.info(f"✅ 添加 {len(findings)} 条历史审计结果")

    except Exception as e:
        logger.error(f"添加历史审计结果失败: {e}")
