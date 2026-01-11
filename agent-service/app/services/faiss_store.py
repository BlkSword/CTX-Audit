"""
基于 Faiss 的向量存储服务

高性能、无外部依赖的本地向量搜索
"""
from typing import Optional, List, Dict, Any, Tuple
from loguru import logger
import numpy as np
import pickle
import hashlib
from pathlib import Path

from app.config import settings


class FaissVectorStore:
    """
    基于 Faiss 的向量存储

    无需外部服务，完全本地运行
    """

    def __init__(self, dimension: int = 384):
        """
        初始化向量存储

        Args:
            dimension: 向量维度（取决于 embedding 模型）
        """
        self.dimension = dimension
        self.index = None
        self.documents: List[Dict[str, Any]] = []
        self.embeddings: Optional[np.ndarray] = None

    def _init_index(self):
        """初始化 Faiss 索引"""
        try:
            import faiss
            # 使用 L2 距离的索引
            self.index = faiss.IndexFlatL2(self.dimension)
            logger.info(f"Faiss 索引初始化成功 (维度: {self.dimension})")
            return True
        except ImportError:
            logger.warning("Faiss 未安装，请运行: pip install faiss-cpu")
            return False
        except Exception as e:
            logger.error(f"Faiss 初始化失败: {e}")
            return False

    def is_available(self) -> bool:
        """检查 Faiss 是否可用"""
        try:
            import faiss
            return True
        except ImportError:
            return False

    def add_documents(
        self,
        texts: List[str],
        embeddings: Optional[np.ndarray] = None,
        metadatas: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """
        添加文档到向量库

        Args:
            texts: 文本列表
            embeddings: 可选的预计算向量
            metadatas: 元数据列表

        Returns:
            是否成功
        """
        if not self.is_available():
            return False

        try:
            import faiss

            # 如果没有提供 embeddings，计算它们
            if embeddings is None:
                embeddings = self._compute_embeddings(texts)

            if embeddings is None:
                return False

            # 初始化索引（如果需要）
            if self.index is None:
                self._init_index()

            # 添加向量到索引
            self.index.add(embeddings.astype(np.float32))

            # 保存文档和元数据
            for i, (text, embedding) in enumerate(zip(texts, embeddings)):
                doc = {
                    "id": hashlib.md5(text.encode()).hexdigest(),
                    "text": text,
                    "embedding": embedding,
                    "metadata": metadatas[i] if metadatas else {},
                }
                self.documents.append(doc)

            logger.info(f"添加 {len(texts)} 个文档到向量库")
            return True

        except Exception as e:
            logger.error(f"添加文档失败: {e}")
            return False

    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_metadata: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        搜索相似文档

        Args:
            query: 查询文本
            top_k: 返回结果数量
            filter_metadata: 元数据过滤

        Returns:
            相似文档列表
        """
        if not self.is_available() or self.index is None:
            return []

        try:
            import faiss

            # 计算查询向量
            query_embedding = self._compute_embeddings([query])
            if query_embedding is None:
                return []

            # 搜索
            distances, indices = self.index.search(query_embedding.astype(np.float32), top_k)

            # 格式化结果
            results = []
            for dist, idx in zip(distances[0], indices[0]):
                if idx < 0 or idx >= len(self.documents):
                    continue

                doc = self.documents[idx].copy()

                # 元数据过滤
                if filter_metadata:
                    match = True
                    for k, v in filter_metadata.items():
                        if doc.get("metadata", {}).get(k) != v:
                            match = False
                            break
                    if not match:
                        continue

                # 添加距离分数（转换为相似度）
                doc["distance"] = float(dist)
                doc["similarity"] = 1.0 / (1.0 + float(dist))

                results.append(doc)

            return results

        except Exception as e:
            logger.error(f"搜索失败: {e}")
            return []

    def _compute_embeddings(self, texts: List[str]) -> Optional[np.ndarray]:
        """
        计算文本向量

        使用 sentence-transformers 模型
        """
        try:
            from sentence_transformers import SentenceTransformer

            # 加载模型（使用轻量级模型）
            model_name = "sentence-transformers/all-MiniLM-L6-v2"  # 384维
            model = SentenceTransformer(model_name)

            # 计算向量
            embeddings = model.encode(texts, show_progress_bar=False)
            return embeddings

        except ImportError:
            logger.warning("sentence-transformers 未安装，请运行: pip install sentence-transformers")
            return None
        except Exception as e:
            logger.error(f"计算向量失败: {e}")
            return None

    def save(self, path: str = "data/vector_store.pkl"):
        """保存向量库到文件"""
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)

            data = {
                "documents": self.documents,
                "dimension": self.dimension,
            }

            # 保存索引
            if self.index:
                import faiss
                faiss.write_index(self.index, path.replace(".pkl", ".index"))

            # 保存文档
            with open(path, "wb") as f:
                pickle.dump(data, f)

            logger.info(f"向量库已保存到 {path}")
            return True

        except Exception as e:
            logger.error(f"保存向量库失败: {e}")
            return False

    def load(self, path: str = "data/vector_store.pkl"):
        """从文件加载向量库"""
        try:
            import faiss

            # 加载文档
            with open(path, "rb") as f:
                data = pickle.load(f)

            self.documents = data["documents"]
            self.dimension = data["dimension"]

            # 加载索引
            index_path = path.replace(".pkl", ".index")
            if Path(index_path).exists():
                self.index = faiss.read_index(index_path)
                logger.info(f"向量库已从 {path} 加载")
                return True

        except Exception as e:
            logger.error(f"加载向量库失败: {e}")

        return False

    def clear(self):
        """清空向量库"""
        self.documents = []
        self.embeddings = None
        if self.index:
            self.index.reset()


# 全局向量存储实例
_vector_store: Optional[FaissVectorStore] = None
_code_store: Optional[FaissVectorStore] = None
_vulnerability_store: Optional[FaissVectorStore] = None


def get_code_store() -> Optional[FaissVectorStore]:
    """获取代码向量存储"""
    global _code_store
    if _code_store is None:
        _code_store = FaissVectorStore(dimension=384)
        # 尝试加载已有的存储
        _code_store.load("data/code_store.pkl")
    return _code_store


def get_vulnerability_store() -> Optional[FaissVectorStore]:
    """获取漏洞知识库存储"""
    global _vulnerability_store
    if _vulnerability_store is None:
        _vulnerability_store = FaissVectorStore(dimension=384)
        # 尝试加载已有的存储
        _vulnerability_store.load("data/vulnerability_store.pkl")
    return _vulnerability_store


async def init_vector_store():
    """初始化向量存储"""
    if not get_code_store().is_available():
        logger.warning("Faiss 不可用，请安装: pip install faiss-cpu sentence-transformers")
        return

    logger.info("✅ Faiss 向量存储初始化完成")


async def check_vector_store() -> bool:
    """检查向量存储是否可用"""
    store = get_code_store()
    return store.is_available() and store.index is not None


async def search_similar_code(
    query: str,
    top_k: int = 5,
    filter_metadata: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """搜索相似代码"""
    store = get_code_store()
    if not store.is_available():
        return []

    return store.search(query, top_k=top_k, filter_metadata=filter_metadata)


async def search_vulnerability_patterns(
    query: str,
    top_k: int = 3,
) -> List[Dict[str, Any]]:
    """搜索漏洞模式"""
    store = get_vulnerability_store()
    if not store.is_available():
        return []

    return store.search(query, top_k=top_k)


async def add_code_chunks(
    project_id: str,
    chunks: List[Dict[str, Any]],
) -> None:
    """添加代码切片到向量库"""
    store = get_code_store()
    if not store.is_available():
        logger.warning("向量存储不可用")
        return

    texts = [c["text"] for c in chunks]
    metadatas = [
        {"project_id": project_id, **c.get("metadata", {})}
        for c in chunks
    ]

    store.add_documents(texts, metadatas=metadatas)
    store.save("data/code_store.pkl")


async def add_vulnerability_knowledge(
    vuln_data: List[Dict[str, Any]],
) -> None:
    """添加漏洞知识到向量库"""
    store = get_vulnerability_store()
    if not store.is_available():
        logger.warning("向量存储不可用")
        return

    texts = [
        f"{v['title']}\n\n{v.get('description', '')}"
        for v in vuln_data
    ]
    metadatas = [
        {"cwe_id": v["cwe_id"], "patterns": ",".join(v.get("patterns", []))}
        for v in vuln_data
    ]

    store.add_documents(texts, metadatas=metadatas)
    store.save("data/vulnerability_store.pkl")
