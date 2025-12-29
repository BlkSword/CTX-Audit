"""
知识模块加载器

动态加载漏洞和框架特定的知识模块
"""
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from loguru import logger
import yaml


class KnowledgeLoader:
    """
    知识模块加载器

    负责从文件系统加载漏洞、框架和模式特定的知识模块
    """

    def __init__(self, knowledge_dir: str = "./prompts/knowledge"):
        """
        初始化知识加载器

        Args:
            knowledge_dir: 知识模块根目录
        """
        self.knowledge_dir = Path(knowledge_dir)
        self._cache: Dict[str, str] = {}
        self._available_modules: Optional[Set[str]] = None

        if not self.knowledge_dir.exists():
            logger.warning(f"知识目录不存在: {self.knowledge_dir}")

    async def load_modules(self, module_names: List[str]) -> str:
        """
        加载指定的知识模块

        Args:
            module_names: 模块名称列表

        Returns:
            拼接后的知识内容
        """
        sections = []

        for module_name in module_names:
            content = await self._load_module(module_name)
            if content:
                sections.append(f"<{module_name}_knowledge>\n{content}\n</{module_name}_knowledge>")

        return "\n\n".join(sections)

    async def load_module(self, module_name: str) -> str:
        """
        加载单个知识模块

        Args:
            module_name: 模块名称

        Returns:
            模块内容
        """
        return await self._load_module(module_name)

    async def _load_module(self, module_name: str) -> str:
        """加载单个模块（内部方法）"""
        if module_name in self._cache:
            return self._cache[module_name]

        # 搜索模块文件
        module_path = self._find_module(module_name)
        if not module_path:
            logger.debug(f"未找到知识模块: {module_name}")
            return ""

        # 读取内容
        try:
            content = module_path.read_text(encoding="utf-8")
            self._cache[module_name] = content
            return content
        except Exception as e:
            logger.warning(f"读取知识模块失败 ({module_name}): {e}")
            return ""

    def _find_module(self, module_name: str) -> Optional[Path]:
        """
        查找模块文件

        搜索顺序：
        1. vulnerabilities/{module_name}.md
        2. frameworks/{module_name}.md
        3. patterns/{module_name}.md
        4. 递归搜索所有 .md 文件
        """
        # 标准化名称
        normalized_name = module_name.lower().replace("-", "_").replace(" ", "_")

        # 直接搜索各个子目录
        for subdir in ["vulnerabilities", "frameworks", "patterns"]:
            path = self.knowledge_dir / subdir / f"{normalized_name}.md"
            if path.exists():
                return path

        # 递归搜索
        if self.knowledge_dir.exists():
            for path in self.knowledge_dir.rglob("*.md"):
                if path.stem.lower() == normalized_name:
                    return path

        return None

    async def get_relevant_modules(
        self,
        tech_stack: List[str],
        vulnerability_types: List[str],
    ) -> List[str]:
        """
        根据技术栈和漏洞类型获取相关模块

        Args:
            tech_stack: 技术栈列表 (如 ["fastapi", "postgresql"])
            vulnerability_types: 漏洞类型列表 (如 ["sql_injection", "xss"])

        Returns:
            相关模块名称列表
        """
        modules = []

        # 添加框架知识
        for framework in tech_stack:
            if await self._module_exists(framework):
                modules.append(framework)

        # 添加漏洞知识
        for vuln_type in vulnerability_types:
            module_name = self._normalize_vuln_name(vuln_type)
            if await self._module_exists(module_name):
                modules.append(module_name)

        return modules

    async def _module_exists(self, module_name: str) -> bool:
        """检查模块是否存在"""
        return self._find_module(module_name) is not None

    def _normalize_vuln_name(self, vuln_type: str) -> str:
        """
        规范化漏洞名称

        将各种漏洞类型别名映射到标准模块名
        """
        mapping = {
            # SQL 注入
            "sqli": "sql_injection",
            "sql injection": "sql_injection",
            "sql": "sql_injection",

            # XSS
            "xss": "xss",
            "cross_site_scripting": "xss",
            "cross site scripting": "xss",
            "csrf": "csrf",  # CSRF 不是 XSS，单独处理

            # SSRF
            "ssrf": "ssrf",

            # 路径遍历
            "path_traversal": "path_traversal",
            "directory traversal": "path_traversal",
            "lfi": "path_traversal",
            "rfi": "path_traversal",

            # 命令注入
            "command_injection": "command_injection",
            "rce": "command_injection",
            "remote code execution": "command_injection",

            # 其他
            "xxe": "xxe",
            "deserialization": "insecure_deserialization",
            "insecure deserialization": "insecure_deserialization",
            "auth": "authentication",
            "authentication": "authentication",
            "authorization": "authorization",
            "idOR": "insecure_direct_object_reference",
            "idor": "insecure_direct_object_reference",
        }

        key = vuln_type.lower().strip()
        return mapping.get(key, key.replace(" ", "_").replace("-", "_"))

    def list_available_modules(self) -> Dict[str, List[str]]:
        """
        列出所有可用的知识模块

        Returns:
            按类别分组的模块列表
        """
        if not self.knowledge_dir.exists():
            return {}

        modules = {
            "vulnerabilities": [],
            "frameworks": [],
            "patterns": [],
        }

        for subdir in modules.keys():
            subdir_path = self.knowledge_dir / subdir
            if subdir_path.exists():
                for md_file in subdir_path.glob("*.md"):
                    modules[subdir].append(md_file.stem)

        return modules

    def reload_cache(self) -> None:
        """清除缓存，强制重新加载"""
        self._cache.clear()
        logger.info("知识模块缓存已清除")

    async def load_knowledge_for_vulnerability(
        self,
        vuln_type: str,
        framework: Optional[str] = None,
    ) -> str:
        """
        为特定漏洞类型加载相关知识

        Args:
            vuln_type: 漏洞类型
            framework: 相关框架（可选）

        Returns:
            知识内容
        """
        modules = [self._normalize_vuln_name(vuln_type)]

        if framework:
            modules.append(framework.lower())

        return await self.load_modules(modules)


# 全局实例
knowledge_loader = KnowledgeLoader()
