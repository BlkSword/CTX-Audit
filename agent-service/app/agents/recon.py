"""
Recon Agent - 侦察兵

负责信息收集、项目结构分析和攻击面识别
"""
from typing import Dict, Any, List
from loguru import logger

from app.agents.base import BaseAgent


class ReconAgent(BaseAgent):
    """
    Recon Agent

    职责：
    1. 扫描项目目录结构
    2. 识别编程语言和框架
    3. 提取 API 端点和路由
    4. 识别用户输入点
    5. 分析依赖库版本
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="recon", config=config)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行侦察任务

        Args:
            context: 上下文，包含:
                - audit_id: 审计 ID
                - project_id: 项目 ID
                - project_path: 项目路径（可选）

        Returns:
            侦察结果
        """
        project_id = context.get("project_id")
        self.think(f"开始项目侦察: {project_id}")

        # 1. 获取项目信息
        project_info = await self._get_project_info(project_id)
        self.think(f"项目路径: {project_info.get('path', 'Unknown')}")

        # 2. 扫描项目结构
        structure = await self._scan_structure(project_info)
        self.think(f"发现 {len(structure.get('files', []))} 个文件")

        # 3. 识别技术栈
        tech_stack = await self._identify_tech_stack(structure)
        self.think(f"识别到语言: {tech_stack.get('languages', [])}")
        self.think(f"识别到框架: {tech_stack.get('frameworks', [])}")

        # 4. 提取攻击面
        attack_surface = await self._extract_attack_surface(structure, tech_stack)
        self.think(f"发现 {len(attack_surface.get('entry_points', []))} 个攻击面入口点")

        # 5. 分析依赖
        dependencies = await self._analyze_dependencies(structure)
        self.think(f"发现 {len(dependencies.get('libraries', []))} 个依赖库")

        return {
            "project_info": project_info,
            "structure": structure,
            "tech_stack": tech_stack,
            "attack_surface": attack_surface,
            "dependencies": dependencies,
        }

    async def _get_project_info(self, project_id: str) -> Dict[str, Any]:
        """获取项目信息"""
        from app.services.rust_client import rust_client

        try:
            return await rust_client.get_project(project_id)
        except Exception as e:
            logger.warning(f"获取项目信息失败: {e}")
            return {"id": project_id, "path": "unknown"}

    async def _scan_structure(self, project_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        扫描项目结构
        
        Args:
            project_info: 项目信息
            
        Returns:
            项目结构
        """
        from app.services.rust_client import rust_client
        
        project_path = project_info.get("path")
        if not project_path:
            return {"files": [], "directories": []}
            
        # 简单递归扫描（深度限制为 3 以防过慢）
        files = []
        directories = []
        
        async def _scan_recursive(path: str, depth: int):
            if depth > 3:
                return
            
            try:
                items = await rust_client.list_files(path)
                for item in items:
                    full_path = f"{path}/{item}" if path != "/" else f"/{item}"
                    # 这里假设没有后缀的是目录，有后缀的是文件（简化逻辑）
                    # 更好的方式是 Rust 返回文件类型
                    if "." in item:
                        files.append(full_path)
                    else:
                        directories.append(full_path)
                        await _scan_recursive(full_path, depth + 1)
            except Exception as e:
                logger.warning(f"扫描目录失败 {path}: {e}")
                
        await _scan_recursive(project_path, 0)
        
        return {"files": files, "directories": directories}

    async def _identify_tech_stack(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        """识别技术栈"""
        files = structure.get("files", [])
        languages = set()
        frameworks = set()
        
        # 基于文件扩展名的简单识别
        extensions = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".java": "Java",
            ".go": "Go",
            ".rs": "Rust",
            ".php": "PHP",
            ".rb": "Ruby",
        }
        
        for f in files:
            for ext, lang in extensions.items():
                if f.endswith(ext):
                    languages.add(lang)
                    
            # 简单框架识别
            if "package.json" in f:
                frameworks.add("Node.js")
            if "requirements.txt" in f:
                frameworks.add("Python/Pip")
            if "pom.xml" in f:
                frameworks.add("Java/Maven")
                
        return {
            "languages": list(languages),
            "frameworks": list(frameworks)
        }

    async def _extract_attack_surface(self, structure: Dict[str, Any], tech_stack: Dict[str, Any]) -> Dict[str, Any]:
        """提取攻击面"""
        # 这里可以使用 LLM 分析关键文件，如 routes.py, app.js 等
        # 暂时返回空，后续集成 LLM
        return {"entry_points": []}

    async def _analyze_dependencies(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        """分析依赖"""
        return {"libraries": []}

        # 临时返回模拟数据
        return {
            "files": [],
            "directories": [],
            "total_files": 0,
            "total_lines": 0,
        }

    async def _identify_tech_stack(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        """
        识别技术栈

        Args:
            structure: 项目结构

        Returns:
            技术栈信息
        """
        # 基于文件扩展名识别语言
        language_map = {
            ".rs": "rust",
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".go": "go",
            ".java": "java",
        }

        languages = []
        frameworks = []

        # TODO: 实际分析文件
        # 这里只是框架

        return {
            "languages": list(set(languages)),
            "frameworks": frameworks,
        }

    async def _extract_attack_surface(
        self,
        structure: Dict[str, Any],
        tech_stack: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        提取攻击面

        Args:
            structure: 项目结构
            tech_stack: 技术栈

        Returns:
            攻击面信息
        """
        entry_points = []

        # TODO: 实际提取攻击面
        # - API 路由
        # - 表单输入
        # - 文件上传
        # - 命令执行点

        return {
            "entry_points": entry_points,
            "api_endpoints": [],
            "user_inputs": [],
            "file_operations": [],
            "command_executions": [],
        }

    async def _analyze_dependencies(self, structure: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析依赖库

        Args:
            structure: 项目结构

        Returns:
            依赖信息
        """
        libraries = []

        # TODO: 实际分析依赖文件
        # - package.json (Node.js)
        # - requirements.txt (Python)
        # - Cargo.toml (Rust)
        # - pom.xml (Java)

        return {
            "libraries": libraries,
            "known_vulnerabilities": [],
        }


# 创建全局实例
recon_agent = ReconAgent()
