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
        """
        识别技术栈

        Args:
            structure: 项目结构

        Returns:
            技术栈信息
        """
        files = structure.get("files", [])
        languages = set()
        frameworks = set()

        # 基于文件扩展名的简单识别
        extensions = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".tsx": "TypeScript",
            ".jsx": "JavaScript",
            ".java": "Java",
            ".go": "Go",
            ".rs": "Rust",
            ".php": "PHP",
            ".rb": "Ruby",
            ".cs": "C#",
            ".cpp": "C++",
            ".c": "C",
        }

        for f in files:
            # 语言识别
            for ext, lang in extensions.items():
                if f.endswith(ext):
                    languages.add(lang)

            # 简单框架识别
            if "package.json" in f:
                frameworks.add("Node.js")
            if "requirements.txt" in f or "Pipfile" in f or "pyproject.toml" in f:
                frameworks.add("Python/Pip")
            if "pom.xml" in f:
                frameworks.add("Java/Maven")
            if "build.gradle" in f:
                frameworks.add("Java/Gradle")
            if "Cargo.toml" in f:
                frameworks.add("Rust/Cargo")
            if "go.mod" in f:
                frameworks.add("Go/Module")
            if "composer.json" in f:
                frameworks.add("PHP/Composer")
            if "Gemfile" in f:
                frameworks.add("Ruby/Bundler")

        return {
            "languages": sorted(list(languages)),
            "frameworks": sorted(list(frameworks))
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
        api_endpoints = []
        user_inputs = []

        files = structure.get("files", [])

        # 识别潜在的攻击面入口
        for file_path in files:
            # Web 路由文件
            if any(x in file_path.lower() for x in ["route", "controller", "handler", "api", "view"]):
                entry_points.append({
                    "type": "web_route",
                    "file": file_path,
                    "description": "Web 路由定义文件"
                })

            # 表单/输入处理
            if any(x in file_path.lower() for x in ["form", "input", "upload", "submit"]):
                user_inputs.append({
                    "type": "user_input",
                    "file": file_path,
                    "description": "用户输入处理文件"
                })

            # 数据库查询
            if any(x in file_path.lower() for x in ["model", "query", "database", "db", "sql"]):
                entry_points.append({
                    "type": "database",
                    "file": file_path,
                    "description": "数据库操作文件"
                })

            # 认证/授权
            if any(x in file_path.lower() for x in ["auth", "login", "permission", "access"]):
                entry_points.append({
                    "type": "auth",
                    "file": file_path,
                    "description": "认证/授权文件",
                    "severity": "high"
                })

            # 文件操作
            if any(x in file_path.lower() for x in ["file", "fs", "io", "upload", "download"]):
                entry_points.append({
                    "type": "file_operation",
                    "file": file_path,
                    "description": "文件操作文件"
                })

            # 命令执行
            if any(x in file_path.lower() for x in ["exec", "spawn", "shell", "command", "system"]):
                entry_points.append({
                    "type": "command_execution",
                    "file": file_path,
                    "description": "命令执行相关",
                    "severity": "high"
                })

        return {
            "entry_points": entry_points,
            "api_endpoints": api_endpoints,
            "user_inputs": user_inputs,
            "file_operations": [e for e in entry_points if e["type"] == "file_operation"],
            "command_executions": [e for e in entry_points if e["type"] == "command_execution"],
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
        known_vulnerabilities = []

        files = structure.get("files", [])

        # 分析依赖文件
        for file_path in files:
            filename = file_path.split("/")[-1].lower()

            if filename == "package.json":
                # Node.js 依赖
                libraries.extend(await self._parse_package_json(file_path))
            elif filename == "requirements.txt":
                # Python 依赖
                libraries.extend(await self._parse_requirements_txt(file_path))
            elif filename == "pom.xml":
                # Java/Maven 依赖
                libraries.extend(await self._parse_pom_xml(file_path))
            elif filename == "cargo.toml":
                # Rust 依赖
                libraries.extend(await self._parse_cargo_toml(file_path))
            elif filename == "go.mod":
                # Go 依赖
                libraries.extend(await self._parse_go_mod(file_path))

        # TODO: 查询已知漏洞数据库（如 OSV、Snyk）
        # 这里可以添加自动化的漏洞检查

        return {
            "libraries": libraries,
            "known_vulnerabilities": known_vulnerabilities,
            "total_libraries": len(libraries)
        }

    async def _parse_package_json(self, file_path: str) -> List[Dict[str, str]]:
        """解析 package.json"""
        from app.services.rust_client import rust_client

        try:
            content = await rust_client.read_file(file_path)
            import json
            data = json.loads(content)

            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})

            libraries = []
            for name, version in list(deps.items()) + list(dev_deps.items()):
                libraries.append({
                    "name": name,
                    "version": version,
                    "type": "production" if name in deps else "development",
                    "ecosystem": "npm"
                })

            return libraries
        except Exception as e:
            logger.warning(f"解析 package.json 失败: {e}")
            return []

    async def _parse_requirements_txt(self, file_path: str) -> List[Dict[str, str]]:
        """解析 requirements.txt"""
        from app.services.rust_client import rust_client

        try:
            content = await rust_client.read_file(file_path)

            libraries = []
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # 解析包名和版本
                parts = line.split(">=")[:1] if ">=" in line else \
                        line.split("==")[:1] if "==" in line else \
                        line.split("~")[:1] if "~" in line else \
                        [line]

                if parts:
                    libraries.append({
                        "name": parts[0].strip(),
                        "version": line.replace(parts[0], "").strip() or "unknown",
                        "type": "production",
                        "ecosystem": "pypi"
                    })

            return libraries
        except Exception as e:
            logger.warning(f"解析 requirements.txt 失败: {e}")
            return []

    async def _parse_pom_xml(self, file_path: str) -> List[Dict[str, str]]:
        """解析 pom.xml（简化版）"""
        # Maven 依赖解析比较复杂，这里简化处理
        return [{
            "name": "maven-project",
            "version": "unknown",
            "type": "production",
            "ecosystem": "maven",
            "note": "Maven 依赖解析需要完整 XML 解析器"
        }]

    async def _parse_cargo_toml(self, file_path: str) -> List[Dict[str, str]]:
        """解析 Cargo.toml（简化版）"""
        return [{
            "name": "rust-project",
            "version": "unknown",
            "type": "production",
            "ecosystem": "crates.io",
            "note": "Cargo 依赖解析需要 TOML 解析器"
        }]

    async def _parse_go_mod(self, file_path: str) -> List[Dict[str, str]]:
        """解析 go.mod（简化版）"""
        return [{
            "name": "go-project",
            "version": "unknown",
            "type": "production",
            "ecosystem": "go",
            "note": "Go 依赖解析需要专用解析器"
        }]


# 创建全局实例
recon_agent = ReconAgent()
