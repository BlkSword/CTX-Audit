"""
Recon Agent - 侦察兵（增强版）

负责信息收集、项目结构分析和攻击面识别
集成外部安全工具和数据流分析
"""
from typing import Dict, Any, List, Optional, Set
from loguru import logger
from pathlib import Path

from app.agents.base import BaseAgent
from app.services.external_tools import (
    ExternalToolService,
    get_external_tool_service,
    ToolInfo,
)
from app.core.dataflow_analysis import (
    DataFlowAnalyzer,
    get_dataflow_analyzer,
    Vulnerability,
)


class ReconAgent(BaseAgent):
    """
    Recon Agent (增强版)

    职责：
    1. 扫描项目目录结构
    2. 识别编程语言和框架
    3. 推荐并运行外部安全工具
    4. 执行数据流分析识别高风险区域
    5. 生成优先级排序的扫描目标列表

    参考 DeepAudit-3.0.0 实现
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="recon", config=config)
        self._tool_service: Optional[ExternalToolService] = None
        self._dataflow_analyzer: Optional[DataFlowAnalyzer] = None

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
        raw_path = project_info.get("path", "")
        
        # 智能解析项目路径
        project_path = await self._resolve_project_path(raw_path)
        self.think(f"项目路径: {project_path}")

        if not project_path:
            self.think("警告: 项目路径为空或不存在，无法进行完整扫描")
            # 尝试使用 context 中的 path
            if context.get("project_path"):
                 project_path = await self._resolve_project_path(context.get("project_path"))
                 self.think(f"尝试使用 context 路径: {project_path}")
            
            if not project_path:
                return {"error": "项目路径不存在"}

        # 初始化服务
        self._tool_service = get_external_tool_service(project_path)
        self._dataflow_analyzer = get_dataflow_analyzer()

        # 2. 识别技术栈
        tech_stack = await self._identify_tech_stack(project_path)
        self.think(f"识别到语言: {tech_stack.get('languages', [])}")
        self.think(f"识别到框架: {tech_stack.get('frameworks', [])}")

        # 3. 推荐并检查可用工具
        recommended_tools = await self._recommend_tools(tech_stack)
        available_tools = await self._tool_service.get_available_tools()
        self.think(f"推荐工具: {[t.name for t in recommended_tools]}")
        self.think(f"可用工具: {[t.name for t in available_tools]}")

        # 4. 运行外部工具进行快速扫描
        tool_findings = await self._scan_with_tools(recommended_tools, available_tools)
        self.think(f"外部工具发现 {len(tool_findings)} 个潜在问题")

        # 5. 提取高风险区域
        high_risk_areas = await self._extract_high_risk_areas(
            tool_findings, tech_stack, project_path
        )
        self.think(f"识别到 {len(high_risk_areas)} 个高风险区域")

        # 6. 执行数据流分析
        dataflow_findings = await self._run_dataflow_analysis(project_path, tech_stack)
        self.think(f"数据流分析发现 {len(dataflow_findings)} 个潜在漏洞")

        # 7. 扫描项目结构
        structure = await self._scan_structure(project_path)
        self.think(f"发现 {len(structure.get('files', []))} 个文件")

        # 8. 提取攻击面
        attack_surface = await self._extract_attack_surface(structure, tech_stack)
        self.think(f"发现 {len(attack_surface.get('entry_points', []))} 个攻击面入口点")

        # 9. 分析依赖
        dependencies = await self._analyze_dependencies(structure)
        self.think(f"发现 {len(dependencies.get('libraries', []))} 个依赖库")

        # 10. 识别高价值目标（Weaponization）
        hvt_targets = await self._identify_high_value_targets(project_path)
        self.think(f"识别到 {len(hvt_targets)} 个高价值目标文件")
        
        # 合并到 high_risk_areas
        for target in hvt_targets:
            high_risk_areas.append({
                "path": target["path"],
                "risk_score": 0.8,  # 高价值目标默认高风险
                "reason": target["description"]
            })

        # 11. 生成优先级排序的扫描目标
        prioritized_targets = self._prioritize_scan_targets(
            high_risk_areas, dataflow_findings, attack_surface
        )

        return {
            "project_info": project_info,
            "project_path": project_path, # 返回解析后的路径
            "tech_stack": tech_stack,
            "recommended_tools": [t.name for t in recommended_tools],
            "available_tools": [t.name for t in available_tools],
            "tool_findings": tool_findings,
            "high_risk_areas": high_risk_areas,
            "dataflow_findings": dataflow_findings,
            "hvt_targets": hvt_targets,
            "structure": structure,
            "attack_surface": attack_surface,
            "dependencies": dependencies,
            "prioritized_targets": prioritized_targets,
        }

    async def _resolve_project_path(self, path_str: str) -> str:
        """智能解析项目路径"""
        if not path_str:
            return ""
            
        try:
            # 1. 直接解析
            path = Path(path_str).resolve()
            if path.exists() and path.is_dir():
                return str(path)
                
            # 2. 尝试相对于当前工作目录解析
            cwd = Path.cwd()
            path = (cwd / path_str).resolve()
            if path.exists() and path.is_dir():
                return str(path)

            # 3. 尝试修正 ./data/projects 路径问题
            # 如果当前在 agent-service 下，而路径包含 agent-service
            if "agent-service" in str(path):
                 new_path_str = str(path).replace("agent-service\\agent-service", "agent-service")
                 new_path = Path(new_path_str)
                 if new_path.exists() and new_path.is_dir():
                     return str(new_path)

            # 4. 尝试利用 Rust Client 反推路径 (最后手段)
            try:
                from app.services.rust_client import rust_client
                # 尝试获取文件列表，看能不能拿到真实路径
                files = await rust_client.list_files(path_str)
                if files:
                    first_file = files[0]
                    # first_file 应该是绝对路径
                    # 尝试找到 path_str 在 first_file 中的位置
                    # 例如 path_str="./data/projects/uuid", first_file="D:/.../data/projects/uuid/file"
                    # 我们取最后一个目录名 (uuid)
                    
                    target_name = Path(path_str).name
                    # 规范化分隔符以进行字符串匹配
                    norm_first_file = first_file.replace("\\", "/")
                    if target_name in norm_first_file:
                        # 截取到 target_name 结束
                        idx = norm_first_file.rfind(target_name)
                        if idx != -1:
                            real_path = norm_first_file[:idx + len(target_name)]
                            real_path_obj = Path(real_path)
                            if real_path_obj.exists() and real_path_obj.is_dir():
                                self.think(f"通过 Rust Client 反推路径成功: {real_path}")
                                return str(real_path)
            except Exception as e:
                # 只有在找不到路径时才记录这个，避免噪音
                pass
             
            return ""
        except Exception as e:
            logger.warning(f"路径解析失败: {e}")
            return ""

    async def _identify_high_value_targets(self, project_path: str) -> List[Dict[str, Any]]:
        """识别高价值目标文件 (Weaponization)"""
        project_dir = Path(project_path)
        targets = []
        
        # 定义高价值模式
        patterns = {
            "config": [
                "config.py", "settings.py", ".env", "application.yml", "application.properties",
                "web.config", "uwsgi.ini", "nginx.conf", "docker-compose.yml", "Dockerfile",
                "k8s.yaml", "helm.yaml"
            ],
            "auth": [
                "*auth*", "*login*", "*user*", "*permission*", "*role*", "*jwt*", "*token*",
                "*middleware*", "*interceptor*", "*filter*", "*security*"
            ],
            "upload": [
                "*upload*", "*file*", "*image*", "*attachment*", "*import*", "*export*"
            ],
            "database": [
                "*schema*", "*migration*", "*model*", "*entity*", "*db*", "*database*", "*sql*"
            ],
            "api": [
                "*api*", "*route*", "*controller*", "*view*", "*endpoint*", "*handler*"
            ],
            "crypto": [
                "*crypto*", "*cipher*", "*encrypt*", "*decrypt*", "*key*", "*secret*"
            ]
        }
        
        self.think("正在扫描高价值目标文件...")
        
        # 扫描 (限制数量以防卡死)
        count = 0
        max_targets = 100
        
        for category, pattern_list in patterns.items():
            if count >= max_targets:
                break
                
            for pattern in pattern_list:
                try:
                    # 使用 rglob 递归查找
                    for file_path in project_dir.rglob(pattern):
                        if count >= max_targets:
                            break
                            
                        # 过滤忽略目录
                        if any(p in str(file_path).replace("\\", "/") for p in [".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", "vendor", ".idea", ".vscode", "bin", "obj", "out"]):
                            continue
                            
                        if file_path.is_file():
                            try:
                                rel_path = str(file_path.relative_to(project_dir))
                                # 避免重复
                                if any(t["path"] == rel_path for t in targets):
                                    continue
                                    
                                targets.append({
                                    "path": rel_path,
                                    "category": category,
                                    "type": "high_value_file",
                                    "description": f"Potential {category} file: {rel_path}"
                                })
                                count += 1
                                
                                # 实时通知发现
                                await self._publish_event("thinking", {
                                    "message": f"🎯 发现高价值目标: {rel_path} ({category})"
                                })
                            except:
                                pass
                except Exception as e:
                    logger.warning(f"Error scanning pattern {pattern}: {e}")
                            
        return targets

    async def _get_project_info(self, project_id: str) -> Dict[str, Any]:
        """获取项目信息"""
        from app.services.rust_client import rust_client

        try:
            return await rust_client.get_project(project_id)
        except Exception as e:
            logger.warning(f"获取项目信息失败: {e}")
            return {"id": project_id, "path": "unknown"}

    async def _identify_tech_stack(self, project_path: str) -> Dict[str, Any]:
        """
        识别技术栈

        Args:
            project_path: 项目路径

        Returns:
            技术栈信息
        """
        languages = set()
        frameworks = set()
        package_managers = set()

        # 规范化路径：转换为绝对路径并规范化分隔符
        project_dir = Path(project_path).resolve()
        self.think(f"规范化后的项目路径: {project_dir}")

        # 检查目录是否存在
        if not project_dir.exists():
            self.think(f"警告: 项目目录不存在: {project_dir}")
            return {
                "languages": [],
                "frameworks": [],
                "package_managers": [],
            }
            
        # 忽略目录列表
        ignored_dirs = {
            ".git", "node_modules", "venv", ".venv", "__pycache__", 
            "dist", "build", "target", "vendor", ".idea", ".vscode",
            "bin", "obj", "out"
        }

        # 检查常见文件识别语言和框架
        check_files = [
            ("package.json", "JavaScript", ["Node.js"]),
            ("tsconfig.json", "TypeScript", ["Node.js"]),
            ("requirements.txt", "Python", ["Python/Pip"]),
            ("Pipfile", "Python", ["Pipenv"]),
            ("pyproject.toml", "Python", ["Poetry"]),
            ("setup.py", "Python", ["Python"]),
            ("pom.xml", "Java", ["Maven"]),
            ("build.gradle", "Java", ["Gradle"]),
            ("Cargo.toml", "Rust", ["Cargo"]),
            ("go.mod", "Go", ["Go Module"]),
            ("composer.json", "PHP", ["Composer"]),
            ("Gemfile", "Ruby", ["Bundler"]),
            ("pubspec.yaml", "Dart", ["Pub"]),
            ("mix.exs", "Elixir", ["Hex"]),
        ]

        found_files = []
        # 递归检查配置文件（限制深度）
        for file_name, lang, fw_list in check_files:
            try:
                # 首先检查根目录
                if (project_dir / file_name).exists():
                    languages.add(lang)
                    frameworks.update(fw_list)
                    found_files.append(file_name)
                    self._update_package_managers(file_name, package_managers)
                else:
                    # 如果根目录没有，尝试在子目录查找（深度2）
                    # 注意：rglob 可能会很慢，所以限制查找
                    matches = list(project_dir.glob(f"*/{file_name}")) + list(project_dir.glob(f"*/*/{file_name}"))
                    if matches:
                        # 过滤忽略目录
                        valid_match = False
                        for match in matches:
                            if not any(d in match.parts for d in ignored_dirs):
                                valid_match = True
                                break
                        
                        if valid_match:
                            languages.add(lang)
                            frameworks.update(fw_list)
                            found_files.append(file_name)
                            self._update_package_managers(file_name, package_managers)
            except Exception:
                pass

        if found_files:
            self.think(f"找到配置文件: {found_files}")

        # 通过文件扩展名补充语言识别
        extension_map = {
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
            ".kt": "Kotlin",
            ".swift": "Swift",
        }

        # 限制扫描深度，避免扫描过深
        scanned_count = 0
        max_files = 1000  # 增加扫描限制

        try:
            for file_path in project_dir.rglob("*"):
                if scanned_count >= max_files:
                    break
                
                # 过滤忽略目录
                if any(d in file_path.parts for d in ignored_dirs):
                    continue

                if file_path.is_file():
                    scanned_count += 1
                    file_str = str(file_path)
                    for ext, lang in extension_map.items():
                        if file_str.endswith(ext):
                            languages.add(lang)
                            break
        except PermissionError as e:
            self.think(f"文件扫描权限错误: {e}")

        # 检测 Web 框架 (增强版)
        web_frameworks_map = {
            "app.py": "Flask",
            "wsgi.py": "Flask",
            "manage.py": "Django",
            "application.go": "Go Web Framework",
            "gin.go": "Gin",
            "main.go": "Go", # 通用
            "NestFactory": "NestJS", # 内容检测可能太慢，这里只做文件名
        }
        
        for fname, fw in web_frameworks_map.items():
             if (project_dir / fname).exists():
                 frameworks.add(fw)

        result = {
            "languages": sorted(list(languages)),
            "frameworks": sorted(list(frameworks)),
            "package_managers": sorted(list(package_managers)),
        }

        self.think(f"技术栈识别结果 - 语言: {result['languages']}, 框架: {result['frameworks']}")
        return result

    def _update_package_managers(self, file_name: str, package_managers: Set[str]):
        """更新包管理器集合"""
        if file_name == "package.json":
            package_managers.add("npm")
        elif file_name == "requirements.txt":
            package_managers.add("pip")
        elif file_name == "Cargo.toml":
            package_managers.add("cargo")
        elif file_name == "go.mod":
            package_managers.add("go")
        elif file_name == "pom.xml":
            package_managers.add("maven")
        elif file_name == "build.gradle":
            package_managers.add("gradle")
        elif file_name == "Gemfile":
            package_managers.add("bundler")
        elif file_name == "composer.json":
            package_managers.add("composer")

    async def _recommend_tools(self, tech_stack: Dict[str, Any]) -> List[ToolInfo]:
        """
        根据技术栈推荐工具

        Args:
            tech_stack: 技术栈信息

        Returns:
            推荐的工具列表（按优先级排序）
        """
        languages = tech_stack.get("languages", [])
        frameworks = tech_stack.get("frameworks", [])

        # 工具推荐规则
        recommendations = []

        # Semgrep - 支持多语言，优先推荐
        recommendations.append("semgrep")

        # Gitleaks - 所有项目都需要
        recommendations.append("gitleaks")

        # 语言特定工具
        if "Python" in languages:
            recommendations.append("bandit")
            recommendations.append("safety")

        if any(lang in languages for lang in ["JavaScript", "TypeScript"]):
            recommendations.append("npm_audit")

        # 包管理器特定工具
        package_managers = tech_stack.get("package_managers", [])
        if "npm" in package_managers:
            recommendations.append("npm_audit")
        if "pip" in package_managers or "poetry" in package_managers:
            recommendations.append("safety")

        # 去重并保持顺序
        seen = set()
        ordered_tools = []
        for tool in recommendations:
            if tool not in seen:
                seen.add(tool)
                ordered_tools.append(tool)

        # 获取工具信息
        all_tools = [
            ToolInfo(
                name="semgrep",
                description="静态代码分析工具，支持多种语言",
                language=["*"],
                install_cmd="pip install semgrep",
                check_cmd=["semgrep", "--version"],
                priority=10,
            ),
            ToolInfo(
                name="bandit",
                description="Python 安全漏洞扫描工具",
                language=["python"],
                install_cmd="pip install bandit",
                check_cmd=["bandit", "--version"],
                priority=9,
            ),
            ToolInfo(
                name="safety",
                description="Python 依赖漏洞扫描工具",
                language=["python"],
                install_cmd="pip install safety",
                check_cmd=["safety", "--version"],
                priority=7,
            ),
            ToolInfo(
                name="gitleaks",
                description="密钥和敏感信息检测工具",
                language=["*"],
                install_cmd="go install github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest",
                check_cmd=["gitleaks", "version"],
                priority=8,
            ),
            ToolInfo(
                name="npm_audit",
                description="Node.js 依赖漏洞扫描工具",
                language=["javascript", "typescript"],
                install_cmd="",  # npm 自带
                check_cmd=["npm", "--version"],
                priority=6,
            ),
        ]

        # 构建推荐工具列表
        tool_map = {t.name: t for t in all_tools}
        return [tool_map[name] for name in ordered_tools if name in tool_map]

    async def _scan_with_tools(
        self,
        recommended_tools: List[ToolInfo],
        available_tools: List[ToolInfo],
    ) -> List[Dict[str, Any]]:
        """
        使用推荐工具进行扫描

        Args:
            recommended_tools: 推荐的工具列表
            available_tools: 可用的工具列表

        Returns:
            工具发现列表
        """
        all_findings = []

        # 只运行可用的工具
        available_names = {t.name for t in available_tools}

        for tool_info in recommended_tools:
            if tool_info.name not in available_names:
                self.think(f"工具 {tool_info.name} 不可用，跳过")
                continue

            self.think(f"运行工具: {tool_info.name}")

            try:
                result = await self._tool_service.run_tool_by_name(tool_info.name)

                if result and result.success:
                    self.think(f"工具 {tool_info.name} 发现 {len(result.findings)} 个问题")

                    # 转换为统一格式
                    for finding in result.findings:
                        all_findings.append({
                            "tool": tool_info.name,
                            "severity": finding.get("severity", "medium"),
                            "title": finding.get("title", ""),
                            "description": finding.get("description", ""),
                            "file_path": finding.get("file_path", ""),
                            "line_number": finding.get("line_number", 0),
                            "rule_id": finding.get("rule_id", ""),
                            "cwe_ids": finding.get("cwe_ids", []),
                            "metadata": finding.get("metadata", {}),
                        })
                else:
                    self.think(f"工具 {tool_info.name} 执行失败: {result.error if result else 'Unknown error'}")

            except Exception as e:
                logger.warning(f"运行工具 {tool_info.name} 失败: {e}")

        return all_findings

    async def _extract_high_risk_areas(
        self,
        tool_findings: List[Dict[str, Any]],
        tech_stack: Dict[str, Any],
        project_path: str,
    ) -> List[Dict[str, Any]]:
        """
        从工具发现中提取高风险区域

        Args:
            tool_findings: 工具发现列表
            tech_stack: 技术栈信息
            project_path: 项目路径

        Returns:
            高风险区域列表（带文件路径和行号）
        """
        high_risk_areas = []

        # 按文件分组统计问题
        file_issues = {}
        for finding in tool_findings:
            file_path = finding.get("file_path", "")
            if not file_path:
                continue

            severity = finding.get("severity", "medium")
            line_number = finding.get("line_number", 0)

            if file_path not in file_issues:
                file_issues[file_path] = {
                    "critical": [],
                    "high": [],
                    "medium": [],
                    "low": [],
                }

            if severity in file_issues[file_path]:
                file_issues[file_path][severity].append(line_number)

        # 生成高风险区域
        for file_path, issues in file_issues.items():
            # 优先级规则
            priority = 0

            # 有 critical 问题
            if issues["critical"]:
                priority = 100 + len(issues["critical"])
            # 有 high 问题
            elif issues["high"]:
                priority = 70 + len(issues["high"])
            # 有多个 medium 问题
            elif len(issues["medium"]) >= 3:
                priority = 50 + len(issues["medium"])
            # 有 medium 问题
            elif issues["medium"]:
                priority = 30 + len(issues["medium"])

            if priority > 0:
                high_risk_areas.append({
                    "file_path": file_path,
                    "priority": priority,
                    "issues": issues,
                    "recommendation": "优先分析此文件",
                })

        # 按优先级排序
        high_risk_areas.sort(key=lambda x: x["priority"], reverse=True)

        # 只返回优先级 >= 30 的区域
        return [area for area in high_risk_areas if area["priority"] >= 30]

    async def _run_dataflow_analysis(
        self,
        project_path: str,
        tech_stack: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        执行数据流分析

        Args:
            project_path: 项目路径
            tech_stack: 技术栈信息

        Returns:
            数据流分析发现的漏洞列表
        """
        languages = tech_stack.get("languages", [])

        # 数据流分析主要针对动态语言
        target_languages = {"Python", "JavaScript", "TypeScript", "PHP", "Ruby"}
        if not any(lang in languages for lang in target_languages):
            self.think("项目不包含支持数据流分析的语言，跳过")
            return []

        self.think("开始数据流分析...")

        try:
            # 分析整个项目
            vulnerabilities = await self._dataflow_analyzer.analyze_project(
                project_path=project_path,
                file_patterns=None,  # 分析所有文件
            )

            self.think(f"数据流分析完成，发现 {len(vulnerabilities)} 个潜在漏洞")

            # 转换为统一格式
            findings = []
            for vuln in vulnerabilities:
                findings.append({
                    "tool": "dataflow",
                    "vulnerability_type": vuln.vuln_type,
                    "severity": vuln.severity,
                    "title": f"{vuln.vuln_type} in {Path(vuln.path.sink_location[0]).name}",
                    "description": vuln.description,
                    "file_path": vuln.path.sink_location[0],
                    "line_number": vuln.path.sink_location[1],
                    "source": vuln.source.name,
                    "sink": vuln.sink.name,
                    "sanitized": vuln.path.is_sanitized,
                    "confidence": vuln.path.confidence,
                    "cwe_ids": vuln.cwe_ids,
                    "recommendation": vuln.recommendation,
                })

            return findings

        except Exception as e:
            logger.warning(f"数据流分析失败: {e}")
            return []

    async def _scan_structure(self, project_path: str) -> Dict[str, Any]:
        """
        扫描项目结构

        Args:
            project_path: 项目路径

        Returns:
            项目结构
        """
        from app.services.rust_client import rust_client

        files = []
        directories = []
        
        # 忽略目录列表
        ignored_dirs = {
            ".git", "node_modules", "venv", ".venv", "__pycache__", 
            "dist", "build", "target", "vendor", ".idea", ".vscode",
            "bin", "obj", "out"
        }

        try:
            items = await rust_client.list_files(project_path)
            for item in items:
                # 规范化路径分隔符
                norm_item = item.replace("\\", "/")
                
                # 过滤忽略目录
                # 检查路径部分中是否包含忽略目录
                parts = norm_item.split("/")
                if any(part in ignored_dirs for part in parts):
                    continue

                full_path = item
                # 简单判断：有后缀的是文件
                if "." in item.split("/")[-1]:
                    files.append(full_path)
                else:
                    directories.append(full_path)

        except Exception as e:
            logger.warning(f"扫描项目结构失败: {e}")

        return {"files": files, "directories": directories}

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
        user_inputs = []

        files = structure.get("files", [])

        # 识别潜在的攻击面入口
        for file_path in files:
            file_name = file_path.split("/")[-1].lower()
            file_dir = "/".join(file_path.split("/")[:-1]).lower()

            # Web 路由文件
            if any(keyword in file_dir or keyword in file_name
                   for keyword in ["route", "controller", "handler", "api", "view", "endpoint"]):
                entry_points.append({
                    "type": "web_route",
                    "file": file_path,
                    "description": "Web 路由定义文件",
                })

            # 表单/输入处理
            if any(keyword in file_name for keyword in ["form", "input", "upload", "submit"]):
                user_inputs.append({
                    "type": "user_input",
                    "file": file_path,
                    "description": "用户输入处理文件",
                })

            # 数据库查询
            if any(keyword in file_dir or keyword in file_name
                   for keyword in ["model", "query", "database", "db", "sql"]):
                entry_points.append({
                    "type": "database",
                    "file": file_path,
                    "description": "数据库操作文件",
                })

            # 认证/授权
            if any(keyword in file_dir or keyword in file_name
                   for keyword in ["auth", "login", "permission", "access", "user", "session"]):
                entry_points.append({
                    "type": "auth",
                    "file": file_path,
                    "description": "认证/授权文件",
                    "severity": "high",
                })

            # 文件操作
            if any(keyword in file_dir or keyword in file_name
                   for keyword in ["file", "fs", "io", "upload", "download", "storage"]):
                entry_points.append({
                    "type": "file_operation",
                    "file": file_path,
                    "description": "文件操作文件",
                })

            # 命令执行
            if any(keyword in file_dir or keyword in file_name
                   for keyword in ["exec", "spawn", "shell", "command", "system", "subprocess"]):
                entry_points.append({
                    "type": "command_execution",
                    "file": file_path,
                    "description": "命令执行相关",
                    "severity": "high",
                })

        return {
            "entry_points": entry_points,
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
        files = structure.get("files", [])

        # 分析依赖文件
        for file_path in files:
            filename = file_path.split("/")[-1].lower()

            if filename == "package.json":
                libraries.extend(await self._parse_package_json(file_path))
            elif filename == "requirements.txt":
                libraries.extend(await self._parse_requirements_txt(file_path))

        return {
            "libraries": libraries,
            "total_libraries": len(libraries),
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
                    "ecosystem": "npm",
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
                        "ecosystem": "pypi",
                    })

            return libraries
        except Exception as e:
            logger.warning(f"解析 requirements.txt 失败: {e}")
            return []

    def _prioritize_scan_targets(
        self,
        high_risk_areas: List[Dict[str, Any]],
        dataflow_findings: List[Dict[str, Any]],
        attack_surface: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        生成优先级排序的扫描目标列表

        Args:
            high_risk_areas: 高风险区域
            dataflow_findings: 数据流分析发现
            attack_surface: 攻击面

        Returns:
            优先级排序的扫描目标
        """
        targets = []

        # 1. 数据流分析发现的漏洞（最高优先级）
        for finding in dataflow_findings:
            if finding.get("severity") in ["critical", "high"]:
                targets.append({
                    "type": "dataflow_vulnerability",
                    "file_path": finding.get("file_path"),
                    "line_number": finding.get("line_number"),
                    "priority": 100,
                    "reason": f"数据流分析发现的 {finding.get('severity')} 漏洞",
                    "finding": finding,
                })

        # 2. 高风险区域
        for area in high_risk_areas:
            targets.append({
                "type": "high_risk_area",
                "file_path": area.get("file_path"),
                "priority": area.get("priority", 50),
                "reason": f"工具扫描发现 {area.get('priority')} 个问题",
                "issues": area.get("issues"),
            })

        # 3. 认证/授权入口点
        for entry in attack_surface.get("entry_points", []):
            if entry.get("severity") == "high":
                targets.append({
                    "type": "auth_entry",
                    "file_path": entry.get("file"),
                    "priority": 70,
                    "reason": "认证/授权相关入口点",
                })

        # 4. 命令执行入口点
        for entry in attack_surface.get("command_executions", []):
            targets.append({
                "type": "command_execution",
                "file_path": entry.get("file"),
                "priority": 80,
                "reason": "命令执行相关代码",
            })

        # 按优先级排序
        targets.sort(key=lambda x: x["priority"], reverse=True)

        return targets


# 创建全局实例
recon_agent = ReconAgent()
