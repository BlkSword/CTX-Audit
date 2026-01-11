"""
外部安全工具集成服务

集成第三方安全扫描工具，提供统一的调用接口和结果格式转换。
支持：
- Semgrep: 静态代码分析
- Bandit: Python 安全扫描
- Gitleaks: 密钥和敏感信息检测
- Safety: 依赖漏洞扫描
- npm audit: Node.js 依赖扫描

参考 DeepAudit-3.0.0 实现
"""
import asyncio
import json
import os
import subprocess
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from loguru import logger
import shutil


@dataclass
class ToolResult:
    """工具执行结果"""
    tool_name: str
    success: bool
    findings: List[Dict[str, Any]]
    execution_time: float  # 秒
    error: Optional[str] = None
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "success": self.success,
            "findings": self.findings,
            "execution_time": self.execution_time,
            "error": self.error,
            "metadata": self.metadata or {},
        }


@dataclass
class ToolInfo:
    """工具信息"""
    name: str
    description: str
    language: List[str]  # 支持的语言
    install_cmd: str  # 安装命令
    check_cmd: List[str]  # 检查是否安装的命令
    priority: int = 0  # 优先级（0-10），越高优先级越高


class ExternalToolAdapter:
    """
    外部工具适配器基类

    提供统一的工具调用接口
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self._is_available: Optional[bool] = None

    @property
    def tool_info(self) -> ToolInfo:
        """工具信息"""
        raise NotImplementedError

    async def is_available(self) -> bool:
        """检查工具是否可用"""
        if self._is_available is not None:
            return self._is_available

        try:
            process = await asyncio.create_subprocess_exec(
                *self.tool_info.check_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            self._is_available = process.returncode == 0
        except FileNotFoundError:
            self._is_available = False
        except Exception as e:
            # 工具未安装是正常情况，使用 debug 级别
            logger.debug(f"检查工具 {self.tool_info.name} 可用性失败: {e}")
            self._is_available = False

        return self._is_available

    async def run(self, **kwargs) -> ToolResult:
        """运行工具"""
        if not await self.is_available():
            return ToolResult(
                tool_name=self.tool_info.name,
                success=False,
                findings=[],
                execution_time=0,
                error=f"工具 {self.tool_info.name} 不可用，请先安装: {self.tool_info.install_cmd}",
            )

        start_time = asyncio.get_event_loop().time()
        try:
            findings = await self._scan(**kwargs)
            execution_time = asyncio.get_event_loop().time() - start_time

            return ToolResult(
                tool_name=self.tool_info.name,
                success=True,
                findings=findings,
                execution_time=execution_time,
                metadata={"scan_path": str(self.project_path)},
            )
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            logger.error(f"运行工具 {self.tool_info.name} 失败: {e}")
            return ToolResult(
                tool_name=self.tool_info.name,
                success=False,
                findings=[],
                execution_time=execution_time,
                error=str(e),
            )

    async def _scan(self, **kwargs) -> List[Dict[str, Any]]:
        """执行扫描"""
        raise NotImplementedError


class SemgrepAdapter(ExternalToolAdapter):
    """
    Semgrep 适配器

    静态代码分析工具，支持多种语言
    """

    @property
    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="semgrep",
            description="静态代码分析工具，支持多种语言和安全规则",
            language=["python", "javascript", "java", "go", "ruby", "php", "c", "cpp"],
            install_cmd="pip install semgrep",
            check_cmd=["semgrep", "--version"],
            priority=10,
        )

    async def _scan(
        self,
        rules: Optional[List[str]] = None,
        config: Optional[str] = "auto",
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        运行 Semgrep 扫描

        Args:
            rules: 自定义规则列表
            config: 配置文件或预设（auto, security, etc.）
        """
        cmd = [
            "semgrep",
            "scan",
            str(self.project_path),
            "--json",
            "--no-git-ignore",
        ]

        if config:
            cmd.extend(["--config", config])

        if rules:
            for rule in rules:
                cmd.extend(["--config", rule])

        # 设置环境变量以确保 UTF-8 编码（修复 Windows GBK 编码问题）
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["LANG"] = "en_US.UTF-8"
        env["LC_ALL"] = "en_US.UTF-8"

        # 执行命令
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            # Semgrep 返回非0可能是因为没有发现结果
            if stderr:
                # 使用 UTF-8 解码，忽略无法解码的字符
                logger.warning(f"Semgrep 警告: {stderr.decode('utf-8', errors='ignore')}")

        # 解析结果
        try:
            result = json.loads(stdout.decode('utf-8'))
            return self._parse_results(result)
        except json.JSONDecodeError:
            return []

    def _parse_results(self, result: Dict) -> List[Dict[str, Any]]:
        """解析 Semgrep 结果"""
        findings = []
        for result_item in result.get("results", []):
            # 提取严重程度
            extra = result_item.get("extra", {})
            severity = extra.get("severity", "warning").lower()

            # 映射严重程度
            severity_map = {
                "error": "high",
                "warning": "medium",
                "info": "low",
            }
            severity = severity_map.get(severity, "medium")

            finding = {
                "tool": "semgrep",
                "rule_id": result_item.get("check_id", ""),
                "severity": severity,
                "title": extra.get("message", ""),
                "description": extra.get("message", ""),
                "file_path": result_item.get("path", ""),
                "line_number": result_item.get("start", {}).get("line", 0),
                "end_line": result_item.get("end", {}).get("line", 0),
                "column": result_item.get("start", {}).get("col", 0),
                "code_snippet": self._extract_code_snippet(result_item),
                "cwe_ids": extra.get("metadata", {}).get("cwe", []),
                "references": extra.get("metadata", {}).get("references", []),
                "metadata": {
                    "match": result_item,
                },
            }
            findings.append(finding)

        return findings

    def _extract_code_snippet(self, result_item: Dict) -> str:
        """提取代码片段"""
        lines = result_item.get("extra", {}).get("lines", "")
        return lines.strip() if lines else ""


class BanditAdapter(ExternalToolAdapter):
    """
    Bandit 适配器

    Python 安全扫描工具
    """

    @property
    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="bandit",
            description="Python 安全漏洞扫描工具",
            language=["python"],
            install_cmd="pip install bandit",
            check_cmd=["bandit", "--version"],
            priority=9,
        )

    async def _scan(
        self,
        severity: Optional[str] = None,
        confidence: Optional[str] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        运行 Bandit 扫描

        Args:
            severity: 最低严重程度 (low, medium, high)
            confidence: 最低置信度 (low, medium, high)
        """
        cmd = [
            "bandit",
            "-r",  # 递归扫描
            "-f", "json",  # JSON 格式输出
            str(self.project_path),
        ]

        if severity:
            cmd.extend(["-ll", severity])  # 最低严重程度
        if confidence:
            cmd.extend(["-ii", confidence])  # 最低置信度

        # 执行命令
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0 and process.returncode != 1:  # 1 表示发现了问题
            logger.warning(f"Bandit 执行异常: {stderr.decode()}")

        # 解析结果
        try:
            result = json.loads(stdout.decode())
            return self._parse_results(result)
        except json.JSONDecodeError:
            return []

    def _parse_results(self, result: Dict) -> List[Dict[str, Any]]:
        """解析 Bandit 结果"""
        findings = []
        for result_item in result.get("results", []):
            # 映射严重程度
            severity = result_item.get("issue_severity", "MEDIUM").lower()
            severity_map = {
                "low": "low",
                "medium": "medium",
                "high": "high",
            }
            severity = severity_map.get(severity, "medium")

            # 获取 CWE 信息
            test_id = result_item.get("test_id", "")
            test_name = result_item.get("test_name", "")

            # 常见的 Bandit 测试到 CWE 的映射
            cwe_map = {
                "B201": ["CWE-79"],  # flask_debug
                "B301": ["CWE-22"],  # pickle
                "B302": ["CWE-22"],  # marshal
                "B303": ["CWE-22"],  # hashlib
                "B304": ["CWE-22"],  # ciphers
                "B305": ["CWE-22"],  # cipher modes
                "B306": ["CWE-327"],  # mktemp_q
                "B307": ["CWE-327"],  # eval
                "B308": ["CWE-22"],  # mark_safe
                "B309": ["CWE-79"],  # httpsconnection
                "B310": ["CWE-295"],  # urllib_urlopen
                "B311": ["CWE-22"],  # random
                "B312": ["CWE-22"],  # telnetlib
                "B313": ["CWE-22"],  # xml_bad_cElementTree
                "B314": ["CWE-22"],  # xml_bad_ElementTree
                "B315": ["CWE-22"],  # xml_bad_expatreader
                "B316": ["CWE-22"],  # xml_bad_expatbuilder
                "B317": ["CWE-22"],  # xml_bad_sax
                "B318": ["CWE-22"],  # xml_bad_minidom
                "B319": ["CWE-22"],  # xml_bad_pulldom
                "B320": ["CWE-22"],  # xml_bad_etree
                "B321": ["CWE-22"],  # ftplib
                "B323": ["CWE-22"],  # unverified_context
                "B324": ["CWE-327"],  # hashlib_new_insecure_functions
                "B325": ["CWE-327"],  # tempnam
                "B401": ["CWE-22"],  # import_telnetlib
                "B402": ["CWE-22"],  # import_ftplib
                "B403": ["CWE-22"],  # import_pickle
                "B404": ["CWE-22"],  # import_subprocess
                "B405": ["CWE-78"],  # import_xml_etree
                "B406": ["CWE-22"],  # import_xml_sax
                "B407": ["CWE-22"],  # import_xml_expat
                "B408": ["CWE-22"],  # import_xml_minidom
                "B409": ["CWE-22"],  # import_xml_pulldom
                "B410": ["CWE-22"],  # import_lxml
                "B411": ["CWE-22"],  # import_xmlrpclib
                "B412": ["CWE-22"],  # import_httpoxy
                "B413": ["CWE-22"],  # import_pycrypto
                "B501": ["CWE-327"],  # request_with_no_cert_validation
                "B502": ["CWE-295"],  # ssl_with_bad_version
                "B503": ["CWE-295"],  # ssl_with_bad_defaults
                "B504": ["CWE-295"],  # ssl_with_no_version
                "B505": ["CWE-757"],  # weak_cryptographic_key
                "B506": ["CWE-327"],  # yaml_load
                "B507": ["CWE-327"],  # ssh_no_host_key_verification
                "B601": ["CWE-89"],  # paramiko_calls
                "B602": ["CWE-78"],  # subprocess_popen_with_shell_equals_true
                "B603": ["CWE-78"],  # subprocess_without_shell_equals_true
                "B604": ["CWE-88"],  # any_other_function_with_shell_equals_true
                "B605": ["CWE-22"],  # start_process_with_a_shell
                "B606": ["CWE-78"],  # start_process_with_no_shell
                "B607": ["CWE-88"],  # start_process_with_partial_path
                "B608": ["CWE-89"],  # hardcoded_sql_expressions
                "B609": ["CWE-79"],  # linux_commands_wildcard_injection
                "B610": ["CWE-22"],  # django_extra_used
                "B611": ["CWE-89"],  # django_rawsql_used
                "B701": ["CWE-22"],  # jinja2_autoescape_false
                "B702": ["CWE-79"],  # mako_template_default_autoescape_false
                "B703": ["CWE-22"],  # django_mark_safe
            }

            finding = {
                "tool": "bandit",
                "rule_id": test_id,
                "severity": severity,
                "title": test_name,
                "description": result_item.get("issue_text", ""),
                "file_path": result_item.get("filename", ""),
                "line_number": result_item.get("line_number", 0),
                "code_snippet": self._extract_code_snippet(result_item),
                "cwe_ids": cwe_map.get(test_id, []),
                "confidence": result_item.get("issue_confidence", "medium").lower(),
                "metadata": {
                    "test_id": test_id,
                    "test_name": test_name,
                    "more_info": result_item.get("more_info", ""),
                },
            }
            findings.append(finding)

        return findings

    def _extract_code_snippet(self, result_item: Dict) -> str:
        """提取代码片段"""
        code = result_item.get("code", "")
        return code.strip() if code else ""


class GitleaksAdapter(ExternalToolAdapter):
    """
    Gitleaks 适配器

    密钥和敏感信息检测工具
    """

    @property
    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="gitleaks",
            description="密钥和敏感信息检测工具",
            language=["*"],  # 支持所有语言
            install_cmd="go install github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest",
            check_cmd=["gitleaks", "version"],
            priority=8,
        )

    async def _scan(self, **kwargs) -> List[Dict[str, Any]]:
        """运行 Gitleaks 扫描"""
        # 创建临时报告文件
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_path = f.name

        try:
            cmd = [
                "gitleaks",
                "detect",
                "--source", str(self.project_path),
                "--report-format", "json",
                "--report-path", report_path,
                "--no-banner",
                "--no-color",
            ]

            # 执行命令
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()

            # 读取报告
            with open(report_path, 'r') as f:
                result = json.load(f)

            return self._parse_results(result)
        except Exception as e:
            logger.error(f"Gitleaks 扫描失败: {e}")
            return []
        finally:
            # 清理临时文件
            try:
                Path(report_path).unlink()
            except:
                pass

    def _parse_results(self, result: Dict) -> List[Dict[str, Any]]:
        """解析 Gitleaks 结果"""
        findings = []
        for finding in result.get("findings", []):
            # 确定严重程度（密钥泄露通常是 critical 或 high）
            rule_id = finding.get("ruleID", "").lower()
            if "api" in rule_id or "key" in rule_id or "secret" in rule_id:
                severity = "critical"
            elif "token" in rule_id or "password" in rule_id:
                severity = "high"
            else:
                severity = "medium"

            item = {
                "tool": "gitleaks",
                "rule_id": finding.get("ruleID", ""),
                "severity": severity,
                "title": finding.get("ruleID", "敏感信息泄露"),
                "description": f"检测到可能的敏感信息: {finding.get('ruleID', '')}",
                "file_path": finding.get("file", ""),
                "line_number": finding.get("startLineNumber", 0),
                "end_line": finding.get("endLineNumber", 0),
                "code_snippet": finding.get("secret", "")[:100],  # 截断敏感信息
                "cwe_ids": ["CWE-312", "CWE-798"],  # 密钥泄露相关 CWE
                "metadata": {
                    "secret": finding.get("secret", "")[:50],  # 只保留前50字符
                    "match": finding.get("match", ""),
                    "entropy": finding.get("entropy", 0),
                },
            }
            findings.append(item)

        return findings


class SafetyAdapter(ExternalToolAdapter):
    """
    Safety 适配器

    Python 依赖漏洞扫描工具
    """

    @property
    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="safety",
            description="Python 依赖漏洞扫描工具",
            language=["python"],
            install_cmd="pip install safety",
            check_cmd=["safety", "--version"],
            priority=7,
        )

    async def _scan(self, **kwargs) -> List[Dict[str, Any]]:
        """运行 Safety 扫描"""
        # 检查是否有 requirements.txt
        requirements_files = list(self.project_path.glob("**/requirements*.txt"))
        if not requirements_files:
            logger.info("未找到 requirements.txt 文件")
            return []

        findings = []
        for req_file in requirements_files:
            cmd = [
                "safety",
                "check",
                "--file", str(req_file),
                "--json",
            ]

            # 执行命令
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            # 解析结果
            try:
                result = json.loads(stdout.decode())
                findings.extend(self._parse_results(result, str(req_file)))
            except json.JSONDecodeError:
                pass

        return findings

    def _parse_results(self, result: List, source_file: str) -> List[Dict[str, Any]]:
        """解析 Safety 结果"""
        findings = []
        for vuln in result:
            # 确定严重程度
            severity = vuln.get("severity", "medium").lower()
            if severity not in ["critical", "high", "medium", "low"]:
                severity = "medium"

            finding = {
                "tool": "safety",
                "rule_id": vuln.get("id", ""),
                "severity": severity,
                "title": f"依赖漏洞: {vuln.get('package_name', '')}",
                "description": vuln.get("advisory", ""),
                "file_path": source_file,
                "line_number": 0,
                "cwe_ids": vuln.get("cwe", []),
                "metadata": {
                    "package_name": vuln.get("package_name", ""),
                    "installed_version": vuln.get("installed_version", ""),
                    "affected_versions": vuln.get("affected_versions", []),
                    "fixed_versions": vuln.get("fixed_versions", []),
                    "vulnerability_id": vuln.get("vulnerability_id", ""),
                    "more_info_url": vuln.get("more_info_url", ""),
                },
            }
            findings.append(finding)

        return findings


class NpmAuditAdapter(ExternalToolAdapter):
    """
    npm audit 适配器

    Node.js 依赖漏洞扫描工具
    """

    @property
    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="npm_audit",
            description="Node.js 依赖漏洞扫描工具",
            language=["javascript", "typescript"],
            install_cmd="",  # npm 自带
            check_cmd=["npm", "--version"],
            priority=6,
        )

    async def _scan(self, **kwargs) -> List[Dict[str, Any]]:
        """运行 npm audit 扫描"""
        # 检查是否有 package.json
        package_json = self.project_path / "package.json"
        if not package_json.exists():
            logger.info("未找到 package.json 文件")
            return []

        cmd = [
            "npm",
            "audit",
            "--json",
        ]

        # 执行命令
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(self.project_path),
        )
        stdout, stderr = await process.communicate()

        # 解析结果
        try:
            result = json.loads(stdout.decode())
            return self._parse_results(result)
        except json.JSONDecodeError:
            return []

    def _parse_results(self, result: Dict) -> List[Dict[str, Any]]:
        """解析 npm audit 结果"""
        findings = []
        vulnerabilities = result.get("vulnerabilities", {})

        for package_name, vuln_data in vulnerabilities.items():
            # 确定严重程度
            severity = vuln_data.get("severity", "moderate").lower()
            severity_map = {
                "critical": "critical",
                "high": "high",
                "moderate": "medium",
                "low": "low",
                "info": "low",
            }
            severity = severity_map.get(severity, "medium")

            # 获取第一个漏洞的详细信息
            vuln_list = vuln_data.get("via", [])
            first_vuln = vuln_list[0] if vuln_list else {}

            if isinstance(first_vuln, dict):
                cwe = first_vuln.get("cwe", [])
                title = first_vuln.get("title", f"依赖漏洞: {package_name}")
                url = first_vuln.get("url", "")
            else:
                cwe = []
                title = f"依赖漏洞: {package_name}"
                url = ""

            finding = {
                "tool": "npm_audit",
                "rule_id": package_name,
                "severity": severity,
                "title": title,
                "description": f"依赖包 {package_name} 存在安全漏洞",
                "file_path": "package.json",
                "line_number": 0,
                "cwe_ids": cwe if isinstance(cwe, list) else [cwe] if cwe else [],
                "metadata": {
                    "package_name": package_name,
                    "vulnerable_versions": vuln_data.get("range", ""),
                    "patched_versions": vuln_data.get("fixAvailable", {}).get("version", ""),
                    "url": url,
                    "effects": vuln_data.get("effects", []),
                },
            }
            findings.append(finding)

        return findings


class ExternalToolService:
    """
    外部工具服务管理器

    管理所有外部安全工具的调用和结果聚合
    """

    def __init__(self, project_path: str):
        self.project_path = project_path
        self._adapters: List[ExternalToolAdapter] = [
            SemgrepAdapter(project_path),
            BanditAdapter(project_path),
            GitleaksAdapter(project_path),
            SafetyAdapter(project_path),
            NpmAuditAdapter(project_path),
        ]

    async def get_available_tools(self) -> List[ToolInfo]:
        """获取所有可用的工具"""
        available = []
        for adapter in self._adapters:
            if await adapter.is_available():
                available.append(adapter.tool_info)
        return available

    async def run_all_tools(self) -> List[ToolResult]:
        """运行所有可用工具"""
        results = []
        for adapter in self._adapters:
            if await adapter.is_available():
                logger.info(f"运行工具: {adapter.tool_info.name}")
                result = await adapter.run()
                results.append(result)
                logger.info(f"工具 {adapter.tool_info.name} 完成，"
                           f"发现 {len(result.findings)} 个问题")
            else:
                logger.warning(f"工具 {adapter.tool_info.name} 不可用")
        return results

    async def run_tool_by_name(self, tool_name: str) -> Optional[ToolResult]:
        """运行指定工具"""
        for adapter in self._adapters:
            if adapter.tool_info.name == tool_name:
                return await adapter.run()
        return None

    async def run_tools_by_language(self, language: str) -> List[ToolResult]:
        """运行支持指定语言的所有工具"""
        results = []
        for adapter in self._adapters:
            if await adapter.is_available():
                if language in adapter.tool_info.language or "*" in adapter.tool_info.language:
                    result = await adapter.run()
                    results.append(result)
        return results

    def get_installation_guide(self) -> str:
        """获取工具安装指南"""
        lines = ["# 外部工具安装指南\n"]
        for adapter in self._adapters:
            info = adapter.tool_info
            lines.append(f"## {info.name}")
            lines.append(f"**描述:** {info.description}")
            lines.append(f"**支持语言:** {', '.join(info.language)}")
            lines.append(f"**安装命令:** ```bash\n{info.install_cmd}\n```")
            lines.append("")
        return "\n".join(lines)


# 全局单例缓存
_service_cache: Dict[str, ExternalToolService] = {}


def get_external_tool_service(project_path: str) -> ExternalToolService:
    """获取外部工具服务实例（缓存）"""
    if project_path not in _service_cache:
        _service_cache[project_path] = ExternalToolService(project_path)
    return _service_cache[project_path]
