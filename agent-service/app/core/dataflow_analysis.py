"""
数据流分析工具

实现污点追踪（Taint Tracking）分析，追踪数据从源点（Source）到汇点（Sink）的流动。
用于检测：
- SQL 注入
- XSS（跨站脚本）
- 路径遍历
- 命令注入
- 不安全的反序列化

参考 DeepAudit-3.0.0 实现
"""
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path
from loguru import logger


class TaintStatus(str, Enum):
    """污点状态"""
    SAFE = "safe"           # 安全，已净化
    TAINTED = "tainted"     # 污染，未净化
    UNKNOWN = "unknown"     # 未知


@dataclass
class Source:
    """污点源点（数据来源）"""
    name: str
    category: str  # user_input, file, network, database, environment
    pattern: str
    severity: str = "medium"
    cwe_ids: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Sink:
    """污点汇点（危险操作）"""
    name: str
    category: str  # sql, command, html, file, network
    pattern: str
    severity: str = "high"
    cwe_ids: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Sanitizer:
    """净化点（消除污点）"""
    name: str
    pattern: str
    effectiveness: float = 1.0  # 净化效果 (0-1)
    description: str = ""


@dataclass
class DataFlowPath:
    """数据流路径"""
    source_location: Tuple[str, int]  # (file, line)
    sink_location: Tuple[str, int]
    variables: List[str]
    functions: List[str]
    sanitizers: List[Tuple[str, int]]  # [(sanitizer_name, line)]
    is_sanitized: bool
    confidence: float


@dataclass
class Vulnerability:
    """漏洞发现"""
    vuln_type: str
    source: Source
    sink: Sink
    path: DataFlowPath
    description: str
    severity: str
    cwe_ids: List[str] = field(default_factory=list)
    recommendation: str = ""


class TaintAnalyzer:
    """
    污点分析器

    基于模式匹配的静态污点分析
    """

    # 常见污点源点
    SOURCES = [
        # 用户输入
        Source("request.get", "user_input", r"request\.(get|post|form|args|values|cookies|headers)",
              "high", ["CWE-20"], "HTTP请求数据"),
        Source("flask.request", "user_input", r"flask\.request",
              "high", ["CWE-20"], "Flask请求数据"),
        Source("django.request", "user_input", r"django\.http\.request",
              "high", ["CWE-20"], "Django请求数据"),
        Source("fastapi.request", "user_input", r"(Request|starlette\.request)",
              "high", ["CWE-20"], "FastAPI请求数据"),
        Source("input", "user_input", r"\binput\s*\(",
              "medium", ["CWE-20"], "用户输入"),
        Source("sys.argv", "user_input", r"sys\.argv",
              "medium", ["CWE-20"], "命令行参数"),

        # 文件操作
        Source("open", "file", r"\bopen\s*\(",
              "medium", ["CWE-20"], "文件读取"),
        Source("file.read", "file", r"\.read\s*\(",
              "medium", ["CWE-20"], "文件读取"),

        # 网络请求
        Source("requests.get", "network", r"requests\.(get|post|put|delete|patch)",
              "medium", ["CWE-20"], "HTTP请求"),
        Source("urllib", "network", r"urllib\.(request|parse)",
              "medium", ["CWE-20"], "HTTP请求"),
        Source("httpx", "network", r"httpx\.",
              "medium", ["CWE-20"], "HTTP请求"),

        # 数据库
        Source("db.execute", "database", r"(cursor|conn)\.execute",
              "low", ["CWE-20"], "数据库查询"),
        Source("session.query", "database", r"session\.query",
              "low", ["CWE-20"], "ORM查询"),

        # 环境变量
        Source("os.environ", "environment", r"os\.environ",
              "medium", ["CWE-20"], "环境变量"),
        Source("dotenv", "environment", r"(load_dotenv|dotenv)",
              "medium", ["CWE-20"], "环境变量文件"),
    ]

    # 常见污点汇点
    SINKS = [
        # SQL 执行
        Sink("execute", "sql", r"cursor\.execute\s*\(",
             "critical", ["CWE-89"], "SQL注入"),
        Sink("executemany", "sql", r"cursor\.executemany\s*\(",
             "critical", ["CWE-89"], "SQL注入"),
        Sink("sql", "sql", r"\.sql\s*\(",
             "critical", ["CWE-89"], "SQL注入"),
        Sink("raw_sql", "sql", r"raw\s*\(",
             "critical", ["CWE-89"], "原生SQL"),

        # 命令执行
        Sink("os.system", "command", r"os\.system\s*\(",
             "critical", ["CWE-78"], "命令注入"),
        Sink("subprocess", "command", r"subprocess\.(call|run|Popen|check_output)\s*\(",
             "critical", ["CWE-78"], "命令注入"),
        Sink("subprocess.shell", "command", r"shell\s*=\s*True",
             "critical", ["CWE-78"], "Shell命令执行"),
        Sink("eval", "command", r"\beval\s*\(",
             "critical", ["CWE-95"], "代码执行"),
        Sink("exec", "command", r"\bexec\s*\(",
             "critical", ["CWE-95"], "代码执行"),

        # HTML/JavaScript 输出
        Sink("html", "html", r"(innerHTML|outerHTML)\s*=",
             "high", ["CWE-79"], "XSS"),
        Sink("render", "html", r"render\s*\(",
             "high", ["CWE-79"], "模板渲染"),
        Sink("Response", "html", r"Response\s*\(",
             "high", ["CWE-79"], "HTTP响应"),
        Sink("write", "html", r"\.write\s*\(",
             "high", ["CWE-79"], "写入HTML"),

        # 文件操作
        Sink("open_write", "file", r"\bopen\s*\([^)]*['\"]w",
             "medium", ["CWE-22"], "路径遍历"),
        Sink("Path.write", "file", r"\.write_text\s*\(",
             "medium", ["CWE-22"], "文件写入"),

        # 网络请求
        Sink("requests.post", "network", r"requests\.post\s*\(",
             "medium", ["CWE-20"], "HTTP POST"),
    ]

    # 常见净化函数
    SANITIZERS = [
        # SQL 净化
        Sanitizer("escape_string", r"escape_string\s*\(", 0.9, "SQL字符串转义"),
        Sanitizer("parameterized", r"%s|\?|:1", 1.0, "参数化查询"),
        Sanitizer("orm_filter", r"\.filter\s*\(", 0.95, "ORM过滤"),

        # HTML 净化
        Sanitizer("escape", r"escape\s*\(", 0.9, "HTML转义"),
        Sanitizer("html.escape", r"html\.escape\s*\(", 0.95, "HTML转义"),
        Sanitizer("markupsafe", r"(Markup|escape)\s*\(", 0.95, "MarkupSafe转义"),
        Sanitizer("bleach", r"bleach\.(clean|linkify)", 0.95, "Bleach净化"),

        # 命令净化
        Sanitizer("shlex.quote", r"shlex\.quote\s*\(", 0.9, "Shell参数转义"),
        Sanitizer("subprocess.list", r"subprocess\.\w+\s*\(\s*\[", 0.95, "列表参数（安全）"),

        # 路径净化
        Sanitizer("os.path.abspath", r"os\.path\.abspath\s*\(", 0.8, "绝对路径"),
        Sanitizer("pathlib.Path", r"Path\s*\(", 0.8, "Pathlib处理"),
        Sanitizer("secure_filename", r"secure_filename\s*\(", 0.9, "安全文件名"),

        # 类型转换净化
        Sanitizer("int", r"\bint\s*\(", 0.95, "整数转换"),
        Sanitizer("float", r"\bfloat\s*\(", 0.95, "浮点数转换"),
        Sanitizer("str.isdigit", r"\.isdigit\s*\(", 0.9, "数字验证"),
    ]

    def __init__(self):
        """初始化分析器"""
        # 编译所有正则表达式
        self._source_patterns = [(s, re.compile(s.pattern, re.IGNORECASE)) for s in self.SOURCES]
        self._sink_patterns = [(s, re.compile(s.pattern, re.IGNORECASE)) for s in self.SINKS]
        self._sanitizer_patterns = [(s, re.compile(s.pattern, re.IGNORECASE)) for s in self.SANITIZERS]

    def analyze_file(self, file_path: str, content: str) -> List[Vulnerability]:
        """
        分析单个文件

        Args:
            file_path: 文件路径
            content: 文件内容

        Returns:
            漏洞列表
        """
        lines = content.split('\n')
        vulnerabilities = []

        # 查找所有源点
        sources = self._find_sources(file_path, lines)

        # 查找所有汇点
        sinks = self._find_sinks(file_path, lines)

        # 查找所有净化点
        sanitizers = self._find_sanitizers(file_path, lines)

        # 分析数据流路径
        for sink_info in sinks:
            sink, sink_line = sink_info
            for source_info in sources:
                source, source_line = source_info

                # 检查是否有净化点
                path_sanitizers = [
                    (s, line) for s, line in sanitizers
                    if source_line < line < sink_line
                ]

                # 判断是否被净化
                is_sanitized = self._is_sanitized(
                    source, sink, path_sanitizers
                )

                if not is_sanitized:
                    # 计算置信度
                    confidence = self._calculate_confidence(
                        source, sink, path_sanitizers
                    )

                    if confidence > 0.3:
                        vuln = self._create_vulnerability(
                            source, sink, source_line, sink_line,
                            path_sanitizers, is_sanitized, confidence
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _find_sources(self, file_path: str, lines: List[str]) -> List[Tuple[Source, int]]:
        """查找所有源点"""
        sources = []
        for line_no, line in enumerate(lines, 1):
            for source, pattern in self._source_patterns:
                if pattern.search(line):
                    sources.append((source, line_no))
                    break  # 每行只匹配一个源点
        return sources

    def _find_sinks(self, file_path: str, lines: List[str]) -> List[Tuple[Sink, int]]:
        """查找所有汇点"""
        sinks = []
        for line_no, line in enumerate(lines, 1):
            for sink, pattern in self._sink_patterns:
                if pattern.search(line):
                    sinks.append((sink, line_no))
                    break  # 每行只匹配一个汇点
        return sinks

    def _find_sanitizers(self, file_path: str, lines: List[str]) -> List[Tuple[Sanitizer, int]]:
        """查找所有净化点"""
        sanitizers = []
        for line_no, line in enumerate(lines, 1):
            for sanitizer, pattern in self._sanitizer_patterns:
                if pattern.search(line):
                    sanitizers.append((sanitizer, line_no))
        return sanitizers

    def _is_sanitized(
        self,
        source: Source,
        sink: Sink,
        path_sanitizers: List[Tuple[Sanitizer, int]]
    ) -> bool:
        """判断路径是否被净化"""
        if not path_sanitizers:
            return False

        # 根据汇点类型检查净化点
        if sink.category == "sql":
            # SQL 需要参数化查询或转义
            for sanitizer, _ in path_sanitizers:
                if "parameterized" in sanitizer.pattern or "orm" in sanitizer.pattern:
                    return True
                if sanitizer.effectiveness >= 0.9:
                    return True

        elif sink.category == "html":
            # HTML 需要转义
            for sanitizer, _ in path_sanitizers:
                if "escape" in sanitizer.pattern or "bleach" in sanitizer.pattern:
                    return True

        elif sink.category == "command":
            # 命令需要用列表参数或转义
            for sanitizer, _ in path_sanitizers:
                if "list" in sanitizer.pattern or "shlex" in sanitizer.pattern:
                    return True

        # 检查总体净化效果
        total_effectiveness = sum(s.effectiveness for s, _ in path_sanitizers)
        if total_effectiveness >= 1.0:
            return True

        return False

    def _calculate_confidence(
        self,
        source: Source,
        sink: Sink,
        path_sanitizers: List[Tuple[Sanitizer, int]]
    ) -> float:
        """
        计算漏洞置信度

        考虑因素：
        1. 源点和汇点的严重程度
        2. 路径长度
        3. 是否有净化点
        4. 源点和汇点的类别匹配度
        """
        confidence = 0.5  # 基础置信度

        # 源点严重程度
        if source.severity == "high":
            confidence += 0.15
        elif source.severity == "medium":
            confidence += 0.1

        # 汇点严重程度
        if sink.severity == "critical":
            confidence += 0.2
        elif sink.severity == "high":
            confidence += 0.15

        # 无净化点增加置信度
        if not path_sanitizers:
            confidence += 0.2

        # 源点和汇点类别匹配度
        compatible_pairs = {
            ("user_input", "sql"): True,
            ("user_input", "command"): True,
            ("user_input", "html"): True,
            ("user_input", "file"): True,
            ("file", "sql"): True,
            ("file", "command"): True,
        }

        if compatible_pairs.get((source.category, sink.category), False):
            confidence += 0.15

        return min(confidence, 1.0)

    def _create_vulnerability(
        self,
        source: Source,
        sink: Sink,
        source_line: int,
        sink_line: int,
        path_sanitizers: List[Tuple[Sanitizer, int]],
        is_sanitized: bool,
        confidence: float,
    ) -> Vulnerability:
        """创建漏洞对象"""
        # 确定漏洞类型
        vuln_type_map = {
            "sql": "SQL Injection",
            "command": "Command Injection",
            "html": "Cross-Site Scripting (XSS)",
            "file": "Path Traversal",
            "network": "SSRF",
        }
        vuln_type = vuln_type_map.get(sink.category, "Injection Vulnerability")

        # 确定严重程度
        if sink.severity == "critical":
            severity = "critical"
        elif sink.severity == "high":
            severity = "high"
        else:
            severity = "medium"

        # 合并 CWE
        cwe_ids = list(set(source.cwe_ids + sink.cwe_ids))

        # 生成描述
        description = (
            f"来自 {source.name} ({source.category}) 的数据流向 {sink.name} "
            f"({sink.category})，可能存在 {vuln_type} 风险"
        )

        # 生成修复建议
        recommendation = self._generate_recommendation(sink.category)

        # 创建路径
        path = DataFlowPath(
            source_location=("", source_line),
            sink_location=("", sink_line),
            variables=[],
            functions=[],
            sanitizers=[(s.name, line) for s, line in path_sanitizers],
            is_sanitized=is_sanitized,
            confidence=confidence,
        )

        return Vulnerability(
            vuln_type=vuln_type,
            source=source,
            sink=sink,
            path=path,
            description=description,
            severity=severity,
            cwe_ids=cwe_ids,
            recommendation=recommendation,
        )

    def _generate_recommendation(self, sink_category: str) -> str:
        """生成修复建议"""
        recommendations = {
            "sql": "使用参数化查询或 ORM 来防止 SQL 注入",
            "command": "使用 subprocess 的列表参数或 shlex.quote 来防止命令注入",
            "html": "对用户输入进行 HTML 转义或使用模板引擎的自动转义功能",
            "file": "验证并规范化文件路径，限制在指定目录内",
            "network": "验证和清理 URL 参数，使用 allowlist 限制目标",
        }
        return recommendations.get(sink_category, "验证并净化所有用户输入")


class DataFlowAnalyzer:
    """
    数据流分析器

    协调多个文件的污点分析
    """

    def __init__(self):
        self.taint_analyzer = TaintAnalyzer()

    def analyze_project(
        self,
        project_path: str,
        file_patterns: Optional[List[str]] = None,
    ) -> List[Vulnerability]:
        """
        分析整个项目

        Args:
            project_path: 项目路径
            file_patterns: 文件匹配模式列表

        Returns:
            所有漏洞列表
        """
        project_dir = Path(project_path)
        vulnerabilities = []

        # 默认分析 Python 文件
        if file_patterns is None:
            file_patterns = ["*.py"]

        # 查找所有匹配的文件
        files = []
        for pattern in file_patterns:
            files.extend(project_dir.rglob(pattern))

        logger.info(f"数据流分析: 找到 {len(files)} 个文件")

        # 分析每个文件
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                file_vulns = self.taint_analyzer.analyze_file(
                    str(file_path),
                    content
                )

                # 添加文件路径到路径信息
                for vuln in file_vulns:
                    vuln.path.source_location = (str(file_path), vuln.path.source_location[1])
                    vuln.path.sink_location = (str(file_path), vuln.path.sink_location[1])

                vulnerabilities.extend(file_vulns)

            except Exception as e:
                logger.warning(f"分析文件 {file_path} 失败: {e}")

        logger.info(f"数据流分析完成: 发现 {len(vulnerabilities)} 个潜在漏洞")
        return vulnerabilities

    def analyze_code(self, code: str, file_path: str = "<unknown>") -> List[Vulnerability]:
        """
        分析代码片段

        Args:
            code: 代码内容
            file_path: 文件路径（用于报告）

        Returns:
            漏洞列表
        """
        vulnerabilities = self.taint_analyzer.analyze_file(file_path, code)

        # 更新路径信息
        for vuln in vulnerabilities:
            vuln.path.source_location = (file_path, vuln.path.source_location[1])
            vuln.path.sink_location = (file_path, vuln.path.sink_location[1])

        return vulnerabilities


# 全局分析器实例
_global_analyzer: Optional[DataFlowAnalyzer] = None


def get_dataflow_analyzer() -> DataFlowAnalyzer:
    """获取全局数据流分析器"""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = DataFlowAnalyzer()
    return _global_analyzer
