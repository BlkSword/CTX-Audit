"""
数据流分析单元测试
"""
import pytest

from app.core.dataflow_analysis import (
    TaintStatus,
    Source,
    Sink,
    Sanitizer,
    DataFlowPath,
    Vulnerability,
    TaintAnalyzer,
    DataFlowAnalyzer,
    get_dataflow_analyzer,
)


class TestDataFlowModels:
    """数据流模型测试"""

    def test_source_creation(self):
        """测试创建污点源点"""
        source = Source(
            name="request.get",
            category="user_input",
            pattern=r"request\.(get|post)",
            severity="high",
            cwe_ids=["CWE-20"],
            description="HTTP请求数据",
        )

        assert source.name == "request.get"
        assert source.category == "user_input"
        assert source.severity == "high"
        assert "CWE-20" in source.cwe_ids

    def test_sink_creation(self):
        """测试创建污点汇点"""
        sink = Sink(
            name="execute",
            category="sql",
            pattern=r"cursor\.execute",
            severity="critical",
            cwe_ids=["CWE-89"],
            description="SQL注入",
        )

        assert sink.name == "execute"
        assert sink.category == "sql"
        assert sink.severity == "critical"

    def test_sanitizer_creation(self):
        """测试创建净化点"""
        sanitizer = Sanitizer(
            name="escape_string",
            pattern=r"escape_string\(",
            effectiveness=0.9,
            description="SQL字符串转义",
        )

        assert sanitizer.name == "escape_string"
        assert sanitizer.effectiveness == 0.9

    def test_data_flow_path(self):
        """测试数据流路径"""
        path = DataFlowPath(
            source_location=("/test/file.py", 10),
            sink_location=("/test/file.py", 20),
            variables=["user_input", "query"],
            functions=["get_input", "execute"],
            sanitizers=[("escape", 15)],
            is_sanitized=True,
            confidence=0.8,
        )

        assert path.source_location == ("/test/file.py", 10)
        assert path.sink_location == ("/test/file.py", 20)
        assert path.is_sanitized is True
        assert path.confidence == 0.8

    def test_vulnerability_creation(self):
        """测试漏洞创建"""
        source = Source("request.get", "user_input", r"request\.get")
        sink = Sink("execute", "sql", r"cursor\.execute")
        path = DataFlowPath(
            source_location=("/test/file.py", 10),
            sink_location=("/test/file.py", 20),
            variables=["user_input"],
            functions=[],
            sanitizers=[],
            is_sanitized=False,
            confidence=0.9,
        )

        vuln = Vulnerability(
            vuln_type="SQL Injection",
            source=source,
            sink=sink,
            path=path,
            description="SQL注入漏洞",
            severity="critical",
            cwe_ids=["CWE-89"],
            recommendation="使用参数化查询",
        )

        assert vuln.vuln_type == "SQL Injection"
        assert vuln.severity == "critical"


class TestTaintAnalyzer:
    """TaintAnalyzer 测试"""

    def test_find_sources(self):
        """测试查找污点源点"""
        analyzer = TaintAnalyzer()

        code = """
def view(request):
    user_id = request.GET.get('id')
    data = request.POST.get('data')
    return render(request, 'template.html')
"""
        sources = analyzer._find_sources("test.py", code.split('\n'))

        assert len(sources) >= 2  # 至少找到 request.GET 和 request.POST

    def test_find_sinks(self):
        """测试查找污点汇点"""
        analyzer = TaintAnalyzer()

        code = """
cursor.execute(query)
subprocess.run(command)
eval(user_input)
"""
        sinks = analyzer._find_sinks("test.py", code.split('\n'))

        assert len(sinks) >= 3  # execute, run, eval

    def test_find_sanitizers(self):
        """测试查找净化点"""
        analyzer = TaintAnalyzer()

        code = """
cleaned = html.escape(user_input)
escaped = escape_string(data)
query = db.filter(id=1)
"""
        sanitizers = analyzer._find_sanitizers("test.py", code.split('\n'))

        assert len(sanitizers) >= 2  # escape, escape_string

    def test_is_sanitized_sql(self):
        """测试 SQL 净化判断"""
        analyzer = TaintAnalyzer()

        source = Source("request.get", "user_input", r"request\.get")
        sink = Sink("execute", "sql", r"cursor\.execute")

        # 有参数化查询
        sanitizers = [
            (Sanitizer("parameterized", r"%s", 1.0), 10),
        ]
        assert analyzer._is_sanitized(source, sink, sanitizers) is True

        # 无净化
        assert analyzer._is_sanitized(source, sink, []) is False

    def test_is_sanitized_html(self):
        """测试 HTML 净化判断"""
        analyzer = TaintAnalyzer()

        source = Source("request.get", "user_input", r"request\.get")
        sink = Sink("innerHTML", "html", r"innerHTML")

        # 有 HTML 转义
        sanitizers = [
            (Sanitizer("escape", r"escape\(", 0.9), 10),
        ]
        assert analyzer._is_sanitized(source, sink, sanitizers) is True

        # 无净化
        assert analyzer._is_sanitized(source, sink, []) is False

    def test_calculate_confidence(self):
        """测试置信度计算"""
        analyzer = TaintAnalyzer()

        source = Source("request.get", "user_input", r"request\.get", severity="high")
        sink = Sink("execute", "sql", r"cursor\.execute", severity="critical")

        # 高风险源 + 危险汇点 + 无净化 = 高置信度
        confidence = analyzer._calculate_confidence(source, sink, [])
        assert confidence > 0.7

        # 有净化点 = 降低置信度
        sanitizers = [(Sanitizer("escape", r"escape", 0.9), 10)]
        confidence_with_sanitizer = analyzer._calculate_confidence(
            source, sink, sanitizers
        )
        assert confidence_with_sanitizer < confidence

    def test_analyze_vulnerable_code(self):
        """测试分析有漏洞的代码"""
        analyzer = TaintAnalyzer()

        vulnerable_code = """
def view(request):
    user_id = request.GET.get('id')
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
    return results
"""
        vulnerabilities = analyzer.analyze_file("test.py", vulnerable_code)

        # 应该检测到 SQL 注入
        assert len(vulnerabilities) > 0
        sql_injections = [v for v in vulnerabilities if "SQL" in v.vuln_type]
        assert len(sql_injections) > 0

    def test_analyze_sanitized_code(self):
        """测试分析已净化的代码"""
        analyzer = TaintAnalyzer()

        sanitized_code = """
def view(request):
    user_id = request.GET.get('id')
    query = "SELECT * FROM users WHERE id=%s"
    cursor.execute(query, [user_id])  # 参数化查询
    return results
"""
        vulnerabilities = analyzer.analyze_file("test.py", sanitized_code)

        # 不应该检测到漏洞（或置信度很低）
        critical_vulns = [v for v in vulnerabilities if v.severity == "critical"]
        assert len(critical_vulns) == 0


class TestDataFlowAnalyzer:
    """DataFlowAnalyzer 测试"""

    def test_analyze_project(self):
        """测试分析项目"""
        # 这个测试需要实际文件，暂时跳过
        pytest.skip("需要实际文件系统")

    def test_analyze_code(self):
        """测试分析代码片段"""
        analyzer = DataFlowAnalyzer()

        code = """
def view(request):
    user_id = request.GET.get('id')
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
"""
        vulnerabilities = analyzer.analyze_code(code, "test.py")

        # 应该检测到 SQL 注入
        assert len(vulnerabilities) > 0


class TestGlobalAnalyzer:
    """全局分析器测试"""

    def test_get_singleton(self):
        """测试获取单例"""
        analyzer1 = get_dataflow_analyzer()
        analyzer2 = get_dataflow_analyzer()

        assert analyzer1 is analyzer2


class TestConfidenceThresholds:
    """置信度阈值测试"""

    def test_low_confidence_not_reported(self):
        """测试低置信度漏洞不被报告"""
        analyzer = TaintAnalyzer()

        # 编写模糊代码，不应该产生高置信度结果
        vague_code = """
def some_function(data):
    result = process(data)
    return result
"""
        vulnerabilities = analyzer.analyze_file("test.py", vague_code)

        # 低置信度的漏洞不应该被报告
        high_confidence = [v for v in vulnerabilities if v.path.confidence > 0.5]
        assert len(high_confidence) == 0
