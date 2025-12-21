import sys
import logging
import asyncio
import os
import json
import re
import fnmatch
import uvicorn
import threading
from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP, Context
from starlette.middleware.cors import CORSMiddleware
from ast_engine import ASTEngine
from llm_engine import LLMEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr,
    force=True
)
logger = logging.getLogger("deep-audit-agent")
# Ensure MCP and AST logs are captured
logging.getLogger("mcp").setLevel(logging.INFO)
logging.getLogger("deep-audit-ast").setLevel(logging.INFO)

# Initialize FastMCP Server
mcp = FastMCP("DeepAudit Agent")

# Initialize AST Engine
ast_engine = ASTEngine()

# Initialize LLM Engine
llm_engine = LLMEngine()

class SecurityScanner:
    @staticmethod
    async def scan_file(file_path: str, custom_rules: Optional[Dict[str, List[Dict[str, str]]]] = None) -> List[Dict[str, Any]]:
        """
        Scan a single file using provided custom rules only.
        Custom rules format: {"ext": [{"pattern": "regex", "message": "description", "severity": "level"}]}
        """
        findings = []
        ext = os.path.splitext(file_path)[1].lower()
        
        # Only use custom rules if provided
        if not custom_rules or not isinstance(custom_rules, dict):
            return findings
        
        # Get rules for this file extension
        file_rules = custom_rules.get(ext, [])
        if not file_rules:
            return findings

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.readlines()
                
            for i, line in enumerate(content):
                for rule in file_rules:
                    pattern = rule.get("pattern")
                    message = rule.get("message", "未定义的问题")
                    severity = rule.get("severity", "medium")
                    
                    if pattern and re.search(pattern, line):
                        findings.append({
                            "file": file_path,
                            "line": i + 1,
                            "severity": severity,
                            "message": message,
                            "code": line.strip()
                        })
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            
        return findings

    @staticmethod
    async def scan_directory(path: str, custom_rules: Optional[Dict[str, List[Dict[str, str]]]] = None, include_dirs: Optional[List[str]] = None, exclude_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Scan directory with custom rules and filtering options.
        
        Args:
            path: Directory to scan
            custom_rules: Custom regex patterns for scanning, format: {"ext": [{"pattern": "regex", "message": "description", "severity": "level"}]}
            include_dirs: List of directories to include (relative paths)
            exclude_dirs: List of directories to exclude (relative paths)
            
        Returns:
            List of findings
        """
        results = []
        files_to_scan = []
        
        # Default exclude patterns
        default_excludes = ["node_modules", ".git", "target", "__pycache__", ".venv", "dist", "build"]
        
        # Combine exclude directories
        excludes = default_excludes.copy()
        if exclude_dirs:
            excludes.extend(exclude_dirs)
        
        # 1. Collect files with improved filtering
        for root, _, files in os.walk(path):
            # Check if directory should be excluded
            if any(exclude in root for exclude in excludes):
                continue
            
            # Check if we should include this directory
            if include_dirs:
                # Only include specified directories
                rel_path = os.path.relpath(root, path)
                if rel_path == ".":
                    # Always include root directory
                    pass
                elif not any(include in rel_path for include in include_dirs):
                    continue
            
            for file in files:
                files_to_scan.append(os.path.join(root, file))

        total_files = len(files_to_scan)
        logger.info(f"在 {path} 中发现 {total_files} 个文件需要扫描")
            
        # 2. Scan files with progress logging
        for i, file_path in enumerate(files_to_scan):
            if i % 50 == 0:  # Reduce logging frequency for large projects
                logger.info(f"正在扫描 {i}/{total_files}: {os.path.basename(file_path)}")
            
            # Run Regex Scan with custom rules
            file_findings = await SecurityScanner.scan_file(file_path, custom_rules)
            results.extend(file_findings)

        return results

@mcp.tool()
async def build_ast_index(directory: str) -> str:
    """构建或更新项目的 AST 索引。

    Purpose: 为项目目录构建 AST 索引，以支持快速符号搜索、调用图生成等功能。
    Usage: 提供 `directory` 参数指定项目根目录。
    Returns: JSON 字符串，包含构建状态、AST 统计信息和摘要。
    Related: 后续可使用 `search_symbol`, `get_call_graph` 等工具。
    """
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        logger.info(f"开始构建 AST 索引: {directory}")
        ast_engine.use_repository(directory)
        
        # 1. Build/Update AST Index
        ast_engine.scan_project(directory)
        
        # 2. Save AST Cache
        ast_engine.save_cache()
        
        # 3. Generate and log statistics
        stats = ast_engine.get_statistics()
        
        stats_msg = "\nAST 索引构建完成！\n"
        stats_msg += f"总节点数: {stats['total_nodes']}\n\n"
        stats_msg += "节点类型统计:\n"
        for k, v in stats['type_counts'].items():
            stats_msg += f"- {k}: {v}\n"
            
        logger.info(stats_msg)
        
        # 4. Generate and Cache Detailed Report
        report_cache_path = os.path.join(ast_engine.cache_dir, "analysis_report.json")
        try:
            full_report = ast_engine.generate_report(directory)
            if not os.path.exists(ast_engine.cache_dir):
                os.makedirs(ast_engine.cache_dir)
            with open(report_cache_path, "w", encoding="utf-8") as f:
                json.dump(full_report, f, ensure_ascii=False, indent=2)
            logger.info(f"详细分析报告已缓存至: {os.path.abspath(report_cache_path)}")
        except Exception as e:
            logger.error(f"缓存分析报告失败: {e}")
        
        result_data = {
            "status": "success",
            "message": "AST 索引已成功构建/更新。",
            "ast_statistics": stats,
            "summary": stats_msg.strip()
        }
        
        return json.dumps(result_data)
    except Exception as e:
        logger.error(f"构建 AST 索引失败: {e}")
        return json.dumps({"error": f"构建 AST 索引过程中出错: {str(e)}"})

@mcp.tool()
async def verify_finding(file: str, line: int, description: str, vuln_type: str, code: Optional[str] = None) -> str:
    """使用 LLM 验证安全发现。

    Purpose: 利用大语言模型分析潜在的安全漏洞，判断其是否为误报。
    Usage: 提供 `file` (文件路径), `line` (行号), `description` (描述), `vuln_type` (漏洞类型), 可选 `code` (代码片段)。
    Returns: JSON 字符串，包含验证结果和分析详情。
    Related: 通常在 `run_security_scan` 发现问题后使用。
    """
    try:
        # Get context from AST engine if possible
        context = ""
        if file and os.path.exists(file):
             # Simple context: read surrounding lines
             try:
                 with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                     lines = f.readlines()
                     line_idx = int(line) - 1
                     start = max(0, line_idx - 5)
                     end = min(len(lines), line_idx + 6)
                     context = "".join(lines[start:end])
             except Exception as e:
                 logger.warning(f"Failed to read context for {file}: {e}")
        
        finding = {
            "file": file,
            "line": line,
            "description": description,
            "vuln_type": vuln_type,
            "code": code or ""
        }
        
        result = await llm_engine.verify_vulnerability(finding, context)
        return json.dumps(result)
    except Exception as e:
        logger.error(f"Error verifying finding: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_knowledge_graph(limit: int = 100) -> str:
    """获取项目的知识图谱。

    Purpose: 获取项目中文件、类、函数及其关系的图形化表示。
    Usage: 可选 `limit` 参数限制返回的节点数量（默认 100）。
    Returns: JSON 字符串，包含节点和边的图数据。
    Related: 可用于前端可视化项目结构。
    """
    try:
        graph = ast_engine.get_knowledge_graph(limit)
        return json.dumps({"status": "success", "graph": graph}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"Failed to get knowledge graph: {str(e)}"})

@mcp.tool()
async def run_security_scan(directory: str, custom_rules: Optional[str] = None, include_dirs: Optional[str] = None, exclude_dirs: Optional[str] = None) -> str:
    """对项目目录运行安全扫描。

    Purpose: 使用 AST 和正则规则扫描项目中的安全漏洞，支持自定义规则和过滤。
    Usage: 提供 `directory`；可选 `custom_rules` (JSON字符串), `include_dirs` (JSON数组字符串), `exclude_dirs` (JSON数组字符串)。
    Returns: JSON 字符串，包含发现的漏洞列表、统计信息和严重程度分布。
    Related: 扫描结果可用 `verify_finding` 进行进一步验证。
    """
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        logger.info(f"开始安全扫描: {directory}")
        ast_engine.use_repository(directory)
        
        # Parse custom rules if provided
        parsed_rules = None
        if custom_rules and isinstance(custom_rules, str):
            try:
                parsed_rules = json.loads(custom_rules)
                logger.info("已加载自定义规则")
            except json.JSONDecodeError as e:
                logger.error(f"解析自定义规则失败: {e}")
                return json.dumps({"error": f"自定义规则格式错误: {str(e)}"})
        
        # Parse include_dirs if provided
        parsed_include = None
        if include_dirs and isinstance(include_dirs, str):
            try:
                parsed_include = json.loads(include_dirs)
                if not isinstance(parsed_include, list):
                    parsed_include = None
            except json.JSONDecodeError as e:
                logger.error(f"解析包含目录失败: {e}")
        
        # Parse exclude_dirs if provided
        parsed_exclude = None
        if exclude_dirs and isinstance(exclude_dirs, str):
            try:
                parsed_exclude = json.loads(exclude_dirs)
                if not isinstance(parsed_exclude, list):
                    parsed_exclude = None
            except json.JSONDecodeError as e:
                logger.error(f"解析排除目录失败: {e}")
        
        # 1. Run Security Scan with custom rules and filtering
        logger.info("正在进行安全扫描...")
        findings = await SecurityScanner.scan_directory(
            directory, 
            custom_rules=parsed_rules, 
            include_dirs=parsed_include, 
            exclude_dirs=parsed_exclude
        )
        
        logger.info(f"安全扫描完成，发现 {len(findings)} 个问题。")
        
        # 2. Group findings by severity for better reporting
        severity_counts = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        result_data = {
            "status": "success",
            "findings": findings,
            "count": len(findings),
            "severity_counts": severity_counts,
            "message": f"安全扫描完成，发现 {len(findings)} 个问题。",
            "details": {
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"]
            }
        }
        
        if not findings:
            result_data["message"] = "安全扫描完成，未发现明显漏洞。"
            
        return json.dumps(result_data)
    except Exception as e:
        logger.error(f"安全扫描失败: {e}")
        return json.dumps({"error": f"安全扫描过程中出错: {str(e)}"})



@mcp.tool()
async def get_analysis_report(directory: str) -> str:
    """检索项目的缓存分析报告。

    Purpose: 获取上一次构建 AST 索引时生成的详细分析报告。
    Usage: 提供 `directory` 参数指定项目路径。
    Returns: JSON 字符串，包含完整的分析报告内容。
    Related: 需先运行 `build_ast_index` 生成报告。
    """
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        ast_engine.use_repository(directory)
        report_cache_path = os.path.join(ast_engine.cache_dir, "analysis_report.json")
        if not os.path.exists(report_cache_path):
            return json.dumps({"error": "未找到缓存报告"})

        with open(report_cache_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if not content:
                return json.dumps({"error": "缓存报告为空，请重新运行 build_ast_index"})
            return content
    except Exception as e:
        return json.dumps({"error": f"读取缓存报告失败: {str(e)}"})

@mcp.tool()
async def find_call_sites(directory: str, symbol: str) -> str:
    """查找特定符号的所有调用点。

    Purpose: 在项目中查找指定函数或方法的调用位置。
    Usage: 提供 `directory` 和 `symbol` (符号名称)。
    Returns: JSON 字符串，包含调用该符号的文件位置和代码片段列表。
    Related: 配合 `get_call_graph` 理解调用关系。
    """
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        ast_engine.use_repository(directory)
        if not ast_engine.index:
            ast_engine.scan_project(directory)
        results = ast_engine.find_call_sites(symbol)
        return json.dumps({"status": "success", "symbol": symbol, "count": len(results), "results": results}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"查询调用点失败: {str(e)}"})

@mcp.tool()
async def get_call_graph(directory: str, entry: str, max_depth: int = 2) -> str:
    """生成指定入口点的调用图。

    Purpose: 生成从特定函数或方法开始的调用结构图。
    Usage: 提供 `directory`, `entry` (入口符号名)；可选 `max_depth` (默认 2)。
    Returns: JSON 字符串，包含节点和边的调用图数据。
    Related: 用于深入分析代码执行流程。
    """
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        ast_engine.use_repository(directory)
        if not ast_engine.index:
            ast_engine.scan_project(directory)
        graph = ast_engine.get_call_graph(entry, max_depth=max_depth)
        return json.dumps({"status": "success", "graph": graph}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"生成调用图失败: {str(e)}"})

@mcp.tool()
async def read_file(file_path: str) -> str:
    """读取文件内容。

    Purpose: 获取指定文件的完整文本内容。
    Usage: 提供 `file_path` (绝对路径)。
    Returns: 文件的文本内容，若读取失败返回错误信息。
    Related: 用于查看代码细节或手动分析。
    """
    try:
        if not os.path.exists(file_path):
            return f"错误: 文件 '{file_path}' 不存在。"
            
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        return f"读取文件出错: {str(e)}"

@mcp.tool()
async def list_files(directory: str) -> str:
    """列出目录下的文件和子目录。

    Purpose: 查看指定目录下的直接子文件和子文件夹（非递归）。
    Usage: 提供 `directory` 路径。
    Returns: 格式化的文件列表字符串，区分文件和目录。
    Related: 用于探索文件系统结构。
    """
    try:
        if not os.path.exists(directory):
            return f"错误: 目录 '{directory}' 不存在。"
            
        items = os.listdir(directory)
        formatted_items = []
        for item in items:
            path = os.path.join(directory, item)
            type_label = "DIR" if os.path.isdir(path) else "FILE"
            formatted_items.append(f"[{type_label}] {item}")
            
        return "\n".join(formatted_items)
    except Exception as e:
        return f"列出目录出错: {str(e)}"

@mcp.tool()
async def search_files(directory: str, pattern: str) -> str:
    """在目录下搜索文件名或内容匹配正则的文件。

    Purpose: 通过正则表达式搜索文件名或文件内容。
    Usage: 提供 `directory` 和 `pattern` (正则表达式)。
    Returns: 匹配的文件路径及行内容列表字符串。
    Related: 用于查找特定代码模式或文件。
    """
    results = []
    try:
        # Validate regex pattern
        try:
            re.compile(pattern)
        except re.error:
            return f"无效的正则表达式: {pattern}"

        for root, _, files in os.walk(directory):
            if "node_modules" in root or ".git" in root or "target" in root:
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                
                # 1. Check if filename matches pattern
                if re.search(pattern, file):
                    results.append(f"{file_path}: [文件名匹配]")

                # 2. Check content
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f):
                            if re.search(pattern, line):
                                results.append(f"{file_path}:{i+1}: {line.strip()}")
                except:
                    continue
                    
        if not results:
            return "未找到匹配项。"
            
        return "\n".join(results)
    except Exception as e:
        return f"搜索文件出错: {str(e)}"

@mcp.tool()
async def get_code_structure(file_path: str) -> str:
    """获取指定文件的代码结构。

    Purpose: 使用 AST 分析文件，提取类、函数和方法等结构信息。
    Usage: 提供 `file_path`。
    Returns: 格式化的代码结构描述字符串。
    Related: 快速了解文件概况，无需阅读全部代码。
    """
    try:
        symbols = ast_engine.get_file_structure(file_path)
        if not symbols:
            return "未找到符号或不支持的文件类型。"
            
        output = f"{os.path.basename(file_path)} 的代码结构:\n"
        for sym in symbols:
            output += f"- [{sym['kind'].upper()}] {sym['name']} (第 {sym['line']} 行)\n"
            
        return output
    except Exception as e:
        return f"分析结构出错: {str(e)}"

@mcp.tool()
async def search_symbol(query: str) -> str:
    """全项目搜索代码符号。

    Purpose: 使用 AST 索引在整个项目中搜索类、函数等符号定义。
    Usage: 提供 `query` (符号名称关键词)。
    Returns: 匹配的符号列表，包含位置、类型、继承关系和代码定义。
    Related: 用于快速定位代码定义。
    """
    try:
        results = ast_engine.search_symbols(query)
        if not results:
            return "未找到匹配的符号。"
            
        output = f"找到 {len(results)} 个匹配 '{query}' 的符号:\n\n"
        for sym in results[:20]: # Limit to 20 results
            file_path = sym.get("file_path") or sym.get("file") or "Unknown"
            output += f"文件: {file_path}:{sym.get('line', '?')}\n"
            output += f"类型: {sym.get('kind', 'Unknown')}\n"
            output += f"名称: {sym.get('name', 'Unknown')}\n"
            if "parent_classes" in sym and sym["parent_classes"]:
                output += f"继承: {', '.join(sym['parent_classes'])}\n"
            
            code = sym.get('code', '').strip()
            if code:
                output += f"代码: `{code}`\n\n"
            else:
                output += "\n"
            
        if len(results) > 20:
            output += f"...以及其他 {len(results) - 20} 个。"
            
        return output
    except Exception as e:
        return f"搜索符号出错: {str(e)}"

@mcp.tool()
async def get_class_hierarchy(class_name: str) -> str:
    """获取类的继承层次结构。

    Purpose: 分析指定类的父类和子类关系。
    Usage: 提供 `class_name`。
    Returns: 格式化的继承树字符串，包含父类和子类信息。
    Related: 用于理解面向对象设计结构。
    """
    try:
        data = ast_engine.get_class_hierarchy(class_name)
        if "error" in data:
            return f"错误: {data['error']}"
            
        output = f"{data['class']} ({os.path.basename(data['file'])}) 的类继承层次:\n\n"
        
        if data["parents"]:
            output += "父类 (Superclasses):\n"
            for p in data["parents"]:
                output += f"  ↑ {p['name']} ({os.path.basename(p['file'])}:{p['line']})\n"
        else:
            output += "父类: 无 (根类或未知)\n"
            
        output += f"\n当前: {data['class']}\n"
        
        if data["children"]:
            output += "\n子类 (Subclasses):\n"
            for c in data["children"]:
                output += f"  ↓ {c['name']} ({os.path.basename(c['file'])}:{c['line']})\n"
        else:
            output += "\n子类: 无\n"
            
        return output
    except Exception as e:
        return f"分析继承层次出错: {str(e)}"



# Create ASGI app with CORS
app = mcp.sse_app()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Mcp-Session-Id"]
)

def _start_sse_server() -> None:
    def run() -> None:
        try:
            port = int(os.environ.get("MCP_PORT", 8338))
            config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
            server = uvicorn.Server(config)
            asyncio.run(server.serve())
        except Exception as e:
            logger.error(f"SSE 服务器启动失败: {e}")

    try:
        port = int(os.environ.get("MCP_PORT", 8338))
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        logger.info(f"MCP SSE 已启动: http://localhost:{port}/sse")
    except Exception as e:
        logger.error(f"SSE 线程启动失败: {e}")

class LLMProcessor:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        
    async def analyze(self, code: str, context: str) -> str:
        if not self.api_key:
            return f"LLM Analysis (Mock): Based on the code snippet provided, there appears to be a potential logic flow issue. \nContext: {context}\nSuggestion: Review input validation."
        
        # Placeholder for real OpenAI call
        # client = AsyncOpenAI(api_key=self.api_key)
        # response = await client.chat.completions.create(...)
        return "Real LLM Analysis would happen here."

llm_processor = LLMProcessor()

@mcp.tool()
async def analyze_code_with_llm(code: str, context: str = "") -> str:
    """使用 LLM 分析代码片段。

    Purpose: 利用大语言模型分析代码逻辑，查找潜在错误或解释代码。
    Usage: 提供 `code` (代码片段)；可选 `context` (上下文信息)。
    Returns: LLM 的分析结果字符串。
    Related: 用于深入理解复杂代码段。
    """
    return await llm_processor.analyze(code, context)

if __name__ == "__main__":
    logger.info("Starting DeepAudit Agent via Stdio")
    try:
        _start_sse_server()
        mcp.run()
    except Exception as e:
        logger.error(f"Agent crashed: {e}")
        sys.exit(1)
