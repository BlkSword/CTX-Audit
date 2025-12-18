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
    """
    Build or update the AST index for a project directory.
    This indexes all code files to enable fast symbol search, call graph generation, etc.
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
async def run_security_scan(directory: str, custom_rules: Optional[str] = None, include_dirs: Optional[str] = None, exclude_dirs: Optional[str] = None) -> str:
    """
    Run security scan on a project directory with custom rules and filtering options.
    
    Args:
        directory: Directory to scan
        custom_rules: JSON string with custom rules, format: {"ext": [{"pattern": "regex", "message": "description", "severity": "level"}]}
        include_dirs: JSON string with list of directories to include (relative paths)
        exclude_dirs: JSON string with list of directories to exclude (relative paths)
        
    Returns:
        JSON string containing the security findings
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
    """
    Retrieve the cached analysis report for a project.
    Returns the JSON content of the last analysis.
    """
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        ast_engine.use_repository(directory)
        report_cache_path = os.path.join(ast_engine.cache_dir, "analysis_report.json")
        if not os.path.exists(report_cache_path):
            return json.dumps({"error": "未找到缓存报告"})

        with open(report_cache_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return json.dumps({"error": f"读取缓存报告失败: {str(e)}"})

@mcp.tool()
async def find_call_sites(directory: str, symbol: str) -> str:
    """
    Find all call sites of a specific function or method symbol in the project.
    Returns a list of file locations and code snippets where the symbol is invoked.
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
    """
    Generate a call graph starting from a specific entry point (function/method).
    Returns nodes and edges representing the call structure up to max_depth.
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
    """
    Read the contents of a file.
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
    """
    List files and directories in a given path (non-recursive).
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
    """
    Search for a text pattern (regex) in all files within a directory.
    """
    results = []
    try:
        for root, _, files in os.walk(directory):
            if "node_modules" in root or ".git" in root or "target" in root:
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
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
    """
    Get the code structure (classes, functions, methods) of a specific file using AST analysis.
    Useful for understanding the file's API without reading the whole content.
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
    """
    Search for code symbols (classes, functions) across the project using AST index.
    Returns the file path, line number, and definition snippet.
    """
    try:
        results = ast_engine.search_symbols(query)
        if not results:
            return "未找到匹配的符号。"
            
        output = f"找到 {len(results)} 个匹配 '{query}' 的符号:\n\n"
        for sym in results[:20]: # Limit to 20 results
            output += f"文件: {sym['file_path']}:{sym['line']}\n"
            output += f"类型: {sym['kind']}\n"
            output += f"名称: {sym['name']}\n"
            if "parent_classes" in sym and sym["parent_classes"]:
                output += f"继承: {', '.join(sym['parent_classes'])}\n"
            output += f"代码: `{sym['code'].strip()}`\n\n"
            
        if len(results) > 20:
            output += f"...以及其他 {len(results) - 20} 个。"
            
        return output
    except Exception as e:
        return f"搜索符号出错: {str(e)}"

@mcp.tool()
async def get_class_hierarchy(class_name: str) -> str:
    """
    Get the inheritance hierarchy (parents and children) for a specific class.
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
            config = uvicorn.Config(app, host="127.0.0.1", port=8338, log_level="warning")
            server = uvicorn.Server(config)
            asyncio.run(server.serve())
        except Exception as e:
            logger.error(f"SSE 服务器启动失败: {e}")

    try:
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        logger.info("MCP SSE 已启动: http://localhost:8338/sse")
    except Exception as e:
        logger.error(f"SSE 线程启动失败: {e}")

if __name__ == "__main__":
    logger.info("Starting DeepAudit Agent via Stdio")
    try:
        _start_sse_server()
        mcp.run()
    except Exception as e:
        logger.error(f"Agent crashed: {e}")
        sys.exit(1)
