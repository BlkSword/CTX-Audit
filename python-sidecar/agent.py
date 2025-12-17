import sys
import logging
import asyncio
import os
import json
import re
import fnmatch
import uvicorn
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
    PATTERNS = {
        ".py": [
            (r"eval\(", "危险的 eval() 用法", "high"),
            (r"exec\(", "危险的 exec() 用法", "high"),
            (r"subprocess\.call\(", "潜在的命令注入", "medium"),
            (r"password\s*=\s*['\"].+['\"]", "可能硬编码的密码", "medium"),
            (r"api_key\s*=\s*['\"].+['\"]", "可能硬编码的 API 密钥", "medium"),
        ],
        ".js": [
            (r"eval\(", "危险的 eval() 用法", "high"),
            (r"dangerouslySetInnerHTML", "不安全的 React 用法", "medium"),
        ],
        ".ts": [
            (r"eval\(", "危险的 eval() 用法", "high"),
            (r"dangerouslySetInnerHTML", "不安全的 React 用法", "medium"),
        ],
        ".tsx": [
            (r"dangerouslySetInnerHTML", "不安全的 React 用法", "medium"),
        ],
        ".rs": [
            (r"\.unwrap\(\)", "不安全的 unwrap() 用法 (潜在 panic)", "low"),
            (r"unsafe\s*\{", "不安全的 Rust 代码块", "medium"),
        ],
        ".java": [
            (r"Runtime\.getRuntime\(\)\.exec\(", "潜在的命令注入", "high"),
            (r"ProcessBuilder\(", "潜在的命令注入", "medium"),
            (r"Statement\.executeQuery\(", "潜在的 SQL 注入 (检查字符串拼接)", "medium"),
            (r"Thread\.stop\(", "不安全的线程终止 (已废弃)", "low"),
            (r"System\.exit\(", "意外的 JVM 终止", "medium"),
            (r"password\s*=\s*['\"].+['\"]", "可能硬编码的密码", "medium"),
        ]
    }

    @staticmethod
    async def scan_file(file_path: str) -> List[Dict[str, Any]]:
        findings = []
        ext = os.path.splitext(file_path)[1].lower()
        
        if ext not in SecurityScanner.PATTERNS:
            return findings

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.readlines()
                
            for i, line in enumerate(content):
                for pattern, message, severity in SecurityScanner.PATTERNS[ext]:
                    if re.search(pattern, line):
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
    async def scan_directory(path: str, update_ast: bool = True) -> List[Dict[str, Any]]:
        results = []
        files_to_scan = []
        
        # 1. Collect files
        for root, _, files in os.walk(path):
            if "node_modules" in root or ".git" in root or "target" in root or "__pycache__" in root:
                continue
            for file in files:
                files_to_scan.append(os.path.join(root, file))

        total_files = len(files_to_scan)
        logger.info(f"在 {path} 中发现 {total_files} 个文件需要扫描")
            
        # 2. Scan files
        for i, file_path in enumerate(files_to_scan):
            if i % 10 == 0:
                logger.info(f"正在扫描 {i}/{total_files}: {os.path.basename(file_path)}")
            
            # Run Regex Scan
            file_findings = await SecurityScanner.scan_file(file_path)
            results.extend(file_findings)

            if update_ast:
                ast_engine.update_file(file_path)

        if update_ast:
            ast_engine.save_cache()

        return results

@mcp.tool()
async def analyze_project(directory: str) -> str:
    """
    Scan a project directory for potential security vulnerabilities and build AST index.
    Returns a JSON string containing the findings.
    """
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        logger.info(f"开始分析: {directory}")

        ast_engine.use_repository(directory)
        report_cache_path = os.path.join(ast_engine.cache_dir, "analysis_report.json")
        
        # 1. Update AST Index
        logger.info("正在构建/更新 AST 索引...")
        ast_engine.scan_project(directory)
        
        # 2. Run Security Scan
        logger.info("正在进行安全扫描...")
        findings = await SecurityScanner.scan_directory(directory, update_ast=False)
        
        # 3. Save AST Cache
        ast_engine.save_cache()
        
        # 4. Generate and log statistics
        stats = ast_engine.get_statistics()
        
        stats_msg = "\n代码分析完成！\n"
        stats_msg += f"总节点数: {stats['total_nodes']}\n\n"
        stats_msg += "节点类型统计:\n"
        for k, v in stats['type_counts'].items():
            stats_msg += f"- {k}: {v}\n"
            
        # Log to stderr (captured by frontend)
        logger.info(stats_msg)
        
        result_data = {
            "status": "success",
            "findings": findings,
            "summary": f"发现 {len(findings)} 个问题。\n\n{stats_msg}",
            "ast_statistics": stats
        }
        
        if not findings:
            result_data["message"] = "未发现明显漏洞。AST 索引已更新。"
            
        # 5. Generate and Cache Detailed Report
        try:
            full_report = ast_engine.generate_report(directory)
            if not os.path.exists(ast_engine.cache_dir):
                os.makedirs(ast_engine.cache_dir)
            with open(report_cache_path, "w", encoding="utf-8") as f:
                json.dump(full_report, f, ensure_ascii=False, indent=2)
            logger.info(f"详细分析报告已缓存至: {os.path.abspath(report_cache_path)}")
        except Exception as e:
            logger.error(f"缓存分析报告失败: {e}")
            
        return json.dumps(result_data)
    except Exception as e:
        logger.error(f"分析失败: {e}")
        return json.dumps({"error": f"分析过程中出错: {str(e)}"})

@mcp.tool()
async def get_analysis_report(directory: str) -> str:
    if not os.path.exists(directory):
        return json.dumps({"error": f"路径 '{directory}' 不存在。"})

    try:
        ast_engine.use_repository(directory)
        report_cache_path = os.path.join(ast_engine.cache_dir, "analysis_report.json")
        if not os.path.exists(report_cache_path):
            return json.dumps({"error": "未找到缓存报告，请先运行 analyze_project。"})

        with open(report_cache_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return json.dumps({"error": f"读取缓存报告失败: {str(e)}"})

@mcp.tool()
async def find_call_sites(directory: str, symbol: str) -> str:
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

if __name__ == "__main__":
    logger.info("Starting DeepAudit Agent via Stdio")
    try:
        mcp.run()
    except Exception as e:
        logger.error(f"Agent crashed: {e}")
        sys.exit(1)
