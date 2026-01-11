"""
MCP 工具实现

包含所有符合 MCP 标准的工具实现
"""
from app.core.mcp_tools import (
    MCPTool, ToolResult, ToolParameter, register_tool, ToolErrorCode
)
from typing import Optional, Dict, Any
import json


# ==================== 文件操作工具 ====================

class ReadFileTool(MCPTool):
    """
    读取文件内容工具

    读取指定文件的内容，可选择读取特定行范围
    """

    name = "read_file"
    description = """
读取文件内容，支持可选的行范围限制。

**用途:**
- 查看源代码文件
- 读取配置文件
- 检查特定行的代码上下文

**示例:**
- 读取整个文件: {"file_path": "src/main.py"}
- 读取特定行: {"file_path": "src/main.py", "line_range": [10, 50]}

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "文件内容..."},
    {"type": "data", "data": {"file_path": "...", "line_count": 100}}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="file_path",
            type="string",
            description="文件路径，可以是绝对路径或相对路径",
            required=True
        ),
        ToolParameter(
            name="line_range",
            type="array",
            description="可选的行范围 [start, end]，用于只读取文件的特定部分",
            required=False,
            items={"type": "integer"}
        ),
    ]

    async def execute(self, file_path: str, line_range: Optional[list] = None) -> ToolResult:
        try:
            from app.services.rust_client import rust_client

            self.think(f"读取文件: {file_path}")
            if line_range:
                self.think(f"行范围: {line_range[0]}-{line_range[1]}")

            content = await rust_client.read_file(file_path)

            if not content:
                return ToolResult.error(f"文件为空或不存在: {file_path}", ToolErrorCode.NOT_FOUND)

            # 应用行范围
            if line_range and len(line_range) == 2:
                lines = content.split('\n')
                start, end = line_range
                start = max(1, start)
                end = min(len(lines), end)
                content = '\n'.join(lines[start-1:end])
                self.think(f"返回第 {start}-{end} 行，共 {end - start + 1} 行")

            return ToolResult.success(
                text=f"文件内容 ({file_path}):\n```\n{content[:5000]}\n```",
                data={
                    "file_path": file_path,
                    "line_count": len(content.split('\n')),
                    "size": len(content)
                }
            )

        except FileNotFoundError:
            return ToolResult.error(f"文件不存在: {file_path}", ToolErrorCode.NOT_FOUND)
        except Exception as e:
            self.log(f"读取文件失败: {str(e)}")
            return ToolResult.error(f"读取文件失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


class ListFilesTool(MCPTool):
    """
    列出目录文件工具

    列出指定目录下的所有文件和子目录
    """

    name = "list_files"
    description = """
列出目录下的所有文件和子目录。

**用途:**
- 探索项目结构
- 查找特定类型的文件
- 了解项目组织方式

**示例:**
```json
{"directory": "src/components"}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "找到 25 个文件"},
    {"type": "data", "data": {"files": ["file1.py", "file2.py"], "count": 25}}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="directory",
            type="string",
            description="目录路径，为空时使用项目根目录",
            required=False
        ),
        ToolParameter(
            name="pattern",
            type="string",
            description="可选的文件名模式过滤，如 '*.py' 只显示Python文件",
            required=False
        ),
    ]

    async def execute(self, directory: str = "", pattern: Optional[str] = None) -> ToolResult:
        try:
            from app.services.rust_client import rust_client

            # 使用项目路径作为默认
            if not directory:
                directory = self.context.get("project_path", ".")

            self.think(f"列出目录: {directory}")

            files = await rust_client.list_files(directory)

            if not files:
                return ToolResult.success(text=f"目录 {directory} 为空或不存在")

            # 应用模式过滤
            if pattern:
                import fnmatch
                filtered = [f for f in files if fnmatch.fnmatch(f, pattern)]
                files = filtered

            return ToolResult.success(
                text=f"目录 {directory} 中的文件 (共 {len(files)} 个):\n" + "\n".join(f"  - {f}" for f in files[:100]),
                data={
                    "directory": directory,
                    "files": files,
                    "count": len(files)
                }
            )

        except Exception as e:
            self.log(f"列出文件失败: {str(e)}")
            return ToolResult.error(f"列出文件失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


# ==================== AST 和代码分析工具 ====================

class GetASTContextTool(MCPTool):
    """
    获取AST上下文工具

    获取指定代码位置的抽象语法树上下文信息
    """

    name = "get_ast_context"
    description = """
获取指定位置的AST（抽象语法树）上下文信息。

**用途:**
- 了解代码的语法结构
- 获取函数、变量的定义和引用
- 分析调用关系和数据流

**示例:**
```json
{"file_path": "src/main.py", "line_number": 42}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "AST上下文信息..."},
    {"type": "json", "json": {
      "function": "main",
      "callers": ["func1", "func2"],
      "callees": ["helper", "utils"]
    }}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="file_path",
            type="string",
            description="文件路径",
            required=True
        ),
        ToolParameter(
            name="line_number",
            type="integer",
            description="目标行号",
            required=True
        ),
        ToolParameter(
            name="include_callers",
            type="boolean",
            description="是否包含调用者信息",
            required=False,
            default=True
        ),
        ToolParameter(
            name="include_callees",
            type="boolean",
            description="是否包含被调用者信息",
            required=False,
            default=True
        ),
    ]

    async def execute(
        self,
        file_path: str,
        line_number: int,
        include_callers: bool = True,
        include_callees: bool = True
    ) -> ToolResult:
        try:
            from app.services.rust_client import rust_client

            self.think(f"获取 {file_path}:{line_number} 的AST上下文")

            line_range = [line_number - 5, line_number + 5]
            ast_context = await rust_client.get_ast_context(
                file_path=file_path,
                line_range=line_range,
                include_callers=include_callers,
                include_callees=include_callees,
            )

            # 格式化上下文信息
            context_text = [f"AST上下文: {file_path}:{line_number}"]

            if "function" in ast_context:
                context_text.append(f"所属函数: {ast_context['function']}")

            if include_callers and "callers" in ast_context:
                callers = ast_context["callers"]
                if callers:
                    context_text.append(f"被以下位置调用 ({len(callers)}个):")
                    for caller in callers[:5]:
                        context_text.append(f"  - {caller}")

            if include_callees and "callees" in ast_context:
                callees = ast_context["callees"]
                if callees:
                    context_text.append(f"调用了以下函数 ({len(callees)}个):")
                    for callee in callees[:5]:
                        context_text.append(f"  - {callee}")

            return ToolResult.json(
                data=ast_context,
                description="\n".join(context_text)
            )

        except Exception as e:
            self.log(f"获取AST上下文失败: {str(e)}")
            return ToolResult.error(f"获取AST上下文失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


class GetCodeStructureTool(MCPTool):
    """
    获取代码结构工具

    获取文件中定义的所有类、方法、函数等结构信息
    """

    name = "get_code_structure"
    description = """
获取文件的代码结构，列出所有定义的符号。

**用途:**
- 快速了解文件的组织结构
- 查找类和方法的定义位置
- 分析代码的模块化程度

**示例:**
```json
{"file_path": "src/models/user.py"}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "代码结构..."},
    {"type": "data", "data": {
      "classes": ["User", "Admin"],
      "functions": ["validate", "save"],
      "symbols": [...]
    }}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="file_path",
            type="string",
            description="文件路径",
            required=True
        ),
    ]

    async def execute(self, file_path: str) -> ToolResult:
        try:
            from app.services.rust_client import rust_client

            self.think(f"获取文件结构: {file_path}")

            # 处理 project_id 类型转换
            project_id = self.context.get("project_id")
            if project_id is not None:
                try:
                    project_id = int(project_id)
                except (ValueError, TypeError):
                    project_id = None

            symbols = await rust_client.get_code_structure(
                file_path=file_path,
                project_id=project_id,
                project_path=self.context.get("project_path"),
            )

            if not symbols:
                return ToolResult.error(
                    f"文件 {file_path} 中未找到符号定义，可能文件未被索引",
                    ToolErrorCode.NOT_FOUND
                )

            # 按类型分组
            by_kind: Dict[str, list] = {}
            for s in symbols:
                kind = s.get("kind", "unknown")
                if kind not in by_kind:
                    by_kind[kind] = []
                by_kind[kind].append(s)

            # 构建结果
            result_data = {
                "file_path": file_path,
                "total_symbols": len(symbols),
                "by_kind": {k: len(v) for k, v in by_kind.items()},
                "symbols": symbols
            }

            # 格式化文本
            lines = [f"文件 {file_path} 的代码结构 (共 {len(symbols)} 个符号):"]
            for kind in ["Class", "Interface", "Struct", "Method", "Function", "Variable"]:
                if kind in by_kind:
                    lines.append(f"\n{kind} ({len(by_kind[kind])}):")
                    for s in by_kind[kind][:20]:  # 限制显示
                        lines.append(f"  - {s.get('name', 'unknown')} (行 {s.get('line', '?')})")

            return ToolResult.json(
                data=result_data,
                description="\n".join(lines)
            )

        except Exception as e:
            self.log(f"获取代码结构失败: {str(e)}")
            return ToolResult.error(f"获取代码结构失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


class SearchSymbolTool(MCPTool):
    """
    符号搜索工具

    在项目中搜索符号（函数、类、变量等）的定义
    """

    name = "search_symbol"
    description = """
在项目中搜索符号的定义位置。

**用途:**
- 查找函数或类的定义
- 定位变量声明位置
- 理解代码组织结构

**示例:**
```json
{"symbol_name": "authenticate"}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "找到 3 个匹配..."},
    {"type": "data", "data": {
      "matches": [
        {"name": "authenticate", "kind": "Function", "file": "...", "line": 42}
      ]
    }}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="symbol_name",
            type="string",
            description="要搜索的符号名称",
            required=True
        ),
    ]

    async def execute(self, symbol_name: str) -> ToolResult:
        try:
            from app.services.rust_client import rust_client

            self.think(f"搜索符号: {symbol_name}")

            # 处理 project_id 类型转换
            project_id = self.context.get("project_id")
            if project_id is not None:
                try:
                    project_id = int(project_id)
                except (ValueError, TypeError):
                    project_id = None

            results = await rust_client.search_symbol(
                symbol_name=symbol_name,
                project_id=project_id,
                project_path=self.context.get("project_path"),
            )

            if not results:
                return ToolResult.error(f"未找到符号: {symbol_name}", ToolErrorCode.NOT_FOUND)

            # 格式化结果
            matches = []
            for r in results:
                matches.append({
                    "name": r.get("name"),
                    "kind": r.get("kind"),
                    "file_path": r.get("file_path"),
                    "line": r.get("line")
                })

            text_lines = [f"找到 {len(results)} 个符号匹配 '{symbol_name}':"]
            for m in matches[:50]:
                text_lines.append(f"  - {m['name']} ({m['kind']}) 在 {m['file_path']}:{m['line']}")

            return ToolResult.json(
                data={"symbol_name": symbol_name, "matches": matches, "count": len(matches)},
                description="\n".join(text_lines)
            )

        except Exception as e:
            self.log(f"符号搜索失败: {str(e)}")
            return ToolResult.error(f"符号搜索失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


# ==================== 代码图谱工具 ====================

class GetCallGraphTool(MCPTool):
    """
    获取调用图工具

    获取函数的调用关系图，显示函数调用链
    """

    name = "get_call_graph"
    description = """
获取指定函数的调用图，展示函数调用关系链。

**用途:**
- 分析函数的调用链路
- 理解程序执行流程
- 识别潜在的递归调用
- 安全分析：追踪敏感函数的调用者

**示例:**
```json
{"entry_function": "main", "max_depth": 3}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "调用图信息..."},
    {"type": "data", "data": {
      "nodes": ["main", "parse", "execute"],
      "edges": [{"from": "main", "to": "parse"}]
    }}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="entry_function",
            type="string",
            description="入口函数名称",
            required=True
        ),
        ToolParameter(
            name="max_depth",
            type="integer",
            description="最大深度，控制调用链的展开层级",
            required=False,
            default=3
        ),
    ]

    async def execute(self, entry_function: str, max_depth: int = 3) -> ToolResult:
        try:
            from app.services.rust_client import rust_client

            self.think(f"获取函数 {entry_function} 的调用图（深度: {max_depth}）")

            # 处理 project_id 类型转换
            project_id = self.context.get("project_id")
            if project_id is not None:
                try:
                    project_id = int(project_id)
                except (ValueError, TypeError):
                    project_id = None

            graph = await rust_client.get_call_graph(
                entry_function=entry_function,
                max_depth=max_depth,
                project_id=project_id,
            )

            nodes = graph.get("nodes", [])
            edges = graph.get("edges", [])

            if not nodes:
                return ToolResult.error(
                    f"未找到函数 {entry_function} 的调用图，可能函数不存在或没有调用关系",
                    ToolErrorCode.NOT_FOUND
                )

            # 构建调用链描述
            lines = [
                f"调用图: {entry_function} (深度: {max_depth})",
                f"节点数: {len(nodes)}, 边数: {len(edges)}",
                "\n关键函数:"
            ]
            for node in nodes[:20]:
                lines.append(f"  - {node.get('id', node.get('name', 'unknown'))}")

            if edges:
                lines.append("\n调用关系:")
                for edge in edges[:30]:
                    lines.append(f"  {edge.get('from', '?')} -> {edge.get('to', '?')}")

            return ToolResult.json(
                data={
                    "entry_function": entry_function,
                    "max_depth": max_depth,
                    "nodes": nodes,
                    "edges": edges,
                    "node_count": len(nodes),
                    "edge_count": len(edges)
                },
                description="\n".join(lines)
            )

        except Exception as e:
            self.log(f"获取调用图失败: {str(e)}")
            return ToolResult.error(f"获取调用图失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


class GetKnowledgeGraphTool(MCPTool):
    """
    获取知识图谱工具

    获取代码知识图谱，展示类、函数、变量等实体及其关系
    """

    name = "get_knowledge_graph"
    description = """
获取代码知识图谱，展示代码实体及其关系。

**用途:**
- 理解代码整体架构
- 分析模块间的依赖关系
- 识别代码的设计模式
- 安全分析：发现可疑的依赖关系

**示例:**
```json
{"limit": 100}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "知识图谱统计..."},
    {"type": "data", "data": {
      "nodes": [...],
      "edges": [...],
      "statistics": {...}
    }}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="limit",
            type="integer",
            description="节点数量限制",
            required=False,
            default=100
        ),
    ]

    async def execute(self, limit: int = 100) -> ToolResult:
        try:
            from app.services.rust_client import rust_client

            self.think(f"获取代码知识图谱（限制: {limit} 个节点）")

            # 处理 project_id 类型转换
            project_id = self.context.get("project_id")
            if project_id is not None:
                try:
                    project_id = int(project_id)
                except (ValueError, TypeError):
                    project_id = None

            graph = await rust_client.get_knowledge_graph(
                limit=limit,
                project_id=project_id,
                project_path=self.context.get("project_path"),
            )

            nodes = graph.get("graph", {}).get("nodes", [])
            edges = graph.get("graph", {}).get("edges", [])

            if not nodes:
                return ToolResult.error(
                    "未找到代码知识图谱，请先构建 AST 索引",
                    ToolErrorCode.NOT_FOUND
                )

            # 统计节点类型
            type_counts: Dict[str, int] = {}
            for node in nodes:
                node_type = node.get("type", "unknown")
                type_counts[node_type] = type_counts.get(node_type, 0) + 1

            lines = [
                f"知识图谱统计 (共 {len(nodes)} 个节点, {len(edges)} 条边)",
                "\n节点类型分布:"
            ]
            for node_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  - {node_type}: {count}")

            lines.append("\n部分节点示例:")
            for node in nodes[:30]:
                lines.append(f"  - {node.get('label', node.get('id', 'unknown'))} ({node.get('type', 'unknown')})")

            return ToolResult.json(
                data={
                    "nodes": nodes,
                    "edges": edges,
                    "statistics": {
                        "node_count": len(nodes),
                        "edge_count": len(edges),
                        "type_distribution": type_counts
                    }
                },
                description="\n".join(lines)
            )

        except Exception as e:
            self.log(f"获取知识图谱失败: {str(e)}")
            return ToolResult.error(f"获取知识图谱失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


# ==================== RAG 工具 ====================

class SearchSimilarCodeTool(MCPTool):
    """
    相似代码搜索工具

    使用向量搜索查找与查询相似的代码片段
    """

    name = "search_similar_code"
    description = """
使用向量搜索查找与查询相似的代码片段（需要启用 RAG）。

**用途:**
- 查找相似的代码实现
- 代码复用和参考
- 发现潜在的代码重复
- 学习最佳实践

**前提条件:**
- 需要启用 ChromaDB 向量数据库
- 项目需要已建立向量索引

**示例:**
```json
{"query": "function that validates email input", "top_k": 5}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "找到 5 个相似代码片段..."},
    {"type": "data", "data": {
      "results": [
        {
          "text": "代码片段...",
          "file": "src/validate.py",
          "line_range": [10, 25],
          "similarity": 0.89
        }
      ]
    }}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="query",
            type="string",
            description="搜索查询，可以是代码片段或自然语言描述",
            required=True
        ),
        ToolParameter(
            name="top_k",
            type="integer",
            description="返回结果数量",
            required=False,
            default=5
        ),
    ]

    async def execute(self, query: str, top_k: int = 5) -> ToolResult:
        # 检查 RAG 是否启用
        use_rag = self.context.get("use_rag", True)
        if not use_rag:
            return ToolResult.error(
                "RAG 功能未启用，请在配置中设置 use_rag=true",
                ToolErrorCode.PERMISSION_DENIED
            )

        try:
            from app.services.vector_store import search_similar_code, check_vector_store

            # 检查向量数据库是否可用
            if not await check_vector_store():
                return ToolResult.error(
                    "向量数据库未连接，请先启动 ChromaDB 服务",
                    ToolErrorCode.INTERNAL_ERROR
                )

            self.think(f"搜索相似代码: {query[:50]}...")

            results = await search_similar_code(query=query, top_k=top_k)

            if not results:
                return ToolResult.success(text=f"未找到与查询相似的代码: {query[:100]}")

            # 格式化结果
            formatted_results = []
            lines = [f"找到 {len(results)} 个相似代码片段:"]
            for i, r in enumerate(results, 1):
                metadata = r.get("metadata", {})
                similarity = 1 - r.get("distance", 1)

                result_item = {
                    "rank": i,
                    "text": r.get("text", "")[:500],
                    "file": metadata.get("file", "unknown"),
                    "line_range": metadata.get("line_range", "unknown"),
                    "similarity": round(similarity, 3)
                }
                formatted_results.append(result_item)

                lines.append(
                    f"\n{i}. 文件: {result_item['file']}, "
                    f"行: {result_item['line_range']}, "
                    f"相似度: {result_item['similarity']}"
                )
                lines.append(f"   代码: {result_item['text']}")

            return ToolResult.json(
                data={"query": query, "count": len(results), "results": formatted_results},
                description="\n".join(lines)
            )

        except ImportError:
            return ToolResult.error(
                "RAG 功能未安装，请安装 chromadb: pip install chromadb",
                ToolErrorCode.INTERNAL_ERROR
            )
        except Exception as e:
            self.log(f"相似代码搜索失败: {str(e)}")
            return ToolResult.error(f"搜索失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


class SearchVulnerabilityPatternsTool(MCPTool):
    """
    漏洞模式搜索工具

    搜索与代码相关的漏洞模式和 CWE 信息
    """

    name = "search_vulnerability_patterns"
    description = """
搜索与代码相关的漏洞模式和 CWE 信息（需要启用 RAG）。

**用途:**
- 识别代码中可能存在的漏洞模式
- 获取漏洞的详细描述和修复建议
- 学习安全编码最佳实践
- 参考 CWE 分类标准

**前提条件:**
- 需要启用 ChromaDB 向量数据库
- 漏洞知识库需要已建立索引

**示例:**
```json
{"query": "SQL injection in user input", "top_k": 3}
```

**返回格式:**
```json
{
  "content": [
    {"type": "text", "text": "找到 3 个相关漏洞模式..."},
    {"type": "data", "data": {
      "results": [
        {
          "cwe_id": "CWE-89",
          "title": "SQL Injection",
          "description": "...",
          "similarity": 0.92
        }
      ]
    }}
  ]
}
```
    """

    parameters = [
        ToolParameter(
            name="query",
            type="string",
            description="搜索查询，可以是代码片段或漏洞描述",
            required=True
        ),
        ToolParameter(
            name="top_k",
            type="integer",
            description="返回结果数量",
            required=False,
            default=3
        ),
    ]

    async def execute(self, query: str, top_k: int = 3) -> ToolResult:
        # 检查 RAG 是否启用
        use_rag = self.context.get("use_rag", True)
        if not use_rag:
            return ToolResult.error(
                "RAG 功能未启用，请在配置中设置 use_rag=true",
                ToolErrorCode.PERMISSION_DENIED
            )

        try:
            from app.services.vector_store import search_vulnerability_patterns, check_vector_store

            # 检查向量数据库是否可用
            if not await check_vector_store():
                return ToolResult.error(
                    "向量数据库未连接，请先启动 ChromaDB 服务",
                    ToolErrorCode.INTERNAL_ERROR
                )

            self.think(f"搜索漏洞模式: {query[:50]}...")

            results = await search_vulnerability_patterns(query=query, top_k=top_k)

            if not results:
                return ToolResult.success(text=f"未找到相关的漏洞模式: {query[:100]}")

            # 格式化结果
            formatted_results = []
            lines = [f"找到 {len(results)} 个相关漏洞模式:"]
            for i, r in enumerate(results, 1):
                metadata = r.get("metadata", {})
                similarity = 1 - r.get("distance", 1)

                result_item = {
                    "rank": i,
                    "cwe_id": metadata.get("cwe_id", "unknown"),
                    "title": r.get("text", "").split('\n')[0][:100],
                    "description": r.get("text", "")[:500],
                    "similarity": round(similarity, 3)
                }
                formatted_results.append(result_item)

                lines.append(
                    f"\n{i}. CWE: {result_item['cwe_id']}, "
                    f"相似度: {result_item['similarity']}"
                )
                lines.append(f"   描述: {result_item['description']}")

            return ToolResult.json(
                data={"query": query, "count": len(results), "results": formatted_results},
                description="\n".join(lines)
            )

        except ImportError:
            return ToolResult.error(
                "RAG 功能未安装，请安装 chromadb: pip install chromadb",
                ToolErrorCode.INTERNAL_ERROR
            )
        except Exception as e:
            self.log(f"漏洞模式搜索失败: {str(e)}")
            return ToolResult.error(f"搜索失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


# ==================== 漏洞报告工具 ====================

class ReportFindingTool(MCPTool):
    """
    报告漏洞工具

    报告确认的安全漏洞
    """

    name = "report_finding"
    description = """
报告确认的安全漏洞，记录到审计结果中。

**用途:**
- 记录经过验证的真实漏洞
- 标记需要修复的安全问题
- 生成漏洞报告

**严重程度等级:**
- critical: 严重漏洞，需要立即修复
- high: 高危漏洞，应尽快修复
- medium: 中危漏洞，建议修复
- low: 低危漏洞，可选择性修复
- info: 信息性提示

**示例:**
```json
{
  "title": "SQL注入漏洞",
  "severity": "high",
  "file_path": "src/auth.py",
  "line_number": 42,
  "description": "用户输入未经过滤直接拼接SQL语句",
  "confidence": 0.95
}
```
    """

    parameters = [
        ToolParameter(
            name="title",
            type="string",
            description="漏洞标题",
            required=True
        ),
        ToolParameter(
            name="severity",
            type="string",
            description="严重程度: critical/high/medium/low/info",
            required=True,
            enum=["critical", "high", "medium", "low", "info"]
        ),
        ToolParameter(
            name="file_path",
            type="string",
            description="受影响的文件路径",
            required=True
        ),
        ToolParameter(
            name="line_number",
            type="integer",
            description="问题所在的行号",
            required=False
        ),
        ToolParameter(
            name="description",
            type="string",
            description="详细描述",
            required=False
        ),
        ToolParameter(
            name="confidence",
            type="number",
            description="置信度 (0-1)",
            required=False,
            default=0.7
        ),
        ToolParameter(
            name="cwe_id",
            type="string",
            description="CWE标识（如果有）",
            required=False
        ),
    ]

    async def execute(
        self,
        title: str,
        severity: str,
        file_path: str,
        line_number: Optional[int] = None,
        description: str = "",
        confidence: float = 0.7,
        cwe_id: Optional[str] = None
    ) -> ToolResult:
        try:
            findings = self.context.get("_confirmed_findings", [])

            finding = {
                "id": f"vuln_{len(findings)}",
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "file_path": file_path,
                "line_number": line_number,
                "description": description,
                "agent_found": "analysis",
            }

            if cwe_id:
                finding["cwe_id"] = cwe_id

            findings.append(finding)
            self.context["_confirmed_findings"] = findings

            self.think(f"记录漏洞: {title} ({severity})")

            return ToolResult.success(
                text=f"已记录漏洞: {title}",
                data={"finding": finding, "total": len(findings)}
            )

        except Exception as e:
            self.log(f"记录漏洞失败: {str(e)}")
            return ToolResult.error(f"记录漏洞失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


class MarkFalsePositiveTool(MCPTool):
    """
    标记误报工具

    将扫描结果标记为误报
    """

    name = "mark_false_positive"
    description = """
将扫描结果标记为误报，排除在最终报告之外。

**用途:**
- 排除不准确的扫描结果
- 记录误报原因
- 提高报告质量

**示例:**
```json
{
  "finding_id": "scan_123",
  "reason": "该函数使用了参数化查询，不存在SQL注入风险"
}
```
    """

    parameters = [
        ToolParameter(
            name="finding_id",
            type="string",
            description="发现ID",
            required=True
        ),
        ToolParameter(
            name="reason",
            type="string",
            description="误报原因",
            required=True
        ),
    ]

    async def execute(self, finding_id: str, reason: str) -> ToolResult:
        try:
            false_positives = self.context.get("_false_positives", [])
            false_positives.append(f"{finding_id}: {reason}")
            self.context["_false_positives"] = false_positives

            self.think(f"标记误报: {finding_id}")

            return ToolResult.success(
                text=f"已标记误报: {finding_id}",
                data={
                    "finding_id": finding_id,
                    "reason": reason,
                    "total_false_positives": len(false_positives)
                }
            )

        except Exception as e:
            self.log(f"标记误报失败: {str(e)}")
            return ToolResult.error(f"标记误报失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


class FinishAnalysisTool(MCPTool):
    """
    完成分析工具

    标记分析任务完成，生成总结
    """

    name = "finish_analysis"
    description = """
完成分析任务，生成分析总结。

**用途:**
- 标记分析任务完成
- 提供分析总结
- 触发后续流程

**示例:**
```json
{
  "summary": "共分析了50个扫描结果，确认5个高危漏洞，3个误报"
}
```
    """

    parameters = [
        ToolParameter(
            name="summary",
            type="string",
            description="分析总结",
            required=True
        ),
        ToolParameter(
            name="recommendations",
            type="array",
            description="修复建议列表",
            required=False,
            items={"type": "string"}
        ),
    ]

    async def execute(self, summary: str, recommendations: Optional[list] = None) -> ToolResult:
        try:
            findings = self.context.get("_confirmed_findings", [])
            false_positives = self.context.get("_false_positives", [])

            self.context["_analysis_summary"] = summary
            if recommendations:
                self.context["_recommendations"] = recommendations

            self.think(f"分析完成: {summary}")

            result_data = {
                "summary": summary,
                "confirmed_findings": len(findings),
                "false_positives": len(false_positives),
            }

            if recommendations:
                result_data["recommendations"] = recommendations

            return ToolResult.success(
                text=f"分析完成指令已接收\n{summary}",
                data=result_data
            )

        except Exception as e:
            self.log(f"完成分析失败: {str(e)}")
            return ToolResult.error(f"完成分析失败: {str(e)}", ToolErrorCode.INTERNAL_ERROR)


# ==================== 注册所有工具 ====================

def register_all_tools():
    """注册所有MCP工具到全局注册表"""
    tools = [
        ReadFileTool,
        ListFilesTool,
        GetASTContextTool,
        GetCodeStructureTool,
        SearchSymbolTool,
        GetCallGraphTool,
        GetKnowledgeGraphTool,
        SearchSimilarCodeTool,
        SearchVulnerabilityPatternsTool,
        ReportFindingTool,
        MarkFalsePositiveTool,
        FinishAnalysisTool,
    ]

    for tool_class in tools:
        register_tool(tool_class)

    return len(tools)


# 自动注册
if __name__ != "__main__":
    register_all_tools()
