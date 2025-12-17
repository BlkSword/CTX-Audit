# DeepAudit Nexus

支持 MCP 协议的高级大语言模型（LLM）代码审计工具。

## 架构

- **前端**：React + TypeScript + Vite + Tauri  
- **后端**：Rust（Tauri 主机）  
- **Sidecar 服务**：Python（LangGraph + MCP）

## 前置依赖

- Node.js  
- Rust（含 Cargo）  
- Python 3.8 或更高版本  
- Tauri CLI（推荐通过 `npm install -g @tauri-apps/cli` 全局安装）

## 安装步骤

1. 安装前端依赖：
   ```bash
   npm install
   ```

2. 安装 Python 依赖：
   ```bash
   pip install -r python-sidecar/requirements.txt
   ```

## 开发模式运行

```bash
npm run tauri dev
```

## 使用方法

1. 点击 “Open Project Folder”（打开项目文件夹）。  
2. 选择要审计的代码目录。  
3. 查看日志，Python Agent 将通过 MCP 协议分析代码。

## MCP 工具

DeepAudit 运行一个 Python MCP Sidecar 服务（`python-sidecar/agent.py`），并通过标准输入/输出（stdio）以 JSON-RPC 方式从 Tauri 主机调用工具。

可用工具（由 `list_mcp_tools` 返回）：

- `analyze_project(directory: string)`  
- `get_analysis_report(directory: string)`  
- `find_call_sites(directory: string, symbol: string)`  
- `get_call_graph(directory: string, entry: string, max_depth?: number)`  
- `read_file(file_path: string)`  
- `list_files(directory: string)`  
- `search_files(directory: string, pattern: string)`  
- `get_code_structure(file_path: string)`  
- `search_symbol(query: string)`  
- `get_class_hierarchy(class_name: string)`

### 调用点（Call Sites）

`find_call_sites` 返回所有 AST 索引中 `callee == symbol` 的调用点。

示例参数：

```json
{ "directory": "/path/to/repo", "symbol": "exec" }
```

响应格式：

```json
{ "status": "success", "symbol": "exec", "count": 3, "results": [ /* 符号列表 */ ] }
```

每个结果均为 `kind == "method_call"` 的符号，可能包含以下元数据字段：
- Java：`metadata.callerClass`、`metadata.callerMethod`
- Python/JS/TS/Rust/Go：`metadata.callerFunction`

### 调用图（Call Graph）

`get_call_graph` 从指定入口 `entry` 开始构建深度受限的调用图。

注意：当前 `entry` 匹配的是调用点元数据中记录的 *调用方法/函数名称*（而非完整限定名）。

示例参数：

```json
{ "directory": "/path/to/repo", "entry": "handleRequest", "max_depth": 2 }
```

响应格式：

```json
{
  "status": "success",
  "graph": {
    "entry": "handleRequest",
    "nodes": [{ "id": "handleRequest", "label": "handleRequest" }],
    "edges": [{ "from": "handleRequest", "to": "validate", "file": "...", "line": 42 }]
  }
}
```

## 缓存机制

Python Sidecar 服务会为每个代码仓库缓存 AST 和分析报告，存储在 `.deepaudit_cache/` 目录下：

- AST 索引：`.deepaudit_cache/<repo_hash>/ast_index.pkl`  
- 分析报告缓存：`.deepaudit_cache/<repo_hash>/analysis_report.json`