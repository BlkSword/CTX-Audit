import sys
import logging
import asyncio
import uvicorn
from typing import Dict, Any, List
from mcp.server.fastmcp import FastMCP, Context
from starlette.middleware.cors import CORSMiddleware

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("deep-audit-agent")

# Initialize FastMCP Server
mcp = FastMCP("DeepAudit Agent")

# Mock LangGraph for now (to be expanded)
# In a real implementation, this would define a StateGraph
async def run_analysis_workflow(path: str, ctx: Context = None):
    if ctx:
        await ctx.info(f"Starting analysis workflow for: {path}")
        await ctx.report_progress(10, 100, "Initializing workflow")
    
    await asyncio.sleep(1)
    if ctx:
        await ctx.info("Scanning files...")
        await ctx.report_progress(30, 100, "Scanning files")
    
    await asyncio.sleep(1)
    if ctx:
        await ctx.info("Building AST...")
        await ctx.report_progress(60, 100, "Building AST")
    
    await asyncio.sleep(1)
    if ctx:
        await ctx.info("Detecting vulnerabilities...")
        await ctx.report_progress(90, 100, "Running detectors")
    
    # Mock results
    results = [
        {"file": f"{path}/src/main.rs", "line": 42, "severity": "high", "message": "Potential SQL Injection detected"},
        {"file": f"{path}/src/utils.py", "line": 10, "severity": "medium", "message": "Hardcoded credential found"}
    ]
    
    return results

@mcp.tool()
async def analyze_project(path: str, ctx: Context) -> str:
    """
    Analyze a project directory for security vulnerabilities using DeepAudit AI Agent.
    """
    try:
        results = await run_analysis_workflow(path, ctx)
        
        # Format results
        report = f"Analysis Report for {path}:\n\n"
        for issue in results:
            report += f"- [{issue['severity'].upper()}] {issue['file']}:{issue['line']} - {issue['message']}\n"
        
        if not results:
            report += "No vulnerabilities found."
            
        return report
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return f"Error during analysis: {str(e)}"

@mcp.tool()
async def explain_vulnerability(vulnerability_id: str, code_snippet: str) -> str:
    """
    Explain a specific vulnerability and suggest remediation.
    """
    # Mock explanation
    return f"The vulnerability '{vulnerability_id}' in the code:\n\n`{code_snippet}`\n\nIs dangerous because..."

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
    logger.info("Starting DeepAudit Agent on SSE (http://127.0.0.1:8765/sse)")
    uvicorn.run(app, host="127.0.0.1", port=8765)
