# -*- coding: utf-8 -*-
"""
Analysis Agent - 分析师

负责深度代码分析、漏洞挖掘和误报过滤
"""
from typing import Dict, Any, List
from loguru import logger

from app.agents.base import BaseAgent


class AnalysisAgent(BaseAgent):
    """
    Analysis Agent

    职责：
    1. 深度代码分析（结合 AST）
    2. 业务逻辑漏洞检测
    3. 跨文件调用链分析
    4. RAG 辅助分析
    5. 降低规则扫描的误报率
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="analysis", config=config)
        self.use_rag = config.get("use_rag", True) if config else True

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行分析任务

        Args:
            context: 上下文，包含:
                - audit_id: 审计 ID
                - project_id: 项目 ID
                - scan_results: 规则扫描结果
                - recon_result: 侦察结果
                - target_types: 目标漏洞类型（可选）

        Returns:
            分析结果
        """
        audit_id = context.get("audit_id")
        scan_results = context.get("scan_results", [])
        recon_result = context.get("recon_result", {})

        self.think(f"开始深度分析，共 {len(scan_results)} 个扫描结果")

        vulnerabilities = []

        for i, finding in enumerate(scan_results):
            self.think(f"分析 [{i+1}/{len(scan_results)}]: {finding.get('title', 'Unknown')}")

            # 分析单个发现
            analyzed = await self._analyze_finding(
                finding=finding,
                recon_result=recon_result,
            )

            if analyzed:
                vulnerabilities.append(analyzed)

        # 统计结果
        self.think(f"分析完成，发现 {len(vulnerabilities)} 个有效漏洞")

        return {
            "vulnerabilities": vulnerabilities,
            "stats": {
                "total_analyzed": len(scan_results),
                "confirmed": len(vulnerabilities),
                "false_positives": len(scan_results) - len(vulnerabilities),
            }
        }

    async def _analyze_finding(
        self,
        finding: Dict[str, Any],
        recon_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        分析单个漏洞发现

        Args:
            finding: 规则扫描结果
            recon_result: 侦察结果

        Returns:
            分析后的漏洞信息（如果判定为误报则返回 None）
        """
        file_path = finding.get("file_path")
        line_number = finding.get("line_number")

        # 1. 获取 AST 上下文
        try:
            ast_context = await self.get_ast_context(
                file_path=file_path,
                line_range=[line_number - 5, line_number + 5],
            )
            self.think(f"获取 AST 上下文成功")
        except Exception as e:
            logger.warning(f"获取 AST 上下文失败: {e}")
            ast_context = {}

        # 2. RAG 检索相关漏洞知识
        rag_context = []
        if self.use_rag:
            try:
                code_snippet = finding.get("code_snippet", "")
                description = finding.get("description", "")

                # 搜索相似代码
                similar_code = await self.search_similar_code(
                    query=f"{code_snippet} {description}",
                    top_k=3,
                )

                # 搜索漏洞模式
                vuln_patterns = await self.search_vulnerability_patterns(
                    query=description,
                    top_k=3,
                )

                rag_context = similar_code + vuln_patterns
                self.think(f"RAG 检索到 {len(rag_context)} 条相关上下文")

            except Exception as e:
                logger.warning(f"RAG 检索失败: {e}")

        # 3. 构建分析提示词
        analysis_prompt = self._build_analysis_prompt(
            finding=finding,
            ast_context=ast_context,
            rag_context=rag_context,
        )

        # 4. 调用 LLM 进行分析
        system_prompt = self._get_system_prompt()
        llm_response = await self.call_llm(
            prompt=analysis_prompt,
            system_prompt=system_prompt,
        )

        # 5. 解析 LLM 响应
        parsed_result = self._parse_llm_response(llm_response)

        # 6. 判断是否为真实漏洞
        if parsed_result.get("is_vulnerability", False):
            self.think(f"确认为真实漏洞: {finding.get('title')}")
            return self._format_vulnerability(
                finding=finding,
                analysis=parsed_result,
            )
        else:
            self.think(f"判定为误报: {finding.get('title')}")
            return None

    async def get_ast_context(self, file_path: str, line_range: List[int]) -> Dict[str, Any]:
        """获取 AST 上下文"""
        from app.services.rust_client import rust_client
        return await rust_client.get_ast_context(file_path, line_range)

    def _build_analysis_prompt(
        self,
        finding: Dict[str, Any],
        ast_context: Dict[str, Any],
        rag_context: List[Dict[str, Any]],
    ) -> str:
        """构建分析提示词"""
        prompt_parts = [
            "请分析以下代码是否存在安全漏洞：\n\n",
            f"文件: {finding.get('file_path')}:{finding.get('line_number')}\n",
            f"代码:\n```\n{finding.get('code_snippet', '')}\n```\n",
            f"\n规则扫描结果: {finding.get('description', '')}\n",
        ]

        # 添加 AST 上下文
        if ast_context:
            prompt_parts.append("\n代码上下文:\n")
            context = ast_context.get("context", {})
            if context.get("callers"):
                prompt_parts.append(f"被调用: {context['callers']}\n")
            if context.get("callees"):
                prompt_parts.append(f"调用: {context['callees']}\n")

        # 添加 RAG 上下文
        if rag_context:
            prompt_parts.append("\n参考信息:\n")
            for ctx in rag_context[:2]:
                prompt_parts.append(f"- {ctx['text'][:200]}...\n")

        # 使用三引号字符串避免转义问题
        json_example = '''
{
  "is_vulnerability": true/false,
  "reasoning": "分析理由",
  "severity": "critical/high/medium/low/info",
  "confidence": 0.0-1.0,
  "exploit_condition": "利用条件",
  "remediation": "修复建议"
}
'''
        prompt_parts.extend([
            "\n请分析并返回 JSON 格式：\n",
            json_example,
        ])

        return "".join(prompt_parts)

    def _get_system_prompt(self) -> str:
        """获取系统提示词"""
        return """You are a senior security audit expert specializing in code vulnerability analysis.

Your task:
1. Analyze whether the code has real security vulnerabilities
2. Determine if rule scan results are false positives
3. Determine severity and confidence
4. Provide exploit conditions and remediation

Please analyze based on these principles:
- Conservative: Don't confirm uncertain vulnerabilities
- Context matters: Consider actual runtime environment
- Exploitability: Focus on whether attackers can actually exploit

Return format must be JSON."""

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析 LLM 响应"""
        import json
        import re

        # 尝试提取 JSON
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        # 解析失败返回默认值
        return {
            "is_vulnerability": False,
            "reasoning": "Parse failed",
            "severity": "low",
            "confidence": 0.0,
        }

    def _format_vulnerability(
        self,
        finding: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """格式化漏洞信息"""
        return {
            "id": f"vuln_{finding.get('id', 'unknown')}",
            "vulnerability_type": finding.get("type", "unknown"),
            "severity": analysis.get("severity", "medium"),
            "confidence": analysis.get("confidence", 0.5),
            "title": finding.get("title", "Unknown Vulnerability"),
            "description": analysis.get("reasoning", finding.get("description", "")),
            "file_path": finding.get("file_path", ""),
            "line_number": finding.get("line_number", 0),
            "code_snippet": finding.get("code_snippet", ""),
            "remediation": analysis.get("remediation", "Please fix this vulnerability"),
            "exploit_condition": analysis.get("exploit_condition", ""),
            "agent_found": "analysis",
            "verified": False,
        }


# 创建全局实例
analysis_agent = AnalysisAgent()
