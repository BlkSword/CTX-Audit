"""
Analysis Agent - LLM 驱动的深度分析者

负责深度代码分析、漏洞挖掘和误报过滤
"""
from typing import Dict, Any, List, Optional
from loguru import logger
import json

from app.agents.base import BaseAgent
from app.services.llm import LLMService, LLMMessage, LLMProvider
from app.core.task_handoff import TaskHandoff, TaskHandoffBuilder
from app.services.prompt_builder import prompt_builder


class AnalysisAgent(BaseAgent):
    """
    LLM 驱动的 Analysis Agent

    核心特性：
    1. LLM 自主决定分析策略
    2. 通过工具调用获取代码上下文
    3. 集成 RAG 向量检索
    4. 使用 TaskHandoff 协议传递结果
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="analysis", config=config)

        # LLM 服务
        llm_config = config or {}
        self.llm = LLMService(
            provider=LLMProvider(llm_config.get("llm_provider", "anthropic")),
            model=llm_config.get("llm_model", "claude-3-5-sonnet-20241022"),
            api_key=llm_config.get("api_key"),
            base_url=llm_config.get("base_url"),
        )

        # 配置
        self.use_rag = config.get("use_rag", True) if config else True
        self.max_iterations = config.get("max_iterations", 15)
        self.max_findings_to_analyze = config.get("max_findings_to_analyze", 50)

        # 对话历史
        self._conversation: List[Dict[str, Any]] = []

        # 分析结果
        self._confirmed_findings: List[Dict[str, Any]] = []
        self._false_positives: List[str] = []

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行 LLM 驱动的深度分析

        Args:
            context: 上下文信息
                - audit_id: 审计 ID
                - project_id: 项目 ID
                - scan_results: 规则扫描结果
                - recon_result: 侦察结果
                - task_handoff: 上游任务交接（可选）

        Returns:
            分析结果 + 任务交接
        """
        audit_id = context.get("audit_id")
        scan_results = context.get("scan_results", [])
        recon_result = context.get("recon_result", {})

        self.think(f"开始 LLM 驱动分析，共 {len(scan_results)} 个扫描结果")

        # 接收任务交接（如果有）
        handoff = context.get("task_handoff")
        if handoff:
            self.think(f"收到上游任务交接: {handoff.get('from_agent')}")

        # 限制分析数量
        if len(scan_results) > self.max_findings_to_analyze:
            self.think(f"扫描结果过多，仅分析前 {self.max_findings_to_analyze} 个高危问题")
            # 优先分析高危问题
            scan_results = self._prioritize_findings(scan_results)[:self.max_findings_to_analyze]

        # 1. 构建初始上下文
        analysis_context = await self._build_initial_context(context)

        # 2. 构建动态提示词
        system_prompt = await self._build_system_prompt(analysis_context)
        initial_message = self._format_initial_message(analysis_context)

        # 3. 初始化对话历史
        self._conversation = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_message},
        ]

        # 4. LLM 分析循环
        for iteration in range(self.max_iterations):
            self.think(f"LLM 分析循环 #{iteration + 1}")

            # 发布状态事件
            await self._publish_event("analysis_progress", {
                "message": f"LLM 正在分析 (迭代 {iteration + 1}/{self.max_iterations})...",
                "iteration": iteration + 1,
                "findings_confirmed": len(self._confirmed_findings),
            })

            try:
                # 调用 LLM 进行决策
                llm_response = await self.llm.generate_with_tools(
                    messages=self._conversation,
                    tools=self._get_available_tools(),
                )
            except Exception as e:
                logger.error(f"LLM 调用失败: {e}")
                break

            # 添加 LLM 响应到对话历史
            self._conversation.append({
                "role": "assistant",
                "content": llm_response.get("content", ""),
            })
            if llm_response.get("tool_calls"):
                self._conversation.append({"tool_calls": llm_response["tool_calls"]})

            # 解析工具调用
            tool_calls = llm_response.get("tool_calls", [])

            if not tool_calls:
                # LLM 决定完成分析
                self.think("LLM 决定完成分析")
                break

            # 执行工具调用
            observations = []
            for tool_call in tool_calls:
                observation = await self._execute_tool(tool_call, analysis_context)
                observations.append(observation)

            # 添加观察结果
            self._conversation.append({
                "role": "user",
                "content": "\n\n".join(observations),
            })

        # 5. 创建任务交接（给 Verification Agent）
        next_handoff = self._create_task_handoff(context)

        self.think(f"分析完成，确认 {len(self._confirmed_findings)} 个漏洞")

        return {
            "status": "success",
            "findings": self._confirmed_findings,
            "task_handoff": next_handoff.to_dict() if next_handoff else None,
            "stats": {
                "total_analyzed": len(scan_results),
                "confirmed": len(self._confirmed_findings),
                "false_positives": len(self._false_positives),
                "iterations": iteration + 1,
            },
        }

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        """获取分析工具列表"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "读取文件内容，获取完整的代码上下文",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "文件路径",
                            },
                            "line_range": {
                                "type": "array",
                                "items": {"type": "integer"},
                                "description": "行号范围 [start, end]，可选",
                            },
                        },
                        "required": ["file_path"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_ast_context",
                    "description": "获取 AST 上下文，包括函数调用关系、数据流等",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                            },
                            "line_number": {
                                "type": "integer",
                            },
                        },
                        "required": ["file_path", "line_number"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_similar_code",
                    "description": "在向量库中搜索相似的代码模式，辅助判断是否为漏洞",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code_snippet": {
                                "type": "string",
                            },
                            "top_k": {
                                "type": "integer",
                                "description": "返回结果数量，默认 3",
                            },
                        },
                        "required": ["code_snippet"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_vulnerability_patterns",
                    "description": "搜索已知漏洞模式，参考 CWE/CVE 数据库",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "漏洞描述或关键词",
                            },
                            "top_k": {
                                "type": "integer",
                            },
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "report_finding",
                    "description": "报告一个确认的漏洞发现",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "severity": {"type": "string"},
                            "file_path": {"type": "string"},
                            "line_number": {"type": "integer"},
                            "code_snippet": {"type": "string"},
                            "description": {"type": "string"},
                            "confidence": {"type": "number"},
                            "exploit_condition": {"type": "string"},
                            "remediation": {"type": "string"},
                        },
                        "required": ["title", "severity", "file_path", "line_number"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "mark_false_positive",
                    "description": "标记扫描结果为误报",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "finding_id": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                        "required": ["finding_id", "reason"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finish_analysis",
                    "description": "完成分析，生成最终报告",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"},
                        },
                    },
                },
            },
        ]

    async def _execute_tool(
        self,
        tool_call: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """执行工具调用"""
        function = tool_call.get("function", {})
        tool_name = function.get("name")
        arguments = function.get("arguments", {})

        # 如果 arguments 是字符串，尝试解析 JSON
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                pass

        self.think(f"执行工具: {tool_name}")

        try:
            if tool_name == "read_file":
                return await self._tool_read_file(arguments, context)

            elif tool_name == "get_ast_context":
                return await self._tool_get_ast_context(arguments, context)

            elif tool_name == "search_similar_code":
                return await self._tool_search_similar_code(arguments, context)

            elif tool_name == "search_vulnerability_patterns":
                return await self._tool_search_vulnerability_patterns(arguments, context)

            elif tool_name == "report_finding":
                return await self._tool_report_finding(arguments, context)

            elif tool_name == "mark_false_positive":
                return await self._tool_mark_false_positive(arguments, context)

            elif tool_name == "finish_analysis":
                return await self._tool_finish_analysis(arguments, context)

            else:
                return f"未知工具: {tool_name}"

        except Exception as e:
            error_msg = f"工具执行失败 ({tool_name}): {str(e)}"
            logger.error(error_msg)
            return error_msg

    # ==================== 工具实现 ====================

    async def _tool_read_file(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """读取文件内容"""
        file_path = arguments["file_path"]
        line_range = arguments.get("line_range")

        try:
            from app.services.rust_client import rust_client
            content = await rust_client.read_file(file_path)

            if line_range and len(line_range) == 2:
                lines = content.split('\n')
                start, end = line_range
                content = '\n'.join(lines[start-1:end])

            return f"""
文件内容 ({file_path}):
```text
{content[:2000]}  # 限制长度
{'...' if len(content) > 2000 else ''}
```
"""
        except Exception as e:
            return f"读取文件失败: {str(e)}"

    async def _tool_get_ast_context(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """获取 AST 上下文"""
        file_path = arguments["file_path"]
        line_number = arguments["line_number"]

        try:
            from app.services.rust_client import rust_client
            ast_context = await rust_client.get_ast_context(
                file_path,
                [line_number - 5, line_number + 5],
            )

            callers = ast_context.get("context", {}).get("callers", [])
            callees = ast_context.get("context", {}).get("callees", [])
            variables = ast_context.get("context", {}).get("variables", [])

            parts = [
                f"**AST 上下文** ({file_path}:{line_number})",
                "",
            ]

            if callers:
                parts.append(f"**被调用处** ({len(callers)} 处):")
                for caller in callers[:3]:
                    parts.append(f"  - {caller.get('file')}:{caller.get('line')}")
                parts.append("")

            if callees:
                parts.append(f"**调用函数** ({len(callees)} 个):")
                for callee in callees[:5]:
                    parts.append(f"  - {callee.get('name', 'unknown')}")
                parts.append("")

            if variables:
                parts.append(f"**相关变量** ({len(variables)} 个):")
                for var in variables[:5]:
                    parts.append(f"  - {var.get('name', 'unknown')}: {var.get('type', 'unknown')}")
                parts.append("")

            return "\n".join(parts)

        except Exception as e:
            return f"获取 AST 上下文失败: {str(e)}"

    async def _tool_search_similar_code(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """搜索相似代码"""
        code_snippet = arguments["code_snippet"]
        top_k = arguments.get("top_k", 3)

        if not self.use_rag:
            return "RAG 功能未启用"

        try:
            similar = await self.search_similar_code(
                query=code_snippet,
                top_k=top_k,
            )

            if not similar:
                return "未找到相似代码"

            parts = [f"**相似代码** (找到 {len(similar)} 条):", ""]
            for i, item in enumerate(similar, 1):
                parts.append(f"{i}. {item.get('text', '')[:200]}...")

            return "\n".join(parts)

        except Exception as e:
            return f"搜索失败: {str(e)}"

    async def _tool_search_vulnerability_patterns(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """搜索漏洞模式"""
        query = arguments["query"]
        top_k = arguments.get("top_k", 3)

        if not self.use_rag:
            return "RAG 功能未启用"

        try:
            patterns = await self.search_vulnerability_patterns(
                query=query,
                top_k=top_k,
            )

            if not patterns:
                return "未找到相关漏洞模式"

            parts = [f"**漏洞模式** (找到 {len(patterns)} 条):", ""]
            for i, item in enumerate(patterns, 1):
                parts.append(f"{i}. {item.get('text', '')[:200]}...")

            return "\n".join(parts)

        except Exception as e:
            return f"搜索失败: {str(e)}"

    async def _tool_report_finding(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """报告漏洞发现"""
        finding = {
            "id": f"vuln_{len(self._confirmed_findings)}",
            "vulnerability_type": context.get("current_finding", {}).get("type", "unknown"),
            "title": arguments.get("title"),
            "severity": arguments.get("severity", "medium"),
            "confidence": arguments.get("confidence", 0.7),
            "file_path": arguments.get("file_path"),
            "line_number": arguments.get("line_number"),
            "code_snippet": arguments.get("code_snippet"),
            "description": arguments.get("description"),
            "exploit_condition": arguments.get("exploit_condition"),
            "remediation": arguments.get("remediation"),
            "agent_found": "analysis",
            "verified": False,
        }

        self._confirmed_findings.append(finding)

        return f"""
已报告漏洞: **{finding['title']}**

- 严重性: {finding['severity']}
- 位置: {finding['file_path']}:{finding['line_number']}
- 置信度: {finding['confidence']:.2f}
- 描述: {finding.get('description', 'N/A')[:100]}...
"""

    async def _tool_mark_false_positive(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """标记误报"""
        finding_id = arguments.get("finding_id", "unknown")
        reason = arguments.get("reason", "")

        self._false_positives.append(f"{finding_id}: {reason}")

        return f"已标记为误报: {finding_id}\n原因: {reason}"

    async def _tool_finish_analysis(
        self,
        arguments: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str:
        """完成分析"""
        summary = arguments.get("summary", "分析完成")

        confirmed = len(self._confirmed_findings)
        false_positives = len(self._false_positives)

        return f"""
{summary}

**统计**:
- 确认漏洞: {confirmed} 个
- 误报: {false_positives} 个
- 总迭代: {len([m for m in self._conversation if m.get('role') == 'user']) - 1} 次
"""

    # ==================== 辅助方法 ====================

    async def _build_initial_context(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """构建初始上下文"""
        scan_results = input_data.get("scan_results", [])
        recon_result = input_data.get("recon_result", {})

        # 提取技术栈
        tech_stack = recon_result.get("tech_stack", [])

        # 提取漏洞类型
        vuln_types = list(set([
            r.get("type", r.get("vulnerability_type", "unknown"))
            for r in scan_results
        ]))

        return {
            "audit_id": input_data.get("audit_id"),
            "project_id": input_data.get("project_id"),
            "scan_results": scan_results,
            "recon_result": recon_result,
            "tech_stack": tech_stack,
            "vulnerability_types": vuln_types,
        }

    async def _build_system_prompt(self, context: Dict[str, Any]) -> str:
        """构建系统提示词"""
        return await prompt_builder.build_analysis_prompt(context)

    def _format_initial_message(self, context: Dict[str, Any]) -> str:
        """格式化初始消息"""
        scan_results = context["scan_results"]
        tech_stack = context.get("tech_stack", [])

        parts = [
            f"请对以下项目的扫描结果进行深度安全分析：\n",
            f"**项目 ID**: {context['project_id']}",
            f"**技术栈**: {', '.join(tech_stack) if tech_stack else '未知'}",
            f"**扫描结果数**: {len(scan_results)}",
            "",
        ]

        # 添加扫描结果摘要
        if scan_results:
            severity_count = {}
            for r in scan_results:
                sev = r.get("severity", "info").lower()
                severity_count[sev] = severity_count.get(sev, 0) + 1

            parts.append("**严重程度分布**:")
            for sev, count in sorted(severity_count.items()):
                parts.append(f"- {sev}: {count}")
            parts.append("")

            parts.append("**前 10 个问题**:")
            for i, r in enumerate(scan_results[:10], 1):
                title = r.get("title", "Untitled")
                sev = r.get("severity", "?")
                location = r.get("file_path", "?")
                parts.append(f"{i}. **{title}** ({sev})")
                parts.append(f"   - 位置: {location}")
                parts.append(f"   - ID: {r.get('id', i)}")

        parts.append("\n" + "="*50)
        parts.append("\n请使用工具分析这些问题。")
        parts.append("\n**工作流程**:")
        parts.append("1. 使用 `get_ast_context` 获取代码上下文")
        parts.append("2. 使用 `search_similar_code` 搜索相似模式")
        parts.append("3. 使用 `search_vulnerability_patterns` 查找漏洞模式")
        parts.append("4. 对于确认的漏洞，使用 `report_finding` 报告")
        parts.append("5. 对于误报，使用 `mark_false_positive` 标记")
        parts.append("6. 完成后，使用 `finish_analysis` 结束")
        parts.append("\n**重要**: 只分析高置信度的问题，重点关注 critical/high 级别。")

        return "\n".join(parts)

    def _prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """优先级排序扫描结果"""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        return sorted(
            findings,
            key=lambda f: (
                severity_order.get(f.get("severity", "info").lower(), 5),
                f.get("rule_id", "")
            )
        )

    def _create_task_handoff(self, context: Dict[str, Any]) -> Optional[TaskHandoff]:
        """创建任务交接"""
        if not self._confirmed_findings:
            return None

        # 提取关键发现
        key_findings = [
            f for f in self._confirmed_findings
            if f.get("severity") in ["critical", "high"]
        ][:10]

        # 提取洞察
        insights = [
            f"共分析 {len(context['scan_results'])} 个扫描结果",
            f"确认 {len(self._confirmed_findings)} 个真实漏洞",
            f"标记 {len(self._false_positives)} 个误报",
        ]

        # 关注点
        attention_points = []
        critical_count = len([f for f in self._confirmed_findings if f.get("severity") == "critical"])
        if critical_count > 0:
            attention_points.append(f"{critical_count} 个严重漏洞需要立即处理")

        high_count = len([f for f in self._confirmed_findings if f.get("severity") == "high"])
        if high_count > 0:
            attention_points.append(f"{high_count} 个高危漏洞")

        return TaskHandoffBuilder(
            from_agent="analysis",
            to_agent="verification",
        ).summary(f"Analysis Agent 完成，发现 {len(self._confirmed_findings)} 个潜在漏洞") \
         .add_work(f"分析了 {len(context['scan_results'])} 个扫描结果") \
         .add_work(f"应用了 {len(context.get('tech_stack', []))} 个框架知识模块") \
          .insights(insights) \
         .add_attention(f"{len(self._confirmed_findings)} 个漏洞需要验证") \
         .priority_areas([f.get('file_path') for f in key_findings]) \
         .build()


# 创建全局实例
analysis_agent = AnalysisAgent()
