"""
动态提示词构建器

根据 Agent 类型和上下文动态构建提示词
"""
from typing import Dict, Any, List, Optional
from loguru import logger

from app.services.knowledge_loader import KnowledgeLoader
from app.services.prompt_loader import load_system_prompt


class PromptBuilder:
    """
    动态提示词构建器

    职责：
    1. 加载基础提示词模板
    2. 添加验证规则
    3. 动态加载相关知识模块
    4. 格式化上下文信息
    """

    def __init__(self, knowledge_loader: Optional[KnowledgeLoader] = None):
        """
        初始化提示词构建器

        Args:
            knowledge_loader: 知识模块加载器（可选）
        """
        self.knowledge = knowledge_loader or KnowledgeLoader()

    async def build_agent_prompt(
        self,
        agent_type: str,
        context: Dict[str, Any],
    ) -> str:
        """
        为特定 Agent 构建完整提示词

        Args:
            agent_type: Agent 类型 (orchestrator, analysis, verification, etc.)
            context: 上下文信息

        Returns:
            完整的提示词
        """
        # 1. 加载基础提示词
        try:
            base_prompt = await load_system_prompt(agent_type)
        except Exception as e:
            logger.warning(f"加载基础提示词失败 ({agent_type}): {e}")
            base_prompt = self._get_default_prompt(agent_type)

        # 2. 构建完整提示词
        sections = []
        sections.append(base_prompt)

        # 3. 添加验证规则（根据 Agent 类型）
        validation_rules = self._get_validation_rules(agent_type)
        if validation_rules:
            sections.append("\n\n")
            sections.append(validation_rules)

        # 4. 加载相关知识模块
        knowledge = await self._load_relevant_knowledge(agent_type, context)
        if knowledge:
            sections.append("\n\n")
            sections.append(knowledge)

        # 5. 添加上下文信息（如果有）
        context_info = self._format_context(agent_type, context)
        if context_info:
            sections.append("\n\n")
            sections.append(context_info)

        return "".join(sections)

    async def build_analysis_prompt(
        self,
        context: Dict[str, Any],
    ) -> str:
        """
        构建分析 Agent 的提示词

        Args:
            context: 包含 scan_results, recon_result 等的上下文

        Returns:
            分析提示词
        """
        # 获取技术栈和漏洞类型
        tech_stack = context.get("tech_stack", [])
        if not tech_stack and context.get("recon_result"):
            tech_stack = context["recon_result"].get("tech_stack", [])

        # 从扫描结果中提取漏洞类型
        vuln_types = self._extract_vuln_types(
            context.get("scan_results", [])
        )

        # 加载相关知识
        knowledge_modules = await self.knowledge.get_relevant_modules(
            tech_stack=tech_stack,
            vulnerability_types=vuln_types,
        )

        # 构建提示词
        sections = []

        # 基础提示词
        try:
            base_prompt = await load_system_prompt("analysis")
        except Exception:
            base_prompt = self._get_default_prompt("analysis")

        sections.append(base_prompt)

        # 验证规则
        sections.append("\n\n")
        sections.append(self._get_validation_rules("analysis"))

        # 知识模块
        if knowledge_modules:
            knowledge = await self.knowledge.load_modules(knowledge_modules)
            sections.append("\n\n")
            sections.append(knowledge)

        # 扫描结果摘要
        scan_summary = self._format_scan_results(context)
        if scan_summary:
            sections.append("\n\n")
            sections.append(scan_summary)

        return "".join(sections)

    async def build_verification_prompt(
        self,
        finding: Dict[str, Any],
    ) -> str:
        """
        构建验证 Agent 的提示词

        Args:
            finding: 待验证的漏洞信息

        Returns:
            验证提示词
        """
        sections = []

        # 基础提示词
        try:
            base_prompt = await load_system_prompt("verification")
        except Exception:
            base_prompt = self._get_default_prompt("verification")

        sections.append(base_prompt)

        # 漏洞特定知识
        vuln_type = finding.get("vulnerability_type", "")
        if vuln_type:
            module_name = self.knowledge._normalize_vuln_name(vuln_type)
            knowledge = await self.knowledge.load_module(module_name)
            if knowledge:
                sections.append("\n\n")
                sections.append(f"<{vuln_type}_knowledge>\n{knowledge}\n</{vuln_type}_knowledge>")

        # 漏洞详情
        sections.append("\n\n")
        sections.append(self._format_finding(finding))

        return "".join(sections)

    def _get_validation_rules(self, agent_type: str) -> str:
        """获取验证规则"""
        if agent_type == "analysis":
            return """## 🔒 强制验证规则

### 1. 文件验证
- 在报告任何漏洞前，必须确认文件存在
- 禁止基于"典型项目结构"猜测文件路径
- 使用提供的代码片段，不要编造

### 2. 漏洞报告标准
- 只报告经过验证的漏洞
- 提供完整的代码证据
- 标注置信度（0.0 - 1.0）
- 说明判断依据

### 3. 误报防范
- 考虑代码上下文
- 检查是否有防护措施
- 评估实际可利用性
- 不确定的标记为低置信度

### 4. 输出格式
每个漏洞发现必须包含：
- title: 简洁的标题
- severity: 严重程度 (critical/high/medium/low/info)
- file_path: 文件路径
- line_number: 行号
- code_snippet: 相关代码
- description: 详细描述
- confidence: 置信度 (0.0-1.0)
- recommendation: 修复建议
"""

        elif agent_type == "verification":
            return """## 🔒 验证规则

### 1. PoC 生成原则
- 生成简洁、可执行的 PoC 代码
- 代码应该能够验证漏洞的存在
- 避免使用复杂的攻击链

### 2. 安全执行
- 只在隔离环境中执行
- 限制网络访问
- 限制资源使用

### 3. 结果判断
- 基于实际执行结果判断
- 提供客观的证据
- 标注验证置信度
"""

        elif agent_type == "orchestrator":
            return """## 🔒 编排规则

### 1. 决策原则
- 优先关注高危漏洞
- 合理使用工具，避免重复
- 根据中间结果动态调整
- 在最大迭代次数内完成

### 2. 资源管理
- 控制调用频率
- 避免不必要的 LLM 调用
- 及时完成审计

### 3. 报告生成
- 汇总所有发现
- 提供清晰的统计
- 标注验证状态
"""

        return ""

    async def _load_relevant_knowledge(
        self,
        agent_type: str,
        context: Dict[str, Any],
    ) -> str:
        """加载相关知识模块"""
        tech_stack = context.get("tech_stack", [])

        # 从 recon_result 获取技术栈
        if not tech_stack and context.get("recon_result"):
            tech_stack = context["recon_result"].get("tech_stack", [])

        # 从扫描结果提取漏洞类型
        vuln_types = self._extract_vuln_types(
            context.get("scan_results", [])
        )

        # 获取相关模块
        modules = await self.knowledge.get_relevant_modules(
            tech_stack=tech_stack,
            vulnerability_types=vuln_types,
        )

        if modules:
            return await self.knowledge.load_modules(modules)

        return ""

    def _extract_vuln_types(self, scan_results: List[Dict[str, Any]]) -> List[str]:
        """从扫描结果提取漏洞类型"""
        vuln_types = set()

        for result in scan_results:
            vuln_type = result.get("vulnerability_type") or result.get("type")
            if vuln_type:
                vuln_types.add(vuln_type)

        return list(vuln_types)

    def _format_context(self, agent_type: str, context: Dict[str, Any]) -> str:
        """格式化上下文信息"""
        if agent_type == "analysis":
            return self._format_scan_results(context)
        elif agent_type == "verification":
            finding = context.get("finding", {})
            return self._format_finding(finding)

        return ""

    def _format_scan_results(self, context: Dict[str, Any]) -> str:
        """格式化扫描结果"""
        scan_results = context.get("scan_results", [])

        if not scan_results:
            return ""

        lines = [
            "## 📊 扫描结果摘要",
            "",
            f"**发现问题数**: {len(scan_results)}",
        ]

        # 按严重程度分组
        severity_count = {}
        for r in scan_results:
            sev = r.get("severity", "info").lower()
            severity_count[sev] = severity_count.get(sev, 0) + 1

        if severity_count:
            lines.append("**严重程度分布**:")
            for sev, count in sorted(severity_count.items()):
                lines.append(f"- {sev}: {count}")

        # 前 10 个问题
        lines.extend([
            "",
            "**需要关注的问题**:",
        ])

        for i, r in enumerate(scan_results[:10], 1):
            title = r.get("title", "Untitled")
            sev = r.get("severity", "unknown")
            location = r.get("file_path") or r.get("location", "unknown")
            lines.append(f"{i}. **{title}** ({sev})")
            lines.append(f"   - 位置: {location}")

        return "\n".join(lines)

    def _format_finding(self, finding: Dict[str, Any]) -> str:
        """格式化漏洞信息"""
        lines = [
            "## 🎯 待验证漏洞",
            "",
            f"**类型**: {finding.get('vulnerability_type', 'unknown')}",
            f"**严重性**: {finding.get('severity', 'unknown')}",
            f"**位置**: {finding.get('file_path', 'unknown')}:{finding.get('line_number', '?')}",
            "",
            "**代码片段**:",
            f"```{finding.get('language', 'text')}",
            finding.get('code_snippet', ''),
            "```",
            "",
            "**描述**:",
            finding.get('description', 'No description'),
        ]

        return "\n".join(lines)

    def _get_default_prompt(self, agent_type: str) -> str:
        """获取默认提示词"""
        prompts = {
            "analysis": """你是 CTX-Audit 的 Analysis Agent，负责深度代码安全分析。

**你的职责**：
1. 分析扫描结果，判断是否为真实漏洞
2. 评估漏洞的严重性和可利用性
3. 提供详细的修复建议
4. 标注每个发现的置信度

**分析原则**：
- 基于证据，不猜测
- 考虑代码上下文
- 评估实际影响
- 保守判断，避免误报
""",
            "verification": """你是 CTX-Audit 的 Verification Agent，负责验证漏洞。

**你的职责**：
1. 为漏洞生成概念验证（PoC）代码
2. 在沙箱环境中执行 PoC
3. 判断漏洞是否真实可利用
4. 降低误报率

**验证原则**：
- 生成可执行的 PoC
- 客观评估执行结果
- 提供验证证据
- 标注验证置信度
""",
            "orchestrator": """你是 CTX-Audit 的 Orchestrator Agent，负责编排审计流程。

**你的职责**：
1. 分析项目特点，制定审计策略
2. 调度各个子 Agent 执行任务
3. 根据中间结果动态调整计划
4. 汇总发现并生成最终报告
""",
        }

        return prompts.get(agent_type, f"你是 CTX-Audit 的 {agent_type.title()} Agent。")


# 全局实例
prompt_builder = PromptBuilder()
