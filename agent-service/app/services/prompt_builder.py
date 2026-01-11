"""
动态提示词构建器（增强版）

根据 Agent 类型和上下文动态构建提示词
参考 DeepAudit-3.0.0 设计，集成：
- 核心安全原则
- 漏洞优先级指南
- 工具使用指南
- 反幻觉规则
- 多 Agent 协作规则
"""
from typing import Dict, Any, List, Optional
from loguru import logger

from app.services.knowledge_loader import KnowledgeLoader
from app.services.prompt_loader import load_system_prompt
from app.prompts.templates import (
    get_system_prompt,
    get_tool_priority_guidance,
    get_anti_hallucination_rules,
    build_context_prompt,
)


# ==================== DeepAudit-3.0.0 风格的核心提示词模块 ====================

CORE_SECURITY_PRINCIPLES = """
## 代码审计核心原则

### 1. 深度分析优于广度扫描
- 深入分析少数真实漏洞比报告大量误报更有价值
- 每个发现都需要上下文验证
- 理解业务逻辑后才能判断安全影响

### 2. 数据流追踪
- 从用户输入（Source）到危险函数（Sink）
- 识别所有数据处理和验证节点
- 评估过滤和编码的有效性

### 3. 上下文感知分析
- 不要孤立看待代码片段
- 理解函数调用链和模块依赖
- 考虑运行时环境和配置

### 4. 自主决策
- 不要机械执行，要主动思考
- 根据发现动态调整分析策略
- 对工具输出进行专业判断

### 5. 质量优先
- 高置信度发现优于低置信度猜测
- 提供明确的证据和复现步骤
- 给出实际可行的修复建议
"""

FILE_VALIDATION_RULES = """
## 文件路径验证规则（强制执行）

### 严禁幻觉行为

在报告任何漏洞之前，你**必须**遵守以下规则：

1. **先验证文件存在**
   - 在报告漏洞前，必须使用 `read_file` 或 `list_files` 工具确认文件存在
   - 禁止基于"典型项目结构"或"常见框架模式"猜测文件路径
   - 禁止假设 `config/database.py`、`app/api.py` 等文件存在

2. **引用真实代码**
   - `code_snippet` 必须来自 `read_file` 工具的实际输出
   - 禁止凭记忆或推测编造代码片段
   - 行号必须在文件实际行数范围内

3. **验证行号准确性**
   - 报告的 `line_start` 和 `line_end` 必须基于实际读取的文件
   - 如果不确定行号，使用 `read_file` 重新确认

4. **匹配项目技术栈**
   - Rust 项目不会有 `.py` 文件（除非明确存在）
   - 前端项目不会有后端数据库配置
   - 仔细观察 Recon Agent 返回的技术栈信息

### 正确做法示例

```
# 错误 ❌：直接报告未验证的文件
Action: create_vulnerability_report
Action Input: {"file_path": "config/database.py", ...}

# 正确 ✅：先读取验证，再报告
Action: read_file
Action Input: {"file_path": "config/database.py"}
# 如果文件存在且包含漏洞代码，再报告
Action: create_vulnerability_report
Action Input: {"file_path": "config/database.py", "code_snippet": "实际读取的代码", ...}
```

### 违规后果

如果报告的文件路径不存在，系统会：
1. 拒绝创建漏洞报告
2. 记录违规行为
3. 要求重新验证

**记住：宁可漏报，不可误报。质量优于数量。**
"""

VULNERABILITY_PRIORITIES = """
## 漏洞检测优先级

### Critical - 远程代码执行类
1. **SQL注入** - 未参数化的数据库查询
   - Source: 请求参数、表单输入、HTTP头
   - Sink: execute(), query(), raw SQL
   - 绕过: ORM raw方法、字符串拼接

2. **命令注入** - 不安全的系统命令执行
   - Source: 用户可控输入
   - Sink: exec(), system(), subprocess, popen
   - 特征: shell=True, 管道符, 反引号

3. **代码注入** - 动态代码执行
   - Source: 用户输入、配置文件
   - Sink: eval(), exec(), pickle.loads(), yaml.unsafe_load()
   - 特征: 模板注入、反序列化

### High - 信息泄露和权限提升
4. **路径遍历** - 任意文件访问
   - Source: 文件名参数、路径参数
   - Sink: open(), readFile(), send_file()
   - 绕过: ../, URL编码, 空字节

5. **SSRF** - 服务器端请求伪造
   - Source: URL参数、redirect参数
   - Sink: requests.get(), fetch(), http.request()
   - 内网: 127.0.0.1, 169.254.169.254, localhost

6. **认证绕过** - 权限控制缺陷
   - 缺失认证装饰器
   - JWT漏洞: 无签名验证、弱密钥
   - IDOR: 直接对象引用

### Medium - XSS和数据暴露
7. **XSS** - 跨站脚本
   - Source: 用户输入、URL参数
   - Sink: innerHTML, document.write, v-html
   - 类型: 反射型、存储型、DOM型

8. **敏感信息泄露**
   - 硬编码密钥、密码
   - 调试信息、错误堆栈
   - API密钥、数据库凭证

### Low - 配置和最佳实践
9. **CSRF** - 跨站请求伪造
10. **弱加密** - MD5、SHA1、DES
11. **不安全传输** - HTTP、明文密码
"""

TOOL_USAGE_GUIDE = """
## 工具使用指南

### 核心原则：优先使用外部专业工具

**外部工具优先级最高！** 外部安全工具（Semgrep、Bandit、Gitleaks 等）是经过业界验证的专业工具，具有：
- 更全面的规则库和漏洞检测能力
- 更低的误报率
- 更专业的安全分析算法
- 持续更新的安全规则

**必须优先调用外部工具，而非依赖内置的模式匹配！**

### 工具优先级（从高到低）

#### 第一优先级：外部专业安全工具
| 工具 | 用途 | 何时使用 |
|------|------|---------|
| `semgrep_scan` | 多语言静态分析 | **每次分析必用**，支持30+语言 |
| `bandit_scan` | Python安全扫描 | Python项目**必用** |
| `gitleaks_scan` | 密钥泄露检测 | **每次分析必用** |

#### 第二优先级：智能扫描工具
| 工具 | 用途 |
|------|------|
| `smart_scan` | 综合智能扫描 |
| `quick_audit` | 快速审计模式 |

#### 第三优先级：内置分析工具
| 工具 | 用途 |
|------|------|
| `pattern_match` | 正则模式匹配 |
| `dataflow_analysis` | 数据流追踪验证 |

#### 辅助工具
| 工具 | 用途 |
|------|------|
| `rag_query` | **首选代码搜索工具** - 语义搜索 |
| `security_search` | **首选安全搜索工具** |
| `function_context` | **理解代码结构** |
| `read_file` | 读取文件内容验证发现 |
| `list_files` | 了解根目录结构 |

### 推荐分析流程

#### 第一步：快速侦察（5%时间）
了解项目根目录结构（不要遍历全项目）

#### 第二步：外部工具全面扫描（60%时间）
根据技术栈选择对应工具，并行执行多个扫描

#### 第三步：深度分析（25%时间）
对外部工具发现的问题进行深入分析

#### 第四步：验证和报告（10%时间）
- 确认漏洞可利用性
- 评估影响范围
- 生成修复建议
"""

MULTI_AGENT_RULES = """
## 多Agent协作规则

### Agent层级
1. **Orchestrator** - 编排层，负责调度和协调
2. **Recon** - 侦察层，负责信息收集
3. **Analysis** - 分析层，负责漏洞检测
4. **Verification** - 验证层，负责验证发现

### 通信原则
- 使用结构化的任务交接（TaskHandoff）
- 明确传递上下文和发现
- 避免重复工作

### 子Agent创建
- 每个Agent专注于特定任务
- 使用知识模块增强专业能力
- 最多加载5个知识模块

### 状态管理
- 定期检查消息
- 正确报告完成状态
- 传递结构化结果

### 完成规则
- 子Agent使用 agent_finish
- 根Agent使用 finish_scan
- 确保所有子Agent完成后再结束
"""


class PromptBuilder:
    """
    动态提示词构建器（增强版）

    职责：
    1. 加载基础提示词模板
    2. 添加核心安全原则（新增）
    3. 添加验证规则
    4. 动态加载相关知识模块
    5. 格式化上下文信息
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
        include_core_principles: bool = True,
        include_validation_rules: bool = True,
        include_tool_guide: bool = True,
    ) -> str:
        """
        为特定 Agent 构建完整提示词（增强版）

        Args:
            agent_type: Agent 类型 (orchestrator, analysis, verification, etc.)
            context: 上下文信息
            include_core_principles: 是否包含核心安全原则
            include_validation_rules: 是否包含验证规则
            include_tool_guide: 是否包含工具指南

        Returns:
            完整的提示词
        """
        sections = []

        # 1. 加载基础提示词
        try:
            base_prompt = await load_system_prompt(agent_type)
        except Exception as e:
            logger.warning(f"加载基础提示词失败 ({agent_type}): {e}")
            base_prompt = self._get_default_prompt(agent_type)

        sections.append(base_prompt)

        # 2. 添加核心安全原则（新增）
        if include_core_principles:
            sections.append("\n\n")
            sections.append(CORE_SECURITY_PRINCIPLES)

        # 3. 添加文件验证规则（新增）
        if include_validation_rules:
            sections.append("\n\n")
            sections.append(FILE_VALIDATION_RULES)

        # 4. 添加漏洞优先级指南
        if include_core_principles:
            sections.append("\n\n")
            sections.append(VULNERABILITY_PRIORITIES)

        # 5. 添加工具使用指南
        if include_tool_guide:
            sections.append("\n\n")
            sections.append(TOOL_USAGE_GUIDE)

        # 6. 添加多 Agent 协作规则（对 orchestrator）
        if agent_type == "orchestrator":
            sections.append("\n\n")
            sections.append(MULTI_AGENT_RULES)

        # 7. 添加 Agent 特定的验证规则
        validation_rules = self._get_validation_rules(agent_type)
        if validation_rules:
            sections.append("\n\n")
            sections.append(validation_rules)

        # 8. 加载相关知识模块
        knowledge = await self._load_relevant_knowledge(agent_type, context)
        if knowledge:
            sections.append("\n\n")
            sections.append(knowledge)

        # 9. 添加上下文信息（如果有）
        context_info = self._format_context(agent_type, context)
        if context_info:
            sections.append("\n\n")
            sections.append(context_info)

        return "".join(sections)

    async def get_knowledge_module(self, module_name: str) -> Optional[str]:
        """
        获取知识模块（新增，供 BaseAgent 使用）

        Args:
            module_name: 模块名称

        Returns:
            模块内容
        """
        try:
            # 这里可以从文件或数据库加载知识模块
            # 暂时返回预定义的模块
            predefined_modules = {
                "core_security": CORE_SECURITY_PRINCIPLES,
                "vulnerability_priorities": VULNERABILITY_PRIORITIES,
                "tool_usage": TOOL_USAGE_GUIDE,
                "multi_agent_rules": MULTI_AGENT_RULES,
                "file_validation": FILE_VALIDATION_RULES,
            }
            return predefined_modules.get(module_name)
        except Exception as e:
            logger.warning(f"获取知识模块 {module_name} 失败: {e}")
            return None

    async def build_enhanced_prompt(
        self,
        base_prompt: str,
        include_principles: bool = True,
        include_priorities: bool = True,
        include_tools: bool = True,
        include_validation: bool = True,
    ) -> str:
        """
        构建增强的提示词（参考 DeepAudit-3.0.0）

        Args:
            base_prompt: 基础提示词
            include_principles: 是否包含核心原则
            include_priorities: 是否包含漏洞优先级
            include_tools: 是否包含工具指南
            include_validation: 是否包含文件验证规则

        Returns:
            增强后的提示词
        """
        parts = [base_prompt]

        if include_principles:
            parts.append(CORE_SECURITY_PRINCIPLES)

        if include_validation:
            parts.append(FILE_VALIDATION_RULES)

        if include_priorities:
            parts.append(VULNERABILITY_PRIORITIES)

        if include_tools:
            parts.append(TOOL_USAGE_GUIDE)

        return "\n\n".join(parts)

    async def build_analysis_prompt(
        self,
        context: Dict[str, Any],
    ) -> str:
        """
        构建分析 Agent 的提示词（使用优化模板）

        Args:
            context: 包含 scan_results, recon_result 等的上下文

        Returns:
            分析提示词
        """
        # 获取技术栈
        tech_stack = context.get("tech_stack", [])
        if not tech_stack and context.get("recon_result"):
            tech_stack = context["recon_result"].get("tech_stack", [])

        # 构建任务描述
        task_description = self._build_analysis_task_description(context)

        # 使用新的优化模板构建 Prompt
        prompt = build_context_prompt(
            agent_type="analysis",
            task_description=task_description,
            prior_findings=context.get("previous_findings", []),
        )

        # 添加扫描结果摘要
        scan_summary = self._format_scan_results(context)
        if scan_summary:
            prompt += f"\n\n{scan_summary}"

        # 添加相关知识模块（如果启用）
        vuln_types = self._extract_vuln_types(context.get("scan_results", []))
        if vuln_types:
            knowledge_modules = await self.knowledge.get_relevant_modules(
                tech_stack=tech_stack,
                vulnerability_types=vuln_types,
            )
            if knowledge_modules:
                knowledge = await self.knowledge.load_modules(knowledge_modules)
                prompt += f"\n\n## 相关漏洞知识\n{knowledge}"

        return prompt

    def _build_analysis_task_description(self, context: Dict[str, Any]) -> str:
        """构建分析任务描述"""
        scan_results = context.get("scan_results", [])
        recon_result = context.get("recon_result", {})

        description = f"""
## 当前分析任务

### 项目信息
- 审计 ID: {context.get('audit_id', 'N/A')}
- 项目 ID: {context.get('project_id', 'N/A')}

### 扫描结果
共收到 {len(scan_results)} 个需要分析的扫描结果。

### 侦察结果（如果有）
"""

        if recon_result:
            tech_stack = recon_result.get("tech_stack", {})
            description += f"""
**技术栈**:
- 语言: {tech_stack.get('languages', [])}
- 框架: {tech_stack.get('frameworks', [])}

**攻击面**: {len(recon_result.get('attack_surface', {}).get('entry_points', []))} 个入口点
"""

        description += """
## 分析要求
1. 对每个扫描结果进行深度验证
2. 使用工具获取代码上下文（read_file, get_ast_context）
3. 判断是否为真实漏洞或误报
4. 只报告经过验证的漏洞
5. 每个发现必须有完整的代码证据
"""

        return description

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
