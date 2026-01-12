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

#### 第一优先级：外部专业安全工具 ⚡
| 工具 | 用途 | 何时使用 |
|------|------|---------|
| `semgrep_scan` | 多语言静态分析 | **每次分析必用**，支持30+语言 |
| `bandit_scan` | Python安全扫描 | Python项目**必用** |
| `gitleaks_scan` | 密钥泄露检测 | **每次分析必用** |
| `safety_scan` | Python依赖扫描 | Python项目推荐 |
| `npm_audit` | Node.js依赖扫描 | Node.js项目推荐 |

#### 第二优先级：智能扫描工具
| 工具 | 用途 |
|------|------|
| `pattern_match` | 正则模式匹配（外部工具不可用时的备选） |

#### 第三优先级：内置分析工具
| 工具 | 用途 |
|------|------|
| `read_file` | 读取文件内容验证发现 |
| `get_ast_context` | 获取代码上下文 |
| `dataflow_analysis` | 数据流追踪验证 |
| `get_code_structure` | 理解代码结构 |
| `search_symbol` | 搜索符号定义 |
| `list_files` | 了解目录结构 |

### 推荐分析流程

#### 第一步：外部工具全面扫描（60%时间）⚡
**必须首先执行以下扫描（并行调用多个工具）：**

```json
// 所有项目必做
{"tool": "semgrep_scan", "input": {"target_path": ".", "rules": "auto"}}
{"tool": "gitleaks_scan", "input": {"target_path": "."}}

// Python 项目额外
{"tool": "bandit_scan", "input": {"target_path": ".", "severity": "medium"}}

// Node.js 项目额外
{"tool": "npm_audit", "input": {"target_path": "."}}
```

#### 第二步：深度分析（30%时间）
- 使用 `read_file` 查看完整代码上下文
- 使用 `get_ast_context` 理解函数调用关系
- 使用 `dataflow_analysis` 追踪污点数据流
- 验证每个发现的真实性

#### 第三步：汇总报告（10%时间）
- 使用 `report_finding` 记录每个确认的漏洞
- 使用 `mark_false_positive` 标记误报
- 使用 `finish_analysis` 完成分析（**必须处理所有结果后调用**）
"""

# ==================== 新增：严格约束规则 ====================

STRICT_CONSTRAINTS = """
## ⚠️ 强制约束 - 必须严格遵守！

### 1. 最少工具调用要求 ⚡⚡⚡
**禁止在没有调用任何工具的情况下直接输出结论！**

#### 最低要求：
- **至少调用 2 个外部扫描工具**（semgrep_scan, bandit_scan, gitleaks_scan）
- **至少调用 1 个读取工具**（read_file 或 get_ast_context）验证发现
- **必须处理所有扫描结果**（每个结果都要调用 report_finding 或 mark_false_positive）

#### 违规示例（❌ 禁止）：
```
Thought: 根据项目结构，可能存在安全问题
Final Answer: {"findings": [...]}  # 没有调用任何工具！
```

#### 正确示例（✅ 必须）：
```
Thought: 我需要先使用外部工具进行全面扫描
Action: semgrep_scan
Action Input: {"target_path": ".", "rules": "auto"}

Observation: [返回15个问题]

Thought: 同时检查密钥泄露
Action: gitleaks_scan
Action Input: {"target_path": "."}

Observation: [返回3个问题]

Thought: 发现一个高危问题，需要查看代码验证
Action: read_file
Action Input: {"file_path": "src/auth.py"}

Observation: [代码内容]

Thought: 确认存在漏洞，记录发现
Action: report_finding
Action Input: {...}
```

### 2. 外部工具优先原则 ⚡⚡⚡
**强制使用顺序：**
1. **第一步必须调用外部工具** - semgrep_scan、gitleaks_scan、bandit_scan
2. 第二步使用内置工具深度分析
3. 最后使用 read_file 验证代码

**禁止跳过外部工具直接使用内置工具！**

### 3. 结果处理完整性 ⚡⚡⚡
**finish_analysis 工具的强制约束：**
- 必须在处理完**所有**扫描结果后才能调用
- 每个扫描结果必须调用 `report_finding` 或 `mark_false_positive`
- 不能有任何未处理的结果

**如果调用 finish_analysis 时还有未处理的结果，工具将返回错误！**

### 4. 代码验证要求 ⚡⚡
**报告漏洞前的必做检查：**
1. 使用 `read_file` 读取包含漏洞的文件
2. 确认代码确实存在安全问题
3. 提供准确的行号
4. 引用真实的代码片段

**禁止基于推测报告漏洞！**

### 5. 思考过程展示要求
**每次调用工具前，先说明：**
- 当前状态分析
- 为什么选择这个工具
- 期望得到什么结果

**示例：**
```
Thought: 当前已获得扫描结果，发现3个潜在SQL注入问题。我需要查看第一个问题的完整代码上下文来验证是否为真实漏洞。
Action: read_file
Action Input: {"file_path": "src/db.py", "line_range": [120, 150]}
```
"""

# ==================== 新增：显式 ReAct 格式 ====================

REACT_FORMAT_GUIDE = """
## ReAct 格式（思考-行动-观察）

### 输出格式要求

每次迭代，你需要按照以下格式输出：

```
Thought: [你的思考过程 - 分析当前情况，规划下一步]

Action: [工具名称]

Action Input: {
  "参数名": "参数值",
  ...
}
```

### 格式说明

#### Thought（思考）
- 分析当前状态和已获得的信息
- 评估发现的优先级和可信度
- 决定下一步行动
- 解释为什么选择这个工具

#### Action（动作）
- 要调用的工具名称
- 必须是可用工具列表中的名称
- 精确匹配，大小写敏感

#### Action Input（动作输入）
- 工具所需的参数
- 必须是有效的 JSON 格式
- 参数名称和类型必须符合工具定义

### 完整示例

```
Thought: 我需要先使用外部工具对项目进行全面安全扫描。首先使用 Semgrep 进行静态代码分析，它可以检测30+编程语言的安全问题。

Action: semgrep_scan

Action Input: {
  "target_path": ".",
  "rules": "auto",
  "severity": "WARNING"
}

[等待工具返回结果...]

Thought: Semgrep 发现了 15 个潜在问题，其中 3 个是高危 SQL 注入问题。我还需要检查是否有密钥泄露问题。

Action: gitleaks_scan

Action Input: {
  "target_path": "."
}

[等待工具返回结果...]

Thought: Gitleaks 发现了 2 个潜在的密钥泄露。现在我需要查看第一个 SQL 问题的完整代码来验证它是否为真实漏洞。

Action: read_file

Action Input: {
  "file_path": "src/database/query.py",
  "line_range": [42, 65]
}

[等待工具返回结果...]

Thought: 我查看了代码，第 45 行确实存在 SQL 注入漏洞。user_id 参数直接拼接到 SQL 语句中，没有使用参数化查询。这是一个真实的高危漏洞，需要记录到报告中。

Action: report_finding

Action Input: {
  "title": "SQL 注入漏洞",
  "severity": "high",
  "file_path": "src/database/query.py",
  "line_number": 45,
  "description": "user_id 参数直接拼接到 SQL 语句，没有使用参数化查询",
  "code_snippet": "query = f'SELECT * FROM users WHERE id = {user_id}'",
  "confidence": 0.95
}

[继续处理其他发现...]

Thought: 我已经处理了所有扫描结果：确认了 5 个真实漏洞，标记了 10 个误报。现在可以完成分析。

Action: finish_analysis

Action Input: {
  "summary": "共分析 18 个扫描结果，确认 5 个高危漏洞，标记 10 个误报",
  "recommendations": [
    "修复所有 SQL 注入漏洞，使用参数化查询",
    "移除硬编码的 API 密钥，使用环境变量",
    "添加输入验证中间件"
  ]
}
```

### 禁止格式

❌ **禁止使用 Markdown 标记：**
```
**Thought:** 分析中...
**Action:** semgrep_scan
```

❌ **禁止直接输出 Final Answer：**
```
Thought: 可能存在一些安全问题
Final Answer: {...}  # 没有调用任何工具！
```

❌ **禁止省略 Action Input：**
```
Thought: 需要扫描
Action: semgrep_scan
[缺少 Action Input]
```
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
        include_strict_constraints: bool = True,  # 新增
        include_react_format: bool = True,       # 新增
    ) -> str:
        """
        为特定 Agent 构建完整提示词（增强版）

        Args:
            agent_type: Agent 类型 (orchestrator, analysis, verification, etc.)
            context: 上下文信息
            include_core_principles: 是否包含核心安全原则
            include_validation_rules: 是否包含验证规则
            include_tool_guide: 是否包含工具指南
            include_strict_constraints: 是否包含严格约束（新增）
            include_react_format: 是否包含 ReAct 格式指南（新增）

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

        # 2. 添加严格约束（新增 - 优先级最高）
        if include_strict_constraints:
            sections.append("\n\n")
            sections.append(STRICT_CONSTRAINTS)

        # 3. 添加 ReAct 格式指南（新增 - 第二优先级）
        if include_react_format:
            sections.append("\n\n")
            sections.append(REACT_FORMAT_GUIDE)

        # 4. 添加核心安全原则
        if include_core_principles:
            sections.append("\n\n")
            sections.append(CORE_SECURITY_PRINCIPLES)

        # 5. 添加文件验证规则
        if include_validation_rules:
            sections.append("\n\n")
            sections.append(FILE_VALIDATION_RULES)

        # 6. 添加漏洞优先级指南
        if include_core_principles:
            sections.append("\n\n")
            sections.append(VULNERABILITY_PRIORITIES)

        # 7. 添加工具使用指南
        if include_tool_guide:
            sections.append("\n\n")
            sections.append(TOOL_USAGE_GUIDE)

        # 8. 添加多 Agent 协作规则（对 orchestrator）
        if agent_type == "orchestrator":
            sections.append("\n\n")
            sections.append(MULTI_AGENT_RULES)

        # 9. 添加 Agent 特定的验证规则
        validation_rules = self._get_validation_rules(agent_type)
        if validation_rules:
            sections.append("\n\n")
            sections.append(validation_rules)

        # 10. 加载相关知识模块
        knowledge = await self._load_relevant_knowledge(agent_type, context)
        if knowledge:
            sections.append("\n\n")
            sections.append(knowledge)

        # 11. 添加上下文信息（如果有）
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
        """构建分析任务描述（包含严格约束）"""
        scan_results = context.get("scan_results", [])
        recon_result = context.get("recon_result", {})
        tech_stack = recon_result.get("tech_stack", {}) if recon_result else {}

        description = f"""
## 当前分析任务

### 项目信息
- 审计 ID: {context.get('audit_id', 'N/A')}
- 项目 ID: {context.get('project_id', 'N/A')}
- 技术栈: {', '.join(tech_stack.get('languages', []))}
- 框架: {', '.join(tech_stack.get('frameworks', []))}

### 扫描结果状态
- 已收到扫描结果: {len(scan_results)} 个
- 状态: {'有结果需要分析' if scan_results else '无结果，必须先运行外部工具扫描'}

{STRICT_CONSTRAINTS}

---

## 执行流程（强制遵守）

### 第一阶段：外部工具扫描（60%时间）⚡⚡⚡
{'**如果 scan_results 为空，你必须先执行以下扫描！**' if not scan_results else '**如果需要更全面的扫描，执行以下扫描：**'}

```
# 必做 - 所有项目
Thought: 我需要使用 Semgrep 进行多语言静态分析
Action: semgrep_scan
Action Input: {{"target_path": ".", "rules": "auto", "severity": "WARNING"}}

Thought: 同时检查密钥泄露问题
Action: gitleaks_scan
Action Input: {{"target_path": "."}}
```

```
# Python 项目必做
Thought: 这是 Python 项目，使用 Bandit 进行安全扫描
Action: bandit_scan
Action Input: {{"target_path": ".", "severity": "medium"}}
```

### 第二阶段：深度分析（30%时间）
对每个发现进行验证：

```
Thought: 发现一个潜在的 [漏洞类型]，需要查看完整代码来验证
Action: read_file
Action Input: {{"file_path": "路径", "line_range": [start, end]}}

Thought: 理解这个函数的调用关系
Action: get_ast_context
Action Input: {{"file_path": "路径", "line_number": 行号}}

Thought: 追踪数据流，确认污点来源
Action: [使用 dataflow_analysis 或其他分析工具]
Action Input: {...}
```

### 第三阶段：报告结果（10%时间）
```
Thought: 确认这是一个真实漏洞
Action: report_finding
Action Input: {{
  "title": "漏洞标题",
  "severity": "high",
  "file_path": "文件路径",
  "line_number": 行号,
  "description": "详细描述",
  "code_snippet": "危险代码",
  "confidence": 0.9
}}

# 或标记为误报
Thought: 这不是真实漏洞，是误报
Action: mark_false_positive
Action Input: {{"finding_id": "ID", "reason": "原因"}}
```

### 第四阶段：完成分析
```
Thought: 我已经处理了所有扫描结果
Action: finish_analysis
Action Input: {{
  "summary": "分析总结",
  "recommendations": ["建议1", "建议2"]
}}
```

---

## ⚠️ 违规后果

### 禁止行为：
1. ❌ 没有调用任何工具就直接输出结论
2. ❌ 跳过外部工具直接使用内置工具
3. ❌ 在处理完所有结果前调用 finish_analysis
4. ❌ 报告没有通过 read_file 验证的漏洞

### 系统将拒绝：
- 没有工具调用的分析结果
- 未经验证的漏洞报告
- 不完整的分析（有未处理的结果）

---

## 重点关注的漏洞类型
- **SQL 注入** - query(), execute(), raw SQL
- **命令注入** - exec(), system(), subprocess
- **XSS** - innerHTML, v-html, dangerouslySetInnerHTML
- **路径遍历** - open(), readFile(), path拼接
- **SSRF** - requests.get(), fetch(), URL参数
- **密钥泄露** - 硬编码 password, api_key, secret
- **不安全反序列化** - pickle.loads(), yaml.load(), eval()
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
