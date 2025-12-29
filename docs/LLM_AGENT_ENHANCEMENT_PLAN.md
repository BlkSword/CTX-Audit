# CTX-Audit LLM 审计系统增强计划 v2.0

> 版本: v2.0
> 日期: 2024-12-29
> 基于: DeepAudit-3.0.0 架构研究 + 现有代码分析
> **状态**: 重新规划中

---

## 📊 DeepAudit 核心架构借鉴

### 1. LLM 驱动的自主编排

**核心思想**: LLM 是真正的大脑，全程参与决策，而非固定的图结构

```python
# DeepAudit 的方式：LLM 决定下一步
class OrchestratorAgent(BaseAgent):
    async def run(self, input_data: Dict) -> AgentResult:
        for iteration in range(max_iterations):
            # 调用 LLM 进行思考和决策
            llm_output = await self.stream_llm_call(conversation_history)

            # 解析 LLM 决策
            step = self._parse_llm_response(llm_output)

            # 执行 LLM 决定的操作
            if step.action == "dispatch_agent":
                observation = await self._dispatch_agent(step.agent_type, step.input)
            elif step.action == "finish":
                break

            # 将观察结果反馈给 LLM
            conversation_history.append({"role": "user", "content": observation})
```

### 2. 任务交接协议 (TaskHandoff)

**核心思想**: Agent 之间通过结构化协议传递上下文，而非简单的数据传递

```python
@dataclass
class TaskHandoff:
    """任务交接协议"""
    from_agent: str
    to_agent: str

    # 工作摘要
    summary: str
    work_completed: List[str]

    # 关键发现和洞察
    key_findings: List[Dict[str, Any]]
    insights: List[str]

    # 建议和关注点
    suggested_actions: List[Dict[str, Any]]
    attention_points: List[str]
    priority_areas: List[str]

    def to_prompt_context(self) -> str:
        """转换为 LLM 可理解的上下文格式"""
        return f"""
## 来自 {self.from_agent} Agent 的任务交接

### 工作摘要
{self.summary}

### 已完成工作
{chr(10).join(f'- {w}' for w in self.work_completed)}

### 关键发现
{format_findings(self.key_findings)}

### 建议后续关注
{chr(10).join(f'- {p}' for p in self.attention_points)}
"""
```

### 3. 模块化知识系统

**核心思想**: 动态加载漏洞和框架特定知识模块

```python
# 知识模块目录结构
prompts/
├── vulnerabilities/
│   ├── sql_injection.md
│   ├── xss.md
│   ├── ssrf.md
│   └── ...
└── frameworks/
    ├── flask.md
    ├── django.md
    ├── fastapi.md
    └── ...

# 动态加载
def build_specialized_prompt(base_prompt: str, modules: List[str]) -> str:
    knowledge_sections = []
    for module_name in modules:
        content = load_knowledge_module(module_name)
        knowledge_sections.append(f"<{module_name}_knowledge>\n{content}\n</{module_name}_knowledge>")

    return f"{base_prompt}\n\n{''.join(knowledge_sections)}"
```

### 4. 文件验证规则

**核心思想**: 防止 LLM 产生幻觉，强制验证文件存在

```python
FILE_VALIDATION_RULES = """
## 🔒 文件路径验证规则（强制执行）

1. **先验证文件存在**
   - 在报告任何漏洞前，必须使用工具确认文件存在
   - 禁止基于"典型项目结构"猜测文件路径

2. **引用真实代码**
   - code_snippet 必须来自工具的实际输出
   - 禁止凭记忆或推测编造代码片段

3. **验证工具**
   - 使用 file_exists() 工具验证文件
   - 使用 read_file() 工具读取代码
   - 使用 search_code() 工具搜索模式
"""
```

---

## 📋 新架构设计

### 混合编排模式

结合 LangGraph 的确定性流程和 DeepAudit 的 LLM 自主决策：

```
┌─────────────────────────────────────────────────────────────────┐
│                        Orchestrator LLM                         │
│                     (自主决策 + 图编排)                          │
└─────────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
    LangGraph             LLM 决策             消息总线
    固定流程              动态调度              Agent 通信
         │                    │                    │
         ▼                    ▼                    ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Recon Agent │───▶│Analysis Agent│───▶│Verification  │
│  (确定性)    │    │  (LLM驱动)   │    │   Agent      │
└──────────────┘    └──────────────┘    └──────────────┘
```

### 核心组件重构

| 组件 | 现有实现 | DeepAudit 启发 | 新设计 |
|------|----------|----------------|--------|
| 编排方式 | LangGraph | LLM 自主决策 | 混合模式 |
| 状态传递 | TypedDict | TaskHandoff | 增强型 State + Handoff |
| 提示词 | YAML 模板 | 模块化知识库 | 分层提示词系统 |
| LLM 调用 | httpx 直连 | 多平台适配器 | 统一 LLM 服务 |
| 事件系统 | Redis Streams | 消息总线 | 增强型事件总线 |

---

## 🎯 分阶段实施计划

### Phase 1: LLM 自主编排核心 (Week 1-2)

#### 1.1 创建 LLM 服务层

**新增**: `agent-service/app/services/llm/`

```
llm/
├── __init__.py
├── service.py          # 统一 LLM 服务
├── factory.py          # LLM 适配器工厂
├── adapters/           # 平台适配器
│   ├── __init__.py
│   ├── base.py         # 基类
│   ├── anthropic.py    # Claude
│   ├── openai.py       # OpenAI
│   ├── deepseek.py     # DeepSeek
│   └── ollama.py       # 本地模型
└── memory_compressor.py # 对话历史压缩
```

**核心代码**:

```python
# llm/service.py
from typing import List, Dict, Any, Optional, AsyncIterator
from enum import Enum

class LLMProvider(Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"
    QWEN = "qwen"

class LLMService:
    """统一 LLM 服务"""

    def __init__(self, provider: LLMProvider, model: str, config: dict):
        self.provider = provider
        self.model = model
        self.adapter = LLMFactory.create_adapter(provider, config)

    async def generate(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        tools: Optional[List[Dict]] = None,
    ) -> str:
        """生成文本"""

    async def generate_stream(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> AsyncIterator[str]:
        """流式生成"""

    async def generate_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """生成并调用工具"""
```

#### 1.2 重构 Orchestrator 为 LLM 驱动

**修改**: `agent-service/app/agents/orchestrator.py`

```python
class OrchestratorAgent(BaseAgent):
    """LLM 驱动的编排 Agent"""

    def __init__(self, config: dict = None):
        super().__init__(name="orchestrator", config=config)
        self.llm = LLMService(
            provider=config.get("llm_provider", LLMProvider.ANTHROPIC),
            model=config.get("model", "claude-3-5-sonnet-20241022"),
            config=config
        )

        # 构建 LangGraph（作为辅助）
        self.graph = self._build_graph() if config.get("use_langgraph") else None

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """LLM 驱动的自主编排"""

        # 1. 构建初始上下文
        context = await self._build_initial_context(input_data)

        # 2. 初始化对话历史
        conversation = [
            {"role": "system", "content": await self._load_system_prompt()},
            {"role": "user", "content": self._format_initial_message(context)},
        ]

        # 3. LLM 决策循环
        for iteration in range(self.config.get("max_iterations", 20)):
            # 调用 LLM 进行决策
            llm_response = await self.llm.generate_with_tools(
                messages=conversation,
                tools=self._get_available_tools(),
            )

            # 解析决策
            tool_calls = llm_response.get("tool_calls", [])

            if not tool_calls:
                # LLM 决定完成
                break

            # 执行工具调用
            observations = []
            for tool_call in tool_calls:
                observation = await self._execute_tool(tool_call, context)
                observations.append(observation)

            # 将观察反馈给 LLM
            conversation.append({
                "role": "assistant",
                "content": llm_response.get("content", ""),
                "tool_calls": tool_calls,
            })
            conversation.append({
                "role": "user",
                "content": "\n\n".join(observations),
            })

            # 更新上下文
            context = self._update_context(context, observations)

        # 4. 生成最终报告
        return self._generate_final_report(context)

    def _get_available_tools(self) -> List[Dict]:
        """获取可用工具列表"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "dispatch_recon_agent",
                    "description": "启动 Recon Agent 进行信息收集",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "focus_areas": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "重点关注区域",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "dispatch_analysis_agent",
                    "description": "启动 Analysis Agent 进行深度分析",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "targets": {
                                "type": "array",
                                "items": {"type": "object"},
                                "description": "待分析的目标列表",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "rust_scan",
                    "description": "调用 Rust 后端进行静态扫描",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "rules": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "启用的规则",
                            },
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finish_audit",
                    "description": "完成审计并生成报告",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"},
                            "findings_count": {"type": "integer"},
                        },
                    },
                },
            },
        ]

    async def _execute_tool(self, tool_call: Dict, context: Dict) -> str:
        """执行工具调用"""
        tool_name = tool_call["function"]["name"]
        arguments = tool_call["function"].get("arguments", {})

        if tool_name == "dispatch_recon_agent":
            return await self._dispatch_recon(arguments, context)
        elif tool_name == "dispatch_analysis_agent":
            return await self._dispatch_analysis(arguments, context)
        elif tool_name == "rust_scan":
            return await self._run_rust_scan(arguments, context)
        elif tool_name == "finish_audit":
            return await self._finish_audit(arguments, context)
        else:
            return f"未知工具: {tool_name}"
```

#### 1.3 任务交接协议

**新增**: `agent-service/app/core/task_handoff.py`

```python
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

@dataclass
class TaskHandoff:
    """Agent 间任务交接协议"""

    # 基本信息
    from_agent: str
    to_agent: str
    handoff_id: str = field(default_factory=lambda: f"handoff_{datetime.now().timestamp()}")

    # 工作摘要
    summary: str = ""
    work_completed: List[str] = field(default_factory=list)

    # 关键发现
    key_findings: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)

    # 建议和关注点
    suggested_actions: List[Dict[str, Any]] = field(default_factory=list)
    attention_points: List[str] = field(default_factory=list)
    priority_areas: List[str] = field(default_factory=list)

    # 元数据
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_prompt_context(self) -> str:
        """转换为 LLM 提示词上下文"""
        lines = [
            f"## 📋 来自 {self.from_agent} Agent 的任务交接",
            "",
            "### 工作摘要",
            self.summary,
            "",
            "### 已完成工作",
        ]

        for work in self.work_completed:
            lines.append(f"- {work}")

        if self.key_findings:
            lines.extend([
                "",
                "### 关键发现",
            ])
            for i, finding in enumerate(self.key_findings, 1):
                lines.append(f"**{i}. {finding.get('title', 'Untitled')}**")
                lines.append(f"   - 类型: {finding.get('type', 'unknown')}")
                lines.append(f"   - 严重性: {finding.get('severity', 'unknown')}")
                lines.append(f"   - 位置: {finding.get('location', 'unknown')}")

        if self.insights:
            lines.extend([
                "",
                "### 分析洞察",
            ])
            for insight in self.insights:
                lines.append(f"- {insight}")

        if self.attention_points:
            lines.extend([
                "",
                "### 建议后续关注",
            ])
            for point in self.attention_points:
                lines.append(f"⚠️ {point}")

        return "\n".join(lines)

    @classmethod
    def from_agent_result(
        cls,
        from_agent: str,
        to_agent: str,
        result: Dict[str, Any],
    ) -> "TaskHandoff":
        """从 Agent 结果创建交接协议"""
        return cls(
            from_agent=from_agent,
            to_agent=to_agent,
            summary=result.get("summary", ""),
            work_completed=result.get("work_completed", []),
            key_findings=result.get("findings", []),
            insights=result.get("insights", []),
            attention_points=result.get("attention_points", []),
            priority_areas=result.get("priority_areas", []),
            metadata=result.get("metadata", {}),
        )
```

---

### Phase 2: 模块化知识系统 (Week 3)

#### 2.1 知识模块结构

**新增目录**: `agent-service/prompts/knowledge/`

```
prompts/knowledge/
├── vulnerabilities/
│   ├── sql_injection.md
│   ├── xss.md
│   ├── ssrf.md
│   ├── path_traversal.md
│   ├── command_injection.md
│   └── insecure_deserialization.md
├── frameworks/
│   ├── fastapi.md
│   ├── flask.md
│   ├── django.md
│   ├── spring_boot.md
│   └── express.md
└── patterns/
    ├── authentication.md
    ├── authorization.md
    ├── input_validation.md
    └── cryptography.md
```

#### 2.2 知识模块加载器

**新增**: `agent-service/app/services/knowledge_loader.py`

```python
from pathlib import Path
from typing import List, Dict, Any
import yaml

class KnowledgeLoader:
    """知识模块加载器"""

    def __init__(self, knowledge_dir: str = "./prompts/knowledge"):
        self.knowledge_dir = Path(knowledge_dir)
        self._cache = {}

    async def load_modules(self, module_names: List[str]) -> str:
        """加载指定的知识模块"""
        sections = []

        for module_name in module_names:
            content = await self._load_module(module_name)
            if content:
                sections.append(f"<{module_name}_knowledge>\n{content}\n</{module_name}_knowledge>")

        return "\n\n".join(sections)

    async def _load_module(self, module_name: str) -> str:
        """加载单个模块"""
        if module_name in self._cache:
            return self._cache[module_name]

        # 搜索模块文件
        module_path = self._find_module(module_name)
        if not module_path:
            return ""

        # 读取内容
        content = module_path.read_text(encoding="utf-8")
        self._cache[module_name] = content
        return content

    def _find_module(self, module_name: str) -> Optional[Path]:
        """查找模块文件"""
        # 尝试 .md 和 .yaml
        for ext in [".md", ".yaml"]:
            path = self.knowledge_dir / f"{module_name}{ext}"
            if path.exists():
                return path

        # 递归搜索
        for path in self.knowledge_dir.rglob(f"{module_name}.md"):
            return path

        return None

    async def get_relevant_modules(
        self,
        tech_stack: List[str],
        vulnerability_types: List[str],
    ) -> List[str]:
        """根据技术栈和漏洞类型获取相关模块"""
        modules = []

        # 添加框架知识
        for framework in tech_stack:
            if self._find_module(framework):
                modules.append(framework)

        # 添加漏洞知识
        for vuln_type in vulnerability_types:
            module_name = self._normalize_vuln_name(vuln_type)
            if self._find_module(module_name):
                modules.append(module_name)

        return modules

    def _normalize_vuln_name(self, vuln_type: str) -> str:
        """规范化漏洞名称"""
        mapping = {
            "sqli": "sql_injection",
            "injection": "sql_injection",
            "xss": "xss",
            "cross_site_scripting": "xss",
            # ... 更多映射
        }
        return mapping.get(vuln_type.lower(), vuln_type)
```

#### 2.3 动态提示词构建器

**新增**: `agent-service/app/services/prompt_builder.py`

```python
class PromptBuilder:
    """动态提示词构建器"""

    def __init__(self, knowledge_loader: KnowledgeLoader):
        self.knowledge = knowledge_loader

    async def build_agent_prompt(
        self,
        agent_type: str,
        base_prompt: str,
        context: Dict[str, Any],
    ) -> str:
        """为特定 Agent 构建提示词"""

        # 1. 加载基础提示词
        prompt = base_prompt

        # 2. 添加验证规则
        prompt += "\n\n" + self._get_validation_rules()

        # 3. 加载相关知识模块
        relevant_modules = await self._get_relevant_modules(agent_type, context)
        if relevant_modules:
            knowledge = await self.knowledge.load_modules(relevant_modules)
            prompt += "\n\n" + knowledge

        # 4. 添加上下文信息
        prompt += "\n\n" + self._format_context(context)

        return prompt

    def _get_validation_rules(self) -> str:
        """获取验证规则"""
        return """
## 🔒 强制验证规则

1. **文件验证**
   - 使用 `file_exists()` 工具验证文件存在
   - 使用 `read_file()` 工具读取实际代码
   - 禁止猜测或编造代码片段

2. **漏洞报告**
   - 只报告经过验证的漏洞
   - 提供完整的代码证据
   - 标注置信度（0.0 - 1.0）

3. **工具使用**
   - 优先使用专用工具而非猜测
   - 记录所有工具调用结果
"""

    async def _get_relevant_modules(
        self,
        agent_type: str,
        context: Dict[str, Any],
    ) -> List[str]:
        """获取相关知识模块"""
        tech_stack = context.get("tech_stack", [])
        vuln_types = context.get("vulnerability_types", [])

        return await self.knowledge.get_relevant_modules(
            tech_stack=tech_stack,
            vulnerability_types=vuln_types,
        )
```

---

### Phase 3: 增强型 Analysis Agent (Week 4)

#### 3.1 LLM 驱动的深度分析

**修改**: `agent-service/app/agents/analysis.py`

```python
class AnalysisAgent(BaseAgent):
    """LLM 驱动的深度分析 Agent"""

    def __init__(self, config: dict = None):
        super().__init__(name="analysis", config=config)
        self.llm = LLMService(...)
        self.prompt_builder = PromptBuilder(...)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """执行深度分析"""

        # 1. 接收任务交接
        handoff = context.get("task_handoff")
        if handoff:
            self.think(f"收到来自 {handoff.from_agent} 的任务交接")
            self.think(f"摘要: {handoff.summary}")

        # 2. 构建分析提示词
        prompt = await self.prompt_builder.build_agent_prompt(
            agent_type="analysis",
            base_prompt=await self._load_base_prompt(),
            context={
                "tech_stack": context.get("tech_stack", []),
                "vulnerability_types": context.get("vulnerability_types", []),
                "scan_results": context.get("scan_results", []),
                "recon_result": context.get("recon_result"),
            },
        )

        # 3. LLM 分析循环
        findings = []
        conversation = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": self._format_analysis_request(context)},
        ]

        for iteration in range(self.config.get("max_iterations", 10)):
            # 调用 LLM
            response = await self.llm.generate_with_tools(
                messages=conversation,
                tools=self._get_analysis_tools(),
            )

            # 处理工具调用
            if response.get("tool_calls"):
                observations = await self._execute_tool_calls(response["tool_calls"])
                conversation.append({"role": "assistant", "content": response.get("content", "")})
                conversation.append({"role": "user", "content": "\n".join(observations)})
            else:
                # LLM 完成分析
                findings = self._extract_findings(response.get("content", ""))
                break

        # 4. 创建任务交接（如果需要传递给 Verification Agent）
        next_handoff = None
        if findings and self.config.get("enable_verification", False):
            next_handoff = TaskHandoff(
                from_agent="analysis",
                to_agent="verification",
                summary=f"完成深度分析，发现 {len(findings)} 个潜在漏洞",
                work_completed=[
                    f"扫描了 {context.get('files_scanned', 0)} 个文件",
                    f"应用了 {len(context.get('tech_stack', []))} 个框架知识模块",
                ],
                key_findings=findings[:5],  # 优先传递高危发现
                insights=[
                    f"重点关注 {self._get_priority_areas(findings)}",
                ],
                attention_points=[
                    f"{len([f for f in findings if f['severity'] == 'critical'])} 个严重漏洞",
                ],
            )

        return {
            "status": "success",
            "findings": findings,
            "task_handoff": next_handoff.to_dict() if next_handoff else None,
        }

    def _get_analysis_tools(self) -> List[Dict]:
        """获取分析工具"""
        return [
            {
                "type": "function",
                "function": {
                    "name": "search_code",
                    "description": "搜索代码模式",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string"},
                            "file_pattern": {"type": "string"},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "读取文件内容",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "file_exists",
                    "description": "验证文件是否存在",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_similar_vulnerabilities",
                    "description": "在向量库中搜索相似漏洞",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "code_snippet": {"type": "string"},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "report_finding",
                    "description": "报告一个漏洞发现",
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
                        },
                    },
                },
            },
        ]
```

---

### Phase 4: Agent 注册表与图控制 (Week 5)

#### 4.1 Agent 注册表

**新增**: `agent-service/app/core/agent_registry.py`

```python
from typing import Dict, Optional, List
from datetime import datetime
import asyncio

class AgentRegistry:
    """Agent 注册表 - 管理运行中的 Agent 实例"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._agents = {}
            cls._instance._lock = asyncio.Lock()
        return cls._instance

    async def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        agent_type: str,
        task: str,
        parent_id: Optional[str] = None,
        agent_instance: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """注册一个新 Agent"""
        async with self._lock:
            self._agents[agent_id] = {
                "agent_id": agent_id,
                "agent_name": agent_name,
                "agent_type": agent_type,
                "task": task,
                "parent_id": parent_id,
                "instance": agent_instance,
                "status": "running",
                "created_at": datetime.now().isoformat(),
                "children": [],
            }

            # 更新父 Agent 的子 Agent 列表
            if parent_id and parent_id in self._agents:
                self._agents[parent_id]["children"].append(agent_id)

            return self._agents[agent_id]

    async def get_agent(self, agent_id: str) -> Optional[Dict]:
        """获取 Agent 信息"""
        return self._agents.get(agent_id)

    async def update_agent_status(
        self,
        agent_id: str,
        status: str,
    ) -> None:
        """更新 Agent 状态"""
        if agent_id in self._agents:
            self._agents[agent_id]["status"] = status
            if status == "completed":
                self._agents[agent_id]["completed_at"] = datetime.now().isoformat()

    async def get_agent_tree(
        self,
        root_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """获取 Agent 树结构"""
        if root_id is None:
            root_id = self._find_root_agent()

        if root_id not in self._agents:
            return {}

        return self._build_tree(root_id)

    def _build_tree(self, agent_id: str) -> Dict[str, Any]:
        """递归构建 Agent 树"""
        agent = self._agents[agent_id].copy()
        agent["children"] = [
            self._build_tree(child_id)
            for child_id in agent.get("children", [])
        ]
        return agent

    def _find_root_agent(self) -> Optional[str]:
        """查找根 Agent"""
        for agent_id, agent in self._agents.items():
            if agent.get("parent_id") is None:
                return agent_id
        return None

    async def stop_agent(self, agent_id: str) -> Dict[str, Any]:
        """停止指定 Agent 及其子 Agent"""
        async with self._lock:
            if agent_id not in self._agents:
                return {"error": "Agent not found"}

            # 递归停止子 Agent
            for child_id in self._agents[agent_id].get("children", []):
                await self.stop_agent(child_id)

            # 停止 Agent 实例
            instance = self._agents[agent_id].get("instance")
            if instance and hasattr(instance, "stop"):
                await instance.stop()

            self._agents[agent_id]["status"] = "stopped"

            return {"status": "stopped", "agent_id": agent_id}
```

#### 4.2 Agent 图控制器

**新增**: `agent-service/app/core/graph_controller.py`

```python
class AgentGraphController:
    """Agent 图控制器 - 管理动态 Agent 树"""

    def __init__(self):
        self.registry = AgentRegistry()
        self.message_bus = MessageBus()

    async def create_agent(
        self,
        agent_type: str,
        task: str,
        parent_id: Optional[str] = None,
        config: Optional[Dict] = None,
    ) -> str:
        """创建新 Agent"""
        agent_id = f"{agent_type}_{uuid.uuid4().hex[:8]}"

        # 实例化 Agent
        agent_class = self._get_agent_class(agent_type)
        agent_instance = agent_class(config=config)

        # 注册
        await self.registry.register_agent(
            agent_id=agent_id,
            agent_name=agent_instance.name,
            agent_type=agent_type,
            task=task,
            parent_id=parent_id,
            agent_instance=agent_instance,
        )

        return agent_id

    async def send_message_to_agent(
        self,
        from_agent: str,
        target_agent_id: str,
        message: Dict[str, Any],
    ) -> Dict[str, Any]:
        """向指定 Agent 发送消息"""
        target_agent = await self.registry.get_agent(target_agent_id)

        if not target_agent:
            return {"error": "Target agent not found"}

        # 通过消息总线发送
        await self.message_bus.publish(
            sender=from_agent,
            recipient=target_agent_id,
            message=message,
        )

        return {"status": "message_sent"}

    async def get_agent_graph(
        self,
        current_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """获取 Agent 图结构"""
        return await self.registry.get_agent_tree(root_id=current_agent_id)
```

---

### Phase 5: 消息总线增强 (Week 6)

#### 5.1 Agent 间消息系统

**新增**: `agent-service/app/core/message.py`

```python
from enum import Enum
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import asyncio

class MessagePriority(Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

class MessageType(Enum):
    INFORMATION = "information"
    INSTRUCTION = "instruction"
    COMPLETION_REPORT = "completion_report"
    ERROR = "error"
    TASK_HANDOFF = "task_handoff"

class AgentMessage:
    """Agent 消息"""

    def __init__(
        self,
        sender: str,
        recipient: str,
        message_type: MessageType,
        content: str,
        priority: MessagePriority = MessagePriority.NORMAL,
        data: Optional[Dict[str, Any]] = None,
    ):
        self.message_id = f"msg_{uuid.uuid4().hex}"
        self.sender = sender
        self.recipient = recipient
        self.message_type = message_type
        self.content = content
        self.priority = priority
        self.data = data or {}
        self.timestamp = datetime.now()
        self.delivered = False

class MessageBus:
    """Agent 消息总线"""

    def __init__(self):
        self._queues: Dict[str, asyncio.Queue] = {}
        self._handlers: Dict[str, Callable] = {}

    async def subscribe(self, agent_id: str) -> asyncio.Queue:
        """订阅消息"""
        if agent_id not in self._queues:
            self._queues[agent_id] = asyncio.Queue()
        return self._queues[agent_id]

    async def publish(
        self,
        sender: str,
        recipient: str,
        message_type: MessageType = MessageType.INFORMATION,
        content: str = "",
        priority: MessagePriority = MessagePriority.NORMAL,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """发布消息"""
        message = AgentMessage(
            sender=sender,
            recipient=recipient,
            message_type=message_type,
            content=content,
            priority=priority,
            data=data,
        )

        if recipient in self._queues:
            await self._queues[recipient].put(message)

    async def register_handler(
        self,
        agent_id: str,
        handler: Callable[[AgentMessage], Any],
    ) -> None:
        """注册消息处理器"""
        self._handlers[agent_id] = handler
```

---

### Phase 6: Verification Agent 增强 (Week 7)

基于现有 Verification Agent，增加：
- LLM 驱动的 PoC 生成
- 更智能的沙箱环境检测
- 多语言支持

---

### Phase 7: 前端 Agent 树可视化 (Week 8)

**新增**: `src/components/audit/AgentTreeVisualization.tsx`

```tsx
// 使用 React Flow 或 D3.js 可视化动态 Agent 树
```

---

## 📊 架构对比

| 特性 | 当前实现 | DeepAudit | 新方案 |
|------|----------|-----------|--------|
| 编排方式 | LangGraph | LLM 自主决策 | 混合模式 |
| Agent 通信 | 直接调用 | 消息总线 | 消息总线 + TaskHandoff |
| 提示词 | YAML 模板 | 模块化知识库 | 分层模块化 |
| LLM 集成 | httpx | 多平台适配器 | 统一 LLM 服务 |
| 状态管理 | StateGraph | Agent 状态 + 注册表 | 增强型注册表 |
| 事件流 | Redis Streams | 事件总线 | 保留现有 |

---

## 🎯 实施优先级

| Phase | 内容 | 优先级 | 依赖 |
|-------|------|--------|------|
| 1 | LLM 自主编排核心 | 🔴 高 | 无 |
| 2 | 模块化知识系统 | 🔴 高 | Phase 1 |
| 3 | 增强 Analysis Agent | 🟡 中 | Phase 1, 2 |
| 4 | Agent 注册表 | 🟡 中 | Phase 1 |
| 5 | 消息总线增强 | 🟢 低 | Phase 4 |
| 6 | Verification 增强 | 🟢 低 | Phase 1 |
| 7 | 前端可视化 | 🟢 低 | Phase 4 |

---

## 📝 总结

本计划借鉴 DeepAudit 的核心设计理念，同时保留我们已有的 LangGraph 和 SSE 架构：

1. **保留**:
   - LangGraph 作为辅助编排（确定性流程）
   - Redis + SSE 事件流（已实现且稳定）
   - Verification Agent（已实现）

2. **新增**:
   - LLM 自主决策（核心创新）
   - TaskHandoff 协议（结构化上下文传递）
   - 模块化知识库（动态加载）
   - Agent 注册表（动态管理）
   - 消息总线（Agent 通信）

3. **重构**:
   - Orchestrator → LLM 驱动 + LangGraph 辅助
   - Analysis → 工具调用增强
   - 提示词 → 分层构建
