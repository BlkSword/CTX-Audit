"""
Verification Agent - LLM 驱动的漏洞验证者

负责漏洞验证和智能 PoC 生成
"""
from typing import Dict, Any, List, Optional
from loguru import logger

from app.agents.base import BaseAgent
from app.services.llm import LLMService, LLMProvider
from app.services.prompt_builder import prompt_builder
from app.core.task_handoff import TaskHandoff

# Docker SDK（可选）
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    logger.warning("Docker SDK 未安装，PoC 验证功能将不可用")
    DOCKER_AVAILABLE = False


class VerificationAgent(BaseAgent):
    """
    LLM 驱动的 Verification Agent

    职责：
    1. 使用 LLM 生成 PoC 代码
    2. 在 Docker 沙箱中执行 PoC
    3. 智能判断漏洞真实性
    4. 降低误报率
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="verification", config=config)

        # LLM 服务
        llm_config = config or {}
        self.llm = LLMService(
            provider=LLMProvider(llm_config.get("llm_provider", "anthropic")),
            model=llm_config.get("llm_model", "claude-3-5-sonnet-20241022"),
            api_key=llm_config.get("api_key"),
            base_url=llm_config.get("base_url"),
        )

        # Docker 客户端（如果可用）
        self._docker_client = None
        if DOCKER_AVAILABLE and self.config.get("enable_sandbox", True):
            try:
                self._docker_client = docker.from_env()
                logger.info("Docker 客户端初始化成功")
            except Exception as e:
                logger.warning(f"Docker 客户端初始化失败: {e}")

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行漏洞验证

        Args:
            context: 包含 findings（待验证的漏洞列表）

        Returns:
            验证结果
        """
        findings = context.get("findings", [])

        # 接收任务交接（如果有）
        handoff = context.get("task_handoff")
        if handoff:
            self.think(f"收到上游任务交接: {handoff.get('from_agent')}")

        self.think(f"开始验证 {len(findings)} 个漏洞")

        verified = []

        for finding in findings:
            # 跳过低危和信息级别的漏洞
            severity = finding.get("severity", "info").lower()
            if severity in ["low", "info"]:
                self.think(f"跳过低危漏洞: {finding.get('title', 'Unknown')}")
                continue

            # 只验证高置信度的发现
            confidence = finding.get("confidence", 0.5)
            if confidence < 0.6:
                self.think(f"跳过低置信度 ({confidence}) 的发现: {finding.get('title')}")
                continue

            result = await self._verify_finding(finding)
            verified.append(result)

        # 统计结果
        total_verified = len([v for v in verified if v["verified"]])
        total_false_positives = len([v for v in verified if not v["verified"]])

        self.think(f"验证完成，{total_verified} 个确认为真实漏洞，{total_false_positives} 个误报")

        return {
            "verified": verified,
            "total_verified": total_verified,
            "total_false_positives": total_false_positives,
        }

    async def _verify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证单个漏洞

        Args:
            finding: 漏洞信息

        Returns:
            验证结果
        """
        vuln_type = finding.get("vulnerability_type", finding.get("type", "unknown"))
        self.think(f"验证漏洞: {vuln_type} - {finding.get('title', 'Unknown')}")

        # 1. 生成 PoC 代码
        poc_code = await self._generate_poc(finding)

        if not poc_code:
            self.think(f"PoC 生成失败，标记为未验证")
            return {
                "finding_id": finding.get("id"),
                "verified": False,
                "confidence": 0.0,
                "poc_output": "",
                "error": "PoC 生成失败",
            }

        # 2. 在沙箱中执行（如果可用）
        execution_result = await self._execute_in_sandbox(
            code=poc_code,
            environment=self._build_sandbox_env(finding),
        )

        # 3. 使用 LLM 分析执行结果
        analysis = await self._analyze_execution_with_llm(
            execution_result=execution_result,
            finding=finding,
            poc_code=poc_code,
        )

        self.think(f"验证结果: {'确认存在漏洞' if analysis['verified'] else '无法确认'} (置信度: {analysis['confidence']:.2f})")

        return {
            "finding_id": finding.get("id"),
            "verified": analysis["verified"],
            "confidence": analysis["confidence"],
            "poc_output": execution_result.get("output", ""),
            "evidence": analysis.get("evidence"),
            "poc_code": poc_code,
            "analysis_reasoning": analysis.get("reasoning", ""),
        }

    async def _generate_poc(self, finding: Dict[str, Any]) -> str:
        """
        使用 LLM 生成 PoC 代码

        Args:
            finding: 漏洞信息

        Returns:
            PoC 代码字符串
        """
        self.think("正在使用 LLM 生成 PoC 代码...")

        # 构建验证提示词
        verification_prompt = await prompt_builder.build_verification_prompt(finding)

        try:
            response = await self.llm.generate(
                messages=[
                    {"role": "system", "content": verification_prompt},
                    {"role": "user", "content": f"请为以下漏洞生成 PoC 代码：\n\n{finding.get('description', '')}"},
                ],
                max_tokens=2048,
                temperature=0.3,  # 降低温度以获得更稳定的代码
            )
            return self._extract_code_from_response(response.content)
        except Exception as e:
            self.think(f"LLM PoC 生成失败: {e}")
            return ""

    async def _analyze_execution_with_llm(
        self,
        execution_result: Dict[str, Any],
        finding: Dict[str, Any],
        poc_code: str,
    ) -> Dict[str, Any]:
        """
        使用 LLM 分析执行结果

        Args:
            execution_result: 执行结果
            finding: 原始漏洞信息
            poc_code: PoC 代码

        Returns:
            分析结果
        """
        exit_code = execution_result.get("exit_code", -1)
        output = execution_result.get("output", "")

        # 构建分析提示词
        analysis_prompt = f"""
请分析以下 PoC 执行结果，判断是否确认漏洞存在：

**漏洞类型**: {finding.get('vulnerability_type', finding.get('type', 'unknown'))}
**PoC 代码**:
```{self._detect_language(finding.get('file_path', ''))}
{poc_code}
```

**执行结果**:
- 退出码: {exit_code}
- 输出:
```
{output[:1000]}
```

请分析并返回 JSON 格式：
{{
  "verified": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "分析理由",
  "evidence": "证据描述"
}}
"""

        try:
            response = await self.llm.generate(
                messages=[
                    {
                        "role": "system",
                        "content": """你是 CTX-Audit 的 Verification Agent 分析助手。
请客观、保守地分析 PoC 执行结果。
返回纯 JSON 格式，不要有其他文字。"""
                    },
                    {"role": "user", "content": analysis_prompt},
                ],
                max_tokens=1024,
                temperature=0.2,
            )

            # 解析 JSON
            import json
            import re

            # 提取 JSON
            json_match = re.search(r'\{[^{}]*\}', response.content, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass

            # 解析失败，使用基本分析
            return self._basic_analysis(execution_result, finding)

        except Exception as e:
            logger.warning(f"LLM 分析失败，使用基本分析: {e}")
            return self._basic_analysis(execution_result, finding)

    def _basic_analysis(self, execution_result: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
        """基本分析（LLM 失败时使用）"""
        exit_code = execution_result.get("exit_code", -1)
        output = execution_result.get("output", "")

        # 基本分析
        is_vulnerable = exit_code == 0
        confidence = 0.5

        # 如果输出包含特定关键词，提高置信度
        vulnerability_indicators = [
            "vulnerable", "exploit", "success", "injection",
            "bypass", "traversal", "xss", "sql"
        ]

        for indicator in vulnerability_indicators:
            if indicator.lower() in output.lower():
                confidence = min(1.0, confidence + 0.2)

        # 如果有异常输出，降低置信度
        error_indicators = [
            "error", "exception", "traceback", "failed"
        ]

        for indicator in error_indicators:
            if indicator.lower() in output.lower()[:200]:
                confidence = max(0.0, confidence - 0.3)

        return {
            "verified": is_vulnerable,
            "confidence": confidence,
            "reasoning": f"基于执行码和输出的基本分析",
            "evidence": output[:500] if output else "",
        }

    async def _execute_in_sandbox(
        self,
        code: str,
        environment: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        在 Docker 沙箱中执行代码

        Args:
            code: 要执行的代码
            environment: 环境配置

        Returns:
            执行结果
        """
        if not DOCKER_AVAILABLE or not self._docker_client:
            self.think("Docker 不可用，跳过沙箱执行")
            return {"output": "Docker 不可用", "exit_code": -1}

        sandbox_image = self.config.get("sandbox_image", "python:3.11-slim")

        self.think(f"在 Docker 沙箱中执行代码（镜像: {sandbox_image}）")

        try:
            # 创建容器
            container = self._docker_client.containers.run(
                image=sandbox_image,
                command=f"python -c {self._quote_string(code)}",
                network_mode="none",  # 隔离网络
                mem_limit="512m",
                cpu_quota=50000,
                detach=True,
            )

            try:
                # 等待执行完成（最多 30 秒）
                result = container.wait(timeout=30)
                output = container.logs(stdout=True, stderr=True).decode('utf-8')

                return {
                    "exit_code": result['StatusCode'],
                    "output": output,
                }
            finally:
                container.remove(force=True)

        except Exception as e:
            self.think(f"沙箱执行失败: {e}")
            return {"output": str(e), "exit_code": -1}

    def _build_sandbox_env(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """构建沙箱环境配置"""
        return {
            "language": self._detect_language(finding.get("file_path", "")),
            "timeout": self.config.get("sandbox_timeout", 30),
            "memory_limit": self.config.get("sandbox_memory", "512m"),
        }

    def _detect_language(self, file_path: str) -> str:
        """根据文件扩展名检测语言"""
        if not file_path:
            return "python"

        ext = file_path.split('.')[-1].lower()

        language_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "java": "java",
            "go": "go",
            "rs": "rust",
            "php": "php",
            "rb": "ruby",
            "cs": "csharp",
            "cpp": "cpp",
            "c": "c",
        }

        return language_map.get(ext, "python")

    def _extract_code_from_response(self, response: str) -> str:
        """从 LLM 响应中提取代码"""
        # 查找代码块
        if "```" in response:
            parts = response.split("```")
            for i, part in enumerate(parts):
                if i > 0 and i % 2 == 1:
                    # 移除语言标识符
                    lines = part.split('\n')
                    if lines and lines[0].strip():
                        # 第一行可能是语言标识符
                        first_word = lines[0].strip().split()[0]
                        if len(first_word) < 20 and first_word.isalpha():
                            # 可能是语言标识符，跳过
                            lines = lines[1:]
                    return '\n'.join(lines).strip()
        return response.strip()

    def _quote_string(self, s: str) -> str:
        """引用字符串用于 shell"""
        return f'"{s.replace('"', '\\"')}"'


# 创建全局实例
verification_agent = VerificationAgent()
