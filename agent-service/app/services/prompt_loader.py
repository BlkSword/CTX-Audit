"""
提示词模板加载器

支持从 YAML 文件动态加载提示词模板，并进行变量替换
"""
from pathlib import Path
from typing import Dict, Any, Optional
from loguru import logger
import yaml
import re


class PromptLoader:
    """
    提示词模板加载器

    功能：
    - 从 YAML 文件加载提示词模板
    - 支持变量替换
    - 模板缓存
    """

    def __init__(self, prompts_dir: str = "./prompts"):
        """
        初始化加载器

        Args:
            prompts_dir: 提示词模板目录路径
        """
        self.prompts_dir = Path(prompts_dir)
        self._cache: Dict[str, Dict[str, Any]] = {}

        # 确保目录存在
        if not self.prompts_dir.exists():
            logger.warning(f"提示词目录不存在: {self.prompts_dir}")
            self.prompts_dir.mkdir(parents=True, exist_ok=True)

    async def load_template(
        self,
        agent_type: str,
        template_name: str = "system_prompt",
    ) -> str:
        """
        加载提示词模板

        Args:
            agent_type: Agent 类型 (orchestrator | recon | analysis | verification)
            template_name: 模板名称 (system_prompt | prompts 下的具体模板名)

        Returns:
            提示词文本
        """
        cache_key = f"{agent_type}:{template_name}"

        # 检查缓存
        if cache_key in self._cache:
            return self._cache[cache_key].get("content", "")

        # 加载 YAML 文件
        yaml_file = self.prompts_dir / f"{agent_type}.yaml"

        if not yaml_file.exists():
            logger.warning(f"提示词文件不存在: {yaml_file}")
            return self._get_default_prompt(agent_type)

        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            # 提取指定模板
            if template_name == "system_prompt":
                content = data.get("system_prompt", "")
            else:
                prompts = data.get("prompts", {})
                content = prompts.get(template_name, "")

            # 缓存
            self._cache[cache_key] = {"content": content, "raw_data": data}

            return content

        except Exception as e:
            logger.error(f"加载提示词失败 {agent_type}/{template_name}: {e}")
            return self._get_default_prompt(agent_type)

    async def render_prompt(
        self,
        agent_type: str,
        template_name: str,
        variables: Dict[str, Any],
    ) -> str:
        """
        渲染提示词（变量替换）

        Args:
            agent_type: Agent 类型
            template_name: 模板名称
            variables: 变量字典

        Returns:
            渲染后的提示词
        """
        template = await self.load_template(agent_type, template_name)

        # 支持多种变量占位符格式
        # - {variable} - Python format 风格
        # - {{variable}} - Jinja2 风格
        # - {{ variable }} - 带空格的 Jinja2 风格

        result = template

        # 首先处理 Jinja2 风格 (双花括号)
        for key, value in variables.items():
            # {{ variable }}
            result = result.replace(f"{{{{ {key} }}}}", str(value))
            # {{variable}}
            result = result.replace(f"{{{{{key}}}}}", str(value))

        # 然后处理单花括号风格
        try:
            result = result.format(**variables)
        except KeyError as e:
            logger.warning(f"变量替换失败，变量不存在: {e}")

        return result

    async def get_system_prompt(self, agent_type: str) -> str:
        """
        获取 Agent 的系统提示词

        Args:
            agent_type: Agent 类型

        Returns:
            系统提示词
        """
        return await self.load_template(agent_type, "system_prompt")

    async def get_prompt(
        self,
        agent_type: str,
        prompt_name: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        获取并渲染提示词

        Args:
            agent_type: Agent 类型
            prompt_name: 提示词名称（在 prompts 下）
            variables: 变量字典（可选）

        Returns:
            渲染后的提示词
        """
        if variables is None:
            variables = {}

        return await self.render_prompt(agent_type, prompt_name, variables)

    def clear_cache(self) -> None:
        """清除缓存"""
        self._cache.clear()
        logger.info("提示词缓存已清除")

    def reload_cache(self) -> None:
        """重新加载所有缓存的模板"""
        for cache_key in list(self._cache.keys()):
            agent_type, template_name = cache_key.split(":")
            # 触发重新加载（下次访问时会重新读取）
            del self._cache[cache_key]
        logger.info("提示词缓存已重置")

    def _get_default_prompt(self, agent_type: str) -> str:
        """获取默认提示词（当加载失败时）"""
        defaults = {
            "orchestrator": "You are the Orchestrator Agent for CTX-Audit, coordinating code audit tasks.",
            "recon": "You are the Recon Agent for CTX-Audit, collecting project information and analyzing structure.",
            "analysis": "You are the Analysis Agent for CTX-Audit, analyzing code for security vulnerabilities.",
            "verification": "You are the Verification Agent for CTX-Audit, validating vulnerabilities with PoC execution.",
        }
        return defaults.get(agent_type, "You are a helpful security audit assistant.")

    async def list_available_prompts(self, agent_type: str) -> list[str]:
        """
        列出指定 Agent 的所有可用提示词

        Args:
            agent_type: Agent 类型

        Returns:
            提示词名称列表
        """
        yaml_file = self.prompts_dir / f"{agent_type}.yaml"

        if not yaml_file.exists():
            return []

        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            prompts = data.get("prompts", {})
            return ["system_prompt"] + list(prompts.keys())

        except Exception as e:
            logger.error(f"列出提示词失败: {e}")
            return []

    async def load_all_templates(self) -> Dict[str, Dict[str, Any]]:
        """
        加载所有提示词模板

        Returns:
            {agent_type: {template_name: content}}
        """
        all_templates = {}

        for yaml_file in self.prompts_dir.glob("*.yaml"):
            agent_type = yaml_file.stem

            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)

                templates = {
                    "system_prompt": data.get("system_prompt", ""),
                }

                for prompt_name, prompt_content in data.get("prompts", {}).items():
                    templates[prompt_name] = prompt_content

                all_templates[agent_type] = templates

            except Exception as e:
                logger.error(f"加载 {yaml_file} 失败: {e}")

        return all_templates


# 全局单例
_prompt_loader: Optional[PromptLoader] = None


def get_prompt_loader() -> PromptLoader:
    """获取全局提示词加载器实例"""
    global _prompt_loader

    if _prompt_loader is None:
        # 从配置获取提示词目录
        from app.config import settings
        prompts_dir = getattr(settings, "PROMPTS_DIR", "./prompts")
        _prompt_loader = PromptLoader(prompts_dir)

    return _prompt_loader


# 便捷函数
async def load_system_prompt(agent_type: str) -> str:
    """加载系统提示词（便捷函数）"""
    loader = get_prompt_loader()
    return await loader.get_system_prompt(agent_type)


async def render_prompt(
    agent_type: str,
    template_name: str,
    variables: Dict[str, Any],
) -> str:
    """渲染提示词（便捷函数）"""
    loader = get_prompt_loader()
    return await loader.render_prompt(agent_type, template_name, variables)
