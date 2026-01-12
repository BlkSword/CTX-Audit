"""
ReAct 格式解析器

解析 LLM 输出中的 Thought/Action/Action Input 格式
"""
import re
import json
from typing import Optional, Dict, Any
from dataclasses import dataclass
from loguru import logger


@dataclass
class ReActStep:
    """ReAct 步骤"""
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict[str, Any]] = None
    is_final: bool = False
    final_answer: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "thought": self.thought,
            "action": self.action,
            "action_input": self.action_input,
            "is_final": self.is_final,
            "final_answer": self.final_answer,
        }


class ReActParser:
    """
    ReAct 格式解析器

    解析 LLM 输出中的标准 ReAct 格式：
    - Thought: [思考内容]
    - Action: [工具名称]
    - Action Input: [JSON 参数]
    - Final Answer: [最终答案]
    """

    # 匹配模式
    THOUGHT_PATTERN = r'Thought:\s*(.*?)(?=Action:|Final Answer:|Observation:|$)'
    ACTION_PATTERN = r'Action:\s*(\w+)'
    ACTION_INPUT_PATTERN = r'Action Input:\s*(.*?)(?=Thought:|Action:|Observation:|Final Answer:|$)'
    FINAL_ANSWER_PATTERN = r'Final Answer:\s*(.*?)$'

    def __init__(self):
        """初始化解析器"""
        # 预编译正则表达式以提高性能
        self.thought_re = re.compile(self.THOUGHT_PATTERN, re.DOTALL | re.MULTILINE)
        self.action_re = re.compile(self.ACTION_PATTERN, re.MULTILINE)
        self.action_input_re = re.compile(self.ACTION_INPUT_PATTERN, re.DOTALL | re.MULTILINE)
        self.final_answer_re = re.compile(self.FINAL_ANSWER_PATTERN, re.DOTALL | re.MULTILINE)

    def parse(self, response: str) -> ReActStep:
        """
        解析 LLM 响应

        Args:
            response: LLM 的文本响应

        Returns:
            ReActStep: 解析后的步骤
        """
        step = ReActStep(thought="")

        # 预处理：移除 Markdown 标记
        cleaned = self._preprocess(response)

        # 提取 Thought
        thought_match = self.thought_re.search(cleaned)
        if thought_match:
            step.thought = thought_match.group(1).strip()
        else:
            # 如果没有明确的 Thought，整个内容作为思考
            step.thought = cleaned.strip()[:500] if cleaned else ""

        # 检查是否是 Final Answer
        final_match = self.final_answer_re.search(cleaned)
        if final_match:
            step.is_final = True
            answer_text = final_match.group(1).strip()
            # 移除代码块标记
            answer_text = re.sub(r'```json\s*', '', answer_text)
            answer_text = re.sub(r'```\s*', '', answer_text)
            # 尝试解析 JSON
            try:
                step.final_answer = json.loads(answer_text)
            except json.JSONDecodeError:
                step.final_answer = {
                    "raw_answer": answer_text,
                    "findings": []
                }

            # 如果没有提取到 thought，使用 Final Answer 前的内容
            if not step.thought or len(step.thought) < 10:
                before_final = cleaned[:cleaned.find('Final Answer:')].strip()
                if before_final:
                    before_final = re.sub(r'^Thought:\s*', '', before_final)
                    step.thought = before_final[:500] if len(before_final) > 500 else before_final

            return step

        # 提取 Action
        action_match = self.action_re.search(cleaned)
        if action_match:
            step.action = action_match.group(1).strip()

            # 如果没有提取到 thought，提取 Action 之前的内容作为思考
            if not step.thought or len(step.thought) < 10:
                action_pos = cleaned.find('Action:')
                if action_pos > 0:
                    before_action = cleaned[:action_pos].strip()
                    before_action = re.sub(r'^Thought:\s*', '', before_action)
                    if before_action:
                        step.thought = before_action[:500] if len(before_action) > 500 else before_action

        # 提取 Action Input
        if step.action:
            input_match = self.action_input_re.search(cleaned)
            if input_match:
                input_text = input_match.group(1).strip()
                # 移除代码块标记
                input_text = re.sub(r'```json\s*', '', input_text)
                input_text = re.sub(r'```\s*', '', input_text)
                # 尝试解析 JSON
                try:
                    step.action_input = json.loads(input_text)
                except json.JSONDecodeError:
                    step.action_input = {
                        "raw_input": input_text,
                        "__parse_error__": True
                    }

        # 如果没有提取到任何结构化内容，整个响应作为思考
        if not step.thought and not step.action and not step.is_final:
            step.thought = cleaned.strip()[:500] if cleaned else ""

        return step

    def _preprocess(self, response: str) -> str:
        """
        预处理响应文本

        移除 Markdown 格式标记，转换为标准 ReAct 格式
        """
        if not response:
            return ""

        cleaned = response

        # 移除 Markdown 加粗标记
        cleaned = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned)
        cleaned = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned)
        cleaned = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned)
        cleaned = re.sub(r'\*\*Final Answer:\*\*', 'Final Answer:', cleaned)
        cleaned = re.sub(r'\*\*Observation:\*\*', 'Observation:', cleaned)

        return cleaned

    def extract_thought_only(self, response: str) -> str:
        """
        仅提取思考内容（用于前端显示）

        Args:
            response: LLM 响应

        Returns:
            思考内容
        """
        step = self.parse(response)
        return step.thought


# 全局单例
_react_parser = ReActParser()


def parse_react_response(response: str) -> ReActStep:
    """
    解析 ReAct 格式响应（便捷函数）

    Args:
        response: LLM 响应文本

    Returns:
        ReActStep: 解析后的步骤
    """
    return _react_parser.parse(response)


def extract_thought(response: str) -> str:
    """
    提取思考内容（便捷函数）

    Args:
        response: LLM 响应文本

    Returns:
        思考内容
    """
    return _react_parser.extract_thought_only(response)
