"""
对话历史压缩器

当对话历史过长时，智能压缩以节省 token
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


class MessageSummary:
    """消息摘要"""

    def __init__(
        self,
        original_count: int,
        key_points: List[str],
        findings: List[Dict[str, Any]],
        decisions: List[str],
    ):
        self.original_count = original_count
        self.key_points = key_points
        self.findings = findings
        self.decisions = decisions

    def to_message(self) -> Dict[str, str]:
        """转换为消息格式"""
        summary_parts = [
            f"[对话摘要: 原始 {self.original_count} 条消息]",
            "",
            "## 关键信息点",
        ]

        for point in self.key_points:
            summary_parts.append(f"- {point}")

        if self.findings:
            summary_parts.extend([
                "",
                "## 已发现的问题",
            ])
            for i, finding in enumerate(self.findings, 1):
                summary_parts.append(f"{i}. {finding.get('title', 'Untitled')}")

        if self.decisions:
            summary_parts.extend([
                "",
                "## 已做的决策",
            ])
            for decision in self.decisions:
                summary_parts.append(f"- {decision}")

        return {
            "role": "system",
            "content": "\n".join(summary_parts),
        }


class MemoryCompressor:
    """对话历史压缩器"""

    def __init__(
        self,
        max_messages: int = 20,
        max_tokens_estimate: int = 8000,
    ):
        self.max_messages = max_messages
        self.max_tokens_estimate = max_tokens_estimate

    def should_compress(self, messages: List[Dict[str, Any]]) -> bool:
        """判断是否需要压缩"""
        # 简单判断：消息数量超过阈值
        return len(messages) > self.max_messages

    def compress(
        self,
        messages: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        压缩对话历史

        Args:
            messages: 原始消息列表
            context: 额外上下文信息

        Returns:
            压缩后的消息列表
        """
        if not self.should_compress(messages):
            return messages

        # 保留系统消息
        system_messages = [m for m in messages if m.get("role") == "system"]

        # 保留最近的 N 条消息
        recent_messages = messages[-(self.max_messages // 2):]

        # 压缩中间的消息
        old_messages = messages[:-(self.max_messages // 2)]
        summary = self._create_summary(old_messages, context)

        # 组合结果
        result = []
        result.extend(system_messages)
        result.append(summary.to_message())
        result.extend(recent_messages)

        return result

    def _create_summary(
        self,
        messages: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]],
    ) -> MessageSummary:
        """创建消息摘要"""
        key_points = []
        findings = []
        decisions = []

        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")

            if role == "assistant":
                # 提取关键信息点
                if "完成" in content or "found" in content.lower():
                    # 尝试提取结构化信息
                    if "findings" in msg:
                        findings.extend(msg.get("findings", []))

                    # 提取决策
                    if "决定" in content or "decided" in content.lower():
                        decisions.append(content[:200])

            elif role == "user":
                # 提取用户关注点
                if "分析" in content or "检查" in content:
                    key_points.append(f"用户请求: {content[:100]}")

        return MessageSummary(
            original_count=len(messages),
            key_points=key_points,
            findings=findings[-10:],  # 保留最近 10 个发现
            decisions=decisions[-5:],  # 保留最近 5 个决策
        )
