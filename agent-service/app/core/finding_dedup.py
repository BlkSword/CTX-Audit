"""
Finding Deduplication Module

智能去重和合并相似的漏洞发现
"""
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
from difflib import SequenceMatcher
from loguru import logger


class Similarity(str, Enum):
    """相似度级别"""
    IDENTICAL = "identical"      # 完全相同
    VERY_HIGH = "very_high"      # 非常相似 (>0.9)
    HIGH = "high"                # 高相似 (>0.75)
    MEDIUM = "medium"            # 中等相似 (>0.5)
    LOW = "low"                  # 低相似 (<=0.5)


@dataclass
class FindingMatch:
    """匹配结果"""
    finding1: Dict[str, Any]
    finding2: Dict[str, Any]
    similarity: float
    similarity_type: Similarity
    match_reasons: List[str] = field(default_factory=list)


@dataclass
class DedupResult:
    """去重结果"""
    unique_findings: List[Dict[str, Any]]
    duplicate_count: int
    merged_count: int
    matches: List[FindingMatch] = field(default_factory=list)


class FindingDeduplicator:
    """
    漏洞发现去重器

    提供智能的去重和合并功能：
    1. 基于位置的精确匹配
    2. 基于描述的相似度匹配
    3. 基于类型的模糊匹配
    4. 智能合并重复发现
    """

    def __init__(
        self,
        similarity_threshold: float = 0.75,
        enable_position_match: bool = True,
        enable_description_match: bool = True,
        enable_type_match: bool = True,
    ):
        """
        初始化去重器

        Args:
            similarity_threshold: 相似度阈值，高于此值视为重复
            enable_position_match: 是否启用位置匹配
            enable_description_match: 是否启用描述匹配
            enable_type_match: 是否启用类型匹配
        """
        self.similarity_threshold = similarity_threshold
        self.enable_position_match = enable_position_match
        self.enable_description_match = enable_description_match
        self.enable_type_match = enable_type_match

    def deduplicate(self, findings: List[Dict[str, Any]]) -> DedupResult:
        """
        去重漏洞发现列表

        Args:
            findings: 漏洞发现列表

        Returns:
            去重结果
        """
        if not findings:
            return DedupResult(
                unique_findings=[],
                duplicate_count=0,
                merged_count=0,
            )

        # 标准化所有发现
        normalized = [self._normalize_finding(f) for f in findings]

        # 查找匹配
        matches = self._find_matches(normalized)

        # 合并重复项
        unique_findings = self._merge_duplicates(normalized, matches)

        # 统计
        duplicate_count = len(findings) - len(unique_findings)
        merged_count = len(matches)

        logger.info(
            f"去重完成: {len(findings)} -> {len(unique_findings)} "
            f"(移除 {duplicate_count} 个重复, 合并 {merged_count} 组)"
        )

        return DedupResult(
            unique_findings=unique_findings,
            duplicate_count=duplicate_count,
            merged_count=merged_count,
            matches=matches,
        )

    def _normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """标准化漏洞发现格式"""
        normalized = dict(finding)

        # 处理 location 字段 -> file_path + line_start
        if "location" in normalized and "file_path" not in normalized:
            location = normalized["location"]
            if isinstance(location, str) and ":" in location:
                parts = location.split(":")
                normalized["file_path"] = parts[0]
                try:
                    normalized["line_start"] = int(parts[1])
                except (ValueError, IndexError):
                    pass
            elif isinstance(location, str):
                normalized["file_path"] = location

        # 处理 file 字段 -> file_path
        if "file" in normalized and "file_path" not in normalized:
            normalized["file_path"] = normalized["file"]

        # 处理 line 字段 -> line_start
        if "line" in normalized and "line_start" not in normalized:
            normalized["line_start"] = normalized["line"]

        # 处理 type 字段 -> vulnerability_type
        if "type" in normalized and "vulnerability_type" not in normalized:
            type_val = normalized["type"]
            if type_val and type_val.lower() not in ["vulnerability", "finding", "issue"]:
                normalized["vulnerability_type"] = type_val

        # 确保 severity 字段存在且为小写
        if "severity" in normalized:
            normalized["severity"] = str(normalized["severity"]).lower()
        else:
            normalized["severity"] = "medium"

        # 处理 risk 字段 -> severity
        if "risk" in normalized and "severity" not in normalized:
            normalized["severity"] = str(normalized["risk"]).lower()

        # 生成 title 如果不存在
        if "title" not in normalized:
            vuln_type = normalized.get("vulnerability_type", "Unknown")
            file_path = normalized.get("file_path", "")
            if file_path:
                import os
                normalized["title"] = f"{vuln_type.replace('_', ' ').title()} in {os.path.basename(file_path)}"
            else:
                normalized["title"] = f"{vuln_type.replace('_', ' ').title()} Vulnerability"

        return normalized

    def _find_matches(self, findings: List[Dict[str, Any]]) -> List[FindingMatch]:
        """查找匹配的发现"""
        matches = []
        matched_indices = set()

        for i, finding1 in enumerate(findings):
            if i in matched_indices:
                continue

            for j, finding2 in enumerate(findings[i + 1:], start=i + 1):
                if j in matched_indices:
                    continue

                similarity, reasons = self._calculate_similarity(finding1, finding2)

                if similarity >= self.similarity_threshold:
                    match = FindingMatch(
                        finding1=finding1,
                        finding2=finding2,
                        similarity=similarity,
                        similarity_type=self._get_similarity_type(similarity),
                        match_reasons=reasons,
                    )
                    matches.append(match)
                    matched_indices.add(j)

        return matches

    def _calculate_similarity(
        self,
        finding1: Dict[str, Any],
        finding2: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        计算两个发现的相似度

        Returns:
            (相似度分数 0-1, 匹配原因列表)
        """
        score = 0.0
        reasons = []

        # 1. 文件路径和行号精确匹配 (权重: 0.4)
        if self.enable_position_match:
            file1 = (finding1.get("file_path", "") or "").lower().strip()
            file2 = (finding2.get("file_path", "") or "").lower().strip()
            line1 = finding1.get("line_start") or finding1.get("line", 0)
            line2 = finding2.get("line_start") or finding2.get("line", 0)

            if file1 and file2:
                # 检查文件路径是否相同或包含关系
                if file1 == file2:
                    if line1 and line2 and line1 == line2:
                        score += 0.4
                        reasons.append(f"相同位置: {file1}:{line1}")
                    elif (not line1 or not line2) or abs(line1 - line2) <= 5:
                        score += 0.3
                        reasons.append(f"相近位置: {file1}")
                elif file1.endswith(file2) or file2.endswith(file1):
                    if line1 and line2 and line1 == line2:
                        score += 0.35
                        reasons.append(f"相关文件相同行: {line1}")
                    else:
                        score += 0.25
                        reasons.append("相关文件")

        # 2. 描述相似度 (权重: 0.3)
        if self.enable_description_match:
            desc1 = self._clean_text(finding1.get("description", "") or "")
            desc2 = self._clean_text(finding2.get("description", "") or "")

            if desc1 and desc2:
                desc_similarity = self._text_similarity(desc1, desc2)
                if desc_similarity > 0.5:
                    score += desc_similarity * 0.3
                    if desc_similarity > 0.8:
                        reasons.append("描述高度相似")
                    else:
                        reasons.append("描述部分相似")

        # 3. 漏洞类型匹配 (权重: 0.2)
        if self.enable_type_match:
            type1 = (finding1.get("vulnerability_type", "") or "").lower()
            type2 = (finding2.get("vulnerability_type", "") or "").lower()

            if type1 and type2:
                if type1 == type2:
                    score += 0.2
                    reasons.append(f"相同类型: {type1}")
                elif type1 in type2 or type2 in type1:
                    score += 0.15
                    reasons.append(f"相关类型: {type1} ~ {type2}")

        # 4. 严重程度匹配 (权重: 0.1)
        sev1 = finding1.get("severity", "medium").lower()
        sev2 = finding2.get("severity", "medium").lower()

        if sev1 == sev2:
            score += 0.1
            reasons.append(f"相同严重度: {sev1}")

        return min(score, 1.0), reasons

    def _text_similarity(self, text1: str, text2: str) -> float:
        """计算文本相似度"""
        return SequenceMatcher(None, text1, text2).ratio()

    def _clean_text(self, text: str) -> str:
        """清理文本用于比较"""
        # 移除多余空格和特殊字符
        text = re.sub(r'\s+', ' ', text)
        text = text.strip().lower()
        # 移除常见的无意义词
        text = re.sub(r'\b(the|a|an|is|are|was|were|be|been|being)\b', '', text)
        return text

    def _get_similarity_type(self, similarity: float) -> Similarity:
        """根据相似度返回类型"""
        if similarity >= 1.0:
            return Similarity.IDENTICAL
        elif similarity >= 0.9:
            return Similarity.VERY_HIGH
        elif similarity >= 0.75:
            return Similarity.HIGH
        elif similarity >= 0.5:
            return Similarity.MEDIUM
        else:
            return Similarity.LOW

    def _merge_duplicates(
        self,
        findings: List[Dict[str, Any]],
        matches: List[FindingMatch]
    ) -> List[Dict[str, Any]]:
        """合并重复的发现"""
        # 构建相似度图
        graph = {i: set() for i in range(len(findings))}

        for match in matches:
            idx1 = findings.index(match.finding1)
            idx2 = findings.index(match.finding2)
            graph[idx1].add(idx2)
            graph[idx2].add(idx1)

        # 找出所有连通分量（每组相似的发现）
        visited = set()
        groups = []

        for i in range(len(findings)):
            if i not in visited:
                group = []
                stack = [i]

                while stack:
                    node = stack.pop()
                    if node not in visited:
                        visited.add(node)
                        group.append(node)
                        stack.extend(graph[node] - visited)

                groups.append(group)

        # 合并每组中的发现
        unique_findings = []

        for group in groups:
            if len(group) == 1:
                # 没有重复，直接保留
                unique_findings.append(findings[group[0]])
            else:
                # 合并重复项
                merged = self._merge_group([findings[i] for i in group])
                unique_findings.append(merged)

        return unique_findings

    def _merge_group(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """合并一组相似的发现"""
        if len(findings) == 1:
            return findings[0]

        # 选择最完整的作为基础
        base = max(findings, key=lambda f: len(f))

        # 合并其他发现的额外信息
        merged = dict(base)

        # 合并置信度（取最高）
        max_confidence = max([
            f.get("confidence", 0.5)
            for f in findings
        ])
        merged["confidence"] = max_confidence

        # 合并验证状态（任一验证过即验证过）
        merged["is_verified"] = any(
            f.get("is_verified", False)
            for f in findings
        )

        # 合并严重程度（取最高）
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = max(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "low"), 0)
        )
        merged["severity"] = max_severity.get("severity", "medium")

        # 合并描述（选择最长的）
        merged["description"] = max(
            [f.get("description", "") for f in findings],
            key=len
        )

        # 合并代码片段（选择最完整的）
        code_snippets = [
            f.get("code_snippet", "")
            for f in findings
            if f.get("code_snippet")
        ]
        if code_snippets:
            merged["code_snippet"] = max(code_snippets, key=len)

        # 添加来源标记
        sources = [
            f.get("source", "unknown")
            for f in findings
            if f.get("source")
        ]
        if sources:
            merged["sources"] = list(set(sources))

        return merged


# 全局去重器实例
_global_deduplicator: Optional[FindingDeduplicator] = None


def get_deduplicator() -> FindingDeduplicator:
    """获取全局去重器实例"""
    global _global_deduplicator
    if _global_deduplicator is None:
        _global_deduplicator = FindingDeduplicator()
    return _global_deduplicator


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    去重漏洞发现的便捷函数

    Args:
        findings: 漏洞发现列表

    Returns:
        去重后的发现列表
    """
    deduplicator = get_deduplicator()
    result = deduplicator.deduplicate(findings)
    return result.unique_findings
