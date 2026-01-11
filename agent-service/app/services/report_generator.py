"""
审计报告生成服务
生成 Markdown 格式的漏洞报告
"""

from datetime import datetime
from typing import List, Dict, Any, Optional


class ReportGenerator:
    """审计报告生成器"""

    @staticmethod
    def _escape_markdown(text: str) -> str:
        """转义 Markdown 特殊字符"""
        if not text:
            return ""
        # 替换特殊字符
        replacements = [
            ("\\", "\\\\"),
            ("*", "\\*"),
            ("_", "\\_"),
            ("[", "\\["),
            ("]", "\\]"),
            ("(", "\\("),
            (")", "\\)"),
            ("#", "\\#"),
            ("`", "\\`"),
        ]
        for old, new in replacements:
            text = text.replace(old, new)
        return text

    @staticmethod
    def _get_severity_label(severity: str) -> str:
        """获取严重程度标签"""
        labels = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危",
            "info": "信息",
        }
        return labels.get(severity.lower(), "未知")

    @staticmethod
    def _get_severity_emoji(severity: str) -> str:
        """获取严重程度表情符号"""
        emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
        }
        return emojis.get(severity.lower(), "⚪")

    @classmethod
    def _format_finding(cls, finding: Dict[str, Any], index: int) -> str:
        """格式化单个漏洞发现"""
        severity = finding.get("severity", "info").lower()
        title = finding.get("title", "未知漏洞")
        description = finding.get("description", "")
        file_path = finding.get("file_path", "")
        line_start = finding.get("line_start")
        line_end = finding.get("line_end", line_start)
        code_snippet = finding.get("code_snippet", "")
        recommendation = finding.get("recommendation", "")
        vulnerability_type = finding.get("vulnerability_type", "")

        severity_label = cls._get_severity_label(severity)
        severity_emoji = cls._get_severity_emoji(severity)

        md = f"### {index}. {cls._escape_markdown(title)} {severity_emoji}\n\n"
        md += f"**严重程度**: {severity_label}\n\n"

        if vulnerability_type:
            md += f"**漏洞类型**: {cls._escape_markdown(vulnerability_type)}\n\n"

        # 位置信息
        if file_path:
            location = f"`{cls._escape_markdown(file_path)}`"
            if line_start:
                location += f" (行 {line_start}"
                if line_end and line_end != line_start:
                    location += f"-{line_end}"
                location += ")"
            md += f"**位置**: {location}\n\n"

        # 描述
        if description:
            md += f"**描述**:\n\n{cls._escape_markdown(description)}\n\n"

        # 代码片段
        if code_snippet:
            md += "**代码片段**:\n\n"
            md += "```python\n"
            md += code_snippet
            md += "\n```\n\n"

        # 修复建议
        if recommendation:
            md += f"**修复建议**:\n\n{cls._escape_markdown(recommendation)}\n\n"

        md += "---\n\n"
        return md

    @classmethod
    def generate_markdown_report(
        cls,
        audit_id: str,
        findings: List[Dict[str, Any]],
        task_info: Optional[Dict[str, Any]] = None,
        project_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        生成 Markdown 格式的审计报告

        Args:
            audit_id: 审计 ID
            findings: 漏洞发现列表
            task_info: 任务信息（可选）
            project_info: 项目信息（可选）

        Returns:
            Markdown 格式的报告内容
        """
        # 统计信息
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low_count = sum(1 for f in findings if f.get("severity", "").lower() == "low")

        # 计算安全评分 (100 - 严重程度权重)
        score = 100
        score -= critical_count * 25
        score -= high_count * 10
        score -= medium_count * 5
        score -= low_count * 2
        score = max(0, min(100, score))

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "").lower(), 5)
        )

        # 生成报告
        md = ""
        md += "# 🔍 安全审计报告\n\n"
        md += f"**报告编号**: `{audit_id}`\n\n"
        md += f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        if project_info:
            md += f"**项目名称**: {cls._escape_markdown(project_info.get('name', 'Unknown'))}\n\n"
            md += f"**项目路径**: `{cls._escape_markdown(project_info.get('path', ''))}`\n\n"

        if task_info:
            audit_type = task_info.get("audit_type", "full")
            md += f"**审计类型**: {'深度审计' if audit_type == 'full' else '快速扫描'}\n\n"

        md += "---\n\n"

        # 概览统计
        md += "## 📊 概览统计\n\n"
        md += f"### 安全评分: **{score}** / 100\n\n"

        if score >= 90:
            grade = "A (优秀)"
            color = "🟢"
        elif score >= 70:
            grade = "B (良好)"
            color = "🟡"
        elif score >= 50:
            grade = "C (中等)"
            color = "🟠"
        else:
            grade = "D (较差)"
            color = "🔴"

        md += f"**等级**: {color} {grade}\n\n"

        md += "| 严重程度 | 数量 | 占比 |\n"
        md += "|---------|------|------|\n"
        if total_findings > 0:
            md += f"| 🔴 严重 | {critical_count} | {critical_count/total_findings*100:.1f}% |\n"
            md += f"| 🟠 高危 | {high_count} | {high_count/total_findings*100:.1f}% |\n"
            md += f"| 🟡 中危 | {medium_count} | {medium_count/total_findings*100:.1f}% |\n"
            md += f"| 🔵 低危 | {low_count} | {low_count/total_findings*100:.1f}% |\n"
        else:
            md += "| 🔴 严重 | 0 | 0% |\n"
            md += "| 🟠 高危 | 0 | 0% |\n"
            md += "| 🟡 中危 | 0 | 0% |\n"
            md += "| 🔵 低危 | 0 | 0% |\n"
        md += f"| **总计** | **{total_findings}** | **100%** |\n\n"

        md += "---\n\n"

        # 漏洞详情
        if sorted_findings:
            md += "## 🐛 漏洞详情\n\n"
            for i, finding in enumerate(sorted_findings, 1):
                md += cls._format_finding(finding, i)
        else:
            md += "## 🎉 未发现漏洞\n\n"
            md += "本次审计未发现任何安全漏洞，代码质量良好！\n\n"

        # 报告说明
        md += "---\n\n"
        md += "## 📝 报告说明\n\n"
        md += "本报告由 AI 安全审计系统自动生成，包含以下内容：\n\n"
        md += "- **漏洞发现**: 通过静态代码分析和动态检测发现的潜在安全问题\n"
        md += "- **风险评估**: 根据漏洞的严重程度和影响范围进行风险评级\n"
        md += "- **修复建议**: 针对每个漏洞提供的具体修复方案和最佳实践\n\n"
        md += "> ⚠️ **注意**: 本报告仅供参考，建议结合人工审核和测试验证。\n\n"

        # 页脚
        md += "---\n\n"
        md += "<div align='center'>\n\n"
        md += "**Generated by CTX-Audit Security Scanner**\n\n"
        md += f"Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        md += "</div>\n"

        return md

    @classmethod
    def generate_json_report(
        cls,
        audit_id: str,
        findings: List[Dict[str, Any]],
        task_info: Optional[Dict[str, Any]] = None,
        project_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        生成 JSON 格式的审计报告

        Args:
            audit_id: 审计 ID
            findings: 漏洞发现列表
            task_info: 任务信息（可选）
            project_info: 项目信息（可选）

        Returns:
            JSON 格式的报告数据
        """
        # 统计信息
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low_count = sum(1 for f in findings if f.get("severity", "").lower() == "low")

        # 计算安全评分
        score = 100
        score -= critical_count * 25
        score -= high_count * 10
        score -= medium_count * 5
        score -= low_count * 2
        score = max(0, min(100, score))

        return {
            "report_id": audit_id,
            "generated_at": datetime.now().isoformat(),
            "project": project_info or {},
            "task": task_info or {},
            "summary": {
                "score": score,
                "grade": "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D",
                "total_findings": total_findings,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
            },
            "findings": findings,
        }

    @classmethod
    def _escape_html(cls, text: str) -> str:
        """转义 HTML 特殊字符"""
        if not text:
            return ""
        replacements = [
            ("&", "&amp;"),
            ("<", "&lt;"),
            (">", "&gt;"),
            ("\"", "&quot;"),
            ("'", "&#39;"),
        ]
        for old, new in replacements:
            text = text.replace(old, new)
        return text

    @classmethod
    def _get_severity_badge(cls, severity: str) -> str:
        """获取严重程度徽章 HTML"""
        severity = severity.lower()
        colors = {
            "critical": ("#dc2626", "#991b1b", "#fecaca"),
            "high": ("#ea580c", "#c2410c", "#fed7aa"),
            "medium": ("#ca8a04", "#a16207", "#fef08a"),
            "low": ("#2563eb", "#1d4ed8", "#bfdbfe"),
            "info": ("#64748b", "#475569", "#e2e8f0"),
        }
        if severity not in colors:
            severity = "info"
        bg_color, border_color, text_color = colors[severity]
        label = cls._get_severity_label(severity)

        return f'<span style="display: inline-block; padding: 2px 8px; border-radius: 4px; background-color: {bg_color}; color: white; font-size: 12px; font-weight: 600;">{label}</span>'

    @classmethod
    def _format_finding_html(cls, finding: Dict[str, Any], index: int) -> str:
        """格式化单个漏洞发现为 HTML"""
        severity = finding.get("severity", "info").lower()
        title = finding.get("title", "未知漏洞")
        description = finding.get("description", "")
        file_path = finding.get("file_path", "")
        line_start = finding.get("line_start")
        line_end = finding.get("line_end", line_start)
        code_snippet = finding.get("code_snippet", "")
        recommendation = finding.get("recommendation", "")
        vulnerability_type = finding.get("vulnerability_type", "")

        html = f'<div class="finding" style="margin-bottom: 24px; padding: 20px; border: 1px solid #e5e7eb; border-left: 4px solid;'
        if severity == "critical":
            html += ' #dc2626; border-radius: 8px; background-color: #fef2f2;">'
        elif severity == "high":
            html += ' #ea580c; border-radius: 8px; background-color: #fff7ed;">'
        elif severity == "medium":
            html += ' #ca8a04; border-radius: 8px; background-color: #fefce8;">'
        elif severity == "low":
            html += ' #2563eb; border-radius: 8px; background-color: #eff6ff;">'
        else:
            html += ' #64748b; border-radius: 8px; background-color: #f8fafc;">'

        # 标题和严重程度
        html += f'<h3 style="margin: 0 0 12px 0; font-size: 16px; font-weight: 600; color: #1f2937;">{index}. {cls._escape_html(title)} {cls._get_severity_badge(severity)}</h3>'

        # 漏洞类型
        if vulnerability_type:
            html += f'<p style="margin: 8px 0; font-size: 14px; color: #6b7280;"><strong>漏洞类型:</strong> {cls._escape_html(vulnerability_type)}</p>'

        # 位置信息
        if file_path:
            location = cls._escape_html(file_path)
            if line_start:
                location += f" (行 {line_start}"
                if line_end and line_end != line_start:
                    location += f"-{line_end}"
                location += ")"
            html += f'<p style="margin: 8px 0; font-size: 14px; color: #6b7280;"><strong>位置:</strong> <code style="background-color: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 13px;">{location}</code></p>'

        # 描述
        if description:
            html += f'<div style="margin: 12px 0;"><p style="margin: 0 0 8px 0; font-size: 14px; font-weight: 600; color: #374151;">描述:</p>'
            html += f'<p style="margin: 0; font-size: 14px; line-height: 1.6; color: #4b5563;">{cls._escape_html(description)}</p></div>'

        # 代码片段
        if code_snippet:
            html += f'<div style="margin: 12px 0;"><p style="margin: 0 0 8px 0; font-size: 14px; font-weight: 600; color: #374151;">代码片段:</p>'
            html += f'<pre style="margin: 0; padding: 12px; background-color: #1f2937; border-radius: 6px; overflow-x: auto;"><code style="font-family: monospace; font-size: 13px; color: #e5e7eb;">{cls._escape_html(code_snippet)}</code></pre></div>'

        # 修复建议
        if recommendation:
            html += f'<div style="margin: 12px 0; padding: 12px; background-color: #ecfdf5; border-radius: 6px;"><p style="margin: 0 0 8px 0; font-size: 14px; font-weight: 600; color: #065f46;">修复建议:</p>'
            html += f'<p style="margin: 0; font-size: 14px; line-height: 1.6; color: #047857;">{cls._escape_html(recommendation)}</p></div>'

        html += '</div>'
        return html

    @classmethod
    def generate_html_report(
        cls,
        audit_id: str,
        findings: List[Dict[str, Any]],
        task_info: Optional[Dict[str, Any]] = None,
        project_info: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        生成 HTML 格式的审计报告

        Args:
            audit_id: 审计 ID
            findings: 漏洞发现列表
            task_info: 任务信息（可选）
            project_info: 项目信息（可选）

        Returns:
            HTML 格式的报告内容
        """
        # 统计信息
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        low_count = sum(1 for f in findings if f.get("severity", "").lower() == "low")

        # 计算安全评分
        score = 100
        score -= critical_count * 25
        score -= high_count * 10
        score -= medium_count * 5
        score -= low_count * 2
        score = max(0, min(100, score))

        # 按严重程度排序
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "").lower(), 5)
        )

        # 项目名称
        project_name = project_info.get("name", "未知项目") if project_info else "未知项目"

        # 评分颜色
        if score >= 80:
            score_color = "#10b981"
            grade = "A"
        elif score >= 60:
            score_color = "#f59e0b"
            grade = "B"
        elif score >= 40:
            score_color = "#f97316"
            grade = "C"
        else:
            score_color = "#ef4444"
            grade = "D"

        # 生成 HTML
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全审计报告 - """ + cls._escape_html(project_name) + """</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background-color: #f9fafb;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 32px;
            margin-bottom: 12px;
        }
        .header p {
            font-size: 14px;
            opacity: 0.9;
        }
        .score-card {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 40px;
            padding: 30px;
            background-color: #f8fafc;
            border-bottom: 1px solid #e5e7eb;
        }
        .score-item {
            text-align: center;
        }
        .score-value {
            font-size: 36px;
            font-weight: 700;
        }
        .score-label {
            font-size: 12px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background-color: #f9fafb;
        }
        .stat-card {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
            text-align: center;
        }
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 4px;
        }
        .stat-label {
            font-size: 12px;
            color: #6b7280;
            text-transform: uppercase;
        }
        .content {
            padding: 30px;
        }
        .section-title {
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 20px;
            color: #1f2937;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            background-color: #f9fafb;
            border-top: 1px solid #e5e7eb;
            font-size: 12px;
            color: #6b7280;
        }
        @media print {
            body { padding: 0; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 头部 -->
        <div class="header">
            <h1>🔒 安全审计报告</h1>
            <p>""" + cls._escape_html(project_name) + """</p>
            <p style="margin-top: 8px;">报告 ID: """ + cls._escape_html(audit_id) + """</p>
        </div>

        <!-- 评分卡片 -->
        <div class="score-card">
            <div class="score-item">
                <div class="score-value" style="color: """ + score_color + """;">""" + str(score) + """</div>
                <div class="score-label">安全评分</div>
            </div>
            <div class="score-item">
                <div class="score-value" style="font-size: 48px;">""" + grade + """</div>
                <div class="score-label">安全等级</div>
            </div>
        </div>

        <!-- 统计数据 -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" style="color: #ef4444;">""" + str(total_findings) + """</div>
                <div class="stat-label">漏洞总数</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #dc2626;">""" + str(critical_count) + """</div>
                <div class="stat-label">严重</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ea580c;">""" + str(high_count) + """</div>
                <div class="stat-label">高危</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #ca8a04;">""" + str(medium_count) + """</div>
                <div class="stat-label">中危</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #2563eb;">""" + str(low_count) + """</div>
                <div class="stat-label">低危</div>
            </div>
        </div>

        <!-- 漏洞详情 -->
        <div class="content">
            <h2 class="section-title">漏洞详情</h2>
"""

        # 添加每个漏洞
        for i, finding in enumerate(sorted_findings, 1):
            html += cls._format_finding_html(finding, i)

        # 如果没有漏洞
        if total_findings == 0:
            html += """
            <div style="text-align: center; padding: 60px 20px; color: #10b981;">
                <div style="font-size: 64px; margin-bottom: 16px;">✅</div>
                <div style="font-size: 20px; font-weight: 600;">未发现安全漏洞</div>
                <div style="margin-top: 8px; color: #6b7280;">代码质量良好，请继续保持！</div>
            </div>
"""

        # 页脚
        html += """
        </div>

        <!-- 页脚 -->
        <div class="footer">
            <p>Generated by CTX-Audit Security Scanner</p>
            <p>Generated at """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </div>
    </div>
</body>
</html>
"""

        return html


# 导出实例
report_generator = ReportGenerator()
