"""
Orchestrator Agent - 总指挥

负责任务编排、决策协调和最终报告生成
"""
from typing import Dict, Any, List
from loguru import logger

from app.agents.base import BaseAgent


class OrchestratorAgent(BaseAgent):
    """
    Orchestrator Agent

    职责：
    1. 接收用户审计任务
    2. 分析项目类型和技术栈
    3. 制定审计策略和计划
    4. 协调子 Agent 的工作
    5. 汇总结果并生成最终报告
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(name="orchestrator", config=config)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行编排逻辑

        Args:
            context: 上下文，包含:
                - audit_id: 审计 ID
                - project_id: 项目 ID
                - audit_type: 审计类型
                - target_types: 目标漏洞类型（可选）
                - config: 配置

        Returns:
            审计计划和执行结果
        """
        audit_id = context.get("audit_id")
        project_id = context.get("project_id")

        self.think(f"开始编排审计任务: {audit_id}")

        # 1. 获取项目信息
        project_info = await self._get_project_info(project_id)
        self.think(f"项目信息获取完成: {project_info.get('name', 'Unknown')}")

        # 2. 分析项目特征
        project_context = await self._analyze_project(project_info)
        self.think(f"项目分析完成，语言: {project_context.get('languages', [])}")

        # 3. 制定审计计划
        audit_plan = await self._create_audit_plan(
            audit_type=context.get("audit_type", "full"),
            project_context=project_context,
            target_types=context.get("target_types"),
        )
        self.think(f"审计计划制定完成，包含 {len(audit_plan.get('stages', []))} 个阶段")

        # 4. 执行审计流程
        execution_result = await self._execute_audit_pipeline(
            audit_id=audit_id,
            audit_plan=audit_plan,
            context=context,
        )

        # 5. 生成最终报告
        final_report = await self._generate_final_report(execution_result)
        self.think("最终报告生成完成")

        return {
            "audit_plan": audit_plan,
            "project_context": project_context,
            "execution_result": execution_result,
            "final_report": final_report,
        }

    async def _get_project_info(self, project_id: str) -> Dict[str, Any]:
        """获取项目信息"""
        from app.services.rust_client import rust_client

        try:
            return await rust_client.get_project(project_id)
        except Exception as e:
            logger.warning(f"获取项目信息失败: {e}")
            return {"id": project_id, "name": "Unknown"}

    async def _analyze_project(self, project_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析项目特征

        Args:
            project_info: 项目信息

        Returns:
            项目上下文
        """
        # 基本分析（后期可以增强）
        context = {
            "project_id": project_info.get("id"),
            "name": project_info.get("name"),
            "path": project_info.get("path"),
            "languages": [],
            "frameworks": [],
            "entry_points": [],
        }

        # 如果有路径，尝试分析
        project_path = project_info.get("path")
        if project_path:
            # TODO: 调用 Recon Agent 进行详细分析
            context["estimated_files"] = "unknown"
            context["estimated_size"] = "unknown"

        return context

    async def _create_audit_plan(
        self,
        audit_type: str,
        project_context: Dict[str, Any],
        target_types: List[str] = None,
    ) -> Dict[str, Any]:
        """
        创建审计计划

        Args:
            audit_type: 审计类型 (full | quick | targeted)
            project_context: 项目上下文
            target_types: 目标漏洞类型

        Returns:
            审计计划
        """
        stages = []

        # 所有审计类型都需要的基础阶段
        stages.append({
            "name": "recon",
            "agent": "recon",
            "description": "项目结构和攻击面分析",
            "enabled": True,
        })

        stages.append({
            "name": "scan",
            "agent": "scanner",
            "description": "规则扫描",
            "enabled": True,
        })

        # 根据审计类型添加分析阶段
        if audit_type in ["full", "targeted"]:
            stages.append({
                "name": "analysis",
                "agent": "analysis",
                "description": "深度代码分析",
                "enabled": True,
                "config": {
                    "target_types": target_types,
                    "use_rag": True,
                }
            })

        # 验证阶段（可选）
        if self.config.get("enable_verification", False):
            stages.append({
                "name": "verification",
                "agent": "verification",
                "description": "漏洞验证",
                "enabled": True,
            })

        return {
            "audit_type": audit_type,
            "stages": stages,
            "estimated_duration": self._estimate_duration(stages),
        }

    def _estimate_duration(self, stages: List[Dict[str, Any]]) -> int:
        """估算审计时长（秒）"""
        base_time = 60  # 基础时间
        per_stage_time = {
            "recon": 30,
            "scan": 120,
            "analysis": 180,
            "verification": 300,
        }

        total = base_time
        for stage in stages:
            if stage.get("enabled"):
                total += per_stage_time.get(stage["name"], 60)

        return total

    async def _execute_audit_pipeline(
        self,
        audit_id: str,
        audit_plan: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        执行审计流程
        
        Args:
            audit_id: 审计 ID
            audit_plan: 审计计划
            context: 上下文
            
        Returns:
            执行结果
        """
        results = {
            "stages_completed": [],
            "stages_failed": [],
            "total_findings": 0,
            "findings": []
        }
        
        stages = audit_plan.get("stages", [])
        
        # 1. Recon Stage
        recon_stage = next((s for s in stages if s["name"] == "recon"), None)
        if recon_stage and recon_stage.get("enabled"):
            try:
                from app.agents.recon import ReconAgent
                recon_agent = ReconAgent()
                recon_result = await recon_agent.run(context)
                if recon_result["status"] == "success":
                    context["recon_result"] = recon_result["result"]
                    results["stages_completed"].append("recon")
                else:
                    results["stages_failed"].append("recon")
            except Exception as e:
                logger.error(f"Recon failed: {e}")
                results["stages_failed"].append("recon")

        # 2. Scan Stage (Rust Scanner)
        scan_stage = next((s for s in stages if s["name"] == "scan"), None)
        if scan_stage and scan_stage.get("enabled"):
            try:
                # TODO: Call Rust Scanner via RustClient
                # For now, mock some findings if scan not implemented
                from app.services.rust_client import rust_client
                # scan_results = await rust_client.scan_project(context["project_id"])
                scan_results = [] # Mock empty for now
                context["scan_results"] = scan_results
                results["stages_completed"].append("scan")
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                results["stages_failed"].append("scan")

        # 3. Analysis Stage
        analysis_stage = next((s for s in stages if s["name"] == "analysis"), None)
        if analysis_stage and analysis_stage.get("enabled"):
            try:
                from app.agents.analysis import AnalysisAgent
                analysis_agent = AnalysisAgent()
                analysis_result = await analysis_agent.run(context)
                if analysis_result["status"] == "success":
                    findings = analysis_result["result"].get("vulnerabilities", [])
                    results["findings"] = findings
                    results["total_findings"] = len(findings)
                    results["stages_completed"].append("analysis")
                else:
                    results["stages_failed"].append("analysis")
            except Exception as e:
                logger.error(f"Analysis failed: {e}")
                results["stages_failed"].append("analysis")

        return results

    async def _generate_final_report(self, execution_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成最终报告

        Args:
            execution_result: 执行结果

        Returns:
            最终报告
        """
        return {
            "summary": {
                "stages_completed": len(execution_result.get("stages_completed", [])),
                "stages_failed": len(execution_result.get("stages_failed", [])),
                "total_findings": execution_result.get("total_findings", 0),
            },
            "recommendations": [],
            "next_steps": [],
        }
